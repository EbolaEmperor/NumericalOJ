#!/usr/bin/env python3
"""Export the trusted VibeHub base from Docker into a verified OCI layout.

The converter treats ``docker image save`` output as untrusted structured data:
it never extracts archive paths and never executes image content.  Only regular
config/layer members referenced by the single Docker manifest are streamed into
an immutable-by-digest OCI image layout.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import NamedTuple
import uuid
import zlib


SCHEMA_VERSION = 1
OCI_LAYOUT_VERSION = "1.0.0"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,191}:[A-Za-z0-9_.-]{1,63}$")
BUILDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_ARCHIVE_BYTES = 8 * 1024**3
MAX_ARCHIVE_MEMBERS = 4096
MAX_MEMBER_BYTES = 4 * 1024**3
MAX_CONFIG_BYTES = 16 * 1024**2
MAX_JSON_BYTES = 2 * 1024**2
MAX_LAYERS = 256
COPY_CHUNK_BYTES = 1024 * 1024


class OCIExportError(RuntimeError):
    """A trusted base export or verification invariant failed."""


class ReleaseInfo(NamedTuple):
    path: Path
    engine_image_ref: str
    engine_image_id: str
    manifest_digest: str
    blobs: tuple[tuple[str, int], ...]


def _json_no_duplicates(raw: bytes, *, label: str, max_bytes: int = MAX_JSON_BYTES):
    if len(raw) > max_bytes:
        raise OCIExportError(f"{label} 异常过大")

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise OCIExportError(f"{label} 含重复 JSON 字段")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OCIExportError(f"{label} 不是有效 JSON") from exc


def _json_bytes(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_image_ref(value: str) -> str:
    if not isinstance(value, str) or IMAGE_REF_RE.fullmatch(value) is None:
        raise OCIExportError("VibeHub 基础镜像引用无效")
    return value


def _validate_digest(value: str, *, label: str = "digest") -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise OCIExportError(f"{label} 无效")
    return value


def _safe_dir(path: Path, *, create: bool = False) -> Path:
    path = Path(os.path.abspath(path))
    for ancestor in (path, *path.parents):
        try:
            ancestor_metadata = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(ancestor_metadata.st_mode):
            raise OCIExportError(f"目录路径不能经过符号链接：{ancestor}")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for ancestor in (path, *path.parents):
        try:
            ancestor_metadata = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(ancestor_metadata.st_mode):
            raise OCIExportError(f"目录路径不能经过符号链接：{ancestor}")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise OCIExportError(f"目录不存在或不可访问：{path}") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise OCIExportError(f"路径必须是实体目录：{path}")
    if metadata.st_uid != os.geteuid():
        raise OCIExportError(f"目录不属于当前用户：{path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise OCIExportError(f"目录不能被 group/world 写入：{path}")
    return path


def _regular_file(path: Path, *, max_bytes: int) -> os.stat_result:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OCIExportError(f"无法安全打开普通文件：{path}") from exc
    try:
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise OCIExportError(f"路径必须是普通文件：{path}")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise OCIExportError(f"文件属主或权限不安全：{path}")
    if metadata.st_size < 0 or metadata.st_size > max_bytes:
        raise OCIExportError(f"文件大小越界：{path}")
    return metadata


def _hash_regular_file(path: Path, *, max_bytes: int) -> tuple[os.stat_result, str]:
    """Hash one stable inode opened with O_NOFOLLOW and re-check its pathname."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OCIExportError(f"无法安全打开普通文件：{path}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise OCIExportError(f"文件类型、属主、权限或大小无效：{path}")
        digest = hashlib.sha256()
        copied = 0
        while chunk := os.read(descriptor, COPY_CHUNK_BYTES):
            copied += len(chunk)
            if copied > before.st_size:
                raise OCIExportError(f"文件读取过程中发生变化：{path}")
            digest.update(chunk)
        after_fd = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise OCIExportError(f"文件读取过程中发生变化：{path}") from exc
    fingerprint = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        copied != before.st_size
        or fingerprint(after_fd) != fingerprint(before)
        or fingerprint(after_path) != fingerprint(before)
    ):
        raise OCIExportError(f"文件读取过程中发生变化：{path}")
    return before, "sha256:" + digest.hexdigest()


def _write_bytes(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
    finally:
        os.close(descriptor)


def _safe_archive_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or not name
        or len(name.encode("utf-8")) > 1024
        or "\x00" in name
        or "\\" in name
    ):
        raise OCIExportError("Docker archive 含无效成员名")
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise OCIExportError(f"Docker archive 成员路径逃逸：{name!r}")
    if str(pure) != name.rstrip("/"):
        raise OCIExportError(f"Docker archive 成员路径不规范：{name!r}")
    return str(pure)


def _read_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if member.size < 0 or member.size > limit:
        raise OCIExportError(f"Docker archive 成员大小越界：{member.name}")
    source = archive.extractfile(member)
    if source is None:
        raise OCIExportError(f"无法读取 Docker archive 成员：{member.name}")
    raw = source.read(limit + 1)
    if len(raw) != member.size:
        raise OCIExportError(f"Docker archive 成员长度不一致：{member.name}")
    return raw


def _stream_layer_blob(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    expected_digest: str,
) -> int:
    if member.size < 0 or member.size > MAX_MEMBER_BYTES:
        raise OCIExportError(f"Docker layer 大小越界：{member.name}")
    source = archive.extractfile(member)
    if source is None:
        raise OCIExportError(f"无法读取 Docker layer：{member.name}")
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    digest = hashlib.sha256()
    read_bytes = 0
    written_bytes = 0
    decompressor = None
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as target:
            while chunk := source.read(COPY_CHUNK_BYTES):
                read_bytes += len(chunk)
                if read_bytes > member.size:
                    raise OCIExportError(f"Docker layer 长度不一致：{member.name}")
                if decompressor is None and read_bytes == len(chunk):
                    decompressor = (
                        zlib.decompressobj(16 + zlib.MAX_WBITS)
                        if chunk.startswith(b"\x1f\x8b")
                        else False
                    )
                try:
                    output = decompressor.decompress(chunk) if decompressor else chunk
                except zlib.error as exc:
                    raise OCIExportError(
                        f"Docker gzip layer 无法解压：{member.name}"
                    ) from exc
                written_bytes += len(output)
                if written_bytes > MAX_MEMBER_BYTES:
                    raise OCIExportError(f"Docker layer 解压后大小越界：{member.name}")
                digest.update(output)
                target.write(output)
            if decompressor:
                try:
                    output = decompressor.flush()
                except zlib.error as exc:
                    raise OCIExportError(
                        f"Docker gzip layer 无法解压：{member.name}"
                    ) from exc
                if not decompressor.eof or decompressor.unused_data:
                    raise OCIExportError(f"Docker gzip layer 数据不完整：{member.name}")
                written_bytes += len(output)
                if written_bytes > MAX_MEMBER_BYTES:
                    raise OCIExportError(f"Docker layer 解压后大小越界：{member.name}")
                digest.update(output)
                target.write(output)
            target.flush()
            os.fsync(target.fileno())
    finally:
        os.close(descriptor)
    actual_digest = "sha256:" + digest.hexdigest()
    if read_bytes != member.size or actual_digest != expected_digest:
        raise OCIExportError(f"Docker layer diff-id/hash 不匹配：{member.name}")
    return written_bytes


def convert_docker_archive(
    archive_path: Path,
    release_path: Path,
    *,
    engine_image_ref: str,
    engine_image_id: str,
) -> ReleaseInfo:
    """Convert one plain ``docker image save`` tar without extracting it."""

    engine_image_ref = _validate_image_ref(engine_image_ref)
    engine_image_id = _validate_digest(engine_image_id, label="engine image ID")
    archive_path = Path(archive_path)
    _safe_dir(archive_path.parent)
    archive_stat = _regular_file(archive_path, max_bytes=MAX_ARCHIVE_BYTES)
    _safe_dir(release_path.parent)
    release_path.mkdir(mode=0o700)
    _safe_dir(release_path)
    blob_root = release_path / "blobs" / "sha256"
    blob_root.mkdir(mode=0o700, parents=True)

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    archive_fd = os.open(archive_path, flags)
    try:
        descriptor_stat = os.fstat(archive_fd)
        with os.fdopen(os.dup(archive_fd), "rb") as archive_file:
            with tarfile.open(fileobj=archive_file, mode="r:") as archive:
                members: dict[str, tarfile.TarInfo] = {}
                total_size = 0
                for member in archive.getmembers():
                    if len(members) >= MAX_ARCHIVE_MEMBERS:
                        raise OCIExportError("Docker archive 成员数量越界")
                    name = _safe_archive_name(member.name)
                    if name in members:
                        raise OCIExportError(f"Docker archive 含重复成员：{name}")
                    if not (member.isdir() or member.isreg()):
                        raise OCIExportError(f"Docker archive 含链接或特殊成员：{name}")
                    if member.isreg():
                        if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                            raise OCIExportError(f"Docker archive 成员大小越界：{name}")
                        total_size += member.size
                        if total_size > MAX_ARCHIVE_BYTES:
                            raise OCIExportError("Docker archive 解包后大小越界")
                    members[name] = member

                docker_manifest_member = members.get("manifest.json")
                if docker_manifest_member is None or not docker_manifest_member.isreg():
                    raise OCIExportError("Docker archive 缺少 manifest.json")
                docker_manifest = _json_no_duplicates(
                    _read_tar_member(archive, docker_manifest_member, MAX_JSON_BYTES),
                    label="Docker manifest",
                )
                if not isinstance(docker_manifest, list) or len(docker_manifest) != 1:
                    raise OCIExportError("Docker archive 必须只包含一个镜像 manifest")
                entry = docker_manifest[0]
                if not isinstance(entry, dict):
                    raise OCIExportError("Docker manifest entry 无效")
                config_name = entry.get("Config")
                layer_names = entry.get("Layers")
                if not isinstance(config_name, str):
                    raise OCIExportError("Docker manifest config 路径无效")
                config_name = _safe_archive_name(config_name)
                if (
                    not isinstance(layer_names, list)
                    or not 1 <= len(layer_names) <= MAX_LAYERS
                    or any(not isinstance(name, str) for name in layer_names)
                ):
                    raise OCIExportError("Docker manifest layer 清单无效")
                layer_names = [_safe_archive_name(name) for name in layer_names]
                if len(set(layer_names)) != len(layer_names):
                    raise OCIExportError("Docker manifest 含重复 layer")

                config_member = members.get(config_name)
                if config_member is None or not config_member.isreg():
                    raise OCIExportError("Docker manifest 引用的 config 不存在")
                config_raw = _read_tar_member(archive, config_member, MAX_CONFIG_BYTES)
                config_digest = _sha256(config_raw)
                config = _json_no_duplicates(
                    config_raw, label="Docker image config", max_bytes=MAX_CONFIG_BYTES
                )
                if not isinstance(config, dict):
                    raise OCIExportError("Docker image config 结构无效")
                rootfs = config.get("rootfs")
                if not isinstance(rootfs, dict):
                    raise OCIExportError("Docker config rootfs.diff_ids 无效")
                diff_ids = rootfs.get("diff_ids")
                if (
                    rootfs.get("type") != "layers"
                    or not isinstance(diff_ids, list)
                    or len(diff_ids) != len(layer_names)
                    or any(
                        not isinstance(item, str)
                        or DIGEST_RE.fullmatch(item) is None
                        for item in diff_ids
                    )
                    or len(set(diff_ids)) != len(diff_ids)
                ):
                    raise OCIExportError("Docker config rootfs.diff_ids 无效")
                architecture = config.get("architecture")
                operating_system = config.get("os")
                if (
                    not isinstance(architecture, str)
                    or not architecture
                    or not isinstance(operating_system, str)
                    or not operating_system
                ):
                    raise OCIExportError("Docker config 缺少 OCI platform")

                config_blob = blob_root / config_digest.removeprefix("sha256:")
                _write_bytes(config_blob, config_raw)
                blob_sizes: dict[str, int] = {config_digest: len(config_raw)}
                layer_descriptors = []
                for layer_name, diff_id in zip(layer_names, diff_ids, strict=True):
                    member = members.get(layer_name)
                    if member is None or not member.isreg():
                        raise OCIExportError(
                            f"Docker manifest 引用的 layer 不存在：{layer_name}"
                        )
                    destination = blob_root / diff_id.removeprefix("sha256:")
                    size = _stream_layer_blob(archive, member, destination, diff_id)
                    blob_sizes[diff_id] = size
                    layer_descriptors.append(
                        {"mediaType": OCI_LAYER_MEDIA_TYPE, "digest": diff_id, "size": size}
                    )

                manifest = {
                    "schemaVersion": 2,
                    "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                    "config": {
                        "mediaType": OCI_CONFIG_MEDIA_TYPE,
                        "digest": config_digest,
                        "size": len(config_raw),
                    },
                    "layers": layer_descriptors,
                }
                manifest_raw = _json_bytes(manifest)
                manifest_digest = _sha256(manifest_raw)
                _write_bytes(
                    blob_root / manifest_digest.removeprefix("sha256:"), manifest_raw
                )
                blob_sizes[manifest_digest] = len(manifest_raw)

                index = {
                    "schemaVersion": 2,
                    "mediaType": OCI_INDEX_MEDIA_TYPE,
                    "manifests": [
                        {
                            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                            "digest": manifest_digest,
                            "size": len(manifest_raw),
                            "platform": {
                                "architecture": architecture,
                                "os": operating_system,
                            },
                            "annotations": {
                                "org.opencontainers.image.ref.name": engine_image_ref
                            },
                        }
                    ],
                }
                metadata = {
                    "schema_version": SCHEMA_VERSION,
                    "engine_image_ref": engine_image_ref,
                    "engine_image_id": engine_image_id,
                    "manifest_digest": manifest_digest,
                    "blobs": [
                        {"digest": digest, "size": size}
                        for digest, size in sorted(blob_sizes.items())
                    ],
                }
                _write_bytes(
                    release_path / "oci-layout",
                    _json_bytes({"imageLayoutVersion": OCI_LAYOUT_VERSION}),
                )
                _write_bytes(release_path / "index.json", _json_bytes(index))
                _write_bytes(release_path / "metadata.json", _json_bytes(metadata))
    except Exception:
        shutil.rmtree(release_path, ignore_errors=True)
        raise
    finally:
        after_fd = os.fstat(archive_fd)
        os.close(archive_fd)
    try:
        after_path = archive_path.stat(follow_symlinks=False)
    except OSError as exc:
        raise OCIExportError("Docker archive 在转换过程中发生变化") from exc
    fingerprint = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        fingerprint(archive_stat) != fingerprint(descriptor_stat)
        or fingerprint(after_fd) != fingerprint(descriptor_stat)
        or fingerprint(after_path) != fingerprint(descriptor_stat)
    ):
        shutil.rmtree(release_path, ignore_errors=True)
        raise OCIExportError("Docker archive 在转换过程中发生变化")
    return verify_release(
        release_path,
        expected_image_ref=engine_image_ref,
        expected_image_id=engine_image_id,
        _allow_unpublished_parent=release_path.parent.name != "releases",
    )


def _read_file(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OCIExportError(f"无法安全打开普通文件：{path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size < 0
            or metadata.st_size > max_bytes
        ):
            raise OCIExportError(f"文件类型、属主、权限或大小无效：{path}")
        chunks = []
        remaining = metadata.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(COPY_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            raise OCIExportError(f"文件长度不一致：{path}")
        after_fd = os.fstat(descriptor)
        try:
            after_path = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise OCIExportError(f"文件读取过程中发生变化：{path}") from exc
        fingerprint = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            fingerprint(after_fd) != fingerprint(metadata)
            or fingerprint(after_path) != fingerprint(metadata)
        ):
            raise OCIExportError(f"文件读取过程中发生变化：{path}")
        return raw
    finally:
        os.close(descriptor)


def verify_release(
    release_path: Path,
    *,
    expected_image_ref: str | None = None,
    expected_image_id: str | None = None,
    _allow_unpublished_parent: bool = False,
) -> ReleaseInfo:
    release_path = _safe_dir(release_path)
    if (
        (not _allow_unpublished_parent and release_path.parent.name != "releases")
        or HEX_RE.fullmatch(release_path.name) is None
    ):
        raise OCIExportError("OCI release 路径结构无效")
    allowed_root = {"oci-layout", "index.json", "metadata.json", "blobs"}
    if {entry.name for entry in os.scandir(release_path)} != allowed_root:
        raise OCIExportError("OCI release 顶层文件集合无效")
    blob_parent = _safe_dir(release_path / "blobs")
    if {entry.name for entry in os.scandir(blob_parent)} != {"sha256"}:
        raise OCIExportError("OCI blobs 目录结构无效")
    blob_root = _safe_dir(blob_parent / "sha256")

    layout = _json_no_duplicates(
        _read_file(release_path / "oci-layout", max_bytes=1024), label="oci-layout"
    )
    if layout != {"imageLayoutVersion": OCI_LAYOUT_VERSION}:
        raise OCIExportError("OCI layout 版本无效")
    metadata = _json_no_duplicates(
        _read_file(release_path / "metadata.json", max_bytes=MAX_JSON_BYTES),
        label="OCI metadata",
    )
    if (
        not isinstance(metadata, dict)
        or set(metadata) != {
            "schema_version",
            "engine_image_ref",
            "engine_image_id",
            "manifest_digest",
            "blobs",
        }
        or metadata.get("schema_version") != SCHEMA_VERSION
    ):
        raise OCIExportError("OCI metadata 字段集合无效")
    image_ref = _validate_image_ref(metadata["engine_image_ref"])
    image_id = _validate_digest(metadata["engine_image_id"], label="engine image ID")
    manifest_digest = _validate_digest(
        metadata["manifest_digest"], label="OCI manifest digest"
    )
    if expected_image_ref is not None and image_ref != expected_image_ref:
        raise OCIExportError("OCI metadata 的 engine image ref 不匹配")
    if expected_image_id is not None and image_id != expected_image_id:
        raise OCIExportError("OCI metadata 的 engine image ID 不匹配")
    if release_path.name != image_id.removeprefix("sha256:"):
        raise OCIExportError("OCI release 目录名与 engine image ID 不匹配")
    raw_blobs = metadata["blobs"]
    if not isinstance(raw_blobs, list) or not 2 <= len(raw_blobs) <= MAX_LAYERS + 2:
        raise OCIExportError("OCI metadata blob 清单无效")
    blobs: dict[str, int] = {}
    for item in raw_blobs:
        if not isinstance(item, dict) or set(item) != {"digest", "size"}:
            raise OCIExportError("OCI metadata blob descriptor 无效")
        digest = _validate_digest(item["digest"], label="OCI blob digest")
        size = item["size"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= MAX_MEMBER_BYTES
        ):
            raise OCIExportError("OCI metadata blob size 无效")
        if digest in blobs:
            raise OCIExportError("OCI metadata 含重复 blob")
        blobs[digest] = size
    actual_names = {entry.name for entry in os.scandir(blob_root)}
    if actual_names != {digest.removeprefix("sha256:") for digest in blobs}:
        raise OCIExportError("OCI blob 实际文件集合与 metadata 不一致")
    for digest, size in blobs.items():
        raw_path = blob_root / digest.removeprefix("sha256:")
        file_stat, actual_digest = _hash_regular_file(
            raw_path, max_bytes=MAX_MEMBER_BYTES
        )
        if file_stat.st_size != size:
            raise OCIExportError("OCI blob size 与 metadata 不一致")
        if actual_digest != digest:
            raise OCIExportError("OCI blob hash 与 metadata 不一致")

    index = _json_no_duplicates(
        _read_file(release_path / "index.json", max_bytes=MAX_JSON_BYTES),
        label="OCI index",
    )
    if (
        not isinstance(index, dict)
        or set(index) != {"schemaVersion", "mediaType", "manifests"}
        or index.get("mediaType") != OCI_INDEX_MEDIA_TYPE
    ):
        raise OCIExportError("OCI index 结构无效")
    manifests = index.get("manifests")
    if index.get("schemaVersion") != 2 or not isinstance(manifests, list) or len(manifests) != 1:
        raise OCIExportError("OCI index 结构无效")
    descriptor = manifests[0]
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != {
            "mediaType",
            "digest",
            "size",
            "platform",
            "annotations",
        }
        or descriptor.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE
        or descriptor.get("digest") != manifest_digest
        or isinstance(descriptor.get("size"), bool)
        or not isinstance(descriptor.get("size"), int)
        or descriptor.get("size") != blobs.get(manifest_digest)
    ):
        raise OCIExportError("OCI index manifest descriptor 无效")
    platform = descriptor.get("platform")
    annotations = descriptor.get("annotations")
    if (
        not isinstance(platform, dict)
        or set(platform) != {"architecture", "os"}
        or not isinstance(platform.get("architecture"), str)
        or not platform.get("architecture")
        or not isinstance(platform.get("os"), str)
        or not platform.get("os")
        or annotations
        != {"org.opencontainers.image.ref.name": image_ref}
    ):
        raise OCIExportError("OCI index platform/annotations 无效")
    manifest = _json_no_duplicates(
        _read_file(
            blob_root / manifest_digest.removeprefix("sha256:"),
            max_bytes=MAX_JSON_BYTES,
        ),
        label="OCI manifest",
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schemaVersion", "mediaType", "config", "layers"}
        or manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE
    ):
        raise OCIExportError("OCI manifest config/layers 结构无效")
    config_descriptor = manifest.get("config")
    layers = manifest.get("layers")
    config_digest = (
        config_descriptor.get("digest")
        if isinstance(config_descriptor, dict)
        else None
    )
    if (
        manifest.get("schemaVersion") != 2
        or not isinstance(config_descriptor, dict)
        or set(config_descriptor) != {"mediaType", "digest", "size"}
        or config_descriptor.get("mediaType") != OCI_CONFIG_MEDIA_TYPE
        or not isinstance(config_digest, str)
        or DIGEST_RE.fullmatch(config_digest) is None
        or isinstance(config_descriptor.get("size"), bool)
        or not isinstance(config_descriptor.get("size"), int)
        or config_descriptor.get("size") != blobs.get(config_digest)
        or not isinstance(layers, list)
        or not 1 <= len(layers) <= MAX_LAYERS
    ):
        raise OCIExportError("OCI manifest config/layers 结构无效")
    layer_digests = []
    for layer in layers:
        if (
            not isinstance(layer, dict)
            or set(layer) != {"mediaType", "digest", "size"}
            or layer.get("mediaType") != OCI_LAYER_MEDIA_TYPE
            or not isinstance(layer.get("digest"), str)
            or DIGEST_RE.fullmatch(layer["digest"]) is None
            or isinstance(layer.get("size"), bool)
            or not isinstance(layer.get("size"), int)
            or layer["digest"] not in blobs
            or layer["size"] != blobs[layer["digest"]]
        ):
            raise OCIExportError("OCI manifest layer descriptor 无效")
        if layer["digest"] in layer_digests:
            raise OCIExportError("OCI manifest 含重复 layer")
        layer_digests.append(layer["digest"])

    referenced_blobs = {manifest_digest, config_digest, *layer_digests}
    if set(blobs) != referenced_blobs:
        raise OCIExportError("OCI metadata blob 清单未精确覆盖 manifest")

    config = _json_no_duplicates(
        _read_file(
            blob_root / config_digest.removeprefix("sha256:"),
            max_bytes=MAX_CONFIG_BYTES,
        ),
        label="OCI image config",
        max_bytes=MAX_CONFIG_BYTES,
    )
    rootfs = config.get("rootfs") if isinstance(config, dict) else None
    diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
    if (
        not isinstance(rootfs, dict)
        or rootfs.get("type") != "layers"
        or not isinstance(diff_ids, list)
        or any(
            not isinstance(diff_id, str) or DIGEST_RE.fullmatch(diff_id) is None
            for diff_id in diff_ids
        )
        or diff_ids != layer_digests
    ):
        raise OCIExportError("OCI config rootfs.diff_ids 与 layer 清单不一致")
    if (
        config.get("architecture") != platform["architecture"]
        or config.get("os") != platform["os"]
    ):
        raise OCIExportError("OCI index platform 与 image config 不一致")
    return ReleaseInfo(
        release_path,
        image_ref,
        image_id,
        manifest_digest,
        tuple(sorted(blobs.items())),
    )


def _run(command_runner, command: list[str], *, timeout: int):
    try:
        return command_runner(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OCIExportError(f"外部命令执行失败：{command[:3]}") from exc


def _inspect_engine_image(command_runner, image: str) -> str:
    result = _run(
        command_runner,
        ["docker", "image", "inspect", "--format", "{{json .}}", image],
        timeout=30,
    )
    if result.returncode != 0:
        raise OCIExportError("无法 inspect VibeHub 基础镜像")
    payload = _json_no_duplicates(result.stdout.encode(), label="Docker image inspect")
    if not isinstance(payload, dict):
        raise OCIExportError("Docker image inspect 结构无效")
    return _validate_digest(payload.get("Id"), label="engine image ID")


def export_engine_image(
    *,
    image: str,
    engine_image_ref: str,
    output_root: Path,
    expected_image_id: str | None = None,
    command_runner: Callable = subprocess.run,
) -> ReleaseInfo:
    image = _validate_image_ref(image)
    engine_image_ref = _validate_image_ref(engine_image_ref)
    output_root = _safe_dir(output_root, create=True)
    releases = _safe_dir(output_root / "releases", create=True)
    image_id = _inspect_engine_image(command_runner, image)
    if expected_image_id is not None and image_id != expected_image_id:
        raise OCIExportError("候选基础镜像 ID 在导出前发生漂移")
    release = releases / image_id.removeprefix("sha256:")
    if release.exists() or release.is_symlink():
        return verify_release(
            release,
            expected_image_ref=engine_image_ref,
            expected_image_id=image_id,
        )

    archive = output_root / f".docker-save-{uuid.uuid4().hex}.tar"
    staging_parent = output_root / f".staging-{uuid.uuid4().hex}"
    staging_parent.mkdir(mode=0o700)
    staging = staging_parent / image_id.removeprefix("sha256:")
    try:
        result = _run(
            command_runner,
            ["docker", "image", "save", "--output", str(archive), image],
            timeout=900,
        )
        if result.returncode != 0:
            raise OCIExportError("docker image save VibeHub 基础镜像失败")
        convert_docker_archive(
            archive,
            staging,
            engine_image_ref=engine_image_ref,
            engine_image_id=image_id,
        )
        after_id = _inspect_engine_image(command_runner, image)
        if after_id != image_id:
            raise OCIExportError("候选基础镜像 ID 在导出过程中发生漂移")
        try:
            os.rename(staging, release)
        except FileExistsError:
            existing = verify_release(
                release,
                expected_image_ref=engine_image_ref,
                expected_image_id=image_id,
            )
            shutil.rmtree(staging)
            return existing
        return verify_release(
            release,
            expected_image_ref=engine_image_ref,
            expected_image_id=image_id,
        )
    finally:
        if archive.exists() and not archive.is_symlink():
            archive.unlink()
        if staging_parent.exists() and staging_parent.is_dir() and not staging_parent.is_symlink():
            shutil.rmtree(staging_parent)


def current_target(output_root: Path, *, allow_missing: bool) -> str:
    output_root = _safe_dir(output_root, create=allow_missing)
    current = output_root / "current"
    try:
        metadata = current.lstat()
    except FileNotFoundError:
        if allow_missing:
            return ""
        raise OCIExportError("OCI current 指针不存在")
    if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise OCIExportError("OCI current 必须是部署用户管理的符号链接")
    target = os.readlink(current)
    if not re.fullmatch(r"releases/[0-9a-f]{64}", target):
        raise OCIExportError("OCI current 指向未知 release")
    resolved = (output_root / target).resolve(strict=True)
    expected = output_root / target
    if resolved != expected:
        raise OCIExportError("OCI current 发生路径逃逸")
    verify_release(resolved)
    return target


def switch_current(
    output_root: Path, release: Path, *, expected_current: str
) -> str:
    output_root = _safe_dir(output_root)
    release_info = verify_release(release)
    expected_release = (
        output_root
        / "releases"
        / release_info.engine_image_id.removeprefix("sha256:")
    )
    if release_info.path != expected_release:
        raise OCIExportError("待切换 OCI release 不属于受管目录")
    actual_current = current_target(output_root, allow_missing=True)
    if actual_current != expected_current:
        raise OCIExportError("OCI current 在切换前发生漂移")
    target = f"releases/{release_info.path.name}"
    temporary = output_root / f".current-{uuid.uuid4().hex}"
    os.symlink(target, temporary)
    os.replace(temporary, output_root / "current")
    directory_fd = os.open(output_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    if current_target(output_root, allow_missing=False) != target:
        raise OCIExportError("OCI current 原子切换后验证失败")
    return target


def clear_current(output_root: Path, *, expected_current: str) -> None:
    output_root = _safe_dir(output_root)
    if current_target(output_root, allow_missing=True) != expected_current:
        raise OCIExportError("OCI current 在清除前发生漂移")
    current = output_root / "current"
    if current.is_symlink():
        current.unlink()


def restore_current(
    output_root: Path, *, candidate_current: str, previous_current: str
) -> None:
    """Idempotently restore a prior pointer after an ambiguous deploy failure."""

    actual = current_target(output_root, allow_missing=True)
    if actual == previous_current:
        return
    if actual != candidate_current:
        raise OCIExportError("OCI current 已被部署流程之外的写入者改变")
    if previous_current:
        if re.fullmatch(r"releases/[0-9a-f]{64}", previous_current) is None:
            raise OCIExportError("上一代 OCI current 指针无效")
        switch_current(
            output_root,
            output_root / previous_current,
            expected_current=candidate_current,
        )
    else:
        clear_current(output_root, expected_current=candidate_current)


def prune_releases(output_root: Path, *, keep_targets: Sequence[str]) -> int:
    """Delete only fully verified old releases, always retaining current."""

    output_root = _safe_dir(output_root)
    releases = _safe_dir(output_root / "releases")
    current = current_target(output_root, allow_missing=False)
    keep = {current}
    for target in keep_targets:
        if re.fullmatch(r"releases/[0-9a-f]{64}", target) is None:
            raise OCIExportError("OCI release 保留目标无效")
        keep.add(target)
    removed = 0
    for entry in os.scandir(releases):
        target = f"releases/{entry.name}"
        if target in keep:
            continue
        if (
            HEX_RE.fullmatch(entry.name) is None
            or entry.is_symlink()
            or not entry.is_dir(follow_symlinks=False)
        ):
            continue
        release = releases / entry.name
        try:
            verify_release(release)
        except OCIExportError:
            continue
        shutil.rmtree(release)
        removed += 1
    return removed


def probe_builder(
    *,
    builder: str,
    release: Path,
    run_id: str,
    command_runner: Callable = subprocess.run,
) -> None:
    if BUILDER_RE.fullmatch(builder) is None or RUN_ID_RE.fullmatch(run_id) is None:
        raise OCIExportError("builder 或 probe run-id 无效")
    info = verify_release(release)
    layout_uri = f"oci-layout://{info.path}@{info.manifest_digest}"
    if not layout_uri.startswith("oci-layout:///"):
        raise OCIExportError("OCI layout probe URI 必须使用绝对路径")
    context = Path(tempfile.mkdtemp(prefix=".probe-", dir=info.path.parent.parent))
    tag = f"numericaloj-vibehub-oci-probe:{run_id}"
    label = f"org.numericaloj.vibehub-oci-probe={info.manifest_digest}"
    try:
        _write_bytes(
            context / "Dockerfile",
            (
                f"FROM {info.engine_image_ref}\n"
                "COPY marker.txt /app/.vibehub-offline-probe\n"
                f"LABEL {label}\n"
            ).encode(),
        )
        _write_bytes(context / "marker.txt", b"offline-oci-context-probe\n")
        command = [
            "docker", "buildx", "build",
            "--builder", builder,
            "--build-context", f"{info.engine_image_ref}={layout_uri}",
            "--network", "none",
            "--pull=false",
            "--load",
            "--resource", "memory=268435456",
            "--resource", "memory-swap=268435456",
            "--resource", "cpu-period=100000",
            "--resource", "cpu-quota=50000",
            "--shm-size", "16m",
            "--ulimit", "nofile=1024:1024",
            "--label", label,
            "--tag", tag,
            "--file", str(context / "Dockerfile"),
            str(context),
        ]
        result = _run(command_runner, command, timeout=180)
        if result.returncode != 0:
            raise OCIExportError("VibeHub 专属 builder 离线 OCI probe 失败")
        inspect_result = _run(
            command_runner,
            [
                "docker", "image", "inspect", "--format",
                "{{if .Config.Labels}}{{index .Config.Labels "
                '"org.numericaloj.vibehub-oci-probe"}}{{end}}',
                tag,
            ],
            timeout=30,
        )
        if inspect_result.returncode != 0 or inspect_result.stdout.strip() != info.manifest_digest:
            raise OCIExportError("VibeHub OCI probe 产物身份校验失败")
        prune_result = _run(
            command_runner,
            [
                "docker", "buildx", "prune", "--builder", builder,
                "--force", "--max-used-space", "4294967296",
            ],
            timeout=120,
        )
        if prune_result.returncode != 0:
            raise OCIExportError("VibeHub 专属 builder 不支持受控缓存清理")
    finally:
        _run(command_runner, ["docker", "image", "rm", tag], timeout=60)
        shutil.rmtree(context, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("--image", required=True)
    export.add_argument("--engine-image-ref", required=True)
    export.add_argument("--expected-image-id")
    export.add_argument("--output-root", type=Path, required=True)
    verify = commands.add_parser("verify-release")
    verify.add_argument("--release", type=Path, required=True)
    verify.add_argument("--expected-image-ref")
    verify.add_argument("--expected-image-id")
    target = commands.add_parser("current-target")
    target.add_argument("--output-root", type=Path, required=True)
    target.add_argument("--allow-missing", action="store_true")
    switch = commands.add_parser("switch-current")
    switch.add_argument("--output-root", type=Path, required=True)
    switch.add_argument("--release", type=Path, required=True)
    switch.add_argument("--expected-current", default="")
    clear = commands.add_parser("clear-current")
    clear.add_argument("--output-root", type=Path, required=True)
    clear.add_argument("--expected-current", required=True)
    restore = commands.add_parser("restore-current")
    restore.add_argument("--output-root", type=Path, required=True)
    restore.add_argument("--candidate-current", required=True)
    restore.add_argument("--previous-current", default="")
    prune = commands.add_parser("prune-releases")
    prune.add_argument("--output-root", type=Path, required=True)
    prune.add_argument("--keep-target", action="append", default=[])
    probe = commands.add_parser("probe")
    probe.add_argument("--builder", required=True)
    probe.add_argument("--release", type=Path, required=True)
    probe.add_argument("--run-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "export":
            info = export_engine_image(
                image=args.image,
                engine_image_ref=args.engine_image_ref,
                output_root=args.output_root,
                expected_image_id=args.expected_image_id,
            )
            print(info.path)
        elif args.command == "verify-release":
            info = verify_release(
                args.release,
                expected_image_ref=args.expected_image_ref,
                expected_image_id=args.expected_image_id,
            )
            print(info.manifest_digest)
        elif args.command == "current-target":
            print(current_target(args.output_root, allow_missing=args.allow_missing))
        elif args.command == "switch-current":
            print(
                switch_current(
                    args.output_root,
                    args.release,
                    expected_current=args.expected_current,
                )
            )
        elif args.command == "clear-current":
            clear_current(args.output_root, expected_current=args.expected_current)
        elif args.command == "restore-current":
            restore_current(
                args.output_root,
                candidate_current=args.candidate_current,
                previous_current=args.previous_current,
            )
        elif args.command == "prune-releases":
            print(prune_releases(args.output_root, keep_targets=args.keep_target))
        else:
            probe_builder(builder=args.builder, release=args.release, run_id=args.run_id)
    except (OCIExportError, OSError, tarfile.TarError, ValueError) as exc:
        print(exc, file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
