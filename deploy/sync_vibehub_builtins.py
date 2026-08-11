#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""把 Git 跟踪的 VibeHub 内置规范包原子同步到 ignored 上传目录。"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.prepare_arc_agi_3 import ArcPublicSetError, _validate_cached_set
from oj_modules.vibehub import storage


BUILTIN_SLUGS = ("circle-cat", "arc-agi-3")
DEPLOYMENT_SCHEMA_VERSION = 1
EXPECTED_ARC_GAME_COUNT = 25
_RELEASE_NAME_RE = re.compile(r"^[0-9a-f]{64}$")
_TRANSIENT_RELEASE_RE = re.compile(
    r"^\.(?:[0-9a-f]{64}\.corrupt-|staging-)[0-9a-f]{32}$"
)


class BuiltinSyncError(RuntimeError):
    """内置作品无法安全同步。"""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_sha256(root: Path, files: list[Path] | None = None) -> str:
    """按相对路径、长度和内容计算与 mtime/宿主权限无关的确定性摘要。"""
    root = root.resolve(strict=True)
    selected = files
    if selected is None:
        selected = [path for path in root.rglob("*") if path.is_file()]
    selected = sorted(
        selected,
        key=lambda path: Path(path).absolute().relative_to(root).as_posix(),
    )
    digest = hashlib.sha256(b"NumericalOJ VibeHub tree v1\0")
    seen = set()
    for candidate in selected:
        path = Path(candidate)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise BuiltinSyncError(f"规范源文件无法读取：{path}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise BuiltinSyncError(f"规范源只允许普通文件：{path}")
        try:
            relative = path.absolute().relative_to(root).as_posix()
        except (OSError, ValueError) as exc:
            raise BuiltinSyncError(f"规范源文件越出目录：{path}") from exc
        if relative in seen:
            raise BuiltinSyncError(f"规范源包含重复路径：{relative}")
        seen.add(relative)
        content_digest = _sha256_file(path)
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(metadata.st_size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(content_digest))
    if not seen:
        raise BuiltinSyncError(f"规范源为空：{root}")
    return digest.hexdigest()


def _tracked_source_files(repository_root: Path, source_dir: Path) -> list[Path]:
    repository_root = repository_root.resolve(strict=True)
    source_dir = source_dir.resolve(strict=True)
    try:
        relative_source = source_dir.relative_to(repository_root).as_posix()
    except ValueError as exc:
        raise BuiltinSyncError("VibeHub 规范源必须位于 Git 仓库内") from exc
    result = subprocess.run(
        ["git", "-C", str(repository_root), "ls-files", "-z", "--", relative_source],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise BuiltinSyncError(f"无法读取 Git 跟踪文件：{message or result.returncode}")
    files = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        try:
            text = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BuiltinSyncError("Git 跟踪路径不是 UTF-8") from exc
        candidate = (repository_root / text).absolute()
        if not candidate.exists() and not candidate.is_symlink():
            raise BuiltinSyncError(f"Git 跟踪文件不存在：{text}")
        try:
            candidate.relative_to(source_dir)
        except ValueError as exc:
            raise BuiltinSyncError(f"Git 返回了越界规范源路径：{text}") from exc
        files.append(candidate)
    if not files:
        raise BuiltinSyncError(f"规范源没有 Git 跟踪文件：{relative_source}")
    required = {source_dir / "Dockerfile", source_dir / storage.MANIFEST_FILENAME}
    if not required.issubset(set(files)):
        raise BuiltinSyncError(f"规范源缺少已跟踪的 Dockerfile 或 {storage.MANIFEST_FILENAME}")
    return sorted(files, key=lambda path: path.relative_to(source_dir).as_posix())


def _copy_selected(source_root: Path, files: list[Path], destination: Path) -> None:
    destination.mkdir(parents=True, mode=0o700)
    for source in files:
        relative = source.relative_to(source_root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(source, target)
        target.chmod(0o600)


def _harden_tree(root: Path) -> None:
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        current = Path(current_root)
        current.chmod(0o700)
        for name in directories:
            target = current / name
            if target.is_symlink():
                raise BuiltinSyncError(f"部署树不得包含符号链接：{target}")
            target.chmod(0o700)
        for name in filenames:
            target = current / name
            if target.is_symlink():
                raise BuiltinSyncError(f"部署树不得包含符号链接：{target}")
            target.chmod(0o600)


def _atomic_json(path: Path, payload: dict) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _prune_old_releases(releases_root: Path, current_release: str) -> None:
    """部署标记成功后仅保留当前 release；遇到异常节点立即拒绝删除。"""
    if not _RELEASE_NAME_RE.fullmatch(current_release):
        raise BuiltinSyncError("当前内置 release 标识无效")
    removable = []
    for candidate in list(releases_root.iterdir()):
        if candidate.name == current_release:
            continue
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BuiltinSyncError(f"内置 releases 含异常节点，拒绝清理：{candidate}")
        if not (
            _RELEASE_NAME_RE.fullmatch(candidate.name)
            or _TRANSIENT_RELEASE_RE.fullmatch(candidate.name)
        ):
            raise BuiltinSyncError(f"内置 release 名称异常，拒绝清理：{candidate.name}")
        removable.append(candidate)
    for candidate in removable:
        shutil.rmtree(candidate)


def finalize_builtin(slug: str, *, upload_root: Path) -> str:
    """在整次部署通过健康检查后，清理某个内置作品的旧 release。"""
    if slug not in BUILTIN_SLUGS:
        raise BuiltinSyncError(f"未知内置作品：{slug}")
    try:
        deployment = storage.resolve_builtin_deployment(
            slug,
            upload_root=upload_root,
        )
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise BuiltinSyncError(f"内置作品当前 release 无法解析：{slug}") from exc
    current_release = str(deployment.get("release") or "")
    releases_root = upload_root / slug / "builtin" / "releases"
    try:
        resolved_releases = releases_root.resolve(strict=True)
    except OSError as exc:
        raise BuiltinSyncError(f"内置作品 releases 目录不存在：{slug}") from exc
    expected_releases = (
        upload_root.resolve(strict=True) / slug / "builtin" / "releases"
    )
    if resolved_releases != expected_releases:
        raise BuiltinSyncError(f"内置作品 releases 目录不得是符号链接：{slug}")
    _prune_old_releases(resolved_releases, current_release)
    return current_release


def _validated_arc_set(arc_set: Path) -> tuple[Path, dict]:
    try:
        resolved = arc_set.resolve(strict=True)
        manifest = _validate_cached_set(resolved, EXPECTED_ARC_GAME_COUNT)
    except (OSError, ArcPublicSetError) as exc:
        raise BuiltinSyncError(f"ARC-AGI-3 官方离线集校验失败：{exc}") from exc
    if manifest.get("game_count") != EXPECTED_ARC_GAME_COUNT:
        raise BuiltinSyncError("ARC-AGI-3 官方离线集必须恰好包含 25 个环境")
    return resolved, manifest


def _current_matches(
    slug: str,
    *,
    upload_root: Path,
    source_sha256: str,
    arc_set_id: str | None,
) -> bool:
    try:
        deployment = storage.resolve_builtin_deployment(slug, upload_root=upload_root)
    except (FileNotFoundError, RuntimeError, ValueError):
        return False
    if (
        deployment.get("source_sha256") != source_sha256
        or deployment.get("arc_set_id") != arc_set_id
    ):
        return False
    package_dir = Path(deployment["package_dir"])
    if _tree_sha256(package_dir) != deployment.get("package_sha256"):
        return False
    try:
        storage.validate_manifest(package_dir)
        cover = storage.processed_cover_path(package_dir)
        cover_metadata = cover.lstat()
        expected_cover_sha256 = deployment.get("cover_sha256")
        if (
            not stat.S_ISREG(cover_metadata.st_mode)
            or cover_metadata.st_size <= 0
            or cover_metadata.st_size > storage.MAX_PROCESSED_COVER_BYTES
            or not isinstance(expected_cover_sha256, str)
            or not _RELEASE_NAME_RE.fullmatch(expected_cover_sha256)
            or _sha256_file(cover) != expected_cover_sha256
        ):
            return False
    except (OSError, storage.PackageValidationError):
        return False
    return True


def sync_builtin(
    slug: str,
    *,
    repository_root: Path,
    source_root: Path,
    upload_root: Path,
    arc_set: Path | None = None,
) -> tuple[str, str]:
    if slug not in BUILTIN_SLUGS:
        raise BuiltinSyncError(f"未知内置作品：{slug}")
    source_dir = (source_root / slug).resolve(strict=True)
    tracked_files = _tracked_source_files(repository_root, source_dir)
    source_sha256 = _tree_sha256(source_dir, tracked_files)

    resolved_arc_set = None
    arc_manifest = None
    arc_set_id = None
    if slug == "arc-agi-3":
        if arc_set is None:
            raise BuiltinSyncError("ARC-AGI-3 同步必须提供经过校验的官方离线集")
        resolved_arc_set, arc_manifest = _validated_arc_set(arc_set)
        arc_set_id = str(arc_manifest["set_id"])

    upload_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    upload_root.chmod(0o700)
    if _current_matches(
        slug,
        upload_root=upload_root,
        source_sha256=source_sha256,
        arc_set_id=arc_set_id,
    ):
        return "unchanged", source_sha256

    builtin_root = upload_root / slug / "builtin"
    releases_root = builtin_root / "releases"
    releases_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    releases_root.chmod(0o700)
    staging = builtin_root / f".staging-{uuid.uuid4().hex}"
    app_dir = staging / "app"
    try:
        _copy_selected(source_dir, tracked_files, app_dir)
        if resolved_arc_set is not None:
            shutil.copytree(
                resolved_arc_set,
                app_dir / "offline_data",
                copy_function=shutil.copyfile,
            )
        manifest = storage.validate_manifest(app_dir)
        storage.generate_processed_cover(
            manifest["cover_image"],
            app_dir,
            staging / storage.PROCESSED_COVER_FILENAME,
        )
        cover_sha256 = _sha256_file(
            staging / storage.PROCESSED_COVER_FILENAME
        )
        _harden_tree(staging)
        package_sha256 = _tree_sha256(app_dir)
        release = releases_root / package_sha256
        deployment = {
            "schema_version": DEPLOYMENT_SCHEMA_VERSION,
            "slug": slug,
            "source_sha256": source_sha256,
            "package_sha256": package_sha256,
            "cover_sha256": cover_sha256,
            "arc_set_id": arc_set_id,
            "arc_game_count": (
                int(arc_manifest["game_count"]) if arc_manifest is not None else None
            ),
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_json(staging / "deployment.json", deployment)
        if release.exists():
            try:
                existing_matches = (
                    _tree_sha256(release / "app") == package_sha256
                    and (release / storage.PROCESSED_COVER_FILENAME).read_bytes()
                    == (staging / storage.PROCESSED_COVER_FILENAME).read_bytes()
                )
            except (OSError, BuiltinSyncError):
                existing_matches = False
            if existing_matches:
                shutil.rmtree(staging)
            else:
                quarantine = releases_root / f".{package_sha256}.corrupt-{uuid.uuid4().hex}"
                os.replace(release, quarantine)
                try:
                    os.replace(staging, release)
                except Exception:
                    os.replace(quarantine, release)
                    raise
        else:
            os.replace(staging, release)

        pointer = dict(deployment)
        pointer["release"] = package_sha256
        _atomic_json(builtin_root / "current.json", pointer)
        return "updated", source_sha256
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    repository_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="同步 Git 跟踪的 VibeHub 内置作品到 uploads/vibehub。",
    )
    parser.add_argument("--repository-root", type=Path, default=repository_root)
    parser.add_argument(
        "--source-root", type=Path, default=repository_root / "vibehub_examples",
    )
    parser.add_argument(
        "--upload-root", type=Path, default=repository_root / "uploads" / "vibehub",
    )
    parser.add_argument("--arc-set", type=Path)
    parser.add_argument(
        "--finalize-only",
        action="store_true",
        help="部署成功后仅清理旧 release，不同步或切换当前指针。",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.finalize_only:
            for slug in BUILTIN_SLUGS:
                release = finalize_builtin(slug, upload_root=args.upload_root)
                print(f"VibeHub 内置作品 {slug}: finalized ({release})")
            return 0
        if args.arc_set is None:
            raise BuiltinSyncError("同步内置作品时必须提供 --arc-set")
        for slug in BUILTIN_SLUGS:
            status, source_sha256 = sync_builtin(
                slug,
                repository_root=args.repository_root,
                source_root=args.source_root,
                upload_root=args.upload_root,
                arc_set=args.arc_set if slug == "arc-agi-3" else None,
            )
            print(f"VibeHub 内置作品 {slug}: {status} ({source_sha256})")
    except (BuiltinSyncError, OSError, subprocess.SubprocessError) as exc:
        print(f"VibeHub 内置作品同步失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
