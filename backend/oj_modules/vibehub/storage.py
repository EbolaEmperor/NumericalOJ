"""VibeHub 不可变作品包快照与指针存储。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import time
from typing import BinaryIO
import uuid
import zipfile

from PIL import Image, ImageOps, UnidentifiedImageError

from backend.oj_modules.project_paths import PROJECT_ROOT
from backend.oj_modules.shared.archive import (
    ArchiveExtractionError,
    ZipExtractionPolicy,
    extract_zip,
)
from backend.oj_modules.vibehub import quotas


VIBEHUB_UPLOAD_ROOT = PROJECT_ROOT / "uploads" / "vibehub"
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 20_000
MAX_COMPRESSION_RATIO = 200.0
MANIFEST_FILENAME = "vibehub.json"
DOCKERFILE_NAME = "Dockerfile"
SOCKET_PATH = "/run/vibehub/app.sock"
HEALTH_PATH = "/healthz"
MAX_COVER_PIXELS = 16_000_000
MAX_COVER_DIMENSION = 8192
MAX_COVER_SOURCE_BYTES = 16 * 1024 * 1024
MAX_PROCESSED_COVER_BYTES = 400 * 1024
PROCESSED_COVER_FILENAME = "cover.jpg"
PROCESSED_COVER_SIZE = (1280, 720)
_COVER_MIME_TYPES = {
    "PNG": "image/png",
    "JPEG": "image/jpeg",
    "WEBP": "image/webp",
}
_STORAGE_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
_VERSION_DIRECTORY_RE = re.compile(r"^v([1-9][0-9]*)$")
_CLONE_STAGING_RE = re.compile(r"^\.v([1-9][0-9]*)\.clone-([0-9a-f]{32})$")
_RETIREMENT_MARKER_RE = re.compile(r"^v([1-9][0-9]*)\.json$")
_RETIREMENT_TEMP_RE = re.compile(r"^\.marker-([0-9a-f]{32})\.tmp$")
_RETIREMENT_MARKER_SCHEMA_VERSION = 2
# runtime 在 resolve 返回后才开始构建，不能用短暂读锁覆盖整个构建。
# 建造硬超时为 15 分钟；1 小时退役宽限覆盖排队、构建和启动余量。
SNAPSHOT_RETIREMENT_GRACE_SECONDS = 60 * 60
CRASH_ORPHAN_GRACE_SECONDS = 60 * 60
CRASH_ORPHAN_MARKER_DIRECTORY = ".orphan-gc"
_CRASH_ORPHAN_MARKER_SCHEMA_VERSION = 2
_CRASH_ORPHAN_MARKER_RE = re.compile(r"^([0-9a-f]{64})\.json$")
_CRASH_ORPHAN_TEMP_RE = re.compile(r"^\.marker-([0-9a-f]{32})\.tmp$")
_STORAGE_SLOT_LOCK_RE = re.compile(r"^\.storage-mutation-slot-([0-7])\.lock$")
_MAX_CRASH_ORPHAN_MARKER_BYTES = 2048
_MAX_CRASH_ORPHAN_ROOT_ENTRIES = 100_000
_MAX_RETIREMENT_MARKER_BYTES = 1024
_LOGGER = logging.getLogger(__name__)


class PackageValidationError(ValueError):
    """用户上传的 VibeHub 作品包不符合公开契约。"""


class SnapshotReconciliationError(RuntimeError):
    """持久快照树无法在 fail-closed 前提下恢复或回收。"""


@dataclass(frozen=True, slots=True)
class SnapshotReconcileResult:
    """一次 live-set 对齐所保留、标记和删除的版本号。"""

    retained: tuple[int, ...]
    newly_retired: tuple[int, ...]
    deleted_expired: tuple[int, ...]
    deleted_orphans: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class SnapshotRetirementGCResult:
    """配额扫描前一次用户退役快照回收的审计结果。"""

    inspected_projects: tuple[str, ...]
    newly_retired: tuple[tuple[str, int], ...]
    deleted_expired: tuple[tuple[str, int], ...]
    reclaimed_bytes: int


@dataclass(frozen=True, slots=True)
class CrashOrphanGCResult:
    """未提交项目、版本与 clone 的延时回收审计结果。"""

    inspected_projects: tuple[str, ...]
    newly_marked: tuple[str, ...]
    refreshed_markers: tuple[str, ...]
    deleted_expired: tuple[str, ...]
    deleted_stale_markers: tuple[str, ...]
    reclaimed_bytes: int


@dataclass(frozen=True, slots=True)
class _RetirementMarker:
    path: Path
    retired_at: float
    snapshot_device: int
    snapshot_inode: int


@dataclass(frozen=True, slots=True)
class _CrashOrphanCandidate:
    key: str
    kind: str
    slug: str
    path: Path
    target_device: int
    target_inode: int
    target_ctime_ns: int
    version: int | None = None
    clone: str | None = None


@dataclass(frozen=True, slots=True)
class _CrashOrphanMarker:
    path: Path
    key: str
    kind: str
    slug: str
    orphaned_at: float
    target_device: int
    target_inode: int
    target_ctime_ns: int | None
    version: int | None = None
    clone: str | None = None


@dataclass
class PreparedPackage:
    """已校验但尚未安装到版本目录的临时快照。"""

    staging_root: Path
    snapshot_dir: Path
    package_sha256: str
    package_size: int
    manifest: dict

    def cleanup(self) -> None:
        shutil.rmtree(self.staging_root, ignore_errors=True)


def _root(upload_root=None) -> Path:
    return Path(upload_root) if upload_root is not None else VIBEHUB_UPLOAD_ROOT


def _safe_slug(value) -> str:
    slug = str(value or "")
    if not _STORAGE_SLUG_RE.fullmatch(slug):
        raise ValueError("invalid VibeHub storage slug")
    return slug


def _ensure_private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def _harden_snapshot_tree(snapshot: Path) -> None:
    """宿主存储不依赖进程 umask，用户源码只允许服务账号读取。"""
    for current_root, directories, filenames in os.walk(snapshot, followlinks=False):
        current = Path(current_root)
        current.chmod(0o700)
        for name in directories:
            (current / name).chmod(0o700)
        for name in filenames:
            (current / name).chmod(0o600)


def _stream_for_upload(upload) -> BinaryIO:
    stream = getattr(upload, "stream", upload)
    if not hasattr(stream, "read"):
        raise PackageValidationError("请上传 ZIP 格式的完整作品包")
    try:
        stream.seek(0)
    except (AttributeError, OSError):
        pass
    return stream


def _save_limited_archive(upload, destination: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    stream = _stream_for_upload(upload)
    with destination.open("xb") as output:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise PackageValidationError("压缩包不能超过 256 MiB")
            digest.update(chunk)
            output.write(chunk)
    destination.chmod(0o600)
    if total <= 0:
        raise PackageValidationError("压缩包不能为空")
    return digest.hexdigest(), total


def validate_cover_image(value, app_dir: Path) -> tuple[str, str]:
    """校验必填封面的路径和真实格式；比例由平台安全副本统一处理。"""
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        raise PackageValidationError("vibehub.json 必须声明 cover_image")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or text.startswith("."):
        raise PackageValidationError("cover_image 必须是作品包内的安全相对路径")
    target = (app_dir / Path(*path.parts)).resolve()
    try:
        target.relative_to(app_dir.resolve())
    except ValueError as exc:
        raise PackageValidationError("cover_image 越出作品包边界") from exc
    if not target.is_file():
        raise PackageValidationError("cover_image 指向的文件不存在")
    try:
        cover_size = target.stat().st_size
    except OSError as exc:
        raise PackageValidationError("cover_image 无法读取") from exc
    if cover_size <= 0 or cover_size > MAX_COVER_SOURCE_BYTES:
        raise PackageValidationError("cover_image 原图不能超过 16 MiB")
    try:
        with Image.open(target) as image:
            image_format = str(image.format or "").upper()
            width, height = image.size
            if image_format not in _COVER_MIME_TYPES:
                raise PackageValidationError("cover_image 仅支持 PNG、JPEG 或 WebP")
            if (
                width <= 0
                or height <= 0
                or width > MAX_COVER_DIMENSION
                or height > MAX_COVER_DIMENSION
                or width * height > MAX_COVER_PIXELS
            ):
                raise PackageValidationError("cover_image 像素尺寸超出限制")
            image.verify()
    except PackageValidationError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise PackageValidationError("cover_image 像素尺寸超出限制") from exc
    except (OSError, UnidentifiedImageError, ValueError) as exc:
        raise PackageValidationError("cover_image 不是有效的 PNG、JPEG 或 WebP 图片") from exc
    return path.as_posix(), _COVER_MIME_TYPES[image_format]


def _cover_crop_box(width: int, height: int) -> tuple[int, int, int, int]:
    """返回确定性的 16:9 中心裁切框，奇数余量留在右侧或下侧。"""
    if width * 9 == height * 16:
        return 0, 0, width, height
    if width * 9 < height * 16:
        cropped_height = max(1, width * 9 // 16)
        top = (height - cropped_height) // 2
        return 0, top, width, top + cropped_height
    cropped_width = max(1, height * 16 // 9)
    left = (width - cropped_width) // 2
    return left, 0, left + cropped_width, height


def generate_processed_cover(value, app_dir: Path, destination: Path) -> tuple[Path, str]:
    """中心裁切并生成不含元数据、严格 16:9 且不超过 400 KiB 的 JPEG。"""
    normalized, _source_mime = validate_cover_image(value, app_dir)
    source = (app_dir / Path(*PurePosixPath(normalized).parts)).resolve()
    try:
        with Image.open(source) as opened:
            image = ImageOps.exif_transpose(opened)
            image.load()
            if image.mode not in {"RGB", "L"}:
                rgba = image.convert("RGBA")
                background = Image.new("RGBA", rgba.size, (255, 250, 240, 255))
                background.alpha_composite(rgba)
                image = background.convert("RGB")
            else:
                image = image.convert("RGB")
            image = image.crop(_cover_crop_box(*image.size))
            image = image.resize(PROCESSED_COVER_SIZE, Image.Resampling.LANCZOS)
    except (OSError, UnidentifiedImageError, ValueError) as exc:
        raise PackageValidationError("cover_image 无法生成安全封面副本") from exc

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = destination.with_name(f".{destination.name}.tmp-{uuid.uuid4().hex}")
    try:
        encoded = None
        for quality in (88, 82, 76, 70, 64, 58, 52, 46, 40, 34):
            candidate = tempfile.SpooledTemporaryFile(max_size=MAX_PROCESSED_COVER_BYTES)
            image.save(
                candidate,
                format="JPEG",
                quality=quality,
                optimize=True,
                progressive=False,
                subsampling=2,
                exif=b"",
            )
            candidate.seek(0, os.SEEK_END)
            size = candidate.tell()
            if 0 < size <= MAX_PROCESSED_COVER_BYTES:
                candidate.seek(0)
                encoded = candidate.read()
                candidate.close()
                break
            candidate.close()
        if encoded is None:
            raise PackageValidationError("cover_image 无法压缩到 400 KiB 以内")
        temporary.write_bytes(encoded)
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        destination.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return destination, "image/jpeg"


def processed_cover_path(app_dir: Path) -> Path:
    """返回不可变版本快照中的平台安全封面副本。"""
    return Path(app_dir).resolve().parent / PROCESSED_COVER_FILENAME


def validate_manifest(app_dir: Path) -> dict:
    """校验并返回可安全对外使用的 manifest 子集。"""
    dockerfile = app_dir / DOCKERFILE_NAME
    manifest_path = app_dir / MANIFEST_FILENAME
    if not dockerfile.is_file():
        raise PackageValidationError("作品包根目录必须包含 Dockerfile")
    if not manifest_path.is_file():
        raise PackageValidationError("作品包根目录必须包含 vibehub.json")
    if manifest_path.stat().st_size > 64 * 1024:
        raise PackageValidationError("vibehub.json 不能超过 64 KiB")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageValidationError("vibehub.json 必须是有效的 UTF-8 JSON") from exc
    if not isinstance(manifest, dict):
        raise PackageValidationError("vibehub.json 顶层必须是 JSON 对象")
    if manifest.get("schema_version") != 1:
        raise PackageValidationError("vibehub.json schema_version 必须为 1")
    if manifest.get("transport") != "unix":
        raise PackageValidationError("vibehub.json transport 必须为 unix")
    if manifest.get("socket_path") != SOCKET_PATH:
        raise PackageValidationError(f"socket_path 必须为 {SOCKET_PATH}")
    if manifest.get("health_path") != HEALTH_PATH:
        raise PackageValidationError(f"health_path 必须为 {HEALTH_PATH}")
    if "port" in manifest:
        raise PackageValidationError("作品不得声明网络端口，请使用固定 Unix socket")

    normalized = {
        "schema_version": 1,
        "transport": "unix",
        "socket_path": SOCKET_PATH,
        "health_path": HEALTH_PATH,
    }
    cover_image, cover_image_mime = validate_cover_image(
        manifest.get("cover_image"), app_dir,
    )
    normalized["cover_image"] = cover_image
    normalized["cover_image_mime"] = cover_image_mime
    for field, limit in (("title", 120), ("summary", 500)):
        value = str(manifest.get(field) or "").strip()
        if value:
            normalized[field] = value[:limit]
    raw_tags = manifest.get("tags")
    if raw_tags is not None:
        if not isinstance(raw_tags, list):
            raise PackageValidationError("tags 必须是字符串数组")
        normalized["tags"] = [str(item).strip() for item in raw_tags]
    return normalized


def prepare_uploaded_package(upload, *, upload_root=None) -> PreparedPackage:
    """流式保存、受限解压并校验一个用户作品包。"""
    root = _root(upload_root)
    staging_root = quotas.create_upload_staging_directory(root)
    snapshot = staging_root / "snapshot"
    app_dir = snapshot / "app"
    package_path = snapshot / "package.zip"
    snapshot.mkdir(mode=0o700)
    try:
        package_sha256, package_size = _save_limited_archive(upload, package_path)
        policy = ZipExtractionPolicy(
            max_members=MAX_MEMBERS,
            max_file_bytes=MAX_FILE_BYTES,
            max_total_bytes=MAX_EXTRACTED_BYTES,
            max_compression_ratio=MAX_COMPRESSION_RATIO,
            require_non_empty=True,
            reject_encrypted=True,
            reject_symlinks=True,
            reject_duplicate_targets=True,
            unsafe_member_action="raise",
            cleanup_on_error=True,
        )
        extract_zip(package_path, app_dir, policy=policy)
        manifest = validate_manifest(app_dir)
        generate_processed_cover(
            manifest["cover_image"], app_dir, snapshot / PROCESSED_COVER_FILENAME,
        )
        _harden_snapshot_tree(snapshot)
        return PreparedPackage(
            staging_root=staging_root,
            snapshot_dir=snapshot,
            package_sha256=package_sha256,
            package_size=package_size,
            manifest=manifest,
        )
    except PackageValidationError:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise
    except ArchiveExtractionError as exc:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise PackageValidationError(f"压缩包未通过安全校验：{exc.reason}") from exc
    except zipfile.BadZipFile as exc:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise PackageValidationError("上传文件不是有效的 ZIP 压缩包") from exc
    except Exception:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise


def project_root(slug: str, *, upload_root=None) -> Path:
    return _root(upload_root) / _safe_slug(slug)


def version_snapshot_path(slug: str, version_number: int, *, upload_root=None) -> Path:
    return project_root(slug, upload_root=upload_root) / "versions" / f"v{int(version_number)}"


def install_prepared_snapshot(
    prepared: PreparedPackage,
    slug: str,
    version_number: int,
    *,
    upload_root=None,
) -> Path:
    """将临时快照以不可变版本号原子安装。"""
    target = version_snapshot_path(slug, version_number, upload_root=upload_root)
    root = _ensure_private_directory(_root(upload_root))
    project = _ensure_private_directory(root / _safe_slug(slug))
    target_parent = _ensure_private_directory(project / "versions")
    target = target_parent / f"v{int(version_number)}"
    if target.exists():
        raise FileExistsError(f"VibeHub version snapshot already exists: {target}")
    os.replace(prepared.snapshot_dir, target)
    shutil.rmtree(prepared.staging_root, ignore_errors=True)
    return target


def clone_snapshot(
    slug: str,
    source_version: int,
    target_version: int,
    *,
    upload_root=None,
) -> Path:
    """为纯元数据编辑创建一个新的不可变包快照。"""
    source = version_snapshot_path(slug, source_version, upload_root=upload_root)
    root = _ensure_private_directory(_root(upload_root))
    project = _ensure_private_directory(root / _safe_slug(slug))
    target_parent = _ensure_private_directory(project / "versions")
    target = target_parent / f"v{int(target_version)}"
    if not source.is_dir():
        raise FileNotFoundError(f"VibeHub source snapshot is missing: {source}")
    if target.exists():
        raise FileExistsError(f"VibeHub version snapshot already exists: {target}")
    staging = target.parent / f".{target.name}.clone-{uuid.uuid4().hex}"
    try:
        shutil.copytree(source, staging, copy_function=shutil.copy2)
        _harden_snapshot_tree(staging)
        os.replace(staging, target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target


def remove_version_snapshot(slug: str, version_number: int, *, upload_root=None) -> None:
    shutil.rmtree(
        version_snapshot_path(slug, version_number, upload_root=upload_root),
        ignore_errors=True,
    )


def _real_directory(path: Path, *, label: str, missing_ok=False) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return False
        raise SnapshotReconciliationError(f"{label}不存在")
    except OSError as exc:
        raise SnapshotReconciliationError(f"{label}无法读取") from exc
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise SnapshotReconciliationError(f"{label}必须是真实目录")
    return True


def _regular_control_file(path: Path, *, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SnapshotReconciliationError(f"{label}无法读取") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
    ):
        raise SnapshotReconciliationError(f"{label}类型、链接数或属主异常")
    return info


def _strict_version_entries(slug: str, *, upload_root=None):
    project = project_root(slug, upload_root=upload_root)
    if not _real_directory(project, label="VibeHub 作品目录", missing_ok=True):
        return None, {}, []
    versions = project / "versions"
    if not _real_directory(versions, label="VibeHub versions 目录", missing_ok=True):
        return versions, {}, []
    physical: dict[int, Path] = {}
    clones: list[tuple[int, Path]] = []
    try:
        entries = list(os.scandir(versions))
    except OSError as exc:
        raise SnapshotReconciliationError("VibeHub versions 目录无法扫描") from exc
    for entry in entries:
        version_match = _VERSION_DIRECTORY_RE.fullmatch(entry.name)
        clone_match = _CLONE_STAGING_RE.fullmatch(entry.name)
        if not version_match and not clone_match:
            raise SnapshotReconciliationError(
                f"VibeHub versions 目录包含未知入口：{entry.name}"
            )
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise SnapshotReconciliationError(
                f"VibeHub 版本入口无法读取：{entry.name}"
            ) from exc
        if not stat.S_ISDIR(info.st_mode) or entry.is_symlink():
            raise SnapshotReconciliationError(
                f"VibeHub 版本入口必须是真实目录：{entry.name}"
            )
        if version_match:
            number = int(version_match.group(1))
            if number in physical:
                raise SnapshotReconciliationError(f"VibeHub 版本号重复：v{number}")
            physical[number] = Path(entry.path)
        else:
            clones.append((int(clone_match.group(1)), Path(entry.path)))
    return versions, physical, clones


def _retirement_markers(slug: str, *, upload_root=None):
    project = project_root(slug, upload_root=upload_root)
    gc_root = project / ".gc"
    if not _real_directory(gc_root, label="VibeHub .gc 目录", missing_ok=True):
        return gc_root, {}, []
    markers = {}
    temporary_files = []
    try:
        entries = list(os.scandir(gc_root))
    except OSError as exc:
        raise SnapshotReconciliationError("VibeHub .gc 目录无法扫描") from exc
    for entry in entries:
        matched = _RETIREMENT_MARKER_RE.fullmatch(entry.name)
        if _RETIREMENT_TEMP_RE.fullmatch(entry.name):
            path = Path(entry.path)
            _regular_control_file(path, label=f"VibeHub 回收临时标记 {entry.name}")
            temporary_files.append(path)
            continue
        if not matched:
            raise SnapshotReconciliationError(
                f"VibeHub .gc 目录包含未知入口：{entry.name}"
            )
        path = Path(entry.path)
        info = _regular_control_file(path, label=f"VibeHub 回收标记 {entry.name}")
        if info.st_size <= 0 or info.st_size > _MAX_RETIREMENT_MARKER_BYTES:
            raise SnapshotReconciliationError(f"VibeHub 回收标记大小异常：{entry.name}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("retirement marker must be an object")
            raw_retired_at = payload.get("retired_at")
            if isinstance(raw_retired_at, bool) or not isinstance(
                raw_retired_at,
                (int, float),
            ):
                raise TypeError("retired_at must be numeric")
            retired_at = float(raw_retired_at)
            raw_device = payload.get("snapshot_device")
            raw_inode = payload.get("snapshot_inode")
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise SnapshotReconciliationError(
                f"VibeHub 回收标记无法解析：{entry.name}"
            ) from exc
        number = int(matched.group(1))
        if (
            payload.get("schema_version") != _RETIREMENT_MARKER_SCHEMA_VERSION
            or isinstance(payload.get("version"), bool)
            or payload.get("version") != number
            or isinstance(raw_device, bool)
            or not isinstance(raw_device, int)
            or raw_device < 0
            or isinstance(raw_inode, bool)
            or not isinstance(raw_inode, int)
            or raw_inode <= 0
            or not math.isfinite(retired_at)
            or retired_at < 0
        ):
            raise SnapshotReconciliationError(f"VibeHub 回收标记内容异常：{entry.name}")
        markers[number] = _RetirementMarker(
            path=path,
            retired_at=retired_at,
            snapshot_device=int(raw_device),
            snapshot_inode=int(raw_inode),
        )
    return gc_root, markers, temporary_files


def _validate_removable_directory(path: Path) -> None:
    if not _real_directory(path, label=f"VibeHub 待回收目录 {path.name}"):
        return
    # 局部导入避免存储初始化与配额常量形成隐式环。
    from backend.oj_modules.vibehub import quotas

    quotas.logical_tree_bytes(path)


def _remove_validated_directory(path: Path) -> None:
    if not shutil.rmtree.avoids_symlink_attacks:
        raise SnapshotReconciliationError("Python 平台不支持抗符号链接的目录回收")
    try:
        shutil.rmtree(path)
    except OSError as exc:
        raise SnapshotReconciliationError(f"VibeHub 目录回收失败：{path.name}") from exc


def _normalize_version_set(values, *, label: str) -> set[int]:
    try:
        normalized = set(values)
    except TypeError as exc:
        raise SnapshotReconciliationError(f"{label}无效") from exc
    result = set()
    for value in normalized:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise SnapshotReconciliationError(f"{label}必须只包含正整数")
        result.add(int(value))
    return result


def _write_retirement_marker(
    gc_root: Path,
    version_number: int,
    retired_at: float,
    snapshot: Path,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> Path:
    gc_root.mkdir(parents=False, exist_ok=True, mode=0o700)
    _real_directory(gc_root, label="VibeHub .gc 目录")
    gc_root.chmod(0o700)
    if not _real_directory(snapshot, label=f"VibeHub v{int(version_number)} 快照"):
        raise SnapshotReconciliationError("VibeHub 退役快照不存在")
    snapshot_identity = _snapshot_identity(
        snapshot,
        label=f"VibeHub v{int(version_number)} 快照",
    )
    if expected_identity is not None and snapshot_identity != expected_identity:
        raise SnapshotReconciliationError("VibeHub 退役快照在 marker 写入前被替换")
    path = gc_root / f"v{int(version_number)}.json"
    temporary = gc_root / f".marker-{uuid.uuid4().hex}.tmp"
    payload = {
        "schema_version": _RETIREMENT_MARKER_SCHEMA_VERSION,
        "version": int(version_number),
        "retired_at": float(retired_at),
        "snapshot_device": snapshot_identity[0],
        "snapshot_inode": snapshot_identity[1],
    }
    try:
        with temporary.open("x", encoding="utf-8") as output:
            output.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
        directory_fd = os.open(gc_root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def _remove_marker(path: Path) -> None:
    _regular_control_file(path, label=f"VibeHub 回收标记 {path.name}")
    try:
        path.unlink()
    except OSError as exc:
        raise SnapshotReconciliationError(f"VibeHub 回收标记无法删除：{path.name}") from exc


def _crash_orphan_key(
    kind: str,
    slug: str,
    *,
    version: int | None = None,
    clone: str | None = None,
) -> str:
    safe_slug = _safe_slug(slug)
    if kind == "project" and version is None and clone is None:
        return f"project:{safe_slug}"
    if (
        kind == "version"
        and isinstance(version, int)
        and not isinstance(version, bool)
        and version > 0
        and clone is None
    ):
        return f"version:{safe_slug}:v{version}"
    if kind == "clone" and isinstance(clone, str):
        matched = _CLONE_STAGING_RE.fullmatch(clone)
        if (
            matched
            and isinstance(version, int)
            and not isinstance(version, bool)
            and int(matched.group(1)) == version
        ):
            return f"clone:{safe_slug}:{clone}"
    raise SnapshotReconciliationError("VibeHub 崩溃孤儿标识无效")


def _managed_directory_identity(
    path: Path,
    *,
    root_device: int,
    label: str,
    scan_tree: bool = True,
) -> tuple[int, int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SnapshotReconciliationError(f"{label}无法读取") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or path.is_symlink()
        or int(info.st_uid) != int(os.geteuid())
        or int(info.st_dev) != int(root_device)
    ):
        raise SnapshotReconciliationError(
            f"{label}必须是同设备、当前用户拥有的真实目录"
        )
    if scan_tree:
        try:
            quotas.logical_tree_bytes(path)
        except quotas.VibeHubStorageSecurityError as exc:
            raise SnapshotReconciliationError(f"{label}审计失败") from exc
    return int(info.st_dev), int(info.st_ino), int(info.st_ctime_ns)


def _managed_orphan_candidate(
    kind: str,
    slug: str,
    path: Path,
    *,
    root_device: int,
    version: int | None = None,
    clone: str | None = None,
) -> _CrashOrphanCandidate:
    target_device, target_inode, target_ctime_ns = _managed_directory_identity(
        path,
        root_device=root_device,
        label="VibeHub 崩溃孤儿目录",
    )
    key = _crash_orphan_key(
        kind,
        slug,
        version=version,
        clone=clone,
    )
    return _CrashOrphanCandidate(
        key=key,
        kind=kind,
        slug=slug,
        path=path,
        target_device=target_device,
        target_inode=target_inode,
        target_ctime_ns=target_ctime_ns,
        version=version,
        clone=clone,
    )


def _crash_orphan_marker_payload(
    candidate: _CrashOrphanCandidate,
    orphaned_at: float,
) -> dict:
    payload = {
        "schema_version": _CRASH_ORPHAN_MARKER_SCHEMA_VERSION,
        "key": candidate.key,
        "kind": candidate.kind,
        "slug": candidate.slug,
        "orphaned_at": float(orphaned_at),
        "target_device": candidate.target_device,
        "target_inode": candidate.target_inode,
        "target_ctime_ns": candidate.target_ctime_ns,
    }
    if candidate.version is not None:
        payload["version"] = candidate.version
    if candidate.clone is not None:
        payload["clone"] = candidate.clone
    return payload


def _write_crash_orphan_marker(
    marker_root: Path,
    candidate: _CrashOrphanCandidate,
    orphaned_at: float,
) -> Path:
    current_identity = _managed_directory_identity(
        candidate.path,
        root_device=candidate.target_device,
        label="VibeHub 崩溃孤儿目录",
        scan_tree=False,
    )
    if current_identity != (
        candidate.target_device,
        candidate.target_inode,
        candidate.target_ctime_ns,
    ):
        raise SnapshotReconciliationError("VibeHub 崩溃孤儿在 marker 写入前被替换")
    marker_root.mkdir(parents=False, exist_ok=True, mode=0o700)
    info = marker_root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or marker_root.is_symlink()
        or int(info.st_uid) != int(os.geteuid())
        or int(info.st_dev) != candidate.target_device
    ):
        raise SnapshotReconciliationError("VibeHub 崩溃孤儿 marker 目录异常")
    marker_root.chmod(0o700)
    marker_name = hashlib.sha256(candidate.key.encode("utf-8")).hexdigest() + ".json"
    path = marker_root / marker_name
    temporary = marker_root / f".marker-{uuid.uuid4().hex}.tmp"
    payload = _crash_orphan_marker_payload(candidate, orphaned_at)
    try:
        with temporary.open("x", encoding="utf-8") as output:
            output.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
        directory_fd = os.open(marker_root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def _crash_orphan_markers(marker_root: Path, *, root_device: int):
    if not _real_directory(
        marker_root,
        label="VibeHub 崩溃孤儿 marker 目录",
        missing_ok=True,
    ):
        return {}, []
    root_info = marker_root.lstat()
    if (
        int(root_info.st_uid) != int(os.geteuid())
        or int(root_info.st_dev) != int(root_device)
    ):
        raise SnapshotReconciliationError("VibeHub 崩溃孤儿 marker 目录异常")
    try:
        entries = list(os.scandir(marker_root))
    except OSError as exc:
        raise SnapshotReconciliationError("VibeHub 崩溃孤儿 marker 无法扫描") from exc
    if len(entries) > _MAX_CRASH_ORPHAN_ROOT_ENTRIES:
        raise SnapshotReconciliationError("VibeHub 崩溃孤儿 marker 数量超限")
    markers = {}
    temporary_files = []
    for entry in entries:
        path = Path(entry.path)
        if _CRASH_ORPHAN_TEMP_RE.fullmatch(entry.name):
            _regular_control_file(path, label=f"VibeHub 崩溃孤儿临时 marker {entry.name}")
            temporary_files.append(path)
            continue
        matched = _CRASH_ORPHAN_MARKER_RE.fullmatch(entry.name)
        if not matched:
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿 marker 目录包含未知入口")
        info = _regular_control_file(path, label=f"VibeHub 崩溃孤儿 marker {entry.name}")
        if info.st_size <= 0 or info.st_size > _MAX_CRASH_ORPHAN_MARKER_BYTES:
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿 marker 大小异常")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("marker must be an object")
            kind = payload.get("kind")
            slug = payload.get("slug")
            if not isinstance(kind, str) or not isinstance(slug, str):
                raise TypeError("marker identity must use strings")
            version = payload.get("version")
            clone = payload.get("clone")
            key = _crash_orphan_key(
                kind,
                slug,
                version=version,
                clone=clone,
            )
            schema_version = payload.get("schema_version")
            expected_keys = {
                "schema_version",
                "key",
                "kind",
                "slug",
                "orphaned_at",
                "target_device",
                "target_inode",
            }
            if schema_version == _CRASH_ORPHAN_MARKER_SCHEMA_VERSION:
                expected_keys.add("target_ctime_ns")
            if version is not None:
                expected_keys.add("version")
            if clone is not None:
                expected_keys.add("clone")
            raw_orphaned_at = payload.get("orphaned_at")
            if isinstance(raw_orphaned_at, bool) or not isinstance(
                raw_orphaned_at,
                (int, float),
            ):
                raise TypeError("orphaned_at must be numeric")
            orphaned_at = float(raw_orphaned_at)
            target_device = payload.get("target_device")
            target_inode = payload.get("target_inode")
            target_ctime_ns = payload.get("target_ctime_ns")
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿 marker 无法解析") from exc
        if (
            set(payload) != expected_keys
            or isinstance(payload.get("schema_version"), bool)
            or not isinstance(payload.get("schema_version"), int)
            or schema_version not in {1, _CRASH_ORPHAN_MARKER_SCHEMA_VERSION}
            or payload.get("key") != key
            or hashlib.sha256(key.encode("utf-8")).hexdigest() != matched.group(1)
            or not math.isfinite(orphaned_at)
            or orphaned_at < 0
            or isinstance(target_device, bool)
            or not isinstance(target_device, int)
            or target_device < 0
            or isinstance(target_inode, bool)
            or not isinstance(target_inode, int)
            or target_inode <= 0
            or (
                schema_version == _CRASH_ORPHAN_MARKER_SCHEMA_VERSION
                and (
                    isinstance(target_ctime_ns, bool)
                    or not isinstance(target_ctime_ns, int)
                    or target_ctime_ns < 0
                )
            )
            or (schema_version == 1 and target_ctime_ns is not None)
        ):
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿 marker 内容异常")
        if key in markers:
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿 marker 重复")
        markers[key] = _CrashOrphanMarker(
            path=path,
            key=key,
            kind=kind,
            slug=slug,
            orphaned_at=orphaned_at,
            target_device=target_device,
            target_inode=target_inode,
            target_ctime_ns=(
                target_ctime_ns
                if schema_version == _CRASH_ORPHAN_MARKER_SCHEMA_VERSION
                else None
            ),
            version=version,
            clone=clone,
        )
    return markers, temporary_files


def cleanup_uncommitted_version_snapshot(
    slug: str,
    version_number: int,
    known_version_numbers,
    *,
    upload_root=None,
) -> bool:
    """在重试前删除数据库从未记录的同号崩溃快照。"""

    safe_slug = _safe_slug(slug)
    if isinstance(version_number, bool) or not isinstance(version_number, int):
        raise SnapshotReconciliationError("VibeHub 待恢复版本号无效")
    number = int(version_number)
    if number <= 0:
        raise SnapshotReconciliationError("VibeHub 待恢复版本号无效")
    known = _normalize_version_set(known_version_numbers, label="VibeHub 已知版本集")
    versions, physical, clones = _strict_version_entries(
        safe_slug,
        upload_root=upload_root,
    )
    if number in physical and number in known:
        raise SnapshotReconciliationError(f"VibeHub v{number} 已有数据库版本元数据")
    candidates = []
    if number in physical:
        candidates.append(physical[number])
    candidates.extend(path for clone_number, path in clones if clone_number == number)
    for path in candidates:
        _validate_removable_directory(path)
    for path in candidates:
        _remove_validated_directory(path)
    if versions is not None:
        try:
            versions.rmdir()
        except OSError:
            pass
    return bool(candidates)


def cleanup_orphan_project_storage(slug: str, *, upload_root=None) -> bool:
    """清理经 DB 唯一性确认为未提交的整个作品遗留。"""

    safe_slug = _safe_slug(slug)
    project = project_root(safe_slug, upload_root=upload_root)
    if not _real_directory(project, label="VibeHub 孤儿作品目录", missing_ok=True):
        return False
    versions, physical, clones = _strict_version_entries(
        safe_slug,
        upload_root=upload_root,
    )
    gc_root, markers, marker_temps = _retirement_markers(
        safe_slug,
        upload_root=upload_root,
    )
    allowed = {"versions", ".gc", "latest.json", "public.json"}
    try:
        entries = list(os.scandir(project))
    except OSError as exc:
        raise SnapshotReconciliationError("VibeHub 孤儿作品目录无法扫描") from exc
    pointers = []
    for entry in entries:
        if entry.name not in allowed:
            raise SnapshotReconciliationError(
                f"VibeHub 孤儿作品目录包含未知入口：{entry.name}"
            )
        if entry.name in {"latest.json", "public.json"}:
            path = Path(entry.path)
            _regular_control_file(path, label=f"VibeHub 指针 {entry.name}")
            pointers.append(path)
    candidates = list(physical.values()) + [path for _number, path in clones]
    for path in candidates:
        _validate_removable_directory(path)
    for path in candidates:
        _remove_validated_directory(path)
    for marker in markers.values():
        _remove_marker(marker.path)
    for path in marker_temps:
        _regular_control_file(path, label=f"VibeHub 回收临时标记 {path.name}")
        path.unlink()
    for path in pointers:
        try:
            path.unlink()
        except OSError as exc:
            raise SnapshotReconciliationError(f"VibeHub 孤儿指针无法删除：{path.name}") from exc
    for directory in (versions, gc_root, project):
        if directory is None:
            continue
        try:
            directory.rmdir()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise SnapshotReconciliationError(
                f"VibeHub 孤儿目录不为空：{directory.name}"
            ) from exc
    return True


def _snapshot_identity(path: Path, *, label: str) -> tuple[int, int]:
    if not _real_directory(path, label=label):
        raise SnapshotReconciliationError(f"{label}不存在")
    try:
        info = path.lstat()
    except OSError as exc:
        raise SnapshotReconciliationError(f"{label}身份无法读取") from exc
    return int(info.st_dev), int(info.st_ino)


def _validate_marker_binding(
    version_number: int,
    marker: _RetirementMarker,
    snapshot: Path,
) -> None:
    identity = _snapshot_identity(
        snapshot,
        label=f"VibeHub v{int(version_number)} 快照",
    )
    if identity != (marker.snapshot_device, marker.snapshot_inode):
        raise SnapshotReconciliationError(
            f"VibeHub v{int(version_number)} 回收标记与物理快照身份不一致"
        )


def _remove_bound_snapshot(
    root: Path,
    version_number: int,
    marker: _RetirementMarker,
    snapshot: Path,
) -> int:
    _validate_marker_binding(version_number, marker, snapshot)
    try:
        return quotas.remove_managed_directory(
            root,
            snapshot,
            expected_device=marker.snapshot_device,
            expected_inode=marker.snapshot_inode,
        )
    except quotas.VibeHubStorageSecurityError as exc:
        raise SnapshotReconciliationError(
            f"VibeHub v{int(version_number)} 退役快照无法安全回收"
        ) from exc


def _audit_retirement_project_root(slug: str, *, upload_root=None) -> None:
    project = project_root(slug, upload_root=upload_root)
    if not _real_directory(project, label="VibeHub 作品目录", missing_ok=True):
        return
    allowed = {"versions", ".gc", "latest.json", "public.json"}
    try:
        entries = list(os.scandir(project))
    except OSError as exc:
        raise SnapshotReconciliationError("VibeHub 作品目录无法扫描") from exc
    for entry in entries:
        if entry.name not in allowed:
            raise SnapshotReconciliationError("VibeHub 作品目录包含未知入口")
        path = Path(entry.path)
        if entry.name in {"versions", ".gc"}:
            _real_directory(path, label=f"VibeHub {entry.name} 目录")
        else:
            _regular_control_file(path, label=f"VibeHub 指针 {entry.name}")


def reclaim_expired_retired_snapshots(
    project_states,
    *,
    upload_root=None,
    now=None,
    grace_seconds=SNAPSHOT_RETIREMENT_GRACE_SECONDS,
) -> SnapshotRetirementGCResult:
    """在配额扫描前按 DB live-set 回收已过宽限的退役快照。

    ``project_states`` 必须覆盖当前配额用户的全部社区容器作品，每项包含 ``slug``、数据库
    已提交的 ``known_versions`` 和 latest/public/review 对应的 ``live_versions``。
    只有 schema v2 marker 中记录的设备号和 inode 仍与同号物理快照完全一致、
    且 DB 确认不再 live 时才会删除。如果进程在 DB 提交后、常规 marker
    写入前退出，本次审计会为该物理快照补写绑定 marker，但仍将它计入当次
    配额；只有后续调用超过宽限期才能回收。整个受管树和全部候选先审计，
    之后才执行 marker 写入或精确 inode 删除。
    """

    root = _root(upload_root)
    quotas.assert_storage_mutation_lock(root)
    try:
        current_time = time.time() if now is None else float(now)
        grace = float(grace_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SnapshotReconciliationError("VibeHub 退役回收时间参数无效") from exc
    if not math.isfinite(current_time) or current_time < 0:
        raise SnapshotReconciliationError("VibeHub 退役回收时刻无效")
    if not math.isfinite(grace) or grace < 0:
        raise SnapshotReconciliationError("VibeHub 退役回收宽限必须是非负数")
    try:
        raw_states = tuple(project_states)
    except TypeError as exc:
        raise SnapshotReconciliationError("VibeHub 用户快照事实无效") from exc

    normalized = []
    seen_slugs = set()
    for state in raw_states:
        if not isinstance(state, dict):
            raise SnapshotReconciliationError("VibeHub 用户快照事实格式无效")
        try:
            slug = _safe_slug(state.get("slug"))
        except ValueError as exc:
            raise SnapshotReconciliationError("VibeHub 用户快照事实 slug 无效") from exc
        if slug in seen_slugs:
            raise SnapshotReconciliationError("VibeHub 用户快照事实包含重复作品")
        seen_slugs.add(slug)
        known = _normalize_version_set(
            state.get("known_versions", ()),
            label="VibeHub 已知版本集",
        )
        live = _normalize_version_set(
            state.get("live_versions", ()),
            label="VibeHub live-set",
        )
        if not live.issubset(known):
            raise SnapshotReconciliationError("VibeHub live-set 包含未知 DB 版本")
        normalized.append((slug, known, live))

    candidates = []
    new_marker_candidates = []
    stale_markers = []
    gc_roots = []
    for slug, known, live in sorted(normalized, key=lambda item: item[0]):
        project = project_root(slug, upload_root=upload_root)
        if project.exists():
            # 先完整审计当前用户的每棵作品树，再准备任何删除候选。
            quotas.logical_tree_bytes(project)
        _audit_retirement_project_root(slug, upload_root=upload_root)
        _versions, physical, _clones = _strict_version_entries(
            slug,
            upload_root=upload_root,
        )
        gc_root, markers, _marker_temps = _retirement_markers(
            slug,
            upload_root=upload_root,
        )
        gc_roots.append(gc_root)
        missing_live = sorted(live - set(physical))
        if missing_live:
            raise SnapshotReconciliationError(
                "VibeHub live-set 缺少物理快照："
                + ", ".join(f"v{number}" for number in missing_live)
            )
        for number, marker in markers.items():
            if number not in known:
                raise SnapshotReconciliationError(
                    f"VibeHub v{number} 回收标记缺少 DB 历史版本"
                )
            snapshot = physical.get(number)
            if snapshot is None:
                if number in live:
                    raise SnapshotReconciliationError(
                        f"VibeHub live v{number} 缺少物理快照"
                    )
                stale_markers.append(marker.path)
                continue
            # 包括 live 版本在内全部验证绑定；异常 marker 绝不会退化成删除依据。
            _validate_marker_binding(number, marker, snapshot)
            if number in live or current_time - marker.retired_at < grace:
                continue
            _validate_removable_directory(snapshot)
            candidates.append((slug, number, snapshot, marker))

        # DB 已经确认为历史版本、但还没有 marker 的物理快照，可能是
        # 进程在 commit 和常规 prune 之间退出所留。先记住已审计的物理
        # 身份；等所有作品都审计通过后才补写 marker。新 marker 绝不在
        # 本次调用中成为删除候选，即使 grace_seconds=0 也一样。
        unmarked_retired = (set(physical) & known) - live - set(markers)
        for number in sorted(unmarked_retired):
            snapshot = physical[number]
            _validate_removable_directory(snapshot)
            identity = _snapshot_identity(
                snapshot,
                label=f"VibeHub v{number} 快照",
            )
            new_marker_candidates.append(
                (slug, number, gc_root, snapshot, identity)
            )

    newly_retired = []
    for slug, number, gc_root, snapshot, identity in sorted(
        new_marker_candidates,
        key=lambda item: (item[0], item[1]),
    ):
        _write_retirement_marker(
            gc_root,
            number,
            current_time,
            snapshot,
            expected_identity=identity,
        )
        newly_retired.append((slug, number))

    deleted = []
    reclaimed_bytes = 0
    for slug, number, snapshot, marker in sorted(
        candidates,
        key=lambda item: (item[0], item[1]),
    ):
        reclaimed_bytes += _remove_bound_snapshot(
            root,
            number,
            marker,
            snapshot,
        )
        _remove_marker(marker.path)
        deleted.append((slug, number))
    for path in stale_markers:
        _remove_marker(path)
    for gc_root in gc_roots:
        try:
            gc_root.rmdir()
        except (FileNotFoundError, OSError):
            pass

    result = SnapshotRetirementGCResult(
        inspected_projects=tuple(sorted(seen_slugs)),
        newly_retired=tuple(newly_retired),
        deleted_expired=tuple(deleted),
        reclaimed_bytes=reclaimed_bytes,
    )
    if result.newly_retired:
        _LOGGER.info(
            "VibeHub 已在配额扫描前补写退役快照标记：snapshots=%s "
            "grace_seconds=%s",
            ",".join(f"{slug}:v{number}" for slug, number in result.newly_retired),
            grace,
        )
    if result.deleted_expired:
        _LOGGER.info(
            "VibeHub 已在配额扫描前回收退役快照：snapshots=%s bytes=%d grace_seconds=%s",
            ",".join(f"{slug}:v{number}" for slug, number in result.deleted_expired),
            result.reclaimed_bytes,
            grace,
        )
    return result


def _audit_upload_staging_for_crash_gc(root: Path, *, root_device: int) -> None:
    staging_root = root / ".staging"
    try:
        staging_root.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SnapshotReconciliationError("VibeHub 上传 staging 无法读取") from exc
    _managed_directory_identity(
        staging_root,
        root_device=root_device,
        label="VibeHub 上传 staging 根目录",
        scan_tree=False,
    )
    try:
        entries = list(os.scandir(staging_root))
    except OSError as exc:
        raise SnapshotReconciliationError("VibeHub 上传 staging 无法扫描") from exc
    if len(entries) > _MAX_CRASH_ORPHAN_ROOT_ENTRIES:
        raise SnapshotReconciliationError("VibeHub 上传 staging 会话数量超限")
    for entry in entries:
        if not re.fullmatch(r"upload-[0-9a-f]{32}", entry.name):
            raise SnapshotReconciliationError("VibeHub 上传 staging 包含未知入口")
        _managed_directory_identity(
            Path(entry.path),
            root_device=root_device,
            label=f"VibeHub 上传 staging 会话 {entry.name}",
        )


def reclaim_expired_crash_orphans(
    project_states,
    *,
    upload_root=None,
    now=None,
    grace_seconds=CRASH_ORPHAN_GRACE_SECONDS,
) -> CrashOrphanGCResult:
    """延时回收事务 commit 前崩溃留下的未提交目录。

    调用方必须持有全局存储变更锁，且 ``project_states`` 必须是在同一
    临界区内通过 ``FOR UPDATE`` 取得的全部社区容器作品与版本事实。
    回收覆盖已知项目中不在 DB 的 ``vN``/残留 clone，以及完全没有 DB
    行的社区项目。所有根入口、项目树、候选和 marker 先完整审计；
    只有同一 device/inode 连续超过一小时才会精确删除。
    """

    root = _root(upload_root)
    quotas.assert_storage_mutation_lock(root)
    try:
        current_time = time.time() if now is None else float(now)
        grace = float(grace_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SnapshotReconciliationError("VibeHub 崩溃孤儿回收时间参数无效") from exc
    if not math.isfinite(current_time) or current_time < 0:
        raise SnapshotReconciliationError("VibeHub 崩溃孤儿回收时刻无效")
    if not math.isfinite(grace) or grace < CRASH_ORPHAN_GRACE_SECONDS:
        raise SnapshotReconciliationError("VibeHub 崩溃孤儿回收宽限不得少于一小时")
    try:
        raw_states = tuple(project_states)
    except TypeError as exc:
        raise SnapshotReconciliationError("VibeHub 崩溃孤儿 DB 事实无效") from exc

    normalized = {}
    for state in raw_states:
        if not isinstance(state, dict):
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿 DB 事实格式无效")
        try:
            raw_slug = state.get("slug")
            if not isinstance(raw_slug, str):
                raise ValueError("slug must be a string")
            slug = _safe_slug(raw_slug)
        except ValueError as exc:
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿 DB slug 无效") from exc
        if slug in normalized:
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿 DB 作品事实冲突")
        known = _normalize_version_set(
            state.get("known_versions", ()),
            label="VibeHub 崩溃孤儿已知版本集",
        )
        live = _normalize_version_set(
            state.get("live_versions", ()),
            label="VibeHub 崩溃孤儿 live-set",
        )
        if not live.issubset(known):
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿 live-set 包含未知版本")
        normalized[slug] = (known, live)

    try:
        root_info = root.lstat()
        entries = list(os.scandir(root))
    except OSError as exc:
        raise SnapshotReconciliationError("VibeHub 存储根无法扫描") from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root.is_symlink()
        or int(root_info.st_uid) != int(os.geteuid())
    ):
        raise SnapshotReconciliationError("VibeHub 存储根类型或属主异常")
    if len(entries) > _MAX_CRASH_ORPHAN_ROOT_ENTRIES:
        raise SnapshotReconciliationError("VibeHub 存储根入口数量超限")
    root_device = int(root_info.st_dev)
    marker_root = root / CRASH_ORPHAN_MARKER_DIRECTORY
    candidates = {}
    inspected_projects = set(normalized)
    present_projects = set()

    for entry in sorted(entries, key=lambda item: item.name):
        name = entry.name
        path = Path(entry.path)
        if name == quotas.MUTATION_LOCK_FILENAME or _STORAGE_SLOT_LOCK_RE.fullmatch(name):
            info = _regular_control_file(path, label=f"VibeHub 存储锁 {name}")
            if int(info.st_dev) != root_device:
                raise SnapshotReconciliationError("VibeHub 存储锁跨设备")
            continue
        if name == ".staging":
            _audit_upload_staging_for_crash_gc(root, root_device=root_device)
            continue
        if name == CRASH_ORPHAN_MARKER_DIRECTORY:
            # marker 在收集完整候选后统一审计。
            continue
        if not _STORAGE_SLUG_RE.fullmatch(name):
            raise SnapshotReconciliationError(f"VibeHub 存储根包含未知入口：{name}")

        present_projects.add(name)
        inspected_projects.add(name)
        _managed_directory_identity(
            path,
            root_device=root_device,
            label=f"VibeHub 社区作品 {name}",
        )
        _audit_retirement_project_root(name, upload_root=root)
        _versions, physical, clones = _strict_version_entries(name, upload_root=root)
        _gc_root, retirement_markers, _temps = _retirement_markers(
            name,
            upload_root=root,
        )
        for number, marker in retirement_markers.items():
            snapshot = physical.get(number)
            if snapshot is not None:
                _validate_marker_binding(number, marker, snapshot)

        state = normalized.get(name)
        if state is None:
            candidate = _managed_orphan_candidate(
                "project",
                name,
                path,
                root_device=root_device,
            )
            candidates[candidate.key] = candidate
            continue

        known, live = state
        missing_live = sorted(live - set(physical))
        if missing_live:
            raise SnapshotReconciliationError(
                "VibeHub 崩溃孤儿 live-set 缺少物理快照："
                + ", ".join(f"v{number}" for number in missing_live)
            )
        unknown_markers = sorted(set(retirement_markers) - known)
        if unknown_markers:
            raise SnapshotReconciliationError(
                "VibeHub 退役 marker 缺少 DB 历史版本："
                + ", ".join(f"v{number}" for number in unknown_markers)
            )
        for number in sorted(set(physical) - known):
            candidate = _managed_orphan_candidate(
                "version",
                name,
                physical[number],
                root_device=root_device,
                version=number,
            )
            candidates[candidate.key] = candidate
        for version, clone_path in sorted(clones, key=lambda item: item[1].name):
            candidate = _managed_orphan_candidate(
                "clone",
                name,
                clone_path,
                root_device=root_device,
                version=version,
                clone=clone_path.name,
            )
            candidates[candidate.key] = candidate

    for slug, (_known, live) in normalized.items():
        if slug not in present_projects and live:
            raise SnapshotReconciliationError(f"VibeHub live 作品缺少物理目录：{slug}")

    markers, temporary_markers = _crash_orphan_markers(
        marker_root,
        root_device=root_device,
    )
    stale_markers = []
    new_candidates = []
    refreshed_candidates = []
    expired_candidates = []
    for key, marker in markers.items():
        candidate = candidates.get(key)
        if candidate is None:
            stale_markers.append(marker.path)
            continue
        identity = (
            candidate.target_device,
            candidate.target_inode,
            candidate.target_ctime_ns,
        )
        marker_identity = (
            marker.target_device,
            marker.target_inode,
            marker.target_ctime_ns,
        )
        if marker.target_ctime_ns is None or identity != marker_identity:
            # 同路径已被新的崩溃遗留替换；即使 inode 被复用，也绝不沿用旧宽限。
            refreshed_candidates.append(candidate)
        elif current_time - marker.orphaned_at >= grace:
            expired_candidates.append((candidate, marker))
    for key, candidate in candidates.items():
        if key not in markers:
            new_candidates.append(candidate)

    # 以上已审计全部根入口、DB 事实、项目树、候选和 marker；
    # 从这里开始才允许修改控制文件或删除精确绑定的目录。
    for path in sorted(stale_markers + temporary_markers, key=lambda item: item.name):
        _remove_marker(path)
    for candidate in sorted(new_candidates, key=lambda item: item.key):
        _write_crash_orphan_marker(marker_root, candidate, current_time)
    for candidate in sorted(refreshed_candidates, key=lambda item: item.key):
        _write_crash_orphan_marker(marker_root, candidate, current_time)

    deleted = []
    reclaimed_bytes = 0
    for candidate, marker in sorted(expired_candidates, key=lambda item: item[0].key):
        try:
            reclaimed_bytes += quotas.remove_managed_directory(
                root,
                candidate.path,
                expected_device=marker.target_device,
                expected_inode=marker.target_inode,
                expected_ctime_ns=marker.target_ctime_ns,
            )
        except quotas.VibeHubStorageSecurityError as exc:
            raise SnapshotReconciliationError("VibeHub 崩溃孤儿目录无法安全回收") from exc
        _remove_marker(marker.path)
        deleted.append(candidate.key)
    try:
        marker_root.rmdir()
    except (FileNotFoundError, OSError):
        pass

    result = CrashOrphanGCResult(
        inspected_projects=tuple(sorted(inspected_projects)),
        newly_marked=tuple(sorted(candidate.key for candidate in new_candidates)),
        refreshed_markers=tuple(
            sorted(candidate.key for candidate in refreshed_candidates)
        ),
        deleted_expired=tuple(deleted),
        deleted_stale_markers=tuple(
            sorted(path.name for path in stale_markers + temporary_markers)
        ),
        reclaimed_bytes=reclaimed_bytes,
    )
    if result.newly_marked or result.refreshed_markers:
        _LOGGER.info(
            "VibeHub 已标记崩溃孤儿：new=%s refreshed=%s grace_seconds=%s",
            ",".join(result.newly_marked),
            ",".join(result.refreshed_markers),
            grace,
        )
    if result.deleted_expired:
        _LOGGER.info(
            "VibeHub 已回收过期崩溃孤儿：targets=%s bytes=%d grace_seconds=%s",
            ",".join(result.deleted_expired),
            result.reclaimed_bytes,
            grace,
        )
    return result


def prune_project_snapshots(
    slug: str,
    known_version_numbers,
    live_version_numbers,
    *,
    upload_root=None,
    now=None,
    grace_seconds=SNAPSHOT_RETIREMENT_GRACE_SECONDS,
) -> SnapshotReconcileResult:
    """将物理快照对齐 DB live-set，并延时回收曾经可解析的版本。"""

    safe_slug = _safe_slug(slug)
    known = _normalize_version_set(known_version_numbers, label="VibeHub 已知版本集")
    live = _normalize_version_set(live_version_numbers, label="VibeHub live-set")
    if not live.issubset(known):
        raise SnapshotReconciliationError("VibeHub live-set 包含未知 DB 版本")
    try:
        current_time = time.time() if now is None else float(now)
        grace = float(grace_seconds)
    except (TypeError, ValueError) as exc:
        raise SnapshotReconciliationError("VibeHub 快照回收时间参数无效") from exc
    if not math.isfinite(current_time) or current_time < 0:
        raise SnapshotReconciliationError("VibeHub 快照回收时刻无效")
    if not math.isfinite(grace) or grace < 0:
        raise SnapshotReconciliationError("VibeHub 快照回收宽限必须是非负数")

    _versions, physical, clones = _strict_version_entries(
        safe_slug,
        upload_root=upload_root,
    )
    gc_root, markers, marker_temps = _retirement_markers(
        safe_slug,
        upload_root=upload_root,
    )
    missing_live = sorted(live - set(physical))
    if missing_live:
        raise SnapshotReconciliationError(
            "VibeHub live-set 缺少物理快照："
            + ", ".join(f"v{number}" for number in missing_live)
        )
    for number, marker in markers.items():
        snapshot = physical.get(number)
        if snapshot is not None:
            _validate_marker_binding(number, marker, snapshot)

    orphans = sorted(set(physical) - known)
    expired = []
    newly_retired = []
    for number in sorted((set(physical) & known) - live):
        marker = markers.get(number)
        if marker is None:
            newly_retired.append(number)
        elif current_time - marker.retired_at >= grace:
            expired.append(number)

    candidates = [path for _number, path in clones]
    candidates.extend(physical[number] for number in orphans)
    for path in candidates:
        _validate_removable_directory(path)
    for number in expired:
        _validate_removable_directory(physical[number])
    for path in candidates:
        _remove_validated_directory(path)
    root = _root(upload_root)
    for number in expired:
        _remove_bound_snapshot(
            root,
            number,
            markers[number],
            physical[number],
        )

    for path in marker_temps:
        _regular_control_file(path, label=f"VibeHub 回收临时标记 {path.name}")
        path.unlink()

    deleted_numbers = set(orphans) | set(expired)
    for number, marker in list(markers.items()):
        if number in live or number in deleted_numbers or number not in physical:
            _remove_marker(marker.path)
            markers.pop(number, None)
    for number in newly_retired:
        _write_retirement_marker(
            gc_root,
            number,
            current_time,
            physical[number],
        )
    try:
        gc_root.rmdir()
    except (FileNotFoundError, OSError):
        pass

    retained = sorted(set(physical) - deleted_numbers)
    return SnapshotReconcileResult(
        retained=tuple(retained),
        newly_retired=tuple(newly_retired),
        deleted_expired=tuple(expired),
        deleted_orphans=tuple(orphans),
    )


def _pointer_path(slug: str, name: str, *, upload_root=None) -> Path:
    if name not in {"latest", "public"}:
        raise ValueError(f"unknown VibeHub pointer: {name}")
    return project_root(slug, upload_root=upload_root) / f"{name}.json"


def read_pointer(slug: str, name: str, *, upload_root=None) -> dict | None:
    path = _pointer_path(slug, name, upload_root=upload_root)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("version"), int):
        raise RuntimeError(f"invalid VibeHub pointer: {path}")
    return payload


def write_pointer(
    slug: str,
    name: str,
    *,
    version_number: int,
    version_id: int,
    upload_root=None,
) -> dict | None:
    """原子更新 latest/public 指针，并返回旧值用于事务回滚。"""
    path = _pointer_path(slug, name, upload_root=upload_root)
    root = _ensure_private_directory(_root(upload_root))
    _ensure_private_directory(root / _safe_slug(slug))
    previous = read_pointer(slug, name, upload_root=upload_root)
    payload = {"version": int(version_number), "version_id": int(version_id)}
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return previous


def restore_pointer(slug: str, name: str, previous: dict | None, *, upload_root=None) -> None:
    path = _pointer_path(slug, name, upload_root=upload_root)
    if previous is None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    write_pointer(
        slug,
        name,
        version_number=int(previous["version"]),
        version_id=int(previous["version_id"]),
        upload_root=upload_root,
    )


def resolve_snapshot_app(slug: str, version_number: int, *, upload_root=None) -> Path:
    path = version_snapshot_path(slug, version_number, upload_root=upload_root) / "app"
    if not path.is_dir():
        raise FileNotFoundError(f"VibeHub version app directory is missing: {path}")
    return path


__all__ = [
    "CRASH_ORPHAN_GRACE_SECONDS",
    "CRASH_ORPHAN_MARKER_DIRECTORY",
    "CrashOrphanGCResult",
    "HEALTH_PATH",
    "PackageValidationError",
    "PreparedPackage",
    "SNAPSHOT_RETIREMENT_GRACE_SECONDS",
    "SOCKET_PATH",
    "SnapshotReconcileResult",
    "SnapshotReconciliationError",
    "SnapshotRetirementGCResult",
    "VIBEHUB_UPLOAD_ROOT",
    "cleanup_orphan_project_storage",
    "cleanup_uncommitted_version_snapshot",
    "clone_snapshot",
    "generate_processed_cover",
    "install_prepared_snapshot",
    "prepare_uploaded_package",
    "prune_project_snapshots",
    "reclaim_expired_crash_orphans",
    "reclaim_expired_retired_snapshots",
    "read_pointer",
    "processed_cover_path",
    "remove_version_snapshot",
    "resolve_snapshot_app",
    "restore_pointer",
    "validate_cover_image",
    "validate_manifest",
    "version_snapshot_path",
    "write_pointer",
]
