#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""代码仓库真实目录树的安全文件系统原语。

业务路径永远是经过校验的 POSIX 相对路径；宿主路径只在本模块内解析。文件访问逐级
使用 ``dir_fd`` + ``O_NOFOLLOW``，避免路径穿越与符号链接逃逸。仓库内容使用同目录
临时文件、fsync 和 ``os.replace`` 原子发布。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import codecs
import fcntl
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import threading
import unicodedata
import uuid

from charset_normalizer import from_bytes

from oj_modules import config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CONFIGURED_STORAGE_ROOT = Path(str(config.REPOSITORY_STORAGE_ROOT))
STORAGE_ROOT = (
    _CONFIGURED_STORAGE_ROOT
    if _CONFIGURED_STORAGE_ROOT.is_absolute()
    else PROJECT_ROOT / _CONFIGURED_STORAGE_ROOT
).resolve(strict=False)

MAX_FILE_BYTES = int(config.REPOSITORY_MAX_FILE_BYTES)
MAX_TOTAL_BYTES = int(config.REPOSITORY_MAX_TOTAL_BYTES)
MAX_ENTRIES = int(config.REPOSITORY_MAX_ENTRIES)
MAX_DEPTH = int(config.REPOSITORY_MAX_DEPTH)
MAX_PATH_BYTES = int(config.REPOSITORY_MAX_PATH_BYTES)
MAX_NAME_BYTES = 255
# UTF-32 等输入转成 UTF-8 后可能显著变小；传输层仍设有限上限，真正配额按规范化
# UTF-8 字节数计算。
MAX_RAW_FILE_BYTES = MAX_FILE_BYTES * 4 + 4
AUTO_DETECT_MIN_COHERENCE = 60.0
ENCODING_PREVIEW_MAX_CHARS = 600

_RESERVED_DOS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_ready_roots: set[str] = set()
_ready_lock = threading.Lock()


class RepositoryStorageError(RuntimeError):
    """仓库文件系统不满足安全前置条件或原子操作失败。"""


class RepositoryPathError(ValueError):
    """用户提供的仓库名称或相对路径不安全。"""


class RepositoryEncodingConfirmationRequired(ValueError):
    """非 UTF-8 输入的编码判断不够可靠，必须由用户确认。"""

    def __init__(
        self,
        candidate_encoding: str,
        confidence: float,
        *,
        preview: str,
        preview_truncated: bool,
        has_disallowed_control: bool,
    ):
        self.candidate_encoding = str(candidate_encoding or "")
        self.confidence = float(confidence)
        self.preview = str(preview)
        self.preview_truncated = bool(preview_truncated)
        self.has_disallowed_control = bool(has_disallowed_control)
        super().__init__(
            f"无法可靠判断文件编码；候选为 {self.candidate_encoding or '未知'}，"
            "请确认后再上传"
        )


@dataclass(frozen=True)
class NormalizedSource:
    text: str
    data: bytes
    source_encoding: str
    had_bom: bool
    newline_normalized: bool
    sha256: str


def _fsync_directory_fd(fd: int) -> None:
    # 目录项持久化是 DB/文件系统 journal 协议的一部分；若宿主文件系统不支持
    # 目录 fsync，就不能宣称发布已经耐受断电，必须失败关闭。
    os.fsync(fd)


def _assert_plain_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise RepositoryStorageError(f"仓库存储目录不存在：{path}") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RepositoryStorageError(f"仓库存储路径必须是真实目录且不能是符号链接：{path}")


def _probe_case_sensitive(path: Path) -> None:
    probe_dir = path / f".numoj-case-probe-{uuid.uuid4().hex}"
    lower = probe_dir / "case"
    upper = probe_dir / "CASE"
    try:
        probe_dir.mkdir(mode=0o700)
        lower.write_bytes(b"x")
        if upper.exists():
            raise RepositoryStorageError(
                f"仓库存储根不区分大小写，拒绝启用代码仓库：{path}"
            )
    finally:
        try:
            lower.unlink(missing_ok=True)
            upper.unlink(missing_ok=True)
            probe_dir.rmdir()
        except OSError:
            pass


def ensure_repository_storage_ready() -> Path:
    """创建受管根并验证其为无符号链接、区分大小写的真实目录。"""
    root_key = os.fspath(STORAGE_ROOT)
    if root_key in _ready_roots:
        expected = [STORAGE_ROOT, *(STORAGE_ROOT / child for child in (
            "users", "staging", "journal", "snapshots", "locks", "quarantine"
        ))]
        if all(path.is_dir() and not path.is_symlink() for path in expected):
            return STORAGE_ROOT
        _ready_roots.discard(root_key)
    with _ready_lock:
        if root_key in _ready_roots:
            return STORAGE_ROOT
        STORAGE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        _assert_plain_directory(STORAGE_ROOT)
        _probe_case_sensitive(STORAGE_ROOT)
        for child in (
            "users", "staging", "journal", "snapshots", "locks", "quarantine",
        ):
            target = STORAGE_ROOT / child
            target.mkdir(mode=0o700, exist_ok=True)
            _assert_plain_directory(target)
        _ready_roots.add(root_key)
    return STORAGE_ROOT


def validate_storage_key(storage_key: str) -> str:
    key = str(storage_key or "")
    if len(key) != 32 or any(ch not in "0123456789abcdef" for ch in key):
        raise RepositoryStorageError("非法仓库存储标识")
    return key


def repository_lock_stat_is_safe(info, *, expected_device=None) -> bool:
    """锁文件必须是当前用户拥有的私有、空、单链接普通文件。"""
    return (
        stat.S_ISREG(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o600
        and int(info.st_uid) == os.geteuid()
        and int(info.st_nlink) == 1
        and int(info.st_size) == 0
        and (
            expected_device is None
            or int(info.st_dev) == int(expected_device)
        )
    )


def validate_entry_name(name: str) -> str:
    normalized = unicodedata.normalize("NFC", str(name or ""))
    if not normalized or normalized in {".", ".."}:
        raise RepositoryPathError("名称不能为空，也不能是 . 或 ..")
    if normalized.rstrip(" .") != normalized:
        raise RepositoryPathError("名称不能以空格或点结尾")
    if "/" in normalized or "\\" in normalized or "\x00" in normalized:
        raise RepositoryPathError("名称不能包含斜杠、反斜杠或 NUL")
    if any(unicodedata.category(ch).startswith("C") for ch in normalized):
        raise RepositoryPathError("名称不能包含控制字符或格式控制符")
    base = normalized.split(".", 1)[0].upper()
    if base in _RESERVED_DOS_NAMES:
        raise RepositoryPathError("名称是系统保留名称")
    if len(normalized.encode("utf-8")) > MAX_NAME_BYTES:
        raise RepositoryPathError(f"单级名称不能超过 {MAX_NAME_BYTES} 字节")
    return normalized


def validate_relative_path(relative_path: str, *, allow_empty: bool = False) -> str:
    raw = str(relative_path or "")
    if "\\" in raw:
        raise RepositoryPathError("仓库路径不能包含反斜杠，只接受 POSIX /")
    if raw.startswith("/"):
        raise RepositoryPathError("仓库路径必须是相对路径")
    if raw == "":
        if allow_empty:
            return ""
        raise RepositoryPathError("仓库路径不能为空")
    raw_parts = tuple(raw.split("/"))
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise RepositoryPathError("仓库路径不能包含空段、. 或 ..")
    path = PurePosixPath(raw)
    parts = tuple(path.parts)
    if not parts and allow_empty:
        return ""
    if any(part in {"", ".", ".."} for part in parts):
        raise RepositoryPathError("仓库路径不能包含空段、. 或 ..")
    normalized_parts = tuple(validate_entry_name(part) for part in parts)
    normalized = "/".join(normalized_parts)
    if len(normalized_parts) > MAX_DEPTH:
        raise RepositoryPathError(f"目录深度不能超过 {MAX_DEPTH}")
    if len(normalized.encode("utf-8")) > MAX_PATH_BYTES:
        raise RepositoryPathError(f"仓库路径不能超过 {MAX_PATH_BYTES} 字节")
    return normalized


def join_relative_path(parent: str, name: str) -> str:
    safe_parent = validate_relative_path(parent, allow_empty=True)
    safe_name = validate_entry_name(name)
    return validate_relative_path(
        f"{safe_parent}/{safe_name}" if safe_parent else safe_name
    )


def normalize_source_bytes(
    raw: bytes,
    *,
    confirmed_encoding: str | None = None,
) -> NormalizedSource:
    """严格解码并统一为 UTF-8（无 BOM）与 LF；绝不替换非法字节。"""
    data = bytes(raw)
    utf8_decoded_with_nul = False
    if len(data) > MAX_RAW_FILE_BYTES:
        raise RepositoryPathError(f"单个文件原始传输不能超过 {MAX_RAW_FILE_BYTES} 字节")

    bom_encodings = (
        (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
    )
    bom = next(((prefix, encoding) for prefix, encoding in bom_encodings if data.startswith(prefix)), None)
    had_bom = bom is not None
    if bom is not None:
        prefix, source_encoding = bom
        try:
            text = data[len(prefix):].decode(source_encoding, errors="strict")
        except UnicodeDecodeError as exc:
            raise RepositoryPathError("带 BOM 的文件无法按其声明编码无损解码") from exc
    else:
        source_encoding = "utf-8"
        try:
            text = data.decode(source_encoding, errors="strict")
        except UnicodeDecodeError:
            text = None
        else:
            # 无 BOM 的 UTF-16/UTF-32 ASCII 源码本身也是“合法 UTF-8 字节”，
            # 但会解出大量 NUL。让编码检测器继续识别并走高/低置信度流程；
            # 若最终候选并非 Unicode 文本，下面的严格控制字符校验仍会拒绝。
            if "\x00" in text:
                utf8_decoded_with_nul = True
                text = None

    if text is None:
        if confirmed_encoding:
            try:
                codec_name = codecs.lookup(str(confirmed_encoding)).name
                text = data.decode(codec_name, errors="strict")
                source_encoding = codec_name
            except (LookupError, UnicodeDecodeError) as exc:
                raise RepositoryPathError("确认的文件编码无法无损解码该文件") from exc
        else:
            match = from_bytes(data).best()
            if match is None or not match.encoding:
                raise RepositoryPathError("文件不是有效 UTF-8，且无法识别候选编码")
            coherence = float(match.percent_coherence or 0.0)
            try:
                candidate_codec = codecs.lookup(str(match.encoding)).name
                candidate_text = data.decode(candidate_codec, errors="strict")
            except (LookupError, UnicodeDecodeError) as exc:
                raise RepositoryPathError("检测到的候选编码无法无损解码该文件") from exc
            if (
                utf8_decoded_with_nul
                and candidate_codec
                not in {"utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"}
            ):
                raise RepositoryPathError("文件包含 NUL，疑似二进制内容")
            if coherence < AUTO_DETECT_MIN_COHERENCE:
                preview_text = candidate_text.replace("\r\n", "\n").replace("\r", "\n")
                raise RepositoryEncodingConfirmationRequired(
                    candidate_codec,
                    coherence,
                    preview=preview_text[:ENCODING_PREVIEW_MAX_CHARS],
                    preview_truncated=len(preview_text) > ENCODING_PREVIEW_MAX_CHARS,
                    has_disallowed_control=any(
                        unicodedata.category(character) == "Cc"
                        and character not in "\n\t\f\r"
                        for character in candidate_text
                    ),
                )
            text = candidate_text
            source_encoding = candidate_codec

    if "\x00" in text:
        raise RepositoryPathError("文件包含 NUL，疑似二进制内容")
    if any(
        unicodedata.category(character) == "Cc" and character not in "\n\t\f\r"
        for character in text
    ):
        raise RepositoryPathError("文件包含二进制控制字符")

    newline_normalized = "\r" in text
    normalized_text = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized_data = normalized_text.encode("utf-8")
    if len(normalized_data) > MAX_FILE_BYTES:
        raise RepositoryPathError(
            f"转为 UTF-8 后单个文件不能超过 {MAX_FILE_BYTES} 字节"
        )
    return NormalizedSource(
        text=normalized_text,
        data=normalized_data,
        source_encoding=source_encoding,
        had_bom=had_bom,
        newline_normalized=newline_normalized,
        sha256=hashlib.sha256(normalized_data).hexdigest(),
    )


def user_base_path(storage_key: str) -> Path:
    ensure_repository_storage_ready()
    return STORAGE_ROOT / "users" / validate_storage_key(storage_key)


def ensure_user_tree(storage_key: str) -> Path:
    base = user_base_path(storage_key)
    base.mkdir(mode=0o700, exist_ok=True)
    _assert_plain_directory(base)
    tree = base / "tree"
    tree.mkdir(mode=0o700, exist_ok=True)
    _assert_plain_directory(tree)
    return tree


def snapshot_tree_root(snapshot_key: str) -> Path:
    ensure_repository_storage_ready()
    return STORAGE_ROOT / "snapshots" / validate_storage_key(snapshot_key) / "tree"


def upload_staging_path(session_id: str) -> Path:
    ensure_repository_storage_ready()
    return STORAGE_ROOT / "staging" / validate_storage_key(session_id)


def prepare_upload_session(session_id: str) -> Path:
    session = upload_staging_path(session_id)
    if session.exists():
        raise RepositoryStorageError("上传会话暂存目录已存在")
    session.mkdir(mode=0o700)
    (session / "raw").mkdir(mode=0o700)
    (session / "normalized").mkdir(mode=0o700)
    return session


def append_upload_chunk(
    session_id: str,
    token: str,
    *,
    offset: int,
    data: bytes,
) -> int:
    session = upload_staging_path(session_id)
    raw_dir = session / "raw"
    _assert_plain_directory(session)
    _assert_plain_directory(raw_dir)
    safe_token = validate_storage_key(token)
    directory_fd = os.open(
        raw_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        fd = os.open(
            safe_token,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RepositoryStorageError("上传分块目标不是普通文件")
            current = int(info.st_size)
            if current != int(offset):
                raise RepositoryStorageError(f"上传 offset 不匹配：期望 {current}")
            os.lseek(fd, 0, os.SEEK_END)
            view = memoryview(bytes(data))
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            return current + len(data)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def upload_file_size(session_id: str, token: str, *, normalized=False) -> int:
    folder = "normalized" if normalized else "raw"
    root = upload_staging_path(session_id) / folder
    _assert_plain_directory(root)
    with _open_directory_chain(root, ()) as directory_fd:
        info = os.stat(validate_storage_key(token), dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise RepositoryStorageError("上传暂存目标不是普通文件")
        return int(info.st_size)


def upload_session_disk_usage(session_id: str) -> int:
    """返回一个上传会话暂存树的真实字节数；拒绝链接或特殊文件。"""
    session = upload_staging_path(session_id)
    _assert_plain_directory(session)
    _entry_count, total_size = tree_disk_usage(session)
    return total_size


def read_upload_file(session_id: str, token: str, *, normalized=False) -> bytes:
    folder = "normalized" if normalized else "raw"
    root = upload_staging_path(session_id) / folder
    _assert_plain_directory(root)
    limit = MAX_FILE_BYTES if normalized else MAX_RAW_FILE_BYTES
    with _open_directory_chain(root, ()) as directory_fd:
        fd = os.open(
            validate_storage_key(token),
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or int(info.st_size) > limit:
                raise RepositoryStorageError("上传暂存文件类型或大小非法")
            chunks = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)


def write_normalized_upload_file(session_id: str, token: str, data: bytes) -> None:
    root = upload_staging_path(session_id) / "normalized"
    _assert_plain_directory(root)
    atomic_write_file_in_tree(root, validate_storage_key(token), data)


def cleanup_upload_session(session_id: str) -> None:
    session = upload_staging_path(session_id)
    if session.exists():
        _assert_plain_directory(session)
        shutil.rmtree(session)


def operation_journal_path(operation_id: str) -> Path:
    ensure_repository_storage_ready()
    return STORAGE_ROOT / "journal" / validate_storage_key(operation_id)


@contextmanager
def repository_user_lock(storage_key: str, *, exclusive: bool = True):
    """跨进程用户仓库锁；所有树写入与快照捕获必须复用此锁。"""
    ensure_repository_storage_ready()
    key = validate_storage_key(storage_key)
    lock_directory = STORAGE_ROOT / "locks"
    try:
        directory_fd = os.open(
            lock_directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise RepositoryStorageError("无法安全打开仓库锁目录") from exc
    try:
        directory_info = os.fstat(directory_fd)
        try:
            fd = os.open(
                f"{key}.lock",
                (
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK
                ),
                0o600,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise RepositoryStorageError("无法安全打开仓库锁文件") from exc
    finally:
        os.close(directory_fd)

    locked = False
    try:
        info = os.fstat(fd)
        if not repository_lock_stat_is_safe(
            info,
            expected_device=directory_info.st_dev,
        ):
            raise RepositoryStorageError(
                "仓库锁文件必须是当前用户拥有的 0600 空白单链接普通文件"
            )
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        locked = True
        yield
    finally:
        try:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


@contextmanager
def _open_directory_chain(tree_root: Path, parts: tuple[str, ...]):
    root_fd = os.open(tree_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    opened = [root_fd]
    try:
        current = root_fd
        for part in parts:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            opened.append(next_fd)
            current = next_fd
        yield current
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _relative_parts(relative_path: str) -> tuple[str, ...]:
    safe = validate_relative_path(relative_path, allow_empty=True)
    return tuple(PurePosixPath(safe).parts) if safe else ()


def read_file(storage_key: str, relative_path: str) -> bytes:
    tree = ensure_user_tree(storage_key)
    parts = _relative_parts(relative_path)
    if not parts:
        raise RepositoryPathError("不能把仓库根作为文件读取")
    with _open_directory_chain(tree, parts[:-1]) as parent_fd:
        fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RepositoryStorageError("目标不是普通文件")
            chunks = []
            remaining = MAX_FILE_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > MAX_FILE_BYTES:
                raise RepositoryStorageError("磁盘文件超过仓库单文件上限")
            return data
        finally:
            os.close(fd)


def make_directory_in_tree(tree: Path, relative_path: str) -> None:
    parts = _relative_parts(relative_path)
    if not parts:
        return
    with _open_directory_chain(tree, parts[:-1]) as parent_fd:
        os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
        _fsync_directory_fd(parent_fd)


def make_directory(storage_key: str, relative_path: str) -> None:
    make_directory_in_tree(ensure_user_tree(storage_key), relative_path)


def atomic_write_file_in_tree(tree: Path, relative_path: str, data: bytes) -> None:
    parts = _relative_parts(relative_path)
    if not parts:
        raise RepositoryPathError("不能写入仓库根")
    payload = bytes(data)
    if len(payload) > MAX_FILE_BYTES:
        raise RepositoryPathError(f"单个文件不能超过 {MAX_FILE_BYTES} 字节")
    with _open_directory_chain(tree, parts[:-1]) as parent_fd:
        temp_name = f".numoj-write-{uuid.uuid4().hex}.tmp"
        fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.replace(
                temp_name,
                parts[-1],
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            _fsync_directory_fd(parent_fd)
        except Exception:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
            raise


def atomic_write_file(storage_key: str, relative_path: str, data: bytes) -> None:
    atomic_write_file_in_tree(ensure_user_tree(storage_key), relative_path, data)


def link_file_between_trees(
    source_tree: Path,
    source_path: str,
    destination_tree: Path,
    destination_path: str,
) -> None:
    source_parts = _relative_parts(source_path)
    destination_parts = _relative_parts(destination_path)
    if not source_parts or not destination_parts:
        raise RepositoryPathError("不能把仓库根作为普通文件链接")
    with _open_directory_chain(source_tree, source_parts[:-1]) as source_parent:
        source_fd = os.open(
            source_parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=source_parent,
        )
        try:
            if not stat.S_ISREG(os.fstat(source_fd).st_mode):
                raise RepositoryStorageError("源目标不是普通文件")
            with _open_directory_chain(destination_tree, destination_parts[:-1]) as destination_parent:
                os.link(
                    source_parts[-1],
                    destination_parts[-1],
                    src_dir_fd=source_parent,
                    dst_dir_fd=destination_parent,
                    follow_symlinks=False,
                )
                _fsync_directory_fd(destination_parent)
        finally:
            os.close(source_fd)


def prepare_operation_tree(operation_id: str) -> Path:
    operation_dir = operation_journal_path(operation_id)
    if operation_dir.exists():
        raise RepositoryStorageError("操作暂存目录已存在")
    operation_dir.mkdir(mode=0o700)
    shadow = operation_dir / "new-tree"
    shadow.mkdir(mode=0o700)
    return shadow


def publish_operation_tree(storage_key: str, operation_id: str) -> None:
    """把已准备的 shadow tree 发布为用户树；DB journal 是提交真相源。"""
    base = user_base_path(storage_key)
    ensure_user_tree(storage_key)
    operation_dir = operation_journal_path(operation_id)
    _assert_plain_directory(operation_dir)
    base_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    operation_fd = os.open(
        operation_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        if (operation_dir / "old-tree").exists():
            raise RepositoryStorageError("操作备份目录已存在")
        os.rename("tree", "old-tree", src_dir_fd=base_fd, dst_dir_fd=operation_fd)
        try:
            os.rename("new-tree", "tree", src_dir_fd=operation_fd, dst_dir_fd=base_fd)
        except Exception:
            os.rename("old-tree", "tree", src_dir_fd=operation_fd, dst_dir_fd=base_fd)
            raise
        _fsync_directory_fd(base_fd)
        _fsync_directory_fd(operation_fd)
    finally:
        os.close(operation_fd)
        os.close(base_fd)


def rollback_operation_tree(storage_key: str, operation_id: str) -> None:
    base = user_base_path(storage_key)
    operation_dir = operation_journal_path(operation_id)
    if not operation_dir.exists():
        return
    base_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    operation_fd = os.open(
        operation_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        try:
            old_info = os.stat("old-tree", dir_fd=operation_fd, follow_symlinks=False)
            has_old = stat.S_ISDIR(old_info.st_mode)
        except FileNotFoundError:
            has_old = False
        if has_old:
            discard_name = f"discard-tree-{uuid.uuid4().hex}"
            try:
                os.rename("tree", discard_name, src_dir_fd=base_fd, dst_dir_fd=operation_fd)
            except FileNotFoundError:
                pass
            os.rename("old-tree", "tree", src_dir_fd=operation_fd, dst_dir_fd=base_fd)
            _fsync_directory_fd(base_fd)
    finally:
        os.close(operation_fd)
        os.close(base_fd)
    cleanup_operation_tree(operation_id)


def cleanup_operation_tree(operation_id: str) -> None:
    operation_dir = operation_journal_path(operation_id)
    if operation_dir.exists():
        _assert_plain_directory(operation_dir)
        shutil.rmtree(operation_dir)


def move_entry(storage_key: str, source_path: str, destination_path: str) -> None:
    tree = ensure_user_tree(storage_key)
    source = _relative_parts(source_path)
    destination = _relative_parts(destination_path)
    if not source or not destination:
        raise RepositoryPathError("不能移动仓库根")
    with _open_directory_chain(tree, source[:-1]) as source_parent:
        with _open_directory_chain(tree, destination[:-1]) as destination_parent:
            os.rename(
                source[-1],
                destination[-1],
                src_dir_fd=source_parent,
                dst_dir_fd=destination_parent,
            )
            _fsync_directory_fd(source_parent)
            if destination_parent != source_parent:
                _fsync_directory_fd(destination_parent)


def remove_entry(storage_key: str, relative_path: str, *, directory: bool) -> None:
    tree = ensure_user_tree(storage_key)
    parts = _relative_parts(relative_path)
    if not parts:
        raise RepositoryPathError("不能删除仓库根")
    with _open_directory_chain(tree, parts[:-1]) as parent_fd:
        if directory:
            os.rmdir(parts[-1], dir_fd=parent_fd)
        else:
            os.unlink(parts[-1], dir_fd=parent_fd)
        _fsync_directory_fd(parent_fd)


def clone_tree(source: Path, destination: Path) -> None:
    """复制目录树用于批量原子发布；拒绝任何符号链接。"""
    if destination.exists():
        raise RepositoryStorageError("批量发布目标已存在")

    def _copy_regular(src: str, dst: str) -> str:
        info = os.lstat(src)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RepositoryStorageError("仓库树包含符号链接或非普通文件")
        try:
            os.link(src, dst)
        except OSError:
            shutil.copyfile(src, dst)
            os.chmod(dst, 0o600)
        # 硬链接成功时 src/dst 共享 inode；不能 chmod(dst)，否则会反向修改权威树。
        return dst

    shutil.copytree(source, destination, copy_function=_copy_regular, symlinks=False)


def tree_disk_usage(tree_root: Path) -> tuple[int, int]:
    entries = 0
    total_size = 0
    for current_root, directories, files in os.walk(tree_root, followlinks=False):
        root_path = Path(current_root)
        for name in directories:
            path = root_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RepositoryStorageError("仓库树包含符号链接或非法目录")
            entries += 1
        for name in files:
            path = root_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RepositoryStorageError("仓库树包含符号链接或非普通文件")
            entries += 1
            total_size += int(info.st_size)
    return entries, total_size
