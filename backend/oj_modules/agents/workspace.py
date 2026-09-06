"""通用 Agent 持久工作区文件操作。

工作区中的内容由不可信 Agent 进程产生。所有读取都逐级使用 ``dir_fd`` 与
``O_NOFOLLOW`` 固定 inode；附件先写入会话私有暂存区，再原子发布到公开工作区。
宿主绝对路径不会出现在对外元数据中。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import BinaryIO, Iterable, Mapping
import unicodedata
import uuid

from backend.oj_modules import config
from backend.oj_modules.project_paths import PROJECT_ROOT


_CONFIGURED_WORKSPACE_ROOT = Path(str(config.AGENT_WORKSPACE_ROOT))
AGENT_WORKSPACE_ROOT = (
    _CONFIGURED_WORKSPACE_ROOT
    if _CONFIGURED_WORKSPACE_ROOT.is_absolute()
    else PROJECT_ROOT / _CONFIGURED_WORKSPACE_ROOT
)
AGENT_WORKSPACE_MAX_BYTES = config.AGENT_WORKSPACE_MAX_BYTES

MAX_ATTACHMENT_FILES = 20
MAX_ATTACHMENT_FILE_BYTES = 32 * 1024 * 1024
MAX_ATTACHMENT_TOTAL_BYTES = 128 * 1024 * 1024
MAX_TEXT_PREVIEW_BYTES = 2 * 1024 * 1024
MAX_ENTRY_NAME_BYTES = 255
MAX_WORKSPACE_PATH_BYTES = 4096

# 原生 harness 会话保存在 workspace 的私有 ``.runtime`` 中；续聊时其中的旧
# 工具输出也会被再次同步。临时 relay 凭据因此必须按 Agent 会话保留脱敏候选，
# 但该历史不能放进容器可见的 workspace，更不能无界增长。
_REDACTION_HISTORY_FILENAME = ".trace-redaction-history.json"
_REDACTION_HISTORY_LOCK_FILENAME = ".trace-redaction-history.lock"
_REDACTION_HISTORY_VERSION = 1
_MAX_REDACTION_HISTORY_ENTRIES = 4096
_MAX_REDACTION_HISTORY_BYTES = 512 * 1024
_MIN_REDACTION_CANDIDATE_BYTES = 8
_MAX_REDACTION_CANDIDATE_BYTES = 4096

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_PRIVATE_EXACT_NAMES = frozenset(
    {
        ".runtime",
        ".numoj-agent",
        ".aj_session_state.json",
        ".aj_session_state.jsonl",
    }
)
_PRIVATE_PREFIXES = (".runtime", ".numoj-agent", ".aj_session_state")
_MARKDOWN_EXTENSIONS = frozenset({".md", ".markdown", ".mdown", ".mkd"})
_CODE_LANGUAGE_BY_EXTENSION = {
    ".asm": "asm",
    ".s": "asm",
    ".bat": "bat",
    ".cmd": "bat",
    ".c": "c",
    ".h": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".cs": "csharp",
    ".fs": "fsharp",
    ".fsx": "fsharp",
    ".vb": "vb",
    ".clj": "clojure",
    ".cljs": "clojure",
    ".coffee": "coffeescript",
    ".css": "css",
    ".scss": "scss",
    ".sass": "scss",
    ".less": "less",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hrl": "erlang",
    ".go": "go",
    ".graphql": "graphql",
    ".gql": "graphql",
    ".groovy": "groovy",
    ".hs": "haskell",
    ".lhs": "haskell",
    ".html": "html",
    ".htm": "html",
    ".xhtml": "html",
    ".ini": "ini",
    ".cfg": "ini",
    ".java": "java",
    ".js": "javascript",
    ".cjs": "javascript",
    ".mjs": "javascript",
    ".jsx": "javascript",
    ".json": "json",
    ".jsonl": "json",
    ".ipynb": "json",
    ".jl": "julia",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".lua": "lua",
    ".lean": "lean4",
    # .m 在本项目中明确按 MATLAB 处理，不按 Objective-C 处理。
    ".m": "matlab",
    ".mm": "objective-c",
    ".pas": "pascal",
    ".pl": "perl",
    ".pm": "perl",
    ".php": "php",
    ".proto": "protobuf",
    ".ps1": "powershell",
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    ".r": "r",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sc": "scala",
    ".scm": "scheme",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".fish": "shell",
    ".sol": "solidity",
    ".sql": "sql",
    ".swift": "swift",
    ".sv": "systemverilog",
    ".svh": "systemverilog",
    ".tcl": "tcl",
    ".tex": "latex",
    ".sty": "latex",
    ".cls": "latex",
    ".toml": "toml",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".v": "verilog",
    ".vh": "verilog",
    ".vue": "html",
    ".xml": "xml",
    ".svg": "xml",
    ".xsd": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
}
_CODE_LANGUAGE_BY_FILENAME = {
    "cmakelists.txt": "cmake",
    "dockerfile": "dockerfile",
    "gemfile": "ruby",
    "makefile": "makefile",
    "rakefile": "ruby",
}

_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class AgentWorkspaceError(OSError):
    """Agent 工作区操作失败。"""


class AgentWorkspacePathError(ValueError):
    """请求中的标识或相对路径不安全。"""


class AgentWorkspaceSecurityError(AgentWorkspaceError):
    """受管路径自身无法按预期访问。"""


class AgentWorkspaceLimitError(AgentWorkspaceError):
    """工作区目录树或预览超过服务端上限。"""


class AgentWorkspaceQuotaError(AgentWorkspaceLimitError):
    """持久工作区超过字节、文件数或宿主磁盘安全边界。"""


class AgentAttachmentError(AgentWorkspaceError):
    """附件校验、暂存或发布失败。"""


@dataclass(frozen=True, slots=True)
class AgentWorkspaceUsage:
    """一个会话 workspace 当前的逻辑用量。"""

    total_bytes: int
    file_count: int
    entry_count: int = 0


def _workspace_root() -> Path:
    configured = Path(AGENT_WORKSPACE_ROOT)
    root = configured if configured.is_absolute() else PROJECT_ROOT / configured
    root = root.absolute()
    if root == Path(root.anchor) or root == PROJECT_ROOT:
        raise AgentWorkspaceSecurityError("AGENT_WORKSPACE_ROOT 不能指向文件系统或项目根目录")
    return root


def _normalize_identifier(value, *, label: str) -> str:
    normalized = str(value or "").strip()
    if (
        not _IDENTIFIER_RE.fullmatch(normalized)
        or normalized in {".", ".."}
    ):
        raise AgentWorkspacePathError(f"{label} 无效")
    return normalized


def _is_private_name(name: str) -> bool:
    folded = unicodedata.normalize("NFC", str(name or "")).casefold()
    return folded in _PRIVATE_EXACT_NAMES or any(
        folded.startswith(prefix) for prefix in _PRIVATE_PREFIXES
    )


def _normalize_entry_name(value, *, attachment: bool = False) -> str:
    if not isinstance(value, str):
        raise AgentWorkspacePathError("文件名必须是字符串")
    normalized = value
    if not normalized or normalized in {".", ".."}:
        raise AgentWorkspacePathError("文件名不能为空，也不能是 . 或 ..")
    if "/" in normalized or "\x00" in normalized:
        raise AgentWorkspacePathError("文件名不能包含 / 或 NUL")
    if len(normalized.encode("utf-8")) > MAX_ENTRY_NAME_BYTES:
        raise AgentWorkspacePathError(
            f"单级文件名不能超过 {MAX_ENTRY_NAME_BYTES} 字节"
        )
    if attachment and _is_private_name(normalized):
        raise AgentWorkspacePathError("附件文件名使用了 Agent 私有保留名称")
    return normalized


def _normalize_relative_path(relative_path, *, public: bool = True) -> str:
    if not isinstance(relative_path, str):
        raise AgentWorkspacePathError("工作区路径必须是字符串")
    raw = relative_path
    if not raw or raw.startswith("/") or "\x00" in raw:
        raise AgentWorkspacePathError("工作区路径必须是非空 POSIX 相对路径")
    raw_parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise AgentWorkspacePathError("工作区路径不能包含空段、. 或 ..")
    parts = tuple(_normalize_entry_name(part) for part in raw_parts)
    if public and any(_is_private_name(part) for part in parts):
        raise AgentWorkspacePathError("不能访问 Agent 私有运行数据")
    normalized = "/".join(parts)
    if len(normalized.encode("utf-8")) > MAX_WORKSPACE_PATH_BYTES:
        raise AgentWorkspacePathError(
            f"工作区路径不能超过 {MAX_WORKSPACE_PATH_BYTES} 字节"
        )
    return normalized


def _harden_managed_directory_fd(fd: int, *, label: str) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise AgentWorkspaceSecurityError(f"{label} 必须是真实目录")
    if int(info.st_uid) != os.geteuid():
        raise AgentWorkspaceSecurityError(f"{label} 必须由当前服务用户拥有")
    if stat.S_IMODE(info.st_mode) != 0o700:
        try:
            os.fchmod(fd, 0o700)
        except OSError as exc:
            raise AgentWorkspaceSecurityError(f"无法把 {label} 权限收紧为 0700") from exc
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
            raise AgentWorkspaceSecurityError(f"{label} 权限必须是 0700")


def _open_workspace_root_fd() -> int:
    root = _workspace_root()
    try:
        root.parent.mkdir(parents=True, exist_ok=True)
        root.mkdir(mode=0o700, exist_ok=True)
        root_info = root.lstat()
    except OSError as exc:
        raise AgentWorkspaceSecurityError("无法创建 Agent 工作区根目录") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise AgentWorkspaceSecurityError("Agent 工作区根必须是真实目录，不能是符号链接")
    try:
        fd = os.open(root, _DIRECTORY_OPEN_FLAGS)
    except OSError as exc:
        raise AgentWorkspaceSecurityError("无法安全打开 Agent 工作区根目录") from exc
    try:
        _harden_managed_directory_fd(fd, label="Agent 工作区根目录")
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_managed_child_directory(parent_fd: int, name: str, *, label: str) -> int:
    try:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise AgentWorkspaceSecurityError(
            f"{label} 必须是真实目录，不能是符号链接"
        ) from exc
    try:
        _harden_managed_directory_fd(fd, label=label)
    except Exception:
        os.close(fd)
        raise
    return fd


@contextmanager
def _open_session_directories(session_id):
    safe_session_id = _normalize_identifier(session_id, label="Agent session_id")
    opened: list[int] = []
    try:
        root_fd = _open_workspace_root_fd()
        opened.append(root_fd)
        sessions_fd = _open_managed_child_directory(
            root_fd, "sessions", label="Agent sessions 目录"
        )
        opened.append(sessions_fd)
        session_fd = _open_managed_child_directory(
            sessions_fd,
            safe_session_id,
            label="Agent 会话目录",
        )
        opened.append(session_fd)
        workspace_fd = _open_managed_child_directory(
            session_fd,
            "workspace",
            label="Agent workspace 目录",
        )
        opened.append(workspace_fd)
        yield safe_session_id, session_fd, workspace_fd
    finally:
        for fd in reversed(opened):
            os.close(fd)


@contextmanager
def _open_existing_session_directories(session_id):
    """只打开已有会话目录；运行中配额检查绝不重建丢失的路径。"""

    safe_session_id = _normalize_identifier(session_id, label="Agent session_id")
    opened: list[int] = []
    try:
        root = _workspace_root()
        try:
            root_info = root.lstat()
            if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
                raise AgentWorkspaceSecurityError(
                    "Agent 工作区根必须是真实目录"
                )
            root_fd = os.open(root, _DIRECTORY_OPEN_FLAGS)
        except (FileNotFoundError, OSError) as exc:
            raise AgentWorkspaceSecurityError(
                "Agent 工作区根目录已丢失或无法安全打开"
            ) from exc
        opened.append(root_fd)
        _harden_managed_directory_fd(root_fd, label="Agent 工作区根目录")
        try:
            sessions_fd = _open_existing_directory_at(
                root_fd,
                "sessions",
                label="Agent sessions 目录",
            )
            opened.append(sessions_fd)
            session_fd = _open_existing_directory_at(
                sessions_fd,
                safe_session_id,
                label="Agent 会话目录",
            )
            opened.append(session_fd)
            workspace_fd = _open_existing_directory_at(
                session_fd,
                "workspace",
                label="Agent workspace 目录",
            )
            opened.append(workspace_fd)
        except FileNotFoundError as exc:
            raise AgentWorkspaceSecurityError(
                "Agent 会话 workspace 已丢失"
            ) from exc
        for fd, label in (
            (sessions_fd, "Agent sessions 目录"),
            (session_fd, "Agent 会话目录"),
            (workspace_fd, "Agent workspace 目录"),
        ):
            _harden_managed_directory_fd(fd, label=label)
        yield safe_session_id, session_fd, workspace_fd
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _positive_limit(value, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AgentWorkspaceQuotaError(f"配置项 {name} 必须是正整数")
    return int(value)


def _nonnegative_projection(value, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AgentWorkspaceQuotaError(f"{label}必须是非负整数")
    return int(value)


def _quota_limit() -> int:
    return _positive_limit(
        AGENT_WORKSPACE_MAX_BYTES,
        name="AGENT_WORKSPACE_MAX_BYTES",
    )


def _scan_workspace_usage_fd(
    workspace_fd: int,
    *,
    max_bytes: int,
    inode_references: dict[tuple[int, int], tuple[int, int]] | None = None,
) -> AgentWorkspaceUsage:
    """逐级 no-follow 统计数据量，不对文件或目录形态施加策略限制。

    批量注入可请求每个 inode 的 (字节数, 目录项引用数)，此时目录必须静默且
    完整可读，任何无法统计的入口都拒绝操作，避免覆盖时低估净增量。
    """

    try:
        root_info = os.fstat(workspace_fd)
    except OSError as exc:
        raise AgentWorkspaceQuotaError("Agent workspace 用量统计失败") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise AgentWorkspaceSecurityError("Agent workspace 必须是真实目录")
    total_bytes = 0
    file_count = 0
    entry_count = 0
    counted_inodes: set[tuple[int, int]] = set()
    frames: list[list] = []

    def push(directory_fd: int, *, owns_fd: bool) -> bool:
        try:
            iterator = os.scandir(directory_fd)
        except OSError as exc:
            if owns_fd:
                os.close(directory_fd)
            if inode_references is not None:
                raise AgentWorkspaceQuotaError("无法完整统计批量注入的 workspace") from exc
            return False
        frames.append([directory_fd, iterator, owns_fd])
        return True

    if not push(workspace_fd, owns_fd=False):
        raise AgentWorkspaceQuotaError("Agent workspace 用量统计失败")
    try:
        while frames:
            directory_fd, iterator, owns_fd = frames[-1]
            try:
                entry = next(iterator)
            except StopIteration:
                frames.pop()
                iterator.close()
                if owns_fd:
                    os.close(directory_fd)
                continue
            raw_name = entry.name
            try:
                info = os.stat(
                    raw_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError as exc:
                if inode_references is not None:
                    raise AgentWorkspaceQuotaError("批量注入期间 workspace 被其他进程修改") from exc
                # Harness 可以在检查期间原子替换或删除文件；
                # 本轮已消失的入口留给下一个周期重新统计。
                continue
            except OSError as exc:
                if inode_references is not None:
                    raise AgentWorkspaceQuotaError("无法完整统计批量注入的 workspace") from exc
                continue
            entry_count += 1
            if stat.S_ISDIR(info.st_mode):
                try:
                    child_fd = _open_existing_directory_at(
                        directory_fd,
                        raw_name,
                        label="Agent workspace 子目录",
                    )
                except (FileNotFoundError, AgentWorkspaceError) as exc:
                    if inode_references is not None:
                        raise AgentWorkspaceQuotaError("无法完整统计批量注入的 workspace") from exc
                    continue
                push(child_fd, owns_fd=True)
                continue
            inode_key = (int(info.st_dev), int(info.st_ino))
            if stat.S_ISREG(info.st_mode):
                file_count += 1
            if inode_references is not None:
                size, count = inode_references.get(inode_key, (max(0, int(info.st_size)), 0))
                inode_references[inode_key] = (size, count + 1)
            if inode_key in counted_inodes:
                continue
            counted_inodes.add(inode_key)
            total_bytes += max(0, int(info.st_size))
            if total_bytes > max_bytes:
                raise AgentWorkspaceQuotaError(
                    f"Agent workspace 总大小不能超过 {max_bytes} 字节"
                )
    finally:
        while frames:
            directory_fd, iterator, owns_fd = frames.pop()
            iterator.close()
            if owns_fd:
                os.close(directory_fd)
    return AgentWorkspaceUsage(
        total_bytes=total_bytes,
        file_count=file_count,
        entry_count=entry_count,
    )


def _check_workspace_quota_fd(
    workspace_fd: int,
    *,
    additional_bytes: int = 0,
) -> AgentWorkspaceUsage:
    max_bytes = _quota_limit()
    added_bytes = _nonnegative_projection(additional_bytes, label="新增字节数")
    usage = _scan_workspace_usage_fd(
        workspace_fd,
        max_bytes=max_bytes,
    )
    projected_bytes = usage.total_bytes + added_bytes
    if projected_bytes > max_bytes:
        raise AgentWorkspaceQuotaError(
            f"Agent workspace 总大小不能超过 {max_bytes} 字节"
        )
    return usage


def check_agent_workspace_quota(
    session_id,
    *,
    additional_bytes: int = 0,
) -> AgentWorkspaceUsage:
    """仅校验会话总数据量。"""

    with _open_existing_session_directories(session_id) as (
        _safe_id,
        _session_fd,
        workspace_fd,
    ):
        return _check_workspace_quota_fd(
            workspace_fd,
            additional_bytes=additional_bytes,
        )


def get_agent_workspace_usage(session_id) -> AgentWorkspaceUsage:
    """返回当前会话用量。"""

    return check_agent_workspace_quota(session_id)


def get_existing_agent_workspace_path(session_id) -> Path:
    """安全验证并返回已有 workspace 路径，不扫描目录配额。"""

    with _open_existing_session_directories(session_id) as (
        safe_session_id,
        _session_fd,
        _workspace_fd,
    ):
        return _workspace_root() / "sessions" / safe_session_id / "workspace"


def ensure_agent_workspace(session_id, *, check_quota=True) -> Path:
    """创建并验证 ``AGENT_WORKSPACE_ROOT/sessions/<id>/workspace``。"""

    with _open_session_directories(session_id) as (
        safe_session_id,
        _session_fd,
        workspace_fd,
    ):
        if check_quota:
            _check_workspace_quota_fd(workspace_fd)
        return _workspace_root() / "sessions" / safe_session_id / "workspace"


def initialize_agent_task_workspace(
    session_id,
    *,
    harness,
    access_role,
) -> Path:
    """初始化新建 Agent 会话的 workspace 与 harness 长期记忆文件。

    调用方只应在首轮创建时调用，续聊必须保留 Agent 后续在 workspace 中的
    修改。Claude Code 识别 ``CLAUDE.md``，其余已支持 harness 共用
    ``AGENTS.md``。
    """

    workspace = ensure_agent_workspace(session_id)
    normalized_harness = str(harness or "").strip().lower().replace("-", "_")
    filename = "CLAUDE.md" if normalized_harness == "claude_code" else "AGENTS.md"
    skill_name = (
        "numoj-admin"
        if str(access_role or "").strip().lower() == "admin"
        else "numoj-user"
    )
    write_agent_workspace_file(
        session_id,
        filename,
        (
            "You are now running in the cloud container environment provided by NumOJ. "
            f"You may use the {skill_name} skill to respond to user requests. "
            "Do not attempt to access the system /tmp directory; "
            "for temporary files, create and use a tmp subdirectory within the current project."
        ),
    )
    return workspace


def _harden_redaction_history_file(fd: int, *, label: str) -> None:
    """验证宿主侧凭据历史文件，不跟随链接并始终收紧为 0600。"""

    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or int(info.st_uid) != os.geteuid()
    ):
        raise AgentWorkspaceSecurityError(f"{label} 必须是服务用户拥有的普通文件")
    if stat.S_IMODE(info.st_mode) != 0o600:
        try:
            os.fchmod(fd, 0o600)
        except OSError as exc:
            raise AgentWorkspaceSecurityError(
                f"无法把 {label} 权限收紧为 0600"
            ) from exc
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise AgentWorkspaceSecurityError(f"{label} 权限必须是 0600")


@contextmanager
def _lock_redaction_history(session_fd: int):
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(
            _REDACTION_HISTORY_LOCK_FILENAME,
            flags,
            0o600,
            dir_fd=session_fd,
        )
    except OSError as exc:
        raise AgentWorkspaceSecurityError("无法安全打开 Agent 脱敏历史锁") from exc
    try:
        _harden_redaction_history_file(fd, label="Agent 脱敏历史锁")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _normalize_redaction_candidates(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values or ():
        if not isinstance(value, str):
            raise AgentWorkspaceSecurityError("Agent 临时脱敏候选必须是字符串")
        if not value:
            continue
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise AgentWorkspaceSecurityError("Agent 临时脱敏候选编码无效") from exc
        if (
            len(encoded) < _MIN_REDACTION_CANDIDATE_BYTES
            or len(encoded) > _MAX_REDACTION_CANDIDATE_BYTES
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in value
            )
        ):
            raise AgentWorkspaceSecurityError("Agent 临时脱敏候选格式无效")
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _read_redaction_history(session_fd: int) -> list[str]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(_REDACTION_HISTORY_FILENAME, flags, dir_fd=session_fd)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise AgentWorkspaceSecurityError("无法安全读取 Agent 脱敏历史") from exc
    try:
        _harden_redaction_history_file(fd, label="Agent 脱敏历史")
        payload = bytearray()
        while len(payload) <= _MAX_REDACTION_HISTORY_BYTES:
            chunk = os.read(
                fd,
                min(64 * 1024, _MAX_REDACTION_HISTORY_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > _MAX_REDACTION_HISTORY_BYTES:
            raise AgentWorkspaceLimitError("Agent 脱敏历史超过大小上限")
    finally:
        os.close(fd)
    try:
        document = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentWorkspaceSecurityError("Agent 脱敏历史格式无效") from exc
    if (
        not isinstance(document, dict)
        or document.get("version") != _REDACTION_HISTORY_VERSION
        or not isinstance(document.get("candidates"), list)
    ):
        raise AgentWorkspaceSecurityError("Agent 脱敏历史格式无效")
    candidates = _normalize_redaction_candidates(document["candidates"])
    if (
        len(candidates) != len(document["candidates"])
        or len(candidates) > _MAX_REDACTION_HISTORY_ENTRIES
    ):
        raise AgentWorkspaceSecurityError("Agent 脱敏历史内容无效")
    return candidates


def _write_redaction_history(session_fd: int, candidates: list[str]) -> None:
    if len(candidates) > _MAX_REDACTION_HISTORY_ENTRIES:
        raise AgentWorkspaceLimitError("Agent 脱敏历史超过条目上限")
    payload = json.dumps(
        {
            "version": _REDACTION_HISTORY_VERSION,
            "candidates": candidates,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload) > _MAX_REDACTION_HISTORY_BYTES:
        raise AgentWorkspaceLimitError("Agent 脱敏历史超过大小上限")

    temporary_name = f".{_REDACTION_HISTORY_FILENAME}.{uuid.uuid4().hex}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = -1
    temporary_exists = False
    try:
        fd = os.open(temporary_name, flags, 0o600, dir_fd=session_fd)
        temporary_exists = True
        _harden_redaction_history_file(fd, label="Agent 脱敏历史临时文件")
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise AgentWorkspaceSecurityError("写入 Agent 脱敏历史失败")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(
            temporary_name,
            _REDACTION_HISTORY_FILENAME,
            src_dir_fd=session_fd,
            dst_dir_fd=session_fd,
        )
        temporary_exists = False
        os.fsync(session_fd)
    except OSError as exc:
        raise AgentWorkspaceSecurityError("无法原子保存 Agent 脱敏历史") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=session_fd)
            except FileNotFoundError:
                pass


def merge_agent_temporary_redaction_candidates(
    session_id,
    current_candidates: Iterable[str],
) -> tuple[str, ...]:
    """原子合并宿主侧临时凭据脱敏历史，并返回当前会话的全部候选。

    文件位于 ``sessions/<id>/`` 而不是容器挂载的 ``workspace/`` 中。调用方
    只能传入本轮短生命周期 relay 值；真实 Session、长期模型密钥和长期 MCP
    凭据不得进入此持久历史。
    """

    normalized_current = _normalize_redaction_candidates(current_candidates)
    with _open_session_directories(session_id) as (
        _safe_session_id,
        session_fd,
        _workspace_fd,
    ):
        with _lock_redaction_history(session_fd):
            historical = _read_redaction_history(session_fd)
            merged = list(dict.fromkeys((*historical, *normalized_current)))
            if len(merged) > _MAX_REDACTION_HISTORY_ENTRIES:
                raise AgentWorkspaceLimitError("Agent 脱敏历史超过条目上限")
            if merged != historical:
                _write_redaction_history(session_fd, merged)
            return tuple(merged)


def _open_existing_directory_at(parent_fd: int, name: str, *, label: str) -> int:
    try:
        fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise AgentWorkspaceSecurityError(
            f"{label} 不是可安全访问的真实目录"
        ) from exc
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise AgentWorkspaceSecurityError(f"{label} 不是目录")
    return fd


def _open_regular_file_fd(workspace_fd: int, parts: tuple[str, ...]):
    opened_directories: list[int] = []
    current_fd = workspace_fd
    try:
        for part in parts[:-1]:
            next_fd = _open_existing_directory_at(
                current_fd, part, label="工作区路径父目录"
            )
            opened_directories.append(next_fd)
            current_fd = next_fd
        try:
            file_fd = os.open(parts[-1], _FILE_OPEN_FLAGS, dir_fd=current_fd)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise AgentWorkspaceSecurityError("无法安全打开工作区文件") from exc
        try:
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode):
                raise AgentWorkspaceSecurityError("工作区目标不是普通文件")
            return file_fd, info
        except Exception:
            os.close(file_fd)
            raise
    finally:
        for fd in reversed(opened_directories):
            os.close(fd)


def _content_magic(head: bytes):
    if head.startswith(b"%PDF-"):
        return "pdf", "application/pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image", "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image", "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image", "image/gif"
    if len(head) >= 12 and head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image", "image/webp"
    if head.startswith(b"BM"):
        return "image", "image/bmp"
    if head.startswith(b"\x00\x00\x01\x00"):
        return "image", "image/x-icon"
    if (
        len(head) >= 12
        and head[4:8] == b"ftyp"
        and head[8:12] in {b"avif", b"avis"}
    ):
        return "image", "image/avif"
    return None


def _read_head(fd: int, length: int = 64) -> bytes:
    if hasattr(os, "pread"):
        return os.pread(fd, length, 0)
    current = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        return os.read(fd, length)
    finally:
        os.lseek(fd, current, os.SEEK_SET)


def open_agent_workspace_file(session_id, path) -> tuple[BinaryIO, dict]:
    """返回已固定 inode 的二进制句柄与不含宿主路径的下载元数据。

    句柄所有权转移给调用方，调用方必须关闭它。该句柄可直接交给 Flask
    ``send_file``，路径在检查后被替换也不会改变实际读取的 inode。
    """

    normalized = _normalize_relative_path(path, public=True)
    parts = tuple(PurePosixPath(normalized).parts)
    with _open_session_directories(session_id) as (_safe_id, _session_fd, workspace_fd):
        fd, info = _open_regular_file_fd(workspace_fd, parts)
    magic = _content_magic(_read_head(fd))
    metadata = {
        "name": parts[-1],
        "path": normalized,
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "mime": magic[1] if magic else "application/octet-stream",
        "mime_type": magic[1] if magic else "application/octet-stream",
    }
    try:
        return os.fdopen(fd, "rb", closefd=True), metadata
    except Exception:
        os.close(fd)
        raise


def build_agent_workspace_tree(session_id) -> list:
    """返回公开工作区目录树；链接和运行期特殊节点不会使列表失败。"""

    def walk(directory_fd: int, parent_path: str):
        try:
            raw_names = os.listdir(directory_fd)
        except OSError as exc:
            raise AgentWorkspaceSecurityError("无法读取 Agent 工作区目录") from exc
        nodes = []
        for raw_name in sorted(raw_names, key=lambda item: item.casefold()):
            if _is_private_name(raw_name):
                continue
            name = raw_name
            relative_path = f"{parent_path}/{name}" if parent_path else name
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                # Agent 工作时目录会实时变化；已消失的条目留到下一次刷新。
                continue
            except OSError:
                continue
            if stat.S_ISLNK(info.st_mode):
                continue
            if stat.S_ISDIR(info.st_mode):
                try:
                    child_fd = _open_existing_directory_at(
                        directory_fd, name, label="工作区子目录"
                    )
                except (FileNotFoundError, AgentWorkspaceError):
                    continue
                try:
                    children = walk(child_fd, relative_path)
                finally:
                    os.close(child_fd)
                nodes.append(
                    {
                        "name": name,
                        "path": relative_path,
                        "type": "directory",
                        "children": children,
                    }
                )
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            nodes.append(
                {
                    "name": name,
                    "path": relative_path,
                    "type": "file",
                    "size": int(info.st_size),
                }
            )
        return nodes

    with _open_session_directories(session_id) as (_safe_id, _session_fd, workspace_fd):
        return walk(workspace_fd, "")


def _text_has_disallowed_controls(text: str) -> bool:
    return any(
        unicodedata.category(character) == "Cc"
        and character not in "\n\r\t\f"
        for character in text
    )


def _code_language(filename: str):
    folded_name = filename.casefold()
    explicit = _CODE_LANGUAGE_BY_FILENAME.get(folded_name)
    if explicit:
        return explicit
    return _CODE_LANGUAGE_BY_EXTENSION.get(Path(folded_name).suffix)


def inspect_agent_workspace_file(session_id, path) -> dict:
    """按真实内容优先分类文件，并构造有界预览数据。"""

    handle, metadata = open_agent_workspace_file(session_id, path)
    with handle:
        head = handle.read(64)
        magic = _content_magic(head)
        if magic:
            kind, mime = magic
            return {
                **metadata,
                "kind": kind,
                "preview_kind": kind,
                "mime": mime,
                "mime_type": mime,
            }

        if metadata["size"] > MAX_TEXT_PREVIEW_BYTES:
            return {
                **metadata,
                "kind": "unsupported",
                "preview_kind": "unsupported",
                "reason": "文件超过文本预览上限",
            }

        handle.seek(0)
        payload = handle.read(MAX_TEXT_PREVIEW_BYTES + 1)
        if len(payload) > MAX_TEXT_PREVIEW_BYTES:
            return {
                **metadata,
                "kind": "unsupported",
                "preview_kind": "unsupported",
                "reason": "文件超过文本预览上限",
            }
        try:
            content = payload.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError:
            return {
                **metadata,
                "kind": "unsupported",
                "preview_kind": "unsupported",
                "reason": "无法预览的文件格式",
            }
        if "\x00" in content or _text_has_disallowed_controls(content):
            return {
                **metadata,
                "kind": "unsupported",
                "preview_kind": "unsupported",
                "reason": "无法预览的文件格式",
            }

    suffix = Path(metadata["name"].casefold()).suffix
    if suffix in _MARKDOWN_EXTENSIONS:
        return {
            **metadata,
            "kind": "markdown",
            "preview_kind": "markdown",
            "mime": "text/markdown; charset=utf-8",
            "mime_type": "text/markdown; charset=utf-8",
            "language": "markdown",
            "content": content,
        }
    language = _code_language(metadata["name"])
    if language:
        return {
            **metadata,
            "kind": "code",
            "preview_kind": "code",
            "mime": "text/plain; charset=utf-8",
            "mime_type": "text/plain; charset=utf-8",
            "language": language,
            "content": content,
        }
    return {
        **metadata,
        "kind": "text",
        "preview_kind": "text",
        "mime": "text/plain; charset=utf-8",
        "mime_type": "text/plain; charset=utf-8",
        "language": "plaintext",
        "content": content,
    }


def _upload_name_and_stream(upload):
    if isinstance(upload, tuple) and len(upload) == 2:
        filename, stream = upload
    else:
        filename = getattr(upload, "filename", None)
        stream = getattr(upload, "stream", upload)
    if filename in {None, ""}:
        return None
    try:
        name = _normalize_entry_name(filename, attachment=True)
    except AgentWorkspacePathError as exc:
        raise AgentAttachmentError(str(exc)) from exc
    if not callable(getattr(stream, "read", None)):
        raise AgentAttachmentError("附件上传对象不可读取")
    return name, stream


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise AgentAttachmentError("附件写入未取得进展")
        view = view[written:]


def _workspace_target_parent_fd(
    workspace_fd: int,
    parts: tuple[str, ...],
) -> tuple[int, list[int]]:
    opened: list[int] = []
    current_fd = workspace_fd
    try:
        for part in parts[:-1]:
            next_fd = _open_managed_child_directory(
                current_fd,
                part,
                label="Agent workspace 宿主写入目录",
            )
            opened.append(next_fd)
            current_fd = next_fd
        return current_fd, opened
    except Exception:
        for fd in reversed(opened):
            os.close(fd)
        raise


def _replaceable_target_info(directory_fd: int, name: str):
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AgentWorkspaceSecurityError(
            "无法安全检查 Agent workspace 宿主写入目标"
        ) from exc
    if stat.S_ISDIR(info.st_mode):
        raise AgentWorkspaceError("Agent workspace 宿主写入目标是目录")
    return info


def write_agent_workspace_file(
    session_id,
    path,
    content,
    *,
    mode: int = 0o600,
) -> Path:
    """通过会话目录外的暂存 inode 原子发布一个宿主注入文件。

    发布后按实际数据量校验；失败时会恢复原文件，不留下部分写入。
    该入口也允许受管的私有运行路径。
    """

    normalized = _normalize_relative_path(path, public=False)
    parts = tuple(PurePosixPath(normalized).parts)
    if isinstance(content, str):
        payload = content.encode("utf-8")
    elif isinstance(content, (bytes, bytearray, memoryview)):
        payload = bytes(content)
    else:
        payload = str(content).encode("utf-8")
    if (
        isinstance(mode, bool)
        or not isinstance(mode, int)
        or mode < 0
        or mode > 0o777
        or mode & 0o022
    ):
        raise AgentWorkspaceSecurityError(
            "Agent workspace 宿主写入权限必须是不允许 group/other 写入的 Unix mode"
        )

    with _open_session_directories(session_id) as (
        safe_session_id,
        session_fd,
        workspace_fd,
    ):
        _check_workspace_quota_fd(workspace_fd)
        staging_fd = _open_managed_child_directory(
            session_fd,
            ".host-write-staging",
            label="Agent workspace 宿主写入暂存目录",
        )
        try:
            _publish_workspace_payload(
                workspace_fd, staging_fd, parts, payload, mode=mode,
                check_publication=lambda _old, _new: _check_workspace_quota_fd(workspace_fd),
            )
        finally:
            os.close(staging_fd)
        return _workspace_root() / "sessions" / safe_session_id / "workspace" / normalized


def _publish_workspace_payload(
    workspace_fd, staging_fd, parts, payload, *, mode, check_publication,
):
    """单文件和静默 workspace 批量写入共用的 inode 暂存、发布与回滚。"""
    parent_fd, opened_parents = _workspace_target_parent_fd(workspace_fd, parts)
    stage_name = f"write-{uuid.uuid4().hex}"
    backup_name = f"backup-{uuid.uuid4().hex}"
    stage_present = False
    backup_present = False
    published = False
    try:
        try:
            file_fd = os.open(
                stage_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=staging_fd,
            )
        except OSError as exc:
            raise AgentWorkspaceError(
                "无法安全创建 Agent workspace 宿主写入暂存文件"
            ) from exc
        stage_present = True
        try:
            view = memoryview(payload)
            while view:
                written = os.write(file_fd, view)
                if written <= 0:
                    raise AgentWorkspaceError(
                        "Agent workspace 宿主写入未取得进展"
                    )
                view = view[written:]
            os.fchmod(file_fd, mode)
            os.fsync(file_fd)
            staged_info = os.fstat(file_fd)
            if (
                not stat.S_ISREG(staged_info.st_mode)
                or int(staged_info.st_size) != len(payload)
            ):
                raise AgentWorkspaceSecurityError(
                    "Agent workspace 宿主写入暂存文件属性异常"
                )
        finally:
            os.close(file_fd)

        # 先把发布时实际存在的旧入口移到会话私有暂存目录，使新文件发布后
        # 仍能在任何后置校验失败时无损恢复。
        if _replaceable_target_info(parent_fd, parts[-1]) is not None:
            os.rename(
                parts[-1],
                backup_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=staging_fd,
            )
            backup_present = True
        replaced_info = (
            os.stat(backup_name, dir_fd=staging_fd, follow_symlinks=False)
            if backup_present else None
        )
        os.rename(
            stage_name,
            parts[-1],
            src_dir_fd=staging_fd,
            dst_dir_fd=parent_fd,
        )
        stage_present = False
        published = True
        os.fsync(parent_fd)
        check_publication(replaced_info, staged_info)
        # 所有可能失败的持久化检查完成后才删除旧入口；否则 fsync 失败会
        # 在备份已被删除后进入回滚，误删已经发布的新文件。
        os.fsync(staging_fd)
        if backup_present:
            _unlink_regular_file(
                staging_fd,
                backup_name,
                missing_ok=False,
            )
            backup_present = False
    except Exception:
        if published:
            try:
                _unlink_regular_file(parent_fd, parts[-1], missing_ok=True)
            except (OSError, AgentWorkspaceError):
                pass
            published = False
        if backup_present:
            try:
                os.rename(
                    backup_name,
                    parts[-1],
                    src_dir_fd=staging_fd,
                    dst_dir_fd=parent_fd,
                )
                backup_present = False
                os.fsync(parent_fd)
            except OSError:
                pass
        raise
    finally:
        if stage_present:
            try:
                _unlink_regular_file(staging_fd, stage_name, missing_ok=True)
            except (OSError, AgentWorkspaceError):
                pass
        if backup_present:
            # 只有恢复本身失败时才可能到达这里；保留备份比删除
            # 用户原文件更安全，下次启动会因私有暂存异常 fail closed。
            pass
        for fd in reversed(opened_parents):
            os.close(fd)


def _unlink_regular_file(directory_fd: int, name: str, *, missing_ok: bool) -> bool:
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return False
        raise
    if stat.S_ISDIR(info.st_mode):
        raise AgentWorkspaceError("清理目标是目录")
    os.unlink(name, dir_fd=directory_fd)
    return True


def save_agent_attachments(session_id, task_id, uploads: Iterable) -> list[dict]:
    """流式保存一批 multipart 附件，并返回可持久化的相对路径元数据。

    每次调用都发布到与消息 ID 关联的独立 generation 目录。这样同一条排队
    消息可以安全追加或替换附件；若进程在文件发布后、数据库提交前退出，
    客户端以相同 message ID 重试时也不会被遗留目录永久阻塞。调用方只根据
    返回的精确路径提交或补偿删除，不会覆盖另一并发请求已经发布的文件。
    """

    safe_task_id = _normalize_identifier(task_id, label="Agent task_id")
    if _is_private_name(safe_task_id):
        raise AgentWorkspacePathError("Agent task_id 使用了私有保留名称")
    prepared = []
    for upload in uploads or []:
        item = _upload_name_and_stream(upload)
        if item is not None:
            prepared.append(item)
            if len(prepared) > MAX_ATTACHMENT_FILES:
                raise AgentAttachmentError(
                    f"单轮最多上传 {MAX_ATTACHMENT_FILES} 个附件"
                )
    folded_names = [name.casefold() for name, _stream in prepared]
    if len(folded_names) != len(set(folded_names)):
        raise AgentAttachmentError("同一轮附件文件名不能重复或仅大小写不同")
    if not prepared:
        return []

    # 目录标识仍保留消息/任务 ID 前缀，便于运维定位；随机 generation 使
    # 每批文件拥有独立、可精确补偿的发布单元。31 + 1 + 32 == 64，满足
    # 受管目录标识上限。
    attachment_generation_id = (
        f"{safe_task_id[:31]}-{uuid.uuid4().hex}"
    )

    with _open_session_directories(session_id) as (_safe_id, session_fd, workspace_fd):
        _check_workspace_quota_fd(workspace_fd)
        staging_root_fd = _open_managed_child_directory(
            session_fd,
            ".attachment-staging",
            label="Agent 附件暂存目录",
        )
        stage_name = f"{attachment_generation_id}-{uuid.uuid4().hex}"
        stage_fd = None
        attachments_fd = None
        target_fd = None
        target_created = False
        staged_names: list[str] = []
        published_names: list[str] = []
        metadata: list[dict] = []
        completed = False
        try:
            os.mkdir(stage_name, mode=0o700, dir_fd=staging_root_fd)
            stage_fd = os.open(stage_name, _DIRECTORY_OPEN_FLAGS, dir_fd=staging_root_fd)
            _harden_managed_directory_fd(stage_fd, label="Agent 单轮附件暂存目录")

            total_size = 0
            for name, stream in prepared:
                try:
                    file_fd = os.open(
                        name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=stage_fd,
                    )
                except OSError as exc:
                    raise AgentAttachmentError("无法安全创建附件暂存文件") from exc
                staged_names.append(name)
                digest = hashlib.sha256()
                file_size = 0
                try:
                    while True:
                        chunk = stream.read(64 * 1024)
                        if chunk is None or chunk == b"":
                            break
                        if not isinstance(chunk, (bytes, bytearray, memoryview)):
                            raise AgentAttachmentError("附件上传流必须返回二进制内容")
                        payload = bytes(chunk)
                        if file_size + len(payload) > MAX_ATTACHMENT_FILE_BYTES:
                            raise AgentAttachmentError(
                                f"单个附件不能超过 {MAX_ATTACHMENT_FILE_BYTES // (1024 * 1024)} MiB"
                            )
                        if total_size + len(payload) > MAX_ATTACHMENT_TOTAL_BYTES:
                            raise AgentAttachmentError(
                                f"单轮附件总大小不能超过 {MAX_ATTACHMENT_TOTAL_BYTES // (1024 * 1024)} MiB"
                            )
                        _write_all(file_fd, payload)
                        digest.update(payload)
                        file_size += len(payload)
                        total_size += len(payload)
                    os.fsync(file_fd)
                    info = os.fstat(file_fd)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or int(info.st_size) != file_size
                        or stat.S_IMODE(info.st_mode) != 0o600
                    ):
                        raise AgentWorkspaceSecurityError("附件暂存文件安全属性异常")
                finally:
                    os.close(file_fd)
                metadata.append(
                    {
                        "name": name,
                        "path": f"attachments/{attachment_generation_id}/{name}",
                        "size": file_size,
                        "sha256": digest.hexdigest(),
                    }
                )
            os.fsync(stage_fd)

            # 暂存数据已经占用真实磁盘，rename 发布不再
            # 预留同等大小；但仍必须以全会话现有用量做配额投影。
            _check_workspace_quota_fd(
                workspace_fd,
                additional_bytes=total_size,
            )

            attachments_fd = _open_managed_child_directory(
                workspace_fd,
                "attachments",
                label="Agent 附件目录",
            )
            try:
                os.mkdir(
                    attachment_generation_id,
                    mode=0o700,
                    dir_fd=attachments_fd,
                )
                target_created = True
            except FileExistsError as exc:
                # UUID generation 碰撞时绝不复用或覆盖未知目录。
                raise AgentAttachmentError("附件批次目录冲突，请重试") from exc
            target_fd = os.open(
                attachment_generation_id,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=attachments_fd,
            )
            _harden_managed_directory_fd(target_fd, label="Agent 单轮附件目录")
            for item in metadata:
                name = item["name"]
                os.rename(
                    name,
                    name,
                    src_dir_fd=stage_fd,
                    dst_dir_fd=target_fd,
                )
                staged_names.remove(name)
                published_names.append(name)
            os.fsync(target_fd)
            os.fsync(attachments_fd)
            _check_workspace_quota_fd(
                workspace_fd,
            )
            completed = True
            return metadata
        except (AgentWorkspaceError, AgentWorkspacePathError):
            raise
        except OSError as exc:
            raise AgentAttachmentError("附件保存失败") from exc
        finally:
            if target_fd is not None:
                if not completed:
                    for name in list(published_names):
                        try:
                            _unlink_regular_file(target_fd, name, missing_ok=True)
                        except (OSError, AgentWorkspaceError):
                            pass
                    try:
                        os.fsync(target_fd)
                    except OSError:
                        pass
                os.close(target_fd)
            if target_created and not completed and attachments_fd is not None:
                try:
                    os.rmdir(attachment_generation_id, dir_fd=attachments_fd)
                    os.fsync(attachments_fd)
                except OSError:
                    pass
            if attachments_fd is not None:
                os.close(attachments_fd)
            if stage_fd is not None:
                for name in list(staged_names):
                    try:
                        _unlink_regular_file(stage_fd, name, missing_ok=True)
                    except (OSError, AgentWorkspaceError):
                        pass
                os.close(stage_fd)
            try:
                os.rmdir(stage_name, dir_fd=staging_root_fd)
                os.fsync(staging_root_fd)
            except OSError:
                pass
            os.close(staging_root_fd)


def _validated_attachment_cleanup_paths(attachments) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    seen = set()
    for attachment in list(attachments or []):
        if not isinstance(attachment, Mapping):
            raise AgentWorkspacePathError("附件清理元数据无效")
        normalized = _normalize_relative_path(attachment.get("path"), public=True)
        parts = tuple(PurePosixPath(normalized).parts)
        if len(parts) != 3 or parts[0] != "attachments":
            raise AgentWorkspacePathError("只允许清理本轮受管附件路径")
        task_id = _normalize_identifier(parts[1], label="Agent task_id")
        filename = _normalize_entry_name(parts[2], attachment=True)
        if attachment.get("name") not in {None, filename}:
            raise AgentWorkspacePathError("附件清理元数据名称不一致")
        identity = (task_id, filename)
        if identity in seen:
            continue
        seen.add(identity)
        grouped.setdefault(task_id, []).append(filename)
    return grouped


def remove_agent_attachments(session_id, attachments) -> int:
    """仅删除参数明确列出的受管附件；绝不递归清理整个工作区。"""

    grouped = _validated_attachment_cleanup_paths(attachments)
    if not grouped:
        return 0
    removed = 0
    with _open_session_directories(session_id) as (_safe_id, _session_fd, workspace_fd):
        try:
            attachments_fd = _open_existing_directory_at(
                workspace_fd, "attachments", label="Agent 附件目录"
            )
        except FileNotFoundError:
            return 0
        try:
            for task_id, filenames in grouped.items():
                try:
                    task_fd = _open_existing_directory_at(
                        attachments_fd, task_id, label="Agent 单轮附件目录"
                    )
                except FileNotFoundError:
                    continue
                try:
                    for filename in filenames:
                        if _unlink_regular_file(task_fd, filename, missing_ok=True):
                            removed += 1
                    os.fsync(task_fd)
                finally:
                    os.close(task_fd)
                try:
                    os.rmdir(task_id, dir_fd=attachments_fd)
                    os.fsync(attachments_fd)
                except OSError as exc:
                    if exc.errno not in {errno.ENOENT, errno.ENOTEMPTY, errno.EEXIST}:
                        raise AgentWorkspaceSecurityError("无法收束附件清理目录") from exc
            try:
                os.rmdir("attachments", dir_fd=workspace_fd)
                os.fsync(workspace_fd)
            except OSError as exc:
                if exc.errno not in {errno.ENOENT, errno.ENOTEMPTY, errno.EEXIST}:
                    raise AgentWorkspaceSecurityError("无法收束附件根目录") from exc
        finally:
            os.close(attachments_fd)
    return removed


def clear_agent_session_state_file(session_id) -> bool:
    """删除 harness 上一轮留下的原生 session 摘要，不跟随链接。"""

    filename = ".aj_session_state.json"
    with _open_session_directories(session_id) as (
        _safe_id,
        _session_fd,
        workspace_fd,
    ):
        try:
            info = os.stat(
                filename,
                dir_fd=workspace_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        if stat.S_ISDIR(info.st_mode):
            raise AgentWorkspaceSecurityError(
                "Agent 原生会话状态路径被目录占用"
            )
        try:
            os.unlink(filename, dir_fd=workspace_fd)
            os.fsync(workspace_fd)
        except OSError as exc:
            raise AgentWorkspaceSecurityError(
                "无法清理 Agent 原生会话状态"
            ) from exc
        return True



def _injection_source_payload(source):
    if isinstance(source, Path):
        absolute = source.absolute()
        root_fd = os.open(absolute.anchor, _DIRECTORY_OPEN_FLAGS)
        try:
            fd, info = _open_regular_file_fd(root_fd, absolute.parts[1:])
        finally:
            os.close(root_fd)
        with os.fdopen(fd, "rb") as stream:
            if info.st_nlink != 1 or info.st_size > _quota_limit():
                raise AgentWorkspaceSecurityError("注入源必须是限额内的独立普通文件")
            content = stream.read(_quota_limit() + 1)
            if len(content) > _quota_limit():
                raise AgentWorkspaceQuotaError("注入文件超过工作区限额")
        return content
    if isinstance(source, str):
        return source.encode("utf-8")
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    raise AgentWorkspacePathError("注入内容必须是文本、字节或 Path")


def inject_agent_workspace_files(session_id, files, *, progress=None):
    """向静默 workspace 批量注入独立副本，目录用量仅在批次前后扫描。

    内部调用方必须先排除容器及其他 writer：仅用于持会话锁且尚未派发的
    首轮初始化，或 worker 全部停止后的历史迁移。普通运行中宿主写入继续
    使用 write_agent_workspace_file。逐文件原子发布并按 inode 净增量校验
    配额；失败恢复当前文件，保留已成功前缀和未列出的旧文件，允许安全续跑。
    progress(completed, total) 在每个文件提交后调用，节流由调用方负责。
    """
    files = files or {}
    if not files:
        return
    with _open_session_directories(session_id) as (_, session_fd, workspace_fd):
        max_bytes = _quota_limit()
        inode_references = {}
        total_bytes = _scan_workspace_usage_fd(
            workspace_fd, max_bytes=max_bytes, inode_references=inode_references,
        ).total_bytes

        def check_publication(old_info, new_info):
            nonlocal total_bytes
            old_key = (int(old_info.st_dev), int(old_info.st_ino)) if old_info else None
            old_size, old_count = inode_references.get(old_key, (0, 0))
            if old_info is not None and (
                old_count == 0 or old_size != max(0, int(old_info.st_size))
            ):
                raise AgentWorkspaceSecurityError("批量注入期间 workspace 被其他进程修改")
            projected = total_bytes + int(new_info.st_size) - (old_size if old_count == 1 else 0)
            if projected > max_bytes:
                raise AgentWorkspaceQuotaError(f"Agent workspace 总大小不能超过 {max_bytes} 字节")
            if old_count == 1:
                del inode_references[old_key]
            elif old_count > 1:
                inode_references[old_key] = (old_size, old_count - 1)
            inode_references[(int(new_info.st_dev), int(new_info.st_ino))] = (int(new_info.st_size), 1)
            total_bytes = projected

        staging_fd = _open_managed_child_directory(
            session_fd, ".host-write-staging", label="Agent workspace 宿主写入暂存目录",
        )
        try:
            for completed, (relative_path, source) in enumerate(files.items(), 1):
                normalized = _normalize_relative_path(relative_path, public=True)
                _publish_workspace_payload(
                    workspace_fd, staging_fd, tuple(PurePosixPath(normalized).parts),
                    _injection_source_payload(source), mode=0o600,
                    check_publication=check_publication,
                )
                if progress is not None:
                    progress(completed, len(files))
            actual = _scan_workspace_usage_fd(
                workspace_fd, max_bytes=max_bytes, inode_references={},
            )
            if actual.total_bytes != total_bytes:
                raise AgentWorkspaceSecurityError("批量注入期间 workspace 被其他进程修改")
        finally:
            os.close(staging_fd)


def export_agent_workspace_file(session_id, path, destination):
    """导出指定结果副本；拒绝链接，目标必须位于宿主私有输出目录。"""
    stream, metadata = open_agent_workspace_file(session_id, path)
    destination = Path(destination)
    with stream:
        if os.fstat(stream.fileno()).st_nlink != 1:
            raise AgentWorkspaceSecurityError("结果文件不能是硬链接")
        if metadata["size"] > _quota_limit():
            raise AgentWorkspaceQuotaError("导出文件超过工作区限额")
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                remaining = _quota_limit()
                while chunk := stream.read(min(1024 * 1024, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise AgentWorkspaceQuotaError("导出文件超过工作区限额")
                    output.write(chunk)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
    return destination


def export_agent_workspace_directory(session_id, path, destination):
    """导出公开 workspace 子树；'.' 表示根，私有运行数据不参与导出。

    调用方须在 Agent 结束且容器清理完成后导出；结果是与原 workspace
    独立的副本，遍历和文件打开都不跟随链接。
    """
    normalized = "" if path == "." else _normalize_relative_path(path, public=True)
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError("导出目标必须是新的私有目录")
    check_agent_workspace_quota(session_id)
    with _open_session_directories(session_id) as (_, _session_fd, workspace_fd):
        opened = []
        current_fd = workspace_fd
        try:
            for part in PurePosixPath(normalized).parts:
                current_fd = _open_existing_directory_at(current_fd, part, label="导出目录")
                opened.append(current_fd)
            def walk(directory_fd, relative, target):
                target.mkdir(mode=0o700, parents=True, exist_ok=False)
                for name in os.listdir(directory_fd):
                    if _is_private_name(name):
                        continue
                    _normalize_entry_name(name, attachment=True)
                    child_relative = f"{relative}/{name}" if relative else name
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child_fd = _open_existing_directory_at(directory_fd, name, label="导出子目录")
                        try:
                            walk(child_fd, child_relative, target / name)
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        export_agent_workspace_file(session_id, child_relative, target / name)
                    else:
                        raise AgentWorkspaceSecurityError("导出结果包含链接或特殊文件")
            walk(current_fd, normalized, destination)
        finally:
            for fd in reversed(opened):
                os.close(fd)
    return destination


__all__ = [
    "inject_agent_workspace_files",
    "export_agent_workspace_file",
    "export_agent_workspace_directory",
    "AGENT_WORKSPACE_ROOT",
    "AGENT_WORKSPACE_MAX_BYTES",
    "MAX_ATTACHMENT_FILES",
    "MAX_ATTACHMENT_FILE_BYTES",
    "MAX_ATTACHMENT_TOTAL_BYTES",
    "MAX_TEXT_PREVIEW_BYTES",
    "AgentWorkspaceError",
    "AgentWorkspacePathError",
    "AgentWorkspaceSecurityError",
    "AgentWorkspaceLimitError",
    "AgentWorkspaceQuotaError",
    "AgentWorkspaceUsage",
    "AgentAttachmentError",
    "ensure_agent_workspace",
    "initialize_agent_task_workspace",
    "merge_agent_temporary_redaction_candidates",
    "check_agent_workspace_quota",
    "get_agent_workspace_usage",
    "get_existing_agent_workspace_path",
    "write_agent_workspace_file",
    "save_agent_attachments",
    "remove_agent_attachments",
    "clear_agent_session_state_file",
    "build_agent_workspace_tree",
    "inspect_agent_workspace_file",
    "open_agent_workspace_file",
]
