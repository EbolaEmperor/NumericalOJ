#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在只读 Docker 根文件系统中运行一次解题或造数据 harness。"""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from config import (
    AGENT_CONTAINER_SITE_URL,
    AGENT_JUDGE_CPU_LIMIT,
    AGENT_JUDGE_DOCKER_IMAGE,
    AGENT_JUDGE_MEM_LIMIT,
    AGENT_JUDGE_PIDS_LIMIT,
    AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS,
    MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS,
)
from oj_modules.problems.agent_launch import (
    AGENT_ACCESS_ROLE_USER,
    normalize_agent_access_role,
    normalize_agent_task_kind,
    normalize_launch_harness,
    skill_for_agent_task,
)
from oj_modules.problems.agent_runs import agent_run_container_name
from oj_modules.site_config.services import get_web_search_settings
from oj_modules.tasks.agent.traces import (
    AGENT_TRACE_SYNC_INTERVAL_SECONDS,
    ensure_agent_trace_dir,
    prepare_agent_trace_dir,
    sync_agent_trace,
)


_CAPTURE_LIMIT_BYTES = 2 * 1024 * 1024
_STDOUT_MIRROR_LIMIT_BYTES = 8 * 1024 * 1024
_AGENT_CONTEXT_WINDOW_TOKENS = 128_000
_AGENT_MAX_OUTPUT_TOKENS = 16_384
_IDENTITY_CONFIG_PATH = "/workspace/.numoj-agent/identity.json"
_SKILL_CONFIG_ENV = {
    "numoj-user": "NUMOJ_USER_CONFIG",
    "numoj-admin": "NUMOJ_CLI_CONFIG",
}
_WEB_SEARCH_MCP_URL_ENV = "AJ_WEB_SEARCH_MCP_URL"
_WEB_SEARCH_MCP_AUTH_ENV = "AJ_WEB_SEARCH_MCP_AUTHORIZATION"
_WEB_SEARCH_MCP_TIMEOUT_ENV = "AJ_WEB_SEARCH_MCP_TIMEOUT_SECONDS"
_NATIVE_SESSION_ID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z",
)
_OPENCODE_NATIVE_SESSION_ID_RE = re.compile(
    r"ses_[A-Za-z0-9_-]{1,120}\Z",
)
_SESSION_STATE_RELATIVE_PATH = ".aj_session_state.json"
_SESSION_STATE_MAX_BYTES = 64 * 1024
_SKILL_WORKSPACE_RESERVATION_BYTES = 10 * 1024 * 1024
_SKILL_WORKSPACE_RESERVATION_FILES = 513
_SKILL_WORKSPACE_RESERVATION_DIRECTORIES = 512


@dataclass(frozen=True, slots=True)
class HarnessRunResult:
    returncode: int
    timed_out: bool
    stdout: str
    stderr: str
    artifacts: dict[str, bytes] = field(default_factory=dict)
    created_submission_ids: tuple[int, ...] = ()
    native_session_id: str = ""


class AgentHarnessCleanupError(RuntimeError):
    """无法证明本轮容器已停止；会话不得进入可续聊终态。"""


def _containerize_url(value):
    """让容器内的 localhost 端点显式回到宿主机。"""

    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw
    if str(parsed.hostname or "").lower() not in {"localhost", "127.0.0.1", "::1"}:
        return raw
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit(
        (
            parsed.scheme,
            f"host.docker.internal{port}",
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def _safe_workspace_path(workspace, relative_path):
    relative = Path(str(relative_path or ""))
    if relative.is_absolute() or not relative.parts:
        raise ValueError("Agent 工作区文件路径无效")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Agent 工作区文件路径无效")
    target = (Path(workspace) / relative).resolve()
    root = Path(workspace).resolve()
    if target == root or root not in target.parents:
        raise ValueError("Agent 工作区文件越界")
    return target


def _workspace_entry_path(workspace, relative_path):
    relative = Path(str(relative_path or ""))
    if relative.is_absolute() or not relative.parts:
        raise ValueError("Agent 工作区文件路径无效")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Agent 工作区文件路径无效")
    root = Path(workspace).resolve()
    return root, relative, root / relative


def _ensure_workspace_directory(workspace, relative_path, *, mode=0o700):
    root, relative, _target = _workspace_entry_path(workspace, relative_path)
    current = root
    for part in relative.parts:
        current = current / part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=mode)
            continue
        if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(current_stat.st_mode):
            raise ValueError("Agent 工作区目录不安全")
    return current


def _write_workspace_file(session_id, relative_path, content, *, mode=0o600):
    from oj_modules.agents.workspace import write_agent_workspace_file

    return write_agent_workspace_file(
        session_id,
        relative_path,
        content,
        mode=mode,
    )


def _prepare_workspace_temp_path(workspace, relative_path):
    root, relative, _target = _workspace_entry_path(workspace, relative_path)
    parent = (
        root
        if len(relative.parts) == 1
        else _ensure_workspace_directory(root, Path(*relative.parts[:-1]))
    )
    target = parent / relative.name
    try:
        current = target.lstat()
    except FileNotFoundError:
        return target
    if stat.S_ISDIR(current.st_mode):
        raise ValueError("Agent 临时文件路径被目录占用")
    target.unlink()
    return target


def _read_workspace_artifacts(workspace, artifact_files):
    """容器已停止后，安全读取显式声明的任务产物。"""

    root = Path(workspace).resolve()
    result = {}
    for relative_path in artifact_files or ():
        relative = Path(str(relative_path or ""))
        _safe_workspace_path(root, relative)

        current = root
        for part in relative.parts[:-1]:
            current = current / part
            try:
                current_stat = current.lstat()
            except OSError as exc:
                raise ValueError(f"Agent 产物目录不存在：{relative_path}") from exc
            if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(current_stat.st_mode):
                raise ValueError(f"Agent 产物目录不安全：{relative_path}")

        target = root / relative
        try:
            target_stat = target.lstat()
        except OSError as exc:
            raise ValueError(f"Agent 没有生成预期产物：{relative_path}") from exc
        if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
            raise ValueError(f"Agent 产物必须是普通文件：{relative_path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags)
        try:
            opened_stat = os.fstat(fd)
            if (
                not stat.S_ISREG(opened_stat.st_mode)
                or opened_stat.st_dev != target_stat.st_dev
                or opened_stat.st_ino != target_stat.st_ino
            ):
                raise ValueError(f"Agent 产物读取时发生变化：{relative_path}")
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(fd)
        result[str(relative)] = payload
    return result


def normalize_native_session_id(value, harness):
    """按 harness 校验不透明原生 ID；OpenCode 的大小写必须原样保留。"""

    normalized = str(value or "").strip()
    if not normalized:
        return ""
    normalized_harness = str(harness or "").strip().lower().replace("-", "_")
    if normalized_harness == "opencode":
        if not _OPENCODE_NATIVE_SESSION_ID_RE.fullmatch(normalized):
            raise ValueError("Agent 原生 session_id 无效")
        return normalized
    if not _NATIVE_SESSION_ID_RE.fullmatch(normalized):
        raise ValueError("Agent 原生 session_id 无效")
    return normalized.lower()


def _ensure_stable_workspace(session_id):
    """延迟导入会话工作区，避免任务包导入时触发目录写入。"""

    from oj_modules.agents.workspace import ensure_agent_workspace

    workspace = Path(ensure_agent_workspace(session_id)).expanduser().resolve()
    if not workspace.is_dir() or workspace.is_symlink():
        raise RuntimeError("Agent 会话工作区不可用")
    return workspace


def _clear_current_session_state(workspace):
    """每轮启动前移除上一轮摘要，防止把陈旧 session 当成新结果。"""

    state_path = Path(workspace) / _SESSION_STATE_RELATIVE_PATH
    try:
        current = state_path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(current.st_mode):
        raise ValueError("Agent 原生会话状态路径被目录占用")
    state_path.unlink()


def _remove_identity_config(workspace, relative_path):
    """删除本轮身份占位配置；异常类型会阻止会话被误标为可续聊。"""

    root, relative, _target = _workspace_entry_path(workspace, relative_path)
    parent = root
    for part in relative.parts[:-1]:
        parent = parent / part
        try:
            parent_state = parent.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise AgentHarnessCleanupError("Agent 身份配置清理失败") from exc
        if stat.S_ISLNK(parent_state.st_mode) or not stat.S_ISDIR(parent_state.st_mode):
            raise AgentHarnessCleanupError("Agent 身份配置清理失败：父目录不安全")
    identity_path = parent / relative.name
    try:
        current = identity_path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AgentHarnessCleanupError("Agent 身份配置清理失败") from exc
    if stat.S_ISDIR(current.st_mode):
        raise AgentHarnessCleanupError("Agent 身份配置清理失败：路径被目录占用")
    try:
        identity_path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AgentHarnessCleanupError("Agent 身份配置清理失败") from exc


@contextmanager
def _identity_relay_context(*args, **kwargs):
    from oj_modules.tasks.agent.identity_relay import (
        IdentityRelayCleanupError,
        run_numoj_identity_relay,
    )

    try:
        with run_numoj_identity_relay(*args, **kwargs) as relay:
            yield relay
    except IdentityRelayCleanupError as exc:
        raise AgentHarnessCleanupError(str(exc)) from exc


@contextmanager
def _secret_relay_context(*args, **kwargs):
    from oj_modules.tasks.agent.secret_relay import (
        AgentSecretRelayCleanupError,
        run_agent_secret_relays,
    )

    try:
        with run_agent_secret_relays(*args, **kwargs) as relay:
            yield relay
    except AgentSecretRelayCleanupError as exc:
        raise AgentHarnessCleanupError(str(exc)) from exc


def _read_native_session_id(workspace, harness):
    """容器停止后以 no-follow + inode 复核读取原生 session 摘要。"""

    state_path = Path(workspace) / _SESSION_STATE_RELATIVE_PATH
    try:
        before = state_path.lstat()
    except FileNotFoundError:
        return ""
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("Agent 原生会话状态不是安全的普通文件")
    if before.st_size > _SESSION_STATE_MAX_BYTES:
        raise ValueError("Agent 原生会话状态过大")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(state_path, flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise ValueError("Agent 原生会话状态读取时发生变化")
        payload = os.read(fd, _SESSION_STATE_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(payload) > _SESSION_STATE_MAX_BYTES:
        raise ValueError("Agent 原生会话状态过大")
    try:
        state = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Agent 原生会话状态无效") from exc
    if not isinstance(state, dict):
        raise ValueError("Agent 原生会话状态无效")
    if str(state.get("harness") or "").strip().lower() != str(harness):
        raise ValueError("Agent 原生会话状态与 harness 不一致")
    return normalize_native_session_id(state.get("session_id"), harness)


def read_agent_native_session_id(session_id, harness):
    """读取正在运行或已结束会话的最近原生恢复点。"""

    normalized_harness = normalize_launch_harness(harness)
    workspace = _ensure_stable_workspace(session_id)
    return _read_native_session_id(workspace, normalized_harness)


class _BoundedStdoutMirror:
    """保留 stdout 的有界完整行尾部，并以原子快照供轨迹同步读取。"""

    def __init__(self, path, limit):
        self._path = os.fspath(path)
        self._limit = max(1, int(limit))
        self._chunks = deque()
        self._size = 0
        self._starts_mid_record = False
        self._closed = False
        self._lock = threading.Lock()

    def write(self, block):
        payload = bytes(block or b"")
        if not payload:
            return 0
        with self._lock:
            if self._closed:
                raise OSError("stdout mirror 已关闭")
            self._chunks.append(payload)
            self._size += len(payload)
            overflow = self._size - self._limit
            removed_last_byte = b""
            while self._chunks and overflow > 0:
                first = self._chunks[0]
                if len(first) <= overflow:
                    removed = self._chunks.popleft()
                    removed_last_byte = removed[-1:]
                    self._size -= len(removed)
                    overflow -= len(removed)
                else:
                    removed_last_byte = first[overflow - 1 : overflow]
                    self._chunks[0] = first[overflow:]
                    self._size -= overflow
                    overflow = 0
            if removed_last_byte:
                self._starts_mid_record = removed_last_byte != b"\n"
        return len(payload)

    def _snapshot(self):
        with self._lock:
            payload = b"".join(self._chunks)
            starts_mid_record = self._starts_mid_record
        if starts_mid_record:
            boundary = payload.find(b"\n")
            if boundary < 0:
                return b""
            payload = payload[boundary + 1 :]
        return payload

    def publish(self):
        payload = self._snapshot()
        directory = os.path.dirname(self._path) or "."
        temporary = ""
        try:
            descriptor, temporary = tempfile.mkstemp(
                dir=directory,
                prefix=f".{os.path.basename(self._path)}.",
                suffix=".tmp",
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
            os.replace(temporary, self._path)
            return True
        except OSError:
            if temporary:
                try:
                    os.remove(temporary)
                except OSError:
                    pass
            return False

    def close(self):
        with self._lock:
            self._closed = True


def _tail_reader(
    stream,
    chunks,
    size_state,
    key,
    limit,
    *,
    mirror_stream=None,
):
    try:
        while True:
            block = stream.read(65536)
            if not block:
                break
            if mirror_stream is not None:
                try:
                    mirror_stream.write(block)
                except OSError:
                    # 轨迹落盘失败不能阻断 stdout drain，否则 harness 可能因
                    # pipe 写满而卡死；任务结果仍保留有界尾部。
                    mirror_stream = None
            chunks.append(block)
            size_state[key] += len(block)
            while chunks and size_state[key] > limit:
                overflow = size_state[key] - limit
                if len(chunks[0]) <= overflow:
                    size_state[key] -= len(chunks.popleft())
                else:
                    chunks[0] = chunks[0][overflow:]
                    size_state[key] -= overflow
    finally:
        stream.close()


def _run_with_bounded_output(
    args,
    prompt,
    *,
    process_env=None,
    stdout_capture_path=None,
    on_tick=None,
    tick_interval=AGENT_TRACE_SYNC_INTERVAL_SECONDS,
    cancel_check=None,
    cancel_check_interval=1.0,
    quota_check=None,
    quota_check_interval=AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS,
):
    stdout_mirror = (
        _BoundedStdoutMirror(
            stdout_capture_path,
            _STDOUT_MIRROR_LIMIT_BYTES,
        )
        if stdout_capture_path else None
    )
    try:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=process_env,
        )
    except BaseException:
        if stdout_mirror is not None:
            stdout_mirror.close()
        raise
    stdout_chunks = deque()
    stderr_chunks = deque()
    sizes = {"stdout": 0, "stderr": 0}
    threads = [
        threading.Thread(
            target=_tail_reader,
            args=(proc.stdout, stdout_chunks, sizes, "stdout", _CAPTURE_LIMIT_BYTES),
            kwargs={"mirror_stream": stdout_mirror},
            daemon=True,
        ),
        threading.Thread(
            target=_tail_reader,
            args=(proc.stderr, stderr_chunks, sizes, "stderr", _CAPTURE_LIMIT_BYTES),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    try:
        try:
            proc.stdin.write(str(prompt or "").encode("utf-8"))
        except BrokenPipeError:
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
        # 与 Reverse Judge 一致：进入执行循环后立即做第一次同步，后续再按
        # 固定间隔同步，避免前端必须空等完整的 tick 周期。
        last_tick = 0.0
        last_cancel_check = None
        last_quota_check = None
        while True:
            try:
                returncode = proc.wait(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                if (
                    callable(quota_check)
                    and (
                        last_quota_check is None
                        or now - last_quota_check
                        >= max(0.5, float(quota_check_interval))
                    )
                ):
                    last_quota_check = now
                    # 配额与磁盘保留检查是安全边界，异常必须
                    # 传播到外层杀死 docker exec，不得像 trace tick 那样吞掉。
                    quota_check()
                if (
                    callable(cancel_check)
                    and (
                        last_cancel_check is None
                        or now - last_cancel_check
                        >= max(0.5, float(cancel_check_interval))
                    )
                ):
                    last_cancel_check = now
                    try:
                        canceled = bool(cancel_check())
                    except Exception:
                        canceled = False
                    if canceled:
                        proc.terminate()
                        try:
                            returncode = proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            returncode = proc.wait()
                        break
                if (
                    callable(on_tick)
                    and now - last_tick >= max(0.5, float(tick_interval))
                ):
                    try:
                        if stdout_mirror is not None:
                            stdout_mirror.publish()
                        on_tick(final=False)
                    except Exception:
                        pass
                    last_tick = now
    except BaseException:
        try:
            proc.kill()
            proc.wait(timeout=10)
        except Exception:
            pass
        raise
    finally:
        for thread in threads:
            thread.join()
        if stdout_mirror is not None:
            stdout_mirror.publish()
        if callable(on_tick):
            try:
                on_tick(final=True)
            except Exception:
                pass
        if stdout_mirror is not None:
            stdout_mirror.close()
    return HarnessRunResult(
        returncode=int(returncode),
        timed_out=False,
        stdout=b"".join(stdout_chunks).decode("utf-8", "replace"),
        stderr=b"".join(stderr_chunks).decode("utf-8", "replace"),
    )


def _web_search_mcp_env(settings):
    if not settings:
        return {}
    base_url = _containerize_url(settings.get("base_url"))
    authorization = str(settings.get("authorization") or "").strip()
    if not base_url or not authorization:
        raise RuntimeError("站点 Web Search MCP 配置不完整")
    try:
        timeout_seconds = int(MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        timeout_seconds = 90
    timeout_seconds = max(10, min(240, timeout_seconds))
    return {
        _WEB_SEARCH_MCP_URL_ENV: base_url,
        _WEB_SEARCH_MCP_AUTH_ENV: authorization,
        _WEB_SEARCH_MCP_TIMEOUT_ENV: str(timeout_seconds),
    }


def _runtime_env(
    endpoint,
    harness,
    task_kind,
    *,
    endpoint_base_url,
    endpoint_api_key,
    access_role=AGENT_ACCESS_ROLE_USER,
    resume_session_id="",
    web_search_settings=None,
):
    protocol = str(endpoint.get("protocol") or "").strip().lower()
    # 长期密钥和真实上游地址不得进入容器；这里只接受本轮宿主 relay
    # 返回的容器地址与临时 API Key。
    base_url = str(endpoint_base_url or "").strip()
    api_key = str(endpoint_api_key or "").strip()
    if not base_url or not api_key:
        raise RuntimeError("Agent 外部服务密钥代理配置不完整")
    model = str(endpoint.get("model") or "").strip()
    thinking_enabled = bool(endpoint.get("thinking_enabled"))
    thinking_format = str(endpoint.get("thinking_format") or "none").strip().lower()
    access_role = normalize_agent_access_role(access_role, task_kind=task_kind)
    skill_name = skill_for_agent_task(task_kind, access_role)
    resume_session_id = normalize_native_session_id(resume_session_id, harness)

    env = {
        "IS_SANDBOX": "1",
        "HOME": "/workspace/.runtime/home",
        "TMPDIR": "/workspace/.runtime/tmp",
        "XDG_CACHE_HOME": "/workspace/.runtime/xdg-cache",
        "XDG_CONFIG_HOME": "/workspace/.runtime/xdg-config",
        "XDG_DATA_HOME": "/workspace/.runtime/xdg-data",
        "PYTHONDONTWRITEBYTECODE": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "AJ_HARNESS": harness,
        "AJ_ENDPOINT_PROTOCOL": protocol,
        "AJ_ENDPOINT_BASE_URL": base_url,
        "AJ_ENDPOINT_API_KEY": api_key,
        "AJ_ENDPOINT_MODEL": model,
        "AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS": str(_AGENT_CONTEXT_WINDOW_TOKENS),
        "AJ_ENDPOINT_MAX_OUTPUT_TOKENS": str(_AGENT_MAX_OUTPUT_TOKENS),
        "AJ_ENDPOINT_THINKING_ENABLED": "1" if thinking_enabled else "0",
        "AJ_ENDPOINT_THINKING_FORMAT": thinking_format,
        "AJ_ENABLE_SKILLS": "1",
        "AJ_TASK_SCOPE": "problem_agent",
        "AJ_RUNTIME_ROOT": "/workspace/.runtime",
        "AJ_PROMPT_STDIN": "1",
        "AJ_WORKSPACE": "/workspace",
        _SKILL_CONFIG_ENV[skill_name]: _IDENTITY_CONFIG_PATH,
    }
    if resume_session_id:
        env["AJ_RESUME_SESSION_ID"] = resume_session_id
        # 真正的“继续会话”必须复用同一个原生 session；Claude Code 的
        # --fork-session 会创建分支，不能作为通用 Agent 的续聊语义。
        env["AJ_FORK_SESSION"] = "0"
    env.update(_web_search_mcp_env(web_search_settings))
    return env


def _docker_args(*, container_name, workspace, env):
    # Colima/virtiofs 会把 macOS bind mount 的属主统一投影为容器 root，数值
    # keep-id 反而无法写入任务目录。本地 Darwin 仅在已经只读根、无 capability、
    # no-new-privileges 的容器中使用 root；Linux 生产仍严格沿用部署用户 UID/GID。
    if platform.system() == "Darwin":
        container_user = "0:0"
    else:
        container_user = f"{os.getuid()}:{os.getgid()}"
    args = [
        "docker",
        "run",
        "--detach",
        "--name",
        container_name,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--ipc",
        "none",
        "--pids-limit",
        str(AGENT_JUDGE_PIDS_LIMIT),
        "--memory",
        str(AGENT_JUDGE_MEM_LIMIT),
        "--cpus",
        str(AGENT_JUDGE_CPU_LIMIT),
        "--user",
        container_user,
        "--add-host",
        "host.docker.internal:host-gateway",
        "--volume",
        f"{Path(workspace).resolve()}:/workspace:rw",
        "--workdir",
        "/workspace",
    ]
    # 只把变量名放进 docker 命令行；值通过 docker 客户端自身的环境继承，
    # 避免 LLM API Key 出现在宿主进程参数和常规进程清单中。
    for key in env:
        args.extend(["--env", key])
    args.extend([
        str(AGENT_JUDGE_DOCKER_IMAGE),
        "bash",
        "-lc",
        "tail -f /dev/null",
    ])
    return args


def _docker_exec_args(container_name):
    return [
        "docker",
        "exec",
        "-i",
        container_name,
        "/usr/local/bin/run_harness",
    ]


def _docker_process_env(container_env):
    """构造 Docker CLI 环境，同时保留宿主的 context 配置位置。"""

    process_env = os.environ.copy()
    host_home = str(process_env.get("HOME") or "").strip()
    if not str(process_env.get("DOCKER_CONFIG") or "").strip() and host_home:
        # `docker run --env HOME` 仍需从此环境读取容器值，但 Docker CLI 自身
        # 必须继续从宿主 ~/.docker 读取 Colima/Desktop context。
        process_env["DOCKER_CONFIG"] = str(Path(host_home) / ".docker")
    process_env.update(container_env)
    return process_env


def _sanitize_output(result, *, secrets):
    stdout = result.stdout
    stderr = result.stderr
    values = {
        str(secret or "")
        for secret in secrets
        if str(secret or "")
    }
    for value in sorted(values, key=len, reverse=True):
        stdout = stdout.replace(value, "[已脱敏]")
        stderr = stderr.replace(value, "[已脱敏]")
    return HarnessRunResult(
        returncode=result.returncode,
        timed_out=result.timed_out,
        stdout=stdout,
        stderr=stderr,
        artifacts=dict(result.artifacts or {}),
        created_submission_ids=tuple(result.created_submission_ids or ()),
        native_session_id=str(result.native_session_id or ""),
    )


def _remove_agent_container(container_name):
    """确认同名容器已不存在；daemon 故障不能伪装成清理成功。"""

    last_detail = ""
    for _attempt in range(2):
        try:
            completed = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception as exc:
            last_detail = str(exc)
            continue
        detail = f"{completed.stdout or ''}\n{completed.stderr or ''}".strip()
        if completed.returncode == 0 or "no such container" in detail.lower():
            return
        last_detail = detail or f"docker rm exited {completed.returncode}"
    raise AgentHarnessCleanupError(
        f"无法确认 Agent 容器 {container_name} 已清理：{last_detail[:500]}"
    )


def _container_name_for_task_id(task_id):
    return agent_run_container_name(task_id)


def run_agent_harness(
    *,
    task_id,
    task_kind,
    problem_id=None,
    requested_by,
    harness,
    endpoint,
    session_cookie,
    prompt,
    session_id=None,
    access_role=AGENT_ACCESS_ROLE_USER,
    resume_session_id="",
    session_cookie_name="session",
    workspace_files=None,
    artifact_files=None,
    trace_callback=None,
    cancel_check=None,
    reset_trace=True,
):
    """在稳定会话工作区内运行一轮 harness，结束后只删除容器和凭证。"""

    task_kind = normalize_agent_task_kind(task_kind)
    harness = normalize_launch_harness(harness)
    access_role = normalize_agent_access_role(access_role, task_kind=task_kind)
    resume_session_id = normalize_native_session_id(resume_session_id, harness)
    quota_check_interval = float(AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS)
    if quota_check_interval <= 0:
        raise RuntimeError(
            "AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS 必须是正数"
        )
    if callable(cancel_check):
        try:
            canceled_before_start = bool(cancel_check())
        except Exception:
            canceled_before_start = False
        if canceled_before_start:
            return HarnessRunResult(
                returncode=-15,
                timed_out=False,
                stdout="",
                stderr="Agent task canceled before harness startup",
            )
    skill_name = skill_for_agent_task(task_kind, access_role)
    normalized_session_id = str(session_id or task_id or "").strip()
    workspace = _ensure_stable_workspace(normalized_session_id)
    from oj_modules.agents.workspace import (
        check_agent_workspace_quota,
        merge_agent_temporary_redaction_candidates,
    )

    check_agent_workspace_quota(normalized_session_id)
    container_name = _container_name_for_task_id(task_id)
    trace_dir = (
        prepare_agent_trace_dir(task_id)
        if reset_trace
        else ensure_agent_trace_dir(task_id)
    )
    runtime_dirs = (
        ".runtime/home",
        ".runtime/tmp",
        ".runtime/xdg-cache",
        ".runtime/xdg-config",
        ".runtime/xdg-data",
    )
    for relative in runtime_dirs:
        _ensure_workspace_directory(workspace, relative)

    # Session 只驻留在宿主转发器内存中。工作区里的固定占位 cookie 仅用于
    # NumOJ CLI 的本地“已登录”检查，没有任何站点权限。
    from oj_modules.tasks.agent.skill_runtime import materialize_skill

    cookie_name = str(session_cookie_name or "").strip() or "session"
    identity_relative_path = ".numoj-agent/identity.json"
    stdout_trace_path = _prepare_workspace_temp_path(
        trace_dir,
        ".agent_harness.stdout.tmp",
    )
    # late-ack 重投时必须先清理由同一 task_id 留下的旧容器，再开放身份
    # 转发端口，避免旧 Agent 与本次代理生命周期发生重叠。
    _remove_agent_container(container_name)
    _clear_current_session_state(workspace)
    try:
        with _identity_relay_context(
            task_kind,
            problem_id,
            AGENT_CONTAINER_SITE_URL,
            cookie_name,
            str(session_cookie or ""),
            requested_by=str(requested_by or ""),
            access_role=access_role,
        ) as identity_relay:
            agent_task = {
                "task_id": str(task_id or ""),
                "session_id": normalized_session_id,
                "task_kind": task_kind,
                "access_role": access_role,
                "skill": skill_name,
            }
            if problem_id is not None:
                agent_task["problem_id"] = int(problem_id)
            identity_config = {
                "base_url": identity_relay.base_url,
                "username": str(requested_by or ""),
                "cookies": {"session": "relay-placeholder"},
                "agent_task": agent_task,
            }
            _write_workspace_file(
                normalized_session_id,
                ".numoj-agent/identity.json",
                json.dumps(identity_config, ensure_ascii=False, indent=2),
            )
            for relative_path, content in (workspace_files or {}).items():
                _write_workspace_file(
                    normalized_session_id,
                    relative_path,
                    content,
                )

            # 每一轮都从仓库规范源重新投影唯一允许的 skill；会话工作区虽会
            # 持久化，但不能信任上一轮留下的运行时配置。
            check_agent_workspace_quota(
                normalized_session_id,
                additional_bytes=_SKILL_WORKSPACE_RESERVATION_BYTES,
                additional_files=_SKILL_WORKSPACE_RESERVATION_FILES,
                additional_entries=_SKILL_WORKSPACE_RESERVATION_DIRECTORIES,
            )
            materialize_skill(workspace, harness, skill_name)
            check_agent_workspace_quota(normalized_session_id)
            web_search_settings = get_web_search_settings(include_secret=True)
            with _secret_relay_context(
                endpoint,
                web_search_settings,
            ) as secret_relay:
                relayed_web_search_settings = None
                if secret_relay.web_search_base_url:
                    relayed_web_search_settings = {
                        "base_url": secret_relay.web_search_base_url,
                        "authorization": (
                            secret_relay.web_search_authorization
                        ),
                    }
                env = _runtime_env(
                    endpoint,
                    harness,
                    task_kind,
                    endpoint_base_url=secret_relay.endpoint_base_url,
                    endpoint_api_key=secret_relay.endpoint_api_key,
                    access_role=access_role,
                    resume_session_id=resume_session_id,
                    web_search_settings=relayed_web_search_settings,
                )
                docker_args = _docker_args(
                    container_name=container_name,
                    workspace=workspace,
                    env=env,
                )
                docker_process_env = _docker_process_env(env)
                identity_temporary_secrets = tuple(
                    getattr(identity_relay, "temporary_secrets", ()) or (),
                )
                # 原生 resume 会保留并再次同步旧轮次 session 文件。这里只把
                # 短生命周期 relay 候选写入容器不可见的宿主会话元数据；真实
                # Session cookie 和长期 endpoint / MCP 凭据仍只驻留本轮内存。
                temporary_trace_secrets = (
                    *identity_temporary_secrets,
                    *secret_relay.temporary_secrets,
                )
                historical_temporary_secrets = (
                    merge_agent_temporary_redaction_candidates(
                        normalized_session_id,
                        temporary_trace_secrets,
                    )
                )
                trace_secrets = (
                    *historical_temporary_secrets,
                    session_cookie,
                    endpoint.get("api_key"),
                    (web_search_settings or {}).get("authorization"),
                )

                def sync_trace(*, final=False):
                    sync_agent_trace(
                        container_name,
                        trace_dir,
                        harness,
                        stdout_trace_path,
                        secrets=trace_secrets,
                    )
                    if callable(trace_callback):
                        try:
                            trace_callback()
                        except Exception:
                            # 轨迹缓存不可用不能中止已运行的 Agent；终态仍会走任务状态
                            # 的规范持久化链路。
                            pass

                def enforce_workspace_quota():
                    return check_agent_workspace_quota(normalized_session_id)

                try:
                    # Docker 启动是最后一个外部副作用；在此前再校验一次，
                    # 确保宿主注入和 skill 投影没有越过配额。
                    enforce_workspace_quota()
                    subprocess.run(
                        docker_args,
                        check=True,
                        capture_output=True,
                        env=docker_process_env,
                        timeout=120,
                    )
                    sync_trace()
                    result = _run_with_bounded_output(
                        _docker_exec_args(container_name),
                        prompt,
                        process_env=docker_process_env,
                        stdout_capture_path=stdout_trace_path,
                        on_tick=sync_trace,
                        tick_interval=AGENT_TRACE_SYNC_INTERVAL_SECONDS,
                        cancel_check=cancel_check,
                        quota_check=enforce_workspace_quota,
                        quota_check_interval=quota_check_interval,
                    )
                    enforce_workspace_quota()
                    sync_trace()
                finally:
                    try:
                        _remove_agent_container(container_name)
                    finally:
                        try:
                            stdout_trace_path.unlink()
                        except FileNotFoundError:
                            pass
            artifacts = _read_workspace_artifacts(workspace, artifact_files)
            native_session_id = (
                _read_native_session_id(workspace, harness)
                or resume_session_id
            )
            result = HarnessRunResult(
                returncode=result.returncode,
                timed_out=result.timed_out,
                stdout=result.stdout,
                stderr=result.stderr,
                artifacts=artifacts,
                created_submission_ids=identity_relay.created_submission_ids,
                native_session_id=native_session_id,
            )
            return _sanitize_output(result, secrets=trace_secrets)
    finally:
        # 保留 Agent 工作产物和原生 session，真实 Session 从未落盘；本地 CLI
        # 占位配置也在每轮结束后删除，避免闲置工作区保留可误用入口。
        _remove_identity_config(workspace, identity_relative_path)


__all__ = [
    "AgentHarnessCleanupError",
    "HarnessRunResult",
    "normalize_native_session_id",
    "read_agent_native_session_id",
    "run_agent_harness",
]
