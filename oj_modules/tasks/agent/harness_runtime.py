#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在只读 Docker 根文件系统中运行一次解题或造数据 harness。"""

from __future__ import annotations

from collections import deque
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
    AGENT_JUDGE_DEFAULT_TIMEOUT,
    AGENT_JUDGE_DOCKER_IMAGE,
    AGENT_JUDGE_MEM_LIMIT,
    AGENT_JUDGE_PIDS_LIMIT,
    AGENT_WORKSPACE_ROOT,
    MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS,
)
from oj_modules.problems.agent_launch import (
    normalize_agent_task_kind,
    normalize_launch_harness,
    skill_for_agent_task,
)
from oj_modules.site_config.services import get_web_search_settings
from oj_modules.tasks.agent.traces import (
    AGENT_TRACE_SYNC_INTERVAL_SECONDS,
    ensure_agent_trace_dir,
    prepare_agent_trace_dir,
    sync_agent_trace,
)


_CAPTURE_LIMIT_BYTES = 2 * 1024 * 1024
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


@dataclass(frozen=True, slots=True)
class HarnessRunResult:
    returncode: int
    timed_out: bool
    stdout: str
    stderr: str
    artifacts: dict[str, bytes] = field(default_factory=dict)
    created_submission_ids: tuple[int, ...] = ()


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


def _write_workspace_file(workspace, relative_path, content, *, mode=0o600):
    target = _safe_workspace_path(workspace, relative_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(str(content), encoding="utf-8")
    target.chmod(mode)
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
    timeout,
    process_env=None,
    stdout_capture_path=None,
    on_tick=None,
    tick_interval=AGENT_TRACE_SYNC_INTERVAL_SECONDS,
):
    stdout_mirror = (
        open(stdout_capture_path, "wb", buffering=0)
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
        timeout_seconds = max(1, int(timeout))
        deadline = time.monotonic() + timeout_seconds
        # 与 Reverse Judge 一致：进入执行循环后立即做第一次同步，后续再按
        # 固定间隔同步，避免前端必须空等完整的 tick 周期。
        last_tick = 0.0
        timed_out = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                proc.kill()
                returncode = proc.wait()
                break
            try:
                returncode = proc.wait(timeout=min(0.25, remaining))
                break
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                if (
                    callable(on_tick)
                    and now - last_tick >= max(0.5, float(tick_interval))
                ):
                    try:
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
        if callable(on_tick):
            try:
                on_tick(final=True)
            except Exception:
                pass
        if stdout_mirror is not None:
            stdout_mirror.close()
    return HarnessRunResult(
        returncode=int(returncode),
        timed_out=timed_out,
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


def _runtime_env(endpoint, harness, task_kind, *, web_search_settings=None):
    protocol = str(endpoint.get("protocol") or "").strip().lower()
    base_url = _containerize_url(endpoint.get("base_url"))
    api_key = str(endpoint.get("api_key") or "").strip()
    model = str(endpoint.get("model") or "").strip()
    thinking_enabled = bool(endpoint.get("thinking_enabled"))
    thinking_format = str(endpoint.get("thinking_format") or "none").strip().lower()
    try:
        endpoint_hostname = str(urlsplit(base_url).hostname or "").lower().rstrip(".")
    except ValueError:
        endpoint_hostname = ""
    harness_thinking_format = (
        "deepseek"
        if endpoint_hostname == "deepseek.com"
        or endpoint_hostname.endswith(".deepseek.com")
        else "generic"
    )
    skill_name = skill_for_agent_task(task_kind)

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
        "AJ_CONTEXT_WINDOW_TOKENS": str(_AGENT_CONTEXT_WINDOW_TOKENS),
        "AJ_MAX_OUTPUT_TOKENS": str(_AGENT_MAX_OUTPUT_TOKENS),
        "AJ_THINKING_COMPATIBILITY": "1" if thinking_enabled else "0",
        "AJ_ENDPOINT_THINKING_FORMAT": thinking_format,
        "AJ_THINKING_FORMAT": harness_thinking_format,
        "AJ_ENABLE_SKILLS": "1",
        "AJ_RUNTIME_ROOT": "/workspace/.runtime",
        "AJ_PROMPT_STDIN": "1",
        "AJ_WORKSPACE": "/workspace",
        _SKILL_CONFIG_ENV[skill_name]: _IDENTITY_CONFIG_PATH,
    }
    if harness == "claude_code":
        env.update({
            "ANTHROPIC_BASE_URL": base_url,
            "ANTHROPIC_AUTH_TOKEN": api_key,
            "ANTHROPIC_API_KEY": api_key,
            "ANTHROPIC_MODEL": model,
        })
    elif harness == "codex":
        env.update({
            "OPENAI_BASE_URL": base_url,
            "OPENAI_API_KEY": api_key,
            "OPENAI_MODEL": model,
        })
    elif harness == "opencode":
        env.update({
            "OPENCODE_BASE_URL": base_url,
            "OPENCODE_API_KEY": api_key,
            "OPENCODE_MODEL": model,
        })
    elif protocol == "anthropic":
        env.update({
            "ANTHROPIC_BASE_URL": base_url,
            "ANTHROPIC_AUTH_TOKEN": api_key,
            "ANTHROPIC_API_KEY": api_key,
            "ANTHROPIC_MODEL": model,
        })
    else:
        env.update({
            "OPENAI_BASE_URL": base_url,
            "OPENAI_API_KEY": api_key,
            "OPENAI_MODEL": model,
        })
    if harness == "pi":
        env["AJ_PI_THINKING_FORMAT"] = harness_thinking_format
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
    inner_timeout = max(1, int(AGENT_JUDGE_DEFAULT_TIMEOUT) - 10)
    return [
        "docker",
        "exec",
        "-i",
        container_name,
        "timeout",
        "-k",
        "10s",
        f"{inner_timeout}s",
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
    for secret in secrets:
        value = str(secret or "")
        if value:
            stdout = stdout.replace(value, "[已脱敏]")
            stderr = stderr.replace(value, "[已脱敏]")
    return HarnessRunResult(
        returncode=result.returncode,
        timed_out=result.timed_out,
        stdout=stdout,
        stderr=stderr,
        artifacts=dict(result.artifacts or {}),
        created_submission_ids=tuple(result.created_submission_ids or ()),
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
    raise RuntimeError(
        f"无法确认 Agent 容器 {container_name} 已清理：{last_detail[:500]}"
    )


def _container_name_for_task_id(task_id):
    safe_task_id = re.sub(
        r"[^a-zA-Z0-9_.-]", "-", str(task_id or ""),
    ) or "unknown"
    return f"numoj-agent-{safe_task_id}"


def run_agent_harness(
    *,
    task_id,
    task_kind,
    problem_id,
    requested_by,
    harness,
    endpoint,
    session_cookie,
    prompt,
    session_cookie_name="session",
    workspace_files=None,
    artifact_files=None,
    trace_callback=None,
    reset_trace=True,
):
    """运行一次 harness；任务结束后凭证和整个工作区都会被删除。"""

    task_kind = normalize_agent_task_kind(task_kind)
    harness = normalize_launch_harness(harness)
    skill_name = skill_for_agent_task(task_kind)
    workspace_root = Path(AGENT_WORKSPACE_ROOT).expanduser().resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    safe_task_id = re.sub(r"[^a-zA-Z0-9_.-]", "-", str(task_id or "")) or "unknown"
    container_name = _container_name_for_task_id(task_id)
    trace_dir = (
        prepare_agent_trace_dir(task_id)
        if reset_trace
        else ensure_agent_trace_dir(task_id)
    )

    with tempfile.TemporaryDirectory(
        prefix=f"{task_kind}-{safe_task_id}-",
        dir=workspace_root,
    ) as workspace:
        runtime_dirs = (
            ".runtime/home",
            ".runtime/tmp",
            ".runtime/xdg-cache",
            ".runtime/xdg-config",
            ".runtime/xdg-data",
        )
        for relative in runtime_dirs:
            _safe_workspace_path(workspace, relative).mkdir(parents=True, exist_ok=True)

        # Session 只驻留在宿主转发器内存中。工作区里的固定占位 cookie 仅用于
        # 通过 numoj-user CLI 的本地“已登录”检查，没有任何站点权限。
        from oj_modules.tasks.agent.identity_relay import run_numoj_identity_relay
        from oj_modules.tasks.agent.skill_runtime import materialize_skill

        cookie_name = str(session_cookie_name or "").strip() or "session"
        # late-ack 重投时必须先清理由同一 task_id 留下的旧容器，再开放身份
        # 转发端口，避免旧 Agent 与本次代理生命周期发生重叠。
        _remove_agent_container(container_name)
        with run_numoj_identity_relay(
            task_kind,
            int(problem_id),
            AGENT_CONTAINER_SITE_URL,
            cookie_name,
            str(session_cookie or ""),
        ) as identity_relay:
            identity_config = {
                "base_url": identity_relay.base_url,
                "username": str(requested_by or ""),
                "cookies": {"session": "relay-placeholder"},
                "agent_task": {
                    "task_id": str(task_id or ""),
                    "task_kind": task_kind,
                    "problem_id": int(problem_id),
                    "skill": skill_name,
                },
            }
            _write_workspace_file(
                workspace,
                ".numoj-agent/identity.json",
                json.dumps(identity_config, ensure_ascii=False, indent=2),
            )
            for relative_path, content in (workspace_files or {}).items():
                _write_workspace_file(workspace, relative_path, content)

            # 每次都从仓库规范源读取并投影，生成目录只属于本任务。
            materialize_skill(workspace, harness, skill_name)
            web_search_settings = get_web_search_settings(include_secret=True)
            env = _runtime_env(
                endpoint,
                harness,
                task_kind,
                web_search_settings=web_search_settings,
            )
            docker_args = _docker_args(
                container_name=container_name,
                workspace=workspace,
                env=env,
            )
            docker_process_env = _docker_process_env(env)
            stdout_trace_path = _safe_workspace_path(
                workspace,
                ".runtime/tmp/agent-harness.stdout",
            )
            trace_secrets = (
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

            try:
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
                    timeout=max(1, int(AGENT_JUDGE_DEFAULT_TIMEOUT)),
                    process_env=docker_process_env,
                    stdout_capture_path=stdout_trace_path,
                    on_tick=sync_trace,
                    tick_interval=AGENT_TRACE_SYNC_INTERVAL_SECONDS,
                )
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
            result = HarnessRunResult(
                returncode=result.returncode,
                timed_out=result.timed_out,
                stdout=result.stdout,
                stderr=result.stderr,
                artifacts=artifacts,
                created_submission_ids=identity_relay.created_submission_ids,
            )
            return _sanitize_output(
                result,
                secrets=trace_secrets,
            )


__all__ = ["HarnessRunResult", "run_agent_harness"]
