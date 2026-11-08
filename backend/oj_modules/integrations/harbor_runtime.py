"""反向评测使用 Harbor 官方 Trial 的宿主适配层。

长期端点凭据只交给既有宿主 relay；独立执行进程只收到临时 relay 凭据。
Harbor 的任务环境、参考解、作答和 verifier 均由官方实现管理。
"""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
import gzip
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import tempfile
import time
import tomllib

from backend.oj_modules import config
from backend.oj_modules.integrations.harbor_results import (
    RESULT_FILENAME, load_harbor_result, normalize_harbor_rewards,
)

HARBOR_VERSION = "0.25.0"
HARBOR_TASK_CONFIG_MAX_BYTES = 1024 * 1024
HARBOR_RAW_LOG_MAX_BYTES = 256 * 1024 * 1024
HARBOR_RAW_LOG_MAX_LINE_BYTES = 8 * 1024 * 1024
HARBOR_NATIVE_STORED_MAX_BYTES = 64 * 1024 * 1024
_WIRE_PREFIX = "NUMOJ_HARBOR "
_RUNTIME_FIELDS = frozenset({
    "task_path", "trial_dir", "verifier_timeout_seconds", "finalize_timeout_seconds",
})


def _positive_int(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"Harbor {name}必须为正整数")
    return value


def harbor_execution_timeout_seconds(agent_timeout_seconds, verifier_timeout_seconds, finalize_timeout_seconds=0):
    """覆盖官方环境构建、Agent安装、执行、验证和确认清理的总预算。"""
    # 预留官方环境构建、Agent安装，以及终止、宿主relay结算与容器清理的余量。
    # 第三个参数仅兼容已持久化的旧调用；Harbor 没有额外续聊收尾阶段。
    return int(agent_timeout_seconds) + int(verifier_timeout_seconds) + 2100


def normalize_harbor_runtime(value, *, require_task=True):
    """校验仅由服务端写入的执行描述，禁止以此访问任意宿主目录。"""
    if not isinstance(value, dict) or set(value) - _RUNTIME_FIELDS:
        raise ValueError("Harbor 执行配置字段无效")
    root = Path(config.REVERSE_JUDGE_WORKSPACE_ROOT).absolute().resolve()
    result = {}
    for name in ("task_path", "trial_dir"):
        path = Path(str(value.get(name) or ""))
        if not path.is_absolute():
            raise ValueError("Harbor 执行路径必须是绝对路径")
        resolved = path.resolve()
        if path != resolved or resolved == root or not resolved.is_relative_to(root):
            raise ValueError("Harbor 执行路径越界或包含符号链接")
        if name == "task_path" and require_task and not resolved.is_dir():
            raise ValueError("Harbor 任务目录不存在")
        if name == "trial_dir" and resolved.exists() and not resolved.is_dir():
            raise ValueError("Harbor 结果目录无效")
        result[name] = str(resolved)
    result["verifier_timeout_seconds"] = _positive_int(
        value.get("verifier_timeout_seconds", 300), "验证超时",
    )
    # 旧轮次可能携带该字段；只校验并保留以支持冻结配置重放，不参与执行。
    if "finalize_timeout_seconds" in value:
        result["finalize_timeout_seconds"] = _positive_int(value["finalize_timeout_seconds"], "旧收尾超时")
    return result


def _reject_host_expansion(value):
    if isinstance(value, dict):
        for item in value.values():
            _reject_host_expansion(item)
    elif isinstance(value, list):
        for item in value:
            _reject_host_expansion(item)
    elif isinstance(value, str) and "${" in value:
        raise ValueError("Harbor 任务配置不能引用宿主环境变量")


def validate_harbor_task(task_path):
    """在启动容器前校验平台支持的 Harbor 单任务边界及官方格式。"""
    path = Path(task_path)
    configuration = path / "task.toml"
    try:
        metadata = configuration.lstat()
    except FileNotFoundError:
        raise ValueError("请提交 Harbor 任务包：缺少 task.toml，旧反向评测格式已弃用")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Harbor task.toml 必须是普通文件，不能是符号链接")
    if metadata.st_size > HARBOR_TASK_CONFIG_MAX_BYTES:
        raise ValueError("Harbor task.toml 不能超过 1 MiB；题目数据请放在环境文件中")
    try:
        descriptor = os.open(configuration, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("Harbor task.toml 必须是普通文件")
            payload = source.read(HARBOR_TASK_CONFIG_MAX_BYTES + 1)
        if len(payload) > HARBOR_TASK_CONFIG_MAX_BYTES:
            raise ValueError("Harbor task.toml 不能超过 1 MiB")
        raw = tomllib.loads(payload.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("Harbor task.toml 无法读取或格式无效") from exc
    _reject_host_expansion(raw)
    if raw.get("steps"):
        raise ValueError("反向评测目前只接受 Harbor 单任务，不支持多步骤任务")
    if raw.get("environment", {}).get("os", "linux") != "linux":
        raise ValueError("反向评测目前只支持 Harbor Linux 环境")
    verifier = raw.get("verifier")
    if isinstance(verifier, dict) and {"environment_mode", "environment"} & verifier.keys():
        raise ValueError("验证器运行环境由平台统一配置")
    for directory in (path / "environment", path / "tests"):
        if any((directory / name).exists() for name in (
            "docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml",
        )):
            raise ValueError("反向评测目前只支持 Dockerfile 或预构建镜像，不支持 Compose 任务")
    for relative in ("instruction.md", "solution/solve.sh"):
        if not (path / relative).is_file():
            raise ValueError(f"Harbor 任务包缺少 {relative}")
    for item in raw.get("artifacts") or []:
        source = item.get("source") if isinstance(item, dict) else item
        source_path = str(source or "").rstrip("/")
        if not source_path or source_path == "/" or source_path.split("/")[1:2] in (
            ["proc"], ["sys"], ["dev"], ["run"], ["logs"], ["tests"], ["solution"],
        ):
            raise ValueError("Harbor artifacts 必须指向明确的任务交付物目录或文件")
    try:
        from harbor.models.task.task import Task
        from harbor.models.task.verifier_mode import (
            VerifierEnvironmentMode, resolve_task_verifier_mode,
        )
    except ImportError as exc:
        raise RuntimeError(f"Harbor 官方执行器未安装，请安装生产依赖 harbor=={HARBOR_VERSION}") from exc
    try:
        task = Task(path)
    except (OSError, ValueError, RuntimeError) as exc:
        raise ValueError(f"Harbor 任务格式校验失败：{exc}") from exc
    if resolve_task_verifier_mode(task.config) != VerifierEnvironmentMode.SHARED:
        raise ValueError("验证器运行环境由平台统一配置")
    return task


def _child_environment(trial_dir):
    """Harbor 任务的变量展开不能接触 Web/Celery 的数据库或站点凭据。"""
    allowed = {"PATH", "LANG", "LC_ALL", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY",
               "DOCKER_CERT_PATH", "DOCKER_CONFIG", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env.setdefault("DOCKER_CONFIG", str(Path.home() / ".docker"))
    home = Path(trial_dir) / ".runner-home"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    env.update(HOME=str(home), TMPDIR=str(home), PYTHONUNBUFFERED="1")
    return env


def _trial_name(trial_dir):
    path = Path(trial_dir) / ".run-name"
    try:
        with path.open("x", encoding="ascii") as stream:
            stream.write("numoj-harbor-" + secrets.token_hex(10))
    except FileExistsError:
        pass
    name = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"numoj-harbor-[a-f0-9]{20}", name):
        raise ValueError("Harbor 执行标识无效")
    return name


def _active_runner(trial_dir):
    path = Path(trial_dir) / ".runner-active"
    try:
        if path.is_symlink() or path.stat().st_size > 4096:
            raise ValueError("Harbor 执行进程状态无效")
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def _worker_alive(active):
    pid = active.get("worker_pid") if active else None
    if not isinstance(pid, int) or pid <= 1:
        return None
    result = subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                            capture_output=True, text=True, timeout=10)
    command = result.stdout
    return ("backend.oj_modules.integrations.harbor_worker" in command
            and "--run-id=" + str(active.get("run_name")) in command)


def _harbor_trial_running(harbor_runtime, *, ignore_preservation_failure=False):
    runtime = normalize_harbor_runtime(harbor_runtime, require_task=False)
    if not ignore_preservation_failure and (Path(runtime["trial_dir"]) / ".preservation-failed").exists():
        return None
    active = _active_runner(runtime["trial_dir"])
    if active is not None:
        alive = _worker_alive(active)
        if alive is True:
            return True
        if alive is None:
            # 准备阶段尚未发布子进程ID，不能把暂时没有容器当作已经停止。
            return None
    path = Path(runtime["trial_dir"]) / ".run-name"
    if not path.exists():
        return False
    name = _trial_name(runtime["trial_dir"])
    for suffix in ("__env", "__verifier__trial"):
        result = subprocess.run(["docker", "ps", "-aq", "--filter",
                                 "label=com.docker.compose.project=" + name + suffix],
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            return None
        if result.stdout.strip():
            return True
    return False


def harbor_trial_running(harbor_runtime):
    return _harbor_trial_running(harbor_runtime)


def harbor_trial_physically_stopped(harbor_runtime):
    """仅供停机恢复确认物理边界；保留失败标记本身不代表仍有进程。"""
    try:
        runtime = normalize_harbor_runtime(harbor_runtime, require_task=False)
        if _harbor_trial_running(runtime, ignore_preservation_failure=True) is not False:
            return False
        trial_dir = Path(runtime['trial_dir'])
        if not (trial_dir / '.run-name').is_file():
            return False
        run_name = _trial_name(trial_dir)
        config_path = str(trial_dir / '.harbor-cli.json')
        processes = subprocess.run(['ps', '-axo', 'pid=,command='],
                                   capture_output=True, text=True, timeout=10, check=True)
        for line in processes.stdout.splitlines():
            if config_path in line or '--run-id=' + run_name in line:
                # ps 不保证给带空格的 argv 加引号；有匹配即视为仍可能活动。
                return False
        return True
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def stop_harbor_trial(harbor_runtime):
    from backend.oj_modules.tasks.agent.harness_runtime import AgentHarnessCleanupError
    runtime = normalize_harbor_runtime(harbor_runtime, require_task=False)
    trial_dir = Path(runtime["trial_dir"])
    trial_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    (trial_dir / ".cancel-requested").touch(mode=0o600)
    deadline = time.monotonic() + 45
    worker_pid = None
    while True:
        active = _active_runner(trial_dir)
        if active is None:
            break
        alive = _worker_alive(active)
        if alive is False:
            break
        if alive is True:
            worker_pid = active["worker_pid"]
            try:
                os.kill(worker_pid, signal.SIGTERM)
            except ProcessLookupError:
                break
        if time.monotonic() > deadline:
            if worker_pid:
                try:
                    os.killpg(worker_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
            raise AgentHarnessCleanupError("暂时无法停止评测，请稍后重试。")
        time.sleep(0.2)
    if worker_pid:
        try:
            os.killpg(worker_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if (trial_dir / ".run-name").exists():
        _cleanup_containers(_trial_name(trial_dir))
    if harbor_trial_running(runtime) is not False:
        raise AgentHarnessCleanupError("评测尚未停止，请稍后重试。")


def _cleanup_containers(trial_name):
    """官方清理采取 best-effort；平台额外确认容器已删除才允许释放端点。"""
    from backend.oj_modules.tasks.agent.harness_runtime import AgentHarnessCleanupError
    for suffix in ("__env", "__verifier__trial"):
        project = trial_name + suffix
        try:
            result = subprocess.run(
                ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
                capture_output=True, text=True, timeout=20, check=True,
            )
            containers = result.stdout.split()
            if containers:
                # 官方 down 可能恰好先删除容器；以最后一次查询为准，
                # rm 的非零退出或超时本身不能证明仍有容器泄漏。
                try:
                    subprocess.run(["docker", "rm", "-f", *containers], capture_output=True,
                                   text=True, timeout=30, check=False)
                except (OSError, subprocess.SubprocessError):
                    pass
            result = subprocess.run(
                ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
                capture_output=True, text=True, timeout=20, check=True,
            )
            if result.stdout.strip():
                raise RuntimeError("仍有容器未删除")
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            raise AgentHarnessCleanupError("评测环境异常，请联系管理员处理。") from exc


def _execute(payload, *, cancel_check=None, event_callback=None, health_check=None):
    """JSON stdin 只传临时凭据，子进程协议与不受信任的容器 stdout 分离。"""
    trial_dir = Path(payload["trial_dir"])
    trial_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (trial_dir / ".cancel-requested").exists():
        return {"ok": False, "error": "Harbor 执行已取消", "result": None,
                "stdout": "", "stderr": "", "canceled": True}
    payload["trial_name"] = _trial_name(trial_dir)
    (trial_dir / RESULT_FILENAME).unlink(missing_ok=True)
    active_path = trial_dir / ".runner-active"
    active = {"host_pid": os.getpid(), "run_name": payload["trial_name"]}
    active_path.write_text(json.dumps(active), encoding="ascii")
    events = queue.Queue(maxsize=256)
    drain_stop = threading.Event()
    process = None
    try:
        _cleanup_containers(payload["trial_name"])
        previous = trial_dir / payload["trial_name"]
        if previous.is_symlink():
            raise ValueError("Harbor 旧执行目录不能是符号链接")
        if previous.exists():
            shutil.rmtree(previous)
        process = subprocess.Popen(
            [sys.executable, "-m", "backend.oj_modules.integrations.harbor_worker", "--run-id=" + payload["trial_name"]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
            env=_child_environment(trial_dir), start_new_session=True,
        )
        active["worker_pid"] = process.pid
        temporary = active_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(active), encoding="ascii")
        temporary.replace(active_path)
        if (trial_dir / ".cancel-requested").exists():
            process.terminate()
        else:
            process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        process.stdin.close()
    except BaseException:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        active_path.unlink(missing_ok=True)
        raise

    def drain():
        def enqueue(value):
            while not drain_stop.is_set():
                try:
                    events.put(value, timeout=0.2)
                    return
                except queue.Full:
                    pass
        while not drain_stop.is_set():
            line = process.stdout.readline(16 * 1024 * 1024 + 1)
            if not line:
                break
            if len(line) > 16 * 1024 * 1024:
                enqueue(_WIRE_PREFIX + json.dumps({"type": "fatal", "error": "Harbor 执行输出单行超过大小限制"}))
                break
            enqueue(line)
        enqueue(None)

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    tail = deque(maxlen=256)
    stopped = False
    stop_time = None
    deadline = time.monotonic() + harbor_execution_timeout_seconds(
        payload["agent_timeout_seconds"], payload["verifier_timeout_seconds"],
    )
    try:
        while True:
            try:
                line = events.get(timeout=0.25)
            except queue.Empty:
                line = ""
            if line is None:
                break
            if line.startswith(_WIRE_PREFIX):
                try:
                    event = json.loads(line[len(_WIRE_PREFIX):])
                except ValueError:
                    event = {}
                if event.get("type") == "fatal":
                    raise RuntimeError(event.get("error") or "Harbor 执行输出无效")
                if callable(event_callback):
                    event_callback(event)
            elif line:
                tail.append(line[-8192:])
            if callable(health_check):
                health_check()
            if not stopped and ((callable(cancel_check) and cancel_check()) or time.monotonic() > deadline):
                stopped = True
                stop_time = time.monotonic()
                os.kill(process.pid, signal.SIGTERM)
            if stopped and process.poll() is None and time.monotonic() - stop_time > 45:
                os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            os.kill(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
        drain_stop.set()
        thread.join(timeout=2)
        try:
            _cleanup_containers(payload["trial_name"])
        finally:
            active_path.unlink(missing_ok=True)
    if stopped or (trial_dir / ".cancel-requested").exists():
        return {"ok": False, "error": "Harbor 执行已取消或超过总超时", "result": None,
                "stdout": "", "stderr": "", "canceled": True}
    if process.returncode:
        raise RuntimeError("Harbor 执行进程异常退出：" + "".join(tail)[-2000:])
    try:
        return load_harbor_result(trial_dir)
    except (OSError, ValueError) as exc:
        raise RuntimeError("Harbor 执行器未生成有效结果：" + "".join(tail)[-2000:]) from exc


def run_harbor_oracle(task_path, trial_dir, timeout_seconds=300, *, build_event_callback=None):
    validate_harbor_task(task_path)
    timeout = _positive_int(timeout_seconds, "自检超时")
    def event_callback(event):
        if event.get("type") == "build" and callable(build_event_callback):
            build_event_callback(event)
    return _execute({"task_path": str(Path(task_path).resolve()), "trial_dir": str(Path(trial_dir).resolve()),
                     "agent_timeout_seconds": timeout, "verifier_timeout_seconds": timeout,
                     "agent": "oracle"}, event_callback=event_callback)


def _gzip_native_log(path, remaining_bytes, redact):
    """有界逐行脱敏压缩原始 stdout，不把流式快照一次读入内存。"""
    class LimitedOutput:
        def __init__(self, output):
            self.output = output
        def write(self, data):
            if self.output.tell() + len(data) > remaining_bytes:
                raise ValueError('Harbor 压缩日志与规范会话超过 64 MiB 保留限制')
            return self.output.write(data)
        def flush(self):
            self.output.flush()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source, tempfile.TemporaryFile(mode='w+b') as output:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError('Harbor 原始日志必须是普通文件')
        if metadata.st_size > HARBOR_RAW_LOG_MAX_BYTES:
            raise ValueError('Harbor 原始日志展开大小超过 256 MiB 限制')
        expanded = 0
        with gzip.GzipFile(filename='', mode='wb', fileobj=LimitedOutput(output), mtime=0) as compressed:
            while line := source.readline(HARBOR_RAW_LOG_MAX_LINE_BYTES + 1):
                expanded += len(line)
                if expanded > HARBOR_RAW_LOG_MAX_BYTES:
                    raise ValueError('Harbor 原始日志展开大小超过 256 MiB 限制')
                if len(line) > HARBOR_RAW_LOG_MAX_LINE_BYTES:
                    raise ValueError('Harbor 原始日志单行超过 8 MiB 限制')
                # 完整有界行覆盖底层 read 块边界，避免把跨块密钥漏存。
                compressed.write(redact(line))
        output.seek(0)
        return output.read(remaining_bytes + 1)


def _preserve_native_logs(session_id, runtime, *, secrets=()):
    from backend.oj_modules.agents.workspace import write_agent_workspace_file
    from backend.oj_modules.integrations.harbor_trace import redact_harbor_value
    def render(value, ending=''):
        return json.dumps(redact_harbor_value(value, secrets), ensure_ascii=False) + ending

    def redact(data):
        try:
            decoded = data.decode('utf-8')
        except UnicodeError:
            for secret in secrets:
                if secret:
                    data = data.replace(str(secret).encode(), b'[REDACTED]')
            return data
        try:
            value = json.loads(decoded)
        except ValueError:
            lines = []
            for line in decoded.splitlines(keepends=True):
                try:
                    value = json.loads(line)
                except ValueError:
                    lines.append(redact_harbor_value(line, secrets))
                else:
                    ending = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
                    lines.append(render(value, ending))
            return ''.join(lines).encode('utf-8')
        else:
            ending = '\r\n' if decoded.endswith('\r\n') else '\n' if decoded.endswith('\n') else ''
            return render(value, ending).encode('utf-8')
    trial_dir = Path(runtime["trial_dir"])
    if not (trial_dir / ".run-name").exists():
        return
    source = trial_dir / _trial_name(trial_dir) / "agent"
    if not source.is_dir() or source.is_symlink():
        return
    if (source / 'pi.txt').exists() and (source / 'pi.txt.gz').exists():
        raise ValueError('Harbor 原始日志压缩目标与已有文件冲突')
    total = count = 0
    for path in source.rglob("*"):
        count += 1
        if count > 4096:
            raise ValueError("Harbor 原生会话超过保留文件数量限制")
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            raise ValueError("Harbor 原生会话包含不安全文件")
        if not stat.S_ISREG(metadata.st_mode):
            continue
        relative = path.relative_to(source).as_posix()
        if relative == 'pi.txt':
            data = _gzip_native_log(path, HARBOR_NATIVE_STORED_MAX_BYTES - total, redact)
            relative += '.gz'
        else:
            if metadata.st_size > 16 * 1024 * 1024:
                raise ValueError("Harbor 规范会话单文件超过 16 MiB 保留限制")
            data = redact(path.read_bytes())
        total += len(data)
        if total > HARBOR_NATIVE_STORED_MAX_BYTES:
            raise ValueError('Harbor 压缩日志与规范会话超过 64 MiB 保留限制')
        write_agent_workspace_file(session_id, ".runtime/harbor/agent/" + relative, data)
    for filename in ("result.json", "config.json"):
        path = source.parent / filename
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024 * 1024:
            data = redact(path.read_bytes())
            total += len(data)
            if total > HARBOR_NATIVE_STORED_MAX_BYTES:
                raise ValueError('Harbor 压缩日志与规范会话超过 64 MiB 保留限制')
            write_agent_workspace_file(session_id, ".runtime/harbor/" + filename, data)


@contextmanager
def _secret_relay(endpoint, **kwargs):
    from backend.oj_modules.tasks.agent.harness_runtime import AgentHarnessCleanupError, AgentUsageHardStopError
    from backend.oj_modules.tasks.agent.secret_relay import (
        AgentSecretRelayCleanupError, AgentSecretRelayUsageHardStopError, run_agent_secret_relays,
    )
    try:
        with run_agent_secret_relays(endpoint, **kwargs) as relay:
            yield relay
    except AgentSecretRelayCleanupError as exc:
        raise AgentHarnessCleanupError(str(exc)) from exc
    except AgentSecretRelayUsageHardStopError as exc:
        raise AgentUsageHardStopError(str(exc)) from exc


def _import_official_trace(runtime, result, *, secrets, emit):
    from backend.oj_modules.integrations.harbor_trace import HarborTraceImporter

    expected = Path(runtime['trial_dir']) / _trial_name(runtime['trial_dir'])
    official = result.get('official_trial_dir') or (str(expected) if not result.get('ok') else '')
    if Path(official) != expected or expected != expected.resolve():
        raise ValueError('Harbor 官方会话目录越界或无效')
    directory = expected / 'agent'
    if (result.get('ok') or (directory / 'trajectory.json').exists()
            or any((directory / 'pi/sessions').glob('*.jsonl'))):
        # 最终完整数据直接送持久化回调，不经过预览 stdout 协议或单行截断。
        HarborTraceImporter(directory, secrets=secrets, emit=emit).sync(final=True)


def import_harbor_artifacts(session_id, runtime, result, task=None):
    """仅导入官方已收集的产物；不执行任务、模型或验证器。"""
    from backend.oj_modules.agents.workspace import inject_agent_workspace_files

    runtime = normalize_harbor_runtime(runtime)
    task = task if task is not None else validate_harbor_task(runtime['task_path'])
    if not result.get('ok'):
        return
    source = Path(result['artifacts_dir'])
    trial_dir = Path(runtime['trial_dir'])
    optional_missing = not task.config.artifacts and not source.exists()
    if (source != source.resolve() or not source.is_relative_to(trial_dir)
            or not source.is_dir() and not optional_missing):
        raise ValueError('Harbor 交付物目录越界或无效')
    files = {}
    total = 0
    for index, path in enumerate(source.rglob('*'), 1):
        if index > config.REVERSE_ANSWER_MAX_FILES * 4:
            raise ValueError('Harbor 交付物目录数量超过限制')
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError('Harbor 交付物不能包含符号链接')
        if stat.S_ISREG(metadata.st_mode):
            if not task.config.artifacts and path == source / 'manifest.json':
                continue
            total += metadata.st_size
            if (len(files) >= config.REVERSE_ANSWER_MAX_FILES
                    or metadata.st_size > config.REVERSE_ANSWER_MAX_FILE_BYTES
                    or total > config.REVERSE_ANSWER_MAX_TOTAL_BYTES):
                raise ValueError('Harbor 交付物数量或大小超过限制')
            files['harbor-artifacts/' + path.relative_to(source).as_posix()] = path
        elif not stat.S_ISDIR(metadata.st_mode):
            raise ValueError('Harbor 交付物包含特殊文件')
    if files:
        inject_agent_workspace_files(str(session_id), files)


def finalize_harbor_trial_outputs(*, runtime, session_id, result, secrets=(), emit):
    """停机恢复使用已有官方证据；不重跑 CLI、不连接端点、不改变原结果。"""
    runtime = normalize_harbor_runtime(runtime)
    if not result.get('ok') or not harbor_trial_physically_stopped(runtime):
        raise ValueError('Harbor 官方结果无效或执行环境尚未确认停止，拒绝恢复')
    _import_official_trace(runtime, result, secrets=secrets, emit=emit)
    _preserve_native_logs(str(session_id), runtime, secrets=secrets)
    import_harbor_artifacts(str(session_id), runtime, result)


def run_harbor_agent(*, harbor_runtime, task_id, requested_by, harness, endpoint,
                     session_id=None, prompt="", timeout_seconds=None,
                     trace_callback=None, trace_records_callback=None, cancel_check=None,
                     usage_callback=None, native_session_callback=None, reasoning_effort="default",
                     **_runner_kwargs):
    from backend.oj_modules.tasks.agent.harness_runtime import HarnessRunResult
    from backend.oj_modules.agents.workspace import merge_agent_temporary_redaction_candidates

    runtime = normalize_harbor_runtime(harbor_runtime)
    task = validate_harbor_task(runtime["task_path"])
    agent = {"claude_code": "claude-code", "codex": "codex", "opencode": "opencode", "pi": "pi"}.get(harness)
    if not agent:
        raise ValueError("Harbor 不支持所选 Agent")
    stop_event = threading.Event()
    pending = []
    native_id = ''
    final_imported = False
    def on_event(event):
        nonlocal native_id, final_imported
        if event.get("type") == "trace":
            records = event.get('records') or []
            if event.get('replace_snapshot') or any(record.get('replace_snapshot') for record in records):
                pending[:] = records
            else:
                pending.extend(records)
        elif event.get("type") == "native":
            native_id = str(event.get('session_id') or '')
            if callable(native_session_callback):
                native_session_callback(native_id)
        final = bool(event.get('final'))
        if (pending or final) and callable(trace_records_callback):
            try:
                trace_records_callback(tuple(pending), final=final)
            except Exception:
                if final:
                    raise
            else:
                pending.clear()
                final_imported = final_imported or final
        if callable(trace_callback):
            try:
                trace_callback()
            except Exception:
                pass

    with _secret_relay(
        endpoint, endpoint_stop_event=stop_event, require_endpoint_usage_ack=callable(usage_callback),
        endpoint_usage_callback=usage_callback,
    ) as relay:
        # 复用通用 Harness 的宿主私有脱敏历史；长期模型密钥不得持久化。
        temporary_secrets = merge_agent_temporary_redaction_candidates(
            str(session_id or task_id), relay.temporary_secrets,
        )
        payload = dict(runtime, agent=agent, agent_timeout_seconds=_positive_int(timeout_seconds or 1800, "作答超时"),
                       endpoint={"base_url": relay.endpoint_base_url, "api_key": relay.endpoint_api_key,
                                 "model": endpoint["model"], "protocol": endpoint.get("protocol") or "openai",
                                 "context_window_tokens": endpoint.get("context_window_tokens"),
                                 "max_output_tokens": endpoint.get("max_output_tokens")},
                       reasoning_effort=reasoning_effort)
        trace_error = None
        try:
            result = _execute(payload, cancel_check=cancel_check, event_callback=on_event,
                              health_check=relay.raise_if_usage_failed)
            relay.wait_for_endpoint_usage()
            relay.raise_if_usage_failed()
            try:
                _import_official_trace(runtime, result,
                    secrets=(*temporary_secrets, str(endpoint.get('api_key') or '')), emit=on_event)
            except Exception as exc:
                trace_error = exc
        finally:
            if harbor_trial_running(runtime) is False:
                try:
                    _preserve_native_logs(str(session_id or task_id), runtime,
                        secrets=(*temporary_secrets, str(endpoint.get('api_key') or '')))
                except Exception as exc:
                    from backend.oj_modules.tasks.agent.harness_runtime import AgentHarnessCleanupError
                    (Path(runtime["trial_dir"]) / ".preservation-failed").touch(mode=0o600)
                    raise AgentHarnessCleanupError("解答记录保存失败，请联系管理员处理。") from exc
            if trace_error is not None:
                from backend.oj_modules.tasks.agent.harness_runtime import AgentHarnessCleanupError
                (Path(runtime['trial_dir']) / '.preservation-failed').touch(mode=0o600)
                raise AgentHarnessCleanupError('解答过程暂时无法查看，请联系管理员处理。') from trace_error
    if callable(trace_records_callback) and not final_imported:
        trace_records_callback(tuple(pending), final=True)
    import_harbor_artifacts(str(session_id or task_id), runtime, result, task=task)
    return HarnessRunResult(returncode=0 if result.get("ok") else -15 if result.get("canceled") else 1,
                            timed_out=False, stdout=str(result.get("stdout") or ""),
                            stderr=str(result.get("error") or result.get("stderr") or ""),
                            native_session_id=native_id or str(result.get("native_session_id") or ""))
