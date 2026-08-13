#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Docker 容器沙箱执行原语。

提供两个核心接口：
- run_in_container(): 只读 sandbox 中运行可信维护命令。
- run_case_in_container(): 以只读源码 + 有界 tmpfs 执行不可信命令，并只导出白名单产物。

所有用户代码在完全隔离的容器中执行：断网、只读根文件系统、非 root 用户、
内存/CPU/进程数限制。
"""

import base64
import json
import os
import re
import selectors
import stat
import subprocess
import time
import uuid

_CONFIG = None
_TIME_MARKER_PREFIX = "__NUMOJ_TIME_NS__="
_TIME_MARKER_RE = re.compile(r"(?:^|\n)" + re.escape(_TIME_MARKER_PREFIX) + r"(\d+)\s*(?=\n|$)")
_TIME_WRAPPER_SCRIPT = (
    'start=$(date +%s%N); '
    '"$@"; rc=$?; '
    'end=$(date +%s%N); '
    'case "$start$end" in *N*) elapsed=0 ;; *) elapsed=$((end-start)) ;; esac; '
    f'printf "\\n{_TIME_MARKER_PREFIX}%s\\n" "$elapsed" >&2; '
    'exit "$rc"'
)
_CASE_PROTOCOL_PREFIX = "__NUMOJ_CASE_RESULT_V1__"
_CASE_RUNNER_HOST_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "case_runner.py",
)
_CASE_RUNNER_CONTAINER_PATH = "/opt/library/.numoj_case_runner.py"
_ALLOWED_IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".gif",
    ".webp",
}


def _get_config():
    global _CONFIG
    if _CONFIG is None:
        try:
            from oj_modules import config as _cfg
            _CONFIG = _cfg
        except ImportError:
            _CONFIG = object()
    return _CONFIG


def _config_value(name, default):
    env_value = os.environ.get(name)
    if env_value is not None and str(env_value).strip() != "":
        return env_value
    return getattr(_get_config(), name, default)


def _image():
    return _config_value("JUDGER_DOCKER_IMAGE", "numericaloj-judger:latest")


def _mem_limit():
    return _config_value("JUDGER_DOCKER_MEM_LIMIT", "1g")


def _cpu_limit():
    # 默认 2 核（而非 1）：Octave 的 gnuplot 出图会拉起独立 gnuplot 子进程，单核下
    # octave↔gnuplot 抢同一核、冷启动严重 thrash（实测 diag79 单核冷跑 15s、热跑
    # ~1.5s 高方差；给到 2 核后稳定 ~1.53s）。带绘图 interactor 的题在 1 核下必 TLE。
    return _config_value("JUDGER_DOCKER_CPU_LIMIT", "2")


def _pids_limit():
    return _config_value("JUDGER_DOCKER_PIDS_LIMIT", "128")


def _network():
    return _config_value("JUDGER_DOCKER_NETWORK", "none")


def _runner_uid():
    try:
        value = int(_config_value("JUDGER_DOCKER_RUNNER_UID", 65532))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("JUDGER_DOCKER_RUNNER_UID 必须是整数") from exc
    if value <= 0 or value > 2_147_483_647:
        raise RuntimeError("JUDGER_DOCKER_RUNNER_UID 超出安全范围")
    if value == os.geteuid():
        raise RuntimeError("判题容器 UID 与宿主服务 UID 相同，拒绝启动")
    return value


def _runner_gid():
    try:
        value = int(_config_value("JUDGER_DOCKER_RUNNER_GID", 65532))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("JUDGER_DOCKER_RUNNER_GID 必须是整数") from exc
    if value <= 0 or value > 2_147_483_647:
        raise RuntimeError("JUDGER_DOCKER_RUNNER_GID 超出安全范围")
    return value


def _runner_identity():
    return f"{_runner_uid()}:{_runner_gid()}"


def _positive_config_int(name, default, *, maximum=2_147_483_647):
    try:
        value = int(_config_value(name, default))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} 必须是整数") from exc
    if value <= 0 or value > int(maximum):
        raise RuntimeError(f"{name} 超出安全范围")
    return value


def _case_tmpfs_bytes():
    return _positive_config_int(
        "JUDGER_DOCKER_CASE_TMPFS_BYTES",
        128 * 1024 * 1024,
    )


def _export_tmpfs_bytes():
    return _positive_config_int(
        "JUDGER_DOCKER_EXPORT_TMPFS_BYTES",
        96 * 1024 * 1024,
    )


def _case_input_max_bytes():
    return _positive_config_int(
        "JUDGER_CASE_INPUT_MAX_BYTES",
        64 * 1024 * 1024,
    )


def _stdout_max_bytes():
    return _positive_config_int(
        "JUDGER_STDOUT_MAX_BYTES",
        1024 * 1024,
    )


def _stderr_max_bytes():
    return _positive_config_int(
        "JUDGER_STDERR_MAX_BYTES",
        1024 * 1024,
    )


def _thread_env_flags():
    """限制 BLAS/OpenMP/MKL 线程数与容器 CPU 配额一致。

    容器是 `--cpus N`（默认 1），而 OpenBLAS/OpenMP/MKL 默认按**宿主机物理核数**
    开线程（本机 40 核）。线程数远超 CPU 配额会造成严重的线程超额争抢：实测
    `eig(800)` 在 `--cpus 1` 下从 0.07s 退化到 124s，导致一切线性代数密集的
    Octave/C/C++ 题必 TLE。这里把线程数钉到 CPU 配额，单线程 BLAS 反而最快。
    """
    try:
        n = max(1, int(float(_cpu_limit())))
    except (TypeError, ValueError):
        n = 1
    val = str(n)
    flags = []
    for var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
                "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
        flags.extend(["-e", f"{var}={val}"])
    # Octave 的 gnuplot toolkit：默认交互终端在 headless 容器里建立 octave↔gnuplot
    # 管道时极慢且高方差（实测 make_plot 6~19s，把带绘图 interactor 的题全拖 TLE）。
    # 把默认终端设为廉价的 'dumb'（ASCII），交互式 drawnow 几乎零成本；而 print('-dpng')
    # 仍会单独切到 png 终端真正出图，output.png 不受影响（实测 19s → ~1.7s）。
    flags.extend(["-e", "GNUTERM=dumb"])
    # 根文件系统只读时 fontconfig 不能写 ~/.cache 或 /var/cache，会在每次 gnuplot
    # 出图时反复扫描字体并刷出 "No writable cache directories"。镜像内会预生成
    # /var/cache/fontconfig；这里给运行期新缓存一个 /tmp 兜底，避免画图题回退到慢路径。
    flags.extend(["-e", "XDG_CACHE_HOME=/tmp/.cache"])
    return flags


class _RunResult:
    __slots__ = (
        "returncode",
        "stdout",
        "stderr",
        "elapsed_ns",
        "artifacts",
        "stdout_truncated",
        "stderr_truncated",
        "oom_killed",
        "artifact_statuses",
    )

    def __init__(
        self,
        returncode,
        stdout,
        stderr,
        elapsed_ns=None,
        *,
        artifacts=None,
        stdout_truncated=False,
        stderr_truncated=False,
        oom_killed=False,
        artifact_statuses=None,
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.elapsed_ns = elapsed_ns
        self.artifacts = dict(artifacts or {})
        self.stdout_truncated = bool(stdout_truncated)
        self.stderr_truncated = bool(stderr_truncated)
        self.oom_killed = bool(oom_killed)
        self.artifact_statuses = dict(artifact_statuses or {})


class ContainerCleanupError(RuntimeError):
    """容器是否已停止无法确认；调用方必须终止当前判题流程。"""


def _wrap_timed_cmd(cmd):
    return ["/bin/sh", "-c", _TIME_WRAPPER_SCRIPT, "numoj-timer"] + list(cmd)


def _strip_timing_marker(stderr):
    text = stderr or ""
    matches = list(_TIME_MARKER_RE.finditer(text))
    if not matches:
        return text, None
    elapsed_ns = int(matches[-1].group(1))
    cleaned = _TIME_MARKER_RE.sub("", text)
    return cleaned, elapsed_ns


class _BoundedOutput:
    def __init__(self, limit):
        self.limit = max(0, int(limit))
        self.data = bytearray()
        self.truncated = False

    def append(self, chunk):
        if not chunk:
            return
        remaining = self.limit - len(self.data)
        if remaining > 0:
            self.data.extend(chunk[:remaining])
        if len(chunk) > max(0, remaining):
            self.truncated = True


def _selector_close_pipe(selector, pipe):
    try:
        selector.unregister(pipe)
    except Exception:
        pass
    try:
        pipe.close()
    except Exception:
        pass


def _communicate_bounded(
    proc,
    *,
    input_bytes=b"",
    timeout_sec=30,
    stdout_limit=None,
    stderr_limit=None,
):
    """持续 drain 子进程管道，但宿主只保留固定上限，避免用户输出撑爆 worker。"""
    stdout_buffer = _BoundedOutput(
        _stdout_max_bytes() if stdout_limit is None else stdout_limit
    )
    stderr_buffer = _BoundedOutput(
        _stderr_max_bytes() if stderr_limit is None else stderr_limit
    )
    selector = selectors.DefaultSelector()
    os.set_blocking(proc.stdout.fileno(), False)
    os.set_blocking(proc.stderr.fileno(), False)
    selector.register(
        proc.stdout,
        selectors.EVENT_READ,
        ("read", stdout_buffer),
    )
    selector.register(
        proc.stderr,
        selectors.EVENT_READ,
        ("read", stderr_buffer),
    )
    payload = bytes(input_bytes or b"")
    input_offset = 0
    if payload:
        os.set_blocking(proc.stdin.fileno(), False)
        selector.register(proc.stdin, selectors.EVENT_WRITE, ("write", None))
    else:
        proc.stdin.close()
    deadline = time.monotonic() + max(0.001, float(timeout_sec))
    try:
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise subprocess.TimeoutExpired(
                    getattr(proc, "args", "docker"),
                    timeout_sec,
                )
            events = selector.select(timeout=min(0.05, remaining_time))
            for key, _mask in events:
                operation, target = key.data
                pipe = key.fileobj
                if operation == "write":
                    try:
                        written = os.write(
                            pipe.fileno(),
                            payload[input_offset : input_offset + 65536],
                        )
                        input_offset += written
                    except BlockingIOError:
                        continue
                    except (BrokenPipeError, OSError):
                        input_offset = len(payload)
                    if input_offset >= len(payload):
                        _selector_close_pipe(selector, pipe)
                    continue
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if chunk:
                    target.append(chunk)
                else:
                    _selector_close_pipe(selector, pipe)

            if proc.poll() is not None:
                if proc.stdin is not None and not proc.stdin.closed:
                    _selector_close_pipe(selector, proc.stdin)
                # stdout/stderr 仍需 drain 到 EOF；用户输出超过上限后只丢弃，不积累。

        proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        return (
            bytes(stdout_buffer.data),
            bytes(stderr_buffer.data),
            stdout_buffer.truncated,
            stderr_buffer.truncated,
        )
    finally:
        selector.close()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None and not pipe.closed:
                try:
                    pipe.close()
                except Exception:
                    pass


def _decode_output(data):
    return bytes(data or b"").decode("utf-8", errors="replace")


def _safe_artifact_name(name):
    value = str(name or "")
    if (
        not value
        or value in {".", ".."}
        or "\x00" in value
        or os.path.basename(value) != value
        or len(value.encode("utf-8")) > 255
    ):
        raise ValueError("容器产物名称不是安全的单级文件名")
    return value


def _safe_image_name(name):
    if not name:
        return ""
    value = _safe_artifact_name(name)
    if os.path.splitext(value)[1].lower() not in _ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("容器图片扩展名不受支持")
    return value


def _inspect_container_absence(container_name):
    """返回 True/False 表示已确认不存在/仍存在，None 表示 daemon 状态未知。"""
    try:
        result = subprocess.run(
            [
                "docker",
                "container",
                "inspect",
                str(container_name),
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception:
        return None
    if result.returncode == 0:
        return False
    stderr = str(result.stderr or "").lower()
    if "no such object:" in stderr or "no such container:" in stderr:
        return True
    return None


def _force_remove_container(container_name):
    """强制移除容器，并只在成功或明确不存在时返回。"""
    try:
        result = subprocess.run(
            ["docker", "rm", "-f", str(container_name)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception:
        result = None
    if result is not None and result.returncode == 0:
        return
    absence = _inspect_container_absence(container_name)
    if absence is True:
        return
    if absence is False:
        raise ContainerCleanupError("判题容器强制清理失败，容器仍在运行")
    raise ContainerCleanupError("无法确认判题容器已经停止")


def _read_container_oom_kill_count(container_name):
    """读取单个 case 容器 cgroup 的可信 ``oom_kill`` 计数。

    正常情况下容器内 wrapper 会比较执行前后的 ``memory.events``。如果 OOM
    把 wrapper 本身一起杀掉，协议帧会缺失；此时宿主在销毁这个全新、独占 case
    容器前读取同一 cgroup 的累计计数，仍可把真实内存越限与普通 SIGKILL 区分开。
    """
    for path in (
        "/sys/fs/cgroup/memory.events.local",
        "/sys/fs/cgroup/memory.events",
    ):
        try:
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    "--user",
                    "0:0",
                    str(container_name),
                    "cat",
                    path,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            continue
        if result.returncode != 0:
            continue
        counters = {}
        try:
            for line in str(result.stdout or "").splitlines():
                key, raw_value = line.split()
                value = int(raw_value)
                if value < 0:
                    raise ValueError
                counters[key] = value
        except (TypeError, ValueError):
            continue
        if "oom_kill" in counters:
            return counters["oom_kill"]
    return None


def run_in_container(
    cmd,
    *,
    run_dir,
    input_text="",
    timeout_sec=30,
    extra_ro_mounts=None,
    measure_time=False,
    workdir="/sandbox",
    docker_image=None,
):
    """在一次性 Docker 容器的只读 sandbox 中执行可信命令。

    Args:
        cmd: 容器内执行的命令列表，如 ["python3", "-I", "-u", "main.py"]
        run_dir: 宿主机运行目录，挂载为容器内 /sandbox
        input_text: 传入容器 stdin 的文本
        timeout_sec: Python 侧超时（秒）
        extra_ro_mounts: 额外只读挂载列表，每项为 (host_path, container_path)
        measure_time: True 时在容器内部测量命令 wall time，不包含 docker run 启动耗时
        workdir: 本次短生命周期容器的工作目录
        docker_image: 可选的独立运行镜像；为空时使用普通判题镜像

    Returns:
        _RunResult(returncode, stdout, stderr)
    """
    container_name = f"numoj-run-{os.getpid()}-{uuid.uuid4().hex}"
    docker_cmd = [
        "docker", "run", "--rm", "-i",
        "--name", container_name,
        "--network", _network(),
        "--security-opt", "no-new-privileges",
        "--memory", _mem_limit(),
        "--cpus", _cpu_limit(),
        "--pids-limit", _pids_limit(),
        "--read-only",
        "--tmpfs", "/tmp:size=64m",
        *_thread_env_flags(),
        "-e", "HOME=/home/runner",
        "-v",
        f"{os.path.abspath(run_dir)}:/sandbox:ro",
        "--user", _runner_identity(),
        "-w", str(workdir or "/sandbox"),
    ]

    if extra_ro_mounts:
        for host_path, container_path in extra_ro_mounts:
            if os.path.exists(host_path):
                docker_cmd.extend(["-v", f"{os.path.abspath(host_path)}:{container_path}:ro"])

    docker_cmd.append(str(docker_image or _image()))
    docker_cmd.extend(_wrap_timed_cmd(cmd) if measure_time else cmd)

    proc = None
    try:
        proc = subprocess.Popen(
            docker_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes, stdout_truncated, stderr_truncated = (
            _communicate_bounded(
                proc,
                input_bytes=str(input_text or "").encode("utf-8"),
                timeout_sec=timeout_sec,
            )
        )
        stdout = _decode_output(stdout_bytes)
        stderr = _decode_output(stderr_bytes)
        elapsed_ns = None
        if measure_time:
            stderr, elapsed_ns = _strip_timing_marker(stderr or "")
        if int(proc.returncode) < 0 or int(proc.returncode) in {125, 126, 127}:
            _force_remove_container(container_name)
        return _RunResult(
            proc.returncode,
            stdout or "",
            stderr or "",
            elapsed_ns,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        _force_remove_container(container_name)
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        stdout_bytes, stderr_bytes = b"", b""
        stdout_truncated = False
        stderr_truncated = False
        stdout = _decode_output(stdout_bytes)
        stderr = _decode_output(stderr_bytes)
        elapsed_ns = None
        if measure_time:
            stderr, elapsed_ns = _strip_timing_marker(stderr or "")
        return _RunResult(
            124,
            stdout or "",
            stderr or "",
            elapsed_ns,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )
    except ContainerCleanupError:
        raise
    except Exception as e:
        if proc is not None:
            _force_remove_container(container_name)
        return _RunResult(-1, "", str(e))


def _validate_case_runner_source():
    try:
        info = os.lstat(_CASE_RUNNER_HOST_PATH)
    except OSError as exc:
        raise RuntimeError("判题容器执行器文件不存在") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or int(info.st_uid) not in {0, int(os.geteuid())}
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise RuntimeError("判题容器执行器必须是可信属主且不可被其他用户修改的普通文件")
    return os.path.abspath(_CASE_RUNNER_HOST_PATH)


def _case_container_start_command(
    container_name,
    run_dir,
    *,
    guard_timeout_sec=30,
):
    runner_source = _validate_case_runner_source()
    idle_timeout = max(30, int(float(guard_timeout_sec)) + 60)
    return [
        "docker",
        "run",
        "-d",
        "--rm",
        "--init",
        "--name",
        str(container_name),
        "--network",
        _network(),
        "--security-opt",
        "no-new-privileges",
        "--memory",
        _mem_limit(),
        "--cpus",
        _cpu_limit(),
        "--pids-limit",
        _pids_limit(),
        "--read-only",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "SETUID",
        "--cap-add",
        "SETGID",
        "--cap-add",
        "KILL",
        "--cap-add",
        "DAC_READ_SEARCH",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--tmpfs",
        (
            "/case:rw,nosuid,nodev,noexec,"
            f"size={_case_tmpfs_bytes()},mode=1777"
        ),
        "--tmpfs",
        (
            "/export:rw,nosuid,nodev,noexec,"
            f"size={_export_tmpfs_bytes()},mode=0700"
        ),
        *_thread_env_flags(),
        "-e",
        "HOME=/home/runner",
        "-v",
        f"{os.path.abspath(run_dir)}:/sandbox:ro",
        "-v",
        f"{runner_source}:{_CASE_RUNNER_CONTAINER_PATH}:ro",
        "--user",
        "0:0",
        "-w",
        "/case",
        _image(),
        "timeout",
        "-k",
        "1s",
        f"{idle_timeout}s",
        "sleep",
        "infinity",
    ]


def _parse_case_protocol(
    stdout_bytes,
    *,
    stdout_limit,
    stderr_limit,
    allowed_artifacts,
):
    try:
        line = bytes(stdout_bytes or b"").decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError("判题容器返回了无效协议") from exc
    if not line.startswith(_CASE_PROTOCOL_PREFIX):
        raise RuntimeError("判题容器未返回可信执行协议")
    encoded = line[len(_CASE_PROTOCOL_PREFIX) :]
    if not encoded or "\n" in encoded or "\r" in encoded:
        raise RuntimeError("判题容器协议帧格式错误")
    try:
        raw_payload = base64.b64decode(encoded, validate=True)
        payload = json.loads(raw_payload.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("判题容器协议无法解析") from exc
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise RuntimeError("判题容器协议版本不受支持")

    def decode_field(field, limit):
        value = payload.get(field)
        if not isinstance(value, str):
            raise RuntimeError("判题容器协议缺少输出字段")
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise RuntimeError("判题容器输出字段不是有效 Base64") from exc
        if len(decoded) > int(limit):
            raise RuntimeError("判题容器输出字段超过宿主上限")
        return decoded.decode("utf-8", errors="replace")

    try:
        returncode = int(payload["returncode"])
        elapsed_ns = int(payload["elapsed_ns"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("判题容器协议缺少执行状态") from exc
    if elapsed_ns < 0:
        raise RuntimeError("判题容器协议计时无效")
    artifact_names = payload.get("artifacts")
    if (
        not isinstance(artifact_names, list)
        or any(not isinstance(name, str) for name in artifact_names)
        or len(set(artifact_names)) != len(artifact_names)
        or not set(artifact_names).issubset(set(allowed_artifacts))
    ):
        raise RuntimeError("判题容器返回了白名单外产物")
    artifact_statuses = payload.get("artifact_statuses")
    fatal_without_artifacts = (
        returncode == -1
        and artifact_names == []
        and artifact_statuses == {}
    )
    if (
        not isinstance(artifact_statuses, dict)
        or (
            not fatal_without_artifacts
            and set(artifact_statuses) != set(allowed_artifacts)
        )
        or any(
            status_value not in {"absent", "exported", "rejected"}
            for status_value in artifact_statuses.values()
        )
        or {
            name
            for name, status_value in artifact_statuses.items()
            if status_value == "exported"
        }
        != set(artifact_names)
    ):
        raise RuntimeError("判题容器产物状态协议无效")
    for field in (
        "stdout_truncated",
        "stderr_truncated",
        "oom_killed",
    ):
        if not isinstance(payload.get(field), bool):
            raise RuntimeError("判题容器协议布尔字段无效")
    return {
        "returncode": returncode,
        "elapsed_ns": elapsed_ns,
        "stdout": decode_field("stdout_b64", stdout_limit),
        "stderr": decode_field("stderr_b64", stderr_limit),
        "stdout_truncated": bool(payload.get("stdout_truncated", False)),
        "stderr_truncated": bool(payload.get("stderr_truncated", False)),
        "oom_killed": bool(payload.get("oom_killed", False)),
        "artifact_names": artifact_names,
        "artifact_statuses": artifact_statuses,
    }


def _read_case_artifact(container_name, name, *, max_bytes):
    safe_name = _safe_artifact_name(name)
    limit = int(max_bytes)
    if limit < 0:
        raise ValueError("容器产物上限不能为负数")
    # Docker 不支持用 `docker cp` 读取 tmpfs。容器仍存活时以 root 只读流式
    # 导出可信 runner 写入的 0600 文件，并在宿主侧持续 drain、严格限制保留字节数。
    proc = subprocess.Popen(
        [
            "docker",
            "exec",
            "--user",
            "0:0",
            container_name,
            "cat",
            "--",
            f"/export/{safe_name}",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        data, stderr, truncated, stderr_truncated = _communicate_bounded(
            proc,
            timeout_sec=30,
            stdout_limit=limit + 1,
            stderr_limit=64 * 1024,
        )
    except subprocess.TimeoutExpired as exc:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        raise RuntimeError(f"从判题容器导出 {safe_name} 超时") from exc
    if (
        proc.returncode != 0
        or truncated
        or stderr_truncated
        or len(data) > limit
    ):
        detail = _decode_output(stderr)[:300]
        message = f"无法从判题容器导出 {safe_name}"
        if detail:
            message += f"：{detail}"
        raise RuntimeError(message)
    return data


def _copy_case_artifacts(container_name, artifact_limits):
    if not artifact_limits:
        return {}
    exported = {}
    for name, max_bytes in artifact_limits.items():
        safe_name = _safe_artifact_name(name)
        exported[safe_name] = _read_case_artifact(
            container_name,
            safe_name,
            max_bytes=max_bytes,
        )
    return exported


def run_case_in_container(
    cmd,
    *,
    run_dir,
    input_text="",
    timeout_sec=30,
    output_name="",
    output_max_bytes=1024 * 1024,
    image_name="",
    image_max_bytes=32 * 1024 * 1024,
    executable_name="",
    executable_max_bytes=64 * 1024 * 1024,
    document_name="",
    document_max_bytes=64 * 1024 * 1024,
):
    """在独立容器的有界 tmpfs 中执行一条不可信命令。

    ``run_dir`` 始终只读挂载为 ``/sandbox``。用户只可写 ``/case`` tmpfs，
    且无权读取 root-only 的 ``/export``。可信执行器在停止所有 runner 进程后，
    仅导出显式白名单中的 output.txt、指定图片或 a.out。
    """
    output_name = _safe_artifact_name(output_name) if output_name else ""
    if output_name and output_name != "output.txt":
        raise ValueError("文本产物只允许 output.txt")
    image_name = _safe_image_name(image_name)
    executable_name = (
        _safe_artifact_name(executable_name)
        if executable_name
        else ""
    )
    if executable_name and executable_name != "a.out":
        raise ValueError("可执行产物只允许 a.out")
    document_name = (
        _safe_artifact_name(document_name)
        if document_name
        else ""
    )
    if (
        document_name
        and os.path.splitext(document_name)[1].lower() != ".pdf"
    ):
        raise ValueError("文档产物只允许 PDF")

    input_bytes = str(input_text or "").encode("utf-8")
    if len(input_bytes) > _case_input_max_bytes():
        return _RunResult(-1, "", "测试点输入超过容器协议上限")

    stdout_limit = _stdout_max_bytes()
    stderr_limit = _stderr_max_bytes()
    allowed_artifacts = {}
    if output_name:
        allowed_artifacts[output_name] = int(output_max_bytes)
    if image_name:
        allowed_artifacts[image_name] = int(image_max_bytes)
    if executable_name:
        allowed_artifacts[executable_name] = int(executable_max_bytes)
    if document_name:
        allowed_artifacts[document_name] = int(document_max_bytes)
    if sum(allowed_artifacts.values()) > _export_tmpfs_bytes():
        raise RuntimeError("白名单产物上限超过导出 tmpfs 容量")

    container_name = f"numoj-case-{os.getpid()}-{uuid.uuid4().hex}"
    cleanup_required = False
    container_started = False
    proc = None
    protocol_parsed = False
    try:
        # `docker run -d` 的 ACK 可能超时或在创建容器后丢失；从发起调用前起，
        # 随机名称就进入必须确认删除的集合。
        cleanup_required = True
        start_result = subprocess.run(
            _case_container_start_command(
                container_name,
                run_dir,
                guard_timeout_sec=timeout_sec,
            ),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if start_result.returncode != 0:
            return _RunResult(-1, "", "无法启动判题测试点容器")
        container_started = True

        executor_cmd = [
            "docker",
            "exec",
            "-i",
            "--user",
            "0:0",
            "-w",
            "/case",
            container_name,
            "python3",
            "-I",
            _CASE_RUNNER_CONTAINER_PATH,
            "--runner-uid",
            str(_runner_uid()),
            "--runner-gid",
            str(_runner_gid()),
            "--workdir",
            "/case",
            "--export-dir",
            "/export",
            "--input-max-bytes",
            str(_case_input_max_bytes()),
            "--stdout-max-bytes",
            str(stdout_limit),
            "--stderr-max-bytes",
            str(stderr_limit),
            "--output-name",
            output_name,
            "--output-max-bytes",
            str(int(output_max_bytes)),
            "--image-name",
            image_name,
            "--image-max-bytes",
            str(int(image_max_bytes)),
            "--executable-name",
            executable_name,
            "--executable-max-bytes",
            str(int(executable_max_bytes)),
            "--document-name",
            document_name,
            "--document-max-bytes",
            str(int(document_max_bytes)),
            "--",
            *list(cmd),
        ]
        proc = subprocess.Popen(
            executor_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        protocol_limit = (
            ((stdout_limit + stderr_limit) * 4 + 2) // 3
            + 256 * 1024
        )
        try:
            protocol_stdout, protocol_stderr, protocol_truncated, _ = (
                _communicate_bounded(
                    proc,
                    input_bytes=input_bytes,
                    timeout_sec=timeout_sec,
                    stdout_limit=protocol_limit,
                    stderr_limit=64 * 1024,
                )
            )
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
            return _RunResult(124, "", "")
        if protocol_truncated:
            raise RuntimeError("判题容器协议超过宿主上限")
        parsed = _parse_case_protocol(
            protocol_stdout,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            allowed_artifacts=allowed_artifacts,
        )
        protocol_parsed = True
        if proc.returncode not in {0, 2}:
            raise RuntimeError(
                "判题容器执行器异常退出："
                + _decode_output(protocol_stderr)[:300]
            )
        requested_limits = {
            name: allowed_artifacts[name]
            for name in parsed["artifact_names"]
        }
        artifacts = _copy_case_artifacts(
            container_name,
            requested_limits,
        )
        return _RunResult(
            parsed["returncode"],
            parsed["stdout"],
            parsed["stderr"],
            parsed["elapsed_ns"],
            artifacts=artifacts,
            stdout_truncated=parsed["stdout_truncated"],
            stderr_truncated=parsed["stderr_truncated"],
            oom_killed=parsed["oom_killed"],
            artifact_statuses=parsed["artifact_statuses"],
        )
    except ContainerCleanupError:
        raise
    except Exception as exc:
        if container_started:
            oom_kill_count = _read_container_oom_kill_count(container_name)
            exec_was_oom_killed = bool(
                not protocol_parsed
                and proc is not None
                and getattr(proc, "returncode", None) == 137
            )
            if (
                (oom_kill_count is not None and oom_kill_count > 0)
                or exec_was_oom_killed
            ):
                return _RunResult(
                    -9,
                    "",
                    "",
                    oom_killed=True,
                )
        return _RunResult(-1, "", str(exc))
    finally:
        if cleanup_required:
            _force_remove_container(container_name)
