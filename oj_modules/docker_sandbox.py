#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Docker 容器沙箱执行原语。

提供两个核心接口：
- run_in_container(): 一次性容器，运行单条命令后销毁。
- ContainerSession: 持续容器上下文管理器，支持多次 exec（用于编译+多测试点场景）。

所有用户代码在完全隔离的容器中执行：断网、只读根文件系统、非 root 用户、
内存/CPU/进程数限制。
"""

import os
import subprocess
import time

_CONFIG = None


def _get_config():
    global _CONFIG
    if _CONFIG is None:
        try:
            import config as _cfg
            _CONFIG = _cfg
        except ImportError:
            _CONFIG = object()
    return _CONFIG


def _image():
    return getattr(_get_config(), "JUDGER_DOCKER_IMAGE", "numericaloj-judger:latest")


def _mem_limit():
    return getattr(_get_config(), "JUDGER_DOCKER_MEM_LIMIT", "1g")


def _cpu_limit():
    # 默认 2 核（而非 1）：Octave 的 gnuplot 出图会拉起独立 gnuplot 子进程，单核下
    # octave↔gnuplot 抢同一核、冷启动严重 thrash（实测 diag79 单核冷跑 15s、热跑
    # ~1.5s 高方差；给到 2 核后稳定 ~1.53s）。带绘图 interactor 的题在 1 核下必 TLE。
    return getattr(_get_config(), "JUDGER_DOCKER_CPU_LIMIT", "2")


def _pids_limit():
    return getattr(_get_config(), "JUDGER_DOCKER_PIDS_LIMIT", "128")


def _network():
    return getattr(_get_config(), "JUDGER_DOCKER_NETWORK", "none")


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
    return flags


class _RunResult:
    __slots__ = ("returncode", "stdout", "stderr")

    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run_in_container(cmd, *, run_dir, input_text="", timeout_sec=30, extra_ro_mounts=None):
    """在一次性 Docker 容器中执行命令。

    Args:
        cmd: 容器内执行的命令列表，如 ["python3", "-I", "-u", "main.py"]
        run_dir: 宿主机运行目录，挂载为容器内 /sandbox (rw)
        input_text: 传入容器 stdin 的文本
        timeout_sec: Python 侧超时（秒）
        extra_ro_mounts: 额外只读挂载列表，每项为 (host_path, container_path)

    Returns:
        _RunResult(returncode, stdout, stderr)
    """
    docker_cmd = [
        "docker", "run", "--rm", "-i",
        "--network", _network(),
        "--security-opt", "no-new-privileges",
        "--memory", _mem_limit(),
        "--cpus", _cpu_limit(),
        "--pids-limit", _pids_limit(),
        "--read-only",
        "--tmpfs", "/tmp:size=64m",
        *_thread_env_flags(),
        "-v", f"{os.path.abspath(run_dir)}:/sandbox:rw",
        "--user", "runner",
        "-w", "/sandbox",
    ]

    if extra_ro_mounts:
        for host_path, container_path in extra_ro_mounts:
            if os.path.exists(host_path):
                docker_cmd.extend(["-v", f"{os.path.abspath(host_path)}:{container_path}:ro"])

    docker_cmd.append(_image())
    docker_cmd.extend(cmd)

    try:
        proc = subprocess.Popen(
            docker_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(input=input_text, timeout=timeout_sec)
        return _RunResult(proc.returncode, stdout or "", stderr or "")
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except Exception:
            stdout, stderr = "", ""
        return _RunResult(124, stdout or "", stderr or "")
    except Exception as e:
        return _RunResult(-1, "", str(e))


class ContainerSession:
    """持续容器会话，支持多次 exec。

    用法:
        with ContainerSession(run_dir="/path/to/dir") as session:
            result = session.exec(["gcc", "-O2", "main.c", "-o", "a.out"])
            result = session.exec(["./a.out"], input_text="1 2 3")
    """

    def __init__(self, *, run_dir, extra_ro_mounts=None):
        self._run_dir = os.path.abspath(run_dir)
        self._extra_ro_mounts = extra_ro_mounts or []
        self._container_id = None

    def __enter__(self):
        docker_cmd = [
            "docker", "run", "-d",
            "--network", _network(),
            "--security-opt", "no-new-privileges",
            "--memory", _mem_limit(),
            "--cpus", _cpu_limit(),
            "--pids-limit", _pids_limit(),
            "--read-only",
            "--tmpfs", "/tmp:size=64m",
            *_thread_env_flags(),
            "-v", f"{self._run_dir}:/sandbox:rw",
            "--user", "runner",
            "-w", "/sandbox",
        ]

        for host_path, container_path in self._extra_ro_mounts:
            if os.path.exists(host_path):
                docker_cmd.extend(["-v", f"{os.path.abspath(host_path)}:{container_path}:ro"])

        docker_cmd.extend([_image(), "sleep", "infinity"])

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to start container: {result.stderr.strip()}")
        self._container_id = result.stdout.strip()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._container_id:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", self._container_id],
                    capture_output=True,
                    timeout=15,
                )
            except Exception:
                pass
            self._container_id = None
        return False

    def exec(self, cmd, *, input_text="", timeout_sec=30):
        """在容器内执行命令。

        Returns:
            _RunResult(returncode, stdout, stderr)
        """
        if not self._container_id:
            raise RuntimeError("Container session not started")

        docker_cmd = ["docker", "exec", "-i", self._container_id] + list(cmd)

        try:
            proc = subprocess.Popen(
                docker_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(input=input_text, timeout=timeout_sec)
            return _RunResult(proc.returncode, stdout or "", stderr or "")
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except Exception:
                stdout, stderr = "", ""
            return _RunResult(124, stdout or "", stderr or "")
        except Exception as e:
            return _RunResult(-1, "", str(e))
