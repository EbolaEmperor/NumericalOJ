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
    return getattr(_get_config(), "JUDGER_DOCKER_MEM_LIMIT", "512m")


def _cpu_limit():
    return getattr(_get_config(), "JUDGER_DOCKER_CPU_LIMIT", "1")


def _pids_limit():
    return getattr(_get_config(), "JUDGER_DOCKER_PIDS_LIMIT", "128")


def _network():
    return getattr(_get_config(), "JUDGER_DOCKER_NETWORK", "none")


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
