#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 Agent Judge 容器内运行标准答案模式的评分脚本。"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import tempfile

from backend.oj_modules import config as _cfg


def _config_value(name, default):
    env_value = os.environ.get(name)
    if env_value is not None and str(env_value).strip() != "":
        return env_value
    return getattr(_cfg, name, default)


AGENT_JUDGE_IMAGE = _config_value(
    "AGENT_JUDGE_DOCKER_IMAGE",
    "numericaloj-agent-judge:latest",
)
AGENT_JUDGE_WORKSPACE_ROOT = _config_value(
    "AGENT_JUDGE_WORKSPACE_ROOT",
    "ranking_uploads/judge_workspace",
)
AGENT_JUDGE_MEM_LIMIT = str(_config_value("AGENT_JUDGE_MEM_LIMIT", "4g"))
AGENT_JUDGE_CPU_LIMIT = str(_config_value("AGENT_JUDGE_CPU_LIMIT", "2"))
AGENT_JUDGE_PIDS_LIMIT = str(_config_value("AGENT_JUDGE_PIDS_LIMIT", "512"))


def _workspace_root():
    return os.path.abspath(os.path.join(AGENT_JUDGE_WORKSPACE_ROOT, "standard"))


def _copy_input(source_path, destination_dir):
    os.makedirs(destination_dir, exist_ok=True)
    filename = os.path.basename(os.path.abspath(source_path))
    destination = os.path.join(destination_dir, filename)
    shutil.copy2(source_path, destination)
    return destination


def _prepare_workspace(script_path, user_answer_path, reference_answer_path):
    root = _workspace_root()
    os.makedirs(root, exist_ok=True)
    workspace = tempfile.mkdtemp(prefix="evaluation-", dir=root)
    try:
        script = _copy_input(script_path, os.path.join(workspace, "scoring"))
        user_answer = _copy_input(
            user_answer_path, os.path.join(workspace, "submission"),
        )
        reference_answer = _copy_input(
            reference_answer_path, os.path.join(workspace, "reference"),
        )
        runtime = os.path.join(workspace, ".runtime")
        for name in ("cache", "config", "data", "tmp"):
            os.makedirs(os.path.join(runtime, name), exist_ok=True)
    except Exception:
        shutil.rmtree(workspace, ignore_errors=True)
        raise
    return workspace, script, user_answer, reference_answer


def _container_path(workspace, host_path):
    relative = os.path.relpath(host_path, workspace)
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        raise ValueError("标准答案评分文件不在临时工作区内")
    return "/workspace/" + relative.replace(os.sep, "/")


def _container_command(
        container_name, workspace, script_path, user_answer_path,
        reference_answer_path, max_score):
    runtime = "/workspace/.runtime"
    return [
        "docker",
        "run",
        "--rm",
        "-i",
        "--name",
        container_name,
        "--read-only",
        "--security-opt",
        "no-new-privileges",
        "--log-opt",
        "max-size=16m",
        "--log-opt",
        "max-file=1",
        "--pids-limit",
        AGENT_JUDGE_PIDS_LIMIT,
        "--memory",
        AGENT_JUDGE_MEM_LIMIT,
        "--cpus",
        AGENT_JUDGE_CPU_LIMIT,
        "--network",
        "bridge",
        "-e",
        "IS_SANDBOX=1",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        f"HOME={runtime}",
        "-e",
        f"XDG_CACHE_HOME={runtime}/cache",
        "-e",
        f"XDG_CONFIG_HOME={runtime}/config",
        "-e",
        f"XDG_DATA_HOME={runtime}/data",
        "-e",
        f"TMPDIR={runtime}/tmp",
        "-e",
        f"TMP={runtime}/tmp",
        "-e",
        f"TEMP={runtime}/tmp",
        "-v",
        f"{os.path.abspath(workspace)}:/workspace",
        "-w",
        "/workspace",
        str(AGENT_JUDGE_IMAGE),
        "python3",
        "-I",
        "-u",
        _container_path(workspace, script_path),
        _container_path(workspace, user_answer_path),
        _container_path(workspace, reference_answer_path),
        str(max_score),
    ]


def _force_remove_container(container_name):
    try:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception:
        pass


def run_standard_scoring_container(
        script_path, user_answer_path, reference_answer_path, max_score,
        timeout_seconds):
    """复制三项输入并在临时 Agent Judge 容器中执行既有评分协议。"""
    workspace, script, user_answer, reference_answer = _prepare_workspace(
        script_path, user_answer_path, reference_answer_path,
    )
    container_name = f"numoj-standard-score-{secrets.token_hex(12)}"
    try:
        command = _container_command(
            container_name,
            workspace,
            script,
            user_answer,
            reference_answer,
            max_score,
        )
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_seconds)),
            check=False,
        )
    finally:
        _force_remove_container(container_name)
        shutil.rmtree(workspace, ignore_errors=True)


__all__ = ["run_standard_scoring_container"]
