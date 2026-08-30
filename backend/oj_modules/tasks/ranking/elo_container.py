#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 Agent Judge 容器内运行 ELO 成对评分脚本。"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import tempfile

from backend.oj_modules import config as _cfg
from backend.oj_modules.shared.archive import ZipExtractionPolicy, extract_zip


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

ELO_PACKAGE_MAX_MEMBERS = 4096
ELO_PACKAGE_MAX_FILE_BYTES = 256 * 1024 * 1024
ELO_PACKAGE_MAX_TOTAL_BYTES = 512 * 1024 * 1024
ELO_PACKAGE_MAX_COMPRESSION_RATIO = 500.0


def _workspace_root():
    return os.path.abspath(os.path.join(AGENT_JUDGE_WORKSPACE_ROOT, "elo"))


def _extract_submission(archive_path, destination):
    extract_zip(
        archive_path,
        destination,
        policy=ZipExtractionPolicy(
            max_members=ELO_PACKAGE_MAX_MEMBERS,
            max_file_bytes=ELO_PACKAGE_MAX_FILE_BYTES,
            max_total_bytes=ELO_PACKAGE_MAX_TOTAL_BYTES,
            max_compression_ratio=ELO_PACKAGE_MAX_COMPRESSION_RATIO,
            require_non_empty=True,
            unsafe_member_action="raise",
            cleanup_on_error=True,
        ),
    )


def _prepare_workspace(script_path, archive_a, archive_b):
    root = _workspace_root()
    os.makedirs(root, exist_ok=True)
    workspace = tempfile.mkdtemp(prefix="match-", dir=root)
    try:
        shutil.copy2(script_path, os.path.join(workspace, "scoring_script.py"))
        _extract_submission(archive_a, os.path.join(workspace, "submission_a"))
        _extract_submission(archive_b, os.path.join(workspace, "submission_b"))
    except Exception:
        shutil.rmtree(workspace, ignore_errors=True)
        raise
    return workspace


def _container_command(container_name, workspace):
    return [
        "docker",
        "run",
        "--rm",
        "-i",
        "--name",
        container_name,
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
        # 与 Agent-as-Judge 容器一致，使用可访问外网的 Docker bridge。
        "--network",
        "bridge",
        "-e",
        "IS_SANDBOX=1",
        "-e",
        "NUMOJ_ELO_SUBMISSION_A=/workspace/submission_a",
        "-e",
        "NUMOJ_ELO_SUBMISSION_B=/workspace/submission_b",
        "-v",
        f"{os.path.abspath(workspace)}:/workspace",
        "-w",
        "/workspace",
        str(AGENT_JUDGE_IMAGE),
        "python3",
        "-I",
        "-u",
        "/workspace/scoring_script.py",
        "/workspace/submission_a",
        "/workspace/submission_b",
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


def run_elo_scoring_container(script_path, archive_a, archive_b, timeout_seconds):
    """解压双方作品，在同一个可联网 Agent Judge 容器中运行评分脚本。

    容器内固定路径为 ``/workspace/submission_a`` 和
    ``/workspace/submission_b``。当前协议暂时把双方代码视为可信内容，不在
    同一容器内继续隔离两个目录或其子进程。
    """
    workspace = _prepare_workspace(script_path, archive_a, archive_b)
    container_name = f"numoj-elo-score-{secrets.token_hex(12)}"
    command = _container_command(container_name, workspace)
    try:
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


__all__ = ["run_elo_scoring_container"]
