#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lean 4 多文件证明题的隔离构建与内核验证。"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import PurePosixPath
import re
import shutil
import tempfile

from oj_modules import config as _cfg
from oj_modules.judging import core
from oj_modules.judging.sandbox import run_in_container


LEAN4_DOCKER_IMAGE = "numericaloj-lean4:latest"
PROBLEM_BUILD_TIMEOUT_SECONDS = 600.0
STUDENT_BUILD_TIMEOUT_SECONDS = 300.0
DEFAULT_PERMITTED_AXIOMS = (
    "propext",
    "Quot.sound",
    "Classical.choice",
)
_QUALIFIED_NAME_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*$"
)
_VERIFIER_RESULT_BEGIN = "__NUMOJ_VERIFIER_RESULT_BEGIN__"


@dataclass(frozen=True)
class LeanProofSpec:
    """旧单文件题的迁移输入；正式判题不再读取此结构。"""

    target: str
    entry: str
    imports: tuple[str, ...]
    permitted_axioms: tuple[str, ...]


def parse_lean_proof_spec(test_code: str) -> LeanProofSpec:
    """读取旧版 ``problems.test_code``，仅供一次性迁移使用。"""

    try:
        payload = json.loads(str(test_code or ""))
    except json.JSONDecodeError as exc:
        raise ValueError("Lean 4 证明规格不是有效 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Lean 4 证明规格必须是 JSON 对象")
    target = str(payload.get("target") or "").strip()
    entry = str(payload.get("entry") or "Submission.answer").strip()
    imports = payload.get("imports") or ["Mathlib.Data.Nat.Basic"]
    permitted_axioms = payload.get("permitted_axioms") or list(
        DEFAULT_PERMITTED_AXIOMS
    )
    if not target:
        raise ValueError("Lean 4 证明规格缺少 target")
    if not _QUALIFIED_NAME_RE.fullmatch(entry):
        raise ValueError("Lean 4 证明入口名称无效")
    if (
        not isinstance(imports, list)
        or not imports
        or any(
            not isinstance(module, str)
            or not _QUALIFIED_NAME_RE.fullmatch(module.strip())
            for module in imports
        )
    ):
        raise ValueError("Lean 4 imports 必须是模块名数组")
    if (
        not isinstance(permitted_axioms, list)
        or any(
            not isinstance(name, str)
            or not _QUALIFIED_NAME_RE.fullmatch(name.strip())
            for name in permitted_axioms
        )
    ):
        raise ValueError("Lean 4 permitted_axioms 必须是声明名数组")
    return LeanProofSpec(
        target=target,
        entry=entry,
        imports=tuple(dict.fromkeys(item.strip() for item in imports)),
        permitted_axioms=tuple(
            dict.fromkeys(item.strip() for item in permitted_axioms)
        ),
    )


def build_lean_solution(spec: LeanProofSpec, submission_id: int | str) -> str:
    """保留旧归档可读性；正式判题禁止执行该文本 bridge。"""

    suffix = re.sub(r"[^A-Za-z0-9_]", "_", str(submission_id or "proof"))
    imports = "\n".join(f"import {module}" for module in spec.imports)
    return (
        f"{imports}\nimport Submission\n\n"
        f"namespace NumOJLegacyArchive_{suffix}\n"
        f"theorem answer : ({spec.target}) := by exact {spec.entry}\n"
        "end NumOJLegacyArchive_" + suffix + "\n"
    )


def _result(status: str, stderr: str, elapsed_ms: int, axioms=None, stage="") -> dict:
    return {
        "status": status,
        "stderr": str(stderr or "").strip(),
        "time": int(elapsed_ms or 0),
        "axioms": list(axioms or []),
        "stage": stage,
    }


def _write_source(root: str, relative_path: str, content: str) -> None:
    parts = PurePosixPath(relative_path).parts
    path = os.path.join(root, *parts)
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    with open(path, "x", encoding="utf-8", newline="\n") as handle:
        handle.write(str(content or ""))
    os.chmod(path, 0o644)


def _elapsed_ms(result) -> int:
    return int(round(int(result.elapsed_ns or 0) / 1_000_000))


def _container_terminal_result(result, elapsed_ms: int, *, stage: str):
    stdout = str(result.stdout or "")
    stderr = str(result.stderr or "")
    if result.returncode == 124:
        return _result(
            "Time Limit Exceeded", "Lean 4 证明检查超时", elapsed_ms, stage=stage
        )
    if result.returncode in (137, -9):
        return _result(
            "Memory Limit Exceeded",
            "Lean 4 证明检查超过内存限制",
            elapsed_ms,
            stage=stage,
        )
    if result.returncode in (-1, 125, 126, 127):
        return _result(
            "Error",
            stderr or stdout or "Lean 4 评测容器启动失败",
            elapsed_ms,
            stage=stage,
        )
    return None


def _parse_verifier_axioms(stdout: str) -> list[str] | None:
    if _VERIFIER_RESULT_BEGIN not in stdout:
        return None
    segment = stdout.rsplit(_VERIFIER_RESULT_BEGIN, 1)[1]
    if "RESULT=ACCEPTED" not in segment:
        return None
    return sorted(
        {
            line.split("=", 1)[1].strip()
            for line in segment.splitlines()
            if line.startswith("AXIOM=") and line.split("=", 1)[1].strip()
        }
    )


def evaluate_lean_proof(
    *,
    submission_id: int,
    workspace: dict | None = None,
    time_limit_ms: int,
    source: str | None = None,
    test_code: str | None = None,
) -> dict:
    """构建绑定版本中的完整工作区，并由可信程序检查学生定理。"""

    if not workspace:
        return _result(
            "Error",
            "该提交没有绑定 Lean 4 多文件工作区，不能使用旧版文本验证器。",
            0,
            stage="workspace",
        )
    files = list(workspace.get("files") or [])
    verification = workspace.get("verification")
    if not files or not isinstance(verification, dict):
        return _result("Error", "Lean 4 工作区记录不完整", 0, stage="workspace")

    readonly = [item for item in files if item.get("mode") == "readonly"]
    writable = [item for item in files if item.get("mode") == "writable"]
    if not readonly or not writable:
        return _result("Error", "Lean 4 工作区文件模式无效", 0, stage="workspace")
    required_names = (
        "target_module",
        "target_decl",
        "entry_module",
        "entry_decl",
    )
    if any(not str(verification.get(name) or "").strip() for name in required_names):
        return _result("Error", "Lean 4 验证配置不完整", 0, stage="workspace")

    os.makedirs(core.JUDGER_RUN_ROOT, mode=0o700, exist_ok=True)
    run_root = tempfile.mkdtemp(
        prefix=f"eoj-lean-{int(submission_id)}-",
        dir=core.JUDGER_RUN_ROOT,
    )
    os.chmod(run_root, 0o755)
    problem_root = os.path.join(run_root, "problem-src")
    student_root = os.path.join(run_root, "student-src")
    trusted_output = os.path.join(run_root, "trusted-olean")
    os.makedirs(problem_root, mode=0o755)
    os.makedirs(trusted_output, mode=0o777)
    os.chmod(trusted_output, 0o777)
    image = (
        str(os.environ.get("LEAN4_DOCKER_IMAGE") or "").strip()
        or LEAN4_DOCKER_IMAGE
    )
    time_limit_sec = min(
        STUDENT_BUILD_TIMEOUT_SECONDS,
        max(1.0, int(time_limit_ms or 10000) / 1000.0),
    )
    problem_build_timeout_sec = PROBLEM_BUILD_TIMEOUT_SECONDS
    total_elapsed_ms = 0
    try:
        for item in readonly:
            _write_source(
                problem_root,
                str(item.get("path") or ""),
                str(item.get("content") or ""),
            )
        readonly_paths = [
            str(item.get("path") or "")
            for item in sorted(readonly, key=lambda row: int(row.get("build_order") or 0))
        ]
        trusted_result = run_in_container(
            [
                "timeout",
                "-k",
                "1s",
                f"{problem_build_timeout_sec:g}s",
                "/usr/local/bin/numoj-lean-problem-build",
                "/sandbox/problem-src",
                "/sandbox/trusted-olean",
                *readonly_paths,
            ],
            run_dir=run_root,
            run_dir_read_only=False,
            timeout_sec=problem_build_timeout_sec + 15,
            measure_time=True,
            docker_image=image,
            memory_limit=str(getattr(_cfg, "LEAN4_JUDGE_MEM_LIMIT", "2g")),
        )
        trusted_elapsed = _elapsed_ms(trusted_result)
        total_elapsed_ms += trusted_elapsed
        terminal = _container_terminal_result(
            trusted_result, total_elapsed_ms, stage="problem_build"
        )
        if terminal:
            return terminal
        if trusted_result.returncode != 0:
            return _result(
                "Error",
                trusted_result.stderr or trusted_result.stdout or "只读题目模块编译失败",
                total_elapsed_ms,
                stage="problem_build",
            )

        shutil.rmtree(student_root, ignore_errors=True)
        os.makedirs(student_root, mode=0o755)
        for item in writable:
            _write_source(
                student_root,
                str(item.get("path") or ""),
                str(item.get("content") or ""),
            )
        writable_paths = [
            str(item.get("path") or "")
            for item in sorted(writable, key=lambda row: int(row.get("build_order") or 0))
        ]
        permitted = verification.get("permitted_axioms") or []
        student_result = run_in_container(
            [
                "timeout",
                "-k",
                "1s",
                f"{time_limit_sec:g}s",
                "/usr/local/bin/numoj-lean-workspace-judge",
                "/sandbox",
                str(verification["target_module"]),
                str(verification["target_decl"]),
                str(verification["entry_module"]),
                str(verification["entry_decl"]),
                ",".join(str(name) for name in permitted),
                *writable_paths,
            ],
            run_dir=run_root,
            timeout_sec=time_limit_sec + 15,
            measure_time=True,
            docker_image=image,
            memory_limit=str(getattr(_cfg, "LEAN4_JUDGE_MEM_LIMIT", "2g")),
        )
        total_elapsed_ms += _elapsed_ms(student_result)
        terminal = _container_terminal_result(
            student_result, total_elapsed_ms, stage="student_build"
        )
        if terminal:
            return terminal
        stdout = str(student_result.stdout or "")
        stderr = str(student_result.stderr or "")
        axioms = _parse_verifier_axioms(stdout)
        if student_result.returncode == 0 and axioms is not None:
            return _result(
                "Accepted",
                "",
                total_elapsed_ms,
                axioms=axioms,
                stage="kernel_check",
            )
        if "__NUMOJ_WRITABLE_MODULE_CONFLICT__" in stderr:
            return _result(
                "Error",
                "Lean 4 可写模块与可信依赖冲突",
                total_elapsed_ms,
                stage="student_build",
            )
        if "__NUMOJ_VERIFIER_PROCESS_BEGIN__" not in stdout:
            return _result(
                "Compile Error",
                stderr or stdout,
                total_elapsed_ms,
                stage="student_build",
            )
        platform_error = any(
            marker in stderr
            for marker in (
                "Target declaration not found",
                "Target declaration must",
                "Lean verifier failed",
            )
        )
        return _result(
            "Error" if platform_error else "Wrong Answer",
            stderr or stdout or "Lean 4 证明未通过可信验证",
            total_elapsed_ms,
            stage="kernel_check",
        )
    finally:
        shutil.rmtree(run_root, ignore_errors=True)


__all__ = [
    "DEFAULT_PERMITTED_AXIOMS",
    "LEAN4_DOCKER_IMAGE",
    "LeanProofSpec",
    "build_lean_solution",
    "evaluate_lean_proof",
    "parse_lean_proof_spec",
]
