#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lean 4 完整文件证明题判题。"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import shutil
import tempfile

from oj_modules.judging import core
from oj_modules.judging.sandbox import run_in_container


LEAN4_DOCKER_IMAGE = "numericaloj-lean4:latest"
DEFAULT_PERMITTED_AXIOMS = (
    "propext",
    "Quot.sound",
    "Classical.choice",
)
_QUALIFIED_NAME_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*$"
)
_AXIOM_BEGIN = "__NUMOJ_AXIOMS_BEGIN__"
_AXIOM_END = "__NUMOJ_AXIOMS_END__"


@dataclass(frozen=True)
class LeanProofSpec:
    target: str
    entry: str
    imports: tuple[str, ...]
    permitted_axioms: tuple[str, ...]


def parse_lean_proof_spec(test_code: str) -> LeanProofSpec:
    """从题目的 ``test_code`` 读取 Lean 证明规格 JSON。"""

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
        imports=tuple(dict.fromkeys(module.strip() for module in imports)),
        permitted_axioms=tuple(
            dict.fromkeys(name.strip() for name in permitted_axioms)
        ),
    )


def build_lean_solution(spec: LeanProofSpec, submission_id: int | str) -> str:
    """生成平台持有的 bridge，要求学生入口精确提供目标命题。"""

    suffix = re.sub(r"[^A-Za-z0-9_]", "_", str(submission_id or "proof"))
    namespace = f"NumOJVerifier_{suffix}"
    import_lines = "\n".join(f"import {module}" for module in spec.imports)
    return (
        f"{import_lines}\n"
        "import Submission\n\n"
        f"namespace {namespace}\n\n"
        f"theorem answer : ({spec.target}) := by\n"
        f"  exact {spec.entry}\n\n"
        f'#eval IO.println "{_AXIOM_BEGIN}"\n'
        "#print axioms answer\n"
        f'#eval IO.println "{_AXIOM_END}"\n\n'
        f"end {namespace}\n"
    )


def _extract_axioms(output: str) -> set[str] | None:
    if _AXIOM_BEGIN not in output or _AXIOM_END not in output:
        return None
    segment = output.rsplit(_AXIOM_BEGIN, 1)[1].split(_AXIOM_END, 1)[0]
    if "does not depend on any axioms" in segment:
        return set()
    match = re.search(r"depends on axioms:\s*\[([^\]]*)\]", segment, re.DOTALL)
    if not match:
        return None
    return {
        name.strip()
        for name in match.group(1).replace("\n", " ").split(",")
        if name.strip()
    }


def _write_workspace_file(workspace: str, name: str, content: str) -> None:
    path = os.path.join(workspace, name)
    with open(path, "x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    os.chmod(path, 0o644)


def evaluate_lean_proof(
    *,
    submission_id: int,
    source: str,
    test_code: str,
    time_limit_ms: int,
) -> dict:
    """在独立 Lean 镜像中检查一份完整的 ``Submission.lean``。"""

    try:
        spec = parse_lean_proof_spec(test_code)
    except ValueError as exc:
        return {
            "status": "Error",
            "stderr": str(exc),
            "time": 0,
            "axioms": [],
        }

    os.makedirs(core.JUDGER_RUN_ROOT, mode=0o700, exist_ok=True)
    workspace = tempfile.mkdtemp(
        prefix=f"eoj-lean-{int(submission_id)}-",
        dir=core.JUDGER_RUN_ROOT,
    )
    os.chmod(workspace, 0o755)
    try:
        _write_workspace_file(workspace, "Submission.lean", str(source or ""))
        _write_workspace_file(
            workspace,
            "Solution.lean",
            build_lean_solution(spec, submission_id),
        )

        time_limit_sec = max(1.0, int(time_limit_ms or 2000) / 1000.0)
        result = run_in_container(
            [
                "timeout",
                "-k",
                "1s",
                f"{time_limit_sec:g}s",
                "/usr/local/bin/numoj-lean-judge",
                "/sandbox",
            ],
            run_dir=workspace,
            timeout_sec=time_limit_sec + 15,
            measure_time=True,
            docker_image=(
                str(os.environ.get("LEAN4_DOCKER_IMAGE") or "").strip()
                or LEAN4_DOCKER_IMAGE
            ),
        )
        elapsed_ms = int(round(int(result.elapsed_ns or 0) / 1_000_000))
        stdout = str(result.stdout or "")
        stderr = str(result.stderr or "")
        combined = f"{stdout}\n{stderr}"

        if result.returncode == 124:
            return {
                "status": "Time Limit Exceeded",
                "stderr": "Lean 4 证明检查超时",
                "time": elapsed_ms,
                "axioms": [],
            }
        if result.returncode in (137, -9):
            return {
                "status": "Memory Limit Exceeded",
                "stderr": "Lean 4 证明检查超过内存限制",
                "time": elapsed_ms,
                "axioms": [],
            }
        if result.returncode in (-1, 125, 126, 127):
            return {
                "status": "Error",
                "stderr": (stderr or stdout or "Lean 4 评测容器启动失败").strip(),
                "time": elapsed_ms,
                "axioms": [],
            }
        if result.returncode != 0:
            return {
                "status": "Compile Error",
                "stderr": (stderr or stdout).strip(),
                "time": elapsed_ms,
                "axioms": [],
            }

        axioms = _extract_axioms(combined)
        if axioms is None:
            return {
                "status": "Error",
                "stderr": "Lean 4 未返回目标定理的公理依赖",
                "time": elapsed_ms,
                "axioms": [],
            }
        forbidden_axioms = sorted(axioms.difference(spec.permitted_axioms))
        if forbidden_axioms:
            return {
                "status": "Wrong Answer",
                "stderr": "证明依赖不允许的公理：" + ", ".join(forbidden_axioms),
                "time": elapsed_ms,
                "axioms": sorted(axioms),
            }

        return {
            "status": "Accepted",
            "stderr": "",
            "time": elapsed_ms,
            "axioms": sorted(axioms),
        }
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


__all__ = [
    "DEFAULT_PERMITTED_AXIOMS",
    "LEAN4_DOCKER_IMAGE",
    "LeanProofSpec",
    "build_lean_solution",
    "evaluate_lean_proof",
    "parse_lean_proof_spec",
]
