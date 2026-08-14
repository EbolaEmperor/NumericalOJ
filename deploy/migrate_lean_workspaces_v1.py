#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一次性把旧 Lean 4 单文件题迁移到不可变多文件工作区。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oj_modules.infrastructure.mysql import get_db_connection  # noqa: E402
from oj_modules.judging.lean_proof import parse_lean_proof_spec  # noqa: E402
from oj_modules.problems.lean_package import build_lean_package  # noqa: E402
from oj_modules.problems.lean_workspace import (  # noqa: E402
    bind_submission_workspace_with_cursor,
    insert_problem_revision_with_cursor,
)


LOCK_NAME = "numericaloj:migrate_lean_workspaces_v1"


def _legacy_package(initial_code: str, test_code: str):
    spec = parse_lean_proof_spec(test_code)
    if "Submission." in spec.target:
        raise ValueError(
            "旧 target 引用了可写 Submission 声明，不能机械迁移为可信只读目标"
        )
    imports = "\n".join(f"import {module}" for module in spec.imports)
    problem_source = (
        f"{imports}\n\n"
        "namespace Problem\n\n"
        f"def Target : Prop := ({spec.target})\n\n"
        "end Problem\n"
    )
    manifest = {
        "schema_version": 1,
        "default_file": "Submission.lean",
        "files": [
            {"path": "Problem.lean", "mode": "readonly"},
            {"path": "Submission.lean", "mode": "writable"},
        ],
        "build_order": ["Problem.lean", "Submission.lean"],
        "verification": {
            "target_module": "Problem",
            "target_decl": "Problem.Target",
            "entry_module": "Submission",
            "entry_decl": spec.entry,
            "permitted_axioms": list(spec.permitted_axioms),
        },
    }
    return build_lean_package(
        manifest,
        {
            "Problem.lean": problem_source,
            "Submission.lean": str(initial_code or ""),
        },
    )


def migrate() -> dict:
    conn = get_db_connection()
    locked = False
    report = {
        "problems_created": 0,
        "problems_existing": 0,
        "submissions_bound": 0,
        "submissions_existing": 0,
    }
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 120) AS locked", (LOCK_NAME,))
            row = cursor.fetchone() or {}
            if int(row.get("locked") or 0) != 1:
                raise RuntimeError("无法取得 Lean 工作区迁移锁")
            locked = True
            cursor.execute(
                """SELECT id, initial_code, test_code
                   FROM problems
                   WHERE type=1 AND LOWER(lang) IN ('lean','lean4')
                   ORDER BY id FOR UPDATE"""
            )
            problems = list(cursor.fetchall() or [])
            for problem in problems:
                problem_id = int(problem["id"])
                cursor.execute(
                    """SELECT id, package_sha256
                       FROM lean_problem_revisions
                       WHERE problem_id=%s
                       ORDER BY revision_number DESC LIMIT 1""",
                    (problem_id,),
                )
                revision = cursor.fetchone()
                if revision:
                    report["problems_existing"] += 1
                else:
                    try:
                        package = _legacy_package(
                            problem.get("initial_code") or "",
                            problem.get("test_code") or "",
                        )
                    except Exception as exc:
                        raise RuntimeError(
                            f"Lean 题目 {problem_id} 无法自动迁移：{exc}"
                        ) from exc
                    revision_id, _ = insert_problem_revision_with_cursor(
                        cursor,
                        problem_id=problem_id,
                        package=package,
                        created_by_user_id=None,
                    )
                    revision = {
                        "id": revision_id,
                        "package_sha256": package.package_sha256,
                    }
                    report["problems_created"] += 1

                cursor.execute(
                    """SELECT s.id, s.code,
                              lsw.submission_id AS workspace_submission_id
                       FROM submissions s
                       LEFT JOIN lean_submission_workspaces lsw
                         ON lsw.submission_id=s.id
                       WHERE s.problem_id=%s ORDER BY s.id""",
                    (problem_id,),
                )
                for submission in cursor.fetchall() or []:
                    if submission.get("workspace_submission_id") is not None:
                        report["submissions_existing"] += 1
                        continue
                    bind_submission_workspace_with_cursor(
                        cursor,
                        submission_id=int(submission["id"]),
                        problem_id=problem_id,
                        revision=str(revision["package_sha256"]),
                        files={"Submission.lean": str(submission.get("code") or "")},
                    )
                    report["submissions_bound"] += 1

            cursor.execute(
                """SELECT COUNT(*) AS missing
                   FROM problems p
                   LEFT JOIN lean_problem_revisions lpr ON lpr.problem_id=p.id
                   WHERE p.type=1 AND LOWER(p.lang) IN ('lean','lean4')
                     AND lpr.id IS NULL"""
            )
            if int((cursor.fetchone() or {}).get("missing") or 0) != 0:
                raise RuntimeError("迁移后仍有 Lean 题目没有工作区")
            cursor.execute(
                """SELECT COUNT(*) AS missing
                   FROM submissions s
                   JOIN problems p ON p.id=s.problem_id
                   LEFT JOIN lean_submission_workspaces lsw
                     ON lsw.submission_id=s.id
                   WHERE p.type=1 AND LOWER(p.lang) IN ('lean','lean4')
                     AND lsw.submission_id IS NULL"""
            )
            if int((cursor.fetchone() or {}).get("missing") or 0) != 0:
                raise RuntimeError("迁移后仍有 Lean 历史提交没有绑定工作区")
        conn.commit()
        return report
    except Exception:
        conn.rollback()
        raise
    finally:
        if locked:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK(%s)", (LOCK_NAME,))
                conn.commit()
            except Exception:
                conn.rollback()
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", required=True)
    parser.add_argument(
        "--confirm-app-writers-stopped", action="store_true", required=True
    )
    parser.parse_args()
    print(json.dumps(migrate(), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
