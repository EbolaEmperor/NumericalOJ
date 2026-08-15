#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""使用所选 CLI harness 在隔离容器内完成一道编程题。"""

from __future__ import annotations

from functools import wraps
import time

from oj_modules.db_services import (
    get_problem,
    get_submissions_by_user_and_problem,
    get_user_by_username,
)
from oj_modules.problems.agent_launch import (
    AGENT_ACCESS_ROLE_USER,
    AGENT_TASK_SOLVE,
    build_solution_agent_prompt,
    resolve_launch_endpoint,
    validate_launch_endpoint_revision,
)
from oj_modules.tasks.agent.conversation import extract_agent_conclusion
from oj_modules.tasks.agent.harness_runtime import (
    AgentHarnessCleanupError,
    run_agent_harness,
)
from oj_modules.tasks.agent.shared import (
    AGENT_SOLVE_TASK_NAME,
    _format_local_time,
    _publish_agent_trace,
    _update_agent_state,
    agent_run_is_canceled,
    canceled_agent_task_result,
    existing_agent_terminal_result,
    finalize_unhandled_agent_failure,
)
from oj_modules.tasks.agent.traces import prepare_agent_trace_dir
from oj_modules.tasks.agent.queue import build_agent_control_bridge
from oj_modules.tasks.agent.titles import (
    generate_initial_agent_session_title,
)
from oj_modules.agents.sessions import get_agent_session


__all__ = [
    "register_agent_solve_problem_task",
]


def _created_submissions(username, problem_id, created_ids):
    rows = get_submissions_by_user_and_problem(username, problem_id) or []
    tracked = {int(value) for value in created_ids or ()}
    return [row for row in rows if int(row.get("id") or 0) in tracked]


def _submission_attempts(rows):
    attempts = []
    for row in sorted(rows, key=lambda item: int(item.get("id") or 0)):
        attempts.append({
            "submission_id": int(row.get("id") or 0),
            "summary": {
                "status": str(row.get("status") or "Unknown"),
                "score": int(row.get("score") or 0),
            },
        })
    return attempts


def _accepted_submission(rows):
    accepted = [
        row
        for row in rows
        if str(row.get("status") or "").strip().lower() == "accepted"
    ]
    if not accepted:
        return None
    return max(accepted, key=lambda item: int(item.get("id") or 0))


def _conclude_unhandled_solve_failures(function):
    @wraps(function)
    def wrapped(
        self,
        problem_id,
        requested_by,
        harness=None,
        endpoint_id=None,
        session_cookie="",
        session_cookie_name="session",
        endpoint_revision=None,
    ):
        task_id = str(
            getattr(getattr(self, "request", None), "id", None) or ""
        ).strip() or f"unknown-{int(time.time())}"
        try:
            normalized_problem_id = int(problem_id)
        except (TypeError, ValueError):
            normalized_problem_id = None
        state = {
            "task_id": task_id,
            "session_id": task_id,
            "problem_id": normalized_problem_id,
            "problem_title": "",
            "requested_by": requested_by,
            "task_kind": AGENT_TASK_SOLVE,
            "access_role": AGENT_ACCESS_ROLE_USER,
            "harness": str(harness or ""),
            "endpoint_id": endpoint_id,
            "status": "Running",
            "message": "解题 Agent 启动中",
            "attempts": [],
            "native_session_id": "",
            "conclusion": "",
        }
        try:
            return function(
                self,
                problem_id,
                requested_by,
                harness,
                endpoint_id,
                session_cookie,
                session_cookie_name,
                endpoint_revision,
            )
        except Exception as exc:
            return finalize_unhandled_agent_failure(
                state,
                exc,
                task_label="解题 Agent",
                update_state=_update_agent_state,
                terminal_result_reader=existing_agent_terminal_result,
                cancellation_check=agent_run_is_canceled,
                canceled_result_factory=canceled_agent_task_result,
            )

    return wrapped


def register_agent_solve_problem_task(celery_app):
    existing = celery_app.tasks.get(AGENT_SOLVE_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(
        bind=True,
        name=AGENT_SOLVE_TASK_NAME,
    )
    @_conclude_unhandled_solve_failures
    def agent_solve_problem(
        self,
        problem_id,
        requested_by,
        harness=None,
        endpoint_id=None,
        session_cookie="",
        session_cookie_name="session",
        endpoint_revision=None,
    ):
        task_id = str(
            getattr(getattr(self, "request", None), "id", None) or ""
        ).strip() or f"unknown-{int(time.time())}"
        terminal_result = existing_agent_terminal_result(task_id)
        if terminal_result is not None:
            return terminal_result
        state = {
            "task_id": task_id,
            "session_id": task_id,
            "problem_id": int(problem_id),
            "problem_title": "",
            "requested_by": requested_by,
            "task_kind": AGENT_TASK_SOLVE,
            "access_role": AGENT_ACCESS_ROLE_USER,
            "harness": str(harness or ""),
            "endpoint_id": endpoint_id,
            "status": "Running",
            "message": "解题 Agent 启动中",
            "best_score": 0,
            "latest_submission_id": None,
            "final_submission_id": None,
            "attempts": [],
            "title": "",
            "native_session_id": "",
            "conclusion": "",
            "stage": "starting",
            "harness_status": "pending",
            "updated_at": _format_local_time(),
        }
        prepare_agent_trace_dir(task_id)
        _update_agent_state(state)

        user = get_user_by_username(requested_by)
        if not user or int(user.get("is_admin") or 0) != 1:
            message = "无权限执行解题 Agent"
            _update_agent_state(state, message, status="Failed", stage="finished")
            return {"success": False, "message": message, "task_id": task_id}

        problem = get_problem(problem_id)
        if not problem:
            message = "题目不存在"
            _update_agent_state(state, message, status="Failed", stage="finished")
            return {"success": False, "message": message, "task_id": task_id}
        if int(problem.get("type") or 1) != 1:
            message = "仅支持编程题"
            _update_agent_state(state, message, status="Failed", stage="finished")
            return {"success": False, "message": message, "task_id": task_id}
        if not str(session_cookie or "").strip():
            persisted_session = get_agent_session(task_id)
            if not persisted_session or not (
                str(persisted_session.get("current_task_id") or "") == task_id
                and str(persisted_session.get("requested_by") or "")
                == str(requested_by or "")
                and str(persisted_session.get("access_role") or "").lower()
                == AGENT_ACCESS_ROLE_USER
                and str(persisted_session.get("task_kind") or "").lower()
                == AGENT_TASK_SOLVE
            ):
                message = "Agent 任务身份已失效"
                _update_agent_state(state, message, status="Failed", stage="finished")
                return {"success": False, "message": message, "task_id": task_id}

        try:
            endpoint = resolve_launch_endpoint(
                harness,
                endpoint_id,
                include_secret=True,
            )
            if endpoint_revision is not None:
                validate_launch_endpoint_revision(endpoint, endpoint_revision)
        except Exception as exc:
            message = str(exc) or "所选 LLM 节点不可用"
            _update_agent_state(state, message, status="Failed", stage="finished")
            return {"success": False, "message": message, "task_id": task_id}

        title = str(problem.get("title") or f"题目 {problem_id}")
        agent_prompt = build_solution_agent_prompt(
            problem_id=problem_id,
            problem_title=title,
        )
        session_title = generate_initial_agent_session_title(
            task_id,
            endpoint,
            agent_prompt,
            fallback=f"解题 {title}",
        )
        state.update({
            "problem_title": title,
            "title": session_title,
            "harness": str(harness),
            "endpoint_id": int(endpoint["id"]),
            "endpoint_model": str(endpoint.get("model") or ""),
        })
        _update_agent_state(
            state,
            f"正在用 {harness} / {endpoint.get('model')} 解题",
            stage="running_harness",
            harness_status="running",
        )

        if agent_run_is_canceled(task_id):
            return canceled_agent_task_result(task_id)
        control_source, control_callback = build_agent_control_bridge(
            task_id,
            task_id,
        )
        try:
            run_result = run_agent_harness(
                task_id=task_id,
                session_id=task_id,
                task_kind=AGENT_TASK_SOLVE,
                access_role=AGENT_ACCESS_ROLE_USER,
                problem_id=int(problem_id),
                requested_by=requested_by,
                harness=harness,
                endpoint=endpoint,
                session_cookie=session_cookie,
                session_cookie_name=session_cookie_name,
                prompt=agent_prompt,
                trace_callback=lambda: _publish_agent_trace(state),
                cancel_check=lambda: agent_run_is_canceled(task_id),
                control_source=control_source,
                control_callback=control_callback,
                control_target_task_id=task_id,
                reset_trace=False,
            )
        except AgentHarnessCleanupError as exc:
            conclusion = extract_agent_conclusion(task_id)
            state["conclusion"] = conclusion
            message = str(exc)
            _update_agent_state(
                state,
                message,
                status="CleanupFailed",
                stage="finished",
                harness_status="cleanup_failed",
            )
            return {"success": False, "message": message, "task_id": task_id}
        except Exception as exc:
            if agent_run_is_canceled(task_id):
                return canceled_agent_task_result(task_id)
            conclusion = extract_agent_conclusion(task_id)
            state["conclusion"] = conclusion
            message = f"解题 harness 启动失败：{str(exc)[:800]}"
            _update_agent_state(
                state,
                message,
                status="Failed",
                stage="finished",
                harness_status="error",
            )
            return {"success": False, "message": message, "task_id": task_id}

        if agent_run_is_canceled(task_id):
            return canceled_agent_task_result(task_id)

        conclusion = extract_agent_conclusion(task_id)
        state["native_session_id"] = str(run_result.native_session_id or "")
        state["conclusion"] = conclusion

        # 只认身份代理亲自转发创建的 submission，避免并发的人工提交被误判为
        # 本次 Agent 产物。
        rows = _created_submissions(
            requested_by,
            problem_id,
            run_result.created_submission_ids,
        )
        attempts = _submission_attempts(rows)
        accepted = _accepted_submission(rows)
        latest_id = max(
            (int(row.get("id") or 0) for row in rows),
            default=None,
        )
        state["attempts"] = attempts
        state["latest_submission_id"] = latest_id

        if not state["native_session_id"]:
            message = "解题 Agent 未记录可恢复的原生会话"
            if accepted is not None:
                message += "；提交虽已通过，但本任务不能继续会话"
            _update_agent_state(
                state,
                message,
                status="Failed",
                stage="finished",
                harness_status="error",
                final_submission_id=(
                    int(accepted.get("id") or 0)
                    if accepted is not None
                    else latest_id
                ),
                conclusion=conclusion or message,
            )
            return {
                "success": False,
                "message": message,
                "task_id": task_id,
                "final_submission_id": state.get("final_submission_id"),
                "attempts": attempts,
            }

        if accepted is not None:
            final_id = int(accepted.get("id") or 0)
            message = "解题 Agent 已提交并通过"
            _update_agent_state(
                state,
                message,
                status="Completed",
                stage="finished",
                harness_status=(
                    "error"
                    if run_result.timed_out or run_result.returncode != 0
                    else "completed"
                ),
                final_submission_id=final_id,
                native_session_id=state["native_session_id"],
                conclusion=conclusion or message,
            )
            return {
                "success": True,
                "message": message,
                "task_id": task_id,
                "final_submission_id": final_id,
                "attempts": attempts,
            }

        if run_result.timed_out:
            message = "解题 harness 超时，且没有产生通过的提交"
        elif run_result.returncode != 0:
            detail = (run_result.stderr or run_result.stdout).strip()[-800:]
            message = f"解题 harness 异常退出（{run_result.returncode}）"
            if detail:
                message += f"：{detail}"
        else:
            message = "解题 harness 已结束，但没有产生通过的提交"
        _update_agent_state(
            state,
            message,
            status="Failed",
            stage="finished",
            harness_status=(
                "timeout"
                if run_result.timed_out
                else "error" if run_result.returncode != 0 else "completed"
            ),
            final_submission_id=latest_id,
            native_session_id=state["native_session_id"],
            conclusion=conclusion or message,
        )
        return {
            "success": False,
            "message": message,
            "task_id": task_id,
            "final_submission_id": latest_id,
            "attempts": attempts,
        }

    return agent_solve_problem
