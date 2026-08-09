#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用 Agent 会话的单轮 Celery 任务。"""

from __future__ import annotations

import time

from oj_modules.agents.sessions import (
    get_agent_session,
    normalize_agent_session_id,
)
from oj_modules.db_services import get_user_by_username
from oj_modules.problems.agent_launch import (
    AGENT_TASK_CUSTOM,
    normalize_agent_access_role,
    normalize_agent_task_kind,
    normalize_launch_harness,
    resolve_launch_endpoint,
    validate_launch_endpoint_revision,
)
from oj_modules.tasks.agent.conversation import extract_agent_conclusion
from oj_modules.tasks.agent.harness_runtime import (
    AgentHarnessCleanupError,
    normalize_native_session_id,
    run_agent_harness,
)
from oj_modules.tasks.agent.shared import (
    AGENT_RUN_TURN_TASK_NAME,
    _format_local_time,
    _publish_agent_trace,
    _update_agent_state,
    agent_run_is_canceled,
    canceled_agent_task_result,
    existing_agent_terminal_result,
)
from oj_modules.tasks.agent.titles import generate_initial_agent_session_title
from oj_modules.tasks.agent.traces import prepare_agent_trace_dir


def _generic_failure(
    state,
    message,
    *,
    status="Failed",
    harness_status="error",
    conclusion="",
):
    _update_agent_state(
        state,
        message,
        status=status,
        stage="finished",
        harness_status=harness_status,
        conclusion=str(conclusion or ""),
    )
    return {
        "success": False,
        "message": message,
        "task_id": state["task_id"],
        "session_id": state["session_id"],
        "title": state.get("title") or "",
        "native_session_id": state.get("native_session_id") or "",
        "conclusion": str(conclusion or ""),
    }


def _validate_frozen_session(
    session,
    *,
    task_id,
    access_role,
    harness,
    endpoint_id,
    resume_session_id,
):
    if not isinstance(session, dict) or session.get("is_legacy"):
        raise ValueError("Agent 会话不存在或不支持续聊")
    session_task_kind = normalize_agent_task_kind(session.get("task_kind"))
    if str(session.get("current_task_id") or "").strip() != task_id:
        raise ValueError("Agent 会话当前轮次与任务不一致")
    frozen_role = normalize_agent_access_role(
        session.get("access_role"),
        task_kind=session_task_kind,
    )
    requested_role = normalize_agent_access_role(
        access_role,
        task_kind=session_task_kind,
    )
    if frozen_role != requested_role:
        raise ValueError("Agent 会话执行身份不可更换")
    if normalize_launch_harness(session.get("harness")) != harness:
        raise ValueError("Agent 会话 harness 不可更换")
    try:
        frozen_endpoint_id = int(session.get("endpoint_id"))
        requested_endpoint_id = int(endpoint_id)
    except (TypeError, ValueError):
        raise ValueError("Agent 会话模型节点无效") from None
    if frozen_endpoint_id != requested_endpoint_id:
        raise ValueError("Agent 会话模型节点不可更换")
    frozen_native_id = normalize_native_session_id(
        session.get("native_session_id"),
        harness,
    )
    requested_native_id = normalize_native_session_id(
        resume_session_id,
        harness,
    )
    if frozen_native_id != requested_native_id:
        raise ValueError("Agent 会话恢复点已变化，请刷新后重试")
    if int(session.get("turn_count") or 1) > 1 and not frozen_native_id:
        raise ValueError("上一轮未记录可恢复的原生会话，无法继续")
    return session_task_kind


def register_agent_run_turn_task(celery_app):
    existing = celery_app.tasks.get(AGENT_RUN_TURN_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(bind=True, name=AGENT_RUN_TURN_TASK_NAME)
    def agent_run_turn(
        self,
        session_id,
        requested_by,
        access_role,
        harness,
        endpoint_id,
        session_cookie,
        prompt,
        session_cookie_name="session",
        resume_session_id="",
        generate_title=False,
    ):
        task_id = str(
            getattr(getattr(self, "request", None), "id", None) or ""
        ).strip() or f"unknown-{int(time.time())}"
        terminal_result = existing_agent_terminal_result(task_id)
        if terminal_result is not None:
            terminal_result["session_id"] = str(session_id or "")
            return terminal_result

        state = {
            "task_id": task_id,
            "session_id": str(session_id or ""),
            "problem_id": None,
            "problem_title": "通用 Agent",
            "requested_by": requested_by,
            "task_kind": AGENT_TASK_CUSTOM,
            "access_role": str(access_role or ""),
            "harness": str(harness or ""),
            "endpoint_id": endpoint_id,
            "status": "Running",
            "message": "通用 Agent 启动中",
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

        try:
            normalized_session_id = normalize_agent_session_id(session_id)
            normalized_role = normalize_agent_access_role(
                access_role,
                task_kind=AGENT_TASK_CUSTOM,
            )
            normalized_harness = normalize_launch_harness(harness)
            normalized_resume_session_id = normalize_native_session_id(
                resume_session_id,
                normalized_harness,
            )
        except ValueError as exc:
            return _generic_failure(state, str(exc))
        state["session_id"] = normalized_session_id
        state["access_role"] = normalized_role
        state["harness"] = normalized_harness

        user = get_user_by_username(requested_by)
        if not user or int(user.get("is_admin") or 0) != 1:
            return _generic_failure(state, "无权限执行通用 Agent")
        if not str(session_cookie or "").strip():
            return _generic_failure(state, "Agent 任务身份已失效")
        if not str(prompt or "").strip():
            return _generic_failure(state, "Agent 消息不能为空")

        try:
            session = get_agent_session(normalized_session_id)
            session_task_kind = _validate_frozen_session(
                session,
                task_id=task_id,
                access_role=normalized_role,
                harness=normalized_harness,
                endpoint_id=endpoint_id,
                resume_session_id=normalized_resume_session_id,
            )
            normalized_role = normalize_agent_access_role(
                normalized_role,
                task_kind=session_task_kind,
            )
        except Exception as exc:
            return _generic_failure(state, str(exc) or "Agent 会话状态无效")
        state["native_session_id"] = normalized_resume_session_id

        try:
            # 本轮只解析一次端点；标题调用与 harness 共用同一冻结映射。
            endpoint = resolve_launch_endpoint(
                normalized_harness,
                endpoint_id,
                include_secret=True,
            )
            validate_launch_endpoint_revision(
                endpoint,
                session.get("endpoint_revision"),
            )
        except Exception as exc:
            return _generic_failure(
                state,
                str(exc) or "所选 LLM 节点不可用",
            )

        title = str(session.get("title") or "").strip()
        if bool(generate_title) and not title:
            title = generate_initial_agent_session_title(
                normalized_session_id,
                endpoint,
                prompt,
                fallback=prompt,
            )
        state.update({
            "task_kind": session_task_kind,
            "access_role": normalized_role,
            "problem_id": session.get("problem_id"),
            "title": title,
            "problem_title": (
                str(session.get("problem_title") or "").strip()
                or title
                or "通用 Agent"
            ),
            "endpoint_id": int(endpoint["id"]),
            "endpoint_model": str(endpoint.get("model") or ""),
        })
        _update_agent_state(
            state,
            f"正在用 {normalized_harness} / {endpoint.get('model')} 工作",
            stage="running_harness",
            harness_status="running",
        )

        if agent_run_is_canceled(task_id):
            return canceled_agent_task_result(task_id)
        try:
            run_result = run_agent_harness(
                task_id=task_id,
                session_id=normalized_session_id,
                task_kind=session_task_kind,
                access_role=normalized_role,
                problem_id=session.get("problem_id"),
                requested_by=requested_by,
                harness=normalized_harness,
                endpoint=endpoint,
                session_cookie=session_cookie,
                session_cookie_name=session_cookie_name,
                prompt=prompt,
                resume_session_id=normalized_resume_session_id,
                trace_callback=lambda: _publish_agent_trace(state),
                cancel_check=lambda: agent_run_is_canceled(task_id),
                reset_trace=False,
            )
        except AgentHarnessCleanupError as exc:
            conclusion = extract_agent_conclusion(task_id)
            state["conclusion"] = conclusion
            return _generic_failure(
                state,
                str(exc),
                status="CleanupFailed",
                harness_status="cleanup_failed",
                conclusion=conclusion,
            )
        except Exception as exc:
            if agent_run_is_canceled(task_id):
                return canceled_agent_task_result(task_id)
            conclusion = extract_agent_conclusion(task_id)
            state["conclusion"] = conclusion
            return _generic_failure(
                state,
                f"Agent harness 运行失败：{str(exc)[:800]}",
                conclusion=conclusion,
            )

        if agent_run_is_canceled(task_id):
            return canceled_agent_task_result(task_id)

        native_session_id = str(
            run_result.native_session_id or normalized_resume_session_id or ""
        ).strip()
        conclusion = extract_agent_conclusion(task_id)
        state["native_session_id"] = native_session_id
        state["conclusion"] = conclusion
        if run_result.timed_out:
            return _generic_failure(
                state,
                "Agent harness 超时",
                harness_status="timeout",
                conclusion=conclusion,
            )
        if run_result.returncode != 0:
            detail = (run_result.stderr or run_result.stdout).strip()[-800:]
            message = f"Agent harness 异常退出（{run_result.returncode}）"
            if detail:
                message += f"：{detail}"
            return _generic_failure(
                state,
                message,
                conclusion=conclusion,
            )
        if not native_session_id:
            return _generic_failure(
                state,
                "Agent 未记录可恢复的原生会话",
                conclusion=conclusion,
            )
        if not conclusion:
            return _generic_failure(
                state,
                "Agent 已结束，但没有返回可展示的结论",
            )

        message = "Agent 已完成本轮任务"
        _update_agent_state(
            state,
            message,
            status="Completed",
            stage="finished",
            harness_status="completed",
            native_session_id=native_session_id,
            conclusion=conclusion,
        )
        return {
            "success": True,
            "message": message,
            "task_id": task_id,
            "session_id": normalized_session_id,
            "title": title,
            "native_session_id": native_session_id,
            "conclusion": conclusion,
        }

    return agent_run_turn


__all__ = ["register_agent_run_turn_task"]
