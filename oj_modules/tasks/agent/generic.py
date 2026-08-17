#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用 Agent 会话的单轮 Celery 任务。"""

from __future__ import annotations

from functools import wraps
import time

from oj_modules.agents.sessions import (
    AGENT_EMPTY_CONCLUSION_MESSAGE,
    get_agent_session,
    normalize_agent_session_id,
)
from oj_modules.agents.quota import (
    charge_agent_usage,
    get_agent_runtime_quota_summary,
    get_agent_session_usage_cost,
    require_agent_start_eligibility,
)
from oj_modules.db_services import get_user_by_username
from oj_modules.problems.agent_launch import (
    AGENT_TASK_CUSTOM,
    normalize_agent_access_role,
    normalize_agent_reasoning_effort,
    normalize_agent_task_kind,
    normalize_launch_harness,
    resolve_launch_endpoint,
    token_pricing_from_endpoint,
)
from oj_modules.site_config.services import (
    DEFAULT_LLM_CONTEXT_WINDOW_TOKENS,
    DEFAULT_LLM_MAX_OUTPUT_TOKENS,
    get_llm_endpoint,
)
from oj_modules.tasks.agent.conversation import extract_agent_conclusion
from oj_modules.tasks.agent.harness_runtime import (
    AgentHarnessCleanupError,
    AgentUsageHardStopError,
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
from oj_modules.tasks.agent.queue import build_agent_control_bridge


def _generic_task_id(task):
    return str(
        getattr(getattr(task, "request", None), "id", None) or ""
    ).strip() or f"unknown-{int(time.time())}"


def _initial_generic_state(
    task_id,
    *,
    session_id,
    requested_by,
    access_role,
    harness,
    endpoint_id,
):
    return {
        "task_id": task_id,
        "session_id": str(session_id or ""),
        "problem_id": None,
        "problem_title": "通用 Agent",
        "requested_by": requested_by,
        "task_kind": AGENT_TASK_CUSTOM,
        "access_role": str(access_role or ""),
        "harness": str(harness or ""),
        "reasoning_effort": "default",
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
    local_terminal = _local_terminal_result(state)
    if local_terminal is not None:
        return _terminal_result_with_session(state) or local_terminal
    return {
        "success": False,
        "message": message,
        "task_id": state["task_id"],
        "session_id": state["session_id"],
        "title": state.get("title") or "",
        "native_session_id": state.get("native_session_id") or "",
        "conclusion": str(conclusion or ""),
    }


def _terminal_result_with_session(state):
    try:
        result = existing_agent_terminal_result(state.get("task_id"))
    except Exception:
        return None
    if result is None:
        return None
    result = dict(result)
    result["session_id"] = str(state.get("session_id") or "")
    return result


def _local_terminal_result(state):
    status = str(state.get("status") or "").strip().lower()
    task_id = str(state.get("task_id") or "")
    session_id = str(state.get("session_id") or "")
    if status in {"canceled", "cancelled"}:
        result = canceled_agent_task_result(task_id)
        result["session_id"] = session_id
        return result
    if status in {"cleanupfailed", "cleanup_failed"}:
        return {
            "success": False,
            "cleanup_failed": True,
            "message": str(
                state.get("message")
                or "Agent 运行时清理失败，需管理员处理"
            ),
            "task_id": task_id,
            "session_id": session_id,
        }
    if status == "completed":
        return {
            "success": True,
            "message": str(state.get("message") or "任务已结束"),
            "task_id": task_id,
            "session_id": session_id,
            "title": str(state.get("title") or ""),
            "native_session_id": str(state.get("native_session_id") or ""),
            "conclusion": str(state.get("conclusion") or ""),
        }
    return None


def _finalize_unhandled_generic_failure(state, exc):
    """尽最大努力收束入口早期异常，同时尊重已经提交的终态。"""

    terminal_result = _terminal_result_with_session(state)
    if terminal_result is not None:
        return terminal_result
    local_terminal = _local_terminal_result(state)
    if local_terminal is not None:
        return local_terminal

    task_id = str(state.get("task_id") or "")
    try:
        if agent_run_is_canceled(task_id):
            result = canceled_agent_task_result(task_id)
            result["session_id"] = str(state.get("session_id") or "")
            return result
    except Exception:
        # DB 故障本身可能正是原始异常；后续失败写入仍会依赖持久层的
        # sticky 终态约束，不能因为取消态探测失败而放弃收束。
        pass

    detail = str(exc).strip() or exc.__class__.__name__
    message = f"通用 Agent worker 异常：{detail[:800]}"
    for _attempt in range(2):
        try:
            result = _generic_failure(state, message)
        except Exception:
            continue
        local_terminal = _local_terminal_result(state)
        if local_terminal is not None:
            return _terminal_result_with_session(state) or local_terminal
        return result

    # agent_task_runs 写入持续失败时，独立尝试以同一 CAS 契约收束会话和
    # 当前轮次。session 投影会拒绝旧轮次、已终态、取消态和清理失败态。
    state.update({
        "status": "Failed",
        "message": message,
        "stage": "finished",
        "harness_status": "error",
        "conclusion": "",
    })
    try:
        from oj_modules.agents.sessions import sync_agent_session_state

        sync_agent_session_state(state)
    except Exception:
        pass
    terminal_result = _terminal_result_with_session(state)
    if terminal_result is not None:
        return terminal_result
    return {
        "success": False,
        "message": message,
        "task_id": task_id,
        "session_id": str(state.get("session_id") or ""),
        "title": str(state.get("title") or ""),
        "native_session_id": str(state.get("native_session_id") or ""),
        "conclusion": "",
    }


def _conclude_unhandled_generic_failures(function):
    @wraps(function)
    def wrapped(
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
        restore_runtime_checkpoint_id="",
        start_fresh_native_session=False,
    ):
        task_id = _generic_task_id(self)
        state = _initial_generic_state(
            task_id,
            session_id=session_id,
            requested_by=requested_by,
            access_role=access_role,
            harness=harness,
            endpoint_id=endpoint_id,
        )
        try:
            return function(
                self,
                session_id,
                requested_by,
                access_role,
                harness,
                endpoint_id,
                session_cookie,
                prompt,
                session_cookie_name,
                resume_session_id,
                generate_title,
                restore_runtime_checkpoint_id,
                start_fresh_native_session,
            )
        except Exception as exc:
            return _finalize_unhandled_generic_failure(state, exc)

    return wrapped


def _validate_frozen_session(
    session,
    *,
    task_id,
    access_role,
    harness,
    endpoint_id,
    resume_session_id,
    allow_empty_resume=False,
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
    if (
        int(session.get("turn_count") or 1) > 1
        and not frozen_native_id
        and not bool(allow_empty_resume)
    ):
        raise ValueError("上一轮未记录可恢复的原生会话，无法继续")
    return session_task_kind


def register_agent_run_turn_task(celery_app):
    existing = celery_app.tasks.get(AGENT_RUN_TURN_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(bind=True, name=AGENT_RUN_TURN_TASK_NAME)
    @_conclude_unhandled_generic_failures
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
        restore_runtime_checkpoint_id="",
        start_fresh_native_session=False,
    ):
        task_id = _generic_task_id(self)
        terminal_result = existing_agent_terminal_result(task_id)
        if terminal_result is not None:
            terminal_result["session_id"] = str(session_id or "")
            return terminal_result

        state = _initial_generic_state(
            task_id,
            session_id=session_id,
            requested_by=requested_by,
            access_role=access_role,
            harness=harness,
            endpoint_id=endpoint_id,
        )
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
        if not user:
            return _generic_failure(state, "无权限执行通用 Agent")
        requester_is_admin = int(user.get("is_admin") or 0) == 1
        if normalized_role == "admin" and not requester_is_admin:
            return _generic_failure(state, "普通用户不能使用管理员身份运行 Agent")
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
                allow_empty_resume=bool(
                    str(restore_runtime_checkpoint_id or "").strip()
                ) or start_fresh_native_session is True,
            )
            normalized_role = normalize_agent_access_role(
                normalized_role,
                task_kind=session_task_kind,
            )
            normalized_reasoning_effort = normalize_agent_reasoning_effort(
                session.get("reasoning_effort"),
                normalized_harness,
            )
        except Exception as exc:
            return _generic_failure(state, str(exc) or "Agent 会话状态无效")
        state["native_session_id"] = normalized_resume_session_id
        state["reasoning_effort"] = normalized_reasoning_effort

        endpoint_source = str(
            session.get("endpoint_source") or "global"
        ).strip().lower()
        uses_personal_endpoint = endpoint_source == "user"
        if endpoint_source not in {"global", "user"}:
            return _generic_failure(state, "Agent 会话模型节点来源无效")
        try:
            require_agent_start_eligibility(
                user["id"],
                is_admin=requester_is_admin,
                uses_personal_endpoint=uses_personal_endpoint,
            )
        except Exception as exc:
            return _generic_failure(state, str(exc) or "当前不能继续 Agent 会话")

        try:
            endpoint_ref = (
                f"user:{int(endpoint_id)}"
                if uses_personal_endpoint
                else endpoint_id
            )
            resolve_kwargs = {"include_secret": True}
            if uses_personal_endpoint:
                resolve_kwargs["user_id"] = user["id"]
            endpoint = resolve_launch_endpoint(
                normalized_harness,
                endpoint_ref,
                **resolve_kwargs,
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
                prompt,
            )
        # 标题使用站点免费链路，最多可能等待两个节点。
        # 真正启动 harness 前再读一次开关与余额，避免等待
        # 期间状态变更后仍发起新的模型请求。
        try:
            require_agent_start_eligibility(
                user["id"],
                is_admin=requester_is_admin,
                uses_personal_endpoint=uses_personal_endpoint,
            )
        except Exception as exc:
            return _generic_failure(
                state,
                str(exc) or "当前不能继续 Agent 会话",
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
            "endpoint_source": endpoint_source,
            "endpoint_model": str(endpoint.get("model") or ""),
            "context_window_tokens": int(
                endpoint.get("context_window_tokens")
                or DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
            ),
            "max_output_tokens": int(
                endpoint.get("max_output_tokens")
                or DEFAULT_LLM_MAX_OUTPUT_TOKENS
            ),
            "reasoning_effort": normalized_reasoning_effort,
        })
        _update_agent_state(
            state,
            f"正在用 {normalized_harness} / {endpoint.get('model')} 工作",
            stage="running_harness",
            harness_status="running",
        )

        if agent_run_is_canceled(task_id):
            return canceled_agent_task_result(task_id)
        control_source, control_callback = build_agent_control_bridge(
            normalized_session_id,
            task_id,
            eligibility_check=lambda: require_agent_start_eligibility(
                user["id"],
                is_admin=requester_is_admin,
                uses_personal_endpoint=uses_personal_endpoint,
            ).get("allowed", False),
        )
        usage_callback = None
        if not uses_personal_endpoint:
            pricing = token_pricing_from_endpoint(endpoint)
            if pricing is None:
                return _generic_failure(state, "所选全站节点尚未配置完整价格")
            try:
                state["session_charged_amount_rmb"] = (
                    get_agent_session_usage_cost(normalized_session_id) or "0"
                )
            except Exception:
                # 计费账本仍是权威数据；这里仅为实时页面准备一个历史基线。
                # 读取失败时不阻断 harness，后续状态接口会再次从账本恢复。
                pass

            def charge_usage(event):
                # 每个上游请求都重新读取节点价格：峰谷切换和管理员调整价格无需
                # 中断已有会话，账本会保留当次实际采用的配置版本和价格快照。
                current_endpoint = get_llm_endpoint(
                    endpoint["id"], include_secret=False,
                )
                current_pricing = token_pricing_from_endpoint(current_endpoint)
                if current_pricing is None:
                    raise RuntimeError("所选全站节点尚未配置完整价格")
                result = charge_agent_usage(
                    user_id=user["id"],
                    session_id=normalized_session_id,
                    task_id=task_id,
                    source=event.get("source"),
                    usage_event_id=event.get("id"),
                    endpoint_id=current_endpoint["id"],
                    # 会话不再冻结节点配置：本轮使用当前端点，并把其版本和
                    # 价格快照写入逐请求账本，保留审计能力。
                    endpoint_revision=current_endpoint.get("revision"),
                    endpoint_model=current_endpoint.get("model"),
                    usage=event.get("usage"),
                    pricing=current_pricing,
                    is_admin=requester_is_admin,
                )
                try:
                    state["session_charged_amount_rmb"] = (
                        get_agent_session_usage_cost(normalized_session_id)
                    )
                    state["quota_summary"] = get_agent_runtime_quota_summary(
                        user["id"]
                    )
                    _publish_agent_trace(state)
                except Exception:
                    # 账本事务已经提交后，额度摘要/Redis 只是界面旁路。
                    # 发布失败不能把已扣费的正常请求误判成记账失败并杀掉任务；
                    # 后续状态读取会直接从额度账户恢复最新余额。
                    pass
                return {
                    **result,
                    "remaining_rmb": result.get("remaining_amount"),
                }

            usage_callback = charge_usage
        try:
            run_result = run_agent_harness(
                task_id=task_id,
                session_id=normalized_session_id,
                task_kind=session_task_kind,
                access_role=normalized_role,
                problem_id=session.get("problem_id"),
                requested_by=requested_by,
                harness=normalized_harness,
                reasoning_effort=normalized_reasoning_effort,
                endpoint=endpoint,
                session_cookie=session_cookie,
                session_cookie_name=session_cookie_name,
                prompt=prompt,
                resume_session_id=normalized_resume_session_id,
                restore_runtime_checkpoint_id=(
                    str(restore_runtime_checkpoint_id or "").strip()
                ),
                trace_callback=lambda: _publish_agent_trace(state),
                cancel_check=lambda: agent_run_is_canceled(task_id),
                control_source=control_source,
                control_callback=control_callback,
                control_target_task_id=task_id,
                usage_callback=usage_callback,
                reset_trace=False,
            )
        except AgentUsageHardStopError:
            conclusion = extract_agent_conclusion(task_id)
            state["conclusion"] = conclusion
            return _generic_failure(
                state,
                "额度耗尽：余额已达到 -5 元，系统已自动停止任务",
                harness_status="quota_exhausted",
                conclusion=conclusion,
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
                AGENT_EMPTY_CONCLUSION_MESSAGE,
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
