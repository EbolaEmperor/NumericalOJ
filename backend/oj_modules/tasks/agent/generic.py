#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用 Agent 会话的单轮 Celery 任务。"""

from __future__ import annotations

from functools import wraps
import time

from celery.exceptions import Retry

from backend.oj_modules.agents.sessions import (
    AGENT_EMPTY_CONCLUSION_MESSAGE,
    get_agent_session,
    get_agent_session_runtime_config,
    normalize_agent_session_id,
)
from backend.oj_modules.agents.judge import resolve_judge_endpoint, judge_endpoint_pricing
from backend.oj_modules.agents.quota import (
    AgentQuotaAccessDeniedError,
    charge_agent_usage,
    get_agent_runtime_quota_summary,
    get_agent_session_usage_cost,
    require_agent_start_eligibility,
)
from backend.oj_modules.db_services import get_user_by_username
from backend.oj_modules.problems.agent_launch import (
    AGENT_TASK_CUSTOM,
    normalize_agent_access_role,
    normalize_agent_reasoning_effort,
    normalize_agent_task_kind,
    normalize_launch_harness,
    resolve_launch_endpoint,
    token_pricing_from_endpoint,
)
from backend.oj_modules.site_config.services import (
    DEFAULT_LLM_CONTEXT_WINDOW_TOKENS,
    DEFAULT_LLM_MAX_OUTPUT_TOKENS,
    DynamicConfigNotFoundError,
    get_llm_endpoint,
)
from backend.oj_modules.tasks.agent.conversation import extract_agent_conclusion
from backend.oj_modules.tasks.agent.harness_runtime import (
    AgentHarnessCleanupError,
    AgentUsageHardStopError,
    extract_harness_failure_detail,
    normalize_native_session_id,
    read_agent_native_session_id,
    run_agent_harness,
)
from backend.oj_modules.tasks.agent.shared import (
    AGENT_RUN_TURN_TASK_NAME,
    _format_local_time,
    _persist_agent_trace_records,
    _publish_agent_trace,
    _update_agent_state,
    agent_run_is_canceled,
    canceled_agent_task_result,
    existing_agent_terminal_result,
    publish_agent_run_snapshot,
)
from backend.oj_modules.tasks.agent.titles import generate_initial_agent_session_title
from backend.oj_modules.tasks.agent.traces import prepare_agent_trace_dir
from backend.oj_modules.tasks.agent.queue import build_agent_control_bridge
from backend.oj_modules.tasks.agent.usage_accounting import (
    ResilientAgentUsageAccountant,
)


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

    try:
        recovered_native_session_id = read_agent_native_session_id(
            state.get("session_id"),
            state.get("harness"),
        )
    except Exception:
        recovered_native_session_id = ""
    if recovered_native_session_id:
        state["native_session_id"] = recovered_native_session_id
        try:
            # 即使取消/失败终态已经先提交，会话投影仍允许同一 current task
            # 只补齐原生恢复点，不会重开或改写终态。
            _update_agent_state(
                state,
                native_session_id=recovered_native_session_id,
            )
        except Exception:
            pass

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
        from backend.oj_modules.agents.sessions import sync_agent_session_state

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
        except Retry:
            # 计费基础设施暂不可用时保持当前轮次非终态，让 Celery 原 task_id
            # 继续退避重试，而不是被通用异常收束误写成 Failed。
            raise
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

    @celery_app.task(bind=True, name=AGENT_RUN_TURN_TASK_NAME, max_retries=None)
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
        if start_fresh_native_session is True:
            return _generic_failure(
                state,
                "续聊不允许丢弃上一轮原生会话后重新开始",
            )

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
                ),
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
        site_funded = session_task_kind == "judge"
        runtime_config = (
            get_agent_session_runtime_config(normalized_session_id, task_id)
            if site_funded else {}
        )
        if runtime_config.get("historical_import"):
            return _generic_failure(state, "历史迁入会话不可执行")
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
                is_admin=requester_is_admin or site_funded,
                uses_personal_endpoint=uses_personal_endpoint,
            )
        except AgentQuotaAccessDeniedError as exc:
            return _generic_failure(state, str(exc) or "当前不能继续 Agent 会话")
        except Exception as exc:
            try:
                _update_agent_state(
                    state,
                    "额度服务暂不可用，正在自动重试启动",
                    stage="waiting_billing",
                    harness_status="pending",
                )
            except Exception:
                pass
            raise self.retry(exc=exc, countdown=5)

        try:
            endpoint_ref = (
                f"user:{int(endpoint_id)}"
                if uses_personal_endpoint
                else endpoint_id
            )
            resolve_kwargs = {"include_secret": True}
            if uses_personal_endpoint:
                resolve_kwargs["user_id"] = user["id"]
            endpoint = (
                resolve_judge_endpoint(session) if site_funded else
                resolve_launch_endpoint(normalized_harness, endpoint_ref, **resolve_kwargs)
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
                is_admin=requester_is_admin or site_funded,
                uses_personal_endpoint=uses_personal_endpoint,
            )
        except AgentQuotaAccessDeniedError as exc:
            return _generic_failure(
                state,
                str(exc) or "当前不能继续 Agent 会话",
            )
        except Exception as exc:
            try:
                _update_agent_state(
                    state,
                    "额度服务暂不可用，正在自动重试启动",
                    stage="waiting_billing",
                    harness_status="pending",
                )
            except Exception:
                pass
            raise self.retry(exc=exc, countdown=5)
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
                is_admin=requester_is_admin or site_funded,
                uses_personal_endpoint=uses_personal_endpoint,
            ).get("allowed", False),
        )
        usage_callback = None
        usage_accountant = None
        if not uses_personal_endpoint:
            judge_pricing = judge_endpoint_pricing(endpoint) if site_funded else None
            pricing = judge_pricing["pricing"] if judge_pricing else token_pricing_from_endpoint(endpoint)
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

            def current_endpoint_snapshot():
                if site_funded:
                    return judge_endpoint_pricing(resolve_judge_endpoint(session))
                # 每个上游请求都尝试读取当前价格；读取失败时容错计费器会沿用
                # 上一份完整快照，不能让动态配置服务故障中断正在运行的任务。
                try:
                    current_endpoint = get_llm_endpoint(
                        endpoint["id"], include_secret=False,
                    )
                except DynamicConfigNotFoundError:
                    return {
                        "endpoint_id": None,
                        "endpoint_revision": endpoint.get("revision"),
                        "endpoint_model": endpoint.get("model"),
                        "pricing": pricing,
                    }
                current_pricing = token_pricing_from_endpoint(current_endpoint)
                if current_pricing is None:
                    raise RuntimeError("所选全站节点尚未配置完整价格")
                return {
                    "endpoint_id": current_endpoint["id"],
                    "endpoint_revision": current_endpoint.get("revision"),
                    "endpoint_model": current_endpoint.get("model"),
                    "pricing": current_pricing,
                }

            def refresh_usage_projection(result):
                try:
                    billing_revision = int(
                        (result or {}).get("billing_revision") or 0
                    )
                except (TypeError, ValueError):
                    billing_revision = 0
                if billing_revision > 0:
                    state["billing_revision"] = max(
                        int(state.get("billing_revision") or 0),
                        billing_revision,
                    )
                try:
                    state["session_charged_amount_rmb"] = (
                        get_agent_session_usage_cost(normalized_session_id)
                    )
                    state["quota_summary"] = get_agent_runtime_quota_summary(
                        user["id"]
                    )
                except Exception:
                    # 账本事务已经提交后，额度摘要只是界面旁路。刷新失败不能
                    # 把已扣费的正常请求误判成记账失败并杀掉任务；后续状态读取
                    # 会直接从额度账户恢复最新余额。
                    pass
                # 每个 Claude 主请求和 subagent 请求都独立经过 relay 结算。
                # 结算成功即发布一次 run 快照，让 COST/余额立即更新；规范轨迹
                # 随后的 tick 再补齐 token 与工作块，两者都保持请求级而非
                # token 级更新。发布异常由共享层按缓存旁路语义吞掉。
                publish_agent_run_snapshot(state)

            usage_accountant = ResilientAgentUsageAccountant(
                user_id=user["id"],
                session_id=normalized_session_id,
                task_id=task_id,
                endpoint_snapshot={
                    "endpoint_id": judge_pricing["endpoint_id"] if judge_pricing else endpoint["id"],
                    "endpoint_revision": judge_pricing["endpoint_revision"] if judge_pricing else endpoint.get("revision"),
                    "endpoint_model": endpoint.get("model"),
                    "pricing": pricing,
                },
                is_admin=requester_is_admin,
                **({"site_funded": True} if site_funded else {}),
                endpoint_snapshot_loader=current_endpoint_snapshot,
                charge_usage=charge_agent_usage,
                on_settled=refresh_usage_projection,
            )
            usage_callback = usage_accountant

        def preserve_native_session(native_session_id):
            normalized_native_session_id = normalize_native_session_id(
                native_session_id,
                normalized_harness,
            )
            if (
                not normalized_native_session_id
                or normalized_native_session_id
                == state.get("native_session_id")
            ):
                return
            # 先更新内存 state；即使这次 MySQL 写入失败，随后异常收束也会
            # 携带同一恢复点再次持久化，而不是回退为空 session。
            state["native_session_id"] = normalized_native_session_id
            _update_agent_state(
                state,
                native_session_id=normalized_native_session_id,
            )

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
                trace_records_callback=lambda records, final=False: (
                    _persist_agent_trace_records(
                        state,
                        records,
                        final=final,
                    )
                ),
                cancel_check=lambda: agent_run_is_canceled(task_id),
                control_source=control_source,
                control_callback=control_callback,
                control_target_task_id=task_id,
                usage_callback=usage_callback,
                native_session_callback=preserve_native_session,
                reset_trace=False,
                **({
                    "timeout_seconds": runtime_config.get("timeout_seconds"),
                    "enable_site_identity": False,
                } if site_funded else {}),
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
        finally:
            if usage_accountant is not None:
                # 待结算事件已经进入宿主持久 outbox；关闭轮内短退避线程不会
                # 删除记录，周期恢复任务会在进程退出或部署后继续幂等重放。
                usage_accountant.close()

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
            detail = extract_harness_failure_detail(run_result, max_chars=800)
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
