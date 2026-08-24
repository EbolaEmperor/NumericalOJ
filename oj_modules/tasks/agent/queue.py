#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用 Agent 持久消息队列的 Celery 调度与 harness 控制桥。"""

from __future__ import annotations

import logging

from oj_modules.agents.quota import check_agent_start_eligibility
from oj_modules.agents.messages import (
    AgentSessionMessageConflictError,
    AgentSessionMessageNotFoundError,
    claim_next_agent_session_message,
    claim_next_agent_session_steer,
    finish_agent_session_message_delivery,
    list_agent_session_queue_recovery_candidates,
    mark_agent_session_message_broker_enqueued,
    release_agent_session_message_dispatch_attempt,
)
from oj_modules.agents.runtime_checkpoints import (
    create_agent_runtime_checkpoint,
    remove_agent_runtime_checkpoint,
)
from oj_modules.db_services import get_user_by_username, upsert_agent_run_snapshot


AGENT_QUEUE_DISPATCH_TASK_NAME = "oj.agent.dispatch_session_queue"
AGENT_QUEUE_RECOVERY_TASK_NAME = "oj.agent.recover_session_queues"

logger = logging.getLogger(__name__)


def prompt_with_agent_attachments(message, attachments):
    """把持久附件位置追加到消息；不复制或移动 workspace 文件。"""

    paths = [
        str(item.get("path") or "").strip()
        for item in attachments or ()
        if isinstance(item, dict) and str(item.get("path") or "").strip()
    ]
    if not paths:
        return str(message or "").strip()
    listing = "\n".join(f"- /workspace/{path}" for path in paths)
    return (
        f"{str(message or '').strip()}\n\n"
        "用户随本条消息上传了以下附件，文件已经放入 workspace。"
        "请在需要时直接读取：\n"
        f"{listing}"
    )


def build_agent_control_bridge(session_id, task_id, *, eligibility_check=None):
    """返回供 harness runtime 轮询的一次一条插话源和确认回调。"""

    normalized_session_id = str(session_id or "").strip()
    normalized_task_id = str(task_id or "").strip()

    def control_source():
        try:
            claim_kwargs = {"task_id": normalized_task_id}
            if callable(eligibility_check):
                claim_kwargs["dispatch_allowed"] = eligibility_check
            message = claim_next_agent_session_steer(
                normalized_session_id,
                **claim_kwargs,
            )
        except (AgentSessionMessageConflictError, AgentSessionMessageNotFoundError):
            return ()
        except Exception:
            logger.exception(
                "领取 Agent 插话失败",
                extra={
                    "session_id": normalized_session_id,
                    "task_id": normalized_task_id,
                },
            )
            return ()
        if not message:
            return ()
        return ({
            "id": message["message_id"],
            "type": "steer",
            "target_task_id": normalized_task_id,
            "message": prompt_with_agent_attachments(
                message.get("user_message"),
                message.get("attachments"),
            ),
        },)

    def control_callback(command_id, status, error=""):
        normalized_id = str(command_id or "").strip()
        if not normalized_id or normalized_id.startswith("__"):
            return
        normalized_status = str(status or "").strip().lower()
        if normalized_status == "accepted":
            normalized_status = "sent"
        if normalized_status == "rejected":
            normalized_status = "failed"
        if normalized_status not in {"sent", "failed", "unknown"}:
            return
        try:
            finish_agent_session_message_delivery(
                normalized_id,
                status=normalized_status,
                task_id=normalized_task_id,
                error_message=str(error or ""),
            )
        except (AgentSessionMessageConflictError, AgentSessionMessageNotFoundError):
            return
        except Exception:
            logger.exception(
                "更新 Agent 插话投递状态失败",
                extra={
                    "message_id": normalized_id,
                    "task_id": normalized_task_id,
                    "delivery_status": normalized_status,
                },
            )

    return control_source, control_callback


def _session_dispatch_allowed(session):
    """在队首升格为 turn 之前做一次实时额度门禁。"""

    requested_by = str((session or {}).get("requested_by") or "").strip()
    user = get_user_by_username(requested_by) if requested_by else None
    if not user:
        return False
    requester_is_admin = int(user.get("is_admin") or 0) == 1
    # 升级前已入队的旧版造数据任务是 user role，但本质上
    # 是管理员操作；保留其原有派发语义。
    legacy_testdata = (
        str((session or {}).get("task_kind") or "").strip().lower() == "testdata"
        and str((session or {}).get("access_role") or "user").strip().lower()
        == "user"
    )
    if legacy_testdata:
        return True
    decision = check_agent_start_eligibility(
        user["id"],
        is_admin=requester_is_admin,
        uses_personal_endpoint=(
            str((session or {}).get("endpoint_source") or "global")
            .strip()
            .lower()
            == "user"
        ),
    )
    return bool(decision.get("allowed"))


def _pending_state(claim):
    return {
        "task_id": claim["task_id"],
        "session_id": claim["session_id"],
        "problem_id": claim.get("problem_id"),
        "problem_title": "通用 Agent",
        "requested_by": claim.get("requested_by"),
        "task_kind": claim.get("task_kind") or "custom",
        "access_role": claim.get("access_role") or "user",
        "harness": claim.get("harness"),
        "reasoning_effort": claim.get("reasoning_effort") or "default",
        "endpoint_id": claim.get("endpoint_id"),
        "endpoint_model": claim.get("endpoint_model"),
        "status": "Pending",
        "message": "任务排队中",
        "best_score": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "native_session_id": claim.get("native_session_id") or "",
    }


def register_agent_queue_tasks(
    celery_app,
    agent_run_turn_task,
    *,
    agent_solve_problem_task=None,
    agent_generate_testdata_task=None,
):
    """注册 FIFO 调度与崩溃窗口恢复任务。

    解题与新版造数据按钮创建的首轮消息和后续聊天一样，统一交给普通
    会话 worker。专用造数据 task 只接管升级前已经持久化、源码仍放在
    dispatch_payload 中的队首，避免部署时丢失尚未派发的数据。
    """

    dispatch_existing = celery_app.tasks.get(AGENT_QUEUE_DISPATCH_TASK_NAME)
    recovery_existing = celery_app.tasks.get(AGENT_QUEUE_RECOVERY_TASK_NAME)
    if dispatch_existing and recovery_existing:
        return dispatch_existing, recovery_existing

    if dispatch_existing:
        dispatch_agent_session_queue = dispatch_existing
    else:

        @celery_app.task(bind=True, name=AGENT_QUEUE_DISPATCH_TASK_NAME, max_retries=5)
        def dispatch_agent_session_queue(self, session_id):
            try:
                claim = claim_next_agent_session_message(
                    str(session_id or ""),
                    prepare_runtime_checkpoint=create_agent_runtime_checkpoint,
                    dispatch_allowed=_session_dispatch_allowed,
                )
            except Exception as exc:
                # checkpoint 发布、DB claim 或连接故障都不能把仍在 MySQL
                # 的队首变成一次性失败；同一调度任务先短退避，周期恢复仍
                # 作为超过 Celery retry 窗口后的兜底。
                raise self.retry(exc=exc, countdown=5)
            if not claim:
                return {"success": True, "dispatched": False}
            task_id = str(claim["task_id"])
            dispatch_attempt_id = str(
                claim.get("dispatch_attempt_id") or ""
            ).strip()
            if not dispatch_attempt_id:
                raise RuntimeError("Agent 消息缺少派发租约")
            if bool(claim.get("newly_promoted")):
                previous_checkpoint_id = str(
                    claim.get("previous_base_runtime_checkpoint_id") or ""
                ).strip()
                current_checkpoint_id = str(
                    claim.get("base_runtime_checkpoint_id") or ""
                ).strip()
                if (
                    previous_checkpoint_id
                    and previous_checkpoint_id != current_checkpoint_id
                ):
                    try:
                        remove_agent_runtime_checkpoint(
                            str(claim["session_id"]),
                            previous_checkpoint_id,
                        )
                    except Exception:
                        # 新 baseline 已经与 turn 原子发布；清理旧 baseline
                        # 失败只会占用额外磁盘，不得阻断同一 outbox 的投递。
                        logger.warning(
                            "清理上一轮 Agent runtime checkpoint 失败",
                            extra={
                                "session_id": claim["session_id"],
                                "task_id": task_id,
                            },
                            exc_info=True,
                        )
            state = _pending_state(claim)
            broker_accepted = False
            try:
                upsert_agent_run_snapshot(state)
                turn_index = int(claim.get("turn_index") or 1)
                payload = claim.get("dispatch_payload") or {}
                common = {
                    "task_id": task_id,
                }
                legacy_testdata = (
                    turn_index == 1
                    and str(claim.get("task_kind") or "").strip().lower()
                    == "testdata"
                    and isinstance(payload, dict)
                    and "standard_code" in payload
                )
                if legacy_testdata:
                    if agent_generate_testdata_task is None:
                        raise RuntimeError("旧版造数据 Agent 任务未注册")
                    agent_generate_testdata_task.apply_async(
                        args=(
                            int(claim.get("problem_id")),
                            claim.get("requested_by") or "",
                            int(payload.get("test_point_count") or 0),
                            str(payload.get("standard_code") or ""),
                            str(payload.get("data_requirement") or ""),
                            str(payload.get("standard_filename") or ""),
                            claim.get("harness") or "",
                            int(claim.get("endpoint_id")),
                            "",
                            "session",
                            claim.get("endpoint_revision"),
                        ),
                        **common,
                    )
                else:
                    agent_run_turn_task.apply_async(
                        args=(
                            claim["session_id"],
                            claim.get("requested_by") or "",
                            claim.get("access_role") or "user",
                            claim.get("harness") or "",
                            int(claim.get("endpoint_id")),
                            "",
                            prompt_with_agent_attachments(
                                claim.get("user_message"),
                                claim.get("attachments"),
                            ),
                            "session",
                            claim.get("native_session_id") or "",
                            turn_index == 1,
                            (
                                claim.get("base_runtime_checkpoint_id") or ""
                                if claim.get("retry_of_task_id")
                                else ""
                            ),
                            False,
                        ),
                        **common,
                    )
                broker_accepted = True
                mark_agent_session_message_broker_enqueued(
                    claim["message_id"],
                    dispatch_attempt_id=dispatch_attempt_id,
                    task_id=task_id,
                )
            except Exception as exc:
                if not broker_accepted:
                    try:
                        release_agent_session_message_dispatch_attempt(
                            claim["message_id"],
                            dispatch_attempt_id=dispatch_attempt_id,
                            task_id=task_id,
                        )
                    except Exception:
                        # 释放失败时保留短租约，由恢复扫描在租约过期后接管。
                        logger.warning(
                            "释放 Agent 消息派发租约失败",
                            extra={
                                "session_id": claim["session_id"],
                                "message_id": claim["message_id"],
                                "task_id": task_id,
                            },
                            exc_info=True,
                        )
                # broker 已接受后的数据库回执失败不能释放租约，否则并发唤醒会
                # 立即重复投递；worker 状态提交或租约到期恢复会继续收束。
                raise self.retry(exc=exc, countdown=5)
            return {
                "success": True,
                "dispatched": True,
                "session_id": claim["session_id"],
                "message_id": claim["message_id"],
                "task_id": task_id,
            }

    if recovery_existing:
        recover_agent_session_queues = recovery_existing
    else:

        @celery_app.task(name=AGENT_QUEUE_RECOVERY_TASK_NAME)
        def recover_agent_session_queues(limit=100):
            session_ids = list_agent_session_queue_recovery_candidates(
                limit=limit,
            )
            scheduled = 0
            for session_id in session_ids:
                try:
                    dispatch_agent_session_queue.apply_async(
                        args=(session_id,),
                    )
                    scheduled += 1
                except Exception:
                    logger.exception(
                        "恢复 Agent 会话队列投递失败",
                        extra={"session_id": session_id},
                    )
            return {
                "success": True,
                "candidates": len(session_ids),
                "scheduled": scheduled,
            }

    return dispatch_agent_session_queue, recover_agent_session_queues


__all__ = [
    "AGENT_QUEUE_DISPATCH_TASK_NAME",
    "AGENT_QUEUE_RECOVERY_TASK_NAME",
    "build_agent_control_bridge",
    "prompt_with_agent_attachments",
    "register_agent_queue_tasks",
]
