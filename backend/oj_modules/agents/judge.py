"""评测业务投递通用 Agent 的内部入口；不执行模型或占用端点池名额。"""

from __future__ import annotations

import hashlib
import logging

from celery import current_app

from backend.oj_modules.agents.runtime_checkpoints import (
    create_empty_agent_runtime_checkpoint, create_agent_runtime_checkpoint,
)
from backend.oj_modules.agents.sessions import (
    begin_agent_session_turn,
    create_agent_session,
    get_agent_session,
    get_agent_session_turns,
    get_agent_session_runtime_config,
    normalize_agent_session_id,
)
from backend.oj_modules.agents.workspace import (
    initialize_agent_task_workspace,
    inject_agent_workspace_files,
)
from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.problems.agent_launch import (
    normalize_launch_harness,
    resolve_launch_endpoint,
    token_pricing_from_endpoint,
)
from backend.oj_modules.ranking.agent_judge.db import (
    list_agent_judge_endpoints,
    list_quality_gate_endpoints,
)
from backend.oj_modules.site_config.services import list_llm_endpoints

logger = logging.getLogger(__name__)
JUDGE_KINDS = frozenset({"agent_judge", "reverse_quality", "reverse_answer"})


def judge_session_id(submission_id, attempt_id, judge_kind):
    if judge_kind not in JUDGE_KINDS:
        raise ValueError("Judge 会话类别无效")
    identity = f"{int(submission_id)}:{attempt_id}:{judge_kind}"
    return "jd-" + hashlib.sha256(identity.encode()).hexdigest()[:32]


def resolve_judge_endpoint(session):
    """只用持久业务引用解析端点，密钥不进入队列、会话 JSON 或 workspace。"""
    runtime = get_agent_session_runtime_config(session["session_id"])
    if runtime.get("endpoint_source") != "competition":
        return resolve_launch_endpoint(
            session["harness"], session["endpoint_id"], include_secret=True,
        )
    list_endpoints = (
        list_quality_gate_endpoints
        if session.get("judge_kind") == "reverse_quality"
        else list_agent_judge_endpoints
    )
    endpoint = next((
        row for row in list_endpoints(session["competition_id"])
        if int(row["id"]) == int(session["endpoint_id"])
    ), None)
    if not endpoint:
        raise ValueError("评测选定的比赛节点已被删除")
    endpoint = dict(endpoint)
    endpoint.update({
        "category": "text", "source": "competition", "revision": 1,
        "thinking_enabled": bool(endpoint.get("thinking_compatibility")),
        "protocol": endpoint.get("effective_protocol") or endpoint.get("protocol"),
    })
    if normalize_launch_harness(endpoint.get("harness")) != session["harness"]:
        raise ValueError("比赛节点 harness 已变化")
    if not str(endpoint.get("api_key") or "").strip():
        raise ValueError("比赛节点没有可用的 API Key")
    return endpoint


def judge_endpoint_pricing(endpoint):
    """匹配全站节点时复用动态定价，否则使用比赛池明确保存的价格。"""
    if endpoint.get("source") != "competition":
        pricing = token_pricing_from_endpoint(endpoint)
        if pricing is None:
            raise ValueError("所选节点尚未配置完整价格")
        return {
            "endpoint_id": endpoint["id"],
            "endpoint_revision": endpoint.get("revision") or 1,
            "endpoint_model": endpoint["model"], "pricing": pricing,
        }
    matching = next((
        row for row in list_llm_endpoints(include_secrets=False)
        if str(row.get("base_url") or "").rstrip("/") == str(endpoint.get("base_url") or "").rstrip("/")
        and row.get("model") == endpoint.get("model")
        and row.get("protocol") == endpoint.get("protocol")
    ), None)
    pricing = token_pricing_from_endpoint(matching or endpoint)
    if pricing is None:
        raise ValueError("比赛节点尚未配置完整价格")
    return {
        # 平台账本的 endpoint_id 外键属于全站节点；专有端点用会话关联审计。
        "endpoint_id": matching["id"] if matching else None,
        "endpoint_revision": (matching or {}).get("revision") or 1,
        "endpoint_model": endpoint["model"], "pricing": pricing,
    }


def submit_judge_turn(
    *, session_id, task_id, requested_by, judge_kind, submission_id,
    attempt_id, competition_id, harness, endpoint, prompt, files=None,
    title="", timeout_seconds=None, celery_app=None,
):
    """幂等持久化首轮或内部续聊，然后唤醒唯一通用 Agent outbox。

    调用方先取得比赛端点池名额，并在对应轮次真正终态后释放。相同 task_id
    重放只唤醒未完成的 outbox，不改写材料、重新创建轮次或等待 Agent worker。
    """
    session_id = normalize_agent_session_id(session_id)
    task_id = normalize_agent_session_id(task_id)
    harness = normalize_launch_harness(harness)
    if judge_kind not in JUDGE_KINDS:
        raise ValueError("Judge 会话类别无效")
    prompt = str(prompt or "").strip()
    if not prompt:
        raise ValueError("Judge 指令不能为空")
    if timeout_seconds is not None and (
        isinstance(timeout_seconds, bool) or int(timeout_seconds) <= 0
    ):
        raise ValueError("Agent 超时必须是正整数")
    runtime = {
        "endpoint_source": "competition" if endpoint.get("competition_id") else "global",
        "timeout_seconds": int(timeout_seconds) if timeout_seconds else None,
    }
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 10) AS acquired", (f"agent-submit:{session_id}",))
            if not (cursor.fetchone() or {}).get("acquired"):
                raise RuntimeError("Judge 会话正在创建，请稍后重试")
            try:
                session = get_agent_session(session_id)
                if session:
                    expected = {
                        "task_kind": "judge", "judge_kind": judge_kind,
                        "requested_by": requested_by, "submission_id": submission_id,
                        "attempt_id": attempt_id, "competition_id": competition_id,
                        "endpoint_id": int(endpoint["id"]), "harness": harness,
                    }
                    if any(str(session.get(key)) != str(value) for key, value in expected.items()):
                        raise ValueError("Judge 会话关联或冻结的执行参数不一致")
                    existing_turn = next((row for row in get_agent_session_turns(session_id) if row["task_id"] == task_id), None)
                    if existing_turn:
                        if str(existing_turn.get("user_message") or "") != prompt:
                            raise ValueError("Judge 轮次幂等键与已持久化指令冲突")
                    else:
                        if files:
                            raise ValueError("续聊复用已有 workspace，不能重新注入首轮材料")
                        create_agent_runtime_checkpoint(session_id, task_id)
                        begin_agent_session_turn(
                            session_id, task_id=task_id, user_message=prompt,
                            internal_judge=True, base_runtime_checkpoint_id=task_id,
                            dispatch_payload={"timeout_seconds": runtime["timeout_seconds"]},
                        )
                        session = get_agent_session(session_id)
                else:
                    initialize_agent_task_workspace(session_id, harness=harness, access_role="user")
                    inject_agent_workspace_files(session_id, files)
                    create_empty_agent_runtime_checkpoint(session_id, task_id)
                    session = create_agent_session(
                        session_id=session_id, task_id=task_id,
                        requested_by=requested_by, harness=harness,
                        endpoint_id=int(endpoint["id"]),
                        endpoint_revision=endpoint.get("revision") or 1,
                        endpoint_model=endpoint["model"], user_message=prompt,
                        task_kind="judge", access_role="user", title=title,
                        judge_kind=judge_kind, submission_id=submission_id,
                        attempt_id=attempt_id, competition_id=competition_id,
                        runtime_config=runtime, base_runtime_checkpoint_id=task_id,
                        dispatch_payload={"timeout_seconds": runtime["timeout_seconds"]},
                    )
            finally:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (f"agent-submit:{session_id}",))
    finally:
        conn.close()
    try:
        (celery_app or current_app).send_task(
            "oj.agent.dispatch_session_queue", args=(session_id,), queue="celery",
        )
    except Exception:
        logger.warning("唤醒 Judge 会话 outbox 失败，通用队列恢复将继续派发", exc_info=True)
    return session
