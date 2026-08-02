#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import time
from dataclasses import dataclass
from types import MappingProxyType

from config import (
    AGENT_CONTEXT_KEEP_ROUNDS,
    AGENT_CONTEXT_MAX_CHARS,
    AGENT_CONTEXT_SUMMARY_INPUT_MAX_CHARS,
    AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS,
    AGENT_CONTEXT_SUMMARY_TIMEOUT,
    AGENT_MAX_ROUNDS,
    AGENT_SUBMIT_LIMIT,
    AGENT_MEMORY_ENABLED,
    AGENT_MEMORY_MAX_NOTES,
    AGENT_MEMORY_MAX_PATTERNS,
    EVALUATE_SUBMISSION_LOCK_TTL_SECONDS,
    SUBMISSION_SNAPSHOT_TTL_SECONDS,
)
from oj_modules.db_services import (
    create_submission,
    get_submission_status_snapshot,
    upsert_agent_run_snapshot,
    get_submission_by_id,
    subscribe_submission_status_events,
)
from oj_modules.infrastructure.redis import (
    RedisClientProfile,
    create_optional_redis_client,
)
from oj_modules.site_config.services import (
    get_web_search_settings,
    resolve_feature_endpoint,
)
from oj_modules.ai.endpoints import LLMEndpointSnapshot, call_chat

AGENT_SOLVE_TASK_NAME = "oj.agent.solve_problem"
AGENT_GENERATE_TESTDATA_TASK_NAME = "oj.agent.generate_testdata"
_agent_progress_rds = None
_agent_progress_blocking_rds = None
_AGENT_PROGRESS_TTL_SECONDS = int(SUBMISSION_SNAPSHOT_TTL_SECONDS)


def _clamp_int(value, default, min_value=None, max_value=None):
    try:
        val = int(value)
    except Exception:
        val = int(default)
    if min_value is not None:
        val = max(int(min_value), val)
    if max_value is not None:
        val = min(int(max_value), val)
    return val


_AGENT_MEMORY_ENABLED = bool(AGENT_MEMORY_ENABLED)
_AGENT_CONTEXT_MAX_CHARS = _clamp_int(AGENT_CONTEXT_MAX_CHARS, 24000, min_value=4000, max_value=120000)
_AGENT_CONTEXT_KEEP_ROUNDS = _clamp_int(AGENT_CONTEXT_KEEP_ROUNDS, 3, min_value=1, max_value=10)
_AGENT_MEMORY_MAX_PATTERNS = _clamp_int(AGENT_MEMORY_MAX_PATTERNS, 12, min_value=4, max_value=60)
_AGENT_MEMORY_MAX_NOTES = _clamp_int(AGENT_MEMORY_MAX_NOTES, 12, min_value=4, max_value=60)
_AGENT_CONTEXT_SUMMARY_TIMEOUT = _clamp_int(AGENT_CONTEXT_SUMMARY_TIMEOUT, 120, min_value=20, max_value=300)
_AGENT_CONTEXT_SUMMARY_INPUT_MAX_CHARS = _clamp_int(
    AGENT_CONTEXT_SUMMARY_INPUT_MAX_CHARS,
    24000,
    min_value=2000,
    max_value=120000,
)
_AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS = _clamp_int(
    AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS,
    2400,
    min_value=500,
    max_value=12000,
)
_AGENT_SUBMIT_LIMIT = _clamp_int(AGENT_SUBMIT_LIMIT, 5, min_value=1, max_value=100)
_TOOL_TIMEOUT_MAX_SECONDS = _clamp_int(EVALUATE_SUBMISSION_LOCK_TTL_SECONDS, 60, min_value=60, max_value=3600)


_AGENT_ENDPOINT_FEATURE_LABELS = {
    "solution_agent": "解题 Agent",
    "agent_summary": "Agent 上下文摘要",
    "repository_query_summary": "仓库检索问题摘要",
    "repository_embedding": "仓库检索 Embedding",
    "code_image_analysis": "代码输出图片分析",
}


@dataclass(frozen=True, slots=True)
class AgentEndpointResolution:
    """任务启动时冻结的端点解析结果，不允许运行中重新查询配置。"""

    feature_key: str
    endpoint: LLMEndpointSnapshot | None = None
    error: str = ""

    @property
    def available(self):
        return self.endpoint is not None

    def require(self, operation_label=None):
        if self.endpoint is not None:
            return self.endpoint
        label = str(operation_label or "").strip()
        if not label:
            label = _AGENT_ENDPOINT_FEATURE_LABELS.get(
                self.feature_key,
                self.feature_key,
            )
        detail = str(self.error or "端点未配置或已被删除").strip()
        raise RuntimeError(
            f"{label}不可用：{detail}（该状态已在任务启动时固定，运行中不会重新读取配置）"
        )


def init_agent_progress_cache(redis_client, ttl_seconds=None, blocking_client=None):
    global _agent_progress_rds, _agent_progress_blocking_rds
    global _AGENT_PROGRESS_TTL_SECONDS
    _agent_progress_rds = redis_client
    _agent_progress_blocking_rds = (
        redis_client if blocking_client is None else blocking_client
    )
    if ttl_seconds is not None:
        try:
            _AGENT_PROGRESS_TTL_SECONDS = max(300, int(ttl_seconds))
        except Exception:
            pass


def _ensure_agent_progress_redis():
    global _agent_progress_rds
    if _agent_progress_rds is not None:
        return _agent_progress_rds
    _agent_progress_rds = create_optional_redis_client()
    return _agent_progress_rds


def _ensure_agent_progress_blocking_redis():
    global _agent_progress_blocking_rds
    if _agent_progress_blocking_rds is not None:
        return _agent_progress_blocking_rds
    _agent_progress_blocking_rds = create_optional_redis_client(
        RedisClientProfile.BLOCKING,
    )
    return _agent_progress_blocking_rds


def _agent_progress_key(task_id):
    return f"agent_run:{task_id}"


def _agent_progress_channel(task_id):
    return f"agent_run_events:{task_id}"


def get_agent_run_snapshot(task_id):
    if not task_id:
        return None
    client = _ensure_agent_progress_redis()
    if client is None:
        return None
    try:
        raw = client.get(_agent_progress_key(task_id))
        if not raw:
            return None
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def subscribe_agent_run_events(task_id):
    if not task_id:
        return None
    client = _ensure_agent_progress_blocking_redis()
    if client is None:
        return None
    try:
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(_agent_progress_channel(task_id))
        return pubsub
    except Exception:
        return None


def _format_local_time(ts=None):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts or time.time()))


def _safe_json_copy(value, default=None):
    fallback = {} if default is None else default
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except Exception:
        return fallback


def _persist_agent_state(state):
    if not isinstance(state, dict):
        return
    attempts = state.get("attempts") if isinstance(state.get("attempts"), list) else []
    best_score = 0
    for item in attempts:
        if not isinstance(item, dict):
            continue
        summary = item.get("summary") or {}
        if not isinstance(summary, dict):
            continue
        try:
            score = int(summary.get("score") or 0)
        except Exception:
            score = 0
        if score > best_score:
            best_score = score
    try:
        current_best = int(state.get("best_score") or 0)
    except Exception:
        current_best = 0
    state["best_score"] = max(best_score, current_best)

    client = _ensure_agent_progress_redis()
    task_id = str(state.get("task_id") or "").strip()
    if not task_id:
        return

    state["updated_at"] = _format_local_time()
    upsert_agent_run_snapshot(state)

    if client is None:
        return
    payload = json.dumps(state, ensure_ascii=False)
    try:
        client.setex(_agent_progress_key(task_id), _AGENT_PROGRESS_TTL_SECONDS, payload)
        client.publish(_agent_progress_channel(task_id), payload)
    except Exception:
        pass


def _push_agent_event(state, event_message, level="info", event_type=None, details=None, **updates):
    if not isinstance(state, dict):
        return
    for k, v in updates.items():
        state[k] = v

    state["message"] = updates.get("message", event_message)
    events = state.get("events") or []
    event_item = {
        "time": _format_local_time(),
        "level": level,
        "message": str(event_message or "").strip(),
    }
    if event_type:
        event_item["event_type"] = str(event_type)
    if details is not None:
        event_item["details"] = _safe_json_copy(details, default={})
    events.append(event_item)
    if len(events) > 120:
        events = events[-120:]
    state["events"] = events
    _persist_agent_state(state)


def _compact_summary(summary):
    if not isinstance(summary, dict):
        return {
            "status": "Error",
            "score": 0,
            "accepted_count": 0,
            "total_count": 0,
            "timeout": False,
            "failed_points": [],
        }
    failed_points = summary.get("failed_points") or []
    return {
        "status": summary.get("status"),
        "score": summary.get("score", 0),
        "accepted_count": summary.get("accepted_count", 0),
        "total_count": summary.get("total_count", 0),
        "timeout": bool(summary.get("timeout")),
        "failed_points": failed_points[:5],
    }


def _resolve_agent_endpoint_resolutions(*feature_keys):
    """在任务启动时把每个功能冻结为端点快照或不可用错误。"""
    resolutions = {}
    for feature_key in feature_keys:
        key = str(feature_key or "").strip()
        if not key or key in resolutions:
            continue
        try:
            resolutions[key] = AgentEndpointResolution(
                feature_key=key,
                endpoint=LLMEndpointSnapshot.from_mapping(
                    resolve_feature_endpoint(key)
                ),
            )
        except Exception as exc:
            label = _AGENT_ENDPOINT_FEATURE_LABELS.get(key, key)
            detail = str(exc).strip() or exc.__class__.__name__
            resolutions[key] = AgentEndpointResolution(
                feature_key=key,
                error=f"全站配置中的“{label}”端点在任务启动时不可用：{detail}",
            )
    return resolutions


def _require_agent_endpoint(
    endpoint_or_resolution,
    *,
    feature_key,
    operation_label=None,
):
    """只消费已冻结的结果；绝不因缺少端点而回退查询数据库。"""
    if isinstance(endpoint_or_resolution, LLMEndpointSnapshot):
        return endpoint_or_resolution
    if isinstance(endpoint_or_resolution, AgentEndpointResolution):
        return endpoint_or_resolution.require(operation_label)
    label = str(operation_label or "").strip()
    if not label:
        label = _AGENT_ENDPOINT_FEATURE_LABELS.get(feature_key, feature_key)
    raise RuntimeError(
        f"{label}不可用：任务启动时未冻结该端点（运行中不会重新读取配置）"
    )


def _resolve_agent_endpoint_snapshots(*feature_keys):
    """解析必需端点；保留给必须在任务启动时失败的调用方。"""
    resolutions = _resolve_agent_endpoint_resolutions(*feature_keys)
    snapshots = {}
    for key, resolution in resolutions.items():
        try:
            snapshots[key] = resolution.require()
        except RuntimeError as exc:
            raise RuntimeError(str(exc)) from exc
    return snapshots


def _resolve_web_search_settings_snapshot():
    """固定当前任务使用的联网搜索配置，避免工具调用中途漂移。"""
    settings = get_web_search_settings(include_secret=True) or {}
    return MappingProxyType(dict(settings))


def _extract_text_from_content(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    return ""


def _build_api_request_payload(messages, endpoint_snapshot, tools=None):
    endpoint = (
        endpoint_snapshot
        if isinstance(endpoint_snapshot, LLMEndpointSnapshot)
        else LLMEndpointSnapshot.from_mapping(endpoint_snapshot)
    )
    payload = {
        "endpoint_id": endpoint.id,
        "protocol": endpoint.protocol.value,
        "model": endpoint.model,
        "messages": _safe_json_copy(messages, default=[]),
        "stream": False,
    }
    if isinstance(tools, list) and tools:
        payload["tools"] = _safe_json_copy(tools, default=[])
        payload["tool_choice"] = "auto"
    if endpoint.thinking_enabled:
        payload["thinking_enabled"] = True
    return payload


def _coerce_message_roles_for_api(messages):
    allowed_roles = {"system", "user", "assistant", "tool"}
    result = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        item = _safe_json_copy(msg, default={})
        role = str(item.get("role") or "user").strip().lower() or "user"
        content = str(item.get("content") or "")
        if role == "memory":
            item["role"] = "system"
            item["content"] = f"[memory]\\n{content}".strip()
            result.append(item)
            continue
        if role not in allowed_roles:
            item["role"] = "user"
            item["content"] = f"[{role}] {content}".strip()
            result.append(item)
            continue
        item["role"] = role
        result.append(item)
    return result


def _append_api_call_log(state, round_idx, request_body, api_type="solve"):
    if not isinstance(state, dict):
        return
    api_calls = state.get("api_calls") if isinstance(state.get("api_calls"), list) else []
    api_calls.append({
        "time": _format_local_time(),
        "round": int(round_idx or 0),
        "api_type": str(api_type or "solve"),
        "request_body": _safe_json_copy(request_body, default={}),
    })
    max_rounds = 0
    try:
        max_rounds = int(state.get("max_rounds") or 0)
    except Exception:
        max_rounds = 0
    state["api_calls"] = api_calls[-max(16, max_rounds + 8):]


def _normalize_assistant_message(raw_message):
    data = {}
    if raw_message is None:
        data = {}
    elif isinstance(raw_message, dict):
        data = raw_message
    elif hasattr(raw_message, "model_dump"):
        try:
            data = raw_message.model_dump()
        except Exception:
            data = {}
    else:
        data = {}

    role = str(data.get("role") or "assistant").strip() or "assistant"
    content = _extract_text_from_content(data.get("content"))
    message = {"role": role, "content": str(content or "")}

    normalized_calls = []
    for call in data.get("tool_calls") or []:
        item = call
        if not isinstance(item, dict) and hasattr(item, "model_dump"):
            try:
                item = item.model_dump()
            except Exception:
                item = {}
        if not isinstance(item, dict):
            continue
        function_data = item.get("function") or {}
        if not isinstance(function_data, dict) and hasattr(function_data, "model_dump"):
            try:
                function_data = function_data.model_dump()
            except Exception:
                function_data = {}
        name = str((function_data or {}).get("name") or "").strip()
        if not name:
            continue
        arguments = (function_data or {}).get("arguments")
        if isinstance(arguments, str):
            arg_text = arguments
        else:
            try:
                arg_text = json.dumps(arguments or {}, ensure_ascii=False)
            except Exception:
                arg_text = "{}"
        call_id = str(item.get("id") or "").strip() or f"call_{int(time.time() * 1000)}_{len(normalized_calls)}"
        normalized_calls.append({
            "id": call_id,
            "type": "function",
            "function": {"name": name, "arguments": arg_text},
        })
    if normalized_calls:
        message["tool_calls"] = normalized_calls
    return message


def _call_agent_chat_completion(endpoint_snapshot, messages, timeout=180, tools=None):
    endpoint = (
        endpoint_snapshot
        if isinstance(endpoint_snapshot, LLMEndpointSnapshot)
        else LLMEndpointSnapshot.from_mapping(endpoint_snapshot)
    )
    api_messages = _coerce_message_roles_for_api(messages)
    result = call_chat(
        endpoint,
        api_messages,
        tools=tools,
        tool_choice="auto" if tools else None,
        timeout=timeout,
    )
    return _normalize_assistant_message(result.to_openai_message())


def _call_agent_text_model(
    endpoint_snapshot,
    messages,
    timeout=180,
    empty_text_error="模型未返回有效文本。",
):
    message = _call_agent_chat_completion(
        endpoint_snapshot=endpoint_snapshot,
        messages=messages,
        timeout=timeout,
        tools=None,
    )
    text = _extract_text_from_content(message.get("content")).strip()
    if not text:
        raise RuntimeError(str(empty_text_error or "模型未返回有效文本。"))
    return text



def _truncate_text(value, limit=300):
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _extract_retry_diagnosis(reply_text):
    text = str(reply_text or "").strip()
    if not text:
        return ""

    marker = re.search(r"【诊断】\s*(.*?)\s*(【代码】|```)", text, flags=re.DOTALL)
    if marker:
        return _truncate_text(marker.group(1), limit=600)

    fence_pos = text.find("```")
    if fence_pos > 0:
        return _truncate_text(text[:fence_pos], limit=600)

    return ""


def _normalize_text_line(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _conversation_total_chars(conversation):
    total = 0
    for msg in conversation or []:
        if not isinstance(msg, dict):
            continue
        total += len(str(msg.get("content") or ""))
        if msg.get("role") == "assistant":
            try:
                total += len(json.dumps(msg.get("tool_calls") or [], ensure_ascii=False))
            except Exception:
                pass
        if msg.get("role") == "tool":
            total += len(str(msg.get("tool_call_id") or ""))
            total += len(str(msg.get("name") or ""))
    return total


def _compact_tool_content_for_history_summary(content):
    text = str(content or "").strip()
    if not text:
        return ""
    try:
        parsed = json.loads(text)
    except Exception:
        return _truncate_text(_normalize_text_line(text), limit=1200)

    if not isinstance(parsed, dict):
        return _truncate_text(_normalize_text_line(text), limit=1200)
    compact = _safe_json_copy(parsed, default={})
    for key in ("latest_code", "code", "content", "ai_tutor_feedback"):
        if key in compact:
            compact[key] = _truncate_text(compact.get(key), limit=500)
    if isinstance(compact.get("files"), list):
        compact["files"] = compact.get("files")[:12]
    if isinstance(compact.get("failed_points"), list):
        compact["failed_points"] = compact.get("failed_points")[:4]
    try:
        return _truncate_text(json.dumps(compact, ensure_ascii=False), limit=1400)
    except Exception:
        return _truncate_text(_normalize_text_line(text), limit=1200)


def _serialize_messages_for_history_summary(messages, max_chars):
    rows = []
    total_chars = 0
    for idx, msg in enumerate(messages or [], start=1):
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "").strip() or "user"
        content = str(msg.get("content") or "").strip()
        if role == "tool":
            content = _compact_tool_content_for_history_summary(content)
        if not content:
            continue

        # 对历史代码块做轻量去噪，保留诊断/关键信息供摘要模型理解。
        if role == "assistant":
            diagnosis = _extract_retry_diagnosis(content)
            if diagnosis:
                content = f"诊断要点：{diagnosis}\n代码：<省略>"
            else:
                content = re.sub(r"```[\s\S]*?```", "<代码块省略>", content, flags=re.DOTALL)
            tool_calls = msg.get("tool_calls") if isinstance(msg.get("tool_calls"), list) else []
            if tool_calls:
                called = []
                for tc in tool_calls[:6]:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function") or {}
                    if isinstance(fn, dict):
                        called.append(str(fn.get("name") or "").strip())
                called = [x for x in called if x]
                if called:
                    content = (content + f"\n工具调用: {', '.join(called)}").strip()

        normalized = _normalize_text_line(content)
        normalized = _truncate_text(normalized, limit=1400)
        row = f"[{idx}] {role}: {normalized}"

        if total_chars + len(row) > max_chars:
            remain = max_chars - total_chars
            if remain > 80:
                rows.append(row[:remain].rstrip() + "...")
            break
        rows.append(row)
        total_chars += len(row) + 1
    return "\n".join(rows).strip()


def _summarize_agent_history(
    history_messages,
    target_chars,
    summary_endpoint,
    state=None,
    round_idx=None,
    event_label="历史摘要",
):
    if not isinstance(history_messages, list) or not history_messages:
        return ""

    messages = _safe_json_copy(history_messages, default=[])
    if not isinstance(messages, list):
        messages = []
    messages.append({
        "role": "user",
        "content": f"生成历史摘要，限制字数：{int(target_chars)}",
    })

    request_body = _build_api_request_payload(messages, summary_endpoint)
    _append_api_call_log(state, round_idx, request_body, api_type="context_summary")
    if isinstance(state, dict):
        _push_agent_event(
            state,
            f"第 {round_idx}/{state.get('max_rounds')} 轮：{event_label}中",
            round=round_idx,
            event_type="api_request",
            details={
                "round": round_idx,
                "api_type": "context_summary",
                "request_body": request_body,
            },
        )
    try:
        summary = _call_agent_text_model(
            summary_endpoint,
            messages,
            timeout=_AGENT_CONTEXT_SUMMARY_TIMEOUT,
            empty_text_error="模型未返回有效摘要文本。",
        )
    except Exception as e:
        print(f"[Agent] 历史摘要调用失败，回退本地压缩: {e}")
        return ""

    cleaned = str(summary or "").strip()
    if cleaned.startswith("```"):
        m = re.search(r"```(?:\w+)?\s*(.*?)\s*```", cleaned, flags=re.DOTALL)
        if m:
            cleaned = m.group(1).strip()
    return cleaned


def _extract_latest_code_only_from_assistant(content):
    text = str(content or "").strip()
    if not text:
        return ""

    fenced_blocks = list(re.finditer(r"```(?:\w+)?\s*[\s\S]*?\s*```", text))
    if fenced_blocks:
        return fenced_blocks[-1].group(0).strip()

    marker = re.search(r"【代码】\s*([\s\S]+)$", text)
    if marker:
        code_part = marker.group(1).strip()
        if code_part:
            return f"```text\n{code_part}\n```"

    return f"```text\n{text}\n```"


def _drop_orphan_tool_messages(messages):
    result = []
    seen_tool_call_ids = set()
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "").strip()
        if role == "assistant":
            tool_calls = msg.get("tool_calls") if isinstance(msg.get("tool_calls"), list) else []
            normalized_tool_calls = []
            for call in tool_calls:
                if not isinstance(call, dict):
                    continue
                call_id = str(call.get("id") or "").strip()
                if not call_id:
                    continue
                seen_tool_call_ids.add(call_id)
                normalized_tool_calls.append(call)
            row = {"role": "assistant", "content": str(msg.get("content") or "")}
            if normalized_tool_calls:
                row["tool_calls"] = normalized_tool_calls
            result.append(row)
            continue
        if role == "tool":
            call_id = str(msg.get("tool_call_id") or "").strip()
            if not call_id or call_id not in seen_tool_call_ids:
                continue
            row = {
                "role": "tool",
                "tool_call_id": call_id,
                "content": str(msg.get("content") or ""),
            }
            if msg.get("name"):
                row["name"] = str(msg.get("name"))
            result.append(row)
            continue
        if role == "user":
            result.append({"role": "user", "content": str(msg.get("content") or "")})
    return result


def _trim_conversation_by_budget(
    conversation,
    max_chars,
    keep_rounds,
    summary_endpoint,
    state=None,
    round_idx=None,
):
    if not isinstance(conversation, list):
        return []
    cleaned = []
    for item in conversation:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip()
        content = str(item.get("content") or "")
        if role not in ("user", "assistant", "tool"):
            continue
        row = {"role": role, "content": content}
        if role == "assistant":
            tool_calls = item.get("tool_calls") if isinstance(item.get("tool_calls"), list) else []
            if tool_calls:
                row["tool_calls"] = _safe_json_copy(tool_calls, default=[])
        if role == "tool":
            row["tool_call_id"] = str(item.get("tool_call_id") or "")
            if item.get("name"):
                row["name"] = str(item.get("name"))
        cleaned.append(row)

    if not cleaned:
        return []
    cleaned = _drop_orphan_tool_messages(cleaned)
    if _conversation_total_chars(cleaned) <= max_chars:
        return cleaned

    # 严禁本地裁剪：仅允许基于完整历史生成摘要，再整体替换上下文。
    _ = keep_rounds
    try:
        use_summary_endpoint = _require_agent_endpoint(
            summary_endpoint,
            feature_key="agent_summary",
            operation_label="Agent 上下文摘要",
        )
    except RuntimeError as exc:
        if isinstance(state, dict):
            _push_agent_event(
                state,
                f"已跳过 Agent 上下文摘要：{exc}",
                level="warning",
                event_type="optional_endpoint_unavailable",
                details={"feature_key": "agent_summary"},
            )
        return cleaned

    summary_budget = min(_AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS, max(600, int(max_chars * 0.9)))
    full_summary = _summarize_agent_history(
        cleaned,
        target_chars=summary_budget,
        summary_endpoint=use_summary_endpoint,
        state=state,
        round_idx=round_idx,
        event_label="全量历史摘要",
    )
    if full_summary:
        summary_model_display = str(use_summary_endpoint.model or "configured-model")
        return [{
            "role": "assistant",
            "content": f"【历史信息摘要（{summary_model_display}）】\n" + full_summary,
        }]
    return cleaned



def _summarize_submission(submission):
    if not submission:
        return {
            "status": "Error",
            "score": 0,
            "accepted_count": 0,
            "total_count": 0,
            "failed_points": [],
            "test_points": [],
        }

    points = submission.get("test_points") or []
    if not isinstance(points, list):
        points = []

    accepted = 0
    failed_points = []
    test_points = []
    for idx, tp in enumerate(points, start=1):
        status = str((tp or {}).get("status") or "Error")
        point_index = (tp or {}).get("test_index")
        try:
            point_index = int(point_index) if point_index is not None else idx
        except Exception:
            point_index = idx
        point_item = {
            "index": point_index,
            "status": status,
            "stdout": _truncate_text((tp or {}).get("stdout"), limit=800),
            "stderr": _truncate_text((tp or {}).get("stderr"), limit=800),
            "time": (tp or {}).get("time", 0),
            "has_output_image": bool((tp or {}).get("has_output_image")),
        }
        test_points.append(point_item)
        if status == "Accepted":
            accepted += 1
            continue
        failed_points.append({
            "index": point_index,
            "status": status,
            "stderr": point_item.get("stderr"),
            "stdout": point_item.get("stdout"),
            "time": (tp or {}).get("time", 0),
            "has_output_image": point_item.get("has_output_image"),
        })

    return {
        "status": submission.get("status"),
        "score": submission.get("score", 0),
        "accepted_count": accepted,
        "total_count": len(points),
        "failed_points": failed_points,
        "test_points": test_points,
    }


def _tool_submit_code(problem, username, code, evaluate_submission_task):
    print(f"[AgentTool] submit_code by {username} for problem={problem['id']}")
    submission_id = create_submission(
        problem_id=problem["id"],
        problem_title=problem["title"],
        username=username,
        code=code,
        score=0,
        test_points=[],
    )
    if not submission_id or int(submission_id) <= 0:
        raise RuntimeError(f"invalid submission id: {submission_id}")
    evaluate_submission_task.delay(submission_id)
    return submission_id


def _tool_query_test_results(submission_id, timeout_seconds=240):
    print(f"[AgentTool] query_test_results submission_id={submission_id}")
    deadline = time.time() + max(30, int(timeout_seconds))

    def is_judging(status):
        return status in ("Pending", "Waiting", "Running")

    def _test_point_count(snapshot):
        if not isinstance(snapshot, dict):
            return 0
        points = snapshot.get("test_points")
        return len(points) if isinstance(points, list) else 0

    def _need_wait_for_terminal_details(snapshot):
        if not isinstance(snapshot, dict):
            return False
        status = str(snapshot.get("status") or "").strip()
        if status not in ("Compile Error", "Forbidden", "Error"):
            return False
        return _test_point_count(snapshot) <= 0

    def _load_latest_direct():
        snap = get_submission_status_snapshot(submission_id, prefer_cache=False)
        if not snap:
            snap = get_submission_by_id(submission_id)
        return snap

    def _finalize_terminal(snapshot):
        latest_snapshot = snapshot if isinstance(snapshot, dict) else {}
        # 评测任务可能先写终态状态，再写 test_points；这里短暂补等，避免拿到空明细。
        if _need_wait_for_terminal_details(latest_snapshot):
            grace_deadline = min(deadline, time.time() + 3.0)
            while time.time() < grace_deadline:
                direct = _load_latest_direct()
                if direct:
                    latest_snapshot = direct
                if not _need_wait_for_terminal_details(latest_snapshot):
                    break
                time.sleep(0.2)
        return {"timeout": False, "completed": True, **_summarize_submission(latest_snapshot)}

    def decode_message(raw):
        payload = raw
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="ignore")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                return None
        return payload if isinstance(payload, dict) else None

    latest = get_submission_status_snapshot(submission_id, prefer_cache=True)
    if not latest:
        latest = get_submission_by_id(submission_id)
    if latest and not is_judging(latest.get("status")):
        return _finalize_terminal(latest)

    pubsub = subscribe_submission_status_events(submission_id)
    if pubsub is not None:
        try:
            while time.time() < deadline:
                msg = pubsub.get_message(timeout=1.0)
                if not msg:
                    continue
                if not isinstance(msg, dict):
                    continue
                if msg.get("type") != "message":
                    continue

                snap = decode_message(msg.get("data"))
                if not snap:
                    continue

                latest = snap
                if not is_judging(latest.get("status")):
                    return _finalize_terminal(latest)
        finally:
            try:
                pubsub.close()
            except Exception:
                pass

    # 订阅不可用或超时时回退轮询，但仍坚持等待到终态/超时后再返回。
    while time.time() < deadline:
        snap = get_submission_status_snapshot(submission_id, prefer_cache=True)
        if not snap:
            snap = get_submission_by_id(submission_id)
        if snap:
            latest = snap
            if not is_judging(latest.get("status")):
                return _finalize_terminal(latest)
        time.sleep(1.0)

    return {"timeout": True, "completed": False, **_summarize_submission(latest)}



def _safe_load_tool_arguments(arguments):
    if isinstance(arguments, dict):
        return arguments
    if arguments is None:
        return {}
    if isinstance(arguments, str):
        text = arguments.strip()
        if not text:
            return {}
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}


__all__ = [
    "AGENT_SOLVE_TASK_NAME",
    "AGENT_GENERATE_TESTDATA_TASK_NAME",
    "init_agent_progress_cache",
    "get_agent_run_snapshot",
    "subscribe_agent_run_events",
]
