#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import time

import requests

from config import (
    AI_TUTOR_MODEL,
    AGENT_CONTEXT_KEEP_ROUNDS,
    AGENT_CONTEXT_MAX_CHARS,
    AGENT_CONTEXT_SUMMARY_INPUT_MAX_CHARS,
    AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS,
    AGENT_CONTEXT_SUMMARY_TIMEOUT,
    AGENT_MAX_ROUNDS,
    AGENT_MEMORY_ENABLED,
    AGENT_MEMORY_MAX_DO_NOT_REPEAT,
    AGENT_MEMORY_MAX_NOTES,
    AGENT_MEMORY_MAX_PATTERNS,
    DASHSCOPE_API_KEY,
    DASHSCOPE_BASE_URL,
    QWEN_CODER_MODEL,
    QWEN_TEXT_MODEL,
    REDIS_DB,
    REDIS_HOST,
    REDIS_PORT,
)
from oj_modules.db_services import (
    create_submission,
    get_db_connection,
    get_cached_ai_code_marks_for_submission,
    get_problem,
    get_submission_status_snapshot,
    save_submission_ai_code_marks_json,
    upsert_agent_run_snapshot,
    get_submission_by_id,
    subscribe_submission_status_events,
    get_user_by_username,
)
from oj_modules.ai_utils import generate_ai_code_marks_from_submission_context
from oj_modules.repository_services import extract_includes_from_code, get_user_repository_files_by_names

try:
    from openai import OpenAI
except Exception:
    OpenAI = None

try:
    import redis
except Exception:
    redis = None


AGENT_SOLVE_TASK_NAME = "oj.agent.solve_problem"
_agent_progress_rds = None
_AGENT_PROGRESS_TTL_SECONDS = 21600


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
_AGENT_MEMORY_MAX_DO_NOT_REPEAT = _clamp_int(AGENT_MEMORY_MAX_DO_NOT_REPEAT, 10, min_value=3, max_value=40)
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


def init_agent_progress_cache(redis_client, ttl_seconds=None):
    global _agent_progress_rds, _AGENT_PROGRESS_TTL_SECONDS
    _agent_progress_rds = redis_client
    if ttl_seconds is not None:
        try:
            _AGENT_PROGRESS_TTL_SECONDS = max(300, int(ttl_seconds))
        except Exception:
            pass


def _ensure_agent_progress_redis():
    global _agent_progress_rds
    if _agent_progress_rds is not None:
        return _agent_progress_rds
    if redis is None:
        return None

    try:
        _agent_progress_rds = redis.StrictRedis(
            host=REDIS_HOST,
            port=int(REDIS_PORT),
            db=int(REDIS_DB),
            decode_responses=True,
        )
        _agent_progress_rds.ping()
    except Exception:
        _agent_progress_rds = None
    return _agent_progress_rds


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
    client = _ensure_agent_progress_redis()
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


def _ensure_dashscope_api_key():
    api_key = DASHSCOPE_API_KEY
    if not api_key or str(api_key).strip() == "" or "YOUR" in str(api_key).upper():
        raise RuntimeError("未配置 DASHSCOPE_API_KEY。")
    return api_key


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


def _build_api_request_payload(messages, model=None, tools=None, enable_thinking=None):
    payload = {
        "model": str(model or QWEN_CODER_MODEL),
        "messages": _safe_json_copy(messages, default=[]),
        "stream": False,
    }
    if isinstance(tools, list) and tools:
        payload["tools"] = _safe_json_copy(tools, default=[])
        payload["tool_choice"] = "auto"
    if enable_thinking is not None:
        payload["enable_thinking"] = bool(enable_thinking)
    return payload


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


def _format_ai_tutor_feedback_from_marks(result):
    if not isinstance(result, dict):
        return ""
    summary = str(result.get("summary") or "").strip()
    issues = result.get("issues") if isinstance(result.get("issues"), list) else []
    image_mismatch_analysis = str(result.get("image_mismatch_analysis") or "").strip()
    image_analysis_test_index = result.get("image_analysis_test_index")

    lines = []
    if summary:
        lines.append(f"总结：{summary}")
    if issues:
        lines.append("关键问题定位：")
        for idx, issue in enumerate(issues[:4], start=1):
            if not isinstance(issue, dict):
                continue
            ls = issue.get("line_start")
            le = issue.get("line_end")
            reason = _normalize_text_line(issue.get("reason"))
            if ls and le:
                if int(ls) == int(le):
                    pos = f"行{ls}"
                else:
                    pos = f"行{ls}-{le}"
            else:
                pos = "未知行"
            sev = str(issue.get("severity") or "error")
            lines.append(f"{idx}) {pos} [{sev}] {reason}")
    if image_mismatch_analysis:
        lines.append(f"这个程序在交互式运行的时候，输出了图片，从图片上看，结果存在以下问题。")
        if image_analysis_test_index:
            lines.append(f"【图片分析】（测试点#{image_analysis_test_index}）：")
        else:
            lines.append("【图片分析】")
        lines.append(_truncate_text(image_mismatch_analysis, limit=500))
    return _truncate_text("\n".join(lines).strip(), limit=1600)


def _simulate_user_click_ai_tutor(problem, submission, user, user_code, submission_id):
    if not isinstance(problem, dict) or not isinstance(submission, dict):
        return ""
    cached = get_cached_ai_code_marks_for_submission(submission)
    if cached and isinstance(cached, dict) and cached.get("success"):
        return _format_ai_tutor_feedback_from_marks(cached)

    test_points_text = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in (submission.get("test_points") or [])])
    repository_files = {}
    if isinstance(user, dict) and user.get("id"):
        included_files = extract_includes_from_code(user_code or "")
        if included_files:
            repository_files = get_user_repository_files_by_names(user["id"], included_files)

    result = generate_ai_code_marks_from_submission_context(
        problem_content=problem.get("content") or "",
        user_code=user_code or "",
        test_points_text=test_points_text,
        repository_files=repository_files,
        submission_id=submission_id,
        test_points=submission.get("test_points") or [],
        max_issues=8,
        timeout=240,
    )
    if not isinstance(result, dict) or not result.get("success"):
        return ""

    payload = {
        "issues": result.get("issues") or [],
        "summary": str(result.get("summary") or "").strip(),
        "code_used": str(result.get("code_used") or user_code or ""),
        "image_mismatch_analysis": str(result.get("image_mismatch_analysis") or "").strip(),
        "image_analysis_test_index": result.get("image_analysis_test_index"),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": AI_TUTOR_MODEL,
    }
    try:
        save_submission_ai_code_marks_json(submission_id, payload)
    except Exception:
        pass
    return _format_ai_tutor_feedback_from_marks(result)


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


def _call_qwen_chat_completion(messages, model, timeout=180, tools=None, enable_thinking=None):
    api_key = _ensure_dashscope_api_key()
    base_url = str(DASHSCOPE_BASE_URL).rstrip("/")
    use_model = str(model or QWEN_CODER_MODEL)
    payload = _build_api_request_payload(
        messages,
        model=use_model,
        tools=tools,
        enable_thinking=enable_thinking,
    )

    if OpenAI is not None:
        try:
            client = OpenAI(api_key=api_key, base_url=base_url)
            kwargs = {
                "model": use_model,
                "messages": messages,
                "stream": False,
            }
            if isinstance(tools, list) and tools:
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"
            if enable_thinking is not None:
                kwargs["extra_body"] = {"enable_thinking": bool(enable_thinking)}
            resp = client.chat.completions.create(**kwargs)
            choices = getattr(resp, "choices", None) or []
            if choices and getattr(choices[0], "message", None):
                return _normalize_assistant_message(choices[0].message)
        except Exception as e:
            print(f"[Agent] OpenAI SDK 调用失败，尝试 requests 回退: {e}")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    resp = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("模型未返回有效结果。")
    message = choices[0].get("message") or {}
    return _normalize_assistant_message(message)


def _call_qwen_chat_model(
    messages,
    model,
    timeout=180,
    empty_text_error="模型未返回有效文本。",
    enable_thinking=None,
):
    message = _call_qwen_chat_completion(
        messages=messages,
        model=model,
        timeout=timeout,
        tools=None,
        enable_thinking=enable_thinking,
    )
    text = _extract_text_from_content(message.get("content")).strip()
    if not text:
        raise RuntimeError(str(empty_text_error or "模型未返回有效文本。"))
    return text


def _call_qwen3_coder_plus(messages, timeout=180):
    return _call_qwen_chat_model(
        messages=messages,
        model=QWEN_CODER_MODEL,
        timeout=timeout,
        empty_text_error="模型未返回有效代码文本。",
    )


def _call_qwen3_coder_plus_with_tools(messages, tools, timeout=180):
    return _call_qwen_chat_completion(
        messages=messages,
        model=QWEN_CODER_MODEL,
        timeout=timeout,
        tools=tools,
    )


def _call_qwen3_5_plus_text(messages, timeout=120, enable_thinking=None):
    return _call_qwen_chat_model(
        messages=messages,
        model=QWEN_TEXT_MODEL,
        timeout=timeout,
        empty_text_error="模型未返回有效摘要文本。",
        enable_thinking=enable_thinking,
    )


def _call_qwen3_5_flash_text(messages, timeout=120, enable_thinking=False):
    return _call_qwen_chat_model(
        messages=messages,
        model=AI_TUTOR_MODEL,
        timeout=timeout,
        empty_text_error="模型未返回有效文本。",
        enable_thinking=enable_thinking,
    )


def _extract_code_from_model_reply(reply_text, lang):
    text = (reply_text or "").strip()
    if not text:
        return ""

    lang_map = {
        "cpp": ["cpp", "c++", "cc", "cxx"],
        "c": ["c"],
        "python": ["python", "py"],
        "py": ["python", "py"],
        "matlab": ["matlab", "octave", "m"],
    }
    aliases = lang_map.get((lang or "").lower(), [])

    for alias in aliases:
        m = re.search(rf"```{re.escape(alias)}\s*(.*?)\s*```", text, flags=re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip()

    m = re.search(r"```(?:\w+)?\s*(.*?)\s*```", text, flags=re.DOTALL)
    if m:
        return m.group(1).strip()

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


def _dedupe_keep_order(items):
    seen = set()
    result = []
    for item in items or []:
        text = _normalize_text_line(item)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _extract_problem_hints(problem):
    if not isinstance(problem, dict):
        return []

    candidates = []
    for key in ("hint", "hints", "tips", "tip"):
        value = problem.get(key)
        if value:
            candidates.append(str(value))

    content = str(problem.get("content") or "")
    if content:
        block_patterns = [
            r"(?:^|\n)#{1,6}\s*提示[:：]?\s*\n(?P<body>.*?)(?=\n#{1,6}\s+\S|\Z)",
            r"(?:^|\n)#{1,6}\s*(?:hint|hints|tips?)[:：]?\s*\n(?P<body>.*?)(?=\n#{1,6}\s+\S|\Z)",
            r"(?:^|\n)提示[:：]\s*(?P<body>.+?)(?=\n\n|\Z)",
            r"(?:^|\n)(?:hint|hints|tips?)[:：]\s*(?P<body>.+?)(?=\n\n|\Z)",
        ]
        for pat in block_patterns:
            for match in re.finditer(pat, content, flags=re.IGNORECASE | re.DOTALL):
                body = str(match.group("body") or "").strip()
                if body:
                    candidates.append(body)

    normalized = []
    for chunk in candidates:
        for line in str(chunk).splitlines():
            text = re.sub(r"^\s*[-*+>\d.()（）]+\s*", "", line).strip()
            if not text:
                continue
            text = _truncate_text(text, limit=220)
            normalized.append(text)
    return _dedupe_keep_order(normalized)[:8]


def _init_working_memory(core_hints=None):
    hints = _dedupe_keep_order(core_hints or [])[:8]
    return {
        "core_hints": hints,
        "failure_patterns": [],
        "high_risk_patterns": [],
        "round_notes": [],
        "do_not_repeat": [],
    }


def _merge_line_numbers(lines_a, lines_b, limit=12):
    merged = []
    for item in (lines_a or []) + (lines_b or []):
        try:
            val = int(item)
        except Exception:
            continue
        if val <= 0 or val in merged:
            continue
        merged.append(val)
        if len(merged) >= limit:
            break
    return merged


def _find_code_line_numbers_by_expr(code_text, expr_text, max_hits=6):
    code = str(code_text or "")
    expr = str(expr_text or "").strip()
    if not code or not expr:
        return []

    def norm(s):
        return re.sub(r"\s+", "", str(s or "")).lower()

    expr_norm = norm(expr)
    if len(expr_norm) < 4:
        return []

    lines = code.splitlines()
    hits = []
    for idx, line in enumerate(lines, start=1):
        if expr_norm in norm(line):
            hits.append(idx)
            if len(hits) >= max_hits:
                return hits

    tokens = [t.lower() for t in re.findall(r"[A-Za-z_]\w+", expr) if len(t) >= 3]
    if len(tokens) >= 2:
        for idx, line in enumerate(lines, start=1):
            line_lower = line.lower()
            if all(tok in line_lower for tok in tokens[:2]):
                hits.append(idx)
                if len(hits) >= max_hits:
                    break
    return _merge_line_numbers([], hits, limit=max_hits)


def _extract_expr_candidates_from_diagnosis(diagnosis):
    text = str(diagnosis or "")
    if not text:
        return []
    candidates = []
    for pat in (
        r"`([^`]{4,120})`",
        r"“([^”]{4,120})”",
        r'"([^"]{4,120})"',
        r"([A-Za-z_]\w*(?:\[[^\]]+\])?\s*=\s*[^,;\n]{3,120})",
    ):
        for m in re.finditer(pat, text):
            c = _normalize_text_line(m.group(1))
            if c and c not in candidates:
                candidates.append(c)
    return candidates[:8]


def _extract_line_numbers_from_text(text, max_hits=6):
    src = str(text or "")
    if not src:
        return []
    hits = []
    for pat in (
        r"\bline\s+(\d+)\b",
        r"\b第\s*(\d+)\s*行\b",
        r":(\d+):\d+",
        r":(\d+)\b",
    ):
        for m in re.finditer(pat, src, flags=re.IGNORECASE):
            try:
                val = int(m.group(1))
            except Exception:
                continue
            if val > 0 and val not in hits:
                hits.append(val)
            if len(hits) >= max_hits:
                return hits
    return hits


def _infer_high_risk_patterns(round_idx, diagnosis, eval_summary, latest_code):
    risks = []
    diag_text = str(diagnosis or "").strip()
    _ = eval_summary

    expr_candidates = _extract_expr_candidates_from_diagnosis(diag_text)
    diag_segments = [x.strip() for x in re.split(r"[。;；\n]", diag_text) if x.strip()]

    for seg in diag_segments[:4]:
        rule = _truncate_text(seg, limit=180)
        if not any(k in rule for k in ("必须", "禁止", "不要", "应当", "改为", "删除")):
            rule = f"必须修复：{rule}"
        lines = []
        for expr in expr_candidates[:3]:
            lines = _merge_line_numbers(lines, _find_code_line_numbers_by_expr(latest_code, expr), limit=8)
        if not lines:
            for expr in expr_candidates[:2]:
                lines = _merge_line_numbers(lines, _extract_line_numbers_from_text(expr), limit=8)
        risks.append({
            "rule": rule,
            "evidence": _truncate_text(seg, limit=180),
            "lines": lines,
            "source_round": int(round_idx),
        })

    deduped = []
    seen = set()
    for item in risks:
        if not isinstance(item, dict):
            continue
        rule = _normalize_text_line(item.get("rule"))
        if not rule:
            continue
        key = rule.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append({
            "rule": rule,
            "evidence": _truncate_text(item.get("evidence"), limit=180),
            "lines": _merge_line_numbers([], item.get("lines"), limit=12),
            "source_round": int(item.get("source_round") or round_idx),
        })
        if len(deduped) >= 8:
            break
    return deduped


def _build_failure_signature(eval_summary):
    if not isinstance(eval_summary, dict):
        return "unknown"

    status = str(eval_summary.get("status") or "Error").strip() or "Error"
    failed_points = eval_summary.get("failed_points") or []
    if not isinstance(failed_points, list):
        failed_points = []
    if not failed_points:
        return status

    parts = []
    for fp in failed_points[:4]:
        if not isinstance(fp, dict):
            continue
        fp_status = str(fp.get("status") or status).strip() or status
        stderr = _normalize_text_line(fp.get("stderr"))
        stdout = _normalize_text_line(fp.get("stdout"))
        raw = stderr or stdout
        if raw:
            lower = raw.lower()
            picked = ""
            for marker in ("error:", "traceback", "exception", "timeout", "segmentation"):
                idx = lower.find(marker)
                if idx >= 0:
                    picked = raw[idx:idx + 96]
                    break
            if not picked:
                picked = raw[:96]
            point_no = fp.get("index")
            if point_no:
                parts.append(f"#{point_no}:{fp_status}:{picked}")
            else:
                parts.append(f"{fp_status}:{picked}")
        else:
            parts.append(fp_status)

    if not parts:
        return status
    signature = f"{status} | {' | '.join(parts)}"
    signature = re.sub(r"\b\d+\b", "N", signature)
    return _truncate_text(signature, limit=220)


def _update_working_memory(working_memory, round_idx, diagnosis, eval_summary, latest_code):
    if not isinstance(working_memory, dict):
        working_memory = _init_working_memory()

    core_hints = working_memory.get("core_hints")
    if not isinstance(core_hints, list):
        core_hints = []
    patterns = working_memory.get("failure_patterns")
    if not isinstance(patterns, list):
        patterns = []
    high_risk_patterns = working_memory.get("high_risk_patterns")
    if not isinstance(high_risk_patterns, list):
        high_risk_patterns = []
    notes = working_memory.get("round_notes")
    if not isinstance(notes, list):
        notes = []
    do_not_repeat = working_memory.get("do_not_repeat")
    if not isinstance(do_not_repeat, list):
        do_not_repeat = []

    signature = _build_failure_signature(eval_summary)
    status = str((eval_summary or {}).get("status") or "Error")
    score = (eval_summary or {}).get("score", 0)
    added_pattern = False
    repeated_pattern = False

    existing = None
    for item in patterns:
        if isinstance(item, dict) and item.get("signature") == signature:
            existing = item
            break
    if existing:
        existing["count"] = int(existing.get("count") or 0) + 1
        existing["last_round"] = int(round_idx)
        existing["last_status"] = status
        repeated_pattern = existing["count"] > 1
    else:
        patterns.append({
            "signature": signature,
            "count": 1,
            "last_round": int(round_idx),
            "last_status": status,
        })
        added_pattern = True

    patterns = sorted(
        patterns,
        key=lambda x: (int((x or {}).get("count") or 0), int((x or {}).get("last_round") or 0)),
        reverse=True,
    )[:_AGENT_MEMORY_MAX_PATTERNS]

    note = {
        "round": int(round_idx),
        "status": status,
        "score": score,
        "signature": signature,
        "diagnosis": _truncate_text(diagnosis, limit=360) if diagnosis else "",
    }
    notes.append(note)
    notes = notes[-_AGENT_MEMORY_MAX_NOTES:]

    risk_candidates = _infer_high_risk_patterns(
        round_idx=round_idx,
        diagnosis=diagnosis,
        eval_summary=eval_summary,
        latest_code=latest_code,
    )
    for risk in risk_candidates:
        rule_key = _normalize_text_line(risk.get("rule")).lower()
        if not rule_key:
            continue
        matched = None
        for saved in high_risk_patterns:
            if not isinstance(saved, dict):
                continue
            if _normalize_text_line(saved.get("rule")).lower() == rule_key:
                matched = saved
                break
        if matched:
            matched["hit_count"] = int(matched.get("hit_count") or 0) + 1
            matched["last_round"] = int(round_idx)
            matched["lines"] = _merge_line_numbers(matched.get("lines"), risk.get("lines"), limit=12)
            if risk.get("evidence"):
                matched["evidence"] = _truncate_text(risk.get("evidence"), limit=180)
        else:
            high_risk_patterns.append({
                "rule": _truncate_text(risk.get("rule"), limit=220),
                "evidence": _truncate_text(risk.get("evidence"), limit=180),
                "lines": _merge_line_numbers([], risk.get("lines"), limit=12),
                "source_round": int(risk.get("source_round") or round_idx),
                "last_round": int(round_idx),
                "hit_count": 1,
            })

    high_risk_patterns = sorted(
        high_risk_patterns,
        key=lambda x: (int((x or {}).get("hit_count") or 0), int((x or {}).get("last_round") or 0)),
        reverse=True,
    )[:_AGENT_MEMORY_MAX_PATTERNS]

    regenerated_rules = []
    for risk in high_risk_patterns[:_AGENT_MEMORY_MAX_DO_NOT_REPEAT]:
        if not isinstance(risk, dict):
            continue
        rule = _normalize_text_line(risk.get("rule"))
        if not rule:
            continue
        lines = risk.get("lines") if isinstance(risk.get("lines"), list) else []
        if lines:
            line_text = ",".join([str(x) for x in lines[:6]])
            regenerated_rules.append(f"{rule}（重点检查行: {line_text}）")
        else:
            regenerated_rules.append(rule)
    do_not_repeat = _dedupe_keep_order(regenerated_rules)[-_AGENT_MEMORY_MAX_DO_NOT_REPEAT:]

    working_memory["core_hints"] = _dedupe_keep_order(core_hints)[:8]
    working_memory["failure_patterns"] = patterns
    working_memory["high_risk_patterns"] = high_risk_patterns
    working_memory["round_notes"] = notes
    working_memory["do_not_repeat"] = do_not_repeat

    return {
        "signature": signature,
        "added_pattern": added_pattern,
        "repeated_pattern": repeated_pattern,
        "pattern_count": len(patterns),
        "high_risk_count": len(high_risk_patterns),
        "do_not_repeat_count": len(do_not_repeat),
    }


def _compact_working_memory_for_attempt(working_memory):
    if not isinstance(working_memory, dict):
        return {}
    core_hints = working_memory.get("core_hints")
    if not isinstance(core_hints, list):
        core_hints = []
    patterns = working_memory.get("failure_patterns")
    if not isinstance(patterns, list):
        patterns = []
    high_risk_patterns = working_memory.get("high_risk_patterns")
    if not isinstance(high_risk_patterns, list):
        high_risk_patterns = []
    do_not_repeat = working_memory.get("do_not_repeat")
    if not isinstance(do_not_repeat, list):
        do_not_repeat = []
    notes = working_memory.get("round_notes")
    if not isinstance(notes, list):
        notes = []
    return {
        "core_hints": core_hints[:4],
        "high_risk_patterns": high_risk_patterns[:6],
        "failure_patterns": patterns[:4],
        "do_not_repeat": do_not_repeat[-6:],
        "round_notes": notes[-3:],
    }


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


def _summarize_history_with_qwen35(history_messages, target_chars, state=None, round_idx=None, event_label="历史摘要"):
    if not isinstance(history_messages, list) or not history_messages:
        return ""

    messages = _safe_json_copy(history_messages, default=[])
    if not isinstance(messages, list):
        messages = []
    messages.append({
        "role": "user",
        "content": f"生成历史摘要，限制字数：{int(target_chars)}",
    })

    request_body = _build_api_request_payload(messages, model=QWEN_TEXT_MODEL)
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
        summary = _call_qwen3_5_plus_text(messages, timeout=_AGENT_CONTEXT_SUMMARY_TIMEOUT)
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


def _trim_conversation_by_budget(conversation, max_chars, keep_rounds, state=None, round_idx=None):
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
    summary_budget = min(_AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS, max(600, int(max_chars * 0.9)))
    full_summary = _summarize_history_with_qwen35(
        cleaned,
        target_chars=summary_budget,
        state=state,
        round_idx=round_idx,
        event_label="全量历史摘要",
    )
    if full_summary:
        return [{
            "role": "assistant",
            "content": "【历史信息摘要（qwen3.5-plus）】\n" + full_summary,
        }]
    return cleaned


def _build_conversation_messages(
    conversation,
    round_idx,
    working_memory,
    latest_submission_id=None,
    latest_summary=None,
    last_ai_tutor_feedback="",
):
    system_lines = [
        "你现在是一个可调用工具的 OJ 自主 Agent。",
        "请自行决策并调用工具迭代解题。",
        "代码仓库里有提前准备好的头文件，如有需要可以通过 #include \"文件名\" 直接引用",
        "目标：产出能通过评测的代码。",
        "要求：1. 不要臆造代码仓库文件或评测结果。 2. 题目给的的提示非常重要，请一定要参考题目提示来完成或者修复代码。",
    ]
    if _AGENT_MEMORY_ENABLED and isinstance(working_memory, dict):
        core_hints = working_memory.get("core_hints")
        if isinstance(core_hints, list) and core_hints:
            system_lines.append("题目硬约束（必须满足）：")
            for item in core_hints[:8]:
                system_lines.append(f"- {str(item)}")
    if latest_submission_id:
        system_lines.append(f"最近一次 submission_id: {latest_submission_id}")
    if isinstance(latest_summary, dict):
        system_lines.append(
            "最近评测摘要："
            f"status={latest_summary.get('status')} "
            f"score={latest_summary.get('score')} "
            f"passed={latest_summary.get('accepted_count')}/{latest_summary.get('total_count')}"
        )
    if last_ai_tutor_feedback:
        system_lines.append("最近 AI 助教建议（可参考）：")
        system_lines.append(_truncate_text(last_ai_tutor_feedback, limit=600))
    system_lines.append(f"当前推理轮次：{int(round_idx)}")

    return [{"role": "system", "content": "\n".join(system_lines)}] + list(conversation or [])


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
        return {"timeout": False, "completed": True, **_summarize_submission(latest)}

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
                    return {"timeout": False, "completed": True, **_summarize_submission(latest)}
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
                return {"timeout": False, "completed": True, **_summarize_submission(latest)}
        time.sleep(1.0)

    return {"timeout": True, "completed": False, **_summarize_submission(latest)}


def _tool_list_repository_files(user_id, limit=200):
    safe_limit = _clamp_int(limit, 200, min_value=1, max_value=500)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, filename, file_size, created_at, updated_at
                FROM user_code_repository
                WHERE user_id = %s
                ORDER BY filename
                LIMIT %s
                """,
                (user_id, safe_limit),
            )
            rows = cursor.fetchall() or []
            files = []
            for row in rows:
                item = {
                    "id": row.get("id"),
                    "filename": row.get("filename"),
                    "file_size": row.get("file_size", 0),
                    "file_size_kb": round(float(row.get("file_size", 0) or 0) / 1024.0, 2),
                }
                created_at = row.get("created_at")
                updated_at = row.get("updated_at")
                item["created_at"] = created_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(created_at, "strftime") else str(created_at or "")
                item["updated_at"] = updated_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(updated_at, "strftime") else str(updated_at or "")
                files.append(item)
            return files
    finally:
        conn.close()


def _detect_repo_file_language(filename):
    lower = str(filename or "").strip().lower()
    if lower.endswith((".h", ".hpp", ".hh", ".hxx", ".c", ".cc", ".cpp", ".cxx")):
        return "cpp"
    if lower.endswith(".py"):
        return "python"
    if lower.endswith(".m"):
        return "matlab"
    return "text"


def _is_header_file(filename):
    lower = str(filename or "").strip().lower()
    return lower.endswith((".h", ".hpp", ".hh", ".hxx"))


def _extract_interfaces_from_header_text(content, max_items=120):
    safe_max = _clamp_int(max_items, 120, min_value=10, max_value=500)
    text = str(content or "")
    lines = text.splitlines()
    rows = []
    for idx, raw in enumerate(lines, start=1):
        line = str(raw or "").strip()
        if not line or line.startswith("//"):
            continue
        cls = re.match(r'^\s*(class|struct)\s+([A-Za-z_]\w*)\b', line)
        if cls:
            rows.append({
                "kind": str(cls.group(1)),
                "name": str(cls.group(2)),
                "signature": _truncate_text(line, limit=300),
                "purpose": "",
                "line": idx,
            })
            if len(rows) >= safe_max:
                break
            continue
        fn = re.match(
            r'^\s*(?:template\s*<[^>]+>\s*)?(?:[\w:\<\>\~\*&\s]+?)\s+([A-Za-z_~]\w*(?:::\w+)*)\s*\([^;{}]*\)\s*(?:const\b)?\s*(?:noexcept\b)?\s*(?:->\s*[^;{]+)?\s*;\s*$',
            line,
        )
        if fn:
            rows.append({
                "kind": "function",
                "name": str(fn.group(1)),
                "signature": _truncate_text(line, limit=300),
                "purpose": "",
                "line": idx,
            })
            if len(rows) >= safe_max:
                break
            continue
        if line.startswith("using ") and line.endswith(";"):
            rows.append({
                "kind": "using",
                "name": "",
                "signature": _truncate_text(line, limit=300),
                "purpose": "",
                "line": idx,
            })
            if len(rows) >= safe_max:
                break
            continue
        if line.startswith("typedef ") and line.endswith(";"):
            rows.append({
                "kind": "typedef",
                "name": "",
                "signature": _truncate_text(line, limit=300),
                "purpose": "",
                "line": idx,
            })
            if len(rows) >= safe_max:
                break
            continue
    return rows


def _normalize_model_plain_code(text, language):
    raw = str(text or "").strip()
    if not raw:
        return ""
    stripped = _extract_code_from_model_reply(raw, language)
    return str(stripped or raw).strip()


def _analyze_repository_file_for_agent(filename, content, max_output_chars=12000, max_interfaces=120):
    safe_output_chars = _clamp_int(max_output_chars, 12000, min_value=200, max_value=50000)
    safe_max_interfaces = _clamp_int(max_interfaces, 120, min_value=10, max_value=500)
    raw_content = str(content or "")
    language = _detect_repo_file_language(filename)
    is_header = _is_header_file(filename)

    safe_input_chars = min(120000, max(8000, safe_output_chars * 4))
    source_truncated = len(raw_content) > safe_input_chars
    if source_truncated:
        half = safe_input_chars // 2
        model_input = (
            raw_content[:half]
            + "\n\n/* ... 文件内容过长，中间部分已省略 ... */\n\n"
            + raw_content[-half:]
        )
    else:
        model_input = raw_content

    if is_header:
        system_prompt = (
            "你是 C/C++ 头文件清理助手。"
            "你的输出必须仍然是一个可读的头文件文本。"
            "禁止输出 JSON，禁止输出解释，禁止输出 Markdown 代码块。"
        )
        user_prompt = (
            f"文件名：{filename}\n"
            "请将下面这个头文件处理成“仅接口定义”的形式：\n"
            "1) 删除/改写函数实现，只保留声明（例如 `int f(){...}` 改为 `int f();`）。\n"
            "2) 给每个函数声明和 class/struct 增加一条简短注释说明用途。\n"
            "3) 若原文件已有注释，保留原注释文本，不要删除或改写。\n"
            "4) 保留原有 include、宏、命名空间、类结构和接口签名。\n"
            "5) 只输出处理后的头文件文本，不要其它内容。\n\n"
            "原文件内容：\n"
            f"{model_input}"
        )
    else:
        system_prompt = (
            "你是代码文件精简助手。"
            "禁止输出 JSON，禁止输出解释，禁止输出 Markdown 代码块。"
        )
        user_prompt = (
            f"文件名：{filename}\n"
            "请输出这个文件的“接口导向视图”：保留可调用接口、类型定义与必要注释，"
            "省略与接口无关的实现细节。若已有注释则保留原注释。"
            "只输出处理后的代码文本，不要其它内容。\n\n"
            "原文件内容：\n"
            f"{model_input}"
        )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    model_text = _call_qwen3_5_flash_text(messages, timeout=120, enable_thinking=False)
    processed_content = _normalize_model_plain_code(model_text, language)
    if not processed_content:
        raise RuntimeError("文件分析失败：模型未返回可用内容。")

    interfaces = _extract_interfaces_from_header_text(processed_content, max_items=safe_max_interfaces)
    output_truncated = len(processed_content) > safe_output_chars
    summary = f"已使用 {AI_TUTOR_MODEL} 生成接口导向视图，识别到 {len(interfaces)} 个接口符号"
    return {
        "analysis_model": AI_TUTOR_MODEL,
        "analysis_enable_thinking": False,
        "language": language,
        "is_header": is_header,
        "summary": _truncate_text(summary, limit=1200),
        "interfaces": interfaces,
        "source_truncated_for_analysis": source_truncated,
        "processed_content": _truncate_text(processed_content, limit=safe_output_chars),
        "processed_truncated": output_truncated,
    }


def _load_repository_file_row(user_id, filename="", file_id=None):
    use_filename = str(filename or "").strip()
    use_file_id = None
    try:
        if file_id is not None and str(file_id).strip() != "":
            use_file_id = int(file_id)
    except Exception:
        use_file_id = None
    if not use_filename and use_file_id is None:
        raise RuntimeError("filename 与 file_id 至少提供一个。")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if use_file_id is not None:
                cursor.execute(
                    """
                    SELECT id, filename, file_content, file_size
                    FROM user_code_repository
                    WHERE id = %s AND user_id = %s
                    LIMIT 1
                    """,
                    (use_file_id, user_id),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, filename, file_content, file_size
                    FROM user_code_repository
                    WHERE filename = %s AND user_id = %s
                    LIMIT 1
                    """,
                    (use_filename, user_id),
                )
            row = cursor.fetchone()
    finally:
        conn.close()

    if not row:
        raise RuntimeError("目标文件不存在。")
    return row


def _tool_read_repository_file(user_id, filename="", file_id=None, max_chars=12000):
    safe_max_chars = _clamp_int(max_chars, 12000, min_value=200, max_value=50000)
    row = _load_repository_file_row(user_id=user_id, filename=filename, file_id=file_id)
    content = str(row.get("file_content") or "")
    analyzed = _analyze_repository_file_for_agent(
        filename=row.get("filename"),
        content=content,
        max_output_chars=safe_max_chars,
        max_interfaces=120,
    )
    return str(analyzed.get("processed_content") or "")


def _tool_read_repository_file_full(user_id, filename="", file_id=None):
    row = _load_repository_file_row(user_id=user_id, filename=filename, file_id=file_id)
    return str(row.get("file_content") or "")


def _tool_update_repository_file(user_id, content, filename="", file_id=None):
    new_content = str(content or "")
    use_filename = str(filename or "").strip()
    use_file_id = None
    try:
        if file_id is not None and str(file_id).strip() != "":
            use_file_id = int(file_id)
    except Exception:
        use_file_id = None
    if not use_filename and use_file_id is None:
        raise RuntimeError("filename 与 file_id 至少提供一个。")

    file_size = len(new_content.encode("utf-8"))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if use_file_id is not None:
                cursor.execute(
                    """
                    UPDATE user_code_repository
                    SET file_content = %s, file_size = %s
                    WHERE id = %s AND user_id = %s
                    """,
                    (new_content, file_size, use_file_id, user_id),
                )
                if cursor.rowcount == 0:
                    raise RuntimeError("目标文件不存在。")
                cursor.execute(
                    """
                    SELECT id, filename
                    FROM user_code_repository
                    WHERE id = %s AND user_id = %s
                    LIMIT 1
                    """,
                    (use_file_id, user_id),
                )
                row = cursor.fetchone() or {}
            else:
                cursor.execute(
                    """
                    UPDATE user_code_repository
                    SET file_content = %s, file_size = %s
                    WHERE filename = %s AND user_id = %s
                    """,
                    (new_content, file_size, use_filename, user_id),
                )
                if cursor.rowcount == 0:
                    raise RuntimeError("目标文件不存在。")
                cursor.execute(
                    """
                    SELECT id, filename
                    FROM user_code_repository
                    WHERE filename = %s AND user_id = %s
                    LIMIT 1
                    """,
                    (use_filename, user_id),
                )
                row = cursor.fetchone() or {}
            conn.commit()
            return {
                "id": row.get("id"),
                "filename": row.get("filename"),
                "file_size": file_size,
                "updated": True,
            }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _tool_search_repository(user_id, pattern, max_files=500, max_matches=120):
    expr = str(pattern or "").strip()
    if not expr:
        raise RuntimeError("pattern 不能为空。")
    safe_max_files = _clamp_int(max_files, 500, min_value=1, max_value=1000)
    safe_max_matches = _clamp_int(max_matches, 120, min_value=1, max_value=1000)
    try:
        regex = re.compile(expr, flags=re.MULTILINE)
    except re.error as e:
        raise RuntimeError(f"正则表达式无效: {e}") from e

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, filename, file_content
                FROM user_code_repository
                WHERE user_id = %s
                ORDER BY filename
                LIMIT %s
                """,
                (user_id, safe_max_files),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()

    matched = []
    for row in rows:
        filename = str(row.get("filename") or "")
        content = str(row.get("file_content") or "")
        for m in regex.finditer(content):
            start = int(m.start())
            end = int(m.end())
            line_no = content.count("\n", 0, start) + 1
            last_nl = content.rfind("\n", 0, start)
            col_no = start + 1 if last_nl < 0 else (start - last_nl)
            snippet_left = max(0, start - 60)
            snippet_right = min(len(content), end + 60)
            snippet = content[snippet_left:snippet_right]
            snippet = snippet.replace("\r", "")
            matched.append({
                "file_id": row.get("id"),
                "filename": filename,
                "line": int(line_no),
                "column": int(col_no),
                "match_text": _truncate_text(m.group(0), limit=160),
                "snippet": _truncate_text(snippet, limit=280),
            })
            if len(matched) >= safe_max_matches:
                break
        if len(matched) >= safe_max_matches:
            break

    return {
        "pattern": expr,
        "scanned_files": len(rows),
        "match_count": len(matched),
        "matches": matched,
    }


def _tool_get_knowledge(question, max_chars=1800):
    query = str(question or "").strip()
    if not query:
        raise RuntimeError("question 不能为空。")
    safe_max_chars = _clamp_int(max_chars, 1800, min_value=300, max_value=6000)
    messages = [
        {
            "role": "system",
            "content": (
                "你是领域知识专家，职责是回答知识性问题，模拟联网搜索后的专家答复。"
            ),
        },
        {"role": "user", "content": query},
    ]
    answer = _call_qwen3_5_plus_text(messages, timeout=120)
    return {
        "question": query,
        "answer": _truncate_text(answer, limit=safe_max_chars),
    }


def _tool_planning(messages):
    if not isinstance(messages, list) or not messages:
        raise RuntimeError("planning 缺少可用 messages。")
    plan_messages = _safe_json_copy(messages, default=[])
    if not isinstance(plan_messages, list):
        plan_messages = []
    plan_messages.append({
        "role": "user",
        "content": "请为我生成一个可执行的代码计划，帮助我完成这道编程题。请充分利用我给你提供的代码仓库，将计划描述清楚。你可以使用自然语言，也可以使用代码语言，也可以二者混杂，总之就是要清晰地表述完成这道编程题的计划",
    })
    plan_text = _call_qwen3_5_plus_text(plan_messages, timeout=120, enable_thinking=True)
    return {
        "plan": str(plan_text or ""),
    }


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


def _build_agent_react_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "read_latest_code",
                "description": "读取当前保存的最新代码。",
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "update_code",
                "description": "更新当前最新代码。默认整段替换。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "完整代码文本"},
                        "note": {"type": "string", "description": "本次修改说明"},
                    },
                    "required": ["code"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_evaluation",
                "description": "提交当前代码到评测系统并等待评测结果。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "可选。若提供则先覆盖当前代码再提交"},
                        "timeout_seconds": {"type": "integer", "description": "等待评测超时时间，默认 300 秒"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_repository_files",
                "description": "读取当前用户代码仓库文件列表。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "description": "最多返回多少个文件，默认 200"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_repository_file",
                "description": "读取用户代码仓库中的单个文件，返回精简后的代码，只包含函数声明与注释，不包含实现",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string", "description": "文件名"},
                        "file_id": {"type": "integer", "description": "文件 id，和 filename 二选一"},
                        "max_chars": {"type": "integer", "description": "返回内容最大字符数，默认 12000"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_repository_file_full",
                "description": "读取用户代码仓库中的单个文件原文全文（包含完整函数实现，不做精简，请你只在必要时调用这个函数）。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string", "description": "文件名"},
                        "file_id": {"type": "integer", "description": "文件 id，和 filename 二选一"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "update_repository_file",
                "description": "修改用户代码仓库中的单个文件内容。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string", "description": "文件名"},
                        "file_id": {"type": "integer", "description": "文件 id，和 filename 二选一"},
                        "content": {"type": "string", "description": "新的完整文件内容"},
                    },
                    "required": ["content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_repository",
                "description": "你可以构造正则表达式，在用户代码仓库全部文件中按正则表达式搜索，函数会返回搜索结果。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "正则表达式"},
                        "max_files": {"type": "integer", "description": "最多扫描的文件数，默认 500"},
                        "max_matches": {"type": "integer", "description": "最多返回匹配条目数，默认 120"},
                    },
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_knowledge",
                "description": "向专家咨询知识性问题。专家只回答知识，不做代码调试。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "question": {"type": "string", "description": "要咨询的知识问题"},
                        "max_chars": {"type": "integer", "description": "回答最大字符数，默认 1800"},
                    },
                    "required": ["question"],
                },
            },
        },
        # {
        #     "type": "function",
        #     "function": {
        #         "name": "planning",
        #         "description": "向一个很厉害的专家询问执行计划。",
        #         "parameters": {
        #             "type": "object",
        #             "properties": {},
        #         },
        #     },
        # },
    ]


def _build_initial_prompt(problem, core_hints=None, repository_filenames=None):
    lang = (problem.get("lang") or "matlab").lower()
    initial_code = (problem.get("initial_code") or "").strip()
    title = str(problem.get("title", "") or "").strip()
    content = str(problem.get("content", "") or "").strip()
    hint_lines = _dedupe_keep_order(core_hints or [])[:8]
    lines = [
        f"我现在要用 {lang} 语言写一道编程题，题目标题是 {title}，题目描述如下：",
        content,
    ]
    if initial_code:
        lines.extend([
            "",
            "题目提供了模板，请基于这个模板补全可运行的代码：",
            f"```{lang}",
            initial_code,
            "```",
        ])
    if hint_lines:
        hint_text = "\n".join([f"- {h}" for h in hint_lines])
        lines.extend([
            "",
            "出题人善意地给了一些提示：",
            hint_text,
            "在你决策的过程中，请首先考虑这些提示，确保提示里的每条内容你都做到了。我重复一遍这些提示：",
            hint_text,
        ])
    repo_names = []
    for item in (repository_filenames or []):
        name = str(item or "").strip()
        if name:
            repo_names.append(name)
    repo_names = _dedupe_keep_order(repo_names)[:200]
    repo_list_text = "\n".join([f"- {name}" for name in repo_names]) if repo_names else "- （暂无文件）"
    lines.extend([
        "",
        "我的代码仓库里目前有这些文件：",
        repo_list_text,
        "你可以通过 #include \"文件名\" 引用它们，然后就可以直接使用里面提供的函数。",
        "请首先确认我的代码仓库里有没有适用于本题的工具，在确认代码仓库里没有可用工具之后，再自己写代码，避免重复造轮子。",
        "请仔细阅读我的代码仓库里的注释，确保你理解了我提供的代码仓库里的代码是做什么用的。",
        # "当你理解了任务意图，并完全理解了我提供的已有工具之后，请向专家询问计划，并按照计划完成代码。",
    ])
    return "\n".join(lines).strip()


def register_agent_solve_problem_task(celery_app, evaluate_submission_task):
    existing = celery_app.tasks.get(AGENT_SOLVE_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(bind=True, name=AGENT_SOLVE_TASK_NAME, time_limit=1800, soft_time_limit=1680)
    def agent_solve_problem(self, problem_id, requested_by):
        task_id = str((getattr(getattr(self, "request", None), "id", None) or "")).strip()
        if not task_id:
            task_id = f"unknown-{int(time.time())}"

        try:
            cfg_rounds = int(AGENT_MAX_ROUNDS)
        except Exception:
            cfg_rounds = 8
        max_rounds = max(1, cfg_rounds)
        max_tool_calls = max(8, max_rounds * 8)

        state = {
            "task_id": task_id,
            "problem_id": int(problem_id),
            "problem_title": "",
            "requested_by": requested_by,
            "status": "Running",
            "message": "Agent 任务启动中",
            "round": 0,
            "max_rounds": max_rounds,
            "best_score": 0,
            "latest_submission_id": None,
            "final_submission_id": None,
            "attempts": [],
            "events": [],
            "api_calls": [],
            "working_memory": _init_working_memory() if _AGENT_MEMORY_ENABLED else {},
            "updated_at": _format_local_time(),
        }
        _push_agent_event(state, "Agent 任务已启动")

        user = get_user_by_username(requested_by)
        if not user or user.get("is_admin") != 1:
            _push_agent_event(state, "无权限执行 Agent 任务", level="error", status="Failed")
            return {
                "success": False,
                "message": "无权限执行 Agent 任务",
                "task_id": task_id,
            }

        problem = get_problem(problem_id)
        if not problem:
            _push_agent_event(state, "题目不存在", level="error", status="Failed")
            return {"success": False, "message": "题目不存在", "task_id": task_id}
        if int(problem.get("type") or 1) != 1:
            _push_agent_event(state, "仅支持编程题", level="error", status="Failed")
            return {"success": False, "message": "仅支持编程题", "task_id": task_id}
        if evaluate_submission_task is None:
            _push_agent_event(state, "评测任务未初始化", level="error", status="Failed")
            return {"success": False, "message": "评测任务未初始化", "task_id": task_id}

        _push_agent_event(
            state,
            f"开始解题：{problem.get('title', '')}",
            problem_id=problem.get("id"),
            problem_title=problem.get("title"),
        )

        attempts = []
        final_submission_id = None
        core_hints = _extract_problem_hints(problem)
        working_memory = _init_working_memory(core_hints=core_hints)
        state["working_memory"] = working_memory
        if core_hints:
            _push_agent_event(
                state,
                f"已提取题目提示 {len(core_hints)} 条，并作为最高优先级记忆",
                event_type="core_hints",
                details={"core_hints": core_hints},
            )

        latest_code = str(problem.get("initial_code") or "")
        runtime = {
            "latest_code": latest_code,
            "latest_submission_id": None,
            "latest_summary": None,
            "last_ai_tutor_feedback": "",
            "submission_code_map": {},
            "accepted": False,
        }

        if latest_code.strip():
            _push_agent_event(
                state,
                f"检测到题目初始代码，长度={len(latest_code)} 字符",
                event_type="initial_code",
            )

        repository_filenames = []
        try:
            repo_rows = _tool_list_repository_files(user_id=user["id"], limit=200)
            if isinstance(repo_rows, list):
                for row in repo_rows:
                    if isinstance(row, dict):
                        name = str(row.get("filename") or "").strip()
                        if name:
                            repository_filenames.append(name)
            if repository_filenames:
                _push_agent_event(
                    state,
                    f"已读取代码仓库文件列表，共 {len(repository_filenames)} 个文件",
                    event_type="repository_files",
                )
        except Exception as repo_err:
            _push_agent_event(
                state,
                f"读取代码仓库文件列表失败: {repo_err}",
                level="warning",
                event_type="repository_files_error",
            )

        conversation = [{
            "role": "user",
            "content": _build_initial_prompt(
                problem,
                core_hints=core_hints,
                repository_filenames=repository_filenames,
            ),
        }]
        tools = _build_agent_react_tools()
        total_tool_calls = 0

        for round_idx in range(1, max_rounds + 1):
            state["round"] = round_idx
            before_chars = _conversation_total_chars(conversation)
            trimmed_conversation = _trim_conversation_by_budget(
                conversation,
                max_chars=_AGENT_CONTEXT_MAX_CHARS,
                keep_rounds=_AGENT_CONTEXT_KEEP_ROUNDS,
                state=state,
                round_idx=round_idx,
            )
            if trimmed_conversation != conversation:
                conversation = trimmed_conversation
                _push_agent_event(
                    state,
                    (
                        f"上下文裁剪：{before_chars} -> {_conversation_total_chars(conversation)} 字符，"
                        f"保留消息数={len(conversation)}"
                    ),
                )
            messages = _build_conversation_messages(
                conversation,
                round_idx=round_idx,
                working_memory=working_memory,
                latest_submission_id=runtime.get("latest_submission_id"),
                latest_summary=runtime.get("latest_summary"),
                last_ai_tutor_feedback=runtime.get("last_ai_tutor_feedback") or "",
            )
            api_request_body = _build_api_request_payload(messages, tools=tools)
            _append_api_call_log(state, round_idx, api_request_body, api_type="solve")
            _push_agent_event(
                state,
                f"第 {round_idx}/{max_rounds} 轮：ReAct 决策中",
                round=round_idx,
                event_type="api_request",
                details={
                    "round": round_idx,
                    "api_type": "solve",
                    "request_body": api_request_body,
                },
            )

            try:
                assistant_output = _call_qwen3_coder_plus_with_tools(messages, tools=tools)
            except Exception as e:
                msg = f"第 {round_idx} 轮模型调用失败: {e}"
                _push_agent_event(state, msg, level="error", status="Failed")
                return {
                    "success": False,
                    "message": msg,
                    "task_id": task_id,
                    "attempts": attempts,
                }

            assistant_text = str(assistant_output.get("content") or "").strip()
            tool_calls = assistant_output.get("tool_calls") if isinstance(assistant_output.get("tool_calls"), list) else []

            assistant_message = {"role": "assistant", "content": assistant_text}
            if tool_calls:
                assistant_message["tool_calls"] = _safe_json_copy(tool_calls, default=[])
            conversation.append(assistant_message)

            if assistant_text:
                _push_agent_event(state, f"第 {round_idx} 轮模型回复：{_truncate_text(assistant_text, limit=200)}")

            if not tool_calls:
                _push_agent_event(state, f"第 {round_idx} 轮未调用工具")
                break

            for tool_call in tool_calls:
                if total_tool_calls >= max_tool_calls:
                    break
                total_tool_calls += 1

                call_id = str(tool_call.get("id") or "").strip()
                if not call_id:
                    call_id = f"tool_call_{round_idx}_{total_tool_calls}"
                function_data = tool_call.get("function") if isinstance(tool_call.get("function"), dict) else {}
                func_name = str((function_data or {}).get("name") or "").strip()
                arguments = _safe_load_tool_arguments((function_data or {}).get("arguments"))

                _push_agent_event(
                    state,
                    f"第 {round_idx} 轮调用工具：{func_name}",
                    event_type="tool_call",
                    details={
                        "round": round_idx,
                        "tool_name": func_name,
                        "tool_call_id": call_id,
                        "arguments": arguments,
                        "model_tool_call": _safe_json_copy(tool_call, default={}),
                    },
                )

                tool_result = {"success": False, "message": f"未知工具：{func_name}"}
                try:
                    if func_name == "read_latest_code":
                        code_text = str(runtime.get("latest_code") or "")
                        tool_result = {
                            "success": True,
                            "has_code": bool(code_text.strip()),
                            "language": (problem.get("lang") or "matlab").lower(),
                            "chars": len(code_text),
                            "latest_code": code_text,
                        }
                    elif func_name == "update_code":
                        code_text = str(arguments.get("code") or "")
                        if not code_text.strip():
                            raise RuntimeError("code 不能为空。")
                        runtime["latest_code"] = code_text
                        tool_result = {
                            "success": True,
                            "message": "代码已更新",
                            "chars": len(code_text),
                            "note": _truncate_text(arguments.get("note"), limit=200),
                        }
                    elif func_name == "submit_evaluation":
                        if arguments.get("code") is not None:
                            incoming_code = str(arguments.get("code") or "")
                            if incoming_code.strip():
                                runtime["latest_code"] = incoming_code
                        code_text = str(runtime.get("latest_code") or "")
                        if not code_text.strip():
                            raise RuntimeError("当前没有可提交代码，请先调用 update_code。")

                        timeout_seconds = _clamp_int(arguments.get("timeout_seconds"), 300, min_value=60, max_value=900)
                        submission_id = _tool_submit_code(problem, requested_by, code_text, evaluate_submission_task)
                        final_submission_id = submission_id
                        runtime["latest_submission_id"] = submission_id
                        runtime["submission_code_map"][str(submission_id)] = code_text
                        _push_agent_event(
                            state,
                            f"第 {round_idx} 轮已提交，submission_id={submission_id}",
                            latest_submission_id=submission_id,
                            final_submission_id=submission_id,
                        )

                        summary = _tool_query_test_results(submission_id, timeout_seconds=timeout_seconds)
                        compact_summary = _compact_summary(summary)
                        runtime["latest_summary"] = compact_summary
                        is_accepted = str(compact_summary.get("status") or "").strip() == "Accepted"
                        runtime["accepted"] = is_accepted

                        diag = _extract_retry_diagnosis(assistant_text) or _truncate_text(assistant_text, limit=360)
                        failure_signature = _build_failure_signature(compact_summary)
                        attempt_item = {
                            "round": len(attempts) + 1,
                            "model_round": round_idx,
                            "submission_id": submission_id,
                            "summary": compact_summary,
                            "diagnosis": diag,
                            "failure_signature": failure_signature,
                            "api_request_body": api_request_body,
                        }
                        attempts.append(attempt_item)
                        state["attempts"] = attempts

                        if _AGENT_MEMORY_ENABLED:
                            memory_delta = _update_working_memory(
                                working_memory,
                                round_idx=round_idx,
                                diagnosis=diag,
                                eval_summary=compact_summary,
                                latest_code=code_text,
                            )
                            state["working_memory"] = working_memory
                            attempts[-1]["memory"] = _compact_working_memory_for_attempt(working_memory)
                            _push_agent_event(
                                state,
                                (
                                    f"工作记忆更新：signature={memory_delta.get('signature')} "
                                    f"patterns={memory_delta.get('pattern_count')} "
                                    f"high_risk={memory_delta.get('high_risk_count')} "
                                    f"do_not_repeat={memory_delta.get('do_not_repeat_count')}"
                                ),
                            )

                        _push_agent_event(
                            state,
                            (
                                f"第 {round_idx} 轮评测完成："
                                f"状态={compact_summary.get('status')} 分数={compact_summary.get('score')}"
                            ),
                            latest_submission_id=submission_id,
                            final_submission_id=submission_id,
                        )

                        if summary.get("timeout"):
                            _push_agent_event(
                                state,
                                f"第 {round_idx} 轮评测等待超时",
                                level="warning",
                                event_type="judge_timeout",
                                details={"round": round_idx, "submission_id": submission_id},
                            )

                        if is_accepted:
                            msg = "任务已成功完成"
                            _push_agent_event(
                                state,
                                f"第 {round_idx} 轮提交已通过全部测试点，结束任务",
                                level="success",
                                status="Completed",
                                event_type="accepted",
                                details={
                                    "round": round_idx,
                                    "submission_id": submission_id,
                                    "status": compact_summary.get("status"),
                                    "score": compact_summary.get("score"),
                                },
                                final_submission_id=submission_id,
                            )
                            return {
                                "success": True,
                                "message": msg,
                                "task_id": task_id,
                                "final_submission_id": submission_id,
                                "attempts": attempts,
                            }

                        tool_result = {
                            "success": True,
                            "submission_id": submission_id,
                            "timeout": bool(summary.get("timeout")),
                            "completed": bool(summary.get("completed")),
                            "test_points": summary.get("test_points") or [],
                            **compact_summary,
                        }
                    elif func_name == "ask_ai_tutor":
                        tool_result = {
                            "success": False,
                            "disabled": True,
                            "message": "ask_ai_tutor 功能暂时禁用",
                        }
                    elif func_name == "list_repository_files":
                        files = _tool_list_repository_files(
                            user_id=user["id"],
                            limit=arguments.get("limit", 200),
                        )
                        tool_result = {"success": True, "count": len(files), "files": files}
                    elif func_name == "read_repository_file":
                        file_content = _tool_read_repository_file(
                            user_id=user["id"],
                            filename=arguments.get("filename", ""),
                            file_id=arguments.get("file_id"),
                            max_chars=arguments.get("max_chars", 12000),
                        )
                        tool_result = {"success": True, "content": file_content}
                    elif func_name == "read_repository_file_full":
                        file_content = _tool_read_repository_file_full(
                            user_id=user["id"],
                            filename=arguments.get("filename", ""),
                            file_id=arguments.get("file_id"),
                        )
                        tool_result = {"success": True, "content": file_content}
                    elif func_name == "update_repository_file":
                        updated = _tool_update_repository_file(
                            user_id=user["id"],
                            filename=arguments.get("filename", ""),
                            file_id=arguments.get("file_id"),
                            content=arguments.get("content", ""),
                        )
                        tool_result = {"success": True, **updated}
                    elif func_name == "search_repository":
                        result = _tool_search_repository(
                            user_id=user["id"],
                            pattern=arguments.get("pattern", ""),
                            max_files=arguments.get("max_files", 500),
                            max_matches=arguments.get("max_matches", 120),
                        )
                        tool_result = {"success": True, **result}
                    elif func_name == "get_knowledge":
                        knowledge = _tool_get_knowledge(
                            question=arguments.get("question", ""),
                            max_chars=arguments.get("max_chars", 1800),
                        )
                        tool_result = {"success": True, **knowledge}
                    elif func_name == "planning":
                        planning_result = _tool_planning(messages=messages)
                        tool_result = {"success": True, **planning_result}
                except Exception as tool_err:
                    tool_result = {"success": False, "message": f"{func_name} 执行失败: {tool_err}"}
                    _push_agent_event(
                        state,
                        tool_result["message"],
                        level="warning",
                        event_type="tool_error",
                        details={"round": round_idx, "tool_name": func_name},
                    )

                tool_content = json.dumps(tool_result, ensure_ascii=False)
                conversation.append({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "name": func_name,
                    "content": tool_content,
                })

            if total_tool_calls >= max_tool_calls:
                _push_agent_event(
                    state,
                    f"工具调用次数已达上限({max_tool_calls})，结束任务",
                    level="warning",
                )
                break

        if runtime.get("accepted"):
            msg = "任务已成功完成"
            _push_agent_event(
                state,
                msg,
                level="success",
                status="Completed",
                event_type="accepted",
                final_submission_id=final_submission_id,
            )
            return {
                "success": True,
                "message": msg,
                "task_id": task_id,
                "final_submission_id": final_submission_id,
                "attempts": attempts,
            }

        _push_agent_event(
            state,
            "Agent 任务结束，未通过全部测试点",
            level="warning",
            status="Failed",
            final_submission_id=final_submission_id,
        )
        return {
            "success": False,
            "message": "Agent 任务结束，未通过全部测试点",
            "task_id": task_id,
            "final_submission_id": final_submission_id,
            "attempts": attempts,
        }

    return agent_solve_problem
