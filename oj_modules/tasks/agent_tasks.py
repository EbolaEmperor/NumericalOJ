#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import time

import requests

from config import (
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


def _build_api_request_payload(messages, model=None):
    return {
        "model": str(model or QWEN_CODER_MODEL),
        "messages": _safe_json_copy(messages, default=[]),
        "stream": False,
    }


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
        "model": "qwen3.5-plus",
    }
    try:
        save_submission_ai_code_marks_json(submission_id, payload)
    except Exception:
        pass
    return _format_ai_tutor_feedback_from_marks(result)


def _call_qwen_chat_model(messages, model, timeout=180, empty_text_error="模型未返回有效文本。"):
    api_key = _ensure_dashscope_api_key()
    base_url = str(DASHSCOPE_BASE_URL).rstrip("/")
    use_model = str(model or QWEN_CODER_MODEL)
    payload = _build_api_request_payload(messages, model=use_model)

    if OpenAI is not None:
        try:
            client = OpenAI(api_key=api_key, base_url=base_url)
            resp = client.chat.completions.create(
                model=use_model,
                messages=messages,
                stream=False,
            )
            choices = getattr(resp, "choices", None) or []
            if choices and getattr(choices[0], "message", None):
                content = choices[0].message.content
                text = _extract_text_from_content(content).strip()
                if text:
                    return text
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
    content = message.get("content")
    text = _extract_text_from_content(content).strip()
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


def _call_qwen3_5_plus_text(messages, timeout=120):
    return _call_qwen_chat_model(
        messages=messages,
        model=QWEN_TEXT_MODEL,
        timeout=timeout,
        empty_text_error="模型未返回有效摘要文本。",
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
    return total


def _serialize_messages_for_history_summary(messages, max_chars):
    rows = []
    total_chars = 0
    for idx, msg in enumerate(messages or [], start=1):
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "").strip() or "user"
        content = str(msg.get("content") or "").strip()
        if not content:
            continue

        # 对历史代码块做轻量去噪，保留诊断/关键信息供摘要模型理解。
        if role == "assistant":
            diagnosis = _extract_retry_diagnosis(content)
            if diagnosis:
                content = f"诊断要点：{diagnosis}\n代码：<省略>"
            else:
                content = re.sub(r"```[\s\S]*?```", "<代码块省略>", content, flags=re.DOTALL)

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
    serialized = _serialize_messages_for_history_summary(
        history_messages,
        max_chars=_AGENT_CONTEXT_SUMMARY_INPUT_MAX_CHARS,
    )
    if not serialized:
        return ""

    user_prompt = (
        "请将以下 OJ 自动解题多轮对话压缩为下一轮可用的历史摘要。\n"
        "输出要求：\n"
        "1) 使用中文；\n"
        "2) 必须包含：题目提示/硬约束、已尝试修改与对应评测现象、仍未解决点、下一轮注意事项；\n"
        "3) 不要编造对话里不存在的信息；\n"
        "4) 如果发现反复尝试且难以解决的数学或代码问题，请你帮助解决\n"
        f"5) 总长度控制在 {int(target_chars)} 字符以内。\n\n"
        "历史对话片段如下：\n"
        f"{serialized}"
    )
    messages = [
        {
            "role": "system",
            "content": (
                "你是 OJ 调试上下文压缩助手。"
                "你的目标是在信息不丢失关键约束的前提下，生成高度可执行的历史摘要。"
            ),
        },
        {"role": "user", "content": user_prompt},
    ]
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
    return _truncate_text(cleaned, limit=max(240, int(target_chars)))


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


def _trim_conversation_by_budget(conversation, max_chars, keep_rounds, state=None, round_idx=None):
    if not isinstance(conversation, list):
        return []
    cleaned = []
    for item in conversation:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip()
        content = str(item.get("content") or "")
        if role not in ("user", "assistant"):
            continue
        cleaned.append({"role": role, "content": content})

    if not cleaned:
        return []
    if _conversation_total_chars(cleaned) <= max_chars:
        return cleaned

    _ = keep_rounds

    latest_assistant_idx = -1
    for idx in range(len(cleaned) - 1, -1, -1):
        if cleaned[idx].get("role") == "assistant":
            latest_assistant_idx = idx
            break

    latest_code_content = ""
    if latest_assistant_idx >= 0:
        latest_code_content = _extract_latest_code_only_from_assistant(
            cleaned[latest_assistant_idx].get("content") or ""
        )

    if latest_assistant_idx >= 0:
        summary_source = cleaned[:latest_assistant_idx] + cleaned[latest_assistant_idx + 1:]
    else:
        summary_source = cleaned

    summary_budget = min(_AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS, max(600, int(max_chars * 0.35)))
    summary_text = (
        _summarize_history_with_qwen35(
            summary_source,
            target_chars=summary_budget,
            state=state,
            round_idx=round_idx,
            event_label="历史摘要",
        )
        if summary_source else ""
    )

    rebuilt = []
    if summary_text:
        rebuilt.append({
            "role": "user",
            "content": "【历史信息摘要（qwen3.5-plus）】\n" + summary_text,
        })

    if latest_code_content:
        rebuilt.append({
            "role": "assistant",
            "content": "【上一版最新代码】\n" + latest_code_content,
        })
    elif cleaned:
        rebuilt.append(cleaned[-1])

    if _conversation_total_chars(rebuilt) <= max_chars:
        return rebuilt

    # 优先保留“最新代码”，超预算时先移除摘要。
    if len(rebuilt) > 1 and rebuilt[-1].get("role") == "assistant":
        code_only = [rebuilt[-1]]
        if _conversation_total_chars(code_only) <= max_chars:
            return code_only
        rebuilt = code_only

    # 极端超长时兜底截断，避免任务无法继续。
    fallback = []
    for idx, msg in enumerate(rebuilt):
        limit = max(220, int(max_chars / max(1, len(rebuilt))))
        if idx == len(rebuilt) - 1 and msg.get("role") == "assistant":
            limit = max(limit, int(limit * 1.8))
        fallback.append({
            "role": msg.get("role"),
            "content": _truncate_text(msg.get("content"), limit=limit),
        })
    while len(fallback) > 1 and _conversation_total_chars(fallback) > max_chars:
        del fallback[0]
    return fallback


def _build_round_feedback_user_message(problem, round_idx, eval_summary, working_memory, ai_tutor_feedback=""):
    core_hints = []
    if isinstance(working_memory, dict):
        maybe_hints = working_memory.get("core_hints")
        if isinstance(maybe_hints, list):
            core_hints = [str(x) for x in maybe_hints if str(x).strip()]
    hint_text = "\n".join([f"- {h}" for h in core_hints[:8]]) if core_hints else "无"

    failed_text = []
    for fp in (eval_summary.get("failed_points") or [])[:4]:
        if not isinstance(fp, dict):
            continue
        stderr = _truncate_text(fp.get("stderr"), limit=140)
        stdout = _truncate_text(fp.get("stdout"), limit=140)
        failed_text.append(
            f"- 测试点#{fp.get('index')} status={fp.get('status')} stderr={stderr} stdout={stdout}"
        )
    failed_joined = "\n".join(failed_text) if failed_text else "- 无失败点详情"
    tutor_block = _truncate_text(ai_tutor_feedback, limit=1400) if ai_tutor_feedback else "无"
    lang = (problem.get("lang") or "matlab").lower()

    return (
        "代码没有通过测试，我接下来给你题目提示和本轮评测结果，请你定位问题并修复 bug。此外，我还会给你来自 AI 助教的建议，你可以酌情采纳。\n\n"
        "【题目提示】\n"
        f"{hint_text}\n\n"
        "【本轮评测结果】\n"
        f"- 目标语言: {lang}\n"
        f"- 题目标题: {problem.get('title', '')}\n"
        f"- 状态: {eval_summary.get('status')}\n"
        f"- 分数: {eval_summary.get('score')}\n"
        f"- 通过数: {eval_summary.get('accepted_count')}/{eval_summary.get('total_count')}\n\n"
        "【前4个错误点】\n"
        f"{failed_joined}\n\n"
        "【AI 助教建议】\n"
        f"{tutor_block}\n\n"
        "【要求】\n"
        "- 不要重复前几轮已经犯过的错误。\n"
        "- 代码必须可编译。\n\n"
        "【输出格式】\n"
        "【诊断】\n"
        "1) 问题：... 修复方案：..."
        "2) 问题：... 修复方案：...\n"
        "【代码】\n"
        "```语言\n"
        "<完整代码>\n"
        "```"
    )


def _build_conversation_messages(conversation, round_idx, working_memory):
    if round_idx == 1:
        system_content = (
            "You are a helpful coding agent. "
            "Current turn is round 1: output final source code only."
        )
    else:
        system_content = (
            "You are a helpful coding agent. "
            "Current turn is a retry round: output must be structured diagnosis + complete source code. "
            "If earlier messages contain round-1-only format requirements, ignore them and follow current turn format."
        )
        if _AGENT_MEMORY_ENABLED:
            system_content += " Do not repeat mistakes from earlier rounds."
        if isinstance(working_memory, dict):
            core_hints = working_memory.get("core_hints")
            if isinstance(core_hints, list) and core_hints:
                hint_lines = "\n".join([f"- {str(x)}" for x in core_hints[:6]])
                system_content += (
                    "\nTreat the following problem hints as highest-priority hard constraints:\n"
                    f"{hint_lines}"
                )

    return [{"role": "system", "content": system_content}] + list(conversation or [])


def _summarize_submission(submission):
    if not submission:
        return {
            "status": "Error",
            "score": 0,
            "accepted_count": 0,
            "total_count": 0,
            "failed_points": [],
        }

    points = submission.get("test_points") or []
    if not isinstance(points, list):
        points = []

    accepted = 0
    failed_points = []
    for idx, tp in enumerate(points, start=1):
        status = str((tp or {}).get("status") or "Error")
        if status == "Accepted":
            accepted += 1
            continue
        failed_points.append({
            "index": idx,
            "status": status,
            "stderr": _truncate_text((tp or {}).get("stderr")),
            "stdout": _truncate_text((tp or {}).get("stdout")),
            "time": (tp or {}).get("time", 0),
        })

    return {
        "status": submission.get("status"),
        "score": submission.get("score", 0),
        "accepted_count": accepted,
        "total_count": len(points),
        "failed_points": failed_points,
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


def _build_initial_prompt(problem, core_hints=None):
    lang = (problem.get("lang") or "matlab").lower()
    initial_code = (problem.get("initial_code") or "").strip()
    hint_lines = _dedupe_keep_order(core_hints or [])[:8]
    hint_part = ""
    if hint_lines:
        hint_part = "题目提示（最高优先级，必须先满足）：\n" + "\n".join([f"- {h}" for h in hint_lines]) + "\n\n"
    initial_code_part = (
        f"\n\n题目初始代码（你必须基于此代码继续实现，而不是忽略它）：\n{initial_code}\n"
        if initial_code else
        "\n\n题目未提供初始代码，可自行从零实现。\n"
    )
    return (
        "你是一个 ACM/OJ 解题助手。"
        "请根据题目描述输出可通过评测的完整代码。"
        "当前是首轮：只输出完整代码，不要解释。"
        "若后续用户消息明确要求“诊断+代码”格式，以后续消息为准。\n\n"
        f"目标语言: {lang}\n"
        f"题目标题: {problem.get('title', '')}\n"
        "题目描述如下：\n"
        f"{problem.get('content', '')}\n\n"
        f"{hint_part}"
        "如果题目提供了模板，你必须在模板风格下补全可运行代码。"
        f"{initial_code_part}"
    )


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
            cfg_rounds = 3
        max_rounds = max(1, cfg_rounds)

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
        last_ai_tutor_feedback = ""
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
        conversation = [{"role": "user", "content": _build_initial_prompt(problem, core_hints=core_hints)}]

        for round_idx in range(1, max_rounds + 1):
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
            messages = _build_conversation_messages(conversation, round_idx, working_memory)
            api_request_body = _build_api_request_payload(messages)
            _append_api_call_log(state, round_idx, api_request_body, api_type="solve")
            _push_agent_event(
                state,
                f"第 {round_idx}/{max_rounds} 轮：生成代码中",
                round=round_idx,
                event_type="api_request",
                details={
                    "round": round_idx,
                    "api_type": "solve",
                    "request_body": api_request_body,
                },
            )

            try:
                model_reply = _call_qwen3_coder_plus(messages)
            except Exception as e:
                msg = f"第 {round_idx} 轮模型调用失败: {e}"
                _push_agent_event(state, msg, level="error", status="Failed")
                return {
                    "success": False,
                    "message": msg,
                    "task_id": task_id,
                    "attempts": attempts,
                }

            conversation.append({"role": "assistant", "content": model_reply})
            code = _extract_code_from_model_reply(model_reply, problem.get("lang"))
            diag = _extract_retry_diagnosis(model_reply) if round_idx > 1 else ""
            if round_idx > 1:
                if diag:
                    _push_agent_event(state, f"模型诊断摘要：{diag}")
            if not code.strip():
                msg = f"第 {round_idx} 轮未生成有效代码"
                _push_agent_event(state, msg, level="error", status="Failed")
                return {
                    "success": False,
                    "message": msg,
                    "task_id": task_id,
                    "attempts": attempts,
                }

            _push_agent_event(state, f"第 {round_idx} 轮代码已生成，准备提交")

            try:
                submission_id = _tool_submit_code(problem, requested_by, code, evaluate_submission_task)
            except Exception as e:
                msg = f"第 {round_idx} 轮提交失败: {e}"
                _push_agent_event(state, msg, level="error", status="Failed")
                return {
                    "success": False,
                    "message": msg,
                    "task_id": task_id,
                    "attempts": attempts,
                }

            final_submission_id = submission_id
            _push_agent_event(
                state,
                f"第 {round_idx} 轮已提交，submission_id={submission_id}",
                latest_submission_id=submission_id,
                final_submission_id=submission_id,
            )

            summary = _tool_query_test_results(submission_id, timeout_seconds=300)
            compact_summary = _compact_summary(summary)
            failure_signature = _build_failure_signature(compact_summary)
            _push_agent_event(
                state,
                (
                    f"第 {round_idx} 轮评测完成："
                    f"状态={compact_summary.get('status')} 分数={compact_summary.get('score')}"
                ),
            )
            ai_tutor_feedback = ""
            is_accepted_round = str(compact_summary.get("status") or "").strip() == "Accepted"
            evaluation_completed = bool(summary.get("completed")) and not bool(summary.get("timeout"))
            should_call_ai_tutor = evaluation_completed and (not is_accepted_round)
            if should_call_ai_tutor:
                try:
                    submission_detail = get_submission_by_id(submission_id) or {}
                    ai_tutor_feedback = _simulate_user_click_ai_tutor(
                        problem=problem,
                        submission=submission_detail,
                        user=user,
                        user_code=code,
                        submission_id=submission_id,
                    )
                except Exception as tutor_err:
                    _push_agent_event(
                        state,
                        f"第 {round_idx} 轮 AI 助教调用失败: {tutor_err}",
                        level="warning",
                        event_type="ai_tutor_error",
                    )
                if ai_tutor_feedback:
                    last_ai_tutor_feedback = ai_tutor_feedback
                    _push_agent_event(
                        state,
                        f"第 {round_idx} 轮 AI 助教建议已获取",
                        event_type="ai_tutor_feedback",
                        details={"round": round_idx, "submission_id": submission_id, "feedback": ai_tutor_feedback},
                    )
            elif not evaluation_completed:
                _push_agent_event(
                    state,
                    f"第 {round_idx} 轮评测未完成（等待超时），跳过 AI 助教调用",
                    level="warning",
                    event_type="ai_tutor_skipped",
                    details={"round": round_idx, "submission_id": submission_id},
                )

            attempt_item = {
                "round": round_idx,
                "submission_id": submission_id,
                "summary": compact_summary,
                "diagnosis": _truncate_text(diag, limit=360) if diag else "",
                "failure_signature": failure_signature,
                "api_request_body": api_request_body,
            }
            if ai_tutor_feedback:
                attempt_item["ai_tutor_feedback"] = ai_tutor_feedback
            if _AGENT_MEMORY_ENABLED:
                attempt_item["memory"] = _compact_working_memory_for_attempt(working_memory)
            attempts.append(attempt_item)
            state["attempts"] = attempts

            if _AGENT_MEMORY_ENABLED:
                memory_delta = _update_working_memory(
                    working_memory,
                    round_idx=round_idx,
                    diagnosis=(diag + "\n" + ai_tutor_feedback).strip() if ai_tutor_feedback else diag,
                    eval_summary=compact_summary,
                    latest_code=code,
                )
                state["working_memory"] = working_memory
                if attempts:
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

            if summary.get("status") == "Accepted":
                msg = f"Agent 在第 {round_idx} 轮通过"
                _push_agent_event(
                    state,
                    msg,
                    level="success",
                    status="Completed",
                    final_submission_id=submission_id,
                )
                return {
                    "success": True,
                    "message": msg,
                    "task_id": task_id,
                    "final_submission_id": submission_id,
                    "attempts": attempts,
                }

            if summary.get("timeout"):
                _push_agent_event(
                    state,
                    f"第 {round_idx} 轮评测超时，提前结束",
                    level="warning",
                )
                break

            if round_idx < max_rounds:
                feedback_user_message = _build_round_feedback_user_message(
                    problem,
                    round_idx=round_idx,
                    eval_summary=compact_summary,
                    working_memory=working_memory,
                    ai_tutor_feedback=last_ai_tutor_feedback,
                )
                conversation.append({"role": "user", "content": feedback_user_message})

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
