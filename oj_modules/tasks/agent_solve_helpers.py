#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import time

from config import AI_TUTOR_MODEL
from oj_modules.ai_utils import generate_ai_code_marks_from_submission_context
from oj_modules.db_services import (
    get_cached_ai_code_marks_for_submission,
    get_db_connection,
    save_submission_ai_code_marks_json,
)
from oj_modules.repository_services import extract_includes_from_code, get_user_repository_files_by_names
from oj_modules.tasks.agent_shared import *

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




__all__ = [name for name in globals().keys() if not name.startswith("__")]
