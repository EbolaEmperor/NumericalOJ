#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import subprocess
import time

from config import (
    AI_TUTOR_MODEL,
    AGENT_REPOSITORY_KNN_SCORE_THRESHOLD,
    AGENT_REPOSITORY_KNN_TOP_K,
)
from oj_modules.ai_utils import generate_ai_code_marks_from_submission_context
from oj_modules.db_services import (
    get_cached_ai_code_marks_for_submission,
    get_db_connection,
    save_submission_ai_code_marks_json,
)
from oj_modules.repository_index_services import search_repository_chunks
from oj_modules.repository_services import extract_includes_from_code, get_user_repository_files_by_names
from oj_modules.tasks.agent_shared import *


_AGENT_REPOSITORY_KNN_TOP_K = _clamp_int(AGENT_REPOSITORY_KNN_TOP_K, 5, min_value=1, max_value=20)
try:
    _AGENT_REPOSITORY_KNN_SCORE_THRESHOLD = float(AGENT_REPOSITORY_KNN_SCORE_THRESHOLD)
except Exception:
    _AGENT_REPOSITORY_KNN_SCORE_THRESHOLD = 0.08

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


def _truncate_block_text(value, limit=12000):
    text = str(value or "")
    safe_limit = _clamp_int(limit, 12000, min_value=200, max_value=200000)
    if len(text) <= safe_limit:
        return text
    keep = safe_limit // 2
    return text[:keep] + "\n...<truncated>...\n" + text[-keep:]


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


def _build_repository_knn_query(problem, latest_summary=None):
    if not isinstance(problem, dict):
        return ""
    lines = []
    title = _normalize_text_line(problem.get("title"))
    if title:
        lines.append(f"题目标题: {title}")
    content = str(problem.get("content") or "").strip()
    if content:
        lines.append(f"题目描述: {_truncate_text(_normalize_text_line(content), limit=800)}")

    hints = _extract_problem_hints(problem)
    if hints:
        lines.append("题目提示: " + "；".join([_truncate_text(_normalize_text_line(x), limit=120) for x in hints[:6]]))

    if isinstance(latest_summary, dict):
        status = _normalize_text_line(latest_summary.get("status"))
        score = latest_summary.get("score")
        accepted_count = latest_summary.get("accepted_count")
        total_count = latest_summary.get("total_count")
        lines.append(
            f"最近评测: status={status} score={score} passed={accepted_count}/{total_count}"
        )
        failed_points = latest_summary.get("failed_points") if isinstance(latest_summary.get("failed_points"), list) else []
        for fp in failed_points[:3]:
            if not isinstance(fp, dict):
                continue
            fp_status = _normalize_text_line(fp.get("status"))
            stderr = _truncate_text(_normalize_text_line(fp.get("stderr")), limit=180)
            stdout = _truncate_text(_normalize_text_line(fp.get("stdout")), limit=180)
            if stderr or stdout:
                lines.append(f"失败点: {fp_status} stderr={stderr} stdout={stdout}")
            else:
                lines.append(f"失败点: {fp_status}")

    query = "\n".join([x for x in lines if x]).strip()
    return _truncate_text(query, limit=1600)


def _format_repository_knn_memory_message(knn_result, query, top_k):
    if not isinstance(knn_result, dict):
        return ""
    hits = knn_result.get("hits") if isinstance(knn_result.get("hits"), list) else []
    if not hits:
        return ""

    model_name = str(knn_result.get("embedding_model") or "").strip()
    backend = str(knn_result.get("vector_db_backend") or "vector_db").strip()
    lines = [
        "这是来自代码仓库向量数据库的记忆（memory），用于辅助当前解题，不可盲从：",
        f"- KNN top_k={int(top_k)} backend={backend} model={model_name}",
        f"- query: {_truncate_text(_normalize_text_line(query), limit=280)}",
    ]
    for idx, hit in enumerate(hits[:top_k], start=1):
        if not isinstance(hit, dict):
            continue
        qname = _truncate_text(_normalize_text_line(hit.get("qualified_name")), limit=120)
        filename = _truncate_text(_normalize_text_line(hit.get("filename")), limit=80)
        signature = _truncate_text(_normalize_text_line(hit.get("signature")), limit=180)
        summary = _truncate_text(_normalize_text_line(hit.get("summary")), limit=220)
        score = hit.get("score")
        access = _normalize_text_line(hit.get("access"))
        lines.append(
            f"{idx}. {qname} ({filename}) score={score} access={access}"
        )
        if signature:
            lines.append(f"   signature: {signature}")
        if summary:
            lines.append(f"   summary: {summary}")
    lines.append("请优先依据题意、测试反馈与本地运行结果，谨慎参考以上记忆。")
    return _truncate_text("\n".join(lines), limit=4200)


def _build_repository_knn_memory_message(user_id, problem, latest_summary=None, top_k=None):
    use_top_k = _clamp_int(top_k, _AGENT_REPOSITORY_KNN_TOP_K, min_value=1, max_value=20)
    query = _build_repository_knn_query(problem=problem, latest_summary=latest_summary)
    if not query:
        return "", 0
    try:
        knn_result = search_repository_chunks(
            user_id=int(user_id),
            query=query,
            top_k=use_top_k,
            score_threshold=_AGENT_REPOSITORY_KNN_SCORE_THRESHOLD,
        )
    except Exception:
        return "", 0

    text = _format_repository_knn_memory_message(knn_result=knn_result, query=query, top_k=use_top_k)
    hits = knn_result.get("hits") if isinstance(knn_result.get("hits"), list) else []
    return text, len(hits)



def _build_conversation_messages(
    conversation,
    round_idx,
    working_memory,
    latest_submission_id=None,
    latest_summary=None,
    workspace_dir="",
    main_code_path="",
    repository_knn_memory="",
):
    system_lines = [
        "你现在是一个可调用工具的 OJ 自主 Agent。",
        "请自行决策并调用工具迭代解题。",
        "系统已把用户代码仓库文件复制到你的工作目录；你只能在工作目录内读写文件。",
        "目标：产出能通过评测的代码。",
        "要求：1. 不要臆造文件或评测结果。 2. 题目给的提示非常重要，请优先满足。 3. 如果提交后没有获得满分，必须在本地复现错误、编译、运行，决不允许编辑完直接再提交。",
        f"硬性约束：最多只能调用 {_AGENT_SUBMIT_LIMIT} 次 submit_evaluation；"
        f"第 {_AGENT_SUBMIT_LIMIT} 次返回后若仍未通过，任务会被强制终止并判定失败。",
        "完成条件：submit_evaluation 返回的评测状态为 Accepted。",
    ]
    if workspace_dir:
        system_lines.append(f"工作目录：{workspace_dir}")
    if main_code_path:
        system_lines.append(f"默认主代码文件：{main_code_path}")
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
    system_lines.append(f"当前推理轮次：{int(round_idx)}")

    messages = [{"role": "system", "content": "\n".join(system_lines)}]
    memory_text = str(repository_knn_memory or "").strip()
    if memory_text:
        messages.append({"role": "memory", "content": memory_text})
    return messages + list(conversation or [])


def _workspace_main_filename(lang):
    use_lang = str(lang or "").strip().lower()
    if use_lang == "c":
        return "main.c"
    if use_lang in ("python", "py"):
        return "main.py"
    if use_lang in ("matlab", "octave"):
        return "main.m"
    return "main.cpp"


def _load_repository_files_for_workspace(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT filename, file_content
                FROM user_code_repository
                WHERE user_id = %s
                ORDER BY filename
                """,
                (user_id,),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()
    files = []
    for row in rows:
        filename = os.path.basename(str(row.get("filename") or "").strip())
        if not filename:
            continue
        files.append({
            "filename": filename,
            "content": str(row.get("file_content") or ""),
        })
    return files


def _initialize_solver_workspace(user_id, problem_id, task_id, lang, initial_code=""):
    root = os.path.abspath(os.path.join("tmp", "agent_solve_runs", f"{int(problem_id)}_{str(task_id)}"))
    os.makedirs(root, exist_ok=True)

    repo_files = _load_repository_files_for_workspace(user_id=user_id)
    synced_files = []
    for item in repo_files:
        filename = os.path.basename(str(item.get("filename") or "").strip())
        if not filename:
            continue
        abs_path = os.path.join(root, filename)
        parent = os.path.dirname(abs_path)
        os.makedirs(parent, exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(str(item.get("content") or ""))
        synced_files.append(filename)

    main_filename = _workspace_main_filename(lang)
    main_abs = os.path.join(root, main_filename)
    initial = str(initial_code or "")
    if initial.strip():
        with open(main_abs, "w", encoding="utf-8") as f:
            f.write(initial)
    elif not os.path.isfile(main_abs):
        with open(main_abs, "w", encoding="utf-8") as f:
            f.write("")
    synced_files.append(main_filename)

    return {
        "workspace_dir": root,
        "main_code_path": main_filename,
        "synced_files": sorted(set(synced_files)),
    }


def _resolve_workspace_path(workspace_dir, relative_path="", allow_workspace_root=False):
    if not workspace_dir:
        raise RuntimeError("workspace 未初始化。")
    root = os.path.abspath(str(workspace_dir))
    rel = str(relative_path or "").replace("\\", "/").strip()
    if not rel:
        if allow_workspace_root:
            return root
        raise RuntimeError("path 不能为空。")
    rel = rel.lstrip("/")
    norm_rel = os.path.normpath(rel)
    abs_path = os.path.abspath(os.path.join(root, norm_rel))
    if abs_path != root and not abs_path.startswith(root + os.sep):
        raise RuntimeError("path 不能越界到工作目录之外。")
    if abs_path == root and not allow_workspace_root:
        raise RuntimeError("path 不能指向工作目录根路径。")
    return abs_path


def _tool_workspace_create_file(workspace_dir, path, content, overwrite=True):
    abs_path = _resolve_workspace_path(workspace_dir, path)
    parent = os.path.dirname(abs_path)
    os.makedirs(parent, exist_ok=True)
    if os.path.exists(abs_path) and not bool(overwrite):
        raise RuntimeError("目标文件已存在，且 overwrite=false。")
    text = str(content or "")
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(text)
    return {
        "path": os.path.relpath(abs_path, workspace_dir),
        "bytes": len(text.encode("utf-8")),
    }


def _tool_workspace_edit_file(
    workspace_dir,
    path,
    new_content=None,
    find_text=None,
    replace_text=None,
    replace_all=True,
):
    abs_path = _resolve_workspace_path(workspace_dir, path)
    if not os.path.isfile(abs_path):
        raise RuntimeError("目标文件不存在。")
    with open(abs_path, "r", encoding="utf-8") as f:
        original = f.read()

    if new_content is not None:
        updated = str(new_content)
        replace_count = 1
    else:
        src = str(find_text or "")
        if not src:
            raise RuntimeError("缺少 find_text 或 new_content。")
        dst = str(replace_text or "")
        if bool(replace_all):
            updated = original.replace(src, dst)
            replace_count = original.count(src)
        else:
            updated = original.replace(src, dst, 1)
            replace_count = 1 if src in original else 0
        if replace_count <= 0:
            raise RuntimeError("未找到待替换文本。")

    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(updated)
    return {
        "path": os.path.relpath(abs_path, workspace_dir),
        "replaced": int(replace_count),
        "bytes": len(updated.encode("utf-8")),
    }


def _tool_workspace_read_file(workspace_dir, path, max_chars=12000):
    abs_path = _resolve_workspace_path(workspace_dir, path)
    if not os.path.isfile(abs_path):
        raise RuntimeError("目标文件不存在。")
    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    safe_limit = _clamp_int(max_chars, 12000, min_value=200, max_value=200000)
    return {
        "path": os.path.relpath(abs_path, workspace_dir),
        "content": _truncate_block_text(content, limit=safe_limit),
        "truncated": len(content) > safe_limit,
    }


def _tool_workspace_list_files(workspace_dir, path="", recursive=True, max_entries=500):
    base_abs = _resolve_workspace_path(workspace_dir, path, allow_workspace_root=True)
    safe_max = _clamp_int(max_entries, 500, min_value=1, max_value=3000)
    rows = []
    if bool(recursive):
        for root, dirnames, filenames in os.walk(base_abs):
            dirnames.sort()
            filenames.sort()
            rel_root = os.path.relpath(root, workspace_dir)
            for dirname in dirnames:
                rel_path = os.path.normpath(os.path.join(rel_root, dirname))
                rows.append({"path": rel_path, "is_dir": True, "size": 0})
                if len(rows) >= safe_max:
                    return {"entries": rows, "truncated": True}
            for filename in filenames:
                abs_file = os.path.join(root, filename)
                rel_path = os.path.normpath(os.path.join(rel_root, filename))
                try:
                    size = os.path.getsize(abs_file)
                except Exception:
                    size = 0
                rows.append({"path": rel_path, "is_dir": False, "size": int(size)})
                if len(rows) >= safe_max:
                    return {"entries": rows, "truncated": True}
    else:
        for name in sorted(os.listdir(base_abs)):
            abs_item = os.path.join(base_abs, name)
            rel_path = os.path.relpath(abs_item, workspace_dir)
            is_dir = os.path.isdir(abs_item)
            try:
                size = 0 if is_dir else os.path.getsize(abs_item)
            except Exception:
                size = 0
            rows.append({"path": rel_path, "is_dir": bool(is_dir), "size": int(size)})
            if len(rows) >= safe_max:
                return {"entries": rows, "truncated": True}
    return {"entries": rows, "truncated": False}


def _tool_workspace_run_command(workspace_dir, command, timeout_seconds=60):
    cmd = str(command or "").strip()
    if not cmd:
        raise RuntimeError("command 不能为空。")
    timeout_val = _clamp_int(timeout_seconds, 60, min_value=1, max_value=900)
    try:
        proc = subprocess.run(
            ["bash", "-lc", cmd],
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            timeout=timeout_val,
            check=False,
        )
        return {
            "success": proc.returncode == 0,
            "exit_code": int(proc.returncode),
            "stdout": _truncate_block_text(proc.stdout, limit=16000),
            "stderr": _truncate_block_text(proc.stderr, limit=16000),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "success": False,
            "exit_code": None,
            "stdout": _truncate_block_text(e.stdout or "", limit=16000),
            "stderr": _truncate_block_text(e.stderr or "", limit=16000),
            "timeout": True,
            "message": f"命令执行超时（{timeout_val}s）",
        }


def _tool_sync_workspace_headers_to_repository(user_id, workspace_dir):
    if not workspace_dir or not os.path.isdir(workspace_dir):
        raise RuntimeError("workspace 目录不存在。")

    candidates = []
    skipped = []
    for name in sorted(os.listdir(workspace_dir)):
        abs_path = os.path.join(workspace_dir, name)
        if not os.path.isfile(abs_path):
            continue
        lower = str(name).lower()
        if not (lower.endswith(".h") or lower.endswith(".hpp")):
            continue
        filename = os.path.basename(name)
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", filename):
            skipped.append({"filename": filename, "reason": "文件名包含非法字符"})
            continue
        candidates.append((filename, abs_path))

    synced = []
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            for filename, abs_path in candidates:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                size = len(content.encode("utf-8"))
                cursor.execute(
                    """
                    INSERT INTO user_code_repository (user_id, filename, file_content, file_size)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        file_content = VALUES(file_content),
                        file_size = VALUES(file_size),
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (user_id, filename, content, size),
                )
                synced.append({"filename": filename, "file_size": size})
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "synced_count": len(synced),
        "synced_files": synced,
        "skipped_files": skipped,
    }


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


def _build_agent_react_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "get_context",
                "description": "读取当前解题任务上下文信息（语言、工作目录、主代码文件等）。",
                "parameters": {
                    "type": "object",
                    "properties": {},
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_files",
                "description": "列出工作目录中的文件。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "相对路径，默认根目录"},
                        "recursive": {"type": "boolean", "description": "是否递归，默认 true"},
                        "max_entries": {"type": "integer", "description": "最大条数，默认 500"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "读取工作目录内文件内容。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "相对路径"},
                        "max_chars": {"type": "integer", "description": "最大字符数，默认 12000"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "create_file",
                "description": "创建文件（代码文件或文本文件）。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "工作目录内相对路径"},
                        "content": {"type": "string", "description": "完整文件内容"},
                        "overwrite": {"type": "boolean", "description": "文件存在时是否覆盖，默认 true"},
                    },
                    "required": ["path", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "edit_file",
                "description": "编辑已存在文件。可整文件替换，或按 find_text 替换。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "工作目录内相对路径"},
                        "new_content": {"type": "string", "description": "若提供则直接整文件替换"},
                        "find_text": {"type": "string", "description": "待替换文本"},
                        "replace_text": {"type": "string", "description": "替换后的文本"},
                        "replace_all": {"type": "boolean", "description": "是否替换全部，默认 true"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_command",
                "description": "在 Debian 工作目录执行命令（用于编译/运行/自检）。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "bash 命令"},
                        "timeout_seconds": {"type": "integer", "description": "超时秒数，默认 60"},
                    },
                    "required": ["command"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_evaluation",
                "description": "从工作目录读取代码并提交评测。系统会提交你的主代码文件以及它依赖的所有头文件，不会提交你自己写的测试代码。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "source_path": {"type": "string", "description": "可选。要提交的代码文件路径，默认主代码文件"},
                        "timeout_seconds": {"type": "integer", "description": "等待评测超时秒数，默认 300"},
                    },
                },
            },
        },
    ]


def _build_initial_prompt(problem, workspace_dir, main_code_path, core_hints=None, workspace_filenames=None):
    lang = (problem.get("lang") or "matlab").lower()
    initial_code = (problem.get("initial_code") or "").strip()
    title = str(problem.get("title", "") or "").strip()
    content = str(problem.get("content", "") or "").strip()
    hint_lines = _dedupe_keep_order(core_hints or [])[:8]
    lines = [
        "你是一个解题 Agent，你需要为在线评测系统完成编程题并通过评测。",
        "你首先需要获取：",
        "1. 题目要求",
        "2. 当前工作目录与文件列表",
        "3. 默认主代码文件路径",
        "",
        f"当前题目语言：{lang}",
        f"题目标题：{title}",
        "题目描述如下：",
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
    file_names = []
    for item in (workspace_filenames or []):
        name = str(item or "").strip()
        if name:
            file_names.append(name)
    file_names = _dedupe_keep_order(file_names)[:200]
    files_text = "\n".join([f"- {name}" for name in file_names]) if file_names else "- （暂无文件）"
    lines.extend([
        "",
        f"你的工作目录是：{workspace_dir}",
        f"默认主代码文件是：{main_code_path}",
        "工作目录里已经有一些我写好的文件可供你通过 include \"文件名\" 直接使用。",
        "你的工作流程如下：",
        "0. 先调用 get_context，确认题目上下文、工作目录与主代码文件。",
        "1. 调用 list_files 列出工作目录中的文件，理解现有代码，优先复用已有文件。",
        "2. 创建/编辑/修改代码文件。对于 C++ 语言，如果主代码文件不包含 main 函数，则需要自己另外写一个测试文件，即：另写一个带 main 函数的 cpp 测试代码，在开头 #include \"主代码文件\"。",
        "3. 根据题意创建必要的输入文件，如果你的测试程序不需要输入，则跳过此步。",
        "4. 编译运行你的测试程序，确保能够编译通过，且能够正确通过测试。如果无法通过，重复 1-4 步，直到能够通过自己写的测试。",
        "5. 调用 submit_evaluation 提交评测；系统会提交你的主代码文件以及它依赖的所有头文件，不会提交你自己写的测试代码。",
        "当你提交后，发现没有获得满分时，严禁修改代码后直接再交，严禁修改代码后直接再交，严禁修改代码后直接再交！你必须：",
        "1. 分析错误原因，尝试写一个测试代码来复现错误。",
        "2. 编译、运行测试代码，看到底为什么错了。",
        "3. 修复你的程序，直到能通过你自己新写的测试代码为止。",
        "4. 重新提交。",
        "",
    ])
    if lang in ("python", "py"):
        lines.append("系统提供了 python3 以及 numpy、pandas 等一切必要的工具，你不必自己安装依赖。")
        lines.append("")
    elif lang in ("matlab", "octave"):
        lines.append("系统没有 MATLAB 环境，但提供了 octave 环境，请用 octave 来代替执行 MATLAB 代码。")
        lines.append("")
    lines.append(
        f"你最多只能调用 {_AGENT_SUBMIT_LIMIT} 次 submit_evaluation，"
        f"若 {_AGENT_SUBMIT_LIMIT} 次还没成功，你会被强制终止并判定失败。"
    )
    return "\n".join(lines).strip()




__all__ = [name for name in globals().keys() if not name.startswith("__")]
