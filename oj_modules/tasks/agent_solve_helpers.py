#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess

from config import (
    AGENT_REPOSITORY_KNN_TOP_K,
    AGENT_REPOSITORY_KNN_SCORE_THRESHOLD,
    AI_TUTOR_MODEL,
)
from oj_modules.ai_utils import analyze_submission_output_image_against_problem
from oj_modules.db_services import (
    get_db_connection,
)
from oj_modules.modelscope_web_search_mcp import (
    web_fetch_content_via_modelscope_mcp,
    web_search_via_modelscope_mcp,
)
from oj_modules.repository_index_services import encode_texts_with_qwen_embedding, search_repository_chunks
from oj_modules.tasks.agent_shared import *


_AGENT_REPOSITORY_KNN_TOP_K = _clamp_int(AGENT_REPOSITORY_KNN_TOP_K, 1, min_value=1, max_value=20)
try:
    _AGENT_REPOSITORY_KNN_SCORE_THRESHOLD = float(AGENT_REPOSITORY_KNN_SCORE_THRESHOLD)
except Exception:
    _AGENT_REPOSITORY_KNN_SCORE_THRESHOLD = 0.0
_READ_FILE_HARD_LIMIT_BYTES = 10 * 1024


# 注意：_truncate_text 已由 `from agent_shared import *` 引入（与此处定义完全一致），
# 不再重复定义，避免同名函数 shadow 造成的维护歧义。


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
        "round_notes": [],
    }


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


def _update_working_memory(working_memory, round_idx, diagnosis, eval_summary):
    if not isinstance(working_memory, dict):
        working_memory = _init_working_memory()

    core_hints = working_memory.get("core_hints")
    if not isinstance(core_hints, list):
        core_hints = []
    patterns = working_memory.get("failure_patterns")
    if not isinstance(patterns, list):
        patterns = []
    notes = working_memory.get("round_notes")
    if not isinstance(notes, list):
        notes = []

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

    working_memory["core_hints"] = _dedupe_keep_order(core_hints)[:8]
    working_memory["failure_patterns"] = patterns
    working_memory["round_notes"] = notes

    return {
        "signature": signature,
        "added_pattern": added_pattern,
        "repeated_pattern": repeated_pattern,
        "pattern_count": len(patterns),
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
    notes = working_memory.get("round_notes")
    if not isinstance(notes, list):
        notes = []
    return {
        "core_hints": core_hints[:4],
        "failure_patterns": patterns[:4],
        "round_notes": notes[-3:],
    }


def _build_problem_summary_source(problem):
    if not isinstance(problem, dict):
        return ""
    lines = []
    title = str(problem.get("title") or "").strip()
    if title:
        lines.append(f"题目标题：\n{title}")

    content = str(problem.get("content") or "")
    if content:
        lines.append(f"题目完整描述：\n{content}")

    initial_code = str(problem.get("initial_code") or "")
    if initial_code.strip():
        lang = str(problem.get("lang") or "").strip()
        lines.append(f"题目提供模板代码（{lang}）：\n{initial_code}")

    for key in ("hint", "hints", "tip", "tips"):
        value = problem.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            lines.append(f"{key}：\n{text}")
    return "\n\n".join([x for x in lines if x]).strip()


def _summarize_problem_for_repository_search(query_text):
    source = str(query_text or "").strip()
    if not source:
        return ""
    messages = [
        {
            "role": "system",
            "content": (
                "你是 OJ 题目检索摘要助手。"
                "请用中文提炼题目的核心任务、可能用到的数据结构或算法关键词。"
                "不要输出解释，只输出摘要文本。"
            ),
        },
        {
            "role": "user",
            "content": (
                "请把下面的题目上下文归纳成向量检索用的题目大意，并列出可能需要的算法关键词，控制在 200 字左右。\n"
                f"{source}"
            ),
        },
    ]
    try:
        summary = _call_qwen_chat_model(
            messages=messages,
            model=AI_TUTOR_MODEL,
            timeout=60,
            empty_text_error="题目大意归纳失败。",
            enable_thinking=False,
        )
    except Exception:
        return source
    normalized = _normalize_text_line(summary)
    if not normalized:
        return source
    return _truncate_text(normalized, limit=320)


def _format_repository_knn_memory_message(knn_result, top_k):
    if not isinstance(knn_result, dict):
        return ""
    hits = knn_result.get("hits") if isinstance(knn_result.get("hits"), list) else []
    if not hits:
        return ""

    lines = [
        "用户曾经写过一些可能与本次任务相关的函数或类：",
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
        class_name = _truncate_text(_normalize_text_line(hit.get("class_name")), limit=120)
        lines.append(
            f"{idx}. {qname} ({filename}) score={score} access={access}"
        )
        if class_name:
            lines.append(f"   class: {class_name}")
        if signature:
            lines.append(f"   signature: {signature}")
        if summary:
            lines.append(f"   summary: {summary}")
    lines.append("这些函数在工作目录中，可以直接引用。如有必要请尽可能复用，不要重复实现已有功能。")
    return _truncate_text("\n".join(lines), limit=4200)


def _build_repository_knn_memory_message(user_id, problem):
    use_top_k = int(_AGENT_REPOSITORY_KNN_TOP_K)
    query_seed = _build_problem_summary_source(problem=problem)
    if not query_seed:
        return "", 0
    query = _summarize_problem_for_repository_search(query_seed)

    query_vector = None
    query_embedding_model = ""
    try:
        vectors, model_used = encode_texts_with_qwen_embedding([query])
        if getattr(vectors, "shape", (0, 0))[0] > 0:
            query_vector = vectors[0]
            query_embedding_model = str(model_used or "").strip()
    except Exception:
        query_vector = None
        query_embedding_model = ""

    try:
        knn_result = search_repository_chunks(
            user_id=int(user_id),
            query=query,
            top_k=use_top_k,
            score_threshold=_AGENT_REPOSITORY_KNN_SCORE_THRESHOLD,
            query_vector=query_vector,
            query_embedding_model=query_embedding_model,
        )
    except Exception:
        if query_vector is None:
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

    text = _format_repository_knn_memory_message(knn_result=knn_result, top_k=use_top_k)
    hits = knn_result.get("hits") if isinstance(knn_result.get("hits"), list) else []
    return text, len(hits)


def _tool_search_useful_code(user_id, description, top_k=None):
    query = str(description or "").strip()
    if not query:
        raise RuntimeError("description 不能为空。")
    use_top_k = _clamp_int(top_k, _AGENT_REPOSITORY_KNN_TOP_K, min_value=1, max_value=20)

    query_vector = None
    query_embedding_model = ""
    try:
        vectors, model_used = encode_texts_with_qwen_embedding([query])
        if getattr(vectors, "shape", (0, 0))[0] > 0:
            query_vector = vectors[0]
            query_embedding_model = str(model_used or "").strip()
    except Exception:
        query_vector = None
        query_embedding_model = ""

    try:
        knn_result = search_repository_chunks(
            user_id=int(user_id),
            query=query,
            top_k=use_top_k,
            score_threshold=_AGENT_REPOSITORY_KNN_SCORE_THRESHOLD,
            query_vector=query_vector,
            query_embedding_model=query_embedding_model,
        )
    except Exception:
        if query_vector is None:
            raise
        knn_result = search_repository_chunks(
            user_id=int(user_id),
            query=query,
            top_k=use_top_k,
            score_threshold=_AGENT_REPOSITORY_KNN_SCORE_THRESHOLD,
        )

    raw_hits = knn_result.get("hits") if isinstance(knn_result.get("hits"), list) else []
    hits = []
    for hit in raw_hits[:use_top_k]:
        if not isinstance(hit, dict):
            continue
        hits.append({
            "chunk_id": hit.get("chunk_id"),
            "filename": hit.get("filename"),
            "qualified_name": hit.get("qualified_name"),
            "class_name": hit.get("class_name"),
            "access": hit.get("access"),
            "signature": _truncate_text(hit.get("signature"), limit=200),
            "summary": _truncate_text(hit.get("summary"), limit=240),
            "start_line": hit.get("start_line"),
            "end_line": hit.get("end_line"),
            "score": hit.get("score"),
        })
    return {
        "query": query,
        "top_k": use_top_k,
        "hit_count": len(hits),
        "embedding_model": knn_result.get("embedding_model"),
        "vector_db_backend": knn_result.get("vector_db_backend"),
        "hits": hits,
    }


def _tool_web_search(query, limit=None, engines=None):
    return web_search_via_modelscope_mcp(
        query=query,
        limit=limit,
        engines=engines,
    )


def _tool_web_fetch_content(url, max_chars=None):
    return web_fetch_content_via_modelscope_mcp(
        url=url,
        max_chars=max_chars,
    )


def _analyze_submission_output_image_for_agent(problem, submission_id, test_points):
    if not submission_id or not isinstance(problem, dict):
        return "", None, False
    problem_text = str(problem.get("content") or "").strip()
    if not problem_text:
        return "", None, False

    points = []
    for idx, tp in enumerate(test_points or [], start=1):
        if not isinstance(tp, dict):
            continue
        item = dict(tp)
        if item.get("test_index") in (None, ""):
            item["test_index"] = item.get("index") or idx
        points.append(item)

    if not points:
        return "", None, False

    try:
        analyzed = analyze_submission_output_image_against_problem(
            problem_text=problem_text,
            submission_id=submission_id,
            test_points=points,
        )
    except Exception:
        return "", None, False

    if not isinstance(analyzed, dict):
        return "", None, False
    analysis = str(analyzed.get("analysis") or "").strip()
    test_index = analyzed.get("test_index")
    has_output_image = bool(analyzed.get("has_output_image"))
    return analysis, test_index, has_output_image



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
        "要求：1. 不要臆造文件或评测结果。 2. 题目给的提示以及用户追加的提示非常重要，请优先满足。 3. 如果提交后没有获得满分，必须在本地复现错误、编译、运行，决不允许编辑完直接再提交。",
        "强制流程：任意一次 submit_evaluation 未满分后，下一次 submit_evaluation 前，必须先本地复现失败并验证修复，禁止跳过本地验证直接再提交。",
        "当题意、算法细节或库函数语义不确定时，调用联网搜索工具查证。",
        "当需要复杂的公式推导/数值校验时，请用 python 写程序去算，不要自己猜。",
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
    file_size = int(os.path.getsize(abs_path))
    if file_size > _READ_FILE_HARD_LIMIT_BYTES:
        file_kb = file_size / 1024.0
        return {
            "path": os.path.relpath(abs_path, workspace_dir),
            "content": f"文件太大（{file_kb:.1f}KB）无法完整返回，请使用正则搜索或语义搜索工具。",
            "truncated": True,
        }
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
    timeout_val = _clamp_int(timeout_seconds, 60, min_value=1, max_value=_TOOL_TIMEOUT_MAX_SECONDS)
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
                "description": "读取工作目录内文件内容。若文件超过10KB，将返回大文件提示并建议使用正则/语义搜索。",
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
                "name": "search_useful_code",
                "description": "在代码仓库里进行语义检索，寻找与需求描述最相关的函数或类。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "description": {"type": "string", "description": "你需要的功能描述"},
                        "top_k": {"type": "integer", "description": f"返回条数，默认 {_AGENT_REPOSITORY_KNN_TOP_K}"},
                    },
                    "required": ["description"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "web_search",
                "description": "联网搜索工具，返回网页标题、URL、摘要。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "检索关键词"},
                        "limit": {"type": "integer", "description": "结果数量，默认 5，最大 50"},
                        "engines": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "搜索引擎列表，国内网络建议 [\"baidu\"] 或 [\"csdn\", \"juejin\"]",
                        },
                    },
                    "required": ["query"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "web_fetch_content",
                "description": "根据 URL 获取网页正文内容，用于阅读搜索结果详情。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "要抓取的网页 URL"},
                        "max_chars": {"type": "integer", "description": "正文最大字符数，默认 30000"},
                    },
                    "required": ["url"],
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


def _build_initial_prompt(problem, workspace_dir, main_code_path, core_hints=None, extra_prompt=""):
    lang = (problem.get("lang") or "matlab").lower()
    initial_code = (problem.get("initial_code") or "").strip()
    title = str(problem.get("title", "") or "").strip()
    content = str(problem.get("content", "") or "").strip()
    hint_lines = _dedupe_keep_order(core_hints or [])[:8]
    user_extra_prompt = str(extra_prompt or "").strip()
    if len(user_extra_prompt) > 4000:
        user_extra_prompt = user_extra_prompt[:4000]
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
    if user_extra_prompt:
        lines.extend([
            "",
            "下面是用户追加的额外提示词，这些提示词可能包含用户对题目的理解、解题思路建议、测试用例信息等重要内容，请务必仔细阅读并优先满足：",
            user_extra_prompt,
            "我将这些内容再重复一遍，请确保你都考虑到了：",
            user_extra_prompt,
        ])
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
        "",
    ])
    if lang in ("python", "py"):
        lines.append("系统提供了 python3 以及 numpy、pandas 等一切必要的工具，你不必自己安装依赖。")
        lines.append("")
    elif lang in ("matlab", "octave"):
        lines.append("系统没有 MATLAB 环境，但提供了 octave 环境，请用 octave 来代替执行 MATLAB 代码。")
        lines.append("")
    if user_extra_prompt:
        lines.extend([
            "最后再次强调用户追加的额外提示词，请务必仔细阅读并优先满足：",
            user_extra_prompt,
        ])
    return "\n".join(lines).strip()




__all__ = [name for name in globals().keys() if not name.startswith("__")]
