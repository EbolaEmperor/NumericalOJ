#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
import json

from flask import Blueprint, jsonify, request

from oj_modules.ai.code_feedback import (
    generate_ai_code_marks_from_submission_context,
)
from oj_modules.ai.client import resolve_llm_endpoint_snapshot
from oj_modules.db_services import (
    get_cached_ai_code_marks_for_submission,
    get_submission_by_id,
    save_submission_ai_code_marks_json,
)
from oj_modules.problems.context import build_problem_detail_context
from oj_modules.repository.includes import (
    extract_includes_from_code,
    get_user_repository_files_by_names,
)
from oj_modules.submissions.repository_snapshots import (
    resolve_submission_repository_user_id,
)
from oj_modules.security.throttling import rate_limit_hit


ai_bp = Blueprint('ai', __name__)

# Redis 客户端（限流）。由 oj.py 的 init_ai_module 注入；为空时限流 fail-open。
_rds = None
# AI 标注是昂贵的 LLM 调用，按用户限流。
_MARKS_MAX_PER_WINDOW = 15
_MARKS_WINDOW = 300


def _truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def init_ai_module(redis_client):
    global _rds
    _rds = redis_client


from oj_modules.security.auth import current_user, is_admin


def _load_accessible_problem(user, raw_problem_id):
    try:
        problem_id = int(raw_problem_id)
    except (TypeError, ValueError):
        return None, None, (jsonify(success=False, message="题目不存在"), 404)

    context, error_code = build_problem_detail_context(user, problem_id)
    if error_code == "not_found":
        return None, None, (jsonify(success=False, message="题目不存在"), 404)
    if error_code == "forbidden":
        return None, None, (jsonify(success=False, message="无权限访问该题目"), 403)
    return context["problem"], problem_id, None


@ai_bp.route('/ask_ai_code_marks', methods=['POST'])
def ask_ai_code_marks():
    data = request.get_json()
    if not data:
        return jsonify(success=False, message="缺少请求体"), 400
    unsupported_keys = sorted(set(data) - {"submission_id", "force_refresh"})
    if unsupported_keys:
        return jsonify(success=False, message=f"不支持的参数：{', '.join(unsupported_keys)}"), 400

    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    sid = data.get('submission_id', '')
    submission = get_submission_by_id(sid)
    if not submission:
        return jsonify(success=False, message="提交记录不存在"), 404

    if submission['username'] != user['username'] and not is_admin(user):
        return jsonify(success=False, message="无权访问该提交"), 403

    problem, problem_id, error_response = _load_accessible_problem(user, submission.get('problem_id'))
    if error_response is not None:
        return error_response

    problem_content = problem.get('content') or ''
    if not problem_content:
        return jsonify(success=False, message="缺少题目内容"), 400

    user_code = str(submission.get('code') or '').replace('\r\n', '\n').replace('\r', '\n')
    if not user_code.strip():
        return jsonify(success=False, message="提交记录没有可标注的代码"), 400

    force_refresh = bool(data.get('force_refresh'))
    if not force_refresh:
        cached_result = get_cached_ai_code_marks_for_submission(submission)
        if cached_result:
            return jsonify(**cached_result, source='cache')

    # 仅在需要真正生成（缓存未命中或 force_refresh 绕过缓存）时限流，避免被反复刷生成昂贵标注。
    allowed, retry = rate_limit_hit(_rds, f"ai:marks:{user['username']}", _MARKS_MAX_PER_WINDOW, _MARKS_WINDOW)
    if not allowed:
        return jsonify(success=False, message=f"请求过于频繁，请 {retry} 秒后再试"), 429

    test_points = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in (submission.get("test_points") or [])])

    included_files = extract_includes_from_code(user_code)
    repository_files = {}
    if included_files:
        submission_owner_id = resolve_submission_repository_user_id(sid)
        repository_files = get_user_repository_files_by_names(
            submission_owner_id,
            included_files,
            submission_id=sid,
        )

    try:
        # 一次请求只解析一次端点。即使管理员在生成过程中修改全站绑定或端点，
        # 本次生成仍使用这里取得的不可变快照。
        marks_endpoint = resolve_llm_endpoint_snapshot(
            feature_key="ai_code_annotation",
            allowed_categories={"omni", "text"},
            purpose="AI 代码标注",
        )
        needs_image_analysis = any(
            _truthy((point or {}).get("has_output_image"))
            and str((point or {}).get("status") or "").strip().lower() != "accepted"
            for point in (submission.get("test_points") or [])
            if isinstance(point, dict)
        )
        image_endpoint = None
        if needs_image_analysis:
            image_endpoint = resolve_llm_endpoint_snapshot(
                feature_key="code_image_analysis",
                allowed_categories={"omni", "vision"},
                purpose="代码图片分析",
            )
        result = generate_ai_code_marks_from_submission_context(
            problem_content=problem_content,
            user_code=user_code,
            test_points_text=test_points,
            repository_files=repository_files,
            submission_id=sid,
            test_points=submission.get("test_points") or [],
            max_issues=8,
            timeout=240,
            endpoint=marks_endpoint,
            image_endpoint=image_endpoint,
        )
        issues = result.get('issues') or []
        summary = str(result.get('summary') or '').strip()
        code_used = str(result.get('code_used') or user_code)
        image_mismatch_analysis = str(result.get('image_mismatch_analysis') or '').strip()
        image_analysis_test_index = result.get('image_analysis_test_index')
        cache_payload = {
            "issues": issues,
            "summary": summary,
            "code_used": code_used,
            "image_mismatch_analysis": image_mismatch_analysis,
            "image_analysis_test_index": image_analysis_test_index,
            "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "model": marks_endpoint.model,
        }
        save_submission_ai_code_marks_json(sid, cache_payload)
        return jsonify(
            success=True,
            issues=issues,
            summary=summary,
            code_used=code_used,
            image_mismatch_analysis=image_mismatch_analysis,
            image_analysis_test_index=image_analysis_test_index,
            source='generated',
        )
    except Exception as e:
        return jsonify(success=False, message=f"标注生成失败：{str(e)}"), 500
