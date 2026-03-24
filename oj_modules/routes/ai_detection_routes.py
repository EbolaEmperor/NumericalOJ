#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Admin routes for AI code detection dashboard.
"""

import json
import re

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from oj_modules.ai_detection.task_tracker import (
    get_recent_tasks,
    record_task_submitted,
    TASK_TYPE_LABELS,
)
from oj_modules.db_services import (
    get_ai_detection_dashboard_summary,
    get_ai_detection_results_for_problem,
    get_ai_detection_results_for_user,
    get_all_classes_except_admin,
    get_all_problems,
    get_filtered_submissions_for_detection,
    get_problem,
    get_user_by_username,
)


ai_detection_bp = Blueprint('ai_detection', __name__)

_detect_single_task = None
_detect_batch_task = None
_detect_user_task = None
_detect_filtered_task = None


def init_ai_detection_module(detect_single, detect_batch, detect_user, detect_filtered):
    global _detect_single_task, _detect_batch_task, _detect_user_task, _detect_filtered_task
    _detect_single_task = detect_single
    _detect_batch_task = detect_batch
    _detect_user_task = detect_user
    _detect_filtered_task = detect_filtered


def _current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def _require_admin():
    user = _current_user()
    if not user or user.get('is_admin') != 1:
        return None, redirect(url_for('auth.login'))
    return user, None


def _strip_problem_title_tags(title):
    if title is None:
        return title
    original = str(title).strip()
    text = re.sub(r'\s*「[^」]{1,32}」\s*', ' ', original)
    text = re.sub(r'\s+', ' ', text).strip()
    return text if text else original


def _parse_filters_from_request():
    """Parse filter params from JSON or form POST, return a clean dict."""
    data = request.get_json(silent=True) or request.form

    def _int_or_none(key):
        v = data.get(key, '')
        if v is None or str(v).strip() == '':
            return None
        try:
            return int(v)
        except (ValueError, TypeError):
            return None

    def _str_or_none(key):
        v = data.get(key, '')
        if v is None or str(v).strip() == '':
            return None
        return str(v).strip()

    return {
        'class_en':     _str_or_none('class_en'),
        'username':     _str_or_none('username'),
        'problem_id':   _int_or_none('problem_id'),
        'submission_id':_int_or_none('submission_id'),
        'score_min':    _int_or_none('score_min'),
        'score_max':    _int_or_none('score_max'),
        'deduplicate':  str(data.get('deduplicate', '1')).strip() not in ('0', 'false', 'False'),
        'lang':         'matlab',
    }


@ai_detection_bp.route('/admin/ai_detection')
def dashboard():
    user, err = _require_admin()
    if err:
        return err

    summary = get_ai_detection_dashboard_summary()
    classes = get_all_classes_except_admin()
    problems = [
        p for p in get_all_problems()
        if (p.get('lang') or 'matlab').strip().lower() == 'matlab'
        and int(p.get('type') or 1) == 1
    ]
    problems.sort(key=lambda p: p['id'])

    return render_template(
        'ai_detection_dashboard.html',
        user=user,
        summary=summary,
        classes=classes,
        problems=problems,
        strip_tags=_strip_problem_title_tags,
    )


@ai_detection_bp.route('/admin/ai_detection/preview', methods=['POST'])
def preview_filtered():
    user, err = _require_admin()
    if err:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    filters = _parse_filters_from_request()
    try:
        rows = get_filtered_submissions_for_detection(**filters)
    except Exception as e:
        return jsonify({'success': False, 'message': f'查询出错: {e}'}), 400

    samples = [
        {
            'id': r['id'],
            'username': r['username'],
            'problem_id': r['problem_id'],
            'problem_title': _strip_problem_title_tags(r.get('problem_title') or ''),
            'score': r['score'],
            'status': r['status'],
        }
        for r in rows[:20]
    ]
    return jsonify({
        'success': True,
        'total': len(rows),
        'samples': samples,
    })


@ai_detection_bp.route('/admin/ai_detection/run_filtered', methods=['POST'])
def run_filtered_detection():
    user, err = _require_admin()
    if err:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    if _detect_filtered_task is None:
        return jsonify({'success': False, 'message': 'Detection task not registered'}), 500

    filters = _parse_filters_from_request()
    task = _detect_filtered_task.delay(filters)
    parts = []
    if filters.get('class_en'):   parts.append(f"班级={filters['class_en']}")
    if filters.get('username'):   parts.append(f"用户={filters['username']}")
    if filters.get('problem_id'): parts.append(f"题目={filters['problem_id']}")
    if filters.get('submission_id'): parts.append(f"提交={filters['submission_id']}")
    if filters.get('score_min') is not None or filters.get('score_max') is not None:
        lo = filters.get('score_min', '')
        hi = filters.get('score_max', '')
        parts.append(f"得分{lo}~{hi}")
    parts.append("去重" if filters.get('deduplicate') else "不去重")
    record_task_submitted(task.id, "filtered", "  ".join(parts) if parts else "全部 MATLAB 提交")
    return jsonify({
        'success': True,
        'message': '已提交检测任务，请稍后刷新页面查看结果',
        'task_id': task.id,
    })


@ai_detection_bp.route('/admin/ai_detection/problem/<int:problem_id>')
def problem_detail(problem_id):
    user, err = _require_admin()
    if err:
        return err

    problem = get_problem(problem_id)
    if not problem:
        return "<h3>题目不存在</h3>", 404

    risk_filter = request.args.get('risk', '').strip() or None
    results = get_ai_detection_results_for_problem(problem_id, risk_level=risk_filter)

    for r in results:
        try:
            r['_evidence'] = json.loads(r.get('llm_evidence') or '[]')
        except Exception:
            r['_evidence'] = []
        try:
            r['_signals'] = json.loads(r.get('behavior_detail') or '[]')
        except Exception:
            r['_signals'] = []

    return render_template(
        'ai_detection_dashboard.html',
        user=user,
        view='problem',
        problem=problem,
        results=results,
        risk_filter=risk_filter,
        strip_tags=_strip_problem_title_tags,
    )


@ai_detection_bp.route('/admin/ai_detection/student/<username>')
def student_detail(username):
    user, err = _require_admin()
    if err:
        return err

    results = get_ai_detection_results_for_user(username)
    for r in results:
        try:
            r['_evidence'] = json.loads(r.get('llm_evidence') or '[]')
        except Exception:
            r['_evidence'] = []
        try:
            r['_signals'] = json.loads(r.get('behavior_detail') or '[]')
        except Exception:
            r['_signals'] = []

    return render_template(
        'ai_detection_dashboard.html',
        user=user,
        view='student',
        target_username=username,
        results=results,
        strip_tags=_strip_problem_title_tags,
    )


@ai_detection_bp.route('/admin/ai_detection/run/<int:problem_id>', methods=['POST'])
def run_batch_detection(problem_id):
    user, err = _require_admin()
    if err:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    problem = get_problem(problem_id)
    if not problem:
        return jsonify({'success': False, 'message': '题目不存在'}), 404

    if _detect_batch_task is None:
        return jsonify({'success': False, 'message': 'Detection task not registered'}), 500

    task = _detect_batch_task.delay(problem_id)
    record_task_submitted(task.id, "batch", f"题目={problem_id} {_strip_problem_title_tags(problem.get('title',''))}")
    return jsonify({
        'success': True,
        'message': f'已提交批量检测任务 (task_id={task.id})',
        'task_id': task.id,
    })


@ai_detection_bp.route('/admin/ai_detection/run_single/<int:submission_id>', methods=['POST'])
def run_single_detection(submission_id):
    user, err = _require_admin()
    if err:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    if _detect_single_task is None:
        return jsonify({'success': False, 'message': 'Detection task not registered'}), 500

    task = _detect_single_task.delay(submission_id)
    record_task_submitted(task.id, "single", f"提交={submission_id}")
    return jsonify({
        'success': True,
        'message': f'已提交检测任务 (task_id={task.id})',
        'task_id': task.id,
    })


@ai_detection_bp.route('/admin/ai_detection/run_user/<username>', methods=['POST'])
def run_user_detection(username):
    user, err = _require_admin()
    if err:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    if _detect_user_task is None:
        return jsonify({'success': False, 'message': 'Detection task not registered'}), 500

    task = _detect_user_task.delay(username)
    record_task_submitted(task.id, "user", f"用户={username}")
    return jsonify({
        'success': True,
        'message': f'已提交用户 {username} 的检测任务 (task_id={task.id})',
        'task_id': task.id,
    })


@ai_detection_bp.route('/admin/ai_detection/api/summary')
def api_summary():
    user, err = _require_admin()
    if err:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    summary = get_ai_detection_dashboard_summary()
    # Convert to JSON-serialisable form
    return jsonify({'success': True, 'summary': {
        'level_counts': summary.get('level_counts', {}),
        'flagged_users': summary.get('flagged_users', []),
        'problem_stats': [
            {**p, 'problem_title': _strip_problem_title_tags(p.get('problem_title', ''))}
            for p in summary.get('problem_stats', [])
        ],
    }})


@ai_detection_bp.route('/admin/ai_detection/api/tasks')
def api_tasks():
    user, err = _require_admin()
    if err:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    tasks = get_recent_tasks(limit=20)
    for t in tasks:
        t['type_label'] = TASK_TYPE_LABELS.get(t.get('task_type', ''), t.get('task_type', ''))
    return jsonify({'success': True, 'tasks': tasks})


@ai_detection_bp.route('/admin/ai_detection/api/stop/<task_id>', methods=['POST'])
def stop_task(task_id):
    user, err = _require_admin()
    if err:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    import time
    from oj_modules.ai_detection.task_tracker import _load, _save

    # Revoke in Celery (terminate running worker process)
    try:
        task_ref = _detect_single_task or _detect_batch_task or _detect_user_task or _detect_filtered_task
        if task_ref is not None:
            task_ref.app.control.revoke(task_id, terminate=True, signal='SIGTERM')
    except Exception:
        pass

    # Mark stopped in Redis regardless
    data = _load(task_id) or {'task_id': task_id}
    if data.get('status') in ('running', 'pending'):
        data['status'] = 'failed'
        data['error'] = '管理员手动停止'
        data['finished_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
        _save(task_id, data)

    return jsonify({'success': True})
