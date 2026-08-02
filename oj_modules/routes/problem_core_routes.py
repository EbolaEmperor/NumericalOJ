#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import logging
import time
from datetime import datetime
from uuid import uuid4

from flask import Blueprint, Response, current_app, flash, jsonify, redirect, render_template, request, stream_with_context, url_for
from werkzeug.utils import secure_filename

from oj_modules.db_services import (
    SubmissionLimitExceeded,
    archive_submission_by_id,
    archive_submission_file_by_id,
    can_submit,
    create_submission,
    get_agent_run_by_task_id,
    get_agent_runs_paginated,
    get_db_connection,
    get_filtered_submissions_paginated,
    get_latest_written_submission,
    get_problem,
    get_submission_problem_options,
    mark_submission_archive_failed,
    normalize_submission_list_status_filter,
    overwrite_written_submission,
    upsert_agent_run_snapshot,
)
from oj_modules.security.auth import current_user
from oj_modules.classroom.dashboard import (
    get_class_activity,
    get_layout_navigation_context,
    select_visible_class,
    visible_classes_for_user_cached,
)
from oj_modules.problems.agent_runs import decorate_agent_run_summaries
from oj_modules.problems.catalog import get_homeworks, get_user_classes_cached
from oj_modules.problems.context import (
    build_problem_detail_context,
    build_problem_library_context,
    build_problem_list_context,
)
from oj_modules.problems.presentation import (
    strip_problem_title_tags as _strip_problem_title_tags,
)
from oj_modules.submissions.written_artifacts import (
    WrittenSubmissionArtifactError,
    publish_manual_written_submission,
)


problem_core_bp = Blueprint('problem_core', __name__)
logger = logging.getLogger(__name__)

_evaluate_submission_task = None
_promptly_generate_submission_task = None
_transcribe_written_homework_task = None
_agent_solve_problem_task = None
_agent_generate_testdata_task = None
_get_agent_run_snapshot = None
_subscribe_agent_run_events = None


def init_problem_core_module(
    evaluate_submission_task,
    transcribe_written_homework_task,
    promptly_generate_submission_task=None,
    agent_solve_problem_task=None,
    agent_generate_testdata_task=None,
    get_agent_run_snapshot=None,
    subscribe_agent_run_events=None,
):
    global _evaluate_submission_task, _promptly_generate_submission_task, _transcribe_written_homework_task, _agent_solve_problem_task, _agent_generate_testdata_task, _get_agent_run_snapshot, _subscribe_agent_run_events
    _evaluate_submission_task = evaluate_submission_task
    _promptly_generate_submission_task = promptly_generate_submission_task
    _transcribe_written_homework_task = transcribe_written_homework_task
    _agent_solve_problem_task = agent_solve_problem_task
    _agent_generate_testdata_task = agent_generate_testdata_task
    _get_agent_run_snapshot = get_agent_run_snapshot
    _subscribe_agent_run_events = subscribe_agent_run_events


def _is_agent_state_finished(state):
    if not isinstance(state, dict):
        return False
    status = str(state.get("status") or "").strip().lower()
    return status in ("completed", "failed", "canceled", "cancelled")


def _build_agent_state_from_async_result(task_id):
    if not task_id or _agent_solve_problem_task is None:
        return None
    try:
        async_result = _agent_solve_problem_task.AsyncResult(task_id)
    except Exception:
        return None

    celery_state = str(async_result.state or "PENDING").upper()
    now = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    state = {
        "task_id": task_id,
        "status": "Pending",
        "message": "任务排队中",
        "round": 0,
        "max_rounds": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [],
        "updated_at": now,
        "celery_state": celery_state,
    }

    if celery_state in ("RECEIVED", "STARTED", "RETRY"):
        state["status"] = "Running"
        state["message"] = "任务执行中"
        return state

    if celery_state == "FAILURE":
        state["status"] = "Failed"
        state["message"] = str(async_result.result) if async_result.result is not None else "任务执行失败"
        return state

    if celery_state == "SUCCESS":
        result_data = async_result.result if isinstance(async_result.result, dict) else {}
        state["status"] = "Completed" if result_data.get("success") else "Failed"
        state["message"] = result_data.get("message") or "任务已结束"
        state["final_submission_id"] = result_data.get("final_submission_id")
        state["latest_submission_id"] = result_data.get("final_submission_id")
        state["attempts"] = result_data.get("attempts") or []
        return state

    return state


def _get_agent_run_state(task_id):
    state = _get_agent_run_snapshot(task_id) if _get_agent_run_snapshot is not None else None
    if isinstance(state, dict):
        return state
    state = get_agent_run_by_task_id(task_id)
    if isinstance(state, dict):
        return state
    return _build_agent_state_from_async_result(task_id)


def _submission_limit_redirect(problem_id, submission_limit):
    flash(f'您对此题的提交次数已达到上限（{submission_limit}次）！', 'danger')
    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))


def _record_archive_failure(submission_id, counted_submission_limit):
    try:
        mark_submission_archive_failed(
            submission_id,
            release_quota=counted_submission_limit is not None,
        )
    except Exception:
        # 保留最初的归档错误响应，同时把原子补偿失败作为可运维告警记录。
        logger.exception(
            '提交归档失败状态与配额补偿写入失败',
            extra={'submission_id': submission_id},
        )


def _load_expected_written_submission(username, problem_id, expected_id):
    latest = get_latest_written_submission(username, problem_id)
    if latest and int(latest['id']) == int(expected_id):
        return latest
    return None


@problem_core_bp.route('/problems', methods=['GET'])
def problem_list():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    context = build_problem_list_context(
        user,
        admin_class_view=(int(user.get('is_admin') or 0) == 1),
        selected_class_en=request.args.get('class_en'),
        include_dashboard=True,
        include_class_activity=False,
    )
    return render_template('problems/list.html', **context)


@problem_core_bp.route('/api/class-activity', methods=['GET'])
def class_activity_data():
    user = current_user()
    if not user:
        return jsonify(success=False, message='请先登录'), 401

    classes = visible_classes_for_user_cached(user)
    requested_class_en = str(request.args.get('class_en') or '').strip()
    if requested_class_en:
        selected_class = next(
            (
                item
                for item in classes
                if item.get('class_en') == requested_class_en
            ),
            None,
        )
        if not selected_class:
            return jsonify(success=False, message='无权查看该班级'), 403
    else:
        selected_class = select_visible_class(classes)

    if not selected_class:
        return jsonify(
            success=True,
            class_en=None,
            class_cn=None,
            activity=[],
        )

    class_en = selected_class['class_en']
    try:
        activity = get_class_activity(class_en)
    except Exception:
        logger.exception('加载班级活跃度失败：class_en=%s', class_en)
        return jsonify(success=False, message='班级活跃度加载失败'), 500

    return jsonify(
        success=True,
        class_en=class_en,
        class_cn=selected_class.get('class_cn'),
        activity=[
            {
                'day': item['day'].isoformat(),
                'count': int(item.get('count') or 0),
                'intensity': int(item.get('intensity') or 0),
                'future': bool(item.get('future')),
            }
            for item in activity
        ],
    )


@problem_core_bp.route('/api/layout-navigation', methods=['GET'])
def layout_navigation_data():
    user = current_user()
    if not user:
        return jsonify(success=False, message='请先登录'), 401
    try:
        context = get_layout_navigation_context(
            user,
            selected_class_en=request.args.get('class_en'),
        )
    except Exception:
        logger.exception('加载桌面导航计数失败')
        context = {"counts": {}, "agent_active": False}
    return jsonify(success=True, **context)


@problem_core_bp.route('/problems/all', methods=['GET'])
def problem_library():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))
    if int(user.get('is_admin') or 0) != 1:
        flash('无权限访问总题库', 'danger')
        return redirect(url_for('problem_core.problem_list'))
    return render_template(
        'problems/list.html',
        **build_problem_library_context(user),
    )


@problem_core_bp.route('/problem/<int:problem_id>', methods=['GET'])
def problem_detail(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    context, error_code = build_problem_detail_context(
        user,
        problem_id,
        selected_class_en=request.args.get('class_en'),
    )
    if error_code == "not_found":
        return "<h3>题目不存在</h3>"
    if error_code == "forbidden":
        flash('无权限访问该题目', 'danger')
        return redirect(url_for('problem_core.problem_list'))

    return render_template('problems/detail.html', **context)


@problem_core_bp.route('/admin/agent_solve_problem/<int:problem_id>', methods=['POST'])
def admin_agent_solve_problem(problem_id):
    user = current_user()
    if not user or user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message='题目不存在'), 404
    if int(problem.get('type') or 1) != 1:
        return jsonify(success=False, message='仅支持编程题'), 400
    if _agent_solve_problem_task is None:
        return jsonify(success=False, message='Agent 任务未初始化'), 500

    payload = request.get_json(silent=True) or {}
    extra_prompt = str(payload.get('extra_prompt') or '').strip()
    if len(extra_prompt) > 4000:
        extra_prompt = extra_prompt[:4000]

    task_id = uuid4().hex
    pending_state = {
        "task_id": task_id,
        "problem_id": int(problem.get("id") or problem_id),
        "problem_title": problem.get("title"),
        "requested_by": user.get("username"),
        "extra_prompt": extra_prompt,
        "status": "Pending",
        "message": "任务排队中",
        "round": 0,
        "max_rounds": 0,
        "best_score": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [{
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "level": "info",
            "message": "任务已创建，等待执行",
            "event_type": "created",
        }],
    }
    upsert_agent_run_snapshot(pending_state)

    try:
        _agent_solve_problem_task.apply_async(args=(problem_id, user['username'], extra_prompt), task_id=task_id)
    except Exception as e:
        pending_state["status"] = "Failed"
        pending_state["message"] = f"任务入队失败：{e}"
        pending_state["events"].append({
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "level": "error",
            "message": pending_state["message"],
            "event_type": "enqueue_error",
        })
        upsert_agent_run_snapshot(pending_state)
        return jsonify(success=False, message=pending_state["message"]), 500

    return jsonify(
        success=True,
        message='Agent 任务已启动',
        task_id=task_id,
        view_url=url_for('problem_core.admin_agent_run', task_id=task_id),
    )


@problem_core_bp.route('/admin/agent_generate_testdata/<int:problem_id>', methods=['POST'])
def admin_agent_generate_testdata(problem_id):
    user = current_user()
    if not user or user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message='题目不存在'), 404
    if int(problem.get('type') or 1) != 1:
        return jsonify(success=False, message='仅支持编程题'), 400
    if _agent_generate_testdata_task is None:
        return jsonify(success=False, message='数据生成 Agent 任务未初始化'), 500

    payload = request.get_json(silent=True) or {}
    standard_code = str(payload.get('standard_code') or '').strip()
    if not standard_code:
        return jsonify(success=False, message='标准程序不能为空'), 400
    data_requirement = str(payload.get('data_requirement') or '').strip()
    if len(data_requirement) > 4000:
        data_requirement = data_requirement[:4000]

    try:
        test_point_count = int(payload.get('test_point_count'))
    except Exception:
        return jsonify(success=False, message='测试点数量无效'), 400
    if test_point_count < 1 or test_point_count > 5000:
        return jsonify(success=False, message='测试点数量需在 1-5000 之间'), 400

    task_id = uuid4().hex
    pending_state = {
        "task_id": task_id,
        "problem_id": int(problem.get("id") or problem_id),
        "problem_title": problem.get("title"),
        "requested_by": user.get("username"),
        "status": "Pending",
        "message": "数据生成 Agent 任务排队中",
        "round": 0,
        "max_rounds": 0,
        "best_score": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [{
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "level": "info",
            "message": "数据生成 Agent 任务已创建，等待执行",
            "event_type": "created",
            "details": {
                "test_point_count": test_point_count,
                "has_data_requirement": bool(data_requirement),
            },
        }],
    }
    upsert_agent_run_snapshot(pending_state)

    try:
        _agent_generate_testdata_task.apply_async(
            args=(problem_id, user['username'], test_point_count, standard_code, data_requirement),
            task_id=task_id,
        )
    except Exception as e:
        pending_state["status"] = "Failed"
        pending_state["message"] = f"任务入队失败：{e}"
        pending_state["events"].append({
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "level": "error",
            "message": pending_state["message"],
            "event_type": "enqueue_error",
        })
        upsert_agent_run_snapshot(pending_state)
        return jsonify(success=False, message=pending_state["message"]), 500

    return jsonify(
        success=True,
        message='数据生成 Agent 任务已启动',
        task_id=task_id,
        view_url=url_for('problem_core.admin_agent_run', task_id=task_id),
    )


@problem_core_bp.route('/admin/agent_run/<task_id>', methods=['GET'])
def admin_agent_run(task_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))
    if user.get('is_admin') != 1:
        flash('无权限访问该页面', 'danger')
        return redirect(url_for('problem_core.problem_list'))

    state = _get_agent_run_state(task_id) or {"task_id": task_id}
    problem_id = state.get("problem_id")
    if not problem_id:
        problem_id = request.args.get("problem_id", type=int)
    problem = get_problem(problem_id) if problem_id else None

    latest_submission_id = state.get("latest_submission_id") or state.get("final_submission_id")
    return render_template(
        'agents/run.html',
        user=user,
        task_id=task_id,
        problem=problem,
        initial_state=state,
        latest_submission_id=latest_submission_id,
    )


@problem_core_bp.route('/admin/agent_run_status/<task_id>', methods=['GET'])
def admin_agent_run_status(task_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    if user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

    state = _get_agent_run_state(task_id) or {
        "task_id": task_id,
        "status": "Pending",
        "message": "任务排队中",
        "round": 0,
        "max_rounds": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [],
    }
    return jsonify(success=True, state=state)


@problem_core_bp.route('/admin/agent_run_stream/<task_id>', methods=['GET'])
def admin_agent_run_stream(task_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if user.get('is_admin') != 1:
        return jsonify({'error': 'Access denied'}), 403

    initial_state = _get_agent_run_state(task_id) or {
        "task_id": task_id,
        "status": "Pending",
        "message": "任务排队中",
        "round": 0,
        "max_rounds": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [],
    }

    def _encode_sse(event_name, payload):
        return f"event: {event_name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

    @stream_with_context
    def generate():
        first_payload = initial_state
        yield _encode_sse("status", first_payload)
        if _is_agent_state_finished(first_payload):
            yield _encode_sse("done", first_payload)
            return

        start_ts = time.time()
        pubsub = (
            _subscribe_agent_run_events(task_id)
            if _subscribe_agent_run_events is not None
            else None
        )
        if pubsub is None:
            last_marker = (
                first_payload.get("status"),
                first_payload.get("round"),
                first_payload.get("latest_submission_id"),
                first_payload.get("updated_at"),
            )
            while True:
                snapshot = _get_agent_run_state(task_id) or first_payload
                marker = (
                    snapshot.get("status"),
                    snapshot.get("round"),
                    snapshot.get("latest_submission_id"),
                    snapshot.get("updated_at"),
                )
                if marker != last_marker:
                    yield _encode_sse("status", snapshot)
                    last_marker = marker
                if _is_agent_state_finished(snapshot):
                    yield _encode_sse("done", snapshot)
                    return
                if time.time() - start_ts > 3600:
                    yield _encode_sse("timeout", snapshot)
                    return
                time.sleep(1.0)

        try:
            while True:
                msg = pubsub.get_message(timeout=15.0)
                now = time.time()
                if now - start_ts > 3600:
                    latest = _get_agent_run_state(task_id) or initial_state
                    yield _encode_sse("timeout", latest)
                    return

                if not msg:
                    yield ": keepalive\n\n"
                    continue

                if msg.get("type") != "message":
                    continue

                raw = msg.get("data")
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="ignore")
                try:
                    snapshot = json.loads(raw) if isinstance(raw, str) else raw
                except Exception:
                    continue
                if not isinstance(snapshot, dict):
                    continue

                yield _encode_sse("status", snapshot)
                if _is_agent_state_finished(snapshot):
                    yield _encode_sse("done", snapshot)
                    return
        finally:
            try:
                pubsub.close()
            except Exception:
                pass

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
    )


@problem_core_bp.route('/submit/<int:problem_id>', methods=['GET', 'POST'])
def submit_solution(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    problem = get_problem(problem_id)
    if not problem:
        return "<h3>题目不存在</h3>"

    if user['is_admin'] != 1:
        homeworks = get_homeworks(user)
        ddls = []
        for hw in homeworks:
            if hw['problem_id'] == problem_id:
                if hw['ddl']:
                    ddls.append(hw['ddl'])

        if ddls:
            latest_ddl = max(ddls)
            if latest_ddl < datetime.now():
                flash('无法提交已过期的作业', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    submission_limit = problem.get('submission_limit', 10)
    counted_submission_limit = submission_limit if user['is_admin'] != 1 else None

    if request.method == 'GET' and user['is_admin'] != 1:
        if not can_submit(user['username'], problem_id, submission_limit):
            return _submission_limit_redirect(problem_id, submission_limit)

    if request.method == 'POST':
        if problem['type'] == 1:
            try:
                programming_mode = int(problem.get('programming_grading_mode') or 1)
            except Exception:
                programming_mode = 1
            if programming_mode == 3:
                prompt_text = request.form.get('prompt', '')
                if not prompt_text.strip():
                    flash('Prompt 不能为空。', 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

                try:
                    submission_id = create_submission(
                        problem_id=problem_id,
                        problem_title=problem['title'],
                        username=user['username'],
                        code="",
                        score=0,
                        test_points=[],
                        status="Generating",
                        prompt_text=prompt_text,
                        generated_from_prompt=True,
                        submission_limit=counted_submission_limit,
                        user_id=user['id'],
                    )
                except SubmissionLimitExceeded:
                    return _submission_limit_redirect(problem_id, submission_limit)
                try:
                    archive_submission_by_id(submission_id, raise_errors=True)
                except Exception as e:
                    _record_archive_failure(submission_id, counted_submission_limit)
                    flash(f'提交归档失败，已停止入队：{str(e)}', 'danger')
                    return redirect(url_for('submission.submission_detail', submission_id=submission_id))

                if _promptly_generate_submission_task is None:
                    flash('提交成功，但 Promptly 生成任务未初始化。', 'warning')
                else:
                    _promptly_generate_submission_task.delay(submission_id)

                return redirect(url_for('submission.submission_detail', submission_id=submission_id))

            code = request.form.get('code', '')
            if not code.strip():
                flash('代码不能为空。', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

            try:
                submission_id = create_submission(
                    problem_id=problem_id,
                    problem_title=problem['title'],
                    username=user['username'],
                    code=code,
                    score=0,
                    test_points=[],
                    submission_limit=counted_submission_limit,
                    user_id=user['id'],
                )
            except SubmissionLimitExceeded:
                return _submission_limit_redirect(problem_id, submission_limit)
            try:
                archive_submission_by_id(submission_id, raise_errors=True)
            except Exception as e:
                _record_archive_failure(submission_id, counted_submission_limit)
                flash(f'提交归档失败，已停止入队：{str(e)}', 'danger')
                return redirect(url_for('submission.submission_detail', submission_id=submission_id))

            if _evaluate_submission_task is None:
                flash('提交成功，但评测任务未初始化。', 'warning')
            else:
                _evaluate_submission_task.delay(submission_id)

            return redirect(url_for('submission.submission_detail', submission_id=submission_id))

        if problem['type'] == 2:
            if 'file' not in request.files:
                flash('请上传文件。', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
            file = request.files['file']
            if file.filename == '':
                flash('未选择文件。', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
            filename = secure_filename(f"file_{file.filename}")

            try:
                written_mode = int(problem.get('written_grading_mode') or 1)
            except Exception:
                written_mode = 1

            lower_filename = filename.lower()
            if written_mode == 3:
                if not lower_filename.endswith('.zip'):
                    flash(f'错误：{filename} 不是 ZIP 文件（tex 文本批改模式仅支持 .zip）', 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
            else:
                if not lower_filename.endswith('.pdf'):
                    flash(f'错误：{filename} 不是 PDF 文件', 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

            # 纯人工批改：覆盖上一次提交
            if written_mode == 4:
                existing = get_latest_written_submission(user['username'], problem_id)
                if existing:
                    submission_id = existing['id']

                    def overwrite_record(expected_id, new_filename, expected_snapshot):
                        return overwrite_written_submission(
                            expected_id,
                            new_filename,
                            submission_limit=counted_submission_limit,
                            username=user['username'],
                            problem_id=problem_id,
                            user_id=user['id'],
                            expected_submission=expected_snapshot,
                        )

                    try:
                        publish_manual_written_submission(
                            uploaded_file=file,
                            filename=filename,
                            previous_submission=existing,
                            problem=problem,
                            user=user,
                            classes=get_user_classes_cached(user['id']),
                            overwrite_record=overwrite_record,
                            load_current_record=lambda expected_id: (
                                _load_expected_written_submission(
                                    existing['username'], problem_id, expected_id,
                                )
                            ),
                            max_bytes=int(
                                current_app.config.get('MAX_CONTENT_LENGTH')
                                or 256 * 1024 * 1024
                            ),
                        )
                    except Exception as exc:
                        if isinstance(exc.__cause__, SubmissionLimitExceeded):
                            return _submission_limit_redirect(problem_id, submission_limit)
                        if isinstance(exc, (WrittenSubmissionArtifactError, ValueError)):
                            error_message = str(exc)
                        else:
                            logger.exception(
                                '人工作业覆盖出现未预期异常',
                                extra={'submission_id': submission_id},
                            )
                            error_message = '新作业发布失败，已保留上一份有效作业'
                        flash(error_message, 'danger')
                        return redirect(url_for('submission.submission_detail', submission_id=submission_id))
                    return redirect(url_for('submission.submission_detail', submission_id=submission_id))
                # 首次提交：走普通 INSERT 流程（下方）

            try:
                submission_id = create_submission(
                    problem_id=problem_id,
                    problem_title=problem['title'],
                    username=user['username'],
                    code=" ",
                    score=0,
                    test_points=[filename],
                    submission_limit=counted_submission_limit,
                    user_id=user['id'],
                )
            except SubmissionLimitExceeded:
                return _submission_limit_redirect(problem_id, submission_limit)

            upload_folder = os.path.join('uploads', f"{submission_id}")
            try:
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)

                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)
                archive_submission_file_by_id(submission_id, file_path, filename, raise_errors=True)
            except Exception as e:
                _record_archive_failure(submission_id, counted_submission_limit)
                flash(f'提交归档失败，已停止入队：{str(e)}', 'danger')
                return redirect(url_for('submission.submission_detail', submission_id=submission_id))

            if written_mode != 4:
                try:
                    if _transcribe_written_homework_task is None:
                        raise RuntimeError("自动评分任务未初始化")
                    _transcribe_written_homework_task.delay(submission_id)
                except Exception as e:
                    flash(f'文件已提交，但自动评分任务入队失败：{str(e)}', 'warning')

            return redirect(url_for('submission.submission_detail', submission_id=submission_id))

    context, error_code = build_problem_detail_context(user, problem_id)
    if error_code == "not_found":
        return "<h3>题目不存在</h3>"
    if error_code == "forbidden":
        flash('无权限访问该题目', 'danger')
        return redirect(url_for('problem_core.problem_list'))
    return render_template('problems/detail.html', **context)


@problem_core_bp.route('/admin/agent_tasks')
def admin_agent_tasks():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))
    if user.get('is_admin') != 1:
        flash('无权限访问该页面', 'danger')
        return redirect(url_for('problem_core.problem_list'))

    page = max(1, request.args.get('page', 1, type=int))
    per_page = 20
    runs, total_pages = get_agent_runs_paginated(page=page, per_page=per_page)
    decorate_agent_run_summaries(runs)

    page_start = max(1, page - 8)
    page_end = min(total_pages, page + 8)
    page_numbers = list(range(page_start, page_end + 1))

    return render_template(
        'admin/agent_tasks.html',
        user=user,
        agent_runs=runs,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
    )


@problem_core_bp.route('/my_submissions')
def all_submissions():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    page = max(1, request.args.get('page', 1, type=int))
    per_page = 30
    query = str(request.args.get('q') or '').strip()[:120]
    status_filter = normalize_submission_list_status_filter(
        request.args.get('status')
    )
    problem_id = request.args.get('problem_id', type=int)
    if not problem_id or problem_id < 1:
        problem_id = None

    scope_username = None if user['is_admin'] else user['username']
    submissions, page, total_pages = get_filtered_submissions_paginated(
        username=scope_username,
        page=page,
        per_page=per_page,
        query=query,
        status_filter=status_filter,
        problem_id=problem_id,
        include_test_points=True,
    )
    for sub in submissions:
        sub['display_problem_title'] = _strip_problem_title_tags(sub.get('problem_title'))
        sub['is_ac'] = (sub.get('status') == 'Accepted')
        sub['display_language'] = str(sub.get('lang') or '—').upper()
        max_score = sub.get('max_score')
        try:
            max_score = int(max_score) if max_score is not None else None
        except (TypeError, ValueError):
            max_score = None
        sub['display_max_score'] = (
            max_score
            if max_score is not None and max_score > 0
            else (sub.get('test_points_count') or None)
        )

    problem_options = get_submission_problem_options(username=scope_username)
    current_problem_label = ''
    for option in problem_options:
        option['display_problem_title'] = _strip_problem_title_tags(
            option.get('problem_title')
        )
        option['filter_label'] = (
            f"P{int(option['problem_id']):04d} · "
            f"{option['display_problem_title']}"
        )
        if int(option['problem_id']) == int(problem_id or 0):
            current_problem_label = option['filter_label']

    page_start = max(1, page - 3)
    page_end = min(total_pages, page + 3)
    page_numbers = list(range(page_start, page_end + 1))

    return render_template(
        'submissions/all.html',
        submissions=submissions,
        user=user,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        problem_options=problem_options,
        current_problem_label=current_problem_label,
        filters={
            'q': query,
            'status': status_filter,
            'problem_id': problem_id,
        },
    )
