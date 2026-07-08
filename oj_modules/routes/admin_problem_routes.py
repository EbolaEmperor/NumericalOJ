#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import pymysql
import shutil
import zipfile
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from config import AI_TUTOR_MODEL, QWEN_CODER_MODEL, QWEN_OMNI_MODEL, QWEN_TEXT_MODEL
from oj_modules.ai_utils import DEFAULT_WRITTEN_GRADING_RULES_TEXT

from oj_modules.db_services import (
    create_problem,
    get_db_connection,
    get_problem,
    get_user_by_username,
    normalize_programming_grading_model,
    normalize_programming_output_filename,
    normalize_written_grading_model,
    safe_table_name,
    update_problem,
)
from oj_modules.testdata_services import TestdataValidationError, import_testdata_zip


admin_problem_bp = Blueprint('admin_problem', __name__)
ALLOWED_EXTENSIONS = {'zip'}
_DEFAULT_WRITTEN_GRADING_MODEL = (
    f"{str(QWEN_TEXT_MODEL or '').strip().lower()}-thinking"
    if str(QWEN_TEXT_MODEL or "").strip()
    else f"{str(AI_TUTOR_MODEL or '').strip().lower()}-thinking"
)
_WRITTEN_GRADING_MODEL_OPTIONS = [
    item for item in dict.fromkeys([
        f"{str(QWEN_TEXT_MODEL or '').strip().lower()}-thinking" if str(QWEN_TEXT_MODEL or "").strip() else "",
        str(QWEN_TEXT_MODEL or "").strip().lower(),
        f"{str(AI_TUTOR_MODEL or '').strip().lower()}-thinking" if str(AI_TUTOR_MODEL or "").strip() else "",
        str(AI_TUTOR_MODEL or "").strip().lower(),
        "mimo",  # MIMO（xiaomimimo OpenAI 兼容端点）
    ])
    if item
]
if _DEFAULT_WRITTEN_GRADING_MODEL and _DEFAULT_WRITTEN_GRADING_MODEL not in _WRITTEN_GRADING_MODEL_OPTIONS:
    _WRITTEN_GRADING_MODEL_OPTIONS.insert(0, _DEFAULT_WRITTEN_GRADING_MODEL)
_DEFAULT_WRITTEN_GRADING_PROMPT = DEFAULT_WRITTEN_GRADING_RULES_TEXT
_DEFAULT_PROGRAMMING_GRADING_MODEL = (
    str(QWEN_OMNI_MODEL or '').strip().lower()
    or str(QWEN_TEXT_MODEL or '').strip().lower()
)
_PROGRAMMING_GRADING_MODEL_OPTIONS = [
    item for item in dict.fromkeys([
        str(QWEN_CODER_MODEL or '').strip().lower(),
        str(QWEN_OMNI_MODEL or '').strip().lower(),
        str(QWEN_TEXT_MODEL or '').strip().lower(),
    ])
    if item
]
if _DEFAULT_PROGRAMMING_GRADING_MODEL and _DEFAULT_PROGRAMMING_GRADING_MODEL not in _PROGRAMMING_GRADING_MODEL_OPTIONS:
    _PROGRAMMING_GRADING_MODEL_OPTIONS.insert(0, _DEFAULT_PROGRAMMING_GRADING_MODEL)


def _wants_json_response():
    if request.is_json:
        return True
    accept = request.headers.get('Accept', '')
    return 'application/json' in accept and 'text/html' not in accept


def _json_or_problem_redirect(message, status=400, *, problem_id=None):
    if _wants_json_response():
        return jsonify(success=False, message=message), status
    flash(message, 'danger')
    if problem_id is not None:
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
    return redirect(url_for('problem_core.problem_list'))


from oj_modules.auth_helpers import current_user, is_admin


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_time_limit_ms_from_form(form):
    """
    支持两种字段（任选其一）：
      - time_limit_s：秒（推荐）
      - time_limit_ms：毫秒
    都为空就用默认 2000ms。
    """
    tls = (form.get('time_limit_s') or '').strip()
    tlms = (form.get('time_limit') or '').strip()
    if tls:
        try:
            return int(float(tls) * 1000)
        except Exception:
            pass
    if tlms:
        try:
            return int(tlms)
        except Exception:
            pass
    return 2000


def parse_written_grading_mode_from_form(form, default=1):
    raw = str(form.get('written_grading_mode', default) or default).strip()
    try:
        mode = int(raw)
    except Exception:
        mode = int(default)
    return mode if mode in (1, 2, 3, 4) else int(default)


def parse_written_grading_model_from_form(form, default=_DEFAULT_WRITTEN_GRADING_MODEL):
    raw = str(form.get('written_grading_model', default) or default).strip().lower()
    return normalize_written_grading_model(raw, default=default)


def parse_written_grading_prompt_from_form(form):
    text = str(form.get('written_grading_prompt') or '').strip()
    if len(text) > 12000:
        text = text[:12000]
    return text


def parse_programming_grading_mode_from_form(form, default=1):
    raw = str(form.get('programming_grading_mode', default) or default).strip()
    try:
        mode = int(raw)
    except Exception:
        mode = int(default)
    return mode if mode in (1, 2, 3) else int(default)


def parse_programming_output_filename_from_form(form, default="output.png"):
    raw = str(form.get('programming_output_filename') or default).strip()
    return normalize_programming_output_filename(raw, default=default)


def parse_programming_grading_model_from_form(form, default=_DEFAULT_PROGRAMMING_GRADING_MODEL):
    raw = str(form.get('programming_grading_model', default) or default).strip().lower()
    return normalize_programming_grading_model(raw, default=default)


def _form_has_promptly_review_fields(form):
    return any(
        key in form
        for key in (
            'promptly_brief',
            'promptly_prompt_requirements',
            'promptly_example_reply',
            'promptly_example_replies',
            'promptly_example_replies_json',
        )
    )


def _promptly_examples_from_form(form):
    examples = []
    json_raw = str(form.get('promptly_example_replies_json') or '').strip()
    if not json_raw:
        json_raw = str(form.get('promptly_example_replies') or '').strip()
    if json_raw:
        try:
            parsed = json.loads(json_raw)
            if isinstance(parsed, list):
                examples.extend(str(item or '').strip() for item in parsed)
            elif isinstance(parsed, str):
                examples.extend(line.strip() for line in parsed.splitlines())
        except Exception:
            examples.extend(line.strip() for line in json_raw.splitlines())

    if hasattr(form, 'getlist'):
        examples.extend(str(item or '').strip() for item in form.getlist('promptly_example_reply'))
    else:
        single = str(form.get('promptly_example_reply') or '').strip()
        if single:
            examples.append(single)
    return [item for item in examples if item]


def build_promptly_review_prompt_value(brief='', prompt_requirements='', example_replies=None):
    payload = {
        "brief": str(brief or '').strip(),
        "prompt_requirements": str(prompt_requirements or '').strip(),
        "example_replies": [
            str(item or '').strip()
            for item in (example_replies or [])
            if str(item or '').strip()
        ],
    }
    return json.dumps(payload, ensure_ascii=False, separators=(',', ':'))


def parse_programming_grading_prompt_from_form(form):
    if _form_has_promptly_review_fields(form):
        text = build_promptly_review_prompt_value(
            brief=form.get('promptly_brief') or '',
            prompt_requirements=form.get('promptly_prompt_requirements') or '',
            example_replies=_promptly_examples_from_form(form),
        )
        return text[:12000]

    text = str(form.get('programming_grading_prompt') or '').strip()
    if len(text) > 12000:
        text = text[:12000]
    return text


@admin_problem_bp.route('/admin/add_problem', methods=['GET', 'POST'])
def add_problem():
    user = current_user()
    if not is_admin(user):
        if _wants_json_response():
            return jsonify(success=False, message="无权限"), 403
        return "<h3>无权限</h3>"

    if request.method == 'POST':
        title = request.form.get('title').strip()
        content = request.form.get('content').strip()
        initial_code = request.form.get('initial_code', '').strip()
        test_code = request.form.get('test_code', '').strip()
        forbidden_func = request.form.get('forbidden_func', '').strip()
        problem_type = request.form.get('type')
        programming_grading_mode = parse_programming_grading_mode_from_form(request.form, default=1)
        programming_grading_model = parse_programming_grading_model_from_form(request.form, default=_DEFAULT_PROGRAMMING_GRADING_MODEL)
        programming_output_filename = parse_programming_output_filename_from_form(request.form, default="output.png")
        programming_grading_prompt = parse_programming_grading_prompt_from_form(request.form)
        written_grading_mode = parse_written_grading_mode_from_form(request.form, default=1)
        written_grading_model = parse_written_grading_model_from_form(request.form, default=_DEFAULT_WRITTEN_GRADING_MODEL)
        written_grading_prompt = parse_written_grading_prompt_from_form(request.form)
        lang = (request.form.get('lang') or 'matlab').strip().lower()
        time_limit_ms = parse_time_limit_ms_from_form(request.form)
        submission_limit = int(request.form.get('submission_limit', 10))

        if not title or not content:
            if _wants_json_response():
                return jsonify(success=False, message="标题和内容不能为空"), 400
            return render_template(
                'add_problem.html',
                user=user,
                error_message="标题和内容不能为空",
                programming_grading_model_options=_PROGRAMMING_GRADING_MODEL_OPTIONS,
                default_programming_grading_model=_DEFAULT_PROGRAMMING_GRADING_MODEL,
                written_grading_model_options=_WRITTEN_GRADING_MODEL_OPTIONS,
                default_written_grading_model=_DEFAULT_WRITTEN_GRADING_MODEL,
                default_written_grading_prompt=_DEFAULT_WRITTEN_GRADING_PROMPT,
            )

        problem_id = create_problem(
            title,
            content,
            initial_code,
            test_code,
            forbidden_func,
            problem_type,
            lang,
            time_limit_ms,
            submission_limit,
            programming_grading_mode,
            programming_grading_model,
            programming_output_filename,
            programming_grading_prompt,
            written_grading_mode,
            written_grading_model,
            written_grading_prompt,
        )
        if _wants_json_response():
            return jsonify(success=True, problem_id=problem_id, message="题目创建成功")
        return redirect(url_for('problem_core.problem_list'))

    return render_template(
        'add_problem.html',
        user=user,
        error_message=None,
        programming_grading_model_options=_PROGRAMMING_GRADING_MODEL_OPTIONS,
        default_programming_grading_model=_DEFAULT_PROGRAMMING_GRADING_MODEL,
        written_grading_model_options=_WRITTEN_GRADING_MODEL_OPTIONS,
        default_written_grading_model=_DEFAULT_WRITTEN_GRADING_MODEL,
        default_written_grading_prompt=_DEFAULT_WRITTEN_GRADING_PROMPT,
    )


@admin_problem_bp.route('/admin/edit_problem/<int:problem_id>', methods=['GET', 'POST'])
def edit_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        if _wants_json_response():
            return jsonify(success=False, message="无权限"), 403
        return "<h3>无权限</h3>"

    problem = get_problem(problem_id)
    if not problem:
        if _wants_json_response():
            return jsonify(success=False, message="题目不存在"), 404
        return "<h3>题目不存在</h3>"

    if request.method == 'POST':
        new_title = request.form.get('title').strip()
        new_content = request.form.get('content').strip()
        new_initial_code = request.form.get('initial_code', '').strip()
        new_test_code = request.form.get('test_code', '').strip()
        forbidden_func = request.form.get('forbidden_func', '').strip()
        new_lang = (request.form.get('lang') or problem.get('lang') or 'matlab').strip().lower()
        has_time_limit_input = 'time_limit_s' in request.form or 'time_limit' in request.form
        if has_time_limit_input:
            new_time_limit_ms = parse_time_limit_ms_from_form(request.form)
        else:
            new_time_limit_ms = problem.get('time_limit') or 2000
        new_submission_limit = int(request.form.get('submission_limit', problem.get('submission_limit', 10)))
        default_programming_mode = problem.get('programming_grading_mode', 1)
        new_programming_grading_mode = parse_programming_grading_mode_from_form(request.form, default=default_programming_mode)
        default_programming_model = problem.get('programming_grading_model', _DEFAULT_PROGRAMMING_GRADING_MODEL)
        new_programming_grading_model = parse_programming_grading_model_from_form(request.form, default=default_programming_model)
        default_output_filename = problem.get('programming_output_filename', 'output.png')
        new_programming_output_filename = parse_programming_output_filename_from_form(request.form, default=default_output_filename)
        new_programming_grading_prompt = parse_programming_grading_prompt_from_form(request.form)
        default_mode = problem.get('written_grading_mode', 1)
        new_written_grading_mode = parse_written_grading_mode_from_form(request.form, default=default_mode)
        default_model = problem.get('written_grading_model', _DEFAULT_WRITTEN_GRADING_MODEL)
        new_written_grading_model = parse_written_grading_model_from_form(request.form, default=default_model)
        new_written_grading_prompt = parse_written_grading_prompt_from_form(request.form)

        if not new_title or not new_content:
            return render_template(
                'edit_problem.html',
                problem=problem,
                user=user,
                error_message="标题和内容不能为空",
                programming_grading_model_options=_PROGRAMMING_GRADING_MODEL_OPTIONS,
                default_programming_grading_model=_DEFAULT_PROGRAMMING_GRADING_MODEL,
                written_grading_model_options=_WRITTEN_GRADING_MODEL_OPTIONS,
                default_written_grading_model=_DEFAULT_WRITTEN_GRADING_MODEL,
            )

        update_problem(
            problem_id,
            new_title,
            new_content,
            new_initial_code,
            new_test_code,
            forbidden_func,
            new_lang,
            new_time_limit_ms,
            new_submission_limit,
            new_programming_grading_mode,
            new_programming_grading_model,
            new_programming_output_filename,
            new_programming_grading_prompt,
            new_written_grading_mode,
            new_written_grading_model,
            new_written_grading_prompt,
        )
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    return render_template(
        'edit_problem.html',
        problem=problem,
        user=user,
        error_message=None,
        programming_grading_model_options=_PROGRAMMING_GRADING_MODEL_OPTIONS,
        default_programming_grading_model=_DEFAULT_PROGRAMMING_GRADING_MODEL,
        written_grading_model_options=_WRITTEN_GRADING_MODEL_OPTIONS,
        default_written_grading_model=_DEFAULT_WRITTEN_GRADING_MODEL,
    )


@admin_problem_bp.app_errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    flash('上传的文件太大。最大允许 256MB。', 'danger')
    return redirect(request.url)


@admin_problem_bp.route('/admin/upload_testdata/<int:problem_id>', methods=['POST'])
def upload_testdata(problem_id):
    user = current_user()
    if not is_admin(user):
        return _json_or_problem_redirect('无权限进行此操作。', 403, problem_id=problem_id)

    if 'testdata_zip' not in request.files:
        return _json_or_problem_redirect('没有文件部分。', 400, problem_id=problem_id)

    file = request.files['testdata_zip']
    if file.filename == '':
        return _json_or_problem_redirect('未选择文件。', 400, problem_id=problem_id)

    if not (file and allowed_file(file.filename)):
        return _json_or_problem_redirect('只允许上传 ZIP 文件。', 400, problem_id=problem_id)

    filename = secure_filename(file.filename)
    temp_path = os.path.join('tmp', filename)
    extract_path = os.path.join('tmp', f'extracted_{problem_id}')

    try:
        os.makedirs('tmp', exist_ok=True)
        file.save(temp_path)
        import_testdata_zip(problem_id=problem_id, zip_path=temp_path, extract_dir=extract_path)
        if _wants_json_response():
            return jsonify(success=True, message='测试数据上传成功。', problem_id=problem_id)
        flash('测试数据上传成功。', 'success')
    except zipfile.BadZipFile:
        if _wants_json_response():
            return jsonify(success=False, message='上传的文件不是有效的 ZIP 压缩包。'), 400
        flash('上传的文件不是有效的 ZIP 压缩包。', 'danger')
    except TestdataValidationError as e:
        if _wants_json_response():
            return jsonify(success=False, message=str(e)), 400
        flash(str(e), 'danger')
    except Exception as e:
        if _wants_json_response():
            return jsonify(success=False, message=f'上传过程中发生错误：{str(e)}'), 500
        flash(f'上传过程中发生错误：{str(e)}', 'danger')
    finally:
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))


@admin_problem_bp.route('/admin/delete_problem/<int:problem_id>', methods=['DELETE'])
def delete_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            problem = cursor.fetchone()
            if not problem:
                return jsonify(success=False, message="题目不存在"), 404

            cursor.execute("SELECT id FROM submissions WHERE problem_id=%s", (problem_id,))
            submission_ids = [row['id'] for row in cursor.fetchall()]
            deleted = {
                "submissions": len(submission_ids),
                "ai_detection_results": 0,
                "plagiarism_records": 0,
                "max_score": 0,
                "ac_record": 0,
                "submission_limits": 0,
                "agent_task_runs": 0,
                "class_homeworks": 0,
            }

            cursor.execute("DELETE FROM ai_detection_results WHERE problem_id=%s", (problem_id,))
            deleted["ai_detection_results"] = cursor.rowcount
            cursor.execute("DELETE FROM plagiarism_records WHERE problem_id=%s", (problem_id,))
            deleted["plagiarism_records"] = cursor.rowcount
            cursor.execute("DELETE FROM max_score WHERE problem_id=%s", (problem_id,))
            deleted["max_score"] = cursor.rowcount
            cursor.execute("DELETE FROM ac_record WHERE problem_id=%s", (problem_id,))
            deleted["ac_record"] = cursor.rowcount
            cursor.execute("DELETE FROM submission_limits WHERE problem_id=%s", (problem_id,))
            deleted["submission_limits"] = cursor.rowcount
            cursor.execute("DELETE FROM agent_task_runs WHERE problem_id=%s", (problem_id,))
            deleted["agent_task_runs"] = cursor.rowcount
            cursor.execute("DELETE FROM submissions WHERE problem_id=%s", (problem_id,))

            cursor.execute("SELECT class_en FROM class_table")
            for row in cursor.fetchall():
                table_name = row.get('class_en')
                if not table_name:
                    continue
                try:
                    safe_name = safe_table_name(table_name)
                except ValueError:
                    continue
                try:
                    cursor.execute(f"DELETE FROM `{safe_name}` WHERE problem_id=%s", (problem_id,))
                    deleted["class_homeworks"] += cursor.rowcount
                except pymysql.Error as exc:
                    if getattr(exc, 'args', [None])[0] != 1146:
                        raise

            cursor.execute("DELETE FROM problems WHERE id=%s", (problem_id,))
        conn.commit()
        return jsonify(success=True, message="题目删除成功", problem_id=problem_id, deleted=deleted)
    except pymysql.Error as e:
        return jsonify(success=False, message="数据库错误: " + str(e)), 500
    finally:
        conn.close()
