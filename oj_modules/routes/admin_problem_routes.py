#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pymysql
import shutil
import zipfile
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from config import AI_TUTOR_MODEL, QWEN_TEXT_MODEL

from oj_modules.db_services import (
    create_problem,
    get_db_connection,
    get_problem,
    get_user_by_username,
    normalize_written_grading_model,
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
    ])
    if item
]
if _DEFAULT_WRITTEN_GRADING_MODEL and _DEFAULT_WRITTEN_GRADING_MODEL not in _WRITTEN_GRADING_MODEL_OPTIONS:
    _WRITTEN_GRADING_MODEL_OPTIONS.insert(0, _DEFAULT_WRITTEN_GRADING_MODEL)


def current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def is_admin(user):
    return user and user.get('is_admin') == 1


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
    return mode if mode in (1, 2) else int(default)


def parse_written_grading_model_from_form(form, default=_DEFAULT_WRITTEN_GRADING_MODEL):
    raw = str(form.get('written_grading_model', default) or default).strip().lower()
    return normalize_written_grading_model(raw, default=default)


@admin_problem_bp.route('/admin/add_problem', methods=['GET', 'POST'])
def add_problem():
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    if request.method == 'POST':
        title = request.form.get('title').strip()
        content = request.form.get('content').strip()
        initial_code = request.form.get('initial_code', '').strip()
        test_code = request.form.get('test_code', '').strip()
        forbidden_func = request.form.get('forbidden_func', '').strip()
        problem_type = request.form.get('type')
        written_grading_mode = parse_written_grading_mode_from_form(request.form, default=1)
        written_grading_model = parse_written_grading_model_from_form(request.form, default=_DEFAULT_WRITTEN_GRADING_MODEL)
        lang = (request.form.get('lang') or 'matlab').strip().lower()
        time_limit_ms = parse_time_limit_ms_from_form(request.form)
        submission_limit = int(request.form.get('submission_limit', 10))

        if not title or not content:
            return render_template(
                'add_problem.html',
                user=user,
                error_message="标题和内容不能为空",
                written_grading_model_options=_WRITTEN_GRADING_MODEL_OPTIONS,
                default_written_grading_model=_DEFAULT_WRITTEN_GRADING_MODEL,
            )

        create_problem(
            title,
            content,
            initial_code,
            test_code,
            forbidden_func,
            problem_type,
            lang,
            time_limit_ms,
            submission_limit,
            written_grading_mode,
            written_grading_model,
        )
        return redirect(url_for('problem_core.problem_list'))

    return render_template(
        'add_problem.html',
        user=user,
        error_message=None,
        written_grading_model_options=_WRITTEN_GRADING_MODEL_OPTIONS,
        default_written_grading_model=_DEFAULT_WRITTEN_GRADING_MODEL,
    )


@admin_problem_bp.route('/admin/edit_problem/<int:problem_id>', methods=['GET', 'POST'])
def edit_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    problem = get_problem(problem_id)
    if not problem:
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
        default_mode = problem.get('written_grading_mode', 1)
        new_written_grading_mode = parse_written_grading_mode_from_form(request.form, default=default_mode)
        default_model = problem.get('written_grading_model', _DEFAULT_WRITTEN_GRADING_MODEL)
        new_written_grading_model = parse_written_grading_model_from_form(request.form, default=default_model)

        if not new_title or not new_content:
            return render_template(
                'edit_problem.html',
                problem=problem,
                user=user,
                error_message="标题和内容不能为空",
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
            new_written_grading_mode,
            new_written_grading_model,
        )
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    return render_template(
        'edit_problem.html',
        problem=problem,
        user=user,
        error_message=None,
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
        flash('无权限进行此操作。', 'danger')
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    if 'testdata_zip' not in request.files:
        flash('没有文件部分。', 'danger')
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    file = request.files['testdata_zip']
    if file.filename == '':
        flash('未选择文件。', 'danger')
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    if not (file and allowed_file(file.filename)):
        flash('只允许上传 ZIP 文件。', 'danger')
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    filename = secure_filename(file.filename)
    temp_path = os.path.join('tmp', filename)
    extract_path = os.path.join('tmp', f'extracted_{problem_id}')

    try:
        os.makedirs('tmp', exist_ok=True)
        file.save(temp_path)
        import_testdata_zip(problem_id=problem_id, zip_path=temp_path, extract_dir=extract_path)
        flash('测试数据上传成功。', 'success')
    except zipfile.BadZipFile:
        flash('上传的文件不是有效的 ZIP 压缩包。', 'danger')
    except TestdataValidationError as e:
        flash(str(e), 'danger')
    except Exception as e:
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

            sql = "DELETE FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
        conn.commit()
        return jsonify(success=True, message="题目删除成功")
    except pymysql.Error as e:
        return jsonify(success=False, message="数据库错误: " + str(e)), 500
    finally:
        conn.close()
