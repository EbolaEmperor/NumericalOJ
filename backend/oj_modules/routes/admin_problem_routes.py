#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import io
import os
import pymysql
import tempfile
import zipfile
from flask import Blueprint, flash, jsonify, redirect, request, send_file, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from backend.oj_modules.db_services import (
    create_problem,
    get_db_connection,
    get_problem,
    get_user_by_username,
    normalize_output_image_filename,
    safe_table_name,
    update_problem,
)
from backend.oj_modules.problems.llm_bindings import (
    ProblemLlmBindingsError,
    problem_llm_bindings_from_form,
)
from backend.oj_modules.problems.testdata import TestdataValidationError, import_testdata_zip
from backend.oj_modules.problems.lean_package import LeanPackageError, load_lean_package_zip
from backend.oj_modules.problems.lean_workspace import (
    LeanWorkspaceError,
    create_problem_revision,
    get_current_lean_workspace,
)


admin_problem_bp = Blueprint('admin_problem', __name__)
ALLOWED_EXTENSIONS = {'zip'}


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


from backend.oj_modules.security.auth import current_user, is_admin


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


def parse_output_image_filename_from_form(form, default="output.png"):
    raw = str(form.get('output_image_filename') or default).strip()
    return normalize_output_image_filename(raw, default=default)


def _output_image_filename_error_response(error):
    """返回输出图片文件名的统一校验错误，避免无效配置入库。"""
    return jsonify(success=False, message=str(error)), 400


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


@admin_problem_bp.post('/api/admin/problems')
@admin_problem_bp.route('/admin/add_problem', methods=['GET', 'POST'])
def add_problem():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    if request.method == 'POST':
        title = request.form.get('title').strip()
        content = request.form.get('content').strip()
        initial_code = request.form.get('initial_code', '').strip()
        test_code = request.form.get('test_code', '').strip()
        forbidden_func = request.form.get('forbidden_func', '').strip()
        problem_type = request.form.get('type')
        programming_grading_mode = parse_programming_grading_mode_from_form(request.form, default=1)
        try:
            output_image_filename = parse_output_image_filename_from_form(
                request.form,
                default="output.png",
            )
        except ValueError as exc:
            return _output_image_filename_error_response(
                exc,
            )
        programming_grading_prompt = parse_programming_grading_prompt_from_form(request.form)
        written_grading_mode = parse_written_grading_mode_from_form(request.form, default=1)
        written_grading_prompt = parse_written_grading_prompt_from_form(request.form)
        lang = (request.form.get('lang') or 'matlab').strip().lower()
        time_limit_ms = parse_time_limit_ms_from_form(request.form)
        submission_limit = int(request.form.get('submission_limit', 10))
        if lang == 'lean4':
            initial_code = ''
            test_code = ''
            programming_grading_mode = 1
        try:
            llm_endpoint_bindings = problem_llm_bindings_from_form(
                request.form,
                problem_type=problem_type,
                programming_grading_mode=programming_grading_mode,
            )
        except ProblemLlmBindingsError as exc:
            return jsonify(success=False, message=str(exc)), 400

        if not title or not content:
            return jsonify(success=False, message="标题和内容不能为空"), 400

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
            output_image_filename=output_image_filename,
            programming_grading_prompt=programming_grading_prompt,
            written_grading_mode=written_grading_mode,
            written_grading_prompt=written_grading_prompt,
            llm_endpoint_bindings=llm_endpoint_bindings,
        )
        if _wants_json_response():
            return jsonify(success=True, problem_id=problem_id, message="题目创建成功")
        return redirect(url_for('problem_core.problem_list'))

    return redirect('/admin/problems/new')


@admin_problem_bp.post('/api/admin/problems/<int:problem_id>')
@admin_problem_bp.route('/admin/edit_problem/<int:problem_id>', methods=['GET', 'POST'])
def edit_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message="题目不存在"), 404

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
        default_output_filename = problem.get('output_image_filename', 'output.png')
        try:
            new_output_image_filename = parse_output_image_filename_from_form(
                request.form,
                default=default_output_filename,
            )
        except ValueError as exc:
            return _output_image_filename_error_response(
                exc,
            )
        new_programming_grading_prompt = parse_programming_grading_prompt_from_form(request.form)
        default_mode = problem.get('written_grading_mode', 1)
        new_written_grading_mode = parse_written_grading_mode_from_form(request.form, default=default_mode)
        new_written_grading_prompt = parse_written_grading_prompt_from_form(request.form)
        if new_lang == 'lean4':
            new_programming_grading_mode = 1
        try:
            new_llm_endpoint_bindings = problem_llm_bindings_from_form(
                request.form,
                problem_type=problem.get('type'),
                programming_grading_mode=new_programming_grading_mode,
                existing=problem.get('llm_endpoint_bindings'),
            )
        except ProblemLlmBindingsError as exc:
            return jsonify(success=False, message=str(exc)), 400

        if not new_title or not new_content:
            return jsonify(success=False, message="标题和内容不能为空"), 400

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
            new_output_image_filename=new_output_image_filename,
            new_programming_grading_prompt=new_programming_grading_prompt,
            new_written_grading_mode=new_written_grading_mode,
            new_written_grading_prompt=new_written_grading_prompt,
            new_llm_endpoint_bindings=new_llm_endpoint_bindings,
        )
        if _wants_json_response():
            return jsonify(
                success=True,
                problem_id=problem_id,
                message="题目修改成功",
                next=f"/problems/{problem_id}",
            )
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    return redirect(f'/admin/problems/{problem_id}/edit')


@admin_problem_bp.app_errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    flash('上传的文件太大。最大允许 256MB。', 'danger')
    return redirect(request.url)


@admin_problem_bp.route('/api/admin/problems/<int:problem_id>/testdata', methods=['POST'])
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

    try:
        os.makedirs('tmp', exist_ok=True)
        # 每个请求使用独占临时根。即使同一道题被并发上传同名 ZIP，归档文件与
        # 解压目录也不会互相覆盖；上下文退出时统一清理成功或失败留下的产物。
        with tempfile.TemporaryDirectory(
            prefix=f'numoj-testdata-{problem_id}-',
            dir='tmp',
        ) as request_root:
            temp_path = os.path.join(request_root, 'upload.zip')
            extract_path = os.path.join(request_root, 'extracted')
            file.save(temp_path)
            import_testdata_zip(
                problem_id=problem_id,
                zip_path=temp_path,
                extract_dir=extract_path,
            )
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

    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))


@admin_problem_bp.post('/api/admin/problems/<int:problem_id>/lean-workspace')
@admin_problem_bp.route('/admin/upload_lean_workspace/<int:problem_id>', methods=['POST'])
def upload_lean_workspace(problem_id):
    """上传 Lean 4 多文件题目包，并发布为新的不可变版本。"""

    user = current_user()
    if not is_admin(user):
        return _json_or_problem_redirect('无权限进行此操作。', 403, problem_id=problem_id)
    problem = get_problem(problem_id)
    if not problem:
        return _json_or_problem_redirect('题目不存在。', 404, problem_id=problem_id)
    if (
        int(problem.get('type') or 0) != 1
        or str(problem.get('lang') or '').strip().lower() not in {'lean', 'lean4'}
    ):
        return _json_or_problem_redirect('只有 Lean 4 编程题可以上传此文件。', 400, problem_id=problem_id)
    upload = request.files.get('lean_package_zip') or request.files.get('file')
    if not upload or not upload.filename:
        return _json_or_problem_redirect('请选择 Lean 4 题目包 ZIP。', 400, problem_id=problem_id)
    if not allowed_file(upload.filename):
        return _json_or_problem_redirect('Lean 4 题目包必须是 ZIP 文件。', 400, problem_id=problem_id)

    try:
        os.makedirs('tmp', exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=f'numoj-lean-package-{problem_id}-',
            dir='tmp',
        ) as request_root:
            zip_path = os.path.join(request_root, 'package.zip')
            extract_path = os.path.join(request_root, 'workspace')
            upload.save(zip_path)
            package = load_lean_package_zip(zip_path, extract_path)
            workspace = create_problem_revision(
                problem_id=problem_id,
                package=package,
                created_by_user_id=user.get('id'),
            )
    except (LeanPackageError, LeanWorkspaceError) as exc:
        return _json_or_problem_redirect(str(exc), 400, problem_id=problem_id)
    except zipfile.BadZipFile:
        return _json_or_problem_redirect('上传的文件不是有效 ZIP。', 400, problem_id=problem_id)
    except Exception as exc:
        if _wants_json_response():
            return jsonify(success=False, message=f'发布 Lean 4 题目包失败：{exc}'), 500
        flash(f'发布 Lean 4 题目包失败：{exc}', 'danger')
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    message = (
        f"Lean 4 工作区 v{workspace['revision_number']} 发布成功。"
        if workspace.get('created')
        else f"Lean 4 工作区 v{workspace['revision_number']} 未变化。"
    )
    if _wants_json_response():
        return jsonify(success=True, message=message, lean_workspace=workspace)
    flash(message, 'success')
    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))


@admin_problem_bp.get('/api/admin/problems/<int:problem_id>/lean-workspace')
def admin_lean_workspace(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403
    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message='题目不存在'), 404
    workspace = get_current_lean_workspace(problem_id)
    if not workspace:
        return jsonify(success=False, message='该题尚未上传 Lean 4 工作区'), 404
    return jsonify(success=True, problem_id=problem_id, lean_workspace=workspace)


@admin_problem_bp.get('/api/admin/problems/<int:problem_id>/lean-workspace/download')
@admin_problem_bp.get('/admin/download_lean_workspace/<int:problem_id>')
def download_lean_workspace(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403
    workspace = get_current_lean_workspace(problem_id)
    if not workspace:
        return jsonify(success=False, message='该题尚未上传 Lean 4 工作区'), 404
    manifest = {
        'schema_version': workspace['schema_version'],
        'default_file': workspace['default_file'],
        'files': [
            {'path': item['path'], 'mode': item['mode']}
            for item in workspace['files']
        ],
        'build_order': [
            item['path']
            for item in sorted(workspace['files'], key=lambda row: row['build_order'])
        ],
        'verification': workspace['verification'],
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            'numoj-lean.json',
            json.dumps(manifest, ensure_ascii=False, indent=2) + '\n',
        )
        for item in workspace['files']:
            archive.writestr(item['path'], item.get('content') or '')
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'lean-problem-{problem_id}-v{workspace["revision_number"]}.zip',
        max_age=0,
    )


@admin_problem_bp.delete('/api/admin/problems/<int:problem_id>')
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
