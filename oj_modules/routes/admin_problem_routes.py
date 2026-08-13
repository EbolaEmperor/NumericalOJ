#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import pymysql
import tempfile
import zipfile
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from oj_modules.db_services import (
    create_problem,
    get_db_connection,
    get_problem,
    get_user_by_username,
    normalize_programming_output_filename,
    safe_table_name,
    update_problem,
)
from oj_modules.problems.grading import (
    DEFAULT_WRITTEN_GRADING_PROMPT as _DEFAULT_WRITTEN_GRADING_PROMPT,
)
from oj_modules.problems.llm_bindings import (
    ProblemLlmBindingsError,
    get_problem_llm_endpoint_candidates as _problem_llm_endpoint_candidates,
    problem_llm_bindings_from_form,
)
from oj_modules.problems.testdata import TestdataValidationError, import_testdata_zip


admin_problem_bp = Blueprint('admin_problem', __name__)
ALLOWED_EXTENSIONS = {'zip'}
LEAN4_DEFAULT_CONFIG = {
    "target": "∀ n : Nat, n + 0 = n",
    "entry": "Submission.answer",
    "imports": ["Mathlib.Data.Nat.Basic"],
}


def _problem_llm_form_context(bindings=None):
    return {
        "llm_endpoint_bindings": dict(bindings or {}),
        "llm_endpoint_candidates": _problem_llm_endpoint_candidates(),
    }


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


from oj_modules.security.auth import current_user, is_admin


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


def parse_programming_output_filename_from_form(form, default="output.png"):
    raw = str(form.get('programming_output_filename') or default).strip()
    return normalize_programming_output_filename(raw, default=default)


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


def normalize_lean4_problem_config(raw):
    """规范管理员保存在 ``test_code`` 中的 Lean 题目契约。"""
    text = str(raw or '').strip()
    payload = json.loads(text) if text else dict(LEAN4_DEFAULT_CONFIG)
    if not isinstance(payload, dict):
        raise ValueError("Lean 4 验证配置必须是 JSON 对象")

    target = str(payload.get("target") or '').strip()
    entry = str(payload.get("entry") or '').strip()
    imports = payload.get("imports") or ["Mathlib.Data.Nat.Basic"]
    if not target:
        raise ValueError("Lean 4 验证配置缺少 target")
    if not entry:
        raise ValueError("Lean 4 验证配置缺少 entry")
    if not isinstance(imports, list) or not all(
        isinstance(item, str) and item.strip() for item in imports
    ):
        raise ValueError("Lean 4 验证配置的 imports 必须是模块名数组")

    return json.dumps(
        {
            "target": target,
            "entry": entry,
            "imports": [item.strip() for item in imports],
        },
        ensure_ascii=False,
        indent=2,
    )


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
        programming_output_filename = parse_programming_output_filename_from_form(request.form, default="output.png")
        programming_grading_prompt = parse_programming_grading_prompt_from_form(request.form)
        written_grading_mode = parse_written_grading_mode_from_form(request.form, default=1)
        written_grading_prompt = parse_written_grading_prompt_from_form(request.form)
        lang = (request.form.get('lang') or 'matlab').strip().lower()
        time_limit_ms = parse_time_limit_ms_from_form(request.form)
        submission_limit = int(request.form.get('submission_limit', 10))
        if lang == 'lean4':
            try:
                test_code = normalize_lean4_problem_config(test_code)
            except (ValueError, json.JSONDecodeError) as exc:
                if _wants_json_response():
                    return jsonify(success=False, message=str(exc)), 400
                return render_template(
                    'problems/create.html',
                    user=user,
                    error_message=str(exc),
                    default_written_grading_prompt=_DEFAULT_WRITTEN_GRADING_PROMPT,
                    **_problem_llm_form_context(),
                ), 400
            programming_grading_mode = 1
        try:
            llm_endpoint_bindings = problem_llm_bindings_from_form(
                request.form,
                problem_type=problem_type,
                programming_grading_mode=programming_grading_mode,
            )
        except ProblemLlmBindingsError as exc:
            if _wants_json_response():
                return jsonify(success=False, message=str(exc)), 400
            return render_template(
                'problems/create.html',
                user=user,
                error_message=str(exc),
                default_written_grading_prompt=_DEFAULT_WRITTEN_GRADING_PROMPT,
                **_problem_llm_form_context(),
            ), 400

        if not title or not content:
            if _wants_json_response():
                return jsonify(success=False, message="标题和内容不能为空"), 400
            return render_template(
                'problems/create.html',
                user=user,
                error_message="标题和内容不能为空",
                default_written_grading_prompt=_DEFAULT_WRITTEN_GRADING_PROMPT,
                **_problem_llm_form_context(llm_endpoint_bindings),
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
            programming_output_filename=programming_output_filename,
            programming_grading_prompt=programming_grading_prompt,
            written_grading_mode=written_grading_mode,
            written_grading_prompt=written_grading_prompt,
            llm_endpoint_bindings=llm_endpoint_bindings,
        )
        if _wants_json_response():
            return jsonify(success=True, problem_id=problem_id, message="题目创建成功")
        return redirect(url_for('problem_core.problem_list'))

    return render_template(
        'problems/create.html',
        user=user,
        error_message=None,
        default_written_grading_prompt=_DEFAULT_WRITTEN_GRADING_PROMPT,
        **_problem_llm_form_context(),
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
        default_output_filename = problem.get('programming_output_filename', 'output.png')
        new_programming_output_filename = parse_programming_output_filename_from_form(request.form, default=default_output_filename)
        new_programming_grading_prompt = parse_programming_grading_prompt_from_form(request.form)
        default_mode = problem.get('written_grading_mode', 1)
        new_written_grading_mode = parse_written_grading_mode_from_form(request.form, default=default_mode)
        new_written_grading_prompt = parse_written_grading_prompt_from_form(request.form)
        if new_lang == 'lean4':
            try:
                new_test_code = normalize_lean4_problem_config(new_test_code)
            except (ValueError, json.JSONDecodeError) as exc:
                if _wants_json_response():
                    return jsonify(success=False, message=str(exc)), 400
                problem_for_form = dict(problem)
                problem_for_form.update({
                    'title': new_title,
                    'content': new_content,
                    'initial_code': new_initial_code,
                    'test_code': new_test_code,
                    'lang': new_lang,
                })
                return render_template(
                    'problems/edit.html',
                    problem=problem_for_form,
                    user=user,
                    error_message=str(exc),
                    **_problem_llm_form_context(problem.get('llm_endpoint_bindings')),
                ), 400
            new_programming_grading_mode = 1
        try:
            new_llm_endpoint_bindings = problem_llm_bindings_from_form(
                request.form,
                problem_type=problem.get('type'),
                programming_grading_mode=new_programming_grading_mode,
                existing=problem.get('llm_endpoint_bindings'),
            )
        except ProblemLlmBindingsError as exc:
            if _wants_json_response():
                return jsonify(success=False, message=str(exc)), 400
            return render_template(
                'problems/edit.html',
                problem=problem,
                user=user,
                error_message=str(exc),
                **_problem_llm_form_context(problem.get('llm_endpoint_bindings')),
            ), 400

        if not new_title or not new_content:
            return render_template(
                'problems/edit.html',
                problem=problem,
                user=user,
                error_message="标题和内容不能为空",
                **_problem_llm_form_context(new_llm_endpoint_bindings),
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
            new_programming_output_filename=new_programming_output_filename,
            new_programming_grading_prompt=new_programming_grading_prompt,
            new_written_grading_mode=new_written_grading_mode,
            new_written_grading_prompt=new_written_grading_prompt,
            new_llm_endpoint_bindings=new_llm_endpoint_bindings,
        )
        return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    return render_template(
        'problems/edit.html',
        problem=problem,
        user=user,
        error_message=None,
        **_problem_llm_form_context(problem.get('llm_endpoint_bindings')),
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
