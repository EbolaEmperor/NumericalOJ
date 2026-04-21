#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打榜赛（Ranking Competition）路由。
"""

import os
import shutil

import markdown
from flask import (
    Blueprint, abort, flash, redirect, render_template, request,
    send_file, session, url_for,
)
from werkzeug.utils import secure_filename

from oj_modules.db_services import get_user_by_username
from oj_modules.ranking_db import (
    competition_attachments_dir,
    competition_dir,
    competition_reference_dir,
    competition_scoring_dir,
    create_competition,
    create_competition_file,
    create_ranking_submission,
    delete_competition,
    delete_competition_file,
    get_competition,
    get_competition_file,
    get_leaderboard,
    get_ranking_submission,
    list_all_submissions,
    list_competition_files,
    list_competitions,
    list_user_submissions,
    submission_dir,
    update_competition,
    update_competition_reference_answer,
    update_competition_scoring_script,
    update_submission_files,
)


ranking_bp = Blueprint('ranking', __name__, url_prefix='/ranking')

ALLOWED_TABS = ('description', 'submit', 'leaderboard', 'all_submissions', 'edit')
ANSWER_MAX_BYTES = 64 * 1024 * 1024        # 64MB
CODE_ZIP_MAX_BYTES = 128 * 1024 * 1024     # 128MB
ATTACHMENT_MAX_BYTES = 256 * 1024 * 1024   # 256MB
SCORING_SCRIPT_MAX_BYTES = 4 * 1024 * 1024 # 4MB
REFERENCE_MAX_BYTES = 64 * 1024 * 1024     # 64MB

_evaluate_ranking_task = None


def init_ranking_module(evaluate_ranking_task):
    global _evaluate_ranking_task
    _evaluate_ranking_task = evaluate_ranking_task


def _current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def _require_user():
    user = _current_user()
    if not user:
        return None, redirect(url_for('auth.login'))
    return user, None


def _require_admin():
    user, resp = _require_user()
    if resp is not None:
        return None, resp
    if (user or {}).get('is_admin') != 1:
        flash('需要管理员权限', 'danger')
        return None, redirect(url_for('ranking.ranking_list'))
    return user, None


def _safe_filename(filename, fallback='file'):
    name = secure_filename(filename or '') or fallback
    # secure_filename 会把中文去掉，这里兜底一个默认名
    if not name.strip():
        name = fallback
    return name


def _ensure_dir(path):
    if path and not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)


def _render_description(text):
    if not text:
        return ''
    return markdown.markdown(
        text,
        extensions=['extra', 'md_in_html', 'fenced_code', 'tables'],
    )


# ---------- 列表页 ----------

@ranking_bp.route('/', methods=['GET'])
def ranking_list():
    user, resp = _require_user()
    if resp is not None:
        return resp
    is_admin = user.get('is_admin') == 1
    competitions = list_competitions(include_inactive=is_admin)
    return render_template(
        'ranking_list.html',
        user=user,
        competitions=competitions,
    )


@ranking_bp.route('/create', methods=['POST'])
def ranking_create():
    user, resp = _require_admin()
    if resp is not None:
        return resp
    title = (request.form.get('title') or '').strip()
    description = request.form.get('description') or ''
    max_score = request.form.get('max_score') or '100'
    if not title:
        flash('比赛标题不能为空', 'danger')
        return redirect(url_for('ranking.ranking_list'))
    try:
        max_score_int = int(max_score)
        if max_score_int <= 0:
            raise ValueError
    except ValueError:
        flash('满分必须是正整数', 'danger')
        return redirect(url_for('ranking.ranking_list'))
    new_id = create_competition(
        title=title,
        description=description,
        max_score=max_score_int,
        created_by=user.get('username'),
    )
    flash('已创建打榜赛', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=new_id, tab='edit'))


# ---------- 详情页（带侧边栏标签） ----------

@ranking_bp.route('/<int:competition_id>/', methods=['GET'])
def ranking_detail(competition_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在或已被删除', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    is_admin = user.get('is_admin') == 1
    if not is_admin and comp.get('is_active') != 1:
        flash('该比赛未开放', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    tab = (request.args.get('tab') or 'description').strip().lower()
    if tab not in ALLOWED_TABS:
        tab = 'description'
    if tab in ('all_submissions', 'edit') and not is_admin:
        tab = 'description'

    files = list_competition_files(competition_id)
    rendered_description = _render_description(comp.get('description') or '')

    user_submissions = []
    all_submissions = []
    leaderboard = []

    if tab == 'submit':
        user_submissions = list_user_submissions(competition_id, user.get('username'))
    elif tab == 'leaderboard':
        leaderboard = get_leaderboard(competition_id)
    elif tab == 'all_submissions':
        all_submissions = list_all_submissions(competition_id)

    return render_template(
        'ranking_detail.html',
        user=user,
        is_admin=is_admin,
        competition=comp,
        files=files,
        tab=tab,
        rendered_description=rendered_description,
        user_submissions=user_submissions,
        all_submissions=all_submissions,
        leaderboard=leaderboard,
    )


# ---------- 用户提交作品 ----------

@ranking_bp.route('/<int:competition_id>/submit', methods=['POST'])
def ranking_submit(competition_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在或已被删除', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    is_admin = user.get('is_admin') == 1
    if not is_admin and comp.get('is_active') != 1:
        flash('该比赛未开放', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    answer_file = request.files.get('answer_file')
    code_file = request.files.get('code_file')
    if not answer_file or not (answer_file.filename or '').strip():
        flash('请上传答案文件（.json）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
    if not code_file or not (code_file.filename or '').strip():
        flash('请上传代码文件（.zip）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    answer_name_raw = answer_file.filename
    code_name_raw = code_file.filename
    if not answer_name_raw.lower().endswith('.json'):
        flash('答案文件必须是 .json', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
    if not code_name_raw.lower().endswith('.zip'):
        flash('代码文件必须是 .zip', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    submission_id = create_ranking_submission(competition_id, user.get('username'))
    target_dir = submission_dir(submission_id)
    _ensure_dir(target_dir)

    answer_name = _safe_filename(answer_name_raw, fallback='answer.json')
    if not answer_name.lower().endswith('.json'):
        answer_name += '.json'
    code_name = _safe_filename(code_name_raw, fallback='code.zip')
    if not code_name.lower().endswith('.zip'):
        code_name += '.zip'

    answer_path = os.path.join(target_dir, answer_name)
    code_path = os.path.join(target_dir, code_name)
    try:
        answer_file.save(answer_path)
        code_file.save(code_path)
    except Exception as e:
        flash(f'文件保存失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    try:
        if os.path.getsize(answer_path) > ANSWER_MAX_BYTES:
            raise ValueError(f'答案文件超过 {ANSWER_MAX_BYTES // (1024*1024)}MB 限制')
        if os.path.getsize(code_path) > CODE_ZIP_MAX_BYTES:
            raise ValueError(f'代码文件超过 {CODE_ZIP_MAX_BYTES // (1024*1024)}MB 限制')
    except Exception as e:
        shutil.rmtree(target_dir, ignore_errors=True)
        flash(str(e), 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    update_submission_files(submission_id, answer_name, answer_path, code_name, code_path)

    if _evaluate_ranking_task is None:
        flash('已接收提交，但评测任务未初始化，请联系管理员', 'warning')
    else:
        try:
            _evaluate_ranking_task.delay(submission_id)
        except Exception as e:
            flash(f'已接收提交，但评测任务入队失败：{e}', 'warning')

    flash('提交成功，正在评测中', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))


# ---------- 管理员：编辑比赛 ----------

@ranking_bp.route('/<int:competition_id>/edit', methods=['POST'])
def ranking_edit(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    title = (request.form.get('title') or '').strip()
    description = request.form.get('description') or ''
    max_score_raw = request.form.get('max_score')
    is_active_raw = request.form.get('is_active')

    if not title:
        flash('标题不能为空', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    try:
        max_score_int = int(max_score_raw) if max_score_raw is not None else int(comp.get('max_score') or 100)
        if max_score_int <= 0:
            raise ValueError
    except ValueError:
        flash('满分必须是正整数', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    is_active = 1 if (is_active_raw and str(is_active_raw).lower() in ('1', 'on', 'true', 'yes')) else 0

    update_competition(
        competition_id,
        title=title,
        description=description,
        max_score=max_score_int,
        is_active=is_active,
    )
    flash('已保存比赛信息', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/delete', methods=['POST'])
def ranking_delete(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    delete_competition(competition_id)
    # 清理磁盘文件
    comp_dir = competition_dir(competition_id)
    shutil.rmtree(comp_dir, ignore_errors=True)
    flash('已删除比赛', 'success')
    return redirect(url_for('ranking.ranking_list'))


@ranking_bp.route('/<int:competition_id>/upload_attachment', methods=['POST'])
def ranking_upload_attachment(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    f = request.files.get('attachment')
    if not f or not (f.filename or '').strip():
        flash('请选择要上传的附件', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    original_name = f.filename
    safe_name = _safe_filename(original_name, fallback='attachment.bin')
    target_dir = competition_attachments_dir(competition_id)
    _ensure_dir(target_dir)
    # 避免同名覆盖：前缀递增
    base, ext = os.path.splitext(safe_name)
    final_name = safe_name
    i = 1
    while os.path.exists(os.path.join(target_dir, final_name)):
        final_name = f'{base}_{i}{ext}'
        i += 1
    target_path = os.path.join(target_dir, final_name)
    try:
        f.save(target_path)
    except Exception as e:
        flash(f'上传失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    size = 0
    try:
        size = os.path.getsize(target_path)
    except Exception:
        pass
    if size > ATTACHMENT_MAX_BYTES:
        try:
            os.remove(target_path)
        except Exception:
            pass
        flash(f'附件超过 {ATTACHMENT_MAX_BYTES // (1024*1024)}MB 限制', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    create_competition_file(competition_id, original_name, target_path, size)
    flash('已上传附件', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/attachment/<int:file_id>/delete', methods=['POST'])
def ranking_delete_attachment(competition_id, file_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    rec = get_competition_file(file_id)
    if not rec or rec.get('competition_id') != competition_id:
        flash('附件不存在', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    stored = rec.get('stored_path') or ''
    if stored and os.path.isfile(stored):
        try:
            os.remove(stored)
        except Exception:
            pass
    delete_competition_file(file_id)
    flash('已删除附件', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/attachment/<int:file_id>/download', methods=['GET'])
def ranking_download_attachment(competition_id, file_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    rec = get_competition_file(file_id)
    if not rec or rec.get('competition_id') != competition_id:
        abort(404)
    stored = rec.get('stored_path') or ''
    if not stored or not os.path.isfile(stored):
        abort(404)
    return send_file(
        os.path.abspath(stored),
        as_attachment=True,
        download_name=rec.get('filename') or os.path.basename(stored),
    )


@ranking_bp.route('/<int:competition_id>/upload_reference', methods=['POST'])
def ranking_upload_reference(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    f = request.files.get('reference')
    if not f or not (f.filename or '').strip():
        flash('请选择标准答案文件（.json）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    if not f.filename.lower().endswith('.json'):
        flash('标准答案必须是 .json 文件', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    target_dir = competition_reference_dir(competition_id)
    _ensure_dir(target_dir)
    # 清理旧的
    old_path = comp.get('reference_answer_path') or ''
    safe_name = _safe_filename(f.filename, fallback='reference.json')
    if not safe_name.lower().endswith('.json'):
        safe_name += '.json'
    target_path = os.path.join(target_dir, safe_name)
    try:
        f.save(target_path)
    except Exception as e:
        flash(f'上传失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    if os.path.getsize(target_path) > REFERENCE_MAX_BYTES:
        os.remove(target_path)
        flash(f'标准答案超过 {REFERENCE_MAX_BYTES // (1024*1024)}MB 限制', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    if old_path and old_path != target_path and os.path.isfile(old_path):
        try:
            os.remove(old_path)
        except Exception:
            pass
    update_competition_reference_answer(competition_id, target_path, f.filename)
    flash('已更新标准答案', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/upload_scoring_script', methods=['POST'])
def ranking_upload_scoring_script(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    f = request.files.get('scoring_script')
    if not f or not (f.filename or '').strip():
        flash('请选择评测脚本（.py）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    if not f.filename.lower().endswith('.py'):
        flash('评测脚本必须是 .py 文件', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    target_dir = competition_scoring_dir(competition_id)
    _ensure_dir(target_dir)
    old_path = comp.get('scoring_script_path') or ''
    safe_name = _safe_filename(f.filename, fallback='scoring.py')
    if not safe_name.lower().endswith('.py'):
        safe_name += '.py'
    target_path = os.path.join(target_dir, safe_name)
    try:
        f.save(target_path)
    except Exception as e:
        flash(f'上传失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    if os.path.getsize(target_path) > SCORING_SCRIPT_MAX_BYTES:
        os.remove(target_path)
        flash(f'评测脚本超过 {SCORING_SCRIPT_MAX_BYTES // (1024*1024)}MB 限制', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    if old_path and old_path != target_path and os.path.isfile(old_path):
        try:
            os.remove(old_path)
        except Exception:
            pass
    update_competition_scoring_script(competition_id, target_path, f.filename)
    flash('已更新评测脚本', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/clear_scoring_script', methods=['POST'])
def ranking_clear_scoring_script(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    old = comp.get('scoring_script_path') or ''
    if old and os.path.isfile(old):
        try:
            os.remove(old)
        except Exception:
            pass
    update_competition_scoring_script(competition_id, None, None)
    flash('已清除评测脚本（将使用默认 JSON 对比打分）', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


# ---------- 提交文件下载 ----------

def _can_access_submission(user, submission):
    if not submission:
        return False
    if user.get('is_admin') == 1:
        return True
    return submission.get('username') == user.get('username')


@ranking_bp.route('/submission/<int:submission_id>/answer', methods=['GET'])
def download_submission_answer(submission_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    sub = get_ranking_submission(submission_id)
    if not sub or not _can_access_submission(user, sub):
        abort(404)
    path = sub.get('answer_path') or ''
    if not path or not os.path.isfile(path):
        abort(404)
    return send_file(
        os.path.abspath(path),
        as_attachment=True,
        download_name=sub.get('answer_filename') or os.path.basename(path),
    )


@ranking_bp.route('/submission/<int:submission_id>/code', methods=['GET'])
def download_submission_code(submission_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    sub = get_ranking_submission(submission_id)
    if not sub or not _can_access_submission(user, sub):
        abort(404)
    path = sub.get('code_path') or ''
    if not path or not os.path.isfile(path):
        abort(404)
    return send_file(
        os.path.abspath(path),
        as_attachment=True,
        download_name=sub.get('code_filename') or os.path.basename(path),
    )
