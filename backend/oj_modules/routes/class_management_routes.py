#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import tempfile

import openpyxl
from flask import Blueprint, current_app, flash, jsonify, request

from backend.oj_modules.classroom.membership import (
    LastMembershipError,
    MembershipNotFoundError,
    add_class_membership,
    leave_class_membership,
    remove_class_membership,
)
from backend.oj_modules.classroom.logos import attach_class_logos
from backend.oj_modules.db_services import (
    get_all_classes,
    get_class_by_en,
    get_db_connection,
    get_user_classes,
    get_user_by_id,
    is_class_adjust_enabled,
)
from backend.oj_modules.problems.catalog import invalidate_problem_list_cache_for_user


class_management_bp = Blueprint('class_management', __name__)

ALLOWED_GRADES_EXTENSIONS = {'xlsx', 'xls'}


def _invalidate_problem_list_cache_for_user(user_id=None, username=None):
    try:
        invalidate_problem_list_cache_for_user(user_id=user_id, username=username)
    except Exception:
        # 缓存失效失败不影响主流程
        pass


from backend.oj_modules.security.auth import current_user, is_admin


def allowed_grade_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_GRADES_EXTENSIONS


@class_management_bp.route('/admin/upload_exam_scores', methods=['POST'])
def upload_exam_scores():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400

    if not get_class_by_en(class_en):
        return jsonify(success=False, message="班级不存在"), 400

    if 'file' not in request.files:
        return jsonify(success=False, message="未选择文件"), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, message="未选择文件"), 400

    if not allowed_grade_file(file.filename):
        return jsonify(success=False, message="仅支持 .xlsx/.xls 文件"), 400

    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, file.filename)
    file.save(temp_path)

    try:
        wb = openpyxl.load_workbook(temp_path, data_only=True)
        sheet = wb.active
        rows = list(sheet.iter_rows(values_only=True))

        if not rows:
            return jsonify(success=False, message="Excel 文件为空"), 400

        start_idx = 0
        if isinstance(rows[0][0], str) and not rows[0][0].isdigit():
            start_idx = 1

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                insert_sql = """
                    INSERT INTO final_exam_scores (class_en, student_id, regular_score, final_score)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE regular_score = VALUES(regular_score), final_score = VALUES(final_score)
                """

                for row in rows[start_idx:]:
                    if row is None:
                        continue
                    if len(row) < 3:
                        continue
                    student_id = str(row[0]).strip()
                    try:
                        regular_score = float(row[1]) if row[1] is not None else None
                        final_score = float(row[2]) if row[2] is not None else None
                    except ValueError:
                        regular_score = None
                        final_score = None
                    if not student_id or regular_score is None or final_score is None:
                        continue

                    cursor.execute(insert_sql, (class_en, student_id, regular_score, final_score))
            conn.commit()
        finally:
            conn.close()

    except Exception as e:
        return jsonify(success=False, message=f"解析 Excel 失败: {str(e)}"), 500
    finally:
        shutil.rmtree(temp_dir)

    flash('期末成绩上传成功', 'success')
    return jsonify(success=True, message="成绩上传成功")


@class_management_bp.route('/admin/add_user_to_class', methods=['POST'])
def add_user_to_class():
    admin = current_user()
    if not is_admin(admin):
        return jsonify(success=False, message='无权限'), 403

    user_id = request.form.get('user_id', type=int)
    class_en = (request.form.get('class_en') or '').strip()
    if not (user_id and class_en):
        return jsonify(success=False, message='参数错误'), 400

    cls = get_class_by_en(class_en)
    if not cls:
        return jsonify(success=False, message='班级不存在'), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify(success=False, message='用户不存在'), 404

    try:
        added = add_class_membership(user_id, class_en)
    except MembershipNotFoundError as exc:
        return jsonify(success=False, message=str(exc)), 404
    except Exception:
        current_app.logger.exception(
            '管理员添加班级成员关系失败',
            extra={'user_id': user_id, 'class_en': class_en},
        )
        return jsonify(success=False, message='添加班级失败，请稍后再试'), 500

    if added:
        _invalidate_problem_list_cache_for_user(user_id=user_id, username=user.get('username'))

    return jsonify(
        success=True,
        added=added,
        reason=None if added else 'already_member',
        message='已添加' if added else '该用户已经是此班级成员',
    )


@class_management_bp.route('/admin/remove_user_from_class', methods=['POST'])
def remove_user_from_class():
    admin = current_user()
    if not is_admin(admin):
        return jsonify(success=False, message='无权限'), 403

    user_id = request.form.get('user_id', type=int)
    class_en = request.form.get('class_en', '').strip()
    if not (user_id and class_en):
        return jsonify(success=False, message='参数错误'), 400

    target_user = get_user_by_id(user_id)
    if not target_user:
        return jsonify(success=False, message='用户不存在'), 404

    try:
        removed = remove_class_membership(user_id, class_en)
    except LastMembershipError:
        return jsonify(success=False, message='至少需要保留一个班级'), 400
    except MembershipNotFoundError as exc:
        return jsonify(success=False, message=str(exc)), 404
    except Exception:
        current_app.logger.exception(
            '管理员移除班级成员关系失败',
            extra={'user_id': user_id, 'class_en': class_en},
        )
        return jsonify(success=False, message='移除班级失败，请稍后再试'), 500

    if removed:
        _invalidate_problem_list_cache_for_user(
            user_id=user_id,
            username=target_user.get('username'),
        )
    return jsonify(
        success=True,
        removed=removed,
        message='已移除' if removed else '该用户不属于此班级',
    )


@class_management_bp.route('/me/classes', methods=['GET'])
def get_my_classes():
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401

    user_classes = get_user_classes(user['id'])
    all_classes = get_all_classes()

    return jsonify(
        success=True,
        memberships=attach_class_logos(user_classes),
        all_classes=attach_class_logos(all_classes),
    )


@class_management_bp.route('/me/join_class', methods=['POST'])
def join_class():
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401
    # 站点开关只控制学生自助调整；管理员始终可以维护自己的等价班级关系，
    # 与弹窗中的权限提示保持一致。
    if not is_admin(user) and not is_class_adjust_enabled():
        return jsonify(success=False, message="当前不允许调整班级，请联系老师"), 403

    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400

    target_class = get_class_by_en(class_en)
    if not target_class:
        return jsonify(success=False, message="班级不存在"), 400

    try:
        added = add_class_membership(user['id'], class_en)
        if not added:
            return jsonify(success=False, message="您已经是该班级成员"), 400
    except MembershipNotFoundError as exc:
        return jsonify(success=False, message=str(exc)), 404
    except Exception:
        current_app.logger.exception(
            '用户加入班级失败',
            extra={'user_id': user['id'], 'class_en': class_en},
        )
        return jsonify(success=False, message="加入班级失败，请稍后再试"), 500

    _invalidate_problem_list_cache_for_user(user_id=user['id'], username=user['username'])
    return jsonify(success=True, message="成功加入班级", class_en=class_en, class_cn=target_class['class_cn'])


@class_management_bp.route('/me/leave_class', methods=['POST'])
def leave_class():
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401
    if not is_admin(user) and not is_class_adjust_enabled():
        return jsonify(success=False, message="当前不允许调整班级，请联系老师"), 403

    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400

    try:
        leave_class_membership(user['id'], class_en)
    except LastMembershipError:
        return jsonify(success=False, message="至少需要保留一个班级"), 400
    except MembershipNotFoundError:
        return jsonify(success=False, message="您不是该班级成员"), 400
    except Exception:
        current_app.logger.exception(
            '用户退出班级失败',
            extra={'user_id': user['id'], 'class_en': class_en},
        )
        return jsonify(success=False, message="退出班级失败，请稍后再试"), 500

    _invalidate_problem_list_cache_for_user(user_id=user['id'], username=user['username'])
    return jsonify(success=True, message="成功退出班级")
