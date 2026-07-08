#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import tempfile

import openpyxl
from flask import Blueprint, flash, jsonify, request, session

from oj_modules.db_services import (
    get_all_classes_except_admin,
    get_class_by_en,
    get_db_connection,
    get_user_classes,
    get_user_by_id,
    get_user_by_username,
    is_class_adjust_enabled,
)


class_management_bp = Blueprint('class_management', __name__)

ALLOWED_GRADES_EXTENSIONS = {'xlsx', 'xls'}


def _invalidate_problem_list_cache_for_user(user_id=None, username=None):
    try:
        from oj_modules.routes.problem_core_routes import invalidate_problem_list_cache_for_user
        invalidate_problem_list_cache_for_user(user_id=user_id, username=username)
    except Exception:
        # 缓存失效失败不影响主流程
        pass


from oj_modules.auth_helpers import current_user, is_admin


def allowed_grade_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_GRADES_EXTENSIONS


def create_final_exam_scores_table():
    return


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

        create_final_exam_scores_table()

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
    if class_en == 'Cadmin':
        return jsonify(success=False, message='管理员班级不能作为附加班级添加，请通过修改主班级显式授予管理员权限'), 400

    cls = get_class_by_en(class_en)
    if not cls:
        return jsonify(success=False, message='班级不存在'), 400

    user = get_user_by_id(user_id)
    if user and (user.get('class') == class_en):
        return jsonify(success=True, added=False, reason='already_primary', message='该用户的主班级已经是此班，无需添加')

    conn = get_db_connection()
    added = False
    try:
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO user_class_map (user_id, class_en, is_primary)
                VALUES (%s, %s, 0)
                ON DUPLICATE KEY UPDATE
                  is_primary = VALUES(is_primary)
            """
            cursor.execute(sql, (user_id, class_en))
            added = (cursor.rowcount == 1)
        if added:
            conn.commit()
            with conn.cursor() as cursor:
                cursor.execute("UPDATE class_table SET class_cnt = class_cnt + 1 WHERE class_en=%s", (class_en,))
            conn.commit()
        else:
            conn.rollback()
    finally:
        conn.close()

    if added:
        _invalidate_problem_list_cache_for_user(user_id=user_id, username=(user or {}).get('username'))

    return jsonify(success=True, added=added, message=('已添加' if added else '班级已存在或无需添加'))


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

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT is_primary FROM user_class_map WHERE user_id=%s AND class_en=%s",
                (user_id, class_en),
            )
            row = cursor.fetchone()
            if row and row['is_primary'] == 1:
                return jsonify(success=False, message='不能移除主班级，请使用修改主班级功能'), 400

        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM user_class_map WHERE user_id=%s AND class_en=%s",
                (user_id, class_en),
            )
        conn.commit()
        with conn.cursor() as cursor:
            cursor.execute("UPDATE class_table SET class_cnt = class_cnt - 1 WHERE class_en=%s AND class_cnt>0", (class_en,))
        conn.commit()
    finally:
        conn.close()

    _invalidate_problem_list_cache_for_user(user_id=user_id, username=(target_user or {}).get('username'))
    return jsonify(success=True)


@class_management_bp.route('/me/classes', methods=['GET'])
def get_my_classes():
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401

    user_classes = get_user_classes(user['id'])

    primary_en = None
    for cls in user_classes:
        if cls.get('is_primary'):
            primary_en = cls['class_en']
            break

    if not user_classes and user.get('class'):
        primary_en = user['class']
        user_classes = [{
            'class_en': user['class'],
            'class_cn': user.get('class_cn') or user['class'],
            'is_primary': 1,
        }]

    all_classes = get_all_classes_except_admin()

    return jsonify(success=True, memberships=user_classes, primary_en=primary_en, all_classes=all_classes)


@class_management_bp.route('/me/join_class', methods=['POST'])
def join_class():
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401
    if not is_class_adjust_enabled():
        return jsonify(success=False, message="当前不允许调整班级，请联系老师"), 403

    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400

    target_class = get_class_by_en(class_en)
    if not target_class:
        return jsonify(success=False, message="班级不存在"), 400

    if class_en == 'Cadmin':
        return jsonify(success=False, message="不能加入管理员班级"), 400

    user_classes = get_user_classes(user['id'])
    for cls in user_classes:
        if cls['class_en'] == class_en:
            return jsonify(success=False, message="您已经是该班级成员"), 400

    if user.get('class') == class_en:
        return jsonify(success=False, message="您已经是该班级成员"), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO user_class_map (user_id, class_en, is_primary)
                VALUES (%s, %s, 0)
            """
            cursor.execute(sql, (user['id'], class_en))
        conn.commit()

        with conn.cursor() as cursor:
            cursor.execute("UPDATE class_table SET class_cnt = class_cnt + 1 WHERE class_en=%s", (class_en,))
        conn.commit()

    except Exception as e:
        return jsonify(success=False, message=f"加入班级失败: {str(e)}"), 500
    finally:
        conn.close()

    _invalidate_problem_list_cache_for_user(user_id=user['id'], username=user['username'])
    return jsonify(success=True, message="成功加入班级", class_en=class_en, class_cn=target_class['class_cn'])


@class_management_bp.route('/me/leave_class', methods=['POST'])
def leave_class():
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401
    if not is_class_adjust_enabled():
        return jsonify(success=False, message="当前不允许调整班级，请联系老师"), 403

    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400

    user_classes = get_user_classes(user['id'])

    is_member = False
    is_primary = False
    for cls in user_classes:
        if cls['class_en'] == class_en:
            is_member = True
            is_primary = cls.get('is_primary', 0) == 1
            break

    if not is_member:
        return jsonify(success=False, message="您不是该班级成员"), 400

    if len(user_classes) <= 1:
        return jsonify(success=False, message="至少需要保留一个班级"), 400

    conn = get_db_connection()
    new_primary_en = None
    try:
        if is_primary:
            for cls in user_classes:
                if cls['class_en'] != class_en:
                    if cls['class_en'] == 'Cadmin' and not is_admin(user):
                        continue
                    new_primary_en = cls['class_en']
                    break

            if new_primary_en:
                new_primary_class = get_class_by_en(new_primary_en)
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE users SET class=%s, class_cn=%s WHERE id=%s",
                        (new_primary_en, new_primary_class['class_cn'], user['id']),
                    )

                with conn.cursor() as cursor:
                    cursor.execute("UPDATE user_class_map SET is_primary=0 WHERE user_id=%s", (user['id'],))
                    cursor.execute(
                        "UPDATE user_class_map SET is_primary=1 WHERE user_id=%s AND class_en=%s",
                        (user['id'], new_primary_en),
                    )
            else:
                return jsonify(success=False, message="至少需要保留一个普通班级"), 400

        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM user_class_map WHERE user_id=%s AND class_en=%s",
                (user['id'], class_en),
            )

        conn.commit()

        with conn.cursor() as cursor:
            cursor.execute("UPDATE class_table SET class_cnt = class_cnt - 1 WHERE class_en=%s AND class_cnt > 0", (class_en,))
        conn.commit()

    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"退出班级失败: {str(e)}"), 500
    finally:
        conn.close()

    _invalidate_problem_list_cache_for_user(user_id=user['id'], username=user['username'])
    return jsonify(success=True, message="成功退出班级", primary_en=new_primary_en)


@class_management_bp.route('/me/set_primary_class', methods=['POST'])
def set_primary_class():
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401
    if not is_class_adjust_enabled():
        return jsonify(success=False, message="当前不允许调整班级，请联系老师"), 403

    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400

    target_class = get_class_by_en(class_en)
    if not target_class:
        return jsonify(success=False, message="班级不存在"), 400

    if class_en == 'Cadmin' and not is_admin(user):
        return jsonify(success=False, message="不能自助切换到管理员班级"), 403

    user_classes = get_user_classes(user['id'])
    is_member = False
    for cls in user_classes:
        if cls['class_en'] == class_en:
            is_member = True
            break

    if not is_member and user.get('class') == class_en:
        is_member = True

    if not is_member:
        return jsonify(success=False, message="您不是该班级成员"), 400

    if user.get('class') == class_en:
        return jsonify(success=True, message="已经是主班级", primary_en=class_en, class_en=class_en)

    new_is_admin = 1 if is_admin(user) else (1 if class_en == 'Cadmin' else 0)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET class=%s, class_cn=%s, is_admin=%s WHERE id=%s",
                (class_en, target_class['class_cn'], new_is_admin, user['id']),
            )

            cursor.execute("UPDATE user_class_map SET is_primary=0 WHERE user_id=%s", (user['id'],))
            cursor.execute(
                """
                INSERT INTO user_class_map (user_id, class_en, is_primary)
                VALUES (%s, %s, 1)
                ON DUPLICATE KEY UPDATE is_primary=1
                """,
                (user['id'], class_en),
            )

        conn.commit()

    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"设置主班级失败: {str(e)}"), 500
    finally:
        conn.close()

    _invalidate_problem_list_cache_for_user(user_id=user['id'], username=user['username'])
    return jsonify(success=True, message="主班级设置成功", primary_en=class_en, class_en=class_en)
