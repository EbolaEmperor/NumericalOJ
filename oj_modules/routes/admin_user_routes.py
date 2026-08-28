#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import secrets

from flask import Blueprint, current_app, flash, jsonify, render_template, request, session

from oj_modules.classroom.logos import generate_class_logo_seed
from oj_modules.db_services import (
    delete_user_problem_max_score,
    get_all_classes,
    get_class_by_cn,
    get_class_by_en,
    get_db_connection,
    get_problem_title,
    get_user_by_id,
    rename_user,
    safe_table_name,
    upsert_user_problem_max_score,
)
from oj_modules.problems.catalog import invalidate_problem_list_cache_for_user
from oj_modules.integrations.mail import MailDeliveryError, send_plain_text_email
from oj_modules.observability import emit_audit, request_audit_fields
from oj_modules.security.credentials import hash_password, validate_email, validate_username
from oj_modules.site_config.services import get_mail_settings


admin_user_bp = Blueprint('admin_user', __name__)

_RESET_PASSWORD_ALPHABET = (
    'ABCDEFGHJKLMNPQRSTUVWXYZ'
    'abcdefghijkmnopqrstuvwxyz'
    '23456789'
)


def _invalidate_problem_list_cache_for_user(user_id=None, username=None):
    try:
        invalidate_problem_list_cache_for_user(user_id=user_id, username=username)
    except Exception:
        # 缓存失效失败不影响主流程
        current_app.logger.exception('用户题目列表缓存失效失败')


def _random_password(length=16):
    """生成不含易混淆字符、同时包含大小写字母和数字的随机密码。"""
    while True:
        password = ''.join(secrets.choice(_RESET_PASSWORD_ALPHABET) for _ in range(length))
        if (
            any(char.islower() for char in password)
            and any(char.isupper() for char in password)
            and any(char.isdigit() for char in password)
        ):
            return password


def _audit_user_admin_action(action, outcome, admin, target_user, **details):
    try:
        fields = request_audit_fields(request)
        fields['actor'] = {
            'id': admin.get('id'),
            'name': admin.get('username'),
            'is_admin': True,
        }
        fields['target_user'] = {
            'id': target_user.get('id') if target_user else None,
            'name': target_user.get('username') if target_user else None,
        }
        fields['change'] = details
        emit_audit(
            'user_admin',
            action=action,
            outcome=outcome,
            message=f'用户管理事件：{action}',
            **fields,
        )
    except Exception:
        # 审计写入故障不能反转已经完成的用户管理操作。
        current_app.logger.exception('用户管理审计事件写入失败')


from oj_modules.security.auth import current_user, is_admin


@admin_user_bp.route('/admin/users')
def user_management():
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    page = max(1, request.args.get('page', 1, type=int))
    # 保留 `username` 作为旧书签的兼容参数；页面使用中性的 `user_search`，
    # 避免密码管理器把筛选框误判成登录账号字段。
    search_username = (
        request.args.get('user_search')
        or request.args.get('username')
        or ''
    ).strip()
    search_class = request.args.get('class', '').strip()
    per_page = 50

    user_where_clauses = []
    user_where_params = []

    if search_username:
        user_where_clauses.append("(u.username LIKE %s OR u.email LIKE %s)")
        user_where_params.extend([
            f"%{search_username}%",
            f"%{search_username}%",
        ])

    if search_class:
        user_where_clauses.append(
            "u.id IN (SELECT user_id FROM user_class_map WHERE class_en = %s)"
        )
        user_where_params.append(search_class)

    user_where_sql = ""
    if user_where_clauses:
        user_where_sql = "WHERE " + " AND ".join(user_where_clauses)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            count_sql = f"""
                SELECT COUNT(*) AS total
                FROM (
                    SELECT u.id
                    FROM users u
                    {user_where_sql}
                    ORDER BY u.id ASC
                ) t
            """
            cursor.execute(count_sql, user_where_params)
            total = cursor.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page
            if not total_pages:
                page = 1
            elif page > total_pages:
                page = total_pages

            data_sql = f"""
                SELECT u.id, u.username, u.email, u.is_admin
                FROM users u
                {user_where_sql}
                ORDER BY u.id ASC
                LIMIT %s OFFSET %s
            """
            params = user_where_params + [per_page, (page - 1) * per_page]
            cursor.execute(data_sql, params)
            users = cursor.fetchall()

        if users:
            uid_list = [u['id'] for u in users]
            placeholders = ','.join(['%s'] * len(uid_list))

            with conn.cursor() as cursor:
                map_sql = f"""
                    SELECT m.user_id, m.class_en, ct.class_cn
                    FROM user_class_map m
                    JOIN class_table ct ON ct.class_en = m.class_en
                    WHERE m.user_id IN ({placeholders})
                    ORDER BY m.user_id ASC, m.class_en ASC
                """
                cursor.execute(map_sql, uid_list)
                mapping_rows = cursor.fetchall()

            class_map = {uid: [] for uid in uid_list}
            for row in mapping_rows:
                class_map[row['user_id']].append({
                    "class_en": row['class_en'],
                    "class_cn": row['class_cn'],
                })

            for u in users:
                u['classes'] = class_map.get(u['id'], [])
                u['classes_display'] = ' / '.join(
                    cls.get('class_cn') or cls['class_en']
                    for cls in u['classes']
                )
        else:
            users = []
    finally:
        conn.close()

    classes = get_all_classes()
    try:
        mail_service_configured = bool(get_mail_settings())
    except Exception:
        current_app.logger.exception('读取邮件服务状态失败')
        mail_service_configured = False
    return render_template(
        'admin/users.html',
        users=users,
        classes=classes,
        user=user,
        current_page=page,
        total_pages=total_pages,
        total_users=total,
        search_username=search_username,
        search_class=search_class,
        mail_service_configured=mail_service_configured,
    )


@admin_user_bp.route('/admin/grant_user_admin_ajax', methods=['POST'])
def grant_user_admin_ajax():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    user_id = request.form.get('user_id', type=int)
    if not user_id:
        return jsonify({'success': False, 'message': '缺少用户ID'}), 400

    target_user = None
    granted = False
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                'SELECT id, username, is_admin FROM users WHERE id=%s FOR UPDATE',
                (user_id,),
            )
            target_user = cursor.fetchone()
            if not target_user:
                conn.rollback()
                return jsonify({'success': False, 'message': '用户不存在'}), 404
            if int(target_user.get('is_admin') or 0) != 1:
                cursor.execute(
                    'UPDATE users SET is_admin=1 WHERE id=%s',
                    (user_id,),
                )
                granted = cursor.rowcount == 1
        conn.commit()
    except Exception:
        current_app.logger.exception(
            '授予管理员权限失败',
            extra={'user_id': user_id},
        )
        conn.rollback()
        return jsonify({'success': False, 'message': '数据库操作失败，请稍后再试'}), 500
    finally:
        conn.close()

    if granted:
        _invalidate_problem_list_cache_for_user(
            user_id=user_id,
            username=target_user.get('username'),
        )
    return jsonify({
        'success': True,
        'message': '管理员权限已授予' if granted else '该用户已经是管理员',
        'user_id': user_id,
        'is_admin': True,
        'granted': granted,
    })


@admin_user_bp.route('/admin/edit_username_ajax', methods=['POST'])
def edit_username_ajax():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    user_id = request.form.get('user_id', type=int)
    new_username = request.form.get('new_username')

    if not new_username or not user_id:
        return jsonify({'success': False, 'message': '缺少必要参数'}), 400

    username_ok, new_username, username_msg = validate_username(new_username)
    if not username_ok:
        return jsonify({'success': False, 'message': username_msg}), 400

    try:
        old_username = rename_user(user_id, new_username)
    except LookupError:
        return jsonify({'success': False, 'message': '用户不存在'}), 404
    except ValueError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400
    except Exception:
        current_app.logger.exception('修改用户名事务失败', extra={'user_id': user_id})
        return jsonify({'success': False, 'message': '数据库操作失败，请稍后再试'}), 500

    if session.get('username') == old_username:
        session['username'] = new_username

    _invalidate_problem_list_cache_for_user(user_id=user_id, username=old_username)
    _invalidate_problem_list_cache_for_user(username=new_username)

    return jsonify({'success': True, 'message': '更新成功', 'user_id': user_id, 'new_username': new_username})


@admin_user_bp.route('/admin/set_user_email_ajax', methods=['POST'])
def set_user_email_ajax():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    user_id = request.form.get('user_id', type=int)
    email_ok, new_email, email_message = validate_email(request.form.get('email'))
    if not user_id:
        return jsonify({'success': False, 'message': '缺少用户ID'}), 400
    if not email_ok:
        return jsonify({'success': False, 'message': email_message}), 400

    target_user = None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                'SELECT id, username, email FROM users WHERE id=%s FOR UPDATE',
                (user_id,),
            )
            target_user = cursor.fetchone()
            if not target_user:
                conn.rollback()
                return jsonify({'success': False, 'message': '用户不存在'}), 404
            cursor.execute(
                'SELECT id FROM users WHERE email=%s AND id<>%s LIMIT 1 FOR UPDATE',
                (new_email, user_id),
            )
            if cursor.fetchone():
                conn.rollback()
                return jsonify({'success': False, 'message': '该邮箱已被其他用户使用'}), 400
            changed = str(target_user.get('email') or '') != new_email
            if changed:
                cursor.execute(
                    'UPDATE users SET email=%s WHERE id=%s',
                    (new_email, user_id),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        current_app.logger.exception('设置用户邮箱失败', extra={'user_id': user_id})
        return jsonify({'success': False, 'message': '数据库操作失败，请稍后再试'}), 500
    finally:
        conn.close()

    _audit_user_admin_action(
        'set_email',
        'success',
        admin,
        target_user,
        changed=changed,
    )
    return jsonify({
        'success': True,
        'message': '邮箱已更新' if changed else '邮箱未发生变化',
        'user_id': user_id,
        'email': new_email,
        'changed': changed,
    })


@admin_user_bp.route('/admin/send_password_reset_email_ajax', methods=['POST'])
def send_password_reset_email_ajax():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    user_id = request.form.get('user_id', type=int)
    if not user_id:
        return jsonify({'success': False, 'message': '缺少用户ID'}), 400

    try:
        mail_settings = get_mail_settings(include_secret=True)
    except Exception:
        current_app.logger.exception('读取邮件服务配置失败')
        return jsonify({'success': False, 'message': '读取邮件服务配置失败'}), 500
    if not mail_settings:
        return jsonify({'success': False, 'message': '站点尚未配置邮件服务'}), 503

    target_user = None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                'SELECT id, username, email FROM users WHERE id=%s FOR UPDATE',
                (user_id,),
            )
            target_user = cursor.fetchone()
            if not target_user:
                conn.rollback()
                return jsonify({'success': False, 'message': '用户不存在'}), 404

            email_ok, recipient, _ = validate_email(target_user.get('email'))
            if not email_ok:
                conn.rollback()
                return jsonify({
                    'success': False,
                    'message': '请先为该用户设置有效邮箱',
                }), 400

            new_password = _random_password()
            cursor.execute(
                'UPDATE users SET password_hash=%s WHERE id=%s',
                (hash_password(new_password), user_id),
            )
            send_plain_text_email(
                settings=mail_settings,
                recipient=recipient,
                subject='NumericalOJ 密码已重置',
                body=(
                    f"您好，{target_user['username']}：\n\n"
                    "管理员已为您的 NumericalOJ 账户重置密码。\n"
                    f"新密码：{new_password}\n\n"
                    "请使用新密码登录，并尽快在账户设置中修改密码。"
                    "\n若您未申请重置，请联系站点管理员。\n"
                ),
            )
        conn.commit()
    except MailDeliveryError as exc:
        conn.rollback()
        _audit_user_admin_action(
            'reset_password_email', 'failure', admin, target_user,
            reason='mail_delivery_failed',
        )
        return jsonify({'success': False, 'message': str(exc)}), 502
    except Exception:
        conn.rollback()
        current_app.logger.exception('重置用户密码失败', extra={'user_id': user_id})
        _audit_user_admin_action(
            'reset_password_email', 'failure', admin, target_user,
            reason='internal_error',
        )
        return jsonify({'success': False, 'message': '重置密码失败，请稍后再试'}), 500
    finally:
        conn.close()

    _audit_user_admin_action(
        'reset_password_email', 'success', admin, target_user,
        delivery='email',
    )
    return jsonify({
        'success': True,
        'message': '随机密码已生成并发送至用户邮箱',
        'user_id': user_id,
    })


@admin_user_bp.route('/admin/get_user_grades', methods=['GET'])
def get_user_grades():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    user_id = request.args.get('user_id', type=int)
    if not user_id:
        return jsonify({'success': False, 'message': '缺少用户ID'}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT p.id AS problem_id, p.title AS problem_title, p.max_score, ms.score AS user_score
                FROM problems p
                LEFT JOIN max_score ms
                    ON ms.problem_id = p.id AND ms.userid = %s
                WHERE ms.score IS NOT NULL
                ORDER BY p.id ASC
                """,
                (user_id,),
            )
            rows = cursor.fetchall()

        grades = []
        for row in rows:
            grades.append({
                'problem_id': row['problem_id'],
                'problem_title': row['problem_title'],
                'user_score': row['user_score'],
                'max_score': row['max_score'] or 0,
            })

        return jsonify({'success': True, 'grades': grades})

    except Exception as e:
        return jsonify({'success': False, 'message': f'数据库操作失败，请稍后再试'}), 500
    finally:
        conn.close()


@admin_user_bp.route('/admin/update_user_grade', methods=['POST'])
def update_user_grade():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    user_id = request.form.get('user_id', type=int)
    problem_id = request.form.get('problem_id', type=int)
    score_str = request.form.get('score', '').strip()

    if not user_id or not problem_id:
        return jsonify({'success': False, 'message': '缺少必要参数'}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    problem = get_problem_title(problem_id)
    if not problem:
        return jsonify({'success': False, 'message': '题目不存在'}), 404

    if score_str == '':
        score = None
    else:
        try:
            score = int(score_str)
            max_score = problem['max_score'] or 0
            if score < 0 or score > max_score:
                return jsonify({'success': False, 'message': f'分数必须在 0 到 {max_score} 之间'}), 400
        except ValueError:
            return jsonify({'success': False, 'message': '分数格式错误'}), 400

    try:
        if score is None:
            delete_user_problem_max_score(user_id, problem_id)
        else:
            upsert_user_problem_max_score(user_id, problem_id, score)
        return jsonify({'success': True, 'message': '成绩更新成功'})

    except Exception as e:
        return jsonify({'success': False, 'message': f'数据库操作失败，请稍后再试'}), 500


@admin_user_bp.route('/admin/problem_scores/<int:problem_id>')
def get_problem_scores(problem_id):
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    problem = get_problem_title(problem_id)
    if not problem:
        return jsonify({'success': False, 'message': '题目不存在'}), 404

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT u.id, u.username, ms.score
                FROM users u
                JOIN max_score ms ON u.id = ms.userid
                WHERE u.is_admin = 0 AND ms.problem_id = %s AND ms.score IS NOT NULL
                ORDER BY u.username
            """
            cursor.execute(sql, (problem_id,))
            results = cursor.fetchall()

        class_map = {row['id']: [] for row in results}
        if results:
            user_ids = [row['id'] for row in results]
            placeholders = ','.join(['%s'] * len(user_ids))
            with conn.cursor() as cursor:
                cursor.execute(
                    f"""
                    SELECT m.user_id, m.class_en, ct.class_cn
                    FROM user_class_map m
                    JOIN class_table ct ON ct.class_en = m.class_en
                    WHERE m.user_id IN ({placeholders})
                    ORDER BY m.user_id ASC, m.class_en ASC
                    """,
                    user_ids,
                )
                for membership in cursor.fetchall() or []:
                    class_map[membership['user_id']].append({
                        'class_en': membership['class_en'],
                        'class_cn': membership['class_cn'],
                    })

        scores = []
        for row in results:
            classes = class_map.get(row['id'], [])
            classes_display = ' / '.join(
                cls.get('class_cn') or cls['class_en']
                for cls in classes
            ) or '未分配班级'
            scores.append({
                'user_id': row['id'],
                'username': row['username'],
                'classes': classes,
                'classes_display': classes_display,
                'score': row['score'],
            })
        scores.sort(
            key=lambda item: (
                item['classes_display'],
                item['username'],
            )
        )

        return jsonify({
            'success': True,
            'problem_id': problem_id,
            'problem_title': problem['title'],
            'max_score': problem['max_score'] or 0,
            'scores': scores,
        })

    except Exception as e:
        return jsonify({'success': False, 'message': f'数据库操作失败，请稍后再试'}), 500
    finally:
        conn.close()


@admin_user_bp.route('/admin/add_class_ajax', methods=['POST'])
def add_class_ajax():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    class_en = request.form.get('class_en', '').strip()
    # 注意：re.match 返回 Match/None，绝不会等于 False，旧写法 `is False` 是永远不成立的死代码。
    if not re.fullmatch(r'[A-Za-z0-9_]+', class_en):
        return jsonify({'success': False, 'message': '班级英文名必须仅由大小写字母、数字、下划线构成'}), 400
    class_en = f"C{class_en}"
    class_cn = request.form.get('class_cn', '').strip()

    if not class_en or not class_cn:
        return jsonify({'success': False, 'message': '班级英文名和中文名不能为空'}), 400

    check_old_class = get_class_by_en(class_en)
    if check_old_class:
        return jsonify({'success': False, 'message': '已存在以这个英文名命名的班级，请修改'}), 400

    check_old_class = get_class_by_cn(class_cn)
    if check_old_class:
        return jsonify({'success': False, 'message': '已存在以这个中文名命名的班级，请修改'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "INSERT INTO class_table "
                "(class_en, class_cn, class_cnt, logo_seed) "
                "VALUES (%s, %s, 0, %s)"
            )
            cursor.execute(
                sql,
                (class_en, class_cn, generate_class_logo_seed()),
            )
        conn.commit()
        with conn.cursor() as cursor:
            sql = f"CREATE TABLE {safe_table_name(class_en)}(id INT PRIMARY KEY AUTO_INCREMENT, problem_id INT, ddl DATETIME, complete_cnt INT, problem_title TEXT, ranking_competition_id INT DEFAULT NULL) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;"
            cursor.execute(sql)
        conn.commit()
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

    flash(f"成功添加班级 {class_cn}", 'success')
    return jsonify({'success': True, 'message': '新增班级成功', 'class_en': class_en, 'class_cn': class_cn})
