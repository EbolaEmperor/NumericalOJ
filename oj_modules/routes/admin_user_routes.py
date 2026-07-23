#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from flask import Blueprint, current_app, flash, jsonify, render_template, request, session

from oj_modules.class_membership_services import (
    MembershipNotFoundError,
    set_primary_membership,
)
from oj_modules.class_logo_services import generate_class_logo_seed
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
from oj_modules.security_utils import validate_username


admin_user_bp = Blueprint('admin_user', __name__)


def _invalidate_problem_list_cache_for_user(user_id=None, username=None):
    try:
        from oj_modules.routes.problem_core_routes import invalidate_problem_list_cache_for_user
        invalidate_problem_list_cache_for_user(user_id=user_id, username=username)
    except Exception:
        # 缓存失效失败不影响主流程
        current_app.logger.exception('用户题目列表缓存失效失败')


from oj_modules.auth_helpers import current_user, is_admin


@admin_user_bp.route('/admin/users')
def user_management():
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    page = request.args.get('page', 1, type=int)
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
        user_where_clauses.append("u.username LIKE %s")
        user_where_params.append(f"%{search_username}%")

    if search_class:
        user_where_clauses.append("(u.class = %s OR u.id IN (SELECT user_id FROM user_class_map WHERE class_en = %s))")
        user_where_params.extend([search_class, search_class])

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

            data_sql = f"""
                SELECT u.id, u.username, u.email, u.class, u.class_cn
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
                    SELECT m.user_id, m.class_en, ct.class_cn, m.is_primary
                    FROM user_class_map m
                    JOIN class_table ct ON ct.class_en = m.class_en
                    WHERE m.user_id IN ({placeholders})
                """
                cursor.execute(map_sql, uid_list)
                mapping_rows = cursor.fetchall()

            extra_map = {uid: [] for uid in uid_list}
            for row in mapping_rows:
                extra_map[row['user_id']].append({
                    "class_en": row['class_en'],
                    "class_cn": row['class_cn'],
                    "is_primary": row.get('is_primary', 0),
                })

            for u in users:
                u_extra = []
                for cls in extra_map.get(u['id'], []):
                    if cls['class_en'] != u['class']:
                        u_extra.append(cls)
                u['extra_classes'] = u_extra
        else:
            users = []
    finally:
        conn.close()

    classes = get_all_classes()
    return render_template(
        'admin/users.html',
        users=users,
        classes=classes,
        user=user,
        current_page=page,
        total_pages=total_pages,
        search_username=search_username,
        search_class=search_class,
    )


@admin_user_bp.route('/admin/edit_user_ajax', methods=['POST'])
def edit_user_ajax():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    user_id = request.form.get('user_id', type=int)
    new_class_en = (request.form.get('class') or '').strip()
    if not user_id or not new_class_en:
        return jsonify({'success': False, 'message': '缺少必要参数'}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    new_class = get_class_by_en(new_class_en)
    if not new_class:
        return jsonify({'success': False, 'message': '目标班级不存在'}), 400

    old_class_en = user.get('class') or None
    give_admin = 1 if is_admin(user) else (1 if new_class['class_en'] == 'Cadmin' else 0)

    if old_class_en == new_class['class_en'] and user.get('class_cn') == new_class['class_cn'] and user.get('is_admin') == give_admin:
        return jsonify({'success': True, 'message': '主班级未变化', 'user_id': user_id, 'new_class': new_class})

    try:
        set_primary_membership(
            user_id,
            new_class['class_en'],
            new_class['class_cn'],
            give_admin,
            create_if_missing=True,
        )
    except MembershipNotFoundError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400
    except Exception:
        current_app.logger.exception(
            '管理员修改用户主班级事务失败',
            extra={'user_id': user_id, 'class_en': new_class['class_en']},
        )
        return jsonify({'success': False, 'message': f'数据库操作失败，请稍后再试'}), 500

    _invalidate_problem_list_cache_for_user(user_id=user_id, username=user.get('username'))
    flash(f"已将 userID={user_id} 的主班级修改为 {new_class['class_cn']}", 'success')
    return jsonify({'success': True, 'message': '更新成功', 'user_id': user_id, 'new_class': new_class})


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
                SELECT u.id, u.username, u.class_cn, ms.score
                FROM users u
                JOIN max_score ms ON u.id = ms.userid
                WHERE u.is_admin = 0 AND ms.problem_id = %s AND ms.score IS NOT NULL
                ORDER BY u.class_cn, u.username
            """
            cursor.execute(sql, (problem_id,))
            results = cursor.fetchall()

            scores = []
            for row in results:
                scores.append({
                    'user_id': row['id'],
                    'username': row['username'],
                    'class_cn': row['class_cn'] or '未分配班级',
                    'score': row['score'],
                })

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
