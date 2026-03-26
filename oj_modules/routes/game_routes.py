#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, jsonify, render_template, request, session

from oj_modules.db_services import get_db_connection, get_user_by_username


game_bp = Blueprint('game', __name__)
_circle_cat_table_ready = False


def current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def ensure_circle_cat_table():
    global _circle_cat_table_ready
    if _circle_cat_table_ready:
        return

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS circle_cat_records (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                    turn_count INT NOT NULL,
                    is_win TINYINT(1) NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_circle_cat_win_turn (is_win, turn_count, created_at),
                    INDEX idx_circle_cat_user_win (username, is_win, turn_count)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
        conn.commit()
        _circle_cat_table_ready = True
    finally:
        conn.close()


def get_circle_cat_leaderboard(limit=5):
    limit = max(1, min(int(limit), 50))
    rows = []
    conn = None
    try:
        ensure_circle_cat_table()
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT username, MIN(turn_count) AS best_turns, MIN(created_at) AS first_win_at
                FROM circle_cat_records
                WHERE is_win=1
                GROUP BY username
                ORDER BY best_turns ASC, first_win_at ASC
                LIMIT {limit}
                """
            )
            rows = cursor.fetchall() or []
    except Exception:
        rows = []
    finally:
        if conn is not None:
            conn.close()

    leaderboard = []
    for row in rows:
        leaderboard.append(
            {
                'username': row.get('username', ''),
                'best_turns': int(row.get('best_turns') or 0),
            }
        )
    return leaderboard


def _parse_turn_count(value):
    try:
        turns = int(value)
    except (TypeError, ValueError):
        return None
    if turns < 0 or turns > 100000:
        return None
    return turns


def save_circle_cat_record(username, turn_count, state):
    ensure_circle_cat_table()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO circle_cat_records (username, turn_count, is_win)
                VALUES (%s, %s, %s)
                """,
                (username, turn_count, 1 if state == 'win' else 0),
            )
        conn.commit()
    finally:
        conn.close()


@game_bp.route('/games/circle-cat')
def circle_cat():
    return render_template(
        'circle_cat.html',
        user=current_user(),
        leaderboard=get_circle_cat_leaderboard(limit=5),
    )


@game_bp.route('/games/circle-cat/leaderboard')
def circle_cat_leaderboard():
    return jsonify({
        'success': True,
        'leaderboard': get_circle_cat_leaderboard(limit=5),
    })


@game_bp.route('/games/circle-cat/result', methods=['POST'])
def circle_cat_result():
    username = session.get('username')
    if not username:
        return jsonify({
            'success': False,
            'message': '未登录，无法记录成绩。',
            'leaderboard': get_circle_cat_leaderboard(limit=5),
        }), 401

    data = request.get_json(silent=True) or {}
    state = str(data.get('state') or '').strip().lower()
    if state not in {'win', 'lose'}:
        return jsonify({'success': False, 'message': '无效的游戏状态。'}), 400

    turn_count = _parse_turn_count(data.get('turn_count'))
    if turn_count is None:
        return jsonify({'success': False, 'message': '无效的回合数。'}), 400

    try:
        save_circle_cat_record(username, turn_count, state)
    except Exception:
        return jsonify({'success': False, 'message': '成绩保存失败，请稍后重试。'}), 500

    return jsonify({
        'success': True,
        'leaderboard': get_circle_cat_leaderboard(limit=5),
    })
