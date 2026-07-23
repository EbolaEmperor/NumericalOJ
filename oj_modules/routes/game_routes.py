#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import random
from uuid import uuid4

from flask import Blueprint, jsonify, render_template, request, send_file, session

from oj_modules.db_services import get_db_connection, get_user_by_username


game_bp = Blueprint('game', __name__)
_circle_cat_tables_ready = False
_circle_cat_rng = random.SystemRandom()
_CIRCLE_CAT_CONFIGS = {
    'desktop': {'size': 11, 'initial_blocks': 5},
    'mobile': {'size': 9, 'initial_blocks': 4},
}
_EVEN_ROW_DIRS = [(-1, -1), (-1, 0), (0, -1), (0, 1), (1, -1), (1, 0)]
_ODD_ROW_DIRS = [(-1, 0), (-1, 1), (0, -1), (0, 1), (1, 0), (1, 1)]


from oj_modules.arc_agi_3.catalog import get_arc_game, list_arc_games
from oj_modules.arc_agi_3.services import (
    ArcGameError,
    ArcGameNotFound,
    ArcInvalidAction,
    ArcSessionBusy,
    ArcSessionNotFound,
    perform_arc_action,
    start_arc_game,
)
from oj_modules.auth_helpers import current_user, is_admin, login_required


def _arc_current_username():
    user = current_user()
    return str(user.get('username') or '') if user else ''


@game_bp.route('/games/arc-agi-3')
@login_required
def arc_agi_3_index():
    games = [game.to_public_dict() for game in list_arc_games()]
    return render_template(
        'games/arc_agi_3/index.html',
        user=current_user(),
        games=games,
    )


@game_bp.route('/games/arc-agi-3/<game_id>')
@login_required
def arc_agi_3_player(game_id):
    game = get_arc_game(game_id)
    if game is None:
        return render_template(
            'games/arc_agi_3/not_found.html',
            user=current_user(),
        ), 404
    return render_template(
        'games/arc_agi_3/player.html',
        user=current_user(),
        game=game.to_public_dict(),
    )


@game_bp.route('/games/arc-agi-3/<game_id>/preview.png')
@login_required
def arc_agi_3_preview(game_id):
    game = get_arc_game(game_id)
    if game is None or not game.preview_path.is_file():
        return '', 404
    return send_file(
        game.preview_path,
        mimetype='image/png',
        conditional=True,
        max_age=86400,
    )


@game_bp.route('/games/arc-agi-3/<game_id>/start', methods=['POST'])
@login_required
def arc_agi_3_start(game_id):
    try:
        session_id, frame_data = start_arc_game(_arc_current_username(), game_id)
    except ArcGameNotFound as exc:
        return jsonify(success=False, message=str(exc)), 404
    except ArcGameError:
        return jsonify(success=False, message='游戏启动失败，请稍后重试。'), 500

    return jsonify(
        success=True,
        session_id=session_id,
        game=frame_data,
    )


@game_bp.route('/games/arc-agi-3/session/<session_id>/action', methods=['POST'])
@login_required
def arc_agi_3_action(session_id):
    data = request.get_json(silent=True) or {}
    try:
        frame_data = perform_arc_action(
            _arc_current_username(),
            session_id,
            data.get('action_id'),
            data.get('data'),
        )
    except ArcSessionNotFound as exc:
        return jsonify(success=False, message=str(exc)), 404
    except ArcSessionBusy as exc:
        return jsonify(success=False, message=str(exc)), 409
    except ArcInvalidAction as exc:
        return jsonify(success=False, message=str(exc)), 400
    except ArcGameError:
        return jsonify(success=False, message='操作执行失败，请重新开始。'), 500

    return jsonify(success=True, game=frame_data)


def ensure_circle_cat_tables():
    global _circle_cat_tables_ready
    _circle_cat_tables_ready = True


def _parse_mode(value):
    mode = str(value or '').strip().lower()
    if mode in _CIRCLE_CAT_CONFIGS:
        return mode
    return 'desktop'


def _parse_positive_int(value, default, minimum=1, maximum=200):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def _in_bounds(board_size, row, col):
    return 0 <= row < board_size and 0 <= col < board_size


def _is_edge(board_size, row, col):
    return row == 0 or col == 0 or row == board_size - 1 or col == board_size - 1


def _cell_key(row, col):
    return f'{row},{col}'


def _get_neighbors(board_size, row, col):
    dirs = _EVEN_ROW_DIRS if row % 2 == 0 else _ODD_ROW_DIRS
    neighbors = []
    for d_row, d_col in dirs:
        next_row = row + d_row
        next_col = col + d_col
        if _in_bounds(board_size, next_row, next_col):
            neighbors.append({'row': next_row, 'col': next_col})
    return neighbors


def _get_open_neighbors(board, cat_pos, board_size, row, col):
    open_neighbors = []
    for cell in _get_neighbors(board_size, row, col):
        if board[cell['row']][cell['col']] == 'blocked':
            continue
        if cell['row'] == cat_pos['row'] and cell['col'] == cat_pos['col']:
            continue
        open_neighbors.append(cell)
    return open_neighbors


def _reconstruct_path(previous, target):
    path = [target]
    cursor = target
    while _cell_key(cursor['row'], cursor['col']) in previous:
        cursor = previous[_cell_key(cursor['row'], cursor['col'])]
        path.append(cursor)
    path.reverse()
    return path


def _find_shortest_path_to_edge(board, board_size, start_row, start_col):
    queue = [{'row': start_row, 'col': start_col}]
    previous = {}
    visited = {_cell_key(start_row, start_col)}
    cursor = 0

    while cursor < len(queue):
        current = queue[cursor]
        cursor += 1
        if not (current['row'] == start_row and current['col'] == start_col) and _is_edge(
            board_size, current['row'], current['col']
        ):
            return _reconstruct_path(previous, current)

        for next_cell in _get_neighbors(board_size, current['row'], current['col']):
            key = _cell_key(next_cell['row'], next_cell['col'])
            if key in visited or board[next_cell['row']][next_cell['col']] == 'blocked':
                continue
            visited.add(key)
            previous[key] = current
            queue.append(next_cell)

    return None


def _estimate_edge_distance(board_size, row, col):
    return min(row, col, board_size - 1 - row, board_size - 1 - col)


def _build_shortest_path_dag_stats(board, cat_pos, board_size):
    dist = [[float('inf')] * board_size for _ in range(board_size)]
    levels = {}
    queue = [{'row': cat_pos['row'], 'col': cat_pos['col']}]
    dist[cat_pos['row']][cat_pos['col']] = 0
    cursor = 0
    min_edge_distance = float('inf')

    while cursor < len(queue):
        current = queue[cursor]
        cursor += 1
        current_dist = dist[current['row']][current['col']]

        if current_dist > min_edge_distance:
            continue

        if not (current['row'] == cat_pos['row'] and current['col'] == cat_pos['col']) and _is_edge(
            board_size, current['row'], current['col']
        ):
            if current_dist < min_edge_distance:
                min_edge_distance = current_dist

        for next_cell in _get_neighbors(board_size, current['row'], current['col']):
            if board[next_cell['row']][next_cell['col']] == 'blocked':
                continue
            next_dist = current_dist + 1
            if next_dist >= dist[next_cell['row']][next_cell['col']]:
                continue
            dist[next_cell['row']][next_cell['col']] = next_dist
            queue.append(next_cell)

    if min_edge_distance == float('inf'):
        return None

    for row in range(board_size):
        for col in range(board_size):
            cell_dist = dist[row][col]
            if cell_dist == float('inf') or cell_dist > min_edge_distance:
                continue
            levels.setdefault(cell_dist, []).append({'row': row, 'col': col})

    path_count = [[0] * board_size for _ in range(board_size)]
    for cell in levels.get(min_edge_distance, []):
        if _is_edge(board_size, cell['row'], cell['col']):
            path_count[cell['row']][cell['col']] = 1

    for level in range(min_edge_distance - 1, -1, -1):
        for cell in levels.get(level, []):
            count = 0
            for next_cell in _get_neighbors(board_size, cell['row'], cell['col']):
                if dist[next_cell['row']][next_cell['col']] == level + 1:
                    count += path_count[next_cell['row']][next_cell['col']]
            path_count[cell['row']][cell['col']] = count

    return {'dist': dist, 'path_count': path_count}


def _choose_max_branch_shortest_step(board, cat_pos, board_size, open_neighbors):
    if not open_neighbors:
        return None

    stats = _build_shortest_path_dag_stats(board, cat_pos, board_size)
    if not stats:
        return None

    best_cell = None
    best_sort_key = None
    for neighbor in open_neighbors:
        path_count = stats['path_count'][neighbor['row']][neighbor['col']]
        if path_count <= 0:
            continue
        sort_key = (
            -path_count,
            _estimate_edge_distance(board_size, neighbor['row'], neighbor['col']),
            neighbor['row'],
            neighbor['col'],
        )
        if best_sort_key is None or sort_key < best_sort_key:
            best_sort_key = sort_key
            best_cell = {'row': neighbor['row'], 'col': neighbor['col']}
    return best_cell


def _choose_fallback_move(board_size, open_neighbors):
    if not open_neighbors:
        return None
    return min(
        open_neighbors,
        key=lambda cell: (
            _estimate_edge_distance(board_size, cell['row'], cell['col']),
            cell['row'],
            cell['col'],
        ),
    )


def _is_cat_sealed(board, cat_pos, board_size):
    return _find_shortest_path_to_edge(board, board_size, cat_pos['row'], cat_pos['col']) is None


def _create_empty_board(board_size):
    return [['empty'] * board_size for _ in range(board_size)]


def _generate_circle_cat_initial_state(mode):
    config = _CIRCLE_CAT_CONFIGS[mode]
    board_size = int(config['size'])
    initial_blocks = int(config['initial_blocks'])

    while True:
        board = _create_empty_board(board_size)
        cat_pos = {'row': board_size // 2, 'col': board_size // 2}
        blocked_positions = []
        blocked_set = set()

        while len(blocked_positions) < initial_blocks:
            row = _circle_cat_rng.randrange(board_size)
            col = _circle_cat_rng.randrange(board_size)
            if (row == cat_pos['row'] and col == cat_pos['col']) or (row, col) in blocked_set:
                continue
            blocked_set.add((row, col))
            board[row][col] = 'blocked'
            blocked_positions.append([row, col])

        if _get_open_neighbors(board, cat_pos, board_size, cat_pos['row'], cat_pos['col']) and _find_shortest_path_to_edge(
            board, board_size, cat_pos['row'], cat_pos['col']
        ):
            return {
                'mode': mode,
                'board_size': board_size,
                'cat': cat_pos,
                'initial_blocked': blocked_positions,
            }


def _create_circle_cat_game(username, mode):
    initial_state = _generate_circle_cat_initial_state(mode)
    game_id = None

    if username:
        game_id = uuid4().hex
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO circle_cat_games (
                        game_id, username, mode, board_size, initial_blocked_json, cat_row, cat_col
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        game_id,
                        username,
                        mode,
                        initial_state['board_size'],
                        json.dumps(initial_state['initial_blocked'], separators=(',', ':')),
                        initial_state['cat']['row'],
                        initial_state['cat']['col'],
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    initial_state['game_id'] = game_id
    return initial_state


def _parse_moves(value, board_size):
    if not isinstance(value, list):
        return None
    max_moves = max(1, board_size * board_size)
    if len(value) > max_moves:
        return None

    parsed_moves = []
    for item in value:
        row = None
        col = None
        if isinstance(item, dict):
            row = item.get('row')
            col = item.get('col')
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            row, col = item
        else:
            return None

        try:
            row = int(row)
            col = int(col)
        except (TypeError, ValueError):
            return None

        if not _in_bounds(board_size, row, col):
            return None
        parsed_moves.append({'row': row, 'col': col})
    return parsed_moves


def _replay_circle_cat_game(board_size, blocked_positions, cat_pos, moves):
    board = _create_empty_board(board_size)
    seen_blocked = set()
    for row, col in blocked_positions:
        if not _in_bounds(board_size, row, col):
            return {'success': False, 'message': '初始棋盘非法。'}
        if row == cat_pos['row'] and col == cat_pos['col']:
            return {'success': False, 'message': '初始棋盘非法。'}
        if (row, col) in seen_blocked:
            return {'success': False, 'message': '初始棋盘非法。'}
        seen_blocked.add((row, col))
        board[row][col] = 'blocked'

    turn_count = 0
    for index, move in enumerate(moves):
        row = move['row']
        col = move['col']
        if board[row][col] == 'blocked' or (row == cat_pos['row'] and col == cat_pos['col']):
            return {'success': False, 'message': '落子序列非法。'}

        board[row][col] = 'blocked'
        turn_count += 1

        if _is_cat_sealed(board, cat_pos, board_size):
            if index != len(moves) - 1:
                return {'success': False, 'message': '对局结束后存在额外落子。'}
            return {'success': True, 'finished': True, 'state': 'win', 'turn_count': turn_count}

        open_neighbors = _get_open_neighbors(board, cat_pos, board_size, cat_pos['row'], cat_pos['col'])
        if not open_neighbors:
            if index != len(moves) - 1:
                return {'success': False, 'message': '对局结束后存在额外落子。'}
            return {'success': True, 'finished': True, 'state': 'win', 'turn_count': turn_count}

        next_step = _choose_max_branch_shortest_step(board, cat_pos, board_size, open_neighbors)
        if next_step is None:
            next_step = _choose_fallback_move(board_size, open_neighbors)
        if next_step is None:
            return {'success': False, 'message': '对局回放失败。'}

        cat_pos = {'row': next_step['row'], 'col': next_step['col']}
        if _is_edge(board_size, cat_pos['row'], cat_pos['col']):
            if index != len(moves) - 1:
                return {'success': False, 'message': '对局结束后存在额外落子。'}
            return {'success': True, 'finished': True, 'state': 'lose', 'turn_count': turn_count}

        if _is_cat_sealed(board, cat_pos, board_size):
            if index != len(moves) - 1:
                return {'success': False, 'message': '对局结束后存在额外落子。'}
            return {'success': True, 'finished': True, 'state': 'win', 'turn_count': turn_count}

    return {'success': False, 'message': '对局尚未结束。'}


def _save_circle_cat_record(cursor, username, turn_count, state):
    cursor.execute(
        """
        INSERT INTO circle_cat_records (username, turn_count, is_win)
        VALUES (%s, %s, %s)
        """,
        (username, turn_count, 1 if state == 'win' else 0),
    )


def get_circle_cat_leaderboard_page(limit=10, offset=0):
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    win_rows = []
    fail_rows = []
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT username, MIN(turn_count) AS best_turns, MIN(created_at) AS first_win_at
                FROM circle_cat_records
                WHERE is_win=1
                GROUP BY username
                ORDER BY best_turns ASC, first_win_at ASC
                """
            )
            win_rows = cursor.fetchall() or []

            winner_usernames = [row.get('username', '') for row in win_rows if row.get('username')]
            if winner_usernames:
                placeholders = ", ".join(["%s"] * len(winner_usernames))
                cursor.execute(
                    f"""
                    SELECT username, MAX(created_at) AS last_fail_at
                    FROM circle_cat_records
                    WHERE is_win=0
                      AND username NOT IN ({placeholders})
                    GROUP BY username
                    ORDER BY last_fail_at DESC
                    """,
                    tuple(winner_usernames),
                )
            else:
                cursor.execute(
                    """
                    SELECT username, MAX(created_at) AS last_fail_at
                    FROM circle_cat_records
                    WHERE is_win=0
                    GROUP BY username
                    ORDER BY last_fail_at DESC
                    """
                )
            fail_rows = cursor.fetchall() or []
    except Exception:
        win_rows = []
        fail_rows = []
    finally:
        if conn is not None:
            conn.close()

    leaderboard = []
    for row in win_rows:
        leaderboard.append(
            {
                'username': row.get('username', ''),
                'best_turns': int(row.get('best_turns') or 0),
                'status': 'win',
            }
        )
    for row in fail_rows:
        leaderboard.append(
            {
                'username': row.get('username', ''),
                'status': 'lose',
            }
        )
    total = len(leaderboard)
    return leaderboard[offset: offset + limit], total


def get_circle_cat_leaderboard(limit=10):
    leaderboard, _ = get_circle_cat_leaderboard_page(limit=limit, offset=0)
    return leaderboard


@game_bp.route('/games/circle-cat')
def circle_cat():
    return render_template(
        'games/circle_cat.html',
        user=current_user(),
        leaderboard=get_circle_cat_leaderboard(limit=10),
    )


@game_bp.route('/games/circle-cat/start', methods=['POST'])
def circle_cat_start():
    data = request.get_json(silent=True) or {}
    mode = _parse_mode(data.get('mode'))
    username = session.get('username')

    try:
        game = _create_circle_cat_game(username, mode)
    except Exception:
        return jsonify({'success': False, 'message': '创建对局失败，请稍后重试。'}), 500

    return jsonify(
        {
            'success': True,
            'game_id': game.get('game_id'),
            'mode': game.get('mode'),
            'board_size': game.get('board_size'),
            'cat': game.get('cat'),
            'initial_blocked': game.get('initial_blocked'),
            'can_record': bool(username),
        }
    )


@game_bp.route('/games/circle-cat/leaderboard')
def circle_cat_leaderboard():
    page = _parse_positive_int(request.args.get('page'), default=1, minimum=1, maximum=1000000)
    limit = _parse_positive_int(request.args.get('limit'), default=10, minimum=1, maximum=200)
    offset = (page - 1) * limit
    leaderboard, total = get_circle_cat_leaderboard_page(limit=limit, offset=offset)
    return jsonify({
        'success': True,
        'leaderboard': leaderboard,
        'total': total,
        'page': page,
        'limit': limit,
    })


@game_bp.route('/games/circle-cat/result', methods=['POST'])
def circle_cat_result():
    username = session.get('username')
    if not username:
        return jsonify({
            'success': False,
            'message': '未登录，无法记录成绩。',
            'leaderboard': get_circle_cat_leaderboard(limit=10),
        }), 401

    data = request.get_json(silent=True) or {}
    game_id = str(data.get('game_id') or '').strip().lower()
    if len(game_id) != 32:
        return jsonify({'success': False, 'message': '无效的对局标识。'}), 400
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT game_id, username, board_size, initial_blocked_json, cat_row, cat_col, is_finished
                FROM circle_cat_games
                WHERE game_id = %s
                FOR UPDATE
                """,
                (game_id,),
            )
            game_row = cursor.fetchone()
            if not game_row:
                conn.rollback()
                return jsonify({'success': False, 'message': '对局不存在。'}), 404
            if game_row.get('username') != username:
                conn.rollback()
                return jsonify({'success': False, 'message': '无权提交该对局结果。'}), 403
            if int(game_row.get('is_finished') or 0) == 1:
                conn.rollback()
                return jsonify({'success': False, 'message': '该对局结果已提交。'}), 409

            board_size = int(game_row.get('board_size') or 0)
            if board_size <= 0:
                conn.rollback()
                return jsonify({'success': False, 'message': '对局数据损坏。'}), 500

            moves = _parse_moves(data.get('moves'), board_size)
            if moves is None:
                conn.rollback()
                return jsonify({'success': False, 'message': '无效的落子序列。'}), 400

            try:
                blocked_positions = json.loads(game_row.get('initial_blocked_json') or '[]')
            except (TypeError, ValueError, json.JSONDecodeError):
                conn.rollback()
                return jsonify({'success': False, 'message': '对局数据损坏。'}), 500

            result = _replay_circle_cat_game(
                board_size=board_size,
                blocked_positions=blocked_positions,
                cat_pos={'row': int(game_row.get('cat_row') or 0), 'col': int(game_row.get('cat_col') or 0)},
                moves=moves,
            )
            if not result.get('success'):
                conn.rollback()
                return jsonify({'success': False, 'message': result.get('message') or '对局校验失败。'}), 400

            _save_circle_cat_record(cursor, username, int(result['turn_count']), result['state'])
            cursor.execute(
                """
                UPDATE circle_cat_games
                SET is_finished = 1, finished_at = CURRENT_TIMESTAMP
                WHERE game_id = %s
                """,
                (game_id,),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        return jsonify({'success': False, 'message': '成绩保存失败，请稍后重试。'}), 500
    finally:
        conn.close()

    return jsonify({
        'success': True,
        'state': result['state'],
        'turn_count': int(result['turn_count']),
        'leaderboard': get_circle_cat_leaderboard(limit=10),
    })
