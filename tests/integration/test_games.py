# -*- coding: utf-8 -*-
"""围住猫（circle-cat）小游戏集成测试（§7）。

覆盖 oj_modules/routes/game_routes.py：
- GET  /games/circle-cat             页面 200。
- POST /games/circle-cat/start       登录态返回 game_id + can_record=True；
                                     匿名 game_id=None + can_record=False。
- GET  /games/circle-cat/leaderboard 分页 JSON（success/leaderboard/total/page/limit）。
- POST /games/circle-cat/result      未登录 401；非 hex/长度!=32 game_id 400；
                                     他人对局 403；已结束对局 409；
                                     合法 win 回放 → 记录入库 + 返回 leaderboard。

约定：
- 登录用 conftest 的 login(username)，匿名用裸 client。
- 直接造对局行：用受控的"几乎围死"小棋盘（cat 居中、六个邻居仅留一个开放）
  插入 circle_cat_games，玩家一手堵掉最后的开放邻居即把猫完全围死。该序列对
  game_routes 自身的回放逻辑 _replay_circle_cat_game 是确定性 win（与 Task 18
  共用 _get_neighbors / _is_cat_sealed 等同源逻辑）。
- 入库断言查 circle_cat_records / circle_cat_games（get_db_connection）。
- 中文文案逐字引自源码。
"""
import json
import uuid

from oj_modules.routes import game_routes as gr
from oj_modules.db_services import get_db_connection
from tests import helpers as h


# --------------------------- 工具：构造合法 win 落子序列 ---------------------------

def _near_sealed_setup(board_size):
    """构造一个"几乎围死"的初始棋盘 + 一手即可封死猫的落子序列。

    猫居中（board_size 奇数时六个六边形邻居都在界内）。初始棋盘预先堵住猫的
    全部邻居中除一个之外的格子；玩家唯一一手堵掉最后那个开放邻居，则猫被完全
    围死（_is_cat_sealed → True），_replay_circle_cat_game 判 win、turn_count=1。

    这样不依赖完整博弈搜索，结果对 game_routes 的回放逻辑是确定性的。
    返回 (blocked_positions, cat_pos, moves)。
    """
    cat_pos = {'row': board_size // 2, 'col': board_size // 2}
    neighbors = gr._get_neighbors(board_size, cat_pos['row'], cat_pos['col'])
    assert len(neighbors) >= 2, '居中猫应至少有两个界内邻居'
    open_cell = neighbors[0]
    blocked_positions = [[c['row'], c['col']] for c in neighbors[1:]]
    moves = [{'row': open_cell['row'], 'col': open_cell['col']}]
    return blocked_positions, cat_pos, moves


def _insert_game(game_id, username, board_size, blocked_positions, cat_pos,
                 is_finished=0):
    """直接插入一行 circle_cat_games（受控棋盘）。"""
    gr.ensure_circle_cat_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO circle_cat_games (
                    game_id, username, mode, board_size, initial_blocked_json,
                    cat_row, cat_col, is_finished
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    game_id, username, 'desktop', board_size,
                    json.dumps(blocked_positions, separators=(',', ':')),
                    cat_pos['row'], cat_pos['col'], is_finished,
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _make_solvable_game(username, board_size=7):
    """造一局：cat 居中、邻居几乎堵满，预先算好合法 win 落子序列（一手封死）。

    返回 (game_id, moves)。
    """
    blocked_positions, cat_pos, moves = _near_sealed_setup(board_size)
    game_id = uuid.uuid4().hex
    _insert_game(game_id, username, board_size, blocked_positions, cat_pos)
    return game_id, moves


# --------------------------- 页面 ---------------------------

def test_circle_cat_page_renders(client):
    resp = client.get('/games/circle-cat')
    assert resp.status_code == 200


# --------------------------- start ---------------------------

def test_start_logged_in_returns_game_id_and_can_record(client, login):
    u = h.make_user('catplayer')
    login('catplayer')
    resp = client.post('/games/circle-cat/start', json={'mode': 'desktop'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['can_record'] is True
    assert data['mode'] == 'desktop'
    assert data['board_size'] == 11
    # game_id 为 uuid4().hex（32 位）。
    assert isinstance(data['game_id'], str) and len(data['game_id']) == 32
    assert 'cat' in data and 'initial_blocked' in data
    # 已落库。
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, mode FROM circle_cat_games WHERE game_id=%s",
                (data['game_id'],))
            row = cur.fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row['username'] == 'catplayer'


def test_start_mobile_mode_board_size(client, login):
    h.make_user('catmobile')
    login('catmobile')
    resp = client.post('/games/circle-cat/start', json={'mode': 'mobile'})
    data = resp.get_json()
    assert data['success'] is True
    assert data['mode'] == 'mobile'
    assert data['board_size'] == 9


def test_start_anonymous_no_game_id_and_cannot_record(client):
    resp = client.post('/games/circle-cat/start', json={'mode': 'desktop'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['can_record'] is False
    # 匿名不落库 → game_id 为 None。
    assert data['game_id'] is None


def test_start_invalid_mode_defaults_to_desktop(client):
    resp = client.post('/games/circle-cat/start', json={'mode': 'nope'})
    data = resp.get_json()
    assert data['mode'] == 'desktop'
    assert data['board_size'] == 11


# --------------------------- leaderboard ---------------------------

def test_leaderboard_pagination_shape(client):
    # 先造若干 win 记录（不同用户、不同步数）。
    gr.ensure_circle_cat_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            for i in range(3):
                cur.execute(
                    "INSERT INTO circle_cat_records (username, turn_count, is_win) "
                    "VALUES (%s, %s, 1)", (f'winner{i}', 5 + i))
        conn.commit()
    finally:
        conn.close()

    resp = client.get('/games/circle-cat/leaderboard?page=1&limit=2')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['page'] == 1
    assert data['limit'] == 2
    assert data['total'] == 3
    assert len(data['leaderboard']) == 2
    # 排序：best_turns 升序 → 第一名 turn_count 最小。
    assert data['leaderboard'][0]['username'] == 'winner0'
    assert data['leaderboard'][0]['best_turns'] == 5
    assert data['leaderboard'][0]['status'] == 'win'

    # 第二页。
    resp2 = client.get('/games/circle-cat/leaderboard?page=2&limit=2')
    data2 = resp2.get_json()
    assert data2['page'] == 2
    assert len(data2['leaderboard']) == 1


def test_leaderboard_defaults_when_no_params(client):
    resp = client.get('/games/circle-cat/leaderboard')
    data = resp.get_json()
    assert data['success'] is True
    assert data['page'] == 1
    assert data['limit'] == 10
    assert data['total'] == 0
    assert data['leaderboard'] == []


# --------------------------- result ---------------------------

def test_result_requires_login(client):
    resp = client.post('/games/circle-cat/result',
                       json={'game_id': 'a' * 32, 'moves': []})
    assert resp.status_code == 401
    data = resp.get_json()
    assert data['success'] is False
    assert data['message'] == '未登录，无法记录成绩。'
    # 401 时仍带 leaderboard 字段。
    assert 'leaderboard' in data


def test_result_non_hex_game_id_400(client, login):
    h.make_user('catbadid')
    login('catbadid')
    # 长度不等于 32 → 400。
    resp = client.post('/games/circle-cat/result',
                       json={'game_id': 'short', 'moves': []})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
    assert data['message'] == '无效的对局标识。'


def test_result_other_users_game_403(client, login):
    owner = 'catowner'
    other = 'catother'
    h.make_user(owner)
    h.make_user(other)
    game_id = uuid.uuid4().hex
    _insert_game(game_id, owner, 7, [], {'row': 3, 'col': 3})

    login(other)
    resp = client.post('/games/circle-cat/result',
                       json={'game_id': game_id, 'moves': []})
    assert resp.status_code == 403
    data = resp.get_json()
    assert data['success'] is False
    assert data['message'] == '无权提交该对局结果。'


def test_result_finished_game_409(client, login):
    h.make_user('catdone')
    game_id = uuid.uuid4().hex
    _insert_game(game_id, 'catdone', 7, [], {'row': 3, 'col': 3},
                 is_finished=1)

    login('catdone')
    resp = client.post('/games/circle-cat/result',
                       json={'game_id': game_id, 'moves': []})
    assert resp.status_code == 409
    data = resp.get_json()
    assert data['success'] is False
    assert data['message'] == '该对局结果已提交。'


def test_result_game_not_found_404(client, login):
    h.make_user('catnogame')
    login('catnogame')
    resp = client.post('/games/circle-cat/result',
                       json={'game_id': uuid.uuid4().hex, 'moves': []})
    assert resp.status_code == 404
    data = resp.get_json()
    assert data['success'] is False
    assert data['message'] == '对局不存在。'


def test_result_valid_win_records_and_returns_leaderboard(client, login):
    username = 'catwinner'
    h.make_user(username)
    game_id, moves = _make_solvable_game(username, board_size=7)

    login(username)
    resp = client.post('/games/circle-cat/result',
                       json={'game_id': game_id, 'moves': moves})
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()
    assert data['success'] is True
    assert data['state'] == 'win'
    assert isinstance(data['turn_count'], int) and data['turn_count'] >= 1
    assert 'leaderboard' in data

    # 记录入库：circle_cat_records 有该用户的 win 行。
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT turn_count, is_win FROM circle_cat_records "
                "WHERE username=%s", (username,))
            rec = cur.fetchone()
            cur.execute(
                "SELECT is_finished FROM circle_cat_games WHERE game_id=%s",
                (game_id,))
            game = cur.fetchone()
    finally:
        conn.close()
    assert rec is not None
    assert int(rec['is_win']) == 1
    assert int(rec['turn_count']) == data['turn_count']
    # 对局被标记为已结束。
    assert int(game['is_finished']) == 1

    # 该用户应出现在 leaderboard 中。
    winners = [r['username'] for r in data['leaderboard']]
    assert username in winners


def test_result_replay_already_submitted_is_idempotent_block(client, login):
    """合法 win 提交后，再次提交同一 game_id 应被 409（已提交）拦截。"""
    username = 'catonce'
    h.make_user(username)
    game_id, moves = _make_solvable_game(username, board_size=7)

    login(username)
    first = client.post('/games/circle-cat/result',
                        json={'game_id': game_id, 'moves': moves})
    assert first.status_code == 200

    second = client.post('/games/circle-cat/result',
                         json={'game_id': game_id, 'moves': moves})
    assert second.status_code == 409
    assert second.get_json()['message'] == '该对局结果已提交。'
