# -*- coding: utf-8 -*-
"""Task 18 — 围猫游戏回放校验逻辑单测。

被测：oj_modules.routes.game_routes._replay_circle_cat_game（纯函数，无 DB/Redis）。

棋盘几何（读源码确认）：
- 偶数行邻居方向 _EVEN_ROW_DIRS = [(-1,-1),(-1,0),(0,-1),(0,1),(1,-1),(1,0)]
- 奇数行邻居方向 _ODD_ROW_DIRS  = [(-1,0),(-1,1),(0,-1),(0,1),(1,0),(1,1)]
- 边界 = row/col 为 0 或 n-1。
- 胜（win）= 猫被封死（到边界无路）或落子后猫无空邻居；负（lose）= 猫走到边界。

所有棋盘/走子序列均按 board_size=5 构造，并已对照源码逐步推演验证为可判定。
不需要任何 fixture——纯函数测试；但 import 走 game_routes（依赖 flask + db_services
可 import，不建连接），与套件其余测试共享 conftest 的 sys.path 设置。
"""
import pytest

from oj_modules.routes import game_routes as gr


# board_size=5，猫居中 (2,2)（偶数行）。其 6 个邻居：
#   (1,1),(1,2),(2,1),(2,3),(3,1),(3,2) —— 均非边界格。
BOARD = 5
CENTER_CAT = {'row': 2, 'col': 2}

# WIN：预先封死猫 6 个邻居中的 5 个，仅留 (3,2) 开放；
# 一手落在 (3,2) → 猫被完全包围、到边界无路 → 第 1 手即 win。
WIN_BLOCKED = [[1, 1], [1, 2], [2, 1], [2, 3], [3, 1]]
WIN_MOVES = [{'row': 3, 'col': 2}]


def test_win_seals_cat_state_win_and_finished():
    """合法 win 回放 → success/finished True，state == 'win'，turn_count == 1。"""
    result = gr._replay_circle_cat_game(
        board_size=BOARD,
        blocked_positions=[list(p) for p in WIN_BLOCKED],
        cat_pos=dict(CENTER_CAT),
        moves=[dict(m) for m in WIN_MOVES],
    )
    assert result['success'] is True
    assert result['finished'] is True
    assert result['state'] == 'win'
    assert result['turn_count'] == 1


def test_cat_reaches_edge_state_lose():
    """猫贴近边界，一手不封死它 → 猫走到边界 → state == 'lose'。

    猫放在 (2,1)：其邻居含多个边界格 (1,0)/(2,0)/(3,0)。
    一手落在远处 (4,4)（不封死猫），猫沿最短路一步抵边 → 第 1 手即 lose。
    """
    result = gr._replay_circle_cat_game(
        board_size=BOARD,
        blocked_positions=[],
        cat_pos={'row': 2, 'col': 1},
        moves=[{'row': 4, 'col': 4}],
    )
    assert result['success'] is True
    assert result['finished'] is True
    assert result['state'] == 'lose'
    assert result['turn_count'] == 1


@pytest.mark.parametrize('bad_move', [
    {'row': 1, 'col': 1},  # 落在已 blocked 的格
    {'row': 2, 'col': 2},  # 落在猫所在格
])
def test_move_on_blocked_or_cat_rejected(bad_move):
    """落子在 blocked 格或猫位 → success False，文案“落子序列非法。”。"""
    result = gr._replay_circle_cat_game(
        board_size=BOARD,
        blocked_positions=[list(p) for p in WIN_BLOCKED],
        cat_pos=dict(CENTER_CAT),
        moves=[bad_move],
    )
    assert result['success'] is False
    assert result['message'] == '落子序列非法。'


def test_extra_move_after_win_rejected():
    """对局已 win 后仍有多余落子 → 拒绝，文案“对局结束后存在额外落子。”。"""
    moves = [dict(m) for m in WIN_MOVES] + [{'row': 0, 'col': 0}]
    result = gr._replay_circle_cat_game(
        board_size=BOARD,
        blocked_positions=[list(p) for p in WIN_BLOCKED],
        cat_pos=dict(CENTER_CAT),
        moves=moves,
    )
    assert result['success'] is False
    assert result['message'] == '对局结束后存在额外落子。'


def test_extra_move_after_lose_rejected():
    """对局已 lose 后仍有多余落子 → 拒绝（同一“额外落子”分支）。"""
    result = gr._replay_circle_cat_game(
        board_size=BOARD,
        blocked_positions=[],
        cat_pos={'row': 2, 'col': 1},
        moves=[{'row': 4, 'col': 4}, {'row': 0, 'col': 0}],
    )
    assert result['success'] is False
    assert result['message'] == '对局结束后存在额外落子。'


def test_game_not_finished_returns_failure():
    """单手落在角落、既不封死猫也不让猫抵边 → 对局未结束 → success False。"""
    result = gr._replay_circle_cat_game(
        board_size=BOARD,
        blocked_positions=[],
        cat_pos=dict(CENTER_CAT),
        moves=[{'row': 0, 'col': 0}],
    )
    assert result['success'] is False
    assert result['message'] == '对局尚未结束。'


@pytest.mark.parametrize('bad_blocked, label', [
    ([[2, 2]], 'on-cat'),          # blocked 落在猫位
    ([[1, 1], [1, 1]], 'dup'),     # blocked 重复
    ([[-1, 0]], 'oob-low'),        # blocked 越界（负）
    ([[BOARD, 0]], 'oob-high'),    # blocked 越界（超上界）
])
def test_illegal_initial_board_rejected(bad_blocked, label):
    """初始 blocked 非法（猫位/重复/越界）→ success False，文案“初始棋盘非法。”。"""
    result = gr._replay_circle_cat_game(
        board_size=BOARD,
        blocked_positions=bad_blocked,
        cat_pos=dict(CENTER_CAT),
        moves=[{'row': 3, 'col': 2}],
    )
    assert result['success'] is False
    assert result['message'] == '初始棋盘非法。'
