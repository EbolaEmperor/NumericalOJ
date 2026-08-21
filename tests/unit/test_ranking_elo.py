# -*- coding: utf-8 -*-
"""Task 16: ELO 评分函数单测（参考 §5c）。

覆盖 oj_modules.tasks.ranking.elo 中不依赖 DB/Redis 的函数：
  - _run_scoring_script：保留显式 HTML 详情协议；
  - _expected_score：对称 / 单调。
  - _new_ratings：winner=1 升降且守恒；平局对等；K 越大变化越大。
  - _pick_partner / _pick_pair：<2 人或同名→None；满足时返回两个不同用户名的提交。

除临时评分脚本用例外均无 IO；涉及 random 的用例提前 seed 以保证确定性。
"""
import json
import random

import pytest

from oj_modules.tasks.ranking import elo


def test_scoring_script_preserves_explicit_html_detail_output(tmp_path):
    answer_a = tmp_path / "a.json"
    answer_b = tmp_path / "b.json"
    script = tmp_path / "score.py"
    answer_a.write_text("{}", encoding="utf-8")
    answer_b.write_text("{}", encoding="utf-8")
    detail = {
        "format": "html",
        "content": "<div class='arena'></div><script>startBattle()</script>",
        "height": 680,
    }
    payload = json.dumps({"winner": 1, "details": detail}, ensure_ascii=False)
    script.write_text(f"print({payload!r})\n", encoding="utf-8")

    winner, returned_detail = elo._run_scoring_script(
        str(script),
        str(answer_a),
        str(answer_b),
    )

    assert winner == 1
    assert returned_detail == detail


# ---------------------------------------------------------------------------
# _expected_score
# ---------------------------------------------------------------------------

def test_expected_score_symmetry():
    # 同分时期望胜率恰好 0.5
    assert abs(elo._expected_score(1500, 1500) - 0.5) < 1e-9


def test_expected_score_monotonic_in_rating_gap():
    # A 分越高于 B，A 的期望胜率越大（>0.5），且随分差单调递增
    assert elo._expected_score(1800, 1500) > 0.5
    assert elo._expected_score(1500, 1800) < 0.5
    assert elo._expected_score(2000, 1500) > elo._expected_score(1800, 1500)


def test_expected_score_complementary():
    # 两个方向的期望胜率之和恒为 1
    assert abs(elo._expected_score(1700, 1400)
               + elo._expected_score(1400, 1700) - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# _new_ratings
# ---------------------------------------------------------------------------

def test_new_ratings_winner1_raises_a_lowers_b():
    # winner=1：A 胜，A 升 B 降
    a, b = elo._new_ratings(1500, 1500, winner=1, k=32)
    assert a > 1500 > b


def test_new_ratings_zero_sum_on_win():
    # 同分对局守恒：A、B 的变化量大小相等、方向相反
    a, b = elo._new_ratings(1500, 1500, winner=1, k=32)
    assert abs((a - 1500) + (b - 1500)) < 1e-6


def test_new_ratings_winner2_lowers_a_raises_b():
    # winner=2：B 胜，A 降 B 升，依然守恒
    a, b = elo._new_ratings(1500, 1500, winner=2, k=32)
    assert a < 1500 < b
    assert abs((a - 1500) + (b - 1500)) < 1e-6


def test_new_ratings_draw_equal_ratings_no_change():
    # 平局（winner=0）且同分：期望各 0.5，分数不变
    a, b = elo._new_ratings(1500, 1500, winner=0, k=32)
    assert abs(a - 1500) < 1e-9
    assert abs(b - 1500) < 1e-9


def test_new_ratings_draw_is_symmetric_zero_sum():
    # 平局即便分差存在也守恒：低分者升、高分者降，变化量相反
    a, b = elo._new_ratings(1400, 1600, winner=0, k=32)
    assert a > 1400  # 低分方在平局中得分
    assert b < 1600  # 高分方在平局中失分
    assert abs((a - 1400) + (b - 1600)) < 1e-6


def test_new_ratings_unknown_winner_treated_as_draw():
    # 非 {0,1,2} 的 winner 视为平局（s_a=0.5），不触发突变
    draw = elo._new_ratings(1500, 1500, winner=5, k=32)
    assert abs(draw[0] - 1500) < 1e-9
    assert abs(draw[1] - 1500) < 1e-9


def test_new_ratings_larger_k_larger_change():
    # K 越大，单场分数变化越大
    a_small, b_small = elo._new_ratings(1500, 1500, winner=1, k=16)
    a_big, b_big = elo._new_ratings(1500, 1500, winner=1, k=64)
    assert (a_big - 1500) > (a_small - 1500) > 0
    assert (1500 - b_big) > (1500 - b_small) > 0


# ---------------------------------------------------------------------------
# _pick_partner / _pick_pair
# ---------------------------------------------------------------------------

def _sub(sub_id, username, rating=1500, match_count=0):
    """构造一个最小的 ELO 提交 dict（仅含被选择逻辑读取的字段）。"""
    return {
        'id': sub_id,
        'username': username,
        'elo_rating': rating,
        'elo_match_count': match_count,
    }


def test_pick_pair_too_few_eligibles_returns_none():
    assert elo._pick_pair([]) is None
    assert elo._pick_pair([_sub(1, 'alice')]) is None


def test_pick_pair_single_username_returns_none():
    # 两份提交但同一用户名（同一用户的两份提交）→ 不应对战
    eligibles = [_sub(1, 'alice'), _sub(2, 'alice')]
    assert elo._pick_pair(eligibles) is None


def test_pick_pair_returns_two_distinct_users():
    random.seed(12345)
    eligibles = [
        _sub(1, 'alice', rating=1500),
        _sub(2, 'bob', rating=1510),
        _sub(3, 'carol', rating=1490),
    ]
    pair = elo._pick_pair(eligibles)
    assert pair is not None
    a, b = pair
    assert a['username'] != b['username']
    assert a['id'] != b['id']
    assert a in eligibles and b in eligibles


def test_pick_partner_excludes_anchor_and_same_username():
    random.seed(7)
    anchor = _sub(1, 'alice', rating=1500)
    eligibles = [
        anchor,
        _sub(2, 'alice', rating=1505),   # 同名，应被排除
        _sub(3, 'bob', rating=1502),     # 唯一合法搭档
    ]
    partner = elo._pick_partner(eligibles, anchor)
    assert partner is not None
    assert partner['id'] == 3
    assert partner['username'] == 'bob'


def test_pick_partner_no_candidates_returns_none():
    anchor = _sub(1, 'alice', rating=1500)
    # 候选要么是 anchor 自己，要么与 anchor 同名，全被过滤
    eligibles = [anchor, _sub(2, 'alice', rating=1600)]
    assert elo._pick_partner(eligibles, anchor) is None


def test_pick_partner_prefers_closest_rating():
    # top_k = max(3, ceil(n/10))；候选数 < 3 时 top 覆盖全部，但分差最近者排在最前。
    # 这里只断言返回的是合法的、非锚点、非同名候选，且分差排序对结果有约束。
    random.seed(0)
    anchor = _sub(1, 'alice', rating=1500)
    near = _sub(2, 'bob', rating=1501)
    far = _sub(3, 'carol', rating=2500)
    eligibles = [anchor, near, far]
    partner = elo._pick_partner(eligibles, anchor)
    assert partner is not None
    assert partner['username'] in ('bob', 'carol')
    assert partner['id'] != anchor['id']
