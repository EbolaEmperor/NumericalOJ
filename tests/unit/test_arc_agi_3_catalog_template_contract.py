"""ARC-AGI-3 目录页说明与官方榜单快照契约。"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (ROOT / "templates" / "games" / "arc_agi_3" / "index.html").read_text(
    encoding="utf-8"
)
STYLESHEET = (ROOT / "static" / "app" / "arc-agi-3.css").read_text(
    encoding="utf-8"
)


def test_help_modal_contains_accessible_verified_top_five_snapshot():
    assert "modal-dialog-scrollable" in TEMPLATE
    assert '<section class="arc-leaderboard" aria-labelledby="arcLeaderboardTitle">' in TEMPLATE
    assert '<ol class="arc-leaderboard-list">' in TEMPLATE
    assert TEMPLATE.count('class="arc-leaderboard-entry') == 5

    rows = re.findall(
        r'<li class="arc-leaderboard-entry[^"]*">(.*?)</li>',
        TEMPLATE,
        flags=re.DOTALL,
    )
    expected_rows = (
        ("Claude Opus 5", "30.16"),
        ("GPT-5.6 Sol", "7.78"),
        ("GPT-5.6 Sol", "6.99"),
        ("GPT-5.6 Sol", "2.15"),
        ("Claude Opus 4.8", "1.52"),
    )
    assert len(rows) == len(expected_rows)
    for rank, (row, (model, score)) in enumerate(zip(rows, expected_rows), start=1):
        assert f'aria-label="第 {rank} 名"' in row
        assert model in row
        assert f"<strong>{score}</strong><small>%</small>" in row


def test_leaderboard_snapshot_explains_scope_source_and_cutoff():
    assert "不同推理档位作为独立榜单项" in TEMPLATE
    assert (
        '<time datetime="2026-07-24T17:57:13Z">'
        "2026 年 7 月 24 日 17:57 UTC</time>"
    ) in TEMPLATE
    assert 'href="https://arcprize.org/leaderboard"' in TEMPLATE
    assert 'href="https://arcprize.org/results/anthropic-claude-opus-5"' in TEMPLATE
    assert "Claude Opus 5（High）以 30.16% 刷新 ARC-AGI-3 官方纪录" in TEMPLATE
    assert "最高分模型是 GPT-5.6 Sol" not in TEMPLATE


def test_leaderboard_styles_cover_record_row_and_small_screens():
    assert ".arc-leaderboard-entry--record" in STYLESHEET
    assert ".arc-leaderboard-cutoff" in STYLESHEET
    assert "@media (max-width: 575.98px)" in STYLESHEET
