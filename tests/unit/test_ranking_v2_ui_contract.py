"""打榜赛 UI-v2 的静态结构契约。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "templates" / "ranking"
STATIC = ROOT / "static" / "app" / "ranking"


def _read(path):
    return path.read_text(encoding="utf-8")


def test_ranking_list_preserves_original_card_structure_and_visual_rules():
    template = _read(TEMPLATES / "list.html")

    assert "RANKING · LIST" not in template
    assert "list-v2.css" not in template
    assert 'class="row g-3 ranking-grid"' in template
    assert 'class="col-12 col-md-6 col-lg-4"' in template
    assert "fa-user-friends" in template
    assert "fa-paper-plane" in template
    assert "fa-chess-knight" in template
    assert "border-radius: 0.85rem" in template
    assert "border-color: #f5c518" in template
    assert "border-radius: 50%" in template


def test_ranking_list_keeps_admin_create_and_copy_actions():
    template = _read(TEMPLATES / "list.html")

    assert "newCompetitionModal" in template
    assert "copyCompetitionModal" in template
    assert "ranking.ranking_create" in template
    assert "ranking.ranking_copy" in template


def test_ranking_detail_uses_v2_shell_and_real_navigation_state():
    template = _read(TEMPLATES / "detail.html")
    stylesheet = _read(STATIC / "detail-v2.css")
    script = _read(STATIC / "detail-v2.js")

    assert "ranking-detail-v2 ranking-v2-detail" in template
    assert "FUNCTION RAIL" not in template
    assert 'data-ranking-detail-url=' in template
    assert 'data-ranking-navigation-url=' in template
    assert "detail-v2.css" in template
    assert "content-v2.css" in template
    assert "detail-v2.js" in template
    assert "'%03d'|format(competition.id)" in template
    assert template.index("ranking-competition-id") < template.index(
        "<h1>{{ competition.title }}</h1>"
    )
    assert "data-ranking-count=\"leaderboard\"" in template
    assert "data-ranking-count=\"matches\"" in template
    assert "data-ranking-count=\"all_submissions\"" in template
    assert "data-ranking-count=\"appeals\"" in template

    assert "grid-template-columns: minmax(0, 1fr) var(--ranking-v2-rail)" in stylesheet
    assert "@media (max-width: 991.98px)" in stylesheet
    assert "window.setTimeout(function ()" in script
    assert "}, 250);" in script
    assert "window.setInterval(pollNavigationState, 10000)" in script
    assert "document.hidden" in script
    assert "new AbortController()" in script
    assert "data-math-curve-loader" in script
    assert "duration: 420" in script
    assert "reducedMotion.matches" in script
    assert "renderContentEqual" in script
    assert "revisionGeneration" in script
    assert "ranking:query-start" in script
    assert "ranking:query-commit" in script
    assert "data-ranking-query-generation" in script
    assert "panelOwnsLocation(refreshNode, refreshUrl)" in script
    assert "setRailBackgroundInert" in script
    assert '[data-ranking-panel][data-ranking-tab="batch_eval"]' not in script
    assert "cache.delete('batch_eval')" in script
    assert "当前页面有尚未保存的修改，确认离开吗？" in script


def test_ranking_detail_function_rail_matches_global_sidebar_type_scale():
    stylesheet = _read(STATIC / "detail-v2.css")

    assert "font: 500 9.5px/1.5 var(--ranking-v2-mono)" in stylesheet
    assert "font-size: 13px" in stylesheet
    assert "font: 10.5px/1 var(--ranking-v2-mono)" in stylesheet
    assert "font-size: 11.5px" in stylesheet


def test_ranking_batch_layout_keeps_options_aligned_and_results_compact():
    stylesheet = _read(STATIC / "content-v2.css")
    template = _read(TEMPLATES / "tabs" / "batch_evaluate.html")

    assert "grid-template-columns: 30px minmax(0, 1fr) 22px" in stylesheet
    assert "min-height: 88px" in stylesheet
    assert "align-content: start" in stylesheet
    assert "wrap.isConnected" in template
    assert "new AbortController()" in template
    assert template.count("mathCurveLoader: false") == 3


def test_ranking_v2_tabs_keep_fragment_refresh_boundaries():
    leaderboard = _read(TEMPLATES / "tabs" / "leaderboard.html")
    submit = _read(TEMPLATES / "tabs" / "submit.html")
    submissions = _read(TEMPLATES / "tabs" / "submissions.html")
    appeals = _read(TEMPLATES / "tabs" / "appeals.html")
    panel = _read(TEMPLATES / "components" / "detail_panel.html")
    batch = _read(TEMPLATES / "tabs" / "batch_evaluate.html")
    matches = _read(TEMPLATES / "tabs" / "matches.html")

    assert "data-ranking-leaderboard" in leaderboard
    for marker in (
        "data-ranking-row",
        "data-ranking-user",
        "data-ranking-rank",
        "data-ranking-score",
    ):
        assert marker in leaderboard
    assert "data-ranking-current-user" in leaderboard
    assert "data-ranking-submission-history" in submit
    assert "s.elo_rating if is_elo else s.score" in submit
    assert submit.index("data-ranking-submission-history") < submit.index(
        "my-history-header"
    )
    assert 'data-ranking-update-slot="all_submissions"' in submissions
    assert 'data-ranking-update-slot="appeals"' in appeals
    assert "ranking/tabs/settings.html" in panel
    assert 'data-selected-count="0"' in batch
    for source in (submissions, appeals, matches):
        assert "ranking:query-start" in source
        assert "ranking:query-commit" in source
        assert "ranking:query-settle" in source
        assert "new AbortController()" in source
        assert "}, 15000)" in source
