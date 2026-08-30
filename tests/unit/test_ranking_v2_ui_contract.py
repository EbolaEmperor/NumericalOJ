"""打榜赛 UI-v2 的静态结构契约。"""

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "backend" / "templates" / "ranking"
STATIC = ROOT / "frontend" / "public" / "static" / "app" / "ranking"
SORA_STATIC = ROOT / "frontend" / "public" / "static" / "vendor" / "sora"
ROUTES = ROOT / "backend" / "oj_modules" / "routes"


def _read(path):
    return path.read_text(encoding="utf-8")


def test_ranking_list_preserves_original_card_structure_and_visual_rules():
    template = _read(TEMPLATES / "list.html")

    assert "<p>RANKING · LIST</p>" in template
    assert '<h1 id="rankingListTitle">打榜赛</h1>' in template
    assert "{{ competitions|length }} COMPETITIONS · {{ list_counts.active }} ACTIVE" in template
    assert "font: 700 9.5px/1.2" in template
    assert "font-size: 23px" in template
    assert "font: 10px/1.3" in template
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
    assert "ranking.ranking_create" in template
    assert "ranking.ranking_copy" in template
    assert 'type="submit" class="ranking-card-copy"' in template


def test_ranking_detail_uses_v2_shell_and_real_navigation_state():
    template = _read(TEMPLATES / "detail.html")
    stylesheet = _read(STATIC / "detail-v2.css")
    script = _read(STATIC / "detail-v2.js")

    assert "ranking-detail-v2 ranking-v2-detail" in template
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
    assert "cache.delete('batch_eval')" in script
    assert "当前页面有尚未保存的修改，确认离开吗？" in script


def test_ranking_detail_self_hosts_sora_font():
    template = _read(TEMPLATES / "detail.html")
    sora_stylesheet = _read(SORA_STATIC / "sora.css")

    assert "vendor/sora/sora.css" in template
    assert "fonts.googleapis.com" not in template
    assert "fonts.gstatic.com" not in template
    assert 'font-family: "Sora"' in sora_stylesheet
    assert "font-weight: 400 700" in sora_stylesheet
    assert 'url("./sora-latin.woff2")' in sora_stylesheet
    assert 'url("./sora-latin-ext.woff2")' in sora_stylesheet
    assert (SORA_STATIC / "sora-latin.woff2").read_bytes()[:4] == b"wOF2"
    assert (SORA_STATIC / "sora-latin-ext.woff2").read_bytes()[:4] == b"wOF2"
    assert "SIL OPEN FONT LICENSE" in _read(SORA_STATIC / "OFL.txt")


def test_ranking_content_scroll_does_not_trap_panel_modals_under_backdrop():
    stylesheet = _read(STATIC / "detail-v2.css")
    rules_panel = _read(TEMPLATES / "settings" / "rules_panel.html")
    endpoint_pool = _read(TEMPLATES / "settings" / "endpoint_pool.html")

    content_scroll_rules = re.findall(
        r"\.ranking-content-scroll\s*\{(?P<body>[^}]*)\}", stylesheet
    )
    assert content_scroll_rules
    content_scroll_rules = "\n".join(content_scroll_rules)

    # 这些弹窗位于滚动容器内，而 Bootstrap 的 backdrop 直接挂到 body。
    # 容器不能创建 stacking context 或 fixed containing block，否则 backdrop
    # 会盖住弹窗并拦截整个页面的交互。
    assert 'id="ajRuleModal"' in rules_panel
    assert 'id="ajeEditModal"' in endpoint_pool


def test_ranking_dirty_guard_only_tracks_persisted_scopes():
    detail_script = _read(STATIC / "detail-v2.js")
    rules_script = _read(STATIC / "rules-editor.js")
    endpoints_script = _read(STATIC / "endpoints.js")
    rules_panel = _read(TEMPLATES / "settings" / "rules_panel.html")
    endpoint_pool = _read(TEMPLATES / "settings" / "endpoint_pool.html")

    assert "control.closest('.modal, [data-ranking-dirty-managed]')" in detail_script
    assert "control.type !== 'hidden'" in detail_script
    assert "control.form.id === 'rankingEditForm'" in detail_script
    assert '[data-ranking-dirty-managed][data-ranking-dirty="true"]' in detail_script
    assert "window.addEventListener('ranking:dirty-state-change'" in detail_script

    assert 'data-ranking-dirty-managed data-ranking-dirty="false"' in rules_panel
    assert endpoint_pool.count(
        'data-ranking-dirty-managed data-ranking-dirty="false"'
    ) == 2

    assert "var submittedSignature = rulesSignature();" in rules_script
    assert "savedRulesSignature = submittedSignature;" in rules_script
    assert "rulesSignature() !== savedRulesSignature" in rules_script
    assert "source: 'judge-rules'" in rules_script

    assert "endpointDirtyState(manager)" in endpoints_script
    assert "var submittedSignature = managerSignature(manager);" in endpoints_script
    assert "managerSignature(manager) !== submittedSignature" in endpoints_script
    assert "manager.savedSignature = managerSignature(manager);" in endpoints_script
    assert "managerSignature(manager) !== manager.savedSignature" in endpoints_script
    assert "source:'primary-endpoints'" in endpoints_script
    assert "source:'quality-gate'" in endpoints_script


def test_ranking_detail_function_rail_matches_global_sidebar_type_scale():
    stylesheet = _read(STATIC / "detail-v2.css")

    assert "font: 500 9.5px/1.5 var(--ranking-v2-mono)" in stylesheet
    assert "font-size: 13px" in stylesheet
    assert "font: 10.5px/1 var(--ranking-v2-mono)" in stylesheet
    assert "font-size: 11.5px" in stylesheet


def test_ranking_mobile_function_rail_aligns_and_matches_global_drawer_width():
    stylesheet = _read(STATIC / "detail-v2.css")
    mobile = stylesheet[
        stylesheet.index("@media (max-width: 991.98px)") : stylesheet.index(
            "@media (max-width: 620px)"
        )
    ]

    assert "padding: 13px 15px" in mobile
    assert "justify-self: end" in mobile
    assert "width: var(--numoj-mobile-sidebar-width)" in mobile


def test_elo_match_cards_fit_mobile_and_open_from_the_whole_card():
    component = _read(TEMPLATES / "components" / "matches.html")
    stylesheet = _read(STATIC / "content-v2.css")
    mobile = stylesheet[stylesheet.index("@media (max-width: 760px)") :]
    match_styles = stylesheet[
        stylesheet.index("/* Matches */") : stylesheet.index(
            "/* Submission/appeal shared cards */"
        )
    ]

    assert 'class="match-detail-btn"' in component
    assert 'aria-label="查看 {{ name_a }} 对阵 {{ name_b }} 的对战详情"' in component
    assert 'class="match-detail-label" aria-hidden="true"' in component
    assert "position: absolute" in stylesheet
    assert "inset: 0" in stylesheet
    assert "padding: 0 14px 0 18px" in stylesheet
    assert "overflow-x: hidden" in mobile
    assert "min-width: 0" in mobile
    assert 'grid-template-areas: "time side-a versus side-b action"' in mobile
    assert "height: 64px" in mobile
    assert "grid-template-columns: 43px minmax(0, 1fr) 26px minmax(0, 1fr) auto" in mobile
    assert "gap: 6px" in mobile
    assert "padding: 8px 10px 26px" in mobile
    assert "padding: 0 7px 0 0" in mobile
    assert "justify-content: stretch" in mobile
    assert "justify-items: end" in mobile
    assert ".ranking-v2-detail .match-avatar" in mobile
    assert "display: none" in mobile
    assert "linear-gradient" not in match_styles
    assert "background: #f6f5f2" not in mobile


def test_elo_match_cards_remove_mine_rail_and_align_you_badges_on_both_sides():
    detail = _read(TEMPLATES / "detail.html")
    component = _read(TEMPLATES / "components" / "matches.html")
    stylesheet = _read(STATIC / "content-v2.css")

    assert ".match-row.is-mine::after" not in detail

    side_a = component[component.index("match-side-a") : component.index("match-vs")]
    side_b = component[component.index("match-side-b") : component.index("match-action")]
    assert side_a.index("{{ name_a }}") < side_a.index("is_me_a")
    assert side_b.index("is_me_b") < side_b.index("{{ name_b }}")

    tag_rule = re.search(
        r"\.ranking-v2-detail \.match-me-tag\s*\{(?P<body>[^{}]+)\}",
        stylesheet,
    )
    assert tag_rule is not None
    tag_body = tag_rule.group("body")
    assert "display: inline-flex" in tag_body
    assert "align-items: center" in tag_body
    assert "justify-content: center" in tag_body
    assert "background: var(--rkv2-orange)" in tag_body
    assert "color: #fff" in tag_body
    assert "text-align: center" in tag_body


def test_mobile_leaderboard_uses_compact_full_width_rows_and_existing_model_logos():
    template = _read(TEMPLATES / "tabs" / "leaderboard.html")
    stylesheet = _read(STATIC / "content-v2.css")
    mobile = stylesheet[stylesheet.index("@media (max-width: 760px)") :]
    leaderboard_start = mobile.index(
        ".ranking-detail-v2.ranking-v2-detail .ranking-v2-leaderboard {"
    )
    leaderboard_end = mobile.index(
        ".ranking-v2-detail .matches-head", leaderboard_start
    )
    leaderboard_mobile = mobile[leaderboard_start:leaderboard_end]

    assert "{{ model_logo(row.best_base_model) }}" in template
    model_region = template[
        template.index("{% if row.best_base_model %}") : template.index(
            "{% if row.best_agent_endpoint_label %}"
        )
    ]
    assert model_region.index("model_logo(row.best_base_model)") < model_region.index(
        "{{ row.best_base_model }}"
    )

    assert "overflow-x: hidden" in leaderboard_mobile
    assert "min-width: 0" in leaderboard_mobile
    assert "grid-template-columns: 27px minmax(0, 1fr) 55px" in leaderboard_mobile
    assert "height: 58px" in leaderboard_mobile
    assert leaderboard_mobile.count("grid-area: auto") == 3
    assert "align-self: center" in leaderboard_mobile
    assert "position: absolute" in leaderboard_mobile
    assert "height: 2px" in leaderboard_mobile
    assert "linear-gradient" not in leaderboard_mobile


def test_elo_admin_rebuild_control_stays_inline_and_keeps_its_hover_icon():
    detail = _read(TEMPLATES / "detail.html")
    stylesheet = _read(STATIC / "content-v2.css")
    mobile = stylesheet[stylesheet.index("@media (max-width: 760px)") :]

    assert ".matches-rebuild-btn:hover i { color: inherit; }" in detail
    assert ".ranking-v2-detail .matches-rebuild-btn:hover i" in stylesheet
    assert "align-items: center" in mobile
    assert "flex-direction: row" in mobile
    assert "flex-wrap: nowrap" in mobile
    assert "width: auto" in mobile
    assert "margin-left: auto" in mobile


def test_elo_trajectory_viewer_is_public_fragment_safe_and_uses_one_color_family():
    detail = _read(TEMPLATES / "detail.html")
    matches = _read(TEMPLATES / "tabs" / "matches.html")
    content_styles = _read(STATIC / "content-v2.css")
    detail_script = _read(STATIC / "detail-v2.js")
    trajectory_script = _read(STATIC / "elo-trajectories.js")
    trajectory_styles = _read(STATIC / "elo-trajectories.css")

    observe_index = matches.index('class="matches-rebuild-btn matches-observe-btn"')
    admin_guard_index = matches.index('{% if is_admin and matches %}', observe_index)
    rebuild_index = matches.index('class="matches-rebuild-form"', admin_guard_index)
    assert observe_index < admin_guard_index < rebuild_index
    assert 'data-bs-target="#eloTrajectoryModal"' in matches
    assert '<div class="modal-dialog">' in matches
    assert 'data-elo-search-input' in matches
    assert 'placeholder="按用户名筛选…"' in matches
    assert 'data-elo-selected-list' in matches
    assert 'elo-observer-selected-panel' not in matches
    assert 'data-elo-clear-selection' not in matches
    assert 'data-elo-selection-count' not in matches
    assert 'data-elo-analyze' in matches
    assert 'data-elo-chart' in matches
    assert "ranking.ranking_elo_trajectory_submissions" in matches
    assert "ranking.ranking_elo_trajectory" in matches
    assert "ELO TRAJECTORY" not in matches
    assert "选择当前仍在役的提交" not in matches
    assert "支持 username 模糊匹配" not in matches
    assert ">01<" not in matches
    assert ">02<" not in matches
    assert "03 · ANALYSIS" not in matches
    assert 'id="eloObserverSearchLabel"' not in matches
    assert 'id="eloObserverSelectedLabel"' not in matches
    assert 'id="eloTrajectoryChartTitle"' not in matches
    assert ">查找提交<" not in matches
    assert ">已选提交<" not in matches
    assert ">得分轨迹<" not in matches

    assert "app/ranking/elo-trajectories.css" in detail
    assert "app/ranking/elo-trajectories.js" in detail
    assert "window.EloTrajectoryViewer.init(root)" in detail_script
    assert "root.querySelectorAll('[data-elo-trajectory-viewer]').forEach(initViewer)" in trajectory_script
    assert "new Map()" in trajectory_script
    assert "clearButton" not in trajectory_script
    assert "selectionCount" not in trajectory_script
    assert "body: JSON.stringify({submission_ids: Array.from(selected.keys())})" in trajectory_script
    assert "modal.classList.add('is-expanded')" in trajectory_script
    assert "modal.classList.remove('is-expanded')" in trajectory_script
    assert "analysisController.abort()" in trajectory_script
    assert "searchInput.focus()" not in trajectory_script
    assert "document.createElementNS(SVG_NS, tag)" in trajectory_script
    assert "hsl(207 55%" in trajectory_script
    assert "var start = 18" in trajectory_script
    assert "var end = count <= 1 ? 42 : 72" in trajectory_script
    assert "document.activeElement === searchInput" in trajectory_script
    assert "searchInput.addEventListener('blur'" in trajectory_script
    assert "searchResults.addEventListener('pointerdown'" in trajectory_script
    assert "Math.floor(chartShell.clientWidth || viewer.clientWidth || 760)" in trajectory_script
    assert "svg.style.width = '100%'" in trajectory_script
    assert "new ResizeObserver(scheduleChartResize).observe(chartShell)" in trajectory_script
    assert "result.hidden = false;\n        renderChart(seriesList);" in trajectory_script
    assert "function axisDayKey(point)" in trajectory_script
    assert "function axisTimeText(point, showDate)" in trajectory_script
    assert "showDate ? value.slice(5, 16) : value.slice(11, 16)" in trajectory_script
    assert "tickDay !== lastTickDay" in trajectory_script
    assert "sequence === maxSequence ? 'end' : 'middle'" in trajectory_script
    assert "var linePoints = points.filter" in trajectory_script
    assert "return pointIndex === 0 || point.participated" in trajectory_script
    assert "var pathData = linePoints.map" in trajectory_script
    assert "return (pointIndex ? 'L' : 'M') + pointX + ' ' + pointY" in trajectory_script
    assert "'H' + pointX + ' V'" not in trajectory_script
    assert "if (!point.participated) return;" in trajectory_script
    assert "条对战记录 · 当前" not in trajectory_script
    assert "setSearchNote('', false)" in trajectory_script
    assert "找到 ' + currentResults.length" not in trajectory_script
    assert "elo-trajectory-legend-copy" in trajectory_script
    assert ".elo-trajectory-legend-copy" in trajectory_styles
    assert "font: 700 10px/1 var(--rkv2-mono)" in trajectory_styles
    assert ".elo-trajectory-line" in trajectory_styles
    assert "--elo-accent: var(--rkv2-orange)" in trajectory_styles
    assert "--elo-accent-soft: var(--rkv2-orange-soft)" in trajectory_styles
    assert "--elo-surface-soft: var(--rkv2-line-soft)" in trajectory_styles
    assert "background: var(--elo-surface-soft)" in trajectory_styles
    assert "--elo-blue" not in trajectory_styles
    assert ".matches-observe-btn i" not in trajectory_styles
    assert "min-height: 30px" in re.search(
        r"\.ranking-v2-detail \.matches-meta\s*\{(?P<body>[^{}]+)\}",
        content_styles,
    ).group("body")
    assert "font: 9px/1 var(--rkv2-mono)" in content_styles
    assert "line-height: 1" in re.search(
        r"\.ranking-v2-detail \.matches-rebuild-btn\s*\{(?P<body>[^{}]+)\}",
        content_styles,
    ).group("body")
    assert "width: min(414px, calc(100vw - 28px))" in trajectory_styles
    assert ".elo-trajectory-modal.is-expanded .modal-dialog" in trajectory_styles
    assert "width: 67vw" in trajectory_styles
    assert "margin: clamp(72px, 14vh, 132px) auto 28px" in trajectory_styles
    assert "margin: 28px auto" in trajectory_styles
    assert ".elo-trajectory-modal.is-expanded .modal-dialog {\n    width: calc(100vw - 16px)" in trajectory_styles
    assert "overflow: visible" in trajectory_styles
    assert "border-radius: 8px 8px 0 0" in trajectory_styles
    assert "border-radius: 0 0 8px 8px" in trajectory_styles
    assert "grid-template-columns: minmax(0, 1fr)" in trajectory_styles
    assert "flex-wrap: wrap" in trajectory_styles
    assert "overflow-x: auto" not in trajectory_styles
    assert "max-width: min(240px, 100%)" in trajectory_styles
    assert ".elo-observer-strip-actions" not in trajectory_styles
    assert ".elo-observer-selection-count" not in trajectory_styles
    assert ".elo-observer-selected-panel" not in trajectory_styles
    result_rule = re.search(
        r"\.ranking-v2-detail \.elo-trajectory-result\s*\{(?P<body>[^{}]+)\}",
        trajectory_styles,
    )
    assert result_rule is not None
    assert "border-top" not in result_rule.group("body")
    assert "margin-top: 6px" in result_rule.group("body")
    assert "padding-top: 0" in result_rule.group("body")
    footer_rule = re.search(
        r"\.ranking-v2-detail \.elo-trajectory-footer\s*\{(?P<body>[^{}]+)\}",
        trajectory_styles,
    )
    assert footer_rule is not None
    assert "border-top: 0" in footer_rule.group("body")
    assert "background: #fff" in footer_rule.group("body")
    chart_shell = re.search(
        r"\.ranking-v2-detail \.elo-trajectory-chart-shell\s*\{(?P<body>[^{}]+)\}",
        trajectory_styles,
    )
    assert chart_shell is not None
    assert "overflow: hidden" in chart_shell.group("body")


def test_harness_logos_follow_selected_endpoints_across_ranking_surfaces():
    detail = _read(TEMPLATES / "detail.html")
    submit = _read(TEMPLATES / "tabs" / "submit.html")
    batch = _read(TEMPLATES / "tabs" / "batch_evaluate.html")
    card = _read(TEMPLATES / "components" / "submission_card.html")
    leaderboard = _read(TEMPLATES / "tabs" / "leaderboard.html")
    choice_picker = _read(ROOT / "frontend" / "public" / "static" / "app" / "choice-picker.js")

    assert "app/ranking/harness-logos.css" in detail
    assert 'data-choice-icon="{{ harness_logo_class(ep.harness) }}"' in submit
    assert 'data-choice-icon="{{ harness_logo_class(ep.harness) }}"' in batch
    assert "harness_logo(s.agent_endpoint_harness)" in card
    assert "harness_logo(row.best_agent_endpoint_harness)" in leaderboard
    assert "icon.className = 'fas ' +" in choice_picker
    assert "selected.getAttribute('data-choice-icon')" in choice_picker

    bound_harness_regions = "\n".join((submit, batch, card, leaderboard))


def test_leaderboard_shows_identicon_avatar_and_best_harness_identity():
    template = _read(TEMPLATES / "tabs" / "leaderboard.html")
    stylesheet = _read(STATIC / "detail-v2.css")
    script = _read(STATIC / "detail-v2.js")

    assert 'class="numoj-avatar lb-avatar"' in template
    assert 'role="img"' in template
    assert 'data-avatar-seed="{{ row.username or \'numericaloj\' }}"' in template
    assert 'class="lb-harness"' in template
    assert "row.best_agent_endpoint_label" in template
    assert ".ranking-v2-leaderboard .lb-avatar" in stylesheet
    assert "grid-template-columns: repeat(8, 1fr);" in stylesheet
    assert ".ranking-v2-leaderboard .lb-harness" in stylesheet
    assert "paintIdenticons(root);" in script
    assert "paintIdenticons(oldBoard);" in script


def test_ranking_description_keeps_accepted_width_and_centers_it():
    stylesheet = _read(STATIC / "content-v2.css")

    assert "width: min(100%, 920px)" in stylesheet
    assert "margin: 0 auto" in stylesheet


def test_ranking_description_reuses_problem_detail_markdown_renderer():
    route = _read(ROUTES / "ranking_routes.py")
    template = _read(TEMPLATES / "detail.html")
    description = _read(TEMPLATES / "tabs" / "description.html")
    problem_template = _read(ROOT / "backend" / "templates" / "problems" / "detail.html")
    shared_stylesheet = _read(ROOT / "frontend" / "public" / "static" / "app" / "markdown-rendering.css")
    layout_stylesheet = _read(ROOT / "frontend" / "public" / "static" / "app" / "layout.css")
    stylesheet = _read(STATIC / "detail-v2.css")

    presentation = _read(ROOT / "backend" / "oj_modules" / "ranking" / "presentation.py")
    assert "from backend.oj_modules.shared.markdown import render_rich_markdown" in presentation
    assert "return render_rich_markdown(text)" in presentation

    assert template.count("app/markdown-rendering.js") == 1
    assert "mathjax_lazy=true" in template
    mathjax_component = _read(
        ROOT / "backend" / "templates" / "components" / "layout" / "mathjax.html"
    )
    assert "app/rich-content-assets.js" in mathjax_component
    for lazy_asset in (
        "app/editor-semantic-tokens.js",
        "vendor/mermaid/mermaid.min.js",
        "vendor/shiki-markdown/highlighter.js",
    ):
        assert lazy_asset not in template
        assert lazy_asset in mathjax_component

    assert (
        "numoj-markdown numoj-problem-code-rendering ranking-description"
        in description
    )
    assert (
        "problem-content numoj-markdown numoj-problem-code-rendering my-3"
        in problem_template
    )
    assert ".numoj-problem-code-rendering pre {" in shared_stylesheet
    assert ".numoj-problem-code-rendering code {" in shared_stylesheet
    assert ".numoj-problem-code-rendering pre code {" in shared_stylesheet
    assert shared_stylesheet.index(
        ".numoj-problem-code-rendering pre {"
    ) < shared_stylesheet.index(".numoj-markdown .codehilite {")


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
    script = _read(STATIC / "detail-v2.js")
    stylesheet = _read(STATIC / "detail-v2.css")
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
    assert "tab === 'all_submissions' || tab === 'appeals'" in script
    assert "await refreshWholeTab(tab)" in script
    assert "requestHardReload()" in script
    assert "if (!hardReloadPending || isDirty()) return false" in script
    assert "data-ranking-refresh-blocked" in script
    assert "data-ranking-refresh-blocked" in submissions
    assert "ranking:refresh-resume" in script
    assert "ranking:refresh-resume" in submissions
    assert "ranking/tabs/settings.html" in panel
    assert 'data-selected-count="0"' in batch
    for source in (submissions, appeals, matches):
        assert "ranking:query-start" in source
        assert "ranking:query-commit" in source
        assert "ranking:query-settle" in source
        assert "new AbortController()" in source
        assert "}, 15000)" in source


def test_elo_match_detail_supports_text_and_networked_sandbox_html():
    matches = _read(TEMPLATES / "tabs" / "matches.html")
    settings = _read(TEMPLATES / "tabs" / "settings.html")
    stylesheet = _read(STATIC / "content-v2.css")
    routes = _read(ROUTES / "ranking_routes.py")

    assert 'id="matchDetailVerdict"' in matches
    assert 'id="matchDetailHtmlFrame"' in matches
    assert 'sandbox="allow-scripts"' in matches
    assert "allow-same-origin" not in matches
    assert 'referrerpolicy="no-referrer"' in matches
    assert "[buildHtmlDocument(output.content, readyToken, scaleHint)]" in matches
    assert "connect-src https: http: wss: ws:" in matches
    assert "script-src 'unsafe-inline' blob: https: http:" in matches
    assert "form-action 'none'" in matches
    assert "frame-src 'none'" in matches
    assert "window.URL.createObjectURL(new Blob(" in matches
    assert "window.URL.revokeObjectURL" in matches
    assert "htmlFrameEl.src = htmlFrameObjectUrl" in matches
    assert "htmlFrameEl.removeAttribute('srcdoc')" in matches
    assert "previousFrame.cloneNode(false)" in matches
    assert "previousFrame.replaceWith(htmlFrameEl)" in matches
    assert "currentFrame.src !== currentObjectUrl" in matches
    assert "htmlFrameEl.style.opacity" in matches
    assert "root.style.zoom" not in matches
    assert "htmlFrameEl.style.zoom" not in matches
    assert "htmlFrameEl.style.transform" not in matches
    assert "numoj:html-detail-viewport" not in matches
    assert 'data-numoj-viewport-fix' in matches
    assert 'data-numoj-embedded-scale' in matches
    assert 'transform:scale(' in matches
    assert 'Math.abs(scale-1)>=0.005' in matches
    assert "String(content || '') + viewportFix + '</body>" in matches
    assert "function safariHtmlFrameScaleHint()" in matches
    assert "window.outerWidth / window.innerWidth" in matches
    assert "Math.abs(nativeDpr - roundedDpr) > 0.03" in matches
    assert "!/(?:Chrome|Chromium|CriOS|Edg|OPR)\\//.test(ua)" in matches
    assert "var repaintObserver=new MutationObserver" in matches
    assert 'body.style.setProperty("visibility","hidden","important")' in matches
    assert "void body.offsetHeight" in matches
    assert "repaintObserver.observe(body,{subtree:true,childList:true,characterData:true})" in matches
    assert "numoj:html-detail-ready" in matches
    assert "event.source !== currentFrame.contentWindow" in matches
    assert "event.data.token !== readyToken" in matches
    assert "clearHtmlFrameReadyWait()" in matches
    assert matches.index("previousFrame.replaceWith(htmlFrameEl)") < matches.index(
        "htmlFrameEl.src = htmlFrameObjectUrl"
    )
    assert "htmlFrameEl.srcdoc =" not in matches
    assert "setHtmlFrameReady(false)" in matches
    assert "setHtmlFrameReady(true)" in matches
    assert "htmlFrameEl.style.visibility" in matches
    assert "htmlFrameEl.style.pointerEvents" in matches
    assert "matchDetailReplay" not in matches
    assert "detail_output" in routes
    assert "normalize_match_detail_output" in routes
    # 输出契约说明统一沉淀在 elo.md，编辑页不再重复展示。
    assert "elo-output-contract" not in settings
    assert "对战详情输出格式" not in settings
    elo_doc = _read(ROOT / "skills" / "numoj-admin" / "references" / "ranking-contests" / "elo.md")
    assert "details" in elo_doc and "format" in elo_doc and "content" in elo_doc
    assert ".match-detail-html iframe" in stylesheet


def test_ranking_ui_avoids_nonessential_interruptions():
    detail = _read(TEMPLATES / "detail.html")
    list_template = _read(TEMPLATES / "list.html")
    submit = _read(TEMPLATES / "tabs" / "submit.html")
    submissions = _read(TEMPLATES / "tabs" / "submissions.html")
    matches = _read(TEMPLATES / "tabs" / "matches.html")
    batch = _read(TEMPLATES / "tabs" / "batch_evaluate.html")
    appeal_review = _read(TEMPLATES / "appeal_review.html")
    detail_script = _read(STATIC / "detail-v2.js")
    detail_stylesheet = _read(STATIC / "detail-v2.css")
    content_stylesheet = _read(STATIC / "content-v2.css")
    endpoints_script = _read(STATIC / "endpoints.js")
    rules_script = _read(STATIC / "rules-editor.js")
    routes = _read(ROUTES / "ranking_routes.py")

    combined_frontend = "\n".join(
        (
            detail,
            list_template,
            submit,
            submissions,
            matches,
            batch,
            appeal_review,
            detail_script,
            endpoints_script,
            rules_script,
        )
    )

    # 本地草稿删除和批量重测 workflow 不再叠加第二层确认。

    # 例行成功由刷新后的真实页面状态自证，不再排入全局 flash box。
    route_tree = ast.parse(routes)
    success_flashes = [
        node
        for node in ast.walk(route_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "flash"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "success"
    ]
    assert not success_flashes
