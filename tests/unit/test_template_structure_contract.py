"""模板目录、引用关系与排名弹窗单一来源契约。"""

import ast
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, meta


ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "templates"


def _environment():
    environment = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
    environment.globals["url_for"] = lambda endpoint, **values: (
        f"/{endpoint}/{values.get('filename', '')}"
    )
    return environment


def _template_names(environment):
    return set(environment.list_templates(extensions=("html",)))


def test_template_root_contains_only_domain_directories():
    root_templates = sorted(path.name for path in TEMPLATES.glob("*.html"))
    assert root_templates == []


def test_all_jinja_templates_compile_and_static_references_exist():
    environment = _environment()
    names = _template_names(environment)
    assert names

    for name in sorted(names):
        source, _, _ = environment.loader.get_source(environment, name)
        parsed = environment.parse(source)
        environment.get_template(name)
        for referenced in meta.find_referenced_templates(parsed):
            if referenced is not None:
                assert referenced in names, f"{name} 引用了不存在的模板 {referenced}"


def test_literal_render_template_targets_exist():
    environment = _environment()
    names = _template_names(environment)
    python_files = [ROOT / "oj.py", *(ROOT / "oj_modules").rglob("*.py")]

    for path in python_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            if not isinstance(function, ast.Name) or function.id != "render_template":
                continue
            target = node.args[0]
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                assert target.value in names, (
                    f"{path.relative_to(ROOT)}:{node.lineno} 渲染了不存在的模板 "
                    f"{target.value}"
                )


def test_literal_static_asset_targets_exist():
    static_root = ROOT / "static"
    pattern = re.compile(r"url_for\(['\"]static['\"],\s*filename=['\"]([^'\"]+)['\"]\)")
    for path in TEMPLATES.rglob("*.html"):
        source = path.read_text(encoding="utf-8")
        for target in pattern.findall(source):
            assert (static_root / target).is_file(), (
                f"{path.relative_to(ROOT)} 引用了不存在的静态资源 {target}"
            )


def test_ranking_detail_uses_one_modal_source_per_judge_mode():
    environment = _environment()
    detail = (TEMPLATES / "ranking" / "detail.html").read_text(encoding="utf-8")
    judge_include = "{% include 'ranking/modals/judge_detail.html' %}"
    reverse_include = "{% include 'ranking/modals/reverse_judge_detail.html' %}"

    assert detail.count(judge_include) == 1
    assert detail.count(reverse_include) == 1
    assert 'id="judgeDetailModal"' not in detail
    assert 'id="reverseJudgeDetailModal"' not in detail

    judge_html = environment.get_template("ranking/modals/judge_detail.html").render(
        tab="submit"
    )
    reverse_html = environment.get_template(
        "ranking/modals/reverse_judge_detail.html"
    ).render()
    assert judge_html.count('id="judgeDetailModal"') == 1
    assert reverse_html.count('id="reverseJudgeDetailModal"') == 1


def test_ranking_detail_dispatches_each_tab_to_a_bounded_partial():
    detail = (TEMPLATES / "ranking" / "detail.html").read_text(encoding="utf-8")
    panel = (
        TEMPLATES / "ranking" / "components" / "detail_panel.html"
    ).read_text(encoding="utf-8")
    expected = {
        "description",
        "submit",
        "leaderboard",
        "matches",
        "submissions",
        "appeals",
        "batch_evaluate",
        "settings",
    }
    panel_include = "{% include 'ranking/components/detail_panel.html' %}"
    assert detail.count(panel_include) == 1
    for name in expected:
        include = f"{{% include 'ranking/tabs/{name}.html' %}}"
        assert detail.count(include) == 0
        assert panel.count(include) == 1

    assert "<script>" not in detail
    assert detail.count("filename='app/choice-picker.js'") == 1
    assert detail.count("filename='app/ranking/topology.js'") == 1
    assert detail.count("{% include 'ranking/modals/media_preview.html' %}") == 1


def test_shared_layout_and_editor_fragments_have_one_canonical_source():
    site = (TEMPLATES / "layouts" / "site.html").read_text(encoding="utf-8")
    for name in (
        "navigation",
        "password_modal",
        "class_manager_modal",
        "flash_messages",
    ):
        assert site.count(f"{{% include 'components/layout/{name}.html' %}}") == 1

    editor_include = "{% include 'components/editor/codemirror.html' %}"
    consumers = {
        "problems/create.html",
        "problems/edit.html",
        "problems/detail.html",
        "submissions/detail.html",
        "repository/index.html",
    }
    for name in consumers:
        source = (TEMPLATES / name).read_text(encoding="utf-8")
        assert source.count(editor_include) == 1


def test_all_code_editing_surfaces_share_the_adaptive_dark_plus_runtime():
    monaco_include = "{% include 'components/editor/monaco.html' %}"
    for name in (
        "problems/create.html",
        "problems/edit.html",
        "problems/detail.html",
        "submissions/detail.html",
        "repository/index.html",
    ):
        source = (TEMPLATES / name).read_text(encoding="utf-8")
        assert source.count(monaco_include) == 1

    create = (TEMPLATES / "problems" / "create.html").read_text(
        encoding="utf-8"
    )
    edit = (TEMPLATES / "problems" / "edit.html").read_text(encoding="utf-8")
    form_editor = (
        ROOT / "static" / "app" / "problem-form-editors.js"
    ).read_text(encoding="utf-8")
    editor_runtime = (
        ROOT / "static" / "app" / "code-editor-runtime.js"
    ).read_text(encoding="utf-8")
    problem_editor = (
        ROOT / "static" / "app" / "problem-editor.js"
    ).read_text(encoding="utf-8")
    submission_editor = (
        ROOT / "static" / "app" / "submissions" / "detail.js"
    ).read_text(encoding="utf-8")
    monaco_component = (
        TEMPLATES / "components" / "editor" / "monaco.html"
    ).read_text(encoding="utf-8")
    codemirror_component = (
        TEMPLATES / "components" / "editor" / "codemirror.html"
    ).read_text(encoding="utf-8")

    for source in (create, edit):
        assert "filename='app/problem-form-editors.js'" in source
        assert "numoj-form-code-editor" in source
        assert "CodeMirror(" not in source
    assert 'context: "problem-form"' in form_editor
    assert '"initial-code"' in form_editor
    assert '"test-code"' in form_editor
    assert "runtime.monacoOptions({" in form_editor
    assert "function registerMatlab(monaco)" in editor_runtime
    assert "function registerMatlab(monaco)" not in problem_editor
    assert "function registerMatlab(monaco)" not in submission_editor
    assert "}, 8000);" in monaco_component
    assert "}, 8000);" in codemirror_component
    assert "TEXTMATE_INITIAL_WAIT_MS = 250" in editor_runtime
    assert 'monaco.editor.setTheme("dark-plus")' in editor_runtime


def test_non_credential_text_fields_opt_out_of_password_managers():
    users = (TEMPLATES / "admin" / "users.html").read_text(encoding="utf-8")
    repository = (TEMPLATES / "repository" / "index.html").read_text(
        encoding="utf-8"
    )
    workbench = (
        ROOT / "static" / "app" / "repository" / "workbench.js"
    ).read_text(encoding="utf-8")
    editor_runtime = (
        ROOT / "static" / "app" / "code-editor-runtime.js"
    ).read_text(encoding="utf-8")

    assert 'name="user_search"' in users
    assert 'name="username"' not in users
    for marker in ('autocomplete="off"', "data-1p-ignore", 'data-lpignore="true"'):
        assert marker in users
        assert marker in repository

    assert "runtime.protectEditorInput(" in workbench
    assert 'input.setAttribute("autocomplete", "off")' in editor_runtime
    assert 'input.setAttribute("data-bwignore", "")' in editor_runtime


def test_problem_dashboard_defers_class_activity_until_after_first_render():
    problem_list = (TEMPLATES / "problems" / "list.html").read_text(
        encoding="utf-8"
    )
    desktop_list = (TEMPLATES / "problems" / "desktop" / "list.html").read_text(
        encoding="utf-8"
    )
    dashboard = (ROOT / "static" / "app" / "problem-dashboard.js").read_text(
        encoding="utf-8"
    )
    layout = (ROOT / "static" / "app" / "layout.css").read_text(encoding="utf-8")

    assert "filename='app/problem-dashboard.js'" in problem_list
    assert "data-numoj-class-activity" in desktop_list
    assert "data-numoj-activity-loading" in desktop_list
    assert "正在加载班级活跃度" in desktop_list
    assert "{% for item in class_activity" not in desktop_list
    assert "fetch(activityUrl" in dashboard
    assert "grid.replaceChildren(fragment)" in dashboard
    assert "min-height: 144px;" in layout


def test_problem_detail_uses_full_width_split_workspace_and_vscode_theme():
    detail = (TEMPLATES / "problems" / "detail.html").read_text(encoding="utf-8")
    layout = (ROOT / "static" / "app" / "layout.css").read_text(encoding="utf-8")
    editor = (ROOT / "static" / "app" / "problem-editor.js").read_text(
        encoding="utf-8"
    )
    semantic_tokens = (
        ROOT / "static" / "app" / "editor-semantic-tokens.js"
    ).read_text(encoding="utf-8")
    monaco_component = (
        TEMPLATES / "components" / "editor" / "monaco.html"
    ).read_text(encoding="utf-8")
    monaco_entry = (ROOT / "frontend" / "monaco" / "editor.js").read_text(
        encoding="utf-8"
    )
    editor_runtime = (
        ROOT / "static" / "app" / "code-editor-runtime.js"
    ).read_text(encoding="utf-8")

    assert "problem-detail-content-shell" in detail
    assert "problem-code-submit-form" in detail
    assert "problem-editor-toolbar" in detail
    assert "problem-editor-actions" in detail
    assert "problem-heading-layout" in detail
    assert "problem-heading-info" in detail
    assert 'id="desktopEditorShell"' in detail
    assert 'id="monacoEditorLoading"' in detail
    assert "代码编辑器正在加载" in detail
    assert 'data-size="lg"' in detail
    assert "recent-submissions-panel" in detail
    assert "recent-submissions-card" in detail
    assert 'class="recent-submissions-panel d-lg-none"' in detail
    assert "recent-submission-arrow" in detail
    for status, abbreviation in (
        ("Accepted", "AC"),
        ("Unaccepted", "WA"),
        ("Compile Error", "CE"),
    ):
        assert f"'{status}': '{abbreviation}'" in detail
    assert "grid-template-columns: repeat(2, minmax(0, 1fr));" in layout
    assert ".numoj-content.problem-detail-content-shell" in layout
    assert ".submission-status.accepted" in layout
    assert ".submission-status.unaccepted" in layout
    assert ".submission-status.compile-error" in layout
    assert ".recent-submissions-card" in layout
    assert ".problem-heading-layout.has-recent-submissions" in layout
    assert ".problem-prompt-submit-form" in layout
    assert ".problem-editor-loading-state" in layout
    assert 'data-editor-state="ready"' in layout
    assert "revealMonacoEditor(instance)" in editor
    assert "window.NumOJSemanticTokens.register(monaco" in editor
    assert "registerDocumentSemanticTokensProvider" in semantic_tokens
    assert '"py", "python", "matlab", "octave"' in semantic_tokens
    assert "/api/editor/semantic-token-legend" in semantic_tokens
    assert "/api/editor/semantic-tokens" in semantic_tokens
    assert "getLegend: getLegend" in semantic_tokens
    assert "requestTokens: requestTokens" in semantic_tokens
    assert semantic_tokens.count("mathCurveLoader: false") == 2
    assert "settings.onRequestStart()" in semantic_tokens
    assert "settings.onRequestEnd()" in semantic_tokens
    assert "filename='app/editor-semantic-tokens.js'" in monaco_component
    assert "filename='app/code-editor-runtime.js'" in monaco_component
    assert "runtime.prepareMonaco(monaco)" in editor
    assert "monaco.prepareTextMateHighlighting()" in editor_runtime
    assert 'return "dark-plus"' in editor_runtime
    assert 'monaco.editor.setTheme("dark-plus")' in editor_runtime
    assert "theme: editorTheme" in editor
    assert "'semanticHighlighting.enabled': true" in editor
    assert 'from "@shikijs/monaco"' in monaco_entry
    assert "darkPlusSemanticRules" in monaco_entry
    assert '{ token: "class", foreground: "4EC9B0" }' in monaco_entry
    assert '{ token: "method", foreground: "DCDCAA" }' in monaco_entry
    assert 'from "@shikijs/langs/cpp"' in monaco_entry
    assert 'from "@shikijs/themes/dark-plus"' in monaco_entry
    assert "createJavaScriptRegexEngine()" in monaco_entry
    assert "numoj-light" not in editor


def test_unified_submission_list_owns_one_component_and_asset_pair():
    component = TEMPLATES / "submissions" / "components" / "table.html"
    stylesheet = ROOT / "static" / "app" / "submissions.css"
    script = ROOT / "static" / "app" / "submissions.js"
    page = TEMPLATES / "submissions" / "all.html"
    assert component.is_file()
    assert stylesheet.is_file()
    assert script.is_file()
    assert not (TEMPLATES / "submissions" / "list.html").exists()

    macro_import = (
        '{% from "submissions/components/table.html" import pagination, '
        'submission_detail_panel, submission_table %}'
    )
    source = page.read_text(encoding="utf-8")
    assert source.count(macro_import) == 1
    assert source.count("submission_table(submissions, user)") == 1
    assert source.count("submission_detail_panel(submissions | length > 0, user)") == 1
    assert source.count("filename='app/submissions.css'") == 1
    assert source.count("filename='app/submissions.js'") == 1
    assert "submission.submission_list" not in source


def test_submission_detail_uses_equal_split_workspace_and_shared_editor_contract():
    detail = (TEMPLATES / "submissions" / "detail.html").read_text(
        encoding="utf-8"
    )
    detail_css = (
        ROOT / "static" / "app" / "submissions" / "detail.css"
    ).read_text(encoding="utf-8")
    detail_js = (
        ROOT / "static" / "app" / "submissions" / "detail.js"
    ).read_text(encoding="utf-8")
    editor_runtime = (
        ROOT / "static" / "app" / "code-editor-runtime.js"
    ).read_text(encoding="utf-8")
    list_component = (
        TEMPLATES / "submissions" / "components" / "table.html"
    ).read_text(encoding="utf-8")
    list_css = (ROOT / "static" / "app" / "submissions.css").read_text(
        encoding="utf-8"
    )
    list_js = (ROOT / "static" / "app" / "submissions.js").read_text(
        encoding="utf-8"
    )

    assert "submission-detail-shell" in detail
    assert "submission-detail-primary" in detail
    assert "submission-detail-summary-card" in detail
    assert "submission-detail-results" in detail
    assert 'class="submission-detail-id">#{{ submission.id }}' in detail
    assert "SUBMISSION · #" not in detail
    assert "<dt>语言</dt>" not in detail
    assert "submission-detail-problem-title" not in detail
    assert "<dt>题目</dt>" in detail
    assert "submissionMonacoContainer" in detail
    assert 'data-problem-id="{{ submission.problem_id }}"' in detail
    assert "{% include 'components/editor/monaco.html' %}" in detail
    assert "{% include 'components/editor/codemirror.html' %}" in detail
    assert "filename='app/submissions/detail.css'" in detail
    assert "filename='app/submissions/detail.js'" in detail
    assert 'class="submission-detail-disclosure submission-prompt-card" open' in detail
    assert 'class="submission-detail-disclosure submission-latex-card"' in detail
    assert "<style" not in detail

    assert 'grid-template-areas:\n    "summary primary"\n    "results primary";' in detail_css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr));" in detail_css
    assert "height: 100vh;" in detail_css
    assert "--submission-time-limit: #172554;" in detail_css
    assert "border-radius: 0;" in detail_css
    assert 'grid-template-areas:\n      "summary"\n      "primary"\n      "results";' in detail_css
    assert "<h2>测试点结果</h2>" not in detail
    assert "0 0 0 4px var(--submission-ink)" in detail_css
    assert "margin-inline: auto;" in detail_css
    assert "card.setAttribute('aria-pressed', isSelected ? 'true' : 'false')" in detail
    assert "readOnly: true" in detail_js
    assert "domReadOnly: true" in detail_js
    assert "runtime.prepareMonaco(monaco)" in detail_js
    assert 'return "dark-plus"' in editor_runtime
    assert 'monaco.editor.setTheme("dark-plus")' in editor_runtime
    assert "window.NumOJMonacoReady" in detail_js
    assert "window.NumOJCodeMirrorReady" in detail_js
    assert "window.NumOJSemanticTokens.register(monaco" in detail_js
    assert "submissionSemanticLoading" in detail
    assert "updateSemanticLoading(1)" in detail_js
    assert "updateSemanticLoading(-1)" in detail_js
    assert ".submission-semantic-loading" in detail_css
    assert "pointer-events: none;" in detail_css
    assert "monaco-ai-issue-underline" in detail_js
    assert "--math-curve-color-a: #ffffff;" in detail_css
    assert "--math-curve-color-b: #ffffff;" in detail_css
    assert 'data-color-a="#ffffff"' in detail
    assert 'data-color-b="#ffffff"' in detail

    for source in (list_component, list_js):
        assert "wrong-answer" in source
        assert "runtime-error" in source
        assert "time-limit" in source
        assert "other-failure" in source
    for source in (list_css, detail_css):
        assert "is-wrong-answer" in source
        assert "is-runtime-error" in source
        assert "is-time-limit" in source
        assert "is-other-failure" in source
    assert "{% elif point_status == 'Wrong Answer' %}" in list_component
    assert 'if (value === "Wrong Answer")' in list_js
    assert "if (normalized === 'Wrong Answer')" in detail
    assert "['Wrong Answer', 'Unaccepted']" not in detail


def test_ranking_list_uses_admin_create_fab_without_intro_hero():
    ranking_list = (TEMPLATES / "ranking" / "list.html").read_text(
        encoding="utf-8"
    )

    assert "围绕开放赛题提交作品" not in ranking_list
    assert "ranking-hero" not in ranking_list
    assert 'class="ranking-create-fab"' in ranking_list
    assert 'aria-label="创建打榜赛"' in ranking_list
    assert 'data-bs-target="#newCompetitionModal"' in ranking_list
    assert ".ranking-create-fab" in ranking_list
    assert "position: fixed;" in ranking_list
    assert "border-radius: 50%;" in ranking_list


def test_circle_cat_uses_full_height_board_with_right_sidebar_without_frames():
    circle_cat = (TEMPLATES / "games" / "circle_cat.html").read_text(
        encoding="utf-8"
    )

    assert "container-fluid p-0 cat-game-page" in circle_cat
    assert 'grid-template-areas: "board sidebar";' in circle_cat
    assert "grid-template-columns: minmax(0, 1fr) minmax(260px, 320px);" in circle_cat
    assert ".cat-sidebar {\n    grid-area: sidebar;" in circle_cat
    assert ".cat-board-card {\n    grid-area: board;" in circle_cat
    assert "height: calc(100vh - 148px);" not in circle_cat
    assert "min-height: calc(100vh - 210px);" not in circle_cat
    assert "const cellSize = Math.max(minCell, fitted);" in circle_cat
    assert '<i class="fas fa-trophy' not in circle_cat
    assert ".cat-leaderboard-score {\n    font-size: 0.72rem;\n    color: #495057;" in circle_cat

    sidebar_rules = circle_cat.split(".cat-sidebar {", 1)[1].split("}", 1)[0]
    board_rules = circle_cat.split(".cat-board-card {", 1)[1].split("}", 1)[0]
    shell_rules = circle_cat.split(".cat-game-shell {", 1)[1].split("}", 1)[0]
    for rules in (sidebar_rules, board_rules, shell_rules):
        assert "border-radius" not in rules
        assert "border:" not in rules


def test_rule_topology_algorithm_has_one_parameterized_source():
    algorithm = (ROOT / "static" / "app" / "ranking" / "topology.js").read_text(
        encoding="utf-8"
    )
    assert "global.RuleTopology" in algorithm
    for method in ("layout: layout", "buildRoutes: buildRoutes", "edgePath: edgePath"):
        assert method in algorithm

    consumers = {
        TEMPLATES / "ranking" / "appeal_review.html": (46, 18),
        TEMPLATES / "ranking" / "modals" / "judge_detail.html": (46, 18),
        ROOT / "static" / "app" / "ranking" / "rules-editor.js": (42, 17),
    }
    for path, geometry in consumers.items():
        source = path.read_text(encoding="utf-8")
        assert source.count("RuleTopology.create") == 1
        assert "function slotOffset" not in source
        assert "function buildEdgeRoutes" not in source
        assert f"slotPadding: {geometry[0]}, maxSlotStep: {geometry[1]}" in source


def test_ranking_settings_are_split_by_cohesive_responsibility():
    settings = (TEMPLATES / "ranking" / "tabs" / "settings.html").read_text(
        encoding="utf-8"
    )
    partials = {
        "endpoint_pool",
        "rules_panel",
        "rules_editor_script",
    }
    for name in partials:
        assert settings.count(f"{{% include 'ranking/settings/{name}.html' %}}") == 1

    assert len(settings.splitlines()) < 700
    rules_script = (
        ROOT / "static" / "app" / "ranking" / "rules-editor.js"
    ).read_text(encoding="utf-8")
    endpoint_script = (
        ROOT / "static" / "app" / "ranking" / "endpoints.js"
    ).read_text(encoding="utf-8")
    assert "{{" not in rules_script
    assert "{{" not in endpoint_script
    assert "window.ChoicePicker.create" in endpoint_script
