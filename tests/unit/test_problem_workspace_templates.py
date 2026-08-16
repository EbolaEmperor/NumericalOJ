from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def _braced_block(source, marker):
    """返回 marker 后首个花括号块，供响应式静态契约精确取规则。"""
    marker_start = source.index(marker)
    block_start = source.index("{", marker_start)
    depth = 0
    for index in range(block_start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[block_start + 1:index]
    raise AssertionError(f"{marker} 缺少闭合花括号")


def test_desktop_problem_templates_preserve_class_context_and_separate_library_deadline():
    repo = Path(__file__).resolve().parents[2]
    problem_list = (repo / "templates/problems/list.html").read_text()
    desktop_list = (repo / "templates/problems/desktop/list.html").read_text()
    detail = (repo / "templates/problems/detail.html").read_text()
    navigation = (repo / "templates/components/layout/navigation.html").read_text()
    class_logo = (
        repo / "templates/components/layout/class_logo.html"
    ).read_text()

    assert "problem_core.problem_library" in navigation
    assert "source='library'" in desktop_list
    assert "class_en=selected_class_en" in desktop_list
    assert "request.args.get('class_en')" in detail
    assert "data-numoj-class-picker" in desktop_list
    assert 'role="listbox"' in desktop_list
    assert "data-numoj-projects-refresh" in desktop_list
    project_refresh = desktop_list.split(
        "data-numoj-projects-refresh",
        1,
    )[1].split("</button>", 1)[0]
    assert "fa-sync-alt" in project_refresh
    assert "{% from 'components/layout/class_logo.html' import class_logo %}" in desktop_list
    assert "<svg" in class_logo
    assert "<rect" in class_logo
    library_rows = desktop_list.split("{% for p in problems %}", 1)[1].split(
        "{% else %}", 1
    )[0]


def test_problem_list_uses_one_canonical_v2_dashboard_at_every_breakpoint():
    repo = Path(__file__).resolve().parents[2]
    problem_list = (repo / "templates/problems/list.html").read_text()
    dashboard = (repo / "templates/problems/desktop/list.html").read_text()

    assert "{% include 'problems/desktop/list.html' %}" in problem_list
    assert '<section class="numoj-problem-dashboard"' in dashboard
    assert "numoj-row-title-link" in dashboard



def test_mobile_assignment_deadline_keeps_only_the_relative_status_visible():
    repo = Path(__file__).resolve().parents[2]
    dashboard = (repo / "templates/problems/desktop/list.html").read_text()
    layout_css = (repo / "static/app/layout.css").read_text()

    assert 'class="numoj-row-deadline-absolute"' in dashboard
    assert 'class="numoj-row-deadline-relative expired"' in dashboard
    assert 'class="numoj-row-deadline-relative urgent"' in dashboard
    assert 'class="numoj-row-deadline-relative"' in dashboard

    mobile_rules = _braced_block(layout_css, "@media (max-width: 991.98px)")
    absolute_rule = _braced_block(
        mobile_rules,
        ".numoj-problem-dashboard .numoj-row-deadline-absolute",
    )
    assert "display: none;" in absolute_rule


def test_problem_detail_mobile_workspace_keeps_the_complete_monaco_surface():
    repo = Path(__file__).resolve().parents[2]
    detail = (repo / "templates/problems/detail.html").read_text()
    layout_css = (repo / "static/app/layout.css").read_text()
    lean_css = (repo / "static/app/lean-workbench.css").read_text()

    assert 'id="problemEditorShell"' in detail
    assert 'id="monacoEditorLoading"' in detail
    assert 'id="monacoEditorContainer"' in detail

    mobile_rules = _braced_block(layout_css, "@media (max-width: 991.98px)")
    detail_row_rule = _braced_block(
        mobile_rules,
        ".problem-detail-page .problem-detail-row",
    )
    assert "grid-template-columns: minmax(0, 1fr);" in detail_row_rule

    outer_splitter_rule = _braced_block(
        mobile_rules,
        ".problem-detail-page .problem-detail-splitter",
    )
    assert "display: none;" in outer_splitter_rule

    editor_rule = _braced_block(
        mobile_rules,
        ".problem-detail-page .problem-editor-shell",
    )
    assert "display: block;" in editor_rule
    assert "height: clamp(360px, 58svh, 620px);" in editor_rule

    title_rule = _braced_block(
        mobile_rules,
        ".problem-detail-page .problem-title-singleline",
    )
    assert "white-space: normal;" in title_rule

    table_rule = _braced_block(
        mobile_rules,
        ".problem-detail-page .problem-content table",
    )
    assert "overflow-x: auto;" in table_rule

    lean_mobile_rules = _braced_block(lean_css, "@media (max-width: 991.98px)")
    lean_workbench_rule = _braced_block(lean_mobile_rules, "\n  .lean-workbench {")
    assert "grid-template-columns: minmax(0, 1fr);" in lean_workbench_rule
    assert "grid-template-rows:" in lean_workbench_rule

    lean_splitter_rule = _braced_block(
        lean_mobile_rules,
        ".lean-workbench-splitter",
    )
    assert "display: none;" in lean_splitter_rule


def test_problem_detail_desktop_splitters_share_pointer_keyboard_and_aria_contract():
    repo = Path(__file__).resolve().parents[2]
    detail = (repo / "templates/problems/detail.html").read_text()
    layout_css = (repo / "static/app/layout.css").read_text()
    lean_css = (repo / "static/app/lean-workbench.css").read_text()
    controller = (repo / "static/app/problem-detail-layout.js").read_text()

    assert "data-problem-detail-splitter" in detail
    assert "data-lean-workbench-splitter" in detail
    assert "--problem-detail-statement-width" in layout_css
    assert "--lean-source-width" in lean_css
    assert 'global.matchMedia("(min-width: 992px)")' in controller

    outer_splitter_rule = _braced_block(
        layout_css,
        ".problem-detail-page .problem-detail-splitter",
    )
    lean_splitter_rule = _braced_block(lean_css, ".lean-workbench-splitter")
    for splitter_rule in (outer_splitter_rule, lean_splitter_rule):
        assert "cursor: col-resize;" in splitter_rule
        assert "touch-action: none;" in splitter_rule

    for event_name in (
        "pointerdown",
        "pointermove",
        "pointerup",
        "pointercancel",
    ):
        assert f'addEventListener("{event_name}"' in controller
    assert "splitter.setPointerCapture(pointerId)" in controller
    for event_name in ("pointermove", "pointerup", "pointercancel"):
        assert f'global.addEventListener("{event_name}"' in controller
    assert 'event.key === "ArrowLeft"' in controller
    assert 'event.key === "ArrowRight"' in controller
    assert 'splitter.setAttribute("aria-valuenow"' in controller
    assert 'propertyName: "--problem-detail-statement-width"' in controller
    assert 'propertyName: "--lean-source-width"' in controller
    assert 'var isLeanWorkbench = page.classList.contains("is-lean-workbench")' in controller
    assert 'storageKey: isLeanWorkbench' in controller
    assert '"numoj.problemDetail.leanStatementRatio"' in controller
    assert '"numoj.problemDetail.statementRatio"' in controller
    assert 'storageKey: "numoj.problemDetail.leanSourceRatio"' in controller
    assert 'container.style.removeProperty(options.propertyName)' in controller
    assert 'typeof global.editor.layout === "function"' in controller
    assert "global.editor.layout()" in controller


def test_problem_resources_link_to_the_repository_instead_of_the_retired_zju_site():
    repo = Path(__file__).resolve().parents[2]
    problem_list = (repo / "templates/problems/list.html").read_text()
    desktop_list = (repo / "templates/problems/desktop/list.html").read_text()
    repository_url = "https://github.com/EbolaEmperor/NumericalOJ"

    for source in (problem_list, desktop_list):
        assert repository_url in source


def test_submission_metric_renders_empty_and_cpp_values_without_undefined_errors():
    repo = Path(__file__).resolve().parents[2]
    environment = Environment(loader=FileSystemLoader(repo / "templates"), autoescape=True)
    macros = environment.get_template("problems/desktop/macros.html").module
    problem_macros = environment.get_template("components/problem_macros.html").module

    empty = str(macros.submission_metric(None))
    populated = str(macros.submission_metric({
        "pass_rate": 0.625,
        "submission_count": 8,
    }))

    assert "—" in empty
    assert "n=0" in empty
    assert "63%" in populated
    assert "n=8" in populated
    assert str(problem_macros.language_label("cpp")) == "C++"


def test_problem_heading_keeps_kickers_and_problem_number_left_aligned():
    repo = Path(__file__).resolve().parents[2]
    detail = (repo / "templates/problems/detail.html").read_text()
    layout_css = (repo / "static/app/layout.css").read_text()

    assert 'class="problem-number"' in detail
    assert 'class="problem-title-text"' in detail
    assert ".problem-detail-page .problem-heading-info {" in layout_css
    assert "align-items: flex-start;" in layout_css
    assert ".problem-detail-page .problem-title-singleline .problem-number {" in layout_css
    assert "flex: 0 0 auto;" in layout_css


def test_problem_detail_uses_the_shared_rich_markdown_renderer_assets():
    repo = Path(__file__).resolve().parents[2]
    detail = (repo / "templates/problems/detail.html").read_text()
    markdown_css = (repo / "static/app/markdown-rendering.css").read_text()

    assert (
        'class="problem-content numoj-markdown '
        'numoj-problem-code-rendering my-3"'
    ) in detail
    assert "data-numoj-markdown" in detail
    assert detail.count("app/markdown-rendering.css") == 1
    assert detail.count("vendor/mermaid/mermaid.min.js") == 1
    assert detail.count("app/markdown-rendering.js") == 1
    assert detail.index("vendor/mermaid/mermaid.min.js") < detail.index(
        "app/markdown-rendering.js"
    )

    inline_math_rule = _braced_block(
        markdown_css,
        '.numoj-markdown mjx-container[jax="CHTML"]:not([display="true"])',
    )
    assert "vertical-align: 0.08em;" in inline_math_rule


def test_written_problem_upload_keeps_the_file_contract_with_drag_drop_ui():
    repo = Path(__file__).resolve().parents[2]
    detail = (repo / "templates/problems/detail.html").read_text()
    stylesheet = (repo / "static/app/problem-written-submit.css").read_text()
    script = (repo / "static/app/problem-written-submit.js").read_text()

    file_input = detail.split("data-written-file-input", 1)[0].rsplit("<input", 1)[1]
    assert 'id="file"' in file_input
    assert 'name="file"' in file_input
    assert 'accept=".zip"' in file_input
    assert 'accept=".pdf"' in file_input
    assert "required" in file_input

    assert detail.count("app/problem-written-submit.css") == 1
    assert detail.count("app/problem-written-submit.js") == 1
    assert "data-written-dropzone" in detail
    assert "problem-written-submit-button" in detail
    assert "border: 1px dashed" in stylesheet
    assert "padding: 18px clamp(16px, 2.4vw, 26px) 24px;" in stylesheet
    for event_name in ("dragenter", "dragover", "dragleave", "drop"):
        assert f"addEventListener('{event_name}'" in script
    assert "input.dispatchEvent(new Event('change'" in script


def test_failed_homework_cross_is_geometrically_centered_in_status_circle():
    repo = Path(__file__).resolve().parents[2]
    desktop_list = (repo / "templates/problems/desktop/list.html").read_text()
    layout_css = (repo / "static/app/layout.css").read_text()

    failed_state = desktop_list.split(
        'class="numoj-row-state failed"',
        1,
    )[1].split("</div>", 1)[0]
    assert 'role="img"' in failed_state
    assert ".numoj-row-state.failed::before" in layout_css
    assert ".numoj-row-state.failed::after" in layout_css
    assert "top: 50%;" in layout_css
    assert "left: 50%;" in layout_css
    assert "translate(-50%, -50%) rotate(45deg)" in layout_css
    assert "translate(-50%, -50%) rotate(-45deg)" in layout_css
