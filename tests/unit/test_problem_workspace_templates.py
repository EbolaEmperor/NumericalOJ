from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def test_desktop_problem_templates_preserve_class_context_and_separate_library_deadline():
    repo = Path(__file__).resolve().parents[2]
    desktop_list = (repo / "templates/problems/desktop/list.html").read_text()
    detail = (repo / "templates/problems/detail.html").read_text()
    navigation = (repo / "templates/components/layout/navigation.html").read_text()

    assert "problem_core.problem_library" in navigation
    assert "source='library'" in desktop_list
    assert "class_en=selected_class_en" in desktop_list
    assert "request.args.get('class_en')" in detail
    assert "data-numoj-class-picker" in desktop_list
    assert 'role="listbox"' in desktop_list
    assert "<select" not in desktop_list
    assert "data-numoj-projects-refresh" in desktop_list
    project_refresh = desktop_list.split(
        "data-numoj-projects-refresh",
        1,
    )[1].split("</button>", 1)[0]
    assert "fa-sync-alt" in project_refresh
    logo_macro = desktop_list.split("{% macro class_logo", 1)[1].split(
        "{%- endmacro %}",
        1,
    )[0]
    assert "<svg" in logo_macro
    assert "<rect" in logo_macro
    assert "fas " not in logo_macro
    assert "palette-" not in logo_macro
    library_rows = desktop_list.split("{% for p in problems %}", 1)[1].split(
        "{% else %}", 1
    )[0]
    assert "p.ddl" not in library_rows


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

    assert 'class="problem-content numoj-markdown my-3"' in detail
    assert "data-numoj-markdown" in detail
    assert detail.count("app/markdown-rendering.css") == 1
    assert detail.count("vendor/mermaid/mermaid.min.js") == 1
    assert detail.count("app/markdown-rendering.js") == 1
    assert detail.index("vendor/mermaid/mermaid.min.js") < detail.index(
        "app/markdown-rendering.js"
    )


def test_failed_homework_cross_is_geometrically_centered_in_status_circle():
    repo = Path(__file__).resolve().parents[2]
    desktop_list = (repo / "templates/problems/desktop/list.html").read_text()
    layout_css = (repo / "static/app/layout.css").read_text()

    failed_state = desktop_list.split(
        'class="numoj-row-state failed"',
        1,
    )[1].split("</div>", 1)[0]
    assert ">×" not in failed_state
    assert 'role="img"' in failed_state
    assert ".numoj-row-state.failed::before" in layout_css
    assert ".numoj-row-state.failed::after" in layout_css
    assert "top: 50%;" in layout_css
    assert "left: 50%;" in layout_css
    assert "translate(-50%, -50%) rotate(45deg)" in layout_css
    assert "translate(-50%, -50%) rotate(-45deg)" in layout_css
