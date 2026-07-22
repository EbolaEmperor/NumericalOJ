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
