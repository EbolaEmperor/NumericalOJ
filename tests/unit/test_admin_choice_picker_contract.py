from pathlib import Path

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "backend" / "templates"


def _read(relative_path):
    return (TEMPLATES / relative_path).read_text(encoding="utf-8")




def test_ranking_endpoint_editor_uses_shared_picker_for_global_nodes():
    template = _read("ranking/settings/endpoint_pool.html")
    script = (ROOT / "frontend/public/static/app/ranking/endpoints.js").read_text(encoding="utf-8")

    assert "choice_picker(" in template
    assert "'ajeEditGlobalEndpoint'" in template
    assert "window.ChoicePicker.configure(" in script
    assert "meta:'节点 #' + endpoint.id" in script


def test_admin_class_pickers_keep_submission_and_required_contracts():
    homework = _read("admin/homework.html")
    users = _read("admin/users.html")
    users_script = (ROOT / "frontend/public/static/app/admin-users.js").read_text(encoding="utf-8")

    assert "simple_choice(" in homework
    assert "'sclass'" in homework
    assert "auto_submit=true" in homework

    assert users.count("simple_choice(") == 2
    add_user_picker = users.split("'manageClassSelect'", 1)[1].split(") }}", 1)[0]
    assert "'class_en'" in add_user_picker
    assert "required=true" in add_user_picker
    assert "data-choice-disabled" in users_script
    assert "controller.setValue('', false)" in users_script


def test_problem_forms_use_shared_pickers_and_disable_endpoint_controllers():
    endpoint_component = _read("problems/components/llm_endpoint_select.html")
    create = _read("problems/create.html")
    edit = _read("problems/edit.html")

    assert "endpoint_choice(" in endpoint_component
    assert "placeholder_label='未配置'" in endpoint_component
    assert "help_text" in endpoint_component

    for source in (create, edit):
        assert "simple_choice(" in source
        assert "endpoint_select(" in source
        assert source.count("window.ChoicePicker.setDisabled(") == 6
        assert "programmingGradingModeSelect" in source
        assert "writtenGradingModeSelect" in source
        assert source.count("addEventListener('change'") >= 2
    assert create.count("addEventListener('change'") >= 3


def test_problem_endpoint_picker_keeps_missing_endpoint_and_help_text():
    environment = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
    macros = environment.get_template(
        "problems/components/llm_endpoint_select.html"
    ).module

    rendered = str(
        macros.endpoint_select(
            "review_endpoint_id",
            "reviewEndpoint",
            "审查端点",
            [],
            {"review_endpoint_id": 42},
            "用于审查。",
        )
    )

    assert 'id="reviewEndpoint"' in rendered
    assert 'name="review_endpoint_id"' in rendered
    assert "端点已删除（ID: 42）" in rendered
    assert 'data-choice-value="42"' in rendered
    assert "节点 #42 · 当前不可用" in rendered
    assert "用于审查。" in rendered
