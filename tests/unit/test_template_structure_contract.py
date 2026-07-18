"""模板目录、引用关系与排名弹窗单一来源契约。"""

import ast
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, meta


ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "templates"


def _environment():
    return Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)


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
    for name in expected:
        assert detail.count(f"{{% include 'ranking/tabs/{name}.html' %}}") == 1

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


def test_submission_lists_share_table_markup_and_styles():
    component = TEMPLATES / "submissions" / "components" / "table.html"
    stylesheet = ROOT / "static" / "app" / "submissions.css"
    assert component.is_file()
    assert stylesheet.is_file()

    macro_import = (
        '{% from "submissions/components/table.html" import pagination, '
        'submission_table %}'
    )
    for name, collection in (
        ("submissions/list.html", "user_submissions"),
        ("submissions/all.html", "submissions"),
    ):
        source = (TEMPLATES / name).read_text(encoding="utf-8")
        assert source.count(macro_import) == 1
        assert source.count(f"submission_table({collection}, user)") == 1
        assert source.count("filename='app/submissions.css'") == 1
        assert 'class="list-group submission-table"' not in source


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
