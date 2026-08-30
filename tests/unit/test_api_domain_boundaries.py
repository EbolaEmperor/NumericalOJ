import ast
from pathlib import Path

from backend.oj_modules.ai_detection.presentation import (
    decode_detection_result_details,
    serialize_detection_result,
)
from backend.oj_modules.problems.agent_runs import decorate_agent_run_summaries
from backend.oj_modules.problems.presentation import strip_problem_title_tags
from backend.oj_modules.submissions.presentation import (
    load_written_submission_latex_and_error,
    render_written_markdown_to_html,
    summarize_panel_test_points,
)


ROOT = Path(__file__).resolve().parents[2]


def test_problem_title_and_agent_run_display_helpers_preserve_contract():
    assert strip_problem_title_tags("  数值积分 「NA-1」  ") == "数值积分"
    assert strip_problem_title_tags("「唯一内容」") == "「唯一内容」"
    assert strip_problem_title_tags(None) is None

    runs = [{
        "problem_id": 17,
        "problem_title": " ",
        "status": "",
        "best_score": "92",
    }]
    assert decorate_agent_run_summaries(runs) is runs
    assert runs == [{
        "problem_id": 17,
        "problem_title": " ",
        "status": "",
        "best_score": "92",
        "display_problem_title": "Problem 17",
        "display_status": "Pending",
        "display_best_score": 92,
    }]


def test_ai_detection_helpers_keep_html_mutation_and_api_copy_semantics():
    original = {
        "problem_title": "线性方程 「A-2」",
        "llm_evidence": '[{"kind": "same-name"}]',
        "behavior_detail": "not-json",
    }

    assert decode_detection_result_details(original) is original
    assert original["_evidence"] == [{"kind": "same-name"}]
    assert original["_signals"] == []

    api_source = {
        "problem_title": "线性方程 「A-2」",
        "llm_evidence": "bad-json",
        "behavior_detail": '[{"score": 1}]',
    }
    serialized = serialize_detection_result(api_source)
    assert serialized is not api_source
    assert "_evidence" not in api_source
    assert serialized["problem_title"] == "线性方程"
    assert serialized["_evidence"] == []
    assert serialized["_signals"] == [{"score": 1}]


def test_submission_panel_and_written_artifact_helpers(tmp_path, monkeypatch):
    points = summarize_panel_test_points([
        {
            "index": "4",
            "status": "",
            "stderr": "e" * 700,
            "stdout": "o" * 700,
            "has_output_image": 1,
        },
        "ignore non-mapping point",
    ])
    assert points == [{
        "test_index": 4,
        "status": "Unknown",
        "time": None,
        "stderr": "e" * 600,
        "stdout": "o" * 600,
        "has_output_image": True,
    }]

    rendered = render_written_markdown_to_html(
        "# 标题\n\n[x](javascript:alert(1))"
    )
    assert "<h1>标题</h1>" in rendered
    assert "javascript:" not in rendered.lower()

    monkeypatch.chdir(tmp_path)
    upload_dir = tmp_path / "uploads" / "9"
    upload_dir.mkdir(parents=True)
    (upload_dir / "answer.md").write_text(
        "公式：a\\\\b",
        encoding="utf-8",
    )
    (upload_dir / "answer_latex_error.txt").write_text(
        "编译失败",
        encoding="utf-8",
    )

    latex_text, error_text = load_written_submission_latex_and_error({
        "id": 9,
        "problem_type": 2,
        "test_points": ["answer.pdf"],
    })
    assert latex_text == "公式：a\\\\\\\\b"
    assert error_text == "编译失败"


def test_scoped_api_modules_do_not_depend_upward_on_routes():
    found = set()
    for filename in (
        "admin_api.py",
        "ai_detection_api.py",
        "homework_api.py",
        "problem_api.py",
        "repository_api.py",
        "submission_api.py",
    ):
        tree = ast.parse(
            (ROOT / "backend" / "oj_modules" / "api" / filename).read_text(encoding="utf-8")
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (
                node.module or ""
            ).startswith("backend.oj_modules.routes"):
                found.update((node.module, alias.name) for alias in node.names)
            elif isinstance(node, ast.Import):
                found.update(
                    (alias.name, "")
                    for alias in node.names
                    if alias.name.startswith("backend.oj_modules.routes")
                )

    assert found == set()


def test_problem_route_keeps_task_dependencies_injected():
    tree = ast.parse(
        (ROOT / "backend" / "oj_modules" / "routes" / "problem_core_routes.py").read_text(
            encoding="utf-8"
        )
    )
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imported_modules.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )

    assert not any(
        module == "backend.oj_modules.tasks" or module.startswith("backend.oj_modules.tasks.")
        for module in imported_modules
    )


def test_extracted_domain_helpers_do_not_import_flask():
    for relative_path in (
        "backend/oj_modules/ai_detection/presentation.py",
        "backend/oj_modules/homework/plagiarism.py",
        "backend/oj_modules/homework/progress.py",
        "backend/oj_modules/homework/records.py",
        "backend/oj_modules/homework/repository.py",
        "backend/oj_modules/homework/runtime.py",
        "backend/oj_modules/homework/targets.py",
        "backend/oj_modules/problems/agent_runs.py",
        "backend/oj_modules/problems/catalog.py",
        "backend/oj_modules/problems/context.py",
        "backend/oj_modules/problems/grading.py",
        "backend/oj_modules/problems/presentation.py",
        "backend/oj_modules/repository/settings.py",
        "backend/oj_modules/submissions/presentation.py",
    ):
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        imported_modules.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        assert not any(
            module == "flask" or module.startswith("flask.")
            for module in imported_modules
        ), relative_path
