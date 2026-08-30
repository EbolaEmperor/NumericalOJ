"""旧目录布局不再提供 Python 导入兼容层。"""

import ast
import importlib
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

LEGACY_MODULES = (
    "backend.oj_modules.ai_utils",
    "backend.oj_modules.archive_utils",
    "backend.oj_modules.auth_helpers",
    "backend.oj_modules.clangd_services",
    "backend.oj_modules.class_logo_services",
    "backend.oj_modules.class_membership_services",
    "backend.oj_modules.dashboard_services",
    "backend.oj_modules.dynamic_config_services",
    "backend.oj_modules.dynamic_config_testers",
    "backend.oj_modules.docker_sandbox",
    "backend.oj_modules.editor_toolchain",
    "backend.oj_modules.forum_identity_services",
    "backend.oj_modules.forum_services",
    "backend.oj_modules.grading_services",
    "backend.oj_modules.idempotency_utils",
    "backend.oj_modules.identicon_utils",
    "backend.oj_modules.judger_case_runner",
    "backend.oj_modules.judger_core",
    "backend.oj_modules.language_server_services",
    "backend.oj_modules.llm_endpoints",
    "backend.oj_modules.markdown_utils",
    "backend.oj_modules.modelscope_web_search_mcp",
    "backend.oj_modules.integrations.modelscope_web_search",
    "backend.oj_modules.octave_language_services",
    "backend.oj_modules.promptly_guard",
    "backend.oj_modules.python_language_services",
    "backend.oj_modules.problem_llm_bindings",
    "backend.oj_modules.ranking_agent_judge",
    "backend.oj_modules.ranking_agent_judge_db",
    "backend.oj_modules.ranking_db",
    "backend.oj_modules.ranking_reverse_judge_db",
    "backend.oj_modules.redis_clients",
    "backend.oj_modules.request_auth",
    "backend.oj_modules.request_security",
    "backend.oj_modules.security_utils",
    "backend.oj_modules.semantic_token_cache",
    "backend.oj_modules.startup_requeue",
    "backend.oj_modules.submission_archive",
    "backend.oj_modules.submission_repository_snapshots",
    "backend.oj_modules.testdata_services",
    "backend.oj_modules.written_submission_artifacts",
    "backend.oj_modules.tasks.agent_generate_helpers",
    "backend.oj_modules.tasks.agent_generate_testdata_task",
    "backend.oj_modules.tasks.agent_shared",
    "backend.oj_modules.tasks.agent_solve_helpers",
    "backend.oj_modules.tasks.agent_solve_task",
    "backend.oj_modules.tasks.agent_tasks",
    "backend.oj_modules.tasks.agent.generate_helpers",
    "backend.oj_modules.tasks.agent.solve_helpers",
    "backend.oj_modules.tasks.ranking_agent_judge_tasks",
    "backend.oj_modules.tasks.ranking_batch_pull_tasks",
    "backend.oj_modules.tasks.ranking_bulk_rejudge_tasks",
    "backend.oj_modules.tasks.ranking_elo_tasks",
    "backend.oj_modules.tasks.ranking_evaluate_tasks",
    "backend.oj_modules.tasks.ranking_reverse_judge_tasks",
)

PACKAGE_ONLY_EXPORTS = {
    "backend.oj_modules.api": {"API_BLUEPRINTS", "admin_api_bp"},
    "backend.oj_modules.tasks": {
        "register_evaluate_submission_task",
        "register_ranking_evaluate_task",
    },
    "backend.oj_modules.ai_detection": {"run_detection"},
}


def test_legacy_module_paths_are_absent():
    for module_name in LEGACY_MODULES:
        module_path = ROOT / (module_name.replace(".", "/") + ".py")
        assert not module_path.exists(), module_name
        assert importlib.util.find_spec(module_name) is None, module_name


def test_oj_modules_root_only_keeps_explicit_transition_seams():
    root_modules = {
        path.name
        for path in (ROOT / "backend" / "oj_modules").glob("*.py")
    }
    assert root_modules == {
        "__init__.py",
        "config.py",
        "db_services.py",
        "project_paths.py",
    }
    assert not (ROOT / "config.py").exists()


def test_python_sources_use_the_packaged_config_module():
    candidates = [ROOT / "backend" / "oj.py"]
    for directory in ("backend/oj_modules", "deploy", "scripts", "tests"):
        candidates.extend((ROOT / directory).rglob("*.py"))

    legacy_imports = []
    for path in candidates:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(
                alias.name == "config" for alias in node.names
            ):
                legacy_imports.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            if isinstance(node, ast.ImportFrom) and node.module == "config":
                legacy_imports.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert legacy_imports == []


def test_packages_do_not_reexport_former_compatibility_symbols():
    for package_name, former_exports in PACKAGE_ONLY_EXPORTS.items():
        package = importlib.import_module(package_name)
        assert package.__all__ == []
        assert "__getattr__" not in vars(package)
        for name in former_exports:
            assert name not in vars(package), f"{package_name}.{name}"
