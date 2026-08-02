"""旧目录布局不再提供 Python 导入兼容层。"""

import importlib
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

LEGACY_MODULES = (
    "oj_modules.ai_utils",
    "oj_modules.archive_utils",
    "oj_modules.auth_helpers",
    "oj_modules.clangd_services",
    "oj_modules.class_logo_services",
    "oj_modules.class_membership_services",
    "oj_modules.dashboard_services",
    "oj_modules.docker_sandbox",
    "oj_modules.editor_toolchain",
    "oj_modules.forum_identity_services",
    "oj_modules.forum_services",
    "oj_modules.grading_services",
    "oj_modules.idempotency_utils",
    "oj_modules.identicon_utils",
    "oj_modules.judger_case_runner",
    "oj_modules.judger_core",
    "oj_modules.language_server_services",
    "oj_modules.markdown_utils",
    "oj_modules.modelscope_web_search_mcp",
    "oj_modules.octave_language_services",
    "oj_modules.promptly_guard",
    "oj_modules.python_language_services",
    "oj_modules.ranking_agent_judge",
    "oj_modules.ranking_agent_judge_db",
    "oj_modules.ranking_db",
    "oj_modules.ranking_reverse_judge_db",
    "oj_modules.redis_clients",
    "oj_modules.request_auth",
    "oj_modules.request_security",
    "oj_modules.security_utils",
    "oj_modules.semantic_token_cache",
    "oj_modules.startup_requeue",
    "oj_modules.submission_archive",
    "oj_modules.submission_repository_snapshots",
    "oj_modules.testdata_services",
    "oj_modules.written_submission_artifacts",
    "oj_modules.tasks.agent_generate_helpers",
    "oj_modules.tasks.agent_generate_testdata_task",
    "oj_modules.tasks.agent_shared",
    "oj_modules.tasks.agent_solve_helpers",
    "oj_modules.tasks.agent_solve_task",
    "oj_modules.tasks.agent_tasks",
    "oj_modules.tasks.ranking_agent_judge_tasks",
    "oj_modules.tasks.ranking_batch_pull_tasks",
    "oj_modules.tasks.ranking_bulk_rejudge_tasks",
    "oj_modules.tasks.ranking_elo_tasks",
    "oj_modules.tasks.ranking_evaluate_tasks",
    "oj_modules.tasks.ranking_reverse_judge_tasks",
)

PACKAGE_ONLY_EXPORTS = {
    "oj_modules.api": {"API_BLUEPRINTS", "admin_api_bp"},
    "oj_modules.tasks": {
        "register_evaluate_submission_task",
        "register_ranking_evaluate_task",
    },
    "oj_modules.ai_detection": {"run_detection"},
}


def test_legacy_module_paths_are_absent():
    for module_name in LEGACY_MODULES:
        module_path = ROOT / (module_name.replace(".", "/") + ".py")
        assert not module_path.exists(), module_name
        assert importlib.util.find_spec(module_name) is None, module_name


def test_packages_do_not_reexport_former_compatibility_symbols():
    for package_name, former_exports in PACKAGE_ONLY_EXPORTS.items():
        package = importlib.import_module(package_name)
        assert package.__all__ == []
        assert "__getattr__" not in vars(package)
        for name in former_exports:
            assert name not in vars(package), f"{package_name}.{name}"
