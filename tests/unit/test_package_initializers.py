import ast
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_INITIALIZERS = (
    "backend/oj_modules/api/__init__.py",
    "backend/oj_modules/tasks/__init__.py",
    "backend/oj_modules/tasks/agent/__init__.py",
    "backend/oj_modules/ai_detection/__init__.py",
    "backend/oj_modules/site_config/__init__.py",
)


def test_package_initializers_do_not_eagerly_import_implementations():
    for relative_path in PACKAGE_INITIALIZERS:
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
            module == "backend.oj_modules" or module.startswith("backend.oj_modules.")
            for module in imported_modules
        ), relative_path


def test_isolated_package_imports_leave_registries_and_implementations_unloaded():
    code = """
import sys
import backend.oj_modules.api
import backend.oj_modules.tasks
import backend.oj_modules.tasks.agent
import backend.oj_modules.ai_detection
import backend.oj_modules.site_config
for name in (
    'backend.oj_modules.api.registry',
    'backend.oj_modules.tasks.registry',
    'backend.oj_modules.tasks.agent.registry',
    'backend.oj_modules.tasks.agent.solve',
    'backend.oj_modules.ai_detection.detector',
):
    assert name not in sys.modules, name
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_legacy_package_initializers_have_no_lazy_compatibility_hook():
    for relative_path in (
        "backend/oj_modules/api/__init__.py",
        "backend/oj_modules/tasks/__init__.py",
        "backend/oj_modules/ai_detection/__init__.py",
        "backend/oj_modules/site_config/__init__.py",
    ):
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        assert not any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "__getattr__"
            for node in tree.body
        ), relative_path
