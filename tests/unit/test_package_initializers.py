import ast
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_INITIALIZERS = (
    "oj_modules/api/__init__.py",
    "oj_modules/tasks/__init__.py",
    "oj_modules/tasks/agent/__init__.py",
    "oj_modules/ai_detection/__init__.py",
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
            module == "oj_modules" or module.startswith("oj_modules.")
            for module in imported_modules
        ), relative_path


def test_isolated_package_imports_leave_registries_and_implementations_unloaded():
    code = """
import sys
import oj_modules.api
import oj_modules.tasks
import oj_modules.tasks.agent
import oj_modules.ai_detection
for name in (
    'oj_modules.api.registry',
    'oj_modules.tasks.registry',
    'oj_modules.tasks.agent.registry',
    'oj_modules.tasks.agent.solve',
    'oj_modules.ai_detection.detector',
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
        "oj_modules/api/__init__.py",
        "oj_modules/tasks/__init__.py",
        "oj_modules/ai_detection/__init__.py",
    ):
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        assert not any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "__getattr__"
            for node in tree.body
        ), relative_path
