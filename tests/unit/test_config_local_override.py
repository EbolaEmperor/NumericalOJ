import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def _run_config_import(tmp_path, *, local_source=None, expression="None"):
    shutil.copy2(ROOT / "config.py", tmp_path / "config.py")
    if local_source is not None:
        (tmp_path / "config_local.py").write_text(
            local_source,
            encoding="utf-8",
        )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(tmp_path)
    return subprocess.run(
        [sys.executable, "-c", f"import config; print({expression})"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_config_imports_without_local_override(tmp_path):
    result = _run_config_import(
        tmp_path,
        expression="(config.MYSQL_USERNAME, config.LOCAL_CONFIG_LOADED)",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "('oj', False)"


def test_config_local_overrides_tracked_defaults(tmp_path):
    result = _run_config_import(
        tmp_path,
        local_source=(
            "MYSQL_USERNAME = 'production-user'\n"
            "CUSTOM_PRODUCTION_SETTING = ['kept-local']\n"
        ),
        expression=(
            "(config.MYSQL_USERNAME, config.CUSTOM_PRODUCTION_SETTING, "
            "config.LOCAL_CONFIG_LOADED)"
        ),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "('production-user', ['kept-local'], True)"
    )
    pycache = tmp_path / "__pycache__"
    assert not list(pycache.glob("config_local*.pyc"))


def test_config_local_import_errors_are_not_hidden(tmp_path):
    result = _run_config_import(
        tmp_path,
        local_source="import missing_production_config_dependency\n",
    )

    assert result.returncode != 0
    assert "missing_production_config_dependency" in result.stderr
