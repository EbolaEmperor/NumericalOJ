import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _template_keys():
    keys = set()
    for raw_line in (ROOT / ".env.tmpl").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys.add(line.split("=", 1)[0].strip())
    return keys


def _run_config_import(
    tmp_path,
    *,
    env_source=None,
    config_local_source=None,
    process_overrides=None,
    expression="None",
):
    shutil.copy2(ROOT / "config.py", tmp_path / "config.py")
    shutil.copy2(ROOT / ".env.tmpl", tmp_path / ".env.tmpl")
    if env_source is not None:
        (tmp_path / ".env").write_text(env_source, encoding="utf-8")
    if config_local_source is not None:
        (tmp_path / "config_local.py").write_text(
            config_local_source,
            encoding="utf-8",
        )
    environment = os.environ.copy()
    for key in _template_keys():
        environment.pop(key, None)
    environment.update(process_overrides or {})
    environment["PYTHONPATH"] = str(tmp_path)
    return subprocess.run(
        [sys.executable, "-B", "-c", f"import config; print({expression})"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_config_imports_template_defaults_without_private_env(tmp_path):
    result = _run_config_import(
        tmp_path,
        expression=(
            "(config.MYSQL_USERNAME, config.ENV_FILE_LOADED, "
            "type(config.MAIL_PORT).__name__, config.AGENT_MEMORY_ENABLED)"
        ),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "('oj', False, 'int', True)"


def test_logging_config_template_defaults_are_strictly_typed(tmp_path):
    result = _run_config_import(
        tmp_path,
        expression=(
            "(config.LOG_LEVEL, config.LOG_TRUSTED_PROXY_CIDRS, "
            "type(config.LOG_LEVEL).__name__, "
            "type(config.LOG_TRUSTED_PROXY_CIDRS).__name__)"
        ),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "('INFO', [], 'str', 'list')"


def test_env_overrides_are_typed_and_special_characters_are_literal(tmp_path):
    password = '  pa#ss=word$HOME\\tail"  '
    env_source = "\n".join(
        (
            'MYSQL_USERNAME="production-user"',
            f"MYSQL_PASSWORD={json.dumps(password)}",
            "MAIL_PORT=2525",
            "AGENT_MEMORY_ENABLED=false",
            "AGENT_REPOSITORY_KNN_SCORE_THRESHOLD=0.25",
            'CSRF_TRUSTED_ORIGINS=["https://oj.example","https://admin.example"]',
            'CUSTOM_PRODUCTION_SETTING=["kept-local"]',
            "CONTENT_SECURITY_POLICY=  # use the application default",
            "",
        )
    )
    result = _run_config_import(
        tmp_path,
        env_source=env_source,
        expression=(
            "(config.MYSQL_USERNAME, config.MYSQL_PASSWORD, config.MAIL_PORT, "
            "config.AGENT_MEMORY_ENABLED, "
            "config.AGENT_REPOSITORY_KNN_SCORE_THRESHOLD, "
            "config.CSRF_TRUSTED_ORIGINS, config.CUSTOM_PRODUCTION_SETTING, "
            "config.CONTENT_SECURITY_POLICY, config.ENV_FILE_LOADED, "
            "sorted(config.ENV_FILE_KEYS), "
            "__import__('os').environ['MYSQL_PASSWORD'])"
        ),
    )

    assert result.returncode == 0, result.stderr
    values = ast.literal_eval(result.stdout.strip())
    assert values == (
        "production-user",
        password,
        2525,
        False,
        0.25,
        ["https://oj.example", "https://admin.example"],
        ["kept-local"],
        None,
        True,
        sorted(
            {
                "MYSQL_USERNAME",
                "MYSQL_PASSWORD",
                "MAIL_PORT",
                "AGENT_MEMORY_ENABLED",
                "AGENT_REPOSITORY_KNN_SCORE_THRESHOLD",
                "CSRF_TRUSTED_ORIGINS",
                "CUSTOM_PRODUCTION_SETTING",
                "CONTENT_SECURITY_POLICY",
            }
        ),
        password,
    )


def test_process_environment_has_priority_over_env_file(tmp_path):
    result = _run_config_import(
        tmp_path,
        env_source='MYSQL_USERNAME="file-user"\nAGENT_MEMORY_ENABLED=true\n',
        process_overrides={
            "MYSQL_USERNAME": "process-user",
            "MYSQL_PASSWORD": "true",
            "AGENT_MEMORY_ENABLED": "false",
        },
        expression=(
            "(config.MYSQL_USERNAME, config.MYSQL_PASSWORD, "
            "config.AGENT_MEMORY_ENABLED)"
        ),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "('process-user', 'true', False)"


def test_logging_process_environment_has_priority_over_env_file(tmp_path):
    result = _run_config_import(
        tmp_path,
        env_source=(
            'LOG_LEVEL="DEBUG"\n'
            'LOG_TRUSTED_PROXY_CIDRS=["10.0.0.0/8"]\n'
        ),
        process_overrides={
            "LOG_LEVEL": "WARNING",
            "LOG_TRUSTED_PROXY_CIDRS": '["192.0.2.0/24","2001:db8::/32"]',
        },
        expression="(config.LOG_LEVEL, config.LOG_TRUSTED_PROXY_CIDRS)",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "('WARNING', ['192.0.2.0/24', '2001:db8::/32'])"
    )


@pytest.mark.parametrize(
    "raw_value",
    (
        '["127.0.0.1/32", "2001:db8::/32"]',
        "[]",
    ),
)
def test_env_str_list_accepts_only_string_arrays(monkeypatch, raw_value):
    import config

    monkeypatch.setitem(config._config_values, "TEST_LOG_CIDRS", raw_value)

    assert config._env_str_list("TEST_LOG_CIDRS") == json.loads(raw_value)


@pytest.mark.parametrize("raw_value", ('"10.0.0.0/8"', '["10.0.0.0/8", 7]', '{}'))
def test_env_str_list_rejects_non_string_arrays(monkeypatch, raw_value):
    import config

    monkeypatch.setitem(config._config_values, "TEST_LOG_CIDRS", raw_value)

    with pytest.raises(ValueError, match="必须是 JSON 字符串数组"):
        config._env_str_list("TEST_LOG_CIDRS")


@pytest.mark.parametrize(
    ("env_source", "error_fragment", "secret_fragment"),
    (
        (
            "AGENT_MEMORY_ENABLED=not-a-bool-secret\n",
            "AGENT_MEMORY_ENABLED",
            "not-a-bool-secret",
        ),
        (
            "CSRF_TRUSTED_ORIGINS=not-a-list-secret\n",
            "CSRF_TRUSTED_ORIGINS",
            "not-a-list-secret",
        ),
        (
            "LOG_TRUSTED_PROXY_CIDRS=not-a-proxy-list-secret\n",
            "LOG_TRUSTED_PROXY_CIDRS",
            "not-a-proxy-list-secret",
        ),
        ("LATEX_OCR_STREAM_EMIT_INTERVAL=nan\n", "有限数字", "nan"),
        (
            'MYSQL_PASSWORD="unterminated-secret\n',
            "引号未闭合",
            "unterminated-secret",
        ),
        (
            "MYSQL_USERNAME=first\nMYSQL_USERNAME=second-secret\n",
            "重复配置项",
            "second-secret",
        ),
    ),
)
def test_invalid_env_fails_closed_without_echoing_values(
    tmp_path,
    env_source,
    error_fragment,
    secret_fragment,
):
    result = _run_config_import(tmp_path, env_source=env_source)

    assert result.returncode != 0
    assert error_fragment in result.stderr
    assert secret_fragment not in result.stderr


def test_legacy_config_local_is_not_executed(tmp_path):
    result = _run_config_import(
        tmp_path,
        config_local_source=(
            "raise RuntimeError('legacy-config-must-not-run')\n"
            "MYSQL_USERNAME = 'legacy-user'\n"
        ),
        expression="config.MYSQL_USERNAME",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "oj"
    pycache = tmp_path / "__pycache__"
    assert not list(pycache.glob("config_local*.pyc"))


def test_every_typed_config_key_exists_in_template():
    source = (ROOT / "config.py").read_text(encoding="utf-8")
    helper_names = {
        "_env_str",
        "_env_optional_str",
        "_env_int",
        "_env_float",
        "_env_bool",
        "_env_optional_bool",
        "_env_str_list",
    }
    referenced = {
        node.args[0].value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in helper_names
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }

    assert referenced <= _template_keys()


def test_private_env_is_ignored_but_template_is_not():
    ignore_lines = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert ".env" in ignore_lines
    assert ".env.tmpl" not in ignore_lines
