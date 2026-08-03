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


def _code_default_keys():
    tree = ast.parse((ROOT / "config.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "_CODE_DEFAULTS"
        ):
            return set(ast.literal_eval(node.value))
    raise AssertionError("config.py 缺少 _CODE_DEFAULTS")


def test_runtime_configuration_documents_every_advanced_default():
    documentation = (ROOT / "docs" / "runtime-configuration.md").read_text(
        encoding="utf-8"
    )
    missing = {
        key for key in _code_default_keys()
        if f"`{key}`" not in documentation
    }

    assert missing == set()


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
    for key in _template_keys() | _code_default_keys():
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


def test_config_imports_code_defaults_without_private_env(tmp_path):
    result = _run_config_import(
        tmp_path,
        expression=(
            "(config.MYSQL_USERNAME, config.ENV_FILE_LOADED, "
            "type(config.RANKING_BATCH_CLONE_TIMEOUT).__name__, "
            "config.SESSION_COOKIE_SECURE)"
        ),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "('oj', False, 'int', False)"


def test_logging_code_defaults_are_strictly_typed(tmp_path):
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


def test_business_and_unknown_env_keys_are_ignored(tmp_path):
    result = _run_config_import(
        tmp_path,
        env_source=(
            'MAIL_SERVER="legacy.example"\n'
            'DASHSCOPE_API_KEY="legacy-secret"\n'
            'REPOSITORY_EMBEDDING_PROVIDER="legacy-provider"\n'
            'CUSTOM_PRODUCTION_SETTING="ignored"\n'
            'UNKNOWN_WITH_BROKEN_QUOTE="ignored too\n'
        ),
        process_overrides={
            "QWEN_TEXT_MODEL": "legacy-model",
            "MODELSCOPE_WEB_SEARCH_MCP_BASE_URL": "https://legacy.invalid",
        },
        expression=(
            "(hasattr(config, 'MAIL_SERVER'), "
            "hasattr(config, 'DASHSCOPE_API_KEY'), "
            "hasattr(config, 'REPOSITORY_EMBEDDING_PROVIDER'), "
            "hasattr(config, 'QWEN_TEXT_MODEL'), "
            "hasattr(config, 'MODELSCOPE_WEB_SEARCH_MCP_BASE_URL'), "
            "hasattr(config, 'CUSTOM_PRODUCTION_SETTING'), "
            "sorted(config.ENV_FILE_KEYS))"
        ),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "(False, False, False, False, False, False, [])"


def test_env_overrides_are_typed_and_special_characters_are_literal(tmp_path):
    password = '  pa#ss=word$HOME\\tail"  '
    env_source = "\n".join(
        (
            'MYSQL_USERNAME="production-user"',
            f"MYSQL_PASSWORD={json.dumps(password)}",
            "SESSION_COOKIE_SECURE=true",
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
            "(config.MYSQL_USERNAME, config.MYSQL_PASSWORD, "
            "config.SESSION_COOKIE_SECURE, "
            "config.AGENT_REPOSITORY_KNN_SCORE_THRESHOLD, "
            "config.CSRF_TRUSTED_ORIGINS, "
            "hasattr(config, 'CUSTOM_PRODUCTION_SETTING'), "
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
        True,
        0.25,
        ["https://oj.example", "https://admin.example"],
        False,
        None,
        True,
        sorted(
            {
                "MYSQL_USERNAME",
                "MYSQL_PASSWORD",
                "SESSION_COOKIE_SECURE",
                "AGENT_REPOSITORY_KNN_SCORE_THRESHOLD",
                "CSRF_TRUSTED_ORIGINS",
                "CONTENT_SECURITY_POLICY",
            }
        ),
        password,
    )


def test_process_environment_has_priority_over_env_file(tmp_path):
    result = _run_config_import(
        tmp_path,
        env_source='MYSQL_USERNAME="file-user"\nSESSION_COOKIE_SECURE=false\n',
        process_overrides={
            "MYSQL_USERNAME": "process-user",
            "MYSQL_PASSWORD": "true",
            "SESSION_COOKIE_SECURE": "true",
        },
        expression=(
            "(config.MYSQL_USERNAME, config.MYSQL_PASSWORD, "
            "config.SESSION_COOKIE_SECURE)"
        ),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "('process-user', 'true', True)"


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
            "SESSION_COOKIE_SECURE=not-a-bool-secret\n",
            "SESSION_COOKIE_SECURE",
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


def test_template_contains_exactly_the_nine_deployment_keys():
    assert _template_keys() == {
        "SECRET_KEY",
        "MYSQL_HOST",
        "MYSQL_PORT",
        "MYSQL_DB",
        "MYSQL_USERNAME",
        "MYSQL_PASSWORD",
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_DB",
    }


def test_every_typed_config_key_is_declared():
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

    assert referenced <= (_template_keys() | _code_default_keys())
    assert not (_template_keys() & _code_default_keys())


def test_private_env_is_ignored_but_template_is_not():
    ignore_lines = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert ".env" in ignore_lines
    assert ".env.tmpl" not in ignore_lines
