"""可观测性公共 API 的惰性框架边界与委托契约。"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from unittest.mock import MagicMock

from oj_modules import observability


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _fake_module(monkeypatch, module_name: str, function_name: str, result):
    module = ModuleType(module_name)
    implementation = MagicMock(return_value=result)
    setattr(module, function_name, implementation)
    monkeypatch.setitem(sys.modules, module_name, module)
    return implementation


def test_package_import_does_not_load_framework_integrations_or_config():
    script = """
import json
import sys
import oj_modules.observability

names = (
    "flask",
    "celery",
    "config",
    "oj_modules.observability.web",
    "oj_modules.observability.celery",
)
print(json.dumps({name: name in sys.modules for name in names}, sort_keys=True))
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout) == {
        "celery": False,
        "config": False,
        "flask": False,
        "oj_modules.observability.celery": False,
        "oj_modules.observability.web": False,
    }


def test_install_celery_observability_delegates_lazily(monkeypatch):
    install = _fake_module(
        monkeypatch,
        "oj_modules.observability.celery",
        "install_celery_observability",
        "celery-installed",
    )

    result = observability.install_celery_observability(
        "app",
        level="WARNING",
    )

    assert result == "celery-installed"
    install.assert_called_once_with("app", level="WARNING")


def test_install_flask_observability_delegates_lazily(monkeypatch):
    install = _fake_module(
        monkeypatch,
        "oj_modules.observability.web",
        "install_flask_observability",
        "flask-installed",
    )

    result = observability.install_flask_observability(
        "app",
        trusted_proxy_cidrs=("127.0.0.1/32",),
    )

    assert result == "flask-installed"
    install.assert_called_once_with(
        "app",
        trusted_proxy_cidrs=("127.0.0.1/32",),
    )


def test_client_ip_delegates_arguments_to_web_module(monkeypatch):
    resolve = _fake_module(
        monkeypatch,
        "oj_modules.observability.web",
        "client_ip",
        "192.0.2.7",
    )

    result = observability.client_ip("request", trusted=True)

    assert result == "192.0.2.7"
    resolve.assert_called_once_with("request", trusted=True)


def test_client_source_delegates_arguments_to_web_module(monkeypatch):
    resolve = _fake_module(
        monkeypatch,
        "oj_modules.observability.web",
        "client_source",
        {"client_ip": "192.0.2.7"},
    )

    result = observability.client_source("request", trusted_proxy_networks=())

    assert result == {"client_ip": "192.0.2.7"}
    resolve.assert_called_once_with("request", trusted_proxy_networks=())


def test_request_audit_fields_delegates_arguments_to_web_module(monkeypatch):
    resolve = _fake_module(
        monkeypatch,
        "oj_modules.observability.web",
        "request_audit_fields",
        {"request": {"method": "POST"}},
    )

    result = observability.request_audit_fields("request")

    assert result == {"request": {"method": "POST"}}
    resolve.assert_called_once_with("request")


def test_user_agent_metadata_delegates_arguments_to_web_module(monkeypatch):
    resolve = _fake_module(
        monkeypatch,
        "oj_modules.observability.web",
        "user_agent_metadata",
        {"user_agent": "Browser/1.0"},
    )

    result = observability.user_agent_metadata("request", include_hints=True)

    assert result == {"user_agent": "Browser/1.0"}
    resolve.assert_called_once_with("request", include_hints=True)


def test_public_exports_include_stable_logging_and_framework_entrypoints():
    assert set(observability.__all__) == {
        "EVENT_SOCKET",
        "LOG_ROOT",
        "SCHEMA_NAME",
        "SCHEMA_VERSION",
        "bind_context",
        "build_event_envelope",
        "client_ip",
        "client_source",
        "configure_logging",
        "configure_redaction",
        "content_fingerprint",
        "current_context",
        "emit_audit",
        "emit_event",
        "file_fingerprint",
        "install_celery_observability",
        "install_flask_observability",
        "redact_text",
        "request_audit_fields",
        "safe_file_fingerprint",
        "sanitize",
        "user_agent_metadata",
        "validate_event_payload",
    }
