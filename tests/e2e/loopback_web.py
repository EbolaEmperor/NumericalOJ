# -*- coding: utf-8 -*-
"""E2E 专用 Flask 入口：只监听 loopback，且绝不启动 debug reloader。"""

from __future__ import annotations

import os


LOOPBACK_HOST = "127.0.0.1"
LOOPBACK_PORT = 2025
_FAKE_DYNAMIC_CONFIG_ENV = "NUMOJ_E2E_FAKE_DYNAMIC_CONFIG_TESTERS"


def _env_truthy(name: str) -> bool:
    return str(os.environ.get(name) or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _fake_smtp_result(candidate):
    """仅替代 SMTP 外部写入，并严格校验 CLI 传入的完整候选配置。"""

    password = str(candidate.get("smtp_password") or "")
    passed = (
        str(candidate.get("smtp_server") or "")
        in {"smtp.example.test", "smtp-updated.example.test"}
        and int(candidate.get("smtp_port") or 0) == 465
        and str(candidate.get("smtp_username") or "") == "mailer@example.test"
        and password.startswith("e2e-pass-smtp-")
        and str(candidate.get("recipient_email") or "") == "admin@example.com"
    )
    return {
        "passed": passed,
        "message": (
            "SMTP e2e probe passed"
            if passed
            else f"SMTP e2e probe rejected: {password}"
        ),
        "latency_ms": 1,
    }


def _configure_fake_dynamic_config_testers() -> None:
    if os.environ.get(_FAKE_DYNAMIC_CONFIG_ENV) != "1":
        return
    if _env_truthy("OJ_LIVE_AI"):
        raise RuntimeError(
            "OJ_LIVE_AI 真实 E2E 禁止启用动态配置测试替身"
        )

    from oj_modules.routes.admin_dynamic_config_routes import (
        configure_dynamic_config_testers,
    )

    configure_dynamic_config_testers(
        mail=_fake_smtp_result,
    )


def main() -> None:
    from oj import app, ensure_background_schedulers

    _configure_fake_dynamic_config_testers()
    app.config["DEBUG"] = False
    ensure_background_schedulers()
    app.run(
        host=LOOPBACK_HOST,
        port=LOOPBACK_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
