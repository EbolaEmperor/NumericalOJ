"""认证入口的结构化审计契约。"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, g

from oj_modules.routes import auth_routes


CLIENT_IP = "198.51.100.77"
PEER_IP = "127.0.0.2"
FORWARDED_PROXY_IP = "127.0.0.3"
USER_AGENT = "NumOJ-Audit-Browser/1.0"
CLIENT_HINT_BRANDS = '"NumOJ";v="1"'
CLIENT_HINT_PLATFORM = '"Linux"'
CLIENT_HINT_MOBILE = "?0"
AUTHORIZATION_SECRET = "Bearer audit-authorization-secret"
COOKIE_SECRET = "audit-cookie-secret"


@pytest.fixture
def app():
    application = Flask(__name__)
    application.config.update(SECRET_KEY="test-secret", TESTING=True)
    application.extensions["numericaloj_observability"] = {
        "trusted_proxy_networks": (ipaddress.ip_network("127.0.0.0/8"),),
    }
    application.add_url_rule(
        "/problems",
        endpoint="problem_core.problem_list",
        view_func=lambda: "problems",
    )
    application.register_blueprint(auth_routes.auth_bp)
    return application


@pytest.fixture
def audit_headers():
    return {
        "X-Forwarded-For": f"{CLIENT_IP}, {FORWARDED_PROXY_IP}",
        "User-Agent": USER_AGENT,
        "Sec-CH-UA": CLIENT_HINT_BRANDS,
        "Sec-CH-UA-Platform": CLIENT_HINT_PLATFORM,
        "Sec-CH-UA-Mobile": CLIENT_HINT_MOBILE,
        "Authorization": AUTHORIZATION_SECRET,
        "Cookie": f"tracking={COOKIE_SECRET}",
    }


def _connection_with_record(record=None):
    connection = MagicMock()
    cursor = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor
    cursor.fetchone.return_value = record
    return connection, cursor


def _audit_payload(
    emit_mock,
    *,
    action,
    outcome,
    reason,
    route,
    user=None,
    secrets=(),
):
    emit_mock.assert_called_once()
    args, payload = emit_mock.call_args
    assert args == ("auth",)
    assert payload["action"] == action
    assert payload["outcome"] == outcome
    assert payload["message"] == f"认证事件：{action}"
    assert payload["authentication"]["method"] == "password"
    assert payload["authentication"]["reason"] == reason
    assert payload["request"]["method"] == "POST"
    assert payload["request"]["route"] == route
    assert payload["request"]["endpoint"].startswith("auth.")
    assert payload["source"] == {
        "ip": CLIENT_IP,
        "peer_ip": PEER_IP,
        "forwarded": True,
        "forwarded_valid": True,
        "forwarded_for": [CLIENT_IP, FORWARDED_PROXY_IP],
    }
    assert payload["user_agent"] == {
        "original": USER_AGENT,
        "client_hints": {
            "brands": CLIENT_HINT_BRANDS,
            "platform": CLIENT_HINT_PLATFORM,
            "mobile": CLIENT_HINT_MOBILE,
        },
    }
    if user is not None:
        assert payload["user"] == user

    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert "password_hash" not in serialized
    assert "authorization" not in serialized.lower()
    assert "cookie" not in serialized.lower()
    for secret in (*secrets, AUTHORIZATION_SECRET, COOKIE_SECRET):
        assert secret not in serialized
    return payload


def test_audit_auth_records_allowlisted_request_and_user_metadata_only(app, audit_headers):
    password = "AuditPassword!1"
    code = "741852"
    email = "private-audit@example.invalid"
    password_hash = "private-password-hash"
    user = {
        "id": 23,
        "username": "alice",
        "is_admin": 1,
        "email": email,
        "password_hash": password_hash,
    }

    with app.test_request_context(
        "/login",
        method="POST",
        data={"username": "alice", "password": password, "code": code, "email": email},
        headers=audit_headers,
        environ_base={"REMOTE_ADDR": PEER_IP},
    ):
        g.numoj_request_id = "request-123"
        with patch.object(auth_routes, "emit_audit") as emit:
            auth_routes._audit_auth(
                "login",
                "success",
                user=user,
                password_rehashed=True,
            )

    payload = _audit_payload(
        emit,
        action="login",
        outcome="success",
        reason=None,
        route="/login",
        user={"id": 23, "name": "alice", "is_admin": True},
        secrets=(password, code, email, password_hash),
    )
    assert payload["request"]["id"] == "request-123"
    assert payload["authentication"]["password_rehashed"] is True


def test_audit_auth_is_fail_open_when_context_or_emitter_fails(app):
    with app.test_request_context("/login", method="POST"):
        with (
            patch.object(auth_routes, "request_audit_fields", side_effect=RuntimeError("down")),
            patch.object(auth_routes, "emit_audit") as emit,
        ):
            assert auth_routes._audit_auth("login", "success", username="alice") is None
            emit.assert_not_called()

        with (
            patch.object(auth_routes, "request_audit_fields", return_value={}),
            patch.object(auth_routes, "emit_audit", side_effect=OSError("socket down")) as emit,
        ):
            assert auth_routes._audit_auth("login", "success", username="alice") is None
            emit.assert_called_once()


def test_client_ip_uses_shared_trusted_proxy_resolution(app, audit_headers):
    with app.test_request_context(
        "/login",
        method="POST",
        headers=audit_headers,
        environ_base={"REMOTE_ADDR": PEER_IP},
    ):
        assert auth_routes._client_ip() == CLIENT_IP


def test_login_invalid_username_emits_failure_audit(app, audit_headers):
    password = "InvalidUsernamePassword!1"
    with (
        patch.object(auth_routes, "validate_username", return_value=(False, "bad name", "invalid")),
        patch.object(auth_routes, "render_template", return_value="invalid username"),
        patch.object(auth_routes, "emit_audit") as emit,
    ):
        response = app.test_client().post(
            "/login",
            data={"username": " bad name ", "password": password},
            headers=audit_headers,
            environ_base={"REMOTE_ADDR": PEER_IP},
        )

    assert response.status_code == 200
    _audit_payload(
        emit,
        action="login",
        outcome="failure",
        reason="invalid_username",
        route="/login",
        user={"name": "bad name"},
        secrets=(password,),
    )


def test_login_rate_limited_emits_denied_audit(app, audit_headers):
    password = "RateLimitedPassword!1"
    with (
        patch.object(auth_routes, "validate_username", return_value=(True, "alice", "")),
        patch.object(auth_routes, "rate_limit_hit", return_value=(False, 30)),
        patch.object(auth_routes, "render_template", return_value="rate limited"),
        patch.object(auth_routes, "emit_audit") as emit,
    ):
        response = app.test_client().post(
            "/login",
            data={"username": "alice", "password": password},
            headers=audit_headers,
            environ_base={"REMOTE_ADDR": PEER_IP},
        )

    assert response.status_code == 200
    _audit_payload(
        emit,
        action="login",
        outcome="denied",
        reason="rate_limited",
        route="/login",
        user={"name": "alice"},
        secrets=(password,),
    )


def test_login_invalid_credentials_emits_failure_without_user_record(app, audit_headers):
    password = "WrongPassword!1"
    email = "alice-private@example.invalid"
    old_hash = "private-old-hash"
    user_record = {
        "id": 31,
        "username": "alice",
        "is_admin": False,
        "email": email,
        "password_hash": old_hash,
    }
    with (
        patch.object(auth_routes, "validate_username", return_value=(True, "alice", "")),
        patch.object(auth_routes, "rate_limit_hit", return_value=(True, 0)),
        patch.object(auth_routes, "get_user_by_username", return_value=user_record),
        patch.object(auth_routes, "verify_password", return_value=(False, False)),
        patch.object(auth_routes, "render_template", return_value="invalid credentials"),
        patch.object(auth_routes, "emit_audit") as emit,
    ):
        response = app.test_client().post(
            "/login",
            data={"username": "alice", "password": password},
            headers=audit_headers,
            environ_base={"REMOTE_ADDR": PEER_IP},
        )

    assert response.status_code == 200
    _audit_payload(
        emit,
        action="login",
        outcome="failure",
        reason="invalid_credentials",
        route="/login",
        user={"name": "alice"},
        secrets=(password, email, old_hash),
    )


def test_login_success_upgrades_legacy_hash_and_audits_safe_metadata(app, audit_headers):
    password = "LegacyPassword!1"
    email = "legacy-private@example.invalid"
    old_hash = "legacy-private-hash"
    new_hash = "argon2-private-hash"
    user_record = {
        "id": 37,
        "username": "legacy-user",
        "is_admin": True,
        "email": email,
        "password_hash": old_hash,
    }
    client = app.test_client()
    with (
        patch.object(auth_routes, "validate_username", return_value=(True, "legacy-user", "")),
        patch.object(auth_routes, "rate_limit_hit", return_value=(True, 0)),
        patch.object(auth_routes, "get_user_by_username", return_value=user_record),
        patch.object(auth_routes, "verify_password", return_value=(True, True)),
        patch.object(auth_routes, "hash_password", return_value=new_hash),
        patch.object(auth_routes, "_update_password_hash") as update_hash,
        patch.object(auth_routes, "emit_audit") as emit,
    ):
        response = client.post(
            "/login",
            data={"username": "legacy-user", "password": password},
            headers=audit_headers,
            environ_base={"REMOTE_ADDR": PEER_IP},
        )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/problems")
    update_hash.assert_called_once_with(user_id=37, new_hash=new_hash)
    with client.session_transaction() as persisted_session:
        assert persisted_session["username"] == "legacy-user"
    payload = _audit_payload(
        emit,
        action="login",
        outcome="success",
        reason=None,
        route="/login",
        user={"id": 37, "name": "legacy-user", "is_admin": True},
        secrets=(password, email, old_hash, new_hash),
    )
    assert payload["authentication"]["password_rehashed"] is True


def test_register_success_audits_identity_without_credentials_or_email(app, audit_headers):
    password = "RegisterPassword!1"
    code = "192837"
    email = "register-private@example.invalid"
    password_hash = "register-private-hash"
    user_class = {"class_en": "C2026", "class_name": "2026"}
    verification = {"code": code, "expires_at": datetime.now() + timedelta(minutes=5)}
    connection, _cursor = _connection_with_record(verification)
    with (
        patch.object(auth_routes, "get_all_classes_except_admin", return_value=[user_class]),
        patch.object(auth_routes, "get_class_by_en", return_value=user_class),
        patch.object(auth_routes, "_verify_attempt_allowed", return_value=True),
        patch.object(auth_routes, "get_db_connection", return_value=connection),
        patch.object(auth_routes, "get_user_by_username", return_value=None),
        patch.object(auth_routes, "get_user_by_email", return_value=None),
        patch.object(auth_routes, "hash_password", return_value=password_hash),
        patch.object(auth_routes, "create_user", return_value=43) as create_user,
        patch.object(auth_routes, "emit_audit") as emit,
    ):
        response = app.test_client().post(
            "/register",
            data={
                "username": "new-user",
                "password": password,
                "email": email,
                "verification_code": code,
                "class": "C2026",
            },
            headers=audit_headers,
            environ_base={"REMOTE_ADDR": PEER_IP},
        )

    assert response.status_code == 302
    create_user.assert_called_once_with("new-user", password_hash, email, user_class)
    payload = _audit_payload(
        emit,
        action="register",
        outcome="success",
        reason=None,
        route="/register",
        user={"id": 43, "name": "new-user", "is_admin": False},
        secrets=(password, code, email, password_hash),
    )
    assert payload["authentication"]["account"] == {"class": "C2026"}


def test_forgot_password_success_reloads_user_and_audits_without_secrets(app, audit_headers):
    password = "ResetPassword!1"
    code = "563412"
    email = "reset-private@example.invalid"
    password_hash = "reset-private-hash"
    user = {
        "id": 47,
        "username": "reset-user",
        "is_admin": False,
        "email": email,
        "password_hash": "old-reset-private-hash",
    }
    record = {"code": code, "expires_at": datetime.now() + timedelta(minutes=5)}
    select_connection, _ = _connection_with_record(record)
    delete_connection, delete_cursor = _connection_with_record()
    with (
        patch.object(auth_routes, "_verify_attempt_allowed", return_value=True),
        patch.object(
            auth_routes,
            "get_db_connection",
            side_effect=[select_connection, delete_connection],
        ),
        patch.object(auth_routes, "get_user_by_email", return_value=user) as get_user,
        patch.object(auth_routes, "hash_password", return_value=password_hash),
        patch.object(auth_routes, "_update_password_hash") as update_hash,
        patch.object(auth_routes, "emit_audit") as emit,
    ):
        response = app.test_client().post(
            f"/forgot_password?step=verify&email={email}",
            data={
                "code": code,
                "new_password": password,
                "confirm_password": password,
            },
            headers=audit_headers,
            environ_base={"REMOTE_ADDR": PEER_IP},
        )

    assert response.status_code == 302
    get_user.assert_called_once_with(email)
    update_hash.assert_called_once_with(email=email, new_hash=password_hash)
    delete_cursor.execute.assert_called_once_with(
        "DELETE FROM verification_codes WHERE email = %s",
        (email,),
    )
    delete_connection.commit.assert_called_once_with()
    _audit_payload(
        emit,
        action="password.reset",
        outcome="success",
        reason=None,
        route="/forgot_password",
        user={"id": 47, "name": "reset-user", "is_admin": False},
        secrets=(password, code, email, password_hash, user["password_hash"]),
    )


def test_change_password_success_audits_json_request_without_secrets(app, audit_headers):
    password = "ChangedPassword!1"
    code = "657483"
    email = "change-private@example.invalid"
    password_hash = "change-private-hash"
    user = {
        "id": 53,
        "username": "change-user",
        "is_admin": False,
        "email": email,
        "password_hash": "old-change-private-hash",
    }
    record = {"code": code, "expires_at": datetime.now() + timedelta(minutes=5)}
    select_connection, _ = _connection_with_record(record)
    delete_connection, delete_cursor = _connection_with_record()
    client = app.test_client()
    with client.session_transaction() as current_session:
        current_session["username"] = "change-user"
    request_headers = {**audit_headers, "Accept": "application/json"}
    with (
        patch.object(auth_routes, "get_current_user", return_value=user),
        patch.object(auth_routes, "_verify_attempt_allowed", return_value=True),
        patch.object(
            auth_routes,
            "get_db_connection",
            side_effect=[select_connection, delete_connection],
        ),
        patch.object(auth_routes, "hash_password", return_value=password_hash),
        patch.object(auth_routes, "_update_password_hash") as update_hash,
        patch.object(auth_routes, "emit_audit") as emit,
    ):
        response = client.post(
            "/change_password",
            data={
                "code": code,
                "new_password": password,
                "confirm_password": password,
            },
            headers=request_headers,
            environ_base={"REMOTE_ADDR": PEER_IP},
        )

    assert response.status_code == 200
    assert response.get_json() == {"success": True, "message": "密码修改成功"}
    update_hash.assert_called_once_with(user_id=53, new_hash=password_hash)
    delete_cursor.execute.assert_called_once_with(
        "DELETE FROM verification_codes WHERE email = %s",
        (email,),
    )
    delete_connection.commit.assert_called_once_with()
    _audit_payload(
        emit,
        action="password.change",
        outcome="success",
        reason=None,
        route="/change_password",
        user={"id": 53, "name": "change-user", "is_admin": False},
        secrets=(password, code, email, password_hash, user["password_hash"]),
    )


@pytest.mark.parametrize(
    ("session_username", "outcome", "reason", "expected_user"),
    [
        ("logout-user", "success", None, {"name": "logout-user"}),
        (None, "unknown", "no_session", None),
    ],
)
def test_logout_audits_with_and_without_session(
    app,
    audit_headers,
    session_username,
    outcome,
    reason,
    expected_user,
):
    client = app.test_client()
    if session_username:
        with client.session_transaction() as current_session:
            current_session["username"] = session_username
    with patch.object(auth_routes, "emit_audit") as emit:
        response = client.post(
            "/logout",
            headers=audit_headers,
            environ_base={"REMOTE_ADDR": PEER_IP},
        )

    assert response.status_code == 302
    payload = _audit_payload(
        emit,
        action="logout",
        outcome=outcome,
        reason=reason,
        route="/logout",
        user=expected_user,
    )
    if expected_user is None:
        assert "user" not in payload
    with client.session_transaction() as persisted_session:
        assert "username" not in persisted_session


def test_send_verification_code_logs_fixed_exception_message_without_printing():
    email = "smtp-private@example.invalid"
    smtp_secret = "smtp-private-failure-detail"
    connection, _ = _connection_with_record()
    smtp_context = MagicMock()
    smtp_context.__enter__.return_value.login.side_effect = RuntimeError(smtp_secret)

    with (
        patch.object(auth_routes, "get_db_connection", return_value=connection),
        patch.object(auth_routes.smtplib, "SMTP_SSL", return_value=smtp_context),
        patch.object(auth_routes.logger, "exception") as log_exception,
        patch("builtins.print") as print_mock,
    ):
        assert auth_routes.send_verification_code(email, "测试验证码") is False

    log_exception.assert_called_once_with("验证码邮件发送失败")
    assert smtp_secret not in str(log_exception.call_args)
    print_mock.assert_not_called()
