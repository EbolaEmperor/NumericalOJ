from flask import Flask, session

from oj_modules.security import auth
from oj_modules.security.agent_identity import (
    AGENT_IDENTITY_HEADER,
    create_agent_identity_capability,
    resolve_agent_identity_capability,
    verify_agent_identity_capability,
)


def _app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "agent-identity-test"
    return app


def test_agent_identity_capability_is_bound_to_username_and_role():
    token = create_agent_identity_capability("admin", "user")

    assert verify_agent_identity_capability(
        token,
        session_username="admin",
    ) == "user"
    assert verify_agent_identity_capability(
        token,
        session_username="another-admin",
    ) is False
    assert verify_agent_identity_capability(
        token + "tampered",
        session_username="admin",
    ) is False


def test_current_user_downscopes_only_a_valid_user_capability(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {"id": 7, "username": username, "is_admin": 1},
    )
    app = _app()

    user_token = create_agent_identity_capability("admin", "user")
    with app.test_request_context(
        "/api/problems",
        headers={AGENT_IDENTITY_HEADER: user_token},
    ):
        session["username"] = "admin"
        assert auth.current_user() == {
            "id": 7,
            "username": "admin",
            "is_admin": 0,
            "agent_access_role": "user",
        }

    admin_token = create_agent_identity_capability("admin", "admin")
    with app.test_request_context(
        "/api/admin/users",
        headers={AGENT_IDENTITY_HEADER: admin_token},
    ):
        session["username"] = "admin"
        assert auth.current_user()["is_admin"] == 1
        assert auth.current_user()["agent_access_role"] == "admin"


def test_invalid_agent_identity_header_fails_closed(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {"username": username, "is_admin": 1},
    )
    app = _app()
    with app.test_request_context(
        "/api/admin/users",
        headers={AGENT_IDENTITY_HEADER: "not-a-signed-capability"},
    ):
        session["username"] = "admin"
        assert auth.current_user() is None


def test_browser_session_without_agent_header_keeps_normal_permissions(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {"username": username, "is_admin": 1},
    )
    app = _app()
    with app.test_request_context("/admin/agent_tasks"):
        session["username"] = "admin"
        assert auth.current_user() == {"username": "admin", "is_admin": 1}


def test_task_capability_authenticates_only_its_active_database_binding(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {"id": 7, "username": username, "is_admin": 1},
    )
    active = {
        "session_id": "session-1",
        "current_task_id": "task-2",
        "requested_by": "admin",
        "access_role": "admin",
        "status": "Running",
    }
    monkeypatch.setattr(
        "oj_modules.agents.sessions.get_agent_session",
        lambda session_id: active if session_id == "session-1" else None,
    )
    token = create_agent_identity_capability(
        "admin",
        "admin",
        session_id="session-1",
        task_id="task-2",
    )
    resolved = resolve_agent_identity_capability(token)
    assert resolved["session_id"] == "session-1"
    assert resolved["task_id"] == "task-2"

    app = _app()
    with app.test_request_context(
        "/api/admin/users",
        headers={AGENT_IDENTITY_HEADER: token},
    ):
        assert auth.current_user()["username"] == "admin"
        assert auth.current_user()["agent_access_role"] == "admin"

    active["status"] = "Completed"
    with app.test_request_context(
        "/api/admin/users",
        headers={AGENT_IDENTITY_HEADER: token},
    ):
        assert auth.current_user() is None


def test_task_capability_rechecks_current_admin_permission(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {"id": 7, "username": username, "is_admin": 0},
    )
    monkeypatch.setattr(
        "oj_modules.agents.sessions.get_agent_session",
        lambda _session_id: {
            "current_task_id": "task-2",
            "requested_by": "admin",
            "access_role": "admin",
            "status": "Running",
        },
    )
    token = create_agent_identity_capability(
        "admin",
        "admin",
        session_id="session-1",
        task_id="task-2",
    )
    app = _app()
    with app.test_request_context(
        "/api/admin/users",
        headers={AGENT_IDENTITY_HEADER: token},
    ):
        assert auth.current_user() is None
