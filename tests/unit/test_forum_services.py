# -*- coding: utf-8 -*-

from __future__ import annotations

import uuid
from datetime import datetime

import pymysql
import pytest
from flask import Flask

from oj_modules import forum_services
from oj_modules.api import forum_api
from oj_modules.forum_services import (
    ForumConflictError,
    ForumValidationError,
    _claim_create_receipt,
    _claim_edit_receipt,
    _existing_thread_by_request,
    _list_where,
    normalize_client_request_id,
    render_forum_markdown,
    serialize_reply,
    serialize_thread,
)


def test_client_request_id_requires_canonical_uuid():
    value = str(uuid.uuid4())
    assert normalize_client_request_id(value) == value

    with pytest.raises(ForumValidationError):
        normalize_client_request_id("not-a-uuid")
    assert normalize_client_request_id(value.upper()) == value
    with pytest.raises(ForumValidationError):
        normalize_client_request_id(f"{{{value}}}")


def test_public_serializers_do_not_expose_identity_mapping():
    row = {
        "id": 7,
        "thread_id": 3,
        "title": "标题",
        "content": "正文",
        "created_at": datetime(2026, 1, 1),
        "updated_at": datetime(2026, 1, 2),
        "edit_version": 2,
        "author_user_id": 42,
        "anonymous_identity_id": 99,
        "display_name": "匿名甲",
        "reply_count": 4,
    }
    thread = serialize_thread(row, 42, include_content=True)
    reply = serialize_reply(row, 42)

    for public in (thread, reply):
        assert public["display_name"] == "匿名甲"
        assert public["is_anonymous"] is True
        assert public["is_owner"] is True
        assert "author_user_id" not in public
        assert "user_id" not in public
        assert "anonymous_identity_id" not in public
        assert "username" not in public


def test_list_serializer_uses_matching_reply_excerpt():
    row = {
        "id": 7,
        "title": "主题",
        "content": "主题正文",
        "display_name": "alice",
        "author_user_id": 1,
        "matching_reply_content": "回复里命中的关键内容",
    }
    public = serialize_thread(row, 1, include_content=False)
    assert public["excerpt"] == "回复里命中的关键内容"
    assert public["match_source"] == "reply"


def test_forum_markdown_is_sanitized_and_images_are_removed():
    rendered = render_forum_markdown(
        "公式 $x^2$\n\n![追踪像素](https://tracker.invalid/pixel.png)"
        "\n\n<img src=https://tracker.invalid/raw.png onerror=alert(1)>"
        "\n\n<script>alert(1)</script>"
    )

    assert "$x^2$" in rendered
    assert "<img" not in rendered.lower()
    assert "<script" not in rendered.lower()


def test_forum_markdown_preserves_inline_and_block_latex_delimiters():
    rendered = render_forum_markdown(
        r"行内 \(x_i^2 < y\)；块级：\[\frac{a_b}{c_d}\]"
    )
    assert r"\(x_i^2 &lt; y\)" in rendered
    assert r"\[\frac{a_b}{c_d}\]" in rendered


def test_search_sql_only_matches_real_name_for_real_posts():
    sql, params = _list_where("all", "Alice", 1)

    assert "t.anonymous_identity_id IS NULL" in sql
    assert "thread_user.username LIKE" in sql
    assert "search_reply.anonymous_identity_id IS NULL" in sql
    assert "search_user.username LIKE" in sql
    assert "thread_identity.display_name LIKE" in sql
    assert "search_identity.user_id = search_reply.user_id" in sql
    assert len(params) == 7


def test_public_identity_joins_always_include_the_real_owner_key():
    assert "thread_identity.user_id = t.user_id" in forum_services._THREAD_SELECT
    assert "reply_identity.user_id = r.user_id" in forum_services._REPLY_SELECT_BASE
    list_source = forum_services.list_threads.__code__.co_consts
    list_sql = "\n".join(value for value in list_source if isinstance(value, str))
    assert "thread_identity.user_id = t.user_id" in list_sql


def test_mine_scope_includes_authored_and_replied_threads():
    sql, params = _list_where("mine", "", 17)
    assert "t.user_id = %s" in sql
    assert "mine_reply.user_id = %s" in sql
    assert params == [17, 17]


class _ReceiptRaceCursor:
    def __init__(self, receipt):
        self.receipt = receipt
        self.statements = []
        self._select_count = 0

    def execute(self, sql, params=None):
        statement = " ".join(str(sql).split())
        self.statements.append((statement, params))
        if statement.startswith("INSERT INTO forum_"):
            raise pymysql.err.IntegrityError(1062, "duplicate")
        if statement.startswith("SELECT"):
            self._select_count += 1

    def fetchone(self):
        if self._select_count == 1:
            return None
        return dict(self.receipt)


def test_create_receipt_duplicate_race_uses_locking_current_read():
    fingerprint = "a" * 64
    cursor = _ReceiptRaceCursor(
        {
            "request_fingerprint": fingerprint,
            "result_id": 17,
            "result_created_at": datetime(2026, 1, 1),
        }
    )

    receipt = _claim_create_receipt(
        cursor,
        user_id=3,
        operation_kind="thread",
        client_request_id=str(uuid.uuid4()),
        fingerprint=fingerprint,
    )

    assert receipt["result_id"] == 17
    assert cursor.statements[-1][0].endswith("FOR UPDATE")


def test_edit_receipt_duplicate_payload_conflicts():
    cursor = _ReceiptRaceCursor(
        {
            "target_id": 7,
            "request_fingerprint": "old",
            "result_version": 2,
            "result_updated_at": datetime(2026, 1, 1),
            "result_changed": 1,
        }
    )

    with pytest.raises(ForumConflictError, match="另一项编辑"):
        _claim_edit_receipt(
            cursor,
            user_id=3,
            operation_kind="thread",
            client_request_id=str(uuid.uuid4()),
            target_id=7,
            fingerprint="new",
        )
    assert cursor.statements[-1][0].endswith("FOR UPDATE")


class _OneRowCursor:
    def __init__(self):
        self.statement = ""

    def execute(self, sql, _params=None):
        self.statement = " ".join(str(sql).split())

    def fetchone(self):
        return {"id": 1, "title": "已编辑", "content": "当前正文"}


def test_legacy_duplicate_lookup_can_be_forced_to_current_read():
    cursor = _OneRowCursor()
    _existing_thread_by_request(
        cursor,
        1,
        str(uuid.uuid4()),
        for_update=True,
    )
    assert cursor.statement.endswith("FOR UPDATE")


def test_create_replay_reconstructs_original_payload_not_edited_body(
    monkeypatch,
):
    monkeypatch.setattr(
        forum_services,
        "get_thread_detail",
        lambda *_args, **_kwargs: {
            "thread": {
                "id": 7,
                "title": "后来标题",
                "content": "后来正文",
                "rendered_content": "later",
                "edit_version": 4,
                "is_edited": True,
                "created_at": datetime(2026, 1, 1),
            }
        },
    )
    result = forum_services._thread_result_for_create(
        1,
        7,
        title="最初标题",
        content="最初正文",
        receipt={
            "result_id": 7,
            "result_created_at": datetime(2026, 1, 1),
        },
    )
    assert result["title"] == "最初标题"
    assert result["content"] == "最初正文"
    assert result["edit_version"] == 1
    assert result["is_edited"] is False


@pytest.fixture
def forum_client(monkeypatch):
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(forum_api.forum_api_bp)
    monkeypatch.setattr(forum_api, "current_user", lambda: {"id": 8, "username": "alice"})
    return app.test_client()


def test_create_thread_api_requires_json_and_passes_uuid(forum_client, monkeypatch):
    captured = {}

    def fake_create(user_id, **payload):
        captured.update(user_id=user_id, **payload)
        return {"id": 12, "title": payload["title"]}, True

    monkeypatch.setattr(forum_api, "create_thread", fake_create)
    request_id = str(uuid.uuid4())
    response = forum_client.post(
        "/api/forum/threads",
        json={
            "title": "主题",
            "content": "内容",
            "client_request_id": request_id,
            "expected_identity_token": "p1_token",
        },
    )

    assert response.status_code == 201
    assert response.get_json()["success"] is True
    assert captured == {
        "user_id": 8,
        "title": "主题",
        "content": "内容",
        "client_request_id": request_id,
        "expected_identity_token": "p1_token",
        "token_secret": "test",
    }


def test_posting_identity_change_is_public_409_without_internal_mapping(
    forum_client,
    monkeypatch,
):
    def changed(*_args, **_kwargs):
        raise forum_api.PostingIdentityConflictError("发布身份已变化")

    monkeypatch.setattr(forum_api, "create_thread", changed)
    response = forum_client.post(
        "/api/forum/threads",
        json={
            "title": "主题",
            "content": "正文",
            "client_request_id": str(uuid.uuid4()),
            "expected_identity_token": "p1_stale",
        },
    )
    payload = response.get_json()
    assert response.status_code == 409
    assert payload == {
        "success": False,
        "message": "发布身份已变化",
        "code": "posting_identity_changed",
    }


def test_edit_conflict_is_returned_as_409(forum_client, monkeypatch):
    def conflict(*_args, **_kwargs):
        raise ForumConflictError("内容已更新", current_version=4)

    monkeypatch.setattr(forum_api, "edit_reply", conflict)
    response = forum_client.patch(
        "/api/forum/replies/9",
        json={"content": "新内容", "edit_version": 3},
    )

    assert response.status_code == 409
    assert response.get_json() == {
        "success": False,
        "message": "内容已更新",
        "current_version": 4,
    }


def test_edit_api_forwards_client_request_id(forum_client, monkeypatch):
    captured = {}

    def fake_edit(user_id, reply_id, **payload):
        captured.update(user_id=user_id, reply_id=reply_id, **payload)
        return {"id": reply_id, "content": payload["content"]}

    monkeypatch.setattr(forum_api, "edit_reply", fake_edit)
    request_id = str(uuid.uuid4())
    response = forum_client.patch(
        "/api/forum/replies/9",
        json={
            "content": "新内容",
            "edit_version": 3,
            "client_request_id": request_id,
        },
    )

    assert response.status_code == 200
    assert captured == {
        "user_id": 8,
        "reply_id": 9,
        "content": "新内容",
        "edit_version": 3,
        "client_request_id": request_id,
    }


def test_public_identity_shape_hides_all_internal_ids():
    public = forum_api._public_identity(
        {
            "user_id": 8,
            "real_username": "alice",
            "use_anonymous": True,
            "anonymous_identity": {
                "id": 77,
                "display_name": "匿名甲",
                "avatar": {"cells": [1]},
            },
            "effective_identity": {
                "kind": "anonymous",
                "display_name": "匿名甲",
                "anonymous_identity_id": 77,
            },
            "refresh_available_at": "2026-01-02T00:00:00Z",
            "refresh_retry_after_seconds": 30,
            "can_refresh": False,
        },
        "test-secret",
    )

    assert public["real_name"] == "alice"
    assert public["anonymous_name"] == "匿名甲"
    assert public["posting_name"] == "匿名甲"
    assert public["cooldown_remaining_seconds"] == 30
    assert "user_id" not in public
    assert "anonymous_identity_id" not in public
    assert public["draft_namespace"].startswith("d1_")
    assert public["posting_token"].startswith("p1_")


def test_anonymous_identity_api_forwards_idempotency_key(
    forum_client,
    monkeypatch,
):
    captured = {}

    def fake_rotate(user_id, display_name, **payload):
        captured.update(
            user_id=user_id,
            display_name=display_name,
            **payload,
        )
        return {
            "user_id": user_id,
            "real_username": "alice",
            "use_anonymous": True,
            "anonymous_identity": {"id": 3, "display_name": display_name},
            "effective_identity": {
                "kind": "anonymous",
                "display_name": display_name,
            },
            "can_refresh": False,
        }

    monkeypatch.setattr(forum_api, "rotate_anonymous_identity", fake_rotate)
    request_id = str(uuid.uuid4())
    response = forum_client.post(
        "/api/forum/identity/anonymous",
        json={
            "display_name": "匿名甲",
            "enable": True,
            "client_request_id": request_id,
        },
    )

    assert response.status_code == 200
    assert captured == {
        "user_id": 8,
        "display_name": "匿名甲",
        "enable": True,
        "client_request_id": request_id,
    }
