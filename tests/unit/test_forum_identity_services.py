# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime, timedelta
import uuid

import pytest

from oj_modules.forum import identity as identities


class _IdentityStore:
    def __init__(self):
        self.users = {1: "Alice", 2: "Bob"}
        self.anonymous_identities = []
        self.settings = {}
        self.identity_receipts = []
        self.next_identity_id = 1
        self.connections = []

    def connection(self):
        connection = _IdentityConnection(self)
        self.connections.append(connection)
        return connection


class _IdentityCursor:
    def __init__(self, store):
        self.store = store
        self.lastrowid = 0
        self._one = None
        self._all = []

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        return False

    def execute(self, sql, params=None):
        statement = " ".join(str(sql).split())
        self._one = None
        self._all = []

        if statement.startswith("SELECT GET_LOCK"):
            self._one = {"identity_namespace_locked": 1}
        elif statement.startswith("SELECT RELEASE_LOCK"):
            self._one = {"identity_namespace_released": 1}
        elif "FROM forum_identity_operation_receipts" in statement:
            user_id, request_id = int(params[0]), params[1]
            receipt = next(
                (
                    row
                    for row in self.store.identity_receipts
                    if row["user_id"] == user_id
                    and row["client_request_id"] == request_id
                ),
                None,
            )
            self._one = dict(receipt) if receipt else None
        elif "FROM users u LEFT JOIN forum_user_identity_settings" in statement:
            user_id = int(params[0])
            username = self.store.users.get(user_id)
            if username is None:
                return
            setting = self.store.settings.get(user_id)
            current_id = (
                setting["current_anonymous_identity_id"] if setting else None
            )
            anonymous = next(
                (
                    row
                    for row in self.store.anonymous_identities
                    if row["id"] == current_id and row["user_id"] == user_id
                ),
                None,
            )
            self._one = {
                "user_id": user_id,
                "real_username": username,
                "settings_user_id": user_id if setting else None,
                "use_anonymous": setting["use_anonymous"] if setting else 0,
                "current_anonymous_identity_id": current_id,
                "identity_changed_at": (
                    setting["identity_changed_at"] if setting else None
                ),
                "anonymous_identity_id": anonymous["id"] if anonymous else None,
                "anonymous_display_name": (
                    anonymous["display_name"] if anonymous else None
                ),
            }
        elif statement == "SELECT id, username FROM users":
            self._all = [
                {"id": user_id, "username": username}
                for user_id, username in self.store.users.items()
            ]
        elif statement.startswith(
            "SELECT id FROM forum_anonymous_identities "
        ):
            normalized_name = params[0]
            matching = next(
                (
                    row
                    for row in self.store.anonymous_identities
                    if row["normalized_name"] == normalized_name
                ),
                None,
            )
            self._one = {"id": matching["id"]} if matching else None
        elif statement.startswith(
            "INSERT INTO forum_anonymous_identities"
        ):
            identity_id = self.store.next_identity_id
            self.store.next_identity_id += 1
            self.store.anonymous_identities.append(
                {
                    "id": identity_id,
                    "user_id": int(params[0]),
                    "display_name": params[1],
                    "normalized_name": params[2],
                    "created_at": params[3],
                }
            )
            self.lastrowid = identity_id
        elif statement.startswith(
            "INSERT INTO forum_user_identity_settings"
        ):
            self.store.settings[int(params[0])] = {
                "use_anonymous": int(params[1]),
                "current_anonymous_identity_id": int(params[2]),
                "identity_changed_at": params[3],
            }
        elif statement.startswith(
            "UPDATE forum_user_identity_settings SET use_anonymous=%s,"
        ):
            setting = self.store.settings[int(params[3])]
            setting.update(
                {
                    "use_anonymous": int(params[0]),
                    "current_anonymous_identity_id": int(params[1]),
                    "identity_changed_at": params[2],
                }
            )
        elif statement.startswith(
            "UPDATE forum_user_identity_settings SET use_anonymous=%s WHERE"
        ):
            self.store.settings[int(params[1])]["use_anonymous"] = int(params[0])
        elif statement.startswith(
            "INSERT INTO forum_identity_operation_receipts"
        ):
            self.store.identity_receipts.append(
                {
                    "user_id": int(params[0]),
                    "client_request_id": params[1],
                    "display_name": params[2],
                    "normalized_name": params[3],
                    "requested_enable": params[4],
                    "anonymous_identity_id": int(params[5]),
                    "result_use_anonymous": int(params[6]),
                    "created_at": params[7],
                }
            )
        else:  # pragma: no cover - 新 SQL 必须显式加入 fake，避免测试静默漏测
            raise AssertionError(f"unexpected SQL: {statement}")

    def fetchone(self):
        result = self._one
        self._one = None
        return result

    def fetchall(self):
        result = self._all
        self._all = []
        return result


class _IdentityConnection:
    def __init__(self, store):
        self.store = store
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return _IdentityCursor(self.store)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class _ReleaseFailureCursor:
    def __init__(self):
        self._one = None

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        return False

    def execute(self, sql, _params=None):
        statement = " ".join(str(sql).split())
        if statement.startswith("SELECT GET_LOCK"):
            self._one = {"identity_namespace_locked": 1}
            return
        if statement.startswith("SELECT RELEASE_LOCK"):
            raise OSError("connection failed after commit")
        raise AssertionError(f"unexpected SQL: {statement}")

    def fetchone(self):
        return self._one


class _ReleaseFailureConnection:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0
        self.discards = 0
        self.closed = False

    def cursor(self):
        return _ReleaseFailureCursor()

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def discard(self):
        self.discards += 1

    def close(self):
        self.closed = True


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  Ａlice-1  ", "alice-1"),
        ("匿名甲", "匿名甲"),
        ("Straße", "straße"),  # 只折叠 ASCII，不把 ß 扩成 ss
    ],
)
def test_normalize_identity_name_uses_nfkc_trim_and_ascii_casefold(raw, expected):
    assert identities.normalize_identity_name(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected", "weight"),
    [
        ("  Owl_7  ", "Owl_7", 5),
        ("匿名甲", "匿名甲", 6),
        ("𠮷a", "𠮷a", 3),
        ("ＡＢ-1", "AB-1", 4),
    ],
)
def test_validate_anonymous_name_returns_nfkc_display_value(raw, expected, weight):
    cleaned = identities.validate_anonymous_name(raw)
    assert cleaned == expected
    assert identities.anonymous_name_weight(cleaned) == weight


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "不能为空"),
        ("abcdef中文甲", "不能超过 10"),
        ("有 空格", "只能包含"),
        ("dot.name", "只能包含"),
        ("emoji🙂", "只能包含"),
        ("\u200bhidden", "只能包含"),
    ],
)
def test_validate_anonymous_name_rejects_invalid_input(raw, message):
    with pytest.raises(identities.AnonymousNameValidationError, match=message):
        identities.validate_anonymous_name(raw)


@pytest.mark.parametrize("raw", ["admin", "SYSTEM", "ＮｕｍｅｒｉｃａｌＯＪ", "管理员"])
def test_validate_anonymous_name_rejects_reserved_names(raw):
    with pytest.raises(identities.IdentityNameReservedError):
        identities.validate_anonymous_name(raw)


def test_avatar_has_stable_browser_compatible_vector_and_horizontal_symmetry():
    cells = identities.avatar_presentation("Alice")["cells"]
    assert cells == [
        0, 7, 9, 11, 12, 14, 24, 25, 30, 31, 34, 35, 36, 37,
        43, 44, 49, 50, 51, 52, 53, 54, 56, 59, 60, 63,
    ]
    assert cells == sorted(set(cells))
    for cell in cells:
        row, column = divmod(cell, 8)
        assert row * 8 + (7 - column) in cells

    assert identities.avatar_presentation("匿名甲")["cells"] == [
        1, 3, 4, 6, 8, 9, 10, 13, 14, 15, 16, 18, 19, 20, 21, 23,
        24, 31, 32, 33, 34, 37, 38, 39, 40, 41, 46, 47, 48, 49,
        54, 55, 56, 57, 58, 61, 62, 63,
    ]


def test_namespace_check_blocks_real_and_historical_anonymous_names():
    store = _IdentityStore()
    store.anonymous_identities.append(
        {
            "id": 7,
            "user_id": 2,
            "display_name": "Old-Owl",
            "normalized_name": "old-owl",
            "created_at": datetime(2026, 1, 1),
        }
    )
    cursor = _IdentityCursor(store)

    with pytest.raises(identities.IdentityNameConflictError):
        identities.assert_identity_name_available(cursor, "ＡＬＩＣＥ")
    with pytest.raises(identities.IdentityNameConflictError):
        identities.assert_identity_name_available(cursor, "OLD-OWL")
    assert (
        identities.assert_identity_name_available(
            cursor,
            "alice",
            exclude_user_id=1,
        )
        == "alice"
    )


def test_first_identity_can_enable_anonymous_and_refresh_has_24_hour_cooldown(
    monkeypatch,
):
    store = _IdentityStore()
    monkeypatch.setattr(identities, "get_db_connection", store.connection)
    started_at = datetime(2026, 7, 25, 8, 0, 0)

    first = identities.rotate_anonymous_identity(
        1,
        "Owl-1",
        enable=True,
        client_request_id=str(uuid.uuid4()),
        now=started_at,
    )

    assert first["use_anonymous"] is True
    assert first["anonymous_identity"]["id"] == 1
    assert first["effective_identity"]["display_name"] == "Owl-1"
    assert first["can_refresh"] is False
    assert first["refresh_retry_after_seconds"] == 24 * 60 * 60
    assert len(store.anonymous_identities) == 1

    with pytest.raises(identities.AnonymousIdentityCooldownError) as caught:
        identities.rotate_anonymous_identity(
            1,
            "Owl-2",
            client_request_id=str(uuid.uuid4()),
            now=started_at + timedelta(hours=1),
        )
    assert caught.value.retry_after_seconds == 23 * 60 * 60
    assert len(store.anonymous_identities) == 1

    refreshed = identities.rotate_anonymous_identity(
        1,
        "Owl-2",
        client_request_id=str(uuid.uuid4()),
        now=started_at + timedelta(hours=24),
    )
    assert refreshed["anonymous_identity"]["id"] == 2
    assert refreshed["effective_identity"]["display_name"] == "Owl-2"
    assert [row["display_name"] for row in store.anonymous_identities] == [
        "Owl-1",
        "Owl-2",
    ]


def test_identity_rotation_retry_uses_receipt_before_cooldown(monkeypatch):
    store = _IdentityStore()
    monkeypatch.setattr(identities, "get_db_connection", store.connection)
    started_at = datetime(2026, 7, 25, 8, 0, 0)
    request_id = str(uuid.uuid4())

    first = identities.rotate_anonymous_identity(
        1,
        "Owl-1",
        enable=True,
        client_request_id=request_id,
        now=started_at,
    )
    replay = identities.rotate_anonymous_identity(
        1,
        "Owl-1",
        enable=True,
        client_request_id=request_id,
        now=started_at + timedelta(hours=1),
    )

    assert first["anonymous_identity"]["display_name"] == "Owl-1"
    assert replay["anonymous_identity"]["display_name"] == "Owl-1"
    assert len(store.anonymous_identities) == 1
    assert len(store.identity_receipts) == 1

    with pytest.raises(identities.IdentityOperationConflictError):
        identities.rotate_anonymous_identity(
            1,
            "Owl-2",
            enable=True,
            client_request_id=request_id,
            now=started_at + timedelta(hours=1),
        )


def test_identity_rotation_requires_uuid_before_writing(monkeypatch):
    store = _IdentityStore()
    monkeypatch.setattr(identities, "get_db_connection", store.connection)
    with pytest.raises(
        identities.ForumIdentityRequestValidationError,
        match="UUID",
    ):
        identities.rotate_anonymous_identity(
            1,
            "Owl-1",
            client_request_id="not-a-uuid",
        )
    assert store.connections == []
    assert store.anonymous_identities == []


def test_posting_token_is_opaque_stable_and_detects_mode_change(monkeypatch):
    store = _IdentityStore()
    monkeypatch.setattr(identities, "get_db_connection", store.connection)
    now = datetime(2026, 7, 25, 8, 0, 0)
    state = identities.rotate_anonymous_identity(
        1,
        "匿名甲",
        enable=False,
        client_request_id=str(uuid.uuid4()),
        now=now,
    )
    token = identities.posting_identity_token_from_state(state, "secret")
    assert token.startswith("p1_")
    assert "Alice" not in token
    draft_namespace = identities.draft_namespace_token(1, "secret")
    assert draft_namespace.startswith("d1_")
    assert draft_namespace == identities.draft_namespace_token(1, "secret")
    assert draft_namespace != identities.draft_namespace_token(2, "secret")

    connection = store.connection()
    with connection.cursor() as cursor:
        assert identities.resolve_posting_identity(
            cursor,
            1,
            expected_identity_token=token,
            token_secret="secret",
        ) is None

    identities.set_anonymous_mode(1, True, now=now)
    connection = store.connection()
    with connection.cursor() as cursor:
        with pytest.raises(identities.PostingIdentityConflictError):
            identities.resolve_posting_identity(
                cursor,
                1,
                expected_identity_token=token,
                token_secret="secret",
            )


def test_mode_toggle_persists_and_resolve_posting_identity_locks_current_choice(
    monkeypatch,
):
    store = _IdentityStore()
    monkeypatch.setattr(identities, "get_db_connection", store.connection)
    now = datetime(2026, 7, 25, 8, 0, 0)

    with pytest.raises(identities.AnonymousIdentityRequiredError):
        identities.set_anonymous_mode(1, True, now=now)

    created = identities.rotate_anonymous_identity(
        1,
        "匿名甲",
        enable=False,
        client_request_id=str(uuid.uuid4()),
        now=now,
    )
    assert created["use_anonymous"] is False

    enabled = identities.set_anonymous_mode(1, True, now=now)
    assert enabled["effective_identity"]["kind"] == "anonymous"
    posting_connection = store.connection()
    with posting_connection.cursor() as cursor:
        assert identities.resolve_posting_identity(cursor, 1) == 1

    disabled = identities.set_anonymous_mode(1, False, now=now)
    assert disabled["effective_identity"]["kind"] == "real"
    posting_connection = store.connection()
    with posting_connection.cursor() as cursor:
        assert identities.resolve_posting_identity(cursor, 1) is None


def test_committed_namespace_operation_is_not_reported_failed_when_unlock_breaks(
    monkeypatch,
):
    connection = _ReleaseFailureConnection()
    monkeypatch.setattr(identities, "get_db_connection", lambda: connection)

    result = identities.run_identity_namespace_transaction(
        lambda _cursor: {"created_id": 73}
    )

    assert result == {"created_id": 73}
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.discards == 1
    assert connection.closed is False
