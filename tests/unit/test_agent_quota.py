"""通用 Agent 额度领域的聚焦回归测试。"""

from __future__ import annotations

from decimal import Decimal

import pytest

from backend.oj_modules.agents import quota


def test_agent_quota_schema_is_part_of_incremental_schema_source():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    assert set(init_db_schema.REQUIRED_AGENT_QUOTA_TABLES) <= set(specs)
    assert (
        specs["agent_quota_accounts"].columns["granted_amount"].lower()
        == "decimal(30,14) not null default '0'"
    )
    assert (
        specs["agent_quota_requests"].columns["requested_amount"].lower()
        == "decimal(30,14) default null"
    )
    assert init_db_schema._column_needs_definition_change(
        "agent_quota_requests",
        "requested_amount",
        {"Type": "decimal(30,14)", "Null": "NO"},
        specs["agent_quota_requests"].columns["requested_amount"],
    ) is True
    assert init_db_schema._column_needs_definition_change(
        "agent_quota_requests",
        "requested_amount",
        {"Type": "decimal(30,14)", "Null": "YES"},
        specs["agent_quota_requests"].columns["requested_amount"],
    ) is False
    assert (
        specs["agent_quota_grants"].columns["amount"].lower()
        == "decimal(30,14) not null"
    )
    assert (
        specs["agent_usage_ledger"].columns["charged_amount"].lower()
        == "decimal(30,14) not null"
    )
    assert (
        specs["agent_usage_ledger"].columns["cached_fallback_request_count"].lower()
        == "bigint unsigned not null default '0'"
    )
    assert (
        specs["agent_usage_ledger"].columns["cached_fallback_input_tokens"].lower()
        == "bigint unsigned not null default '0'"
    )
    unique_event = specs["agent_usage_ledger"].indexes["uniq_agent_usage_event"]
    assert "(`task_id`,`source`,`usage_event_id`)" in unique_event

    compact = " ".join(
        init_db_schema.DATABASE_BOOTSTRAP_SQL.read_text(encoding="utf-8")
        .lower()
        .split()
    )
    assert (
        "constraint `fk_agent_usage_task` foreign key (`task_id`) references "
        "`agent_session_turns` (`task_id`) on delete restrict"
    ) in compact
    assert "check (`kind` in ('request_approval','manual_adjustment','class_batch'))" in compact


def test_usage_charge_uses_price_snapshot_and_adaptive_money_text():
    counts, prices, charged = quota.calculate_agent_usage_charge(
        {
            "input_uncached_tokens": 200_000,
            "input_cached_tokens": 700_000,
            "input_cache_write_tokens": 100_000,
            "output_tokens": 50_000,
            "reasoning_output_tokens": 20_000,
        },
        {
            "input_price_per_million": "2.00000000",
            "cached_input_price_per_million": "0.50000000",
            "output_price_per_million": "8.00000000",
        },
    )

    assert counts["input_cache_write_tokens"] == 100_000
    assert prices["input_price_per_million"] == Decimal("2.00000000000000")
    assert charged == Decimal("1.35000000000000")
    assert quota._money_text(charged) == "1.35"
    assert quota._money_text(Decimal("1.00000000000000")) == "1"
    assert quota._money_text(Decimal("10")) == "10"


def test_usage_charge_treats_invalid_cache_write_as_zero():
    counts, _prices, _charged = quota.calculate_agent_usage_charge(
        {
            "input_uncached_tokens": 10,
            "input_cached_tokens": 90,
            "input_cache_write_tokens": "invalid",
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
        },
        {
            "input_price_per_million": "1",
            "cached_input_price_per_million": "0.1",
            "output_price_per_million": "2",
        },
    )

    assert counts["input_cache_write_tokens"] == 0


def test_quota_request_payload_preserves_legacy_amount_and_allows_new_null():
    base = {"id": 9, "user_id": 7, "status": "pending"}

    assert quota._request_from_row(
        {**base, "requested_amount": Decimal("1.25000000000000")}
    )["requested_amount"] == "1.25"
    assert quota._request_from_row(
        {**base, "requested_amount": None}
    )["requested_amount"] is None


@pytest.mark.parametrize(
    "usage",
    [
        {
            "input_uncached_tokens": 1,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 1,
        },
        {
            "input_uncached_tokens": None,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
        },
    ],
)
def test_usage_charge_requires_all_token_fields_to_be_valid(usage):
    with pytest.raises(quota.AgentQuotaValidationError):
        quota.calculate_agent_usage_charge(
            usage,
            {
                "input_price_per_million": "1",
                "cached_input_price_per_million": "0.1",
                "output_price_per_million": "2",
            },
        )


def test_usage_charge_accepts_zero_token_request_as_zero_cost():
    counts, _prices, charged = quota.calculate_agent_usage_charge(
        {
            "input_uncached_tokens": 0,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 0,
            "reasoning_output_tokens": 0,
        },
        {
            "input_price_per_million": "1",
            "cached_input_price_per_million": "0.1",
            "output_price_per_million": "2",
        },
    )

    assert all(value == 0 for value in counts.values())
    assert charged == Decimal("0E-14")


class _ChargeStore:
    def __init__(self):
        self.account = {
            "user_id": 7,
            "granted_amount": Decimal("0"),
            "used_amount": Decimal("4.9"),
        }
        self.ledger = None
        self.ledger_inserts = 0
        self.account_updates = 0


class _ChargeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.result = None
        self.lastrowid = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql, params):
        normalized = " ".join(sql.split())
        store = self.connection.store
        self.result = None
        if normalized.startswith("SELECT * FROM agent_quota_accounts"):
            self.result = dict(store.account)
        elif normalized.startswith("SELECT * FROM agent_usage_ledger WHERE task_id="):
            self.result = dict(store.ledger) if store.ledger else None
        elif normalized.startswith("INSERT INTO agent_usage_ledger"):
            store.ledger_inserts += 1
            self.lastrowid = 1
            store.ledger = {
                "id": 1,
                "user_id": params[0],
                "session_id": params[1],
                "task_id": params[2],
                "source": params[3],
                "usage_event_id": params[4],
                "endpoint_id": params[5],
                "endpoint_revision": params[6],
                "endpoint_model": params[7],
                "input_uncached_tokens": params[8],
                "input_cached_tokens": params[9],
                "input_cache_write_tokens": params[10],
                "output_tokens": params[11],
                "reasoning_output_tokens": params[12],
                "input_price_per_million": params[13],
                "cached_input_price_per_million": params[14],
                "output_price_per_million": params[15],
                "charged_amount": params[16],
                "remaining_after": params[17],
                "cached_fallback_request_count": params[18],
                "cached_fallback_input_tokens": params[19],
            }
        elif normalized.startswith("UPDATE agent_quota_accounts SET used_amount="):
            store.account_updates += 1
            store.account["used_amount"] = params[0]
        elif normalized.startswith("SELECT * FROM agent_usage_ledger WHERE id="):
            self.result = dict(store.ledger)
        else:
            raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        return self.result


class _ChargeConnection:
    def __init__(self, store):
        self.store = store
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return _ChargeCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        pass


def _charge_once():
    return quota.charge_agent_usage(
        user_id=7,
        session_id="session-1",
        task_id="task-1",
        source="pi",
        usage_event_id="response-1",
        endpoint_id=3,
        endpoint_revision=2,
        endpoint_model="deepseek-v4-flash",
        usage={
            "input_uncached_tokens": 0,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 100_000,
            "reasoning_output_tokens": 0,
        },
        pricing={
            "input_price_per_million": "0",
            "cached_input_price_per_million": "0",
            "output_price_per_million": "2",
        },
    )


def test_usage_debit_is_atomic_idempotent_and_reports_hard_stop(monkeypatch):
    store = _ChargeStore()
    connections = []

    def connection_factory():
        connection = _ChargeConnection(store)
        connections.append(connection)
        return connection

    monkeypatch.setattr(quota, "get_db_connection", connection_factory)

    first = _charge_once()
    replay = _charge_once()

    assert first["applied"] is True
    assert first["charged_amount"] == "0.2"
    assert first["remaining_amount"] == "-5.1"
    assert first["hard_stop"] is True
    assert replay["applied"] is False
    assert replay["hard_stop"] is True
    assert store.ledger_inserts == 1
    assert store.account_updates == 1
    assert store.account["used_amount"] == Decimal("5.10000000000000")
    assert all(connection.commits == 1 for connection in connections)
    assert all(connection.rollbacks == 0 for connection in connections)


def test_zero_token_usage_is_persisted_without_debiting_quota(monkeypatch):
    store = _ChargeStore()
    store.account = {
        "user_id": 7,
        "granted_amount": Decimal("10"),
        "used_amount": Decimal("4.9"),
    }
    monkeypatch.setattr(
        quota,
        "get_db_connection",
        lambda: _ChargeConnection(store),
    )

    result = quota.charge_agent_usage(
        user_id=7,
        session_id="session-interrupted",
        task_id="task-interrupted",
        source="relay_anthropic",
        usage_event_id="interrupted-request-1",
        endpoint_id=3,
        endpoint_revision=2,
        endpoint_model="model-a",
        usage={
            "input_uncached_tokens": 0,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 0,
            "reasoning_output_tokens": 0,
        },
        pricing={
            "input_price_per_million": "1",
            "cached_input_price_per_million": "0.1",
            "output_price_per_million": "2",
        },
    )

    assert result["applied"] is True
    assert result["charged_amount"] == "0"
    assert result["remaining_amount"] == "5.1"
    assert result["hard_stop"] is False
    assert store.ledger["charged_amount"] == Decimal("0E-14")
    assert store.account["used_amount"] == Decimal("4.90000000000000")


def test_usage_charge_preserves_snapshot_when_endpoint_was_deleted(monkeypatch):
    store = _ChargeStore()
    monkeypatch.setattr(
        quota,
        "get_db_connection",
        lambda: _ChargeConnection(store),
    )

    result = quota.charge_agent_usage(
        user_id=7,
        session_id="session-deleted-endpoint",
        task_id="task-deleted-endpoint",
        source="relay_openai",
        usage_event_id="request-after-delete",
        endpoint_id=None,
        endpoint_revision=9,
        endpoint_model="deleted-model",
        usage={
            "input_uncached_tokens": 10,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 2,
            "reasoning_output_tokens": 0,
        },
        pricing={
            "input_price_per_million": "1",
            "cached_input_price_per_million": "0.1",
            "output_price_per_million": "2",
        },
    )

    assert result["applied"] is True
    assert store.ledger["endpoint_id"] is None
    assert store.ledger["endpoint_revision"] == 9
    assert store.ledger["endpoint_model"] == "deleted-model"


def test_usage_charge_persists_cached_fallback_audit_metadata(monkeypatch):
    store = _ChargeStore()
    monkeypatch.setattr(
        quota,
        "get_db_connection",
        lambda: _ChargeConnection(store),
    )

    result = quota.charge_agent_usage(
        user_id=7,
        session_id="session-fallback",
        task_id="task-fallback",
        source="relay_openai",
        usage_event_id="response-fallback",
        endpoint_id=3,
        endpoint_revision=2,
        endpoint_model="model-fallback",
        usage={
            "input_uncached_tokens": 10,
            "input_cached_tokens": 90,
            "input_cache_write_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
            "cached_fallback_request_count": 1,
            "cached_fallback_input_tokens": 100,
        },
        pricing={
            "input_price_per_million": "1",
            "cached_input_price_per_million": "0.1",
            "output_price_per_million": "2",
        },
    )

    assert result["cached_fallback_request_count"] == 1
    assert result["cached_fallback_input_tokens"] == 100
    assert store.ledger["cached_fallback_request_count"] == 1
    assert store.ledger["cached_fallback_input_tokens"] == 100


def test_admin_usage_is_recorded_without_debiting_a_quota_account(monkeypatch):
    store = _ChargeStore()
    store.account = None

    class AdminCursor(_ChargeCursor):
        def execute(self, sql, params):
            normalized = " ".join(sql.split())
            if normalized.startswith("SELECT id, is_admin FROM users"):
                self.result = {"id": 7, "is_admin": 1}
                return
            super().execute(sql, params)

    class AdminConnection(_ChargeConnection):
        def cursor(self):
            return AdminCursor(self)

    monkeypatch.setattr(quota, "get_db_connection", lambda: AdminConnection(store))

    result = quota.charge_agent_usage(
        user_id=7,
        session_id="admin-session",
        task_id="admin-task",
        source="relay_openai",
        usage_event_id="admin-request-1",
        endpoint_id=3,
        endpoint_revision=5,
        endpoint_model="model-a",
        usage={
            "input_uncached_tokens": 10,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 5,
            "reasoning_output_tokens": 0,
        },
        pricing={
            "input_price_per_million": "1",
            "cached_input_price_per_million": "0.1",
            "output_price_per_million": "2",
        },
        is_admin=True,
    )

    assert result["applied"] is True
    assert result["remaining_amount"] is None
    assert result["hard_stop"] is False
    assert store.ledger["charged_amount"] == Decimal("0.00002000000000")
    assert store.ledger["remaining_after"] == Decimal("0")
    assert store.account_updates == 0


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("user_id", 8),
        ("session_id", "another-session"),
        ("endpoint_id", 4),
        ("endpoint_revision", 3),
        ("endpoint_model", "another-model"),
        ("input_uncached_tokens", 1),
        ("input_cached_tokens", 1),
        ("input_cache_write_tokens", 1),
        ("output_tokens", 100_001),
        ("reasoning_output_tokens", 1),
        ("input_price_per_million", Decimal("0.1")),
        ("cached_input_price_per_million", Decimal("0.1")),
        ("output_price_per_million", Decimal("2.1")),
        ("charged_amount", Decimal("0.3")),
    ],
)
def test_idempotent_usage_replay_rejects_conflicting_payload(
    monkeypatch,
    field,
    replacement,
):
    store = _ChargeStore()
    monkeypatch.setattr(
        quota,
        "get_db_connection",
        lambda: _ChargeConnection(store),
    )

    _charge_once()
    store.ledger[field] = replacement

    with pytest.raises(
        quota.AgentQuotaConflictError,
        match="幂等键与既有记账内容冲突",
    ):
        _charge_once()

    assert store.ledger_inserts == 1
    assert store.account_updates == 1


@pytest.mark.parametrize(
    ("aggregate", "expected"),
    [
        (None, None),
        (Decimal("0"), "0"),
        (Decimal("1.25000000000000"), "1.25"),
    ],
)
def test_session_usage_cost_uses_ledger_sum_and_distinguishes_no_records(
    monkeypatch,
    aggregate,
    expected,
):
    observed = {}

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params):
            observed["sql"] = " ".join(sql.split())
            observed["params"] = params

        def fetchone(self):
            return {"charged_amount": aggregate}

    class Connection:
        def cursor(self):
            return Cursor()

        def close(self):
            observed["closed"] = True

    monkeypatch.setattr(quota, "get_db_connection", Connection)

    assert quota.get_agent_session_usage_cost("session-ledger") == expected
    assert observed["sql"] == (
        "SELECT SUM(charged_amount) AS charged_amount "
        "FROM agent_usage_ledger WHERE session_id=%s"
    )
    assert observed["params"] == ("session-ledger",)
    assert observed["closed"] is True


@pytest.mark.parametrize(
    ("rows", "latest_context", "expected"),
    [
        ([], None, None),
        ([{
            "task_id": "turn-1",
            "request_count": 2,
            "input_uncached_tokens": 60,
            "input_cached_tokens": 50,
            "input_cache_write_tokens": 5,
            "output_tokens": 12,
            "reasoning_output_tokens": 5,
            "charged_amount": Decimal("0.07500000000000"),
        }, {
            "task_id": "turn-2",
            "request_count": 1,
            "input_uncached_tokens": 40,
            "input_cached_tokens": 20,
            "input_cache_write_tokens": 0,
            "output_tokens": 8,
            "reasoning_output_tokens": 3,
            "charged_amount": Decimal("0.05000000000000"),
        }], {
            "id": 42,
            "task_id": "turn-2",
            "input_uncached_tokens": 17,
            "input_cached_tokens": 19,
            "input_cache_write_tokens": 3,
            "output_tokens": 7,
        }, {
            "source": "session",
            "request_count": 3,
            "turn_count": 2,
            "input_uncached_tokens": 100,
            "input_cached_tokens": 70,
            "input_cache_write_tokens": 5,
            "input_total_tokens": 175,
            "output_tokens": 20,
            "reasoning_output_tokens": 8,
            "cost_rmb": "0.125",
            "cost_complete": True,
            "billing_revision": 42,
            "_task_ids": ["turn-1", "turn-2"],
            "_latest_context_task_id": "turn-2",
            "_latest_context_tokens": 46,
            "_latest_context_request_count": 1,
        }),
    ],
)
def test_session_token_usage_comes_from_frozen_ledger(
    monkeypatch,
    rows,
    latest_context,
    expected,
):
    observed = {"sql": [], "params": []}

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params):
            observed["sql"].append(" ".join(sql.split()))
            observed["params"].append(params)

        def fetchall(self):
            return rows

        def fetchone(self):
            return latest_context

    class Connection:
        def cursor(self):
            return Cursor()

        def close(self):
            observed["closed"] = True

    monkeypatch.setattr(quota, "get_db_connection", Connection)

    assert quota.get_agent_session_token_usage("session-ledger") == expected
    assert "GROUP BY task_id" in observed["sql"][0]
    if rows:
        assert "ORDER BY id DESC LIMIT 1" in observed["sql"][1]
    assert observed["params"] == [("session-ledger",)] * (2 if rows else 1)
    assert observed["closed"] is True


def test_start_gate_allows_personal_endpoint_but_not_when_public_is_off(monkeypatch):
    monkeypatch.setattr(quota, "get_agent_public_enabled", lambda: True)
    monkeypatch.setattr(
        quota,
        "get_db_connection",
        lambda: pytest.fail("自有端点不应读取额度账户"),
    )
    personal = quota.check_agent_start_eligibility(
        9,
        uses_personal_endpoint=True,
    )
    assert personal["allowed"] is True
    assert personal["reason_code"] == "personal_endpoint_bypass"

    monkeypatch.setattr(quota, "get_agent_public_enabled", lambda: False)
    disabled = quota.check_agent_start_eligibility(
        9,
        uses_personal_endpoint=True,
    )
    assert disabled["allowed"] is False
    assert disabled["reason_code"] == "agent_public_disabled"

    admin = quota.check_agent_start_eligibility(1, is_admin=True)
    assert admin["allowed"] is True
    assert admin["reason_code"] == "admin_bypass"


class _RowsCursor:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql):
        normalized = " ".join(sql.split())
        assert "LEFT JOIN users AS u" in normalized
        assert "u.is_admin=0" in normalized
        assert "c.logo_seed" in normalized

    def fetchall(self):
        return list(self.rows)


class _RowsConnection:
    def __init__(self, rows):
        self.rows = rows

    def cursor(self):
        return _RowsCursor(self.rows)

    def close(self):
        pass


def test_quota_grant_class_preview_keeps_empty_classes_and_groups_user_ids(
    monkeypatch,
):
    class_seed = "0123456789abcdef" * 2
    connection = _RowsConnection(
        [
            {"class_en": "a", "class_cn": "甲班", "logo_seed": class_seed, "user_id": 2},
            {"class_en": "a", "class_cn": "甲班", "logo_seed": class_seed, "user_id": 3},
            {"class_en": "b", "class_cn": None, "logo_seed": None, "user_id": None},
        ]
    )
    monkeypatch.setattr(quota, "get_db_connection", lambda: connection)

    classes = quota.list_agent_quota_grant_classes()
    assert [
        {key: item[key] for key in ("class_en", "label", "user_ids")}
        for item in classes
    ] == [
        {"class_en": "a", "label": "甲班", "user_ids": [2, 3]},
        {"class_en": "b", "label": "b", "user_ids": []},
    ]
    assert all(item["logo"]["cells"] for item in classes)
    assert classes[0]["logo"] == quota.class_logo_presentation(class_seed)


class _BatchCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql, params):
        normalized = " ".join(sql.split())
        self.connection.calls.append((normalized, params))
        if normalized.startswith("SELECT id, is_admin FROM users"):
            self.rows = [{"id": 1, "is_admin": 1}]
        elif normalized.startswith("SELECT DISTINCT u.id"):
            assert params == ("class-a", "class-b")
            self.rows = [{"id": 2}, {"id": 3}]
        elif normalized.startswith("SELECT id FROM users WHERE id IN"):
            self.rows = [{"id": 2}, {"id": 3}]
        else:
            raise AssertionError(f"unexpected SQL: {normalized}")

    def executemany(self, sql, rows):
        normalized = " ".join(sql.split())
        materialized = list(rows)
        self.connection.many_calls.append((normalized, materialized))
        return len(materialized)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)


class _BatchConnection:
    def __init__(self):
        self.calls = []
        self.many_calls = []
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return _BatchCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


def test_batch_class_grant_deduplicates_classes_and_writes_one_audit_per_user(
    monkeypatch,
):
    connection = _BatchConnection()
    monkeypatch.setattr(quota, "get_db_connection", lambda: connection)
    monkeypatch.setattr(quota.uuid, "uuid4", lambda: type("U", (), {"hex": "a" * 32})())

    result = quota.batch_grant_quota_by_classes(
        ["class-a", "class-b", "class-a"],
        "1.25000000000000",
        1,
    )

    assert result == {
        "batch_id": "a" * 32,
        "affected_users": 2,
        "user_ids": [2, 3],
        "amount_per_user": "1.25",
        "total_rmb": "2.5",
    }
    assert connection.committed is True
    assert connection.rolled_back is False
    assert len(connection.many_calls) == 2
    account_rows = connection.many_calls[0][1]
    grant_rows = connection.many_calls[1][1]
    assert [row[0] for row in account_rows] == [2, 3]
    assert [row[0] for row in grant_rows] == [2, 3]
    assert all(row[2] == "a" * 32 for row in grant_rows)


@pytest.mark.parametrize("reason", [None, "", "  ", "x" * 2001])
def test_quota_request_reason_rejects_invalid_values_before_db(monkeypatch, reason):
    monkeypatch.setattr(
        quota,
        "get_db_connection",
        lambda: pytest.fail("非法申请理由不应访问数据库"),
    )
    with pytest.raises(quota.AgentQuotaValidationError):
        quota.create_agent_quota_request(7, reason)


@pytest.mark.parametrize("amount", [None, "", "0", "-1", "nan"])
def test_quota_approval_requires_admin_decided_positive_amount_before_db(
    monkeypatch,
    amount,
):
    monkeypatch.setattr(
        quota,
        "get_db_connection",
        lambda: pytest.fail("非法批准额度不应访问数据库"),
    )
    with pytest.raises(quota.AgentQuotaValidationError):
        quota.review_agent_quota_request(
            9,
            reviewer_user_id=1,
            approved=True,
            approved_amount=amount,
        )
