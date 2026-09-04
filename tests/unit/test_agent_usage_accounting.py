from pathlib import Path

import pytest

from backend.oj_modules.agents import workspace as agent_workspace
from backend.oj_modules.tasks.agent import usage_accounting


@pytest.fixture(autouse=True)
def _isolated_usage_outbox(monkeypatch, tmp_path):
    monkeypatch.setattr(
        agent_workspace,
        "AGENT_WORKSPACE_ROOT",
        tmp_path / "agent-workspaces",
    )


def _snapshot():
    return {
        "endpoint_id": 8,
        "endpoint_revision": 4,
        "endpoint_model": "model-a",
        "pricing": {
            "input_price_per_million": "1",
            "cached_input_price_per_million": "0.1",
            "output_price_per_million": "2",
        },
    }


def _event(event_id="request-1"):
    return {
        "source": "relay_openai",
        "id": event_id,
        "usage": {
            "input_uncached_tokens": 10,
            "input_cached_tokens": 2,
            "input_cache_write_tokens": 1,
            "output_tokens": 3,
            "reasoning_output_tokens": 0,
        },
    }


def _accountant(charge_usage, **kwargs):
    return usage_accounting.ResilientAgentUsageAccountant(
        user_id=7,
        session_id="session-1",
        task_id="task-1",
        endpoint_snapshot=_snapshot(),
        is_admin=False,
        charge_usage=charge_usage,
        start_retry_worker=False,
        **kwargs,
    )


def _outbox_files():
    root = Path(agent_workspace.AGENT_WORKSPACE_ROOT) / ".usage-outbox"
    return sorted(root.glob("*.json")) if root.exists() else []


def test_database_failure_is_deferred_and_retried_without_stopping_task():
    calls = []
    settled = []

    def charge(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise RuntimeError("database unavailable")
        return {
            "applied": True,
            "charged_amount": "0.25",
            "remaining_amount": "9.75",
            "hard_stop": False,
        }

    accountant = _accountant(charge, on_settled=settled.append)

    deferred = accountant(_event())

    assert deferred == {
        "applied": False,
        "acknowledged": True,
        "deferred": True,
        "hard_stop": False,
        "remaining_rmb": None,
    }
    assert len(_outbox_files()) == 1

    assert accountant.retry_pending_once() == {"pending": 0, "settled": 1}
    assert len(calls) == 2
    assert calls[0] == calls[1]
    assert settled[0]["remaining_rmb"] == "9.75"
    assert _outbox_files() == []


def test_idempotent_existing_ledger_record_acknowledges_and_clears_outbox():
    accountant = _accountant(
        lambda **_kwargs: {
            "applied": False,
            "charged_amount": "0.25",
            "remaining_amount": "9.75",
            "hard_stop": False,
        }
    )

    result = accountant(_event())

    assert result["applied"] is False
    assert result["acknowledged"] is True
    assert "deferred" not in result
    assert _outbox_files() == []


def test_committed_usage_publishes_durable_session_billing_revision(monkeypatch):
    published = []
    monkeypatch.setattr(
        usage_accounting,
        "publish_agent_billing_revision",
        lambda *args: published.append(args) or True,
    )
    accountant = _accountant(
        lambda **_kwargs: {
            "id": 41,
            "applied": True,
            "charged_amount": "0.25",
            "remaining_amount": "9.75",
            "hard_stop": False,
        }
    )

    result = accountant(_event())

    assert result["billing_revision"] == 41
    assert published == [("session-1", "task-1", 41)]


def test_billing_revision_publish_failure_never_reopens_settlement(monkeypatch):
    monkeypatch.setattr(
        usage_accounting,
        "publish_agent_billing_revision",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("redis unavailable")),
    )
    accountant = _accountant(
        lambda **_kwargs: {
            "id": 42,
            "applied": True,
            "charged_amount": "0.25",
            "remaining_amount": "9.75",
            "hard_stop": False,
        }
    )

    result = accountant(_event())

    assert result["acknowledged"] is True
    assert result["billing_revision"] == 42
    assert "deferred" not in result
    assert _outbox_files() == []


def test_disk_and_database_failure_keep_in_memory_copy_for_later_retry(
    monkeypatch,
):
    attempts = []

    def charge(**_kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            raise RuntimeError("database unavailable")
        return {
            "applied": True,
            "charged_amount": "0.1",
            "remaining_amount": "9.9",
            "hard_stop": False,
        }

    persist = usage_accounting._persist_record
    persist_attempts = []

    def fail_first_persist(envelope):
        persist_attempts.append(True)
        if len(persist_attempts) == 1:
            raise OSError("disk temporarily read-only")
        return persist(envelope)

    monkeypatch.setattr(
        usage_accounting,
        "_persist_record",
        fail_first_persist,
    )
    accountant = _accountant(charge)

    assert accountant(_event())["deferred"] is True
    assert _outbox_files() == []

    assert accountant.retry_pending_once() == {"pending": 0, "settled": 1}
    assert len(persist_attempts) == 2
    assert _outbox_files() == []


def test_endpoint_refresh_failure_uses_last_complete_pricing_snapshot():
    charged = []
    accountant = _accountant(
        lambda **kwargs: charged.append(kwargs) or {
            "applied": True,
            "charged_amount": "0.1",
            "remaining_amount": "9.9",
            "hard_stop": False,
        },
        endpoint_snapshot_loader=lambda: (_ for _ in ()).throw(
            RuntimeError("dynamic config database unavailable")
        ),
    )

    result = accountant(_event())

    assert result["hard_stop"] is False
    assert charged[0]["endpoint_revision"] == 4
    assert charged[0]["pricing"] == _snapshot()["pricing"]


def test_deleted_endpoint_reference_is_detached_and_settled_with_snapshot():
    snapshots = iter((_snapshot(), {**_snapshot(), "endpoint_id": None}))
    charged = []

    def charge(**kwargs):
        charged.append(kwargs)
        if kwargs["endpoint_id"] is not None:
            raise RuntimeError("foreign key rejects deleted endpoint")
        return {
            "applied": True,
            "charged_amount": "0.1",
            "remaining_amount": "9.9",
            "hard_stop": False,
        }

    accountant = _accountant(
        charge,
        endpoint_snapshot_loader=lambda: next(snapshots),
    )

    result = accountant(_event())

    assert result["acknowledged"] is True
    assert [call["endpoint_id"] for call in charged] == [8, None]
    assert charged[1]["endpoint_revision"] == 4
    assert charged[1]["endpoint_model"] == "model-a"
    assert charged[1]["pricing"] == _snapshot()["pricing"]
    assert _outbox_files() == []


def test_background_retry_notifies_only_committed_hard_stop():
    attempts = []
    hard_stops = []

    def charge(**_kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            raise RuntimeError("database unavailable")
        return {
            "applied": True,
            "charged_amount": "6",
            "remaining_amount": "-5.2",
            "hard_stop": True,
        }

    accountant = _accountant(charge)
    accountant.set_hard_stop_callback(hard_stops.append)

    assert accountant(_event())["hard_stop"] is False
    assert hard_stops == []

    accountant.retry_pending_once()

    assert len(hard_stops) == 1
    assert hard_stops[0]["remaining_rmb"] == "-5.2"


def test_periodic_reconciliation_replays_persisted_record_after_worker_exit():
    accountant = _accountant(
        lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("database unavailable")
        )
    )
    assert accountant(_event())["deferred"] is True
    accountant.close()
    assert len(_outbox_files()) == 1
    replayed = []

    result = usage_accounting.reconcile_agent_usage_outbox(
        charge_usage=lambda **kwargs: replayed.append(kwargs) or {
            "applied": True,
            "charged_amount": "0.25",
            "remaining_amount": "9.75",
            "hard_stop": False,
        },
        endpoint_lookup=lambda *_args, **_kwargs: _snapshot(),
    )

    assert result == {
        "scanned": 1,
        "settled": 1,
        "hard_stops": 0,
        "failed": 0,
    }
    assert replayed[0]["usage_event_id"] == "request-1"
    assert _outbox_files() == []


def test_periodic_reconciliation_detaches_endpoint_deleted_after_worker_exit():
    accountant = _accountant(
        lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("database unavailable")
        )
    )
    assert accountant(_event())["deferred"] is True
    replayed = []

    result = usage_accounting.reconcile_agent_usage_outbox(
        charge_usage=lambda **kwargs: replayed.append(kwargs) or {
            "applied": True,
            "charged_amount": "0.25",
            "remaining_amount": "9.75",
            "hard_stop": False,
        },
        endpoint_lookup=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            usage_accounting.DynamicConfigNotFoundError("端点不存在")
        ),
    )

    assert result["settled"] == 1
    assert replayed[0]["endpoint_id"] is None
    assert replayed[0]["endpoint_revision"] == 4
    assert _outbox_files() == []
