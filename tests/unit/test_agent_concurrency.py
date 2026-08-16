from types import SimpleNamespace

import pytest

from oj_modules.tasks.agent import concurrency


class _Autoscaler:
    def __init__(self):
        self.updates = []

    def update(self, **kwargs):
        self.updates.append(kwargs)
        return kwargs["max"], kwargs["min"]


def _consumer(hostname="agent@test", *, autoscaler=None):
    return SimpleNamespace(
        hostname=hostname,
        controller=SimpleNamespace(autoscaler=autoscaler),
    )


def test_install_registers_one_strong_worker_ready_receiver(monkeypatch):
    calls = []
    signal = SimpleNamespace(
        connect=lambda receiver, **kwargs: calls.append((receiver, kwargs))
    )
    monkeypatch.setattr(concurrency.signals, "worker_ready", signal)

    concurrency.install_agent_concurrency_control()

    assert calls == [(
        concurrency._agent_worker_ready,
        {
            "weak": False,
            "dispatch_uid": "numoj.agent.concurrency.worker-ready",
        },
    )]


def test_ready_agent_worker_restores_persisted_limit():
    autoscaler = _Autoscaler()

    applied = concurrency.configure_ready_agent_worker(
        _consumer(autoscaler=autoscaler),
        limit_reader=lambda: 8,
    )

    assert applied is True
    assert autoscaler.updates == [{"max": 8, "min": 1}]


def test_ready_hook_ignores_non_agent_workers_without_reading_database():
    autoscaler = _Autoscaler()

    applied = concurrency.configure_ready_agent_worker(
        _consumer("judge@test", autoscaler=autoscaler),
        limit_reader=lambda: pytest.fail("非 Agent worker 不应读取并发设置"),
    )

    assert applied is False
    assert autoscaler.updates == []


def test_ready_agent_worker_keeps_safe_startup_limit_when_settings_fail():
    autoscaler = _Autoscaler()

    applied = concurrency.configure_ready_agent_worker(
        _consumer(autoscaler=autoscaler),
        limit_reader=lambda: (_ for _ in ()).throw(RuntimeError("db unavailable")),
    )

    assert applied is False
    assert autoscaler.updates == []


def test_runtime_apply_targets_only_agent_workers_with_glob_matcher():
    calls = []
    control = SimpleNamespace(
        autoscale=lambda *args, **kwargs: calls.append((args, kwargs))
        or [{"agent@test": {"ok": "autoscale now max=12 min=1"}}]
    )

    applied = concurrency.apply_agent_concurrency_limit(
        SimpleNamespace(control=control),
        12,
    )

    assert applied is True
    assert calls == [(
        (12, 1),
        {
            "pattern": "agent@*",
            "matcher": "glob",
            "reply": True,
            "timeout": 1.0,
        },
    )]


@pytest.mark.parametrize("reply", [None, [], [{"judge@test": {"ok": "ignored"}}]])
def test_runtime_apply_is_best_effort_when_agent_worker_does_not_reply(reply):
    control = SimpleNamespace(autoscale=lambda *_args, **_kwargs: reply)

    assert concurrency.apply_agent_concurrency_limit(
        SimpleNamespace(control=control),
        5,
    ) is False


def test_runtime_apply_is_best_effort_when_broker_fails():
    def fail(*_args, **_kwargs):
        raise RuntimeError("broker unavailable")

    assert concurrency.apply_agent_concurrency_limit(
        SimpleNamespace(control=SimpleNamespace(autoscale=fail)),
        5,
    ) is False


@pytest.mark.parametrize("limit", [0, 101, True, "not-a-number"])
def test_runtime_control_rejects_invalid_limits(limit):
    with pytest.raises(ValueError, match="1 到 100"):
        concurrency.apply_agent_concurrency_limit(
            SimpleNamespace(control=SimpleNamespace()),
            limit,
        )
