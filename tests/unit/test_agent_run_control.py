from types import SimpleNamespace

import pytest

from oj_modules.tasks.agent import control


def test_terminator_persists_before_revoke_and_force_remove(monkeypatch):
    calls = []

    def cancel(task_id):
        calls.append(("cancel", task_id))
        return {
            "exists": True,
            "changed": True,
            "canceled": True,
            "state": {"task_id": task_id, "status": "Canceled"},
        }

    class CeleryControl:
        def revoke(self, task_id, **kwargs):
            calls.append(("revoke", task_id, kwargs))

    def run(command, **_kwargs):
        calls.append(("docker", command))
        return SimpleNamespace(returncode=0, stdout=command[-1], stderr="")

    monkeypatch.setattr(control, "cancel_agent_run", cancel)
    monkeypatch.setattr(control.subprocess, "run", run)
    terminate = control.build_agent_run_terminator(
        SimpleNamespace(control=CeleryControl()),
    )

    result = terminate("abc-123")

    assert result["errors"] == []
    assert calls[0] == ("cancel", "abc-123")
    assert calls[1] == (
        "revoke",
        "abc-123",
        {"terminate": True, "signal": "SIGTERM"},
    )
    assert calls[2] == (
        "docker",
        ["docker", "rm", "-f", "numoj-agent-abc-123"],
    )


def test_terminator_does_not_touch_finished_task(monkeypatch):
    monkeypatch.setattr(
        control,
        "cancel_agent_run",
        lambda _task_id: {
            "exists": True,
            "changed": False,
            "canceled": False,
            "state": {"status": "Completed"},
        },
    )
    celery_control = SimpleNamespace(
        revoke=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("终态任务不得 revoke"),
        ),
    )
    monkeypatch.setattr(
        control.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("终态任务不得清理容器"),
        ),
    )

    result = control.build_agent_run_terminator(
        SimpleNamespace(control=celery_control),
    )("done-task")

    assert result["canceled"] is False
    assert result["errors"] == []


def test_terminator_validates_task_id_before_persisting_cancel(monkeypatch):
    monkeypatch.setattr(
        control,
        "cancel_agent_run",
        lambda _task_id: pytest.fail("无效 task_id 不得写入终止状态"),
    )
    terminate = control.build_agent_run_terminator(
        SimpleNamespace(control=SimpleNamespace()),
    )

    with pytest.raises(ValueError, match="task_id"):
        terminate("../invalid")
