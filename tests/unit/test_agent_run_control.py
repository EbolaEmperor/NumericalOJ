from types import SimpleNamespace

import pytest

from backend.oj_modules.tasks.agent import control


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
    monkeypatch.setattr(control, "_wait_for_protocol_interrupt", lambda _task_id: False)
    monkeypatch.setattr(
        control,
        "_project_session_cleanup_status",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        control,
        "_read_native_session_id_for_task",
        lambda _task_id: "",
    )
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


def test_terminator_projects_canceled_only_after_cleanup_succeeds(monkeypatch):
    projected = []
    monkeypatch.setattr(
        control,
        "cancel_agent_run",
        lambda task_id: {
            "exists": True,
            "changed": True,
            "canceled": True,
            "state": {
                "task_id": task_id,
                "status": "Canceled",
                "message": "任务已被手动终止",
            },
        },
    )
    monkeypatch.setattr(control, "_force_remove_agent_container", lambda _task_id: None)
    monkeypatch.setattr(control, "_wait_for_protocol_interrupt", lambda _task_id: False)
    monkeypatch.setattr(
        control,
        "_read_native_session_id_for_task",
        lambda _task_id: "",
    )
    monkeypatch.setattr(
        control,
        "_project_session_cleanup_status",
        lambda *args, **kwargs: projected.append((args, kwargs)) or True,
    )
    celery_control = SimpleNamespace(revoke=lambda *_args, **_kwargs: None)

    result = control.build_agent_run_terminator(
        SimpleNamespace(control=celery_control),
    )("cleanup-ok")

    assert result["errors"] == []
    assert projected == [(("cleanup-ok", "Canceled", "任务已被手动终止"), {
        "native_session_id": "",
    })]


def test_terminator_projects_cleanup_failed_when_revoke_is_uncertain(monkeypatch):
    projected = []
    monkeypatch.setattr(
        control,
        "cancel_agent_run",
        lambda task_id: {
            "exists": True,
            "changed": True,
            "canceled": True,
            "state": {"task_id": task_id, "status": "Canceled"},
        },
    )
    monkeypatch.setattr(control, "_force_remove_agent_container", lambda _task_id: None)
    monkeypatch.setattr(control, "_wait_for_protocol_interrupt", lambda _task_id: False)
    monkeypatch.setattr(
        control,
        "_read_native_session_id_for_task",
        lambda _task_id: "",
    )
    monkeypatch.setattr(
        control,
        "_project_session_cleanup_status",
        lambda *args, **kwargs: projected.append((args, kwargs)) or True,
    )

    def fail_revoke(*_args, **_kwargs):
        raise RuntimeError("broker unavailable")

    result = control.build_agent_run_terminator(
        SimpleNamespace(control=SimpleNamespace(revoke=fail_revoke)),
    )("cleanup-unknown")

    assert len(result["errors"]) == 1
    assert "broker unavailable" in result["errors"][0]
    assert result["state"]["status"] == "CleanupFailed"
    assert result["state"]["harness_status"] == "cleanup_failed"
    assert projected[0][0][0:2] == ("cleanup-unknown", "CleanupFailed")
    assert "broker unavailable" in projected[0][0][2]


def test_terminator_preserves_live_native_session_for_resume(monkeypatch):
    projected = []
    monkeypatch.setattr(
        control,
        "cancel_agent_run",
        lambda task_id: {
            "exists": True,
            "changed": True,
            "canceled": True,
            "state": {"task_id": task_id, "status": "Canceled"},
        },
    )
    monkeypatch.setattr(control, "_force_remove_agent_container", lambda _task_id: None)
    monkeypatch.setattr(control, "_wait_for_protocol_interrupt", lambda _task_id: False)
    monkeypatch.setattr(
        control,
        "_read_native_session_id_for_task",
        lambda _task_id: "native-live-123",
    )
    monkeypatch.setattr(
        control,
        "_project_session_cleanup_status",
        lambda *args, **kwargs: projected.append((args, kwargs)) or True,
    )

    result = control.build_agent_run_terminator(
        SimpleNamespace(control=SimpleNamespace(revoke=lambda *_args, **_kwargs: None)),
    )("cancel-live")

    assert result["errors"] == []
    assert result["state"]["native_session_id"] == "native-live-123"
    assert projected == [(("cancel-live", "Canceled", "任务已被手动终止"), {
        "native_session_id": "native-live-123",
    })]


def test_terminator_prefers_protocol_interrupt_without_revoke_or_force_remove(
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(
        control,
        "cancel_agent_run",
        lambda task_id: {
            "exists": True,
            "changed": True,
            "canceled": True,
            "state": {"task_id": task_id, "status": "Canceled"},
        },
    )
    monkeypatch.setattr(
        control,
        "_wait_for_protocol_interrupt",
        lambda task_id: calls.append(("wait", task_id)) or True,
    )
    monkeypatch.setattr(
        control,
        "_force_remove_agent_container",
        lambda _task_id: pytest.fail("协议中断成功后不得强制删除容器"),
    )
    monkeypatch.setattr(
        control,
        "_read_native_session_id_for_task",
        lambda _task_id: "native-after-interrupt",
    )
    monkeypatch.setattr(
        control,
        "_project_session_cleanup_status",
        lambda *_args, **_kwargs: True,
    )
    celery_control = SimpleNamespace(
        revoke=lambda *_args, **_kwargs: pytest.fail(
            "协议中断成功后不得 revoke"
        ),
    )

    result = control.build_agent_run_terminator(
        SimpleNamespace(control=celery_control),
    )("soft-stop")

    assert calls == [("wait", "soft-stop")]
    assert result["errors"] == []
    assert result["state"]["status"] == "Canceled"
    assert result["state"]["native_session_id"] == "native-after-interrupt"
