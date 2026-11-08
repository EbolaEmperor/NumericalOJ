"""指定 Harbor 终态恢复 CLI 必须经过原有全部停机守卫。"""

from __future__ import annotations

import builtins
import json
import sys
import types

import pytest

from scripts import recover_pending_tasks as recovery


def _runtime(monkeypatch, *, local=(), remote=(), ping_error=None, result=None, finalize_error=None):
    events = []

    def local_workers():
        events.append("local")
        return list(local)

    def ping(*, timeout):
        assert timeout == 1.5
        events.append("remote")
        if ping_error:
            raise ping_error
        return list(remote)

    celery = types.SimpleNamespace(control=types.SimpleNamespace(ping=ping))
    app = types.ModuleType("backend.oj")
    app.celery = celery
    app.recover_pending_after_all_workers_stopped = lambda: events.append("global-recovery")
    target = types.ModuleType("backend.oj_modules.tasks.agent.harbor_recovery")

    def finalize(task_id, *, celery_app):
        events.append(("finalize", task_id))
        assert celery_app is celery
        if finalize_error:
            raise finalize_error
        return result if result is not None else {"success": True, "task_id": task_id, "reused_trial": True}

    target.finalize_completed_harbor_task = finalize
    monkeypatch.setattr(recovery, "_local_numoj_celery_processes", local_workers)
    monkeypatch.setitem(sys.modules, "backend.oj", app)
    monkeypatch.setitem(sys.modules, target.__name__, target)
    original_import = builtins.__import__

    def tracked_import(name, *args, **kwargs):
        if name == "backend.oj":
            events.append("app-import")
        if name == target.__name__:
            events.append("target-import")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", tracked_import)
    return events


def _args(task_id="judge-task-run"):
    return ["--confirm-celery-stopped", "--finalize-harbor-task", task_id]


def test_target_requires_explicit_confirmation_before_process_or_app_access(monkeypatch):
    events = _runtime(monkeypatch)
    with pytest.raises(SystemExit, match="confirm-celery-stopped"):
        recovery.main(["--finalize-harbor-task", "judge-task-run"])
    assert events == []


def test_target_is_not_imported_when_local_worker_is_running(monkeypatch):
    events = _runtime(monkeypatch, local=["123 celery -A backend.oj.celery worker"])
    with pytest.raises(SystemExit, match="本机 Celery worker"):
        recovery.main(_args())
    assert events == ["local"]


@pytest.mark.parametrize("broken_ping", [False, True])
def test_target_is_not_imported_unless_remote_worker_guard_passes(monkeypatch, broken_ping):
    events = _runtime(monkeypatch, remote=[{"agent@remote": {"ok": "pong"}}],
                      ping_error=RuntimeError("broker unavailable") if broken_ping else None)
    with pytest.raises(SystemExit, match="无法确认|仍有 Celery worker"):
        recovery.main(_args())
    assert events == ["local", "app-import", "remote"]


def test_target_runs_after_all_guards_and_prints_only_machine_readable_result(monkeypatch, capsys):
    events = _runtime(monkeypatch)
    assert recovery.main(_args()) == 0
    assert events == ["local", "app-import", "remote", "target-import", ("finalize", "judge-task-run")]
    assert json.loads(capsys.readouterr().out) == {
        "success": True, "task_id": "judge-task-run", "reused_trial": True,
    }
    assert "global-recovery" not in events


def test_target_failure_result_returns_nonzero_without_global_recovery(monkeypatch, capsys):
    events = _runtime(monkeypatch, result={"success": False, "message": "结果不可恢复"})
    assert recovery.main(_args()) == 1
    assert json.loads(capsys.readouterr().out)["success"] is False
    assert "global-recovery" not in events


def test_target_exception_is_not_swallowed_or_followed_by_global_recovery(monkeypatch, capsys):
    events = _runtime(monkeypatch, finalize_error=RuntimeError("原始结果损坏"))
    with pytest.raises(RuntimeError, match="原始结果损坏"):
        recovery.main(_args())
    assert capsys.readouterr().out == ""
    assert "global-recovery" not in events


def test_explicit_empty_target_never_falls_back_to_global_recovery(monkeypatch):
    events = _runtime(monkeypatch, finalize_error=ValueError("任务 ID 无效"))
    with pytest.raises(ValueError, match="任务 ID 无效"):
        recovery.main(_args(""))
    assert events[-1] == ("finalize", "")
    assert "global-recovery" not in events


def test_default_cli_still_uses_original_global_recovery(monkeypatch, capsys):
    events = _runtime(monkeypatch)
    assert recovery.main(["--confirm-celery-stopped"]) == 0
    assert events == ["local", "app-import", "remote", "global-recovery"]
    assert "恢复与后台调度链重建已完成" in capsys.readouterr().out
