import subprocess
import sys
import types

import pytest

from oj_modules import startup_requeue
from oj_modules.tasks import ranking_agent_judge_tasks, ranking_elo_tasks
from scripts import recover_pending_tasks


class _FakeRedis:
    def __init__(self):
        self.values = {}

    def set(self, key, value, *, ex=None, nx=False):
        del ex
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def get(self, key):
        return self.values.get(key)

    def delete(self, *keys):
        for key in keys:
            self.values.pop(key, None)


class _FakeTask:
    def __init__(self):
        self.calls = []

    def apply_async(self, *, args, countdown):
        self.calls.append((list(args), countdown))


def test_elo_safe_seed_is_idempotent_and_full_recovery_can_replace_owner():
    redis_client = _FakeRedis()
    task = _FakeTask()

    ranking_elo_tasks.seed_elo_matchmaker_tick(redis_client, task)
    ranking_elo_tasks.seed_elo_matchmaker_tick(redis_client, task)
    assert len(task.calls) == 1

    ranking_elo_tasks.seed_elo_matchmaker_tick(
        redis_client,
        task,
        reset_owner=True,
    )
    assert len(task.calls) == 2


def test_watchdog_safe_seed_does_not_duplicate_an_existing_owner_chain():
    redis_client = _FakeRedis()
    task = _FakeTask()

    startup_requeue.seed_pending_requeue_watchdog(
        redis_client, task, countdown=17,
    )
    assert len(task.calls) == 1

    # 模拟 60 秒 seed lock 已过期、但活动 owner 仍在的 Web worker 重建。
    redis_client.delete(startup_requeue._PENDING_REQUEUE_SEED_LOCK_KEY)
    startup_requeue.seed_pending_requeue_watchdog(
        redis_client, task, countdown=17,
    )

    assert len(task.calls) == 1


def test_paused_probe_safe_seed_does_not_duplicate_an_existing_owner_chain():
    redis_client = _FakeRedis()
    task = _FakeTask()

    ranking_agent_judge_tasks.seed_agent_judge_paused_probe(
        redis_client, task, countdown=23,
    )
    assert len(task.calls) == 1

    redis_client.delete(ranking_agent_judge_tasks.PAUSED_PROBE_SEED_LOCK_KEY)
    ranking_agent_judge_tasks.seed_agent_judge_paused_probe(
        redis_client, task, countdown=23,
    )

    assert len(task.calls) == 1


def test_recovery_cli_requires_explicit_worker_stop_confirmation(monkeypatch):
    monkeypatch.setattr(
        recover_pending_tasks,
        '_local_numoj_celery_processes',
        lambda: pytest.fail('缺少确认时不应检查进程'),
    )

    with pytest.raises(SystemExit, match='--confirm-celery-stopped'):
        recover_pending_tasks.main([])


def test_recovery_cli_rejects_live_local_worker(monkeypatch):
    monkeypatch.setattr(
        recover_pending_tasks,
        '_local_numoj_celery_processes',
        lambda: ['123 celery -A oj.celery worker -Q celery'],
    )

    with pytest.raises(SystemExit, match='本机 Celery worker 仍在运行'):
        recover_pending_tasks.main(['--confirm-celery-stopped'])


def test_recovery_cli_fails_closed_when_local_process_check_fails(monkeypatch):
    monkeypatch.setattr(
        recover_pending_tasks,
        '_local_numoj_celery_processes',
        lambda: (_ for _ in ()).throw(subprocess.TimeoutExpired('ps', 5)),
    )

    with pytest.raises(SystemExit, match='无法检查本机 Celery 进程'):
        recover_pending_tasks.main(['--confirm-celery-stopped'])


def test_recovery_cli_rejects_remote_worker_ping(monkeypatch):
    monkeypatch.setattr(recover_pending_tasks, '_local_numoj_celery_processes', lambda: [])
    recovered = []
    fake_oj = types.ModuleType('oj')
    fake_oj.celery = types.SimpleNamespace(
        control=types.SimpleNamespace(
            ping=lambda timeout: [{'celery@remote': {'ok': 'pong'}}],
        ),
    )
    fake_oj.recover_pending_after_all_workers_stopped = lambda: recovered.append(True)
    monkeypatch.setitem(sys.modules, 'oj', fake_oj)

    with pytest.raises(SystemExit, match='celery@remote'):
        recover_pending_tasks.main(['--confirm-celery-stopped'])

    assert recovered == []


def test_recovery_cli_runs_only_after_both_liveness_checks_pass(monkeypatch, capsys):
    monkeypatch.setattr(recover_pending_tasks, '_local_numoj_celery_processes', lambda: [])
    recovered = []
    fake_oj = types.ModuleType('oj')
    fake_oj.celery = types.SimpleNamespace(
        control=types.SimpleNamespace(ping=lambda timeout: []),
    )
    fake_oj.recover_pending_after_all_workers_stopped = lambda: recovered.append(True)
    monkeypatch.setitem(sys.modules, 'oj', fake_oj)

    assert recover_pending_tasks.main(['--confirm-celery-stopped']) == 0
    assert recovered == [True]
    assert '恢复与后台调度链重建已完成' in capsys.readouterr().out


def test_local_worker_detection_uses_process_listing(monkeypatch):
    output = "\n".join([
        '11 python app.py',
        '12 celery -A oj.celery worker -Q celery',
        '13 celery -A another.app worker',
    ])
    monkeypatch.setattr(
        subprocess,
        'run',
        lambda *args, **kwargs: types.SimpleNamespace(stdout=output),
    )

    assert recover_pending_tasks._local_numoj_celery_processes() == [
        '12 celery -A oj.celery worker -Q celery',
    ]
