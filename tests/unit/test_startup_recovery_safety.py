import subprocess
import sys
import types
from datetime import datetime, timedelta

import pytest

from oj_modules.runtime import pending_recovery as startup_requeue
from oj_modules.tasks.ranking import (
    agent_judge as ranking_agent_judge_tasks,
    elo as ranking_elo_tasks,
)
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


class _ResultTask(_FakeTask):
    def __init__(self):
        super().__init__()
        self.task_ids = []

    def apply_async(self, *, args, countdown, task_id=None):
        super().apply_async(args=args, countdown=countdown)
        resolved_task_id = task_id or f'task-{len(self.calls)}'
        self.task_ids.append(resolved_task_id)
        return types.SimpleNamespace(id=resolved_task_id)


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


def test_watchdog_requeues_only_old_standard_ranking_submission_without_task_id(
        monkeypatch):
    old = datetime.now() - timedelta(minutes=20)
    rows = [
        {
            'id': 71,
            'competition_id': 9,
            'status': 'Judging',
            'scoring_mode': 'absolute',
            'judge_task_id': None,
            'created_at': old,
        },
        {
            'id': 72,
            'competition_id': 9,
            'status': 'Judging',
            'scoring_mode': 'absolute',
            'judge_task_id': 'already-enqueued',
            'created_at': old,
        },
        {
            'id': 73,
            'competition_id': 9,
            'status': 'Judging',
            'scoring_mode': 'absolute',
            'judge_task_id': None,
            'created_at': datetime.now(),
        },
    ]
    redis_client = _FakeRedis()
    task = _ResultTask()
    reservations = []
    monkeypatch.setattr(startup_requeue, '_redis_client', lambda: redis_client)
    monkeypatch.setattr(startup_requeue.uuid, 'uuid4', lambda: 'dispatch-71')
    monkeypatch.setattr(
        startup_requeue,
        'get_incomplete_ranking_submissions',
        lambda: rows,
    )
    monkeypatch.setattr(
        startup_requeue,
        'reserve_standard_ranking_evaluation',
        lambda submission_id, task_id, **kwargs: reservations.append(
            (submission_id, task_id, kwargs)
        ) or 1,
    )

    assert startup_requeue._requeue_orphaned_standard_ranking_submissions(task) == 1
    assert task.calls == [([71], 0)]
    assert task.task_ids == ['dispatch-71']
    assert reservations == [(
        71,
        'dispatch-71',
        {'stale_after_seconds': startup_requeue._RANKING_TASK_LEASE_SECONDS},
    )]


def test_watchdog_initializes_old_elo_submission_before_burst(monkeypatch):
    row = {
        'id': 81,
        'competition_id': 19,
        'username': 'student',
        'status': 'Judging',
        'scoring_mode': 'elo',
        'judge_task_id': None,
        'elo_initial_rating': 1600,
        'created_at': datetime.now() - timedelta(minutes=20),
    }
    initialized = []
    burst = _ResultTask()
    monkeypatch.setattr(startup_requeue, '_redis_client', lambda: _FakeRedis())
    monkeypatch.setattr(
        startup_requeue,
        'get_incomplete_ranking_submissions',
        lambda: [row],
    )
    monkeypatch.setattr(
        startup_requeue,
        'activate_elo_submission',
        lambda submission_id, competition_id, username, rating, **kwargs: initialized.append(
            (submission_id, competition_id, username, rating, kwargs)
        ),
    )

    assert startup_requeue._requeue_orphaned_standard_ranking_submissions(
        None,
        burst,
    ) == 1
    assert initialized == [(81, 19, 'student', 1600.0, {'keep_count': 2})]
    assert burst.calls == [([19, 81], 3)]


def test_ranking_watchdog_persists_task_reservation_before_dispatch(monkeypatch):
    row = {
        'id': 91,
        'competition_id': 29,
        'status': 'Judging',
        'scoring_mode': 'absolute',
        'judge_task_id': None,
        'created_at': datetime.now() - timedelta(minutes=20),
    }
    redis_client = _FakeRedis()
    task = _ResultTask()
    monkeypatch.setattr(startup_requeue, '_redis_client', lambda: redis_client)
    monkeypatch.setattr(startup_requeue.uuid, 'uuid4', lambda: 'dispatch-91')
    monkeypatch.setattr(
        startup_requeue,
        'get_incomplete_ranking_submissions',
        lambda: [row],
    )
    monkeypatch.setattr(
        startup_requeue,
        'reserve_standard_ranking_evaluation',
        lambda submission_id, task_id, **_kwargs: int(
            (submission_id, task_id) == (91, 'dispatch-91')
        ),
    )

    assert startup_requeue._requeue_orphaned_standard_ranking_submissions(task) == 1
    claim_key = startup_requeue._RANKING_REQUEUE_ITEM_KEY_FMT.format(submission_id=91)
    assert claim_key in redis_client.values
    assert task.calls == [([91], 0)]
    assert task.task_ids == ['dispatch-91']


def test_ranking_watchdog_releases_database_reservation_when_dispatch_fails(
        monkeypatch):
    row = {
        'id': 101,
        'competition_id': 39,
        'status': 'Judging',
        'scoring_mode': 'absolute',
        'judge_task_id': None,
        'created_at': datetime.now() - timedelta(minutes=20),
    }
    redis_client = _FakeRedis()
    released = []
    task = _ResultTask()
    monkeypatch.setattr(startup_requeue, '_redis_client', lambda: redis_client)
    monkeypatch.setattr(startup_requeue.uuid, 'uuid4', lambda: 'dispatch-101')
    monkeypatch.setattr(
        startup_requeue,
        'get_incomplete_ranking_submissions',
        lambda: [row],
    )
    monkeypatch.setattr(
        startup_requeue,
        'reserve_standard_ranking_evaluation',
        lambda *_args, **_kwargs: 1,
    )
    monkeypatch.setattr(
        startup_requeue,
        'release_standard_ranking_evaluation',
        lambda submission_id, task_id: released.append((submission_id, task_id)),
    )

    def fail_dispatch(**_kwargs):
        raise OSError('broker unavailable')

    monkeypatch.setattr(task, 'apply_async', fail_dispatch)

    assert startup_requeue._requeue_orphaned_standard_ranking_submissions(task) == 0
    assert released == [(101, 'dispatch-101')]
    claim_key = startup_requeue._RANKING_REQUEUE_ITEM_KEY_FMT.format(submission_id=101)
    assert claim_key not in redis_client.values


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
