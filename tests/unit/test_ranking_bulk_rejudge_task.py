# -*- coding: utf-8 -*-
"""打榜赛批量重测任务：必须在原提交记录上重测，不创建新提交。"""

from contextlib import nullcontext

import pytest
import backend.oj_modules.tasks.ranking.bulk_rejudge as m


@pytest.fixture(autouse=True)
def mock_judge_stop(monkeypatch):
    monkeypatch.setattr(m, "_ensure_rds", lambda: object())
    monkeypatch.setattr(m, "stopped_judge_submission", lambda *args, **kwargs: nullcontext())



class _FakeCelery:
    def task(self, **_kwargs):
        def deco(fn):
            return fn
        return deco


class _FakeAsyncTask:
    def __init__(self):
        self.calls = []

    def apply_async(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return type("AsyncResult", (), {"id": "task-id"})()


def test_bulk_rejudge_requeues_original_agent_judge_submissions(monkeypatch):
    comp = {'id': 7, 'scoring_mode': 'agent_judge'}
    submissions = {
        101: {'id': 101, 'competition_id': 7, 'username': 'u1'},
        102: {'id': 102, 'competition_id': 7, 'username': 'u2'},
    }
    jobs = {'job1': {'competition_id': 7}}
    attempts = []
    statuses = []
    agent_task = _FakeAsyncTask()
    eval_task = _FakeAsyncTask()

    monkeypatch.setattr(m, 'ITEM_SLEEP_SECONDS', 0.0)
    monkeypatch.setattr(m, 'get_competition', lambda cid: comp)
    monkeypatch.setattr(m, 'get_ranking_submission', lambda sid: submissions.get(int(sid)))
    monkeypatch.setattr(m, 'get_bulk_rejudge_job', lambda job_id: dict(jobs.get(job_id) or {}))
    monkeypatch.setattr(m, 'save_bulk_rejudge_job',
                        lambda job_id, payload: jobs.__setitem__(job_id, dict(payload)))
    monkeypatch.setattr(
        m,
        'begin_agent_judge_attempt',
        lambda sid, **kw: attempts.append((int(sid), dict(kw))) or f'attempt-{int(sid)}',
    )
    monkeypatch.setattr(m, 'set_agent_judge_task_id', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        m, 'update_submission_result',
        lambda sid, score, status, grade_details=None, error_message=None:
            statuses.append((int(sid), score, status, grade_details, error_message)),
    )

    task = m.register_ranking_bulk_rejudge_task(
        _FakeCelery(), eval_task, agent_judge_task=agent_task,
    )
    task(7, [101, 102], 'job1', 'admin')

    assert [c[1]['args'] for c in agent_task.calls] == [
        [101, 'attempt-101'],
        [102, 'attempt-102'],
    ]
    assert eval_task.calls == []
    assert attempts == [
        (101, {'status': 'Queued', 'reset_result': True, 'clear_agent_results': True}),
        (102, {'status': 'Queued', 'reset_result': True, 'clear_agent_results': True}),
    ]
    assert statuses == []
    assert jobs['job1']['status'] == 'finished'
    assert jobs['job1']['requeued'] == 2
    assert jobs['job1']['requeued_ids'] == [101, 102]
    assert jobs['job1'].get('created', 0) == 0
    assert jobs['job1'].get('created_ids', []) == []


def test_bulk_rejudge_requeues_original_reverse_judge_submissions(monkeypatch):
    comp = {'id': 8, 'scoring_mode': 'reverse_judge'}
    submissions = {
        201: {'id': 201, 'competition_id': 8, 'username': 'u1'},
    }
    jobs = {'job2': {'competition_id': 8}}
    attempts = []
    reverse_task = _FakeAsyncTask()
    agent_task = _FakeAsyncTask()
    eval_task = _FakeAsyncTask()

    monkeypatch.setattr(m, 'ITEM_SLEEP_SECONDS', 0.0)
    monkeypatch.setattr(m, 'get_competition', lambda cid: comp)
    monkeypatch.setattr(m, 'get_ranking_submission', lambda sid: submissions.get(int(sid)))
    monkeypatch.setattr(m, 'get_bulk_rejudge_job', lambda job_id: dict(jobs.get(job_id) or {}))
    monkeypatch.setattr(m, 'save_bulk_rejudge_job',
                        lambda job_id, payload: jobs.__setitem__(job_id, dict(payload)))
    monkeypatch.setattr(
        m,
        'begin_agent_judge_attempt',
        lambda sid, **kw: attempts.append((int(sid), dict(kw))) or f'reverse-attempt-{int(sid)}',
    )
    monkeypatch.setattr(m, 'set_agent_judge_task_id', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(m, 'update_submission_result', lambda *_args, **_kwargs: None)

    task = m.register_ranking_bulk_rejudge_task(
        _FakeCelery(), eval_task, agent_judge_task=agent_task, reverse_judge_task=reverse_task,
    )
    task(8, [201], 'job2', 'admin')

    assert [c[1]['args'] for c in reverse_task.calls] == [[201, 'reverse-attempt-201']]
    assert agent_task.calls == []
    assert eval_task.calls == []
    assert attempts == [(201, {
        'status': 'Queued', 'reset_result': True, 'clear_reverse_steps': True,
    })]
    assert jobs['job2']['status'] == 'finished'
    assert jobs['job2']['requeued'] == 1
    assert jobs['job2']['requeued_ids'] == [201]


def test_bulk_rejudge_reserves_standard_task_id_before_dispatch(monkeypatch):
    comp = {'id': 9, 'scoring_mode': 'absolute'}
    submission = {'id': 301, 'competition_id': 9, 'username': 'u1'}
    jobs = {'job3': {'competition_id': 9}}
    statuses = []
    reservations = []
    eval_task = _FakeAsyncTask()

    monkeypatch.setattr(m, 'ITEM_SLEEP_SECONDS', 0.0)
    monkeypatch.setattr(m, 'get_competition', lambda _cid: comp)
    monkeypatch.setattr(m, 'get_ranking_submission', lambda _sid: submission)
    monkeypatch.setattr(m, 'get_bulk_rejudge_job', lambda job_id: dict(jobs.get(job_id) or {}))
    monkeypatch.setattr(
        m,
        'save_bulk_rejudge_job',
        lambda job_id, payload: jobs.__setitem__(job_id, dict(payload)),
    )
    monkeypatch.setattr(
        m,
        'update_submission_result',
        lambda sid, score, status, grade_details=None, error_message=None: statuses.append(
            (sid, score, status, grade_details, error_message)
        ),
    )
    monkeypatch.setattr(m.uuid, 'uuid4', lambda: 'bulk-task-301')
    monkeypatch.setattr(
        m,
        'reserve_standard_ranking_evaluation',
        lambda submission_id, task_id, **kwargs: reservations.append(
            (submission_id, task_id, kwargs)
        ) or 1,
    )

    task = m.register_ranking_bulk_rejudge_task(_FakeCelery(), eval_task)
    task(9, [301], 'job3', 'admin')

    assert statuses == [(301, None, 'Judging', None, None)]
    assert reservations == [(301, 'bulk-task-301', {'force': True})]
    assert eval_task.calls == [((), {
        'args': [301],
        'task_id': 'bulk-task-301',
    })]
    assert jobs['job3']['status'] == 'finished'
    assert jobs['job3']['requeued'] == 1


def test_bulk_rejudge_elo_keeps_activation_and_retirement_in_one_boundary(monkeypatch):
    comp = {'id': 10, 'scoring_mode': 'elo', 'elo_initial_rating': 1550}
    submission = {'id': 401, 'competition_id': 10, 'username': 'u1'}
    jobs = {'job4': {'competition_id': 10}}
    activations = []
    burst = _FakeAsyncTask()

    monkeypatch.setattr(m, 'ITEM_SLEEP_SECONDS', 0.0)
    monkeypatch.setattr(m, 'get_competition', lambda _cid: comp)
    monkeypatch.setattr(m, 'get_ranking_submission', lambda _sid: submission)
    monkeypatch.setattr(m, 'get_bulk_rejudge_job', lambda job_id: dict(jobs.get(job_id) or {}))
    monkeypatch.setattr(
        m,
        'save_bulk_rejudge_job',
        lambda job_id, payload: jobs.__setitem__(job_id, dict(payload)),
    )
    monkeypatch.setattr(
        m,
        'activate_elo_submission',
        lambda *args, **kwargs: activations.append((args, kwargs)),
    )

    task = m.register_ranking_bulk_rejudge_task(
        _FakeCelery(),
        _FakeAsyncTask(),
        elo_initial_burst_task=burst,
    )
    task(10, [401], 'job4', 'admin')

    assert activations == [((401, 10, 'u1', 1550.0), {'keep_count': 2})]
    assert burst.calls == [((), {'args': [10, 401], 'countdown': 3})]
    assert jobs['job4']['requeued'] == 1
