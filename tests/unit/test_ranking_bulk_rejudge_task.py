# -*- coding: utf-8 -*-
"""打榜赛批量重测任务：必须在原提交记录上重测，不创建新提交。"""

import oj_modules.tasks.ranking_bulk_rejudge_tasks as m


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
    cleared = []
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
    monkeypatch.setattr(m, 'clear_judge_results', lambda sid: cleared.append(int(sid)))
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

    assert cleared == [101, 102]
    assert [c[1]['args'] for c in agent_task.calls] == [
        [101, 'attempt-101'],
        [102, 'attempt-102'],
    ]
    assert eval_task.calls == []
    assert attempts == [
        (101, {'status': 'Queued', 'reset_result': True}),
        (102, {'status': 'Queued', 'reset_result': True}),
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
    cleared_reverse = []
    cleared_agent = []
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
    monkeypatch.setattr(m, 'clear_reverse_judge_steps', lambda sid: cleared_reverse.append(int(sid)))
    monkeypatch.setattr(m, 'clear_judge_results', lambda sid: cleared_agent.append(int(sid)))
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

    assert cleared_reverse == [201]
    assert cleared_agent == []
    assert [c[1]['args'] for c in reverse_task.calls] == [[201, 'reverse-attempt-201']]
    assert agent_task.calls == []
    assert eval_task.calls == []
    assert attempts == [(201, {'status': 'Queued', 'reset_result': True})]
    assert jobs['job2']['status'] == 'finished'
    assert jobs['job2']['requeued'] == 1
    assert jobs['job2']['requeued_ids'] == [201]
