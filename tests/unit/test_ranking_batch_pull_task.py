# -*- coding: utf-8 -*-
"""打榜赛 Git 批量拉取任务的模式分派测试。"""

import backend.oj_modules.tasks.ranking.batch_pull as m


class _FakeCelery:
    def task(self, **_kwargs):
        def deco(fn):
            return fn
        return deco


class _FakeTask:
    pass


def test_batch_run_dispatches_reverse_judge_task(monkeypatch):
    agent_task = _FakeTask()
    reverse_task = _FakeTask()
    seen = []

    monkeypatch.setattr(m, 'ITEM_SLEEP_SECONDS', 0.0)
    monkeypatch.setattr(m, 'get_competition', lambda cid: {'id': cid, 'scoring_mode': 'reverse_judge'})
    monkeypatch.setattr(
        m,
        '_process_one',
        lambda competition_id, username, url, judge_task, source='batch',
        mode='agent_judge', agent_endpoint_id=None:
            seen.append((competition_id, username, url, judge_task, source, mode, agent_endpoint_id)),
    )

    _probe_task, run_task = m.register_ranking_batch_tasks(
        _FakeCelery(), agent_judge_task=agent_task, reverse_judge_task=reverse_task,
    )
    run_task(None, 9, [{
        'username': 'student1',
        'url': 'git@example/repo.git',
        'source': 'self',
        'agent_endpoint_id': 17,
    }])

    assert seen == [(9, 'student1', 'git@example/repo.git', reverse_task, 'self', 'reverse_judge', 17)]


def test_batch_run_keeps_agent_judge_task_for_agent_mode(monkeypatch):
    agent_task = _FakeTask()
    reverse_task = _FakeTask()
    seen = []

    monkeypatch.setattr(m, 'ITEM_SLEEP_SECONDS', 0.0)
    monkeypatch.setattr(m, 'get_competition', lambda cid: {'id': cid, 'scoring_mode': 'agent_judge'})
    monkeypatch.setattr(
        m,
        '_process_one',
        lambda competition_id, username, url, judge_task, source='batch',
        mode='agent_judge', agent_endpoint_id=None:
            seen.append((competition_id, username, url, judge_task, source, mode, agent_endpoint_id)),
    )

    _probe_task, run_task = m.register_ranking_batch_tasks(
        _FakeCelery(), agent_judge_task=agent_task, reverse_judge_task=reverse_task,
    )
    run_task(None, 10, [{'username': 'student2', 'url': 'git@example/repo.git'}])

    assert seen == [(10, 'student2', 'git@example/repo.git', agent_task, 'batch', 'agent_judge', None)]
