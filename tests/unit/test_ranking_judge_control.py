"""停止评测必须与业务派发互斥，并在通用轮次停止后释放端点名额。"""

import fnmatch

import pytest
from flask import Flask

from backend.oj_modules.ranking import judge_control as control
from backend.oj_modules.routes import ranking_routes as routes


class Redis:
    def __init__(self):
        self.data = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.data:
            return False
        self.data[key] = value
        return True

    def get(self, key):
        return self.data.get(key)

    def scan_iter(self, match, **kwargs):
        return [key for key in self.data if fnmatch.fnmatch(key, match)]

    def eval(self, script, count, key, expected):
        if self.data.get(key) == expected:
            del self.data[key]
            return 1
        return 0


@pytest.fixture
def judge_sessions(monkeypatch):
    rows = {
        'reverse_quality': {'current_task_id': 'quality', 'status': 'Completed'},
        'reverse_answer': {'current_task_id': 'answer', 'status': 'Pending'},
    }
    monkeypatch.setattr(control, 'get_judge_session_for_attempt', lambda sid, attempt, kind: rows.get(kind))
    redis = Redis()
    redis.data.update({
        'aj:ep:-7:slot:0': b'turn|123|quality',
        'aj:ep:8:slot:0': 'turn|123|answer',
        'aj:ep:8:slot:1': 'turn|123|another-submission',
    })
    return rows, redis


def test_stop_holds_business_lock_and_both_pool_slots_until_attempt_changes(judge_sessions):
    rows, redis = judge_sessions
    stopped = []

    def terminate(task_id):
        stopped.append(task_id)
        rows['reverse_answer']['status'] = 'Canceled'
        return {'errors': []}

    with control.stopped_judge_submission(
        {'id': 7, 'judge_attempt_id': 'attempt'}, 'reverse_judge',
        redis_client=redis, terminate_agent=terminate,
    ):
        assert 'ranking:reverse_judge:lock:7:attempt' in redis.data
        assert redis.data['aj:ep:-7:slot:0'] == b'turn|123|quality'
        assert redis.data['aj:ep:8:slot:0'] == 'turn|123|answer'
        assert stopped == ['answer']
        # 调用方此处原子切换 attempt；离开上下文之前名额仍保留。
    assert redis.data == {'aj:ep:8:slot:1': 'turn|123|another-submission'}


def test_stop_failure_keeps_attempt_and_all_endpoint_slots(judge_sessions):
    rows, redis = judge_sessions
    with pytest.raises(control.JudgeCancellationError, match='容器清理失败'):
        with control.stopped_judge_submission(
            {'id': 7, 'judge_attempt_id': 'attempt'}, 'reverse_judge',
            redis_client=redis, terminate_agent=lambda tid: {'errors': ['容器清理失败']},
        ):
            pytest.fail('停止失败时不应允许变更 attempt')
    assert len(redis.data) == 3
    assert rows['reverse_answer']['status'] == 'Pending'


def test_stop_requires_persisted_terminal_readback(judge_sessions):
    _rows, redis = judge_sessions
    with pytest.raises(control.JudgeCancellationError, match='状态尚未确认'):
        with control.stopped_judge_submission(
            {'id': 7, 'judge_attempt_id': 'attempt'}, 'reverse_judge',
            redis_client=redis, terminate_agent=lambda tid: {'exists': False, 'errors': []},
        ):
            pytest.fail('没有错误的回包并不足以证明持久队列已停止')
    assert len(redis.data) == 3


def test_stop_does_not_race_an_active_business_phase(judge_sessions):
    _rows, redis = judge_sessions
    redis.data['ranking:reverse_judge:lock:7:attempt'] = 'active-worker'
    with pytest.raises(control.JudgeCancellationError, match='正在推进'):
        with control.stopped_judge_submission(
            {'id': 7, 'judge_attempt_id': 'attempt'}, 'reverse_judge',
            redis_client=redis, terminate_agent=lambda tid: pytest.fail('不应在锁外停止'),
        ):
            pytest.fail('活跃业务阶段未让出锁')
    assert redis.data['ranking:reverse_judge:lock:7:attempt'] == 'active-worker'


@pytest.mark.parametrize('operation', ['ranking_rejudge_agent', 'ranking_delete_submission'])
def test_http_delete_and_rejudge_refuse_to_change_submission_until_stopped(monkeypatch, operation):
    monkeypatch.setattr(routes, '_require_admin', lambda: ({'is_admin': 1}, None))
    monkeypatch.setattr(routes, 'get_ranking_submission', lambda sid: {'id': sid, 'competition_id': 3})
    monkeypatch.setattr(routes, 'get_competition', lambda cid: {'id': cid, 'scoring_mode': 'reverse_judge'})
    monkeypatch.setattr(routes, '_cancel_ranking_submission_runtime', lambda *args: ['通用 Agent 清理失败'])
    monkeypatch.setattr(routes, 'begin_agent_judge_attempt', lambda *args, **kwargs: pytest.fail('不能重测'))
    monkeypatch.setattr(routes, 'delete_ranking_submission', lambda *args: pytest.fail('不能删除'))
    monkeypatch.setattr(routes, 'submission_dir', lambda *args: pytest.fail('不能删除文件'))
    app = Flask(__name__)
    with app.test_request_context(headers={'Accept': 'application/json'}):
        response, status = getattr(routes, operation)(3, 7)
    assert status == 409
    assert response.get_json()['success'] is False
