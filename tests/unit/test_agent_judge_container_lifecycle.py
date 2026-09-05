"""Judge 端点池与通用 Agent 编排回归（不连接外部服务）。"""
from contextlib import contextmanager

import os

import tempfile

import json

import time

from types import SimpleNamespace

import pytest

import backend.oj_modules.tasks.ranking.agent_judge as m

def test_hello_probe_request_requires_configured_values():
    req, err = m._hello_probe_request({
        "harness": m.HARNESS_PI,
        "base_url": "https://openai-compatible/v1",
        "api_key": "k",
        "model": "",
    })
    assert req is None
    assert "模型为空" in err

def test_hello_probe_request_uses_exact_endpoint_config():
    req, err = m._hello_probe_request({
        "harness": m.HARNESS_PI,
        "base_url": "https://openai-compatible/v1",
        "api_key": "k",
        "model": "configured-model",
    })
    assert err is None
    assert req.full_url == "https://openai-compatible/v1/chat/completions"
    assert json.loads(req.data.decode("utf-8"))["model"] == "configured-model"

    req, err = m._hello_probe_request({
        "harness": m.HARNESS_CLAUDE_CODE,
        "base_url": "https://anthropic-compatible",
        "api_key": "k",
        "model": "configured-claude",
    })
    assert err is None
    assert req.full_url == "https://anthropic-compatible/v1/messages"
    assert json.loads(req.data.decode("utf-8"))["model"] == "configured-claude"

def test_pi_probe_uses_configured_url_and_model(monkeypatch):
    requests = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return Response()

    monkeypatch.setattr(m.urllib.request, "urlopen", fake_urlopen)
    ok, msg = m._probe_endpoint_once({
        "harness": m.HARNESS_PI,
        "base_url": "https://gate.example/custom/v1",
        "api_key": "gate-key",
        "model": "configured-gate-model",
    })

    assert ok is True and msg == "ok"
    assert len(requests) == 1
    request, timeout = requests[0]
    assert request.full_url == "https://gate.example/custom/v1/chat/completions"
    assert json.loads(request.data.decode("utf-8"))["model"] == "configured-gate-model"
    assert request.headers["Authorization"] == "Bearer gate-key"
    assert timeout == m.JUDGE_HELLO_TIMEOUT_SECONDS

def test_paused_pi_recovery_reuses_configured_endpoint(monkeypatch):
    requested_urls = []
    requested_models = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        requested_urls.append(request.full_url)
        requested_models.append(json.loads(request.data.decode("utf-8"))["model"])
        return Response()

    monkeypatch.setattr(m.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(m.time, "sleep", lambda *_args, **_kwargs: None)
    endpoint = {
        "id": 41,
        "pool_kind": "quality_gate",
        "harness": m.HARNESS_PI,
        "base_url": "https://recovery.example/api/v1",
        "api_key": "recovery-key",
        "model": "recovery-model",
        "status": m.ENDPOINT_STATUS_PAUSED,
    }

    successes, message = m._probe_paused_endpoint_for_resume(endpoint)

    assert successes == m.PAUSED_PROBE_ATTEMPTS
    assert message == "ok"
    assert requested_urls == [
        "https://recovery.example/api/v1/chat/completions"
    ] * m.PAUSED_PROBE_ATTEMPTS
    assert requested_models == ["recovery-model"] * m.PAUSED_PROBE_ATTEMPTS

def test_probe_pi_missing_key_fails_without_request(monkeypatch):
    called = []
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *_a, **_k: called.append(True))
    ok, msg = m._probe_endpoint_once({
        "harness": m.HARNESS_PI,
        "base_url": "",
        "api_key": "",
        "model": "",
    })
    assert ok is False
    assert "API Key" in msg
    assert called == []

def test_probe_error_message_redacts_key_and_control_characters():
    message = m._sanitize_probe_message(
        {"api_key": "secret-token"},
        "invalid Authorization: Bearer secret-token\r\nnext-line",
    )

    assert "secret-token" not in message
    assert "[redacted]" in message
    assert "\r" not in message
    assert "\n" not in message

def test_probe_endpoint_retries_configured_attempts(monkeypatch):
    calls = []

    def fake_probe_once(endpoint):
        calls.append(endpoint["id"])
        return False, "down"

    monkeypatch.setattr(m, "_probe_endpoint_once", fake_probe_once)
    monkeypatch.setattr(m.time, "sleep", lambda *_a, **_k: None)
    ok, msg = m._probe_endpoint({"id": 9}, attempts=5)
    assert ok is False
    assert msg == "down"
    assert calls == [9, 9, 9, 9, 9]

class _FakeCelery:
    def task(self, **_kwargs):
        def deco(fn):
            return fn
        return deco

class _FakeTaskSelf:
    class request:
        id = "req-1"

    def retry(self, **_kwargs):
        raise m.Retry()

def test_failed_hello_pauses_endpoint(monkeypatch):
    paused = []
    monkeypatch.setattr(m, "pause_agent_judge_endpoint", lambda eid: paused.append(eid) or 1)

    m._disable_unhealthy_endpoint({"id": 17}, "down")

    assert paused == [17]

def test_paused_endpoint_resume_probe_requires_three_successes(monkeypatch):
    seq = iter([(True, "ok"), (False, "down"), (True, "ok"), (False, "down"), (True, "ok")])
    calls = []

    def fake_probe_once(ep):
        calls.append(ep["id"])
        return next(seq)

    monkeypatch.setattr(m, "_probe_endpoint_once", fake_probe_once)
    monkeypatch.setattr(m.time, "sleep", lambda *_a, **_k: None)

    ok_count, last_msg = m._probe_paused_endpoint_for_resume({"id": 18})

    assert ok_count == 3
    assert last_msg == "down"
    assert calls == [18, 18, 18, 18, 18]

class _FakePeriodicSelf:
    def __init__(self):
        self.scheduled = []

    def apply_async(self, **kwargs):
        self.scheduled.append(kwargs)

def test_paused_probe_task_resumes_healthy_paused_endpoint(monkeypatch):
    resumed = []
    ep = {"id": 19, "status": m.ENDPOINT_STATUS_PAUSED}

    monkeypatch.setattr(m, "_ensure_judge_redis", lambda: None)
    monkeypatch.setattr(m, "list_paused_agent_judge_endpoints", lambda: [ep])
    monkeypatch.setattr(m, "_probe_paused_endpoint_for_resume", lambda endpoint: (3, "ok"))
    monkeypatch.setattr(m, "resume_paused_agent_judge_endpoint",
                        lambda eid: resumed.append(eid) or 1)

    task = m.register_ranking_agent_judge_paused_probe_task(_FakeCelery())
    fake_self = _FakePeriodicSelf()
    assert task(fake_self, "owner") == {"success": True, "checked": 1, "resumed": 1}
    assert resumed == [19]
    assert fake_self.scheduled

def test_paused_probe_task_ignores_non_paused_endpoint(monkeypatch):
    resumed = []
    probed = []

    monkeypatch.setattr(m, "_ensure_judge_redis", lambda: None)
    monkeypatch.setattr(m, "list_paused_agent_judge_endpoints",
                        lambda: [{"id": 20, "status": "disabled"}])
    monkeypatch.setattr(m, "_probe_paused_endpoint_for_resume",
                        lambda endpoint: probed.append(endpoint["id"]) or (5, "ok"))
    monkeypatch.setattr(m, "resume_paused_agent_judge_endpoint",
                        lambda eid: resumed.append(eid) or 1)

    task = m.register_ranking_agent_judge_paused_probe_task(_FakeCelery())
    fake_self = _FakePeriodicSelf()
    assert task(fake_self, "owner") == {"success": True, "checked": 0, "resumed": 0}
    assert probed == []
    assert resumed == []
    assert fake_self.scheduled

def test_paused_probe_task_reschedules_when_run_lock_is_busy(monkeypatch):
    class BusyRunLockRedis:
        def get(self, key):
            if key == m.PAUSED_PROBE_OWNER_KEY:
                return "owner"
            return None

        def set(self, key, *_args, **kwargs):
            if key == m.PAUSED_PROBE_RUN_LOCK_KEY and kwargs.get("nx"):
                return False
            return True

    monkeypatch.setattr(m, "_ensure_judge_redis", lambda: BusyRunLockRedis())
    monkeypatch.setattr(
        m,
        "list_paused_agent_judge_endpoints",
        lambda: pytest.fail("run-lock busy path should not probe endpoints"),
    )

    task = m.register_ranking_agent_judge_paused_probe_task(_FakeCelery())
    fake_self = _FakePeriodicSelf()
    assert task(fake_self, "owner") == {
        "success": True,
        "reason": "paused probe already running",
    }
    assert fake_self.scheduled == [{
        "args": ["owner"],
        "countdown": m.PAUSED_PROBE_INTERVAL_SECONDS,
    }]


class _PoolRedis:
    def __init__(self):
        self.values = {}
        self.options = []

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, **kwargs):
        self.options.append(kwargs)
        if kwargs.get('nx') and key in self.values:
            return False
        self.values[key] = value
        return True

    def eval(self, script, count, key, value):
        if self.values.get(key) == value:
            self.values.pop(key, None)
            return 1
        return 0

    def scan_iter(self, **kwargs):
        return list(self.values)


def test_pool_keeps_pending_turn_reservation_without_expiry(monkeypatch):
    redis = _PoolRedis()
    endpoints = [{'id': 1, 'concurrency_limit': 1}]
    endpoint, key, token = m._acquire_endpoint_slot(redis, endpoints, 3, 60, owner='turn-1')
    assert endpoint == endpoints[0]
    assert 'ex' not in redis.options[-1]
    monkeypatch.setattr(m, 'get_agent_session_by_task_id', lambda task: {'session_id': 'session-1'})
    monkeypatch.setattr(m, 'get_agent_session_turns', lambda sid: [{'task_id': 'turn-1', 'status': 'Pending'}])
    monkeypatch.setattr(m.time, 'time', lambda: 10**12)
    assert m._acquire_endpoint_slot(redis, endpoints, 4, 60, owner='turn-2') == (None, None, None)
    assert m._acquire_endpoint_slot(redis, endpoints, 3, 60, owner='turn-1') == (endpoint, key, token)
    assert m._acquire_endpoint_slot(None, endpoints, 3, 60, owner='turn-3') == (None, None, None)


def test_pool_reclaims_completed_but_keeps_cleanup_failure(monkeypatch):
    redis = _PoolRedis()
    endpoints = [{'id': 1, 'concurrency_limit': 1}]
    m._acquire_endpoint_slot(redis, endpoints, 3, 60, owner='turn-1')
    monkeypatch.setattr(m, 'get_agent_session_by_task_id', lambda task: {'session_id': 'session-1'})
    monkeypatch.setattr(m, 'get_agent_session_turns', lambda sid: [{'task_id': 'turn-1', 'status': 'CleanupFailed'}])
    assert m._acquire_endpoint_slot(redis, endpoints, 4, 60, owner='turn-2')[0] is None
    monkeypatch.setattr(m, 'get_agent_session_turns', lambda sid: [{'task_id': 'turn-1', 'status': 'Completed'}])
    assert m._acquire_endpoint_slot(redis, endpoints, 4, 60, owner='turn-2')[0] == endpoints[0]


def test_topology_continues_same_session_and_skips_failed_dependencies(monkeypatch):
    submission = {'id': 3, 'competition_id': 9, 'judge_attempt_id': 'attempt', 'username': 'alice'}
    competition = {'id': 9, 'title': '测试'}
    session_id = m.judge_session_id(3, 'attempt', 'agent_judge')
    session = {'session_id': session_id, 'current_task_id': f'{session_id}-rule-1', 'endpoint_id': 7}
    rules = m.aj.normalize_rules([
        {'rule_id': 1, 'rule_text': '基础规则', 'value': 10, 'dependencies': []},
        {'rule_id': 2, 'rule_text': '依赖规则', 'value': 20, 'dependencies': [1]},
        {'rule_id': 3, 'rule_text': '独立规则', 'value': 30, 'dependencies': []},
    ])
    monkeypatch.setattr(m, 'list_competition_rules', lambda cid: rules)
    monkeypatch.setattr(m, 'get_agent_session', lambda sid: session)
    monkeypatch.setattr(m, 'get_agent_session_turns', lambda sid: [{
        'task_id': f'{session_id}-rule-1', 'status': 'Completed',
        'conclusion': '{"rule_id":1,"result":"failed","evidence":"检查未通过"}',
    }])
    monkeypatch.setattr(m, 'list_judge_results', lambda sid: [])
    monkeypatch.setattr(m, '_publish_snapshot', lambda sid: None)
    monkeypatch.setattr(m, '_release_task_slot', lambda *args: None)
    records = []
    monkeypatch.setattr(m, 'upsert_judge_result_for_attempt', lambda *args: records.append(args) or 1)
    phases = []
    monkeypatch.setattr(m, '_dispatch_judge_phase', lambda *args: phases.append(args) or {'queued': True})
    assert m._advance_agent_judge(object(), object(), submission, competition) == {'queued': True}
    assert [(row[2], row[4]) for row in records] == [(1, 'failed'), (2, 'skipped')]
    assert phases[0][5] is session
    assert phases[0][6] == 'rule-3'


def test_rule_result_rejects_other_rules_and_surrounding_tool_text():
    assert m._parse_rule_conclusion('{"rule_id":2,"result":"pass"}', 1) is None
    assert m._parse_rule_conclusion('tool output\n{"rule_id":1,"result":"pass"}', 1) is None
    assert m._parse_rule_conclusion('```json\n{"rule_id":1,"result":"pass"}\n```', 1)['result'] == 'pass'


def test_pool_never_reclaims_slow_input_preparation_without_a_session(monkeypatch):
    redis = _PoolRedis()
    endpoints = [{'id': 1, 'concurrency_limit': 1}]
    first = m._acquire_endpoint_slot(redis, endpoints, 3, 60, owner='slow-turn')
    monkeypatch.setattr(m, 'get_agent_session_by_task_id', lambda _: None)
    monkeypatch.setattr(m.time, 'time', lambda: 10**12)
    assert m._acquire_endpoint_slot(redis, endpoints, 4, 60, owner='another-turn') == (None, None, None)
    assert m._acquire_endpoint_slot(redis, endpoints, 3, 60, owner='slow-turn') == first


def test_deleted_frozen_endpoint_reports_error_instead_of_waiting_forever(monkeypatch):
    monkeypatch.setattr(m, '_resolve_endpoints', lambda *_: [{'id': 12}])
    monkeypatch.setattr(m, 'list_agent_judge_endpoints', lambda _: [{'id': 12}])
    monkeypatch.setattr(m, '_wait_for_judge_turn', lambda *_a, **_k: pytest.fail('被删除的绑定端点不能无限等待'))
    with pytest.raises(ValueError, match='已被删除'):
        m._dispatch_judge_phase(
            object(), object(), {'id': 3, 'judge_attempt_id': 'attempt'}, {'id': 9},
            [], {'endpoint_id': 11}, 'rule-2', '下一条规则',
        )
