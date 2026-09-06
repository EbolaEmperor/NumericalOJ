"""Judge 端点池与通用 Agent 编排回归（不连接外部服务）。"""
from contextlib import contextmanager

import os

import tempfile

import json
from io import BytesIO

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
    competition = {'id': 9, 'title': '测试', 'agent_judge_orchestration_mode': 'topological'}
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
        'user_message': '最终回答必须只有一个 JSON 对象\n多行证据使用 JSON 字符串转义。',
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
    assert phases[0][7] == m.aj.build_rule_prompt('测试', rules[2], continuation=True)


def test_rule_result_rejects_other_rules_and_surrounding_tool_text():
    assert m._parse_rule_conclusion('{"rule_id":2,"result":"pass"}', 1) is None
    assert m._parse_rule_conclusion('tool output\n{"rule_id":1,"result":"pass"}', 1) is None
    assert m._parse_rule_conclusion('```json\n{"rule_id":1,"result":"pass"}\n```', 1)['result'] == 'pass'


@pytest.fixture
def single_flow(monkeypatch):
    flow = SimpleNamespace(
        submission={'id': 3, 'competition_id': 9, 'judge_attempt_id': 'attempt', 'username': 'alice'},
        competition={'id': 9, 'title': '单轮测试', 'description': '比赛说明', 'agent_judge_timeout_seconds': 90},
        session_id=m.judge_session_id(3, 'attempt', 'agent_judge'),
        session=None, turns=[], results={}, writes=[], updates=[], submissions=[], statuses=[], releases=[],
        current=True, client=_PoolRedis(), task=_FakeTaskSelf(), workspace={}, reads=[], snapshot={},
    )
    flow.task.app = object()
    flow.rules = m.aj.normalize_rules([
        {'rule_id': 1, 'rule_text': '基础规则', 'value': 10, 'dependencies': []},
        {'rule_id': 2, 'rule_text': '依赖规则', 'value': 20, 'dependencies': [1]},
        {'rule_id': 3, 'rule_text': '独立规则', 'value': 30, 'dependencies': []},
        {'rule_id': 4, 'rule_text': '缺失规则', 'value': 40, 'dependencies': []},
        {'rule_id': 5, 'rule_text': '依赖缺失规则', 'value': 50, 'dependencies': [4]},
    ])
    monkeypatch.setattr(m, 'list_competition_rules', lambda _: flow.rules)
    monkeypatch.setattr(m, 'list_competition_files', lambda _: [])
    monkeypatch.setattr(m, 'get_agent_session', lambda _: flow.session)
    monkeypatch.setattr(m, 'get_agent_session_by_task_id', lambda _: flow.session)
    monkeypatch.setattr(m, 'get_agent_session_turns', lambda _: flow.turns)
    monkeypatch.setattr(m, 'get_agent_run_snapshot', lambda _: flow.snapshot)
    monkeypatch.setattr(m, 'list_judge_results', lambda _: list(flow.results.values()))
    monkeypatch.setattr(m, '_attempt_still_current', lambda *_: flow.current)
    monkeypatch.setattr(m, '_publish_snapshot', lambda _: None)
    monkeypatch.setattr(m, '_release_task_slot', lambda _client, task_id: flow.releases.append(task_id))
    monkeypatch.setattr(m, 'set_submission_status_for_attempt', lambda sid, attempt, status: flow.statuses.append(status) or 1)
    monkeypatch.setattr(m, 'update_submission_result_for_attempt', lambda *args, **kwargs: flow.updates.append((args, kwargs)) or 1)
    endpoint = {'id': 7, 'harness': 'pi', 'model': 'test-model', 'concurrency_limit': 1}
    monkeypatch.setattr(m, '_resolve_endpoints', lambda *_: [endpoint])
    monkeypatch.setattr(m, '_probe_endpoint', lambda _: (True, 'ok'))

    def write_result(sid, attempt, rid, raw, effective, score, evidence):
        flow.writes.append((sid, attempt, rid, raw, effective, score, evidence))
        if not flow.current:
            return 0
        flow.results[rid] = {'rule_id': rid, 'raw_result': raw, 'effective_result': effective,
                             'score': score, 'evidence': evidence}
        return 1

    def submit(**kwargs):
        assert kwargs['dispatch_guard']()
        flow.submissions.append(kwargs)
        flow.session = {'session_id': flow.session_id, 'current_task_id': kwargs['task_id'], 'endpoint_id': 7}
        flow.turns.append({'task_id': kwargs['task_id'], 'status': 'Pending', 'conclusion': '', 'user_message': kwargs['prompt']})
        flow.workspace.update(kwargs.get('files') or {})

    def read_file(session_id, path):
        assert session_id == flow.session_id
        flow.reads.append(path)
        if path not in flow.workspace:
            raise FileNotFoundError(path)
        data = flow.workspace[path]
        return BytesIO(data), {'size': len(data), 'path': path}

    monkeypatch.setattr(m, 'upsert_judge_result_for_attempt', write_result)
    monkeypatch.setattr(m, 'submit_judge_turn', submit)
    monkeypatch.setattr(m, 'open_agent_workspace_file', read_file)
    return flow


def _saved_turn(flow, phase='single', status='Completed', conclusion='已完成评测并填写评分文件。'):
    task_id = f'{flow.session_id}-{phase}'
    flow.session = {'session_id': flow.session_id, 'current_task_id': task_id, 'endpoint_id': 7}
    flow.turns = [{'task_id': task_id, 'status': status, 'conclusion': conclusion,
                   'user_message': '请填写 workspace 中的评分文件。'}]


def _write_results(flow, value, path='judge_results.json'):
    flow.workspace[path] = json.dumps(value, ensure_ascii=False).encode('utf-8')


@pytest.mark.parametrize('mode', [None, 'single'])
def test_single_dispatches_one_generic_turn_and_injects_materials_once(single_flow, mode):
    flow = single_flow
    if mode is not None:
        flow.competition['agent_judge_orchestration_mode'] = mode
    with pytest.raises(m.Retry):
        m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    dispatched, = flow.submissions
    assert dispatched['task_id'] == f'{flow.session_id}-single'
    assert dispatched['prompt'] == m.aj.build_prompt('单轮测试')
    assert dispatched['timeout_seconds'] == 90
    assert dispatched['files']['description.md'] == '比赛说明'.encode()
    assert json.loads(dispatched['files']['rules.json']) == m.aj.build_rules_json(flow.rules)
    assert json.loads(dispatched['files']['judge_results.json']) == [
        {'rule_id': rule['rule_id'], 'result': None, 'evidence': ''} for rule in flow.rules
    ]
    assert flow.statuses == ['Judging']
    with pytest.raises(m.Retry):
        m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    _write_results(flow, [{'rule_id': 3, 'result': 'pass', 'evidence': '已检查'}])
    flow.turns[0].update(status='Completed', conclusion='文件已填写完成。')
    assert m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)['success']
    assert m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)['success']
    assert len(flow.submissions) == 1
    assert flow.updates[-1][0][2:4] == (30.0, 'Accepted')


def test_single_file_keeps_first_valid_known_rule_and_applies_dependency_gates(single_flow):
    flow = single_flow
    _saved_turn(flow)
    _write_results(flow, [
        {'rule_id': 1, 'result': None, 'evidence': '模板空值'},
        {'rule_id': 1, 'result': 'failed', 'evidence': '首条有效结果'},
        {'rule_id': 1, 'result': 'pass', 'evidence': '后续结果不能覆盖'},
        {'rule_id': 1, 'result': 'unsupported', 'evidence': '不能覆盖有效结果'},
        {'rule_id': 2, 'result': 'pass', 'evidence': '依赖规则声称通过'},
        {'rule_id': 3, 'result': 'pass', 'evidence': '独立通过'},
        {'rule_id': 999, 'result': 'pass', 'evidence': '未配置的规则'},
    ])
    assert m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)['success']
    assert set(flow.results) == {1, 2, 3, 4, 5}
    assert flow.results[1]['raw_result'] == 'failed'
    assert flow.results[1]['evidence'] == '首条有效结果'
    assert {rid: row['effective_result'] for rid, row in flow.results.items()} == {
        1: 'failed', 2: 'skipped', 3: 'pass', 4: 'error', 5: 'skipped',
    }
    assert flow.updates[-1][0][2:4] == (30.0, 'Accepted')
    assert flow.submissions == []


def test_single_limits_result_file_reads_and_preserves_saved_scores(single_flow, monkeypatch):
    flow = single_flow
    _saved_turn(flow, status='Running')
    limit = m._UNTRUSTED_RESULT_MAX_BYTES
    assert limit == 1024 * 1024
    reads = []

    class BoundedStream(BytesIO):
        def read(self, size=-1):
            assert size == limit + 1
            data = super().read(size)
            reads.append((size, len(data)))
            return data

    def read_file(_session_id, path):
        data = flow.workspace[path]
        return BoundedStream(data), {'size': len(data)}

    monkeypatch.setattr(m, 'open_agent_workspace_file', read_file)
    _write_results(flow, [{'rule_id': 3, 'result': 'pass', 'evidence': '已保存的评分'}])
    flow.workspace['judge_results.json'] = flow.workspace['judge_results.json'].ljust(limit, b' ')
    with pytest.raises(m.Retry):
        m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    assert flow.results[3]['raw_result'] == 'pass'

    _write_results(flow, [{'rule_id': 1, 'result': 'pass', 'evidence': '超限文件不能新增评分'}])
    flow.workspace['judge_results.json'] = flow.workspace['judge_results.json'].ljust(limit + 128, b' ')
    flow.turns[0]['status'] = 'Failed'
    assert m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)['success']
    assert reads == [(limit + 1, limit), (limit + 1, limit + 1)]
    assert flow.results[1]['raw_result'] is None
    assert flow.results[3]['raw_result'] == 'pass'
    assert flow.results[3]['evidence'] == '已保存的评分'
    assert flow.updates[-1][0][2:4] == (30.0, 'Accepted')


@pytest.mark.parametrize('content', [
    None, '[]', '{"rule_id":1,"result":"pass"}', 'incomplete [{"rule_id":1',
    '[{"rule_id":999,"result":"pass"}]', '[{"rule_id":1,"result":"unsupported"}]',
])
def test_single_without_valid_file_results_ignores_reply_json_and_finishes_error(single_flow, content):
    flow = single_flow
    _saved_turn(flow, conclusion='[{"rule_id":1,"result":"pass","evidence":"回复不算评分文件"}]')
    if content is not None:
        flow.workspace['judge_results.json'] = content.encode()
    assert m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)['success']
    assert flow.updates[-1][0][2:4] == (None, 'Error')
    assert flow.submissions == []


def test_existing_single_turn_keeps_mode_after_admin_changes_configuration(single_flow):
    flow = single_flow
    flow.competition['agent_judge_orchestration_mode'] = 'topological'
    _saved_turn(flow)
    _write_results(flow, [{'rule_id': 3, 'result': 'pass'}])
    assert m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)['success']
    assert flow.updates[-1][0][2:4] == (30.0, 'Accepted')
    assert flow.submissions == []


@pytest.mark.parametrize('prior_skipped_rule', [False, True])
def test_existing_setup_turn_keeps_topology_after_admin_selects_single(single_flow, prior_skipped_rule):
    flow = single_flow
    flow.competition['agent_judge_orchestration_mode'] = 'single'
    _saved_turn(flow, phase='setup', conclusion='环境准备完成')
    if prior_skipped_rule:
        # 后端已有跳过记录不等于曾向 Agent 发送过评分轮次。
        flow.results[1] = {'rule_id': 1, 'raw_result': None, 'effective_result': 'skipped'}
    first_rule = flow.rules[2] if prior_skipped_rule else flow.rules[0]
    rid = first_rule['rule_id']
    with pytest.raises(m.Retry):
        m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    dispatched, = flow.submissions
    assert dispatched['task_id'] == f'{flow.session_id}-rule-{rid}'
    assert dispatched['prompt'] == m.aj.build_rule_prompt('单轮测试', first_rule, continuation=False)
    assert len(dispatched['prompt']) > len(m.aj.build_rule_prompt('单轮测试', first_rule, continuation=True))
    assert '后端已经按照拓扑序检查依赖' not in dispatched['prompt']
    assert list(dispatched['files']) == [f'judge_result_{rid}.json']
    assert json.loads(dispatched['files'][f'judge_result_{rid}.json']) == {'rule_id': rid, 'result': None, 'evidence': ''}
    if prior_skipped_rule:
        assert flow.results[2]['effective_result'] == 'skipped'
        assert [turn['task_id'] for turn in flow.turns] == [f'{flow.session_id}-setup', f'{flow.session_id}-rule-3']


@pytest.mark.parametrize('status', ['Pending', 'Running'])
def test_single_pending_or_running_turn_waits_without_resubmitting(single_flow, status):
    flow = single_flow
    _saved_turn(flow, status=status)
    with pytest.raises(m.Retry):
        m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    assert flow.statuses == ['Queued' if status == 'Pending' else 'Judging']
    assert flow.submissions == flow.releases == flow.writes == []


@pytest.mark.parametrize('failure_source', ['snapshot_timeout', 'session_timeout', 'failure'])
def test_single_polls_first_results_and_keeps_them_when_later_run_fails(single_flow, failure_source):
    flow = single_flow
    _saved_turn(flow, status='Running')
    _write_results(flow, [{'rule_id': 1, 'result': 'failed', 'evidence': '运行中首条有效评分'}])
    with pytest.raises(m.Retry):
        m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    assert flow.results[1]['raw_result'] == 'failed'
    assert flow.updates == flow.releases == []

    _write_results(flow, [
        {'rule_id': 1, 'result': 'pass', 'evidence': '后写文件不得覆盖'},
        {'rule_id': 3, 'result': 'pass', 'evidence': '失败前已完成的独立规则'},
    ])
    flow.turns[0]['status'] = 'Failed'
    if failure_source == 'snapshot_timeout':
        flow.snapshot = {'harness_status': 'timeout'}
    elif failure_source == 'session_timeout':
        flow.session['message'] = 'Agent harness 超时'
    assert m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)['success']
    assert flow.results[1]['raw_result'] == 'failed'
    assert flow.results[1]['evidence'] == '运行中首条有效评分'
    assert flow.results[3]['raw_result'] == 'pass'
    assert flow.updates[-1][0][2:4] == (30.0, 'Accepted')
    assert flow.updates[-1][1]['grade_details']['timed_out'] is (failure_source != 'failure')
    assert flow.releases == [f'{flow.session_id}-single']
    assert flow.submissions == []


@pytest.mark.parametrize('status', ['Failed', 'Canceled'])
def test_single_failed_or_canceled_without_file_results_is_error(single_flow, status):
    flow = single_flow
    _saved_turn(flow, status=status)
    assert m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)['success']
    assert flow.updates[-1][0][2:4] == (None, 'Error')
    assert flow.releases == [f'{flow.session_id}-single']
    assert flow.submissions == []


def test_topology_reads_only_executed_rule_file_and_resets_next_template(single_flow):
    flow = single_flow
    flow.competition['agent_judge_orchestration_mode'] = 'topological'
    _saved_turn(flow, phase='rule-1', conclusion='{"rule_id":1,"result":"pass"}')
    flow.rules[0]['rule_text'] = '检查参赛者输出是否包含：最终回答必须只有一个 JSON 对象'
    flow.turns[0]['user_message'] = m.aj.build_rule_prompt('单轮测试', flow.rules[0])
    _write_results(flow, {'rule_id': 1, 'result': 'failed', 'evidence': '当前文件结果'}, 'judge_result_1.json')
    _write_results(flow, {'rule_id': 2, 'result': 'pass'}, 'judge_result_2.json')
    _write_results(flow, {'rule_id': 3, 'result': 'pass'}, 'judge_result_3.json')
    with pytest.raises(m.Retry):
        m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    assert flow.reads == ['judge_result_1.json']
    assert flow.results[1]['raw_result'] == 'failed'
    assert flow.results[2]['effective_result'] == 'skipped'
    assert 3 not in flow.results
    dispatched, = flow.submissions
    assert dispatched['task_id'] == f'{flow.session_id}-rule-3'
    assert dispatched['prompt'] == m.aj.build_rule_prompt('单轮测试', flow.rules[2], continuation=True)
    assert len(dispatched['prompt']) < len(m.aj.build_rule_prompt('单轮测试', flow.rules[2], continuation=False))
    assert '后端已经按照拓扑序检查依赖' not in dispatched['prompt']
    assert 'judge_result_3.json' in dispatched['prompt']
    assert json.loads(flow.workspace['judge_result_3.json']) == {'rule_id': 3, 'result': None, 'evidence': ''}


def test_single_cleanup_failure_never_reads_results_or_releases_slot(single_flow):
    flow = single_flow
    _saved_turn(flow, status='CleanupFailed')
    _write_results(flow, [{'rule_id': 3, 'result': 'pass'}])
    with pytest.raises(ValueError, match='通用 Agent'):
        m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    assert flow.submissions == flow.writes == []
    assert flow.releases == flow.reads == []


def test_single_result_write_for_old_attempt_stops_without_finalizing(single_flow):
    flow = single_flow
    _saved_turn(flow)
    _write_results(flow, [{'rule_id': 1, 'result': 'pass'}])
    flow.current = False
    result = m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    assert '旧评测 attempt' in result['message']
    assert flow.results == {}
    assert flow.updates == flow.submissions == []


def test_single_waiting_for_endpoint_slot_does_not_prepare_or_submit(single_flow, monkeypatch):
    flow = single_flow
    monkeypatch.setattr(m, '_acquire_endpoint_slot', lambda *_args, **_kwargs: (None, None, None))
    monkeypatch.setattr(m, '_judge_input_files', lambda *_args: pytest.fail('无空闲端点时不能重复准备材料'))
    with pytest.raises(m.Retry):
        m._advance_agent_judge(flow.task, flow.client, flow.submission, flow.competition)
    assert flow.statuses == ['Queued']
    assert flow.submissions == []


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
