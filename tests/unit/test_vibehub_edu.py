"""教学协议的权限、不可伪报成绩、去重与冻结回归；不连接外部基础设施。"""

import json
from types import SimpleNamespace

import pytest
from flask import Flask

from backend.oj_modules.api import vibehub_edu_api
from backend.oj_modules.vibehub import edu, services


ACTOR = {'id': 12, 'username': '2026001', 'is_admin': 0}
ROW = {'id': 'att_existing', 'user_id': 12, 'assignment_id': None,
       'project_id': 3, 'version_id': 9, 'seq': 1, 'status': 'active',
       'context_json': '{"attempt_id":"att_existing"}',
       'state_json': '{"private_answer":42}', 'view_json': '{"ready":true}'}


class Cursor:
    def __init__(self, *, one=(), many=(), events=None):
        self.one = list(one)
        self.many = list(many)
        self.calls = []
        self.rowcount = 1
        self.lastrowid = 21
        self.events = events if events is not None else []

    def execute(self, sql, params=None):
        self.calls.append((' '.join(sql.split()), params))
        self.events.append('sql')

    def fetchone(self):
        return self.one.pop(0)

    def fetchall(self):
        return self.many.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


class Connection:
    def __init__(self, cursor):
        self.cursor_value = cursor
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_value

    def commit(self):
        self.committed = True
        self.cursor_value.events.append('commit')

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


@pytest.mark.parametrize('field,value', [('score', 100), ('completed', True), ('state', {}), ('user_id', 1)])
def test_action_cannot_supply_grade_identity_or_state(monkeypatch, field, value):
    monkeypatch.setattr(edu, 'get_db_connection', lambda: pytest.fail('非法请求不能触及数据库'))
    payload = {'command_id': 'command_123', 'expected_seq': 1, 'action': {'type': 'swap'}, field: value}
    with pytest.raises(services.VibeHubError, match='字段无效'):
        edu.apply_action('att_existing', payload, ACTOR)


@pytest.mark.parametrize('value', [True, '1', 1.0, None])
def test_action_requires_integer_sequence(monkeypatch, value):
    monkeypatch.setattr(edu, 'get_db_connection', lambda: pytest.fail('非法序号不能触及数据库'))
    with pytest.raises(services.VibeHubError, match='序号无效'):
        edu.apply_action('att_existing', {'command_id': 'command_123', 'expected_seq': value, 'action': {'type': 'swap'}}, ACTOR)


def test_owner_cannot_read_other_students_attempt():
    cursor = Cursor(one=[{**ROW, 'user_id': 99}])
    with pytest.raises(services.VibeHubPermissionError):
        edu._get_attempt(cursor, ROW['id'], ACTOR)


def test_internal_assignment_request_restores_owner_admin_role(monkeypatch):
    cursor = Cursor(one=[{**ROW, 'assignment_id': 5}, {'id': 12, 'is_admin': 1}])
    actors = []
    monkeypatch.setattr(edu, '_assignment', lambda _cursor, assignment_id, actor: actors.append((assignment_id, actor)))
    edu._get_attempt(cursor, ROW['id'], for_update=True)
    assert actors == [(5, {'id': 12, 'is_admin': 1})]
    assert cursor.calls[0][0].endswith('FOR UPDATE')


def test_dispatch_recovers_saved_submissions_without_rewriting_evidence(monkeypatch):
    cursor = Cursor(many=[[{'id': 21}, {'id': 22}]])
    conn = Connection(cursor)
    tasks = []
    monkeypatch.setattr(edu, 'get_db_connection', lambda: conn)
    monkeypatch.setattr(edu, '_grade_task', SimpleNamespace(apply_async=lambda **kwargs: tasks.append(kwargs)))
    assert edu.dispatch_pending_grades() == 2
    assert tasks == [{'args': [21], 'queue': 'celery'}, {'args': [22], 'queue': 'celery'}]
    assert not conn.committed
    assert all(sql.startswith('SELECT') for sql, _params in cursor.calls)


def test_student_must_belong_to_assignment_class():
    cursor = Cursor(one=[{'id': 5, 'class_en': 'C1', 'homework_id': 4}, None])
    with pytest.raises(services.VibeHubPermissionError, match='班级'):
        edu._assignment(cursor, 5, ACTOR)
    assert cursor.calls[-1][1] == (ACTOR['id'], 'C1')


def test_assignment_creation_locks_and_pins_approved_public_version():
    manifest = {'kind': 'edu', 'education': {'protocol': edu.PROTOCOL}}
    cursor = Cursor(one=[{'id': 3, 'public_version_id': 9, 'manifest_json': json.dumps(manifest)}])
    assignment_id = edu.create_assignment(cursor, 'C1', 4, 3, {**ACTOR, 'is_admin': 1})
    assert assignment_id == 21
    assert "v.review_status='approved' FOR UPDATE" in cursor.calls[0][0]
    assert cursor.calls[1][1] == ('C1', 4, 3, 9)


def test_students_cannot_create_assignments():
    cursor = Cursor()
    with pytest.raises(ValueError, match='管理员'):
        edu.create_assignment(cursor, 'C1', 4, 3, ACTOR)
    assert cursor.calls == []


def test_public_attempt_state_never_returns_private_state(monkeypatch):
    cursor = Cursor()
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    monkeypatch.setattr(edu, '_get_attempt', lambda *_args, **_kwargs: dict(ROW))
    result = edu.attempt_state(ROW['id'], ACTOR)
    assert result['view'] == {'ready': True}
    assert 'state' not in result
    assert 'private_answer' not in json.dumps(result)


def test_assignment_launch_uses_pinned_version_even_for_latest_channel(monkeypatch):
    assignment = {'id': 5, 'project_id': 3, 'version_id': 9}
    version = {'id': 9, 'project_id': 3, 'slug': 'balance'}
    cursor = Cursor(one=[dict(ROW)])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    monkeypatch.setattr(edu, '_assignment', lambda *_args: assignment)
    versions = []
    monkeypatch.setattr(edu, '_version', lambda _cursor, project_id, version_id: versions.append((project_id, version_id)) or version)
    monkeypatch.setattr(services, 'resolve_project_package', lambda *_args, **_kwargs: pytest.fail('作业不能追随公开或latest指针'))
    lease = SimpleNamespace(token='lease', proxy_base_path='/vibehub/runtime/lease', expires_at=1)
    monkeypatch.setattr(edu, '_lease', lambda selected: lease if selected is version else pytest.fail('错误版本'))
    bindings = []
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(bind_edu_attempt=lambda *args: bindings.append(args)))
    result = edu.launch('balance', ACTOR, assignment_id=5, channel='latest')
    assert versions == [(3, 9)]
    assert bindings == [('lease', ROW['id'])]
    assert result['attempt_id'] == ROW['id']


def test_internal_protocol_explicitly_uses_education_socket(monkeypatch):
    calls = []
    def relay(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(status=200, body=b'{"verdict":"passed","score_bp":10000}')
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(relay_http=relay)))
    result = edu._internal(SimpleNamespace(container_name='trusted-container'), 'grade', {'actions': []})
    assert result['score_bp'] == 10000
    assert calls[0][0][:3] == ('trusted-container', 'POST', '/v1/grade')
    assert calls[0][1]['edu'] is True


def test_duplicate_action_returns_saved_response_without_running_project(monkeypatch):
    action = {'type': 'swap', 'indices': [0, 1]}
    saved = {'seq': 2, 'view': {'heap': [1, 2]}}
    cursor = Cursor(one=[{'seq': 2, 'action_json': json.dumps(action), 'response_json': json.dumps(saved)}])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    monkeypatch.setattr(edu, '_get_attempt', lambda *_args, **_kwargs: dict(ROW))
    monkeypatch.setattr(edu, '_version', lambda *_args: pytest.fail('重试不能再次调用作品'))
    result = edu.apply_action(ROW['id'], {'command_id': 'command_123', 'expected_seq': 1, 'action': action}, ACTOR)
    assert result == saved
    assert len(cursor.calls) == 1


def test_command_id_reuse_with_changed_action_is_conflict(monkeypatch):
    cursor = Cursor(one=[{'seq': 2, 'action_json': '{"type":"original"}', 'response_json': '{}'}])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    monkeypatch.setattr(edu, '_get_attempt', lambda *_args, **_kwargs: dict(ROW))
    with pytest.raises(services.VibeHubError) as captured:
        edu.apply_action(ROW['id'], {'command_id': 'command_123', 'expected_seq': 1, 'action': {'type': 'changed'}}, ACTOR)
    assert captured.value.status_code == 409


def test_submitted_attempt_rejects_new_operations(monkeypatch):
    cursor = Cursor(one=[None])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    monkeypatch.setattr(edu, '_get_attempt', lambda *_args, **_kwargs: {**ROW, 'status': 'submitted'})
    with pytest.raises(services.VibeHubError) as captured:
        edu.apply_action(ROW['id'], {'command_id': 'command_123', 'expected_seq': 1, 'action': {'type': 'swap'}}, ACTOR)
    assert captured.value.status_code == 409


def test_submit_freezes_platform_actions_before_dispatch(monkeypatch):
    events = []
    cursor = Cursor(one=[None], many=[[{'seq': 1, 'action_json': '{"type":"swap","indices":[0,1]}'}]], events=events)
    conn = Connection(cursor)
    monkeypatch.setattr(edu, 'get_db_connection', lambda: conn)
    monkeypatch.setattr(edu, '_get_attempt', lambda *_args, **_kwargs: dict(ROW))
    tasks = []
    def enqueue(**kwargs):
        events.append('enqueue')
        tasks.append(kwargs)
    monkeypatch.setattr(edu, '_grade_task', SimpleNamespace(apply_async=enqueue))
    result = edu.submit(ROW['id'], {'request_id': 'request_123', 'expected_seq': 1}, ACTOR)
    assert result['submission_id'] == 21
    assert events.index('commit') < events.index('enqueue')
    freeze = next(call for call in cursor.calls if call[0].startswith('UPDATE vibehub_edu_attempts'))
    assert "status='active' AND seq=%s" in freeze[0]
    snapshot = json.loads(cursor.calls[-1][1][-1])
    assert snapshot['actions'] == [{'seq': 1, 'action': {'type': 'swap', 'indices': [0, 1]}}]
    assert 'private_answer' not in json.dumps(snapshot)
    assert tasks == [{'args': [21], 'queue': 'celery'}]


def test_submit_rejects_browser_reported_score(monkeypatch):
    monkeypatch.setattr(edu, 'get_db_connection', lambda: pytest.fail('伪报成绩不能触及数据库'))
    with pytest.raises(services.VibeHubError, match='字段无效'):
        edu.submit(ROW['id'], {'request_id': 'request_123', 'expected_seq': 1, 'score': 100}, ACTOR)


def test_repeated_submit_reuses_existing_snapshot(monkeypatch):
    cursor = Cursor(one=[{'id': 21, 'request_id': 'request_first', 'final_seq': 1}])
    conn = Connection(cursor)
    monkeypatch.setattr(edu, 'get_db_connection', lambda: conn)
    monkeypatch.setattr(edu, '_get_attempt', lambda *_args, **_kwargs: {**ROW, 'status': 'submitted'})
    monkeypatch.setattr(edu, '_grade_task', SimpleNamespace(apply_async=lambda **_kwargs: None))
    result = edu.submit(ROW['id'], {'request_id': 'request_retry', 'expected_seq': 1}, ACTOR)
    assert result['submission_id'] == 21
    assert not any(sql.startswith(('INSERT', 'UPDATE')) for sql, _params in cursor.calls)


@pytest.mark.parametrize('score_bp', [True, -1, 10001, '10000', None])
def test_grading_rejects_out_of_range_or_non_integer_score(monkeypatch, score_bp):
    row = {'id': 21, 'attempt_id': ROW['id'], 'project_id': 3, 'version_id': 9,
           'user_id': 12, 'status': 'submitted', 'snapshot_json': '{"context":{},"actions":[]}'}
    cursor = Cursor(one=[{'acquired': 1}, row])
    conn = Connection(cursor)
    monkeypatch.setattr(edu, 'get_db_connection', lambda: conn)
    monkeypatch.setattr(edu, '_version', lambda *_args: {'manifest': {}})
    monkeypatch.setattr(edu, '_execution', lambda context, *_args, **_kwargs: context)
    monkeypatch.setattr(edu, '_lease', lambda *_args: SimpleNamespace(token='lease'))
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(release=lambda _token: None))
    monkeypatch.setattr(edu, '_internal', lambda *_args: {'score_bp': score_bp, 'verdict': 'passed'})
    with pytest.raises(services.VibeHubError, match='评分响应无效'):
        edu.grade_submission(21)
    assert not any("SET status='graded'" in sql for sql, _params in cursor.calls)
    assert any("SET status='error'" in sql for sql, _params in cursor.calls)


def test_cpp_execution_uses_recorded_source_and_new_hidden_inputs(monkeypatch):
    from backend.oj_modules.vibehub import edu_cpp

    calls = []
    monkeypatch.setattr(edu_cpp, 'run_code', lambda source, inputs: calls.append((source, inputs)) or {'passed': len(inputs)})
    cursor = Cursor(one=[{'acquired': 1}, {'acquired': 1}])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    context = {'attempt_id': ROW['id'], 'challenge_seed': 'seed', 'parameters': {'inputs': [7, 3]}}
    actions = [
        {'action': {'type': 'run_code', 'source': 'int step(int x) {return 0;}'}},
        {'action': {'type': 'run_code', 'source': 'int step(int x) {return x;}', 'execution': {'passed': 10000}}},
    ]
    result = edu._execution(context, {'education': {'executor': 'cpp-heap-median-v1'}}, actions, grading=True)
    assert calls[0][0] == 'int step(int x) {return x;}'
    assert len(calls[0][1]) == 129
    assert calls[0][1] != [7, 3]
    assert result['execution'] == {'passed': 129}
    assert 'execution' not in context


def test_education_api_requires_login_and_rejects_identity_override(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(vibehub_edu_api.vibehub_edu_api_bp)
    client = app.test_client()
    monkeypatch.setattr(vibehub_edu_api, 'current_user', lambda: None)
    assert client.post('/api/vibehub/projects/balance/edu/launch', json={}).status_code == 403
    monkeypatch.setattr(vibehub_edu_api, 'current_user', lambda: ACTOR)
    monkeypatch.setattr(edu, 'launch', lambda *_args, **_kwargs: pytest.fail('不接受客户端覆盖身份'))
    assert client.post('/api/vibehub/projects/balance/edu/launch', json={'user_id': 99}).status_code == 400
