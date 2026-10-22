"""教育作答继续入口：持久去重、冻结记录、租约绑定与权限；仅内存替身。"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import json
import threading
from types import SimpleNamespace

from flask import Flask
import pytest

from backend.oj_modules.api import vibehub_edu_api
from backend.oj_modules.routes import vibehub_routes
from backend.oj_modules.vibehub import edu, runtime, services


ACTOR = {'id': 12, 'is_admin': 0}
SOURCE_ID = 'att_original'
REQUEST_ID = 'a240746f-9d4f-4dc0-b8e5-748db6e68863'
TARGET_ID = 'att_a240746f9d4f4dc0b8e5748db6e68863'
REQUEST = {'request_id': REQUEST_ID, 'expected_attempt_id': SOURCE_ID}
SOURCE = {'id': SOURCE_ID, 'user_id': 12, 'assignment_id': None, 'project_id': 3,
    'version_id': 9, 'seq': 2, 'status': 'submitted',
    'context_json': json.dumps({'attempt_id': SOURCE_ID, 'project_version_id': 9,
        'challenge_seed': 'old-seed', 'parameters': {'custom_level': 7}}),
    'state_json': '{"private_solution":"old-state"}', 'view_json': '{"source":"old-source"}'}


class Store:
    def __init__(self):
        self.attempts = {SOURCE_ID: deepcopy(SOURCE)}
        self.submissions = {21: {'attempt_id': SOURCE_ID, 'snapshot_json': '{"frozen":"old-snapshot"}', 'score_bp': 7312, 'status': 'graded'}}
        self.commands = {SOURCE_ID: [{'seq': 1, 'action': {'type': 'custom', 'source': 'old-source'}}]}
        self.calls = []
        self.events = []
        self.named_lock = threading.Lock()
        self.lock_available = True
        self.state_lock = threading.RLock()

    def connection(self):
        store = self

        class Connection:
            def __init__(self):
                self.pending = {}
                self.locked = False
                self.result = None

            def cursor(self):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def execute(self, sql, params=None):
                sql = ' '.join(sql.split())
                with store.state_lock:
                    store.calls.append((sql, deepcopy(params)))
                if sql.startswith('SELECT GET_LOCK'):
                    self.locked = store.lock_available and store.named_lock.acquire(timeout=3)
                    self.result = {'acquired': int(self.locked)}
                elif sql.startswith('SELECT RELEASE_LOCK'):
                    self._release()
                elif sql.startswith('SELECT * FROM vibehub_edu_attempts WHERE id='):
                    with store.state_lock:
                        self.result = deepcopy(store.attempts.get(params[0]))
                elif sql.startswith('SELECT * FROM vibehub_edu_attempts WHERE user_id='):
                    user_id, assignment_id, version_id = params
                    self.result = next((deepcopy(row) for row in store.attempts.values()
                        if (row['user_id'], row['assignment_id'], row['version_id'], row['status'])
                        == (user_id, assignment_id, version_id, 'active')), None)
                elif sql.startswith('SELECT a.* FROM vibehub_edu_attempts a JOIN vibehub_edu_submissions s'):
                    user_id, assignment_id, version_id = params
                    pending = {row['attempt_id'] for row in store.submissions.values() if row['status'] in {'submitted', 'grading'}}
                    self.result = next((deepcopy(row) for row in store.attempts.values()
                        if (row['user_id'], row['assignment_id'], row['version_id']) == (user_id, assignment_id, version_id)
                        and row['id'] in pending), None)
                elif sql.startswith('SELECT status FROM vibehub_edu_submissions WHERE attempt_id='):
                    assert 'FOR UPDATE' not in sql
                    with store.state_lock:
                        row = next((row for row in store.submissions.values() if row['attempt_id'] == params[0]), None)
                        self.result = {'status': row['status']} if row else None
                elif sql.startswith('SELECT id,is_admin FROM users'):
                    self.result = dict(ACTOR) if params == (12,) else None
                elif sql.startswith('INSERT INTO vibehub_edu_attempts'):
                    (attempt_id, assignment_id, project_id, version_id, user_id, context, state, view) = params
                    assert attempt_id not in store.attempts
                    self.pending[attempt_id] = {'id': attempt_id, 'assignment_id': assignment_id,
                        'project_id': project_id, 'version_id': version_id, 'user_id': user_id,
                        'context_json': context, 'state_json': state, 'view_json': view, 'seq': 0, 'status': 'active'}
                else:
                    raise AssertionError(f'继续作答不应操作其他记录：{sql}')

            def fetchone(self):
                return deepcopy(self.result)

            def commit(self):
                with store.state_lock:
                    for key, value in self.pending.items():
                        assert key not in store.attempts
                        store.attempts[key] = deepcopy(value)
                    self.pending.clear()
                    store.events.append('commit')

            def rollback(self):
                self.pending.clear()

            def _release(self):
                if self.locked:
                    self.locked = False
                    store.named_lock.release()

            def close(self):
                self._release()

        return Connection()


class Manager:
    def __init__(self, store):
        self.store = store
        self.bindings = {'lease': SOURCE_ID, 'other-lease': SOURCE_ID}
        self.heartbeats = []
        self.binds = []
        self.fail_bind_once = False
        self.before_bind = None
        self.wrong_project = False
        self.lock = threading.RLock()
        self.lease = SimpleNamespace(token='lease', container_name='fixed-version-container',
            proxy_base_path='/vibehub/runtime/lease', expires_at=5000)

    def edu_attempt_for_token(self, token):
        with self.lock:
            if token not in self.bindings:
                raise runtime.VibeHubLeaseError('该运行会话未绑定作答')
            return self.bindings[token]

    def heartbeat(self, token, **kwargs):
        assert kwargs == {'project_key': 'edu:3:v9', 'channel': 'public'}
        self.heartbeats.append((token, kwargs))
        if self.wrong_project:
            raise runtime.VibeHubLeaseError('VibeHub lease 与作品不匹配')
        return self.lease

    def bind_edu_attempt(self, token, attempt_id, *, expected_attempt_id=None):
        self.store.events.append('bind')
        self.binds.append((token, attempt_id, expected_attempt_id))
        if self.fail_bind_once:
            self.fail_bind_once = False
            raise runtime.VibeHubLeaseError('temporary lease failure')
        if self.before_bind:
            self.before_bind()
        with self.lock:
            if expected_attempt_id is not None and self.bindings[token] not in {expected_attempt_id, attempt_id}:
                raise runtime.VibeHubLeaseError('绑定已变化')
            self.bindings[token] = attempt_id


@pytest.fixture
def continuation(monkeypatch):
    store = Store()
    manager = Manager(store)
    starts = []
    versions = []
    monkeypatch.setattr(edu, 'get_db_connection', store.connection)
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: manager)
    monkeypatch.setattr(edu, '_lease', lambda _version: manager.lease)
    monkeypatch.setattr(services, 'resolve_project_package', lambda *_args, **_kwargs: {'project_id': 3, 'version_id': 9})
    monkeypatch.setattr(vibehub_routes, 'get_runtime_manager', lambda: manager)
    monkeypatch.setattr(edu, '_version', lambda _cursor, project_id, version_id:
        versions.append((project_id, version_id)) or {'id': version_id, 'project_id': project_id})

    def internal(lease, operation, payload):
        assert lease is manager.lease and operation == 'start'
        starts.append(deepcopy(payload))
        return {'state': {'private_solution': 'new-state'}, 'view': {'source': 'starter', 'ready': True}}

    monkeypatch.setattr(edu, '_internal', internal)
    return SimpleNamespace(store=store, manager=manager, starts=starts, versions=versions)


def assert_frozen_unchanged(env):
    assert env.store.attempts[SOURCE_ID] == SOURCE
    assert env.store.submissions == {21: {'attempt_id': SOURCE_ID, 'snapshot_json': '{"frozen":"old-snapshot"}', 'score_bp': 7312, 'status': 'graded'}}
    assert env.store.commands[SOURCE_ID] == [{'seq': 1, 'action': {'type': 'custom', 'source': 'old-source'}}]
    assert not any(sql.startswith(('UPDATE', 'DELETE')) for sql, _params in env.store.calls)


def test_continue_starts_a_new_fixed_version_attempt_and_binds_only_after_commit(continuation):
    env = continuation
    result = edu.continue_attempt('lease', REQUEST, ACTOR)
    assert result == {'attempt_id': TARGET_ID, 'assignment_id': None, 'seq': 0, 'status': 'active',
        'view': {'source': 'starter', 'ready': True}}
    assert env.versions == [(3, 9)]
    new = env.store.attempts[TARGET_ID]
    assert (new['user_id'], new['project_id'], new['version_id'], new['assignment_id']) == (12, 3, 9, None)
    context = json.loads(new['context_json'])
    assert context == env.starts[0]['context']
    assert context['attempt_id'] == TARGET_ID
    assert context['challenge_seed'] != 'old-seed'
    assert context['parameters'] == {'custom_level': 7}
    assert context['continued_from'] == SOURCE_ID and context['continue_request_id'] == REQUEST_ID
    assert json.loads(new['state_json']) == {'private_solution': 'new-state'}
    assert env.manager.binds == [('lease', TARGET_ID, SOURCE_ID)]
    assert env.store.events.index('commit') < env.store.events.index('bind')
    assert any(sql.endswith('FOR UPDATE') and params == (SOURCE_ID,) for sql, params in env.store.calls)
    assert any('RELEASE_LOCK' in sql for sql, _params in env.store.calls)
    assert 'private_solution' not in json.dumps(result)
    assert_frozen_unchanged(env)


@pytest.mark.parametrize('submission_status', ['submitted', 'grading'])
def test_launch_reuses_the_pending_attempt_instead_of_bypassing_continuation_gate(continuation, submission_status):
    env = continuation
    env.store.submissions[21]['status'] = submission_status
    old = deepcopy(env.store.attempts[SOURCE_ID])
    result = edu.launch('balance', ACTOR)
    assert result['attempt_id'] == SOURCE_ID and result['seq'] == old['seq']
    assert env.manager.bindings['lease'] == SOURCE_ID
    assert env.starts == [] and len(env.store.attempts) == 1
    assert env.store.attempts[SOURCE_ID] == old
    query = next((sql, params) for sql, params in env.store.calls if sql.startswith('SELECT a.*'))
    assert "s.status IN ('submitted','grading')" in query[0]
    assert 'a.assignment_id <=> %s' in query[0] and query[1] == (12, None, 9)


@pytest.mark.parametrize('submission_status', ['graded', 'error'])
def test_launch_keeps_creating_fresh_attempts_after_previous_evaluation_finishes(continuation, submission_status):
    env = continuation
    env.store.submissions[21]['status'] = submission_status
    result = edu.launch('balance', ACTOR)
    assert result['attempt_id'] != SOURCE_ID and result['seq'] == 0
    assert len(env.store.attempts) == 2 and len(env.starts) == 1
    new = env.store.attempts[result['attempt_id']]
    assert (new['version_id'], new['user_id'], new['status']) == (9, 12, 'active')


def test_launch_prioritizes_an_existing_active_attempt_without_changing_legacy_semantics(continuation):
    env = continuation
    env.store.attempts[SOURCE_ID]['status'] = 'active'
    env.store.submissions[21]['status'] = 'grading'
    result = edu.launch('balance', ACTOR)
    assert result['attempt_id'] == SOURCE_ID
    assert env.starts == []
    assert not any(sql.startswith('SELECT a.*') for sql, _params in env.store.calls)


@pytest.mark.parametrize('new_status', ['active', 'submitted', 'graded'])
def test_continue_retry_reuses_its_persisted_target_even_after_target_is_submitted(continuation, new_status):
    env = continuation
    edu.continue_attempt('lease', REQUEST, ACTOR)
    env.store.attempts[TARGET_ID].update(status=new_status, seq=4)
    result = edu.continue_attempt('lease', REQUEST, ACTOR)
    assert result['attempt_id'] == TARGET_ID and result['status'] == new_status and result['seq'] == 4
    assert len(env.starts) == 1
    assert len(env.store.attempts) == 2
    assert_frozen_unchanged(env)


def test_continue_retry_repairs_a_committed_attempt_whose_lease_bind_failed(continuation):
    env = continuation
    env.manager.fail_bind_once = True
    with pytest.raises(runtime.VibeHubLeaseError, match='temporary'):
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert TARGET_ID in env.store.attempts and env.manager.bindings['lease'] == SOURCE_ID
    result = edu.continue_attempt('lease', REQUEST, ACTOR)
    assert result['attempt_id'] == TARGET_ID and env.manager.bindings['lease'] == TARGET_ID
    assert len(env.starts) == 1
    assert_frozen_unchanged(env)


def test_concurrent_same_request_creates_one_attempt_and_reuses_the_rebound_token(continuation, monkeypatch):
    env = continuation
    barrier = threading.Barrier(2)
    original = env.manager.edu_attempt_for_token
    local = threading.local()

    def read_bound(token):
        result = original(token)
        if not getattr(local, 'first_read', False):
            local.first_read = True
            barrier.wait(timeout=3)
        return result

    monkeypatch.setattr(env.manager, 'edu_attempt_for_token', read_bound)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: edu.continue_attempt('lease', REQUEST, ACTOR), range(2)))
    assert [result['attempt_id'] for result in results] == [TARGET_ID, TARGET_ID]
    assert len(env.starts) == 1 and len(env.store.attempts) == 2
    assert_frozen_unchanged(env)


def test_distinct_requests_on_distinct_tokens_keep_independent_attempts(continuation):
    env = continuation
    first = edu.continue_attempt('lease', REQUEST, ACTOR)
    second = edu.continue_attempt('other-lease', {**REQUEST, 'request_id': '328a716b-282d-4190-9e63-9d6d329ab908'}, ACTOR)
    assert first['attempt_id'] != second['attempt_id']
    assert len(env.starts) == 2 and len(env.store.attempts) == 3
    assert_frozen_unchanged(env)


@pytest.mark.parametrize('field,value', [('user_id', 99), ('project_id', 4), ('version_id', 10), ('assignment_id', 7)])
def test_persisted_request_id_collision_never_reuses_another_attempt_scope(continuation, field, value):
    env = continuation
    edu.continue_attempt('lease', REQUEST, ACTOR)
    env.manager.bindings['lease'] = SOURCE_ID
    env.store.attempts[TARGET_ID][field] = value
    with pytest.raises(services.VibeHubPermissionError):
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert len(env.starts) == 1
    assert env.manager.bindings['lease'] == SOURCE_ID


@pytest.mark.parametrize('field,value', [('continued_from', 'att_other'), ('continue_request_id', 'another-request')])
def test_persisted_target_must_match_the_exact_parent_and_request_id(continuation, field, value):
    env = continuation
    edu.continue_attempt('lease', REQUEST, ACTOR)
    env.manager.bindings['lease'] = SOURCE_ID
    context = json.loads(env.store.attempts[TARGET_ID]['context_json'])
    context[field] = value
    env.store.attempts[TARGET_ID]['context_json'] = json.dumps(context)
    with pytest.raises(services.VibeHubPermissionError):
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert len(env.starts) == 1 and env.manager.bindings['lease'] == SOURCE_ID


def test_active_source_is_not_forked(continuation):
    env = continuation
    env.store.attempts[SOURCE_ID]['status'] = 'active'
    with pytest.raises(services.VibeHubError, match='尚未提交') as captured:
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert captured.value.status_code == 409
    assert len(env.store.attempts) == 1 and env.starts == []


@pytest.mark.parametrize('submission_status', ['submitted', 'grading', None])
def test_previous_evaluation_must_finish_before_a_new_attempt_starts(continuation, submission_status):
    env = continuation
    if submission_status is None:
        env.store.submissions.clear()
    else:
        env.store.submissions[21]['status'] = submission_status
    before = deepcopy(env.store.submissions)
    with pytest.raises(services.VibeHubError, match='仍在评测') as captured:
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert captured.value.status_code == 409
    assert env.starts == [] and len(env.store.attempts) == 1
    assert env.manager.bindings['lease'] == SOURCE_ID
    assert env.store.submissions == before
    reads = [(sql, params) for sql, params in env.store.calls if 'FROM vibehub_edu_submissions' in sql]
    assert reads == [('SELECT status FROM vibehub_edu_submissions WHERE attempt_id=%s', (SOURCE_ID,))]
    assert not env.store.named_lock.locked()


def test_terminal_evaluation_error_allows_continuing_even_when_attempt_remains_submitted(continuation):
    env = continuation
    env.store.submissions[21]['status'] = 'error'
    before = deepcopy(env.store.submissions)
    assert env.store.attempts[SOURCE_ID]['status'] == 'submitted'
    result = edu.continue_attempt('lease', REQUEST, ACTOR)
    assert result['attempt_id'] == TARGET_ID and result['status'] == 'active'
    assert env.store.submissions == before
    assert env.store.attempts[SOURCE_ID] == SOURCE


def test_persisted_continue_retry_does_not_recheck_source_evaluation_terminal_state(continuation):
    env = continuation
    edu.continue_attempt('lease', REQUEST, ACTOR)
    env.store.submissions[21]['status'] = 'grading'
    result = edu.continue_attempt('lease', REQUEST, ACTOR)
    assert result['attempt_id'] == TARGET_ID and len(env.starts) == 1
    assert sum('FROM vibehub_edu_submissions' in sql for sql, _params in env.store.calls) == 1


def test_login_actor_cannot_continue_another_owners_token(continuation):
    with pytest.raises(services.VibeHubPermissionError, match='他人'):
        edu.continue_attempt('lease', REQUEST, {'id': 99})
    assert len(continuation.store.attempts) == 1 and continuation.starts == []


def test_revoked_assignment_membership_blocks_continuation(continuation, monkeypatch):
    env = continuation
    env.store.attempts[SOURCE_ID]['assignment_id'] = 7

    def denied(*_args):
        raise services.VibeHubPermissionError('你不在该作业的班级中')

    monkeypatch.setattr(edu, '_assignment', denied)
    with pytest.raises(services.VibeHubPermissionError, match='班级'):
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert env.starts == [] and len(env.store.attempts) == 1


def test_lease_must_still_match_the_fixed_project_version(continuation):
    env = continuation
    env.manager.wrong_project = True
    with pytest.raises(runtime.VibeHubLeaseError, match='作品不匹配'):
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert env.starts == [] and len(env.store.attempts) == 1
    assert any('RELEASE_LOCK' in sql for sql, _params in env.store.calls)
    assert_frozen_unchanged(env)


def test_scope_lock_contention_does_not_start_or_insert_an_attempt(continuation):
    env = continuation
    env.store.lock_available = False
    with pytest.raises(services.VibeHubError) as captured:
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert captured.value.status_code == 429
    assert env.starts == [] and len(env.store.attempts) == 1
    assert not any('RELEASE_LOCK' in sql for sql, _params in env.store.calls)


def test_failed_private_start_preserves_old_submission_and_does_not_rebind(continuation, monkeypatch):
    env = continuation

    def failed(*_args):
        raise services.VibeHubError('作品暂时无法启动', status_code=502)

    monkeypatch.setattr(edu, '_internal', failed)
    with pytest.raises(services.VibeHubError, match='无法启动'):
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert len(env.store.attempts) == 1 and env.manager.binds == []
    assert not env.store.named_lock.locked()
    assert_frozen_unchanged(env)


def test_binding_change_during_creation_is_never_overwritten(continuation):
    env = continuation
    env.manager.before_bind = lambda: env.manager.bindings.update(lease='att_newer')
    with pytest.raises(runtime.VibeHubLeaseError, match='绑定已变化'):
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert TARGET_ID in env.store.attempts
    assert env.manager.bindings['lease'] == 'att_newer'
    assert_frozen_unchanged(env)


@pytest.mark.parametrize('payload', [None, {}, [], {**REQUEST, 'user_id': 99},
    {**REQUEST, 'assignment_id': 7}, {**REQUEST, 'version_id': 99},
    {**REQUEST, 'request_id': 'not-a-uuid'}, {**REQUEST, 'request_id': 1},
    {**REQUEST, 'expected_attempt_id': '../other'}])
def test_invalid_continue_requests_fail_before_database_access(monkeypatch, payload):
    monkeypatch.setattr(edu, 'get_db_connection', lambda: pytest.fail('无效请求不能连接数据库'))
    with pytest.raises(services.VibeHubError):
        edu.continue_attempt('lease', payload, ACTOR)


def test_continue_request_does_not_follow_an_unrelated_token_binding(continuation):
    env = continuation
    env.manager.bindings['lease'] = 'att_unrelated'
    with pytest.raises(services.VibeHubError) as captured:
        edu.continue_attempt('lease', REQUEST, ACTOR)
    assert captured.value.status_code == 409
    assert env.store.calls == []


def test_runtime_binding_compare_and_set_preserves_legacy_binding_and_rejects_stale_source():
    manager = object.__new__(runtime.VibeHubRuntimeManager)
    state = {'leases': {'digest': {}}}

    @contextmanager
    def locked():
        yield state

    manager._locked_state = locked
    manager._lookup_lease = lambda current, _token: ('digest', current['leases']['digest'], {})
    manager.bind_edu_attempt('lease', SOURCE_ID)
    manager.bind_edu_attempt('lease', TARGET_ID, expected_attempt_id=SOURCE_ID)
    manager.bind_edu_attempt('lease', TARGET_ID, expected_attempt_id=SOURCE_ID)
    with pytest.raises(runtime.VibeHubLeaseError, match='绑定已变化'):
        manager.bind_edu_attempt('lease', 'att_unrelated', expected_attempt_id=SOURCE_ID)
    assert state['leases']['digest']['edu_attempt_id'] == TARGET_ID


def test_iframe_continue_reuses_its_path_and_keeps_capability_headers(continuation):
    env = continuation
    app = Flask(__name__)
    app.register_blueprint(vibehub_routes.vibehub_bp)
    client = app.test_client()
    path = '/vibehub/runtime/lease/_edu/v1/continue'
    first = client.post(path, json=REQUEST)
    second = client.post(path, json=REQUEST)
    assert first.status_code == second.status_code == 200
    assert first.get_json()['attempt_id'] == second.get_json()['attempt_id'] == TARGET_ID
    assert first.headers['Access-Control-Allow-Origin'] == 'null'
    assert first.headers['Cache-Control'] == 'private, no-store'
    assert env.manager.bindings['lease'] == TARGET_ID and len(env.starts) == 1
    assert_frozen_unchanged(env)


def test_login_continue_requires_auth_and_rejects_client_identity_fields(continuation, monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(vibehub_edu_api.vibehub_edu_api_bp)
    client = app.test_client()
    path = '/api/vibehub/edu/continue'
    body = {'lease_token': 'lease', **REQUEST}
    monkeypatch.setattr(vibehub_edu_api, 'current_user', lambda: None)
    assert client.post(path, json=body).status_code == 403
    monkeypatch.setattr(vibehub_edu_api, 'current_user', lambda: ACTOR)
    assert client.post(path, json={**body, 'user_id': 99}).status_code == 400
    result = client.post(path, json=body)
    assert result.status_code == 200 and result.get_json()['attempt_id'] == TARGET_ID
