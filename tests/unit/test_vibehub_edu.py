"""教学协议的权限、不可伪报成绩、去重与冻结回归；不连接外部基础设施。"""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue
import threading
from types import SimpleNamespace

import pytest
from flask import Flask

from backend.oj_modules.api import vibehub_edu_api
from backend.oj_modules.vibehub import edu, runtime, services


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


_PACKAGE = 'a' * 64
_EDU_KEY = 'edu:3:v9'
_PUBLIC_REF = runtime.image_reference_for('balance', channel='public')
_LATEST_REF = runtime.image_reference_for('balance', channel='latest')
_FIXED_REF = runtime.image_reference_for(_EDU_KEY, channel='public')
_LEASE_VERSION = {'id': 9, 'project_id': 3, 'slug': 'balance', 'version_number': 2,
                  'package_sha256': _PACKAGE, 'is_featured': 0}


def _lease_image(reference, *, number='1', labels=None, size=1024, volumes=()):
    return runtime.ImageInfo(reference, 'sha256:' + number * 64, size,
        labels if labels is not None else {runtime.MANAGED_IMAGE_LABEL: '1', runtime.PACKAGE_DIGEST_LABEL: _PACKAGE},
        volumes)


class _LeaseDocker:
    def __init__(self, images):
        self.images = dict(images)
        self.lookups = []
        self.tags = []
        self.after_find = None

    def find_image(self, reference):
        self.lookups.append(reference)
        found = self.images.get(reference)
        if self.after_find is not None:
            self.after_find(reference)
        return found

    def tag_image(self, captured_id, target):
        self.tags.append((captured_id, target))


class _LeaseManager:
    def __init__(self, images, *, fixed_id=None):
        self.docker = _LeaseDocker(images)
        self.fixed_id = fixed_id
        self.captures, self.pins, self.builds, self.promotions, self.acquisitions = [], [], [], [], []
        self.lease = SimpleNamespace(token='prepared-lease')

    def capture_image_tag(self, key, *, channel):
        self.captures.append((key, channel))
        return self.fixed_id

    def pin_existing_image(self, target, source, **kwargs):
        self.pins.append((target, source, kwargs))
        # 保留生产 helper 的实际标签/容量/immutable ID 逻辑，只替换 Docker I/O。
        return runtime.VibeHubRuntimeManager.pin_existing_image(self, target, source, **kwargs)

    def build_latest_image(self, key, app_dir, **kwargs):
        self.builds.append((key, app_dir, kwargs))

    def promote_latest_to_public(self, key, **kwargs):
        self.promotions.append((key, kwargs))

    def acquire(self, key, **kwargs):
        self.acquisitions.append((key, kwargs))
        return self.lease


@pytest.fixture
def lease_environment(monkeypatch):
    def prepare(images=(), *, fixed_id=None, acquired=1):
        manager = _LeaseManager(images, fixed_id=fixed_id)
        cursor = Cursor(one=[{'acquired': acquired}])
        snapshots = []
        monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
        monkeypatch.setattr(edu, 'get_runtime_manager', lambda: manager)
        def snapshot(slug, version_number):
            snapshots.append((slug, version_number))
            return Path('/retained/balance/v2/app')
        monkeypatch.setattr(edu.storage, 'resolve_snapshot_app', snapshot)
        return manager, cursor, snapshots
    return prepare


def test_lease_keeps_an_existing_fixed_alias_without_reading_mutable_project_tags(lease_environment):
    manager, cursor, snapshots = lease_environment(fixed_id='sha256:' + '9' * 64)
    assert edu._lease(dict(_LEASE_VERSION)) is manager.lease
    assert manager.captures == [(_EDU_KEY, 'public')]
    assert manager.pins == manager.docker.lookups == manager.docker.tags == []
    assert manager.builds == manager.promotions == snapshots == []
    assert any('RELEASE_LOCK' in sql for sql, _params in cursor.calls)


def test_first_lease_reuses_a_matching_published_image_without_building_or_reading_the_snapshot(lease_environment):
    image = _lease_image(_PUBLIC_REF)
    manager, _cursor, snapshots = lease_environment({_PUBLIC_REF: image})
    assert edu._lease(dict(_LEASE_VERSION)) is manager.lease
    assert manager.pins == [(_EDU_KEY, 'balance', {'package_digest': _PACKAGE, 'featured': False})]
    assert manager.docker.lookups == [_PUBLIC_REF]
    assert manager.docker.tags == [(image.image_id, _FIXED_REF)]
    assert manager.builds == manager.promotions == snapshots == []
    assert manager.acquisitions == [(_EDU_KEY, {
        'channel': 'public', 'featured': False, 'education': True, 'base_path': '/vibehub/runtime',
        'package_digest': _PACKAGE, 'storage_key': 'project-3-public',
    })]


def test_lease_checks_latest_only_when_public_does_not_match_the_pinned_package(lease_environment):
    public = _lease_image(_PUBLIC_REF, labels={runtime.MANAGED_IMAGE_LABEL: '1', runtime.PACKAGE_DIGEST_LABEL: 'b' * 64})
    latest = _lease_image(_LATEST_REF, number='2')
    manager, _cursor, snapshots = lease_environment({_PUBLIC_REF: public, _LATEST_REF: latest})
    edu._lease(dict(_LEASE_VERSION))
    assert manager.docker.lookups == [_PUBLIC_REF, _LATEST_REF]
    assert manager.docker.tags == [(latest.image_id, _FIXED_REF)]
    assert manager.builds == manager.promotions == snapshots == []


def test_lease_tags_the_captured_image_id_even_if_the_mutable_public_tag_changes(lease_environment):
    original = _lease_image(_PUBLIC_REF)
    replaced = _lease_image(_PUBLIC_REF, number='2')
    manager, _cursor, _snapshots = lease_environment({_PUBLIC_REF: original})
    manager.docker.after_find = lambda reference: manager.docker.images.update({reference: replaced})
    edu._lease(dict(_LEASE_VERSION))
    assert manager.docker.images[_PUBLIC_REF].image_id == replaced.image_id
    assert manager.docker.tags == [(original.image_id, _FIXED_REF)]
    assert not manager.builds


@pytest.mark.parametrize('images', [
    {},
    {_PUBLIC_REF: _lease_image(_PUBLIC_REF, labels={runtime.MANAGED_IMAGE_LABEL: '1', runtime.PACKAGE_DIGEST_LABEL: 'b' * 64}),
     _LATEST_REF: _lease_image(_LATEST_REF, number='2', labels={runtime.MANAGED_IMAGE_LABEL: '1', runtime.PACKAGE_DIGEST_LABEL: 'c' * 64})},
])
def test_unavailable_historical_images_keep_the_retained_snapshot_build_fallback(lease_environment, images):
    manager, _cursor, snapshots = lease_environment(images)
    edu._lease(dict(_LEASE_VERSION))
    assert manager.docker.lookups == [_PUBLIC_REF, _LATEST_REF]
    assert manager.docker.tags == []
    assert snapshots == [('balance', 2)]
    assert manager.builds == [(_EDU_KEY, Path('/retained/balance/v2/app'), {'package_digest': _PACKAGE, 'featured': False})]
    assert manager.promotions == [(_EDU_KEY, {'package_digest': _PACKAGE})]


@pytest.mark.parametrize('labels', [
    {},
    {runtime.MANAGED_IMAGE_LABEL: '1'},
    {runtime.PACKAGE_DIGEST_LABEL: _PACKAGE},
    {runtime.MANAGED_IMAGE_LABEL: '0', runtime.PACKAGE_DIGEST_LABEL: _PACKAGE},
])
def test_lease_never_reuses_legacy_or_unmanaged_images_without_both_trusted_labels(lease_environment, labels):
    manager, _cursor, snapshots = lease_environment({_PUBLIC_REF: _lease_image(_PUBLIC_REF, labels=labels)})
    edu._lease(dict(_LEASE_VERSION))
    assert manager.docker.tags == []
    assert snapshots == [('balance', 2)]
    assert len(manager.builds) == len(manager.promotions) == 1


@pytest.mark.parametrize('unsafe', ['volume', 'oversized'])
def test_matching_image_with_unsafe_resources_fails_without_tagging_or_rebuilding(lease_environment, unsafe):
    image = _lease_image(_PUBLIC_REF,
        size=runtime.limits_for(False).image_bytes + 1 if unsafe == 'oversized' else 1024,
        volumes=('/unexpected',) if unsafe == 'volume' else ())
    manager, cursor, snapshots = lease_environment({_PUBLIC_REF: image})
    with pytest.raises(runtime.VibeHubImageError):
        edu._lease(dict(_LEASE_VERSION))
    assert manager.docker.tags == manager.builds == manager.promotions == manager.acquisitions == snapshots == []
    assert any('RELEASE_LOCK' in sql for sql, _params in cursor.calls)


def test_pinning_a_featured_work_uses_its_current_larger_image_budget(lease_environment):
    image = _lease_image(_PUBLIC_REF, size=runtime.limits_for(False).image_bytes + 1)
    manager, _cursor, snapshots = lease_environment({_PUBLIC_REF: image})
    edu._lease({**_LEASE_VERSION, 'is_featured': 1})
    assert manager.docker.tags == [(image.image_id, _FIXED_REF)]
    assert manager.pins[0][2]['featured'] is True
    assert manager.builds == snapshots == []


def test_docker_inspection_failure_is_not_treated_as_a_missing_image(lease_environment):
    manager, cursor, snapshots = lease_environment()
    def unavailable(_reference):
        raise runtime.VibeHubImageError('Docker inspect 暂时不可用')
    manager.docker.after_find = unavailable
    with pytest.raises(runtime.VibeHubImageError, match='inspect'):
        edu._lease(dict(_LEASE_VERSION))
    assert manager.docker.tags == manager.builds == manager.acquisitions == snapshots == []
    assert any('RELEASE_LOCK' in sql for sql, _params in cursor.calls)


def test_image_preparation_lock_timeout_reports_a_specific_retryable_error(lease_environment):
    manager, cursor, snapshots = lease_environment(acquired=0)
    with pytest.raises(services.VibeHubError, match='教学作品镜像正在准备') as error:
        edu._lease(dict(_LEASE_VERSION))
    assert error.value.status_code == 503
    assert error.value.code == 'edu_image_preparing'
    assert manager.captures == manager.pins == manager.docker.lookups == manager.builds == manager.acquisitions == snapshots == []
    assert not any('RELEASE_LOCK' in sql for sql, _params in cursor.calls)


@pytest.mark.parametrize('field,value', [('score', 100), ('completed', True), ('state', {}), ('user_id', 1),
    ('execute', {}), ('execution_result', {}), ('continuation', {})])
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


@pytest.mark.parametrize('operation', ['start', 'step', 'grade'])
@pytest.mark.parametrize('status', [400, 422, 403, 500])
def test_internal_initial_rule_rejection_only_maps_client_operations_to_400(monkeypatch, operation, status):
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(
        relay_http=lambda *_args, **_kwargs: SimpleNamespace(status=status, body=b'private context and grading data'))))
    with pytest.raises(services.VibeHubError) as captured:
        edu._internal(SimpleNamespace(container_name='container'), operation, {'context': {}})
    client_rejection = operation in {'start', 'step'} and status in {400, 422}
    assert captured.value.status_code == (400 if client_rejection else 502)
    assert str(captured.value) == ('操作不符合该作品规则' if client_rejection else '作品无法处理本次操作')
    assert 'private' not in str(captured.value)


@pytest.mark.parametrize('operation', ['start', 'step', 'grade'])
@pytest.mark.parametrize('status', [400, 422])
def test_internal_execution_continuation_rule_rejection_remains_server_error(monkeypatch, operation, status):
    replies = iter([
        SimpleNamespace(status=200, body=b'{"execute":{},"continuation":null}'),
        SimpleNamespace(status=status, body=b'private execution result'),
    ])
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(
        relay_http=lambda *_args, **_kwargs: next(replies))))
    monkeypatch.setattr(edu, '_execute_process', lambda *_args: {'compile': {'returncode': 0}})
    with pytest.raises(services.VibeHubError, match='作品无法处理本次操作') as captured:
        edu._internal(SimpleNamespace(container_name='container'), operation, {'context': {'attempt_id': ROW['id']}})
    assert captured.value.status_code == 502


@pytest.mark.parametrize('field,value', [('score', 100), ('execution', {'passed': 100}), ('completed', True)])
def test_browser_invalid_project_action_returns_400_without_writes_or_private_error(monkeypatch, field, value):
    app = Flask(__name__)
    app.register_blueprint(vibehub_edu_api.vibehub_edu_api_bp)
    monkeypatch.setattr(vibehub_edu_api, 'current_user', lambda: ACTOR)
    cursor = Cursor(one=[None])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    monkeypatch.setattr(edu, '_get_attempt', lambda *_args, **_kwargs: dict(ROW))
    monkeypatch.setattr(edu, '_version', lambda *_args: {'manifest': {}})
    lease = SimpleNamespace(token='lease', container_name='container')
    monkeypatch.setattr(edu, '_lease', lambda *_args: lease)
    relayed, released = [], []
    action = {'type': 'run_code', 'source': 'student source', field: value}

    def relay(*args, **kwargs):
        assert args[:3] == ('container', 'POST', '/v1/step') and kwargs['edu'] is True
        relayed.append(json.loads(args[4]))
        return SimpleNamespace(status=400, body=b'private test inputs and hidden answer')

    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(
        docker=SimpleNamespace(relay_http=relay), release=lambda token: released.append(token)))
    response = app.test_client().post(f"/api/vibehub/edu/attempts/{ROW['id']}/actions", json={
        'command_id': 'command_123', 'expected_seq': 1, 'action': action})
    assert response.status_code == 400
    assert response.get_json()['message'] == '操作不符合该作品规则'
    assert 'private' not in response.get_data(as_text=True)
    assert relayed[0]['action'] == action
    assert released == ['lease']
    assert not any(sql.startswith(('INSERT', 'UPDATE')) for sql, _params in cursor.calls)


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
    monkeypatch.setattr(edu, '_lease', lambda *_args: SimpleNamespace(token='lease'))
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(release=lambda _token: None))
    monkeypatch.setattr(edu, '_internal', lambda *_args: {'score_bp': score_bp, 'verdict': 'passed'})
    with pytest.raises(services.VibeHubError, match='评分响应无效'):
        edu.grade_submission(21)
    assert not any("SET status='graded'" in sql for sql, _params in cursor.calls)
    assert any("SET status='error'" in sql for sql, _params in cursor.calls)


@pytest.mark.parametrize('executor', [None, 'cpp-heap-median-v1', 'cpp-heap-median-v2', 'custom-runtime'])
def test_launch_preserves_assignment_parameters_without_platform_problem_rules(monkeypatch, executor):
    version = {'id': 9, 'project_id': 3, 'slug': 'balance', 'manifest': {'education': {'executor': executor}}}
    parameters = {'custom_level': 3, 'inputs': ['author-defined']}
    assignment = {'id': 5, 'project_id': 3, 'version_id': 9, 'parameters_json': json.dumps(parameters)}
    cursor = Cursor(one=[None, None])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    monkeypatch.setattr(edu, '_assignment', lambda *_args: assignment)
    monkeypatch.setattr(edu, '_version', lambda *_args: version)
    lease = SimpleNamespace(token='lease', proxy_base_path='/vibehub/runtime/lease', expires_at=1)
    monkeypatch.setattr(edu, '_lease', lambda *_args: lease)
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(bind_edu_attempt=lambda *_args: None))
    contexts = []

    def internal(_lease, operation, payload):
        assert operation == 'start'
        contexts.append(payload['context'])
        return {'state': {}, 'view': {}}

    monkeypatch.setattr(edu, '_internal', internal)
    edu.launch('balance', ACTOR, assignment_id=5)
    assert contexts[0]['parameters'] == parameters
    assert 'execution' not in contexts[0]
    assert contexts[0]['project_version_id'] == 9
    stored = json.loads(next(params[5] for sql, params in cursor.calls if sql.startswith('INSERT')))
    assert stored == contexts[0]


@pytest.mark.parametrize('executor', [None, 'cpp-heap-median-v1', 'cpp-heap-median-v2', 'author-specific', ''])
def test_manifest_validation_preserves_opaque_executor_metadata(tmp_path, monkeypatch, executor):
    manifest = {'schema_version': 1, 'kind': 'edu', 'transport': 'unix',
        'socket_path': '/run/vibehub/app.sock', 'health_path': '/healthz',
        'cover_image': 'static/cover.jpg', 'education': {'protocol': edu.PROTOCOL,
            'socket_path': '/run/vibehub/edu.sock', 'executor': executor}}
    (tmp_path / 'Dockerfile').write_text('FROM numericaloj-vibehub-runtime:1\n')
    (tmp_path / 'vibehub.json').write_text(json.dumps(manifest))
    monkeypatch.setattr(edu.storage, 'validate_cover_image', lambda *_args: ('static/cover.jpg', 'image/jpeg'))
    result = edu.storage.validate_manifest(tmp_path)
    assert result['education'].get('executor') == executor


@pytest.mark.parametrize('executor', [True, 3, {}, []])
def test_manifest_validation_rejects_non_string_executor_metadata(tmp_path, executor):
    manifest = {'schema_version': 1, 'kind': 'edu', 'transport': 'unix',
        'socket_path': '/run/vibehub/app.sock', 'health_path': '/healthz',
        'education': {'protocol': edu.PROTOCOL, 'socket_path': '/run/vibehub/edu.sock', 'executor': executor}}
    (tmp_path / 'Dockerfile').write_text('FROM numericaloj-vibehub-runtime:1\n')
    (tmp_path / 'vibehub.json').write_text(json.dumps(manifest))
    with pytest.raises(edu.storage.PackageValidationError, match='education.executor 必须为字符串'):
        edu.storage.validate_manifest(tmp_path)


@pytest.mark.parametrize('operation', ['start', 'step', 'grade'])
def test_internal_execution_keeps_original_context_and_returns_only_platform_process_result(monkeypatch, operation):
    context = {'attempt_id': ROW['id'], 'project_version_id': 9, 'challenge_seed': 'trusted-seed',
               'parameters': {'level': 4}}
    browser_result = {'returncode': 0, 'stdout_b64': 'forged'}
    original = {'context': context, 'action': {'type': 'arbitrary', 'execution_result': browser_result},
                'seq': 2, 'state': {'private': 42}}
    continuation = {'context': {'project_version_id': 999}, 'execution_result': browser_result}
    execute = {'files': {'solution.txt': 'opaque program'}, 'executable': 'program'}
    trusted_result = {'compile': {'returncode': 1, 'stdout_b64': '', 'stderr_b64': 'error'}}
    final = {'score_bp': 3712, 'verdict': 'failed'} if operation == 'grade' else {'state': {}, 'view': {}}
    responses = iter([{'execute': execute, 'continuation': continuation}, final])
    relays, executions = [], []

    def relay(*args, **kwargs):
        relays.append((args, kwargs))
        return SimpleNamespace(status=200, body=json.dumps(next(responses)).encode())

    def run(lease, actual_context, payload):
        executions.append((lease.container_name, actual_context, payload))
        return trusted_result

    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(relay_http=relay)))
    monkeypatch.setattr(edu, '_execute_process', run)
    assert edu._internal(SimpleNamespace(container_name='trusted-container'), operation, original) == final
    assert executions == [('trusted-container', context, execute)]
    assert len(relays) == 2
    callback = json.loads(relays[1][0][4])
    assert callback == {**original, 'continuation': continuation, 'execution_result': trusted_result}
    assert callback['context'] == context and 'execution' not in callback['context']
    assert callback['action']['execution_result'] == browser_result
    assert set(original) == {'context', 'action', 'seq', 'state'}
    for args, kwargs in relays:
        assert args[:3] == ('trusted-container', 'POST', f'/v1/{operation}')
        assert kwargs == {'timeout': 45, 'response_max_bytes': edu.MAX_JSON_BYTES, 'edu': True}


@pytest.mark.parametrize('reply', [
    {'execute': {}}, {'continuation': {}}, {'execute': [], 'continuation': {}},
    {'execute': {}, 'continuation': {}, 'context': {}},
    {'execute': {}, 'continuation': {}, 'state': {}, 'view': {}},
])
def test_internal_execution_request_requires_exactly_two_fields(monkeypatch, reply):
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(
        relay_http=lambda *_args, **_kwargs: SimpleNamespace(status=200, body=json.dumps(reply).encode()))))
    monkeypatch.setattr(edu, '_execute_process', lambda *_args: pytest.fail('非法请求不能执行进程'))
    with pytest.raises(services.VibeHubError, match='执行请求字段无效'):
        edu._internal(SimpleNamespace(container_name='container'), 'step', {'context': {}})


@pytest.mark.parametrize('requests,should_finish', [(4, True), (5, False)])
def test_internal_execution_has_a_bounded_continuation_loop(monkeypatch, requests, should_finish):
    relays, executions = [], []
    original = {'context': {'attempt_id': ROW['id']}, 'actions': [{'action': {'type': 'custom'}}]}

    def relay(*args, **_kwargs):
        relays.append(json.loads(args[4]))
        result = {'execute': {'number': len(relays)}, 'continuation': len(relays)} if len(relays) <= requests else {'score_bp': 1234, 'verdict': 'failed'}
        return SimpleNamespace(status=200, body=json.dumps(result).encode())

    def run(_lease, _context, execute):
        executions.append(execute)
        return {'finished': execute['number']}

    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(relay_http=relay)))
    monkeypatch.setattr(edu, '_execute_process', run)
    if should_finish:
        assert edu._internal(SimpleNamespace(container_name='container'), 'grade', original)['score_bp'] == 1234
    else:
        with pytest.raises(services.VibeHubError, match='执行请求次数超过限制'):
            edu._internal(SimpleNamespace(container_name='container'), 'grade', original)
    assert len(executions) == 4 and len(relays) == 5
    for index, payload in enumerate(relays[1:], 1):
        assert payload['context'] == original['context']
        assert payload['actions'] == original['actions']
        assert payload['execution_result'] == {'finished': index}
        assert payload['continuation'] == index


def test_oversized_internal_response_never_executes(monkeypatch):
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(
        relay_http=lambda *_args, **_kwargs: SimpleNamespace(status=200, body=b' ' * (edu.MAX_JSON_BYTES + 1)))))
    monkeypatch.setattr(edu, '_execute_process', lambda *_args: pytest.fail('超限请求不能执行进程'))
    with pytest.raises(services.VibeHubError, match='教育协议响应无效'):
        edu._internal(SimpleNamespace(container_name='container'), 'step', {'context': {}})


def test_internal_callback_size_includes_original_payload_continuation_and_execution_result(monkeypatch):
    calls = []
    monkeypatch.setattr(edu, 'MAX_JSON_BYTES', 256)

    def relay(*_args, **_kwargs):
        calls.append('relay')
        return SimpleNamespace(status=200, body=b'{"execute":{},"continuation":"opaque"}')

    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(relay_http=relay)))
    monkeypatch.setattr(edu, '_execute_process', lambda *_args: {'stdout_b64': 'x' * 180})
    with pytest.raises(services.VibeHubError, match='作答数据超过限制'):
        edu._internal(SimpleNamespace(container_name='container'), 'step',
            {'context': {'attempt_id': ROW['id']}, 'action': {'type': 'custom'}})
    assert calls == ['relay']


def test_internal_response_does_not_promote_browser_execute_or_execution_result(monkeypatch):
    payload = {'context': {'attempt_id': ROW['id']}, 'action': {'type': 'custom',
        'execute': {'files': {'spoof': 'browser'}}, 'execution_result': {'score_bp': 10000}}}
    calls = []

    def relay(*args, **_kwargs):
        calls.append(json.loads(args[4]))
        return SimpleNamespace(status=200, body=b'{"state":{},"view":{"saved":true}}')

    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(relay_http=relay)))
    monkeypatch.setattr(edu, '_execute_process', lambda *_args: pytest.fail('浏览器动作不能自行执行进程'))
    assert edu._internal(SimpleNamespace(container_name='container'), 'step', payload)['view'] == {'saved': True}
    assert calls == [payload]


@pytest.mark.parametrize('runtime_failure', [False, True])
def test_generic_process_uses_existing_container_and_releases_all_locks(monkeypatch, runtime_failure):
    cursor = Cursor(one=[{'acquired': 1}, {'acquired': 0}, {'acquired': 1}])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    calls = []
    execute = {'files': {'program.c': 'author program'}, 'run': {'stdin': 'test'}}
    result = {'compile': {'returncode': 0}}

    def run(container, payload, **kwargs):
        calls.append((container, payload, kwargs))
        if runtime_failure:
            raise RuntimeError('process unavailable')
        return result

    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(execute_edu_process=run)))
    lease = SimpleNamespace(container_name='existing-container')
    if runtime_failure:
        with pytest.raises(RuntimeError, match='process unavailable'):
            edu._execute_process(lease, {'attempt_id': ROW['id']}, execute)
    else:
        assert edu._execute_process(lease, {'attempt_id': ROW['id']}, execute) == result
    assert calls == [('existing-container', execute, {'timeout': 40})]
    assert [params[0] for sql, params in cursor.calls if 'RELEASE_LOCK' in sql] == [
        'edu:process-slot:1', f"edu:execute:{ROW['id']}"]


@pytest.mark.parametrize('owner_available', [False, True])
def test_generic_process_does_not_execute_when_owner_or_global_capacity_is_busy(monkeypatch, owner_available):
    cursor = Cursor(one=[{'acquired': int(owner_available)}] + ([{'acquired': 0}] * 10 if owner_available else []))
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(
        execute_edu_process=lambda *_args, **_kwargs: pytest.fail('没有资源时不能执行'))))
    with pytest.raises(services.VibeHubError) as captured:
        edu._execute_process(SimpleNamespace(container_name='container'), {'attempt_id': ROW['id']}, {})
    assert captured.value.status_code == 429
    releases = [params[0] for sql, params in cursor.calls if 'RELEASE_LOCK' in sql]
    assert releases == ([f"edu:execute:{ROW['id']}"] if owner_available else [])


def test_ten_executions_share_database_slots_and_eleventh_waits_until_a_slot_is_released(monkeypatch):
    held = {}
    guard = threading.Lock()
    entered = Queue()
    release = [threading.Event() for _ in range(10)]

    class NamedLockConnection:
        """模拟各 worker 的独立连接共享 MySQL 命名锁，不使用进程内业务计数器。"""
        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def execute(self, sql, params):
            name = params[0]
            with guard:
                if 'GET_LOCK' in sql:
                    self.result = {'acquired': int(name not in held)}
                    if self.result['acquired']:
                        held[name] = self
                else:
                    assert 'RELEASE_LOCK' in sql and held[name] is self
                    del held[name]

        def fetchone(self):
            return self.result

        def close(self):
            with guard:
                assert self not in held.values(), '每个连接关闭前都应主动释放它持有的锁'

    def execute(_container, payload, **kwargs):
        assert kwargs == {'timeout': 40}
        number = payload['number']
        entered.put(number)
        if number < 10:
            assert release[number].wait(timeout=15), '测试未及时释放执行进程'
        return {'compile': {'returncode': 0}}

    monkeypatch.setattr(edu, 'get_db_connection', NamedLockConnection)
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(docker=SimpleNamespace(execute_edu_process=execute)))
    lease = SimpleNamespace(container_name='existing-container')

    def run(number):
        return edu._execute_process(lease, {'attempt_id': f'att_capacity_{number}'}, {'number': number})

    with ThreadPoolExecutor(max_workers=10) as workers:
        futures = [workers.submit(run, number) for number in range(10)]
        try:
            assert {entered.get(timeout=5) for _ in range(10)} == set(range(10))
            with guard:
                assert {name for name in held if name.startswith('edu:process-slot:')} == {
                    f'edu:process-slot:{index}' for index in range(10)}
                assert len({id(owner) for name, owner in held.items() if name.startswith('edu:process-slot:')}) == 10
            with pytest.raises(services.VibeHubError) as captured:
                run(10)
            assert captured.value.status_code == 429
            assert entered.empty(), '第 11 个执行不能进入 Docker'
            with guard:
                assert 'edu:execute:att_capacity_10' not in held
            release[9].set()
            assert futures[9].result(timeout=5) == {'compile': {'returncode': 0}}
            assert run(10) == {'compile': {'returncode': 0}}
            assert entered.get(timeout=5) == 10
        finally:
            for event in release:
                event.set()
        assert all(future.result(timeout=5) == {'compile': {'returncode': 0}} for future in futures)
    assert held == {}


def test_generic_action_keeps_runtime_lease_until_internal_execution_finishes(monkeypatch):
    events = []
    cursor = Cursor(one=[None])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    monkeypatch.setattr(edu, '_get_attempt', lambda *_args, **_kwargs: dict(ROW))
    monkeypatch.setattr(edu, '_version', lambda *_args: {'manifest': {'education': {'executor': 'opaque-value'}}})
    lease = SimpleNamespace(token='existing-lease', container_name='existing-container')
    monkeypatch.setattr(edu, '_lease', lambda *_args: events.append('lease') or lease)
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(release=lambda token: events.append(('release', token))))

    def internal(actual_lease, operation, payload):
        assert actual_lease is lease and operation == 'step'
        assert payload['context'] == json.loads(ROW['context_json'])
        assert payload['action'] == {'type': 'rotate', 'target': 'node-1'}
        events.append('execute')
        raise RuntimeError('process unavailable')

    monkeypatch.setattr(edu, '_internal', internal)
    with pytest.raises(RuntimeError, match='process unavailable'):
        edu.apply_action(ROW['id'], {'command_id': 'command_123', 'expected_seq': 1,
            'action': {'type': 'rotate', 'target': 'node-1'}}, ACTOR)
    assert events == ['lease', 'execute', ('release', 'existing-lease')]


def test_grading_passes_frozen_snapshot_and_stores_private_project_score_without_recomputing(monkeypatch):
    snapshot = {'context': {'attempt_id': ROW['id'], 'parameters': {'arbitrary': 3}},
                'actions': [{'seq': 1, 'action': {'type': 'rotate', 'value': 2, 'score_bp': 10000}}]}
    row = {'id': 21, 'attempt_id': ROW['id'], 'project_id': 3, 'version_id': 9,
           'user_id': 12, 'status': 'submitted', 'snapshot_json': json.dumps(snapshot)}
    cursor = Cursor(one=[{'acquired': 1}, row])
    monkeypatch.setattr(edu, 'get_db_connection', lambda: Connection(cursor))
    versions, requests = [], []
    monkeypatch.setattr(edu, '_version', lambda _cursor, project_id, version_id: versions.append((project_id, version_id)) or {'manifest': {}})
    monkeypatch.setattr(edu, '_lease', lambda *_args: SimpleNamespace(token='lease'))
    monkeypatch.setattr(edu, 'get_runtime_manager', lambda: SimpleNamespace(release=lambda _token: None))
    result = {'score_bp': 3712, 'verdict': 'failed', 'metrics': {'author-defined': 14}}

    def internal(_lease, operation, payload):
        requests.append((operation, payload))
        return result

    monkeypatch.setattr(edu, '_internal', internal)
    monkeypatch.setattr('backend.oj_modules.problems.catalog.invalidate_problem_list_cache_for_user', lambda **_kwargs: None)
    edu.grade_submission(21)
    assert versions == [(3, 9)]
    assert requests == [('grade', snapshot)]
    score_update = next(params for sql, params in cursor.calls if "SET status='graded',score_bp=" in sql)
    assert score_update == (3712, 37.12, edu._dump(result), 21)


def test_education_api_requires_login_and_rejects_identity_override(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(vibehub_edu_api.vibehub_edu_api_bp)
    client = app.test_client()
    monkeypatch.setattr(vibehub_edu_api, 'current_user', lambda: None)
    assert client.post('/api/vibehub/projects/balance/edu/launch', json={}).status_code == 403
    monkeypatch.setattr(vibehub_edu_api, 'current_user', lambda: ACTOR)
    monkeypatch.setattr(edu, 'launch', lambda *_args, **_kwargs: pytest.fail('不接受客户端覆盖身份'))
    assert client.post('/api/vibehub/projects/balance/edu/launch', json={'user_id': 99}).status_code == 400
