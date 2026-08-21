# -*- coding: utf-8 -*-
"""打榜赛上传文件与计费提交的一致性回归测试（不连接 MySQL）。"""

from datetime import datetime
import io
import inspect
from pathlib import Path

import pytest
from flask import Flask

from oj_modules.ranking import db as ranking_db
from oj_modules.routes import ranking_routes
from oj_modules.tasks.ranking import evaluate as ranking_evaluate_tasks


class _FakeCursor:
    def __init__(self, *, rowcount=1, fetch_values=None):
        self.calls = []
        self.rowcount = rowcount
        self.lastrowid = 71
        self._fetch_values = list(fetch_values or [])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchone(self):
        if self._fetch_values:
            return self._fetch_values.pop(0)
        return None


class _FakeConnection:
    def __init__(self, cursor, *, commit_error=None):
        self.fake_cursor = cursor
        self.commit_error = commit_error
        self.commit_count = 0
        self.rollback_count = 0
        self.closed = False

    def cursor(self):
        return self.fake_cursor

    def commit(self):
        self.commit_count += 1
        if self.commit_error is not None:
            raise self.commit_error

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.closed = True


class _Upload:
    def __init__(self, payload):
        self.payload = payload

    def save(self, path):
        Path(path).write_bytes(self.payload)


def _staged_file(tmp_path, name, payload=b'artifact'):
    staging = tmp_path / 'staging'
    staging.mkdir(exist_ok=True)
    path = staging / name
    path.write_bytes(payload)
    return path


def _patch_artifact_db(monkeypatch, tmp_path, cursor):
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)
    monkeypatch.setattr(ranking_db, '_lock_submission_quota', lambda *_a, **_kw: None)
    monkeypatch.setattr(ranking_db, '_insert_ranking_submission', lambda *_a, **_kw: 71)
    monkeypatch.setattr(
        ranking_db,
        'submission_dir',
        lambda submission_id: str(tmp_path / 'submissions' / str(submission_id)),
    )
    return conn


def test_artifact_submission_commits_files_metadata_and_counter_once(monkeypatch, tmp_path):
    code = _staged_file(tmp_path, 'code.zip', b'code')
    answer = _staged_file(tmp_path, 'answer.json', b'answer')
    cursor = _FakeCursor(rowcount=1)
    conn = _patch_artifact_db(monkeypatch, tmp_path, cursor)
    counter_calls = []
    monkeypatch.setattr(ranking_db, 'bump_daily_submission_count', lambda: counter_calls.append(1))

    submission_id = ranking_db.create_ranking_artifact_submission(
        9,
        'student',
        code_staged_path=str(code),
        code_filename='code.zip',
        answer_staged_path=str(answer),
        answer_filename='answer.json',
        base_model='qwen-test',
        enforce_quota=True,
    )

    target = tmp_path / 'submissions' / '71'
    assert submission_id == 71
    assert (target / 'code.zip').read_bytes() == b'code'
    assert (target / 'answer.json').read_bytes() == b'answer'
    assert not code.exists() and not answer.exists()
    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    assert conn.closed is True
    assert counter_calls == [1]
    update_sql, update_params = cursor.calls[-1]
    assert 'UPDATE ranking_submissions' in update_sql
    assert update_params == (
        'answer.json', str(target / 'answer.json'),
        'code.zip', str(target / 'code.zip'),
        'qwen-test', 71,
    )


def test_elo_submission_accepts_single_archive_and_activates_pool(monkeypatch):
    app = Flask(__name__)
    app.secret_key = 'test-only'
    user = {'username': 'student', 'is_admin': 0}
    competition = {
        'id': 9,
        'is_active': 1,
        'scoring_mode': 'elo',
        'submission_method': 'zip',
        'elo_initial_rating': 1500,
    }
    monkeypatch.setattr(ranking_routes, '_require_user', lambda: (user, None))
    monkeypatch.setattr(ranking_routes, 'get_competition', lambda _cid: competition)
    monkeypatch.setattr(ranking_routes, '_ranking_submit_block_reason', lambda *_a, **_kw: '')
    monkeypatch.setattr(ranking_routes, 'rate_limit_hit', lambda *_a, **_kw: (True, 0))
    monkeypatch.setattr(ranking_routes, 'get_submission_quota', lambda *_a, **_kw: None)
    created = []
    monkeypatch.setattr(
        ranking_routes,
        '_create_uploaded_ranking_submission',
        lambda *_a, **kwargs: created.append(kwargs) or 71,
    )
    activated = []
    monkeypatch.setattr(
        ranking_routes,
        'activate_elo_submission',
        lambda *args, **kwargs: activated.append((args, kwargs)),
    )
    monkeypatch.setattr(ranking_routes, '_elo_initial_burst_task', None)
    monkeypatch.setattr(
        ranking_routes,
        'url_for',
        lambda _endpoint, **_values: '/ranking/9?tab=submit',
    )

    with app.test_request_context(
            '/ranking/9/submit',
            method='POST',
            data={
                'base_model': 'qwen-test',
                'code_file': (io.BytesIO(b'archive'), 'submission.zip'),
            },
            content_type='multipart/form-data',
    ):
        response = ranking_routes.ranking_submit(9)

    assert response.status_code == 302
    assert created[0]['code_name'] == 'submission.zip'
    assert activated == [((71, 9, 'student', 1500.0), {'keep_count': 2})]


def test_artifact_metadata_failure_rolls_back_and_removes_target(monkeypatch, tmp_path):
    code = _staged_file(tmp_path, 'code.zip')
    cursor = _FakeCursor(rowcount=0)
    conn = _patch_artifact_db(monkeypatch, tmp_path, cursor)
    counter_calls = []
    monkeypatch.setattr(ranking_db, 'bump_daily_submission_count', lambda: counter_calls.append(1))

    with pytest.raises(RuntimeError, match='文件元数据写入失败'):
        ranking_db.create_ranking_artifact_submission(
            9,
            'student',
            code_staged_path=str(code),
            code_filename='code.zip',
            enforce_quota=True,
        )

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert not (tmp_path / 'submissions' / '71').exists()
    assert counter_calls == []


def test_artifact_commit_error_confirmed_by_new_connection_is_success(monkeypatch, tmp_path):
    code = _staged_file(tmp_path, 'code.zip')
    cursor = _FakeCursor(rowcount=1)
    conn = _patch_artifact_db(monkeypatch, tmp_path, cursor)
    conn.commit_error = OSError('commit response lost')
    monkeypatch.setattr(ranking_db, '_artifact_commit_matches', lambda *_args: True)
    counter_calls = []
    monkeypatch.setattr(ranking_db, 'bump_daily_submission_count', lambda: counter_calls.append(1))

    submission_id = ranking_db.create_ranking_artifact_submission(
        9,
        'student',
        code_staged_path=str(code),
        code_filename='code.zip',
    )

    target = tmp_path / 'submissions' / '71' / 'code.zip'
    assert submission_id == 71
    assert target.is_file()
    assert conn.rollback_count == 1
    assert counter_calls == [1]


def test_artifact_unknown_commit_preserves_files_for_reconciliation(monkeypatch, tmp_path):
    code = _staged_file(tmp_path, 'code.zip')
    cursor = _FakeCursor(rowcount=1)
    conn = _patch_artifact_db(monkeypatch, tmp_path, cursor)
    conn.commit_error = OSError('commit response lost')
    monkeypatch.setattr(ranking_db, '_artifact_commit_matches', lambda *_args: False)
    counter_calls = []
    monkeypatch.setattr(ranking_db, 'bump_daily_submission_count', lambda: counter_calls.append(1))

    with pytest.raises(
            ranking_db.RankingSubmissionCommitUnknown,
            match='文件已保留待核验',
    ):
        ranking_db.create_ranking_artifact_submission(
            9,
            'student',
            code_staged_path=str(code),
            code_filename='code.zip',
        )

    assert (tmp_path / 'submissions' / '71' / 'code.zip').is_file()
    assert counter_calls == []


def test_artifact_commit_confirmation_checks_metadata_and_files(monkeypatch, tmp_path):
    target = tmp_path / 'submissions' / '71'
    target.mkdir(parents=True)
    code = target / 'code.zip'
    code.write_bytes(b'zip')
    monkeypatch.setattr(
        ranking_db,
        'get_ranking_submission',
        lambda _submission_id: {
            'id': 71,
            'code_filename': 'code.zip',
            'code_path': str(code),
            'answer_filename': None,
            'answer_path': None,
        },
    )

    assert ranking_db._artifact_commit_matches(
        71,
        {'code': str(code)},
        'code.zip',
        None,
    ) is True

    code.unlink()
    assert ranking_db._artifact_commit_matches(
        71,
        {'code': str(code)},
        'code.zip',
        None,
    ) is False


def test_artifact_metric_failure_does_not_change_committed_result(monkeypatch, tmp_path):
    code = _staged_file(tmp_path, 'code.zip')
    conn = _patch_artifact_db(monkeypatch, tmp_path, _FakeCursor(rowcount=1))

    def fail_metric():
        raise OSError('metric unavailable')

    monkeypatch.setattr(ranking_db, 'bump_daily_submission_count', fail_metric)

    assert ranking_db.create_ranking_artifact_submission(
        9,
        'student',
        code_staged_path=str(code),
        code_filename='code.zip',
    ) == 71
    assert conn.commit_count == 1
    assert (tmp_path / 'submissions' / '71' / 'code.zip').is_file()


def test_artifact_move_failure_rolls_back_and_removes_partial_target(monkeypatch, tmp_path):
    code = _staged_file(tmp_path, 'code.zip')
    answer = _staged_file(tmp_path, 'answer.json')
    conn = _patch_artifact_db(monkeypatch, tmp_path, _FakeCursor())
    counter_calls = []
    monkeypatch.setattr(ranking_db, 'bump_daily_submission_count', lambda: counter_calls.append(1))
    real_replace = ranking_db.os.replace
    replace_count = 0

    def fail_second_replace(src, dst):
        nonlocal replace_count
        replace_count += 1
        if replace_count == 2:
            raise OSError('disk failure')
        real_replace(src, dst)

    monkeypatch.setattr(ranking_db.os, 'replace', fail_second_replace)

    with pytest.raises(OSError, match='disk failure'):
        ranking_db.create_ranking_artifact_submission(
            9,
            'student',
            code_staged_path=str(code),
            code_filename='code.zip',
            answer_staged_path=str(answer),
            answer_filename='answer.json',
        )

    assert conn.rollback_count == 1
    assert not (tmp_path / 'submissions' / '71').exists()
    assert counter_calls == []


def test_artifact_quota_rejection_happens_before_insert_and_count(monkeypatch, tmp_path):
    code = _staged_file(tmp_path, 'code.zip')
    cursor = _FakeCursor()
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)

    def reject_quota(*_args, **_kwargs):
        raise ranking_db.RankingSubmissionQuotaExceeded({'remaining': 0})

    monkeypatch.setattr(ranking_db, '_lock_submission_quota', reject_quota)
    insert_calls = []
    monkeypatch.setattr(
        ranking_db,
        '_insert_ranking_submission',
        lambda *_a, **_kw: insert_calls.append(1),
    )
    counter_calls = []
    monkeypatch.setattr(ranking_db, 'bump_daily_submission_count', lambda: counter_calls.append(1))

    with pytest.raises(ranking_db.RankingSubmissionQuotaExceeded):
        ranking_db.create_ranking_artifact_submission(
            9,
            'student',
            code_staged_path=str(code),
            code_filename='code.zip',
            enforce_quota=True,
        )

    assert insert_calls == []
    assert conn.rollback_count == 1
    assert counter_calls == []


def test_quota_check_keeps_for_update_before_counting_usage():
    anchor = datetime(2026, 7, 1, 12, 0, 0)
    now = datetime(2026, 7, 2, 12, 0, 0)
    cursor = _FakeCursor(fetch_values=[
        {'id': 7},
        {
            'id': 9,
            'submit_limit_per_window': 2,
            'limit_window_start': anchor,
            'created_at': anchor,
        },
        {'now': now},
        {'c': 1},
    ])

    ranking_db._lock_submission_quota(
        cursor, 9, 'student', source='self', enforce_quota=True,
    )

    assert 'FROM users' in cursor.calls[0][0]
    assert 'FOR UPDATE' in cursor.calls[0][0]
    assert 'FROM ranking_competitions' in cursor.calls[1][0]
    assert 'FOR UPDATE' not in cursor.calls[1][0]
    assert 'COUNT(*)' in cursor.calls[3][0]


def test_quota_lock_is_scoped_to_user_not_whole_competition():
    source = inspect.getsource(ranking_db._lock_submission_quota)

    assert 'FROM users' in source
    assert source.count('FOR UPDATE') == 1
    competition_query = source.split('FROM ranking_competitions', 1)[1]
    assert 'FOR UPDATE' not in competition_query


def test_upload_size_failure_never_opens_submission_transaction_and_cleans_staging(
        monkeypatch, tmp_path):
    monkeypatch.setattr(
        ranking_routes,
        'submission_dir',
        lambda submission_id: str(tmp_path / 'submissions' / str(submission_id)),
    )
    monkeypatch.setattr(ranking_routes, 'CODE_ZIP_MAX_BYTES', 2)
    db_calls = []
    monkeypatch.setattr(
        ranking_routes,
        'create_ranking_artifact_submission',
        lambda *_a, **_kw: db_calls.append(1),
    )

    with pytest.raises(ValueError, match='超过'):
        ranking_routes._create_uploaded_ranking_submission(
            9,
            'student',
            code_file=_Upload(b'123'),
            code_name='code.zip',
            enforce_quota=True,
        )

    assert db_calls == []
    staging_root = tmp_path / 'submissions'
    assert list(staging_root.glob('.upload-*')) == []


def test_upload_helper_cleans_staging_when_database_rejects_submission(monkeypatch, tmp_path):
    monkeypatch.setattr(
        ranking_routes,
        'submission_dir',
        lambda submission_id: str(tmp_path / 'submissions' / str(submission_id)),
    )

    def reject(*_args, **_kwargs):
        raise RuntimeError('metadata failure')

    monkeypatch.setattr(ranking_routes, 'create_ranking_artifact_submission', reject)

    with pytest.raises(RuntimeError, match='metadata failure'):
        ranking_routes._create_uploaded_ranking_submission(
            9,
            'student',
            code_file=_Upload(b'zip'),
            code_name='code.zip',
        )

    assert list((tmp_path / 'submissions').glob('.upload-*')) == []


def test_all_zip_submission_modes_share_artifact_boundary():
    source = inspect.getsource(ranking_routes.ranking_submit)

    assert source.count('_create_uploaded_ranking_submission(') == 4
    assert source.count('except RankingSubmissionCommitUnknown as exc:') == 4
    assert 'create_ranking_submission(' not in source
    assert 'update_submission_files(' not in source


def test_commit_unknown_route_returns_pending_confirmation_and_does_not_enqueue(
        monkeypatch):
    app = Flask(__name__)
    app.secret_key = 'test-only'
    user = {'username': 'student', 'is_admin': 0}
    competition = {
        'id': 9,
        'is_active': 1,
        'scoring_mode': 'reverse_judge',
        'submission_method': 'zip',
    }
    monkeypatch.setattr(ranking_routes, '_require_user', lambda: (user, None))
    monkeypatch.setattr(ranking_routes, 'get_competition', lambda _cid: competition)
    monkeypatch.setattr(ranking_routes, '_ranking_submit_block_reason', lambda *_a, **_kw: '')
    monkeypatch.setattr(ranking_routes, 'rate_limit_hit', lambda *_a, **_kw: (True, 0))
    monkeypatch.setattr(ranking_routes, 'get_submission_quota', lambda *_a, **_kw: None)
    monkeypatch.setattr(
        ranking_routes,
        '_validate_reverse_endpoint_choice',
        lambda _cid: (5, None),
    )

    def commit_unknown(*_args, **_kwargs):
        raise ranking_db.RankingSubmissionCommitUnknown(71)

    monkeypatch.setattr(
        ranking_routes,
        '_create_uploaded_ranking_submission',
        commit_unknown,
    )

    with app.test_request_context(
            '/ranking/9/submit',
            method='POST',
            data={'code_file': (io.BytesIO(b'zip'), 'code.zip')},
            content_type='multipart/form-data',
            headers={'Accept': 'application/json'},
    ):
        response, status = ranking_routes.ranking_submit(9)

    payload = response.get_json()
    assert status == 202
    assert payload == {
        'success': False,
        'pending_confirmation': True,
        'submission_id': 71,
        'message': (
            '提交 #71 的状态暂时无法确认，请勿立即重复提交。'
            '系统会自动核验并补发评测；15 分钟后若历史提交仍不可见，再重试或联系管理员。'
        ),
    }


def test_elo_activation_and_retirement_commit_in_one_transaction(monkeypatch):
    cursor = _FakeCursor(rowcount=1, fetch_values=[{'id': 7}])
    cursor.fetchall = lambda: [{'id': 81}, {'id': 80}, {'id': 79}]
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)

    retired = ranking_db.activate_elo_submission(
        81,
        9,
        'student',
        1600,
        keep_count=2,
    )

    assert retired == [79]
    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    assert 'FROM users' in cursor.calls[0][0]
    assert 'FOR UPDATE' in cursor.calls[0][0]
    assert "status = 'Active'" in cursor.calls[1][0]
    assert 'elo_in_pool = 1' in cursor.calls[2][0]
    assert "status = 'Retired'" in cursor.calls[3][0]


def test_standard_ranking_reservation_is_persistent_compare_and_set(monkeypatch):
    cursor = _FakeCursor(rowcount=1)
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)

    assert ranking_db.reserve_standard_ranking_evaluation(
        71,
        'task-71',
        stale_after_seconds=1800,
    ) == 1

    sql, params = cursor.calls[0]
    assert "status = 'Queued'" in sql
    assert "status = 'Judging' AND judge_task_id IS NULL" in sql
    assert "status IN ('Judging', 'Queued')" in sql
    assert params[:2] == ('task-71', 71)
    assert params[2] == 1800
    assert conn.commit_count == 1

    claim_cursor = _FakeCursor(rowcount=1)
    claim_conn = _FakeConnection(claim_cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: claim_conn)
    assert ranking_db.claim_standard_ranking_evaluation(71, 'task-71') == 1
    assert "status = 'Judging'" in claim_cursor.calls[0][0]
    assert claim_cursor.calls[0][1] == ('task-71', 71, 'task-71')

    release_cursor = _FakeCursor(rowcount=1)
    release_conn = _FakeConnection(release_cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: release_conn)
    assert ranking_db.release_standard_ranking_evaluation(71, 'task-71') == 1
    assert 'judge_task_id = NULL' in release_cursor.calls[0][0]
    assert release_cursor.calls[0][1] == (71, 'task-71')

    result_cursor = _FakeCursor(rowcount=1)
    result_conn = _FakeConnection(result_cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: result_conn)
    assert ranking_db.update_standard_ranking_result_for_task(
        71,
        'task-71',
        95,
        'Accepted',
        grade_details={'ok': True},
    ) == 1
    assert 'WHERE id = %s AND judge_task_id = %s' in result_cursor.calls[0][0]
    assert result_cursor.calls[0][1] == (
        95,
        'Accepted',
        '{"ok": true}',
        None,
        71,
        'task-71',
    )


def test_standard_ranking_task_skips_when_database_lease_belongs_to_newer_task(
        monkeypatch):
    class _FakeCelery:
        def task(self, **_kwargs):
            return lambda func: func

    evaluate_calls = []
    monkeypatch.setattr(
        ranking_evaluate_tasks,
        'claim_standard_ranking_evaluation',
        lambda submission_id, task_id: 0,
    )
    monkeypatch.setattr(
        ranking_evaluate_tasks,
        '_evaluate',
        lambda submission_id: evaluate_calls.append(submission_id),
    )
    task = ranking_evaluate_tasks.register_ranking_evaluate_task(_FakeCelery())
    bound = type('BoundTask', (), {'request': type('Request', (), {'id': 'old-task'})()})()

    result = task(bound, 71)

    assert result['skipped'] is True
    assert evaluate_calls == []


def test_standard_ranking_terminal_result_is_discarded_after_lease_replacement(
        monkeypatch):
    persisted = []
    monkeypatch.setattr(
        ranking_evaluate_tasks,
        'get_ranking_submission',
        lambda _submission_id: {'competition_id': 9},
    )
    monkeypatch.setattr(
        ranking_evaluate_tasks,
        'get_competition',
        lambda _competition_id: None,
    )
    monkeypatch.setattr(
        ranking_evaluate_tasks,
        'update_standard_ranking_result_for_task',
        lambda *args, **kwargs: persisted.append((args, kwargs)) or 0,
    )

    result = ranking_evaluate_tasks._evaluate(71, 'old-task')

    assert result == {
        'success': True,
        'skipped': True,
        'message': '评测租约已被新任务替换，丢弃旧任务结果',
    }
    assert persisted == [((71, 'old-task', None, 'Error'), {
        'grade_details': None,
        'error_message': '比赛不存在或已被删除',
    })]
