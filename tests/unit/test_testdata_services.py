import zipfile

import pytest

from backend.oj_modules.problems import testdata as testdata_services


def test_import_testdata_uses_restricted_extraction_and_replaces_stale_files(
        monkeypatch, tmp_path):
    archive = tmp_path / 'testdata.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('1.in', '1 2\n')
        zf.writestr('1.out', '3\n')

    destination = tmp_path / 'extracted'
    destination.mkdir()
    (destination / 'stale.in').write_text('stale', encoding='utf-8')
    saved = []
    monkeypatch.setattr(
        testdata_services,
        'update_problem_testdata',
        lambda problem_id, rows: saved.append((problem_id, rows)),
    )

    result = testdata_services.import_testdata_zip(7, archive, destination)

    assert result == {
        'count': 1,
        'testdata': [{'input': '1 2\n', 'output': '3\n'}],
    }
    assert saved == [(7, result['testdata'])]
    assert not (destination / 'stale.in').exists()


def test_parse_testdata_zip_stages_rows_without_writing_database(
        monkeypatch, tmp_path):
    archive = tmp_path / 'testdata.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('1.in', '4\n')
        zf.writestr('1.out', '16\n')

    monkeypatch.setattr(
        testdata_services,
        'get_db_connection',
        lambda: pytest.fail('staging 解析不得连接数据库'),
    )

    result = testdata_services.parse_testdata_zip(
        archive,
        tmp_path / 'staged',
    )

    assert result == {
        'count': 1,
        'testdata': [{'input': '4\n', 'output': '16\n'}],
    }


def test_import_testdata_rejects_traversal_without_leaving_partial_output(tmp_path):
    archive = tmp_path / 'unsafe.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('1.in', 'input')
        zf.writestr('../escape.out', 'escape')

    destination = tmp_path / 'extracted'
    with pytest.raises(testdata_services.TestdataValidationError, match='目录穿越'):
        testdata_services.import_testdata_zip(7, archive, destination)

    assert not destination.exists()
    assert not (tmp_path / 'escape.out').exists()


def test_import_testdata_accepts_highly_compressible_large_text(
        monkeypatch, tmp_path):
    archive = tmp_path / 'compressible.zip'
    repeated = 'A' * 2_000_000
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('1.in', repeated + '\n')
        zf.writestr('1.out', repeated + '!\n')
    saved = []
    monkeypatch.setattr(
        testdata_services,
        'update_problem_testdata',
        lambda problem_id, rows: saved.append((problem_id, rows)),
    )

    result = testdata_services.import_testdata_zip(
        7, archive, tmp_path / 'out',
    )

    assert result['count'] == 1
    assert result['testdata'][0]['input'] == repeated + '\n'
    assert result['testdata'][0]['output'] == repeated + '!\n'
    assert saved == [(7, result['testdata'])]


@pytest.mark.parametrize(
    'members',
    [
        {'case.in': '1', 'case.out': '1'},
        {'1.in': '1', '1.out': '1', 'README.txt': 'extra'},
        {'1.in': '1', '1.out': '1', '3.in': '3', '3.out': '3'},
        {'nested/1.in': '1', 'nested/1.out': '1'},
    ],
)
def test_import_testdata_only_accepts_contiguous_root_pairs(tmp_path, members):
    archive = tmp_path / 'invalid-format.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        for name, content in members.items():
            zf.writestr(name, content)

    with pytest.raises(testdata_services.TestdataValidationError):
        testdata_services.parse_testdata_zip(archive, tmp_path / 'out')


class _FailingCursor:
    def __init__(self):
        self.execute_count = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, _sql, _params):
        self.execute_count += 1
        raise RuntimeError('模拟 UPDATE 失败')


class _FailingConnection:
    def __init__(self):
        self.cursor_instance = _FailingCursor()
        self.commit_count = 0
        self.rollback_count = 0
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commit_count += 1

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.closed = True


def test_update_problem_testdata_rolls_back_on_failure(monkeypatch):
    connection = _FailingConnection()
    monkeypatch.setattr(
        testdata_services,
        'get_db_connection',
        lambda: connection,
    )

    with pytest.raises(RuntimeError, match='模拟 UPDATE 失败'):
        testdata_services.update_problem_testdata(
            7,
            [{'input': '1', 'output': '2'}],
        )

    assert connection.commit_count == 0
    assert connection.rollback_count == 1
    assert connection.closed is True
    assert connection.cursor_instance.execute_count == 1


class _StateCursor:
    def __init__(self, *, row=None):
        self.row = row
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql, params):
        self.calls.append((sql, params))

    def fetchone(self):
        return self.row


class _StateConnection:
    def __init__(self, cursor):
        self.cursor_instance = cursor
        self.commit_count = 0
        self.rollback_count = 0
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commit_count += 1

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.closed = True


def test_get_problem_testdata_state_preserves_nullable_raw_values(monkeypatch):
    cursor = _StateCursor(row={"testdata": None, "max_score": None})
    connection = _StateConnection(cursor)
    monkeypatch.setattr(
        testdata_services,
        "get_db_connection",
        lambda: connection,
    )

    result = testdata_services.get_problem_testdata_state(7)

    assert result == {"testdata": None, "max_score": None}
    assert cursor.calls[0][1] == (7,)
    assert connection.closed is True


def test_publish_staged_testdata_locks_compares_and_publishes(monkeypatch):
    cursor = _StateCursor(row={"testdata": "old", "max_score": 1})
    connection = _StateConnection(cursor)
    monkeypatch.setattr(
        testdata_services,
        "get_db_connection",
        lambda: connection,
    )

    published = testdata_services.publish_staged_testdata(
        7,
        before_state={"testdata": "old", "max_score": 1},
        testdata=[
            {"input": "1", "output": "2"},
            {"input": "3", "output": "4"},
        ],
    )

    assert published is True
    assert len(cursor.calls) == 2
    select_sql, select_params = cursor.calls[0]
    assert "FOR UPDATE" in select_sql
    assert select_params == (7,)
    update_sql, update_params = cursor.calls[1]
    assert "UPDATE problems SET testdata=%s, max_score=%s" in update_sql
    assert update_params[1:] == (2, 7)
    assert update_params[0] == (
        '[{"input": "1", "output": "2"}, '
        '{"input": "3", "output": "4"}]'
    )
    assert connection.commit_count == 1
    assert connection.rollback_count == 0
    assert connection.closed is True


def test_agent_publish_locks_run_before_problem_and_completes_atomically(
    monkeypatch,
):
    class AgentPublishCursor(_StateCursor):
        def __init__(self):
            super().__init__()
            self.rows = iter([
                {"status": "Running"},
                {"testdata": "old", "max_score": 1},
            ])
            self.rowcount = 0

        def execute(self, sql, params):
            super().execute(sql, params)
            self.rowcount = 1 if "UPDATE agent_task_runs" in sql else 0

        def fetchone(self):
            return next(self.rows)

    cursor = AgentPublishCursor()
    connection = _StateConnection(cursor)
    monkeypatch.setattr(
        testdata_services,
        "get_db_connection",
        lambda: connection,
    )

    published = testdata_services.publish_staged_testdata(
        7,
        before_state={"testdata": "old", "max_score": 1},
        testdata=[{"input": "1", "output": "2"}],
        agent_task_id="task-7",
        agent_completion_message="已发布",
    )

    assert published is True
    assert "FROM agent_task_runs" in cursor.calls[0][0]
    assert "FOR UPDATE" in cursor.calls[0][0]
    assert cursor.calls[0][1] == ("task-7",)
    assert "FROM problems" in cursor.calls[1][0]
    assert "UPDATE problems" in cursor.calls[2][0]
    assert "UPDATE agent_task_runs" in cursor.calls[3][0]
    assert cursor.calls[3][1] == ("已发布", "task-7")
    assert connection.commit_count == 1
    assert connection.rollback_count == 0


def test_agent_publish_stops_when_cancel_wins_task_lock(monkeypatch):
    cursor = _StateCursor(row={"status": "Canceled"})
    connection = _StateConnection(cursor)
    monkeypatch.setattr(
        testdata_services,
        "get_db_connection",
        lambda: connection,
    )

    published = testdata_services.publish_staged_testdata(
        7,
        before_state={"testdata": "old", "max_score": 1},
        testdata=[{"input": "1", "output": "2"}],
        agent_task_id="task-7",
    )

    assert published is False
    assert len(cursor.calls) == 1
    assert "FROM agent_task_runs" in cursor.calls[0][0]
    assert connection.commit_count == 0
    assert connection.rollback_count == 1


def test_publish_staged_testdata_rejects_changed_live_state_without_update(
        monkeypatch):
    cursor = _StateCursor(row={"testdata": "admin-new", "max_score": 8})
    connection = _StateConnection(cursor)
    monkeypatch.setattr(
        testdata_services,
        "get_db_connection",
        lambda: connection,
    )

    published = testdata_services.publish_staged_testdata(
        7,
        before_state={"testdata": "old", "max_score": 1},
        testdata=[{"input": "1", "output": "2"}],
    )

    assert published is False
    assert len(cursor.calls) == 1
    assert "FOR UPDATE" in cursor.calls[0][0]
    assert connection.commit_count == 0
    assert connection.rollback_count == 1
    assert connection.closed is True


def test_publish_staged_testdata_rejects_incomplete_before_state(monkeypatch):
    monkeypatch.setattr(
        testdata_services,
        "get_db_connection",
        lambda: pytest.fail('参数无效时不应连接数据库'),
    )

    with pytest.raises(ValueError, match="before_state"):
        testdata_services.publish_staged_testdata(
            7,
            before_state={"testdata": "old"},
            testdata=[{"input": "1", "output": "2"}],
        )
