import zipfile

import pytest

from oj_modules.problems import testdata as testdata_services


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
        'testdata': [{'input': '1 2', 'output': '3'}],
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
        'testdata': [{'input': '4', 'output': '16'}],
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


def test_import_testdata_rejects_declared_total_over_policy(monkeypatch, tmp_path):
    archive = tmp_path / 'large.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('1.in', b'1234')
        zf.writestr('1.out', b'5678')

    monkeypatch.setattr(testdata_services, 'TESTDATA_ZIP_MAX_FILE_BYTES', 8)
    monkeypatch.setattr(testdata_services, 'TESTDATA_ZIP_MAX_TOTAL_BYTES', 7)

    with pytest.raises(testdata_services.TestdataValidationError, match='总大小'):
        testdata_services.import_testdata_zip(7, archive, tmp_path / 'out')


def test_import_testdata_enforces_configured_text_total_limit(monkeypatch, tmp_path):
    archive = tmp_path / 'text-large.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('1.in', b'1234')
        zf.writestr('1.out', b'5678')

    destination = tmp_path / 'out'
    monkeypatch.setattr(testdata_services, 'TESTDATA_TEXT_MAX_TOTAL_BYTES', 7)
    monkeypatch.setattr(
        testdata_services,
        'update_problem_testdata',
        lambda *_args, **_kwargs: pytest.fail('文本超限时不应更新数据库'),
    )

    with pytest.raises(
        testdata_services.TestdataValidationError,
        match=r'\.in/\.out 文本总大小超过限制（上限 7 字节）',
    ):
        testdata_services.import_testdata_zip(7, archive, destination)

    assert not destination.exists()


def test_text_size_limit_is_checked_before_reading_any_file(monkeypatch, tmp_path):
    destination = tmp_path / 'extracted'
    destination.mkdir()
    (destination / '1.in').write_bytes(b'1234')
    (destination / '1.out').write_bytes(b'5678')

    def _unexpected_open(*_args, **_kwargs):
        pytest.fail('超限时不应读取任何测试数据文本')

    monkeypatch.setattr(testdata_services, 'open', _unexpected_open, raising=False)

    with pytest.raises(
        testdata_services.TestdataValidationError,
        match=r'\.in/\.out 文本总大小超过限制（上限 7 字节）',
    ):
        testdata_services.load_testdata_from_extracted_dir(
            destination,
            max_total_text_bytes=7,
        )


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
