"""历史 Judge 导入：原样复制、作答隔离、失败继续与完成标记幂等。"""
import errno
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import zipfile

import pytest

from scripts import migrate_judge_agent_sessions as migration
from backend.oj_modules.agents import workspace
from backend.oj_modules.agents.trace_store import _normalize_canonical_record, _normalized_token_usage


def _submission(**patch):
    return {'id': 7, 'competition_id': 3, 'username': 'student', 'scoring_mode': 'reverse_judge', 'judge_attempt_id': 'current', **patch}


def _file(path, content='content'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


@pytest.fixture
def storage(monkeypatch, tmp_path):
    monkeypatch.setattr(workspace, 'AGENT_WORKSPACE_ROOT', tmp_path / 'generic')
    monkeypatch.setattr(migration, 'submission_dir', lambda sid: str(tmp_path / 'submissions' / str(sid)))
    monkeypatch.setattr(migration.config, 'AGENT_JUDGE_WORKSPACE_ROOT', str(tmp_path / 'agent-workspaces'))
    monkeypatch.setattr(migration.config, 'REVERSE_JUDGE_WORKSPACE_ROOT', str(tmp_path / 'reverse-workspaces'))
    return tmp_path


@pytest.fixture
def database(monkeypatch, storage):
    data = SimpleNamespace(sessions={}, configs={}, traces={}, usage={}, creates=0)
    def create(**kwargs):
        data.creates += 1
        sid = kwargs['session_id']
        data.sessions[sid] = {**kwargs, 'status': 'Pending'}
        data.configs[sid] = kwargs['runtime_config']
    def complete(state):
        sid = state['session_id']
        data.sessions[sid]['status'] = state['status']
    def ingest(sid, records, **_kwargs):
        data.traces[sid] = [_normalize_canonical_record(sid, row) for row in records]
    class Connection:
        def cursor(self): return self
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def close(self): pass
        def commit(self): pass
        def execute(self, sql, params):
            if sql.startswith('UPDATE agent_sessions SET runtime_config_json'):
                data.configs[params[1]] = json.loads(params[0])
                self.result = []
            else: raise AssertionError(sql)
        def fetchone(self): return self.result[0] if self.result else None
        def fetchall(self): return self.result
    monkeypatch.setattr(migration, 'get_db_connection', Connection)
    monkeypatch.setattr(migration, 'create_agent_session', create)
    monkeypatch.setattr(migration, 'get_agent_session', lambda sid: data.sessions.get(sid))
    monkeypatch.setattr(migration, 'get_agent_session_runtime_config', lambda sid: dict(data.configs.get(sid, {})))
    monkeypatch.setattr(migration, 'upsert_agent_run_snapshot', complete)
    monkeypatch.setattr(migration, 'ingest_agent_trace_records', ingest)
    monkeypatch.setattr(migration, 'save_agent_trace_token_usage', lambda sid, usage: data.usage.update({sid: _normalized_token_usage(usage)}))
    return data


def test_reverse_answer_copies_only_public_material_and_current_answer(storage, database):
    root = storage / 'reverse-workspaces/7/current'
    _file(root / 'package/problem/prompt.md', 'PUBLIC QUESTION')
    _file(root / 'package/template/main.py', 'TEMPLATE')
    _file(root / 'package/solution/main.py', 'SECRET SOLUTION')
    _file(root / 'package/judge.sh', 'SECRET JUDGE')
    _file(root / 'quality_gate_source/rules.txt', 'SECRET GATE')
    archive = storage / 'submissions/7/reverse_agent_answers/current.zip'
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, 'w') as zipped:
        zipped.writestr('main.py', 'AI ANSWER')
    before = archive.read_bytes()
    result = migration.migrate_one(_submission(), 'reverse_answer', 'current', None, {'status': 'passed'}, root)
    sid = result['session_id']
    output = workspace.get_existing_agent_workspace_path(sid)
    assert {path.relative_to(output).as_posix() for path in output.rglob('*') if path.is_file()} == {'problem/prompt.md', 'template/main.py', 'historical_record.json'}
    assert (output / 'template/main.py').read_text() == 'AI ANSWER'
    assert 'SECRET' not in ''.join(path.read_text() for path in output.rglob('*') if path.is_file())
    assert archive.read_bytes() == before
    assert (root / 'package/solution/main.py').read_text() == 'SECRET SOLUTION'
    assert json.loads((output / 'historical_record.json').read_text())['result']['status'] == 'passed'
    assert database.configs[sid]['historical_import_completed'] == 1


def test_existing_completed_import_skips_material_and_trace_scans(storage, database, monkeypatch):
    root = storage / 'agent-workspaces/7/source'
    _file(root / 'submission/code.py', 'ORIGINAL')
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {'status': 'Accepted'}, root)
    first = migration.migrate_one(*args)
    def unexpected(*_args, **_kwargs):
        pytest.fail('已完成会话不应重新扫描材料或轨迹')
    for helper in ('_workspace_files', '_trace_records', '_regular_files', '_open_source'):
        monkeypatch.setattr(migration, helper, unexpected)
    second = migration.migrate_one(*args)
    assert database.creates == 1
    assert second['existing'] is True
    assert first['trace_events'] == 0
    assert second['session_id'] == first['session_id']


def test_existing_import_rejects_another_submission_identity(storage, database):
    root = storage / 'empty'
    root.mkdir()
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, root)
    result = migration.migrate_one(*args)
    sid = result['session_id']
    database.sessions[sid]['requested_by'] = 'another-student'
    with pytest.raises(RuntimeError, match='历史会话 ID'):
        migration.migrate_one(*args)


def test_canonical_trace_imports_all_events_including_early_history_and_deduplicates(storage, database):
    trace = storage / 'trace'
    events = [{'version': 1, 'type': 'numoj_trace', 'sequence': index + 1, 'event': {'id': f'event-{index}', 'kind': 'assistant', 'text': f'text-{index}'}} for index in range(350)]
    _file(trace / 'numoj_trace_v1.jsonl', '\n'.join(json.dumps(row) for row in [*events, events[0]]))
    root = storage / 'empty'
    root.mkdir()
    result = migration.migrate_one(_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', trace, {}, root)
    persisted = database.traces[result['session_id']]
    assert len(persisted) == 350
    assert persisted[0]['text'] == 'text-0'
    assert persisted[-1]['text'] == 'text-349'
    assert result['trace_events'] == 350


@pytest.mark.parametrize('harness', ['claude', 'pi'])
def test_legacy_trace_migrates_more_than_old_240_event_window(storage, harness):
    trace = storage / 'trace'
    source = trace / ('.claude/projects/-workspace/agent_judge_combined.jsonl' if harness == 'claude' else 'pi_reverse_solve.jsonl')
    events = [{'type': 'assistant' if harness == 'claude' else 'message', 'uuid': f'e-{i}', 'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': f'answer-{i}'}]}} for i in range(350)]
    _file(source, '\n'.join(json.dumps(row) for row in events))
    missing = []
    rows, _ = migration._trace_records('history-task', trace, storage / 'staging', missing)
    assert len(rows) == 350
    assert rows[0]['event']['text'] == 'answer-0'
    assert any('全量扫描' in item for item in missing)


def test_source_discovery_includes_workspace_only_attempts_and_correct_reverse_step(storage):
    unknown = storage / 'agent-workspaces/7/1234567890abcdef'
    unknown.mkdir(parents=True)
    sources = list(migration._sources(_submission(scoring_mode='agent_judge'), {}))
    assert any(source[1] == 'unknown-workspace-1234567890abcdef' and source[-1] == unknown for source in sources)
    (storage / 'reverse-workspaces/7/old/quality_gate_source').mkdir(parents=True)
    steps = {(7, 'agent_answer'): {'status': 'passed', 'result_json': '{"message":"correct answer step"}'}}
    sources = list(migration._sources(_submission(), steps))
    assert next(row for row in sources if row[0:2] == ('reverse_answer', 'current'))[3] == steps[(7, 'agent_answer')]
    assert ('reverse_quality', 'old') in [row[:2] for row in sources]
    assert ('reverse_answer', 'old') in [row[:2] for row in sources]


def test_missing_attempt_id_remains_none_for_current_lookup(storage, database):
    root = storage / 'empty'
    root.mkdir()
    result = migration.migrate_one(_submission(judge_attempt_id=None), 'reverse_answer', 'legacy', None, {}, root)
    assert database.sessions[result['session_id']]['attempt_id'] is None
    assert result['missing']


def test_source_symlinks_and_hardlinks_are_not_imported(storage):
    outside = _file(storage / 'outside/secret.txt', 'SECRET')
    root = storage / 'source'
    root.mkdir()
    (root / 'linked').symlink_to(outside)
    (root / 'hardlinked').hardlink_to(outside)
    files = migration._regular_files(root, 'public', [])
    assert files == {}
    (storage / 'parent-link').symlink_to(root, target_is_directory=True)
    assert migration._regular_files(storage / 'parent-link/child', 'public', []) == {}
    with pytest.raises((OSError, ValueError)):
        migration._open_source(root / 'linked')


def test_migration_requires_stop_ack_and_verified_backup_before_db(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        migration.main([])
    called = []
    monkeypatch.setattr(migration, 'validate_production_config', lambda _: called.append('env'))
    monkeypatch.setattr(migration, 'read_manifest', lambda _: {'backup_status': 'failed'})
    monkeypatch.setattr(migration, '_rows', lambda: pytest.fail('未完成备份时不能连接数据库'))
    args = ['--confirm-writers-stopped', '--backup-manifest', str(tmp_path / 'manifest'), '--backup-plan', str(tmp_path / 'plan'), '--report', str(tmp_path / 'report')]
    with pytest.raises(ValueError, match='备份'):
        migration.main(args)
    assert called == ['env']
    monkeypatch.setattr(migration, 'read_manifest', lambda _: {'backup_status': 'complete', 'completed_at': 'now', 'gzip_crc_verified': True})
    def reject(*_args, **_kwargs): raise ValueError('SHA-256 mismatch')
    monkeypatch.setattr(migration, 'validate_manifest_artifact', reject)
    with pytest.raises(ValueError, match='SHA-256'):
        migration.main(args)



def test_missing_runtime_workspace_recovers_only_public_input_from_original_upload(storage, database):
    original = storage / 'original.zip'
    with zipfile.ZipFile(original, 'w') as zipped:
        zipped.writestr('task/problem/p.md', 'QUESTION')
        zipped.writestr('task/template/a.py', 'TEMPLATE')
        zipped.writestr('task/solution/a.py', 'SECRET SOLUTION')
        zipped.writestr('task/judge.sh', 'SECRET SCRIPT')
    result = migration.migrate_one(_submission(code_path=str(original)), 'reverse_answer', 'current', None, {}, storage / 'removed-runtime')
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert (output / 'problem/p.md').read_text() == 'QUESTION'
    assert (output / 'template/a.py').read_text() == 'TEMPLATE'
    assert not (output / 'solution').exists()
    assert any('从原提交恢复输入' in item for item in result['missing'])
    assert original.exists()


@pytest.mark.parametrize('denied', [False, True])
def test_core_file_is_imported_when_readable_or_reported_missing_when_denied(storage, database, monkeypatch, denied):
    root = storage / 'source'
    core = _file(root / 'core', 'EXISTING CORE')
    _file(root / 'main.py', 'SOURCE')
    original_copy = migration.shutil.copyfile
    def copyfile(source, target):
        if denied and source == core:
            raise PermissionError(errno.EACCES, 'Permission denied', str(source))
        return original_copy(source, target)
    monkeypatch.setattr(migration.shutil, 'copyfile', copyfile)
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, root)
    result = migration.migrate_one(*args)
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert (output / 'historical_workspace/core').exists() is not denied
    assert (output / 'historical_workspace/main.py').read_text() == 'SOURCE'
    record = json.loads((output / 'historical_record.json').read_text())
    assert any('/core' in item for item in record['missing']) is denied
    assert record['missing'] == result['missing']
    assert core.read_text() == 'EXISTING CORE'
    assert migration.migrate_one(*args)['existing'] is True
    assert database.creates == 1


def test_unreadable_directory_is_recorded_instead_of_silently_disappearing(storage, monkeypatch):
    root = storage / 'source'
    _file(root / 'public.txt')
    _file(root / 'private/secret.txt')
    original_scandir = migration.os.scandir
    def scandir(path):
        if str(path) == str(root / 'private'):
            raise PermissionError(errno.EACCES, 'Permission denied', str(path))
        return original_scandir(path)
    monkeypatch.setattr(migration.os, 'scandir', scandir)
    missing = []
    assert set(migration._regular_files(root, 'audit', missing)) == {'audit/public.txt'}
    assert any('PermissionError' in item and 'audit/private' in item for item in missing)


@pytest.mark.parametrize('kind', ['agent_judge', 'reverse_answer'])
def test_missing_original_upload_still_archives_results_with_explicit_missing_note(storage, database, kind):
    result = migration.migrate_one(
        _submission(code_path=str(storage / 'deleted.zip')), kind, 'current', None,
        {'status': 'passed'}, storage / 'removed-runtime',
    )
    assert any('文件已不存在' in item and '原提交' in item for item in result['missing'])
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert [path.name for path in output.iterdir() if path.is_file()] == ['historical_record.json']
    assert database.configs[result['session_id']]['historical_import_completed'] == 1


def test_unreadable_trace_and_corrupt_answer_archive_are_reported(storage, database, monkeypatch):
    root = storage / 'reverse'
    _file(root / 'package/problem/p.md', 'QUESTION')
    _file(root / 'package/template/a.py', 'TEMPLATE')
    trace = storage / 'trace'
    unreadable = _file(trace / 'numoj_trace_v1.jsonl', 'PRIVATE TRACE')
    _file(storage / 'submissions/7/reverse_agent_answers/current.zip', 'CORRUPT ZIP')
    original_copy = migration.shutil.copyfile
    def copyfile(source, target):
        if source == unreadable:
            raise PermissionError(errno.EACCES, 'Permission denied', str(source))
        return original_copy(source, target)
    monkeypatch.setattr(migration.shutil, 'copyfile', copyfile)
    result = migration.migrate_one(_submission(), 'reverse_answer', 'current', trace, {}, root)
    assert result['trace_events'] == 0
    assert any('trace/numoj_trace_v1.jsonl' in item for item in result['missing'])
    assert any('历史归档无法安全解包' in item for item in result['missing'])
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert (output / 'template/a.py').read_text() == 'TEMPLATE'


def test_migration_logs_progress_and_reports_database_interruption(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(migration, 'validate_production_config', lambda _: None)
    monkeypatch.setattr(migration, 'read_manifest', lambda _: {'backup_status': 'complete', 'completed_at': 'now', 'prepared': True})
    monkeypatch.setattr(migration, 'validate_manifest_artifact', lambda *_, **__: None)
    monkeypatch.setattr(migration, '_rows', lambda: ([_submission()], {}))
    def sources(submission, steps, missing):
        missing.append('无法枚举历史目录：unreadable')
        yield 'reverse_answer', 'current', None, {}, tmp_path
    monkeypatch.setattr(migration, '_sources', sources)
    def fail(*_):
        raise RuntimeError('database disconnected')
    monkeypatch.setattr(migration, 'migrate_one', fail)
    report = tmp_path / 'report.json'
    with pytest.raises(RuntimeError, match='database disconnected'):
        migration.main(['--confirm-writers-stopped', '--backup-manifest', str(tmp_path / 'manifest'),
                        '--backup-plan', str(tmp_path / 'plan'), '--report', str(report)])
    saved = json.loads(report.read_text())
    assert saved['completed'] is False
    assert saved['interrupted_at'] == {'submission_id': 7, 'judge_kind': 'reverse_answer', 'attempt': 'current'}
    assert saved['discovery_missing'] == ['无法枚举历史目录：unreadable']
    assert report.stat().st_mode & 0o777 == 0o600
    log = capsys.readouterr().out
    assert '数据库备份核验通过' in log and '提交 1/1' in log


@pytest.mark.parametrize('failure_code', [errno.EIO, errno.ENOSPC])
def test_copy_failure_keeps_existing_file_and_continues_with_later_files(storage, monkeypatch, failure_code):
    first = _file(storage / 'source/a.txt', 'UNREADABLE OR UNWRITABLE')
    second = _file(storage / 'source/b.txt', 'SECOND COPY')
    output = workspace.ensure_agent_workspace('copy-history')
    _file(output / 'historical_workspace/a.txt', 'EXISTING COPY')
    original_copy = migration.shutil.copyfile
    def copyfile(source, target):
        if source == first:
            Path(target).write_text('INCOMPLETE COPY')
            raise OSError(failure_code, 'simulated copy failure', str(source))
        return original_copy(source, target)
    monkeypatch.setattr(migration.shutil, 'copyfile', copyfile)
    missing = []
    root, copied = migration._copy_workspace_files(
        'copy-history', {'historical_workspace/a.txt': first, 'historical_workspace/b.txt': second}, missing,
    )
    assert copied == 1 and root == output
    assert (root / 'historical_workspace/a.txt').read_text() == 'EXISTING COPY'
    assert (root / 'historical_workspace/b.txt').read_text() == 'SECOND COPY'
    assert first.read_text() == 'UNREADABLE OR UNWRITABLE'
    assert len(missing) == 1 and 'historical_workspace/a.txt' in missing[0]
    assert not list(root.rglob('.history-copy-*'))


def test_historical_copy_preserves_names_without_public_upload_normalization(storage, database):
    source = storage / 'source'
    names = [' spaced name \n.m', 'module:part.py', 'back\\slash.bin']
    for name in names:
        path = _file(source / name)
        path.write_bytes(b'\x00\xffUNCHANGED\n')
    result = migration.migrate_one(
        _submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, source,
    )
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert result['copied_files'] == len(names)
    for name in names:
        assert (output / 'historical_workspace' / name).read_bytes() == (source / name).read_bytes()


def test_non_utf8_filename_reaches_copy_and_destination_unchanged(storage, monkeypatch):
    # macOS 无法创建 surrogateescape 文件名；只替代源枚举和最终 rename 系统调用。
    root = storage / 'source'
    root.mkdir()
    raw_name = 'old-\udcff.m'
    source = root / raw_name
    original_lstat = Path.lstat
    def lstat(path, *args, **kwargs):
        if path == source:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1)
        return original_lstat(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(migration.os, 'walk', lambda *_args, **_kwargs: iter([(str(root), [], [raw_name])]))
    missing = []
    files = migration._regular_files(root, 'historical_workspace', missing)
    assert files == {f'historical_workspace/{raw_name}': source}
    sources, destinations = [], []
    def copyfile(original, temporary):
        sources.append(original)
        Path(temporary).write_bytes(b'ORIGINAL BYTES')
    original_replace = migration.os.replace
    def replace(temporary, target):
        if Path(target).name == raw_name:
            destinations.append(Path(target))
            Path(temporary).unlink()
        else:
            original_replace(temporary, target)
    monkeypatch.setattr(migration.shutil, 'copyfile', copyfile)
    monkeypatch.setattr(migration.os, 'replace', replace)
    output, copied = migration._copy_workspace_files('raw-name-history', files, missing)
    assert copied == 1 and missing == []
    assert sources == [source]
    assert destinations == [output / 'historical_workspace' / raw_name]
