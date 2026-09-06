"""历史 Judge 导入：原材料只读、作答隔离、完整轨迹、幂等核验与部署前置。"""
import hashlib
import errno
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from scripts import migrate_judge_agent_sessions as migration
from backend.oj_modules.agents import workspace


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
    data = SimpleNamespace(sessions={}, configs={}, traces={}, usage={}, turns={}, messages={}, creates=0, ledgers=0)
    def create(**kwargs):
        data.creates += 1
        sid = kwargs['session_id']
        data.sessions[sid] = {**kwargs, 'status': 'Pending'}
        data.configs[sid] = kwargs['runtime_config']
        data.messages[sid] = [{'status': 'dispatching'}]
        data.turns[sid] = {'status': 'Pending'}
    def complete(state):
        sid = state['session_id']
        data.sessions[sid]['status'] = state['status']
        data.turns[sid]['status'] = state['status']
        data.messages[sid] = [{'status': 'sent'}]
    def ingest(sid, records, **_kwargs):
        data.traces[sid] = [migration._normalize_canonical_record(sid, row) for row in records]
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
            elif 'agent_usage_ledger' in sql: self.result = [{'n': data.ledgers}]
            elif 'agent_session_turns' in sql: self.result = [data.turns[params[0]]]
            elif 'agent_session_messages' in sql: self.result = data.messages[params[0]]
            elif 'agent_trace_events' in sql: self.result = data.traces.get(params[0], [])
            else: raise AssertionError(sql)
        def fetchone(self): return self.result[0] if self.result else None
        def fetchall(self): return self.result
    monkeypatch.setattr(migration, 'get_db_connection', Connection)
    monkeypatch.setattr(migration, 'create_agent_session', create)
    monkeypatch.setattr(migration, 'get_agent_session', lambda sid: data.sessions.get(sid))
    monkeypatch.setattr(migration, 'get_agent_session_runtime_config', lambda sid: dict(data.configs.get(sid, {})))
    monkeypatch.setattr(migration, 'upsert_agent_run_snapshot', complete)
    monkeypatch.setattr(migration, 'ingest_agent_trace_records', ingest)
    monkeypatch.setattr(migration, 'save_agent_trace_token_usage', lambda sid, usage: data.usage.update({sid: migration._normalized_token_usage(usage)}))
    monkeypatch.setattr(migration, 'get_agent_trace_token_usage', lambda sid: data.usage.get(sid))
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
    before = hashlib.sha256(archive.read_bytes()).hexdigest()
    result = migration.migrate_one(_submission(), 'reverse_answer', 'current', None, {'status': 'passed'}, root)
    sid = result['session_id']
    manifest = result['workspace_manifest']
    assert set(manifest) == {'problem/prompt.md', 'template/main.py', 'historical_record.json'}
    output = workspace.get_existing_agent_workspace_path(sid)
    assert (output / 'template/main.py').read_text() == 'AI ANSWER'
    assert 'SECRET' not in ''.join(path.read_text() for path in output.rglob('*') if path.is_file())
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == before
    assert (root / 'package/solution/main.py').read_text() == 'SECRET SOLUTION'
    assert json.loads((output / 'historical_record.json').read_text())['result']['status'] == 'passed'
    assert database.configs[sid]['historical_import_completed'] == 1


def test_existing_completed_import_is_reverified_and_detects_tampered_workspace(storage, database):
    root = storage / 'agent-workspaces/7/source'
    _file(root / 'submission/code.py', 'ORIGINAL')
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {'status': 'Accepted'}, root)
    first = migration.migrate_one(*args)
    second = migration.migrate_one(*args)
    assert database.creates == 1
    assert second['existing'] is True
    assert first['trace_events'] == 0
    output = workspace.get_existing_agent_workspace_path(first['session_id'])
    (output / 'historical_workspace/submission/code.py').write_text('TAMPERED')
    with pytest.raises(RuntimeError, match='副本核验失败'):
        migration.migrate_one(*args)


def test_verification_checks_trace_content_outbox_and_no_duplicate_billing(storage, database):
    root = storage / 'empty'
    root.mkdir()
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, root)
    result = migration.migrate_one(*args)
    sid = result['session_id']
    database.traces[sid] = [{'kind': 'assistant', 'text': 'unexpected'}]
    with pytest.raises(RuntimeError, match='轨迹持久化'):
        migration.migrate_one(*args)
    database.traces[sid] = []
    database.messages[sid] = [{'status': 'dispatching'}]
    with pytest.raises(RuntimeError, match='outbox'):
        migration.migrate_one(*args)
    database.messages[sid] = [{'status': 'sent'}]
    database.ledgers = 1
    with pytest.raises(RuntimeError, match='费用流水'):
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
    original_open = migration._open_source
    def open_source(path):
        if denied and path == core:
            raise PermissionError(errno.EACCES, 'Permission denied', str(path))
        return original_open(path)
    monkeypatch.setattr(migration, '_open_source', open_source)
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, root)
    result = migration.migrate_one(*args)
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert ('historical_workspace/core' in result['workspace_manifest']) is not denied
    assert (output / 'historical_workspace/main.py').read_text() == 'SOURCE'
    record = json.loads((output / 'historical_record.json').read_text())
    assert any('权限不足' in item and '/core' in item for item in record['missing']) is denied
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
    assert set(result['workspace_manifest']) == {'historical_record.json'}
    assert database.configs[result['session_id']]['historical_import_completed'] == 1


def test_unreadable_trace_and_corrupt_answer_archive_are_reported(storage, database, monkeypatch):
    root = storage / 'reverse'
    _file(root / 'package/problem/p.md', 'QUESTION')
    _file(root / 'package/template/a.py', 'TEMPLATE')
    trace = storage / 'trace'
    unreadable = _file(trace / 'numoj_trace_v1.jsonl', 'PRIVATE TRACE')
    _file(storage / 'submissions/7/reverse_agent_answers/current.zip', 'CORRUPT ZIP')
    original_open = migration._open_source
    def open_source(path):
        if path == unreadable:
            raise PermissionError(errno.EACCES, 'Permission denied', str(path))
        return original_open(path)
    monkeypatch.setattr(migration, '_open_source', open_source)
    result = migration.migrate_one(_submission(), 'reverse_answer', 'current', trace, {}, root)
    assert result['trace_events'] == 0
    assert any('trace/numoj_trace_v1.jsonl' in item for item in result['missing'])
    assert any('历史归档无法安全解包' in item for item in result['missing'])
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert (output / 'template/a.py').read_text() == 'TEMPLATE'


def test_interrupted_injection_preserves_copy_when_source_becomes_unreadable(storage, database, monkeypatch):
    root = storage / 'source'
    first_source = _file(root / 'a.txt', 'FIRST COPY')
    _file(root / 'b.txt', 'SECOND COPY')
    inject = migration.inject_agent_workspace_files
    def interrupt(sid, files, **kwargs):
        inject(sid, dict(list(files.items())[:1]))
        raise OSError(errno.ENOSPC, 'simulated target disk full')
    monkeypatch.setattr(migration, 'inject_agent_workspace_files', interrupt)
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, root)
    with pytest.raises(OSError, match='disk full'):
        migration.migrate_one(*args)
    monkeypatch.setattr(migration, 'inject_agent_workspace_files', inject)
    original_open = migration._open_source
    def open_source(path):
        if path == first_source:
            raise PermissionError(errno.EACCES, 'Permission denied', str(path))
        return original_open(path)
    monkeypatch.setattr(migration, '_open_source', open_source)
    result = migration.migrate_one(*args)
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert (output / 'historical_workspace/a.txt').read_text() == 'FIRST COPY'
    assert (output / 'historical_workspace/b.txt').read_text() == 'SECOND COPY'
    assert any('保留上次未完成导入的副本' in item for item in result['missing'])
    assert migration.migrate_one(*args)['existing'] is True
    assert database.creates == 1


def test_migration_logs_progress_and_reports_interrupted_submission(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(migration, 'validate_production_config', lambda _: None)
    monkeypatch.setattr(migration, 'read_manifest', lambda _: {'backup_status': 'complete', 'completed_at': 'now', 'prepared': True})
    monkeypatch.setattr(migration, 'validate_manifest_artifact', lambda *_, **__: None)
    monkeypatch.setattr(migration, '_rows', lambda: ([_submission()], {}))
    def sources(submission, steps, missing):
        missing.append('无法枚举历史目录：unreadable')
        yield 'reverse_answer', 'current', None, {}, tmp_path
    monkeypatch.setattr(migration, '_sources', sources)
    def fail(*_):
        raise OSError(errno.ENOSPC, 'target disk full')
    monkeypatch.setattr(migration, 'migrate_one', fail)
    report = tmp_path / 'report.json'
    with pytest.raises(OSError, match='disk full'):
        migration.main(['--confirm-writers-stopped', '--backup-manifest', str(tmp_path / 'manifest'),
                        '--backup-plan', str(tmp_path / 'plan'), '--report', str(report)])
    saved = json.loads(report.read_text())
    assert saved['verified'] is False
    assert saved['interrupted_at'] == {'submission_id': 7, 'judge_kind': 'reverse_answer', 'attempt': 'current'}
    assert saved['discovery_missing'] == ['无法枚举历史目录：unreadable']
    assert report.stat().st_mode & 0o777 == 0o600
    log = capsys.readouterr().out
    assert '数据库备份核验通过' in log and '提交 1/1' in log


def test_source_disk_io_errors_remain_fatal(storage, monkeypatch):
    def broken(_):
        raise OSError(errno.EIO, 'source disk I/O failure')
    monkeypatch.setattr(migration, '_open_source', broken)
    with pytest.raises(OSError, match='I/O failure'):
        migration._available_source(storage / 'source', [], 'source')
