"""历史 Judge 导入：系统目录搬运、作答隔离和失败续跑。"""
import json
from pathlib import Path
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



@pytest.fixture
def deployment(monkeypatch, storage):
    monkeypatch.setattr(migration, 'validate_production_config', lambda _: None)
    monkeypatch.setattr(migration, 'read_manifest', lambda _: {'backup_status': 'complete', 'completed_at': 'now', 'prepared': True})
    monkeypatch.setattr(migration, 'validate_manifest_artifact', lambda *_, **__: None)
    report = storage / 'report.json'
    return ['--confirm-writers-stopped', '--backup-manifest', str(storage / 'manifest'),
            '--backup-plan', str(storage / 'plan'), '--report', str(report)], report


def test_agent_workspace_moves_as_one_directory_without_file_prechecks(storage, database, monkeypatch):
    source = storage / 'source'
    names = ['core', ' spaced name \n.m', 'module:part.py', 'back\\slash.bin']
    for name in names:
        _file(source / name).write_bytes(b'\x00\xffORIGINAL\n')
    _file(source / 'folder/nested.txt', 'NESTED')
    (source / 'horizons').symlink_to('missing-target')
    (source / 'directory-link').symlink_to('folder', target_is_directory=True)
    (source / 'hardlink').hardlink_to(source / 'core')
    for method in ('lstat', 'is_symlink'):
        original = getattr(Path, method)
        def checked(path, *args, _original=original, **kwargs):
            if path == source or source in path.parents:
                pytest.fail('搬运旧目录不应逐文件预检查')
            return _original(path, *args, **kwargs)
        monkeypatch.setattr(Path, method, checked)
    original_scandir = migration.os.scandir
    def scandir(path):
        if not isinstance(path, int) and (Path(path) == source or source in Path(path).parents):
            pytest.fail('搬运旧目录不应由 Python 扫描文件')
        return original_scandir(path)
    monkeypatch.setattr(migration.os, 'scandir', scandir)
    result = migration.migrate_one(_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, source)
    output = workspace.get_existing_agent_workspace_path(result['session_id']) / 'historical_workspace'
    assert not source.exists()
    for name in names:
        assert (output / name).read_bytes() == b'\x00\xffORIGINAL\n'
    assert (output / 'horizons').readlink() == Path('missing-target')
    assert (output / 'directory-link').readlink() == Path('folder')
    assert (output / 'folder/nested.txt').read_text() == 'NESTED'
    assert (output / 'hardlink').read_bytes() == (output / 'core').read_bytes()


def test_directory_move_replaces_previous_copy_only_after_transfer(storage):
    source = storage / 'source'
    target = storage / 'existing'
    _file(source / 'new.txt', 'NEW')
    _file(target / 'old.txt', 'OLD')
    missing = []
    migration._transfer_path(source, target, missing, '历史目录', move=True)
    assert missing == [] and not source.exists()
    assert (target / 'new.txt').read_text() == 'NEW'
    assert not (target / 'old.txt').exists()
    assert not (target / source.name).exists()


def test_failed_move_preserves_existing_target(storage):
    source = storage / 'missing-source'
    target = storage / 'existing'
    _file(target / 'old.txt', 'KEEP')
    missing = []
    migration._transfer_path(source, target, missing, '缺失目录', move=True)
    assert len(missing) == 1
    assert (target / 'old.txt').read_text() == 'KEEP'


@pytest.mark.parametrize('fail_first_copy', [False, True])
def test_reverse_answer_is_copied_before_quality_moves_package_and_attempt_is_removed(storage, database, deployment, monkeypatch, fail_first_copy):
    source = storage / 'reverse-workspaces/7/current'
    _file(source / 'package/problem/p.md', 'QUESTION')
    _file(source / 'package/template/a.py', 'TEMPLATE')
    _file(source / 'package/solution/a.py', 'SECRET SOLUTION')
    _file(source / 'package/judge.sh', 'SECRET JUDGE')
    submission = _submission()
    steps = {(7, 'quality_gate'): {'status': 'passed'}, (7, 'agent_answer'): {'status': 'passed'}}
    monkeypatch.setattr(migration, '_rows', lambda: ([submission], steps))
    args, report_path = deployment
    original_run = migration.subprocess.run
    rejected = False
    def run(command, *args, **kwargs):
        nonlocal rejected
        if fail_first_copy and not rejected and str(source / 'package/problem') in command:
            rejected = True
            return SimpleNamespace(returncode=1, stdout=b'', stderr=b'cp: Permission denied')
        return original_run(command, *args, **kwargs)
    monkeypatch.setattr(migration.subprocess, 'run', run)
    assert migration.main(args) == 0
    if fail_first_copy:
        first = json.loads(report_path.read_text())
        assert first['completed'] is True and rejected
        assert (source / 'package/problem/p.md').read_text() == 'QUESTION'
        assert (source / 'package/solution/a.py').read_text() == 'SECRET SOLUTION'
        assert all(item['material_complete'] is False for item in first['sessions'])
        assert migration.main(args) == 0
        assert database.creates == 2
    report = json.loads(report_path.read_text())
    assert report['completed'] is True
    answer = next(sid for sid, session in database.sessions.items() if session['judge_kind'] == 'reverse_answer')
    quality = next(sid for sid, session in database.sessions.items() if session['judge_kind'] == 'reverse_quality')
    answer_root = workspace.get_existing_agent_workspace_path(answer)
    audit_root = workspace.get_existing_agent_workspace_path(quality) / 'audit'
    assert (answer_root / 'problem/p.md').read_text() == 'QUESTION'
    assert (answer_root / 'template/a.py').read_text() == 'TEMPLATE'
    assert not (answer_root / 'solution').exists()
    assert not (answer_root / 'judge.sh').exists()
    assert (audit_root / 'solution/a.py').read_text() == 'SECRET SOLUTION'
    assert not source.exists()


def test_reverse_answer_archive_and_original_upload_are_retained(storage, database):
    source = storage / 'source'
    _file(source / 'package/problem/p.md', 'QUESTION')
    _file(source / 'package/template/a.py', 'TEMPLATE')
    _file(source / 'package/solution/a.py', 'SECRET')
    archive = storage / 'submissions/7/reverse_agent_answers/current.zip'
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, 'w') as zipped:
        zipped.writestr('a.py', 'AI ANSWER')
    uploaded = _file(storage / 'uploaded.zip', 'ORIGINAL UPLOAD')
    before = archive.read_bytes()
    result = migration.migrate_one(_submission(code_path=str(uploaded)), 'reverse_answer', 'current', None, {}, source)
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert (output / 'template/a.py').read_text() == 'AI ANSWER'
    assert not (output / 'solution').exists()
    assert archive.read_bytes() == before and uploaded.read_text() == 'ORIGINAL UPLOAD'


def test_reverse_problem_root_symlink_is_preserved_on_first_and_repeat_copy(storage):
    source = storage / 'source'
    _file(source / 'package/solution/secret.txt', 'SECRET SOLUTION')
    _file(source / 'package/template/a.py', 'TEMPLATE')
    (source / 'package/problem').symlink_to('solution', target_is_directory=True)
    missing = []
    materials = migration._workspace_materials(
        _submission(), 'reverse_answer', 'current', source, storage / 'staging', missing,
    )
    for _ in range(2):
        output, transferred, complete = migration._copy_workspace_materials(
            'public-root-link-history', materials, missing,
        )
        assert complete is True and transferred == 2
        assert (output / 'problem').is_symlink()
        assert (output / 'problem').readlink() == Path('solution')
        assert not (output / 'solution').exists()
        assert not (output / 'problem/secret.txt').exists()
        assert (output / 'template/a.py').read_text() == 'TEMPLATE'
    assert (source / 'package/solution/secret.txt').read_text() == 'SECRET SOLUTION'


def test_removed_workspace_uses_public_upload_material_without_removing_upload(storage, database):
    upload = storage / 'original.zip'
    with zipfile.ZipFile(upload, 'w') as zipped:
        for name, content in [('problem/p.md', 'QUESTION'), ('template/a.py', 'TEMPLATE'), ('solution/a.py', 'SECRET')]:
            zipped.writestr('task/' + name, content)
    result = migration.migrate_one(_submission(code_path=str(upload)), 'reverse_answer', 'current', None, {}, storage / 'removed')
    output = workspace.get_existing_agent_workspace_path(result['session_id'])
    assert (output / 'problem/p.md').read_text() == 'QUESTION'
    assert (output / 'template/a.py').read_text() == 'TEMPLATE'
    assert not (output / 'solution').exists() and upload.exists()
    assert any('从原提交恢复输入' in note for note in result['missing'])


def test_completed_session_moves_leftover_directory_without_reimporting_history(storage, database, monkeypatch):
    source = storage / 'source'
    _file(source / 'code.py', 'ORIGINAL')
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, source)
    first = migration.migrate_one(*args)
    _file(source / 'code.py', 'LEFTOVER DIRECTORY')
    database.configs[first['session_id']].pop('workspace_moved')
    def unexpected(*_args, **_kwargs):
        pytest.fail('已完成会话不应重新导入轨迹或数据库')
    for helper in ('_trace_records', 'create_agent_session', 'upsert_agent_run_snapshot', 'ingest_agent_trace_records'):
        monkeypatch.setattr(migration, helper, unexpected)
    second = migration.migrate_one(*args)
    output = workspace.get_existing_agent_workspace_path(first['session_id'])
    assert second['existing'] is True and not source.exists()
    assert (output / 'historical_workspace/code.py').read_text() == 'LEFTOVER DIRECTORY'
    assert database.configs[first['session_id']]['workspace_moved'] is True


def test_completed_session_without_old_directory_is_skipped(storage, database, monkeypatch):
    source = storage / 'source'
    _file(source / 'code.py', 'ORIGINAL')
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, source)
    first = migration.migrate_one(*args)
    monkeypatch.setattr(migration, '_trace_records', lambda *_: pytest.fail('完成会话不得重读轨迹'))
    second = migration.migrate_one(*args)
    assert second['existing'] is True and second['session_id'] == first['session_id']
    assert database.creates == 1


@pytest.mark.parametrize('kind,attempt,relative,material,output_file', [
    ('agent_judge', 'unknown-workspace-1234567890abcdef', 'agent-workspaces/7/1234567890abcdef', 'code.py', 'historical_workspace/code.py'),
    ('reverse_quality', 'old', 'reverse-workspaces/7/old', 'quality_gate_source/rules.txt', 'audit/rules.txt'),
])
def test_moved_workspace_is_rediscovered_from_history_after_database_interruption(storage, database, monkeypatch, kind, attempt, relative, material, output_file):
    source = storage / relative
    _file(source / material, 'MOVED CONTENT')
    submission = _submission(scoring_mode='agent_judge' if kind == 'agent_judge' else 'reverse_judge')
    def fail(*_args, **_kwargs):
        raise RuntimeError('database disconnected after move')
    with monkeypatch.context() as interrupted:
        interrupted.setattr(migration, 'upsert_agent_run_snapshot', fail)
        with pytest.raises(RuntimeError, match='database disconnected'):
            migration.migrate_one(submission, kind, attempt, None, {}, source)
    sid = next(iter(database.sessions))
    assert 'historical_import_completed' not in database.configs[sid]
    if source.exists():
        source.rmdir()  # 质量材料整目录搬走后，旧 attempt 只剩空壳。
    assert not source.exists()
    submission['historical_sessions'] = [database.sessions[sid]]
    discovered = [row for row in migration._sources(submission, {}) if row[:2] == (kind, attempt)]
    assert len(discovered) == 1 and discovered[0][-1] == source
    resumed = migration.migrate_one(submission, *discovered[0])
    assert resumed['session_id'] == sid and database.creates == 1
    assert resumed['material_complete'] is True
    assert (workspace.get_existing_agent_workspace_path(sid) / output_file).read_text() == 'MOVED CONTENT'
    assert database.sessions[sid]['status'] == 'Completed'


def test_missing_current_attempt_remains_none_and_workspace_only_attempt_is_discovered(storage, database):
    unknown = storage / 'agent-workspaces/7/1234567890abcdef'
    unknown.mkdir(parents=True)
    sources = list(migration._sources(_submission(scoring_mode='agent_judge'), {}))
    assert any(row[1] == 'unknown-workspace-1234567890abcdef' and row[-1] == unknown for row in sources)
    result = migration.migrate_one(_submission(judge_attempt_id=None), 'reverse_answer', 'legacy', None, {}, storage / 'missing')
    assert database.sessions[result['session_id']]['attempt_id'] is None
    assert result['missing']
    next_attempt = _submission(historical_sessions=[database.sessions[result['session_id']]])
    resumed = migration.migrate_one(next_attempt, 'reverse_answer', 'legacy', None, {}, storage / 'missing')
    assert resumed['session_id'] == result['session_id'] and database.creates == 1


def test_existing_import_rejects_another_submission_identity(storage, database):
    source = storage / 'source'
    _file(source / 'code.py')
    args = (_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', None, {}, source)
    result = migration.migrate_one(*args)
    database.sessions[result['session_id']]['requested_by'] = 'another-user'
    with pytest.raises(RuntimeError, match='历史会话 ID'):
        migration.migrate_one(*args)


def test_canonical_trace_keeps_early_history_and_deduplicates(storage, database):
    trace = storage / 'trace'
    events = [{'version': 1, 'type': 'numoj_trace', 'sequence': index + 1,
               'event': {'id': f'event-{index}', 'kind': 'assistant', 'text': f'text-{index}'}} for index in range(350)]
    original = _file(trace / 'numoj_trace_v1.jsonl', '\n'.join(json.dumps(row) for row in [*events, events[0]]))
    result = migration.migrate_one(_submission(scoring_mode='agent_judge'), 'agent_judge', 'current', trace, {}, storage / 'missing')
    rows = database.traces[result['session_id']]
    assert len(rows) == 350 and rows[0]['text'] == 'text-0' and rows[-1]['text'] == 'text-349'
    assert original.exists()


@pytest.mark.parametrize('harness', ['claude', 'pi'])
def test_legacy_trace_keeps_more_than_240_events(storage, harness):
    trace = storage / 'trace'
    source = trace / ('.claude/projects/-workspace/agent_judge_combined.jsonl' if harness == 'claude' else 'pi_reverse_solve.jsonl')
    events = [{'type': 'assistant' if harness == 'claude' else 'message', 'uuid': f'e-{i}',
               'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': f'answer-{i}'}]}} for i in range(350)]
    _file(source, '\n'.join(json.dumps(row) for row in events))
    missing = []
    rows, _ = migration._trace_records('history-task', trace, storage / 'staging', missing)
    assert len(rows) == 350 and rows[0]['event']['text'] == 'answer-0'


def test_migration_requires_stopped_writers_and_completed_backup(monkeypatch, storage):
    with pytest.raises(SystemExit):
        migration.main([])
    monkeypatch.setattr(migration, 'validate_production_config', lambda _: None)
    monkeypatch.setattr(migration, 'read_manifest', lambda _: {'backup_status': 'failed'})
    monkeypatch.setattr(migration, '_rows', lambda: pytest.fail('未完成备份时不能读取业务库'))
    with pytest.raises(ValueError, match='备份'):
        migration.main(['--confirm-writers-stopped', '--backup-manifest', str(storage / 'manifest'),
                        '--backup-plan', str(storage / 'plan'), '--report', str(storage / 'report')])


def test_database_interruption_writes_incomplete_report(deployment, monkeypatch, capsys):
    monkeypatch.setattr(migration, '_rows', lambda: ([_submission()], {}))
    monkeypatch.setattr(migration, '_sources', lambda *_: iter([('reverse_answer', 'current', None, {}, Path('/unused'))]))
    def fail(*_args, **_kwargs):
        raise RuntimeError('database disconnected')
    monkeypatch.setattr(migration, 'migrate_one', fail)
    args, report_path = deployment
    with pytest.raises(RuntimeError, match='database disconnected'):
        migration.main(args)
    report = json.loads(report_path.read_text())
    assert report['completed'] is False
    assert report['interrupted_at'] == {'submission_id': 7, 'judge_kind': 'reverse_answer', 'attempt': 'current'}
    assert report_path.stat().st_mode & 0o777 == 0o600
    assert '提交 1/1' in capsys.readouterr().out
