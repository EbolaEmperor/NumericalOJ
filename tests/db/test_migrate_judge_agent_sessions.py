"""一次性数据库上的历史 Judge 搬迁、完成跳过与访问权限。"""
import json
import shutil

from backend.oj_modules.agents import sessions, workspace
from backend.oj_modules.infrastructure.mysql import get_db_connection
from scripts import migrate_judge_agent_sessions as migration
import pytest


def test_history_import_roundtrip_is_idempotent_and_permission_scoped(monkeypatch, tmp_path):
    monkeypatch.setattr(workspace, 'AGENT_WORKSPACE_ROOT', tmp_path / 'generic')
    monkeypatch.setattr(migration, 'submission_dir', lambda sid: str(tmp_path / 'submissions' / str(sid)))
    trace = tmp_path / 'trace'
    trace.mkdir()
    (trace / 'numoj_trace_v1.jsonl').write_text(json.dumps({
        'version': 1, 'type': 'numoj_trace', 'sequence': 1,
        'event': {'id': 'original-event', 'kind': 'assistant', 'text': '历史模型回复'},
    }) + '\n')
    source = tmp_path / 'source'
    for directory, filename, content in [('package/problem', 'p.md', 'QUESTION'), ('package/template', 'a.py', 'AI ANSWER'), ('package/solution', 'a.py', 'SECRET'), ('quality_gate_source', 'judge.sh', 'SECRET GATE')]:
        path = source / directory / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    submission = {'id': 73, 'competition_id': 7, 'username': 'admin', 'judge_attempt_id': None}
    ids = []
    for kind in ('agent_judge', 'reverse_quality', 'reverse_answer'):
        legacy = tmp_path / kind
        shutil.copytree(source, legacy)
        args = (submission, kind, 'legacy', trace if kind != 'reverse_quality' else None, {'status': 'passed'}, legacy)
        result = migration.migrate_one(*args)
        with monkeypatch.context() as completed:
            def rescan(*_args, **_kwargs):
                pytest.fail('已完成历史会话不得再次扫描材料或轨迹')
            completed.setattr(migration, '_workspace_materials', rescan)
            completed.setattr(migration, '_trace_records', rescan)
            replay = migration.migrate_one(*args)
        sid = result['session_id']
        ids.append(sid)
        assert replay['existing'] is True
        session = sessions.get_agent_session(sid)
        assert session['status'] == 'Completed' and session['judge_kind'] == kind
        assert session['attempt_id'] is None
        assert len(sessions.get_agent_session_turns(sid)) == 1
        assert sessions.get_judge_session_for_attempt(73, None, kind)['session_id'] == sid
        assert sessions.can_view_agent_session(session, username='admin', is_admin=True)
        assert not sessions.can_view_agent_session(session, username='another-user')
        assert sessions.can_view_agent_session(session, username='admin') is (kind == 'reverse_answer')
        runtime = sessions.get_agent_session_runtime_config(sid)
        assert runtime['historical_import_completed'] == migration.MIGRATION_VERSION
        assert runtime['transferred_paths'] > 0 and runtime['workspace_moved']
        assert 'workspace_manifest' not in runtime and 'trace_sha256' not in runtime
        assert sessions.claim_next_agent_session_message(sid) is None
        if kind == 'agent_judge':
            assert not legacy.exists()
        elif kind == 'reverse_quality':
            assert not (legacy / 'quality_gate_source').exists()
        if kind == 'reverse_answer':
            output = workspace.get_existing_agent_workspace_path(sid)
            assert (output / 'template/a.py').read_text() == 'AI ANSWER'
            assert not (output / 'solution').exists()
            assert not (output / 'quality_gate_source').exists()
    assert sessions.get_agent_sessions_paginated()[0] == []
    assert {row['session_id'] for row in sessions.get_agent_sessions_paginated(judge_only=True)[0]} == set(ids)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS n FROM agent_usage_ledger')
            assert cursor.fetchone()['n'] == 0
            cursor.execute('SELECT COUNT(*) AS n FROM agent_trace_events')
            assert cursor.fetchone()['n'] == 2
            cursor.execute("SELECT COUNT(*) AS n FROM agent_session_messages WHERE status='sent'")
            assert cursor.fetchone()['n'] == 3
    finally:
        conn.close()
