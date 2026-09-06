"""历史 Judge 输入恢复：只采纳原文或有归档摘要佐证的旧门禁模板。"""

import hashlib
import json
from pathlib import Path

import pytest

from scripts import backfill_judge_history_prompts as backfill


def _row(**changes):
    return {
        'session_id': 'jd-history', 'submission_id': 7, 'attempt_id': 'current',
        'judge_kind': 'reverse_answer', 'harness': 'claude_code',
        'turn_prompt': backfill.PLACEHOLDER, 'message_prompt': backfill.PLACEHOLDER,
        **changes,
    }


def _jsonl(path, events):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(event, ensure_ascii=False) + '\n' for event in events))
    return path


def _claude(text, identity='u1', **extra):
    return {'type': 'user', 'uuid': identity, 'sessionId': 'native-session',
            'message': {'role': 'user', 'content': text}, **extra}


@pytest.fixture
def paths(monkeypatch, tmp_path):
    submissions = tmp_path / 'submissions'
    generic = tmp_path / 'generic'
    monkeypatch.setattr(backfill, 'submission_dir', lambda sid: str(submissions / str(sid)))
    monkeypatch.setattr(backfill, 'AGENT_WORKSPACE_ROOT', generic)
    return submissions / '7', generic


def test_claude_keeps_real_inputs_and_excludes_tool_feedback_and_internal_events(tmp_path):
    path = _jsonl(tmp_path / 'native.jsonl', [
        _claude('首条真实输入'),
        _claude([{'type': 'text', 'text': '继续处理'}, {'type': 'image', 'data': 'not text'}], 'u2'),
        _claude([{'type': 'tool_result', 'content': '工具结果'}], 'tool1'),
        _claude([{'type': 'tool_result', 'content': '工具结果'},
                 {'type': 'text', 'text': '工具反馈附带文本'}], 'tool2'),
        _claude('子 Agent 输入', 'child', isSidechain=True),
        _claude('元消息', 'meta', isMeta=True),
        _claude('压缩摘要', 'compact', isCompactSummary=True),
        {'type': 'assistant', 'message': {'role': 'assistant', 'content': '模型输出'}},
    ])

    records = backfill._input_records(path, [])

    assert [record['text'] for record in records] == ['首条真实输入', '继续处理']


def test_pi_reads_user_messages_without_treating_tool_results_as_prompts(tmp_path):
    path = _jsonl(tmp_path / 'pi.jsonl', [
        {'type': 'session', 'id': 'pi-native'},
        {'type': 'message', 'id': 'u1', 'message': {'role': 'user', 'content': [{'type': 'text', 'text': '开始作答'}]}},
        {'type': 'message', 'id': 'tool', 'message': {'role': 'toolResult', 'content': [{'type': 'text', 'text': '执行结果'}]}},
        {'type': 'message', 'id': 'assistant', 'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': '模型输出'}]}},
        {'type': 'message', 'id': 'u2', 'message': {'role': 'user', 'content': '立即整理交付物'}},
    ])

    records = backfill._input_records(path, [])

    assert [record['text'] for record in records] == ['开始作答', '立即整理交付物']
    assert records[0]['identity'] == ('pi-native', 'u1')


def test_native_and_combined_deduplicate_ids_but_keep_repeated_text_from_distinct_inputs(paths):
    submissions, _ = paths
    root = submissions / 'reverse_agent_trace/current/.claude/projects/-workspace'
    events = [_claude('继续', 'u1', timestamp=1), _claude('继续', 'u2', timestamp=2)]
    _jsonl(root / 'native.jsonl', events)
    _jsonl(root / 'reverse_solve_combined.jsonl', events)

    result = backfill.recover_prompt(_row())

    assert result['status'] == 'restored'
    assert result['prompt_count'] == 2
    assert result['text'].count('\n\n继续') == 2


def test_only_corresponding_attempt_logs_are_read_and_student_workspaces_are_ignored(paths):
    submissions, generic = paths
    for kind, trace_name in [('reverse_answer', 'reverse_agent_trace'), ('agent_judge', 'agent_judge_trace')]:
        _jsonl(submissions / trace_name / 'current/.claude/projects/-workspace/native.jsonl', [_claude(kind)])
        _jsonl(submissions / trace_name / 'another/.claude/projects/-workspace/native.jsonl', [_claude('另一轮内容')])
    _jsonl(generic / 'sessions/jd-history/workspace/historical_workspace/submission/.claude/projects/-workspace/native.jsonl', [_claude('学生伪造输入')])

    for kind in ('reverse_answer', 'agent_judge'):
        result = backfill.recover_prompt(_row(judge_kind=kind))
        assert result['text'] == kind
        assert result['prompt_count'] == 1
    assert backfill.recover_prompt(_row(judge_kind='agent_judge', attempt_id='unknown-workspace-submission'))['status'] == 'missing'


def test_quality_gate_never_recovers_from_answer_logs(paths):
    submissions, _ = paths
    _jsonl(submissions / 'reverse_agent_trace/current/.claude/projects/-workspace/native.jsonl', [_claude('这是作答输入')])

    result = backfill.recover_prompt(_row(judge_kind='reverse_quality'))

    assert result['status'] == 'missing'
    assert result['text'] == backfill.MISSING_PROMPT


@pytest.mark.parametrize('archive_state', ['matched', 'changed', 'not_agentic', 'absent'])
def test_quality_gate_requires_archived_agentic_review_and_matching_criteria(paths, archive_state):
    _, generic = paths
    criteria = '题面明确且样例自洽'
    row = _row(judge_kind='reverse_quality', reverse_quality_gate_prompt=f'  {criteria}\n')
    if archive_state != 'absent':
        result = {'agentic_review': archive_state != 'not_agentic',
                  'criteria_sha256': hashlib.sha256(criteria.encode()).hexdigest()}
        historical = generic / 'sessions/jd-history/workspace/historical_record.json'
        historical.parent.mkdir(parents=True)
        historical.write_text(json.dumps({'result': {'result_json': json.dumps(result)}}))
    if archive_state == 'changed':
        row['reverse_quality_gate_prompt'] = '新审核标准'

    recovered = backfill.recover_prompt(row)

    if archive_state == 'matched':
        assert recovered['status'] == 'restored'
        assert recovered['prompt_count'] == 1
        # 冻结统一前 2d68dae^ 的原模板字节；不以当前业务模板作期望值。
        assert hashlib.sha256(recovered['text'].encode()).hexdigest() == '4a09f148c300e9f585976d3b627e7d54d2a4a02399ad1ea5f9b67d717392ee5d'
    else:
        assert recovered['status'] == 'missing'
        assert recovered['prompt_count'] == 0


def test_missing_denied_and_malformed_logs_do_not_block_recoverable_input(paths, monkeypatch):
    submissions, _ = paths
    root = submissions / 'reverse_agent_trace/current/.claude/projects/-workspace'
    denied = _jsonl(root / 'denied.jsonl', [_claude('无法读取的输入')])
    available = _jsonl(root / 'native.jsonl', [_claude('能够恢复的原文')])
    available.write_text('not-json\n' + available.read_text() + '{broken\n')
    original_open = Path.open
    def open_path(path, *args, **kwargs):
        if path == denied:
            raise PermissionError('permission denied')
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', open_path)

    result = backfill.recover_prompt(_row())

    assert result['text'] == '能够恢复的原文'
    assert result['prompt_count'] == 1
    assert any('无法读取' in warning for warning in result['warnings'])
    assert sum('无法解析' in warning for warning in result['warnings']) == 2


def test_multiple_full_prompts_keep_actual_timezone_order_without_truncation(paths):
    submissions, _ = paths
    root = submissions / 'reverse_agent_trace/current/.claude/projects/-workspace'
    first = '完整首轮\n' + '原文。' * 100_000 + '\n末尾内容'
    _jsonl(root / 'later.jsonl', [_claude('第二轮输入', 'u2', timestamp='2026-09-01T01:00:00Z')])
    _jsonl(root / 'earlier.jsonl', [_claude(first, 'u1', timestamp='2026-09-01T08:00:00+08:00')])

    result = backfill.recover_prompt(_row())

    assert result['prompt_count'] == 2
    assert first in result['text']
    assert result['text'].index(first) < result['text'].index('第二轮输入')


def _args(tmp_path):
    return ['--confirm-writers-stopped', '--backup-manifest', str(tmp_path / 'backup.json'),
            '--backup-plan', str(tmp_path / 'plan.json'), '--report', str(tmp_path / 'report.json')]


def _valid_backup(monkeypatch):
    monkeypatch.setattr(backfill, 'validate_production_config', lambda *_: None)
    monkeypatch.setattr(backfill, 'read_manifest', lambda *_: {
        'backup_status': 'complete', 'completed_at': 'now', 'gzip_crc_verified': True})
    monkeypatch.setattr(backfill, 'validate_manifest_artifact', lambda *args, **kwargs: None)


def test_main_validates_backup_artifact_before_database_access(monkeypatch, tmp_path):
    _valid_backup(monkeypatch)
    monkeypatch.setattr(backfill, 'load_candidates', lambda: pytest.fail('备份核验前不能查询数据库'))
    calls = []
    def reject(*args, **kwargs):
        calls.append('backup')
        raise ValueError('backup digest mismatch')
    monkeypatch.setattr(backfill, 'validate_manifest_artifact', reject)

    with pytest.raises(ValueError, match='backup digest mismatch'):
        backfill.main(_args(tmp_path))
    assert calls == ['backup']


def test_completed_report_makes_next_run_skip_database_and_source_scans(monkeypatch, tmp_path):
    _valid_backup(monkeypatch)
    monkeypatch.setattr(backfill, 'load_candidates', lambda: [_row()])
    monkeypatch.setattr(backfill, 'backfill_one', lambda row: {'session_id': row['session_id'], 'status': 'restored'})
    assert backfill.main(_args(tmp_path)) == 0
    report = json.loads((tmp_path / 'report.json').read_text())
    assert report['completed'] is True
    assert report['interrupted_at'] is None
    def unexpected(*args, **kwargs):
        pytest.fail('完成报告存在时不应再次访问数据库、日志或部署配置')
    for name in ('load_candidates', 'backfill_one', '_trace_files', 'validate_production_config'):
        monkeypatch.setattr(backfill, name, unexpected)

    assert backfill.main(_args(tmp_path)) == 0
    assert json.loads((tmp_path / 'report.json').read_text()) == report


def test_interrupted_run_preserves_progress_and_records_current_session(monkeypatch, tmp_path):
    _valid_backup(monkeypatch)
    previous = {'session_id': 'already-done', 'status': 'restored'}
    (tmp_path / 'report.json').write_text(json.dumps({'version': backfill.VERSION, 'completed': False, 'sessions': [previous]}))
    monkeypatch.setattr(backfill, 'load_candidates', lambda: [_row(session_id='first'), _row(session_id='failed')])
    def fill(row):
        if row['session_id'] == 'failed':
            raise RuntimeError('database disconnected')
        return {'session_id': row['session_id'], 'status': 'missing'}
    monkeypatch.setattr(backfill, 'backfill_one', fill)

    with pytest.raises(RuntimeError, match='database disconnected'):
        backfill.main(_args(tmp_path))

    report = json.loads((tmp_path / 'report.json').read_text())
    assert report['completed'] is False
    assert report['interrupted_at'] == 'failed'
    assert report['sessions'] == [previous, {'session_id': 'first', 'status': 'missing'}]
