"""历史 Judge 多轮输入与原有 trace ID 的对应，不使用数据库或模型。"""

import json
from pathlib import Path

import pytest

from backend.oj_modules.agents.trace_store import _event_storage_id
from scripts import judge_history_trace as history


def _row(**values):
    return {'task_id': 'jd-old-history', 'session_id': 'jd-old-history',
            'judge_kind': 'reverse_answer', 'harness': 'claude_code', **values}


def _write(path, events):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(event, ensure_ascii=False) + '\n' for event in events), encoding='utf-8')
    return path


def _claude(role, text, identifier, **values):
    return {'type': role, 'uuid': identifier, 'sessionId': 'native',
            'message': {'role': role, 'content': [{'type': 'text', 'text': text}]}, **values}


def _claude_path(root, name='reverse_solve_combined.jsonl'):
    return root / '.claude/projects/-workspace' / name


def _event(index):
    return _event_storage_id('jd-old-history', f'history-{index}')


def test_claude_two_real_inputs_have_exact_trace_ids_even_with_identical_replies(tmp_path):
    path = _write(_claude_path(tmp_path), [
        _claude('user', '开始作答', 'u1'), _claude('assistant', '继续处理', 'a1'),
        _claude('user', '立即整理交付物', 'u2'), _claude('assistant', '继续处理', 'a2'),
    ])

    recovered = history.recover_trace_turns(_row(), [path])

    assert [turn['text'] for turn in recovered['turns']] == ['开始作答', '立即整理交付物']
    assert recovered['event_turns'] == {_event(1): 0, _event(2): 1}
    assert recovered['event_signatures'] == {
        _event(1): {'kind': 'assistant', 'text': '继续处理'},
        _event(2): {'kind': 'assistant', 'text': '继续处理'},
    }
    assert recovered['warnings'] == []


def test_tools_follow_their_input_and_ignored_users_do_not_split_turns(tmp_path):
    first = _claude('assistant', '第一轮说明', 'a1')
    first['message']['content'] += [
        {'type': 'thinking', 'thinking': '第一轮思考'},
        {'type': 'tool_use', 'id': 'tool1', 'name': 'Read', 'input': {'file_path': 'problem/README.md'}},
    ]
    path = _write(_claude_path(tmp_path), [
        _claude('user', '开始', 'u1'), first,
        {**_claude('user', '附带文本', 'tool-result'), 'toolUseResult': {'content': 'result'}},
        {**_claude('user', '附带文本', 'tool-content'), 'message': {'role': 'user', 'content': [
            {'type': 'tool_result', 'content': 'result'}, {'type': 'text', 'text': '不是输入'}]}},
        _claude('user', '元消息', 'meta', isMeta=True),
        _claude('user', '压缩摘要', 'compact', isCompactSummary=True),
        _claude('user', '子任务', 'child', isSidechain=True),
        _claude('assistant', '第一轮完成', 'a2'),
        _claude('user', '第二轮', 'u2'), _claude('assistant', '第二轮完成', 'a3'),
    ])

    recovered = history.recover_trace_turns(_row(), [path])

    assert [turn['text'] for turn in recovered['turns']] == ['开始', '第二轮']
    assert recovered['event_turns'] == {**{_event(index): 0 for index in range(1, 5)}, _event(5): 1}


def test_combined_precedence_and_copied_fork_history_keep_original_import_indexes(tmp_path):
    initial = [_claude('user', '第一轮', 'u1'), _claude('assistant', '答一', 'a1')]
    resumed = [_claude('user', '第二轮', 'u2'), _claude('assistant', '答二', 'a2')]
    combined = _write(_claude_path(tmp_path), initial + initial + resumed)
    raw = _write(_claude_path(tmp_path, 'newer-native.jsonl'), initial + resumed)
    # 较新的原生日志不能覆盖旧迁移优先选中的 combined。
    other = _write(_claude_path(tmp_path, 'unrelated.jsonl'), [_claude('assistant', '未被原迁移选中', 'a3')])

    recovered = history.recover_trace_turns(_row(), [raw, combined, other])

    assert [turn['text'] for turn in recovered['turns']] == ['第一轮', '第二轮']
    assert recovered['event_turns'] == {_event(1): 0, _event(2): 1}
    assert len(recovered['turns'][0]['sources']) == 2


def test_pi_user_boundaries_include_tool_result_and_identical_input_text(tmp_path):
    def entry(role, text, identifier):
        return {'type': 'message', 'id': identifier, 'message': {'role': role, 'content': [{'type': 'text', 'text': text}]}}
    path = _write(tmp_path / '.pi/agent/sessions/reverse_solve_combined.jsonl', [
        {'type': 'session', 'version': 3, 'id': 'pi-native'},
        entry('user', '继续', 'u1'), entry('assistant', '答一', 'a1'),
        entry('toolResult', '第一轮工具结果', 'r1'),
        entry('user', '继续', 'u2'), entry('assistant', '答二', 'a2'),
    ])

    recovered = history.recover_trace_turns(_row(harness='pi'), [path])

    assert [turn['text'] for turn in recovered['turns']] == ['继续', '继续']
    assert recovered['event_turns'] == {_event(1): 0, _event(2): 0, _event(3): 1}
    assert history.input_records(path, [])[0]['identity'] == ('pi-native', 'u1')


def test_assistant_only_judge_phases_prove_rounds_without_inventing_prompts(tmp_path):
    path = _write(_claude_path(tmp_path, 'agent_judge_combined.jsonl'), [
        _claude('assistant', '检查结构', 'a1', _trace_phase='setup'),
        _claude('assistant', '结构检查完成', 'a2', _trace_phase='setup'),
        _claude('assistant', '检查规则一', 'a3', _trace_phase='rule_1'),
        _claude('assistant', '总结', 'a4', _trace_phase='final'),
    ])

    recovered = history.recover_trace_turns(_row(judge_kind='agent_judge'), [path])

    assert [turn['phase'] for turn in recovered['turns']] == ['setup', 'rule_1']
    assert [turn['text'] for turn in recovered['turns']] == ['', '']
    assert recovered['event_turns'] == {_event(1): 0, _event(2): 0, _event(3): 1}
    assert '1 条历史轨迹' in recovered['warnings'][0]


@pytest.mark.parametrize('phase', ['final', 'sync', 'rule_unknown', 'single_prompt', None])
def test_sync_or_unknown_phase_is_not_evidence_of_a_sent_input(tmp_path, phase):
    path = _write(_claude_path(tmp_path, 'agent_judge_combined.jsonl'), [
        _claude('assistant', '仅收尾同步的输出', 'a1', _trace_phase=phase),
    ])

    recovered = history.recover_trace_turns(_row(judge_kind='agent_judge'), [path])

    assert recovered['turns'] == []
    assert recovered['event_turns'] == {}


def test_real_user_input_proves_round_even_when_sync_label_is_final(tmp_path):
    path = _write(_claude_path(tmp_path, 'agent_judge_combined.jsonl'), [
        _claude('user', '真实第二次输入', 'u1'),
        _claude('assistant', '对应的回复', 'a1', _trace_phase='final'),
    ])

    recovered = history.recover_trace_turns(_row(judge_kind='agent_judge'), [path])

    assert [turn['text'] for turn in recovered['turns']] == ['真实第二次输入']
    assert recovered['event_turns'] == {_event(1): 0}


def test_explicit_empty_legacy_judge_phase_recovers_single_prompt(tmp_path):
    path = _write(_claude_path(tmp_path, 'agent_judge_combined.jsonl'), [
        _claude('assistant', '审核过程', 'a1', _trace_phase=''),
        _claude('assistant', '审核结束', 'a2', _trace_phase=''),
    ])

    recovered = history.recover_trace_turns(_row(judge_kind='agent_judge'), [path])

    assert [turn['phase'] for turn in recovered['turns']] == ['single_prompt']
    assert recovered['event_turns'] == {_event(1): 0, _event(2): 0}


def test_repeated_same_phase_with_distinct_real_users_remains_two_rounds(tmp_path):
    path = _write(_claude_path(tmp_path), [
        _claude('user', '第一次', 'u1', _trace_phase='rule_1'),
        _claude('assistant', '答一', 'a1', _trace_phase='rule_1'),
        _claude('user', '再试一次', 'u2', _trace_phase='rule_1'),
        _claude('assistant', '答二', 'a2', _trace_phase='rule_1'),
    ])

    recovered = history.recover_trace_turns(_row(judge_kind='agent_judge'), [path])

    assert [turn['text'] for turn in recovered['turns']] == ['第一次', '再试一次']
    assert recovered['event_turns'] == {_event(1): 0, _event(2): 1}


def test_native_event_identity_fills_assistant_only_combined_boundaries(tmp_path):
    combined = _write(_claude_path(tmp_path, 'agent_judge_combined.jsonl'), [
        _claude('assistant', '答一', 'a1', _trace_phase='rule_1'),
        _claude('assistant', '答二', 'a2', _trace_phase='rule_1'),
    ])
    native = _write(_claude_path(tmp_path, 'native.jsonl'), [
        _claude('user', '第一次', 'u1'), _claude('assistant', '答一', 'a1'),
        _claude('user', '再试一次', 'u2'), _claude('assistant', '答二', 'a2'),
    ])

    recovered = history.recover_trace_turns(_row(judge_kind='agent_judge'), [combined, native])

    assert len(recovered['turns']) == 2
    assert recovered['event_turns'] == {_event(1): 0, _event(2): 1}


def test_same_phase_in_distinct_native_sessions_does_not_merge_rounds(tmp_path):
    path = _write(_claude_path(tmp_path, 'agent_judge_combined.jsonl'), [
        _claude('assistant', '答一', 'a1', _trace_phase='rule_1'),
        _claude('assistant', '答二', 'a2', _trace_phase='rule_1', sessionId='resumed-native'),
    ])

    recovered = history.recover_trace_turns(_row(judge_kind='agent_judge'), [path])

    assert len(recovered['turns']) == 2
    assert recovered['event_turns'] == {_event(1): 0, _event(2): 1}


def test_conflicting_native_event_owners_remain_unknown(tmp_path):
    combined = _write(_claude_path(tmp_path), [
        _claude('user', '第一次', 'u1'), _claude('assistant', '同一事件', 'a1'),
    ])
    conflicting = _write(_claude_path(tmp_path, 'native.jsonl'), [
        _claude('user', '第二次', 'u2'), _claude('assistant', '同一事件', 'a1'),
    ])

    recovered = history.recover_trace_turns(_row(), [combined, conflicting])

    assert len(recovered['turns']) == 2
    assert recovered['event_turns'] == {}
    assert '缺少可靠的输入边界' in recovered['warnings'][0]


def test_unknown_output_and_sidechain_never_get_attached_to_a_known_round(tmp_path):
    path = _write(_claude_path(tmp_path), [
        _claude('assistant', '缺失输入的输出', 'a0'),
        _claude('user', '已知输入', 'u1'),
        _claude('assistant', '子任务输出', 'child', isSidechain=True),
        _claude('assistant', '正确输出', 'a1'),
        _claude('assistant', '另一个会话缺少输入', 'a2', sessionId='other-native'),
    ])

    recovered = history.recover_trace_turns(_row(), [path])

    assert len(recovered['turns']) == 1
    assert recovered['event_turns'] == {_event(3): 0}
    assert '3 条历史轨迹' in recovered['warnings'][0]


def test_canonical_is_not_assigned_synthetic_legacy_event_ids(tmp_path):
    path = _write(_claude_path(tmp_path), [_claude('user', '原输入', 'u1'), _claude('assistant', '原输出', 'a1')])
    _write(tmp_path / 'numoj_trace_v1.jsonl', [{'version': 1, 'type': 'numoj_trace', 'sequence': 1,
                                             'event': {'id': 'native-id:text:0', 'kind': 'assistant', 'text': '原输出'}}])

    recovered = history.recover_trace_turns(_row(), [path])

    assert recovered['turns'][0]['text'] == '原输入'
    assert recovered['event_turns'] == {}
    assert '规范轨迹' in recovered['warnings'][0]


def test_canonical_native_message_and_tool_ids_map_to_real_input_boundaries(tmp_path):
    assistant = _claude('assistant', '答一', 'a1')
    assistant['message']['id'] = 'provider-message-1'
    assistant['message']['content'].extend([
        {'type': 'thinking', 'thinking': '检查中'},
        {'type': 'tool_use', 'id': 'tool-1', 'name': 'Bash', 'input': {'command': 'echo 1'}},
    ])
    tool_result = _claude('user', '', 'r1')
    tool_result['message']['content'] = [{'type': 'tool_result', 'tool_use_id': 'tool-1', 'content': '1'}]
    native = _write(_claude_path(tmp_path), [
        _claude('user', '第一轮', 'u1'), assistant, tool_result,
        _claude('user', '第二轮', 'u2'), _claude('assistant', '答二', 'a2'),
    ])
    entries = [
        ('provider-message-1:text:0', 'assistant', '答一'),
        ('provider-message-1:thinking:1', 'thinking', '检查中'),
        ('tool-1:call', 'tool', '{"command":"echo 1"}'),
        ('tool-1:result', 'tool_result', '1'),
        ('a2:text:0', 'assistant', '答二'),
        ('cannot-identify', 'assistant', '相同正文也不能证明归属'),
    ]
    canonical = _write(tmp_path / 'numoj_trace_v1.jsonl', [
        {'type': 'numoj_trace', 'version': 1, 'sequence': index,
         'event': {'id': identity, 'kind': kind, 'text': text}}
        for index, (identity, kind, text) in enumerate(entries, 1)
    ])

    recovered = history.recover_trace_turns(_row(), [native, canonical])

    expected = {_event_storage_id('jd-old-history', identity): (1 if identity == 'a2:text:0' else 0)
                for identity, _kind, _text in entries[:-1]}
    assert recovered['event_turns'] == expected
    assert all(_event(index) not in expected for index in range(1, 6))
    assert '1 条规范轨迹' in recovered['warnings'][0]
    assert recovered['event_signatures'][_event_storage_id('jd-old-history', 'tool-1:result')] == {
        'kind': 'tool_result', 'text': '1',
    }


def test_missing_or_denied_logs_do_not_block_available_inputs(tmp_path, monkeypatch):
    available = _write(_claude_path(tmp_path), [_claude('user', '完整原文\n末尾', 'u1')])
    denied = _write(_claude_path(tmp_path, 'denied.jsonl'), [_claude('user', '不可读', 'u2')])
    available.write_text('broken\n' + available.read_text(), encoding='utf-8')
    original_open = Path.open
    def read(path, *args, **kwargs):
        if path == denied:
            raise PermissionError('EACCES')
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', read)

    recovered = history.recover_trace_turns(_row(), [available, denied, _claude_path(tmp_path, 'missing.jsonl')])

    assert recovered['turns'][0]['text'] == '完整原文\n末尾'
    assert any('无法读取' in warning for warning in recovered['warnings'])
    assert any('无法解析' in warning for warning in recovered['warnings'])


def test_quality_gate_does_not_read_answer_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(history, '_read_events', lambda *_: pytest.fail('质量门禁不能读取作答轨迹'))
    assert history.recover_trace_turns(_row(judge_kind='reverse_quality'), [tmp_path / 'answer.jsonl']) == {
        'turns': [], 'event_turns': {}, 'event_signatures': {}, 'warnings': [],
    }
