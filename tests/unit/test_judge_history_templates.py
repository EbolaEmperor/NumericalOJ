"""冻结历史正文与有依据的阶段恢复，不能用当前规则制造历史轮次。"""

import hashlib
import json
from pathlib import Path

import pytest

from scripts import judge_history_templates as templates


RESULT_NAME = 'result_' + 'a' * 32 + '.jsonl'
RULE = {'rule_id': 2, 'rule_name': '规则名', 'rule_text': '必须正确运行',
        'value': 5, 'dependencies': [1]}


@pytest.mark.parametrize('function,args,digest', [
    (templates._quoted_single_prompt, ('固定测试比赛',),
     'f0dc8d9ef2930a4082896bd5e7b63986e92e859f88cd0ad90d28b75d98ab1f23'),
    (templates._heredoc_single_prompt, ('固定测试比赛',),
     '1da75d43d188c6e72e83d07507944499a78edbb3e52c63c34040bf31ddec1d30'),
    (templates._random_single_prompt, ('固定测试比赛', RESULT_NAME),
     '69a800705d285ab48003c8d0c39acb6acd305ccd25374376afe7d95bc2a8bc01'),
    (templates._setup_prompt, ('固定测试比赛',),
     'fff9a6ef682325a40a4b174ef705bdab5c8085df8af4740d7b83481f73eb92d2'),
    (templates._rule_prompt, ('固定测试比赛', RULE, RESULT_NAME + '.rule_2.jsonl'),
     '3beae38cb2e376984b06ba2eb1a4600745a1c6312a43312c59aa8e5c9071ed67'),
    (templates._reverse_solve_prompt, (),
     '7c5786e0920b43c7cc87257e6151075c90872ec900a6ca79a0c63c8a7d60faed'),
])
def test_fixed_templates_match_original_git_bytes(function, args, digest):
    # 摘要从各自旧 git 源码执行取得，而不是从现行模板生成。
    assert hashlib.sha256(function(*args).encode()).hexdigest() == digest


def _archive(root, rules=()):
    legacy = root / 'historical_workspace'
    legacy.mkdir(parents=True)
    (legacy / 'rules.json').write_text(json.dumps(list(rules), ensure_ascii=False))
    return legacy


def test_actual_phases_restore_only_executed_rules_in_recorded_order(tmp_path):
    legacy = _archive(tmp_path, [
        {'rule_id': 1, 'rule': '第一项', 'value': 1, 'dependence': []}, RULE,
        {'rule_id': 3, 'rule': '依赖失败被跳过', 'value': 9, 'dependence': [2]},
    ])
    (legacy / RESULT_NAME).write_text('')
    states = [{'phase': phase, 'session_id': phase, 'returncode': 0}
              for phase in ('setup', 'setup', 'rule_1', 'rule_2')]
    (legacy / '.aj_session_state.jsonl').write_text('\n'.join(json.dumps(row) for row in states))
    history = {'result': {'judge_results': [
        {'rule_id': 2, 'raw_result': 'failed'},
        {'rule_id': 3, 'raw_result': None, 'effective_result': 'skipped'},
    ]}}

    outputs = templates.recover_fixed_history_prompts(
        {'judge_kind': 'agent_judge', 'historical_competition_title': '固定测试比赛'},
        tmp_path, history,
    )

    assert [row['phase'] for row in outputs] == ['setup', 'rule_1', 'rule_2']
    assert all(row['actual_phase'] and row['reconstructed'] for row in outputs)
    assert outputs[2]['text'] == templates._rule_prompt('固定测试比赛', RULE, RESULT_NAME + '.rule_2.jsonl')
    assert not outputs[2]['warnings']
    assert 'rule_3' not in ''.join(row['text'] for row in outputs)


@pytest.mark.parametrize('version,builder', [
    ('quoted_report', templates._quoted_single_prompt),
    ('heredoc_report', templates._heredoc_single_prompt),
])
def test_single_versions_retain_original_report_protocol(tmp_path, version, builder):
    legacy = _archive(tmp_path)
    (legacy / '.aj_session_state.json').write_text(json.dumps({'phase': '', 'session_id': 'original-session'}))

    outputs = templates.recover_fixed_history_prompts({
        'judge_kind': 'agent_judge', 'historical_template_version': version,
        'historical_competition_title': '固定测试比赛',
    }, tmp_path)

    assert len(outputs) == 1 and outputs[0]['phase'] == 'single_prompt'
    assert outputs[0]['text'] == builder('固定测试比赛')
    assert outputs[0]['actual_phase'] is True


def test_missing_rule_variables_are_local_markers_and_current_title_is_not_original(tmp_path):
    _archive(tmp_path)

    outputs = templates.recover_fixed_history_prompts(
        {'judge_kind': 'agent_judge', 'competition_title': '后来改的比赛名'},
        tmp_path, phase_records=['rule_9'],
    )

    text = outputs[0]['text']
    assert '后来改的比赛名' not in text
    for marker in ('比赛名称', 'rule_name', 'rule_text', 'value', 'dependence', '随机结果文件名'):
        assert f'[历史{marker}未保留]' in text
    assert '如仍缺依赖，可以继续安装或调整' in text
    assert 'evidence 要写清楚你运行了什么' in text
    assert '- value: 0.0' not in text and '- dependence: []' not in text


def test_result_path_from_phase_record_takes_precedence_over_ambiguous_artifacts(tmp_path):
    legacy = _archive(tmp_path, [RULE])
    for character in ('b', 'c'):
        (legacy / ('result_' + character * 32 + '.jsonl')).write_text('')

    output = templates.recover_fixed_history_prompts(
        {'judge_kind': 'agent_judge'}, tmp_path,
        phase_records=[{'phase': 'rule_2', 'report_path': '/workspace/' + RESULT_NAME + '.rule_2.jsonl'}],
    )[0]

    assert RESULT_NAME + '.rule_2.jsonl' in output['text']
    assert templates.MISSING_RESULT_PATH not in output['text']


def test_no_phase_does_not_make_rules_into_fictional_turns_or_read_student_state(tmp_path):
    legacy = _archive(tmp_path, [RULE])
    student = legacy / 'submission'
    student.mkdir()
    (student / '.aj_session_state.jsonl').write_text('{"phase":"rule_2"}\n')

    outputs = templates.recover_fixed_history_prompts(
        {'judge_kind': 'agent_judge'}, tmp_path,
        {'result': {'judge_results': [{'rule_id': 2, 'raw_result': 'pass'}]}},
    )

    assert len(outputs) == 1
    assert outputs[0]['phase'] == 'unknown' and outputs[0]['actual_phase'] is False
    assert outputs[0]['text'].startswith('历史固定提示词模板（发送轮次记录未保留）')
    assert '请帮我评测参赛者提交的代码' in outputs[0]['text']


def test_reverse_solve_and_finalize_are_separate_original_prompts(tmp_path):
    outputs = templates.recover_fixed_history_prompts(
        {'judge_kind': 'reverse_answer'}, tmp_path,
        phase_records=['reverse_solve', 'reverse_finalize'],
    )

    assert [row['phase'] for row in outputs] == ['reverse_solve', 'reverse_finalize']
    assert outputs[0]['text'] == templates._reverse_solve_prompt()
    assert outputs[1]['text'] == templates.REVERSE_FORCE_FINALIZE_PROMPT
    assert '都请停下你的工作' not in outputs[0]['text']
    assert templates.recover_fixed_history_prompts({'judge_kind': 'reverse_answer'}, tmp_path) == []
    assert templates.recover_fixed_history_prompts({'judge_kind': 'reverse_quality'}, tmp_path) == []


def test_reverse_abort_resume_does_not_repeat_initial_prompt(tmp_path):
    outputs = templates.recover_fixed_history_prompts(
        {'judge_kind': 'reverse_answer'}, tmp_path,
        phase_records=[
            {'phase': 'reverse_solve', 'session_id': 'native', 'resume_session_id': ''},
            {'phase': 'reverse_solve', 'session_id': 'native', 'resume_session_id': ''},
            {'phase': 'reverse_solve', 'session_id': 'native', 'resume_session_id': 'native'},
        ],
    )

    assert len(outputs) == 2
    assert outputs[0]['text'] == templates._reverse_solve_prompt()
    assert outputs[1]['text'] == templates.REVERSE_RETRY_PROMPT


def test_unreadable_rules_and_bad_state_line_do_not_block_saved_setup(monkeypatch, tmp_path):
    legacy = _archive(tmp_path)
    (legacy / '.aj_session_state.jsonl').write_text('bad json\n{"phase":"setup"}\n')
    original = Path.read_text

    def read(path, *args, **kwargs):
        if path.name == 'rules.json':
            raise PermissionError('permission denied')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', read)
    outputs = templates.recover_fixed_history_prompts({'judge_kind': 'agent_judge'}, tmp_path)
    assert [row['phase'] for row in outputs] == ['setup']
    assert '请先完成评测前置准备' in outputs[0]['text']


def _quality_history(*, agentic=False, count=5):
    result = {'criteria_sha256': hashlib.sha256('归档标准'.encode()).hexdigest(),
              'passed': True, 'source_file_count': count}
    if agentic:
        result['agentic_review'] = True
    else:
        result.update(reviewed_file_count=count, source_truncated=False)
    return {'result': {'status': 'passed', 'result_json': json.dumps(result)}}


def _quality_audit(root):
    audit = root / 'audit'
    for name, data in {
        'template/main.py': b'print("ready")\n',
        'solution/main.py': b'print(42)\n',
        'problem/题目.md': '# 题面\n最后一行\n'.encode(),
        'judge.sh': b'#!/bin/sh\nexit 0\n',
        'extra.txt': b'metadata\n',
    }.items():
        path = audit / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return audit


def _quality_row(criteria='归档标准'):
    return {'judge_kind': 'reverse_quality', 'reverse_quality_gate_prompt': criteria}


def test_direct_quality_recovers_one_api_request_with_both_original_roles(tmp_path):
    _quality_audit(tmp_path)

    output = templates.recover_quality_history_prompt(_quality_row(), tmp_path, _quality_history())

    system, user = output['text'].split('### system\n\n', 1)[1].split('\n\n### user\n\n', 1)
    # 分别从 8eafc06^ 的原 system 构造与 snapshot/request 算法执行取得。
    assert hashlib.sha256(system.encode()).hexdigest() == '45f1c1fbd37a058045af5980602602a2c08a2cdf78bbc3eafe1530d8cf5877f2'
    assert hashlib.sha256(user.encode()).hexdigest() == '5b9b0f418139dc1fde475a10140c6a1703d2d2b78a3d7e1f62ed89d917efd18b'
    assert output['phase'] == 'quality_gate' and output['actual_phase'] is True
    assert '同一轮' in output['text'] and '/evidence' not in output['text']
    assert json.loads(user)['package']['files'][0]['path'] == 'judge.sh'


def test_agentic_quality_uses_original_cli_template_without_snapshot_request(tmp_path):
    output = templates.recover_quality_history_prompt(
        _quality_row(), tmp_path, _quality_history(agentic=True),
    )

    # 从 2d68dae^ 的原函数取得，避免把 direct 的“只输出”混入 CLI 模板。
    assert hashlib.sha256(output['text'].encode()).hexdigest() == '779647229e80ff765e4a001504991b1b221b795d40b2ee4287951153e62a5ef4'
    assert '/evidence' in output['text'] and '### system' not in output['text']
    assert output['warnings'] == []


@pytest.mark.parametrize('agentic', [False, True])
def test_missing_quality_criteria_keeps_fixed_task_with_local_marker(tmp_path, agentic):
    _quality_audit(tmp_path)
    output = templates.recover_quality_history_prompt(
        _quality_row('后来修改的标准'), tmp_path, _quality_history(agentic=agentic),
    )

    assert templates.MISSING_CRITERIA in output['text']
    assert '后来修改的标准' not in output['text']
    assert '管理员审核标准是唯一的判定依据' in output['text']
    assert output['actual_phase'] is True and output['warnings']


def test_direct_quality_missing_audit_does_not_read_answer_or_student_logs(tmp_path):
    (tmp_path / 'template').mkdir()
    (tmp_path / 'template/main.py').write_text('later answer must not enter original request')
    (tmp_path / 'problem').mkdir()
    (tmp_path / 'problem/prompt.txt').write_text('student supplied prompt')
    output = templates.recover_quality_history_prompt(_quality_row(), tmp_path, _quality_history())

    assert '历史文件路径或内容未保留' in output['text']
    assert 'later answer' not in output['text'] and 'student supplied prompt' not in output['text']
    assert '审核以下反向评测题目包快照' in output['text']


def test_direct_quality_unreadable_file_and_walk_error_do_not_drop_other_inputs(monkeypatch, tmp_path):
    audit = _quality_audit(tmp_path)
    original_read = Path.read_bytes
    original_walk = templates.os.walk

    def read(path):
        if path.name == 'judge.sh':
            raise PermissionError('unreadable file')
        return original_read(path)

    def walk(path, **kwargs):
        kwargs['onerror'](PermissionError('unreadable directory'))
        return original_walk(path, **kwargs)

    monkeypatch.setattr(Path, 'read_bytes', read)
    monkeypatch.setattr(templates.os, 'walk', walk)
    output = templates.recover_quality_history_prompt(_quality_row(), tmp_path, _quality_history())
    payload = json.loads(output['text'].split('### user\n\n', 1)[1])['package']

    assert payload['files'][0]['path'] == 'judge.sh'
    assert payload['files'][0]['content'] == '[历史文件内容未保留]'
    assert any(isinstance(item, dict) and item['content'] == 'print(42)\n' for item in payload['files'])
    assert any('unreadable directory' in warning for warning in output['warnings'])
    assert str(audit) in output['sources']


@pytest.mark.parametrize('history', [
    {}, {'result': {'status': 'error', 'error_message': '端点不可用'}},
    {'result': {'status': 'passed', 'result_json': {'skipped': True}}},
])
def test_quality_without_request_evidence_does_not_invent_a_turn(tmp_path, history):
    _quality_audit(tmp_path)
    assert templates.recover_quality_history_prompt(_quality_row(), tmp_path, history) is None


def test_quality_reply_uses_only_saved_model_fields_and_prefers_original_text(tmp_path):
    result = json.loads(_quality_history(agentic=True)['result']['result_json'])
    model_result = {
        'passed': False, 'summary': '缺少运行说明',
        'violations': [{'rule': '提供运行说明', 'reason': '没有入口说明', 'evidence': []}],
    }
    result.update(model_result)
    history = {'result': {'result_json': result}}

    output = templates.recover_quality_history_prompt(_quality_row(), tmp_path, history)
    label, encoded = output['conclusion'].split('\n\n', 1)
    assert label == '历史审核回复（原始格式未保存）'
    assert json.loads(encoded) == model_result
    assert 'criteria_sha256' not in encoded and 'agentic_review' not in encoded

    result['response_text'] = '```json\n' + json.dumps(model_result, ensure_ascii=False) + '\n```\n'
    output = templates.recover_quality_history_prompt(_quality_row(), tmp_path, history)
    assert output['conclusion'] == result['response_text']


@pytest.mark.parametrize('invalid', [
    {'passed': 1}, {'summary': ''}, {'violations': None}, {'violations': ['not an object']},
])
def test_quality_reply_does_not_fill_missing_or_invalid_model_fields(tmp_path, invalid):
    result = json.loads(_quality_history(agentic=True)['result']['result_json'])
    history = {'result': {'result_json': result}}
    assert templates.recover_quality_history_prompt(_quality_row(), tmp_path, history)['conclusion'] == ''
    result.update(passed=True, summary='通过', violations=[])
    result.update(invalid)
    assert templates.recover_quality_history_prompt(_quality_row(), tmp_path, history)['conclusion'] == ''
