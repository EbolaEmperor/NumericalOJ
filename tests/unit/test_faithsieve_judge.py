"""Judge 派发不等待、重入身份核验和独立工具失败边界。"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.unit.test_faithsieve_input_transport import decode_input_message

from backend.oj_modules.ai.endpoints import LLMChatResult
from backend.oj_modules.faithsieve import judge


class Tools:
    def __init__(self):
        self.calls = []
        self.numeric_status = 'passed'

    def run(self, operation, payload, **kwargs):
        self.calls.append((operation, payload, kwargs))
        if operation == 'extract':
            target = Path(kwargs['workspace'])
            (target / 'page-1.png').write_bytes(b'\x89PNG\r\n\x1a\nactual rendered pixels')
            return {'page_count': 1, 'pages': [{'page': 1, 'rendered': True, 'image_path': '/workspace/page-1.png'}], 'exit_code': 0}
        return {'exit_code': 0, 'stdout': '实际工具结果', 'stderr': '', 'status': self.numeric_status, 'commands': [['trusted-tool', operation]], 'tool_executed': True}


@pytest.fixture
def environment(tmp_path, monkeypatch):
    sessions, turns, submissions = {}, {}, []
    run = {'attempt_id': 'a' * 32, 'submission_id': 42, 'requested_by': 'admin', 'problem_id': 5, 'harness': 'pi'}
    endpoint = {'id': 7, 'model': 'actual-model', 'revision': 3, 'category': 'omni',
                'protocol': 'openai', 'base_url': 'https://mock.invalid/v1', 'api_key': 'mock-private-key'}
    tools = Tools()
    monkeypatch.setattr(judge, 'get_agent_session', lambda key: sessions.get(key))
    monkeypatch.setattr(judge, 'get_agent_session_turns', lambda key: turns.get(key, []))
    def submit(**kwargs):
        submissions.append(kwargs)
        sid = kwargs['session_id']
        sessions[sid] = {
            'session_id': sid, 'current_task_id': kwargs['task_id'], 'task_kind': 'judge', 'judge_kind': 'faithsieve',
            'attempt_id': kwargs['attempt_id'], 'submission_id': kwargs['submission_id'], 'requested_by': kwargs['requested_by'],
            'competition_id': None, 'harness': kwargs['harness'], 'endpoint_id': endpoint['id'], 'endpoint_model': endpoint['model'],
            'endpoint_revision': endpoint['revision'], 'status': 'Running', 'problem_id': kwargs['problem_id'], 'access_role': 'user',
        }
        turns[sid] = [{'task_id': kwargs['task_id'], 'user_message': kwargs['prompt'], 'status': 'Running'}]
        for path, content in kwargs['files'].items():
            file = tmp_path / 'child' / sid / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(content if isinstance(content, bytes) else content.encode())
        return sessions[sid]
    monkeypatch.setattr(judge, 'submit_judge_turn', submit)
    def open_file(sid, path):
        file = tmp_path / 'child' / sid / path
        return file.open('rb'), {'size': file.stat().st_size}
    monkeypatch.setattr(judge, 'open_agent_workspace_file', open_file)
    agent = judge.FaithSieveJudgeAgent(run=run, endpoint=endpoint, workspace=tmp_path / 'coordinator', tool_runner=tools)
    def finish(sid, *, role='statement-formalizer', status='ok', text='def p : Prop := True', artifact='statement.lean'):
        sessions[sid]['status'] = turns[sid][0]['status'] = 'Completed'
        turns[sid][0].update(harness=run['harness'], endpoint_id=endpoint['id'], endpoint_model=endpoint['model'])
        root = tmp_path / 'child' / sid
        result_file = 'source-result.json' if role == 'source-extractor' else 'result.json'
        (root / result_file).write_text(json.dumps({'status': status, 'artifact': artifact, 'report': '任务结果'}))
        output = root / artifact
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
    return SimpleNamespace(agent=agent, tools=tools, run=run, endpoint=endpoint, sessions=sessions, turns=turns, submissions=submissions, finish=finish, root=tmp_path)


def invoke(agent, **changes):
    arguments = {'role': 'statement-formalizer', 'prompt': '自然条件与结论；搜索 mathlib、写 Lean、编译修订。', 'files': {'problem.md': '完整题面'}, 'expected_result_path': 'result.json', 'timeout_seconds': 600, 'invocation_key': 'role-000001-attempt-1'}
    arguments.update(changes)
    return agent.run_role(**arguments)


def test_submit_returns_pending_immediately_and_reentry_does_not_duplicate(environment):
    env = environment
    for _ in range(3):
        with pytest.raises(judge.FaithSievePending) as raised:
            invoke(env.agent)
        assert raised.value.countdown == 5
    assert len(env.submissions) == 1
    submitted = env.submissions[0]
    assert submitted['project_skill'] is False
    assert submitted['judge_kind'] == 'faithsieve'
    assert len(submitted['session_id']) <= 64
    assert len(submitted['task_id']) <= 64
    assert submitted['timeout_seconds'] == 600
    assert env.tools.calls == []


@pytest.mark.parametrize('result_path', ['result.json', 'faithsieve-work/results/statement.json'])
def test_role_request_has_one_absolute_result_destination_and_checks_that_file(environment, result_path):
    with pytest.raises(judge.FaithSievePending):
        invoke(environment.agent, expected_result_path=result_path)

    instruction = environment.submissions[0]['prompt']
    absolute_path = f'/workspace/{result_path}'
    assert f'结果元数据 JSON 的唯一绝对位置是 {absolute_path}。' in instruction
    assert f'with open({json.dumps(absolute_path)}, encoding="utf-8") as stream:' in instruction
    assert 'result = json.load(stream)' in instruction
    assert 'set(result) == {"status", "artifact", "report"}' in instruction
    assert 'assert result["status"] in [\'inconclusive\', \'ok\']' in instruction
    assert 'artifact 字段仍使用相对于 /workspace 的路径' in instruction
    assert 'report 一律使用中文；原稿转录和原文引用保留原语言。' in instruction
    frozen = json.loads((environment.agent.directory / 'role-000001-attempt-1.json').read_text())
    assert frozen['result_path'] == result_path
    assert frozen['prompt'] == instruction


def test_completed_role_reads_original_files_and_existing_result(environment):
    env = environment
    with pytest.raises(judge.FaithSievePending) as raised:
        invoke(env.agent)
    env.finish(raised.value.session_id)
    result = invoke(env.agent)
    assert result['artifacts']['statement.lean'] == 'def p : Prop := True'
    assert result['execution']['provider'] == 'numoj-agent-judge'
    assert invoke(env.agent) == result
    assert len(env.submissions) == 1


@pytest.mark.parametrize('change', [
    {'prompt': '修改指令'}, {'files': {'problem.md': '不同题面'}}, {'files': {}}, {'timeout_seconds': 900},
])
def test_reentry_rejects_changed_full_request(environment, change):
    with pytest.raises(judge.FaithSievePending):
        invoke(environment.agent)
    with pytest.raises(judge.FaithSieveJudgeError):
        invoke(environment.agent, **change)
    assert len(environment.submissions) == 1


@pytest.mark.parametrize(('field', 'value'), [('harness', 'codex'), ('endpoint_model', 'other'), ('endpoint_revision', 4), ('attempt_id', 'other'), ('current_task_id', 'other'), ('requested_by', 'student')])
def test_metadata_collision_is_rejected_before_reading_result(environment, field, value):
    with pytest.raises(judge.FaithSievePending) as raised:
        invoke(environment.agent)
    environment.sessions[raised.value.session_id][field] = value
    with pytest.raises(judge.FaithSieveJudgeError, match='元数据'):
        invoke(environment.agent)


@pytest.mark.parametrize('status', ['Failed', 'Canceled', 'CleanupFailed', 'Timeout', 'QuotaExhausted'])
def test_failed_terminal_never_returns_role_result(environment, status):
    with pytest.raises(judge.FaithSievePending) as raised:
        invoke(environment.agent)
    environment.sessions[raised.value.session_id]['status'] = status
    with pytest.raises(judge.FaithSieveJudgeError, match='未正常完成'):
        invoke(environment.agent)


def test_wrong_turn_prompt_and_mutated_inputs_are_rejected(environment):
    env = environment
    with pytest.raises(judge.FaithSievePending) as raised:
        invoke(env.agent)
    sid = raised.value.session_id
    original = env.turns[sid][0]['user_message']
    env.turns[sid][0]['user_message'] = '其他任务'
    with pytest.raises(judge.FaithSieveJudgeError, match='轮次'):
        invoke(env.agent)
    env.turns[sid][0]['user_message'] = original
    env.finish(sid)
    (env.root / 'child' / sid / 'problem.md').write_text('Agent篡改题面')
    with pytest.raises(judge.FaithSieveJudgeError, match='修改了输入'):
        invoke(env.agent)


@pytest.mark.parametrize('revision_reason', ['compile', 'semantic'])
def test_real_judge_immutable_inputs_allow_formalizer_revision_and_checkpoint_reentry(environment, monkeypatch, revision_reason):
    """使用真实 adapter 的输入核验，模拟持久 Judge 完成及 Celery 逐阶段重入。"""
    from backend.oj_modules.faithsieve import workflow

    env = environment
    workspace = env.agent.workspace
    obligation = 'faithsieve-work/obligations/E1/E1-O1.md'
    check = 'faithsieve-work/formal/E1-O1-check.md'
    statement = 'faithsieve-work/formal/E1-O1-original-statement.lean'
    previous = 'faithsieve-work/formal/E1-O1-original-previous-statement.lean'
    proof = 'faithsieve-work/formal/E1-O1-original-proof.lean'
    name = '«FaithSieve_E1-O1_original»'
    drafts = [f'def {name} : Prop := True\n#check {name}\n',
              f'def {name} : Prop := True ∧ True\n#check {name}\n']
    semantic_calls = []

    def audit(_endpoint, messages, **options):
        inputs = decode_input_message(messages[1]['content'])['input_files']
        semantic_calls.append(inputs)
        needs_revision = revision_reason == 'semantic' and len(semantic_calls) == 1
        payload = {
            'result': {'status': 'needs_revision' if needs_revision else 'ok',
                       'artifact': 'faithsieve-work/formal/E1-O1-original-semantics.md',
                       'report': '命题需要保留完整合取' if needs_revision else '命题与原义务一致'},
            'artifacts': {'faithsieve-work/formal/E1-O1-original-semantics.md': '独立语义审计记录'},
            'control': {},
        }
        assert options['response_format'] == {'type': 'json_object'}
        assert not {'tools', 'tool_choice'} & set(options)
        return LLMChatResult(text=json.dumps(payload, ensure_ascii=False))

    original_tool = env.tools.run
    first_compile = True

    def tools(operation, payload, **kwargs):
        nonlocal first_compile
        result = original_tool(operation, payload, **kwargs)
        if operation == 'compile' and first_compile:
            first_compile = False
            if revision_reason == 'compile':
                return {**result, 'exit_code': 1, 'stdout': '需要修订 Lean 命题'}
        return result

    monkeypatch.setattr(env.tools, 'run', tools)

    def resumed_workflow():
        engine = workflow.FaithSieveWorkflow(endpoint=env.endpoint, verification_agent=env.agent,
                                            workspace=workspace, chat=audit)
        for path, text in {
            'problem.md': '由 True 得到 True ∧ True。', workflow.SOURCE: '第1页：真命题的合取。',
            obligation: 'E1-O1：证明 True ∧ True，保留合取两项。', check: 'route=lean\n完整命题为 True ∧ True。',
        }.items():
            engine.store.write(path, text)
        engine.store.begin_replay({'problem.md', workflow.SOURCE, obligation, check})
        engine.edge_contexts = {'E1': {
            'edge': {'id': 'E1', 'from': 'N0', 'to': 'N1', 'step_id': 'S1', 'source_text': '真命题的合取。'},
            'parent_state': {'id': 'N0', 'conditions': ['True'], 'goal': 'True ∧ True', 'scope': []},
            'child_state': {'id': 'N1', 'conditions': ['True', 'True ∧ True'], 'goal': 'True ∧ True', 'scope': []},
        }}
        return engine

    for number, expected_role in enumerate(['statement-formalizer', 'statement-formalizer', 'proof-searcher']):
        with pytest.raises(judge.FaithSievePending) as raised:
            resumed_workflow()._verify_lean_branch('E1-O1', obligation, 'original')
        assert raised.value.role == expected_role
        submitted = env.submissions[-1]
        files = submitted['files']
        if number == 0:
            assert statement not in files and previous not in files
            assert f'def {name} : Prop' in submitted['prompt']
        elif number == 1:
            assert statement not in files and files[previous] == drafts[0]
        else:
            assert files[statement] == drafts[1] and previous not in files
        artifact, content, status = (statement, drafts[number], 'ok') if number < 2 else (
            proof, drafts[1] + f'\ntheorem FaithSieveProof : {name} := by trivial\n', 'passed',
        )
        session_id = raised.value.session_id
        child = env.root / 'child' / session_id
        output = child / artifact
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content)
        result_path = child / (
            'faithsieve-work/results/E1-O1-original-statement-formalizer.json' if number < 2 else
            'faithsieve-work/results/E1-O1-original-proof-searcher.json'
        )
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(json.dumps({'status': status, 'artifact': artifact, 'report': '实际工具角色输出'}))
        env.sessions[session_id]['status'] = env.turns[session_id][0]['status'] = 'Completed'
        env.turns[session_id][0].update(harness=env.run['harness'], endpoint_id=env.endpoint['id'], endpoint_model=env.endpoint['model'])

    verified = resumed_workflow()._verify_lean_branch('E1-O1', obligation, 'original')
    assert verified['status'] == 'passed' and verified['proof_compiled'] is True
    assert len(env.submissions) == 3
    assert semantic_calls[-1][statement] == drafts[1]
    assert previous not in semantic_calls[-1]
    assert (env.root / 'child' / env.submissions[-1]['session_id'] / statement).read_text() == drafts[1]


def test_result_symlink_is_rejected_by_safe_workspace_reader(environment, monkeypatch):
    with pytest.raises(judge.FaithSievePending) as raised:
        invoke(environment.agent)
    environment.finish(raised.value.session_id)
    original = judge.open_agent_workspace_file
    def safe_open(sid, path):
        if path == 'result.json':
            raise ValueError('拒绝符号链接')
        return original(sid, path)
    monkeypatch.setattr(judge, 'open_agent_workspace_file', safe_open)
    with pytest.raises(judge.FaithSieveJudgeError, match='安全读取'):
        invoke(environment.agent)


def test_numeric_mismatch_keeps_status_inconclusive_and_records_actual_tool_result(environment):
    env = environment
    with pytest.raises(judge.FaithSievePending) as raised:
        invoke(env.agent, role='numeric-evaluator')
    sid = raised.value.session_id
    env.finish(sid, role='numeric-evaluator', status='passed', text='原断言和解析', artifact='numeric.md')
    (env.root / 'child' / sid / 'result.json.expressions.json').write_text('{"relations":[{"lhs":"1","relation":"eq","rhs":"2"}]}')
    env.tools.numeric_status = 'refuted'
    result = invoke(env.agent, role='numeric-evaluator')
    assert result['result']['status'] == 'inconclusive'
    assert result['execution']['verified'] is True
    assert result['execution']['exit_code'] == 0
    assert result['execution']['commands'] == [['trusted-tool', 'numeric']]
    assert '独立符号复验原始记录' in result['artifacts']['numeric.md']


@pytest.mark.parametrize('budget', [None, 45])
def test_compile_uses_direct_tool_and_preserves_lean_budget_with_cleanup_margin(environment, budget):
    arguments = {} if budget is None else {'timeout_seconds': budget}
    result = environment.agent.compile_lean({'statement.lean': 'import Mathlib'}, 'statement.lean', **arguments)
    assert result['exit_code'] == 0
    assert result['diagnostics'] == '实际工具结果'
    assert environment.submissions == []
    operation, payload, tool_options = environment.tools.calls[0]
    expected_budget = 300 if budget is None else budget
    assert operation == 'compile'
    assert payload == {'path': 'statement.lean', 'timeout_seconds': expected_budget}
    assert tool_options['timeout_seconds'] == expected_budget + 10


def test_source_extraction_persists_rendered_pages_and_does_not_repeat_on_pending(environment):
    env = environment
    for _ in range(3):
        with pytest.raises(judge.FaithSievePending):
            env.agent.extract_submission(b'%PDF-original', problem_text='题面')
    assert [call[0] for call in env.tools.calls] == ['extract']
    assert len(env.submissions) == 1
    assert env.submissions[0]['timeout_seconds'] == judge.SOURCE_TIMEOUT_SECONDS == 1200
    frozen = json.loads((env.agent.directory / 'source-extraction.json').read_text())
    assert frozen['timeout_seconds'] == 1200
    inputs = env.submissions[0]['files']
    assert set(inputs) == {'pages.json', 'source-pages/page-1.png'}
    assert {item['path'] for item in frozen['files']} == set(inputs)
    assert inputs['source-pages/page-1.png'].startswith(b'\x89PNG')
    assert json.loads(inputs['pages.json']) == [{'page': 1, 'rendered': True, 'image_path': 'source-pages/page-1.png'}]
    assert (env.agent.directory / 'source-extraction/rendered/submission.pdf').read_bytes() == b'%PDF-original'
    assert 'pdftotext' not in env.submissions[0]['prompt']
    assert '不要调用 PDF 文本提取或 OCR' in env.submissions[0]['prompt']
    instruction = env.submissions[0]['prompt']
    assert '写入 /workspace/source-result.json。该结果 JSON 与转录工件是两个独立文件。' in instruction
    assert '结果元数据 JSON 的唯一绝对位置是 /workspace/source-result.json。' in instruction
    assert 'with open("/workspace/source-result.json", encoding="utf-8") as stream:' in instruction
    assert 'faithsieve-work/source-result.json' not in instruction
    assert '只确认图像中实际写出的字符，不判断数学正确性，不猜测作者的正确意图' in instruction
    assert '转录只以页清单和原稿图像为依据，不使用题面或其他定义校正原稿' in instruction
    assert '按原图保留全部记号及其位置' in instruction
    assert '不得按预期定义或数学惯例改写原稿' in instruction
    assert '题面只供理解符号' not in instruction
    assert '清晰可辨的符号即使与数学预期冲突或疑似原稿笔误，也必须照原样保留' in instruction
    assert '不得修正；不得仅因此返回 inconclusive' in instruction
    assert '先对相应区域裁剪或放大并用图像工具重新查看' in instruction
    assert '仍无法确定实际字符时才写 `[无法辨认]` 并返回 inconclusive' in instruction
    assert 'report 一律使用中文；原稿转录和原文引用保留原语言。' in instruction
    with pytest.raises(judge.FaithSieveJudgeError, match='重入请求'):
        env.agent.extract_submission(b'%PDF-original', problem_text='题面', timeout_seconds=600)
    assert len(env.submissions) == 1
    with pytest.raises(judge.FaithSieveJudgeError, match='PDF'):
        env.agent.extract_submission(b'%PDF-changed', problem_text='题面')


def test_source_native_request_is_independent_of_problem_context(environment):
    env = environment
    for problem_text in ('题面私有参照 P 与预期定义 A', '另一题面参照 Q 与预期定义 B'):
        with pytest.raises(judge.FaithSievePending):
            env.agent.extract_submission(b'%PDF-original', problem_text=problem_text)
    assert len(env.submissions) == 1
    assert [call[0] for call in env.tools.calls] == ['extract']
    request = env.submissions[0]
    assert 'problem.md' not in request['files']
    assert '题面私有参照' not in request['prompt'] and '另一题面参照' not in request['prompt']
    assert request['problem_id'] == env.run['problem_id']
    assert request['attempt_id'] == env.run['attempt_id']
    assert not (env.root / 'child' / request['session_id'] / 'problem.md').exists()


@pytest.mark.parametrize('status', ['Running', 'Failed', 'Error'])
def test_legacy_source_with_problem_input_cannot_switch_to_blind_request(environment, status):
    env = environment
    with pytest.raises(judge.FaithSievePending) as raised:
        env.agent.extract_submission(b'%PDF-original', problem_text='旧题面')
    frozen_path = env.agent.directory / 'source-extraction.json'
    frozen = json.loads(frozen_path.read_text())
    content = '旧题面'.encode()
    input_path = env.agent.directory / 'source-extraction/inputs/problem.md'
    input_path.write_bytes(content)
    frozen['files'].append({'path': 'problem.md', 'type': 'text', 'size': len(content)})
    frozen_path.write_text(json.dumps(frozen, ensure_ascii=False))
    original = frozen_path.read_bytes()
    env.sessions[raised.value.session_id]['status'] = status
    env.turns[raised.value.session_id][0]['status'] = status
    with pytest.raises(judge.FaithSieveJudgeError, match='重入请求'):
        env.agent.extract_submission(b'%PDF-original', problem_text='旧题面')
    assert frozen_path.read_bytes() == original
    assert input_path.read_bytes() == content
    assert len(env.submissions) == 1
    assert [call[0] for call in env.tools.calls] == ['extract']


def test_source_result_in_artifact_directory_is_not_accepted_as_root_metadata(environment):
    env = environment
    with pytest.raises(judge.FaithSievePending) as raised:
        env.agent.extract_submission(b'%PDF-original', problem_text='题面')
    sid = raised.value.session_id
    env.finish(sid, role='source-extractor', status='ok', text='## 第 1 页\n\nx = y', artifact='faithsieve-work/source/submission.md')
    root = env.root / 'child' / sid
    (root / 'source-result.json').rename(root / 'faithsieve-work/source-result.json')

    with pytest.raises(judge.FaithSieveJudgeError, match='结果文件无法安全读取'):
        env.agent.extract_submission(b'%PDF-original', problem_text='题面')
    assert len(env.submissions) == 1


@pytest.mark.parametrize('changes', [
    {'page_count': 2}, {'page_count': True}, {'exit_code': 1},
    {'pages': [{'page': 1, 'rendered': False}]}, {'pages': [{'page': True, 'rendered': True}]},
])
def test_incomplete_rendering_never_reaches_source_agent(environment, monkeypatch, changes):
    env = environment
    original = env.tools.run
    def malformed(operation, payload, **kwargs):
        return {**original(operation, payload, **kwargs), **changes}
    monkeypatch.setattr(env.tools, 'run', malformed)
    with pytest.raises(judge.FaithSieveJudgeError, match='PDF'):
        env.agent.extract_submission(b'%PDF-original', problem_text='题面')
    assert env.submissions == []


def test_legacy_machine_extracted_text_cannot_enter_image_input(environment, monkeypatch):
    env = environment
    original = env.tools.run
    def legacy_result(operation, payload, **kwargs):
        result = original(operation, payload, **kwargs)
        return {**result, 'text': '乱码或丢失公式', 'report': '未经图像核对的旧 OCR',
                'pages': [{**page, 'text': '旧逐页提取内容'} for page in result['pages']]}
    monkeypatch.setattr(env.tools, 'run', legacy_result)
    with pytest.raises(judge.FaithSievePending):
        env.agent.extract_submission(b'%PDF-original', problem_text='题面')
    inputs = env.submissions[0]['files']
    assert set(inputs) == {'pages.json', 'source-pages/page-1.png'}
    assert '乱码' not in inputs['pages.json'] and 'text' not in inputs['pages.json']


@pytest.mark.parametrize('actual_image', [False, True])
def test_source_ok_requires_real_successful_image_tool_result(environment, monkeypatch, actual_image):
    env = environment
    with pytest.raises(judge.FaithSievePending) as raised:
        env.agent.extract_submission(b'%PDF-original', problem_text='题面')
    env.finish(raised.value.session_id, role='source-extractor', status='ok', text='## 第 1 页\n\nx = y', artifact='faithsieve-work/source/submission.md')
    trace = env.root / 'trusted-trace'
    trace.mkdir()
    monkeypatch.setattr(judge, 'agent_run_trace_dir', lambda _tid: trace)
    records = [
        {'kind': 'tool', 'id': 'read1:call', 'meta': 'read', 'text': '{"path":"source-pages/page-1.png"}'},
        {'kind': 'tool_result', 'id': 'read1:result', 'text': '{"type":"image","data":"actual pixels"}' if actual_image else '我看到了图片'},
    ]
    (trace / 'numoj_trace_v1.jsonl').write_text('\n'.join(json.dumps({'type': 'numoj_trace', 'version': 1, 'event': event}) for event in records))
    result = env.agent.extract_submission(b'%PDF-original', problem_text='题面')
    assert result['status'] == ('ok' if actual_image else 'inconclusive')
    assert result['execution']['image_verified'] is actual_image


def test_text_node_cannot_claim_to_have_visually_checked_source(environment):
    environment.agent.endpoint['category'] = 'text'
    result = environment.agent.extract_submission(b'%PDF-original')
    assert result['status'] == 'inconclusive'
    assert '全模态' in result['report']
    assert environment.submissions == []
    assert environment.tools.calls == []


@pytest.mark.parametrize(('failed_second', 'native_ids', 'expected'), [
    (False, True, {1, 2}), (True, True, {1}), (False, False, set()),
])
def test_parallel_image_calls_pair_native_ids_even_when_results_arrive_out_of_order(environment, monkeypatch, failed_second, native_ids, expected):
    env = environment
    trace = env.root / 'trusted-trace'
    trace.mkdir()
    monkeypatch.setattr(judge, 'agent_run_trace_dir', lambda _tid: trace)
    events = [
        {'kind': 'tool', 'id': 'first:call', 'meta': 'read', 'text': '{"path":"source-pages/page-1.png"}'},
        {'kind': 'tool', 'id': 'second:call', 'meta': 'read', 'text': '{"path":"source-pages/page-2.png"}'},
        {'kind': 'tool_result', 'id': 'second:result', 'is_error': failed_second, 'text': '{"type":"image","data":"page2"}'},
        {'kind': 'tool_result', 'id': 'first:result', 'text': '{"type":"image","data":"page1"}'},
        {'kind': 'tool', 'id': 'repeat:call', 'meta': 'read', 'text': '{"path":"source-pages/page-1.png"}'},
        {'kind': 'tool_result', 'id': 'repeat:result', 'text': '{"type":"image","data":"page1 repeated"}'},
    ]
    if not native_ids:
        for event in events:
            event.pop('id')
    (trace / 'numoj_trace_v1.jsonl').write_text('\n'.join(json.dumps({'type': 'numoj_trace', 'version': 1, 'event': event}) for event in events))
    assert env.agent._viewed_source_pages('stable-task') == expected


def test_completed_turn_actual_endpoint_mismatch_is_rejected(environment):
    env = environment
    with pytest.raises(judge.FaithSievePending) as raised:
        invoke(env.agent)
    env.finish(raised.value.session_id)
    env.turns[raised.value.session_id][0]['endpoint_model'] = 'different-runtime-model'
    with pytest.raises(judge.FaithSieveJudgeError, match='实际执行参数'):
        invoke(env.agent)


def test_cancel_pending_uses_manifest_frozen_metadata_with_minimal_endpoint(environment, monkeypatch):
    env = environment
    with pytest.raises(judge.FaithSievePending) as raised:
        invoke(env.agent)
    from backend.oj_modules.tasks.agent import control
    canceled = []
    monkeypatch.setattr(control, 'build_agent_run_terminator', lambda _app: lambda tid: canceled.append(tid) or {'canceled': True, 'errors': []})
    adapter = judge.FaithSieveJudgeAgent(run=env.run, endpoint={'id': 7}, workspace=env.agent.workspace, tool_runner=env.tools)
    adapter.cancel_pending()
    assert canceled == [raised.value.task_id]
    assert env.tools.calls == []


def test_direct_docker_has_only_workspace_writable_and_always_confirms_cleanup(tmp_path, monkeypatch):
    calls, removals = [], []
    class Process:
        returncode = 0
        def __init__(self, args, **kwargs):
            calls.append(args)
        def poll(self):
            return 0
        def wait(self, timeout):
            return 0
    monkeypatch.setattr(judge.subprocess, 'Popen', Process)
    monkeypatch.setattr(judge.sandbox, '_communicate_bounded', lambda *args, **kwargs: (b'{"protocol":"faithsieve-tools-v1","exit_code":0,"status":"passed"}', b'', False, False))
    monkeypatch.setattr(judge.sandbox, '_force_remove_container', removals.append)
    runner = judge.DockerFaithSieveTools(tmp_path, image='trusted-agent-image')
    runner._ready = True
    result = runner.run('numeric', {'expressions': {'relations': []}})
    assert result['tool_executed'] is True
    command = calls[0]
    assert command[command.index('--network') + 1] == 'none'
    assert '--read-only' in command and command[command.index('--cap-drop') + 1] == 'ALL'
    assert '--tmpfs' not in command
    assert 'TMPDIR=/workspace/.runtime' in command
    assert command.count('--volume') == 1
    assert removals == [command[command.index('--name') + 1]]


def test_cleanup_failure_discards_successful_tool_result(tmp_path, monkeypatch):
    class Process:
        returncode = 0
        def __init__(self, *args, **kwargs): pass
        def poll(self): return 0
    monkeypatch.setattr(judge.subprocess, 'Popen', Process)
    monkeypatch.setattr(judge.sandbox, '_communicate_bounded', lambda *args, **kwargs: (b'{"protocol":"faithsieve-tools-v1","exit_code":0}', b'', False, False))
    def fail(_name):
        raise judge.sandbox.ContainerCleanupError('无法确认清理')
    monkeypatch.setattr(judge.sandbox, '_force_remove_container', fail)
    runner = judge.DockerFaithSieveTools(tmp_path)
    runner._ready = True
    with pytest.raises(judge.sandbox.ContainerCleanupError):
        runner.run('compile', {})


def test_docker_preflight_success_is_reused_across_controller_reentry(tmp_path, monkeypatch):
    calls = []
    class Process:
        returncode = 0
        def __init__(self, args, **kwargs): calls.append(args)
        def poll(self): return 0
        def wait(self, timeout): return 0
    monkeypatch.setattr(judge.subprocess, 'Popen', Process)
    monkeypatch.setattr(judge.sandbox, '_communicate_bounded', lambda *args, **kwargs: (b'{"protocol":"faithsieve-tools-v1","exit_code":0,"ready":true}', b'', False, False))
    monkeypatch.setattr(judge.sandbox, '_force_remove_container', lambda _name: None)
    for _ in range(2):
        judge.DockerFaithSieveTools(tmp_path).run('numeric', {})
    assert len(calls) == 3  # 预检一次、独立检查两次。
    assert [command[-2] for command in calls] == ['preflight', 'numeric', 'numeric']
