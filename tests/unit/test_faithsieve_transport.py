"""单次 JSON 或结果函数回传仍须经过工件校验、冻结输入和缓存边界。"""

from copy import deepcopy
import json

import pytest

from backend.oj_modules.ai import endpoints as llm
from backend.oj_modules.ai.endpoints import LLMChatResult, LLMToolCall
from backend.oj_modules.faithsieve import workflow
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
from backend.oj_modules.faithsieve.prompts import (
    LEGACY_SCORE_PROMPT, SCORE_PROMPT, function_result_prompt, input_message,
    legacy_json_input_message, model_result_prompt, render_role_prompt,
)
from backend.oj_modules.faithsieve.transport import (
    RESULT_TOOL_NAME, function_response_diagnostic, parse_function_result, parse_model_result,
    result_request_options, result_tool_options,
)
from tests.unit.test_faithsieve_workflow import thinking_endpoint, tree_payload
from tests.unit.test_llm_endpoints import FakeResponse


def response(payload=None, *, arguments=None, name=RESULT_TOOL_NAME, text="", count=1, finish_reason=None):
    if arguments is None:
        arguments = json.dumps(payload, ensure_ascii=False)
    return LLMChatResult(text=text, reasoning="仅思考，不作为结果正文", tool_calls=tuple(
        LLMToolCall(f"result-{index}", name, arguments) for index in range(count)
    ), finish_reason=finish_reason)


def role_result(content="## S1\n原稿内容。", *, artifact=workflow.STEPS, control=None):
    return {"result": {"status": "ok", "artifact": artifact, "report": "忠实回传"},
            "artifacts": {artifact: content}, "control": {} if control is None else control}


def engine(root, chat, *, enabled=True, endpoint=None, initial_reasoning_effort=None):
    return workflow.FaithSieveWorkflow(endpoint=endpoint or thinking_endpoint(enabled=enabled),
                                      verification_agent=None, workspace=root, chat=chat,
                                      initial_reasoning_effort=initial_reasoning_effort)


def openai_endpoint(*, enabled=False, thinking_format="enable_thinking"):
    return workflow.LLMEndpointSnapshot(
        id=7, category="text", protocol="openai", base_url="https://llm.example.test/openai",
        api_key="private-retry-secret", model="configured-model", thinking_enabled=enabled,
        thinking_format=thinking_format, max_output_tokens=64000,
    )


def json_response(payload=None, *, text=None, tool_calls=(), finish_reason=None):
    return LLMChatResult(text=json.dumps(payload, ensure_ascii=False) if text is None else text,
                         reasoning="仅思考，不作为结果正文", tool_calls=tool_calls, finish_reason=finish_reason)


def test_markdown_latex_and_newlines_survive_function_arguments_and_artifact_storage(tmp_path):
    content = "## S1\n\n$$\\frac{a}{b} \\le \\varepsilon$$\n\n路径文字：C:\\sample\\proof\n"
    payload = role_result(content)
    assert parse_function_result(response(payload)) == payload
    calls = []
    def chat(_endpoint, _messages, **options):
        calls.append(deepcopy(options))
        return response(payload)
    first = engine(tmp_path, chat)
    first._invoke("decomposer", files={"problem.md": "完整题目"})
    assert first.store.read(workflow.STEPS) == content
    record = first.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-1.json")
    assert record["request"]["call_options"] == {key: value for key, value in calls[0].items() if key != "timeout"}
    assert record["request"]["call_options"]["tool_choice"] == "auto"
    assert len(record["request"]["call_options"]["tools"]) == 1
    engine(tmp_path, chat)._invoke("decomposer", files={"problem.md": "完整题目"})
    assert len(calls) == 1


@pytest.mark.parametrize("arguments", [
    '[]', 'null', '"string"', '```json\n{}\n```', '{"x":1} {"control":{}}',
    '{"x":1,"x":2}', '{"x":"\\invalid"}', '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}',
])
def test_function_arguments_must_be_one_standard_json_object(arguments):
    with pytest.raises(FaithSieveProtocolError):
        parse_function_result(response(arguments=arguments))


@pytest.mark.parametrize("options", [
    {"count": 0}, {"count": 2}, {"name": "other_function"},
    {"text": "已完成"}, {"text": '{"result":{}}'},
])
def test_single_named_function_without_text_is_required(options):
    with pytest.raises(FaithSieveProtocolError):
        parse_function_result(response(role_result(), **options))


def test_pure_llm_cannot_submit_execution_evidence():
    payload = {**role_result(), "execution": {"verified": True, "exit_code": 0}}
    with pytest.raises(FaithSieveProtocolError, match="不得自报"):
        parse_function_result(response(payload))


@pytest.mark.parametrize("enabled", [True, False])
def test_thinking_choice_and_result_schema_are_part_of_the_request_contract(enabled):
    endpoint = thinking_endpoint(enabled=enabled)
    options = result_tool_options(endpoint, fields={"status", "artifact", "report"},
                                  statuses={"ok", "inconclusive"}, artifact=workflow.STEPS)
    assert options["tool_choice"] == ("auto" if enabled else
        {"type": "function", "function": {"name": RESULT_TOOL_NAME}})
    tool, = options["tools"]
    assert tool["type"] == "function" and tool["function"]["name"] == RESULT_TOOL_NAME
    result = tool["function"]["parameters"]["properties"]["result"]
    assert set(result["required"]) == {"status", "artifact", "report"}
    assert result["additionalProperties"] is False
    assert result["properties"]["artifact"]["enum"] == [workflow.STEPS]
    assert endpoint.thinking_enabled is enabled


def test_tree_function_result_still_expands_and_validates_before_storage(tmp_path):
    tree = tree_payload()
    tree["nodes"][1]["conditions"] = {"inherit_from": "N0", "remove": [], "add": ["新事实"]}
    tree["nodes"][1]["goal"] = {"inherit_from": "N0"}
    original = deepcopy(tree)
    payload = role_result(tree, artifact=workflow.TREE)
    run = engine(tmp_path, lambda *_args, **_kwargs: response(payload))
    output = run._invoke("tree-builder", files={workflow.STEPS: "## S1\n原稿第1页：一个转换。"})
    stored = run.store.read_json(workflow.TREE)
    assert stored["nodes"][1]["conditions"] == tree["nodes"][0]["conditions"] + ["新事实"]
    assert stored["nodes"][1]["goal"] == tree["nodes"][0]["goal"]
    assert output.control["edge_units"] == ["E1"] and tree == original


@pytest.mark.parametrize("failure", ["text", "two_calls", "escape", "extra_json", "execution", "input_artifact", "bad_control"])
def test_invalid_role_result_uses_only_existing_two_protocol_attempts(tmp_path, failure):
    payload, options = role_result(), {}
    if failure == "text":
        options["text"] = "另附一份结果"
    elif failure == "two_calls":
        options["count"] = 2
    elif failure == "escape":
        options["arguments"] = '{"x":"\\invalid"}'
    elif failure == "extra_json":
        options["arguments"] = json.dumps(payload) + '{"control":{}}'
    elif failure == "execution":
        payload["execution"] = {"verified": True}
    elif failure == "input_artifact":
        payload["artifacts"]["problem.md"] = "覆盖输入"
    else:
        payload["control"] = []
    calls = []
    def chat(*_args, **_kwargs):
        calls.append(1)
        return response(payload, **options)
    run = engine(tmp_path, chat)
    run.store.write("problem.md", "原题目")
    with pytest.raises(FaithSieveProtocolError):
        run._invoke("decomposer", files={"problem.md": "原题目"})
    assert len(calls) == 2 and run.store.read("problem.md") == "原题目"
    assert not (tmp_path / workflow.STEPS).exists()
    with pytest.raises(FaithSieveProtocolError):
        engine(tmp_path, chat)._invoke("decomposer", files={"problem.md": "原题目"})
    assert len(calls) == 2


@pytest.mark.parametrize("changed", ["tool_choice", "schema"])
def test_tampered_frozen_tool_options_do_not_call_model_or_rewrite_checkpoint(tmp_path, changed):
    calls = []
    def chat(*_args, **_kwargs):
        calls.append(1)
        return response(role_result())
    engine(tmp_path, chat)._invoke("decomposer", files={})
    path = tmp_path / "faithsieve-work/checkpoints/role-000001-attempt-1.json"
    record = json.loads(path.read_text())
    if changed == "tool_choice":
        record["request"]["call_options"]["tool_choice"] = "none"
    else:
        record["request"]["call_options"]["tools"][0]["function"]["parameters"]["additionalProperties"] = True
    path.write_text(json.dumps(record))
    saved = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        engine(tmp_path, chat)._invoke("decomposer", files={})
    assert len(calls) == 1 and path.read_bytes() == saved


def test_scoring_uses_three_fields_and_replays_without_another_call(tmp_path):
    grade = {"verdict": "correct", "score": 5, "comment": "证明正确且充分。"}
    calls = []
    def chat(*_args, **options):
        calls.append(deepcopy(options))
        return response(grade)
    assert engine(tmp_path, chat)._score("correct") == grade
    assert engine(tmp_path, chat)._score("correct") == grade and len(calls) == 1
    schema = calls[0]["tools"][0]["function"]["parameters"]
    assert set(schema["required"]) == set(grade) and schema["additionalProperties"] is False


@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("initial_effort", [None, "low", "medium"])
def test_completed_legacy_request_preserves_initial_effort_contract_without_call_or_rewrite(tmp_path, target, initial_effort):
    def unexpected(*_args, **_kwargs):
        pytest.fail("已完成缓存不得调用模型")
    run = engine(tmp_path, unexpected, initial_reasoning_effort=initial_effort)
    if target == "role":
        key = "role-000001-attempt-1"
        request = {"role": "decomposer", "prompt": render_role_prompt("decomposer", legacy_input=True), "files": {},
                   "parameters": {}, "revision_report": "", "expected_result_path": "faithsieve-work/results/decomposer.json",
                   "endpoint": run._endpoint_identity()}
        payload = {**role_result(), "execution": {}}
    else:
        key = "final-scoring"
        request = {"messages": [{"role": "system", "content": LEGACY_SCORE_PROMPT},
                                {"role": "user", "content": legacy_json_input_message({}, approved_verdict="correct")}],
                   "endpoint": run._endpoint_identity()}
        payload = {"verdict": "correct", "score": 5, "comment": "历史已完成评分。"}
    run.checkpoints.put(key, request, state="completed", response=payload)
    path = run.checkpoints._path(key)
    before = path.read_bytes()
    def replay():
        return run._invoke("decomposer", files={}) if target == "role" else run._score("correct")
    if initial_effort is None:
        replay()
    else:
        with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
            replay()
    assert path.read_bytes() == before


def test_function_diagnostics_preserve_failed_arguments_for_existing_redaction(tmp_path):
    arguments = '{"unfinished":"private-retry-secret", "x":"\\invalid"}'
    reply = response(arguments=arguments)
    assert function_response_diagnostic(reply)["tool_calls"][0]["arguments"] == arguments
    run = engine(tmp_path, lambda *_args, **_kwargs: reply)
    with pytest.raises(FaithSieveProtocolError):
        run._invoke("decomposer", files={})
    diagnostic = run.store.read_json("faithsieve-work/protocol-diagnostics/role-000001-attempt-1.json")
    assert "unfinished" in diagnostic["response_head"]
    assert "private-retry-secret" not in json.dumps(diagnostic)


@pytest.mark.parametrize("enabled", [True, False])
def test_request_options_select_json_mode_only_for_openai_off_without_changing_thinking(enabled):
    fields = {"status", "artifact", "report"}
    kwargs = {"fields": fields, "statuses": {"ok", "inconclusive"}, "artifact": workflow.STEPS}
    openai, anthropic = openai_endpoint(enabled=enabled), thinking_endpoint(enabled=enabled)
    expected = (result_tool_options(openai, **kwargs) if enabled else {"response_format": {"type": "json_object"}})
    assert result_request_options(openai, **kwargs) == expected
    assert result_request_options(openai, scoring=True) == (result_tool_options(openai, scoring=True)
                                                          if enabled else expected)
    if enabled:
        assert expected["tool_choice"] == "auto" and "response_format" not in expected
    assert result_request_options(anthropic, **kwargs) == result_tool_options(anthropic, **kwargs)
    assert openai.thinking_enabled is enabled and anthropic.thinking_enabled is enabled
    mapping = {**openai.to_public_dict(), "api_key": "private-retry-secret"}
    assert result_request_options(mapping, **kwargs) == expected


@pytest.mark.parametrize("text", [
    "", "[]", "null", '"string"', '```json\n{}\n```', '```\n{}\n```',
    '已完成\n{}', '{"x":1} {"control":{}}', '{"x":1,"x":2}',
    '{"x":{"a":1,"a":2}}', '{"x":"\\invalid"}',
    '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}',
])
def test_json_mode_requires_one_standard_json_object_without_fences_or_narration(text):
    with pytest.raises(FaithSieveProtocolError):
        parse_model_result(json_response(text=text), result_request_options(openai_endpoint()))


def test_response_parser_uses_the_frozen_transport_without_trying_another_format():
    payload = role_result()
    json_options = result_request_options(openai_endpoint())
    tool_options = result_tool_options(thinking_endpoint(), fields={"status", "artifact", "report"},
                                       statuses={"ok"}, artifact=workflow.STEPS)
    assert parse_model_result(json_response(payload), json_options) == payload
    assert parse_model_result(response(payload), tool_options) == payload
    for reply, options in [(response(payload), json_options), (json_response(payload), tool_options),
                           (json_response(payload, tool_calls=response(payload).tool_calls), json_options)]:
        with pytest.raises(FaithSieveProtocolError):
            parse_model_result(reply, options)
    with pytest.raises(FaithSieveProtocolError, match="不得自报"):
        parse_model_result(json_response({**payload, "execution": {"exit_code": 0}}), json_options)


@pytest.mark.parametrize("enabled", [True, False])
def test_openai_transports_preserve_markdown_and_record_exact_options_with_zero_call_replay(tmp_path, enabled):
    content = "## S1\n\n$$\\forall x\\in\\mathbb{R},\\quad \\frac{x}{2}\\le x$$\n\n原文换行\n第二行。\n"
    endpoint, calls = openai_endpoint(enabled=enabled), []
    def chat(_endpoint, messages, **options):
        assert _endpoint.thinking_enabled is enabled
        assert "JSON" in messages[0]["content"]
        calls.append(deepcopy(options))
        return response(role_result(content)) if enabled else json_response(role_result(content))
    run = engine(tmp_path, chat, endpoint=endpoint)
    run._invoke("decomposer", files={"problem.md": "完整题面"})
    assert run.store.read(workflow.STEPS) == content
    path = run.checkpoints._path("role-000001-attempt-1")
    record, saved = json.loads(path.read_text()), path.read_bytes()
    expected = result_request_options(endpoint, fields={"status", "artifact", "report"},
                                      statuses={"ok", "needs_revision", "inconclusive"}, artifact=workflow.STEPS)
    assert record["request"]["call_options"] == expected
    assert record["request"]["call_options"] == {key: value for key, value in calls[0].items() if key != "timeout"}
    engine(tmp_path, chat, endpoint=endpoint)._invoke("decomposer", files={"problem.md": "完整题面"})
    assert len(calls) == 1 and path.read_bytes() == saved


def test_json_tree_still_requires_complete_valid_expansion_before_publishing(tmp_path):
    tree = tree_payload()
    tree["nodes"][1]["conditions"] = {"inherit_from": "N0", "remove": [], "add": ["新事实"]}
    tree["nodes"][1]["goal"] = {"inherit_from": "N0"}
    original = deepcopy(tree)
    calls = []
    def chat(*_args, **options):
        calls.append(options)
        return json_response(role_result(tree, artifact=workflow.TREE))
    run = engine(tmp_path, chat, endpoint=openai_endpoint())
    result = run._invoke("tree-builder", files={workflow.STEPS: "## S1\n原稿第1页：一个转换。"})
    stored = run.store.read_json(workflow.TREE)
    assert stored["nodes"][1]["conditions"] == tree["nodes"][0]["conditions"] + ["新事实"]
    assert stored["nodes"][1]["goal"] == tree["nodes"][0]["goal"]
    assert result.control["edge_units"] == ["E1"] and tree == original and len(calls) == 1


def test_json_native_tree_does_not_bypass_host_topology_validation(tmp_path):
    tree, calls = tree_payload(), []
    tree["nodes"][1]["conditions"] = {"inherit_from": "Unknown", "remove": [], "add": []}
    def chat(*_args, **_kwargs):
        calls.append(1)
        return json_response(role_result(tree, artifact=workflow.TREE))
    endpoint = openai_endpoint()
    for _attempt in range(2):
        run = engine(tmp_path, chat, endpoint=endpoint)
        with pytest.raises(FaithSieveProtocolError):
            run._invoke("tree-builder", files={workflow.STEPS: "## S1\n原稿第1页：一个转换。"})
    assert len(calls) == 2 and not (tmp_path / workflow.TREE).exists()


@pytest.mark.parametrize("failure", [
    "tool_call", "escape", "extra_json", "duplicate", "constant", "execution", "input_artifact", "bad_control",
])
def test_json_role_failure_preserves_existing_retry_limit_and_cached_terminal_failure(tmp_path, failure):
    payload, text, tool_calls = role_result(), None, ()
    if failure == "tool_call":
        tool_calls = response(payload).tool_calls
    elif failure == "escape":
        text = '{"x":"\\invalid"}'
    elif failure == "extra_json":
        text = json.dumps(payload) + '{"control":{}}'
    elif failure == "duplicate":
        text = '{"result":{},"result":{}}'
    elif failure == "constant":
        text = '{"result":{"status":NaN}}'
    elif failure == "execution":
        payload["execution"] = {"verified": True}
    elif failure == "input_artifact":
        payload["artifacts"]["problem.md"] = "覆盖输入"
    else:
        payload["control"] = []
    calls = []
    def chat(*_args, **_kwargs):
        calls.append(1)
        return json_response(payload, text=text, tool_calls=tool_calls)
    endpoint = openai_endpoint()
    run = engine(tmp_path, chat, endpoint=endpoint)
    run.store.write("problem.md", "原题面")
    with pytest.raises(FaithSieveProtocolError):
        run._invoke("decomposer", files={"problem.md": "原题面"})
    assert len(calls) == 2 and run.store.read("problem.md") == "原题面"
    assert not (tmp_path / workflow.STEPS).exists()
    with pytest.raises(FaithSieveProtocolError):
        engine(tmp_path, chat, endpoint=endpoint)._invoke("decomposer", files={"problem.md": "原题面"})
    assert len(calls) == 2


@pytest.mark.parametrize("changed", ["format", "missing_options", "thinking_format"])
def test_json_request_configuration_cannot_be_tampered_without_a_checkpoint_mismatch(tmp_path, changed):
    endpoint, calls = openai_endpoint(), []
    def chat(*_args, **_kwargs):
        calls.append(1)
        return json_response(role_result())
    run = engine(tmp_path, chat, endpoint=endpoint)
    run._invoke("decomposer", files={})
    path = run.checkpoints._path("role-000001-attempt-1")
    record = json.loads(path.read_text())
    if changed == "format":
        record["request"]["call_options"]["response_format"] = {"type": "text"}
    elif changed == "missing_options":
        record["request"].pop("call_options")
    else:
        endpoint = openai_endpoint(thinking_format="thinking_type")
    path.write_text(json.dumps(record))
    saved = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        engine(tmp_path, chat, endpoint=endpoint)._invoke("decomposer", files={})
    assert len(calls) == 1 and path.read_bytes() == saved


def test_json_scoring_keeps_the_three_field_grade_and_does_not_repeat_completed_call(tmp_path):
    grade, calls = {"verdict": "correct", "score": 5, "comment": "证明正确且充分。"}, []
    def chat(*_args, **options):
        calls.append(deepcopy(options))
        return json_response(grade)
    endpoint = openai_endpoint()
    run = engine(tmp_path, chat, endpoint=endpoint)
    assert run._score("correct") == grade
    path = run.checkpoints._path("final-scoring")
    saved = path.read_bytes()
    assert json.loads(saved)["request"]["call_options"] == {"response_format": {"type": "json_object"}}
    assert engine(tmp_path, chat, endpoint=endpoint)._score("correct") == grade
    assert len(calls) == 1 and path.read_bytes() == saved
    assert set(run.store.read_json(workflow.RESULT)) == {"verdict", "score", "comment"}


@pytest.mark.parametrize("failure", ["extra_field", "wrong_verdict", "rubric_conflict", "duplicate", "tool_call"])
def test_json_scoring_protocol_or_approved_verdict_failure_is_cached_without_new_call(tmp_path, failure):
    grade, text, tool_calls = {"verdict": "correct", "score": 5, "comment": "证明正确。"}, None, ()
    if failure == "extra_field":
        grade["unexpected"] = "额外评分字段"
    elif failure == "wrong_verdict":
        grade["verdict"] = "incorrect"
    elif failure == "rubric_conflict":
        grade["score"] = 2
    elif failure == "duplicate":
        text = '{"verdict":"correct","score":5,"score":2,"comment":"评分"}'
    else:
        tool_calls = response(grade).tool_calls
    calls, endpoint = [], openai_endpoint()
    def chat(*_args, **_kwargs):
        calls.append(1)
        return json_response(grade, text=text, tool_calls=tool_calls)
    for _attempt in range(2):
        with pytest.raises(FaithSieveProtocolError):
            engine(tmp_path, chat, endpoint=endpoint)._score("correct")
    assert len(calls) == 1 and not (tmp_path / workflow.RESULT).exists()


def legacy_openai_tool_record(run, target):
    """保存上一传输协议的完整请求，不使用本轮 JSON mode 的 prompt 或选项。"""
    if target == "role":
        request = {"role": "decomposer", "prompt": function_result_prompt(render_role_prompt("decomposer", legacy_input=True), legacy_result=True),
                   "files": {}, "parameters": {}, "revision_report": "",
                   "expected_result_path": "faithsieve-work/results/decomposer.json",
                   "endpoint": run._endpoint_identity(),
                   "call_options": result_tool_options(run.endpoint, fields={"status", "artifact", "report"},
                       statuses={"ok", "needs_revision", "inconclusive"}, artifact=workflow.STEPS)}
        return "role-000001-attempt-1", request, {**role_result(), "execution": {}}
    request = {"messages": [{"role": "system", "content": function_result_prompt(LEGACY_SCORE_PROMPT, scoring=True, legacy_result=True)},
                            {"role": "user", "content": legacy_json_input_message({}, approved_verdict="correct")}],
               "endpoint": run._endpoint_identity(), "call_options": result_tool_options(run.endpoint, scoring=True)}
    return "final-scoring", request, {"verdict": "correct", "score": 5, "comment": "历史已完成评分。"}


@pytest.mark.parametrize("target", ["role", "scoring"])
def test_completed_openai_function_transport_cache_replays_without_migration_or_call(tmp_path, target):
    def unexpected(*_args, **_kwargs):
        pytest.fail("历史已完成结果不得再次调用模型")
    run = engine(tmp_path, unexpected, endpoint=openai_endpoint())
    key, request, payload = legacy_openai_tool_record(run, target)
    run.checkpoints.put(key, request, state="completed", response=payload)
    path = run.checkpoints._path(key)
    before = path.read_bytes()
    if target == "role":
        run._invoke("decomposer", files={})
        assert run.store.read(workflow.STEPS) == payload["artifacts"][workflow.STEPS]
    else:
        assert run._score("correct") == payload
    assert path.read_bytes() == before


@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("state", ["pending", "protocol_error", "endpoint_error"])
def test_incomplete_old_function_transport_cannot_replay_under_json_mode(tmp_path, target, state):
    def unexpected(*_args, **_kwargs):
        pytest.fail("传输协议变化时，未完成旧请求不得发出新调用")
    run = engine(tmp_path, unexpected, endpoint=openai_endpoint())
    key, request, payload = legacy_openai_tool_record(run, target)
    run.checkpoints.put(key, request, state=state, response=payload)
    path = run.checkpoints._path(key)
    before = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        if target == "role":
            run._invoke("decomposer", files={})
        else:
            run._score("correct")
    assert path.read_bytes() == before


@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("changed", ["prompt", "schema", "tool_choice"])
def test_completed_old_function_cache_still_requires_exact_prompt_schema_and_choice(tmp_path, target, changed):
    def unexpected(*_args, **_kwargs):
        pytest.fail("篡改过的历史请求不得调用模型")
    run = engine(tmp_path, unexpected, endpoint=openai_endpoint())
    key, request, payload = legacy_openai_tool_record(run, target)
    if changed == "tool_choice":
        request["call_options"]["tool_choice"] = "none"
    elif changed == "schema":
        request["call_options"]["tools"][0]["function"]["parameters"]["additionalProperties"] = True
    elif target == "role":
        request["prompt"] += "\n覆盖原职责"
    else:
        request["messages"][0]["content"] += "\n覆盖原职责"
    run.checkpoints.put(key, request, state="completed", response=payload)
    path = run.checkpoints._path(key)
    before = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        if target == "role":
            run._invoke("decomposer", files={})
        else:
            run._score("correct")
    assert path.read_bytes() == before


def test_json_failed_body_is_retained_only_in_bounded_redacted_private_diagnostics(tmp_path):
    text = '{"unfinished":"private-retry-secret","x":"\\invalid"}'
    run = engine(tmp_path, lambda *_args, **_kwargs: json_response(text=text), endpoint=openai_endpoint())
    with pytest.raises(FaithSieveProtocolError):
        run._invoke("decomposer", files={})
    diagnostic = run.store.read_json("faithsieve-work/protocol-diagnostics/role-000001-attempt-1.json")
    assert "unfinished" in diagnostic["response_head"]
    assert "private-retry-secret" not in json.dumps(diagnostic)


@pytest.mark.parametrize("transport", ["json", "openai_function", "anthropic_function"])
@pytest.mark.parametrize("exhausted", [False, True])
def test_actual_protocol_finish_reason_is_preserved_and_truncated_valid_payload_is_rejected(transport, exhausted):
    payload = role_result("## S1\n已闭合 JSON 中的原稿片段。")
    endpoint = thinking_endpoint() if transport == "anthropic_function" else openai_endpoint(enabled=transport != "json")
    options = result_request_options(endpoint, fields={"status", "artifact", "report"},
                                     statuses={"ok"}, artifact=workflow.STEPS)
    if transport == "anthropic_function":
        finish = "max_tokens" if exhausted else "tool_use"
        wire = {"content": [{"type": "tool_use", "id": "result-1", "name": RESULT_TOOL_NAME, "input": payload}],
                "stop_reason": finish}
    else:
        finish = "length" if exhausted else ("stop" if transport == "json" else "tool_calls")
        message = ({"content": json.dumps(payload, ensure_ascii=False)} if transport == "json" else
                   {"content": None, "tool_calls": [{"id": "result-1", "type": "function", "function": {
                       "name": RESULT_TOOL_NAME, "arguments": json.dumps(payload, ensure_ascii=False)}}]})
        wire = {"choices": [{"message": message, "finish_reason": finish}]}
    http_calls = []
    def post(_url, **kwargs):
        http_calls.append(kwargs)
        return FakeResponse(wire)
    reply = llm.call_chat(endpoint, [{"role": "user", "content": "返回 JSON"}], request_post=post, **options)
    assert len(http_calls) == 1 and reply.finish_reason == finish
    assert http_calls[0]["json"]["max_tokens"] == endpoint.max_output_tokens
    if exhausted:
        with pytest.raises(FaithSieveProtocolError, match="截断"):
            parse_model_result(reply, options)
    else:
        assert parse_model_result(reply, options) == payload


@pytest.mark.parametrize("transport", ["json", "function"])
@pytest.mark.parametrize("finish", ["length", "max_tokens"])
@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("initial_effort", [None, "medium"])
def test_closed_json_with_truncated_finish_cannot_publish_or_add_extra_calls(tmp_path, transport, finish, target, initial_effort):
    endpoint = openai_endpoint(enabled=transport == "function")
    payload = (role_result("## S1\n仅包含本应继续输出的部分原稿。") if target == "role" else
               {"verdict": "correct", "score": 5, "comment": "仅包含尚未完成的评分意见。"})
    calls = []
    def chat(*_args, **options):
        calls.append(deepcopy(options))
        return (json_response(payload, finish_reason=finish) if transport == "json" else
                response(payload, finish_reason=finish))
    for _reentry in range(2):
        run = engine(tmp_path, chat, endpoint=endpoint, initial_reasoning_effort=initial_effort)
        with pytest.raises(FaithSieveProtocolError, match="截断"):
            run._invoke("decomposer", files={}) if target == "role" else run._score("correct")
    assert len(calls) == (2 if target == "role" else 1)
    assert all(options.get("reasoning_effort") == (initial_effort if transport == "function" else None) for options in calls)
    records = [json.loads(path.read_text()) for path in (tmp_path / "faithsieve-work/checkpoints").glob("*.json")]
    assert len(records) == len(calls) and all(record["state"] == "protocol_error" for record in records)
    assert not (tmp_path / workflow.STEPS).exists() and not (tmp_path / workflow.RESULT).exists()


def legacy_openai_json_record(run, target, *, initial_effort=None):
    options = {"response_format": {"type": "json_object"}}
    if initial_effort is not None:
        options["reasoning_effort"] = initial_effort
    if target == "role":
        request = {"role": "decomposer", "prompt": model_result_prompt(render_role_prompt("decomposer", legacy_input=True), options, legacy_result=True),
                   "files": {}, "parameters": {}, "revision_report": "",
                   "expected_result_path": "faithsieve-work/results/decomposer.json",
                   "endpoint": run._endpoint_identity(), "call_options": options}
        return "role-000001-attempt-1", request, {**role_result(), "execution": {}}
    request = {"messages": [{"role": "system", "content": model_result_prompt(LEGACY_SCORE_PROMPT, options, scoring=True, legacy_result=True)},
                            {"role": "user", "content": legacy_json_input_message({}, approved_verdict="correct")}],
               "endpoint": run._endpoint_identity(), "call_options": options}
    return "final-scoring", request, {"verdict": "correct", "score": 5, "comment": "历史已完成评分。"}


@pytest.mark.parametrize("target", ["role", "scoring"])
def test_completed_openai_on_json_cache_replays_under_function_transport_without_call_or_rewrite(tmp_path, target):
    def unexpected(*_args, **_kwargs):
        pytest.fail("完整输入一致的旧已完成结果不得重调模型")
    run = engine(tmp_path, unexpected, endpoint=openai_endpoint(enabled=True))
    key, request, payload = legacy_openai_json_record(run, target)
    assert "tools" in result_request_options(run.endpoint, scoring=True)
    run.checkpoints.put(key, request, state="completed", response=payload)
    path = run.checkpoints._path(key)
    before = path.read_bytes()
    if target == "role":
        run._invoke("decomposer", files={})
        assert run.store.read(workflow.STEPS) == payload["artifacts"][workflow.STEPS]
    else:
        assert run._score("correct") == payload
    assert path.read_bytes() == before


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("initial_effort", [None, "low", "medium"])
@pytest.mark.parametrize("target", ["role", "scoring"])
def test_initial_reasoning_effort_uses_existing_protocol_adapter_and_freezes_full_request(tmp_path, protocol, enabled, initial_effort, target):
    endpoint = openai_endpoint(enabled=enabled) if protocol == "openai" else thinking_endpoint(enabled=enabled)
    payload = role_result() if target == "role" else {"verdict": "correct", "score": 5, "comment": "证明充分。"}
    http_calls, chat_options = [], []
    def post(_url, **kwargs):
        http_calls.append(deepcopy(kwargs["json"]))
        if protocol == "anthropic":
            return FakeResponse({"content": [{"type": "tool_use", "id": "result-1", "name": RESULT_TOOL_NAME, "input": payload}],
                                 "stop_reason": "tool_use"})
        message = ({"content": json.dumps(payload)} if not enabled else
                   {"content": None, "tool_calls": [{"id": "result-1", "type": "function", "function": {
                       "name": RESULT_TOOL_NAME, "arguments": json.dumps(payload)}}]})
        return FakeResponse({"choices": [{"message": message, "finish_reason": "tool_calls" if enabled else "stop"}]})
    def chat(endpoint, messages, **options):
        chat_options.append(deepcopy(options))
        return llm.call_chat(endpoint, messages, request_post=post, **options)
    run = engine(tmp_path, chat, endpoint=endpoint, initial_reasoning_effort=initial_effort)
    if target == "role":
        run._invoke("decomposer", files={})
        key = "role-000001-attempt-1"
    else:
        assert run._score("correct") == payload
        key = "final-scoring"
    path = run.checkpoints._path(key)
    before = path.read_bytes()
    frozen = run.store.read_json(path.relative_to(tmp_path).as_posix())["request"]["call_options"]
    assert frozen == {name: value for name, value in chat_options[0].items() if name != "timeout"}
    expected_effort = initial_effort if enabled else None
    assert frozen.get("reasoning_effort") == expected_effort
    wire, = http_calls
    assert wire["max_tokens"] == 64000 and endpoint.thinking_enabled is enabled
    if protocol == "openai":
        assert wire.get("reasoning_effort") == expected_effort and "output_config" not in wire
        assert wire["enable_thinking"] is enabled
        if enabled:
            assert frozen["tool_choice"] == "auto" and "response_format" not in wire
        else:
            assert wire["response_format"] == {"type": "json_object"} and "tools" not in wire
    else:
        assert wire.get("output_config") == ({"effort": expected_effort} if expected_effort else None)
        assert "reasoning_effort" not in wire
        assert wire["thinking"] == {"type": "adaptive" if enabled else "disabled"}
    replay = engine(tmp_path, chat, endpoint=endpoint, initial_reasoning_effort=initial_effort)
    replay._invoke("decomposer", files={}) if target == "role" else replay._score("correct")
    assert len(http_calls) == 1 and path.read_bytes() == before


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize("initial_effort", ["low", "medium"])
def test_ordinary_protocol_retry_keeps_initial_reasoning_effort(tmp_path, protocol, initial_effort):
    calls = []
    def chat(*_args, **options):
        calls.append(deepcopy(options))
        return response(arguments='{"broken":') if len(calls) == 1 else response(role_result())
    endpoint = openai_endpoint(enabled=True) if protocol == "openai" else thinking_endpoint()
    run = engine(tmp_path, chat, endpoint=endpoint, initial_reasoning_effort=initial_effort)
    run._invoke("decomposer", files={})
    assert len(calls) == 2 and calls[0] == calls[1] and calls[0]["reasoning_effort"] == initial_effort
    first = run.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-1.json")
    assert "reasoning_retry" not in first["metadata"]


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize("target", ["role", "scoring"])
def test_rejected_initial_effort_is_terminal_without_silent_parameter_drop(tmp_path, protocol, target):
    endpoint = openai_endpoint(enabled=True) if protocol == "openai" else thinking_endpoint()
    calls = []
    def rejected(*_args, **options):
        calls.append(deepcopy(options))
        raise llm.LLMEndpointRequestError("供应商拒绝 reasoning_effort", status_code=400)
    for _reentry in range(2):
        run = engine(tmp_path, rejected, endpoint=endpoint, initial_reasoning_effort="low")
        with pytest.raises(FaithSieveEndpointError):
            run._invoke("decomposer", files={}) if target == "role" else run._score("correct")
    assert len(calls) == 1 and calls[0]["reasoning_effort"] == "low"
    path = run.checkpoints._path("role-000001-attempt-1" if target == "role" else "final-scoring")
    record = json.loads(path.read_text())
    assert record["state"] == "endpoint_error" and record["request"]["call_options"]["reasoning_effort"] == "low"
    assert not (tmp_path / workflow.STEPS).exists() and not (tmp_path / workflow.RESULT).exists()


@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("state", ["completed", "pending"])
@pytest.mark.parametrize("saved_effort,resumed_effort", [(None, "low"), ("low", None), ("low", "medium"), ("medium", "low")])
def test_changed_initial_effort_cannot_replay_or_resume_frozen_request(tmp_path, target, state, saved_effort, resumed_effort):
    endpoint = openai_endpoint(enabled=True)
    payload = role_result() if target == "role" else {"verdict": "correct", "score": 5, "comment": "证明充分。"}
    run = engine(tmp_path, lambda *_args, **_options: response(payload), endpoint=endpoint,
                 initial_reasoning_effort=saved_effort)
    run._invoke("decomposer", files={}) if target == "role" else run._score("correct")
    path = run.checkpoints._path("role-000001-attempt-1" if target == "role" else "final-scoring")
    record = json.loads(path.read_text())
    record["state"] = state
    path.write_text(json.dumps(record))
    before = path.read_bytes()
    replay = engine(tmp_path, lambda *_args, **_options: pytest.fail("改变初始强度不能重调或丢弃冻结选项"),
                    endpoint=endpoint, initial_reasoning_effort=resumed_effort)
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        replay._invoke("decomposer", files={}) if target == "role" else replay._score("correct")
    assert path.read_bytes() == before


@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("saved_effort", [None, "low", "medium"])
@pytest.mark.parametrize("resumed_effort", [None, "low", "medium"])
def test_completed_legacy_json_cache_requires_exact_initial_effort(tmp_path, target, saved_effort, resumed_effort):
    run = engine(tmp_path, lambda *_args, **_options: pytest.fail("旧缓存不得调用模型"),
                 endpoint=openai_endpoint(enabled=True), initial_reasoning_effort=resumed_effort)
    key, request, payload = legacy_openai_json_record(run, target, initial_effort=saved_effort)
    run.checkpoints.put(key, request, state="completed", response=payload)
    path = run.checkpoints._path(key)
    before = path.read_bytes()
    def replay():
        return run._invoke("decomposer", files={}) if target == "role" else run._score("correct")
    if saved_effort == resumed_effort:
        replay()
    else:
        with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
            replay()
    assert path.read_bytes() == before


@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("state", ["pending", "protocol_error", "endpoint_error"])
def test_incomplete_openai_on_json_cache_cannot_switch_to_function_transport(tmp_path, target, state):
    def unexpected(*_args, **_kwargs):
        pytest.fail("旧未完成或失败请求不能切换传输格式继续调用")
    run = engine(tmp_path, unexpected, endpoint=openai_endpoint(enabled=True))
    key, request, payload = legacy_openai_json_record(run, target)
    run.checkpoints.put(key, request, state=state, response=payload)
    path = run.checkpoints._path(key)
    before = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        run._invoke("decomposer", files={}) if target == "role" else run._score("correct")
    assert path.read_bytes() == before


@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("changed", ["prompt", "format", "endpoint_thinking"])
def test_completed_old_openai_on_json_cache_requires_exact_input_and_format(tmp_path, target, changed):
    def unexpected(*_args, **_kwargs):
        pytest.fail("篡改过的旧 JSON 请求不能重调模型")
    run = engine(tmp_path, unexpected, endpoint=openai_endpoint(enabled=True))
    key, request, payload = legacy_openai_json_record(run, target)
    if changed == "format":
        request["call_options"]["response_format"] = {"type": "text"}
    elif changed == "endpoint_thinking":
        request["endpoint"]["thinking_enabled"] = False
    elif target == "role":
        request["prompt"] += "\n改变职责"
    else:
        request["messages"][0]["content"] += "\n改变职责"
    run.checkpoints.put(key, request, state="completed", response=payload)
    path = run.checkpoints._path(key)
    before = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        run._invoke("decomposer", files={}) if target == "role" else run._score("correct")
    assert path.read_bytes() == before
