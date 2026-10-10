"""完整空结果函数只做一次流式重试，冻结输入与所有数学校验保持。"""

import copy
import json

import pytest

from backend.oj_modules.ai.endpoints import LLMChatResult, LLMEndpointRequestError, LLMToolCall
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.empty_result_retry import (
    build_empty_result_retry_state, empty_result_response, empty_result_retry_options,
    validate_empty_result_retry_state,
)
from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
from backend.oj_modules.faithsieve.json_repair import REPAIR_SYSTEM_PROMPT
from backend.oj_modules.faithsieve.workflow import TREE, WORK
from tests.unit.test_faithsieve_image_repair import checkpoint_bytes
from tests.unit.test_faithsieve_image_workflow import Pending, Script, seed


def tool_response(arguments="{}", *, text="", name="faithsieve_result", finish="tool_use", count=1):
    return LLMChatResult(text=text, finish_reason=finish, tool_calls=tuple(
        LLMToolCall(id=f"result-{index}", name=name, arguments=arguments) for index in range(count)))


def helper_request(protocol="anthropic"):
    return {"role": "tree-auditor", "proof_graph_version": 3, "node_selection_version": 1,
            "endpoint": {"protocol": protocol, "max_output_tokens": 128000},
            "messages": [{"role": "system", "content": "完整原始角色指令"},
                         {"role": "user", "content": [{"type": "text", "text": "完整原稿与DAG条件"},
                             {"type": "image_url", "image_url": {"url": "data:image/png;base64,cGFnZQ=="}}]}],
            "files": {"problem.md": "原始题面", TREE: "完整原图"},
            "call_options": {"reasoning_effort": "low", "tool_choice": "auto", "tools": [{"type": "function",
                             "function": {"name": "faithsieve_result", "parameters": {"type": "object"}}}]}}


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_pure_helper_freezes_complete_request_without_mutating_or_retaining_provider_call_id(protocol):
    request = helper_request(protocol)
    before = copy.deepcopy(request)
    state = build_empty_result_retry_state(request, tool_response())
    assert request == before
    assert set(state) == {"version", "state", "original_request", "original_response", "retry_request"}
    assert state["original_response"] == {"text": "", "finish_reason": "tool_use",
                                          "tool_calls": [{"name": "faithsieve_result", "arguments": "{}"}]}
    assert state["retry_request"]["messages"] == state["original_request"]["messages"] == before["messages"]
    assert state["retry_request"]["files"] == state["original_request"]["files"] == before["files"]
    expected = {**before["call_options"], "stream": True, "require_complete_stream": True}
    if protocol == "openai":
        expected["stream_options"] = {"include_usage": True}
    assert state["retry_request"]["call_options"] == empty_result_retry_options(request) == expected
    assert validate_empty_result_retry_state(state, request) == state
    state["retry_request"]["messages"][0]["content"] = "更改副本"
    assert request == before and state["original_request"] == before


@pytest.mark.parametrize("version,marker", [(True, 1), (3.0, 1), (2, 1), (3, True), (3, 1.0), (3, None)])
def test_pure_helper_never_upgrades_nonexact_v3_and_selector1_types(version, marker):
    request = helper_request()
    request.update(proof_graph_version=version, node_selection_version=marker)
    with pytest.raises(FaithSieveProtocolError):
        build_empty_result_retry_state(request, tool_response())


@pytest.mark.parametrize("arguments", ["{}", " \n{}\n "])
def test_pure_helper_accepts_only_complete_unique_empty_object_with_original_text_separate(arguments):
    response = tool_response(arguments, text="正文不会用于补充结果。")
    snapshot = empty_result_response(response, helper_request()["call_options"])
    assert snapshot["text"] == response.text and snapshot["tool_calls"][0]["arguments"] == arguments
    assert empty_result_response(response, {**helper_request()["call_options"], "stream": True}) is None
    assert empty_result_response(response, {"response_format": {"type": "json_object"}}) is None
    assert empty_result_response(response, {"tools": []}) is None


class EmptyResultScript(Script):
    def __init__(self, root, *, initial=None, retry_failure=None, target="tree-auditor", repair_failure=None):
        super().__init__(root)
        self.initial = initial or tool_response()
        self.retry_failure = retry_failure
        self.repair_failure = repair_failure
        self.target = target
        self.target_calls, self.repairs = [], []
        self.payload = None
        self.bad_raw = None
        self.was_pending = False
        self.repair_was_pending = False

    def _response(self, payload, options):
        raw = json.dumps(payload, ensure_ascii=False)
        if "response_format" in options:
            return LLMChatResult(text=raw, finish_reason="stop")
        return tool_response(raw)

    def chat(self, endpoint, messages, **options):
        if messages[0]["content"] == REPAIR_SYSTEM_PROMPT:
            self.repairs.append((endpoint, copy.deepcopy(messages), copy.deepcopy(options)))
            if self.repair_failure == "pending" and not self.repair_was_pending:
                self.repair_was_pending = True
                raise Pending("json-repair")
            if self.repair_failure == "endpoint":
                raise LLMEndpointRequestError("格式修复暂时不可用", request_failure="connection")
            payload = copy.deepcopy(self.payload)
            if self.repair_failure == "changed_math":
                payload["result"]["report"] = "这是另一份数学判断。"
            return self._response(payload, options)

        reply = super().chat(endpoint, messages, **options)
        role = self.pure[-1][0]
        if role != self.target:
            return reply
        self.target_calls.append((endpoint, copy.deepcopy(messages), copy.deepcopy(options)))
        self.payload = json.loads(reply.tool_calls[0].arguments if reply.tool_calls else reply.text)
        if len(self.target_calls) == 1:
            return self.initial
        # 非流式普通角色重试不属于空参数回退；让它按既有路径正常完成。
        if not options.get("stream") or self.target == "tree-builder":
            return reply
        if self.retry_failure == "pending" and not self.was_pending:
            self.was_pending = True
            raise Pending("empty-result-stream")
        if self.retry_failure == "endpoint":
            raise LLMEndpointRequestError("流式端点暂时不可用", request_failure="connection")
        if self.retry_failure == "empty":
            return tool_response()
        if self.retry_failure == "truncated":
            return tool_response(json.dumps(self.payload), finish="max_tokens")
        if self.retry_failure == "execution":
            self.payload["execution"] = {"decision_source": "agent"}
        elif self.retry_failure == "missing_field":
            self.payload["result"].pop("report")
        elif self.retry_failure == "wrong_artifact":
            self.payload["result"]["artifact"] = f"{WORK}/unexpected.md"
        elif self.retry_failure == "bad_control":
            self.payload["control"] = {"target_coverage": "invented"}
        elif self.retry_failure == "syntax":
            self.bad_raw = json.dumps(self.payload, ensure_ascii=False) + "}"
            return tool_response(self.bad_raw)
        return self._response(self.payload, options)


def target_records(engine, target="tree-auditor"):
    return {key: record for key, record in engine.checkpoints.records().items()
            if record["request"].get("role") == target}


def assert_frozen_stream_retry(script, record, *, protocol):
    retry = record["metadata"]["empty_result_retry"]
    assert retry["version"] == 1 and type(retry["version"]) is int
    assert retry["original_request"] == record["request"]
    assert retry["original_response"] == {
        "text": script.initial.text, "finish_reason": script.initial.finish_reason,
        "tool_calls": [{"name": call.name, "arguments": call.arguments}
                       for call in script.initial.tool_calls],
    }
    original_endpoint, original_messages, original_options = script.target_calls[0]
    retry_endpoint, retry_messages, retry_options = script.target_calls[1]
    assert original_endpoint == retry_endpoint and original_messages == retry_messages
    assert original_endpoint["max_output_tokens"] == retry_endpoint["max_output_tokens"] == 128000
    assert retry_messages == retry["retry_request"]["messages"]
    expected = {**original_options, "stream": True, "require_complete_stream": True}
    if protocol == "openai":
        expected["stream_options"] = {"include_usage": True}
    assert retry_options == expected
    assert retry["retry_request"] == {
        **record["request"], "call_options": {**record["request"]["call_options"], **{
            key: value for key, value in expected.items() if key != "timeout"}},
    }
    assert "max_tokens" not in retry_options and "max_output_tokens" not in retry_options
    assert "max_stream_bytes" not in retry_options
    assert retry_options.get("reasoning_effort") == original_options.get("reasoning_effort")


@pytest.mark.parametrize("protocol,thinking", [("openai", True), ("anthropic", True), ("anthropic", False)])
@pytest.mark.parametrize("initial", [tool_response(), tool_response(" \n {} \n ", text="已经处理原稿。")])
def test_empty_complete_unique_result_retries_same_images_and_context_once_then_readonly(
        tmp_path, protocol, thinking, initial):
    script = EmptyResultScript(tmp_path, initial=initial)
    engine = seed(tmp_path, script, protocol, thinking=thinking)
    result = engine.run()
    assert result["verdict"] == "correct" and len(script.target_calls) == 2 and len(script.native) == 3
    assert not script.repairs
    records = target_records(engine)
    assert list(records) == ["role-000002-attempt-1"]
    record = records["role-000002-attempt-1"]
    assert record["state"] == record["metadata"]["empty_result_retry"]["state"] == "completed"
    assert_frozen_stream_retry(script, record, protocol=protocol)
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native))
    resumed = seed(tmp_path, script, protocol, thinking=thinking)
    assert resumed.run() == result
    assert checkpoint_bytes(resumed) == before and (len(script.pure), len(script.native)) == calls


@pytest.mark.parametrize("initial", [
    tool_response('{"result":{}}'), tool_response('{"result":{"status":"ok"}}'),
    tool_response('{"execution":{}}'), tool_response("not-json"), tool_response("null"),
    tool_response("[]"), tool_response("{}junk"), tool_response({}, name="faithsieve_result"),
    tool_response(name="wrong_result"), tool_response(count=2), tool_response(count=0),
    tool_response(finish="max_tokens"), tool_response(finish="length"), tool_response(finish=None),
    tool_response(finish="unknown"),
])
def test_nonempty_or_invalid_results_never_receive_empty_argument_stream_fallback(tmp_path, initial):
    script = EmptyResultScript(tmp_path, initial=initial)
    engine = seed(tmp_path, script, "anthropic", thinking=True)
    engine.run()
    assert all(not options.get("stream") for _endpoint, _messages, options in script.target_calls)
    assert all("empty_result_retry" not in record.get("metadata", {}) for record in target_records(engine).values())


@pytest.mark.parametrize("case", ["json_mode", "already_stream", "pre_selector_epoch", "scoring"])
def test_fallback_is_not_enabled_for_json_mode_already_stream_old_epoch_or_scoring(tmp_path, case):
    target = "tree-builder" if case == "already_stream" else ("scoring" if case == "scoring" else "tree-auditor")
    script = EmptyResultScript(tmp_path, target=target)
    engine = seed(tmp_path, script, "openai", thinking=case != "json_mode")
    if case == "pre_selector_epoch":
        engine._select_node_selection_version = lambda: None
    engine.run()
    records = (dict(filter(lambda item: item[0] == "final-scoring", engine.checkpoints.records().items()))
               if case == "scoring" else target_records(engine, target))
    assert records and all("empty_result_retry" not in record.get("metadata", {}) for record in records.values())
    if case != "already_stream":
        assert all(not options.get("stream") for _endpoint, _messages, options in script.target_calls)


@pytest.mark.parametrize("failure", ["empty", "truncated", "execution", "missing_field", "wrong_artifact"])
def test_failed_stream_result_is_terminal_without_another_role_generation(tmp_path, failure):
    script = EmptyResultScript(tmp_path, retry_failure=failure)
    engine = seed(tmp_path, script, "anthropic", thinking=True)
    assert engine.run()["verdict"] == "inconclusive"
    assert len(script.target_calls) == 2 and not script.native and not script.repairs
    records = target_records(engine)
    assert list(records) == ["role-000002-attempt-1"]
    record = records["role-000002-attempt-1"]
    assert record["state"] == "protocol_error"
    assert record["metadata"]["empty_result_retry"]["state"] == ("protocol_error" if failure == "truncated" else "completed")
    before = checkpoint_bytes(engine)
    assert seed(tmp_path, script, "anthropic", thinking=True).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before and len(script.target_calls) == 2


def test_stream_success_still_cannot_certify_an_invalid_mathematical_control(tmp_path):
    script = EmptyResultScript(tmp_path, retry_failure="bad_control")
    engine = seed(tmp_path, script, "anthropic", thinking=True)
    assert engine.run()["verdict"] == "inconclusive"
    assert len(script.target_calls) == 2 and not script.native and not script.repairs
    assert list(target_records(engine)) == ["role-000002-attempt-1"]


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_pending_stream_retry_resumes_only_exact_frozen_retry_request(tmp_path, protocol):
    script = EmptyResultScript(tmp_path, retry_failure="pending")
    engine = seed(tmp_path, script, protocol, thinking=True)
    with pytest.raises(Pending):
        engine.run()
    pending = target_records(engine)["role-000002-attempt-1"]
    assert pending["state"] == pending["metadata"]["empty_result_retry"]["state"] == "pending"
    assert len(script.target_calls) == 2 and not script.native
    assert_frozen_stream_retry(script, pending, protocol=protocol)
    resumed = seed(tmp_path, script, protocol, thinking=True)
    assert resumed.run()["verdict"] == "correct"
    assert len(script.target_calls) == 3 and script.target_calls[1] == script.target_calls[2]
    assert len(script.native) == 3
    completed = target_records(resumed)["role-000002-attempt-1"]
    assert completed["request"] == pending["request"]
    assert completed["metadata"]["empty_result_retry"]["retry_request"] == pending["metadata"]["empty_result_retry"]["retry_request"]


def test_stream_endpoint_error_is_terminal_and_reentry_never_calls_again(tmp_path):
    script = EmptyResultScript(tmp_path, retry_failure="endpoint")
    engine = seed(tmp_path, script, "anthropic", thinking=True)
    with pytest.raises(FaithSieveEndpointError):
        engine.run()
    record = target_records(engine)["role-000002-attempt-1"]
    assert record["state"] == record["metadata"]["empty_result_retry"]["state"] == "endpoint_error"
    assert len(script.target_calls) == 2 and not script.native
    before = checkpoint_bytes(engine)
    with pytest.raises(FaithSieveEndpointError):
        seed(tmp_path, script, "anthropic", thinking=True).run()
    assert checkpoint_bytes(engine) == before and len(script.target_calls) == 2


@pytest.mark.parametrize("mutation", ["version_bool", "version_float", "original_message", "original_marker",
                                     "retry_message", "retry_effort", "retry_stream_type", "extra_cap",
                                     "original_nonempty", "original_multiple", "original_finish", "unknown_field"])
def test_pending_metadata_rejects_changed_requests_response_shape_and_types_before_any_call(tmp_path, mutation):
    script = EmptyResultScript(tmp_path, retry_failure="pending")
    engine = seed(tmp_path, script, "anthropic", thinking=True)
    with pytest.raises(Pending):
        engine.run()
    path = engine.checkpoints._path("role-000002-attempt-1")
    record = json.loads(path.read_text())
    retry = record["metadata"]["empty_result_retry"]
    if mutation == "version_bool":
        retry["version"] = True
    elif mutation == "version_float":
        retry["version"] = 1.0
    elif mutation == "original_message":
        retry["original_request"]["messages"][0]["content"] += "\n篡改上下文"
    elif mutation == "original_marker":
        retry["original_request"]["node_selection_version"] = 1.0
    elif mutation == "retry_message":
        retry["retry_request"]["messages"][0]["content"] += "\n篡改上下文"
    elif mutation == "retry_effort":
        retry["retry_request"]["call_options"]["reasoning_effort"] = "high"
    elif mutation == "retry_stream_type":
        retry["retry_request"]["call_options"]["stream"] = 1
    elif mutation == "extra_cap":
        retry["retry_request"]["call_options"]["max_stream_bytes"] = 1024
    elif mutation == "original_nonempty":
        retry["original_response"]["tool_calls"][0]["arguments"] = '{"result":{}}'
    elif mutation == "original_multiple":
        retry["original_response"]["tool_calls"] *= 2
    elif mutation == "original_finish":
        retry["original_response"]["finish_reason"] = "max_tokens"
    else:
        retry["unregistered"] = "不能补充调用身份"
    path.write_text(json.dumps(record, ensure_ascii=False))
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native))
    assert seed(tmp_path, script, "anthropic", thinking=True).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before and (len(script.pure), len(script.native)) == calls


def test_existing_terminal_empty_result_failure_remains_readonly_without_upgrade(tmp_path):
    script = EmptyResultScript(tmp_path)
    original_chat = script.chat

    def old_chat(endpoint, messages, **options):
        reply = original_chat(endpoint, messages, **options)
        return tool_response() if messages[0]["content"].startswith("# Tree auditor") else reply

    engine = seed(tmp_path, script, "anthropic", thinking=True)
    engine.chat = old_chat
    engine._allow_empty_result_retry = lambda _role: False
    assert engine.run()["verdict"] == "inconclusive"
    records = target_records(engine)
    assert len(records) == len(script.target_calls) == 2
    assert all(record["state"] == "protocol_error" and "empty_result_retry" not in record["metadata"]
               for record in records.values())
    assert all(record["request"]["node_selection_version"] == 1 for record in records.values())
    before, calls = checkpoint_bytes(engine), len(script.pure)
    assert seed(tmp_path, script, "anthropic", thinking=True).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before and len(script.pure) == calls


def test_completed_retry_response_cannot_disagree_with_the_canonical_checkpoint_result(tmp_path):
    script = EmptyResultScript(tmp_path)
    engine = seed(tmp_path, script, "anthropic", thinking=True)
    assert engine.run()["verdict"] == "correct"
    path = engine.checkpoints._path("role-000002-attempt-1")
    record = json.loads(path.read_text())
    response = record["metadata"]["empty_result_retry"]["response"]
    payload = json.loads(response["tool_calls"][0]["arguments"])
    payload["result"]["report"] = "更改后的另一份结论"
    response["tool_calls"][0]["arguments"] = json.dumps(payload, ensure_ascii=False)
    path.write_text(json.dumps(record, ensure_ascii=False))
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native))
    assert seed(tmp_path, script, "anthropic", thinking=True).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before and (len(script.pure), len(script.native)) == calls


@pytest.mark.parametrize("failure", [None, "pending", "changed_math", "endpoint"])
def test_streamed_syntax_error_can_use_one_isolated_json_repair_with_consistent_metadata(tmp_path, failure):
    script = EmptyResultScript(tmp_path, retry_failure="syntax", repair_failure=failure)
    engine = seed(tmp_path, script, "anthropic", thinking=True)
    if failure == "pending":
        with pytest.raises(Pending):
            engine.run()
        pending = target_records(engine)["role-000002-attempt-1"]
        assert pending["state"] == pending["metadata"]["json_repair"]["state"] == "pending"
        assert pending["metadata"]["empty_result_retry"]["state"] == "completed"
        assert len(script.target_calls) == 2 and len(script.repairs) == 1 and not script.native
        assert seed(tmp_path, script, "anthropic", thinking=True).run()["verdict"] == "correct"
        assert script.repairs[0] == script.repairs[1]
    elif failure == "endpoint":
        with pytest.raises(FaithSieveEndpointError):
            engine.run()
    else:
        assert engine.run()["verdict"] == ("inconclusive" if failure else "correct")
    record = target_records(engine)["role-000002-attempt-1"]
    expected = "endpoint_error" if failure == "endpoint" else ("protocol_error" if failure == "changed_math" else "completed")
    assert record["state"] == record["metadata"]["json_repair"]["state"] == expected
    assert record["metadata"]["empty_result_retry"]["state"] == "completed"
    assert len(script.target_calls) == 2 and len(script.repairs) == (2 if failure == "pending" else 1)
    assert script.bad_raw == record["metadata"]["json_repair"]["raw_response"]
    assert script.repairs[0][1] == record["metadata"]["json_repair"]["request"]["messages"]
    assert "data:image" not in script.repairs[0][1][1]["content"]
    assert not {"max_tokens", "max_output_tokens", "max_stream_bytes"} & script.repairs[0][2].keys()
    assert list(target_records(engine)) == ["role-000002-attempt-1"]
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native), len(script.repairs))
    resumed = seed(tmp_path, script, "anthropic", thinking=True)
    if failure == "endpoint":
        with pytest.raises(FaithSieveEndpointError):
            resumed.run()
    else:
        assert resumed.run()["verdict"] == ("inconclusive" if failure == "changed_math" else "correct")
    assert checkpoint_bytes(resumed) == before
    assert (len(script.pure), len(script.native), len(script.repairs)) == calls


def test_native_agent_invalid_result_never_uses_pure_model_stream_retry(tmp_path):
    script = Script(tmp_path)
    script.bad_local = True
    engine = seed(tmp_path, script, "anthropic", thinking=True)
    assert engine.run()["verdict"] == "inconclusive"
    local = target_records(engine, "local-verifier")
    assert len(local) == len(script.native) == 1
    assert all("empty_result_retry" not in record.get("metadata", {}) for record in local.values())
    assert all(not options.get("stream") for role, _messages, options in script.pure if role != "tree-builder")
