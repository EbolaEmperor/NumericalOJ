"""auto 回传可使用完整 JSON 正文；通道不可混合，旧失败不可升级。"""

import copy
import json

import pytest

from backend.oj_modules.ai.endpoints import LLMChatResult, LLMToolCall
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.graph_repair_policy import GRAPH_REPAIR_POLICY_KEY, graph_repair_policy_request
from backend.oj_modules.faithsieve.transport import model_result_raw, parse_model_result
from backend.oj_modules.faithsieve.workflow import TREE
from tests.unit.test_faithsieve_image_repair import checkpoint_bytes
from tests.unit.test_faithsieve_image_workflow import Script, mathematical_records, seed
from tests.unit.test_faithsieve_tool_commentary import tool_options
from tests.unit.test_faithsieve_transport import response, role_result


def body(payload=None, *, text=None, finish_reason="stop", calls=()):
    return LLMChatResult(text=json.dumps(payload, ensure_ascii=False) if text is None else text,
                         finish_reason=finish_reason, tool_calls=calls)


@pytest.mark.parametrize("finish", ["stop", "end_turn", "tool_calls"])
def test_auto_empty_tool_array_reads_one_complete_standard_json_body(finish):
    payload = role_result("原稿符号 ŷ、ĝ；\\Delta；\n保留换行 😀")
    raw = json.dumps(payload, ensure_ascii=False)
    reply = body(text=raw, finish_reason=finish)
    before = copy.deepcopy(reply)
    assert tool_options()["tool_choice"] == "auto"
    assert model_result_raw(reply, tool_options(), allow_result_body=True) == raw
    assert parse_model_result(reply, tool_options(), allow_result_body=True) == payload
    assert reply == before
    with pytest.raises(FaithSieveProtocolError):
        parse_model_result(reply, tool_options())
    with pytest.raises(FaithSieveProtocolError):
        model_result_raw(reply, tool_options(), allow_result_body=False)


@pytest.mark.parametrize("reader", [parse_model_result, model_result_raw])
@pytest.mark.parametrize("allowed", [None, 1, 0, "true", [], {}])
def test_body_permission_is_exact_boolean(reader, allowed):
    with pytest.raises(FaithSieveProtocolError):
        reader(body(role_result()), tool_options(), allow_result_body=allowed)


@pytest.mark.parametrize("reader", [parse_model_result, model_result_raw])
@pytest.mark.parametrize("choice", [None, "required", "none", {"type": "function", "function": {"name": "faithsieve_result"}},
                                    True, {}, []])
def test_body_cannot_downgrade_forced_or_non_auto_tool_contract(reader, choice):
    options = {**tool_options(), "tool_choice": choice}
    with pytest.raises(FaithSieveProtocolError):
        reader(body(role_result()), options, allow_result_body=True, allow_tool_commentary=True)


@pytest.mark.parametrize("reader", [parse_model_result, model_result_raw])
@pytest.mark.parametrize("text", ["", "[]", "null", "结果如下：{}", "```json\n{}\n```", '{}\n解释', '{}{}',
                                 '{"a":1,}', '{"a":NaN}', '{"a":1,"a":2}', '{"x":"\\invalid"}',
                                 '{"unfinished":', '{"result":{},"execution":{}}'])
def test_auto_body_is_never_extracted_guessed_repaired_or_execution_evidence(reader, text):
    with pytest.raises(FaithSieveProtocolError):
        reader(body(text=text), tool_options(), allow_result_body=True, allow_tool_commentary=True)


@pytest.mark.parametrize("reader", [parse_model_result, model_result_raw])
@pytest.mark.parametrize("finish", [None, "length", "max_tokens", "error"])
def test_auto_body_requires_complete_termination(reader, finish):
    with pytest.raises(FaithSieveProtocolError):
        reader(body(role_result(), finish_reason=finish), tool_options(), allow_result_body=True)


@pytest.mark.parametrize("reader", [parse_model_result, model_result_raw])
@pytest.mark.parametrize("call_options", [
    {"name": "other_result"}, {"count": 2}, {"arguments": '{"bad":'},
    {"arguments": '[]'}, {"arguments": '{"execution":{"exit_code":0}}'},
])
def test_invalid_or_multiple_tools_never_fall_back_to_valid_body(reader, call_options):
    reply = response(role_result(), text=json.dumps(role_result()), finish_reason="tool_calls", **call_options)
    with pytest.raises(FaithSieveProtocolError):
        reader(reply, tool_options(), allow_result_body=True, allow_tool_commentary=True)


def test_valid_body_and_tool_are_never_combined_and_only_function_payload_is_authoritative():
    tool_payload = role_result("函数的唯一完整结果")
    contradictory_body = {"result": {"status": "refuted"}, "execution": {"exit_code": 0},
                          "artifacts": {"problem.md": "替换输入"}}
    reply = response(tool_payload, text=json.dumps(contradictory_body, ensure_ascii=False), finish_reason="tool_calls")
    assert parse_model_result(reply, tool_options(), allow_result_body=True, allow_tool_commentary=True) == tool_payload
    assert model_result_raw(reply, tool_options(), allow_result_body=True, allow_tool_commentary=True) == reply.tool_calls[0].arguments
    with pytest.raises(FaithSieveProtocolError):
        parse_model_result(reply, tool_options(), allow_result_body=True)


def test_json_mode_contract_is_unchanged_even_if_auto_body_compatibility_is_enabled():
    payload = role_result()
    options = {"response_format": {"type": "json_object"}}
    assert parse_model_result(body(payload), options, allow_result_body=True) == payload
    with pytest.raises(FaithSieveProtocolError):
        parse_model_result(body(payload, calls=response(payload).tool_calls), options, allow_result_body=True)
    with pytest.raises(FaithSieveProtocolError):
        parse_model_result(body(payload), {**options, **tool_options()}, allow_result_body=True)


class BodyScript(Script):
    def __init__(self, root, *, invalid=None):
        super().__init__(root)
        self.invalid = invalid

    def chat(self, endpoint, messages, **options):
        reply = super().chat(endpoint, messages, **options)
        assert options["tool_choice"] == "auto" and reply.tool_calls
        payload = json.loads(reply.tool_calls[0].arguments)
        if self.invalid == "self_execution":
            payload["execution"] = {"exit_code": 0, "verified": True}
        elif self.invalid == "missing_field":
            payload["result"].pop("artifact")
        elif self.invalid == "invalid_graph":
            payload["artifacts"][TREE]["nodes"][3]["kind"] = "given"
        return body(payload)


def test_fresh_auto_body_and_scoring_keep_frozen_requests_identical_to_function_mode(tmp_path):
    clean_script = Script(tmp_path / "functions")
    clean = seed(tmp_path / "functions", clean_script, thinking=True)
    expected = clean.run()
    script = BodyScript(tmp_path / "body")
    engine = seed(tmp_path / "body", script, thinking=True)
    events = []
    engine.progress = events.append
    result = engine.run()
    assert result == expected and result["verdict"] == "correct"
    records, originals = engine.checkpoints.records(), clean.checkpoints.records()
    assert set(records) == set(originals)
    assert all(record["request"] == originals[key]["request"] for key, record in records.items())
    assert all(record["request"]["node_selection_version"] == 1 for record in mathematical_records(records).values())
    assert records[GRAPH_REPAIR_POLICY_KEY]["request"] == graph_repair_policy_request()
    assert all(event["role"] != GRAPH_REPAIR_POLICY_KEY for event in events)
    assert all("allow_result_body" not in record["request"].get("call_options", {}) for record in records.values())
    assert len(script.native) == len(clean_script.native) == 3
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native))
    resumed = seed(tmp_path / "body", script, thinking=True)
    assert resumed.run() == result
    assert checkpoint_bytes(resumed) == before and (len(script.pure), len(script.native)) == calls


@pytest.mark.parametrize("epoch", [None, 1])
def test_historical_failed_body_result_does_not_upgrade_or_rewrite_original_checkpoint(tmp_path, epoch):
    script = BodyScript(tmp_path)
    engine = seed(tmp_path, script, thinking=True)
    engine._select_node_selection_version = lambda: epoch
    engine._allow_result_body = lambda role: False
    assert engine.run()["verdict"] == "inconclusive"
    records = engine.checkpoints.records()
    model_records = mathematical_records(records)
    assert len(model_records) == 2 and all(record["state"] == "protocol_error" for record in model_records.values())
    assert all(record["request"].get("node_selection_version") == epoch for record in model_records.values())
    assert not script.native
    before, calls = checkpoint_bytes(engine), len(script.pure)
    resumed = seed(tmp_path, script, thinking=True)
    assert resumed.run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(resumed) == before and len(script.pure) == calls and not script.native


@pytest.mark.parametrize("invalid", ["self_execution", "missing_field", "invalid_graph"])
def test_fresh_auto_body_still_requires_exact_role_fields_graph_and_real_execution_evidence(tmp_path, invalid):
    script = BodyScript(tmp_path, invalid=invalid)
    engine = seed(tmp_path, script, thinking=True)
    assert engine.run()["verdict"] == "inconclusive"
    assert len(script.pure) == 2 and not script.native
    records = engine.checkpoints.records()
    model_records = mathematical_records(records)
    assert len(model_records) == 2 and all(record["state"] == "protocol_error" for record in model_records.values())
    assert all("json_repair" not in record["metadata"] for record in model_records.values())
    assert not engine.store.path(TREE).exists()
