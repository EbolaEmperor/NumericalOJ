"""新图片协议在角色重试后只修一次 JSON，不重新生成数学结果。"""

import copy
import json

import pytest

from backend.oj_modules.ai.endpoints import LLMChatResult, LLMEndpointRequestError, LLMToolCall
from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
from backend.oj_modules.faithsieve.json_repair import REPAIR_SYSTEM_PROMPT
from backend.oj_modules.faithsieve.workflow import TREE, WORK
from tests.unit.test_faithsieve_image_repair import checkpoint_bytes
from tests.unit.test_faithsieve_image_workflow import Pending, Script, graph, seed


class RetryRepairScript(Script):
    def __init__(self, root, *, first_failure="channel", repair_failure=None, repair_commentary=False):
        super().__init__(root)
        self.first_failure = first_failure
        self.repair_failure = repair_failure
        self.repair_commentary = repair_commentary
        self.generations = []
        self.repairs = []
        self.payload = None
        self.bad_raw = None
        self.was_pending = False

    def _respond(self, raw, options, *, commentary=False):
        if "response_format" in options:
            return LLMChatResult(text=raw, finish_reason="stop")
        return LLMChatResult(text="只修正 JSON 格式。" if commentary else "", finish_reason="tool_calls",
                             tool_calls=(LLMToolCall(id="result", name="faithsieve_result", arguments=raw),))

    def chat(self, endpoint, messages, **options):
        if messages[0]["content"] == REPAIR_SYSTEM_PROMPT:
            self.repairs.append((endpoint, copy.deepcopy(messages), copy.deepcopy(options)))
            if self.repair_failure == "pending" and not self.was_pending:
                self.was_pending = True
                raise Pending("json-repair")
            if self.repair_failure == "endpoint":
                raise LLMEndpointRequestError("格式修复端点暂时不可用", request_failure="connection")
            payload = copy.deepcopy(self.payload)
            if self.repair_failure == "changed_math":
                payload["artifacts"][TREE]["nodes"][1]["statement"] = "换成了另一个数学命题"
            elif self.repair_failure == "changed_state":
                payload["result"]["status"] = "inconclusive"
            raw = self.bad_raw if self.repair_failure == "still_invalid" else json.dumps(payload, ensure_ascii=False)
            return self._respond(raw, options, commentary=self.repair_commentary)

        reply = super().chat(endpoint, messages, **options)
        if messages[0]["content"].startswith("# Tree builder"):
            self.generations.append((endpoint, copy.deepcopy(messages), copy.deepcopy(options)))
            self.payload = json.loads(reply.tool_calls[0].arguments if reply.tool_calls else reply.text)
            self.bad_raw = json.dumps(self.payload, ensure_ascii=False) + "}"
            if len(self.generations) == 1 and self.first_failure == "channel":
                if "response_format" in options:
                    return LLMChatResult(text="", finish_reason="tool_calls", tool_calls=(
                        LLMToolCall(id="result", name="faithsieve_result", arguments=json.dumps(self.payload)),))
                # auto 模式允许完整 JSON 正文；错误函数仍必须失败，不能借正文降级。
                return LLMChatResult(text=json.dumps(self.payload, ensure_ascii=False), finish_reason="tool_calls", tool_calls=(
                    LLMToolCall(id="result", name="wrong_result_function", arguments=json.dumps(self.payload)),))
            return self._respond(self.bad_raw, options)
        return reply


def builder_records(engine):
    return {key: record for key, record in engine.checkpoints.records().items()
            if record["request"].get("role") == "tree-builder"}


def assert_isolated_frozen_repair(script, record):
    repair = record["metadata"]["json_repair"]
    _endpoint, messages, options = script.repairs[0]
    assert repair["raw_response"] == script.bad_raw
    assert messages == repair["request"]["messages"]
    assert messages[0]["content"] == REPAIR_SYSTEM_PROMPT
    assert script.bad_raw in messages[1]["content"]
    assert all(type(message["content"]) is str for message in messages)
    assert "problem.md" not in messages[1]["content"] and "pages.json" not in messages[1]["content"]
    assert "固定共享对象 x，给定命题1" not in messages[1]["content"]
    assert "data:image" not in messages[1]["content"]
    assert repair["request"]["endpoint"] == record["request"]["endpoint"]
    assert {key: value for key, value in options.items() if key != "timeout"} == {
        key: value for key, value in repair["request"]["call_options"].items() if key != "timeout"}
    assert not {"max_tokens", "max_output_tokens"} & options.keys()


@pytest.mark.parametrize("thinking,repair_commentary", [(False, False), (True, False), (True, True)])
def test_second_generation_syntax_uses_one_isolated_repair_then_continues_without_pipeline_restart(
        tmp_path, thinking, repair_commentary):
    script = RetryRepairScript(tmp_path, repair_commentary=repair_commentary)
    engine = seed(tmp_path, script, thinking=thinking)
    result = engine.run()
    assert result["verdict"] == "correct" and len(script.generations) == 2 and len(script.repairs) == 1
    assert len(script.native) == 3
    records = builder_records(engine)
    assert list(records) == ["role-000001-attempt-1", "role-000001-attempt-2"]
    first, second = records.values()
    assert first["state"] == "protocol_error" and "json_repair" not in first["metadata"]
    assert second["state"] == second["metadata"]["json_repair"]["state"] == "completed"
    assert second["request"]["node_selection_version"] == 1
    assert engine.store.read_json(TREE) == graph()
    assert_isolated_frozen_repair(script, second)
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native), len(script.generations), len(script.repairs))
    resumed = seed(tmp_path, script, thinking=thinking)
    assert resumed.run() == result
    assert checkpoint_bytes(resumed) == before
    assert (len(script.pure), len(script.native), len(script.generations), len(script.repairs)) == calls


@pytest.mark.parametrize("thinking", [False, True])
@pytest.mark.parametrize("failure", ["still_invalid", "changed_math", "changed_state", "endpoint"])
def test_second_generation_format_repair_failure_is_terminal_without_third_generation(tmp_path, thinking, failure):
    script = RetryRepairScript(tmp_path, repair_failure=failure)
    engine = seed(tmp_path, script, thinking=thinking)
    if failure == "endpoint":
        with pytest.raises(FaithSieveEndpointError):
            engine.run()
    else:
        assert engine.run()["verdict"] == "inconclusive"
    assert len(script.generations) == 2 and len(script.repairs) == 1 and not script.native
    records = builder_records(engine)
    assert len(records) == 2
    second = records["role-000001-attempt-2"]
    assert second["state"] == second["metadata"]["json_repair"]["state"] == (
        "endpoint_error" if failure == "endpoint" else "protocol_error")
    assert_isolated_frozen_repair(script, second)
    assert not engine.store.path(TREE).exists()
    assert not (engine.checkpoints.directory / "role-000001-attempt-3.json").exists()
    before, calls = checkpoint_bytes(engine), (len(script.generations), len(script.repairs))
    resumed = seed(tmp_path, script, thinking=thinking)
    if failure == "endpoint":
        with pytest.raises(FaithSieveEndpointError):
            resumed.run()
    else:
        assert resumed.run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(resumed) == before
    assert (len(script.generations), len(script.repairs)) == calls and not script.native


@pytest.mark.parametrize("thinking", [False, True])
def test_second_generation_pending_repair_resumes_only_exact_repair_and_keeps_first_failure(tmp_path, thinking):
    script = RetryRepairScript(tmp_path, repair_failure="pending")
    engine = seed(tmp_path, script, thinking=thinking)
    with pytest.raises(Pending):
        engine.run()
    records = builder_records(engine)
    first_before = engine.checkpoints._path("role-000001-attempt-1").read_bytes()
    pending = records["role-000001-attempt-2"]
    assert pending["state"] == pending["metadata"]["json_repair"]["state"] == "pending"
    assert len(script.generations) == 2 and len(script.repairs) == 1 and not script.native
    assert_isolated_frozen_repair(script, pending)
    resumed = seed(tmp_path, script, thinking=thinking)
    assert resumed.run()["verdict"] == "correct"
    assert len(script.generations) == 2 and len(script.repairs) == 2 and len(script.native) == 3
    assert script.repairs[0] == script.repairs[1]
    assert resumed.checkpoints._path("role-000001-attempt-1").read_bytes() == first_before
    completed = builder_records(resumed)["role-000001-attempt-2"]
    assert completed["request"] == pending["request"]
    assert completed["metadata"]["json_repair"]["request"] == pending["metadata"]["json_repair"]["request"]
    before, calls = checkpoint_bytes(resumed), (len(script.generations), len(script.repairs), len(script.native))
    assert resumed.run()["verdict"] == "correct"
    assert checkpoint_bytes(resumed) == before
    assert (len(script.generations), len(script.repairs), len(script.native)) == calls


@pytest.mark.parametrize("thinking", [False, True])
def test_pre_selector_epoch_still_rejects_second_generation_syntax_without_upgrade(tmp_path, thinking):
    script = RetryRepairScript(tmp_path)
    engine = seed(tmp_path, script, thinking=thinking)
    engine._select_node_selection_version = lambda: None
    assert engine.run()["verdict"] == "inconclusive"
    records = builder_records(engine)
    assert len(records) == 2 and len(script.generations) == 2 and not script.repairs and not script.native
    assert all(record["state"] == "protocol_error" and "json_repair" not in record["metadata"] for record in records.values())
    assert all("node_selection_version" not in record["request"] for record in records.values())
    before = checkpoint_bytes(engine)
    resumed = seed(tmp_path, script, thinking=thinking)
    assert resumed.run()["verdict"] == "inconclusive"
    assert resumed.node_selection_version is None
    assert checkpoint_bytes(resumed) == before
    assert len(script.generations) == 2 and not script.repairs and not script.native


@pytest.mark.parametrize("thinking", [False, True])
def test_first_generation_repair_failure_cannot_gain_second_generation_repair_opportunity(tmp_path, thinking):
    script = RetryRepairScript(tmp_path, first_failure="syntax", repair_failure="changed_math")
    engine = seed(tmp_path, script, thinking=thinking)
    assert engine.run()["verdict"] == "inconclusive"
    assert len(script.generations) == len(script.repairs) == 1 and not script.native
    records = builder_records(engine)
    assert list(records) == ["role-000001-attempt-1"]
    first = next(iter(records.values()))
    assert first["state"] == first["metadata"]["json_repair"]["state"] == "protocol_error"
    before = checkpoint_bytes(engine)
    assert seed(tmp_path, script, thinking=thinking).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before
    assert len(script.generations) == len(script.repairs) == 1 and not script.native
