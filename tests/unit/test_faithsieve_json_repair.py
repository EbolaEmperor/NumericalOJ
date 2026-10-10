"""仅完整 JSON 语法错误可做一次隔离格式修复，不重做数学任务。"""

from copy import deepcopy
import json

import pytest

from backend.oj_modules.ai.endpoints import LLMEndpointRequestError
from backend.oj_modules.faithsieve import prompts, recovery, workflow
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
from backend.oj_modules.faithsieve.json_repair import assert_repair_content_unchanged
from tests.unit.test_faithsieve_transport import engine, json_response, openai_endpoint, response, role_result
from tests.unit.test_faithsieve_workflow import tree_payload


CONTEXT_NOISE = "ORIGINAL_MATH_CONTEXT_DO_NOT_SEND_TO_REPAIR"
REVISION_NOISE = "ORIGINAL_REVISION_CONTEXT_DO_NOT_SEND_TO_REPAIR"
CONTENT = "## S1\n\n$$\n" + r"u(y)=\|y\|,\quad \Delta>0" + "\n$$\n原稿错误与未决范围保持原样。\n"
ROLE_PAYLOAD = role_result(CONTENT)
GRADE = {"verdict": "inconclusive", "score": 2, "comment": r"原稿的 \Delta 条件与 \|y\| 仍未得到可靠证据。"}
TREE = tree_payload()
for node in TREE["nodes"]:
    node["goal"] = r"原稿目标 \Delta 仍未解决。"
TREE_PAYLOAD = role_result(TREE, artifact=workflow.TREE)
TREE_PAYLOAD.pop("control")


def _payload(target):
    return {"role": ROLE_PAYLOAD, "tree": TREE_PAYLOAD, "score": GRADE}[target]


def _raw(payload, kind="invalid_escape"):
    text = json.dumps(payload, ensure_ascii=False)
    if kind == "invalid_escape":
        assert r"\\Delta" in text
        return text.replace(r"\\Delta", r"\Delta", 1)
    if kind == "extra_close":
        # 等价于真实闭合符号错误：完整有效对象后多出一个右括号。
        return text + "}"
    raise AssertionError(kind)


def _respond(payload=None, *, raw=None, json_mode=False, finish=None):
    if json_mode:
        return json_response(payload, text=raw, finish_reason=finish or "stop")
    return response(payload, arguments=raw, finish_reason=finish or "tool_calls")


def _run(root, chat, json_mode):
    # ON 模式冻结初始 low，OFF 模式不得隐式激活它。
    return engine(root, chat, endpoint=openai_endpoint(enabled=not json_mode), initial_reasoning_effort="low")


def _execute(run, target):
    if target == "score":
        return run._score("inconclusive")
    if target == "tree":
        return run._invoke("tree-builder", files={"problem.md": CONTEXT_NOISE, workflow.STEPS: "## S1\n原稿第 1 页：1=2。"},
                           revision_report=REVISION_NOISE)
    return run._invoke("decomposer", files={"problem.md": CONTEXT_NOISE}, revision_report=REVISION_NOISE)


def _key(target):
    return "final-scoring" if target == "score" else "role-000001-attempt-1"


def _seed_score(run, target):
    if target == "score":
        run.store.write("problem.md", CONTEXT_NOISE)
        run.store.write(workflow.FINAL, REVISION_NOISE)


def _assert_isolated_repair(calls, raw, repair):
    original, repaired = calls
    assert repaired[0] == original[0]
    assert repaired[2] == original[2]
    assert not {"max_tokens", "max_output_tokens"} & set(repaired[2])
    messages = repaired[1]
    assert messages == repair["request"]["messages"]
    assert raw in messages[1]["content"] and repair["parse_error"] in messages[1]["content"]
    assert repair["raw_response"] == raw
    assert repair["request"]["endpoint"] == original[0].to_public_dict()
    for message in messages:
        assert CONTEXT_NOISE not in message["content"]
        assert REVISION_NOISE not in message["content"]
        assert "# Decomposer" not in message["content"]
        assert "# Tree builder" not in message["content"]
        assert "# FaithSieve 评分" not in message["content"]


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("target", ["role", "tree", "score"])
def test_normal_completed_result_never_enters_repair_on_reentry(tmp_path, json_mode, target):
    calls = []
    def chat(*_args, **_options):
        calls.append(1)
        return _respond(_payload(target), json_mode=json_mode)
    run = _run(tmp_path, chat, json_mode)
    _seed_score(run, target)
    first = _execute(run, target)
    path = run.checkpoints._path(_key(target))
    saved = path.read_bytes()
    assert "json_repair" not in json.loads(saved).get("metadata", {})
    assert _execute(_run(tmp_path, lambda *_a, **_k: pytest.fail("正常完成不得修复或重发"), json_mode), target) == first
    assert len(calls) == 1 and path.read_bytes() == saved


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("target", ["role", "tree", "score"])
@pytest.mark.parametrize("syntax", ["invalid_escape", "extra_close"])
def test_one_isolated_repair_preserves_latex_states_and_completed_cache(tmp_path, json_mode, target, syntax):
    payload = _payload(target)
    raw = _raw(payload, syntax)
    calls = []
    def chat(endpoint, messages, **options):
        calls.append((endpoint, deepcopy(messages), deepcopy(options)))
        return _respond(payload, raw=raw if len(calls) == 1 else None, json_mode=json_mode)
    run = _run(tmp_path, chat, json_mode)
    _seed_score(run, target)
    result = _execute(run, target)
    assert len(calls) == 2
    path = run.checkpoints._path(_key(target))
    record = json.loads(path.read_text())
    assert record["state"] == "completed"
    repair = record["metadata"]["json_repair"]
    assert repair["state"] == "completed"
    _assert_isolated_repair(calls, raw, repair)
    if target == "role":
        assert result.result == payload["result"] and result.control == payload["control"]
        assert run.store.read(workflow.STEPS) == CONTENT
        assert not run.checkpoints._path("role-000001-attempt-2").exists()
    elif target == "tree":
        assert result.result == payload["result"] and result.control["edge_units"] == ["E1"]
        assert run.store.read_json(workflow.TREE) == TREE
        assert calls[0][2]["stream"] is True and calls[0][2]["require_complete_stream"] is True
        assert calls[0][2]["max_stream_bytes"] == 8 * 1024 * 1024
        assert not run.checkpoints._path("role-000001-attempt-2").exists()
    else:
        assert result == GRADE and run.store.read_json(workflow.RESULT) == GRADE
    before = {item: item.read_bytes() for item in path.parent.glob("*.json")}
    resumed = _run(tmp_path, lambda *_a, **_k: pytest.fail("完成缓存不得再次请求"), json_mode)
    replayed = _execute(resumed, target)
    assert replayed == result
    assert all(item.read_bytes() == saved for item, saved in before.items())


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("target", ["role", "tree", "score"])
@pytest.mark.parametrize("failure", ["still_invalid", "changed_math", "changed_state", "bad_fields", "empty_json"])
def test_failed_repair_is_terminal_without_a_third_mathematical_request(tmp_path, json_mode, target, failure):
    payload = _payload(target)
    raw = _raw(payload)
    second = deepcopy(payload)
    if failure == "changed_math":
        if target == "role":
            second["artifacts"][workflow.STEPS] = CONTENT.replace("u(y)", r"\nu(y)")
        elif target == "tree":
            second["artifacts"][workflow.TREE]["nodes"][1]["goal"] = "原稿目标已通过。"
        else:
            second["verdict"] = "correct"
    elif failure == "changed_state":
        if target == "score":
            second["score"] = 3
        else:
            second["result"]["status"] = "inconclusive"
    elif failure == "bad_fields":
        second = {"result": payload["result"]} if target != "score" else {"result": payload, "artifacts": {}}
    elif failure == "empty_json":
        second = {}
    calls = []
    def chat(endpoint, messages, **options):
        calls.append((endpoint, deepcopy(messages), deepcopy(options)))
        return _respond(second, raw=raw if len(calls) == 1 or failure == "still_invalid" else None,
                        json_mode=json_mode)
    run = _run(tmp_path, chat, json_mode)
    _seed_score(run, target)
    with pytest.raises(FaithSieveProtocolError):
        _execute(run, target)
    assert len(calls) == 2
    record = run.store.read_json(f"faithsieve-work/checkpoints/{_key(target)}.json")
    assert record["state"] == "protocol_error" and record["metadata"]["json_repair"]["state"] == "protocol_error"
    _assert_isolated_repair(calls, raw, record["metadata"]["json_repair"])
    artifact = {"role": workflow.STEPS, "tree": workflow.TREE, "score": workflow.RESULT}[target]
    assert not (tmp_path / artifact).exists()
    assert not run.checkpoints._path("role-000001-attempt-2").exists()
    with pytest.raises(FaithSieveProtocolError):
        _execute(_run(tmp_path, lambda *_a, **_k: pytest.fail("修复失败不得第三次请求"), json_mode), target)


class RepairPending(Exception):
    pass


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("target", ["role", "tree", "score"])
def test_pending_repair_resumes_frozen_repair_only_without_repeating_original_role(tmp_path, json_mode, target):
    payload = _payload(target)
    raw = _raw(payload)
    calls = []
    def initial(endpoint, messages, **options):
        calls.append((endpoint, deepcopy(messages), deepcopy(options)))
        if len(calls) == 1:
            return _respond(raw=raw, json_mode=json_mode)
        raise RepairPending("修复请求尚未返回")
    run = _run(tmp_path, initial, json_mode)
    _seed_score(run, target)
    with pytest.raises(RepairPending):
        _execute(run, target)
    path = run.checkpoints._path(_key(target))
    pending = json.loads(path.read_text())
    assert pending["metadata"]["json_repair"]["state"] == "pending"
    _assert_isolated_repair(calls, raw, pending["metadata"]["json_repair"])
    resumed_calls = []
    def resumed(endpoint, messages, **options):
        resumed_calls.append((endpoint, deepcopy(messages), deepcopy(options)))
        return _respond(payload, json_mode=json_mode)
    _execute(_run(tmp_path, resumed, json_mode), target)
    assert resumed_calls == [calls[1]]
    completed = json.loads(path.read_text())
    assert completed["request"] == pending["request"] and completed["state"] == "completed"
    assert len(calls) == 2 and not run.checkpoints._path("role-000001-attempt-2").exists()


@pytest.mark.parametrize("json_mode", [False, True])
def test_pending_repair_rejects_equal_but_differently_typed_frozen_endpoint(tmp_path, json_mode):
    calls = []
    def chat(*_args, **_options):
        calls.append(1)
        if len(calls) == 1:
            return _respond(raw=_raw(ROLE_PAYLOAD), json_mode=json_mode)
        raise RepairPending("修复未返回")
    run = _run(tmp_path, chat, json_mode)
    with pytest.raises(RepairPending):
        _execute(run, "role")
    path = run.checkpoints._path(_key("role"))
    record = json.loads(path.read_text())
    identity = record["metadata"]["json_repair"]["request"]["endpoint"]
    identity["id"] = float(identity["id"])
    path.write_text(json.dumps(record, ensure_ascii=False))
    saved = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        _execute(_run(tmp_path, lambda *_a, **_k: pytest.fail("冻结修复身份被改动不得请求"), json_mode), "role")
    assert len(calls) == 2
    assert json.loads(path.read_bytes())["request"] == json.loads(saved)["request"]


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("target", ["role", "tree", "score"])
def test_repair_endpoint_error_is_terminal_and_not_authorized_as_another_role_attempt(tmp_path, json_mode, target):
    calls = []
    def chat(*_args, **_options):
        calls.append(1)
        if len(calls) == 1:
            return _respond(raw=_raw(_payload(target)), json_mode=json_mode)
        raise LLMEndpointRequestError("VENDOR_PRIVATE_RESPONSE", status_code=503)
    run = _run(tmp_path, chat, json_mode)
    _seed_score(run, target)
    with pytest.raises(FaithSieveEndpointError):
        _execute(run, target)
    path = run.checkpoints._path(_key(target))
    saved = path.read_bytes()
    record = json.loads(saved)
    assert record["state"] == record["metadata"]["json_repair"]["state"] == "endpoint_error"
    assert "VENDOR_PRIVATE_RESPONSE" not in saved.decode()
    with pytest.raises(FaithSieveEndpointError):
        _execute(_run(tmp_path, lambda *_a, **_k: pytest.fail("修复 HTTP 失败不得第三次调用"), json_mode), target)
    assert len(calls) == 2 and path.read_bytes() == saved
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.recovery_target(tmp_path)
    assert not run.checkpoints._path("role-000001-attempt-2").exists()


def test_content_guard_rejects_container_type_change_even_when_all_scalars_are_identical():
    with pytest.raises(FaithSieveProtocolError, match="已有容器"):
        assert_repair_content_unchanged('{"a":[]}}', '{"a":{}}')


@pytest.mark.parametrize("original,repaired", [
    ('{"a":{"x":1},"y":2,}', '{"a":{"x":1,"y":2}}'),
    ('{"a":[1],"b":[2],}', '{"a":[1,"b",[2]]}'),
])
def test_content_guard_rejects_changed_parent_or_array_ownership_with_same_leaf_sequence(original, repaired):
    with pytest.raises(FaithSieveProtocolError, match="已有容器"):
        assert_repair_content_unchanged(original, repaired)


@pytest.mark.parametrize("original,repaired", [
    ('{"a":{"x":1},"b":[2]}', '{"a":{"x":1},"b":[2]}'),
    ('{"a":{"x":1}},"b":[2]}', '{"a":{"x":1},"b":[2]}'),
    ('{"a":{"x":1,},"b":[2,],}', '{"a":{"x":1},"b":[2]}'),
])
def test_content_guard_accepts_same_groups_root_closed_early_and_trailing_commas(original, repaired):
    assert_repair_content_unchanged(original, repaired)


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("target", ["role", "score"])
@pytest.mark.parametrize("alias", ["float", "bool"])
def test_repair_parent_request_rejects_equal_endpoint_id_type_alias_without_calls(tmp_path, json_mode, target, alias):
    original = openai_endpoint(enabled=not json_mode)
    endpoint = workflow.LLMEndpointSnapshot.from_mapping({**original.to_public_dict(), "api_key": original.api_key,
                                                         "id": 7 if alias == "float" else 1})
    calls = []
    def chat(*_args, **_options):
        calls.append(1)
        return _respond(_payload(target), raw=_raw(_payload(target)) if len(calls) == 1 else None, json_mode=json_mode)
    run = engine(tmp_path, chat, endpoint=endpoint, initial_reasoning_effort="low")
    _seed_score(run, target)
    _execute(run, target)
    path = run.checkpoints._path(_key(target))
    record = json.loads(path.read_text())
    record["request"]["endpoint"]["id"] = 7.0 if alias == "float" else True
    path.write_text(json.dumps(record, ensure_ascii=False))
    saved = path.read_bytes()
    resumed = engine(tmp_path, lambda *_a, **_k: pytest.fail("修复父请求身份类型漂移不得请求"),
                     endpoint=endpoint, initial_reasoning_effort="low")
    with pytest.raises(FaithSieveProtocolError, match="字段类型或完整输入不一致"):
        _execute(resumed, target)
    assert len(calls) == 2 and path.read_bytes() == saved


@pytest.mark.parametrize("invalid_state", [[], {}])
def test_repair_metadata_state_list_or_dict_is_protocol_error_without_type_error_or_calls(tmp_path, invalid_state):
    calls = []
    def chat(*_args, **_options):
        calls.append(1)
        return _respond(ROLE_PAYLOAD, raw=_raw(ROLE_PAYLOAD) if len(calls) == 1 else None)
    run = _run(tmp_path, chat, False)
    _execute(run, "role")
    path = run.checkpoints._path(_key("role"))
    record = json.loads(path.read_text())
    record["metadata"]["json_repair"]["state"] = invalid_state
    path.write_text(json.dumps(record, ensure_ascii=False))
    saved = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="元数据无效"):
        _execute(_run(tmp_path, lambda *_a, **_k: pytest.fail("非法修复状态不得请求"), False), "role")
    assert len(calls) == 2 and path.read_bytes() == saved


@pytest.mark.parametrize("json_mode", [False, True])
def test_old_completed_without_repair_still_replays_original_tail_exactly(tmp_path, json_mode):
    run = _run(tmp_path, lambda *_a, **_k: _respond(ROLE_PAYLOAD, json_mode=json_mode), json_mode)
    _execute(run, "role")
    path = run.checkpoints._path(_key("role"))
    record = json.loads(path.read_text())
    assert "json_repair" not in record["metadata"]
    old_prompt = prompts.model_result_prompt(prompts.render_role_prompt("decomposer"),
                                            record["request"]["call_options"], legacy_result=True)
    record["request"]["prompt"] = old_prompt
    record["request"]["messages"][0]["content"] = old_prompt
    path.write_text(json.dumps(record, ensure_ascii=False))
    saved = path.read_bytes()
    output = _execute(_run(tmp_path, lambda *_a, **_k: pytest.fail("旧已完成请求不得重发或修复"), json_mode), "role")
    assert output.result == ROLE_PAYLOAD["result"] and path.read_bytes() == saved


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("target", ["role", "tree", "score"])
def test_complete_but_ambiguous_unclosed_string_stops_without_repair_or_regeneration(tmp_path, json_mode, target):
    calls = []
    raw = '{"verdict":"inconclusive","comment":"未闭合' if target == "score" else '{"result":{"status":"ok","report":"未闭合'
    def chat(*_args, **_options):
        calls.append(1)
        return _respond(raw=raw, json_mode=json_mode)
    run = _run(tmp_path, chat, json_mode)
    _seed_score(run, target)
    with pytest.raises(FaithSieveProtocolError):
        _execute(run, target)
    path = run.checkpoints._path(_key(target))
    assert json.loads(path.read_text())["state"] == "protocol_error"
    assert len(calls) == 1 and not run.checkpoints._path("role-000001-attempt-2").exists()
    with pytest.raises(FaithSieveProtocolError):
        _execute(_run(tmp_path, lambda *_a, **_k: pytest.fail("歧义原文终态不得重新请求"), json_mode), target)
    assert len(calls) == 1


@pytest.mark.parametrize("json_mode", [False, True])
def test_missing_complete_finish_retains_original_protocol_retry_without_repair(tmp_path, json_mode):
    calls = []
    raw = _raw(ROLE_PAYLOAD)
    def chat(_endpoint, messages, **_options):
        calls.append(deepcopy(messages))
        if len(calls) == 1:
            return json_response(text=raw) if json_mode else response(arguments=raw)
        return _respond(ROLE_PAYLOAD, json_mode=json_mode)
    run = _run(tmp_path, chat, json_mode)
    assert _execute(run, "role").result == ROLE_PAYLOAD["result"]
    assert len(calls) == 2 and calls[1][0]["content"].startswith("# Decomposer")
    assert CONTEXT_NOISE in calls[1][1]["content"]
    assert all("json_repair" not in json.loads(path.read_text()).get("metadata", {})
               for path in run.checkpoints.directory.glob("*.json"))


@pytest.mark.parametrize("json_mode", [False, True])
def test_pending_with_completed_score_repair_fails_original_verdict_gate_without_another_request(tmp_path, json_mode):
    wrong = {**GRADE, "verdict": "correct", "score": 5}
    calls = []
    def chat(*_args, **_options):
        calls.append(1)
        return _respond(wrong, raw=_raw(wrong) if len(calls) == 1 else None, json_mode=json_mode)
    run = _run(tmp_path, chat, json_mode)
    _seed_score(run, "score")
    with pytest.raises(FaithSieveProtocolError, match="已经独立审计通过"):
        _execute(run, "score")
    path = run.checkpoints._path("final-scoring")
    record = json.loads(path.read_text())
    # 模拟修复完成、原评分门槛尚未核验时的正常 pending 窗口。
    record["state"] = "pending"
    record.pop("error", None)
    record["metadata"]["json_repair"]["state"] = "completed"
    record["metadata"]["json_repair"].pop("error", None)
    path.write_text(json.dumps(record, ensure_ascii=False))
    resumed = _run(tmp_path, lambda *_a, **_k: pytest.fail("完成的修复不得重新调用"), json_mode)
    with pytest.raises(FaithSieveProtocolError, match="已经独立审计通过"):
        _execute(resumed, "score")
    final = json.loads(path.read_text())
    assert final["state"] == final["metadata"]["json_repair"]["state"] == "protocol_error"
    saved = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError):
        _execute(_run(tmp_path, lambda *_a, **_k: pytest.fail("评分门槛失败不得再次请求"), json_mode), "score")
    assert len(calls) == 2 and path.read_bytes() == saved
    assert not (tmp_path / workflow.RESULT).exists()


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("failure", ["truncated", "duplicate_key", "valid_bad_fields", "wrong_tool"])
def test_non_syntax_failures_never_receive_dedicated_repair(tmp_path, json_mode, failure):
    raw = _raw(ROLE_PAYLOAD)
    first = _respond(raw=raw, json_mode=json_mode)
    if failure == "truncated":
        first = _respond(raw=raw, json_mode=json_mode, finish="length")
    elif failure == "duplicate_key":
        text = json.dumps(ROLE_PAYLOAD, ensure_ascii=False)
        text = text[:-1] + ',"control":{}}'
        first = _respond(raw=text, json_mode=json_mode)
    elif failure == "valid_bad_fields":
        first = _respond(ROLE_PAYLOAD["result"], json_mode=json_mode)
    else:
        first = response(arguments=raw, name="different_tool", finish_reason="tool_calls")
    calls = []
    def chat(_endpoint, messages, **_options):
        calls.append(deepcopy(messages))
        return first if len(calls) == 1 else _respond(ROLE_PAYLOAD, json_mode=json_mode)
    run = _run(tmp_path, chat, json_mode)
    assert _execute(run, "role").result == ROLE_PAYLOAD["result"]
    assert len(calls) == 2
    assert calls[1][0]["content"].startswith("# Decomposer")
    assert CONTEXT_NOISE in calls[1][1]["content"]
    records = [json.loads(path.read_text()) for path in run.checkpoints.directory.glob("*.json")]
    assert all("json_repair" not in record.get("metadata", {}) for record in records)
