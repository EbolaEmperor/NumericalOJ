"""实际发送的原文消息冻结，旧 JSON 输入仅用于完整已完成缓存的只读比对。"""

from copy import deepcopy
import json

import pytest

from backend.oj_modules.faithsieve import prompts, workflow
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from tests.unit.test_faithsieve_input_transport import decode_input_message
from tests.unit.test_faithsieve_transport import engine, json_response, openai_endpoint, response, role_result
from tests.unit.test_faithsieve_workflow import tree_payload


SOURCE_TEXT = "$$\n" + r"u(y)=\int_0^1 y(t)\,dt" + "\n$$\n"
SOURCE_FILES = {"problem.md": "条件与结论", workflow.SOURCE: SOURCE_TEXT}
NUMERIC_PARAMETERS = {"obligation_id": "E1-O1", "obligation_path": "faithsieve-work/obligations/E1/E1-O1.md",
                      "check_object_path": "faithsieve-work/formal/E1-O1-check.md",
                      "numeric_result_path": "faithsieve-work/formal/E1-O1-numeric.md"}


def numeric_payload():
    artifact = NUMERIC_PARAMETERS["numeric_result_path"]
    return {"result": {"status": "refuted", "artifact": artifact, "report": "精确关系不成立"},
            "artifacts": {artifact: "精确关系检验记录"}, "control": {}, "execution": {}}


def test_actual_pure_messages_preserve_newline_before_u_and_replay_without_call(tmp_path):
    calls = []
    def chat(_endpoint, messages, **options):
        calls.append(deepcopy(messages))
        assert options["reasoning_effort"] == "low"
        assert not {"stream", "require_complete_stream", "max_stream_bytes", "stream_options"}.intersection(options)
        return response(role_result())
    run = engine(tmp_path, chat, initial_reasoning_effort="low")
    run._invoke("decomposer", files=SOURCE_FILES)
    path = run.checkpoints._path("role-000001-attempt-1")
    saved = path.read_bytes()
    request = json.loads(saved)["request"]
    assert request["messages"] == calls[0]
    assert request["messages"][0]["content"] == request["prompt"]
    content = calls[0][1]["content"]
    assert decode_input_message(content)["input_files"] == SOURCE_FILES
    assert "$$\nu(y)" in content and r"$$\nu(y)" not in content
    assert r"\nu(y)" not in content
    assert request["call_options"]["reasoning_effort"] == "low"
    engine(tmp_path, lambda *_a, **_k: pytest.fail("已完成请求不能重复调用"),
           initial_reasoning_effort="low")._invoke("decomposer", files=SOURCE_FILES)
    assert len(calls) == 1 and path.read_bytes() == saved


@pytest.mark.parametrize("changed", ["system", "user", "missing_messages", "file_order"])
def test_completed_pure_cache_rejects_changed_actual_messages_before_call(tmp_path, changed):
    run = engine(tmp_path, lambda *_a, **_k: response(role_result()))
    run._invoke("decomposer", files=SOURCE_FILES)
    path = run.checkpoints._path("role-000001-attempt-1")
    record = json.loads(path.read_bytes())
    files = SOURCE_FILES
    if changed == "system":
        record["request"]["messages"][0]["content"] += "\n改变实际 system 内容"
    elif changed == "user":
        record["request"]["messages"][1]["content"] = record["request"]["messages"][1]["content"].replace(
            "\nu(y)", r"\nu(y)")
    elif changed == "missing_messages":
        record["request"].pop("messages")
    else:
        files = dict(reversed(list(SOURCE_FILES.items())))
    path.write_text(json.dumps(record, ensure_ascii=False))
    saved = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        engine(tmp_path, lambda *_a, **_k: pytest.fail("真实消息不一致不能调用模型"))._invoke(
            "decomposer", files=files)
    assert path.read_bytes() == saved


def test_native_prompt_is_frozen_and_pending_reentry_uses_identical_raw_input(tmp_path):
    class Pending(Exception):
        pass
    class Agent:
        def __init__(self):
            self.prompts = []
        def run_role(self, **options):
            self.prompts.append(options["prompt"])
            if len(self.prompts) == 1:
                raise Pending()
            return numeric_payload()
    agent = Agent()
    def run():
        instance = engine(tmp_path, lambda *_a, **_k: pytest.fail("native 不调用纯 LLM"))
        instance.agent = agent
        return instance._invoke("numeric-evaluator", files=SOURCE_FILES, parameters=NUMERIC_PARAMETERS)
    with pytest.raises(Pending):
        run()
    path = tmp_path / "faithsieve-work/checkpoints/role-000001-attempt-1.json"
    first = json.loads(path.read_bytes())
    assert first["state"] == "pending" and first["request"]["agent_prompt"] == agent.prompts[0]
    assert "$$\nu(y)" in agent.prompts[0] and r"$$\nu(y)" not in agent.prompts[0]
    run()
    assert agent.prompts == [first["request"]["agent_prompt"]] * 2
    saved = path.read_bytes()
    run()
    assert len(agent.prompts) == 2 and path.read_bytes() == saved


def test_native_prompt_tampering_cannot_reissue_agent(tmp_path):
    run = engine(tmp_path, lambda *_a, **_k: pytest.fail("不能调用模型"))
    class Agent:
        def run_role(self, **_options):
            return numeric_payload()
    run.agent = Agent()
    run._invoke("numeric-evaluator", files=SOURCE_FILES, parameters=NUMERIC_PARAMETERS)
    path = run.checkpoints._path("role-000001-attempt-1")
    record = json.loads(path.read_bytes())
    record["request"]["agent_prompt"] += "\n改变实际 Agent 内容"
    path.write_text(json.dumps(record, ensure_ascii=False))
    saved = path.read_bytes()
    resumed = engine(tmp_path, lambda *_a, **_k: pytest.fail("不能调用模型"))
    resumed.agent = None
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        resumed._invoke("numeric-evaluator", files=SOURCE_FILES, parameters=NUMERIC_PARAMETERS)
    assert path.read_bytes() == saved


@pytest.mark.parametrize("role", ["decomposer", "numeric-evaluator"])
@pytest.mark.parametrize("state", ["completed", "pending", "protocol_error", "endpoint_error"])
def test_legacy_full_role_inputs_are_compatible_only_after_completion(tmp_path, role, state):
    run = engine(tmp_path, lambda *_a, **_k: pytest.fail("旧输入不能重发模型"), initial_reasoning_effort="low")
    parameters = NUMERIC_PARAMETERS if role == "numeric-evaluator" else {}
    old_prompt = prompts.render_role_prompt(role, parameters, legacy_input=True)
    artifact, result_path = workflow._role_paths(role, parameters)
    request = {"role": role, "prompt": old_prompt, "files": SOURCE_FILES, "parameters": parameters,
               "revision_report": "", "expected_result_path": result_path, "endpoint": run._endpoint_identity()}
    if role == "decomposer":
        options = {**workflow.result_request_options(run.endpoint, fields={"status", "artifact", "report"},
                   statuses={"ok", "needs_revision", "inconclusive"}, artifact=artifact), "reasoning_effort": "low"}
        request.update(prompt=prompts.model_result_prompt(old_prompt, options, legacy_result=True), call_options=options)
    payload = numeric_payload() if role == "numeric-evaluator" else {**role_result(), "execution": {}}
    run.checkpoints.put("role-000001-attempt-1", request, state=state, response=payload)
    path = run.checkpoints._path("role-000001-attempt-1")
    saved = path.read_bytes()
    if state == "completed":
        run._invoke(role, files=SOURCE_FILES, parameters=parameters)
        assert run.store.read(artifact) == payload["artifacts"][artifact]
    else:
        with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
            run._invoke(role, files=SOURCE_FILES, parameters=parameters)
    assert path.read_bytes() == saved


def test_score_freezes_actual_messages_and_file_snapshots(tmp_path):
    grade = {"verdict": "correct", "score": 5, "comment": "证明充分。"}
    calls = []
    def chat(_endpoint, messages, **options):
        assert not {"stream", "require_complete_stream", "max_stream_bytes", "stream_options"}.intersection(options)
        calls.append(deepcopy(messages))
        return response(grade)
    run = engine(tmp_path, chat)
    for path, content in SOURCE_FILES.items():
        run.store.write(path, content)
    assert run._score("correct") == grade
    path = run.checkpoints._path("final-scoring")
    saved = path.read_bytes()
    request = json.loads(saved)["request"]
    assert request["messages"] == calls[0] and request["files"] == SOURCE_FILES
    assert decode_input_message(calls[0][1]["content"])["input_files"] == SOURCE_FILES
    assert decode_input_message(calls[0][1]["content"])["approved_verdict"] == "correct"
    assert run._score("correct") == grade and len(calls) == 1 and path.read_bytes() == saved


@pytest.mark.parametrize("state", ["completed", "pending", "protocol_error", "endpoint_error"])
def test_score_legacy_json_input_is_readonly_completed_compatibility(tmp_path, state):
    run = engine(tmp_path, lambda *_a, **_k: pytest.fail("评分旧请求不能重发"), initial_reasoning_effort="low")
    for path, content in SOURCE_FILES.items():
        run.store.write(path, content)
    options = {**workflow.result_request_options(run.endpoint, scoring=True), "reasoning_effort": "low"}
    request = {"endpoint": run._endpoint_identity(), "call_options": options, "messages": [
        {"role": "system", "content": prompts.model_result_prompt(prompts.LEGACY_SCORE_PROMPT, options, scoring=True, legacy_result=True)},
        {"role": "user", "content": prompts.legacy_json_input_message(
            run._files("problem.md", workflow.SOURCE, workflow.STEPS, workflow.TREE, workflow.EVIDENCE,
                       workflow.FINAL, "faithsieve-work/review/final.md"), approved_verdict="correct")},
    ]}
    grade = {"verdict": "correct", "score": 5, "comment": "历史原评分。"}
    run.checkpoints.put("final-scoring", request, state=state, response=grade)
    path = run.checkpoints._path("final-scoring")
    saved = path.read_bytes()
    if state == "completed":
        assert run._score("correct") == grade
    else:
        with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
            run._score("correct")
    assert path.read_bytes() == saved


TREE_FILES = {"problem.md": "题面条件与完整目标", workflow.STEPS: "## S1\n" + SOURCE_TEXT}


def old_tree_request(run, *, json_input=False, old_tree_transport=True, revision_report="核对原稿符号"):
    options = {**workflow.result_request_options(
        run.endpoint, fields={"status", "artifact", "report"},
        statuses={"ok", "needs_revision", "inconclusive"}, artifact=workflow.TREE,
    ), **run._initial_reasoning_options("tree-builder")}
    original_prompt = prompts.render_role_prompt(
        "tree-builder", legacy_input=json_input, legacy_tree_transport=old_tree_transport and not json_input,
    )
    prompt = prompts.model_result_prompt(original_prompt, options, tree=True, legacy_result=True)
    request = {
        "role": "tree-builder", "prompt": prompt, "files": TREE_FILES, "parameters": {},
        "revision_report": revision_report,
        "expected_result_path": "faithsieve-work/results/tree-builder.json",
        "endpoint": run._endpoint_identity(), "call_options": options,
    }
    if not json_input:
        request["messages"] = [{"role": "system", "content": prompt},
                               {"role": "user", "content": prompts.input_message(
                                   TREE_FILES, revision_report=revision_report)}]
    payload = {**role_result(json.dumps(tree_payload(), ensure_ascii=False), artifact=workflow.TREE),
               "execution": {}}
    return request, payload


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("state", ["completed", "pending", "protocol_error", "endpoint_error"])
def test_previous_raw_tree_prompt_is_readonly_completed_compatibility(tmp_path, json_mode, state):
    run = engine(tmp_path, lambda *_a, **_k: pytest.fail("旧树请求不能重新调用"),
                 endpoint=openai_endpoint() if json_mode else None, initial_reasoning_effort="low")
    request, payload = old_tree_request(run)
    assert request["prompt"] != prompts.model_result_prompt(
        prompts.render_role_prompt("tree-builder"), request["call_options"], tree=True)
    run.checkpoints.put("role-000001-attempt-1", request, state=state, response=payload)
    path = run.checkpoints._path("role-000001-attempt-1")
    saved = path.read_bytes()
    if state == "completed":
        output = run._invoke("tree-builder", files=TREE_FILES, revision_report=request["revision_report"])
        assert run.store.read(workflow.TREE) == payload["artifacts"][workflow.TREE]
        assert output.control["edge_units"] == ["E1"]
        assert output.control["edge_contexts"]["E1"]["parent_state"]["conditions"] == ["自然数"]
    else:
        with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
            run._invoke("tree-builder", files=TREE_FILES, revision_report=request["revision_report"])
    assert path.read_bytes() == saved


@pytest.mark.parametrize("json_mode", [False, True])
def test_previous_json_tree_prompt_completed_cache_remains_exact(tmp_path, json_mode):
    run = engine(tmp_path, lambda *_a, **_k: pytest.fail("旧 JSON 树不能重新调用"),
                 endpoint=openai_endpoint() if json_mode else None, initial_reasoning_effort="low")
    request, payload = old_tree_request(run, json_input=True)
    assert "messages" not in request
    run.checkpoints.put("role-000001-attempt-1", request, state="completed", response=payload)
    path = run.checkpoints._path("role-000001-attempt-1")
    saved = path.read_bytes()
    output = run._invoke("tree-builder", files=TREE_FILES, revision_report=request["revision_report"])
    assert output.control["edge_units"] == ["E1"] and path.read_bytes() == saved


@pytest.mark.parametrize("changed", ["prompt", "system", "user", "missing_messages", "files",
                                      "revision_report", "parameters", "endpoint", "schema", "effort",
                                      "expected_result_path"])
def test_previous_raw_tree_cache_requires_complete_request_identity(tmp_path, changed):
    run = engine(tmp_path, lambda *_a, **_k: pytest.fail("旧树身份不一致不能调用"),
                 initial_reasoning_effort="low")
    request, payload = old_tree_request(run)
    request = deepcopy(request)
    if changed == "prompt":
        request["prompt"] += "\n未保存的额外指令"
    elif changed in {"system", "user"}:
        request["messages"][0 if changed == "system" else 1]["content"] += "\n改写"
    elif changed == "missing_messages":
        request.pop("messages")
    elif changed == "files":
        request["files"][workflow.STEPS] += "\n改变原稿"
    elif changed == "endpoint":
        request["endpoint"]["model"] = "另一个模型"
    elif changed == "schema":
        request["call_options"]["tools"][0]["function"]["parameters"]["required"] = []
    elif changed == "effort":
        request["call_options"]["reasoning_effort"] = "medium"
    elif changed == "parameters":
        request["parameters"] = {"其他条件": "改变任务"}
    else:
        request[changed] += "改写"
    run.checkpoints.put("role-000001-attempt-1", request, state="completed", response=payload)
    path = run.checkpoints._path("role-000001-attempt-1")
    saved = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
        run._invoke("tree-builder", files=TREE_FILES, revision_report="核对原稿符号")
    assert path.read_bytes() == saved and not run.store.path(workflow.TREE).exists()


def test_previous_raw_tree_cached_response_still_passes_strict_tree_validator(tmp_path):
    run = engine(tmp_path, lambda *_a, **_k: pytest.fail("非法旧树不能重复调用"),
                 initial_reasoning_effort="low")
    request, payload = old_tree_request(run)
    tree = tree_payload()
    tree["edges"][0]["step_id"] = "S2"
    payload["artifacts"][workflow.TREE] = json.dumps(tree, ensure_ascii=False)
    run.checkpoints.put("role-000001-attempt-1", request, state="completed", response=payload)
    path = run.checkpoints._path("role-000001-attempt-1")
    saved = path.read_bytes()
    with pytest.raises(FaithSieveProtocolError):
        run._invoke("tree-builder", files=TREE_FILES, revision_report=request["revision_report"])
    assert path.read_bytes() == saved and not run.store.path(workflow.TREE).exists()


@pytest.mark.parametrize("json_mode", [False, True])
def test_new_tree_prompt_keeps_actual_input_options_and_budget(tmp_path, json_mode):
    calls = []
    payload = role_result(tree_payload(), artifact=workflow.TREE)
    def chat(_endpoint, messages, **options):
        calls.append((deepcopy(messages), deepcopy(options)))
        return json_response(payload) if json_mode else response(payload)
    run = engine(tmp_path, chat, endpoint=openai_endpoint() if json_mode else None,
                 initial_reasoning_effort="low")
    run._invoke("tree-builder", files=TREE_FILES, revision_report="核对原稿符号")
    request = run.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-1.json")["request"]
    assert calls[0][0] == request["messages"]
    assert calls[0][0][0]["content"] == request["prompt"]
    assert calls[0][0][1]["content"] == prompts.input_message(TREE_FILES, revision_report="核对原稿符号")
    assert request["call_options"] == calls[0][1]
    assert calls[0][1]["timeout"] == 600
    assert calls[0][1]["stream"] is True and calls[0][1]["require_complete_stream"] is True
    assert calls[0][1]["max_stream_bytes"] == 8 * 1024 * 1024
    assert calls[0][1].get("stream_options") == ({"include_usage": True} if json_mode else None)


@pytest.mark.parametrize("state", ["completed", "pending", "protocol_error", "endpoint_error"])
def test_plain_current_tree_request_cannot_switch_to_stream_unless_completed(tmp_path, state):
    run = engine(tmp_path, lambda *_a, **_k: pytest.fail("普通树请求不能重新发送流式调用"),
                 initial_reasoning_effort="low")
    request, payload = old_tree_request(run, old_tree_transport=False)
    assert "stream" not in request["call_options"]
    run.checkpoints.put("role-000001-attempt-1", request, state=state, response=payload)
    path = run.checkpoints._path("role-000001-attempt-1")
    saved = path.read_bytes()
    if state == "completed":
        output = run._invoke("tree-builder", files=TREE_FILES, revision_report=request["revision_report"])
        assert output.control["edge_units"] == ["E1"]
    else:
        with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
            run._invoke("tree-builder", files=TREE_FILES, revision_report=request["revision_report"])
    assert path.read_bytes() == saved


@pytest.mark.parametrize("state", ["completed", "pending", "protocol_error", "endpoint_error"])
@pytest.mark.parametrize("changed", ["stream", "require_complete_stream", "include_usage", "max_stream_bytes", "timeout"])
def test_frozen_tree_stream_types_are_checked_before_call_or_cache_replay(tmp_path, changed, state):
    run = engine(tmp_path, lambda *_a, **_k: response(role_result(tree_payload(), artifact=workflow.TREE)),
                 endpoint=openai_endpoint(enabled=True), initial_reasoning_effort="low")
    run._invoke("tree-builder", files=TREE_FILES)
    path = run.checkpoints._path("role-000001-attempt-1")
    record = json.loads(path.read_bytes())
    options = record["request"]["call_options"]
    if changed == "include_usage":
        options["stream_options"]["include_usage"] = 1
    elif changed in {"max_stream_bytes", "timeout"}:
        options[changed] = float(options[changed])
    else:
        options[changed] = 1
    record["state"] = state
    path.write_text(json.dumps(record, ensure_ascii=False))
    saved = path.read_bytes()
    replay = engine(tmp_path, lambda *_a, **_k: pytest.fail("流式类型漂移不能调用模型"),
                    endpoint=openai_endpoint(enabled=True), initial_reasoning_effort="low")
    with pytest.raises(FaithSieveProtocolError, match="类型无效"):
        replay._invoke("tree-builder", files=TREE_FILES)
    assert path.read_bytes() == saved
