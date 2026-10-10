"""排序只改变验证顺序：完整闭包、图返修、冻结回退及只读展示。"""

from collections import Counter
import copy
import json

import pytest

from backend.oj_modules.ai.endpoints import LLMChatResult, LLMEndpointRequestError, LLMToolCall
from backend.oj_modules.faithsieve import views
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.dependency_workflow import NODE_VERIFICATION
from backend.oj_modules.faithsieve.node_selection import (
    NODE_SELECTION_FALLBACK_REASON, NODE_SELECTION_PATH, default_node_selection_order,
    parse_node_selection, validate_node_selection, validate_node_selection_fallback,
    validate_node_selection_version,
)
from backend.oj_modules.faithsieve.workflow import TREE, WORK
from tests.unit.test_faithsieve_image_repair import RepairScript, checkpoint_bytes, make_engine
from tests.unit.test_faithsieve_image_workflow import Pending, Script, graph, mathematical_records, seed
from tests.unit.test_faithsieve_input_transport import decode_input_message
from tests.unit.test_faithsieve_views import saved  # noqa: F401；复用安全展示工作区 fixture。


def replace_payload(response, mutate):
    payload = json.loads(response.tool_calls[0].arguments if response.tool_calls else response.text)
    mutate(payload)
    raw = json.dumps(payload, ensure_ascii=False)
    if response.tool_calls:
        return LLMChatResult(text="", tool_calls=(LLMToolCall(id="result", name="faithsieve_result", arguments=raw),),
                             finish_reason="tool_calls")
    return LLMChatResult(text=raw, finish_reason="stop")


class SelectionScript(Script):
    def __init__(self, root, *, selection=None, selector_status="ok", selector_control=None,
                 endpoint_error=False, selector_pending=False, audit_status="ok", statuses=None):
        super().__init__(root, statuses=statuses)
        self.selection = selection if selection is not None else {"node_ids": ["N2", "N4", "N3"]}
        self.selector_status = selector_status
        self.selector_control = selector_control or {}
        self.endpoint_error = endpoint_error
        self.selector_pending = selector_pending
        self.audit_status = audit_status
        self.selection_calls = 0

    def chat(self, endpoint, messages, **options):
        response = super().chat(endpoint, messages, **options)
        if messages[0]["content"].startswith("# Node selector"):
            self.selection_calls += 1
            if self.selector_pending:
                self.selector_pending = False
                raise Pending("node-selector")
            if self.endpoint_error:
                raise LLMEndpointRequestError("排序端点暂时无法连接", request_failure="connection")

            def mutate(payload):
                payload["result"].update(status=self.selector_status, report="优先级说明::不得传给局部 Judge")
                payload["artifacts"][NODE_SELECTION_PATH] = (
                    self.selection if type(self.selection) is str else json.dumps(self.selection, ensure_ascii=False))
                payload["control"] = copy.deepcopy(self.selector_control)

            return replace_payload(response, mutate)
        if messages[0]["content"].startswith("# Verification auditor") and self.audit_status != "ok":
            return replace_payload(response, lambda payload: payload["result"].update(status=self.audit_status))
        return response


def native_nodes(script):
    return [request["expected_result_path"].rsplit("/", 1)[-1].split("-local-verifier")[0]
            for request in script.native]


def selector_records(engine):
    return {key: record for key, record in engine.checkpoints.records().items()
            if record["request"].get("role") == "node-selector"}


@pytest.mark.parametrize("version", [None, 1])
def test_selection_version_is_frozen_exact_integer(version):
    assert validate_node_selection_version(version) == version


@pytest.mark.parametrize("version", [True, False, 1.0, 0, 2, "1", {}, []])
def test_selection_version_rejects_coercion(version):
    with pytest.raises(FaithSieveProtocolError):
        validate_node_selection_version(version)


@pytest.mark.parametrize("order", [["N2", "N4", "N3"], ["N4", "N3", "N2"], ["N3", "N2", "N4"]])
def test_complete_permutation_is_copied_without_changing_original(order):
    value = {"node_ids": order}
    before = copy.deepcopy(value)
    result = validate_node_selection(value, required_node_ids=["N4", "N3", "N2"])
    assert result == value and value == before
    assert result is not value and result["node_ids"] is not order
    assert parse_node_selection(json.dumps(value), required_node_ids=["N2", "N3", "N4"]) == value


INVALID_SELECTIONS = [
    {"node_ids": ["N4"]}, {"node_ids": ["N4", "N3", "N2", "N2"]},
    {"node_ids": ["N4", "N3", "N1"]}, {"node_ids": ["N4", "N3", "N5"]},
    {"node_ids": ["N4", "N3", "N99"]}, {"node_ids": ["N4", "N3", "n2"]},
    {"node_ids": ["N4", "N3", "Ｎ2"]}, {"node_ids": ["N4", "N3", "N02"]},
    {"node_ids": ["N4", "N3", 2]}, {"node_ids": ["N4", "N3", True]},
    {"node_ids": ["N4", "N3", {}]}, {"node_ids": "N4,N3,N2"},
    {"node_ids": None}, {"node_ids": ["N4", "N3", "N2"], "verdict": "correct"},
    {"node_ids": ["N4", "N3", "N2"], "node_verdicts": {"N2": "passed"}},
    {"nodes": ["N4", "N3", "N2"]}, [], None,
]


@pytest.mark.parametrize("value", INVALID_SELECTIONS)
def test_order_must_exactly_cover_required_claims(value):
    with pytest.raises(FaithSieveProtocolError):
        validate_node_selection(value, required_node_ids=["N2", "N3", "N4"])


@pytest.mark.parametrize("content", ["```json\n{\"node_ids\": []}\n```", "说明\n{\"node_ids\": []}",
                                      "[]", "{broken", {}, b'{"node_ids": []}'])
def test_selection_artifact_is_pure_json_object(content):
    with pytest.raises(FaithSieveProtocolError):
        parse_node_selection(content, required_node_ids=[])


def test_reverse_fallback_contains_only_required_claims():
    dag = graph()
    assert default_node_selection_order(dag) == ["N4", "N3", "N2"]
    dag["target_ids"] = ["N5"]
    assert default_node_selection_order(dag) == ["N5"]


@pytest.mark.parametrize("thinking", [False, True])
def test_non_target_refutation_is_audited_before_early_stop_with_complete_context(tmp_path, thinking):
    script = SelectionScript(tmp_path, statuses={"N2": "refuted", "N3": "passed", "N4": "passed", "N5": "passed"})
    engine = seed(tmp_path, script, thinking=thinking)
    result = engine.run()
    assert result["verdict"] == "incorrect" and result["score"] == 2
    assert native_nodes(script) == ["N2"]
    assert [role for role, _messages, _options in script.pure] == [
        "tree-builder", "tree-auditor", "node-selector", "verification-auditor",
        "evidence-mapper", "final-synthesizer", "consistency-auditor", "scoring"]
    local = script.native[0]
    assert set(local["files"]) == {"problem.md", "pages.json", f"{WORK}/obligations/N2/N2-O1.md",
                                    "source-pages/page-1.png", "source-pages/page-2.png"}
    context = json.loads(local["files"][f"{WORK}/obligations/N2/N2-O1.md"])
    assert context["node"] == graph()["nodes"][1] and context["premises"] == [graph()["nodes"][0]]
    assert "优先级说明" not in local["prompt"] and NODE_SELECTION_PATH not in local["files"]
    summary = engine.store.read_json(NODE_VERIFICATION)
    assert summary["nodes"]["N2"]["local_status"] == "refuted"
    assert summary["nodes"]["N3"]["local_status"] == summary["nodes"]["N4"]["local_status"] == "not_checked"
    assert engine._reliable_error() == "N2"


def test_selector_priority_cannot_make_unaudited_refutation_stop_or_enter_ledger(tmp_path):
    script = SelectionScript(tmp_path, audit_status="inconclusive",
                             statuses={"N2": "refuted", "N3": "passed", "N4": "passed", "N5": "passed"})
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "inconclusive"
    assert native_nodes(script) == ["N2", "N4", "N3"]
    assert engine.store.read_json(NODE_VERIFICATION)["nodes"]["N2"]["local_status"] == "inconclusive"
    assert engine._reliable_error() is None


def test_custom_order_requires_all_claims_before_correct_and_reentry_is_readonly(tmp_path):
    script = SelectionScript(tmp_path)
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "correct" and native_nodes(script) == ["N2", "N4", "N3"]
    assert engine.store.read_json(NODE_VERIFICATION)["targets_established"] is True
    assert engine.store.read_json(NODE_SELECTION_PATH) == {"node_ids": ["N2", "N4", "N3"]}
    assert len(selector_records(engine)) == script.selection_calls == 1
    assert all(record["request"]["node_selection_version"] == 1 for record in mathematical_records(engine.checkpoints.records()).values())
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native), script.selection_calls)
    assert engine.run() == result
    assert (len(script.pure), len(script.native), script.selection_calls) == calls
    assert checkpoint_bytes(engine) == before


def test_pending_selector_reentry_preserves_frozen_messages_and_does_not_start_judge_early(tmp_path):
    script = SelectionScript(tmp_path, selector_pending=True)
    engine = seed(tmp_path, script)
    with pytest.raises(Pending):
        engine.run()
    assert not script.native and script.selection_calls == 1
    key, record = next(iter(selector_records(engine).items()))
    assert record["state"] == "pending" and "node_selection_fallback" not in record["metadata"]
    assert record["request"]["node_selection_version"] == 1
    frozen_completed = {name: content for name, content in checkpoint_bytes(engine).items()
                        if json.loads(content)["state"] == "completed"}
    resumed = seed(tmp_path, script)
    assert resumed.run()["verdict"] == "correct"
    current = selector_records(resumed)
    assert list(current) == [key] and current[key]["request"] == record["request"]
    requests = [messages for role, messages, _options in script.pure if role == "node-selector"]
    assert len(requests) == 2 and requests[0] == requests[1] == record["request"]["messages"]
    assert native_nodes(script) == ["N2", "N4", "N3"]
    assert all((resumed.checkpoints.directory / name).read_bytes() == content
               for name, content in frozen_completed.items())


@pytest.mark.parametrize("selection", INVALID_SELECTIONS + ["{broken"])
def test_invalid_order_falls_back_once_without_omitting_unknown_ancestor(tmp_path, selection):
    script = SelectionScript(tmp_path, selection=selection,
                             statuses={"N2": "inconclusive", "N3": "passed", "N4": "passed", "N5": "passed"})
    # None 在 fixture 中表示默认响应；此用例必须保留实际非法 null。
    script.selection = selection
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "inconclusive" and result["score"] == 2
    assert native_nodes(script) == ["N4", "N3", "N2"]
    assert engine.store.read_json(NODE_VERIFICATION)["nodes"]["N4"]["status"] == "blocked"
    records = selector_records(engine)
    assert len(records) == script.selection_calls == 1
    record = next(iter(records.values()))
    assert record["state"] == "protocol_error"
    assert record.get("response") is None
    assert record["metadata"]["node_selection_fallback"] == {
        "version": 1, "code_validated": True, "node_ids": ["N4", "N3", "N2"], "reason": NODE_SELECTION_FALLBACK_REASON}
    assert engine.store.read_json(NODE_SELECTION_PATH) == {"node_ids": ["N4", "N3", "N2"]}
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native), script.selection_calls)
    assert engine.run() == result
    assert (len(script.pure), len(script.native), script.selection_calls) == calls
    assert checkpoint_bytes(engine) == before


@pytest.mark.parametrize("options,state", [
    ({"endpoint_error": True}, "endpoint_error"),
    ({"selector_status": "inconclusive"}, "completed"),
    ({"selector_status": "passed"}, "protocol_error"),
    ({"selector_control": {"skip_verification": True}}, "protocol_error"),
])
def test_optional_sort_failure_freezes_original_terminal_state_and_default_order(tmp_path, options, state):
    script = SelectionScript(tmp_path, **options)
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "correct" and native_nodes(script) == ["N4", "N3", "N2"]
    records = selector_records(engine)
    assert len(records) == 1
    record = next(iter(records.values()))
    assert record["state"] == state
    assert validate_node_selection_fallback(record["metadata"]["node_selection_fallback"],
                                             expected_node_ids=["N4", "N3", "N2"])["code_validated"] is True
    if state == "endpoint_error":
        assert record["metadata"]["endpoint_error"]["request_failure"] == "connection"
        assert record.get("response") is None
    elif state == "completed":
        assert record["response"]["result"]["status"] == "inconclusive"
        assert json.loads(record["response"]["artifacts"][NODE_SELECTION_PATH]) == {"node_ids": ["N2", "N4", "N3"]}
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native), script.selection_calls)
    assert engine.run() == result
    assert checkpoint_bytes(engine) == before
    assert (len(script.pure), len(script.native), script.selection_calls) == calls


@pytest.mark.parametrize("field,value", [
    ("version", True), ("code_validated", 1), ("code_validated", False), ("reason", "模型自己确认安全"),
    ("node_ids", ["N4"]), ("node_ids", ["N2", "N4", "N3"]),
])
def test_corrupt_frozen_fallback_cannot_certify_or_repeat_selector(tmp_path, field, value):
    script = SelectionScript(tmp_path, endpoint_error=True)
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    key, record = next(iter(selector_records(engine).items()))
    path = engine.checkpoints.directory / f"{key}.json"
    record["metadata"]["node_selection_fallback"][field] = value
    path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native), script.selection_calls)
    assert engine.run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before
    assert (len(script.pure), len(script.native), script.selection_calls) == calls


def test_failed_selector_requires_exact_original_graph_identity_for_fallback(tmp_path):
    script = SelectionScript(tmp_path, endpoint_error=True)
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    key, record = next(iter(selector_records(engine).items()))
    altered = graph()
    altered["nodes"][1]["statement"] = "被改写的条件"
    record["request"]["files"][TREE] = json.dumps(altered, ensure_ascii=False)
    (engine.checkpoints.directory / f"{key}.json").write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native), script.selection_calls)
    assert engine.run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before
    assert (len(script.pure), len(script.native), script.selection_calls) == calls


@pytest.mark.parametrize("pending", [False, True])
def test_prior_diagnostic_projection_epoch_never_gains_selector_or_changes_pending_identity(tmp_path, pending):
    script = SelectionScript(tmp_path)
    engine = seed(tmp_path, script)
    engine._select_node_selection_version = lambda: None
    if pending:
        script.pending = "N4"
        with pytest.raises(Pending):
            engine.run()
        original_pending = copy.deepcopy(script.native[-1])
    else:
        assert engine.run()["verdict"] == "correct"
    frozen = checkpoint_bytes(engine)
    records = engine.checkpoints.records()
    assert all(record["request"]["local_diagnostic_version"] == 1 for record in mathematical_records(records).values())
    assert all(record["request"]["result_projection_version"] == 1 for record in mathematical_records(records).values())
    assert all("node_selection_version" not in record["request"] for record in records.values())
    before_native, before_pure = len(script.native), len(script.pure)
    resumed = seed(tmp_path, script)
    assert resumed.run()["verdict"] == "correct"
    assert script.selection_calls == 0 and resumed.node_selection_version is None
    if pending:
        assert script.native[before_native] == original_pending
        assert native_nodes(script) == ["N4", "N4", "N3", "N2"]
        for name, content in frozen.items():
            if json.loads(content)["state"] == "completed":
                assert (resumed.checkpoints.directory / name).read_bytes() == content
    else:
        assert checkpoint_bytes(resumed) == frozen
        assert (len(script.native), len(script.pure)) == (before_native, before_pure)


def test_successful_graph_repair_selects_again_and_reuses_unchanged_implications(tmp_path):
    script = RepairScript(tmp_path)
    original = script.chat
    selected_graphs = []

    def chat(endpoint, messages, **options):
        response = original(endpoint, messages, **options)
        if messages[0]["content"].startswith("# Node selector"):
            files = decode_input_message(messages[1]["content"][0]["text"])["input_files"]
            selected_graphs.append(json.loads(files[TREE]))
            order = ["N5", "N4", "N3", "N2"] if len(selected_graphs) == 1 else ["N2", "N3", "N4", "N5"]
            return replace_payload(response, lambda payload: payload["artifacts"].update(
                {NODE_SELECTION_PATH: json.dumps({"node_ids": order})}))
        return response

    engine = make_engine(tmp_path, script)
    engine.chat = chat
    result = engine.run()
    assert result["verdict"] == "correct" and selected_graphs == [script.initial_graph, script.repaired_graph]
    assert [call["node"] for call in script.native] == ["N5", "N4", "N3", "N2", "N3", "N4"]
    assert Counter(call["node"] for call in script.native) == {"N2": 1, "N3": 2, "N4": 2, "N5": 1}
    assert len(selector_records(engine)) == 2
    assert engine.store.read_json(NODE_SELECTION_PATH) == {"node_ids": ["N2", "N3", "N4", "N5"]}
    for call in script.native:
        assert NODE_SELECTION_PATH not in call["request"]["files"]
    before, counts = checkpoint_bytes(engine), (len(script.pure), len(script.native), len(selected_graphs))
    assert engine.run() == result
    assert checkpoint_bytes(engine) == before
    assert (len(script.pure), len(script.native), len(selected_graphs)) == counts


def store_public_fallback(saved, *, state="endpoint_error", mutate=None):
    key = "role-000003-attempt-1"
    request = {"role": "node-selector", "proof_graph_version": 3, "node_selection_version": 1,
               "files": {TREE: json.dumps(graph(), ensure_ascii=False), "private": "SECRET-INPUT"},
               "expected_result_path": f"{WORK}/results/node-selector.json"}
    metadata = {"node_selection_fallback": {"version": 1, "code_validated": True,
                "node_ids": ["N4", "N3", "N2"], "reason": NODE_SELECTION_FALLBACK_REASON},
                "endpoint_error": {"message": "SECRET-ENDPOINT"}}
    if mutate:
        mutate(request, metadata)
    saved.store.put(key, request, state=state, error="SECRET-ORIGINAL-ERROR", metadata=metadata)
    return key


@pytest.mark.parametrize("state", ["endpoint_error", "protocol_error", "completed"])
def test_fallback_view_is_safe_completed_llm_stage_and_readonly_artifact(saved, state):
    key = store_public_fallback(saved, state=state)
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in saved.workspace.rglob("*") if path.is_file()}
    snapshot = views.workflow_snapshot(saved.run)
    stage = snapshot["stages"][0]
    assert stage["role"] == "node-selector" and stage["kind"] == "llm"
    assert stage["label"] == "选择验证顺序" and stage["state"] == "completed"
    assert stage["status"] == "default_order" and stage["report"] == NODE_SELECTION_FALLBACK_REASON
    assert "SECRET" not in json.dumps(snapshot)
    artifact = views.read_artifact(saved.run, NODE_SELECTION_PATH, stage_key=key)
    assert json.loads(artifact["content"]) == {"node_ids": ["N4", "N3", "N2"]}
    assert "SECRET" not in json.dumps(artifact)
    assert {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in saved.workspace.rglob("*") if path.is_file()} == before


@pytest.mark.parametrize("mutate", [
    lambda request, metadata: request.update(node_selection_version=True),
    lambda request, metadata: request.update(proof_graph_version=3.0),
    lambda request, metadata: request.pop("node_selection_version"),
    lambda request, metadata: request["files"].update({TREE: "not-json"}),
    lambda request, metadata: metadata["node_selection_fallback"].update(code_validated=1),
    lambda request, metadata: metadata["node_selection_fallback"].update(node_ids=["N4"]),
    lambda request, metadata: metadata["node_selection_fallback"].update(node_ids=["N2", "N4", "N3"]),
    lambda request, metadata: metadata["node_selection_fallback"].update(reason="SECRET-FORGED"),
])
def test_invalid_fallback_metadata_is_never_presented_as_default_order(saved, mutate):
    key = store_public_fallback(saved, mutate=mutate)
    snapshot = views.workflow_snapshot(saved.run)
    assert snapshot["stages"][0]["status"] != "default_order"
    assert "SECRET" not in json.dumps(snapshot)
    with pytest.raises(views.FaithSieveArtifactNotFoundError):
        views.read_artifact(saved.run, NODE_SELECTION_PATH, stage_key=key)


def test_pending_fallback_cannot_be_presented_as_completed(saved):
    key = store_public_fallback(saved, state="pending")
    stage = views.workflow_snapshot(saved.run)["stages"][0]
    assert stage["state"] == "pending" and stage["status"] != "default_order"
    with pytest.raises(views.FaithSieveArtifactNotFoundError):
        views.read_artifact(saved.run, NODE_SELECTION_PATH, stage_key=key)
