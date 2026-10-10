"""独立宿主返修策略：数学角色前缀不变，次数按局部目标分别计算。"""

import copy
import json
from collections import Counter
import shutil

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from backend.oj_modules.faithsieve.graph_repair_policy import (
    GRAPH_REPAIR_POLICY_KEY, GraphRepairProgress, graph_repair_policy_request,
    graph_repair_policy_value, select_graph_repair_policy, validate_graph_repair_policy,
    validate_graph_repair_policy_record,
)
from backend.oj_modules.faithsieve.dependency_workflow import NODE_VERIFICATION
from backend.oj_modules.faithsieve.workflow import TREE, WORK
from tests.unit.test_faithsieve_image_repair import RepairScript, make_engine
from tests.unit.test_faithsieve_image_workflow import Pending, default_node_selection, mathematical_records
from tests.unit.test_faithsieve_node_selection import replace_payload
from tests.unit.test_faithsieve_input_transport import decode_input_message


def context(identifier="N2", statement="目标 A", *, premise="条件 a>0"):
    return {"node": {"id": identifier, "kind": "claim", "statement": statement},
            "premises": [{"id": "N1", "kind": "given", "statement": premise}]}


def record():
    return {"request": graph_repair_policy_request(), "state": "completed",
            "response": graph_repair_policy_value()}


def checkpoint_bytes(store):
    return {path.name: path.read_bytes() for path in store.directory.glob("*.json")}


def test_fresh_policy_is_a_single_host_checkpoint_and_reentry_is_readonly(tmp_path):
    store = CheckpointStore(tmp_path)
    selected = select_graph_repair_policy(store, revision_limit=3)
    assert selected == {"version": 1, "mode": "per_node", "revision_limit": 3}
    assert list(store.records()) == [GRAPH_REPAIR_POLICY_KEY]
    saved = store.records()[GRAPH_REPAIR_POLICY_KEY]
    assert saved["request"] == {"role": GRAPH_REPAIR_POLICY_KEY, **selected}
    assert saved["response"] == selected and saved["state"] == "completed"
    assert not {"messages", "images", "files", "endpoint", "call_options", "prompt"} & saved["request"].keys()
    before = checkpoint_bytes(store)
    selected["revision_limit"] = 100
    assert select_graph_repair_policy(store) == graph_repair_policy_value()
    assert checkpoint_bytes(store) == before


def test_existing_policy_uses_checkpoint_get_to_register_recovery_replay(tmp_path, monkeypatch):
    store = CheckpointStore(tmp_path)
    assert select_graph_repair_policy(store) == graph_repair_policy_value()
    visited = []
    original = store.get

    def get(key, request, **options):
        visited.append((key, copy.deepcopy(request)))
        return original(key, request, **options)

    monkeypatch.setattr(store, "get", get)
    before = checkpoint_bytes(store)
    assert select_graph_repair_policy(store) == graph_repair_policy_value()
    assert visited == [(GRAPH_REPAIR_POLICY_KEY, graph_repair_policy_request())]
    assert checkpoint_bytes(store) == before


@pytest.mark.parametrize("change", ["missing", "float_value", "timestamp"])
def test_policy_get_must_return_the_exact_strict_read_snapshot_before_accepting_it(tmp_path, monkeypatch, change):
    store = CheckpointStore(tmp_path)
    select_graph_repair_policy(store)
    modified = store._read_record(GRAPH_REPAIR_POLICY_KEY, strict=True)[0]
    if change == "float_value":
        modified["response"]["version"] = 1.0
    elif change == "timestamp":
        modified["updated_at"] += "更改"
    monkeypatch.setattr(store, "get", lambda *_args, **_kwargs: None if change == "missing" else modified)
    before = checkpoint_bytes(store)
    with pytest.raises(FaithSieveProtocolError, match="之间发生变化"):
        select_graph_repair_policy(store)
    assert checkpoint_bytes(store) == before


@pytest.mark.parametrize("state", ["pending", "completed", "protocol_error", "endpoint_error"])
def test_started_legacy_builder_without_host_policy_is_never_upgraded_or_rewritten(tmp_path, state):
    store = CheckpointStore(tmp_path)
    request = {"role": "tree-builder", "proof_graph_version": 3, "messages": [{"role": "user", "content": "原始完整数学输入"}],
               "files": {"problem.md": "原题"}, "call_options": {"reasoning_effort": "low"}}
    store.put("role-000001-attempt-1", request, state=state,
              **({"response": {"result": {"status": "ok"}}} if state == "completed" else {}))
    before = checkpoint_bytes(store)
    assert select_graph_repair_policy(store) is None
    assert checkpoint_bytes(store) == before
    assert not store._path(GRAPH_REPAIR_POLICY_KEY).exists()
    assert store.records()["role-000001-attempt-1"]["request"] == request


def test_preseeded_new_host_policy_can_coexist_with_an_unchanged_mathematical_prefix(tmp_path):
    store = CheckpointStore(tmp_path)
    original = {"role": "tree-builder", "proof_graph_version": 3, "messages": [{"role": "system", "content": "原数学指令"}],
                "files": {"problem.md": "原题"}, "node_selection_version": 1}
    store.put("role-000001-attempt-1", original, state="completed", response={"result": {"status": "ok"}})
    original_bytes = store._path("role-000001-attempt-1").read_bytes()
    store.put(GRAPH_REPAIR_POLICY_KEY, graph_repair_policy_request(), state="completed", response=graph_repair_policy_value())
    before = checkpoint_bytes(store)
    assert select_graph_repair_policy(store) == graph_repair_policy_value()
    assert checkpoint_bytes(store) == before
    assert store._path("role-000001-attempt-1").read_bytes() == original_bytes
    assert "graph_repair_version" not in original


def test_rendered_input_alone_is_still_a_fresh_mathematical_workspace(tmp_path):
    store = CheckpointStore(tmp_path)
    store.put("image-render", {"role": "image-render", "proof_graph_version": 3}, state="completed", response={"pages": []})
    before = store._path("image-render").read_bytes()
    assert select_graph_repair_policy(store) == graph_repair_policy_value()
    assert store._path("image-render").read_bytes() == before


def test_fresh_inventory_reads_rendered_input_without_registering_it_as_replayed(tmp_path, monkeypatch):
    store = CheckpointStore(tmp_path)
    store.put("image-render", {"role": "image-render", "proof_graph_version": 3}, state="completed", response={"pages": []})
    before = store._path("image-render").read_bytes()
    calls = []
    original_read, original_get = store.read_records, store.get

    def read_records():
        calls.append("inventory")
        return original_read()

    def get(key, request, **options):
        calls.append(key)
        assert key == GRAPH_REPAIR_POLICY_KEY
        return original_get(key, request, **options)

    monkeypatch.setattr(store, "read_records", read_records)
    monkeypatch.setattr(store, "get", get)
    monkeypatch.setattr(store, "records", lambda: pytest.fail("库存枚举不能登记历史请求已重放"))
    assert select_graph_repair_policy(store) == graph_repair_policy_value()
    assert calls == ["inventory", GRAPH_REPAIR_POLICY_KEY]
    assert store._path("image-render").read_bytes() == before


@pytest.mark.parametrize("key", ["role-000002-attempt-1", "final-scoring", "image-graph-context-revision"])
def test_orphan_inventory_is_rejected_without_registering_any_replayed_request(tmp_path, monkeypatch, key):
    store = CheckpointStore(tmp_path)
    store.put(key, {"role": "孤立旧阶段"}, state="completed", response={})
    before = checkpoint_bytes(store)
    inventory_reads = []
    original = store.read_records

    def read_records():
        inventory_reads.append(True)
        return original()

    monkeypatch.setattr(store, "read_records", read_records)
    monkeypatch.setattr(store, "get", lambda *_args, **_kwargs: pytest.fail("库存检查不能登记已重放请求"))
    monkeypatch.setattr(store, "records", lambda: pytest.fail("库存枚举不能走动态 get"))
    with pytest.raises(FaithSieveProtocolError, match="前缀不完整"):
        select_graph_repair_policy(store)
    assert inventory_reads == [True]
    assert checkpoint_bytes(store) == before


@pytest.mark.parametrize("key", ["role-000002-attempt-1", "final-scoring", "compile-000001",
                                 "image-graph-context-revision", "source-extraction"])
def test_missing_first_builder_with_other_history_never_creates_a_new_policy(tmp_path, key):
    store = CheckpointStore(tmp_path)
    store.put(key, {"role": "孤立旧阶段"}, state="completed", response={})
    before = checkpoint_bytes(store)
    with pytest.raises(FaithSieveProtocolError, match="前缀不完整"):
        select_graph_repair_policy(store)
    assert checkpoint_bytes(store) == before
    assert not store._path(GRAPH_REPAIR_POLICY_KEY).exists()


@pytest.mark.parametrize("target", ["request", "response"])
@pytest.mark.parametrize("mutation", ["version_bool", "version_float", "version_string", "version_unknown", "mode",
                                     "limit_bool", "limit_float", "limit_string", "limit_unknown", "missing", "extra"])
def test_policy_fields_values_and_types_are_exactly_frozen(target, mutation):
    value = record()
    altered = value[target]
    if mutation == "version_bool":
        altered["version"] = True
    elif mutation == "version_float":
        altered["version"] = 1.0
    elif mutation == "version_string":
        altered["version"] = "1"
    elif mutation == "version_unknown":
        altered["version"] = 2
    elif mutation == "mode":
        altered["mode"] = "global"
    elif mutation == "limit_bool":
        altered["revision_limit"] = True
    elif mutation == "limit_float":
        altered["revision_limit"] = 3.0
    elif mutation == "limit_string":
        altered["revision_limit"] = "3"
    elif mutation == "limit_unknown":
        altered["revision_limit"] = 4
    elif mutation == "missing":
        altered.pop("mode")
    else:
        altered["extra_control"] = "不能改变控制语义"
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_repair_policy_record(value)


@pytest.mark.parametrize("field,value", [("state", "pending"), ("state", "protocol_error"), ("state", "endpoint_error"),
                                       ("state", True), ("sequence", True), ("sequence", 1.0), ("sequence", 0),
                                       ("created_at", 1), ("updated_at", None), ("error", "不能附加"),
                                       ("metadata", {"revision_limit": 100})])
def test_policy_checkpoint_is_not_a_pending_llm_stage_or_mutable_metadata(field, value):
    altered = record()
    altered[field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_repair_policy_record(altered)


@pytest.mark.parametrize("kind", ["version", "request", "response", "state", "duplicate"])
def test_invalid_preseeded_policy_is_rejected_without_any_checkpoint_write(tmp_path, kind):
    store = CheckpointStore(tmp_path)
    store.put(GRAPH_REPAIR_POLICY_KEY, graph_repair_policy_request(), state="completed", response=graph_repair_policy_value())
    path = store._path(GRAPH_REPAIR_POLICY_KEY)
    value = json.loads(path.read_text())
    if kind == "version":
        value["response"]["version"] = True
    elif kind == "request":
        value["request"]["role"] = "tree-builder"
    elif kind == "response":
        value["response"]["revision_limit"] = 100
    elif kind == "state":
        value["state"] = "pending"
    if kind == "duplicate":
        path.write_text('{"request":{},"request":{},"state":"completed","response":{}}')
    else:
        path.write_text(json.dumps(value, ensure_ascii=False))
    before = checkpoint_bytes(store)
    with pytest.raises(FaithSieveProtocolError):
        select_graph_repair_policy(store)
    assert checkpoint_bytes(store) == before


@pytest.mark.parametrize("limit", [True, 3.0, "3", 0, 4, None])
def test_policy_version_one_cannot_change_its_limit_even_in_a_fresh_workspace(tmp_path, limit):
    store = CheckpointStore(tmp_path)
    with pytest.raises(FaithSieveProtocolError):
        select_graph_repair_policy(store, revision_limit=limit)
    assert not checkpoint_bytes(store)


def test_four_independent_defects_do_not_share_the_same_three_repair_budget():
    progress = GraphRepairProgress(graph_repair_policy_value())
    for revision, identifier in enumerate(("N2", "N3", "N4", "N5"), 1):
        assert progress.before_repair(identifier, context(identifier)) == revision
        progress.after_repair(identifier, context(identifier, "完整修复后的命题"))
        assert progress.count(identifier) == 1
    assert progress.revision == 4


def test_same_target_new_context_does_not_reset_its_repair_budget():
    progress = GraphRepairProgress(graph_repair_policy_value())
    for index in range(3):
        assert progress.before_repair("N2", context(statement=f"目标状态{index}")) == index + 1
        progress.after_repair("N2", context(statement=f"目标状态{index + 1}"))
    with pytest.raises(FaithSieveProtocolError, match="3 次"):
        progress.before_repair("N2", context(statement="目标状态3"))
    assert progress.count("N2") == progress.revision == 3


def test_no_progress_stops_once_without_resetting_or_allowing_another_repair():
    progress = GraphRepairProgress(graph_repair_policy_value())
    original = context()
    assert progress.before_repair("N2", original) == 1
    with pytest.raises(FaithSieveProtocolError, match="没有改变"):
        progress.after_repair("N2", copy.deepcopy(original))
    with pytest.raises(FaithSieveProtocolError):
        progress.before_repair("N2", context(statement="换一种诊断措辞也不重试"))
    assert progress.count("N2") == progress.revision == 1


def test_returning_to_a_previously_defective_context_is_not_progress():
    progress = GraphRepairProgress(graph_repair_policy_value())
    progress.before_repair("N2", context(statement="A"))
    progress.after_repair("N2", context(statement="B"))
    progress.before_repair("N2", context(statement="B"))
    with pytest.raises(FaithSieveProtocolError, match="此前"):
        progress.after_repair("N2", context(statement="A"))
    assert progress.count("N2") == progress.revision == 2


def test_prior_defective_context_cannot_be_reused_even_after_another_target_changes():
    progress = GraphRepairProgress(graph_repair_policy_value())
    progress.before_repair("N2", context(statement="A"))
    progress.after_repair("N2", context(statement="B"))
    progress.before_repair("N3", context("N3", "另一目标 A"))
    progress.after_repair("N3", context("N3", "另一目标 B"))
    with pytest.raises(FaithSieveProtocolError, match="再次出现"):
        progress.before_repair("N2", context(statement="A"))
    assert progress.count("N2") == 1 and progress.count("N3") == 1


def test_changed_direct_premise_is_progress_without_modifying_the_goal():
    progress = GraphRepairProgress(graph_repair_policy_value())
    progress.before_repair("N2", context())
    progress.after_repair("N2", context(premise="完整条件 a>0 且 b>0"))
    assert progress.count("N2") == 1


def test_pending_before_is_idempotent_only_for_the_exact_same_target_and_context():
    progress = GraphRepairProgress(graph_repair_policy_value())
    assert progress.before_repair("N2", context()) == 1
    assert progress.before_repair("N2", copy.deepcopy(context())) == 1
    assert progress.count("N2") == progress.revision == 1
    for identifier, value in (("N2", context(statement="不同命题")), ("N3", context("N3"))):
        with pytest.raises(FaithSieveProtocolError, match="未完成"):
            progress.before_repair(identifier, value)
    progress.after_repair("N2", context(statement="修复后的命题"))
    assert progress.before_repair("N2", context(statement="修复后的命题")) == 2


def test_replaying_completed_prefix_rebuilds_pending_revision_without_persistent_counters():
    def replay():
        progress = GraphRepairProgress(graph_repair_policy_value())
        for identifier in ("N2", "N3", "N4"):
            progress.before_repair(identifier, context(identifier))
            progress.after_repair(identifier, context(identifier, "已修复完整命题"))
        return progress

    pending, resumed = replay(), replay()
    assert pending.before_repair("N5", context("N5")) == resumed.before_repair("N5", context("N5")) == 4
    assert pending.revision == resumed.revision == 4
    assert [pending.count(identifier) for identifier in ("N2", "N3", "N4", "N5")] == [1, 1, 1, 1]


def test_mutating_caller_policy_or_context_cannot_change_saved_history_or_quota():
    policy = graph_repair_policy_value()
    progress = GraphRepairProgress(policy)
    policy["revision_limit"] = 100
    exposed = progress.policy
    exposed["revision_limit"] = 100
    assert progress.policy == graph_repair_policy_value()
    value = context(statement="A")
    progress.before_repair("N2", value)
    value["node"]["statement"] = "B"
    progress.after_repair("N2", value)
    with pytest.raises(FaithSieveProtocolError, match="再次出现"):
        progress.before_repair("N2", context(statement="A"))


@pytest.mark.parametrize("mutation", ["node_id", "given_goal", "node_extra", "context_extra", "premise_id",
                                     "premise_kind", "premise_float", "unsorted", "duplicate", "self_parent", "unicode"])
def test_progress_context_requires_the_exact_canonical_goal_and_direct_premises(mutation):
    value = context()
    if mutation == "node_id":
        value["node"]["id"] = "N3"
    elif mutation == "given_goal":
        value["node"]["kind"] = "given"
    elif mutation == "node_extra":
        value["node"]["label"] = "标签不是局部数学快照"
    elif mutation == "context_extra":
        value["downstream"] = "不得改变控制上下文"
    elif mutation == "premise_id":
        value["premises"][0]["id"] = True
    elif mutation == "premise_kind":
        value["premises"][0]["kind"] = True
    elif mutation == "premise_float":
        value["premises"][0]["statement"] = 1.0
    elif mutation == "unsorted":
        value["premises"] = [{"id": "N9", "kind": "given", "statement": "条件9"}, value["premises"][0]]
    elif mutation == "duplicate":
        value["premises"] *= 2
    elif mutation == "self_parent":
        value["premises"][0]["id"] = "N2"
    else:
        value["node"]["statement"] = "\ud800"
    progress = GraphRepairProgress(graph_repair_policy_value())
    with pytest.raises(FaithSieveProtocolError):
        progress.before_repair("N2", value)
    assert progress.revision == progress.count("N2") == 0


def test_invalid_policy_cannot_create_progress_state():
    value = graph_repair_policy_value()
    value["version"] = True
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_repair_policy(value)
    with pytest.raises(FaithSieveProtocolError):
        GraphRepairProgress(value)


class FourDefectScript(RepairScript):
    """四个独立目标逐次漏掉同一个真实 given，原独立引理可一直复用。"""

    def __init__(self, root, *, pending_builder=None):
        super().__init__(root, defect=False)
        self.initial_graph = {
            "schema_version": 3,
            "nodes": [{"id": "N1", "kind": "given", "label": "条件", "statement": "共享条件 a>0。"},
                      {"id": "N2", "kind": "claim", "label": "独立引理", "statement": "完整独立引理 P(a)。"},
                      *[{"id": f"N{i}", "kind": "claim", "label": f"目标{i}", "statement": f"完整目标 Q{i}(a)。"}
                        for i in range(3, 7)]],
            "edges": [{"id": f"D{i-1}", "from": "N1" if i == 2 else "N2", "to": f"N{i}"}
                      for i in range(2, 7)],
            "target_ids": [f"N{i}" for i in range(3, 7)], "ambiguities": [],
        }
        self.repaired_graph = copy.deepcopy(self.initial_graph)
        self.pending_builder = pending_builder
        self.builder_was_pending = False

    def chat(self, endpoint, messages, **options):
        reply = super().chat(endpoint, messages, **options)
        role = self.pure[-1]["role"]
        if role == "tree-builder" and self.builder_count == self.pending_builder and not self.builder_was_pending:
            self.builder_was_pending = True
            raise Pending("第四个局部目标的修图尚未返回")
        if role == "node-selector":
            files = decode_input_message(messages[1]["content"][0]["text"])["input_files"]
            allowed = set(default_node_selection(json.loads(files[TREE])))
            order = [identifier for identifier in ("N2", "N6", "N5", "N4", "N3") if identifier in allowed]
            return replace_payload(reply, lambda payload: payload["artifacts"].update({f"{WORK}/node-selection.json": json.dumps({"node_ids": order})}))
        return reply

    def run_role(self, **request):
        payload = super().run_role(**request)
        local = self.native[-1]
        identifier = local["node"]
        if identifier != "N2" and "N1" not in {node["id"] for node in local["context"]["premises"]}:
            payload["result"].update(status="graph_defect", report="原图漏掉已经明示的共享直接条件。",
                diagnostics=[{"kind": "missing_premise", "affected_node_ids": [identifier], "reason": "该局部命题缺少直接条件 a>0。"}])
            payload["artifacts"][payload["result"]["artifact"]] = "图遗漏明示条件，不作为作者证明错误。"
            self.repaired_graph = json.loads((self.root / TREE).read_text())
            self.repaired_graph["edges"].append({"id": f"D{len(self.repaired_graph['edges']) + 1}", "from": "N1", "to": identifier})
        return payload


def test_real_workflow_repairs_four_distinct_targets_and_reuses_every_unchanged_context(tmp_path):
    script = FourDefectScript(tmp_path)
    engine = make_engine(tmp_path, script)
    events = []
    engine.progress = events.append
    result = engine.run()
    assert result["verdict"] == "correct" and script.builder_count == 5
    assert Counter(call["node"] for call in script.native) == {"N2": 1, "N3": 2, "N4": 2, "N5": 2, "N6": 2}
    assert engine._graph_repair_progress.revision == 4
    assert [engine._graph_repair_progress.count(f"N{i}") for i in range(3, 7)] == [1, 1, 1, 1]
    assert engine.store.read_json(NODE_VERIFICATION)["targets_established"] is True
    assert all(event["role"] != GRAPH_REPAIR_POLICY_KEY for event in events)
    assert not any(call["role"] == GRAPH_REPAIR_POLICY_KEY for call in script.pure)
    records = engine.checkpoints.records()
    assert validate_graph_repair_policy_record(records[GRAPH_REPAIR_POLICY_KEY]) == graph_repair_policy_value()
    assert all("graph_repair_version" not in value["request"] for value in mathematical_records(records).values())
    before, calls = checkpoint_bytes(engine.checkpoints), (len(script.native), len(script.pure))
    assert engine.run() == result
    assert checkpoint_bytes(engine.checkpoints) == before and (len(script.native), len(script.pure)) == calls


def test_fourth_target_pending_replay_reconstructs_counts_and_frozen_inputs_without_revalidating_prefix(tmp_path):
    script = FourDefectScript(tmp_path, pending_builder=5)
    engine = make_engine(tmp_path, script)
    with pytest.raises(Pending):
        engine.run()
    completed = {key: value for key, value in checkpoint_bytes(engine.checkpoints).items()
                 if json.loads(value)["state"] == "completed"}
    pending = next(value for value in engine.checkpoints.records().values() if value["state"] == "pending")
    first_call = copy.deepcopy(script.pure[-1])
    previous_native, previous_pure = len(script.native), len(script.pure)
    assert engine._graph_repair_progress.revision == 4
    assert engine.run()["verdict"] == "correct"
    resumed_builder = next(call for call in script.pure[previous_pure:] if call["role"] == "tree-builder")
    assert resumed_builder["messages"] == first_call["messages"] and resumed_builder["options"] == first_call["options"]
    resumed_record = next(value for value in engine.checkpoints.records().values() if value["request"] == pending["request"])
    assert resumed_record["state"] == "completed" and resumed_record["request"] == pending["request"]
    assert [call["node"] for call in script.native[previous_native:]] == ["N3"]
    assert engine._graph_repair_progress.revision == 4 and engine._graph_repair_progress.count("N3") == 1
    assert all(checkpoint_bytes(engine.checkpoints)[key] == value for key, value in completed.items())


def legacy_four_defect_run(root):
    script = FourDefectScript(root)
    engine = make_engine(root, script)
    original = script.run_role
    first = [True]

    def initial_pending(**request):
        payload = original(**request)
        if first[0]:
            first[0] = False
            raise Pending("首个Judge尚未完成")
        return payload

    script.run_role = initial_pending
    # 初次暂挂只为生成完全相同的首builder前缀；删除测试中的host记录模拟真实旧epoch。
    with pytest.raises(Pending):
        engine.run()
    engine.checkpoints._path(GRAPH_REPAIR_POLICY_KEY).unlink()
    assert engine.run()["verdict"] == "inconclusive"
    return engine, script


def test_old_full_graph_limit_stays_frozen_and_completed_failure_reentry_is_readonly(tmp_path):
    engine, script = legacy_four_defect_run(tmp_path)
    assert engine._graph_repair_progress is None and script.builder_count == 4
    assert not engine.checkpoints._path(GRAPH_REPAIR_POLICY_KEY).exists()
    before, calls = checkpoint_bytes(engine.checkpoints), (len(script.native), len(script.pure))
    assert engine.run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine.checkpoints) == before and (len(script.native), len(script.pure)) == calls


def test_explicit_new_workspace_policy_extends_an_exact_old_prefix_without_touching_the_source(tmp_path):
    source, destination = tmp_path / "source", tmp_path / "continued"
    old_engine, old_script = legacy_four_defect_run(source)
    original = checkpoint_bytes(old_engine.checkpoints)
    shutil.copytree(source, destination)
    script = FourDefectScript(destination)
    script.builder_count = old_script.builder_count
    script.repaired_graph = json.loads((destination / TREE).read_text())
    script.repaired_graph["edges"].append({"id": f"D{len(script.repaired_graph['edges']) + 1}", "from": "N1", "to": "N3"})
    engine = make_engine(destination, script)
    engine.checkpoints.put(GRAPH_REPAIR_POLICY_KEY, graph_repair_policy_request(), state="completed", response=graph_repair_policy_value())
    assert engine.run()["verdict"] == "correct"
    assert [call["node"] for call in script.native] == ["N3"]
    assert [call["role"] for call in script.pure].count("tree-builder") == 1
    assert engine._graph_repair_progress.revision == 4
    copied = checkpoint_bytes(engine.checkpoints)
    assert all(copied[key] == value for key, value in original.items())
    assert checkpoint_bytes(old_engine.checkpoints) == original
