"""宿主审图指令只接受完整冻结事实输入，不产生数学状态。"""

import copy
import json

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from backend.oj_modules.faithsieve.graph_context_revision import (
    GRAPH_CONTEXT_REVISION_KEY, graph_context_revision_input_paths, read_graph_context_revision,
    validate_graph_context_revision, validate_graph_context_revision_request, validate_graph_context_revision_prefix,
)


def instruction():
    return {"version": 1, "after_role_counter": 8, "affected_node_ids": ["N2", "N5"],
            "report": "原稿明确列出的参数范围尚未进入直接前驱，请对照完整原稿核对这些图遗漏。"}


def record():
    return {"request": instruction(), "state": "completed", "response": {"accepted": True},
            "sequence": 9, "created_at": "2026-10-10T02:00:00.000000+00:00",
            "updated_at": "2026-10-10T02:00:01.000000+00:00"}


def test_validated_instruction_preserves_exact_content_and_is_independent():
    value = record()
    original = copy.deepcopy(value)
    result = validate_graph_context_revision(value, after_role_counter=8, known_node_ids={"N2": {}, "N5": {}})
    assert result == value["request"]
    result["affected_node_ids"].append("N6")
    assert value == original
    assert graph_context_revision_input_paths(value["request"]) == {
        "previous_graph": "faithsieve-work/graphs/context-revision-8-previous.json",
        "review": "faithsieve-work/review/context-revision-8.md",
    }


@pytest.mark.parametrize("field,value", [
    ("version", None), ("version", True), ("version", 1.0), ("version", 2),
    ("after_role_counter", None), ("after_role_counter", True), ("after_role_counter", 8.0),
    ("after_role_counter", "8"), ("after_role_counter", 0), ("after_role_counter", -1),
    ("affected_node_ids", []), ("affected_node_ids", ["N2", "N2"]),
    ("affected_node_ids", ["N0"]), ("affected_node_ids", ["N02"]),
    ("affected_node_ids", ["N2 "]), ("affected_node_ids", ["N2\n"]),
    ("affected_node_ids", [2]), ("affected_node_ids", [["N2"]]),
    ("affected_node_ids", "N2"), ("affected_node_ids", ("N2",)),
    ("report", None), ("report", True), ("report", " "), ("report", "review only"),
    ("report", "中文\ud800"),
])
def test_invalid_instruction_values_are_rejected(field, value):
    request = instruction()
    request[field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision_request(request)
    with pytest.raises(FaithSieveProtocolError):
        graph_context_revision_input_paths(request)


@pytest.mark.parametrize("field", ["version", "after_role_counter", "affected_node_ids", "report"])
def test_missing_instruction_fields_are_rejected(field):
    request = instruction()
    request.pop(field)
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision_request(request)


@pytest.mark.parametrize("field,value", [
    ("verdict", "incorrect"), ("score", 0), ("diagnostics", []), ("execution", {}),
    ("node_selection_version", 1), ("role", "tree-auditor"), ("expected_result_path", "other.json"),
])
def test_instruction_cannot_contain_role_fields_or_mathematical_results(field, value):
    request = instruction()
    request[field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision_request(request)


@pytest.mark.parametrize("context", [
    {"after_role_counter": 7}, {"after_role_counter": True}, {"after_role_counter": 8.0},
    {"after_role_counter": 0}, {"known_node_ids": ["N2"]}, {"known_node_ids": "N2"},
    {"known_node_ids": ["N2", 5]}, {"known_node_ids": [["N2"]]},
])
def test_boundary_and_current_node_context_are_checked(context):
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision(record(), **context)


@pytest.mark.parametrize("field,value", [
    ("state", "pending"), ("state", "protocol_error"), ("state", "endpoint_error"),
    ("state", "failed"), ("state", True), ("response", {"accepted": 1}),
    ("response", {"accepted": 1.0}), ("response", {"accepted": False}),
    ("response", {"accepted": True, "verdict": "correct"}), ("response", {}),
    ("sequence", True), ("sequence", 9.0), ("sequence", 0), ("sequence", -1),
    ("created_at", 0), ("created_at", "2026-10-10"),
    ("created_at", "2026-10-10T02:00:00"), ("created_at", "2026-10-10T02:00:00+08:00"),
    ("created_at", "20261010T020000Z"), ("created_at", "2026-10-10 02:00:00+00:00"),
    ("created_at", "2026-10-10T02:00:00.0000000+00:00"),
    ("created_at", "2026-99-99T02:00:00+00:00"),
    ("updated_at", "2026-10-10T01:59:59+00:00"),
])
def test_incomplete_or_invalid_checkpoint_is_rejected(field, value):
    saved = record()
    saved[field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision(saved)


@pytest.mark.parametrize("field", ["request", "state", "response", "sequence", "created_at", "updated_at"])
def test_checkpoint_requires_standard_fields(field):
    saved = record()
    saved.pop(field)
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision(saved)


@pytest.mark.parametrize("field", ["metadata", "error", "execution", "artifacts", "version"])
def test_checkpoint_rejects_metadata_error_and_extra_fields(field):
    saved = record()
    saved[field] = {}
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision(saved)


def test_reader_uses_strict_checkpoint_boundary_without_writes():
    class ReadOnlyStore:
        def __init__(self):
            self.calls = []

        def _read_record(self, key, *, strict):
            self.calls.append(("read", key, strict))
            return record(), 500

        def get(self, key, request):
            self.calls.append(("get", key, copy.deepcopy(request)))
            return record()

    store = ReadOnlyStore()
    assert read_graph_context_revision(store, after_role_counter=8, known_node_ids=["N2", "N5"]) == instruction()
    assert store.calls == [("read", GRAPH_CONTEXT_REVISION_KEY, True),
                           ("get", GRAPH_CONTEXT_REVISION_KEY, instruction())]


@pytest.mark.parametrize("mutation", ["missing", "request", "typed_request", "typed_counter", "state", "response",
                                      "time", "sequence", "typed_sequence"])
def test_reader_rejects_changed_snapshot_after_strict_validation_without_writes(mutation):
    class ChangedStore:
        def __init__(self):
            self.saved = record()
            self.visited = []

        def _read_record(self, key, *, strict):
            assert key == GRAPH_CONTEXT_REVISION_KEY and strict is True
            return self.saved, 500

        def get(self, key, request):
            assert key == GRAPH_CONTEXT_REVISION_KEY and request == instruction()
            self.visited.append(key)
            if mutation == "missing":
                return None
            # 复用引用也不能把首次合法快照悄悄改成第二份记录。
            if mutation == "request":
                self.saved["request"]["report"] += "另一份意见。"
            elif mutation == "typed_request":
                self.saved["request"]["version"] = 1.0
            elif mutation == "typed_counter":
                self.saved["request"]["after_role_counter"] = 8.0
            elif mutation == "state":
                self.saved["state"] = "pending"
            elif mutation == "response":
                self.saved["response"]["accepted"] = 1
            elif mutation == "time":
                self.saved["updated_at"] = "2026-10-10T02:00:02.000000+00:00"
            else:
                self.saved["sequence"] = 10 if mutation == "sequence" else 9.0
            return self.saved

    store = ChangedStore()
    with pytest.raises(FaithSieveProtocolError, match="只读重放时发生变化"):
        read_graph_context_revision(store)
    assert store.visited == [GRAPH_CONTEXT_REVISION_KEY]


def test_missing_instruction_is_optional_and_does_not_create_workspace(tmp_path):
    class MissingStore:
        def _read_record(self, key, *, strict):
            assert key == GRAPH_CONTEXT_REVISION_KEY and strict is True
            raise FileNotFoundError

    assert read_graph_context_revision(MissingStore()) is None
    assert list(tmp_path.iterdir()) == []


def test_reader_preserves_protocol_error_without_reclassifying_as_missing():
    class InvalidStore:
        def _read_record(self, key, *, strict):
            raise FaithSieveProtocolError("冻结指令无法解析")

    with pytest.raises(FaithSieveProtocolError, match="无法解析"):
        read_graph_context_revision(InvalidStore())


def test_completed_real_checkpoint_is_read_only(tmp_path, monkeypatch):
    # 独立模块不改变普通角色 key；本测试仅模拟调用方显式允许的宿主 key。
    import backend.oj_modules.faithsieve.checkpoints as module
    import re

    monkeypatch.setattr(module, "_KEY", re.compile(r"image-graph-context-revision\Z"))
    path = tmp_path / "faithsieve-work/checkpoints" / f"{GRAPH_CONTEXT_REVISION_KEY}.json"
    path.parent.mkdir(parents=True)
    raw = json.dumps(record(), ensure_ascii=False, indent=2).encode()
    path.write_bytes(raw)
    assert read_graph_context_revision(CheckpointStore(tmp_path)) == instruction()
    assert path.read_bytes() == raw


@pytest.mark.parametrize("raw", [
    '{"request":{},"request":{}}', '{"request":NaN}', '{"request":Infinity}', '[]', 'null',
])
def test_real_reader_rejects_duplicate_keys_constants_and_nonobjects(tmp_path, monkeypatch, raw):
    import backend.oj_modules.faithsieve.checkpoints as module
    import re

    monkeypatch.setattr(module, "_KEY", re.compile(r"image-graph-context-revision\Z"))
    path = tmp_path / "faithsieve-work/checkpoints" / f"{GRAPH_CONTEXT_REVISION_KEY}.json"
    path.parent.mkdir(parents=True)
    path.write_text(raw)
    with pytest.raises(FaithSieveProtocolError):
        read_graph_context_revision(CheckpointStore(tmp_path))
    assert path.read_text() == raw


@pytest.mark.parametrize("kind", ["file_symlink", "directory_symlink", "hardlink"])
def test_reader_inherits_checkpoint_file_boundaries_without_writes(tmp_path, monkeypatch, kind):
    import backend.oj_modules.faithsieve.checkpoints as module
    import os
    import re

    monkeypatch.setattr(module, "_KEY", re.compile(r"image-graph-context-revision\Z"))
    outside = tmp_path / "outside"
    outside.mkdir()
    source = outside / f"{GRAPH_CONTEXT_REVISION_KEY}.json"
    raw = json.dumps(record(), ensure_ascii=False).encode()
    source.write_bytes(raw)
    workspace = tmp_path / "workspace"
    directory = workspace / "faithsieve-work/checkpoints"
    if kind == "directory_symlink":
        directory.parent.mkdir(parents=True)
        directory.symlink_to(outside, target_is_directory=True)
    else:
        directory.mkdir(parents=True)
        target = directory / source.name
        if kind == "file_symlink":
            target.symlink_to(source)
        else:
            os.link(source, target)
    with pytest.raises(FaithSieveProtocolError):
        read_graph_context_revision(CheckpointStore(workspace))
    assert source.read_bytes() == raw


def test_real_missing_reader_does_not_create_directories(tmp_path, monkeypatch):
    import backend.oj_modules.faithsieve.checkpoints as module
    import re

    monkeypatch.setattr(module, "_KEY", re.compile(r"image-graph-context-revision\Z"))
    workspace = tmp_path / "missing-workspace"
    assert read_graph_context_revision(CheckpointStore(workspace)) is None
    assert not workspace.exists()


class FrozenRecords:
    def __init__(self, values):
        self.values = values
        self.calls = 0

    def read_records(self):
        self.calls += 1
        return self.values

    def records(self):
        raise AssertionError("只读前缀枚举不得登记角色已完成重放")


def prefix_role(role="tree-builder", state="completed", **request_fields):
    return {"request": {"role": role, "proof_graph_version": 3, **request_fields}, "state": state,
            "response": {"result": {"status": "ok"}}}


def prefix_instruction(counter=2):
    return {**instruction(), "after_role_counter": counter}


def test_cached_prefix_allows_frozen_attempt_retry_and_later_pending_repair_without_writes():
    records = {
        "image-graph-repair-policy": {"state": "completed"},
        "role-000001-attempt-1": prefix_role(),
        "role-000002-attempt-1": prefix_role("tree-auditor", "protocol_error"),
        "role-000002-attempt-2": prefix_role("tree-auditor"),
        "role-000003-attempt-1": prefix_role("tree-builder", "pending"),
        "role-000004-attempt-1": prefix_role("tree-auditor"),
    }
    original = copy.deepcopy(records)
    store = FrozenRecords(records)
    assert validate_graph_context_revision_prefix(store, prefix_instruction()) is None
    assert store.calls == 1 and records == original


@pytest.mark.parametrize("counter", [3, 10 ** 100])
def test_missing_or_enormous_boundary_cannot_expand_actual_cached_records(counter):
    records = {"role-000001-attempt-1": prefix_role(), "role-000002-attempt-1": prefix_role("tree-auditor")}
    store = FrozenRecords(records)
    with pytest.raises(FaithSieveProtocolError, match="完整缓存角色前缀"):
        validate_graph_context_revision_prefix(store, prefix_instruction(counter))
    assert store.calls == 1


@pytest.mark.parametrize("records", [
    {"role-000001-attempt-1": prefix_role(), "role-000003-attempt-1": prefix_role()},
    {"role-000001-attempt-2": prefix_role(), "role-000002-attempt-1": prefix_role()},
    {"role-000001-attempt-1": prefix_role(), "role-000002-attempt-1": prefix_role(state="pending")},
    {"role-000001-attempt-1": prefix_role(), "role-000002-attempt-1": prefix_role(state="endpoint_error")},
    {"role-000001-attempt-1": prefix_role(), "role-000002-attempt-1": prefix_role(state="protocol_error")},
    {"role-000001-attempt-1": prefix_role(), "role-000002-attempt-1": prefix_role(), "role-000002-attempt-2": prefix_role()},
    {"role-000001-attempt-1": prefix_role(), "role-000002-attempt-1": prefix_role(state="endpoint_error"), "role-000002-attempt-2": prefix_role()},
    {"role-000001-attempt-1": prefix_role(), "role-000002-attempt-1": prefix_role(state="protocol_error"), "role-000002-attempt-2": prefix_role(state="pending")},
    {"role-000001-attempt-1": prefix_role(), "role-000002-attempt-1": prefix_role(state="protocol_error"), "role-000002-attempt-2": prefix_role("tree-auditor")},
    {"role-000000-attempt-1": prefix_role(), "role-000001-attempt-1": prefix_role()},
    {"role-000001-attempt-1": prefix_role(), "role-0000001-attempt-1": prefix_role(), "role-000002-attempt-1": prefix_role()},
])
def test_incomplete_or_ambiguous_role_groups_are_rejected_readonly(records):
    original = copy.deepcopy(records)
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision_prefix(FrozenRecords(records), prefix_instruction())
    assert records == original


@pytest.mark.parametrize("field,value", [("role", ""), ("role", " "), ("role", None), ("role", 1),
                                         ("proof_graph_version", True), ("proof_graph_version", 3.0),
                                         ("proof_graph_version", 2), ("proof_graph_version", None)])
def test_completed_prefix_requires_image_role_identity(field, value):
    saved = prefix_role()
    saved["request"][field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision_prefix(FrozenRecords({"role-000001-attempt-1": saved}), prefix_instruction(1))


@pytest.mark.parametrize("child", ["json_repair", "empty_result_retry"])
def test_completed_role_cannot_hide_pending_runtime_child(child):
    saved = prefix_role("verification-auditor")
    saved["metadata"] = {child: {"state": "pending"}}
    with pytest.raises(FaithSieveProtocolError, match="修复子操作"):
        validate_graph_context_revision_prefix(FrozenRecords({"role-000001-attempt-1": saved}), prefix_instruction(1))
    saved["metadata"][child]["state"] = "completed"
    assert validate_graph_context_revision_prefix(FrozenRecords({"role-000001-attempt-1": saved}), prefix_instruction(1)) is None


def test_opaque_provider_metadata_does_not_control_prefix_completion():
    saved = prefix_role("verification-auditor")
    saved["metadata"] = {"ignored_result_metadata": {"state": "pending", "result": {"state": "pending"}}}
    assert validate_graph_context_revision_prefix(FrozenRecords({"role-000001-attempt-1": saved}), prefix_instruction(1)) is None


@pytest.mark.parametrize("state", ["protocol_error", "endpoint_error"])
def test_only_selector_with_strict_code_fallback_counts_as_completed_prefix(state):
    from backend.oj_modules.faithsieve.node_selection import NODE_SELECTION_FALLBACK_REASON

    saved = prefix_role("node-selector", state, node_selection_version=1)
    saved["metadata"] = {"node_selection_fallback": {
        "version": 1, "code_validated": True, "node_ids": ["N3", "N2"], "reason": NODE_SELECTION_FALLBACK_REASON,
    }}
    assert validate_graph_context_revision_prefix(FrozenRecords({"role-000001-attempt-1": saved}), prefix_instruction(1)) is None
    saved["request"]["role"] = "tree-auditor"
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision_prefix(FrozenRecords({"role-000001-attempt-1": saved}), prefix_instruction(1))


@pytest.mark.parametrize("field,value", [("version", True), ("code_validated", 1), ("node_ids", None),
                                         ("node_ids", ["N2", "N2"]), ("reason", "自行放行")])
def test_selector_fallback_must_be_strict_before_prefix_is_accepted(field, value):
    from backend.oj_modules.faithsieve.node_selection import NODE_SELECTION_FALLBACK_REASON

    fallback = {"version": 1, "code_validated": True, "node_ids": ["N2"], "reason": NODE_SELECTION_FALLBACK_REASON}
    fallback[field] = value
    saved = prefix_role("node-selector", "protocol_error", node_selection_version=1)
    saved["metadata"] = {"node_selection_fallback": fallback}
    with pytest.raises(FaithSieveProtocolError):
        validate_graph_context_revision_prefix(FrozenRecords({"role-000001-attempt-1": saved}), prefix_instruction(1))


@pytest.mark.parametrize("role,status,markers,safe", [
    ("node-selector", "ok", {"node_selection_version": 1}, True),
    ("node-selector", "inconclusive", {"node_selection_version": 1}, False),
    ("verification-auditor", "ok", {"verification_audit_version": 1}, True),
    ("verification-auditor", "ok", {}, True),
    ("verification-auditor", "graph_defect", {}, False),
    ("verification-auditor", "needs_revision", {}, False),
    ("verification-auditor", "inconclusive", {}, False),
    ("tree-auditor", "ok", {}, True),
    ("tree-auditor", "ok", {"node_selection_version": 1}, False),
    ("tree-auditor", "ok", {"node_selection_version": None}, False),
    ("tree-auditor", "needs_revision", {}, False),
    ("local-verifier", "passed", {}, True),
    ("local-verifier", "refuted", {}, True),
    ("local-verifier", "inconclusive", {}, True),
    ("local-verifier", "inconclusive", {"local_diagnostic_version": 1}, True),
    ("local-verifier", "passed", {"local_diagnostic_version": 1}, False),
    ("local-verifier", "refuted", {"local_diagnostic_version": 1}, False),
    ("local-verifier", "inconclusive", {"verification_audit_version": 1}, False),
    ("local-verifier", "graph_defect", {}, False),
    ("tree-builder", "ok", {}, False),
    ("evidence-mapper", "ok", {}, False),
    ("final-synthesizer", "ok", {}, False),
    ("consistency-auditor", "ok", {}, False),
])
def test_context_revision_boundary_is_a_reachable_gate(role, status, markers, safe):
    saved = prefix_role(role, **markers)
    saved["response"]["result"]["status"] = status
    store = FrozenRecords({"role-000001-attempt-1": saved})
    if safe:
        assert validate_graph_context_revision_prefix(store, prefix_instruction(1)) is None
    else:
        with pytest.raises(FaithSieveProtocolError, match="边界"):
            validate_graph_context_revision_prefix(store, prefix_instruction(1))
