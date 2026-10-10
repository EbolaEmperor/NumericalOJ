"""方法审核宿主指令严格、可选且只读，不替代任何真实数学审核。"""

from copy import deepcopy
import json
import os
import re

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from backend.oj_modules.faithsieve.verification_method_policy import (
    VERIFICATION_METHOD_POLICY_KEY, read_verification_method_policy,
    validate_verification_method_policy, validate_verification_method_policy_prefix,
    validate_verification_method_policy_request, validate_verification_method_version,
)


def request(counter=4):
    return {"version": 1, "after_role_counter": counter}


def record():
    return {"request": request(), "state": "completed", "response": {"accepted": True},
            "sequence": 5, "created_at": "2026-10-10T04:00:00.000000+00:00",
            "updated_at": "2026-10-10T04:00:01.000000+00:00"}


@pytest.mark.parametrize("version", [None, 1])
def test_version_accepts_only_absent_or_exact_one(version):
    assert validate_verification_method_version(version) is version


@pytest.mark.parametrize("version", [True, False, 1.0, 0, 2, "1", [], {}])
def test_invalid_version_does_not_upgrade_legacy_contract(version):
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_version(version)


def test_valid_policy_returns_independent_exact_request():
    saved = record()
    before = deepcopy(saved)
    value = validate_verification_method_policy(saved)
    assert value == request()
    value["after_role_counter"] = 9
    assert saved == before


@pytest.mark.parametrize("field,value", [
    ("version", None), ("version", True), ("version", 1.0), ("version", 2),
    ("after_role_counter", None), ("after_role_counter", True), ("after_role_counter", 4.0),
    ("after_role_counter", "4"), ("after_role_counter", 0), ("after_role_counter", -1),
])
def test_request_rejects_invalid_typed_values(field, value):
    policy = request()
    policy[field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy_request(policy)


@pytest.mark.parametrize("field", ["version", "after_role_counter"])
def test_request_requires_exact_declared_fields(field):
    policy = request()
    policy.pop(field)
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy_request(policy)


@pytest.mark.parametrize("field,value", [
    ("report", "预期判断"), ("affected_node_ids", ["N4"]), ("role", "verification-auditor"),
    ("verdict", "incorrect"), ("score", 0), ("diagnostics", []), ("parameters", {}),
])
def test_policy_does_not_accept_mathematical_or_role_input(field, value):
    policy = request()
    policy[field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy_request(policy)


@pytest.mark.parametrize("field,value", [
    ("state", "pending"), ("state", "protocol_error"), ("state", "endpoint_error"), ("state", True),
    ("response", {"accepted": False}), ("response", {"accepted": 1}), ("response", {"accepted": 1.0}),
    ("response", {"accepted": True, "status": "ok"}), ("response", {}),
    ("sequence", True), ("sequence", 5.0), ("sequence", 0), ("sequence", -1),
    ("created_at", None), ("created_at", "2026-10-10"), ("created_at", "2026-10-10T04:00:00"),
    ("created_at", "2026-10-10T04:00:00+08:00"), ("created_at", "20261010T040000Z"),
    ("created_at", "2026-10-10 04:00:00+00:00"), ("created_at", "2026-99-99T04:00:00+00:00"),
    ("created_at", "2026-10-10T04:00:00.0000000+00:00"),
    ("updated_at", "2026-10-10T03:59:59+00:00"),
])
def test_checkpoint_requires_completed_typed_ack_and_standard_utc_time(field, value):
    saved = record()
    saved[field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy(saved)


@pytest.mark.parametrize("field", ["request", "state", "response", "sequence", "created_at", "updated_at"])
def test_checkpoint_requires_all_standard_fields(field):
    saved = record()
    saved.pop(field)
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy(saved)


@pytest.mark.parametrize("field", ["metadata", "error", "execution", "artifacts", "version"])
def test_checkpoint_cannot_carry_unknown_control_or_evidence(field):
    saved = record()
    saved[field] = {}
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy(saved)


def test_reader_registers_standard_get_only_after_strict_validation_without_writes():
    class ReadOnly:
        def __init__(self):
            self.calls = []

        def _read_record(self, key, *, strict):
            self.calls.append(("strict_read", key, strict))
            return record(), 400

        def get(self, key, actual):
            self.calls.append(("get", key, deepcopy(actual)))
            return record()

    store = ReadOnly()
    assert read_verification_method_policy(store) == request()
    assert store.calls == [("strict_read", VERIFICATION_METHOD_POLICY_KEY, True),
                           ("get", VERIFICATION_METHOD_POLICY_KEY, request())]


@pytest.mark.parametrize("mutation", ["missing", "request", "typed_request", "counter", "state", "ack", "sequence", "time"])
def test_reader_rejects_second_read_drift_including_shared_reference_and_types(mutation):
    class Changed:
        def __init__(self):
            self.saved = record()
            self.visited = []

        def _read_record(self, key, *, strict):
            assert key == VERIFICATION_METHOD_POLICY_KEY and strict is True
            return self.saved, 400

        def get(self, key, actual):
            assert key == VERIFICATION_METHOD_POLICY_KEY and actual == request()
            self.visited.append(key)
            if mutation == "missing":
                return None
            if mutation == "request":
                self.saved["request"]["version"] = 2
            elif mutation == "typed_request":
                self.saved["request"]["version"] = 1.0
            elif mutation == "counter":
                self.saved["request"]["after_role_counter"] = 4.0
            elif mutation == "state":
                self.saved["state"] = "pending"
            elif mutation == "ack":
                self.saved["response"]["accepted"] = 1
            elif mutation == "sequence":
                self.saved["sequence"] = 5.0
            else:
                self.saved["updated_at"] = "2026-10-10T04:00:02+00:00"
            return self.saved

    store = Changed()
    with pytest.raises(FaithSieveProtocolError, match="只读重放时发生变化"):
        read_verification_method_policy(store)
    assert store.visited == [VERIFICATION_METHOD_POLICY_KEY]


def test_missing_policy_is_optional_and_does_not_call_get_or_create_workspace(tmp_path):
    class Missing:
        def _read_record(self, key, *, strict):
            assert key == VERIFICATION_METHOD_POLICY_KEY and strict is True
            raise FileNotFoundError

    assert read_verification_method_policy(Missing()) is None
    assert list(tmp_path.iterdir()) == []


def test_invalid_first_read_never_registers_as_a_valid_policy():
    class Invalid:
        def _read_record(self, _key, *, strict):
            saved = record()
            saved["response"]["accepted"] = 1
            return saved, 400

        def get(self, *_args):
            pytest.fail("不合法策略不能登记完成重放")

    with pytest.raises(FaithSieveProtocolError):
        read_verification_method_policy(Invalid())


def write_record(tmp_path, monkeypatch, raw):
    import backend.oj_modules.faithsieve.checkpoints as module

    monkeypatch.setattr(module, "_KEY", re.compile(r"image-verification-method-policy\Z"))
    path = tmp_path / "faithsieve-work/checkpoints" / f"{VERIFICATION_METHOD_POLICY_KEY}.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    return path


def test_real_reader_preserves_complete_checkpoint_bytes_and_timestamp(tmp_path, monkeypatch):
    raw = json.dumps(record(), ensure_ascii=False, indent=2).encode()
    path = write_record(tmp_path, monkeypatch, raw)
    mtime = path.stat().st_mtime_ns
    assert read_verification_method_policy(CheckpointStore(tmp_path)) == request()
    assert path.read_bytes() == raw and path.stat().st_mtime_ns == mtime


@pytest.mark.parametrize("raw", ['{"request":{},"request":{}}', '{"request":NaN}', '{"request":Infinity}', '[]', 'null'])
def test_real_reader_rejects_duplicate_keys_constants_and_nonobjects_without_write(tmp_path, monkeypatch, raw):
    path = write_record(tmp_path, monkeypatch, raw.encode())
    with pytest.raises(FaithSieveProtocolError):
        read_verification_method_policy(CheckpointStore(tmp_path))
    assert path.read_text() == raw


@pytest.mark.parametrize("kind", ["file_symlink", "directory_symlink", "hardlink"])
def test_real_reader_inherits_secure_file_boundaries(tmp_path, monkeypatch, kind):
    import backend.oj_modules.faithsieve.checkpoints as module

    monkeypatch.setattr(module, "_KEY", re.compile(r"image-verification-method-policy\Z"))
    outside = tmp_path / "outside"
    outside.mkdir()
    source = outside / f"{VERIFICATION_METHOD_POLICY_KEY}.json"
    raw = json.dumps(record()).encode()
    source.write_bytes(raw)
    root = tmp_path / "workspace"
    directory = root / "faithsieve-work/checkpoints"
    if kind == "directory_symlink":
        directory.parent.mkdir(parents=True)
        directory.symlink_to(outside, target_is_directory=True)
    else:
        directory.mkdir(parents=True)
        destination = directory / source.name
        if kind == "file_symlink":
            destination.symlink_to(source)
        else:
            os.link(source, destination)
    with pytest.raises(FaithSieveProtocolError):
        read_verification_method_policy(CheckpointStore(root))
    assert source.read_bytes() == raw


class FrozenPrefix:
    def __init__(self, records):
        self.records_value = records
        self.reads = 0

    def read_records(self):
        self.reads += 1
        return self.records_value

    def records(self):
        pytest.fail("安全枚举不能登记 visited 或提前完成实际审核")

    def get(self, *_args):
        pytest.fail("前缀核查不能消费实际角色重放")


def role_record(role, *, state="completed", status="ok", **fields):
    return {"request": {"role": role, "proof_graph_version": 3, **fields}, "state": state,
            "response": {"result": {"status": status}}}


def prefix():
    return {"role-000001-attempt-1": role_record("tree-builder"),
            "role-000002-attempt-1": role_record("tree-auditor"),
            "role-000003-attempt-1": role_record("node-selector", node_selection_version=1),
            "role-000004-attempt-1": role_record("local-verifier", status="inconclusive", verification_audit_version=1)}


def test_completed_prefix_requires_true_inconclusive_judge_and_does_not_consume_next_audit():
    records = prefix()
    records["role-000005-attempt-1"] = role_record("verification-auditor", state="pending", verification_method_version=1)
    records[VERIFICATION_METHOD_POLICY_KEY] = record()
    before = deepcopy(records)
    store = FrozenPrefix(records)
    assert validate_verification_method_policy_prefix(store, request()) is None
    assert store.reads == 1 and records == before


def test_legal_completed_second_attempt_preserves_frozen_role_identity():
    records = prefix()
    original = records["role-000002-attempt-1"]
    original["state"] = "protocol_error"
    records["role-000002-attempt-2"] = role_record("tree-auditor")
    assert validate_verification_method_policy_prefix(FrozenPrefix(records), request()) is None


@pytest.mark.parametrize("mutation", ["gap", "missing_first", "pending", "failed", "endpoint_retry",
                                     "unsolicited_retry", "pending_retry", "changed_retry_role", "duplicate_counter"])
def test_incomplete_or_ambiguous_prefix_never_dispatches_or_approves_audit(mutation):
    records = prefix()
    if mutation == "gap":
        del records["role-000002-attempt-1"]
    elif mutation == "missing_first":
        records["role-000002-attempt-2"] = records.pop("role-000002-attempt-1")
    elif mutation in {"pending", "failed"}:
        records["role-000002-attempt-1"]["state"] = "pending" if mutation == "pending" else "protocol_error"
    elif mutation == "duplicate_counter":
        records["role-0000002-attempt-1"] = deepcopy(records["role-000002-attempt-1"])
    else:
        records["role-000002-attempt-1"]["state"] = "endpoint_error" if mutation == "endpoint_retry" else (
            "completed" if mutation == "unsolicited_retry" else "protocol_error")
        records["role-000002-attempt-2"] = role_record("tree-builder" if mutation == "changed_retry_role" else "tree-auditor",
                                                     state="pending" if mutation == "pending_retry" else "completed")
    before = deepcopy(records)
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy_prefix(FrozenPrefix(records), request())
    assert records == before


@pytest.mark.parametrize("counter", [5, 10 ** 100])
def test_unreached_or_huge_counter_does_not_expand_or_create_prefix(counter):
    store = FrozenPrefix(prefix())
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy_prefix(store, request(counter))
    assert store.reads == 1


@pytest.mark.parametrize("role,status,audit", [
    ("local-verifier", "inconclusive", 1), ("local-verifier", "passed", 1), ("local-verifier", "refuted", 1),
    ("local-verifier", "graph_defect", 1), ("local-verifier", "ok", 1), ("local-verifier", "inconclusive", None),
    ("local-verifier", "inconclusive", True), ("local-verifier", "inconclusive", 1.0),
    ("tree-auditor", "ok", 1), ("verification-auditor", "ok", 1), ("verification-auditor", "inconclusive", 1),
    ("evidence-mapper", "inconclusive", 1), ("final-synthesizer", "inconclusive", 1),
])
def test_cutoff_is_only_pending_audit_of_completed_true_inconclusive_local_result(role, status, audit):
    records = prefix()
    records["role-000004-attempt-1"] = role_record(role, status=status, verification_audit_version=audit)
    store = FrozenPrefix(records)
    if role == "local-verifier" and status == "inconclusive" and type(audit) is int and audit == 1:
        assert validate_verification_method_policy_prefix(store, request()) is None
    else:
        with pytest.raises(FaithSieveProtocolError):
            validate_verification_method_policy_prefix(store, request())


@pytest.mark.parametrize("field,value", [("role", None), ("role", " "), ("proof_graph_version", 3.0),
                                         ("proof_graph_version", True), ("proof_graph_version", 2)])
def test_prefix_proof_protocol_and_role_are_strict(field, value):
    records = prefix()
    records["role-000001-attempt-1"]["request"][field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy_prefix(FrozenPrefix(records), request())


@pytest.mark.parametrize("child", ["json_repair", "empty_result_retry"])
def test_completed_prefix_cannot_hide_pending_format_or_transport_repair(child):
    records = prefix()
    records["role-000002-attempt-1"]["metadata"] = {child: {"state": "pending"}}
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy_prefix(FrozenPrefix(records), request())


def test_provider_opaque_metadata_has_no_method_control_authority():
    records = prefix()
    records["role-000002-attempt-1"]["metadata"] = {"ignored_result_metadata": {"state": "pending"}}
    assert validate_verification_method_policy_prefix(FrozenPrefix(records), request()) is None


@pytest.mark.parametrize("state", ["protocol_error", "endpoint_error"])
def test_strict_code_selector_fallback_remains_safe_in_completed_prefix(state):
    from backend.oj_modules.faithsieve.node_selection import NODE_SELECTION_FALLBACK_REASON

    records = prefix()
    selector = records["role-000003-attempt-1"]
    selector["state"] = state
    selector["metadata"] = {"node_selection_fallback": {
        "version": 1, "code_validated": True, "node_ids": ["N4", "N3", "N2"],
        "reason": NODE_SELECTION_FALLBACK_REASON,
    }}
    assert validate_verification_method_policy_prefix(FrozenPrefix(records), request()) is None
    selector["metadata"]["node_selection_fallback"]["code_validated"] = 1
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_method_policy_prefix(FrozenPrefix(records), request())
