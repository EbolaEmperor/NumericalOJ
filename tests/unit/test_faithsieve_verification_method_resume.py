"""方法纠正只发生在冻结前缀之后，审核与重验均来自实际角色调用。"""

from collections import Counter
import copy
from datetime import datetime
import json
import os
import shutil

import pytest

from backend.oj_modules.faithsieve import judge, recovery, views
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.dependency_workflow import NODE_VERIFICATION
from backend.oj_modules.faithsieve.image_workflow import ImageWorkflow, render_workflow_images
from backend.oj_modules.faithsieve.prompts import render_image_role_prompt
from backend.oj_modules.faithsieve.runtime_snapshot import SNAPSHOT_FILENAME
from backend.oj_modules.faithsieve.verification_method_policy import VERIFICATION_METHOD_POLICY_KEY
from backend.oj_modules.faithsieve.workflow import WORK
from tests.unit.test_faithsieve_image_repair import checkpoint_bytes
from tests.unit.test_faithsieve_image_workflow import Pending, PNG, Script, seed
from tests.unit.test_faithsieve_inconclusive_audit import audit_inputs
from tests.unit.test_faithsieve_input_transport import decode_input_message
from tests.unit.test_faithsieve_node_selection import replace_payload


PROBLEM = "固定共享对象 x，给定命题1，证明完整命题4。"
PDF = b"%PDF-frozen-verification-method"
METHOD_REPORT = "误把适用已有定理需要另行登记为直接前驱，因此未完成当前联合条件下的验证。"
REVISION_REPORT = "已知数学定理可搜索并核对适用条件，不需要作为原证明前驱登记。请自主完成尚缺的验证，仍无法判断时保留无结论。"
BOUNDARY = 4


class MethodScript(Script):
    def __init__(self, root):
        super().__init__(root, statuses={"N2": "passed", "N3": "passed", "N4": "inconclusive", "N5": "passed"})
        self.events, self.audit_counts = [], Counter()
        self.needs_method_revision = False
        self.always_needs_revision = False
        self.pause_audit = False
        self.paused_audit = None

    def chat(self, endpoint, messages, **options):
        header = messages[0]["content"].splitlines()[0]
        self.events.append(("pure", header))
        if header == "# Verification auditor" and self.pause_audit:
            self.pause_audit = False
            self.paused_audit = copy.deepcopy((messages, options))
            raise Pending("method-auditor")
        reply = super().chat(endpoint, messages, **options)
        if header == "# Verification auditor":
            _files, context, _result = audit_inputs(messages)
            identifier = context["node"]["id"]
            self.audit_counts[identifier] += 1
            if identifier == "N4" and (self.always_needs_revision or
                    (self.needs_method_revision and self.audit_counts[identifier] == 1)):
                return replace_payload(reply, lambda payload: payload["result"].update(
                    status="needs_revision", report=REVISION_REPORT))
        return reply

    def run_role(self, **request):
        identifier = request["expected_result_path"].rsplit("/", 1)[-1].split("-local-verifier")[0]
        self.events.append(("native", identifier))
        payload = super().run_role(**request)
        if identifier == "N4":
            payload["result"]["report"] = METHOD_REPORT
            payload["artifacts"][payload["result"]["artifact"]] = METHOD_REPORT
        return payload


def frozen_prefix(root, *, recoverable=False):
    script = MethodScript(root)
    engine = seed(root, script)
    engine._select_verification_method_version = lambda: None
    if recoverable:
        snapshot = root / SNAPSHOT_FILENAME
        snapshot.write_text(json.dumps({"endpoint_id": 8, "initial_reasoning_effort": "low"}))
        snapshot.chmod(0o600)
        render_workflow_images(engine, problem_text=PROBLEM, submission_pdf=PDF)
    invoke = engine._invoke

    def stop_before_actual_audit(role, **request):
        if role == "verification-auditor":
            raise Pending("completed-local-prefix")
        return invoke(role, **request)

    engine._invoke = stop_before_actual_audit
    with pytest.raises(Pending, match="completed-local-prefix"):
        engine.run()
    engine._invoke = invoke
    assert engine._role_counter == BOUNDARY
    record = engine.checkpoints.read_records()["role-000004-attempt-1"]
    assert record["state"] == "completed"
    assert record["response"]["result"]["status"] == "inconclusive"
    assert record["request"]["role"] == "local-verifier"
    assert len(script.native) == 1
    assert not engine.checkpoints._path("role-000005-attempt-1").exists()
    original = checkpoint_bytes(engine)
    assert all(json.loads(raw)["state"] == "completed" for raw in original.values())
    assert all("verification_method_version" not in json.loads(raw)["request"] for raw in original.values())
    return engine, script, original


def add_policy(engine, *, boundary=BOUNDARY):
    request = {"version": 1, "after_role_counter": boundary}
    engine.checkpoints.put(VERIFICATION_METHOD_POLICY_KEY, request, state="completed", response={"accepted": True})
    return request


def unchanged_prefix(engine, original):
    assert all((engine.checkpoints.directory / name).read_bytes() == raw for name, raw in original.items())


def resumed_roles(engine):
    return [(key, record) for key, record in sorted(engine.checkpoints.read_records().items())
            if key.startswith("role-") and int(key.split("-")[1]) > BOUNDARY]


def local_context(request, identifier="N4"):
    return json.loads(request["files"][f"{WORK}/obligations/{identifier}/{identifier}-O1.md"])


def file_snapshot(root):
    return {path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in root.rglob("*") if path.is_file()}


def test_fresh_method_contract_is_frozen_and_completed_reentry_does_not_call_any_role(tmp_path):
    script = MethodScript(tmp_path)
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "inconclusive" and engine.verification_method_version == 1
    records = engine.checkpoints.read_records()
    assert records["role-000001-attempt-1"]["request"]["verification_method_version"] == 1
    roles = [record for key, record in records.items() if key.startswith("role-") or key == "final-scoring"]
    assert all(record["request"]["verification_method_version"] == 1 for record in roles)
    assert VERIFICATION_METHOD_POLICY_KEY not in records
    native = script.native[0]
    old_prompt = render_image_role_prompt("local-verifier", {"node_id": "N4"},
                                         node_selection_version=1, verification_audit_version=1)
    new_prompt = render_image_role_prompt("local-verifier", {"node_id": "N4"},
        node_selection_version=1, verification_audit_version=1, verification_method_version=1)
    assert new_prompt.startswith(old_prompt) and new_prompt != old_prompt
    assert native["prompt"].startswith(new_prompt)
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native))
    assert seed(tmp_path, script).run() == result
    assert checkpoint_bytes(engine) == before and (len(script.pure), len(script.native)) == calls


def test_completed_old_epoch_keeps_exact_old_prompts_and_does_not_implicitly_add_method_contract(tmp_path):
    script = MethodScript(tmp_path)
    engine = seed(tmp_path, script)
    engine._select_verification_method_version = lambda: None
    result = engine.run()
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native))
    assert all("verification_method_version" not in record["request"]
               for record in engine.checkpoints.read_records().values())
    native = script.native[0]
    old_prompt = render_image_role_prompt("local-verifier", {"node_id": "N4"},
        node_selection_version=1, verification_audit_version=1, verification_method_version=None)
    assert native["prompt"].startswith(old_prompt)
    assert seed(tmp_path, script).run() == result
    assert checkpoint_bytes(engine) == before and (len(script.pure), len(script.native)) == calls


def test_host_method_policy_audits_cached_inconclusive_then_dispatches_real_complete_revision(tmp_path):
    engine, script, original = frozen_prefix(tmp_path)
    add_policy(engine)
    script.needs_method_revision = True
    resumed = seed(tmp_path, script)
    events = len(script.events)
    result = resumed.run()
    assert result["verdict"] == "inconclusive"
    assert script.events[events:events + 3] == [
        ("pure", "# Verification auditor"), ("native", "N4"), ("pure", "# Verification auditor")]
    roles = resumed_roles(resumed)
    assert [record["request"]["role"] for _key, record in roles[:3]] == [
        "verification-auditor", "local-verifier", "verification-auditor"]
    assert all(record["request"]["verification_method_version"] == 1 for _key, record in roles)
    first_audit = roles[0][1]
    assert first_audit["response"]["result"]["status"] == "needs_revision"
    assert roles[1][1]["response"]["result"]["status"] == "inconclusive"
    assert script.audit_counts["N4"] == 2
    n4 = [request for request in script.native if request["expected_result_path"].endswith("/N4-local-verifier.json")]
    assert len(n4) == 2 and local_context(n4[0]) == local_context(n4[1])
    assert REVISION_REPORT in n4[1]["prompt"] and "自主完成尚缺的验证" in n4[1]["prompt"]
    assert "只澄清上述对象" not in n4[1]["prompt"]
    assert n4[1]["files"]["source-pages/page-1.png"] == PNG + b"\x01"
    assert n4[1]["files"]["source-pages/page-2.png"] == PNG + b"\x02"
    audit = next(messages for role, messages, _options in script.pure if role == "verification-auditor")
    files, context, local = audit_inputs(audit)
    assert context == local_context(n4[0]) and local["status"] == "inconclusive"
    assert files[local["artifact"]] == METHOD_REPORT
    assert resumed.store.read_json(NODE_VERIFICATION)["targets_established"] is False
    assert resumed.verification["N4-O1"]["status"] == "inconclusive"
    assert resumed.verification["N4-O1"]["semantic_audit_status"] == "ok"
    unchanged_prefix(resumed, original)
    before, calls = checkpoint_bytes(resumed), (len(script.pure), len(script.native), len(script.events))
    assert seed(tmp_path, script).run() == result
    assert checkpoint_bytes(resumed) == before
    assert (len(script.pure), len(script.native), len(script.events)) == calls


def test_real_audit_ok_does_not_upgrade_inconclusive_or_repeat_cached_judge(tmp_path):
    engine, script, original = frozen_prefix(tmp_path)
    add_policy(engine)
    events = len(script.events)
    resumed = seed(tmp_path, script)
    assert resumed.run()["verdict"] == "inconclusive"
    assert script.events[events] == ("pure", "# Verification auditor")
    assert sum(request["expected_result_path"].endswith("/N4-local-verifier.json") for request in script.native) == 1
    assert resumed.verification["N4-O1"]["status"] == "inconclusive"
    assert resumed.verification["N4-O1"]["semantic_audit_status"] == "ok"
    unchanged_prefix(resumed, original)


def test_copied_old_prefix_stays_readonly_and_restarts_at_actual_audit_before_any_new_native(tmp_path):
    source, target = tmp_path / "source", tmp_path / "continued"
    original_engine, _original_script, original = frozen_prefix(source)
    original_files = file_snapshot(source)
    shutil.copytree(source, target)
    script = MethodScript(target)
    resumed = seed(target, script)
    add_policy(resumed)
    script.pause_audit = True
    with pytest.raises(Pending, match="method-auditor"):
        resumed.run()
    assert not script.native and not script.pure
    assert script.events == [("pure", "# Verification auditor")]
    unchanged_prefix(resumed, original)
    assert file_snapshot(source) == original_files
    script.needs_method_revision = True
    assert resumed.run()["verdict"] == "inconclusive"
    assert Counter(request["expected_result_path"].rsplit("/", 1)[-1] for request in script.native) == {
        "N4-local-verifier.json": 1, "N3-local-verifier.json": 1, "N2-local-verifier.json": 1}
    old_context = json.loads(original_engine.checkpoints.read_records()["role-000004-attempt-1"]["request"]["files"][
        f"{WORK}/obligations/N4/N4-O1.md"])
    assert local_context(script.native[0]) == old_context
    unchanged_prefix(resumed, original)
    assert file_snapshot(source) == original_files


def test_method_revision_is_bounded_to_one_actual_native_retry_without_forcing_a_verdict(tmp_path):
    engine, script, original = frozen_prefix(tmp_path)
    add_policy(engine)
    script.always_needs_revision = True
    resumed = seed(tmp_path, script)
    assert resumed.run()["verdict"] == "inconclusive"
    n4 = [request for request in script.native if request["expected_result_path"].endswith("/N4-local-verifier.json")]
    assert len(n4) == 2 and script.audit_counts["N4"] == 2
    assert local_context(n4[0]) == local_context(n4[1])
    assert resumed.verification["N4-O1"]["status"] == "inconclusive"
    assert resumed.verification["N4-O1"]["semantic_audit_status"] == "needs_revision"
    assert resumed.store.read_json(NODE_VERIFICATION)["targets_established"] is False
    unchanged_prefix(resumed, original)


def test_pending_new_method_audit_reenters_exact_request_without_dispatching_original_judge(tmp_path):
    engine, script, original = frozen_prefix(tmp_path)
    add_policy(engine)
    script.pause_audit = True
    with pytest.raises(Pending, match="method-auditor"):
        seed(tmp_path, script).run()
    record = engine.checkpoints.read_records()["role-000005-attempt-1"]
    assert record["state"] == "pending" and record["request"]["verification_method_version"] == 1
    assert len(script.native) == 1
    event_count = len(script.events)
    assert seed(tmp_path, script).run()["verdict"] == "inconclusive"
    assert script.events[event_count] == ("pure", "# Verification auditor")
    audit = next((messages, options) for role, messages, options in script.pure if role == "verification-auditor")
    assert audit == script.paused_audit
    assert sum(request["expected_result_path"].endswith("/N4-local-verifier.json") for request in script.native) == 1
    unchanged_prefix(engine, original)


@pytest.mark.parametrize("boundary", [3, 5, 99])
def test_invalid_method_boundary_cannot_generate_missing_prefix_or_dispatch_any_role(tmp_path, boundary):
    engine, script, original = frozen_prefix(tmp_path)
    add_policy(engine, boundary=boundary)
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native), len(script.events))
    assert seed(tmp_path, script).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before
    assert (len(script.pure), len(script.native), len(script.events)) == calls
    unchanged_prefix(engine, original)


def test_host_method_policy_has_no_public_stage_or_own_prompt_context(tmp_path):
    engine, script, _original = frozen_prefix(tmp_path)
    add_policy(engine)
    resumed = seed(tmp_path, script)
    assert resumed.run()["verdict"] == "inconclusive"
    for request in script.native:
        assert "after_role_counter" not in request
        assert VERIFICATION_METHOD_POLICY_KEY not in request["prompt"]
        assert not any("verification-method-policy" in path for path in request["files"])
    for _role, messages, _options in script.pure:
        assert VERIFICATION_METHOD_POLICY_KEY not in json.dumps(messages, ensure_ascii=False)
        assert "after_role_counter" not in decode_input_message(messages[1]["content"][0]["text"])
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        snapshot = views._snapshot(fd, {"attempt_id": "a" * 32, "execution_mode": "workflow"})
    finally:
        os.close(fd)
    assert snapshot["stages"]
    assert not any(stage["key"] == VERIFICATION_METHOD_POLICY_KEY for stage in snapshot["stages"])


@pytest.mark.parametrize("marker", [True, False, 1.0, 0, 2, "1"])
def test_first_builder_method_marker_requires_exact_supported_type_without_new_calls(tmp_path, marker):
    script = MethodScript(tmp_path)
    engine = seed(tmp_path, script)
    engine.run()
    path = engine.checkpoints._path("role-000001-attempt-1")
    record = json.loads(path.read_text())
    record["request"]["verification_method_version"] = marker
    path.write_text(json.dumps(record, ensure_ascii=False))
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native))
    assert seed(tmp_path, script).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before and (len(script.pure), len(script.native)) == calls


@pytest.mark.parametrize("drift", [None, "old_prompt", "new_audit", "new_native", "new_images", "policy_boundary"])
def test_actual_recovery_preview_replays_old_prefix_and_method_audit_without_calls_or_writes(tmp_path, monkeypatch, drift):
    engine, script, original = frozen_prefix(tmp_path, recoverable=True)
    add_policy(engine)
    script.needs_method_revision = True
    script.pending = "N4"
    resumed = seed(tmp_path, script)
    with pytest.raises(Pending, match="N4"):
        resumed.run()
    target = "role-000006-attempt-1"
    pending = resumed.checkpoints.read_records()[target]
    assert pending["state"] == "pending" and pending["request"]["verification_method_version"] == 1
    dispatch = copy.deepcopy(script.native[-1])
    run = {"attempt_id": "a" * 32, "submission_id": 12, "problem_id": 4, "endpoint_id": 8,
           "harness": "pi", "execution_mode": "workflow", "requested_by": "teacher",
           "session_id": "faithsieve-" + "a" * 32,
           "started_at": datetime(2026, 10, 10, 8, 32, 49), "status": "failed",
           "elapsed_seconds": 1200, "result_json": None}

    def inspect(_workspace, actual_run, key, _record):
        assert key == target
        task = f"ft-{run['attempt_id']}-{target}"
        return {"kind": "native_timeout", "session_id": f"fs-{run['attempt_id']}-{target}",
                "failed_task_id": task, "original_timeout_seconds": 600,
                "continuation_task_id": task + "-c1",
                "continuation_timeout_seconds": 7200 - actual_run["elapsed_seconds"],
                "continuation_prompt": "继续同一完整局部验证，原始图片和命题保持只读。"}

    monkeypatch.setattr(judge, "inspect_native_timeout", inspect)
    permission = recovery.prepare_recovery(tmp_path, run, "admin")
    assert permission["target_key"] == target
    script.pending = "N3"
    with pytest.raises(Pending, match="N3"):
        resumed.run()
    assert script.native[-2] == dispatch
    unchanged_prefix(resumed, original)
    monkeypatch.setattr(judge, "inspect_completed_native", lambda *_args: None)
    if drift is not None:
        key = {"old_prompt": "role-000004-attempt-1", "new_audit": "role-000005-attempt-1",
               "new_native": target, "new_images": "role-000008-attempt-1",
               "policy_boundary": VERIFICATION_METHOD_POLICY_KEY}[drift]
        path = resumed.checkpoints._path(key)
        record = json.loads(path.read_text())
        if drift == "old_prompt" or drift == "new_native":
            record["request"]["agent_prompt"] += "改变冻结方法指令。"
        elif drift == "new_audit":
            record["request"]["messages"][0]["content"] += "加入不同的审核要求。"
        elif drift == "new_images":
            record["request"]["images"]["source-pages/page-1.png"] += "AAAA"
        else:
            record["request"]["after_role_counter"] = float(BOUNDARY)
        path.write_text(json.dumps(record, ensure_ascii=False))
    replayed = []
    original_invoke = ImageWorkflow._invoke

    def track(self, role, **request):
        replayed.append((role, request.get("parameters", {}).get("node_id")))
        return original_invoke(self, role, **request)

    monkeypatch.setattr(ImageWorkflow, "_invoke", track)
    before, calls = file_snapshot(tmp_path), (len(script.pure), len(script.native), len(script.events))
    options = {"problem_text": PROBLEM, "submission_pdf": PDF, "endpoint": resumed.endpoint, "target_key": target}
    if drift is None:
        recovery.validate_recovery_inputs(tmp_path, {**run, "status": "running", "elapsed_seconds": 2400}, **options)
        assert replayed == [("tree-builder", None), ("tree-auditor", None), ("node-selector", None),
                            ("local-verifier", "N4"), ("verification-auditor", "N4"),
                            ("local-verifier", "N4"), ("verification-auditor", "N4"),
                            ("local-verifier", "N3")]
    else:
        with pytest.raises((recovery.FaithSieveRecoveryError, FaithSieveProtocolError)):
            recovery.validate_recovery_inputs(tmp_path, {**run, "status": "running", "elapsed_seconds": 2400}, **options)
    assert file_snapshot(tmp_path) == before
    assert (len(script.pure), len(script.native), len(script.events)) == calls
