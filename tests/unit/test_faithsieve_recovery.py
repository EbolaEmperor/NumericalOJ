"""显式端点恢复只能消费原调用的第二次机会，历史记录始终只读。"""

from copy import deepcopy
from datetime import datetime
import json
import os
from pathlib import Path

import pytest

from backend.oj_modules.ai.endpoints import LLMEndpointRequestError
from backend.oj_modules.faithsieve import recovery, workflow
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
from backend.oj_modules.faithsieve.runtime_snapshot import SNAPSHOT_FILENAME
from tests.unit.test_faithsieve_workflow import _function_response, envelope, thinking_endpoint


ATTEMPT = "a" * 32
TARGET = "role-000001-attempt-1"
SECOND = "role-000001-attempt-2"
# 与 ArtifactStore.bundle 的确定排序一致，冻结实际 raw 消息中的文件顺序。
FILES = {workflow.SOURCE: "第1页：证明原文。", "problem.md": "题面原文。"}


@pytest.fixture
def run():
    return {"attempt_id": ATTEMPT, "submission_id": 12, "problem_id": 4, "endpoint_id": 7,
            "harness": "pi", "execution_mode": "workflow", "requested_by": "teacher",
            "session_id": f"faithsieve-{ATTEMPT}", "started_at": datetime(2026, 10, 9, 8, 32, 49),
            "status": "failed", "elapsed_seconds": 1800, "result_json": None}


def engine(root, chat):
    return workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(enabled=False),
                                      verification_agent=None, workspace=root, chat=chat)


def fail_first(root, *, reason=None):
    calls = []

    def chat(_endpoint, messages, **options):
        calls.append((messages, options))
        raise LLMEndpointRequestError("模型端点请求失败（HTTP 403）。", status_code=403, provider_reason=reason)

    with pytest.raises(FaithSieveEndpointError):
        engine(root, chat)._invoke("decomposer", files=FILES)
    cache = CheckpointStore(root)
    record = cache._read_record(TARGET, strict=True)[0]
    return calls, record


def history(root):
    directory = Path(root) / "faithsieve-work/checkpoints"
    return {path.name: path.read_bytes() for path in directory.glob("*.json")}


@pytest.mark.parametrize("reason", [None, "service_not_enabled", "free_tier_exhausted"])
def test_explicit_recovery_consumes_second_attempt_then_replays_cache_without_calls(tmp_path, run, reason):
    calls, record = fail_first(tmp_path, reason=reason)
    before = history(tmp_path)
    permission = recovery.prepare_recovery(tmp_path, run, "admin")
    auth_path = tmp_path / recovery.AUTHORIZATION_FILENAME
    auth_bytes = auth_path.read_bytes()
    assert auth_path.stat().st_mode & 0o777 == 0o600
    assert history(tmp_path) == before
    assert permission["request"] == record["request"]
    assert permission["run_identity"]["started_at"] == run["started_at"].isoformat()
    assert recovery.validate_recovery_run(tmp_path, run) == permission

    def chat(_endpoint, messages, **options):
        calls.append((messages, options))
        return _function_response(envelope(workflow.STEPS))

    result = engine(tmp_path, chat)._invoke("decomposer", files=FILES)
    assert result.key == SECOND and len(calls) == 2
    assert calls[1] == calls[0]
    after = history(tmp_path)
    assert set(after) == {TARGET + ".json", SECOND + ".json"}
    assert after[TARGET + ".json"] == before[TARGET + ".json"]
    second = CheckpointStore(tmp_path)._read_record(SECOND, strict=True)[0]
    assert second["state"] == "completed"
    assert TARGET in second["metadata"]["dependency_keys"]
    assert engine(tmp_path, lambda *_a, **_k: pytest.fail("缓存不得调用模型"))._invoke(
        "decomposer", files=FILES,
    ).key == SECOND
    assert history(tmp_path) == after and auth_path.read_bytes() == auth_bytes
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.prepare_recovery(tmp_path, run, "admin")


def test_no_authorization_keeps_endpoint_failure_terminal_and_creates_no_second_call(tmp_path):
    _calls, _record = fail_first(tmp_path)
    before = history(tmp_path)
    with pytest.raises(FaithSieveEndpointError):
        engine(tmp_path, lambda *_a, **_k: pytest.fail("未授权不得重调"))._invoke("decomposer", files=FILES)
    assert history(tmp_path) == before
    assert not (tmp_path / recovery.AUTHORIZATION_FILENAME).exists()


def test_second_endpoint_failure_cannot_create_third_call_or_be_reauthorized(tmp_path, run):
    fail_first(tmp_path)
    before = history(tmp_path)
    recovery.prepare_recovery(tmp_path, run, "admin")
    calls = []

    def chat(*_args, **_kwargs):
        calls.append(1)
        raise LLMEndpointRequestError("固定连接说明。", request_failure="connection")

    with pytest.raises(FaithSieveEndpointError):
        engine(tmp_path, chat)._invoke("decomposer", files=FILES)
    after = history(tmp_path)
    assert len(calls) == 1 and set(after) == {TARGET + ".json", SECOND + ".json"}
    assert after[TARGET + ".json"] == before[TARGET + ".json"]
    with pytest.raises(FaithSieveEndpointError):
        engine(tmp_path, lambda *_a, **_k: pytest.fail("第二次失败仍须终态"))._invoke("decomposer", files=FILES)
    assert history(tmp_path) == after
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.prepare_recovery(tmp_path, run, "admin")


def test_prepare_is_idempotent_and_does_not_rewrite_authorization_or_history(tmp_path, run):
    fail_first(tmp_path)
    permission = recovery.prepare_recovery(tmp_path, run, "admin")
    before = history(tmp_path)
    auth = tmp_path / recovery.AUTHORIZATION_FILENAME
    data, modified = auth.read_bytes(), auth.stat().st_mtime_ns
    assert recovery.prepare_recovery(tmp_path, run, "another-admin") == permission
    assert auth.read_bytes() == data and auth.stat().st_mtime_ns == modified
    assert history(tmp_path) == before


@pytest.mark.parametrize("field,value", [
    ("submission_id", True), ("problem_id", 4.0), ("endpoint_id", 7.0),
    ("harness", "other"), ("execution_mode", "skill"), ("requested_by", "other"),
    ("session_id", "other"), ("started_at", datetime(2026, 10, 9, 8, 33)),
])
def test_authorization_requires_original_typed_run_identity(tmp_path, run, field, value):
    fail_first(tmp_path)
    recovery.prepare_recovery(tmp_path, run, "admin")
    changed = {**run, field: value}
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.validate_recovery_run(tmp_path, changed)


@pytest.mark.parametrize("mutation", ["boolean_number", "float_number", "file", "message", "format"])
def test_authorized_retry_rejects_any_frozen_request_change_without_mutation(tmp_path, run, mutation):
    _calls, record = fail_first(tmp_path)
    recovery.prepare_recovery(tmp_path, run, "admin")
    before = history(tmp_path)
    request = deepcopy(record["request"])
    if mutation == "boolean_number":
        request["endpoint"]["thinking_enabled"] = 0
    elif mutation == "float_number":
        request["endpoint"]["id"] = 7.0
    elif mutation == "file":
        request["files"]["problem.md"] += " 新前提。"
    elif mutation == "message":
        request["messages"][1]["content"] += " 新输入。"
    else:
        request["call_options"]["tool_choice"] = "auto"
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.authorize_endpoint_retry(tmp_path, TARGET, record, request)
    assert history(tmp_path) == before


@pytest.mark.parametrize("status", ["pending", "protocol_error", "completed"])
def test_prepare_only_accepts_endpoint_error_not_other_checkpoint_states(tmp_path, run, status):
    _calls, record = fail_first(tmp_path)
    CheckpointStore(tmp_path).put(TARGET, record["request"], state=status)
    before = history(tmp_path)
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.prepare_recovery(tmp_path, run, "admin")
    assert history(tmp_path) == before and not (tmp_path / recovery.AUTHORIZATION_FILENAME).exists()


@pytest.mark.parametrize("change", [
    {"elapsed_seconds": 7200}, {"elapsed_seconds": -1}, {"elapsed_seconds": True},
    {"elapsed_seconds": 1800.0}, {"status": "running"}, {"result_json": "{}"},
])
def test_prepare_rejects_exhausted_or_invalid_original_budget_before_authorization(tmp_path, run, change):
    fail_first(tmp_path)
    before = history(tmp_path)
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.prepare_recovery(tmp_path, {**run, **change}, "admin")
    assert history(tmp_path) == before and not (tmp_path / recovery.AUTHORIZATION_FILENAME).exists()


@pytest.mark.parametrize("corruption", ["duplicate", "nan", "extra", "public_permissions", "symlink", "hardlink"])
def test_private_authorization_damage_is_terminal_without_calls_or_history_writes(tmp_path, run, corruption):
    _calls, record = fail_first(tmp_path)
    permission = recovery.prepare_recovery(tmp_path, run, "admin")
    auth = tmp_path / recovery.AUTHORIZATION_FILENAME
    if corruption == "duplicate":
        auth.write_text(auth.read_text().replace('"actor": "admin"', '"actor": "admin", "actor": "admin"'))
    elif corruption == "nan":
        auth.write_text(auth.read_text().replace('"actor": "admin"', '"actor": NaN'))
    elif corruption == "extra":
        auth.write_text(json.dumps({**permission, "extra": "SECRET"}))
    elif corruption == "public_permissions":
        auth.chmod(0o644)
    else:
        original = tmp_path / "original-authorization.json"
        auth.rename(original)
        if corruption == "symlink":
            auth.symlink_to(original)
        else:
            os.link(original, auth)
    before = history(tmp_path)
    with pytest.raises(recovery.FaithSieveRecoveryError):
        engine(tmp_path, lambda *_a, **_k: pytest.fail("损坏授权不得调用模型"))._invoke("decomposer", files=FILES)
    assert history(tmp_path) == before


def test_damaged_original_failure_record_is_not_overwritten_as_protocol_retry(tmp_path, run):
    _calls, record = fail_first(tmp_path)
    recovery.prepare_recovery(tmp_path, run, "admin")
    target = tmp_path / "faithsieve-work/checkpoints" / (TARGET + ".json")
    target.write_text(target.read_text().replace('"state": "endpoint_error"',
                                               '"state": "completed", "state": "endpoint_error"'))
    before = history(tmp_path)
    with pytest.raises(recovery.FaithSieveRecoveryError):
        engine(tmp_path, lambda *_a, **_k: pytest.fail("损坏历史不得重做"))._invoke("decomposer", files=FILES)
    assert history(tmp_path) == before


@pytest.mark.parametrize("changed", [None, "problem", "pdf", "endpoint"])
def test_recovery_input_preflight_is_readonly_and_requires_actual_source_and_request(tmp_path, run, changed):
    snapshot = tmp_path / SNAPSHOT_FILENAME
    snapshot.write_text(json.dumps({"endpoint_id": 7, "initial_reasoning_effort": None}))
    snapshot.chmod(0o600)
    (tmp_path / "submission.pdf").write_bytes(b"%PDF-original")
    cache = CheckpointStore(tmp_path)
    cache.put("source-extraction", {"problem_text": FILES["problem.md"], "pdf_path": "submission.pdf",
                                   "timeout_seconds": workflow.SOURCE_TIMEOUT_SECONDS},
              state="completed", response={"status": "ok", "text": FILES[workflow.SOURCE]})
    fail_first(tmp_path)
    before = {path.relative_to(tmp_path).as_posix(): path.read_bytes()
              for path in tmp_path.rglob("*") if path.is_file()}
    options = {"problem_text": FILES["problem.md"], "submission_pdf": b"%PDF-original",
               "endpoint": thinking_endpoint(enabled=False)}
    if changed == "problem":
        options["problem_text"] += "新目标。"
    elif changed == "pdf":
        options["submission_pdf"] = b"%PDF-other"
    elif changed == "endpoint":
        options["endpoint"] = thinking_endpoint(enabled=True)
    if changed is None:
        recovery.validate_recovery_inputs(tmp_path, run, **options)
    else:
        with pytest.raises((recovery.FaithSieveRecoveryError, FaithSieveProtocolError)):
            recovery.validate_recovery_inputs(tmp_path, run, **options)
    after = {path.relative_to(tmp_path).as_posix(): path.read_bytes()
             for path in tmp_path.rglob("*") if path.is_file()}
    assert after == before
