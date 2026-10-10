"""完整图片局部任务只授权一次同会话续聊，预算与原数学输入保持冻结。"""

from copy import deepcopy
from datetime import datetime
import json
from types import SimpleNamespace

import pytest

from backend.oj_modules.faithsieve import judge, recovery
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from backend.oj_modules.faithsieve.image_workflow import render_workflow_images
from backend.oj_modules.faithsieve.runtime_snapshot import SNAPSHOT_FILENAME
from tests.unit.test_faithsieve_image_workflow import Pending, Script, seed


TARGET = "role-000003-attempt-1"
PROBLEM = "固定共享对象 x，给定命题1，证明完整命题4。"
PDF = b"%PDF-original-images"


def files(root):
    return {p.relative_to(root).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def native_timeout(tmp_path, monkeypatch):
    script = Script(tmp_path)
    script.pending = "N4"
    engine = seed(tmp_path, script)
    # 本组审计的是旧 600 秒 Judge 的显式续聊；旧请求不能升级诊断或增加审核调用。
    engine._select_local_diagnostic_version = lambda: None
    snapshot = tmp_path / SNAPSHOT_FILENAME
    snapshot.write_text(json.dumps({"endpoint_id": 8, "initial_reasoning_effort": "low"}))
    snapshot.chmod(0o600)
    render_workflow_images(engine, problem_text=PROBLEM, submission_pdf=PDF)
    with pytest.raises(Pending):
        engine.run()
    record = CheckpointStore(tmp_path)._read_record(TARGET, strict=True)[0]
    assert record["state"] == "pending" and record["request"]["role"] == "local-verifier"
    assert not (tmp_path / "faithsieve_result.json").exists()
    run = {"attempt_id": "a" * 32, "submission_id": 12, "problem_id": 4, "endpoint_id": 8,
           "harness": "pi", "execution_mode": "workflow", "requested_by": "teacher",
           "session_id": "faithsieve-" + "a" * 32,
           "started_at": datetime(2026, 10, 9, 8, 32, 49), "status": "failed",
           "elapsed_seconds": 1200, "result_json": None}
    inspected = []

    def inspect(workspace, actual_run, key, actual_record):
        assert workspace == tmp_path and key == TARGET
        assert recovery.typed_equal(actual_record, record)
        inspected.append(deepcopy(actual_run))
        sid = f"fs-{run['attempt_id']}-{TARGET}"
        task = f"ft-{run['attempt_id']}-{TARGET}"
        return {"kind": "native_timeout", "session_id": sid, "failed_task_id": task,
                "original_timeout_seconds": 600, "continuation_task_id": task + "-c1",
                "continuation_timeout_seconds": 7200 - actual_run["elapsed_seconds"],
                "continuation_prompt": "继续同一完整局部验证；原始图片、条件和目标保持只读。"}

    monkeypatch.setattr(judge, "inspect_native_timeout", inspect)
    return SimpleNamespace(root=tmp_path, script=script, engine=engine, run=run,
                           record=record, inspected=inspected, inspect=inspect)


def test_native_timeout_preview_replays_actual_images_and_dag_without_any_writes_or_calls(native_timeout):
    env = native_timeout
    before = files(env.root)
    calls = (len(env.script.pure), len(env.script.native), len(env.script.renders))
    recovery.validate_recovery_inputs(env.root, env.run, problem_text=PROBLEM,
                                     submission_pdf=PDF, endpoint=env.engine.endpoint)
    assert len(env.inspected) == 1
    assert files(env.root) == before
    assert (len(env.script.pure), len(env.script.native), len(env.script.renders)) == calls
    assert not (env.root / recovery.AUTHORIZATION_FILENAME).exists()


def test_native_authorization_preserves_original_checkpoint_and_freezes_whole_remaining_budget(native_timeout):
    env = native_timeout
    before = files(env.root)
    permission = recovery.prepare_recovery(env.root, env.run, "admin")
    assert set(permission) == {"attempt_id", "actor", "created_at", "target_key", "request",
                               "run_identity", "native_timeout"}
    continuation = permission["native_timeout"]
    assert continuation["continuation_timeout_seconds"] == 6000
    assert continuation["original_timeout_seconds"] == 600
    assert continuation["continuation_task_id"] == continuation["failed_task_id"] + "-c1"
    assert permission["request"] == env.record["request"]
    assert permission["run_identity"]["started_at"] == env.run["started_at"].isoformat()
    assert all(files(env.root)[path] == value for path, value in before.items())
    auth = env.root / recovery.AUTHORIZATION_FILENAME
    saved = auth.read_bytes(), auth.stat().st_mtime_ns
    assert auth.stat().st_mode & 0o777 == 0o600
    assert recovery.prepare_recovery(env.root, {**env.run, "elapsed_seconds": 2400}, "another-admin") == permission
    assert (auth.read_bytes(), auth.stat().st_mtime_ns) == saved
    assert recovery.read_native_timeout_authorization(env.root, {**env.run, "elapsed_seconds": 6000},
                                                     TARGET, env.record, env.record["request"]) == continuation
    # 原生续聊没有消费纯模型 attempt2；不能通过端点恢复跳过原 pending。
    with pytest.raises(recovery.FaithSieveRecoveryError, match="不能转成纯模型"):
        recovery.authorize_endpoint_retry(env.root, TARGET, env.record, env.record["request"])


def test_authorized_native_task_preflight_does_not_reinspect_or_extend_budget(native_timeout, monkeypatch):
    env = native_timeout
    permission = recovery.prepare_recovery(env.root, env.run, "admin")
    before = files(env.root)
    monkeypatch.setattr(judge, "inspect_native_timeout", lambda *_a: pytest.fail("已冻结预算不能重新核算"))
    recovery.validate_recovery_inputs(env.root, {**env.run, "elapsed_seconds": 3600},
                                     problem_text=PROBLEM, submission_pdf=PDF, endpoint=env.engine.endpoint,
                                     target_key=permission["target_key"])
    assert files(env.root) == before


def test_native_pending_is_not_automatically_authorized(native_timeout):
    env = native_timeout
    before = files(env.root)
    assert recovery.read_native_timeout_authorization(env.root, env.run, TARGET, env.record, env.record["request"]) is None
    with pytest.raises(recovery.FaithSieveRecoveryError, match="尚未显式授权"):
        recovery.validate_recovery_inputs(env.root, env.run, problem_text=PROBLEM,
                                         submission_pdf=PDF, endpoint=env.engine.endpoint, target_key=TARGET)
    assert not env.inspected and files(env.root) == before


@pytest.mark.parametrize("change", ["problem", "pdf", "model", "thinking", "output_budget"])
def test_native_readonly_preflight_rejects_changed_actual_inputs_without_dispatch(native_timeout, change):
    env = native_timeout
    endpoint = dict(env.engine.endpoint)
    problem, pdf = PROBLEM, PDF
    if change == "problem":
        problem += "新假设。"
    elif change == "pdf":
        pdf = b"%PDF-different"
    elif change == "model":
        endpoint["model"] = "different-model"
    elif change == "thinking":
        endpoint["thinking_enabled"] = True
    else:
        endpoint["max_output_tokens"] -= 1
    before = files(env.root)
    with pytest.raises((recovery.FaithSieveRecoveryError, FaithSieveProtocolError)):
        recovery.validate_recovery_inputs(env.root, env.run, problem_text=problem,
                                         submission_pdf=pdf, endpoint=endpoint)
    assert files(env.root) == before


@pytest.mark.parametrize("field,value", [
    ("original_timeout_seconds", 600.0), ("original_timeout_seconds", True),
    ("continuation_timeout_seconds", 6000.0), ("continuation_timeout_seconds", True),
    ("continuation_timeout_seconds", 7201), ("continuation_timeout_seconds", 0),
    ("continuation_timeout_seconds", 6001),
    ("kind", "other"), ("session_id", "another-session"),
    ("continuation_task_id", "another-task-c1"), ("continuation_prompt", ""),
])
def test_native_contract_typed_drift_never_writes_permission(native_timeout, monkeypatch, field, value):
    env = native_timeout
    def inspect(*args):
        return {**env.inspect(*args), field: value}
    monkeypatch.setattr(judge, "inspect_native_timeout", inspect)
    before = files(env.root)
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.prepare_recovery(env.root, env.run, "admin")
    assert files(env.root) == before


@pytest.mark.parametrize("change", ["float_budget", "boolean_original_budget", "extra", "permission"])
def test_damaged_native_authorization_fails_closed_before_continuation(native_timeout, change):
    env = native_timeout
    permission = recovery.prepare_recovery(env.root, env.run, "admin")
    auth = env.root / recovery.AUTHORIZATION_FILENAME
    if change == "float_budget":
        permission["native_timeout"]["continuation_timeout_seconds"] = 6000.0
    elif change == "boolean_original_budget":
        permission["native_timeout"]["original_timeout_seconds"] = True
    elif change == "extra":
        permission["native_timeout"]["extra"] = "private-input"
    else:
        auth.chmod(0o644)
    if change != "permission":
        auth.write_text(json.dumps(permission, ensure_ascii=False))
    before = files(env.root)
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.read_native_timeout_authorization(env.root, env.run, TARGET, env.record, env.record["request"])
    assert files(env.root) == before


@pytest.mark.parametrize("change", [
    {"elapsed_seconds": 7200}, {"elapsed_seconds": -1}, {"elapsed_seconds": True},
    {"elapsed_seconds": 1200.0}, {"status": "running"}, {"result_json": "{}"},
])
def test_native_recovery_keeps_original_deadline_and_failed_only_gate(native_timeout, change):
    env = native_timeout
    before = files(env.root)
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.prepare_recovery(env.root, {**env.run, **change}, "admin")
    assert not env.inspected and files(env.root) == before


def test_native_terminal_inspection_failure_cannot_issue_authorization(native_timeout, monkeypatch):
    env = native_timeout
    def denied(*_args):
        raise judge.FaithSieveJudgeError("原生安全终态无法确认")
    monkeypatch.setattr(judge, "inspect_native_timeout", denied)
    before = files(env.root)
    with pytest.raises(judge.FaithSieveJudgeError):
        recovery.prepare_recovery(env.root, env.run, "admin")
    assert files(env.root) == before


@pytest.mark.parametrize("change", ["second_attempt", "completed", "protocol_error", "v2", "float_version", "repair", "result"])
def test_only_first_v3_native_pending_without_other_result_is_potentially_recoverable(native_timeout, change):
    env = native_timeout
    request = deepcopy(env.record["request"])
    state, key, metadata = "pending", TARGET, dict(env.record["metadata"])
    if change == "second_attempt":
        key = TARGET[:-1] + "2"
    elif change in {"completed", "protocol_error"}:
        state = change
    elif change == "v2":
        request["proof_graph_version"] = 2
    elif change == "float_version":
        request["proof_graph_version"] = 3.0
    elif change == "repair":
        metadata["json_repair"] = {}
    else:
        (env.root / "faithsieve_result.json").write_text('{"verdict":"inconclusive","score":0,"comment":"结果已写入"}')
    if change in {"v2", "float_version"}:
        path = env.engine.checkpoints.directory / (TARGET + ".json")
        stored = json.loads(path.read_text())
        stored["request"] = request
        path.write_text(json.dumps(stored, ensure_ascii=False))
    elif change != "result":
        env.engine.checkpoints.put(key, request, state=state, metadata=metadata)
    before = files(env.root)
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.prepare_recovery(env.root, env.run, "admin")
    assert not env.inspected and files(env.root) == before


@pytest.mark.parametrize("change", ["image", "goal", "float_version", "node", "prompt"])
def test_frozen_authorization_rejects_native_request_drift_without_history_change(native_timeout, change):
    env = native_timeout
    recovery.prepare_recovery(env.root, env.run, "admin")
    actual = deepcopy(env.record["request"])
    if change == "image":
        actual["images"]["source-pages/page-1.png"] += "AAAA"
    elif change == "goal":
        path = next(p for p in actual["files"] if p.endswith("N4-O1.md"))
        actual["files"][path] += "改变命题。"
    elif change == "float_version":
        actual["proof_graph_version"] = 3.0
    elif change == "node":
        actual["parameters"]["node_id"] = "N3"
    else:
        actual["agent_prompt"] += "新指令。"
    before = files(env.root)
    with pytest.raises(recovery.FaithSieveRecoveryError):
        recovery.read_native_timeout_authorization(env.root, env.run, TARGET, env.record, actual)
    assert files(env.root) == before


def test_authorized_task_preview_progresses_beyond_completed_target_to_two_later_native_tasks(native_timeout, monkeypatch):
    """续跑后 N4 已完成，后续 Celery 重入须继续读取 N3/N2，不能再要求 N4 pending。"""
    env = native_timeout
    permission = recovery.prepare_recovery(env.root, env.run, "admin")
    auth = env.root / recovery.AUTHORIZATION_FILENAME
    authorization = auth.read_bytes(), auth.stat().st_mtime_ns
    prior = {p.name: p.read_bytes() for p in env.engine.checkpoints.directory.glob("*.json")
             if p.name != TARGET + ".json"}
    original_request = deepcopy(env.record["request"])
    original_dispatch = deepcopy(env.script.native[0])
    monkeypatch.setattr(judge, "inspect_native_timeout", lambda *_a: pytest.fail("已授权任务不能再次申请原超时续跑"))
    for elapsed, node in ((2400, "N3"), (3600, "N2")):
        env.script.pending = node
        with pytest.raises(Pending):
            env.engine.run()
        target = CheckpointStore(env.root)._read_record(TARGET, strict=True)[0]
        assert target["state"] == "completed"
        assert recovery.typed_equal(target["request"], original_request)
        assert env.script.native[-1]["expected_result_path"].endswith(f"/{node}-local-verifier.json")
        current = {**env.run, "status": "running", "elapsed_seconds": elapsed}
        before = files(env.root)
        calls = len(env.script.pure), len(env.script.native), len(env.script.renders)
        recovery.validate_recovery_inputs(env.root, current, problem_text=PROBLEM, submission_pdf=PDF,
                                         endpoint=env.engine.endpoint, target_key=permission["target_key"])
        assert files(env.root) == before
        assert (len(env.script.pure), len(env.script.native), len(env.script.renders)) == calls
        assert (auth.read_bytes(), auth.stat().st_mtime_ns) == authorization
        assert recovery.validate_recovery_run(env.root, current)["run_identity"]["started_at"] == env.run["started_at"].isoformat()
        assert recovery.validate_recovery_run(env.root, current)["native_timeout"]["continuation_timeout_seconds"] == 6000
        assert env.script.native[0] == original_dispatch
        assert all((env.engine.checkpoints.directory / name).read_bytes() == data for name, data in prior.items())


@pytest.mark.parametrize("mutation", ["target_request", "later_images", "later_goal", "later_prompt", "later_endpoint", "later_version"])
def test_authorized_later_native_preview_still_rejects_complete_request_drift(native_timeout, mutation):
    env = native_timeout
    permission = recovery.prepare_recovery(env.root, env.run, "admin")
    env.script.pending = "N3"
    with pytest.raises(Pending):
        env.engine.run()
    name = TARGET if mutation == "target_request" else "role-000004-attempt-1"
    path = env.engine.checkpoints.directory / (name + ".json")
    stored = json.loads(path.read_text())
    request = stored["request"]
    if mutation == "target_request":
        request["agent_prompt"] += "改变原授权请求。"
    elif mutation == "later_images":
        request["images"]["source-pages/page-1.png"] += "AAAA"
    elif mutation == "later_goal":
        field = next(p for p in request["files"] if p.endswith("N3-O1.md"))
        request["files"][field] += "改变完整目标。"
    elif mutation == "later_prompt":
        request["agent_prompt"] += "新假设。"
    elif mutation == "later_endpoint":
        request["endpoint"]["max_output_tokens"] -= 1
    else:
        request["proof_graph_version"] = 3.0
    path.write_text(json.dumps(stored, ensure_ascii=False))
    before = files(env.root)
    with pytest.raises((recovery.FaithSieveRecoveryError, FaithSieveProtocolError)):
        recovery.validate_recovery_inputs(env.root, {**env.run, "status": "running", "elapsed_seconds": 2400},
                                         problem_text=PROBLEM, submission_pdf=PDF, endpoint=env.engine.endpoint,
                                         target_key=permission["target_key"])
    assert files(env.root) == before
