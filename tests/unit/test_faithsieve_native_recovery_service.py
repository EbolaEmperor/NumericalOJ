"""原续聊已完成后的编排重投只回读结果，不创建新的续聊授权。"""

from copy import deepcopy

import pytest

from backend.oj_modules.faithsieve import judge, recovery, services
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from tests.unit.test_faithsieve_native_recovery import PDF, PROBLEM, files, native_timeout
from tests.unit.test_faithsieve_image_workflow import Pending
from tests.unit.test_faithsieve_recovery_service import state


_validate_inputs = services._validate_inputs


@pytest.fixture
def resumed(native_timeout, state, monkeypatch):
    env = native_timeout
    permission = recovery.prepare_recovery(env.root, env.run, "admin")
    env.script.pending = "N3"
    with pytest.raises(Pending):
        env.engine.run()
    key = "role-000004-attempt-1"
    record = CheckpointStore(env.root)._read_record(key, strict=True)[0]
    inspected = []

    def inspect(workspace, run, actual_key, actual_record):
        assert workspace == env.root and actual_key == key
        assert recovery.typed_equal(actual_record, record)
        assert run["started_at"] == env.run["started_at"]
        inspected.append(actual_key)
        return {"result": {"status": "passed", "artifact": "faithsieve-work/verification/N3.md", "report": "完整验证"},
                "artifacts": {"faithsieve-work/verification/N3.md": "完整验证证据"},
                "execution": {"decision_source": "agent"}, "control": {}}

    monkeypatch.setattr(judge, "inspect_completed_native", inspect)
    state.connection.run = deepcopy(env.run)
    monkeypatch.setattr(services, "_validate_inputs", _validate_inputs)
    monkeypatch.setattr(services, "prepare_recovery", recovery.prepare_recovery)
    monkeypatch.setattr(services, "get_existing_agent_workspace_path", lambda _id: env.root)
    monkeypatch.setattr(services, "get_problem", lambda _id: {"type": 2, "written_grading_mode": 4})
    monkeypatch.setattr(services, "get_submission_by_id", lambda _id: {"problem_id": env.run["problem_id"]})
    monkeypatch.setattr(services, "problem_material", lambda _problem: PROBLEM)
    monkeypatch.setattr(services, "submission_pdf", lambda _id: PDF)
    monkeypatch.setattr(services, "resolve_launch_endpoint", lambda *_a, **_kw: env.engine.endpoint)
    return env, state, permission, inspected


def test_readonly_eligibility_and_explicit_requeue_reuse_original_authorization(resumed):
    env, state, permission, inspected = resumed
    before = files(env.root)
    calls = (len(env.script.pure), len(env.script.native), len(env.script.renders))

    assert services.can_retry_failed_run(env.run["attempt_id"])
    assert files(env.root) == before and not state.dispatched
    assert services.retry_failed_run(env.run["attempt_id"], actor="admin", dispatcher=state.dispatcher) == {
        "attempt_id": env.run["attempt_id"], "status": "queued",
    }

    assert files(env.root) == before
    assert recovery.validate_recovery_run(env.root, state.connection.run) == permission
    assert state.connection.run["started_at"] == env.run["started_at"]
    assert len(state.dispatched) == 1 and inspected == ["role-000004-attempt-1"] * 3
    assert (len(env.script.pure), len(env.script.native), len(env.script.renders)) == calls
    with pytest.raises(recovery.FaithSieveRecoveryConflict):
        services.retry_failed_run(env.run["attempt_id"], actor="admin", dispatcher=state.dispatcher)
    assert len(state.dispatched) == 1


@pytest.mark.parametrize("failure", ["native_failed", "protocol_error", "endpoint_error", "new_result"])
def test_same_authorization_cannot_recover_new_real_failure(resumed, monkeypatch, failure):
    env, state, _permission, _inspected = resumed
    key = "role-000004-attempt-1"
    record = CheckpointStore(env.root)._read_record(key, strict=True)[0]
    if failure == "native_failed":
        def rejected(*_args):
            raise judge.FaithSieveJudgeError("Judge 未正常完成")
        monkeypatch.setattr(judge, "inspect_completed_native", rejected)
    elif failure == "new_result":
        (env.root / "faithsieve_result.json").write_text('{"verdict":"inconclusive"}')
    else:
        env.engine.checkpoints.put(key, record["request"], state=failure, metadata=record["metadata"])
    before = files(env.root)

    assert services.can_retry_failed_run(env.run["attempt_id"]) is False
    with pytest.raises((recovery.FaithSieveRecoveryError, judge.FaithSieveJudgeError)):
        services.retry_failed_run(env.run["attempt_id"], actor="admin", dispatcher=state.dispatcher)

    assert not state.dispatched and files(env.root) == before
    assert state.connection.run["status"] == "failed"
