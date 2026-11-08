"""仅恢复已完成官方 Trial 的保存故障；不再投递模型。"""

from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from types import SimpleNamespace

import pytest

from backend.oj_modules.ranking.reverse_judge import recovery as domain
from backend.oj_modules.tasks.agent import harbor_recovery as service


def _candidate():
    return {"task_id": "judge-task", "session_id": "judge-session", "current_task_id": "judge-task",
            "task_kind": "judge", "judge_kind": "reverse_answer", "submission_id": 4,
            "attempt_id": "attempt-1", "judge_attempt_id": "attempt-1", "competition_id": 3,
            "submission_competition_id": 3, "harness": "pi", "scoring_mode": "reverse_judge",
            "endpoint_id": 7, "native_session_id": "native-session",
            "runtime_config": {"harbor_runtime": {}, "endpoint_source": "competition"},
            "agent_result": {"_agent": {"task_id": "judge-task", "session_id": "judge-session", "endpoint_id": 7}},
            "run_status": "CleanupFailed", "session_status": "CleanupFailed", "turn_status": "CleanupFailed",
            "run_message": next(iter(domain.PRESERVATION_FAILURES)),
            "session_message": next(iter(domain.PRESERVATION_FAILURES)),
            "submission_status": "Error", "agent_step_status": "error", "agent_step_error": domain.STEP_FAILURE}


def test_clear_user_messages_and_existing_failure_records_remain_recoverable():
    row = _candidate()
    row['run_message'] = row['session_message'] = '解答记录保存失败，请联系管理员处理。'
    assert domain.validate_harbor_recovery_candidate(row, 'judge-task') == 'pending'
    row['run_message'] = row['session_message'] = 'Harbor 原生会话保存失败，已保留执行目录与端点名额'
    row['agent_step_error'] = '通用 Agent 清理失败，端点名额已保留，请管理员处理后重测'
    assert domain.validate_harbor_recovery_candidate(row, 'judge-task') == 'pending'


@pytest.mark.parametrize("changes", [
    {"judge_kind": "reverse_quality"}, {"task_kind": "user"}, {"scoring_mode": "absolute"},
    {"current_task_id": "new-task"}, {"judge_attempt_id": "new-attempt"}, {"session_status": "Canceled"},
    {"run_message": "arbitrary failure"}, {"session_message": "arbitrary failure"},
    {"agent_step_error": "arbitrary failure"}, {"submission_status": "Accepted"}, {"endpoint_id": 8},
])
def test_candidate_fail_closed_for_other_failures_or_identity(changes):
    row = _candidate()
    row.update(changes)
    with pytest.raises(domain.HarborRecoveryError):
        domain.validate_harbor_recovery_candidate(row, "judge-task")


def test_candidate_query_supplies_actual_competition_endpoint_resolver_contract(monkeypatch):
    from backend.oj_modules.agents import judge
    row = _candidate()
    row["runtime_config_json"] = json.dumps(row["runtime_config"])
    row["agent_step_result"] = json.dumps(row["agent_result"])
    class Cursor:
        def execute(self, sql, params):
            assert "s.endpoint_id" in sql
            assert params == ("judge-task",)
        def fetchone(self):
            return row
    candidate = domain._read_candidate(Cursor(), "judge-task")
    monkeypatch.setattr(judge, "get_agent_session_runtime_config", lambda session: {"endpoint_source": "competition"})
    seen = []
    def endpoints(competition):
        seen.append(competition)
        return [{"id": 7, "harness": "pi", "api_key": "fixture-secret", "model": "fixture-model", "protocol": "openai"}]
    monkeypatch.setattr(judge, "list_agent_judge_endpoints", endpoints)
    resolved = judge.resolve_judge_endpoint(candidate)
    assert resolved["id"] == 7 and resolved["harness"] == "pi"
    assert seen == [candidate["competition_id"]]


def test_state_cannot_enable_cleanup_repair_without_durable_recovery_audit():
    row = _candidate()
    row.update(cleanup_confirmed=True, run_status="Completed", session_status="Completed",
               turn_status="Completed", submission_status="Judging", agent_step_status="running")
    with pytest.raises(domain.HarborRecoveryError):
        domain.validate_harbor_recovery_candidate(row, "judge-task")
    row["agent_result"]["_agent"]["output_recovery"] = {
        "outputs_preserved": True, "task_id": row["task_id"], "session_id": row["session_id"],
        "attempt_id": row["attempt_id"], "native_session_id": row["native_session_id"],
    }
    assert domain.validate_harbor_recovery_candidate(row, "judge-task") == "already_repaired"


class _Connection:
    def __init__(self, reject_update=False):
        self.queries = []
        self.commits = self.rollbacks = 0
        self.rowcount = 1
        self.reject_update = reject_update
    def cursor(self):
        return self
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def execute(self, sql, params=()):
        self.queries.append((" ".join(sql.split()), params))
        self.rowcount = 0 if self.reject_update and "UPDATE ranking_submissions" in sql else 1
    def commit(self):
        self.commits += 1
    def rollback(self):
        self.rollbacks += 1
    def close(self):
        pass


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("event_count", [0, 2])
def test_domain_repairs_all_projections_atomically_or_rolls_back(monkeypatch, changed, event_count):
    from backend.oj_modules.agents import sessions
    row = _candidate()
    connection = _Connection(reject_update=changed)
    monkeypatch.setattr(domain, "get_db_connection", lambda: connection)
    monkeypatch.setattr(domain, "_read_candidate", lambda *_args, **_kwargs: deepcopy(row))
    projected = []
    monkeypatch.setattr(sessions, "sync_agent_session_state_in_transaction",
                        lambda _cursor, state, **kwargs: projected.append((state, kwargs)) or True)
    manifest = {"complete": True, "session_id": "native-session", "events_expected": event_count,
                "events_imported": event_count, "counts": {"imported_events": event_count}}
    conclusion = "真实回复" if event_count else ""
    if changed:
        with pytest.raises(domain.HarborRecoveryError):
            domain.complete_preserved_harbor_judge(row, native_session_id="native-session", conclusion=conclusion, manifest=manifest)
        assert connection.commits == 0 and connection.rollbacks == 1
    else:
        assert domain.complete_preserved_harbor_judge(row, native_session_id="native-session", conclusion=conclusion, manifest=manifest) == {"already_repaired": False}
        assert connection.commits == 1
        assert projected[0][0]["conclusion"] == conclusion
        assert projected[0][1] == {"cleanup_confirmed": True}
        step = next(params for sql, params in connection.queries if "UPDATE ranking_reverse_judge_steps" in sql)
        audit = json.loads(step[0])["_agent"]["output_recovery"]
        assert audit["outputs_preserved"] is True
        assert audit["import_counts"]["imported_events"] == event_count
        assert not any("begin_agent_judge_attempt" in sql for sql, _ in connection.queries)


@pytest.mark.parametrize("proof", [
    {}, {"events_expected": 0}, {"events_imported": 0},
    {"events_expected": False, "events_imported": False},
    {"events_expected": True, "events_imported": 1},
    {"events_expected": 0, "events_imported": False},
    {"events_expected": -1, "events_imported": -1},
    {"events_expected": 0, "events_imported": -1},
    {"events_expected": 0.0, "events_imported": 0.0},
    {"events_expected": "0", "events_imported": "0"},
    {"events_expected": None, "events_imported": None},
    {"events_expected": 0, "events_imported": 1},
])
def test_domain_rejects_invalid_event_counts_before_writing(monkeypatch, proof):
    def no_connection():
        raise AssertionError("无效输出证明不得连接数据库")

    monkeypatch.setattr(domain, "get_db_connection", no_connection)
    manifest = {"complete": True, "session_id": "native-session", "counts": {}, **proof}
    with pytest.raises(domain.HarborRecoveryError, match="Harbor 完整输出证明无效"):
        domain.complete_preserved_harbor_judge(
            _candidate(), native_session_id="native-session", conclusion="", manifest=manifest,
        )


@pytest.fixture
def recovery_context(tmp_path, monkeypatch):
    row = _candidate()
    runtime = {"task_path": str(tmp_path / "task"), "trial_dir": str(tmp_path / "trial")}
    trial = tmp_path / "trial" / "official"
    (trial / "agent").mkdir(parents=True)
    (trial / "result.json").write_text(json.dumps({"finished_at": "2026-11-08T13:34:32.265129Z"}))
    marker = tmp_path / "trial" / ".preservation-failed"
    marker.touch()
    manifest = {"complete": True, "session_id": "native-session", "events_expected": 1,
                "events_imported": 1, "counts": {"imported_events": 1}}
    (trial / "agent" / "numoj-import-manifest.json").write_text(json.dumps(manifest))
    (trial / "agent" / "numoj-import-manifest.json").chmod(0o600)
    calls = []
    monkeypatch.setattr(service, "get_harbor_recovery_candidate", lambda _task: deepcopy(row))
    monkeypatch.setattr(service, "judge_session_write_lock", lambda _session: nullcontext())
    monkeypatch.setattr(service, "is_agent_run_canceled", lambda _task: False)
    monkeypatch.setattr(service, "_runtime_for_candidate", lambda _candidate: runtime)
    monkeypatch.setattr(service, "_official_result", lambda _runtime: ({"ok": True}, trial))
    monkeypatch.setattr(service, "_recovery_secrets", lambda *_args: ("secret",))
    monkeypatch.setattr(service, "ingest_agent_trace_records", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(service, "get_last_agent_trace_assistant", lambda _task: "官方原始最终回复")
    def outputs(**kwargs):
        assert marker.exists()
        calls.append("preserve+artifacts")
        kwargs["emit"]({"type": "native", "session_id": "native-session"})
        kwargs["emit"]({"type": "trace", "records": [{}], "final": True})
    monkeypatch.setattr(service.harbor_runtime, "finalize_harbor_trial_outputs", outputs)
    def complete(*_args, **kwargs):
        assert marker.exists() and kwargs["conclusion"] == "官方原始最终回复"
        calls.append("domain-commit")
        return {"already_repaired": False}
    monkeypatch.setattr(service, "complete_preserved_harbor_judge", complete)
    monkeypatch.setattr(service, "_refresh_public_state", lambda *_args: calls.append("refresh-cache"))
    monkeypatch.setattr(service, "set_agent_judge_task_id", lambda *_args: calls.append("set-orchestrator") or 1)
    def enqueue(name, **kwargs):
        assert marker.exists()
        assert name == "oj.ranking_reverse_judge" and kwargs["args"] == [4, "attempt-1", 7]
        calls.append("enqueue-original-orchestrator")
        return SimpleNamespace(id="new-orchestrator-id")
    return row, marker, calls, SimpleNamespace(send_task=enqueue)


def test_service_only_finalizes_outputs_and_requeues_same_attempt(recovery_context):
    _, marker, calls, celery = recovery_context
    result = service.finalize_completed_harbor_task("judge-task", celery_app=celery)
    assert result["model_reexecuted"] is False
    assert calls == ["preserve+artifacts", "domain-commit", "refresh-cache", "enqueue-original-orchestrator", "set-orchestrator"]
    assert not marker.exists()


@pytest.mark.parametrize("stage", ["outputs", "domain", "refresh"])
def test_service_failure_keeps_marker_and_never_enqueues(recovery_context, monkeypatch, stage):
    _, marker, calls, celery = recovery_context
    def fail(*_args, **_kwargs):
        raise RuntimeError("targeted failure")
    target, name = {"outputs": (service.harbor_runtime, "finalize_harbor_trial_outputs"),
                    "domain": (service, "complete_preserved_harbor_judge"),
                    "refresh": (service, "_refresh_public_state")}[stage]
    monkeypatch.setattr(target, name, fail)
    with pytest.raises(RuntimeError):
        service.finalize_completed_harbor_task("judge-task", celery_app=celery)
    assert marker.exists()
    assert "enqueue-original-orchestrator" not in calls


def test_service_rejects_canceled_task_before_output_reads(recovery_context, monkeypatch):
    _, marker, calls, celery = recovery_context
    monkeypatch.setattr(service, "is_agent_run_canceled", lambda _task: True)
    with pytest.raises(domain.HarborRecoveryError, match="取消"):
        service.finalize_completed_harbor_task("judge-task", celery_app=celery)
    assert marker.exists() and not calls


@pytest.mark.parametrize("invalid", ["active", "canceled", "unfinished", "invalid-reward", "mismatched-reward", "wrong-directory"])
def test_original_official_result_must_be_finished_valid_and_physically_stopped(tmp_path, monkeypatch, invalid):
    from harbor.models.task.id import LocalTaskId
    from harbor.models.trial.config import TrialConfig, TaskConfig
    from harbor.models.trial.result import TrialResult, AgentInfo, ExceptionInfo
    from harbor.models.verifier.result import VerifierResult

    name = "numoj-harbor-" + "a" * 20
    official = tmp_path / name
    official.mkdir()
    (tmp_path / ".run-name").write_text(name)
    original = TrialResult(task_name="task", trial_name=name, trial_uri=official.as_uri(),
        task_id=LocalTaskId(path=tmp_path / "task"), task_checksum="",
        config=TrialConfig(task=TaskConfig(path=tmp_path / "task")),
        agent_info=AgentInfo(name="pi", version="0.82.1"),
        finished_at=datetime.now(timezone.utc), verifier_result=VerifierResult(rewards={"reward": 0.375}))
    if invalid == "unfinished":
        original.finished_at = None
    if invalid == "invalid-reward":
        original.exception_info = ExceptionInfo(exception_type="ApiConnectionError", exception_message="failed",
            exception_traceback="", occurred_at=datetime.now(timezone.utc))
    (official / "result.json").write_text(original.model_dump_json())
    normalized = {"ok": True, "official_trial_dir": str(official), "result": {"rewards": {"reward": 0.375}}}
    if invalid == "mismatched-reward":
        normalized["result"]["rewards"]["reward"] = 1
    if invalid == "wrong-directory":
        normalized["official_trial_dir"] = str(tmp_path / "another-trial")
    if invalid == "canceled":
        (tmp_path / ".cancel-requested").touch()
        os.utime(tmp_path / ".cancel-requested", ns=(0, 0))
    monkeypatch.setattr(service.harbor_runtime, "load_harbor_result", lambda _path: normalized)
    monkeypatch.setattr(service.harbor_runtime, "harbor_trial_physically_stopped", lambda _runtime: invalid != "active")
    with pytest.raises(domain.HarborRecoveryError):
        service._official_result({"trial_dir": str(tmp_path)})


def test_original_official_fractional_result_is_read_without_changes(tmp_path, monkeypatch):
    from harbor.models.task.id import LocalTaskId
    from harbor.models.trial.config import TrialConfig, TaskConfig
    from harbor.models.trial.result import TrialResult, AgentInfo
    from harbor.models.verifier.result import VerifierResult
    name = "numoj-harbor-" + "b" * 20
    official = tmp_path / name
    official.mkdir()
    (tmp_path / ".run-name").write_text(name)
    original = TrialResult(task_name="task", trial_name=name, trial_uri=official.as_uri(),
        task_id=LocalTaskId(path=tmp_path / "task"), task_checksum="",
        config=TrialConfig(task=TaskConfig(path=tmp_path / "task")),
        agent_info=AgentInfo(name="pi", version="0.82.1"),
        finished_at=datetime.now(timezone.utc), verifier_result=VerifierResult(rewards={"reward": 0.375}))
    original_text = original.model_dump_json()
    (official / "result.json").write_text(original_text)
    cancel = tmp_path / ".cancel-requested"
    cancel.touch()
    completed_ns = int(original.finished_at.timestamp()) * 1_000_000_000 + original.finished_at.microsecond * 1000
    os.utime(cancel, ns=(completed_ns + 1_000_000_000, completed_ns + 1_000_000_000))
    normalized = {"ok": True, "official_trial_dir": str(official), "result": {"rewards": {"reward": 0.375}}}
    monkeypatch.setattr(service.harbor_runtime, "load_harbor_result", lambda _path: normalized)
    monkeypatch.setattr(service.harbor_runtime, "harbor_trial_physically_stopped", lambda _runtime: True)
    assert service._official_result({"trial_dir": str(tmp_path)}) == (normalized, official)
    assert (official / "result.json").read_text() == original_text
    assert cancel.exists()


def test_repaired_domain_can_be_retried_without_reopening_or_mutating_other_statuses(monkeypatch):
    row = _candidate()
    row.update(run_status="Completed", session_status="Completed", turn_status="Completed",
               submission_status="Judging", agent_step_status="running")
    row["agent_result"]["_agent"]["output_recovery"] = {
        "outputs_preserved": True, "task_id": row["task_id"], "session_id": row["session_id"],
        "attempt_id": row["attempt_id"], "native_session_id": row["native_session_id"],
    }
    connection = _Connection()
    monkeypatch.setattr(domain, "get_db_connection", lambda: connection)
    monkeypatch.setattr(domain, "_read_candidate", lambda *_args, **_kwargs: deepcopy(row))
    result = domain.complete_preserved_harbor_judge(row, native_session_id="native-session", conclusion="真实回复",
        manifest={"complete": True, "session_id": "native-session", "events_expected": 2, "events_imported": 2, "counts": {}})
    assert result == {"already_repaired": True}
    assert not connection.queries


def test_marker_unlink_failure_is_explicit_and_does_not_enqueue(recovery_context, monkeypatch):
    from pathlib import Path
    _, marker, calls, celery = recovery_context
    original = Path.unlink
    def unlink(path, *args, **kwargs):
        if path == marker:
            raise PermissionError("marker retained")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", unlink)
    with pytest.raises(PermissionError, match="retained"):
        service.finalize_completed_harbor_task("judge-task", celery_app=celery)
    assert marker.exists()
    assert "domain-commit" in calls and "enqueue-original-orchestrator" in calls
    assert "set-orchestrator" in calls


def test_refreshed_public_state_keeps_judge_kind_and_competition_pricing_source(monkeypatch):
    deleted, published = [], []
    row = _candidate()
    monkeypatch.setattr(service, "create_optional_redis_client", lambda: SimpleNamespace(
        delete=lambda *keys: deleted.extend(keys), get=lambda _key: json.dumps(published[-1])))
    monkeypatch.setattr(service, "get_agent_run_by_task_id", lambda _task: {
        "task_id": "judge-task", "status": "Completed", "endpoint_id": 7, "endpoint_model": "actual-model",
    })
    monkeypatch.setattr(service, "publish_agent_run_snapshot", published.append)
    service._refresh_public_state(row, "native-session", "真实回复")
    assert deleted == ["agent_run:judge-task", "ranking_reverse_judge:4"]
    assert published[0]["task_kind"] == "judge"
    assert published[0]["judge_kind"] == "reverse_answer"
    assert published[0]["endpoint_source"] == "competition"
    assert published[0]["endpoint_id"] == 7 and published[0]["endpoint_model"] == "actual-model"
    assert published[0]["conclusion"] == "真实回复"


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_cancel_marker_only_allows_strictly_post_completion_cleanup(tmp_path, offset):
    finished = datetime(2026, 11, 8, 13, 34, 32, 265129, tzinfo=timezone.utc)
    delta = finished - datetime(1970, 1, 1, tzinfo=timezone.utc)
    completed_ns = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
    marker = tmp_path / ".cancel-requested"
    marker.touch()
    os.utime(marker, ns=(completed_ns + offset, completed_ns + offset))
    if offset <= 0:
        with pytest.raises(domain.HarborRecoveryError, match="早于或等于"):
            service._post_completion_cleanup_audit({"trial_dir": str(tmp_path)}, finished)
    else:
        audit = service._post_completion_cleanup_audit({"trial_dir": str(tmp_path)}, finished)
        assert audit["classification"] == "post_completion_cleanup"
        assert audit["cancel_marker_mtime_ns"] == completed_ns + offset
    assert marker.exists()


@pytest.mark.parametrize("invalid", ["symlink", "directory", "naive-time"])
def test_cancel_marker_and_finished_time_fail_closed(tmp_path, invalid):
    marker = tmp_path / ".cancel-requested"
    if invalid == "symlink":
        target = tmp_path / "target"
        target.touch()
        marker.symlink_to(target)
    elif invalid == "directory":
        marker.mkdir()
    else:
        marker.touch()
    with pytest.raises(domain.HarborRecoveryError):
        service._post_completion_cleanup_audit({"trial_dir": str(tmp_path)}, datetime(2026, 11, 8))


def test_post_completion_cleanup_does_not_override_db_cancellation(recovery_context, monkeypatch):
    _, marker, calls, celery = recovery_context
    (marker.parent / ".cancel-requested").touch()
    monkeypatch.setattr(service, "is_agent_run_canceled", lambda _task: True)
    with pytest.raises(domain.HarborRecoveryError, match="取消"):
        service.finalize_completed_harbor_task("judge-task", celery_app=celery)
    assert not calls and marker.exists()


def test_broker_failure_after_repair_keeps_marker(recovery_context):
    _, marker, calls, _ = recovery_context
    def send_task(*_args, **_kwargs):
        raise RuntimeError("broker unavailable")
    with pytest.raises(RuntimeError, match="broker"):
        service.finalize_completed_harbor_task("judge-task", celery_app=SimpleNamespace(send_task=send_task))
    assert marker.exists() and "domain-commit" in calls


@pytest.mark.parametrize("changed", [0, None])
def test_task_id_unconfirmed_after_enqueue_keeps_marker(recovery_context, monkeypatch, changed):
    _, marker, calls, celery = recovery_context
    monkeypatch.setattr(service, "set_agent_judge_task_id", lambda *_args: changed)
    monkeypatch.setattr(service, "get_ranking_submission", lambda _sid: {
        "judge_attempt_id": "new-attempt", "judge_task_id": "new-orchestrator-id", "status": "Judging",
    })
    with pytest.raises(domain.HarborRecoveryError, match="任务 ID"):
        service.finalize_completed_harbor_task("judge-task", celery_app=celery)
    assert marker.exists() and "enqueue-original-orchestrator" in calls


def test_same_task_id_and_same_second_zero_changed_rows_is_verified(recovery_context, monkeypatch):
    _, marker, _, celery = recovery_context
    monkeypatch.setattr(service, "set_agent_judge_task_id", lambda *_args: 0)
    monkeypatch.setattr(service, "get_ranking_submission", lambda _sid: {
        "judge_attempt_id": "attempt-1", "judge_task_id": "new-orchestrator-id", "status": "Judging",
    })
    assert service.finalize_completed_harbor_task("judge-task", celery_app=celery)["success"] is True
    assert not marker.exists()


@pytest.mark.parametrize("bad", [None, "invalid-json", {"status": "CleanupFailed"},
                                {"task_kind": "user"}, {"endpoint_source": "global"},
                                {"native_session_id": "wrong-session"}])
def test_redis_readback_must_confirm_completed_judge_snapshot(monkeypatch, bad):
    row = _candidate()
    published = []
    def get(_key):
        if bad is None or isinstance(bad, str):
            return bad
        return json.dumps({**published[-1], **bad})
    monkeypatch.setattr(service, "create_optional_redis_client", lambda: SimpleNamespace(delete=lambda *_keys: None, get=get))
    monkeypatch.setattr(service, "get_agent_run_by_task_id", lambda _task: {
        "task_id": "judge-task", "status": "Completed", "endpoint_id": 7, "endpoint_model": "actual-model",
    })
    monkeypatch.setattr(service, "publish_agent_run_snapshot", published.append)
    with pytest.raises(domain.HarborRecoveryError, match="Redis"):
        service._refresh_public_state(row, "native-session", "真实回复")


def test_post_completion_cleanup_is_audited_without_removing_cancel_marker(recovery_context, monkeypatch):
    _, marker, _, celery = recovery_context
    cancel = marker.parent / ".cancel-requested"
    cancel.touch()
    completed = datetime(2026, 11, 8, 13, 34, 32, 265129, tzinfo=timezone.utc)
    completed_ns = int(completed.timestamp()) * 1_000_000_000 + completed.microsecond * 1000
    os.utime(cancel, ns=(completed_ns + 1_000_000_000, completed_ns + 1_000_000_000))
    audits = []
    def commit(*_args, **kwargs):
        audits.append(kwargs["cleanup_audit"])
        return {"already_repaired": False}
    monkeypatch.setattr(service, "complete_preserved_harbor_judge", commit)
    result = service.finalize_completed_harbor_task("judge-task", celery_app=celery)
    assert result["post_completion_cleanup"] == audits[0]
    assert audits[0]["classification"] == "post_completion_cleanup"
    assert cancel.exists() and not marker.exists()
