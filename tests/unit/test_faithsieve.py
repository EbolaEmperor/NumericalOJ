"""FaithSieve 队列、结果协议与 schema 契约。"""

from pathlib import Path
import re
from types import SimpleNamespace

from flask import Flask
import pytest
from celery.exceptions import Retry

from backend.oj_modules.api import problem_api
from backend.oj_modules.routes import grading_routes
from backend.oj_modules.api.submission_api import _submission_problem_payload
from backend.oj_modules.submissions import faithsieve
from backend.oj_modules.tasks import faithsieve_tasks
from scripts import init_db_schema
from tests.unit.test_agent_sessions import _ScriptedConnection


def test_result_protocol_is_minimal_and_strict():
    payload = {
        "verdict": "incorrect",
        "score": 2,
        "comment": "第 3 步把必要条件当成了充分条件。",
    }
    assert faithsieve.parse_result(payload) == payload

    with pytest.raises(ValueError, match="只能包含"):
        faithsieve.parse_result({**payload, "evidence": []})
    with pytest.raises(ValueError, match="整数"):
        faithsieve.parse_result({**payload, "score": True})
    with pytest.raises(ValueError, match="不能为空"):
        faithsieve.parse_result({**payload, "comment": " "})


def test_public_problem_exposes_written_grading_mode_for_button_visibility():
    problem = {
        "id": 7,
        "title": "证明题",
        "type": 2,
        "written_grading_mode": 4,
    }
    assert _submission_problem_payload(
        problem,
        {"is_admin": 1},
    )["written_grading_mode"] == 4
    assert "written_grading_mode" not in _submission_problem_payload(
        problem,
        {"is_admin": 0},
    )


@pytest.mark.parametrize(
    ("user", "expected_mode"),
    [
        ({"id": 1, "username": "admin", "is_admin": 1}, 4),
        ({"id": 2, "username": "student", "is_admin": 0}, None),
    ],
)
def test_problem_detail_exposes_written_grading_mode_only_to_admin(
    monkeypatch,
    user,
    expected_mode,
):
    app = Flask(__name__)
    app.register_blueprint(problem_api.problem_api_bp)
    monkeypatch.setattr(problem_api, "current_user", lambda: user)
    monkeypatch.setattr(
        problem_api,
        "build_problem_detail_context",
        lambda *_args: ({
            "problem": {
                "id": 7,
                "title": "证明题",
                "type": 2,
                "written_grading_mode": 4,
            },
            "rendered_content": "",
            "last_submissions": [],
            "initial_code": "",
            "remaining_submissions": 10,
            "can_submit": True,
            "submit_block_code": "",
            "submit_block_reason": "",
        }, None),
    )

    response = app.test_client().get("/api/problems/7")

    assert response.status_code == 200
    payload = response.get_json()
    if expected_mode is None:
        assert "written_grading_mode" not in payload["problem"]
    else:
        assert payload["problem"]["written_grading_mode"] == expected_mode


def test_queue_runs_uses_named_lock_and_skips_active_submission(monkeypatch):
    connection = _ScriptedConnection(
        one_values=[
            {"acquired": 1},
            {"attempt_id": "active", "status": "running"},
            None,
        ],
    )
    monkeypatch.setattr(faithsieve, "get_db_connection", lambda: connection)

    queued, skipped = faithsieve.queue_runs(
        [
            {"id": 11, "problem_id": 7},
            {"id": 12, "problem_id": 7},
        ],
        requested_by="admin",
        harness="pi",
        endpoint_id=3,
    )

    assert skipped == [11]
    assert len(queued) == 1 and queued[0]["submission_id"] == 12
    calls = connection.cursor_instance.calls
    assert "GET_LOCK" in calls[0][0]
    assert any("INSERT INTO faithsieve_grading_runs" in query for query, _ in calls)
    assert "RELEASE_LOCK" in calls[-1][0]
    assert connection.commits == 1
    assert connection.closed is True


def test_claim_run_slot_stops_at_twenty_active_runs(monkeypatch):
    connection = _ScriptedConnection(
        one_values=[
            {"acquired": 1},
            {"status": "queued"},
            {"total": 20},
        ],
    )
    monkeypatch.setattr(faithsieve, "get_db_connection", lambda: connection)

    assert not faithsieve.claim_run_slot(
        "attempt", task_id="task", session_id="session",
    )
    assert not any(
        "SET status='running'" in query
        for query, _params in connection.cursor_instance.calls
    )
    assert connection.commits == 0
    assert connection.closed is True


def test_schema_declares_faithsieve_run_table():
    spec = init_db_schema._load_schema_specs()["faithsieve_grading_runs"]
    assert {
        "attempt_id",
        "submission_id",
        "problem_id",
        "status",
        "session_id",
        "result_json",
    }.issubset(spec.columns)
    assert "uniq_faithsieve_attempt" in spec.indexes
    assert "idx_faithsieve_status" in spec.indexes


def test_skill_keeps_subagent_protocol_compact():
    from backend.oj_modules.faithsieve.prompts import IMAGE_ROLE_NAMES

    root = Path(__file__).resolve().parents[2]
    skill = (root / "skills" / "faithsieve" / "SKILL.md").read_text(
        encoding="utf-8",
    )
    agents = root / "skills" / "faithsieve" / "references" / "image-agents"
    assert "数学职责实际派发 Task 子 Agent" in skill
    assert "references/image-agents/tree-builder.md" in skill
    assert "references/image-agents/local-verifier.md" in skill
    assert "派发提示词时填写参数" not in skill
    assert "frozen_declaration_hash" not in skill
    for role in IMAGE_ROLE_NAMES:
        prompt = agents / f"{role}.md"
        content = prompt.read_text(encoding="utf-8")
        assert '"report"' in content
        assert '"context"' not in content
        assert '"evidence"' not in content
        assert "调用者" not in content
        assert "主 Agent" not in content
        assert "占位符" not in content
        assert "最终只返回" not in content
        assert "faithsieve-work/results/" in content
        assert "{result_path}" not in content
        for parameter in re.findall(r"\{[a-z_]+\}", content):
            assert parameter in skill


class _FakeCelery:
    def __init__(self):
        self.tasks = {}
        self.dispatched = []

    def task(self, **options):
        def decorate(function):
            self.tasks[options["name"]] = function
            function.apply_async = lambda **kwargs: self.dispatched.append(kwargs)
            return function
        return decorate


class _FakeLock:
    def __init__(self, acquired=True):
        self.acquired = acquired
        self.released = False

    def acquire(self, **_kwargs):
        return self.acquired

    def release(self):
        self.released = True


def _worker_fixture(monkeypatch, *, verdict="incorrect", score=2, execution_mode="workflow"):
    celery = _FakeCelery()
    faithsieve_tasks.register_faithsieve_grading_task(celery)
    worker = celery.tasks[faithsieve_tasks.FAITHSIEVE_WORKFLOW_TASK_NAME if execution_mode == "workflow" else faithsieve_tasks.FAITHSIEVE_SKILL_TASK_NAME]
    run = {"attempt_id": "attempt", "status": "running", "submission_id": 12, "problem_id": 7, "execution_mode": execution_mode}
    monkeypatch.setattr(faithsieve_tasks, "get_run", lambda _attempt: run)
    monkeypatch.setattr(faithsieve_tasks, "get_submission_by_id", lambda _id: {
        "id": 12, "problem_id": 7, "username": "student",
    })
    monkeypatch.setattr(faithsieve_tasks, "get_problem", lambda _id: {
        "id": 7, "type": 2, "written_grading_mode": 4,
    })
    lock = _FakeLock()
    monkeypatch.setattr(faithsieve_tasks, "_workflow_lock", lambda _id: lock)
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", lambda *_args: {
        "verdict": verdict, "score": score, "comment": "首个实质错误出现在第 3 步。",
    })
    monkeypatch.setattr(faithsieve_tasks, "_execute_skill", lambda *_args: {
        "verdict": verdict, "score": score, "comment": "首个实质错误出现在第 3 步。",
    })
    writes, finishes = [], []
    monkeypatch.setattr(faithsieve_tasks, "complete_run",
                        lambda *args: writes.append(("complete", *args)))
    monkeypatch.setattr(faithsieve_tasks, "finish_run",
                        lambda *args, **kwargs: finishes.append((args, kwargs)))
    monkeypatch.setattr(faithsieve_tasks, "update_run_progress", lambda *_args: None)
    def retry(**_kwargs):
        raise Retry()
    context = SimpleNamespace(request=SimpleNamespace(id="workflow-task"), app=celery, retry=retry,
                              run=run, cancellations=[])
    monkeypatch.setattr(faithsieve_tasks, "_cancel_workflow_judges",
                        lambda *_args: context.cancellations.append("cancel"))
    monkeypatch.setattr(faithsieve_tasks, "_cancel_skill_judge",
                        lambda *_args: context.cancellations.append("skill-cancel"))
    return worker, context, writes, finishes, lock


def test_completed_workflow_result_updates_manual_grade(monkeypatch):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch)
    assert worker(context, "attempt") == {"success": True, "score": 2}
    assert writes == [("complete", "attempt", {
        "verdict": "incorrect", "score": 2, "comment": "首个实质错误出现在第 3 步。",
    })]
    assert finishes == []
    assert lock.released


def test_inconclusive_workflow_result_does_not_overwrite_grade(monkeypatch):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch, verdict="inconclusive")
    assert worker(context, "attempt")["success"] is False
    assert writes == []
    assert finishes[0][0][1] == "inconclusive"
    assert lock.released


def test_executor_failure_does_not_overwrite_grade_or_expose_supplier_error(monkeypatch, caplog):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch)
    def fail(*_args):
        raise RuntimeError("supplier secret API-key must never reach public state")
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", fail)
    assert worker(context, "attempt")["success"] is False
    assert writes == []
    assert finishes[0][0][1] == "failed"
    assert "supplier secret" not in finishes[0][0][2]
    assert context.cancellations == ["cancel"]
    assert lock.released
    record = next(record for record in caplog.records if record.message == "FaithSieve 执行异常")
    assert record.exc_info[0] is RuntimeError
    assert record.attempt_id == "attempt"
    assert record.execution_mode == "workflow"


def test_safe_endpoint_failure_preserves_role_and_http_code_in_failed_run(monkeypatch):
    from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch)
    def fail(*_args):
        raise FaithSieveEndpointError("建立证明状态树", {"kind": "request", "status_code": 402})
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", fail)
    outcome = worker(context, "attempt")
    assert outcome["success"] is False and "建立证明状态树失败" in outcome["message"]
    assert "HTTP 402" in outcome["message"] and "余额不足或需要付费" in outcome["message"]
    assert finishes == [(("attempt", "failed", outcome["message"]), {})]
    assert writes == [] and context.cancellations == ["cancel"] and lock.released


def test_pending_judge_releases_worker_and_execution_lock_without_finishing_run(monkeypatch):
    from backend.oj_modules.faithsieve.judge import FaithSievePending

    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch)
    def pending(*_args):
        raise FaithSievePending(session_id="role-session", task_id="role-task", role="proof-searcher", invocation_key="role-000001")
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", pending)
    with pytest.raises(Retry):
        worker(context, "attempt")
    assert writes == finishes == context.cancellations == []
    assert lock.released


def test_overall_timeout_uses_durable_age_and_cancels_judge_before_terminal_failure(monkeypatch):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch)
    context.run["elapsed_seconds"] = faithsieve_tasks.FAITHSIEVE_TIMEOUT_SECONDS
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", lambda *_args: pytest.fail("过期任务不得继续派发"))
    assert worker(context, "attempt")["success"] is False
    assert writes == []
    assert context.cancellations == ["cancel"]
    assert finishes[0][0][1] == "failed"
    assert "整体时限" in finishes[0][0][2]
    assert lock.released


def test_pending_judge_keeps_retry_when_progress_update_fails(monkeypatch):
    from backend.oj_modules.faithsieve.judge import FaithSievePending

    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch)
    def pending(*_args):
        raise FaithSievePending(session_id="role-session", task_id="role-task", role="proof-searcher", invocation_key="role-000001")
    def failed_progress(*_args):
        raise RuntimeError("database temporarily unavailable")
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", pending)
    monkeypatch.setattr(faithsieve_tasks, "update_run_progress", failed_progress)
    with pytest.raises(Retry):
        worker(context, "attempt")
    assert writes == finishes == context.cancellations == []
    assert lock.released


def test_score_transaction_timeout_after_workflow_does_not_write_grade(monkeypatch):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch)
    def expire(*_args):
        raise faithsieve.FaithSieveRunTimedOutError("成绩提交前已超过整体时限")
    monkeypatch.setattr(faithsieve_tasks, "complete_run", expire)
    assert worker(context, "attempt")["success"] is False
    assert writes == []
    assert context.cancellations == ["cancel"]
    assert finishes[0][0][1] == "failed"
    assert "整体时限" in finishes[0][0][2]
    assert lock.released


def test_score_commit_response_loss_retries_and_reads_completed_run(monkeypatch):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch)
    def unknown(*_args):
        context.run["status"] = "completed"
        context.run["message"] = "评测完成，得分 2/5"
        raise faithsieve.FaithSieveCommitOutcomeUnknownError("重读持久状态")
    monkeypatch.setattr(faithsieve_tasks, "complete_run", unknown)
    with pytest.raises(Retry):
        worker(context, "attempt")
    assert writes == finishes == context.cancellations == []
    assert lock.released
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", lambda *_args: pytest.fail("已提交的请求不能重做模型请求"))
    assert worker(context, "attempt") == {"success": True, "message": "评测完成，得分 2/5"}


def test_unavailable_database_at_resume_keeps_recovery_message(monkeypatch):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch)
    def unavailable(*_args):
        raise RuntimeError("database temporarily unavailable")
    monkeypatch.setattr(faithsieve_tasks, "get_run", unavailable)
    with pytest.raises(Retry):
        worker(context, "attempt")
    assert writes == finishes == context.cancellations == []
    assert lock.released


def test_failed_terminal_state_save_keeps_recovery_message(monkeypatch):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch, verdict="inconclusive")
    def unavailable(*_args, **_kwargs):
        raise RuntimeError("database temporarily unavailable")
    monkeypatch.setattr(faithsieve_tasks, "finish_run", unavailable)
    with pytest.raises(Retry):
        worker(context, "attempt")
    assert writes == finishes == []
    assert context.cancellations == ["cancel"]
    assert lock.released


def test_incorrect_proof_cannot_be_marked_accepted_by_inconsistent_score(monkeypatch):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch, score=5)
    assert worker(context, "attempt")["success"] is False
    assert writes == []
    assert finishes[0][0][1] == "failed"
    assert lock.released


def test_duplicate_workflow_delivery_does_not_run_model(monkeypatch):
    worker, context, writes, finishes, _lock = _worker_fixture(monkeypatch)
    monkeypatch.setattr(faithsieve_tasks, "_workflow_lock", lambda _id: _FakeLock(False))
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", lambda *_args: pytest.fail("不得重复执行"))
    with pytest.raises(Retry):
        worker(context, "attempt")
    assert writes == finishes == []


def test_controller_only_dispatches_long_work_to_agent_queue(monkeypatch):
    celery = _FakeCelery()
    controller = faithsieve_tasks.register_faithsieve_grading_task(celery)
    run = {"status": "queued", "submission_id": 12, "problem_id": 7, "execution_mode": "workflow"}
    monkeypatch.setattr(faithsieve_tasks, "get_run", lambda _attempt: run)
    monkeypatch.setattr(faithsieve_tasks, "claim_run_slot", lambda *_args, **_kwargs: True)
    context = SimpleNamespace(request=SimpleNamespace(id="controller-task"), app=celery)
    assert controller(context, "attempt")["success"] is True
    assert celery.dispatched == [{"args": ("attempt",), "queue": "agent", "task_id": "fs-workflow-attempt"}]
    run["status"] = "running"
    assert controller(context, "attempt")["success"] is True
    assert len(celery.dispatched) == 2
    assert celery.dispatched[0] == celery.dispatched[1]


@pytest.mark.parametrize("execution_mode", ["skill", None])
def test_skill_worker_and_historical_null_use_shared_atomic_completion(monkeypatch, execution_mode):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch, execution_mode=execution_mode)
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", lambda *_args: pytest.fail("skill不得切换到workflow"))
    assert worker(context, "attempt") == {"success": True, "score": 2}
    assert writes[0][0] == "complete" and finishes == context.cancellations == []
    assert lock.released


def test_skill_wait_retries_and_releases_worker_without_writing_grade(monkeypatch):
    from backend.oj_modules.faithsieve.judge import FaithSievePending
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch, execution_mode="skill")
    def waiting(*_args):
        raise FaithSievePending(session_id="main-skill", task_id="fs-attempt", role="skill", invocation_key="skill")
    monkeypatch.setattr(faithsieve_tasks, "_execute_skill", waiting)
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", lambda *_args: pytest.fail("不得回退"))
    with pytest.raises(Retry):
        worker(context, "attempt")
    assert writes == finishes == context.cancellations == [] and lock.released


@pytest.mark.parametrize("failure", ["timeout", "executor", "inconclusive"])
def test_skill_terminal_failure_only_cancels_its_own_judge_without_fallback(monkeypatch, failure):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch, execution_mode="skill")
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", lambda *_args: pytest.fail("skill失败不得回退"))
    if failure == "timeout":
        context.run["elapsed_seconds"] = faithsieve_tasks.FAITHSIEVE_TIMEOUT_SECONDS
        monkeypatch.setattr(faithsieve_tasks, "_execute_skill", lambda *_args: pytest.fail("过期不得派发"))
    elif failure == "executor":
        def broken(*_args):
            raise RuntimeError("SECRET-SUPPLIER")
        monkeypatch.setattr(faithsieve_tasks, "_execute_skill", broken)
    else:
        monkeypatch.setattr(faithsieve_tasks, "_execute_skill", lambda *_args: {"verdict": "inconclusive", "score": 0, "comment": "证据不足"})
    assert worker(context, "attempt")["success"] is False
    assert writes == [] and context.cancellations == ["skill-cancel"]
    assert finishes[0][0][1] == ("inconclusive" if failure == "inconclusive" else "failed")
    assert "SECRET" not in finishes[0][0][2] and lock.released


@pytest.mark.parametrize("queued_mode,persisted_mode", [("workflow", "skill"), ("skill", "workflow"), ("workflow", None)])
def test_wrong_execution_worker_does_not_fail_or_cancel_other_persistent_mode(monkeypatch, queued_mode, persisted_mode):
    worker, context, writes, finishes, lock = _worker_fixture(monkeypatch, execution_mode=queued_mode)
    context.run["execution_mode"] = persisted_mode
    monkeypatch.setattr(faithsieve_tasks, "_execute_skill", lambda *_args: pytest.fail("错误队列不得执行"))
    monkeypatch.setattr(faithsieve_tasks, "_execute_workflow", lambda *_args: pytest.fail("错误队列不得执行"))
    assert worker(context, "attempt")["success"] is False
    assert context.run["status"] == "running"
    assert writes == finishes == context.cancellations == [] and lock.released


@pytest.mark.parametrize("mode", [None, "skill", "workflow"])
def test_controller_selects_durable_mode_and_claims_matching_workspace(monkeypatch, mode):
    from backend.oj_modules.faithsieve.skill import skill_identity
    celery = _FakeCelery()
    controller = faithsieve_tasks.register_faithsieve_grading_task(celery)
    run = {"attempt_id": "attempt", "status": "queued", "submission_id": 12, "problem_id": 7, "execution_mode": mode}
    monkeypatch.setattr(faithsieve_tasks, "get_run", lambda _attempt: run)
    claims = []
    monkeypatch.setattr(faithsieve_tasks, "claim_run_slot", lambda *_args, **kwargs: claims.append(kwargs) or True)
    context = SimpleNamespace(request=SimpleNamespace(id="ordinary-controller"), app=celery)
    assert controller(context, "attempt")["success"] is True
    actual = mode or "skill"
    assert claims[0]["session_id"] == ("faithsieve-attempt" if actual == "workflow" else skill_identity(run)[0])
    assert celery.dispatched == [{"args": ("attempt",), "queue": "agent", "task_id": f"fs-{actual}-attempt"}]


def test_controller_retries_invalid_persistent_mode_without_guessing_workflow(monkeypatch):
    celery = _FakeCelery()
    controller = faithsieve_tasks.register_faithsieve_grading_task(celery)
    monkeypatch.setattr(faithsieve_tasks, "get_run", lambda _attempt: {"status": "queued", "execution_mode": "", "submission_id": 12})
    monkeypatch.setattr(faithsieve_tasks, "claim_run_slot", lambda *_args, **_kwargs: pytest.fail("非法模式不得领取名额"))
    def retry(**_kwargs):
        raise Retry()
    context = SimpleNamespace(request=SimpleNamespace(id="ordinary-controller"), app=celery, retry=retry)
    with pytest.raises(Retry):
        controller(context, "attempt")
    assert celery.dispatched == []


def test_controller_database_read_failure_keeps_entry_message_without_finishing_run(monkeypatch):
    celery = _FakeCelery()
    controller = faithsieve_tasks.register_faithsieve_grading_task(celery)
    def unavailable(_attempt):
        raise RuntimeError("database temporarily unavailable")
    monkeypatch.setattr(faithsieve_tasks, "get_run", unavailable)
    monkeypatch.setattr(faithsieve_tasks, "claim_run_slot", lambda *_args, **_kwargs: pytest.fail("读失败不得领取名额"))
    monkeypatch.setattr(faithsieve_tasks, "finish_run", lambda *_args, **_kwargs: pytest.fail("读失败不得写终态"))
    monkeypatch.setattr(faithsieve_tasks, "_cancel_workflow_judges", lambda *_args: pytest.fail("读失败不得取消 workflow"))
    monkeypatch.setattr(faithsieve_tasks, "_cancel_skill_judge", lambda *_args: pytest.fail("读失败不得取消 skill"))
    retries = []
    def retry(**options):
        retries.append(options)
        raise Retry()
    context = SimpleNamespace(request=SimpleNamespace(id="ordinary-controller"), app=celery, retry=retry)
    with pytest.raises(Retry):
        controller(context, "attempt")
    assert retries == [{"countdown": 10, "max_retries": None}]
    assert celery.dispatched == []


def test_batch_route_queues_latest_submissions_for_manual_problem(monkeypatch):
    monkeypatch.setattr(
        grading_routes,
        "current_user",
        lambda: {"id": 1, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(grading_routes, "is_admin", lambda user: bool(user["is_admin"]))
    monkeypatch.setattr(
        grading_routes,
        "get_problem",
        lambda _problem_id: {"id": 7, "type": 2, "written_grading_mode": 4},
    )
    latest = [{"id": 11, "problem_id": 7}, {"id": 19, "problem_id": 7}]
    monkeypatch.setattr(
        grading_routes,
        "latest_submissions_for_problem",
        lambda _problem_id: latest,
    )
    monkeypatch.setattr(
        grading_routes,
        "_faithsieve_runtime",
        lambda _user: ("pi", 3, "workflow"),
    )
    seen = []
    monkeypatch.setattr(
        grading_routes,
        "_enqueue_faithsieve",
        lambda submissions, **kwargs: (
            seen.append((submissions, kwargs))
            or ([{"submission_id": 11}, {"submission_id": 19}], [], [])
        ),
    )
    monkeypatch.setattr(grading_routes, "_faithsieve_grading_task", object())
    app = Flask(__name__)

    with app.test_request_context(
        "/api/admin/problems/7/faithsieve",
        method="POST",
        json={"harness": "pi", "endpoint_id": 3},
    ):
        response = grading_routes.faithsieve_grade_problem(7)

    assert response.get_json()["submission_ids"] == [11, 19]
    assert seen == [(latest, {"user": {"id": 1, "username": "admin", "is_admin": 1}, "harness": "pi", "endpoint_id": 3, "execution_mode": "workflow"})]
