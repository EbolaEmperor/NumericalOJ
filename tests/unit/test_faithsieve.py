"""FaithSieve 队列、结果协议与 schema 契约。"""

from pathlib import Path
import re
from types import SimpleNamespace

from flask import Flask
import pytest

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
    root = Path(__file__).resolve().parents[2]
    skill = (root / "skills" / "faithsieve" / "SKILL.md").read_text(
        encoding="utf-8",
    )
    agents = root / "skills" / "faithsieve" / "references" / "agents"
    assert "必须实际使用 Task 子 Agent" in skill
    assert "references/agents/semantic-checker.md" in skill
    assert "references/agents/proof-searcher.md" in skill
    assert "派发提示词时填写参数" not in skill
    assert "frozen_declaration_hash" not in skill
    for prompt in agents.glob("*.md"):
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
    def task(self, **_options):
        def decorate(function):
            self.registered = function
            return function

        return decorate


def test_completed_agent_result_updates_manual_grade(monkeypatch):
    celery = _FakeCelery()
    task = faithsieve_tasks.register_faithsieve_grading_task(celery)
    writes = []
    finishes = []
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_run",
        lambda _attempt: {
            "status": "running",
            "submission_id": 12,
            "problem_id": 7,
        },
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_submission_by_id",
        lambda _submission_id: {"id": 12, "problem_id": 7, "username": "student"},
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_problem",
        lambda _problem_id: {"id": 7, "type": 2, "written_grading_mode": 4},
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_agent_session",
        lambda session_id: {
            "session_id": session_id,
            "current_task_id": "turn",
            "status": "Completed",
        },
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_agent_session_turns",
        lambda _session_id: [{"task_id": "turn", "status": "Completed"}],
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "_read_result",
        lambda _session_id: {
            "verdict": "incorrect",
            "score": 2,
            "comment": "首个实质错误出现在第 3 步。",
        },
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "update_submission_score_and_comment",
        lambda submission_id, score, comment: writes.append(
            ("grade", submission_id, score, comment),
        ),
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "update_submission_status",
        lambda submission_id, status: writes.append(("status", submission_id, status)),
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "finish_run",
        lambda *args, **kwargs: finishes.append((args, kwargs)),
    )
    task_context = SimpleNamespace(
        request=SimpleNamespace(id="controller-task"),
        app=SimpleNamespace(),
    )

    result = task(task_context, "attempt")

    assert result == {"success": True, "score": 2}
    assert writes == [
        ("grade", 12, 2, "首个实质错误出现在第 3 步。"),
        ("status", 12, "Unaccepted"),
    ]
    assert finishes[0][0][:3] == ("attempt", "completed", "评测完成，得分 2/5")


def test_inconclusive_agent_result_does_not_overwrite_grade(monkeypatch):
    celery = _FakeCelery()
    task = faithsieve_tasks.register_faithsieve_grading_task(celery)
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_run",
        lambda _attempt: {
            "status": "running",
            "submission_id": 12,
            "problem_id": 7,
        },
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_submission_by_id",
        lambda _submission_id: {"id": 12, "problem_id": 7, "username": "student"},
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_problem",
        lambda _problem_id: {"id": 7, "type": 2, "written_grading_mode": 4},
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_agent_session",
        lambda session_id: {
            "session_id": session_id,
            "current_task_id": "turn",
            "status": "Completed",
        },
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "get_agent_session_turns",
        lambda _session_id: [{"task_id": "turn", "status": "Completed"}],
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "_read_result",
        lambda _session_id: {
            "verdict": "inconclusive",
            "score": 3,
            "comment": "原稿第 2 页符号无法辨认。",
        },
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "update_submission_score_and_comment",
        lambda *_args: pytest.fail("无结论不得覆盖分数"),
    )
    monkeypatch.setattr(
        faithsieve_tasks,
        "update_submission_status",
        lambda *_args: pytest.fail("无结论不得覆盖状态"),
    )
    finishes = []
    monkeypatch.setattr(
        faithsieve_tasks,
        "finish_run",
        lambda *args, **kwargs: finishes.append((args, kwargs)),
    )

    result = task(
        SimpleNamespace(request=SimpleNamespace(id="task"), app=SimpleNamespace()),
        "attempt",
    )

    assert result["success"] is False
    assert finishes[0][0][1] == "inconclusive"


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
        lambda _user: ("pi", 3),
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
    assert seen == [(latest, {"user": {"id": 1, "username": "admin", "is_admin": 1}, "harness": "pi", "endpoint_id": 3})]
