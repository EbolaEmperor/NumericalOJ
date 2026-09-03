from __future__ import annotations

import pymysql
import pytest

from backend.oj_modules.tasks import evaluate_tasks


class _FakeCelery:
    def __init__(self):
        self.tasks = {}

    def task(self, **options):
        def decorator(function):
            self.tasks[options["name"]] = function
            return function

        return decorator


def _patch_runtime(monkeypatch, *, problem):
    submission = {
        "id": 46026,
        "problem_id": 71,
        "problem_type": 1,
        "username": "admin",
        "status": "Pending",
        "code": "int main(void) { return 0; }",
    }
    status_updates = []
    evaluation_updates = []
    snapshots = []
    monkeypatch.setattr(
        evaluate_tasks,
        "get_submission_by_id",
        lambda _submission_id: dict(submission),
    )
    monkeypatch.setattr(evaluate_tasks, "get_problem", problem)
    monkeypatch.setattr(
        evaluate_tasks,
        "_acquire_submission_lock",
        lambda _submission_id: (None, None, None),
    )
    monkeypatch.setattr(evaluate_tasks, "_release_submission_lock", lambda *_args: None)
    monkeypatch.setattr(
        evaluate_tasks,
        "update_submission_status",
        lambda submission_id, status: status_updates.append((submission_id, status)),
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "update_submission_evaluation",
        lambda submission_id, points, score, status: evaluation_updates.append(
            (submission_id, points, score, status)
        ),
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "set_submission_status_snapshot",
        lambda **payload: snapshots.append(payload),
    )
    monkeypatch.setattr(
        evaluate_tasks.core,
        "cleanup_run_artifacts_for_submission",
        lambda _submission_id: None,
    )
    return submission, status_updates, evaluation_updates, snapshots


def test_missing_image_grading_endpoint_finishes_submission_and_sse(monkeypatch):
    submission, status_updates, evaluation_updates, snapshots = _patch_runtime(
        monkeypatch,
        problem=lambda _problem_id: {
            "id": 71,
            "lang": "c",
            "programming_grading_mode": 2,
            "output_image_grading_endpoint_id": 4,
        },
    )
    monkeypatch.delenv("NUMOJ_FAKE_PROGRAM_IMAGE_GRADING_RESULT", raising=False)
    monkeypatch.setattr(
        evaluate_tasks,
        "resolve_problem_llm_endpoint_snapshot",
        lambda *_args: (_ for _ in ()).throw(
            RuntimeError("端点不存在或已删除（ID: 4）")
        ),
    )

    task = evaluate_tasks.register_evaluate_submission_task(_FakeCelery())
    task(None, submission["id"])

    assert status_updates == [(submission["id"], "Running")]
    assert evaluation_updates[-1][2:] == (0, "Error")
    assert "端点不存在或已删除" in evaluation_updates[-1][1][0]["stderr"]
    assert snapshots[-1]["status"] == "Error"
    assert snapshots[-1]["test_points"][0]["status"] == "Error"


def test_unexpected_runtime_error_is_terminal_before_task_failure(monkeypatch):
    submission, _status_updates, evaluation_updates, snapshots = _patch_runtime(
        monkeypatch,
        problem=lambda _problem_id: (_ for _ in ()).throw(
            ValueError("unexpected internal detail")
        ),
    )

    task = evaluate_tasks.register_evaluate_submission_task(_FakeCelery())
    with pytest.raises(ValueError, match="unexpected internal detail"):
        task(None, submission["id"])

    assert evaluation_updates[-1][2:] == (0, "Error")
    assert evaluation_updates[-1][1][0]["stderr"] == (
        "判题任务异常退出，请联系管理员检查服务日志。"
    )
    assert snapshots[-1]["status"] == "Error"


def test_transient_database_error_during_endpoint_resolution_still_retries(
        monkeypatch):
    submission, _status_updates, evaluation_updates, snapshots = _patch_runtime(
        monkeypatch,
        problem=lambda _problem_id: {
            "id": 71,
            "lang": "c",
            "programming_grading_mode": 2,
            "output_image_grading_endpoint_id": 4,
        },
    )
    monkeypatch.delenv("NUMOJ_FAKE_PROGRAM_IMAGE_GRADING_RESULT", raising=False)
    monkeypatch.setattr(
        evaluate_tasks,
        "resolve_problem_llm_endpoint_snapshot",
        lambda *_args: (_ for _ in ()).throw(
            pymysql.err.OperationalError(2006, "server has gone away")
        ),
    )

    task = evaluate_tasks.register_evaluate_submission_task(_FakeCelery())
    with pytest.raises(pymysql.err.OperationalError):
        task(None, submission["id"])

    assert evaluation_updates == []
    assert snapshots[-1]["status"] == "Running"
