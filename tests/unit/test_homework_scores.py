from datetime import datetime

from backend.oj_modules.homework.scores import homework_score_snapshot


def _submission(submission_id, score, created_at, status="Accepted"):
    return {
        "id": submission_id,
        "score": score,
        "status": status,
        "created_at": created_at,
    }


def test_homework_score_accepts_submissions_made_before_assignment_exists():
    snapshot = homework_score_snapshot(
        [_submission(1, 10, datetime(2025, 1, 1, 12, 0))],
        datetime(2026, 8, 28, 23, 59),
    )

    assert snapshot["best"]["id"] == 1
    assert snapshot["best"]["score"] == 10


def test_homework_score_includes_exact_deadline_and_excludes_late_improvement():
    deadline = datetime(2026, 8, 28, 20, 0)
    snapshot = homework_score_snapshot(
        [
            _submission(1, 7, deadline),
            _submission(2, 10, datetime(2026, 8, 28, 20, 0, 1)),
        ],
        deadline,
    )

    assert snapshot["best"]["id"] == 1
    assert snapshot["best"]["score"] == 7
    assert snapshot["practice_best"]["id"] == 2
    assert snapshot["practice_best"]["score"] == 10


def test_homework_score_waits_for_pre_deadline_submission_to_finish_grading():
    snapshot = homework_score_snapshot(
        [
            _submission(
                3,
                0,
                datetime(2026, 8, 28, 19, 59),
                status="Running",
            )
        ],
        datetime(2026, 8, 28, 20, 0),
    )

    assert snapshot["best"] is None
    assert snapshot["has_pending"] is True
    assert len(snapshot["eligible"]) == 1


def test_homework_without_deadline_uses_lifetime_best_score():
    snapshot = homework_score_snapshot(
        [
            _submission(1, 4, datetime(2025, 1, 1)),
            _submission(2, 9, datetime(2027, 1, 1)),
        ],
        None,
    )

    assert snapshot["best"]["id"] == 2
    assert snapshot["practice_best"]["id"] == 2
