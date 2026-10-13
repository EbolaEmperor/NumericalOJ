"""关闭公开评分时，学生聚合视图不能从缓存和派生状态推断成绩。"""

from copy import deepcopy
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from backend.oj_modules.classroom import dashboard
from backend.oj_modules.problems import catalog, context


STUDENT = {"id": 8, "username": "alice", "is_admin": 0}
ADMIN = {"id": 1, "username": "admin", "is_admin": 1}


def _written_problem(*, public=False):
    return {
        "id": 7,
        "type": 2,
        "written_grading_mode": 1,
        "written_score_public": int(public),
    }


def test_homework_projection_respects_new_policy_without_mutating_cached_scores(monkeypatch):
    cached = {"C1": [{
        "problem_id": 7, "kind": "problem", "max_score": 95,
        "practice_max_score": 100, "best_submission_id": 10,
        "best_submission_at": datetime(2026, 10, 12), "is_completed": True,
        "complete_cnt": 4, "has_submission": True, "has_pending_submission": False,
    }, {"kind": "ranking", "competition_id": 2, "max_score": 80}]}
    original = deepcopy(cached)
    policy = _written_problem()
    load_policy = MagicMock(side_effect=lambda _ids: {7: dict(policy)})
    monkeypatch.setattr(catalog, "get_problem_visibility_map", load_policy)

    hidden = catalog.project_homework_grading_map(cached, STUDENT)["C1"]

    assert hidden[0]["result_visible"] is False
    for key in (
        "max_score", "practice_max_score", "best_submission_id",
        "best_submission_at", "is_completed", "complete_cnt",
    ):
        assert hidden[0][key] is None
    assert hidden[0]["has_submission"] is True
    assert hidden[0]["has_pending_submission"] is False
    assert hidden[1]["max_score"] == 80
    assert cached == original

    policy["written_score_public"] = 1
    published = catalog.project_homework_grading_map(cached, STUDENT)
    assert published == original
    assert load_policy.call_count == 2


def test_administrator_homework_scores_do_not_require_visibility_lookup(monkeypatch):
    load_policy = MagicMock()
    monkeypatch.setattr(catalog, "get_problem_visibility_map", load_policy)
    cached = {"C1": [{"problem_id": 7, "max_score": 100, "is_completed": True}]}

    assert catalog.project_homework_grading_map(cached, ADMIN) == cached
    load_policy.assert_not_called()


def test_student_metrics_recheck_current_policy_after_cache_hit(monkeypatch):
    dashboard.clear_dashboard_cache()
    rows = MagicMock(return_value=[{
        "entity_id": 7, "submission_count": 5, "accepted_count": 4,
    }])
    monkeypatch.setattr(dashboard, "_metric_rows", rows)
    policy = _written_problem(public=True)
    load_policy = MagicMock(side_effect=lambda _ids: {7: dict(policy)})
    monkeypatch.setattr(dashboard, "get_problem_visibility_map", load_policy)
    try:
        published = dashboard.get_problem_submission_metrics([7], viewer=STUDENT)
        assert published[7]["accepted_count"] == 4

        policy["written_score_public"] = 0
        hidden = dashboard.get_problem_submission_metrics([7], viewer=STUDENT)
        assert hidden[7] == {
            "submission_count": 5, "accepted_count": None,
            "pass_rate": None, "result_visible": False,
        }
        admin_result = dashboard.get_problem_submission_metrics([7], viewer=ADMIN)
        assert admin_result[7]["accepted_count"] == 4
        assert admin_result[7]["pass_rate"] == 0.8
        rows.assert_called_once()
        assert load_policy.call_count == 2
    finally:
        dashboard.clear_dashboard_cache()


def test_student_problem_context_projects_all_class_homeworks(monkeypatch):
    cached = {
        "C1": [{"problem_id": 7, "max_score": 90, "is_completed": True}],
        "C2": [{"problem_id": 7, "max_score": 80, "is_completed": False}],
    }
    monkeypatch.setattr(context, "get_user_classes_cached", lambda _id: [
        {"class_en": "C1", "class_cn": "一班"},
        {"class_en": "C2", "class_cn": "二班"},
    ])
    monkeypatch.setattr(context, "get_homeworks_and_grades_map", lambda *_args: (cached, {}))
    load_policy = MagicMock(return_value={7: _written_problem()})
    monkeypatch.setattr(catalog, "get_problem_visibility_map", load_policy)

    result = context.build_problem_list_context(STUDENT)

    assert all(
        row["result_visible"] is False and row["max_score"] is None
        for block in result["homeworks_by_class"] for row in block["hw_list"]
    )
    assert cached["C1"][0]["max_score"] == 90
    load_policy.assert_called_once_with({7})


def test_problem_detail_latest_submission_obeys_current_visibility(monkeypatch):
    problem = {**_written_problem(), "content": "题面", "submission_limit": 10}
    submission = {"id": 9, "score": 88, "status": "Accepted", "code": "隐藏评语"}
    monkeypatch.setattr(context, "get_problem", lambda _id: problem)
    monkeypatch.setattr(context, "get_problem_homework_assignments", lambda *_args: [])
    monkeypatch.setattr(context, "render_rich_markdown", lambda text: text)
    monkeypatch.setattr(context, "get_submission_summaries_by_user_and_problem", lambda *_a, **_kw: [submission])
    monkeypatch.setattr(context, "get_remaining_submissions", lambda *_args: 9)

    result, error = context.build_problem_detail_context(STUDENT, 7)

    assert error is None
    assert result["last_submissions"][0]["score"] is None
    assert result["last_submissions"][0]["status"] == "评分未公开"
    assert result["last_submissions"][0]["code"] == ""
    assert submission["score"] == 88

    admin_result, _ = context.build_problem_detail_context(ADMIN, 7)
    assert admin_result["last_submissions"][0]["score"] == 88


@pytest.mark.parametrize("viewer, applies_visibility", [(STUDENT, True), (ADMIN, False), (None, False)])
def test_today_accepted_count_filters_hidden_written_scores_only_for_students(monkeypatch, viewer, applies_visibility):
    cursor = MagicMock()
    cursor.__enter__.return_value = cursor
    cursor.fetchone.return_value = {"total_accepted": 3}
    connection = MagicMock()
    connection.cursor.return_value = cursor
    monkeypatch.setattr(catalog, "get_db_connection", lambda: connection)
    monkeypatch.setattr(catalog, "get_today_submission_total_from_counter", lambda: 12)

    assert catalog.get_today_submission_counts(viewer=viewer) == (12, 3)

    query, params = cursor.execute.call_args.args
    assert len(params) == 2
    assert ("p.written_score_public" in query) is applies_visibility
    if applies_visibility:
        assert "p.written_grading_mode, 1) IN (1, 2, 3)" in query
        assert "p.type, 0) = 2" in query
    connection.close.assert_called_once()
