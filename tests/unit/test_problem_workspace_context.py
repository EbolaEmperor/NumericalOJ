from datetime import date, datetime
from unittest.mock import MagicMock

from flask import Flask

from oj_modules.routes import problem_core_routes


def _stub_base_context(monkeypatch):
    monkeypatch.setattr(
        problem_core_routes,
        "_base_problem_list_context",
        lambda: {"now": datetime(2026, 7, 22, 11, 35)},
    )


def test_admin_problem_list_rejects_unseen_class_and_uses_primary(monkeypatch):
    _stub_base_context(monkeypatch)
    classes = [
        {"class_en": "C1", "class_cn": "一班", "is_primary": 1},
        {"class_en": "C2", "class_cn": "二班", "is_primary": 0},
    ]
    monkeypatch.setattr(problem_core_routes, "visible_classes_for_user_cached", lambda _user: classes)
    monkeypatch.setattr(problem_core_routes, "get_all_problems", lambda: [{"id": 9}])
    load_homeworks = MagicMock(return_value={"C1": [{"id": 3, "problem_id": 7}]})
    monkeypatch.setattr(problem_core_routes, "_get_homeworks_for_classes", load_homeworks)
    attach_metrics = MagicMock(side_effect=lambda rows, **_kwargs: rows)
    monkeypatch.setattr(problem_core_routes, "attach_submission_metrics", attach_metrics)
    monkeypatch.setattr(problem_core_routes, "get_class_activity", lambda class_en: [class_en])
    user = {"id": 1, "username": "admin", "is_admin": 1}

    context = problem_core_routes.build_problem_list_context(
        user,
        admin_class_view=True,
        selected_class_en="NOT_VISIBLE",
        include_dashboard=True,
    )

    assert context["view_mode"] == "admin_class"
    assert context["selected_class_en"] == "C1"
    assert context["selected_homeworks"] == [{"id": 3, "problem_id": 7}]
    assert context["class_activity"] == ["C1"]
    assert context["problems"] == [{"id": 9}]  # 旧移动端仍保留总题库数据
    load_homeworks.assert_called_once_with(1, ["C1"], username="admin")
    attach_metrics.assert_called_once_with(context["selected_homeworks"], class_en="C1")


def test_admin_problem_list_without_classes_has_explicit_empty_workspace(monkeypatch):
    _stub_base_context(monkeypatch)
    monkeypatch.setattr(problem_core_routes, "visible_classes_for_user_cached", lambda _user: [])
    monkeypatch.setattr(problem_core_routes, "get_all_problems", lambda: [])

    context = problem_core_routes.build_problem_list_context(
        {"id": 1, "is_admin": 1},
        admin_class_view=True,
        include_dashboard=True,
    )

    assert context["view_mode"] == "admin_class_empty"
    assert context["selected_class"] is None
    assert context["selected_homeworks"] == []
    assert context["class_activity"] == []


def test_student_multi_class_context_only_aggregates_selected_class(monkeypatch):
    _stub_base_context(monkeypatch)
    classes = [
        {"class_en": "C1", "class_cn": "一班", "is_primary": 1},
        {"class_en": "C2", "class_cn": "二班", "is_primary": 0},
    ]
    monkeypatch.setattr(problem_core_routes, "get_user_classes_cached", lambda _uid: classes)
    monkeypatch.setattr(
        problem_core_routes,
        "get_homeworks_and_grades_map",
        lambda *_args: (
            {
                "C1": [{"id": 1, "problem_id": 11}],
                "C2": [{"id": 2, "problem_id": 22}],
            },
            {"C1": {"regular_score": 80}, "C2": {"regular_score": 90}},
        ),
    )
    attach_metrics = MagicMock(side_effect=lambda rows, **_kwargs: rows)
    monkeypatch.setattr(problem_core_routes, "attach_submission_metrics", attach_metrics)
    monkeypatch.setattr(problem_core_routes, "get_class_activity", lambda class_en: [class_en])

    context = problem_core_routes.build_problem_list_context(
        {"id": 8, "username": "student", "is_admin": 0},
        selected_class_en="C2",
        include_dashboard=True,
    )

    assert context["view_mode"] == "student_multi_class"
    assert context["selected_class_en"] == "C2"
    assert context["selected_homeworks"] == [{"id": 2, "problem_id": 22}]
    assert [block["class_en"] for block in context["homeworks_by_class"]] == ["C1", "C2"]
    attach_metrics.assert_called_once_with(context["selected_homeworks"], class_en="C2")
    assert context["class_activity"] == ["C2"]


def test_student_api_context_skips_dashboard_aggregation(monkeypatch):
    _stub_base_context(monkeypatch)
    classes = [{"class_en": "C1", "class_cn": "一班", "is_primary": 1}]
    monkeypatch.setattr(problem_core_routes, "get_user_classes_cached", lambda _uid: classes)
    monkeypatch.setattr(
        problem_core_routes,
        "get_homeworks_and_grades_map",
        lambda *_args: ({"C1": [{"id": 1, "problem_id": 11}]}, {}),
    )
    attach_metrics = MagicMock()
    class_activity = MagicMock()
    monkeypatch.setattr(problem_core_routes, "attach_submission_metrics", attach_metrics)
    monkeypatch.setattr(problem_core_routes, "get_class_activity", class_activity)

    context = problem_core_routes.build_problem_list_context(
        {"id": 8, "username": "student", "is_admin": 0}
    )

    assert context["homeworks"] == [{"id": 1, "problem_id": 11}]
    assert "selected_homeworks" not in context
    assert "class_activity" not in context
    attach_metrics.assert_not_called()
    class_activity.assert_not_called()


def test_problem_list_context_can_defer_class_activity(monkeypatch):
    _stub_base_context(monkeypatch)
    classes = [{"class_en": "C1", "class_cn": "一班", "is_primary": 1}]
    monkeypatch.setattr(problem_core_routes, "get_user_classes_cached", lambda _uid: classes)
    monkeypatch.setattr(
        problem_core_routes,
        "get_homeworks_and_grades_map",
        lambda *_args: ({"C1": [{"id": 1, "problem_id": 11}]}, {}),
    )
    monkeypatch.setattr(
        problem_core_routes,
        "attach_submission_metrics",
        lambda rows, **_kwargs: rows,
    )
    class_activity = MagicMock()
    monkeypatch.setattr(problem_core_routes, "get_class_activity", class_activity)

    context = problem_core_routes.build_problem_list_context(
        {"id": 8, "username": "student", "is_admin": 0},
        include_dashboard=True,
        include_class_activity=False,
    )

    assert context["selected_class_en"] == "C1"
    assert context["class_activity"] == []
    class_activity.assert_not_called()


def test_problem_library_attaches_global_metrics_without_deadline(monkeypatch):
    _stub_base_context(monkeypatch)
    problems = [{"id": 1, "title": "A"}, {"id": 2, "title": "B"}]
    monkeypatch.setattr(problem_core_routes, "get_all_problems", lambda: problems)
    get_metrics = MagicMock(
        return_value={1: {"submission_count": 3, "accepted_count": 2, "pass_rate": 2 / 3}}
    )
    monkeypatch.setattr(problem_core_routes, "get_problem_submission_metrics", get_metrics)

    context = problem_core_routes.build_problem_library_context(
        {"id": 1, "is_admin": 1}
    )

    assert context["view_mode"] == "admin_library"
    assert [problem["id"] for problem in context["problems"]] == [1, 2]
    assert context["problems"][0]["submission_metrics"]["submission_count"] == 3
    assert context["problems"][1]["submission_metrics"] is None
    assert all("ddl" not in problem for problem in context["problems"])
    get_metrics.assert_called_once_with([1, 2])


def test_admin_problem_detail_uses_only_authorized_class_homework(monkeypatch):
    problem = {
        "id": 7,
        "content": "# 题面",
        "initial_code": "",
        "submission_limit": 10,
    }
    monkeypatch.setattr(problem_core_routes, "get_problem", lambda _id: problem)
    monkeypatch.setattr(
        problem_core_routes,
        "visible_classes_for_user_cached",
        lambda _user: [{"class_en": "C1", "is_primary": 1}],
    )
    load_homeworks = MagicMock(
        return_value={
            "C1": [
                {"kind": "ranking", "problem_id": 7, "ddl": "wrong"},
                {"kind": "problem", "problem_id": 7, "ddl": "correct"},
            ]
        }
    )
    monkeypatch.setattr(problem_core_routes, "_get_homeworks_for_classes", load_homeworks)
    monkeypatch.setattr(
        problem_core_routes,
        "get_submission_summaries_by_user_and_problem",
        lambda *_args, **_kwargs: [],
    )
    user = {"id": 1, "username": "admin", "is_admin": 1}

    context, error = problem_core_routes.build_problem_detail_context(
        user, 7, selected_class_en="C1"
    )

    assert error is None
    assert context["homework"]["ddl"] == "correct"
    load_homeworks.assert_called_once_with(1, ["C1"], username="admin")

    load_homeworks.reset_mock()
    context, error = problem_core_routes.build_problem_detail_context(
        user, 7, selected_class_en="INJECTED"
    )
    assert error is None
    assert context["homework"] is None
    load_homeworks.assert_not_called()


def test_student_problem_detail_prefers_selected_class_deadline(monkeypatch):
    problem = {
        "id": 7,
        "content": "# 题面",
        "initial_code": "",
        "submission_limit": 10,
    }
    user = {"id": 8, "username": "student", "is_admin": 0}
    monkeypatch.setattr(problem_core_routes, "get_problem", lambda _id: problem)
    monkeypatch.setattr(
        problem_core_routes,
        "get_homeworks",
        lambda _user: [{"problem_id": 7, "ddl": "merged-latest"}],
    )
    monkeypatch.setattr(
        problem_core_routes,
        "visible_classes_for_user_cached",
        lambda _user: [{"class_en": "C2", "is_primary": 0}],
    )
    monkeypatch.setattr(
        problem_core_routes,
        "_get_homeworks_for_classes",
        lambda *_args, **_kwargs: {
            "C2": [{"kind": "problem", "problem_id": 7, "ddl": "selected-class"}]
        },
    )
    monkeypatch.setattr(
        problem_core_routes,
        "get_submission_summaries_by_user_and_problem",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(problem_core_routes, "get_remaining_submissions", lambda *_args: 9)
    monkeypatch.setattr(problem_core_routes, "can_submit", lambda *_args: True)

    context, error = problem_core_routes.build_problem_detail_context(
        user, 7, selected_class_en="C2"
    )

    assert error is None
    assert context["homework"]["ddl"] == "selected-class"


def test_problem_routes_forward_class_query_and_protect_total_library(monkeypatch):
    app = Flask(__name__)
    app.secret_key = "test"
    render = MagicMock(return_value="rendered")
    monkeypatch.setattr(problem_core_routes, "render_template", render)
    monkeypatch.setattr(problem_core_routes, "current_user", lambda: {"id": 1, "is_admin": 1})
    build_list = MagicMock(return_value={"marker": "list"})
    monkeypatch.setattr(problem_core_routes, "build_problem_list_context", build_list)

    with app.test_request_context("/problems?class_en=C2"):
        assert problem_core_routes.problem_list() == "rendered"
    build_list.assert_called_once_with(
        {"id": 1, "is_admin": 1},
        admin_class_view=True,
        selected_class_en="C2",
        include_dashboard=True,
        include_class_activity=False,
    )

    monkeypatch.setattr(problem_core_routes, "current_user", lambda: {"id": 8, "is_admin": 0})
    monkeypatch.setattr(problem_core_routes, "url_for", lambda endpoint, **_kwargs: f"/{endpoint}")
    with app.test_request_context("/problems/all"):
        response = problem_core_routes.problem_library()
    assert response.status_code == 302
    assert response.location.endswith("/problem_core.problem_list")


def test_class_activity_endpoint_returns_authorized_class_data(monkeypatch):
    app = Flask(__name__)
    user = {"id": 8, "username": "student", "is_admin": 0}
    monkeypatch.setattr(problem_core_routes, "current_user", lambda: user)
    monkeypatch.setattr(
        problem_core_routes,
        "visible_classes_for_user_cached",
        lambda _user: [
            {"class_en": "C1", "class_cn": "一班", "is_primary": 1},
        ],
    )
    load_activity = MagicMock(return_value=[
        {
            "day": date(2026, 7, 20),
            "count": 7,
            "intensity": 3,
            "future": False,
        }
    ])
    monkeypatch.setattr(problem_core_routes, "get_class_activity", load_activity)

    with app.test_request_context("/api/class-activity?class_en=C1"):
        response = problem_core_routes.class_activity_data()

    assert response.get_json() == {
        "success": True,
        "class_en": "C1",
        "class_cn": "一班",
        "activity": [
            {
                "day": "2026-07-20",
                "count": 7,
                "intensity": 3,
                "future": False,
            }
        ],
    }
    load_activity.assert_called_once_with("C1")


def test_class_activity_endpoint_rejects_unseen_class(monkeypatch):
    app = Flask(__name__)
    monkeypatch.setattr(
        problem_core_routes,
        "current_user",
        lambda: {"id": 8, "username": "student", "is_admin": 0},
    )
    monkeypatch.setattr(
        problem_core_routes,
        "visible_classes_for_user_cached",
        lambda _user: [
            {"class_en": "C1", "class_cn": "一班", "is_primary": 1},
        ],
    )
    load_activity = MagicMock()
    monkeypatch.setattr(problem_core_routes, "get_class_activity", load_activity)

    with app.test_request_context("/api/class-activity?class_en=C2"):
        response, status = problem_core_routes.class_activity_data()

    assert status == 403
    assert response.get_json() == {
        "success": False,
        "message": "无权查看该班级",
    }
    load_activity.assert_not_called()


def test_layout_navigation_endpoint_returns_fail_open_counts(monkeypatch):
    app = Flask(__name__)
    user = {"id": 1, "username": "admin", "is_admin": 1}
    monkeypatch.setattr(problem_core_routes, "current_user", lambda: user)
    navigation = MagicMock(return_value={
        "counts": {"homeworks": 6},
        "agent_active": True,
    })
    monkeypatch.setattr(
        problem_core_routes,
        "get_layout_navigation_context",
        navigation,
    )

    with app.test_request_context("/api/layout-navigation?class_en=C2"):
        response = problem_core_routes.layout_navigation_data()

    assert response.get_json() == {
        "success": True,
        "counts": {"homeworks": 6},
        "agent_active": True,
    }
    navigation.assert_called_once_with(user, selected_class_en="C2")


def test_problem_detail_route_forwards_class_query(monkeypatch):
    app = Flask(__name__)
    monkeypatch.setattr(
        problem_core_routes,
        "current_user",
        lambda: {"id": 1, "username": "admin", "is_admin": 1},
    )
    build_detail = MagicMock(return_value=({"marker": "detail"}, None))
    monkeypatch.setattr(problem_core_routes, "build_problem_detail_context", build_detail)
    render = MagicMock(return_value="rendered")
    monkeypatch.setattr(problem_core_routes, "render_template", render)

    with app.test_request_context("/problem/7?class_en=C2"):
        assert problem_core_routes.problem_detail(7) == "rendered"

    build_detail.assert_called_once_with(
        {"id": 1, "username": "admin", "is_admin": 1},
        7,
        selected_class_en="C2",
    )
    render.assert_called_once_with("problems/detail.html", marker="detail")
