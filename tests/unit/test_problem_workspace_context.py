from datetime import date, datetime
from unittest.mock import MagicMock

from flask import Flask

from backend.oj_modules.problems import catalog as problem_catalog
from backend.oj_modules.problems import context as problem_context
from backend.oj_modules.api import problem_api
from backend.oj_modules.routes import problem_core_routes


def _stub_base_context(monkeypatch):
    monkeypatch.setattr(
        problem_context,
        "_base_problem_list_context",
        lambda **_kwargs: {"now": datetime(2026, 7, 22, 11, 35)},
    )


def test_problem_list_statistics_are_opt_in(monkeypatch):
    today_counts = MagicMock(return_value=(12, 7))
    trend_counts = MagicMock(return_value=(["2026-07-22"], [12]))
    monkeypatch.setattr(problem_context, "get_today_submission_counts", today_counts)
    monkeypatch.setattr(
        problem_context,
        "get_last_10_days_counts_from_counter",
        trend_counts,
    )

    html_context = problem_context._base_problem_list_context()

    assert "total_submissions" not in html_context
    assert "daily_counts" not in html_context
    today_counts.assert_not_called()
    trend_counts.assert_not_called()

    api_context = problem_context._base_problem_list_context(
        include_statistics=True,
    )

    assert api_context["total_submissions"] == 12
    assert api_context["total_accepted"] == 7
    assert api_context["daily_counts"] == [12]
    today_counts.assert_called_once_with()
    trend_counts.assert_called_once_with()


def test_problem_catalog_cache_invalidation_keeps_original_scope(monkeypatch):
    clear_dashboard = MagicMock()
    monkeypatch.setattr(problem_catalog, "clear_dashboard_cache", clear_dashboard)
    monkeypatch.setattr(
        problem_catalog,
        "_homeworks_cache",
        {
            (1, ("C1",)): "user-one",
            (2, ("C1", "C2")): "class-two",
            (3, ("C3",)): "unrelated",
        },
    )
    monkeypatch.setattr(
        problem_catalog,
        "_class_grades_cache",
        {
            ("alice", ("C1",)): "user-one",
            ("bob", ("C2",)): "class-two",
            ("carol", ("C3",)): "unrelated",
        },
    )

    problem_catalog.invalidate_problem_list_cache_for_user(
        user_id=1,
        username="alice",
    )
    assert set(problem_catalog._homeworks_cache) == {
        (2, ("C1", "C2")),
        (3, ("C3",)),
    }
    assert set(problem_catalog._class_grades_cache) == {
        ("bob", ("C2",)),
        ("carol", ("C3",)),
    }

    problem_catalog.invalidate_problem_list_cache_for_class("C2")
    assert set(problem_catalog._homeworks_cache) == {(3, ("C3",))}
    assert set(problem_catalog._class_grades_cache) == {("carol", ("C3",))}

    problem_catalog.invalidate_problem_list_cache_all()
    assert problem_catalog._homeworks_cache == {}
    assert problem_catalog._class_grades_cache == {}
    assert clear_dashboard.call_count == 3


def test_admin_problem_list_rejects_unseen_class_and_uses_stable_first_class(monkeypatch):
    _stub_base_context(monkeypatch)
    classes = [
        {"class_en": "C1", "class_cn": "一班"},
        {"class_en": "C2", "class_cn": "二班"},
    ]
    monkeypatch.setattr(problem_context, "visible_classes_for_user_cached", lambda _user: classes)
    monkeypatch.setattr(problem_context, "get_all_problems", lambda: [{"id": 9}])
    load_homeworks = MagicMock(return_value={"C1": [{"id": 3, "problem_id": 7}]})
    monkeypatch.setattr(problem_context, "_get_homeworks_for_classes", load_homeworks)
    attach_metrics = MagicMock(side_effect=lambda rows, **_kwargs: rows)
    monkeypatch.setattr(problem_context, "attach_submission_metrics", attach_metrics)
    monkeypatch.setattr(problem_context, "get_class_activity", lambda class_en: [class_en])
    user = {"id": 1, "username": "admin", "is_admin": 1}

    context = problem_context.build_problem_list_context(
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
    monkeypatch.setattr(problem_context, "visible_classes_for_user_cached", lambda _user: [])
    monkeypatch.setattr(problem_context, "get_all_problems", lambda: [])

    context = problem_context.build_problem_list_context(
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
        {"class_en": "C1", "class_cn": "一班"},
        {"class_en": "C2", "class_cn": "二班"},
    ]
    monkeypatch.setattr(problem_context, "get_user_classes_cached", lambda _uid: classes)
    monkeypatch.setattr(
        problem_context,
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
    monkeypatch.setattr(problem_context, "attach_submission_metrics", attach_metrics)
    monkeypatch.setattr(problem_context, "get_class_activity", lambda class_en: [class_en])

    context = problem_context.build_problem_list_context(
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
    classes = [{"class_en": "C1", "class_cn": "一班"}]
    monkeypatch.setattr(problem_context, "get_user_classes_cached", lambda _uid: classes)
    monkeypatch.setattr(
        problem_context,
        "get_homeworks_and_grades_map",
        lambda *_args: ({"C1": [{"id": 1, "problem_id": 11}]}, {}),
    )
    attach_metrics = MagicMock()
    class_activity = MagicMock()
    monkeypatch.setattr(problem_context, "attach_submission_metrics", attach_metrics)
    monkeypatch.setattr(problem_context, "get_class_activity", class_activity)

    context = problem_context.build_problem_list_context(
        {"id": 8, "username": "student", "is_admin": 0}
    )

    assert context["homeworks"] == [{"id": 1, "problem_id": 11}]
    assert "selected_homeworks" not in context
    assert "class_activity" not in context
    attach_metrics.assert_not_called()
    class_activity.assert_not_called()


def test_problem_list_context_can_defer_class_activity(monkeypatch):
    _stub_base_context(monkeypatch)
    classes = [{"class_en": "C1", "class_cn": "一班"}]
    monkeypatch.setattr(problem_context, "get_user_classes_cached", lambda _uid: classes)
    monkeypatch.setattr(
        problem_context,
        "get_homeworks_and_grades_map",
        lambda *_args: ({"C1": [{"id": 1, "problem_id": 11}]}, {}),
    )
    monkeypatch.setattr(
        problem_context,
        "attach_submission_metrics",
        lambda rows, **_kwargs: rows,
    )
    class_activity = MagicMock()
    monkeypatch.setattr(problem_context, "get_class_activity", class_activity)

    context = problem_context.build_problem_list_context(
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
    monkeypatch.setattr(problem_context, "get_all_problems", lambda: problems)
    get_metrics = MagicMock(
        return_value={1: {"submission_count": 3, "accepted_count": 2, "pass_rate": 2 / 3}}
    )
    monkeypatch.setattr(problem_context, "get_problem_submission_metrics", get_metrics)

    context = problem_context.build_problem_library_context(
        {"id": 1, "is_admin": 1}
    )

    assert context["view_mode"] == "admin_library"
    assert [problem["id"] for problem in context["problems"]] == [1, 2]
    assert context["problems"][0]["submission_metrics"]["submission_count"] == 3
    assert context["problems"][1]["submission_metrics"] is None
    assert all("ddl" not in problem for problem in context["problems"])
    get_metrics.assert_called_once_with([1, 2])


def test_problem_detail_uses_all_visible_class_homeworks_regardless_of_entry(monkeypatch):
    problem = {
        "id": 7,
        "content": "# 题面",
        "initial_code": "",
        "submission_limit": 10,
    }
    monkeypatch.setattr(problem_context, "get_problem", lambda _id: problem)
    monkeypatch.setattr(
        problem_context,
        "visible_classes_for_user_cached",
        lambda _user: [{"class_en": "C1"}],
    )
    load_homeworks = MagicMock(
        return_value={
            "problem_exists": True,
            "rows": [{"id": 2, "class_en": "C1", "problem_id": 7, "ddl": "correct"}],
        }
    )
    monkeypatch.setattr(
        problem_context, "get_problem_homework_deadline_state", load_homeworks,
    )
    monkeypatch.setattr(
        problem_context,
        "get_submission_summaries_by_user_and_problem",
        lambda *_args, **_kwargs: [],
    )
    user = {"id": 1, "username": "admin", "is_admin": 1}

    context, error = problem_context.build_problem_detail_context(
        user, 7, selected_class_en="C1"
    )

    assert error is None
    assert context["homework"]["ddl"] == "correct"
    load_homeworks.assert_called_once_with(7, ["C1"], verify_problem=False)

    load_homeworks.reset_mock()
    context, error = problem_context.build_problem_detail_context(
        user, 7, selected_class_en="INJECTED"
    )
    assert error is None
    assert context["homework"]["ddl"] == "correct"
    load_homeworks.assert_called_once_with(7, ["C1"], verify_problem=False)


def test_problem_task_agent_can_read_only_its_scoped_problem(monkeypatch):
    problem = {
        "id": 104,
        "content": "# Lean 题目",
        "initial_code": "theorem answer : True := by trivial",
        "submission_limit": 10,
    }
    monkeypatch.setattr(problem_context, "get_problem", lambda _id: problem)
    load_assignments = MagicMock(return_value=[])
    monkeypatch.setattr(
        problem_context, "get_problem_homework_assignments", load_assignments,
    )
    monkeypatch.setattr(
        problem_context,
        "get_submission_summaries_by_user_and_problem",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(problem_context, "get_remaining_submissions", lambda *_args: 10)
    monkeypatch.setattr(problem_context, "can_submit", lambda *_args: True)
    agent_user = {
        "id": 1,
        "username": "admin",
        "is_admin": 0,
        "agent_access_role": "user",
        "agent_task_kind": "solve",
        "agent_problem_id": 104,
    }

    context, error = problem_context.build_problem_detail_context(agent_user, 104)

    assert error is None
    assert context["problem"]["id"] == 104
    load_assignments.assert_not_called()

    _context, error = problem_context.build_problem_detail_context(agent_user, 105)

    assert error == "forbidden"
    load_assignments.assert_not_called()


def test_problem_detail_context_uses_shared_rich_markdown_renderer(monkeypatch):
    problem = {
        "id": 7,
        "content": "```python\nprint('shared')\n```",
        "initial_code": "",
        "submission_limit": 10,
    }
    renderer = MagicMock(
        return_value=(
            '<div class="codehilite language-python">'
            "<pre><code><span class=\"nb\">print</span></code></pre></div>"
        )
    )
    monkeypatch.setattr(problem_context, "get_problem", lambda _id: problem)
    monkeypatch.setattr(problem_context, "render_rich_markdown", renderer)
    monkeypatch.setattr(
        problem_context,
        "get_submission_summaries_by_user_and_problem",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        problem_context, "get_problem_homework_assignments", lambda *_args: [],
    )

    context, error = problem_context.build_problem_detail_context(
        {"id": 1, "username": "admin", "is_admin": 1},
        7,
    )

    assert error is None
    assert 'class="codehilite language-python"' in context["rendered_content"]
    renderer.assert_called_once_with(problem["content"])


def test_student_problem_detail_lists_all_class_deadlines_regardless_of_entry(monkeypatch):
    problem = {
        "id": 7,
        "content": "# 题面",
        "initial_code": "",
        "submission_limit": 10,
    }
    user = {"id": 8, "username": "student", "is_admin": 0}
    monkeypatch.setattr(problem_context, "get_problem", lambda _id: problem)
    monkeypatch.setattr(
        problem_context,
        "visible_classes_for_user_cached",
        lambda _user: [
            {"class_en": "C1", "class_cn": "一班"},
            {"class_en": "C2", "class_cn": "二班"},
        ],
    )
    monkeypatch.setattr(
        problem_context,
        "get_problem_homework_deadline_state",
        lambda *_args, **_kwargs: {
            "problem_exists": True,
            "rows": [
                {"id": 1, "class_en": "C1", "problem_id": 7, "ddl": "first-class"},
                {"id": 2, "class_en": "C2", "problem_id": 7, "ddl": "selected-class"},
            ],
        },
    )
    monkeypatch.setattr(
        problem_context,
        "get_submission_summaries_by_user_and_problem",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(problem_context, "get_remaining_submissions", lambda *_args: 9)
    monkeypatch.setattr(problem_context, "can_submit", lambda *_args: True)

    context, error = problem_context.build_problem_detail_context(
        user, 7, selected_class_en="C2"
    )

    assert error is None
    assert [item["class_cn"] for item in context["homework_assignments"]] == [
        "一班", "二班",
    ]
    assert context["homework"]["ddl"] == "first-class"


def test_student_problem_detail_reports_expired_homework_submission_warning(monkeypatch):
    problem = {
        "id": 7,
        "content": "# 题面",
        "initial_code": "",
        "submission_limit": 10,
    }
    user = {"id": 8, "username": "student", "is_admin": 0}
    monkeypatch.setattr(problem_context, "get_problem", lambda _id: problem)
    monkeypatch.setattr(
        problem_context,
        "visible_classes_for_user_cached",
        lambda _user: [{"class_en": "C1", "class_cn": "一班"}],
    )
    monkeypatch.setattr(
        problem_context,
        "get_problem_homework_deadline_state",
        lambda *_args, **_kwargs: {
            "problem_exists": True,
            "rows": [{
                "id": 3,
                "class_en": "C1",
                "problem_id": 7,
                "ddl": datetime(2026, 1, 1),
            }],
        },
    )
    monkeypatch.setattr(
        problem_context,
        "get_submission_summaries_by_user_and_problem",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(problem_context, "get_remaining_submissions", lambda *_args: 10)
    monkeypatch.setattr(problem_context, "can_submit", lambda *_args: True)

    context, error = problem_context.build_problem_detail_context(user, 7)

    assert error is None
    assert context["can_submit"] is True
    assert context["submit_block_code"] == ""
    assert context["submit_block_reason"] == ""
    assert context["submit_warning"]["code"] == "homework_deadline_passed"
    assert context["submit_warning"]["homeworks"][0]["class_cn"] == "一班"


def test_deadline_warning_api_uses_lightweight_context(monkeypatch):
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(problem_api.problem_api_bp)
    monkeypatch.setattr(
        problem_api,
        "current_user",
        lambda: {"id": 8, "username": "student", "is_admin": 0},
    )
    warning = {
        "code": "homework_deadline_passed",
        "message": "已截止",
        "homeworks": [{"class_en": "C1", "class_cn": "一班", "ddl": "2026-01-01 00:00"}],
    }
    lightweight = MagicMock(return_value=(
        {"problem_id": 7, "submit_warning": warning},
        None,
    ))
    monkeypatch.setattr(
        problem_api,
        "build_problem_deadline_warning_context",
        lightweight,
    )
    monkeypatch.setattr(
        problem_api,
        "build_problem_detail_context",
        MagicMock(side_effect=AssertionError("轻量接口不应构建完整题目详情")),
    )

    response = app.test_client().get("/api/problems/7/deadline-warning")

    assert response.status_code == 200
    assert response.get_json() == {
        "success": True,
        "problem_id": 7,
        "submit_warning": warning,
    }
    lightweight.assert_called_once_with(
        {"id": 8, "username": "student", "is_admin": 0},
        7,
    )


def test_problem_routes_forward_class_query_and_open_total_library(monkeypatch):
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
    build_library = MagicMock(return_value={"marker": "library"})
    monkeypatch.setattr(
        problem_core_routes, "build_problem_library_context", build_library,
    )
    with app.test_request_context("/problems/all"):
        response = problem_core_routes.problem_library()
    assert response == "rendered"
    build_library.assert_called_once_with({"id": 8, "is_admin": 0})


def test_problem_list_remembers_selected_class_in_cookie(monkeypatch):
    app = Flask(__name__)
    app.secret_key = "test"
    user = {"id": 1, "is_admin": 0}
    monkeypatch.setattr(problem_core_routes, "current_user", lambda: user)
    monkeypatch.setattr(
        problem_core_routes,
        "render_template",
        lambda _template, **_context: "rendered",
    )
    build_list = MagicMock(
        side_effect=lambda _user, **kwargs: {
            "selected_class_en": kwargs["selected_class_en"] or "C1",
        },
    )
    monkeypatch.setattr(
        problem_core_routes, "build_problem_list_context", build_list,
    )

    cookie_name = problem_core_routes._PROBLEM_LIST_CLASS_COOKIE
    with app.test_request_context(
        "/problems?class_en=C2",
        headers={"Cookie": f"{cookie_name}=C1"},
    ):
        response = problem_core_routes.problem_list()

    assert response.get_data(as_text=True) == "rendered"
    assert f"{cookie_name}=C2" in response.headers["Set-Cookie"]
    assert "HttpOnly" in response.headers["Set-Cookie"]
    assert "SameSite=Lax" in response.headers["Set-Cookie"]
    assert "Path=/problems" in response.headers["Set-Cookie"]
    assert build_list.call_args.kwargs["selected_class_en"] == "C2"

    build_list.reset_mock()
    with app.test_request_context(
        "/problems",
        headers={"Cookie": f"{cookie_name}=C2"},
    ):
        problem_core_routes.problem_list()
    assert build_list.call_args.kwargs["selected_class_en"] == "C2"


def test_class_activity_endpoint_returns_authorized_class_data(monkeypatch):
    app = Flask(__name__)
    user = {"id": 8, "username": "student", "is_admin": 0}
    monkeypatch.setattr(problem_core_routes, "current_user", lambda: user)
    monkeypatch.setattr(
        problem_core_routes,
        "visible_classes_for_user_cached",
        lambda _user: [
            {"class_en": "C1", "class_cn": "一班"},
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
            {"class_en": "C1", "class_cn": "一班"},
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
