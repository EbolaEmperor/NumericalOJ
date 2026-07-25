import json
from pathlib import Path

from flask import Flask

from oj_modules import db_services
from oj_modules.api import submission_api
from oj_modules.routes import rejudge_routes
from oj_modules.routes import submission_routes


ROOT = Path(__file__).resolve().parents[2]


def test_regular_user_search_cannot_match_submitter():
    sql, params = db_services._build_submission_list_where(
        username="alice",
        query="bob",
        status_filter="accepted",
        problem_id=17,
    )

    assert "s.username = %s" in sql
    assert "s.username LIKE %s" not in sql
    assert "s.problem_title LIKE %s" in sql
    assert "s.problem_id = %s" in sql
    assert params == ("alice", "Accepted", 17, "%bob%")


def test_admin_search_can_match_submitter_and_numeric_ids():
    sql, params = db_services._build_submission_list_where(
        username=None,
        query="42",
    )

    assert "s.username = %s" not in sql
    assert "s.username LIKE %s" in sql
    assert "s.id = %s" in sql
    assert "s.problem_id = %s" in sql
    assert params == ("%42%", 42, 42, "%42%")


def test_output_limit_filter_is_first_class_and_not_grouped_as_other():
    sql, params = db_services._build_submission_list_where(
        status_filter="output_limit",
    )

    assert db_services.normalize_submission_list_status_filter(
        "output_limit"
    ) == "output_limit"
    assert "s.status = %s" in sql
    assert params == ("Output Limit Exceeded",)

    other_sql, other_params = db_services._build_submission_list_where(
        status_filter="other",
    )
    assert "s.status NOT IN" in other_sql
    assert "Output Limit Exceeded" in other_params


def test_output_limit_status_has_failure_styles_and_compact_labels():
    list_js = (ROOT / "static" / "app" / "submissions.js").read_text(
        encoding="utf-8"
    )
    list_css = (ROOT / "static" / "app" / "submissions.css").read_text(
        encoding="utf-8"
    )
    list_page = (
        ROOT / "templates" / "submissions" / "all.html"
    ).read_text(encoding="utf-8")
    list_component = (
        ROOT / "templates" / "submissions" / "components" / "table.html"
    ).read_text(encoding="utf-8")
    submission_detail = (
        ROOT / "templates" / "submissions" / "detail.html"
    ).read_text(encoding="utf-8")
    problem_detail = (
        ROOT / "templates" / "problems" / "detail.html"
    ).read_text(encoding="utf-8")
    layout_css = (ROOT / "static" / "app" / "layout.css").read_text(
        encoding="utf-8"
    )

    assert '"Output Limit Exceeded"' in list_js
    assert "Output Limit Exceeded" in list_component
    assert "'Output Limit Exceeded': 'OLE'" in submission_detail
    assert "'Output Limit Exceeded': 'OL'" in problem_detail
    assert "('output_limit', 'Output Limit Exceeded')" in list_page
    assert ".submission-verdict--output-limit-exceeded" in list_css
    assert ".submission-status.output-limit-exceeded" in layout_css


class _SubmissionListCursor:
    def __init__(self):
        self.calls = []
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self.calls.append((normalized, params))
        if normalized.startswith("SELECT COUNT(*)"):
            self._result = {"total": 31}
        else:
            self._result = [{
                "id": 1,
                "problem_id": 2,
                "username": "alice",
                "status": "Unaccepted",
                "score": 1,
                "problem_title": "题目",
                "problem_type": 1,
                "created_at": None,
                "test_points": "\n".join((
                    json.dumps({"status": "Accepted"}),
                    json.dumps({"status": "Wrong Answer"}),
                    json.dumps("written-file.pdf"),
                )),
                "lang": "python",
                "max_score": 2,
            }]

    def fetchone(self):
        return self._result

    def fetchall(self):
        return self._result


class _SubmissionListConnection:
    def __init__(self):
        self.cursor_instance = _SubmissionListCursor()
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def close(self):
        self.closed = True


def test_filtered_submission_query_clamps_page_and_parses_spark_points(monkeypatch):
    connection = _SubmissionListConnection()
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)

    rows, page, total_pages = db_services.get_filtered_submissions_paginated(
        username="alice",
        page=99,
        per_page=30,
        include_test_points=True,
    )

    assert page == 2
    assert total_pages == 2
    assert rows[0]["test_points"] == [
        {"status": "Accepted"},
        {"status": "Wrong Answer"},
    ]
    assert rows[0]["test_points_count"] == 2
    data_sql, data_params = connection.cursor_instance.calls[1]
    assert "LEFT JOIN problems p ON p.id = s.problem_id" in data_sql
    assert data_params[-2:] == (30, 30)
    assert connection.closed is True


def test_panel_payload_excludes_source_and_truncates_test_output(monkeypatch):
    monkeypatch.setattr(
        submission_api,
        "url_for",
        lambda endpoint, **values: (
            f"/{endpoint}/{values['submission_id']}"
            + ("?view=panel" if values.get("view") == "panel" else "")
        ),
    )
    submission = {
        "id": 9,
        "username": "alice",
        "problem_id": 3,
        "problem_title": "题目",
        "problem_type": 1,
        "status": "Wrong Answer",
        "score": 1,
        "created_at": "2026-07-23 12:00:00",
        "code": "do not send",
        "prompt_text": "do not send",
        "test_points": [{
            "test_index": 1,
            "status": "Wrong Answer",
            "stderr": "x" * 900,
        }],
    }

    payload = submission_api._submission_panel_payload(
        submission,
        {"id": 3, "title": "题目", "lang": "cpp", "max_score": 2},
        {"username": "admin", "is_admin": 1},
    )

    assert "code" not in payload["submission"]
    assert "prompt_text" not in payload["submission"]
    assert len(payload["test_points"][0]["stderr"]) == 600
    assert payload["problem"]["lang"] == "cpp"
    assert "content" not in payload["problem"]
    assert payload["status_stream_url"].endswith("?view=panel")
    assert payload["rejudge_url"].startswith("/rejudge.rejudge_submission/")


def test_panel_endpoint_uses_minimal_submission_loader(monkeypatch):
    app = Flask(__name__)
    monkeypatch.setattr(
        submission_api,
        "current_user",
        lambda: {"username": "alice", "is_admin": 0},
    )
    monkeypatch.setattr(
        submission_api,
        "get_submission_panel_by_id",
        lambda submission_id: {
            "id": submission_id,
            "username": "alice",
            "problem_id": 3,
            "problem_title": "题目",
            "problem_type": 1,
            "status": "Accepted",
            "score": 2,
            "created_at": None,
            "test_points": [],
        },
    )
    monkeypatch.setattr(
        submission_api,
        "get_submission_by_id",
        lambda _submission_id: (_ for _ in ()).throw(
            AssertionError("面板请求不应加载完整提交")
        ),
    )
    monkeypatch.setattr(
        submission_api,
        "get_problem",
        lambda problem_id: {
            "id": problem_id,
            "title": "题目",
            "lang": "python",
            "max_score": 2,
        },
    )
    monkeypatch.setattr(
        submission_api,
        "url_for",
        lambda endpoint, **values: f"/{endpoint}/{values['submission_id']}",
    )

    with app.test_request_context("/api/submissions/9?view=panel"):
        response = submission_api.submission_detail(9)

    payload = response.get_json()
    assert payload["success"] is True
    assert "code" not in payload["submission"]
    assert "prompt_text" not in payload["submission"]


def test_panel_status_stream_omits_written_content(monkeypatch):
    app = Flask(__name__)
    monkeypatch.setattr(
        submission_routes,
        "current_user",
        lambda: {"username": "alice", "is_admin": 0},
    )
    monkeypatch.setattr(
        submission_routes,
        "_get_authorized_submission_snapshot",
        lambda submission_id, user: {
            "id": submission_id,
            "username": user["username"],
            "problem_type": 2,
            "status": "Accepted",
            "score": 1,
            "prompt_generation_error": "不应出现在面板流中",
            "test_points": [{
                "test_index": 1,
                "status": "Accepted",
                "stderr": "x" * 900,
            }],
            "last_updated": "2026-07-23 12:00:00",
        },
    )

    with app.test_request_context("/submission_status_stream/9?view=panel"):
        response = submission_routes.submission_status_stream(9)
        body = b"".join(response.iter_encoded()).decode("utf-8")

    assert "written_latex" not in body
    assert "written_comment" not in body
    assert "prompt_generation_error" not in body
    assert "不应出现在面板流中" not in body
    assert "x" * 600 in body
    assert "x" * 601 not in body


def test_admin_can_rejudge_one_submission(monkeypatch):
    app = Flask(__name__)
    queued = []
    monkeypatch.setattr(
        rejudge_routes,
        "current_user",
        lambda: {"username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(rejudge_routes, "is_admin", lambda user: True)
    monkeypatch.setattr(rejudge_routes, "_rejudge_task", object())
    monkeypatch.setattr(rejudge_routes, "_rds", object())
    monkeypatch.setattr(
        rejudge_routes,
        "get_submission_by_id",
        lambda submission_id: {
            "id": submission_id,
            "problem_type": 1,
            "status": "Running",
        },
    )
    monkeypatch.setattr(
        rejudge_routes,
        "_enqueue_rejudge",
        lambda submissions, key, clear_running_lock=False: queued.append(
            (submissions, key, clear_running_lock)
        ),
    )

    with app.test_request_context("/admin/rejudge_submission/7", method="POST"):
        response = rejudge_routes.rejudge_submission(7)

    assert response.get_json()["success"] is True
    assert queued == [(
        [{"id": 7, "problem_type": 1, "status": "Running"}],
        "rejudge:submission:7",
        True,
    )]
