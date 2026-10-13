"""公开评分权限覆盖实际 API、旧别名和未经脱敏的内部快照。"""

import json

import pytest
from flask import Flask

from backend.oj_modules.api import submission_api
from backend.oj_modules.routes import ai_routes, submission_routes
from backend.oj_modules.submissions.visibility import (
    grading_results_visible,
    project_submission_grading,
)


@pytest.fixture
def grading_api(monkeypatch):
    state = {
        "user": {"username": "alice", "is_admin": 0},
        "problem": {
            "id": 3, "type": 2, "title": "书面题", "lang": "latex",
            "max_score": 5, "content": "题目内容",
            "written_grading_mode": 1, "written_score_public": 0,
        },
        "submission": {
            "id": 9, "username": "alice", "problem_id": 3,
            "problem_type": 2, "problem_title": "书面题",
            "status": "Accepted", "score": 5, "code": "秘密批改评语",
            "created_at": "2026-10-13 12:00:00", "test_points": ["answer.pdf"],
            "test_points_count": 1,
        },
        "vote": {
            "id": 7, "status": "consensus", "consensus_score": 5,
            "votes": [{"vote_index": 1, "score": 5, "comment": "秘密评委评语"}],
        },
    }
    for module in (submission_api, submission_routes, ai_routes):
        monkeypatch.setattr(module, "current_user", lambda: state["user"])
        monkeypatch.setattr(module, "get_submission_by_id", lambda _sid: dict(state["submission"]))
    for module in (submission_api, submission_routes):
        monkeypatch.setattr(module, "get_problem", lambda _pid: dict(state["problem"]))
        monkeypatch.setattr(module, "get_latest_written_vote_attempt", lambda _sid: state["vote"])
        monkeypatch.setattr(module, "_load_written_submission_latex_and_error", lambda _row: ("我的原稿转写", ""))
    monkeypatch.setattr(submission_api, "get_submission_panel_by_id", lambda _sid: dict(state["submission"]))
    monkeypatch.setattr(submission_api, "url_for", lambda *_args, **_kwargs: "/rejudge")
    monkeypatch.setattr(submission_routes, "get_submission_status_snapshot", lambda _sid, **_kwargs: dict(state["submission"]))
    monkeypatch.setattr(submission_routes, "get_latest_submission_code_by_user_and_problem", lambda _user, _pid: dict(state["submission"]))
    monkeypatch.setattr(submission_routes, "try_acquire_sse_slot", lambda: object())
    monkeypatch.setattr(submission_routes, "guard_sse_stream", lambda stream, _lease: stream)
    monkeypatch.setattr(ai_routes, "_load_accessible_problem", lambda _user, _pid: (dict(state["problem"]), 3, None))

    def list_rows():
        return [dict(state["submission"],
                     current_problem_type=state["problem"]["type"],
                     written_grading_mode=state["problem"]["written_grading_mode"],
                     written_score_public=state["problem"]["written_score_public"])]

    def filtered_submissions(**kwargs):
        assert kwargs["respect_grading_visibility"] is (state["user"]["is_admin"] != 1)
        return list_rows(), 1, 1

    monkeypatch.setattr(submission_api, "get_filtered_submissions_paginated", filtered_submissions)
    monkeypatch.setattr(submission_api, "get_submission_summaries_by_user_and_problem_paginated", lambda *_args, **_kwargs: (list_rows(), 1))
    monkeypatch.setattr(submission_api, "get_submission_problem_options", lambda **_kwargs: [])
    app = Flask(__name__)
    app.json.ensure_ascii = False
    app.register_blueprint(submission_api.submission_api_bp)
    app.register_blueprint(submission_routes.submission_bp)
    app.register_blueprint(ai_routes.ai_bp)
    return app.test_client(), state


@pytest.mark.parametrize("user,problem,expected", [
    ({"is_admin": 1}, {"type": 2, "written_score_public": 0}, True),
    ({"is_admin": 0}, {"type": 2, "written_score_public": 0}, False),
    ({"is_admin": 0}, {"type": 2, "written_grading_mode": 2, "written_score_public": 0}, False),
    ({"is_admin": 0}, {"type": 2, "written_grading_mode": 3, "written_score_public": 0}, False),
    ({"is_admin": 0}, {"type": 2, "written_grading_mode": 4, "written_score_public": 0}, True),
    ({"is_admin": 0}, {"type": 1, "written_score_public": 0}, True),
    ({"is_admin": 0}, {"type": 2, "written_score_public": 1}, True),
    ({"is_admin": 0}, {"type": 2}, True),
])
def test_grading_policy_scope(user, problem, expected):
    assert grading_results_visible(user, problem) is expected


@pytest.mark.parametrize("status", ["Pending", "Waiting", "Running", "Generating"])
def test_projection_keeps_progress_and_original_submission(status):
    submission = {"status": status, "score": 5, "code": "旧评语", "test_points": ["answer.pdf", {"status": "Accepted"}]}
    projected = project_submission_grading(submission, {"type": 2, "written_score_public": 0}, {"is_admin": 0})
    assert projected["status"] == status
    assert projected["score"] is None
    assert projected["code"] == ""
    assert projected["test_points"] == ["answer.pdf"]
    assert submission["score"] == 5
    assert submission["code"] == "旧评语"
    assert len(submission["test_points"]) == 2


@pytest.mark.parametrize("path,row_key", [
    ("/api/submissions", "submissions"),
    ("/api/problems/3/submissions", "submissions"),
    ("/api/submissions/9", "submission"),
    ("/api/submissions/9?view=panel", "submission"),
    ("/api/submissions/9/status", None),
    ("/submission_status/9", None),
    ("/api/problems/3/last-submission-code", None),
    ("/api/get_last_submission_code/3", None),
])
def test_student_endpoints_hide_current_grading_results(grading_api, path, row_key):
    client, state = grading_api
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    payload = response.get_json()
    row = payload[row_key] if row_key else payload
    if isinstance(row, list):
        row = row[0]
    assert row["result_visible"] is False
    assert row["score"] is None
    assert row.get("code", "") == ""
    assert row.get("status", "评分未公开") == "评分未公开"
    assert row.get("is_ac", False) is False
    assert "秘密" not in response.get_data(as_text=True)
    if path == "/api/submissions/9":
        assert payload["written_submission"]["vote"] is None
        assert payload["submission_latex_text"] == "我的原稿转写"
        assert payload["test_points"] == ["answer.pdf"]
    if "status" in path:
        assert payload["is_judging"] is False
        assert payload["written_vote"] is None
    assert state["submission"]["score"] == 5
    assert state["submission"]["code"] == "秘密批改评语"


@pytest.mark.parametrize("path,row_key", [
    ("/api/submissions", "submissions"),
    ("/api/problems/3/submissions", "submissions"),
    ("/api/submissions/9", "submission"),
    ("/api/submissions/9?view=panel", "submission"),
    ("/api/submissions/9/status", None),
    ("/api/problems/3/last-submission-code", None),
])
@pytest.mark.parametrize("is_admin,public", [(1, 0), (0, 1)])
def test_administrator_or_public_results_remain_visible(grading_api, path, row_key, is_admin, public):
    client, state = grading_api
    state["user"]["is_admin"] = is_admin
    state["problem"]["written_score_public"] = public
    payload = client.get(path).get_json()
    row = payload[row_key] if row_key else payload
    if isinstance(row, list):
        row = row[0]
    assert row["result_visible"] is True
    assert row["score"] == 5
    assert row.get("status", "Accepted") == "Accepted"
    if path == "/api/submissions/9":
        assert row["code"] == "秘密批改评语"
        assert payload["written_submission"]["vote"]["votes"][0]["comment"] == "秘密评委评语"
    if path.endswith("/status"):
        assert payload["written_comment"] == "秘密批改评语"


def test_old_snapshot_uses_current_problem_switch(grading_api):
    client, state = grading_api
    state["submission"]["written_score_public"] = 1  # 模拟旧缓存带有过期配置。
    assert client.get("/api/submissions/9/status").get_json()["score"] is None
    state["problem"]["written_score_public"] = 1
    assert client.get("/api/submissions/9/status").get_json()["score"] == 5
    state["problem"]["written_score_public"] = 0
    assert client.get("/api/submissions/9/status").get_json()["score"] is None


def test_missing_problem_does_not_open_historical_written_grading(grading_api, monkeypatch):
    client, state = grading_api
    state["problem"]["written_score_public"] = 1
    monkeypatch.setattr(submission_routes, "get_problem", lambda _pid: None)
    monkeypatch.setattr(submission_api, "get_problem", lambda _pid: None)
    for path in ("/api/submissions/9", "/api/submissions/9?view=panel", "/api/submissions/9/status"):
        response = client.get(path)
        assert response.status_code == 200
        assert "秘密" not in response.get_data(as_text=True)
    state["user"]["is_admin"] = 1
    assert client.get("/api/submissions/9/status").get_json()["score"] == 5


@pytest.mark.parametrize("legacy_type", [None, 0])
@pytest.mark.parametrize("path", [
    "/api/submissions/9", "/api/submissions/9?view=panel",
    "/api/submissions/9/status", "/api/submissions/9/events",
    "/api/submissions/9/events?view=panel",
    "/api/problems/3/submissions", "/api/problems/3/last-submission-code",
])
def test_nullable_historical_submission_type_uses_current_problem(grading_api, monkeypatch, legacy_type, path):
    client, state = grading_api
    state["submission"]["problem_type"] = legacy_type
    # 题目提交列表真实查询仅带历史字段，不能依赖 general list 的联查字段。
    monkeypatch.setattr(
        submission_api, "get_submission_summaries_by_user_and_problem_paginated",
        lambda *_args, **_kwargs: ([dict(state["submission"])], 1),
    )
    response = client.get(path)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "秘密" not in body
    if "/events" in path:
        payloads = [payload for _event, payload in _sse_events(body)]
    else:
        payload = response.get_json()
        rows = payload.get("submissions")
        payloads = rows or [payload.get("submission", payload)]
    for payload in payloads:
        assert payload["result_visible"] is False
        assert payload["score"] is None


def test_hidden_detail_does_not_load_legacy_ai_code_marks(grading_api, monkeypatch):
    client, state = grading_api
    state["submission"]["problem_type"] = 1
    def forbidden_cache(_submission):
        raise AssertionError("隐藏的书面结果不得加载旧代码标注缓存")
    monkeypatch.setattr(submission_api, "get_cached_ai_code_marks_for_submission", forbidden_cache)
    response = client.get("/api/submissions/9")
    assert response.status_code == 200
    assert response.get_json()["cached_ai_code_marks"] is None
    assert "秘密" not in response.get_data(as_text=True)


@pytest.mark.parametrize("path", ["/api/submissions/9", "/api/submissions/9?view=panel", "/api/submissions/9/status"])
def test_hidden_results_waiting_for_manual_review_are_not_still_judging(grading_api, path):
    client, state = grading_api
    state["submission"]["status"] = "Pending"
    state["vote"]["status"] = "needs_manual_review"
    payload = client.get(path).get_json()
    submission = payload.get("submission", payload)
    assert submission["is_judging"] is False
    assert submission["score"] is None
    assert submission["result_visible"] is False


@pytest.mark.parametrize("path", ["/api/submissions/9", "/api/submissions/9/events", "/submission_status_stream/9"])
def test_historical_latex_error_cannot_disclose_raw_ai_grading(grading_api, monkeypatch, path):
    client, state = grading_api
    raw_grading_error = 'AI 解析失败：{"score":5,"comment":"秘密模型评语"}'
    for module in (submission_api, submission_routes):
        monkeypatch.setattr(module, "_load_written_submission_latex_and_error", lambda _row: ("我的原稿转写", raw_grading_error))
    response = client.get(path)
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "秘密" not in body
    if "/events" in path or "stream" in path:
        payload = _sse_events(body)[0][1]
        assert payload["written_latex_error"] == ""
        assert payload["written_latex_text"] == "我的原稿转写"
    else:
        assert response.get_json()["submission_latex_error"] == ""
        assert response.get_json()["submission_latex_text"] == "我的原稿转写"
    state["user"]["is_admin"] = 1
    assert "秘密" in client.get(path).get_data(as_text=True)


@pytest.mark.parametrize("path", ["/api/submissions/9", "/api/submissions/9?view=panel", "/api/submissions/9/status", "/api/submissions/9/events"])
def test_submission_ownership_is_checked_before_visibility(grading_api, monkeypatch, path):
    client, state = grading_api
    state["submission"]["username"] = "bob"
    def inaccessible_policy(_pid):
        raise AssertionError("未授权的提交不应读取公开配置")
    monkeypatch.setattr(submission_api, "get_problem", inaccessible_policy)
    monkeypatch.setattr(submission_routes, "get_problem", inaccessible_policy)
    assert client.get(path).status_code == 403


def _sse_events(body):
    events = []
    for block in body.split("\n\n"):
        lines = block.splitlines()
        event = next((line.removeprefix("event: ") for line in lines if line.startswith("event: ")), None)
        data = next((line.removeprefix("data: ") for line in lines if line.startswith("data: ")), None)
        if event and data:
            events.append((event, json.loads(data)))
    return events


@pytest.mark.parametrize("path", [
    "/api/submissions/9/events", "/api/submissions/9/events?view=panel",
    "/submission_status_stream/9", "/submission_status_stream/9?view=panel",
])
def test_completed_hidden_stream_stops_without_disclosing_results(grading_api, path):
    client, state = grading_api
    response = client.get(path)
    events = _sse_events(response.get_data(as_text=True))
    assert [event for event, _payload in events] == ["status", "done"]
    assert response.headers["Cache-Control"] == "no-store"
    for _event, payload in events:
        assert payload["is_judging"] is False
        assert payload["result_visible"] is False
        assert payload["score"] is None
        assert payload["written_vote"] is None
        assert "秘密" not in json.dumps(payload, ensure_ascii=False)
    assert state["submission"]["status"] == "Accepted"


def test_done_event_rechecks_visibility_after_previous_status_event(grading_api, monkeypatch):
    client, state = grading_api
    reads = 0
    def current_problem(_pid):
        nonlocal reads
        reads += 1
        return dict(state["problem"], written_score_public=1 if reads == 1 else 0)
    monkeypatch.setattr(submission_routes, "get_problem", current_problem)
    events = _sse_events(client.get("/api/submissions/9/events").get_data(as_text=True))
    assert [event for event, _payload in events] == ["status", "done"]
    assert events[0][1]["score"] == 5
    assert events[1][1]["score"] is None
    assert events[1][1]["written_vote"] is None
    assert events[1][1]["written_comment"] == ""


@pytest.mark.parametrize("panel", [False, True])
def test_stream_reloads_current_visibility_for_every_frame(grading_api, monkeypatch, panel):
    client, state = grading_api
    state["submission"]["status"] = "Running"
    class Pubsub:
        reads = 0
        closed = False
        def get_message(self, **_kwargs):
            self.reads += 1
            state["problem"]["written_score_public"] = 1 if self.reads == 1 else 0
            snapshot = dict(state["submission"], status="Running" if self.reads == 1 else "Accepted")
            return {"type": "message", "data": json.dumps(snapshot)}
        def close(self):
            self.closed = True
    pubsub = Pubsub()
    monkeypatch.setattr(submission_routes, "subscribe_submission_status_events", lambda _sid: pubsub)
    path = "/api/submissions/9/events" + ("?view=panel" if panel else "")
    events = _sse_events(client.get(path).get_data(as_text=True))
    statuses = [payload for event, payload in events if event == "status"]
    assert [payload["result_visible"] for payload in statuses] == [False, True, False]
    assert [payload["score"] for payload in statuses] == [None, 5, None]
    assert statuses[-1]["status"] == "评分未公开"
    assert events[-1][0] == "done"
    assert events[-1][1]["is_judging"] is False
    assert pubsub.closed is True
    for payload in (statuses[0], statuses[-1], events[-1][1]):
        assert "秘密" not in json.dumps(payload, ensure_ascii=False)


@pytest.mark.parametrize("path", ["/api/ai/code-marks", "/ask_ai_code_marks", "/ask_ai_code_marks_stream"])
@pytest.mark.parametrize("mode", [1, 4])
def test_written_comments_cannot_be_read_via_ai_code_marks_cache(grading_api, monkeypatch, path, mode):
    client, state = grading_api
    state["problem"]["written_grading_mode"] = mode
    def forbidden_cache(_submission):
        raise AssertionError("书面题不得读取代码标注缓存")
    monkeypatch.setattr(ai_routes, "get_cached_ai_code_marks_for_submission", forbidden_cache)
    response = client.post(path, json={"submission_id": 9})
    assert response.status_code == 400
    assert response.get_json()["message"] == "书面题不支持代码标注"
    assert "秘密" not in response.get_data(as_text=True)
