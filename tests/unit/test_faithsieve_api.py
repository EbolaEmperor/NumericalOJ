"""管理列表/详情只读查询、权限、公开字段和工件入口的边界。"""

from datetime import datetime
from html.parser import HTMLParser
import json

from flask import Flask
import pytest

from backend.oj_modules.api import faithsieve_api as api
from backend.oj_modules.submissions import faithsieve_views as views
from tests.unit.test_faithsieve_modes import skill_run
from tests.unit.test_faithsieve_workflow import tree_payload


ATTEMPT = "a" * 32


def assert_safe_html(content):
    class Probe(HTMLParser):
        def handle_starttag(self, tag, attrs):
            assert tag.lower() not in {"script", "iframe", "object", "embed"}
            for name, value in attrs:
                assert not name.lower().startswith("on")
                if name.lower() in {"href", "src"}:
                    assert not str(value or "").strip().lower().startswith(("javascript:", "data:"))
    Probe(convert_charrefs=True).feed(content)


def sample_row(**changes):
    return {
        "id": 9, "attempt_id": ATTEMPT, "submission_id": 42, "problem_id": 5,
        "requested_by": "admin", "harness": "pi", "endpoint_id": 7,
        "execution_mode": "workflow",
        "session_id": f"faithsieve-{ATTEMPT}", "task_id": f"task-{ATTEMPT}",
        "endpoint_model": "frozen-model", "endpoint_revision": 2, "model_source": "judge",
        "status": "completed", "message": "评测完成，得分 5/5",
        "username": "学生甲", "user_id": 12, "problem_title": "积分 「NA-1」",
        "created_at": datetime(2026, 10, 2, 12, 0), "started_at": None, "finished_at": None,
        "result_json": '{"verdict":"correct","score":5,"comment":"证明正确"}',
        "submission_created_at": datetime(2026, 10, 2, 11, 0),
        "existing_submission_id": 42, "existing_problem_id": 5,
        "submission_status": "Accepted", "submission_score": 5,
        "submission_comment": "# 已批改\n<script>alert(1)</script>\n[x](javascript:alert(1))",
        "problem_content": "# 题面\n<img src=x onerror=alert(1)>\n$x^2$",
        "problem_type": 2, "problem_max_score": 5,
        "api_key": "MUST-NOT-EXPOSE", "prompt_text": "MUST-NOT-EXPOSE",
        "request": "MUST-NOT-EXPOSE", **changes,
    }


class Cursor:
    def __init__(self, rows=None, counts=None):
        self.rows = [sample_row()] if rows is None else rows
        self.counts = {"total": 41, "completed": 41} if counts is None else counts
        self.calls = []
        self.result = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self.calls.append((normalized, params))
        self.result = self.counts if normalized.startswith("SELECT COUNT(*)") else self.rows

    def fetchone(self):
        return self.result if isinstance(self.result, dict) else next(iter(self.result), None)

    def fetchall(self):
        return self.result


class Connection:
    def __init__(self, **kwargs):
        self.query = Cursor(**kwargs)
        self.closed = False

    def cursor(self):
        return self.query

    def close(self):
        self.closed = True

    def commit(self):
        pytest.fail("管理只读查询不得提交写事务")


@pytest.fixture
def database(monkeypatch):
    connection = Connection()
    monkeypatch.setattr(views, "get_db_connection", lambda: connection)
    return connection


@pytest.fixture
def client(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(api.faithsieve_api_bp)
    monkeypatch.setattr(api, "current_user", lambda: {"id": 1, "username": "admin", "is_admin": True})
    monkeypatch.setattr(api, "is_admin", lambda user: bool(user.get("is_admin")))
    monkeypatch.setattr(api, "can_retry_failed_run", lambda _attempt_id: False)
    monkeypatch.setattr(api, "load_run_costs", lambda _runs: {ATTEMPT: api.unknown_cost()})
    return app.test_client()


@pytest.mark.parametrize("user,expected", [(None, 401), ({"username": "student", "is_admin": False}, 403)])
@pytest.mark.parametrize("suffix", ["", f"/{ATTEMPT}", f"/{ATTEMPT}/artifacts?path=problem.md"])
def test_authentication_precedes_all_database_and_artifact_access(client, monkeypatch, user, expected, suffix):
    monkeypatch.setattr(api, "current_user", lambda: user)
    def forbidden(*_args, **_kwargs):
        pytest.fail("鉴权失败前不得读取数据库或工件")
    for function in ("list_faithsieve_runs", "get_faithsieve_detail", "get_faithsieve_run", "workflow_snapshot", "read_artifact", "render_rich_markdown", "load_run_costs"):
        monkeypatch.setattr(api, function, forbidden)
    assert client.get("/api/admin/faithsieve" + suffix).status_code == expected


def test_filtered_query_escapes_literal_username_and_clamps_pagination(database):
    data = views.list_faithsieve_runs(page=999, status="completed", username="a%_\\'", problem_id="5", submission_id="42")
    assert data["page"] == data["total_pages"] == 3
    assert data["per_page"] == 20
    assert data["total"] == 41
    assert data["summary"]["completed"] == 41
    assert data["summary"]["queued"] == 0
    for query, params in database.query.calls:
        assert "a%_" not in query
        assert "r.status=%s" in query
        assert "s.username LIKE %s ESCAPE" in query
        assert "r.problem_id=%s" in query and "r.submission_id=%s" in query
        assert params[:4] == ("completed", "%a\\%\\_\\\\'%", 5, 42)
    query, params = database.query.calls[-1]
    assert "ORDER BY r.created_at DESC, r.id DESC LIMIT %s OFFSET %s" in query
    assert params[-2:] == (20, 40)
    assert "MIN(a2.id)" in query and "a2.judge_kind='faithsieve'" in query
    assert "a2.submission_id=r.submission_id" in query and "a2.endpoint_source='global'" in query
    assert "api_key" not in query and "user_message" not in query
    assert database.closed


@pytest.mark.parametrize("changes", [
    {"status": "bogus"}, {"problem_id": "0"}, {"submission_id": "-1"},
    {"problem_id": "5 OR 1=1"}, {"submission_id": "2.1"}, {"username": "x" * 51},
    {"problem_id": True}, {"submission_id": "9" * 5000},
])
def test_invalid_filters_do_not_open_database(monkeypatch, changes):
    monkeypatch.setattr(views, "get_db_connection", lambda: pytest.fail("无效筛选不得查询数据库"))
    with pytest.raises(ValueError):
        views.list_faithsieve_runs(**changes)


def test_list_payload_is_whitelisted_and_datetime_is_serialized(client, database):
    response = client.get("/api/admin/faithsieve?page=2&username=%E5%AD%A6%E7%94%9F")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True and data["page"] == 2
    assert response.headers["Cache-Control"] == "private, no-store"
    assert data["page_numbers"] == [1, 2, 3]
    run = data["runs"][0]
    assert run["student_name"] == run["username"] == "学生甲"
    assert run["execution_mode"] == "workflow"
    assert run["problem_title"] == "积分"
    assert run["created_at"] == "2026-10-02 12:00:00"
    assert run["runtime"] == {"harness": "pi", "endpoint_id": 7, "model": "frozen-model", "endpoint_revision": 2, "model_source": "judge"}
    assert run["result"] == {"verdict": "correct", "score": 5, "comment": "证明正确"}
    assert "MUST-NOT-EXPOSE" not in response.get_data(as_text=True)


@pytest.mark.parametrize("query", ["status=bogus", "problem_id=0", "submission_id=abc"])
def test_api_returns_400_for_invalid_filters(client, database, query):
    assert client.get("/api/admin/faithsieve?" + query).status_code == 400
    assert database.query.calls == []


def test_empty_list_keeps_first_page_and_zero_summary(monkeypatch):
    connection = Connection(rows=[], counts={})
    monkeypatch.setattr(views, "get_db_connection", lambda: connection)
    data = views.list_faithsieve_runs(page=99)
    assert data["runs"] == []
    assert data["page"] == data["total_pages"] == 1
    assert data["summary"] == {"total": 0, **{status: 0 for status in views.STATUSES}}


@pytest.mark.parametrize("suffix", ["", "/artifacts?path=problem.md"])
def test_missing_attempt_returns_404_before_workflow_read(client, monkeypatch, suffix):
    monkeypatch.setattr(api, "get_faithsieve_detail", lambda *_args: None)
    monkeypatch.setattr(api, "get_faithsieve_run", lambda *_args: None)
    monkeypatch.setattr(api, "workflow_snapshot", lambda *_args: pytest.fail("不存在 run 不得读工件"))
    monkeypatch.setattr(api, "read_artifact", lambda *_args, **_kwargs: pytest.fail("不存在 run 不得读工件"))
    assert client.get(f"/api/admin/faithsieve/{ATTEMPT}{suffix}").status_code == 404


def test_invalid_attempt_id_returns_404_without_database(client, monkeypatch):
    monkeypatch.setattr(api, "get_faithsieve_detail", lambda *_args: pytest.fail("非法 ID 不得读数据库"))
    assert client.get("/api/admin/faithsieve/not-an-attempt").status_code == 404


def test_detail_returns_safe_problem_submission_and_actual_workflow(client, database, monkeypatch):
    workflow = {"stages": [{"key": "role-000001-attempt-1", "role": "statement-formalizer", "state": "completed", "report": "实际编译通过"}], "source": {}, "artifacts": [], "warnings": []}
    monkeypatch.setattr(api, "workflow_snapshot", lambda run: workflow if run["attempt_id"] == ATTEMPT else pytest.fail("错误 run"))
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["workflow"] == {
        **workflow,
        "stages": [{**workflow["stages"][0], "report_html": "<p>实际编译通过</p>"}],
    }
    assert "report_html" not in workflow["stages"][0]
    assert data["submission"]["pdf_url"] == "/api/submissions/42/file"
    assert data["result"] == data["run"]["result"]
    assert data["result"]["comment_html"] == "<p>证明正确</p>"
    for field, value in (("comment_html", data["submission"]), ("content_html", data["problem"])):
        assert_safe_html(value[field])
    assert "$x^2$" in data["problem"]["content_html"]
    assert "MUST-NOT-EXPOSE" not in response.get_data(as_text=True)
    assert database.query.calls[0][1] == (ATTEMPT,)
    assert database.closed


@pytest.mark.parametrize("cleaner_failure", [False, True])
def test_detail_report_and_result_render_rich_math_safely_without_changing_source(client, database, monkeypatch, cleaner_failure):
    from backend.oj_modules.shared import markdown
    marker = "详情清洗异常" if cleaner_failure else "详情正常清洗"
    formula = r"\[e^{-2\pi i f_\ell t_n}\longrightarrow 1\]"
    report = (
        f"## {marker}\n\n**验证结论**\n\n{formula}\n\n"
        "| 条件 | 结论 |\n| --- | --- |\n| 间距 | 成立 |\n\n"
        '<script>alert(1)</script><img src=x onerror=alert(2)>[链接](javascript:alert(3))'
    )
    comment = f"### 最终结果：{marker}\n\n{formula}\n\n<iframe src=x></iframe>"
    database.query.rows[0]["result_json"] = json.dumps({"verdict": "incorrect", "score": 0, "comment": comment})
    check = {"label": "运行检查", "report": "exit 0"}
    source = {"report": "原稿核对记录"}
    workflow = {"stages": [{"key": "proof", "report": report, "checks": [check]}], "source": source}
    monkeypatch.setattr(api, "workflow_snapshot", lambda *_args: workflow)
    if cleaner_failure:
        def failed_cleaner(*_args, **_kwargs):
            raise RuntimeError("安全清洗库暂不可用")
        monkeypatch.setattr(markdown.bleach, "clean", failed_cleaner)
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}")
    assert response.status_code == 200
    data = response.get_json()
    stage = data["workflow"]["stages"][0]
    assert stage["report"] == report
    assert stage["checks"] == [check]
    assert data["workflow"]["source"] == source
    assert data["result"] == data["run"]["result"]
    assert data["result"]["comment"] == comment
    for rendered in (stage["report_html"], data["result"]["comment_html"]):
        assert_safe_html(rendered)
        assert formula in rendered
    if cleaner_failure:
        assert "&lt;" in stage["report_html"] or "&amp;lt;" in stage["report_html"]
    else:
        assert "<h2>" in stage["report_html"]
        assert "<strong>验证结论</strong>" in stage["report_html"]
        assert "<table>" in stage["report_html"]
        assert "<h3>" in data["result"]["comment_html"]
    assert "report_html" not in workflow["stages"][0]
    assert response.headers["Cache-Control"] == "private, no-store"


@pytest.mark.parametrize("report", [None, "", " \n\t"])
def test_detail_preserves_empty_reports_and_invalid_result(client, database, monkeypatch, report):
    workflow = {"stages": [{"key": "pending", "report": report}], "source": {}}
    monkeypatch.setattr(api, "workflow_snapshot", lambda *_args: workflow)
    database.query.rows[0]["result_json"] = json.dumps({"verdict": "correct", "score": 5, "comment": " \n\t"})
    data = client.get(f"/api/admin/faithsieve/{ATTEMPT}").get_json()
    assert data["workflow"] == workflow
    assert data["result"] is data["run"]["result"] is None


@pytest.mark.parametrize("error", [ValueError("raw prompt MUST-NOT-EXPOSE"), PermissionError("/private/workspace")])
def test_unreadable_workflow_returns_complete_empty_dag_schema(client, database, monkeypatch, error):
    def reject(*_args):
        raise error
    monkeypatch.setattr(api, "workflow_snapshot", reject)
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}")
    assert response.status_code == 200
    assert response.get_json()["workflow"] == {
        "stages": [], "source": {}, "artifacts": [], "edges": [],
        "summary": {"stage_count": 0, "shown_stage_count": 0, "truncated": False},
        "warnings": ["评测工件暂不可读取"],
    }
    assert "MUST-NOT-EXPOSE" not in response.get_data(as_text=True)
    assert "/private/workspace" not in response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "private, no-store"


def test_damaged_result_does_not_expose_unexpected_json_fields():
    malicious = json.dumps({"verdict": "correct", "score": 5, "comment": "ok", "api_key": "MUST-NOT-EXPOSE"})
    assert views.public_run(sample_row(result_json=malicious))["result"] is None
    assert views.public_run(sample_row(result_json="broken"))["result"] is None


@pytest.mark.parametrize("stored,expected", [
    ({}, "skill"), ({"execution_mode": None}, "skill"),
    ({"execution_mode": "skill"}, "skill"), ({"execution_mode": "workflow"}, "workflow"),
])
def test_public_run_always_exposes_execution_mode_and_preserves_historical_skill(stored, expected):
    row = sample_row()
    row.pop("execution_mode")
    row.update(stored)
    assert views.public_run(row)["execution_mode"] == expected


def test_legacy_skill_detail_and_artifact_use_actual_single_judge(client, database, skill_run, monkeypatch):
    from backend.oj_modules.faithsieve import views as workflow_views
    run, session, workspace = skill_run
    row = sample_row(
        attempt_id=run["attempt_id"],
        execution_mode=None, session_id=run["session_id"], submission_id=12,
        existing_submission_id=12, problem_id=7, existing_problem_id=7,
        endpoint_id=3, username="student", status="running",
    )
    database.query.rows = [row]
    monkeypatch.setattr(workflow_views, "workflow_snapshot", lambda *_args: pytest.fail("skill 不能伪造 workflow DAG"))
    (workspace / "faithsieve-work").mkdir()
    (workspace / "faithsieve-work/steps.md").write_text("# 原稿拆分\n\n$x^2$", encoding="utf-8")
    response = client.get(f"/api/admin/faithsieve/{run['attempt_id']}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["run"]["execution_mode"] == "skill"
    assert data["workflow"]["edges"] == []
    stage = data["workflow"]["stages"][0]
    assert stage["session_id"] == session["session_id"] and stage["judge_status"] == "Running"
    artifact = client.get(f"/api/admin/faithsieve/{run['attempt_id']}/artifacts", query_string={"path": "faithsieve-work/steps.md", "stage_key": "skill-judge"})
    assert artifact.status_code == 200
    assert artifact.get_json()["artifact"]["content"] == "# 原稿拆分\n\n$x^2$"
    assert "<h1>" in artifact.get_json()["artifact"]["content_html"]
    assert "PRIVATE-" not in response.get_data(as_text=True) + artifact.get_data(as_text=True)
    query = database.query.calls[0][0]
    assert "a2.requested_by=s.username" in query and "a2.session_id=r.session_id" in query


def test_artifact_route_passes_history_stage_without_exposing_transport(client, database, monkeypatch):
    calls = []
    artifact = {"path": "statement.lean", "name": "statement.lean", "content": "def P : Prop := True", "language": "lean", "mime_type": "text/plain", "size": 20}
    def read(run, path, *, stage_key=None):
        calls.append((run["attempt_id"], path, stage_key))
        return artifact
    monkeypatch.setattr(api, "read_artifact", read)
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}/artifacts?path=statement.lean&stage_key=role-000001-attempt-1")
    assert response.status_code == 200
    assert response.get_json()["artifact"] == artifact
    assert calls == [(ATTEMPT, "statement.lean", "role-000001-attempt-1")]


@pytest.mark.parametrize("error", [ValueError("unsafe /etc/secret"), FileNotFoundError("/private/workspace"), PermissionError("/private/workspace")])
def test_artifact_denial_is_404_and_hides_private_paths(client, database, monkeypatch, error):
    def reject(*_args, **_kwargs):
        raise error
    monkeypatch.setattr(api, "read_artifact", reject)
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}/artifacts?path=../../etc/secret")
    assert response.status_code == 404
    assert "/etc/secret" not in response.get_data(as_text=True)
    assert "/private/workspace" not in response.get_data(as_text=True)


def test_blueprint_is_registered():
    from backend.oj_modules.api.registry import API_BLUEPRINTS
    assert api.faithsieve_api_bp in API_BLUEPRINTS


@pytest.fixture
def actual_workspace(tmp_path, monkeypatch):
    from backend.oj_modules.faithsieve import views as workflow_views
    from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
    root = tmp_path / "managed"
    workspace = root / "sessions" / f"faithsieve-{ATTEMPT}" / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setattr(workflow_views.workspace_store, "AGENT_WORKSPACE_ROOT", root)
    monkeypatch.setattr(workflow_views, "get_agent_session", lambda *_args: pytest.fail("纯 LLM 记录不得查询 Judge"))
    store = CheckpointStore(workspace)
    for number, content in ((1, "第一轮忠实拆分"), (2, "修订后的忠实拆分")):
        store.put(
            f"role-{number:06d}-attempt-1",
            {"role": "decomposer", "prompt": "SECRET-REQUEST", "files": {"private": "SECRET-INPUT"},
             "endpoint": {"api_key": "SECRET-KEY"}, "expected_result_path": "faithsieve-work/results/decomposer.json"},
            state="completed",
            response={"result": {"status": "ok", "artifact": "faithsieve-work/steps.md", "report": "忠实拆分"},
                      "artifacts": {"faithsieve-work/steps.md": content}, "control": {"secret": "SECRET-CONTROL"}},
        )
    (workspace / "faithsieve-work/steps.md").write_text("当前磁盘版", encoding="utf-8")
    return root, workspace


def test_real_detail_snapshot_is_readonly_and_hides_checkpoint_requests(client, database, actual_workspace):
    root, _workspace = actual_workspace
    before = {path: (path.stat().st_mode, path.stat().st_mtime_ns, path.stat().st_size) for path in root.rglob("*")}
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}")
    assert response.status_code == 200
    workflow = response.get_json()["workflow"]
    assert [stage["sequence"] for stage in workflow["stages"]] == [1, 2]
    assert [stage["role"] for stage in workflow["stages"]] == ["decomposer", "decomposer"]
    assert "SECRET" not in response.get_data(as_text=True)
    after = {path: (path.stat().st_mode, path.stat().st_mtime_ns, path.stat().st_size) for path in root.rglob("*")}
    assert before == after


def test_real_stage_artifact_serves_historical_original_without_request(client, database, actual_workspace):
    response = client.get(
        f"/api/admin/faithsieve/{ATTEMPT}/artifacts?path=faithsieve-work/steps.md&stage_key=role-000001-attempt-1",
    )
    assert response.status_code == 200
    artifact = response.get_json()["artifact"]
    assert artifact["content"] == "第一轮忠实拆分"
    assert artifact["stage_key"] == "role-000001-attempt-1"
    assert response.headers["Cache-Control"] == "private, no-store"
    assert "SECRET" not in response.get_data(as_text=True)


@pytest.mark.parametrize("path", [
    "../secret", "/etc/passwd", "faithsieve-work/checkpoints/role-000001-attempt-1.json",
    "faithsieve-work/judge-invocations/source-extraction.json", ".runtime/config.json",
])
def test_real_artifact_service_denies_private_paths(client, database, actual_workspace, path):
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}/artifacts", query_string={"path": path})
    assert response.status_code == 404
    assert response.headers["Cache-Control"] == "private, no-store"


def test_real_artifact_service_rejects_symlink_without_reading_external_file(client, database, actual_workspace, tmp_path):
    _root, workspace = actual_workspace
    external = tmp_path / "private.txt"
    external.write_text("SECRET-OUTSIDE", encoding="utf-8")
    (workspace / "problem.md").symlink_to(external)
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}/artifacts?path=problem.md")
    assert response.status_code == 404
    assert "SECRET" not in response.get_data(as_text=True)


def test_queued_detail_does_not_initialize_workspace(client, database, tmp_path, monkeypatch):
    from backend.oj_modules.faithsieve import views as workflow_views
    root = tmp_path / "absent-managed-root"
    monkeypatch.setattr(workflow_views.workspace_store, "AGENT_WORKSPACE_ROOT", root)
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}")
    assert response.status_code == 200
    snapshot = response.get_json()["workflow"]
    assert {name: snapshot[name] for name in ("stages", "source", "artifacts", "warnings")} == {
        "stages": [], "source": {}, "artifacts": [], "warnings": [],
    }
    assert snapshot.get("edges", []) == []
    if "summary" in snapshot:
        assert snapshot["summary"]["stage_count"] == 0
    assert not root.exists()


@pytest.mark.parametrize("cleaner_failure", [False, True])
def test_markdown_artifact_returns_safe_rich_html_and_keeps_original(client, database, monkeypatch, cleaner_failure):
    from backend.oj_modules.shared import markdown
    marker = "清洗异常" if cleaner_failure else "正常清洗"
    content = (
        f"# 原稿：{marker}\n\n$x^2$\n\n| 步骤 | 结论 |\n| --- | --- |\n| 1 | 成立 |\n\n"
        '<script>alert(1)</script><img src=x onerror=alert(1)>[x](javascript:alert(1))'
    )
    artifact = {"path": "faithsieve-work/source/submission.md", "name": "submission.md",
                "language": "markdown", "content": content, "size": len(content.encode())}
    monkeypatch.setattr(api, "read_artifact", lambda *_args, **_kwargs: artifact)
    if cleaner_failure:
        def failed_cleaner(*_args, **_kwargs):
            raise RuntimeError("安全清洗库暂不可用")
        monkeypatch.setattr(markdown.bleach, "clean", failed_cleaner)
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}/artifacts?path=faithsieve-work/source/submission.md")
    assert response.status_code == 200
    result = response.get_json()["artifact"]
    assert result["content"] == content
    assert "content_html" not in artifact
    assert_safe_html(result["content_html"])
    assert "$x^2$" in result["content_html"]
    if cleaner_failure:
        assert "&lt;" in result["content_html"] or "&amp;lt;" in result["content_html"]
    else:
        assert "<h1>" in result["content_html"] and "<table>" in result["content_html"]


def test_running_detail_refreshes_persisted_pending_to_completed(client, database, actual_workspace):
    from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
    _root, workspace = actual_workspace
    database.query.rows[0]["status"] = "running"
    store = CheckpointStore(workspace)
    key = "role-000003-attempt-1"
    request = {"role": "tree-builder", "prompt": "SECRET-REQUEST",
               "expected_result_path": "faithsieve-work/results/tree-builder.json"}
    store.put(key, request, state="pending")
    before = client.get(f"/api/admin/faithsieve/{ATTEMPT}")
    pending = before.get_json()["workflow"]["stages"][-1]
    assert pending["key"] == key and pending["state"] == "pending"
    store.put(
        key, request, state="completed",
        response={"result": {"status": "ok", "artifact": "faithsieve-work/tree.json", "report": "已建立实际证明树"},
                  "artifacts": {"faithsieve-work/tree.json": json.dumps(tree_payload())}, "control": {}},
    )
    after = client.get(f"/api/admin/faithsieve/{ATTEMPT}")
    completed = after.get_json()["workflow"]["stages"][-1]
    assert completed["key"] == key and completed["state"] == "completed"
    assert pending["sequence"] == completed["sequence"] == 3
    assert completed["report"] == "已建立实际证明树"
    assert after.get_json()["workflow"]["proof_tree"] == {"path": "faithsieve-work/tree.json", "stage_key": key, "format": "json"}
    artifact_response = client.get(f"/api/admin/faithsieve/{ATTEMPT}/artifacts?path=faithsieve-work/tree.json&stage_key={key}")
    artifact = artifact_response.get_json()["artifact"]
    assert artifact["proof_tree"] == tree_payload() and artifact["proof_tree_format"] == "json"
    assert artifact["language"] == "json" and "content_html" not in artifact
    assert before.headers["Cache-Control"] == after.headers["Cache-Control"] == "private, no-store"
    assert "SECRET" not in after.get_data(as_text=True)
