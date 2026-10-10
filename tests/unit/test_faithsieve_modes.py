"""执行方式的持久化、历史兼容及 skill 单会话只读边界。"""

import json

import pytest

from backend.oj_modules.agents.judge import judge_session_id
from backend.oj_modules.faithsieve import skill_views, views
from backend.oj_modules.submissions import faithsieve, faithsieve_views
from scripts import init_db_schema
from tests.unit.test_agent_sessions import _ScriptedConnection
from tests.unit.test_faithsieve_workflow import tree_payload


@pytest.mark.parametrize("value,default,expected", [
    (None, "workflow", "workflow"), (None, "skill", "skill"),
    ("workflow", "skill", "workflow"), (" SKILL ", "workflow", "skill"),
])
def test_mode_normalization_requires_explicit_historical_default(value, default, expected):
    assert faithsieve.normalize_execution_mode(value, default=default) == expected


@pytest.mark.parametrize("value", ["", "  ", "agent", "auto", True, False, 0, {}, ["skill"]])
def test_invalid_new_mode_is_rejected_before_database(monkeypatch, value):
    monkeypatch.setattr(faithsieve, "get_db_connection", lambda: pytest.fail("非法执行方式不能读取数据库"))
    with pytest.raises(ValueError, match="执行方式"):
        faithsieve.queue_runs([], requested_by="admin", harness="pi", endpoint_id=3, execution_mode=value)


@pytest.mark.parametrize("mode", ["workflow", "skill", None])
def test_new_queue_persists_mode_and_deduplicates_across_modes(monkeypatch, mode):
    connection = _ScriptedConnection(one_values=[{"acquired": 1}, {"attempt_id": "other-mode", "status": "running"}, None])
    monkeypatch.setattr(faithsieve, "get_db_connection", lambda: connection)
    options = {} if mode is None else {"execution_mode": mode}
    queued, skipped = faithsieve.queue_runs(
        [{"id": 11, "problem_id": 7}, {"id": 12, "problem_id": 7}],
        requested_by="admin", harness="pi", endpoint_id=3, **options,
    )
    assert skipped == [11] and [item["submission_id"] for item in queued] == [12]
    queries = connection.cursor_instance.calls
    insert, values = next((query, values) for query, values in queries if "INSERT INTO faithsieve_grading_runs" in query)
    assert "endpoint_id, execution_mode, status" in insert
    assert values[-1] == (mode or "workflow")
    latest = [query for query, _params in queries if "WHERE submission_id=%s" in query]
    assert len(latest) == 2 and all("execution_mode" not in query for query in latest)
    assert connection.commits == 1 and connection.closed


@pytest.mark.parametrize("mode", ["workflow", "skill"])
def test_modes_share_the_same_twenty_run_slots(monkeypatch, mode):
    connection = _ScriptedConnection(one_values=[{"acquired": 1}, {"status": "queued", "execution_mode": mode}, {"total": 20}])
    monkeypatch.setattr(faithsieve, "get_db_connection", lambda: connection)
    assert faithsieve.MAX_CONCURRENT_RUNS == 20
    assert not faithsieve.claim_run_slot("attempt", task_id="task", session_id="session")
    count = next(query for query, _params in connection.cursor_instance.calls if "COUNT(*)" in query)
    assert "WHERE status='running'" in count and "execution_mode" not in count
    assert connection.commits == 0


@pytest.mark.parametrize("stored", [{}, {"execution_mode": None}, {"execution_mode": "skill"}, {"execution_mode": "workflow"}])
def test_get_run_normalizes_historical_records_without_writes(monkeypatch, stored):
    connection = _ScriptedConnection(one_values=[{"attempt_id": "attempt", **stored}])
    monkeypatch.setattr(faithsieve, "get_db_connection", lambda: connection)
    row = faithsieve.get_run("attempt")
    assert row["execution_mode"] == (stored.get("execution_mode") or "skill")
    assert connection.commits == 0 and connection.closed
    assert all(query.startswith("SELECT") for query, _params in connection.cursor_instance.calls)


def test_invalid_stored_mode_is_not_silently_reinterpreted(monkeypatch):
    connection = _ScriptedConnection(one_values=[{"attempt_id": "attempt", "execution_mode": "unknown"}])
    monkeypatch.setattr(faithsieve, "get_db_connection", lambda: connection)
    with pytest.raises(ValueError):
        faithsieve.get_run("attempt")
    with pytest.raises(ValueError):
        faithsieve_views.public_run({"execution_mode": "unknown"})
    assert connection.closed and connection.commits == 0


def test_schema_adds_only_nullable_mode_without_backfill(monkeypatch):
    spec = init_db_schema._load_schema_specs()["faithsieve_grading_runs"]
    definition = spec.columns["execution_mode"].lower()
    assert definition.startswith("varchar(16) default null") and "not null" not in definition
    monkeypatch.setattr(init_db_schema, "_table_exists", lambda *_args: True)
    monkeypatch.setattr(init_db_schema, "_existing_columns", lambda *_args: {
        name: {"Type": init_db_schema._column_type(value)} for name, value in spec.columns.items() if name != "execution_mode"
    })
    monkeypatch.setattr(init_db_schema, "_existing_indexes", lambda *_args: set(spec.indexes))
    class NeverExecute:
        def execute(self, *_args):
            pytest.fail("schema 契约仅生成计划，不能执行 DDL")
    actions = []
    init_db_schema._sync_table(NeverExecute(), spec, True, actions)
    assert len(actions) == 1
    assert actions[0].startswith("ALTER TABLE `faithsieve_grading_runs` ADD COLUMN `execution_mode` varchar(16) DEFAULT NULL")
    assert "AFTER `endpoint_id`" in actions[0] and "UPDATE " not in actions[0]


@pytest.fixture
def skill_run(tmp_path, monkeypatch):
    attempt = "b" * 32
    sid = judge_session_id(12, attempt, "faithsieve")
    root = tmp_path / "agent-root"
    workspace = root / "sessions" / sid / "workspace"
    workspace.mkdir(parents=True)
    run = {"attempt_id": attempt, "submission_id": 12, "problem_id": 7,
           "requested_by": "admin", "username": "student", "execution_mode": "skill",
           "session_id": sid, "task_id": "dispatcher-task", "status": "running",
           "runtime": {"harness": "pi", "endpoint_id": 3}}
    session = {"session_id": sid, "current_task_id": f"fs-{attempt}", "task_kind": "judge",
               "judge_kind": "faithsieve", "submission_id": 12, "problem_id": 7,
               "attempt_id": attempt, "requested_by": "student", "harness": "pi",
               "endpoint_source": "global", "endpoint_id": 3, "status": "Running", "message": "正在核验原稿",
               "user_message": "PRIVATE-PROMPT", "api_key": "PRIVATE-KEY"}
    monkeypatch.setattr(views.workspace_store, "AGENT_WORKSPACE_ROOT", root)
    monkeypatch.setattr(skill_views, "get_agent_session", lambda requested: session if requested == sid else pytest.fail("错误 Judge 身份"))
    return run, session, workspace


def test_skill_snapshot_only_has_actual_single_judge_and_safe_artifacts(skill_run):
    run, session, workspace = skill_run
    (workspace / "faithsieve-work").mkdir()
    (workspace / "faithsieve-work/steps.md").write_text("# 原证明拆分", encoding="utf-8")
    (workspace / "PRIVATE-PROMPT.md").write_text("PRIVATE-PROMPT", encoding="utf-8")
    (workspace / "faithsieve_result.json").write_text(json.dumps({"verdict": "correct", "score": 5, "comment": "证明正确"}), encoding="utf-8")
    before = {path: path.stat().st_mtime_ns for path in workspace.rglob("*")}
    snapshot = skill_views.skill_snapshot(run)
    assert snapshot["edges"] == [] and len(snapshot["stages"]) == 1
    stage = snapshot["stages"][0]
    assert stage["role"] == "skill" and stage["kind"] == "judge" and stage["judge_status"] == "Running"
    assert stage["session_id"] == run["session_id"] and stage["task_id"] == session["current_task_id"]
    assert {item["path"] for item in snapshot["artifacts"]} == {"faithsieve-work/steps.md", "faithsieve_result.json"}
    assert "PRIVATE-" not in json.dumps(snapshot)
    assert before == {path: path.stat().st_mtime_ns for path in workspace.rglob("*")}
    assert skill_views.read_skill_artifact(run, "faithsieve-work/steps.md", stage_key="skill-judge")["content"] == "# 原证明拆分"
    session["status"] = "Canceled"
    assert skill_views.skill_snapshot(run)["stages"][0]["state"] == "completed"


def test_skill_json_proof_tree_is_parsed_without_inventing_internal_stages(skill_run):
    run, _session, workspace = skill_run
    path = "faithsieve-work/tree.json"
    (workspace / "faithsieve-work").mkdir()
    (workspace / path).write_text(json.dumps(tree_payload()))
    snapshot = skill_views.skill_snapshot(run)
    assert len(snapshot["stages"]) == 1 and snapshot["edges"] == []
    assert snapshot["proof_tree"] == {"path": path, "stage_key": "skill-judge", "format": "json"}
    artifact = skill_views.read_skill_artifact(run, path, stage_key="skill-judge")
    assert artifact["proof_tree"] == tree_payload() and artifact["proof_tree_format"] == "json"


@pytest.mark.parametrize("field,value", [
    ("requested_by", "admin"), ("submission_id", 13), ("problem_id", 8),
    ("attempt_id", "c" * 32), ("current_task_id", "other-task"),
    ("harness", "claude_code"), ("endpoint_id", 4), ("endpoint_source", "user"),
])
def test_skill_judge_requires_student_ownership_and_frozen_identity(skill_run, field, value):
    run, session, _workspace = skill_run
    session[field] = value
    with pytest.raises(views.FaithSieveViewError):
        skill_views.skill_snapshot(run)


@pytest.mark.parametrize("path", ["AGENTS.md", "submission.pdf", ".runtime/config.json", "../secret", "faithsieve-work/checkpoints/source-extraction.json"])
def test_skill_artifact_does_not_expose_prompt_or_internal_files(skill_run, path):
    run, _session, _workspace = skill_run
    with pytest.raises(views.FaithSieveArtifactNotFoundError):
        skill_views.read_skill_artifact(run, path)


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_skill_math_artifact_rejects_links(skill_run, tmp_path, kind):
    run, _session, workspace = skill_run
    secret = tmp_path / "secret.md"
    secret.write_text("PRIVATE-SECRET", encoding="utf-8")
    if kind == "symlink":
        (workspace / "problem.md").symlink_to(secret)
    else:
        import os
        os.link(secret, workspace / "problem.md")
    with pytest.raises(views.FaithSieveViewError):
        skill_views.read_skill_artifact(run, "problem.md")


def test_unstarted_historical_skill_snapshot_does_not_create_workspace(skill_run, monkeypatch):
    run, _session, workspace = skill_run
    run.pop("execution_mode")
    run["session_id"] = None
    monkeypatch.setattr(skill_views, "get_agent_session", lambda *_args: pytest.fail("未派发不应查 Judge"))
    snapshot = skill_views.skill_snapshot(run)
    assert snapshot["stages"] == [] and snapshot["edges"] == []
    assert list(workspace.iterdir()) == []
