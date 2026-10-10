"""FaithSieve 展示不派任务、不泄露内部请求，文件访问拒绝链接和越界。"""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.oj_modules.faithsieve import views
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from tests.unit.test_faithsieve_workflow import tree_payload
from tests.unit.test_faithsieve_legacy_proof_tree import legacy_tree, legacy_steps


@pytest.fixture
def saved(tmp_path, monkeypatch):
    root = tmp_path / "managed"
    run = {"attempt_id": "a" * 32, "session_id": "faithsieve-" + "a" * 32,
           "status": "running", "submission_id": 42, "requested_by": "管理员"}
    workspace = root / "sessions" / run["session_id"] / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setattr(views.workspace_store, "AGENT_WORKSPACE_ROOT", root)
    sessions = {}
    monkeypatch.setattr(views, "get_agent_session", lambda sid: sessions.get(sid))
    store = CheckpointStore(workspace)
    def write(path, value):
        target = workspace / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return target
    def record(key, role, *, content="数学产物", artifact="faithsieve-work/steps.md", state="completed", parameters=None, response=None):
        request = {"role": role, "prompt": "SECRET-PROMPT", "files": {"private-input": "SECRET-INPUT"},
                   "endpoint": {"api_key": "SECRET-KEY", "base_url": "SECRET-URL"},
                   "parameters": parameters or {}, "expected_result_path": f"faithsieve-work/results/{role}.json"}
        result = {"status": "ok", "artifact": artifact, "report": "已忠实核对"}
        payload = response or {"result": result, "artifacts": {artifact: content}, "control": {"secret": "SECRET-CONTROL"}, "execution": {"credential": "SECRET-EXECUTION"}}
        store.put(key, request, state=state, response=payload if state == "completed" else None,
                  error="SECRET-PROTOCOL-REQUEST" if state == "protocol_error" else None)
        return request
    def native(key, role):
        sid, tid = f"fs-{run['attempt_id']}-{key}", f"ft-{run['attempt_id']}-{key}"
        write(f"faithsieve-work/judge-invocations/{key}.json",
              {"session_id": sid, "task_id": tid, "role": role, "prompt": "SECRET-AGENT-PROMPT"})
        sessions[sid] = {"session_id": sid, "current_task_id": tid, "task_kind": "judge", "judge_kind": "faithsieve", "attempt_id": run["attempt_id"],
                         "submission_id": run["submission_id"], "requested_by": run["requested_by"], "status": "Running"}
        return sid, tid
    return SimpleNamespace(root=root, run=run, workspace=workspace, store=store, write=write, record=record, native=native, sessions=sessions)


def test_queued_snapshot_does_not_create_or_change_files(tmp_path, monkeypatch):
    root = tmp_path / "absent-root"
    monkeypatch.setattr(views.workspace_store, "AGENT_WORKSPACE_ROOT", root)
    snapshot = views.workflow_snapshot({"attempt_id": "queued", "status": "queued"})
    assert snapshot == {"stages": [], "source": {}, "artifacts": [], "warnings": [], "edges": [],
                        "summary": {"stage_count": 0, "shown_stage_count": 0, "truncated": False}}
    assert not root.exists()


def test_all_request_and_execution_secrets_are_hidden(saved):
    saved.record("role-000001-attempt-1", "decomposer")
    before = {path: (path.stat().st_mtime_ns, path.stat().st_mode) for path in saved.root.rglob("*")}
    snapshot = views.workflow_snapshot(saved.run)
    assert "SECRET" not in json.dumps(snapshot)
    assert snapshot["stages"][0]["label"] == "忠实拆分证明"
    assert snapshot["stages"][0]["kind"] == "llm"
    assert "SECRET" not in views.read_artifact(saved.run, "faithsieve-work/results/decomposer.json")["content"]
    after = {path: (path.stat().st_mtime_ns, path.stat().st_mode) for path in saved.root.rglob("*")}
    assert before == after


def test_order_interleaves_llm_judge_code_and_scoring(saved):
    saved.record("role-000001-attempt-1", "statement-formalizer", artifact="faithsieve-work/formal/E1-O1-original-statement.lean")
    sid, tid = saved.native("role-000001-attempt-1", "statement-formalizer")
    request = {"files": {"x": "SECRET-CODE-INPUT"}, "statement_path": "faithsieve-work/formal/E1-O1-original-statement.lean"}
    saved.store.put("compile-000001", request, state="completed", response={"exit_code": 0, "diagnostics": "实际编译成功"},
                    metadata={"diagnostics_path": "faithsieve-work/formal/E1-O1-original-diagnostics.txt"})
    saved.record("role-000002-attempt-1", "semantic-checker", artifact="faithsieve-work/formal/E1-O1-original-semantics.md")
    saved.store.put("final-scoring", {"messages": ["SECRET-SCORE-PROMPT"]}, state="completed", response={"verdict": "correct", "score": 5, "comment": "证明充分"})
    stages = views.workflow_snapshot(saved.run)["stages"]
    assert [stage["sequence"] for stage in stages] == [1, 2, 3, 4]
    assert [stage["kind"] for stage in stages] == ["judge", "code", "llm", "llm"]
    assert stages[0]["session_id"] == sid and stages[0]["task_id"] == tid
    assert stages[1]["parameters"] == {"edge_id": "E1", "obligation_id": "E1-O1", "branch": "original", "target": "statement"}
    assert stages[1]["status"] == "passed"
    assert stages[3]["status"] == "correct"


def test_stage_artifact_keeps_each_revision_original(saved):
    saved.record("role-000001-attempt-1", "decomposer", content="第一次忠实拆分")
    saved.record("role-000002-attempt-1", "decomposer", content="修订后的忠实拆分")
    saved.write("faithsieve-work/steps.md", "磁盘上的新版")
    assert views.read_artifact(saved.run, "faithsieve-work/steps.md", stage_key="role-000001-attempt-1")["content"] == "第一次忠实拆分"
    assert views.read_artifact(saved.run, "faithsieve-work/steps.md")["content"] == "修订后的忠实拆分"
    with pytest.raises(views.FaithSieveArtifactNotFoundError):
        views.read_artifact(saved.run, "faithsieve-work/tree.md", stage_key="role-000001-attempt-1")


def test_proof_tree_reference_and_artifact_keep_exact_revision(saved):
    first, revised = tree_payload(), tree_payload(2)
    first["nodes"][1]["goal"] = "第一次目标"
    revised["nodes"][1]["goal"] = "修订后的目标"
    path = "faithsieve-work/tree.json"
    saved.record("role-000001-attempt-1", "tree-builder", artifact=path, content=json.dumps(first))
    saved.record("role-000002-attempt-1", "tree-builder", artifact=path, content=json.dumps(revised))
    saved.write(path, "磁盘上的未经校验内容")
    before = {p: p.stat().st_mtime_ns for p in saved.root.rglob("*")}
    snapshot = views.workflow_snapshot(saved.run)
    assert snapshot["proof_tree"] == {"path": path, "stage_key": "role-000002-attempt-1", "format": "json"}
    artifact = views.read_artifact(saved.run, path, stage_key="role-000001-attempt-1")
    assert artifact["proof_tree"] == first and artifact["proof_tree_format"] == "json"
    assert artifact["language"] == "json"
    assert views.read_artifact(saved.run, path)["proof_tree"] == revised
    assert before == {p: p.stat().st_mtime_ns for p in saved.root.rglob("*")}
    assert "SECRET" not in json.dumps(snapshot) + json.dumps(artifact)


def test_invalid_tree_cannot_supply_frontend_structure_or_reference(saved):
    tree = tree_payload()
    tree["edges"][0]["to"] = "N0"
    path = "faithsieve-work/tree.json"
    saved.record("role-000001-attempt-1", "tree-builder", artifact=path, content=json.dumps(tree))
    assert "proof_tree" not in views.workflow_snapshot(saved.run)
    assert "proof_tree" not in views.read_artifact(saved.run, path)


def test_legacy_tree_projection_uses_only_same_stage_steps_and_never_rewrites_history(saved):
    path = "faithsieve-work/tree.md"
    steps = legacy_steps(count=1)
    text = legacy_tree(count=2)
    key = "role-000001-attempt-1"
    request = {"role": "tree-builder", "files": {"faithsieve-work/steps.md": steps},
               "expected_result_path": "faithsieve-work/results/tree-builder.json"}
    saved.store.put(key, request, state="completed", response={
        "result": {"status": "ok", "artifact": path, "report": "历史树"}, "artifacts": {path: text}})
    saved.write("faithsieve-work/steps.md", "## S1\n这是不应使用的当前源文本")
    before = {p: p.stat().st_mtime_ns for p in saved.root.rglob("*")}
    snapshot = views.workflow_snapshot(saved.run)
    assert snapshot["proof_tree"] == {"path": path, "stage_key": key, "format": "legacy_markdown"}
    artifact = views.read_artifact(saved.run, path, stage_key=key)
    assert artifact["content"] == text and artifact["language"] == "markdown"
    assert artifact["proof_tree_format"] == "legacy_markdown"
    assert artifact["proof_tree"]["format"] == "legacy_markdown"
    assert len(artifact["proof_tree"]["nodes"]) == 2
    assert "不应使用" not in artifact["proof_tree"]["edges"][0]["source_text"]
    assert artifact["proof_tree"]["edges"][0]["source_text"]
    assert before == {p: p.stat().st_mtime_ns for p in saved.root.rglob("*")}


def test_strict_json_tree_reference_has_priority_over_legacy_projection(saved):
    saved.record("role-000001-attempt-1", "tree-builder", artifact="faithsieve-work/tree.json", content=json.dumps(tree_payload()))
    saved.record("role-000002-attempt-1", "tree-builder", artifact="faithsieve-work/tree.md", content=legacy_tree(count=2))
    assert views.workflow_snapshot(saved.run)["proof_tree"] == {
        "path": "faithsieve-work/tree.json", "stage_key": "role-000001-attempt-1", "format": "json"}


def test_pending_judge_links_actual_child_and_does_not_mark_result_completed(saved):
    saved.record("role-000001-attempt-1", "numeric-evaluator", state="pending", parameters={"edge_id": "E1", "obligation_id": "E1-O1", "branch": "original", "hidden": "SECRET"})
    sid, _tid = saved.native("role-000001-attempt-1", "numeric-evaluator")
    stage = views.workflow_snapshot(saved.run)["stages"][0]
    assert stage["state"] == "pending" and stage["status"] == ""
    assert stage["judge_status"] == "Running" and stage["session_id"] == sid
    assert "hidden" not in stage["parameters"]
    saved.sessions[sid]["submission_id"] = 999
    with pytest.raises(views.FaithSieveViewError, match="归属"):
        views.workflow_snapshot(saved.run)


def test_source_pdf_code_and_agent_check_are_both_visible(saved):
    saved.store.put("source-extraction", {"problem_text": "SECRET-PROBLEM", "pdf_path": "submission.pdf"}, state="completed",
                    response={"status": "ok", "text": "## 第 1 页\n忠实原稿", "report": "逐页图像已核对", "execution": {"secret": "SECRET"}})
    saved.native("source-extraction", "source-extractor")
    saved.write("faithsieve-work/judge-invocations/source-extraction/rendered/extraction.json",
                {"page_count": 1, "pages": [{"page": 1, "rendered": True, "image_path": "SECRET-HOST-PATH"}], "exit_code": 0})
    snapshot = views.workflow_snapshot(saved.run)
    assert snapshot["source"]["status"] == "ok"
    assert snapshot["source"]["preprocessing"]["pages"] == [{"page": 1, "rendered": True}]
    assert snapshot["source"]["preprocessing"]["label"] == "PDF 逐页图像渲染"
    assert "SECRET" not in json.dumps(snapshot)
    assert views.read_artifact(saved.run, "faithsieve-work/source/submission.md")["content"] == "## 第 1 页\n忠实原稿"


def test_numeric_independent_code_verification_visible_without_execution_secrets(saved):
    saved.record("role-000001-attempt-1", "numeric-evaluator", response={"result": {"status": "refuted", "report": "等式不成立"}, "artifacts": {},
                 "execution": {"tool_executed": True, "status": "refuted", "exit_code": 0, "stdout": "精确结果 false", "stderr": "", "token": "SECRET"}})
    saved.native("role-000001-attempt-1", "numeric-evaluator")
    stage = views.workflow_snapshot(saved.run)["stages"][0]
    assert stage["checks"] == [{"label": "独立精确符号复验", "kind": "code", "state": "completed", "status": "refuted", "report": "精确结果 false", "exit_code": 0}]
    assert "SECRET" not in json.dumps(stage)


def test_actual_environment_preflight_is_folded_into_source_without_image_or_commands(saved):
    saved.store.put("source-extraction", {}, state="pending")
    saved.write("faithsieve-work/tool-preflight.json", {"image": "SECRET-IMAGE", "result": {"ready": True, "exit_code": 0, "stdout": "Lean/mathlib 编译成功", "python": "3.12.0", "sympy": "1.14.0", "commands": ["SECRET-COMMAND"]}})
    snapshot = views.workflow_snapshot(saved.run)
    assert snapshot["source"]["environment"]["ready"] is True
    assert snapshot["stages"][0]["checks"][0]["label"] == "预装数学与原稿工具环境检查"
    assert 'python' not in snapshot["source"]["environment"] and 'sympy' not in snapshot["source"]["environment"]
    assert "SECRET" not in json.dumps(snapshot)


def test_protocol_failure_hides_raw_error(saved):
    saved.record("role-000001-attempt-1", "decomposer", state="protocol_error")
    stage = views.workflow_snapshot(saved.run)["stages"][0]
    assert stage["state"] == "protocol_error" and "SECRET" not in stage["report"]


@pytest.mark.parametrize(("key", "role"), [
    ("role-000001-attempt-1", "decomposer"),
    ("role-000001-attempt-1", "numeric-evaluator"),
    ("final-scoring", "scoring"),
])
def test_endpoint_failure_uses_only_safe_metadata_and_exposes_no_outputs(saved, key, role):
    request = {"role": role, "prompt": "SECRET-PROMPT", "files": {"private-input": "SECRET-INPUT"},
               "endpoint": {"api_key": "SECRET-KEY", "base_url": "SECRET-URL"}}
    saved.store.put(key, request, state="endpoint_error", error="SECRET-RAW-UPSTREAM-ERROR", metadata={
        "endpoint_error": {"kind": "request", "status_code": 402}, "private": "SECRET-METADATA",
    }, response={
        "result": {"status": "passed", "report": "SECRET-RESPONSE"},
        "artifacts": {"faithsieve-work/steps.md": "SECRET-OUTPUT"},
        "execution": {"tool_executed": True, "status": "passed", "stdout": "SECRET-EXECUTION", "exit_code": 0},
    })
    before = {path: (path.stat().st_mtime_ns, path.stat().st_mode) for path in saved.root.rglob("*")}
    snapshot = views.workflow_snapshot(saved.run)
    stage = snapshot["stages"][0]
    assert stage["state"] == "endpoint_error" and stage["status"] == "failed"
    assert stage["report"] == stage["label"] + "：模型端点余额不足或需要付费（HTTP 402）。"
    assert stage["artifacts"] == stage["checks"] == snapshot["artifacts"] == []
    assert "SECRET" not in json.dumps(snapshot)
    with pytest.raises(views.FaithSieveArtifactNotFoundError):
        views.read_artifact(saved.run, "faithsieve-work/steps.md", stage_key=key)
    after = {path: (path.stat().st_mtime_ns, path.stat().st_mode) for path in saved.root.rglob("*")}
    assert before == after


@pytest.mark.parametrize("metadata", [
    None, "SECRET-METADATA", {}, {"endpoint_error": None},
    {"endpoint_error": "SECRET-UPSTREAM"},
    {"endpoint_error": {"kind": "request", "status_code": True}},
    {"endpoint_error": {"kind": "request", "status_code": 200}},
    {"endpoint_error": {"kind": "request", "status_code": 600}},
    {"endpoint_error": {"kind": "request", "status_code": "402"}},
    {"endpoint_error": {"kind": "request", "status_code": 402.5}},
    {"endpoint_error": {"kind": "SECRET-KIND", "status_code": 402}},
    {"endpoint_error": {"kind": ["request"], "status_code": 402}},
    {"endpoint_error": {"kind": "request", "status_code": 402, "message": "SECRET-MESSAGE"}},
])
def test_invalid_endpoint_metadata_has_a_fixed_safe_failure_report(saved, metadata):
    saved.store.put("role-000001-attempt-1", {"role": "decomposer", "prompt": "SECRET-PROMPT"},
                    state="endpoint_error", error="SECRET-RAW-ERROR", metadata=metadata)
    snapshot = views.workflow_snapshot(saved.run)
    stage = snapshot["stages"][0]
    assert stage["state"] == "endpoint_error" and stage["status"] == "failed"
    assert stage["report"] == "忠实拆分证明：模型端点调用失败。"
    assert "SECRET" not in json.dumps(snapshot)


@pytest.mark.parametrize("path", ["../secret", "/etc/passwd", "faithsieve-work/../problem.md", "faithsieve-work//steps.md", "faithsieve-work\\steps.md",
                                 "faithsieve-work/checkpoints/role-000001-attempt-1.json", "faithsieve-work/judge-invocations/source-extraction.json",
                                 "faithsieve-work/results/decomposer.json.transport.json", ".runtime/config.json", "faithsieve-work/tool-preflight.json"])
def test_request_paths_and_private_files_never_exposed(saved, path):
    with pytest.raises(views.FaithSieveArtifactNotFoundError):
        views.read_artifact(saved.run, path)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_unsafe_checkpoint_nodes_fail_closed(saved, tmp_path, kind):
    directory = saved.workspace / "faithsieve-work/checkpoints"
    directory.mkdir(parents=True)
    target = directory / "role-000001-attempt-1.json"
    secret = tmp_path / "secret.json"
    secret.write_text('{"request":{},"state":"pending"}')
    if kind == "symlink":
        target.symlink_to(secret)
    elif kind == "hardlink":
        os.link(secret, target)
    else:
        os.mkfifo(target)
    with pytest.raises(views.FaithSieveViewError):
        views.workflow_snapshot(saved.run)


def test_symlink_directory_and_mismatched_run_are_rejected(saved, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (saved.workspace / "faithsieve-work").symlink_to(outside, target_is_directory=True)
    with pytest.raises(views.FaithSieveViewError):
        views.workflow_snapshot(saved.run)
    with pytest.raises(views.FaithSieveViewError, match="身份"):
        views.workflow_snapshot({**saved.run, "session_id": "another-session"})


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_root_artifact_never_follows_links(saved, tmp_path, kind):
    secret = tmp_path / "secret.md"
    secret.write_text("SECRET")
    target = saved.workspace / "problem.md"
    target.symlink_to(secret) if kind == "symlink" else os.link(secret, target)
    with pytest.raises(views.FaithSieveViewError):
        views.read_artifact(saved.run, "problem.md")


def test_unrecognized_extra_response_output_is_hidden(saved):
    saved.record("role-000001-attempt-1", "decomposer", response={"result": {"status": "ok", "report": "已核对"},
                 "artifacts": {"faithsieve-work/checkpoints/secret.json": "SECRET", "faithsieve-work/.runtime/config.json": "SECRET", "faithsieve-work/steps.md": "数学工件"}})
    snapshot = views.workflow_snapshot(saved.run)
    assert "SECRET" not in json.dumps(snapshot)
    assert {artifact["path"] for artifact in snapshot["artifacts"]} == {"faithsieve-work/steps.md", "faithsieve-work/results/decomposer.json"}


def test_legacy_records_have_explicit_order_warning_and_diagnostics(saved):
    saved.write("faithsieve-work/checkpoints/compile-000001.json", {"request": {"statement_path": "faithsieve-work/formal/E2-O3-negation-proof.lean"},
                 "state": "completed", "response": {"exit_code": 1, "diagnostics": "类型错误"}})
    snapshot = views.workflow_snapshot(saved.run)
    assert snapshot["warnings"] and snapshot["stages"][0]["sequence"] is None
    assert snapshot["stages"][0]["parameters"]["branch"] == "negation"
    assert snapshot["stages"][0]["status"] == "failed"
    assert views.read_artifact(saved.run, "faithsieve-work/formal/E2-O3-negation-proof-diagnostics.txt")["content"] == "类型错误"


def test_sequence_and_created_time_survive_resume_and_multiple_updates(saved):
    request = saved.record("role-000001-attempt-1", "decomposer", state="pending")
    pending = saved.store.get("role-000001-attempt-1", request)
    new = CheckpointStore(saved.workspace)
    new.put("compile-000001", {}, state="pending")
    new.put("role-000001-attempt-1", request, state="completed", response={})
    completed = new.get("role-000001-attempt-1", request)
    assert completed["sequence"] == pending["sequence"] == 1
    assert completed["created_at"] == pending["created_at"]
    assert completed["updated_at"] >= pending["updated_at"]
    assert new.get("compile-000001", {})["sequence"] == 2


def test_sequence_scan_ignores_unrelated_json_even_if_link_or_oversized(saved, tmp_path):
    directory = saved.workspace / "faithsieve-work/checkpoints"
    directory.mkdir(parents=True)
    secret = tmp_path / "secret"
    secret.write_text("not JSON")
    (directory / "unrelated.json").symlink_to(secret)
    with (directory / "unused.json").open("wb") as stream:
        stream.truncate(33 * 1024 * 1024)
    saved.store.put("compile-000001", {}, state="pending")
    assert saved.store.get("compile-000001", {})["sequence"] == 1


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_sequence_scan_rejects_linked_valid_checkpoint_without_reading(saved, tmp_path, kind):
    directory = saved.workspace / "faithsieve-work/checkpoints"
    directory.mkdir(parents=True)
    secret = tmp_path / "secret"
    secret.write_text('{"request":{},"state":"pending","sequence":1000}')
    target = directory / "compile-000001.json"
    target.symlink_to(secret) if kind == "symlink" else os.link(secret, target)
    for _retry in range(2):
        with pytest.raises(FaithSieveProtocolError):
            saved.store.put("compile-000002", {}, state="pending")
    assert not (directory / "compile-000002.json").exists()


@pytest.mark.parametrize("field,value", [("current_task_id", "foreign-task"), ("session_id", "foreign-session"), ("problem_id", 999), ("harness", "foreign-harness"), ("endpoint_id", 999)])
def test_native_link_checks_complete_run_runtime_identity(saved, field, value):
    saved.run.update(problem_id=5, runtime={"harness": "pi", "endpoint_id": 7})
    saved.record("role-000001-attempt-1", "statement-formalizer", state="pending")
    sid, _tid = saved.native("role-000001-attempt-1", "statement-formalizer")
    saved.sessions[sid].update(problem_id=5, harness="pi", endpoint_id=7)
    saved.sessions[sid][field] = value
    with pytest.raises(views.FaithSieveViewError, match="归属"):
        views.workflow_snapshot(saved.run)


def dag_stage(saved, index, role, artifact, content, *, files=None, parameters=None, report="已核对", revision="", dependencies=None, status="ok", extra=None):
    key = f"role-{index:06d}-attempt-1"
    request = {"role": role, "files": files or {}, "parameters": parameters or {}, "revision_report": revision,
               "expected_result_path": f"faithsieve-work/results/{role}.json"}
    result = {"status": status, "report": report, "artifact": artifact, **(extra or {})}
    saved.store.put(key, request, state="completed", response={"result": result, "artifacts": {artifact: content}},
                    metadata={"dependency_keys": dependencies} if dependencies is not None else None)
    return key


def assert_acyclic(snapshot):
    keys = [stage["key"] for stage in snapshot["stages"]]
    for edge in snapshot["edges"]:
        assert edge["source"] in keys and edge["target"] in keys
        assert keys.index(edge["source"]) < keys.index(edge["target"])
    return {(edge["source"], edge["target"]) for edge in snapshot["edges"]}


def test_dag_independent_obligations_fork_and_merge_without_sequence_chain(saved):
    one, two = "faithsieve-work/obligations/E1/E1-O1.md", "faithsieve-work/obligations/E1/E1-O2.md"
    review_path = "faithsieve-work/review/E1.md"
    reviewer = dag_stage(saved, 1, "local-reviewer", review_path, "局部原稿", parameters={"edge_id": "E1"})
    builder = dag_stage(saved, 2, "obligation-builder", "faithsieve-work/obligations/E1/index.md", "两项独立义务", files={review_path: "局部原稿"}, parameters={"edge_id": "E1"})
    builder_path = saved.store._path(builder)
    record = json.loads(builder_path.read_text())
    record["response"]["artifacts"].update({one: "第一义务", two: "第二义务"})
    builder_path.write_text(json.dumps(record))
    check1 = dag_stage(saved, 3, "check-object-generator", "faithsieve-work/formal/E1-O1-check.md", "第一检查", files={one: "第一义务"}, parameters={"obligation_id": "E1-O1"})
    numeric1 = dag_stage(saved, 4, "numeric-evaluator", "faithsieve-work/formal/E1-O1-numeric.md", "第一精确验证", files={"faithsieve-work/formal/E1-O1-check.md": "第一检查"}, parameters={"obligation_id": "E1-O1"}, status="passed")
    check2 = dag_stage(saved, 5, "check-object-generator", "faithsieve-work/formal/E1-O2-check.md", "第二检查", files={two: "第二义务"}, parameters={"obligation_id": "E1-O2"})
    numeric2 = dag_stage(saved, 6, "numeric-evaluator", "faithsieve-work/formal/E1-O2-numeric.md", "第二精确验证", files={"faithsieve-work/formal/E1-O2-check.md": "第二检查"}, parameters={"obligation_id": "E1-O2"}, status="passed")
    mapper = dag_stage(saved, 7, "evidence-mapper", "faithsieve-work/evidence-map.md", "可靠映射", files={
        "faithsieve-work/formal/E1-O1-verification.json": json.dumps({"status": "passed", "route": "numeric"}),
        "faithsieve-work/formal/E1-O2-verification.json": json.dumps({"status": "passed", "route": "numeric"})})
    edges = assert_acyclic(views.workflow_snapshot(saved.run))
    assert edges == {(reviewer, builder), (builder, check1), (check1, numeric1), (builder, check2), (check2, numeric2), (numeric1, mapper), (numeric2, mapper)}
    assert (numeric1, check2) not in edges


def test_dag_compile_semantic_proof_control_gates_for_historical_records(saved):
    statement = "faithsieve-work/formal/E1-O1-original-statement.lean"
    semantic = "faithsieve-work/formal/E1-O1-original-semantics.md"
    proof = "faithsieve-work/formal/E1-O1-original-proof.lean"
    parameters = {"obligation_id": "E1-O1", "branch": "original"}
    formal = dag_stage(saved, 1, "statement-formalizer", statement, "固定命题", parameters=parameters)
    saved.store.put("compile-000001", {"files": {statement: "固定命题"}, "statement_path": statement}, state="completed", response={"exit_code": 0, "diagnostics": ""})
    audit = dag_stage(saved, 2, "semantic-checker", semantic, "独立语义一致", files={statement: "固定命题"}, parameters=parameters)
    search = dag_stage(saved, 3, "proof-searcher", proof, "固定命题及证明", files={statement: "固定命题"}, parameters=parameters, status="passed")
    saved.store.put("compile-000002", {"files": {proof: "固定命题及证明"}, "statement_path": proof}, state="completed", response={"exit_code": 0, "diagnostics": ""})
    mapper = dag_stage(saved, 4, "evidence-mapper", "faithsieve-work/evidence-map.md", "已验证", files={
        "faithsieve-work/formal/E1-O1-verification.json": json.dumps({"route": "lean", "branch": "original", "proof_compiled": True})})
    edges = assert_acyclic(views.workflow_snapshot(saved.run))
    assert edges == {(formal, "compile-000001"), ("compile-000001", audit), (audit, search), (search, "compile-000002"), ("compile-000002", mapper)}


def test_dag_audit_revision_and_transitive_reduction_preserve_source_of_correction(saved):
    original = dag_stage(saved, 1, "decomposer", "faithsieve-work/steps.md", "未修订")
    audit = dag_stage(saved, 2, "decomposition-auditor", "faithsieve-work/review/decomposition.md", "原稿出处修订清单", files={"faithsieve-work/steps.md": "未修订"}, report="条件遗漏", status="needs_revision")
    revised = dag_stage(saved, 3, "decomposer", "faithsieve-work/steps.md", "忠实修订", revision="条件遗漏\n原稿出处修订清单")
    second_audit = dag_stage(saved, 4, "decomposition-auditor", "faithsieve-work/review/decomposition.md", "忠实审核通过", files={"faithsieve-work/steps.md": "忠实修订"})
    tree = dag_stage(saved, 5, "tree-builder", "faithsieve-work/tree.md", "证明树", files={"faithsieve-work/steps.md": "忠实修订"})
    edges = assert_acyclic(views.workflow_snapshot(saved.run))
    assert edges == {(original, audit), (audit, revised), (revised, second_audit), (second_audit, tree)}
    assert (revised, tree) not in edges


def test_dag_branches_expand_failed_search_into_fallback_without_cycle(saved):
    base = "faithsieve-work/formal/E1-O1-"
    original = dag_stage(saved, 1, "statement-formalizer", base + "original-statement.lean", "原命题", parameters={"obligation_id": "E1-O1", "branch": "original"})
    failed = dag_stage(saved, 2, "proof-searcher", base + "original-proof.lean", "搜索未解决", files={base + "original-statement.lean": "原命题"}, parameters={"obligation_id": "E1-O1", "branch": "original"}, status="inconclusive")
    negative = dag_stage(saved, 3, "statement-formalizer", base + "negation-statement.lean", "否定命题", files={base + "original-statement.lean": "原命题"}, parameters={"obligation_id": "E1-O1", "branch": "negation"})
    counter = dag_stage(saved, 4, "statement-formalizer", base + "counterexample-statement.lean", "反例命题", parameters={"obligation_id": "E1-O1", "branch": "counterexample"})
    edges = assert_acyclic(views.workflow_snapshot(saved.run))
    assert edges == {(original, failed), (failed, negative), (negative, counter)}


def test_dag_score_parses_messages_and_requires_consistency_gate(saved):
    final = dag_stage(saved, 1, "final-synthesizer", "faithsieve-work/final.md", "综合证据", extra={"verdict": "correct"})
    consistency = dag_stage(saved, 2, "consistency-auditor", "faithsieve-work/review/final.md", "独立证据审计", files={"faithsieve-work/final.md": "综合证据"})
    request = {"messages": [{"role": "system", "content": "SECRET-PROMPT"}, {"role": "user", "content": json.dumps({"input_files": {"faithsieve-work/final.md": "综合证据"}})}]}
    saved.store.put("final-scoring", request, state="completed", response={"verdict": "correct", "score": 5, "comment": "正确且充分"})
    snapshot = views.workflow_snapshot(saved.run)
    assert assert_acyclic(snapshot) == {(final, consistency), (consistency, "final-scoring")}
    assert "SECRET" not in json.dumps(snapshot)


def test_view_budget_returns_prefix_warning_without_restricting_workflow(saved, monkeypatch):
    monkeypatch.setattr(views, "_MAX_RECORDS", 2)
    for index in range(1, 5):
        saved.record(f"role-{index:06d}-attempt-1", "decomposer", content=f"第{index}次")
    snapshot = views.workflow_snapshot(saved.run)
    assert len(snapshot["stages"]) == 2 and snapshot["warnings"]
    assert snapshot["summary"] == {"stage_count": 4, "shown_stage_count": 2, "truncated": True}
    # 当轮原文不受图形展示预算影响，并且重建 Store 后仍允许继续原评测。
    assert views.read_artifact(saved.run, "faithsieve-work/steps.md", stage_key="role-000004-attempt-1")["content"] == "第4次"
    CheckpointStore(saved.workspace).put("compile-000001", {}, state="pending")
    assert len(list(saved.store.directory.glob("*.json"))) == 5


@pytest.mark.parametrize("prefix_response", [None, "旧记录损坏", {"result": {"candidate_units": None}}, {"result": {"candidate_units": "E1"}}])
def test_legacy_prefix_nullable_fields_cannot_crash_snapshot(saved, prefix_response):
    saved.write("faithsieve-work/checkpoints/role-000001-attempt-1.json", {
        "request": {"role": "prefix-auditor", "files": {}, "parameters": None}, "state": "completed", "response": prefix_response})
    saved.write("faithsieve-work/checkpoints/role-000002-attempt-1.json", {
        "request": {"role": "local-reviewer", "files": {}, "parameters": None}, "state": "pending"})
    snapshot = views.workflow_snapshot(saved.run)
    assert len(snapshot["stages"]) == 2 and snapshot["warnings"]
    assert_acyclic(snapshot)
