"""依赖图展示使用宿主传播结果，修订间不串状态，读取不执行模型。"""

from copy import deepcopy
import json

import pytest

from backend.oj_modules.faithsieve import views
from backend.oj_modules.faithsieve.proof_dag import propagate_node_verdicts
from tests.unit.test_faithsieve_proof_dag import dag
from tests.unit.test_faithsieve_views import saved


def save_graph(saved, value=None, *, key="role-000001-attempt-1"):
    value = value or dag()
    request = {"role": "tree-builder", "proof_graph_version": value["schema_version"], "files": {},
               "parameters": {}, "expected_result_path": "faithsieve-work/results/tree-builder.json"}
    saved.store.put(key, request, state="completed", response={
        "result": {"status": "ok", "artifact": "faithsieve-work/tree.json", "report": "已忠实对齐原稿"},
        "artifacts": {"faithsieve-work/tree.json": json.dumps(value, ensure_ascii=False)}})
    return value


def save_summary(saved, value, local=None):
    states = propagate_node_verdicts(value, local or {"N20": "inconclusive", "N30": "passed", "N70": "passed"})
    payload = {"schema_version": 1, "proof_dag": value, "nodes": states, "target_ids": value["target_ids"], "target_coverage": "matched",
               "targets_established": all(states[key]["established"] for key in value["target_ids"])}
    saved.write(views.NODE_VERIFICATION_PATH, payload)
    return payload


def test_dag_snapshot_and_artifact_include_safe_host_states_without_write(saved):
    value = save_graph(saved)
    summary = save_summary(saved, value)
    before = {p: p.stat().st_mtime_ns for p in saved.root.rglob("*")}
    snapshot = views.workflow_snapshot(saved.run)
    assert snapshot["proof_tree"] == {"path": "faithsieve-work/tree.json", "stage_key": "role-000001-attempt-1",
                                      "format": "dependency_dag", "schema_version": 2, "node_verification": summary["nodes"]}
    assert snapshot["stages"][0]["label"] == "建立证明依赖图"
    assert next(item for item in snapshot["stages"][0]["artifacts"] if item["path"] == "faithsieve-work/tree.json")["format"] == "dependency_dag"
    result = views.read_artifact(saved.run, "faithsieve-work/tree.json", stage_key="role-000001-attempt-1")
    assert result["proof_tree"] == value and result["proof_tree_format"] == "dependency_dag"
    assert result["proof_node_verification"]["N70"]["status"] == "blocked"
    assert before == {p: p.stat().st_mtime_ns for p in saved.root.rglob("*")}


def test_same_ids_different_graph_revision_cannot_reuse_host_states(saved):
    old = save_graph(saved)
    revised = deepcopy(old)
    revised["nodes"][0]["statement"] = "另一条命题"
    save_graph(saved, revised, key="role-000002-attempt-1")
    save_summary(saved, revised)
    old_result = views.read_artifact(saved.run, "faithsieve-work/tree.json", stage_key="role-000001-attempt-1")
    assert "proof_node_verification" not in old_result
    assert "node_verification" in views.workflow_snapshot(saved.run)["proof_tree"]


def test_image_dag_is_displayed_without_steps_or_source_annotations(saved):
    value = dag()
    value["schema_version"] = 3
    value["nodes"] = [{key: entry for key, entry in item.items()
                       if key in {"id", "kind", "label", "statement"}} for item in value["nodes"]]
    save_graph(saved, value)
    save_summary(saved, value)
    snapshot = views.workflow_snapshot(saved.run)
    assert snapshot["proof_tree"]["schema_version"] == 3
    assert snapshot["stages"][0]["label"] == "生成证明依赖图"
    artifact = next(item for item in snapshot["stages"][0]["artifacts"] if item["path"] == "faithsieve-work/tree.json")
    assert artifact["schema_version"] == 3
    assert views.read_artifact(saved.run, "faithsieve-work/tree.json")["proof_tree"] == value
    assert views._artifact_allowed("faithsieve-work/verification/N20.md")
    assert views._artifact_allowed("faithsieve-work/results/N20-local-verifier.json")


@pytest.mark.parametrize("mutation", ["graph", "targets", "unknown", "established", "status", "bool", "coverage", "target_bool"])
def test_stale_or_unrecomputable_summary_is_omitted(saved, mutation):
    value = save_graph(saved)
    summary = save_summary(saved, value)
    if mutation == "graph":
        summary["proof_dag"]["nodes"][0]["statement"] = "改变命题"
    elif mutation == "targets":
        summary["target_ids"] = ["N99"]
    elif mutation == "unknown":
        summary["nodes"]["N999"] = summary["nodes"]["N30"]
    elif mutation == "established":
        summary["nodes"]["N70"]["established"] = True
    elif mutation == "status":
        summary["nodes"]["N70"]["local_status"] = "given"
    elif mutation == "bool":
        summary["nodes"]["N10"]["established"] = 1
    elif mutation == "coverage":
        summary["target_coverage"] = "approved"
    else:
        summary["targets_established"] = 0
    saved.write(views.NODE_VERIFICATION_PATH, summary)
    assert "node_verification" not in views.workflow_snapshot(saved.run)["proof_tree"]
    assert "proof_node_verification" not in views.read_artifact(saved.run, "faithsieve-work/tree.json")


def test_node_paths_and_compiler_parameters_are_visible_but_not_private_requests(saved):
    paths = ["faithsieve-work/review/N20.md", "faithsieve-work/obligations/N20/N20-O1.md",
             "faithsieve-work/formal/N20-O1-verification.json",
             "faithsieve-work/formal/N20-O1-original-proof.lean",
             "faithsieve-work/results/N20-O1-original-semantic-checker.json"]
    assert all(views._artifact_allowed(path) for path in paths)
    assert not views._artifact_allowed("faithsieve-work/obligations/N20/../../request.json")
    assert views._parameters({"statement_path": "faithsieve-work/formal/N20-O1-original-proof.lean"}) == {
        "node_id": "N20", "obligation_id": "N20-O1", "branch": "original", "target": "proof"}
    assert views._parameters({"parameters": {"node_id": "N20", "edge_id": "D1", "private": "secret"}}) == {"node_id": "N20"}
    assert views._parameters({"parameters": {"obligation_id": "N20-O1", "branch": "original"}}) == {
        "node_id": "N20", "obligation_id": "N20-O1", "branch": "original"}
    with pytest.raises(views.FaithSieveViewError, match="身份"):
        views._parameters({"parameters": {"node_id": "N21", "obligation_id": "N20-O1"}})


def test_verification_auditor_is_readonly_llm_stage_with_safe_diagnostics_and_revision_history(saved, monkeypatch):
    node = "N20"
    path = f"faithsieve-work/review/{node}-verification.md"
    result_path = f"faithsieve-work/results/{node}-verification-auditor.json"
    diagnostic = {"kind": "quantifier_drift", "affected_node_ids": [node],
                  "reason": "局部报告把固定参数概率事件加强为统一事件。"}
    for number, status, report in ((1, "graph_defect", "原稿量词在节点中被改变。"), (2, "ok", "修订后核对完整量词。")):
        key = f"role-{number:06d}-attempt-1"
        request = {"role": "verification-auditor", "proof_graph_version": 3, "local_diagnostic_version": 1,
                   "parameters": {"node_id": node}, "expected_result_path": result_path,
                   "prompt": "SECRET-PROMPT", "files": {"private-input": "SECRET-INPUT"},
                   "endpoint": {"api_key": "SECRET-KEY"}}
        payload = {"result": {"status": status, "artifact": path, "report": report,
                              "diagnostics": [diagnostic] if status == "graph_defect" else []},
                   "artifacts": {path: report}, "control": {"private": "SECRET-CONTROL"},
                   "execution": {"private": "SECRET-EXECUTION"}}
        saved.store.put(key, request, state="completed", response=payload)
    saved.write(path, "磁盘内容不能覆盖历史检查点。")
    # 纯模型审核没有 Judge 会话，读取页面不能查询或初始化一个 Native。
    def forbidden(*_args):
        pytest.fail("verification-auditor 不能作为 Judge 读取原生会话")
    monkeypatch.setattr(views, "get_agent_session", forbidden)
    before = {p: (p.read_bytes() if p.is_file() else None, p.stat().st_mtime_ns, p.stat().st_mode)
              for p in saved.root.rglob("*")}
    snapshot = views.workflow_snapshot(saved.run)
    assert [stage["label"] for stage in snapshot["stages"]] == ["审核局部验证", "审核局部验证"]
    assert [stage["kind"] for stage in snapshot["stages"]] == ["llm", "llm"]
    assert [stage["status"] for stage in snapshot["stages"]] == ["graph_defect", "ok"]
    assert all(stage["session_id"] is None and stage["task_id"] is None for stage in snapshot["stages"])
    assert all(stage["parameters"]["node_id"] == node for stage in snapshot["stages"])
    assert "SECRET" not in json.dumps(snapshot, ensure_ascii=False)
    historical = views.read_artifact(saved.run, result_path, stage_key="role-000001-attempt-1")
    assert json.loads(historical["content"])["diagnostics"] == [diagnostic]
    assert json.loads(views.read_artifact(saved.run, result_path)["content"])["diagnostics"] == []
    assert views.read_artifact(saved.run, path, stage_key="role-000001-attempt-1")["content"] == "原稿量词在节点中被改变。"
    assert views.read_artifact(saved.run, path)["content"] == "修订后核对完整量词。"
    assert "SECRET" not in historical["content"]
    assert before == {p: (p.read_bytes() if p.is_file() else None, p.stat().st_mtime_ns, p.stat().st_mode)
                      for p in saved.root.rglob("*")}
    assert not views._artifact_allowed(result_path + ".transport.json")
    assert not views._artifact_allowed("faithsieve-work/results/E20-verification-auditor.json")
    assert not views._artifact_allowed("faithsieve-work/review/../../N20-verification.md")


@pytest.mark.parametrize("role", ["local-verifier", "verification-auditor"])
def test_unvalidated_diagnostic_extras_cannot_become_public_result_fields(saved, role):
    result_path = f"faithsieve-work/results/N20-{role}.json"
    artifact = ("faithsieve-work/verification/N20.md" if role == "local-verifier"
                else "faithsieve-work/review/N20-verification.md")
    request = {"role": role, "proof_graph_version": 3, "local_diagnostic_version": 1,
               "parameters": {"node_id": "N20"}, "expected_result_path": result_path}
    result = {"status": "graph_defect", "artifact": artifact, "report": "构图需修订。",
              "diagnostics": [{"kind": "statement_mismatch", "affected_node_ids": ["N20"],
                               "reason": "数学对象不同。", "private": "SECRET-EXTRA"}]}
    saved.store.put("role-000001-attempt-1", request, state="completed",
                    response={"result": result, "artifacts": {artifact: "公开数学报告。"}})
    public_result = views.read_artifact(saved.run, result_path)["content"]
    assert "SECRET" not in public_result and "diagnostics" not in json.loads(public_result)
