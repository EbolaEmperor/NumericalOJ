"""原图 DAG 返修闭环：保留原请求，并只重新验证改变的局部蕴含。"""

from collections import Counter
import copy
from datetime import datetime, timezone
import json

import pytest

from backend.oj_modules.ai.endpoints import LLMChatResult, LLMToolCall
from backend.oj_modules.faithsieve.dependency_workflow import NODE_VERIFICATION
from backend.oj_modules.faithsieve.image_workflow import ImageWorkflow, freeze_rendered_images
from backend.oj_modules.faithsieve.workflow import TREE, WORK
from tests.unit.test_faithsieve_image_workflow import PNG, Pending, default_node_selection, endpoint, rendered
from tests.unit.test_faithsieve_input_transport import decode_input_message


def proof_graph():
    return {
        "schema_version": 3,
        "nodes": [
            {"id": "N1", "kind": "given", "label": "条件", "statement": "共享参数 B>0、Δ>0 和随机频率 f₁,…,fₘ。"},
            {"id": "N2", "kind": "claim", "label": "独立引理", "statement": "对上述共享参数，窗口函数的范数上界成立。"},
            {"id": "N3", "kind": "claim", "label": "集中估计", "statement": "同一抽样事件上，所有满足条件的 y 都有 ĝ 的集中估计。"},
            {"id": "N4", "kind": "claim", "label": "主要结论", "statement": "由集中估计得到所述统一条件数上界。"},
            {"id": "N5", "kind": "claim", "label": "另一目标", "statement": "窗口范数上界推出另一独立结论。"},
        ],
        "edges": [
            {"id": "D1", "from": "N1", "to": "N2"},
            {"id": "D2", "from": "N2", "to": "N3"},
            {"id": "D3", "from": "N3", "to": "N4"},
            {"id": "D4", "from": "N2", "to": "N5"},
        ],
        "target_ids": ["N4", "N5"],
        "ambiguities": [],
    }


class RepairScript:
    """所有数学结果均为桩；只测试编排、冻结输入和失效范围。"""

    def __init__(self, root, *, change="statement_mismatch", repair=True, defect=True,
                 semantic_revision=False, auditor_defect=False, out_of_scope_diagnostic=False):
        self.root = root
        self.initial_graph = proof_graph()
        self.repaired_graph = copy.deepcopy(self.initial_graph)
        self.change = change
        self.repair = repair
        self.defect = defect
        self.semantic_revision = semantic_revision
        self.auditor_defect = auditor_defect
        self.out_of_scope_diagnostic = out_of_scope_diagnostic
        self.semantic_rejections = []
        self.pure = []
        self.native = []
        self.pending = None
        self.builder_count = 0
        self.defect_count = 0
        self.before_repair = {}
        if change == "statement_mismatch":
            self.repaired_graph["nodes"][2]["statement"] = self.initial_graph["nodes"][2]["statement"].replace("ĝ", "ŷ")
        elif change == "missing_premise":
            self.repaired_graph["edges"].append({"id": "D5", "from": "N1", "to": "N3"})
        elif change == "new_ancestor":
            node = {"id": "N6", "kind": "claim", "label": "所需引理", "statement": "共享参数满足集中定理所需的辅助范数估计。"}
            self.initial_graph["nodes"].append(node)
            self.initial_graph["edges"].append({"id": "D5", "from": "N1", "to": "N6"})
            self.repaired_graph = copy.deepcopy(self.initial_graph)
            self.repaired_graph["edges"].append({"id": "D6", "from": "N6", "to": "N3"})
        elif change == "quantifier_drift":
            self.initial_graph["nodes"][2]["statement"] = "先固定 y，再抽样；以至少 1-η 的概率得到 ŷ 的集中估计。"
            self.repaired_graph["nodes"][2]["statement"] = "同一次抽样，以至少 1-η 的概率对所有 y 同时得到 ŷ 的集中估计。"
        else:
            raise AssertionError(change)

    def chat(self, _endpoint, messages, **options):
        assert isinstance(messages[1]["content"], list)
        assert len(messages[1]["content"]) == 3
        data = decode_input_message(messages[1]["content"][0]["text"])
        files = data["input_files"]
        assert not any("source/submission" in path or path.endswith("steps.md") for path in files)
        prompt = messages[0]["content"]
        names = {
            "Tree builder": "tree-builder", "Tree auditor": "tree-auditor",
            "Verification auditor": "verification-auditor",
            "Node selector": "node-selector",
            "Evidence mapper": "evidence-mapper", "Final synthesizer": "final-synthesizer",
            "Consistency auditor": "consistency-auditor",
        }
        role = "scoring" if prompt.startswith("# FaithSieve 评分") else names[prompt.splitlines()[0][2:]]
        self.pure.append({"role": role, "messages": copy.deepcopy(messages), "options": copy.deepcopy(options)})
        if role == "tree-auditor":
            assert set(files) == {"problem.md", "pages.json", TREE}
        if role == "scoring":
            payload = {"verdict": data["approved_verdict"], "score": 5 if data["approved_verdict"] == "correct" else 2,
                       "comment": "按验证证据评分。"}
        else:
            artifact = {
                "tree-builder": TREE, "tree-auditor": f"{WORK}/review/tree.md",
                "evidence-mapper": f"{WORK}/evidence-map.md",
                "final-synthesizer": f"{WORK}/final.md",
                "consistency-auditor": f"{WORK}/review/final.md",
                "verification-auditor": "",
                "node-selector": f"{WORK}/node-selection.json",
            }[role]
            if role == "verification-auditor":
                paths = [path for path in files if path.startswith(f"{WORK}/obligations/") and path.endswith("-O1.md")]
                assert len(paths) == 1
                node = json.loads(files[paths[0]])["node"]["id"]
                artifact = f"{WORK}/review/{node}-verification.md"
            payload = {
                "result": {"status": "ok", "artifact": artifact, "report": "独立核对原图及完整命题。"},
                "artifacts": {artifact: "角色报告"}, "control": {},
            }
            if role == "tree-builder":
                self.builder_count += 1
                if self.builder_count == 2:
                    self.before_repair = {
                        path.name: path.read_bytes()
                        for path in (self.root / WORK / "checkpoints").glob("*.json")
                        if json.loads(path.read_text())["state"] == "completed"
                    }
                graph = self.repaired_graph if self.repair and self.builder_count > 1 else self.initial_graph
                payload["artifacts"][artifact] = copy.deepcopy(graph)
                payload.pop("control")
            elif role == "tree-auditor":
                payload["control"] = {"target_coverage": "matched"}
            elif role == "node-selector":
                assert set(files) == {"problem.md", "pages.json", TREE}
                payload["artifacts"][artifact] = json.dumps({"node_ids": default_node_selection(json.loads(files[TREE]))})
            elif role == "verification-auditor":
                payload["result"]["diagnostics"] = []
                if self.semantic_revision and node == "N4" and (self.semantic_revision == "always" or not self.semantic_rejections):
                    snapshot = json.loads((self.root / NODE_VERIFICATION).read_text())
                    self.semantic_rejections.append(snapshot["nodes"][node])
                    payload["result"]["status"] = "needs_revision"
                    payload["result"]["report"] = "Judge 擅自将固定参数的概率事件强化为统一事件，需核对完整量词后重验。"
                elif self.auditor_defect and node == "N3" and self.builder_count == 1:
                    payload["result"]["status"] = "graph_defect"
                    payload["result"]["diagnostics"] = [{"kind": "statement_mismatch", "affected_node_ids": ["N3"],
                                                            "reason": "Judge 验证了误写成 ĝ 的节点，原图为 ŷ。"}]
            elif role == "final-synthesizer":
                summary = json.loads(files[NODE_VERIFICATION])
                payload["result"]["verdict"] = "correct" if summary["targets_established"] else "inconclusive"
        raw = json.dumps(payload, ensure_ascii=False)
        if "response_format" in options:
            return LLMChatResult(text=raw, finish_reason="stop")
        return LLMChatResult(text="", tool_calls=(LLMToolCall(id="result", name="faithsieve_result", arguments=raw),), finish_reason="tool_calls")

    def run_role(self, **request):
        assert request["role"] == "local-verifier"
        assert request["files"]["source-pages/page-1.png"] == PNG + b"\x01"
        assert request["files"]["source-pages/page-2.png"] == PNG + b"\x02"
        assert TREE not in request["files"]
        node = request["expected_result_path"].rsplit("/", 1)[-1].split("-local-verifier")[0]
        context = json.loads(request["files"][f"{WORK}/obligations/{node}/{node}-O1.md"])
        saved = json.loads((self.root / WORK / "checkpoints" / f"{request['invocation_key']}.json").read_text())
        protocol = saved["request"].get("local_diagnostic_version")
        self.native.append({"node": node, "context": copy.deepcopy(context), "request": copy.deepcopy(request)})
        if self.pending == node and self.builder_count > 1:
            self.pending = None
            raise Pending(node)
        artifact = f"{WORK}/verification/{node}.md"
        result = {"status": "passed", "artifact": artifact, "report": "验证完整联合前提推出完整目标。"}
        if protocol == 1:
            result["diagnostics"] = []
        current_is_bad = self.defect and node == "N3" and self.builder_count == 1
        if current_is_bad:
            self.defect_count += 1
            result["status"] = "graph_defect"
            result["diagnostics"] = [{
                "kind": "missing_premise" if self.change == "new_ancestor" else self.change,
                "affected_node_ids": ["N5"] if self.out_of_scope_diagnostic else ["N3"],
                "reason": "原图的 ŷ 被换为 ĝ，或原图的直接条件、量词没有忠实进入当前节点。",
            }]
        return {
            "result": result,
            "artifacts": {artifact: "构图诊断" if current_is_bad else "完整命题和联合前提验证通过。\n" + json.dumps(context, ensure_ascii=False)},
            "execution": {"decision_source": "agent"},
        }


def make_engine(root, script):
    engine = ImageWorkflow(endpoint=endpoint(), verification_agent=script, workspace=root, chat=script.chat)
    engine.store.write("problem.md", "固定共同对象和参数，证明同一次抽样对所有允许对象同时成立的结论。")
    engine.set_images(freeze_rendered_images(rendered()))
    return engine


def checkpoint_bytes(engine):
    return {path.name: path.read_bytes() for path in engine.checkpoints.directory.glob("*.json")}


@pytest.mark.parametrize("change", ["statement_mismatch", "quantifier_drift"])
def test_graph_defect_repairs_goal_and_direct_consumer_but_keeps_independent_branch(tmp_path, change):
    script = RepairScript(tmp_path, change=change)
    engine = make_engine(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "correct"
    assert script.builder_count == 2
    counts = Counter(call["node"] for call in script.native)
    assert counts == {"N2": 1, "N3": 2, "N4": 2, "N5": 1}
    contexts = [call["context"] for call in script.native if call["node"] == "N4"]
    assert contexts[0]["premises"][0]["statement"] != contexts[1]["premises"][0]["statement"]
    assert engine.store.read_json(TREE) == script.repaired_graph
    summary = engine.store.read_json(NODE_VERIFICATION)
    assert summary["targets_established"] is True
    assert all(node["local_status"] in {"given", "passed"} for node in summary["nodes"].values())
    records = engine.checkpoints.records()
    for record in records.values():
        for dependency in record.get("metadata", {}).get("dependency_keys", []):
            if dependency in records:
                assert records[dependency]["sequence"] < record["sequence"]
    bad = [record for record in records.values() if record.get("response", {}).get("result", {}).get("status") == "graph_defect"]
    assert len(bad) == 1 and bad[0]["state"] == "completed"
    assert bad[0]["request"]["local_diagnostic_version"] == 1
    assert all((engine.checkpoints.directory / name).read_bytes() == data for name, data in script.before_repair.items())
    original_consumer = [record for record in records.values()
                         if record["request"].get("parameters", {}).get("node_id") == "N4"
                         and record["request"].get("role") == "local-verifier"]
    assert len(original_consumer) == 2
    assert original_consumer[0]["request"] != original_consumer[1]["request"]
    if change == "statement_mismatch":
        final_report = engine._final_files()[f"{WORK}/verification/N4.md"]
        assert "ŷ" in final_report and "ĝ" not in final_report
    before, calls = checkpoint_bytes(engine), (len(script.native), len(script.pure))
    assert engine.run() == result
    assert (len(script.native), len(script.pure)) == calls
    assert checkpoint_bytes(engine) == before


def test_missing_global_condition_becomes_direct_edge_and_rechecks_only_changed_implication(tmp_path):
    script = RepairScript(tmp_path, change="missing_premise")
    engine = make_engine(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    assert Counter(call["node"] for call in script.native) == {"N2": 1, "N3": 2, "N4": 1, "N5": 1}
    contexts = [call["context"] for call in script.native if call["node"] == "N3"]
    assert [node["id"] for node in contexts[0]["premises"]] == ["N2"]
    assert [node["id"] for node in contexts[1]["premises"]] == ["N1", "N2"]
    assert contexts[0]["node"] == contexts[1]["node"]
    assert engine.node_verification["targets_established"] is True


def test_repair_adds_required_ancestor_without_redoing_unchanged_downstream_implication(tmp_path):
    script = RepairScript(tmp_path, change="new_ancestor")
    engine = make_engine(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    assert Counter(call["node"] for call in script.native) == {"N2": 1, "N3": 2, "N4": 1, "N5": 1, "N6": 1}
    contexts = [call["context"] for call in script.native if call["node"] == "N3"]
    assert [node["id"] for node in contexts[1]["premises"]] == ["N2", "N6"]
    assert engine.node_verification["nodes"]["N6"]["established"] is True


def test_pending_repaired_judge_reentry_reuses_exact_task_and_all_previous_results(tmp_path):
    script = RepairScript(tmp_path)
    script.pending = "N3"
    engine = make_engine(tmp_path, script)
    with pytest.raises(Pending):
        engine.run()
    pending = script.native[-1]
    assert pending["node"] == "N3" and "ŷ" in pending["context"]["node"]["statement"]
    pure_count, native_count = len(script.pure), len(script.native)
    completed_before = {path.name: path.read_bytes() for path in engine.checkpoints.directory.glob("*.json")
                        if json.loads(path.read_text())["state"] == "completed"}
    assert engine.run()["verdict"] == "correct"
    assert script.native[native_count]["request"] == pending["request"]
    new_pure = script.pure[pure_count:]
    assert not any(call["role"] in {"tree-builder", "tree-auditor"} for call in new_pure)
    assert [call["role"] for call in new_pure][-4:] == ["evidence-mapper", "final-synthesizer", "consistency-auditor", "scoring"]
    assert all((engine.checkpoints.directory / name).read_bytes() == data for name, data in completed_before.items())
    assert script.builder_count == 2


def test_unchanged_graph_after_diagnostic_stops_without_marking_student_incorrect(tmp_path):
    script = RepairScript(tmp_path, repair=False)
    engine = make_engine(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "inconclusive"
    assert script.builder_count >= 2
    assert script.builder_count <= 4
    assert Counter(call["node"] for call in script.native)["N3"] == 1
    assert not any(call["role"] == "scoring" for call in script.pure)


def test_completed_legacy_three_field_results_replay_without_protocol_upgrade(tmp_path):
    script = RepairScript(tmp_path, defect=False)
    engine = make_engine(tmp_path, script)
    engine._select_local_diagnostic_version = lambda: None
    engine._select_node_selection_version = lambda: None
    result = engine.run()
    assert result["verdict"] == "correct"
    before = checkpoint_bytes(engine)
    records = engine.checkpoints.records()
    local = [record for record in records.values() if record["request"].get("role") == "local-verifier"]
    assert local and all("local_diagnostic_version" not in record["request"] for record in local)
    assert all(set(record["response"]["result"]) == {"status", "artifact", "report"} for record in local)
    assert not any(call["role"] == "verification-auditor" for call in script.pure)
    calls = (len(script.native), len(script.pure))
    del engine._select_local_diagnostic_version
    del engine._select_node_selection_version
    assert engine.run() == result
    assert engine.local_diagnostic_version is None
    assert (len(script.native), len(script.pure)) == calls
    assert checkpoint_bytes(engine) == before


def test_semantic_audit_rejects_strengthened_quantifier_before_accepting_judge_pass(tmp_path):
    script = RepairScript(tmp_path, defect=False, semantic_revision=True)
    engine = make_engine(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    assert Counter(call["node"] for call in script.native) == {"N2": 1, "N3": 1, "N4": 2, "N5": 1}
    assert len(script.semantic_rejections) == 1
    assert script.semantic_rejections[0]["local_status"] == "not_checked"
    assert script.semantic_rejections[0]["established"] is False
    consumer = [call for call in script.native if call["node"] == "N4"]
    assert consumer[0]["context"] == consumer[1]["context"]
    assert consumer[0]["request"]["invocation_key"] != consumer[1]["request"]["invocation_key"]
    assert "量词" in consumer[1]["request"]["prompt"]
    assert script.builder_count == 1


def test_auditor_graph_defect_repairs_dag_instead_of_accepting_judge_pass(tmp_path):
    script = RepairScript(tmp_path, defect=False, auditor_defect=True)
    engine = make_engine(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    assert script.builder_count == 2
    assert Counter(call["node"] for call in script.native) == {"N2": 1, "N3": 2, "N4": 2, "N5": 1}
    audits = [record for record in engine.checkpoints.records().values()
              if record["request"].get("role") == "verification-auditor"
              and record["request"].get("parameters", {}).get("node_id") == "N3"]
    assert [record["response"]["result"]["status"] for record in audits] == ["graph_defect", "ok"]
    assert engine.node_verification["nodes"]["N3"]["local_status"] == "passed"
    assert "ŷ" in engine.proof_dag["nodes"][2]["statement"]


def test_repeated_semantic_rejection_keeps_passed_judge_out_of_established_ledger(tmp_path):
    script = RepairScript(tmp_path, defect=False, semantic_revision="always")
    engine = make_engine(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "inconclusive"
    assert Counter(call["node"] for call in script.native) == {"N2": 1, "N3": 1, "N4": 2, "N5": 1}
    assert len(script.semantic_rejections) == 2
    assert all(node["local_status"] == "not_checked" and node["established"] is False
               for node in script.semantic_rejections)
    assert engine.local_statuses["N4"] == "inconclusive"
    assert engine.verification["N4-O1"]["agent_status"] == "passed"
    assert engine.verification["N4-O1"]["semantic_audit_status"] == "needs_revision"
    assert engine.node_verification["targets_established"] is False
    assert script.builder_count == 1


def test_diagnostic_cannot_reference_known_but_undisclosed_other_branch(tmp_path):
    script = RepairScript(tmp_path, out_of_scope_diagnostic=True)
    engine = make_engine(tmp_path, script)
    assert engine.run()["verdict"] == "inconclusive"
    assert script.builder_count == 1
    assert Counter(call["node"] for call in script.native) == {"N3": 1, "N4": 1, "N5": 1}
    diagnostic = [record for record in engine.checkpoints.records().values()
                  if record["request"].get("role") == "local-verifier"
                  and record["request"].get("parameters", {}).get("node_id") == "N3"]
    assert len(diagnostic) == 1 and diagnostic[0]["state"] == "protocol_error"
    assert "response" not in diagnostic[0]
    assert not (tmp_path / WORK / "graphs").exists()
    assert not any(call["role"] == "scoring" for call in script.pure)


def test_fresh_verification_auditor_endpoint_failure_has_readonly_recovery_and_exact_retry(tmp_path):
    from backend.oj_modules.ai.endpoints import LLMEndpointRequestError
    from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
    from backend.oj_modules.faithsieve.image_workflow import image_render_request
    from backend.oj_modules.faithsieve.recovery import (
        FaithSieveRecoveryError, prepare_recovery, validate_recovery_inputs,
    )
    from backend.oj_modules.faithsieve.runtime_snapshot import SNAPSHOT_FILENAME

    script = RepairScript(tmp_path, defect=False)
    engine = make_engine(tmp_path, script)
    problem, pdf = engine.store.read("problem.md"), b"%PDF-original"
    engine.checkpoints.preserve_pdf(pdf)
    engine.checkpoints.put("image-render", image_render_request(problem), state="completed",
                           response=freeze_rendered_images(rendered()), metadata={"role": "image-render"})
    snapshot = tmp_path / SNAPSHOT_FILENAME
    snapshot.write_text(json.dumps({"endpoint_id": 8, "initial_reasoning_effort": None}))
    snapshot.chmod(0o600)

    def failure(endpoint_value, messages, **options):
        if messages[0]["content"].startswith("# Verification auditor"):
            raise LLMEndpointRequestError("固定连接失败", request_failure="connection")
        return script.chat(endpoint_value, messages, **options)

    engine.chat = failure
    with pytest.raises(FaithSieveEndpointError):
        engine.run()
    records = engine.checkpoints.records()
    failed_key, failed = next((key, record) for key, record in records.items() if record["state"] == "endpoint_error")
    assert failed["request"]["role"] == "verification-auditor"
    assert failed["request"]["local_diagnostic_version"] == 1
    assert engine.local_statuses["N5"] == "not_checked"
    before = {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    calls = (len(script.native), len(script.pure))
    validate_recovery_inputs(tmp_path, {"endpoint_id": 8}, problem_text=problem, submission_pdf=pdf, endpoint=endpoint())
    assert (len(script.native), len(script.pure)) == calls
    assert {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before

    attempt = "a" * 32
    run = {"attempt_id": attempt, "submission_id": 1, "problem_id": 1, "endpoint_id": 8,
           "harness": "pi", "execution_mode": "workflow", "requested_by": "admin",
           "session_id": f"faithsieve-{attempt}", "started_at": datetime(2026, 10, 9, tzinfo=timezone.utc),
           "status": "failed", "result_json": None, "elapsed_seconds": 100}
    permission = prepare_recovery(tmp_path, run, "admin")
    assert permission["target_key"] == failed_key
    assert permission["request"] == failed["request"]
    failed_bytes = (engine.checkpoints.directory / f"{failed_key}.json").read_bytes()
    authorized_before = {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    with pytest.raises(FaithSieveRecoveryError):
        validate_recovery_inputs(tmp_path, run, problem_text=problem, submission_pdf=b"%PDF-changed", endpoint=endpoint())
    validate_recovery_inputs(tmp_path, run, problem_text=problem, submission_pdf=pdf, endpoint=endpoint())
    assert {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == authorized_before
    engine.chat = script.chat
    assert engine.run()["verdict"] == "correct"
    assert (engine.checkpoints.directory / f"{failed_key}.json").read_bytes() == failed_bytes
    retry_key = failed_key.removesuffix("-1") + "-2"
    retry = engine.checkpoints.records()[retry_key]
    assert retry["state"] == "completed" and retry["request"] == failed["request"]
    assert failed_key in retry["metadata"]["dependency_keys"]
    assert Counter(call["node"] for call in script.native) == {"N2": 1, "N3": 1, "N4": 1, "N5": 1}
    assert script.builder_count == 1
