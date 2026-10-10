"""实际节点编排：多前驱、全分支验证与局部/全局证据门禁。"""

import copy
import json
import re

import pytest

from backend.oj_modules.ai.endpoints import LLMChatResult, LLMToolCall
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.dependency_workflow import DependencyWorkflow, NODE_VERIFICATION
from backend.oj_modules.faithsieve.workflow import SOURCE, STEPS, TREE, WORK, _Inconclusive, _role_paths
from tests.unit.test_faithsieve_input_transport import decode_input_message


def graph():
    nodes = [{"id": "N1", "kind": "given", "label": "题设", "statement": "对固定对象 x，条件 A(x)",
              "source_type": "problem", "step_ids": [], "source_location": "题面", "source_text": "条件 A(x)"}]
    for identifier, steps in (("N2", ["S1"]), ("N3", ["S2"]), ("N4", ["S3", "S4"]), ("N5", ["S4"])):
        nodes.append({"id": identifier, "kind": "claim", "label": identifier,
                      "statement": f"完整结论 {identifier}(x)，含其局部假设与量词",
                      "source_type": "submission", "step_ids": steps,
                      "source_location": f"第1页 {','.join(steps)}", "source_text": f"原稿唯一片段-{identifier}"})
    return {"schema_version": 2, "nodes": nodes,
            "edges": [{"id": f"D{index}", "from": parent, "to": child} for index, (parent, child) in enumerate(
                (("N1", "N2"), ("N1", "N3"), ("N2", "N4"), ("N3", "N4")), 1)],
            "target_ids": ["N4"], "ambiguities": []}


HEADINGS = {"Decomposer": "decomposer", "Decomposition auditor": "decomposition-auditor",
            "Tree builder": "tree-builder", "Tree auditor": "tree-auditor", "Suspicion scanner": "suspicion-scanner",
            "Local reviewer": "local-reviewer", "Check-object generator": "check-object-generator",
            "Semantic checker": "semantic-checker", "Evidence mapper": "evidence-mapper",
            "Final synthesizer": "final-synthesizer", "Consistency auditor": "consistency-auditor"}


class Script:
    def __init__(self, root, *, statuses=None, route="numeric", verdict=None, dag=None, target_coverage="matched"):
        self.root, self.dag = root, copy.deepcopy(dag or graph())
        self.statuses = statuses or {"N2": "passed", "N3": "passed", "N4": "passed", "N5": "passed"}
        self.route, self.verdict = route, verdict
        self.target_coverage = target_coverage
        self.calls, self.agent_calls, self.compiles = [], [], []

    def chat(self, endpoint, messages, **kwargs):
        data = decode_input_message(messages[1]["content"])
        files = data["input_files"]
        system = messages[0]["content"]
        if system.startswith("# FaithSieve 评分"):
            role = "scoring"
            result = {"verdict": data["approved_verdict"], "score": 5 if data["approved_verdict"] == "correct" else 2,
                      "comment": "依据实际节点证据，主路线完整或仍需补足核心论证。"}
        else:
            role = HEADINGS[system.splitlines()[0].removeprefix("# ")]
            node = None
            if TREE in files:
                local = json.loads(files[TREE])
                if "node_contexts" in local:
                    node = local["node_contexts"][0]["node"]["id"]
            obligation = f"{node}-O1" if node else None
            parameters = {"node_id": node, "obligation_id": obligation, "branch": "original",
                          "check_object_path": f"{WORK}/formal/{obligation}-check.md",
                          "semantic_report_path": f"{WORK}/formal/{obligation}-original-semantics.md"}
            artifact, _ = _role_paths(role, parameters)
            result = {"result": {"status": "ok", "artifact": artifact, "report": "完整读取并核对来源"},
                      "artifacts": {artifact: "完整报告"}, "control": {}}
            if role == "decomposer":
                result["artifacts"][artifact] = "# 原题目标\n完整目标\n" + "".join(
                    f"\n## S{index}\n第1页原稿片段S{index}\n" for index in range(1, 5))
            elif role == "tree-builder":
                result["artifacts"][artifact] = copy.deepcopy(self.dag)
                result.pop("control")
            elif role == "tree-auditor":
                result["control"] = {"target_coverage": self.target_coverage}
            elif role == "suspicion-scanner":
                result["result"]["focus_unit"] = None
                units = [{"node_id": n["id"], "suspicion": 0.1, "uncertain": False, "reason": "待验证完整命题"}
                         for n in self.dag["nodes"] if n["kind"] == "claim"]
                result["control"] = {"units": units}
                result["artifacts"][artifact] = "| node | suspicion | uncertain | reason |\n" + "\n".join(
                    f"| {u['node_id']} | 0.1 | false | 待验证完整命题 |" for u in units)
            elif role == "local-reviewer":
                result["control"] = {"review_outcome": "supported"}
                result["artifacts"][artifact] = "review_outcome: supported\n仅检查直接前驱共同推出本节点。"
            elif role == "check-object-generator":
                result["control"] = {"route": self.route}
                result["artifacts"][artifact] = f"- route: **{self.route}**\n完整局部蕴含，原文与目标未改。"
            elif role == "evidence-mapper":
                summary = json.loads(files[NODE_VERIFICATION])
                required, pending = set(), list(self.dag["target_ids"])
                while pending:
                    identifier = pending.pop()
                    if identifier in required:
                        continue
                    required.add(identifier)
                    pending += [e["from"] for e in self.dag["edges"] if e["to"] == identifier]
                units = [{"node_id": n["id"], "status": summary["nodes"][n["id"]]["local_status"]}
                         for n in self.dag["nodes"] if n["kind"] == "claim"]
                result["control"] = {"units": units,
                    "provisional_error_node": next((u["node_id"] for u in units
                        if u["node_id"] in required and u["status"] == "refuted"), None),
                    "unresolved_ancestors": [u["node_id"] for u in units if u["node_id"] in required
                                             and not summary["nodes"][u["node_id"]]["established"]]}
            elif role == "final-synthesizer":
                summary = json.loads(files[NODE_VERIFICATION])
                verdict = self.verdict or ("correct" if summary["targets_established"]
                                          and summary["target_coverage"] == "matched" else "inconclusive")
                result["result"]["verdict"] = verdict
        self.calls.append((role, copy.deepcopy(files), copy.deepcopy(messages), copy.deepcopy(kwargs)))
        if "response_format" in kwargs:
            return LLMChatResult(text=json.dumps(result, ensure_ascii=False), finish_reason="stop")
        return LLMChatResult(text="", tool_calls=(LLMToolCall("r", "faithsieve_result", json.dumps(result, ensure_ascii=False)),),
                             finish_reason="tool_calls")

    def run_role(self, *, role, prompt, files, expected_result_path, invocation_key, proof_graph_version):
        assert proof_graph_version == 2
        match = re.search(r"(N[1-9][0-9]*-O1)", expected_result_path)
        obligation = match.group(1)
        node = obligation.split("-O")[0]
        self.agent_calls.append((role, node, copy.deepcopy(files), prompt))
        status = self.statuses.get(node, "inconclusive")
        if role == "numeric-evaluator":
            artifact = f"{WORK}/formal/{obligation}-numeric.md"
            return {"result": {"status": status, "artifact": artifact, "report": "自主数值验证完整局部蕴含"},
                    "artifacts": {artifact: "已独立核对所有前提、参数与完整目标；结论及依据。"}}
        branch = re.search(r"-(original|negation|counterexample)-", expected_result_path).group(1)
        statement_path = f"{WORK}/formal/{obligation}-{branch}-statement.lean"
        name = f"«FaithSieve_{obligation}_{branch}»"
        artifact = statement_path if role == "statement-formalizer" else f"{WORK}/formal/{obligation}-{branch}-proof.lean"
        content = f"import Mathlib\ndef {name} : Prop := True\n#check {name}\n"
        if role == "statement-formalizer":
            result_status = "ok"
        else:
            content = files[statement_path] + f"\ntheorem FaithSieveProof : {name} := by trivial\n"
            result_status = "passed" if branch == "original" and status == "passed" else "inconclusive"
            if status == "refuted" and branch == "negation":
                result_status = "refuted"
        return {"result": {"status": result_status, "artifact": artifact, "report": "完整固定命题"},
                "artifacts": {artifact: content}}

    def compile_lean(self, files, statement_path, timeout_seconds=None):
        self.compiles.append((statement_path, copy.deepcopy(files)))
        return {"exit_code": 0, "diagnostics": ""}


def seed(tmp_path, script, *, protocol="openai", thinking=False):
    endpoint = {"id": 8, "category": "omni", "protocol": protocol, "base_url": "https://example.invalid/v1",
                "model": "test-model", "api_key": "test-key", "thinking_enabled": thinking,
                "thinking_format": "none", "openai_thinking_format": "enable_thinking" if protocol == "openai" else "none", "max_output_tokens": 64000,
                "context_window_tokens": 128000}
    engine = DependencyWorkflow(endpoint=endpoint, verification_agent=script, workspace=tmp_path, chat=script.chat)
    engine.store.write("problem.md", "给定固定对象x及条件A(x)，目标N4。题面仅审查类型与来源。")
    engine.store.write(SOURCE, "完整源稿-不得把全稿传给局部验证。无关信息-PRIVATE-NOISE")
    return engine


@pytest.mark.parametrize("protocol,thinking", [("openai", False), ("openai", True), ("anthropic", True)])
def test_diamond_verifies_each_claim_with_direct_premises_and_completed_reentry(tmp_path, protocol, thinking):
    script = Script(tmp_path)
    engine = seed(tmp_path, script, protocol=protocol, thinking=thinking)
    result = engine.run()
    assert result == {"verdict": "correct", "score": 5, "comment": "依据实际节点证据，主路线完整或仍需补足核心论证。"}
    assert [node for role, node, _, _ in script.agent_calls if role == "numeric-evaluator"] == ["N2", "N3", "N4", "N5"]
    assert not {"obligation-builder", "prefix-auditor"} & {r for r, *_ in script.calls}
    summary = engine.store.read_json(NODE_VERIFICATION)
    assert summary["proof_dag"] == script.dag
    assert summary["targets_established"] is True
    assert summary["nodes"]["N4"]["premise_ids"] == ["N2", "N3"]
    assert summary["nodes"]["N1"]["local_status"] == "given"
    for role, node, files, prompt in script.agent_calls:
        assert "PRIVATE-NOISE" not in files[SOURCE]
        assert "完整源稿" not in files[SOURCE]
        assert "条件 A(x)" not in files[TREE] if node == "N4" else True
        if node == "N4":
            context = json.loads(files[TREE])["node_contexts"][0]
            assert [n["id"] for n in context["premises"]] == ["N2", "N3"]
            assert "原稿唯一片段-N5" not in files[SOURCE]
            obligation = files[f"{WORK}/obligations/N4/N4-O1.md"]
            assert all(n["statement"] in obligation for n in script.dag["nodes"] if n["id"] in {"N2", "N3", "N4"})
            assert "E1" not in obligation
    checkpoints = engine.checkpoints.directory
    records = [json.loads(path.read_text()) for path in checkpoints.glob("*.json")]
    assert all(r["request"]["proof_graph_version"] == 2 for r in records)
    tree = next(r for r in records if r["request"].get("role") == "tree-builder")
    assert tree["request"]["call_options"]["require_complete_stream"] is True
    if thinking:
        schema = tree["request"]["call_options"]["tools"][0]["function"]["parameters"]
        assert schema["properties"]["artifacts"]["properties"][TREE]["properties"]["schema_version"]["enum"] == [2]
    frozen = {p.name: p.read_bytes() for p in checkpoints.glob("*.json")}
    script.calls.clear(); script.agent_calls.clear()
    assert engine.run() == result
    assert not script.calls and not script.agent_calls
    assert {p.name: p.read_bytes() for p in checkpoints.glob("*.json")} == frozen


def test_unknown_parent_does_not_block_local_verification_or_other_branch(tmp_path):
    script = Script(tmp_path, statuses={"N2": "inconclusive", "N3": "passed", "N4": "passed", "N5": "refuted"})
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "inconclusive" and result["score"] == 2
    nodes = engine.store.read_json(NODE_VERIFICATION)["nodes"]
    assert nodes["N4"]["local_status"] == "passed" and nodes["N4"]["status"] == "blocked"
    assert nodes["N4"]["blocking_premise_ids"] == ["N2"]
    assert nodes["N3"]["established"] is True
    assert nodes["N5"]["local_status"] == "refuted"
    assert engine._reliable_error() is None  # 无关支线反证不改变目标证明判断。
    assert [r for r, *_ in script.calls][-3:] == ["final-synthesizer", "consistency-auditor", "scoring"]
    assert {node for role, node, *_ in script.agent_calls} == {"N2", "N3", "N4", "N5"}


def test_all_unknown_still_completes_evidence_audit_and_real_scoring(tmp_path):
    script = Script(tmp_path, statuses={n: "inconclusive" for n in ("N2", "N3", "N4", "N5")})
    engine = seed(tmp_path, script)
    assert engine.run()["score"] == 2
    assert not engine.node_verification["targets_established"]
    assert engine._unresolved_ancestors() == ["N2", "N3", "N4"]
    assert [r for r, *_ in script.calls][-4:] == ["evidence-mapper", "final-synthesizer", "consistency-auditor", "scoring"]


def test_local_refutation_is_only_target_ancestor_and_not_propagated_as_refutation(tmp_path):
    script = Script(tmp_path, statuses={"N2": "refuted", "N3": "passed", "N4": "passed", "N5": "passed"}, verdict="incorrect")
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "incorrect"
    assert engine._reliable_error() == "N2"
    assert engine.node_verification["nodes"]["N4"]["local_status"] == "passed"
    assert engine.node_verification["nodes"]["N4"]["status"] == "blocked"


def test_unrelated_refutation_does_not_block_established_target(tmp_path):
    script = Script(tmp_path, statuses={"N2": "passed", "N3": "passed", "N4": "passed", "N5": "refuted"})
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    assert engine.node_verification["nodes"]["N5"]["established"] is False


def test_cannot_certify_blocked_target_or_call_auxiliary_failure_student_refutation(tmp_path):
    script = Script(tmp_path, statuses={n: "inconclusive" for n in ("N2", "N3", "N4", "N5")}, verdict="correct")
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "inconclusive" and "祖先" in result["comment"]
    assert "scoring" not in [r for r, *_ in script.calls]
    script = Script(tmp_path, statuses={n: "inconclusive" for n in ("N2", "N3", "N4", "N5")}, verdict="incorrect")
    engine = seed(tmp_path / "other", script)
    result = engine.run()
    assert result["verdict"] == "inconclusive" and "可靠反证" in result["comment"]


def test_lean_paths_keep_full_fixed_prop_and_independent_host_compile(tmp_path):
    script = Script(tmp_path, route="lean")
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    assert len(script.compiles) == 8
    assert all("N" in path and path.endswith(("statement.lean", "proof.lean")) for path, _ in script.compiles)
    assert len([r for r, *_ in script.calls if r == "semantic-checker"]) == 4
    assert len([r for r, *_ in script.agent_calls if r == "proof-searcher"]) == 4


def test_new_graph_never_accepts_old_state_tree(tmp_path):
    from tests.unit.test_faithsieve_workflow import tree_payload
    script = Script(tmp_path, dag=tree_payload())
    # 最先 tree-builder 严格失败，不能发布旧状态树给后续节点检查。
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "inconclusive"
    assert [r for r, *_ in script.calls].count("tree-builder") == 2
    assert not engine.store.path(TREE).exists()
    assert not script.agent_calls


@pytest.mark.parametrize("coverage", ["missing", "inconclusive"])
def test_established_author_conclusions_do_not_certify_different_problem_targets(tmp_path, coverage):
    script = Script(tmp_path, target_coverage=coverage)
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "inconclusive"
    assert engine.node_verification["targets_established"] is True
    assert engine.node_verification["target_coverage"] == coverage
    assert [r for r, *_ in script.calls][-3:] == ["final-synthesizer", "consistency-auditor", "scoring"]


def test_host_rejects_correct_when_original_target_coverage_missing(tmp_path):
    script = Script(tmp_path, target_coverage="missing", verdict="correct")
    engine = seed(tmp_path, script)
    assert "题目全部目标" in engine.run()["comment"]
    assert "scoring" not in [r for r, *_ in script.calls]


@pytest.mark.parametrize("coverage", [None, True, 1, [], {}, "ok"])
def test_target_coverage_must_be_explicit_exact_enum_before_claim_verification(tmp_path, coverage):
    script = Script(tmp_path, target_coverage=coverage)
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "inconclusive"
    assert not script.agent_calls


def test_pending_native_node_reentry_uses_same_frozen_request_and_does_not_repeat_completed_roles(tmp_path):
    class Pending(Exception):
        pass
    class Agent(Script):
        pending_once = True
        invocation_keys = []
        def run_role(self, **options):
            self.invocation_keys.append(options["invocation_key"])
            if self.pending_once:
                self.pending_once = False
                raise Pending()
            return super().run_role(**options)
    script = Agent(tmp_path)
    engine = seed(tmp_path, script)
    with pytest.raises(Pending):
        engine.run()
    pure_count = len(script.calls)
    key = script.invocation_keys[0]
    record_path = engine.checkpoints._path(key)
    request = json.loads(record_path.read_text())["request"]
    assert request["proof_graph_version"] == 2 and "agent_prompt" in request
    completed_bytes = {path.name: path.read_bytes() for path in engine.checkpoints.directory.glob("*.json") if path != record_path}
    assert engine.run()["verdict"] == "correct"
    assert script.invocation_keys[:2] == [key, key]
    assert json.loads(record_path.read_text())["request"] == request
    assert [role for role, *_ in script.calls[:pure_count]] == ["decomposer", "decomposition-auditor", "tree-builder",
                                                              "tree-auditor", "suspicion-scanner", "local-reviewer", "check-object-generator"]
    assert all((engine.checkpoints.directory / name).read_bytes() == original for name, original in completed_bytes.items())


@pytest.mark.parametrize("value", [2.0, True, "2", None])
def test_new_request_graph_version_type_drift_fails_closed_without_call(tmp_path, value):
    script = Script(tmp_path)
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    path = engine.checkpoints._path("role-000001-attempt-1")
    record = json.loads(path.read_text())
    record["request"]["proof_graph_version"] = value
    path.write_text(json.dumps(record, ensure_ascii=False))
    original = path.read_bytes()
    script.calls.clear(); script.agent_calls.clear()
    assert engine.run()["verdict"] == "inconclusive"
    assert not script.calls and not script.agent_calls and path.read_bytes() == original


def test_role_json_syntax_repair_is_reused_without_regenerating_node_task(tmp_path):
    script = Script(tmp_path)
    engine = seed(tmp_path, script)
    original = script.chat
    responses = []
    def chat(endpoint, messages, **options):
        if responses and messages[1]["content"].startswith("原始回传（字面全文）"):
            assert not any(n["source_text"] in messages[1]["content"] for n in script.dag["nodes"])
            assert "max_tokens" not in options
            return LLMChatResult(text=responses[0], finish_reason="stop")
        response = original(endpoint, messages, **options)
        if messages[0]["content"].startswith("# Local reviewer") and not responses:
            responses.append(response.text)
            return LLMChatResult(text=response.text[:-1] + ",}", finish_reason="stop")
        return response
    engine.chat = chat
    assert engine.run()["verdict"] == "correct"
    record = engine.checkpoints._read_record("role-000006-attempt-1")[0]
    assert record["metadata"]["json_repair"]["state"] == "completed"
    assert not engine.checkpoints._path("role-000006-attempt-2").exists()
    script.calls.clear(); script.agent_calls.clear()
    assert engine.run()["verdict"] == "correct"
    assert not script.calls and not script.agent_calls
