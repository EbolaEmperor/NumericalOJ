"""外部定理显式成图、条件化 Lean 验证及历史冻结边界。"""

from copy import deepcopy
import json

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.external_results import validate_external_results_version
from backend.oj_modules.faithsieve.graph_repair_policy import GraphRepairProgress, graph_repair_policy_value
from backend.oj_modules.faithsieve.node_selection import default_node_selection_order
from backend.oj_modules.faithsieve.proof_dag import (
    node_contexts, parse_image_proof_dag, propagate_node_verdicts, validate_image_proof_dag,
)
from backend.oj_modules.faithsieve.transport import result_tool_options
from backend.oj_modules.faithsieve import judge
from backend.oj_modules.faithsieve.workflow import WORK
from tests.unit.test_faithsieve_judge import environment as judge_environment, invoke
from tests.unit.test_faithsieve_image_workflow import Script, endpoint, graph, mathematical_records, seed


def external_graph():
    value = graph()
    value["nodes"].append({"id": "N6", "kind": "external", "label": "广义 Hilbert 不等式",
                           "statement": "∀满足间距条件的有限节点族及复系数，广义 Hilbert 双线性式满足完整常数上界。"})
    value["edges"].append({"id": "D5", "from": "N6", "to": "N4"})
    return value


class ExternalScript(Script):
    def __init__(self, root, *, repair=False):
        super().__init__(root)
        self.dag = graph() if repair else external_graph()
        self.repair = repair

    def chat(self, actual_endpoint, messages, **options):
        if self.repair and messages[0]["content"].startswith("# Tree builder") and any(
                role == "tree-builder" for role, *_rest in self.pure):
            self.dag = external_graph()
        return super().chat(actual_endpoint, messages, **options)

    def run_role(self, **request):
        self.native.append(deepcopy(request))
        identifier = request["expected_result_path"].rsplit("/", 1)[-1].split("-local")[0]
        context = json.loads(request["files"][f"{WORK}/obligations/{identifier}/{identifier}-O1.md"])
        assert request["external_results_version"] == 1
        assert "FaithSieveProof" in context["verification_contract"]
        assert "premise_N编号" in context["verification_contract"]
        artifact = f"{WORK}/verification/{identifier}.md"
        status, diagnostics = "passed", []
        if self.repair and identifier == "N4" and len(context["premises"]) == 2:
            status = "graph_defect"
            diagnostics = [{"kind": "missing_premise", "affected_node_ids": ["N4"],
                            "reason": "此步骤需要完整广义 Hilbert 定理作为外部前置结论。"}]
        elif identifier == "N4":
            assert [node["id"] for node in context["premises"]] == ["N2", "N3", "N6"]
            assert context["premises"][-1]["kind"] == "external"
        return {"result": {"status": status, "artifact": artifact, "report": "验证当前完整局部步骤。",
                           "diagnostics": diagnostics},
                "artifacts": {artifact: "列明前驱完整声明用 sorry；完整 FaithSieveProof 无占位，记录编译退出码 0。"},
                "execution": {"decision_source": "agent"}}


def test_external_is_a_direct_complete_premise_and_not_a_verification_target():
    value = external_graph()
    assert validate_image_proof_dag(value) is value
    assert parse_image_proof_dag(json.dumps(value)) == value
    contexts = node_contexts(value)
    assert list(contexts) == ["N2", "N3", "N4", "N5"]
    assert contexts["N4"]["premises"][-1] == value["nodes"][-1]
    assert default_node_selection_order(value) == ["N4", "N3", "N2"]
    result = propagate_node_verdicts(value, {"N4": "passed", "N2": "inconclusive", "N3": "passed"})
    assert result["N6"] == {"local_status": "external", "established": True, "status": "established",
                            "premise_ids": [], "blocking_premise_ids": []}
    assert result["N4"]["local_status"] == "passed" and result["N4"]["status"] == "blocked"
    assert result["N4"]["blocking_premise_ids"] == ["N2"]


@pytest.mark.parametrize("mutation", ["incoming", "target", "status", "old_image"])
def test_external_cannot_hide_an_authors_target_or_upgrade_old_protocol(mutation):
    value = external_graph()
    with pytest.raises(FaithSieveProtocolError):
        if mutation == "incoming":
            value["edges"].append({"id": "D6", "from": "N1", "to": "N6"})
            validate_image_proof_dag(value)
        elif mutation == "target":
            value["target_ids"] = ["N6"]
            validate_image_proof_dag(value)
        elif mutation == "status":
            propagate_node_verdicts(value, {"N6": "passed"})
        else:
            validate_image_proof_dag(value, allow_external_results=False)


@pytest.mark.parametrize("version", [True, 1.0, 2, 0, "1", [], {}])
def test_external_version_is_strictly_frozen(version):
    with pytest.raises(FaithSieveProtocolError):
        validate_external_results_version(version)


def test_external_tool_schema_is_opt_in_for_image_protocol_only():
    options = {"fields": {"status", "artifact", "report"}, "statuses": {"ok", "needs_revision"},
               "artifact": "faithsieve-work/tree.json", "proof_graph_version": 3}
    def kinds(**extra):
        schema = result_tool_options(endpoint(thinking=True), **options, **extra)["tools"][0]["function"]["parameters"]
        return schema["properties"]["artifacts"]["properties"][options["artifact"]]["properties"]["nodes"]["items"]["properties"]["kind"]["enum"]
    assert kinds() == ["given", "claim"]
    assert kinds(external_results_version=1) == ["given", "claim", "external"]
    with pytest.raises(FaithSieveProtocolError):
        result_tool_options(endpoint(thinking=True), **{**options, "proof_graph_version": 2}, external_results_version=1)


def test_fresh_workflow_freezes_external_contract_in_all_roles_and_native_requests(tmp_path):
    script = ExternalScript(tmp_path)
    engine = seed(tmp_path, script, thinking=True)
    result = engine.run()
    assert result["verdict"] == "correct"
    records = mathematical_records(engine.checkpoints.records())
    assert all(record["request"]["external_results_version"] == 1 for key, record in records.items()
               if key != "image-render")
    assert [request["expected_result_path"].split("/")[-1].split("-")[0] for request in script.native] == ["N4", "N3", "N2"]
    assert all(request["external_results_version"] == 1 for request in script.native)
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in engine.checkpoints.directory.glob("*.json")}
    calls = len(script.pure), len(script.native)
    assert seed(tmp_path, script, thinking=True).run() == result
    assert calls == (len(script.pure), len(script.native))
    assert all((path.read_bytes(), path.stat().st_mtime_ns) == saved for path, saved in before.items())


def test_missing_external_result_returns_to_graph_repair_then_verifies_only_claims(tmp_path):
    script = ExternalScript(tmp_path, repair=True)
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "correct"
    assert [role for role, *_rest in script.pure].count("tree-builder") == 2
    identifiers = [request["expected_result_path"].rsplit("/", 1)[-1].split("-")[0] for request in script.native]
    assert identifiers == ["N4", "N4", "N3", "N2"]
    assert "N6" not in engine.verification and "N6" not in identifiers
    assert engine.nodes["N6"]["kind"] == "external"


def test_old_markerless_workflow_replays_original_contract_without_new_calls(tmp_path):
    script = Script(tmp_path)
    engine = seed(tmp_path, script)
    engine._select_external_results_version = lambda: None
    result = engine.run()
    records = mathematical_records(engine.checkpoints.records())
    assert all("external_results_version" not in record["request"] for record in records.values())
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in engine.checkpoints.directory.glob("*.json")}
    calls = len(script.pure), len(script.native)
    resumed = seed(tmp_path, script)
    assert resumed.run() == result and resumed.external_results_version is None
    assert calls == (len(script.pure), len(script.native))
    assert all((path.read_bytes(), path.stat().st_mtime_ns) == saved for path, saved in before.items())


def test_graph_repair_progress_accepts_a_new_external_premise_without_resetting_budget():
    progress = GraphRepairProgress(graph_repair_policy_value())
    original = {"node": {"id": "N4", "kind": "claim", "statement": "当前完整步骤"}, "premises": []}
    assert progress.before_repair("N4", original) == 1
    revised = deepcopy(original)
    revised["premises"] = [{"id": "N6", "kind": "external", "statement": "完整已有定理"}]
    progress.after_repair("N4", revised)
    assert progress.count("N4") == 1


def test_native_judge_freezes_local_sorry_scope_and_reuses_same_request(judge_environment):
    env = judge_environment
    options = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1,
               "external_results_version": 1}
    for _ in range(2):
        with pytest.raises(judge.FaithSievePending):
            invoke(env.agent, **options)
    assert len(env.submissions) == 1
    frozen = json.loads((env.agent.directory / "role-000001-attempt-1.json").read_text())
    assert frozen["external_results_version"] == 1
    assert "列明前驱的完整声明可用 sorry" in frozen["prompt"]
    assert "FaithSieveProof" in frozen["prompt"]
    assert "目标、定义及其他未列辅助结论不得使用 sorry" in frozen["prompt"]
    with pytest.raises((FaithSieveProtocolError, judge.FaithSieveJudgeError)):
        invoke(env.agent, **{**options, "external_results_version": None})
    assert len(env.submissions) == 1


@pytest.mark.parametrize("options", [
    {"role": "proof-searcher", "proof_graph_version": 3, "local_diagnostic_version": None},
    {"role": "local-verifier", "proof_graph_version": 2, "local_diagnostic_version": 1},
    {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": None},
])
def test_native_external_contract_cannot_upgrade_other_judge_roles(judge_environment, options):
    with pytest.raises((FaithSieveProtocolError, judge.FaithSieveJudgeError)):
        invoke(judge_environment.agent, external_results_version=1, **options)
    assert judge_environment.submissions == []


def test_native_continuation_retains_external_and_diagnostic_contract():
    current = judge._continuation_prompt("result.json", external_results_version=1)
    historical = judge._continuation_prompt("result.json")
    assert current.startswith(historical)
    assert "直接前驱和 external 完整声明可用 sorry" in current
    assert "status、artifact、report、diagnostics" in current
    assert "graph_defect/missing_premise" in current
    assert "external" not in historical and "graph_defect" not in historical
