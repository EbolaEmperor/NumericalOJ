"""FaithSieve 原流程、独立证据边界和请求传输契约。"""

import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest
from tests.unit.test_faithsieve_input_transport import decode_input_message

from backend.oj_modules.ai.endpoints import (
    LLMChatResult, LLMToolCall, LLMUsage, LLMEndpointRequestError, LLMEndpointResponseError, LLMEndpointValidationError,
)
from backend.oj_modules.faithsieve.artifacts import ArtifactStore, FaithSieveProtocolError
from backend.oj_modules.faithsieve import prompts, workflow
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from backend.oj_modules.faithsieve.dependency_workflow import DependencyWorkflow
from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError, endpoint_error_message


ROOT = Path(__file__).resolve().parents[2]
_HEADINGS = {
    "Decomposer": "decomposer", "Decomposition auditor": "decomposition-auditor",
    "Tree builder": "tree-builder", "Tree auditor": "tree-auditor",
    "Suspicion scanner": "suspicion-scanner", "Local reviewer": "local-reviewer",
    "Obligation builder": "obligation-builder", "Check-object generator": "check-object-generator",
    "Semantic checker": "semantic-checker", "Evidence mapper": "evidence-mapper",
    "Prefix auditor": "prefix-auditor", "Final synthesizer": "final-synthesizer",
    "Consistency auditor": "consistency-auditor",
}


def _function_response(payload, **fields):
    arguments = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    return LLMChatResult(text="", tool_calls=(LLMToolCall("result", "faithsieve_result", arguments),), **fields)


def _function_payload(response):
    return json.loads(response.tool_calls[0].arguments)


def _assert_function_options(options):
    assert len(options["tools"]) == 1
    assert options["tools"][0]["type"] == "function"
    assert options["tools"][0]["function"]["name"] == "faithsieve_result"
    assert options["tool_choice"] in ("auto", {"type": "function", "function": {"name": "faithsieve_result"}})


def envelope(artifact, *, status="ok", report="证据与原文一致", control=None, **extra):
    result = {"status": status, "artifact": artifact, "report": report, **extra}
    return {"result": result, "artifacts": {artifact: "完整工件"}, "control": control or {}}


def tree_payload(count=1):
    return {"schema_version": 1, "root_id": "N0",
            "nodes": [{"id": f"N{number}", "label": "根状态" if number == 0 else f"第 {number} 步后",
                       "conditions": ["自然数"] if number == 0 else [f"{number}={number + 1}"],
                       "goal": "证明一。", "scope": []} for number in range(count + 1)],
            "edges": [{"id": f"E{number}", "from": f"N{number - 1}", "to": f"N{number}",
                       "step_id": f"S{number}", "source_location": "原稿第 1 页", "source_text": f"{number}={number + 1}。",
                       "changes": {"retained": [], "added": [f"{number}={number + 1}"], "consumed": [], "transformed": []},
                       "goal_relation": "目标不变", "transition_type": "等价改写", "scope": []}
                      for number in range(1, count + 1)], "ambiguities": []}


class ScriptedRun:
    def __init__(self, root, *, suspicious=False, numeric_verified=True, route="numeric", verdict=None):
        self.root = root
        self.suspicious = suspicious
        self.numeric_verified = numeric_verified
        self.route = route
        self.verdict = verdict or ("incorrect" if suspicious and route == "numeric" else "correct")
        self.roles = []
        self.tool_roles = []
        self.compiled = []
        self.messages = []
        self.audit_revisions = 0
        self.consistency_revisions = 0
        self.semantic_revisions = 0
        self.two_obligations = False
        self.tamper_proof = False
        self.proof_compile_failure = False
        self.unsafe_proof = ""
        self.grade_score = 2 if self.verdict == "incorrect" else 5
        self.state = "inconclusive"

    def chat(self, endpoint, messages, **kwargs):
        if "response_format" in kwargs:
            assert kwargs["response_format"] == {"type": "json_object"}
            assert not {"tools", "tool_choice"} & set(kwargs)
            respond = lambda payload: LLMChatResult(text=json.dumps(payload, ensure_ascii=False))
        else:
            _assert_function_options(kwargs)
            respond = _function_response
        assert len(messages) == 2
        system = messages[0]["content"]
        data = decode_input_message(messages[1]["content"])
        files = data["input_files"]
        self.messages.append((system, data))
        if system.startswith("# FaithSieve 评分"):
            self.roles.append("scoring")
            return respond({"verdict": self.verdict, "score": self.grade_score, "comment": "主证明骨架尚未成立，需重做核心路线。"})
        role = _HEADINGS[system.splitlines()[0].removeprefix("# ")]
        self.roles.append(role)
        artifact, _result = workflow._role_paths(role, {"edge_id": "E1", "obligation_id": "E1-O1", "branch": "original", "check_object_path": "faithsieve-work/formal/E1-O1-check.md", "semantic_report_path": "faithsieve-work/formal/E1-O1-original-semantics.md"})
        out = envelope(artifact)
        if role == "decomposer":
            if self.roles.count(role) > 1:
                assert not (self.root / "faithsieve-work/results/decomposer.json").exists()
                assert not (self.root / "faithsieve-work/steps.md").exists()
                assert data["revision_report"]
            out["artifacts"][artifact] = "# 目标及定义\n证明一。\n\n## S1\n原稿第 1 页：1 = 2。唯一动作是等价改写。当前分支 root。"
        elif role == "decomposition-auditor" and self.audit_revisions:
            self.audit_revisions -= 1
            out["result"]["status"] = "needs_revision"
            out["result"]["report"] = "须忠实保留原稿常数"
        elif role == "tree-builder":
            out["artifacts"][artifact] = json.dumps(tree_payload(), ensure_ascii=False)
        elif role == "suspicion-scanner":
            suspicion = 0.8 if self.suspicious else 0.1
            out["result"]["focus_unit"] = "E1" if self.suspicious else None
            out["artifacts"][artifact] = f"| EdgeUnit | suspicion | 理由 |\n| E1 | {suspicion} | 核对原稿的等价转换 |"
            out["control"] = {"units": [{"edge_id": "E1", "suspicion": suspicion, "uncertain": self.suspicious, "reason": "核对原稿的等价转换"}]}
        elif role == "local-reviewer":
            out["artifacts"][artifact] = "review_outcome: suspect\n原稿中的 1=2 需要验证。"
            out["control"] = {"review_outcome": "suspect"}
        elif role == "obligation-builder":
            count = 2 if self.two_obligations else 1
            obligations = []
            for index in range(1, count + 1):
                identifier = f"E1-O{index}"
                path = f"faithsieve-work/obligations/E1/{identifier}.md"
                obligations.append({"id": identifier, "path": path, "depends_on": [] if index == 1 else ["E1-O1"]})
                out["artifacts"][path] = f"{identifier}：输入条件自然数；待证 1=2；方向旧条件推出新事实；原稿第1页；见证不变。"
            out["artifacts"][artifact] = "\n".join(item["path"] for item in obligations)
            out["control"] = {"obligations": obligations}
        elif role == "check-object-generator":
            out["artifacts"][artifact] = f"route={self.route}\n原义务 E1-O1，source mapping 第1页：1=2。"
            out["control"] = {"route": self.route}
        elif role == "semantic-checker":
            assert not any("proof.lean" in path for path in files)
            assert not any(path.endswith("evidence-map.md") for path in files)
            if self.semantic_revisions:
                self.semantic_revisions -= 1
                out["result"]["status"] = "needs_revision"
                out["result"]["report"] = "量词映射需要修订"
        elif role == "evidence-mapper":
            verification_path = "faithsieve-work/formal/E1-O1-verification.json"
            self.state = json.loads(files[verification_path])["status"] if verification_path in files else "inconclusive"
            out["control"] = {"units": [{"edge_id": "E1", "status": self.state}], "provisional_error_unit": "E1" if self.state == "refuted" else None, "prefix_units": []}
        elif role == "prefix-auditor":
            out["result"]["candidate_units"] = []
        elif role == "final-synthesizer":
            out["result"]["verdict"] = self.verdict
            out["artifacts"][artifact] = "总体判断及证据，首错是第 1 步，或完整证明无缺口。"
        elif role == "consistency-auditor":
            assert artifact not in files
            if self.consistency_revisions:
                self.consistency_revisions -= 1
                out["result"]["status"] = "needs_revision"
                out["result"]["report"] = "须准确引用已核验的证据路径"
        return respond(out)

    def run_role(self, role, prompt, files, expected_result_path, timeout_seconds=None, invocation_key=None):
        self.tool_roles.append(role)
        assert "最终只返回一个可解析 JSON 对象" not in prompt
        assert "faithsieve-work/scan.md" not in files
        assert "faithsieve-work/evidence-map.md" not in files
        if role == "numeric-evaluator":
            artifact = "faithsieve-work/formal/E1-O1-numeric.md"
            out = envelope(artifact, status="refuted", report="SymPy 实际计算 1 == 2 为 False")
            out["artifacts"][artifact] = "原始断言 1=2；忠实解析；工具命令 sympy.Eq(Integer(1), Integer(2))；原始结果 False。"
            out["execution"] = {"verified": self.numeric_verified, "exit_code": 0, "stdout": "False"}
            return out
        branch = re.search(r"E1-O1-(original|negation|counterexample)-", expected_result_path).group(1)
        statement_path = f"faithsieve-work/formal/E1-O1-{branch}-statement.lean"
        if role == "statement-formalizer":
            out = envelope(statement_path)
            name = f"«FaithSieve_E1-O1_{branch}»"
            out["artifacts"][statement_path] = f"import Mathlib\ndef {name} : Prop := True\n#check {name}\n"
            return out
        assert "problem.md" in files
        assert "faithsieve-work/source/submission.md" in files
        assert "faithsieve-work/obligations/E1/E1-O1.md" in files
        artifact = f"faithsieve-work/formal/E1-O1-{branch}-proof.lean"
        out = envelope(artifact, status="passed" if branch == "original" else "refuted")
        out["artifacts"][artifact] = files[statement_path] + f"\ntheorem FaithSieveProof : «FaithSieve_E1-O1_{branch}» := by trivial\n"
        if self.tamper_proof:
            out["artifacts"][artifact] = out["artifacts"][artifact].replace(": «FaithSieve_E1-O1_" + branch + "» := by trivial", ": True := by trivial")
        if self.unsafe_proof:
            out["artifacts"][artifact] += "\n#check " + self.unsafe_proof
        return out

    def compile_lean(self, files, statement_path, timeout_seconds=None):
        self.compiled.append(statement_path)
        if self.proof_compile_failure and statement_path.endswith("proof.lean"):
            return {"exit_code": 1, "diagnostics": "实际 Lean 编译失败"}
        return {"exit_code": 0, "diagnostics": ""}


def seeded_workflow(tmp_path, run):
    engine = workflow.FaithSieveWorkflow(endpoint=object(), verification_agent=run, workspace=tmp_path, chat=run.chat)
    engine.store.write("problem.md", "证明题，原条件、定义及目标。")
    engine.store.write(workflow.SOURCE, "第1页：学生证明原稿。")
    return engine


@pytest.mark.parametrize("effort", ["", "default", "high", "xhigh", True, 1, {}, []])
def test_initial_reasoning_effort_rejects_unsupported_or_non_string_values(tmp_path, effort):
    with pytest.raises(ValueError, match="初始思考强度"):
        workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(), verification_agent=None,
                                   workspace=tmp_path, initial_reasoning_effort=effort)
    assert not (tmp_path / "faithsieve-work").exists()


@pytest.mark.parametrize("effort", [None, "low", "medium"])
def test_workflow_entry_passes_initial_effort_without_changing_image_judge_contract(tmp_path, monkeypatch, effort):
    calls = []
    class Agent:
        def extract_submission(self, pdf, **options):
            calls.append((pdf, options))
            return {"status": "ok", "text": "第1页：忠实原稿。", "report": "已逐页核对"}
    def run(instance):
        assert instance.initial_reasoning_effort == effort
        return {"verdict": "correct", "score": 5, "comment": "证明充分。"}
    monkeypatch.setattr(DependencyWorkflow, "run", run)
    result = workflow._run_dependency_workflow(
        problem_text="原题面", submission_pdf=b"%PDF-original", endpoint=thinking_endpoint(),
        verification_agent=Agent(), workspace=tmp_path, initial_reasoning_effort=effort,
    )
    assert result["verdict"] == "correct"
    assert calls == [(b"%PDF-original", {"problem_text": "原题面", "invocation_key": "source-extraction",
                                      "timeout_seconds": workflow.SOURCE_TIMEOUT_SECONDS})]


def test_role_prompts_and_control_source_are_verbatim_skill_copies():
    source = ROOT / "skills/faithsieve"
    assert (prompts.PROMPT_ROOT.parent / "workflow_source.md").read_text() == (source / "references/legacy-dependency-workflow.md").read_text()
    for path in (source / "references/agents").glob("*.md"):
        assert (prompts.PROMPT_ROOT / path.name).read_text() == path.read_text()
    original = (source / "references/legacy-dependency-workflow.md").read_text()
    tree_stage = original.split("## 3. 建立并审计命题依赖 DAG", 1)[1].split("## 4.", 1)[0]
    assert "faithsieve-work/source/submission.md" in tree_stage
    assert "修订时仍保留全部原始输入" in tree_stage
    source_stage = original.split("## 1. 查看并整理原稿", 1)[1].split("## 2.", 1)[0]
    assert "不读取题面作为转录参照" in source_stage
    assert "按实际字形保留全部记号、结构及其相对位置" in source_stage
    rubric = original.split("主 Agent 根据最终综合给 0–5 整数分：", 1)[1].split("将总体判断", 1)[0]
    assert rubric in prompts.SCORE_PROMPT
    assert len(prompts.ROLE_NAMES) == 16


def test_low_risk_proof_still_reaches_final_synthesis_and_audit(tmp_path):
    run = ScriptedRun(tmp_path)
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "correct"
    assert run.tool_roles == []
    assert run.roles[-3:] == ["final-synthesizer", "consistency-auditor", "scoring"]
    assert json.loads((tmp_path / workflow.RESULT).read_text()) == result


def test_decomposition_revision_repeats_independent_auditor_once(tmp_path):
    run = ScriptedRun(tmp_path)
    run.audit_revisions = 1
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "correct"
    assert run.roles.count("decomposer") == 2
    assert run.roles.count("decomposition-auditor") == 2


def test_three_decomposition_revisions_can_reach_independent_approval(tmp_path):
    run = ScriptedRun(tmp_path)
    run.audit_revisions = 3
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "correct"
    assert run.roles.count("decomposer") == run.roles.count("decomposition-auditor") == 4


def test_four_failed_decomposition_audits_remain_inconclusive(tmp_path):
    run = ScriptedRun(tmp_path)
    run.audit_revisions = 4
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "inconclusive"
    assert run.roles == ["decomposer", "decomposition-auditor"] * 4


@pytest.mark.parametrize(("generator", "auditor", "artifact"), [
    ("decomposer", "decomposition-auditor", workflow.STEPS),
    ("tree-builder", "tree-auditor", workflow.TREE),
])
def test_generator_revision_gets_exact_previous_readonly_artifact_and_independent_auditor(tmp_path, generator, auditor, artifact):
    run = ScriptedRun(tmp_path)
    original = run.chat
    generated, audited, input_files = [], [], []
    def chat(endpoint, messages, **kwargs):
        response = original(endpoint, messages, **kwargs)
        role = _HEADINGS[messages[0]["content"].splitlines()[0].removeprefix("# ")]
        files = decode_input_message(messages[1]["content"])["input_files"]
        payload = _function_payload(response)
        if role == generator:
            input_files.append(files)
            if generator == "decomposer":
                payload["artifacts"][artifact] += f"\n未受影响的共享前提与原文；版本 {len(generated) + 1}。"
            else:
                tree = json.loads(payload["artifacts"][artifact])
                tree["nodes"][0]["label"] = f"版本 {len(generated) + 1}"
                payload["artifacts"][artifact] = json.dumps(tree, ensure_ascii=False)
            generated.append(payload["artifacts"][artifact])
        if role == auditor:
            audited.append(files)
            assert not any(path.startswith(f"{workflow.WORK}/reference/") for path in files)
            own_artifact, _result_path = workflow._role_paths(auditor, {})
            assert own_artifact not in files
            if len(audited) <= 2:
                payload["result"].update(status="needs_revision", report="局部修订动作摘要，其他原文保留。")
        response = _function_response(payload)
        return response
    engine = seeded_workflow(tmp_path, run)
    engine.chat = chat
    if generator == "tree-builder":
        engine.store.write(workflow.STEPS, "## S1\n完整原稿步骤。")
    sources = ("problem.md", workflow.SOURCE) if generator == "decomposer" else ("problem.md", workflow.STEPS)
    output = engine._audit_pair(generator, auditor,
                               generator_files=lambda: engine._files(*sources, artifact),
                               auditor_files=lambda: engine._files(*sources, artifact))
    assert output.result["status"] == "ok" and len(generated) == len(audited) == 3
    reference = f"{workflow.WORK}/reference/{generator}-previous.{artifact.rsplit('.', 1)[-1]}"
    assert reference not in input_files[0]
    for index in (1, 2):
        assert input_files[index][reference] == generated[index - 1]
        assert artifact not in input_files[index]
    assert [files[artifact] for files in audited] == generated
    assert not engine.store.path(reference).exists()
    for generation, audit in ((3, 2), (5, 4)):
        record = json.loads((tmp_path / f"faithsieve-work/checkpoints/role-{generation:06d}-attempt-1.json").read_text())
        assert f"role-{audit:06d}-attempt-1" in record["metadata"]["dependency_keys"]


def test_tree_calls_freeze_original_problem_and_source_through_revision(tmp_path):
    run = ScriptedRun(tmp_path)
    original = run.chat
    observed = []
    suggestion = "建议把题目目标 P 改为作者声称的 Q。"
    engine = seeded_workflow(tmp_path, run)
    problem, source = engine.store.read("problem.md"), engine.store.read(workflow.SOURCE)

    def chat(endpoint, messages, **kwargs):
        response = original(endpoint, messages, **kwargs)
        role = _HEADINGS.get(messages[0]["content"].splitlines()[0].removeprefix("# "))
        if role in {"tree-builder", "tree-auditor"}:
            data = decode_input_message(messages[1]["content"])
            assert data["input_files"]["problem.md"] == problem
            assert data["input_files"][workflow.SOURCE] == source
            observed.append((role, data["revision_report"]))
            if role == "tree-auditor" and sum(item[0] == role for item in observed) == 1:
                payload = _function_payload(response)
                payload["result"].update(status="needs_revision", report=suggestion)
                response = _function_response(payload)
        return response

    engine.chat = chat
    assert engine.run()["verdict"] == "correct"
    assert [role for role, _ in observed] == ["tree-builder", "tree-auditor"] * 2
    assert suggestion in observed[2][1]
    assert observed[3][1] == ""
    assert engine.store.read("problem.md") == problem
    assert engine.store.read(workflow.SOURCE) == source
    for record_path in (tmp_path / "faithsieve-work/checkpoints").glob("role-*.json"):
        request = json.loads(record_path.read_text())["request"]
        if request["role"] in {"tree-builder", "tree-auditor"}:
            assert request["files"][workflow.SOURCE] == source
            assert decode_input_message(request["messages"][1]["content"])["input_files"][workflow.SOURCE] == source
            assert "不是权威原文" in request["prompt"] or "生成者有责任拒绝" in request["prompt"]


@pytest.mark.parametrize("role", ["decomposer", "decomposition-auditor", "tree-builder", "tree-auditor"])
def test_source_and_revision_authority_rules_match_workflow_and_skill(role):
    body = (ROOT / "backend/oj_modules/faithsieve/prompts" / f"{role}.md").read_text()
    mirrored = (ROOT / "skills/faithsieve/references/agents" / f"{role}.md").read_text()
    assert body == mirrored
    assert "来源职责必须分开" in body
    assert "problem.md" in body and "faithsieve-work/source/submission.md" in body
    assert "原样引文" in body
    assert "审计意见" in body or "审计建议" in body
    assert "错误建议必须拒绝" in body or "生成者有责任拒绝" in body
    assert "原文的替代来源" in body or "不得覆盖原文" in body or "代替本次独立核对" in body


def test_consistency_reaudit_does_not_receive_its_own_previous_conclusion(tmp_path):
    run = ScriptedRun(tmp_path)
    run.consistency_revisions = 1
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "correct"
    assert run.roles.count("final-synthesizer") == 2
    assert run.roles.count("consistency-auditor") == 2


def test_focus_is_earliest_over_threshold_and_window_has_six_preceding_edges(tmp_path):
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path)
    engine.edges = [f"E{index}" for index in range(1, 12)]
    units = [{"edge_id": edge, "suspicion": 0.7 if edge == "E9" else 0.9 if edge == "E10" else 0.1, "uncertain": False, "reason": "原稿一致"} for edge in engine.edges]
    output = workflow.RoleOutput({"status": "ok", "focus_unit": "E9", "report": "最早风险"}, {"units": units}, {})
    assert engine._scan_window(output) == [f"E{index}" for index in range(3, 10)]
    output.result["focus_unit"] = "E10"
    with pytest.raises(FaithSieveProtocolError, match="最早"):
        engine._scan_window(output)


def test_numeric_refutation_requires_observed_actual_execution(tmp_path):
    run = ScriptedRun(tmp_path, suspicious=True)
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "incorrect"
    assert run.tool_roles == ["numeric-evaluator"]
    assert run.roles.count("prefix-auditor") == 1
    assert run.roles.count("evidence-mapper") == 2
    verification = json.loads((tmp_path / "faithsieve-work/formal/E1-O1-verification.json").read_text())
    assert verification["tool_verified"] is True
    assert verification["status"] == "refuted"


def test_model_claim_without_actual_numeric_execution_cannot_refute(tmp_path):
    run = ScriptedRun(tmp_path, suspicious=True, numeric_verified=False)
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "inconclusive"
    assert "没有忠实检查对象" in result["comment"]
    assert "scoring" not in run.roles


def test_unpassed_new_fact_blocks_dependent_goal_obligation(tmp_path):
    run = ScriptedRun(tmp_path, suspicious=True)
    run.two_obligations = True
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "incorrect"
    assert run.roles.count("check-object-generator") == 1
    verification = json.loads((tmp_path / "faithsieve-work/formal/E1-O2-verification.json").read_text())
    assert verification["status"] == "inconclusive"
    assert "前置义务未通过" in verification["report"]


def test_lean_semantic_drift_requires_reformalization_recompile_and_independent_audit(tmp_path):
    run = ScriptedRun(tmp_path, suspicious=True, route="lean")
    run.semantic_revisions = 1
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "correct"
    assert run.tool_roles == ["statement-formalizer", "statement-formalizer", "proof-searcher"]
    assert run.roles.count("semantic-checker") == 2
    assert len(run.compiled) == 3
    assert run.compiled[-1].endswith("original-proof.lean")


def test_lean_revision_uses_a_separate_readonly_draft_and_keeps_audited_statement_frozen(tmp_path):
    class RevisingRun(ScriptedRun):
        def __init__(self, root):
            super().__init__(root, suspicious=True, route="lean")
            self.semantic_revisions = 1
            self.formalizer_inputs = []
            self.searcher_inputs = None

        def run_role(self, role, prompt, files, **kwargs):
            if role == "statement-formalizer":
                self.formalizer_inputs.append(dict(files))
            elif role == "proof-searcher":
                self.searcher_inputs = dict(files)
            output = super().run_role(role, prompt, files, **kwargs)
            if role == "statement-formalizer" and len(self.formalizer_inputs) == 2:
                artifact = output["result"]["artifact"]
                output["artifacts"][artifact] = output["artifacts"][artifact].replace(":= True", ":= True ∧ True")
            return output

    run = RevisingRun(tmp_path)
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "correct"
    statement = "faithsieve-work/formal/E1-O1-original-statement.lean"
    previous = "faithsieve-work/formal/E1-O1-original-previous-statement.lean"
    first, revised = run.formalizer_inputs
    assert statement not in first and previous not in first
    assert statement not in revised and ":= True\n" in revised[previous]
    assert ":= True ∧ True" in run.searcher_inputs[statement]
    assert previous not in run.searcher_inputs


@pytest.mark.parametrize("attribute", ["tamper_proof", "proof_compile_failure"])
def test_lean_statement_tampering_or_compile_failure_is_never_student_error(tmp_path, attribute):
    run = ScriptedRun(tmp_path, suspicious=True, route="lean", verdict="incorrect")
    setattr(run, attribute, True)
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "inconclusive"
    assert "scoring" not in run.roles


@pytest.mark.parametrize("placeholder", ["Lean.sorryAx", "Lean.mkSorry", ".axiomDecl", "ADMIT"])
def test_lean_placeholders_and_axiom_metaprogramming_are_rejected(tmp_path, placeholder):
    run = ScriptedRun(tmp_path, suspicious=True, route="lean", verdict="incorrect")
    run.unsafe_proof = placeholder
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "inconclusive"
    assert not any(path.endswith("proof.lean") for path in run.compiled)


def test_lean_proof_doccomments_and_literal_words_keep_fixed_statement_and_require_compile(tmp_path):
    class DocumentedRun(ScriptedRun):
        def run_role(self, role, prompt, files, **kwargs):
            output = super().run_role(role, prompt, files, **kwargs)
            if role == 'proof-searcher':
                artifact = output['result']['artifact']
                output['artifacts'][artifact] = output['artifacts'][artifact].replace(
                    '\ntheorem FaithSieveProof',
                    '\n/-- 证明说明；/- 嵌套说明含 sorry/axiom -/ -/\n-- 不添加 admit\ntheorem FaithSieveProof',
                ).replace(':= by trivial', ':= by\n  let note := "sorry -- /- axiom"\n  trivial')
            return output

    run = DocumentedRun(tmp_path, suspicious=True, route='lean')
    assert seeded_workflow(tmp_path, run).run()['verdict'] == 'correct'
    assert any(path.endswith('original-proof.lean') for path in run.compiled)


def test_score_keeps_original_rubric_without_invented_verdict_score_ranges(tmp_path):
    run = ScriptedRun(tmp_path, suspicious=True)
    run.grade_score = 4
    assert seeded_workflow(tmp_path, run).run()["score"] == 4


@pytest.mark.parametrize(("suspicious", "score"), [(True, 5), (False, 3)])
def test_score_cannot_contradict_original_definition_of_a_correct_sufficient_proof(tmp_path, suspicious, score):
    run = ScriptedRun(tmp_path, suspicious=suspicious)
    run.grade_score = score
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "inconclusive"
    assert "原量表" in result["comment"]


def test_artifact_transport_cannot_overwrite_an_input_or_escape_workspace(tmp_path):
    store = ArtifactStore(tmp_path)
    store.write("problem.md", "原题面")
    for path in ["../problem.md", "/tmp/problem.md", "faithsieve-work/../problem.md", "faithsieve-work/evil.py"]:
        with pytest.raises(FaithSieveProtocolError):
            store.write(path, "非法内容")
    run = ScriptedRun(tmp_path)
    original_chat = run.chat

    def malicious_chat(endpoint, messages, **kwargs):
        response = original_chat(endpoint, messages, **kwargs)
        payload = _function_payload(response)
        if messages[0]["content"].startswith("# Decomposer"):
            payload["artifacts"]["problem.md"] = "修改题面"
        return _function_response(payload)

    engine = seeded_workflow(tmp_path, run)
    engine.chat = malicious_chat
    assert engine.run()["verdict"] == "inconclusive"
    assert engine.store.read("problem.md") == "证明题，原条件、定义及目标。"


def test_prefix_auditor_rechecks_a_previously_reviewed_uncertain_edge_once(tmp_path, monkeypatch):
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path)
    engine.edges = ["E1", "E2", "E3"]
    engine.checked_edges.update(engine.edges)
    calls = []
    monkeypatch.setattr(engine, "_invoke", lambda *_args, **_kwargs: workflow.RoleOutput(
        {"status": "ok", "candidate_units": ["E2"]}, {}, {},
    ))
    monkeypatch.setattr(engine, "_check_window", lambda window, **kwargs: calls.append((window, kwargs)))
    monkeypatch.setattr(engine, "_map_evidence", lambda: ("E3", ["E2"]))
    engine._prefix_check("E3", ["E2"])
    engine._prefix_check("E3", ["E2"])
    assert calls == [(["E1", "E2"], {"force_units": {"E2"}})]


def test_prefix_recheck_reuses_unchanged_passed_obligation_and_refreshes_uncertain_outputs(tmp_path, monkeypatch):
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path)
    engine.edges = ["E1"]
    engine.checked_edges.add("E1")
    engine.edge_contexts["E1"] = {"edge": tree_payload()["edges"][0],
                                  "parent_state": tree_payload()["nodes"][0], "child_state": tree_payload()["nodes"][1]}
    engine.edge_obligations["E1"] = ["E1-O1", "E1-O2"]
    engine.verification = {"E1-O1": {"status": "passed"}, "E1-O2": {"status": "inconclusive"}}
    engine.store.write("faithsieve-work/obligations/E1/E1-O1.md", "第一项忠实义务")
    engine.store.write("faithsieve-work/obligations/E1/E1-O2.md", "第二项忠实义务")
    stale = "faithsieve-work/formal/E1-O2-original-proof.lean"
    engine.store.write(stale, "旧的失败搜索结果")
    monkeypatch.setattr(engine, "_window_files", lambda window: {})

    def invoke(role, **kwargs):
        if role == "local-reviewer":
            path = "faithsieve-work/review/E1.md"
            engine.store.write(path, "review_outcome: uncertain")
            return workflow.RoleOutput({"status": "ok", "artifact": path}, {"review_outcome": "uncertain"}, {})
        assert role == "obligation-builder"
        path = "faithsieve-work/obligations/E1/index.md"
        obligations = [
            {"id": "E1-O1", "path": "faithsieve-work/obligations/E1/E1-O1.md", "depends_on": []},
            {"id": "E1-O2", "path": "faithsieve-work/obligations/E1/E1-O2.md", "depends_on": ["E1-O1"]},
        ]
        engine.store.write(path, "\n".join(item["path"] for item in obligations))
        return workflow.RoleOutput({"status": "ok", "artifact": path}, {"obligations": obligations}, {})

    monkeypatch.setattr(engine, "_invoke", invoke)
    verified = []
    monkeypatch.setattr(engine, "_verify_obligation", lambda obligation: verified.append(obligation["id"]))
    engine._check_window(["E1"], force_units={"E1"})
    assert verified == ["E1-O2"]
    assert engine.verification["E1-O1"]["status"] == "passed"
    assert not engine.store.path(stale).exists()


@pytest.mark.parametrize("status", [None, "inconclusive"])
def test_uncertain_or_untrusted_pdf_extraction_stops_before_grading(tmp_path, status):
    class Agent:
        def extract_submission(self, pdf, *, problem_text, invocation_key, timeout_seconds):
            assert pdf.startswith(b"%PDF-")
            assert problem_text == "题面上下文"
            assert invocation_key == "source-extraction"
            assert timeout_seconds == workflow.SOURCE_TIMEOUT_SECONDS
            return {"status": status, "text": "第1页：[无法辨认]", "report": "原图公式无法忠实确认"}

    result = workflow._run_dependency_workflow(
        problem_text="题面上下文", submission_pdf=b"%PDF-test", endpoint=None,
        verification_agent=Agent(), workspace=tmp_path,
    )
    assert result["verdict"] == "inconclusive"
    assert result["score"] == 0
    assert "原稿无法忠实确认" in result["comment"]
    assert not (tmp_path / "faithsieve-work/results/decomposer.json").exists()
    assert json.loads((tmp_path / "faithsieve-work/source/extraction.json").read_text())["status"] == status


class Pending(Exception):
    """模拟子 Judge 未完成；不得被工作流变成 inconclusive。"""


class PendingRun(ScriptedRun):
    def __init__(self, root, **kwargs):
        super().__init__(root, **kwargs)
        self.pending_keys = set()
        self.dispatched_keys = []
        self.polls = []
        self.source_polls = 0
        self.pending_source = False

    def run_role(self, *args, invocation_key, **kwargs):
        self.polls.append(invocation_key)
        if invocation_key not in self.pending_keys:
            self.pending_keys.add(invocation_key)
            self.dispatched_keys.append(invocation_key)
            raise Pending(invocation_key)
        return super().run_role(*args, invocation_key=invocation_key, **kwargs)

    def extract_submission(self, pdf, *, problem_text, invocation_key, timeout_seconds):
        assert invocation_key == "source-extraction"
        assert timeout_seconds == workflow.SOURCE_TIMEOUT_SECONDS
        self.source_polls += 1
        if self.pending_source and self.source_polls == 1:
            raise Pending(invocation_key)
        return {"status": "ok", "text": "第1页：学生证明原稿。", "report": "逐页忠实核对", "execution": {"session_id": "judge-source"}}


def test_pending_numeric_releases_caller_and_resumes_without_repeating_text_requests(tmp_path):
    run = PendingRun(tmp_path, suspicious=True)
    engine = seeded_workflow(tmp_path, run)
    with pytest.raises(Pending):
        engine.run()
    initial_roles = list(run.roles)
    assert initial_roles[-1] == "check-object-generator"
    assert len(initial_roles) == 8
    resumed = workflow.FaithSieveWorkflow(endpoint=object(), verification_agent=run, workspace=tmp_path, chat=run.chat)
    result = resumed.run()
    assert result["verdict"] == "incorrect"
    assert run.roles[:8] == initial_roles
    assert run.roles.count("decomposer") == 1
    assert run.roles.count("check-object-generator") == 1
    assert len(run.dispatched_keys) == 1
    assert run.polls == [run.dispatched_keys[0], run.dispatched_keys[0]]


def test_reentry_preserves_auditor_revision_and_lean_semantic_revision_order(tmp_path):
    run = PendingRun(tmp_path, suspicious=True, route="lean")
    run.audit_revisions = 1
    run.semantic_revisions = 1
    result = None
    for _ in range(5):
        engine = seeded_workflow(tmp_path, run)
        try:
            result = engine.run()
            break
        except Pending:
            pass
    assert result and result["verdict"] == "correct"
    assert run.roles.count("decomposer") == 2
    assert run.roles.count("decomposition-auditor") == 2
    assert run.roles.count("semantic-checker") == 2
    assert run.tool_roles == ["statement-formalizer", "statement-formalizer", "proof-searcher"]
    assert len(run.dispatched_keys) == 3
    assert len(run.compiled) == 3


def test_resume_after_first_lean_obligation_restores_past_inputs_before_next_pending_obligation(tmp_path):
    class TwoLeanRun(ScriptedRun):
        def __init__(self, root):
            super().__init__(root, suspicious=True, route="lean")
            self.two_obligations = True
            self.pending_once = False
            self.tool_requests = []

        def chat(self, endpoint, messages, **kwargs):
            response = super().chat(endpoint, messages, **kwargs)
            system = messages[0]["content"]
            if system.startswith(("# Check-object generator", "# Semantic checker")) and "E1-O2" in system:
                response = _function_response(response.tool_calls[0].arguments.replace("E1-O1", "E1-O2"))
            return response

        def run_role(self, role, prompt, files, expected_result_path, invocation_key, **kwargs):
            self.tool_requests.append((role, expected_result_path, invocation_key))
            if "E1-O2" in expected_result_path and role == "statement-formalizer" and not self.pending_once:
                self.pending_once = True
                raise Pending(invocation_key)
            second = "E1-O2" in expected_result_path
            normalized_files = {path.replace("E1-O2", "E1-O1"): value.replace("E1-O2", "E1-O1") for path, value in files.items()} if second else files
            payload = super().run_role(role, prompt, normalized_files, expected_result_path.replace("E1-O2", "E1-O1"), invocation_key=invocation_key, **kwargs)
            return json.loads(json.dumps(payload, ensure_ascii=False).replace("E1-O1", "E1-O2")) if second else payload

    run = TwoLeanRun(tmp_path)
    with pytest.raises(Pending):
        seeded_workflow(tmp_path, run).run()
    completed_roles = list(run.roles)
    assert "proof-searcher" in run.tool_roles
    assert json.loads((tmp_path / "faithsieve-work/formal/E1-O1-verification.json").read_text())["status"] == "passed"
    # 后续义务的旧检查对象和前一义务的最终 statement/proof 此时均在磁盘。
    assert (tmp_path / "faithsieve-work/formal/E1-O2-check.md").exists()
    resumed = workflow.FaithSieveWorkflow(endpoint=object(), verification_agent=run, workspace=tmp_path, chat=run.chat)
    assert resumed.run()["verdict"] == "correct"
    assert run.roles[:len(completed_roles)] == completed_roles
    assert run.roles.count("decomposer") == 1
    assert run.roles.count("check-object-generator") == 2
    assert run.tool_roles == ["statement-formalizer", "proof-searcher", "statement-formalizer", "proof-searcher"]
    assert len(run.compiled) == 4


def test_pending_prefix_revalidation_replays_previous_evidence_without_repeating_reviews(tmp_path):
    class PrefixRun(ScriptedRun):
        def __init__(self, root):
            super().__init__(root, suspicious=True)
            self.numeric_calls = []
            self.first_numeric_key = None
            self.pending_key = None

        def chat(self, endpoint, messages, **kwargs):
            response = super().chat(endpoint, messages, **kwargs)
            system = messages[0]["content"]
            if system.startswith("# FaithSieve 评分"):
                return response
            role = _HEADINGS[system.splitlines()[0].removeprefix("# ")]
            payload = _function_payload(response)
            if role == "decomposer":
                payload["artifacts"][workflow.STEPS] += "\n\n## S2\n原稿第1页第二段：2=3。唯一动作等价改写，分支root。"
            elif role == "tree-builder":
                payload["artifacts"][workflow.TREE] = json.dumps(tree_payload(2), ensure_ascii=False)
            elif role == "suspicion-scanner":
                payload["result"]["focus_unit"] = "E2"
                payload["artifacts"][workflow.SCAN] = "| E1 | 0.5 | 不确定 |\n| E2 | 0.8 | 可疑 |"
                payload["control"]["units"] = [
                    {"edge_id": "E1", "suspicion": 0.5, "uncertain": True, "reason": "需要完整核对"},
                    {"edge_id": "E2", "suspicion": 0.8, "uncertain": True, "reason": "等价关系可疑"},
                ]
            elif role == "evidence-mapper":
                files = decode_input_message(messages[1]["content"])["input_files"]
                states = {edge: json.loads(files[f"faithsieve-work/formal/{edge}-O1-verification.json"])["status"] for edge in ("E1", "E2")}
                payload["control"] = {"units": [{"edge_id": edge, "status": states[edge]} for edge in states], "provisional_error_unit": "E2", "prefix_units": ["E1"] if states["E1"] == "inconclusive" else []}
            elif role == "prefix-auditor":
                payload["result"]["candidate_units"] = ["E1"]
            elif role in {"local-reviewer", "obligation-builder", "check-object-generator"}:
                edge = "E2" if (role == "check-object-generator" and "`E2-O1`" in system) or (role != "check-object-generator" and "`E2`" in system) else "E1"
                if edge == "E2":
                    payload = json.loads(json.dumps(payload, ensure_ascii=False).replace("E1", "E2"))
            response = _function_response(payload)
            return response

        def run_role(self, role, prompt, files, expected_result_path, invocation_key, **kwargs):
            self.numeric_calls.append(invocation_key)
            edge = "E1" if "E1-O1" in expected_result_path else "E2"
            if edge == "E1":
                if self.first_numeric_key is None:
                    self.first_numeric_key = invocation_key
                elif self.pending_key is None:
                    self.pending_key = invocation_key
                    raise Pending(invocation_key)
                status = "inconclusive" if invocation_key == self.first_numeric_key else "passed"
            else:
                status = "refuted"
            artifact = f"faithsieve-work/formal/{edge}-O1-numeric.md"
            payload = envelope(artifact, status=status, report="忠实精确符号核验")
            payload["execution"] = {"verified": status != "inconclusive", "exit_code": 0}
            return payload

    run = PrefixRun(tmp_path)
    with pytest.raises(Pending):
        seeded_workflow(tmp_path, run).run()
    roles = list(run.roles)
    assert run.roles.count("local-reviewer") == 3
    assert run.roles.count("prefix-auditor") == 1
    resumed = workflow.FaithSieveWorkflow(endpoint=object(), verification_agent=run, workspace=tmp_path, chat=run.chat)
    assert resumed.run()["verdict"] == "incorrect"
    assert run.roles[:len(roles)] == roles
    assert run.roles.count("local-reviewer") == 3
    assert run.roles.count("prefix-auditor") == 1
    assert len(run.numeric_calls) == 4
    assert run.numeric_calls[-2:] == [run.pending_key, run.pending_key]


def test_finished_reentry_reuses_score_and_hides_future_artifacts_in_cached_inputs(tmp_path):
    run = ScriptedRun(tmp_path, suspicious=True)
    run.consistency_revisions = 1
    engine = seeded_workflow(tmp_path, run)
    expected = engine.run()
    roles, tools = list(run.roles), list(run.tool_roles)
    assert engine.run() == expected
    assert run.roles == roles
    assert run.tool_roles == tools
    assert run.roles.count("scoring") == 1
    # 使用新对象重放也必须得到同一结果，而非把末尾审计输入污染前面阶段。
    resumed = workflow.FaithSieveWorkflow(endpoint=object(), verification_agent=run, workspace=tmp_path, chat=run.chat)
    assert resumed.run() == expected
    assert run.roles == roles


def test_source_pending_and_completed_extraction_are_durable_across_wrapper_reentry(tmp_path, monkeypatch):
    run = PendingRun(tmp_path, suspicious=True)
    run.pending_source = True
    monkeypatch.setattr(workflow, "call_chat", run.chat)
    stage_calls = []
    def coordinator(_self):
        stage_calls.append(True)
        if len(stage_calls) == 1:
            raise Pending("coordinator")
        return {"verdict": "incorrect", "score": 2, "comment": "来源读取已完成，后续编排单独重入。"}
    monkeypatch.setattr(DependencyWorkflow, "run", coordinator)
    options = {"problem_text": "证明题，原条件、定义及目标。", "submission_pdf": b"%PDF-source", "endpoint": {"id": 7, "category": "omni", "protocol": "openai", "base_url": "https://mock.invalid/v1", "model": "chosen-model", "api_key": "private-key-never-checkpoint"}, "verification_agent": run, "workspace": tmp_path}
    with pytest.raises(Pending, match="source-extraction"):
        workflow._run_dependency_workflow(**options)
    assert run.roles == []
    source_path = tmp_path / "faithsieve-work/checkpoints/source-extraction.json"
    assert json.loads(source_path.read_text())["request"]["timeout_seconds"] == workflow.SOURCE_TIMEOUT_SECONDS == 1200
    with pytest.raises(Pending):
        workflow._run_dependency_workflow(**options)
    assert run.source_polls == 2
    result = workflow._run_dependency_workflow(**options)
    assert result["verdict"] == "incorrect"
    assert run.source_polls == 2
    assert run.roles == [] and len(stage_calls) == 2
    saved = "\n".join(file.read_text() for file in (tmp_path / "faithsieve-work/checkpoints").glob("*.json"))
    assert "private-key-never-checkpoint" not in saved
    with pytest.raises(FaithSieveProtocolError, match="原 PDF"):
        workflow._run_dependency_workflow(**{**options, "submission_pdf": b"%PDF-changed"})


def test_old_completed_source_replays_without_reading_images_or_rewriting_checkpoint(tmp_path, monkeypatch):
    request = {"problem_text": "完整题面", "pdf_path": "submission.pdf"}
    store = workflow.CheckpointStore(tmp_path)
    store.put("source-extraction", request, state="completed", response={
        "status": "ok", "text": "## 第 1 页\n\n原学生证明", "report": "已看图核对",
    })
    path = tmp_path / "faithsieve-work/checkpoints/source-extraction.json"
    original = path.read_bytes()
    class Agent:
        def extract_submission(self, *_args, **_kwargs):
            pytest.fail("已完成的旧原稿不能重复读图或派发 Judge")
    expected = {"verdict": "correct", "score": 5, "comment": "证明充分。"}
    monkeypatch.setattr(DependencyWorkflow, "run", lambda _self: expected)
    result = workflow.run_faithsieve_workflow(
        problem_text="完整题面", submission_pdf=b"%PDF-original", endpoint=None,
        verification_agent=Agent(), workspace=tmp_path,
    )
    assert result == expected and path.read_bytes() == original


@pytest.mark.parametrize("state", ["pending", "completed", "protocol_error"])
def test_outer_source_still_rejects_problem_change_before_native_call(tmp_path, state):
    request = {"problem_text": "原题面", "pdf_path": "submission.pdf",
               "timeout_seconds": workflow.SOURCE_TIMEOUT_SECONDS}
    store = workflow.CheckpointStore(tmp_path)
    store.put("source-extraction", request, state=state, response={
        "status": "ok", "text": "## 第 1 页\n\n原学生证明", "report": "已看图核对",
    } if state == "completed" else None)
    path = tmp_path / "faithsieve-work/checkpoints/source-extraction.json"
    original = path.read_bytes()
    class Agent:
        def extract_submission(self, *_args, **_kwargs):
            pytest.fail("题面绑定不一致时不能读取图片或派发 Judge")
    with pytest.raises(FaithSieveProtocolError, match="重入请求"):
        workflow.run_faithsieve_workflow(
            problem_text="不同题面", submission_pdf=b"%PDF-original", endpoint=None,
            verification_agent=Agent(), workspace=tmp_path,
        )
    assert path.read_bytes() == original


@pytest.mark.parametrize("state", ["pending", "protocol_error"])
def test_unfinished_legacy_source_cannot_switch_frozen_budget_and_dispatch_again(tmp_path, state):
    request = {"problem_text": "完整题面", "pdf_path": "submission.pdf"}
    store = workflow.CheckpointStore(tmp_path)
    store.put("source-extraction", request, state=state)
    path = tmp_path / "faithsieve-work/checkpoints/source-extraction.json"
    original = path.read_bytes()
    class Agent:
        def extract_submission(self, *_args, **_kwargs):
            pytest.fail("旧未完成请求不能换预算重新派发 Judge")
    with pytest.raises(FaithSieveProtocolError, match="重入请求"):
        workflow.run_faithsieve_workflow(
            problem_text="完整题面", submission_pdf=b"%PDF-original", endpoint=None,
            verification_agent=Agent(), workspace=tmp_path,
        )
    assert path.read_bytes() == original


def test_source_budget_type_is_checked_even_when_number_compares_equal(tmp_path):
    request = {"problem_text": "完整题面", "pdf_path": "submission.pdf", "timeout_seconds": 1200.0,
               "proof_graph_version": 2}
    store = workflow.CheckpointStore(tmp_path)
    store.put("source-extraction", request, state="pending")
    class Agent:
        def extract_submission(self, *_args, **_kwargs):
            pytest.fail("非法冻结预算不能派发 Judge")
    with pytest.raises(FaithSieveProtocolError, match="字段或类型不一致"):
        workflow.run_faithsieve_workflow(
            problem_text="完整题面", submission_pdf=b"%PDF-original", endpoint=None,
            verification_agent=Agent(), workspace=tmp_path,
        )


def test_checkpoint_compares_full_input_and_rejects_changed_problem(tmp_path):
    run = ScriptedRun(tmp_path)
    engine = seeded_workflow(tmp_path, run)
    assert engine.run()["verdict"] == "correct"
    roles = list(run.roles)
    engine.store.write("problem.md", "改变后的题面")
    result = engine.run()
    assert result["verdict"] == "inconclusive"
    assert "完整输入不一致" in result["comment"]
    assert run.roles == roles


def test_invalid_protocol_attempt_is_not_requested_again_after_pending_resume(tmp_path):
    run = PendingRun(tmp_path, suspicious=True)
    original = run.chat
    requested = []

    def chat(endpoint, messages, **kwargs):
        if messages[0]["content"].startswith("# Decomposer"):
            requested.append("decomposer")
            if len(requested) == 1:
                return _function_response("不是 JSON")
        return original(endpoint, messages, **kwargs)

    engine = seeded_workflow(tmp_path, run)
    engine.chat = chat
    with pytest.raises(Pending):
        engine.run()
    assert requested == ["decomposer", "decomposer"]
    resumed = workflow.FaithSieveWorkflow(endpoint=object(), verification_agent=run, workspace=tmp_path, chat=chat)
    assert resumed.run()["verdict"] == "incorrect"
    assert requested == ["decomposer", "decomposer"]
    records = list((tmp_path / "faithsieve-work/checkpoints").glob("role-000001-*.json"))
    assert {json.loads(file.read_text())["state"] for file in records} == {"protocol_error", "completed"}


def test_checkpoint_is_published_atomically_and_keeps_explicit_request(tmp_path):
    cache = CheckpointStore(tmp_path)
    request = {"files": {"problem.md": "题面原文"}, "parameters": {"edge_id": "E1"}}
    cache.put("role-000001-attempt-1", request, state="pending")
    cache.put("role-000001-attempt-1", request, state="completed", response={"value": "完整响应"})
    assert cache.get("role-000001-attempt-1", request)["response"] == {"value": "完整响应"}
    assert not list((tmp_path / "faithsieve-work/checkpoints").glob(".checkpoint-*"))


def thinking_endpoint(*, enabled=True, thinking_format="thinking_type", protocol="anthropic"):
    return workflow.LLMEndpointSnapshot(
        id=7, category="text", protocol=protocol, base_url=f"https://llm.example.test/{protocol}",
        api_key="private-retry-secret", model="configured-model", thinking_enabled=enabled,
        thinking_format=thinking_format, max_output_tokens=64000,
    )


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize("target", ["role", "scoring"])
def test_completed_pure_llm_checkpoint_keeps_only_safe_response_summary_and_replays_unchanged(tmp_path, protocol, target):
    endpoint = thinking_endpoint(protocol=protocol, enabled=False,
                                 thinking_format="enable_thinking" if protocol == "openai" else "thinking_type")
    payload = envelope(workflow.STEPS) if target == "role" else {
        "verdict": "correct", "score": 5, "comment": "证明正确且充分。",
    }
    calls = []
    def chat(_endpoint, _messages, **options):
        calls.append(options)
        fields = {"finish_reason": "stop" if protocol == "openai" else "end_turn",
                  "usage": LLMUsage(101, 55, 156), "reasoning": "不保存的思考正文"}
        if "response_format" in options:
            return LLMChatResult(text=json.dumps(payload, ensure_ascii=False), **fields)
        return _function_response(payload, **fields)
    def execute():
        run = workflow.FaithSieveWorkflow(endpoint=endpoint, verification_agent=None, workspace=tmp_path, chat=chat)
        if target == "role":
            run._invoke("decomposer", files={})
        else:
            assert run._score("correct") == payload
        return run
    run = execute()
    key = "role-000001-attempt-1" if target == "role" else "final-scoring"
    path = run.checkpoints._path(key)
    record, before = json.loads(path.read_text()), path.read_bytes()
    assert record["state"] == "completed"
    dependencies = [] if target == "role" else [""]
    assert record["metadata"] == {"dependency_keys": dependencies, "finish_reason": "stop" if protocol == "openai" else "end_turn",
                                  "input_tokens": 101, "output_tokens": 55, "total_tokens": 156}
    assert set(record["request"]["call_options"]) == set(calls[0]) - {"timeout"}
    assert "不保存的思考正文" not in json.dumps(record) and endpoint.api_key not in json.dumps(record)
    execute()
    assert len(calls) == 1 and path.read_bytes() == before
    # 旧已完成记录没有摘要时，重放仍须只读，不从缓存正文猜测 finish 或 usage。
    record["metadata"] = {"dependency_keys": dependencies}
    path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    before = path.read_bytes()
    execute()
    assert len(calls) == 1 and path.read_bytes() == before


@pytest.mark.parametrize("target", ["role", "scoring"])
def test_successful_response_summary_redacts_finish_reason_and_ignores_vendor_extra_fields(tmp_path, target):
    payload = envelope(workflow.STEPS) if target == "role" else {
        "verdict": "correct", "score": 5, "comment": "证明正确且充分。",
    }
    finish = "stop private-retry-secret " + "x" * 200
    usage = SimpleNamespace(input_tokens=0, output_tokens=8, total_tokens=8,
                            vendor_private="不得保存的供应商字段")
    reply = _function_response(payload, finish_reason=finish, usage=usage)
    run = workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(), verification_agent=None,
                                     workspace=tmp_path, chat=lambda *_args, **_kwargs: reply)
    if target == "role":
        run._invoke("decomposer", files={})
        key = "role-000001-attempt-1"
    else:
        run._score("correct")
        key = "final-scoring"
    metadata = run.store.read_json(f"faithsieve-work/checkpoints/{key}.json")["metadata"]
    assert metadata["finish_reason"].startswith("stop <redacted> ")
    assert "<truncated:" in metadata["finish_reason"] and len(metadata["finish_reason"]) < 160
    assert "private-retry-secret" not in json.dumps(metadata)
    assert "不得保存的供应商字段" not in json.dumps(metadata)
    assert set(metadata) == {"dependency_keys", "finish_reason", "input_tokens", "output_tokens", "total_tokens"}


@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("finish,usage,expected", [
    (["length"], {"input_tokens": True, "output_tokens": -1, "total_tokens": "12"}, {}),
    (None, {"input_tokens": 0, "output_tokens": False, "total_tokens": 0}, {"input_tokens": 0, "total_tokens": 0}),
])
def test_success_summary_omits_invalid_finish_and_usage_without_rejecting_valid_artifacts(tmp_path, target, finish, usage, expected):
    payload = envelope(workflow.STEPS) if target == "role" else {
        "verdict": "correct", "score": 5, "comment": "证明正确且充分。",
    }
    reply = _function_response(payload, finish_reason=finish, usage=SimpleNamespace(**usage))
    run = workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(), verification_agent=None,
                                     workspace=tmp_path, chat=lambda *_args, **_kwargs: reply)
    if target == "role":
        run._invoke("decomposer", files={})
        key = "role-000001-attempt-1"
    else:
        run._score("correct")
        key = "final-scoring"
    record = run.store.read_json(f"faithsieve-work/checkpoints/{key}.json")
    dependencies = [] if target == "role" else [""]
    assert record["state"] == "completed" and record["metadata"] == {"dependency_keys": dependencies, **expected}


@pytest.mark.parametrize("error,summary,visible", [
    (LLMEndpointRequestError("VENDOR_BODY_SECRET", status_code=402),
     {"kind": "request", "status_code": 402}, "余额不足或需要付费（HTTP 402）"),
    (LLMEndpointResponseError("VENDOR_BODY_SECRET"),
     {"kind": "response", "status_code": None}, "响应无效"),
    (LLMEndpointValidationError("VENDOR_BODY_SECRET"),
     {"kind": "configuration", "status_code": None}, "配置无效"),
])
def test_endpoint_failure_finishes_role_without_math_result_or_reissuing_on_resume(tmp_path, error, summary, visible):
    run, failed_calls, events = ScriptedRun(tmp_path), [], []
    def chat(endpoint, messages, **options):
        if messages[0]["content"].startswith("# Tree builder"):
            failed_calls.append(options)
            raise error
        return run.chat(endpoint, messages, **options)
    engine = seeded_workflow(tmp_path, run)
    engine.chat, engine.progress = chat, events.append
    with pytest.raises(FaithSieveEndpointError, match="建立证明依赖图失败") as raised:
        engine.run()
    assert visible in str(raised.value) and "VENDOR_BODY_SECRET" not in str(raised.value)
    assert not (tmp_path / workflow.RESULT).exists()
    assert not (tmp_path / workflow.TREE).exists()
    assert not (tmp_path / "faithsieve-work/results/tree-builder.json").exists()
    record = engine.store.read_json("faithsieve-work/checkpoints/role-000003-attempt-1.json")
    assert record["state"] == "endpoint_error" and record["metadata"]["endpoint_error"] == summary
    assert "response" not in record and "VENDOR_BODY_SECRET" not in json.dumps(record)
    assert record["metadata"]["dependency_keys"] == ["role-000002-attempt-1"]
    assert events[-1]["state"] == "failed" and visible in events[-1]["message"]
    assert not (tmp_path / "faithsieve-work/checkpoints/role-000003-attempt-2.json").exists()
    before = list(run.roles)
    resumed = seeded_workflow(tmp_path, run)
    resumed.chat = chat
    with pytest.raises(FaithSieveEndpointError, match="建立证明依赖图失败"):
        resumed.run()
    assert len(failed_calls) == 1 and run.roles == before
    assert not (tmp_path / workflow.RESULT).exists()


def test_scoring_endpoint_failure_is_terminal_and_replayed_without_a_grade(tmp_path):
    run, failed_calls = ScriptedRun(tmp_path), []
    def chat(endpoint, messages, **options):
        if messages[0]["content"].startswith("# FaithSieve 评分"):
            failed_calls.append(options)
            raise LLMEndpointRequestError("VENDOR_BODY_SECRET", status_code=429)
        return run.chat(endpoint, messages, **options)
    engine = seeded_workflow(tmp_path, run)
    engine.chat = chat
    with pytest.raises(FaithSieveEndpointError, match="按原量表评分失败.*HTTP 429"):
        engine.run()
    record = engine.store.read_json("faithsieve-work/checkpoints/final-scoring.json")
    assert record["state"] == "endpoint_error"
    assert record["metadata"]["endpoint_error"] == {"kind": "request", "status_code": 429}
    assert record["metadata"]["dependency_keys"] == [engine._role_key("consistency-auditor")]
    assert not (tmp_path / workflow.RESULT).exists()
    assert "VENDOR_BODY_SECRET" not in json.dumps(record)
    before = list(run.roles)
    resumed = seeded_workflow(tmp_path, run)
    resumed.chat = chat
    with pytest.raises(FaithSieveEndpointError, match="HTTP 429"):
        resumed.run()
    assert len(failed_calls) == 1 and run.roles == before
    assert not (tmp_path / workflow.RESULT).exists()


def test_low_effort_second_protocol_attempt_endpoint_failure_does_not_add_retry(tmp_path):
    calls = []
    def chat(_endpoint, _messages, **options):
        calls.append(options)
        if len(calls) == 1:
            return SimpleNamespace(text="", finish_reason="max_tokens", tool_calls=())
        raise LLMEndpointRequestError("VENDOR_BODY_SECRET", status_code=402)
    endpoint = thinking_endpoint()
    engine = workflow.FaithSieveWorkflow(endpoint=endpoint, verification_agent=None, workspace=tmp_path, chat=chat)
    with pytest.raises(FaithSieveEndpointError, match="HTTP 402"):
        engine._invoke("tree-auditor", files={})
    second = engine.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-2.json")
    assert second["state"] == "endpoint_error"
    _assert_function_options(second["request"]["call_options"])
    assert second["request"]["call_options"] == {key: value for key, value in calls[1].items() if key != "timeout"}
    assert second["metadata"]["dependency_keys"] == ["role-000001-attempt-1"]
    assert "reasoning_effort" not in calls[0] and calls[1]["reasoning_effort"] == "low"
    resumed = workflow.FaithSieveWorkflow(endpoint=endpoint, verification_agent=None, workspace=tmp_path, chat=chat)
    with pytest.raises(FaithSieveEndpointError, match="HTTP 402"):
        resumed._invoke("tree-auditor", files={})
    assert len(calls) == 2


@pytest.mark.parametrize("summary", [
    None, [], {"kind": [], "status_code": None},
    {"kind": "request", "status_code": True}, {"kind": "request", "status_code": "402"},
    {"kind": "request", "status_code": 200}, {"kind": "response", "status_code": 402},
    {"kind": "request", "status_code": 402, "message": "VENDOR_BODY_SECRET"},
])
def test_endpoint_error_summary_rejects_unknown_or_untrusted_data(summary):
    with pytest.raises(FaithSieveProtocolError, match="摘要无效"):
        endpoint_error_message(summary)


@pytest.mark.parametrize("target", ["role", "scoring"])
@pytest.mark.parametrize("metadata", [None, [], {"endpoint_error": {"kind": "request", "status_code": "402", "message": "VENDOR_BODY_SECRET"}}])
def test_invalid_saved_endpoint_error_summary_stays_terminal_without_retry_or_math_result(tmp_path, target, metadata):
    run, failed_calls = ScriptedRun(tmp_path), []
    def chat(endpoint, messages, **options):
        heading = "# Tree builder" if target == "role" else "# FaithSieve 评分"
        if messages[0]["content"].startswith(heading):
            failed_calls.append(options)
            raise LLMEndpointRequestError("VENDOR_BODY_SECRET", status_code=402)
        return run.chat(endpoint, messages, **options)
    engine = seeded_workflow(tmp_path, run)
    engine.chat = chat
    with pytest.raises(FaithSieveEndpointError):
        engine.run()
    key = "role-000003-attempt-1" if target == "role" else "final-scoring"
    path = tmp_path / f"faithsieve-work/checkpoints/{key}.json"
    record = json.loads(path.read_text())
    record["metadata"] = metadata
    path.write_text(json.dumps(record))
    saved = path.read_bytes()
    resumed = seeded_workflow(tmp_path, run)
    resumed.chat = chat
    with pytest.raises(FaithSieveEndpointError, match="模型端点调用失败") as raised:
        resumed.run()
    assert "VENDOR_BODY_SECRET" not in str(raised.value)
    assert len(failed_calls) == 1 and path.read_bytes() == saved
    assert not (tmp_path / workflow.RESULT).exists()
    assert not (tmp_path / "faithsieve-work/checkpoints/role-000003-attempt-2.json").exists()


@pytest.mark.parametrize("finish", ["max_tokens", "length"])
@pytest.mark.parametrize("protocol", ["anthropic", "openai"])
@pytest.mark.parametrize("initial_effort", [None, "low", "medium"])
def test_empty_thinking_exhaustion_uses_only_second_protocol_retry_low_and_replays_choice(tmp_path, finish, protocol, initial_effort):
    calls = []
    def chat(_endpoint, _messages, **options):
        calls.append(options)
        if len(calls) == 1:
            return SimpleNamespace(text=" \n", reasoning="PRIVATE-THINKING", tool_calls=(), finish_reason=finish)
        payload = envelope("faithsieve-work/review/tree.md", status="needs_revision")
        return (LLMChatResult(text=json.dumps(payload)) if "response_format" in options
                else _function_response(payload))
    endpoint = thinking_endpoint(protocol=protocol,
                                 thinking_format="enable_thinking" if protocol == "openai" else "thinking_type")
    engine = workflow.FaithSieveWorkflow(endpoint=endpoint, verification_agent=None, workspace=tmp_path, chat=chat,
                                        initial_reasoning_effort=initial_effort)
    output = engine._invoke("tree-auditor", files={"problem.md": "原题面"})
    assert output.result["status"] == "needs_revision"
    first = engine.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-1.json")
    second = engine.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-2.json")
    first_options = first["request"]["call_options"]
    _assert_function_options(first_options)
    assert first_options["tool_choice"] == "auto"
    if initial_effort is None:
        assert "reasoning_effort" not in first_options
    else:
        assert first_options["reasoning_effort"] == initial_effort
    assert calls == [{"timeout": workflow.ROLE_TIMEOUT_SECONDS, **first_options},
                     {"timeout": workflow.ROLE_TIMEOUT_SECONDS, **first_options, "reasoning_effort": "low"}]
    assert first["metadata"]["reasoning_retry"] == {
        "finish_reason": finish, "empty_text": True, "tool_call_count": 0,
        "call_options": {"reasoning_effort": "low"},
    }
    assert second["request"]["call_options"] == {**first_options, "reasoning_effort": "low"}
    assert second["request"]["endpoint"]["thinking_enabled"] is True
    assert second["request"]["endpoint"]["max_output_tokens"] == 64000
    assert "private-retry-secret" not in json.dumps([first, second])
    assert "PRIVATE-THINKING" not in json.dumps([first, second])
    replay = workflow.FaithSieveWorkflow(endpoint=endpoint, verification_agent=None, workspace=tmp_path,
                                         initial_reasoning_effort=initial_effort,
                                         chat=lambda *_args, **_options: pytest.fail("完成缓存不能再次请求模型"))
    assert replay._invoke("tree-auditor", files={"problem.md": "原题面"}).result == output.result
    assert replay.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-1.json")["metadata"] == first["metadata"]


@pytest.mark.parametrize("protocol", ["anthropic", "openai"])
@pytest.mark.parametrize("initial_effort", [None, "medium"])
def test_pending_low_retry_keeps_frozen_options_when_resumed(tmp_path, protocol, initial_effort):
    initial_options = []
    def interrupted(_endpoint, _messages, **options):
        initial_options.append(options)
        if len(initial_options) == 1:
            return SimpleNamespace(text="", tool_calls=(), finish_reason="max_tokens")
        raise Pending("第二次调用尚未完成")
    endpoint = thinking_endpoint(protocol=protocol,
                                 thinking_format="enable_thinking" if protocol == "openai" else "thinking_type")
    engine = workflow.FaithSieveWorkflow(endpoint=endpoint, verification_agent=None, workspace=tmp_path, chat=interrupted,
                                        initial_reasoning_effort=initial_effort)
    with pytest.raises(Pending):
        engine._invoke("tree-auditor", files={})
    pending = engine.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-2.json")
    assert pending["state"] == "pending"
    _assert_function_options(pending["request"]["call_options"])
    assert pending["request"]["call_options"]["reasoning_effort"] == "low"
    assert pending["request"]["call_options"] == {key: value for key, value in initial_options[1].items() if key != "timeout"}
    resumed_options = []
    def completed(_endpoint, _messages, **options):
        resumed_options.append(options)
        payload = envelope("faithsieve-work/review/tree.md")
        return (LLMChatResult(text=json.dumps(payload)) if "response_format" in options
                else _function_response(payload))
    resumed = workflow.FaithSieveWorkflow(endpoint=endpoint, verification_agent=None, workspace=tmp_path, chat=completed,
                                         initial_reasoning_effort=initial_effort)
    assert resumed._invoke("tree-auditor", files={}).result["status"] == "ok"
    assert resumed_options == [{"timeout": workflow.ROLE_TIMEOUT_SECONDS, **pending["request"]["call_options"]}]
    saved = resumed.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-2.json")
    assert saved["request"] == pending["request"]


@pytest.mark.parametrize("text,finish,tool_calls,enabled,thinking_format", [
    ("不是 JSON", "end_turn", (), True, "thinking_type"),
    ('{"result":', "max_tokens", (), True, "thinking_type"),
    ("", "end_turn", (), True, "thinking_type"),
    ("", "max_tokens", ("tool-call",), True, "thinking_type"),
    ("", "max_tokens", (), False, "thinking_type"),
    ("", "max_tokens", (), True, "none"),
])
def test_other_protocol_failures_do_not_change_default_request_effort(tmp_path, text, finish, tool_calls, enabled, thinking_format):
    calls = []
    def chat(_endpoint, _messages, **options):
        calls.append(options)
        if len(calls) == 1:
            if text and not tool_calls:
                return _function_response(text, finish_reason=finish)
            return SimpleNamespace(text=text, finish_reason=finish, tool_calls=tool_calls)
        return _function_response(envelope("faithsieve-work/review/tree.md"))
    engine = workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(enabled=enabled, thinking_format=thinking_format),
                                        verification_agent=None, workspace=tmp_path, chat=chat)
    assert engine._invoke("tree-auditor", files={}).result["status"] == "ok"
    assert len(calls) == 2 and all("reasoning_effort" not in options for options in calls)
    first = engine.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-1.json")
    assert "reasoning_retry" not in first["metadata"]


@pytest.mark.parametrize("initial_effort", [None, "low", "medium"])
def test_tool_judge_protocol_retries_keep_agent_inputs_without_effort_override(tmp_path, initial_effort):
    artifact = "faithsieve-work/formal/E1-O1-numeric.md"
    calls = []
    def run_role(**options):
        calls.append(options)
        return "" if len(calls) == 1 else envelope(artifact, status="refuted")
    engine = workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(), verification_agent=SimpleNamespace(run_role=run_role),
                                        initial_reasoning_effort=initial_effort,
                                        workspace=tmp_path, chat=lambda *_args, **_options: pytest.fail("工具角色不能调用普通 LLM"))
    parameters = {"obligation_id": "E1-O1", "obligation_path": "faithsieve-work/obligations/E1/E1-O1.md",
                  "check_object_path": "faithsieve-work/formal/E1-O1-check.md", "numeric_result_path": artifact}
    assert engine._invoke("numeric-evaluator", files={}, parameters=parameters).result["status"] == "refuted"
    assert len(calls) == 2 and all("reasoning_effort" not in options for options in calls)
    second = engine.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-2.json")
    assert "call_options" not in second["request"]
    assert not {"finish_reason", "input_tokens", "output_tokens", "total_tokens"} & set(second["metadata"])


@pytest.mark.parametrize("second_text", ["", "invalid_tree"])
@pytest.mark.parametrize("initial_effort", [None, "medium"])
def test_low_retry_does_not_add_third_call_or_accept_invalid_tree(tmp_path, second_text, initial_effort):
    calls = []
    def chat(_endpoint, _messages, **options):
        calls.append(options)
        if len(calls) == 1 or second_text == "":
            return SimpleNamespace(text="", tool_calls=(), finish_reason="max_tokens")
        tree = tree_payload()
        tree["nodes"][0]["goal"] = ""
        payload = envelope(workflow.TREE)
        payload["artifacts"][workflow.TREE] = tree
        return _function_response(payload, finish_reason="end_turn")
    engine = workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(), verification_agent=None, workspace=tmp_path, chat=chat,
                                        initial_reasoning_effort=initial_effort)
    files = {workflow.STEPS: "## S1\n原稿"}
    with pytest.raises(FaithSieveProtocolError):
        engine._invoke("tree-builder", files=files)
    assert len(calls) == 2 and calls[1]["reasoning_effort"] == "low"
    assert not (tmp_path / workflow.TREE).exists()
    replay = workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(), verification_agent=None, workspace=tmp_path,
                                         initial_reasoning_effort=initial_effort,
                                         chat=lambda *_args, **_options: pytest.fail("失败缓存不能触发第三次请求"))
    with pytest.raises(FaithSieveProtocolError):
        replay._invoke("tree-builder", files=files)
    records = [json.loads(path.read_text()) for path in (tmp_path / "faithsieve-work/checkpoints").glob("*.json")]
    assert len(records) == 2 and all(record["state"] == "protocol_error" for record in records)


@pytest.mark.parametrize("corruption", ["retry_selection", "frozen_options"])
def test_reasoning_retry_reentry_rejects_invalid_selection_or_changed_request_options(tmp_path, corruption):
    calls = []
    def chat(_endpoint, _messages, **options):
        calls.append(options)
        if len(calls) == 1:
            return SimpleNamespace(text="", tool_calls=(), finish_reason="max_tokens")
        return _function_response(envelope("faithsieve-work/review/tree.md"))
    engine = workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(), verification_agent=None, workspace=tmp_path, chat=chat)
    engine._invoke("tree-auditor", files={})
    if corruption == "retry_selection":
        path = tmp_path / "faithsieve-work/checkpoints/role-000001-attempt-1.json"
        record = json.loads(path.read_text())
        record["metadata"]["reasoning_retry"]["finish_reason"] = ["max_tokens"]
    else:
        path = tmp_path / "faithsieve-work/checkpoints/role-000001-attempt-2.json"
        record = json.loads(path.read_text())
        record["request"]["call_options"]["reasoning_effort"] = "high"
    path.write_text(json.dumps(record), encoding="utf-8")
    replay = workflow.FaithSieveWorkflow(endpoint=thinking_endpoint(), verification_agent=None, workspace=tmp_path,
                                         chat=lambda *_args, **_options: pytest.fail("不一致的缓存不能触发请求"))
    with pytest.raises(FaithSieveProtocolError):
        replay._invoke("tree-auditor", files={})


def dag_snapshot(tmp_path, monkeypatch, run):
    from backend.oj_modules.faithsieve import views
    attempt = "dag-real-run"
    workspace = tmp_path / "sessions" / f"faithsieve-{attempt}" / "workspace"
    monkeypatch.setattr(views.workspace_store, "AGENT_WORKSPACE_ROOT", tmp_path)
    run.root = workspace
    result = seeded_workflow(workspace, run).run()
    snapshot = views.workflow_snapshot({"attempt_id": attempt, "session_id": f"faithsieve-{attempt}", "status": "running"})
    return result, snapshot


def test_real_lean_run_dag_preserves_compile_and_semantic_gates(tmp_path, monkeypatch):
    run = ScriptedRun(tmp_path, suspicious=True, route="lean")
    result, snapshot = dag_snapshot(tmp_path, monkeypatch, run)
    assert result["verdict"] == "correct"
    stages = snapshot["stages"]
    by_role = {stage["role"]: stage["key"] for stage in stages}
    statement_compile = next(stage["key"] for stage in stages if stage["role"] == "lean-compiler" and stage["parameters"]["target"] == "statement")
    proof_compile = next(stage["key"] for stage in stages if stage["role"] == "lean-compiler" and stage["parameters"]["target"] == "proof")
    edges = {(edge["source"], edge["target"]) for edge in snapshot["edges"]}
    assert (by_role["statement-formalizer"], statement_compile) in edges
    assert (statement_compile, by_role["semantic-checker"]) in edges
    assert (by_role["semantic-checker"], by_role["proof-searcher"]) in edges
    assert (by_role["proof-searcher"], proof_compile) in edges
    assert (proof_compile, by_role["evidence-mapper"]) in edges
    assert (by_role["decomposition-auditor"], by_role["tree-builder"]) in edges
    assert (by_role["tree-auditor"], by_role["suspicion-scanner"]) in edges
    assert (by_role["consistency-auditor"], by_role["scoring"]) in edges


def test_real_semantic_revision_dag_expands_each_attempt_without_cycle(tmp_path, monkeypatch):
    run = ScriptedRun(tmp_path, suspicious=True, route="lean")
    run.semantic_revisions = 1
    result, snapshot = dag_snapshot(tmp_path, monkeypatch, run)
    assert result["verdict"] == "correct"
    formals = [stage["key"] for stage in snapshot["stages"] if stage["role"] == "statement-formalizer"]
    audit = next(stage["key"] for stage in snapshot["stages"] if stage["role"] == "semantic-checker" and stage["status"] == "needs_revision")
    edges = {(edge["source"], edge["target"]) for edge in snapshot["edges"]}
    assert len(formals) == 2 and (audit, formals[1]) in edges
    positions = {stage["key"]: index for index, stage in enumerate(snapshot["stages"])}
    assert all(positions[source] < positions[target] for source, target in edges)


def test_real_failed_lean_branches_dag_requires_prior_failure_for_fallback(tmp_path, monkeypatch):
    run = ScriptedRun(tmp_path, suspicious=True, route="lean")
    run.proof_compile_failure = True
    original_chat = run.chat
    def branch_chat(endpoint, messages, **kwargs):
        response = original_chat(endpoint, messages, **kwargs)
        if messages[0]["content"].splitlines()[0] == "# Semantic checker":
            files = decode_input_message(messages[1]["content"])["input_files"]
            branch = next((candidate for candidate in ("negation", "counterexample") if f"faithsieve-work/formal/E1-O1-{candidate}-statement.lean" in files), "original")
            payload = _function_payload(response)
            previous = payload["result"]["artifact"]
            artifact = f"faithsieve-work/formal/E1-O1-{branch}-semantics.md"
            payload["result"]["artifact"] = artifact
            payload["artifacts"][artifact] = payload["artifacts"].pop(previous)
            response = _function_response(payload)
        return response
    run.chat = branch_chat
    result, snapshot = dag_snapshot(tmp_path, monkeypatch, run)
    assert result["verdict"] == "inconclusive"
    proof_compiles = {stage["parameters"]["branch"]: stage["key"] for stage in snapshot["stages"] if stage["role"] == "lean-compiler" and stage["parameters"]["target"] == "proof"}
    formals = {stage["parameters"]["branch"]: stage["key"] for stage in snapshot["stages"] if stage["role"] == "statement-formalizer"}
    edges = {(edge["source"], edge["target"]) for edge in snapshot["edges"]}
    assert (proof_compiles["original"], formals["negation"]) in edges
    assert (proof_compiles["negation"], formals["counterexample"]) in edges
    mapper = next(stage["key"] for stage in snapshot["stages"] if stage["role"] == "evidence-mapper")
    assert (proof_compiles["counterexample"], mapper) in edges
