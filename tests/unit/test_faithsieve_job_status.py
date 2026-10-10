"""任务完成状态与数学未知状态分别控制真实后续阶段。"""

import json

import pytest

from backend.oj_modules.faithsieve import prompts, workflow
from tests.unit.test_faithsieve_workflow import (
    ROOT, ScriptedRun, _function_payload, _function_response, seeded_workflow, tree_payload,
)


class UnknownEvidenceRun(ScriptedRun):
    """完整映射三条未知边；数值自报未获执行证据仍不得 refuted。"""

    def __init__(self, root):
        super().__init__(root, suspicious=True, numeric_verified=False, verdict="inconclusive")
        self.grade_score = 2
        self.mapper_status = "ok"
        self.consistency_status = "ok"
        self.claim_refuted = False

    def chat(self, endpoint, messages, **options):
        response = super().chat(endpoint, messages, **options)
        role = self.roles[-1]
        if role == "scoring":
            return response
        payload = _function_payload(response)
        artifact = payload["result"]["artifact"]
        if role == "decomposer":
            payload["artifacts"][artifact] += "\n\n## S2\n原稿第 1 页：2=3。\n\n## S3\n原稿第 1 页：3=4。"
        elif role == "tree-builder":
            payload["artifacts"][artifact] = tree_payload(3)
        elif role == "suspicion-scanner":
            payload["control"]["units"] = [
                {"edge_id": f"E{index}", "suspicion": 0.8 if index == 1 else 0.1,
                 "uncertain": True, "reason": "已有证据不足以确定该转换"}
                for index in range(1, 4)
            ]
        elif role == "evidence-mapper":
            payload["result"]["status"] = self.mapper_status
            payload["result"]["report"] = (
                "全部步骤已映射；所有数学状态仍不确定，没有可靠反证。"
                if self.mapper_status == "ok" else "原稿出处无法可靠对齐，不能形成完整映射。"
            )
            payload["control"] = {
                "units": [{"edge_id": f"E{index}", "status": "inconclusive"} for index in range(1, 4)],
                "provisional_error_unit": None, "prefix_units": [],
            }
            if self.claim_refuted:
                payload["control"]["units"][0]["status"] = "refuted"
                payload["control"]["provisional_error_unit"] = "E1"
            payload["artifacts"][artifact] = "E1、E2、E3 的来源与已有证据均已映射，数学状态均为 inconclusive；没有可靠负面证据。"
        elif role == "final-synthesizer":
            payload["artifacts"][artifact] = "暂时无法安全判断；E1 的工具结论未获独立执行证据，E2、E3 仍存在未解决的覆盖缺口。"
        elif role == "consistency-auditor":
            if self.consistency_status != "ok":
                payload["result"]["status"] = self.consistency_status
                payload["result"]["report"] = "结论引用的来源无法核对，不能通过证据链审计。"
            payload["artifacts"][artifact] = "逐项核对原文和证据；未将未知当反证，现有证据只支持不确定结论。"
        return _function_response(payload)


def _checkpoints(root, role):
    records = [json.loads(path.read_text()) for path in sorted((root / "faithsieve-work/checkpoints").glob("*.json"))]
    return [record for record in records if record.get("request", {}).get("role") == role]


def test_complete_unknown_mapping_runs_synthesis_consistency_and_actual_scoring(tmp_path):
    run = UnknownEvidenceRun(tmp_path)
    result = seeded_workflow(tmp_path, run).run()

    assert result["verdict"] == "inconclusive" and result["score"] == 2
    assert run.roles[-3:] == ["final-synthesizer", "consistency-auditor", "scoring"]
    assert "prefix-auditor" not in run.roles  # 没有可靠首错，不新增前缀调用。
    assert run.state == "inconclusive"
    mapper = _checkpoints(tmp_path, "evidence-mapper")[0]
    assert mapper["state"] == "completed" and mapper["response"]["result"]["status"] == "ok"
    assert mapper["response"]["control"] == {
        "units": [{"edge_id": f"E{index}", "status": "inconclusive"} for index in range(1, 4)],
        "provisional_error_unit": None, "prefix_units": [],
    }
    for role in ("final-synthesizer", "consistency-auditor"):
        record = _checkpoints(tmp_path, role)[0]
        assert record["state"] == "completed" and record["response"]["result"]["status"] == "ok"
    scoring = json.loads((tmp_path / "faithsieve-work/checkpoints/final-scoring.json").read_text())
    assert scoring["state"] == "completed" and scoring["response"] == result
    assert run.messages[-1][1]["approved_verdict"] == "inconclusive"
    assert workflow.FINAL in run.messages[-1][1]["input_files"]
    assert "faithsieve-work/review/final.md" in run.messages[-1][1]["input_files"]
    assert json.loads((tmp_path / workflow.RESULT).read_text()) == result
    assert json.loads((tmp_path / "faithsieve-work/formal/E1-O1-verification.json").read_text())["status"] == "inconclusive"

    before = {path: path.read_bytes() for path in (tmp_path / "faithsieve-work/checkpoints").glob("*.json")}
    roles_before = list(run.roles)
    assert seeded_workflow(tmp_path, run).run() == result
    assert run.roles == roles_before
    assert all(path.read_bytes() == original for path, original in before.items())


def test_task_inconclusive_mapper_is_not_promoted_from_complete_control(tmp_path):
    run = UnknownEvidenceRun(tmp_path)
    run.mapper_status = "inconclusive"
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "inconclusive" and result["score"] == 0
    assert "无法可靠对齐" in result["comment"]
    assert not {"final-synthesizer", "consistency-auditor", "scoring"} & set(run.roles)
    assert _checkpoints(tmp_path, "evidence-mapper")[0]["response"]["result"]["status"] == "inconclusive"


def test_unknown_final_still_requires_independent_consistency_revision(tmp_path):
    run = UnknownEvidenceRun(tmp_path)
    run.consistency_revisions = 1
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "inconclusive" and result["score"] == 2
    assert run.roles.count("final-synthesizer") == run.roles.count("consistency-auditor") == 2
    assert run.roles.count("scoring") == 1
    assert _checkpoints(tmp_path, "consistency-auditor")[0]["response"]["result"]["status"] == "needs_revision"


def test_unknown_final_does_not_bypass_unrecoverable_consistency_failure(tmp_path):
    run = UnknownEvidenceRun(tmp_path)
    run.consistency_status = "inconclusive"
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "inconclusive" and result["score"] == 0
    assert "来源无法核对" in result["comment"]
    assert "scoring" not in run.roles


def test_completed_mapping_cannot_relabel_unknown_as_refuted(tmp_path):
    run = UnknownEvidenceRun(tmp_path)
    run.claim_refuted = True
    result = seeded_workflow(tmp_path, run).run()
    assert result["verdict"] == "inconclusive" and "未独立核验" in result["comment"]
    assert "final-synthesizer" not in run.roles and "scoring" not in run.roles


def test_completed_empty_prefix_selection_remains_ok_without_new_mathematical_evidence(tmp_path):
    run = ScriptedRun(tmp_path, suspicious=True)
    assert seeded_workflow(tmp_path, run).run()["verdict"] == "incorrect"
    prefix = _checkpoints(tmp_path, "prefix-auditor")[0]
    assert prefix["state"] == "completed"
    assert prefix["response"]["result"]["status"] == "ok"
    assert prefix["response"]["result"]["candidate_units"] == []
    assert prefix["request"]["parameters"]["prefix_units"] == "[]"
    assert run.tool_roles == ["numeric-evaluator"]


@pytest.mark.parametrize("role,required", [
    ("evidence-mapper", ("完整映射到 claim", "全部局部 inconclusive", "status 表示映射任务是否完成")),
    ("final-synthesizer", ("status:ok, verdict:inconclusive", "综合任务完成", "没有可靠反证本身不排除正确")),
    ("consistency-auditor", ("即使最终 inconclusive 也可返回 ok", "不能因为最终未知就免审来源")),
    ("prefix-auditor", ("candidate_units:[]", "不产生新的 passed/refuted")),
])
def test_job_status_contract_is_present_in_workflow_and_skill_prompts(role, required):
    text = (prompts.PROMPT_ROOT / f"{role}.md").read_text()
    assert text == (ROOT / "skills/faithsieve/references/agents" / f"{role}.md").read_text()
    assert all(part in text for part in required)
