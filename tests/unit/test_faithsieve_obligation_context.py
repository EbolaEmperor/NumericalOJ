"""桥梁义务只读证据、依赖门禁和角色保真约束。"""

import json
from pathlib import Path

import pytest

from backend.oj_modules.faithsieve import workflow
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from tests.unit.test_faithsieve_input_transport import decode_input_message
from tests.unit.test_faithsieve_workflow import _function_response, envelope, thinking_endpoint, tree_payload


def registered_engine(tmp_path, chat=None):
    engine = workflow.FaithSieveWorkflow(
        endpoint=thinking_endpoint(enabled=False), verification_agent=None, workspace=tmp_path, chat=chat,
    )
    tree = tree_payload()
    engine.edge_contexts["E1"] = {
        "edge": tree["edges"][0], "parent_state": tree["nodes"][0], "child_state": tree["nodes"][1],
    }
    engine.store.write("problem.md", "给定源条件 A，证明 P。")
    engine.store.write(workflow.SOURCE, "作者在父状态 Γ 中声称条件 A；随后声称 P。")
    index = f"{workflow.WORK}/obligations/E1/index.md"
    obligations = [{"id": f"E1-O{i}", "path": f"{workflow.WORK}/obligations/E1/E1-O{i}.md",
                    "depends_on": ["E1-O1"] if i == 2 else ["E1-O2"] if i == 5 else []} for i in range(1, 6)]
    for item in obligations:
        engine.store.write(item["path"], f"{item['id']}：源条件、桥梁结论与 depends_on={item['depends_on']}。")
    engine.store.write(index, "\n".join(item["path"] for item in obligations))
    engine._read_obligations("E1", workflow.RoleOutput({"artifact": index}, {"obligations": obligations}, {}))
    for identifier in ("E1-O1", "E1-O2", "E1-O4"):
        statement = f"{workflow.WORK}/formal/{identifier}-original-statement.lean"
        semantics = f"{workflow.WORK}/formal/{identifier}-original-semantics.md"
        engine.store.write(statement, f"def {identifier.replace('-', '_')} : Prop := True")
        engine.store.write(semantics, f"{identifier} 的独立源对应与适用性映射。")
        engine._record_verification(identifier, status="passed", route="lean", branch="original",
                                    statement=statement, semantic_audit=semantics,
                                    statement_compiled=True, proof_compiled=True)
        engine.store.write(f"{workflow.WORK}/formal/{identifier}-original-proof.lean", "证明搜索上下文噪音")
        engine.store.write(f"{workflow.WORK}/formal/{identifier}-negation-statement.lean", "失败分支噪音")
    engine._record_verification("E1-O3", status="refuted", report="无关义务")
    return engine, obligations


def test_check_and_semantic_requests_include_only_passed_dependency_closure(tmp_path):
    observed = []

    def chat(_endpoint, messages, **_options):
        files = decode_input_message(messages[1]["content"])["input_files"]
        observed.append(files)
        semantic = messages[0]["content"].startswith("# Semantic checker")
        artifact = f"{workflow.WORK}/formal/E1-O5-" + ("original-semantics.md" if semantic else "check.md")
        return _function_response(envelope(artifact, control={} if semantic else {"route": "lean"}))

    engine, obligations = registered_engine(tmp_path, chat)
    item = obligations[-1]
    parameters = {"obligation_id": item["id"], "obligation_path": item["path"],
                  "check_object_path": f"{workflow.WORK}/formal/E1-O5-check.md", "branch": "original",
                  "statement_path": f"{workflow.WORK}/formal/E1-O5-original-statement.lean",
                  "semantic_report_path": f"{workflow.WORK}/formal/E1-O5-original-semantics.md"}
    engine._invoke("check-object-generator", files=engine._obligation_context(item["id"], item["path"]), parameters=parameters)
    engine._invoke("semantic-checker", files=engine._obligation_context(item["id"], item["path"], include_review=False), parameters=parameters)
    for files in observed:
        for dependency in ("E1-O1", "E1-O2"):
            assert f"{workflow.WORK}/obligations/E1/{dependency}.md" in files
            assert json.loads(files[f"{workflow.WORK}/formal/{dependency}-verification.json"])["status"] == "passed"
            assert f"{workflow.WORK}/formal/{dependency}-original-statement.lean" in files
            assert f"{workflow.WORK}/formal/{dependency}-original-semantics.md" in files
        assert not any("E1-O3" in name or "E1-O4" in name or "-proof.lean" in name or "-negation-" in name for name in files)
    for index, files in enumerate(observed, 1):
        saved = engine.store.read_json(f"{workflow.WORK}/checkpoints/role-{index:06d}-attempt-1.json")
        assert saved["request"]["files"] == files
        assert decode_input_message(saved["request"]["messages"][1]["content"])["input_files"] == files


@pytest.mark.parametrize("status", [None, "inconclusive", "refuted"])
def test_unpassed_bridge_stops_before_any_check_request(tmp_path, status):
    engine, obligations = registered_engine(tmp_path, lambda *_args, **_options: pytest.fail("桥梁未通过不得派检查"))
    if status is None:
        engine.verification.pop("E1-O2")
    else:
        engine.verification["E1-O2"]["status"] = status
    assert engine._verify_obligation(obligations[-1]) == "inconclusive"
    assert engine.verification["E1-O5"]["depends_on"] == ["E1-O2"]


def test_dependency_context_rejects_unpassed_ancestor_or_foreign_evidence_path(tmp_path):
    engine, obligations = registered_engine(tmp_path)
    current = obligations[-1]
    engine.verification["E1-O1"]["status"] = "refuted"
    with pytest.raises(FaithSieveProtocolError, match="已通过"):
        engine._obligation_context(current["id"], current["path"])
    engine.verification["E1-O1"]["status"] = "passed"
    engine.verification["E1-O2"]["statement"] = f"{workflow.WORK}/formal/E1-O4-original-statement.lean"
    engine.store.write_json(f"{workflow.WORK}/formal/E1-O2-verification.json", engine.verification["E1-O2"])
    with pytest.raises(FaithSieveProtocolError, match="证据路径"):
        engine._obligation_context(current["id"], current["path"])


@pytest.mark.parametrize("role", ["obligation-builder", "check-object-generator", "semantic-checker"])
def test_fixed_node_rules_match_skill_without_adding_mathematical_premises(role):
    root = Path(__file__).resolve().parents[2]
    body = (root / "backend/oj_modules/faithsieve/prompts" / f"{role}.md").read_text()
    assert body == (root / "skills/faithsieve/references/agents" / f"{role}.md").read_text()
    for text in ("全部直接前驱", "固定", "来源", "inconclusive"):
        assert text in body
    if role == "obligation-builder":
        assert "义务由编排代码确定" in body and "不另造 O2" in body
        assert "前驱 claim 仅是局部蕴含的条件" in body
    elif role == "check-object-generator":
        assert "不追加 O2" in body and "不能改为较弱条件命题" in body
        assert "同一验证中已证明等价" in body and "题面全文不能暗中提供" in body
    else:
        assert "不要求在此证明它们" in body and "同一验证中已证明等价" in body
        assert "新增源外前提" in body and "不能靠附加假设或新桥梁任务消除" in body
