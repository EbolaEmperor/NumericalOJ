"""无结论报告也需核对原稿与图，审核不能替局部 Agent 证明命题。"""

from collections import Counter
import copy
import json

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.dependency_workflow import NODE_VERIFICATION
from backend.oj_modules.faithsieve.workflow import TREE, WORK
from tests.unit.test_faithsieve_image_repair import RepairScript, checkpoint_bytes, make_engine
from tests.unit.test_faithsieve_image_workflow import Pending, Script, mathematical_records, seed
from tests.unit.test_faithsieve_input_transport import decode_input_message
from tests.unit.test_faithsieve_node_selection import replace_payload


def audit_inputs(messages):
    files = decode_input_message(messages[1]["content"][0]["text"])["input_files"]
    paths = [path for path in files if path.startswith(f"{WORK}/obligations/") and path.endswith("-O1.md")]
    assert len(paths) == 1
    context = json.loads(files[paths[0]])
    node = context["node"]["id"]
    result = json.loads(files[f"{WORK}/results/{node}-local-verifier.json"])
    return files, context, result


class InconclusiveGraphScript(RepairScript):
    def __init__(self, root):
        super().__init__(root, defect=False)
        # N13 与被修订的 N3/N4 分支独立，检验真实缓存不能因全图变化而失效。
        for dag in (self.initial_graph, self.repaired_graph):
            for node in dag["nodes"]:
                if node["id"] == "N5":
                    node["id"] = "N13"
            for edge in dag["edges"]:
                if edge["to"] == "N5":
                    edge["to"] = "N13"
            dag["target_ids"] = ["N4", "N13"]
        self.inconclusive_audits = []

    def run_role(self, **request):
        payload = super().run_role(**request)
        if self.native[-1]["node"] == "N3" and self.builder_count == 1:
            payload["result"].update(status="inconclusive", report="原图对象是 ŷ，节点改成了 ĝ，当前命题无法可靠判断。")
            payload["artifacts"][payload["result"]["artifact"]] = "原稿与当前节点对象不一致；尚未得到当前局部命题的数学结论。"
        return payload

    def chat(self, endpoint, messages, **options):
        reply = super().chat(endpoint, messages, **options)
        if messages[0]["content"].startswith("# Verification auditor"):
            files, context, local_result = audit_inputs(messages)
            if context["node"]["id"] == "N3" and self.builder_count == 1:
                assert local_result["status"] == "inconclusive"
                assert files[local_result["artifact"]] == "原稿与当前节点对象不一致；尚未得到当前局部命题的数学结论。"
                self.inconclusive_audits.append(copy.deepcopy(context))

                def mutate(payload):
                    payload["result"].update(status="graph_defect", report="原图中的 ŷ 被构图错误替换为 ĝ。",
                        diagnostics=[{"kind": "statement_mismatch", "affected_node_ids": ["N3"],
                                      "reason": "节点对象与原图不同，须修订 DAG 后验证。"}])

                return replace_payload(reply, mutate)
        return reply


@pytest.mark.parametrize("version", [None, 1])
def test_audit_version_is_frozen_without_coercion(version):
    from backend.oj_modules.faithsieve.verification_audit import (
        VERIFICATION_AUDIT_VERSION, validate_verification_audit_version,
    )
    assert VERIFICATION_AUDIT_VERSION == 1
    assert validate_verification_audit_version(version) is version


@pytest.mark.parametrize("version", [True, False, 1.0, 0, 2, "1", [], {}])
def test_audit_version_rejects_implicit_upgrade(version):
    from backend.oj_modules.faithsieve.verification_audit import validate_verification_audit_version
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_audit_version(version)


def test_inconclusive_graph_error_repairs_and_selects_again_but_preserves_n13_context_and_result(tmp_path):
    script = InconclusiveGraphScript(tmp_path)
    engine = make_engine(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "correct" and script.builder_count == 2
    assert len(script.inconclusive_audits) == 1
    assert Counter(call["node"] for call in script.native) == {"N13": 1, "N4": 2, "N3": 2, "N2": 1}
    assert [call["role"] for call in script.pure].count("node-selector") == 2
    assert [call["role"] for call in script.pure].count("tree-auditor") == 2
    assert engine.store.read_json(TREE) == script.repaired_graph
    assert engine.store.read_json(NODE_VERIFICATION)["targets_established"] is True
    records = engine.checkpoints.records()
    assert all(record["request"]["verification_audit_version"] == 1 for record in mathematical_records(records).values())
    n13 = [record for record in records.values() if record["request"].get("role") == "local-verifier"
           and record["request"].get("parameters", {}).get("node_id") == "N13"]
    assert len(n13) == 1
    assert all((engine.checkpoints.directory / name).read_bytes() == content
               for name, content in script.before_repair.items())
    incomplete = [record for record in records.values()
                  if record["request"].get("role") == "local-verifier"
                  and record["response"]["result"]["status"] == "inconclusive"]
    assert len(incomplete) == 1 and incomplete[0]["state"] == "completed"
    before, counts = checkpoint_bytes(engine), (len(script.native), len(script.pure))
    assert engine.run() == result
    assert checkpoint_bytes(engine) == before and (len(script.native), len(script.pure)) == counts


def test_auditing_genuine_inconclusive_keeps_it_inconclusive_without_extra_proving_task(tmp_path):
    script = Script(tmp_path, statuses={"N2": "inconclusive", "N3": "passed", "N4": "passed", "N5": "passed"})
    original_native = script.run_role

    def native(**request):
        payload = original_native(**request)
        if payload["result"]["status"] == "inconclusive":
            payload["result"]["report"] = "原稿和 DAG 对象、前提均一致；尚无覆盖全部参数的数学证据，不能可靠证明或反驳。"
            payload["artifacts"][payload["result"]["artifact"]] = "已经核对原图与全部直接条件；当前验证方法不足，保留无结论。"
        return payload

    script.run_role = native
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "inconclusive" and result["score"] == 2
    assert len(script.native) == 3
    assert [role for role, _messages, _options in script.pure].count("tree-builder") == 1
    audits = [messages for role, messages, _options in script.pure if role == "verification-auditor"]
    assert len(audits) == 3
    reviewed = [(context, local) for messages in audits for _files, context, local in [audit_inputs(messages)]
                if local["status"] == "inconclusive"]
    assert len(reviewed) == 1 and reviewed[0][0]["node"]["id"] == "N2"
    summary = engine.store.read_json(NODE_VERIFICATION)
    assert summary["nodes"]["N2"]["local_status"] == "inconclusive"
    assert summary["nodes"]["N4"]["status"] == "blocked" and summary["targets_established"] is False
    verification = engine.verification["N2-O1"]
    assert verification["status"] == verification["agent_status"] == "inconclusive"
    assert verification["semantic_audit_status"] == "ok"
    before, counts = checkpoint_bytes(engine), (len(script.native), len(script.pure))
    assert engine.run() == result
    assert checkpoint_bytes(engine) == before and (len(script.native), len(script.pure)) == counts


def test_inconclusive_needs_revision_is_one_clarification_with_exact_goal_and_premises(tmp_path):
    script = Script(tmp_path, statuses={"N2": "inconclusive", "N3": "passed", "N4": "passed", "N5": "passed"})
    original = script.chat
    reviewed = []

    def chat(endpoint, messages, **options):
        reply = original(endpoint, messages, **options)
        if messages[0]["content"].startswith("# Verification auditor"):
            _files, context, local = audit_inputs(messages)
            if context["node"]["id"] == "N2":
                assert local["status"] == "inconclusive"
                reviewed.append(copy.deepcopy(context))
                return replace_payload(reply, lambda payload: payload["result"].update(
                    status="needs_revision", report="请澄清已知前提的核对范围与当前证据不足的原因；无需强求证明。"))
        return reply

    engine = seed(tmp_path, script)
    engine.chat = chat
    assert engine.run()["verdict"] == "inconclusive"
    local_calls = [request for request in script.native if request["expected_result_path"].endswith("N2-local-verifier.json")]
    assert len(local_calls) == len(reviewed) == 2
    path = f"{WORK}/obligations/N2/N2-O1.md"
    assert json.loads(local_calls[0]["files"][path]) == json.loads(local_calls[1]["files"][path])
    assert reviewed[0] == reviewed[1]
    assert "无需强求证明" in local_calls[1]["prompt"]
    assert engine.verification["N2-O1"]["status"] == "inconclusive"
    assert engine.verification["N2-O1"]["semantic_audit_status"] == "needs_revision"
    assert len(script.native) == 4


@pytest.mark.parametrize("pending", [False, True])
def test_pre_audit_epoch_preserves_roles_prompts_and_completed_or_pending_identity(tmp_path, pending):
    script = Script(tmp_path, statuses={"N2": "inconclusive", "N3": "passed", "N4": "passed", "N5": "passed"})
    engine = seed(tmp_path, script)
    engine._select_verification_audit_version = lambda: None
    if pending:
        script.pending = "N4"
        with pytest.raises(Pending):
            engine.run()
        original_pending = copy.deepcopy(script.native[-1])
    else:
        assert engine.run()["verdict"] == "inconclusive"
    original = checkpoint_bytes(engine)
    assert all("verification_audit_version" not in record["request"] for record in engine.checkpoints.records().values())
    assert all(record["request"]["node_selection_version"] == 1 for record in mathematical_records(engine.checkpoints.records()).values())
    before_native, before_pure = len(script.native), len(script.pure)
    resumed = seed(tmp_path, script)
    assert resumed.run()["verdict"] == "inconclusive" and resumed.verification_audit_version is None
    assert all("verification_audit_version" not in record["request"] for record in resumed.checkpoints.records().values())
    audits = [messages for role, messages, _options in script.pure if role == "verification-auditor"]
    assert len(audits) == 2
    assert all(audit_inputs(messages)[2]["status"] == "passed" for messages in audits)
    if pending:
        assert script.native[before_native] == original_pending
        assert all((resumed.checkpoints.directory / name).read_bytes() == content
                   for name, content in original.items() if json.loads(content)["state"] == "completed")
    else:
        assert checkpoint_bytes(resumed) == original
        assert (len(script.native), len(script.pure)) == (before_native, before_pure)


@pytest.mark.parametrize("marker", [True, False, 1.0, 0, 2, "1"])
def test_invalid_first_builder_audit_marker_does_not_dispatch_or_modify_frozen_records(tmp_path, marker):
    script = Script(tmp_path)
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    path = engine.checkpoints._path("role-000001-attempt-1")
    record = json.loads(path.read_text())
    record["request"]["verification_audit_version"] = marker
    path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    before, calls = checkpoint_bytes(engine), (len(script.native), len(script.pure))
    assert seed(tmp_path, script).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before and (len(script.native), len(script.pure)) == calls


@pytest.mark.parametrize("missing", ["node_selection_version", "local_diagnostic_version"])
def test_new_audit_marker_cannot_upgrade_a_legacy_verification_prerequisite(tmp_path, missing):
    script = Script(tmp_path)
    engine = seed(tmp_path, script)
    assert engine.run()["verdict"] == "correct"
    path = engine.checkpoints._path("role-000001-attempt-1")
    record = json.loads(path.read_text())
    record["request"].pop(missing)
    path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    before, calls = checkpoint_bytes(engine), (len(script.native), len(script.pure))
    assert seed(tmp_path, script).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before and (len(script.native), len(script.pure)) == calls
