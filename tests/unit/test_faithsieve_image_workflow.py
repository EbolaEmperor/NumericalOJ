"""直接图片工作流的实际调用、联合前提及冻结重入。"""

import base64
import copy
import json

import pytest

from backend.oj_modules.ai.endpoints import LLMChatResult, LLMToolCall
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.image_workflow import (
    ImageWorkflow, freeze_rendered_images, restore_rendered_images, render_workflow_images,
    image_render_request,
)
from backend.oj_modules.faithsieve.dependency_workflow import NODE_VERIFICATION
from backend.oj_modules.faithsieve.graph_repair_policy import GRAPH_REPAIR_POLICY_KEY, validate_graph_repair_policy_record
from backend.oj_modules.faithsieve.proof_dag import topological_node_ids
from backend.oj_modules.faithsieve.workflow import TREE, WORK, RESULT, run_faithsieve_workflow
from tests.unit.test_faithsieve_input_transport import decode_input_message


PNG = b"\x89PNG\r\n\x1a\n"


def rendered():
    pages = [{"page": i, "rendered": True, "image_path": f"source-pages/page-{i}.png"} for i in (1, 2)]
    return {"pages": pages, "files": {"pages.json": json.dumps(pages),
            **{p["image_path"]: PNG + bytes([p["page"]]) for p in pages}}}


def graph():
    return {"schema_version": 3,
            "nodes": [{"id": f"N{i}", "kind": "given" if i == 1 else "claim",
                       "label": f"命题{i}", "statement": f"完整命题{i}(x)，保留共享条件与量词"} for i in range(1, 6)],
            "edges": [{"id": f"D{i}", "from": a, "to": b} for i, (a,b) in enumerate(
                (("N1", "N2"), ("N1", "N3"), ("N2", "N4"), ("N3", "N4")), 1)],
            "target_ids": ["N4"], "ambiguities": []}


def default_node_selection(dag):
    required, pending = set(), list(dag["target_ids"])
    parents = {node["id"]: [] for node in dag["nodes"]}
    for edge in dag["edges"]:
        parents[edge["to"]].append(edge["from"])
    while pending:
        identifier = pending.pop()
        if identifier not in required:
            required.add(identifier)
            pending.extend(parents[identifier])
    claims = {node["id"] for node in dag["nodes"] if node["kind"] == "claim"}
    return [identifier for identifier in reversed(topological_node_ids(dag)) if identifier in required & claims]


def endpoint(protocol="openai", thinking=False):
    return {"id": 8, "category": "omni", "protocol": protocol, "base_url": "https://example.invalid/v1",
            "model": "mock-model", "api_key": "do-not-freeze-key", "thinking_enabled": thinking,
            "thinking_format": "none", "openai_thinking_format": "enable_thinking" if protocol == "openai" else "thinking_type",
            "max_output_tokens": 128000, "context_window_tokens": 384000}


class Pending(Exception):
    pass


class Script:
    def __init__(self, root, *, statuses=None):
        self.root = root
        self.statuses = statuses or {f"N{i}": "passed" for i in range(2, 6)}
        self.pure, self.native, self.renders = [], [], []
        self.pending = None
        self.bad_local = False
        self.dag = graph()

    def render_submission_images(self, pdf, **options):
        self.renders.append((pdf, options))
        return rendered()

    def chat(self, endpoint, messages, **options):
        content = messages[1]["content"]
        assert isinstance(content, list) and len(content) == 3
        assert [base64.b64decode(block["image_url"]["url"].split(",",1)[1]) for block in content[1:]] == [PNG+b"\x01", PNG+b"\x02"]
        data = decode_input_message(content[0]["text"])
        files = data["input_files"]
        assert "faithsieve-work/source/submission.md" not in files and "faithsieve-work/steps.md" not in files
        system = messages[0]["content"]
        headers = {"Tree builder": "tree-builder", "Tree auditor": "tree-auditor", "Evidence mapper": "evidence-mapper",
                   "Final synthesizer": "final-synthesizer", "Consistency auditor": "consistency-auditor",
                   "Verification auditor": "verification-auditor", "Node selector": "node-selector"}
        role = "scoring" if system.startswith("# FaithSieve 评分") else headers[system.splitlines()[0][2:]]
        self.pure.append((role, copy.deepcopy(messages), copy.deepcopy(options)))
        if role == "scoring":
            payload = {"verdict": data["approved_verdict"], "score": 5 if data["approved_verdict"] == "correct" else 2, "comment": "按独立审计后的证据评分。"}
        else:
            artifact = {"tree-builder": TREE, "tree-auditor": f"{WORK}/review/tree.md", "evidence-mapper": f"{WORK}/evidence-map.md",
                        "final-synthesizer": f"{WORK}/final.md", "consistency-auditor": f"{WORK}/review/final.md",
                        "verification-auditor": "", "node-selector": f"{WORK}/node-selection.json"}[role]
            if role == "verification-auditor":
                obligations = [path for path in files if path.startswith(f"{WORK}/obligations/") and path.endswith("-O1.md")]
                assert len(obligations) == 1
                node = json.loads(files[obligations[0]])["node"]["id"]
                artifact = f"{WORK}/review/{node}-verification.md"
            payload = {"result": {"status": "ok", "artifact": artifact, "report": "完整看图并核对任务。"}, "artifacts": {artifact: "完整中文报告"}, "control": {}}
            if role == "tree-builder":
                payload["artifacts"][artifact] = copy.deepcopy(self.dag)
                payload.pop("control")
            elif role == "tree-auditor":
                payload["control"] = {"target_coverage": "matched"}
            elif role == "node-selector":
                assert set(files) == {"problem.md", "pages.json", TREE}
                payload["artifacts"][artifact] = json.dumps({"node_ids": default_node_selection(json.loads(files[TREE]))})
            elif role == "verification-auditor":
                payload["result"]["diagnostics"] = []
            elif role == "evidence-mapper":
                summary = json.loads(files[NODE_VERIFICATION])
                closure = {"N1", "N2", "N3", "N4"}
                failed = next((f"N{i}" for i in range(2,5) if summary["nodes"][f"N{i}"]["local_status"] == "refuted"), None)
                payload["control"] = {"units": [{"node_id": f"N{i}", "status": summary["nodes"][f"N{i}"]["local_status"]} for i in range(2,6)],
                                      "provisional_error_node": failed,
                                      "unresolved_ancestors": [n["id"] for n in self.dag["nodes"] if n["kind"] == "claim" and n["id"] in closure and not summary["nodes"][n["id"]]["established"]]}
            elif role == "final-synthesizer":
                summary = json.loads(files[NODE_VERIFICATION])
                payload["result"]["verdict"] = "correct" if summary["targets_established"] else ("incorrect" if any(summary["nodes"][f"N{i}"]["local_status"] == "refuted" for i in (2,3,4)) else "inconclusive")
        raw = json.dumps(payload, ensure_ascii=False)
        return LLMChatResult(text=raw, finish_reason="stop") if "response_format" in options else LLMChatResult(text="", tool_calls=(LLMToolCall(id="result",name="faithsieve_result",arguments=raw),), finish_reason="tool_calls")

    def run_role(self, **request):
        self.native.append(copy.deepcopy(request))
        node = request["expected_result_path"].split("/")[-1].split("-local")[0]
        assert request["role"] == "local-verifier" and request["proof_graph_version"] == 3
        assert request["files"]["source-pages/page-1.png"] == PNG+b"\x01"
        assert request["files"]["source-pages/page-2.png"] == PNG+b"\x02"
        assert TREE not in request["files"]
        assert not any("source/submission" in p or p.endswith("steps.md") for p in request["files"])
        local = json.loads(request["files"][f"{WORK}/obligations/{node}/{node}-O1.md"])
        assert local["node"]["id"] == node
        assert [n["id"] for n in local["premises"]] == {"N2":["N1"], "N3":["N1"], "N4":["N2","N3"], "N5":[]}[node]
        if self.pending == node:
            self.pending = None
            raise Pending(node)
        artifact = f"{WORK}/verification/{node}.md"
        payload = {"result": {"status": self.statuses[node], "artifact": artifact, "report": "完整 Agent 自主完成局部联合条件验证。"},
                   "artifacts": {artifact: "验证方法、完整前提和目标，以及证据和不确定性。"}, "execution": {"decision_source": "agent"}}
        if request.get("local_diagnostic_version") == 1:
            payload["result"]["diagnostics"] = []
        if self.bad_local:
            payload["result"]["status"] = "unregistered-verdict"
        return payload


def seed(root, script, protocol="openai", thinking=False):
    engine = ImageWorkflow(endpoint=endpoint(protocol, thinking), verification_agent=script, workspace=root, chat=script.chat,
                           initial_reasoning_effort="low")
    engine.store.write("problem.md", "固定共享对象 x，给定命题1，证明完整命题4。")
    engine.set_images(freeze_rendered_images(rendered()))
    return engine


def mathematical_records(records):
    return {key: record for key, record in records.items()
            if key == "image-render" or key == "final-scoring" or key.startswith("role-")}


@pytest.mark.parametrize("protocol,thinking", [("openai",False), ("openai",True), ("anthropic",True)])
def test_actual_three_step_workflow_and_readonly_completed_reentry(tmp_path, protocol, thinking):
    script = Script(tmp_path)
    engine = seed(tmp_path, script, protocol, thinking)
    result = engine.run()
    assert result["verdict"] == "correct" and result["score"] == 5
    assert [role for role,_messages,_options in script.pure] == [
        "tree-builder", "tree-auditor", "node-selector", *["verification-auditor"] * 3,
        "evidence-mapper", "final-synthesizer", "consistency-auditor", "scoring"]
    assert [r["expected_result_path"] for r in script.native] == [f"{WORK}/results/N{i}-local-verifier.json" for i in (4,3,2)]
    assert all("max_tokens" not in options for _role,_messages,options in script.pure)
    tree = script.pure[0][2]
    assert tree["stream"] is True and tree["require_complete_stream"] is True
    assert "max_stream_bytes" not in tree
    if thinking:
        schema = tree["tools"][0]["function"]["parameters"]["properties"]["artifacts"]["properties"][TREE]
        assert schema["properties"]["schema_version"]["enum"] == [3]
        assert set(schema["properties"]["nodes"]["items"]["properties"]) == {"id","kind","label","statement"}
        assert tree["reasoning_effort"] == "low"
    paths = list(engine.checkpoints.directory.glob("*.json"))
    original = {p.name:p.read_bytes() for p in paths}
    all_records = engine.checkpoints.records()
    records = list(mathematical_records(all_records).values())
    assert all(r["request"]["proof_graph_version"] == 3 for r in records)
    assert validate_graph_repair_policy_record(all_records[GRAPH_REPAIR_POLICY_KEY])["mode"] == "per_node"
    assert not {"proof_graph_version", "local_diagnostic_version", "result_projection_version", "node_selection_version",
                "verification_audit_version", "messages", "prompt", "call_options"} & all_records[GRAPH_REPAIR_POLICY_KEY]["request"].keys()
    local = next(r for r in records if r["request"].get("role") == "local-verifier"
                 and r["request"].get("parameters",{}).get("node_id") == "N4")
    assert local["metadata"]["node_id"] == "N4"
    assert base64.b64decode(local["request"]["images"]["source-pages/page-2.png"]) == PNG+b"\x02"
    assert not any(p.name.startswith("compile-") or p.name == "source-extraction.json" for p in paths)
    script.pure.clear(); script.native.clear()
    assert engine.run() == result
    assert not script.pure and not script.native
    assert {p.name:p.read_bytes() for p in paths} == original


def test_unknown_parent_does_not_stop_required_nodes_and_skips_unrelated_branch(tmp_path):
    script = Script(tmp_path, statuses={"N2":"inconclusive","N3":"passed","N4":"passed","N5":"refuted"})
    engine = seed(tmp_path,script)
    result = engine.run()
    assert len(script.native) == 3 and result["verdict"] == "inconclusive" and result["score"] == 2
    summary = engine.store.read_json(NODE_VERIFICATION)
    assert summary["nodes"]["N4"]["local_status"] == "passed" and summary["nodes"]["N4"]["status"] == "blocked"
    assert summary["nodes"]["N5"]["local_status"] == "not_checked"
    assert engine._reliable_error() is None


@pytest.mark.parametrize("mapper_status", ["ok", "inconclusive"])
def test_host_evidence_ledger_keeps_true_statuses_when_model_includes_given_and_omits_target(tmp_path, mapper_status):
    script = Script(tmp_path, statuses={"N2":"inconclusive", "N3":"passed", "N4":"passed", "N5":"passed"})
    original = script.chat

    def chat(endpoint, messages, **options):
        response = original(endpoint, messages, **options)
        if messages[0]["content"].startswith("# Evidence mapper"):
            payload = json.loads(response.text)
            payload["result"]["status"] = mapper_status
            payload["artifacts"][f"{WORK}/evidence-map.md"] = "错误模型摘要：N1和全部节点passed，目标已建立。"
            payload["control"] = {"units": [{"node_id":"N1", "status":"passed"}],
                                  "provisional_error_node": "N5", "unresolved_ancestors": []}
            return LLMChatResult(text=json.dumps(payload, ensure_ascii=False), finish_reason="stop")
        if messages[0]["content"].startswith("# Final synthesizer"):
            inputs = decode_input_message(messages[1]["content"][0]["text"])["input_files"]
            evidence = inputs[f"{WORK}/evidence-map.md"]
            assert "错误模型摘要" not in evidence
            ledger = json.loads(evidence.removeprefix("```json\n").removesuffix("\n```\n"))
            assert ledger["nodes"]["N1"]["local_status"] == "given"
            assert ledger["nodes"]["N1"]["established"] is True
            assert ledger["nodes"]["N4"]["local_status"] == "passed"
            assert ledger["nodes"]["N4"]["status"] == "blocked"
            assert ledger["nodes"]["N5"]["local_status"] == "not_checked"
            assert ledger["control"]["units"] == [
                {"node_id":f"N{i}", "status":status} for i,status in
                ((2,"inconclusive"),(3,"passed"),(4,"passed"),(5,"not_checked"))]
            assert ledger["control"]["unresolved_ancestors"] == ["N2", "N4"]
            assert ledger["control"]["provisional_error_node"] is None
            assert ledger["targets_established"] is False
            assert ledger["verification"]["N2"]["status"] == "inconclusive"
            assert ledger["verification"]["N4"]["status"] == "passed"
            assert ledger["verification"]["N5"] is None
        return response

    engine = seed(tmp_path, script)
    engine.chat = chat
    result = engine.run()
    assert result["verdict"] == "inconclusive" and result["score"] == 2
    assert len(script.native) == 3
    assert [role for role,_messages,_options in script.pure][-4:] == [
        "evidence-mapper", "final-synthesizer", "consistency-auditor", "scoring"]
    mapper = next(record for record in engine.checkpoints.records().values()
                  if record["request"].get("role") == "evidence-mapper")
    assert mapper["response"]["result"]["status"] == mapper_status
    assert mapper["response"]["control"]["units"] == [{"node_id":"N1", "status":"passed"}]
    before = {p.name:p.read_bytes() for p in engine.checkpoints.directory.glob("*.json")}
    pure, native = len(script.pure), len(script.native)
    assert engine.run() == result
    assert (len(script.pure), len(script.native)) == (pure, native)
    assert {p.name:p.read_bytes() for p in engine.checkpoints.directory.glob("*.json")} == before


def test_native_pending_reentry_only_polls_same_full_agent_identity(tmp_path):
    script=Script(tmp_path); script.pending="N4"
    engine=seed(tmp_path,script)
    with pytest.raises(Pending): engine.run()
    pure_before=len(script.pure); native_before=len(script.native)
    pending=script.native[-1]
    assert engine.run()["verdict"] == "correct"
    assert script.native[native_before] == pending
    assert [role for role, _messages, _options in script.pure[pure_before:]] == [
        *["verification-auditor"] * 3, "evidence-mapper", "final-synthesizer",
        "consistency-auditor", "scoring"]
    assert [r["expected_result_path"] for r in script.native].count(f"{WORK}/results/N2-local-verifier.json") == 1


def test_invalid_native_protocol_does_not_dispatch_another_agent(tmp_path):
    script=Script(tmp_path); script.bad_local=True
    engine=seed(tmp_path,script)
    result=engine.run()
    assert result["verdict"] == "inconclusive" and len(script.native) == 1
    failed_key = next(key for key, record in engine.checkpoints.records().items()
                      if record["request"].get("role") == "local-verifier")
    assert not (tmp_path/f"{WORK}/checkpoints/{failed_key.removesuffix('-1')}-2.json").exists()


def with_result_metadata(response):
    if response.tool_calls:
        payload = json.loads(response.tool_calls[0].arguments)
        payload["result"].update(confidence="high", target_ids_note="see tree.json")
        return LLMChatResult(text="", tool_calls=(LLMToolCall(
            id="result", name="faithsieve_result", arguments=json.dumps(payload, ensure_ascii=False)),),
            finish_reason="tool_calls")
    payload = json.loads(response.text)
    payload["result"].update(confidence="high", target_ids_note="see tree.json")
    return LLMChatResult(text=json.dumps(payload, ensure_ascii=False), finish_reason="stop")


@pytest.mark.parametrize("thinking", [False, True])
def test_extra_result_metadata_is_private_without_regeneration_or_replay_calls(tmp_path, thinking):
    script = Script(tmp_path)
    engine = seed(tmp_path, script, thinking=thinking)
    original_chat, original_native = script.chat, script.run_role

    def chat(endpoint, messages, **options):
        response = original_chat(endpoint, messages, **options)
        if messages[0]["content"].startswith("# FaithSieve 评分"):
            if response.tool_calls:
                payload = json.loads(response.tool_calls[0].arguments)
                payload["confidence"] = "high"
                return LLMChatResult(text="", tool_calls=(LLMToolCall(
                    id="result", name="faithsieve_result", arguments=json.dumps(payload)),), finish_reason="tool_calls")
            payload = json.loads(response.text)
            payload["confidence"] = "high"
            return LLMChatResult(text=json.dumps(payload), finish_reason="stop")
        return with_result_metadata(response)

    def native(**request):
        payload = original_native(**request)
        payload["result"]["confidence"] = "high"
        return payload

    engine.chat, script.run_role = chat, native
    result = engine.run()
    assert result["verdict"] == "correct"
    assert [role for role, *_ in script.pure].count("tree-builder") == 1
    assert len(script.native) == 3
    records = engine.checkpoints.records()
    for record in mathematical_records(records).values():
        assert record["request"]["result_projection_version"] == 1
        if record["request"].get("role"):
            assert record["metadata"]["ignored_result_metadata"]["confidence"] == "high"
            response = record["response"]
            assert "confidence" not in response["result"]
            assert "confidence" not in response["execution"] and "confidence" not in response["control"]
        else:
            assert record["metadata"]["ignored_result_metadata"] == {"confidence": "high"}
            assert set(record["response"]) == {"verdict", "score", "comment"}
    before = {p.name: p.read_bytes() for p in engine.checkpoints.directory.glob("*.json")}
    calls = len(script.pure), len(script.native)
    assert engine.run() == result
    assert (len(script.pure), len(script.native)) == calls
    assert before == {p.name: p.read_bytes() for p in engine.checkpoints.directory.glob("*.json")}


def test_pre_projection_image_request_keeps_strict_result_and_failed_history(tmp_path):
    script = Script(tmp_path)
    engine = seed(tmp_path, script)
    engine._select_result_projection_version = lambda: None
    engine._select_node_selection_version = lambda: None
    engine.chat = lambda endpoint, messages, **options: with_result_metadata(script.chat(endpoint, messages, **options))
    result = engine.run()
    assert result["verdict"] == "inconclusive"
    assert not script.native and len(script.pure) == 2
    before = {p.name: p.read_bytes() for p in engine.checkpoints.directory.glob("*.json")}
    assert all("result_projection_version" not in record["request"]
               for record in engine.checkpoints.records().values())
    engine = seed(tmp_path, script)
    assert engine.run() == result
    assert len(script.pure) == 2 and not script.native
    assert before == {p.name: p.read_bytes() for p in engine.checkpoints.directory.glob("*.json")}


@pytest.mark.parametrize("state", ["pending","completed"])
def test_changed_image_request_cannot_reenter_or_hit_cache(tmp_path,state):
    script=Script(tmp_path); engine=seed(tmp_path,script)
    if state=="pending":
        script.pending="N4"
        with pytest.raises(Pending): engine.run()
    else: assert engine.run()["verdict"] == "correct"
    before=(len(script.pure),len(script.native))
    engine.image_files["source-pages/page-1.png"] = PNG+b"changed"
    assert engine.run()["verdict"] == "inconclusive"
    assert (len(script.pure),len(script.native)) == before


def test_fresh_entry_code_renders_once_and_never_transcribes(tmp_path,monkeypatch):
    script=Script(tmp_path)
    from backend.oj_modules.faithsieve import workflow
    monkeypatch.setattr(workflow,"call_chat",script.chat)
    options=dict(problem_text="题面",submission_pdf=b"%PDF-original",endpoint=endpoint(),verification_agent=script,workspace=tmp_path)
    result=run_faithsieve_workflow(**options)
    assert result["verdict"] == "correct" and len(script.renders)==1
    assert script.renders[0][1] == {"invocation_key":"image-render","timeout_seconds":600}
    frozen={p.name:p.read_bytes() for p in (tmp_path/f"{WORK}/checkpoints").glob("*.json")}
    assert "image-render.json" in frozen and "source-extraction.json" not in frozen
    assert run_faithsieve_workflow(**options)==result and len(script.renders)==1
    assert {p.name:p.read_bytes() for p in (tmp_path/f"{WORK}/checkpoints").glob("*.json")} == frozen
    with pytest.raises(FaithSieveProtocolError,match="原 PDF"):
        run_faithsieve_workflow(**{**options,"submission_pdf":b"%PDF-changed"})


@pytest.mark.parametrize("mutate", ["extra_source","wrong_order","fake_png","duplicate_pages","float_page"])
def test_render_input_strict_png_only(mutate):
    data=rendered()
    if mutate=="extra_source": data["files"]["submission.md"]="transcription"
    elif mutate=="wrong_order": data["pages"].reverse()
    elif mutate=="fake_png": data["files"]["source-pages/page-1.png"]=b"text"
    elif mutate=="duplicate_pages": data["files"]["pages.json"]='[{"page":1,"page":1}]'
    elif mutate=="float_page": data["pages"][0]["page"]=1.0
    with pytest.raises(FaithSieveProtocolError): freeze_rendered_images(data)


@pytest.mark.parametrize("state",["pending","completed"])
def test_render_frozen_budget_type_alias_rejected_without_work(tmp_path,state):
    script=Script(tmp_path); engine=seed(tmp_path,script)
    request=image_render_request("题面"); request["timeout_seconds"]=600.0
    engine.checkpoints.put("image-render",request,state=state,response=freeze_rendered_images(rendered()) if state=="completed" else None)
    with pytest.raises(FaithSieveProtocolError,match="字段类型"):
        render_workflow_images(engine,problem_text="题面",submission_pdf=b"%PDF-original")
    assert not script.renders


def test_original_png_roundtrip_exact():
    raw=rendered()
    assert restore_rendered_images(freeze_rendered_images(raw)) == raw


def test_target_local_refutation_stops_other_judges_then_real_summary_scoring(tmp_path):
    script = Script(tmp_path, statuses={"N2":"passed", "N3":"passed", "N4":"refuted", "N5":"passed"})
    engine = seed(tmp_path,script)
    result = engine.run()
    assert result["verdict"] == "incorrect" and result["score"] == 2
    assert [r["expected_result_path"] for r in script.native] == [f"{WORK}/results/N4-local-verifier.json"]
    summary = engine.store.read_json(NODE_VERIFICATION)
    assert summary["nodes"]["N4"]["local_status"] == "refuted"
    assert all(summary["nodes"][f"N{i}"]["local_status"] == "not_checked" for i in (2,3,5))
    assert [r for r,_m,_o in script.pure][-4:] == ["evidence-mapper","final-synthesizer","consistency-auditor","scoring"]
    before=(len(script.pure),len(script.native))
    assert engine.run()==result and (len(script.pure),len(script.native))==before


def test_v3_json_syntax_repair_sees_only_raw_not_problem_or_images(tmp_path):
    script=Script(tmp_path)
    engine=seed(tmp_path,script)
    ordinary=script.chat
    seen={"initial":0,"repair":0}
    def chat(ep,messages,**options):
        if messages[0]["content"].startswith("你只修复"):
            seen["repair"]+=1
            assert type(messages[1]["content"]) is str
            assert seen["raw"] in messages[1]["content"]
            assert "data:image" not in messages[1]["content"]
            assert "固定共享对象 x" not in messages[1]["content"]
            assert "max_tokens" not in options and "max_stream_bytes" not in options
            return LLMChatResult(text=seen["raw"].replace('\\Delta','\\\\Delta'),finish_reason="stop")
        response=ordinary(ep,messages,**options)
        if script.pure[-1][0]=="tree-builder":
            seen["initial"]+=1
            seen["raw"]=response.text.replace('完整看图并核对任务。','完整报告 \\Delta')
            return LLMChatResult(text=seen["raw"],finish_reason="stop")
        return response
    engine.chat=chat
    result=engine.run()
    assert result["verdict"]=="correct" and seen["initial"]==1 and seen["repair"]==1
    record=engine.checkpoints._read_record("role-000001-attempt-1",strict=True)[0]
    assert record["metadata"]["json_repair"]["state"]=="completed"
    assert record["metadata"]["json_repair"]["raw_response"]==seen["raw"]
    assert not engine.checkpoints._path("role-000001-attempt-2").exists()
    assert engine.run()==result and seen["initial"]==1 and seen["repair"]==1


def test_v3_rejects_valid_v2_graph_without_schema_or_content_repair(tmp_path):
    script=Script(tmp_path); script.dag["schema_version"]=2
    engine=seed(tmp_path,script)
    result=engine.run()
    assert result["verdict"]=="inconclusive" and not script.native
    assert [role for role,_m,_o in script.pure]==["tree-builder","tree-builder"]
    assert all("json_repair" not in record.get("metadata",{}) for record in engine.checkpoints.records().values())


def test_v3_endpoint_recovery_preflight_uses_frozen_png_only_and_is_readonly(tmp_path):
    from backend.oj_modules.ai.endpoints import LLMEndpointRequestError
    from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
    from backend.oj_modules.faithsieve.recovery import validate_recovery_inputs
    from backend.oj_modules.faithsieve.runtime_snapshot import SNAPSHOT_FILENAME
    script=Script(tmp_path); engine=seed(tmp_path,script)
    problem=engine.store.read("problem.md")
    render_workflow_images(engine,problem_text=problem,submission_pdf=b"%PDF-original")
    snapshot=tmp_path/SNAPSHOT_FILENAME
    snapshot.write_text(json.dumps({"endpoint_id":8,"initial_reasoning_effort":None})); snapshot.chmod(0o600)
    def failure(*_a,**_k):
        raise LLMEndpointRequestError("固定连接失败",request_failure="connection")
    engine.chat=failure
    with pytest.raises(FaithSieveEndpointError):
        engine._invoke("tree-builder",files=engine._files("problem.md","pages.json"))
    before={p.relative_to(tmp_path).as_posix():p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    validate_recovery_inputs(tmp_path,{"endpoint_id":8},problem_text=problem,submission_pdf=b"%PDF-original",endpoint=endpoint())
    assert {p.relative_to(tmp_path).as_posix():p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before
    assert len(script.renders)==1 and not script.pure and not script.native
