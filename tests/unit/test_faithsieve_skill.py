"""旧 skill 主 Judge 的可执行投影、异步恢复、身份与结果安全边界。"""

import json
import os
from types import SimpleNamespace
from pathlib import Path

import pytest

from backend.oj_modules.faithsieve import skill
from backend.oj_modules.faithsieve.judge import FaithSievePending
from tests.unit.test_faithsieve_workflow import tree_payload
from tests.unit.test_faithsieve_proof_dag import node, single_claim
from backend.oj_modules.faithsieve.proof_dag import propagate_node_verdicts


@pytest.fixture
def environment(tmp_path, monkeypatch):
    run = {"attempt_id": "a" * 32, "status": "running", "execution_mode": "skill",
           "submission_id": 42, "problem_id": 5, "requested_by": "admin", "harness": "pi",
           "endpoint_id": 7, "elapsed_seconds": 120}
    submission = {"id": 42, "problem_id": 5, "username": "student"}
    problem = {"id": 5, "title": "完整证明题", "content": "全部自然条件、定义和结论。"}
    endpoint = {"id": 7, "model": "frozen-model", "revision": 3, "category": "omni"}
    sessions, turns, runtime, dispatched, loaders = {}, {}, {}, [], []
    sid, tid = skill.skill_identity(run)
    run["session_id"] = sid
    monkeypatch.setattr(skill, "get_agent_session", lambda key: sessions.get(key))
    monkeypatch.setattr(skill, "get_agent_session_turns", lambda key: turns.get(key, []))
    monkeypatch.setattr(skill, "get_agent_session_runtime_config", lambda key: runtime.get(key, {}))
    def dispatch(**kwargs):
        dispatched.append(kwargs)
        sessions[kwargs["session_id"]] = {
            "session_id": kwargs["session_id"], "current_task_id": kwargs["task_id"],
            "task_kind": "judge", "judge_kind": "faithsieve", "access_role": "user",
            "attempt_id": run["attempt_id"], "submission_id": run["submission_id"], "problem_id": run["problem_id"],
            "requested_by": "student", "competition_id": None, "harness": run["harness"],
            "endpoint_id": endpoint["id"], "endpoint_model": endpoint["model"], "status": "Running",
        }
        turns[kwargs["session_id"]] = [{"task_id": kwargs["task_id"], "user_message": kwargs["prompt"], "status": "Running"}]
        runtime[kwargs["session_id"]] = {"endpoint_source": "global"}
        for path, content in kwargs["files"].items():
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    monkeypatch.setattr(skill, "submit_judge_turn", dispatch)
    def open_file(_session, path):
        target = tmp_path / path
        return target.open("rb"), {"size": target.stat().st_size}
    monkeypatch.setattr(skill, "open_agent_workspace_file", open_file)
    def endpoint_loader():
        loaders.append("endpoint")
        return endpoint
    def pdf_loader():
        loaders.append("pdf")
        return b"%PDF-original-student-proof"
    class Tools:
        def __init__(self): self.calls = []
        def run(self, operation, payload, **kwargs):
            self.calls.append(operation)
            (Path(kwargs['workspace']) / 'page-1.png').write_bytes(b'\x89PNG\r\n\x1a\nrendered pixels')
            return {'page_count': 1, 'pages': [{'page': 1, 'rendered': True, 'image_path': '/workspace/page-1.png'}], 'exit_code': 0}
    tools = Tools()
    def adapter():
        return skill.FaithSieveSkillAgent(run=run, submission=submission, problem=problem, celery_app=object(),
                                        workspace=tmp_path / 'coordinator', tool_runner=tools)
    def execute():
        return adapter().execute(endpoint_loader=endpoint_loader, pdf_loader=pdf_loader)
    def completed(result=None):
        sessions[sid]["status"] = turns[sid][0]["status"] = "Completed"
        turns[sid][0].update(harness=run["harness"], endpoint_id=endpoint["id"], endpoint_model=endpoint["model"])
        (tmp_path / "faithsieve_result.json").write_text(json.dumps(result or {"verdict": "incorrect", "score": 2, "comment": "须重做核心路线"}), encoding="utf-8")
        (tmp_path / "faithsieve-work").mkdir(exist_ok=True)
        dag = single_claim()
        dag["nodes"][0].update(statement="1=2。", label="作者声称的等式", source_text="1=2。")
        dag["schema_version"] = 3
        dag["nodes"] = [{key: value for key, value in item.items() if key in {"id", "kind", "label", "statement"}}
                        for item in dag["nodes"]]
        (tmp_path / "faithsieve-work/tree.json").write_text(json.dumps(dag), encoding="utf-8")
        verdict = (result or {}).get("verdict", "incorrect")
        states = propagate_node_verdicts(dag, {"N1": "passed" if verdict == "correct" else "refuted"})
        (tmp_path / "faithsieve-work/node-verification.json").write_text(json.dumps({
            "schema_version": 1, "proof_dag": dag, "nodes": states, "target_ids": ["N1"],
            "targets_established": states["N1"]["established"], "target_coverage": "matched"}), encoding="utf-8")
        (tmp_path / "faithsieve-work/steps.md").write_text("## S1\n原稿第1页：1=2。", encoding="utf-8")
    return SimpleNamespace(run=run, submission=submission, problem=problem, endpoint=endpoint, sessions=sessions,
                           turns=turns, runtime=runtime, dispatched=dispatched, loaders=loaders, adapter=adapter,
                           execute=execute, completed=completed, sid=sid, tid=tid, root=tmp_path, tools=tools)


def test_skill_dispatch_projects_real_skill_and_original_task_material_once(environment):
    env = environment
    for _retry in range(3):
        with pytest.raises(FaithSievePending) as pending:
            env.execute()
        assert pending.value.session_id == env.sid and pending.value.task_id == env.tid
    assert len(env.dispatched) == 1 and env.loaders == ["endpoint", "pdf"]
    request = env.dispatched[0]
    assert request["project_skill"] is True and request["judge_kind"] == "faithsieve"
    assert request["requested_by"] == "student" and env.run["requested_by"] == "admin"
    assert request["timeout_seconds"] == skill.RUN_TIMEOUT_SECONDS - env.run["elapsed_seconds"]
    assert request["prompt"] == skill.SKILL_TASK_PROMPT
    assert request["files"]["problem.md"] == "# 完整证明题\n\n全部自然条件、定义和结论。\n\n## 评分\n\n满分 5 分。请按 FaithSieve skill 的量表评分。\n".encode()
    assert set(request["files"]) == {"problem.md", "pages.json", "source-pages/page-1.png", "faithsieve_result.json"}
    assert request["files"]["source-pages/page-1.png"].startswith(b'\x89PNG')
    assert json.loads(request["files"]["pages.json"]) == [{'page': 1, 'rendered': True, 'image_path': 'source-pages/page-1.png'}]
    assert env.tools.calls == ['extract']
    assert set(json.loads(request["files"]["faithsieve_result.json"])) == {"verdict", "score", "comment"}


@pytest.mark.parametrize("mode", [None, "missing", "skill"])
def test_old_skill_session_reuses_persisted_identity_without_model_or_pdf_reload(environment, mode):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    if mode == "missing":
        env.run.pop("execution_mode")
    else:
        env.run["execution_mode"] = mode
    env.completed()
    assert env.execute() == {"verdict": "incorrect", "score": 2, "comment": "须重做核心路线"}
    assert env.loaders == ["endpoint", "pdf"] and len(env.dispatched) == 1


@pytest.mark.parametrize("field,value", [("requested_by", "admin"), ("submission_id", 999), ("attempt_id", "foreign"), ("current_task_id", "foreign-task"), ("harness", "foreign"), ("endpoint_id", 999), ("problem_id", 999)])
def test_skill_session_mismatches_never_read_result_or_dispatch_fallback(environment, field, value):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.sessions[env.sid][field] = value
    with pytest.raises(ValueError, match="不一致"):
        env.execute()
    assert len(env.dispatched) == 1


def test_skill_resume_requires_original_instruction_and_actual_skill_projection(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.runtime[env.sid]["project_skill"] = False
    with pytest.raises(ValueError, match="技能投影"):
        env.execute()
    env.runtime[env.sid].pop("project_skill")
    env.turns[env.sid][0]["user_message"] = "SECRET-OTHER-PROMPT"
    with pytest.raises(ValueError, match="原始任务") as error:
        env.execute()
    assert "SECRET" not in str(error.value)


@pytest.mark.parametrize("status", ["Failed", "Canceled", "CleanupFailed"])
def test_failed_skill_has_no_automatic_workflow_fallback(environment, status):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.sessions[env.sid]["status"] = env.turns[env.sid][0]["status"] = status
    with pytest.raises(ValueError, match="未正常完成"):
        env.execute()
    assert len(env.dispatched) == 1


@pytest.mark.parametrize("result", [{"verdict": "correct", "score": True, "comment": "不合法"},
                                   {"verdict": "incorrect", "score": 2, "comment": "", "extra": "x"},
                                   {"verdict": "unknown", "score": 5, "comment": "不合法"}])
def test_skill_result_uses_original_strict_json_protocol(environment, result):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed(result)
    with pytest.raises(ValueError):
        env.execute()


def test_skill_result_rejects_hardlinked_host_file(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed()
    source = env.root / "faithsieve_result.json"
    os.link(source, env.root / "host-copy.json")
    with pytest.raises(ValueError, match="安全"):
        env.execute()


def test_skill_completed_actual_model_must_match_frozen_session(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed()
    env.turns[env.sid][0]["endpoint_model"] = "unrelated-model"
    with pytest.raises(ValueError, match="实际执行参数"):
        env.execute()


def test_skill_cancel_only_targets_its_single_persisted_judge(environment, monkeypatch):
    from backend.oj_modules.tasks.agent import control
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    terminated = []
    monkeypatch.setattr(control, "build_agent_run_terminator", lambda _app: lambda task_id: terminated.append(task_id) or {"canceled": True})
    env.adapter().cancel_pending()
    assert terminated == [env.tid]
    env.completed()
    env.adapter().cancel_pending()
    assert terminated == [env.tid]


def test_expired_skill_does_not_launch_new_judge(environment):
    environment.run["elapsed_seconds"] = skill.RUN_TIMEOUT_SECONDS
    with pytest.raises(ValueError, match="整体时限"):
        environment.execute()
    assert environment.dispatched == environment.loaders == []


def test_skill_rejects_text_only_model_before_loading_pdf_or_dispatch(environment):
    environment.endpoint['category'] = 'text'
    with pytest.raises(ValueError, match='全模态'):
        environment.execute()
    assert environment.loaders == ['endpoint']
    assert environment.dispatched == environment.tools.calls == []


def test_completed_historical_pdf_skill_prompt_still_reads_original_result(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.turns[env.sid][0]['user_message'] = (
        '请使用 faithsieve skill 批改 problem.md 中的题目与 submission.pdf 中的学生证明，'
        '并严格按 skill 规定覆盖写入 faithsieve_result.json。'
    )
    env.completed()
    assert env.execute()['verdict'] == 'incorrect'
    assert env.loaders == ['endpoint', 'pdf'] and env.tools.calls == ['extract']


def test_skill_adapter_rejects_persisted_workflow_mode(environment):
    environment.run["execution_mode"] = "workflow"
    with pytest.raises(ValueError, match="执行模式"):
        environment.adapter()


def test_skill_adapter_rejects_empty_mode_instead_of_treating_it_as_history(environment):
    environment.run["execution_mode"] = ""
    with pytest.raises(ValueError):
        environment.adapter()


def test_new_skill_conclusive_result_requires_valid_json_tree(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed()
    (env.root / "faithsieve-work/tree.json").write_text("# 旧 Markdown 树")
    with pytest.raises(ValueError, match="纯 JSON"):
        env.execute()


def test_skill_early_inconclusive_and_historical_image_prompt_do_not_require_new_tree(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed({"verdict": "inconclusive", "score": 0, "comment": "原稿无法辨认"})
    (env.root / "faithsieve-work/tree.json").unlink()
    (env.root / "faithsieve-work/steps.md").unlink()
    assert env.execute()["verdict"] == "inconclusive"
    env.turns[env.sid][0]["user_message"] = skill._IMAGE_TASK_PROMPT
    (env.root / "faithsieve_result.json").write_text(json.dumps({"verdict": "correct", "score": 5, "comment": "历史证明正确"}))
    assert env.execute()["verdict"] == "correct"


def test_new_skill_rejects_old_state_tree_without_silent_conversion(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed()
    (env.root / "faithsieve-work/tree.json").write_text(json.dumps(tree_payload()))
    with pytest.raises(ValueError):
        env.execute()
    assert len(env.dispatched) == 1


def test_historical_state_tree_prompt_keeps_original_v1_validation(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed()
    env.turns[env.sid][0]["user_message"] = skill._STATE_TREE_TASK_PROMPT
    (env.root / "faithsieve-work/tree.json").write_text(json.dumps(tree_payload()))
    before = (env.root / "faithsieve-work/tree.json").read_bytes()
    assert env.execute()["verdict"] == "incorrect"
    assert (env.root / "faithsieve-work/tree.json").read_bytes() == before
    assert len(env.dispatched) == 1


@pytest.mark.parametrize("mutation", ["graph", "graph_type", "unproven", "coverage", "target_bool", "irrelevant"])
def test_new_skill_conclusive_result_requires_node_evidence_gate(environment, mutation):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    correct = mutation != "irrelevant"
    env.completed({"verdict": "correct" if correct else "incorrect", "score": 5 if correct else 2, "comment": "评测报告"})
    path = env.root / "faithsieve-work/node-verification.json"
    summary = json.loads(path.read_text())
    if mutation == "graph":
        summary["proof_dag"]["nodes"][0]["statement"] = "另一份命题"
    elif mutation == "graph_type":
        summary["proof_dag"]["schema_version"] = 3.0
    elif mutation in {"unproven", "irrelevant"}:
        summary["nodes"] = propagate_node_verdicts(summary["proof_dag"], {"N1": "inconclusive"})
        summary["targets_established"] = False
    elif mutation == "coverage":
        summary["target_coverage"] = "missing"
    else:
        summary["targets_established"] = 1
    path.write_text(json.dumps(summary))
    with pytest.raises(ValueError):
        env.execute()
    assert len(env.dispatched) == 1


@pytest.mark.parametrize("verdict", ["correct", "incorrect"])
def test_new_skill_can_finish_without_checking_unrelated_claim(environment, verdict):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed({"verdict": verdict, "score": 5 if verdict == "correct" else 2, "comment": "评测报告"})
    path = env.root / "faithsieve-work/node-verification.json"
    summary = json.loads(path.read_text())
    summary["proof_dag"]["nodes"].append({key: value for key, value in node("N2", "独立声明").items()
                                        if key in {"id", "kind", "label", "statement"}})
    summary["nodes"] = propagate_node_verdicts(summary["proof_dag"], {"N1": "passed" if verdict == "correct" else "refuted"})
    path.write_text(json.dumps(summary))
    (env.root / "faithsieve-work/tree.json").write_text(json.dumps(summary["proof_dag"]))
    with (env.root / "faithsieve-work/steps.md").open("a") as steps:
        steps.write("\n## S2\n独立声明")
    assert env.execute()["verdict"] == verdict
    assert len(env.dispatched) == 1


def test_image_skill_completion_does_not_read_transcription_or_steps(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed()
    (env.root / "faithsieve-work/steps.md").unlink()
    assert env.execute()["verdict"] == "incorrect"
    assert len(env.dispatched) == 1


def test_historical_dependency_skill_keeps_original_v2_graph_and_steps(environment):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed()
    env.turns[env.sid][0]["user_message"] = skill._DEPENDENCY_TASK_PROMPT
    graph = single_claim()
    graph["nodes"][0].update(statement="1=2。", label="作者声称的等式", source_text="1=2。")
    (env.root / "faithsieve-work/tree.json").write_text(json.dumps(graph))
    states = propagate_node_verdicts(graph, {"N1": "refuted"})
    (env.root / "faithsieve-work/node-verification.json").write_text(json.dumps({
        "schema_version": 1, "proof_dag": graph, "nodes": states, "target_ids": ["N1"],
        "targets_established": False, "target_coverage": "matched"}))
    before = (env.root / "faithsieve-work/tree.json").read_bytes()
    assert env.execute()["verdict"] == "incorrect"
    assert (env.root / "faithsieve-work/tree.json").read_bytes() == before
    assert len(env.dispatched) == 1


@pytest.mark.parametrize("independent_status", ["inconclusive", "refuted"])
def test_new_skill_checked_irrelevant_claim_does_not_block_established_target(environment, independent_status):
    env = environment
    with pytest.raises(FaithSievePending):
        env.execute()
    env.completed({"verdict": "correct", "score": 5, "comment": "目标已证明"})
    path = env.root / "faithsieve-work/node-verification.json"
    summary = json.loads(path.read_text())
    summary["proof_dag"]["nodes"].append({key: value for key, value in node("N2", "独立声明").items()
                                        if key in {"id", "kind", "label", "statement"}})
    summary["nodes"] = propagate_node_verdicts(summary["proof_dag"], {"N1": "passed", "N2": independent_status})
    path.write_text(json.dumps(summary))
    (env.root / "faithsieve-work/tree.json").write_text(json.dumps(summary["proof_dag"]))
    with (env.root / "faithsieve-work/steps.md").open("a") as steps:
        steps.write("\n## S2\n独立声明")
    assert env.execute()["verdict"] == "correct"
    assert len(env.dispatched) == 1
