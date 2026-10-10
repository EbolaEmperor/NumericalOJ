"""局部 Judge 拿到完整原稿图片与联合命题，自主给结论，不依赖转录。"""

import base64
from copy import deepcopy
from datetime import datetime
import json
from types import SimpleNamespace

import pytest

from backend.oj_modules.faithsieve import judge, recovery, views
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from backend.oj_modules.faithsieve.recovery import read_native_timeout_authorization
from tests.unit.test_faithsieve_judge import environment, invoke
from tests.unit.test_faithsieve_views import saved


@pytest.mark.parametrize("status", ["passed", "refuted", "inconclusive"])
def test_local_image_judge_receives_all_original_images_and_reuses_complete_task(environment, status):
    env = environment
    files = {"problem.md": "题面", "pages.json": '[{"page":1,"image_path":"source-pages/page-1.png"},{"page":2,"image_path":"source-pages/page-2.png"}]',
             "source-pages/page-1.png": b'\x89PNG\r\n\x1a\nfirst-original',
             "source-pages/page-2.png": b'\x89PNG\r\n\x1a\nsecond-original',
             "faithsieve-work/obligations/N3/N3-O1.md": "直接前提A、B；目标C；验证A∧B⇒C"}
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "files": files,
                 "prompt": "读取全部原稿图片，自主验证整个局部蕴含。"}
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    assert env.submissions[0]["files"] == files
    assert env.tools.calls == []
    env.finish(pending.value.session_id, role="local-verifier", status=status,
               artifact="faithsieve-work/verification/N3.md", text="实际验证方法、依据和完整结论")
    result = invoke(env.agent, **arguments)
    assert result["result"]["status"] == status
    assert result["execution"]["decision_source"] == "agent"
    assert not {"verified", "tool_executed", "relations"} & result["execution"].keys()
    assert invoke(env.agent, **arguments) == result
    assert len(env.submissions) == 1 and env.tools.calls == []
    assert ".expressions.json" not in env.submissions[0]["prompt"]
    (env.root / "child" / pending.value.session_id / "source-pages/page-2.png").write_bytes(b"changed")
    with pytest.raises(judge.FaithSieveJudgeError, match="修改了输入"):
        invoke(env.agent, **arguments)


@pytest.mark.parametrize("status", ["passed", "refuted", "inconclusive", "graph_defect"])
def test_fresh_local_judge_freezes_and_reads_distinct_graph_diagnostic_protocol(environment, status):
    env = environment
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1,
                 "prompt": "核对原图与目标；构图有误时报告诊断。"}
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    request = env.agent.directory / "role-000001-attempt-1.json"
    frozen_before = (request.read_bytes(), request.stat().st_mtime_ns)
    frozen = json.loads(request.read_text())
    assert type(frozen["local_diagnostic_version"]) is int and frozen["local_diagnostic_version"] == 1
    assert 'set(result) == {"status", "artifact", "report", "diagnostics"}' in frozen["prompt"]
    assert "graph_defect" in frozen["prompt"]
    env.finish(pending.value.session_id, role="local-verifier", status=status,
               artifact="faithsieve-work/verification/N6.md", text="原图核对与完整局部验证报告。")
    result_path = env.root / "child" / pending.value.session_id / "result.json"
    payload = json.loads(result_path.read_text())
    payload["diagnostics"] = ([{"kind": "statement_mismatch", "affected_node_ids": ["N6"],
                                "reason": "原稿为 ŷ；节点错误地写成 ĝ。"}]
                              if status == "graph_defect" else [])
    result_path.write_text(json.dumps(payload, ensure_ascii=False))
    result = invoke(env.agent, **arguments)
    assert result["result"] == payload
    assert result["execution"]["decision_source"] == "agent"
    assert invoke(env.agent, **arguments) == result
    assert len(env.submissions) == 1 and not env.tools.calls
    assert (request.read_bytes(), request.stat().st_mtime_ns) == frozen_before
    with pytest.raises(judge.FaithSieveJudgeError, match="持久身份"):
        invoke(env.agent, **{**arguments, "local_diagnostic_version": None})
    assert len(env.submissions) == 1


@pytest.mark.parametrize("change", ["missing_diagnostics", "empty_defect", "defect_as_passed", "unknown_kind"])
def test_fresh_local_judge_rejects_mixed_graph_defect_and_mathematical_result(environment, change):
    env = environment
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1}
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    env.finish(pending.value.session_id, role="local-verifier", status="graph_defect",
               artifact="faithsieve-work/verification/N6.md", text="构图诊断报告。")
    result_path = env.root / "child" / pending.value.session_id / "result.json"
    payload = json.loads(result_path.read_text())
    payload["diagnostics"] = [{"kind": "statement_mismatch", "affected_node_ids": ["N6"], "reason": "数学对象改变。"}]
    if change == "missing_diagnostics":
        payload.pop("diagnostics")
    elif change == "empty_defect":
        payload["diagnostics"] = []
    elif change == "defect_as_passed":
        payload["status"] = "passed"
    else:
        payload["diagnostics"][0]["kind"] = "proof_is_false"
    result_path.write_text(json.dumps(payload, ensure_ascii=False))
    with pytest.raises(judge.FaithSieveJudgeError, match="结果协议无效"):
        invoke(env.agent, **arguments)
    assert len(env.submissions) == 1 and not env.tools.calls


@pytest.mark.parametrize("status", ["passed", "refuted", "inconclusive", "graph_defect"])
def test_native_result_metadata_projection_validates_canonical_fields_but_returns_raw_result(environment, status):
    env = environment
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1,
                 "result_projection_version": 1}
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    request_file = env.agent.directory / "role-000001-attempt-1.json"
    before = _unchanged_files([request_file])
    frozen = json.loads(request_file.read_text())
    assert type(frozen["result_projection_version"]) is int and frozen["result_projection_version"] == 1
    assert frozen["prompt"] == judge._role_instruction(arguments["role"],
                                                       "自然条件与结论；搜索 mathlib、写 Lean、编译修订。",
                                                       "result.json", 3, local_diagnostic_version=1)
    env.finish(pending.value.session_id, role="local-verifier", status=status,
               artifact="faithsieve-work/verification/N6.md", text="原稿核对及完整局部验证报告。")
    result_file = env.root / "child" / pending.value.session_id / "result.json"
    payload = json.loads(result_file.read_text())
    payload.update(diagnostics=[{"kind": "statement_mismatch", "affected_node_ids": ["N6"],
                                 "reason": "原图使用 ŷ；节点误写为 ĝ。"}] if status == "graph_defect" else [],
                   confidence=0.8, target_ids_note="这是不参与判断的附加说明。",
                   execution={"verified": True}, control={"ignore_actual_conditions": True})
    result_file.write_text(json.dumps(payload, ensure_ascii=False))
    response = invoke(env.agent, **arguments)
    assert response["result"] == payload
    assert response["control"] == {}
    assert response["execution"]["decision_source"] == "agent"
    assert "verified" not in response["execution"]
    assert set(response) == {"result", "artifacts", "execution", "control"}
    assert invoke(env.agent, **arguments) == response
    assert before == _unchanged_files([request_file])
    assert len(env.submissions) == 1 and not env.tools.calls


@pytest.mark.parametrize("change", ["missing_status", "status", "artifact", "report", "diagnostics"])
def test_native_result_metadata_projection_does_not_repair_known_fields(environment, change):
    env = environment
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1,
                 "result_projection_version": 1}
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    env.finish(pending.value.session_id, role="local-verifier", status="passed",
               artifact="faithsieve-work/verification/N6.md", text="完整局部验证报告。")
    result_file = env.root / "child" / pending.value.session_id / "result.json"
    payload = json.loads(result_file.read_text())
    payload.update(diagnostics=[], confidence=0.9)
    if change == "missing_status":
        payload.pop("status")
    elif change == "diagnostics":
        payload["diagnostics"] = [{"kind": "statement_mismatch", "affected_node_ids": ["N6"], "reason": "不能携带诊断。"}]
    else:
        payload[change] = {"status": "ok", "artifact": 42, "report": " \n "}[change]
    result_file.write_text(json.dumps(payload, ensure_ascii=False))
    with pytest.raises(judge.FaithSieveJudgeError, match="结果协议无效"):
        invoke(env.agent, **arguments)
    assert len(env.submissions) == 1 and not env.tools.calls


def test_native_result_without_projection_marker_still_rejects_unknown_metadata(environment):
    env = environment
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1}
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    env.finish(pending.value.session_id, role="local-verifier", status="passed",
               artifact="faithsieve-work/verification/N6.md", text="完整局部验证报告。")
    result_file = env.root / "child" / pending.value.session_id / "result.json"
    payload = json.loads(result_file.read_text())
    payload.update(diagnostics=[], confidence=0.8)
    result_file.write_text(json.dumps(payload, ensure_ascii=False))
    with pytest.raises(judge.FaithSieveJudgeError, match="结果协议无效"):
        invoke(env.agent, **arguments)
    assert len(env.submissions) == 1


@pytest.mark.parametrize("version", [True, 1.0, "1", 0, 2])
def test_native_result_projection_version_requires_exact_integer_one(environment, version):
    with pytest.raises(FaithSieveProtocolError, match="投影版本无效"):
        invoke(environment.agent, role="local-verifier", proof_graph_version=3,
               local_diagnostic_version=1, result_projection_version=version)
    assert not environment.submissions


@pytest.mark.parametrize("arguments", [
    {"role": "local-verifier", "proof_graph_version": 3},
    {"role": "numeric-evaluator", "proof_graph_version": 3},
    {"role": "statement-formalizer", "proof_graph_version": 1},
])
def test_native_result_projection_cannot_upgrade_other_protocols(environment, arguments):
    with pytest.raises(judge.FaithSieveJudgeError, match="仅适用于新版图像局部验证"):
        invoke(environment.agent, **arguments, result_projection_version=1)
    assert not environment.submissions


@pytest.mark.parametrize("initial,changed", [(None, 1), (1, None)])
def test_native_result_projection_marker_cannot_change_a_frozen_invocation(environment, initial, changed):
    env = environment
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1,
                 "result_projection_version": initial}
    with pytest.raises(judge.FaithSievePending):
        invoke(env.agent, **arguments)
    before = _unchanged_files([env.agent.directory / "role-000001-attempt-1.json"])
    with pytest.raises(judge.FaithSieveJudgeError, match="持久身份"):
        invoke(env.agent, **{**arguments, "result_projection_version": changed})
    assert before == _unchanged_files(before)
    assert len(env.submissions) == 1


def test_native_result_projection_frozen_bool_cannot_equal_integer_one(environment):
    env = environment
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1,
                 "result_projection_version": 1}
    with pytest.raises(judge.FaithSievePending):
        invoke(env.agent, **arguments)
    path = env.agent.directory / "role-000001-attempt-1.json"
    frozen = json.loads(path.read_text())
    frozen["result_projection_version"] = True
    path.write_text(json.dumps(frozen))
    with pytest.raises(judge.FaithSieveJudgeError, match="持久身份"):
        invoke(env.agent, **arguments)
    assert len(env.submissions) == 1


def test_code_renders_images_without_dispatching_source_agent(environment):
    env = environment
    rendered = env.agent.render_submission_images(b"%PDF-original-image")
    assert rendered["files"]["source-pages/page-1.png"].startswith(b"\x89PNG")
    assert set(rendered["files"]) == {"pages.json", "source-pages/page-1.png"}
    assert len(env.tools.calls) == 1 and not env.submissions
    assert env.agent.render_submission_images(b"%PDF-original-image") == rendered
    assert len(env.tools.calls) == 1 and not env.submissions


def test_image_judge_frozen_protocol_type_drift_is_rejected(environment):
    env = environment
    with pytest.raises(judge.FaithSievePending):
        invoke(env.agent, role="local-verifier", proof_graph_version=3)
    path = env.agent.directory / "role-000001-attempt-1.json"
    value = json.loads(path.read_text())
    value["proof_graph_version"] = 3.0
    path.write_text(json.dumps(value))
    with pytest.raises(judge.FaithSieveJudgeError, match="持久身份"):
        invoke(env.agent, role="local-verifier", proof_graph_version=3)
    assert len(env.submissions) == 1


def _unchanged_files(paths):
    return {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}


@pytest.fixture
def native_continuation(environment, monkeypatch):
    """真实 adapter 的失败历史保持不变，续聊提交只追加同 SID 第二轮。"""
    env = environment
    key = "role-000001-attempt-1"
    result_path = "faithsieve-work/results/N3-local-verifier.json"
    inputs = {
        "problem.md": "固定共享对象，验证所有直接前提共同推出完整目标。",
        "pages.json": '[{"page":1,"image_path":"source-pages/page-1.png"}]',
        "source-pages/page-1.png": b"\x89PNG\r\n\x1a\noriginal-image",
        "faithsieve-work/obligations/N3/N3-O1.md": "共同前提 A、B；目标 C；保留全部量词。",
    }
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "files": inputs,
                 "prompt": "读取全部原图，独立完成完整局部验证。", "timeout_seconds": 600,
                 "expected_result_path": result_path, "invocation_key": key}
    env.agent.run["elapsed_seconds"] = 1200
    env.agent.run["endpoint_id"] = env.endpoint["id"]
    with pytest.raises(judge.FaithSievePending) as initial:
        invoke(env.agent, **arguments)
    sid, tid = initial.value.session_id, initial.value.task_id
    native_id = "original-pi-native-session"
    env.sessions[sid].update(status="Failed", message="Agent harness 超时", native_session_id=native_id)
    env.turns[sid][0].update(status="Failed", harness=env.run["harness"],
                             endpoint_id=env.endpoint["id"], endpoint_model=env.endpoint["model"])
    original_turn = deepcopy(env.turns[sid][0])
    checkpoint_request = {"role": "local-verifier", "proof_graph_version": 3,
                          "files": {path: value for path, value in inputs.items() if isinstance(value, str)},
                          "images": {path: base64.b64encode(value).decode()
                                     for path, value in inputs.items() if isinstance(value, bytes)},
                          "endpoint": {"model": env.endpoint["model"]},
                          "parameters": {"node_id": "N3"}, "expected_result_path": result_path,
                          "agent_prompt": arguments["prompt"]}
    store = CheckpointStore(env.agent.workspace)
    store.put(key, checkpoint_request, state="pending", metadata={"node_id": "N3"})
    record, _size = store._read_record(key, strict=True)
    immutable_paths = [env.agent.directory / f"{key}.json", store.directory / f"{key}.json"]
    immutable_paths += list((env.agent.directory / key / "inputs").rglob("*"))
    immutable_paths += list((env.root / "child" / sid).rglob("*"))
    immutable_paths = [path for path in immutable_paths if path.is_file()]
    frozen_files = _unchanged_files(immutable_paths)
    authorization = {
        "kind": "native_timeout", "session_id": sid, "failed_task_id": tid,
        "original_timeout_seconds": 600, "continuation_task_id": tid + "-c1",
        "continuation_timeout_seconds": 6000,
        "continuation_prompt": judge._continuation_prompt(result_path),
    }
    inspections, authorizations = [], []

    def authorize(workspace, run, actual_key, actual_record, actual_request):
        assert workspace == env.agent.workspace and actual_key == key
        assert actual_record == record and actual_request == checkpoint_request
        assert _unchanged_files(immutable_paths) == frozen_files
        authorizations.append(deepcopy(run))
        return deepcopy(authorization)

    def inspect(workspace, run, actual_key, actual_record):
        assert workspace == env.agent.workspace and actual_key == key and actual_record == record
        assert env.sessions[sid]["status"] == "Failed"
        assert env.sessions[sid]["native_session_id"] == native_id
        assert env.turns[sid] == [original_turn]
        assert _unchanged_files(immutable_paths) == frozen_files
        inspections.append(deepcopy(run))
        return deepcopy(authorization)

    def append_turn(**kwargs):
        assert kwargs["session_id"] == sid and kwargs["task_id"] == tid + "-c1"
        assert kwargs["files"] is None and kwargs["timeout_seconds"] == 6000
        assert kwargs["prompt"] == authorization["continuation_prompt"]
        assert env.turns[sid] == [original_turn]
        assert env.sessions[sid]["native_session_id"] == native_id
        assert _unchanged_files(immutable_paths) == frozen_files
        env.submissions.append(kwargs)
        env.sessions[sid].update(current_task_id=kwargs["task_id"], status="Running")
        env.turns[sid].append({"task_id": kwargs["task_id"], "user_message": kwargs["prompt"],
                               "status": "Running"})
        return env.sessions[sid]

    monkeypatch.setattr(recovery, "read_native_timeout_authorization", authorize)
    monkeypatch.setattr(judge, "inspect_native_timeout", inspect)
    monkeypatch.setattr(judge, "submit_judge_turn", append_turn)
    return SimpleNamespace(env=env, arguments=arguments, sid=sid, tid=tid, authorization=authorization,
                           original_turn=original_turn, native_id=native_id, immutable_paths=immutable_paths,
                           frozen_files=frozen_files, inspections=inspections, authorizations=authorizations)


def test_native_timeout_continuation_reuses_failed_session_and_reads_actual_completed_outputs(native_continuation):
    continuation = native_continuation
    env = continuation.env
    for elapsed in (1200, 3600, 5400):
        env.agent.run["elapsed_seconds"] = elapsed
        with pytest.raises(judge.FaithSievePending) as pending:
            invoke(env.agent, **continuation.arguments)
        assert pending.value.session_id == continuation.sid
        assert pending.value.task_id == continuation.tid + "-c1"
    assert len(env.submissions) == 2 and len(continuation.inspections) == 1
    assert len(continuation.authorizations) == 3
    assert len(env.turns[continuation.sid]) == 2
    assert env.turns[continuation.sid][0] == continuation.original_turn
    assert env.sessions[continuation.sid]["native_session_id"] == continuation.native_id
    saved_continuation = env.agent.directory / continuation.arguments["invocation_key"] / "continuation.json"
    assert json.loads(saved_continuation.read_text()) == continuation.authorization
    persisted_continuation = _unchanged_files([saved_continuation])

    child = env.root / "child" / continuation.sid
    artifact = "faithsieve-work/verification/N3.md"
    payload = {"status": "inconclusive", "artifact": artifact, "report": "完整局部蕴含仍有未解决的作用域问题。"}
    result_file = child / continuation.arguments["expected_result_path"]
    result_file.parent.mkdir(parents=True, exist_ok=True)
    result_file.write_text(json.dumps(payload, ensure_ascii=False))
    output_file = child / artifact
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("续跑实际产物：核对了全部前提与目标，未把辅助引理当成完整证明。")
    env.sessions[continuation.sid]["status"] = "Completed"
    env.turns[continuation.sid][1].update(status="Completed", harness=env.run["harness"],
                                         endpoint_id=env.endpoint["id"], endpoint_model=env.endpoint["model"])
    result = invoke(env.agent, **continuation.arguments)
    assert result["result"] == payload
    assert result["artifacts"] == {artifact: output_file.read_text()}
    assert result["execution"]["session_id"] == continuation.sid
    assert result["execution"]["task_id"] == continuation.tid + "-c1"
    assert result["execution"]["decision_source"] == "agent"
    assert invoke(env.agent, **continuation.arguments) == result
    assert len(env.submissions) == 2 and env.tools.calls == []
    assert env.turns[continuation.sid][0] == continuation.original_turn
    assert env.sessions[continuation.sid]["native_session_id"] == continuation.native_id
    assert _unchanged_files(continuation.immutable_paths) == continuation.frozen_files
    assert _unchanged_files([saved_continuation]) == persisted_continuation


def test_cancel_pending_terminates_native_continuation_instead_of_original_failed_turn(native_continuation, monkeypatch):
    from backend.oj_modules.tasks.agent import control

    continuation = native_continuation
    env = continuation.env
    with pytest.raises(judge.FaithSievePending):
        invoke(env.agent, **continuation.arguments)
    canceled = []

    def terminate(task_id):
        canceled.append(task_id)
        env.sessions[continuation.sid]["status"] = "Canceled"
        env.turns[continuation.sid][1]["status"] = "Canceled"
        return {"canceled": True, "errors": []}

    monkeypatch.setattr(control, "build_agent_run_terminator", lambda _app: terminate)
    env.agent.cancel_pending()
    env.agent.cancel_pending()
    assert canceled == [continuation.tid + "-c1"]
    assert env.turns[continuation.sid][0] == continuation.original_turn
    assert env.sessions[continuation.sid]["native_session_id"] == continuation.native_id
    assert _unchanged_files(continuation.immutable_paths) == continuation.frozen_files
    assert len(env.submissions) == 2 and env.tools.calls == []


def _persist_native_continuation_authorization(continuation):
    """测试写入真实私有授权，清理兼容必须核对其身份与原检查点。"""
    env = continuation.env
    key = continuation.arguments['invocation_key']
    env.agent.run.update(execution_mode='workflow', session_id='faithsieve-' + env.run['attempt_id'],
                         started_at=datetime(2026, 10, 10, 8, 0), status='running')
    record, _size = CheckpointStore(env.agent.workspace)._read_record(key, strict=True)
    permission = {'attempt_id': env.run['attempt_id'], 'actor': 'admin',
                  'created_at': '2026-10-10T00:20:00+00:00', 'target_key': key,
                  'request': record['request'], 'run_identity': recovery._run_identity(env.agent.run),
                  'native_timeout': deepcopy(continuation.authorization)}
    path = env.agent.workspace / recovery.AUTHORIZATION_FILENAME
    path.write_text(json.dumps(permission, ensure_ascii=False))
    path.chmod(0o600)
    return path


def _complete_native_continuation(continuation):
    env = continuation.env
    artifact = 'faithsieve-work/verification/N3.md'
    payload = {'status': 'inconclusive', 'artifact': artifact, 'report': '完整局部验证仍未解决。'}
    root = env.root / 'child' / continuation.sid
    path = root / continuation.arguments['expected_result_path']
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False))
    output = root / artifact
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text('原续聊的完整局部验证报告。')
    env.sessions[continuation.sid]['status'] = 'Completed'
    env.turns[continuation.sid][1].update(status='Completed', harness=env.run['harness'],
                                         endpoint_id=env.endpoint['id'], endpoint_model=env.endpoint['model'])
    return payload


def test_authorized_historical_continuation_replays_original_prompt_and_reads_completed_result(native_continuation, monkeypatch):
    continuation = native_continuation
    continuation.authorization['continuation_prompt'] = '已获授权的旧版完整验证职责，保持原输入。'
    assert continuation.authorization['continuation_prompt'] != judge._continuation_prompt(
        continuation.arguments['expected_result_path'])
    permission_path = _persist_native_continuation_authorization(continuation)
    monkeypatch.setattr(recovery, 'read_native_timeout_authorization', read_native_timeout_authorization)
    with pytest.raises(judge.FaithSievePending):
        invoke(continuation.env.agent, **continuation.arguments)
    payload = _complete_native_continuation(continuation)
    env = continuation.env
    record, _size = CheckpointStore(env.agent.workspace)._read_record(continuation.arguments['invocation_key'], strict=True)
    before = _readonly_workspace_snapshot(env.root)
    assert invoke(env.agent, **continuation.arguments)['result'] == payload
    _forbid_native_inspection_writes(monkeypatch)
    result = judge.inspect_completed_native(env.agent.workspace, env.agent.run,
                                            continuation.arguments['invocation_key'], record)
    assert result['result'] == payload
    assert env.turns[continuation.sid][1]['user_message'] == continuation.authorization['continuation_prompt']
    assert json.loads(permission_path.read_text())['native_timeout'] == continuation.authorization
    assert _readonly_workspace_snapshot(env.root) == before
    assert len(env.submissions) == 2 and env.tools.calls == []


def test_authorized_historical_continuation_can_be_canceled_after_whole_budget_expired(native_continuation, monkeypatch):
    from backend.oj_modules.tasks.agent import control

    continuation = native_continuation
    continuation.authorization['continuation_prompt'] = '原管理员已授权的旧职责全文。'
    _persist_native_continuation_authorization(continuation)
    monkeypatch.setattr(recovery, 'read_native_timeout_authorization', read_native_timeout_authorization)
    with pytest.raises(judge.FaithSievePending):
        invoke(continuation.env.agent, **continuation.arguments)
    continuation.env.agent.run['elapsed_seconds'] = 7200
    before = _readonly_workspace_snapshot(continuation.env.root)
    canceled = []

    def terminate(task):
        canceled.append(task)
        continuation.env.sessions[continuation.sid]['status'] = 'Canceled'
        continuation.env.turns[continuation.sid][1]['status'] = 'Canceled'
        return {'canceled': True, 'errors': []}

    monkeypatch.setattr(control, 'build_agent_run_terminator', lambda _app: terminate)
    continuation.env.agent.cancel_pending()
    continuation.env.agent.cancel_pending()
    assert canceled == [continuation.tid + '-c1']
    assert _readonly_workspace_snapshot(continuation.env.root) == before
    assert continuation.env.turns[continuation.sid][0] == continuation.original_turn
    assert len(continuation.env.submissions) == 2 and continuation.env.tools.calls == []


@pytest.mark.parametrize(('field', 'value'), [
    ('continuation_prompt', '未经授权的新指令'), ('session_id', 'another-session'),
    ('failed_task_id', 'another-original'), ('continuation_task_id', 'another-continuation'),
    ('original_timeout_seconds', 601), ('original_timeout_seconds', True),
    ('continuation_timeout_seconds', 5999), ('continuation_timeout_seconds', True),
])
def test_historical_continuation_rejects_drift_from_exact_authorized_contract(native_continuation, field, value):
    continuation = native_continuation
    continuation.authorization['continuation_prompt'] = '旧版已冻结且获授权的完整职责。'
    path = continuation.env.agent.directory / (continuation.arguments['invocation_key'] + '.json')
    frozen = json.loads(path.read_text())
    altered = {**continuation.authorization, field: value}
    with pytest.raises(judge.FaithSieveJudgeError, match='完整管理员授权'):
        judge.validate_native_continuation(altered, frozen, authorization=continuation.authorization)
    with pytest.raises(judge.FaithSieveJudgeError, match='冻结身份或指令'):
        judge.validate_native_continuation(continuation.authorization, frozen)
    assert judge.validate_native_continuation(continuation.authorization, frozen,
                                             authorization=continuation.authorization) == continuation.authorization
    current = {**continuation.authorization, 'continuation_prompt': judge._continuation_prompt(frozen['result_path'])}
    assert judge.validate_native_continuation(current, frozen) == current


@pytest.mark.parametrize('corruption', ['missing_authorization', 'continuation_prompt', 'authorized_prompt',
                                      'authorized_budget', 'authorized_identity', 'authorized_request',
                                      'checkpoint_request', 'session_prompt', 'session_task'])
@pytest.mark.parametrize('operation', ['cleanup', 'completed_read'])
def test_historical_continuation_cleanup_requires_matching_private_authorization_and_actual_turn(
        native_continuation, monkeypatch, corruption, operation):
    from backend.oj_modules.tasks.agent import control

    continuation = native_continuation
    continuation.authorization['continuation_prompt'] = '旧版已冻结且获授权的完整职责。'
    permission_path = _persist_native_continuation_authorization(continuation)
    monkeypatch.setattr(recovery, 'read_native_timeout_authorization', read_native_timeout_authorization)
    with pytest.raises(judge.FaithSievePending):
        invoke(continuation.env.agent, **continuation.arguments)
    env = continuation.env
    if operation == 'completed_read':
        _complete_native_continuation(continuation)
    saved_path = env.agent.directory / continuation.arguments['invocation_key'] / 'continuation.json'
    permission = json.loads(permission_path.read_text())
    if corruption == 'missing_authorization':
        permission_path.unlink()
    elif corruption == 'continuation_prompt':
        saved = json.loads(saved_path.read_text())
        saved['continuation_prompt'] = '未经授权的替换指令。'
        saved_path.write_text(json.dumps(saved))
    elif corruption == 'authorized_prompt':
        permission['native_timeout']['continuation_prompt'] = '授权文件与原续聊文件不相同。'
    elif corruption == 'authorized_budget':
        permission['native_timeout']['continuation_timeout_seconds'] -= 1
    elif corruption == 'authorized_identity':
        permission['run_identity']['harness'] = 'other-harness'
    elif corruption == 'authorized_request':
        permission['request']['files']['problem.md'] = '更换数学输入。'
    elif corruption == 'checkpoint_request':
        store = CheckpointStore(env.agent.workspace)
        path = store._path(continuation.arguments['invocation_key'])
        record = json.loads(path.read_text())
        record['request']['files']['problem.md'] = '更换数学输入。'
        path.write_text(json.dumps(record))
    elif corruption == 'session_prompt':
        env.turns[continuation.sid][1]['user_message'] = '数据库中是另一职责。'
    else:
        env.turns[continuation.sid][1]['task_id'] = 'another-task'
    if corruption.startswith('authorized_'):
        permission_path.write_text(json.dumps(permission))
    canceled = []
    monkeypatch.setattr(control, 'build_agent_run_terminator', lambda _app: lambda task: canceled.append(task))
    before = _readonly_workspace_snapshot(env.root)
    with pytest.raises((judge.FaithSieveJudgeError, recovery.FaithSieveRecoveryError)):
        if operation == 'cleanup':
            env.agent.cancel_pending()
        else:
            record, _size = CheckpointStore(env.agent.workspace)._read_record(
                continuation.arguments['invocation_key'], strict=True)
            judge.inspect_completed_native(env.agent.workspace, env.agent.run,
                                           continuation.arguments['invocation_key'], record)
    assert canceled == [] and len(env.submissions) == 2 and env.tools.calls == []
    assert _readonly_workspace_snapshot(env.root) == before


@pytest.mark.parametrize("elapsed_seconds", [0, 1200])
def test_new_local_image_judge_defaults_to_frozen_remaining_whole_budget(environment, elapsed_seconds):
    env = environment
    env.agent.run["elapsed_seconds"] = elapsed_seconds
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "timeout_seconds": None}
    with pytest.raises(judge.FaithSievePending):
        invoke(env.agent, **arguments)
    frozen = env.agent.directory / "role-000001-attempt-1.json"
    original = _unchanged_files([frozen])
    assert env.submissions[0]["timeout_seconds"] == 7200 - elapsed_seconds
    assert json.loads(frozen.read_text())["timeout_seconds"] == 7200 - elapsed_seconds
    env.agent.run["elapsed_seconds"] = 7100
    with pytest.raises(judge.FaithSievePending):
        invoke(env.agent, **arguments)
    assert _unchanged_files([frozen]) == original
    assert len(env.submissions) == 1


def test_image_workflow_view_links_same_native_session_continuation_without_rewriting_history(saved):
    key = "role-000001-attempt-1"
    request = {"role": "local-verifier", "proof_graph_version": 3, "files": {},
               "parameters": {"node_id": "N3"},
               "expected_result_path": "faithsieve-work/results/N3-local-verifier.json"}
    saved.store.put(key, request, state="pending")
    sid, tid = saved.native(key, "local-verifier")
    record_path = f"faithsieve-work/judge-invocations/{key}.json"
    original_record = json.loads((saved.workspace / record_path).read_text())
    original_record.update(proof_graph_version=3, timeout_seconds=600,
                           result_path="faithsieve-work/results/N3-local-verifier.json")
    saved.write(record_path, original_record)
    authorization = {
        "kind": "native_timeout", "session_id": sid, "failed_task_id": tid,
        "original_timeout_seconds": 600, "continuation_task_id": tid + "-c1",
        "continuation_timeout_seconds": 6000,
        "continuation_prompt": judge._continuation_prompt(original_record["result_path"]),
    }
    saved.write(f"faithsieve-work/judge-invocations/{key}/continuation.json", authorization)
    saved.sessions[sid].update(current_task_id=tid + "-c1", native_session_id="same-pi-native-session")
    before = _unchanged_files(path for path in saved.root.rglob("*") if path.is_file())
    stage = views.workflow_snapshot(saved.run)["stages"][0]
    assert stage["session_id"] == sid and stage["task_id"] == tid + "-c1"
    assert stage["judge_status"] == "Running" and stage["state"] == "pending"
    assert stage["parameters"]["node_id"] == "N3"
    assert _unchanged_files(before) == before


def _readonly_workspace_snapshot(root):
    """比较整棵目录的内容与时间，也发现新增或删除的文件、目录。"""
    return {path.relative_to(root).as_posix():
            (path.read_bytes() if path.is_file() else None, path.stat().st_mtime_ns)
            for path in [root, *root.rglob("*")]}


def _forbid_native_inspection_writes(monkeypatch):
    from backend.oj_modules.faithsieve import checkpoints

    def forbidden(*_args, **_kwargs):
        pytest.fail("已完成 Native 的只读检查不能派发、冻结或写入")
    monkeypatch.setattr(judge, "submit_judge_turn", forbidden)
    monkeypatch.setattr(judge, "atomic_write", forbidden)
    monkeypatch.setattr(checkpoints, "atomic_write", forbidden)
    monkeypatch.setattr(judge.FaithSieveJudgeAgent, "_freeze_request", forbidden)


@pytest.mark.parametrize("projection_version", [None, 1])
def test_completed_native_inspection_preserves_new_graph_defect_without_dispatch_or_write(environment, monkeypatch, projection_version):
    env = environment
    key = "role-000002-attempt-1"
    result_path = "faithsieve-work/results/N6-local-verifier.json"
    artifact = "faithsieve-work/verification/N6.md"
    inputs = {"problem.md": "完整题面和统一量词。", "pages.json": '[{"page":1,"image_path":"source-pages/page-1.png"}]',
              "source-pages/page-1.png": b"\x89PNG\r\n\x1a\noriginal-page",
              "faithsieve-work/obligations/N6/N6-O1.md": "直接前提与完整目标；只报告构图缺陷。"}
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1,
                 "files": inputs, "prompt": "原图与节点不符时使用 graph_defect 结构化诊断。",
                 "expected_result_path": result_path, "invocation_key": key}
    if projection_version is not None:
        arguments["result_projection_version"] = projection_version
    env.agent.run["endpoint_id"] = env.endpoint["id"]
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    request = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1,
               "agent_prompt": arguments["prompt"], "expected_result_path": result_path,
               "files": {path: value for path, value in inputs.items() if isinstance(value, str)},
               "images": {path: base64.b64encode(value).decode() for path, value in inputs.items() if isinstance(value, bytes)},
               "endpoint": {"model": env.endpoint["model"]}, "parameters": {"node_id": "N6"}}
    if projection_version is not None:
        request["result_projection_version"] = projection_version
    store = CheckpointStore(env.agent.workspace)
    store.put(key, request, state="pending")
    record, _size = store._read_record(key, strict=True)
    env.finish(pending.value.session_id, role="local-verifier", status="graph_defect", artifact=artifact,
               text="原稿条件存在，但 DAG 没有连入目标的直接前提。")
    payload = {"status": "graph_defect", "artifact": artifact, "report": "需修复直接依赖。",
               "diagnostics": [{"kind": "missing_premise", "affected_node_ids": ["N6"],
                                "reason": "目标的原稿条件未列入直接前提。"}]}
    if projection_version is not None:
        payload.update(confidence=0.7, target_ids_note="原始额外元数据应由编排器保留。")
    result_file = env.root / "child" / pending.value.session_id / result_path
    result_file.parent.mkdir(parents=True, exist_ok=True)
    result_file.write_text(json.dumps(payload, ensure_ascii=False))
    expected = invoke(env.agent, **arguments)
    before = _readonly_workspace_snapshot(env.root)
    _forbid_native_inspection_writes(monkeypatch)
    assert judge.inspect_completed_native(env.agent.workspace, env.agent.run, key, record) == expected
    assert expected["result"] == payload
    assert _readonly_workspace_snapshot(env.root) == before
    assert len(env.submissions) == 1 and not env.tools.calls
    if projection_version is not None:
        drifted = deepcopy(record)
        drifted["request"].pop("result_projection_version")
        with pytest.raises(judge.FaithSieveJudgeError, match="投影协议不一致"):
            judge.inspect_completed_native(env.agent.workspace, env.agent.run, key, drifted)
        drifted["request"]["result_projection_version"] = True
        with pytest.raises(FaithSieveProtocolError, match="投影版本无效"):
            judge.inspect_completed_native(env.agent.workspace, env.agent.run, key, drifted)
        assert _readonly_workspace_snapshot(env.root) == before


@pytest.fixture
def completed_native(environment, monkeypatch):
    """原生任务已完成，但宿主仍保留原始 pending 检查点。"""
    env = environment
    key = "role-000002-attempt-1"
    result_path = "faithsieve-work/results/N4-local-verifier.json"
    artifact = "faithsieve-work/verification/N4.md"
    inputs = {
        "problem.md": "固定共享参数；联合前提 A、B 推出完整命题 C。",
        "pages.json": '[{"page":1,"image_path":"source-pages/page-1.png"}]',
        "source-pages/page-1.png": b"\x89PNG\r\n\x1a\ncompleted-original-image",
        "faithsieve-work/obligations/N4/N4-O1.md": "保留共同见证、概率事件和所有量词。",
    }
    arguments = {"role": "local-verifier", "proof_graph_version": 3, "files": inputs,
                 "prompt": "完整核对所有原图、直接前提与目标，独立验证联合蕴含。",
                 "timeout_seconds": None, "expected_result_path": result_path, "invocation_key": key}
    env.agent.run.update(endpoint_id=env.endpoint["id"], elapsed_seconds=1200)
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    sid, tid = pending.value.session_id, pending.value.task_id
    env.sessions[sid].update(status="Completed", native_session_id="completed-pi-session")
    env.turns[sid][0].update(status="Completed", harness=env.run["harness"],
                             endpoint_id=env.endpoint["id"], endpoint_model=env.endpoint["model"])
    request = {"role": "local-verifier", "proof_graph_version": 3,
               "agent_prompt": arguments["prompt"], "expected_result_path": result_path,
               "files": {path: value for path, value in inputs.items() if isinstance(value, str)},
               "images": {path: base64.b64encode(value).decode()
                          for path, value in inputs.items() if isinstance(value, bytes)},
               "endpoint": {"model": env.endpoint["model"]}, "parameters": {"node_id": "N4"}}
    store = CheckpointStore(env.agent.workspace)
    store.put(key, request, state="pending", metadata={"node_id": "N4"})
    record, _size = store._read_record(key, strict=True)
    child = env.root / "child" / sid
    result_file = child / result_path
    result_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {"status": "passed", "artifact": artifact, "report": "已验证所有直接前提共同推出完整结论。"}
    result_file.write_text(json.dumps(payload, ensure_ascii=False))
    output_file = child / artifact
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("原生实际数学报告：共享参数、完整目标和证明依据均保留。")
    before = _readonly_workspace_snapshot(env.root)
    expected = invoke(env.agent, **arguments)
    assert _readonly_workspace_snapshot(env.root) == before
    assert store._read_record(key, strict=True)[0]["state"] == "pending"
    _forbid_native_inspection_writes(monkeypatch)
    return SimpleNamespace(env=env, key=key, sid=sid, tid=tid, record=record,
                           arguments=arguments, result_file=result_file, output_file=output_file,
                           expected=expected)


def test_completed_native_inspection_reads_same_response_as_adapter_without_any_write(completed_native):
    completed = completed_native
    env = completed.env
    before = _readonly_workspace_snapshot(env.root)
    histories = deepcopy((env.sessions, env.turns))
    result = judge.inspect_completed_native(env.agent.workspace, env.agent.run, completed.key, completed.record)
    assert result == completed.expected
    assert result["artifacts"] == {completed.output_file.relative_to(env.root / "child" / completed.sid).as_posix():
                                   completed.output_file.read_text()}
    assert result["execution"]["task_id"] == completed.tid
    assert _readonly_workspace_snapshot(env.root) == before
    assert (env.sessions, env.turns) == histories
    assert len(env.submissions) == 1 and env.tools.calls == []


@pytest.mark.parametrize("change, message", [
    ("native_image", "修改了原始材料"),
    ("frozen_input", "原始材料不一致"),
    ("turn_model", "实际执行参数不一致"),
    ("turn_prompt", "轮次身份或完整指令不一致"),
    ("missing_artifact", "结果文件无法安全读取"),
    ("invalid_json", "可解析 JSON"),
    ("duplicate_json", "重复字段"),
    ("wrong_status", "结果协议无效"),
    ("native_failed", "尚未正常完成"),
])
def test_completed_native_inspection_refuses_untrustworthy_result_without_mutation(completed_native, change, message):
    completed = completed_native
    env = completed.env
    if change == "native_image":
        (env.root / "child" / completed.sid / "source-pages/page-1.png").write_bytes(b"changed-image")
    elif change == "frozen_input":
        (env.agent.directory / completed.key / "inputs" / "problem.md").write_text("被替换的原始条件。")
    elif change == "turn_model":
        env.turns[completed.sid][0]["endpoint_model"] = "another-model"
    elif change == "turn_prompt":
        env.turns[completed.sid][0]["user_message"] += "增加一个前提。"
    elif change == "missing_artifact":
        completed.output_file.unlink()
    elif change == "invalid_json":
        completed.result_file.write_text('{"status":')
    elif change == "duplicate_json":
        completed.result_file.write_text('{"status":"passed","status":"refuted","artifact":"x.md","report":"不可信"}')
    elif change == "wrong_status":
        payload = json.loads(completed.result_file.read_text())
        payload["status"] = "ok"
        completed.result_file.write_text(json.dumps(payload))
    else:
        env.sessions[completed.sid]["status"] = env.turns[completed.sid][0]["status"] = "Failed"
    before = _readonly_workspace_snapshot(env.root)
    histories = deepcopy((env.sessions, env.turns))
    with pytest.raises((judge.FaithSieveJudgeError, FaithSieveProtocolError), match=message):
        judge.inspect_completed_native(env.agent.workspace, env.agent.run, completed.key, completed.record)
    assert _readonly_workspace_snapshot(env.root) == before
    assert (env.sessions, env.turns) == histories
    assert len(env.submissions) == 1 and env.tools.calls == []


def test_completed_native_inspection_preserves_failed_first_turn_and_returns_continuation_response(native_continuation, monkeypatch):
    continuation = native_continuation
    env = continuation.env
    with pytest.raises(judge.FaithSievePending):
        invoke(env.agent, **continuation.arguments)
    child = env.root / "child" / continuation.sid
    artifact = "faithsieve-work/verification/N3.md"
    result_file = child / continuation.arguments["expected_result_path"]
    result_file.parent.mkdir(parents=True, exist_ok=True)
    result_file.write_text(json.dumps({"status": "inconclusive", "artifact": artifact, "report": "保留完整局部责任，尚不能可靠决定。"}))
    output_file = child / artifact
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("续跑原生报告：未把原失败或部分编译成功当成数学结论。")
    env.sessions[continuation.sid]["status"] = "Completed"
    env.turns[continuation.sid][1].update(status="Completed", harness=env.run["harness"],
                                         endpoint_id=env.endpoint["id"], endpoint_model=env.endpoint["model"])
    expected = invoke(env.agent, **continuation.arguments)
    record, _size = CheckpointStore(env.agent.workspace)._read_record(continuation.arguments["invocation_key"], strict=True)
    _forbid_native_inspection_writes(monkeypatch)
    before = _readonly_workspace_snapshot(env.root)
    result = judge.inspect_completed_native(env.agent.workspace, env.agent.run,
                                            continuation.arguments["invocation_key"], record)
    assert result == expected
    assert result["execution"]["task_id"] == continuation.tid + "-c1"
    assert result["execution"]["session_id"] == continuation.sid
    assert env.turns[continuation.sid][0] == continuation.original_turn
    assert env.sessions[continuation.sid]["native_session_id"] == continuation.native_id
    assert _readonly_workspace_snapshot(env.root) == before
    assert len(env.submissions) == 2 and env.tools.calls == []
