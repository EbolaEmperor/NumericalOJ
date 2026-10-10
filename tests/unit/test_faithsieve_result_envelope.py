"""角色工件外层与评分协议分开，历史尾部仅兼容已完成请求。"""

from copy import deepcopy
import json

import pytest

from backend.oj_modules.faithsieve import prompts, workflow
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from tests.unit.test_faithsieve_input_transport import decode_input_message
from tests.unit.test_faithsieve_transport import engine, json_response, openai_endpoint, response, role_result
from tests.unit.test_faithsieve_workflow import tree_payload


OLD_FUNCTION_SUFFIX = """

## 本次结果函数回传

本条传输约定覆盖前文“最终只返回 JSON 文本”和“不调用工具”的回传方式。
完成上述数学职责后，必须且只能调用一次 faithsieve_result，函数参数直接是原来要求的
完整结果 JSON 对象；不要将整个参数序列化成字符串，不要另包 payload 或 response 字段。
该函数仅接收完整结果，不执行代码、搜索或 Agent 任务；本次不会提供工具结果或续聊。
除思考内容外，不输出任何正文、解释、代码围栏或第二份文本 JSON。
文件正文作为 artifacts 对应路径的字符串值，保留实际换行及 LaTeX 反斜杠；
tree-builder 的 tree.json 仍是原生对象，并遵守上方明确的状态引用传输约定。
字段与原角色要求完全一致，不增加 execution 或自称已经执行工具的证据。
"""
OLD_JSON_SUFFIX = """

## 本次 JSON mode 回传

本条传输约定覆盖前文可能出现的结果函数回传要求。本次不提供或调用工具。
完成上述数学职责后，只输出一个完整 JSON 对象，不输出正文说明、代码围栏或第二份结果。
对象字段与原角色要求完全一致；不要将整个对象序列化成字符串，不要另包 payload 或 response 字段。
文件正文作为 artifacts 对应路径的字符串值，正确转义实际换行及 LaTeX 反斜杠；
tree-builder 的 tree.json 仍是原生对象，并遵守上方明确的状态引用传输约定。
不要增加 execution 或自称已经执行工具的证据；思考内容不能作为结果正文。
"""
GRADE = {"verdict": "correct", "score": 5, "comment": "证明充分。"}
FILES = {"problem.md": "完整条件与目标", workflow.STEPS: "## S1\n原稿第1页：1=2。"}


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("flags", [{}, {"scoring": True}, {"tree": True}])
def test_legacy_result_suffix_is_exact_even_with_new_role_flags(json_mode, flags):
    options = {"response_format": {"type": "json_object"}} if json_mode else {}
    expected = OLD_JSON_SUFFIX if json_mode else OLD_FUNCTION_SUFFIX
    assert prompts.model_result_prompt("原职责\n", options, legacy_result=True, **flags) == "原职责\n" + expected
    assert prompts.function_result_prompt("原职责\n", options, legacy_result=True, **flags) == "原职责\n" + OLD_FUNCTION_SUFFIX


@pytest.mark.parametrize("json_mode", [False, True])
def test_actual_role_tree_and_score_messages_distinguish_their_outer_contracts(tmp_path, json_mode):
    calls = []
    tree = role_result(tree_payload(), artifact=workflow.TREE)
    tree.pop("control")
    values = [role_result(), tree, GRADE]
    def chat(_endpoint, messages, **options):
        calls.append((deepcopy(messages), deepcopy(options)))
        return (json_response if json_mode else response)(values[len(calls) - 1])
    run = engine(tmp_path, chat, endpoint=openai_endpoint() if json_mode else None)
    run._invoke("decomposer", files={"problem.md": FILES["problem.md"]})
    assert run._invoke("tree-builder", files=FILES).control["edge_units"] == ["E1"]
    assert run._score("correct") == GRADE
    role_prompt, tree_prompt, score_prompt = [call[0][0]["content"] for call in calls]
    assert "status,artifact,report" in role_prompt and "不能省略 artifacts" in role_prompt
    assert "tree-builder 顶层只有 result 与 artifacts，不返回 control" in tree_prompt
    assert "顶层必须且只能包含 verdict、score、comment" in score_prompt
    assert "原角色要求写入 results 目录" not in score_prompt
    if not json_mode:
        schemas = [options["tools"][0]["function"]["parameters"] for _messages, options in calls]
        assert set(schemas[0]["properties"]) == {"result", "artifacts", "control"}
        assert set(schemas[1]["properties"]) == {"result", "artifacts"}
        assert set(schemas[2]["properties"]) == set(GRADE)


@pytest.mark.parametrize("json_mode", [False, True])
def test_inner_role_result_is_rejected_then_specific_feedback_allows_one_correction(tmp_path, json_mode):
    calls = []
    payload = role_result()
    def chat(_endpoint, messages, **_options):
        calls.append(deepcopy(messages))
        assert not (tmp_path / workflow.STEPS).exists()
        assert not (tmp_path / "faithsieve-work/results/decomposer.json").exists()
        if len(calls) == 1:
            return (json_response if json_mode else response)(payload["result"])
        feedback = decode_input_message(messages[1]["content"])["revision_report"]
        assert "result 和 artifacts" in feedback and "只能放在 result 内" in feedback
        return (json_response if json_mode else response)(payload)
    endpoint = openai_endpoint() if json_mode else None
    run = engine(tmp_path, chat, endpoint=endpoint)
    assert run._invoke("decomposer", files={"problem.md": "完整题目"}).result == payload["result"]
    first_path = run.checkpoints._path("role-000001-attempt-1")
    saved = first_path.read_bytes()
    first = json.loads(saved)
    assert first["state"] == "protocol_error" and "result 和 artifacts" in first["error"]
    assert run.store.read(workflow.STEPS) == payload["artifacts"][workflow.STEPS]
    completed_path = run.checkpoints._path("role-000001-attempt-2")
    completed = completed_path.read_bytes()
    engine(tmp_path, lambda *_a, **_k: pytest.fail("缓存不能产生第三次调用"), endpoint=endpoint)._invoke(
        "decomposer", files={"problem.md": "完整题目"})
    assert len(calls) == 2 and completed_path.read_bytes() == completed
    replayed_first = json.loads(first_path.read_bytes())
    assert (replayed_first["request"], replayed_first["state"], replayed_first["error"]) == (
        first["request"], first["state"], first["error"])


@pytest.mark.parametrize("json_mode", [False, True])
def test_missing_artifacts_is_never_wrapped_or_published_and_remains_terminal(tmp_path, json_mode):
    calls = []
    def chat(*_args, **_options):
        calls.append(1)
        return (json_response if json_mode else response)({"result": role_result()["result"]})
    endpoint = openai_endpoint() if json_mode else None
    for _ in range(2):
        with pytest.raises(FaithSieveProtocolError, match="result 和 artifacts"):
            engine(tmp_path, chat, endpoint=endpoint)._invoke("decomposer", files={})
    assert len(calls) == 2 and not (tmp_path / workflow.STEPS).exists()


@pytest.mark.parametrize("json_mode", [False, True])
def test_scoring_rejects_role_envelope_without_a_second_request(tmp_path, json_mode):
    calls = []
    def chat(*_args, **_options):
        calls.append(1)
        return (json_response if json_mode else response)({"result": GRADE, "artifacts": {}})
    endpoint = openai_endpoint() if json_mode else None
    for _ in range(2):
        with pytest.raises(FaithSieveProtocolError):
            engine(tmp_path, chat, endpoint=endpoint)._score("correct")
    assert len(calls) == 1 and not (tmp_path / workflow.RESULT).exists()


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("target", ["role", "tree", "score"])
@pytest.mark.parametrize("state", ["completed", "pending", "protocol_error", "endpoint_error"])
def test_previous_raw_result_suffix_is_completed_only_exact_readonly_cache(tmp_path, json_mode, target, state):
    endpoint = openai_endpoint() if json_mode else None
    payload = GRADE if target == "score" else role_result(
        tree_payload() if target == "tree" else "## S1\n原稿内容。",
        artifact=workflow.TREE if target == "tree" else workflow.STEPS)
    if target == "tree":
        payload.pop("control")
    run = engine(tmp_path, lambda *_a, **_k: (json_response if json_mode else response)(payload),
                 endpoint=endpoint, initial_reasoning_effort="low")
    def execute(current):
        if target == "score":
            return current._score("correct")
        return current._invoke("tree-builder" if target == "tree" else "decomposer", files=FILES)
    execute(run)
    key = "final-scoring" if target == "score" else "role-000001-attempt-1"
    path = run.checkpoints._path(key)
    record = json.loads(path.read_bytes())
    old_request = deepcopy(record["request"])
    base = prompts.SCORE_PROMPT if target == "score" else prompts.render_role_prompt(
        "tree-builder" if target == "tree" else "decomposer")
    old_prompt = prompts.model_result_prompt(base, old_request["call_options"], legacy_result=True)
    old_request["messages"][0]["content"] = old_prompt
    if target != "score":
        old_request["prompt"] = old_prompt
    # 构造旧格式记录，不能通过生产 put 改写已经冻结的新请求。
    path.write_text(json.dumps({**record, "request": old_request, "state": state}, ensure_ascii=False))
    saved = path.read_bytes()
    artifact = workflow.RESULT if target == "score" else workflow.TREE if target == "tree" else workflow.STEPS
    run.store.remove(artifact)
    resumed = engine(tmp_path, lambda *_a, **_k: pytest.fail("历史尾部不能再次请求"),
                     endpoint=endpoint, initial_reasoning_effort="low")
    if state == "completed":
        execute(resumed)
        assert (tmp_path / artifact).exists()
    else:
        with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
            execute(resumed)
        assert not (tmp_path / artifact).exists()
    assert path.read_bytes() == saved
