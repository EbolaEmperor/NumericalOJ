# -*- coding: utf-8 -*-
"""书面题讨论协议与 JSON 修复的纯单元回归，不连接模型或数据库。"""

import json

import pytest


def _response(*, peer_replies=None):
    result = {"score": 5, "deductions": [], "comment": "论证完整"}
    if peer_replies is not None:
        result["peer_replies"] = peer_replies
    return json.dumps(result, ensure_ascii=False)


def _replies():
    return [
        {"vote_index": 1, "reply": "已核对评委一指出的条件。"},
        {"vote_index": 3, "reply": "已复查评委三提出的推导。"},
    ]


@pytest.fixture
def grading(monkeypatch):
    from backend.oj_modules.ai import grading as module

    def unexpected_llm_call(*_args, **_kwargs):
        pytest.fail("单元测试不得连接真实 LLM。")

    def unexpected_sleep(_seconds):
        pytest.fail("测试未预期重试，不得实际等待。")

    monkeypatch.setattr(module, "_call_llm_text", unexpected_llm_call)
    monkeypatch.setattr(module, "_call_llm_vision", unexpected_llm_call)
    monkeypatch.setattr(module.time, "sleep", unexpected_sleep)
    return module


@pytest.mark.parametrize("from_images", [False, True])
def test_initial_grading_repairs_json_with_its_own_endpoint(
    grading, monkeypatch, from_images,
):
    endpoint = object()
    invalid = "评分结果无法识别为 JSON"
    repaired = _response()
    calls = []

    def text_call(*args, **kwargs):
        calls.append(("text", args, kwargs))
        if not from_images and len(calls) == 1:
            return invalid
        return repaired

    def vision_call(*args, **kwargs):
        calls.append(("vision", args, kwargs))
        return invalid

    monkeypatch.setattr(grading, "resolve_problem_llm_endpoint_snapshot", lambda *_args, **_kwargs: endpoint)
    monkeypatch.setattr(grading, "_call_llm_text", text_call)
    monkeypatch.setattr(grading, "_call_llm_vision", vision_call)
    monkeypatch.setattr(grading, "_build_image_data_url", lambda _path: "data:image/png;base64,AA==")
    common_kwargs = {
        "endpoint": endpoint,
        "timeout_seconds": 45,
        "return_round": True,
        "vote_index": 2,
    }
    if from_images:
        result = grading.evaluate_written_homework_with_ai_from_images(
            {"title": "题目", "content": "题面"}, ["answer.png"], **common_kwargs,
        )
    else:
        result = grading.evaluate_written_homework_with_ai(
            {"title": "题目", "content": "题面"}, "学生推导", **common_kwargs,
        )

    assert len(calls) == 2
    assert calls[0][1][2 if from_images else 1] is endpoint
    assert calls[1][0] == "text"
    assert calls[1][1][1] is endpoint
    assert calls[1][2]["timeout"] == 45
    assert invalid in calls[1][1][0]
    assert "score" in calls[1][1][0]
    assert result.score == 5
    assert result.raw_response == repaired
    assert json.loads(result.raw_response)["score"] == 5
    assert result.vote_index == 2
    assert "评委 2" in result.prompt
    assert result.image_data_urls == (("data:image/png;base64,AA==",) if from_images else ())


def test_repaired_image_round_keeps_images_and_usable_history(grading, monkeypatch):
    endpoint = object()
    repaired = _response()
    vision_calls = []

    def vision_call(*args, **kwargs):
        vision_calls.append((args, kwargs))
        if len(vision_calls) == 1:
            return "第一轮 JSON 损坏"
        return _response(peer_replies=[{"vote_index": 2, "reply": "同意完整推导。"}])

    monkeypatch.setattr(grading, "resolve_problem_llm_endpoint_snapshot", lambda *_args, **_kwargs: endpoint)
    monkeypatch.setattr(grading, "_build_image_data_url", lambda _path: "data:image/png;base64,AA==")
    monkeypatch.setattr(grading, "_call_llm_vision", vision_call)
    monkeypatch.setattr(grading, "_call_llm_text", lambda *_args, **_kwargs: repaired)
    initial = grading.evaluate_written_homework_with_ai_from_images(
        {"title": "题目"}, ["answer.png"], endpoint=endpoint, return_round=True, vote_index=1,
    )
    peer = grading.WrittenGradingRound(4, "缺条件", _response(), "同伴题面", vote_index=2)
    reconsidered = grading.reconsider_written_homework_with_ai(
        initial, [{"vote_index": 2, "round": peer}], endpoint=endpoint,
    )

    args, kwargs = vision_calls[1]
    assert args[0] == initial.prompt
    assert args[1] == initial.image_data_urls
    assert args[2] is endpoint
    assert kwargs["continuation_messages"][0] == {"role": "assistant", "content": repaired}
    assert reconsidered.vote_index == 1
    assert reconsidered.image_data_urls == initial.image_data_urls


@pytest.mark.parametrize("from_images", [False, True])
def test_discussion_json_repair_uses_same_endpoint_and_preserves_next_round_history(
    grading, monkeypatch, from_images,
):
    endpoint = object()
    repaired = _response(peer_replies=_replies())
    calls = []
    initial = grading.WrittenGradingRound(
        score=4,
        comment="缺条件",
        raw_response='{"score":4,"deductions":["缺条件"],"comment":"请复查"}',
        prompt="原题与学生答案",
        image_data_urls=("data:image/png;base64,AA==",) if from_images else (),
        vote_index=2,
    )
    peers = [
        {"vote_index": 1, "round": grading.WrittenGradingRound(5, "完整", _response(), "同伴题面", vote_index=1)},
        {"vote_index": 3, "round": grading.WrittenGradingRound(5, "完整", _response(), "同伴题面", vote_index=3)},
    ]

    def fake_call(kind, *args, **kwargs):
        calls.append((kind, args, kwargs))
        return "讨论轮损坏 JSON" if len(calls) == 1 else repaired

    monkeypatch.setattr(grading, "_call_llm_text", lambda *args, **kwargs: fake_call("text", *args, **kwargs))
    monkeypatch.setattr(grading, "_call_llm_vision", lambda *args, **kwargs: fake_call("vision", *args, **kwargs))
    second = grading.reconsider_written_homework_with_ai(
        initial, peers, endpoint=endpoint, timeout_seconds=45,
    )
    third = grading.reconsider_written_homework_with_ai(
        second,
        [{**peers[0], "reply_to_current_judge": "评委一回应评委二"},
         {**peers[1], "reply_to_current_judge": "评委三回应评委二"}],
        endpoint=endpoint,
        round_number=3,
    )

    assert len(calls) == 3
    assert calls[0][1][2 if from_images else 1] is endpoint
    assert calls[1][0] == "text"
    assert calls[1][1][1] is endpoint
    assert calls[1][2]["timeout"] == 45
    repair_prompt = calls[1][1][0]
    assert "peer_replies" in repair_prompt
    assert "vote_index" in repair_prompt
    assert "reply" in repair_prompt
    assert second.raw_response == repaired
    assert second.peer_replies == tuple(_replies())
    assert third.vote_index == second.vote_index == initial.vote_index == 2
    assert third.continuation_messages[:2] == second.continuation_messages
    assert third.continuation_messages[2] == {"role": "assistant", "content": repaired}
    user_message = third.continuation_messages[3]["content"]
    assert "评委 2" in user_message
    assert "评委一回应评委二" in user_message
    assert "评委三回应评委二" in user_message
    assert "评委 1 对你（评委 2）的回复" in user_message
    assert "评委 3 对你（评委 2）的回复" in user_message
    assert user_message.index("## 评委 1") < user_message.index("评委一回应评委二") < user_message.index("## 评委 3")
    if from_images:
        assert calls[2][1][1] == initial.image_data_urls


def test_json_repair_retries_invalid_outputs_with_delays(grading, monkeypatch):
    endpoint = object()
    repaired = _response(peer_replies=_replies())
    outputs = iter(["仍然无法解析", '{"score":5,"deductions":{}}', _response(), "null", repaired])
    events = []

    def fake_call(*args, **_kwargs):
        assert args[1] is endpoint
        events.append("call")
        return next(outputs)

    monkeypatch.setattr(grading, "_call_llm_text", fake_call)
    monkeypatch.setattr(grading.time, "sleep", lambda seconds: events.append(seconds))
    result = grading._parse_written_homework_grading_payload(
        "无法解析的讨论结果", repair_endpoint=endpoint, expected_peer_indices=(1, 3),
    )

    assert events == ["call", 5, "call", 20, "call", 60, "call", 60, "call"]
    assert result[0] == 5
    assert result[3] == tuple(_replies())
    assert result[4] == repaired


def test_json_repair_retries_endpoint_errors_with_delays(grading, monkeypatch):
    endpoint = object()
    events = []

    def fake_call(*args, **_kwargs):
        assert args[1] is endpoint
        events.append("call")
        if events.count("call") < 5:
            raise ConnectionError("端点暂时不可用")
        return _response()

    monkeypatch.setattr(grading, "_call_llm_text", fake_call)
    monkeypatch.setattr(grading.time, "sleep", lambda seconds: events.append(seconds))
    assert grading._parse_written_homework_grading_result("原始损坏 JSON", repair_endpoint=endpoint)[0] == 5
    assert events == ["call", 5, "call", 20, "call", 60, "call", 60, "call"]


@pytest.mark.parametrize("endpoint_error", [False, True])
def test_exhausted_json_repair_has_five_attempts_and_raises(grading, monkeypatch, endpoint_error):
    endpoint = object()
    calls = []
    delays = []

    def fake_call(*args, **_kwargs):
        assert args[1] is endpoint
        calls.append(args)
        if endpoint_error:
            raise TimeoutError("端点超时")
        return _response(peer_replies=[{"vote_index": 1, "reply": "仅回复一位评委"}])

    monkeypatch.setattr(grading, "_call_llm_text", fake_call)
    monkeypatch.setattr(grading.time, "sleep", delays.append)
    with pytest.raises(grading.WrittenGradingJSONRepairError):
        grading._parse_written_homework_grading_payload(
            "损坏 JSON", repair_endpoint=endpoint, expected_peer_indices=(1, 3),
        )

    assert len(calls) == 5
    assert delays == [5, 20, 60, 60]


def test_json_repair_does_not_swallow_worker_time_limit(grading, monkeypatch):
    from celery.exceptions import SoftTimeLimitExceeded

    calls = []

    def fake_call(*args, **_kwargs):
        calls.append(args)
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(grading, "_call_llm_text", fake_call)
    with pytest.raises(SoftTimeLimitExceeded):
        grading._parse_written_homework_grading_result("损坏 JSON", repair_endpoint=object())
    assert len(calls) == 1


@pytest.mark.parametrize("changes", [
    {"score": None},
    {"score": True},
    {"score": float("nan")},
    {"score": float("inf")},
    {"score": 10 ** 400},
    {"deductions": {"reason": "错误类型"}},
    {"deductions": [{"reason": "数组项类型错误"}]},
    {"comment": ["错误类型"]},
    {"peer_replies": None},
    {"peer_replies": "应当是数组"},
    {"peer_replies": []},
    {"peer_replies": [{"vote_index": 1, "reply": "漏评委三"}]},
    {"peer_replies": [{"vote_index": 1, "reply": "重复"}, {"vote_index": 1, "reply": "重复"}]},
    {"peer_replies": [{"vote_index": 1, "reply": "正确编号"}, {"vote_index": 4, "reply": "未知编号"}]},
    {"peer_replies": [{"vote_index": 1, "reply": "正确编号"}, {"vote_index": 3, "reply": "  \n "}]},
    {"peer_replies": [{"vote_index": 1, "reply": "正确编号"}, {"vote_index": 3, "reply": {"text": "错误类型"}}]},
    {"peer_replies": [{"vote_index": 1, "reply": "正确编号"}, {"vote_index": True, "reply": "编号类型错误"}]},
    {"peer_replies": [{"vote_index": 1, "reply": "正确编号"}, {"vote_index": "3", "reply": "编号类型错误"}]},
    {"peer_replies": [{"vote_index": 1, "reply": "正确编号"}, {"reply": "漏编号"}]},
    {"peer_replies": [{"vote_index": 1, "reply": "正确编号"}, {"vote_index": 3}]},
    {"peer_replies": [{"vote_index": 1, "reply": "正确编号"}, "回复项应当是对象"]},
])
def test_invalid_grading_structure_is_repaired_instead_of_accepted(grading, monkeypatch, changes):
    data = json.loads(_response(peer_replies=_replies()))
    data.update(changes)
    raw = json.dumps(data, ensure_ascii=False)
    repaired = _response(peer_replies=_replies())
    calls = []

    def fake_call(*args, **_kwargs):
        calls.append(args)
        return repaired

    monkeypatch.setattr(grading, "_call_llm_text", fake_call)
    result = grading._parse_written_homework_grading_payload(
        raw, repair_endpoint=object(), expected_peer_indices=(1, 3),
    )

    assert len(calls) == 1
    assert raw in calls[0][0]
    assert result[3] == tuple(_replies())
    assert result[4] == repaired


def test_discussion_cannot_omit_peer_replies(grading, monkeypatch):
    repaired = _response(peer_replies=_replies())
    calls = []
    monkeypatch.setattr(grading, "_call_llm_text", lambda *args, **_kwargs: calls.append(args) or repaired)

    result = grading._parse_written_homework_grading_payload(
        _response(), repair_endpoint=object(), expected_peer_indices=(1, 3),
    )

    assert len(calls) == 1
    assert result[3] == tuple(_replies())


@pytest.mark.parametrize("raw", [
    '{"peer_replies":[{"score":5,"deductions":[],"comment":"内部对象不是评分"}',
    '{"peer_replies":[{"vote_index":1,"reply":"这里有数字5"}]}',
    '{"peer_replies":[{"vote_index":1,"reply":"```json\n{"score":5,"deductions":[],"comment":"内部代码块不是评分"}\n```',
])
def test_nested_reply_objects_and_numbers_do_not_supply_missing_score(grading, monkeypatch, raw):
    repaired = _response()
    calls = []
    monkeypatch.setattr(grading, "_call_llm_text", lambda *args, **_kwargs: calls.append(args) or repaired)

    result = grading._parse_written_homework_grading_result(raw, repair_endpoint=object())

    assert len(calls) == 1
    assert result == (5, [], "论证完整")


def test_unbraced_outer_grading_does_not_pick_nested_score(grading):
    raw = (
        '"score":5,"deductions":[],"comment":"原评分",'
        '"peer_replies":[{"score":2,"deductions":["内部扣分"],"comment":"内部对象"}]'
    )

    result = grading._parse_written_homework_grading_result(raw)

    assert result == (5, [], "原评分")


def test_unbraced_outer_with_nested_fence_requests_model_repair(grading, monkeypatch):
    raw = (
        '"score":5,"deductions":[],"comment":"原评分",'
        '"peer_replies":[{"vote_index":1,"reply":"```json\n'
        '{"score":2,"deductions":["内部扣分"],"comment":"内部代码块"}\n```"}]'
    )
    repaired = _response()
    calls = []
    monkeypatch.setattr(grading, "_call_llm_text", lambda *args, **_kwargs: calls.append(args) or repaired)

    result = grading._parse_written_homework_grading_result(raw, repair_endpoint=object())

    assert len(calls) == 1
    assert result == (5, [], "论证完整")


@pytest.mark.parametrize(("reply", "expected"), [
    ("  见 \frac{a}{b} 的论证。  ", "见 \\frac{a}{b} 的论证。"),
    ("\frac{a}{b} 与条件一致。", "\\frac{a}{b} 与条件一致。"),
])
def test_normalized_discussion_replies_match_assistant_history(grading, reply, expected):
    replies = [{"vote_index": 1, "reply": reply}]
    raw = _response(peer_replies=replies)

    result = grading._written_grading_round_result(
        raw, prompt="题面", expected_peer_indices=(1,), vote_index=2,
    )

    assert result.peer_replies == ({"vote_index": 1, "reply": expected},)
    assert json.loads(result.raw_response)["peer_replies"] == list(result.peer_replies)


def test_valid_complex_discussion_json_preserves_each_reply_without_repair(grading):
    replies = [
        {"vote_index": 3, "reply": '包含括号 { } 与引号 "；再核对 \\frac{a}{b}。'},
        {"vote_index": 1, "reply": "依据第二步\n逐项检查条件。"},
    ]
    raw = "```json\n" + _response(peer_replies=replies) + "\n```"
    result = grading._parse_written_homework_grading_payload(
        raw, repair_endpoint=object(), expected_peer_indices=(1, 3),
    )

    assert result[0] == 5
    assert result[3] == tuple(replies)


def test_normalization_remains_compatible_with_existing_grading(grading):
    assert grading._parse_written_homework_grading_result(
        '{"score":"5","deductions":"关键条件未检查","comment":"请补充"}',
    ) == (5, ["关键条件未检查"], "请补充")


def test_same_endpoint_judges_receive_distinct_identity_prompts(grading, monkeypatch):
    endpoint = object()
    prompts = []
    monkeypatch.setattr(grading, "resolve_problem_llm_endpoint_snapshot", lambda *_args, **_kwargs: endpoint)
    monkeypatch.setattr(grading, "_call_llm_text", lambda prompt, *_args, **_kwargs: prompts.append(prompt) or _response())

    rounds = [
        grading.evaluate_written_homework_with_ai(
            {"title": "题目"}, "同一份学生答案", endpoint=endpoint, vote_index=index, return_round=True,
        )
        for index in (1, 2)
    ]

    assert [result.vote_index for result in rounds] == [1, 2]
    assert "评委 1" in prompts[0]
    assert "评委 2" in prompts[1]
