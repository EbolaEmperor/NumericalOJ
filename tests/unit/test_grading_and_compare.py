# -*- coding: utf-8 -*-
"""判分核心纯函数单测（对应路线图 quick-win）。

- compare_float_strings：决定 AC vs Wrong Answer 的数值比较（容差、长度不一致、NaN、解析失败回退）
- _parse_written_homework_grading_result：书面作业评分 JSON 解析 + 分数 0..5 夹取（信任模型给分，不再做降分/补扣分后处理）
"""
import pytest


# ---------------- compare_float_strings ----------------
def _cmp():
    from backend.oj_modules.tasks.evaluate_tasks import compare_float_strings
    return compare_float_strings


def test_compare_exact_match():
    cmp = _cmp()
    assert cmp("1 2 3", "1 2 3") is True
    assert cmp("1,2,3", "1 2 3") is True       # 逗号/空白都算分隔


def test_compare_within_tolerance():
    cmp = _cmp()
    assert cmp("1.0", "1.000001") is True
    assert cmp("100", "100.0000001") is True


def test_compare_outside_tolerance():
    cmp = _cmp()
    assert cmp("1", "2") is False
    assert cmp("1.0", "1.01") is False


def test_compare_length_mismatch():
    cmp = _cmp()
    assert cmp("1 2", "1 2 3") is False


def test_compare_nan_never_equal():
    cmp = _cmp()
    assert cmp("nan", "nan") is False


def test_compare_nonnumeric_falls_back_to_string_eq():
    cmp = _cmp()
    assert cmp("abc", "abc") is True
    assert cmp("abc", "abd") is False


def test_compare_zero_pair():
    cmp = _cmp()
    assert cmp("0", "0") is True
    assert cmp("0 0", "0 0") is True


# ---------------- 程序题终态快照 ----------------
def test_finalize_terminal_programming_submission_preserves_terminal_status(monkeypatch):
    from backend.oj_modules.tasks import evaluate_tasks

    captured = {}

    def fake_finalize(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(evaluate_tasks, "_finalize_programming_submission", fake_finalize)

    submission = {
        "id": 123,
        "username": "student",
        "problem_id": 456,
        "problem_type": 1,
    }
    points = evaluate_tasks._finalize_programming_terminal_submission(
        submission=submission,
        problem_id=456,
        test_cases=[{"input": "1"}, {"input": "2"}],
        final_status="Compile Error",
        stderr="main.cpp: error",
    )

    assert captured["submission"] == submission
    assert captured["problem_id"] == 456
    assert captured["score"] == 0
    assert captured["final_status"] == "Compile Error"
    assert captured["test_point_statuses"] == points
    assert [tp["status"] for tp in points] == ["Compile Error", "Compile Error"]
    assert [tp["test_index"] for tp in points] == [1, 2]
    assert points[0]["stderr"] == "main.cpp: error"


# ---------------- _parse_written_homework_grading_result ----------------
def _parse():
    from backend.oj_modules.ai.grading import _parse_written_homework_grading_result
    return _parse_written_homework_grading_result


def test_parse_full_marks_no_deductions():
    parse = _parse()
    score, deductions, comment = parse('{"score": 5, "deductions": [], "comment": "很好"}')
    assert score == 5
    assert deductions == []
    assert comment == "很好"


def test_parse_full_marks_with_deductions_kept():
    parse = _parse()
    score, deductions, _ = parse('{"score": 5, "deductions": ["第二步跳步"], "comment": "x"}')
    assert score == 5                       # 信任模型给分，5 分即便有扣分也不再降为 4
    assert deductions == ["第二步跳步"]


@pytest.mark.parametrize("from_images", [False, True])
def test_written_homework_grading_uses_streaming_response(monkeypatch, from_images):
    from backend.oj_modules.ai import grading

    endpoint = object()
    captured = {}

    def fake_resolve(_problem, _binding_key, **_kwargs):
        return endpoint

    def fake_call(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return '{"score": 5, "deductions": [], "comment": "正确"}'

    monkeypatch.setattr(grading, "resolve_problem_llm_endpoint_snapshot", fake_resolve)
    if from_images:
        monkeypatch.setattr(grading, "_build_image_data_url", lambda _path: "data:image/png;base64,AA==")
        monkeypatch.setattr(grading, "_call_llm_vision", fake_call)
        result = grading.evaluate_written_homework_with_ai_from_images(
            {"title": "题目", "content": "内容"},
            ["answer.png"],
            endpoint=endpoint,
            timeout_seconds=45,
            repair_invalid_json=False,
        )
    else:
        monkeypatch.setattr(grading, "_call_llm_text", fake_call)
        result = grading.evaluate_written_homework_with_ai(
            {"title": "题目", "content": "内容"},
            "学生答案",
            endpoint=endpoint,
            timeout_seconds=45,
            repair_invalid_json=False,
        )

    assert result[0] == 5
    assert captured["kwargs"]["stream"] is True
    assert captured["kwargs"]["timeout"] == 45
    assert captured["kwargs"]["preserve_whitespace"] is True


@pytest.mark.parametrize("from_images", [False, True])
def test_written_homework_reconsideration_preserves_first_round_prefix(
    monkeypatch,
    from_images,
):
    from backend.oj_modules.ai import grading

    captured = {}
    first_round = grading.WrittenGradingRound(
        score=4,
        comment="首轮评语",
        raw_response='{"score":4,"deductions":["缺一步"],"comment":"首轮"}',
        prompt="完全相同的首轮请求",
        image_data_urls=("data:image/png;base64,AA==",) if from_images else (),
    )
    peers = [
        {
            "vote_index": 1,
            "round": grading.WrittenGradingRound(
                score=5,
                comment="评委一",
                raw_response='{"score":5,"deductions":[],"comment":"正确"}',
                prompt="peer",
            ),
        },
        {
            "vote_index": 3,
            "round": grading.WrittenGradingRound(
                score=3,
                comment="评委三",
                raw_response='{"score":3,"deductions":["识图不同"],"comment":"复查图片"}',
                prompt="peer",
            ),
        },
    ]

    def fake_call(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return '{"score":5,"deductions":[],"comment":"最终一致"}'

    monkeypatch.setattr(
        grading,
        "_call_llm_vision" if from_images else "_call_llm_text",
        fake_call,
    )
    result = grading.reconsider_written_homework_with_ai(
        first_round,
        peers,
        endpoint=object(),
        timeout_seconds=45,
    )

    assert result.score == 5
    assert captured["args"][0] == "完全相同的首轮请求"
    if from_images:
        assert captured["args"][1] == first_round.image_data_urls
    continuation = captured["kwargs"]["continuation_messages"]
    assert captured["kwargs"]["preserve_whitespace"] is True
    assert continuation[0] == {
        "role": "assistant",
        "content": first_round.raw_response,
    }
    followup = continuation[1]["content"]
    assert continuation[1]["role"] == "user"
    assert "## 评委 1" in followup
    assert "## 评委 3" in followup
    assert "给分：5/5" in followup
    assert peers[0]["round"].raw_response in followup
    assert peers[1]["round"].raw_response in followup
    assert "仔细地重新读一遍图" in followup


def test_written_homework_third_round_keeps_full_transcript(monkeypatch):
    from backend.oj_modules.ai import grading

    captured = []

    def fake_call(*args, **kwargs):
        captured.append((args, kwargs))
        return '{"score":5,"deductions":[],"comment":"复评"}'

    monkeypatch.setattr(grading, "_call_llm_text", fake_call)
    first_round = grading.WrittenGradingRound(
        score=4,
        comment="首轮评语",
        raw_response='{"score":4,"deductions":["缺一步"],"comment":"首轮"}',
        prompt="完全相同的首轮请求",
    )
    peers_second = [{
        "vote_index": 2,
        "round": grading.WrittenGradingRound(
            score=3, comment="第二轮分歧", raw_response='{"score":3}', prompt="peer",
        ),
    }]

    second_round = grading.reconsider_written_homework_with_ai(
        first_round,
        peers_second,
        endpoint=object(),
        timeout_seconds=45,
    )
    third_round = grading.reconsider_written_homework_with_ai(
        second_round,
        peers_second,
        endpoint=object(),
        timeout_seconds=45,
        round_number=3,
    )

    assert third_round.score == 5
    second_args, second_kwargs = captured[0]
    third_args, third_kwargs = captured[1]
    assert second_args[0] == third_args[0] == "完全相同的首轮请求"

    second_continuation = second_kwargs["continuation_messages"]
    third_continuation = third_kwargs["continuation_messages"]
    # 第三轮在前两轮完整对话基础上追加「本轮回复 + 本轮指令」。
    assert third_continuation[:2] == second_continuation
    assert [message["role"] for message in third_continuation] == [
        "assistant", "user", "assistant", "user",
    ]
    assert third_continuation[2]["content"] == second_round.raw_response

    followup = third_continuation[3]["content"]
    assert peers_second[0]["round"].raw_response in followup
    assert "这是第二轮讨论的结果" in followup
    assert "请再核对一轮，解决争议的问题" in followup
    assert "还是用一样的 json 格式回复我" in followup


def test_parse_low_score_without_deductions_kept_empty():
    parse = _parse()
    score, deductions, _ = parse('{"score": 3, "deductions": [], "comment": ""}')
    assert score == 3
    assert deductions == []                  # 不再补默认扣分，信任模型输出


def test_parse_clamps_out_of_range():
    parse = _parse()
    # 单纯验证 0..5 夹取
    assert parse('{"score": 9, "deductions": []}')[0] == 5
    assert parse('{"score": -2, "deductions": []}')[0] == 0
