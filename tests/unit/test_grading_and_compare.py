# -*- coding: utf-8 -*-
"""判分核心纯函数单测（对应路线图 quick-win）。

- compare_float_strings：决定 AC vs Wrong Answer 的数值比较（容差、长度不一致、NaN、解析失败回退）
- _parse_written_homework_grading_result：书面作业评分 JSON 解析 + 分数夹取 + 5分有扣分降4 + <5无扣分补默认
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


def test_parse_full_marks_with_deductions_downgraded_to_4():
    parse = _parse()
    score, deductions, _ = parse('{"score": 5, "deductions": ["第二步跳步"], "comment": "x"}')
    assert score == 4                       # 5 分但有扣分 → 降为 4
    assert deductions


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


def test_parse_low_score_without_deductions_gets_default():
    parse = _parse()
    score, deductions, _ = parse('{"score": 3, "deductions": [], "comment": ""}')
    assert score == 3
    assert deductions                        # <5 分且无扣分 → 补默认扣分


def test_parse_clamps_out_of_range():
    parse = _parse()
    # 用空 deductions 避免触发「5分有扣分降4」，单纯验证 0..5 夹取
    assert parse('{"score": 9, "deductions": []}')[0] == 5
    assert parse('{"score": -2, "deductions": []}')[0] == 0
