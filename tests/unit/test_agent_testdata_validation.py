from __future__ import annotations

import pytest

from oj_modules.tasks.agent import testdata_validation as validation


def _problem(**overrides):
    value = {
        "id": 7,
        "type": 1,
        "programming_grading_mode": 1,
        "lang": "cpp",
        "test_code": "// checker start\n%%user_code_here\n// checker end\n",
        "forbidden_func": "system, fork",
        "time_limit_ms": 1234,
    }
    value.update(overrides)
    return value


def _run_result(stdout, *, status="Accepted", stderr="", time_ns=0):
    return {
        "status": status,
        "files": {"stdout": stdout, "stderr": stderr},
        "time": time_ns,
    }


def test_validate_staged_testdata_uses_normal_judge_payload_and_float_compare(
    monkeypatch,
):
    calls = []
    cleanups = []

    def fake_batch(language, payload):
        calls.append((language, payload))
        return {
            "compile_result": {"status": "success", "stderr": ""},
            "test_results": [
                _run_result("1.000001, 2", time_ns=2_600_000),
                _run_result("done\n", time_ns=900_000),
            ],
        }

    monkeypatch.setattr(validation.core, "batch_evaluate", fake_batch)
    monkeypatch.setattr(
        validation.core,
        "cleanup_run_artifacts",
        lambda sid, **kwargs: cleanups.append((sid, kwargs)),
    )

    marker_start = "here_is_user_code_fuck_fuck_fuck_hahaha"
    marker_end = "user_code_end_fuck_hahaha_fuck"
    source = f"int main() {{ /* {marker_start} {marker_end} */ return 0; }}"
    testdata = [
        {"input": "1\n", "output": "1.0 2.0\n", "score": 20},
        {"input": "2\n", "output": "done"},
    ]

    result = validation.validate_staged_testdata(
        _problem(),
        source,
        testdata,
        task_id="task/unsafe value",
    )

    assert result == {
        "success": True,
        "status": "Accepted",
        "score": 2,
        "test_points": [
            {
                "test_index": 1,
                "status": "Accepted",
                "stdout": "1.000001, 2",
                "stderr": "",
                "time": 3,
            },
            {
                "test_index": 2,
                "status": "Accepted",
                "stdout": "done",
                "stderr": "",
                "time": 1,
            },
        ],
        "message": "标准程序通过全部 2 个测试点",
    }
    assert len(calls) == 1
    language, payload = calls[0]
    assert language == "cpp"
    assert payload["submittedCode"] == source
    assert payload["checkerCode"] == _problem()["test_code"]
    assert payload["code"].startswith("// checker start\n")
    assert payload["code"].endswith("\n// checker end\n")
    assert payload["code"].count(marker_start) == 1
    assert payload["code"].count(marker_end) == 1
    assert payload["forbidden"] == "system, fork"
    assert payload["timeLimit"] == 1_234_000_000
    assert payload["memoryLimit"] == 512 * 1024 * 1024
    assert payload["user_files"] == []
    assert payload["test_cases"] == [
        {"input": "1\n", "output": "1.0 2.0\n"},
        {"input": "2\n", "output": "done"},
    ]
    assert payload["sid"].startswith("agent-testdata-validation-")
    assert "/" not in payload["sid"]
    assert cleanups == [(
        payload["sid"],
        {"keep_images": False, "keep_sources": False},
    )]


def test_validate_staged_testdata_returns_per_point_failure_summary(monkeypatch):
    long_output = "x" * 600
    monkeypatch.setattr(
        validation.core,
        "batch_evaluate",
        lambda _language, _payload: {
            "compile_result": {"status": "success"},
            "test_results": [
                _run_result("42"),
                _run_result(long_output, stderr="bad output"),
                _run_result("", status="Runtime Error", stderr="boom"),
            ],
        },
    )
    monkeypatch.setattr(validation.core, "cleanup_run_artifacts", lambda *_a, **_k: None)

    result = validation.validate_staged_testdata(
        _problem(test_code=""),
        "int main() {}",
        [
            {"input": "", "output": "42"},
            {"input": "", "output": long_output + "different"},
            {"input": "", "output": "0"},
        ],
        task_id="task-1",
    )

    assert result["success"] is False
    assert result["status"] == "Unaccepted"
    assert result["score"] == 1
    assert [item["status"] for item in result["test_points"]] == [
        "Accepted",
        "Wrong Answer",
        "Runtime Error",
    ]
    assert result["test_points"][1]["stdout"] == "x" * 500 + "..."
    assert "第 2 点（Wrong Answer）" in result["message"]


@pytest.mark.parametrize(
    ("compile_status", "expected_status"),
    [("error", "Compile Error"), ("forbidden", "Forbidden")],
)
def test_validate_staged_testdata_returns_structured_compile_failure(
    monkeypatch,
    compile_status,
    expected_status,
):
    cleanups = []
    monkeypatch.setattr(
        validation.core,
        "batch_evaluate",
        lambda _language, _payload: {
            "compile_result": {"status": compile_status, "stderr": "diagnostic"},
            "test_results": [],
        },
    )
    monkeypatch.setattr(
        validation.core,
        "cleanup_run_artifacts",
        lambda sid, **kwargs: cleanups.append((sid, kwargs)),
    )

    result = validation.validate_staged_testdata(
        _problem(),
        "int main() {}",
        [{"input": "", "output": ""}],
        task_id="task-2",
    )

    assert result["success"] is False
    assert result["status"] == expected_status
    assert result["score"] == 0
    assert result["test_points"] == []
    assert "diagnostic" in result["message"]
    assert len(cleanups) == 1


def test_validate_staged_testdata_raises_infrastructure_error_after_cleanup(monkeypatch):
    cleanups = []

    def fail_batch(_language, _payload):
        raise OSError("docker unavailable")

    monkeypatch.setattr(validation.core, "batch_evaluate", fail_batch)
    monkeypatch.setattr(
        validation.core,
        "cleanup_run_artifacts",
        lambda sid, **kwargs: cleanups.append((sid, kwargs)),
    )

    with pytest.raises(RuntimeError, match="docker unavailable"):
        validation.validate_staged_testdata(
            _problem(),
            "int main() {}",
            [{"input": "", "output": ""}],
            task_id="task-3",
        )

    assert len(cleanups) == 1
    assert cleanups[0][0].startswith("agent-testdata-validation-")


@pytest.mark.parametrize(
    ("problem_overrides", "message"),
    [
        ({"type": 2}, "仅支持编程题"),
        ({"programming_grading_mode": 2}, "仅支持标准测试点评分模式"),
        ({"programming_grading_mode": 3}, "仅支持标准测试点评分模式"),
        ({"lang": "rust"}, "不支持的编程语言"),
        ({"time_limit_ms": "invalid"}, "题目时间限制无效"),
    ],
)
def test_validate_staged_testdata_rejects_unsupported_configuration_without_judging(
    monkeypatch,
    problem_overrides,
    message,
):
    monkeypatch.setattr(
        validation.core,
        "batch_evaluate",
        lambda *_args, **_kwargs: pytest.fail("不应启动判题"),
    )
    result = validation.validate_staged_testdata(
        _problem(**problem_overrides),
        "code",
        [{"input": "", "output": ""}],
        task_id="task-4",
    )
    assert result["success"] is False
    assert message in result["message"]


@pytest.mark.parametrize(
    ("standard_solution_source", "testdata", "message"),
    [
        ("", [{"input": "", "output": ""}], "标准程序不能为空"),
        ("code", [], "测试数据不能为空"),
        ("code", "not-json", "不是合法的 JSON"),
        ("code", {"input": ""}, "必须是测试点数组"),
        ("code", ["bad"], "第 1 个测试点格式无效"),
    ],
)
def test_validate_staged_testdata_rejects_invalid_inputs_without_judging(
    monkeypatch,
    standard_solution_source,
    testdata,
    message,
):
    monkeypatch.setattr(
        validation.core,
        "batch_evaluate",
        lambda *_args, **_kwargs: pytest.fail("不应启动判题"),
    )
    result = validation.validate_staged_testdata(
        _problem(),
        standard_solution_source,
        testdata,
        task_id="task-5",
    )
    assert result["success"] is False
    assert result["status"] == "Error"
    assert message in result["message"]


def test_validate_staged_testdata_marks_missing_test_result_as_error(monkeypatch):
    monkeypatch.setattr(
        validation.core,
        "batch_evaluate",
        lambda _language, _payload: {
            "compile_result": {"status": "success"},
            "test_results": [_run_result("one")],
        },
    )
    monkeypatch.setattr(validation.core, "cleanup_run_artifacts", lambda *_a, **_k: None)

    result = validation.validate_staged_testdata(
        _problem(),
        "int main() {}",
        [
            {"input": "", "output": "one"},
            {"input": "", "output": "two"},
        ],
        task_id="task-6",
    )

    assert result["success"] is False
    assert result["score"] == 1
    assert result["test_points"][1]["status"] == "Error"
    assert "未返回" in result["test_points"][1]["stderr"]
