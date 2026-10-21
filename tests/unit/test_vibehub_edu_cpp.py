"""教学 C++ 运行必须走普通判题沙箱，分数与堆状态独立重放。"""

from pathlib import Path

import pytest

from backend.oj_modules.judging.sandbox import _RunResult
from backend.oj_modules.vibehub import edu_cpp


VALID_TRACE = """ROUND 0 7 2
A I 7
A T 7
ROUND 1 3 4
A I 3
A T 7
A P 7
B I 7
ROUND 2 7 6
B I 10
B T 7
B P 7
A I 7
A T 7
A T 7
"""


def test_replay_uses_lower_median_and_reconstructs_real_heap_snapshots():
    rounds = edu_cpp._replay(VALID_TRACE, [7, 3, 10])
    assert [item["expected"] for item in rounds] == [7, 3, 7]
    assert all(item["passed"] for item in rounds)
    assert rounds[1]["left_heap"] == [3]
    assert rounds[1]["right_heap"] == [7]
    assert rounds[2]["left_heap"] == [7, 3]
    assert rounds[2]["right_heap"] == [10]


def test_correct_return_without_storing_the_input_does_not_pass():
    result = edu_cpp._replay("ROUND 0 7 0\n", [7])[0]
    assert result["returned"] == result["expected"]
    assert result["passed"] is False
    assert "保存所有已经输入的数" in result["feedback"]


@pytest.mark.parametrize("trace", [
    "ROUND 0 7 2\nA I 3\nA T 7\n",  # 伪报堆顶。
    "ROUND 0 7 1\nA P 7\n",  # 空堆出队。
    "ROUND 0 7 1\nC I 7\n",  # 非协议堆。
    "ROUND 0 7 1\nA I 2147483648\n",  # 非 int。
    "ROUND 0 7 4097\n",  # 单轮输出不受控。
    "ROUND 0 7 -1\n",  # 负操作数。
    "ROUND 1 7 0\n",  # 伪报序号。
    "ROUND 0 7 1\nA I 7\ncompleted=true score=100\n",  # 自报成绩。
])
def test_replay_rejects_fabricated_or_unbounded_operation_records(trace):
    with pytest.raises(ValueError):
        edu_cpp._replay(trace, [7])


def test_replay_checks_balance_and_partition_separately_from_answer():
    rounds = edu_cpp._replay("ROUND 0 3 1\nA I 3\nROUND 1 3 1\nA I 7\n", [3, 7])
    assert rounds[0]["passed"] is True
    assert rounds[1]["passed"] is False
    assert "元素数" in rounds[1]["feedback"]
    rounds = edu_cpp._replay("ROUND 0 3 1\nA I 3\nROUND 1 1 1\nB I 1\n", [3, 1])
    assert rounds[1]["passed"] is False
    assert "全部不大于" in rounds[1]["feedback"]


def test_compile_and_execute_are_separate_bounded_docker_sandbox_calls(monkeypatch):
    calls = []
    source = "#define main ignored\nint step(int x) { A.insert(x); return A.top(); }"

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if len(calls) == 1:
            root = Path(kwargs["run_dir"])
            assert source in (root / "student.cpp").read_text()
            assert source not in (root / "harness.cpp").read_text()
            assert "int main()" in (root / "harness.cpp").read_text()
            assert "size()" not in (root / "heap_api.hpp").read_text()
            return _RunResult(0, "", "", artifacts={"a.out": b"test executable"})
        assert (Path(kwargs["run_dir"]) / "a.out").stat().st_mode & 0o777 == 0o755
        return _RunResult(0, VALID_TRACE, "")

    monkeypatch.setattr(edu_cpp.sandbox, "run_case_in_container", run)
    result = edu_cpp.run_code(source, [7, 3, 10])
    assert result["compiled"] is True
    assert result["passed"] == result["total"] == 3
    assert len(calls) == 2
    assert calls[0][0][:5] == ["timeout", "-k", "1s", "25s", "g++"]
    assert calls[0][1]["executable_name"] == "a.out"
    assert calls[1][0][-1] == "/sandbox/a.out"
    assert calls[1][1]["input_text"] == "3\n7\n3\n10\n"
    assert "executable_name" not in calls[1][1]
    assert not Path(calls[0][1]["run_dir"]).exists()


def test_score_counts_only_the_correct_prefix(monkeypatch):
    responses = iter([
        _RunResult(0, "", "", artifacts={"a.out": b"executable"}),
        _RunResult(0, VALID_TRACE.replace("ROUND 1 3", "ROUND 1 999"), ""),
    ])
    monkeypatch.setattr(edu_cpp.sandbox, "run_case_in_container", lambda *_a, **_k: next(responses))
    result = edu_cpp.run_code("int step(int x) { return x; }", [7, 3, 10])
    assert [item["passed"] for item in result["rounds"]] == [True, False, True]
    assert result["passed"] == 1


def test_runtime_exception_preserves_completed_rounds_and_current_heap_operations(monkeypatch):
    output = "ROUND 0 7 2\nA I 7\nA T 7\nERROR 1 1\nA I 3\n"
    responses = iter([
        _RunResult(0, "", "", artifacts={"a.out": b"executable"}),
        _RunResult(3, output, "B.top()：不能读取空堆的堆顶"),
    ])
    monkeypatch.setattr(edu_cpp.sandbox, "run_case_in_container", lambda *_a, **_k: next(responses))
    result = edu_cpp.run_code("int step(int x) { return x; }", [7, 3, 10])
    assert result["compiled"] is True
    assert result["passed"] == 1 and result["total"] == 3
    assert len(result["rounds"]) == 2
    failure = result["rounds"][-1]
    assert failure["error"] is True and failure["passed"] is False
    assert failure["returned"] is None
    assert failure["left_heap"] == [7, 3]
    assert failure["right_heap"] == []
    assert failure["operations"] == [{"heap": "A", "type": "insert", "value": 3}]
    assert "B.top()" in failure["feedback"]


def test_timeout_without_error_frame_adds_a_failure_after_the_complete_prefix():
    rounds = edu_cpp._replay("ROUND 0 7 2\nA I 7\nA T 7\n", [7, 3, 10], runtime_error="运行超时")
    assert len(rounds) == 2
    assert rounds[0]["passed"] is True
    assert rounds[1]["passed"] is False and rounds[1]["x"] == 3
    assert rounds[1]["left_heap"] == [7]
    assert "运行超时" in rounds[1]["feedback"]


def test_a_successful_process_cannot_pass_by_printing_a_runtime_error_frame():
    with pytest.raises(ValueError):
        edu_cpp._replay("ERROR 0 0\n", [7])


def test_compile_failure_never_starts_the_user_executable(monkeypatch):
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        return _RunResult(1, "", "step 编译错误")

    monkeypatch.setattr(edu_cpp.sandbox, "run_case_in_container", run)
    result = edu_cpp.run_code("invalid C++", [7])
    assert result["compiled"] is False
    assert "编译错误" in result["error"]
    assert len(calls) == 1


def test_empty_and_oversized_source_do_not_start_a_container(monkeypatch):
    monkeypatch.setattr(edu_cpp.sandbox, "run_case_in_container", lambda *_a, **_k: pytest.fail("不应启动容器"))
    assert edu_cpp.run_code("", [7])["compiled"] is False
    assert edu_cpp.run_code("x" * (edu_cpp.MAX_SOURCE_BYTES + 1), [7])["compiled"] is False
    with pytest.raises(ValueError):
        edu_cpp.run_code("int step(int x){return x;}", [True])
