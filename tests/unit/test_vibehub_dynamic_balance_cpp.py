"""作品内部的 C++ 执行请求、中位数规则与可信轨迹重放。"""

import base64
import importlib.util
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[2] / "vibehub_examples" / "dynamic-balance"
_spec = importlib.util.spec_from_file_location("dynamic_balance_cpp_test", EXAMPLE / "cpp.py")
cpp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cpp)


def _replay(stdout, inputs, *, executor=cpp.LEGACY_EXECUTOR, **kwargs):
    return cpp._replay(stdout, inputs, executor=executor, **kwargs)


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
    rounds = _replay(VALID_TRACE, [7, 3, 10])
    assert [item["expected"] for item in rounds] == [7, 3, 7]
    assert all(item["passed"] for item in rounds)
    assert rounds[1]["left_heap"] == [3]
    assert rounds[1]["right_heap"] == [7]
    assert rounds[2]["left_heap"] == [7, 3]
    assert rounds[2]["right_heap"] == [10]


def test_correct_return_without_storing_the_input_passes():
    result = _replay("ROUND 0 7 0\n", [7])[0]
    assert result["returned"] == result["expected"]
    assert result["passed"] is True
    assert result["left_heap"] == result["right_heap"] == []
    assert result["feedback"] == "中位数正确"


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
        _replay(trace, [7])


def test_replay_does_not_require_balanced_sizes_or_a_fixed_partition():
    rounds = _replay("ROUND 0 3 1\nA I 3\nROUND 1 3 1\nA I 7\n", [3, 7])
    assert rounds[0]["passed"] is True
    assert rounds[1]["passed"] is True
    assert rounds[1]["left_heap"] == [7, 3] and rounds[1]["right_heap"] == []
    rounds = _replay("ROUND 0 3 1\nA I 3\nROUND 1 1 1\nB I 1\n", [3, 1])
    assert rounds[1]["passed"] is True
    assert rounds[1]["left_heap"] == [3] and rounds[1]["right_heap"] == [1]


@pytest.mark.parametrize("operations", ["", "A I 7\nB I 7\n", "A I 7\nA P 7\n"])
def test_correct_median_passes_even_with_missing_duplicate_or_discarded_heap_elements(operations):
    count = len(operations.splitlines())
    result = cpp._replay(f"ROUND 0 7 {count}\n" + operations, [7])[0]
    assert result["passed"] is True
    assert result["feedback"] == "中位数正确"


def test_standard_median_uses_the_input_history_with_no_heap_operations():
    rounds = cpp._replay("ROUND 0 7 0\nROUND 1 5 0\nROUND 2 7 0\n", [7, 3, 10])
    assert all(item["passed"] for item in rounds)
    assert all(item["left_heap"] == item["right_heap"] == [] for item in rounds)
    assert [item["expected"] for item in rounds] == [7, 5, 7]


def test_wrong_return_still_fails_even_with_a_normal_heap_trace():
    result = cpp._replay("ROUND 0 9 1\nA I 7\n", [7])[0]
    assert result["passed"] is False
    assert result["feedback"] == "返回的中位数不正确"


def command_result(returncode=0, stdout="", stderr="", **overrides):
    return {"returncode": returncode,
        "stdout_b64": base64.b64encode(stdout.encode()).decode(),
        "stderr_b64": base64.b64encode(stderr.encode()).decode(),
        "stdout_truncated": False, "stderr_truncated": False, **overrides}


def execute(source, inputs, response, *, executor=cpp.LEGACY_EXECUTOR):
    cpp.build_request(source, inputs, executor=executor)
    return cpp.finish_execution(response, inputs, executor=executor)


def test_compile_request_keeps_student_macros_out_of_the_driver():
    source = "#define main ignored\nint step(int x) { A.insert(x); return A.top(); }"
    request = cpp.build_request(source, [7, 3, 10], executor=cpp.LEGACY_EXECUTOR)
    assert set(request) == {"files", "compile", "run", "executable"}
    assert set(request["files"]) == {"api.hpp", "student.cpp", "driver.cpp"}
    assert request["files"]["student.cpp"] == '#include "api.hpp"\n' + source
    assert source not in request["files"]["driver.cpp"]
    assert "int main()" in request["files"]["driver.cpp"]
    assert "int size();" in request["files"]["api.hpp"]
    assert request["compile"] == {"argv": ["/usr/bin/g++", "-std=c++20", "-O2", "-pipe", "-I", "${WORKDIR}",
        "${WORKDIR}/student.cpp", "${WORKDIR}/driver.cpp", "-o", "${WORKDIR}/program"], "seconds": 25}
    assert request["run"] == {"stdin": "3\n7\n3\n10\n", "seconds": 5}
    assert request["executable"] == "program"


def test_score_counts_only_the_correct_prefix():
    result = execute("int step(int x) { return x; }", [7, 3, 10], {
        "compile": command_result(),
        "run": command_result(stdout=VALID_TRACE.replace("ROUND 1 3", "ROUND 1 999")),
    })
    assert [item["passed"] for item in result["rounds"]] == [True, False, True]
    assert result["passed"] == 1


def test_runtime_exception_preserves_completed_rounds_and_current_heap_operations():
    output = "ROUND 0 7 2\nA I 7\nA T 7\nERROR 1 1\nA I 3\n"
    result = execute("int step(int x) { return x; }", [7, 3, 10], {
        "compile": command_result(),
        "run": command_result(3, output, "B.top()：不能读取空堆的堆顶"),
    })
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
    rounds = _replay("ROUND 0 7 2\nA I 7\nA T 7\n", [7, 3, 10], runtime_error="运行超时")
    assert len(rounds) == 2
    assert rounds[0]["passed"] is True
    assert rounds[1]["passed"] is False and rounds[1]["x"] == 3
    assert rounds[1]["left_heap"] == [7]
    assert "运行超时" in rounds[1]["feedback"]


def test_a_successful_process_cannot_pass_by_printing_a_runtime_error_frame():
    with pytest.raises(ValueError):
        _replay("ERROR 0 0\n", [7])


def test_compile_failure_does_not_require_a_user_executable_result():
    result = execute("invalid C++", [7], {"compile": command_result(1, stderr="step 编译错误")})
    assert result["compiled"] is False
    assert "编译错误" in result["error"]


@pytest.mark.parametrize("stage", ["compile", "run"])
def test_infrastructure_failure_raises_for_platform_retry_instead_of_grading_zero(stage):
    response = {"compile": command_result()}
    if stage == "run":
        response["run"] = command_result(-1)
    else:
        response["compile"] = command_result(-1)
    with pytest.raises(RuntimeError, match="服务暂时不可用"):
        execute("int step(int x) { return x; }", [7], response)


def test_student_exit_255_remains_a_student_runtime_error():
    result = execute("int step(int x) { return x; }", [7], {
        "compile": command_result(), "run": command_result(255, stderr="学生程序退出"),
    })
    assert result["compiled"] is True
    assert result["passed"] == 0 and result["total"] == 1
    assert "学生程序退出" in result["error"]
    assert result["rounds"][0]["returned"] is None


@pytest.mark.parametrize("source", ["", "   ", "x" * (cpp.MAX_SOURCE_BYTES + 1), "double step(int x) {\x00}"])
def test_empty_and_oversized_source_cannot_create_an_execution_request(source):
    with pytest.raises(ValueError):
        cpp.build_request(source, [7])


@pytest.mark.parametrize("inputs", [[], [True], [1.5], [1000000001], [-1000000001], [0] * 513])
def test_invalid_inputs_are_rejected_by_request_and_result_processing(inputs):
    with pytest.raises(ValueError):
        cpp.build_request("double step(int x){return x;}", inputs)
    with pytest.raises(ValueError):
        cpp.finish_execution({}, inputs)


def test_size_reads_empty_and_nonempty_heaps_without_mutating_them():
    result = _replay("ROUND 0 7 5\nA S 0\nB S 0\nA I 7\nA S 1\nA T 7\n", [7])[0]
    assert result["passed"] is True
    assert result["left_heap"] == [7] and result["right_heap"] == []
    assert [item["value"] for item in result["operations"] if item["type"] == "size"] == [0, 0, 1]
    with pytest.raises(ValueError, match="实际堆大小"):
        _replay("ROUND 0 7 2\nA I 7\nA S 99\n", [7])


@pytest.mark.parametrize("response", [None, {}, {"compile": {}},
    {"compile": command_result(), "score": 100},
    {"compile": command_result(), "run": command_result(stdout_b64="not base64!")},
    {"compile": command_result()},
])
def test_invalid_runner_results_never_become_a_grade(response):
    with pytest.raises(RuntimeError, match="执行响应"):
        execute("int step(int x){return x;}", [7], response)


def test_v2_uses_the_average_and_keeps_the_legacy_lower_median_unchanged():
    trace = VALID_TRACE.replace('ROUND 1 3 ', 'ROUND 1 5 ')
    rounds = _replay(trace, [7, 3, 10], executor=cpp.MEDIAN_EXECUTOR)
    assert [item['expected'] for item in rounds] == [7.0, 5.0, 7.0]
    assert all(item['passed'] for item in rounds)
    legacy = _replay(VALID_TRACE, [7, 3, 10], executor=cpp.LEGACY_EXECUTOR)
    assert [item['expected'] for item in legacy] == [7, 3, 7]
    assert all(item['passed'] for item in legacy)
    with pytest.raises(ValueError, match='无效整数'):
        _replay('ROUND 0 7.0 1\nA I 7\n', [7])


@pytest.mark.parametrize('left,right,returned', [(1, 2, '1.5'), (-4, -1, '-2.5'),
    (999999999, 1000000000, '999999999.5'),
    (-1000000000, -999999999, '-999999999.5'),
    (-1000000000, 1000000000, '0'), (1000000000, 1000000000, '1e9')])
def test_v2_accepts_exact_half_integer_and_extreme_medians(left, right, returned):
    trace = f'ROUND 0 {left} 1\nA I {left}\nROUND 1 {returned} 1\nB I {right}\n'
    result = _replay(trace, [left, right], executor=cpp.MEDIAN_EXECUTOR)
    assert all(item['passed'] for item in result)
    assert result[-1]['returned'] == result[-1]['expected'] == (left + right) / 2


@pytest.mark.parametrize('left,right,wrong', [(1, 2, '1'), (-4, -1, '-2'),
    (999999999, 1000000000, '999999999'), (999999999, 1000000000, '1000000000'),
    (-1000000000, -999999999, '-999999999')])
def test_v2_rejects_integer_division_and_half_unit_errors_at_large_magnitudes(left, right, wrong):
    trace = f'ROUND 0 {left} 1\nA I {left}\nROUND 1 {wrong} 1\nB I {right}\n'
    result = _replay(trace, [left, right], executor=cpp.MEDIAN_EXECUTOR)
    assert result[0]['passed'] is True
    assert result[1]['valid'] is True and result[1]['passed'] is False
    assert '中位数不正确' in result[1]['feedback']


@pytest.mark.parametrize('returned', ['nan', '-nan', 'NaN', 'inf', '-inf', '+Infinity',
    '1e309', '-1e999', '1_000', '0x1p0'])
def test_v2_never_accepts_nonfinite_or_nondecimal_return_values(returned):
    with pytest.raises(ValueError, match='有限浮点数'):
        _replay(f'ROUND 0 {returned} 1\nA I 7\n', [7], executor=cpp.MEDIAN_EXECUTOR)


@pytest.mark.parametrize('operation', ['A I 7.0', 'A I 7e0', 'A I 7_0', 'A S 0.0'])
def test_v2_keeps_heap_operation_values_strictly_integer(operation):
    with pytest.raises(ValueError, match='无效整数'):
        _replay(f'ROUND 0 7 1\n{operation}\n', [7], executor=cpp.MEDIAN_EXECUTOR)


@pytest.mark.parametrize('executor,result_type,returned,expected', [
    (cpp.LEGACY_EXECUTOR, 'int', '7', 7),
    (cpp.MEDIAN_EXECUTOR, 'double', '7.0', 7.0),
])
def test_request_selects_the_matching_work_owned_function_abi_and_replay(executor, result_type, returned, expected):
    request = cpp.build_request(f'{result_type} step(int x){{A.insert(x);return A.top();}}', [7], executor=executor)
    assert f'{result_type} step(int x);' in request['files']['api.hpp']
    assert f'using NumOJStepResult = {result_type};' in request['files']['driver.cpp']
    assert 'std::numeric_limits<NumOJStepResult>::max_digits10' in request['files']['driver.cpp']
    result = cpp.finish_execution({'compile': command_result(),
        'run': command_result(stdout=f'ROUND 0 {returned} 1\nA I 7\n')}, [7], executor=executor)
    assert result['passed'] == 1
    assert result['rounds'][0]['expected'] == expected


def test_v2_nonfinite_program_output_is_a_student_failure():
    result = execute('double step(int x){return 0.0/0.0;}', [7],
        {'compile': command_result(), 'run': command_result(stdout='ROUND 0 nan 1\nA I 7\n')},
        executor=cpp.MEDIAN_EXECUTOR)
    assert result['compiled'] is True and result['passed'] == 0
    assert '有限浮点数' in result['error']


def test_unknown_work_owned_abi_cannot_create_any_program():
    with pytest.raises(ValueError, match='不支持'):
        cpp.build_request('double step(int x){return x;}', [7], executor='client-defined-executor')


def test_default_abi_is_double_and_even_median_is_an_average():
    request = cpp.build_request('double step(int x){return x;}', [1, 2])
    assert 'double step(int x);' in request['files']['api.hpp']
    result = cpp.finish_execution({'compile': command_result(), 'run': command_result(
        stdout='ROUND 0 1 1\nA I 1\nROUND 1 1.5 1\nB I 2\n')}, [1, 2])
    assert result['passed'] == 2
    assert result['rounds'][1]['returned'] == result['rounds'][1]['expected'] == 1.5


def test_work_implementation_has_no_platform_or_process_dependency():
    source = (EXAMPLE / 'cpp.py').read_text()
    assert 'from backend' not in source and 'import backend' not in source
    assert 'subprocess' not in source and 'docker.' not in source


def test_work_request_satisfies_the_generic_execution_resource_contract():
    from backend.oj_modules.vibehub.edu_execution import validate_request

    request = cpp.build_request('double step(int x){A.insert(x);return A.top();}',
        [1, 2, -1000000000, 1000000000])
    assert validate_request(request) == request
