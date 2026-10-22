"""教学 C++ 只在已有 VibeHub 容器执行，分数与堆状态由平台独立重放。"""

import base64
from types import SimpleNamespace

import pytest

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


def command_result(returncode=0, stdout="", stderr="", **overrides):
    return {"returncode": returncode,
        "stdout_b64": base64.b64encode(stdout.encode()).decode(),
        "stderr_b64": base64.b64encode(stderr.encode()).decode(),
        "stdout_truncated": False, "stderr_truncated": False, **overrides}


def execute(source, inputs, response, *, executor=edu_cpp.LEGACY_EXECUTOR):
    return edu_cpp.run_code(source, inputs, container_name="existing-container",
        docker=SimpleNamespace(execute_edu_cpp=lambda *_args, **_kwargs: response), executor=executor)


def test_compile_and_execute_use_one_existing_vibehub_container():
    calls = []
    source = "#define main ignored\nint step(int x) { A.insert(x); return A.top(); }"

    def run(container_name, payload, **kwargs):
        calls.append((container_name, payload, kwargs))
        assert payload["source"] == source
        assert source not in payload["harness"]
        assert "int main()" in payload["harness"]
        assert "int size();" in payload["api_header"]
        return {"compile": command_result(), "run": command_result(stdout=VALID_TRACE)}

    result = edu_cpp.run_code(source, [7, 3, 10], container_name="existing-container",
        docker=SimpleNamespace(execute_edu_cpp=run))
    assert result["compiled"] is True
    assert result["passed"] == result["total"] == 3
    assert len(calls) == 1
    assert calls[0][0] == "existing-container"
    assert calls[0][1]["inputs"] == [7, 3, 10]
    assert calls[0][1]["timeout_seconds"] == 5
    assert calls[0][2]["timeout"] == 35


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
    rounds = edu_cpp._replay("ROUND 0 7 2\nA I 7\nA T 7\n", [7, 3, 10], runtime_error="运行超时")
    assert len(rounds) == 2
    assert rounds[0]["passed"] is True
    assert rounds[1]["passed"] is False and rounds[1]["x"] == 3
    assert rounds[1]["left_heap"] == [7]
    assert "运行超时" in rounds[1]["feedback"]


def test_a_successful_process_cannot_pass_by_printing_a_runtime_error_frame():
    with pytest.raises(ValueError):
        edu_cpp._replay("ERROR 0 0\n", [7])


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


def test_empty_and_oversized_source_do_not_execute():
    docker = SimpleNamespace(execute_edu_cpp=lambda *_a, **_k: pytest.fail("不应执行"))
    kwargs = {"docker": docker, "container_name": "existing-container"}
    assert edu_cpp.run_code("", [7], **kwargs)["compiled"] is False
    assert edu_cpp.run_code("x" * (edu_cpp.MAX_SOURCE_BYTES + 1), [7], **kwargs)["compiled"] is False
    with pytest.raises(ValueError):
        edu_cpp.run_code("int step(int x){return x;}", [True], **kwargs)


def test_size_reads_empty_and_nonempty_heaps_without_mutating_them():
    result = edu_cpp._replay("ROUND 0 7 5\nA S 0\nB S 0\nA I 7\nA S 1\nA T 7\n", [7])[0]
    assert result["passed"] is True
    assert result["left_heap"] == [7] and result["right_heap"] == []
    assert [item["value"] for item in result["operations"] if item["type"] == "size"] == [0, 0, 1]
    with pytest.raises(ValueError, match="实际堆大小"):
        edu_cpp._replay("ROUND 0 7 2\nA I 7\nA S 99\n", [7])


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
    rounds = edu_cpp._replay(trace, [7, 3, 10], executor=edu_cpp.MEDIAN_EXECUTOR)
    assert [item['expected'] for item in rounds] == [7.0, 5.0, 7.0]
    assert all(item['passed'] for item in rounds)
    legacy = edu_cpp._replay(VALID_TRACE, [7, 3, 10], executor=edu_cpp.LEGACY_EXECUTOR)
    assert [item['expected'] for item in legacy] == [7, 3, 7]
    assert all(item['passed'] for item in legacy)
    with pytest.raises(ValueError, match='无效整数'):
        edu_cpp._replay('ROUND 0 7.0 1\nA I 7\n', [7])


@pytest.mark.parametrize('left,right,returned', [(1, 2, '1.5'), (-4, -1, '-2.5'),
    (999999999, 1000000000, '999999999.5'),
    (-1000000000, -999999999, '-999999999.5'),
    (-1000000000, 1000000000, '0'), (1000000000, 1000000000, '1e9')])
def test_v2_accepts_exact_half_integer_and_extreme_medians(left, right, returned):
    trace = f'ROUND 0 {left} 1\nA I {left}\nROUND 1 {returned} 1\nB I {right}\n'
    result = edu_cpp._replay(trace, [left, right], executor=edu_cpp.MEDIAN_EXECUTOR)
    assert all(item['passed'] for item in result)
    assert result[-1]['returned'] == result[-1]['expected'] == (left + right) / 2


@pytest.mark.parametrize('left,right,wrong', [(1, 2, '1'), (-4, -1, '-2'),
    (999999999, 1000000000, '999999999'), (999999999, 1000000000, '1000000000'),
    (-1000000000, -999999999, '-999999999')])
def test_v2_rejects_integer_division_and_half_unit_errors_at_large_magnitudes(left, right, wrong):
    trace = f'ROUND 0 {left} 1\nA I {left}\nROUND 1 {wrong} 1\nB I {right}\n'
    result = edu_cpp._replay(trace, [left, right], executor=edu_cpp.MEDIAN_EXECUTOR)
    assert result[0]['passed'] is True
    assert result[1]['valid'] is True and result[1]['passed'] is False
    assert '中位数不正确' in result[1]['feedback']


@pytest.mark.parametrize('returned', ['nan', '-nan', 'NaN', 'inf', '-inf', '+Infinity',
    '1e309', '-1e999', '1_000', '0x1p0'])
def test_v2_never_accepts_nonfinite_or_nondecimal_return_values(returned):
    with pytest.raises(ValueError, match='有限浮点数'):
        edu_cpp._replay(f'ROUND 0 {returned} 1\nA I 7\n', [7], executor=edu_cpp.MEDIAN_EXECUTOR)


@pytest.mark.parametrize('operation', ['A I 7.0', 'A I 7e0', 'A I 7_0', 'A S 0.0'])
def test_v2_keeps_heap_operation_values_strictly_integer(operation):
    with pytest.raises(ValueError, match='无效整数'):
        edu_cpp._replay(f'ROUND 0 7 1\n{operation}\n', [7], executor=edu_cpp.MEDIAN_EXECUTOR)


@pytest.mark.parametrize('executor,result_type,returned,expected', [
    (edu_cpp.LEGACY_EXECUTOR, 'int', '7', 7),
    (edu_cpp.MEDIAN_EXECUTOR, 'double', '7.0', 7.0),
])
def test_run_code_selects_the_matching_frozen_function_abi_and_replay(executor, result_type, returned, expected):
    calls = []

    def run(container_name, payload, **_kwargs):
        calls.append((container_name, payload))
        assert f'{result_type} step(int x);' in payload['api_header']
        assert f'using NumOJStepResult = {result_type};' in payload['harness']
        assert 'std::numeric_limits<NumOJStepResult>::max_digits10' in payload['harness']
        return {'compile': command_result(), 'run': command_result(stdout=f'ROUND 0 {returned} 1\nA I 7\n')}

    result = edu_cpp.run_code(f'{result_type} step(int x){{A.insert(x);return A.top();}}', [7],
        docker=SimpleNamespace(execute_edu_cpp=run), container_name='existing-container', executor=executor)
    assert len(calls) == 1 and result['passed'] == 1
    assert result['rounds'][0]['expected'] == expected


def test_v2_nonfinite_program_output_is_a_student_failure():
    result = execute('double step(int x){return 0.0/0.0;}', [7],
        {'compile': command_result(), 'run': command_result(stdout='ROUND 0 nan 1\nA I 7\n')},
        executor=edu_cpp.MEDIAN_EXECUTOR)
    assert result['compiled'] is True and result['passed'] == 0
    assert '有限浮点数' in result['error']


def test_unknown_executor_cannot_start_any_program():
    docker = SimpleNamespace(execute_edu_cpp=lambda *_a, **_k: pytest.fail('不应执行'))
    with pytest.raises(ValueError, match='不支持'):
        edu_cpp.run_code('double step(int x){return x;}', [7], docker=docker,
            container_name='existing-container', executor='client-defined-executor')
