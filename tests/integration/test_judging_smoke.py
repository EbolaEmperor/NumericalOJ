# -*- coding: utf-8 -*-
import pytest

from oj_modules import judger_core

pytestmark = pytest.mark.judger


def _batch_data(code):
    return {
        'code': code,
        'test_cases': [{'input': ''}],
        'timeLimit': 2_000_000_000,
        'memoryLimit': 268435456,
        'sid': 'smoke-batch',
        'forbidden': '',
        'user_files': {},
        'outputImageFilename': 'output.png',
    }


def _single_data(code):
    return {
        'code': code,
        'input': '',
        'timeLimit': 2_000_000_000,
        'memoryLimit': 268435456,
        'sid': 'smoke-single',
        'forbidden': '',
        'user_files': {},
        'outputImageFilename': 'output.png',
    }


def test_python_runs_and_outputs():
    # Python 走单次运行（batch_evaluate 仅支持 c/cpp）
    res = judger_core.run_single('python', _single_data("print('hello')\n"))
    assert res['status'] == 'Accepted', res
    assert 'hello' in res['files']['stdout']


def test_c_compiles_and_runs():
    code = '#include <stdio.h>\nint main(){printf("42\\n");return 0;}\n'
    res = judger_core.batch_evaluate('c', _batch_data(code))
    assert res['compile_result']['status'] == 'success'
    assert '42' in res['test_results'][0]['files']['stdout']


# ============== 真实判题结论（核心决策逻辑回归） ==============
def test_compile_error_verdict():
    # C 语法错误 → 编译失败
    res = judger_core.batch_evaluate('c', _batch_data('int main(){ return }\n'))
    assert res['compile_result']['status'] != 'success'
    assert res['test_results'] == []


def test_runtime_error_verdict():
    # 空指针解引用 → 段错误 → Runtime Error（returncode != 0）
    code = '#include <stdio.h>\nint main(){ int *p = 0; *p = 1; return 0; }\n'
    res = judger_core.batch_evaluate('c', _batch_data(code))
    assert res['compile_result']['status'] == 'success'
    assert res['test_results'][0]['status'] == 'Runtime Error'


def test_time_limit_exceeded_verdict():
    # 死循环 → 超时（coreutils timeout 先于 Python 兜底触发）
    data = _single_data("while True:\n    pass\n")
    data['timeLimit'] = 1_000_000_000   # 1s，加速用例
    res = judger_core.run_single('python', data)
    assert res['status'] == 'Time Limit Exceeded', res


def test_forbidden_function_verdict():
    # 禁用 eval，但代码用了 eval( → Forbidden
    data = _single_data("print(eval('1+1'))\n")
    data['forbidden'] = 'eval'
    res = judger_core.run_single('python', data)
    assert res['status'] == 'Forbidden', res


def test_forbidden_marker_injection_does_not_bypass():
    # 安全回归：即便用户代码里塞入结束标记串，禁用函数仍应被检测到。
    # （evaluate_tasks 会在包裹前剥离标记；此处直接验证 check_forbidden 对 eval 的命中。）
    code = "print('user_code_end_fuck_hahaha_fuck')\nprint(eval('1+1'))\n"
    data = _single_data(code)
    data['forbidden'] = 'eval'
    res = judger_core.run_single('python', data)
    assert res['status'] == 'Forbidden', res


mkl_required = pytest.mark.skipif(
    not getattr(judger_core, 'MKL_ROOT', None),
    reason="未检测到 Intel MKL（judger_core.MKL_ROOT 为空）——需在挂载了 oneAPI MKL 的主机上运行",
)


@mkl_required
def test_c_submit_with_mkl_cblas():
    """提交一段引用 MKL（cblas_ddot）的 C 代码，验证判题沙箱能编译+链接 MKL 并运行得到正确结果。"""
    code = (
        '#include <stdio.h>\n'
        '#include "mkl.h"\n'
        'int main(void){\n'
        '    double a[3] = {1, 2, 3}, b[3] = {4, 5, 6};\n'
        '    printf("%.0f\\n", cblas_ddot(3, a, 1, b, 1));\n'  # 1*4+2*5+3*6 = 32
        '    return 0;\n'
        '}\n'
    )
    res = judger_core.batch_evaluate('c', _batch_data(code))
    assert res['compile_result']['status'] == 'success', res['compile_result'].get('stderr')
    tr = res['test_results'][0]
    assert tr['status'] == 'Accepted', tr
    assert '32' in tr['files']['stdout']
