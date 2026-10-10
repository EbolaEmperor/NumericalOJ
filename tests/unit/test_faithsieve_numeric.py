"""使用镜像的实际 SymPy 版本检验符号证据，不运行学生代码或云资源。"""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest


pytest.importorskip("sympy")
_TOOL_PATH = Path(__file__).resolve().parents[2] / "docker/agent_judge/faithsieve_tool.py"
_SPEC = spec_from_file_location("faithsieve_numeric_tool", _TOOL_PATH)
tool = module_from_spec(_SPEC)
_SPEC.loader.exec_module(tool)


@pytest.mark.parametrize(("lhs", "rhs", "status"), [
    ("1/2 + 1/3", "5/6", "passed"),
    ("sqrt(4)", "2", "passed"),
    ("sin(pi)", "0", "passed"),
    ("1", "2", "refuted"),
    ("1/0", "1/0", "inconclusive"),
    ("0/0", "0/0", "inconclusive"),
    ("log(0)", "log(0)", "inconclusive"),
    ("0/(1-1)", "0", "inconclusive"),
    ("0/sin(pi)", "0", "inconclusive"),
    ("0**-1", "0**-1", "inconclusive"),
    ("0*(0**-1)", "0", "inconclusive"),
    ("0*log(0)", "0", "inconclusive"),
    ("Rational(0,0)", "Rational(0,0)", "inconclusive"),
    ("0.1 + 0.2", "3/10", "inconclusive"),
    ("x", "x", "inconclusive"),
    ("__import__('os').system('echo unsafe')", "0", "inconclusive"),
])
def test_exact_relations_preserve_definedness_and_reject_unsafe_or_approximate_input(lhs, rhs, status):
    checked = tool.numeric({"expressions": {"relations": [{"lhs": lhs, "relation": "eq", "rhs": rhs}]}})
    assert checked["status"] == status
    assert checked["exit_code"] == 0
    assert checked["commands"]


def test_undefined_relation_keeps_whole_chain_inconclusive_even_when_another_relation_is_false():
    checked = tool.numeric({"expressions": {"relations": [
        {"lhs": "1", "relation": "eq", "rhs": "2"},
        {"lhs": "0/0", "relation": "eq", "rhs": "0/0"},
    ]}})
    assert checked["status"] == "inconclusive"


@pytest.mark.parametrize("warmups", [
    ["0", "1/0", "0/0"],
    ["0/0", "0", "1/0"],
    ["0**-1", "0", "0/0"],
    ["0*(0**-1)", "0/0", "0"],
])
def test_undefinedness_is_stable_after_sympy_cache_warmups_and_repeated_relations(warmups):
    import sympy as s
    from sympy.core.cache import clear_cache
    from sympy.parsing.sympy_parser import parse_expr
    clear_cache()
    for text in warmups:
        expression = parse_expr(text, evaluate=False)
        # 重现 SymPy 对未求值 0**-1 的假设/化简缓存已经访问过的情况。
        try:
            _ = expression.is_finite
            s.simplify(expression)
        except s.core.facts.InconsistentAssumptions:
            # SymPy 1.14 对同一未求值 0/0 的缓存访问也可能抛假设冲突；
            # 继续用已经访问过的缓存检验真实工具始终 fail closed。
            pass
    for _ in range(4):
        checked = tool.numeric({"expressions": {"relations": [
            {"lhs": "0", "relation": "eq", "rhs": "0"},
            {"lhs": "0/0", "relation": "eq", "rhs": "0/0"},
            {"lhs": "1", "relation": "eq", "rhs": "2"},
        ]}})
        assert checked["status"] == "inconclusive"
