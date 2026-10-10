#!/usr/bin/env python3
"""预装在通用 Judge 镜像中的确定性工具；不调用 LLM。"""

from __future__ import annotations

import ast
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


MATHLIB = Path('/opt/numoj-lean-project')
ELAN = Path('/opt/elan')
LEAN = Path('/usr/local/bin/lean')
LEAN_PATH_FILE = Path('/opt/numoj-lean-path')
PROTOCOL = "faithsieve-tools-v1"


def _run(command, *, timeout, cwd=None, env=None):
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
        return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "commands": [command]}
    except subprocess.TimeoutExpired as exc:
        def _text(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else str(value or "")
        return {"exit_code": 124, "stdout": _text(exc.stdout), "stderr": _text(exc.stderr) + "\n工具执行超时", "commands": [command]}


def preflight(_payload):
    import sympy
    if sympy.simplify(sympy.Rational(1, 2) + sympy.Rational(1, 3) - sympy.Rational(5, 6)) != 0:
        raise ValueError("SymPy 精确运算不可用")
    if not (MATHLIB / ".lake/build/lib/lean/Mathlib.olean").is_file():
        raise ValueError("缺少预编译 mathlib")
    for program in ("pdftoppm", "pdfinfo"):
        if not shutil.which(program):
            raise ValueError(f"未预装 {program}")
    with tempfile.TemporaryDirectory(prefix="faithsieve-lean-check-") as directory:
        path = Path(directory) / "check.lean"
        path.write_text("import Mathlib.Data.Nat.Basic\nexample : (1 : Nat) + 1 = 2 := by decide\n")
        result = compile_lean({"workspace": directory, "path": path.name, "timeout_seconds": 30})
    if result["exit_code"] != 0:
        raise ValueError("Lean 无法编译预装 mathlib 模块")
    return {**result, "ready": True}


def compile_lean(payload):
    workspace = Path(payload["workspace"]).resolve()
    path = (workspace / payload["path"]).resolve()
    if not path.is_relative_to(workspace) or not path.is_file():
        raise ValueError("Lean 文件路径无效")
    env = dict(os.environ)
    env["ELAN_HOME"] = str(ELAN)
    cached_paths = LEAN_PATH_FILE.read_text().strip().split(':')
    absolute_paths = [str((MATHLIB / path).resolve()) if not Path(path).is_absolute() else path for path in cached_paths if path]
    env["LEAN_PATH"] = ':'.join([str(workspace), *absolute_paths])
    return _run([str(LEAN), str(path)], timeout=int(payload.get("timeout_seconds") or 300), cwd=workspace, env=env)


def _exact_expression(text):
    """安全校验 Agent 的标准 SymPy 表达式，数学解析交给 SymPy。"""

    import sympy as s
    from sympy.parsing.sympy_parser import parse_expr
    if not isinstance(text, str) or not text or len(text) > 2048:
        raise ValueError("表达式过长或为空")
    tree = ast.parse(text, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > 256:
        raise ValueError("表达式过于复杂")
    names = {"pi": s.pi, "E": s.E, "I": s.I}
    functions = {name: getattr(s, name) for name in (
        "Rational", "Integer", "sqrt", "sin", "cos", "tan", "exp", "log", "Abs", "factorial", "binomial", "floor", "ceiling",
    )}
    allowed_nodes = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Call, ast.Name, ast.Load,
                     ast.Constant, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.UAdd, ast.USub)
    for node in ast.walk(tree):
        if not isinstance(node, allowed_nodes):
            raise ValueError("不是允许的封闭精确表达式")
        if isinstance(node, ast.Constant):
            if not isinstance(node.value, int) or isinstance(node.value, bool):
                raise ValueError("不允许浮点近似或字符串")
            if abs(node.value).bit_length() > 4096:
                raise ValueError("整数过大")
        if isinstance(node, ast.Name) and node.id not in names and node.id not in functions:
            raise ValueError("不允许自由变量或未知函数")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in functions or node.keywords or len(node.args) > 3:
                raise ValueError("函数参数过多")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow) and isinstance(node.right, ast.Constant) and abs(node.right.value) > 10000:
            raise ValueError("指数过大")
    # 仅校验可执行语法边界；不维护学生原稿或数学表达式的自定义解析器。
    globals_dict = {"__builtins__": {}, "Integer": s.Integer, "Rational": s.Rational,
                    "Add": s.Add, "Mul": s.Mul, "Pow": s.Pow}
    # 先在原安全 AST 上定位除法，分母的数学求值仍完全交给 SymPy。
    # 这保留定义域信息，避免后续化简或缓存把 0/0 直接消成 0。
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            denominator = parse_expr(ast.unparse(node.right), local_dict={**names, **functions}, global_dict=globals_dict, evaluate=False)
            denominator = s.simplify(denominator)
            if denominator.is_zero is True or denominator.has(s.nan, s.zoo, s.oo, -s.oo) or denominator.is_finite is not True:
                raise ValueError("分母为零、未定义或不能确认是有限数值")
    expression = parse_expr(text, local_dict={**names, **functions}, global_dict=globals_dict, evaluate=False)
    if expression.free_symbols:
        raise ValueError("不是封闭数值表达式")
    # 必须在化简前检查每个子表达式：SymPy 的 0*(0**-1) 化简可吞掉
    # 未定义的分母，直接只检查最终结果会把 0/0 错判为有限数值。
    for part in s.preorder_traversal(expression):
        # unevaluated Pow(0, -1) 的 is_finite 可错误地显示 True；需要实际
        # 求值每个子项后检查 zoo/nan/oo，不能相信未求值表达式的假设缓存。
        checked_part = s.simplify(part)
        if checked_part.has(s.nan, s.zoo, s.oo, -s.oo) or checked_part.is_finite is False:
            raise ValueError("子表达式未定义或不是有限数值")
    expression = s.simplify(expression)
    if expression.has(s.nan, s.zoo, s.oo, -s.oo) or expression.is_finite is not True:
        raise ValueError("表达式未定义或不属于可验证的有限数值")
    return expression


def numeric(payload):
    import sympy as s
    expressions = payload.get("expressions")
    relations = expressions.get("relations") if isinstance(expressions, dict) else None
    if not isinstance(relations, list) or not relations or len(relations) > 128:
        return {"status": "inconclusive", "exit_code": 0, "stdout": "无可复验的封闭精确关系", "stderr": "", "relations": [], "commands": ["faithsieve-tool numeric (SymPy exact relations)"]}
    results = []
    operators = {"eq": s.Eq, "ne": s.Ne, "lt": s.Lt, "le": s.Le, "gt": s.Gt, "ge": s.Ge}
    for relation in relations:
        try:
            if not isinstance(relation, dict) or set(relation) != {"lhs", "relation", "rhs"}:
                raise ValueError("关系协议无效")
            lhs, rhs = _exact_expression(relation["lhs"]), _exact_expression(relation["rhs"])
            operation = operators[relation["relation"]]
            actual = s.simplify(operation(lhs, rhs))
            truth = True if actual is s.true else False if actual is s.false else None
            results.append({**relation, "actual": str(actual), "truth": truth})
        except Exception:
            results.append({"relation": relation, "actual": "无法可靠解析或符号工具不能决定", "truth": None})
    # 任一关系不可靠，整项都不报告确定性证伪。
    status = "inconclusive" if any(item["truth"] is None for item in results) else "refuted" if any(item["truth"] is False for item in results) else "passed"
    return {"status": status, "exit_code": 0, "stdout": json.dumps(results, ensure_ascii=False), "stderr": "", "relations": results, "commands": ["faithsieve-tool numeric (SymPy exact relations)"]}


def extract(payload):
    pdf = base64.b64decode(payload["pdf"], validate=True)
    if not pdf.startswith(b"%PDF-") or len(pdf) > 20 * 1024 * 1024:
        raise ValueError("PDF 无效或过大")
    budget = int(payload.get("timeout_seconds") or 120)
    import time
    deadline = time.monotonic() + budget
    def run(command):
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            raise ValueError("PDF 提取超时")
        result = _run(command, timeout=remaining)
        if result["exit_code"]:
            raise ValueError("PDF 渲染工具执行失败")
        return result["stdout"]
    with tempfile.TemporaryDirectory(prefix="faithsieve-pdf-") as directory:
        root = Path(payload["workspace"]) if payload.get("workspace") else Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        source = root / "submission.pdf"
        source.write_bytes(pdf)
        info = run(["pdfinfo", str(source)])
        pages = next((int(line.split(":", 1)[1]) for line in info.splitlines() if line.startswith("Pages:")), 0)
        if not 1 <= pages <= 100:
            raise ValueError("PDF 页数无效或超过 100 页")
        page_files = []
        for page in range(1, pages + 1):
            image_prefix = root / f"page-{page}"
            run(["pdftoppm", "-f", str(page), "-l", str(page), "-scale-to", "2400", "-singlefile", "-png", str(source), str(image_prefix)])
            image_path = Path(str(image_prefix) + ".png")
            if not image_path.is_file() or image_path.read_bytes()[:8] != b"\x89PNG\r\n\x1a\n":
                raise ValueError("PDF 页面未成功渲染")
            page_files.append({"page": page, "image_path": str(image_path), "rendered": True})
    return {"page_count": pages, "pages": page_files, "exit_code": 0, "tool_executed": True}


def main():
    try:
        operation, packed = sys.argv[1:]
        payload = json.loads(Path(packed[1:]).read_text()) if packed.startswith("@") else json.loads(base64.b64decode(packed, validate=True))
        methods = {"preflight": preflight, "compile": compile_lean, "numeric": numeric, "extract": extract}
        result = methods[operation](payload)
        print(json.dumps({"protocol": PROTOCOL, **result}, ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({"protocol": PROTOCOL, "error": True, "message": str(exc)}, ensure_ascii=False))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
