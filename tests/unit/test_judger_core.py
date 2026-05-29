# -*- coding: utf-8 -*-
"""judger_core 纯逻辑单测（不触发真实编译/运行）。

覆盖（参考 plan Task 14 / contracts §2）：
- check_forbidden：命中各语言、未命中返回 None、Octave 反斜杠特例、正则词边界
- build_c_compile_cmd / build_cpp_compile_cmd：命令形状
- set_run_limits：RLIMIT_CPU / RLIMIT_AS 设置（monkeypatch resource.setrlimit 收集调用）
- run_dir_for：JUDGER_RUN_ROOT/<sanitized_sid>，不创建目录，危险字符清洗
- capture_output_image_file：合法扩展名集合，非法/缺失返回 None

真实编译运行的项见 tests/judger/test_judging_smoke.py，不在本文件。
"""
import os
import resource

import pytest

from oj_modules import judger_core


# ============== check_forbidden ==============
def test_check_forbidden_empty_returns_none():
    # 空禁用串 → 直接放行
    assert judger_core.check_forbidden("y = sin(x)\n", "") is None
    assert judger_core.check_forbidden("anything", None) is None


def test_check_forbidden_hits_octave_func():
    msg = judger_core.check_forbidden("y = sin(x)\n", "sin")
    assert msg is not None
    assert "sin" in msg
    # 源码返回的精确文案
    assert msg == "Function 'sin' is not allowed"


def test_check_forbidden_hits_c_func():
    code = '#include <stdio.h>\nint main(){ printf("hi"); return 0; }\n'
    msg = judger_core.check_forbidden(code, "printf")
    assert msg == "Function 'printf' is not allowed"


def test_check_forbidden_miss_when_func_absent():
    # 列表里有 cos 但代码只用了 sin → 不命中
    assert judger_core.check_forbidden("y = sin(x)\n", "cos") is None


def test_check_forbidden_word_boundary_asin_vs_sin():
    # asin 不应被 sin 命中（前缀需非 [a-zA-Z0-9_]）
    assert judger_core.check_forbidden("y = asin(x)\n", "sin") is None
    assert judger_core.check_forbidden("y = sin(x)\n", "sin") is not None


def test_check_forbidden_requires_call_paren():
    # 只出现函数名但没有 '(' → 不算调用，不命中
    assert judger_core.check_forbidden("x = sin;\n", "sin") is None
    # 函数名与 '(' 之间允许空白
    assert judger_core.check_forbidden("y = sin (x)\n", "sin") is not None


def test_check_forbidden_octave_backslash_special():
    # 反斜杠运算符特例（仅对 Octave 有意义）
    msg = judger_core.check_forbidden("x = A \\ b\n", "\\")
    assert msg == "Operator \\ is not allowed"
    # 代码里没有反斜杠 → 不命中
    assert judger_core.check_forbidden("x = A / b\n", "\\") is None


def test_check_forbidden_comma_separated_list():
    # 逗号分割多个禁用函数，命中其中之一即返回
    msg = judger_core.check_forbidden("z = cos(t)\n", "sin, cos , tan")
    assert msg == "Function 'cos' is not allowed"


def test_check_forbidden_only_checks_user_code_markers():
    # 命中只在用户代码标记之间检测；标记外的 sin( 不算
    code = (
        "y = sin(x)\n"  # 标记外
        "here_is_user_code_fuck_fuck_fuck_hahaha\n"
        "z = cos(t)\n"  # 标记内
        "user_code_end_fuck_hahaha_fuck\n"
    )
    # sin 在标记外 → 不命中
    assert judger_core.check_forbidden(code, "sin") is None
    # cos 在标记内 → 命中
    assert judger_core.check_forbidden(code, "cos") == "Function 'cos' is not allowed"


# ============== build_c/cpp_compile_cmd ==============
def test_build_c_compile_cmd_shape():
    cmd = judger_core.build_c_compile_cmd("a.c", "a.out")
    assert cmd[0] == "timeout"
    assert "30s" in cmd
    assert "gcc" in cmd
    assert "-O2" in cmd
    assert "-pipe" in cmd
    assert "-std=c11" in cmd
    # source 紧跟 -o output
    assert "a.c" in cmd and "-o" in cmd and "a.out" in cmd
    oi = cmd.index("-o")
    assert cmd[oi + 1] == "a.out"
    # 链接 -lm 在末尾
    assert cmd[-1] == "-lm"


def test_build_cpp_compile_cmd_shape():
    cmd = judger_core.build_cpp_compile_cmd("main.cpp", "a.out")
    assert cmd[0] == "timeout"
    assert "g++" in cmd
    assert "-O2" in cmd
    assert "-std=c++20" in cmd
    assert "main.cpp" in cmd
    oi = cmd.index("-o")
    assert cmd[oi + 1] == "a.out"
    assert cmd[-1] == "-lm"


def test_build_compile_cmd_custom_timeout():
    cmd = judger_core.build_c_compile_cmd("a.c", "a.out", compile_timeout_sec=15)
    assert "15s" in cmd
    assert "30s" not in cmd


def test_build_compile_cmd_source_before_output_flag():
    # source 必须在 -o 之前出现（gcc 语序）
    cmd = judger_core.build_cpp_compile_cmd("main.cpp", "bin")
    assert cmd.index("main.cpp") < cmd.index("-o")


# ============== set_run_limits ==============
class _RecordingSetrlimit:
    """收集 resource.setrlimit 的调用 (which, (soft, hard))。"""

    def __init__(self):
        self.calls = []

    def __call__(self, which, limits):
        self.calls.append((which, limits))


def test_set_run_limits_returns_callable():
    setter = judger_core.set_run_limits(2.0, 1024)
    assert callable(setter)


def test_set_run_limits_cpu_and_mem(monkeypatch):
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)

    # 源码用 int() 截断（非 ceil）：int(2.3)=2 → soft=2, hard=3
    setter = judger_core.set_run_limits(2.3, 4096)
    setter()

    cpu_calls = [c for c in rec.calls if c[0] == resource.RLIMIT_CPU]
    as_calls = [c for c in rec.calls if c[0] == resource.RLIMIT_AS]
    assert len(cpu_calls) == 1
    cpu_soft, cpu_hard = cpu_calls[0][1]
    assert cpu_soft == 2
    assert cpu_hard == 3
    # mem_bytes > 0 → 设置 RLIMIT_AS
    assert len(as_calls) == 1
    assert as_calls[0][1] == (4096, 4096)


def test_set_run_limits_cpu_min_one(monkeypatch):
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)

    # cpu_seconds < 1 → soft 兜底为 1，hard=2
    setter = judger_core.set_run_limits(0.4, 0)
    setter()

    cpu_calls = [c for c in rec.calls if c[0] == resource.RLIMIT_CPU]
    assert len(cpu_calls) == 1
    assert cpu_calls[0][1] == (1, 2)


def test_set_run_limits_skips_as_when_mem_zero(monkeypatch):
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)

    # mem_bytes == 0 → 不设置 RLIMIT_AS
    setter = judger_core.set_run_limits(1.0, 0)
    setter()

    as_calls = [c for c in rec.calls if c[0] == resource.RLIMIT_AS]
    assert as_calls == []


# ============== run_dir_for ==============
def test_run_dir_for_under_run_root_no_creation(tmp_path, monkeypatch):
    # 把运行根指到临时目录，确认拼接正确且不创建
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    d = judger_core.run_dir_for("sub123")
    assert d == os.path.join(str(tmp_path), "sub123")
    assert not os.path.exists(d)


def test_run_dir_for_sanitizes_dangerous_sid(monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", "/tmp/judger_runs_test")
    d = judger_core.run_dir_for("../../etc/passwd")
    base = os.path.basename(d)
    # 危险字符被清洗，兜底为 run_<timestamp>，不含路径穿越
    assert ".." not in base
    assert "/" not in base
    assert base.startswith("run_")


def test_run_dir_for_keeps_safe_chars(monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", "/tmp/jr")
    d = judger_core.run_dir_for("abc_-1.2")
    assert os.path.basename(d) == "abc_-1.2"


# ============== capture_output_image_file ==============
def test_capture_output_image_valid_ext_png(tmp_path):
    run_dir = str(tmp_path)
    src = os.path.join(run_dir, "output.png")
    with open(src, "wb") as f:
        f.write(b"\x89PNG fake")
    stored = judger_core.capture_output_image_file(run_dir, "output.png", "output_0")
    assert stored == "output_0.png"
    assert os.path.isfile(os.path.join(run_dir, stored))


def test_capture_output_image_jpeg_ext(tmp_path):
    run_dir = str(tmp_path)
    with open(os.path.join(run_dir, "plot.jpeg"), "wb") as f:
        f.write(b"jpegdata")
    stored = judger_core.capture_output_image_file(run_dir, "plot.jpeg", "output_1")
    assert stored == "output_1.jpeg"


def test_capture_output_image_invalid_ext_returns_none(tmp_path):
    run_dir = str(tmp_path)
    # 文件存在但扩展名不在允许集合 → None
    with open(os.path.join(run_dir, "result.txt"), "w") as f:
        f.write("not an image")
    assert judger_core.capture_output_image_file(run_dir, "result.txt", "output_0") is None


def test_capture_output_image_missing_file_returns_none(tmp_path):
    run_dir = str(tmp_path)
    # 源文件不存在 → None
    assert judger_core.capture_output_image_file(run_dir, "output.png", "output_0") is None


def test_capture_output_image_extension_set_matches_source():
    # 守护源码常量集合，避免被无意修改
    assert judger_core.IMAGE_FILE_EXTENSIONS == {
        ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"
    }
