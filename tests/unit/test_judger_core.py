# -*- coding: utf-8 -*-
"""judger_core 纯逻辑单测（不触发真实编译/运行）。

覆盖：
- check_forbidden：命中各语言、未命中返回 None、Octave 反斜杠特例、正则词边界
- run_dir_for：JUDGER_RUN_ROOT/<sanitized_sid>，不创建目录，危险字符清洗
- capture_output_image_file：合法扩展名集合，非法/缺失返回 None
- _timeout_sec_from_ns / _guard_timeout：超时转换逻辑

真实编译运行的项见 tests/integration/test_judging_smoke.py，不在本文件。
"""
import os
import sys

import pytest

from oj_modules import judger_core


# ============== check_forbidden ==============
def test_check_forbidden_empty_returns_none():
    assert judger_core.check_forbidden("y = sin(x)\n", "") is None
    assert judger_core.check_forbidden("anything", None) is None


def test_check_forbidden_hits_octave_func():
    msg = judger_core.check_forbidden("y = sin(x)\n", "sin")
    assert msg is not None
    assert "sin" in msg
    assert msg == "Function 'sin' is not allowed"


def test_check_forbidden_hits_c_func():
    code = '#include <stdio.h>\nint main(){ printf("hi"); return 0; }\n'
    msg = judger_core.check_forbidden(code, "printf")
    assert msg == "Function 'printf' is not allowed"


def test_check_forbidden_miss_when_func_absent():
    assert judger_core.check_forbidden("y = sin(x)\n", "cos") is None


def test_check_forbidden_word_boundary_asin_vs_sin():
    assert judger_core.check_forbidden("y = asin(x)\n", "sin") is None
    assert judger_core.check_forbidden("y = sin(x)\n", "sin") is not None


def test_check_forbidden_requires_call_paren():
    assert judger_core.check_forbidden("x = sin;\n", "sin") is None
    assert judger_core.check_forbidden("y = sin (x)\n", "sin") is not None


def test_check_forbidden_octave_backslash_special():
    msg = judger_core.check_forbidden("x = A \\ b\n", "\\")
    assert msg == "Operator \\ is not allowed"
    assert judger_core.check_forbidden("x = A / b\n", "\\") is None


def test_check_forbidden_comma_separated_list():
    msg = judger_core.check_forbidden("z = cos(t)\n", "sin, cos , tan")
    assert msg == "Function 'cos' is not allowed"


def test_check_forbidden_only_checks_user_code_markers():
    code = (
        "y = sin(x)\n"
        "here_is_user_code_fuck_fuck_fuck_hahaha\n"
        "z = cos(t)\n"
        "user_code_end_fuck_hahaha_fuck\n"
    )
    assert judger_core.check_forbidden(code, "sin") is None
    assert judger_core.check_forbidden(code, "cos") == "Function 'cos' is not allowed"


# ============== JUDGER_RUN_ROOT 默认位置 ==============
def test_default_run_root_is_oj_root_judger_not_tmp(monkeypatch):
    """默认运行根必须是 <OJ_ROOT>/judger，且不再经过 tmp/。"""
    monkeypatch.delenv("JUDGER_RUN_ROOT", raising=False)
    import importlib
    reloaded = importlib.reload(judger_core)
    try:
        expected = os.path.join(reloaded.OJ_ROOT_PATH, "judger")
        assert reloaded.JUDGER_RUN_ROOT == expected
        norm = os.path.normpath(reloaded.JUDGER_RUN_ROOT)
        assert (os.sep + "tmp" + os.sep) not in norm + os.sep
        assert not norm.endswith(os.sep + "tmp")
        d = reloaded.run_dir_for("eoj-batch-123")
        assert d == os.path.join(expected, "eoj-batch-123")
    finally:
        importlib.reload(judger_core)


# ============== run_dir_for ==============
def test_run_dir_for_under_run_root_no_creation(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    d = judger_core.run_dir_for("sub123")
    assert d == os.path.join(str(tmp_path), "sub123")
    assert not os.path.exists(d)


def test_run_dir_for_sanitizes_dangerous_sid(monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", "/tmp/judger_runs_test")
    d = judger_core.run_dir_for("../../etc/passwd")
    base = os.path.basename(d)
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


def test_capture_output_image_from_case_dir_to_parent(tmp_path):
    source_dir = tmp_path / "case_0"
    source_dir.mkdir()
    with open(source_dir / "output.png", "wb") as f:
        f.write(b"\x89PNG case")

    stored = judger_core.capture_output_image_file_to_dir(
        str(source_dir), str(tmp_path), "output.png", "output_0"
    )

    assert stored == "output_0.png"
    assert os.path.isfile(tmp_path / "output_0.png")
    assert not os.path.exists(source_dir / "output.png")


def test_capture_output_image_invalid_ext_returns_none(tmp_path):
    run_dir = str(tmp_path)
    with open(os.path.join(run_dir, "result.txt"), "w") as f:
        f.write("not an image")
    assert judger_core.capture_output_image_file(run_dir, "result.txt", "output_0") is None


def test_capture_output_image_missing_file_returns_none(tmp_path):
    run_dir = str(tmp_path)
    assert judger_core.capture_output_image_file(run_dir, "output.png", "output_0") is None


def test_capture_output_image_extension_set_matches_source():
    assert judger_core.IMAGE_FILE_EXTENSIONS == {
        ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"
    }


# ============== timeout helpers ==============
def test_timeout_sec_from_ns_basic():
    result = judger_core._timeout_sec_from_ns(1_000_000_000, factor=1.0)
    assert abs(result - 1.0) < 0.01


def test_timeout_sec_from_ns_with_factor():
    result = judger_core._timeout_sec_from_ns(2_000_000_000, factor=1.2)
    assert abs(result - 2.4) < 0.01


def test_timeout_sec_from_ns_min_one():
    result = judger_core._timeout_sec_from_ns(0)
    assert result >= 1.0


def test_guard_timeout_exceeds_base():
    assert judger_core._guard_timeout(2.0) > 2.0
    assert judger_core._guard_timeout(0) >= 1.0


def test_measured_exec_time_uses_container_elapsed():
    result = type("R", (), {"returncode": 0, "elapsed_ns": 123})()
    assert judger_core._measured_exec_time_ns(result, 10) == 123


def test_measured_exec_time_marks_guard_timeout_as_tle():
    result = type("R", (), {"returncode": 124, "elapsed_ns": None})()
    assert judger_core._measured_exec_time_ns(result, 10) == 11


# ============== C/C++ compile command numeric backend ==============
def test_build_compile_cmd_defaults_to_mkl(monkeypatch):
    monkeypatch.delenv("JUDGER_NUMERIC_BACKEND", raising=False)
    monkeypatch.delenv("JUDGER_ENABLE_MKL", raising=False)
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger:latest")

    cmd = judger_core.build_compile_cmd("cpp")

    assert "-I" in cmd
    assert judger_core.MKL_INCLUDE_DIR in cmd
    assert "-lmkl_core" in cmd
    assert "-lopenblas" not in cmd


def test_build_compile_cmd_uses_openblas_for_lite_image(monkeypatch):
    monkeypatch.delenv("JUDGER_NUMERIC_BACKEND", raising=False)
    monkeypatch.delenv("JUDGER_ENABLE_MKL", raising=False)
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger-lite:latest")

    cmd = judger_core.build_compile_cmd("c")

    assert judger_core.MKL_INCLUDE_DIR not in cmd
    assert "-lmkl_core" not in cmd
    assert "-lopenblas" in cmd
    assert "-llapacke" in cmd


def test_build_compile_cmd_numeric_backend_override_none(monkeypatch):
    monkeypatch.setenv("JUDGER_NUMERIC_BACKEND", "none")
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger-lite:latest")

    cmd = judger_core.build_compile_cmd("cpp")

    assert "-lmkl_core" not in cmd
    assert "-lopenblas" not in cmd
