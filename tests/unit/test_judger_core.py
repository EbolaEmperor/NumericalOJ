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

from oj_modules import docker_sandbox, judger_core


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


def test_reserved_archive_sid_is_never_used_as_attempt_directory(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "runs"
    archive = root / "submission_archive"
    archive.mkdir(parents=True)
    marker = archive / "keep"
    marker.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(root))

    prepared = judger_core._prepare_run_dir("submission_archive")

    assert os.path.basename(prepared).startswith("run_")
    assert marker.read_text(encoding="utf-8") == "keep"


def test_reaper_refuses_symlinked_run_root(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    stale = outside / "eoj-batch-1"
    stale.mkdir(parents=True)
    marker = stale / "keep"
    marker.write_text("keep", encoding="utf-8")
    run_root = tmp_path / "runs"
    run_root.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(run_root))

    removed = judger_core.reap_stale_run_dirs(0.000001)

    assert removed == 0
    assert marker.read_text(encoding="utf-8") == "keep"


def test_prepare_run_dir_replaces_stale_symlinks_without_following(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path / "runs"))
    os.makedirs(judger_core.JUDGER_RUN_ROOT)
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "config.py"
    protected.write_text("SECRET = True\n", encoding="utf-8")

    stale = tmp_path / "runs" / "eoj-batch-9"
    stale.mkdir()
    (stale / "main.cpp").symlink_to(protected)

    prepared = judger_core._prepare_run_dir("eoj-batch-9")
    judger_core._write_text_file_exclusive(
        prepared,
        "main.cpp",
        "int main() { return 0; }\n",
    )

    assert protected.read_text(encoding="utf-8") == "SECRET = True\n"
    assert not os.path.islink(prepared)
    assert not os.path.islink(os.path.join(prepared, "main.cpp"))
    assert oct(os.stat(prepared).st_mode & 0o7777) == "0o700"
    assert oct(os.stat(os.path.join(prepared, "main.cpp")).st_mode & 0o777) == "0o644"


def test_prepare_run_dir_unlinks_stale_root_symlink_only(tmp_path, monkeypatch):
    root = tmp_path / "runs"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep"
    marker.write_text("keep", encoding="utf-8")
    (root / "eoj-batch-10").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(root))

    prepared = judger_core._prepare_run_dir("eoj-batch-10")

    assert os.path.isdir(prepared)
    assert not os.path.islink(prepared)
    assert marker.read_text(encoding="utf-8") == "keep"


def test_prepare_workspace_replaces_symlink_without_touching_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path / "runs"))
    run_dir = judger_core._prepare_run_dir("eoj-batch-11")
    outside = tmp_path / "outside-case"
    outside.mkdir()
    marker = outside / "keep"
    marker.write_text("keep", encoding="utf-8")
    os.symlink(
        outside,
        os.path.join(run_dir, "workspace"),
        target_is_directory=True,
    )

    workspace = judger_core._prepare_execution_workspace(run_dir)
    judger_core._write_text_file_exclusive(
        workspace,
        "main.py",
        "print(42)\n",
    )

    assert not os.path.islink(workspace)
    assert marker.read_text(encoding="utf-8") == "keep"
    assert (
        tmp_path / "runs" / "eoj-batch-11" / "workspace" / "main.py"
    ).read_text(
        encoding="utf-8"
    ) == "print(42)\n"
    assert os.stat(workspace).st_mode & 0o777 == 0o755


def test_exclusive_text_write_refuses_existing_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path / "runs"))
    run_dir = judger_core._prepare_run_dir("eoj-batch-12")
    protected = tmp_path / "protected"
    protected.write_text("unchanged", encoding="utf-8")
    os.symlink(protected, os.path.join(run_dir, "main.cpp"))

    with pytest.raises(FileExistsError):
        judger_core._write_text_file_exclusive(
            run_dir,
            "main.cpp",
            "overwrite",
        )

    assert protected.read_text(encoding="utf-8") == "unchanged"


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


def test_capture_output_image_rejects_proc_self_symlink(
    tmp_path,
    monkeypatch,
):
    (tmp_path / "output.png").symlink_to("/proc/self/environ")
    monkeypatch.setattr(
        judger_core,
        "_wait_for_output_file",
        lambda *_args, **_kwargs: True,
    )

    stored = judger_core.capture_output_image_file(
        str(tmp_path),
        "output.png",
        "output",
    )

    assert stored is None
    assert os.path.islink(tmp_path / "output.png")


def test_capture_output_image_replaces_container_inode_with_safe_regular_file(
    tmp_path,
):
    source = tmp_path / "output.png"
    source.write_bytes(b"\x89PNG safe")

    stored = judger_core.capture_output_image_file(
        str(tmp_path),
        "output.png",
        "output",
    )

    assert stored == "output.png"
    assert judger_core.is_safe_regular_artifact(source)
    assert judger_core.read_safe_regular_artifact(source) == b"\x89PNG safe"
    info = source.stat()
    assert info.st_nlink == 1
    assert not (info.st_mode & 0o022)


def test_read_output_file_does_not_follow_container_symlink(tmp_path):
    (tmp_path / "output.txt").symlink_to("/proc/self/environ")

    assert (
        judger_core.read_output_with_fallback(
            str(tmp_path / "output.txt"),
            "captured",
        )
        == "captured"
    )


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


def test_compiled_batch_compiles_once_and_runs_each_case_in_fresh_container(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path / "runs"))
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((list(cmd), dict(kwargs)))
        if "g++" in cmd:
            return docker_sandbox._RunResult(
                0,
                "",
                "",
                artifacts={"a.out": b"fake executable"},
            )
        return docker_sandbox._RunResult(
            0,
            f"case-{len(calls) - 2}",
            "",
            123,
        )

    monkeypatch.setattr(judger_core, "run_case_in_container", fake_run)

    events = list(
        judger_core._batch_evaluate_stream(
            {
                "sid": "eoj-batch-30",
                "code": "int main() { return 0; }",
                "timeLimit": 1_000_000_000,
                "test_cases": [{"input": "one"}, {"input": "two"}],
                "user_files": [],
            },
            "cpp",
        )
    )

    assert len(calls) == 3
    assert "/sandbox/main.cpp" in calls[0][0]
    assert calls[0][1]["executable_name"] == "a.out"
    assert all("/sandbox/a.out" in call[0] for call in calls[1:])
    assert all(call[1]["output_name"] == "output.txt" for call in calls[1:])
    results = [event["result"] for event in events if event["event"] == "test_result"]
    assert [result["files"]["stdout"] for result in results] == [
        "case-0",
        "case-1",
    ]
    executable = (
        tmp_path / "runs" / "eoj-batch-30" / "workspace" / "a.out"
    )
    assert executable.stat().st_uid == os.geteuid()
    assert oct(executable.stat().st_mode & 0o777) == "0o555"


def test_script_batch_uses_one_short_lived_container_per_case(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path / "runs"))
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((list(cmd), dict(kwargs)))
        return docker_sandbox._RunResult(0, "ok", "", 456)

    monkeypatch.setattr(judger_core, "run_case_in_container", fake_run)

    events = list(
        judger_core._batch_evaluate_script_stream(
            {
                "sid": "eoj-batch-31",
                "code": "print(input())",
                "timeLimit": 1_000_000_000,
                "test_cases": [{"input": "one"}, {"input": "two"}],
            },
            "python",
        )
    )

    assert len(calls) == 2
    assert all("/sandbox/main.py" in call[0] for call in calls)
    assert all(call[1]["output_name"] == "output.txt" for call in calls)
    results = [event["result"] for event in events if event["event"] == "test_result"]
    assert [result["time"] for result in results] == [456, 456]


def test_batch_never_creates_host_writable_case_directories(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path / "runs"))
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((list(cmd), dict(kwargs)))
        if "g++" in cmd:
            return docker_sandbox._RunResult(
                0,
                "",
                "",
                artifacts={"a.out": b"fake executable"},
            )
        return docker_sandbox._RunResult(0, "ok", "", 123)

    monkeypatch.setattr(judger_core, "run_case_in_container", fake_run)

    events = list(
        judger_core._batch_evaluate_stream(
            {
                "sid": "eoj-batch-cleanup-failure",
                "code": "int main() { return 0; }",
                "timeLimit": 1_000_000_000,
                "test_cases": [{"input": "one"}, {"input": "two"}],
                "user_files": [],
            },
            "cpp",
        )
    )

    assert len(calls) == 3
    assert [event["event"] for event in events] == [
        "compile",
        "test_result",
        "test_result",
        "done",
    ]
    assert events[-1] == {"event": "done", "ok": True}
    run_dir = tmp_path / "runs" / "eoj-batch-cleanup-failure"
    assert not (run_dir / "case_0").exists()
    assert not (run_dir / "case_1").exists()
    assert not (run_dir / "input.txt").exists()


def test_batch_public_images_are_never_mounted_into_later_case(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path / "runs"))
    calls = []

    def fake_run(_cmd, **kwargs):
        calls.append(dict(kwargs))
        workspace = tmp_path / "runs" / "eoj-batch-image-isolation" / "workspace"
        if len(calls) == 2:
            assert (workspace.parent / "output_0.png").is_file()
            assert not (workspace / "output_0.png").exists()
        return docker_sandbox._RunResult(
            0,
            "ok",
            "",
            1,
            artifacts={"output.png": b"\x89PNG secret"},
            artifact_statuses={
                "output.txt": "absent",
                "output.png": "exported",
            },
        )

    monkeypatch.setattr(judger_core, "run_case_in_container", fake_run)

    events = list(
        judger_core._batch_evaluate_script_stream(
            {
                "sid": "eoj-batch-image-isolation",
                "code": "print('ok')",
                "timeLimit": 1_000_000_000,
                "outputImageFilename": "output.png",
                "test_cases": [{"input": "one"}, {"input": "two"}],
            },
            "python",
        )
    )

    assert len(calls) == 2
    assert all(
        call["run_dir"].endswith("/workspace")
        for call in calls
    )
    assert events[-1] == {"event": "done", "ok": True}
    artifact_dir = tmp_path / "runs" / "eoj-batch-image-isolation"
    assert (artifact_dir / "output_0.png").read_bytes() == b"\x89PNG secret"
    assert (artifact_dir / "output_1.png").read_bytes() == b"\x89PNG secret"


@pytest.mark.parametrize(
    ("stdout_truncated", "output_status"),
    [
        (True, "absent"),
        (False, "rejected"),
    ],
)
def test_truncated_or_rejected_output_is_explicit_ole(
    tmp_path,
    monkeypatch,
    stdout_truncated,
    output_status,
):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path / "runs"))
    monkeypatch.setattr(
        judger_core,
        "run_case_in_container",
        lambda *_args, **_kwargs: docker_sandbox._RunResult(
            0,
            "correct answer",
            "",
            1,
            stdout_truncated=stdout_truncated,
            artifact_statuses={"output.txt": output_status},
        ),
    )

    result = judger_core.run_py(
        {
            "sid": f"output-limit-{output_status}",
            "code": "print('correct answer')",
            "input": "",
            "timeLimit": 1_000_000_000,
        }
    )

    assert result["status"] == "Output Limit Exceeded"
    assert result["exitStatus"] == 12


# ============== C/C++ compile command numeric backend ==============
def test_build_compile_cmd_defaults_to_mkl(monkeypatch):
    monkeypatch.delenv("JUDGER_NUMERIC_BACKEND", raising=False)
    monkeypatch.delenv("JUDGER_ENABLE_MKL", raising=False)
    monkeypatch.setenv("JUDGER_TARGET_ARCH", "x86_64")
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger:latest")

    cmd = judger_core.build_compile_cmd("cpp")

    assert "-m64" in cmd
    assert "-I" in cmd
    assert judger_core.EIGEN_INCLUDE_DIR in cmd
    assert judger_core.MKL_INCLUDE_DIR in cmd
    assert "-lmkl_core" in cmd
    assert "-lopenblas" not in cmd


def test_build_compile_cmd_defaults_to_openblas_on_arm(monkeypatch):
    monkeypatch.delenv("JUDGER_NUMERIC_BACKEND", raising=False)
    monkeypatch.delenv("JUDGER_ENABLE_MKL", raising=False)
    monkeypatch.setenv("JUDGER_TARGET_ARCH", "arm64")
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger:latest")

    cmd = judger_core.build_compile_cmd("cpp")

    assert "-m64" not in cmd
    assert judger_core.MKL_INCLUDE_DIR not in cmd
    assert "-lmkl_core" not in cmd
    assert "-lopenblas" in cmd


def test_build_compile_cmd_explicit_mkl_on_arm_omits_m64(monkeypatch):
    monkeypatch.setenv("JUDGER_NUMERIC_BACKEND", "mkl")
    monkeypatch.setenv("JUDGER_TARGET_ARCH", "arm64")
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger:latest")

    cmd = judger_core.build_compile_cmd("cpp")

    assert "-m64" not in cmd
    assert judger_core.MKL_INCLUDE_DIR in cmd
    assert "-lmkl_core" in cmd


def test_build_compile_cmd_uses_openblas_for_lite_image(monkeypatch):
    monkeypatch.delenv("JUDGER_NUMERIC_BACKEND", raising=False)
    monkeypatch.delenv("JUDGER_ENABLE_MKL", raising=False)
    monkeypatch.setenv("JUDGER_TARGET_ARCH", "x86_64")
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger-lite:latest")

    cmd = judger_core.build_compile_cmd("c")

    assert judger_core.EIGEN_INCLUDE_DIR not in cmd
    assert judger_core.MKL_INCLUDE_DIR not in cmd
    assert "-lmkl_core" not in cmd
    assert "-lopenblas" in cmd
    assert "-llapacke" in cmd


def test_build_compile_cmd_lite_image_ignores_explicit_mkl(monkeypatch):
    monkeypatch.setenv("JUDGER_NUMERIC_BACKEND", "mkl")
    monkeypatch.setenv("JUDGER_TARGET_ARCH", "x86_64")
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger-lite:latest")

    cmd = judger_core.build_compile_cmd("cpp")

    assert judger_core.MKL_INCLUDE_DIR not in cmd
    assert "-lmkl_core" not in cmd
    assert "-lopenblas" in cmd


def test_build_compile_cmd_lite_image_ignores_legacy_enable_mkl(monkeypatch):
    monkeypatch.delenv("JUDGER_NUMERIC_BACKEND", raising=False)
    monkeypatch.setenv("JUDGER_ENABLE_MKL", "true")
    monkeypatch.setenv("JUDGER_TARGET_ARCH", "x86_64")
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger-lite:latest")

    cmd = judger_core.build_compile_cmd("c")

    assert judger_core.MKL_INCLUDE_DIR not in cmd
    assert "-lmkl_core" not in cmd
    assert "-lopenblas" in cmd


def test_build_compile_cmd_numeric_backend_override_none(monkeypatch):
    monkeypatch.setenv("JUDGER_NUMERIC_BACKEND", "none")
    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger-lite:latest")

    cmd = judger_core.build_compile_cmd("cpp")

    assert "-lmkl_core" not in cmd
    assert "-lopenblas" not in cmd
