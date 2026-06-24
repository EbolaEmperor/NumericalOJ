#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""沙箱判题核心（Docker 容器隔离）。

所有用户代码在 Docker 容器中执行，实现进程/文件系统/网络完全隔离。
不再使用 RLIMIT_* 或宿主机直接 subprocess 执行。

API:
  - run_single(language, data) -> result_dict
  - batch_evaluate_stream(language, data) -> 生成器，逐个 yield 事件 dict
  - batch_evaluate(language, data) -> {compile_result, test_results}
"""

import os
import re
import shutil
import time

from oj_modules.docker_sandbox import run_in_container, ContainerSession


# ========== OJ 根目录 / 头文件库路径 ==========
def get_oj_root_path():
    """获取 OJ 系统根目录：环境变量 OJ_ROOT_PATH > 基于本文件位置（oj_modules/ 的上一级）> /opt/oj。"""
    oj_root = os.environ.get("OJ_ROOT_PATH")
    if oj_root and os.path.exists(oj_root):
        return oj_root

    current_dir = os.path.dirname(os.path.abspath(__file__))
    oj_root = os.path.dirname(current_dir)
    if os.path.exists(oj_root):
        return oj_root

    return "/opt/oj"


OJ_ROOT_PATH = get_oj_root_path()

JUDGER_RUN_ROOT = (
    str(os.environ.get("JUDGER_RUN_ROOT") or "").strip()
    or os.path.join(OJ_ROOT_PATH, "judger")
)


# ========== 通用工具 ==========
SAFE_SID_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.]+$')
IMAGE_FILE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def sanitize_sid(sid: str) -> str:
    if not sid or not SAFE_SID_PATTERN.match(sid):
        return f"run_{int(time.time()*1000)}"
    return sid


def run_dir_for(sid: str) -> str:
    """返回某 sid 对应的运行目录绝对路径（不创建）。"""
    return os.path.join(JUDGER_RUN_ROOT, sanitize_sid(sid))


def _prepare_run_dir(sid: str) -> str:
    """把 sid 落到 JUDGER_RUN_ROOT 下的绝对运行目录并确保存在。"""
    run_dir = run_dir_for(sid)
    ensure_dir(run_dir)
    return run_dir


def sanitize_output_image_filename(filename: str) -> str:
    raw = str(filename or "").strip().replace("\\", "/")
    if "/" in raw:
        raw = raw.rsplit("/", 1)[-1].strip()
    if not raw:
        raw = "output.png"
    return raw[:255] or "output.png"


def capture_output_image_file(sid: str, requested_filename: str, stored_stem: str):
    requested_name = sanitize_output_image_filename(requested_filename)
    source_path = os.path.join(sid, requested_name)
    if not os.path.isfile(source_path):
        return None

    _, ext = os.path.splitext(requested_name)
    ext = str(ext or "").lower()
    if not ext:
        ext = ".png"
    if ext not in IMAGE_FILE_EXTENSIONS:
        return None

    target_filename = f"{stored_stem}{ext}"
    target_path = os.path.join(sid, target_filename)
    if os.path.abspath(source_path) == os.path.abspath(target_path):
        return target_filename

    try:
        os.replace(source_path, target_path)
        return target_filename
    except Exception:
        pass

    try:
        shutil.copyfile(source_path, target_path)
        return target_filename
    except Exception:
        return None


def check_forbidden(code_content: str, forbidden_str: str):
    """禁用函数检查：逗号分割禁用函数名，按 func(...) 正则匹配。"""
    if not forbidden_str:
        return None
    match0 = re.search(
        r'here_is_user_code_fuck_fuck_fuck_hahaha(.*?)user_code_end_fuck_hahaha_fuck',
        code_content, re.DOTALL
    )
    code_content_check = match0.group(1) if match0 else code_content

    forbidden_funcs = [func.strip() for func in forbidden_str.split(",") if func.strip()]
    for func in forbidden_funcs:
        pattern = r'[^a-zA-Z0-9_](' + re.escape(func) + r')\s*\('
        if re.search(pattern, code_content_check):
            return f"Function '{func}' is not allowed"

        if func == "\\" and re.search(r'\\', code_content_check):
            return "Operator \\ is not allowed"
    return None


def read_output_with_fallback(output_filename: str, captured_stdout: str):
    try:
        with open(output_filename, "r", encoding="utf-8", errors="replace") as file:
            outp = file.read()
        try:
            os.remove(output_filename)
        except OSError:
            pass
        return outp
    except FileNotFoundError:
        return captured_stdout
    except Exception:
        return captured_stdout


def safe_user_header_filename(filename):
    """校验用户头文件名：仅允许字母/数字/下划线/连字符/点，扩展名限定为头/源文件。"""
    name = os.path.basename(str(filename or "").replace("\\", "/").strip())
    if not name or name in (".", ".."):
        return None
    if not re.match(r'^[A-Za-z0-9_\-.]+$', name):
        return None
    if os.path.splitext(name)[1].lower() not in (".h", ".hpp", ".c", ".cpp", ".hh", ".hxx"):
        return None
    return name


def _write_user_files(run_dir, user_files):
    """把用户头文件写入运行目录。"""
    if not user_files:
        return
    for filename, content in user_files.items():
        safe_name = safe_user_header_filename(filename)
        if not safe_name:
            continue
        with open(os.path.join(run_dir, safe_name), "w", encoding="utf-8") as f:
            f.write(content if isinstance(content, str) else str(content or ""))


def cleanup_run_artifacts(sid, keep_images=True):
    """评测结束后清理运行目录里的临时产物，默认保留输出图片。"""
    run_dir = run_dir_for(sid)
    if not os.path.isdir(run_dir):
        return
    try:
        for name in os.listdir(run_dir):
            path = os.path.join(run_dir, name)
            if not os.path.isfile(path):
                continue
            ext = os.path.splitext(name)[1].lower()
            if keep_images and ext in IMAGE_FILE_EXTENSIONS:
                continue
            try:
                os.remove(path)
            except Exception:
                pass
        try:
            if not os.listdir(run_dir):
                os.rmdir(run_dir)
        except Exception:
            pass
    except Exception:
        pass


def cleanup_run_artifacts_for_submission(submission_id, keep_images=True):
    """清理某次提交可能用到的所有运行目录的临时产物。"""
    sid = str(submission_id)
    prefix = f"eoj-{sid}-"
    exact = {f"eoj-batch-{sid}", f"eoj-quick-compile-{sid}"}
    if not os.path.isdir(JUDGER_RUN_ROOT):
        return
    try:
        for name in os.listdir(JUDGER_RUN_ROOT):
            if name in exact or name.startswith(prefix):
                cleanup_run_artifacts(name, keep_images=keep_images)
    except Exception:
        pass


def reap_stale_run_dirs(ttl_seconds):
    """删除 JUDGER_RUN_ROOT 下早于 ttl 的整个运行子目录。"""
    if not ttl_seconds or ttl_seconds <= 0 or not os.path.isdir(JUDGER_RUN_ROOT):
        return 0
    now = time.time()
    removed = 0
    try:
        for name in os.listdir(JUDGER_RUN_ROOT):
            path = os.path.join(JUDGER_RUN_ROOT, name)
            if not os.path.isdir(path):
                continue
            try:
                if now - os.path.getmtime(path) > ttl_seconds:
                    shutil.rmtree(path, ignore_errors=True)
                    removed += 1
            except Exception:
                pass
    except Exception:
        pass
    return removed



def _timeout_sec_from_ns(time_limit_ns, factor=1.2):
    """将纳秒时间限制转换为秒（带 factor 余量），最小 1 秒。"""
    return max(1.0, (time_limit_ns or 0) * factor / 1e9)


def _guard_timeout(base_sec):
    """Docker 操作的 Python 侧总超时 = 基础时间 + 固定缓冲。"""
    return max(1.0, float(base_sec or 0)) + 10.0


# ========== 单次运行（Octave / Python / C / C++）==========
def run_octave(data):
    """Octave/MATLAB 单次运行。"""
    run_dir = _prepare_run_dir(data.get("sid", ""))
    user_input = data.get("input", "")
    code_content = data.get("code", "")
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    output_image_filename = data.get("outputImageFilename", "output.png")

    forbid_msg = check_forbidden(code_content, forbidden_funcs)
    if forbid_msg:
        return {
            "status": "Forbidden",
            "exitStatus": 11,
            "files": {"stdout": forbid_msg, "stderr": forbid_msg},
            "time": 0,
            "memory": 0,
        }

    with open(os.path.join(run_dir, "a.m"), "w", encoding="utf-8") as f:
        f.write(code_content)

    timeLim_sec = _timeout_sec_from_ns(tle, factor=1.1)
    container_cmd = ["timeout", f"{timeLim_sec}s", "octave", "a.m"]

    start_time = time.perf_counter_ns()
    result = run_in_container(
        container_cmd,
        run_dir=run_dir,
        input_text=user_input,
        timeout_sec=_guard_timeout(timeLim_sec),
    )
    exec_time = time.perf_counter_ns() - start_time

    output_filename = os.path.join(run_dir, "output.txt")
    outp = read_output_with_fallback(output_filename, result.stdout)

    status = "Accepted"
    exval = 0
    stderr = result.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif result.returncode == 137:
        status = "Memory Limit Exceeded"
        exval = 10
    elif result.returncode != 0:
        status = "Nonzero Exit Status"
        exval = result.returncode

    files_dict = {"stdout": outp, "stderr": stderr}
    stored_image_filename = capture_output_image_file(run_dir, output_image_filename, "output")
    if stored_image_filename:
        files_dict[stored_image_filename] = True

    return {
        "status": status,
        "exitStatus": exval,
        "files": files_dict,
        "time": exec_time,
        "memory": 0,
    }


def run_py(data):
    """Python 单次运行。"""
    run_dir = _prepare_run_dir(data.get("sid", ""))
    user_input = data.get("input", "")
    code_content = data.get("code", "")
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    output_image_filename = data.get("outputImageFilename", "output.png")

    forbid_msg = check_forbidden(code_content, forbidden_funcs)
    if forbid_msg:
        return {
            "status": "Forbidden",
            "exitStatus": 11,
            "files": {"stdout": forbid_msg, "stderr": forbid_msg},
            "time": 0,
            "memory": 0,
        }

    with open(os.path.join(run_dir, "main.py"), "w", encoding="utf-8") as f:
        f.write(code_content)

    timeLim_sec = _timeout_sec_from_ns(tle, factor=1.2)
    container_cmd = ["timeout", f"{timeLim_sec}s", "python3", "-I", "-u", "main.py"]

    start_time = time.perf_counter_ns()
    result = run_in_container(
        container_cmd,
        run_dir=run_dir,
        input_text=user_input,
        timeout_sec=_guard_timeout(timeLim_sec),
    )
    exec_time = time.perf_counter_ns() - start_time

    output_filename = os.path.join(run_dir, "output.txt")
    outp = read_output_with_fallback(output_filename, result.stdout or "")

    status = "Accepted"
    exval = 0
    stderr = result.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif result.returncode == 137:
        status = "Memory Limit Exceeded"
        exval = 10
    elif result.returncode != 0:
        status = "Runtime Error"
        exval = result.returncode

    files_dict = {"stdout": outp, "stderr": stderr}
    stored_image_filename = capture_output_image_file(run_dir, output_image_filename, "output")
    if stored_image_filename:
        files_dict[stored_image_filename] = True

    return {
        "status": status,
        "exitStatus": exval,
        "files": files_dict,
        "time": exec_time,
        "memory": 0,
    }


def _run_compiled_single(data, language):
    """C/C++ 单次运行。"""
    run_dir = _prepare_run_dir(data.get("sid", ""))
    user_input = data.get("input", "")
    code_content = data.get("code", "")
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    output_image_filename = data.get("outputImageFilename", "output.png")
    user_files = data.get("user_files", {})

    forbid_msg = check_forbidden(code_content, forbidden_funcs)
    if forbid_msg:
        return {
            "status": "Forbidden",
            "exitStatus": 11,
            "files": {"stdout": forbid_msg, "stderr": forbid_msg},
            "time": 0,
            "memory": 0,
        }

    if language == "cpp":
        src_name = "main.cpp"
        compile_cmd = ["timeout", "30s", "g++", "-O2", "-pipe", "-s", "-std=c++20",
                       "-I", "/opt/library", "main.cpp", "-o", "a.out", "-lm"]
        compile_err_cap = 3000
    else:
        src_name = "main.c"
        compile_cmd = ["timeout", "30s", "gcc", "-O2", "-pipe", "-s", "-std=c11",
                       "-I", "/opt/library", "main.c", "-o", "a.out", "-lm"]
        compile_err_cap = 300

    with open(os.path.join(run_dir, src_name), "w", encoding="utf-8") as f:
        f.write(code_content)

    _write_user_files(run_dir, user_files)

    # Compile
    compile_res = run_in_container(
        compile_cmd,
        run_dir=run_dir,
        timeout_sec=45,
    )
    if compile_res.returncode != 0:
        stderr = compile_res.stderr or ""
        if len(stderr) > compile_err_cap:
            stderr = stderr[:compile_err_cap] + "..."
        return {
            "status": "Compile Error",
            "exitStatus": compile_res.returncode,
            "files": {"stdout": compile_res.stdout or "", "stderr": stderr},
            "time": 0,
            "memory": 0,
        }

    # Run
    timeLim_sec = _timeout_sec_from_ns(tle, factor=1.2)
    run_cmd = ["timeout", f"{timeLim_sec}s", "./a.out"]

    start_time = time.perf_counter_ns()
    run_res = run_in_container(
        run_cmd,
        run_dir=run_dir,
        input_text=user_input,
        timeout_sec=_guard_timeout(timeLim_sec),
    )
    exec_time = time.perf_counter_ns() - start_time

    output_filename = os.path.join(run_dir, "output.txt")
    outp = read_output_with_fallback(output_filename, run_res.stdout or "")

    status = "Accepted"
    exval = 0
    stderr = run_res.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif run_res.returncode == 137:
        status = "Memory Limit Exceeded"
        exval = 10
    elif run_res.returncode != 0:
        status = "Runtime Error"
        exval = run_res.returncode

    files_dict = {"stdout": outp, "stderr": stderr}
    stored_image_filename = capture_output_image_file(run_dir, output_image_filename, "output")
    if stored_image_filename:
        files_dict[stored_image_filename] = True

    return {
        "status": status,
        "exitStatus": exval,
        "files": files_dict,
        "time": exec_time,
        "memory": 0,
    }


def run_c(data):
    return _run_compiled_single(data, "c")


def run_cpp(data):
    return _run_compiled_single(data, "cpp")


# ========== 批量评测：编译一次，运行多个测试点 ==========
def _batch_evaluate_stream(data, language):
    """编译一次、逐个跑测试点的生成器（使用 ContainerSession）。"""
    code_content = data.get("code", "")
    test_cases = data.get("test_cases", [])
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    user_files = data.get("user_files", {})
    output_image_filename = data.get("outputImageFilename", "output.png")

    try:
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            yield {"event": "compile", "status": "forbidden", "stderr": forbid_msg}
            yield {"event": "done", "ok": False}
            return

        run_dir = _prepare_run_dir(data.get("sid", ""))

        if language == "cpp":
            src_name = "main.cpp"
            compile_cmd = ["timeout", "30s", "g++", "-O2", "-pipe", "-s", "-std=c++20",
                           "-I", "/opt/library", "main.cpp", "-o", "a.out", "-lm"]
            compile_err_cap = 3000
        else:
            src_name = "main.c"
            compile_cmd = ["timeout", "30s", "gcc", "-O2", "-pipe", "-s", "-std=c11",
                           "-I", "/opt/library", "main.c", "-o", "a.out", "-lm"]
            compile_err_cap = 300

        with open(os.path.join(run_dir, src_name), "w", encoding="utf-8") as f:
            f.write(code_content)

        _write_user_files(run_dir, user_files)

        with ContainerSession(run_dir=run_dir) as session:
            # Compile
            compile_res = session.exec(compile_cmd, timeout_sec=45)
            if compile_res.returncode != 0:
                stderr = compile_res.stderr or ""
                if len(stderr) > compile_err_cap:
                    stderr = stderr[:compile_err_cap] + "..."
                yield {"event": "compile", "status": "error", "stderr": stderr}
                yield {"event": "done", "ok": False}
                return

            yield {"event": "compile", "status": "success", "stderr": ""}

            # Run each test case
            for i, test_case in enumerate(test_cases):
                user_input = test_case.get("input", "")
                timeLim_sec = _timeout_sec_from_ns(tle, factor=1.2)
                run_cmd = ["timeout", f"{timeLim_sec}s", "./a.out"]

                start_time = time.perf_counter_ns()
                run_res = session.exec(run_cmd, input_text=user_input, timeout_sec=_guard_timeout(timeLim_sec))
                exec_time = time.perf_counter_ns() - start_time

                output_filename = os.path.join(run_dir, f"output_{i}.txt")
                outp = read_output_with_fallback(output_filename, run_res.stdout or "")

                status = "Accepted"
                exval = 0
                stderr = run_res.stderr or ""
                if len(stderr) > 300:
                    stderr = stderr[:300] + "..."

                if exec_time > (tle or 0):
                    status = "Time Limit Exceeded"
                    exval = 9
                elif run_res.returncode == 137:
                    status = "Memory Limit Exceeded"
                    exval = 10
                elif run_res.returncode != 0:
                    status = "Runtime Error"
                    exval = run_res.returncode

                files_dict = {"stdout": outp, "stderr": stderr}
                stored_image_filename = capture_output_image_file(
                    run_dir, output_image_filename, f"output_{i}",
                )
                if stored_image_filename:
                    files_dict[stored_image_filename] = True

                yield {"event": "test_result", "result": {
                    "test_case_index": i,
                    "status": status,
                    "exitStatus": exval,
                    "files": files_dict,
                    "time": exec_time,
                    "memory": 0,
                }}

        yield {"event": "done", "ok": True}
    except Exception as e:
        yield {"event": "error", "message": f"Failed to stream batch evaluate {language}: {str(e)}"}
        yield {"event": "done", "ok": False}


# ========== 对外分派 ==========
def run_single(language, data):
    """单次运行分派。language: matlab/octave、c、cpp、py/python。"""
    lang = str(language or "").strip().lower()
    if lang in ("matlab", "octave", "hello"):
        return run_octave(data)
    if lang == "c":
        return run_c(data)
    if lang in ("cpp", "c++"):
        return run_cpp(data)
    if lang in ("py", "python", "python3"):
        return run_py(data)
    raise ValueError(f"run_single: 不支持的语言 {language!r}")


def batch_evaluate_stream(language, data):
    """流式批量评测分派（生成器）。language: c、cpp。"""
    lang = str(language or "").strip().lower()
    if lang in ("cpp", "c++"):
        return _batch_evaluate_stream(data, "cpp")
    if lang == "c":
        return _batch_evaluate_stream(data, "c")
    raise ValueError(f"batch_evaluate_stream: 不支持的语言 {language!r}")


def batch_evaluate(language, data):
    """非流式批量评测。返回 {compile_result, test_results}。"""
    test_results = []
    for event in batch_evaluate_stream(language, data):
        ev = event.get("event")
        if ev == "compile":
            if event.get("status") != "success":
                return {
                    "compile_result": {"status": event.get("status"), "stderr": event.get("stderr", "")},
                    "test_results": [],
                }
        elif ev == "test_result":
            test_results.append(event.get("result"))
        elif ev == "error":
            raise RuntimeError(event.get("message") or "batch evaluate failed")
    return {"compile_result": {"status": "success", "stderr": ""}, "test_results": test_results}
