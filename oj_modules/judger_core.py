#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""沙箱判题核心（框架无关库）。

原先这套逻辑跑在独立的 Flask 服务（judger/app.py，5050 端口），主程序通过 HTTP
调用它。现在 judger 不再是独立服务，本模块把同一套编译/运行/限额/禁用函数检查的
逻辑暴露成普通 Python 函数，由 Celery 评测任务（oj_modules/tasks/evaluate_tasks.py）
在 worker 进程内直接调用：

  - run_single(language, data) -> result_dict
        单次运行（Octave/Python/C/C++），等价于旧的 /run-hello /run-py /run-c /run-cpp。
  - batch_evaluate_stream(language, data) -> 生成器，逐个 yield 事件 dict
        编译一次、运行多个测试点，等价于旧的 /batch-evaluate-stream-{c,cpp} 的 NDJSON 流，
        每个 yield 对应原来的一行 NDJSON（compile / test_result / done / error）。
  - batch_evaluate(language, data) -> {compile_result, test_results}
        非流式批量评测（基于上面的生成器收集），等价于旧的 /batch-evaluate-{c,cpp}。

入参 data 与返回 dict 的字段与旧 HTTP 接口完全一致，方便调用方平滑迁移。

沙箱手段保持不变：coreutils timeout + RLIMIT_CPU/RLIMIT_AS（preexec_fn，在 Celery
prefork 子进程里同样有效）+ 基于正则的禁用函数过滤；内存限制沿用历史的“乘 10”处理。
"""

import json
import os
import re
import resource
import shutil
import subprocess
import time


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
LIBRARY_PATH = os.path.join(OJ_ROOT_PATH, "library")

# 判题运行目录的根；每次评测在其下建立以 sid 命名的子目录（编译产物 / 输入输出 / 图片），
# 例如 <OJ_ROOT>/judger/eoj-batch-123/。
# 可用环境变量 JUDGER_RUN_ROOT 覆盖；默认放在 OJ_ROOT/judger（运行子目录 judger/eoj-* 不入库）。
JUDGER_RUN_ROOT = (
    str(os.environ.get("JUDGER_RUN_ROOT") or "").strip()
    or os.path.join(OJ_ROOT_PATH, "judger")
)


# ========== Intel MKL 检测 ==========
def _detect_mkl_root():
    """优先 MKLROOT 环境变量，否则尝试 oneAPI 默认安装路径。"""
    mklroot = os.environ.get("MKLROOT")
    if mklroot and os.path.isdir(mklroot):
        return mklroot
    for candidate in ("/opt/intel/oneapi/mkl/latest", "/opt/intel/mkl"):
        if os.path.isdir(candidate):
            return candidate
    return None


def _build_mkl_flags():
    """返回 (compile_flags, link_flags)；找不到 MKL 时返回 ([], [])。"""
    root = _detect_mkl_root()
    if not root:
        return [], []
    include_dir = os.path.join(root, "include")
    if not os.path.isdir(include_dir):
        return [], []
    lib_dir = None
    for sub in ("lib/intel64", "lib"):
        candidate = os.path.join(root, sub)
        if os.path.isdir(candidate):
            lib_dir = candidate
            break
    if not lib_dir:
        return [], []
    compile_flags = ["-m64", f"-I{include_dir}"]
    # Sequential / LP64 链接组合，与 Intel Link Line Advisor 推荐的 gcc 选项一致
    link_flags = [
        f"-L{lib_dir}",
        f"-Wl,-rpath,{lib_dir}",
        "-Wl,--no-as-needed",
        "-lmkl_intel_lp64",
        "-lmkl_sequential",
        "-lmkl_core",
        "-lpthread",
        "-ldl",
    ]
    return compile_flags, link_flags


MKL_ROOT = _detect_mkl_root()
MKL_COMPILE_FLAGS, MKL_LINK_FLAGS = _build_mkl_flags()


def build_c_compile_cmd(source, output, compile_timeout_sec=30):
    cmd = ["timeout", f"{compile_timeout_sec}s",
           "gcc", "-O2", "-pipe", "-s", "-std=c11"]
    if os.path.exists(LIBRARY_PATH):
        cmd.extend(["-I", LIBRARY_PATH])
    cmd.extend(MKL_COMPILE_FLAGS)
    cmd.extend([source, "-o", output])
    cmd.extend(MKL_LINK_FLAGS)
    cmd.append("-lm")
    return cmd


def build_cpp_compile_cmd(source, output, compile_timeout_sec=30):
    cmd = ["timeout", f"{compile_timeout_sec}s",
           "g++", "-O2", "-pipe", "-s", "-std=c++20"]
    if os.path.exists(LIBRARY_PATH):
        cmd.extend(["-I", LIBRARY_PATH])
    cmd.extend(MKL_COMPILE_FLAGS)
    cmd.extend([source, "-o", output])
    cmd.extend(MKL_LINK_FLAGS)
    cmd.append("-lm")
    return cmd


# ========== 通用工具 ==========
SAFE_SID_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.]+$')
IMAGE_FILE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def sanitize_sid(sid: str) -> str:
    # 防止目录穿越与奇怪字符
    if not sid or not SAFE_SID_PATTERN.match(sid):
        # 用时间戳兜底
        return f"run_{int(time.time()*1000)}"
    return sid


def run_dir_for(sid: str) -> str:
    """返回某 sid 对应的运行目录绝对路径（不创建）。调用方据此定位评测产物（如输出图片）。"""
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
    """
    与原逻辑一致：
    - 支持把用户代码嵌在 here_is_user_code_fuck_fuck_fuck_hahaha ... user_code_end_fuck_hahaha_fuck 中时只检查中间部分
    - 逗号分割禁用函数名，按 func(...) 正则匹配
    """
    if not forbidden_str:
        return None  # OK
    match0 = re.search(
        r'here_is_user_code_fuck_fuck_fuck_hahaha(.*?)user_code_end_fuck_hahaha_fuck',
        code_content, re.DOTALL
    )
    code_content_check = match0.group(1) if match0 else code_content

    forbidden_funcs = [func.strip() for func in forbidden_str.split(",") if func.strip()]
    for func in forbidden_funcs:
        # C/Octave/Python 通用的“函数名(”匹配：前缀不为字母/数字/下划线
        pattern = r'[^a-zA-Z0-9_](' + re.escape(func) + r')\s*\('
        if re.search(pattern, code_content_check):
            return f"Function '{func}' is not allowed"

        # 特别处理：禁止反斜杠（只对 Octave 有意义，这里保留）
        if func == "\\" and re.search(r'\\', code_content_check):
            return "Operator \\ is not allowed"
    return None  # OK


def read_output_with_fallback(output_filename: str, captured_stdout: str):
    try:
        with open(output_filename, "r", encoding="utf-8") as file:
            outp = file.read()
        # 读到就删
        subprocess.run(["rm", output_filename], capture_output=False, text=False)
        return outp
    except FileNotFoundError:
        # 没有 output.txt，就用 stdout
        return captured_stdout


def set_run_limits(cpu_seconds: float, mem_bytes: int):
    """
    作为 preexec_fn：对子进程设置 rlimit。
    - CPU 限时：RLIMIT_CPU（秒，向上取整）
    - 地址空间：RLIMIT_AS（Byte）
    """
    def _setter():
        cpu_soft = max(1, int(cpu_seconds))
        cpu_hard = cpu_soft + 1
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))

        if mem_bytes and mem_bytes > 0:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    return _setter


def run_compiled_binary_test_case(sid, case_index, test_case, tle, mle, output_image_filename="output.png"):
    user_input = test_case.get("input", "")
    input_filename = f"{sid}/input_{case_index}.txt"
    output_filename = f"{sid}/output_{case_index}.txt"

    with open(input_filename, "w", encoding="utf-8") as f:
        f.write(user_input)

    time_lim_sec = (tle or 0) * 1.2 / 1e9
    start_time = time.perf_counter_ns()
    start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

    run_cmd = ["timeout", f"{time_lim_sec}s", "./a.out"]
    run_res = subprocess.run(
        run_cmd,
        cwd=sid,
        capture_output=True,
        text=True,
        input=user_input,
        preexec_fn=set_run_limits(time_lim_sec, mle or 0)
    )

    end_time = time.perf_counter_ns()
    end_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

    exec_time = end_time - start_time  # ns
    mem_usage_byte = (end_mem - start_mem) * 1024  # Byte
    outp = read_output_with_fallback(output_filename, run_res.stdout or "")

    # 处理用户程序输出图片，避免覆盖
    stored_image_filename = capture_output_image_file(
        sid,
        output_image_filename,
        f"output_{case_index}",
    )
    has_output_image = bool(stored_image_filename)

    status = "Accepted"
    exval = 0
    stderr = run_res.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif mem_usage_byte > (mle or 0):
        status = "Memory Limit Exceeded"
        exval = 10
    elif run_res.returncode != 0:
        status = "Runtime Error"
        exval = run_res.returncode

    files_dict = {"stdout": outp, "stderr": stderr}
    if has_output_image and stored_image_filename:
        files_dict[stored_image_filename] = True

    return {
        "test_case_index": case_index,
        "status": status,
        "exitStatus": exval,
        "files": files_dict,
        "time": exec_time,
        "memory": mem_usage_byte,
    }


# ========== 单次运行（Octave / Python / C / C++）==========
def run_octave(data):
    """等价于旧 /run-hello（Octave/MATLAB）。注意：Octave 不设 RLIMIT，仅靠 timeout。"""
    run_dir = _prepare_run_dir(data.get("sid", ""))
    user_input = data.get("input", "")
    code_content = data.get("code", "")
    tle = data.get("timeLimit")  # ns
    mle = (data.get("memoryLimit") or 0) * 10  # 保留历史的乘 10 逻辑
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

    input_filename = os.path.join(run_dir, "input.txt")
    output_filename = os.path.join(run_dir, "output.txt")
    code_filename = os.path.join(run_dir, "a.m")

    with open(input_filename, "w", encoding="utf-8") as f:
        f.write(user_input)
    with open(code_filename, "w", encoding="utf-8") as f:
        f.write(code_content)

    # timeout 用秒；Octave 多给 10% buffer
    timeLim_sec = (tle or 0) * 1.1 / 1e9

    start_time = time.perf_counter_ns()
    start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

    result = subprocess.run(
        ["timeout", f"{timeLim_sec}s", "octave", "a.m"],
        capture_output=True,
        text=True,
        input=user_input,
        cwd=run_dir,
    )

    end_time = time.perf_counter_ns()
    end_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

    exec_time = end_time - start_time  # ns
    mem_usage_byte = (end_mem - start_mem) * 1024  # ru_maxrss: KB => Byte

    outp = read_output_with_fallback(output_filename, result.stdout)

    status = "Accepted"
    exval = 0
    stderr = result.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif mem_usage_byte > (mle or 0):
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
        "memory": mem_usage_byte,
    }


def run_py(data):
    """等价于旧 /run-py。"""
    run_dir = _prepare_run_dir(data.get("sid", ""))
    user_input = data.get("input", "")
    code_content = data.get("code", "")
    tle = data.get("timeLimit")  # ns
    mle = (data.get("memoryLimit") or 0) * 10
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

    input_filename = os.path.join(run_dir, "input.txt")
    output_filename = os.path.join(run_dir, "output.txt")
    code_filename = os.path.join(run_dir, "main.py")

    with open(input_filename, "w", encoding="utf-8") as f:
        f.write(user_input)
    with open(code_filename, "w", encoding="utf-8") as f:
        f.write(code_content)

    timeLim_sec = (tle or 0) * 1.2 / 1e9

    start_time = time.perf_counter_ns()
    start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

    # -I 隔离环境（忽略用户 site），-u 无缓冲 IO；设置 PYTHONIOENCODING 保证中文一致性
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    run_cmd = ["timeout", f"{timeLim_sec}s", "python3", "-I", "-u", "main.py"]
    run_res = subprocess.run(
        run_cmd,
        cwd=run_dir,
        capture_output=True,
        text=True,
        input=user_input,
        preexec_fn=set_run_limits(timeLim_sec, mle or 0),
        env=env,
    )

    end_time = time.perf_counter_ns()
    end_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

    exec_time = end_time - start_time  # ns
    mem_usage_byte = (end_mem - start_mem) * 1024  # Byte

    outp = read_output_with_fallback(output_filename, run_res.stdout or "")

    status = "Accepted"
    exval = 0
    stderr = run_res.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif mem_usage_byte > (mle or 0):
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
        "memory": mem_usage_byte,
    }


def _run_compiled_single(data, language):
    """C/C++ 单次运行的公共实现（等价于旧 /run-c、/run-cpp）。"""
    run_dir = _prepare_run_dir(data.get("sid", ""))
    user_input = data.get("input", "")
    code_content = data.get("code", "")
    tle = data.get("timeLimit")  # ns
    mle = (data.get("memoryLimit") or 0) * 10
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
        compile_cmd = build_cpp_compile_cmd("main.cpp", "a.out")
        compile_err_cap = 3000
    else:
        src_name = "main.c"
        compile_cmd = build_c_compile_cmd("main.c", "a.out")
        compile_err_cap = 300

    input_filename = os.path.join(run_dir, "input.txt")
    output_filename = os.path.join(run_dir, "output.txt")
    code_filename = os.path.join(run_dir, src_name)

    with open(input_filename, "w", encoding="utf-8") as f:
        f.write(user_input)
    with open(code_filename, "w", encoding="utf-8") as f:
        f.write(code_content)

    # 写入用户的头文件（如果有）
    if user_files:
        for filename, content in user_files.items():
            with open(os.path.join(run_dir, filename), "w", encoding="utf-8") as f:
                f.write(content)

    # ===== 编译 =====
    compile_res = subprocess.run(compile_cmd, cwd=run_dir, capture_output=True, text=True)
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

    # ===== 运行 =====
    timeLim_sec = (tle or 0) * 1.2 / 1e9

    start_time = time.perf_counter_ns()
    start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

    run_cmd = ["timeout", f"{timeLim_sec}s", "./a.out"]
    run_res = subprocess.run(
        run_cmd,
        cwd=run_dir,
        capture_output=True,
        text=True,
        input=user_input,
        preexec_fn=set_run_limits(timeLim_sec, mle or 0),
    )

    end_time = time.perf_counter_ns()
    end_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

    exec_time = end_time - start_time  # ns
    mem_usage_byte = (end_mem - start_mem) * 1024  # Byte

    outp = read_output_with_fallback(output_filename, run_res.stdout or "")

    status = "Accepted"
    exval = 0
    stderr = run_res.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif mem_usage_byte > (mle or 0):
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
        "memory": mem_usage_byte,
    }


def run_c(data):
    return _run_compiled_single(data, "c")


def run_cpp(data):
    return _run_compiled_single(data, "cpp")


# ========== 批量评测：编译一次，运行多个测试点 ==========
def _batch_evaluate_stream(data, language):
    """编译一次、逐个跑测试点的生成器，逐步 yield 事件 dict：
       {"event":"compile", "status": "success/error/forbidden", "stderr": ...}
       {"event":"test_result", "result": {...}}
       {"event":"done", "ok": bool}
       {"event":"error", "message": ...}
    等价于旧 /batch-evaluate-stream-{c,cpp} 的每一行 NDJSON。"""
    code_content = data.get("code", "")
    test_cases = data.get("test_cases", [])
    tle = data.get("timeLimit")  # ns
    mle = (data.get("memoryLimit") or 0) * 10
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
            compile_cmd = build_cpp_compile_cmd("main.cpp", "a.out")
            compile_err_cap = 3000
        else:
            src_name = "main.c"
            compile_cmd = build_c_compile_cmd("main.c", "a.out")
            compile_err_cap = 300

        with open(os.path.join(run_dir, src_name), "w", encoding="utf-8") as f:
            f.write(code_content)

        if user_files:
            for filename, content in user_files.items():
                with open(os.path.join(run_dir, filename), "w", encoding="utf-8") as f:
                    f.write(content)

        compile_res = subprocess.run(compile_cmd, cwd=run_dir, capture_output=True, text=True)
        if compile_res.returncode != 0:
            stderr = compile_res.stderr or ""
            if len(stderr) > compile_err_cap:
                stderr = stderr[:compile_err_cap] + "..."
            yield {"event": "compile", "status": "error", "stderr": stderr}
            yield {"event": "done", "ok": False}
            return

        yield {"event": "compile", "status": "success", "stderr": ""}

        for i, test_case in enumerate(test_cases):
            result = run_compiled_binary_test_case(
                run_dir, i, test_case, tle, mle,
                output_image_filename=output_image_filename,
            )
            yield {"event": "test_result", "result": result}

        yield {"event": "done", "ok": True}
    except Exception as e:
        yield {"event": "error", "message": f"Failed to stream batch evaluate {language}: {str(e)}"}
        yield {"event": "done", "ok": False}


# ========== 对外分派 ==========
def run_single(language, data):
    """单次运行分派。language: matlab/octave、c、cpp、py/python。返回 result dict。"""
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
    """非流式批量评测（基于流式生成器收集）。返回 {compile_result, test_results}。"""
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
