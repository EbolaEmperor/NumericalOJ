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
import platform
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


# ========== C/C++ 编译命令 ==========
# 数值库题（题面所谓"评测环境已配置好编译链接参数"）依赖 Intel MKL。镜像内通过
# /opt/mkl/{include,lib} 软链统一暴露 MKL（屏蔽 oneAPI 版本目录差异，见 Dockerfile）。
# Sequential / LP64 链接组合，与 Intel Link Line Advisor 推荐的 gcc 选项一致；MKL 同时
# 提供 Fortran 原生符号（dsyev_ 等）、CBLAS（cblas_*）、LAPACKE（LAPACKE_*），因此用
# <mkl.h> 或通用 <cblas.h>/<lapacke.h> 头的解法都能解析符号。否则数值库题必 CE。
# -Wl,--no-as-needed 确保即使目标文件未直接引用也保留这些库；-ldl/-lpthread/-lm 兜底。
MKL_INCLUDE_DIR = "/opt/mkl/include"
MKL_LIB_DIR = "/opt/mkl/lib"
MKL_COMPILE_FLAGS = ["-I", MKL_INCLUDE_DIR]
MKL_LINK_FLAGS = [
    "-L", MKL_LIB_DIR,
    f"-Wl,-rpath,{MKL_LIB_DIR}",
    "-Wl,--no-as-needed",
    "-lmkl_intel_lp64", "-lmkl_sequential", "-lmkl_core",
    "-lpthread", "-ldl", "-lm",
]
OPENBLAS_LINK_FLAGS = [
    "-lopenblas", "-llapacke", "-llapack", "-lblas", "-lm",
]


def _config_value(name, default=None):
    env_value = os.environ.get(name)
    if env_value is not None and str(env_value).strip() != "":
        return env_value
    try:
        import config as _cfg
    except ImportError:
        return default
    return getattr(_cfg, name, default)


def _truthy_config_value(value):
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return None


def _target_machine_arch():
    raw = str(_config_value("JUDGER_TARGET_ARCH", "") or "").strip().lower()
    if raw:
        return raw
    return str(platform.machine() or "").strip().lower()


def _is_x86_64_target():
    return _target_machine_arch() in ("x86_64", "amd64")


def _mkl_compile_flags():
    flags = []
    if _is_x86_64_target():
        flags.append("-m64")
    flags.extend(MKL_COMPILE_FLAGS)
    return flags


def _numeric_backend():
    """返回 C/C++ 数值库后端：mkl / openblas / none。

    生产默认仍是 MKL；本机 lite 镜像名包含 judger-lite 时自动改用
    OpenBLAS/LAPACKE，避免 lite 镜像因为没有 /opt/mkl 而所有 C/C++ 编译失败。
    JUDGER_NUMERIC_BACKEND 可显式关闭数值库；但 judger-lite 镜像没有 MKL，
    因此不会允许显式切回 MKL。
    """
    image = str(_config_value("JUDGER_DOCKER_IMAGE", "numericaloj-judger:latest") or "").lower()
    raw_backend = str(_config_value("JUDGER_NUMERIC_BACKEND", "") or "").strip().lower()
    if raw_backend == "none":
        return "none"
    if "judger-lite" in image:
        return "openblas"
    if raw_backend in ("mkl", "openblas"):
        return raw_backend

    legacy_mkl = _config_value("JUDGER_ENABLE_MKL", None)
    if legacy_mkl is not None:
        parsed = _truthy_config_value(legacy_mkl)
        if parsed is not None:
            return "mkl" if parsed else "openblas"

    if not _is_x86_64_target():
        return "openblas"

    return "mkl"


def build_compile_cmd(language, compile_timeout_sec=30):
    """构造 C/C++ 容器内编译命令。"""
    if language == "cpp":
        cmd = ["timeout", f"{compile_timeout_sec}s", "g++", "-O2", "-pipe", "-s", "-std=c++20"]
        src = "main.cpp"
    else:
        cmd = ["timeout", f"{compile_timeout_sec}s", "gcc", "-O2", "-pipe", "-s", "-std=c11"]
        src = "main.c"
    cmd.extend(["-I", "/opt/library"])
    backend = _numeric_backend()
    if backend == "mkl":
        cmd.extend(_mkl_compile_flags())
    cmd.extend([src, "-o", "a.out"])
    if backend == "mkl":
        cmd.extend(MKL_LINK_FLAGS)
    elif backend == "openblas":
        cmd.extend(OPENBLAS_LINK_FLAGS)
    return cmd


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
    """把 sid 落到 JUDGER_RUN_ROOT 下的绝对运行目录并确保存在。

    run_dir 由本进程（宿主用户，如 uid 1004）创建，但容器内以非特权用户
    runner（uid 1000）运行，需要在该目录里创建 output.txt / a.out 等结果文件。
    宿主与容器 uid 不一致时，0755 目录会导致容器写入 Permission denied，
    故放宽为 0777（run_dir 为每次评测的一次性临时目录，判题后即清理）。
    """
    run_dir = run_dir_for(sid)
    ensure_dir(run_dir)
    try:
        os.chmod(run_dir, 0o777)
    except OSError:
        pass
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


def capture_output_image_file_to_dir(source_dir: str, target_dir: str, requested_filename: str, stored_stem: str):
    requested_name = sanitize_output_image_filename(requested_filename)
    source_path = os.path.join(source_dir, requested_name)
    if not os.path.isfile(source_path):
        return None

    _, ext = os.path.splitext(requested_name)
    ext = str(ext or "").lower()
    if not ext:
        ext = ".png"
    if ext not in IMAGE_FILE_EXTENSIONS:
        return None

    target_filename = f"{stored_stem}{ext}"
    target_path = os.path.join(target_dir, target_filename)
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


def _measured_exec_time_ns(result, tle_ns):
    """返回容器内部测得的运行时间。

    正常路径下由 docker_sandbox 的 shell wrapper 写回 elapsed_ns；如果外层
    Docker guard 超时导致 wrapper 来不及输出 marker，则把本次运行视作超时。
    """
    elapsed_ns = getattr(result, "elapsed_ns", None)
    if isinstance(elapsed_ns, int) and elapsed_ns >= 0:
        return elapsed_ns
    if getattr(result, "returncode", None) == 124 and tle_ns:
        return int(tle_ns) + 1
    return 0


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
    with open(os.path.join(run_dir, "input.txt"), "w", encoding="utf-8") as f:
        f.write(user_input)

    timeLim_sec = _timeout_sec_from_ns(tle, factor=1.1)
    container_cmd = ["timeout", f"{timeLim_sec}s", "octave", "a.m"]

    result = run_in_container(
        container_cmd,
        run_dir=run_dir,
        input_text=user_input,
        timeout_sec=_guard_timeout(timeLim_sec),
        measure_time=True,
    )
    exec_time = _measured_exec_time_ns(result, tle)

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
    with open(os.path.join(run_dir, "input.txt"), "w", encoding="utf-8") as f:
        f.write(user_input)

    timeLim_sec = _timeout_sec_from_ns(tle, factor=1.2)
    container_cmd = ["timeout", f"{timeLim_sec}s", "python3", "-I", "-u", "main.py"]

    result = run_in_container(
        container_cmd,
        run_dir=run_dir,
        input_text=user_input,
        timeout_sec=_guard_timeout(timeLim_sec),
        measure_time=True,
    )
    exec_time = _measured_exec_time_ns(result, tle)

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
        compile_err_cap = 3000
    else:
        src_name = "main.c"
        compile_err_cap = 300
    compile_cmd = build_compile_cmd(language)

    with open(os.path.join(run_dir, src_name), "w", encoding="utf-8") as f:
        f.write(code_content)
    with open(os.path.join(run_dir, "input.txt"), "w", encoding="utf-8") as f:
        f.write(user_input)

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

    run_res = run_in_container(
        run_cmd,
        run_dir=run_dir,
        input_text=user_input,
        timeout_sec=_guard_timeout(timeLim_sec),
        measure_time=True,
    )
    exec_time = _measured_exec_time_ns(run_res, tle)

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
            compile_err_cap = 3000
        else:
            src_name = "main.c"
            compile_err_cap = 300
        compile_cmd = build_compile_cmd(language)

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
                with open(os.path.join(run_dir, "input.txt"), "w", encoding="utf-8") as f:
                    f.write(user_input)
                timeLim_sec = _timeout_sec_from_ns(tle, factor=1.2)
                run_cmd = ["timeout", f"{timeLim_sec}s", "./a.out"]

                run_res = session.exec(
                    run_cmd,
                    input_text=user_input,
                    timeout_sec=_guard_timeout(timeLim_sec),
                    measure_time=True,
                )
                exec_time = _measured_exec_time_ns(run_res, tle)

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


# ========== 批量评测：解释型语言（Octave / Python），单容器多测试点 ==========
def _batch_evaluate_script_stream(data, language):
    """解释型语言（Octave/Python）批量评测生成器。

    每份提交只起 **一个常驻容器**（ContainerSession），逐测试点 `docker exec`
    运行脚本，避免每个测试点都 `docker run` 带来的容器启动开销与 docker 守护
    进程争抢（这是 Octave 题在容器化后必然 TLE 的根因）。计时只包住单次
    `session.exec`（容器内脚本启动+运行），**不含** 容器一次性启动开销，
    与旧的进程内模型时间语义保持一致。
    """
    code_content = data.get("code", "")
    test_cases = data.get("test_cases", [])
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    output_image_filename = data.get("outputImageFilename", "output.png")

    try:
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            yield {"event": "compile", "status": "forbidden", "stderr": forbid_msg}
            yield {"event": "done", "ok": False}
            return

        run_dir = _prepare_run_dir(data.get("sid", ""))

        if language in ("matlab", "octave", "hello"):
            src_name = "a.m"
            factor = 1.1
            run_status_nonzero = "Nonzero Exit Status"
            make_cmd = lambda t: ["timeout", f"{t}s", "octave", "../a.m"]
        else:  # python
            src_name = "main.py"
            factor = 1.2
            run_status_nonzero = "Runtime Error"
            make_cmd = lambda t: ["timeout", f"{t}s", "python3", "-I", "-u", "../main.py"]

        with open(os.path.join(run_dir, src_name), "w", encoding="utf-8") as f:
            f.write(code_content)

        # 解释型语言无编译步骤，直接报告编译成功以复用上层 stream 处理逻辑。
        yield {"event": "compile", "status": "success", "stderr": ""}

        with ContainerSession(run_dir=run_dir) as session:
            for i, test_case in enumerate(test_cases):
                user_input = test_case.get("input", "")
                case_dir = os.path.join(run_dir, f"case_{i}")
                if os.path.isdir(case_dir):
                    shutil.rmtree(case_dir, ignore_errors=True)
                ensure_dir(case_dir)
                try:
                    os.chmod(case_dir, 0o777)
                except OSError:
                    pass

                with open(os.path.join(case_dir, "input.txt"), "w", encoding="utf-8") as f:
                    f.write(user_input)

                timeLim_sec = _timeout_sec_from_ns(tle, factor=factor)
                run_cmd = make_cmd(timeLim_sec)

                run_res = session.exec(
                    run_cmd,
                    input_text=user_input,
                    timeout_sec=_guard_timeout(timeLim_sec),
                    workdir=f"/sandbox/case_{i}",
                    measure_time=True,
                )
                exec_time = _measured_exec_time_ns(run_res, tle)

                output_filename = os.path.join(case_dir, "output.txt")
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
                    status = run_status_nonzero
                    exval = run_res.returncode

                files_dict = {"stdout": outp, "stderr": stderr}
                stored_image_filename = capture_output_image_file_to_dir(
                    case_dir, run_dir, output_image_filename, f"output_{i}",
                )
                if stored_image_filename:
                    files_dict[stored_image_filename] = True
                try:
                    shutil.rmtree(case_dir, ignore_errors=True)
                except Exception:
                    pass

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
        yield {"event": "error", "message": f"Failed to stream script batch evaluate {language}: {str(e)}"}
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
    """流式批量评测分派（生成器）。

    c/cpp：编译一次 + 逐测试点运行（_batch_evaluate_stream）。
    matlab/octave、python：常驻容器逐测试点 exec（_batch_evaluate_script_stream）。
    """
    lang = str(language or "").strip().lower()
    if lang in ("cpp", "c++"):
        return _batch_evaluate_stream(data, "cpp")
    if lang == "c":
        return _batch_evaluate_stream(data, "c")
    if lang in ("matlab", "octave", "hello"):
        return _batch_evaluate_script_stream(data, "octave")
    if lang in ("py", "python", "python3"):
        return _batch_evaluate_script_stream(data, "python")
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
