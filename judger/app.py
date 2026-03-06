import re
import json
from flask import Flask, request, jsonify, Response, stream_with_context
import subprocess
import time
import resource
import os
import shlex

app = Flask(__name__)

# 获取OJ系统根目录路径
def get_oj_root_path():
    """
    获取OJ系统根目录路径，用于-I编译选项
    优先级：环境变量 > 相对路径计算 > 默认路径
    """
    # 方法1: 从环境变量获取
    oj_root = os.environ.get('OJ_ROOT_PATH')
    if oj_root and os.path.exists(oj_root):
        return oj_root
    
    # 方法2: 基于当前脚本位置计算
    # judger/app.py -> ../  (上一级目录就是OJ根目录)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    oj_root = os.path.dirname(current_dir)
    if os.path.exists(oj_root):
        return oj_root
    
    # 方法3: 使用默认路径
    return "/opt/oj"

OJ_ROOT_PATH = get_oj_root_path()
LIBRARY_PATH = os.path.join(OJ_ROOT_PATH, "library")

# 启动时打印路径信息，便于调试
print(f"[Judger] OJ Root Path: {OJ_ROOT_PATH}")
print(f"[Judger] Library Path: {LIBRARY_PATH}")
print(f"[Judger] Library Path exists: {os.path.exists(LIBRARY_PATH)}")

ALLOWED_IPS = [
    "127.0.0.1"
]

# ========== 通用工具 ==========
SAFE_SID_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.]+$')

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def sanitize_sid(sid: str) -> str:
    # 防止目录穿越与奇怪字符
    if not sid or not SAFE_SID_PATTERN.match(sid):
        # 用时间戳兜底
        return f"run_{int(time.time()*1000)}"
    return sid

def check_forbidden(code_content: str, forbidden_str: str):
    """
    与你原来逻辑一致：
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
        # 注意对 Python 的 os.system/ pathlib.Path(...).write_text( 也可匹配到 system( / write_text(
        pattern = r'[^a-zA-Z0-9_](' + re.escape(func) + r')\s*\('
        if re.search(pattern, code_content_check):
            return f"Function '{func}' is not allowed"

        # 你原来的特别处理：禁止反斜杠（只对 Octave 有意义，这里保留）
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
        # CPU：再加一点点 buffer，避免刚好被 SIGXCPU 打断
        cpu_soft = max(1, int(cpu_seconds))
        cpu_hard = cpu_soft + 1
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))

        if mem_bytes and mem_bytes > 0:
            # 地址空间（含堆栈）
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            # 限制数据段也可以考虑（部分系统上更严格）：
            # resource.setrlimit(resource.RLIMIT_DATA, (mem_bytes, mem_bytes))
    return _setter


def ndjson_line(data):
    return json.dumps(data, ensure_ascii=False) + "\n"


def run_compiled_binary_test_case(sid, case_index, test_case, tle, mle):
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
    original_image_path = f"{sid}/output.png"
    renamed_image_path = f"{sid}/output_{case_index}.png"
    has_output_image = False
    if os.path.exists(original_image_path):
        try:
            subprocess.run(["mv", original_image_path, renamed_image_path], capture_output=True, text=False)
            has_output_image = True
        except Exception:
            try:
                subprocess.run(["cp", original_image_path, renamed_image_path], capture_output=True, text=False)
                has_output_image = True
            except Exception:
                pass

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
    if has_output_image:
        files_dict[f"output_{case_index}.png"] = True

    return {
        "test_case_index": case_index,
        "status": status,
        "exitStatus": exval,
        "files": files_dict,
        "time": exec_time,
        "memory": mem_usage_byte,
    }

# ========== 白名单 ==========
@app.before_request
def check_ip_whitelist():
    client_ip = request.remote_addr
    if client_ip not in ALLOWED_IPS:
        return jsonify({"message": f"Forbidden: IP {client_ip} not allowed"}), 403

# ========== Octave/MATLAB 保留的原接口 ==========
@app.route("/run-hello", methods=["POST"])
def run_hello():
    data = request.get_json() or {}
    try:
        sid = sanitize_sid(data.get("sid", ""))
        user_input = data.get("input", "")
        code_content = data.get("code", "")
        tle = data.get("timeLimit")  # ns
        mle = (data.get("memoryLimit") or 0) * 10  # 保留你原来的乘 10 逻辑
        forbidden_funcs = data.get("forbidden", "")

        # 禁用函数检查
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            return jsonify({
                "status": "Forbidden",
                "exitStatus": 11,
                "files": {"stdout": forbid_msg, "stderr": forbid_msg},
                "time": 0,
                "memory": 0,
            }), 200

        # 路径
        ensure_dir(sid)
        input_filename = f"{sid}/input.txt"
        output_filename = f"{sid}/output.txt"
        code_filename = f"{sid}/a.m"

        # 生成文件
        with open(input_filename, "w", encoding="utf-8") as f:
            f.write(user_input)
        with open(code_filename, "w", encoding="utf-8") as f:
            f.write(code_content)

        # timeout 用秒；多给 10% buffer
        timeLim_sec = (tle or 0) * 1.1 / 1e9

        start_time = time.perf_counter_ns()
        start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

        result = subprocess.run(
            ["timeout", f"{timeLim_sec}s", "octave", "a.m"],
            capture_output=True,
            text=True,
            input=user_input,
            cwd=sid
        )

        end_time = time.perf_counter_ns()
        end_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

        exec_time = end_time - start_time        # ns
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

        # 检查是否生成了输出图片
        files_dict = {"stdout": outp, "stderr": stderr}
        output_image_path = f"{sid}/output.png"
        if os.path.exists(output_image_path):
            files_dict["output.png"] = True  # 标记存在图片文件

        return jsonify({
            "status": status,
            "exitStatus": exval,
            "files": files_dict,
            "time": exec_time,
            "memory": mem_usage_byte,
        }), 200

    except Exception as e:
        return jsonify({"message": f"Failed to run hello: {str(e)}"}), 500

# ========== 新增：Python 语言评测接口 ==========
@app.route("/run-py", methods=["POST"])
def run_py():
    """
    输入字段与 /run-hello 保持一致：
    - sid: 运行目录（会创建）
    - input: 作为程序 stdin
    - code: Python 源码（写入 main.py）
    - timeLimit: ns
    - memoryLimit: Byte（与原接口一致；按你原来逻辑乘 10，用作运行时 RLIMIT_AS）
    - forbidden: 逗号分割的函数名列表（如 "system,exec,eval,open"）
    返回字段与 /run-hello 相同。
    """
    data = request.get_json() or {}
    try:
        sid = sanitize_sid(data.get("sid", ""))
        user_input = data.get("input", "")
        code_content = data.get("code", "")
        tle = data.get("timeLimit")  # ns
        mle = (data.get("memoryLimit") or 0) * 10  # 与其它语言保持一致
        forbidden_funcs = data.get("forbidden", "")

        # 禁用函数检查（正则兼容 Python）
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            return jsonify({
                "status": "Forbidden",
                "exitStatus": 11,
                "files": {"stdout": forbid_msg, "stderr": forbid_msg},
                "time": 0,
                "memory": 0,
            }), 200

        # 建目录 & 写文件
        ensure_dir(sid)
        input_filename = f"{sid}/input.txt"
        output_filename = f"{sid}/output.txt"
        code_filename = f"{sid}/main.py"

        with open(input_filename, "w", encoding="utf-8") as f:
            f.write(user_input)
        with open(code_filename, "w", encoding="utf-8") as f:
            f.write(code_content)

        # ===== 运行 =====
        timeLim_sec = (tle or 0) * 1.2 / 1e9

        start_time = time.perf_counter_ns()
        start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

        # 使用 -I 隔离环境（忽略用户 site），-u 无缓冲 IO，-B 禁止 .pyc 生成可选
        # 同时设置 PYTHONIOENCODING，保证中文一致性
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"

        run_cmd = ["timeout", f"{timeLim_sec}s", "python3", "-I", "-u", "main.py"]
        run_res = subprocess.run(
            run_cmd,
            cwd=sid,
            capture_output=True,
            text=True,
            input=user_input,
            preexec_fn=set_run_limits(timeLim_sec, mle or 0),
            env=env
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

        # 判定优先级与其它语言一致
        if exec_time > (tle or 0):
            status = "Time Limit Exceeded"
            exval = 9
        elif mem_usage_byte > (mle or 0):
            status = "Memory Limit Exceeded"
            exval = 10
        elif run_res.returncode != 0:
            status = "Runtime Error"
            exval = run_res.returncode

        # 检查是否生成了输出图片
        files_dict = {"stdout": outp, "stderr": stderr}
        output_image_path = f"{sid}/output.png"
        if os.path.exists(output_image_path):
            files_dict["output.png"] = True  # 标记存在图片文件

        return jsonify({
            "status": status,
            "exitStatus": exval,
            "files": files_dict,
            "time": exec_time,
            "memory": mem_usage_byte,
        }), 200

    except Exception as e:
        return jsonify({"message": f"Failed to run Python: {str(e)}"}), 500

# ========== 新增：C 语言评测接口 ==========
@app.route("/run-c", methods=["POST"])
def run_c():
    """
    输入字段与 /run-hello 保持一致：
    - sid: 运行目录（会创建）
    - input: 作为程序 stdin
    - code: C 源码（写入 main.c）
    - timeLimit: ns（和原接口一致）
    - memoryLimit: Byte（与原接口一致；按你原来逻辑乘 10，用作运行时 RLIMIT_AS）
    - forbidden: 逗号分割的函数名列表（如 "system,fopen"）
    返回字段与 /run-hello 相同。
    """
    data = request.get_json() or {}
    try:
        sid = sanitize_sid(data.get("sid", ""))
        user_input = data.get("input", "")
        code_content = data.get("code", "")
        tle = data.get("timeLimit")  # ns
        mle = (data.get("memoryLimit") or 0) * 10  # 与 /run-hello 一致
        forbidden_funcs = data.get("forbidden", "")

        # 禁用函数检查（对 C 同样生效）
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            return jsonify({
                "status": "Forbidden",
                "exitStatus": 11,
                "files": {"stdout": forbid_msg, "stderr": forbid_msg},
                "time": 0,
                "memory": 0,
            }), 200

        # 建目录 & 写文件
        ensure_dir(sid)
        input_filename = f"{sid}/input.txt"
        output_filename = f"{sid}/output.txt"
        code_filename = f"{sid}/main.c"
        bin_filename = f"{sid}/a.out"

        with open(input_filename, "w", encoding="utf-8") as f:
            f.write(user_input)
        with open(code_filename, "w", encoding="utf-8") as f:
            f.write(code_content)
        
        # 写入用户的头文件（如果有）
        user_files = data.get("user_files", {})
        if user_files:
            for filename, content in user_files.items():
                user_file_path = f"{sid}/{filename}"
                with open(user_file_path, "w", encoding="utf-8") as f:
                    f.write(content)

        # ===== 编译 =====
        compile_timeout_sec = 30
        compile_cmd = ["timeout", f"{compile_timeout_sec}s",
                       "gcc", "-O2", "-pipe", "-s", "-lm", "-std=c11"]
        
        # 添加库路径（如果存在）
        if os.path.exists(LIBRARY_PATH):
            compile_cmd.extend(["-I", LIBRARY_PATH])
        
        compile_cmd.extend(["main.c", "-o", "a.out"])
        compile_res = subprocess.run(
            compile_cmd,
            cwd=sid,
            capture_output=True,
            text=True
        )
        if compile_res.returncode != 0:
            stderr = compile_res.stderr or ""
            if len(stderr) > 300:
                stderr = stderr[:300] + "..."
            return jsonify({
                "status": "Compile Error",
                "exitStatus": compile_res.returncode,
                "files": {"stdout": compile_res.stdout or "", "stderr": stderr},
                "time": 0,
                "memory": 0,
            }), 200

        # ===== 运行 =====
        timeLim_sec = (tle or 0) * 1.2 / 1e9

        start_time = time.perf_counter_ns()
        start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

        # 注意：同时使用 coreutils 的 timeout 和 RLIMIT_CPU；双保险
        run_cmd = ["timeout", f"{timeLim_sec}s", "./a.out"]
        run_res = subprocess.run(
            run_cmd,
            cwd=sid,
            capture_output=True,
            text=True,
            input=user_input,
            preexec_fn=set_run_limits(timeLim_sec, mle or 0)
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

        # 与 /run-hello 同样的判定优先级
        if exec_time > (tle or 0):
            status = "Time Limit Exceeded"
            exval = 9
        elif mem_usage_byte > (mle or 0):
            status = "Memory Limit Exceeded"
            exval = 10
        elif run_res.returncode != 0:
            status = "Runtime Error"
            exval = run_res.returncode

        # 检查是否生成了输出图片
        files_dict = {"stdout": outp, "stderr": stderr}
        output_image_path = f"{sid}/output.png"
        if os.path.exists(output_image_path):
            files_dict["output.png"] = True  # 标记存在图片文件

        return jsonify({
            "status": status,
            "exitStatus": exval,
            "files": files_dict,
            "time": exec_time,
            "memory": mem_usage_byte,
        }), 200

    except Exception as e:
        return jsonify({"message": f"Failed to run C: {str(e)}"}), 500

# ========== 新增：C++ 语言评测接口 ==========
@app.route("/run-cpp", methods=["POST"])
def run_cpp():
    """
    输入字段与 /run-hello 保持一致：
    - sid: 运行目录（会创建）
    - input: 作为程序 stdin
    - code: C++ 源码（写入 main.cpp）
    - timeLimit: ns（和原接口一致）
    - memoryLimit: Byte（与原接口一致；按你原来逻辑乘 10，用作运行时 RLIMIT_AS）
    - forbidden: 逗号分割的函数名列表（如 "system,fopen"）
    返回字段与 /run-hello 相同。
    """
    data = request.get_json() or {}
    try:
        sid = sanitize_sid(data.get("sid", ""))
        user_input = data.get("input", "")
        code_content = data.get("code", "")
        tle = data.get("timeLimit")  # ns
        mle = (data.get("memoryLimit") or 0) * 10  # 与 /run-hello 一致
        forbidden_funcs = data.get("forbidden", "")

        # 禁用函数检查（对 C 同样生效）
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            return jsonify({
                "status": "Forbidden",
                "exitStatus": 11,
                "files": {"stdout": forbid_msg, "stderr": forbid_msg},
                "time": 0,
                "memory": 0,
            }), 200

        # 建目录 & 写文件
        ensure_dir(sid)
        input_filename = f"{sid}/input.txt"
        output_filename = f"{sid}/output.txt"
        code_filename = f"{sid}/main.cpp"
        bin_filename = f"{sid}/a.out"

        with open(input_filename, "w", encoding="utf-8") as f:
            f.write(user_input)
        with open(code_filename, "w", encoding="utf-8") as f:
            f.write(code_content)
        
        # 写入用户的头文件（如果有）
        user_files = data.get("user_files", {})
        if user_files:
            for filename, content in user_files.items():
                user_file_path = f"{sid}/{filename}"
                with open(user_file_path, "w", encoding="utf-8") as f:
                    f.write(content)

        # ===== 编译 =====
        compile_timeout_sec = 30
        compile_cmd = ["timeout", f"{compile_timeout_sec}s",
                       "g++", "-O2", "-pipe", "-s", "-lm", "-std=c++20"]
        
        # 添加库路径（如果存在）
        if os.path.exists(LIBRARY_PATH):
            compile_cmd.extend(["-I", LIBRARY_PATH])
        
        compile_cmd.extend(["main.cpp", "-o", "a.out"])
        compile_res = subprocess.run(
            compile_cmd,
            cwd=sid,
            capture_output=True,
            text=True
        )
        if compile_res.returncode != 0:
            stderr = compile_res.stderr or ""
            if len(stderr) > 3000:
                stderr = stderr[:3000] + "..."
            return jsonify({
                "status": "Compile Error",
                "exitStatus": compile_res.returncode,
                "files": {"stdout": compile_res.stdout or "", "stderr": stderr},
                "time": 0,
                "memory": 0,
            }), 200

        # ===== 运行 =====
        timeLim_sec = (tle or 0) * 1.2 / 1e9

        start_time = time.perf_counter_ns()
        start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

        # 注意：同时使用 coreutils 的 timeout 和 RLIMIT_CPU；双保险
        run_cmd = ["timeout", f"{timeLim_sec}s", "./a.out"]
        run_res = subprocess.run(
            run_cmd,
            cwd=sid,
            capture_output=True,
            text=True,
            input=user_input,
            preexec_fn=set_run_limits(timeLim_sec, mle or 0)
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

        # 与 /run-hello 同样的判定优先级
        if exec_time > (tle or 0):
            status = "Time Limit Exceeded"
            exval = 9
        elif mem_usage_byte > (mle or 0):
            status = "Memory Limit Exceeded"
            exval = 10
        elif run_res.returncode != 0:
            status = "Runtime Error"
            exval = run_res.returncode

        # 检查是否生成了输出图片
        files_dict = {"stdout": outp, "stderr": stderr}
        output_image_path = f"{sid}/output.png"
        if os.path.exists(output_image_path):
            files_dict["output.png"] = True  # 标记存在图片文件

        return jsonify({
            "status": status,
            "exitStatus": exval,
            "files": files_dict,
            "time": exec_time,
            "memory": mem_usage_byte,
        }), 200

    except Exception as e:
        return jsonify({"message": f"Failed to run C++: {str(e)}"}), 500

# ========== 批量评测接口：编译一次，运行多个测试点 ==========
@app.route("/batch-evaluate-stream-c", methods=["POST"])
def batch_evaluate_stream_c():
    data = request.get_json() or {}
    sid = sanitize_sid(data.get("sid", ""))
    code_content = data.get("code", "")
    test_cases = data.get("test_cases", [])
    tle = data.get("timeLimit")  # ns
    mle = (data.get("memoryLimit") or 0) * 10
    forbidden_funcs = data.get("forbidden", "")
    user_files = data.get("user_files", {})

    def generate():
        try:
            forbid_msg = check_forbidden(code_content, forbidden_funcs)
            if forbid_msg:
                yield ndjson_line({"event": "compile", "status": "forbidden", "stderr": forbid_msg})
                yield ndjson_line({"event": "done", "ok": False})
                return

            ensure_dir(sid)
            with open(f"{sid}/main.c", "w", encoding="utf-8") as f:
                f.write(code_content)

            if user_files:
                for filename, content in user_files.items():
                    with open(f"{sid}/{filename}", "w", encoding="utf-8") as f:
                        f.write(content)

            compile_timeout_sec = 30
            compile_cmd = ["timeout", f"{compile_timeout_sec}s", "gcc", "-O2", "-pipe", "-s", "-lm", "-std=c11"]
            if os.path.exists(LIBRARY_PATH):
                compile_cmd.extend(["-I", LIBRARY_PATH])
            compile_cmd.extend(["main.c", "-o", "a.out"])

            compile_res = subprocess.run(
                compile_cmd,
                cwd=sid,
                capture_output=True,
                text=True
            )
            if compile_res.returncode != 0:
                stderr = compile_res.stderr or ""
                if len(stderr) > 300:
                    stderr = stderr[:300] + "..."
                yield ndjson_line({"event": "compile", "status": "error", "stderr": stderr})
                yield ndjson_line({"event": "done", "ok": False})
                return

            yield ndjson_line({"event": "compile", "status": "success", "stderr": ""})

            for i, test_case in enumerate(test_cases):
                result = run_compiled_binary_test_case(sid, i, test_case, tle, mle)
                yield ndjson_line({"event": "test_result", "result": result})

            yield ndjson_line({"event": "done", "ok": True})
        except Exception as e:
            yield ndjson_line({"event": "error", "message": f"Failed to stream batch evaluate C: {str(e)}"})
            yield ndjson_line({"event": "done", "ok": False})

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/batch-evaluate-stream-cpp", methods=["POST"])
def batch_evaluate_stream_cpp():
    data = request.get_json() or {}
    sid = sanitize_sid(data.get("sid", ""))
    code_content = data.get("code", "")
    test_cases = data.get("test_cases", [])
    tle = data.get("timeLimit")  # ns
    mle = (data.get("memoryLimit") or 0) * 10
    forbidden_funcs = data.get("forbidden", "")
    user_files = data.get("user_files", {})

    def generate():
        try:
            forbid_msg = check_forbidden(code_content, forbidden_funcs)
            if forbid_msg:
                yield ndjson_line({"event": "compile", "status": "forbidden", "stderr": forbid_msg})
                yield ndjson_line({"event": "done", "ok": False})
                return

            ensure_dir(sid)
            with open(f"{sid}/main.cpp", "w", encoding="utf-8") as f:
                f.write(code_content)

            if user_files:
                for filename, content in user_files.items():
                    with open(f"{sid}/{filename}", "w", encoding="utf-8") as f:
                        f.write(content)

            compile_timeout_sec = 30
            compile_cmd = ["timeout", f"{compile_timeout_sec}s", "g++", "-O2", "-pipe", "-s", "-lm", "-std=c++20"]
            if os.path.exists(LIBRARY_PATH):
                compile_cmd.extend(["-I", LIBRARY_PATH])
            compile_cmd.extend(["main.cpp", "-o", "a.out"])

            compile_res = subprocess.run(
                compile_cmd,
                cwd=sid,
                capture_output=True,
                text=True
            )
            if compile_res.returncode != 0:
                stderr = compile_res.stderr or ""
                if len(stderr) > 3000:
                    stderr = stderr[:3000] + "..."
                yield ndjson_line({"event": "compile", "status": "error", "stderr": stderr})
                yield ndjson_line({"event": "done", "ok": False})
                return

            yield ndjson_line({"event": "compile", "status": "success", "stderr": ""})

            for i, test_case in enumerate(test_cases):
                result = run_compiled_binary_test_case(sid, i, test_case, tle, mle)
                yield ndjson_line({"event": "test_result", "result": result})

            yield ndjson_line({"event": "done", "ok": True})
        except Exception as e:
            yield ndjson_line({"event": "error", "message": f"Failed to stream batch evaluate C++: {str(e)}"})
            yield ndjson_line({"event": "done", "ok": False})

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/batch-evaluate-c", methods=["POST"])
def batch_evaluate_c():
    """
    C语言批量评测接口：编译一次，运行多个测试点
    输入字段：
    - sid: 运行目录（会创建）
    - code: C 源码
    - test_cases: 测试点数组 [{"input": "...", "expected_output": "..."}, ...]
    - timeLimit: ns（每个测试点的时间限制）
    - memoryLimit: Byte
    - forbidden: 逗号分割的函数名列表
    - user_files: 用户头文件字典
    返回字段：
    - compile_result: 编译结果 {"status": "success/error", "stderr": "..."}
    - test_results: 每个测试点的结果数组
    """
    data = request.get_json() or {}
    try:
        sid = sanitize_sid(data.get("sid", ""))
        code_content = data.get("code", "")
        test_cases = data.get("test_cases", [])
        tle = data.get("timeLimit")  # ns
        mle = (data.get("memoryLimit") or 0) * 10
        forbidden_funcs = data.get("forbidden", "")
        user_files = data.get("user_files", {})

        # 禁用函数检查
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            return jsonify({
                "compile_result": {"status": "forbidden", "stderr": forbid_msg},
                "test_results": []
            }), 200

        # 建目录 & 写文件
        ensure_dir(sid)
        code_filename = f"{sid}/main.c"
        bin_filename = f"{sid}/a.out"

        with open(code_filename, "w", encoding="utf-8") as f:
            f.write(code_content)
        
        # 写入用户的头文件
        if user_files:
            for filename, content in user_files.items():
                user_file_path = f"{sid}/{filename}"
                with open(user_file_path, "w", encoding="utf-8") as f:
                    f.write(content)

        # ===== 编译（只编译一次）=====
        compile_timeout_sec = 30
        compile_cmd = ["timeout", f"{compile_timeout_sec}s",
                       "gcc", "-O2", "-pipe", "-s", "-lm", "-std=c11"]
        
        if os.path.exists(LIBRARY_PATH):
            compile_cmd.extend(["-I", LIBRARY_PATH])
        
        compile_cmd.extend(["main.c", "-o", "a.out"])
        compile_res = subprocess.run(
            compile_cmd,
            cwd=sid,
            capture_output=True,
            text=True
        )
        
        if compile_res.returncode != 0:
            stderr = compile_res.stderr or ""
            if len(stderr) > 300:
                stderr = stderr[:300] + "..."
            return jsonify({
                "compile_result": {"status": "error", "stderr": stderr},
                "test_results": []
            }), 200

        # ===== 逐个运行测试点 =====
        test_results = []
        timeLim_sec = (tle or 0) * 1.2 / 1e9

        for i, test_case in enumerate(test_cases):
            user_input = test_case.get("input", "")
            input_filename = f"{sid}/input_{i}.txt"
            output_filename = f"{sid}/output_{i}.txt"
            
            # 写入测试输入
            with open(input_filename, "w", encoding="utf-8") as f:
                f.write(user_input)

            start_time = time.perf_counter_ns()
            start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

            # 运行程序
            run_cmd = ["timeout", f"{timeLim_sec}s", "./a.out"]
            run_res = subprocess.run(
                run_cmd,
                cwd=sid,
                capture_output=True,
                text=True,
                input=user_input,
                preexec_fn=set_run_limits(timeLim_sec, mle or 0)
            )

            end_time = time.perf_counter_ns()
            end_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

            exec_time = end_time - start_time  # ns
            mem_usage_byte = (end_mem - start_mem) * 1024  # Byte

            outp = read_output_with_fallback(output_filename, run_res.stdout or "")

            # 处理用户程序可能输出的图片文件
            # 如果用户程序输出了 output.png，立即重命名为 output_{i}.png 避免被覆盖
            original_image_path = f"{sid}/output.png"
            renamed_image_path = f"{sid}/output_{i}.png"
            has_output_image = False
            
            if os.path.exists(original_image_path):
                try:
                    # 重命名图片文件
                    subprocess.run(["mv", original_image_path, renamed_image_path], 
                                 capture_output=True, text=False)
                    has_output_image = True
                except Exception:
                    # 重命名失败，尝试复制
                    try:
                        subprocess.run(["cp", original_image_path, renamed_image_path], 
                                     capture_output=True, text=False)
                        has_output_image = True
                    except Exception:
                        pass

            status = "Accepted"
            exval = 0
            stderr = run_res.stderr or ""
            if len(stderr) > 300:
                stderr = stderr[:300] + "..."

            # 判定结果
            if exec_time > (tle or 0):
                status = "Time Limit Exceeded"
                exval = 9
            elif mem_usage_byte > (mle or 0):
                status = "Memory Limit Exceeded"
                exval = 10
            elif run_res.returncode != 0:
                status = "Runtime Error"
                exval = run_res.returncode

            # 检查输出图片
            files_dict = {"stdout": outp, "stderr": stderr}
            if has_output_image:
                files_dict[f"output_{i}.png"] = True

            test_results.append({
                "test_case_index": i,
                "status": status,
                "exitStatus": exval,
                "files": files_dict,
                "time": exec_time,
                "memory": mem_usage_byte,
            })

        return jsonify({
            "compile_result": {"status": "success", "stderr": ""},
            "test_results": test_results
        }), 200

    except Exception as e:
        return jsonify({"message": f"Failed to batch evaluate C: {str(e)}"}), 500

@app.route("/batch-evaluate-cpp", methods=["POST"])
def batch_evaluate_cpp():
    """
    C++语言批量评测接口：编译一次，运行多个测试点
    """
    data = request.get_json() or {}
    try:
        sid = sanitize_sid(data.get("sid", ""))
        code_content = data.get("code", "")
        test_cases = data.get("test_cases", [])
        tle = data.get("timeLimit")  # ns
        mle = (data.get("memoryLimit") or 0) * 10
        forbidden_funcs = data.get("forbidden", "")
        user_files = data.get("user_files", {})

        # 禁用函数检查
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            return jsonify({
                "compile_result": {"status": "forbidden", "stderr": forbid_msg},
                "test_results": []
            }), 200

        # 建目录 & 写文件
        ensure_dir(sid)
        code_filename = f"{sid}/main.cpp"
        bin_filename = f"{sid}/a.out"

        with open(code_filename, "w", encoding="utf-8") as f:
            f.write(code_content)
        
        # 写入用户的头文件
        if user_files:
            for filename, content in user_files.items():
                user_file_path = f"{sid}/{filename}"
                with open(user_file_path, "w", encoding="utf-8") as f:
                    f.write(content)

        # ===== 编译（只编译一次）=====
        compile_timeout_sec = 30
        compile_cmd = ["timeout", f"{compile_timeout_sec}s",
                       "g++", "-O2", "-pipe", "-s", "-lm", "-std=c++20"]
        
        if os.path.exists(LIBRARY_PATH):
            compile_cmd.extend(["-I", LIBRARY_PATH])
        
        compile_cmd.extend(["main.cpp", "-o", "a.out"])
        compile_res = subprocess.run(
            compile_cmd,
            cwd=sid,
            capture_output=True,
            text=True
        )
        
        if compile_res.returncode != 0:
            stderr = compile_res.stderr or ""
            if len(stderr) > 3000:
                stderr = stderr[:3000] + "..."
            return jsonify({
                "compile_result": {"status": "error", "stderr": stderr},
                "test_results": []
            }), 200

        # ===== 逐个运行测试点 =====
        test_results = []
        timeLim_sec = (tle or 0) * 1.2 / 1e9

        for i, test_case in enumerate(test_cases):
            user_input = test_case.get("input", "")
            input_filename = f"{sid}/input_{i}.txt"
            output_filename = f"{sid}/output_{i}.txt"
            
            # 写入测试输入
            with open(input_filename, "w", encoding="utf-8") as f:
                f.write(user_input)

            start_time = time.perf_counter_ns()
            start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

            # 运行程序
            run_cmd = ["timeout", f"{timeLim_sec}s", "./a.out"]
            run_res = subprocess.run(
                run_cmd,
                cwd=sid,
                capture_output=True,
                text=True,
                input=user_input,
                preexec_fn=set_run_limits(timeLim_sec, mle or 0)
            )

            end_time = time.perf_counter_ns()
            end_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

            exec_time = end_time - start_time  # ns
            mem_usage_byte = (end_mem - start_mem) * 1024  # Byte

            outp = read_output_with_fallback(output_filename, run_res.stdout or "")

            # 处理用户程序可能输出的图片文件
            # 如果用户程序输出了 output.png，立即重命名为 output_{i}.png 避免被覆盖
            original_image_path = f"{sid}/output.png"
            renamed_image_path = f"{sid}/output_{i}.png"
            has_output_image = False
            
            if os.path.exists(original_image_path):
                try:
                    # 重命名图片文件
                    subprocess.run(["mv", original_image_path, renamed_image_path], 
                                 capture_output=True, text=False)
                    has_output_image = True
                except Exception:
                    # 重命名失败，尝试复制
                    try:
                        subprocess.run(["cp", original_image_path, renamed_image_path], 
                                     capture_output=True, text=False)
                        has_output_image = True
                    except Exception:
                        pass

            status = "Accepted"
            exval = 0
            stderr = run_res.stderr or ""
            if len(stderr) > 300:
                stderr = stderr[:300] + "..."

            # 判定结果
            if exec_time > (tle or 0):
                status = "Time Limit Exceeded"
                exval = 9
            elif mem_usage_byte > (mle or 0):
                status = "Memory Limit Exceeded"
                exval = 10
            elif run_res.returncode != 0:
                status = "Runtime Error"
                exval = run_res.returncode

            # 检查输出图片
            files_dict = {"stdout": outp, "stderr": stderr}
            if has_output_image:
                files_dict[f"output_{i}.png"] = True

            test_results.append({
                "test_case_index": i,
                "status": status,
                "exitStatus": exval,
                "files": files_dict,
                "time": exec_time,
                "memory": mem_usage_byte,
            })

        return jsonify({
            "compile_result": {"status": "success", "stderr": ""},
            "test_results": test_results
        }), 200

    except Exception as e:
        return jsonify({"message": f"Failed to batch evaluate C++: {str(e)}"}), 500


if __name__ == "__main__":
    # 生产环境建议把 debug=False，并由反向代理/进程管理器托管
    app.run(host="0.0.0.0", port=5050, debug=True)
