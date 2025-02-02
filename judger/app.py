import re
from flask import Flask, request, jsonify
import subprocess
import time
import resource
import os

app = Flask(__name__)

ALLOWED_IPS = [
    "127.0.0.1"
]

@app.before_request
def check_ip_whitelist():
    client_ip = request.remote_addr
    if client_ip not in ALLOWED_IPS:
        return jsonify({"message": f"Forbidden: IP {client_ip} not allowed"}), 403

@app.route("/run-hello", methods=["POST"])
def run_hello():
    data = request.get_json() or {}

    try:
        # --------------------------------------------------------
        # 2) 从用户 POST 的字段里获取 sid, input, code 和 forbidden
        # --------------------------------------------------------
        sid = data.get("sid", "")
        user_input = data.get("input", "")
        code_content = data.get("code", "")
        tle = data.get("timeLimit")
        mle = data.get("memoryLimit")
        forbidden_funcs = data.get("forbidden", "")

        if forbidden_funcs:
            forbidden_funcs = forbidden_funcs.split(",")  # 获取禁用的函数列表，按逗号分割
            forbidden_funcs = [func.strip() for func in forbidden_funcs]
            # --------------------------------------------------------
            # 3) 检查代码中是否包含禁用函数
            # --------------------------------------------------------
            for func in forbidden_funcs:
                # 正则表达式匹配函数调用，确保匹配函数名后面跟着 '('，前后允许有空格或符号
                pattern = r'[^a-zA-Z0-9_](' + re.escape(func) + r')\s*\('  # 匹配前面不是字母、数字或下划线的字符，并且后面跟 '('
                if re.search(pattern, code_content):
                    return jsonify({
                        "status": "Forbidden",
                        "exitStatus": 11, 
                        "files": {
                            "stdout": "Function '{func}' is not allowed",
                            "stderr": "Function '{func}' is not allowed"
                        },
                        "time": 0,
                        "memory": 0,
                    }), 200

        # --------------------------------------------------------
        # 继续处理代码的运行逻辑
        # --------------------------------------------------------
        input_filename = f"{sid}/input.txt"
        output_filename = f"{sid}/output.txt"
        code_filename = f"{sid}/a.m"
        code_content = code_content.replace("input.txt", input_filename)
        code_content = code_content.replace("output.txt", output_filename)
        timeLim = tle * 1.5 / 1000 / 1000 / 1000

        subprocess.run(
            ["mkdir", f"{sid}"],
            capture_output=False, 
            text=False
        )

        with open(input_filename, "w", encoding="utf-8") as f:
            f.write(user_input)

        with open(code_filename, "w", encoding="utf-8") as f:
            f.write(code_content)

        start_time = time.perf_counter_ns()
        start_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

        result = subprocess.run(
            ["timeout", f"{timeLim}s", "baltamatica", "-m", code_filename],
            capture_output=True, 
            text=True,
            input=user_input
        )

        end_time = time.perf_counter_ns()
        end_mem = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

        exec_time = end_time - start_time        # 纳秒
        mem_usage_byte = (end_mem - start_mem) * 1024       # Byte

        outp = ""
        try:
            with open(output_filename, "r", encoding="utf-8") as file:
                outp = file.read()
                subprocess.run(
                    ["rm", output_filename],
                    capture_output=False, 
                    text=False
                )
        except FileNotFoundError:
            outp = f"{output_filename} not found"

        status = "Accepted"
        exval = 0
        if exec_time > tle:
            status = "Time Limit Exceeded"
            exval = 9
        elif mem_usage_byte > mle:
            status = "Memory Limit Exceeded"
            exval = 10
        elif result.returncode != 0:
            status = "Nonzero Exit Status"
            exval = result.returncode
        return jsonify({
            "status": status,
            "exitStatus": exval, 
            "files": {
                "stdout": outp,
                "stderr": result.stderr
            },
            "time": exec_time,
            "memory": mem_usage_byte,
        }), 200

    except Exception as e:
        return jsonify({
            "message": f"Failed to run hello: {str(e)}"
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)