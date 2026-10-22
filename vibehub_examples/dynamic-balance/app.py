"""动态平衡术教学作品。平台在既有作品容器执行 C++，后端独立核验轨迹。"""

from __future__ import annotations

from http.server import SimpleHTTPRequestHandler
import json
import os
from pathlib import Path
import random
import socketserver
import threading
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 4 * 1024 * 1024
DEFAULT_SOURCE = """// A 是大顶堆，B 是小顶堆。两棵堆在各次 step 调用之间保留。
// 可调用 insert(int)、pop()、top()、size()。
int step(int x) {
    // TODO：插入 x，调整两个堆，再返回当前的较小中位数。
    A.insert(x);
    return A.top();
}
"""


def start(context):
    parameters = context.get("parameters") or {}
    inputs = parameters.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        generator = random.Random(str(context.get("challenge_seed", "balance")))
        inputs = [generator.randrange(-20, 100) for _ in range(20)]
    state = {"source": DEFAULT_SOURCE, "inputs": inputs, "execution": None,
             "assignment_id": context.get("assignment_id")}
    return {"state": state, "view": {**state, "initial_source": DEFAULT_SOURCE}}


def step(context, state, action):
    if action.get("type") != "run_code":
        raise ValueError("只支持试运行 C++ 代码")
    source = action.get("source")
    if not isinstance(source, str) or len(source.encode("utf-8")) > 64 * 1024:
        raise ValueError("代码必须是 64 KiB 以内的文本")
    execution = context.get("execution")
    if not isinstance(execution, dict):
        raise ValueError("平台没有提供可信的 C++ 执行结果")
    new_state = {"source": source, "inputs": list(state["inputs"]), "execution": execution,
                 "assignment_id": context.get("assignment_id")}
    return {"state": new_state, "view": {**new_state, "initial_source": DEFAULT_SOURCE}}


def grade(context, actions):
    # execution 由平台从冻结的最后一份源码重新执行隐藏测试得到。
    source = next((item.get("action", {}).get("source") for item in reversed(actions)
                   if item.get("action", {}).get("type") == "run_code"), None)
    if not isinstance(source, str) or not source.strip():
        raise ValueError("提交快照中没有 C++ 代码")
    execution = context.get("execution") or {}
    total = execution.get("total", 0)
    passed = execution.get("passed", 0)
    if type(total) is not int or type(passed) is not int or not 0 <= passed <= total or total <= 0:
        raise ValueError("平台评分结果无效")
    compiled = execution.get("compiled") is True
    score = 10000 * passed // total if compiled else 0
    # 隐藏测试的输入、堆状态与源码均不放进成绩反馈。
    return {
        "verdict": "passed" if compiled and passed == total else "failed",
        "score_bp": score,
        "metrics": {"passed_rounds": passed, "total_rounds": total},
        "feedback": (
            f"隐藏测试通过 {passed}/{total} 轮。"
            if compiled and not execution.get("error")
            else "隐藏测试未能完成：" + str(execution.get("error", "编译失败"))[:3000]
        ),
    }


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / "static"), **kwargs)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if path.startswith("/v1/") or path.startswith("/_edu/"):
            self.send_error(404)
            return
        super().do_GET()

    def log_message(self, *_args):
        pass


class EducationHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_REQUEST_BYTES:
                raise ValueError("请求体大小无效")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("请求必须是 JSON 对象")
            context = payload.get("context") or {}
            if not isinstance(context, dict):
                raise ValueError("作答上下文无效")
            path = urlsplit(self.path).path
            if path == "/v1/start":
                response = start(context)
            elif path == "/v1/step":
                response = step(context, payload.get("state") or {}, payload.get("action") or {})
            elif path == "/v1/grade":
                response = grade(context, payload.get("actions") or [])
            else:
                self.send_error(404)
                return
            status = 200
        except (ValueError, KeyError, TypeError) as exc:
            response, status = {"error": str(exc)}, 400
        body = json.dumps(response, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_error(404)

    def log_message(self, *_args):
        pass


def serve():
    app_socket = Path(os.environ.get("VIBEHUB_SOCKET", "/run/vibehub/app.sock"))
    edu_socket = Path(os.environ.get("VIBEHUB_EDU_SOCKET", "/run/vibehub/edu.sock"))
    servers = []
    for socket_path, handler in ((app_socket, AppHandler), (edu_socket, EducationHandler)):
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        socket_path.unlink(missing_ok=True)
        server = UnixHTTPServer(str(socket_path), handler)
        socket_path.chmod(0o666)
        servers.append(server)
    thread = threading.Thread(target=servers[1].serve_forever, daemon=True)
    thread.start()
    try:
        servers[0].serve_forever()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    serve()
