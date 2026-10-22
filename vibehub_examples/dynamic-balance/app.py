"""动态平衡术教学作品：作品定义 C++ 接口、题目输入、轨迹核验与评分。"""

from __future__ import annotations

from http.server import SimpleHTTPRequestHandler
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import random
import socketserver
import stat
import threading
from urllib.parse import urlsplit

import cpp


ROOT = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 4 * 1024 * 1024


class _StarterSourceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.selected = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.selected = dict(attrs).get("id") == "starterSource"

    def handle_endtag(self, tag):
        if tag == "script":
            self.selected = False

    def handle_data(self, data):
        if self.selected:
            self.parts.append(data)


def _default_source():
    parser = _StarterSourceParser()
    parser.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
    source = "".join(parser.parts).strip()
    if not source:
        raise RuntimeError("页面缺少初始示例代码")
    return source + "\n"


DEFAULT_SOURCE = _default_source()
_MISSING = object()


def practice_inputs(context):
    generator = random.Random("practice:" + str(context.get("challenge_seed", "balance")))
    prefix = [7, 4, 10, -2, 6, 12, 15, 1]
    candidates = [value for value in range(-30, 31) if value not in prefix]
    return prefix + generator.sample(candidates, 16)


def hidden_inputs(context):
    generator = random.Random("grade:" + str(context.get("challenge_seed", "balance")))
    prefix = [999999999, 1000000000, -1000000000, -999999999,
              -999999998, -999999997, 0, 0, -1, 1]
    return prefix + [generator.randint(-10000, 10000) for _ in range(129 - len(prefix))]


def start(context):
    inputs = practice_inputs(context)
    state = {"source": DEFAULT_SOURCE, "inputs": inputs, "execution": None,
             "assignment_id": context.get("assignment_id")}
    return {"state": state, "view": {**state, "initial_source": DEFAULT_SOURCE}}


def action_source(action):
    if not isinstance(action, dict) or set(action) != {"type", "source"} or action["type"] != "run_code":
        raise ValueError("只接受 run_code/source 操作，不能传入执行结果或分数")
    source = action.get("source")
    if not isinstance(source, str) or not source.strip() or len(source.encode("utf-8")) > cpp.MAX_SOURCE_BYTES or "\x00" in source:
        raise ValueError("代码必须是 64 KiB 以内的非空文本")
    return source


def _resume(continuation, execution_result, operation, fields):
    if (not isinstance(continuation, dict) or set(continuation) != {"operation", *fields}
            or continuation.get("operation") != operation or execution_result is _MISSING):
        raise ValueError("执行续调数据无效")
    return continuation


def step(context, state, action, *, continuation=None, execution_result=_MISSING):
    if continuation is None and execution_result is _MISSING:
        source = action_source(action)
        inputs = list(state["inputs"])
        return {"execute": cpp.build_request(source, inputs),
                "continuation": {"operation": "step", "source": source, "inputs": inputs}}
    saved = _resume(continuation, execution_result, "step", {"source", "inputs"})
    source = action_source({"type": "run_code", "source": saved["source"]})
    inputs = saved["inputs"]
    execution = cpp.finish_execution(execution_result, inputs)
    new_state = {"source": source, "inputs": list(inputs), "execution": execution,
                 "assignment_id": context.get("assignment_id")}
    return {"state": new_state, "view": {**new_state, "initial_source": DEFAULT_SOURCE}}


def grade(context, actions, *, continuation=None, execution_result=_MISSING):
    inputs = hidden_inputs(context)
    if continuation is None and execution_result is _MISSING:
        if not isinstance(actions, list) or not actions:
            raise ValueError("提交快照中没有 C++ 代码")
        sources = [action_source(item.get("action")) for item in actions if isinstance(item, dict)]
        if len(sources) != len(actions):
            raise ValueError("提交快照的操作格式无效")
        source = sources[-1]
        return {"execute": cpp.build_request(source, inputs),
                "continuation": {"operation": "grade", "source": source}}
    saved = _resume(continuation, execution_result, "grade", {"source"})
    action_source({"type": "run_code", "source": saved["source"]})
    execution = cpp.finish_execution(execution_result, inputs)
    total, passed = execution["total"], execution["passed"]
    # 只按正确返回中位数的连续前缀计分；堆大小和元素分配不参与评分。
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
            else "隐藏测试未能完成，请在试运行中检查代码。"
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
            resumed = {}
            if "continuation" in payload or "execution_result" in payload:
                if not {"continuation", "execution_result"} <= payload.keys():
                    raise ValueError("执行续调数据无效")
                resumed = {"continuation": payload["continuation"], "execution_result": payload["execution_result"]}
            path = urlsplit(self.path).path
            if path == "/v1/start":
                if resumed:
                    raise ValueError("启动不接受执行续调")
                response = start(context)
            elif path == "/v1/step":
                response = step(context, payload.get("state") or {}, payload.get("action") or {}, **resumed)
            elif path == "/v1/grade":
                response = grade(context, payload.get("actions") or [], **resumed)
            else:
                self.send_error(404)
                return
            status = 200
        except (ValueError, KeyError, TypeError) as exc:
            response, status = {"error": str(exc)}, 400
        except RuntimeError:
            response, status = {"error": "执行资源暂时不可用，请稍后重试"}, 503
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


def protect_data_directory(path=Path("/data")):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise PermissionError("持久数据目录必须是作品服务拥有的真实目录")
    path.chmod(0o700)


def serve():
    protect_data_directory()
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
