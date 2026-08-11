"""只使用 Python 标准库的 VibeHub Unix Socket 静态服务。"""

from __future__ import annotations

from http.server import SimpleHTTPRequestHandler
import os
from pathlib import Path
import socketserver


APP_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = APP_ROOT / "static"
SOCKET_PATH = Path(os.environ.get("VIBEHUB_SOCKET", "/run/vibehub/app.sock"))
HEALTH_PATH = os.environ.get("VIBEHUB_HEALTH_PATH", "/healthz")


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def do_GET(self):
        if self.path.split("?", 1)[0] == HEALTH_PATH:
            payload = b'{"status":"ok"}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.split("?", 1)[0] == "/":
            self.path = "/index.html"
        super().do_GET()

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, _format, *_args):
        return


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass
    previous_umask = os.umask(0)
    try:
        server = UnixHTTPServer(str(SOCKET_PATH), Handler)
    finally:
        os.umask(previous_umask)
    # 应用与受信 relay 都以 UID 65532 在同一容器内运行；socket 不需要向
    # 其它 UID 开放，也不会挂载到宿主。
    try:
        os.chmod(SOCKET_PATH, 0o600)
    except OSError:
        # bind 时的 umask(0) 已保证当前容器 UID 可以继续连接。
        pass
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        try:
            SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
