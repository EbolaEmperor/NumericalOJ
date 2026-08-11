"""围住小猫的独立 VibeHub 服务。"""

from __future__ import annotations

from http.server import SimpleHTTPRequestHandler
import json
import os
from pathlib import Path
import socketserver
import sqlite3
import unicodedata
from urllib.parse import parse_qs, urlsplit


APP_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = APP_ROOT / "static"
SOCKET_PATH = Path(os.environ.get("VIBEHUB_SOCKET", "/run/vibehub/app.sock"))
HEALTH_PATH = os.environ.get("VIBEHUB_HEALTH_PATH", "/healthz")
DATABASE_PATH = Path(
    os.environ.get("CIRCLE_CAT_DATABASE", "/data/circle-cat.sqlite3")
)
MAX_JSON_BYTES = 16 * 1024
MAX_TURN_COUNT = 121
DISPLAY_NAME_MAX_LENGTH = 24

_SCHEMA = """
CREATE TABLE IF NOT EXISTS circle_cat_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    turn_count INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_circle_cat_user_turn
    ON circle_cat_records (username, turn_count);
"""


def _connect_database():
    connection = sqlite3.connect(DATABASE_PATH, timeout=5, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def _initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = _connect_database()
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.executescript(_SCHEMA)
    finally:
        connection.close()


def _normalize_display_name(value):
    if not isinstance(value, str):
        return None
    name = unicodedata.normalize("NFC", value.strip())
    if (
        not 1 <= len(name) <= DISPLAY_NAME_MAX_LENGTH
        or any(unicodedata.category(char).startswith("C") for char in name)
    ):
        return None
    return name


def _parse_positive_int(value, default, minimum=1, maximum=200):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def get_circle_cat_leaderboard_page(limit=10, offset=0):
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    connection = _connect_database()
    try:
        rows = connection.execute(
            """
            SELECT username, MIN(turn_count) AS best_turns,
                   MIN(created_at) AS first_win_at
            FROM circle_cat_records
            GROUP BY username
            ORDER BY best_turns ASC, first_win_at ASC
            """
        ).fetchall()
    finally:
        connection.close()
    leaderboard = [
        {
            "username": row["username"],
            "best_turns": int(row["best_turns"]),
        }
        for row in rows
    ]
    return leaderboard[offset : offset + limit], len(leaderboard)


def _leaderboard_response(query):
    page = _parse_positive_int(
        query.get("page", [None])[0], default=1, maximum=1_000_000
    )
    limit = _parse_positive_int(
        query.get("limit", [None])[0], default=10, maximum=200
    )
    leaderboard, total = get_circle_cat_leaderboard_page(
        limit=limit, offset=(page - 1) * limit
    )
    return {
        "success": True,
        "leaderboard": leaderboard,
        "total": total,
        "page": page,
        "limit": limit,
    }


def _submit_result(data):
    username = _normalize_display_name(data.get("display_name"))
    turn_count = data.get("turn_count")
    if username is None:
        return {
            "success": False,
            "message": "用户名需为 1–24 个字符，且不能包含控制字符。",
        }, 400
    if (
        isinstance(turn_count, bool)
        or not isinstance(turn_count, int)
        or not 1 <= turn_count <= MAX_TURN_COUNT
    ):
        return {"success": False, "message": "回合数无效。"}, 400

    connection = _connect_database()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO circle_cat_records (username, turn_count)
            VALUES (?, ?)
            """,
            (username, turn_count),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        return {"success": False, "message": "成绩保存失败，请稍后重试。"}, 500
    finally:
        connection.close()

    return {"success": True}, 200


class Handler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".woff2": "font/woff2",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def _send_json(self, payload, status=200):
        body = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = -1
        if length < 0:
            self._send_json({"success": False, "message": "请求体长度无效。"}, 400)
            return None
        if length > MAX_JSON_BYTES:
            self._send_json({"success": False, "message": "请求体过大。"}, 413)
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            data = {}
        return data if isinstance(data, dict) else {}

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == HEALTH_PATH:
            self._send_json({"status": "ok"})
            return
        if parsed.path == "/leaderboard":
            self._send_json(_leaderboard_response(parse_qs(parsed.query)))
            return
        if parsed.path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        parsed = urlsplit(self.path)
        data = self._read_json()
        if data is None:
            return
        if parsed.path == "/result":
            payload, status = _submit_result(data)
            self._send_json(payload, status)
            return
        self._send_json({"success": False, "message": "接口不存在。"}, 404)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, _format, *_args):
        return


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    _initialize_database()
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
    try:
        os.chmod(SOCKET_PATH, 0o600)
    except OSError:
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
