"""ARC-AGI-3 的完整离线 VibeHub 服务。

官方环境源码只在受限作品容器中加载；部署宿主仅做字节、许可与哈希校验。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http.server import SimpleHTTPRequestHandler
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import sys
import threading
import time
from urllib.parse import unquote, urlsplit


APP_ROOT = Path(__file__).resolve().parent
VENDOR_ROOT = APP_ROOT / "vendor"
if VENDOR_ROOT.is_dir():
    sys.path.insert(0, str(VENDOR_ROOT))

from arcengine import ARCBaseGame, ActionInput, FrameDataRaw, GameAction  # noqa: E402
import numpy as np  # noqa: E402


STATIC_ROOT = APP_ROOT / "static"
SOCKET_PATH = Path(os.environ.get("VIBEHUB_SOCKET", "/run/vibehub/app.sock"))
HEALTH_PATH = os.environ.get("VIBEHUB_HEALTH_PATH", "/healthz")
ARC_DATA_ROOT = APP_ROOT / "offline_data"
SLUG_RE = re.compile(r"^[a-z0-9]{4}$")
VERSION_RE = re.compile(r"^[0-9a-f]{8}$")
SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_FRAMES = 180
SESSION_TTL_SECONDS = 45 * 60
MAX_ACTIVE_SESSIONS = 160


class ArcAppError(RuntimeError):
    pass


@dataclass
class ActiveSession:
    token: str
    game_spec: dict
    game: ARCBaseGame
    available_actions: tuple[int, ...]
    updated_at: float
    action_count: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


_catalog_cache = None
_class_cache = {}
_class_cache_lock = threading.Lock()
_sessions = {}
_sessions_lock = threading.RLock()


def load_catalog():
    global _catalog_cache
    if _catalog_cache is not None:
        return _catalog_cache
    manifest_path = ARC_DATA_ROOT / "manifest.json"
    try:
        if manifest_path.stat().st_size > 2 * 1024 * 1024:
            raise ArcAppError("离线清单过大")
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArcAppError("离线清单无法读取") from exc
    raw_games = payload.get("games")
    if payload.get("schema_version") != 1 or not isinstance(raw_games, list):
        raise ArcAppError("离线清单格式无效")
    games = []
    seen = set()
    for item in raw_games:
        if not isinstance(item, dict):
            raise ArcAppError("离线游戏条目无效")
        slug = str(item.get("slug") or "")
        version = str(item.get("version") or "")
        if not SLUG_RE.fullmatch(slug) or not VERSION_RE.fullmatch(version) or slug in seen:
            raise ArcAppError("离线游戏标识无效")
        seen.add(slug)
        source_path = ARC_DATA_ROOT / "environments" / slug / version / f"{slug}.py"
        preview_path = ARC_DATA_ROOT / "previews" / f"{slug}.png"
        if not source_path.is_file() or not preview_path.is_file():
            raise ArcAppError("离线游戏文件不完整")
        games.append({
            "slug": slug,
            "version": version,
            "full_id": f"{slug}-{version}",
            "title": str(item.get("title") or slug)[:80],
            "default_fps": max(1, min(int(item.get("default_fps") or 10), 30)),
            "level_count": max(1, int(item.get("level_count") or 1)),
            "input_label": str(item.get("input_label") or "探索")[:80],
            "source_path": source_path,
            "preview_url": f"./preview/{slug}.png",
        })
    if len(games) != 25:
        raise ArcAppError("离线公开集必须恰好包含 25 个环境")
    _catalog_cache = tuple(games)
    return _catalog_cache


def public_game(spec):
    return {
        key: value
        for key, value in spec.items()
        if key not in {"source_path", "version"}
    }


def find_game(slug):
    return next((game for game in load_catalog() if game["slug"] == slug), None)


def load_game_class(spec):
    full_id = spec["full_id"]
    cached = _class_cache.get(full_id)
    if cached is not None:
        return cached
    with _class_cache_lock:
        cached = _class_cache.get(full_id)
        if cached is not None:
            return cached
        module_spec = importlib.util.spec_from_file_location(
            f"vibehub_arc_{spec['slug']}_{spec['version']}", spec["source_path"],
        )
        if module_spec is None or module_spec.loader is None:
            raise ArcAppError("游戏模块无法加载")
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        class_name = spec["slug"][0].upper() + spec["slug"][1:]
        game_class = getattr(module, class_name, None)
        if not isinstance(game_class, type) or not issubclass(game_class, ARCBaseGame):
            raise ArcAppError("游戏模块格式无效")
        _class_cache[full_id] = game_class
        return game_class


def new_game(spec):
    game_class = load_game_class(spec)
    signature = inspect.signature(game_class)
    kwargs = {"seed": 0} if "seed" in signature.parameters else {}
    return game_class(**kwargs)


def serialize_frame_data(frame_data, session):
    if not isinstance(frame_data, FrameDataRaw) or not frame_data.frame:
        raise ArcAppError("游戏没有返回有效画面")
    frames = frame_data.frame
    if len(frames) > MAX_RESPONSE_FRAMES:
        last = len(frames) - 1
        indices = sorted({
            round(index * last / (MAX_RESPONSE_FRAMES - 1))
            for index in range(MAX_RESPONSE_FRAMES)
        })
        selected = [frames[index] for index in indices]
    else:
        selected = frames
    output_frames = []
    for raw_frame in selected:
        frame = np.asarray(raw_frame)
        if (
            frame.ndim != 2
            or frame.size == 0
            or frame.shape[0] > 64
            or frame.shape[1] > 64
            or int(frame.min()) < 0
            or int(frame.max()) > 15
        ):
            raise ArcAppError("游戏返回的像素画面无效")
        output_frames.append(frame.astype(np.int16, copy=False).tolist())
    return {
        "game_id": session.game_spec["slug"],
        "state": frame_data.state.value,
        "levels_completed": int(frame_data.levels_completed),
        "win_levels": int(frame_data.win_levels),
        "available_actions": [int(action) for action in frame_data.available_actions],
        "frames": output_frames,
        "skipped_frames": max(0, len(frames) - len(selected)),
        "action_count": session.action_count,
        "default_fps": session.game_spec["default_fps"],
    }


def prune_sessions(now):
    with _sessions_lock:
        expired = [
            token for token, session in _sessions.items()
            if now - session.updated_at > SESSION_TTL_SECONDS
        ]
        for token in expired:
            _sessions.pop(token, None)
        overflow = len(_sessions) - MAX_ACTIVE_SESSIONS
        if overflow > 0:
            oldest = sorted(_sessions.values(), key=lambda session: session.updated_at)
            for session in oldest[:overflow]:
                _sessions.pop(session.token, None)


def start_game(slug):
    spec = find_game(slug)
    if spec is None:
        raise ArcAppError("游戏不存在")
    game = new_game(spec)
    frame_data = game.perform_action(ActionInput(id=GameAction.RESET), raw=True)
    now = time.monotonic()
    session = ActiveSession(
        token=secrets.token_urlsafe(24),
        game_spec=spec,
        game=game,
        available_actions=tuple(int(action) for action in frame_data.available_actions),
        updated_at=now,
    )
    prune_sessions(now)
    with _sessions_lock:
        _sessions[session.token] = session
    return session, serialize_frame_data(frame_data, session)


def perform_action(token, action_id, action_data):
    prune_sessions(time.monotonic())
    with _sessions_lock:
        session = _sessions.get(token)
    if session is None:
        raise ArcAppError("对局已失效，请重新开始")
    if not session.lock.acquire(blocking=False):
        raise ArcAppError("上一个操作仍在处理中")
    try:
        try:
            parsed_id = int(action_id)
            action = GameAction.from_id(parsed_id)
        except (TypeError, ValueError) as exc:
            raise ArcAppError("无效操作") from exc
        if parsed_id != GameAction.RESET.value and parsed_id not in session.available_actions:
            raise ArcAppError("当前游戏不支持这个操作")
        data = {}
        if action.is_complex():
            try:
                x = int((action_data or {}).get("x"))
                y = int((action_data or {}).get("y"))
            except (TypeError, ValueError) as exc:
                raise ArcAppError("点击坐标无效") from exc
            if not (0 <= x <= 63 and 0 <= y <= 63):
                raise ArcAppError("点击坐标超出棋盘")
            data = {"x": x, "y": y}
        frame_data = session.game.perform_action(
            ActionInput(id=action, data=data), raw=True,
        )
        if action != GameAction.RESET:
            session.action_count += 1
        session.available_actions = tuple(
            int(available) for available in frame_data.available_actions
        )
        session.updated_at = time.monotonic()
        return serialize_frame_data(frame_data, session)
    finally:
        session.lock.release()


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def _json(self, payload, status=200):
        data = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError as exc:
            raise ArcAppError("请求长度无效") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ArcAppError("请求体过大")
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ArcAppError("请求 JSON 无效") from exc
        if not isinstance(payload, dict):
            raise ArcAppError("请求 JSON 必须是对象")
        return payload

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == HEALTH_PATH:
            try:
                count = len(load_catalog())
            except ArcAppError:
                self._json({"status": "error"}, 503)
                return
            self._json({"status": "ok", "games": count})
            return
        if path == "/api/catalog":
            try:
                games = [public_game(game) for game in load_catalog()]
            except ArcAppError as exc:
                self._json({"success": False, "message": str(exc)}, 503)
                return
            self._json({"success": True, "games": games})
            return
        if path.startswith("/preview/"):
            filename = unquote(path.removeprefix("/preview/"))
            slug = filename.removesuffix(".png")
            if filename != f"{slug}.png" or not SLUG_RE.fullmatch(slug):
                self.send_error(404)
                return
            target = ARC_DATA_ROOT / "previews" / filename
            try:
                data = target.read_bytes()
            except OSError:
                self.send_error(404)
                return
            if len(data) > 2 * 1024 * 1024 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        path = urlsplit(self.path).path
        start_match = re.fullmatch(r"/api/games/([a-z0-9]{4})/start", path)
        action_match = re.fullmatch(r"/api/sessions/([A-Za-z0-9_-]{20,64})/action", path)
        try:
            payload = self._read_json()
            if start_match:
                session, game = start_game(start_match.group(1))
                self._json({"success": True, "session_id": session.token, "game": game})
                return
            if action_match and SESSION_RE.fullmatch(action_match.group(1)):
                game = perform_action(
                    action_match.group(1), payload.get("action_id"), payload.get("data"),
                )
                self._json({"success": True, "game": game})
                return
        except ArcAppError as exc:
            self._json({"success": False, "message": str(exc)}, 400)
            return
        except Exception:
            self._json({"success": False, "message": "环境执行失败，请重新开始"}, 500)
            return
        self._json({"success": False, "message": "接口不存在"}, 404)

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
    SOCKET_PATH.unlink(missing_ok=True)
    previous_umask = os.umask(0)
    try:
        server = UnixHTTPServer(str(SOCKET_PATH), Handler)
    finally:
        os.umask(previous_umask)
    try:
        # 应用与受信 relay 同为 UID 65532；UDS 只存在于容器 tmpfs。
        os.chmod(SOCKET_PATH, 0o600)
    except OSError:
        pass
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        SOCKET_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
