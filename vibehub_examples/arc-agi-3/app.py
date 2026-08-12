"""ARC-AGI-3 的完整本地数据 VibeHub 服务。

官方环境源码只在受限作品容器中加载；部署宿主仅做字节、许可与哈希校验。
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from functools import cache
import gzip
from http.server import SimpleHTTPRequestHandler
import html
import importlib.util
import inspect
from io import BytesIO
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import sys
import threading
from urllib.parse import unquote, urlsplit


APP_ROOT = Path(__file__).resolve().parent
VENDOR_ROOT = APP_ROOT / "vendor"
if VENDOR_ROOT.is_dir():
    sys.path.insert(0, str(VENDOR_ROOT))

from arcengine import ARCBaseGame, ActionInput, FrameDataRaw, GameAction  # noqa: E402
import numpy as np  # noqa: E402
from PIL import Image  # noqa: E402


STATIC_ROOT = APP_ROOT / "static"
PRECOMPUTED_ROOT = APP_ROOT / ".precomputed"
SOCKET_PATH = Path(os.environ.get("VIBEHUB_SOCKET", "/run/vibehub/app.sock"))
HEALTH_PATH = os.environ.get("VIBEHUB_HEALTH_PATH", "/healthz")
ARC_DATA_ROOT = APP_ROOT / "offline_data"
SLUG_RE = re.compile(r"^[a-z0-9]{4}$")
VERSION_RE = re.compile(r"^[0-9a-f]{8}$")
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_FRAMES = 180
MAX_ACTIVE_SESSIONS = 160
PALETTE = np.asarray(
    [
        (255, 255, 255), (204, 204, 204), (153, 153, 153), (102, 102, 102),
        (51, 51, 51), (0, 0, 0), (229, 58, 163), (255, 123, 204),
        (249, 60, 49), (30, 147, 255), (136, 216, 241), (255, 220, 0),
        (255, 133, 27), (146, 18, 49), (79, 204, 48), (163, 86, 214),
    ],
    dtype=np.uint8,
)


class ArcAppError(RuntimeError):
    def __init__(self, message, status=500):
        super().__init__(message)
        self.status = status


@dataclass
class ActiveSession:
    token: str
    game_spec: dict
    game: ARCBaseGame
    available_actions: tuple[int, ...]
    action_count: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


_catalog_cache = None
_class_cache = {}
_sessions = {}
_sessions_lock = threading.Lock()
_reset_cache = {}

_INLINE_STYLESHEETS = frozenset({
    "vendor/bootstrap/bootstrap.min.css",
    "vendor/fontawesome/css/all.min.css",
    "vendor/model-family/model-family-logos.css",
    "arc-agi-3.css",
})
_INLINE_SCRIPTS = frozenset({
    "vendor/bootstrap/bootstrap.bundle.min.js",
    "arc-agi-3-catalog.js",
    "arc-agi-3.js",
})
_STYLESHEET_TAG_RE = re.compile(
    r'<link rel="stylesheet" href="(?P<path>(?:\./|\.\./)[^"]+)">'
)
_SCRIPT_TAG_RE = re.compile(
    r'<script src="(?P<path>(?:\./|\.\./)[^"]+)"></script>'
)


@cache
def _precomputed_text(relative_path):
    try:
        return (PRECOMPUTED_ROOT / relative_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


@cache
def _precomputed_bytes(relative_path):
    try:
        return (PRECOMPUTED_ROOT / relative_path).read_bytes()
    except FileNotFoundError:
        return None


def _accepts_gzip(value):
    qualities = {}
    for item in str(value or "").split(","):
        coding, *parameters = item.split(";")
        coding = coding.strip().lower()
        if not coding:
            continue
        quality = 1.0
        for parameter in parameters:
            name, separator, raw_value = parameter.partition("=")
            if separator and name.strip().lower() == "q":
                try:
                    quality = float(raw_value.strip())
                except ValueError:
                    quality = 0.0
        qualities[coding] = quality
    return qualities.get("gzip", qualities.get("*", 0.0)) > 0


def load_catalog():
    global _catalog_cache
    if _catalog_cache is not None:
        return _catalog_cache
    try:
        payload = json.loads(
            (ARC_DATA_ROOT / "manifest.json").read_text(encoding="utf-8")
        )
        items = payload["games"]
        if payload.get("schema_version") != 1 or len(items) != 25:
            raise ValueError
        games, seen = [], set()
        for item in items:
            slug, version, title = item["slug"], item["version"], item["title"]
            fps, levels = item["default_fps"], item["level_count"]
            source = ARC_DATA_ROOT / "environments" / slug / version / f"{slug}.py"
            if (
                not isinstance(title, str) or not title or len(title) > 80
                or type(fps) is not int or not 1 <= fps <= 240
                or type(levels) is not int or levels < 1
                or not SLUG_RE.fullmatch(slug) or not VERSION_RE.fullmatch(version)
                or slug in seen or not source.is_file()
            ):
                raise ValueError
            seen.add(slug)
            games.append({
                "slug": slug, "version": version, "full_id": f"{slug}-{version}",
                "title": title, "default_fps": fps, "level_count": levels,
                "source_path": source,
            })
    except (KeyError, TypeError, ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArcAppError("离线清单无效") from exc
    _catalog_cache = tuple(games)
    return _catalog_cache


def find_game(slug):
    return next((game for game in load_catalog() if game["slug"] == slug), None)


def _template(name):
    return (STATIC_ROOT / name).read_text(encoding="utf-8")


def _static_asset_name(relative_url):
    name = relative_url
    while name.startswith("../"):
        name = name[3:]
    return name.removeprefix("./")


@cache
def _data_uri(name, content_type):
    encoded = base64.b64encode((STATIC_ROOT / name).read_bytes()).decode("ascii")
    return f"data:{content_type};base64,{encoded}"


def _inline_fontawesome_fonts(stylesheet):
    """只保留当前页面使用的 Font Awesome 6 字体，并嵌入响应。"""

    solid = _data_uri(
        "vendor/fontawesome/webfonts/fa-solid-900.woff2", "font/woff2",
    )
    brands = _data_uri(
        "vendor/fontawesome/webfonts/fa-brands-400.woff2", "font/woff2",
    )

    def replace_font_face(match):
        rule = match.group(0)
        if 'font-family:"Font Awesome 6 Brands"' in rule:
            source = brands
        elif (
            'font-family:"Font Awesome 6 Free"' in rule
            and "font-weight:900" in rule
        ):
            source = solid
        else:
            return ""
        return re.sub(
            r"src:[^}]+",
            f'src:url("{source}") format("woff2")',
            rule,
            count=1,
        )

    return re.sub(r"@font-face\{[^{}]*\}", replace_font_face, stylesheet)


@cache
def _inline_stylesheet(name):
    stylesheet = (STATIC_ROOT / name).read_text(encoding="utf-8")
    if name == "vendor/fontawesome/css/all.min.css":
        stylesheet = _inline_fontawesome_fonts(stylesheet)
    elif name == "vendor/model-family/model-family-logos.css":
        for family in ("openai", "claude"):
            source = f"model-family-logos/{family}.svg"
            stylesheet = stylesheet.replace(
                f'url("{source}")',
                f'url("{_data_uri(f"vendor/model-family/{source}", "image/svg+xml")}")',
            )
    if "</style" in stylesheet.lower():
        raise ArcAppError("内联样式包含无效结束标签")
    return stylesheet


@cache
def _inline_script(name):
    javascript = (STATIC_ROOT / name).read_text(encoding="utf-8")
    if "</script" in javascript.lower():
        raise ArcAppError("内联脚本包含无效结束标签")
    return javascript


def _inline_frontend_assets(content):
    """消除沙箱页面首屏对额外 CSS、JS 和字体请求的依赖。"""

    def replace_stylesheet(match):
        name = _static_asset_name(match.group("path"))
        if name not in _INLINE_STYLESHEETS:
            raise ArcAppError("页面引用了未登记的样式资源")
        return (
            f'<style data-vibehub-inline-asset="{html.escape(name, quote=True)}">\n'
            f"{_inline_stylesheet(name)}\n"
            "</style>"
        )

    def replace_script(match):
        name = _static_asset_name(match.group("path"))
        if name not in _INLINE_SCRIPTS:
            raise ArcAppError("页面引用了未登记的脚本资源")
        return (
            f'<script data-vibehub-inline-asset="{html.escape(name, quote=True)}">\n'
            f"{_inline_script(name)}\n"
            "</script>"
        )

    content = _STYLESHEET_TAG_RE.sub(replace_stylesheet, content)
    return _SCRIPT_TAG_RE.sub(replace_script, content)


def _catalog_pages(games):
    pages = []
    for page_index in range(0, len(games), 15):
        page_number = page_index // 15
        active = page_number == 0
        lines = [
            "      <section",
            '        class="arc-catalog-page{}"'.format(" is-active" if active else ""),
            f'        data-arc-page-index="{page_number}"',
            f'        aria-label="公开游戏第 {page_number + 1} 组"',
            f'        aria-hidden="{"false" if active else "true"}"',
        ]
        if not active:
            lines.append("        inert")
        lines.append("      >")
        for offset, game in enumerate(games[page_index:page_index + 15], start=1):
            game_number = page_index + offset
            slug = game["slug"]
            title = html.escape(game["title"])
            input_label = html.escape(game["input_label"])
            # Safari/WebKit 在沙箱 iframe 内可能永远不会触发懒加载图片。
            lines.extend([
                "        <a",
                f'          class="arc-game-card arc-accent-{(game_number - 1) % 4}"',
                f'          href="./game/{slug}"',
                "        >",
                f'          <span class="arc-card-number">{game_number:02d}</span>',
                '          <div class="arc-card-preview">',
                f'            <img src="./preview/{slug}.png" alt="{title} 初始画面预览">',
                '            <span class="arc-card-play" aria-hidden="true">',
                '              <i class="fas fa-arrow-right"></i>',
                "            </span>",
                "          </div>",
                '          <div class="arc-card-copy">',
                f"            <h2>{title}</h2>",
                f"            <p>{int(game['level_count'])} 个关卡</p>",
                f"            <span>{input_label}</span>",
                "          </div>",
                "        </a>",
            ])
        lines.append("      </section>")
        pages.append("\n".join(lines))
    return "\n".join(pages)


def _input_label(actions):
    direction = bool(actions & {1, 2, 3, 4})
    if 6 in actions:
        return "方向键 + 点击" if direction else (
            "操作键 + 点击" if 5 in actions else "点击"
        )
    return "方向键" if direction else ("操作键" if 5 in actions else "键盘")


def _runtime_game(game):
    reset = _reset_snapshot(game)
    return {**game, "input_label": reset["input_label"]}


def _render_index_live():
    games = tuple(_runtime_game(game) for game in load_catalog())
    content = (
        _template("index.html")
        .replace("__TOTAL_GAMES__", str(len(games)))
        .replace("__FIRST_PAGE_END__", str(min(15, len(games))))
        .replace("      <!-- ARC_CATALOG_PAGES -->", _catalog_pages(games))
    )
    return _inline_frontend_assets(content)


def render_index():
    return _precomputed_text("index.html") or _render_index_live()


def _render_game_live(game):
    game = _runtime_game(game)
    values = {
        "__GAME_TITLE__": html.escape(game["title"]),
        "__GAME_SLUG__": game["slug"],
        "__GAME_FULL_ID__": game["full_id"],
        "__GAME_LEVEL_COUNT__": str(int(game["level_count"])),
        "__GAME_INPUT_LABEL__": html.escape(game["input_label"]),
        "__CATALOG_URL__": "../",
        "__START_URL__": f"../api/games/{game['slug']}/start",
        "__ACTION_URL_TEMPLATE__": "../api/sessions/SESSION_ID/action",
    }
    output = _template("game.html")
    for token, value in values.items():
        output = output.replace(token, value)
    return _inline_frontend_assets(output)


def render_game(game):
    return (
        _precomputed_text(f"games/{game['slug']}.html")
        or _render_game_live(game)
    )


def _render_not_found_live():
    content = _template("not-found.html").replace("__CATALOG_URL__", "../")
    return _inline_frontend_assets(content)


def render_not_found():
    return _precomputed_text("not-found.html") or _render_not_found_live()


def precompute_frontend_assets():
    """在镜像构建期完成目录页所需的 25 个环境初始化。"""

    games = tuple(load_catalog())
    games_root = PRECOMPUTED_ROOT / "games"
    previews_root = PRECOMPUTED_ROOT / "previews"
    games_root.mkdir(parents=True, exist_ok=True)
    previews_root.mkdir(parents=True, exist_ok=True)
    (PRECOMPUTED_ROOT / "index.html").write_text(
        _render_index_live(), encoding="utf-8",
    )
    (PRECOMPUTED_ROOT / "not-found.html").write_text(
        _render_not_found_live(), encoding="utf-8",
    )
    for game in games:
        slug = game["slug"]
        (games_root / f"{slug}.html").write_text(
            _render_game_live(game), encoding="utf-8",
        )
        (previews_root / f"{slug}.png").write_bytes(
            _reset_snapshot(game)["preview"],
        )


def load_game_class(spec):
    full_id = spec["full_id"]
    cached = _class_cache.get(full_id)
    if cached is not None:
        return cached
    module_spec = importlib.util.spec_from_file_location(
        f"vibehub_arc_{full_id}", spec["source_path"],
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
    return game_class(seed=0) if "seed" in inspect.signature(game_class).parameters else game_class()


def _validated_frame(raw_frame):
    frame = np.asarray(raw_frame)
    if (
        frame.ndim != 2
        or frame.size == 0
        or frame.shape[0] > 64
        or frame.shape[1] > 64
        or int(frame.min()) < 0
        or int(frame.max()) >= len(PALETTE)
    ):
        raise ArcAppError("游戏返回的像素画面无效")
    return frame.astype(np.uint8, copy=False)


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
    encoded_frames = []
    for raw_frame in selected:
        frame = _validated_frame(raw_frame)
        height, width = frame.shape
        encoded_frames.append([
            int(width),
            int(height),
            base64.b64encode(frame.tobytes(order="C")).decode("ascii"),
        ])
    return {
        "game_id": session.game_spec["slug"],
        "state": frame_data.state.value,
        "levels_completed": int(frame_data.levels_completed),
        "win_levels": int(frame_data.win_levels),
        "available_actions": [int(action) for action in frame_data.available_actions],
        "frames": encoded_frames,
        "skipped_frames": max(0, len(frames) - len(selected)),
        "action_count": session.action_count,
        "default_fps": session.game_spec["default_fps"],
    }


def _reset_snapshot(spec):
    full_id = spec["full_id"]
    cached = _reset_cache.get(full_id)
    if cached is not None:
        return cached
    try:
        frame_data = new_game(spec).perform_action(
            ActionInput(id=GameAction.RESET), raw=True,
        )
        actions = {int(action) for action in frame_data.available_actions}
    except Exception as exc:
        raise ArcAppError("游戏初始状态生成失败") from exc
    if (
        not isinstance(frame_data, FrameDataRaw) or not frame_data.frame
        or not actions or not actions.issubset(range(1, 8))
    ):
        raise ArcAppError("游戏初始状态无效")
    output = BytesIO()
    Image.fromarray(PALETTE[_validated_frame(frame_data.frame[-1])]).save(
        output, format="PNG",
    )
    cached = {"input_label": _input_label(actions), "preview": output.getvalue()}
    _reset_cache[full_id] = cached
    return cached


def preview_png(slug):
    spec = find_game(slug)
    if spec is None:
        raise ArcAppError("游戏不存在", 404)
    precomputed = _precomputed_bytes(f"previews/{slug}.png")
    if precomputed is not None:
        return precomputed
    return _reset_snapshot(spec)["preview"]


def start_game(slug):
    spec = find_game(slug)
    if spec is None:
        raise ArcAppError("游戏不存在", 404)
    try:
        game = new_game(spec)
        frame_data = game.perform_action(ActionInput(id=GameAction.RESET), raw=True)
    except ArcAppError:
        raise
    except Exception as exc:
        raise ArcAppError("游戏启动失败") from exc
    if not isinstance(frame_data, FrameDataRaw):
        raise ArcAppError("游戏返回了无效画面")
    session = ActiveSession(
        token=secrets.token_urlsafe(24),
        game_spec=spec,
        game=game,
        available_actions=tuple(int(action) for action in frame_data.available_actions),
    )
    with _sessions_lock:
        if len(_sessions) >= MAX_ACTIVE_SESSIONS:
            _sessions.pop(next(iter(_sessions)))
        _sessions[session.token] = session
    return session, serialize_frame_data(frame_data, session)


def perform_action(token, action_id, action_data):
    with _sessions_lock:
        session = _sessions.get(token)
    if session is None:
        raise ArcAppError("对局已失效，请重新开始", 404)
    if not session.lock.acquire(blocking=False):
        raise ArcAppError("上一个操作仍在处理中", 409)
    try:
        try:
            parsed_id = int(action_id)
            action = GameAction.from_id(parsed_id)
        except (TypeError, ValueError) as exc:
            raise ArcAppError("无效操作", 400) from exc
        if parsed_id != GameAction.RESET.value and parsed_id not in session.available_actions:
            raise ArcAppError("当前游戏不支持这个操作", 400)
        data = {}
        if action.is_complex():
            try:
                x = int((action_data or {}).get("x"))
                y = int((action_data or {}).get("y"))
            except (TypeError, ValueError) as exc:
                raise ArcAppError("点击坐标无效", 400) from exc
            if not (0 <= x <= 63 and 0 <= y <= 63):
                raise ArcAppError("点击坐标超出棋盘", 400)
            data = {"x": x, "y": y}
        try:
            frame_data = session.game.perform_action(
                ActionInput(id=action, data=data), raw=True,
            )
        except Exception as exc:
            raise ArcAppError("操作执行失败") from exc
        if action != GameAction.RESET:
            session.action_count += 1
        session.available_actions = tuple(
            int(available) for available in frame_data.available_actions
        )
        return serialize_frame_data(frame_data, session)
    finally:
        session.lock.release()


class Handler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".woff2": "font/woff2",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def _send(self, data, content_type, status=200):
        if isinstance(data, str):
            data = data.encode()
        compressed = False
        if (
            len(data) >= 1024
            and (
                content_type.startswith("text/")
                or content_type.startswith("application/json")
            )
            and _accepts_gzip(self.headers.get("Accept-Encoding"))
        ):
            data = gzip.compress(data, compresslevel=6, mtime=0)
            compressed = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if compressed:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, payload, status=200):
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        self._send(data, "application/json; charset=utf-8", status)

    def _html(self, content, status=200):
        self._send(content, "text/html; charset=utf-8", status)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or "0")
            if not 0 <= length <= MAX_REQUEST_BYTES:
                raise ValueError
            payload = json.loads(self.rfile.read(length) or b"{}")
            if isinstance(payload, dict):
                return payload
        except (ValueError, UnicodeError, json.JSONDecodeError):
            pass
        raise ArcAppError("请求 JSON 无效", 400)

    def do_GET(self):
        path = urlsplit(self.path).path
        try:
            if path == HEALTH_PATH:
                count = len(load_catalog())
                self._json({"status": "ok", "games": count})
                return
            if path in {"/", "/index.html"}:
                self._html(render_index())
                return
            if path.startswith("/game/"):
                slug = unquote(path.removeprefix("/game/"))
                game = find_game(slug) if SLUG_RE.fullmatch(slug) else None
                self._html(render_game(game) if game else render_not_found(), 200 if game else 404)
                return
            if path.startswith("/preview/"):
                filename = unquote(path.removeprefix("/preview/"))
                slug = filename.removesuffix(".png")
                if filename != f"{slug}.png" or not SLUG_RE.fullmatch(slug):
                    raise ArcAppError("游戏不存在", 404)
                self._send(preview_png(slug), "image/png")
                return
        except ArcAppError as exc:
            if path == HEALTH_PATH:
                self._json({"status": "error"}, 503)
            else:
                self.send_error(exc.status)
            return
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
            if action_match:
                game = perform_action(
                    action_match.group(1),
                    payload.get("action_id"),
                    payload.get("data"),
                )
                self._json({"success": True, "game": game})
                return
        except ArcAppError as exc:
            self._json(
                {"success": False, "message": str(exc)},
                exc.status,
            )
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
    if sys.argv[1:]:
        if sys.argv[1:] == ["--precompute"]:
            precompute_frontend_assets()
            return
        raise SystemExit("usage: app.py [--precompute]")
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
