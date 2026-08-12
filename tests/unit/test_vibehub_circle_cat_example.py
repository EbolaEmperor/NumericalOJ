"""围住小猫历史还原与独立排行榜契约。"""

from contextlib import contextmanager
from hashlib import sha256
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading

import pytest


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "vibehub_examples" / "circle-cat"
HISTORICAL_LAYOUT_SHA256 = (
    "e52687d7e2c714ec1066f1aa606739a6a2abcb82c29bcc7aebf3755ecaf79e16"
)
HISTORICAL_RULES_SHA256 = (
    "8eb574fbe56892772e47609e4f70375668676363378ceb51fff15edcd7bc9d8c"
)
HISTORICAL_SETUP_SHA256 = (
    "e880cf1eb28ca220d0826bfa3a23b5b3cb4628f3252627a81b9154bfc0e22a90"
)
VENDOR_HASHES = {
    "static/vendor/bootstrap/bootstrap.min.css": (
        "c6e9088a8d5ab202745f06f5579795b6e8d3d7505a39049e6a620a6ac995da9b"
    ),
    "static/vendor/fontawesome/css/all.min.css": (
        "1edb1725a9ea8ca4dcf2f5508cee183218aa1685e47c1b23056717f754f58ebf"
    ),
    "static/vendor/fontawesome/webfonts/fa-solid-900.woff2": (
        "7152a6933ee3d690ec2af3d09da9d701723d16aa3410a6d80f28ff8866f3b880"
    ),
}


def _load_app():
    module_name = "vibehub_circle_cat_example"
    spec = importlib.util.spec_from_file_location(module_name, PACKAGE / "app.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def circle_app(tmp_path, monkeypatch):
    module = _load_app()
    monkeypatch.setattr(module, "DATABASE_PATH", tmp_path / "circle-cat.sqlite3")
    module._initialize_database()
    return module


def test_historical_layout_rules_and_local_assets_are_unchanged(circle_app):
    index = (PACKAGE / "static" / "index.html").read_text(encoding="utf-8")
    layout_start = index.index('  <div class="cat-game-layout">')
    layout_end = index.index('\n\n  <dialog id="victoryDialog"', layout_start)
    rules_start = index.index("    function inBounds")
    rules_end = index.index("    function setVictoryError", rules_start)

    assert sha256(index[layout_start:layout_end].encode()).hexdigest() == (
        HISTORICAL_LAYOUT_SHA256
    )
    assert sha256(index[rules_start:rules_end].encode()).hexdigest() == (
        HISTORICAL_RULES_SHA256
    )
    for relative_path, expected_hash in VENDOR_HASHES.items():
        assert sha256((PACKAGE / relative_path).read_bytes()).hexdigest() == expected_hash
    assert circle_app.Handler.extensions_map[".woff2"] == "font/woff2"


def test_served_index_embeds_styles_and_solid_icon_font(circle_app):
    document = circle_app._embedded_index_document().decode("utf-8")

    assert '<link rel="stylesheet"' not in document
    assert 'data-vibehub-asset="bootstrap"' in document
    assert 'data-vibehub-asset="fontawesome"' in document
    assert ".btn-dark{" in document
    assert '.fa-cat:before{content:"\\f6be"' in document
    assert "data:font/woff2;base64," in document
    assert "../webfonts/" not in document


def test_local_board_and_custom_victory_dialog_contract():
    index = (PACKAGE / "static" / "index.html").read_text(encoding="utf-8")
    setup = index[
        index.index("    function setupBoard()") : index.index(
            "    function updateBadge", index.index("    function setupBoard()")
        )
    ]
    setup = setup.replace(
        "      if (victoryDialogEl.open) {\n        return;\n      }\n", ""
    ).replace(
        "        gameState = 'playing';\n",
        "        gameState = 'playing';\n        hasSubmittedResult = false;\n",
    )

    assert sha256(setup.encode()).hexdigest() == HISTORICAL_SETUP_SHA256
    assert "fetch('start'" not in index
    assert "gameId" not in index
    assert "playerMoves" not in index
    assert "Math.floor(boardSize / 2)" in index
    assert "Math.floor(Math.random() * boardSize)" in index
    assert "while (placed < initialBlocks)" in index
    assert "getOpenNeighbors(cat.row, cat.col).length > 0" in index
    assert "!!findShortestPathToEdge(cat.row, cat.col)" in index

    assert '<dialog id="victoryDialog"' in index
    assert 'role="dialog"' in index
    assert 'aria-modal="true"' in index
    assert 'aria-live="polite"' in index
    assert "victoryDialogEl.showModal()" in index
    assert "victoryNameEl.focus()" in index
    assert "newGameBtn.focus()" in index
    assert "victoryDialogEl.addEventListener('cancel'" in index
    assert "prefers-reduced-motion" in index
    assert "victoryErrorEl.textContent" in index
    assert "user.textContent" in index
    assert "window.alert(" not in index
    assert "window.prompt(" not in index
    assert "window.confirm(" not in index
    assert "VIBEHUB_VICTORY_" not in index
    assert "isLose" not in index
    assert "item.status" not in index
    assert ".cat-leaderboard-score.fail" not in index


def test_sqlite_keeps_only_winner_records_and_validates_input(circle_app):
    assert circle_app._normalize_display_name("  Cafe\u0301  ") == "Café"
    for invalid_name in (None, "", "   ", "a" * 25, "坏\n名", "坏\u200b名"):
        assert circle_app._normalize_display_name(invalid_name) is None

    for payload in (
        {"display_name": "  小猫  ", "turn_count": 9},
        {"display_name": "小猫", "turn_count": 4},
        {"display_name": "小狗", "turn_count": 5},
    ):
        response, status = circle_app._submit_result(payload)
        assert status == 200
        assert response == {"success": True}

    leaderboard, total = circle_app.get_circle_cat_leaderboard_page()
    assert total == 2
    assert leaderboard == [
        {"username": "小猫", "best_turns": 4},
        {"username": "小狗", "best_turns": 5},
    ]

    for turn_count in (0, 122, True, "3", 3.0):
        response, status = circle_app._submit_result(
            {"display_name": "非法回合", "turn_count": turn_count}
        )
        assert status == 400
        assert response["success"] is False

    connection = circle_app._connect_database()
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
            if not row[0].startswith("sqlite_")
        }
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(circle_cat_records)")
        }
    finally:
        connection.close()
    assert tables == {"circle_cat_records"}
    assert columns == {"id", "username", "turn_count", "created_at"}
    assert circle_app.get_circle_cat_leaderboard_page()[1] == 2


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path):
        super().__init__("vibehub.internal", timeout=3)
        self.socket_path = str(socket_path)

    def connect(self):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(self.socket_path)
        self.sock = connection


@contextmanager
def _running_server(circle_app, socket_path):
    try:
        server = circle_app.UnixHTTPServer(str(socket_path), circle_app.Handler)
    except PermissionError:
        pytest.skip("当前沙箱不允许创建 Unix socket")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _request(socket_path, method, path, payload=None):
    body = (
        None
        if payload is None
        else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    )
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection = _UnixHTTPConnection(socket_path)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def test_unix_socket_result_and_leaderboard_api(circle_app):
    with tempfile.TemporaryDirectory(prefix="vhcc-", dir="/tmp") as temp_dir:
        socket_path = Path(temp_dir) / "app.sock"
        server_context = _running_server(circle_app, socket_path)
        with server_context:
            status, health = _request(socket_path, "GET", "/healthz")
            assert (status, health) == (200, {"status": "ok"})

            status, result = _request(
                socket_path,
                "POST",
                "/result",
                {"display_name": "  UDS 玩家  ", "turn_count": 7},
            )
            assert status == 200
            assert result == {"success": True}

            status, leaderboard = _request(
                socket_path, "GET", "/leaderboard?page=1&limit=10"
            )
            assert status == 200
            assert leaderboard["total"] == 1
            assert leaderboard["leaderboard"][0]["username"] == "UDS 玩家"

            status, missing = _request(socket_path, "POST", "/start", {})
            assert status == 404
            assert missing["message"] == "接口不存在。"
