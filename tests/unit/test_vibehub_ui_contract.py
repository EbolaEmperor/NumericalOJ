"""VibeHub 页面、内置示例与嵌入式游玩安全契约。"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from flask import Flask, request
from jinja2 import Environment

from oj_modules.routes import vibehub_routes
from oj_modules.routes.game_routes import game_bp
from oj_modules.routes.vibehub_routes import vibehub_bp
from oj_modules.security import auth as auth_module
from oj_modules.vibehub.builtins import get_builtin_project, list_builtin_projects
from oj_modules.vibehub.storage import validate_manifest


ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")


def _read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def test_vibehub_templates_parse_and_use_external_assets():
    environment = Environment()
    for path in sorted((ROOT / "templates" / "vibehub").glob("*.html")):
        environment.parse(path.read_text(encoding="utf-8"))

    site_templates = "\n".join(
        _read(f"templates/vibehub/{name}")
        for name in (
            "index.html",
            "detail.html",
            "workspace.html",
            "admin_reviews.html",
            "guide.html",
            "player.html",
        )
    )
    assert "app/vibehub.css" in site_templates
    assert "app/vibehub.js" in site_templates
    assert "app/vibehub-player.js" in site_templates
    assert "<style" not in site_templates


def test_navigation_replaces_standalone_games_with_vibehub():
    navigation = _read("templates/components/layout/navigation.html")
    assert navigation.count(">VibeHub</span>") == 1
    assert "VibeHub 审核" in navigation
    assert ">围住小猫</span>" not in navigation
    assert ">ARC-AGI-3</span>" not in navigation
    assert "href=\"{{ url_for('vibehub.index') }}\"" in navigation


def test_builtin_catalog_is_single_source_and_enters_play_shell():
    projects = list_builtin_projects()
    assert [project["slug"] for project in projects] == [
        "circle-cat",
        "arc-agi-3",
    ]
    for project in projects:
        assert project["project_kind"] == "builtin"
        assert project["play_url"] == f"/vibehub/{project['slug']}/play"
        assert project["builtin_entrypoint"] is None
        assert project["cover_image"] == "static/cover.jpg"
        assert project["cover_url"] == (
            f"/api/vibehub/projects/{project['slug']}/cover?view=public&v=1"
        )
        assert get_builtin_project(project["slug"]) == project
    projects[0]["title"] = "changed"
    assert get_builtin_project("circle-cat")["title"] == "围住小猫"


def test_player_keeps_site_layout_and_separates_sandbox_trust():
    player = _read("templates/vibehub/player.html")
    css = _read("static/app/vibehub.css")
    javascript = _read("static/app/vibehub-player.js")

    assert '{% extends "layouts/site.html" %}' in player
    assert "vibehub-player-shell" in player
    assert (
        'sandbox="allow-scripts allow-forms allow-modals allow-pointer-lock '
        'allow-downloads"'
    ) in player
    assert "allow-same-origin" not in player
    assert "BUILT-IN SANDBOX" in player
    assert ".numoj-content.container-fluid.vibehub-player-page" in css
    assert "height: 100vh" in css
    assert 'window.addEventListener("pagehide"' in javascript
    assert "navigator.sendBeacon" in javascript
    assert "window.setInterval(heartbeat" in javascript
    assert "heartbeatFailures >= 3" in javascript
    assert "releaseLease(false)" in javascript
    assert "acquireLease();" in javascript
    assert "if (acquirePromise) return acquirePromise;" in javascript
    assert "generation !== acquireGeneration || isLeaving" in javascript
    assert "releaseGrantedPayload(payload, isLeaving)" in javascript
    assert "if (lease && !released) return Promise.resolve(lease);" in javascript
    assert "if (heartbeatPromise) return heartbeatPromise;" in javascript
    assert "lease !== heartbeatLease || released" in javascript
    assert "controller.abort()" in javascript
    assert "if (!isBuiltin)" not in javascript


def test_player_route_overrides_global_csp_and_confines_iframe(monkeypatch):
    user = {"id": 7, "username": "alice", "is_admin": 0}
    monkeypatch.setattr(auth_module, "current_user", lambda: user)
    monkeypatch.setattr(vibehub_routes, "current_user", lambda: user)
    monkeypatch.setattr(
        vibehub_routes,
        "render_template",
        lambda template, **_context: template,
    )
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test-secret", TESTING=True)
    app.add_url_rule("/login", endpoint="auth.login", view_func=lambda: "login")
    app.register_blueprint(vibehub_bp)

    @app.after_request
    def apply_compatible_global_csp(response):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self' https:",
        )
        return response

    response = app.test_client().get("/vibehub/circle-cat/play")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    directives = {
        parts[0]: parts[1:]
        for directive in response.headers["Content-Security-Policy"].split(";")
        if (parts := directive.strip().split())
    }
    for name in ("frame-src", "child-src", "connect-src"):
        assert directives[name] == ["'self'"]
    assert directives["script-src"] == ["'self'"]
    assert "'self'" in directives["style-src"]
    assert directives["object-src"] == ["'none'"]
    assert "https:" not in response.headers["Content-Security-Policy"]


def test_runtime_proxy_is_the_only_capability_public_route_contract():
    app = Flask(__name__)
    app.register_blueprint(vibehub_bp)
    rules = {rule.endpoint: rule for rule in app.url_map.iter_rules()}

    assert "vibehub.runtime_proxy" in rules
    assert rules["vibehub.runtime_proxy"].rule.startswith(
        "/vibehub/runtime/<token>/"
    )
    assert {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}.issubset(
        rules["vibehub.runtime_proxy"].methods
    )
    assert rules["vibehub.runtime_acquire"].methods == {"OPTIONS", "POST"}
    assert rules["vibehub.runtime_heartbeat"].methods == {"OPTIONS", "POST"}
    assert rules["vibehub.runtime_release"].methods == {"OPTIONS", "POST"}


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    (
        (vibehub_routes.VibeHubLeaseError("invalid token"), 404),
        (vibehub_routes.VibeHubCapacityError("proxy full"), 429),
    ),
)
def test_runtime_proxy_rejects_invalid_or_busy_request_before_body_read(
    monkeypatch,
    failure,
    expected_status,
):
    class RejectingManager:
        request_max_bytes = 1024

        def proxy_from_reader(self, _token, _method, _path, _headers, reader):
            assert callable(reader)
            raise failure

    monkeypatch.setattr(
        vibehub_routes,
        "get_runtime_manager",
        lambda: RejectingManager(),
    )
    app = Flask(__name__)
    with app.test_request_context(
        "/vibehub/runtime/invalid/path",
        method="POST",
        data=b"must-not-be-read",
    ):
        monkeypatch.setattr(
            request.stream,
            "read",
            lambda *_args, **_kwargs: pytest.fail("路由不得在 manager 前读取 body"),
        )
        response = vibehub_routes.runtime_proxy("invalid", "path")

    assert response.status_code == expected_status


def test_runtime_proxy_answers_sandbox_json_preflight_without_proxying_body(
    monkeypatch,
):
    calls = []

    class PreflightManager:
        def validate_proxy_capability(self, token):
            calls.append(("validate", token))

        def proxy_from_reader(self, *_args, **_kwargs):
            pytest.fail("CORS 预检不得转发到作品容器或读取 body")

    monkeypatch.setattr(
        vibehub_routes,
        "get_runtime_manager",
        lambda: PreflightManager(),
    )
    app = Flask(__name__)
    app.register_blueprint(vibehub_bp)

    response = app.test_client().options(
        "/vibehub/runtime/signed-token/api/state",
        headers={
            "Origin": "null",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 204
    assert response.get_data() == b""
    assert response.headers["Access-Control-Allow-Origin"] == "null"
    assert response.headers["Access-Control-Allow-Methods"] == "POST"
    assert response.headers["Access-Control-Allow-Headers"] == "Content-Type"
    assert response.headers["Cache-Control"] == "no-store"
    assert calls == [("validate", "signed-token")]


def test_runtime_proxy_preflight_normalizes_same_origin_allowed_headers(
    monkeypatch,
):
    calls = []

    class PreflightManager:
        def validate_proxy_capability(self, token):
            calls.append(token)

    monkeypatch.setattr(
        vibehub_routes,
        "get_runtime_manager",
        lambda: PreflightManager(),
    )
    app = Flask(__name__)
    app.register_blueprint(vibehub_bp)

    response = app.test_client().options(
        "/vibehub/runtime/signed-token/api/state",
        base_url="https://numoj.example",
        headers={
            "Origin": "HTTPS://NUMOJ.EXAMPLE",
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": " range, CONTENT-type ",
        },
    )

    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == (
        "HTTPS://NUMOJ.EXAMPLE"
    )
    assert response.headers["Access-Control-Allow-Headers"] == (
        "Range, Content-Type"
    )
    assert calls == ["signed-token"]


@pytest.mark.parametrize(
    "headers",
    (
        {
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
        {
            "Origin": "null",
            "Access-Control-Request-Method": "OPTIONS",
            "Access-Control-Request-Headers": "content-type",
        },
        {
            "Origin": "null",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-vibehub-secret",
        },
        {
            "Origin": "null",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
            "Access-Control-Request-Private-Network": "true",
        },
    ),
)
def test_runtime_proxy_rejects_untrusted_or_overbroad_preflight_before_lease(
    monkeypatch,
    headers,
):
    class UnexpectedManager:
        def validate_proxy_capability(self, _token):
            pytest.fail("非法 CORS 预检不得查询 lease")

        def proxy_from_reader(self, *_args, **_kwargs):
            pytest.fail("非法 CORS 预检不得进入代理")

    monkeypatch.setattr(
        vibehub_routes,
        "get_runtime_manager",
        lambda: UnexpectedManager(),
    )
    app = Flask(__name__)
    app.register_blueprint(vibehub_bp)

    response = app.test_client().options(
        "/vibehub/runtime/forged-token/api/state",
        base_url="https://numoj.example",
        headers=headers,
    )

    assert response.status_code == 403
    assert "Access-Control-Allow-Origin" not in response.headers


def test_runtime_proxy_preflight_invalid_token_fails_closed_without_proxy(
    monkeypatch,
):
    class InvalidTokenManager:
        def validate_proxy_capability(self, _token):
            raise vibehub_routes.VibeHubLeaseError("invalid token")

        def proxy_from_reader(self, *_args, **_kwargs):
            pytest.fail("无效 capability 不得进入作品代理")

    monkeypatch.setattr(
        vibehub_routes,
        "get_runtime_manager",
        lambda: InvalidTokenManager(),
    )
    app = Flask(__name__)
    app.register_blueprint(vibehub_bp)

    response = app.test_client().options(
        "/vibehub/runtime/forged-token/api/state",
        headers={
            "Origin": "null",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 404
    assert "Access-Control-Allow-Origin" not in response.headers


def test_runtime_capacity_error_maps_to_http_429():
    app = Flask(__name__)
    with app.app_context():
        response = vibehub_routes._runtime_capacity_response(
            vibehub_routes.VibeHubCapacityError("capacity reached")
        )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "1"
    assert response.get_json()["success"] is False


def test_heartbeat_capacity_error_maps_to_http_429_without_lease_payload(
    monkeypatch,
):
    class BusyManager:
        def heartbeat(self, _token):
            raise vibehub_routes.VibeHubCapacityError("health probes busy")

    monkeypatch.setattr(
        vibehub_routes,
        "get_runtime_manager",
        lambda: BusyManager(),
    )
    app = Flask(__name__)
    with app.test_request_context("/vibehub/runtime/token/heartbeat", method="POST"):
        response = vibehub_routes.runtime_heartbeat.__wrapped__("token")

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "1"
    assert response.get_json() == {
        "success": False,
        "message": "运行资源繁忙，请稍后重试。",
    }


def test_workspace_prioritizes_pending_snapshot_and_uses_api_play_url():
    workspace = _read("templates/vibehub/workspace.html")
    assert "{% if project.has_pending_review %}" in workspace
    assert "v{{ project.submitted_version }} 审核中" in workspace
    assert (
        "{% if not project.has_pending_review and "
        "(not project.public_version or project.latest_version != "
        "project.public_version) %}"
    ) in workspace
    assert 'href="{{ project.play_url }}"' in workspace
    assert "project.play_url }}?channel=latest" not in workspace
    assert "project.last_review_note" in workspace
    assert 'name="cover_image" type="file"' not in workspace

    reviews = _read("templates/vibehub/admin_reviews.html")
    assert "v{{ project.submitted_version }}" in reviews
    assert "v{{ project.latest_version }}" not in reviews


def test_legacy_game_bookmarks_redirect_and_old_apis_are_gone():
    app = Flask(__name__)
    app.register_blueprint(vibehub_bp)
    app.register_blueprint(game_bp)
    client = app.test_client()

    for old_path, slug in (
        ("/games/circle-cat", "circle-cat"),
        ("/games/circle-cat/leaderboard", "circle-cat"),
        ("/games/arc-agi-3", "arc-agi-3"),
        ("/games/arc-agi-3/ft09-0d8bbf25", "arc-agi-3"),
    ):
        response = client.get(old_path)
        assert response.status_code == 301
        assert response.headers["Location"].endswith(f"/vibehub/{slug}")

    for old_api in (
        "/games/circle-cat/start",
        "/games/circle-cat/result",
        "/games/arc-agi-3/ft09-0d8bbf25/start",
        "/games/arc-agi-3/session/legacy/action",
    ):
        response = client.post(old_api, json={})
        assert response.status_code == 410
        assert response.get_json()["code"] == "legacy_game_retired"


def test_bundled_examples_are_complete_valid_offline_packages():
    for slug in ("circle-cat", "arc-agi-3"):
        package = ROOT / "vibehub_examples" / slug
        manifest = validate_manifest(package)
        dockerfile = (package / "Dockerfile").read_text(encoding="utf-8")
        assert manifest == {
            **manifest,
            "schema_version": 1,
            "transport": "unix",
            "socket_path": "/run/vibehub/app.sock",
            "health_path": "/healthz",
        }
        assert manifest["cover_image"] == "static/cover.jpg"
        assert manifest["cover_image_mime"] == "image/jpeg"
        assert dockerfile.startswith("FROM numericaloj-vibehub-runtime:1\n")
        assert "COPY --chown=65532:65532 . /app" in dockerfile
        assert (package / "app.py").is_file()
        app_source = (package / "app.py").read_text(encoding="utf-8")
        assert "previous_umask = os.umask(0)" in app_source
        assert "os.umask(previous_umask)" in app_source
        assert "os.chmod(SOCKET_PATH, 0o600)" in app_source
        assert "except OSError:" in app_source
        assert (package / "README.md").is_file()
        assert (package / "static" / "index.html").is_file()


def test_circle_cat_example_keeps_original_rules_and_declares_isolation_tradeoff():
    index = _read("vibehub_examples/circle-cat/static/index.html")
    readme = _read("vibehub_examples/circle-cat/README.md")
    project = get_builtin_project("circle-cat")

    for contract in (
        "const DESKTOP_BOARD_SIZE = 11;",
        "const MOBILE_BOARD_SIZE = 9;",
        "const DESKTOP_INITIAL_BLOCKS = 5;",
        "const MOBILE_INITIAL_BLOCKS = 4;",
        "function buildShortestPathDagStats",
        "function chooseMaxBranchShortestStep",
        "function chooseFallbackMove",
        "function generateInitialState",
        "function finishGame",
        "function setupBoard",
        'gameState = "moving";',
        "-branchCount",
        "cat-arriving",
        "just-blocked",
    ):
        assert contract in index
    assert "fetch(" not in index
    assert "/games/" not in index
    assert "localStorage" not in index
    assert "不接入 OJ 排行榜" in index
    assert "移除了排行榜和战绩持久化" in readme
    assert "不接入 OJ 排行榜或持久保存战绩" in project["description"]


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_circle_cat_rules_execute_original_hex_geometry_and_max_branch_ai():
    index = _read("vibehub_examples/circle-cat/static/index.html")
    match = re.search(r"<script>([\s\S]*?)</script>", index)
    assert match is not None
    script = match.group(1)

    subprocess.run(
        [NODE, "--check", "-"],
        input=script,
        text=True,
        check=True,
        capture_output=True,
    )
    harness = r"""
const R = globalThis.CircleCatRules;
function check(value, message) {
  if (!value) throw new Error(message);
}
check(R.DESKTOP_BOARD_SIZE === 11, "desktop size");
check(R.MOBILE_BOARD_SIZE === 9, "mobile size");
check(R.DESKTOP_INITIAL_BLOCKS === 5, "desktop blocks");
check(R.MOBILE_INITIAL_BLOCKS === 4, "mobile blocks");
check(
  JSON.stringify(R.getNeighbors(5, 2, 2))
    === JSON.stringify([{row:1,col:1},{row:1,col:2},{row:2,col:1},{row:2,col:3},{row:3,col:1},{row:3,col:2}]),
  "even-row hex geometry"
);
check(
  JSON.stringify(R.getNeighbors(5, 1, 2))
    === JSON.stringify([{row:0,col:2},{row:0,col:3},{row:1,col:1},{row:1,col:3},{row:2,col:2},{row:2,col:3}]),
  "odd-row hex geometry"
);

let seed = 0x51f15e;
function deterministicRandom(maximum) {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed % maximum;
}
for (const mode of ["desktop", "mobile"]) {
  const generated = R.generateInitialState(mode, deterministicRandom);
  const expectedSize = mode === "desktop" ? 11 : 9;
  const expectedBlocks = mode === "desktop" ? 5 : 4;
  check(generated.boardSize === expectedSize, mode + " generated size");
  check(generated.initialBlocked.length === expectedBlocks, mode + " generated blocks");
  check(generated.cat.row === Math.floor(expectedSize / 2), mode + " centered cat");
  check(
    R.findShortestPathToEdge(
      generated.board,
      generated.boardSize,
      generated.cat.row,
      generated.cat.col
    ) !== null,
    mode + " starts with an escape path"
  );
}

const sealedBoard = R.createEmptyBoard(5);
const centeredCat = {row: 2, col: 2};
for (const cell of [[1,1],[1,2],[2,1],[2,3],[3,1],[3,2]]) {
  sealedBoard[cell[0]][cell[1]] = "blocked";
}
check(R.isCatSealed(sealedBoard, centeredCat, 5), "six neighboring stones seal the cat");

const size = 5;
const cat = {row: 2, col: 2};
const candidates = [];
for (let row = 0; row < size; row += 1) {
  for (let col = 0; col < size; col += 1) {
    if (row !== cat.row || col !== cat.col) candidates.push({row, col});
  }
}
let witness = null;
function inspect(blocks) {
  const board = R.createEmptyBoard(size);
  for (const cell of blocks) board[cell.row][cell.col] = "blocked";
  const path = R.findShortestPathToEdge(board, size, cat.row, cat.col);
  const open = R.getOpenNeighbors(board, cat, size, cat.row, cat.col);
  const choice = R.chooseMaxBranchShortestStep(board, cat, size, open);
  if (!path || path.length < 2 || !choice) return;
  const stats = R.buildShortestPathDagStats(board, cat, size);
  const counts = open.map((cell) => stats.pathCount[cell.row][cell.col]).filter((count) => count > 0);
  const maximum = Math.max(...counts);
  check(stats.pathCount[choice.row][choice.col] === maximum, "choice must maximize shortest-path branches");
  const firstBfsStep = path[1];
  if (choice.row !== firstBfsStep.row || choice.col !== firstBfsStep.col) {
    witness = {blocks, choice, firstBfsStep, maximum};
  }
}
function chooseBlocks(start, remaining, selected) {
  if (witness) return;
  if (remaining === 0) {
    inspect(selected);
    return;
  }
  for (let index = start; index <= candidates.length - remaining; index += 1) {
    chooseBlocks(index + 1, remaining - 1, selected.concat([candidates[index]]));
    if (witness) return;
  }
}
for (let depth = 0; depth <= 4 && !witness; depth += 1) {
  chooseBlocks(0, depth, []);
}
check(witness !== null, "need a board where max-branch AI differs from first BFS path");
"""
    subprocess.run(
        [NODE, "-e", f"{script}\n{harness}"],
        check=True,
        capture_output=True,
        text=True,
    )
