"""VibeHub 页面、示例作品与嵌入式游玩安全契约。"""

import logging
import re
from pathlib import Path

import pytest
from flask import Flask, request
from jinja2 import Environment

from oj_modules.observability.events import build_payload
from oj_modules.routes import vibehub_routes
from oj_modules.routes.game_routes import game_bp
from oj_modules.routes.vibehub_routes import vibehub_bp
from oj_modules.security import auth as auth_module
from oj_modules.vibehub import runtime as vibehub_runtime
from oj_modules.vibehub import guide as guide_module
from oj_modules.vibehub.guide import render_developer_guide
from oj_modules.vibehub.storage import validate_manifest


ROOT = Path(__file__).resolve().parents[2]


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
            "guide.html",
            "player.html",
        )
    )
    assert "app/vibehub.css" in site_templates
    assert "app/vibehub.js" in site_templates
    assert "app/vibehub-player.js" in site_templates


def test_vibehub_gallery_keeps_the_compact_card_and_dialog_contract():
    gallery = _read("templates/vibehub/index.html")
    card = _read("templates/vibehub/_project_card.html")
    css = _read("static/app/vibehub.css")
    javascript = _read("static/app/vibehub.js")

    assert all(token in gallery for token in (
        'data-vibe-filter="mine"', 'data-vibe-filter="pending"', "<dialog", "data-vibe-project-modal",
        "data-vibe-approve-modal", "创建并自动送审", 'aria-label="创建作品"',
        "data-admin-review-url-template", "data-vibe-featured-modal",
        "data-admin-featured-url-template",
    ))
    assert 'class="vibe-toolbar-link"' in gallery
    assert "fa-book-open" in gallery
    assert css.count("font-size: .66rem") >= 2
    assert ".vibehub-page input { font-family: inherit; }" in css
    assert ".vibe-toolbar-link { border: 1px solid" in css
    assert "border-top-right-radius: 9px" in css
    assert "保存更新并自动送审" in javascript
    assert all(token in card for token in (
        "project.play_url", "vibe-featured-mark", "vibe-featured-mark--inactive",
        "data-vibe-toggle-featured", "fa-gem", "data-avatar-seed",
        "project.owner_username", "project.is_pending", "data-vibe-edit-project",
        "data-vibe-approve-project", "审核通过",
    ))
    assert 'decision: "approve"' in javascript
    assert "JSON.stringify({ featured: featured })" in javascript
    assert "expected_version" in javascript
    assert "NumojIdenticon" in javascript
    assert "projectDialog.dataset.originFilter = activeFilter" in javascript
    assert "deleteDialog.dataset.originFilter = projectDialog.dataset.originFilter" in javascript
    assert '"/vibehub/?view=" + encodeURIComponent(originFilter)' in javascript


def test_vibehub_author_avatar_keeps_its_identicon_grid_on_mobile():
    css = _read("static/app/vibehub.css")
    avatar_rule = re.search(
        r"\.vibe-card-author \.vibe-author-avatar\s*\{(?P<body>[^{}]+)\}",
        css,
    )

    assert avatar_rule is not None
    body = avatar_rule.group("body")
    assert "display: grid" in body
    assert "grid-template-columns: repeat(8, 1fr)" in body
    assert "grid-template-rows: repeat(8, 1fr)" in body
    assert "flex: 0 0 22px" in body
    assert ".vibe-card-author .vibe-author-avatar > span.is-filled" in css


def test_navigation_replaces_standalone_games_with_vibehub():
    navigation = _read("templates/components/layout/navigation.html")
    assert navigation.count(">VibeHub</span>") == 1
    assert "href=\"{{ url_for('vibehub.index') }}\"" in navigation


def test_gallery_uses_uploaded_covers_without_generated_art():
    card = _read("templates/vibehub/_project_card.html")
    css = _read("static/app/vibehub.css")

    assert '<img src="{{ project.cover_url }}"' in card


def test_player_keeps_site_layout_and_separates_sandbox_trust():
    player = _read("templates/vibehub/player.html")
    css = _read("static/app/vibehub.css")
    javascript = _read("static/app/vibehub-player.js")

    assert '{% extends "layouts/site.html" %}' in player
    assert "vibehub-player-shell" in player
    assert (
        'sandbox="allow-scripts allow-forms allow-modals allow-pointer-lock '
        'allow-downloads allow-popups allow-popups-to-escape-sandbox"'
    ) in player
    assert "allow-same-origin" not in player
    assert "allow-top-navigation" not in player
    assert "data-math-curve-loader" in player
    assert 'data-icon-only="true"' in player
    assert 'data-size="lg"' in player
    assert 'data-color-a="#c95d32"' in player
    assert 'data-color-b="#c95d32"' in player
    assert "作品镜像已在保存时构建完成" in player
    assert ".vibe-player-loading .vibe-player-loader" in css
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
    assert 'response.headers.get("Retry-After")' in javascript
    assert "error.status === 429" in javascript
    assert "retryCount < MAX_ACQUIRE_RETRIES" in javascript
    assert "requestLease(generation, retryCount + 1)" in javascript
    assert "controller.abort()" in javascript


def test_player_route_removes_outgoing_csp_restrictions(monkeypatch):
    user = {"id": 7, "username": "alice", "is_admin": 0}
    monkeypatch.setattr(auth_module, "current_user", lambda: user)
    monkeypatch.setattr(vibehub_routes, "current_user", lambda: user)
    monkeypatch.setattr(
        vibehub_routes.services, "get_project",
        lambda slug, **_kwargs: {"slug": slug, "title": "围住小猫"},
    )
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
    assert response.headers["Content-Security-Policy"] == "frame-ancestors 'self'"


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


def test_runtime_failure_logs_the_bounded_buildkit_cause_but_keeps_http_generic(
    caplog,
):
    error = vibehub_runtime.VibeHubImageError(
        "VibeHub 镜像构建失败",
        buildkit_diagnostic="ERROR: buildkit returned a concrete failure",
        buildkit_returncode=1,
        buildkit_stderr_truncated=True,
    )
    app = Flask(__name__)

    with app.test_request_context("/vibehub/example/runtime/acquire", method="POST"):
        with caplog.at_level(logging.WARNING):
            response, status = vibehub_routes._runtime_error_response(error)

    assert status == 503
    assert response.get_json() == {
        "success": False,
        "message": "作品运行服务暂时不可用，请稍后重试。",
    }
    record = next(
        item for item in caplog.records if item.getMessage() == "VibeHub 运行请求失败"
    )
    assert record.exc_info is None
    assert record.event_fields == {
        "error_type": "VibeHubImageError",
        "buildkit": {
            "diagnostic": "ERROR: buildkit returned a concrete failure",
            "returncode": 1,
            "stdout_truncated": False,
            "stderr_truncated": True,
        },
    }
    payload = build_payload(record)
    assert payload["buildkit"] == record.event_fields["buildkit"]
    assert "buildkit" not in response.get_json()


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


def test_removed_auxiliary_pages_leave_gallery_and_play_routes(monkeypatch):
    for name in ("workspace.html", "detail.html", "admin_reviews.html"):
        assert not (ROOT / "templates/vibehub" / name).exists()
    user = {"id": 7, "username": "alice", "is_admin": 0}
    seen = []
    monkeypatch.setattr(auth_module, "current_user", lambda: user)
    monkeypatch.setattr(vibehub_routes, "current_user", lambda: user)
    monkeypatch.setattr(
        vibehub_routes.services, "list_gallery_projects",
        lambda actor: seen.append(actor) or [],
    )
    monkeypatch.setattr(
        vibehub_routes.services, "get_project",
        lambda slug, **_kwargs: {"play_url": f"/vibehub/{slug}/play"},
    )
    rendered_contexts = []
    monkeypatch.setattr(
        vibehub_routes,
        "render_template",
        lambda template, **context: rendered_contexts.append(context) or template,
    )
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", TESTING=True)
    app.add_url_rule("/login", endpoint="auth.login", view_func=lambda: "login")
    app.register_blueprint(vibehub_bp)
    client = app.test_client()
    gallery = client.get("/vibehub/?view=mine")
    assert seen == [user]
    assert gallery.headers["Cache-Control"] == "private, no-store"
    assert rendered_contexts[-1]["initial_filter"] == "mine"
    client.get("/vibehub/?view=featured")
    assert rendered_contexts[-1]["initial_filter"] == "featured"
    client.get("/vibehub/?view=pending")
    assert rendered_contexts[-1]["initial_filter"] == "all"
    assert client.get("/vibehub/admin/reviews").status_code == 404

    for path, destination in (
        ("/vibehub/workspace", "/vibehub/?view=mine"),
        ("/vibehub/circle-cat", "/vibehub/circle-cat/play"),
    ):
        response = client.get(path)
        assert response.status_code == 302
        assert response.headers["Location"].endswith(destination)


def test_developer_guide_renders_the_cli_markdown_with_generated_toc():
    template = _read("templates/vibehub/guide.html")
    problem_template = _read("templates/problems/detail.html")
    markdown = _read("docs/vibehub-developer-guide.md")
    content_html, toc_html = render_developer_guide()

    assert all(token in template for token in (
        "guide_html|safe", "guide_toc_html|safe", "numoj-markdown",
        "numoj-problem-code-rendering", "data-numoj-markdown",
        "{% block mathjax %}", "components/layout/mathjax.html",
    ))
    for asset in (
        "app/editor-semantic-tokens.js",
        "vendor/mermaid/mermaid.min.js",
        "vendor/shiki-markdown/highlighter.js",
        "app/markdown-rendering.js",
    ):
        assert asset in template
        assert asset in problem_template
    assert all(token not in markdown for token in ("## API", "/api/vibehub/"))
    assert "## 使用 CLI 管理作品" in markdown
    assert "id=\"使用-cli-管理作品\"" in content_html
    assert "href=\"#使用-cli-管理作品\"" in toc_html


def test_developer_guide_reloads_rich_markdown_and_generated_toc(
    monkeypatch,
    tmp_path,
):
    guide_path = tmp_path / "vibehub-developer-guide.md"
    guide_path.write_text(
        "# 临时手册\n\n"
        "## 第一节\n\n"
        "### 子节\n\n"
        "#### 不进入目录\n\n"
        r"公式 \(x_i^2 < y\)。" "\n\n"
        "```python\n"
        "def solve(x):\n"
        "    return x + 1\n"
        "```\n\n"
        "<script>alert(1)</script>\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(guide_module, "DEVELOPER_GUIDE_PATH", guide_path)

    content_html, toc_html = guide_module.render_developer_guide()

    assert 'id="第一节"' in content_html
    assert 'class="codehilite language-python"' in content_html
    assert '<span class="' in content_html
    assert r"\(x_i^2 &lt; y\)" in content_html
    assert "<script" not in content_html.lower()
    assert 'href="#第一节"' in toc_html
    assert 'href="#子节"' in toc_html
    assert "不进入目录" not in toc_html

    guide_path.write_text("# 临时手册\n\n## 第二节\n", encoding="utf-8")
    refreshed_html, refreshed_toc = guide_module.render_developer_guide()

    assert 'id="第二节"' in refreshed_html
    assert 'href="#第二节"' in refreshed_toc
    assert "第一节" not in refreshed_html
    assert "第一节" not in refreshed_toc


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
        assert response.headers["Location"].endswith(f"/vibehub/{slug}/play")

    for old_api in (
        "/games/circle-cat/start",
        "/games/circle-cat/result",
        "/games/arc-agi-3/ft09-0d8bbf25/start",
        "/games/arc-agi-3/session/legacy/action",
    ):
        response = client.post(old_api, json={})
        assert response.status_code == 410
        assert response.get_json()["code"] == "legacy_game_retired"


def test_bundled_examples_are_complete_valid_packages():
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
