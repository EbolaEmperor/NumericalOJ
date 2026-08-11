"""ARC-AGI-3 原版界面、真实预览与 VibeHub 会话隔离契约。"""

from io import BytesIO
from html.parser import HTMLParser
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from arcengine import FrameDataRaw, GameAction, GameState
import numpy as np
from PIL import Image
import pytest


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "vibehub_examples" / "arc-agi-3"
STATIC = PACKAGE / "static"
HISTORICAL_DOM_HASHES = {
    "index.html": "1ee11f7010a5ea8ccfa6dd5cdc463a10aee1ebe187c0f101af16f2b2f1a18467",
    "game.html": "4cf4e337073c4caaaaae9d93db295077c3123374360fe8f84381008e3ef0631e",
    "not-found.html": "54b47ce22dba3d96fcd0057201db58ceb50250b3a55c6feb47fa90e3007d9417",
}
HISTORICAL_CATALOG_DOM_HASH = (
    "d725458590b59595363187a5227c7747a71ccc8609b63c8caa39e0cb173040b6"
)
SPEC = importlib.util.spec_from_file_location("arc_vibehub_example", PACKAGE / "app.py")
arc_app = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = arc_app
SPEC.loader.exec_module(arc_app)


def _game_spec(slug="ft09"):
    return {
        "slug": slug,
        "version": "0d8bbf25",
        "full_id": f"{slug}-0d8bbf25",
        "title": slug.upper(),
        "default_fps": 8,
        "level_count": 6,
        "input_label": "点击",
        "source_path": PACKAGE / "offline_data" / f"{slug}.py",
    }


def _normalized_historical_dom(name):
    """只撤销独立 HTML 外壳、相对路由和服务端动态占位。"""
    source = (STATIC / name).read_text(encoding="utf-8")
    prefix = '<div class="numoj-content arc-agi-page">\n'
    suffixes = {
        "index.html": '\n</div>\n<script src="./vendor/bootstrap/bootstrap.bundle.min.js">',
        "game.html": '\n</div>\n<script src="../../arc-agi-3.js">',
        "not-found.html": "\n</div>\n\n</body>",
    }
    assert source.count(prefix) == 1
    assert source.count(suffixes[name]) == 1
    body = source.split(prefix, 1)[1].split(suffixes[name], 1)[0]
    if name == "index.html":
        body = body.replace("__TOTAL_GAMES__", "{{ games|length }}")
        body = body.replace(
            "__FIRST_PAGE_END__", "{{ [15, games|length]|min }}"
        )
        for model_name, family in (
            ("Claude Opus 5", "claude"),
            ("GPT-5.6 Sol", "openai"),
            ("GPT-5.6 Sol", "openai"),
            ("GPT-5.6 Sol", "openai"),
            ("Claude Opus 4.8", "claude"),
            ("Opus 5", "claude"),
        ):
            logo = (
                '<i class="fas fa-microchip model-family-logo '
                f'model-family-logo--{family}" aria-hidden="true"></i>'
            )
            body = body.replace(
                logo, "{{ model_logo('" + model_name + "') }}", 1,
            )
    elif name == "game.html":
        replacements = {
            "__GAME_SLUG__": "{{ game.slug }}",
            "__START_URL__": (
                "{{ url_for('game.arc_agi_3_start', game_id=game.slug) }}"
            ),
            "__ACTION_URL_TEMPLATE__": (
                "{{ url_for('game.arc_agi_3_action', "
                "session_id='SESSION_ID') }}"
            ),
            "__CATALOG_URL__": "{{ url_for('game.arc_agi_3_index') }}",
            "__GAME_TITLE__": "{{ game.title }}",
            "__GAME_LEVEL_COUNT__": "{{ game.level_count }}",
            "__GAME_FULL_ID__": "{{ game.full_id }}",
            "__GAME_INPUT_LABEL__": "{{ game.input_label }}",
        }
        for placeholder, historical in replacements.items():
            body = body.replace(placeholder, historical)
    else:
        body = body.replace(
            "__CATALOG_URL__", "{{ url_for('game.arc_agi_3_index') }}"
        )
    return body


class _CanonicalDom(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.nodes = []

    def handle_starttag(self, tag, attrs):
        self.nodes.append(("start", tag, tuple(sorted(attrs))))

    def handle_startendtag(self, tag, attrs):
        self.nodes.append(("empty", tag, tuple(sorted(attrs))))

    def handle_endtag(self, tag):
        self.nodes.append(("end", tag))

    def handle_data(self, data):
        text = " ".join(data.split())
        if text:
            self.nodes.append(("text", text))


def _canonical_dom_hash(source):
    parser = _CanonicalDom()
    parser.feed(source)
    parser.close()
    return hashlib.sha256(repr(parser.nodes).encode()).hexdigest()


class _FakeGame:
    def __init__(self, available_actions=(6,)):
        self.available_actions = list(available_actions)
        self.last_action = None

    def perform_action(self, action_input, raw=False):
        assert raw is True
        self.last_action = action_input
        frame_data = FrameDataRaw(
            state=GameState.NOT_FINISHED,
            levels_completed=0,
            win_levels=6,
            available_actions=self.available_actions,
            action_input=action_input,
        )
        frame = np.zeros((4, 4), dtype=np.uint8)
        if action_input.id != GameAction.RESET:
            frame[0, 0] = 9
        else:
            frame[1, 1] = 11
        frame_data.frame = [frame]
        return frame_data


@pytest.fixture(autouse=True)
def _clear_runtime_state():
    arc_app._catalog_cache = None
    arc_app._sessions.clear()
    arc_app._reset_cache.clear()
    yield
    arc_app._sessions.clear()
    arc_app._reset_cache.clear()
    arc_app._catalog_cache = None


def test_original_css_and_javascript_are_byte_identical_to_pre_vibehub_assets():
    expected = {
        "arc-agi-3.css": "05d745dfdaee0208a6272f4d0ac17ebc67da37e18c98b76d071f5e08dad851d1",
        "arc-agi-3.js": "8f611b984368a8b0bcfa5881420af612f18569a985b899dc9495bd9b208be190",
        "arc-agi-3-catalog.js": "6be82d1140f6e0993c12694a44a8f26dfb4e44b8259e79c2008f9570bb7d22f8",
    }
    for name, digest in expected.items():
        assert hashlib.sha256((STATIC / name).read_bytes()).hexdigest() == digest
    assert arc_app.Handler.extensions_map[".woff2"] == "font/woff2"
    assert not (STATIC / "vendor/model-family/model-family.js").exists()


def test_templates_match_the_normalized_pre_vibehub_dom():
    for name, digest in HISTORICAL_DOM_HASHES.items():
        normalized = _normalized_historical_dom(name)
        assert hashlib.sha256(normalized.encode()).hexdigest() == digest


def test_rendered_catalog_pages_match_the_historical_jinja_dom():
    games = tuple(_game_spec(f"g{index:03d}") for index in range(25))

    assert _canonical_dom_hash(arc_app._catalog_pages(games)) == (
        HISTORICAL_CATALOG_DOM_HASH
    )


def test_catalog_cache_contains_only_manifest_and_official_sources(
    tmp_path,
    monkeypatch,
):
    games = []
    for index in range(25):
        slug = f"g{index:03d}"
        version = f"{index:08x}"
        source = tmp_path / "environments" / slug / version / f"{slug}.py"
        source.parent.mkdir(parents=True)
        source.write_text("# MIT License\n", encoding="utf-8")
        games.append({
            "slug": slug,
            "version": version,
            "title": slug.upper(),
            "default_fps": 8,
            "level_count": 1,
        })
    (tmp_path / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "games": games}),
        encoding="utf-8",
    )
    monkeypatch.setattr(arc_app, "ARC_DATA_ROOT", tmp_path)
    monkeypatch.setattr(arc_app, "_catalog_cache", None)

    assert len(arc_app.load_catalog()) == 25
    assert not (tmp_path / "previews").exists()


def test_catalog_and_player_keep_original_dom_and_only_use_relative_runtime_urls(
    monkeypatch,
):
    games = tuple(_game_spec(f"g{index:03d}") for index in range(25))
    monkeypatch.setattr(arc_app, "load_catalog", lambda: games)
    monkeypatch.setattr(arc_app, "_runtime_game", lambda game: game)

    index = arc_app.render_index()
    player = arc_app.render_game(games[0])

    assert index.count('class="arc-catalog-page') == 2
    assert index.count('class="arc-game-card ') == 25
    assert "arcHelpModal" in index
    assert index.count('class="arc-leaderboard-entry') == 5
    assert "探索未知规则" not in index
    assert "OFFLINE SANDBOX" not in index
    assert 'id="arcGameApp"' in player
    assert 'data-start-url="../../api/games/g000/start"' in player
    assert 'data-action-url-template="../../api/sessions/SESSION_ID/action"' in player
    assert "__GAME_" not in player
    assert "url_for(" not in index + player


def test_reset_preview_is_rendered_from_the_real_game_frame_inside_the_container(
    monkeypatch,
):
    spec = _game_spec()
    created = []
    monkeypatch.setattr(arc_app, "find_game", lambda slug: spec if slug == "ft09" else None)
    monkeypatch.setattr(
        arc_app,
        "new_game",
        lambda _spec: created.append(_FakeGame()) or created[-1],
    )

    content = arc_app.preview_png("ft09")
    runtime_game = arc_app._runtime_game(spec)

    assert content.startswith(b"\x89PNG\r\n\x1a\n")
    with Image.open(BytesIO(content)) as image:
        assert image.size == (4, 4)
        assert image.getpixel((1, 1)) == tuple(arc_app.PALETTE[11])
    assert runtime_game["input_label"] == "点击"
    assert arc_app.preview_png("ft09") == content
    assert len(created) == 1


@pytest.mark.parametrize(
    ("slug", "actions", "input_label"),
    (
        ("tn36", (6,), "点击"),
        ("s5i5", (6,), "点击"),
        ("ls20", (1, 2, 3, 4), "方向键"),
        ("sb26", (5, 6, 7), "操作键 + 点击"),
    ),
)
def test_catalog_labels_come_from_each_real_reset_action_shape(
    monkeypatch,
    slug,
    actions,
    input_label,
):
    spec = _game_spec(slug)
    monkeypatch.setattr(arc_app, "new_game", lambda _spec: _FakeGame(actions))

    runtime_game = arc_app._runtime_game(spec)
    assert runtime_game["input_label"] == input_label


def test_action_7_is_accepted_when_reset_exposes_it(monkeypatch):
    spec = _game_spec("sb26")
    game = _FakeGame((5, 6, 7))
    monkeypatch.setattr(
        arc_app,
        "find_game",
        lambda slug: spec if slug == "sb26" else None,
    )
    monkeypatch.setattr(arc_app, "new_game", lambda _spec: game)
    session, initial = arc_app.start_game("sb26")
    updated = arc_app.perform_action(session.token, 7, {})

    assert initial["available_actions"] == [5, 6, 7]
    assert updated["action_count"] == 1
    assert game.last_action.id == GameAction.ACTION7


def test_random_session_token_selects_the_active_game(monkeypatch):
    spec = _game_spec()
    monkeypatch.setattr(arc_app, "find_game", lambda slug: spec if slug == "ft09" else None)
    monkeypatch.setattr(arc_app, "new_game", lambda _spec: _FakeGame())
    session, initial = arc_app.start_game("ft09")

    assert len(session.token) >= 32
    assert initial["available_actions"] == [6]
    updated = arc_app.perform_action(session.token, 6, {"x": 0, "y": 0})
    assert updated["action_count"] == 1
    assert updated["frames"][0][0][0] == 9


def test_sessions_are_bounded_and_same_session_actions_cannot_overlap(monkeypatch):
    spec = _game_spec()
    monkeypatch.setattr(arc_app, "find_game", lambda _slug: spec)
    monkeypatch.setattr(arc_app, "new_game", lambda _spec: _FakeGame())
    monkeypatch.setattr(arc_app, "MAX_ACTIVE_SESSIONS", 2)

    first, _ = arc_app.start_game("ft09")
    second, _ = arc_app.start_game("ft09")
    third, _ = arc_app.start_game("ft09")

    assert list(arc_app._sessions) == [second.token, third.token]
    third.lock.acquire()
    try:
        with pytest.raises(arc_app.ArcAppError) as exc_info:
            arc_app.perform_action(third.token, 6, {"x": 0, "y": 0})
        assert exc_info.value.status == 409
    finally:
        third.lock.release()
