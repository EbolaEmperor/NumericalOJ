"""ARC-AGI-3 部署目录、本地运行与会话隔离契约。"""

import json
from pathlib import Path

from arcengine import FrameDataRaw, GameAction, GameState
import numpy as np
import pytest

from oj_modules.arc_agi_3 import catalog
from oj_modules.arc_agi_3.catalog import get_arc_game, list_arc_games
from oj_modules.arc_agi_3 import services
from oj_modules.arc_agi_3.services import (
    ArcInvalidAction,
    ArcSessionNotFound,
    _clear_arc_sessions_for_tests,
    perform_arc_action,
    start_arc_game,
)


ROOT = Path(__file__).resolve().parents[2]


class _FakeGame:
    def perform_action(self, action_input, raw=False):
        assert raw is True
        frame_data = FrameDataRaw(
            state=GameState.NOT_FINISHED,
            levels_completed=0,
            win_levels=6,
            available_actions=[6],
            action_input=action_input,
        )
        frame = np.zeros((64, 64), dtype=np.uint8)
        if action_input.id != GameAction.RESET:
            frame[0, 0] = 9
        frame_data.frame = [frame]
        return frame_data


def _write_test_catalog(root):
    game_rows = (
        {
            "slug": "ft09",
            "version": "0d8bbf25",
            "title": "FT09",
            "default_fps": 8,
            "level_count": 6,
            "input_kind": "click",
            "input_label": "点击",
        },
        {
            "slug": "ls20",
            "version": "9607627b",
            "title": "LS20",
            "default_fps": 30,
            "level_count": 7,
            "input_kind": "keyboard",
            "input_label": "方向键",
        },
    )
    for game in game_rows:
        source_dir = (
            root
            / "environments"
            / game["slug"]
            / game["version"]
        )
        source_dir.mkdir(parents=True)
        (source_dir / f"{game['slug']}.py").write_text(
            "# MIT License\n",
            encoding="utf-8",
        )
        preview_dir = root / "previews"
        preview_dir.mkdir(exist_ok=True)
        (preview_dir / f"{game['slug']}.png").write_bytes(b"\x89PNG\r\n")
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "set_id": "a" * 64,
                "games": list(game_rows),
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture(autouse=True)
def isolated_deployment_cache(tmp_path, monkeypatch):
    set_root = tmp_path / "sets" / ("a" * 64)
    set_root.mkdir(parents=True)
    _write_test_catalog(set_root)
    current_link = tmp_path / "current"
    current_link.symlink_to(set_root, target_is_directory=True)
    monkeypatch.setattr(catalog, "_CURRENT_SET_LINK", current_link)
    monkeypatch.setattr(services, "_new_game_instance", lambda _spec: _FakeGame())
    catalog._load_catalog.cache_clear()
    _clear_arc_sessions_for_tests()
    yield
    _clear_arc_sessions_for_tests()
    catalog._load_catalog.cache_clear()


def test_catalog_reads_games_from_the_active_deployment_cache():
    games = list_arc_games()

    assert [game.slug for game in games] == ["ft09", "ls20"]
    assert all(game.source_path.is_file() for game in games)
    assert all(game.preview_path.is_file() for game in games)


def test_repository_does_not_store_downloaded_public_game_files():
    assert not (ROOT / "oj_modules" / "arc_agi_3" / "environments").exists()
    assert not (ROOT / "static" / "app" / "arc-agi-3" / "previews").exists()


def test_local_click_game_starts_and_accepts_supported_action():
    session_id, initial = start_arc_game("alice", "ft09")

    assert initial["state"] == "NOT_FINISHED"
    assert initial["game_id"] == "ft09"
    assert initial["frames"]
    assert initial["available_actions"] == [6]

    updated = perform_arc_action(
        "alice",
        session_id,
        6,
        {"x": 0, "y": 0},
    )

    assert updated["action_count"] == 1
    assert updated["win_levels"] == get_arc_game("ft09").level_count
    assert updated["frames"][0][0][0] == 9


def test_sessions_are_owned_by_the_logged_in_user():
    session_id, _ = start_arc_game("alice", "ls20")

    with pytest.raises(ArcSessionNotFound):
        perform_arc_action("bob", session_id, 1)


def test_game_rejects_an_action_not_exposed_by_current_environment():
    session_id, _ = start_arc_game("alice", "ft09")

    with pytest.raises(ArcInvalidAction):
        perform_arc_action("alice", session_id, 1)


def test_runtime_service_has_no_remote_api_dependency():
    source = (
        ROOT / "oj_modules" / "arc_agi_3" / "services.py"
    ).read_text(encoding="utf-8")

    assert "requests" not in source
    assert "http://" not in source
    assert "https://" not in source
    assert "ARC_API_KEY" not in source
