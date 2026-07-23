"""ARC-AGI-3 部署下载缓存的复用与完整性契约。"""

import hashlib
import io
import json
from pathlib import Path

import pytest

from deploy import prepare_arc_agi_3


def _sha256(content):
    return hashlib.sha256(content).hexdigest()


def _make_complete_cache(data_root, game_count=25):
    set_id = "a" * 64
    set_root = data_root / "sets" / set_id
    set_root.mkdir(parents=True)
    games = []
    source = b"# MIT License\n# synthetic deployment cache\n"
    preview = b"\x89PNG\r\n\x1a\nsynthetic"
    for index in range(game_count):
        slug = f"g{index:03d}"
        version = f"{index:08x}"
        source_dir = set_root / "environments" / slug / version
        source_dir.mkdir(parents=True)
        (source_dir / f"{slug}.py").write_bytes(source)
        preview_dir = set_root / "previews"
        preview_dir.mkdir(exist_ok=True)
        (preview_dir / f"{slug}.png").write_bytes(preview)
        games.append(
            {
                "slug": slug,
                "version": version,
                "full_id": f"{slug}-{version}",
                "source_sha256": _sha256(source),
                "preview_sha256": _sha256(preview),
            }
        )
    (set_root / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "set_id": set_id,
                "game_count": game_count,
                "games": games,
            }
        ),
        encoding="utf-8",
    )
    (data_root / "current").symlink_to(
        Path("sets") / set_id,
        target_is_directory=True,
    )
    return set_root


def test_complete_local_cache_is_verified_and_reused_without_download(
    tmp_path,
    monkeypatch,
):
    data_root = tmp_path / "arc-agi-3"
    data_root.mkdir()
    _make_complete_cache(data_root)
    result_file = data_root / ".candidate-test"
    output = io.StringIO()

    def unexpected_download(*_args, **_kwargs):
        raise AssertionError("完整缓存不应触发网络下载")

    monkeypatch.setattr(
        prepare_arc_agi_3,
        "_download_public_set",
        unexpected_download,
    )

    target = prepare_arc_agi_3.prepare_public_set(
        data_root,
        result_file,
        output=output,
    )

    assert target == f"sets/{'a' * 64}"
    assert result_file.read_text(encoding="ascii").strip() == target
    assert "25/25" in output.getvalue()
    assert "跳过下载" in output.getvalue()


def test_cache_validation_rejects_a_modified_game_file(tmp_path):
    data_root = tmp_path / "arc-agi-3"
    data_root.mkdir()
    set_root = _make_complete_cache(data_root)
    preview = next((set_root / "previews").iterdir())
    preview.write_bytes(b"modified")

    with pytest.raises(
        prepare_arc_agi_3.ArcPublicSetError,
        match="哈希不匹配",
    ):
        prepare_arc_agi_3._validate_cached_set(set_root, 25)


def test_download_progress_contains_a_visual_bar_and_counter():
    line = prepare_arc_agi_3._progress_line(7, 25, "ft09-0d8bbf25")

    assert "████" in line
    assert "░░░░" in line
    assert "07/25" in line
    assert "ft09-0d8bbf25" in line
