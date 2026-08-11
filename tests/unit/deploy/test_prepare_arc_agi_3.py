"""ARC-AGI-3 部署下载缓存的复用与完整性契约。"""

import hashlib
import io
import json
from pathlib import Path

import pytest

from deploy import prepare_arc_agi_3


def _sha256(content):
    return hashlib.sha256(content).hexdigest()


class _StreamingResponse:
    def __init__(self, chunks, *, content_length=None):
        self._chunks = tuple(chunks)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self.is_redirect = False
        self.is_permanent_redirect = False
        self.closed = False
        self.iterated = 0

    def raise_for_status(self):
        return None

    def iter_content(self, *, chunk_size):
        assert chunk_size == 64 * 1024
        for chunk in self._chunks:
            self.iterated += 1
            yield chunk

    def close(self):
        self.closed = True


class _StreamingSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def _source_bytes(index, variant="v1"):
    return (
        f"# MIT License\n# synthetic deployment cache {index:03d} {variant}\n"
    ).encode("utf-8")


def _make_complete_cache(data_root, game_count=25, variant="v1"):
    staging = data_root / ".fixture-staging"
    (staging / "environments").mkdir(parents=True)
    (staging / "previews").mkdir()
    games = []
    for index in range(game_count):
        slug = f"g{index:03d}"
        version = f"{index:08x}"
        full_id = f"{slug}-{version}"
        source = _source_bytes(index, variant)
        source_dir = staging / "environments" / slug / version
        source_dir.mkdir(parents=True)
        (source_dir / f"{slug}.py").write_bytes(source)
        preview_path = staging / "previews" / f"{slug}.png"
        prepare_arc_agi_3._write_fingerprint_preview(
            preview_path,
            _sha256(source),
        )
        games.append(
            {
                "slug": slug,
                "version": version,
                "full_id": full_id,
                "title": f"Synthetic {index:03d}",
                "default_fps": 30,
                "level_count": 1,
                "input_kind": "keyboard_click",
                "input_label": "方向键 + 点击",
                "available_actions": [1, 2, 3, 4, 5, 6],
                "source_sha256": _sha256(source),
                "preview_sha256": _sha256(preview_path.read_bytes()),
            }
        )
    set_id = prepare_arc_agi_3._games_fingerprint(games)
    (staging / "manifest.json").write_text(
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
    set_root = data_root / "sets" / set_id
    set_root.parent.mkdir()
    staging.rename(set_root)
    (data_root / "current").symlink_to(
        Path("sets") / set_id,
        target_is_directory=True,
    )
    return set_root


def _install_fake_online(monkeypatch, *, variant="v1", game_count=25):
    game_ids = tuple(f"g{index:03d}-{index:08x}" for index in range(game_count))
    catalog_checks = []
    source_requests = []

    def fake_catalog(_session, count):
        catalog_checks.append(count)
        return game_ids

    def fake_metadata(_session, path):
        slug = path.rsplit("/", 1)[-1]
        index = int(slug[1:])
        return {
            "game_id": game_ids[index],
            "title": f"Synthetic {index:03d}",
            "default_fps": 30,
            "baseline_actions": [1],
            "available_actions": [1, 2, 3, 4, 5, 6],
        }

    def fake_source(_session, path, **_kwargs):
        full_id = path.split("/")[3]
        index = int(full_id.split("-", 1)[0][1:])
        source_requests.append(full_id)
        return _source_bytes(index, variant)

    monkeypatch.setattr(prepare_arc_agi_3, "_fetch_public_catalog", fake_catalog)
    monkeypatch.setattr(prepare_arc_agi_3, "_get_json", fake_metadata)
    monkeypatch.setattr(prepare_arc_agi_3, "_get_content", fake_source)
    return catalog_checks, source_requests


def test_complete_cache_is_reused_only_after_all_online_sources_are_downloaded(
    tmp_path,
    monkeypatch,
):
    data_root = tmp_path / "arc-agi-3"
    data_root.mkdir()
    cached = _make_complete_cache(data_root)
    result_file = data_root / ".candidate-test"
    output = io.StringIO()
    online_checks, source_requests = _install_fake_online(monkeypatch)

    target = prepare_arc_agi_3.prepare_public_set(
        data_root,
        result_file,
        output=output,
    )

    assert target == f"sets/{cached.name}"
    assert result_file.read_text(encoding="ascii").strip() == target
    assert "25/25" in output.getvalue()
    assert "线上内容哈希一致" in output.getvalue()
    assert online_checks == [25]
    assert len(source_requests) == 25
    assert len(set(source_requests)) == 25


def test_same_game_ids_with_changed_source_publish_a_new_set(tmp_path, monkeypatch):
    data_root = tmp_path / "arc-agi-3"
    data_root.mkdir()
    cached = _make_complete_cache(data_root, variant="v1")
    result_file = data_root / ".candidate-test"
    _catalog_checks, source_requests = _install_fake_online(
        monkeypatch,
        variant="v2",
    )

    target = prepare_arc_agi_3.prepare_public_set(
        data_root,
        result_file,
        output=io.StringIO(),
    )

    assert target != f"sets/{cached.name}"
    published = data_root / target
    prepare_arc_agi_3._validate_cached_set(published, 25)
    assert b"v2" in next((published / "environments").glob("*/*/*.py")).read_bytes()
    assert len(source_requests) == 25
    assert cached.is_dir()


def test_catalog_failure_does_not_silently_reuse_old_cache(tmp_path, monkeypatch):
    data_root = tmp_path / "arc-agi-3"
    data_root.mkdir()
    _make_complete_cache(data_root)

    def failed_catalog(*_args, **_kwargs):
        raise prepare_arc_agi_3.ArcPublicSetError("catalog unavailable")

    monkeypatch.setattr(prepare_arc_agi_3, "_fetch_public_catalog", failed_catalog)
    with pytest.raises(prepare_arc_agi_3.ArcPublicSetError, match="catalog unavailable"):
        prepare_arc_agi_3.prepare_public_set(
            data_root, data_root / ".candidate-test", output=io.StringIO(),
        )


def test_deployer_never_imports_downloaded_game_source():
    source = Path(prepare_arc_agi_3.__file__).read_text(encoding="utf-8")
    assert "module_from_spec" not in source
    assert "exec_module" not in source
    assert "_write_fingerprint_preview" in source


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


def test_http_download_streams_and_closes_response():
    response = _StreamingResponse((b"ab", b"", b"cd"), content_length="4")
    session = _StreamingSession(response)

    content = prepare_arc_agi_3._get_content(
        session,
        "/api/example",
        maximum_bytes=4,
        accept="text/plain",
    )

    assert content == b"abcd"
    assert session.calls == [
        (
            f"{prepare_arc_agi_3.BASE_URL}/api/example",
            {
                "headers": {"Accept": "text/plain"},
                "timeout": (10, 90),
                "allow_redirects": False,
                "stream": True,
            },
        )
    ]
    assert response.iterated == 3
    assert response.closed is True


def test_http_download_stops_before_buffering_oversized_stream():
    response = _StreamingResponse((b"1234", b"5678", b"must-not-be-read"))
    session = _StreamingSession(response)

    with pytest.raises(
        prepare_arc_agi_3.ArcPublicSetError,
        match="超过安全大小限制",
    ):
        prepare_arc_agi_3._get_content(
            session,
            "/api/example",
            maximum_bytes=6,
            accept="text/plain",
        )

    assert response.iterated == 2
    assert response.closed is True


@pytest.mark.parametrize("declared_size", ("7", "-1", "invalid"))
def test_http_download_rejects_invalid_or_oversized_content_length(declared_size):
    response = _StreamingResponse((b"must-not-be-read",), content_length=declared_size)
    session = _StreamingSession(response)

    with pytest.raises(prepare_arc_agi_3.ArcPublicSetError):
        prepare_arc_agi_3._get_content(
            session,
            "/api/example",
            maximum_bytes=6,
            accept="text/plain",
        )

    assert response.iterated == 0
    assert response.closed is True
