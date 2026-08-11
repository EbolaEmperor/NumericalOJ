"""VibeHub 内置规范源同步的哈希、幂等与原子替换契约。"""

from io import BytesIO
import hashlib
import json
from pathlib import Path

from PIL import Image

from deploy import sync_vibehub_builtins as sync
from oj_modules.vibehub import storage


def _cover_bytes():
    output = BytesIO()
    Image.new("RGB", (900, 900), (222, 190, 142)).save(output, format="PNG")
    return output.getvalue()


def _source_tree(root):
    source = root / "vibehub_examples" / "circle-cat"
    (source / "static").mkdir(parents=True)
    (source / "Dockerfile").write_text(
        "FROM numericaloj-vibehub-runtime:1\nCOPY . /app\n",
        encoding="utf-8",
    )
    (source / "vibehub.json").write_text(
        json.dumps({
            "schema_version": 1,
            "transport": "unix",
            "socket_path": "/run/vibehub/app.sock",
            "health_path": "/healthz",
            "cover_image": "static/cover.png",
        }),
        encoding="utf-8",
    )
    (source / "app.py").write_text("print('v1')\n", encoding="utf-8")
    (source / "static" / "cover.png").write_bytes(_cover_bytes())
    return source


def _all_files(source):
    return sorted(
        (path for path in source.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(source).as_posix(),
    )


def _sync_circle(monkeypatch, repository, upload_root):
    source = repository / "vibehub_examples" / "circle-cat"
    monkeypatch.setattr(sync, "_tracked_source_files", lambda *_args: _all_files(source))
    return sync.sync_builtin(
        "circle-cat",
        repository_root=repository,
        source_root=repository / "vibehub_examples",
        upload_root=upload_root,
    )


def _arc_cache(root):
    cache = root / ".staging"
    games = []
    source = b"# MIT License\n# safe synthetic game\n"
    preview = b"\x89PNG\r\n\x1a\nsynthetic"
    for index in range(25):
        slug = f"g{index:03d}"
        version = f"{index:08x}"
        source_dir = cache / "environments" / slug / version
        source_dir.mkdir(parents=True)
        (source_dir / f"{slug}.py").write_bytes(source)
        (cache / "previews").mkdir(exist_ok=True)
        (cache / "previews" / f"{slug}.png").write_bytes(preview)
        games.append({
            "slug": slug,
            "version": version,
            "full_id": f"{slug}-{version}",
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "preview_sha256": hashlib.sha256(preview).hexdigest(),
        })
    set_id = hashlib.sha256(json.dumps(
        games,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")).hexdigest()
    (cache / "manifest.json").write_text(json.dumps({
        "schema_version": 1,
        "set_id": set_id,
        "game_count": 25,
        "games": games,
    }), encoding="utf-8")
    final = root / set_id
    cache.rename(final)
    return final


def test_tree_hash_ignores_mtime_but_detects_content(tmp_path):
    source = _source_tree(tmp_path)
    files = _all_files(source)
    first = sync._tree_sha256(source, list(reversed(files)))
    (source / "app.py").touch()
    assert sync._tree_sha256(source, files) == first
    (source / "app.py").write_text("print('v2')\n", encoding="utf-8")
    assert sync._tree_sha256(source, files) != first


def test_sync_is_idempotent_and_reinstalls_tampered_snapshot(tmp_path, monkeypatch):
    source = _source_tree(tmp_path)
    upload_root = tmp_path / "uploads" / "vibehub"

    status, source_hash = _sync_circle(monkeypatch, tmp_path, upload_root)
    assert status == "updated"
    deployment = storage.resolve_builtin_deployment(
        "circle-cat", upload_root=upload_root,
    )
    pointer = upload_root / "circle-cat" / "builtin" / "current.json"
    pointer_mtime = pointer.stat().st_mtime_ns
    installed_app = Path(deployment["package_dir"]) / "app.py"

    status, repeated_hash = _sync_circle(monkeypatch, tmp_path, upload_root)
    assert status == "unchanged"
    assert repeated_hash == source_hash
    assert pointer.stat().st_mtime_ns == pointer_mtime

    installed_app.write_text("tampered\n", encoding="utf-8")
    status, repaired_hash = _sync_circle(monkeypatch, tmp_path, upload_root)
    assert status == "updated"
    assert repaired_hash == source_hash
    repaired = storage.resolve_builtin_deployment("circle-cat", upload_root=upload_root)
    assert (Path(repaired["package_dir"]) / "app.py").read_text() == "print('v1')\n"

    installed_cover = Path(repaired["release_dir"]) / storage.PROCESSED_COVER_FILENAME
    expected_cover = installed_cover.read_bytes()
    installed_cover.write_bytes(b"x")
    status, repaired_hash = _sync_circle(monkeypatch, tmp_path, upload_root)
    assert status == "updated"
    assert repaired_hash == source_hash
    repaired = storage.resolve_builtin_deployment("circle-cat", upload_root=upload_root)
    repaired_cover = Path(repaired["release_dir"]) / storage.PROCESSED_COVER_FILENAME
    assert repaired_cover.read_bytes() == expected_cover
    assert repaired["cover_sha256"] == hashlib.sha256(expected_cover).hexdigest()


def test_changed_source_keeps_old_release_until_deploy_is_finalized(
    tmp_path, monkeypatch,
):
    source = _source_tree(tmp_path)
    upload_root = tmp_path / "uploads" / "vibehub"
    _sync_circle(monkeypatch, tmp_path, upload_root)
    first = storage.resolve_builtin_deployment("circle-cat", upload_root=upload_root)
    releases = upload_root / "circle-cat" / "builtin" / "releases"
    first_release = first["release"]

    (source / "app.py").write_text("print('v2')\n", encoding="utf-8")
    status, _source_hash = _sync_circle(monkeypatch, tmp_path, upload_root)

    assert status == "updated"
    second = storage.resolve_builtin_deployment("circle-cat", upload_root=upload_root)
    assert second["release"] != first_release
    assert {path.name for path in releases.iterdir()} == {
        first_release,
        second["release"],
    }
    assert (Path(second["package_dir"]) / "app.py").read_text() == "print('v2')\n"

    finalized = sync.finalize_builtin("circle-cat", upload_root=upload_root)

    assert finalized == second["release"]
    assert [path.name for path in releases.iterdir()] == [second["release"]]


def test_arc_sync_freezes_all_25_verified_games_into_offline_app(tmp_path, monkeypatch):
    source = tmp_path / "vibehub_examples" / "arc-agi-3"
    (source / "static").mkdir(parents=True)
    (source / "Dockerfile").write_text(
        "FROM numericaloj-vibehub-runtime:1\nCOPY . /app\n", encoding="utf-8",
    )
    (source / "vibehub.json").write_text(json.dumps({
        "schema_version": 1,
        "transport": "unix",
        "socket_path": "/run/vibehub/app.sock",
        "health_path": "/healthz",
        "cover_image": "static/cover.png",
    }), encoding="utf-8")
    (source / "app.py").write_text("# standalone ARC app\n", encoding="utf-8")
    (source / "static" / "cover.png").write_bytes(_cover_bytes())
    cache = _arc_cache(tmp_path / "arc-cache")
    monkeypatch.setattr(sync, "_tracked_source_files", lambda *_args: _all_files(source))
    upload_root = tmp_path / "uploads" / "vibehub"

    status, _source_hash = sync.sync_builtin(
        "arc-agi-3",
        repository_root=tmp_path,
        source_root=tmp_path / "vibehub_examples",
        upload_root=upload_root,
        arc_set=cache,
    )

    assert status == "updated"
    deployed = storage.resolve_builtin_deployment("arc-agi-3", upload_root=upload_root)
    offline = Path(deployed["package_dir"]) / "offline_data"
    payload = json.loads((offline / "manifest.json").read_text(encoding="utf-8"))
    assert payload["game_count"] == 25
    assert len(list((offline / "environments").glob("*/*/*.py"))) == 25
    assert deployed["arc_set_id"] == cache.name
