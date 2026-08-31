import gzip
import os
from pathlib import Path
import subprocess

import pytest

from backend.oj_modules.shared.static_delivery import PrecompressedStaticFlask


ROOT = Path(__file__).resolve().parents[2]


def _write_asset(root, name, raw):
    source = root / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(raw)
    source.with_name(f"{source.name}.br").write_bytes(b"brotli-sidecar")
    source.with_name(f"{source.name}.gz").write_bytes(gzip.compress(raw))


def test_static_delivery_prefers_brotli_then_gzip(tmp_path):
    raw = b"console.log('fast');" * 100
    _write_asset(tmp_path, "app.js", raw)
    app = PrecompressedStaticFlask(
        __name__, static_folder=str(tmp_path), static_url_path="/static",
    )
    client = app.test_client()

    brotli_response = client.get(
        "/static/app.js",
        headers={"Accept-Encoding": "gzip, br"},
    )
    gzip_response = client.get(
        "/static/app.js",
        headers={"Accept-Encoding": "gzip"},
    )
    identity_response = client.get("/static/app.js")

    assert brotli_response.status_code == 200
    assert brotli_response.headers["Content-Encoding"] == "br"
    assert "Accept-Encoding" in brotli_response.headers["Vary"]
    assert brotli_response.data == b"brotli-sidecar"
    assert gzip_response.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(gzip_response.data) == raw
    assert "Content-Encoding" not in identity_response.headers
    assert "Accept-Encoding" in identity_response.headers["Vary"]
    assert identity_response.data == raw
    assert len({
        brotli_response.headers["ETag"],
        gzip_response.headers["ETag"],
        identity_response.headers["ETag"],
    }) == 3

    not_modified = client.get(
        "/static/app.js",
        headers={
            "Accept-Encoding": "br",
            "If-None-Match": brotli_response.headers["ETag"],
        },
    )
    assert not_modified.status_code == 304
    assert "Content-Encoding" not in not_modified.headers
    assert "Accept-Encoding" in not_modified.headers["Vary"]
    assert not_modified.headers["ETag"] == brotli_response.headers["ETag"]
    assert "Content-Length" not in not_modified.headers


@pytest.mark.parametrize(
    ("accept_encoding", "expected_encoding"),
    (
        ("gzip;q=.8, identity;q=1", None),
        ("br;q=0.4, gzip;q=.8, identity;q=0.5", "gzip"),
        ("gzip;q=0, *;q=.5, identity;q=0", "br"),
        ("br;q=0, gzip;q=0", None),
        ("gzip;q=invalid, identity;q=invalid", None),
    ),
)
def test_static_delivery_honors_identity_wildcard_and_quality_values(
    tmp_path,
    accept_encoding,
    expected_encoding,
):
    raw = b"quality negotiation" * 100
    _write_asset(tmp_path, "app.js", raw)
    app = PrecompressedStaticFlask(
        __name__, static_folder=str(tmp_path), static_url_path="/static",
    )

    response = app.test_client().get(
        "/static/app.js",
        headers={"Accept-Encoding": accept_encoding},
    )

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") == expected_encoding
    assert "Accept-Encoding" in response.headers["Vary"]
    if expected_encoding is None:
        assert response.data == raw
        assert response.headers["Content-Length"] == str(len(raw))
    elif expected_encoding == "gzip":
        assert gzip.decompress(response.data) == raw
    else:
        assert response.data == b"brotli-sidecar"


@pytest.mark.parametrize(
    "accept_encoding",
    (
        "br;q=0, gzip;q=0, identity;q=0",
        "*;q=0",
        "br;q=0, gzip;q=0, *;q=0",
    ),
)
def test_static_delivery_returns_406_when_every_representation_is_rejected(
    tmp_path,
    accept_encoding,
):
    _write_asset(tmp_path, "app.js", b"not acceptable" * 100)
    app = PrecompressedStaticFlask(
        __name__, static_folder=str(tmp_path), static_url_path="/static",
    )

    response = app.test_client().get(
        "/static/app.js",
        headers={"Accept-Encoding": accept_encoding},
    )

    assert response.status_code == 406
    assert response.data == b""
    assert "Content-Encoding" not in response.headers
    assert "Accept-Encoding" in response.headers["Vary"]


def test_static_delivery_head_and_range_keep_selected_representation_metadata(
    tmp_path,
):
    raw = b"range response" * 100
    _write_asset(tmp_path, "app.js", raw)
    encoded = (tmp_path / "app.js.br").read_bytes()
    app = PrecompressedStaticFlask(
        __name__, static_folder=str(tmp_path), static_url_path="/static",
    )
    client = app.test_client()

    full = client.get(
        "/static/app.js",
        headers={"Accept-Encoding": "br, identity;q=0"},
    )
    head = client.head(
        "/static/app.js",
        headers={"Accept-Encoding": "br, identity;q=0"},
    )
    partial = client.get(
        "/static/app.js",
        headers={
            "Accept-Encoding": "br, identity;q=0",
            "Range": "bytes=1-5",
        },
    )

    assert full.status_code == 200
    assert head.status_code == 200
    assert head.data == b""
    assert head.headers["Content-Encoding"] == "br"
    assert head.headers["Content-Length"] == str(len(encoded))
    assert head.headers["ETag"] == full.headers["ETag"]
    assert "Accept-Encoding" in head.headers["Vary"]

    assert partial.status_code == 206
    assert partial.data == encoded[1:6]
    assert partial.headers["Content-Encoding"] == "br"
    assert partial.headers["Content-Length"] == "5"
    assert partial.headers["Content-Range"] == f"bytes 1-5/{len(encoded)}"
    assert partial.headers["ETag"] == full.headers["ETag"]
    assert "Accept-Encoding" in partial.headers["Vary"]


def test_static_delivery_ignores_a_stale_sidecar(tmp_path):
    old = b"old" * 100
    current = b"current" * 100
    _write_asset(tmp_path, "app.js", old)
    source = tmp_path / "app.js"
    source.write_bytes(current)
    compressed = tmp_path / "app.js.br"
    source.touch()
    compressed.touch()
    source_stat = source.stat()
    compressed.touch()
    # 显式把旁路文件调旧，避免不同文件系统的时间分辨率影响断言。
    os.utime(compressed, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns - 1))

    app = PrecompressedStaticFlask(
        __name__, static_folder=str(tmp_path), static_url_path="/static",
    )
    response = app.test_client().get(
        "/static/app.js",
        headers={"Accept-Encoding": "br"},
    )

    assert "Content-Encoding" not in response.headers
    assert response.data == current


def test_static_delivery_falls_back_to_a_fresh_gzip_sidecar(tmp_path):
    raw = b"console.log('fallback');" * 100
    _write_asset(tmp_path, "app.js", raw)
    source = tmp_path / "app.js"
    brotli_path = tmp_path / "app.js.br"
    gzip_path = tmp_path / "app.js.gz"
    source.touch()
    source_stat = source.stat()
    os.utime(brotli_path, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns - 1))
    os.utime(gzip_path, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns + 1))

    app = PrecompressedStaticFlask(
        __name__, static_folder=str(tmp_path), static_url_path="/static",
    )
    response = app.test_client().get(
        "/static/app.js",
        headers={"Accept-Encoding": "br, gzip"},
    )

    assert response.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(response.data) == raw


def test_static_delivery_does_not_probe_or_serve_outside_static_root(tmp_path):
    static_root = tmp_path / "static"
    static_root.mkdir()
    _write_asset(tmp_path, "secret.js", b"secret" * 100)
    app = PrecompressedStaticFlask(
        __name__, static_folder=str(static_root), static_url_path="/static",
    )

    response = app.test_client().get(
        "/static/%2e%2e/secret.js",
        headers={"Accept-Encoding": "br"},
    )

    assert response.status_code == 404
    assert b"secret" not in response.data


def test_static_delivery_falls_back_to_untracked_legacy_assets(tmp_path):
    primary = tmp_path / "frontend-static"
    legacy = tmp_path / "legacy-static"
    primary.mkdir()
    legacy.mkdir()
    _write_asset(legacy, "articles/handout.pdf", b"legacy-pdf" * 100)
    app = PrecompressedStaticFlask(
        __name__,
        static_folder=str(primary),
        legacy_static_folder=str(legacy),
        static_url_path="/static",
    )

    response = app.test_client().get(
        "/static/articles/handout.pdf",
        headers={"Accept-Encoding": "gzip"},
    )

    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(response.data) == b"legacy-pdf" * 100


def test_tracked_frontend_asset_wins_over_legacy_fallback(tmp_path):
    primary = tmp_path / "frontend-static"
    legacy = tmp_path / "legacy-static"
    primary.mkdir()
    legacy.mkdir()
    _write_asset(primary, "app/layout.css", b"new-layout" * 100)
    _write_asset(legacy, "app/layout.css", b"old-layout" * 100)
    app = PrecompressedStaticFlask(
        __name__,
        static_folder=str(primary),
        legacy_static_folder=str(legacy),
        static_url_path="/static",
    )

    response = app.test_client().get("/static/app/layout.css")

    assert response.status_code == 200
    assert response.data == b"new-layout" * 100


def test_precompressed_assets_are_not_tracked():
    result = subprocess.run(
        ["git", "ls-files", "--", ":(glob)**/*.br", ":(glob)**/*.gz"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout == ""
