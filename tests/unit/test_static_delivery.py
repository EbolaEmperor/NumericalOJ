import gzip
import os
from pathlib import Path
import subprocess

import pytest

from oj_modules.shared.static_delivery import PrecompressedStaticFlask


ROOT = Path(__file__).resolve().parents[2]
PRECOMPRESS_MINIMUM_BYTES = 100 * 1024
PRECOMPRESS_EXTENSIONS = {".css", ".html", ".js", ".json", ".svg"}


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


def test_checked_in_precompressed_assets_match_sources():
    expected_sources = sorted(
        path
        for path in (ROOT / "static").rglob("*")
        if path.is_file()
        and path.suffix in PRECOMPRESS_EXTENSIONS
        and path.stat().st_size >= PRECOMPRESS_MINIMUM_BYTES
    )
    brotli_sidecars = sorted((ROOT / "static").rglob("*.br"))
    gzip_sidecars = sorted((ROOT / "static").rglob("*.gz"))
    assert [Path(str(path)[:-3]) for path in brotli_sidecars] == expected_sources
    assert [Path(str(path)[:-3]) for path in gzip_sidecars] == expected_sources
    for gzip_path in gzip_sidecars:
        source = Path(str(gzip_path)[:-3])
        assert source.is_file(), source
        raw = source.read_bytes()
        assert gzip.decompress(gzip_path.read_bytes()) == raw

    result = subprocess.run(
        [
            "node",
            "-e",
            (
                "const fs=require('node:fs');"
                "const z=require('node:zlib');"
                "for(const p of process.argv.slice(1)){"
                "const source=p.slice(0,-3);"
                "if(!z.brotliDecompressSync(fs.readFileSync(p))"
                ".equals(fs.readFileSync(source)))process.exit(1);"
                "}"
            ),
            *(str(path) for path in brotli_sidecars),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_precompress_build_removes_only_orphaned_sidecars(tmp_path):
    static_root = tmp_path / "static"
    static_root.mkdir()
    expected_source = static_root / "expected.js"
    expected_source.write_bytes(b"const expected = true;\n" * 6_000)
    expected_brotli = Path(f"{expected_source}.br")
    expected_gzip = Path(f"{expected_source}.gz")
    expected_brotli.write_bytes(b"stale-brotli")
    expected_gzip.write_bytes(b"stale-gzip")

    small_source = static_root / "small.js"
    small_source.write_bytes(b"small")
    orphaned = (
        Path(f"{small_source}.br"),
        Path(f"{small_source}.gz"),
        static_root / "missing.js.br",
        static_root / "missing.js.gz",
        static_root / "large.bin.br",
        static_root / "large.bin.gz",
    )
    for path in orphaned:
        path.write_bytes(b"orphaned")
    (static_root / "large.bin").write_bytes(b"x" * PRECOMPRESS_MINIMUM_BYTES)

    result = subprocess.run(
        ["node", str(ROOT / "scripts" / "precompress_static.mjs")],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert expected_source.is_file()
    assert expected_brotli.is_file()
    assert expected_gzip.is_file()
    assert gzip.decompress(expected_gzip.read_bytes()) == expected_source.read_bytes()
    brotli_result = subprocess.run(
        [
            "node",
            "-e",
            (
                "const fs=require('node:fs');"
                "const z=require('node:zlib');"
                "const raw=fs.readFileSync(process.argv[1]);"
                "const compressed=fs.readFileSync(process.argv[2]);"
                "if(!z.brotliDecompressSync(compressed).equals(raw))process.exit(1);"
            ),
            str(expected_source),
            str(expected_brotli),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert brotli_result.returncode == 0, brotli_result.stderr
    assert all(not path.exists() for path in orphaned)
