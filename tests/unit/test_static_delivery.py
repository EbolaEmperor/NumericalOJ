import gzip
import os
from pathlib import Path
import subprocess

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
    assert "Accept-Encoding" in not_modified.headers["Vary"]


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
    sidecars = sorted((ROOT / "static").rglob("*.br"))
    assert [Path(str(path)[:-3]) for path in sidecars] == expected_sources
    for brotli_path in sidecars:
        source = Path(str(brotli_path)[:-3])
        gzip_path = Path(f"{source}.gz")
        assert source.is_file(), source
        assert gzip_path.is_file(), gzip_path
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
            *(str(path) for path in sidecars),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
