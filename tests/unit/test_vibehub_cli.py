from __future__ import annotations

import importlib
from argparse import Namespace
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def test_user_and_admin_vibehub_cli_groups_expose_expected_commands():
    cases = [
        (
            ROOT / "skills" / "numoj-user" / "scripts" / "numoj_user.py",
            ("guide", "list", "mine", "detail", "create", "update", "edit"),
        ),
        (
            ROOT / "skills" / "numoj-admin" / "scripts" / "numoj_admin.py",
            ("guide", "pending", "review", "featured"),
        ),
    ]
    for script, commands in cases:
        completed = subprocess.run(
            [sys.executable, str(script), "vibehub", "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        for command in commands:
            assert command in completed.stdout
        assert "request-featured" not in completed.stdout
        assert "featured-pending" not in completed.stdout
        assert "featured-review" not in completed.stdout


def test_vibehub_cli_payload_projection_keeps_review_state_and_drops_internal_fields(monkeypatch):
    user_scripts = ROOT / "skills" / "numoj-user" / "scripts"
    monkeypatch.syspath_prepend(str(user_scripts))
    module = importlib.import_module("numoj_user_cli.vibehub")

    projected = module.necessary_project_payload({
        "success": True,
        "project": {
            "slug": "demo-vibe",
            "title": "Demo",
            "submitted_version": 2,
            "has_pending_review": True,
            "latest_review_note": "fix it",
            "package_sha256": "secret-internal-detail",
            "manifest_json": {"socket_path": "/run/vibehub/app.sock"},
        },
    })

    assert projected == {
        "success": True,
        "project": {
            "slug": "demo-vibe",
            "title": "Demo",
            "submitted_version": 2,
            "has_pending_review": True,
            "latest_review_note": "fix it",
        },
    }


def test_user_cli_guide_fetches_markdown_from_server(monkeypatch, capsys):
    user_scripts = ROOT / "skills" / "numoj-user" / "scripts"
    monkeypatch.syspath_prepend(str(user_scripts))
    module = importlib.import_module("numoj_user_cli.vibehub")

    class Response:
        status_code = 200
        headers = {"Content-Type": "text/markdown; charset=utf-8"}
        text = "# VibeHub 开发者手册"
        content = text.encode("utf-8")

    class Client:
        def request(self, method, path, **kwargs):
            assert (method, path) == ("GET", "/api/vibehub/developer-guide")
            return Response()

    monkeypatch.setattr(module, "client_from_args", lambda _args: Client())
    module.developer_guide(Namespace(output=None))

    assert capsys.readouterr().out.strip() == "# VibeHub 开发者手册"


def test_both_clis_stream_multipart_and_support_lengths_above_four_gib(tmp_path, monkeypatch):
    import io
    import requests
    from werkzeug.formparser import parse_form_data
    from werkzeug.test import EnvironBuilder

    for skill, package in [("numoj-admin", "numoj_admin_cli"), ("numoj-user", "numoj_user_cli")]:
        monkeypatch.syspath_prepend(str(ROOT / "skills" / skill / "scripts"))
        module = importlib.import_module(f"{package}.multipart")
        path = tmp_path / "weights.zip"
        path.write_bytes(b"model weights")
        with path.open("rb") as handle:
            body = module.MultipartUpload({"title": "模型实验", "tag": [b"a", "b"], "skip": None}, {"package": ('权重".zip', handle)})
            prepared = requests.Request("POST", "http://localhost/upload", data=body,
                                        headers={"Content-Type": body.content_type}).prepare()
            assert prepared.body is body
            assert prepared.headers["Content-Length"] == str(len(body))
            assert "Transfer-Encoding" not in prepared.headers
            raw = b"".join(body)
            assert len(raw) == len(body)
            assert b"".join(body) == raw
            environ = EnvironBuilder(method="POST", input_stream=io.BytesIO(raw),
                                     content_length=len(raw), content_type=body.content_type).get_environ()
            _, form, files = parse_form_data(environ)
            assert form["title"] == "模型实验"
            assert form.getlist("tag") == ["a", "b"]
            assert "skip" not in form
            assert files["package"].read() == b"model weights"
            files["package"].close()
        with path.open("wb") as handle:
            handle.truncate(5 * 1024**3)
        with path.open("rb") as handle:
            body = module.MultipartUpload({}, {"package": (path.name, handle)})
            assert len(body) > 5 * 1024**3
            chunks = iter(body)
            next(chunks)  # multipart header
            assert len(next(chunks)) == 1024 * 1024


def test_cli_common_streams_all_file_uploads_and_preserves_headers(tmp_path, monkeypatch):
    for skill, package in [("numoj-admin", "numoj_admin_cli"), ("numoj-user", "numoj_user_cli")]:
        monkeypatch.syspath_prepend(str(ROOT / "skills" / skill / "scripts"))
        common = importlib.import_module(f"{package}.common")
        client = common.NumOJClient({"base_url": "http://localhost"})
        calls = []
        monkeypatch.setattr(client.session, "request", lambda *args, **kw: calls.append((args, kw)))
        path = tmp_path / "code.txt"
        path.write_bytes(b"print(1)")
        files = {"code_file": common.require_file(str(path)), "answer_file": common.require_file(str(path))}
        try:
            client.request("POST", "/upload", data={"title": "测试"}, files=files,
                           headers={"Accept": "application/json"})
            args, kwargs = calls[0]
            assert args == ("POST", "http://localhost/upload")
            assert "files" not in kwargs
            assert kwargs["headers"]["Accept"] == "application/json"
            assert kwargs["headers"]["Content-Type"] == kwargs["data"].content_type
            raw = b"".join(kwargs["data"])
            assert raw.count(b"print(1)") == 2
            assert len(raw) == len(kwargs["data"])
            path.write_bytes(b"x")
            import pytest
            with pytest.raises(OSError, match="截断"):
                b"".join(kwargs["data"])
        finally:
            common.close_files(files)
        assert all(handle.closed for _, handle in files.values())
