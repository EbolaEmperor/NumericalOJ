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
            ("guide", "list", "mine", "detail", "create", "update", "edit", "request-featured"),
        ),
        (
            ROOT / "skills" / "numoj-admin" / "scripts" / "numoj_admin.py",
            ("guide", "pending", "review", "featured-pending", "featured-review"),
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
