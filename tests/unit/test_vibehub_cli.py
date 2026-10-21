from __future__ import annotations

import importlib
import json
from argparse import Namespace
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_user_and_admin_vibehub_cli_groups_expose_expected_commands():
    cases = [
        (
            ROOT / "skills" / "numoj-user" / "scripts" / "numoj_user.py",
            ("guide", "list", "mine", "detail", "create", "update", "edit", "edu"),
        ),
        (
            ROOT / "skills" / "numoj-admin" / "scripts" / "numoj_admin.py",
            ("guide", "pending", "review", "featured", "edu"),
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


def test_both_clis_submit_git_as_json_and_reject_ambiguous_sources(monkeypatch):
    import pytest
    for skill, package in [("numoj-admin", "numoj_admin_cli"), ("numoj-user", "numoj_user_cli")]:
        monkeypatch.syspath_prepend(str(ROOT / "skills" / skill / "scripts"))
        module = importlib.import_module(f"{package}.vibehub")
        calls = []
        class Client:
            def request(self, *args, **kwargs):
                calls.append((args, kwargs))
        monkeypatch.setattr(module, 'client_from_args', lambda _args: Client())
        monkeypatch.setattr(module, '_build_output', lambda *_args: None)
        monkeypatch.setattr(module.common, 'require_file', lambda *_args: pytest.fail('Git must not open an upload'))
        args = Namespace(package=None, git_url='git@example.org:a/b.git', git_ref='main', title='测试', slug='demo')
        module.project_create(args)
        module.project_update(args)
        assert [args[1] for args, _ in calls] == ['/api/vibehub/projects', '/api/vibehub/projects/demo/versions']
        for _, kwargs in calls:
            assert kwargs['headers']['Accept'] == 'application/x-ndjson'
            assert kwargs['stream'] is True
            assert kwargs['json']['git_url'] == 'git@example.org:a/b.git'
            assert kwargs['json']['git_ref'] == 'main'
            assert kwargs['json']['source_type'] == 'git'
        args.package = 'also.zip'
        with pytest.raises(module.common.CliError):
            module.project_create(args)
        args.package = args.git_url = None
        with pytest.raises(module.common.CliError):
            module.project_update(args)
        assert len(calls) == 2


@pytest.mark.parametrize("skill,package", [
    ("numoj-admin", "numoj_admin_cli"),
    ("numoj-user", "numoj_user_cli"),
])
def test_edu_cli_uses_login_apis_and_preserves_retry_identifiers(skill, package, tmp_path, monkeypatch, capsys):
    monkeypatch.syspath_prepend(str(ROOT / "skills" / skill / "scripts"))
    module = importlib.import_module(f"{package}.vibehub")
    calls = []

    class Response:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        text = '{"success": true}'

        def json(self):
            return {"success": True}

    class Client:
        def request(self, method, path, **kwargs):
            calls.append((method, path, kwargs))
            return Response()

    monkeypatch.setattr(module, "client_from_args", lambda _args: Client())
    action = {"type": "run_code", "source": "int step(int x) { return x; }"}
    action_file = tmp_path / "action.json"
    action_file.write_text(json.dumps(action), encoding="utf-8")

    module.edu_launch(Namespace(slug="dynamic-balance", assignment_id=17))
    module.edu_launch(Namespace(slug="dynamic-balance", assignment_id=None))
    module.edu_state(Namespace(attempt_id="att-demo"))
    command = Namespace(attempt_id="att-demo", command_id="command-1", expected_seq=0, action=f"@{action_file}")
    module.edu_action(command)
    module.edu_action(command)  # 原样重试，不能悄悄更换去重编号。
    module.edu_submit(Namespace(attempt_id="att-demo", request_id="submit-1", expected_seq=1))
    module.edu_result(Namespace(attempt_id="att-demo", submission_id=None))
    module.edu_result(Namespace(attempt_id=None, submission_id=23))

    assert calls == [
        ("POST", "/api/vibehub/projects/dynamic-balance/edu/launch", {"json": {"assignment_id": 17}}),
        ("POST", "/api/vibehub/projects/dynamic-balance/edu/launch", {"json": {}}),
        ("GET", "/api/vibehub/edu/attempts/att-demo", {}),
        ("POST", "/api/vibehub/edu/attempts/att-demo/actions", {
            "json": {"command_id": "command-1", "expected_seq": 0, "action": action},
        }),
        ("POST", "/api/vibehub/edu/attempts/att-demo/actions", {
            "json": {"command_id": "command-1", "expected_seq": 0, "action": action},
        }),
        ("POST", "/api/vibehub/edu/attempts/att-demo/submit", {
            "json": {"request_id": "submit-1", "expected_seq": 1},
        }),
        ("GET", "/api/vibehub/edu/attempts/att-demo/result", {}),
        ("GET", "/api/vibehub/edu/submissions/23", {}),
    ]
    assert capsys.readouterr().out.count('"success": true') == 8

    for invalid in ("[]", "null", "not json"):
        command.action = invalid
        with pytest.raises(module.common.CliError, match="JSON 对象"):
            module.edu_action(command)
    assert len(calls) == 8


def test_admin_homework_edu_target_is_exclusive_and_sent_to_assignment_api(monkeypatch, capsys):
    monkeypatch.syspath_prepend(str(ROOT / "skills" / "numoj-admin" / "scripts"))
    cli = importlib.import_module("numoj_admin")
    module = importlib.import_module("numoj_admin_cli.homework")
    parser = cli.build_parser()
    args = parser.parse_args([
        "homework", "add", "--class-en", "C2026A", "--ddl", "2026-12-31T23:59",
        "--vibehub-project-id", "7",
    ])
    calls = []

    class Client:
        def request(self, *arguments, **kwargs):
            calls.append((arguments, kwargs))
            return object()

    monkeypatch.setattr(module, "client_from_args", lambda _args: Client())
    monkeypatch.setattr(module, "print_or_save_response", lambda _response: None)
    args.func(args)
    assert calls == [(("POST", "/api/admin/homework"), {"data": {
        "class_en": "C2026A", "ddl": "2026-12-31T23:59", "vibehub_project_id": "7",
    }})]
    with pytest.raises(SystemExit):
        parser.parse_args([
            "homework", "add", "--class-en", "C2026A", "--ddl", "2026-12-31T23:59",
            "--vibehub-project-id", "7", "--problem-id", "8",
        ])
    capsys.readouterr()


@pytest.mark.parametrize("skill,package", [
    ("numoj-admin", "numoj_admin_cli"),
    ("numoj-user", "numoj_user_cli"),
])
def test_project_projection_exposes_edu_eligibility_without_internal_manifest(skill, package, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "skills" / skill / "scripts"))
    module = importlib.import_module(f"{package}.vibehub")
    assert module.necessary_project({
        "id": 7, "kind": "edu", "education": {"protocol": "vibehub-edu/1"},
        "manifest_json": {"private": "internal"},
    }) == {"id": 7, "kind": "edu", "education": {"protocol": "vibehub-edu/1"}}
