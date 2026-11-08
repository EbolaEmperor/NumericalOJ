"""管理员 CLI 可下载内置 Harbor 附件，同时保留数字附件与删除边界。"""

import importlib.util
from pathlib import Path

import pytest


def _cli():
    path = Path(__file__).resolve().parents[2] / "skills/numoj-admin/scripts/numoj_admin.py"
    spec = importlib.util.spec_from_file_location("numoj_admin_harbor_template", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_download_parser_accepts_builtin_and_keeps_existing_numeric_ids():
    parser = _cli().build_parser()
    assert parser.parse_args(["ranking", "download-attachment", "7", "harbor-template"]).file_id == "harbor-template"
    assert parser.parse_args(["ranking", "download-attachment", "7", "009"]).file_id == 9
    with pytest.raises(SystemExit):
        parser.parse_args(["ranking", "download-attachment", "7", "../arbitrary"])
    with pytest.raises(SystemExit):
        parser.parse_args(["ranking", "delete-attachment", "7", "harbor-template"])
    assert parser.parse_args(["ranking", "delete-attachment", "7", "9"]).file_id == 9


@pytest.mark.parametrize("file_id", ["harbor-template", "9"])
def test_download_command_uses_existing_api_and_output_handler(monkeypatch, tmp_path, file_id):
    cli = _cli()
    requests, outputs = [], []
    response = object()

    class Client:
        def request(self, method, path, **kwargs):
            requests.append((method, path, kwargs))
            return response

    monkeypatch.setattr(cli.ranking, "client_from_args", lambda _args: Client())
    monkeypatch.setattr(cli.ranking, "print_or_save_response", lambda value, **kwargs: outputs.append((value, kwargs)))
    destination = tmp_path / "attachment.zip"
    assert cli.main(["ranking", "download-attachment", "7", file_id, "-o", str(destination)]) == 0
    assert requests == [("GET", f"/api/ranking/competitions/7/attachments/{file_id}/download", {"params": None})]
    assert outputs == [(response, {"output": str(destination)})]
