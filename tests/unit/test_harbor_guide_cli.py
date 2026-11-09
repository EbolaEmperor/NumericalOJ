"""两个 CLI 从服务端获取同一份完整 Harbor 说明，而不是内置格式副本。"""

import importlib.util
import json
from pathlib import Path

from flask import Flask
import pytest
import requests

from backend.oj_modules.api.ranking_api import ranking_api_bp
from backend.oj_modules.ranking.reverse_judge.guide import HARBOR_GUIDE_PATH


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('role', ['admin', 'user'])
@pytest.mark.parametrize('save', [False, True])
def test_ranking_harbor_guide_fetches_server_markdown(role, save, tmp_path, monkeypatch, capsys):
    script = ROOT / 'skills' / f'numoj-{role}' / 'scripts' / f'numoj_{role}.py'
    spec = importlib.util.spec_from_file_location(f'numoj_{role}_harbor_guide_test', script)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    app = Flask(__name__)
    app.register_blueprint(ranking_api_bp)
    calls = []

    class Client:
        def request(self, method, path, **kwargs):
            calls.append((method, path, kwargs))
            served = app.test_client().open(path, method=method)
            response = requests.Response()
            response.status_code = served.status_code
            response.headers.update(served.headers)
            response._content = served.get_data()
            response.encoding = 'utf-8'
            served.close()
            return response

    client_module = cli.ranking if role == 'admin' else cli.common
    monkeypatch.setattr(client_module, 'client_from_args', lambda _args: Client())
    argv = ['ranking', 'harbor-guide']
    destination = tmp_path / 'guide.md'
    if save:
        argv.extend(['-o', str(destination)])

    assert cli.main(argv) == 0

    assert calls == [('GET', '/api/ranking/harbor-guide', {})]
    output = capsys.readouterr().out
    source = HARBOR_GUIDE_PATH.read_bytes()
    if save:
        assert destination.read_bytes() == source
        assert json.loads(output) == {'success': True, 'path': str(destination), 'bytes': len(source)}
    else:
        assert output.strip() == source.decode('utf-8').strip()
