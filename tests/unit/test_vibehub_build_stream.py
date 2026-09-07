from io import BytesIO
import importlib
import json
from pathlib import Path
import threading

from flask import Flask, request
import pytest

from backend.oj_modules.api import vibehub_api
from backend.oj_modules.vibehub import build_progress, services


@pytest.mark.parametrize('method,path,metadata_only', [('POST','/api/vibehub/projects',False),('POST','/api/vibehub/projects/demo/versions',False),('PATCH','/api/vibehub/projects/demo',True)])
def test_progress_arrives_before_result_and_upload_stays_open(monkeypatch, method, path, metadata_only):
    app=Flask(__name__);app.secret_key='local-test';app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api,'current_user',lambda:{'id':1})
    release=threading.Event(); entered=threading.Event()
    def operation(*args,**kwargs):
        assert kwargs['metadata_only'] is metadata_only
        upload=request.files['package'];assert upload.read()==b'zip-data'
        build_progress.emit('build','开始构建')
        entered.set();assert release.wait(3)
        assert not upload.closed
        return {'slug':'demo','latest_version':2}
    monkeypatch.setattr(vibehub_api,'_save_submission',operation)
    response=app.test_client().open(path,method=method,data={'package':(BytesIO(b'zip-data'),'app.zip')},headers={'Accept':'application/x-ndjson'},buffered=False)
    try:
        first=json.loads(next(response.response));assert first['phase']=='accepted'
        assert entered.wait(2)
        progress=json.loads(next(response.response));assert progress['message']=='开始构建'
        release.set()
        result=[json.loads(line) for chunk in response.response for line in chunk.splitlines()]
        assert result[-1]['event']=='result' and result[-1]['project']['latest_version']==2
        assert response.headers['X-Accel-Buffering']=='no'
    finally:
        release.set();response.close()


def test_stream_errors_are_structured_and_authentication_still_precedes_stream(monkeypatch):
    app=Flask(__name__);app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api,'current_user',lambda:None)
    assert app.test_client().post('/api/vibehub/projects',headers={'Accept':'application/x-ndjson'}).status_code==401
    monkeypatch.setattr(vibehub_api,'current_user',lambda:{'id':1})
    def fail(*args,**kwargs):raise services.VibeHubError('资源忙',status_code=429,code='capacity')
    monkeypatch.setattr(vibehub_api,'_save_submission',fail)
    response=app.test_client().post('/api/vibehub/projects',headers={'Accept':'application/x-ndjson'})
    events=[json.loads(line) for line in response.data.splitlines()]
    assert events[-1]=={'event':'error','success':False,'message':'资源忙','code':'capacity','http_status':429}
    assert not any(event['event']=='result' for event in events)


def test_build_output_handles_split_utf8_redacts_and_bounds_logs():
    events=[]
    with build_progress.capture(events.append):
        output=build_progress.BuildOutput()
        raw='中文 CACHED\nAuthorization: Bearer private-token\n'.encode()
        for byte in raw:output.feed(1,bytes([byte]))
        output.feed(1,b'')
        output.feed(2,b'x'*100000)
        output.total=2*1024*1024
        output.line('too much');output.line('also too much')
    assert events[0]['message']=='中文 CACHED'
    assert 'private-token' not in json.dumps(events)
    assert max(len(event['message']) for event in events)<4200
    assert sum('显示上限' in event['message'] for event in events)==1
    build_progress.emit('build','must not escape scope')


@pytest.mark.parametrize('skill,package',[('numoj-admin','numoj_admin_cli'),('numoj-user','numoj_user_cli')])
def test_cli_emits_progress_before_final_json(monkeypatch,capsys,skill,package):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]/'skills'/skill/'scripts'))
    module=importlib.import_module(package+'.vibehub')
    class Response:
        headers={'Content-Type':'application/x-ndjson'};status_code=200;closed=False
        def close(self):self.closed=True
        def iter_lines(self,**kwargs):
            yield json.dumps({'event':'log','message':'#1 CACHED'}).encode()
            output=capsys.readouterr();assert '#1 CACHED' in output.err and not output.out
            yield json.dumps({'event':'result','success':True,'project':{'slug':'demo','latest_version':4}}).encode()
    response=Response();module._build_output(response)
    assert json.loads(capsys.readouterr().out)['project']['latest_version']==4
    assert response.closed
    class Broken(Response):
        def iter_lines(self,**kwargs):yield b'{"event":"heartbeat","elapsed_seconds":5}'
    with pytest.raises(module.common.CliError,match='最终结果尚未确认'):module._build_output(Broken())
