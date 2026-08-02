# -*- coding: utf-8 -*-

import io
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask import Flask

from oj_modules.routes import admin_problem_routes


def _upload_app():
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY='test-secret')
    app.register_blueprint(admin_problem_routes.admin_problem_bp)
    return app


def test_concurrent_same_name_uploads_use_isolated_temporary_roots(
    monkeypatch,
    tmp_path,
):
    monkeypatch.chdir(tmp_path)
    app = _upload_app()
    monkeypatch.setattr(
        admin_problem_routes,
        'current_user',
        lambda: {'id': 1, 'username': 'admin', 'is_admin': 1},
    )
    monkeypatch.setattr(admin_problem_routes, 'is_admin', lambda _user: True)

    barrier = threading.Barrier(2)
    records = []
    records_lock = threading.Lock()

    def _fake_import(*, problem_id, zip_path, extract_dir):
        archive_path = Path(zip_path).resolve()
        extraction_path = Path(extract_dir).resolve()
        payload = archive_path.read_bytes()
        extraction_path.mkdir(parents=True)
        marker = extraction_path / 'request.marker'
        marker.write_bytes(payload)

        with records_lock:
            records.append((problem_id, archive_path, extraction_path, payload))

        # 两个请求都已保存并写入各自解压目录后再检查，确定性覆盖旧实现中
        # `tmp/<同名文件>` 与 `tmp/extracted_<problem_id>` 的相互覆盖问题。
        barrier.wait(timeout=5)
        assert archive_path.read_bytes() == payload
        assert marker.read_bytes() == payload

    monkeypatch.setattr(
        admin_problem_routes,
        'import_testdata_zip',
        _fake_import,
    )

    def _post(payload):
        with app.test_client() as client:
            return client.post(
                '/admin/upload_testdata/7',
                data={'testdata_zip': (io.BytesIO(payload), 'same-name.zip')},
                headers={'Accept': 'application/json'},
                content_type='multipart/form-data',
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(_post, b'first-request'),
            executor.submit(_post, b'second-request'),
        ]
        responses = [future.result(timeout=10) for future in futures]

    assert [response.status_code for response in responses] == [200, 200]
    assert all(response.get_json()['success'] is True for response in responses)
    assert len(records) == 2

    request_roots = {archive_path.parent for _, archive_path, _, _ in records}
    assert len(request_roots) == 2
    assert {payload for _, _, _, payload in records} == {
        b'first-request',
        b'second-request',
    }
    for _problem_id, archive_path, extraction_path, _payload in records:
        assert archive_path.parent == extraction_path.parent
        assert not archive_path.parent.exists()


def test_failed_upload_also_cleans_its_temporary_root(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    app = _upload_app()
    monkeypatch.setattr(
        admin_problem_routes,
        'current_user',
        lambda: {'id': 1, 'username': 'admin', 'is_admin': 1},
    )
    monkeypatch.setattr(admin_problem_routes, 'is_admin', lambda _user: True)
    request_roots = []

    def _reject_import(*, problem_id, zip_path, extract_dir):
        assert problem_id == 7
        archive_path = Path(zip_path).resolve()
        extraction_path = Path(extract_dir).resolve()
        request_roots.append(archive_path.parent)
        extraction_path.mkdir(parents=True)
        (extraction_path / 'partial.in').write_text('partial', encoding='utf-8')
        raise admin_problem_routes.TestdataValidationError('模拟校验失败')

    monkeypatch.setattr(
        admin_problem_routes,
        'import_testdata_zip',
        _reject_import,
    )

    with app.test_client() as client:
        response = client.post(
            '/admin/upload_testdata/7',
            data={'testdata_zip': (io.BytesIO(b'invalid'), 'testdata.zip')},
            headers={'Accept': 'application/json'},
            content_type='multipart/form-data',
        )

    assert response.status_code == 400
    assert response.get_json()['message'] == '模拟校验失败'
    assert len(request_roots) == 1
    assert not request_roots[0].exists()
