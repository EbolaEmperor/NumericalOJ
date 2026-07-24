#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""全站登录边界与安全登录返回路径的回归测试。"""

from pathlib import Path

import pytest
from flask import Flask, session

from oj_modules.request_auth import install_global_login_guard, safe_local_next
from oj_modules.routes import auth_routes


ROOT = Path(__file__).resolve().parents[2]


def _guarded_app():
    app = Flask(__name__)
    app.config.update(SECRET_KEY='test-secret', TESTING=True)

    app.add_url_rule('/login', endpoint='auth.login', view_func=lambda: 'login')
    app.add_url_rule('/register', endpoint='auth.register', view_func=lambda: 'register')
    app.add_url_rule(
        '/send_code',
        endpoint='auth.send_verification',
        view_func=lambda: ('', 204),
        methods=['POST'],
    )
    app.add_url_rule(
        '/forgot_password',
        endpoint='auth.forgot_password',
        view_func=lambda: 'forgot',
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/send_password_code',
        endpoint='auth.send_password_code',
        view_func=lambda: ('', 204),
        methods=['POST'],
    )
    app.add_url_rule(
        '/change_password',
        endpoint='auth.change_password',
        view_func=lambda: ('', 204),
        methods=['POST'],
    )
    app.add_url_rule(
        '/logout',
        endpoint='auth.logout',
        view_func=lambda: ('', 204),
        methods=['POST'],
    )
    app.add_url_rule('/health/live', endpoint='health.live', view_func=lambda: 'live')
    app.add_url_rule('/health/ready', endpoint='health.ready', view_func=lambda: 'ready')
    app.add_url_rule('/private', endpoint='private', view_func=lambda: 'private')
    app.add_url_rule('/api/private', endpoint='api.private', view_func=lambda: {'ok': True})

    install_global_login_guard(
        app,
        user_loader=lambda: {'username': session['username']} if session.get('username') else None,
    )
    return app


def test_html_and_unknown_pages_redirect_to_login_with_original_target():
    client = _guarded_app().test_client()

    response = client.get('/private?tab=latest&page=2')
    assert response.status_code == 302
    assert response.headers['Location'].endswith(
        '/login?next=/private?tab%3Dlatest%26page%3D2'
    )

    missing = client.get('/does-not-exist')
    assert missing.status_code == 302
    assert missing.headers['Location'].endswith('/login?next=/does-not-exist')


def test_api_routes_and_unknown_api_paths_always_return_json_401():
    client = _guarded_app().test_client()

    for path in ('/api/private', '/api/does-not-exist', '/api'):
        response = client.get(path, headers={'Accept': 'text/html'})
        assert response.status_code == 401
        assert response.is_json
        assert response.get_json() == {'success': False, 'message': '请先登录'}
        assert 'Location' not in response.headers


@pytest.mark.parametrize(
    ('method', 'path', 'expected_status'),
    (
        ('get', '/login', 200),
        ('get', '/register', 200),
        ('post', '/send_code', 204),
        ('get', '/forgot_password', 200),
        ('post', '/forgot_password?step=verify', 200),
        ('get', '/health/live', 200),
        ('get', '/health/ready', 200),
        ('get', '/favicon.ico', 404),
        ('get', '/static/missing.css', 404),
    ),
)
def test_only_declared_public_flows_and_assets_are_exempt(method, path, expected_status):
    response = getattr(_guarded_app().test_client(), method)(path)
    assert response.status_code == expected_status
    assert 'Location' not in response.headers


def test_authenticated_request_reaches_routes_and_normal_404():
    client = _guarded_app().test_client()
    with client.session_transaction() as persisted_session:
        persisted_session['username'] = 'alice'

    assert client.get('/private').get_data(as_text=True) == 'private'
    assert client.get('/api/private').get_json() == {'ok': True}
    assert client.get('/does-not-exist').status_code == 404


@pytest.mark.parametrize('path', ('/send_password_code', '/change_password', '/logout'))
def test_account_mutations_are_not_public_exemptions(path):
    response = _guarded_app().test_client().post(path)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(f'/login?next={path}')


@pytest.mark.parametrize(
    'request_kwargs',
    (
        {'headers': {'X-Requested-With': 'XMLHttpRequest'}},
        {'headers': {'Accept': 'application/json'}},
        {'json': {}},
    ),
)
def test_non_api_path_json_requests_receive_json_401(request_kwargs):
    response = _guarded_app().test_client().post(
        '/change_password',
        **request_kwargs,
    )

    assert response.status_code == 401
    assert response.get_json() == {'success': False, 'message': '请先登录'}
    assert 'Location' not in response.headers


@pytest.mark.parametrize(
    'candidate',
    (
        None,
        '',
        'forum/thread/7',
        '//evil.example/path',
        '///evil.example/path',
        r'/\evil.example/path',
        r'\evil.example/path',
        '/%5cevil.example/path',
        '/%2f%2fevil.example/path',
        '/%255cevil.example/path',
        'https://evil.example/path',
        'javascript:alert(1)',
        '/safe#https://evil.example',
        '/safe\nLocation: https://evil.example',
    ),
)
def test_safe_local_next_rejects_external_or_ambiguous_targets(candidate):
    assert safe_local_next(candidate) is None


def test_safe_local_next_accepts_path_and_query_only():
    target = '/forum/thread/7?sort=oldest&from=%E8%AE%A8%E8%AE%BA'
    assert safe_local_next(target) == target


def _login_app():
    app = Flask(__name__, template_folder=str(ROOT / 'templates'))
    app.config.update(SECRET_KEY='test-secret', TESTING=True)
    app.add_url_rule(
        '/problems',
        endpoint='problem_core.problem_list',
        view_func=lambda: 'problems',
    )
    app.register_blueprint(auth_routes.auth_bp)
    return app


def _patch_successful_login(monkeypatch):
    monkeypatch.setattr(
        auth_routes,
        'validate_username',
        lambda username: (True, username, ''),
    )
    monkeypatch.setattr(auth_routes, 'rate_limit_hit', lambda *_args: (True, 0))
    monkeypatch.setattr(
        auth_routes,
        'get_user_by_username',
        lambda username: {
            'id': 7,
            'username': username,
            'is_admin': 0,
            'password_hash': 'stored',
        },
    )
    monkeypatch.setattr(auth_routes, 'verify_password', lambda *_args: (True, False))
    monkeypatch.setattr(auth_routes, 'emit_audit', lambda *_args, **_kwargs: None)


def test_login_success_returns_to_valid_local_next(monkeypatch):
    _patch_successful_login(monkeypatch)
    target = '/forum/thread/7?sort=oldest'

    response = _login_app().test_client().post(
        '/login',
        data={'username': 'alice', 'password': 'secret', 'next': target},
    )

    assert response.status_code == 302
    assert response.headers['Location'].endswith(target)


@pytest.mark.parametrize(
    'target',
    (
        '//evil.example/phishing',
        'https://evil.example/phishing',
        r'/\evil.example/phishing',
    ),
)
def test_login_success_ignores_malicious_next(monkeypatch, target):
    _patch_successful_login(monkeypatch)

    response = _login_app().test_client().post(
        '/login',
        data={'username': 'alice', 'password': 'secret', 'next': target},
    )

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/problems')


def test_login_form_carries_the_validated_next_target():
    template = (ROOT / 'templates' / 'auth' / 'login.html').read_text(encoding='utf-8')
    assert 'name="next" value="{{ next_url }}"' in template
