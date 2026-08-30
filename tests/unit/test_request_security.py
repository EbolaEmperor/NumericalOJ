from flask import Flask

from backend.oj_modules.security.origin_guard import (
    install_same_origin_protection,
    is_same_origin,
)


def _make_client(trusted_origins=()):
    app = Flask(__name__)
    install_same_origin_protection(app, trusted_origins=trusted_origins)

    @app.route('/write', methods=['GET', 'POST', 'DELETE'])
    def write():
        return 'ok'

    app.add_url_rule(
        '/vibehub/runtime/<token>/<path:path>',
        endpoint='vibehub.runtime_proxy',
        view_func=lambda token, path: f'{token}:{path}',
        methods=['POST'],
    )

    app.add_url_rule(
        '/vibehub/runtime/<token>/heartbeat',
        endpoint='vibehub.runtime_heartbeat',
        view_func=lambda token: token,
        methods=['POST'],
    )

    return app.test_client()


def test_origin_comparison_normalizes_case_and_default_ports():
    assert is_same_origin('HTTPS://EXAMPLE.COM/form', 'https://example.com/')
    assert is_same_origin('http://example.com:80', 'http://example.com/')
    assert not is_same_origin('https://example.com', 'http://example.com/')
    assert not is_same_origin('https://example.com:444', 'https://example.com/')


def test_safe_method_does_not_require_browser_headers():
    response = _make_client().get('/write', headers={'Origin': 'https://attacker.example'})

    assert response.status_code == 200


def test_same_origin_browser_write_is_allowed():
    client = _make_client()

    assert client.post(
        '/write',
        base_url='https://numoj.example',
        headers={'Origin': 'https://numoj.example'},
    ).status_code == 200
    assert client.delete(
        '/write',
        base_url='https://numoj.example',
        headers={'Referer': 'https://numoj.example/page'},
    ).status_code == 200


def test_cross_origin_and_malformed_browser_writes_are_rejected():
    client = _make_client()

    assert client.post(
        '/write',
        base_url='https://numoj.example',
        headers={'Origin': 'https://attacker.example'},
    ).status_code == 403
    assert client.post(
        '/write',
        base_url='https://numoj.example',
        headers={'Origin': 'null'},
    ).status_code == 403


def test_only_exact_vibehub_proxy_endpoint_accepts_sandbox_null_origin():
    client = _make_client()

    proxy = client.post(
        '/vibehub/runtime/opaque-token/state/save',
        base_url='https://numoj.example',
        headers={'Origin': 'null'},
    )
    assert proxy.status_code == 200

    heartbeat = client.post(
        '/vibehub/runtime/opaque-token/heartbeat',
        base_url='https://numoj.example',
        headers={'Origin': 'null'},
    )
    assert heartbeat.status_code == 403

    cross_origin_proxy = client.post(
        '/vibehub/runtime/opaque-token/state/save',
        base_url='https://numoj.example',
        headers={'Origin': 'https://attacker.example'},
    )
    assert cross_origin_proxy.status_code == 403


def test_cli_write_without_origin_or_referer_remains_compatible():
    response = _make_client().post('/write')

    assert response.status_code == 200


def test_explicit_trusted_origin_accepts_reverse_proxy_public_origin():
    client = _make_client('https://public.example, https://second.example')

    response = client.post(
        '/write',
        base_url='http://internal-service:2025',
        headers={'Origin': 'https://public.example'},
    )

    assert response.status_code == 200
