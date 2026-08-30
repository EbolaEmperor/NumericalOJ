from flask import Flask

from backend.oj_modules.routes.health_routes import create_health_blueprint


class _FakeCursor:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    def execute(self, _sql):
        return 1

    def fetchone(self):
        return {'1': 1}


class _FakeConnection:
    def __init__(self, close_error=None):
        self.closed = False
        self.close_error = close_error

    def cursor(self):
        return _FakeCursor()

    def close(self):
        self.closed = True
        if self.close_error:
            raise self.close_error


class _FakeRedis:
    def __init__(self, result=True):
        self.result = result

    def ping(self):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _make_client(redis_client, connection_factory):
    app = Flask(__name__)
    app.register_blueprint(create_health_blueprint(redis_client, connection_factory))
    return app.test_client()


def test_live_probe_has_no_external_dependency():
    client = _make_client(_FakeRedis(RuntimeError('不应访问')), lambda: (_ for _ in ()).throw(RuntimeError()))

    response = client.get('/health/live')

    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}


def test_ready_probe_reports_all_dependencies():
    connection = _FakeConnection()
    client = _make_client(_FakeRedis(), lambda: connection)

    response = client.get('/health/ready')

    assert response.status_code == 200
    assert response.get_json() == {
        'status': 'ok',
        'checks': {'mysql': True, 'redis': True},
    }
    assert connection.closed is True


def test_ready_probe_fails_closed_without_exposing_exception():
    client = _make_client(
        _FakeRedis(RuntimeError('redis secret')),
        lambda: (_ for _ in ()).throw(RuntimeError('mysql secret')),
    )

    response = client.get('/health/ready')

    assert response.status_code == 503
    assert response.get_json() == {
        'status': 'unavailable',
        'checks': {'mysql': False, 'redis': False},
    }


def test_ready_probe_treats_connection_cleanup_failure_as_unavailable():
    connection = _FakeConnection(close_error=RuntimeError('close secret'))
    client = _make_client(_FakeRedis(), lambda: connection)

    response = client.get('/health/ready')

    assert response.status_code == 503
    assert response.get_json() == {
        'status': 'unavailable',
        'checks': {'mysql': False, 'redis': True},
    }
