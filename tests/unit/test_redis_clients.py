import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from oj_modules.infrastructure.redis import (
    DEFAULT_BLOCKING_SOCKET_TIMEOUT_SECONDS,
    DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS,
    RedisClientProfile,
    create_binary_redis_client,
    create_blocking_redis_client,
    create_optional_redis_client,
    create_text_redis_client,
    redis_client_options,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class _FakeStrictRedis:
    def __init__(self, **kwargs):
        self.options = kwargs

    def ping(self):
        return True


class _FakeRedisModule:
    StrictRedis = _FakeStrictRedis


def _config(**overrides):
    values = {
        "REDIS_HOST": "redis.internal",
        "REDIS_PORT": "6380",
        "REDIS_DB": "7",
        "REDIS_SOCKET_TIMEOUT_SECONDS": "4.5",
        "REDIS_CONNECT_TIMEOUT_SECONDS": "1.25",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    ("factory", "decode_responses"),
    [
        (create_text_redis_client, True),
        (create_binary_redis_client, False),
    ],
)
def test_text_and_binary_profiles_preserve_connection_target_and_short_timeouts(
    factory,
    decode_responses,
):
    client = factory(config_module=_config(), redis_module=_FakeRedisModule)

    assert isinstance(client, _FakeStrictRedis)
    assert client.options == {
        "host": "redis.internal",
        "port": 6380,
        "db": 7,
        "decode_responses": decode_responses,
        "socket_connect_timeout": 1.25,
        "socket_timeout": 4.5,
        "health_check_interval": DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS,
    }


def test_blocking_profile_has_an_independent_read_timeout():
    client = create_blocking_redis_client(
        config_module=_config(REDIS_BLOCKING_SOCKET_TIMEOUT_SECONDS="45"),
        redis_module=_FakeRedisModule,
    )

    assert client.options["decode_responses"] is True
    assert client.options["socket_connect_timeout"] == 1.25
    assert client.options["socket_timeout"] == 45.0


def test_blocking_profile_default_is_longer_than_short_request_timeout():
    options = redis_client_options(
        RedisClientProfile.BLOCKING,
        config_module=_config(),
    )

    assert options["socket_timeout"] == DEFAULT_BLOCKING_SOCKET_TIMEOUT_SECONDS
    assert options["socket_timeout"] > 15.0


def test_connect_timeout_defaults_to_the_regular_socket_timeout():
    config = SimpleNamespace(
        REDIS_HOST="localhost",
        REDIS_PORT=6379,
        REDIS_DB=0,
        REDIS_SOCKET_TIMEOUT_SECONDS=2,
    )

    options = redis_client_options(config_module=config)

    assert options["socket_connect_timeout"] == 2.0
    assert options["socket_timeout"] == 2.0


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("REDIS_SOCKET_TIMEOUT_SECONDS", 0),
        ("REDIS_CONNECT_TIMEOUT_SECONDS", -1),
        ("REDIS_BLOCKING_SOCKET_TIMEOUT_SECONDS", "not-a-number"),
    ],
)
def test_invalid_timeout_configuration_fails_fast(name, value):
    config = _config(**{name: value})
    profile = (
        RedisClientProfile.BLOCKING
        if name == "REDIS_BLOCKING_SOCKET_TIMEOUT_SECONDS"
        else RedisClientProfile.TEXT
    )

    with pytest.raises(ValueError, match=name):
        redis_client_options(profile, config_module=config)


def test_unknown_profile_fails_fast():
    with pytest.raises(ValueError, match="未知 Redis client profile"):
        redis_client_options("unknown", config_module=_config())


def test_optional_client_verifies_connection_and_returns_client():
    client = create_optional_redis_client(
        config_module=_config(),
        redis_module=_FakeRedisModule,
    )

    assert isinstance(client, _FakeStrictRedis)


def test_optional_client_returns_none_when_cache_is_unavailable():
    class FailingClient(_FakeStrictRedis):
        def ping(self):
            raise OSError("redis unavailable")

    backend = SimpleNamespace(StrictRedis=FailingClient)

    assert create_optional_redis_client(
        config_module=_config(),
        redis_module=backend,
    ) is None


def test_production_modules_do_not_construct_redis_clients_outside_factory():
    allowed_file = PROJECT_ROOT / "oj_modules" / "infrastructure" / "redis.py"
    production_files = [PROJECT_ROOT / "oj.py"]
    production_files.extend((PROJECT_ROOT / "oj_modules").rglob("*.py"))
    violations = []

    for path in production_files:
        if path == allowed_file:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = function.attr if isinstance(function, ast.Attribute) else getattr(function, "id", None)
            if name in {"Redis", "StrictRedis"}:
                violations.append(f"{path.relative_to(PROJECT_ROOT)}:{node.lineno}")

    assert violations == []


def test_app_wires_blocking_profile_into_all_pubsub_caches():
    source = (PROJECT_ROOT / "oj.py").read_text(encoding="utf-8")

    assert "rds = create_text_redis_client()" in source
    assert "rds_binary = create_binary_redis_client()" in source
    assert "rds_blocking = create_blocking_redis_client()" in source
    for initializer in (
        "init_submission_snapshot_cache",
        "init_agent_progress_cache",
        "init_judge_progress_cache",
        "init_reverse_judge_progress_cache",
    ):
        assert f"{initializer}(rds, blocking_client=rds_blocking)" in source
