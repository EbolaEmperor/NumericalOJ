# -*- coding: utf-8 -*-
"""测试环境护栏纯逻辑测试；不得连接 MySQL、Redis 或网络。"""

from __future__ import annotations

import pytest

from tests.environment_guard import (
    DestructiveTestTarget,
    UnsafeTestEnvironmentError,
    assert_disposable_test_target,
    unsafe_environment_reasons,
)
from tests import conftest as test_fixtures


def _target(**overrides) -> DestructiveTestTarget:
    values = {
        "test_env": "1",
        "hostname": "developer-mac",
        "checkout_path": "/Users/developer/NumericalOJ",
        "mysql_host": "127.0.0.1",
        "mysql_db": "myojdb_test",
        "redis_host": "localhost",
        "redis_db": 15,
    }
    values.update(overrides)
    return DestructiveTestTarget(**values)


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"mysql_host": "mysql", "redis_host": "redis"},
        {"mysql_host": "127.9.8.7", "redis_host": "[::1]"},
        {"mysql_db": "test_numoj", "redis_db": "14"},
        {"mysql_db": "numoj_test_worker_2"},
    ],
)
def test_accepts_explicitly_disposable_targets(overrides):
    target = _target(**overrides)

    assert unsafe_environment_reasons(target) == ()
    assert_disposable_test_target(target)


@pytest.mark.parametrize("value", [None, "", "0", "true", "yes", " 01 "])
def test_requires_exact_test_environment_opt_in(value):
    reasons = unsafe_environment_reasons(_target(test_env=value))

    assert any("NUMOJ_TEST_ENV=1" in reason for reason in reasons)


@pytest.mark.parametrize(
    "hostname",
    ["computing", "COMPUTING", "computing.local", "why-server", ""],
)
def test_rejects_known_production_hosts(hostname):
    reasons = unsafe_environment_reasons(_target(hostname=hostname))

    assert any("主机" in reason for reason in reasons)


@pytest.mark.parametrize(
    "checkout",
    ["/home/ebola/oj", "/home/ebola/oj/tests", "/home/ebola/oj/", "/home/ebola/oj/../oj", "relative/checkout"],
)
def test_rejects_production_checkout(checkout):
    reasons = unsafe_environment_reasons(_target(checkout_path=checkout))

    assert any("检出目录" in reason for reason in reasons)


@pytest.mark.parametrize("mysql_db", ["myojdb", "MYOJDB", "numoj", "", "production"])
def test_rejects_default_or_non_test_database(mysql_db):
    reasons = unsafe_environment_reasons(_target(mysql_db=mysql_db))

    assert any("MYSQL_DB" in reason for reason in reasons)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mysql_host", "10.0.0.8"),
        ("mysql_host", "db.internal.example"),
        ("redis_host", "10.0.0.9"),
        ("redis_host", "cache.internal.example"),
    ],
)
def test_rejects_remote_data_targets(field, value):
    reasons = unsafe_environment_reasons(_target(**{field: value}))

    assert any(field.upper() in reason for reason in reasons)


@pytest.mark.parametrize("redis_db", [0, "0", -1, "not-an-int", None])
def test_requires_dedicated_non_default_redis_database(redis_db):
    reasons = unsafe_environment_reasons(_target(redis_db=redis_db))

    assert any("REDIS_DB" in reason for reason in reasons)


def test_assertion_reports_every_unsafe_fact_at_once():
    target = _target(
        test_env=None,
        hostname="computing.example.com",
        checkout_path="/home/ebola/oj/tests",
        mysql_host="prod-db.internal",
        mysql_db="myojdb",
        redis_host="prod-redis.internal",
        redis_db=0,
    )

    with pytest.raises(UnsafeTestEnvironmentError) as error:
        assert_disposable_test_target(target)

    message = str(error.value)
    assert "NUMOJ_TEST_ENV=1" in message
    assert "生产主机" in message
    assert "生产检出目录" in message
    assert "MYSQL_HOST" in message
    assert "MYSQL_DB" in message
    assert "REDIS_HOST" in message
    assert "REDIS_DB" in message


def test_filesystem_reset_removes_stale_ranking_artifacts(tmp_path, monkeypatch):
    ranking_root = tmp_path / "ranking_uploads"
    stale_submission = ranking_root / "submissions" / "1" / "answer.zip"
    stale_submission.parent.mkdir(parents=True)
    stale_submission.write_bytes(b"stale")
    monkeypatch.setattr(test_fixtures, "OJ_ROOT", tmp_path)
    monkeypatch.setattr(
        test_fixtures,
        "_assert_destructive_test_environment",
        lambda: None,
    )

    test_fixtures._reset_test_filesystem_artifacts()

    assert ranking_root.is_dir()
    assert not list(ranking_root.iterdir())


def test_filesystem_reset_refuses_symlinked_artifact_root(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    (tmp_path / "ranking_uploads").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(test_fixtures, "OJ_ROOT", tmp_path)
    monkeypatch.setattr(
        test_fixtures,
        "_assert_destructive_test_environment",
        lambda: None,
    )

    with pytest.raises(pytest.fail.Exception, match="拒绝清理异常测试产物根目录"):
        test_fixtures._reset_test_filesystem_artifacts()

    assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
