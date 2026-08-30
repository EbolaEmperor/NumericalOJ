# -*- coding: utf-8 -*-
"""测试环境护栏纯逻辑测试；不得连接 MySQL、Redis 或网络。"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from tests.environment_guard import (
    DestructiveTestTarget,
    DockerTestTarget,
    UnsafeDockerDaemonError,
    UnsafeTestEnvironmentError,
    assert_disposable_test_target,
    assert_local_docker_daemon,
    unsafe_docker_daemon_reasons,
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


def _docker_target(**overrides) -> DockerTestTarget:
    values = {
        "test_env": "1",
        "context_name": "colima-numericaloj-ci",
        "context_endpoint": "unix:///Users/developer/.colima/docker.sock",
        "docker_host_env": None,
    }
    values.update(overrides)
    return DockerTestTarget(**values)


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


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"context_endpoint": "unix:///var/run/docker.sock"},
        {"context_endpoint": "npipe:////./pipe/docker_engine"},
        {"context_endpoint": "tcp://127.0.0.1:2375"},
        {"context_endpoint": "tcp://localhost:2375"},
        {"context_endpoint": "tcp://[::1]:2375"},
        {"docker_host_env": "unix:///tmp/docker-test.sock"},
        {"docker_host_env": "tcp://127.0.0.1:2375"},
    ],
)
def test_accepts_only_provably_local_docker_daemons(overrides):
    target = _docker_target(**overrides)

    assert unsafe_docker_daemon_reasons(target) == ()
    assert_local_docker_daemon(target)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("context_endpoint", "ssh://deploy@why-server", "ssh"),
        ("context_endpoint", "tcp://10.72.190.121:2375", "非 loopback"),
        ("context_endpoint", "https://127.0.0.1:2376", "不受信任"),
        ("context_endpoint", "unix://relative.sock", "Unix socket"),
        ("context_endpoint", "", "为空"),
        ("docker_host_env", "ssh://deploy@why-server", "DOCKER_HOST"),
        ("docker_host_env", "tcp://docker.internal:2375", "DOCKER_HOST"),
    ],
)
def test_rejects_remote_or_ambiguous_docker_daemons(field, value, message):
    reasons = unsafe_docker_daemon_reasons(
        _docker_target(**{field: value}),
    )

    assert any(message in reason for reason in reasons)


def test_docker_guard_requires_opt_in_and_context_identity():
    target = _docker_target(
        test_env="0",
        context_name="",
        context_endpoint="ssh://deploy@why-server",
        docker_host_env="tcp://10.0.0.8:2375",
    )

    with pytest.raises(UnsafeDockerDaemonError) as error:
        assert_local_docker_daemon(target)

    message = str(error.value)
    assert "NUMOJ_TEST_ENV=1" in message
    assert "Docker context" in message
    assert "ssh" in message
    assert "DOCKER_HOST" in message


def test_live_e2e_web_entry_binds_only_loopback_without_reloader(monkeypatch):
    from tests.e2e import loopback_web

    calls = []

    class FakeApp:
        config = {"DEBUG": True}

        def run(self, **kwargs):
            calls.append(("run", kwargs))

    fake_app = FakeApp()
    monkeypatch.setitem(
        sys.modules,
        "backend.oj",
        SimpleNamespace(
            app=fake_app,
            ensure_background_schedulers=lambda: calls.append(("schedule", {})),
        ),
    )

    loopback_web.main()

    assert fake_app.config["DEBUG"] is False
    assert calls == [
        ("schedule", {}),
        (
            "run",
            {
                "host": "127.0.0.1",
                "port": 2025,
                "debug": False,
                "use_reloader": False,
                "threaded": True,
            },
        ),
    ]


def test_live_reverse_cleanup_deletes_every_db_submission_and_verifies_state(
        monkeypatch):
    from backend.oj_modules.ranking import db as ranking_db
    from tests.e2e import test_reverse_judge_live_ui as live

    states = iter([
        {
            "submission_ids": {41, 42},
            "endpoint_count": 3,
            "competition_count": 1,
        },
        {
            "submission_ids": set(),
            "endpoint_count": 0,
            "competition_count": 0,
        },
        {
            "submission_ids": set(),
            "endpoint_count": 0,
            "competition_count": 0,
        },
    ])
    monkeypatch.setattr(live, "_assert_disposable_environment", lambda: None)
    monkeypatch.setattr(
        live, "_reverse_cleanup_db_state", lambda _competition_id: next(states),
    )
    removed = []
    monkeypatch.setattr(
        live,
        "_remove_live_artifact_dir",
        lambda path, root, label, errors: removed.append((path, root, label)),
    )
    monkeypatch.setattr(
        ranking_db, "submission_dir", lambda sid: f"submissions/{sid}",
    )
    monkeypatch.setattr(
        ranking_db, "competition_dir", lambda cid: f"competitions/{cid}",
    )

    class Result:
        returncode = 0

        @staticmethod
        def json():
            return {"success": True}

    class Cli:
        calls = []

        def admin(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return Result()

    cli = Cli()
    errors = live._cleanup_reverse_live_state(cli, 7, {41})

    assert errors == []
    assert [call[0] for call in cli.calls] == [
        ("ranking", "delete-submission", "7", "41"),
        ("ranking", "delete-submission", "7", "42"),
        ("ranking", "delete", "7"),
    ]
    assert [item[2] for item in removed] == [
        "提交 #41 workspace",
        "提交 #41 反向评测临时目录",
        "提交 #42 workspace",
        "提交 #42 反向评测临时目录",
        "比赛 #7 文件",
    ]


def test_live_reverse_cleanup_falls_back_but_reports_cli_failures(monkeypatch):
    from backend.oj_modules.ranking import db as ranking_db
    from tests.e2e import test_reverse_judge_live_ui as live

    states = iter([
        {
            "submission_ids": {51},
            "endpoint_count": 2,
            "competition_count": 1,
        },
        {
            "submission_ids": {51},
            "endpoint_count": 2,
            "competition_count": 1,
        },
        {
            "submission_ids": set(),
            "endpoint_count": 0,
            "competition_count": 0,
        },
    ])
    monkeypatch.setattr(live, "_assert_disposable_environment", lambda: None)
    monkeypatch.setattr(
        live, "_reverse_cleanup_db_state", lambda _competition_id: next(states),
    )
    fallback_ids = []
    monkeypatch.setattr(
        ranking_db, "delete_competition", lambda cid: fallback_ids.append(cid),
    )
    monkeypatch.setattr(
        ranking_db, "submission_dir", lambda sid: f"submissions/{sid}",
    )
    monkeypatch.setattr(
        ranking_db, "competition_dir", lambda cid: f"competitions/{cid}",
    )
    monkeypatch.setattr(
        live, "_remove_live_artifact_dir", lambda *_args, **_kwargs: None,
    )

    class FailedResult:
        returncode = 17

    class Cli:
        @staticmethod
        def admin(*_args, **_kwargs):
            return FailedResult()

    errors = live._cleanup_reverse_live_state(Cli(), 8, set())

    assert fallback_ids == [8]
    assert any("提交 #51 删除命令退出码 17" in error for error in errors)
    assert any("比赛 #8 删除命令退出码 17" in error for error in errors)


def test_live_reverse_artifact_cleanup_is_confined_to_exact_root(tmp_path):
    from tests.e2e import test_reverse_judge_live_ui as live

    artifact_root = tmp_path / "ranking_uploads" / "submissions"
    target = artifact_root / "71"
    target.mkdir(parents=True)
    (target / "answer.zip").write_bytes(b"answer")
    errors = []

    live._remove_live_artifact_dir(
        str(target), artifact_root, "提交 #71 workspace", errors,
    )

    assert errors == []
    assert not target.exists()

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    live._remove_live_artifact_dir(
        str(outside), artifact_root, "越界目录", errors,
    )
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert any("超出一次性测试产物目录" in error for error in errors)


def test_live_reverse_artifact_cleanup_refuses_symlink(tmp_path):
    from tests.e2e import test_reverse_judge_live_ui as live

    artifact_root = tmp_path / "ranking_uploads" / "submissions"
    artifact_root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    linked = artifact_root / "72"
    linked.symlink_to(outside, target_is_directory=True)
    errors = []

    live._remove_live_artifact_dir(
        str(linked), artifact_root, "提交 #72 workspace", errors,
    )

    assert linked.is_symlink()
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert errors == ["提交 #72 workspace是符号链接，拒绝自动清理"]


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
