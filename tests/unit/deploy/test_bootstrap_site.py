"""首次管理员和开机服务配置不会覆盖旧站点。"""

import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from deploy import bootstrap_site as site


SETTINGS = SimpleNamespace(host="127.0.0.1", port=13306, database="numoj_dev_test", user="numoj")


class Connection:
    def __init__(self, rows):
        self.rows = iter(rows)
        self.calls = []
        self.closed = self.committed = self.rolled_back = False

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query, parameters=None):
        self.calls.append((query, parameters))

    def fetchone(self):
        return next(self.rows)

    def close(self):
        self.closed = True

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def test_prepare_missing_database_is_read_only_and_replay_preserves_private_password(tmp_path):
    first = Connection([None])
    result = site.prepare_admin(tmp_path, "test-cpu", settings=SETTINGS, connect=lambda *a, **k: first)
    assert result == {"needs_admin": True, "first_install": True}
    record = tmp_path / ".deploy/initial-admin.json"
    original = record.read_bytes()
    assert stat.S_IMODE(record.stat().st_mode) == 0o600
    assert all(query.startswith("SELECT ") for query, _ in first.calls)
    second = Connection([None])
    site.prepare_admin(tmp_path, "test-cpu", settings=SETTINGS, connect=lambda *a, **k: second)
    assert record.read_bytes() == original
    assert first.closed and second.closed


def test_production_password_is_validated_before_any_database_write(tmp_path):
    answers = iter(["a sufficiently long password", "different password"])
    connection = Connection([None])
    with pytest.raises(site.BootstrapSiteError, match="密码不一致"):
        site.prepare_admin(tmp_path, "production", settings=SETTINGS,
                           connect=lambda *a, **k: connection, password_reader=lambda _: next(answers))
    assert all(query.startswith("SELECT ") for query, _ in connection.calls)
    assert not (tmp_path / ".deploy/initial-admin.json").exists()


def test_existing_accounts_need_no_initial_password_and_are_not_modified(tmp_path):
    server = Connection([{"schema": "numoj_dev_test"}, {"n": 3}, {"TABLE_NAME": "users"}])
    database = Connection([{"n": 12}, {"is_admin": 1}])
    connections = iter([server, database])
    result = site.prepare_admin(tmp_path, "production", settings=SETTINGS,
                                connect=lambda *a, **k: next(connections))
    assert result == {"needs_admin": False, "first_install": False}
    assert not (tmp_path / ".deploy/initial-admin.json").exists()
    assert all(query.startswith("SELECT ") for connection in (server, database) for query, _ in connection.calls)


def test_unrelated_preexisting_schema_is_not_guessed_to_be_fresh(tmp_path):
    server = Connection([{"schema": "numoj_dev_test"}, {"n": 3}, {"TABLE_NAME": "users"}])
    database = Connection([{"n": 0}])
    connections = iter([server, database])
    with pytest.raises(site.BootstrapSiteError, match="已有结构"):
        site.prepare_admin(tmp_path, "test-cpu", settings=SETTINGS, connect=lambda *a, **k: next(connections))


def test_initial_account_insert_is_parameterized_and_uses_existing_password_primitive(tmp_path):
    from backend.oj_modules.security.credentials import verify_password

    site.prepare_admin(tmp_path, "test-cpu", settings=SETTINGS, connect=lambda *a, **k: Connection([None]))
    record_path = tmp_path / ".deploy/initial-admin.json"
    password = json.loads(record_path.read_text())["password"]
    connection = Connection([{"acquired": 1}, {"n": 0}])
    assert site.initialize_admin(tmp_path, settings=SETTINGS, connect=lambda *a, **k: connection)
    insertion = next(call for call in connection.calls if call[0].startswith("INSERT"))
    assert insertion[1][0] == "admin" and insertion[1][2] == 1
    assert password not in insertion[0]
    assert verify_password(insertion[1][1], password)[0]
    assert connection.committed and connection.closed
    assert json.loads(record_path.read_text())["initialized"] is True
    assert site.initialize_admin(tmp_path, settings=SETTINGS,
                                 connect=lambda *a, **k: pytest.fail("已初始化账号不能重写")) is False


def test_record_for_another_database_or_symlink_is_rejected(tmp_path):
    site.prepare_admin(tmp_path, "test-cpu", settings=SETTINGS, connect=lambda *a, **k: Connection([None]))
    other = SimpleNamespace(**(vars(SETTINGS) | {"database": "another_test"}))
    with pytest.raises(site.BootstrapSiteError, match="不一致"):
        site.initialize_admin(tmp_path, settings=other)
    record = tmp_path / ".deploy/initial-admin.json"
    saved = record.with_suffix(".saved")
    record.rename(saved)
    record.symlink_to(saved)
    with pytest.raises(site.BootstrapSiteError, match="符号链接"):
        site.initialize_admin(tmp_path, settings=SETTINGS)


def test_first_install_marker_survives_admin_creation_until_deployment_success(tmp_path):
    site.prepare_admin(tmp_path, "test-cpu", settings=SETTINGS, connect=lambda *a, **k: Connection([None]))
    connection = Connection([{"acquired": 1}, {"n": 0}])
    site.initialize_admin(tmp_path, settings=SETTINGS, connect=lambda *a, **k: connection)
    server = Connection([{"schema": "numoj_dev_test"}, {"n": 3}, {"TABLE_NAME": "users"}])
    database = Connection([{"n": 1}, {"is_admin": 1}])
    connections = iter([server, database])
    result = site.prepare_admin(tmp_path, "test-cpu", settings=SETTINGS, connect=lambda *a, **k: next(connections))
    assert result == {"needs_admin": False, "first_install": True}
    marker = tmp_path / ".deploy/first-install-pending"
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600


def test_boot_units_use_stable_venv_and_keep_existing_supervisor_topology(tmp_path):
    text = site.render_unit(tmp_path / 'project space', "celery", "operator", "operator")
    assert "User=operator\nGroup=operator" in text
    assert ".deploy/current-venv/bin/supervisord" in text
    assert "PIDFile=/tmp/noj_celery_supervisord.pid" in text
    assert "TimeoutStopSec=1960" in text
    assert "numericaloj-observability.service" in text
    assert "WantedBy=multi-user.target" in text
    assert "deploy.sh" not in text


def test_boot_install_enables_without_starting_a_second_manual_supervisor(tmp_path):
    calls = []
    units = tmp_path / "systemd"
    units.mkdir()
    names = site.install_boot(tmp_path, system_directory=units,
                              run=lambda command, **kwargs: calls.append(command) or SimpleNamespace(returncode=0))
    assert len(names) == 3
    assert any("daemon-reload" in call for call in calls)
    assert any("enable" in call for call in calls)
    assert not any("start" in call or "restart" in call for call in calls)


def test_foreign_systemd_unit_cannot_be_overwritten(tmp_path):
    directory = tmp_path / "units"
    directory.mkdir()
    foreign = directory / "numericaloj-observability.service"
    foreign.write_text("[Service]\nExecStart=/usr/bin/false\n")
    with pytest.raises(site.BootstrapSiteError, match="不属于"):
        site.install_boot(tmp_path, system_directory=directory,
                          run=lambda *a, **k: pytest.fail("不能覆盖另一部署的服务"))
    assert foreign.read_text().startswith("[Service]")
