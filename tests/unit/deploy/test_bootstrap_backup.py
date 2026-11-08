"""托管容器首次备份的客户端归属、凭据传递与旧计划兼容。"""

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from deploy.backup import container_client, orchestrator as backup


def _config():
    return SimpleNamespace(MYSQL_HOST="127.0.0.1", MYSQL_PORT=13306, MYSQL_DB="numoj_dev",
                           MYSQL_USERNAME="oj", MYSQL_PASSWORD="private-backup-password")


def test_managed_mysql_logical_plan_never_provisions_host_database_tools(tmp_path, monkeypatch):
    root = tmp_path / "backups"
    path = root / "plans" / "fresh.json"
    snapshot = backup.DatabaseSnapshot("8.4.4", "MySQL Community Server - GPL", False)
    monkeypatch.setattr(backup, "discover_database", lambda _: backup.DatabaseDiscovery(snapshot, 0, 0))
    monkeypatch.setattr(container_client, "owned_container", lambda *_: "numoj-mysql-" + "a" * 16)
    monkeypatch.setattr(backup, "validate_logical_preflight", lambda *a, **kw: {"required_bytes": 1})
    monkeypatch.setattr(backup, "query_xtrabackup_metadata", lambda *_: pytest.fail("container must not inspect host datadir"))
    document = backup.create_preflight_plan(
        path, root, "fresh", _config(), logical_only=True,
        provisioner=lambda *a, **kw: pytest.fail("container must not install XtraBackup"),
    )
    assert document["strategy"] == "logical"
    assert document["decision_reason"] == "managed_mysql_container"
    assert document["xtrabackup_plan"] is None
    assert backup.read_plan(path)["mysql_client"] == {"container_name": "numoj-mysql-" + "a" * 16}
    assert "private-backup-password" not in path.read_text()


def test_client_help_is_checked_before_entering_stopped_window(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "MariaDB client --quick", ""))
    with pytest.raises(RuntimeError, match="部署尚未停服"):
        container_client.validate_client(Path("/usr/bin/mysqldump"))


def test_container_client_credentials_only_travel_through_stdin_and_are_cleaned(tmp_path, monkeypatch):
    option = tmp_path / "credentials.cnf"
    option.write_text('[client]\npassword="private-backup-password"\n')
    calls = []
    monkeypatch.setattr(container_client, "_docker", lambda: "/usr/bin/docker")
    monkeypatch.setenv("MYSQL_PWD", "inherited-secret")
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, b"/tmp/numoj-mysql-backup.A1B2C3D4.cnf\n", b"")
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ValueError, match="dump failed"):
        with container_client.dump_command("numoj-mysql-" + "a" * 16, option, "numoj_dev") as command:
            assert "private-backup-password" not in repr(command)
            assert command[-1] == "numoj_dev"
            raise ValueError("dump failed")
    assert len(calls) == 2
    assert calls[0][1]["input"] == option.read_bytes()
    assert "MYSQL_PWD" not in calls[0][1]["env"]
    assert all("private-backup-password" not in repr(command) for command, _ in calls)
    assert "rm -f" in calls[-1][0][-3]


def test_container_dump_overrides_host_published_port_3307(tmp_path, monkeypatch):
    configuration = _config()
    configuration.MYSQL_PORT = 3307
    settings = backup.settings_from_config(configuration)
    monkeypatch.setattr(container_client, "_docker", lambda: "/usr/bin/docker")
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    with backup.mysql_option_file(settings, tmp_path) as option:
        content = option.read_bytes()
        with container_client.dump_command("numoj-mysql-" + "a" * 16, option, settings.database) as command:
            # defaults-extra-file 先读取，随后 argv 显式覆盖容器内连接目标。
            assert 'exec mysqldump --defaults-extra-file="$p" "$@"' in command[command.index("-c") + 1]
            assert command[command.index("--protocol=TCP"):command.index("--protocol=TCP") + 3] == [
                "--protocol=TCP", "--host=127.0.0.1", "--port=3306",
            ]
            assert "--port=3307" not in command
            assert all("private-backup-password" not in value and "user=oj" not in value for value in command)
    assert calls[0][1]["input"] == content
    assert b"port=3307" in calls[0][1]["input"]
    assert len(calls) == 2


def test_plan_rejects_arbitrary_container_name(tmp_path, monkeypatch):
    root = tmp_path / "backups"
    path = root / "plans" / "fresh.json"
    snapshot = backup.DatabaseSnapshot("8.4.4", "MySQL Community Server - GPL", False)
    monkeypatch.setattr(backup, "discover_database", lambda _: backup.DatabaseDiscovery(snapshot, 0, 0))
    monkeypatch.setattr(container_client, "owned_container", lambda *_: "numoj-mysql-" + "a" * 16)
    monkeypatch.setattr(backup, "validate_logical_preflight", lambda *a, **kw: {"required_bytes": 1})
    backup.create_preflight_plan(path, root, "fresh", _config(), logical_only=True)
    document = json.loads(path.read_text())
    document["mysql_client"]["container_name"] = "other-database"
    path.write_text(json.dumps(document))
    with pytest.raises(backup.PlanError, match="客户端字段"):
        backup.read_plan(path)
