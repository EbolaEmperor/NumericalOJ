import gzip
import importlib.util
import io
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "deploy_backup_database", ROOT / "deploy" / "backup_database.py"
)
backup_database = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(backup_database)


def _config(database="myojdb"):
    return SimpleNamespace(
        MYSQL_HOST="db.internal",
        MYSQL_PORT=3307,
        MYSQL_USERNAME="oj-user",
        MYSQL_PASSWORD="secret-value",
        MYSQL_DB=database,
    )


class _FakeDumpProcess:
    def __init__(self, command, *, stdout, env, return_code=0):
        assert stdout is subprocess.PIPE
        self.args = command
        self.stdout = io.BytesIO(b"CREATE TABLE example (id INT);\n")
        self.environment = env
        self.return_code = return_code
        self.killed = False

    def wait(self):
        return self.return_code

    def kill(self):
        self.killed = True


def test_backup_streams_mysqldump_to_an_atomic_gzip(monkeypatch, tmp_path):
    captured = {}

    monkeypatch.setattr(backup_database, "_database_exists", lambda _settings: True)

    def fake_popen(command, *, stdout, env):
        process = _FakeDumpProcess(command, stdout=stdout, env=env)
        captured["process"] = process
        return process

    monkeypatch.setattr(backup_database.subprocess, "Popen", fake_popen)
    output = tmp_path / "backup.sql.gz"

    result = backup_database.backup_database(output, _config())

    process = captured["process"]
    assert result == output.resolve()
    assert gzip.decompress(output.read_bytes()) == b"CREATE TABLE example (id INT);\n"
    assert "--single-transaction" in process.args
    assert "--routines" in process.args
    assert "--connect-timeout=5" in process.args
    assert process.args[-1] == "myojdb"
    assert all("secret-value" not in argument for argument in process.args)
    assert process.environment["MYSQL_PWD"] == "secret-value"
    assert not list(tmp_path.glob("*.partial"))


def test_backup_records_a_missing_database_without_running_mysqldump(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(backup_database, "_database_exists", lambda _settings: False)
    monkeypatch.setattr(
        backup_database.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("missing database must not run mysqldump"),
    )
    output = tmp_path / "missing.sql.gz"

    backup_database.backup_database(output, _config())

    assert b"configured database did not exist" in gzip.decompress(output.read_bytes())


def test_failed_dump_leaves_no_backup_or_partial_file(monkeypatch, tmp_path):
    monkeypatch.setattr(backup_database, "_database_exists", lambda _settings: True)
    monkeypatch.setattr(
        backup_database.subprocess,
        "Popen",
        lambda command, *, stdout, env: _FakeDumpProcess(
            command, stdout=stdout, env=env, return_code=2
        ),
    )
    output = tmp_path / "failed.sql.gz"

    with pytest.raises(subprocess.CalledProcessError):
        backup_database.backup_database(output, _config())

    assert not output.exists()
    assert not list(tmp_path.iterdir())


def test_backup_rejects_an_option_shaped_database_name(tmp_path):
    with pytest.raises(ValueError, match="invalid database name"):
        backup_database.backup_database(tmp_path / "backup.sql.gz", _config("--all"))
