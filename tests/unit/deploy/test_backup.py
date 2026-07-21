import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace

import pytest

from deploy.backup import orchestrator as backup


def _config(*, password="secret-value", database="myojdb"):
    return SimpleNamespace(
        MYSQL_HOST="db.internal",
        MYSQL_PORT=3307,
        MYSQL_USERNAME="oj-user",
        MYSQL_PASSWORD=password,
        MYSQL_DB=database,
    )


class _FakeDumpProcess:
    def __init__(self, command, *, stdout, env, data=b"SELECT 1;\n", return_code=0):
        assert stdout is subprocess.PIPE
        self.args = command
        self.stdout = io.BytesIO(data)
        self.environment = env
        self.return_code = return_code
        self.killed = False

    def wait(self):
        return self.return_code

    def kill(self):
        self.killed = True


def _snapshot(*, exists=True):
    return backup.DatabaseSnapshot(
        version="8.4.4",
        version_comment="MySQL Community Server - GPL",
        database_exists=exists,
    )


def test_dump_uses_ephemeral_option_file_and_publishes_verified_manifest(
    monkeypatch, tmp_path
):
    raw_dump = (b"CREATE TABLE example (id INT);\n" * 128)
    captured = {}
    monkeypatch.setattr(backup, "inspect_database", lambda _settings: _snapshot())
    monkeypatch.setenv("MYSQL_PWD", "inherited-credential")
    monkeypatch.setenv("DATABASE_URL", "mysql://oj-user:secret-value@db.internal/")

    def fake_popen(command, *, stdout, env):
        option_path = Path(command[1].split("=", 1)[1])
        captured["option_path"] = option_path
        captured["option_mode"] = option_path.stat().st_mode & 0o777
        captured["option_body"] = option_path.read_text(encoding="utf-8")
        process = _FakeDumpProcess(command, stdout=stdout, env=env, data=raw_dump)
        captured["process"] = process
        return process

    monkeypatch.setattr(backup.subprocess, "Popen", fake_popen)
    progress = io.StringIO()
    output = tmp_path / "mysql.sql.gz"

    result = backup.backup_database(output, _config(), progress_stream=progress)

    process = captured["process"]
    assert result == output.resolve()
    assert gzip.decompress(output.read_bytes()) == raw_dump
    assert captured["option_mode"] == 0o600
    assert "password=\"secret-value\"" in captured["option_body"]
    assert not captured["option_path"].exists()
    assert process.args[1].startswith("--defaults-extra-file=")
    assert process.args[-1] == "myojdb"
    assert "--quick" in process.args
    assert "--skip-lock-tables" in process.args
    assert "--hex-blob" in process.args
    assert all("secret-value" not in item for item in process.args)
    assert "MYSQL_PWD" not in process.environment
    assert all("secret-value" not in value for value in process.environment.values())
    assert set(process.environment) <= set(backup.SAFE_SUBPROCESS_ENV_KEYS)
    assert process.args[0] == "/usr/bin/mysqldump"

    manifest = backup.read_manifest(backup.manifest_path_for(output))
    assert manifest["schema_version"] == 1
    assert manifest["deployment_status"] == "pending"
    assert manifest["backup_status"] == "complete"
    assert manifest["scope"] == "database"
    assert manifest["database"] == "myojdb"
    assert manifest["raw_bytes"] == len(raw_dump)
    assert manifest["artifact"]["compressed_bytes"] == output.stat().st_size
    assert manifest["artifact"]["sha256"] == hashlib.sha256(
        output.read_bytes()
    ).hexdigest()
    assert manifest["gzip_crc_verified"] is True
    assert "secret-value" not in json.dumps(manifest)
    assert output.stat().st_mode & 0o777 == 0o600
    assert backup.manifest_path_for(output).stat().st_mode & 0o777 == 0o600

    records = [json.loads(line) for line in progress.getvalue().splitlines()]
    assert records[-1]["completed"] is True
    assert records[-1]["raw_bytes"] == len(raw_dump)
    assert records[-1]["compressed_bytes"] == output.stat().st_size
    assert not list(tmp_path.glob(".*.partial"))


def test_failed_mysqldump_removes_partial_credentials_and_manifest(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(backup, "inspect_database", lambda _settings: _snapshot())
    captured = {}

    def fake_popen(command, *, stdout, env):
        captured["option_path"] = Path(command[1].split("=", 1)[1])
        return _FakeDumpProcess(
            command, stdout=stdout, env=env, data=b"incomplete", return_code=2
        )

    monkeypatch.setattr(backup.subprocess, "Popen", fake_popen)
    output = tmp_path / "failed.sql.gz"

    with pytest.raises(subprocess.CalledProcessError):
        backup.backup_database(output, _config(), progress_stream=io.StringIO())

    assert not captured["option_path"].exists()
    assert not output.exists()
    assert not backup.manifest_path_for(output).exists()
    assert not list(tmp_path.iterdir())


def test_missing_database_creates_a_crc_verified_placeholder(monkeypatch, tmp_path):
    monkeypatch.setattr(
        backup, "inspect_database", lambda _settings: _snapshot(exists=False)
    )
    monkeypatch.setattr(
        backup.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("mysqldump must not run"),
    )
    output = tmp_path / "missing.sql.gz"

    backup.backup_database(output, _config(), progress_stream=io.StringIO())

    assert b"configured database did not exist" in gzip.decompress(output.read_bytes())
    manifest = backup.read_manifest(backup.manifest_path_for(output))
    assert manifest["database_existed"] is False
    assert manifest["gzip_crc_verified"] is True


def test_crc_validation_reads_to_the_trailer_and_rejects_corruption(tmp_path):
    output = tmp_path / "corrupt.sql.gz"
    corrupted = bytearray(gzip.compress(b"payload"))
    corrupted[-8] ^= 0xFF
    output.write_bytes(corrupted)

    with pytest.raises((gzip.BadGzipFile, EOFError, OSError)):
        backup.validate_gzip_stream(output, expected_raw_bytes=7)


def test_validation_returns_the_compressed_artifact_sha256(tmp_path):
    output = tmp_path / "valid.sql.gz"
    output.write_bytes(gzip.compress(b"payload"))

    result = backup.validate_gzip_stream(output, expected_raw_bytes=7)

    assert result.raw_bytes == 7
    assert result.sha256 == hashlib.sha256(output.read_bytes()).hexdigest()


def test_crc_failure_does_not_publish_artifact_or_manifest(monkeypatch, tmp_path):
    monkeypatch.setattr(backup, "inspect_database", lambda _settings: _snapshot())
    monkeypatch.setattr(
        backup.subprocess,
        "Popen",
        lambda command, *, stdout, env: _FakeDumpProcess(
            command, stdout=stdout, env=env
        ),
    )
    monkeypatch.setattr(
        backup,
        "validate_gzip_stream",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(gzip.BadGzipFile("bad CRC")),
    )
    output = tmp_path / "bad.sql.gz"

    with pytest.raises(gzip.BadGzipFile):
        backup.backup_database(output, _config(), progress_stream=io.StringIO())

    assert not output.exists()
    assert not backup.manifest_path_for(output).exists()
    assert not list(tmp_path.iterdir())


class _TTYBuffer(io.StringIO):
    def isatty(self):
        return True


def test_progress_is_json_for_logs_and_single_line_for_a_tty():
    times = iter((0.0, 1.0, 2.0))
    logged = io.StringIO()
    reporter = backup.ProgressReporter(stream=logged, clock=lambda: next(times))
    reporter.update(1024, 256)
    reporter.update(2048, 512, completed=True)

    first, second = map(json.loads, logged.getvalue().splitlines())
    assert first["event"] == "mysql_backup_progress"
    assert first["raw_bytes_per_second"] == 1024
    assert second["completed"] is True

    tty_times = iter((0.0, 1.0, 2.0))
    tty = _TTYBuffer()
    tty_reporter = backup.ProgressReporter(stream=tty, clock=lambda: next(tty_times))
    tty_reporter.update(1024, 256)
    tty_reporter.update(2048, 512, completed=True)

    assert tty.getvalue().startswith("\rmysqldump raw=")
    assert "throughput=" in tty.getvalue()
    assert tty.getvalue().endswith("\n")


def test_progress_expands_an_outgrown_estimate_and_finishes_with_average_rate():
    times = iter((0.0, 1.0, 3.0))
    stream = io.StringIO()
    reporter = backup.ProgressReporter(
        stream=stream,
        estimated_raw_bytes=100,
        clock=lambda: next(times),
    )

    reporter.update(150, 60)
    reporter.update(300, 120, completed=True)

    first, final = map(json.loads, stream.getvalue().splitlines())
    assert first["estimated_total_raw_bytes"] == 200
    assert first["estimated_percent"] == 75.0
    assert final["raw_bytes_per_second"] == 100.0
    assert final["estimated_percent"] == 100.0


def test_manifest_status_transitions_are_atomic_and_failure_is_best_effort(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        backup, "inspect_database", lambda _settings: _snapshot(exists=False)
    )
    failed_output = tmp_path / "failed-deploy.sql.gz"
    backup.backup_database(
        failed_output, _config(), progress_stream=io.StringIO()
    )
    failed_manifest = backup.manifest_path_for(failed_output)

    assert backup.mark_manifest_failed(failed_manifest, phase="start_web") is True
    failed = backup.read_manifest(failed_manifest)
    assert failed["deployment_status"] == "failed"
    assert failed["failure_phase"] == "start_web"
    assert not list(tmp_path.glob(".*.partial"))

    successful_output = tmp_path / "successful-deploy.sql.gz"
    backup.backup_database(
        successful_output, _config(), progress_stream=io.StringIO()
    )
    successful_manifest = backup.manifest_path_for(successful_output)
    backup.mark_manifest_success(successful_manifest)
    backup.mark_manifest_success(successful_manifest)
    assert backup.read_manifest(successful_manifest)["deployment_status"] == "success"
    assert backup.mark_manifest_failed(successful_manifest, phase="cleanup") is False
    assert backup.mark_manifest_failed(tmp_path / "absent.json", phase="backup") is False


def test_manifest_cannot_be_marked_success_without_backend_integrity_facts(tmp_path):
    manifest = tmp_path / "incomplete.manifest.json"
    backup._publish_new_json(
        manifest,
        {
            "schema": backup.MANIFEST_SCHEMA,
            "schema_version": backup.MANIFEST_SCHEMA_VERSION,
            "backup_method": "mysqldump",
            "backup_status": "complete",
            "deployment_status": "pending",
            "artifact": {},
            "completed_at": "2026-07-21T00:00:00+00:00",
        },
    )

    with pytest.raises(ValueError, match="完整性状态"):
        backup.mark_manifest_success(manifest)


def test_manifest_cannot_be_marked_success_after_logical_artifact_is_deleted(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        backup, "inspect_database", lambda _settings: _snapshot(exists=False)
    )
    output = tmp_path / "deleted-before-success.sql.gz"
    backup.backup_database(output, _config(), progress_stream=io.StringIO())
    manifest = backup.manifest_path_for(output)
    output.unlink()

    with pytest.raises(ValueError, match="不存在"):
        backup.mark_manifest_success(manifest)


def test_manifest_cannot_be_marked_success_after_logical_artifact_is_corrupted(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        backup, "inspect_database", lambda _settings: _snapshot(exists=False)
    )
    output = tmp_path / "corrupted-before-success.sql.gz"
    backup.backup_database(output, _config(), progress_stream=io.StringIO())
    manifest = backup.manifest_path_for(output)
    payload = bytearray(output.read_bytes())
    payload[-1] ^= 0xFF
    output.write_bytes(payload)
    output.chmod(0o600)

    with pytest.raises((OSError, ValueError)):
        backup.mark_manifest_success(manifest)


def test_deployment_generation_is_monotonic_and_private(tmp_path):
    root = tmp_path / "backups"
    layout = backup.prepare_backup_layout(root)

    assert backup.allocate_deployment_generation(root) == 1
    assert backup.allocate_deployment_generation(root) == 2
    generation_file = layout["plans"] / backup.GENERATION_FILE_NAME
    assert generation_file.read_text(encoding="ascii") == "2\n"
    assert generation_file.stat().st_mode & 0o777 == 0o600


def test_deployment_generation_rejects_a_hard_link(tmp_path):
    root = tmp_path / "backups"
    layout = backup.prepare_backup_layout(root)
    unrelated = layout["plans"] / "unrelated"
    unrelated.write_text("41\n", encoding="ascii")
    unrelated.chmod(0o600)
    os.link(unrelated, layout["plans"] / backup.GENERATION_FILE_NAME)

    with pytest.raises(backup.PreflightError, match="普通文件"):
        backup.allocate_deployment_generation(root)

    assert unrelated.read_text(encoding="ascii") == "41\n"


def test_successful_manifest_supplies_the_next_progress_estimate(tmp_path):
    old = tmp_path / "old.sql.gz.manifest.json"
    backup._atomic_replace_json(
        old,
        {
            "schema": backup.MANIFEST_SCHEMA,
            "schema_version": backup.MANIFEST_SCHEMA_VERSION,
            "deployment_status": "success",
            "backup_method": "mysqldump",
            "database": "myojdb",
            "raw_bytes": 12345,
            "completed_at": "2026-07-20T00:00:00+00:00",
        },
    )
    backup._atomic_replace_json(
        tmp_path / "pending.sql.gz.manifest.json",
        {
            "schema": backup.MANIFEST_SCHEMA,
            "schema_version": backup.MANIFEST_SCHEMA_VERSION,
            "deployment_status": "pending",
            "backup_method": "mysqldump",
            "database": "myojdb",
            "raw_bytes": 99999,
            "completed_at": "2026-07-21T00:00:00+00:00",
        },
    )

    assert backup.estimate_raw_bytes(tmp_path, "myojdb") == 12345


def test_backup_refuses_to_replace_an_existing_success(monkeypatch, tmp_path):
    output = tmp_path / "existing.sql.gz"
    output.write_bytes(b"keep me")
    monkeypatch.setattr(
        backup,
        "inspect_database",
        lambda _settings: pytest.fail("must reject before connecting"),
    )

    with pytest.raises(FileExistsError):
        backup.backup_database(output, _config(), progress_stream=io.StringIO())

    assert output.read_bytes() == b"keep me"


def test_manifest_can_live_in_a_separate_partition(monkeypatch, tmp_path):
    monkeypatch.setattr(
        backup, "inspect_database", lambda _settings: _snapshot(exists=False)
    )
    output = tmp_path / "logical" / "backup.sql.gz"
    manifest = tmp_path / "manifests" / "backup.json"

    backup.backup_database(
        output,
        _config(),
        manifest_path=manifest,
        progress_stream=io.StringIO(),
    )

    document = backup.read_manifest(manifest)
    assert document["artifact"]["path_relative_to"] == "manifest_directory"
    assert document["artifact"]["relative_path"] == "../logical/backup.sql.gz"
    assert manifest.stat().st_mode & 0o777 == 0o600


def test_option_file_rejects_multiline_credentials_and_cleans_up(tmp_path):
    settings = backup.settings_from_config(_config(password="line1\nline2"))

    with pytest.raises(ValueError, match="control lines"):
        with backup.mysql_option_file(settings, tmp_path):
            pytest.fail("invalid credentials must not be yielded")

    assert not list(tmp_path.iterdir())


def _discovery(*, version="10.11.6-MariaDB", comment="MariaDB Server"):
    return backup.DatabaseDiscovery(
        snapshot=backup.DatabaseSnapshot(
            version=version,
            version_comment=comment,
            database_exists=True,
        ),
        estimated_bytes=1024,
        estimated_tables=3,
    )


def _physical_plan():
    return backup.xtrabackup.XtraBackupPlan(
        schema_version=1,
        mysql_host="127.0.0.1",
        server_version="8.4.4",
        server_version_comment="MySQL Community Server - GPL",
        server_vendor="oracle_mysql",
        server_uuid="12345678-1234-1234-1234-123456789abc",
        datadir="/var/lib/mysql",
        mysql_socket="/run/mysqld/mysqld.sock",
        server_series="8.4",
        upstream_version="8.4.0-6",
        package_name="percona-xtrabackup-84",
        package_version="8.4.0-6-1.bookworm",
        apt_repository="pxb-84-lts",
    )


def _physical_metadata():
    plan = _physical_plan()
    return backup.xtrabackup.ServerMetadata(
        version=plan.server_version,
        version_comment=plan.server_version_comment,
        datadir=plan.datadir,
        socket=plan.mysql_socket,
        server_uuid=plan.server_uuid,
    )


def test_preflight_uses_basic_metadata_for_unsupported_server(monkeypatch, tmp_path):
    root = tmp_path / "backups"
    plan_path = root / "plans" / "run-1.json"
    monkeypatch.setattr(backup, "discover_database", lambda _settings: _discovery())
    monkeypatch.setattr(
        backup,
        "validate_logical_preflight",
        lambda *_args: {
            "estimated_bytes": 1024,
            "estimated_inodes": 4,
            "required_bytes": 2048,
            "required_inodes": 64,
            "free_bytes": 9999,
            "free_inodes": 9999,
        },
    )
    monkeypatch.setattr(
        backup,
        "query_xtrabackup_metadata",
        lambda _settings: pytest.fail("MariaDB must not query @@server_uuid"),
    )

    document = backup.create_preflight_plan(
        plan_path, root, "run-1", _config()
    )

    assert document["strategy"] == "logical"
    assert document["decision_reason"] == "no_compatible_xtrabackup_mapping"
    assert document["artifact_relative_path"] == "logical/run-1.sql.gz"
    assert plan_path.stat().st_mode & 0o777 == 0o600
    assert all(
        (root / name).is_dir()
        for name in ("plans", "logical", "physical", "manifests")
    )
    assert root.stat().st_mode & 0o777 == 0o700
    assert "secret-value" not in plan_path.read_text(encoding="utf-8")


def test_only_provisioning_error_falls_back_to_logical(monkeypatch, tmp_path):
    root = tmp_path / "backups"
    plan_path = root / "plans" / "run-2.json"
    discovery = _discovery(
        version="8.4.4", comment="MySQL Community Server - GPL"
    )
    monkeypatch.setattr(backup, "discover_database", lambda _settings: discovery)
    monkeypatch.setattr(
        backup,
        "validate_logical_preflight",
        lambda *_args: {"estimated_bytes": 1, "estimated_inodes": 1},
    )

    def provisioning_failed(*_args, **_kwargs):
        raise backup.percona_apt.ProvisioningError("apt unavailable")

    document = backup.create_preflight_plan(
        plan_path,
        root,
        "run-2",
        _config(),
        provisioner=provisioning_failed,
    )

    assert document["strategy"] == "logical"
    assert document["decision_reason"] == "xtrabackup_provisioning_failed"


def test_root_auth_failure_is_not_a_logical_fallback(monkeypatch, tmp_path):
    root = tmp_path / "backups"
    plan_path = root / "plans" / "run-3.json"
    monkeypatch.setattr(
        backup,
        "discover_database",
        lambda _settings: _discovery(
            version="8.4.4", comment="MySQL Community Server - GPL"
        ),
    )
    monkeypatch.setattr(
        backup, "query_xtrabackup_metadata", lambda _settings: _physical_metadata()
    )
    monkeypatch.setattr(
        backup,
        "validate_logical_preflight",
        lambda *_args: pytest.fail("root auth errors must not fallback"),
    )

    def root_auth_failed(*_args, **_kwargs):
        raise backup.xtrabackup.RootSocketAuthenticationError("denied")

    with pytest.raises(backup.xtrabackup.RootSocketAuthenticationError):
        backup.create_preflight_plan(
            plan_path,
            root,
            "run-3",
            _config(),
            provisioner=lambda *_args, **_kwargs: SimpleNamespace(),
            physical_plan_preparer=root_auth_failed,
        )

    assert not plan_path.exists()


def test_physical_preflight_persists_the_validated_backend(monkeypatch, tmp_path):
    root = tmp_path / "backups"
    plan_path = root / "plans" / "run-4.json"
    monkeypatch.setattr(
        backup,
        "discover_database",
        lambda _settings: _discovery(
            version="8.4.4", comment="MySQL Community Server - GPL"
        ),
    )
    monkeypatch.setattr(
        backup, "query_xtrabackup_metadata", lambda _settings: _physical_metadata()
    )
    calls = []

    def capacity(*_args, **_kwargs):
        calls.append("capacity")
        return SimpleNamespace(
            to_dict=lambda: {"estimated_bytes": 100, "estimated_inodes": 10}
        )

    monkeypatch.setattr(backup.xtrabackup, "preflight_physical_capacity", capacity)

    document = backup.create_preflight_plan(
        plan_path,
        root,
        "run-4",
        _config(),
        provisioner=lambda *_args, **_kwargs: SimpleNamespace(),
        physical_plan_preparer=lambda *_args, **_kwargs: _physical_plan(),
        physical_layout_hardener=lambda *_args: calls.append("harden"),
    )

    assert document["strategy"] == "physical"
    assert document["artifact_relative_path"] == "physical/run-4"
    assert document["xtrabackup_plan"]["server_uuid"] == _physical_plan().server_uuid
    assert calls == ["harden", "capacity"]


def test_physical_layout_hardening_uses_the_inode_bound_privileged_helper(
    monkeypatch, tmp_path
):
    root = tmp_path / "backups"
    physical = root / "physical"
    before_root = SimpleNamespace(
        st_dev=1,
        st_ino=10,
        st_uid=os.geteuid(),
        st_gid=os.getegid(),
        st_mode=stat.S_IFDIR | 0o700,
    )
    before_physical = SimpleNamespace(
        st_dev=1,
        st_ino=11,
        st_uid=os.geteuid(),
        st_gid=os.getegid(),
        st_mode=stat.S_IFDIR | 0o700,
    )
    after_root = SimpleNamespace(
        st_dev=1,
        st_ino=10,
        st_uid=0,
        st_gid=0,
        st_mode=stat.S_IFDIR | 0o711,
    )
    after_physical = SimpleNamespace(
        st_dev=1,
        st_ino=11,
        st_uid=0,
        st_gid=0,
        st_mode=stat.S_IFDIR | 0o711,
    )
    metadata = iter((before_root, before_physical, after_root, after_physical))
    monkeypatch.setattr(Path, "lstat", lambda _path: next(metadata))
    captured = {}

    def fake_runner(command, *, check, env):
        captured["command"] = command
        captured["check"] = check
        captured["env"] = env
        return subprocess.CompletedProcess(command, 0)

    backup.harden_physical_backup_layout(root, physical, runner=fake_runner)

    command = captured["command"]
    assert command[:3] == ["/usr/bin/sudo", "-n", "--"]
    assert "harden-physical-layout" in command
    assert command[command.index("--expected-root-ino") + 1] == "10"
    assert command[command.index("--expected-physical-ino") + 1] == "11"
    assert captured["check"] is True
    assert captured["env"]["LC_ALL"] == "C"


def test_physical_backup_revalidates_identity_and_never_falls_back(
    monkeypatch, tmp_path
):
    root = tmp_path / "backups"
    layout = backup.prepare_backup_layout(root)
    plan_path = layout["plans"] / "run-5.json"
    manifest = layout["manifests"] / "run-5.manifest.json"
    plan = _physical_plan()
    backup._publish_new_json(
        plan_path,
        {
            "schema": backup.PLAN_SCHEMA,
            "schema_version": backup.PLAN_SCHEMA_VERSION,
            "created_at": "2026-07-21T00:00:00+00:00",
            "run_id": "run-5",
            "generation": 5,
            "backup_root": str(root),
            "strategy": "physical",
            "decision_reason": "compatible_xtrabackup_preflight_passed",
            "database": "myojdb",
            "server": {
                "version": plan.server_version,
                "version_comment": plan.server_version_comment,
            },
            "artifact_relative_path": "physical/run-5",
            "manifest_relative_path": "manifests/run-5.manifest.json",
            "capacity": {
                "required_bytes": 1,
                "reserved_bytes": 0,
                "source_inode_count": 1,
            },
            "xtrabackup_plan": plan.to_dict(),
        },
    )
    monkeypatch.setattr(
        backup, "query_xtrabackup_metadata", lambda _settings: _physical_metadata()
    )
    monkeypatch.setattr(
        backup.xtrabackup,
        "validate_server_environment",
        lambda metadata: (Path(metadata.datadir), Path(metadata.socket)),
    )
    monkeypatch.setattr(
        backup,
        "backup_database",
        lambda *_args, **_kwargs: pytest.fail("physical failure must not fallback"),
    )

    def failed_runtime(*_args, **_kwargs):
        raise backup.xtrabackup.BackupValidationError("prepare failed")

    with pytest.raises(backup.xtrabackup.BackupValidationError):
        backup.execute_backup_plan(
            plan_path, manifest, _config(), physical_executor=failed_runtime
        )

    failed = backup.read_manifest(manifest)
    assert failed["backup_status"] == "failed"
    assert failed["deployment_status"] == "failed"
    assert failed["artifact"]["relative_path"] == "../physical/run-5"
    assert failed["artifact"]["validation"] == "failed"
    with pytest.raises(ValueError, match="完整备份"):
        backup.mark_manifest_success(manifest)


def test_logical_runtime_failure_publishes_a_failed_manifest(monkeypatch, tmp_path):
    root = tmp_path / "backups"
    layout = backup.prepare_backup_layout(root)
    plan_path = layout["plans"] / "run-logical.json"
    manifest = layout["manifests"] / "run-logical.manifest.json"
    snapshot = _snapshot()
    backup._publish_new_json(
        plan_path,
        {
            "schema": backup.PLAN_SCHEMA,
            "schema_version": backup.PLAN_SCHEMA_VERSION,
            "created_at": "2026-07-21T00:00:00+00:00",
            "run_id": "run-logical",
            "generation": 6,
            "backup_root": str(root),
            "strategy": "logical",
            "decision_reason": "xtrabackup_provisioning_failed",
            "database": "myojdb",
            "server": {
                "version": snapshot.version,
                "version_comment": snapshot.version_comment,
            },
            "artifact_relative_path": "logical/run-logical.sql.gz",
            "manifest_relative_path": "manifests/run-logical.manifest.json",
            "capacity": {
                "required_bytes": 1,
                "reserved_bytes": 0,
                "required_inodes": 1,
                "progress_estimated_raw_bytes": None,
            },
            "xtrabackup_plan": None,
        },
    )
    monkeypatch.setattr(backup, "inspect_database", lambda _settings: snapshot)

    def fail_dump(*_args, **_kwargs):
        raise OSError("dump failed")

    monkeypatch.setattr(backup, "backup_database", fail_dump)

    with pytest.raises(OSError, match="dump failed"):
        backup.execute_backup_plan(plan_path, manifest, _config())

    failed = backup.read_manifest(manifest)
    assert failed["backup_status"] == "failed"
    assert failed["deployment_status"] == "failed"
    assert failed["artifact"]["relative_path"] == "../logical/run-logical.sql.gz"
    assert failed["gzip_crc_verified"] is False


def test_successful_physical_backup_writes_a_complete_pending_manifest(
    monkeypatch, tmp_path
):
    root = tmp_path / "backups"
    layout = backup.prepare_backup_layout(root)
    plan_path = layout["plans"] / "run-6.json"
    manifest = layout["manifests"] / "run-6.manifest.json"
    plan = _physical_plan()
    backup._publish_new_json(
        plan_path,
        {
            "schema": backup.PLAN_SCHEMA,
            "schema_version": backup.PLAN_SCHEMA_VERSION,
            "created_at": "2026-07-21T00:00:00+00:00",
            "run_id": "run-6",
            "generation": 7,
            "backup_root": str(root),
            "strategy": "physical",
            "decision_reason": "compatible_xtrabackup_preflight_passed",
            "database": "myojdb",
            "server": {
                "version": plan.server_version,
                "version_comment": plan.server_version_comment,
            },
            "artifact_relative_path": "physical/run-6",
            "manifest_relative_path": "manifests/run-6.manifest.json",
            "capacity": {
                "required_bytes": 1,
                "reserved_bytes": 0,
                "source_inode_count": 1,
            },
            "xtrabackup_plan": plan.to_dict(),
        },
    )
    monkeypatch.setattr(
        backup, "query_xtrabackup_metadata", lambda _settings: _physical_metadata()
    )
    monkeypatch.setattr(
        backup.xtrabackup,
        "validate_server_environment",
        lambda metadata: (Path(metadata.datadir), Path(metadata.socket)),
    )

    executed = {}

    def execute(_plan, target):
        target.mkdir()
        result = backup.xtrabackup.XtraBackupResult(
            target=str(target),
            backup_type="full-prepared",
            from_lsn=0,
            to_lsn=10,
            last_lsn=10,
            file_count=8,
            total_bytes=4096,
        )
        executed["result"] = result
        return result

    artifact = backup.execute_backup_plan(
        plan_path, manifest, _config(), physical_executor=execute
    )

    document = backup.read_manifest(manifest)
    assert artifact == root / "physical" / "run-6"
    assert document["backup_status"] == "complete"
    assert document["deployment_status"] == "pending"
    assert document["scope"] == "full_instance"
    assert document["prepared"] is True
    assert document["restore_verified_at"] is None
    assert document["tool"]["package_version"] == plan.package_version

    monkeypatch.setattr(
        backup.xtrabackup,
        "inspect_prepared_backup",
        lambda checked_plan, checked_target: (
            executed["result"]
            if checked_plan == plan and checked_target == artifact
            else pytest.fail("mark-success must inspect the bound physical artifact")
        ),
    )
    backup.mark_manifest_success(manifest, plan_path=plan_path)
    assert backup.read_manifest(manifest)["deployment_status"] == "success"


def _write_prune_manifest(
    root, run_id, status, completed_at, *, generation=None
):
    if generation is None:
        generation = int(run_id.rsplit("-", 1)[1])
    artifact = root / "logical" / f"{run_id}.sql.gz"
    artifact.write_bytes(run_id.encode())
    manifest = root / "manifests" / f"{run_id}.manifest.json"
    backup._publish_new_json(
        manifest,
        {
            "schema": backup.MANIFEST_SCHEMA,
            "schema_version": backup.MANIFEST_SCHEMA_VERSION,
            "run_id": run_id,
            "generation": generation,
            "backup_method": "mysqldump",
            "backup_status": "complete",
            "deployment_status": status,
            "deployment_completed_at": completed_at,
            "artifact": {
                "relative_path": f"../logical/{run_id}.sql.gz",
                "path_relative_to": "manifest_directory",
            },
        },
    )
    backup._publish_new_json(
        root / "plans" / f"{run_id}.json",
        {
            "schema": backup.PLAN_SCHEMA,
            "schema_version": backup.PLAN_SCHEMA_VERSION,
            "created_at": "2026-07-01",
            "run_id": run_id,
            "generation": generation,
            "backup_root": str(root),
            "strategy": "logical",
            "decision_reason": "test",
            "database": "myojdb",
            "server": {"version": "8.4.4", "version_comment": "MySQL"},
            "artifact_relative_path": f"logical/{run_id}.sql.gz",
            "manifest_relative_path": f"manifests/{run_id}.manifest.json",
            "capacity": {},
            "xtrabackup_plan": None,
        },
    )
    return artifact, manifest


def _write_physical_prune_manifest(root, run_id, generation):
    artifact = root / "physical" / run_id
    artifact.mkdir()
    manifest = root / "manifests" / f"{run_id}.manifest.json"
    plan = _physical_plan()
    backup._publish_new_json(
        manifest,
        {
            "schema": backup.MANIFEST_SCHEMA,
            "schema_version": backup.MANIFEST_SCHEMA_VERSION,
            "run_id": run_id,
            "generation": generation,
            "backup_method": "xtrabackup",
            "backup_status": "complete",
            "deployment_status": "success",
            "deployment_completed_at": f"2026-07-{generation:02d}",
            "artifact": {
                "relative_path": f"../physical/{run_id}",
                "path_relative_to": "manifest_directory",
            },
        },
    )
    backup._publish_new_json(
        root / "plans" / f"{run_id}.json",
        {
            "schema": backup.PLAN_SCHEMA,
            "schema_version": backup.PLAN_SCHEMA_VERSION,
            "created_at": "2026-07-01",
            "run_id": run_id,
            "generation": generation,
            "backup_root": str(root),
            "strategy": "physical",
            "decision_reason": "test",
            "database": "myojdb",
            "server": {
                "version": plan.server_version,
                "version_comment": plan.server_version_comment,
            },
            "artifact_relative_path": f"physical/{run_id}",
            "manifest_relative_path": f"manifests/{run_id}.manifest.json",
            "capacity": {},
            "xtrabackup_plan": plan.to_dict(),
        },
    )
    return artifact, manifest


def test_prune_removes_only_old_successful_backups(tmp_path):
    root = tmp_path / "backups"
    backup.prepare_backup_layout(root)
    oldest = _write_prune_manifest(root, "run-1", "success", "2026-07-01")
    kept_one = _write_prune_manifest(root, "run-2", "success", "2026-07-02")
    kept_two = _write_prune_manifest(root, "run-3", "success", "2026-07-03")
    pending = _write_prune_manifest(root, "run-4", "pending", "2026-07-04")
    failed = _write_prune_manifest(root, "run-5", "failed", "2026-07-05")

    removed = backup.prune_successful_backups(root, keep_success=2)

    assert removed == [oldest[0]]
    assert not oldest[0].exists() and not oldest[1].exists()
    for artifact, manifest in (kept_one, kept_two, pending, failed):
        assert artifact.exists() and manifest.exists()


def test_prune_resumes_a_deleting_manifest_after_partial_cleanup(tmp_path):
    root = tmp_path / "backups"
    backup.prepare_backup_layout(root)
    oldest = _write_prune_manifest(root, "run-1", "success", "2026-07-01")
    _write_prune_manifest(root, "run-2", "success", "2026-07-02")
    _write_prune_manifest(root, "run-3", "success", "2026-07-03")

    backup._mark_retention_deleting(oldest[1])
    oldest[0].unlink()
    (root / "plans" / "run-1.json").unlink()

    removed = backup.prune_successful_backups(root, keep_success=2)

    assert removed == [oldest[0]]
    assert not oldest[1].exists()


def test_prune_uses_generation_and_explicitly_protects_the_current_run(tmp_path):
    root = tmp_path / "backups"
    backup.prepare_backup_layout(root)
    current = _write_prune_manifest(
        root,
        "run-1",
        "success",
        "1999-01-01",
        generation=1,
    )
    removed = _write_prune_manifest(
        root,
        "run-2",
        "success",
        "2099-01-01",
        generation=2,
    )
    newest = _write_prune_manifest(
        root,
        "run-3",
        "success",
        "2000-01-01",
        generation=3,
    )

    result = backup.prune_successful_backups(
        root,
        keep_success=2,
        protected_run_ids={"run-1"},
    )

    assert result == [removed[0]]
    assert current[0].exists() and current[1].exists()
    assert newest[0].exists() and newest[1].exists()


def test_prune_routes_old_physical_backup_through_the_privileged_remover(tmp_path):
    root = tmp_path / "backups"
    backup.prepare_backup_layout(root)
    oldest = _write_physical_prune_manifest(root, "physical-1", 1)
    kept_one = _write_physical_prune_manifest(root, "physical-2", 2)
    kept_two = _write_physical_prune_manifest(root, "physical-3", 3)
    removed_by_helper = []

    def remove_physical(path):
        removed_by_helper.append(path)
        shutil.rmtree(path)

    removed = backup.prune_successful_backups(
        root,
        keep_success=2,
        physical_remover=remove_physical,
    )

    assert removed == [oldest[0]]
    assert removed_by_helper == [oldest[0]]
    assert not oldest[1].exists()
    for artifact, manifest in (kept_one, kept_two):
        assert artifact.exists() and manifest.exists()


def test_physical_remove_invokes_the_inode_bound_privileged_helper(tmp_path):
    root = tmp_path / "backups"
    layout = backup.prepare_backup_layout(root)
    target = layout["physical"] / "physical-remove"
    target.mkdir()
    captured = {}

    def fake_runner(command, *, check, env):
        captured["command"] = command
        captured["check"] = check
        captured["env"] = env
        shutil.rmtree(target)
        return subprocess.CompletedProcess(command, 0)

    backup._remove_physical(target, root, runner=fake_runner)

    command = captured["command"]
    assert command[:3] == ["/usr/bin/sudo", "-n", "--"]
    assert "remove-physical-tree" in command
    assert "--expected-parent-dev" in command
    assert "--expected-parent-ino" in command
    assert "--expected-target-dev" in command
    assert "--expected-target-ino" in command
    assert "/usr/bin/rm" not in command
    assert captured["check"] is True
    assert captured["env"]["LC_ALL"] == "C"


def test_prune_rejects_a_symlinked_managed_directory(tmp_path):
    root = tmp_path / "backups"
    layout = backup.prepare_backup_layout(root)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "must-survive"
    sentinel.write_text("keep", encoding="utf-8")
    layout["physical"].rmdir()
    layout["physical"].symlink_to(outside, target_is_directory=True)

    with pytest.raises(backup.PruneError, match="符号链接"):
        backup.prune_successful_backups(root, keep_success=2)

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_logical_backup_rejects_a_symlinked_output_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "logical"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(backup.PreflightError, match="符号链接"):
        backup.backup_database(
            linked / "run.sql.gz",
            _config(),
            progress_stream=io.StringIO(),
        )

    assert not list(outside.iterdir())


def test_capacity_is_rechecked_after_services_stop(monkeypatch, tmp_path):
    monkeypatch.setattr(
        backup.os,
        "statvfs",
        lambda _path: SimpleNamespace(
            f_frsize=1,
            f_bsize=1,
            f_bavail=99,
            f_files=1000,
            f_favail=1000,
        ),
    )

    with pytest.raises(backup.PlanError, match="空间不再满足"):
        backup.revalidate_planned_capacity(
            {
                "required_bytes": 80,
                "reserved_bytes": 20,
                "required_inodes": 1,
            },
            tmp_path,
            strategy="logical",
        )
