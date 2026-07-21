from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

from deploy.backup import physical as xtrabackup


ROOT = Path(__file__).resolve().parents[3]

SERVER_UUID = "12345678-1234-1234-1234-123456789abc"


@pytest.fixture
def mysql_environment(monkeypatch, tmp_path):
    datadir = tmp_path / "data"
    datadir.mkdir()
    socket_path = tmp_path / "mysql.sock"
    socket_path.touch()
    real_lstat = Path.lstat

    def fake_lstat(path):
        if path == socket_path:
            return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o770)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    return xtrabackup.ServerMetadata(
        version="8.0.36",
        version_comment="MySQL Community Server - GPL",
        datadir=str(datadir),
        socket=str(socket_path),
        server_uuid=SERVER_UUID,
    )


def _build_plan(metadata, *, package_version="8.0.35-36-1.bookworm"):
    return xtrabackup.build_plan(
        metadata,
        mysql_host="db.production.internal",
        package_version=package_version,
    )


@pytest.mark.parametrize(
    ("version", "comment", "expected"),
    [
        (
            "8.0.34",
            "MySQL Community Server - GPL",
            ("8.0.35-36", "percona-xtrabackup-80", "pxb-80"),
        ),
        (
            "8.0.44-35",
            "Percona Server (GPL), Release 35",
            ("8.0.35-36", "percona-xtrabackup-80", "pxb-80"),
        ),
        (
            "8.4.0",
            "MySQL Enterprise Server - Commercial",
            ("8.4.0-6", "percona-xtrabackup-84", "pxb-84-lts"),
        ),
        (
            "8.4.6-6",
            "Percona Server (GPL), Release 6",
            ("8.4.0-6", "percona-xtrabackup-84", "pxb-84-lts"),
        ),
    ],
)
def test_select_release_uses_the_fixed_compatibility_matrix(
    version, comment, expected
):
    release = xtrabackup.select_release(version, comment)

    assert release is not None
    assert (
        release.upstream_version,
        release.package_name,
        release.apt_repository,
    ) == expected


@pytest.mark.parametrize(
    ("version", "comment"),
    [
        ("8.0.33", "MySQL Community Server - GPL"),
        ("5.7.44", "MySQL Community Server - GPL"),
        ("9.0.1", "MySQL Community Server - GPL"),
        ("8.0.36-MariaDB", "Debian 12"),
        ("8.0.36", "Amazon Aurora MySQL"),
        ("8.0.36", "TiDB Server"),
        ("8.0.36", "unknown distribution"),
        ("not-a-version", "MySQL Community Server - GPL"),
    ],
)
def test_select_release_fails_closed_for_unknown_or_incompatible_servers(
    version, comment
):
    assert xtrabackup.select_release(version, comment) is None


def test_fixed_upstream_version_accepts_only_debian_revisions_of_that_release():
    release = xtrabackup.MYSQL_80_RELEASE

    assert release.accepts_package_version("8.0.35-36")
    assert release.accepts_package_version("1:8.0.35-36-1.bookworm")
    assert not release.accepts_package_version("8.0.35-360")
    assert not release.accepts_package_version("8.0.35-37")
    assert not release.accepts_package_version("8.0.36-36")


def test_server_metadata_requires_the_exact_five_query_columns(mysql_environment):
    row = {
        "version": mysql_environment.version,
        "version_comment": mysql_environment.version_comment,
        "datadir": mysql_environment.datadir,
        "socket": mysql_environment.socket,
        "server_uuid": mysql_environment.server_uuid,
    }

    assert xtrabackup.ServerMetadata.from_query_row(row) == mysql_environment
    assert xtrabackup.ServerMetadata.from_query_row(tuple(row.values())) == mysql_environment
    assert "@@server_uuid" in xtrabackup.SERVER_METADATA_SQL

    with pytest.raises(xtrabackup.PlanValidationError, match="精确"):
        xtrabackup.ServerMetadata.from_query_row({**row, "unexpected": "value"})
    with pytest.raises(xtrabackup.PlanValidationError, match="五列"):
        xtrabackup.ServerMetadata.from_query_row(tuple(row.values())[:-1])


def test_plan_json_round_trip_is_strict_and_self_validating(mysql_environment):
    plan = _build_plan(mysql_environment)

    restored = xtrabackup.XtraBackupPlan.from_json(plan.to_json())

    assert restored == plan
    assert restored.to_dict()["server_uuid"] == SERVER_UUID

    tampered = restored.to_dict()
    tampered["package_name"] = "untrusted-package"
    with pytest.raises(xtrabackup.PlanValidationError, match="兼容矩阵"):
        xtrabackup.XtraBackupPlan.from_dict(tampered)

    with pytest.raises(xtrabackup.PlanValidationError, match="重复 JSON 字段"):
        xtrabackup.XtraBackupPlan.from_json(
            '{"schema_version":1,"schema_version":1}'
        )


def test_plan_rejects_unknown_fields_and_non_exact_package_versions(
    mysql_environment,
):
    values = _build_plan(mysql_environment).to_dict()
    values["future_field"] = True
    with pytest.raises(xtrabackup.PlanValidationError, match="字段不匹配"):
        xtrabackup.XtraBackupPlan.from_dict(values)

    values.pop("future_field")
    values["package_version"] = "8.0.35-360"
    with pytest.raises(xtrabackup.PlanValidationError, match="固定上游版本"):
        xtrabackup.XtraBackupPlan.from_dict(values)


def test_environment_requires_real_local_datadir_and_unix_socket(
    mysql_environment, tmp_path
):
    datadir_link = tmp_path / "linked-data"
    datadir_link.symlink_to(mysql_environment.datadir, target_is_directory=True)
    linked = xtrabackup.ServerMetadata(
        version=mysql_environment.version,
        version_comment=mysql_environment.version_comment,
        datadir=str(datadir_link),
        socket=mysql_environment.socket,
        server_uuid=SERVER_UUID,
    )

    datadir, _ = xtrabackup.validate_server_environment(linked)
    assert datadir == Path(mysql_environment.datadir).resolve()

    regular_file = tmp_path / "not-a-socket"
    regular_file.touch()
    invalid_socket = xtrabackup.ServerMetadata(
        version=mysql_environment.version,
        version_comment=mysql_environment.version_comment,
        datadir=mysql_environment.datadir,
        socket=str(regular_file),
        server_uuid=SERVER_UUID,
    )
    with pytest.raises(xtrabackup.EnvironmentValidationError, match="Unix socket"):
        xtrabackup.validate_server_environment(invalid_socket)


class FakeRunner:
    def __init__(self, plan, binary, *, root_uuid=SERVER_UUID):
        self.plan = plan
        self.binary = binary
        self.root_uuid = root_uuid
        self.calls = []
        self.target = None
        self.fail_backup = False
        self.checkpoints = (
            "backup_type = full-prepared\n"
            "from_lsn = 0\n"
            "to_lsn = 120\n"
            "last_lsn = 125\n"
        )

    def __call__(self, command, **kwargs):
        command = [str(argument) for argument in command]
        self.calls.append((command, kwargs))
        stdout = ""
        stderr = ""

        if command in (
            [str(xtrabackup.SUDO_BINARY), "-v"],
            [str(xtrabackup.SUDO_BINARY), "-n", "-v"],
        ):
            pass
        elif "--search" in command:
            stdout = f"{self.plan.package_name}: {self.binary}\n"
        elif "--show" in command:
            stdout = f"install ok installed\t{self.plan.package_version}\n"
        elif command == [
            str(xtrabackup.DPKG_BINARY),
            "--verify",
            self.plan.package_name,
        ]:
            pass
        elif command == [str(self.binary), "--version"]:
            stderr = (
                f"{self.binary} version {self.plan.upstream_version} "
                "based on MySQL server\n"
            )
        elif str(xtrabackup.MYSQL_BINARY) in command:
            stdout = f"{self.root_uuid}\n"
        elif str(xtrabackup.INSTALL_BINARY) in command:
            self.target = Path(command[-1])
            self.target.mkdir()
            self.target.chmod(0o700)
        elif str(xtrabackup.STAT_BINARY) in command:
            stdout = "0:0:700:directory\n"
        elif str(self.binary) in command and "--backup" in command:
            if self.fail_backup:
                raise subprocess.CalledProcessError(1, command)
        elif str(self.binary) in command and "--prepare" in command:
            pass
        elif str(xtrabackup.FIND_BINARY) in command:
            stdout = "f\t10\nf\t20\nf\t30\nf\t40\n"
        elif str(xtrabackup.CAT_BINARY) in command:
            stdout = self.checkpoints
        elif str(xtrabackup.TEST_BINARY) in command:
            pass
        else:
            raise AssertionError(f"unexpected command: {command}")

        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=stderr)


@pytest.fixture
def installed_backend(monkeypatch, tmp_path, mysql_environment):
    binary = tmp_path / "xtrabackup"
    binary.write_text("binary", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setattr(xtrabackup, "XTRABACKUP_BINARY", binary)
    plan = _build_plan(mysql_environment)
    runner = FakeRunner(plan, binary)
    return plan, binary, runner


def test_installation_is_bound_to_exact_dpkg_owner_and_binary_version(
    installed_backend,
):
    plan, binary, runner = installed_backend

    xtrabackup.validate_installation(plan, runner=runner)

    commands = [call[0] for call in runner.calls]
    assert [str(xtrabackup.DPKG_QUERY_BINARY), "--search", str(binary)] in commands
    assert [str(binary), "--version"] in commands


def test_prepare_plan_runs_the_installed_backend_and_root_socket_happy_path(
    mysql_environment, installed_backend
):
    expected, _, runner = installed_backend

    prepared = xtrabackup.prepare_plan(
        mysql_environment,
        mysql_host=expected.mysql_host,
        installer=lambda _release: pytest.fail(
            "a valid pinned installation must not be replaced"
        ),
        runner=runner,
    )

    assert prepared == expected
    commands = [command for command, _ in runner.calls]
    sudo_index = commands.index([str(xtrabackup.SUDO_BINARY), "-v"])
    socket_index = next(
        index
        for index, command in enumerate(commands)
        if str(xtrabackup.MYSQL_BINARY) in command
    )
    assert sudo_index < socket_index
    assert "--execute=SELECT @@server_uuid" in commands[socket_index]
    assert not any("--backup" in command for command in commands)


def test_installation_rejects_wrong_dpkg_owner(installed_backend):
    plan, binary, runner = installed_backend
    original = runner.__call__

    def wrong_owner(command, **kwargs):
        if "--search" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"other-package: {binary}\n",
                stderr="",
            )
        return original(command, **kwargs)

    with pytest.raises(xtrabackup.InstallationValidationError, match="other-package"):
        xtrabackup.validate_installation(plan, runner=wrong_owner)


def test_root_socket_preflight_requires_the_same_server_uuid(installed_backend):
    plan, _, runner = installed_backend

    xtrabackup.preflight_root_socket(plan, runner=runner)

    mysql_call = next(
        call for call in runner.calls if str(xtrabackup.MYSQL_BINARY) in call[0]
    )
    command, kwargs = mysql_call
    assert "--no-defaults" in command
    assert "--protocol=socket" in command
    assert "--execute=SELECT @@server_uuid" in command
    assert not any("password" in argument.lower() for argument in command)
    assert not any("PASSWORD" in key or "PWD" in key for key in kwargs["env"])

    mismatch_runner = FakeRunner(plan, runner.binary, root_uuid="ffffffff-ffff-ffff-ffff-ffffffffffff")
    with pytest.raises(xtrabackup.RootSocketAuthenticationError, match="同一 MySQL 实例"):
        xtrabackup.preflight_root_socket(plan, runner=mismatch_runner)


def test_root_socket_preflight_uses_validated_ephemeral_credentials(
    installed_backend, tmp_path
):
    plan, _, runner = installed_backend
    defaults_file = tmp_path / "mysql.cnf"
    defaults_file.write_text("[client]\npassword=secret\n", encoding="utf-8")
    defaults_file.chmod(0o600)

    xtrabackup.preflight_root_socket(
        plan,
        mysql_defaults_file=defaults_file,
        runner=runner,
    )

    command, kwargs = next(
        call for call in runner.calls if str(xtrabackup.MYSQL_BINARY) in call[0]
    )
    assert command[4] == f"--defaults-file={defaults_file}"
    assert "--no-defaults" not in command
    assert "--user=root" not in command
    assert not any("secret" in argument for argument in command)
    assert not any("PASSWORD" in key or "PWD" in key for key in kwargs["env"])


def test_execute_full_backup_runs_backup_then_prepare_and_validates_result(
    installed_backend, tmp_path
):
    plan, _, runner = installed_backend
    target = tmp_path / "backups" / "mysql-run"
    target.parent.mkdir()
    defaults_file = tmp_path / "mysql.cnf"
    defaults_file.write_text("[xtrabackup]\npassword=secret\n", encoding="utf-8")
    defaults_file.chmod(0o600)

    result = xtrabackup.execute_full_backup(
        plan,
        target,
        mysql_defaults_file=defaults_file,
        runner=runner,
    )

    commands = [call[0] for call in runner.calls]
    backup_index = next(index for index, command in enumerate(commands) if "--backup" in command)
    prepare_index = next(index for index, command in enumerate(commands) if "--prepare" in command)
    assert backup_index < prepare_index
    backup_command = commands[backup_index]
    assert [str(xtrabackup.SUDO_BINARY), "-n", "-v"] in commands
    assert backup_command[:4] == [
        str(xtrabackup.SUDO_BINARY),
        "-n",
        "--",
        str(runner.binary),
    ]
    assert f"--defaults-file={defaults_file}" in backup_command
    assert "--no-defaults" not in backup_command
    assert "--user=root" not in backup_command
    assert "--strict" in backup_command
    assert "--check-privileges" in backup_command
    assert "--parallel=4" in backup_command
    assert "--ftwrl-wait-timeout=60" in backup_command
    assert f"--datadir={plan.datadir}" in backup_command
    assert f"--socket={plan.mysql_socket}" in backup_command
    assert "--no-server-version-check" not in backup_command
    assert not any("password" in argument.lower() for argument in backup_command)
    assert all(
        command[1] == "-n"
        for command in commands
        if command and command[0] == str(xtrabackup.SUDO_BINARY)
        and command != [str(xtrabackup.SUDO_BINARY), "-v"]
    )
    assert result.to_dict() == {
        "target": str(target),
        "backup_type": "full-prepared",
        "from_lsn": 0,
        "to_lsn": 120,
        "last_lsn": 125,
        "file_count": 4,
        "total_bytes": 100,
    }
    assert all(
        not any("PASSWORD" in key or "PWD" in key for key in kwargs["env"])
        for _, kwargs in runner.calls
    )


def test_backup_failure_is_not_prepared_cleaned_or_fallen_back(
    installed_backend, tmp_path
):
    plan, _, runner = installed_backend
    runner.fail_backup = True
    target = tmp_path / "backups" / "failed-run"
    target.parent.mkdir()

    with pytest.raises(subprocess.CalledProcessError):
        xtrabackup.execute_full_backup(plan, target, runner=runner)

    commands = [call[0] for call in runner.calls]
    assert any("--backup" in command for command in commands)
    assert not any("--prepare" in command for command in commands)
    assert not any("mysqldump" in argument for command in commands for argument in command)
    assert target.is_dir()


def test_prepared_backup_validation_rejects_non_full_checkpoint(
    installed_backend, tmp_path
):
    plan, _, runner = installed_backend
    target = tmp_path / "backup"
    target.mkdir()
    target.chmod(0o700)
    runner.checkpoints = (
        "backup_type = full-backuped\n"
        "from_lsn = 0\n"
        "to_lsn = 120\n"
        "last_lsn = 125\n"
    )

    with pytest.raises(xtrabackup.BackupValidationError, match="full-prepared"):
        xtrabackup.inspect_prepared_backup(plan, target, runner=runner)


def test_backup_target_must_not_exist_or_overlap_datadir(
    mysql_environment, tmp_path
):
    datadir = Path(mysql_environment.datadir)
    with pytest.raises(xtrabackup.EnvironmentValidationError, match="重叠"):
        xtrabackup.validate_new_target(datadir / "backup", datadir)

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(xtrabackup.EnvironmentValidationError, match="尚不存在"):
        xtrabackup.validate_new_target(existing, datadir)


def test_physical_capacity_preflight_reserves_space_and_inodes(
    monkeypatch, installed_backend, tmp_path
):
    plan, _, _ = installed_backend
    parent = tmp_path / "physical"
    parent.mkdir()

    def runner(command, **_kwargs):
        command = [str(item) for item in command]
        if str(xtrabackup.DU_BINARY) in command:
            if "--inodes" in command:
                size = "100"
            else:
                size = (
                    "10737418240"
                    if "--apparent-size" in command
                    else "8589934592"
                )
            return subprocess.CompletedProcess(command, 0, stdout=f"{size}\tdata\n")
        raise AssertionError(command)

    monkeypatch.setattr(
        xtrabackup.os,
        "statvfs",
        lambda _path: SimpleNamespace(
            f_frsize=4096,
            f_bsize=4096,
            f_bavail=10_000_000,
            f_blocks=20_000_000,
            f_files=1_000_000,
            f_favail=900_000,
        ),
    )

    capacity = xtrabackup.preflight_physical_capacity(
        plan, parent, runner=runner
    )

    assert capacity.apparent_bytes == 10 * 1024**3
    assert capacity.required_bytes > capacity.apparent_bytes
    assert capacity.source_inode_count == 100
    assert capacity.available_inodes == 900_000


def test_physical_capacity_preflight_fails_before_backup_when_space_is_short(
    monkeypatch, installed_backend, tmp_path
):
    plan, _, _ = installed_backend
    parent = tmp_path / "physical"
    parent.mkdir()

    def runner(command, **_kwargs):
        command = [str(item) for item in command]
        if str(xtrabackup.DU_BINARY) in command:
            if "--inodes" in command:
                return subprocess.CompletedProcess(
                    command, 0, stdout="100\tdata\n"
                )
            return subprocess.CompletedProcess(
                command, 0, stdout=f"{10 * 1024**3}\tdata\n"
            )
        raise AssertionError(command)

    monkeypatch.setattr(
        xtrabackup.os,
        "statvfs",
        lambda _path: SimpleNamespace(
            f_frsize=4096,
            f_bsize=4096,
            f_bavail=100,
            f_blocks=20_000_000,
            f_files=1_000_000,
            f_favail=900_000,
        ),
    )

    with pytest.raises(xtrabackup.EnvironmentValidationError, match="空间不足"):
        xtrabackup.preflight_physical_capacity(plan, parent, runner=runner)


def test_module_pins_absolute_debian_binary_paths():
    assert xtrabackup.XTRABACKUP_BINARY == Path("/usr/bin/xtrabackup")
    assert xtrabackup.MYSQL_BINARY == Path("/usr/bin/mysql")
    assert xtrabackup.DPKG_QUERY_BINARY == Path("/usr/bin/dpkg-query")
    assert xtrabackup.DPKG_BINARY == Path("/usr/bin/dpkg")
    assert xtrabackup.DU_BINARY == Path("/usr/bin/du")
    source = (ROOT / "deploy" / "backup" / "physical.py").read_text(
        encoding="utf-8"
    )
    assert "--no-server-version-check" not in source.replace(
        '"--no-server-version-check"', ""
    )
    assert '"mysqldump"' not in source
    assert "'mysqldump'" not in source
