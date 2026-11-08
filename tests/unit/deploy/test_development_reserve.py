"""开发固定磁盘预留不得进入生产、原生或远程数据库路径。"""

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from deploy import bootstrap
from deploy.backup import container_client, development, orchestrator as backup


CONTAINER = "numoj-mysql-" + "a" * 16
ENDPOINT = "unix:///var/run/docker.sock"
GIB = 1024**3


def _filesystem(*, free=54 * GIB, inodes=10000):
    return SimpleNamespace(f_frsize=1, f_bsize=1, f_bavail=free, f_blocks=1800 * GIB,
                           f_files=10000, f_favail=inodes)


@pytest.fixture
def site(tmp_path, monkeypatch):
    root = tmp_path / "site"
    state = root / ".deploy"
    state.mkdir(parents=True, mode=0o700)
    profile = state / "profile"
    profile.write_text("test-cpu\n")
    profile.chmod(0o600)
    settings = SimpleNamespace(host="127.0.0.1", port=3306, database="numoj_dev_test")
    config = SimpleNamespace(MYSQL_HOST=settings.host, MYSQL_PORT=settings.port, MYSQL_DB=settings.database,
                             MYSQL_USERNAME="oj", MYSQL_PASSWORD="private-password")
    snapshot = backup.DatabaseSnapshot("8.4.4", "MySQL Community Server - GPL", True)
    monkeypatch.setattr(backup, "ROOT", root)
    monkeypatch.setattr(development.socket, "gethostname", lambda: "development.example")
    monkeypatch.setattr(development, "_local_docker_endpoint", lambda: ENDPOINT)
    monkeypatch.setattr(container_client, "owned_container", lambda *_: CONTAINER)
    monkeypatch.setattr(container_client, "validate_client", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backup, "discover_database", lambda _: backup.DatabaseDiscovery(snapshot, 1024, 3))
    monkeypatch.setattr(backup, "inspect_database", lambda _: snapshot)
    monkeypatch.setattr(backup.os, "statvfs", lambda _: _filesystem())
    return SimpleNamespace(root=root, profile=profile, settings=settings, config=config)


def _plan(site):
    root = site.root / ".deploy/backups"
    path = root / "plans/development.json"
    document = backup.create_preflight_plan(path, root, "development", site.config,
                                           logical_only=True, development_reserve=True)
    return path, document


def test_large_development_disk_retains_required_bytes_and_inodes_with_two_gib_reserve(site):
    with pytest.raises(backup.PreflightError, match="空间不足"):
        backup._logical_capacity(site.root, estimated_bytes=1024, estimated_inodes=4)
    capacity = backup._logical_capacity(site.root, estimated_bytes=1024, estimated_inodes=4,
                                        development_reserve=True)
    assert capacity["reserved_bytes"] == 2 * GIB
    assert capacity["required_bytes"] == 64 * 1024**2 + 2048
    assert capacity["required_inodes"] == 64


@pytest.mark.parametrize("free,inodes,error", [(2 * GIB, 10000, "空间不足"), (54 * GIB, 63, "inode 不足")])
def test_development_reserve_still_rejects_insufficient_space_or_inodes(site, monkeypatch, free, inodes, error):
    monkeypatch.setattr(backup.os, "statvfs", lambda _: _filesystem(free=free, inodes=inodes))
    with pytest.raises(backup.PreflightError, match=error):
        _plan(site)


@pytest.mark.parametrize("case", ["production-profile", "public-profile", "symlink-profile", "production-host",
                                  "production-fqdn", "production-alias", "ordinary-database", "remote-database", "native-database"])
def test_development_reserve_requires_every_development_fact(site, monkeypatch, case):
    if case == "production-profile":
        site.profile.write_text("production\n")
    elif case == "public-profile":
        site.profile.chmod(0o644)
    elif case == "symlink-profile":
        target = site.profile.with_name("other-profile")
        site.profile.rename(target)
        site.profile.symlink_to(target)
    elif case in {"production-host", "production-fqdn", "production-alias"}:
        hostname = {"production-host": "computing", "production-fqdn": "computing.example", "production-alias": "WHY-SERVER"}[case]
        monkeypatch.setattr(development.socket, "gethostname", lambda: hostname)
    elif case == "ordinary-database":
        site.config.MYSQL_DB = "myojdb"
    elif case == "remote-database":
        site.config.MYSQL_HOST = "db.example"
    else:
        monkeypatch.setattr(container_client, "owned_container", lambda *_: None)
    with pytest.raises(backup.PreflightError, match="开发备份预留"):
        _plan(site)


def test_development_reserve_requires_explicit_managed_logical_mode(tmp_path):
    with pytest.raises(backup.PreflightError, match="受管 MySQL 逻辑备份"):
        backup.create_preflight_plan(tmp_path / "unused.json", tmp_path, "unused", development_reserve=True)


@pytest.mark.parametrize("database,eligible", [("numoj_dev_test", True), ("custom_cpu_site", False)])
def test_readonly_eligibility_keeps_custom_cpu_database_on_standard_policy(site, monkeypatch, database, eligible):
    site.config.MYSQL_DB = database
    monkeypatch.setattr(bootstrap, "_load_config", lambda _: site.config)
    assert bootstrap.development_reserve_eligible(site.root) is eligible
    assert not (site.root / ".deploy/backups").exists()


def test_development_plan_records_all_facts_without_credentials_and_executes_after_revalidation(site, monkeypatch):
    path, document = _plan(site)
    facts = document["capacity"]["reserve_policy"]
    assert facts == {
        "mode": "development-managed-test", "deployment_root": str(site.root), "profile": "test-cpu",
        "hostname": "development.example", "database": "numoj_dev_test", "mysql_host": "127.0.0.1",
        "mysql_port": 3306, "container_name": CONTAINER, "docker_endpoint": ENDPOINT,
    }
    assert backup.read_plan(path)["capacity"]["reserve_policy"] == facts
    assert "private-password" not in path.read_text()
    calls = []
    monkeypatch.setattr(backup, "backup_database", lambda artifact, *_args, **kwargs: calls.append(kwargs) or artifact)
    output = backup.execute_backup_plan(path, Path(document["backup_root"]) / document["manifest_relative_path"], site.config)
    assert output.name == "development.sql.gz"
    assert calls[0]["managed_container"] == CONTAINER


@pytest.mark.parametrize("change", ["profile", "hostname", "container", "endpoint", "space"])
def test_backup_rechecks_development_identity_and_capacity_inside_stopped_window(site, monkeypatch, change):
    path, document = _plan(site)
    if change == "profile":
        site.profile.write_text("production\n")
    elif change == "hostname":
        monkeypatch.setattr(development.socket, "gethostname", lambda: "other-development")
    elif change == "container":
        monkeypatch.setattr(container_client, "owned_container", lambda *_: "numoj-mysql-" + "b" * 16)
    elif change == "endpoint":
        monkeypatch.setattr(development, "_local_docker_endpoint", lambda: "unix:///another-docker.sock")
    else:
        monkeypatch.setattr(backup.os, "statvfs", lambda _: _filesystem(free=2 * GIB))
    monkeypatch.setattr(backup, "backup_database", lambda *_args, **_kwargs: pytest.fail("核验失败前不得开始备份"))
    with pytest.raises(backup.PlanError, match="停服后"):
        backup.execute_backup_plan(path, Path(document["backup_root"]) / document["manifest_relative_path"], site.config)


@pytest.mark.parametrize("damage", ["mode", "reserved-bytes", "extra-field"])
def test_plan_reader_rejects_malformed_development_policy(site, damage):
    path, document = _plan(site)
    if damage == "mode":
        document["capacity"]["reserve_policy"]["mode"] = "allow-everywhere"
    elif damage == "reserved-bytes":
        document["capacity"]["reserved_bytes"] = 1
    else:
        document["capacity"]["reserve_policy"]["unchecked"] = True
    path.write_text(json.dumps(document))
    with pytest.raises(backup.PlanError, match="开发预留字段无效"):
        backup.read_plan(path)


@pytest.mark.parametrize("endpoint,context,success", [(ENDPOINT, "", True), ("tcp://remote:2375", "", False),
                                                      ("ssh://remote", "", False), ("tcp://remote:2375", "local-context", True)])
def test_docker_endpoint_must_be_local_and_matches_cli_context_precedence(monkeypatch, endpoint, context, success):
    monkeypatch.setenv("DOCKER_HOST", endpoint)
    monkeypatch.setenv("DOCKER_CONTEXT", context)
    monkeypatch.setattr(container_client, "_docker", lambda: "/usr/bin/docker")
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(ENDPOINT), "")
    monkeypatch.setattr(development.subprocess, "run", run)
    if success:
        assert development._local_docker_endpoint() == ENDPOINT
    else:
        with pytest.raises(development.DevelopmentReserveError, match="本机 Unix"):
            development._local_docker_endpoint()
    assert bool(calls) is bool(context)


@pytest.mark.parametrize("profile,managed,eligible", [("production", "0", "1"), ("production", "1", "1"),
                                                    ("test-cpu", "0", "1"), ("test-cpu", "1", "1"), ("test-cpu", "1", "0")])
def test_deploy_only_requests_development_reserve_for_eligible_managed_cpu_profile(profile, managed, eligible):
    script = (Path(__file__).resolve().parents[3] / "deploy.sh").read_text()
    start = script.index('if [[ "$("$CANDIDATE_PYTHON" -B deploy/bootstrap.py value --file "$SERVICES_BOOTSTRAP_RESULT" --field managed_mysql)" == 1 ]]; then')
    block = script[start:script.index("\nFIRST_INSTALL=", start)]
    source = r'''
python_stub() {
  if [[ "$*" == *"--field managed_mysql" ]]; then
    printf '%s' "$MANAGED"
  elif [[ "$*" == *development-reserve-eligible* ]]; then
    printf '%s' "$ELIGIBLE"
  fi
}
CANDIDATE_PYTHON=python_stub
BOOTSTRAP_PYTHON=python_stub
ROOT_DIR=unused
SERVICES_BOOTSTRAP_RESULT=unused
DEPLOY_PROFILE="$1"
MANAGED="$2"
ELIGIBLE="$3"
backup_preflight_arguments=()
''' + block + '\nprintf "%s\\n" "${backup_preflight_arguments[@]}"\n'
    result = subprocess.run(["bash", "-c", source, "reserve-profile-test", profile, managed, eligible], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    arguments = result.stdout.split()
    assert ("--logical-only" in arguments) is (managed == "1")
    assert ("--development-reserve" in arguments) is (managed == "1" and profile == "test-cpu" and eligible == "1")
