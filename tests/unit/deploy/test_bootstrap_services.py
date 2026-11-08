"""首次依赖供应的归属、凭据、重试及已有数据边界。"""

from __future__ import annotations

import json
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

from deploy import bootstrap_services as services


@pytest.fixture
def config():
    return SimpleNamespace(MYSQL_HOST="127.0.0.1", MYSQL_PORT=13306,
                           MYSQL_DB="numoj_dev", MYSQL_USERNAME="oj",
                           MYSQL_PASSWORD="private-development-password",
                           REDIS_HOST="127.0.0.1", REDIS_PORT=16379)


class Docker:
    def __init__(self):
        self.calls = []
        self.containers = {}
        self.ready = set()
        self.fail_create = False

    def probe(self, kind, host, port):
        return (kind, host, port) in self.ready

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        stdout, code = "", 0
        if command[:3] == ["docker", "container", "inspect"]:
            container = self.containers.get(command[3])
            stdout, code = (json.dumps([container]), 0) if container else ("", 1)
        elif command[:2] == ["docker", "run"]:
            if self.fail_create:
                return subprocess.CompletedProcess(command, 1, "", "creation failed")
            labels, mounts, index = {}, [], 2
            while command[index].startswith("--"):
                flag = command[index]
                if flag == "--detach":
                    index += 1
                    continue
                value = command[index + 1]
                if flag == "--name":
                    name = value
                elif flag == "--label":
                    key, item = value.split("=", 1)
                    labels[key] = item
                elif flag == "--volume":
                    source, target, *_ = value.split(":")
                    mounts.append({"Type": "bind", "Source": source, "Destination": target})
                elif flag == "--publish":
                    bind, port, internal = value.split(":")
                index += 2
            kind = labels[services._KIND_LABEL]
            self.containers[name] = {
                "Config": {"Image": command[index], "Labels": labels},
                "Mounts": mounts, "State": {"Running": True},
                "HostConfig": {"PortBindings": {internal + "/tcp": [{"HostIp": bind, "HostPort": port}]}},
            }
            self.ready.add((kind, bind, int(port)))
        elif command[:2] == ["docker", "start"]:
            self.containers[command[2]]["State"]["Running"] = True
            descriptor = self.containers[command[2]]
            kind = descriptor["Config"]["Labels"][services._KIND_LABEL]
            bindings = next(iter(descriptor["HostConfig"]["PortBindings"].values()))[0]
            self.ready.add((kind, bindings["HostIp"], int(bindings["HostPort"])))
        elif command[:2] == ["systemctl", "show"]:
            stdout = "not-found\n"
        return subprocess.CompletedProcess(command, code, stdout, "")


def ensure(root, config, docker, **kwargs):
    return services.ensure_services(root, config, run=docker, probe=docker.probe,
                                    wait_timeout=0, **kwargs)


def test_available_external_services_are_reused_without_commands(tmp_path, config):
    docker = Docker()
    docker.ready = {("mysql", config.MYSQL_HOST, config.MYSQL_PORT),
                    ("redis", config.REDIS_HOST, config.REDIS_PORT)}
    assert ensure(tmp_path, config, docker) == {
        "managed_mysql": False, "managed_redis": False, "first_database": False,
    }
    assert docker.calls == []
    assert not (tmp_path / ".deploy").exists()


def test_missing_existing_endpoint_never_silently_creates_empty_database(tmp_path, config):
    docker = Docker()
    with pytest.raises(services.BootstrapServiceError, match="首次初始化授权"):
        ensure(tmp_path, config, docker)
    assert not docker.calls
    assert not (tmp_path / ".deploy").exists()


def test_remote_endpoint_is_never_provisioned_even_with_authorization(tmp_path, config):
    config.MYSQL_HOST = "database.example.com"
    with pytest.raises(services.BootstrapServiceError, match="远端服务"):
        ensure(tmp_path, config, Docker(), allow_create=True)


def test_first_install_keeps_password_out_of_argv_and_preserves_missing_database(tmp_path, config):
    docker = Docker()
    result = ensure(tmp_path, config, docker, allow_create=True)
    assert result == {"managed_mysql": True, "managed_redis": True, "first_database": True}
    assert config.MYSQL_PASSWORD not in repr(docker.calls)
    path = tmp_path / ".deploy/services/mysql/environment"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert f"MYSQL_PASSWORD={config.MYSQL_PASSWORD}\n" in path.read_text()
    assert "MYSQL_DATABASE=" not in path.read_text()
    assert r"GRANT ALL PRIVILEGES ON `numoj\_dev`.* TO 'oj'@'%';" in path.with_name("grants.sql").read_text()
    commands = [call for call in docker.calls if call[:2] == ["docker", "run"]]
    assert len(commands) == 2
    assert all(call[call.index("--restart") + 1] == "unless-stopped" for call in commands)
    assert all(call[call.index("--publish") + 1].startswith("127.0.0.1:") for call in commands)


def test_rerun_reuses_same_containers_credentials_and_seed_pending(tmp_path, config):
    docker = Docker()
    ensure(tmp_path, config, docker, allow_create=True)
    env_path = tmp_path / ".deploy/services/mysql/environment"
    original = env_path.read_bytes()
    names = set(docker.containers)
    result = ensure(tmp_path, config, docker)
    assert result["first_database"] is True
    services.mark_database_initialized(tmp_path)
    assert ensure(tmp_path, config, docker)["first_database"] is False
    assert env_path.read_bytes() == original
    assert set(docker.containers) == names
    assert len([c for c in docker.calls if c[:2] == ["docker", "run"]]) == 2


def test_failed_initial_creation_can_retry_from_persisted_owned_state(tmp_path, config):
    docker = Docker()
    docker.fail_create = True
    with pytest.raises(services.BootstrapServiceError, match="创建失败"):
        ensure(tmp_path, config, docker, allow_create=True)
    docker.fail_create = False
    assert ensure(tmp_path, config, docker)["managed_redis"] is True


def test_foreign_same_name_container_is_never_started_or_replaced(tmp_path, config):
    docker = Docker()
    ensure(tmp_path, config, docker, allow_create=True)
    container = next(iter(docker.containers.values()))
    container["Config"]["Labels"][services._ROOT_LABEL] = "/other/deployment"
    container["State"]["Running"] = False
    before = len(docker.calls)
    with pytest.raises(services.BootstrapServiceError, match="不属于此部署"):
        ensure(tmp_path, config, docker)
    assert all(call[:2] not in (["docker", "start"], ["docker", "rm"])
               for call in docker.calls[before:])


def test_stopped_owned_container_is_started_without_recreation(tmp_path, config):
    docker = Docker()
    ensure(tmp_path, config, docker, allow_create=True)
    name, container = next(iter(docker.containers.items()))
    container["State"]["Running"] = False
    docker.ready.clear()
    for other in docker.containers.values():
        kind = other["Config"]["Labels"][services._KIND_LABEL]
        if kind != "mysql":
            docker.ready.add((kind, config.REDIS_HOST, config.REDIS_PORT))
    ensure(tmp_path, config, docker)
    assert ["docker", "start", name] in docker.calls
    assert len([c for c in docker.calls if c[:2] == ["docker", "run"]]) == 2


@pytest.mark.parametrize("relative", [".deploy", ".deploy/services"])
def test_directory_symlink_is_rejected_before_any_write(tmp_path, config, relative):
    outside = tmp_path / "outside"
    outside.mkdir()
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(outside, target_is_directory=True)
    with pytest.raises(services.BootstrapServiceError, match="符号链接"):
        ensure(tmp_path, config, Docker(), allow_create=True)
    assert list(outside.iterdir()) == []


def test_mysql_probe_accepts_fragmented_handshake(monkeypatch):
    class Connection:
        def __enter__(self):
            self.parts = iter((b"\x4a", b"\x00\x00", b"\x00\x0a"))
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, value):
            pass

        def recv(self, size):
            return next(self.parts)

    monkeypatch.setattr(services.socket, "create_connection", lambda *a, **k: Connection())
    assert services._probe("mysql", "127.0.0.1", 3306) is True


def test_backup_container_lookup_requires_matching_owned_running_container(tmp_path, config):
    docker = Docker()
    assert services.managed_mysql_container(tmp_path, run=docker) is None
    assert not docker.calls
    ensure(tmp_path, config, docker, allow_create=True)
    name = services.managed_mysql_container(tmp_path, run=docker)
    assert name.startswith("numoj-mysql-")
    assert services.managed_mysql_container(tmp_path, host=config.MYSQL_HOST,
                                            port=config.MYSQL_PORT, run=docker) == name
    with pytest.raises(services.BootstrapServiceError, match="地址不一致"):
        services.managed_mysql_container(tmp_path, host="localhost", run=docker)
    with pytest.raises(services.BootstrapServiceError, match="地址不一致"):
        services.managed_mysql_container(tmp_path, port=3306, run=docker)
    docker.containers[name]["State"]["Running"] = False
    with pytest.raises(services.BootstrapServiceError, match="未运行"):
        services.managed_mysql_container(tmp_path, run=docker)
    docker.containers[name]["State"]["Running"] = True
    docker.containers[name]["Config"]["Labels"][services._ROOT_LABEL] = "/foreign"
    with pytest.raises(services.BootstrapServiceError, match="不属于此部署"):
        services.managed_mysql_container(tmp_path, run=docker)
