"""仅为已核验的本机 CPU 开发测试库提供固定磁盘预留。"""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

from deploy.backup import container_client
from deploy.backup.paths import assert_no_symlink_components


RESERVE_BYTES = 2 * 1024**3
POLICY_MODE = "development-managed-test"
_PRODUCTION_HOSTS = frozenset({"computing", "why-server"})
_POLICY_FIELDS = frozenset({
    "mode", "deployment_root", "profile", "hostname", "database", "mysql_host",
    "mysql_port", "container_name", "docker_endpoint",
})


class DevelopmentReserveError(RuntimeError):
    pass


def _loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _development_hostname(value):
    return (isinstance(value, str) and bool(value)
            and value.lower().rstrip(".").split(".", 1)[0] not in _PRODUCTION_HOSTS)


def _local_endpoint(value):
    return (isinstance(value, str) and value.startswith("unix:///")
            and "\x00" not in value and "\n" not in value and "\r" not in value)


def _local_docker_endpoint():
    environment = container_client.docker_environment()
    # Docker CLI 的显式 context 优先于 DOCKER_HOST；否则后者覆盖当前 context。
    if environment.get("DOCKER_HOST") and not environment.get("DOCKER_CONTEXT"):
        endpoint = environment["DOCKER_HOST"]
    else:
        result = subprocess.run(
            [container_client._docker(), "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
            capture_output=True, text=True, check=False, timeout=30, env=environment,
        )
        if result.returncode:
            raise DevelopmentReserveError("开发备份预留无法确认本机 Docker endpoint")
        try:
            endpoint = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise DevelopmentReserveError("开发备份预留的 Docker endpoint 无效") from exc
    if not _local_endpoint(endpoint):
        raise DevelopmentReserveError("开发备份预留仅允许本机 Unix Docker endpoint")
    return endpoint


def validate_record(value, *, database, container_name, reserved_bytes):
    """先验证冻结记录结构；实际备份前还必须重新验证全部现场事实。"""
    if (not isinstance(value, dict) or set(value) != _POLICY_FIELDS
            or value["mode"] != POLICY_MODE or value["profile"] != "test-cpu"
            or value["database"] != database
            or not isinstance(database, str) or not re.fullmatch(r"[A-Za-z0-9_]+_test", database)
            or value["container_name"] != container_name
            or not isinstance(container_name, str) or not re.fullmatch(r"numoj-mysql-[a-f0-9]{16}", container_name)
            or not _development_hostname(value["hostname"])
            or not isinstance(value["mysql_host"], str) or not _loopback(value["mysql_host"])
            or type(value["mysql_port"]) is not int or not 1 <= value["mysql_port"] <= 65535
            or not _local_endpoint(value["docker_endpoint"])
            or type(reserved_bytes) is not int or reserved_bytes != RESERVE_BYTES):
        raise DevelopmentReserveError("开发备份预留记录无效或不属于受管测试库")
    root = value["deployment_root"]
    if not isinstance(root, str) or not Path(root).is_absolute() or ".." in Path(root).parts:
        raise DevelopmentReserveError("开发备份预留的部署路径无效")


def reserve_facts(root, settings):
    """只读核验 profile、主机、地址和受管容器，不创建服务或修改数据库。"""
    root = Path(root).absolute()
    profile = assert_no_symlink_components(root / ".deploy/profile", label="开发备份 profile")
    info = profile.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
            or info.st_size > 128 or profile.read_text(encoding="ascii").strip() != "test-cpu"):
        raise DevelopmentReserveError("开发备份预留需要当前用户私有的 test-cpu profile")
    hostname = socket.gethostname().lower().rstrip(".")
    if not _development_hostname(hostname):
        raise DevelopmentReserveError("生产主机禁止使用开发备份预留")
    if not re.fullmatch(r"[A-Za-z0-9_]+_test", settings.database) or not _loopback(settings.host):
        raise DevelopmentReserveError("开发备份预留仅允许 loopback 地址的 *_test 数据库")
    endpoint = _local_docker_endpoint()
    container = container_client.owned_container(root, settings)
    facts = {
        "mode": POLICY_MODE, "deployment_root": str(root), "profile": "test-cpu",
        "hostname": hostname, "database": settings.database, "mysql_host": settings.host,
        "mysql_port": settings.port, "container_name": container, "docker_endpoint": endpoint,
    }
    validate_record(facts, database=settings.database, container_name=container, reserved_bytes=RESERVE_BYTES)
    return facts
