#!/usr/bin/env python3
"""显式首次部署的本机 MySQL/Redis 引导；已有服务与数据始终优先复用。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time


class BootstrapServiceError(RuntimeError):
    """服务归属或首次初始化条件无法确认。"""


_ROOT_LABEL = "org.numericaloj.service-root"
_KIND_LABEL = "org.numericaloj.service-kind"
_INSTANCE_LABEL = "org.numericaloj.service-instance"
_MYSQL_IMAGE = "mysql:8.4.4"
_REDIS_IMAGE = "redis:7.4-alpine"


def _private_file(path: Path):
    if path.is_symlink():
        raise BootstrapServiceError("服务状态或凭据不能是符号链接")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise BootstrapServiceError("无法安全读取服务状态或凭据") from exc
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise BootstrapServiceError("服务状态或凭据必须属于部署用户且权限为 0600")


def _save(path: Path, value):
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(4))
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _state(root: Path):
    path = root / ".deploy/services/state.json"
    if path.parent.is_symlink() or path.parent.parent.is_symlink():
        raise BootstrapServiceError("托管服务的目录祖先不能是符号链接")
    if not path.exists():
        if path.is_symlink():
            raise BootstrapServiceError("服务状态不能是符号链接")
        return path, None
    _private_file(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if (data["root"] != str(root) or data["version"] != 1
                or not re.fullmatch(r"[a-f0-9]{16}", data["instance"])
                or not isinstance(data["services"], dict)):
            raise ValueError
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise BootstrapServiceError("托管服务状态无效，拒绝猜测或覆盖已有数据") from exc
    return path, data


def _command(run, command, *, timeout=30):
    try:
        return run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BootstrapServiceError("本机服务管理命令未能完成；已有数据保持原状") from exc


def _local(host):
    if str(host).lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _probe(kind, host, port):
    try:
        with socket.create_connection((host, port), timeout=2) as connection:
            connection.settimeout(2)
            if kind == "redis":
                connection.sendall(b"*1\r\n$4\r\nPING\r\n")
                return connection.recv(64).startswith(b"+PONG\r\n")
            data = b""
            while len(data) < 5:
                part = connection.recv(5 - len(data))
                if not part:
                    return False
                data += part
            return len(data) == 5 and data[4] == 10
    except OSError:
        return False


def _start_installed(kind, port, run):
    # 非标准端口不能证明与系统服务有关，不启动一项无关的既有数据库。
    if sys.platform != "linux" or port != (3306 if kind == "mysql" else 6379):
        return
    units = ("mysql.service", "mariadb.service") if kind == "mysql" else ("redis-server.service",)
    for unit in units:
        result = _command(run, ["systemctl", "show", "--property=LoadState", "--value", unit])
        if result.returncode == 0 and result.stdout.strip() == "loaded":
            result = _command(run, ["sudo", "-n", "systemctl", "start", unit], timeout=60)
            if result.returncode:
                raise BootstrapServiceError("已安装的本机服务无法启动；拒绝改用空数据库")
            return


def _inspect(run, name):
    result = _command(run, ["docker", "container", "inspect", name])
    if result.returncode:
        # 不能把 daemon 不可达或权限失败误认作容器不存在。
        check = _command(run, ["docker", "info", "--format", "{{.ServerVersion}}"])
        if check.returncode:
            raise BootstrapServiceError("Docker daemon 不可用，无法确认服务容器归属")
        return None
    try:
        rows = json.loads(result.stdout)
        if len(rows) != 1 or not isinstance(rows[0], dict):
            raise ValueError
        return rows[0]
    except (ValueError, TypeError) as exc:
        raise BootstrapServiceError("服务容器状态格式无效") from exc


def _owned(container, root, state, kind, descriptor):
    labels = container.get("Config", {}).get("Labels") or {}
    if any(labels.get(key) != expected for key, expected in (
        (_ROOT_LABEL, str(root)), (_KIND_LABEL, kind), (_INSTANCE_LABEL, state["instance"]),
    )):
        raise BootstrapServiceError("同名容器不属于此部署，拒绝启动或修改")
    target = "/var/lib/mysql" if kind == "mysql" else "/data"
    source = str(root / ".deploy/services" / kind / "data")
    if not any(mount.get("Type") == "bind" and mount.get("Source") == source
               and mount.get("Destination") == target for mount in container.get("Mounts", [])):
        raise BootstrapServiceError("托管服务的数据目录与持久状态不一致")
    key = "3306/tcp" if kind == "mysql" else "6379/tcp"
    bindings = container.get("HostConfig", {}).get("PortBindings", {}).get(key) or []
    if bindings != [{"HostIp": descriptor["bind_host"], "HostPort": str(descriptor["port"])}]:
        raise BootstrapServiceError("托管服务端口或监听地址发生变化")
    if container.get("Config", {}).get("Image") != descriptor["image"]:
        raise BootstrapServiceError("托管服务镜像与持久状态不一致")


def _credentials(directory, kind, config):
    path = directory / "environment"
    if path.exists() or path.is_symlink():
        _private_file(path)
        return path
    if kind != "mysql":
        return None
    database = str(config.MYSQL_DB)
    username = str(config.MYSQL_USERNAME)
    password = str(config.MYSQL_PASSWORD)
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", database):
        raise BootstrapServiceError("首次托管 MySQL 的数据库名无效")
    if (not re.fullmatch(r"[A-Za-z0-9_]{1,32}", username) or not password
            or any(c in password for c in "\r\n\0")):
        raise BootstrapServiceError("首次托管 MySQL 的账号或密码格式无效")
    # 不设置 MYSQL_DATABASE：官方镜像据此提前建库会抹掉首次备份的“库不存在”事实。
    values = {"MYSQL_ROOT_PASSWORD": password if username == "root" else secrets.token_urlsafe(36)}
    if username == "root":
        values["MYSQL_ROOT_HOST"] = "%"
    else:
        values.update(MYSQL_USER=username, MYSQL_PASSWORD=password)
        grants = directory / "grants.sql"
        grant_database = database.replace("_", r"\_")
        grant_sql = f"GRANT ALL PRIVILEGES ON `{grant_database}`.* TO '{username}'@'%';\n"
        if grants.exists() or grants.is_symlink():
            if grants.is_symlink() or not grants.is_file() or grants.read_text() != grant_sql:
                raise BootstrapServiceError("已有 MySQL 首次授权文件不一致")
        else:
            with grants.open("x", encoding="utf-8") as stream:
                # 这里没有密码；容器内 mysql 用户需要读取此只读 bind 文件。
                os.chmod(grants, 0o644)
                stream.write(grant_sql)
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        stream.write("".join(f"{key}={value}\n" for key, value in values.items()))
        stream.flush()
        os.fsync(stream.fileno())
    return path


def _ensure_container(root, state_path, state, kind, host, port, image, config, run):
    services = state["services"]
    descriptor = services.get(kind)
    if descriptor is None:
        directory = root / ".deploy/services" / kind
        # 没有持久状态时，非空 data 可能来自旧部署，不能把它当新库接管。
        data = directory / "data"
        if directory.is_symlink() or data.is_symlink() or (data.exists() and any(data.iterdir())):
            raise BootstrapServiceError("发现未登记的服务数据，拒绝自动接管")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        data.mkdir(mode=0o700, exist_ok=True)
        descriptor = {"name": f"numoj-{kind}-{state['instance']}", "host": host, "port": port,
                      "bind_host": "::1" if ":" in host else "127.0.0.1", "image": image,
                      "seed_pending": kind == "mysql"}
        _credentials(directory, kind, config)
        services[kind] = descriptor
        _save(state_path, state)
    elif descriptor.get("host") != host or descriptor.get("port") != port:
        raise BootstrapServiceError("配置中的服务地址与已有托管服务不一致")
    expected_name = f"numoj-{kind}-{state['instance']}"
    if descriptor.get("name") != expected_name:
        raise BootstrapServiceError("托管服务名称无效")
    if kind == "mysql":
        _private_file(root / ".deploy/services/mysql/environment")
    container = _inspect(run, descriptor["name"])
    if container:
        _owned(container, root, state, kind, descriptor)
        if not container.get("State", {}).get("Running"):
            result = _command(run, ["docker", "start", descriptor["name"]], timeout=60)
            if result.returncode:
                raise BootstrapServiceError("托管服务容器启动失败，保留已有数据")
        return descriptor
    directory = root / ".deploy/services" / kind
    data = directory / "data"
    if directory.is_symlink() or data.is_symlink() or not data.is_dir():
        raise BootstrapServiceError("托管服务持久目录缺失或无效")
    bind_host = f"[{descriptor['bind_host']}]" if ":" in descriptor["bind_host"] else descriptor["bind_host"]
    target, container_port = ("/var/lib/mysql", 3306) if kind == "mysql" else ("/data", 6379)
    command = ["docker", "run", "--detach", "--name", descriptor["name"], "--restart", "unless-stopped",
               "--label", f"{_ROOT_LABEL}={root}", "--label", f"{_KIND_LABEL}={kind}",
               "--label", f"{_INSTANCE_LABEL}={state['instance']}", "--publish",
               f"{bind_host}:{port}:{container_port}", "--volume", f"{data}:{target}"]
    credentials = _credentials(directory, kind, config)
    if credentials:
        command.extend(["--env-file", str(credentials)])
    grants = directory / "grants.sql"
    if kind == "mysql" and grants.exists():
        if grants.is_symlink() or not grants.is_file():
            raise BootstrapServiceError("MySQL 首次授权文件无效")
        command.extend(["--volume", f"{grants}:/docker-entrypoint-initdb.d/01-numoj-grants.sql:ro"])
    command.append(descriptor["image"])
    if kind == "redis":
        command.extend(["redis-server", "--appendonly", "yes"])
    result = _command(run, command, timeout=600)
    if result.returncode:
        raise BootstrapServiceError("托管服务创建失败，保留状态与数据以便重试")
    return descriptor


def ensure_services(root, config, *, allow_create=False, mysql_image=_MYSQL_IMAGE,
                    redis_image=_REDIS_IMAGE, run=subprocess.run, probe=None,
                    wait_timeout=180, sleep=time.sleep, monotonic=time.monotonic):
    """返回服务归属及首次空库标记；创建必须由调用方明确授权。"""
    root = Path(root).absolute().resolve()
    state_path, state = _state(root)
    probe = probe or _probe
    output = {"managed_mysql": False, "managed_redis": False, "first_database": False}
    for kind, image in (("mysql", mysql_image), ("redis", redis_image)):
        host = str(getattr(config, f"{kind.upper()}_HOST"))
        port = int(getattr(config, f"{kind.upper()}_PORT"))
        if not 1 <= port <= 65535:
            raise BootstrapServiceError("服务端口无效")
        descriptor = state["services"].get(kind) if state else None
        available = probe(kind, host, port)
        if available and descriptor is None:
            continue
        if not _local(host):
            raise BootstrapServiceError("远端服务不可用；部署不会创建或替换远端数据库")
        if not available and descriptor is None:
            _start_installed(kind, port, run)
            available = probe(kind, host, port)
            if available:
                continue
        if descriptor is None and not allow_create and state is None:
            raise BootstrapServiceError("本机服务不可用；需要明确首次初始化授权，拒绝创建空数据库")
        if state is None:
            directory = state_path.parent
            if directory.is_symlink() or directory.parent.is_symlink():
                raise BootstrapServiceError("托管服务根目录不能是符号链接")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            state = {"version": 1, "root": str(root), "instance": secrets.token_hex(8), "services": {}}
        descriptor = _ensure_container(root, state_path, state, kind, host, port, image, config, run)
        deadline = monotonic() + wait_timeout
        while not probe(kind, host, port):
            if monotonic() >= deadline:
                raise BootstrapServiceError("托管服务未在期限内就绪，保留现场且不切换到另一空库")
            sleep(1)
        output[f"managed_{kind}"] = True
        if kind == "mysql":
            output["first_database"] = bool(descriptor.get("seed_pending"))
    return output


def mark_database_initialized(root):
    """调用方确认首次种子已完成后清除持久标记，不操作数据库。"""
    path, state = _state(Path(root).absolute().resolve())
    if state and state["services"].get("mysql"):
        state["services"]["mysql"]["seed_pending"] = False
        _save(path, state)


def managed_mysql_container(root, *, host=None, port=None, run=subprocess.run):
    """备份入口只获取已复核归属、持久卷和运行状态的 MySQL 容器。"""
    root = Path(root).absolute().resolve()
    _path, state = _state(root)
    descriptor = state["services"].get("mysql") if state else None
    if descriptor is None:
        return None
    if ((host is not None and descriptor.get("host") != str(host))
            or (port is not None and descriptor.get("port") != int(port))):
        raise BootstrapServiceError("备份目标与已有托管 MySQL 地址不一致")
    name = f"numoj-mysql-{state['instance']}"
    if descriptor.get("name") != name:
        raise BootstrapServiceError("托管 MySQL 容器名称无效")
    container = _inspect(run, name)
    if container is None:
        raise BootstrapServiceError("托管 MySQL 容器不存在，无法安全备份")
    _owned(container, root, state, "mysql", descriptor)
    if not container.get("State", {}).get("Running"):
        raise BootstrapServiceError("托管 MySQL 容器未运行，无法安全备份")
    return name


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("ensure", "mark-database-initialized"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--allow-create", action="store_true")
    parser.add_argument("--mysql-image", default=_MYSQL_IMAGE)
    parser.add_argument("--redis-image", default=_REDIS_IMAGE)
    args = parser.parse_args(argv)
    try:
        if args.action == "mark-database-initialized":
            mark_database_initialized(args.root)
            return 0
        sys.path.insert(0, str(args.root))
        from backend.oj_modules import config
        result = ensure_services(args.root, config, allow_create=args.allow_create,
                                 mysql_image=args.mysql_image, redis_image=args.redis_image)
        print(json.dumps(result))
        return 0
    except BootstrapServiceError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
