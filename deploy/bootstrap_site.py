#!/usr/bin/env python3
"""首次站点账号与开机启动配置；发布仍沿用既有 Supervisor 状态机。"""

from __future__ import annotations

import argparse
import getpass
import grp
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mysql_admin import connect_mysql, database_exists, settings_from_config


class BootstrapSiteError(RuntimeError):
    """首次账号或服务归属无法安全确认。"""


def _private_directory(path):
    if path.is_symlink():
        raise BootstrapSiteError("部署私有目录不能是符号链接")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise BootstrapSiteError("部署私有目录必须属于部署用户")
    os.chmod(path, 0o700)


def _identity(settings):
    return {name: getattr(settings, name) for name in ("host", "port", "database", "user")}


def _credential_path(root):
    return root / ".deploy/initial-admin.json"


def _first_install_pending(root):
    marker = root / ".deploy/first-install-pending"
    if not marker.exists() and not marker.is_symlink():
        return False
    if marker.is_symlink():
        raise BootstrapSiteError("首次部署标记不能是符号链接")
    info = marker.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise BootstrapSiteError("首次部署标记必须属于部署用户且权限为 0600")
    return True


def _mark_first_install(root):
    if _first_install_pending(root):
        return
    with (root / ".deploy/first-install-pending").open("x", encoding="utf-8") as stream:
        os.chmod(stream.fileno(), 0o600)
        stream.write("站点首次部署尚未成功；部署成功后由唯一入口移除此标记。\n")


def _load_record(root, settings):
    path = _credential_path(root)
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink():
        raise BootstrapSiteError("初始管理员记录不能是符号链接")
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
        raise BootstrapSiteError("初始管理员记录必须属于部署用户且权限为 0600")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if (value["version"] != 1 or value["target"] != _identity(settings)
                or value["username"] != "admin" or type(value["initialized"]) is not bool):
            raise ValueError
        if not value["initialized"] and not isinstance(value.get("password"), str):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise BootstrapSiteError("初始管理员记录与当前数据库配置不一致") from exc
    return value


def _save_record(root, value):
    parent = root / ".deploy"
    _private_directory(parent)
    path = _credential_path(root)
    temporary = parent / (".initial-admin-" + secrets.token_hex(6))
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _account_state(settings, connect):
    connection = connect(settings, with_database=False, dict_rows=True)
    try:
        with connection.cursor() as cursor:
            if not database_exists(cursor, settings.database):
                return "empty"
            cursor.execute("SELECT COUNT(*) AS n FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%s", (settings.database,))
            if not int(cursor.fetchone()["n"]):
                return "empty"
            cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s", (settings.database, "users"))
            if not cursor.fetchone():
                return "existing"
        # 业务表读取仍使用连接选定的 schema，数据库名称不拼入 SQL。
    finally:
        connection.close()
    connection = connect(settings, with_database=True, dict_rows=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS n FROM users")
            if not int(cursor.fetchone()["n"]):
                return "uninitialized"
            cursor.execute("SELECT is_admin FROM users WHERE username=%s", ("admin",))
            admin = cursor.fetchone()
            if not admin or int(admin.get("is_admin") or 0) != 1:
                raise BootstrapSiteError("现有站点缺少 username=admin 的管理员；部署不会重置或提升既有账号")
            return "existing"
    finally:
        connection.close()


def prepare_admin(root, profile, *, settings=None, connect=connect_mysql, password_reader=None):
    root = Path(root).resolve()
    settings = settings or settings_from_config()
    previous = _load_record(root, settings)
    state = _account_state(settings, connect)
    if state == "existing":
        return {"needs_admin": False, "first_install": _first_install_pending(root)}
    if previous:
        if previous["initialized"]:
            raise BootstrapSiteError("曾初始化的站点账号已清空，拒绝自动重置管理员")
        _mark_first_install(root)
        return {"needs_admin": True, "first_install": True}
    if state != "empty":
        raise BootstrapSiteError("数据库已有结构但没有首次初始化记录，拒绝猜测为新站点")
    if profile == "test-cpu":
        password = secrets.token_urlsafe(24)
    else:
        reader = password_reader or getpass.getpass
        if password_reader is None and not sys.stdin.isatty():
            raise BootstrapSiteError("首次生产部署请在交互终端内运行 bash deploy.sh，以设置管理员密码")
        password = reader("首次站点管理员 admin 的密码（至少 12 位）：")
        confirmation = reader("再次输入管理员密码：")
        if password != confirmation or len(password) < 12:
            raise BootstrapSiteError("管理员密码不一致或少于 12 位；数据库尚未修改")
    _save_record(root, {"version": 1, "target": _identity(settings), "username": "admin",
                        "password": password, "initialized": False})
    _mark_first_install(root)
    return {"needs_admin": True, "first_install": True}


def initialize_admin(root, *, settings=None, connect=connect_mysql):
    from backend.oj_modules.security.credentials import hash_password, verify_password

    root = Path(root).resolve()
    settings = settings or settings_from_config()
    record = _load_record(root, settings)
    if record is None or record["initialized"]:
        return False
    connection = connect(settings, with_database=True, dict_rows=True)
    inserted = False
    locked = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 30) AS acquired", ("numericaloj:initial-admin",))
            locked = bool(cursor.fetchone()["acquired"])
            if not locked:
                raise BootstrapSiteError("另一个首次账号初始化正在运行")
            cursor.execute("SELECT COUNT(*) AS n FROM users")
            if int(cursor.fetchone()["n"]):
                cursor.execute("SELECT password_hash, is_admin FROM users WHERE username=%s", ("admin",))
                existing = cursor.fetchone()
                if not existing or int(existing.get("is_admin") or 0) != 1:
                    raise BootstrapSiteError("账号表已出现既有用户，首次管理员不会覆盖或提升账号")
                # commit 后凭据记录发布失败的重试可保留原记录；其他既有账号绝不改密码。
                if not verify_password(existing["password_hash"], record["password"])[0]:
                    record.pop("password", None)
            else:
                cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)",
                               ("admin", hash_password(record["password"]), 1))
                inserted = True
            connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        try:
            if locked:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK(%s)", ("numericaloj:initial-admin",))
        finally:
            connection.close()
    record["initialized"] = True
    _save_record(root, record)
    return inserted


_UNITS = {
    "observability": ("/tmp/noj_observability_supervisord.pid", "", 45),
    "celery": ("/tmp/noj_celery_supervisord.pid", "numericaloj-observability.service", 1960),
    "web": ("/tmp/noj_web_supervisord.pid", "numericaloj-celery.service", 60),
}


def _unit_quote(value, *, executable=False):
    value = str(value)
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BootstrapSiteError("systemd 配置路径包含控制字符")
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if executable:
        value = value.replace("$", "$$")
    return '"' + value + '"'


def render_unit(root, kind, username, group):
    if kind not in _UNITS:
        raise BootstrapSiteError("未知 Supervisor 分组")
    root = Path(root).resolve()
    pid, predecessor, stop_timeout = _UNITS[kind]
    binaries = root / ".deploy/current-venv/bin"
    configuration = root / "deploy/supervisor" / (kind + ".conf")
    marker = "# NumericalOJ deployment: " + str(root)
    return "\n".join([
        marker, "[Unit]", f"Description=NumericalOJ {kind} Supervisor",
        "After=network-online.target docker.service " + predecessor,
        "Wants=network-online.target " + predecessor,
        "[Service]", "Type=forking", f"User={username}", f"Group={group}",
        "WorkingDirectory=" + _unit_quote(root), "UMask=0077", "LimitNOFILE=65536",
        "PIDFile=" + pid,
        "ExecStart=" + _unit_quote(binaries / "supervisord", executable=True) + " -c " + _unit_quote(configuration, executable=True),
        "ExecStop=" + _unit_quote(binaries / "supervisorctl", executable=True) + " -c " + _unit_quote(configuration, executable=True) + " shutdown",
        "Restart=on-failure", "RestartSec=5", f"TimeoutStopSec={stop_timeout}",
        "KillMode=mixed", "[Install]", "WantedBy=multi-user.target", "",
    ])


def install_boot(root, *, run=subprocess.run, system_directory=Path("/etc/systemd/system")):
    root = Path(root).resolve()
    account = pwd.getpwuid(os.geteuid())
    group = grp.getgrgid(os.getegid()).gr_name
    staging = root / ".deploy/systemd"
    _private_directory(staging)
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    names = []
    for kind in _UNITS:
        name = f"numericaloj-{kind}.service"
        destination = system_directory / name
        content = render_unit(root, kind, account.pw_name, group)
        marker = content.splitlines()[0]
        if destination.is_symlink() or (destination.exists() and destination.read_text().splitlines()[:1] != [marker]):
            raise BootstrapSiteError("同名 systemd 服务不属于本项目目录，拒绝覆盖")
        source = staging / name
        if source.is_symlink():
            raise BootstrapSiteError("systemd 暂存配置不能是符号链接")
        source.write_text(content, encoding="utf-8")
        os.chmod(source, 0o600)
        result = run([*sudo, "install", "-o", "root", "-g", "root", "-m", "0644", str(source), str(destination)], check=False)
        if result.returncode:
            raise BootstrapSiteError("安装开机启动配置失败；现有 Supervisor 未变更")
        names.append(name)
    for command in (["systemctl", "daemon-reload"], ["systemctl", "enable", *names]):
        if run([*sudo, *command], check=False).returncode:
            raise BootstrapSiteError("启用开机启动配置失败；现有 Supervisor 未重复启动")
    return names


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare-admin", "initialize-admin", "install-boot"))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--profile", choices=("production", "test-cpu"), default="production")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare-admin":
            result = prepare_admin(args.root, args.profile)
            if result["needs_admin"]:
                print("首次管理员凭据已准备，保存在：" + str(_credential_path(args.root.resolve())), file=sys.stderr)
            print(json.dumps(result))
        elif args.command == "initialize-admin":
            if initialize_admin(args.root):
                print("首次管理员 admin 已初始化；初始凭据记录为部署用户私有文件。")
        else:
            install_boot(args.root)
            print("三组 Supervisor 已设置开机启动；当前服务仍由发布流程统一切换。")
    except BootstrapSiteError as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
