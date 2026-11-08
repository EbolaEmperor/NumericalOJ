#!/usr/bin/env python3
"""同一部署入口的首次配置、宿主依赖与开机启动引导。"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import grp
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
UV_VERSION = "0.13.7"
PROFILES = {"production", "test-cpu"}
DEPLOYMENT_MODES = {"full", "lite"}


class BootstrapError(RuntimeError):
    pass


def _run(command, *, run=subprocess.run, capture=True, **kwargs):
    result = run(command, check=False, text=True, capture_output=capture, **kwargs)
    if result.returncode:
        raise BootstrapError(f"首次部署命令失败：{Path(command[0]).name}（退出码 {result.returncode}）")
    return result


def _private_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
        raise BootstrapError(f"配置必须是当前用户所有、权限 0400/0600 的普通文件：{path}")
    if info.st_size > 1024 * 1024:
        raise BootstrapError(f"配置文件过大：{path}")


def _write_private(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _ask(prompt, *, input_fn=input):
    print(prompt, file=sys.stderr, end="", flush=True)
    return input_fn().strip()


def ensure_configuration(root, *, profile="production", input_fn=input, interactive=None):
    path = root / ".env"
    if path.exists() or path.is_symlink():
        _private_file(path)
        return False
    interactive = sys.stdin.isatty() if interactive is None else interactive
    if not interactive:
        raise BootstrapError("首次部署缺少 .env；请在交互终端直接运行 bash deploy.sh，脚本会在同一流程中初始化配置")
    answer = _ask("未发现 .env。创建使用本机托管 MySQL/Redis 的新站点？[y/N] ", input_fn=input_fn)
    if answer.lower() not in {"y", "yes"}:
        raise BootstrapError("未创建新站点配置；已有数据库请先提供其真实 .env，脚本不会猜测或替换凭据")
    default_database = "numoj_dev_test" if profile == "test-cpu" else "myojdb"
    database = _ask(f"新数据库名称 [{default_database}]：", input_fn=input_fn) or default_database
    if not re.fullmatch(r"[A-Za-z0-9_]+", database):
        raise BootstrapError("数据库名仅允许字母、数字与下划线")
    values = {
        "SECRET_KEY": secrets.token_urlsafe(48), "MYSQL_HOST": "127.0.0.1",
        "MYSQL_PORT": 3306, "MYSQL_DB": database, "MYSQL_USERNAME": "oj",
        "MYSQL_PASSWORD": secrets.token_urlsafe(32), "REDIS_HOST": "127.0.0.1",
        "REDIS_PORT": 6379, "REDIS_DB": 15 if profile == "test-cpu" else 0,
    }
    _write_private(path, "# 由 bash deploy.sh 首次初始化；请保留此文件。\n" + "".join(
        f"{name}={json.dumps(value, ensure_ascii=False)}\n" for name, value in values.items()
    ))
    _write_private(root / ".deploy" / "new-local-site.json", json.dumps({"database": database}))
    print("已生成权限 0600 的 .env；站点与数据库密钥不会显示在终端。", file=sys.stderr)
    return True


def resolve_profile(root, requested=None, *, gpu_available=None):
    path = root / ".deploy" / "profile"
    if requested is None and path.exists():
        _private_file(path)
        requested = path.read_text(encoding="ascii").strip()
    if requested is None:
        # 既有部署保持原生产默认；新站点按实际 GPU 能力选择完整 CPU/GPU 运行时。
        existing = (root / ".deploy" / "current-venv").exists() or (
            (root / ".env").exists() and not (root / ".deploy/new-local-site.json").exists()
        )
        available = (Path("/usr/local/cuda-12.6").is_dir() and shutil.which("nvidia-smi")) if gpu_available is None else gpu_available
        requested = "production" if existing or available else "test-cpu"
    if requested not in PROFILES:
        raise BootstrapError("部署模式仅支持 production 或 test-cpu")
    if not path.exists():
        _write_private(path, requested + "\n")
    elif path.read_text(encoding="ascii").strip() != requested:
        _private_file(path)
        temporary = path.with_name(".profile-new")
        _write_private(temporary, requested + "\n")
        temporary.replace(path)
    return requested


def resolve_mode(root, requested=None):
    path = root / ".deploy" / "deployment-mode"
    if path.exists() or path.is_symlink():
        _private_file(path)
        saved = path.read_text(encoding="ascii").strip()
        if saved not in DEPLOYMENT_MODES:
            raise BootstrapError("已保存的部署模式必须是 full 或 lite")
    else:
        saved = "full"
    selected = saved if requested is None else requested
    if selected not in DEPLOYMENT_MODES:
        raise BootstrapError("部署模式仅支持 full 或 lite")
    if selected != saved or not path.exists():
        temporary = path.with_name(".deployment-mode-new")
        _write_private(temporary, selected + "\n")
        temporary.replace(path)
    return selected


def _apt_candidate(package, *, run=subprocess.run):
    result = _run(["apt-cache", "policy", package], run=run)
    match = re.search(r"^\s*Candidate:\s*(\S+)", result.stdout, re.MULTILINE)
    return None if not match or match[1] == "(none)" else match[1]


def _apt_supported():
    return Path("/etc/debian_version").is_file() and shutil.which("apt-get") is not None


def _download_proxy_values():
    from deploy.bootstrap_proxy import _proxy_values, _read_state

    return _read_state(ROOT) or _proxy_values(os.environ)


@contextmanager
def _apt_proxy_arguments():
    values = _download_proxy_values()
    if not values:
        yield []
        return
    descriptor, name = tempfile.mkstemp(prefix="numoj-deploy-apt-", suffix=".conf")
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            for key, protocol in (("HTTP_PROXY", "http"), ("HTTPS_PROXY", "https")):
                if key in values:
                    value = values[key].replace("\\", "\\\\").replace('"', '\\"')
                    stream.write(f'Acquire::{protocol}::Proxy "{value}";\n')
        yield ["-c", str(path)]
    finally:
        path.unlink(missing_ok=True)


def _install_missing(packages, *, run=subprocess.run):
    if not packages:
        return
    if not _apt_supported():
        raise BootstrapError("自动安装宿主依赖目前支持 Debian/Ubuntu APT")
    sudo = [] if os.geteuid() == 0 else ["sudo"]
    with _apt_proxy_arguments() as proxy_arguments:
        _run([*sudo, "apt-get", *proxy_arguments, "update"], run=run, capture=False)
        targets = []
        for candidates in packages:
            for package in candidates:
                version = _apt_candidate(package, run=run)
                if version:
                    targets.append(f"{package}={version}")
                    break
            else:
                raise BootstrapError("APT 仓库缺少部署依赖：" + "/".join(candidates))
        arguments = ["apt-get", *proxy_arguments, "--no-install-recommends", "--no-remove", "install", *targets]
        simulation = _run([*sudo, "apt-get", *proxy_arguments, "--simulate", *arguments[1 + len(proxy_arguments):]], run=run)
        # 首次供应只添加缺失包；不得借此升级/替换宿主既有数据库或其它依赖。
        new_packages = {
            match[1] for line in simulation.stdout.splitlines()
            if (match := re.match(r"^Inst\s+(\S+)\s+\(", line))
        }
        for line in simulation.stdout.splitlines():
            configure = re.match(r"^Conf\s+(\S+)", line)
            database_server = re.match(r"^(?:Inst|Conf)\s+(?:mysql-server|mysql-community-server|mariadb-server|percona-server)(?:\S*)\s", line)
            if (line.startswith("Remv ") or re.match(r"^Inst\s+\S+\s+\[", line)
                    or (configure and configure[1] not in new_packages) or database_server):
                raise BootstrapError("首次依赖安装将删除或升级已有系统包，已停止：" + line)
        _run([*sudo, "apt-get", *proxy_arguments, "--yes", *arguments[1 + len(proxy_arguments):]], run=run, capture=False)


def ensure_host_tools(*, run=subprocess.run):
    packages = []
    for binary, package in (("flock", "util-linux"), ("pgrep", "procps"), ("git", "git"), ("curl", "curl")):
        if shutil.which(binary) is None:
            packages.append((package,))
    if shutil.which("docker") is None:
        packages.append(("docker.io",))
    _install_missing(packages, run=run)
    for arguments, choices in ((["docker", "buildx", "version"], ("docker-buildx-plugin", "docker-buildx")),
                               (["docker", "compose", "version"], ("docker-compose-plugin", "docker-compose-v2", "docker-compose"))):
        if run(arguments, check=False, capture_output=True, text=True).returncode:
            _install_missing([choices], run=run)
            _run(arguments, run=run)
    if shutil.which("systemctl"):
        _run((["sudo"] if os.geteuid() else []) + ["systemctl", "enable", "--now", "docker"], run=run, capture=False)
    access = run(["docker", "info"], check=False, capture_output=True, text=True)
    if access.returncode == 0:
        return False
    if "permission denied" not in (access.stderr or "").lower():
        raise BootstrapError("Docker daemon 无法访问；请检查 Docker 服务或 DOCKER_HOST 配置")
    username = pwd.getpwuid(os.geteuid()).pw_name
    try:
        group = grp.getgrnam("docker")
    except KeyError as exc:
        raise BootstrapError("Docker daemon 无法访问，且不存在 docker 用户组") from exc
    if group.gr_gid in os.getgroups():
        raise BootstrapError("Docker daemon 无法访问；请检查 Docker 服务或 DOCKER_HOST 配置")
    if username not in group.gr_mem:
        _run(["sudo", "usermod", "--append", "--groups", "docker", username], run=run, capture=False)
    if shutil.which("sg") is None:
        raise BootstrapError("缺少 sg，无法在当前部署进程中应用 Docker 组权限")
    return True


def ensure_mysql_client(*, run=subprocess.run):
    if not Path("/usr/bin/mysqldump").is_file():
        _install_missing([("mysql-client", "default-mysql-client")], run=run)
    if not Path("/usr/bin/mysqldump").is_file():
        raise BootstrapError("MySQL 逻辑备份客户端安装后仍不可用")


def ensure_python(root, *, run=subprocess.run):
    candidates = [os.environ.get("NUMOJ_PYTHON"), str(root / ".deploy/bootstrap-python/bin/python3.12"), "python3.12", "python3"]
    for candidate in candidates:
        executable = shutil.which(candidate) if candidate else None
        if executable and run([executable, "-c", "import sys; raise SystemExit(sys.version_info[:2] != (3, 12))"], check=False).returncode == 0:
            check = run([executable, "-c", "import venv, ensurepip"], check=False, capture_output=True)
            if check.returncode == 0:
                return executable
            try:
                _install_missing([("python3.12-venv", "python3-venv")], run=run)
            except BootstrapError:
                print("宿主 venv 无法在不升级已有依赖的条件下供应，改用项目内隔离 Python。", file=sys.stderr)
            else:
                if run([executable, "-c", "import venv, ensurepip"], check=False, capture_output=True).returncode == 0:
                    return executable
    tools = root / ".deploy" / "bootstrap-tools"
    if tools.is_symlink():
        raise BootstrapError("Python 引导工具目录不能是符号链接")
    tools.mkdir(mode=0o700, parents=True, exist_ok=True)
    uv = tools / "uv"
    if uv.is_symlink() or (uv.exists() and (not uv.is_file() or uv.stat().st_uid != os.geteuid() or uv.stat().st_mode & 0o022)):
        raise BootstrapError("uv 引导程序必须是当前用户管理且不可被其它用户写入的普通文件")
    if not uv.is_file():
        installer = tools / f"uv-{UV_VERSION}-install.sh"
        with urllib.request.urlopen(f"https://astral.sh/uv/{UV_VERSION}/install.sh", timeout=60) as response:
            data = response.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise BootstrapError("uv 安装脚本异常过大")
        if installer.exists():
            _private_file(installer)
            installer.unlink()
        _write_private(installer, data.decode("utf-8"))
        environment = os.environ.copy()
        environment.update(UV_UNMANAGED_INSTALL=str(tools), UV_NO_MODIFY_PATH="1")
        _run(["sh", str(installer)], run=run, capture=False, env=environment)
    environment = os.environ.copy()
    environment.update(UV_PYTHON_INSTALL_DIR=str(root / ".deploy/managed-python"), UV_PYTHON_BIN_DIR=str(tools), UV_NO_MODIFY_PATH="1")
    _run([str(uv), "python", "install", "3.12"], run=run, capture=False, env=environment)
    executable = _run([str(uv), "python", "find", "--managed-python", "3.12"], run=run, env=environment).stdout.strip()
    target = root / ".deploy" / "bootstrap-python"
    _run([executable, "-m", "venv", str(target)], run=run, capture=False)
    return str(target / "bin" / "python3.12")


def _load_config(root):
    sys.path.insert(0, str(root))
    from backend.oj_modules import config
    return config


def development_reserve_eligible(root):
    from deploy.backup.development import reserve_facts
    from scripts.mysql_admin import settings_from_config

    try:
        reserve_facts(root, settings_from_config(_load_config(root)))
    except (RuntimeError, OSError, ValueError):
        return False
    return True


def prepare_host(root, *, profile=None, mode=None):
    state = root / ".deploy"
    if state.is_symlink():
        raise BootstrapError("部署状态目录不能是符号链接")
    if (root / ".env").exists() or (root / ".env").is_symlink():
        _private_file(root / ".env")
    selected = resolve_profile(root, profile)
    deployment_mode = resolve_mode(root, mode)
    ensure_configuration(root, profile=selected)
    sys.path.insert(0, str(root))
    from deploy.preflight import validate_production_config
    validate_production_config(root / ".env")
    # 从同一入口的私有记录恢复标准代理变量，首次缺包阶段也无需人工重设环境。
    for name, value in _download_proxy_values().items():
        os.environ[name] = value
    regroup = ensure_host_tools()
    python = ensure_python(root)
    return {"profile": selected, "mode": deployment_mode, "python": python, "docker_group_reexec": regroup}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("host", "mysql-client", "value", "development-reserve-eligible"))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--profile", choices=sorted(PROFILES))
    parser.add_argument("--mode", choices=sorted(DEPLOYMENT_MODES))
    parser.add_argument("--result-file", type=Path)
    parser.add_argument("--file", type=Path)
    parser.add_argument("--field")
    args = parser.parse_args(argv)
    try:
        if args.command == "value":
            if args.file is None or not args.field:
                raise BootstrapError("缺少部署结果文件或字段")
            _private_file(args.file)
            value = json.loads(args.file.read_text(encoding="utf-8"))[args.field]
            if not isinstance(value, (str, int, bool)):
                raise BootstrapError("部署结果字段必须是字符串、整数或布尔值")
            print(int(value) if isinstance(value, bool) else value)
            return 0
        if args.command == "mysql-client":
            ensure_mysql_client()
            return 0
        if args.command == "development-reserve-eligible":
            print(int(development_reserve_eligible(args.root.resolve())))
            return 0
        result = prepare_host(args.root.resolve(), profile=args.profile, mode=args.mode)
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print(f"[bootstrap] {exc}", file=sys.stderr)
        return 1
    if args.result_file:
        _write_private(args.result_file, json.dumps(result, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
