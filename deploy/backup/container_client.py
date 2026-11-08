"""托管 MySQL 容器内的同版本逻辑备份客户端；凭据只通过 stdin 传入。"""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess

_OPTIONS = (
    "--single-transaction", "--quick", "--skip-lock-tables", "--hex-blob",
    "--routines", "--triggers", "--events", "--no-tablespaces", "--set-gtid-purged=OFF",
)
_SAFE_ENV = {"LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TERM", "TZ", "PATH", "DOCKER_HOST",
             "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}


def docker_environment():
    environment = {key: value for key, value in os.environ.items() if key in _SAFE_ENV}
    environment.setdefault("DOCKER_CONFIG", str(Path.home() / ".docker"))
    environment["LC_ALL"] = "C"
    return environment


def _docker():
    binary = shutil.which("docker")
    if not binary:
        raise RuntimeError("托管 MySQL 备份缺少 Docker CLI")
    return binary


def owned_container(root, settings):
    from deploy.bootstrap_services import managed_mysql_container
    name = managed_mysql_container(root, host=settings.host, port=settings.port)
    if not name:
        raise RuntimeError("逻辑容器备份需要已登记并核验的托管 MySQL 容器")
    return name


def validate_client(binary, *, container=None):
    command = ([ _docker(), "exec", "--user", "0", container, "mysqldump", "--help"]
               if container else [str(binary), "--help"])
    result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                            env=docker_environment() if container else {"LC_ALL": "C"})
    help_text = str(result.stdout or "") + str(result.stderr or "")
    # --skip-lock-tables 是通用的布尔反选形式，help通常只列lock-tables。
    required = {item.split("=", 1)[0].removeprefix("--").removeprefix("skip-") for item in _OPTIONS}
    missing = sorted(flag for flag in required if flag not in help_text)
    if result.returncode or missing:
        raise RuntimeError("mysqldump 客户端不兼容，部署尚未停服；缺少选项：" + ", ".join(missing))


@contextmanager
def dump_command(container, option_file, database):
    """返回同版本mysqldump argv；失败也确认临时客户端退出并删除凭据。"""
    docker = _docker()
    environment = docker_environment()
    path = "/tmp/numoj-mysql-backup." + secrets.token_hex(12) + ".cnf"
    create = (
        'set -euC; umask 077; cat > "$1"'
    )
    command = [docker, "exec", "--user", "0", container, "sh", "-c",
               'set -eu; umask 077; p="$1"; shift; printf "%s\\n" "$$" > "$p.pid"; '
               'exec mysqldump --defaults-extra-file="$p" "$@"',
               "numoj-backup", path,
               # 宿主发布端口可以不同；已核验的托管 MySQL 在容器内固定监听 3306。
               "--protocol=TCP", "--host=127.0.0.1", "--port=3306", *_OPTIONS, database]
    try:
        result = subprocess.run([docker, "exec", "--user", "0", "-i", container, "sh", "-c", create,
                                 "numoj-backup-credentials", path],
                                input=Path(option_file).read_bytes(), capture_output=True, timeout=30, env=environment)
        if result.returncode:
            raise RuntimeError("托管 MySQL 临时备份凭据准备失败")
        yield command
    finally:
        # PID复用时只终止仍携带此随机option-file参数的客户端。
        cleanup = (
            'set -eu; p="$1"; trap \'rm -f -- "$p" "$p.pid"\' EXIT; '
            'if [ -f "$p.pid" ]; then read -r pid < "$p.pid"; '
            'case "$pid" in ""|*[!0-9]*) exit 2;; esac; [ "$pid" -gt 1 ] || exit 2; '
            'if [ -r "/proc/$pid/cmdline" ] && tr "\\000" " " < "/proc/$pid/cmdline" | grep -F -- "$p" >/dev/null; then '
            'kill -TERM "$pid" 2>/dev/null || true; i=0; '
            'while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i+1)); done; '
            'if [ -r "/proc/$pid/cmdline" ] && tr "\\000" " " < "/proc/$pid/cmdline" | grep -F -- "$p" >/dev/null; then '
            'kill -KILL "$pid" 2>/dev/null || true; fi; fi; fi'
        )
        result = subprocess.run([docker, "exec", "--user", "0", container, "sh", "-c", cleanup,
                                 "numoj-backup-cleanup", path], capture_output=True, timeout=30, env=environment)
        if result.returncode:
            raise RuntimeError("托管 MySQL 临时备份客户端或凭据清理失败，已停止部署")
