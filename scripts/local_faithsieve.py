#!/usr/bin/env python3
"""启动、查看、停止或清理独立的 FaithSieve 本地服务。"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import tempfile
from urllib.request import urlopen
from uuid import uuid4


REPO = Path(__file__).resolve().parents[1]
ROOT = REPO / "tmp" / "local-faithsieve"
STATE = ROOT / "state.json"
PYTHON = REPO / ".venv" / "bin" / "python"
DB_NAME = "faithsieve_local_test"
DB_USER = "faithsieve_local"
PROFILE = "faithsieve-check"
IMAGE = "numericaloj-agent-judge-lite:faithsieve-check"
DOCKER_HOST = f"unix://{Path.home() / '.colima' / PROFILE / 'docker.sock'}"
WEB_URL = "http://127.0.0.1:2025"
SUPERVISOR_CONFIG = ROOT / "supervisord.conf"
PROFILE_OWNER = Path.home() / ".colima" / PROFILE / "numericaloj-local-owner.json"
PROFILE_IMAGE_TAGS = {
    IMAGE, "numericaloj-agent-judge-lite-prefix:faithsieve-check",
    "numericaloj-lean4:latest", "numericaloj-lean4-cache:faithsieve-check",
    "node:24-bookworm-slim", "debian:bookworm-slim",
}

if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def run(args, *, env=None, check=True, capture=False):
    return subprocess.run(
        [str(arg) for arg in args], env=env if env is not None else base_environment(), check=check,
        text=True, capture_output=capture,
    )


def base_environment():
    return {
        key: value for key, value in os.environ.items()
        if not any(part in key.upper() for part in (
            "API_KEY", "TOKEN", "PASSWORD", "SECRET", "AUTHORIZATION", "COOKIE",
        ))
    }


def local_agent_memory_limit():
    value = os.environ.get("AGENT_JUDGE_MEM_LIMIT", "5g")
    if not re.fullmatch(r"[1-9][0-9]*[bBkKmMgG]?", value):
        raise RuntimeError("本地 Agent 内存配置无效")
    return value


def load_state():
    if not STATE.exists():
        return None
    state = json.loads(STATE.read_text(encoding="utf-8"))
    metadata = STATE.stat()
    if (
        ROOT.is_symlink() or STATE.is_symlink()
        or metadata.st_uid != os.getuid() or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or state.get("kind") != "numericaloj-local-faithsieve"
        or state.get("repository") != str(REPO)
        or state.get("database") != DB_NAME
    ):
        raise RuntimeError("本地服务标记不匹配，拒绝操作")
    return state


def save_state(state):
    temporary = ROOT / "state.pending.json"
    with temporary.open("w", encoding="utf-8") as output:
        temporary.chmod(0o600)
        json.dump(state, output, ensure_ascii=False, indent=2)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(STATE)


def root_connection():
    import pymysql
    return pymysql.connect(
        host="127.0.0.1", port=3306, user="root",
        password=os.environ.get("NUMOJ_LOCAL_MYSQL_ROOT_PASSWORD", ""),
        charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
    )


def environment(state):
    # 全部连接配置都显式覆盖，不能意外采用仓库 .env 的数据库或 Redis。
    env = base_environment()
    env.update({
        "PYTHONPATH": str(REPO), "PYTHONDONTWRITEBYTECODE": "1",
        "NUMOJ_LOCAL_FAITHSIEVE_ROOT": str(ROOT),
        "NUMOJ_ENVIRONMENT": "development", "SECRET_KEY": state["secret_key"],
        "MYSQL_HOST": "127.0.0.1", "MYSQL_PORT": "3306", "MYSQL_DB": DB_NAME,
        "MYSQL_USERNAME": DB_USER, "MYSQL_PASSWORD": state["database_password"],
        "MYSQL_POOL_MIN_SIZE": "1", "MYSQL_POOL_MAX_SIZE": "3",
        "MYSQL_WEB_POOL_MAX_SIZE": "8",
        "REDIS_HOST": "127.0.0.1", "REDIS_PORT": "6389", "REDIS_DB": "15",
        "DOCKER_HOST": DOCKER_HOST, "DOCKER_CONTEXT": "",
        "AGENT_JUDGE_DOCKER_IMAGE": IMAGE,
        "AGENT_WORKSPACE_ROOT": str(ROOT / "agent-workspaces"),
        "AGENT_WORKSPACE_MAX_BYTES": str(1024**3),
        "AGENT_JUDGE_WORKSPACE_ROOT": str(ROOT / "ranking" / "judge"),
        "REVERSE_JUDGE_WORKSPACE_ROOT": str(ROOT / "ranking" / "reverse"),
        "AGENT_CONTAINER_SITE_URL": WEB_URL.replace("127.0.0.1", "host.docker.internal"),
        "JUDGER_RUN_ROOT": str(ROOT / "judger"),
        "REPOSITORY_STORAGE_ROOT": str(ROOT / "repository-storage"),
        "REPOSITORY_FAISS_INDEX_ROOT": str(ROOT / "repository-vector-index"),
        "VIBEHUB_RUNTIME_ROOT": str(ROOT / "vibehub-runtime"),
        "TMPDIR": str(ROOT / "temp"),
        "FLASK_DEBUG": "false", "SESSION_COOKIE_SECURE": "false",
        "OBJC_DISABLE_INITIALIZE_FORK_SAFETY": "YES",
    })
    # 管理员数据库凭据不进入 Web、Celery 或容器进程。
    env.pop("NUMOJ_LOCAL_MYSQL_ROOT_PASSWORD", None)
    # 本地全库导入已实测触及 4 GiB 限额并持续回收；给 Lean 留出堆内存。
    # 显式进程配置仍优先，生产 Agent 默认不在此处调整。
    env["AGENT_JUDGE_MEM_LIMIT"] = local_agent_memory_limit()
    return env


def require_database_scope(state):
    import pymysql
    with pymysql.connect(
        host="127.0.0.1", port=3306, user=DB_USER, password=state["database_password"],
        database=DB_NAME, cursorclass=pymysql.cursors.DictCursor,
    ) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT owner_id FROM _local_faithsieve_owner")
            if cursor.fetchall() != [{"owner_id": state.get("ownership_id")}]:
                raise RuntimeError("数据库归属标记不匹配，拒绝启动或写入")


def supervisor(args, *, check=False):
    return run(
        [PYTHON, "-m", "supervisor.supervisorctl", "-c", SUPERVISOR_CONFIG, *args],
        check=check, capture=True,
    )


def running():
    return SUPERVISOR_CONFIG.exists() and supervisor(["pid"]).returncode == 0


def services_ready():
    result = supervisor(["status"])
    rows = [line.split() for line in result.stdout.splitlines()]
    return result.returncode == 0 and len(rows) == 5 and all(
        len(row) > 1 and row[1] == "RUNNING" for row in rows
    )


def wait_ready():
    for _ in range(45):
        try:
            with urlopen(f"{WEB_URL}/health/ready", timeout=2) as response:
                if response.status == 200 and services_ready():
                    status()
                    print(f"登录信息：{ROOT / 'access.json'}")
                    return
        except OSError:
            pass
        time.sleep(1)
    raise RuntimeError(f"服务未就绪，请查看 {ROOT / 'logs'}")


def managed_processes_alive():
    result = run(["ps", "-axo", "pid=,command="], capture=True)
    # 只检测该固定本地入口；不输出命令行，也不对来源不明 PID 发送终止信号。
    return any(
        "scripts.local_faithsieve_app" in line or str(SUPERVISOR_CONFIG) in line
        for line in result.stdout.splitlines()
    )


def ports_closed():
    for port in (2025, 6389):
        with socket.socket() as connection:
            if connection.connect_ex(("127.0.0.1", port)) == 0:
                return False
    return True


def require_free_port(port):
    with socket.socket() as connection:
        if connection.connect_ex(("127.0.0.1", port)) == 0:
            raise RuntimeError(f"本地端口 {port} 已被其他进程占用")


def initialize():
    state = load_state()
    if state:
        return state
    if ROOT.exists() and any(ROOT.iterdir()):
        raise RuntimeError(f"{ROOT} 已存在未标记内容，拒绝覆盖")
    ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
    ROOT.chmod(0o700)
    state = {
        "kind": "numericaloj-local-faithsieve", "repository": str(REPO),
        "database": DB_NAME, "database_password": secrets.token_urlsafe(24),
        "secret_key": secrets.token_urlsafe(32),
        "admin_password": secrets.token_urlsafe(16),
        "ownership_id": str(uuid4()),
    }
    with root_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s",
                (DB_NAME,),
            )
            if cursor.fetchone():
                raise RuntimeError("同名数据库已存在但无本地服务标记，拒绝接管")
            cursor.execute("SELECT User FROM mysql.user WHERE User=%s", (DB_USER,))
            if cursor.fetchone():
                raise RuntimeError("同名数据库用户已存在，拒绝覆盖")
            # 先保存归属与凭据；中断后可以明确清理已创建的资源。
            save_state(state)
            cursor.execute(
                f"CREATE DATABASE `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
            )
            cursor.execute(
                f"CREATE TABLE `{DB_NAME}`.`_local_faithsieve_owner` "
                "(owner_id VARCHAR(36) PRIMARY KEY)"
            )
            cursor.execute(
                f"INSERT INTO `{DB_NAME}`.`_local_faithsieve_owner` VALUES (%s)",
                (state["ownership_id"],),
            )
            cursor.execute(
                f"CREATE USER '{DB_USER}'@'127.0.0.1' IDENTIFIED BY %s",
                (state["database_password"],),
            )
            cursor.execute(f"GRANT ALL ON `{DB_NAME}`.* TO '{DB_USER}'@'127.0.0.1'")
        conn.commit()
    return state


def require_profile_scope(state):
    """删除虚拟机前核对归属，并拒绝包含其他用途资源的环境。"""
    if PROFILE_OWNER.is_symlink() or not PROFILE_OWNER.is_file():
        raise RuntimeError("专用虚拟机归属标记缺失，保留虚拟机")
    owner = json.loads(PROFILE_OWNER.read_text(encoding="utf-8"))
    if owner != {"repository": str(REPO), "ownership_id": state["ownership_id"]}:
        raise RuntimeError("专用虚拟机归属已改变，保留虚拟机")
    env = environment(state)
    # Colima 停止时重新启动，仅用于只读核对，再由 clean 删除。
    run(["colima", "start", PROFILE, "--activate=false"])
    require_profile_resources(env)


def require_profile_resources(env):
    for args in (["docker", "ps", "-aq"], ["docker", "volume", "ls", "-q"]):
        if run(args, env=env, capture=True).stdout.strip():
            raise RuntimeError("专用虚拟机含其他容器或数据卷，保留全部数据")
    tags = set(run(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
        env=env, capture=True,
    ).stdout.splitlines())
    if not tags.issubset(PROFILE_IMAGE_TAGS):
        raise RuntimeError("专用虚拟机含其他用途镜像，保留全部数据")


def write_runtime_configuration():
    agent_memory_limit = local_agent_memory_limit()
    for directory in ("logs/run", "redis", "temp", "uploads", "agent-workspaces"):
        (ROOT / directory).mkdir(parents=True, mode=0o700, exist_ok=True)
    gunicorn_config = ROOT / "gunicorn_config.py"
    gunicorn_config.write_text(
        "def post_worker_init(worker):\n"
        "    from scripts.local_faithsieve_app import start_web_background_services\n"
        "    start_web_background_services()\n",
        encoding="utf-8",
    )
    redis_config = ROOT / "redis.conf"
    redis_config.write_text(
        f'bind 127.0.0.1\nport 6389\ndir "{ROOT / "redis"}"\n'
        'protected-mode yes\nsave 60 1\nappendonly no\nmaxmemory 256mb\n'
        'maxmemory-policy noeviction\nloglevel warning\n', encoding="utf-8",
    )
    programs = {
        "logs": f"{PYTHON} -m scripts.local_faithsieve_app --logs",
        "redis": f"{shutil.which('redis-server')} {redis_config}",
        "web": (
            f"{PYTHON} -m gunicorn --config {gunicorn_config} "
            "--bind 127.0.0.1:2025 --worker-class gthread --workers 1 --threads 16 "
            f"--worker-tmp-dir {ROOT / 'temp'} --timeout 600 --no-control-socket "
            "scripts.local_faithsieve_app:app"
        ),
        "worker-default": (
            f"{PYTHON} -m celery -A scripts.local_faithsieve_app:celery worker "
            "--loglevel=info -Q celery -c 1 -n judge@local-faithsieve "
            "--prefetch-multiplier=1"
        ),
        "worker-agent": (
            f"{PYTHON} -m celery -A scripts.local_faithsieve_app:celery worker "
            "--loglevel=info -Q agent --autoscale=1,1 --prefetch-multiplier=1 "
            "-n agent@local-faithsieve"
        ),
    }
    content = (
        f"[supervisord]\nlogfile={ROOT / 'logs/supervisor.log'}\n"
        f"pidfile={ROOT / 'supervisord.pid'}\nchildlogdir={ROOT / 'logs'}\n"
        "logfile_maxbytes=1MB\nlogfile_backups=2\numask=0077\n"
        f"[unix_http_server]\nfile={ROOT / 'supervisor.sock'}\nchmod=0700\n"
        "[rpcinterface:supervisor]\n"
        "supervisor.rpcinterface_factory=supervisor.rpcinterface:make_main_rpcinterface\n"
        f"[supervisorctl]\nserverurl=unix://{ROOT / 'supervisor.sock'}\n"
    )
    for name, command in programs.items():
        program_environment = f'NUMOJ_SERVICE_NAME="local-{name}"'
        if name in {"web", "worker-default", "worker-agent"}:
            # supervisor 重启子进程不会继承 CLI 的新环境，必须显式固定本地值。
            program_environment += f',AGENT_JUDGE_MEM_LIMIT="{agent_memory_limit}"'
        content += (
            f"\n[program:{name}]\ndirectory={ROOT}\ncommand={command}\n"
            "autostart=true\nautorestart=true\nstartsecs=2\nstartretries=3\n"
            "stopasgroup=true\nkillasgroup=true\nstopwaitsecs=15\nredirect_stderr=true\n"
            f"stdout_logfile={ROOT / 'logs' / (name + '.log')}\n"
            "stdout_logfile_maxbytes=1MB\nstdout_logfile_backups=2\n"
            f"environment={program_environment}\n"
            f"priority={10 if name in ('logs', 'redis') else 20}\n"
        )
    SUPERVISOR_CONFIG.write_text(content, encoding="utf-8")
    SUPERVISOR_CONFIG.chmod(0o600)


def start():
    if running():
        state = load_state()
        if not state:
            raise RuntimeError("服务正在运行但归属标记缺失，拒绝接管")
        require_database_scope(state)
        write_runtime_configuration()
        supervisor(["reread"], check=True)
        supervisor(["update"], check=True)
        supervisor(["start", "all"])
        wait_ready()
        return
    for port in (2025, 6389):
        require_free_port(port)
    for command in ("docker", "colima", "redis-server"):
        if not shutil.which(command):
            raise RuntimeError(f"缺少已安装的本地依赖：{command}")
    if not PYTHON.is_file() or not (REPO / "frontend/dist/index.html").is_file():
        raise RuntimeError("先准备项目 .venv 和前端构建产物")
    state = initialize()
    require_database_scope(state)
    write_runtime_configuration()
    env = environment(state)
    run(["colima", "start", PROFILE, "--activate=false"])
    expected_owner = {"repository": str(REPO), "ownership_id": state["ownership_id"]}
    if not PROFILE_OWNER.exists():
        require_profile_resources(env)
        PROFILE_OWNER.write_text(json.dumps(expected_owner), encoding="utf-8")
        PROFILE_OWNER.chmod(0o600)
    elif PROFILE_OWNER.is_symlink() or json.loads(PROFILE_OWNER.read_text()) != expected_owner:
        raise RuntimeError("专用虚拟机已有其他本地服务的归属标记，拒绝接管")
    image = run(["docker", "image", "inspect", IMAGE], env=env, check=False, capture=True)
    if image.returncode:
        raise RuntimeError(f"缺少预安装 Lean/mathlib 的镜像：{IMAGE}")
    with (ROOT / "logs/schema.log").open("w", encoding="utf-8") as log:
        subprocess.run(
            [PYTHON, REPO / "scripts/init_db_schema.py"], cwd=ROOT, env=env,
            stdout=log, stderr=subprocess.STDOUT, check=True,
        )
    import pymysql
    from scripts.local_faithsieve_seed import import_local_provider_config, seed_local_demo
    with pymysql.connect(
        host="127.0.0.1", port=3306, user=DB_USER, password=state["database_password"],
        database=DB_NAME, charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor,
    ) as conn:
        state["demo"] = seed_local_demo(conn, ROOT, state["admin_password"])
        state["provider"] = import_local_provider_config(conn, REPO / ".env")
        state["demo"]["real_model_configured"] = bool(
            state["provider"].get("imported") or state["provider"].get("model")
        )
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT IGNORE INTO site_settings (k,v) VALUES ('AGENT_CONCURRENCY_LIMIT','1')"
            )
        conn.commit()
    access_path = ROOT / "access.json"
    if not access_path.exists():
        access_path.write_text(json.dumps({
            "url": WEB_URL, "username": state["demo"]["admin_username"],
            "password": state["admin_password"],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        access_path.chmod(0o600)
    save_state(state)
    run([PYTHON, "-m", "supervisor.supervisord", "-c", SUPERVISOR_CONFIG], env=env)
    wait_ready()


def owned_containers(state):
    env = environment(state)
    ids = run(["docker", "ps", "-aq"], env=env, check=False, capture=True)
    if ids.returncode or not ids.stdout.strip():
        return []
    details = run(
        ["docker", "inspect", *ids.stdout.split()], env=env, capture=True,
    )
    containers = []
    for container in json.loads(details.stdout):
        for mount in container.get("Mounts", []):
            if mount.get("Type") != "bind":
                continue
            source = Path(mount.get("Source", "")).resolve()
            if source == ROOT or ROOT in source.parents:
                containers.append(container["Id"])
                break
    return containers


def stop(*, keep_vm=False):
    state = load_state()
    if not state:
        print("本地服务尚未创建")
        return
    if running():
        result = supervisor(["shutdown"], check=True)
        print(result.stdout.strip())
        for _ in range(45):
            if not managed_processes_alive() and ports_closed():
                break
            time.sleep(1)
        else:
            raise RuntimeError("本地进程尚未停止，保留现场")
    elif managed_processes_alive() or not ports_closed():
        raise RuntimeError("本地控制通道不可用且进程尚未停止，保留全部数据")
    env = environment(state)
    containers = owned_containers(state)
    if containers:
        run(["docker", "rm", "-f", *containers], env=env)
    if not keep_vm:
        active = run(["docker", "ps", "-q"], env=env, check=False, capture=True)
        if active.returncode == 0 and not active.stdout.strip():
            run(["colima", "stop", PROFILE])
    print("本地服务已停止，测试数据保留")


def status():
    state = load_state()
    if not state:
        print("本地服务尚未创建")
        return
    if SUPERVISOR_CONFIG.exists():
        result = supervisor(["status"])
        print(result.stdout.strip())
    print(f"网页：{WEB_URL}")
    print(f"Faith Sieve：{WEB_URL}/admin/faithsieve")
    if state.get("demo"):
        print(json.dumps(state["demo"], ensure_ascii=False, indent=2))
    print(f"运行数据：{ROOT}")


def clean(*, remove_vm=False):
    state = load_state()
    if not state:
        print("没有受管的本地服务数据")
        return
    stop()
    if remove_vm:
        require_profile_scope(state)
    with root_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s",
                (DB_NAME,),
            )
            exists = bool(cursor.fetchone())
            if exists:
                if state.get("database_removed"):
                    raise RuntimeError("同名数据库已重新创建，拒绝清理")
                cursor.execute(f"SELECT owner_id FROM `{DB_NAME}`.`_local_faithsieve_owner`")
                owners = cursor.fetchall()
                if owners != [{"owner_id": state.get("ownership_id")}]:
                    raise RuntimeError("数据库归属标记不匹配，拒绝清理")
            elif not state.get("database_removed"):
                raise RuntimeError("数据库归属无法确认，保留清理现场")
            cursor.execute(f"DROP DATABASE IF EXISTS `{DB_NAME}`")
            cursor.execute(f"DROP USER IF EXISTS '{DB_USER}'@'127.0.0.1'")
        conn.commit()
    state["database_removed"] = True
    save_state(state)
    if remove_vm:
        # 此 profile 专用于 FaithSieve；禁止清理默认或其他 Docker 环境。
        run(["colima", "delete", PROFILE, "--force"])
    elif PROFILE_OWNER.is_file() and not PROFILE_OWNER.is_symlink():
        owner = json.loads(PROFILE_OWNER.read_text(encoding="utf-8"))
        if owner == {"repository": str(REPO), "ownership_id": state["ownership_id"]}:
            PROFILE_OWNER.unlink()
    shutil.rmtree(ROOT)
    print("已清理独立数据库、数据库用户和运行目录")
    if remove_vm:
        print("已删除 FaithSieve 专用虚拟机及其全部镜像；再次启动需重建镜像")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "status", "stop", "clean"))
    parser.add_argument("--keep-vm", action="store_true", help="停止服务时保留虚拟机运行")
    parser.add_argument("--remove-vm", action="store_true", help="清理时同时删除专用虚拟机与镜像")
    args = parser.parse_args()
    if args.keep_vm and args.action != "stop":
        parser.error("--keep-vm 只能与 stop 使用")
    if args.remove_vm and args.action != "clean":
        parser.error("--remove-vm 只能与 clean 使用")
    try:
        lock_path = Path(tempfile.gettempdir()) / f"numoj-local-faithsieve-{os.getuid()}.lock"
        with lock_path.open("a") as lock:
            lock_path.chmod(0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("另一本地服务操作正在执行，请稍后重试") from None
            if args.action == "start":
                start()
            elif args.action == "status":
                status()
            elif args.action == "stop":
                stop(keep_vm=args.keep_vm)
            else:
                clean(remove_vm=args.remove_vm)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"本地服务操作失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
