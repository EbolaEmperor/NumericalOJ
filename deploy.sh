#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$ROOT_DIR/.deploy"
VENV_ROOT="$STATE_DIR/venvs"
CURRENT_VENV="$STATE_DIR/current-venv"
BACKUP_DIR="$STATE_DIR/backups"
LOCK_FILE='/tmp/noj_deploy.lock'
WEB_CONFIG="$ROOT_DIR/deploy/supervisor/web.conf"
CELERY_CONFIG="$ROOT_DIR/deploy/supervisor/celery.conf"
WEB_PIDFILE='/tmp/noj_web_supervisord.pid'
WEB_SOCKET='/tmp/noj_web_supervisor.sock'
CELERY_PIDFILE='/tmp/noj_celery_supervisord.pid'
CELERY_SOCKET='/tmp/noj_celery_supervisor.sock'
WEB_STOP_TIMEOUT_SECONDS=60
CELERY_STOP_TIMEOUT_SECONDS=1960

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
DOCKER_BUILDER="${NUMOJ_DOCKER_BUILDER:-default}"
JUDGER_STABLE='numericaloj-judger:latest'
AGENT_JUDGE_STABLE='numericaloj-agent-judge:latest'
JUDGER_CANDIDATE="numericaloj-judger:deploy-$RUN_ID"
AGENT_JUDGE_CANDIDATE="numericaloj-agent-judge:deploy-$RUN_ID"
MANAGED_IMAGE_LABEL='org.numericaloj.deploy-managed=true'
SOURCE_IMAGE_LABEL='org.numericaloj.source-sha256'
phase='初始化'
database_backup=''
restart_started=0
CURRENT_VENV_TEMP="$STATE_DIR/.current-venv-$RUN_ID"

usage() {
  printf '%s\n' \
    '用法: bash deploy.sh' \
    '' \
    '请先在当前项目目录完成 git pull，再执行本脚本。'
}

if (($#)); then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '未知参数: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
fi

cleanup() {
  local exit_code=$?
  trap - EXIT HUP INT TERM
  set +e
  rm -f -- "$CURRENT_VENV_TEMP"
  if [[ "$exit_code" -ne 0 && "$restart_started" -eq 1 \
      && -x "${CANDIDATE_SUPERVISORCTL:-}" ]]; then
    "$CANDIDATE_SUPERVISORCTL" -c "$WEB_CONFIG" shutdown >/dev/null 2>&1 || true
    "$CANDIDATE_SUPERVISORCTL" -c "$CELERY_CONFIG" shutdown >/dev/null 2>&1 || true
  fi
  docker image rm "$JUDGER_CANDIDATE" "$AGENT_JUDGE_CANDIDATE" \
    >/dev/null 2>&1 || true
  if [[ "$exit_code" -ne 0 ]]; then
    printf '部署失败（阶段：%s，退出码：%s）。\n' "$phase" "$exit_code" >&2
    if [[ -n "$database_backup" ]]; then
      printf '部署前数据库备份：%s\n' "$database_backup" >&2
    fi
  fi
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

cd "$ROOT_DIR"
install -d -m 0700 "$STATE_DIR" "$VENV_ROOT" "$BACKUP_DIR"

for command_name in docker flock mysqldump pgrep; do
  command -v "$command_name" >/dev/null || {
    printf '缺少部署命令: %s\n' "$command_name" >&2
    exit 1
  }
done

exec 9>>"$LOCK_FILE"
if ! flock -n 9; then
  printf '本机已有 NumericalOJ 部署正在运行。\n' >&2
  exit 1
fi

if ! docker buildx inspect "$DOCKER_BUILDER" >/dev/null 2>&1; then
  printf 'Docker builder 不存在或不可用：%s\n' "$DOCKER_BUILDER" >&2
  exit 1
fi
docker_cache_root="$(docker info --format '{{.DockerRootDir}}')"
printf '使用 Docker builder %s（缓存位于 %s）。\n' \
  "$DOCKER_BUILDER" "$docker_cache_root"

resolve_bootstrap_python() {
  local candidate
  local resolved
  local version
  local candidates=()

  if [[ -n "${NUMOJ_PYTHON:-}" ]]; then
    candidates+=("$NUMOJ_PYTHON")
  fi
  candidates+=(
    "$STATE_DIR/bootstrap-python/bin/python3.12"
    "$STATE_DIR/bootstrap-python/bin/python3"
    python3.12
    python3
  )

  for candidate in "${candidates[@]}"; do
    if [[ "$candidate" == */* ]]; then
      [[ -x "$candidate" ]] || continue
      resolved="$candidate"
    else
      resolved="$(command -v "$candidate" 2>/dev/null || true)"
      [[ -n "$resolved" ]] || continue
    fi
    version="$(
      "$resolved" -c \
        'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' \
        2>/dev/null || true
    )"
    if [[ "$version" == '3.12' ]]; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done

  printf '%s\n' \
    '生产部署要求 Python 3.12。请安装 python3.12，设置 NUMOJ_PYTHON，' \
    '或准备 .deploy/bootstrap-python/bin/python3.12。' >&2
  return 1
}

BOOTSTRAP_PYTHON="$(resolve_bootstrap_python)"
printf '使用 Python 3.12：%s\n' "$BOOTSTRAP_PYTHON"

phase='校验生产本地配置'
ENV_FILE="$ROOT_DIR/.env"
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" && -r "$ENV_FILE" ]] || {
  printf '缺少仅当前用户可读的生产配置文件: %s\n' "$ENV_FILE" >&2
  exit 1
}
PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B -c '
import os
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(path, flags)
except OSError as exc:
    raise SystemExit(f"无法安全打开生产配置: {path}") from exc
try:
    metadata = os.fstat(descriptor)
finally:
    os.close(descriptor)
mode = stat.S_IMODE(metadata.st_mode)
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit(f"生产配置不是普通文件: {path}")
if metadata.st_uid != os.geteuid():
    raise SystemExit(f"生产配置不属于当前部署用户: {path}")
if mode not in (0o400, 0o600):
    raise SystemExit(f"生产配置权限必须是 0400 或 0600: {path} mode={mode:04o}")
if metadata.st_size > 1024 * 1024:
    raise SystemExit(f"生产配置文件异常过大: {path}")
fingerprint = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)

import config

after = path.stat(follow_symlinks=False)
after_fingerprint = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
if after_fingerprint != fingerprint:
    raise SystemExit("生产配置在校验过程中发生变化")
if not config.ENV_FILE_LOADED:
    raise SystemExit("生产 .env 没有被 config.py 加载")

required_strings = (
    "SECRET_KEY",
    "MYSQL_HOST",
    "MYSQL_DB",
    "MYSQL_USERNAME",
    "MYSQL_PASSWORD",
    "REDIS_HOST",
)
required_in_file = required_strings + (
    "MYSQL_PORT",
    "REDIS_PORT",
    "REDIS_DB",
)
missing = sorted(set(required_in_file) - set(config.ENV_FILE_KEYS))
if missing:
    raise SystemExit("生产 .env 缺少必填项: " + ", ".join(missing))
for name in required_strings:
    value = getattr(config, name, None)
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"生产 .env 的必填字符串无效: {name}")
for name in ("MYSQL_PORT", "REDIS_PORT"):
    value = getattr(config, name, None)
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise SystemExit(f"生产 .env 的端口无效: {name}")
redis_db = getattr(config, "REDIS_DB", None)
if not isinstance(redis_db, int) or isinstance(redis_db, bool) or redis_db < 0:
    raise SystemExit("生产 .env 的 REDIS_DB 无效")
' "$ENV_FILE"

remove_stale_candidate_tags() {
  local reference
  local tags
  local tag

  for reference in \
      'numericaloj-judger:deploy-*' \
      'numericaloj-agent-judge:deploy-*'; do
    tags="$(
      docker image ls \
        --filter "label=$MANAGED_IMAGE_LABEL" \
        --filter "reference=$reference" \
        --format '{{.Repository}}:{{.Tag}}'
    )" || return 1
    while IFS= read -r tag; do
      [[ -n "$tag" ]] || continue
      docker image rm "$tag" >/dev/null || return 1
    done <<<"$tags"
  done
}

docker_source_digest() {
  local context="$1"
  local inputs=()

  case "$context" in
    docker/judger)
      inputs=(Dockerfile)
      ;;
    docker/agent_judge)
      inputs=(Dockerfile report run_harness)
      ;;
    *)
      printf '没有定义 Docker 构建输入清单：%s\n' "$context" >&2
      return 1
      ;;
  esac

  "$BOOTSTRAP_PYTHON" - "$context" "${inputs[@]}" <<'PY'
import hashlib
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
digest = hashlib.sha256(b"NumericalOJ Docker source v1\0")
for relative_name in sys.argv[2:]:
    path = root / relative_name
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise SystemExit(f"Docker 构建输入必须是普通文件: {path}")
    name = relative_name.encode("utf-8")
    digest.update(len(name).to_bytes(8, "big"))
    digest.update(name)
    digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "big"))
    digest.update(metadata.st_size.to_bytes(8, "big"))
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
print(digest.hexdigest())
PY
}

image_source_digest() {
  local image="$1"

  docker image inspect \
    --format "{{if .Config.Labels}}{{index .Config.Labels \"$SOURCE_IMAGE_LABEL\"}}{{end}}" \
    "$image" 2>/dev/null || true
}

build_candidate_image() {
  local stable="$1"
  local candidate="$2"
  local context="$3"
  shift 3
  local cache_markers=("$@")
  local stable_id
  local cache_descriptions
  local cache_marker
  local source_digest
  local stable_source_digest
  local candidate_source_digest
  local cache_args=()

  stable_id="$(
    docker image inspect --format '{{.Id}}' "$stable" 2>/dev/null || true
  )"
  if [[ -z "$stable_id" ]]; then
    printf '未检测到稳定镜像 %s；为避免冷构建，拒绝继续部署。\n' \
      "$stable" >&2
    return 1
  fi

  source_digest="$(docker_source_digest "$context")" || return 1
  stable_source_digest="$(image_source_digest "$stable")"
  if [[ "$stable_source_digest" == "$source_digest" ]]; then
    printf 'Docker 构建输入未变化，直接复用稳定镜像：%s (%s)\n' \
      "$stable" "$source_digest"
    docker tag "$stable" "$candidate"
    return
  fi

  cache_descriptions="$(
    docker buildx du \
      --builder "$DOCKER_BUILDER" \
      --format '{{.Description}}'
  )" || {
    printf '无法读取 Docker builder %s 的步骤缓存。\n' \
      "$DOCKER_BUILDER" >&2
    return 1
  }
  for cache_marker in "${cache_markers[@]}"; do
    if [[ "$cache_descriptions" != *"$cache_marker"* ]]; then
      printf 'Docker builder %s 缺少关键步骤缓存：%s；为避免冷构建，拒绝继续部署。\n' \
        "$DOCKER_BUILDER" "$cache_marker" >&2
      return 1
    fi
  done

  printf '使用 Docker builder %s 的步骤缓存；稳定镜像：%s (%s)\n' \
    "$DOCKER_BUILDER" "$stable" "$stable_id"
  cache_args+=(--cache-from "$stable")

  DOCKER_BUILDKIT=1 docker build \
    --builder "$DOCKER_BUILDER" \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    "${cache_args[@]}" \
    --label "$MANAGED_IMAGE_LABEL" \
    --label "$SOURCE_IMAGE_LABEL=$source_digest" \
    --tag "$candidate" \
    "$context"

  candidate_source_digest="$(image_source_digest "$candidate")"
  if [[ "$candidate_source_digest" != "$source_digest" ]]; then
    printf '候选镜像缺少预期的构建输入指纹：%s\n' "$candidate" >&2
    return 1
  fi
}

phase='清理遗留候选镜像'
remove_stale_candidate_tags

current_venv_target="$(readlink "$CURRENT_VENV" 2>/dev/null || true)"
if [[ -e "$CURRENT_VENV" && ! -L "$CURRENT_VENV" ]]; then
  printf '%s 必须是部署脚本管理的符号链接。\n' "$CURRENT_VENV" >&2
  exit 1
fi
case "$current_venv_target" in
  '') candidate_slot='slot-a' ;;
  venvs/slot-a|./venvs/slot-a|"$VENV_ROOT/slot-a") candidate_slot='slot-b' ;;
  venvs/slot-b|./venvs/slot-b|"$VENV_ROOT/slot-b") candidate_slot='slot-a' ;;
  *)
    printf 'current-venv 指向未知环境，拒绝删除任何 venv：%s\n' \
      "$current_venv_target" >&2
    exit 1
    ;;
esac
CANDIDATE_VENV="$VENV_ROOT/$candidate_slot"
CANDIDATE_PYTHON="$CANDIDATE_VENV/bin/python3"
CANDIDATE_SUPERVISORD="$CANDIDATE_VENV/bin/supervisord"
CANDIDATE_SUPERVISORCTL="$CANDIDATE_VENV/bin/supervisorctl"

phase='准备 Python 运行环境'
rm -rf -- "$CANDIDATE_VENV"
"$BOOTSTRAP_PYTHON" -m venv "$CANDIDATE_VENV"
"$CANDIDATE_PYTHON" -m pip install \
  --disable-pip-version-check \
  --requirement requirements/production.txt

phase='构建判题镜像'
build_candidate_image \
  "$JUDGER_STABLE" "$JUDGER_CANDIDATE" docker/judger \
  'debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df' \
  'texlive-full' 'intel-oneapi-mkl-devel'
build_candidate_image \
  "$AGENT_JUDGE_STABLE" "$AGENT_JUDGE_CANDIDATE" docker/agent_judge \
  'node:20-bookworm@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5' \
  'texlive-full' 'torch torchvision' 'paddlepaddle paddleocr' \
  'playwright install chromium'

phase='备份数据库'
backup_target="$BACKUP_DIR/mysql-$RUN_ID.sql.gz"
"$CANDIDATE_PYTHON" deploy/backup_database.py --output "$backup_target"
database_backup="$backup_target"

supervisor_pid() {
  local config="$1"
  local pid
  pid="$("$CANDIDATE_SUPERVISORCTL" -c "$config" pid 2>/dev/null \
    | tr -d '[:space:]' || true)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "$pid"
}

legacy_supervisor_pids() {
  local kind="$1"
  "$CANDIDATE_PYTHON" deploy/legacy_supervisor.py \
    --root "$ROOT_DIR" list --service "$kind"
}

unmanaged_processes() {
  local kind="$1"
  local pattern
  local matches
  local found=''
  local patterns=()

  if [[ "$kind" == 'web' ]]; then
    patterns=(
      '[s]upervisord.*deploy/supervisor/web[.]conf'
      '[g]unicorn.*oj:app'
      '[p]ython[^ ]*[[:space:]].*oj[.]py'
    )
  else
    patterns=(
      '[s]upervisord.*deploy/supervisor/celery[.]conf'
      '[c]elery.*-A[[:space:]]+oj[.]celery.*worker'
    )
  fi
  for pattern in "${patterns[@]}"; do
    matches="$(pgrep -f "$pattern" 2>/dev/null || true)"
    if [[ -n "$matches" ]]; then
      found+="${found:+ }${matches//$'\n'/ }"
    fi
  done
  printf '%s\n' "$found"
}

resolve_supervisor() {
  local label="$1"
  local kind="$2"
  local config="$3"
  local pidfile="$4"
  local legacy_pids="$5"
  local pid
  local unmanaged

  pid="$(supervisor_pid "$config" || true)"
  if [[ -n "$pid" ]]; then
    if [[ -n "$legacy_pids" ]]; then
      printf '%s 同时存在新旧两套 Supervisor，拒绝自动停服。\n' \
        "$label" >&2
      return 1
    fi
    printf '%s\n' "$pid"
    return 0
  fi
  if [[ -r "$pidfile" ]]; then
    pid="$(tr -d '[:space:]' <"$pidfile")"
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null; then
      printf '%s Supervisor PID %s 仍存活，但控制 socket 不可用。\n' \
        "$label" "$pid" >&2
      return 1
    fi
  fi
  if [[ -n "$legacy_pids" ]]; then
    printf 'LEGACY\n'
    return 0
  fi
  unmanaged="$(unmanaged_processes "$kind")"
  if [[ -n "$unmanaged" ]]; then
    printf '发现无法由当前 Supervisor socket 管理的 %s 进程：%s\n' \
      "$label" "$unmanaged" >&2
    return 1
  fi
  printf 'ABSENT\n'
}

stop_supervisor() {
  local label="$1"
  local kind="$2"
  local config="$3"
  local pidfile="$4"
  local socket="$5"
  local timeout="$6"
  local pid="$7"
  local legacy_pids="$8"
  local unmanaged

  if [[ "$pid" == 'LEGACY' ]]; then
    printf '正在停止旧版 %s 服务（Supervisor PID %s）...\n' \
      "$label" "$legacy_pids"
    "$CANDIDATE_PYTHON" deploy/legacy_supervisor.py \
      --root "$ROOT_DIR" stop \
      --service "$kind" \
      --expected-pids "$legacy_pids" \
      --timeout "$timeout"
    unmanaged="$(unmanaged_processes "$kind")"
    if [[ -n "$unmanaged" ]]; then
      printf '旧版 %s Supervisor 已退出，但仍有相关进程：%s\n' \
        "$label" "$unmanaged" >&2
      return 1
    fi
    rm -f -- "$pidfile" "$socket"
    return 0
  fi

  if [[ "$pid" == 'ABSENT' ]]; then
    rm -f -- "$pidfile" "$socket"
    printf '%s 服务未运行，跳过停止。\n' "$label"
    return 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f -- "$pidfile" "$socket"
    printf '%s 服务已退出，跳过停止。\n' "$label"
    return 0
  fi

  printf '正在停止 %s 服务（Supervisor PID %s）...\n' "$label" "$pid"
  "$CANDIDATE_SUPERVISORCTL" -c "$config" shutdown >/dev/null
  local deadline=$((SECONDS + timeout))
  while kill -0 "$pid" 2>/dev/null; do
    if ((SECONDS >= deadline)); then
      printf '等待 %s 服务退出超时。\n' "$label" >&2
      return 1
    fi
    sleep 1
  done
  rm -f -- "$pidfile" "$socket"
}

phase='确认现有服务可管理'
legacy_web_pids="$(legacy_supervisor_pids web)"
legacy_celery_pids="$(legacy_supervisor_pids celery)"
web_supervisor_pid="$(
  resolve_supervisor 'Web' web "$WEB_CONFIG" "$WEB_PIDFILE" "$legacy_web_pids"
)"
celery_supervisor_pid="$(
  resolve_supervisor \
    'Celery' celery "$CELERY_CONFIG" "$CELERY_PIDFILE" "$legacy_celery_pids"
)"

phase='停止现有服务'
stop_supervisor \
  'Celery' celery "$CELERY_CONFIG" "$CELERY_PIDFILE" "$CELERY_SOCKET" \
  "$CELERY_STOP_TIMEOUT_SECONDS" "$celery_supervisor_pid" "$legacy_celery_pids"
stop_supervisor \
  'Web' web "$WEB_CONFIG" "$WEB_PIDFILE" "$WEB_SOCKET" \
  "$WEB_STOP_TIMEOUT_SECONDS" "$web_supervisor_pid" "$legacy_web_pids"

phase='切换运行环境并更新数据库结构'
rm -f -- "$CURRENT_VENV_TEMP"
ln -s "venvs/$candidate_slot" "$CURRENT_VENV_TEMP"
"$CANDIDATE_PYTHON" -c \
  'import os, sys; os.replace(sys.argv[1], sys.argv[2])' \
  "$CURRENT_VENV_TEMP" "$CURRENT_VENV"
"$CANDIDATE_PYTHON" scripts/init_db_schema.py
"$CANDIDATE_PYTHON" scripts/recover_pending_tasks.py --confirm-celery-stopped

phase='切换判题镜像'
docker tag "$JUDGER_CANDIDATE" "$JUDGER_STABLE"
docker tag "$AGENT_JUDGE_CANDIDATE" "$AGENT_JUDGE_STABLE"

wait_for_programs() {
  local config="$1"
  local attempts=120
  local status=''
  local name
  local state
  local ignored
  local seen
  local all_running

  while ((attempts > 0)); do
    status="$("$CANDIDATE_SUPERVISORCTL" -c "$config" status 2>/dev/null || true)"
    seen=0
    all_running=1
    while read -r name state ignored; do
      [[ -n "$name" ]] || continue
      seen=1
      if [[ "$state" != 'RUNNING' ]]; then
        all_running=0
        break
      fi
    done <<<"$status"
    if [[ "$seen" -eq 1 && "$all_running" -eq 1 ]]; then
      return 0
    fi
    sleep 1
    attempts=$((attempts - 1))
  done

  printf '服务未在预期时间内进入 RUNNING：\n%s\n' "$status" >&2
  return 1
}

restart_started=1
phase='启动 Celery 服务'
"$CANDIDATE_SUPERVISORD" -c "$CELERY_CONFIG" 9>&-
wait_for_programs "$CELERY_CONFIG"

phase='启动 Web 服务'
"$CANDIDATE_SUPERVISORD" -c "$WEB_CONFIG" 9>&-
wait_for_programs "$WEB_CONFIG"

phase='确认全部服务状态'
wait_for_programs "$CELERY_CONFIG"
wait_for_programs "$WEB_CONFIG"
restart_started=0

phase='清理旧判题镜像'
if ! docker image prune --force --filter "label=$MANAGED_IMAGE_LABEL" >/dev/null; then
  printf '警告：旧的 NumericalOJ dangling 镜像清理失败，请稍后人工检查。\n' >&2
fi

phase='完成'
printf 'NumericalOJ 部署完成。数据库备份：%s\n' "$database_backup"
