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
JUDGER_CANDIDATE="numericaloj-judger:deploy-$RUN_ID"
AGENT_JUDGE_CANDIDATE="numericaloj-agent-judge:deploy-$RUN_ID"
MANAGED_IMAGE_LABEL='org.numericaloj.deploy-managed=true'
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

for command_name in docker flock mysqldump pgrep python3; do
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

python_version="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$python_version" != '3.12' ]]; then
  printf '生产部署要求 Python 3.12，当前 python3 为 %s。\n' "$python_version" >&2
  exit 1
fi

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
python3 -m venv "$CANDIDATE_VENV"
"$CANDIDATE_PYTHON" -m pip install \
  --disable-pip-version-check \
  --requirement requirements/production.txt

phase='构建判题镜像'
docker build --label "$MANAGED_IMAGE_LABEL" \
  --tag "$JUDGER_CANDIDATE" docker/judger
docker build --label "$MANAGED_IMAGE_LABEL" \
  --tag "$AGENT_JUDGE_CANDIDATE" docker/agent_judge

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
docker tag "$JUDGER_CANDIDATE" numericaloj-judger:latest
docker tag "$AGENT_JUDGE_CANDIDATE" numericaloj-agent-judge:latest

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
