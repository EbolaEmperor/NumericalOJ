#!/usr/bin/env bash

set -Eeuo pipefail
export LC_ALL=C
umask 077

STAGING=''
TARGET=''
STATE=''
REVISION=''
EXPECTED_PREVIOUS_REVISION=''
RUN_ID=''
BUILD_JUDGER=0
BUILD_AGENT_JUDGE=0
MIN_TARGET_FREE_BYTES=''
MIN_STATE_FREE_BYTES=''
MIN_DOCKER_FREE_BYTES=''
phase='参数检查'

while (($#)); do
  case "$1" in
    --staging) STAGING="${2-}"; shift 2 ;;
    --target) TARGET="${2-}"; shift 2 ;;
    --state) STATE="${2-}"; shift 2 ;;
    --revision) REVISION="${2-}"; shift 2 ;;
    --expected-previous-revision) EXPECTED_PREVIOUS_REVISION="${2-}"; shift 2 ;;
    --run-id) RUN_ID="${2-}"; shift 2 ;;
    --build-judger) BUILD_JUDGER="${2-}"; shift 2 ;;
    --build-agent-judge) BUILD_AGENT_JUDGE="${2-}"; shift 2 ;;
    --min-target-free-bytes) MIN_TARGET_FREE_BYTES="${2-}"; shift 2 ;;
    --min-state-free-bytes) MIN_STATE_FREE_BYTES="${2-}"; shift 2 ;;
    --min-docker-free-bytes) MIN_DOCKER_FREE_BYTES="${2-}"; shift 2 ;;
    *) printf '未知远端部署参数: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "$(hostname -s)" == 'computing' ]]
[[ "$(id -un)" == 'ebola' ]]
[[ "$TARGET" == '/home/ebola/oj' && "$(realpath "$TARGET")" == '/home/ebola/oj' ]]
[[ "$STATE" == '/home/ebola/.numericaloj-deploy' ]]
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]]
[[ "$EXPECTED_PREVIOUS_REVISION" == 'NONE' \
    || "$EXPECTED_PREVIOUS_REVISION" =~ ^[0-9a-f]{40}$ ]]
[[ "$RUN_ID" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+-[A-Za-z0-9]+$ ]]
[[ "$BUILD_JUDGER" =~ ^[01]$ && "$BUILD_AGENT_JUDGE" =~ ^[01]$ ]]
[[ "$MIN_TARGET_FREE_BYTES" =~ ^[0-9]+$ \
    && "$MIN_STATE_FREE_BYTES" =~ ^[0-9]+$ \
    && "$MIN_DOCKER_FREE_BYTES" =~ ^[0-9]+$ ]]
[[ "$STAGING" == "$STATE/staging/$REVISION-$RUN_ID" ]]
[[ -d "$STAGING" && -f "$STAGING/.deploy-manifest" && -f "$STAGING/config.py" ]]
[[ -f "$STAGING/deploy/process_guard.py" && -f "$STAGING/deploy/static_files.py" \
    && -f "$STAGING/deploy/managed_tree.py" \
    && -f "$STAGING/deploy/manifest.py" \
    && -f "$STAGING/deploy/venv_integrity.py" \
    && -f "$STAGING/requirements/production.txt" ]]
[[ "$(realpath "$STATE")" == "$STATE" && "$(realpath "$STAGING")" == "$STAGING" ]]

partial_venv=''
backup_partial=''
database_partial=''
deployment_succeeded=0
deployment_committed=0

cleanup_failed_artifacts() {
  local cleanup_failed=0
  if [[ -n "$partial_venv" && -e "$partial_venv" ]]; then
    chmod -R u+w "$partial_venv" 2>/dev/null || true
    find "$partial_venv" -depth -delete || cleanup_failed=1
  fi
  [[ -z "$database_partial" ]] || rm -f -- "$database_partial" || cleanup_failed=1
  [[ -z "$backup_partial" ]] || rm -f -- "$backup_partial" || cleanup_failed=1
  # staging 含生产 config.py 和可选 .env；即使完整目录清理失败也先删密钥载体。
  rm -f -- "$STAGING/config.py" "$STAGING/.env" || cleanup_failed=1
  if [[ -d "$STAGING" ]]; then
    find "$STAGING" -depth -delete || cleanup_failed=1
  fi
  return "$cleanup_failed"
}

early_on_error() {
  local exit_code="${1:-$?}"
  trap - ERR EXIT HUP INT TERM
  set +e
  cleanup_failed_artifacts
  printf '远端部署失败（阶段：%s，退出码：%s）。\n' "$phase" "$exit_code" >&2
  exit "$exit_code"
}

cleanup_on_exit() {
  local exit_code=$?
  trap - EXIT
  if [[ "$exit_code" -ne 0 ]] && declare -F on_error >/dev/null; then
    on_error "$exit_code"
  fi
  if [[ "$deployment_succeeded" -eq 0 ]]; then
    set +e
    cleanup_failed_artifacts
  fi
  exit "$exit_code"
}
trap 'early_on_error $?' ERR
trap 'early_on_error 130' HUP INT TERM
trap cleanup_on_exit EXIT

# shellcheck source=deploy/shell_helpers.sh
source "$STAGING/deploy/shell_helpers.sh"

install -d -m 0700 \
  "$STATE" "$STATE/backups" "$STATE/logs" "$STATE/releases" \
  "$STATE/runs" "$STATE/venvs"
RUN_STATE="$STATE/runs/$RUN_ID"
install -d -m 0700 "$RUN_STATE"
exec 9>"$STATE/deploy.lock"
flock -n 9 || {
  printf '已有 NumericalOJ 部署正在运行。\n' >&2
  exit 1
}

LOG_FILE="$RUN_STATE/deploy.log"
exec > >(tee -a "$LOG_FILE") 2>&1

phase='候选版本检查'
shutdown_started=0
code_activated=0
venv_switched=0
judger_tag_switched=0
agent_judge_tag_switched=0
initial_web_present=0
initial_celery_present=0
backup_archive=''
database_backup=''
previous_manifest="$STAGING/.previous-manifest"
STATIC_ADDITIONS="$STAGING/.static-additions"
STATIC_INSTALLED="$STAGING/.static-installed"
STATIC_CANDIDATES="$STAGING/.static-candidates"
STATIC_SYMLINKS="$STAGING/.static-symlinks"
CODE_INSTALL_RECORD="$STAGING/.managed-installed.jsonl"
: >"$previous_manifest"
: >"$STATIC_ADDITIONS"
: >"$STATIC_INSTALLED"
: >"$STATIC_CANDIDATES"
: >"$STATIC_SYMLINKS"
: >"$CODE_INSTALL_RECORD"

PROCESS_GUARD=(python3 "$STAGING/deploy/process_guard.py")
STATIC_TOOL=(python3 "$STAGING/deploy/static_files.py")
MANAGED_TOOL=(python3 "$STAGING/deploy/managed_tree.py")
VENV_TOOL=(python3 "$STAGING/deploy/venv_integrity.py")
REQUIREMENTS_SHA256="$(python3 - "$STAGING/requirements/production.txt" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
[[ "$REQUIREMENTS_SHA256" =~ ^[0-9a-f]{64}$ ]]
CANDIDATE_VENV="$STATE/venvs/py312-$REQUIREMENTS_SHA256"
CURRENT_VENV_LINK="$STATE/current-venv"
old_venv_target=''
if [[ -L "$CURRENT_VENV_LINK" ]]; then
  old_venv_target="$(readlink "$CURRENT_VENV_LINK")"
  old_venv_real="$(realpath "$CURRENT_VENV_LINK")"
  [[ -d "$old_venv_real" && "$old_venv_real" == "$STATE/venvs/"* ]] || {
    printf 'current-venv 未指向受管的版本化虚拟环境。\n' >&2
    exit 1
  }
elif [[ -e "$CURRENT_VENV_LINK" ]]; then
  printf '%s 必须是符号链接。\n' "$CURRENT_VENV_LINK" >&2
  exit 1
fi

if [[ -e "$STATE/current" || -L "$STATE/current" ]]; then
  [[ -L "$STATE/current" && -d "$STATE/current" ]] || {
    printf '部署 current 状态必须是有效符号链接。\n' >&2
    exit 1
  }
  current_state_real="$(realpath "$STATE/current")"
  [[ "$current_state_real" == "$STATE/runs/"* \
      && -f "$STATE/current/revision" && -f "$STATE/current/manifest" ]] || {
    printf '部署 current 状态不完整或越过受管目录。\n' >&2
    exit 1
  }
fi

authoritative_previous_revision='NONE'
if [[ -L "$STATE/current" ]]; then
  authoritative_previous_revision="$(tr -d '[:space:]' <"$STATE/current/revision")"
elif [[ -f "$STATE/current_commit" ]]; then
  authoritative_previous_revision="$(tr -d '[:space:]' <"$STATE/current_commit")"
fi
[[ "$authoritative_previous_revision" == 'NONE' \
    || "$authoritative_previous_revision" =~ ^[0-9a-f]{40}$ ]]
[[ "$authoritative_previous_revision" == "$EXPECTED_PREVIOUS_REVISION" ]] || {
  printf '部署基线在本地预检后已变化，请重新执行 deploy.sh。\n' >&2
  exit 1
}

old_judger_id="$(docker image inspect --format '{{.Id}}' numericaloj-judger:latest 2>/dev/null || true)"
old_agent_judge_id="$(docker image inspect --format '{{.Id}}' numericaloj-agent-judge:latest 2>/dev/null || true)"
if [[ -L "$STATE/current" ]]; then
  if [[ -f "$STATE/current/judger-image-id" ]]; then
    state_judger_id="$(tr -d '[:space:]' <"$STATE/current/judger-image-id")"
    [[ "$state_judger_id" =~ ^sha256:[0-9a-f]{64}$ ]]
    docker image inspect "$state_judger_id" >/dev/null
    if [[ "$old_judger_id" != "$state_judger_id" ]]; then
      printf '检测到 numericaloj-judger:latest 漂移，将重建候选镜像。\n' >&2
      BUILD_JUDGER=1
    fi
    old_judger_id="$state_judger_id"
  else
    BUILD_JUDGER=1
  fi
  if [[ -f "$STATE/current/agent-judge-image-id" ]]; then
    state_agent_judge_id="$(tr -d '[:space:]' <"$STATE/current/agent-judge-image-id")"
    [[ "$state_agent_judge_id" =~ ^sha256:[0-9a-f]{64}$ ]]
    docker image inspect "$state_agent_judge_id" >/dev/null
    if [[ "$old_agent_judge_id" != "$state_agent_judge_id" ]]; then
      printf '检测到 numericaloj-agent-judge:latest 漂移，将重建候选镜像。\n' >&2
      BUILD_AGENT_JUDGE=1
    fi
    old_agent_judge_id="$state_agent_judge_id"
  else
    BUILD_AGENT_JUDGE=1
  fi
fi

DOCKER_ROOT="$(docker info --format '{{.DockerRootDir}}')"
[[ "$DOCKER_ROOT" == /* && -d "$DOCKER_ROOT" ]] || {
  printf 'Docker data-root 无法识别或不存在：%s\n' "$DOCKER_ROOT" >&2
  exit 1
}
DOCKER_ROOT="$(realpath "$DOCKER_ROOT")"
[[ "$DOCKER_ROOT" == /* && -d "$DOCKER_ROOT" ]] || {
  printf 'Docker data-root 解析失败：%s\n' "$DOCKER_ROOT" >&2
  exit 1
}

check_disk_headroom() {
  numoj_require_free_bytes "$TARGET" "$MIN_TARGET_FREE_BYTES" '生产代码目录'
  numoj_require_free_bytes "$STATE" "$MIN_STATE_FREE_BYTES" '部署状态目录'
  numoj_require_free_bytes "$DOCKER_ROOT" "$MIN_DOCKER_FREE_BYTES" 'Docker data-root'
}

phase='磁盘余量预检'
check_disk_headroom

validate_manifest() {
  local manifest="$1"
  [[ -f "$manifest" ]] || return 1
  LC_ALL=C sort -c "$manifest" >/dev/null || return 1
  while IFS= read -r path; do
    numoj_is_safe_path "$path" || {
      printf '部署清单包含不安全路径：%q\n' "$path" >&2
      return 1
    }
  done <"$manifest"
}

if [[ -L "$STATE/current" && -f "$STATE/current/manifest" ]]; then
  cp "$STATE/current/manifest" "$previous_manifest"
elif [[ -f "$STATE/current_manifest" ]]; then
  cp "$STATE/current_manifest" "$previous_manifest"
elif git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  previous_tracked="$STAGING/.previous-tracked.bin"
  previous_managed="$STAGING/.previous-managed.bin"
  git -C "$TARGET" ls-files -z >"$previous_tracked"
  python3 "$STAGING/deploy/manifest.py" \
    --input "$previous_tracked" \
    --excludes "$STAGING/deploy/rsync-excludes.txt" \
    --manifest "$previous_manifest" \
    --nul-output "$previous_managed"
fi
validate_manifest "$STAGING/.deploy-manifest"
validate_manifest "$previous_manifest"

restore_venv_link() {
  [[ "$venv_switched" -eq 1 ]] || return 0
  if [[ -n "$old_venv_target" ]]; then
    numoj_atomic_symlink "$old_venv_target" "$CURRENT_VENV_LINK" "$RUN_ID" || return 1
  else
    rm -f -- "$CURRENT_VENV_LINK" || return 1
  fi
  venv_switched=0
}

remove_installed_static() {
  [[ -f "$STATIC_INSTALLED" ]] || return 0
  "${STATIC_TOOL[@]}" remove-recorded \
    --target-root "$TARGET" --record "$STATIC_INSTALLED"
}

restore_code() {
  [[ "$code_activated" -eq 1 && -f "$backup_archive" ]] || return 0
  "${MANAGED_TOOL[@]}" rollback \
    --target-root "$TARGET" \
    --old-manifest "$previous_manifest" \
    --new-manifest "$STAGING/.deploy-manifest" \
    --record "$CODE_INSTALL_RECORD" \
    --archive "$backup_archive" || return 1
  code_activated=0
}

restore_image_tag() {
  local image="$1"
  local previous_id="$2"
  local switched="$3"
  [[ "$switched" -eq 1 ]] || return 0
  if [[ -n "$previous_id" ]]; then
    docker tag "$previous_id" "$image:latest"
  else
    # 首次部署没有旧 latest；回滚必须撤销本次新建的浮动标签。
    docker image rm "$image:latest"
  fi
}

guard_pids() {
  local process_type="$1"
  local kind="$2"
  shift 2
  "${PROCESS_GUARD[@]}" "$process_type" --target "$TARGET" --kind "$kind" "$@"
}

guard_pid() {
  local process_type="$1"
  local kind="$2"
  local pid="$3"
  "${PROCESS_GUARD[@]}" "$process_type" --target "$TARGET" --kind "$kind" --pid "$pid"
}

# PID 必须在发送信号的当下仍通过 argv/cwd 校验。校验与信号间若恰好退出，视为成功；
# 仍存活但不再匹配则认为发生 PID 复用，失败关闭。
signal_guarded_process() {
  local process_type="$1"
  local kind="$2"
  local pid="$3"
  local signal="$4"
  if guard_pid "$process_type" "$kind" "$pid"; then
    if kill "-$signal" "$pid"; then
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || return 0
    printf '向重新验证的 %s/%s PID 发送 %s 失败：%s\n' \
      "$process_type" "$kind" "$signal" "$pid" >&2
    return 1
  fi
  kill -0 "$pid" 2>/dev/null || return 0
  printf 'PID 在发送 %s 前已不再属于目标 %s/%s：%s\n' \
    "$signal" "$process_type" "$kind" "$pid" >&2
  return 1
}

# 输出 ABSENT 或唯一且经过 argv/cwd 精确校验的 PID；任何歧义均失败关闭。
resolve_supervisor_pid() {
  local kind="$1"
  local pidfile="$2"
  local -a candidates=()
  local candidate_output
  candidate_output="$(guard_pids supervisor "$kind")" || return 1
  if [[ -n "$candidate_output" ]]; then
    mapfile -t candidates <<<"$candidate_output"
  fi
  if ((${#candidates[@]} > 1)); then
    printf '检测到多个 %s supervisord：%s\n' "$kind" "${candidates[*]}" >&2
    return 1
  fi

  local recorded=''
  if [[ -f "$pidfile" ]]; then
    recorded="$(tr -d '[:space:]' <"$pidfile")" || return 1
    if [[ -n "$recorded" && ! "$recorded" =~ ^[0-9]+$ ]]; then
      printf '%s PID 文件格式非法。\n' "$kind" >&2
      return 1
    fi
    if [[ -n "$recorded" ]] && kill -0 "$recorded" 2>/dev/null; then
      guard_pid supervisor "$kind" "$recorded" || {
        printf '%s PID 文件指向非目标进程：%s\n' "$kind" "$recorded" >&2
        return 1
      }
      if ((${#candidates[@]} != 1)) || [[ "${candidates[0]}" != "$recorded" ]]; then
        printf '%s Supervisor PID 状态不一致。\n' "$kind" >&2
        return 1
      fi
      printf '%s\n' "$recorded"
      return 0
    fi
  fi

  if ((${#candidates[@]} == 1)); then
    printf '%s\n' "${candidates[0]}"
  else
    printf 'ABSENT\n'
  fi
}

terminate_app_processes() {
  local kind="$1"
  local -a pids=()
  local pid_output
  pid_output="$(guard_pids app "$kind")" || return 1
  if [[ -n "$pid_output" ]]; then
    mapfile -t pids <<<"$pid_output"
  fi
  local pid
  for pid in "${pids[@]}"; do
    signal_guarded_process app "$kind" "$pid" TERM || return 1
  done
  for _ in $(seq 1 30); do
    pids=()
    pid_output="$(guard_pids app "$kind")" || return 1
    if [[ -n "$pid_output" ]]; then
      mapfile -t pids <<<"$pid_output"
    fi
    ((${#pids[@]} == 0)) && return 0
    sleep 1
  done
  for pid in "${pids[@]}"; do
    signal_guarded_process app "$kind" "$pid" KILL || return 1
  done
  for _ in $(seq 1 10); do
    pids=()
    pid_output="$(guard_pids app "$kind")" || return 1
    if [[ -n "$pid_output" ]]; then
      mapfile -t pids <<<"$pid_output"
    fi
    ((${#pids[@]} == 0)) && return 0
    sleep 1
  done
  printf '仍存在 %s 应用进程：%s\n' "$kind" "${pids[*]}" >&2
  return 1
}

wait_supervisor_exit() {
  local pid="$1"
  local kind="$2"
  local timeout_seconds="$3"
  local deadline=$((SECONDS + timeout_seconds))
  local exited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [[ -r "/proc/$pid/stat" && "$(awk '{print $3}' "/proc/$pid/stat")" == 'Z' ]]; then
      exited=1
      break
    fi
    guard_pid supervisor "$kind" "$pid" || {
      printf '%s Supervisor PID 在等待期间被其他进程复用：%s\n' "$kind" "$pid" >&2
      return 1
    }
    ((SECONDS < deadline)) || break
    sleep 2
  done
  if [[ "$exited" -eq 0 ]] && kill -0 "$pid" 2>/dev/null; then
    guard_pid supervisor "$kind" "$pid" || {
      printf '%s Supervisor PID 已被其他进程复用，拒绝发送信号：%s\n' "$kind" "$pid" >&2
      return 1
    }
    printf '%s Supervisor 超时，对重新验证的 PID 发送 SIGKILL：%s\n' "$kind" "$pid" >&2
    signal_guarded_process supervisor "$kind" "$pid" KILL || return 1
    for _ in $(seq 1 10); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null && guard_pid supervisor "$kind" "$pid"; then
      printf '%s Supervisor 在 SIGKILL 后仍存在：%s\n' "$kind" "$pid" >&2
      return 1
    fi
  fi
  terminate_app_processes "$kind"
}

stop_supervisor() {
  local kind="$1"
  local config="$2"
  local socket="$3"
  local pidfile="$4"
  local timeout_seconds="$5"
  local state
  state="$(resolve_supervisor_pid "$kind" "$pidfile")" || return 1
  if [[ "$state" == 'ABSENT' ]]; then
    rm -f -- "$pidfile" "$socket" || return 1
    terminate_app_processes "$kind" || return 1
    return 0
  fi

  local pid="$state"
  if [[ -S "$socket" ]]; then
    local control_pid
    if control_pid="$(supervisorctl -c "$config" pid 2>/dev/null | tr -d '[:space:]')"; then
      [[ "$control_pid" == "$pid" ]] || {
        printf '%s Supervisor socket/PID 不一致。\n' "$kind" >&2
        return 1
      }
      supervisorctl -c "$config" shutdown \
        || signal_guarded_process supervisor "$kind" "$pid" TERM \
        || return 1
    else
      signal_guarded_process supervisor "$kind" "$pid" TERM || return 1
    fi
  else
    signal_guarded_process supervisor "$kind" "$pid" TERM || return 1
  fi
  wait_supervisor_exit "$pid" "$kind" "$timeout_seconds"
}

start_services() {
  local start_web="${1:-1}"
  local start_celery="${2:-1}"
  local web_config='deploy/supervisor/web.conf'
  local celery_config='deploy/supervisor/celery.conf'
  [[ -f "$TARGET/$web_config" ]] || web_config='web.conf'
  [[ -f "$TARGET/$celery_config" ]] || celery_config='celery.conf'
  local web_pids celery_pids web_supervisors celery_supervisors
  web_pids="$(guard_pids app web)" || return 1
  celery_pids="$(guard_pids app celery)" || return 1
  web_supervisors="$(guard_pids supervisor web)" || return 1
  celery_supervisors="$(guard_pids supervisor celery)" || return 1
  [[ -z "$web_pids" ]] || {
    printf '启动前仍存在旧 Gunicorn 进程。\n' >&2
    return 1
  }
  [[ -z "$celery_pids" ]] || {
    printf '启动前仍存在旧 Celery 进程。\n' >&2
    return 1
  }
  [[ -z "$web_supervisors" && -z "$celery_supervisors" ]] || {
    printf '启动前仍存在目标 Supervisor 进程。\n' >&2
    return 1
  }
  if [[ "$start_web" -eq 1 ]]; then
    rm -f -- /tmp/noj_web_supervisord.pid /tmp/noj_web_supervisor.sock || return 1
    (cd "$TARGET" && supervisord -c "$web_config") || return 1
  fi
  if [[ "$start_celery" -eq 1 ]]; then
    rm -f -- /tmp/noj_celery_supervisord.pid /tmp/noj_celery_supervisor.sock || return 1
    (cd "$TARGET" && supervisord -c "$celery_config") || return 1
  fi
}

verify_rollback_services() {
  local expect_web="$1"
  local expect_celery="$2"
  local web_state celery_state web_apps celery_apps queue_apps web_ok celery_ok
  local queue
  for _ in $(seq 1 60); do
    web_state="$(resolve_supervisor_pid web /tmp/noj_web_supervisord.pid)" || return 1
    celery_state="$(resolve_supervisor_pid celery /tmp/noj_celery_supervisord.pid)" || return 1
    web_apps="$(guard_pids app web)" || return 1
    celery_apps="$(guard_pids app celery)" || return 1
    web_ok=0
    celery_ok=0
    if [[ "$expect_web" -eq 1 && "$web_state" != 'ABSENT' && -n "$web_apps" ]]; then
      if curl -fsS --connect-timeout 2 --max-time 5 \
          http://127.0.0.1:2025/health/live >/dev/null \
          && curl -fsS --connect-timeout 2 --max-time 5 \
            http://127.0.0.1:2025/health/ready >/dev/null; then
        web_ok=1
      fi
    elif [[ "$expect_web" -eq 0 && "$web_state" == 'ABSENT' && -z "$web_apps" ]]; then
      web_ok=1
    fi
    if [[ "$expect_celery" -eq 1 && "$celery_state" != 'ABSENT' \
        && -n "$celery_apps" ]]; then
      local all_queues=1
      for queue in celery agent judge; do
        queue_apps="$(guard_pids app celery --queue "$queue")" || return 1
        [[ -n "$queue_apps" ]] || all_queues=0
      done
      [[ "$all_queues" -eq 1 ]] && celery_ok=1
    elif [[ "$expect_celery" -eq 0 && "$celery_state" == 'ABSENT' \
        && -z "$celery_apps" ]]; then
      celery_ok=1
    fi
    [[ "$web_ok" -eq 1 && "$celery_ok" -eq 1 ]] && return 0
    sleep 2
  done
  printf '回滚后的 Web/Celery 未通过进程与健康检查。\n' >&2
  return 1
}

on_error() {
  local exit_code="${1:-$?}"
  trap - ERR EXIT HUP INT TERM
  set +e
  printf '远端部署失败（阶段：%s，退出码：%s）。\n' "$phase" "$exit_code" >&2
  if [[ "$shutdown_started" -eq 1 && "$deployment_committed" -eq 0 ]]; then
    local rollback_failed=0
    stop_supervisor web "$STAGING/deploy/supervisor/web.conf" \
      /tmp/noj_web_supervisor.sock /tmp/noj_web_supervisord.pid 60 || rollback_failed=1
    stop_supervisor celery "$STAGING/deploy/supervisor/celery.conf" \
      /tmp/noj_celery_supervisor.sock /tmp/noj_celery_supervisord.pid 1900 || rollback_failed=1
    remove_installed_static || rollback_failed=1
    restore_code || rollback_failed=1
    restore_image_tag numericaloj-judger "$old_judger_id" \
      "$judger_tag_switched" || rollback_failed=1
    restore_image_tag numericaloj-agent-judge "$old_agent_judge_id" \
      "$agent_judge_tag_switched" || rollback_failed=1
    restore_venv_link || rollback_failed=1
    if [[ "$rollback_failed" -eq 0 ]]; then
      start_services "$initial_web_present" "$initial_celery_present" \
        || rollback_failed=1
      [[ "$rollback_failed" -ne 0 ]] \
        || verify_rollback_services "$initial_web_present" "$initial_celery_present" \
        || rollback_failed=1
    fi
    if [[ "$rollback_failed" -ne 0 ]]; then
      printf '自动回滚未完整成功；已停止继续启动，请按日志人工恢复。\n' >&2
    fi
  fi
  [[ -n "$database_backup" && -f "$database_backup" ]] \
    && printf '已验证的数据库备份：%s（不会自动回灌）。\n' "$database_backup" >&2
  cleanup_failed_artifacts || printf '警告：失败工件未能完整清理。\n' >&2
  exit "$exit_code"
}
trap 'on_error $?' ERR
trap 'on_error 130' HUP INT TERM

phase='准备生产虚拟环境'
if [[ ! -d "$CANDIDATE_VENV" ]]; then
  [[ ! -e "$CANDIDATE_VENV" && ! -L "$CANDIDATE_VENV" ]] || {
    printf '依赖摘要对应路径存在但不是目录：%s\n' "$CANDIDATE_VENV" >&2
    exit 1
  }
  partial_venv="$STATE/venvs/.py312-${REQUIREMENTS_SHA256}-${RUN_ID}.partial"
  [[ ! -e "$partial_venv" && ! -L "$partial_venv" ]] || {
    printf '候选虚拟环境临时路径已存在，拒绝覆盖：%s\n' "$partial_venv" >&2
    exit 1
  }
  python3 -m venv "$partial_venv"
  "$partial_venv/bin/python3" -m pip install --disable-pip-version-check \
    -r "$STAGING/requirements/production.txt"
  "$partial_venv/bin/python3" -m pip check
  "$partial_venv/bin/python3" -c \
    'import bleach, celery, faiss, flask, gunicorn, openai, pypdfium2, pymysql, redis, tree_sitter, tree_sitter_cpp'
  "$partial_venv/bin/python3" -c \
    'import sys; assert sys.version_info[:2] == (3, 12), sys.version'
  printf '%s\n' "$REQUIREMENTS_SHA256" \
    >"$partial_venv/.numericaloj-requirements-sha256"
  "${VENV_TOOL[@]}" seal \
    --venv "$partial_venv" \
    --requirements-sha256 "$REQUIREMENTS_SHA256"
  mv "$partial_venv" "$CANDIDATE_VENV"
  partial_venv=''
fi
"${VENV_TOOL[@]}" verify \
  --venv "$CANDIDATE_VENV" \
  --requirements-sha256 "$REQUIREMENTS_SHA256"
[[ "$(cat "$CANDIDATE_VENV/.numericaloj-requirements-sha256")" \
    == "$REQUIREMENTS_SHA256" ]]
PYTHONDONTWRITEBYTECODE=1 "$CANDIDATE_VENV/bin/python3" -m pip check
PYTHONDONTWRITEBYTECODE=1 "$CANDIDATE_VENV/bin/python3" -c \
  'import bleach, celery, faiss, flask, gunicorn, openai, pypdfium2, pymysql, redis, tree_sitter, tree_sitter_cpp'
PYTHONDONTWRITEBYTECODE=1 "$CANDIDATE_VENV/bin/python3" -c \
  'import sys; assert sys.version_info[:2] == (3, 12), sys.version'
"${VENV_TOOL[@]}" verify \
  --venv "$CANDIDATE_VENV" \
  --requirements-sha256 "$REQUIREMENTS_SHA256"

phase='候选版本检查'
cd "$STAGING"
"$CANDIDATE_VENV/bin/python3" scripts/init_db_schema.py --dry-run >"$RUN_STATE/schema-plan.sql"

phase='构建候选镜像'
if [[ "$BUILD_JUDGER" -eq 1 ]] || ! docker image inspect numericaloj-judger:latest >/dev/null 2>&1; then
  docker build -t "numericaloj-judger:$REVISION" docker/judger
  BUILD_JUDGER=1
fi
if [[ "$BUILD_AGENT_JUDGE" -eq 1 ]] || ! docker image inspect numericaloj-agent-judge:latest >/dev/null 2>&1; then
  docker build -t "numericaloj-agent-judge:$REVISION" docker/agent_judge
  BUILD_AGENT_JUDGE=1
fi
judger_candidate='numericaloj-judger:latest'
agent_candidate='numericaloj-agent-judge:latest'
[[ "$BUILD_JUDGER" -eq 0 ]] || judger_candidate="numericaloj-judger:$REVISION"
[[ "$BUILD_AGENT_JUDGE" -eq 0 ]] || agent_candidate="numericaloj-agent-judge:$REVISION"
docker image inspect "$judger_candidate" >/dev/null
docker image inspect "$agent_candidate" >/dev/null
docker run --rm --network none "$judger_candidate" /bin/sh -ceu \
  'command -v python3 gcc g++ octave >/dev/null; python3 -c "import numpy, scipy, matplotlib"'
docker run --rm --network none "$agent_candidate" /bin/sh -ceu \
  'command -v claude codex opencode report run_harness >/dev/null; claude --version >/dev/null; codex --version >/dev/null; opencode --version >/dev/null'

phase='静态资源预检'
if [[ -d "$STAGING/.static-payload/static" ]]; then
  find "$STAGING/.static-payload/static" -type f -print0 >"$STATIC_CANDIDATES"
  find "$STAGING/.static-payload/static" -type l -print0 >"$STATIC_SYMLINKS"
fi
[[ ! -s "$STATIC_SYMLINKS" ]] || {
  printf '生产 static 不接受仓库符号链接。\n' >&2
  exit 1
}
while IFS= read -r -d '' source_file; do
  relative="${source_file#"$STAGING/.static-payload/"}"
  numoj_is_safe_path "$relative"
  static_state="$("${STATIC_TOOL[@]}" classify \
    --source "$source_file" --target-root "$TARGET" --relative "$relative")" || {
    printf '生产 static 为追加式目录，拒绝冲突或符号链接路径：%s\n' "$relative" >&2
    exit 1
  }
  if [[ "$static_state" == 'MISSING' ]]; then
    printf '%s\0' "$relative" >>"$STATIC_ADDITIONS"
  elif [[ "$static_state" != 'IDENTICAL' ]]; then
    printf 'static 检查返回未知状态：%s\n' "$static_state" >&2
    exit 1
  fi
done <"$STATIC_CANDIDATES"

phase='停机前磁盘余量检查'
check_disk_headroom

phase='停止现有服务'
initial_web_state="$(resolve_supervisor_pid web /tmp/noj_web_supervisord.pid)"
initial_celery_state="$(resolve_supervisor_pid celery /tmp/noj_celery_supervisord.pid)"
initial_web_apps="$(guard_pids app web)"
initial_celery_apps="$(guard_pids app celery)"
[[ "$initial_web_state" == 'ABSENT' && -z "$initial_web_apps" ]] \
  || initial_web_present=1
[[ "$initial_celery_state" == 'ABSENT' && -z "$initial_celery_apps" ]] \
  || initial_celery_present=1
shutdown_started=1
stop_supervisor web "$STAGING/deploy/supervisor/web.conf" \
  /tmp/noj_web_supervisor.sock /tmp/noj_web_supervisord.pid 60
stop_supervisor celery "$STAGING/deploy/supervisor/celery.conf" \
  /tmp/noj_celery_supervisor.sock /tmp/noj_celery_supervisord.pid 1900

phase='备份数据库与当前代码'
database_final="$STATE/backups/mysql-${REVISION}-${RUN_ID}.sql.gz"
database_partial="$database_final.partial"
eval "$("$CANDIDATE_VENV/bin/python3" - <<'PY'
import shlex
import config
import pymysql

values = {
    'DB_HOST': getattr(config, 'MYSQL_HOST', '127.0.0.1'),
    'DB_PORT': int(getattr(config, 'MYSQL_PORT', 3306)),
    'DB_USER': getattr(config, 'MYSQL_USERNAME'),
    'DB_PASSWORD': getattr(config, 'MYSQL_PASSWORD'),
    'DB_NAME': getattr(config, 'MYSQL_DB', 'myojdb'),
}
connection = pymysql.connect(
    host=values['DB_HOST'],
    port=values['DB_PORT'],
    user=values['DB_USER'],
    password=values['DB_PASSWORD'],
    charset='utf8mb4',
)
try:
    with connection.cursor() as cursor:
        cursor.execute(
            'SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=%s',
            (values['DB_NAME'],),
        )
        values['DB_EXISTS'] = 1 if cursor.fetchone() else 0
finally:
    connection.close()
for key, value in values.items():
    print(f'{key}={shlex.quote(str(value))}')
PY
)"
[[ "$DB_EXISTS" =~ ^[01]$ ]]
if [[ "$DB_EXISTS" -eq 1 ]]; then
  MYSQL_PWD="$DB_PASSWORD" mysqldump \
    --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" \
    --single-transaction --routines --triggers --events --no-tablespaces \
    --set-gtid-purged=OFF "$DB_NAME" | gzip -c >"$database_partial"
else
  printf '%s\n' \
    '-- NumericalOJ pre-deploy state: configured database did not exist.' \
    | gzip -c >"$database_partial"
fi
unset DB_PASSWORD MYSQL_PWD
[[ -s "$database_partial" ]]
gzip -t "$database_partial"
mv "$database_partial" "$database_final"
database_partial=''
database_backup="$database_final"

backup_archive="$STATE/releases/previous-${REVISION}-${RUN_ID}.tar.gz"
backup_partial="$backup_archive.partial"
"${MANAGED_TOOL[@]}" backup \
  --target-root "$TARGET" \
  --manifest "$previous_manifest" \
  --archive "$backup_partial"
tar -tzf "$backup_partial" >/dev/null
"${MANAGED_TOOL[@]}" validate-backup \
  --manifest "$previous_manifest" \
  --archive "$backup_partial"
mv "$backup_partial" "$backup_archive"

phase='激活候选代码'
code_activated=1
"${MANAGED_TOOL[@]}" activate \
  --source-root "$STAGING" \
  --target-root "$TARGET" \
  --old-manifest "$previous_manifest" \
  --new-manifest "$STAGING/.deploy-manifest" \
  --record "$CODE_INSTALL_RECORD"

while IFS= read -r -d '' relative; do
  "${STATIC_TOOL[@]}" install \
    --source "$STAGING/.static-payload/$relative" \
    --target-root "$TARGET" \
    --relative "$relative" \
    --record "$STATIC_INSTALLED"
done <"$STATIC_ADDITIONS"

phase='同步数据库结构与恢复任务'
cd "$TARGET"
"$CANDIDATE_VENV/bin/python3" scripts/init_db_schema.py
"$CANDIDATE_VENV/bin/python3" scripts/recover_pending_tasks.py --confirm-celery-stopped

phase='切换运行环境、镜像并启动服务'
numoj_atomic_symlink "$CANDIDATE_VENV" "$CURRENT_VENV_LINK" "$RUN_ID"
venv_switched=1
if [[ "$BUILD_JUDGER" -eq 1 ]]; then
  docker tag "numericaloj-judger:$REVISION" numericaloj-judger:latest
  judger_tag_switched=1
fi
if [[ "$BUILD_AGENT_JUDGE" -eq 1 ]]; then
  docker tag "numericaloj-agent-judge:$REVISION" numericaloj-agent-judge:latest
  agent_judge_tag_switched=1
fi
start_services

assert_supervisor_running() {
  local kind="$1"
  local config="$2"
  local pidfile="$3"
  local expected_programs="$4"
  local pid
  pid="$(resolve_supervisor_pid "$kind" "$pidfile")" || return 1
  [[ "$pid" != 'ABSENT' ]] || return 1
  local control_pid
  control_pid="$(supervisorctl -c "$config" pid | tr -d '[:space:]')" || return 1
  [[ "$control_pid" == "$pid" ]] || return 1
  local status
  status="$(supervisorctl -c "$config" status)" || return 1
  local program
  for program in $expected_programs; do
    grep -E "^${program}[[:space:]]+RUNNING[[:space:]]" <<<"$status" >/dev/null \
      || return 1
  done
}

queues_ready() {
  local expected_host
  expected_host="$(hostname -s)"
  local queue_json
  queue_json="$("$CURRENT_VENV_LINK/bin/python3" -m celery -A oj.celery \
    inspect active_queues --timeout=5 --json 2>/dev/null)" || return 1
  ACTIVE_QUEUES_JSON="$queue_json" EXPECTED_HOST="$expected_host" \
    "$CURRENT_VENV_LINK/bin/python3" - <<'PY'
import json
import os

data = json.loads(os.environ['ACTIVE_QUEUES_JSON'])
host = os.environ['EXPECTED_HOST']
expected = {
    f'judge@{host}': {'celery'},
    f'agent@{host}': {'agent'},
    f'agent_judge@{host}': {'judge'},
}
if set(data) != set(expected):
    raise SystemExit(1)
for worker, queues in expected.items():
    actual = {entry.get('name') for entry in data[worker] if isinstance(entry, dict)}
    if actual != queues:
        raise SystemExit(1)
PY
}

phase='健康检查'
for _ in $(seq 1 60); do
  if assert_supervisor_running web "$TARGET/deploy/supervisor/web.conf" \
        /tmp/noj_web_supervisord.pid 'web' \
      && curl -fsS --connect-timeout 2 --max-time 5 http://127.0.0.1:2025/health/live >/dev/null \
      && curl -fsS --connect-timeout 2 --max-time 5 http://127.0.0.1:2025/health/ready >/dev/null \
      && assert_supervisor_running celery "$TARGET/deploy/supervisor/celery.conf" \
        /tmp/noj_celery_supervisord.pid \
        'celery:celery_judge celery:celery_agent celery:celery_agent_judge' \
      && queues_ready; then
    deployment_ready=1
    break
  fi
  sleep 2
done
[[ "${deployment_ready:-0}" -eq 1 ]]

phase='记录部署状态'
cp "$STAGING/.deploy-manifest" "$RUN_STATE/manifest"
[[ ! -f "$STAGING/.static-changed-files.bin" ]] \
  || cp "$STAGING/.static-changed-files.bin" "$RUN_STATE/static-changed-files.bin"
printf '%s\n' "$REVISION" >"$RUN_STATE/revision"
printf '%s\n' "$CANDIDATE_VENV" >"$RUN_STATE/venv"
printf '%s\n' "$REQUIREMENTS_SHA256" >"$RUN_STATE/requirements-sha256"
printf '%s\n' "$database_backup" >"$RUN_STATE/database-backup"
printf '%s\n' "$DB_EXISTS" >"$RUN_STATE/database-existed"
docker image inspect --format '{{.Id}}' numericaloj-judger:latest >"$RUN_STATE/judger-image-id"
docker image inspect --format '{{.Id}}' numericaloj-agent-judge:latest >"$RUN_STATE/agent-judge-image-id"
numoj_atomic_symlink "runs/$RUN_ID" "$STATE/current" "$RUN_ID"
deployment_committed=1

printf '部署成功。数据库备份：%s\n' "$database_backup"
if ! cleanup_failed_artifacts; then
  printf '警告：候选 staging 清理失败，请人工删除：%s\n' "$STAGING" >&2
fi
deployment_succeeded=1
