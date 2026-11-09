#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export NUMOJ_ENVIRONMENT=production
STATE_DIR="$ROOT_DIR/.deploy"
VENV_ROOT="$STATE_DIR/venvs"
CURRENT_VENV="$STATE_DIR/current-venv"
EDITOR_TOOLCHAIN_ROOT="$STATE_DIR/editor-toolchains"
CURRENT_EDITOR_TOOLCHAIN="$STATE_DIR/current-editor-toolchain"
BACKUP_DIR="$STATE_DIR/backups"
ARC_DATA_ROOT="$STATE_DIR/arc-agi-3"
ARC_CURRENT_SET="$ARC_DATA_ROOT/current"
STATIC_PRECOMPRESSION_STATE_DIR="$STATE_DIR/static-precompression"
FRONTEND_NODE_MODULES_DIR="$STATE_DIR/frontend-node-modules"
VIBEHUB_BASE_OCI_LAYOUT_ROOT="$STATE_DIR/vibehub-base-oci"
LOCK_FILE='/tmp/noj_deploy.lock'
WEB_CONFIG="$ROOT_DIR/deploy/supervisor/web.conf"
CELERY_CONFIG="$ROOT_DIR/deploy/supervisor/celery.conf"
OBSERVABILITY_CONFIG="$ROOT_DIR/deploy/supervisor/observability.conf"
WEB_PIDFILE='/tmp/noj_web_supervisord.pid'
WEB_SOCKET='/tmp/noj_web_supervisor.sock'
CELERY_PIDFILE='/tmp/noj_celery_supervisord.pid'
CELERY_SOCKET='/tmp/noj_celery_supervisor.sock'
OBSERVABILITY_PIDFILE='/tmp/noj_observability_supervisord.pid'
OBSERVABILITY_SOCKET='/tmp/noj_observability_supervisor.sock'
WEB_STOP_TIMEOUT_SECONDS=60
CELERY_STOP_TIMEOUT_SECONDS=1960

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
DOCKER_BUILDER="${NUMOJ_DOCKER_BUILDER:-default}"
JUDGER_STABLE='numericaloj-judger:latest'
AGENT_JUDGE_STABLE='numericaloj-agent-judge:latest'
LEAN4_STABLE='numericaloj-lean4:latest'
VIBEHUB_RUNTIME_STABLE='numericaloj-vibehub-runtime:1'
HARBOR_BASE_STABLE='numericaloj-harbor-base:1'
JUDGER_CANDIDATE="numericaloj-judger:deploy-$RUN_ID"
AGENT_JUDGE_CANDIDATE="numericaloj-agent-judge:deploy-$RUN_ID"
LEAN4_CANDIDATE="numericaloj-lean4:deploy-$RUN_ID"
VIBEHUB_RUNTIME_CANDIDATE="numericaloj-vibehub-runtime:deploy-$RUN_ID"
HARBOR_BASE_CANDIDATE="numericaloj-harbor-base:deploy-$RUN_ID"
MANAGED_IMAGE_LABEL='org.numericaloj.deploy-managed=true'
VIBEHUB_MANAGED_IMAGE_LABEL='com.numericaloj.vibehub.image=1'
SOURCE_IMAGE_LABEL='org.numericaloj.source-sha256'
phase='初始化'
database_backup=''
backup_plan="$BACKUP_DIR/plans/$RUN_ID.json"
backup_manifest="$BACKUP_DIR/manifests/$RUN_ID.manifest.json"
restart_started=0
vibehub_runtime_previous_id=''
vibehub_runtime_candidate_id=''
vibehub_runtime_tag_switched=0
harbor_base_previous_id=''
harbor_base_tag_switched=0
vibehub_oci_previous_target=''
vibehub_oci_candidate_release=''
vibehub_oci_candidate_target=''
vibehub_oci_current_switch_attempted=0
sudo_keepalive_pid=''
SUDO_KEEPALIVE_STOP="$STATE_DIR/.sudo-keepalive-$RUN_ID.stop"
CURRENT_VENV_TEMP="$STATE_DIR/.current-venv-$RUN_ID"
CURRENT_EDITOR_TOOLCHAIN_TEMP="$STATE_DIR/.current-editor-toolchain-$RUN_ID"
ARC_CURRENT_SET_TEMP="$ARC_DATA_ROOT/.current-$RUN_ID"
ARC_RESULT_FILE="$ARC_DATA_ROOT/.candidate-$RUN_ID"
HOST_BOOTSTRAP_RESULT="$STATE_DIR/.bootstrap-host-$RUN_ID.json"
SERVICES_BOOTSTRAP_RESULT="$STATE_DIR/.bootstrap-services-$RUN_ID.json"
ADMIN_BOOTSTRAP_RESULT="$STATE_DIR/.bootstrap-admin-$RUN_ID.json"
FIRST_INSTALL=0
backup_preflight_arguments=()
DEPLOY_DOCKER_BUILD_ARGUMENTS=()
DEPLOY_DOWNLOAD_CONTAINER_ARGUMENTS=()
DEPLOY_FULL_IMAGE_BUILD_ARGUMENTS=()
DEVELOPMENT_RESERVE_ELIGIBLE=0
DEFERRED_UNPACK_ENABLED=0
REQUESTED_DEPLOY_MODE=''
HARBOR_RECOVERY_ARGUMENTS=()

usage() {
  printf '%s\n' \
    '用法: bash deploy.sh [--mode full|lite] [--finalize-harbor-task TASK_ID]' \
    '' \
    '请先在当前项目目录完成 git pull，再执行本脚本。' \
    'full 为完整判题环境，lite 使用现有轻量判题镜像；首次默认 full，显式选择后持久保存。' \
    '仅在 Harbor 已完成但封存失败时，可显式指定原任务；停服并备份后恢复原结果，不重新调用模型。' \
    '独立 CPU 测试站可显式设置 NUMOJ_DEPLOY_PROFILE=test-cpu；与 full/lite 独立。'
}

configure_deployment_mode() {
  DEPLOY_MODE="$1"
  case "$DEPLOY_MODE" in
    full)
      JUDGER_CONTEXT='docker/judger'
      AGENT_JUDGE_CONTEXT='docker/agent_judge'
      JUDGER_CACHE_MARKERS=('debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df' 'texlive-full' 'intel-oneapi-mkl-devel')
      AGENT_CACHE_MARKERS=('node:24-bookworm@sha256:be23f54a88d34e8824c741b19b91064094f92c1c97b194144bfc8b50d67258e2' 'texlive-full' 'torch torchvision' 'paddlepaddle paddleocr' 'playwright install chromium')
      ;;
    lite)
      JUDGER_CONTEXT='docker/judger-lite'
      AGENT_JUDGE_CONTEXT='docker/agent_judge-lite'
      JUDGER_CACHE_MARKERS=('gcc g++ make' 'texlive-xetex')
      AGENT_CACHE_MARKERS=('node:24.20.0-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e' 'pi-coding-agent' 'run_harness')
      ;;
    *) printf '未知部署模式：%s；仅支持 full 或 lite。\n' "$DEPLOY_MODE" >&2; return 2 ;;
  esac
}

configure_deployment_profile() {
  DEPLOY_PROFILE="${NUMOJ_DEPLOY_PROFILE:-production}"
  case "$DEPLOY_PROFILE" in
    production)
      VIBEHUB_RUNTIME_GPU=1
      VIBEHUB_RUNTIME_BUILD_ARGS=(--build-context host_cuda=/usr/local/cuda-12.6)
      ;;
    test-cpu)
      VIBEHUB_RUNTIME_GPU=0
      VIBEHUB_RUNTIME_BUILD_ARGS=(--target web-edu)
      ;;
    *)
      printf '未知部署模式：%s；仅支持 production 或 test-cpu。\n' \
        "$DEPLOY_PROFILE" >&2
      return 2
      ;;
  esac
}

bootstrap_apt() {
  # 最小 Python/flock 尚未就绪时，只给 sudo 保留下载所需的标准代理变量。
  export http_proxy="${http_proxy:-${HTTP_PROXY:-}}"
  export https_proxy="${https_proxy:-${HTTPS_PROXY:-}}"
  export no_proxy="${no_proxy:-${NO_PROXY:-localhost,127.0.0.1,::1}}"
  sudo --preserve-env=http_proxy,https_proxy,no_proxy apt-get "$@"
}

clear_download_proxy_environment() {
  # 下载代理仅服务部署供应；业务进程按自己的 .env/服务配置加载代理。
  unset HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy
}

configure_download_container_proxy() {
  local name
  DEPLOY_DOWNLOAD_CONTAINER_ARGUMENTS=()
  if [[ -z "${HTTP_PROXY:-}${HTTPS_PROXY:-}" ]]; then
    return
  fi
  # 回环下载代理在 bridge 中不可达；仅依赖下载容器使用 host 网络。
  DEPLOY_DOWNLOAD_CONTAINER_ARGUMENTS=(--network host)
  for name in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
    if [[ -n "${!name:-}" ]]; then
      DEPLOY_DOWNLOAD_CONTAINER_ARGUMENTS+=(--env "$name")
    fi
  done
}

bootstrap_install_missing() {
  local package candidate policy line simulation
  local targets=()
  local -A new_packages=()
  for package in "$@"; do
    candidate=''
    policy="$(apt-cache policy "$package")" || return 1
    while IFS= read -r line; do
      if [[ "$line" =~ ^[[:space:]]*Candidate:[[:space:]]*([^[:space:]]+) ]]; then
        candidate="${BASH_REMATCH[1]}"
        break
      fi
    done <<<"$policy"
    if [[ -z "$candidate" || "$candidate" == '(none)' ]]; then
      printf 'APT 仓库缺少最小引导依赖：%s\n' "$package" >&2
      return 1
    fi
    targets+=("$package=$candidate")
  done
  simulation="$(bootstrap_apt --simulate --no-install-recommends --no-remove install "${targets[@]}")" || return 1
  while IFS= read -r line; do
    if [[ "$line" =~ ^Inst[[:space:]]+([^[:space:]]+)[[:space:]]+\( ]]; then
      new_packages["${BASH_REMATCH[1]}"]=1
    fi
  done <<<"$simulation"
  while IFS= read -r line; do
    if [[ "$line" == 'Remv '* \
        || "$line" =~ ^Inst[[:space:]]+[^[:space:]]+[[:space:]]+\[ \
        || "$line" =~ ^(Inst|Conf)[[:space:]]+(mysql-server|mysql-community-server|mariadb-server|percona-server)[^[:space:]]*[[:space:]] ]]; then
      printf '最小依赖安装将删除、升级或配置数据库服务，已停止：%s\n' "$line" >&2
      return 1
    fi
    if [[ "$line" =~ ^Conf[[:space:]]+([^[:space:]]+) \
        && -z "${new_packages[${BASH_REMATCH[1]}]:-}" ]]; then
      printf '最小依赖安装将配置已有系统包，已停止：%s\n' "$line" >&2
      return 1
    fi
  done <<<"$simulation"
  bootstrap_apt --yes --no-install-recommends --no-remove install "${targets[@]}"
}

stop_sudo_keepalive() {
  if [[ -n "$sudo_keepalive_pid" ]]; then
    if ! /usr/bin/touch -- "$SUDO_KEEPALIVE_STOP"; then
      printf '无法写入 sudo 保活停止标记：%s\n' \
        "$SUDO_KEEPALIVE_STOP" >&2
      sudo_keepalive_pid=''
      return 0
    fi
    wait "$sudo_keepalive_pid" >/dev/null 2>&1 || true
    sudo_keepalive_pid=''
  fi
  rm -f -- "$SUDO_KEEPALIVE_STOP"
  return 0
}

start_sudo_keepalive() {
  local deployment_pid=$$
  local remaining

  if [[ -n "$sudo_keepalive_pid" ]]; then
    assert_sudo_keepalive '继续部署'
    return
  fi

  rm -f -- "$SUDO_KEEPALIVE_STOP"
  /usr/bin/sudo -v
  (
    while [[ ! -e "$SUDO_KEEPALIVE_STOP" ]] \
        && [[ -d "/proc/$deployment_pid" ]]; do
      /usr/bin/sudo -n -v || exit 1
      for ((remaining = 0; remaining < 30; remaining++)); do
        [[ -e "$SUDO_KEEPALIVE_STOP" ]] && exit 0
        [[ -d "/proc/$deployment_pid" ]] || exit 0
        /usr/bin/sleep 1
      done
    done
  ) 9>&- &
  sudo_keepalive_pid=$!
}

assert_sudo_keepalive() {
  local checkpoint="$1"
  local running_pid
  local running=0
  local wait_status=0

  [[ -n "$sudo_keepalive_pid" ]] || return 0
  while IFS= read -r running_pid; do
    if [[ "$running_pid" == "$sudo_keepalive_pid" ]]; then
      running=1
      break
    fi
  done < <(jobs -pr)
  if [[ "$running" -ne 1 ]]; then
    wait "$sudo_keepalive_pid" >/dev/null 2>&1 || wait_status=$?
    sudo_keepalive_pid=''
    printf 'sudo 保活任务在%s前异常退出（退出码：%s）。\n' \
      "$checkpoint" "$wait_status" >&2
    return 1
  fi
  if ! /usr/bin/sudo -n -v; then
    printf 'sudo 凭据在%s前已失效。\n' "$checkpoint" >&2
    return 1
  fi
}

while (($#)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --mode)
      if (($# < 2)) || [[ -n "$REQUESTED_DEPLOY_MODE" || ( "$2" != full && "$2" != lite ) ]]; then
        printf '%s\n' '--mode 必须且只能指定一次 full 或 lite。' >&2
        exit 2
      fi
      REQUESTED_DEPLOY_MODE="$2"
      shift 2
      ;;
    --finalize-harbor-task)
      if (($# < 2)) || ((${#HARBOR_RECOVERY_ARGUMENTS[@]})) || [[ ! "$2" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$ ]]; then
        printf '%s\n' '--finalize-harbor-task 必须且只能指定一次有效的原任务 ID。' >&2
        exit 2
      fi
      HARBOR_RECOVERY_ARGUMENTS=(--finalize-harbor-task "$2")
      shift 2
      ;;
    *)
      printf '未知参数: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

configure_deployment_profile

cleanup() {
  local exit_code=$?
  trap - EXIT HUP INT TERM
  set +e
  stop_sudo_keepalive || true
  rm -f -- "$CURRENT_VENV_TEMP"
  rm -f -- "$CURRENT_EDITOR_TOOLCHAIN_TEMP"
  rm -f -- "$ARC_CURRENT_SET_TEMP" "$ARC_RESULT_FILE"
  rm -f -- "$HOST_BOOTSTRAP_RESULT" "$SERVICES_BOOTSTRAP_RESULT" "$ADMIN_BOOTSTRAP_RESULT"
  if [[ "$exit_code" -ne 0 && -f "$backup_manifest" \
      && -x "${CANDIDATE_PYTHON:-}" ]]; then
    if ! "$CANDIDATE_PYTHON" -B deploy/backup_database.py mark-failed \
        --manifest "$backup_manifest" --phase "$phase"; then
      printf '警告：无法把部署失败阶段写入备份清单：%s\n' \
        "$backup_manifest" >&2
    fi
  fi
  if [[ "$exit_code" -ne 0 && "$restart_started" -eq 1 \
      && -x "${CANDIDATE_SUPERVISORCTL:-}" ]]; then
    "$CANDIDATE_SUPERVISORCTL" -c "$WEB_CONFIG" shutdown >/dev/null 2>&1 || true
    "$CANDIDATE_SUPERVISORCTL" -c "$CELERY_CONFIG" shutdown >/dev/null 2>&1 || true
  fi
  if [[ "$exit_code" -ne 0 \
      && "$vibehub_oci_current_switch_attempted" -eq 1 \
      && -x "${BOOTSTRAP_PYTHON:-}" ]]; then
    if ! "$BOOTSTRAP_PYTHON" -B deploy/vibehub_base_oci.py restore-current \
        --output-root "$VIBEHUB_BASE_OCI_LAYOUT_ROOT" \
        --candidate-current "$vibehub_oci_candidate_target" \
        --previous-current "$vibehub_oci_previous_target"; then
      printf '警告：无法恢复部署前 VibeHub OCI current 指针。\n' >&2
    fi
  fi
  if [[ "$exit_code" -ne 0 && "$vibehub_runtime_tag_switched" -eq 1 ]]; then
    if [[ -n "$vibehub_runtime_previous_id" ]]; then
      if ! docker tag "$vibehub_runtime_previous_id" "$VIBEHUB_RUNTIME_STABLE"; then
        printf '警告：无法恢复部署前 VibeHub 基础镜像：%s\n' \
          "$vibehub_runtime_previous_id" >&2
      fi
    elif ! docker image rm "$VIBEHUB_RUNTIME_STABLE" >/dev/null 2>&1; then
      printf '警告：无法移除本次部署新建的 VibeHub stable 标签。\n' >&2
    fi
  fi
  if [[ "$exit_code" -ne 0 && "$harbor_base_tag_switched" -eq 1 ]]; then
    if [[ -n "$harbor_base_previous_id" ]]; then
      docker tag "$harbor_base_previous_id" "$HARBOR_BASE_STABLE" || \
        printf '警告：无法恢复部署前 Harbor 基础镜像。\n' >&2
    else
      docker image rm "$HARBOR_BASE_STABLE" >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$exit_code" -eq 0 ]]; then
    docker image rm "$JUDGER_CANDIDATE" "$AGENT_JUDGE_CANDIDATE" \
      "$LEAN4_CANDIDATE" "$HARBOR_BASE_CANDIDATE" >/dev/null 2>&1 || true
  fi
  docker image rm "$VIBEHUB_RUNTIME_CANDIDATE" >/dev/null 2>&1 || true
  if [[ "$exit_code" -ne 0 ]]; then
    printf '部署失败（阶段：%s，退出码：%s）。\n' "$phase" "$exit_code" >&2
    if [[ -n "$database_backup" ]]; then
      printf '已验证的部署前数据库备份清单：%s\n' \
        "$database_backup" >&2
    elif [[ -f "$backup_manifest" ]]; then
      printf '数据库备份失败清单（不可作为回滚点）：%s\n' \
        "$backup_manifest" >&2
    fi
  fi
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

cd "$ROOT_DIR"
ENV_FILE="$ROOT_DIR/.env"
if [[ -e "$ENV_FILE" || -L "$ENV_FILE" ]]; then
  if [[ ! -f "$ENV_FILE" || -L "$ENV_FILE" \
      || "$(stat -c '%u' -- "$ENV_FILE")" != "$(id -u)" ]]; then
    printf '已有 .env 必须是当前部署用户所有的普通文件，不能是符号链接。\n' >&2
    exit 1
  fi
  case "$(stat -c '%a' -- "$ENV_FILE")" in
    400|600) ;;
    *) printf '已有 .env 权限必须是 0400 或 0600。\n' >&2; exit 1 ;;
  esac
fi
[[ ! -L "$STATE_DIR" ]] || {
  printf '部署状态目录不能是符号链接：%s\n' "$STATE_DIR" >&2
  exit 1
}
install -d -m 0700 "$STATE_DIR" "$VENV_ROOT" "$EDITOR_TOOLCHAIN_ROOT"
install -d -m 0700 \
  "$STATIC_PRECOMPRESSION_STATE_DIR" \
  "$FRONTEND_NODE_MODULES_DIR"

if ! command -v flock >/dev/null; then
  bootstrap_apt update
  bootstrap_install_missing util-linux
fi
exec 9>>"$LOCK_FILE"
if ! flock -n 9; then
  printf '本机已有 NumericalOJ 部署正在运行。\n' >&2
  exit 1
fi

phase='首次配置与宿主依赖引导'
if ! command -v python3 >/dev/null; then
  printf '正在供应最小 Python 引导解释器。\n'
  bootstrap_apt update
  bootstrap_install_missing python3
fi
bootstrap_arguments=(host --root "$ROOT_DIR" --result-file "$HOST_BOOTSTRAP_RESULT")
if [[ -n "${NUMOJ_DEPLOY_PROFILE:-}" ]]; then
  bootstrap_arguments+=(--profile "$NUMOJ_DEPLOY_PROFILE")
fi
if [[ -n "$REQUESTED_DEPLOY_MODE" ]]; then
  bootstrap_arguments+=(--mode "$REQUESTED_DEPLOY_MODE")
fi
PYTHONDONTWRITEBYTECODE=1 python3 -B deploy/bootstrap.py "${bootstrap_arguments[@]}"
BOOTSTRAP_PYTHON="$(python3 -B deploy/bootstrap.py value --file "$HOST_BOOTSTRAP_RESULT" --field python)"
NUMOJ_DEPLOY_PROFILE="$(python3 -B deploy/bootstrap.py value --file "$HOST_BOOTSTRAP_RESULT" --field profile)"
DEPLOY_MODE="$(python3 -B deploy/bootstrap.py value --file "$HOST_BOOTSTRAP_RESULT" --field mode)"
export NUMOJ_DEPLOY_PROFILE
configure_deployment_profile
configure_deployment_mode "$DEPLOY_MODE"
printf '本次部署模式：%s（运行配置：%s）。\n' "$DEPLOY_MODE" "$DEPLOY_PROFILE"
if [[ "$(python3 -B deploy/bootstrap.py value --file "$HOST_BOOTSTRAP_RESULT" --field docker_group_reexec)" == 1 ]]; then
  if [[ "${NUMOJ_DEPLOY_GROUP_REEXEC:-0}" == 1 ]]; then
    printf '应用 Docker 组权限后仍不能访问 daemon，停止部署。\n' >&2
    exit 1
  fi
  rm -f -- "$HOST_BOOTSTRAP_RESULT"
  export NUMOJ_DEPLOY_GROUP_REEXEC=1
  printf -v deployment_command '%q ' bash "$ROOT_DIR/deploy.sh"
  flock -u 9
  exec 9>&-
  exec sg docker -c "$deployment_command"
fi
start_sudo_keepalive

phase='准备首次下载代理'
"$BOOTSTRAP_PYTHON" -B deploy/bootstrap_proxy.py prepare --root "$ROOT_DIR" >/dev/null
while IFS= read -r -d '' proxy_setting; do
  export "$proxy_setting"
done < <("$BOOTSTRAP_PYTHON" -B deploy/bootstrap_proxy.py environment --root "$ROOT_DIR")
while IFS= read -r -d '' build_argument; do
  DEPLOY_DOCKER_BUILD_ARGUMENTS+=("$build_argument")
done < <("$BOOTSTRAP_PYTHON" -B deploy/bootstrap_proxy.py arguments --root "$ROOT_DIR")
configure_download_container_proxy

phase='选择 Docker 官方镜像入口'
NUMOJ_DOCKER_LIBRARY_REGISTRY="$("$BOOTSTRAP_PYTHON" -B deploy/docker_registry.py select --root "$ROOT_DIR")"
export NUMOJ_DOCKER_LIBRARY_REGISTRY

for command_name in docker flock git pgrep; do
  command -v "$command_name" >/dev/null || {
    printf '缺少部署命令: %s\n' "$command_name" >&2
    exit 1
  }
done
phase='读取发布版本'
DEPLOY_COMMIT_SHA="$(git rev-parse --verify HEAD)"
if [[ ! "$DEPLOY_COMMIT_SHA" =~ ^[0-9a-f]{40,64}$ ]]; then
  printf '无法读取有效的 Git commit 哈希。\n' >&2
  exit 1
fi
printf '发布版本：%.12s\n' "$DEPLOY_COMMIT_SHA"

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
    version="$("$resolved" --version 2>&1 || true)"
    if [[ "$version" =~ ^Python[[:space:]]+3\.12([.]|$) ]]; then
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

phase='初始化日志目录'
PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B scripts/log_admin.py init >/dev/null

phase='校验生产本地配置'
ENV_FILE="$ROOT_DIR/.env"
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" && -r "$ENV_FILE" ]] || {
  printf '缺少仅当前用户可读的生产配置文件: %s\n' "$ENV_FILE" >&2
  exit 1
}
PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B \
  deploy/preflight.py validate-config "$ENV_FILE"
if [[ "$DEPLOY_PROFILE" == 'production' ]]; then
  phase='准备 NVIDIA CDI 容器接入'
  PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B deploy/prepare_nvidia_cdi.py
else
  printf 'CPU 测试模式：跳过 NVIDIA CDI，VibeHub 仅提供 Web 运行环境。\n'
fi
phase='准备并校验 VibeHub 专属 builder'
VIBEHUB_BUILD_BUILDER="$(
  PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B \
    deploy/preflight.py ensure-vibehub-builder
)"
vibehub_oci_previous_target="$(
  PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B \
    deploy/vibehub_base_oci.py current-target \
      --output-root "$VIBEHUB_BASE_OCI_LAYOUT_ROOT" \
      --allow-missing
)"
if [[ -n "$vibehub_oci_previous_target" ]]; then
  vibehub_runtime_existing_id="$(
    docker image inspect --format '{{.Id}}' "$VIBEHUB_RUNTIME_STABLE"
  )"
  PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B \
    deploy/vibehub_base_oci.py verify-release \
      --release "$VIBEHUB_BASE_OCI_LAYOUT_ROOT/$vibehub_oci_previous_target" \
      --expected-image-ref "$VIBEHUB_RUNTIME_STABLE" \
      --expected-image-id "$vibehub_runtime_existing_id" >/dev/null
fi

phase='准备编辑器语言服务宿主运行时'
PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B \
  deploy/system_packages.py ensure-editor-runtime

remove_stale_candidate_tags() {
  local reference
  local tags
  local tag

  for reference in \
      'numericaloj-judger:deploy-*' \
      'numericaloj-agent-judge:deploy-*' \
      'numericaloj-lean4:deploy-*' \
      'numericaloj-harbor-base:deploy-*' \
      'numericaloj-vibehub-runtime:deploy-*'; do
    tags="$(
      docker image ls \
        --filter "label=$MANAGED_IMAGE_LABEL" \
        --filter "reference=$reference" \
        --format '{{.Repository}}:{{.Tag}}'
    )" || return 1
    while IFS= read -r tag; do
      [[ -n "$tag" ]] || continue
      if [[ "$tag" == "$JUDGER_CANDIDATE" || "$tag" == "$AGENT_JUDGE_CANDIDATE" \
          || "$tag" == "$LEAN4_CANDIDATE" || "$tag" == "$HARBOR_BASE_CANDIDATE" \
          || "$tag" == "$VIBEHUB_RUNTIME_CANDIDATE" ]]; then
        continue
      fi
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
      context='docker'
      inputs=(
        agent_judge/Dockerfile
        agent_judge/run_harness
        agent_judge/pi_web_search_mcp.ts
        agent_judge/lean
        lean4/Dockerfile
        lean4/NumOJVerifier.lean
        lean4/run_lean_judge.sh
        lean4/run_lean_lsp.sh
        lean4/run_lean_problem_build.sh
        lean4/run_lean_workspace_judge.sh
      )
      ;;
    docker/lean4)
      inputs=(
        Dockerfile
        NumOJVerifier.lean
        run_lean_judge.sh
        run_lean_lsp.sh
        run_lean_problem_build.sh
        run_lean_workspace_judge.sh
      )
      ;;
    *)
      printf '没有定义 Docker 构建输入清单：%s\n' "$context" >&2
      return 1
      ;;
  esac

  "$BOOTSTRAP_PYTHON" -B deploy/preflight.py \
    docker-source-digest "$context" "${inputs[@]}"
}

image_source_digest() {
  local image="$1"

  docker image inspect \
    --format "{{if .Config.Labels}}{{index .Config.Labels \"$SOURCE_IMAGE_LABEL\"}}{{end}}" \
    "$image" 2>/dev/null || true
}

prepare_build_dockerfile() {
  local context="$1"
  local name="${context//\//_}"
  PREPARED_DOCKERFILE="$STATE_DIR/dockerfiles/$RUN_ID/$name.Dockerfile"
  "$BOOTSTRAP_PYTHON" -B deploy/docker_registry.py dockerfile \
    --root "$ROOT_DIR" \
    --source "$ROOT_DIR/$context/Dockerfile" \
    --output "$PREPARED_DOCKERFILE" >/dev/null
}

find_matching_managed_candidate() {
  local repository="${1%:*}"
  local expected_source="$2"
  local references reference record image_id managed source_label additional
  local managed_key="${MANAGED_IMAGE_LABEL%%=*}"
  local managed_value="${MANAGED_IMAGE_LABEL#*=}"
  references="$(docker image ls --filter "label=$MANAGED_IMAGE_LABEL" \
    --filter "reference=$repository:deploy-*" --format '{{.Repository}}:{{.Tag}}')" || return 1
  while IFS= read -r reference; do
    [[ "$reference" == "$repository:deploy-"* ]] || continue
    record="$(docker image inspect --format \
      "{{.Id}} {{if .Config.Labels}}{{index .Config.Labels \"$managed_key\"}} {{index .Config.Labels \"$SOURCE_IMAGE_LABEL\"}}{{end}}" \
      "$reference" 2>/dev/null)" || continue
    read -r image_id managed source_label additional <<<"$record"
    if [[ -n "$image_id" && "$managed" == "$managed_value" \
        && "$source_label" == "$expected_source" && -z "$additional" ]]; then
      printf '%s\n' "$image_id"
      return 0
    fi
  done <<<"$references"
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
  local matching_candidate_id
  local missing_cache=0
  local docker_build_args=()
  local dockerfile_args=()
  local build_context="$context"
  local use_source_metadata=1
  local source_label_arguments=()

  if [[ -n "${NUMOJ_DOCKER_LIBRARY_REGISTRY:-}" ]]; then
    prepare_build_dockerfile "$context"
    dockerfile_args=(--file "$PREPARED_DOCKERFILE")
  fi

  if [[ "$context" == 'docker/agent_judge-lite' ]]; then
    build_context='docker'
    if [[ "${#dockerfile_args[@]}" -eq 0 ]]; then
      dockerfile_args=(--file docker/agent_judge-lite/Dockerfile)
    fi
  fi
  if [[ "$context" == 'docker/agent_judge' || "$context" == 'docker/agent_judge-lite' ]]; then
    docker_build_args=(--build-arg "LEAN4_IMAGE=$LEAN4_CANDIDATE")
  fi
  if [[ "$context" == 'docker/harbor-base' ]]; then
    docker_build_args=(--build-arg "AGENT_IMAGE=$AGENT_JUDGE_CANDIDATE")
  fi

  if [[ "$context" == 'docker/judger-lite' || "$context" == 'docker/agent_judge-lite' \
        || "$context" == 'docker/harbor-base' ]]; then
    use_source_metadata=0
  fi
  if [[ "$use_source_metadata" == 1 ]]; then
  stable_id="$(
    docker image inspect --format '{{.Id}}' "$stable" 2>/dev/null || true
  )"
  source_digest="$(docker_source_digest "$context")" || return 1
  source_label_arguments=(--label "$SOURCE_IMAGE_LABEL=$source_digest")
  if [[ -n "$stable_id" ]]; then
    stable_source_digest="$(image_source_digest "$stable")"
    if [[ "$stable_source_digest" == "$source_digest" ]]; then
      printf 'Docker 构建输入未变化，直接复用稳定镜像：%s (%s)\n' \
        "$stable" "$source_digest"
      docker tag "$stable" "$candidate"
      return
    fi
  fi

  matching_candidate_id="$(find_matching_managed_candidate "$stable" "$source_digest")" || return 1
  if [[ -n "$matching_candidate_id" ]]; then
    printf '复用此前已完成且构建输入一致的受管候选镜像：%s -> %s\n' "$matching_candidate_id" "$candidate"
    docker tag "$matching_candidate_id" "$candidate"
    return
  fi

  if [[ -z "$stable_id" ]]; then
    printf '未检测到稳定镜像 %s，正在构建独立候选镜像：%s（模式：%s）。\n' \
      "$stable" "$candidate" "$DEPLOY_PROFILE"
  else
    cache_descriptions="$(
      docker buildx du \
        --builder "$DOCKER_BUILDER" \
        --format '{{.Description}}'
    )" || {
      printf '无法读取 Docker builder %s 的步骤缓存记录，将由构建器复用可用缓存并补齐缺失层。\n' \
        "$DOCKER_BUILDER" >&2
      cache_descriptions=''
      missing_cache=1
    }
    for cache_marker in "${cache_markers[@]}"; do
      if [[ "$cache_descriptions" != *"$cache_marker"* ]]; then
        printf 'Docker builder %s 缺少关键步骤缓存记录：%s；将自动构建缺失层。\n' \
          "$DOCKER_BUILDER" "$cache_marker" >&2
        missing_cache=1
      fi
    done

    if [[ "$missing_cache" == 0 ]]; then
      printf '已检测到 Docker builder %s 的基础镜像及关键步骤缓存记录；构建将逐层确认命中。稳定镜像：%s (%s)\n' \
        "$DOCKER_BUILDER" "$stable" "$stable_id"
    else
      printf '正在保留稳定镜像并构建独立候选镜像：%s；首次供应缺失层可能需要较长时间。\n' "$candidate"
    fi
  fi
  else
    printf '构建候选镜像并复用 Docker 原生层缓存：%s\n' "$candidate"
  fi

  DOCKER_BUILDKIT=1 docker build \
    --builder "$DOCKER_BUILDER" \
    "${DEPLOY_DOCKER_BUILD_ARGUMENTS[@]}" \
    "${DEPLOY_FULL_IMAGE_BUILD_ARGUMENTS[@]}" \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    "${dockerfile_args[@]}" \
    "${docker_build_args[@]}" \
    --label "$MANAGED_IMAGE_LABEL" \
    "${source_label_arguments[@]}" \
    --tag "$candidate" \
    "$build_context"

  if [[ "$use_source_metadata" == 0 ]]; then
    docker image inspect --format '{{.Id}}' "$candidate" >/dev/null
    return
  fi
  candidate_source_digest="$(image_source_digest "$candidate")"
  if [[ "$candidate_source_digest" != "$source_digest" ]]; then
    printf '候选镜像缺少预期的构建输入指纹：%s\n' "$candidate" >&2
    return 1
  fi
}

current_venv_target="$(readlink "$CURRENT_VENV" 2>/dev/null || true)"
if [[ -e "$CURRENT_VENV" && ! -L "$CURRENT_VENV" ]]; then
  printf '%s 必须是部署脚本管理的符号链接。\n' "$CURRENT_VENV" >&2
  exit 1
fi
case "$current_venv_target" in
  '')
    active_slot=''
    candidate_slot='slot-a'
    ;;
  venvs/slot-a|./venvs/slot-a|"$VENV_ROOT/slot-a")
    active_slot='slot-a'
    candidate_slot='slot-b'
    ;;
  venvs/slot-b|./venvs/slot-b|"$VENV_ROOT/slot-b")
    active_slot='slot-b'
    candidate_slot='slot-a'
    ;;
  *)
    printf 'current-venv 指向未知环境，拒绝删除任何 venv：%s\n' \
      "$current_venv_target" >&2
    exit 1
    ;;
esac
current_editor_toolchain_target="$(
  readlink "$CURRENT_EDITOR_TOOLCHAIN" 2>/dev/null || true
)"
if [[ -e "$CURRENT_EDITOR_TOOLCHAIN" \
    && ! -L "$CURRENT_EDITOR_TOOLCHAIN" ]]; then
  printf '%s 必须是部署脚本管理的符号链接。\n' \
    "$CURRENT_EDITOR_TOOLCHAIN" >&2
  exit 1
fi
case "$current_editor_toolchain_target" in
  '')
    ;;
  editor-toolchains/slot-a|./editor-toolchains/slot-a|\
"$EDITOR_TOOLCHAIN_ROOT/slot-a")
    editor_toolchain_active_slot='slot-a'
    ;;
  editor-toolchains/slot-b|./editor-toolchains/slot-b|\
"$EDITOR_TOOLCHAIN_ROOT/slot-b")
    editor_toolchain_active_slot='slot-b'
    ;;
  *)
    printf 'current-editor-toolchain 指向未知槽位，拒绝覆盖：%s\n' \
      "$current_editor_toolchain_target" >&2
    exit 1
    ;;
esac
if [[ -n "${editor_toolchain_active_slot:-}" \
    && "$editor_toolchain_active_slot" != "$active_slot" ]]; then
  printf '%s\n' \
    'current-editor-toolchain 与 current-venv 槽位不一致，拒绝覆盖仍可能在用的头文件。' \
    >&2
  exit 1
fi
CANDIDATE_VENV="$VENV_ROOT/$candidate_slot"
CANDIDATE_EDITOR_TOOLCHAIN="$EDITOR_TOOLCHAIN_ROOT/$candidate_slot"
CANDIDATE_PYTHON="$CANDIDATE_VENV/bin/python3"
CANDIDATE_SUPERVISORD="$CANDIDATE_VENV/bin/supervisord"
CANDIDATE_SUPERVISORCTL="$CANDIDATE_VENV/bin/supervisorctl"

phase='准备 Python 运行环境'
rm -rf -- "$CANDIDATE_VENV"
"$BOOTSTRAP_PYTHON" -m venv "$CANDIDATE_VENV"
"$CANDIDATE_PYTHON" -m pip install \
  --disable-pip-version-check \
  --requirement backend/requirements/production.txt

phase='准备 MySQL 与 Redis 服务'
service_arguments=(ensure --root "$ROOT_DIR")
if [[ "$DEPLOY_PROFILE" == 'test-cpu' || -f "$STATE_DIR/new-local-site.json" ]]; then
  service_arguments+=(--allow-create)
fi
if [[ -n "${NUMOJ_DOCKER_LIBRARY_REGISTRY:-}" ]]; then
  service_arguments+=(
    --mysql-image "${NUMOJ_DOCKER_LIBRARY_REGISTRY%/}/mysql:8.4.4"
    --redis-image "${NUMOJ_DOCKER_LIBRARY_REGISTRY%/}/redis:7.4-alpine"
  )
fi
"$CANDIDATE_PYTHON" -B deploy/bootstrap_services.py "${service_arguments[@]}" >"$SERVICES_BOOTSTRAP_RESULT"
chmod 0600 "$SERVICES_BOOTSTRAP_RESULT"
if [[ "$("$CANDIDATE_PYTHON" -B deploy/bootstrap.py value --file "$SERVICES_BOOTSTRAP_RESULT" --field managed_mysql)" == 1 ]]; then
  backup_preflight_arguments+=(--logical-only)
  if [[ "$DEPLOY_PROFILE" == 'test-cpu' ]]; then
    DEVELOPMENT_RESERVE_ELIGIBLE="$("$CANDIDATE_PYTHON" -B deploy/bootstrap.py development-reserve-eligible --root "$ROOT_DIR")"
    if [[ "$DEVELOPMENT_RESERVE_ELIGIBLE" == 1 ]]; then
      backup_preflight_arguments+=(--development-reserve)
    fi
  fi
else
  "$BOOTSTRAP_PYTHON" -B deploy/bootstrap.py mysql-client --root "$ROOT_DIR"
fi
FIRST_INSTALL="$("$CANDIDATE_PYTHON" -B deploy/bootstrap.py value --file "$SERVICES_BOOTSTRAP_RESULT" --field first_database)"

phase='准备首次管理员与开机启动'
"$CANDIDATE_PYTHON" -B deploy/bootstrap_site.py prepare-admin --root "$ROOT_DIR" --profile "$DEPLOY_PROFILE" >"$ADMIN_BOOTSTRAP_RESULT"
chmod 0600 "$ADMIN_BOOTSTRAP_RESULT"
if [[ "$("$CANDIDATE_PYTHON" -B deploy/bootstrap.py value --file "$ADMIN_BOOTSTRAP_RESULT" --field first_install)" == 1 ]]; then
  FIRST_INSTALL=1
fi
if [[ -f "$STATE_DIR/new-local-site.json" || -f "$STATE_DIR/first-install-pending" ]]; then
  FIRST_INSTALL=1
fi
"$CANDIDATE_PYTHON" -B deploy/bootstrap_site.py install-boot --root "$ROOT_DIR"

phase='构建 VibeHub 受信基础候选镜像'
vibehub_dockerfile_arguments=()
if [[ -n "${NUMOJ_DOCKER_LIBRARY_REGISTRY:-}" ]]; then
  prepare_build_dockerfile docker/vibehub-runtime
  vibehub_dockerfile_arguments=(--file "$PREPARED_DOCKERFILE")
fi
DOCKER_BUILDKIT=1 docker build \
  --provenance=false \
  "${DEPLOY_DOCKER_BUILD_ARGUMENTS[@]}" \
  "${vibehub_dockerfile_arguments[@]}" \
  "${VIBEHUB_RUNTIME_BUILD_ARGS[@]}" \
  --label "$MANAGED_IMAGE_LABEL" \
  --label "com.numericaloj.vibehub.gpu=$VIBEHUB_RUNTIME_GPU" \
  --tag "$VIBEHUB_RUNTIME_CANDIDATE" \
  docker/vibehub-runtime
vibehub_runtime_candidate_id="$(
  docker image inspect --format '{{.Id}}' "$VIBEHUB_RUNTIME_CANDIDATE"
)"
if [[ ! "$vibehub_runtime_candidate_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  printf 'VibeHub 基础候选镜像标识无效：%s\n' \
    "$vibehub_runtime_candidate_id" >&2
  exit 1
fi

phase='导出并核验 VibeHub 受信基础 OCI layout'
vibehub_oci_candidate_release="$(
  PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B \
    deploy/vibehub_base_oci.py export \
      --image "$VIBEHUB_RUNTIME_CANDIDATE" \
      --engine-image-ref "$VIBEHUB_RUNTIME_STABLE" \
      --expected-image-id "$vibehub_runtime_candidate_id" \
      --output-root "$VIBEHUB_BASE_OCI_LAYOUT_ROOT"
)"
if [[ "$vibehub_oci_candidate_release" \
    != "$VIBEHUB_BASE_OCI_LAYOUT_ROOT/releases/${vibehub_runtime_candidate_id#sha256:}" ]]; then
  printf 'VibeHub OCI 候选 release 路径无效：%s\n' \
    "$vibehub_oci_candidate_release" >&2
  exit 1
fi
vibehub_oci_candidate_target="releases/${vibehub_runtime_candidate_id#sha256:}"
PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B \
  deploy/vibehub_base_oci.py verify-release \
    --release "$vibehub_oci_candidate_release" \
    --expected-image-ref "$VIBEHUB_RUNTIME_STABLE" \
    --expected-image-id "$vibehub_runtime_candidate_id" >/dev/null

phase='准备 ARC-AGI-3 公开游戏'
"$CANDIDATE_PYTHON" -B deploy/prepare_arc_agi_3.py \
  --data-root "$ARC_DATA_ROOT" \
  --result-file "$ARC_RESULT_FILE" \
  --expected-count 25
arc_candidate_target="$(tr -d '\r\n' <"$ARC_RESULT_FILE")"
if [[ ! "$arc_candidate_target" =~ ^sets/[0-9a-f]{64}$ ]]; then
  printf 'ARC-AGI-3 候选缓存标识无效：%s\n' \
    "$arc_candidate_target" >&2
  exit 1
fi

phase='构建判题镜像'
if [[ "$DEPLOY_MODE" == full && "$DEVELOPMENT_RESERVE_ELIGIBLE" == 1 ]]; then
  DEFERRED_UNPACK_ENABLED="$("$CANDIDATE_PYTHON" -B deploy/deferred_unpack.py --root "$ROOT_DIR" --builder "$DOCKER_BUILDER")"
  if [[ "$DEFERRED_UNPACK_ENABLED" == 1 ]]; then
    DEPLOY_FULL_IMAGE_BUILD_ARGUMENTS=(--output type=image,unpack=false)
    printf '开发判题镜像延迟解包；完整候选准备后、首次运行前核验并回收可用的项目构建缓存。\n'
  fi
fi
build_candidate_image \
  "$JUDGER_STABLE" "$JUDGER_CANDIDATE" "$JUDGER_CONTEXT" \
  "${JUDGER_CACHE_MARKERS[@]}"
build_candidate_image \
  "$LEAN4_STABLE" "$LEAN4_CANDIDATE" docker/lean4 \
  'debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241' \
  'elan-init.sh' 'lake exe cache get'
build_candidate_image \
  "$AGENT_JUDGE_STABLE" "$AGENT_JUDGE_CANDIDATE" "$AGENT_JUDGE_CONTEXT" \
  "${AGENT_CACHE_MARKERS[@]}"
if [[ "$DEFERRED_UNPACK_ENABLED" == 1 ]]; then
  phase='回收开发候选构建缓存'
  "$CANDIDATE_PYTHON" -B deploy/project_build_cache.py \
    --root "$ROOT_DIR" --builder "$DOCKER_BUILDER" \
    --candidate "$JUDGER_CANDIDATE" --candidate "$LEAN4_CANDIDATE" \
    --candidate "$AGENT_JUDGE_CANDIDATE"
fi

if [[ "$DEPLOY_MODE" == lite ]]; then
  docker tag "$AGENT_JUDGE_CANDIDATE" "$HARBOR_BASE_CANDIDATE"
else
  # 完整 Agent 的依赖直接继承；低磁盘开发环境须先回收缓存再解包父镜像。
  build_candidate_image \
    "$HARBOR_BASE_STABLE" "$HARBOR_BASE_CANDIDATE" docker/harbor-base
fi

phase='清理遗留候选镜像'
remove_stale_candidate_tags

phase='构建 React 前端'
docker run --rm \
  "${DEPLOY_DOWNLOAD_CONTAINER_ARGUMENTS[@]}" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --workdir /workspace \
  --env HOME=/tmp/numoj-frontend \
  --env npm_config_cache=/tmp/numoj-npm-cache \
  --env npm_config_registry=https://registry.npmmirror.com \
  --env VITE_NUMOJ_COMMIT_SHA="$DEPLOY_COMMIT_SHA" \
  --mount "type=bind,src=$ROOT_DIR/frontend,dst=/workspace" \
  --mount "type=bind,src=$FRONTEND_NODE_MODULES_DIR,dst=/workspace/node_modules" \
  --entrypoint /bin/sh \
  "$AGENT_JUDGE_CANDIDATE" \
  -c 'npm ci --no-audit --no-fund && npm run build'

phase='生成预压缩静态资源'
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --workdir /workspace/frontend \
  --env NUMOJ_STATIC_ROOT=public/static \
  --env NUMOJ_PRECOMPRESS_MANIFEST=/workspace/.precompress-state/legacy-manifest.json \
  --mount "type=bind,src=$ROOT_DIR/frontend,dst=/workspace/frontend" \
  --mount "type=bind,src=$STATIC_PRECOMPRESSION_STATE_DIR,dst=/workspace/.precompress-state" \
  --entrypoint node \
  "$AGENT_JUDGE_CANDIDATE" \
  scripts/precompress_static.mjs

docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --workdir /workspace/frontend \
  --env NUMOJ_STATIC_ROOT=dist/assets \
  --env NUMOJ_PRECOMPRESS_MANIFEST=/workspace/.precompress-state/spa-manifest.json \
  --mount "type=bind,src=$ROOT_DIR/frontend,dst=/workspace/frontend" \
  --mount "type=bind,src=$STATIC_PRECOMPRESSION_STATE_DIR,dst=/workspace/.precompress-state" \
  --entrypoint node \
  "$AGENT_JUDGE_CANDIDATE" \
  scripts/precompress_static.mjs

phase='准备判题器官方头文件工具链'
"$CANDIDATE_PYTHON" -B deploy/prepare_editor_toolchain.py \
  --image "$JUDGER_CANDIDATE" \
  --mode "$DEPLOY_MODE" \
  --output "$CANDIDATE_EDITOR_TOOLCHAIN"

phase='核验编辑器语言服务'
NUMOJ_EDITOR_TOOLCHAIN_ROOT="$CANDIDATE_EDITOR_TOOLCHAIN" \
  PYTHONDONTWRITEBYTECODE=1 "$CANDIDATE_PYTHON" -B \
  deploy/verify_editor_runtime.py

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

assert_service_stopped() {
  local label="$1"
  local kind="$2"
  local unmanaged

  unmanaged="$(unmanaged_processes "$kind")"
  if [[ -n "$unmanaged" ]]; then
    printf '%s 停止后仍有相关进程：%s\n' "$label" "$unmanaged" >&2
    return 1
  fi
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

  if [[ "$pid" == 'LEGACY' ]]; then
    printf '正在停止旧版 %s 服务（Supervisor PID %s）...\n' \
      "$label" "$legacy_pids"
    "$CANDIDATE_PYTHON" deploy/legacy_supervisor.py \
      --root "$ROOT_DIR" stop \
      --service "$kind" \
      --expected-pids "$legacy_pids" \
      --timeout "$timeout"
    rm -f -- "$pidfile" "$socket"
  elif [[ "$pid" == 'ABSENT' ]]; then
    rm -f -- "$pidfile" "$socket"
    printf '%s 服务未运行，跳过停止。\n' "$label"
  elif ! kill -0 "$pid" 2>/dev/null; then
    rm -f -- "$pidfile" "$socket"
    printf '%s 服务已退出，跳过停止。\n' "$label"
  else
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
  fi
  assert_service_stopped "$label" "$kind"
}

stop_observability_best_effort() {
  local pid
  local deadline
  pid="$(supervisor_pid "$OBSERVABILITY_CONFIG" || true)"
  if [[ -z "$pid" ]]; then
    if [[ -r "$OBSERVABILITY_PIDFILE" ]]; then
      pid="$(tr -d '[:space:]' <"$OBSERVABILITY_PIDFILE")"
      if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null; then
        printf '警告：日志采集 Supervisor PID %s 存活但不可管理，本次保留旧采集器。\n' \
          "$pid" >&2
        return 0
      fi
    fi
    rm -f -- "$OBSERVABILITY_PIDFILE" "$OBSERVABILITY_SOCKET"
    return 0
  fi

  if ! "$CANDIDATE_SUPERVISORCTL" -c "$OBSERVABILITY_CONFIG" shutdown >/dev/null; then
    printf '警告：日志采集 Supervisor 无法停止，本次保留旧采集器。\n' >&2
    return 0
  fi
  deadline=$((SECONDS + 30))
  while kill -0 "$pid" 2>/dev/null; do
    if ((SECONDS >= deadline)); then
      printf '警告：日志采集 Supervisor 未按时退出，本次保留现场。\n' >&2
      return 0
    fi
    sleep 1
  done
  rm -f -- "$OBSERVABILITY_PIDFILE" "$OBSERVABILITY_SOCKET"
}

phase='准备数据库备份计划'
"$CANDIDATE_PYTHON" -B deploy/backup_database.py preflight \
  --plan "$backup_plan" \
  --backup-root "$BACKUP_DIR" \
  --run-id "$RUN_ID" \
  "${backup_preflight_arguments[@]}"
backup_strategy="$("$CANDIDATE_PYTHON" -B deploy/backup_database.py strategy \
  --plan "$backup_plan")"
case "$backup_strategy" in
  physical)
    start_sudo_keepalive
    ;;
  logical)
    ;;
  *)
    printf '数据库备份计划返回未知策略：%s\n' "$backup_strategy" >&2
    exit 1
    ;;
esac

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
assert_sudo_keepalive '停止 Celery'
stop_supervisor \
  'Celery' celery "$CELERY_CONFIG" "$CELERY_PIDFILE" "$CELERY_SOCKET" \
  "$CELERY_STOP_TIMEOUT_SECONDS" "$celery_supervisor_pid" "$legacy_celery_pids"
assert_sudo_keepalive 'Celery 停止完成'
stop_supervisor \
  'Web' web "$WEB_CONFIG" "$WEB_PIDFILE" "$WEB_SOCKET" \
  "$WEB_STOP_TIMEOUT_SECONDS" "$web_supervisor_pid" "$legacy_web_pids"
stop_observability_best_effort
assert_service_stopped 'Celery' celery
assert_service_stopped 'Web' web

phase='创建并验证数据库回滚点'
assert_sudo_keepalive '数据库备份'
"$CANDIDATE_PYTHON" -B deploy/backup_database.py backup \
  --plan "$backup_plan" \
  --manifest "$backup_manifest"
database_backup="$backup_manifest"

clear_download_proxy_environment

phase='切换 VibeHub 受信基础镜像'
vibehub_runtime_previous_id="$(
  docker image inspect --format '{{.Id}}' \
    "$VIBEHUB_RUNTIME_STABLE" 2>/dev/null || true
)"
docker tag "$VIBEHUB_RUNTIME_CANDIDATE" "$VIBEHUB_RUNTIME_STABLE"
vibehub_runtime_tag_switched=1
if [[ "$(docker image inspect --format '{{.Id}}' "$VIBEHUB_RUNTIME_STABLE")" \
    != "$vibehub_runtime_candidate_id" ]]; then
  printf 'VibeHub stable 标签未指向本次候选镜像。\n' >&2
  exit 1
fi
vibehub_oci_current_switch_attempted=1
vibehub_oci_switched_target="$(
  PYTHONDONTWRITEBYTECODE=1 "$BOOTSTRAP_PYTHON" -B \
    deploy/vibehub_base_oci.py switch-current \
      --output-root "$VIBEHUB_BASE_OCI_LAYOUT_ROOT" \
      --release "$vibehub_oci_candidate_release" \
      --expected-current "$vibehub_oci_previous_target"
)"
if [[ "$vibehub_oci_switched_target" != "$vibehub_oci_candidate_target" ]]; then
  printf 'VibeHub OCI current 未指向本次候选 release。\n' >&2
  exit 1
fi

phase='切换运行环境并更新数据库结构'
assert_service_stopped 'Celery' celery
assert_service_stopped 'Web' web
rm -f -- "$CURRENT_VENV_TEMP"
ln -s "venvs/$candidate_slot" "$CURRENT_VENV_TEMP"
mv -Tf -- "$CURRENT_VENV_TEMP" "$CURRENT_VENV"
rm -f -- "$CURRENT_EDITOR_TOOLCHAIN_TEMP"
ln -s "editor-toolchains/$candidate_slot" "$CURRENT_EDITOR_TOOLCHAIN_TEMP"
mv -Tf -- "$CURRENT_EDITOR_TOOLCHAIN_TEMP" "$CURRENT_EDITOR_TOOLCHAIN"
rm -f -- "$ARC_CURRENT_SET_TEMP"
ln -s "$arc_candidate_target" "$ARC_CURRENT_SET_TEMP"
mv -Tf -- "$ARC_CURRENT_SET_TEMP" "$ARC_CURRENT_SET"
rm -f -- "$ARC_RESULT_FILE"

"$CANDIDATE_PYTHON" scripts/init_db_schema.py
"$CANDIDATE_PYTHON" -B deploy/bootstrap_site.py initialize-admin --root "$ROOT_DIR"
"$CANDIDATE_PYTHON" -B deploy/bootstrap_services.py mark-database-initialized --root "$ROOT_DIR"

phase='种入 VibeHub 示例作品'
"$CANDIDATE_PYTHON" -B deploy/seed_vibehub_examples.py \
  --repository-root "$ROOT_DIR" \
  --upload-root "$ROOT_DIR/uploads/vibehub" \
  --arc-set "$ARC_CURRENT_SET"

phase='维护代码仓库存储'
"$CANDIDATE_PYTHON" scripts/repository_storage_admin.py \
  cleanup-expired-uploads --apply --confirm-expired-staging-delete
"$CANDIDATE_PYTHON" scripts/repository_storage_admin.py \
  quarantine-orphan-snapshots --apply --confirm-app-writers-stopped
"$CANDIDATE_PYTHON" scripts/repository_storage_admin.py doctor
"$CANDIDATE_PYTHON" scripts/recover_pending_tasks.py --confirm-celery-stopped
if ((${#HARBOR_RECOVERY_ARGUMENTS[@]})); then
  "$CANDIDATE_PYTHON" scripts/recover_pending_tasks.py --confirm-celery-stopped "${HARBOR_RECOVERY_ARGUMENTS[@]}"
fi

phase='切换判题镜像'
docker tag "$JUDGER_CANDIDATE" "$JUDGER_STABLE"
docker tag "$AGENT_JUDGE_CANDIDATE" "$AGENT_JUDGE_STABLE"
harbor_base_previous_id="$(docker image inspect --format '{{.Id}}' "$HARBOR_BASE_STABLE" 2>/dev/null || true)"
docker tag "$HARBOR_BASE_CANDIDATE" "$HARBOR_BASE_STABLE"
harbor_base_tag_switched=1
docker tag "$LEAN4_CANDIDATE" "$LEAN4_STABLE"

wait_for_programs() {
  local config="$1"
  local attempts="$2"
  shift 2
  local expected_names=("$@")
  local status=''
  local supervisorctl_status=0
  local name
  local state
  local ignored
  local expected_name
  local seen_name
  local name_expected
  local duplicate
  local valid
  local seen_names=()

  while ((attempts > 0)); do
    supervisorctl_status=0
    if status="$(
      "$CANDIDATE_SUPERVISORCTL" -c "$config" status 2>/dev/null
    )"; then
      supervisorctl_status=0
    else
      supervisorctl_status=$?
    fi
    if [[ "$supervisorctl_status" -eq 0 ]]; then
      valid=1
      seen_names=()
      while read -r name state ignored; do
        [[ -n "$name" ]] || continue
        name_expected=0
        for expected_name in "${expected_names[@]}"; do
          if [[ "$name" == "$expected_name" ]]; then
            name_expected=1
            break
          fi
        done
        duplicate=0
        for seen_name in "${seen_names[@]}"; do
          if [[ "$name" == "$seen_name" ]]; then
            duplicate=1
            break
          fi
        done
        if [[ "$name_expected" -ne 1 || "$duplicate" -eq 1 \
            || "$state" != 'RUNNING' ]]; then
          valid=0
          break
        fi
        seen_names+=("$name")
      done <<<"$status"
      if [[ "$valid" -eq 1 \
          && "${#seen_names[@]}" -eq "${#expected_names[@]}" ]]; then
        return 0
      fi
    fi
    sleep 1
    attempts=$((attempts - 1))
  done

  printf '服务未在预期时间内以完整拓扑进入 RUNNING（supervisorctl=%s）：\n%s\n' \
    "$supervisorctl_status" "$status" >&2
  return 1
}

restart_started=1
phase='启动统一日志采集'
if "$CANDIDATE_SUPERVISORD" -c "$OBSERVABILITY_CONFIG" 9>&-; then
  if ! wait_for_programs "$OBSERVABILITY_CONFIG" 15 log_collector; then
    printf '警告：统一日志采集器未稳定运行；业务服务继续启动，请运行日志 doctor 检查。\n' >&2
  fi
else
  printf '警告：统一日志采集 Supervisor 启动失败；业务服务继续启动。\n' >&2
fi

phase='启动 Celery 服务'
"$CANDIDATE_SUPERVISORD" -c "$CELERY_CONFIG" 9>&-
wait_for_programs "$CELERY_CONFIG" 120 \
  celery:celery_judge celery:celery_agent

phase='启动 Web 服务'
"$CANDIDATE_SUPERVISORD" -c "$WEB_CONFIG" 9>&-
wait_for_programs "$WEB_CONFIG" 120 web

phase='确认全部服务状态'
wait_for_programs "$CELERY_CONFIG" 120 \
  celery:celery_judge celery:celery_agent
wait_for_programs "$WEB_CONFIG" 120 web

phase='确认数据库回滚点状态'
"$CANDIDATE_PYTHON" -B deploy/backup_database.py mark-success \
  --manifest "$backup_manifest" \
  --plan "$backup_plan"
rm -f -- "$STATE_DIR/new-local-site.json" "$STATE_DIR/first-install-pending"
restart_started=0

vibehub_oci_prune_args=(
  --output-root "$VIBEHUB_BASE_OCI_LAYOUT_ROOT"
)
if [[ -n "$vibehub_oci_previous_target" ]]; then
  vibehub_oci_prune_args+=(--keep-target "$vibehub_oci_previous_target")
fi
if ! "$CANDIDATE_PYTHON" -B deploy/vibehub_base_oci.py prune-releases \
    "${vibehub_oci_prune_args[@]}" >/dev/null; then
  printf '警告：旧 VibeHub 基础 OCI release 清理失败，已保留供人工检查。\n' >&2
fi
if ! "$CANDIDATE_PYTHON" -B deploy/backup_database.py prune \
    --backup-root "$BACKUP_DIR" \
    --keep-success 2 \
    --protect-run-id "$RUN_ID"; then
  printf '警告：历史数据库备份清理失败，请根据 manifest 人工检查。\n' >&2
fi
stop_sudo_keepalive

phase='清理旧受管镜像'
if ! docker image prune --force --filter "label=$MANAGED_IMAGE_LABEL" >/dev/null; then
  printf '警告：旧的 NumericalOJ dangling 镜像清理失败，请稍后人工检查。\n' >&2
fi
if ! docker image prune --force \
    --filter "label=$VIBEHUB_MANAGED_IMAGE_LABEL" >/dev/null; then
  printf '警告：旧的 VibeHub dangling 镜像清理失败，请稍后人工检查。\n' >&2
fi

phase='完成'
printf 'NumericalOJ 部署完成。数据库备份清单：%s\n' "$database_backup"
