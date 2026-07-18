#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_HOST="${NUMOJ_DEPLOY_HOST:-why-server}"
REMOTE_ROOT='/home/ebola/oj'
REMOTE_STATE='/home/ebola/.numericaloj-deploy'
REBUILD_ALL=0
REMOTE_STAGING_CREATED=0
STAGING=''
MIN_TARGET_FREE_BYTES="${NUMOJ_DEPLOY_MIN_TARGET_FREE_BYTES:-10737418240}"
MIN_STATE_FREE_BYTES="${NUMOJ_DEPLOY_MIN_STATE_FREE_BYTES:-10737418240}"
MIN_DOCKER_FREE_BYTES="${NUMOJ_DEPLOY_MIN_DOCKER_FREE_BYTES:-21474836480}"

usage() {
  printf '%s\n' \
    '用法: bash deploy.sh [--rebuild-all]' \
    '' \
    '默认只在对应 Docker context 变化或远端镜像缺失时重建。' \
    '--rebuild-all  强制重建普通判题和 Agent-as-Judge 两个生产镜像。' \
    '' \
    '磁盘余量可通过 NUMOJ_DEPLOY_MIN_TARGET_FREE_BYTES、' \
    'NUMOJ_DEPLOY_MIN_STATE_FREE_BYTES、NUMOJ_DEPLOY_MIN_DOCKER_FREE_BYTES 调整。'
}

while (($#)); do
  case "$1" in
    --rebuild-all)
      REBUILD_ALL=1
      ;;
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
  shift
done

phase='本地预检'
on_error() {
  local exit_code="${1:-$?}"
  trap - ERR HUP INT TERM
  set +e
  if [[ "$REMOTE_STAGING_CREATED" -eq 1 && -n "$STAGING" ]]; then
    ssh "$REMOTE_HOST" bash -s -- "$REMOTE_STATE" "$STAGING" <<'CLEAN_FAILED_STAGING'
set -Eeuo pipefail
state="$1"
staging="$2"
[[ "$staging" == "$state/staging/"* && "$staging" != "$state/staging/" ]]
rm -f -- "$staging/config.py" "$staging/.env"
[[ ! -d "$staging" ]] || find "$staging" -depth -delete
CLEAN_FAILED_STAGING
  fi
  printf '部署失败（阶段：%s，退出码：%s）。\n' "$phase" "$exit_code" >&2
  exit "$exit_code"
}
trap 'on_error $?' ERR
trap 'on_error 130' HUP INT TERM

cd "$ROOT_DIR"

for threshold in "$MIN_TARGET_FREE_BYTES" "$MIN_STATE_FREE_BYTES" \
    "$MIN_DOCKER_FREE_BYTES"; do
  [[ "$threshold" =~ ^[0-9]+$ ]] || {
    printf '部署磁盘余量阈值必须是非负十进制整数：%s\n' "$threshold" >&2
    exit 1
  }
done

for command_name in date git hostname mkdir mktemp python3 rm rsync ssh tar; do
  command -v "$command_name" >/dev/null || {
    printf '缺少本地命令: %s\n' "$command_name" >&2
    exit 1
  }
done

if [[ "$(hostname -s 2>/dev/null || hostname)" == 'computing' ]]; then
  printf '拒绝在生产主机 computing 上从工作树发起部署。\n' >&2
  exit 1
fi

# 只允许仓库约定的生产 alias；远端仍会二次验证 hostname、用户和固定路径。
case "$REMOTE_HOST" in
  why-server|ebola@why-server) ;;
  *)
    printf '部署主机不在白名单中: %s\n' "$REMOTE_HOST" >&2
    exit 1
    ;;
esac

if [[ -n "$(git status --porcelain)" ]]; then
  printf '工作树不干净；请先提交或清理全部改动。\n' >&2
  exit 1
fi

REVISION="$(git rev-parse HEAD)"
if [[ ! "$REVISION" =~ ^[0-9a-f]{40}$ ]]; then
  printf '无法取得完整 Git commit。\n' >&2
  exit 1
fi

phase='远端预检'
ssh "$REMOTE_HOST" bash -s -- "$REMOTE_ROOT" "$REMOTE_STATE" <<'REMOTE_PREFLIGHT'
set -Eeuo pipefail
root="$1"
state="$2"
[[ "$(hostname -s)" == 'computing' ]] || {
  printf '远端 hostname 不是 computing。\n' >&2
  exit 1
}
[[ "$(id -un)" == 'ebola' ]] || {
  printf '远端部署用户必须是 ebola。\n' >&2
  exit 1
}
[[ "$root" == '/home/ebola/oj' && "$(realpath "$root")" == '/home/ebola/oj' ]] || {
  printf '远端目录不是 /home/ebola/oj。\n' >&2
  exit 1
}
[[ -f "$root/config.py" ]] || {
  printf '远端生产 config.py 不存在。\n' >&2
  exit 1
}
for command_name in awk bash cat cp curl docker find flock git grep gzip \
    hostname id install ln mkdir mysqldump mv python3 readlink realpath rm rsync \
    seq sleep sort supervisord supervisorctl tar tee tr; do
  command -v "$command_name" >/dev/null || {
    printf '远端缺少命令: %s\n' "$command_name" >&2
    exit 1
  }
done
install -d -m 0700 "$state"
[[ "$state" == '/home/ebola/.numericaloj-deploy' \
    && "$(realpath "$state")" == "$state" && -w "$state" ]] || {
  printf '远端部署状态目录不安全或不可写。\n' >&2
  exit 1
}
python3 -c 'import sys; assert sys.version_info[:2] == (3, 12), sys.version'
python3 -m venv --help >/dev/null
docker info >/dev/null
REMOTE_PREFLIGHT

PREVIOUS_REVISION="$(ssh "$REMOTE_HOST" bash -s <<'READ_STATE'
set -Eeuo pipefail
state='/home/ebola/.numericaloj-deploy'
if [[ -L "$state/current" && -f "$state/current/revision" ]]; then
  cat "$state/current/revision"
elif [[ -f "$state/current_commit" ]]; then
  cat "$state/current_commit"
fi
READ_STATE
)"
EXPECTED_PREVIOUS_REVISION='NONE'
if [[ "$PREVIOUS_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
  EXPECTED_PREVIOUS_REVISION="$PREVIOUS_REVISION"
fi
BUILD_JUDGER=$REBUILD_ALL
BUILD_AGENT_JUDGE=$REBUILD_ALL

if [[ "$REBUILD_ALL" -eq 0 ]]; then
  if [[ "$PREVIOUS_REVISION" =~ ^[0-9a-f]{40}$ ]] \
      && git cat-file -e "$PREVIOUS_REVISION^{commit}" 2>/dev/null; then
    git diff --quiet "$PREVIOUS_REVISION" "$REVISION" -- docker/judger \
      || BUILD_JUDGER=1
    git diff --quiet "$PREVIOUS_REVISION" "$REVISION" -- docker/agent_judge \
      || BUILD_AGENT_JUDGE=1
  else
    BUILD_JUDGER=1
    BUILD_AGENT_JUDGE=1
  fi
fi

TEMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT
TEMP_TOKEN="${TEMP_DIR##*/}"
TEMP_TOKEN="${TEMP_TOKEN##*.}"
[[ "$TEMP_TOKEN" =~ ^[A-Za-z0-9]+$ ]] || {
  printf 'mktemp 返回了不可用的随机标识：%q\n' "$TEMP_TOKEN" >&2
  exit 1
}
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-$TEMP_TOKEN"
STAGING="$REMOTE_STATE/staging/$REVISION-$RUN_ID"

ARTIFACT_ROOT="$TEMP_DIR/release"
MANIFEST="$TEMP_DIR/manifest.txt"
TREE_FILES="$TEMP_DIR/tree-files.bin"
TRACKED_FILES="$TEMP_DIR/tracked-files.bin"
STATIC_FILES="$TEMP_DIR/static-files.bin"
STATIC_CHANGED_FILES="$TEMP_DIR/static-changed-files.bin"
mkdir -p "$ARTIFACT_ROOT"

# 从 commit 对象生成工件，避免 clean check 后工作树被并发改写而发布出一个不存在的版本。
git archive --format=tar "$REVISION" | tar -xf - -C "$ARTIFACT_ROOT"
git ls-tree -rz --name-only "$REVISION" >"$TREE_FILES"
python3 "$ARTIFACT_ROOT/deploy/manifest.py" \
  --input "$TREE_FILES" \
  --excludes "$ARTIFACT_ROOT/deploy/rsync-excludes.txt" \
  --manifest "$MANIFEST" \
  --nul-output "$TRACKED_FILES"

if [[ "$PREVIOUS_REVISION" =~ ^[0-9a-f]{40}$ ]] \
    && git cat-file -e "$PREVIOUS_REVISION^{commit}" 2>/dev/null; then
  git diff --name-only -z --diff-filter=ACMR "$PREVIOUS_REVISION" "$REVISION" -- static \
    >"$STATIC_CHANGED_FILES"
else
  git ls-tree -rz --name-only "$REVISION" -- static >"$STATIC_CHANGED_FILES"
fi
# 每次都核对当前提交的完整 static 集合：既能补回生产误删文件，也能发现历史漂移。
git ls-tree -rz --name-only "$REVISION" -- static >"$STATIC_FILES"

phase='同步候选版本'
ssh "$REMOTE_HOST" bash -s -- "$REMOTE_STATE" "$STAGING" <<'CREATE_STAGING'
set -Eeuo pipefail
state="$1"
staging="$2"
install -d -m 0700 "$state" "$state/staging"
[[ ! -e "$staging" && ! -L "$staging" ]] || {
  printf '候选 staging 已存在，拒绝复用：%s\n' "$staging" >&2
  exit 1
}
install -d -m 0700 "$staging" "$staging/.static-payload"
CREATE_STAGING
REMOTE_STAGING_CREATED=1
rsync -az --delete \
  --exclude-from="$ARTIFACT_ROOT/deploy/rsync-excludes.txt" \
  --from0 --files-from="$TRACKED_FILES" \
  "$ARTIFACT_ROOT/" "$REMOTE_HOST:$STAGING/"
rsync -az --from0 --files-from="$STATIC_FILES" \
  "$ARTIFACT_ROOT/" "$REMOTE_HOST:$STAGING/.static-payload/"
rsync -az "$MANIFEST" "$REMOTE_HOST:$STAGING/.deploy-manifest"
rsync -az "$STATIC_CHANGED_FILES" "$REMOTE_HOST:$STAGING/.static-changed-files.bin"
ssh "$REMOTE_HOST" bash -s -- "$REMOTE_ROOT" "$STAGING" <<'COPY_PRODUCTION_CONFIG'
set -Eeuo pipefail
root="$1"
staging="$2"
install -m 0600 "$root/config.py" "$staging/config.py"
if [[ -f "$root/.env" ]]; then
  install -m 0600 "$root/.env" "$staging/.env"
elif [[ -e "$root/.env" || -L "$root/.env" ]]; then
  printf '生产 .env 存在但不是普通文件。\n' >&2
  exit 1
fi
COPY_PRODUCTION_CONFIG

phase='远端部署状态机'
# 自此远端状态机独占 staging；即使 SSH 传输中断，本地也不能与其回滚并发删除。
REMOTE_STAGING_CREATED=0
ssh "$REMOTE_HOST" bash "$STAGING/deploy/remote.sh" \
  --staging "$STAGING" \
  --target "$REMOTE_ROOT" \
  --state "$REMOTE_STATE" \
  --revision "$REVISION" \
  --expected-previous-revision "$EXPECTED_PREVIOUS_REVISION" \
  --run-id "$RUN_ID" \
  --build-judger "$BUILD_JUDGER" \
  --build-agent-judge "$BUILD_AGENT_JUDGE" \
  --min-target-free-bytes "$MIN_TARGET_FREE_BYTES" \
  --min-state-free-bytes "$MIN_STATE_FREE_BYTES" \
  --min-docker-free-bytes "$MIN_DOCKER_FREE_BYTES"

phase='完成'
printf 'NumericalOJ 部署完成：%s -> %s:%s\n' "$REVISION" "$REMOTE_HOST" "$REMOTE_ROOT"
