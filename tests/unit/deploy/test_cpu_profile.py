"""两种部署配置均可自动供应完整候选镜像，并复用已有稳定镜像和缓存。"""

from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (ROOT / "deploy.sh").read_text(encoding="utf-8")


def _function(name):
    start = SCRIPT.index(f"{name}() {{")
    return SCRIPT[start:SCRIPT.index("\n}\n", start) + 3]


def _bash(source, *arguments):
    return subprocess.run(["bash", "-c", source, "cpu-profile-test", *arguments], capture_output=True, text=True)


def test_production_is_default_and_unknown_profile_fails_closed():
    definition = _function("configure_deployment_profile")
    result = _bash(definition + '\nunset NUMOJ_DEPLOY_PROFILE\nconfigure_deployment_profile\nprintf "%s\\n" "$DEPLOY_PROFILE" "$VIBEHUB_RUNTIME_GPU" "${VIBEHUB_RUNTIME_BUILD_ARGS[@]}"')
    assert result.returncode == 0
    assert result.stdout.splitlines() == ["production", "1", "--build-context", "host_cuda=/usr/local/cuda-12.6"]
    result = _bash(definition + '\nNUMOJ_DEPLOY_PROFILE=unknown\nconfigure_deployment_profile')
    assert result.returncode == 2
    assert "未知部署模式" in result.stderr


def test_cpu_profile_uses_web_target_without_host_cuda_or_nvidia_cdi():
    definition = _function("configure_deployment_profile")
    result = _bash(definition + '\nNUMOJ_DEPLOY_PROFILE=test-cpu\nconfigure_deployment_profile\nprintf "%s\\n" "$VIBEHUB_RUNTIME_GPU" "${VIBEHUB_RUNTIME_BUILD_ARGS[@]}"')
    assert result.returncode == 0
    assert result.stdout.splitlines() == ["0", "--target", "web-edu"]
    block_start = SCRIPT.index('if [[ "$DEPLOY_PROFILE" == \'production\' ]]; then')
    block_end = SCRIPT.index("phase='准备并校验 VibeHub 专属 builder'", block_start)
    block = SCRIPT[block_start:block_end]
    result = _bash('python_stub() { printf "CDI-CALLED\\n"; }\nBOOTSTRAP_PYTHON=python_stub\nDEPLOY_PROFILE=test-cpu\n' + block)
    assert result.returncode == 0
    assert "CDI-CALLED" not in result.stdout
    result = _bash('python_stub() { printf "CDI-CALLED\\n"; }\nBOOTSTRAP_PYTHON=python_stub\nDEPLOY_PROFILE=production\n' + block)
    assert result.returncode == 0
    assert "CDI-CALLED" in result.stdout
    assert '--label "com.numericaloj.vibehub.gpu=$VIBEHUB_RUNTIME_GPU"' in SCRIPT


@pytest.mark.parametrize("profile,context", [
    ("production", "docker/judger"),
    ("production", "docker/agent_judge"),
    ("production", "docker/lean4"),
    ("test-cpu", "docker/judger"),
    ("test-cpu", "docker/agent_judge"),
    ("test-cpu", "docker/lean4"),
])
def test_missing_images_are_built_in_both_profiles_and_agent_reuses_candidate_lean(
    tmp_path, profile, context,
):
    calls = tmp_path / "docker-arguments"
    source = _function("find_matching_managed_candidate") + _function("build_candidate_image") + r'''
DEPLOY_PROFILE="$1"
DOCKER_BUILDER=default
LEAN4_CANDIDATE=numericaloj-lean4:deploy-same-run
MANAGED_IMAGE_LABEL=org.numericaloj.deploy-managed=true
SOURCE_IMAGE_LABEL=org.numericaloj.source-sha256
docker_source_digest() { printf input-version; }
image_source_digest() { printf input-version; }
docker() {
  case "$1:$2" in
    image:inspect) return 1 ;;
    image:ls) return 0 ;;
    build:--builder) printf '%s\n' "$@" > "$3" ;;
    *) return 2 ;;
  esac
}
'''
    # 单独使用文件变量，避免模拟 docker 的局部参数覆盖测试文件路径。
    source = source.replace('> "$3"', '> "$CALLS_FILE"')
    source += '\nCALLS_FILE="$3"\nbuild_candidate_image stable-image candidate-image "$2" marker\n'
    result = _bash(source, profile, context, str(calls))
    assert result.returncode == 0, result.stderr
    arguments = calls.read_text().splitlines()
    assert arguments[-1] == context
    assert "candidate-image" in arguments
    assert "BUILDKIT_INLINE_CACHE=1" in arguments
    assert "org.numericaloj.source-sha256=input-version" in arguments
    if context == "docker/agent_judge":
        assert "LEAN4_IMAGE=numericaloj-lean4:deploy-same-run" in arguments
    else:
        assert not any(item.startswith("LEAN4_IMAGE=") for item in arguments)


@pytest.mark.parametrize("cache", ["warm", "missing", "unreadable", "unchanged"])
def test_existing_images_keep_cache_reuse_and_supply_missing_layers(tmp_path, cache):
    calls = tmp_path / "docker-arguments"
    source = _function("find_matching_managed_candidate") + _function("build_candidate_image") + r'''
DEPLOY_PROFILE=production
DOCKER_BUILDER=default
MANAGED_IMAGE_LABEL=org.numericaloj.deploy-managed=true
SOURCE_IMAGE_LABEL=org.numericaloj.source-sha256
docker_source_digest() { printf current-input; }
image_source_digest() {
  if [[ "$1" == candidate-image || "$CACHE" == unchanged ]]; then
    printf current-input
  else
    printf previous-input
  fi
}
docker() {
  printf '%s\n' "$*" >> "$CALLS_FILE"
  case "$1:$2" in
    image:inspect) printf stable-id ;;
    image:ls) return 0 ;;
    buildx:du)
      [[ "$CACHE" != unreadable ]] || return 1
      [[ "$CACHE" != warm ]] || printf required-marker
      ;;
    build:--builder|tag:stable-image) return 0 ;;
    *) return 2 ;;
  esac
}
CACHE="$1"
CALLS_FILE="$2"
build_candidate_image stable-image candidate-image docker/judger required-marker
'''
    result = _bash(source, cache, str(calls))
    assert result.returncode == 0, result.stderr
    commands = calls.read_text().splitlines()
    if cache == "unchanged":
        assert commands[-1] == "tag stable-image candidate-image"
        assert not any(command.startswith(("buildx du", "build ")) for command in commands)
    else:
        assert any(command.startswith("build --builder default ") for command in commands)
        assert not any(command.startswith(("tag ", "image rm", "builder prune")) for command in commands)
        if cache == "warm":
            assert "构建将逐层确认命中" in result.stdout
        else:
            assert "将自动构建缺失层" in result.stderr


def test_cpu_profile_keeps_the_full_release_state_machine():
    assert SCRIPT.index("configure_deployment_profile\n") < SCRIPT.index('install -d -m 0700 "$STATE_DIR"')
    assert '--target web-edu' in _function("configure_deployment_profile")
    assert 'JUDGER_CONTEXT=\'docker/judger-lite\'' in _function("configure_deployment_mode")
    for operation in (
        "deploy/preflight.py validate-config", "deploy/backup_database.py backup",
        "scripts/init_db_schema.py", "deploy/seed_vibehub_examples.py",
        "scripts/recover_pending_tasks.py --confirm-celery-stopped",
        "phase='启动 Celery 服务'", "phase='启动 Web 服务'",
    ):
        assert operation in SCRIPT
