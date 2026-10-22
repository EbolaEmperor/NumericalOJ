"""显式 CPU 测试配置可首次供应完整镜像，生产门禁保持不变。"""

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


@pytest.mark.parametrize("profile,context,expected_success", [
    ("production", "docker/judger", False),
    ("production", "docker/agent_judge", False),
    ("production", "docker/lean4", True),
    ("test-cpu", "docker/judger", True),
    ("test-cpu", "docker/agent_judge", True),
    ("test-cpu", "docker/lean4", True),
])
def test_first_candidate_builds_are_profile_scoped_and_agent_reuses_candidate_lean(
    tmp_path, profile, context, expected_success,
):
    calls = tmp_path / "docker-arguments"
    source = _function("build_candidate_image") + r'''
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
    build:--builder) printf '%s\n' "$@" > "$3" ;;
    *) return 2 ;;
  esac
}
'''
    # 单独使用文件变量，避免模拟 docker 的局部参数覆盖测试文件路径。
    source = source.replace('> "$3"', '> "$CALLS_FILE"')
    source += '\nCALLS_FILE="$3"\nbuild_candidate_image stable-image candidate-image "$2" marker\n'
    result = _bash(source, profile, context, str(calls))
    assert (result.returncode == 0) is expected_success
    if not expected_success:
        assert "为避免冷构建，拒绝继续部署" in result.stderr
        assert not calls.exists()
        return
    arguments = calls.read_text().splitlines()
    assert arguments[-1] == context
    assert "candidate-image" in arguments
    assert "BUILDKIT_INLINE_CACHE=1" in arguments
    assert "org.numericaloj.source-sha256=input-version" in arguments
    if context == "docker/agent_judge":
        assert "LEAN4_IMAGE=numericaloj-lean4:deploy-same-run" in arguments
    else:
        assert not any(item.startswith("LEAN4_IMAGE=") for item in arguments)


def test_cpu_profile_keeps_the_full_release_state_machine():
    assert SCRIPT.index("configure_deployment_profile\n") < SCRIPT.index('install -d -m 0700 "$STATE_DIR"')
    assert '--target web-edu' in _function("configure_deployment_profile")
    assert "judger-lite" not in SCRIPT and "agent_judge_lite" not in SCRIPT
    for operation in (
        "deploy/preflight.py validate-config", "deploy/backup_database.py backup",
        "scripts/init_db_schema.py", "deploy/seed_vibehub_examples.py",
        "scripts/recover_pending_tasks.py --confirm-celery-stopped",
        "phase='启动 Celery 服务'", "phase='启动 Web 服务'",
    ):
        assert operation in SCRIPT
