"""显式选择 full/lite 并持久保存，不自动改变既有生产镜像模式。"""

from pathlib import Path
import subprocess

import pytest

from deploy import bootstrap


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (ROOT / "deploy.sh").read_text()


def _function(name):
    start = SCRIPT.index(f"{name}() {{")
    return SCRIPT[start:SCRIPT.index("\n}\n", start) + 3]


def test_mode_defaults_full_and_only_explicit_switch_changes_persistent_selection(tmp_path):
    state = tmp_path / ".deploy"
    state.mkdir()
    (state / "profile").write_text("test-cpu\n")
    assert bootstrap.resolve_mode(tmp_path) == "full"
    path = state / "deployment-mode"
    assert path.stat().st_mode & 0o777 == 0o600
    assert bootstrap.resolve_mode(tmp_path, "lite") == "lite"
    assert bootstrap.resolve_mode(tmp_path) == "lite"
    assert bootstrap.resolve_mode(tmp_path, "full") == "full"
    assert bootstrap.resolve_mode(tmp_path) == "full"


@pytest.mark.parametrize("damage", ["public", "symlink", "invalid"])
def test_saved_mode_is_private_owned_and_validated_before_use(tmp_path, damage):
    state = tmp_path / ".deploy"
    state.mkdir()
    path = state / "deployment-mode"
    if damage == "symlink":
        target = state / "other"
        target.write_text("lite\n")
        path.symlink_to(target)
    else:
        path.write_text("unknown\n" if damage == "invalid" else "lite\n")
        path.chmod(0o600 if damage == "invalid" else 0o644)
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.resolve_mode(tmp_path, "full")


@pytest.mark.parametrize("arguments,success", [(["--help"], True), (["--mode"], False), (["--mode", "unknown"], False),
                                            (["--mode", "lite", "--mode", "full"], False), (["--other"], False)])
def test_cli_explains_and_validates_mode_before_starting_deployment(arguments, success):
    result = subprocess.run(["bash", str(ROOT / "deploy.sh"), *arguments], capture_output=True, text=True)
    assert result.returncode == (0 if success else 2)
    if success:
        assert "--mode full|lite" in result.stdout


@pytest.mark.parametrize("arguments", [
    ["--finalize-harbor-task"],
    ["--finalize-harbor-task", "../task"],
    ["--finalize-harbor-task", "--help"],
    ["--finalize-harbor-task", "task\nother"],
    ["--finalize-harbor-task", "x" * 65],
    ["--finalize-harbor-task", "first", "--finalize-harbor-task", "second"],
])
def test_harbor_recovery_rejects_invalid_or_duplicate_task_before_deploy(arguments):
    result = subprocess.run(["bash", str(ROOT / "deploy.sh"), *arguments], capture_output=True, text=True)
    assert result.returncode == 2
    assert "原任务 ID" in result.stderr


def test_harbor_recovery_is_optional_and_runs_after_backup_with_worker_stop_guard():
    result = subprocess.run(["bash", str(ROOT / "deploy.sh"), "--finalize-harbor-task", "jd-example-run", "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "不重新调用模型" in result.stdout
    recovery = SCRIPT.index('scripts/recover_pending_tasks.py --confirm-celery-stopped "${HARBOR_RECOVERY_ARGUMENTS[@]}"')
    assert SCRIPT.index('deploy/backup_database.py backup') < recovery
    assert SCRIPT.index("assert_service_stopped 'Celery' celery") < recovery
    assert SCRIPT.index('scripts/recover_pending_tasks.py --confirm-celery-stopped\n') < recovery


@pytest.mark.parametrize("mode,judger,agent", [("full", "docker/judger", "docker/agent_judge"),
                                            ("lite", "docker/judger-lite", "docker/agent_judge-lite")])
def test_mode_selects_existing_dockerfiles_and_keeps_canonical_runtime_interfaces(mode, judger, agent):
    source = _function("configure_deployment_mode") + '\nconfigure_deployment_mode "$1"\nprintf "%s\\n" "$JUDGER_CONTEXT" "$AGENT_JUDGE_CONTEXT"\n'
    result = subprocess.run(["bash", "-c", source, "mode-test", mode], capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.splitlines() == [judger, agent]
    assert "JUDGER_STABLE='numericaloj-judger:latest'" in SCRIPT
    assert "AGENT_JUDGE_STABLE='numericaloj-agent-judge:latest'" in SCRIPT


@pytest.mark.parametrize("context", ["docker/agent_judge-lite", "docker/judger-lite", "docker/harbor-base"])
def test_lite_and_derived_harbor_builds_use_native_layer_cache_without_source_hashes(tmp_path, context):
    calls = tmp_path / "build-args"
    source = _function("build_candidate_image") + r'''
unset NUMOJ_DOCKER_LIBRARY_REGISTRY
DEPLOY_PROFILE=test-cpu
DOCKER_BUILDER=default
LEAN4_CANDIDATE=lean-same-run
AGENT_JUDGE_CANDIDATE=numericaloj-agent-judge:deploy-same-run
MANAGED_IMAGE_LABEL=org.numericaloj.deploy-managed=true
SOURCE_IMAGE_LABEL=org.numericaloj.source-sha256
docker_source_digest() { printf '本次构建不得调用文件摘要\n' >&2; return 93; }
image_source_digest() { printf '本次构建不得读取自定义摘要\n' >&2; return 94; }
find_matching_managed_candidate() { printf '本次构建不得按摘要复用旧候选\n' >&2; return 95; }
docker() {
  case "$1:$2" in
    image:inspect) printf candidate-id ;;
    build:--builder) printf '%s\n' "$@" > "$CALLS_FILE" ;;
    *) return 2 ;;
  esac
}
CALLS_FILE="$1"
build_candidate_image numericaloj-agent-judge:latest numericaloj-agent-judge:deploy-test "$2"
'''
    result = subprocess.run(["bash", "-c", source, "lite-build-test", str(calls), context], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    arguments = calls.read_text().splitlines()
    assert not any(value.startswith("org.numericaloj.source-") for value in arguments)
    if context == "docker/agent_judge-lite":
        assert arguments[-1] == "docker"
        assert arguments[arguments.index("--file") + 1] == "docker/agent_judge-lite/Dockerfile"
        assert "LEAN4_IMAGE=lean-same-run" in arguments
    else:
        assert arguments[-1] == context
        assert "--file" not in arguments
    if context == "docker/harbor-base":
        assert "AGENT_IMAGE=numericaloj-agent-judge:deploy-same-run" in arguments
        assert not any(value.startswith("LEAN4_IMAGE=") for value in arguments)
    else:
        assert not any(value.startswith("AGENT_IMAGE=") for value in arguments)


@pytest.mark.parametrize("mode", ["full", "lite"])
@pytest.mark.parametrize("deferred", ["0", "1"])
def test_harbor_reuses_selected_agent_and_defers_full_derivation_until_cache_reclaimed(tmp_path, mode, deferred):
    calls = tmp_path / "candidate-calls"
    start = SCRIPT.index("phase='构建判题镜像'")
    block = SCRIPT[start:SCRIPT.index("\nphase='清理遗留候选镜像'", start)]
    source = _function("configure_deployment_mode") + r'''
DEPLOY_PROFILE=test-cpu
DEVELOPMENT_RESERVE_ELIGIBLE="$3"
DEFERRED_UNPACK_ENABLED=0
DEPLOY_FULL_IMAGE_BUILD_ARGUMENTS=()
DEPLOY_MODE="$1"
CALLS_FILE="$2"
CANDIDATE_PYTHON=python_stub
ROOT_DIR=/dev/null
DOCKER_BUILDER=default
configure_deployment_mode "$DEPLOY_MODE"
JUDGER_STABLE=judger-stable
JUDGER_CANDIDATE=judger-candidate
LEAN4_STABLE=lean-stable
LEAN4_CANDIDATE=lean-candidate
AGENT_JUDGE_STABLE=agent-stable
AGENT_JUDGE_CANDIDATE=agent-candidate
HARBOR_BASE_STABLE=harbor-stable
HARBOR_BASE_CANDIDATE=harbor-candidate
build_candidate_image() { printf 'build:%s\n' "$*" >> "$CALLS_FILE"; }
docker() { printf '%s\n' "$*" >> "$CALLS_FILE"; }
python_stub() {
  case "$2" in
    deploy/deferred_unpack.py) printf 'probe-deferred\n' >> "$CALLS_FILE"; printf 1 ;;
    deploy/project_build_cache.py) printf 'reclaim-cache\n' >> "$CALLS_FILE" ;;
    *) return 2 ;;
  esac
}
''' + block
    result = subprocess.run(["bash", "-c", source, "harbor-mode-test", mode, str(calls), deferred], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    commands = calls.read_text().splitlines()
    assert any(command.startswith("build:lean-stable lean-candidate docker/lean4") for command in commands)
    if mode == "lite":
        assert len([command for command in commands if command.startswith("build:")]) == 3
        assert any(command.startswith("build:agent-stable agent-candidate docker/agent_judge-lite") for command in commands)
        assert "tag agent-candidate harbor-candidate" in commands
        assert "probe-deferred" not in commands and "reclaim-cache" not in commands
    else:
        assert len([command for command in commands if command.startswith("build:")]) == 4
        assert any(command.startswith("build:agent-stable agent-candidate docker/agent_judge ") for command in commands)
        harbor_build = "build:harbor-stable harbor-candidate docker/harbor-base"
        assert harbor_build in commands
        assert "tag agent-candidate harbor-candidate" not in commands
        assert not any("docker/agent_judge-lite" in command for command in commands)
        if deferred == "1":
            agent_build = next(command for command in commands if command.startswith("build:agent-stable"))
            assert commands.index(agent_build) < commands.index("reclaim-cache") < commands.index(harbor_build)
        else:
            assert "probe-deferred" not in commands and "reclaim-cache" not in commands
    stable_switch = SCRIPT.index('docker tag "$HARBOR_BASE_CANDIDATE" "$HARBOR_BASE_STABLE"')
    assert SCRIPT.index("phase='创建并验证数据库回滚点'") < stable_switch
    assert '--mode "$DEPLOY_MODE"' in SCRIPT[SCRIPT.index("phase='准备判题器官方头文件工具链'"):SCRIPT.index("phase='核验编辑器语言服务'")]


def test_full_harbor_derivative_only_adds_workdir_and_validates_inherited_tools():
    dockerfile = (ROOT / "docker/harbor-base/Dockerfile").read_text()
    assert "ARG AGENT_IMAGE=numericaloj-agent-judge:latest" in dockerfile
    assert "FROM ${AGENT_IMAGE}" in dockerfile
    assert "mkdir -p /app" in dockerfile
    for command in ("claude --version", "codex --version", "opencode --version", "pi --version", "timeout --version"):
        assert command in dockerfile
    for install in ("apt-get", "pip install", "pip3 install", "npm install", "COPY --from"):
        assert install not in dockerfile
