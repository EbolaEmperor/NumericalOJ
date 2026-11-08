from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_agent_judge_images_reuse_the_pinned_lean_runtime():
    dockerfiles = [
        (ROOT / "docker/agent_judge/Dockerfile").read_text(encoding="utf-8"),
        (ROOT / "docker/agent_judge-lite/Dockerfile").read_text(
            encoding="utf-8"
        ),
    ]
    wrapper = (ROOT / "docker/agent_judge/lean").read_text(encoding="utf-8")

    for dockerfile in dockerfiles:
        assert "ARG LEAN4_IMAGE=numericaloj-lean4:latest" in dockerfile
        assert "FROM ${LEAN4_IMAGE} AS lean4_runtime" in dockerfile
        for path in (
            "/opt/elan",
            "/opt/numoj-lean-project",
            "/opt/numoj-lean-path",
        ):
            assert f"COPY --from=lean4_runtime {path} {path}" in dockerfile
        assert "/usr/local/bin/lean" in dockerfile
        assert "Mathlib.olean" in dockerfile
    assert 'Path("/opt/numoj-lean-path").read_text()' in wrapper
    assert 'root=Path("/opt/numoj-lean-project")' in wrapper
    assert '(root/p).resolve()' in wrapper
    assert 'exec /opt/elan/bin/lean "$@"' in wrapper


@pytest.mark.parametrize("mode", ["full", "lite"])
def test_production_deploy_builds_lean_before_the_agent_image(tmp_path, mode):
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")

    lean_build = deploy.index(
        '"$LEAN4_STABLE" "$LEAN4_CANDIDATE" docker/lean4'
    )
    agent_build = deploy.index(
        '"$AGENT_JUDGE_STABLE" "$AGENT_JUDGE_CANDIDATE" "$AGENT_JUDGE_CONTEXT"'
    )
    assert lean_build < agent_build

    def function(name):
        start = deploy.index(f"{name}() {{")
        return deploy[start:deploy.index("\n}\n", start) + 3]

    start = deploy.index("phase='构建判题镜像'")
    stage = deploy[start:deploy.index('\nif [[ "$DEFERRED_UNPACK_ENABLED" == 1 ]]; then', start)]
    calls = tmp_path / "docker-builds"
    source = "set -e\n" + function("configure_deployment_mode") + function("build_candidate_image") + r'''
unset NUMOJ_DOCKER_LIBRARY_REGISTRY
DEPLOY_PROFILE=production
DEVELOPMENT_RESERVE_ELIGIBLE=0
DEFERRED_UNPACK_ENABLED=0
DOCKER_BUILDER=default
DEPLOY_MODE="$1"
CALLS_FILE="$2"
configure_deployment_mode "$DEPLOY_MODE"
JUDGER_STABLE=judger-stable
JUDGER_CANDIDATE=judger-candidate
LEAN4_STABLE=lean-stable
LEAN4_CANDIDATE=lean-candidate
AGENT_JUDGE_STABLE=agent-stable
AGENT_JUDGE_CANDIDATE=agent-candidate
HARBOR_BASE_STABLE=harbor-stable
HARBOR_BASE_CANDIDATE=harbor-candidate
MANAGED_IMAGE_LABEL=org.numericaloj.deploy-managed=true
SOURCE_IMAGE_LABEL=org.numericaloj.source-sha256
docker_source_digest() { printf legacy-source-metadata; }
image_source_digest() { printf legacy-source-metadata; }
find_matching_managed_candidate() { :; }
docker() {
  case "$1:$2" in
    image:inspect)
      [[ "${@: -1}" == *-candidate ]] || return 1
      printf image-id
      ;;
    build:--builder)
      printf '%s\t' "$@" >> "$CALLS_FILE"
      printf '\n' >> "$CALLS_FILE"
      ;;
    tag:agent-candidate) return 0 ;;
    *) return 2 ;;
  esac
}
''' + stage
    result = subprocess.run(["bash", "-c", source, "lean-order-contract", mode, str(calls)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    builds = [line.rstrip("\t").split("\t") for line in calls.read_text().splitlines()]
    candidates = [arguments[arguments.index("--tag") + 1] for arguments in builds]
    assert candidates == (["judger-candidate", "lean-candidate", "agent-candidate", "harbor-candidate"]
                          if mode == "full" else ["judger-candidate", "lean-candidate", "agent-candidate"])
    assert builds[1][-1] == "docker/lean4"
    assert builds[2][-1] == ("docker/agent_judge" if mode == "full" else "docker")
    if mode == "lite":
        assert builds[2][builds[2].index("--file") + 1] == "docker/agent_judge-lite/Dockerfile"
    for arguments in builds[2:]:
        lean_argument = arguments.index("LEAN4_IMAGE=lean-candidate")
        assert arguments[lean_argument - 1] == "--build-arg"
    assert "agent_judge/lean" in deploy
    assert "lean4/Dockerfile" in deploy


def test_ci_passes_lean_image_through_a_local_registry():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    lean_build = workflow.index("Build the pinned Lean4 and Mathlib runtime")
    agent_build = workflow.index("Build the Agent Judge lite image")
    assert lean_build < agent_build
    assert "context: docker/lean4" in workflow
    assert "image: registry:3" in workflow
    assert "driver-opts: network=host" in workflow
    assert "tags: localhost:5000/numericaloj-lean4:ci" in workflow
    assert "push: true" in workflow
    assert (
        "numericaloj-lean4-runtime="
        "docker-image://localhost:5000/numericaloj-lean4:ci"
    ) in workflow
    assert "LEAN4_IMAGE=numericaloj-lean4-runtime" in workflow
    assert "outputs: type=local" not in workflow
