from pathlib import Path


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
    assert "cat /opt/numoj-lean-path" in wrapper
    assert 'exec /opt/elan/bin/lean "$@"' in wrapper


def test_production_deploy_builds_lean_before_the_agent_image():
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")

    lean_build = deploy.index(
        '"$LEAN4_STABLE" "$LEAN4_CANDIDATE" docker/lean4'
    )
    agent_build = deploy.index(
        '"$AGENT_JUDGE_STABLE" "$AGENT_JUDGE_CANDIDATE" docker/agent_judge'
    )
    assert lean_build < agent_build
    assert 'docker_build_args=(--build-arg "LEAN4_IMAGE=$LEAN4_CANDIDATE")' in deploy
    assert "agent_judge/lean" in deploy
    assert "lean4/Dockerfile" in deploy


def test_ci_exports_lean_rootfs_before_building_the_lite_agent_image():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    lean_build = workflow.index("Build the pinned Lean4 and Mathlib runtime")
    agent_build = workflow.index("Build the Agent Judge lite image")
    assert lean_build < agent_build
    assert "context: docker/lean4" in workflow
    assert "numericaloj-lean4-rootfs=${{ runner.temp }}" in workflow
    assert "LEAN4_IMAGE=numericaloj-lean4-rootfs" in workflow
