from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_agent_judge_reuses_the_pinned_lean_runtime_and_deploy_builds_it_first():
    dockerfile = (ROOT / "docker/agent_judge/Dockerfile").read_text(
        encoding="utf-8"
    )
    wrapper = (ROOT / "docker/agent_judge/lean").read_text(encoding="utf-8")
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")

    assert "ARG LEAN4_IMAGE=numericaloj-lean4:latest" in dockerfile
    assert "FROM ${LEAN4_IMAGE} AS lean4_runtime" in dockerfile
    for path in ("/opt/elan", "/opt/numoj-lean-project", "/opt/numoj-lean-path"):
        assert f"COPY --from=lean4_runtime {path} {path}" in dockerfile
    assert "cat /opt/numoj-lean-path" in wrapper
    assert 'exec /opt/elan/bin/lean "$@"' in wrapper

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
