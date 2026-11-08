"""发布重试可复用已完成候选镜像，构建失败的私有缓存不能冒充完整镜像。"""

from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (ROOT / "deploy.sh").read_text()


def _function(name):
    start = SCRIPT.index(f"{name}() {{")
    return SCRIPT[start:SCRIPT.index("\n}\n", start) + 3]


@pytest.mark.parametrize("scenario", ["partial-retry", "direct-reuse", "stale-stable", "stable-match", "unmatched", "unmatched-stable"])
def test_candidate_selection_prefers_stable_then_matching_complete_managed_retry(tmp_path, scenario):
    calls = tmp_path / "docker-commands"
    source = _function("find_matching_managed_candidate") + _function("build_candidate_image") + r'''
DEPLOY_PROFILE=production
DOCKER_BUILDER=default
MANAGED_IMAGE_LABEL=org.numericaloj.deploy-managed=true
SOURCE_IMAGE_LABEL=org.numericaloj.source-sha256
docker_source_digest() { printf current-input; }
image_source_digest() {
  if [[ "$1" == repo:deploy-new || "$SCENARIO" == stable-match ]]; then
    printf current-input
  else
    printf previous-input
  fi
}
docker() {
  printf '%s\n' "$*" >> "$CALLS_FILE"
  case "$1:$2" in
    image:inspect)
      case "${@: -1}" in
        repo:latest)
          case "$SCENARIO" in stable-match|stale-stable|unmatched-stable) printf stable-id;; *) return 1;; esac
          ;;
        repo:deploy-partial) return 1 ;;
        repo:deploy-completed-retry) printf 'completed-id true current-input' ;;
        repo:deploy-wrong-input) printf 'old-id true previous-input' ;;
        repo:deploy-not-managed) printf 'unmanaged-id false current-input' ;;
        *) return 2 ;;
      esac
      ;;
    image:ls)
      case "$SCENARIO" in
        partial-retry) printf 'repo:deploy-partial\nrepo:deploy-completed-retry\n' ;;
        unmatched|unmatched-stable) printf 'repo:deploy-partial\nrepo:deploy-wrong-input\nrepo:deploy-not-managed\nother:deploy-completed-retry\n' ;;
        *) printf 'repo:deploy-completed-retry\n' ;;
      esac
      ;;
    buildx:du) printf required-marker ;;
    build:--builder|tag:completed-id|tag:repo:latest) return 0 ;;
    *) return 2 ;;
  esac
}
SCENARIO="$1"
CALLS_FILE="$2"
build_candidate_image repo:latest repo:deploy-new docker/judger required-marker
'''
    result = subprocess.run(["bash", "-c", source, "retry-candidate-test", scenario, str(calls)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    commands = calls.read_text().splitlines()
    if scenario == "stable-match":
        assert commands[-1] == "tag repo:latest repo:deploy-new"
        assert not any(command.startswith("image ls") for command in commands)
    elif scenario in {"partial-retry", "direct-reuse", "stale-stable"}:
        assert commands[-1] == "tag completed-id repo:deploy-new"
        assert not any(command.startswith(("build ", "buildx du")) for command in commands)
    else:
        assert any(command.startswith("build --builder default ") for command in commands)
        assert not any(command.startswith("tag ") for command in commands)
    assert not any(command.startswith(("image rm", "builder prune")) for command in commands)


def test_stale_candidate_cleanup_runs_after_all_candidates_and_preserves_current_aliases(tmp_path):
    calls = tmp_path / "removed"
    source = _function("remove_stale_candidate_tags") + r'''
MANAGED_IMAGE_LABEL=org.numericaloj.deploy-managed=true
JUDGER_CANDIDATE=numericaloj-judger:deploy-current
AGENT_JUDGE_CANDIDATE=numericaloj-agent-judge:deploy-current
LEAN4_CANDIDATE=numericaloj-lean4:deploy-current
HARBOR_BASE_CANDIDATE=numericaloj-harbor-base:deploy-current
VIBEHUB_RUNTIME_CANDIDATE=numericaloj-vibehub-runtime:deploy-current
docker() {
  if [[ "$1:$2" == image:ls ]]; then
    repository="${6#reference=}"
    repository="${repository%%:*}"
    printf '%s\n' "$repository:deploy-current" "$repository:deploy-old-retry"
  elif [[ "$1:$2" == image:rm ]]; then
    printf '%s\n' "$3" >> "$CALLS_FILE"
  else
    return 2
  fi
}
CALLS_FILE="$1"
remove_stale_candidate_tags
'''
    result = subprocess.run(["bash", "-c", source, "retry-cleanup-test", str(calls)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    removed = calls.read_text().splitlines()
    assert len(removed) == 5 and all(tag.endswith(":deploy-old-retry") for tag in removed)
    cleanup = SCRIPT.index("\nremove_stale_candidate_tags\n")
    assert SCRIPT.index('"$AGENT_JUDGE_STABLE" "$AGENT_JUDGE_CANDIDATE" "$AGENT_JUDGE_CONTEXT"') < cleanup
    assert cleanup < SCRIPT.index("phase='构建 React 前端'") < SCRIPT.index("phase='停止现有服务'")


@pytest.mark.parametrize("exit_code", [0, 1])
def test_failed_release_keeps_completed_judging_candidates_for_retry(tmp_path, exit_code):
    start = SCRIPT.index('  if [[ "$exit_code" -eq 0 ]]; then\n    docker image rm')
    block = SCRIPT[start:SCRIPT.index('  if [[ "$exit_code" -ne 0 ]]; then', start)]
    calls = tmp_path / "removed"
    source = r'''
JUDGER_CANDIDATE=judger-candidate
AGENT_JUDGE_CANDIDATE=agent-candidate
LEAN4_CANDIDATE=lean-candidate
HARBOR_BASE_CANDIDATE=harbor-candidate
VIBEHUB_RUNTIME_CANDIDATE=vibe-candidate
docker() { printf '%s\n' "$*" >> "$CALLS_FILE"; }
exit_code="$1"
CALLS_FILE="$2"
''' + block
    result = subprocess.run(["bash", "-c", source, "retry-exit-test", str(exit_code), str(calls)], capture_output=True, text=True)
    assert result.returncode == 0
    removed = calls.read_text().splitlines()
    assert "image rm vibe-candidate" in removed
    assert ("image rm judger-candidate agent-candidate lean-candidate harbor-candidate" in removed) is (exit_code == 0)
