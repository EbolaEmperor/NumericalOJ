"""延迟解包必须同时满足开发事实和已核对的 Docker 能力。"""

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from deploy import deferred_unpack


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (ROOT / "deploy.sh").read_text()
CONTAINERD_STATUS = [["driver-type", "io.containerd.snapshotter.v1"]]


@pytest.mark.parametrize("version,supported", [("29.1.3", True), ("29.2.0", True), ("29.9.3+build.1", True),
                                             ("29.1.2", False), ("29.0.0", False), ("28.5.1", False),
                                             ("30.0.0", False), ("29.1.3-rc1", False), ("unknown", False)])
def test_only_verified_stable_engine_versions_can_defer_unpack(version, supported):
    assert deferred_unpack._supported_engine({"ServerVersion": version, "DriverStatus": CONTAINERD_STATUS}) is supported


@pytest.mark.parametrize("status", [None, [], [["driver-type", "overlay2"]], {"driver-type": "io.containerd.snapshotter.v1"}])
def test_containerd_image_store_must_be_explicitly_reported(status):
    assert not deferred_unpack._supported_engine({"ServerVersion": "29.1.3", "DriverStatus": status})


@pytest.mark.parametrize("driver,enabled", [("docker", True), ("docker-container", False), ("remote", False)])
def test_engine_and_builder_are_readonly_verified_after_full_development_facts(monkeypatch, tmp_path, driver, enabled):
    settings = SimpleNamespace(MYSQL_HOST="127.0.0.1", MYSQL_PORT=3306, MYSQL_DB="numoj_dev_test",
                               MYSQL_USERNAME="oj", MYSQL_PASSWORD="private-password")
    facts = []
    monkeypatch.setattr(deferred_unpack.development, "reserve_facts", lambda root, value: facts.append((root, value.database)))
    monkeypatch.setattr(deferred_unpack.container_client, "_docker", lambda: "/usr/bin/docker")
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        payload = ({"ServerVersion": "29.1.3", "DriverStatus": CONTAINERD_STATUS}
                   if command[1] == "info" else {"Driver": driver})
        assert kwargs["check"] is False and kwargs["timeout"] == 30
        assert "--bootstrap" not in command
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
    assert deferred_unpack.enabled(tmp_path, "default", config=settings, run=run) is enabled
    assert facts == [(tmp_path, "numoj_dev_test")]
    assert [command[1:3] for command in calls] == [["info", "--format"], ["buildx", "inspect"]]
    assert "private-password" not in repr(calls)


def test_ineligible_deployment_keeps_original_output_without_docker_queries(monkeypatch, tmp_path):
    monkeypatch.setattr(deferred_unpack, "settings_from_config", lambda _: object())
    def forbidden(*_args):
        raise RuntimeError("生产或非受管测试库")
    monkeypatch.setattr(deferred_unpack.development, "reserve_facts", forbidden)
    assert not deferred_unpack.enabled(tmp_path, "default", config=object(), run=lambda *_a, **_kw: pytest.fail("资格不符不得探测 Docker"))


@pytest.mark.parametrize("failure", ["unknown-engine", "invalid-json", "command-failure"])
def test_unknown_capability_keeps_original_exporter(monkeypatch, tmp_path, failure):
    monkeypatch.setattr(deferred_unpack, "settings_from_config", lambda _: object())
    monkeypatch.setattr(deferred_unpack.development, "reserve_facts", lambda *_: {})
    monkeypatch.setattr(deferred_unpack.container_client, "_docker", lambda: "/usr/bin/docker")
    def run(command, **kwargs):
        output = "invalid" if failure == "invalid-json" else json.dumps({"ServerVersion": "29.1.2", "DriverStatus": CONTAINERD_STATUS})
        return subprocess.CompletedProcess(command, 1 if failure == "command-failure" else 0, output, "")
    assert not deferred_unpack.enabled(tmp_path, "default", config=object(), run=run)


@pytest.mark.parametrize("eligible,supported,mode", [("0", "0", "full"), ("0", "1", "full"),
                                                   ("1", "0", "full"), ("1", "1", "full"), ("1", "1", "lite")])
def test_deploy_only_sets_image_output_after_both_eligibility_and_capability(eligible, supported, mode):
    start = SCRIPT.index('if [[ "$DEPLOY_MODE" == full && "$DEVELOPMENT_RESERVE_ELIGIBLE" == 1 ]]; then', SCRIPT.index("phase='构建判题镜像'"))
    block = SCRIPT[start:SCRIPT.index("build_candidate_image \\\n", start)]
    source = r'''
CANDIDATE_PYTHON=probe_stub
ROOT_DIR=unused
DOCKER_BUILDER=default
DEVELOPMENT_RESERVE_ELIGIBLE="$1"
SUPPORTED="$2"
DEPLOY_MODE="$3"
DEFERRED_UNPACK_ENABLED=0
DEPLOY_FULL_IMAGE_BUILD_ARGUMENTS=()
probe_stub() { printf '%s' "$SUPPORTED"; }
''' + block + '\nprintf "ARG=%s\\n" "${DEPLOY_FULL_IMAGE_BUILD_ARGUMENTS[@]}"\n'
    result = subprocess.run(["bash", "-c", source, "deferred-unpack-test", eligible, supported, mode], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    arguments = [line.removeprefix("ARG=") for line in result.stdout.splitlines() if line.startswith("ARG=") and line != "ARG="]
    assert arguments == (["--output", "type=image,unpack=false"] if eligible == supported == "1" and mode == "full" else [])


def test_full_candidate_output_and_cache_hook_do_not_change_vibehub_or_runtime():
    build_function = SCRIPT[SCRIPT.index("build_candidate_image() {"):SCRIPT.index("current_venv_target=")]
    assert '"${DEPLOY_FULL_IMAGE_BUILD_ARGUMENTS[@]}"' in build_function
    assert SCRIPT.count('"${DEPLOY_FULL_IMAGE_BUILD_ARGUMENTS[@]}"') == 1
    vibe = SCRIPT[SCRIPT.index("phase='构建 VibeHub 受信基础候选镜像'"):SCRIPT.index("phase='导出并核验 VibeHub 受信基础 OCI layout'")]
    assert "unpack=false" not in vibe and "DEPLOY_FULL_IMAGE_BUILD_ARGUMENTS" not in vibe
    hook = SCRIPT.index("deploy/project_build_cache.py")
    assert SCRIPT.index('"$AGENT_JUDGE_STABLE" "$AGENT_JUDGE_CANDIDATE" "$AGENT_JUDGE_CONTEXT"') < hook
    assert hook < SCRIPT.index("phase='构建 React 前端'") < SCRIPT.index("phase='停止现有服务'")
    for candidate in ("JUDGER_CANDIDATE", "LEAN4_CANDIDATE", "AGENT_JUDGE_CANDIDATE"):
        assert '--candidate "$' + candidate + '"' in SCRIPT[hook:SCRIPT.index("phase='构建 React 前端'")]
