# -*- coding: utf-8 -*-
"""纯逻辑单测：打榜赛 Agent-as-Judge 容器生命周期（不依赖 Docker / 不连生产）。

验证评测轨迹写入独立脱敏目录而不复制原始 harness 会话，且：
  - docker run 不带 --rm，便于停止后读取最终日志；
  - run 之前会先 docker rm -f 同名残留容器；
  - 正常退出 / 超时两条路径最终都回收容器。
做法：把模块里的 subprocess 换成假对象，记录所有 docker 调用并模拟其行为。
"""
from contextlib import contextmanager
import os
import tempfile
import json
import time
from types import SimpleNamespace

import pytest

import backend.oj_modules.tasks.ranking.agent_judge as m


class _FakeProc:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class _FakeSubprocess:
    """假 subprocess：记录每次 docker 调用；inspect 按预设序列返回 running 状态；
    cp 时真的按源目录名在目标里建目录（模拟拷贝成功）。"""

    def __init__(self, running_seq):
        self.running_seq = list(running_seq)
        self.calls = []
        self._i = 0

    def run(self, args, **kw):
        self.calls.append(list(args))
        sub = args[1] if len(args) > 1 else ""
        if sub == "inspect":
            val = self.running_seq[min(self._i, len(self.running_seq) - 1)]
            self._i += 1
            return _FakeProc(0, val)
        if sub == "cp":
            src = args[-2].split(":", 1)[1]
            dest_dir = args[-1]
            os.makedirs(os.path.join(dest_dir, os.path.basename(src)), exist_ok=True)
            return _FakeProc(0, "")
        return _FakeProc(0, "")


def _docker_subcmds(calls):
    return [c[1] for c in calls if len(c) > 1 and c[0] == "docker"]


def test_resolve_endpoints_preserves_model_capabilities(monkeypatch):
    monkeypatch.setattr(m, "list_agent_judge_endpoints", lambda *_args, **_kwargs: [{
        "id": 9,
        "harness": m.HARNESS_CODEX,
        "protocol": "openai",
        "base_url": "https://model.example/v1",
        "api_key": "temporary-token",
        "model": "generic-model",
        "context_window_tokens": 131_072,
        "max_output_tokens": 16_384,
        "thinking_compatibility": False,
        "thinking_format": "none",
        "concurrency_limit": 3,
    }])

    assert m._resolve_endpoints(7) == [{
        "id": 9,
        "harness": m.HARNESS_CODEX,
        "protocol": "openai",
        "base_url": "https://model.example/v1",
        "api_key": "temporary-token",
        "model": "generic-model",
        "context_window_tokens": 131_072,
        "max_output_tokens": 16_384,
        "thinking_compatibility": False,
        "thinking_format": "none",
        "concurrency_limit": 3,
    }]


@pytest.mark.parametrize(
    ("orchestration_mode", "harness", "expected_protocol", "runner_name"),
    [
        ("single", m.HARNESS_CODEX, "openai", "_run_container_and_tail"),
        (
            m.aj.ORCH_TOPOLOGICAL,
            m.HARNESS_CLAUDE_CODE,
            "anthropic",
            "_run_container_topological",
        ),
    ],
)
def test_judge_container_only_receives_secret_relay_credential(
        monkeypatch, tmp_path, orchestration_mode, harness, expected_protocol,
        runner_name):
    real_key = "LONG_LIVED_PROVIDER_KEY"
    temporary_key = "attempt-scoped-relay-token"
    relay_url = "http://host.docker.internal:43123/provider/v1"
    events = []
    captured = {}
    endpoint = {
        "id": 9,
        "harness": harness,
        # 覆盖旧端点 protocol 为 NULL 时按 harness 推断协议的兼容路径。
        "protocol": None,
        "base_url": "https://provider.example/provider/v1",
        "api_key": real_key,
        "model": "configured-model",
    }
    competition = {
        "id": 3,
        "title": "relay security test",
        "agent_judge_orchestration_mode": orchestration_mode,
    }
    rules = [{
        "rule_id": 1,
        "rule_text": "rule",
        "value": 10,
        "dependencies": [],
    }]
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    @contextmanager
    def fake_secret_relays(host_endpoint):
        assert host_endpoint["api_key"] == real_key
        assert host_endpoint["base_url"] == endpoint["base_url"]
        assert host_endpoint["protocol"] == expected_protocol
        events.append("relay-start")
        try:
            yield SimpleNamespace(
                endpoint_base_url=relay_url,
                endpoint_api_key=temporary_key,
            )
        finally:
            events.append("relay-close")

    def fake_runner(
            submission_id, ws, result_name, competition_arg, rules_arg,
            timeout_s, endpoint_arg=None, attempt_id=None, trace_dir=None):
        events.append(f"run:{runner_name}")
        captured["endpoint"] = endpoint_arg
        docker_args = m._docker_container_args(
            "aj-relay-test", ws, endpoint_arg["harness"],
            endpoint_arg["base_url"], endpoint_arg["api_key"],
            endpoint_arg["model"], result_name, endpoint=endpoint_arg,
        )
        rendered = "\0".join(docker_args)
        assert real_key not in rendered
        assert "host.docker.internal:host-gateway" in docker_args
        assert f"AJ_ENDPOINT_API_KEY={temporary_key}" in docker_args
        assert f"AJ_ENDPOINT_BASE_URL={relay_url}" in docker_args
        return False, True

    monkeypatch.setattr(m, "run_agent_secret_relays", fake_secret_relays)
    monkeypatch.setattr(m, "get_ranking_submission", lambda _sid: {
        "id": 7,
        "competition_id": 3,
        "status": "Queued",
    })
    monkeypatch.setattr(m, "_task_should_skip", lambda *_a, **_k: (False, ""))
    monkeypatch.setattr(m, "set_submission_status_for_attempt", lambda *_a, **_k: 1)
    monkeypatch.setattr(m, "get_competition", lambda _cid: competition)
    monkeypatch.setattr(m, "list_competition_rules", lambda _cid: rules)
    monkeypatch.setattr(m, "clear_judge_results_for_attempt", lambda *_a, **_k: None)
    monkeypatch.setattr(m, "_publish_snapshot", lambda *_a, **_k: None)
    monkeypatch.setattr(m, "_remove_stale_agent_containers", lambda *_a, **_k: None)
    monkeypatch.setattr(
        m, "_prepare_workspace",
        lambda *_a, **_k: (str(workspace), "result.jsonl"),
    )
    monkeypatch.setattr(m, "_prune_stale_attempt_workspaces", lambda *_a, **_k: None)
    monkeypatch.setattr(
        m, "_prepare_agent_trace_attempt",
        lambda *_a, **_k: str(tmp_path / "trace"),
    )
    monkeypatch.setattr(m, runner_name, fake_runner)
    other_runner = (
        "_run_container_and_tail"
        if runner_name == "_run_container_topological"
        else "_run_container_topological"
    )
    monkeypatch.setattr(
        m, other_runner,
        lambda *_a, **_k: pytest.fail("不应调用另一种编排 runner"),
    )
    monkeypatch.setattr(
        m, "_finalize",
        lambda *_a, **_k: events.append("finalize"),
    )

    assert m._judge(7, endpoint=endpoint, attempt_id="attempt-1") == {
        "success": True,
    }
    assert captured["endpoint"]["protocol"] == expected_protocol
    assert captured["endpoint"]["api_key"] == temporary_key
    assert endpoint["api_key"] == real_key
    assert events == [
        "relay-start",
        f"run:{runner_name}",
        "relay-close",
        "finalize",
    ]


def _run(monkeypatch, running_seq, timeout_s, endpoint=None):
    fake = _FakeSubprocess(running_seq)
    monkeypatch.setattr(m, "subprocess", fake)
    monkeypatch.setattr(m.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(m, "_attempt_still_current", lambda *_a, **_k: True)
    ws = tempfile.mkdtemp(prefix="ajws_")
    os.makedirs(os.path.join(ws, "submission"), exist_ok=True)
    competition = {"title": "t", "description": "d"}
    endpoint = endpoint or {
        "harness": "codex",
        "protocol": "openai",
        "base_url": "https://model.example/v1",
        "api_key": "temporary-token",
        "model": "generic-model",
        "thinking_format": "none",
    }
    timed_out, ok = m._run_container_and_tail(
        submission_id=5, ws=ws, result_name="result_x.jsonl",
        competition=competition, rules=[], timeout_s=timeout_s, endpoint=endpoint,
    )
    return fake, ws, timed_out, ok


def test_run_args_have_no_rm_and_prerun_cleanup(monkeypatch):
    fake, ws, timed_out, ok = _run(monkeypatch, ["false"], timeout_s=600)
    run_call = next(c for c in fake.calls if len(c) > 1 and c[1] == "run")
    assert "--rm" not in run_call, "容器不应再带 --rm（否则退出即删，无法拷 .claude）"
    assert "-d" in run_call and "--name" in run_call
    # run 之前必须先有一次 docker rm -f（清同名残留）
    run_idx = fake.calls.index(run_call)
    pre = fake.calls[:run_idx]
    assert any(c[:3] == ["docker", "rm", "-f"] for c in pre), "run 前应先 docker rm -f 残留容器"


def test_normal_agent_container_receives_selected_endpoint_capabilities(monkeypatch):
    endpoint = {
        "id": 9,
        "harness": m.HARNESS_CODEX,
        "base_url": "https://model.example/v1",
        "api_key": "temporary-token",
        "model": "generic-model",
        "context_window_tokens": 131_072,
        "max_output_tokens": 16_384,
        "thinking_compatibility": False,
        "concurrency_limit": 1,
    }

    fake, _ws, _timed_out, _ok = _run(
        monkeypatch, ["false"], timeout_s=600, endpoint=endpoint,
    )

    run_call = next(c for c in fake.calls if len(c) > 1 and c[1] == "run")
    assert "AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS=131072" in run_call
    assert "AJ_ENDPOINT_MAX_OUTPUT_TOKENS=16384" in run_call
    assert "AJ_ENDPOINT_THINKING_ENABLED=0" in run_call


def test_normal_exit_does_not_copy_raw_claude_state(monkeypatch):
    fake, ws, timed_out, ok = _run(monkeypatch, ["false"], timeout_s=600)
    assert ok is True and timed_out is False
    subs = _docker_subcmds(fake.calls)
    assert "cp" not in subs
    assert any(c[:3] == ["docker", "rm", "-f"] for c in fake.calls)
    assert not os.path.isdir(os.path.join(ws, "submission", ".claude"))


def test_timeout_path_kills_without_copying_raw_state(monkeypatch):
    # inspect 一直 true + timeout_s=0 -> 命中超时分支
    fake, ws, timed_out, ok = _run(monkeypatch, ["true"], timeout_s=0)
    assert timed_out is True and ok is True
    subs = _docker_subcmds(fake.calls)
    assert "kill" in subs, "超时应 docker kill"
    assert "cp" not in subs
    assert not os.path.isdir(os.path.join(ws, "submission", ".claude"))


def test_run_does_not_copy_raw_codex_state(monkeypatch):
    endpoint = {
        "harness": m.HARNESS_CODEX,
        "base_url": "http://openai-compatible",
        "api_key": "k",
        "model": "m",
    }
    fake, ws, timed_out, ok = _run(monkeypatch, ["false"], timeout_s=600, endpoint=endpoint)
    assert ok is True and timed_out is False
    assert not any(len(c) > 1 and c[1] == "cp" for c in fake.calls)
    assert not os.path.isdir(os.path.join(ws, "submission", ".codex"))
    assert not os.path.isdir(os.path.join(ws, "submission", ".claude"))


def test_run_does_not_copy_raw_opencode_state(monkeypatch):
    endpoint = {
        "harness": m.HARNESS_OPENCODE,
        "base_url": "",
        "api_key": "k",
        "model": "",
    }
    fake, ws, timed_out, ok = _run(monkeypatch, ["false"], timeout_s=600, endpoint=endpoint)
    assert ok is True and timed_out is False
    assert not any(len(c) > 1 and c[1] == "cp" for c in fake.calls)
    assert not os.path.isdir(os.path.join(ws, "submission", ".opencode"))
    assert not os.path.isdir(os.path.join(ws, "submission", ".claude"))


def test_exec_harness_phase_streams_prompt_without_workspace_file(monkeypatch):
    ws = tempfile.mkdtemp(prefix="ajphase_")
    calls = []

    def fake_run(args, input_text, **kwargs):
        calls.append((list(args), input_text, dict(kwargs)))
        return _FakeProc(0, "")

    monkeypatch.setattr(m, "_run_process_with_input_limited", fake_run)

    m._exec_harness_phase(
        "aj_7", ws, "rule_9", "prompt containing result_secret.jsonl", 30,
        resume_session_id="11111111-1111-1111-1111-111111111111",
        result_filename="result_secret.rule_9.jsonl",
    )

    assert len(calls) == 1
    args, input_text, kwargs = calls[0]
    joined = " ".join(args)
    assert "AJ_PROMPT_FILE" not in joined
    assert ".aj_prompt_" not in joined
    assert "-i" in args
    assert "-e" in args and "DEBIAN_FRONTEND=noninteractive" in args
    assert input_text == "prompt containing result_secret.jsonl"
    assert kwargs["timeout"] == 30
    assert not any(name.startswith(".aj_prompt_") for name in os.listdir(ws))


def test_topological_orchestration_skips_blocked_rule(monkeypatch):
    ws = tempfile.mkdtemp(prefix="ajtopo_")
    os.makedirs(os.path.join(ws, "submission"), exist_ok=True)
    result_name = "result_topo.jsonl"
    open(os.path.join(ws, result_name), "w").close()
    rules = m.aj.normalize_rules([
        {"rule_id": 1, "rule_text": "基础运行", "value": 10, "dependencies": []},
        {"rule_id": 2, "rule_text": "依赖基础", "value": 20, "dependencies": [1]},
        {"rule_id": 3, "rule_text": "独立检查", "value": 30, "dependencies": []},
    ])
    phases = []
    writes = []
    trace_sessions = []

    class FakeSubprocess:
        def __init__(self):
            self.calls = []

        def run(self, args, **kwargs):
            self.calls.append(list(args))
            return _FakeProc(0, "false")

    def fake_exec(container_name, ws_arg, phase, prompt, timeout_s,
                  resume_session_id=None, result_filename=None, **_kwargs):
        phases.append((phase, resume_session_id))
        phase_result_path = os.path.join(ws_arg, result_filename or result_name)
        if phase == "setup":
            with open(os.path.join(ws_arg, ".aj_session_state.json"), "w", encoding="utf-8") as f:
                json.dump({"session_id": "11111111-1111-1111-1111-111111111111"}, f)
        elif phase == "rule_1":
            with open(phase_result_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"rule_id": 1, "result": "failed", "evidence": "no"}) + "\n")
            with open(os.path.join(ws_arg, ".aj_session_state.json"), "w", encoding="utf-8") as f:
                json.dump({"session_id": "22222222-2222-2222-2222-222222222222"}, f)
        elif phase == "rule_3":
            with open(phase_result_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"rule_id": 3, "result": "pass", "evidence": "ok"}) + "\n")
            with open(os.path.join(ws_arg, ".aj_session_state.json"), "w", encoding="utf-8") as f:
                json.dump({"session_id": "33333333-3333-3333-3333-333333333333"}, f)
        return _FakeProc(0, "")

    def fake_upsert(submission_id, attempt_id, rule_id, raw, effective, score, evidence):
        writes.append((rule_id, raw, effective, score, evidence))
        return 1

    def fake_sync(_container_name, ws_arg, _trace_dir, **_kwargs):
        state_path = os.path.join(ws_arg, ".aj_session_state.json")
        with open(state_path, "r", encoding="utf-8") as f:
            trace_sessions.append(json.load(f)["session_id"])
        return True

    fake_subprocess = FakeSubprocess()
    monkeypatch.setattr(m, "subprocess", fake_subprocess)
    monkeypatch.setattr(m, "_exec_harness_phase", fake_exec)
    monkeypatch.setattr(m, "_attempt_still_current", lambda *_a, **_k: True)
    monkeypatch.setattr(m, "_sync_claude_execution_trace", fake_sync)
    monkeypatch.setattr(m, "_publish_snapshot", lambda *_a, **_k: None)
    monkeypatch.setattr(m, "upsert_judge_result_for_attempt", fake_upsert)

    timed_out, ok = m._run_container_topological(
        submission_id=7,
        ws=ws,
        result_name=result_name,
        competition={"title": "拓扑赛"},
        rules=rules,
        timeout_s=600,
        endpoint={
            "harness": m.HARNESS_CLAUDE_CODE,
            "base_url": "http://x",
            "api_key": "k",
            "model": "m",
            "context_window_tokens": 131_072,
            "max_output_tokens": 16_384,
            "thinking_compatibility": False,
        },
        attempt_id="att",
    )
    assert (timed_out, ok) == (False, True)
    assert phases == [
        ("setup", None),
        ("rule_1", "11111111-1111-1111-1111-111111111111"),
        ("rule_3", "22222222-2222-2222-2222-222222222222"),
    ]
    run_call = next(
        call for call in fake_subprocess.calls
        if len(call) > 1 and call[1] == "run"
    )
    assert "AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS=131072" in run_call
    assert "AJ_ENDPOINT_MAX_OUTPUT_TOKENS=16384" in run_call
    assert "AJ_ENDPOINT_THINKING_ENABLED=0" in run_call
    # setup、每次真正执行的 resume、finally 都同步；依赖跳过的 rule_2 不伪造轨迹。
    assert trace_sessions == [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "33333333-3333-3333-3333-333333333333",
    ]
    by_rule = {row[0]: row for row in writes}
    assert by_rule[1][1:3] == ("failed", "failed")
    assert by_rule[2][1] is None and by_rule[2][2] == m.aj.EFF_SKIPPED
    assert by_rule[3][1:3] == ("pass", "pass")
    run_call = next(c for c in fake_subprocess.calls if len(c) > 1 and c[1] == "run")
    assert run_call[-1] == "tail -f /dev/null"
    apt_call = next(
        c for c in fake_subprocess.calls
        if len(c) > 1 and c[1] == "exec" and "apt-get update" in c[-1]
    )
    assert "-e" in apt_call and "DEBIAN_FRONTEND=noninteractive" in apt_call


def test_topological_claude_trace_syncs_before_long_phase_finishes(monkeypatch):
    ws = tempfile.mkdtemp(prefix="ajtopo_live_")
    os.makedirs(os.path.join(ws, "submission"), exist_ok=True)
    result_name = "result_live.jsonl"
    open(os.path.join(ws, result_name), "w").close()
    rules = m.aj.normalize_rules([
        {"rule_id": 1, "rule_text": "检查", "value": 10, "dependencies": []},
    ])
    phase_running = {"value": False}
    syncs_during_phase = []

    def fake_run(_args, **_kwargs):
        return _FakeProc(0, "false")

    def fake_exec(_container, ws_arg, phase, _prompt, _timeout, result_filename=None, **_kwargs):
        phase_running["value"] = True
        if phase == "setup":
            with open(os.path.join(ws_arg, ".aj_session_state.json"), "w", encoding="utf-8") as f:
                json.dump({"session_id": "11111111-1111-1111-1111-111111111111"}, f)
        else:
            with open(os.path.join(ws_arg, result_filename), "a", encoding="utf-8") as f:
                f.write(json.dumps({"rule_id": 1, "result": "pass", "evidence": "ok"}) + "\n")
        time.sleep(0.08)
        phase_running["value"] = False
        return _FakeProc(0, "")

    def fake_sync(_container, _ws, _trace_dir, **kwargs):
        if phase_running["value"]:
            syncs_during_phase.append(kwargs.get("default_phase"))
        return False

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    monkeypatch.setattr(m, "_exec_harness_phase", fake_exec)
    monkeypatch.setattr(m, "_sync_claude_execution_trace", fake_sync)
    monkeypatch.setattr(m, "_attempt_still_current", lambda *_a, **_k: True)
    monkeypatch.setattr(m, "_publish_snapshot", lambda *_a, **_k: None)
    monkeypatch.setattr(m, "upsert_judge_result_for_attempt", lambda *_a, **_k: 1)
    monkeypatch.setattr(m, "JUDGE_TRACE_SYNC_INTERVAL", 0.01)

    timed_out, ok = m._run_container_topological(
        submission_id=13,
        ws=ws,
        result_name=result_name,
        competition={"title": "live"},
        rules=rules,
        timeout_s=60,
        endpoint={
            "harness": m.HARNESS_CLAUDE_CODE,
            "base_url": "http://x",
            "api_key": "secret-key",
            "model": "model",
        },
        attempt_id="attempt-live",
    )

    assert (timed_out, ok) == (False, True)
    assert "setup" in syncs_during_phase or "rule_1" in syncs_during_phase


def test_hello_probe_request_requires_configured_values():
    req, err = m._hello_probe_request({
        "harness": m.HARNESS_CODEX,
        "base_url": "https://openai-compatible/v1",
        "api_key": "k",
        "model": "",
    })
    assert req is None
    assert "模型为空" in err


def test_hello_probe_request_uses_exact_endpoint_config():
    req, err = m._hello_probe_request({
        "harness": m.HARNESS_CODEX,
        "base_url": "https://openai-compatible/v1",
        "api_key": "k",
        "model": "configured-model",
    })
    assert err is None
    assert req.full_url == "https://openai-compatible/v1/chat/completions"
    assert json.loads(req.data.decode("utf-8"))["model"] == "configured-model"

    req, err = m._hello_probe_request({
        "harness": m.HARNESS_CLAUDE_CODE,
        "base_url": "https://anthropic-compatible",
        "api_key": "k",
        "model": "configured-claude",
    })
    assert err is None
    assert req.full_url == "https://anthropic-compatible/v1/messages"
    assert json.loads(req.data.decode("utf-8"))["model"] == "configured-claude"


def test_opencode_probe_uses_configured_url_and_model(monkeypatch):
    requests = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return Response()

    monkeypatch.setattr(m.urllib.request, "urlopen", fake_urlopen)
    ok, msg = m._probe_endpoint_once({
        "harness": m.HARNESS_OPENCODE,
        "base_url": "https://gate.example/custom/v1",
        "api_key": "gate-key",
        "model": "configured-gate-model",
    })

    assert ok is True and msg == "ok"
    assert len(requests) == 1
    request, timeout = requests[0]
    assert request.full_url == "https://gate.example/custom/v1/chat/completions"
    assert json.loads(request.data.decode("utf-8"))["model"] == "configured-gate-model"
    assert request.headers["Authorization"] == "Bearer gate-key"
    assert timeout == m.JUDGE_HELLO_TIMEOUT_SECONDS


def test_paused_opencode_recovery_reuses_configured_endpoint(monkeypatch):
    requested_urls = []
    requested_models = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

    def fake_urlopen(request, timeout):
        requested_urls.append(request.full_url)
        requested_models.append(json.loads(request.data.decode("utf-8"))["model"])
        return Response()

    monkeypatch.setattr(m.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(m.time, "sleep", lambda *_args, **_kwargs: None)
    endpoint = {
        "id": 41,
        "pool_kind": "quality_gate",
        "harness": m.HARNESS_OPENCODE,
        "base_url": "https://recovery.example/api/v1",
        "api_key": "recovery-key",
        "model": "recovery-model",
        "status": m.ENDPOINT_STATUS_PAUSED,
    }

    successes, message = m._probe_paused_endpoint_for_resume(endpoint)

    assert successes == m.PAUSED_PROBE_ATTEMPTS
    assert message == "ok"
    assert requested_urls == [
        "https://recovery.example/api/v1/chat/completions"
    ] * m.PAUSED_PROBE_ATTEMPTS
    assert requested_models == ["recovery-model"] * m.PAUSED_PROBE_ATTEMPTS


def test_probe_opencode_missing_key_fails_without_request(monkeypatch):
    called = []
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *_a, **_k: called.append(True))
    ok, msg = m._probe_endpoint_once({
        "harness": m.HARNESS_OPENCODE,
        "base_url": "",
        "api_key": "",
        "model": "",
    })
    assert ok is False
    assert "API Key" in msg
    assert called == []


def test_probe_error_message_redacts_key_and_control_characters():
    message = m._sanitize_probe_message(
        {"api_key": "secret-token"},
        "invalid Authorization: Bearer secret-token\r\nnext-line",
    )

    assert "secret-token" not in message
    assert "[redacted]" in message
    assert "\r" not in message
    assert "\n" not in message


def test_probe_endpoint_retries_configured_attempts(monkeypatch):
    calls = []

    def fake_probe_once(endpoint):
        calls.append(endpoint["id"])
        return False, "down"

    monkeypatch.setattr(m, "_probe_endpoint_once", fake_probe_once)
    monkeypatch.setattr(m.time, "sleep", lambda *_a, **_k: None)
    ok, msg = m._probe_endpoint({"id": 9}, attempts=5)
    assert ok is False
    assert msg == "down"
    assert calls == [9, 9, 9, 9, 9]


class _FakeCelery:
    def task(self, **_kwargs):
        def deco(fn):
            return fn
        return deco


class _FakeTaskSelf:
    class request:
        id = "req-1"

    def retry(self, **_kwargs):
        raise m.Retry()


def test_agent_judge_switches_endpoint_after_failed_hello(monkeypatch):
    bad = {"id": 1, "harness": m.HARNESS_CODEX, "base_url": "https://bad/v1",
           "api_key": "k1", "model": "m1", "concurrency_limit": 1}
    good = {"id": 2, "harness": m.HARNESS_CODEX, "base_url": "https://good/v1",
            "api_key": "k2", "model": "m2", "concurrency_limit": 1}
    disabled = []
    judged = []

    monkeypatch.setattr(m, "_ensure_judge_redis", lambda: None)
    monkeypatch.setattr(m, "get_ranking_submission",
                        lambda sid: {"id": sid, "competition_id": 7, "status": "Queued"})
    monkeypatch.setattr(m, "get_competition",
                        lambda cid: {"id": cid, "agent_judge_timeout_seconds": 60})
    monkeypatch.setattr(m, "_resolve_endpoints", lambda *_a, **_k: [bad, good])
    monkeypatch.setattr(m, "_probe_endpoint",
                        lambda ep: (ep["id"] == 2, "ok" if ep["id"] == 2 else "down"))
    monkeypatch.setattr(m, "_disable_unhealthy_endpoint",
                        lambda ep, reason: disabled.append((ep["id"], reason)))
    monkeypatch.setattr(m, "_judge", lambda sid, ep, *args: judged.append(ep["id"]) or {"success": True})

    task = m.register_ranking_agent_judge_task(_FakeCelery())
    assert task(_FakeTaskSelf(), 100) == {"success": True}
    assert disabled == [(1, "down")]
    assert judged == [2]


def test_failed_hello_pauses_endpoint(monkeypatch):
    paused = []
    monkeypatch.setattr(m, "pause_agent_judge_endpoint", lambda eid: paused.append(eid) or 1)

    m._disable_unhealthy_endpoint({"id": 17}, "down")

    assert paused == [17]


def test_paused_endpoint_resume_probe_requires_three_successes(monkeypatch):
    seq = iter([(True, "ok"), (False, "down"), (True, "ok"), (False, "down"), (True, "ok")])
    calls = []

    def fake_probe_once(ep):
        calls.append(ep["id"])
        return next(seq)

    monkeypatch.setattr(m, "_probe_endpoint_once", fake_probe_once)
    monkeypatch.setattr(m.time, "sleep", lambda *_a, **_k: None)

    ok_count, last_msg = m._probe_paused_endpoint_for_resume({"id": 18})

    assert ok_count == 3
    assert last_msg == "down"
    assert calls == [18, 18, 18, 18, 18]


class _FakePeriodicSelf:
    def __init__(self):
        self.scheduled = []

    def apply_async(self, **kwargs):
        self.scheduled.append(kwargs)


def test_paused_probe_task_resumes_healthy_paused_endpoint(monkeypatch):
    resumed = []
    ep = {"id": 19, "status": m.ENDPOINT_STATUS_PAUSED}

    monkeypatch.setattr(m, "_ensure_judge_redis", lambda: None)
    monkeypatch.setattr(m, "list_paused_agent_judge_endpoints", lambda: [ep])
    monkeypatch.setattr(m, "_probe_paused_endpoint_for_resume", lambda endpoint: (3, "ok"))
    monkeypatch.setattr(m, "resume_paused_agent_judge_endpoint",
                        lambda eid: resumed.append(eid) or 1)

    task = m.register_ranking_agent_judge_paused_probe_task(_FakeCelery())
    fake_self = _FakePeriodicSelf()
    assert task(fake_self, "owner") == {"success": True, "checked": 1, "resumed": 1}
    assert resumed == [19]
    assert fake_self.scheduled


def test_paused_probe_task_ignores_non_paused_endpoint(monkeypatch):
    resumed = []
    probed = []

    monkeypatch.setattr(m, "_ensure_judge_redis", lambda: None)
    monkeypatch.setattr(m, "list_paused_agent_judge_endpoints",
                        lambda: [{"id": 20, "status": "disabled"}])
    monkeypatch.setattr(m, "_probe_paused_endpoint_for_resume",
                        lambda endpoint: probed.append(endpoint["id"]) or (5, "ok"))
    monkeypatch.setattr(m, "resume_paused_agent_judge_endpoint",
                        lambda eid: resumed.append(eid) or 1)

    task = m.register_ranking_agent_judge_paused_probe_task(_FakeCelery())
    fake_self = _FakePeriodicSelf()
    assert task(fake_self, "owner") == {"success": True, "checked": 0, "resumed": 0}
    assert probed == []
    assert resumed == []
    assert fake_self.scheduled


def test_paused_probe_task_reschedules_when_run_lock_is_busy(monkeypatch):
    class BusyRunLockRedis:
        def get(self, key):
            if key == m.PAUSED_PROBE_OWNER_KEY:
                return "owner"
            return None

        def set(self, key, *_args, **kwargs):
            if key == m.PAUSED_PROBE_RUN_LOCK_KEY and kwargs.get("nx"):
                return False
            return True

    monkeypatch.setattr(m, "_ensure_judge_redis", lambda: BusyRunLockRedis())
    monkeypatch.setattr(
        m,
        "list_paused_agent_judge_endpoints",
        lambda: pytest.fail("run-lock busy path should not probe endpoints"),
    )

    task = m.register_ranking_agent_judge_paused_probe_task(_FakeCelery())
    fake_self = _FakePeriodicSelf()
    assert task(fake_self, "owner") == {
        "success": True,
        "reason": "paused probe already running",
    }
    assert fake_self.scheduled == [{
        "args": ["owner"],
        "countdown": m.PAUSED_PROBE_INTERVAL_SECONDS,
    }]


def test_agent_judge_requeues_when_every_endpoint_slot_is_busy(monkeypatch):
    class BusyRedis:
        def set(self, *_args, **_kwargs):
            return False

    statuses = []
    endpoint = {"id": 1, "harness": m.HARNESS_CODEX, "base_url": "https://busy/v1",
                "api_key": "k", "model": "m", "concurrency_limit": 1}

    monkeypatch.setattr(m, "_ensure_judge_redis", lambda: BusyRedis())
    monkeypatch.setattr(m, "get_ranking_submission",
                        lambda sid: {"id": sid, "competition_id": 7, "status": "Queued"})
    monkeypatch.setattr(m, "get_competition",
                        lambda cid: {"id": cid, "agent_judge_timeout_seconds": 60})
    monkeypatch.setattr(m, "_resolve_endpoints", lambda *_a, **_k: [endpoint])
    monkeypatch.setattr(
        m, "set_submission_status_for_attempt",
        lambda sid, attempt_id, status: statuses.append((sid, attempt_id, status)) or 1,
    )
    monkeypatch.setattr(m, "_publish_snapshot", lambda sid: None)
    monkeypatch.setattr(m.random, "randint", lambda *_a, **_k: 0)

    task = m.register_ranking_agent_judge_task(_FakeCelery())
    with pytest.raises(m.Retry):
        task(_FakeTaskSelf(), 101)
    assert statuses == [(101, None, "Queued")]
