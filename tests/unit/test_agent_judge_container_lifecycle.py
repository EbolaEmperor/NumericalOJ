# -*- coding: utf-8 -*-
"""纯逻辑单测：打榜赛 Agent-as-Judge 容器生命周期（不依赖 Docker / 不连生产）。

验证回收容器前会把容器内 harness 会话目录 docker cp 到宿主 submission 目录，且：
  - docker run 不再带 --rm（否则容器退出即删，没有拷出会话目录的窗口）；
  - run 之前会先 docker rm -f 同名残留容器；
  - 正常退出 / 超时 两条路径，都在「最终 docker rm -f」之前完成 docker cp。
做法：把模块里的 subprocess 换成假对象，记录所有 docker 调用并模拟其行为。
"""
import os
import tempfile
import json

import pytest

import oj_modules.tasks.ranking_agent_judge_tasks as m


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


def _run(monkeypatch, running_seq, timeout_s, endpoint=None):
    fake = _FakeSubprocess(running_seq)
    monkeypatch.setattr(m, "subprocess", fake)
    monkeypatch.setattr(m.time, "sleep", lambda *_a, **_k: None)
    ws = tempfile.mkdtemp(prefix="ajws_")
    os.makedirs(os.path.join(ws, "submission"), exist_ok=True)
    competition = {
        "title": "t", "description": "d",
        "agent_judge_base_url": "http://x", "agent_judge_api_key": "k", "agent_judge_model": "mdl",
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


def test_normal_exit_copies_claude_before_removal(monkeypatch):
    fake, ws, timed_out, ok = _run(monkeypatch, ["false"], timeout_s=600)
    assert ok is True and timed_out is False
    subs = _docker_subcmds(fake.calls)
    assert "cp" in subs, "回收前应 docker cp 出 .claude"
    # 找最后一次 rm -f（最终回收）与 cp 的位置：cp 必须在最终 rm 之前
    cp_idx = max(i for i, c in enumerate(fake.calls) if len(c) > 1 and c[1] == "cp")
    final_rm_idx = max(i for i, c in enumerate(fake.calls) if c[:3] == ["docker", "rm", "-f"])
    assert cp_idx < final_rm_idx, "docker cp 必须发生在最终 docker rm -f 之前"
    # cp 源应是容器内 ~/.claude
    cp_call = fake.calls[cp_idx]
    assert any(str(a).endswith(":/root/.claude") for a in cp_call)
    # .claude 落到了 submission 目录
    assert os.path.isdir(os.path.join(ws, "submission", ".claude"))


def test_timeout_path_kills_then_copies_then_removes(monkeypatch):
    # inspect 一直 true + timeout_s=0 -> 命中超时分支
    fake, ws, timed_out, ok = _run(monkeypatch, ["true"], timeout_s=0)
    assert timed_out is True and ok is True
    subs = _docker_subcmds(fake.calls)
    assert "kill" in subs, "超时应 docker kill"
    assert "cp" in subs, "超时回收前仍应拷 .claude"
    cp_idx = max(i for i, c in enumerate(fake.calls) if len(c) > 1 and c[1] == "cp")
    final_rm_idx = max(i for i, c in enumerate(fake.calls) if c[:3] == ["docker", "rm", "-f"])
    assert cp_idx < final_rm_idx
    assert os.path.isdir(os.path.join(ws, "submission", ".claude"))


def test_dump_container_claude_replaces_existing(monkeypatch):
    fake = _FakeSubprocess(["false"])
    monkeypatch.setattr(m, "subprocess", fake)
    ws = tempfile.mkdtemp(prefix="ajws_")
    sub = os.path.join(ws, "submission")
    os.makedirs(os.path.join(sub, ".claude", "stale"), exist_ok=True)  # 预置旧内容
    m._dump_container_claude("aj_9", ws)
    # 旧的 stale 子目录应被清掉（先 rmtree 再 cp）
    assert not os.path.exists(os.path.join(sub, ".claude", "stale"))
    assert os.path.isdir(os.path.join(sub, ".claude"))
    assert any(len(c) > 1 and c[1] == "cp" for c in fake.calls)


def test_run_copies_codex_state_for_codex_harness(monkeypatch):
    endpoint = {
        "harness": m.HARNESS_CODEX,
        "base_url": "http://openai-compatible",
        "api_key": "k",
        "model": "m",
    }
    fake, ws, timed_out, ok = _run(monkeypatch, ["false"], timeout_s=600, endpoint=endpoint)
    assert ok is True and timed_out is False
    cp_call = max((c for c in fake.calls if len(c) > 1 and c[1] == "cp"), key=fake.calls.index)
    assert any(str(a).endswith(":/workspace/.codex") for a in cp_call)
    assert os.path.isdir(os.path.join(ws, "submission", ".codex"))
    assert not os.path.isdir(os.path.join(ws, "submission", ".claude"))


def test_run_copies_opencode_state_for_opencode_harness(monkeypatch):
    endpoint = {
        "harness": m.HARNESS_OPENCODE,
        "base_url": "",
        "api_key": "k",
        "model": "",
    }
    fake, ws, timed_out, ok = _run(monkeypatch, ["false"], timeout_s=600, endpoint=endpoint)
    assert ok is True and timed_out is False
    cp_call = max((c for c in fake.calls if len(c) > 1 and c[1] == "cp"), key=fake.calls.index)
    assert any(str(a).endswith(":/workspace/.opencode") for a in cp_call)
    assert os.path.isdir(os.path.join(ws, "submission", ".opencode"))
    assert not os.path.isdir(os.path.join(ws, "submission", ".claude"))


def test_exec_harness_phase_streams_prompt_without_workspace_file(monkeypatch):
    ws = tempfile.mkdtemp(prefix="ajphase_")
    calls = []

    class FakeSubprocess:
        def run(self, args, **kwargs):
            calls.append((list(args), dict(kwargs)))
            return _FakeProc(0, "")

    monkeypatch.setattr(m, "subprocess", FakeSubprocess())

    m._exec_harness_phase(
        "aj_7", ws, "rule_9", "prompt containing result_secret.jsonl", 30,
        resume_session_id="11111111-1111-1111-1111-111111111111",
        result_filename="result_secret.rule_9.jsonl",
    )

    assert len(calls) == 1
    args, kwargs = calls[0]
    joined = " ".join(args)
    assert "AJ_PROMPT_FILE" not in joined
    assert ".aj_prompt_" not in joined
    assert "-i" in args
    assert "-e" in args and "DEBIAN_FRONTEND=noninteractive" in args
    assert kwargs["input"] == "prompt containing result_secret.jsonl"
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

    class FakeSubprocess:
        def __init__(self):
            self.calls = []

        def run(self, args, **kwargs):
            self.calls.append(list(args))
            return _FakeProc(0, "false")

    def fake_exec(container_name, ws_arg, phase, prompt, timeout_s,
                  resume_session_id=None, result_filename=None):
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

    fake_subprocess = FakeSubprocess()
    monkeypatch.setattr(m, "subprocess", fake_subprocess)
    monkeypatch.setattr(m, "_exec_harness_phase", fake_exec)
    monkeypatch.setattr(m, "_attempt_still_current", lambda *_a, **_k: True)
    monkeypatch.setattr(m, "_dump_container_harness_state", lambda *_a, **_k: None)
    monkeypatch.setattr(m, "_publish_snapshot", lambda *_a, **_k: None)
    monkeypatch.setattr(m, "upsert_judge_result_for_attempt", fake_upsert)

    timed_out, ok = m._run_container_topological(
        submission_id=7,
        ws=ws,
        result_name=result_name,
        competition={"title": "拓扑赛"},
        rules=rules,
        timeout_s=600,
        endpoint={"harness": m.HARNESS_CLAUDE_CODE, "base_url": "http://x", "api_key": "k", "model": "m"},
        attempt_id="att",
    )
    assert (timed_out, ok) == (False, True)
    assert phases == [
        ("setup", None),
        ("rule_1", "11111111-1111-1111-1111-111111111111"),
        ("rule_3", "22222222-2222-2222-2222-222222222222"),
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


def test_probe_opencode_uses_cli_with_cheapest_go_model(monkeypatch):
    calls = {}

    class Result:
        returncode = 0
        stdout = "hello"
        stderr = ""

    def fake_run(args, **kwargs):
        calls["args"] = list(args)
        calls["env"] = dict(kwargs["env"])
        calls["config"] = json.loads(calls["env"]["OPENCODE_CONFIG_CONTENT"])
        return Result()

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    ok, msg = m._probe_opencode_once({
        "harness": m.HARNESS_OPENCODE,
        "base_url": "",
        "api_key": "go-key",
        "model": "",
    })
    assert ok is True and msg == "ok"
    assert calls["args"][0:2] == ["docker", "run"]
    assert "--rm" in calls["args"]
    assert "--read-only" in calls["args"]
    assert "--cap-drop" in calls["args"] and "ALL" in calls["args"]
    assert "-v" not in calls["args"]
    assert m.JUDGE_IMAGE in calls["args"]
    assert calls["args"][-1] == (
        "mkdir -p /tmp/opencode_work /tmp/opencode_home /tmp/opencode_config "
        "/tmp/opencode_data /tmp/opencode_state /tmp/opencode_cache && "
        "cd /tmp/opencode_work && opencode run --model %s hello"
    ) % m.OPENCODE_GO_HELLO_MODEL
    assert calls["env"]["OPENCODE_API_KEY"] == "go-key"
    assert calls["config"]["model"] == m.OPENCODE_GO_HELLO_MODEL
    assert calls["config"]["enabled_providers"] == ["opencode-go"]


def test_probe_opencode_missing_key_fails_without_cli(monkeypatch):
    called = []
    monkeypatch.setattr(m.subprocess, "run", lambda *_a, **_k: called.append(True))
    ok, msg = m._probe_opencode_once({
        "harness": m.HARNESS_OPENCODE,
        "base_url": "",
        "api_key": "",
        "model": "",
    })
    assert ok is False
    assert "API Key" in msg
    assert called == []


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
