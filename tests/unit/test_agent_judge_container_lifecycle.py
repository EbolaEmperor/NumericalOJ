# -*- coding: utf-8 -*-
"""纯逻辑单测：打榜赛 Agent-as-Judge 容器生命周期（不依赖 Docker / 不连生产）。

验证回收容器前会把容器内 ~/.claude docker cp 到宿主 submission 目录，且：
  - docker run 不再带 --rm（否则容器退出即删，没有拷出 .claude 的窗口）；
  - run 之前会先 docker rm -f 同名残留容器；
  - 正常退出 / 超时 两条路径，都在「最终 docker rm -f」之前完成 docker cp。
做法：把模块里的 subprocess 换成假对象，记录所有 docker 调用并模拟其行为。
"""
import os
import tempfile

import oj_modules.tasks.ranking_agent_judge_tasks as m


class _FakeProc:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class _FakeSubprocess:
    """假 subprocess：记录每次 docker 调用；inspect 按预设序列返回 running 状态；
    cp 时真的在目标里建出 .claude（模拟拷贝成功）。"""

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
            dest_dir = args[-1]
            os.makedirs(os.path.join(dest_dir, ".claude"), exist_ok=True)
            return _FakeProc(0, "")
        return _FakeProc(0, "")


def _docker_subcmds(calls):
    return [c[1] for c in calls if len(c) > 1 and c[0] == "docker"]


def _run(monkeypatch, running_seq, timeout_s):
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
        competition=competition, rules=[], timeout_s=timeout_s,
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
