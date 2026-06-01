# -*- coding: utf-8 -*-
"""沙箱新增加固的单测：RLIMIT_NPROC/FSIZE、Python 兜底超时、运行目录清理保留图片。"""
import os
import resource

from oj_modules import judger_core


class _RecordingSetrlimit:
    def __init__(self):
        self.calls = []

    def __call__(self, which, limits):
        self.calls.append((which, limits))


def test_set_run_limits_sets_nproc_and_fsize(monkeypatch):
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)
    judger_core.set_run_limits(1.0, 4096)()
    whichs = {c[0] for c in rec.calls}
    assert resource.RLIMIT_NPROC in whichs   # 防 fork 炸弹
    assert resource.RLIMIT_FSIZE in whichs   # 防写满磁盘
    assert resource.RLIMIT_CPU in whichs
    assert resource.RLIMIT_AS in whichs


def test_set_run_limits_apply_as_false_skips_as(monkeypatch):
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)
    judger_core.set_run_limits(1.0, 4096, apply_as=False)()
    as_calls = [c for c in rec.calls if c[0] == resource.RLIMIT_AS]
    assert as_calls == []                    # Octave 路径默认不施加 RLIMIT_AS
    # 但 CPU/NPROC/FSIZE 仍施加
    assert any(c[0] == resource.RLIMIT_CPU for c in rec.calls)
    assert any(c[0] == resource.RLIMIT_NPROC for c in rec.calls)


def test_guard_timeout_exceeds_coreutils():
    # Python 兜底超时必须大于 coreutils 超时，保证 coreutils 先动作
    assert judger_core._guard_timeout(2.0) > 2.0
    assert judger_core._guard_timeout(0) >= 1.0


def test_cleanup_run_artifacts_keeps_images(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    sid = "eoj-batch-999"
    run_dir = os.path.join(str(tmp_path), sid)
    os.makedirs(run_dir, exist_ok=True)
    # 临时产物 + 一张输出图片
    for name in ("a.out", "main.c", "input_0.txt", "output_0.txt"):
        with open(os.path.join(run_dir, name), "w") as f:
            f.write("x")
    img = os.path.join(run_dir, "output_0.png")
    with open(img, "wb") as f:
        f.write(b"\x89PNG")

    judger_core.cleanup_run_artifacts(sid)

    assert not os.path.exists(os.path.join(run_dir, "a.out"))        # 编译产物已清
    assert not os.path.exists(os.path.join(run_dir, "output_0.txt"))  # 输出文本已清
    assert os.path.isfile(img)                                        # 图片保留（结果页要用）


def test_cleanup_run_artifacts_for_submission_prefixes(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    # 三种命名都应被清理临时产物
    for sid in ("eoj-batch-7", "eoj-quick-compile-7", "eoj-7-1"):
        d = os.path.join(str(tmp_path), sid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "a.out"), "w") as f:
            f.write("x")
    # 不同提交号不应被误清
    other = os.path.join(str(tmp_path), "eoj-70-1")
    os.makedirs(other, exist_ok=True)
    with open(os.path.join(other, "a.out"), "w") as f:
        f.write("x")

    judger_core.cleanup_run_artifacts_for_submission(7)

    assert not os.path.exists(os.path.join(str(tmp_path), "eoj-batch-7", "a.out"))
    assert not os.path.exists(os.path.join(str(tmp_path), "eoj-7-1", "a.out"))
    assert os.path.isfile(os.path.join(other, "a.out"))   # eoj-70-1 未受影响
