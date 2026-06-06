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
    # 给定可测的 UID 基线，保证 NPROC 被施加（非 Linux 无 /proc 时基线为 None）
    monkeypatch.setattr(judger_core, "_current_uid_task_count", lambda: 100)
    judger_core.set_run_limits(1.0, 4096)()
    whichs = {c[0] for c in rec.calls}
    assert resource.RLIMIT_NPROC in whichs   # 防 fork 炸弹
    assert resource.RLIMIT_FSIZE in whichs   # 防写满磁盘
    assert resource.RLIMIT_CPU in whichs
    assert resource.RLIMIT_AS in whichs


def test_set_run_limits_apply_as_false_skips_as(monkeypatch):
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)
    monkeypatch.setattr(judger_core, "_current_uid_task_count", lambda: 100)
    judger_core.set_run_limits(1.0, 4096, apply_as=False)()
    as_calls = [c for c in rec.calls if c[0] == resource.RLIMIT_AS]
    assert as_calls == []                    # Octave 路径默认不施加 RLIMIT_AS
    # 但 CPU/NPROC/FSIZE 仍施加
    assert any(c[0] == resource.RLIMIT_CPU for c in rec.calls)
    assert any(c[0] == resource.RLIMIT_NPROC for c in rec.calls)


def test_nproc_limit_is_relative_to_baseline(monkeypatch):
    """回归（2026-06-06 线上事故）：RLIMIT_NPROC 必须按「当前 UID 基线 + 余量」设置，
    且严格高于基线。旧实现写死 256，当 ebola UID 常驻线程（泄漏的 Chrome + worker + web）
    超过 256 时，沙箱内 timeout fork 用户程序一律 EAGAIN，判题整体瘫痪。"""
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)
    monkeypatch.setattr(judger_core, "_current_uid_task_count", lambda: 400)
    monkeypatch.setattr(judger_core, "_RLIMIT_NPROC_ABS", 0)
    judger_core.set_run_limits(1.0, 4096)()
    nproc = [c[1] for c in rec.calls if c[0] == resource.RLIMIT_NPROC]
    assert nproc, "应设置 RLIMIT_NPROC"
    soft, hard = nproc[0]
    assert soft > 400                                       # 关键：高于基线，合法 fork 不被误杀
    assert soft == 400 + judger_core._RLIMIT_NPROC_HEADROOM


def test_nproc_limit_skipped_when_baseline_unknown(monkeypatch):
    """无法读取 /proc 统计基线时（如非 Linux 开发机），宁可不设 NPROC 也不误杀合法运行。"""
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)
    monkeypatch.setattr(judger_core, "_current_uid_task_count", lambda: None)
    monkeypatch.setattr(judger_core, "_RLIMIT_NPROC_ABS", 0)
    judger_core.set_run_limits(1.0, 4096)()
    assert not [c for c in rec.calls if c[0] == resource.RLIMIT_NPROC]
    assert any(c[0] == resource.RLIMIT_CPU for c in rec.calls)   # 其它限制仍照常


def test_nproc_absolute_override(monkeypatch):
    """显式设了绝对值（JUDGER_RLIMIT_NPROC_ABS）时按绝对值，作为运维逃生阀。"""
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)
    monkeypatch.setattr(judger_core, "_RLIMIT_NPROC_ABS", 777)
    judger_core.set_run_limits(1.0, 4096)()
    nproc = [c[1] for c in rec.calls if c[0] == resource.RLIMIT_NPROC]
    assert nproc and nproc[0] == (777, 777)


def test_cpu_limit_is_multithread_aware(monkeypatch):
    """回归（2026-06-06 Octave 全 Nonzero Exit）：RLIMIT_CPU 限的是进程「累计 CPU 秒（所有线程
    之和）」。Octave/MATLAB 的 BLAS/MKL 仅启动就要 ~4 CPU-秒（跨数十线程在百毫秒墙钟内烧完），
    若按墙钟 TLE(=1s) 设 1 秒 CPU 上限会被秒杀。CPU 上限必须按 核数 × ⌈墙钟⌉ + 启动余量 计，
    远高于旧实现的 max(1,int(秒))=1。墙钟仍由 coreutils timeout 兜底。"""
    rec = _RecordingSetrlimit()
    monkeypatch.setattr(resource, "setrlimit", rec)
    monkeypatch.setattr(judger_core, "_current_uid_task_count", lambda: 100)
    judger_core.set_run_limits(1.1, 4096)()
    cpu = [c[1] for c in rec.calls if c[0] == resource.RLIMIT_CPU]
    assert cpu, "应设置 RLIMIT_CPU"
    soft, hard = cpu[0]
    # 必须高于 Octave ~4 CPU-秒的启动开销（旧实现是 1，必被秒杀）
    assert soft > 4
    # 按 核数 × ⌈1.1⌉(=2) + 启动余量 计
    assert soft == judger_core._CPU_COUNT * 2 + judger_core._RLIMIT_CPU_STARTUP_BUFFER_SEC
    assert hard > soft


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
