# -*- coding: utf-8 -*-
"""Agent Judge 镜像入口必须边执行边转发 CLI 输出。"""

import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import threading


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "docker" / "agent_judge" / "run_harness"


def _load_run_harness():
    loader = importlib.machinery.SourceFileLoader("agent_judge_run_harness_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_run_relays_first_line_before_child_exits(monkeypatch, tmp_path):
    module = _load_run_harness()
    first_line = threading.Event()
    writes = []
    result = []

    class Recorder:
        def write(self, value):
            writes.append(value)
            if "first" in value:
                first_line.set()

        def flush(self):
            return None

    monkeypatch.setattr(module.sys, "stdout", Recorder())
    release = tmp_path / "release"
    command = [
        sys.executable,
        "-c",
        (
            "import pathlib,time; print('first',flush=True); "
            f"p=pathlib.Path({str(release)!r}); "
            "exec(\"while not p.exists():\\n time.sleep(0.02)\"); "
            "print('second',flush=True)"
        ),
    ]
    env = dict(os.environ, AJ_WORKSPACE=str(tmp_path))
    worker = threading.Thread(target=lambda: result.append(module._run(command, env=env)))
    worker.start()

    assert first_line.wait(3)
    assert worker.is_alive(), "收到 first 时子进程应仍在执行，证明不是结束后一次性回放"
    release.write_text("go", encoding="utf-8")
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert result[0].returncode == 0
    assert result[0].stdout == "first\nsecond\n"
    assert "".join(writes) == "first\nsecond\n"
