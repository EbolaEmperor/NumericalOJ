import importlib.util
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "deploy" / "process_guard.py"
SPEC = importlib.util.spec_from_file_location("deploy_process_guard", MODULE_PATH)
process_guard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(process_guard)


def _fake_process(proc_root, pid, cwd, argv):
    process_dir = proc_root / str(pid)
    process_dir.mkdir()
    (process_dir / "cmdline").write_bytes(b"\0".join(os.fsencode(arg) for arg in argv) + b"\0")
    (process_dir / "cwd").symlink_to(cwd, target_is_directory=True)


def test_supervisor_requires_exact_nul_separated_config_argument(tmp_path):
    target = tmp_path / "oj"
    target.mkdir()
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    _fake_process(
        proc_root,
        101,
        target,
        ["/usr/bin/python3", "/usr/local/bin/supervisord", "-c", "deploy/supervisor/web.conf"],
    )
    _fake_process(
        proc_root,
        102,
        target,
        ["/usr/bin/python3", "/usr/local/bin/supervisord", "-c", "evil-web.conf"],
    )

    assert process_guard.is_supervisor_process(101, str(target), "web", proc_root=proc_root)
    assert not process_guard.is_supervisor_process(102, str(target), "web", proc_root=proc_root)
    assert process_guard.matching_pids(
        str(target), "web", "supervisor", proc_root=proc_root
    ) == [101]


def test_processes_outside_target_are_never_matched(tmp_path):
    target = tmp_path / "oj"
    other = tmp_path / "other"
    target.mkdir()
    other.mkdir()
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    _fake_process(
        proc_root,
        201,
        other,
        ["python3", "-m", "gunicorn", "oj:app"],
    )

    assert not process_guard.is_app_process(201, str(target), "web", proc_root=proc_root)


def test_gunicorn_and_celery_parent_and_pool_processes_are_detected(tmp_path):
    target = tmp_path / "oj"
    target.mkdir()
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    _fake_process(proc_root, 301, target, ["python3", "-m", "gunicorn", "oj:app"])
    _fake_process(
        proc_root,
        302,
        target,
        ["python3", "-m", "celery", "-A", "oj.celery", "worker", "-Q", "celery"],
    )
    _fake_process(
        proc_root,
        303,
        target,
        ["[celeryd: judge@computing:ForkPoolWorker-1]"],
    )

    assert process_guard.matching_pids(str(target), "web", "app", proc_root=proc_root) == [301]
    assert process_guard.matching_pids(str(target), "celery", "app", proc_root=proc_root) == [302, 303]
    assert process_guard.matching_pids(
        str(target), "celery", "app", proc_root=proc_root, queue="celery"
    ) == [302]


def test_missing_proc_root_fails_closed(tmp_path):
    missing = tmp_path / "missing-proc"
    try:
        process_guard.matching_pids("/tmp/oj", "web", "app", proc_root=missing)
    except RuntimeError as exc:
        assert "unavailable" in str(exc)
    else:
        raise AssertionError("missing proc filesystem must not be treated as an empty process list")


def test_similar_arguments_are_not_treated_as_process_entrypoints(tmp_path):
    target = tmp_path / "oj"
    target.mkdir()
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    _fake_process(
        proc_root,
        401,
        target,
        ["python3", "unrelated.py", "supervisord", "-c", "deploy/supervisor/web.conf"],
    )
    _fake_process(proc_root, 402, target, ["python3", "tool.py", "gunicorn", "oj:app"])
    _fake_process(
        proc_root,
        403,
        target,
        ["python3", "tool.py", "ForkPoolWorker", "worker", "-A", "oj.celery"],
    )
    _fake_process(
        proc_root,
        404,
        target,
        ["[celeryd: impostor@computing:ForkPoolWorker-1] trailing"],
    )

    assert not process_guard.is_supervisor_process(401, str(target), "web", proc_root=proc_root)
    assert not process_guard.is_app_process(402, str(target), "web", proc_root=proc_root)
    assert not process_guard.is_app_process(403, str(target), "celery", proc_root=proc_root)
    assert not process_guard.is_app_process(404, str(target), "celery", proc_root=proc_root)
