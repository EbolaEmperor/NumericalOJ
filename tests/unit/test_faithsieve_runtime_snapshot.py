"""单次评测的运行选项冻结及 Celery 重入；全部使用临时目录和假配置。"""

from concurrent.futures import ThreadPoolExecutor
import errno
import json
import os
import stat

import pytest

from backend.oj_modules.faithsieve import runtime_snapshot


@pytest.mark.parametrize("effort", [None, "low", "medium"])
def test_initial_setting_is_frozen_once_and_reentry_does_not_read_settings(tmp_path, monkeypatch, effort):
    calls = []
    def getter(endpoint_id):
        calls.append(endpoint_id)
        return effort
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort", getter)
    assert runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4) == effort
    path = tmp_path / runtime_snapshot.SNAPSHOT_FILENAME
    original = path.read_bytes()
    changed_at = path.stat().st_mtime_ns
    assert json.loads(original) == {"endpoint_id": 4, "initial_reasoning_effort": effort}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort",
                        lambda _endpoint_id: pytest.fail("重入不能读取已变更的设置"))
    assert runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4) == effort
    assert path.read_bytes() == original and path.stat().st_mtime_ns == changed_at
    assert calls == [4]
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("name", ["source-extraction.json", "role-000001-attempt-1.json", "damaged.json"])
def test_old_checkpoint_without_snapshot_keeps_default_none(tmp_path, monkeypatch, name):
    directory = tmp_path / "faithsieve-work/checkpoints"
    directory.mkdir(parents=True)
    path = directory / name
    path.write_bytes(b"original or damaged old checkpoint")
    original = path.read_bytes()
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort",
                        lambda _endpoint_id: pytest.fail("旧评测不能套用今天的新设置"))
    assert runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4) is None
    assert runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4) is None
    assert path.read_bytes() == original
    snapshot = json.loads((tmp_path / runtime_snapshot.SNAPSHOT_FILENAME).read_bytes())
    assert snapshot == {"endpoint_id": 4, "initial_reasoning_effort": None}


def test_empty_checkpoint_directory_is_a_fresh_attempt(tmp_path, monkeypatch):
    (tmp_path / "faithsieve-work/checkpoints").mkdir(parents=True)
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort", lambda _id: "medium")
    assert runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4) == "medium"


@pytest.mark.parametrize("payload", [
    {}, [], None, {"endpoint_id": 4}, {"initial_reasoning_effort": None},
    {"endpoint_id": True, "initial_reasoning_effort": None},
    {"endpoint_id": "4", "initial_reasoning_effort": "low"},
    {"endpoint_id": 4.0, "initial_reasoning_effort": "medium"},
    {"endpoint_id": 5, "initial_reasoning_effort": None},
    {"endpoint_id": 4, "initial_reasoning_effort": "default"},
    {"endpoint_id": 4, "initial_reasoning_effort": True},
    {"endpoint_id": 4, "initial_reasoning_effort": {}},
    {"endpoint_id": 4, "initial_reasoning_effort": None, "extra": 1},
])
def test_invalid_snapshot_is_not_overwritten_or_defaulted(tmp_path, monkeypatch, payload):
    path = tmp_path / runtime_snapshot.SNAPSHOT_FILENAME
    data = json.dumps(payload).encode()
    path.write_bytes(data)
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort",
                        lambda _id: pytest.fail("损坏快照不能发起新配置请求"))
    with pytest.raises(runtime_snapshot.FaithSieveRuntimeSnapshotError):
        runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4)
    assert path.read_bytes() == data


@pytest.mark.parametrize("data", [
    b'{"endpoint_id":4,"initial_reasoning_effort":null,"endpoint_id":4}',
    b'{"endpoint_id":4,"initial_reasoning_effort":NaN}',
    b'{"endpoint_id":4,"initial_reasoning_effort":Infinity}',
    b'{"endpoint_id":4,"initial_reasoning_effort":null}{}',
    b'```json\n{"endpoint_id":4,"initial_reasoning_effort":null}\n```',
    b'\xff', b' ' * 4097,
])
def test_nonstandard_or_unbounded_snapshot_is_rejected(tmp_path, monkeypatch, data):
    path = tmp_path / runtime_snapshot.SNAPSHOT_FILENAME
    path.write_bytes(data)
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort", lambda _id: pytest.fail("不能读设置"))
    with pytest.raises(runtime_snapshot.FaithSieveRuntimeSnapshotError):
        runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4)
    assert path.read_bytes() == data


@pytest.mark.parametrize("effort", ["default", "high", "LOW", True, 1, [], {}])
def test_invalid_initial_setting_never_creates_snapshot(tmp_path, monkeypatch, effort):
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort", lambda _id: effort)
    with pytest.raises(runtime_snapshot.FaithSieveRuntimeSnapshotError, match="思考强度"):
        runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4)
    assert not (tmp_path / runtime_snapshot.SNAPSHOT_FILENAME).exists()


@pytest.mark.parametrize("endpoint_id", [None, True, False, 0, -4, 4.0, "4"])
def test_snapshot_requires_integer_endpoint_identity(tmp_path, monkeypatch, endpoint_id):
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort", lambda _id: pytest.fail("不能读设置"))
    with pytest.raises(runtime_snapshot.FaithSieveRuntimeSnapshotError, match="端点 ID"):
        runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, endpoint_id)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("name", [runtime_snapshot.SNAPSHOT_FILENAME, runtime_snapshot._LOCK_FILENAME])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "fifo"])
def test_snapshot_and_lock_reject_unsafe_files(tmp_path, monkeypatch, name, kind):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = tmp_path / "outside"
    target.write_bytes(b'{"endpoint_id":4,"initial_reasoning_effort":"low"}' if name.endswith("json") else b"")
    path = workspace / name
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, path)
    elif kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort", lambda _id: pytest.fail("不能读设置"))
    with pytest.raises(runtime_snapshot.FaithSieveRuntimeSnapshotError):
        runtime_snapshot.freeze_initial_reasoning_effort(workspace, 4)


@pytest.mark.parametrize("directory", ["faithsieve-work", "faithsieve-work/checkpoints"])
def test_legacy_checkpoint_detection_never_follows_directory_symlinks(tmp_path, monkeypatch, directory):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = tmp_path / "outside"
    target.mkdir()
    path = workspace / directory
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort", lambda _id: pytest.fail("不能读设置"))
    with pytest.raises(runtime_snapshot.FaithSieveRuntimeSnapshotError):
        runtime_snapshot.freeze_initial_reasoning_effort(workspace, 4)
    assert list(target.iterdir()) == []


def test_concurrent_first_entries_share_one_frozen_setting(tmp_path, monkeypatch):
    for index in range(20):
        workspace = tmp_path / str(index)
        workspace.mkdir()
        calls = []
        def getter(endpoint_id):
            calls.append(endpoint_id)
            return "low" if len(calls) == 1 else "medium"
        monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort", getter)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: runtime_snapshot.freeze_initial_reasoning_effort(workspace, 4), range(4)))
        assert results == ["low"] * 4 and calls == [4]


def test_competing_lock_creator_reopens_without_create_flags(tmp_path, monkeypatch):
    original_open = os.open
    lock_flags = []
    def competing_open(path, flags, *args, **kwargs):
        if path == runtime_snapshot._LOCK_FILENAME:
            lock_flags.append(flags)
            if len(lock_flags) == 1:
                fd = original_open(path, flags, *args, **kwargs)
                os.close(fd)
                raise FileExistsError(errno.EEXIST, "another caller created the lock")
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(runtime_snapshot.os, "open", competing_open)
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort", lambda _id: "low")
    assert runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4) == "low"
    assert len(lock_flags) == 2
    assert lock_flags[0] & os.O_CREAT and lock_flags[0] & os.O_EXCL
    assert not lock_flags[1] & (os.O_CREAT | os.O_EXCL)
    assert all(flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK for flags in lock_flags)
    lock = tmp_path / runtime_snapshot._LOCK_FILENAME
    assert lock.is_file() and lock.stat().st_size == 0 and lock.stat().st_nlink == 1


@pytest.mark.parametrize("existing", [False, True])
def test_missing_lock_creation_or_reopen_fails_without_retry(tmp_path, monkeypatch, existing):
    original_open = os.open
    lock_flags = []
    def missing_open(path, flags, *args, **kwargs):
        if path == runtime_snapshot._LOCK_FILENAME:
            lock_flags.append(flags)
            if existing and len(lock_flags) == 1:
                raise FileExistsError(errno.EEXIST, "lock existed during creation")
            raise FileNotFoundError(errno.ENOENT, "lock is absent")
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(runtime_snapshot.os, "open", missing_open)
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort",
                        lambda _id: pytest.fail("未取得锁不能读取配置"))
    with pytest.raises(runtime_snapshot.FaithSieveRuntimeSnapshotError, match="安全读取或保存"):
        runtime_snapshot.freeze_initial_reasoning_effort(tmp_path, 4)
    assert len(lock_flags) == (2 if existing else 1)
    assert not (tmp_path / runtime_snapshot.SNAPSHOT_FILENAME).exists()


def test_workflow_adapter_passes_frozen_effort_only_to_pure_workflow(tmp_path, monkeypatch):
    from backend.oj_modules.faithsieve import judge, workflow
    from backend.oj_modules.tasks import faithsieve_tasks
    frozen_reads, workflow_calls, judge_calls = [], [], []
    monkeypatch.setattr(runtime_snapshot, "get_faithsieve_pure_reasoning_effort",
                        lambda endpoint_id: frozen_reads.append(endpoint_id) or "low")
    monkeypatch.setattr(faithsieve_tasks, "resolve_launch_endpoint", lambda *_args, **_kwargs: {"id": 4})
    monkeypatch.setattr(faithsieve_tasks, "ensure_agent_workspace", lambda _session_id: tmp_path)
    monkeypatch.setattr(faithsieve_tasks, "_submission_pdf", lambda _id: b"%PDF-local")
    monkeypatch.setattr(judge, "FaithSieveJudgeAgent", lambda **options: judge_calls.append(options) or object())
    monkeypatch.setattr(workflow, "run_faithsieve_workflow", lambda **options: workflow_calls.append(options) or "result")
    run = {"attempt_id": "a" * 32, "harness": "pi", "endpoint_id": 4, "submission_id": 12}
    problem = {"title": "题目", "content": "条件与结论"}
    assert faithsieve_tasks._execute_workflow(run, problem) == "result"
    assert faithsieve_tasks._execute_workflow(run, problem) == "result"
    assert [call["initial_reasoning_effort"] for call in workflow_calls] == ["low", "low"]
    assert frozen_reads == [4]
    assert all("initial_reasoning_effort" not in call for call in judge_calls)
