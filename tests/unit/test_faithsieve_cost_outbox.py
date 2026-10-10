"""费用展示只读宿主 outbox，不能把等待补账误报为已完整结算。"""

import json
import os

import pytest

from backend.oj_modules.faithsieve import cost_outbox


@pytest.fixture
def outbox(tmp_path, monkeypatch):
    root = tmp_path / "agent-workspaces"
    monkeypatch.setattr(cost_outbox.workspace_store, "AGENT_WORKSPACE_ROOT", root)
    directory = root / ".usage-outbox"
    directory.mkdir(mode=0o700, parents=True)
    return directory


def write_event(directory, name="opaque-request.json", **changes):
    path = directory / name
    event = {"version": 1, "session_id": "session-1", "task_id": "task-1",
             "source": "relay_openai", "usage_event_id": "request-1", **changes}
    path.write_text(json.dumps(event))
    path.chmod(0o600)
    return path


def test_absent_directory_is_read_only_and_does_not_initialize_workspaces(tmp_path, monkeypatch):
    root = tmp_path / "absent"
    monkeypatch.setattr(cost_outbox.workspace_store, "AGENT_WORKSPACE_ROOT", root)
    def forbidden(*_args, **_options):
        pytest.fail("费用读取不能创建受管目录")
    monkeypatch.setattr(os, "mkdir", forbidden)
    assert cost_outbox.read_pending_usage_events({"session-1": {"task-1"}}) == []
    assert not root.exists()


def test_only_formal_session_turns_return_original_idempotency_keys(outbox):
    path = write_event(outbox)
    write_event(outbox, "other-session.json", session_id="other-session")
    write_event(outbox, "other-turn.json", task_id="other-task")
    before = {p: (p.stat().st_mtime_ns, p.stat().st_mode, p.read_bytes()) for p in outbox.iterdir()}
    assert cost_outbox.read_pending_usage_events({"session-1": {"task-1"}}) == [
        ("session-1", "task-1", "relay_openai", "request-1"),
    ]
    assert path.name == "opaque-request.json"
    assert before == {p: (p.stat().st_mtime_ns, p.stat().st_mode, p.read_bytes()) for p in outbox.iterdir()}


def test_repeated_original_keys_are_returned_once_without_hash_validation(outbox):
    write_event(outbox, "one.json")
    write_event(outbox, "two.json")
    assert cost_outbox.read_pending_usage_events({"session-1": {"task-1"}}) == [
        ("session-1", "task-1", "relay_openai", "request-1"),
    ]


@pytest.mark.parametrize("corrupt", ["symlink", "hardlink", "file_mode", "directory_mode", "json", "duplicate", "version", "identity", "size", "fifo"])
def test_unsafe_or_unreadable_outbox_is_unknown_instead_of_empty(outbox, corrupt):
    path = write_event(outbox)
    if corrupt in {"symlink", "hardlink"}:
        original = outbox.parent / "outside.json"
        path.rename(original)
        if corrupt == "symlink": path.symlink_to(original)
        else: os.link(original, path)
    elif corrupt == "file_mode": path.chmod(0o644)
    elif corrupt == "directory_mode": outbox.chmod(0o755)
    elif corrupt == "json": path.write_text("{")
    elif corrupt == "duplicate": path.write_text('{"version":1,"version":1}')
    elif corrupt == "version": write_event(outbox, version=True)
    elif corrupt == "identity": write_event(outbox, usage_event_id="")
    elif corrupt == "size": path.write_bytes(b" " * (cost_outbox._MAX_RECORD_BYTES + 1))
    elif corrupt == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    assert cost_outbox.read_pending_usage_events({"session-1": {"task-1"}}) is None


def test_symlinked_ancestor_is_not_followed(outbox, monkeypatch):
    write_event(outbox)
    link = outbox.parent.parent / "linked-root"
    link.symlink_to(outbox.parent, target_is_directory=True)
    monkeypatch.setattr(cost_outbox.workspace_store, "AGENT_WORKSPACE_ROOT", link)
    assert cost_outbox.read_pending_usage_events({"session-1": {"task-1"}}) is None


def test_outbox_removal_during_read_is_a_safe_reconciliation_race(outbox, monkeypatch):
    write_event(outbox)
    original = cost_outbox._read_event
    def removed(directory, name):
        os.unlink(name, dir_fd=directory)
        return original(directory, name)
    monkeypatch.setattr(cost_outbox, "_read_event", removed)
    assert cost_outbox.read_pending_usage_events({"session-1": {"task-1"}}) == []


def test_display_budget_exhaustion_is_unknown_without_mutation(outbox, monkeypatch):
    write_event(outbox, "one.json")
    write_event(outbox, "two.json")
    monkeypatch.setattr(cost_outbox, "_MAX_FILES", 1)
    assert cost_outbox.read_pending_usage_events({"session-1": {"task-1"}}) is None
    assert len(list(outbox.iterdir())) == 2


def test_empty_target_set_never_reads_other_agent_pending_costs(monkeypatch):
    monkeypatch.setattr(cost_outbox.workspace_store, "_workspace_root", lambda: pytest.fail("无正式会话时无需访问宿主待办"))
    assert cost_outbox.read_pending_usage_events({}) == []
