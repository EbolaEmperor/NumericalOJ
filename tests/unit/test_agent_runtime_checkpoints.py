from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import tempfile

import pytest

from backend.oj_modules.agents import runtime_checkpoints
from backend.oj_modules.agents import workspace


@pytest.fixture
def checkpoint_workspace(monkeypatch, tmp_path):
    root = tmp_path / "agent-workspaces"
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_ROOT", root)
    return root


def _public(root: Path, session_id: str = "session") -> Path:
    return root / "sessions" / session_id / "workspace"


def _checkpoint(root: Path, checkpoint_id: str = "checkpoint") -> Path:
    return (
        root
        / "sessions"
        / "session"
        / runtime_checkpoints._CHECKPOINTS_DIRECTORY
        / checkpoint_id
    )


def _create_unix_socket_node(path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="numoj-agent-socket-") as short_tmp:
        short_socket_path = os.path.join(short_tmp, "agent.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(short_socket_path)
        finally:
            server.close()
        os.replace(short_socket_path, path)


def test_create_and_restore_runtime_preserves_workspace_files(
    checkpoint_workspace,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    (runtime / "bin").mkdir(parents=True)
    (runtime / "bin" / "session.jsonl").write_text("before\n", encoding="utf-8")
    (runtime / "bin" / "session-link").symlink_to("session.jsonl")
    (public / "solution.py").write_text("original\n", encoding="utf-8")

    usage = runtime_checkpoints.create_agent_runtime_checkpoint(
        "session",
        "checkpoint",
    )

    assert usage == workspace.AgentWorkspaceUsage(
        total_bytes=len(b"before\n") + len("session.jsonl"),
        file_count=1,
        entry_count=3,
    )
    private_checkpoint = _checkpoint(checkpoint_workspace)
    assert private_checkpoint.is_dir()
    assert (private_checkpoint / "manifest.json").is_file()
    assert (private_checkpoint / "runtime" / "bin" / "session.jsonl").read_text() == (
        "before\n"
    )
    assert workspace.build_agent_workspace_tree("session") == [
        {
            "name": "solution.py",
            "path": "solution.py",
            "type": "file",
            "size": len(b"original\n"),
        }
    ]

    (runtime / "bin" / "session.jsonl").write_text("discarded\n", encoding="utf-8")
    (runtime / "new-cache").write_text("discarded", encoding="utf-8")
    # 这是被废弃轮次对项目文件的修改；恢复 runtime 时必须保留。
    (public / "solution.py").write_text("changed by discarded turn\n", encoding="utf-8")
    (public / "generated.txt").write_text("keep this file\n", encoding="utf-8")

    restored = runtime_checkpoints.restore_agent_runtime_checkpoint(
        "session",
        "checkpoint",
    )

    assert restored == usage
    assert (runtime / "bin" / "session.jsonl").read_text() == "before\n"
    assert not (runtime / "new-cache").exists()
    assert (runtime / "bin" / "session-link").is_symlink()
    assert os.readlink(runtime / "bin" / "session-link") == "session.jsonl"
    assert (runtime / "bin" / "session-link").read_text() == "before\n"
    assert (public / "solution.py").read_text() == "changed by discarded turn\n"
    assert (public / "generated.txt").read_text() == "keep this file\n"
    assert runtime_checkpoints.remove_agent_runtime_checkpoint(
        "session",
        "checkpoint",
    ) is True
    assert not private_checkpoint.exists()


def test_empty_checkpoint_restores_an_empty_private_runtime(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    (runtime / "old-state").write_text("old", encoding="utf-8")

    usage = runtime_checkpoints.create_empty_agent_runtime_checkpoint(
        "session",
        "empty",
    )

    assert usage == workspace.AgentWorkspaceUsage(0, 0, 0)
    # 创建空基线本身不能更改当前运行态。
    assert (runtime / "old-state").read_text() == "old"

    runtime_checkpoints.restore_agent_runtime_checkpoint("session", "empty")

    assert runtime.is_dir()
    assert list(runtime.iterdir()) == []
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700


def test_checkpoint_treats_missing_runtime_as_empty(checkpoint_workspace):
    workspace.ensure_agent_workspace("session")

    usage = runtime_checkpoints.create_agent_runtime_checkpoint(
        "session",
        "missing-runtime",
    )

    assert usage == workspace.AgentWorkspaceUsage(0, 0, 0)
    assert (_checkpoint(checkpoint_workspace, "missing-runtime") / "runtime").is_dir()


def test_checkpoint_preserves_runtime_hardlinks(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    original = runtime / "package-cache"
    linked = runtime / "package-copy"
    original.write_bytes(b"shared package")
    os.link(original, linked)

    usage = runtime_checkpoints.create_agent_runtime_checkpoint(
        "session",
        "hardlinks",
    )

    saved_runtime = _checkpoint(checkpoint_workspace, "hardlinks") / "runtime"
    assert usage == workspace.AgentWorkspaceUsage(
        total_bytes=len(b"shared package"),
        file_count=2,
        entry_count=2,
    )
    assert saved_runtime.joinpath("package-cache").stat().st_ino == (
        saved_runtime / "package-copy"
    ).stat().st_ino

    original.unlink()
    linked.write_bytes(b"changed")
    runtime_checkpoints.restore_agent_runtime_checkpoint("session", "hardlinks")

    assert original.read_bytes() == b"shared package"
    assert original.stat().st_ino == linked.stat().st_ino


def test_checkpoint_is_immutable_and_never_overwritten(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    (runtime / "state").write_text("first", encoding="utf-8")
    runtime_checkpoints.create_agent_runtime_checkpoint("session", "fixed")

    (runtime / "state").write_text("second", encoding="utf-8")
    with pytest.raises(workspace.AgentWorkspaceError, match="拒绝覆盖"):
        runtime_checkpoints.create_agent_runtime_checkpoint("session", "fixed")

    assert (
        _checkpoint(checkpoint_workspace, "fixed") / "runtime" / "state"
    ).read_text() == "first"


@pytest.mark.parametrize(
    ("relative_path", "target"),
    [
        ("absolute", "/etc/passwd"),
        ("escape", "../outside"),
        ("nested/escape", "../../outside"),
    ],
)
def test_checkpoint_preserves_symlinks_without_target_policy(
    checkpoint_workspace,
    relative_path,
    target,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    link = runtime / relative_path
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)

    runtime_checkpoints.create_agent_runtime_checkpoint("session", "opaque-link")

    saved_link = (
        _checkpoint(checkpoint_workspace, "opaque-link") / "runtime" / relative_path
    )
    assert saved_link.is_symlink()
    assert os.readlink(saved_link) == target

    runtime_checkpoints.restore_agent_runtime_checkpoint(
        "session",
        "opaque-link",
    )

    assert os.readlink(runtime / relative_path) == target


def test_checkpoint_preserves_parent_reference_that_stays_inside_runtime(
    checkpoint_workspace,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    package = runtime / "config" / "node_modules" / "package"
    executable = runtime / "config" / "node_modules" / ".bin" / "package"
    package.mkdir(parents=True)
    executable.parent.mkdir()
    (package / "cli.js").write_text("export {};\n", encoding="utf-8")
    executable.symlink_to("../package/cli.js")

    runtime_checkpoints.create_agent_runtime_checkpoint("session", "safe-link")

    saved_link = (
        _checkpoint(checkpoint_workspace, "safe-link")
        / "runtime"
        / "config"
        / "node_modules"
        / ".bin"
        / "package"
    )
    assert saved_link.is_symlink()
    assert os.readlink(saved_link) == "../package/cli.js"


def test_checkpoint_preserves_chained_symlink_escape(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    nested = runtime / "nested"
    nested.mkdir(parents=True)
    (nested / "collapse").symlink_to("..")
    # 逐条做词法归一化时两个 target 都仍在 runtime 内；只有按完整
    # symlink 解析语义展开后，第二条链接才会越过 runtime 根。
    (nested / "escape").symlink_to("collapse/../../etc/passwd")

    runtime_checkpoints.create_agent_runtime_checkpoint("session", "opaque-chain")

    saved_nested = _checkpoint(checkpoint_workspace, "opaque-chain") / "runtime" / "nested"
    assert os.readlink(saved_nested / "collapse") == ".."
    assert os.readlink(saved_nested / "escape") == "collapse/../../etc/passwd"


def test_checkpoint_preserves_symlink_cycle(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    (runtime / "first").symlink_to("second")
    (runtime / "second").symlink_to("first")

    runtime_checkpoints.create_agent_runtime_checkpoint("session", "cycle")

    saved_runtime = _checkpoint(checkpoint_workspace, "cycle") / "runtime"
    assert os.readlink(saved_runtime / "first") == "second"
    assert os.readlink(saved_runtime / "second") == "first"


def test_checkpoint_ignores_sockets_without_modifying_source(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    source_socket = runtime / "agent.sock"
    _create_unix_socket_node(source_socket)

    runtime_checkpoints.create_agent_runtime_checkpoint("session", "special")

    assert stat.S_ISSOCK(os.stat(source_socket).st_mode)
    assert not (
        _checkpoint(checkpoint_workspace, "special")
        / "runtime"
        / "agent.sock"
    ).exists()


def test_checkpoint_ignores_runtime_tmp_sockets_but_preserves_other_state(
    checkpoint_workspace,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime_tmp = runtime / "tmp" / "nested"
    runtime_tmp.mkdir(parents=True)
    (runtime_tmp / "state.json").write_text("persist tmp\n", encoding="utf-8")
    socket_path = runtime_tmp / "agent.sock"
    _create_unix_socket_node(socket_path)
    (runtime / "home").mkdir()
    (runtime / "home" / "state.json").write_text("persist\n", encoding="utf-8")

    runtime_checkpoints.create_agent_runtime_checkpoint(
        "session",
        "runtime-tmp-baseline",
    )

    assert (runtime_tmp / "state.json").read_text() == "persist tmp\n"
    assert stat.S_ISSOCK(os.stat(socket_path).st_mode)
    saved_runtime = _checkpoint(
        checkpoint_workspace,
        "runtime-tmp-baseline",
    ) / "runtime"
    assert (saved_runtime / "home" / "state.json").read_text() == "persist\n"
    assert (saved_runtime / "tmp" / "nested" / "state.json").read_text() == (
        "persist tmp\n"
    )
    assert not (saved_runtime / "tmp" / "nested" / "agent.sock").exists()


def test_checkpoint_ignores_fifos_without_modifying_source(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime_tmp = public / ".runtime" / "tmp"
    runtime_tmp.mkdir(parents=True)
    source_fifo = runtime_tmp / "agent.pipe"
    os.mkfifo(source_fifo)

    runtime_checkpoints.create_agent_runtime_checkpoint(
        "session",
        "runtime-tmp-fifo",
    )

    checkpoint_fifo = (
        _checkpoint(checkpoint_workspace, "runtime-tmp-fifo")
        / "runtime"
        / "tmp"
        / "agent.pipe"
    )
    assert stat.S_ISFIFO(os.stat(source_fifo).st_mode)
    assert not checkpoint_fifo.exists()


def test_checkpoint_creation_enforces_only_total_bytes(
    checkpoint_workspace,
    monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    (runtime / "large").write_bytes(b"1234")
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MAX_BYTES", 3)

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="总大小"):
        runtime_checkpoints.create_agent_runtime_checkpoint("session", "limited")

    assert not _checkpoint(checkpoint_workspace, "limited").exists()


def test_restore_does_not_depend_on_free_space_preflight(
    checkpoint_workspace,
    monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    (runtime / "state").write_text("checkpoint", encoding="utf-8")
    runtime_checkpoints.create_agent_runtime_checkpoint("session", "saved")
    (runtime / "state").write_text("current", encoding="utf-8")

    monkeypatch.setattr(
        workspace.os,
        "fstatvfs",
        lambda _fd: (_ for _ in ()).throw(OSError("must not be called")),
    )

    runtime_checkpoints.restore_agent_runtime_checkpoint("session", "saved")

    assert (runtime / "state").read_text() == "checkpoint"


def test_restore_copy_failure_keeps_previous_runtime_and_cleans_stage(
    checkpoint_workspace,
    monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    (runtime / "state").write_text("checkpoint", encoding="utf-8")
    runtime_checkpoints.create_agent_runtime_checkpoint("session", "saved")
    (runtime / "state").write_text("current", encoding="utf-8")

    def fail_copy(_source_fd, destination_fd):
        os.mkdir("partial", mode=0o700, dir_fd=destination_fd)
        raise workspace.AgentWorkspaceError("injected copy failure")

    monkeypatch.setattr(runtime_checkpoints, "_copy_tree_fd", fail_copy)

    with pytest.raises(workspace.AgentWorkspaceError, match="injected"):
        runtime_checkpoints.restore_agent_runtime_checkpoint("session", "saved")

    assert (runtime / "state").read_text() == "current"
    session_root = checkpoint_workspace / "sessions" / "session"
    assert not list(session_root.glob(".runtime-restore-*"))
    assert not list(session_root.glob(".runtime-backup-*"))


def test_restore_publish_failure_rolls_previous_runtime_back(
    checkpoint_workspace,
    monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    (runtime / "state").write_text("checkpoint", encoding="utf-8")
    runtime_checkpoints.create_agent_runtime_checkpoint("session", "saved")
    (runtime / "state").write_text("current", encoding="utf-8")
    original_rename = runtime_checkpoints.os.rename

    def fail_publish(source, destination, *args, **kwargs):
        if str(source).startswith(".runtime-restore-") and destination == ".runtime":
            raise OSError("injected publish failure")
        return original_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(runtime_checkpoints.os, "rename", fail_publish)

    with pytest.raises(workspace.AgentWorkspaceError, match="无法恢复"):
        runtime_checkpoints.restore_agent_runtime_checkpoint("session", "saved")

    assert (runtime / "state").read_text() == "current"
    session_root = checkpoint_workspace / "sessions" / "session"
    assert not list(session_root.glob(".runtime-restore-*"))
    assert not list(session_root.glob(".runtime-backup-*"))


def test_remove_checkpoint_is_precise_and_missing_policy_is_explicit(
    checkpoint_workspace,
):
    workspace.ensure_agent_workspace("session")
    runtime_checkpoints.create_empty_agent_runtime_checkpoint("session", "orphan")

    assert runtime_checkpoints.remove_agent_runtime_checkpoint(
        "session",
        "orphan",
    ) is True
    assert not _checkpoint(checkpoint_workspace, "orphan").exists()
    assert runtime_checkpoints.remove_agent_runtime_checkpoint(
        "session",
        "orphan",
    ) is False
    with pytest.raises(FileNotFoundError):
        runtime_checkpoints.remove_agent_runtime_checkpoint(
            "session",
            "orphan",
            missing_ok=False,
        )


def test_restore_rejects_symlinked_checkpoint_without_touching_target(
    checkpoint_workspace,
    tmp_path,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    (runtime / "state").write_text("current", encoding="utf-8")
    runtime_checkpoints.create_empty_agent_runtime_checkpoint("session", "seed")
    checkpoints = _checkpoint(checkpoint_workspace, "seed").parent
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel").write_text("keep", encoding="utf-8")
    (checkpoints / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(workspace.AgentWorkspaceSecurityError):
        runtime_checkpoints.restore_agent_runtime_checkpoint("session", "linked")

    assert (outside / "sentinel").read_text() == "keep"
    assert (runtime / "state").read_text() == "current"
