from __future__ import annotations

import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from oj_modules.agents import runtime_checkpoints
from oj_modules.agents import workspace


@pytest.fixture
def checkpoint_workspace(monkeypatch, tmp_path):
    root = tmp_path / "agent-workspaces"
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_ROOT", root)
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MIN_FREE_BYTES", 1)
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
def test_checkpoint_rejects_absolute_or_escaping_symlinks(
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

    with pytest.raises(workspace.AgentWorkspaceSecurityError, match="符号链接"):
        runtime_checkpoints.create_agent_runtime_checkpoint("session", "unsafe")

    assert not _checkpoint(checkpoint_workspace, "unsafe").exists()


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


def test_checkpoint_rejects_chained_symlink_escape(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    nested = runtime / "nested"
    nested.mkdir(parents=True)
    (nested / "collapse").symlink_to("..")
    # 逐条做词法归一化时两个 target 都仍在 runtime 内；只有按完整
    # symlink 解析语义展开后，第二条链接才会越过 runtime 根。
    (nested / "escape").symlink_to("collapse/../../etc/passwd")

    with pytest.raises(workspace.AgentWorkspaceSecurityError, match="链接链"):
        runtime_checkpoints.create_agent_runtime_checkpoint("session", "unsafe-chain")

    assert not _checkpoint(checkpoint_workspace, "unsafe-chain").exists()


def test_checkpoint_rejects_symlink_cycle(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    (runtime / "first").symlink_to("second")
    (runtime / "second").symlink_to("first")

    with pytest.raises(workspace.AgentWorkspaceSecurityError, match="包含环"):
        runtime_checkpoints.create_agent_runtime_checkpoint("session", "cycle")

    assert not _checkpoint(checkpoint_workspace, "cycle").exists()


def test_symlink_graph_has_a_linear_global_resolution_budget(monkeypatch):
    link_count = 2_000
    links = {
        (f"link-{index}",): (
            f"link-{index + 1}" if index + 1 < link_count else "target"
        )
        for index in range(link_count)
    }
    calls = 0
    original_entry_name = runtime_checkpoints._entry_name

    def counted_entry_name(raw_name):
        nonlocal calls
        calls += 1
        return original_entry_name(raw_name)

    monkeypatch.setattr(runtime_checkpoints, "_entry_name", counted_entry_name)

    with pytest.raises(workspace.AgentWorkspaceSecurityError, match="过于复杂"):
        runtime_checkpoints._validate_symlink_graph(links)

    assert calls <= link_count * 64


def test_checkpoint_rejects_special_files(checkpoint_workspace):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    os.mkfifo(runtime / "agent.pipe")

    with pytest.raises(workspace.AgentWorkspaceSecurityError, match="只允许"):
        runtime_checkpoints.create_agent_runtime_checkpoint("session", "special")

    assert not _checkpoint(checkpoint_workspace, "special").exists()


def test_checkpoint_discards_root_runtime_tmp_with_special_files(
    checkpoint_workspace,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime_tmp = runtime / "tmp" / "nested"
    runtime_tmp.mkdir(parents=True)
    os.mkfifo(runtime_tmp / "agent.pipe")
    (runtime / "home").mkdir()
    (runtime / "home" / "state.json").write_text("persist\n", encoding="utf-8")

    runtime_checkpoints.create_agent_runtime_checkpoint(
        "session",
        "runtime-tmp-baseline",
    )

    assert not (runtime / "tmp").exists()
    saved_runtime = _checkpoint(
        checkpoint_workspace,
        "runtime-tmp-baseline",
    ) / "runtime"
    assert (saved_runtime / "home" / "state.json").read_text() == "persist\n"
    assert not (saved_runtime / "tmp").exists()


def test_checkpoint_discards_codex_arg0_absolute_symlinks(
    checkpoint_workspace,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    codex = runtime / "codex"
    sessions = codex / "sessions"
    arg0 = codex / "tmp" / "arg0" / "codex-arg0"
    sessions.mkdir(parents=True)
    arg0.mkdir(parents=True)
    (sessions / "turn.jsonl").write_text("persist\n", encoding="utf-8")
    (arg0 / "apply_patch").symlink_to("/usr/local/bin/codex")

    runtime_checkpoints.create_agent_runtime_checkpoint(
        "session",
        "codex-baseline",
    )

    assert not (codex / "tmp").exists()
    saved_runtime = _checkpoint(
        checkpoint_workspace,
        "codex-baseline",
    ) / "runtime"
    assert (saved_runtime / "codex" / "sessions" / "turn.jsonl").read_text() == (
        "persist\n"
    )
    assert not (saved_runtime / "codex" / "tmp").exists()


@pytest.mark.parametrize(
    ("limit_name", "limit", "builder", "message"),
    [
        (
            "AGENT_WORKSPACE_MAX_BYTES",
            3,
            lambda runtime: (runtime / "large").write_bytes(b"1234"),
            "总大小",
        ),
        (
            "AGENT_WORKSPACE_MAX_FILES",
            1,
            lambda runtime: [
                (runtime / "one").write_bytes(b"1"),
                (runtime / "two").write_bytes(b"2"),
            ],
            "普通文件数",
        ),
        (
            "AGENT_WORKSPACE_MAX_ENTRIES",
            1,
            lambda runtime: (
                (runtime / "dir").mkdir(),
                (runtime / "dir" / "file").write_bytes(b"1"),
            ),
            "entry",
        ),
        (
            "AGENT_WORKSPACE_MAX_DEPTH",
            1,
            lambda runtime: (
                (runtime / "dir").mkdir(),
                (runtime / "dir" / "file").write_bytes(b"1"),
            ),
            "目录深度",
        ),
    ],
)
def test_checkpoint_creation_enforces_workspace_limits(
    checkpoint_workspace,
    monkeypatch,
    limit_name,
    limit,
    builder,
    message,
):
    public = workspace.ensure_agent_workspace("session")
    runtime = public / ".runtime"
    runtime.mkdir()
    builder(runtime)
    monkeypatch.setattr(workspace, limit_name, limit)

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match=message):
        runtime_checkpoints.create_agent_runtime_checkpoint("session", "limited")

    assert not _checkpoint(checkpoint_workspace, "limited").exists()


def test_restore_checks_disk_reserve_before_touching_runtime(
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
        lambda _fd: SimpleNamespace(f_frsize=1, f_bsize=1, f_bavail=4),
    )
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MIN_FREE_BYTES", 1)

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="可用空间不足"):
        runtime_checkpoints.restore_agent_runtime_checkpoint("session", "saved")

    assert (runtime / "state").read_text() == "current"


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
