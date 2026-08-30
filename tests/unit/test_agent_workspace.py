from __future__ import annotations

from io import BytesIO
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from backend.oj_modules.agents import workspace


class Upload:
    def __init__(self, filename, data):
        self.filename = filename
        self.stream = BytesIO(data)


@pytest.fixture
def workspace_root(monkeypatch, tmp_path):
    root = tmp_path / "agent-workspaces"
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_ROOT", root)
    return root


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)


def test_ensure_agent_workspace_uses_private_fixed_layout(workspace_root):
    actual = workspace.ensure_agent_workspace("session-01")

    assert actual == workspace_root / "sessions" / "session-01" / "workspace"
    assert actual.is_dir()
    for path in (
        workspace_root,
        workspace_root / "sessions",
        workspace_root / "sessions" / "session-01",
        actual,
    ):
        assert _mode(path) == 0o700

    os.chmod(actual, 0o755)
    assert workspace.ensure_agent_workspace("session-01") == actual
    assert _mode(actual) == 0o700


@pytest.mark.parametrize(
    ("harness", "access_role", "filename"),
    [
        ("claude_code", "user", "CLAUDE.md"),
        ("codex", "user", "AGENTS.md"),
        ("pi", "admin", "AGENTS.md"),
    ],
)
def test_initialize_agent_task_workspace_writes_harness_memory_file(
    workspace_root,
    harness,
    access_role,
    filename,
):
    actual = workspace.initialize_agent_task_workspace(
        "session-01",
        harness=harness,
        access_role=access_role,
    )

    assert actual == workspace_root / "sessions" / "session-01" / "workspace"
    assert (actual / filename).is_file()


@pytest.mark.parametrize("session_id", ["", ".", "..", "../escape", "a/b", "a\\b", "空"])
def test_ensure_agent_workspace_rejects_unsafe_session_ids(
    workspace_root, session_id
):
    with pytest.raises(workspace.AgentWorkspacePathError):
        workspace.ensure_agent_workspace(session_id)


def test_ensure_agent_workspace_rejects_symlinked_managed_component(
    workspace_root, tmp_path
):
    safe = workspace.ensure_agent_workspace("safe")
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = safe.parent.parent / "linked"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(workspace.AgentWorkspaceSecurityError):
        workspace.ensure_agent_workspace("linked")
    assert linked.is_symlink()


def test_ensure_agent_workspace_rejects_symlinked_root(monkeypatch, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_ROOT", linked_root)

    with pytest.raises(workspace.AgentWorkspaceSecurityError):
        workspace.ensure_agent_workspace("session")


def test_temporary_redaction_history_is_host_only_private_and_persistent(
    workspace_root,
):
    first = workspace.merge_agent_temporary_redaction_candidates(
        "session",
        ("previous-temporary-token",),
    )
    second = workspace.merge_agent_temporary_redaction_candidates(
        "session",
        ("current-temporary-token", "previous-temporary-token"),
    )

    assert first == ("previous-temporary-token",)
    assert second == (
        "previous-temporary-token",
        "current-temporary-token",
    )
    session_root = workspace_root / "sessions" / "session"
    history_path = session_root / workspace._REDACTION_HISTORY_FILENAME
    lock_path = session_root / workspace._REDACTION_HISTORY_LOCK_FILENAME
    assert history_path.parent != session_root / "workspace"
    assert _mode(history_path) == 0o600
    assert _mode(lock_path) == 0o600
    assert json.loads(history_path.read_text(encoding="utf-8")) == {
        "version": 1,
        "candidates": [
            "previous-temporary-token",
            "current-temporary-token",
        ],
    }
    assert workspace.build_agent_workspace_tree("session") == []
    assert not list(session_root.glob("*.tmp"))


def test_temporary_redaction_history_rejects_symlink_without_touching_target(
    workspace_root,
    tmp_path,
):
    workspace.ensure_agent_workspace("session")
    outside = tmp_path / "outside.json"
    outside.write_text("keep", encoding="utf-8")
    history_path = (
        workspace_root
        / "sessions"
        / "session"
        / workspace._REDACTION_HISTORY_FILENAME
    )
    history_path.symlink_to(outside)

    with pytest.raises(workspace.AgentWorkspaceSecurityError):
        workspace.merge_agent_temporary_redaction_candidates(
            "session",
            ("current-temporary-token",),
        )

    assert history_path.is_symlink()
    assert outside.read_text(encoding="utf-8") == "keep"


def test_temporary_redaction_history_overflow_preserves_previous_file(
    workspace_root,
    monkeypatch,
):
    workspace.merge_agent_temporary_redaction_candidates(
        "session",
        ("previous-temporary-token",),
    )
    history_path = (
        workspace_root
        / "sessions"
        / "session"
        / workspace._REDACTION_HISTORY_FILENAME
    )
    before = history_path.read_bytes()
    monkeypatch.setattr(workspace, "_MAX_REDACTION_HISTORY_ENTRIES", 1)

    with pytest.raises(workspace.AgentWorkspaceLimitError, match="条目上限"):
        workspace.merge_agent_temporary_redaction_candidates(
            "session",
            ("current-temporary-token",),
        )

    assert history_path.read_bytes() == before


def test_save_unicode_attachments_and_remove_only_listed_files(workspace_root):
    metadata = workspace.save_agent_attachments(
        "session",
        "task",
        [
            Upload("报告 π.md", "附件内容".encode()),
            Upload("solver.m", b"disp('ok')\n"),
        ],
    )

    public = workspace_root / "sessions" / "session" / "workspace"
    generation = metadata[0]["path"].split("/")[1]
    assert generation.startswith("task-")
    assert metadata == [
        {
            "name": "报告 π.md",
            "path": f"attachments/{generation}/报告 π.md",
            "size": len("附件内容".encode()),
            "sha256": metadata[0]["sha256"],
        },
        {
            "name": "solver.m",
            "path": f"attachments/{generation}/solver.m",
            "size": len(b"disp('ok')\n"),
            "sha256": metadata[1]["sha256"],
        },
    ]
    assert len(metadata[0]["sha256"]) == 64
    assert (public / metadata[0]["path"]).read_text() == "附件内容"
    assert _mode(public / metadata[0]["path"]) == 0o600
    assert _mode(public / "attachments" / generation) == 0o700

    assert workspace.remove_agent_attachments("session", metadata[:1]) == 1
    assert not (public / metadata[0]["path"]).exists()
    assert (public / metadata[1]["path"]).is_file()
    assert workspace.remove_agent_attachments("session", metadata[1:]) == 1
    assert not (public / "attachments").exists()
    assert workspace.remove_agent_attachments("session", metadata) == 0


@pytest.mark.parametrize(
    "filename",
    [
        "../secret.txt",
        "/absolute.txt",
        "folder/file.txt",
        "folder\\file.txt",
        "control\x01.txt",
        "bad\u200bname.txt",
        "trailing. ",
        "CON.txt",
        ".runtime",
        ".numoj-agent-token",
        ".aj_session_state.json",
    ],
)
def test_save_agent_attachments_rejects_unsafe_names_without_publication(
    workspace_root, filename
):
    with pytest.raises(workspace.AgentAttachmentError):
        workspace.save_agent_attachments(
            "session", "task", [Upload(filename, b"secret")]
        )

    public = workspace_root / "sessions" / "session" / "workspace"
    assert not any((public / "attachments").glob("task-*"))


def test_save_agent_attachments_rejects_casefold_duplicates(workspace_root):
    with pytest.raises(workspace.AgentAttachmentError):
        workspace.save_agent_attachments(
            "session",
            "task",
            [Upload("Answer.txt", b"a"), Upload("answer.TXT", b"b")],
        )


def test_save_agent_attachments_rejects_private_task_namespace(workspace_root):
    with pytest.raises(workspace.AgentWorkspacePathError):
        workspace.save_agent_attachments(
            "session", ".runtime", [Upload("answer.txt", b"answer")]
        )


def test_attachment_limits_rollback_only_failed_attempt(
    workspace_root, monkeypatch
):
    monkeypatch.setattr(workspace, "MAX_ATTACHMENT_FILE_BYTES", 4)
    monkeypatch.setattr(workspace, "MAX_ATTACHMENT_TOTAL_BYTES", 6)

    with pytest.raises(workspace.AgentAttachmentError, match="单个附件"):
        workspace.save_agent_attachments(
            "session", "large", [Upload("large.bin", b"12345")]
        )
    with pytest.raises(workspace.AgentAttachmentError, match="总大小"):
        workspace.save_agent_attachments(
            "session",
            "total",
            [Upload("one.txt", b"1234"), Upload("two.txt", b"5678")],
        )

    session = workspace_root / "sessions" / "session"
    public = session / "workspace"
    assert not any((public / "attachments").glob("large-*"))
    assert not any((public / "attachments").glob("total-*"))
    assert list((session / ".attachment-staging").iterdir()) == []


def test_attachment_count_limit_is_checked_before_reading(
    workspace_root, monkeypatch
):
    monkeypatch.setattr(workspace, "MAX_ATTACHMENT_FILES", 2)
    uploads = [Upload(f"{index}.txt", b"x") for index in range(3)]

    with pytest.raises(workspace.AgentAttachmentError, match="最多上传"):
        workspace.save_agent_attachments("session", "task", uploads)
    assert not workspace_root.exists()


def test_save_agent_attachments_uses_independent_generations(workspace_root):
    first = workspace.save_agent_attachments(
        "session", "task", [Upload("answer.txt", b"original")]
    )
    second = workspace.save_agent_attachments(
        "session", "task", [Upload("answer.txt", b"replacement")]
    )

    public = workspace_root / "sessions" / "session" / "workspace"
    assert first[0]["path"] != second[0]["path"]
    assert (public / first[0]["path"]).read_bytes() == b"original"
    assert (public / second[0]["path"]).read_bytes() == b"replacement"


def test_remove_agent_attachments_rejects_paths_outside_attachment_namespace(
    workspace_root
):
    public = workspace.ensure_agent_workspace("session")
    sentinel = public / "sentinel.txt"
    sentinel.write_text("keep")

    with pytest.raises(workspace.AgentWorkspacePathError):
        workspace.remove_agent_attachments(
            "session", [{"name": "sentinel.txt", "path": "sentinel.txt"}]
        )
    with pytest.raises(workspace.AgentWorkspacePathError):
        workspace.remove_agent_attachments(
            "session",
            [{"name": "sentinel.txt", "path": "attachments/task/../../sentinel.txt"}],
        )
    assert sentinel.read_text() == "keep"


def test_clear_agent_session_state_file_removes_only_summary(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    summary = public / ".aj_session_state.json"
    runtime = public / ".runtime"
    summary.write_text('{"session_id":"discarded"}')
    runtime.mkdir()
    (runtime / "keep.txt").write_text("restored runtime")

    assert workspace.clear_agent_session_state_file("session") is True
    assert not summary.exists()
    assert (runtime / "keep.txt").read_text() == "restored runtime"
    assert workspace.clear_agent_session_state_file("session") is False


def test_clear_agent_session_state_file_unlinks_symlink_without_following(
    workspace_root,
    tmp_path,
):
    public = workspace.ensure_agent_workspace("session")
    outside = tmp_path / "outside.json"
    outside.write_text("keep")
    summary = public / ".aj_session_state.json"
    summary.symlink_to(outside)

    assert workspace.clear_agent_session_state_file("session") is True
    assert not summary.exists()
    assert outside.read_text() == "keep"


def test_workspace_tree_is_recursive_and_hides_private_runtime_data(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    (public / "src").mkdir()
    (public / "src" / "main.py").write_text("print('ok')\n")
    (public / "README.md").write_text("# Read me\n")
    (public / ".runtime").mkdir()
    (public / ".runtime" / "token").write_text("secret")
    (public / ".numoj-agent").write_text("secret")
    (public / ".aj_session_state.json").write_text("secret")
    (public / ".aj_session_state.jsonl").write_text("secret")

    tree = workspace.build_agent_workspace_tree("session")

    assert tree == [
        {"name": "README.md", "path": "README.md", "type": "file", "size": 10},
        {
            "name": "src",
            "path": "src",
            "type": "directory",
            "children": [
                {
                    "name": "main.py",
                    "path": "src/main.py",
                    "type": "file",
                    "size": 12,
                }
            ],
        },
    ]


def test_workspace_tree_skips_and_open_rejects_symlink_escape(workspace_root, tmp_path):
    public = workspace.ensure_agent_workspace("session")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (public / "escape.txt").symlink_to(outside)

    assert workspace.build_agent_workspace_tree("session") == []
    with pytest.raises(workspace.AgentWorkspaceSecurityError):
        workspace.open_agent_workspace_file("session", "escape.txt")


def test_workspace_tree_skips_and_open_rejects_hardlinks(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    original = public / "original.txt"
    original.write_text("content")
    os.link(original, public / "linked.txt")

    assert workspace.build_agent_workspace_tree("session") == []
    with pytest.raises(workspace.AgentWorkspaceSecurityError, match="单链接"):
        workspace.open_agent_workspace_file("session", "original.txt")


def test_workspace_tree_skips_special_files(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    fifo = public / "pipe"
    os.mkfifo(fifo)

    assert workspace.build_agent_workspace_tree("session") == []


def test_workspace_tree_enforces_entry_and_depth_limits(
    workspace_root, monkeypatch
):
    public = workspace.ensure_agent_workspace("session")
    (public / "one").write_text("1")
    (public / "two").write_text("2")
    monkeypatch.setattr(workspace, "MAX_WORKSPACE_TREE_ENTRIES", 1)
    with pytest.raises(workspace.AgentWorkspaceLimitError, match="最多展示"):
        workspace.build_agent_workspace_tree("session")

    monkeypatch.setattr(workspace, "MAX_WORKSPACE_TREE_ENTRIES", 5000)
    monkeypatch.setattr(workspace, "MAX_WORKSPACE_TREE_DEPTH", 2)
    (public / "nested").mkdir()
    (public / "nested" / "deeper").mkdir()
    (public / "nested" / "deeper" / "file.txt").write_text("x")
    with pytest.raises(workspace.AgentWorkspaceLimitError, match="深度"):
        workspace.build_agent_workspace_tree("session")


@pytest.mark.parametrize(
    ("filename", "payload", "kind", "mime"),
    [
        ("document.txt", b"%PDF-1.7\n", "pdf", "application/pdf"),
        ("picture.bin", b"\x89PNG\r\n\x1a\nrest", "image", "image/png"),
        ("picture.bin", b"\xff\xd8\xffrest", "image", "image/jpeg"),
        ("picture.bin", b"GIF89arest", "image", "image/gif"),
        ("picture.bin", b"BMrest", "image", "image/bmp"),
        ("picture.bin", b"\x00\x00\x01\x00rest", "image", "image/x-icon"),
        (
            "picture.bin",
            b"\x00\x00\x00\x18ftypavif\x00\x00\x00\x00",
            "image",
            "image/avif",
        ),
        (
            "picture.bin",
            b"RIFF\x04\x00\x00\x00WEBPrest",
            "image",
            "image/webp",
        ),
    ],
)
def test_inspect_agent_workspace_file_uses_content_magic_before_extension(
    workspace_root, filename, payload, kind, mime
):
    public = workspace.ensure_agent_workspace("session")
    (public / filename).write_bytes(payload)

    result = workspace.inspect_agent_workspace_file("session", filename)

    assert result["preview_kind"] == kind
    assert result["kind"] == kind
    assert result["mime_type"] == mime
    assert result["size"] == len(payload)
    assert "content" not in result


@pytest.mark.parametrize(
    ("filename", "content", "kind", "language"),
    [
        ("notes.md", "# 标题\n", "markdown", "markdown"),
        ("solver.m", "disp('ok')\n", "code", "matlab"),
        ("query.sql", "SELECT 1;\n", "code", "sql"),
        ("program.go", "package main\n", "code", "go"),
        ("Submission.lean", "theorem answer : True := by trivial\n", "code", "lean4"),
        ("paper.tex", "\\section{Test}\n", "code", "latex"),
        ("unknown.pdf", "this is text\n", "text", "plaintext"),
        ("README", "ordinary text\n", "text", "plaintext"),
        ("graphic.svg", "<svg></svg>\n", "code", "xml"),
    ],
)
def test_inspect_agent_workspace_file_classifies_utf8_text(
    workspace_root, filename, content, kind, language
):
    public = workspace.ensure_agent_workspace("session")
    (public / filename).write_text(content)

    result = workspace.inspect_agent_workspace_file("session", filename)

    assert result["preview_kind"] == kind
    assert result["language"] == language
    assert result["content"] == content


@pytest.mark.parametrize("payload", [b"\xff\xfe\x00x", b"text\x00binary", b"text\x01binary"])
def test_inspect_agent_workspace_file_rejects_non_utf8_or_binary_text(
    workspace_root, payload
):
    public = workspace.ensure_agent_workspace("session")
    (public / "data.txt").write_bytes(payload)

    result = workspace.inspect_agent_workspace_file("session", "data.txt")

    assert result["preview_kind"] == "unsupported"
    assert "content" not in result


def test_inspect_agent_workspace_file_enforces_text_preview_limit(
    workspace_root, monkeypatch
):
    monkeypatch.setattr(workspace, "MAX_TEXT_PREVIEW_BYTES", 4)
    public = workspace.ensure_agent_workspace("session")
    (public / "long.txt").write_text("12345")

    result = workspace.inspect_agent_workspace_file("session", "long.txt")

    assert result["preview_kind"] == "unsupported"
    assert "文本预览上限" in result["reason"]


def test_open_agent_workspace_file_returns_inode_stable_handle(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    target = public / "result.txt"
    target.write_bytes(b"original")

    handle, metadata = workspace.open_agent_workspace_file("session", "result.txt")
    replacement = public / "replacement.txt"
    replacement.write_bytes(b"replacement")
    os.replace(replacement, target)
    try:
        assert handle.read() == b"original"
        assert metadata["path"] == "result.txt"
        assert metadata["size"] == len(b"original")
        assert metadata["mime_type"] == "application/octet-stream"
        assert "agent-workspaces" not in str(metadata)
    finally:
        handle.close()


@pytest.mark.parametrize(
    "relative_path",
    [
        "",
        "/etc/passwd",
        "../secret",
        "dir/../secret",
        "dir//secret",
        "dir\\secret",
        ".runtime/token",
        ".numoj-agent",
        ".aj_session_state.json",
    ],
)
def test_open_agent_workspace_file_rejects_unsafe_or_private_paths(
    workspace_root, relative_path
):
    workspace.ensure_agent_workspace("session")

    with pytest.raises(workspace.AgentWorkspacePathError):
        workspace.open_agent_workspace_file("session", relative_path)


def test_open_agent_workspace_file_reports_missing_file(workspace_root):
    workspace.ensure_agent_workspace("session")

    with pytest.raises(FileNotFoundError):
        workspace.open_agent_workspace_file("session", "missing.txt")


def test_workspace_quota_counts_hidden_runtime_and_content_without_suffix(
    workspace_root,
):
    public = workspace.ensure_agent_workspace("session")
    (public / "artifact-without-suffix").write_bytes(b"abc")
    runtime_dir = public / ".runtime"
    runtime_dir.mkdir()
    (runtime_dir / "opaque-cache").write_bytes(b"1234")

    usage = workspace.check_agent_workspace_quota("session")

    assert usage == workspace.AgentWorkspaceUsage(
        total_bytes=7,
        file_count=2,
        entry_count=3,
    )


def test_workspace_quota_counts_but_does_not_follow_links_or_special_files(
    workspace_root,
    tmp_path,
):
    public = workspace.ensure_agent_workspace("session")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside content must not be counted")
    link = public / "python"
    link.symlink_to(outside)
    fifo = public / "tool.pipe"
    os.mkfifo(fifo)

    usage = workspace.check_agent_workspace_quota("session")

    assert usage.file_count == 0
    assert usage.entry_count == 2
    assert usage.total_bytes == link.lstat().st_size + fifo.lstat().st_size


def test_workspace_quota_conservatively_counts_each_hardlink(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    original = public / "package.js"
    original.write_bytes(b"content")
    os.link(original, public / "package-copy.js")

    usage = workspace.check_agent_workspace_quota("session")

    assert usage == workspace.AgentWorkspaceUsage(
        total_bytes=14,
        file_count=2,
        entry_count=2,
    )


def test_workspace_quota_counts_empty_directories_toward_total_entries(
    workspace_root,
    monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MAX_ENTRIES", 2)
    for name in ("one", "two", "three"):
        (public / name).mkdir()

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="总 entry 数"):
        workspace.check_agent_workspace_quota("session")


def test_workspace_quota_uses_explicit_stack_and_rejects_excessive_depth(
    workspace_root,
    monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MAX_DEPTH", 64)
    current = public
    for index in range(70):
        current = current / f"d{index}"
        current.mkdir()

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="目录深度"):
        workspace.check_agent_workspace_quota("session")


@pytest.mark.parametrize(
    ("limit_name", "limit", "payloads", "message"),
    [
        ("AGENT_WORKSPACE_MAX_BYTES", 4, (b"12345",), "总大小"),
        ("AGENT_WORKSPACE_MAX_FILES", 1, (b"1", b"2"), "文件数"),
    ],
)
def test_workspace_quota_enforces_bytes_and_file_count(
    workspace_root,
    monkeypatch,
    limit_name,
    limit,
    payloads,
    message,
):
    public = workspace.ensure_agent_workspace("session")
    monkeypatch.setattr(workspace, limit_name, limit)
    for index, payload in enumerate(payloads):
        (public / f"entry-{index}").write_bytes(payload)

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match=message):
        workspace.check_agent_workspace_quota("session")


def test_workspace_quota_fails_closed_when_free_space_cannot_be_confirmed(
    workspace_root,
    monkeypatch,
):
    workspace.ensure_agent_workspace("session")
    monkeypatch.setattr(
        workspace.os,
        "fstatvfs",
        lambda _fd: (_ for _ in ()).throw(OSError("statvfs failed")),
    )

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="可用空间"):
        workspace.check_agent_workspace_quota("session")

    monkeypatch.setattr(
        workspace.os,
        "fstatvfs",
        lambda _fd: SimpleNamespace(f_frsize=1, f_bsize=1, f_bavail=3),
    )
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MIN_FREE_BYTES", 4)
    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="可用空间不足"):
        workspace.check_agent_workspace_quota("session")


def test_attachment_publication_cannot_cross_persistent_session_quota(
    workspace_root,
    monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    (public / "existing.bin").write_bytes(b"1234")
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MAX_BYTES", 5)

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="总大小"):
        workspace.save_agent_attachments(
            "session",
            "turn-2",
            [Upload("new.bin", b"56")],
        )

    assert not any((public / "attachments").glob("turn-2-*"))
    staging = workspace_root / "sessions" / "session" / ".attachment-staging"
    assert list(staging.iterdir()) == []


def test_host_workspace_write_uses_net_projection_and_preserves_old_file_on_failure(
    workspace_root,
    monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    (public / "other.bin").write_bytes(b"123")
    target = public / ".runtime-state"
    target.write_bytes(b"45")
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MAX_BYTES", 5)

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="总大小"):
        workspace.write_agent_workspace_file(
            "session",
            ".runtime-state",
            b"6789",
        )

    assert target.read_bytes() == b"45"
    workspace.write_agent_workspace_file("session", ".runtime-state", b"6")
    assert target.read_bytes() == b"6"
    assert workspace.get_agent_workspace_usage("session").total_bytes == 4
