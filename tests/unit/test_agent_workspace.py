from __future__ import annotations

from io import BytesIO
import json
import os
from pathlib import Path
import stat

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
    memory = (actual / filename).read_text(encoding="utf-8")
    assert f"use the {'numoj-admin' if access_role == 'admin' else 'numoj-user'} skill" in memory
    assert "Background subagents and workflows" not in memory


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
        "bad\x00name.txt",
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


@pytest.mark.parametrize(
    "filename",
    ["folder\\file.txt", "control\x01.txt", "bad\u200bname.txt", "trailing. ", "CON.txt"],
)
def test_save_agent_attachments_allows_platform_valid_names(workspace_root, filename):
    saved = workspace.save_agent_attachments(
        "session",
        f"task-{abs(hash(filename))}",
        [Upload(filename, b"content")],
    )

    assert saved[0]["name"] == filename


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


def test_workspace_tree_and_preview_allow_hardlinks(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    original = public / "original.txt"
    original.write_text("content")
    os.link(original, public / "linked.txt")

    assert workspace.build_agent_workspace_tree("session") == [
        {"name": "linked.txt", "path": "linked.txt", "type": "file", "size": 7},
        {
            "name": "original.txt",
            "path": "original.txt",
            "type": "file",
            "size": 7,
        },
    ]
    handle, _metadata = workspace.open_agent_workspace_file("session", "original.txt")
    with handle:
        assert handle.read() == b"content"


def test_workspace_tree_skips_special_files(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    fifo = public / "pipe"
    os.mkfifo(fifo)

    assert workspace.build_agent_workspace_tree("session") == []


def test_workspace_tree_does_not_enforce_entry_or_depth_limits(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    (public / "one").write_text("1")
    (public / "two").write_text("2")
    (public / "nested").mkdir()
    current = public / "nested"
    for index in range(24):
        current = current / f"d{index}"
        current.mkdir()
    (current / "file.txt").write_text("x")

    tree = workspace.build_agent_workspace_tree("session")

    assert [node["name"] for node in tree] == ["nested", "one", "two"]


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


def test_workspace_quota_counts_shared_hardlink_inode_once(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    original = public / "package.js"
    original.write_bytes(b"content")
    os.link(original, public / "package-copy.js")

    usage = workspace.check_agent_workspace_quota("session")

    assert usage == workspace.AgentWorkspaceUsage(
        total_bytes=7,
        file_count=2,
        entry_count=2,
    )


def test_workspace_quota_does_not_limit_empty_directories(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    for name in ("one", "two", "three"):
        (public / name).mkdir()

    usage = workspace.check_agent_workspace_quota("session")

    assert usage.entry_count == 3


def test_workspace_quota_uses_explicit_stack_without_depth_limit(workspace_root):
    public = workspace.ensure_agent_workspace("session")
    current = public
    for index in range(70):
        current = current / f"d{index}"
        current.mkdir()

    assert workspace.check_agent_workspace_quota("session").entry_count == 70


def test_workspace_quota_enforces_only_total_bytes(
    workspace_root,
    monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MAX_BYTES", 4)
    (public / "entry").write_bytes(b"12345")

    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="总大小"):
        workspace.check_agent_workspace_quota("session")


def test_workspace_quota_does_not_depend_on_free_space_preflight(
    workspace_root,
    monkeypatch,
):
    workspace.ensure_agent_workspace("session")
    monkeypatch.setattr(
        workspace.os,
        "fstatvfs",
        lambda _fd: (_ for _ in ()).throw(OSError("statvfs failed")),
    )

    assert workspace.check_agent_workspace_quota("session").total_bytes == 0


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


@pytest.mark.parametrize("file_count", [1, 200])
def test_batch_injection_scans_workspace_twice_and_reports_committed_progress(
    workspace_root, monkeypatch, file_count,
):
    scans = []
    original_scan = workspace._scan_workspace_usage_fd

    def track_scan(*args, **kwargs):
        scans.append(True)
        return original_scan(*args, **kwargs)

    monkeypatch.setattr(workspace, "_scan_workspace_usage_fd", track_scan)
    events = []
    files = {f"evidence/lib/file-{index}.h": b"content" for index in range(file_count)}
    workspace.inject_agent_workspace_files("session", files, progress=lambda *event: events.append(event))

    assert len(scans) == 2
    assert events == [(index, file_count) for index in range(1, file_count + 1)]
    public = workspace_root / "sessions/session/workspace"
    assert len(list((public / "evidence/lib").iterdir())) == file_count
    assert (public / "evidence/lib/file-0.h").read_bytes() == b"content"
    assert _mode(public / "evidence/lib/file-0.h") == 0o600


def test_batch_injection_resume_counts_overwrites_and_keeps_unlisted_files(
    workspace_root, monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    (public / "keep").write_bytes(b"12")
    (public / "first").write_bytes(b"34")
    (public / "second").write_bytes(b"56")
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MAX_BYTES", 6)

    with pytest.raises(workspace.AgentWorkspaceQuotaError):
        workspace.inject_agent_workspace_files("session", {"first": b"a", "second": b"long"})
    assert (public / "first").read_bytes() == b"a"
    assert (public / "second").read_bytes() == b"56"
    assert (public / "keep").read_bytes() == b"12"

    workspace.inject_agent_workspace_files("session", {"first": b"a", "second": b"xyz"})
    assert workspace.get_agent_workspace_usage("session").total_bytes == 6
    assert (public / "second").read_bytes() == b"xyz"
    assert (public / "keep").read_bytes() == b"12"
    assert not list((public.parent / ".host-write-staging").iterdir())


def test_batch_injection_replacing_shared_hardlinks_counts_remaining_inode(
    workspace_root, monkeypatch,
):
    public = workspace.ensure_agent_workspace("session")
    (public / "first").write_bytes(b"1234")
    os.link(public / "first", public / "second")
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_MAX_BYTES", 6)

    with pytest.raises(workspace.AgentWorkspaceQuotaError):
        workspace.inject_agent_workspace_files("session", {"first": b"abc"})
    assert (public / "first").stat().st_ino == (public / "second").stat().st_ino
    assert (public / "first").read_bytes() == b"1234"

    workspace.inject_agent_workspace_files("session", {"first": b"ab", "second": b"cdef"})
    assert workspace.get_agent_workspace_usage("session").total_bytes == 6
    assert (public / "first").stat().st_ino != (public / "second").stat().st_ino


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_batch_injection_replaces_destination_link_without_changing_outside_file(
    workspace_root, tmp_path, link_kind,
):
    public = workspace.ensure_agent_workspace("session")
    outside = tmp_path / "outside"
    outside.write_text("original")
    if link_kind == "symlink":
        (public / "target").symlink_to(outside)
    else:
        os.link(outside, public / "target")

    workspace.inject_agent_workspace_files("session", {"target": "replacement"})
    assert outside.read_text() == "original"
    assert (public / "target").read_text() == "replacement"
    assert (public / "target").stat().st_nlink == 1
    assert not (public / "target").is_symlink()


@pytest.mark.parametrize("source_kind", ["symlink", "hardlink", "parent_symlink", "fifo"])
def test_batch_injection_rejects_linked_and_special_sources(
    workspace_root, tmp_path, source_kind,
):
    directory = tmp_path / "input"
    directory.mkdir()
    original = directory / "original"
    original.write_bytes(b"original")
    source = directory / "source"
    if source_kind == "symlink":
        source.symlink_to(original)
    elif source_kind == "hardlink":
        os.link(original, source)
    elif source_kind == "parent_symlink":
        linked = tmp_path / "linked"
        linked.symlink_to(directory, target_is_directory=True)
        source = linked / "original"
    else:
        os.mkfifo(source)

    with pytest.raises(workspace.AgentWorkspaceSecurityError):
        workspace.inject_agent_workspace_files("session", {"result": source})
    assert not (workspace_root / "sessions/session/workspace/result").exists()
    assert original.read_bytes() == b"original"


def test_batch_injection_rejects_linked_destination_parent(workspace_root, tmp_path):
    public = workspace.ensure_agent_workspace("session")
    outside = tmp_path / "outside"
    outside.mkdir()
    (public / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(workspace.AgentWorkspaceSecurityError):
        workspace.inject_agent_workspace_files("session", {"linked/result": b"bad"})
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("relative_path", ["../escape", "/absolute", ".runtime/private", "dir/.numoj-agent/state"])
def test_batch_injection_rejects_nonpublic_paths(workspace_root, relative_path):
    with pytest.raises(workspace.AgentWorkspacePathError):
        workspace.inject_agent_workspace_files("session", {relative_path: b"bad"})


def test_batch_injection_restores_old_file_when_publication_fails(workspace_root, monkeypatch):
    public = workspace.ensure_agent_workspace("session")
    (public / "target").write_bytes(b"original")
    original_rename = workspace.os.rename

    def fail_publication(source, destination, **kwargs):
        if str(source).startswith("write-"):
            raise OSError("publication failed")
        return original_rename(source, destination, **kwargs)

    monkeypatch.setattr(workspace.os, "rename", fail_publication)
    with pytest.raises(OSError, match="publication failed"):
        workspace.inject_agent_workspace_files("session", {"target": b"replacement"})
    assert (public / "target").read_bytes() == b"original"
    assert not list((public.parent / ".host-write-staging").iterdir())


@pytest.mark.parametrize("batch", [False, True])
def test_host_publication_keeps_backup_until_fsync_succeeds(workspace_root, monkeypatch, batch):
    public = workspace.ensure_agent_workspace("session")
    (public / "target").write_bytes(b"original")
    staging = public.parent / ".host-write-staging"
    staging.mkdir()
    staging_inode = staging.stat().st_ino
    original_fsync = workspace.os.fsync

    def fail_staging_fsync(fd):
        if os.fstat(fd).st_ino == staging_inode:
            raise OSError("fsync failed")
        return original_fsync(fd)

    monkeypatch.setattr(workspace.os, "fsync", fail_staging_fsync)
    with pytest.raises(OSError, match="fsync failed"):
        if batch:
            workspace.inject_agent_workspace_files("session", {"target": b"replacement"})
        else:
            workspace.write_agent_workspace_file("session", "target", b"replacement")
    assert (public / "target").read_bytes() == b"original"
    assert not list(staging.iterdir())


def test_batch_injection_refuses_incomplete_existing_usage_scan(workspace_root, monkeypatch):
    public = workspace.ensure_agent_workspace("session")
    (public / "unreadable").mkdir()
    (public / "unreadable/old").write_bytes(b"existing data")
    original_open = workspace._open_existing_directory_at

    def deny_existing_directory(parent_fd, name, **kwargs):
        if name == "unreadable":
            raise workspace.AgentWorkspaceSecurityError("cannot inspect")
        return original_open(parent_fd, name, **kwargs)

    monkeypatch.setattr(workspace, "_open_existing_directory_at", deny_existing_directory)
    with pytest.raises(workspace.AgentWorkspaceQuotaError, match="无法完整统计"):
        workspace.inject_agent_workspace_files("session", {"new": b"new data"})
    assert not (public / "new").exists()
    assert (public / "unreadable/old").read_bytes() == b"existing data"



def test_export_public_workspace_root_keeps_independent_files_and_skips_runtime(workspace_root, tmp_path):
    public = workspace.ensure_agent_workspace("session")
    visible = {
        "main.py": b"print('answer')", "problem/problem.md": b"question",
        "assets/data.bin": b"data", ".gitignore": b"cache/",
        ".git/config": b"user project config", ".claude/notes": b"user project notes",
    }
    hidden = {
        ".runtime/home/token": b"secret", ".numoj-agent": b"internal",
        ".aj_session_state.json": b"native session", "src/.runtime-cache/private": b"secret",
    }
    for relative, content in (visible | hidden).items():
        path = public / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    destination = tmp_path / "answer"

    assert workspace.export_agent_workspace_directory("session", ".", destination) == destination
    assert {path.relative_to(destination).as_posix(): path.read_bytes()
            for path in destination.rglob("*") if path.is_file()} == visible
    assert not (destination / ".runtime").exists()
    assert not (destination / "src/.runtime-cache").exists()
    (public / "main.py").write_bytes(b"late change")
    assert (destination / "main.py").read_bytes() == visible["main.py"]
    assert (public / ".runtime/home/token").read_bytes() == b"secret"


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_export_workspace_root_still_rejects_links(workspace_root, tmp_path, link_kind):
    public = workspace.ensure_agent_workspace("session")
    outside = tmp_path / "original"
    outside.write_bytes(b"outside")
    if link_kind == "symlink":
        (public / "linked").symlink_to(outside)
    else:
        os.link(outside, public / "linked")

    with pytest.raises(workspace.AgentWorkspaceSecurityError):
        workspace.export_agent_workspace_directory("session", ".", tmp_path / "answer")
    assert outside.read_bytes() == b"outside"


def test_export_workspace_root_does_not_overwrite_existing_destination(workspace_root, tmp_path):
    workspace.inject_agent_workspace_files("session", {"new.txt": b"new"})
    destination = tmp_path / "answer"
    destination.mkdir()
    (destination / "old.txt").write_bytes(b"old")

    with pytest.raises(FileExistsError):
        workspace.export_agent_workspace_directory("session", ".", destination)
    assert [path.name for path in destination.iterdir()] == ["old.txt"]
    assert (destination / "old.txt").read_bytes() == b"old"


@pytest.mark.parametrize("path", ["", "./", "..", "/"])
def test_export_workspace_root_alias_does_not_relax_other_paths(workspace_root, tmp_path, path):
    with pytest.raises(workspace.AgentWorkspacePathError):
        workspace.export_agent_workspace_directory("session", path, tmp_path / "answer")
