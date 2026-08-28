# -*- coding: utf-8 -*-
"""受限 ZIP 解压工具的纯文件系统测试。"""

from pathlib import Path
import stat
import zipfile

import pytest

from oj_modules.shared.archive import (
    ArchiveExtractionError,
    ZipExtractionPolicy,
    build_directory_zip,
    extract_zip,
)


def _policy(**overrides):
    values = {
        "max_members": 16,
        "max_file_bytes": 1024,
        "max_total_bytes": 2048,
        "max_compression_ratio": 100.0,
    }
    values.update(overrides)
    return ZipExtractionPolicy(**values)


def _assert_reason(error, reason):
    assert error.value.reason == reason


def test_build_directory_zip_preserves_one_named_root(tmp_path):
    source = tmp_path / "skill-source"
    (source / "scripts").mkdir(parents=True)
    (source / "SKILL.md").write_text("skill", encoding="utf-8")
    (source / "scripts" / "cli.py").write_text("print('ok')", encoding="utf-8")

    archive_buffer = build_directory_zip(source, archive_root="numoj-user")

    with zipfile.ZipFile(archive_buffer) as archive:
        assert archive.namelist() == [
            "numoj-user/SKILL.md",
            "numoj-user/scripts/cli.py",
        ]
        assert archive.read("numoj-user/SKILL.md") == b"skill"


def test_extract_zip_writes_nested_files_and_normalizes_backslashes(tmp_path):
    archive = tmp_path / "valid.zip"
    destination = tmp_path / "out"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("project/", b"")
        zf.writestr("project\\main.tex", b"content")

    extract_zip(archive, destination, policy=_policy())

    assert (destination / "project" / "main.tex").read_bytes() == b"content"


@pytest.mark.parametrize(
    ("member_name", "reason"),
    [
        ("../outside.txt", "path_traversal"),
        ("nested/../../outside.txt", "path_traversal"),
        ("/absolute.txt", "absolute_path"),
        (r"C:\\absolute.txt", "absolute_path"),
        (r"\\server\\share\\file.txt", "absolute_path"),
    ],
)
def test_extract_zip_rejects_traversal_and_absolute_paths_and_cleans_destination(
        tmp_path, member_name, reason):
    archive = tmp_path / "unsafe.zip"
    destination = tmp_path / "out"
    outside = tmp_path / "outside.txt"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("safe.txt", b"safe")
        zf.writestr(member_name, b"unsafe")

    with pytest.raises(ArchiveExtractionError) as error:
        extract_zip(
            archive,
            destination,
            policy=_policy(cleanup_on_error=True),
        )

    _assert_reason(error, reason)
    assert not destination.exists()
    assert not outside.exists()


def test_extract_zip_can_skip_unsafe_members_without_weakening_resource_limits(tmp_path):
    archive = tmp_path / "mixed.zip"
    destination = tmp_path / "out"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../outside.txt", b"unsafe")
        zf.writestr("safe.txt", b"safe")

    extract_zip(
        archive,
        destination,
        policy=_policy(unsafe_member_action="skip"),
    )

    assert (destination / "safe.txt").read_bytes() == b"safe"
    assert not (tmp_path / "outside.txt").exists()

    with pytest.raises(ArchiveExtractionError) as error:
        extract_zip(
            archive,
            tmp_path / "limited",
            policy=_policy(max_members=1, unsafe_member_action="skip"),
        )
    _assert_reason(error, "too_many_members")


def test_extract_zip_rejects_symlink_members(tmp_path):
    archive = tmp_path / "symlink.zip"
    link_info = zipfile.ZipInfo("link")
    link_info.create_system = 3
    link_info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(link_info, "../outside.txt")

    with pytest.raises(ArchiveExtractionError) as error:
        extract_zip(archive, tmp_path / "out", policy=_policy())

    _assert_reason(error, "symlink")
    assert not (tmp_path / "out" / "link").exists()


@pytest.mark.parametrize(
    ("entries", "policy_overrides", "reason"),
    [
        ([('a.txt', b'a'), ('b.txt', b'b')], {"max_members": 1}, "too_many_members"),
        ([('large.txt', b'12345')], {"max_file_bytes": 4}, "file_too_large"),
        (
            [('a.txt', b'123'), ('b.txt', b'456')],
            {"max_total_bytes": 5},
            "total_too_large",
        ),
    ],
)
def test_extract_zip_enforces_member_and_size_limits(
        tmp_path, entries, policy_overrides, reason):
    archive = tmp_path / f"{reason}.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, content in entries:
            zf.writestr(name, content)

    with pytest.raises(ArchiveExtractionError) as error:
        extract_zip(archive, tmp_path / reason, policy=_policy(**policy_overrides))

    _assert_reason(error, reason)


def test_extract_zip_rejects_suspicious_compression_ratio(tmp_path):
    archive = tmp_path / "ratio.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.txt", b"0" * 1000)

    with pytest.raises(ArchiveExtractionError) as error:
        extract_zip(
            archive,
            tmp_path / "out",
            policy=_policy(max_compression_ratio=2.0),
        )

    _assert_reason(error, "compression_ratio")


def test_extract_zip_rejects_duplicate_normalized_targets(tmp_path):
    archive = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("same.txt", b"first")
        zf.writestr("./same.txt", b"second")

    with pytest.raises(ArchiveExtractionError) as error:
        extract_zip(archive, tmp_path / "out", policy=_policy())

    _assert_reason(error, "duplicate_target")


@pytest.mark.parametrize(
    "entries",
    [
        [("node", b"file"), ("node/child.txt", b"child")],
        [("node/child.txt", b"child"), ("node", b"file")],
    ],
)
def test_extract_zip_rejects_file_and_descendant_path_conflicts(tmp_path, entries):
    archive = tmp_path / "conflict.zip"
    destination = tmp_path / "out"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, content in entries:
            zf.writestr(name, content)

    with pytest.raises(ArchiveExtractionError) as error:
        extract_zip(
            archive,
            destination,
            policy=_policy(cleanup_on_error=True),
        )

    _assert_reason(error, "target_conflict")
    assert not destination.exists()


def test_extract_zip_can_require_a_non_empty_archive(tmp_path):
    archive = tmp_path / "empty.zip"
    with zipfile.ZipFile(archive, "w"):
        pass

    with pytest.raises(ArchiveExtractionError) as error:
        extract_zip(
            archive,
            tmp_path / "out",
            policy=_policy(require_non_empty=True),
        )

    _assert_reason(error, "empty_archive")


def test_extract_zip_cleanup_policy_also_applies_to_invalid_zip_files(tmp_path):
    archive = tmp_path / "invalid.zip"
    archive.write_bytes(b"not a zip")
    destination = tmp_path / "out"

    with pytest.raises(zipfile.BadZipFile):
        extract_zip(
            archive,
            destination,
            policy=_policy(cleanup_on_error=True),
        )

    assert not destination.exists()


def test_agent_workspace_does_not_copy_a_policy_rejected_zip(monkeypatch, tmp_path):
    from oj_modules.tasks.ranking import agent_judge as agent_tasks

    archive = tmp_path / "too-many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", b"a")
        zf.writestr("b.txt", b"b")

    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(agent_tasks, "JUDGE_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(agent_tasks, "JUDGE_PACKAGE_MAX_MEMBERS", 1)

    with pytest.raises(ArchiveExtractionError) as error:
        agent_tasks._prepare_workspace(
            {"id": 7, "code_path": str(archive)},
            {"id": 3, "description": ""},
            [],
            attempt_id="attempt-1",
        )

    _assert_reason(error, "too_many_members")
    assert not list(workspace_root.rglob(archive.name))


def test_agent_workspace_still_accepts_a_plain_source_file(monkeypatch, tmp_path):
    from oj_modules.tasks.ranking import agent_judge as agent_tasks

    source = tmp_path / "main.py"
    source.write_text("print('ok')\n", encoding="utf-8")
    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(agent_tasks, "JUDGE_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(agent_tasks, "list_competition_files", lambda _competition_id: [])

    workspace, result_name = agent_tasks._prepare_workspace(
        {"id": 8, "code_path": str(source)},
        {"id": 4, "description": "test"},
        [],
        attempt_id="attempt-2",
    )

    workspace_path = Path(workspace)
    copied_source = workspace_path / "submission" / source.name
    assert copied_source.read_text(encoding="utf-8") == "print('ok')\n"
    assert (workspace_path / result_name).is_file()


def test_agent_workspace_does_not_copy_a_crc_damaged_zip(monkeypatch, tmp_path):
    from oj_modules.tasks.ranking import agent_judge as agent_tasks

    archive = tmp_path / "damaged.dat"
    original_payload = b"unique archive payload"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("main.py", original_payload)
    damaged = bytearray(archive.read_bytes())
    payload_offset = damaged.find(original_payload)
    assert payload_offset >= 0
    damaged[payload_offset] ^= 0x01
    archive.write_bytes(damaged)
    assert zipfile.is_zipfile(archive)

    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(agent_tasks, "JUDGE_WORKSPACE_ROOT", str(workspace_root))

    with pytest.raises(zipfile.BadZipFile):
        agent_tasks._prepare_workspace(
            {"id": 9, "code_path": str(archive)},
            {"id": 5, "description": ""},
            [],
            attempt_id="attempt-3",
        )

    assert not list(workspace_root.rglob(archive.name))


def test_written_homework_adapter_preserves_validation_messages_and_cleans_up(tmp_path):
    from oj_modules.tasks import written_homework_tasks as written_tasks

    empty_archive = tmp_path / "empty-written.zip"
    with zipfile.ZipFile(empty_archive, "w"):
        pass
    empty_destination = tmp_path / "empty-out"
    with pytest.raises(RuntimeError, match="ZIP 压缩包为空"):
        written_tasks._safe_extract_zip(empty_archive, empty_destination)
    assert not empty_destination.exists()

    traversal_archive = tmp_path / "traversal-written.zip"
    with zipfile.ZipFile(traversal_archive, "w") as zf:
        zf.writestr("../main.tex", b"unsafe")
    traversal_destination = tmp_path / "traversal-out"
    with pytest.raises(RuntimeError, match="ZIP 包含非法路径"):
        written_tasks._safe_extract_zip(traversal_archive, traversal_destination)
    assert not traversal_destination.exists()

    oversized_archive = tmp_path / "oversized-written.zip"
    with zipfile.ZipFile(oversized_archive, "w") as zf:
        zf.writestr("main.tex", b"12345")
    oversized_destination = tmp_path / "oversized-out"
    with pytest.raises(RuntimeError, match="ZIP 解压后体积过大"):
        written_tasks._safe_extract_zip(
            oversized_archive,
            oversized_destination,
            max_total_uncompressed=4,
        )
    assert not oversized_destination.exists()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"max_members": 0}, "max_members"),
        ({"max_file_bytes": 0}, "max_file_bytes"),
        ({"max_total_bytes": 0}, "max_total_bytes"),
        ({"max_compression_ratio": 0}, "max_compression_ratio"),
        ({"max_compression_ratio": float("nan")}, "max_compression_ratio"),
        ({"max_compression_ratio": float("inf")}, "max_compression_ratio"),
        ({"unsafe_member_action": "ignore"}, "unsafe_member_action"),
        ({"chunk_size": 0}, "chunk_size"),
    ],
)
def test_zip_extraction_policy_rejects_invalid_configuration(overrides, message):
    with pytest.raises(ValueError, match=message):
        _policy(**overrides)
