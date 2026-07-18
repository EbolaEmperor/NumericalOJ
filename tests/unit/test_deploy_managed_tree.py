import os
from pathlib import Path

import pytest

from deploy.managed_tree import activate, create_backup, rollback


def _manifest(path: Path, *entries: str) -> Path:
    path.write_text("".join(f"{entry}\n" for entry in sorted(entries)), encoding="utf-8")
    return path


def _transaction(tmp_path, old_entries, new_entries):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    old_manifest = _manifest(tmp_path / "old.txt", *old_entries)
    new_manifest = _manifest(tmp_path / "new.txt", *new_entries)
    record = tmp_path / "record.jsonl"
    archive = tmp_path / "backup.tar.gz"
    return source, target, old_manifest, new_manifest, record, archive


def test_activation_and_rollback_support_file_to_directory_conversion(tmp_path):
    source, target, old_manifest, new_manifest, record, archive = _transaction(
        tmp_path, ("feature",), ("feature/handler.py",)
    )
    (target / "feature").write_text("old file", encoding="utf-8")
    (source / "feature").mkdir()
    (source / "feature/handler.py").write_text("new file", encoding="utf-8")

    create_backup(target, old_manifest, archive)
    activate(source, target, old_manifest, new_manifest, record)
    assert (target / "feature").is_dir()
    assert (target / "feature/handler.py").read_text(encoding="utf-8") == "new file"

    rollback(target, old_manifest, new_manifest, record, archive)
    assert (target / "feature").is_file()
    assert (target / "feature").read_text(encoding="utf-8") == "old file"


def test_activation_and_rollback_support_directory_to_file_conversion(tmp_path):
    source, target, old_manifest, new_manifest, record, archive = _transaction(
        tmp_path, ("feature/python/handler.py",), ("feature",)
    )
    (target / "feature/python").mkdir(parents=True)
    (target / "feature/python/handler.py").write_text("old file", encoding="utf-8")
    (source / "feature").write_text("new file", encoding="utf-8")

    create_backup(target, old_manifest, archive)
    activate(source, target, old_manifest, new_manifest, record)
    assert (target / "feature").is_file()
    assert (target / "feature").read_text(encoding="utf-8") == "new file"

    rollback(target, old_manifest, new_manifest, record, archive)
    assert (target / "feature").is_dir()
    assert (target / "feature/python/handler.py").read_text(encoding="utf-8") == "old file"


def test_activation_refuses_to_overwrite_an_unowned_path(tmp_path):
    source, target, old_manifest, new_manifest, record, archive = _transaction(
        tmp_path, (), ("manual.txt",)
    )
    (source / "manual.txt").write_text("candidate", encoding="utf-8")
    (target / "manual.txt").write_text("production-owned", encoding="utf-8")
    create_backup(target, old_manifest, archive)

    with pytest.raises(FileExistsError):
        activate(source, target, old_manifest, new_manifest, record)
    assert (target / "manual.txt").read_text(encoding="utf-8") == "production-owned"


def test_rollback_refuses_to_delete_a_replaced_candidate_file(tmp_path):
    source, target, old_manifest, new_manifest, record, archive = _transaction(
        tmp_path, ("old.txt",), ("new.txt",)
    )
    (target / "old.txt").write_text("old", encoding="utf-8")
    (source / "new.txt").write_text("candidate", encoding="utf-8")
    create_backup(target, old_manifest, archive)
    activate(source, target, old_manifest, new_manifest, record)
    (target / "new.txt").unlink()
    (target / "new.txt").write_text("replaced", encoding="utf-8")

    with pytest.raises(RuntimeError, match="changed during deployment"):
        rollback(target, old_manifest, new_manifest, record, archive)
    assert (target / "new.txt").read_text(encoding="utf-8") == "replaced"


def test_managed_symlink_must_stay_inside_repository(tmp_path):
    source, target, old_manifest, new_manifest, record, _archive = _transaction(
        tmp_path, (), ("link",)
    )
    os.symlink("../../outside", source / "link")

    with pytest.raises(ValueError, match="escapes root"):
        activate(source, target, old_manifest, new_manifest, record)
