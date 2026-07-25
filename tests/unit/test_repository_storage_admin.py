#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import os
from pathlib import Path
import stat

from oj_modules.repository import admin as admin_services
from oj_modules.repository import storage


def _state(*, entry_count, total_size):
    return {
        "user_id": 7,
        "entry_count": entry_count,
        "total_size": total_size,
    }


def _directory(entry_id, path, name, parent_id=None):
    return {
        "id": entry_id,
        "parent_id": parent_id,
        "name": name,
        "relative_path": path,
        "entry_type": "directory",
        "file_size": 0,
        "content_sha256": None,
    }


def _file(entry_id, path, name, data, parent_id=None):
    return {
        "id": entry_id,
        "parent_id": parent_id,
        "name": name,
        "relative_path": path,
        "entry_type": "file",
        "file_size": len(data),
        "content_sha256": hashlib.sha256(data).hexdigest(),
    }


def test_doctor_tree_audit_accepts_exact_files_and_empty_directories(tmp_path):
    tree = tmp_path / "tree"
    (tree / "empty").mkdir(parents=True)
    (tree / "src").mkdir()
    data = b"int main() {}\n"
    (tree / "src" / "main.cpp").write_bytes(data)
    entries = [
        _directory(1, "empty", "empty"),
        _directory(2, "src", "src"),
        _file(3, "src/main.cpp", "main.cpp", data, parent_id=2),
    ]

    issues = admin_services.audit_tree_against_metadata(
        tree,
        _state(entry_count=3, total_size=len(data)),
        entries,
    )

    assert issues == []


def test_doctor_tree_audit_reports_digest_or_orphan_mismatch(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.h").write_bytes(b"changed\n")
    (tree / "orphan.txt").write_bytes(b"orphan\n")
    expected = b"expected\n"

    issues = admin_services.audit_tree_against_metadata(
        tree,
        _state(entry_count=1, total_size=len(expected)),
        [_file(1, "a.h", "a.h", expected)],
    )

    codes = {issue["code"] for issue in issues}
    assert "tree_file_digest_mismatch" in codes
    assert "tree_orphan_entry" in codes
    assert "tree_entry_count_mismatch" in codes


def test_doctor_tree_audit_never_follows_symlink(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    (tree / "linked").symlink_to(outside)

    issues = admin_services.audit_tree_against_metadata(
        tree,
        _state(entry_count=0, total_size=0),
        [],
    )

    assert any(issue["code"] == "tree_entry_unsafe" for issue in issues)


def test_doctor_managed_root_reports_every_non_directory_inode(tmp_path):
    managed = tmp_path / "snapshots"
    managed.mkdir()
    (managed / "real").mkdir()
    (managed / "plain-file").write_text("unexpected", encoding="utf-8")
    (managed / "linked").symlink_to(managed / "real")

    directories, issues = admin_services._managed_child_directories(
        managed,
        managed_root="snapshots",
    )

    assert directories == {"real"}
    assert {issue["code"] for issue in issues} == {
        "managed_root_entry_unsafe"
    }
    assert {os.path.basename(issue["path"]) for issue in issues} == {
        "plain-file",
        "linked",
    }


def test_doctor_managed_locks_accepts_only_private_empty_storage_key_files(
    tmp_path,
):
    managed = tmp_path / "locks"
    managed.mkdir()
    valid_key = "a" * 32
    valid = managed / f"{valid_key}.lock"
    valid.touch(mode=0o600)
    os.chmod(valid, 0o600)

    storage_keys, issues = admin_services._managed_lock_files(managed)

    assert storage_keys == {valid_key}
    assert issues == []
    assert stat.S_IMODE(valid.stat().st_mode) == 0o600


def test_doctor_managed_locks_rejects_wrong_name_mode_content_and_inode_type(
    tmp_path,
):
    managed = tmp_path / "locks"
    managed.mkdir()
    wrong_name = managed / "unexpected.lock"
    wrong_name.touch(mode=0o600)
    wrong_mode = managed / f"{'b' * 32}.lock"
    wrong_mode.touch(mode=0o600)
    os.chmod(wrong_mode, 0o640)
    nonempty = managed / f"{'c' * 32}.lock"
    nonempty.write_text("not empty", encoding="utf-8")
    os.chmod(nonempty, 0o600)
    directory = managed / f"{'d' * 32}.lock"
    directory.mkdir()
    linked = managed / f"{'e' * 32}.lock"
    linked.symlink_to(wrong_name)
    hardlinked = managed / f"{'f' * 32}.lock"
    os.link(wrong_name, hardlinked)

    storage_keys, issues = admin_services._managed_lock_files(managed)

    assert storage_keys == set()
    assert {Path(issue["path"]).name for issue in issues} == {
        wrong_name.name,
        wrong_mode.name,
        nonempty.name,
        directory.name,
        linked.name,
        hardlinked.name,
    }
    assert {issue["code"] for issue in issues} == {
        "managed_root_entry_unsafe",
    }


def test_doctor_snapshot_audit_checks_binding_manifest_tree_and_file_hashes(
    tmp_path,
):
    root = tmp_path / "repository-storage"
    snapshot_key = "d" * 32
    snapshot_base = root / "snapshots" / snapshot_key
    tree = snapshot_base / "tree"
    (tree / "include").mkdir(parents=True)
    content = b"#define VALUE 1\n"
    (tree / "include" / "value.h").write_bytes(content)
    manifest = {
        "schema_version": 1,
        "submission_id": 91,
        "user_id": 7,
        "repository_generation": 3,
        "entries": [
            {
                "entry_id": 1,
                "path": "include",
                "type": "directory",
            },
            {
                "entry_id": 2,
                "path": "include/value.h",
                "type": "file",
                "size": len(content),
                "file_version": 2,
                "sha256": hashlib.sha256(content).hexdigest(),
            },
        ],
    }
    manifest_bytes = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    (snapshot_base / "manifest.json").write_bytes(manifest_bytes)
    row = {
        "submission_id": 91,
        "user_id": 7,
        "snapshot_key": snapshot_key,
        "relative_root": f"snapshots/{snapshot_key}/tree",
        "repository_generation": 3,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "entry_count": 2,
        "total_size": len(content),
    }

    assert (
        admin_services.audit_submission_snapshot_against_metadata(row, root)
        == []
    )

    wrong_binding = {**row, "repository_generation": 4}
    assert admin_services.audit_submission_snapshot_against_metadata(
        wrong_binding,
        root,
    )[0]["code"] == "snapshot_integrity_error"

    (tree / "include" / "value.h").write_bytes(b"#define VALUE 2\n")
    assert admin_services.audit_submission_snapshot_against_metadata(
        row,
        root,
    )[0]["code"] == "snapshot_integrity_error"

    (tree / "include" / "value.h").write_bytes(content)
    (tree / "orphan.h").write_bytes(b"orphan\n")
    assert admin_services.audit_submission_snapshot_against_metadata(
        row,
        root,
    )[0]["code"] == "snapshot_integrity_error"


def test_quarantine_moves_orphan_atomically_without_deleting(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "repository-storage"
    monkeypatch.setattr(storage, "STORAGE_ROOT", root)
    monkeypatch.setattr(storage, "_probe_case_sensitive", lambda _path: None)
    storage._ready_roots.clear()
    storage.ensure_repository_storage_ready()
    source = root / "staging" / ("a" * 32)
    source.mkdir()
    (source / "payload").write_text("keep", encoding="utf-8")
    info = source.lstat()
    monkeypatch.setattr(
        admin_services,
        "plan_repository_orphan_quarantine",
        lambda: {
            "storage_root": str(root),
            "doctor_ok": False,
            "items": [
                {
                    "category": "upload_staging_orphan_or_expired",
                    "source_relative": source.relative_to(root).as_posix(),
                    "device": int(info.st_dev),
                    "inode": int(info.st_ino),
                    "mode": int(info.st_mode),
                }
            ],
            "blocked": [],
        },
    )

    report = admin_services.quarantine_repository_orphans(
        apply=True,
        writers_stopped_confirmed=True,
    )

    assert not source.exists()
    destination = root / report["items"][0]["quarantine_relative"]
    assert (destination / "payload").read_text(encoding="utf-8") == "keep"
    manifest = json.loads(
        (root / "quarantine" / report["batch_id"] / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["status"] == "complete"
    assert manifest["items"][0]["source_relative"] == f"staging/{'a' * 32}"
    storage._ready_roots.clear()


def test_quarantine_default_is_dry_run(monkeypatch):
    monkeypatch.setattr(
        admin_services,
        "plan_repository_orphan_quarantine",
        lambda: {
            "storage_root": "/managed",
            "doctor_ok": False,
            "items": [{"source_relative": "staging/orphan"}],
            "blocked": [],
        },
    )

    report = admin_services.quarantine_repository_orphans()

    assert report["apply"] is False
    assert report["batch_id"] is None
