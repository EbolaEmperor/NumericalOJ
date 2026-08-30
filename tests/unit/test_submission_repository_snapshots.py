#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import os

import pytest

from backend.oj_modules.repository import storage as repository_storage
from backend.oj_modules.submissions import repository_snapshots as snapshots
from backend.oj_modules.tasks import evaluate_tasks


class _FakeCelery:
    def __init__(self):
        self.tasks = {}

    def task(self, **options):
        def decorator(function):
            self.tasks[options["name"]] = function
            return function

        return decorator


class _SnapshotCursor:
    def __init__(self, state, entries):
        self.state = dict(state)
        self.entries = [dict(item) for item in entries]
        self._one = None
        self._many = []
        self.binding = None
        self.executed = []

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        self.executed.append((normalized, params))
        if "FROM repository_states" in normalized:
            self._one = dict(self.state)
            self._many = []
            return
        if "FROM repository_entries" in normalized:
            self._one = None
            self._many = [dict(item) for item in self.entries]
            return
        if "INSERT INTO submission_repository_snapshots" in normalized:
            keys = (
                "submission_id",
                "user_id",
                "snapshot_key",
                "relative_root",
                "repository_generation",
                "manifest_sha256",
                "entry_count",
                "total_size",
            )
            self.binding = dict(zip(keys, params))
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        return self._one

    def fetchall(self):
        return list(self._many)


@pytest.fixture
def isolated_repository_storage(tmp_path, monkeypatch):
    storage_root = tmp_path / "repository-storage"
    monkeypatch.setattr(repository_storage, "STORAGE_ROOT", storage_root)
    # macOS 默认测试卷可能大小写不敏感；此处只测试快照语义，存储根探针另有覆盖。
    monkeypatch.setattr(repository_storage, "_probe_case_sensitive", lambda _path: None)
    repository_storage._ready_roots.clear()
    yield storage_root
    repository_storage._ready_roots.clear()


def test_submission_snapshot_keeps_old_tree_after_live_atomic_replace(
    isolated_repository_storage,
):
    storage_key = "a" * 32
    live_tree = repository_storage.ensure_user_tree(storage_key)
    (live_tree / "include").mkdir()
    (live_tree / "empty").mkdir()
    original = b"#define VALUE 1\n"
    (live_tree / "include" / "value.h").write_bytes(original)

    cursor = _SnapshotCursor(
        state={
            "storage_key": storage_key,
            "repository_generation": 7,
            "entry_count": 3,
            "total_size": len(original),
        },
        # 故意打乱输入顺序，快照实现必须按目录深度恢复。
        entries=[
            {
                "id": 3,
                "parent_id": 1,
                "relative_path": "include/value.h",
                "entry_type": "file",
                "file_size": len(original),
                "file_version": 4,
                "content_sha256": hashlib.sha256(original).hexdigest(),
            },
            {
                "id": 2,
                "parent_id": None,
                "relative_path": "empty",
                "entry_type": "directory",
                "file_size": 0,
                "file_version": 0,
                "content_sha256": None,
            },
            {
                "id": 1,
                "parent_id": None,
                "relative_path": "include",
                "entry_type": "directory",
                "file_size": 0,
                "file_version": 0,
                "content_sha256": None,
            },
        ],
    )

    result = snapshots.capture_submission_repository_snapshot(
        cursor,
        submission_id=91,
        user_id=12,
    )
    assert cursor.binding is not None
    assert result["repository_generation"] == 7

    replacement = live_tree / "include" / ".value.h.new"
    replacement.write_bytes(b"#define VALUE 2\n")
    os.replace(replacement, live_tree / "include" / "value.h")

    restored = snapshots._read_snapshot_entries(cursor.binding)
    by_path = {item["relative_path"]: item for item in restored}
    assert by_path["empty"]["entry_type"] == "directory"
    assert by_path["include/value.h"]["content"] == original.decode("utf-8")


def test_submission_snapshot_rejects_live_metadata_hash_mismatch(
    isolated_repository_storage,
):
    storage_key = "b" * 32
    live_tree = repository_storage.ensure_user_tree(storage_key)
    (live_tree / "bad.h").write_text("actual", encoding="utf-8")
    cursor = _SnapshotCursor(
        state={
            "storage_key": storage_key,
            "repository_generation": 3,
            "entry_count": 1,
            "total_size": len("actual"),
        },
        entries=[
            {
                "id": 1,
                "parent_id": None,
                "relative_path": "bad.h",
                "entry_type": "file",
                "file_size": len("actual"),
                "file_version": 1,
                "content_sha256": hashlib.sha256(b"different").hexdigest(),
            },
        ],
    )

    with pytest.raises(snapshots.RepositorySnapshotError, match="摘要"):
        snapshots.capture_submission_repository_snapshot(
            cursor,
            submission_id=92,
            user_id=12,
        )
    assert cursor.binding is None
    snapshot_dirs = [
        item
        for item in (isolated_repository_storage / "snapshots").iterdir()
        if not item.name.startswith(".")
    ]
    assert snapshot_dirs == []


def test_snapshot_uses_current_locking_reads_after_waiting_for_repository_lock(
    isolated_repository_storage,
):
    storage_key = "d" * 32
    live_tree = repository_storage.ensure_user_tree(storage_key)
    added = b"#define ADDED 1\n"
    (live_tree / "added.h").write_bytes(added)

    class ConcurrentAddCursor(_SnapshotCursor):
        def __init__(self):
            super().__init__(
                state={
                    "storage_key": storage_key,
                    "repository_generation": 8,
                    "entry_count": 1,
                    "total_size": len(added),
                },
                entries=[
                    {
                        "id": 8,
                        "parent_id": None,
                        "relative_path": "added.h",
                        "entry_type": "file",
                        "file_size": len(added),
                        "file_version": 1,
                        "content_sha256": hashlib.sha256(added).hexdigest(),
                    }
                ],
            )
            self.old_state = {
                "storage_key": storage_key,
                "repository_generation": 7,
                "entry_count": 0,
                "total_size": 0,
            }

        def execute(self, sql, params=()):
            normalized = " ".join(str(sql).split())
            self.executed.append((normalized, params))
            if "FROM repository_states" in normalized:
                self._one = (
                    dict(self.state)
                    if "FOR SHARE" in normalized
                    else dict(self.old_state)
                )
                self._many = []
                return
            if "FROM repository_entries" in normalized:
                self._one = None
                self._many = (
                    [dict(item) for item in self.entries]
                    if "FOR SHARE" in normalized
                    else []
                )
                return
            if "INSERT INTO submission_repository_snapshots" in normalized:
                keys = (
                    "submission_id",
                    "user_id",
                    "snapshot_key",
                    "relative_root",
                    "repository_generation",
                    "manifest_sha256",
                    "entry_count",
                    "total_size",
                )
                self.binding = dict(zip(keys, params))
                return
            raise AssertionError(f"unexpected SQL: {normalized}")

    cursor = ConcurrentAddCursor()
    result = snapshots.capture_submission_repository_snapshot(
        cursor,
        submission_id=95,
        user_id=12,
    )

    assert result["repository_generation"] == 8
    assert result["entry_count"] == 1
    restored = snapshots._read_snapshot_entries(cursor.binding)
    assert restored[0]["relative_path"] == "added.h"
    assert restored[0]["content"] == added.decode("utf-8")
    locking_reads = [
        sql for sql, _params in cursor.executed if "FOR SHARE" in sql
    ]
    assert any("FROM repository_states" in sql for sql in locking_reads)
    assert any("FROM repository_entries" in sql for sql in locking_reads)


def test_snapshot_manifest_cannot_be_rebound_to_another_submission(
    isolated_repository_storage,
):
    storage_key = "c" * 32
    live_tree = repository_storage.ensure_user_tree(storage_key)
    cursor = _SnapshotCursor(
        state={
            "storage_key": storage_key,
            "repository_generation": 1,
            "entry_count": 0,
            "total_size": 0,
        },
        entries=[],
    )
    snapshots.capture_submission_repository_snapshot(
        cursor,
        submission_id=93,
        user_id=12,
    )

    rebound = dict(cursor.binding)
    rebound["submission_id"] = 94
    with pytest.raises(snapshots.RepositorySnapshotError, match="所属提交"):
        snapshots._read_snapshot_entries(rebound)


def test_programming_result_uses_snapshot_owner_after_username_changes(monkeypatch):
    calls = []

    monkeypatch.setattr(
        evaluate_tasks,
        "resolve_submission_repository_user_id",
        lambda submission_id: 42 if submission_id == 93 else None,
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "get_user_by_id",
        lambda user_id: {"id": user_id, "is_admin": 1},
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "upsert_user_problem_max_score_if_higher",
        lambda user_id, problem_id, score: calls.append(
            ("score", user_id, problem_id, score)
        ),
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "update_submission_evaluation",
        lambda submission_id, _points, score, status: calls.append(
            ("result", submission_id, score, status)
        ),
    )

    evaluate_tasks._finalize_programming_submission(
        {"id": 93, "username": "已经改名的旧用户名"},
        7,
        [],
        60,
        "Wrong Answer",
    )

    assert ("score", 42, 7, 60) in calls
    assert ("result", 93, 60, "Wrong Answer") in calls


def test_snapshot_integrity_error_finishes_evaluation_instead_of_being_requeued(
    monkeypatch,
):
    submission = {
        "id": 96,
        "username": "student",
        "problem_id": 7,
        "problem_type": 1,
        "status": "Pending",
        "code": '#include "A/B.h"\n',
    }
    status_updates = []
    evaluation_updates = []
    snapshots_seen = []

    monkeypatch.setattr(
        evaluate_tasks,
        "get_submission_by_id",
        lambda _submission_id: dict(submission),
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "_acquire_submission_lock",
        lambda _submission_id: (None, None, None),
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "_release_submission_lock",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "update_submission_status",
        lambda submission_id, status: status_updates.append(
            (submission_id, status)
        ),
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "set_submission_status_snapshot",
        lambda **payload: snapshots_seen.append(payload),
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "update_submission_evaluation",
        lambda submission_id, points, score, status: evaluation_updates.append(
            (submission_id, points, score, status)
        ),
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "get_problem",
        lambda _problem_id: {"lang": "cpp", "test_code": ""},
    )
    monkeypatch.setattr(
        evaluate_tasks,
        "resolve_submission_repository_user_id",
        lambda _submission_id: (_ for _ in ()).throw(
            snapshots.RepositorySnapshotError("manifest hash mismatch")
        ),
    )
    monkeypatch.setattr(
        evaluate_tasks.core,
        "cleanup_run_artifacts_for_submission",
        lambda _submission_id: None,
    )

    task = evaluate_tasks.register_evaluate_submission_task(_FakeCelery())
    task(None, submission["id"])

    assert status_updates == [(submission["id"], "Running")]
    assert evaluation_updates
    assert evaluation_updates[-1][0] == submission["id"]
    assert evaluation_updates[-1][2:] == (0, "Error")
    assert evaluation_updates[-1][1][0]["status"] == "Error"
    assert snapshots_seen[-1]["status"] == "Error"
