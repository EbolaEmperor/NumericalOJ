#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from contextlib import contextmanager
import codecs
from datetime import datetime, timedelta
import hashlib
import os
from pathlib import Path
import stat

import pytest

from oj_modules.repository import storage
from oj_modules.repository import tree as tree_services


@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    root = tmp_path / "repository-storage"
    monkeypatch.setattr(storage, "STORAGE_ROOT", root)
    monkeypatch.setattr(storage, "_probe_case_sensitive", lambda _path: None)
    storage._ready_roots.clear()
    yield root
    storage._ready_roots.clear()


@pytest.mark.parametrize(
    "path",
    (
        "/absolute.h",
        "../escape.h",
        "a/../escape.h",
        "a//b.h",
        "a\\b.h",
        "a/trailing ",
        "a/trailing.",
        "AUX/file.h",
    ),
)
def test_repository_path_validation_rejects_ambiguous_or_unsafe_names(path):
    with pytest.raises(storage.RepositoryPathError):
        storage.validate_relative_path(path)


def test_repository_path_validation_preserves_case_unicode_dotfiles_and_leading_space():
    assert storage.validate_relative_path("Foo/foo/.配置/ leading.h") == (
        "Foo/foo/.配置/ leading.h"
    )


def test_repository_metadata_namespace_uses_binary_collation():
    bootstrap = (
        Path(__file__).resolve().parents[2] / "database" / "bootstrap.sql"
    ).read_text(encoding="utf-8")
    assert (
        "`name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL"
        in bootstrap
    )
    assert (
        "`relative_path` varchar(1024) CHARACTER SET utf8mb4 "
        "COLLATE utf8mb4_bin NOT NULL"
        in bootstrap
    )
    assert "`parent_scope` bigint unsigned NOT NULL" in bootstrap
    assert "GENERATED ALWAYS AS (ifnull(`parent_id`,0))" not in bootstrap
    assert (
        "CONSTRAINT `chk_repository_entries_parent_scope` "
        "CHECK (`parent_scope` = ifnull(`parent_id`,0))"
        in bootstrap
    )


def test_upload_session_target_is_not_cascade_bound_to_repository_entry():
    """删除暂存目标目录后，会话必须留下来供 finalize/过期清理显式处理。

    若 ``parent_id`` 使用 ``ON DELETE CASCADE`` 外键，目录删除会先删掉 DB 会话，
    但宿主机 staging 仍存在且从此无法被会话清理器发现。
    """
    bootstrap = (
        Path(__file__).resolve().parents[2] / "database" / "bootstrap.sql"
    ).read_text(encoding="utf-8")
    assert "fk_repository_upload_sessions_parent_owner" not in bootstrap


def test_persist_entries_writes_parent_scope_for_root_and_child():
    class Cursor:
        def __init__(self):
            self.executed = []
            self.lastrowid = 0

        def execute(self, sql, params=()):
            normalized = " ".join(str(sql).split())
            self.executed.append((normalized, tuple(params)))
            if normalized.startswith("INSERT INTO repository_entries"):
                self.lastrowid += 1

    cursor = Cursor()
    final_entries = [
        {
            "_key": "n:directory",
            "_parent_key": None,
            "name": "A",
            "relative_path": "A",
            "entry_type": "directory",
            "file_size": 0,
            "file_version": 0,
            "content_sha256": None,
        },
        {
            "_key": "n:file",
            "_parent_key": "n:directory",
            "name": "B.h",
            "relative_path": "A/B.h",
            "entry_type": "file",
            "file_size": 3,
            "file_version": 1,
            "content_sha256": "a" * 64,
        },
    ]

    tree_services._persist_entries(
        cursor,
        user_id=7,
        before_rows=[],
        final_entries=final_entries,
        operation_id="operation",
    )

    inserts = [
        (sql, params)
        for sql, params in cursor.executed
        if sql.startswith("INSERT INTO repository_entries")
    ]
    assert len(inserts) == 2
    assert "user_id, parent_id, parent_scope" in inserts[0][0]
    assert inserts[0][1][1:3] == (None, 0)
    assert inserts[1][1][1:3] == (1, 1)


def test_persist_entries_keeps_parent_scope_in_sync_while_moving_existing_entry():
    class Cursor:
        def __init__(self):
            self.executed = []
            self.lastrowid = 0

        def execute(self, sql, params=()):
            normalized = " ".join(str(sql).split())
            self.executed.append((normalized, tuple(params)))
            if normalized.startswith("INSERT INTO repository_entries"):
                self.lastrowid += 1

    cursor = Cursor()
    before_rows = [{
        "id": 5,
        "parent_id": None,
        "name": "B.h",
        "relative_path": "B.h",
        "entry_type": "file",
        "file_size": 3,
        "file_version": 1,
        "content_sha256": "a" * 64,
    }]
    final_entries = [
        {
            "_key": "n:directory",
            "_parent_key": None,
            "name": "A",
            "relative_path": "A",
            "entry_type": "directory",
            "file_size": 0,
            "file_version": 0,
            "content_sha256": None,
        },
        {
            "_key": "i:5",
            "_parent_key": "n:directory",
            "name": "B.h",
            "relative_path": "A/B.h",
            "entry_type": "file",
            "file_size": 3,
            "file_version": 1,
            "content_sha256": "a" * 64,
        },
    ]

    tree_services._persist_entries(
        cursor,
        user_id=7,
        before_rows=before_rows,
        final_entries=final_entries,
        operation_id="operation",
    )

    temporary_update = next(
        (sql, params)
        for sql, params in cursor.executed
        if sql.startswith("UPDATE repository_entries")
        and "parent_id = NULL" in sql
    )
    final_update = next(
        (sql, params)
        for sql, params in cursor.executed
        if sql.startswith("UPDATE repository_entries")
        and "parent_id = %s" in sql
    )
    assert "parent_scope = 0" in temporary_update[0]
    assert "parent_scope = %s" in final_update[0]
    assert final_update[1][:2] == (1, 1)


@pytest.mark.parametrize(
    ("raw", "encoding"),
    (
        (codecs.BOM_UTF8 + "甲\r\n乙".encode("utf-8"), "utf-8"),
        (codecs.BOM_UTF16_LE + "甲\r乙".encode("utf-16-le"), "utf-16-le"),
        (codecs.BOM_UTF16_BE + "甲\r乙".encode("utf-16-be"), "utf-16-be"),
        (codecs.BOM_UTF32_LE + "甲\r乙".encode("utf-32-le"), "utf-32-le"),
        (codecs.BOM_UTF32_BE + "甲\r乙".encode("utf-32-be"), "utf-32-be"),
    ),
)
def test_normalize_source_strips_bom_and_normalizes_lf(raw, encoding):
    normalized = storage.normalize_source_bytes(raw)
    assert normalized.text == "甲\n乙"
    assert normalized.data == "甲\n乙".encode("utf-8")
    assert normalized.source_encoding == encoding
    assert normalized.had_bom is True
    assert normalized.newline_normalized is True


def test_low_confidence_encoding_requires_strict_preview_and_exact_confirmation(
    monkeypatch,
):
    class Match:
        encoding = "cp1252"
        percent_coherence = 12.5

    class Matches:
        @staticmethod
        def best():
            return Match()

    monkeypatch.setattr(storage, "from_bytes", lambda _raw: Matches())
    raw = b"caf\xe9\r\nsuite"
    with pytest.raises(storage.RepositoryEncodingConfirmationRequired) as raised:
        storage.normalize_source_bytes(raw)
    error = raised.value
    assert error.candidate_encoding == "cp1252"
    assert error.preview == "café\nsuite"
    assert error.preview_truncated is False
    assert error.has_disallowed_control is False

    normalized = storage.normalize_source_bytes(
        raw,
        confirmed_encoding=error.candidate_encoding,
    )
    assert normalized.text == "café\nsuite"
    assert normalized.source_encoding == "cp1252"


@pytest.mark.parametrize("raw", (b"a\x00b", b"a\x01b"))
def test_normalize_source_rejects_binary_control_bytes(raw):
    with pytest.raises(storage.RepositoryPathError):
        storage.normalize_source_bytes(raw)


@pytest.mark.parametrize(
    "encoding",
    ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"),
)
def test_bomless_utf16_and_utf32_reach_strict_encoding_confirmation(encoding):
    raw = "int main() {}\r\n".encode(encoding)

    with pytest.raises(storage.RepositoryEncodingConfirmationRequired) as raised:
        storage.normalize_source_bytes(raw)

    assert raised.value.candidate_encoding.replace("-", "_") == encoding.replace("-", "_")
    normalized = storage.normalize_source_bytes(
        raw,
        confirmed_encoding=raised.value.candidate_encoding,
    )
    assert normalized.text == "int main() {}\n"
    assert normalized.data == b"int main() {}\n"


def test_clone_tree_never_chmods_shared_hardlink_inode(isolated_storage, tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    original = source / "mode.h"
    original.write_text("x", encoding="utf-8")
    original.chmod(0o640)

    storage.clone_tree(source, destination)

    assert stat_mode(original) == 0o640
    assert stat_mode(destination / "mode.h") == 0o640
    assert os.stat(original).st_ino == os.stat(destination / "mode.h").st_ino


def test_repository_directory_fsync_failure_is_not_silently_accepted(
    isolated_storage,
    monkeypatch,
):
    tree = storage.ensure_user_tree("f" * 32)
    original_fsync = storage.os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected directory fsync failure")
        return original_fsync(fd)

    monkeypatch.setattr(storage.os, "fsync", fail_directory_fsync)

    with pytest.raises(OSError, match="directory fsync failure"):
        storage.atomic_write_file_in_tree(tree, "durability.h", b"x\n")


def stat_mode(path):
    return os.stat(path).st_mode & 0o777


class _UploadCursor:
    def __init__(self):
        self.rowcount = 1

    def execute(self, _sql, _params=()):
        return None

    def fetchall(self):
        return []


class _UploadConnection:
    def __init__(self):
        self.cursor_value = _UploadCursor()
        self.committed = False

    @contextmanager
    def cursor(self):
        yield self.cursor_value

    def commit(self):
        self.committed = True

    def rollback(self):
        return None

    def close(self):
        return None


class _ScriptedCursor:
    def __init__(self, *, row=None, rows=None, execute_error=None):
        self.row = row
        self.rows = [] if rows is None else rows
        self.execute_error = execute_error
        self.executed = []
        self.rowcount = 1

    def execute(self, sql, params=()):
        self.executed.append((sql, params))
        if self.execute_error is not None:
            raise self.execute_error

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class _ScriptedConnection:
    def __init__(self, cursor, *, fail_commit_number=None):
        self.cursor_value = cursor
        self.fail_commit_number = fail_commit_number
        self.commit_count = 0
        self.rollback_count = 0
        self.closed = False

    @contextmanager
    def cursor(self):
        yield self.cursor_value

    def commit(self):
        self.commit_count += 1
        if self.commit_count == self.fail_commit_number:
            raise OSError("injected COMMIT ACK loss")

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.closed = True


def test_zero_byte_upload_session_creates_real_raw_staging_file(
    isolated_storage,
    monkeypatch,
):
    storage_key = "a" * 32
    connection = _UploadConnection()
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: {
            "storage_key": storage_key,
            "structure_version": 4,
            "entry_count": 0,
        },
    )
    monkeypatch.setattr(
        tree_services,
        "_load_state",
        lambda _cursor, _user_id, for_update=False: {
            "storage_key": storage_key,
            "structure_version": 4,
            "entry_count": 0,
        },
    )
    monkeypatch.setattr(tree_services, "_load_entries", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: connection)

    result = tree_services.create_repository_upload_session(
        7,
        parent_id=None,
        expected_structure_version=4,
        entries=[
            {
                "kind": "file",
                "relative_path": "empty.txt",
                "size": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            }
        ],
    )

    token = result["files"][0]["token"]
    assert storage.read_upload_file(result["session_id"], token) == b""
    assert connection.committed is True


def test_upload_session_commit_ack_loss_keeps_staging_when_fresh_read_finds_row(
    isolated_storage,
    monkeypatch,
):
    storage_key = "a" * 32
    repository_state = {
        "storage_key": storage_key,
        "structure_version": 4,
        "entry_count": 0,
    }
    main = _ScriptedConnection(
        _ScriptedCursor(rows=[]),
        fail_commit_number=1,
    )

    class AuthoritativeUploadCursor(_ScriptedCursor):
        def execute(self, sql, params=()):
            super().execute(sql, params)
            session_id = params[0]
            self.row = {
                "id": session_id,
                "user_id": 7,
                "parent_id": None,
                "base_structure_version": 4,
                "status": "receiving",
                "manifest_json": __import__("json").dumps(
                    {
                        "version": 1,
                        "files": [
                            {
                                "token": "f" * 32,
                                "relative_path": "authoritative.h",
                                "raw_size": 0,
                                "received_size": 0,
                                "raw_sha256": hashlib.sha256(b"").hexdigest(),
                                "status": "receiving",
                            }
                        ],
                        "directories": [],
                    }
                ),
                "entry_count": 1,
                "total_size": 0,
                "expires_at": datetime.now() + timedelta(hours=1),
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
            }

    verifier = _ScriptedConnection(AuthoritativeUploadCursor())
    connections = iter((main, verifier))
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: next(connections))
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: dict(repository_state),
    )
    monkeypatch.setattr(
        tree_services,
        "_load_state",
        lambda _cursor, _user_id, for_update=False: dict(repository_state),
    )
    monkeypatch.setattr(tree_services, "_load_entries", lambda *_args, **_kwargs: [])

    result = tree_services.create_repository_upload_session(
        7,
        parent_id=None,
        expected_structure_version=4,
        entries=[
            {
                "kind": "file",
                "relative_path": "local-name.h",
                "size": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            }
        ],
    )

    assert result["files"][0]["relative_path"] == "authoritative.h"
    assert storage.upload_staging_path(result["session_id"]).is_dir()
    assert "FOR SHARE" in verifier.cursor_value.executed[0][0]


def test_upload_session_commit_ack_loss_cleans_staging_only_when_row_is_absent(
    isolated_storage,
    monkeypatch,
):
    storage_key = "b" * 32
    repository_state = {
        "storage_key": storage_key,
        "structure_version": 4,
        "entry_count": 0,
    }
    main = _ScriptedConnection(_ScriptedCursor(rows=[]), fail_commit_number=1)
    verifier = _ScriptedConnection(_ScriptedCursor(row=None))
    connections = iter((main, verifier))
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: next(connections))
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: dict(repository_state),
    )
    monkeypatch.setattr(
        tree_services,
        "_load_state",
        lambda _cursor, _user_id, for_update=False: dict(repository_state),
    )
    monkeypatch.setattr(tree_services, "_load_entries", lambda *_args, **_kwargs: [])
    cleaned = []
    original_cleanup = storage.cleanup_upload_session

    def cleanup(session_id):
        cleaned.append(session_id)
        original_cleanup(session_id)

    monkeypatch.setattr(storage, "cleanup_upload_session", cleanup)

    with pytest.raises(OSError, match="COMMIT ACK loss"):
        tree_services.create_repository_upload_session(
            7,
            parent_id=None,
            expected_structure_version=4,
            entries=[
                {
                    "kind": "file",
                    "relative_path": "uncommitted.h",
                    "size": 0,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                }
            ],
        )

    assert len(cleaned) == 1
    assert not storage.upload_staging_path(cleaned[0]).exists()


def test_upload_session_commit_unknown_preserves_staging_and_fails_closed(
    isolated_storage,
    monkeypatch,
):
    storage_key = "c" * 32
    repository_state = {
        "storage_key": storage_key,
        "structure_version": 4,
        "entry_count": 0,
    }
    main = _ScriptedConnection(_ScriptedCursor(rows=[]), fail_commit_number=1)
    verifier = _ScriptedConnection(
        _ScriptedCursor(execute_error=OSError("verification unavailable"))
    )
    connections = iter((main, verifier))
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: next(connections))
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: dict(repository_state),
    )
    monkeypatch.setattr(
        tree_services,
        "_load_state",
        lambda _cursor, _user_id, for_update=False: dict(repository_state),
    )
    monkeypatch.setattr(tree_services, "_load_entries", lambda *_args, **_kwargs: [])

    with pytest.raises(tree_services.RepositoryDomainError) as raised:
        tree_services.create_repository_upload_session(
            7,
            parent_id=None,
            expected_structure_version=4,
            entries=[
                {
                    "kind": "file",
                    "relative_path": "unknown.h",
                    "size": 0,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                }
            ],
        )

    assert raised.value.code == "upload_session_commit_outcome_unknown"
    assert raised.value.status == 503
    assert storage.upload_staging_path(raised.value.details["session_id"]).is_dir()


def test_upload_session_requires_a_full_file_sha256_before_allocating_staging():
    with pytest.raises(tree_services.RepositoryDomainError) as raised:
        tree_services.create_repository_upload_session(
            7,
            parent_id=None,
            expected_structure_version=4,
            entries=[
                {
                    "kind": "file",
                    "relative_path": "missing-hash.txt",
                    "size": 3,
                }
            ],
        )

    assert raised.value.code == "hash_required"
    assert raised.value.status == 400


def test_upload_session_keeps_invalid_path_available_for_later_exclusion(
    isolated_storage,
    monkeypatch,
):
    storage_key = "b" * 32
    connection = _UploadConnection()
    repository_state = {
        "storage_key": storage_key,
        "structure_version": 4,
        "entry_count": storage.MAX_ENTRIES,
    }
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: dict(repository_state),
    )
    monkeypatch.setattr(
        tree_services,
        "_load_state",
        lambda _cursor, _user_id, for_update=False: dict(repository_state),
    )
    monkeypatch.setattr(tree_services, "_load_entries", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: connection)

    result = tree_services.create_repository_upload_session(
        7,
        parent_id=None,
        expected_structure_version=4,
        entries=[
            {
                "kind": "file",
                "relative_path": r"invalid\name.h",
                "size": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            }
        ],
    )

    assert result["files"][0]["relative_path"] == r"invalid\name.h"
    assert result["files"][0]["path_error"]
    # 仓库即使已有 10000 条，纯覆盖/合并仍必须等最终态精确判额，
    # 不能在创建上传会话时按清单长度保守拒绝。
    assert connection.committed is True


def test_upload_chunk_requires_sha256_before_touching_session_state():
    with pytest.raises(tree_services.RepositoryDomainError) as raised:
        tree_services.append_repository_upload_chunk(
            7,
            "b" * 32,
            "c" * 32,
            offset=0,
            total_size=3,
            data=b"abc",
        )

    assert raised.value.code == "hash_required"
    assert raised.value.status == 400


def test_upload_staging_accounting_counts_raw_and_normalized_copies():
    manifest = {
        "files": [
            {"raw_size": 12, "normalized_size": 7},
            {"raw_size": 5},
        ]
    }

    assert tree_services._upload_manifest_staging_bytes(manifest) == 24
    assert tree_services._upload_manifest_staging_bytes(
        __import__("json").dumps(manifest)
    ) == 24


def test_normalized_upload_copy_cannot_expand_staging_past_real_disk_cap(
    monkeypatch,
):
    cursor = _UploadCursor()
    cursor.fetchall = lambda: [{"id": "5" * 32}]
    monkeypatch.setattr(
        storage,
        "upload_session_disk_usage",
        lambda _session_id: tree_services.UPLOAD_MAX_STAGING_BYTES_PER_USER,
    )

    with pytest.raises(tree_services.RepositoryDomainError) as raised:
        tree_services._assert_upload_staging_capacity(
            cursor,
            7,
            additional_bytes=1,
        )

    assert raised.value.code == "upload_staging_quota_exceeded"
    assert raised.value.details["staging_bytes"] == (
        tree_services.UPLOAD_MAX_STAGING_BYTES_PER_USER
    )


def test_orphan_upload_staging_is_reaped_only_after_grace_period(
    isolated_storage,
):
    old_session = "1" * 32
    fresh_session = "2" * 32
    known_session = "3" * 32
    old_path = storage.prepare_upload_session(old_session)
    fresh_path = storage.prepare_upload_session(fresh_session)
    known_path = storage.prepare_upload_session(known_session)
    now = datetime.now()
    old_timestamp = (
        now
        - timedelta(seconds=tree_services.UPLOAD_ORPHAN_GRACE_SECONDS + 10)
    ).timestamp()
    os.utime(old_path, (old_timestamp, old_timestamp))
    os.utime(known_path, (old_timestamp, old_timestamp))

    assert tree_services._find_orphan_upload_staging(
        {known_session},
        now=now,
    ) == [old_session]
    assert fresh_path.is_dir()


def test_expired_upload_cleanup_also_removes_old_untracked_staging(
    isolated_storage,
    monkeypatch,
):
    connection = _UploadConnection()
    orphan = "4" * 32
    storage.prepare_upload_session(orphan)
    old_timestamp = (
        datetime.now()
        - timedelta(seconds=tree_services.UPLOAD_ORPHAN_GRACE_SECONDS + 10)
    ).timestamp()
    os.utime(storage.upload_staging_path(orphan), (old_timestamp, old_timestamp))
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: connection)

    report = tree_services.cleanup_expired_repository_upload_sessions(
        apply=True,
        now=datetime.now(),
    )

    assert report["orphan_candidates"] == [orphan]
    assert report["orphan_cleaned"] == [orphan]
    assert not storage.upload_staging_path(orphan).exists()


def test_upload_manifest_rejects_file_that_is_also_an_ancestor_path():
    digest = hashlib.sha256(b"x").hexdigest()

    with pytest.raises(tree_services.RepositoryDomainError) as raised:
        tree_services.create_repository_upload_session(
            7,
            parent_id=None,
            expected_structure_version=4,
            entries=[
                {
                    "kind": "file",
                    "relative_path": "blocked",
                    "size": 1,
                    "sha256": digest,
                },
                {
                    "kind": "file",
                    "relative_path": "blocked/child.h",
                    "size": 1,
                    "sha256": digest,
                },
            ],
        )

    assert raised.value.code == "manifest_type_conflict"
    assert raised.value.details["relative_path"] == "blocked/child.h"


def test_structural_mutation_requires_structure_cas_before_planning(
    isolated_storage,
    monkeypatch,
):
    storage_key = "d" * 32
    connection = _UploadConnection()
    repository_state = {
        "user_id": 7,
        "storage_key": storage_key,
        "structure_version": 4,
        "repository_generation": 9,
        "active_index_generation": None,
        "index_status": "stale",
        "entry_count": 0,
        "total_size": 0,
    }
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: dict(repository_state),
    )
    monkeypatch.setattr(
        tree_services,
        "_load_state",
        lambda _cursor, _user_id, for_update=False: dict(repository_state),
    )
    monkeypatch.setattr(tree_services, "_load_entries", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(tree_services, "_recover_locked", lambda *_args: None)
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: connection)
    planned = []

    with pytest.raises(tree_services.RepositoryDomainError) as raised:
        tree_services._run_mutation(
            7,
            operation_type="missing_cas",
            planner=lambda entries, state: planned.append((entries, state)),
        )

    assert raised.value.code == "version_required"
    assert raised.value.status == 428
    assert planned == []


def test_save_response_uses_its_transaction_snapshot_not_a_later_reread(
    monkeypatch,
):
    transaction_entry = {
        "id": 5,
        "parent_id": None,
        "name": "answer.cpp",
        "path": "answer.cpp",
        "relative_path": "answer.cpp",
        "kind": "file",
        "file_size": 3,
        "file_version": 2,
        "sha256": hashlib.sha256(b"v2\n").hexdigest(),
        "indexable": True,
        "created_at": None,
        "updated_at": None,
    }
    monkeypatch.setattr(
        tree_services,
        "_run_mutation",
        lambda *_args, **_kwargs: {
            "saved_key": "i:5",
            "created": False,
            "changed": True,
            "structure_version": 4,
            "repository_generation": 10,
            "_resolved_ids": {"i:5": 5},
            "_resolved_entries": {"i:5": transaction_entry},
        },
    )
    monkeypatch.setattr(
        tree_services,
        "read_repository_file",
        lambda *_args, **_kwargs: pytest.fail(
            "释放仓库锁后不得为保存响应重新读取更晚版本"
        ),
    )

    result = tree_services.save_repository_file(
        7,
        entry_id=5,
        content="v2\n",
        expected_file_version=1,
    )

    assert result["entry"] == transaction_entry
    assert result["entry"]["file_version"] == 2


def _commit_uncertainty_mutation_plan(_entries, _state):
    return {
        "entries": [
            {
                "_key": "n:directory",
                "_parent_key": None,
                "_old_path": None,
                "name": "include",
                "relative_path": "include",
                "entry_type": "directory",
                "file_size": 0,
                "file_version": 0,
                "content_sha256": None,
            }
        ],
        "content_overrides": {},
        "structure_changed": True,
    }


def _patch_commit_uncertainty_mutation(
    monkeypatch,
    *,
    storage_key,
    connections,
):
    repository_state = {
        "user_id": 7,
        "storage_key": storage_key,
        "structure_version": 4,
        "repository_generation": 9,
        "active_index_generation": None,
        "index_status": "stale",
        "entry_count": 0,
        "total_size": 0,
    }
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: dict(repository_state),
    )
    monkeypatch.setattr(
        tree_services,
        "_load_state",
        lambda _cursor, _user_id, for_update=False: dict(repository_state),
    )
    monkeypatch.setattr(tree_services, "_load_entries", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(tree_services, "_recover_locked", lambda *_args: None)
    monkeypatch.setattr(tree_services, "_prepare_shadow_tree", lambda *_args: None)
    monkeypatch.setattr(
        tree_services,
        "_persist_entries",
        lambda *_args, **_kwargs: {"n:directory": 101},
    )
    connection_iter = iter(connections)
    monkeypatch.setattr(
        tree_services,
        "get_db_connection",
        lambda: next(connection_iter),
    )


def test_mutation_commit_ack_loss_confirmed_committed_keeps_published_tree(
    isolated_storage,
    monkeypatch,
):
    storage_key = "d" * 32
    # prepared journal 单独提交一次；publish 后不再提交 fs_applied，第二次
    # COMMIT 就是 metadata+journal committed 的最终原子事务。
    main = _ScriptedConnection(_ScriptedCursor(), fail_commit_number=2)
    verifier = _ScriptedConnection(
        _ScriptedCursor(
            row={
                "user_id": 7,
                "journal_status": "committed",
                "structure_version_before": 4,
                "structure_version_after": 5,
                "state_structure_version": 5,
                "state_repository_generation": 10,
            }
        )
    )
    _patch_commit_uncertainty_mutation(
        monkeypatch,
        storage_key=storage_key,
        connections=(main, verifier),
    )
    rollback_calls = []
    finalize_calls = []
    monkeypatch.setattr(storage, "publish_operation_tree", lambda *_args: None)
    monkeypatch.setattr(
        storage,
        "rollback_operation_tree",
        lambda *_args: rollback_calls.append(_args),
    )
    monkeypatch.setattr(
        tree_services,
        "_finalize_committed_operation",
        lambda operation_id: finalize_calls.append(operation_id),
    )

    result = tree_services._run_mutation(
        7,
        operation_type="commit_ack_loss",
        expected_structure_version=4,
        planner=_commit_uncertainty_mutation_plan,
    )

    assert result["structure_version"] == 5
    assert result["repository_generation"] == 10
    assert rollback_calls == []
    assert len(finalize_calls) == 1
    assert main.commit_count == 2
    assert "FOR SHARE" in verifier.cursor_value.executed[0][0]


@pytest.mark.parametrize("journal_status", ("prepared", "fs_applied"))
def test_mutation_commit_ack_loss_confirmed_uncommitted_rolls_back_tree(
    isolated_storage,
    monkeypatch,
    journal_status,
):
    storage_key = "e" * 32
    main = _ScriptedConnection(_ScriptedCursor(), fail_commit_number=2)
    verifier = _ScriptedConnection(
        _ScriptedCursor(
            row={
                "user_id": 7,
                "journal_status": journal_status,
                "structure_version_before": 4,
                "structure_version_after": None,
                "state_structure_version": 4,
                "state_repository_generation": 9,
            }
        )
    )
    _patch_commit_uncertainty_mutation(
        monkeypatch,
        storage_key=storage_key,
        connections=(main, verifier),
    )
    rollback_calls = []
    marked = []
    monkeypatch.setattr(storage, "publish_operation_tree", lambda *_args: None)
    monkeypatch.setattr(
        storage,
        "rollback_operation_tree",
        lambda *_args: rollback_calls.append(_args),
    )
    monkeypatch.setattr(
        tree_services,
        "_mark_mutation_rolled_back",
        lambda operation_id: marked.append(operation_id),
    )

    with pytest.raises(OSError, match="COMMIT ACK loss"):
        tree_services._run_mutation(
            7,
            operation_type="commit_ack_loss",
            expected_structure_version=4,
            planner=_commit_uncertainty_mutation_plan,
        )

    assert len(rollback_calls) == 1
    assert len(marked) == 1


def test_mutation_commit_unknown_preserves_journal_tree_and_fails_closed(
    isolated_storage,
    monkeypatch,
):
    storage_key = "f" * 32
    main = _ScriptedConnection(_ScriptedCursor(), fail_commit_number=2)
    verifier = _ScriptedConnection(_ScriptedCursor(row=None))
    _patch_commit_uncertainty_mutation(
        monkeypatch,
        storage_key=storage_key,
        connections=(main, verifier),
    )
    rollback_calls = []
    cleanup_calls = []

    def publish(_storage_key, operation_id):
        operation_dir = storage.operation_journal_path(operation_id)
        operation_dir.mkdir(mode=0o700)
        (operation_dir / "old-tree").mkdir(mode=0o700)

    monkeypatch.setattr(storage, "publish_operation_tree", publish)
    monkeypatch.setattr(
        storage,
        "rollback_operation_tree",
        lambda *_args: rollback_calls.append(_args),
    )
    monkeypatch.setattr(
        storage,
        "cleanup_operation_tree",
        lambda operation_id: cleanup_calls.append(operation_id),
    )

    with pytest.raises(tree_services.RepositoryDomainError) as raised:
        tree_services._run_mutation(
            7,
            operation_type="commit_unknown",
            expected_structure_version=4,
            planner=_commit_uncertainty_mutation_plan,
        )

    assert raised.value.code == "mutation_commit_outcome_unknown"
    assert raised.value.status == 503
    assert rollback_calls == []
    assert cleanup_calls == []
    old_trees = list((isolated_storage / "journal").glob("*/old-tree"))
    assert len(old_trees) == 1
    assert old_trees[0].is_dir()


def test_publish_double_failure_preserves_the_only_recovery_tree(
    isolated_storage,
    monkeypatch,
):
    storage_key = "a" * 32
    connection = _UploadConnection()
    repository_state = {
        "user_id": 7,
        "storage_key": storage_key,
        "structure_version": 4,
        "repository_generation": 9,
        "active_index_generation": None,
        "index_status": "stale",
        "entry_count": 0,
        "total_size": 0,
    }
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: dict(repository_state),
    )
    monkeypatch.setattr(
        tree_services,
        "_load_state",
        lambda _cursor, _user_id, for_update=False: dict(repository_state),
    )
    monkeypatch.setattr(tree_services, "_load_entries", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(tree_services, "_recover_locked", lambda *_args: None)
    monkeypatch.setattr(tree_services, "_prepare_shadow_tree", lambda *_args: None)
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: connection)
    cleanup_calls = []

    def fail_publish(_storage_key, operation_id):
        operation_dir = storage.operation_journal_path(operation_id)
        operation_dir.mkdir(mode=0o700)
        (operation_dir / "old-tree").mkdir(mode=0o700)
        raise OSError("新树发布与旧树补偿均失败")

    monkeypatch.setattr(storage, "publish_operation_tree", fail_publish)
    monkeypatch.setattr(
        storage,
        "cleanup_operation_tree",
        lambda operation_id: cleanup_calls.append(operation_id),
    )

    def planner(_entries, _state):
        return {
            "entries": [
                {
                    "_key": "n:directory",
                    "_parent_key": None,
                    "_old_path": None,
                    "name": "include",
                    "relative_path": "include",
                    "entry_type": "directory",
                    "file_size": 0,
                    "file_version": 0,
                    "content_sha256": None,
                }
            ],
            "content_overrides": {},
            "structure_changed": True,
        }

    with pytest.raises(OSError, match="补偿均失败"):
        tree_services._run_mutation(
            7,
            operation_type="fault_injection",
            expected_structure_version=4,
            planner=planner,
        )

    old_trees = list((isolated_storage / "journal").glob("*/old-tree"))
    assert len(old_trees) == 1
    assert old_trees[0].is_dir()
    assert cleanup_calls == []


def test_upload_preview_status_prioritizes_incomplete_then_encoding_confirmation():
    assert tree_services._upload_preview_session_status(
        {"files": [{"status": "incomplete"}, {"status": "encoding_confirmation_required"}]},
        pending_confirmation=True,
    ) == "receiving"
    assert tree_services._upload_preview_session_status(
        {"files": [{"status": "encoding_confirmation_required"}]}
    ) == "needs_confirmation"
    assert tree_services._upload_preview_session_status(
        {"files": [{"status": "invalid"}, {"status": "conflict"}]}
    ) == "preview_ready"


def test_upload_encoding_confirmation_only_accepts_prechecked_candidate():
    item = {
        "relative_path": "legacy.txt",
        "status": "encoding_confirmation_required",
        "candidate_encoding": "cp1252",
    }
    assert tree_services._validated_upload_encoding_confirmation(
        item,
        "windows-1252",
        token="d" * 32,
    ) == "cp1252"
    with pytest.raises(tree_services.RepositoryDomainError) as raised:
        tree_services._validated_upload_encoding_confirmation(
            item,
            "gb18030",
            token="d" * 32,
        )
    assert raised.value.code == "encoding_confirmation_mismatch"
    assert raised.value.details["relative_path"] == "legacy.txt"


def test_upload_excluding_directory_also_excludes_descendant_directories(
    monkeypatch,
):
    session = {
        "id": "8" * 32,
        "user_id": 7,
        "parent_id": None,
        "base_structure_version": 4,
        "status": "preview_ready",
        "entry_count": 2,
        "total_size": 0,
        "expires_at": datetime.now() + timedelta(hours=1),
        "manifest": {
            "files": [],
            "directories": [
                {"relative_path": "blocked", "status": "blocking_conflict"},
                {"relative_path": "blocked/child", "status": "new"},
            ],
        },
    }
    connection = _UploadConnection()
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: {"structure_version": 4},
    )
    monkeypatch.setattr(
        tree_services,
        "_load_upload_session",
        lambda *_args, **_kwargs: session,
    )
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(storage, "cleanup_upload_session", lambda _session_id: None)
    captured = {}

    def run_mutation(
        user_id,
        *,
        operation_type,
        expected_structure_version,
        planner,
        db_finalize,
    ):
        plan = planner([], {"structure_version": 4})
        captured["plan"] = plan
        return {
            **plan["result"],
            "_resolved_ids": {},
            "_resolved_entries": {},
            "structure_version": 4,
            "repository_generation": 8,
        }

    monkeypatch.setattr(tree_services, "_run_mutation", run_mutation)

    result = tree_services.commit_repository_upload_session(
        7,
        session["id"],
        expected_structure_version=4,
        resolutions={"blocked": "exclude"},
    )

    assert captured["plan"]["entries"] == []
    assert result["skipped"] == ["blocked", "blocked/child"]


def test_explicit_upload_overwrite_increments_version_even_when_bytes_match(
    monkeypatch,
    tmp_path,
):
    digest = hashlib.sha256(b"same\n").hexdigest()
    session = {
        "id": "b" * 32,
        "user_id": 7,
        "parent_id": None,
        "base_structure_version": 4,
        "status": "preview_ready",
        "entry_count": 1,
        "total_size": 5,
        "expires_at": datetime.now() + timedelta(hours=1),
        "manifest": {
            "files": [
                {
                    "token": "c" * 32,
                    "relative_path": "same.h",
                    "status": "conflict",
                    "normalized_size": 5,
                    "normalized_sha256": digest,
                    "existing_entry_id": 5,
                    "existing_file_version": 3,
                    "existing_sha256": digest,
                }
            ],
            "directories": [],
        },
    }
    connection = _UploadConnection()
    monkeypatch.setattr(
        tree_services,
        "_get_or_create_state",
        lambda _user_id: {"structure_version": 4},
    )
    monkeypatch.setattr(
        tree_services,
        "_load_upload_session",
        lambda *_args, **_kwargs: session,
    )
    monkeypatch.setattr(tree_services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        storage,
        "upload_staging_path",
        lambda _session_id: tmp_path / "staging",
    )
    monkeypatch.setattr(storage, "cleanup_upload_session", lambda _session_id: None)
    captured = {}

    def run_mutation(
        user_id,
        *,
        operation_type,
        expected_structure_version,
        planner,
        db_finalize,
    ):
        entries = [
            {
                "_key": "e:5",
                "_parent_key": None,
                "_old_path": "same.h",
                "id": 5,
                "parent_id": None,
                "name": "same.h",
                "relative_path": "same.h",
                "entry_type": "file",
                "file_size": 5,
                "file_version": 3,
                "content_sha256": digest,
            }
        ]
        captured["plan"] = planner(entries, {"structure_version": 4})
        return {
            "_resolved_ids": {"e:5": 5},
            "structure_version": 4,
            "repository_generation": 8,
            "committed_count": 1,
        }

    monkeypatch.setattr(tree_services, "_run_mutation", run_mutation)

    result = tree_services.commit_repository_upload_session(
        7,
        "b" * 32,
        expected_structure_version=4,
        resolutions={"same.h": "overwrite"},
    )

    plan = captured["plan"]
    assert plan["entries"][0]["id"] == 5
    assert plan["entries"][0]["file_version"] == 4
    assert "e:5" in plan["content_overrides"]
    assert plan["structure_changed"] is False
    assert plan["no_change"] is False
    assert result["committed"][0]["entry_id"] == 5
