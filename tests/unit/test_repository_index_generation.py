#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from oj_modules.llm_endpoints import LLMEndpointSnapshot
from oj_modules.repository import index as index_services


def _endpoint(category, endpoint_id):
    return LLMEndpointSnapshot(
        id=endpoint_id,
        name=f"test-{category}",
        category=category,
        protocol="openai",
        base_url="https://llm.example.test/v1",
        api_key="test-key",
        model=f"{category}-model",
        thinking_enabled=False,
        thinking_format="none",
    )


class _StaleJobCursor:
    def __init__(self):
        self.rowcount = 0
        self.job = {
            "id": 81,
            "user_id": 4,
            "base_repository_generation": 12,
            "status": "running",
            "total_files": 2,
            "processed_files": 1,
            "total_chunks": 3,
            "total_classes": 1,
            "error_message": None,
            "progress_message": "working",
            "task_id": "task-81",
            "cancel_requested": 0,
            "created_at": None,
            "updated_at": None,
            "finished_at": None,
        }
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        self.executed.append((normalized, params))
        if normalized.startswith("UPDATE repository_index_jobs"):
            self.job["status"] = "failed"
            self.job["error_message"] = params[0]
            self.job["progress_message"] = params[1]
            self.job["finished_at"] = None
            self.rowcount = 1
            return
        if normalized.startswith("SELECT id, user_id"):
            self.rowcount = 0
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        return dict(self.job)


class _StaleJobConnection:
    def __init__(self):
        self.cursor_object = _StaleJobCursor()
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_object

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


class _RedeliveredJobCursor:
    def __init__(self):
        self.rowcount = 0
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        self.executed.append((" ".join(str(sql).split()), params))
        # 模拟 PyMySQL 默认的 changed-rows 语义：running -> running 命中，
        # 但 UPDATE 没有可见字段变化时 rowcount 仍可能是 0。
        self.rowcount = 0

    def fetchone(self):
        return {"status": "running", "cancel_requested": 0}


class _RedeliveredJobConnection:
    def __init__(self):
        self.cursor_object = _RedeliveredJobCursor()
        self.committed = False

    def cursor(self):
        return self.cursor_object

    def commit(self):
        self.committed = True

    def close(self):
        pass


class _TerminalPublishCursor:
    def __init__(self):
        self.executed = []
        self.rowcount = 0
        self._next_row = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        self.executed.append((normalized, params))
        if normalized.startswith("SELECT repository_generation"):
            self._next_row = {"repository_generation": 12}
            return
        if normalized.startswith(
            "SELECT status, cancel_requested, base_repository_generation"
        ):
            self._next_row = {
                "status": "failed",
                "cancel_requested": 0,
                "base_repository_generation": 12,
            }
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        row = self._next_row
        self._next_row = None
        return row


class _TerminalPublishConnection:
    def __init__(self):
        self.cursor_object = _TerminalPublishCursor()
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_object

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


class _CancelJobCursor:
    def __init__(self, status):
        self.job = {
            "id": 91,
            "user_id": 4,
            "status": status,
            "task_id": "task-91",
            "cancel_requested": 0,
        }
        self.executed = []
        self.rowcount = 0
        self._next_row = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        self.executed.append((normalized, params))
        if normalized.startswith("SELECT id, user_id"):
            self._next_row = dict(self.job)
            self.rowcount = 0
            return
        if normalized.startswith("UPDATE repository_index_jobs"):
            self.job["cancel_requested"] = 1
            if "status = 'canceled'" in normalized:
                self.job["status"] = "canceled"
            self.rowcount = 1
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        row = self._next_row
        self._next_row = None
        return row


class _CancelJobConnection:
    def __init__(self, status):
        self.cursor_object = _CancelJobCursor(status)
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_object

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


class _CancelingReservationCursor:
    def __init__(self):
        self.executed = []
        self.rowcount = 0
        self._next_row = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        self.executed.append((normalized, params))
        if normalized.startswith("SELECT id FROM users"):
            self._next_row = {"id": 4}
            return
        if normalized.startswith("UPDATE repository_index_jobs"):
            self.rowcount = 0
            return
        if normalized.startswith(
            "SELECT id, user_id, base_repository_generation"
        ):
            self._next_row = {
                "id": 91,
                "user_id": 4,
                "base_repository_generation": 12,
                "status": "running",
                "task_id": "task-91",
                "cancel_requested": 1,
            }
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        row = self._next_row
        self._next_row = None
        return row


class _CancelingReservationConnection:
    def __init__(self):
        self.cursor_object = _CancelingReservationCursor()
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_object

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


def test_embedding_cache_key_is_path_independent():
    text = "math::sum\nint sum(int a, int b)\nreturn a + b;"
    embedding_endpoint = _endpoint("embedding", 2)
    structured_endpoint = _endpoint("text", 1)
    first = index_services._embedding_input_hash(
        text,
        embedding_endpoint,
        structured_endpoint,
    )
    moved = index_services._embedding_input_hash(
        text,
        embedding_endpoint,
        structured_endpoint,
    )
    assert first == moved


def test_repository_embedding_uses_snapshot_and_generic_adapter(monkeypatch):
    embedding_endpoint = _endpoint("embedding", 2)
    calls = []

    def fake_create_embeddings(endpoint, texts, **kwargs):
        calls.append((endpoint, list(texts), kwargs))
        return SimpleNamespace(vectors=((3.0, 4.0), (0.0, 2.0)))

    monkeypatch.setattr(
        index_services,
        "create_embeddings",
        fake_create_embeddings,
    )

    vectors, model = index_services.encode_texts_with_repository_embedding(
        ["first", "second"],
        endpoint=embedding_endpoint,
    )

    assert model == "embedding-model"
    assert vectors[0].tolist() == pytest.approx([0.6, 0.8])
    assert vectors[1].tolist() == pytest.approx([0.0, 1.0])
    assert calls[0][0] is embedding_endpoint
    assert calls[0][1] == ["first", "second"]


def test_structuring_prompts_never_receive_repository_path(monkeypatch):
    prompts = []

    def fake_call_llm_text(prompt_text, _endpoint, **_kwargs):
        prompts.append(prompt_text)
        if "[函数代码]" in prompt_text:
            return '{"summary":"求和","params":[],"returns":{"description":"结果"}}'
        return (
            '{"class_name":"Vector","qualified_name":"math::Vector",'
            '"kind":"class","bases":[],"member_variables":[],"member_methods":[]}'
        )

    monkeypatch.setattr(index_services, "_call_llm_text", fake_call_llm_text)
    sensitive_path = "private/course/A/B/vector.hpp"
    endpoint = _endpoint("text", 1)
    index_services._call_structured_function_entity(
        {
            "filename": sensitive_path,
            "qualified_name": "math::sum",
            "code": "int sum(int a, int b) { return a + b; }",
        },
        endpoint,
    )
    index_services._call_structured_class_entity(
        {
            "filename": sensitive_path,
            "class_name": "Vector",
            "qualified_name": "math::Vector",
            "kind": "class",
        },
        endpoint,
    )

    assert len(prompts) == 2
    assert all("[文件名]" not in prompt for prompt in prompts)
    assert all(sensitive_path not in prompt for prompt in prompts)


def test_running_cancel_is_row_locked_and_remains_active_until_worker_ack(
    monkeypatch,
):
    connection = _CancelJobConnection("running")
    monkeypatch.setattr(index_services, "get_db_connection", lambda: connection)

    job = index_services.request_cancel_repository_index_job(
        91,
        user_id=4,
        reason="用户取消结构化整理任务。",
    )

    select_sql = connection.cursor_object.executed[0][0]
    update_sql = connection.cursor_object.executed[1][0]
    assert select_sql.endswith("FOR UPDATE")
    assert "status = 'canceled'" not in update_sql
    assert "WHERE id = %s AND status = 'running'" in update_sql
    assert job["status"] == "running"
    assert job["cancel_requested"] == 1
    assert "[stage:canceling]" in job["progress_message"]
    assert connection.committed is True
    assert connection.rolled_back is False


def test_cancel_after_publish_observes_success_under_the_same_row_lock(
    monkeypatch,
):
    connection = _CancelJobConnection("success")
    monkeypatch.setattr(index_services, "get_db_connection", lambda: connection)

    job = index_services.request_cancel_repository_index_job(
        91,
        user_id=4,
        reason="用户取消结构化整理任务。",
    )

    assert job["status"] == "success"
    assert job["cancel_requested"] == 0
    assert len(connection.cursor_object.executed) == 1
    assert connection.cursor_object.executed[0][0].endswith("FOR UPDATE")
    assert connection.committed is True


def test_new_build_attaches_to_running_job_with_cancel_requested(monkeypatch):
    connection = _CancelingReservationConnection()
    monkeypatch.setattr(index_services, "get_db_connection", lambda: connection)

    reservation = index_services.get_or_create_active_repository_index_job(4)

    active_query = connection.cursor_object.executed[2][0]
    assert "status IN ('queued', 'running')" in active_query
    assert "cancel_requested = 0" not in active_query
    assert reservation["created"] is False
    assert reservation["job_id"] == 91
    assert reservation["job"]["cancel_requested"] == 1
    assert connection.committed is True
    assert connection.rolled_back is False


def test_repository_build_lock_is_shared_by_all_jobs_of_one_user(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        index_services,
        "_FAISS_INDEX_ROOT",
        str(tmp_path / "faiss"),
    )

    with index_services._repository_index_build_lock(4, 101):
        pass
    with index_services._repository_index_build_lock(4, 202):
        pass

    lock_root = tmp_path / "faiss" / "4" / ".build-locks"
    assert sorted(path.name for path in lock_root.iterdir()) == ["user.lock"]


def test_structured_cache_clone_rewrites_only_generation_identity_and_path():
    cached = {
        "classes": [
            {
                "class_id": "old-class",
                "filename": "old/path.h",
                "repo_file_id": 1,
                "source_hash": "a" * 64,
                "qualified_name": "math::Vector",
                "_index_cache": {"file_cache_key": "old"},
            },
        ],
        "functions": [
            {
                "chunk_id": "old-chunk",
                "filename": "old/path.h",
                "repo_file_id": 1,
                "source_hash": "a" * 64,
                "language": "c",
                "qualified_name": "math::sum",
                "code": "return a + b;",
                "_index_cache": {"file_cache_key": "old"},
            },
        ],
    }
    cloned = index_services._clone_cached_structured_file(
        cached,
        {
            "id": 9,
            "filename": " new/path.h",
            "source_hash": "a" * 64,
        },
    )

    assert cloned["classes"][0]["filename"] == " new/path.h"
    assert cloned["functions"][0]["filename"] == " new/path.h"
    assert cloned["functions"][0]["repo_file_id"] == 9
    assert cloned["functions"][0]["language"] == "cpp"
    assert cloned["functions"][0]["qualified_name"] == "math::sum"
    assert cloned["functions"][0]["code"] == "return a + b;"
    assert cloned["classes"][0]["class_id"] != "old-class"
    assert cloned["functions"][0]["chunk_id"] != "old-chunk"
    assert "_index_cache" not in cloned["functions"][0]


def test_running_job_redelivery_is_claimed_even_when_update_rowcount_is_zero(
    monkeypatch,
):
    connection = _RedeliveredJobConnection()
    monkeypatch.setattr(index_services, "get_db_connection", lambda: connection)

    assert index_services._try_mark_repository_index_job_running(51) is True
    assert connection.committed is True
    assert len(connection.cursor_object.executed) == 2
    assert connection.cursor_object.executed[1][0].startswith(
        "SELECT status, cancel_requested"
    )


def test_terminal_index_lease_rejects_late_worker_publish(monkeypatch):
    from oj_modules.repository import tree as repository_tree

    @contextmanager
    def no_op_repository_lock(_user_id, *, exclusive):
        assert exclusive is False
        yield

    connection = _TerminalPublishConnection()
    inserted = []
    monkeypatch.setattr(
        repository_tree,
        "repository_user_lock",
        no_op_repository_lock,
    )
    monkeypatch.setattr(index_services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        index_services,
        "_insert_index_generation_rows",
        lambda *_args, **_kwargs: inserted.append(True),
    )

    with pytest.raises(RuntimeError, match="迟到 worker"):
        index_services._publish_repository_index_generation(
            user_id=4,
            job_id=81,
            base_repository_generation=12,
            classes=[],
            functions=[],
            embedding_map={},
            embedding_hashes={},
            embedding_model="test-embedding",
            structured_model="test-structured",
        )

    assert inserted == []
    assert connection.committed is False
    assert connection.rolled_back is True
    assert all(
        "SET active_index_generation" not in sql
        for sql, _params in connection.cursor_object.executed
    )


def test_empty_faiss_generation_is_directory_fsynced_before_publish(
    tmp_path,
    monkeypatch,
):
    sync_calls = []
    monkeypatch.setattr(index_services, "_FAISS_INDEX_ROOT", str(tmp_path / "faiss"))
    monkeypatch.setattr(index_services, "_ensure_faiss_available", lambda: None)
    monkeypatch.setattr(
        index_services,
        "_fsync_faiss_generation_directories",
        lambda user_id, index_generation=None: sync_calls.append(
            (user_id, index_generation)
        ),
    )

    index_services._write_faiss_index(
        4,
        [],
        [],
        "test-embedding",
        index_generation=82,
    )

    meta_path = Path(
        index_services._faiss_paths(4, index_generation=82)["meta"]
    )
    assert meta_path.is_file()
    assert sync_calls == [(4, 82)]


def test_failed_candidate_never_reaches_publish(monkeypatch):
    updates = []
    published = []
    staged = []
    monkeypatch.setattr(index_services, "_try_mark_repository_index_job_running", lambda _job: True)
    monkeypatch.setattr(index_services, "_is_repository_index_job_cancel_requested", lambda _job: False)
    endpoints = {
        "repository_structuring": _endpoint("text", 1),
        "repository_embedding": _endpoint("embedding", 2),
    }
    monkeypatch.setattr(
        index_services,
        "resolve_llm_endpoint_snapshot",
        lambda *, feature_key, **_kwargs: endpoints[feature_key],
    )
    monkeypatch.setattr(
        index_services,
        "_load_repository_index_snapshot",
        lambda _user: (
            8,
            [{
                "id": 1,
                "filename": "broken.h",
                "content": "int broken(",
                "source_hash": index_services._sha256_text("int broken("),
            }],
        ),
    )
    monkeypatch.setattr(
        index_services,
        "_load_active_repository_index_cache",
        lambda _user, _endpoint: ({}, {}),
    )

    def fail_structuring(**_kwargs):
        raise RuntimeError("simulated parser failure")

    monkeypatch.setattr(
        index_services,
        "_build_structured_with_treesitter_and_llm",
        fail_structuring,
    )
    monkeypatch.setattr(
        index_services,
        "_stage_faiss_generation",
        lambda *_args, **_kwargs: staged.append(True),
    )
    monkeypatch.setattr(
        index_services,
        "_publish_repository_index_generation",
        lambda **_kwargs: published.append(True),
    )
    monkeypatch.setattr(
        index_services,
        "update_repository_index_job",
        lambda job_id, **fields: updates.append((job_id, fields)),
    )

    result = index_services._run_repository_index_job_once(4, 51)

    assert result["success"] is False
    assert "simulated parser failure" in result["error"]
    assert staged == []
    assert published == []
    assert updates[-1][1]["status"] == "failed"


def test_retry_returns_success_when_generation_is_already_active(monkeypatch):
    @contextmanager
    def no_op_lock(_user_id, _job_id):
        yield

    monkeypatch.setattr(index_services, "_repository_index_build_lock", no_op_lock)
    monkeypatch.setattr(index_services, "_get_active_repository_index_generation", lambda _user: 63)
    monkeypatch.setattr(
        index_services,
        "get_repository_index_job",
        lambda **_kwargs: {
            "base_repository_generation": 12,
            "total_files": 3,
            "total_chunks": 7,
            "total_classes": 2,
        },
    )
    monkeypatch.setattr(
        index_services,
        "_discard_unpublished_repository_index_generation",
        lambda *_args: pytest.fail("active generation must not be discarded"),
    )
    monkeypatch.setattr(
        index_services,
        "_run_repository_index_job_once",
        lambda *_args, **_kwargs: pytest.fail("active generation must not rebuild"),
    )

    result = index_services.run_repository_index_job(4, 63)

    assert result == {
        "success": True,
        "job_id": 63,
        "repository_generation": 12,
        "index_generation": 63,
        "files": 3,
        "chunks": 7,
        "classes": 2,
        "idempotent": True,
    }


def test_retry_discards_only_its_unpublished_generation(monkeypatch):
    calls = []

    @contextmanager
    def no_op_lock(_user_id, _job_id):
        yield

    monkeypatch.setattr(index_services, "_repository_index_build_lock", no_op_lock)
    monkeypatch.setattr(index_services, "_get_active_repository_index_generation", lambda _user: 60)
    monkeypatch.setattr(
        index_services,
        "_discard_unpublished_repository_index_generation",
        lambda user_id, generation: calls.append(("discard", user_id, generation)),
    )
    monkeypatch.setattr(
        index_services,
        "_run_repository_index_job_once",
        lambda **kwargs: calls.append(("run", kwargs)) or {"success": True},
    )

    result = index_services.run_repository_index_job(4, 64, file_id=9)

    assert result == {"success": True}
    assert calls == [
        ("discard", 4, 64),
        ("run", {"user_id": 4, "job_id": 64, "file_id": 9}),
    ]


def test_build_route_terminates_created_job_when_dispatch_fails(monkeypatch):
    from flask import Flask
    from oj_modules.routes import repository_routes

    class BrokenTask:
        @staticmethod
        def delay(*_args, **_kwargs):
            raise RuntimeError("broker unavailable")

    failed = []
    monkeypatch.setattr(repository_routes, "current_user", lambda: {"id": 4})
    monkeypatch.setattr(repository_routes, "_repository_build_index_task", BrokenTask())
    monkeypatch.setattr(
        repository_routes,
        "get_or_create_active_repository_index_job",
        lambda _user_id: {"created": True, "job_id": 71},
    )
    monkeypatch.setattr(
        repository_routes,
        "get_repository_state",
        lambda _user_id: {"repository_generation": 13},
    )
    monkeypatch.setattr(
        repository_routes,
        "update_repository_index_job",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        repository_routes,
        "fail_repository_index_job_dispatch",
        lambda job_id, user_id, message: failed.append((job_id, user_id, message)),
    )

    app = Flask(__name__)
    app.register_blueprint(repository_routes.repository_bp)
    response = app.test_client().post("/api/repository/index/build")

    assert response.status_code == 500
    assert failed == [(71, 4, "启动结构化整理失败：broker unavailable")]


def test_status_poll_atomically_expires_job_past_hard_limit_lease(monkeypatch):
    connection = _StaleJobConnection()
    monkeypatch.setattr(index_services, "get_db_connection", lambda: connection)

    job = index_services.get_repository_index_job(job_id=81, user_id=4)

    assert job["status"] == "failed"
    assert "超过执行租约" in job["error_message"]
    assert connection.committed is True
    assert connection.rolled_back is False
    update_sql, update_params = connection.cursor_object.executed[0]
    assert "status IN ('queued', 'running')" in update_sql
    assert int(index_services.REPOSITORY_INDEX_TASK_STALE_AFTER_SECONDS) > int(
        index_services.REPOSITORY_INDEX_TASK_HARD_TIME_LIMIT_SECONDS
    )
    assert update_params[3] == 4
