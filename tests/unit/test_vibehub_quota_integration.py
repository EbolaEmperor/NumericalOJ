from __future__ import annotations

from contextlib import contextmanager
from io import BytesIO
import json
from pathlib import Path
import zipfile

from PIL import Image
import pytest

from oj_modules.vibehub import quotas, services, storage


USER = {"id": 7, "username": "viber", "is_admin": 0}
OTHER_USER = {"id": 8, "username": "other", "is_admin": 0}
ADMIN = {"id": 1, "username": "admin", "is_admin": 1}
_REAL_LOCK_OWNER_SNAPSHOT_GC_STATES = services._lock_owner_snapshot_gc_states
_REAL_LOCK_AND_COUNT_NONFEATURED_PROJECTS = (
    services._lock_and_count_nonfeatured_projects
)


@pytest.fixture(autouse=True)
def _default_quota_service_helpers(monkeypatch):
    monkeypatch.setattr(
        services,
        "_lock_owner_snapshot_gc_states",
        lambda _cursor, _owner_id: [],
    )
    monkeypatch.setattr(
        services,
        "_lock_and_count_nonfeatured_projects",
        lambda _cursor, _owner_id: 0,
    )
    monkeypatch.setattr(
        services,
        "_prepare_latest_image",
        lambda _project_key, _app_dir, **_kwargs: None,
    )


class _Cursor:
    def __init__(self):
        self.lastrowid = 31
        self.rowcount = 1
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))


class _Connection:
    def __init__(self):
        self.fake_cursor = _Cursor()
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self.fake_cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def _png_bytes(size=(16, 12)) -> bytes:
    output = BytesIO()
    Image.new("RGB", size, (232, 205, 166)).save(output, format="PNG")
    return output.getvalue()


def _package_bytes() -> bytes:
    manifest = {
        "schema_version": 1,
        "transport": "unix",
        "socket_path": "/run/vibehub/app.sock",
        "health_path": "/healthz",
        "title": "配额测试",
        "cover_image": "assets/cover.png",
    }
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Dockerfile", "FROM python:3.12-slim\n")
        archive.writestr("vibehub.json", json.dumps(manifest, ensure_ascii=False))
        archive.writestr("assets/cover.png", _png_bytes())
    return output.getvalue()


def _core_project(*, owner_id=7):
    return {
        "id": 3,
        "slug": "demo-vibe",
        "owner_id": owner_id,
        "latest_version_id": 12,
        "public_version_id": None,
        "review_version_id": None,
        "last_reviewed_version_id": None,
        "featured_status": "none",
        "is_featured": 0,
    }


def _latest_version():
    return {
        "id": 12,
        "project_id": 3,
        "version_number": 1,
        "title": "version",
        "summary": "",
        "description": "",
        "tags_json": "[]",
        "cover_image": "assets/cover.png",
        "package_sha256": "a" * 64,
        "package_size": 100,
        "manifest_json": json.dumps(
            {
                "schema_version": 1,
                "transport": "unix",
                "socket_path": "/run/vibehub/app.sock",
                "health_path": "/healthz",
                "cover_image": "assets/cover.png",
                "cover_image_mime": "image/png",
            }
        ),
        "review_status": "draft",
    }


def _empty_staging(root: Path) -> bool:
    staging = root / ".staging"
    return not staging.exists() or not any(staging.iterdir())


def test_database_quota_helpers_lock_user_projects_and_versions():
    class Cursor(_Cursor):
        def __init__(self):
            super().__init__()
            self.one = {"id": USER["id"]}
            self.many = [
                [{"slug": "alpha-vibe"}, {"slug": "beta-vibe"}],
                [{"id": 1}, {"id": 2}],
                [{"id": 1}],
                [{"id": 10, "version_number": 1}],
            ]

        def fetchone(self):
            return self.one

        def fetchall(self):
            return self.many.pop(0)

    cursor = Cursor()

    assert services._lock_owner_and_list_slugs(cursor, USER["id"]) == [
        "alpha-vibe",
        "beta-vibe",
    ]
    assert _REAL_LOCK_AND_COUNT_NONFEATURED_PROJECTS(cursor, USER["id"]) == 2
    assert services._lock_and_count_versions(cursor, 3) == 1
    assert services._version_identity_map(cursor, 3) == {10: 1}
    statements = [sql for sql, _params in cursor.calls]
    assert statements[0] == "SELECT id FROM users WHERE id = %s FOR UPDATE"
    assert "FROM vibehub_projects" in statements[1]
    assert statements[1].endswith("FOR UPDATE")
    assert "is_featured = 0" in statements[2]
    assert statements[2].endswith("FOR UPDATE")
    assert "FROM vibehub_versions" in statements[3]
    assert statements[3].endswith("FOR UPDATE")
    assert "SELECT id, version_number" in statements[4]
    assert statements[4].endswith("FOR UPDATE")


def test_snapshot_sets_preserve_distinct_latest_public_and_review_versions():
    known, live = services._snapshot_sets(
        {10: 1, 11: 2, 12: 3, 13: 4},
        (12, 10, 11),
    )

    assert known == {1, 2, 3, 4}
    assert live == {1, 2, 3}


def test_owner_snapshot_gc_facts_lock_only_owner_projects_and_versions():
    class Cursor(_Cursor):
        def __init__(self):
            super().__init__()
            self.many = iter(
                (
                    [
                        {
                            "id": 3,
                            "slug": "alpha-vibe",
                            "latest_version_id": 12,
                            "public_version_id": 10,
                            "review_version_id": 11,
                        },
                        {
                            "id": 4,
                            "slug": "beta-vibe",
                            "latest_version_id": 20,
                            "public_version_id": None,
                            "review_version_id": None,
                        },
                    ],
                    [
                        {"project_id": 3, "id": 10, "version_number": 1},
                        {"project_id": 3, "id": 11, "version_number": 2},
                        {"project_id": 3, "id": 12, "version_number": 3},
                        {"project_id": 3, "id": 13, "version_number": 4},
                        {"project_id": 4, "id": 20, "version_number": 1},
                    ],
                )
            )

        def fetchall(self):
            return next(self.many)

    cursor = Cursor()
    states = _REAL_LOCK_OWNER_SNAPSHOT_GC_STATES(cursor, USER["id"])

    assert states == [
        {
            "slug": "alpha-vibe",
            "known_versions": {1, 2, 3, 4},
            "live_versions": {1, 2, 3},
        },
        {
            "slug": "beta-vibe",
            "known_versions": {1},
            "live_versions": {1},
        },
    ]
    statements = [sql for sql, _params in cursor.calls]
    assert all(statement.endswith("FOR UPDATE") for statement in statements)
    assert "owner_id = %s" in statements[0]
    assert cursor.calls[0][1] == (USER["id"],)


def test_unauthorized_upload_fails_before_package_is_prepared(tmp_path, monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        services,
        "_fetch_core_for_update",
        lambda *_args: _core_project(owner_id=USER["id"]),
    )
    prepared = []
    monkeypatch.setattr(
        storage,
        "prepare_uploaded_package",
        lambda *_args, **_kwargs: prepared.append(True),
    )

    with pytest.raises(services.VibeHubPermissionError):
        services.upload_new_version(
            OTHER_USER,
            "demo-vibe",
            BytesIO(b"hostile payload"),
            upload_root=tmp_path,
        )

    assert prepared == []
    assert connection.rolled_back is True
    assert connection.closed is True


def test_project_count_quota_is_checked_before_create_upload(tmp_path, monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        services,
        "_lock_owner_and_list_slugs",
        lambda *_args: ["regular-one", "regular-two", "featured-one"],
    )
    monkeypatch.setattr(
        services,
        "_lock_and_count_nonfeatured_projects",
        lambda *_args: 2,
    )
    prepared = []
    monkeypatch.setattr(
        storage,
        "prepare_uploaded_package",
        lambda *_args, **_kwargs: prepared.append(True),
    )

    with pytest.raises(services.VibeHubError) as raised:
        services.create_project(
            USER,
            BytesIO(b"not read"),
            {"slug": "new-vibe"},
            upload_root=tmp_path,
        )

    assert raised.value.status_code == 409
    assert raised.value.code == "projects_quota_exceeded"
    assert prepared == []
    assert connection.rolled_back is True


def test_admin_project_creation_skips_project_count_limit(tmp_path, monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        services,
        "_lock_owner_and_list_slugs",
        lambda *_args: [f"admin-project-{index}" for index in range(50)],
    )
    monkeypatch.setattr(
        services,
        "_lock_and_count_nonfeatured_projects",
        lambda *_args: pytest.fail("管理员不应检查作品数量上限"),
    )
    monkeypatch.setattr(
        storage,
        "prepare_uploaded_package",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            storage.PackageValidationError("stop after quota gate")
        ),
    )

    with pytest.raises(services.VibeHubError, match="stop after quota gate"):
        services.create_project(
            ADMIN,
            BytesIO(b"invalid after quota gate"),
            {"slug": "admin-new-vibe"},
            upload_root=tmp_path,
        )

    assert connection.rolled_back is True


def test_admin_can_set_and_unset_featured_directly(monkeypatch):
    connections = (_Connection(), _Connection())
    connection_iter = iter(connections)
    monkeypatch.setattr(services, "get_db_connection", lambda: next(connection_iter))
    monkeypatch.setattr(
        services,
        "_fetch_core_for_update",
        lambda *_args: _core_project(),
    )
    monkeypatch.setattr(
        services,
        "_fetch_project_row",
        lambda *_args: {"public_version_id": 10},
    )
    monkeypatch.setattr(
        services,
        "_serialize_project",
        lambda row, *, audience, **_kwargs: {"row": row, "audience": audience},
    )

    enabled = services.set_featured(ADMIN, "demo-vibe", True)
    disabled = services.set_featured(ADMIN, "demo-vibe", False)

    updates = [next(
        (sql, params)
        for sql, params in connection.fake_cursor.calls
        if "is_featured = %s" in sql
    ) for connection in connections]
    assert updates[0][1] == ("approved", 1, ADMIN["id"], 3)
    assert updates[1][1] == ("none", 0, ADMIN["id"], 3)
    assert enabled["audience"] == disabled["audience"] == "public"
    assert all(connection.committed for connection in connections)


def test_featured_setting_requires_admin_and_boolean_without_opening_db(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_db_connection",
        lambda: pytest.fail("无效精品设置不应打开 DB"),
    )

    with pytest.raises(services.VibeHubPermissionError):
        services.set_featured(USER, "demo-vibe", True)
    with pytest.raises(services.VibeHubError, match="featured 必须为布尔值"):
        services.set_featured(ADMIN, "demo-vibe", 1)


def test_version_count_quota_is_checked_before_update_upload(tmp_path, monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(services, "_fetch_core_for_update", lambda *_args: _core_project())
    monkeypatch.setattr(
        services,
        "_lock_owner_and_list_slugs",
        lambda *_args: ["demo-vibe"],
    )
    monkeypatch.setattr(services, "_lock_and_count_versions", lambda *_args: 1000)
    prepared = []
    monkeypatch.setattr(
        storage,
        "prepare_uploaded_package",
        lambda *_args, **_kwargs: prepared.append(True),
    )

    with pytest.raises(services.VibeHubError) as raised:
        services.upload_new_version(
            USER,
            "demo-vibe",
            BytesIO(b"not read"),
            upload_root=tmp_path,
        )

    assert raised.value.status_code == 409
    assert raised.value.code == "versions_quota_exceeded"
    assert prepared == []
    assert connection.rolled_back is True


def test_create_storage_quota_maps_413_and_cleans_staging(
    tmp_path,
    monkeypatch,
):
    connection = _Connection()
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(services, "_lock_owner_and_list_slugs", lambda *_args: [])
    active = {"locked": False}
    real_lock = quotas.storage_mutation_lock

    @contextmanager
    def traced_lock(root):
        with real_lock(root) as locked:
            active["locked"] = True
            try:
                yield locked
            finally:
                active["locked"] = False

    real_prepare = storage.prepare_uploaded_package

    def traced_prepare(*args, **kwargs):
        assert active["locked"] is True
        return real_prepare(*args, **kwargs)

    def reject_quota(_slugs, incoming_bytes, _root, *, staged_incoming_path, **_kwargs):
        assert active["locked"] is True
        assert incoming_bytes == quotas.logical_tree_bytes(staged_incoming_path)
        raise quotas.VibeHubStorageQuotaExceeded(
            scope="user",
            current_bytes=100,
            incoming_bytes=incoming_bytes,
            projected_bytes=100 + incoming_bytes,
            limit_bytes=100,
        )

    monkeypatch.setattr(quotas, "storage_mutation_lock", traced_lock)
    monkeypatch.setattr(storage, "prepare_uploaded_package", traced_prepare)
    monkeypatch.setattr(quotas, "enforce_storage_quota", reject_quota)

    with pytest.raises(services.VibeHubError) as raised:
        services.create_project(
            USER,
            BytesIO(_package_bytes()),
            {"slug": "new-vibe"},
            upload_root=tmp_path,
        )

    assert raised.value.status_code == 413
    assert raised.value.code == "user_storage_quota_exceeded"
    assert connection.rolled_back is True
    assert _empty_staging(tmp_path)


def test_create_retries_after_rolled_back_slug_storage(tmp_path, monkeypatch):
    orphan = tmp_path / "retry-vibe" / "versions" / "v1" / "app"
    orphan.mkdir(parents=True)
    (orphan / "orphan.txt").write_text("old failed transaction", encoding="utf-8")
    (orphan.parent / "package.zip").write_bytes(b"old")
    storage.write_pointer(
        "retry-vibe",
        "latest",
        version_number=1,
        version_id=999,
        upload_root=tmp_path,
    )

    connection = _Connection()
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(services, "_lock_owner_and_list_slugs", lambda *_args: [])
    monkeypatch.setattr(services, "_insert_version", lambda *_args, **_kwargs: 41)
    monkeypatch.setattr(services, "_fetch_project_row", lambda *_args: {"ok": True})
    monkeypatch.setattr(
        services,
        "_serialize_project",
        lambda row, *, audience: {"row": row, "audience": audience},
    )
    built = []
    monkeypatch.setattr(
        services,
        "_prepare_latest_image",
        lambda project_key, app_dir, **kwargs: built.append(
            (project_key, Path(app_dir), kwargs)
        ),
    )

    result = services.create_project(
        USER,
        BytesIO(_package_bytes()),
        {"slug": "retry-vibe"},
        upload_root=tmp_path,
    )

    installed = tmp_path / "retry-vibe" / "versions" / "v1" / "app"
    assert not (installed / "orphan.txt").exists()
    assert (installed / "Dockerfile").is_file()
    assert storage.read_pointer(
        "retry-vibe", "latest", upload_root=tmp_path,
    ) == {"version": 1, "version_id": 41}
    assert result["audience"] == "latest"
    assert connection.committed is True
    assert len(built) == 1
    assert built[0][0] == "retry-vibe"
    assert built[0][1].name == "app"
    assert len(built[0][2]["package_digest"]) == 64


def test_upload_quota_failure_cleans_prepared_staging(tmp_path, monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(services, "_fetch_core_for_update", lambda *_args: _core_project())
    monkeypatch.setattr(
        services,
        "_lock_owner_and_list_slugs",
        lambda *_args: ["demo-vibe"],
    )
    monkeypatch.setattr(services, "_lock_and_count_versions", lambda *_args: 1)
    monkeypatch.setattr(services, "_fetch_version", lambda *_args: _latest_version())
    monkeypatch.setattr(services, "_version_identity_map", lambda *_args: {12: 1})

    def reject_quota(*_args, **_kwargs):
        raise quotas.VibeHubStorageQuotaExceeded(
            scope="user",
            current_bytes=100,
            incoming_bytes=1,
            projected_bytes=101,
            limit_bytes=100,
        )

    monkeypatch.setattr(quotas, "enforce_storage_quota", reject_quota)

    with pytest.raises(services.VibeHubError) as raised:
        services.upload_new_version(
            USER,
            "demo-vibe",
            BytesIO(_package_bytes()),
            upload_root=tmp_path,
        )

    assert raised.value.code == "user_storage_quota_exceeded"
    assert connection.rolled_back is True
    assert _empty_staging(tmp_path)


def test_update_restores_previous_latest_image_when_db_write_fails(
    tmp_path,
    monkeypatch,
):
    connection = _Connection()
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(services, "_fetch_core_for_update", lambda *_args: _core_project())
    monkeypatch.setattr(
        services,
        "_lock_owner_and_list_slugs",
        lambda *_args: ["demo-vibe"],
    )
    monkeypatch.setattr(services, "_lock_and_count_versions", lambda *_args: 1)
    monkeypatch.setattr(services, "_fetch_version", lambda *_args: _latest_version())
    monkeypatch.setattr(services, "_version_identity_map", lambda *_args: {12: 1})
    previous_image_id = "sha256:" + "a" * 64
    monkeypatch.setattr(
        services,
        "_prepare_latest_image",
        lambda *_args, **_kwargs: previous_image_id,
    )
    def fail_db_write(*_args, **_kwargs):
        raise RuntimeError("db write failed")

    monkeypatch.setattr(services, "_insert_version", fail_db_write)
    restored = []
    monkeypatch.setattr(
        services,
        "_restore_image_tag",
        lambda project_key, channel, image_id: restored.append(
            (project_key, channel, image_id)
        ),
        raising=False,
    )

    with pytest.raises(RuntimeError, match="db write failed"):
        services.upload_new_version(
            USER,
            "demo-vibe",
            BytesIO(_package_bytes()),
            upload_root=tmp_path,
        )

    assert restored == [("demo-vibe", "latest", previous_image_id)]
    assert connection.rolled_back is True
    assert connection.committed is False


def test_metadata_edit_checks_source_size_before_clone(tmp_path, monkeypatch):
    source_app = tmp_path / "demo-vibe" / "versions" / "v1" / "app"
    (source_app / "assets").mkdir(parents=True)
    (source_app / "assets" / "cover.png").write_bytes(_png_bytes())
    (source_app / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    (source_app / "vibehub.json").write_text("{}\n", encoding="utf-8")
    (source_app.parent / "package.zip").write_bytes(b"package")
    storage.generate_processed_cover(
        "assets/cover.png",
        source_app,
        source_app.parent / storage.PROCESSED_COVER_FILENAME,
    )
    orphan_app = tmp_path / "demo-vibe" / "versions" / "v2" / "app"
    orphan_app.mkdir(parents=True)
    (orphan_app / "orphan.txt").write_text("rolled back", encoding="utf-8")
    (orphan_app.parent / "package.zip").write_bytes(b"orphan package")

    connection = _Connection()
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(services, "_fetch_core_for_update", lambda *_args: _core_project())
    monkeypatch.setattr(
        services,
        "_lock_owner_and_list_slugs",
        lambda *_args: ["demo-vibe"],
    )
    monkeypatch.setattr(services, "_lock_and_count_versions", lambda *_args: 1)
    monkeypatch.setattr(services, "_fetch_version", lambda *_args: _latest_version())
    monkeypatch.setattr(services, "_version_identity_map", lambda *_args: {12: 1})
    monkeypatch.setattr(services, "_insert_version", lambda *_args, **_kwargs: 13)
    monkeypatch.setattr(services, "_fetch_project_row", lambda *_args: {"ok": True})
    monkeypatch.setattr(
        services,
        "_serialize_project",
        lambda row, *, audience: {"row": row, "audience": audience},
    )

    order = []
    real_enforce = quotas.enforce_storage_quota
    real_clone = storage.clone_snapshot

    def traced_enforce(*args, **kwargs):
        order.append(("quota", args[1]))
        return real_enforce(*args, **kwargs)

    def traced_clone(*args, **kwargs):
        order.append(("clone", None))
        return real_clone(*args, **kwargs)

    monkeypatch.setattr(quotas, "enforce_storage_quota", traced_enforce)
    monkeypatch.setattr(storage, "clone_snapshot", traced_clone)
    monkeypatch.setattr(
        services,
        "_lock_and_count_nonfeatured_projects",
        lambda *_args: pytest.fail("编辑已有作品不应检查作品数量"),
    )
    monkeypatch.setattr(
        services,
        "_prepare_latest_image",
        lambda project_key, app_dir, **kwargs: order.append(
            ("image", project_key, Path(app_dir), kwargs)
        ),
    )

    source_bytes = quotas.logical_tree_bytes(source_app.parent)
    result = services.edit_project(
        USER,
        "demo-vibe",
        {"title": "version 2"},
        upload_root=tmp_path,
    )

    assert order == [
        ("quota", source_bytes),
        ("clone", None),
        (
            "image",
            "demo-vibe",
            tmp_path / "demo-vibe" / "versions" / "v2" / "app",
            {"package_digest": "a" * 64, "featured": False},
        ),
    ]
    assert (tmp_path / "demo-vibe" / "versions" / "v2" / "app").is_dir()
    assert not (
        tmp_path / "demo-vibe" / "versions" / "v2" / "app" / "orphan.txt"
    ).exists()
    assert result["audience"] == "latest"
    assert connection.committed is True
