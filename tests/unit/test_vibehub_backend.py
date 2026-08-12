from __future__ import annotations

from io import BytesIO
from contextlib import contextmanager
import inspect
import json
from pathlib import Path
import re
import stat
import time
import zipfile

from flask import Flask, Request, request
from PIL import Image
import pytest
from werkzeug.datastructures import MultiDict

from oj_modules.api import vibehub_api
from oj_modules.vibehub import quotas, services, storage


USER = {"id": 7, "username": "viber", "is_admin": 0}
ADMIN = {"id": 1, "username": "admin", "is_admin": 1}
OUTSIDER = {"id": 8, "username": "visitor", "is_admin": 0}

PRIVATE_PUBLIC_PROJECT_FIELDS = {
    "latest_version",
    "submitted_version",
    "has_pending_review",
    "review_status",
    "latest_review_status",
    "review_note",
    "latest_review_note",
    "last_reviewed_version",
    "last_review_status",
    "last_review_note",
    "featured_status",
    "featured_review_note",
    "review_requested_at",
    "updated_at",
}


def _png_bytes(size=(8, 6)):
    output = BytesIO()
    Image.new("RGB", size, (232, 205, 166)).save(output, format="PNG")
    return output.getvalue()


def _package_bytes(*, manifest=None, files=None, symlink=None, include_cover=True):
    manifest = dict(manifest or {
        "schema_version": 1,
        "transport": "unix",
        "socket_path": "/run/vibehub/app.sock",
        "health_path": "/healthz",
        "title": "测试 Vibe",
    })
    files = dict(files or {})
    if include_cover and "cover_image" not in manifest:
        manifest["cover_image"] = "assets/cover.png"
        files.setdefault("assets/cover.png", _png_bytes())
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Dockerfile", "FROM python:3.12-slim\n")
        archive.writestr("vibehub.json", json.dumps(manifest, ensure_ascii=False))
        for name, content in files.items():
            archive.writestr(name, content)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "/etc/passwd")
    return output.getvalue()


def test_package_validation_installs_immutable_snapshot_and_pointers(tmp_path):
    raw = _package_bytes(
        manifest={
            "schema_version": 1,
            "transport": "unix",
            "socket_path": "/run/vibehub/app.sock",
            "health_path": "/healthz",
            "title": "小屋",
            "cover_image": "assets/cover.png",
        },
        files={"assets/cover.png": _png_bytes()},
    )

    prepared = storage.prepare_uploaded_package(BytesIO(raw), upload_root=tmp_path)

    assert re.fullmatch(r"upload-[0-9a-f]{32}", prepared.staging_root.name)
    assert prepared.manifest["cover_image"] == "assets/cover.png"
    assert prepared.manifest["cover_image_mime"] == "image/png"
    assert prepared.package_sha256
    target = storage.install_prepared_snapshot(
        prepared, "safe-vibe", 1, upload_root=tmp_path,
    )
    assert (target / "app" / "Dockerfile").is_file()
    assert (target / "package.zip").read_bytes() == raw
    assert stat.S_IMODE((tmp_path).stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / ".staging").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "safe-vibe").stat().st_mode) == 0o700
    assert stat.S_IMODE((target / "app").stat().st_mode) == 0o700
    assert stat.S_IMODE((target / "app" / "Dockerfile").stat().st_mode) == 0o600
    assert stat.S_IMODE((target / "package.zip").stat().st_mode) == 0o600
    processed = target / storage.PROCESSED_COVER_FILENAME
    assert processed.stat().st_size <= storage.MAX_PROCESSED_COVER_BYTES
    with Image.open(processed) as image:
        assert image.format == "JPEG"
        assert image.size == (1280, 720)

    assert storage.read_pointer("safe-vibe", "latest", upload_root=tmp_path) is None
    old = storage.write_pointer(
        "safe-vibe", "latest", version_number=1, version_id=19, upload_root=tmp_path,
    )
    assert old is None
    assert storage.read_pointer("safe-vibe", "latest", upload_root=tmp_path) == {
        "version": 1,
        "version_id": 19,
    }
    assert stat.S_IMODE((tmp_path / "safe-vibe" / "latest.json").stat().st_mode) == 0o600


def test_package_prepare_rejects_symlink_staging_root_before_writing(tmp_path):
    upload_root = tmp_path / "vibehub"
    upload_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (upload_root / ".staging").symlink_to(outside, target_is_directory=True)

    with pytest.raises(quotas.VibeHubStorageSecurityError):
        storage.prepare_uploaded_package(
            BytesIO(_package_bytes()),
            upload_root=upload_root,
        )

    assert list(outside.iterdir()) == []


def test_storage_rejects_slug_path_traversal(tmp_path):
    with pytest.raises(ValueError, match="storage slug"):
        storage.version_snapshot_path("../outside", 1, upload_root=tmp_path)
    with pytest.raises(ValueError, match="storage slug"):
        storage.write_pointer(
            "bad/slug", "latest", version_number=1, version_id=1, upload_root=tmp_path,
        )
    assert not (tmp_path.parent / "outside").exists()


@pytest.mark.parametrize(
    "raw, message",
    [
        (
            _package_bytes(
                manifest={
                    "schema_version": 1,
                    "transport": "unix",
                    "socket_path": "/run/vibehub/app.sock",
                    "health_path": "/healthz",
                    "port": 8080,
                }
            ),
            "不得声明网络端口",
        ),
        (_package_bytes(symlink="escape"), "symlink"),
    ],
)
def test_package_validation_rejects_network_port_and_symlinks(tmp_path, raw, message):
    with pytest.raises(storage.PackageValidationError, match=message):
        storage.prepare_uploaded_package(BytesIO(raw), upload_root=tmp_path)


@pytest.mark.parametrize(
    "name, content",
    [
        ("cover.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>'),
        ("cover.png", b"<html><script>alert(1)</script></html>"),
    ],
)
def test_cover_must_be_a_real_safe_raster_image(tmp_path, name, content):
    raw = _package_bytes(
        manifest={
            "schema_version": 1,
            "transport": "unix",
            "socket_path": "/run/vibehub/app.sock",
            "health_path": "/healthz",
            "cover_image": name,
        },
        files={name: content},
    )
    with pytest.raises(storage.PackageValidationError, match="cover_image"):
        storage.prepare_uploaded_package(BytesIO(raw), upload_root=tmp_path)


def test_cover_pixel_limit_is_enforced(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "cover.png").write_bytes(_png_bytes((4, 4)))
    monkeypatch.setattr(storage, "MAX_COVER_PIXELS", 10)

    with pytest.raises(storage.PackageValidationError, match="像素尺寸"):
        storage.validate_cover_image("cover.png", app_dir)


def test_cover_is_required_in_manifest(tmp_path):
    raw = _package_bytes(include_cover=False)
    with pytest.raises(storage.PackageValidationError, match="必须声明 cover_image"):
        storage.prepare_uploaded_package(BytesIO(raw), upload_root=tmp_path)


@pytest.mark.parametrize(
    "size, expected",
    [
        ((1600, 900), (0, 0, 1600, 900)),
        ((801, 901), (0, 225, 801, 675)),
        ((1001, 500), (56, 0, 944, 500)),
    ],
)
def test_cover_center_crop_box_is_deterministic(size, expected):
    assert storage._cover_crop_box(*size) == expected


def test_processed_cover_keeps_source_unchanged_and_meets_contract(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    source = app_dir / "cover.png"
    source.write_bytes(_png_bytes((801, 901)))
    original = source.read_bytes()

    output, mime = storage.generate_processed_cover(
        "cover.png", app_dir, tmp_path / "cover.jpg",
    )

    assert source.read_bytes() == original
    assert mime == "image/jpeg"
    assert output.stat().st_size <= 400 * 1024
    with Image.open(output) as image:
        assert image.size == (1280, 720)
        assert image.format == "JPEG"


def test_new_package_manifest_cover_does_not_inherit_old_cover(tmp_path):
    (tmp_path / "new.png").write_bytes(_png_bytes())
    (tmp_path / "old.png").write_bytes(_png_bytes())

    chosen = services._metadata(
        {"title": "v2"},
        base={"title": "v1", "cover_image": "old.png"},
        manifest={"cover_image": "new.png"},
        app_dir=tmp_path,
        package_replaced=True,
    )
    assert chosen["cover_image"] == "new.png"
    with pytest.raises(services.VibeHubError, match="必须声明 cover_image"):
        services._metadata(
            {"title": "v2"},
            base={"title": "v1", "cover_image": "old.png"},
            manifest={},
            app_dir=tmp_path,
            package_replaced=True,
        )


def _project_row(**overrides):
    row = {
        "id": 3,
        "slug": "demo-vibe",
        "owner_id": 7,
        "owner_username": "viber",
        "latest_version_id": 12,
        "public_version_id": 10,
        "review_version_id": 12,
        "last_reviewed_version_id": None,
        "featured_status": "none",
        "is_featured": 0,
        "latest_version": 3,
        "latest_title": "latest",
        "latest_summary": "",
        "latest_description": "",
        "latest_tags_json": "[]",
        "latest_cover_image": None,
        "latest_review_status": "pending",
        "latest_review_note": None,
        "public_version": 1,
        "public_title": "public",
        "public_summary": "",
        "public_description": "",
        "public_tags_json": "[]",
        "public_cover_image": None,
        "public_review_status": "approved",
        "public_review_note": None,
        "submitted_version": 3,
        "review_title": "latest",
        "review_summary": "",
        "review_description": "",
        "review_tags_json": "[]",
        "review_cover_image": None,
        "review_review_status": "pending",
        "review_review_note": None,
        "last_reviewed_version": None,
        "last_review_status": None,
        "last_review_note": None,
    }
    row.update(overrides)
    return row


def test_latest_serializer_exposes_explicit_pending_version_and_rejection_note():
    pending = services._serialize_project(_project_row(), audience="latest")
    rejected = services._serialize_project(
        _project_row(
            review_version_id=None,
            submitted_version=None,
            latest_review_status="rejected",
            latest_review_note="请移除未授权素材",
        ),
        audience="latest",
    )

    assert pending["has_pending_review"] is True
    assert pending["submitted_version"] == 3
    assert pending["latest_version"] == 3
    assert pending["play_url"] == "/vibehub/demo-vibe/play?channel=latest"
    assert rejected["has_pending_review"] is False
    assert rejected["review_note"] == "请移除未授权素材"

    edited_after_rejection = services._serialize_project(
        _project_row(
            review_version_id=None,
            submitted_version=None,
            last_reviewed_version=2,
            last_review_status="rejected",
            last_review_note="v2 使用了未授权素材",
        ),
        audience="latest",
    )
    assert edited_after_rejection["last_review_note"] == "v2 使用了未授权素材"


def test_public_serializer_omits_private_workflow_instead_of_masking_values():
    row = _project_row(
        latest_review_status="rejected",
        latest_review_note="PRIVATE latest note",
        last_reviewed_version=2,
        last_review_status="rejected",
        last_review_note="PRIVATE last note",
        featured_status="pending",
        featured_review_note="PRIVATE featured note",
        review_requested_at="PRIVATE review time",
        updated_at="PRIVATE draft update time",
    )

    public = services._serialize_project(row, audience="public")
    latest = services._serialize_project(row, audience="latest")
    review = services._serialize_project(row, audience="review")

    assert public["title"] == "public"
    assert public["public_version"] == 1
    assert public["selected_version"] == 1
    assert PRIVATE_PUBLIC_PROJECT_FIELDS.isdisjoint(public)
    assert latest["latest_review_note"] == "PRIVATE latest note"
    assert latest["last_review_note"] == "PRIVATE last note"
    assert review["submitted_version"] == 3
    assert review["has_pending_review"] is True


def test_private_first_version_views_have_scoped_play_urls():
    private = _project_row(
        public_version_id=None,
        public_version=None,
    )

    latest = services._serialize_project(private, audience="latest")
    review = services._serialize_project(private, audience="review")
    public = services._serialize_project(private, audience="public")

    assert latest["play_url"] == "/vibehub/demo-vibe/play?channel=latest"
    assert review["play_url"] == "/vibehub/demo-vibe/play?channel=review"
    assert public["play_url"] is None


class _Cursor:
    def __init__(self, rows):
        self.rows = iter(rows)
        self.calls = []
        self.rowcount = 1
        self.lastrowid = 99

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))

    def fetchone(self):
        return next(self.rows)

    def fetchall(self):
        return []


class _Connection:
    def __init__(self, rows):
        self.fake_cursor = _Cursor(rows)
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


def test_gallery_projects_selects_only_actor_visible_snapshots(monkeypatch):
    public_row = _project_row(
        slug="public-vibe",
        owner_id=OUTSIDER["id"],
    )
    own_private_row = _project_row(
        slug="own-private",
        public_version_id=None,
        public_version=None,
        public_title=None,
        review_version_id=12,
        submitted_version=3,
        review_title="latest",
        review_review_status="pending",
    )
    user_connection = _Connection([])
    user_connection.fake_cursor.fetchall = lambda: [public_row, own_private_row]
    monkeypatch.setattr(services, "get_db_connection", lambda: user_connection)
    by_slug = {
        project["slug"]: project
        for project in services.list_gallery_projects(USER)
    }
    assert PRIVATE_PUBLIC_PROJECT_FIELDS.isdisjoint(by_slug["public-vibe"])
    own = by_slug["own-private"]
    assert tuple(own[key] for key in (
        "title", "is_mine", "is_pending", "can_edit", "can_approve",
        "can_manage_featured",
    )) == ("latest", True, True, True, False, False)
    user_query, params = user_connection.fake_cursor.calls[0]
    assert "p.owner_id = %s" in user_query and "rv.review_status = 'pending'" not in user_query
    assert params == (USER["id"], USER["id"])

    admin_connection = _Connection([])
    admin_connection.fake_cursor.fetchall = lambda: [_project_row()]
    monkeypatch.setattr(services, "get_db_connection", lambda: admin_connection)
    pending = services.list_gallery_projects(ADMIN)[0]
    assert (
        pending["title"], pending["is_pending"], pending["can_approve"],
        pending["can_manage_featured"],
    ) == (
        "latest", True, True, True,
    )
    assert pending["play_url"].endswith("?channel=review")
    assert "rv.review_status = 'pending'" in admin_connection.fake_cursor.calls[0][0]


def test_save_always_replaces_the_pending_review():
    cursor = _Cursor([])
    review_version_id = services._point_latest_version(
        cursor, project_id=3, version_id=13, previous_review_id=11,
    )

    assert review_version_id == 13
    assert [params for _sql, params in cursor.calls] == [
        (11,), (13,), (13, 13, 3),
    ]


def test_create_preflight_rejects_nonfeatured_limit_and_admin_skips_db(monkeypatch):
    connection = _Connection([{"nonfeatured_count": 2}])
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)

    with pytest.raises(services.VibeHubError) as raised:
        services.preflight_create_project(USER)

    assert raised.value.code == "projects_quota_exceeded"
    assert connection.closed is True
    sql, params = connection.fake_cursor.calls[0]
    assert "COUNT(*) AS nonfeatured_count" in sql
    assert "is_featured = 0" in sql
    assert "FOR UPDATE" not in sql
    assert params == (USER["id"],)

    monkeypatch.setattr(
        services,
        "get_db_connection",
        lambda: pytest.fail("管理员创建预检不应访问作品数配额"),
    )
    assert services.preflight_create_project(ADMIN) is None


def test_upload_preflight_checks_owner_and_version_cap_in_one_query(monkeypatch):
    connection = _Connection(
        [{"owner_id": USER["id"], "version_count": 1_000}]
    )
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)

    with pytest.raises(services.VibeHubError) as raised:
        services.preflight_upload_project(USER, "demo-vibe")

    assert raised.value.code == "versions_quota_exceeded"
    assert connection.closed is True
    sql, params = connection.fake_cursor.calls[0]
    assert "SELECT COUNT(*)" in sql
    assert "FROM vibehub_versions" in sql
    assert len(connection.fake_cursor.calls) == 1
    assert params == ("demo-vibe",)


def test_admin_preflight_is_db_free(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_db_connection",
        lambda: pytest.fail("管理员身份预检不应打开 DB"),
    )

    assert services.preflight_admin(ADMIN) is None
    with pytest.raises(services.VibeHubPermissionError):
        services.preflight_admin(USER)


def test_public_and_mine_lists_are_database_backed(monkeypatch):
    public_connection = _Connection([])
    mine_connection = _Connection([])
    connections = iter((public_connection, mine_connection))
    monkeypatch.setattr(services, "get_db_connection", lambda: next(connections))

    public = services.list_public_projects()
    mine = services.list_user_projects(USER)

    assert public == []
    public_query = public_connection.fake_cursor.calls[0][0]
    assert "p.updated_at DESC" not in public_query
    assert "COALESCE(pv.reviewed_at, p.created_at) DESC" in public_query
    assert mine == []


def test_only_owner_gets_workflow_enrichment_on_explicit_public_detail(monkeypatch):
    row = _project_row(
        latest_review_note="PRIVATE latest note",
        last_review_note="PRIVATE last note",
        featured_status="pending",
        featured_review_note="PRIVATE featured note",
        updated_at="PRIVATE draft update time",
    )
    connections = iter(
        (_Connection([row]), _Connection([row]), _Connection([row]))
    )
    monkeypatch.setattr(services, "get_db_connection", lambda: next(connections))

    outsider = services.get_project(
        "demo-vibe", actor=OUTSIDER, audience="public",
    )
    administrator = services.get_project(
        "demo-vibe", actor=ADMIN, audience="public",
    )
    owner = services.get_project(
        "demo-vibe", actor=USER, audience="public",
    )

    assert PRIVATE_PUBLIC_PROJECT_FIELDS.isdisjoint(outsider)
    assert PRIVATE_PUBLIC_PROJECT_FIELDS.isdisjoint(administrator)
    assert owner["latest_version"] == 3
    assert owner["has_pending_review"] is True
    assert owner["latest_review_note"] == "PRIVATE latest note"
    assert "featured_status" not in owner
    assert "featured_review_note" not in owner


def test_admin_cannot_read_owner_latest_but_can_read_pending_review(monkeypatch):
    public_row = _project_row()
    private_row = _project_row(
        public_version_id=None,
        public_version=None,
        public_title=None,
    )
    connections = iter(
        (
            _Connection([public_row]),
            _Connection([private_row]),
            _Connection([public_row]),
            _Connection([_project_row(review_review_status="approved")]),
        )
    )
    monkeypatch.setattr(services, "get_db_connection", lambda: next(connections))

    default_view = services.get_project("demo-vibe", actor=ADMIN)
    assert default_view["title"] == "public"
    with pytest.raises(services.VibeHubPermissionError):
        services.get_project("demo-vibe", actor=ADMIN, audience="latest")
    review = services.get_project("demo-vibe", actor=ADMIN, audience="review")
    assert review["title"] == "latest"
    assert review["selected_version"] == 3
    assert review["submitted_version"] == 3
    assert review["has_pending_review"] is True
    with pytest.raises(services.VibeHubNotFoundError):
        services.get_project("demo-vibe", actor=ADMIN, audience="review")


def test_admin_cannot_run_latest_but_can_run_pending_review(
    tmp_path,
    monkeypatch,
):
    app_dir = tmp_path / "demo-vibe" / "versions" / "v3" / "app"
    app_dir.mkdir(parents=True)
    project = _project_row()
    connections = iter(
        (
            _Connection([project]),
            _Connection([project, _version_row(12, 3, "pending")]),
        )
    )
    monkeypatch.setattr(services, "get_db_connection", lambda: next(connections))

    with pytest.raises(services.VibeHubPermissionError):
        services.resolve_project_package(
            "demo-vibe",
            audience="latest",
            actor=ADMIN,
            upload_root=tmp_path,
        )
    review = services.resolve_project_package(
        "demo-vibe",
        audience="review",
        actor=ADMIN,
        upload_root=tmp_path,
    )
    assert review["version"] == 3
    assert "package_dir" not in review


def _version_row(version_id=12, version_number=3, status="draft"):
    return {
        "id": version_id,
        "project_id": 3,
        "version_number": version_number,
        "title": "version",
        "summary": "",
        "description": "",
        "tags_json": "[]",
        "cover_image": None,
        "package_sha256": "a" * 64,
        "package_size": 12,
        "manifest_json": "{}",
        "review_status": status,
    }


def test_review_rejects_a_stale_confirmed_version_before_writing_public_pointer(
    tmp_path,
    monkeypatch,
):
    connection = _Connection([_project_row(), _version_row(12, 3, "pending")])
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        storage,
        "write_pointer",
        lambda *_args, **_kwargs: pytest.fail("版本身份校验前不得写 public 指针"),
    )

    with pytest.raises(services.VibeHubError) as raised:
        services.review_submission(
            ADMIN,
            "demo-vibe",
            "approve",
            expected_version=99,
            upload_root=tmp_path,
        )

    assert raised.value.code == "review_stale"
    assert connection.rolled_back is True


@pytest.mark.parametrize("decision", ("approve", "reject"))
def test_review_rejects_pending_version_that_is_not_the_latest(
    tmp_path,
    monkeypatch,
    decision,
):
    stale_project = _project_row(
        review_version_id=11,
        submitted_version=2,
        review_title="submitted",
    )
    connection = _Connection([stale_project, _version_row(11, 2, "pending")])
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        storage,
        "write_pointer",
        lambda *_args, **_kwargs: pytest.fail("过期待审版本不得写 public 指针"),
    )

    with pytest.raises(services.VibeHubError) as raised:
        services.review_submission(
            ADMIN,
            "demo-vibe",
            decision,
            expected_version=2,
            upload_root=tmp_path,
        )

    assert raised.value.code == "review_stale"
    assert connection.rolled_back is True
    assert connection.committed is False


def test_review_rejection_response_returns_the_just_reviewed_latest_version(
    tmp_path,
    monkeypatch,
):
    project = _project_row()
    reviewed = _project_row()
    final_row = _project_row(
        latest_review_status="rejected",
        review_version_id=None,
        submitted_version=None,
    )
    connection = _Connection(
        [project, _version_row(12, 3, "pending"), reviewed, final_row]
    )
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        services,
        "_version_identity_map",
        lambda *_args: {10: 1, 12: 3},
    )
    monkeypatch.setattr(storage, "prune_project_snapshots", lambda *_args, **_kwargs: None)

    result = services.review_submission(
        ADMIN,
        "demo-vibe",
        "reject",
        note="needs changes",
        expected_version=3,
        upload_root=tmp_path,
    )

    assert result["title"] == "latest"
    assert result["review_status"] == "rejected"
    assert result["play_url"] is None


def test_review_approval_promotes_latest_image_to_public(tmp_path, monkeypatch):
    final_row = _project_row(
        public_version_id=12,
        public_version=3,
        public_title="latest",
        review_version_id=None,
    )
    connection = _Connection([
        _project_row(), _version_row(12, 3, "pending"), final_row,
    ])
    promoted = []
    pointers = []
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        services,
        "_promote_latest_image",
        lambda *args: promoted.append(args),
    )
    monkeypatch.setattr(services, "_version_identity_map", lambda *_args: {10: 1, 12: 3})
    monkeypatch.setattr(storage, "read_pointer", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        storage, "write_pointer",
        lambda *args, **kwargs: pointers.append((args, kwargs)),
    )
    monkeypatch.setattr(storage, "prune_project_snapshots", lambda *_args, **_kwargs: None)

    result = services.review_submission(
        ADMIN, "demo-vibe", "approve", expected_version=3, upload_root=tmp_path,
    )

    assert promoted == [("demo-vibe", "a" * 64)]
    assert pointers[0][0][:2] == ("demo-vibe", "public")
    assert result["public_version"] == 3
    assert connection.committed is True


def test_review_approval_restores_previous_public_image_when_pointer_write_fails(
    tmp_path,
    monkeypatch,
):
    connection = _Connection([
        _project_row(), _version_row(12, 3, "pending"),
    ])
    previous_image_id = "sha256:" + "b" * 64
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        services,
        "_promote_latest_image",
        lambda _project_key, _package_digest: previous_image_id,
    )
    monkeypatch.setattr(storage, "read_pointer", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        storage,
        "write_pointer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("pointer write failed")
        ),
    )
    restored = []
    monkeypatch.setattr(
        services,
        "_restore_image_tag",
        lambda project_key, channel, image_id: restored.append(
            (project_key, channel, image_id)
        ),
        raising=False,
    )

    with pytest.raises(RuntimeError, match="pointer write failed"):
        services.review_submission(
            ADMIN,
            "demo-vibe",
            "approve",
            expected_version=3,
            upload_root=tmp_path,
        )

    assert restored == [("demo-vibe", "public", previous_image_id)]
    assert connection.rolled_back is True
    assert connection.committed is False


def _api_client(monkeypatch):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: USER)
    return app.test_client()


def test_public_detail_api_does_not_give_admin_an_authorship_bypass(monkeypatch):
    row = _project_row(
        latest_review_note="PRIVATE latest note",
        last_review_note="PRIVATE last note",
        featured_status="pending",
        featured_review_note="PRIVATE featured note",
        updated_at="PRIVATE draft update time",
    )
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: ADMIN)
    monkeypatch.setattr(
        services, "get_db_connection", lambda: _Connection([row]),
    )

    response = app.test_client().get(
        "/api/vibehub/projects/demo-vibe?view=public",
    )

    assert response.status_code == 200
    project = response.get_json()["project"]
    assert project["title"] == "public"
    assert PRIVATE_PUBLIC_PROJECT_FIELDS.isdisjoint(project)


def test_cover_api_forces_verified_image_mime_and_nosniff(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "cover.bin").write_bytes(_png_bytes())
    storage.generate_processed_cover(
        "cover.bin", app_dir, storage.processed_cover_path(app_dir),
    )
    monkeypatch.setattr(
        services,
        "get_project",
        lambda *_args, **_kwargs: {"cover_image": "cover.bin"},
    )
    monkeypatch.setattr(
        services,
        "resolve_project_package",
        lambda *_args, **_kwargs: {
            "slug": "demo-vibe",
            "version": 1,
            "manifest": {"cover_image_mime": "image/png"},
        },
    )
    monkeypatch.setattr(
        storage,
        "resolve_snapshot_app",
        lambda *_args, **_kwargs: app_dir,
    )
    client = _api_client(monkeypatch)

    response = client.get("/api/vibehub/projects/demo-vibe/cover")

    assert response.status_code == 200
    assert response.content_type == "image/jpeg"
    assert response.headers["Cache-Control"] == "public, max-age=0, must-revalidate"
    assert response.headers["X-Content-Type-Options"] == "nosniff"

    private_response = client.get(
        "/api/vibehub/projects/demo-vibe/cover?view=latest",
    )
    assert private_response.headers["Cache-Control"] == "private, no-store"


def test_cover_api_revalidates_file_instead_of_trusting_stored_mime(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "cover.png").write_text("<html><script>alert(1)</script></html>", encoding="utf-8")
    storage.processed_cover_path(app_dir).write_text(
        "<html><script>alert(1)</script></html>", encoding="utf-8",
    )
    monkeypatch.setattr(
        services,
        "get_project",
        lambda *_args, **_kwargs: {"cover_image": "cover.png"},
    )
    monkeypatch.setattr(
        services,
        "resolve_project_package",
        lambda *_args, **_kwargs: {
            "slug": "demo-vibe",
            "version": 1,
            "manifest": {"cover_image_mime": "image/png"},
        },
    )
    monkeypatch.setattr(
        storage,
        "resolve_snapshot_app",
        lambda *_args, **_kwargs: app_dir,
    )
    client = _api_client(monkeypatch)

    response = client.get("/api/vibehub/projects/demo-vibe/cover")

    assert response.status_code == 404
    assert response.get_json()["message"] == "平台封面副本格式无效"


def _multipart_body() -> tuple[bytes, str]:
    boundary = "vibehub-test-boundary"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="package"; filename="large.zip"\r\n'
        "Content-Type: application/zip\r\n\r\n"
        "not parsed\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    return body, f"multipart/form-data; boundary={boundary}"


def _forbid_multipart_parse(_request):
    raise AssertionError("本请求必须在读取 request.files/form 前被拒绝")


def test_create_api_requires_login_without_parsing_multipart(monkeypatch):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: None)
    monkeypatch.setattr(Request, "_load_form_data", _forbid_multipart_parse)
    body, content_type = _multipart_body()

    response = app.test_client().post(
        "/api/vibehub/projects",
        data=body,
        content_type=content_type,
    )

    assert response.status_code == 401
    assert response.get_json()["code"] == "authentication_required"


def test_featured_admin_setting_rejects_non_admin_before_parsing_multipart(
    monkeypatch,
):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: USER)
    monkeypatch.setattr(Request, "_load_form_data", _forbid_multipart_parse)
    body, content_type = _multipart_body()

    response = app.test_client().post(
        "/api/vibehub/admin/featured/demo-vibe",
        data=body,
        content_type=content_type,
    )

    assert response.status_code == 403
    assert response.get_json()["code"] == "forbidden"


def test_user_featured_request_route_is_removed(monkeypatch):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: USER)

    response = app.test_client().post(
        "/api/vibehub/projects/demo-vibe/featured",
    )

    assert response.status_code == 404


def test_admin_featured_api_passes_explicit_boolean(monkeypatch):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: ADMIN)
    received = []
    monkeypatch.setattr(
        services,
        "set_featured",
        lambda actor, slug, featured: received.append((actor, slug, featured))
        or {"slug": slug, "is_featured": featured},
    )

    response = app.test_client().post(
        "/api/vibehub/admin/featured/demo-vibe",
        json={"featured": True},
    )

    assert response.status_code == 200
    assert received == [(ADMIN, "demo-vibe", True)]


def test_create_api_rejects_project_limit_before_parsing_multipart(
    tmp_path,
    monkeypatch,
):
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        VIBEHUB_UPLOAD_ROOT=tmp_path,
    )
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: USER)
    monkeypatch.setattr(Request, "_load_form_data", _forbid_multipart_parse)

    def reject_limit(_actor):
        raise services.VibeHubError(
            "VibeHub 作品数不能超过 2",
            status_code=409,
            code="projects_quota_exceeded",
        )

    monkeypatch.setattr(services, "preflight_create_project", reject_limit)
    body, content_type = _multipart_body()
    response = app.test_client().post(
        "/api/vibehub/projects",
        data=body,
        content_type=content_type,
    )

    assert response.status_code == 409
    assert response.get_json()["code"] == "projects_quota_exceeded"
    assert not (tmp_path / ".staging").exists()


@pytest.mark.parametrize(
    ("preflight_error", "expected_code"),
    [
        (services.VibeHubPermissionError(), "forbidden"),
        (
            services.VibeHubError(
                "VibeHub 作品版本数不能超过 1000",
                status_code=409,
                code="versions_quota_exceeded",
            ),
            "versions_quota_exceeded",
        ),
    ],
)
def test_upload_api_rejects_owner_or_version_preflight_before_multipart(
    tmp_path,
    monkeypatch,
    preflight_error,
    expected_code,
):
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        VIBEHUB_UPLOAD_ROOT=tmp_path,
    )
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: USER)
    monkeypatch.setattr(Request, "_load_form_data", _forbid_multipart_parse)

    def reject_preflight(_actor, _slug):
        raise preflight_error

    monkeypatch.setattr(services, "preflight_upload_project", reject_preflight)
    body, content_type = _multipart_body()
    response = app.test_client().post(
        "/api/vibehub/projects/demo-vibe/versions",
        data=body,
        content_type=content_type,
    )

    assert response.status_code == preflight_error.status_code
    assert response.get_json()["code"] == expected_code
    assert not (tmp_path / ".staging").exists()


def test_patch_rejects_version_cap_before_parsing_form(tmp_path, monkeypatch):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test", VIBEHUB_UPLOAD_ROOT=tmp_path)
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: USER)
    monkeypatch.setattr(Request, "_load_form_data", _forbid_multipart_parse)

    def reject_version(_actor, _slug):
        raise services.VibeHubError(
            "VibeHub 作品版本数不能超过 1000",
            status_code=409,
            code="versions_quota_exceeded",
        )

    monkeypatch.setattr(services, "preflight_upload_project", reject_version)
    body, content_type = _multipart_body()
    response = app.test_client().patch(
        "/api/vibehub/projects/demo-vibe",
        data=body,
        content_type=content_type,
    )

    assert response.status_code == 409
    assert response.get_json()["code"] == "versions_quota_exceeded"
    assert not (tmp_path / ".staging").exists()


def test_third_storage_mutation_request_fails_fast_before_db_or_body(
    tmp_path,
    monkeypatch,
):
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        VIBEHUB_UPLOAD_ROOT=tmp_path,
        VIBEHUB_STORAGE_MUTATION_SLOTS=2,
        VIBEHUB_STORAGE_MUTATION_SLOT_WAIT_SECONDS=0,
    )
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: USER)
    monkeypatch.setattr(
        services,
        "preflight_create_project",
        lambda _actor: pytest.fail("第三个请求不应进入 DB 预检"),
    )
    monkeypatch.setattr(Request, "_load_form_data", _forbid_multipart_parse)
    body, content_type = _multipart_body()

    started = time.monotonic()
    with quotas.storage_mutation_capacity_slot(tmp_path, slots=2, wait_seconds=0):
        with quotas.storage_mutation_capacity_slot(tmp_path, slots=2, wait_seconds=0):
            response = app.test_client().post(
                "/api/vibehub/projects",
                data=body,
                content_type=content_type,
            )
    elapsed = time.monotonic() - started

    assert response.status_code == 429
    assert elapsed < 0.5
    assert response.headers["Retry-After"] == "1"
    assert response.get_json()["code"] == "storage_mutation_capacity_exceeded"


def test_every_storage_mutation_route_uses_one_shared_gate_before_preflight_and_service(
    tmp_path,
    monkeypatch,
):
    route_functions = (
        vibehub_api.create_project,
        vibehub_api.upload_version,
        vibehub_api.edit_project,
        vibehub_api.review_project,
    )
    for function in route_functions:
        source = inspect.getsource(function)
        assert source.count("with _storage_mutation_request_slot():") == 1

    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test", VIBEHUB_UPLOAD_ROOT=tmp_path)
    active = [False]
    gate_entries = []
    current_actor = [USER]
    db_checks = []

    @contextmanager
    def checked_gate():
        assert active[0] is False, "同一请求不得嵌套取得持久变更槽"
        active[0] = True
        gate_entries.append(True)
        try:
            yield
        finally:
            active[0] = False

    def assert_db_preflight(*_args, **_kwargs):
        assert active[0] is True
        db_checks.append("preflight")

    def assert_service(*_args, **_kwargs):
        assert active[0] is True
        db_checks.append("service-open-db")
        if "expected_version" in _kwargs:
            assert _kwargs["expected_version"] == 3
        return {"id": 1}

    def assert_payload():
        assert active[0] is True
        return {
            "decision": "approve",
            "expected_version": 3,
        }

    def assert_upload():
        assert active[0] is True
        return object()

    def assert_admin_preflight(_actor):
        # 管理员身份检查不访问 DB/body，因此先于容量槽。
        assert active[0] is False

    monkeypatch.setattr(vibehub_api, "current_user", lambda: current_actor[0])
    monkeypatch.setattr(
        vibehub_api,
        "_storage_mutation_request_slot",
        checked_gate,
    )
    monkeypatch.setattr(vibehub_api, "_payload", assert_payload)
    monkeypatch.setattr(vibehub_api, "_uploaded_package", assert_upload)
    monkeypatch.setattr(services, "preflight_create_project", assert_db_preflight)
    monkeypatch.setattr(services, "preflight_upload_project", assert_db_preflight)
    monkeypatch.setattr(services, "preflight_admin", assert_admin_preflight)
    monkeypatch.setattr(services, "create_project", assert_service)
    monkeypatch.setattr(services, "upload_new_version", assert_service)
    monkeypatch.setattr(services, "edit_project", assert_service)
    monkeypatch.setattr(services, "review_submission", assert_service)

    with app.test_request_context("/api/vibehub/projects", method="POST"):
        vibehub_api.create_project()
    with app.test_request_context(
        "/api/vibehub/projects/demo-vibe/versions",
        method="POST",
    ):
        vibehub_api.upload_version("demo-vibe")
    with app.test_request_context(
        "/api/vibehub/projects/demo-vibe",
        method="PATCH",
    ):
        vibehub_api.edit_project("demo-vibe")
    current_actor[0] = ADMIN
    with app.test_request_context(
        "/api/vibehub/admin/reviews/demo-vibe",
        method="POST",
    ):
        vibehub_api.review_project("demo-vibe")

    assert gate_entries == [True] * 4
    assert db_checks.count("preflight") == 3
    assert db_checks.count("service-open-db") == 4
    assert active[0] is False


def test_missing_package_releases_real_parse_slot(tmp_path, monkeypatch):
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        VIBEHUB_UPLOAD_ROOT=tmp_path,
        VIBEHUB_STORAGE_MUTATION_SLOTS=1,
        VIBEHUB_STORAGE_MUTATION_SLOT_WAIT_SECONDS=0,
    )
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: USER)
    monkeypatch.setattr(services, "preflight_create_project", lambda _actor: None)

    response = app.test_client().post(
        "/api/vibehub/projects",
        data={"title": "missing package"},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "ZIP" in response.get_json()["message"]
    with quotas.multipart_parse_slot(tmp_path, slots=1, wait_seconds=0) as slot:
        assert slot == 0


def test_route_closes_every_parsed_upload_before_releasing_slot(tmp_path, monkeypatch):
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        VIBEHUB_UPLOAD_ROOT=tmp_path,
    )
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, "current_user", lambda: USER)
    monkeypatch.setattr(services, "preflight_create_project", lambda _actor: None)

    class UploadSpy:
        filename = "package.zip"

        def __init__(self):
            self.close_calls = 0

        def close(self):
            self.close_calls += 1

    first = UploadSpy()
    second = UploadSpy()
    calls_at_release = []

    def uploaded_package():
        request._get_current_object().__dict__["files"] = MultiDict(
            [("package", first), ("duplicate", first), ("extra", second)]
        )
        return first

    @contextmanager
    def checked_slot(*_args, **_kwargs):
        try:
            yield 0
        finally:
            calls_at_release.append((first.close_calls, second.close_calls))
            assert first.close_calls == 1
            assert second.close_calls == 1

    monkeypatch.setattr(vibehub_api, "_uploaded_package", uploaded_package)
    monkeypatch.setattr(vibehub_api, "_payload", lambda: {})
    monkeypatch.setattr(quotas, "storage_mutation_capacity_slot", checked_slot)
    monkeypatch.setattr(
        services,
        "create_project",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            services.VibeHubError("stop", code="stop")
        ),
    )

    response = app.test_client().post("/api/vibehub/projects")

    assert response.status_code == 400
    assert response.get_json()["code"] == "stop"
    assert calls_at_release == [(1, 1)]
    # Flask teardown 会再次幂等关闭；关键是在 slot finally 观察到 1。
    assert first.close_calls >= 1
    assert second.close_calls >= 1


def test_api_serves_the_tracked_developer_guide():
    app = Flask(__name__)
    app.register_blueprint(vibehub_api.vibehub_api_bp)

    response = app.test_client().get("/api/vibehub/developer-guide")

    assert response.status_code == 200
    assert response.mimetype == "text/markdown"
    guide = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "vibehub-developer-guide.md"
    ).read_bytes()
    assert response.get_data() == guide
    assert b"/api/vibehub/" not in guide
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-cache, max-age=0"
    assert "vibehub-developer-guide.md" in response.headers["Content-Disposition"]


def test_schema_contains_vibehub_project_and_immutable_version_tables():
    sql = (Path(__file__).resolve().parents[2] / "database" / "bootstrap.sql").read_text(encoding="utf-8")

    assert "CREATE TABLE `vibehub_projects`" in sql
    assert "CREATE TABLE `vibehub_versions`" in sql
    assert "UNIQUE KEY `uq_vibehub_versions_project_number`" in sql
    assert "`review_version_id` bigint unsigned" in sql
    assert "`last_reviewed_version_id` bigint unsigned" in sql
