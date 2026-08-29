"""VibeHub 内置示例通过普通发布流程幂等同步。"""

import hashlib
import os
import subprocess
import zipfile

import pytest

from deploy import seed_vibehub_examples as seed


ADMIN = {"id": 4, "username": "admin", "is_admin": 1}


def test_load_state_parameterizes_every_example_slug(monkeypatch):
    calls = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, params):
            calls.append((" ".join(query.split()), params))

        def fetchone(self):
            return dict(ADMIN)

        def fetchall(self):
            return []

    class Connection:
        closed = False

        def cursor(self):
            return Cursor()

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(seed, "get_db_connection", lambda: connection)

    admin, projects = seed._load_state()

    assert admin == ADMIN
    assert projects == {}
    assert connection.closed is True
    project_query, project_params = calls[1]
    placeholders = ", ".join("%s" for _ in seed.EXAMPLE_SLUGS)
    assert f"WHERE p.slug IN ({placeholders})" in project_query
    assert project_params == seed.EXAMPLE_SLUGS
    assert project_query.count("%s") == len(seed.EXAMPLE_SLUGS)
    assert all(slug not in project_query for slug in seed.EXAMPLE_SLUGS)


def test_seed_uses_normal_publish_and_direct_featured_setting(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(seed, "_load_state", lambda: (ADMIN, {}))
    monkeypatch.setattr(seed, "_validated_arc_set", lambda path: path)
    monkeypatch.setattr(
        seed,
        "_write_package",
        lambda package, *_args: package.write(b"example zip"),
    )
    monkeypatch.setattr(
        seed,
        "_remove_legacy_storage",
        lambda _root, slug: calls.append(("remove", slug)),
    )

    def create(actor, package, metadata, **kwargs):
        calls.append(("create", actor, package.read(), metadata, kwargs))
        return {"latest_version": 1}

    monkeypatch.setattr(seed.services, "create_project", create)
    monkeypatch.setattr(
        seed.services,
        "review_submission",
        lambda *args, **kwargs: calls.append(("review", args, kwargs)),
    )
    monkeypatch.setattr(
        seed.services,
        "set_featured",
        lambda *args, **kwargs: calls.append(("set_featured", args, kwargs)),
    )

    result = seed.seed_examples(tmp_path, tmp_path / "uploads", tmp_path / "arc")

    assert result == [f"{slug}: created" for slug in seed.EXAMPLE_SLUGS]
    assert [call[0] for call in calls] == [
        action
        for _slug in seed.EXAMPLE_SLUGS
        for action in ("remove", "create", "review", "set_featured")
    ]
    for index, slug in enumerate(seed.EXAMPLE_SLUGS):
        offset = index * 4
        assert calls[offset + 1][1] == ADMIN
        assert calls[offset + 2][2]["expected_version"] == 1
        assert calls[offset + 3][1] == (ADMIN, slug, True)


def test_existing_admin_projects_with_same_package_are_unchanged(tmp_path, monkeypatch):
    package_bytes = b"example zip"
    package_sha256 = hashlib.sha256(package_bytes).hexdigest()
    projects = {
        slug: {
            "owner_id": ADMIN["id"],
            "public_version_id": 10 + index,
            "public_package_sha256": package_sha256,
        }
        for index, slug in enumerate(seed.EXAMPLE_SLUGS)
    }
    monkeypatch.setattr(seed, "_load_state", lambda: (ADMIN, projects))
    monkeypatch.setattr(seed, "_validated_arc_set", lambda path: path)
    monkeypatch.setattr(
        seed,
        "_write_package",
        lambda package, *_args: package.write(package_bytes),
    )
    monkeypatch.setattr(
        seed.services,
        "create_project",
        lambda *_args, **_kwargs: pytest.fail("已有作品不得被部署覆盖"),
    )
    monkeypatch.setattr(
        seed.services,
        "upload_new_version",
        lambda *_args, **_kwargs: pytest.fail("相同内容不得重复升版"),
    )
    removed = []
    ensured = []
    monkeypatch.setattr(
        seed,
        "_remove_legacy_storage",
        lambda _root, slug: removed.append(slug),
    )
    monkeypatch.setattr(
        seed,
        "_ensure_existing_images",
        lambda actor, slug, root: ensured.append((actor, slug, root)),
    )

    result = seed.seed_examples(tmp_path, tmp_path / "uploads", tmp_path / "arc")

    assert result == [f"{slug}: unchanged" for slug in seed.EXAMPLE_SLUGS]
    assert removed == list(seed.EXAMPLE_SLUGS)
    assert ensured == [
        (ADMIN, slug, tmp_path / "uploads") for slug in seed.EXAMPLE_SLUGS
    ]


def test_ensure_existing_images_builds_latest_and_restores_public_alias(
    tmp_path, monkeypatch,
):
    calls = []

    class Manager:
        def build_channel_image(self, slug, app_dir, **kwargs):
            calls.append(("build", slug, app_dir, kwargs))

        def promote_latest_to_public(self, slug, **kwargs):
            calls.append(("promote", slug, kwargs))

    package = {
        "slug": "arc-agi-3",
        "version": 4,
        "package_sha256": "a" * 64,
        "featured": True,
    }
    monkeypatch.setattr(
        seed.services,
        "resolve_project_package",
        lambda *_args, **_kwargs: dict(package),
    )
    monkeypatch.setattr(seed, "get_runtime_manager", lambda: Manager())
    monkeypatch.setattr(
        seed.storage,
        "resolve_snapshot_app",
        lambda slug, version, **_kwargs: tmp_path / slug / str(version) / "app",
    )

    seed._ensure_existing_images(ADMIN, "arc-agi-3", tmp_path / "uploads")

    assert calls == [
        (
            "build",
            "arc-agi-3",
            tmp_path / "arc-agi-3" / "4" / "app",
            {
                "channel": "latest",
                "package_digest": "a" * 64,
                "featured": True,
            },
        ),
        ("promote", "arc-agi-3", {"package_digest": "a" * 64}),
    ]


def test_existing_admin_project_is_published_when_package_changes(tmp_path, monkeypatch):
    projects = {
        slug: {
            "owner_id": ADMIN["id"],
            "public_version_id": 10 + index,
            "public_package_sha256": "0" * 64,
        }
        for index, slug in enumerate(seed.EXAMPLE_SLUGS)
    }
    calls = []
    monkeypatch.setattr(seed, "_load_state", lambda: (ADMIN, projects))
    monkeypatch.setattr(seed, "_validated_arc_set", lambda path: path)
    monkeypatch.setattr(
        seed,
        "_write_package",
        lambda package, _root, slug, _arc: package.write(slug.encode()),
    )
    monkeypatch.setattr(seed, "_remove_legacy_storage", lambda *_args: None)

    def upload(actor, slug, package, metadata, **kwargs):
        calls.append(("upload", actor, slug, package.read(), metadata, kwargs))
        return {"latest_version": 20 + len(calls)}

    monkeypatch.setattr(seed.services, "upload_new_version", upload)
    monkeypatch.setattr(
        seed.services,
        "review_submission",
        lambda *args, **kwargs: calls.append(("review", args, kwargs)),
    )
    monkeypatch.setattr(
        seed.services,
        "create_project",
        lambda *_args, **_kwargs: pytest.fail("已有作品不得重新创建"),
    )

    result = seed.seed_examples(tmp_path, tmp_path / "uploads", tmp_path / "arc")

    assert result == [f"{slug}: updated" for slug in seed.EXAMPLE_SLUGS]
    assert [call[0] for call in calls] == [
        action
        for _slug in seed.EXAMPLE_SLUGS
        for action in ("upload", "review")
    ]
    for index, slug in enumerate(seed.EXAMPLE_SLUGS):
        upload_call = calls[index * 2]
        review_call = calls[index * 2 + 1]
        assert upload_call[1] == ADMIN
        assert upload_call[2] == slug
        assert upload_call[4] == {}
        assert review_call[1][1] == slug
        assert review_call[2]["expected_version"] == 21 + index * 2


def test_deterministic_package_ignores_unrelated_commit_timestamp(tmp_path):
    repository = tmp_path / "repo"
    example = repository / "vibehub_examples" / "circle-cat"
    example.mkdir(parents=True)
    (example / "vibehub.json").write_text('{"title":"example"}', encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(repository), "-c", "user.name=Test",
            "-c", "user.email=test@example.com", "commit", "-qm", "first",
        ],
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z",
        },
    )
    first_path = tmp_path / "first.zip"
    with first_path.open("w+b") as first:
        seed._write_package(first, repository, "circle-cat", tmp_path / "unused")

    (repository / "unrelated.txt").write_text("new commit", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "unrelated.txt"], check=True)
    subprocess.run(
        [
            "git", "-C", str(repository), "-c", "user.name=Test",
            "-c", "user.email=test@example.com", "commit", "-qm", "second",
        ],
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_DATE": "2024-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2024-01-01T00:00:00Z",
        },
    )
    second_path = tmp_path / "second.zip"
    with second_path.open("w+b") as second:
        seed._write_package(second, repository, "circle-cat", tmp_path / "unused")

    assert first_path.read_bytes() == second_path.read_bytes()
    with zipfile.ZipFile(second_path) as archive:
        assert archive.getinfo("vibehub.json").date_time == seed.DETERMINISTIC_ZIP_DATE_TIME


def test_seed_fails_closed_when_slug_belongs_to_another_user(tmp_path, monkeypatch):
    monkeypatch.setattr(
        seed,
        "_load_state",
        lambda: (ADMIN, {"circle-cat": {"owner_id": 99}}),
    )
    monkeypatch.setattr(seed, "_validated_arc_set", lambda path: path)

    with pytest.raises(seed.ExampleSeedError, match="circle-cat"):
        seed.seed_examples(tmp_path, tmp_path / "uploads", tmp_path / "arc")


def test_seed_fails_closed_after_a_partial_first_publish(tmp_path, monkeypatch):
    monkeypatch.setattr(
        seed,
        "_load_state",
        lambda: (ADMIN, {"circle-cat": {"owner_id": ADMIN["id"], "public_version_id": None}}),
    )
    monkeypatch.setattr(seed, "_validated_arc_set", lambda path: path)

    with pytest.raises(seed.ExampleSeedError, match="尚未完成首次发布"):
        seed.seed_examples(tmp_path, tmp_path / "uploads", tmp_path / "arc")


def test_seed_fails_closed_when_public_hash_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        seed,
        "_load_state",
        lambda: (
            ADMIN,
            {
                "circle-cat": {
                    "owner_id": ADMIN["id"],
                    "public_version_id": 10,
                    "public_package_sha256": None,
                }
            },
        ),
    )
    monkeypatch.setattr(seed, "_validated_arc_set", lambda path: path)

    with pytest.raises(seed.ExampleSeedError, match="公开版本缺少有效内容哈希"):
        seed.seed_examples(tmp_path, tmp_path / "uploads", tmp_path / "arc")


def test_legacy_directory_cleanup_rejects_symlink(tmp_path):
    upload_root = tmp_path / "uploads"
    project = upload_root / "circle-cat"
    project.mkdir(parents=True)
    (project / "builtin").symlink_to(tmp_path)

    with pytest.raises(seed.ExampleSeedError, match="目录结构异常"):
        seed._remove_legacy_storage(upload_root, "circle-cat")
