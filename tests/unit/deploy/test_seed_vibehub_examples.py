"""VibeHub 内置示例通过普通发布流程幂等同步。"""

import hashlib
import os
import subprocess
import zipfile

import pytest

from deploy import seed_vibehub_examples as seed


ADMIN = {"id": 4, "username": "admin", "is_admin": 1}


def test_seed_uses_normal_publish_and_featured_workflow(tmp_path, monkeypatch):
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
        "request_featured",
        lambda *args, **kwargs: calls.append(("request_featured", args, kwargs)),
    )
    monkeypatch.setattr(
        seed.services,
        "review_featured",
        lambda *args, **kwargs: calls.append(("review_featured", args, kwargs)),
    )

    result = seed.seed_examples(tmp_path, tmp_path / "uploads", tmp_path / "arc")

    assert result == ["circle-cat: created", "arc-agi-3: created"]
    assert [call[0] for call in calls] == [
        "remove", "create", "review", "request_featured", "review_featured",
        "remove", "create", "review", "request_featured", "review_featured",
    ]
    for call in (calls[1], calls[6]):
        assert call[1] == ADMIN
    assert calls[2][2]["expected_version"] == 1


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
    monkeypatch.setattr(
        seed,
        "_remove_legacy_storage",
        lambda _root, slug: removed.append(slug),
    )

    result = seed.seed_examples(tmp_path, tmp_path / "uploads", tmp_path / "arc")

    assert result == ["circle-cat: unchanged", "arc-agi-3: unchanged"]
    assert removed == list(seed.EXAMPLE_SLUGS)


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

    assert result == ["circle-cat: updated", "arc-agi-3: updated"]
    assert [call[0] for call in calls] == ["upload", "review", "upload", "review"]
    for upload_call in (calls[0], calls[2]):
        assert upload_call[1] == ADMIN
        assert upload_call[4] == {}
    assert calls[1][2]["expected_version"] == 21
    assert calls[3][2]["expected_version"] == 23


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
