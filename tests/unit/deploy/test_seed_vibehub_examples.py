"""VibeHub 示例只首次种入普通 admin 作品。"""

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
        assert call[4]["submit_for_review"] is True
    assert calls[2][2]["expected_version"] == 1


def test_existing_admin_projects_are_not_overwritten(tmp_path, monkeypatch):
    projects = {
        slug: {"owner_id": ADMIN["id"], "public_version_id": 10 + index}
        for index, slug in enumerate(seed.EXAMPLE_SLUGS)
    }
    monkeypatch.setattr(seed, "_load_state", lambda: (ADMIN, projects))
    monkeypatch.setattr(seed, "_validated_arc_set", lambda path: path)
    monkeypatch.setattr(
        seed.services,
        "create_project",
        lambda *_args, **_kwargs: pytest.fail("已有作品不得被部署覆盖"),
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


def test_legacy_directory_cleanup_rejects_symlink(tmp_path):
    upload_root = tmp_path / "uploads"
    project = upload_root / "circle-cat"
    project.mkdir(parents=True)
    (project / "builtin").symlink_to(tmp_path)

    with pytest.raises(seed.ExampleSeedError, match="目录结构异常"):
        seed._remove_legacy_storage(upload_root, "circle-cat")
