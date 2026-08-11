#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""首次部署时把示例种入 admin 的普通 VibeHub 作品。"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.prepare_arc_agi_3 import ArcPublicSetError, _validate_cached_set
from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.vibehub import services


EXAMPLE_SLUGS = ("circle-cat", "arc-agi-3")
EXPECTED_ARC_GAME_COUNT = 25


class ExampleSeedError(RuntimeError):
    """示例不能安全种入。"""


def _load_state() -> tuple[dict, dict[str, dict]]:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, username, is_admin FROM users WHERE username = %s",
                ("admin",),
            )
            admin = cursor.fetchone()
            cursor.execute(
                """SELECT slug, owner_id, public_version_id
                FROM vibehub_projects WHERE slug IN (%s, %s)""",
                EXAMPLE_SLUGS,
            )
            projects = {row["slug"]: row for row in (cursor.fetchall() or [])}
    finally:
        conn.close()
    if not admin or int(admin.get("is_admin") or 0) != 1:
        raise ExampleSeedError("缺少 username=admin 的管理员账号")
    return admin, projects


def _validated_arc_set(arc_set: Path) -> Path:
    try:
        source = arc_set.resolve(strict=True)
        _validate_cached_set(source, EXPECTED_ARC_GAME_COUNT)
    except (OSError, ArcPublicSetError) as exc:
        raise ExampleSeedError(f"ARC-AGI-3 官方离线集校验失败：{exc}") from exc
    return source


def _append_arc_data(package, source: Path) -> None:
    package.seek(0, 2)
    with zipfile.ZipFile(package, "a", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, Path("offline_data") / path.relative_to(source))


def _write_package(package, repository_root: Path, slug: str, arc_set: Path) -> None:
    source = f"HEAD:vibehub_examples/{slug}"
    subprocess.run(
        ["git", "-C", str(repository_root), "archive", "--format=zip", source],
        check=True,
        stdout=package,
    )
    if slug == "arc-agi-3":
        _append_arc_data(package, arc_set)
    package.seek(0)


def _remove_legacy_storage(upload_root: Path, slug: str) -> None:
    legacy = upload_root / slug / "builtin"
    try:
        metadata = legacy.lstat()
    except FileNotFoundError:
        return
    project_root = legacy.parent
    expected = upload_root.resolve(strict=True) / slug
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or project_root.resolve(strict=True) != expected
    ):
        raise ExampleSeedError(f"旧 VibeHub 示例目录结构异常：{legacy}")
    shutil.rmtree(legacy)


def seed_examples(repository_root: Path, upload_root: Path, arc_set: Path) -> list[str]:
    admin, projects = _load_state()
    arc_set = _validated_arc_set(arc_set)
    for slug, existing in projects.items():
        if int(existing.get("owner_id") or 0) != int(admin["id"]):
            raise ExampleSeedError(f"slug {slug} 不属于 admin")
        if not existing.get("public_version_id"):
            raise ExampleSeedError(f"slug {slug} 已存在但尚未完成首次发布")

    results = []
    with ExitStack() as stack:
        packages = {}
        for slug in EXAMPLE_SLUGS:
            if slug not in projects:
                package = stack.enter_context(tempfile.TemporaryFile())
                _write_package(package, repository_root, slug, arc_set)
                packages[slug] = package

        for slug in EXAMPLE_SLUGS:
            _remove_legacy_storage(upload_root, slug)
            if slug in projects:
                status = "unchanged"
            else:
                created = services.create_project(
                    admin,
                    packages[slug],
                    {"slug": slug},
                    upload_root=upload_root,
                    submit_for_review=True,
                )
                services.review_submission(
                    admin,
                    slug,
                    "approve",
                    expected_version=created["latest_version"],
                    upload_root=upload_root,
                )
                services.request_featured(admin, slug)
                services.review_featured(admin, slug, "approve")
                status = "created"
            results.append(f"{slug}: {status}")
    return results


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="种入 admin 的 VibeHub 示例作品。")
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--upload-root", type=Path, default=ROOT / "uploads/vibehub")
    parser.add_argument("--arc-set", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        for result in seed_examples(
            args.repository_root.resolve(strict=True),
            args.upload_root,
            args.arc_set,
        ):
            print(f"VibeHub 示例 {result}")
    except (
        ExampleSeedError,
        services.VibeHubError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"VibeHub 示例种入失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
