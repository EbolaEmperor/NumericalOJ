"""VibeHub 作品、不可变版本与审核流程。"""

from __future__ import annotations

import json
from pathlib import Path
import re
import secrets

from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.vibehub import quotas, storage
from oj_modules.vibehub.runtime import get_runtime_manager


SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
MAX_TITLE_LENGTH = 120
MAX_SUMMARY_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 10_000
MAX_TAGS = 8
MAX_TAG_LENGTH = 24

# 这些字段描述作者尚未公开的工作流，不能进入通用公开响应。公开版本本身的
# 版本号与精品展示结果是公开事实；草稿版本号、审核队列状态、审核意见和
# project.updated_at 则会泄露尚未发布的编辑活动。
_PRIVATE_WORKFLOW_FIELDS = frozenset(
    {
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
        "review_requested_at",
        "updated_at",
    }
)


class VibeHubError(RuntimeError):
    """可安全返回给用户的 VibeHub 业务错误。"""

    def __init__(self, message: str, *, status_code: int = 400, code: str = "invalid_request"):
        self.status_code = int(status_code)
        self.code = str(code)
        super().__init__(str(message))


class VibeHubNotFoundError(VibeHubError):
    def __init__(self, message="VibeHub 作品不存在"):
        super().__init__(message, status_code=404, code="not_found")


class VibeHubPermissionError(VibeHubError):
    def __init__(self, message="无权操作该 VibeHub 作品"):
        super().__init__(message, status_code=403, code="forbidden")


def _prepare_latest_image(
    project_key: str,
    app_dir: Path,
    *,
    package_digest: str,
    featured=False,
):
    manager = get_runtime_manager()
    previous_image_id = None
    captured = False
    try:
        previous_image_id = manager.capture_image_tag(project_key, channel="latest")
        captured = True
        manager.build_latest_image(
            project_key,
            app_dir,
            package_digest=package_digest,
            featured=featured,
        )
    except RuntimeError as exc:
        if captured:
            _restore_image_tag(project_key, "latest", previous_image_id)
        raise VibeHubError(
            "作品镜像构建失败，请稍后重试",
            status_code=503,
            code="image_build_failed",
        ) from exc
    return previous_image_id


def _promote_latest_image(project_key: str, package_digest: str):
    try:
        return get_runtime_manager().promote_latest_to_public(
            project_key, package_digest=package_digest,
        )
    except RuntimeError as exc:
        raise VibeHubError(
            "作品发布镜像不可用，请稍后重试",
            status_code=503,
            code="image_publish_failed",
        ) from exc


def _restore_image_tag(project_key: str, channel: str, image_id: str | None):
    try:
        get_runtime_manager().restore_image_tag(
            project_key, channel=channel, image_id=image_id,
        )
    except RuntimeError as exc:
        raise VibeHubError(
            "作品镜像状态恢复失败，请联系管理员",
            status_code=503,
            code="image_restore_failed",
        ) from exc


_PROJECT_SELECT = """
SELECT
    p.id, p.slug, p.owner_id,
    p.latest_version_id, p.public_version_id, p.review_version_id,
    p.last_reviewed_version_id,
    p.is_featured,
    p.created_at, p.updated_at,
    u.username AS owner_username,
    lv.version_number AS latest_version,
    lv.title AS latest_title,
    lv.summary AS latest_summary,
    lv.description AS latest_description,
    lv.tags_json AS latest_tags_json,
    lv.cover_image AS latest_cover_image,
    lv.review_status AS latest_review_status,
    lv.review_note AS latest_review_note,
    lv.created_at AS latest_version_created_at,
    pv.version_number AS public_version,
    pv.title AS public_title,
    pv.summary AS public_summary,
    pv.description AS public_description,
    pv.tags_json AS public_tags_json,
    pv.cover_image AS public_cover_image,
    pv.review_status AS public_review_status,
    pv.review_note AS public_review_note,
    pv.reviewed_at AS public_reviewed_at,
    rv.version_number AS submitted_version,
    rv.title AS review_title,
    rv.summary AS review_summary,
    rv.description AS review_description,
    rv.tags_json AS review_tags_json,
    rv.cover_image AS review_cover_image,
    rv.review_status AS review_review_status,
    rv.review_note AS review_review_note,
    rv.review_requested_at AS review_requested_at,
    xv.version_number AS last_reviewed_version,
    xv.review_status AS last_review_status,
    xv.review_note AS last_review_note
FROM vibehub_projects p
LEFT JOIN users u ON u.id = p.owner_id
LEFT JOIN vibehub_versions lv ON lv.id = p.latest_version_id
LEFT JOIN vibehub_versions pv ON pv.id = p.public_version_id
LEFT JOIN vibehub_versions rv ON rv.id = p.review_version_id
LEFT JOIN vibehub_versions xv ON xv.id = p.last_reviewed_version_id
"""


def _is_admin(actor) -> bool:
    return bool(actor and int(actor.get("is_admin") or 0) == 1)


def _actor_id(actor) -> int:
    try:
        return int(actor.get("id"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise VibeHubPermissionError("请先登录") from exc


def _owns(project, actor) -> bool:
    if not actor:
        return False
    try:
        return int(project.get("owner_id")) == int(actor.get("id"))
    except (TypeError, ValueError):
        return False


def _require_owner(project, actor) -> None:
    # 管理员权限只用于独立的审核入口，不能冒充作者改写或直接发布他人的作品。
    if not _owns(project, actor):
        raise VibeHubPermissionError()


def _require_admin(actor) -> None:
    if not _is_admin(actor):
        raise VibeHubPermissionError("仅管理员可执行该操作")


def _clean_text(value, *, field: str, limit: int, required=False) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise VibeHubError(f"{field} 不能为空")
    if len(text) > int(limit):
        raise VibeHubError(f"{field} 不能超过 {limit} 个字符")
    return text


def _normalize_tags(value) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                raise VibeHubError("tags 必须是 JSON 数组或逗号分隔文本") from exc
        else:
            value = text.split(",")
    if not isinstance(value, (list, tuple)):
        raise VibeHubError("tags 必须是字符串数组")
    tags = []
    seen = set()
    for raw in value:
        tag = _clean_text(raw, field="tag", limit=MAX_TAG_LENGTH)
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    if len(tags) > MAX_TAGS:
        raise VibeHubError(f"tags 最多只能包含 {MAX_TAGS} 项")
    return tags


def _normalize_cover(value, app_dir: Path) -> tuple[str | None, str | None]:
    try:
        return storage.validate_cover_image(value, app_dir)
    except storage.PackageValidationError as exc:
        raise VibeHubError(str(exc)) from exc


def _metadata(
    payload,
    *,
    base=None,
    manifest=None,
    app_dir: Path,
    package_replaced=False,
) -> dict:
    payload = dict(payload or {})
    base = dict(base or {})
    manifest = dict(manifest or {})

    def choose(name, default=""):
        if name in payload and payload[name] is not None:
            return payload[name]
        if name in base:
            return base.get(name)
        return manifest.get(name, default)

    title = _clean_text(
        choose("title"),
        field="title",
        limit=MAX_TITLE_LENGTH,
        required=True,
    )
    summary = _clean_text(
        choose("summary"), field="summary", limit=MAX_SUMMARY_LENGTH,
    )
    description = _clean_text(
        choose("description"), field="description", limit=MAX_DESCRIPTION_LENGTH,
    )
    tags_value = choose("tags", [])
    if "cover_image" in payload:
        cover_value = payload.get("cover_image")
    elif package_replaced:
        # 新包的 manifest 封面优先于旧版本；否则旧路径可能
        # 在新包中不存在，或意外覆盖开发者的新封面。
        cover_value = manifest.get("cover_image")
    elif "cover_image" in base:
        cover_value = base.get("cover_image")
    else:
        cover_value = manifest.get("cover_image")
    cover_image, cover_image_mime = _normalize_cover(cover_value, app_dir)
    return {
        "title": title,
        "summary": summary,
        "description": description,
        "tags": _normalize_tags(tags_value),
        "cover_image": cover_image,
        "cover_image_mime": cover_image_mime,
    }


def _requested_slug(value=None) -> str:
    if value in (None, ""):
        return f"vibe-{secrets.token_hex(8)}"
    slug = str(value).strip().lower()
    if not SLUG_RE.fullmatch(slug):
        raise VibeHubError("slug 只能包含小写字母、数字和连字符，长度为 3–63")
    return slug


def _decode_tags(value) -> list[str]:
    try:
        tags = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    return [str(tag) for tag in tags] if isinstance(tags, list) else []


def _without_private_workflow(project: dict) -> dict:
    """返回不含草稿、审核和申请侧信道的公开项目副本。"""

    public = dict(project)
    for field in _PRIVATE_WORKFLOW_FIELDS:
        public.pop(field, None)
    return public


def _serialize_project(row, *, audience: str, include_workflow=False) -> dict:
    prefix = {"latest": "latest", "public": "public", "review": "review"}[audience]
    selected_version = row.get(
        {"latest": "latest_version", "public": "public_version", "review": "submitted_version"}[audience]
    )
    cover_image = row.get(f"{prefix}_cover_image")
    slug = row.get("slug")
    if audience == "latest":
        play_url = f"/vibehub/{slug}/play?channel=latest"
    elif audience == "review":
        play_url = f"/vibehub/{slug}/play?channel=review"
    else:
        play_url = f"/vibehub/{slug}/play" if row.get("public_version_id") else None
    project = {
        "id": row.get("id"),
        "slug": slug,
        "title": row.get(f"{prefix}_title") or "",
        "summary": row.get(f"{prefix}_summary") or "",
        "description": row.get(f"{prefix}_description") or "",
        "owner_username": row.get("owner_username") or "",
        "latest_version": row.get("latest_version"),
        "public_version": row.get("public_version"),
        "submitted_version": row.get("submitted_version"),
        "has_pending_review": bool(row.get("review_version_id")),
        "selected_version": selected_version,
        "review_status": row.get(f"{prefix}_review_status") or "draft",
        "latest_review_status": row.get("latest_review_status") or "draft",
        "review_note": row.get(f"{prefix}_review_note"),
        "latest_review_note": row.get("latest_review_note"),
        "last_reviewed_version": row.get("last_reviewed_version"),
        "last_review_status": row.get("last_review_status"),
        "last_review_note": row.get("last_review_note"),
        "is_featured": bool(row.get("is_featured")),
        "visibility": "public" if row.get("public_version_id") else "private",
        "cover_image": cover_image,
        "cover_url": (
            f"/api/vibehub/projects/{slug}/cover?view={audience}&v={selected_version}"
            if cover_image else None
        ),
        "tags": _decode_tags(row.get(f"{prefix}_tags_json")),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "review_requested_at": row.get("review_requested_at"),
        "play_url": play_url,
    }
    if audience == "public" and not include_workflow:
        return _without_private_workflow(project)
    return project


def _fetch_project_row(cursor, slug: str):
    cursor.execute(_PROJECT_SELECT + " WHERE p.slug = %s", (slug,))
    return cursor.fetchone()


def _fetch_core_for_update(cursor, slug: str):
    cursor.execute(
        """
        SELECT id, slug, owner_id, latest_version_id,
               public_version_id, review_version_id, last_reviewed_version_id,
               is_featured
        FROM vibehub_projects
        WHERE slug = %s
        FOR UPDATE
        """,
        (slug,),
    )
    row = cursor.fetchone()
    if not row:
        raise VibeHubNotFoundError()
    return row


def _lock_owner_and_list_slugs(cursor, owner_id: int) -> list[str]:
    """锁定用户配额域，并返回当前全部持久作品标识。"""
    cursor.execute(
        "SELECT id FROM users WHERE id = %s FOR UPDATE",
        (int(owner_id),),
    )
    if not cursor.fetchone():
        raise VibeHubPermissionError("用户账号不存在")
    cursor.execute(
        """
        SELECT slug
        FROM vibehub_projects
        WHERE owner_id = %s
        ORDER BY id
        FOR UPDATE
        """,
        (int(owner_id),),
    )
    rows = cursor.fetchall() or []
    return [str(row["slug"]) for row in rows]


def _lock_and_count_versions(cursor, project_id: int) -> int:
    """锁定项目的已有版本元数据，防止并发越过版本上限。"""
    cursor.execute(
        """
        SELECT id
        FROM vibehub_versions
        WHERE project_id = %s
        ORDER BY version_number
        FOR UPDATE
        """,
        (int(project_id),),
    )
    return len(cursor.fetchall() or [])


def _lock_and_count_nonfeatured_projects(cursor, owner_id: int) -> int:
    """锁定并统计占用普通作品名额的项目；已批准精品不占名额。"""

    cursor.execute(
        """
        SELECT id
        FROM vibehub_projects
        WHERE owner_id = %s AND is_featured = 0
        ORDER BY id
        FOR UPDATE
        """,
        (int(owner_id),),
    )
    return len(cursor.fetchall() or [])


def _version_identity_map(cursor, project_id: int) -> dict[int, int]:
    """返回已锁项目的全部历史版本 ID -> 版本号映射。"""
    cursor.execute(
        """
        SELECT id, version_number
        FROM vibehub_versions
        WHERE project_id = %s
        ORDER BY version_number
        FOR UPDATE
        """,
        (int(project_id),),
    )
    result = {}
    seen_numbers = set()
    for row in cursor.fetchall() or []:
        try:
            version_id = int(row["id"])
            version_number = int(row["version_number"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VibeHubError(
                "VibeHub 版本元数据无法对齐",
                status_code=409,
                code="snapshot_metadata_conflict",
            ) from exc
        if version_id <= 0 or version_number <= 0 or version_number in seen_numbers:
            raise VibeHubError(
                "VibeHub 版本元数据冲突",
                status_code=409,
                code="snapshot_metadata_conflict",
            )
        result[version_id] = version_number
        seen_numbers.add(version_number)
    return result


def _snapshot_sets(identity_map: dict[int, int], reference_ids) -> tuple[set[int], set[int]]:
    known = set(identity_map.values())
    live = set()
    for raw_id in reference_ids:
        if raw_id in (None, ""):
            continue
        version_id = int(raw_id)
        try:
            live.add(identity_map[version_id])
        except KeyError as exc:
            raise VibeHubError(
                "VibeHub live-set 引用了缺失的版本",
                status_code=409,
                code="snapshot_metadata_conflict",
            ) from exc
    return known, live


def _lock_owner_snapshot_gc_states(cursor, owner_id: int) -> list[dict]:
    """锁定当前用户社区作品及版本，生成配额前退役回收的 DB 事实。"""

    cursor.execute(
        """
        SELECT id, slug, latest_version_id, public_version_id, review_version_id
        FROM vibehub_projects
        WHERE owner_id = %s
        ORDER BY id
        FOR UPDATE
        """,
        (int(owner_id),),
    )
    project_rows = list(cursor.fetchall() or [])
    projects = {}
    slugs = set()
    try:
        for row in project_rows:
            project_id = int(row["id"])
            slug = str(row["slug"])
            if (
                project_id <= 0
                or not SLUG_RE.fullmatch(slug)
                or project_id in projects
                or slug in slugs
            ):
                raise ValueError("duplicate project identity")
            projects[project_id] = {
                "slug": slug,
                "references": (
                    row.get("latest_version_id"),
                    row.get("public_version_id"),
                    row.get("review_version_id"),
                ),
                "identity_map": {},
            }
            slugs.add(slug)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise VibeHubError(
            "VibeHub 用户作品元数据无法对齐",
            status_code=409,
            code="snapshot_metadata_conflict",
        ) from exc
    if projects:
        cursor.execute(
            """
            SELECT v.project_id, v.id, v.version_number
            FROM vibehub_versions v
            INNER JOIN vibehub_projects p ON p.id = v.project_id
            WHERE p.owner_id = %s
            ORDER BY v.project_id, v.version_number
            FOR UPDATE
            """,
            (int(owner_id),),
        )
        try:
            for row in cursor.fetchall() or []:
                project_id = int(row["project_id"])
                version_id = int(row["id"])
                version_number = int(row["version_number"])
                project = projects[project_id]
                identity_map = project["identity_map"]
                if (
                    version_id <= 0
                    or version_number <= 0
                    or version_id in identity_map
                    or version_number in identity_map.values()
                ):
                    raise ValueError("duplicate version identity")
                identity_map[version_id] = version_number
        except (KeyError, TypeError, ValueError) as exc:
            raise VibeHubError(
                "VibeHub 用户版本元数据无法对齐",
                status_code=409,
                code="snapshot_metadata_conflict",
            ) from exc

    states = []
    for project in projects.values():
        known, live = _snapshot_sets(
            project["identity_map"],
            project["references"],
        )
        states.append(
            {
                "slug": project["slug"],
                "known_versions": known,
                "live_versions": live,
            }
        )
    return states


def _storage_root(upload_root) -> Path:
    return Path(upload_root) if upload_root is not None else storage.VIBEHUB_UPLOAD_ROOT


def _raise_quota_error(exc: quotas.VibeHubQuotaPolicyError):
    raise VibeHubError(
        str(exc),
        status_code=exc.status_code,
        code=exc.code,
    ) from exc


def _raise_snapshot_error(exc: storage.SnapshotReconciliationError):
    raise VibeHubError(
        str(exc),
        status_code=409,
        code="snapshot_reconciliation_conflict",
    ) from exc


def preflight_create_project(actor) -> None:
    """在解析大 multipart 请求体前做廉价作品数预检。

    这个无锁读只用于尽早拒绝已明确超额的请求；``create_project``
    仍会在事务内锁定用户配额域并重新检查，因此并发创建不能借
    预检竞态越界。管理员按业务规则不受作品数限制。
    """

    actor_id = _actor_id(actor)
    if _is_admin(actor):
        return
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS nonfeatured_count
                FROM vibehub_projects
                WHERE owner_id = %s AND is_featured = 0
                """,
                (actor_id,),
            )
            row = cursor.fetchone()
        try:
            count = int(row["nonfeatured_count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VibeHubError(
                "VibeHub 作品数量暂时无法校验",
                status_code=503,
                code="project_preflight_unavailable",
            ) from exc
        if count < 0:
            raise VibeHubError(
                "VibeHub 作品数量暂时无法校验",
                status_code=503,
                code="project_preflight_unavailable",
            )
        try:
            quotas.enforce_project_count(count)
        except quotas.VibeHubQuotaPolicyError as exc:
            _raise_quota_error(exc)
    finally:
        conn.close()


def preflight_upload_project(actor, slug: str) -> None:
    """在 multipart 解析前确认上传目标存在且当前用户是作者。"""

    _actor_id(actor)
    normalized_slug = str(slug or "").strip().lower()
    if not SLUG_RE.fullmatch(normalized_slug):
        raise VibeHubNotFoundError()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT p.owner_id,
                       (SELECT COUNT(*)
                        FROM vibehub_versions v
                        WHERE v.project_id = p.id) AS version_count
                FROM vibehub_projects p
                WHERE p.slug = %s
                """,
                (normalized_slug,),
            )
            project = cursor.fetchone()
        if not project:
            raise VibeHubNotFoundError()
        _require_owner(project, actor)
        try:
            version_count = int(project["version_count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VibeHubError(
                "VibeHub 作品版本数量暂时无法校验",
                status_code=503,
                code="version_preflight_unavailable",
            ) from exc
        if version_count < 0:
            raise VibeHubError(
                "VibeHub 作品版本数量暂时无法校验",
                status_code=503,
                code="version_preflight_unavailable",
            )
        try:
            quotas.enforce_version_count(version_count)
        except quotas.VibeHubQuotaPolicyError as exc:
            _raise_quota_error(exc)
    finally:
        conn.close()


def preflight_admin(actor) -> None:
    """在取得管理员持久变更槽前做无 DB 身份预检。"""

    _actor_id(actor)
    _require_admin(actor)


def _fetch_version(cursor, version_id: int):
    cursor.execute(
        """
        SELECT id, project_id, version_number, title, summary, description,
               tags_json, cover_image, package_sha256, package_size,
               manifest_json, review_status, review_requested_at, reviewed_at
        FROM vibehub_versions
        WHERE id = %s
        """,
        (version_id,),
    )
    row = cursor.fetchone()
    if not row:
        raise VibeHubError("作品版本记录不存在", status_code=409, code="missing_version")
    return row


def _version_metadata(row) -> dict:
    return {
        "title": row.get("title") or "",
        "summary": row.get("summary") or "",
        "description": row.get("description") or "",
        "tags": _decode_tags(row.get("tags_json")),
        "cover_image": row.get("cover_image"),
    }


def _insert_version(
    cursor,
    *,
    project_id: int,
    version_number: int,
    actor_id: int,
    metadata: dict,
    package_sha256: str,
    package_size: int,
    manifest: dict,
) -> int:
    cursor.execute(
        """
        INSERT INTO vibehub_versions (
            project_id, version_number, created_by_user_id,
            title, summary, description, tags_json, cover_image,
            package_sha256, package_size, manifest_json, review_status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'draft')
        """,
        (
            project_id,
            version_number,
            actor_id,
            metadata["title"],
            metadata["summary"],
            metadata["description"],
            json.dumps(metadata["tags"], ensure_ascii=False, separators=(",", ":")),
            metadata["cover_image"],
            package_sha256,
            package_size,
            json.dumps(manifest, ensure_ascii=False, separators=(",", ":")),
        ),
    )
    return int(cursor.lastrowid)


def _point_latest_version(
    cursor,
    *,
    project_id: int,
    version_id: int,
    previous_review_id=None,
):
    """在当前项目事务内切换 latest，并原子替换待审版本。"""

    if previous_review_id and int(previous_review_id) != version_id:
        cursor.execute(
            """UPDATE vibehub_versions SET review_status = 'draft',
            review_requested_at = NULL WHERE id = %s AND review_status = 'pending'""",
            (previous_review_id,),
        )
    cursor.execute(
        """UPDATE vibehub_versions SET review_status = 'pending',
        review_requested_at = CURRENT_TIMESTAMP WHERE id = %s""",
        (version_id,),
    )
    cursor.execute(
        """UPDATE vibehub_projects
        SET latest_version_id = %s, review_version_id = %s,
        updated_at = CURRENT_TIMESTAMP WHERE id = %s""",
        (version_id, version_id, project_id),
    )
    return version_id


def _list_projects(*, limit=None, actor=None, gallery=False) -> list[dict]:
    admin = _is_admin(actor)
    if admin:
        condition = "p.public_version_id IS NOT NULL OR p.owner_id = %s"
        condition += " OR (p.review_version_id IS NOT NULL AND rv.review_status = 'pending')"
        params = (_actor_id(actor),)
    elif actor:
        condition = "p.public_version_id IS NOT NULL OR p.owner_id = %s"
        actor_id = _actor_id(actor)
        params = (actor_id,)
    else:
        condition = "p.public_version_id IS NOT NULL"
        params = ()

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                _PROJECT_SELECT
                + f" WHERE ({condition}) ORDER BY p.is_featured DESC,"
                + " RAND()",
                params,
            )
            projects = []
            for row in cursor.fetchall() or []:
                is_mine = _owns(row, actor)
                is_review = admin and row.get("review_review_status") == "pending"
                audience = "review" if is_review else ("latest" if is_mine else "public")
                project = _serialize_project(row, audience=audience)
                pending = is_review or is_mine and (
                    row.get("latest_version_id") != row.get("public_version_id")
                )
                if gallery:
                    project.update(
                        is_mine=is_mine, is_pending=bool(pending),
                        can_edit=is_mine, can_approve=is_review,
                        can_manage_featured=admin,
                    )
                projects.append(project)
    finally:
        conn.close()

    if limit is not None:
        try:
            projects = projects[: max(0, min(int(limit), 500))]
        except (TypeError, ValueError):
            pass
    return projects


def list_public_projects(*, limit=None) -> list[dict]:
    return _list_projects(limit=limit)


def list_gallery_projects(actor=None) -> list[dict]:
    """公开作品加本人 latest；管理员额外看到 pending review。"""
    return _list_projects(actor=actor, gallery=True)


def list_user_projects(actor) -> list[dict]:
    actor_id = _actor_id(actor)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                _PROJECT_SELECT
                + " WHERE p.owner_id = %s ORDER BY p.updated_at DESC",
                (actor_id,),
            )
            return [
                _serialize_project(row, audience="latest")
                for row in (cursor.fetchall() or [])
            ]
    finally:
        conn.close()


def get_project(slug: str, *, actor=None, audience=None) -> dict:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            row = _fetch_project_row(cursor, str(slug).strip().lower())
            if not row:
                raise VibeHubNotFoundError()
            is_owner = _owns(row, actor)
            selected = audience or ("latest" if is_owner else "public")
            if selected not in {"latest", "public", "review"}:
                raise VibeHubError("未知的作品视图")
            if selected == "latest" and not is_owner:
                raise VibeHubPermissionError()
            if selected == "review" and not _is_admin(actor):
                raise VibeHubPermissionError()
            if selected == "public" and not row.get("public_version_id"):
                raise VibeHubNotFoundError("该作品尚未公开发布")
            if selected == "review" and (
                not row.get("review_version_id")
                or row.get("review_review_status") != "pending"
            ):
                raise VibeHubNotFoundError("该作品当前没有待审核版本")
            return _serialize_project(
                row,
                audience=selected,
                # 作者显式读取 public 投影时需要看到开发版本管理提示；管理员
                # 对他人作品的 public 投影仍必须与其他访客完全相同。
                include_workflow=selected == "public" and is_owner,
            )
    finally:
        conn.close()


def create_project(actor, upload, metadata=None, *, upload_root=None) -> dict:
    actor_id = _actor_id(actor)
    metadata = dict(metadata or {})
    slug = _requested_slug(metadata.pop("slug", None))
    root = _storage_root(upload_root)
    prepared = None
    installed = False
    committed = False
    previous_pointer = None
    previous_latest_image = None
    latest_image_changed = False
    conn = get_db_connection()
    try:
        with quotas.storage_mutation_lock(root):
            try:
                with conn.cursor() as cursor:
                    owner_slugs = _lock_owner_and_list_slugs(cursor, actor_id)
                    if not _is_admin(actor):
                        quotas.enforce_project_count(
                            _lock_and_count_nonfeatured_projects(cursor, actor_id)
                        )
                    cursor.execute(
                        """
                        INSERT INTO vibehub_projects (slug, owner_id)
                        VALUES (%s, %s)
                        """,
                        (slug, actor_id),
                    )
                    project_id = int(cursor.lastrowid)
                    # INSERT 成功证明没有同 slug 的已提交项目；此时才可
                    # 精确清理上次在 DB rollback/SIGKILL 后留下的孤儿目录。
                    storage.cleanup_orphan_project_storage(
                        slug,
                        upload_root=upload_root,
                    )
                    try:
                        prepared = storage.prepare_uploaded_package(
                            upload,
                            upload_root=upload_root,
                        )
                    except storage.PackageValidationError as exc:
                        raise VibeHubError(str(exc), code="invalid_package") from exc
                    normalized = _metadata(
                        metadata,
                        manifest=prepared.manifest,
                        app_dir=prepared.snapshot_dir / "app",
                        package_replaced=True,
                    )
                    prepared.manifest["cover_image"] = normalized["cover_image"]
                    prepared.manifest["cover_image_mime"] = normalized["cover_image_mime"]
                    storage.generate_processed_cover(
                        normalized["cover_image"],
                        prepared.snapshot_dir / "app",
                        prepared.snapshot_dir / storage.PROCESSED_COVER_FILENAME,
                    )
                    incoming_bytes = quotas.logical_tree_bytes(prepared.snapshot_dir)
                    retirement_states = _lock_owner_snapshot_gc_states(cursor, actor_id)
                    quotas.enforce_storage_quota(
                        owner_slugs,
                        incoming_bytes,
                        root,
                        staged_incoming_path=prepared.snapshot_dir,
                        retirement_project_states=retirement_states,
                    )
                    previous_latest_image = _prepare_latest_image(
                        slug,
                        prepared.snapshot_dir / "app",
                        package_digest=prepared.package_sha256,
                    )
                    latest_image_changed = True
                    version_id = _insert_version(
                        cursor,
                        project_id=project_id,
                        version_number=1,
                        actor_id=actor_id,
                        metadata=normalized,
                        package_sha256=prepared.package_sha256,
                        package_size=prepared.package_size,
                        manifest=prepared.manifest,
                    )
                    storage.install_prepared_snapshot(
                        prepared, slug, 1, upload_root=upload_root,
                    )
                    installed = True
                    previous_pointer = storage.read_pointer(
                        slug, "latest", upload_root=upload_root,
                    )
                    storage.write_pointer(
                        slug,
                        "latest",
                        version_number=1,
                        version_id=version_id,
                        upload_root=upload_root,
                    )
                    _point_latest_version(
                        cursor,
                        project_id=project_id,
                        version_id=version_id,
                    )
                    row = _fetch_project_row(cursor, slug)
                conn.commit()
                committed = True
                storage.prune_project_snapshots(
                    slug,
                    {1},
                    {1},
                    upload_root=upload_root,
                )
                return _serialize_project(row, audience="latest")
            except Exception as exc:
                if not committed:
                    conn.rollback()
                    try:
                        if installed:
                            storage.restore_pointer(
                                slug,
                                "latest",
                                previous_pointer,
                                upload_root=upload_root,
                            )
                            storage.remove_version_snapshot(
                                slug, 1, upload_root=upload_root,
                            )
                        if prepared is not None:
                            prepared.cleanup()
                    finally:
                        if latest_image_changed:
                            _restore_image_tag(slug, "latest", previous_latest_image)
                if getattr(exc, "args", (None,))[0] == 1062:
                    raise VibeHubError(
                        "该 slug 已被使用",
                        status_code=409,
                        code="slug_conflict",
                    ) from exc
                raise
    except quotas.VibeHubQuotaPolicyError as exc:
        _raise_quota_error(exc)
    except storage.SnapshotReconciliationError as exc:
        _raise_snapshot_error(exc)
    finally:
        conn.close()


def _create_next_version(
    actor,
    slug: str,
    metadata,
    *,
    upload=None,
    upload_root=None,
) -> dict:
    actor_id = _actor_id(actor)
    normalized_slug = str(slug or "").strip().lower()
    root = _storage_root(upload_root)
    prepared = None
    installed_version = None
    previous_pointer = None
    pointer_changed = False
    committed = False
    previous_latest_image = None
    latest_image_changed = False
    conn = get_db_connection()
    try:
        with quotas.storage_mutation_lock(root):
            try:
                with conn.cursor() as cursor:
                    project = _fetch_core_for_update(cursor, normalized_slug)
                    # 上传内容在此之后才会保存和解压，未授权请求不会
                    # 消耗宿主磁盘、CPU 或触发用户包解析。
                    _require_owner(project, actor)
                    owner_slugs = _lock_owner_and_list_slugs(cursor, actor_id)
                    version_count = _lock_and_count_versions(
                        cursor,
                        int(project["id"]),
                    )
                    quotas.enforce_version_count(version_count)
                    latest = _fetch_version(cursor, int(project["latest_version_id"]))
                    next_number = int(latest["version_number"]) + 1
                    identity_map = _version_identity_map(cursor, int(project["id"]))
                    storage.cleanup_uncommitted_version_snapshot(
                        normalized_slug,
                        next_number,
                        set(identity_map.values()),
                        upload_root=upload_root,
                    )

                    if upload is not None:
                        try:
                            prepared = storage.prepare_uploaded_package(
                                upload,
                                upload_root=upload_root,
                            )
                        except storage.PackageValidationError as exc:
                            raise VibeHubError(str(exc), code="invalid_package") from exc
                        app_dir = prepared.snapshot_dir / "app"
                        manifest = prepared.manifest
                        package_sha256 = prepared.package_sha256
                        package_size = prepared.package_size
                        normalized = _metadata(
                            metadata,
                            base=_version_metadata(latest),
                            manifest=manifest,
                            app_dir=app_dir,
                            package_replaced=True,
                        )
                        manifest["cover_image"] = normalized["cover_image"]
                        manifest["cover_image_mime"] = normalized["cover_image_mime"]
                        storage.generate_processed_cover(
                            normalized["cover_image"],
                            app_dir,
                            app_dir.parent / storage.PROCESSED_COVER_FILENAME,
                        )
                        incoming_bytes = quotas.logical_tree_bytes(prepared.snapshot_dir)
                        retirement_states = _lock_owner_snapshot_gc_states(
                            cursor,
                            actor_id,
                        )
                        quotas.enforce_storage_quota(
                            owner_slugs,
                            incoming_bytes,
                            root,
                            staged_incoming_path=prepared.snapshot_dir,
                            retirement_project_states=retirement_states,
                        )
                    else:
                        source_version = int(latest["version_number"])
                        source_snapshot = storage.version_snapshot_path(
                            normalized_slug,
                            source_version,
                            upload_root=upload_root,
                        )
                        source_app = storage.resolve_snapshot_app(
                            normalized_slug,
                            source_version,
                            upload_root=upload_root,
                        )
                        try:
                            manifest = json.loads(latest.get("manifest_json") or "{}")
                        except json.JSONDecodeError:
                            manifest = {}
                        package_sha256 = latest["package_sha256"]
                        package_size = int(latest["package_size"])
                        normalized = _metadata(
                            metadata,
                            base=_version_metadata(latest),
                            manifest=manifest,
                            app_dir=source_app,
                            package_replaced=False,
                        )
                        manifest["cover_image"] = normalized["cover_image"]
                        manifest["cover_image_mime"] = normalized["cover_image_mime"]
                        incoming_bytes = quotas.logical_tree_bytes(source_snapshot)
                        if normalized["cover_image"] != latest.get("cover_image"):
                            try:
                                previous_cover_bytes = (
                                    source_snapshot / storage.PROCESSED_COVER_FILENAME
                                ).stat(follow_symlinks=False).st_size
                            except FileNotFoundError:
                                previous_cover_bytes = 0
                            # 克隆后更换封面可能使平台 JPEG 变大。在实际
                            # 复制前按 400 KiB 硬上限保守预留，不给封面
                            # 重编码留下配额竞态窗口。
                            incoming_bytes += max(
                                0,
                                storage.MAX_PROCESSED_COVER_BYTES
                                - int(previous_cover_bytes),
                            )
                        retirement_states = _lock_owner_snapshot_gc_states(
                            cursor,
                            actor_id,
                        )
                        quotas.enforce_storage_quota(
                            owner_slugs,
                            incoming_bytes,
                            root,
                            retirement_project_states=retirement_states,
                        )
                        storage.clone_snapshot(
                            normalized_slug,
                            source_version,
                            next_number,
                            upload_root=upload_root,
                        )
                        installed_version = next_number
                        app_dir = storage.resolve_snapshot_app(
                            normalized_slug,
                            next_number,
                            upload_root=upload_root,
                        )
                        storage.generate_processed_cover(
                            normalized["cover_image"],
                            app_dir,
                            app_dir.parent / storage.PROCESSED_COVER_FILENAME,
                        )

                    previous_latest_image = _prepare_latest_image(
                        normalized_slug, app_dir,
                        package_digest=package_sha256,
                        featured=bool(project.get("is_featured")),
                    )
                    latest_image_changed = True
                    version_id = _insert_version(
                        cursor,
                        project_id=int(project["id"]),
                        version_number=next_number,
                        actor_id=actor_id,
                        metadata=normalized,
                        package_sha256=package_sha256,
                        package_size=package_size,
                        manifest=manifest,
                    )
                    identity_map[version_id] = next_number
                    if prepared is not None:
                        storage.install_prepared_snapshot(
                            prepared,
                            normalized_slug,
                            next_number,
                            upload_root=upload_root,
                        )
                        installed_version = next_number
                    previous_pointer = storage.read_pointer(
                        normalized_slug, "latest", upload_root=upload_root,
                    )
                    pointer_changed = True
                    storage.write_pointer(
                        normalized_slug,
                        "latest",
                        version_number=next_number,
                        version_id=version_id,
                        upload_root=upload_root,
                    )
                    review_version_id = _point_latest_version(
                        cursor,
                        project_id=int(project["id"]),
                        version_id=version_id,
                        previous_review_id=project.get("review_version_id"),
                    )
                    row = _fetch_project_row(cursor, normalized_slug)
                    known_versions, live_versions = _snapshot_sets(
                        identity_map,
                        (
                            version_id,
                            project.get("public_version_id"),
                            review_version_id,
                        ),
                    )
                conn.commit()
                committed = True
                storage.prune_project_snapshots(
                    normalized_slug,
                    known_versions,
                    live_versions,
                    upload_root=upload_root,
                )
                return _serialize_project(row, audience="latest")
            except Exception:
                if not committed:
                    conn.rollback()
                    try:
                        if pointer_changed:
                            storage.restore_pointer(
                                normalized_slug,
                                "latest",
                                previous_pointer,
                                upload_root=upload_root,
                            )
                        if installed_version is not None:
                            storage.remove_version_snapshot(
                                normalized_slug,
                                installed_version,
                                upload_root=upload_root,
                            )
                        if prepared is not None:
                            prepared.cleanup()
                    finally:
                        if latest_image_changed:
                            _restore_image_tag(
                                normalized_slug, "latest", previous_latest_image,
                            )
                raise
    except quotas.VibeHubQuotaPolicyError as exc:
        _raise_quota_error(exc)
    except storage.SnapshotReconciliationError as exc:
        _raise_snapshot_error(exc)
    finally:
        conn.close()


def upload_new_version(actor, slug: str, upload, metadata=None, *, upload_root=None) -> dict:
    return _create_next_version(
        actor, slug, metadata or {}, upload=upload, upload_root=upload_root,
    )


def edit_project(actor, slug: str, metadata, *, upload_root=None) -> dict:
    if not isinstance(metadata, dict) or not any(
        key in metadata for key in ("title", "summary", "description", "tags", "cover_image")
    ):
        raise VibeHubError("没有可更新的作品字段")
    return _create_next_version(
        actor, slug, metadata, upload=None, upload_root=upload_root,
    )


def delete_project(actor, slug: str, *, upload_root=None) -> dict:
    """删除作品元数据；级联删除其不可变版本记录。"""

    _actor_id(actor)
    normalized_slug = str(slug or "").strip().lower()
    if not SLUG_RE.fullmatch(normalized_slug):
        raise VibeHubNotFoundError()
    root = _storage_root(upload_root)
    conn = get_db_connection()
    try:
        with quotas.storage_mutation_lock(root):
            with conn.cursor() as cursor:
                project = _fetch_core_for_update(cursor, normalized_slug)
                if not (_owns(project, actor) or _is_admin(actor)):
                    raise VibeHubPermissionError()
                cursor.execute(
                    "DELETE FROM vibehub_projects WHERE id = %s",
                    (int(project["id"]),),
                )
                if cursor.rowcount != 1:
                    raise VibeHubError(
                        "作品删除时状态已变化，请刷新后重试",
                        status_code=409,
                        code="delete_stale",
                    )
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    # 不能在提交前直接删除快照，否则事务回滚会使仍存在的作品丢失包。
    # 提交后目录不再有 DB live-set 引用，现有安全孤儿回收会审计并回收它。
    return {"deleted": True, "slug": normalized_slug}


def list_pending_reviews(actor) -> list[dict]:
    _require_admin(actor)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                _PROJECT_SELECT
                + " WHERE p.review_version_id IS NOT NULL"
                + " AND rv.review_status = 'pending'"
                + " ORDER BY rv.review_requested_at ASC"
            )
            return [
                _serialize_project(row, audience="review")
                for row in (cursor.fetchall() or [])
            ]
    finally:
        conn.close()


def review_submission(
    actor,
    slug: str,
    decision: str,
    *,
    note="",
    expected_version=None,
    upload_root=None,
) -> dict:
    _require_admin(actor)
    decision = str(decision or "").strip().lower()
    if decision not in {"approve", "reject"}:
        raise VibeHubError("decision 必须为 approve 或 reject")
    note = _clean_text(note, field="note", limit=2000)
    normalized_slug = str(slug or "").strip().lower()
    root = _storage_root(upload_root)
    try:
        expected_number = int(expected_version)
    except (TypeError, ValueError) as exc:
        raise VibeHubError("expected_version 必须是整数") from exc
    previous_public = None
    public_pointer_changed = False
    committed = False
    previous_public_image = None
    public_image_changed = False
    conn = get_db_connection()
    try:
        with quotas.storage_mutation_lock(root):
            try:
                with conn.cursor() as cursor:
                    project = _fetch_core_for_update(cursor, normalized_slug)
                    review_version_id = project.get("review_version_id")
                    if not review_version_id:
                        raise VibeHubError(
                            "该作品当前没有待审核版本",
                            status_code=409,
                            code="review_not_pending",
                        )
                    version = _fetch_version(cursor, int(review_version_id))
                    if version.get("review_status") != "pending":
                        raise VibeHubError(
                            "待审核版本状态已变更，请刷新列表",
                            status_code=409,
                            code="review_stale",
                        )
                    if (
                        int(project.get("latest_version_id") or 0) != int(review_version_id)
                        or expected_number != int(version["version_number"])
                    ):
                        raise VibeHubError(
                            "待审核版本已经更新，请刷新后重新确认",
                            status_code=409,
                            code="review_stale",
                        )
                    rejected_response = None
                    if decision == "reject":
                        rejected_response = _serialize_project(
                            _fetch_project_row(cursor, normalized_slug),
                            audience="review",
                        )
                    new_status = "approved" if decision == "approve" else "rejected"
                    if decision == "approve":
                        previous_public_image = _promote_latest_image(
                            normalized_slug, version["package_sha256"],
                        )
                        public_image_changed = True
                        previous_public = storage.read_pointer(
                            normalized_slug, "public", upload_root=upload_root,
                        )
                        public_pointer_changed = True
                        storage.write_pointer(
                            normalized_slug,
                            "public",
                            version_number=int(version["version_number"]),
                            version_id=int(version["id"]),
                            upload_root=upload_root,
                        )
                    cursor.execute(
                        """
                        UPDATE vibehub_versions
                        SET review_status = %s, reviewed_at = CURRENT_TIMESTAMP,
                            reviewed_by_user_id = %s, review_note = %s
                        WHERE id = %s AND review_status = 'pending'
                        """,
                        (new_status, _actor_id(actor), note or None, version["id"]),
                    )
                    if cursor.rowcount != 1:
                        raise VibeHubError(
                            "待审核版本已被其他管理员处理",
                            status_code=409,
                            code="review_stale",
                        )
                    if decision == "approve":
                        cursor.execute(
                            """
                            UPDATE vibehub_projects
                            SET public_version_id = %s, review_version_id = NULL,
                                last_reviewed_version_id = %s,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = %s AND review_version_id = %s
                            """,
                            (version["id"], version["id"], project["id"], version["id"]),
                        )
                        public_version_id = version["id"]
                    else:
                        cursor.execute(
                            """
                            UPDATE vibehub_projects
                            SET review_version_id = NULL,
                                last_reviewed_version_id = %s,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = %s AND review_version_id = %s
                            """,
                            (version["id"], project["id"], version["id"]),
                        )
                        public_version_id = project.get("public_version_id")
                    identity_map = _version_identity_map(cursor, int(project["id"]))
                    known_versions, live_versions = _snapshot_sets(
                        identity_map,
                        (
                            project.get("latest_version_id"),
                            public_version_id,
                            None,
                        ),
                    )
                    row = _fetch_project_row(cursor, normalized_slug)
                conn.commit()
                committed = True
                storage.prune_project_snapshots(
                    normalized_slug,
                    known_versions,
                    live_versions,
                    upload_root=upload_root,
                )
                if decision == "approve":
                    return _serialize_project(
                        row, audience="public", include_workflow=True,
                    )
                # 驳回响应只返回管理员刚刚审核过的副本，
                # 不能在 review 引用清除后改返作者的未提交 latest。
                rejected_response.update(
                    {
                        "has_pending_review": False,
                        "review_status": "rejected",
                        "review_note": note or None,
                        "play_url": None,
                    }
                )
                return rejected_response
            except Exception:
                if not committed:
                    conn.rollback()
                    try:
                        if public_pointer_changed:
                            storage.restore_pointer(
                                normalized_slug,
                                "public",
                                previous_public,
                                upload_root=upload_root,
                            )
                    finally:
                        if public_image_changed:
                            _restore_image_tag(
                                normalized_slug, "public", previous_public_image,
                            )
                raise
    except quotas.VibeHubQuotaPolicyError as exc:
        _raise_quota_error(exc)
    except storage.SnapshotReconciliationError as exc:
        _raise_snapshot_error(exc)
    finally:
        conn.close()


def set_featured(actor, slug: str, featured: bool) -> dict:
    """由管理员直接设置或取消作品的精品资格。"""

    _require_admin(actor)
    if type(featured) is not bool:
        raise VibeHubError("featured 必须为布尔值")
    normalized_slug = str(slug or "").strip().lower()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            project = _fetch_core_for_update(cursor, normalized_slug)
            cursor.execute(
                """
                UPDATE vibehub_projects
                SET featured_status = %s, is_featured = %s,
                    featured_requested_at = NULL,
                    featured_reviewed_at = CURRENT_TIMESTAMP,
                    featured_reviewed_by_user_id = %s, featured_review_note = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (
                    "approved" if featured else "none",
                    1 if featured else 0,
                    _actor_id(actor),
                    project["id"],
                ),
            )
            row = _fetch_project_row(cursor, normalized_slug)
        conn.commit()
        audience = (
            "public" if row.get("public_version_id")
            else "review" if row.get("review_version_id")
            else "latest"
        )
        return _serialize_project(
            row, audience=audience, include_workflow=True,
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def resolve_project_package(slug: str, *, audience="public", actor=None, upload_root=None) -> dict:
    """为运行时解析已授权的作品版本。"""
    if audience not in {"public", "latest", "review"}:
        raise VibeHubError("未知的作品包视图")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            project = _fetch_project_row(cursor, str(slug or "").strip().lower())
            if not project:
                raise VibeHubNotFoundError()
            if audience == "latest" and not _owns(project, actor):
                raise VibeHubPermissionError()
            if audience == "review" and not _is_admin(actor):
                raise VibeHubPermissionError()
            if audience == "review" and (
                not project.get("review_version_id")
                or project.get("review_review_status") != "pending"
            ):
                raise VibeHubNotFoundError("该作品当前没有待审核版本")
            version_id_key = {
                "public": "public_version_id",
                "latest": "latest_version_id",
                "review": "review_version_id",
            }[audience]
            version_id = project.get(version_id_key)
            if not version_id:
                raise VibeHubNotFoundError("该作品包尚不存在")
            version = _fetch_version(cursor, int(version_id))
    finally:
        conn.close()
    try:
        manifest = json.loads(version.get("manifest_json") or "{}")
    except json.JSONDecodeError:
        manifest = {}
    return {
        "project_id": int(project["id"]),
        "slug": project["slug"],
        "version_id": int(version["id"]),
        "version": int(version["version_number"]),
        "package_sha256": version["package_sha256"],
        "manifest": manifest,
        "featured": bool(project.get("is_featured")),
    }


__all__ = [
    "VibeHubError",
    "VibeHubNotFoundError",
    "VibeHubPermissionError",
    "create_project",
    "delete_project",
    "edit_project",
    "get_project",
    "list_pending_reviews",
    "list_public_projects",
    "list_user_projects",
    "preflight_admin",
    "preflight_create_project",
    "preflight_upload_project",
    "resolve_project_package",
    "review_submission",
    "set_featured",
    "upload_new_version",
]
