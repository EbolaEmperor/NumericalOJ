"""VibeHub 面向浏览器与 NumOJ CLI 的 JSON API。"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from flask import Blueprint, current_app, request, send_file
from PIL import Image, UnidentifiedImageError

from backend.oj_modules.api.helpers import json_error, json_success, public_user
from backend.oj_modules.security.auth import current_user
from backend.oj_modules.vibehub import quotas, services, storage
from backend.oj_modules.vibehub.guide import DEVELOPER_GUIDE_PATH


vibehub_api_bp = Blueprint("vibehub_api", __name__, url_prefix="/api/vibehub")


def _upload_root():
    return current_app.config.get("VIBEHUB_UPLOAD_ROOT")


def _require_user():
    user = current_user()
    if not user:
        raise services.VibeHubError(
            "请先登录", status_code=401, code="authentication_required",
        )
    return user


def _payload():
    if request.is_json:
        value = request.get_json(silent=True)
        return value if isinstance(value, dict) else {}
    return request.form.to_dict(flat=True)


def _uploaded_package():
    upload = request.files.get("package") or request.files.get("file")
    if not upload or not getattr(upload, "filename", ""):
        raise services.VibeHubError("请上传 ZIP 格式的完整作品包")
    return upload


def _close_parsed_uploads() -> None:
    """在释放持久变更槽前关闭所有 FileStorage 及其临时 spool。"""

    # 直接查看 cached_property 的实例缓存，不得在 finally 中首次
    # 访问 request.files，否则缺包/解析异常可能被再次触发。
    request_object = request._get_current_object()
    parsed_files = request_object.__dict__.get("files")
    if parsed_files is None:
        return
    seen = set()
    for _field, upload in parsed_files.items(multi=True):
        identity = id(upload)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            upload.close()
        except Exception:
            # FileStorage.close 通常只转发 stream.close；异常时再直接
            # best-effort 关闭底层 stream，同时继续处理其余文件。
            stream = getattr(upload, "stream", None)
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass


@contextmanager
def _storage_mutation_request_slot():
    """在 DB/body/全局存储锁前限制全宿主持久变更并发。"""

    root = _upload_root() or storage.VIBEHUB_UPLOAD_ROOT
    slots = current_app.config.get(
        "VIBEHUB_STORAGE_MUTATION_SLOTS",
        current_app.config.get(
            "VIBEHUB_MULTIPART_PARSE_SLOTS",
            quotas.DEFAULT_STORAGE_MUTATION_SLOTS,
        ),
    )
    wait_seconds = current_app.config.get(
        "VIBEHUB_STORAGE_MUTATION_SLOT_WAIT_SECONDS",
        current_app.config.get(
            "VIBEHUB_MULTIPART_SLOT_WAIT_SECONDS",
            quotas.DEFAULT_STORAGE_MUTATION_SLOT_WAIT_SECONDS,
        ),
    )
    try:
        with quotas.storage_mutation_capacity_slot(
            root,
            slots=slots,
            wait_seconds=wait_seconds,
        ):
            try:
                yield
            finally:
                _close_parsed_uploads()
    except quotas.VibeHubStorageMutationCapacityExceeded as exc:
        raise services.VibeHubError(
            str(exc),
            status_code=429,
            code=exc.code,
        ) from exc
    except quotas.VibeHubStorageSecurityError as exc:
        raise services.VibeHubError(
            "VibeHub 持久变更槽暂时不可用",
            status_code=503,
            code="storage_mutation_unavailable",
        ) from exc


@vibehub_api_bp.errorhandler(services.VibeHubError)
def _handle_vibehub_error(exc):
    response, status = json_error(str(exc), exc.status_code, code=exc.code)
    if exc.status_code in {429, 503}:
        response.headers["Retry-After"] = "1"
    return response, status


@vibehub_api_bp.route("/developer-guide", methods=["GET"])
def developer_guide():
    """向网页之外的客户端提供仓库内同一份完整开发手册。"""
    response = send_file(
        DEVELOPER_GUIDE_PATH,
        mimetype="text/markdown; charset=utf-8",
        as_attachment=False,
        download_name="vibehub-developer-guide.md",
        conditional=True,
        max_age=0,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@vibehub_api_bp.route("/projects", methods=["GET"])
def public_projects():
    rows = services.list_public_projects(limit=request.args.get("limit"))
    return json_success(projects=rows, count=len(rows), total=len(rows))


@vibehub_api_bp.route("/projects/mine", methods=["GET"])
def my_projects():
    user = _require_user()
    rows = services.list_user_projects(user)
    return json_success(user=public_user(user), projects=rows, count=len(rows))


@vibehub_api_bp.route("/projects/<slug>", methods=["GET"])
def project_detail(slug):
    view = (request.args.get("view") or "").strip().lower() or None
    project = services.get_project(slug, actor=current_user(), audience=view)
    return json_success(project=project)


@vibehub_api_bp.route("/projects", methods=["POST"])
def create_project():
    user = _require_user()
    with _storage_mutation_request_slot():
        # 预检位于槽内但仍先于 request.files/form；事务内会最终重检。
        services.preflight_create_project(user)
        upload = _uploaded_package()
        payload = _payload()
        project = services.create_project(
            user, upload, payload, upload_root=_upload_root(),
        )
    return json_success(project=project), 201


@vibehub_api_bp.route("/projects/<slug>", methods=["PATCH"])
def edit_project(slug):
    user = _require_user()
    with _storage_mutation_request_slot():
        services.preflight_upload_project(user, slug)
        payload = _payload()
        project = services.edit_project(
            user, slug, payload, upload_root=_upload_root(),
        )
    return json_success(project=project)


@vibehub_api_bp.route("/projects/<slug>", methods=["DELETE"])
def delete_project(slug):
    user = _require_user()
    with _storage_mutation_request_slot():
        result = services.delete_project(
            user,
            slug,
            upload_root=_upload_root(),
        )
    return json_success(**result)


@vibehub_api_bp.route("/projects/<slug>/versions", methods=["POST"])
def upload_version(slug):
    user = _require_user()
    with _storage_mutation_request_slot():
        services.preflight_upload_project(user, slug)
        upload = _uploaded_package()
        payload = _payload()
        project = services.upload_new_version(
            user, slug, upload, payload, upload_root=_upload_root(),
        )
    return json_success(project=project), 201


@vibehub_api_bp.route("/projects/<slug>/cover", methods=["GET"])
def project_cover(slug):
    view = (request.args.get("view") or "public").strip().lower()
    actor = current_user()
    project = services.get_project(slug, actor=actor, audience=view)
    cover_image = project.get("cover_image")
    if not cover_image:
        raise services.VibeHubNotFoundError("该作品没有封面图")
    package = services.resolve_project_package(
        slug, audience=view, actor=actor, upload_root=_upload_root(),
    )
    app_dir = storage.resolve_snapshot_app(
        package["slug"], package["version"], upload_root=_upload_root(),
    )
    target = storage.processed_cover_path(app_dir)
    if not target.is_file():
        raise services.VibeHubNotFoundError("平台封面副本不存在")
    try:
        if target.stat().st_size > storage.MAX_PROCESSED_COVER_BYTES:
            raise services.VibeHubNotFoundError("平台封面副本格式无效")
        with Image.open(target) as image:
            if image.format != "JPEG" or image.size != storage.PROCESSED_COVER_SIZE:
                raise services.VibeHubNotFoundError("平台封面副本格式无效")
            image.verify()
    except (OSError, UnidentifiedImageError, ValueError) as exc:
        raise services.VibeHubNotFoundError("平台封面副本格式无效") from exc
    response = send_file(
        target,
        mimetype="image/jpeg",
        as_attachment=False,
        conditional=True,
        max_age=0,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    if view != "public":
        response.headers["Cache-Control"] = "private, no-store"
    else:
        response.headers["Cache-Control"] = "public, max-age=0, must-revalidate"
    return response


@vibehub_api_bp.route("/admin/reviews", methods=["GET"])
def pending_reviews():
    rows = services.list_pending_reviews(_require_user())
    return json_success(projects=rows, count=len(rows))


@vibehub_api_bp.route("/admin/reviews/<slug>", methods=["POST"])
def review_project(slug):
    user = _require_user()
    services.preflight_admin(user)
    with _storage_mutation_request_slot():
        payload = _payload()
        project = services.review_submission(
            user,
            slug,
            payload.get("decision"),
            note=payload.get("note") or "",
            expected_version=payload.get("expected_version"),
            upload_root=_upload_root(),
        )
    return json_success(project=project)


@vibehub_api_bp.route("/admin/featured/<slug>", methods=["POST"])
def set_project_featured(slug):
    user = _require_user()
    # 管理员身份必须在任何 JSON/form/multipart 解析前确认，避免未授权
    # 请求用大 body 占用解析线程和临时文件。
    services.preflight_admin(user)
    payload = _payload()
    project = services.set_featured(user, slug, payload.get("featured"))
    return json_success(project=project)


__all__ = ["vibehub_api_bp"]
