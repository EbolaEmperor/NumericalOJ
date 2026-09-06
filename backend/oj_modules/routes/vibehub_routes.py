"""VibeHub 兼容路由与运行时能力端点。"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import Blueprint, Response, current_app, jsonify, redirect
from flask import request, url_for

from backend.oj_modules.security.auth import (
    current_user,
    login_required,
)
from backend.oj_modules.security.origin_guard import is_same_origin
from backend.oj_modules.vibehub import services
from backend.oj_modules.vibehub.runtime import (
    VibeHubCapacityError,
    VibeHubGPUError,
    VibeHubLeaseError,
    VibeHubRequestTooLarge,
    VibeHubRuntimeError,
    RUNTIME_CORS_METHODS,
    RUNTIME_CORS_REQUEST_HEADERS,
    get_runtime_manager,
)


vibehub_bp = Blueprint("vibehub", __name__, url_prefix="/vibehub")


def _log_page_failure(operation):
    current_app.logger.exception(
        "VibeHub 页面数据加载失败",
        extra={"operation": operation},
    )


@vibehub_bp.get("")
@vibehub_bp.get("/")
def index():
    return jsonify(
        success=False,
        message="该页面由 React 前端提供",
        path="/vibehub",
    ), 406


@vibehub_bp.get("/guide")
def guide():
    return jsonify(
        success=False,
        message="该页面由 React 前端提供",
        path="/vibehub/guide",
    ), 406


@vibehub_bp.get("/workspace")
@login_required
def workspace():
    return redirect(url_for("vibehub.index", view="mine"))


@vibehub_bp.get("/<slug>")
def detail(slug):
    """兼容旧作品地址，并按当前身份直接进入对应试玩版本。"""

    user = current_user()
    try:
        if user and int(user.get("is_admin") or 0) == 1:
            try:
                project = services.get_project(slug, actor=user, audience="review")
            except services.VibeHubNotFoundError:
                project = services.get_project(slug, actor=user)
        else:
            project = services.get_project(slug, actor=user)
    except services.VibeHubError as exc:
        return Response(str(exc), status=exc.status_code, mimetype='text/plain')
    except Exception:
        _log_page_failure("project_redirect")
        return Response(
            "作品暂时无法打开，请稍后再试。",
            status=503,
            mimetype='text/plain',
        )

    response = redirect(project.get("play_url") or url_for("vibehub.index"))
    # 跳转目标会因作者、管理员和普通用户的可见版本不同而变化。
    response.headers["Cache-Control"] = "private, no-store"
    return response


@vibehub_bp.get("/<slug>/play")
@login_required
def play(slug):
    return jsonify(
        success=False,
        message="该页面由 React 前端提供",
        path=f"/vibehub/{slug}/play",
    ), 406


def _runtime_error_response(exc, *, status=503):
    event_fields = {"error_type": type(exc).__name__}
    buildkit_diagnostic = getattr(exc, "buildkit_diagnostic", "")
    if buildkit_diagnostic:
        event_fields["buildkit"] = {
            "diagnostic": buildkit_diagnostic,
            "returncode": getattr(exc, "buildkit_returncode", None),
            "stdout_truncated": bool(
                getattr(exc, "buildkit_stdout_truncated", False)
            ),
            "stderr_truncated": bool(
                getattr(exc, "buildkit_stderr_truncated", False)
            ),
        }
    current_app.logger.warning(
        "VibeHub 运行请求失败",
        extra={"event_fields": event_fields},
    )
    return jsonify(success=False, message="作品运行服务暂时不可用，请稍后重试。"), status


def _runtime_capacity_response(exc):
    current_app.logger.info(
        "VibeHub 运行容量已满",
        extra={"error_type": type(exc).__name__},
    )
    response = jsonify(success=False, message="运行资源繁忙，请稍后重试。")
    response.status_code = 429
    response.headers["Retry-After"] = "1"
    return response


@vibehub_bp.post("/<slug>/runtime/acquire")
@login_required
def runtime_acquire(slug):
    user = current_user()
    channel = str(request.args.get("channel") or "public").strip().lower()
    if channel not in {"public", "latest", "review"}:
        return jsonify(success=False, message="未知的作品版本通道。"), 400
    try:
        package = services.resolve_project_package(
            slug,
            audience=channel,
            actor=user,
            upload_root=current_app.config.get("VIBEHUB_UPLOAD_ROOT"),
        )
        project_key = package["slug"]
        lease = get_runtime_manager().acquire(
            project_key,
            featured=bool(package.get("featured")),
            channel=channel,
            base_path="/vibehub/runtime",
            package_digest=package["package_sha256"],
            storage_key=f"project-{package['project_id']}-{channel}",
            **({"gpu_allocation": package["gpu"]} if package.get("gpu") else {}),
        )
    except services.VibeHubError as exc:
        return jsonify(success=False, message=str(exc), code=exc.code), exc.status_code
    except VibeHubGPUError as exc:
        return jsonify(success=False, message=str(exc), code="gpu_unavailable"), 429
    except VibeHubCapacityError as exc:
        return _runtime_capacity_response(exc)
    except VibeHubRuntimeError as exc:
        return _runtime_error_response(exc)
    return jsonify(
        success=True,
        lease_token=lease.token,
        proxy_url=lease.proxy_base_path,
        heartbeat_url=f"/vibehub/runtime/{lease.token}/heartbeat",
        release_url=f"/vibehub/runtime/{lease.token}/release",
        expires_at=lease.expires_at,
    )


@vibehub_bp.post("/runtime/<token>/heartbeat")
@login_required
def runtime_heartbeat(token):
    try:
        lease = get_runtime_manager().heartbeat(token)
    except VibeHubLeaseError as exc:
        return _runtime_error_response(exc, status=404)
    except VibeHubCapacityError as exc:
        return _runtime_capacity_response(exc)
    except VibeHubRuntimeError as exc:
        return _runtime_error_response(exc)
    return jsonify(success=True, expires_at=lease.expires_at)


@vibehub_bp.post("/runtime/<token>/release")
@login_required
def runtime_release(token):
    try:
        released = get_runtime_manager().release(token)
    except VibeHubLeaseError as exc:
        return _runtime_error_response(exc, status=404)
    except VibeHubRuntimeError as exc:
        return _runtime_error_response(exc)
    return jsonify(success=True, released=bool(released))


def _proxy_target(path):
    target = "/" + str(path or "").lstrip("/")
    if request.query_string:
        raw = request.query_string
        safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:/?@"
        encoded = []
        index = 0
        while index < len(raw):
            value = raw[index]
            if (
                value == 0x25
                and index + 2 < len(raw)
                and all(chr(item) in "0123456789abcdefABCDEF" for item in raw[index + 1:index + 3])
            ):
                encoded.append("%" + raw[index + 1:index + 3].decode("ascii").upper())
                index += 3
                continue
            encoded.append(chr(value) if value in safe else f"%{value:02X}")
            index += 1
        target += "?" + "".join(encoded)
    return target


def _runtime_preflight_origin():
    """返回可回显的严格 Origin；opaque sandbox 只会发送字面量 ``null``。"""

    origin = request.headers.get("Origin")
    if origin == "null":
        return origin
    if not origin or origin != origin.strip():
        return None
    try:
        parsed = urlsplit(origin)
        # Origin 是序列化后的源，不允许凭证、路径、查询或 fragment。调用
        # ``port`` 同时让非法端口 fail closed。
        parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return None
    if not is_same_origin(origin, request.host_url):
        return None
    return origin


def _runtime_preflight(manager, token):
    origin = _runtime_preflight_origin()
    requested_method = request.headers.get("Access-Control-Request-Method", "")
    raw_headers = request.headers.get("Access-Control-Request-Headers")
    allowed_headers = {
        name.lower(): name for name in RUNTIME_CORS_REQUEST_HEADERS
    }

    if (
        origin is None
        or requested_method not in RUNTIME_CORS_METHODS
        or request.content_length not in {None, 0}
        or request.headers.get("Access-Control-Request-Private-Network") is not None
    ):
        return Response("CORS preflight rejected", status=403, content_type="text/plain")

    requested_headers = []
    if raw_headers is not None:
        parts = [part.strip() for part in raw_headers.split(",")]
        lowered = [part.lower() for part in parts]
        if (
            not parts
            or any(not part for part in parts)
            or len(set(lowered)) != len(lowered)
            or any(name not in allowed_headers for name in lowered)
        ):
            return Response(
                "CORS preflight rejected", status=403, content_type="text/plain"
            )
        requested_headers = [allowed_headers[name] for name in lowered]

    try:
        manager.validate_proxy_capability(token)
    except VibeHubLeaseError:
        return Response("runtime lease unavailable", status=404, content_type="text/plain")
    except VibeHubRuntimeError:
        current_app.logger.warning("VibeHub 代理预检失败")
        return Response("runtime proxy unavailable", status=502, content_type="text/plain")

    response = Response(status=204)
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Methods"] = requested_method
    if requested_headers:
        response.headers["Access-Control-Allow-Headers"] = ", ".join(
            requested_headers
        )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Vary"] = (
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
    )
    return response


@vibehub_bp.route(
    "/runtime/<token>/",
    defaults={"path": ""},
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@vibehub_bp.route(
    "/runtime/<token>/<path:path>",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
def runtime_proxy(token, path):
    """仅凭短期 capability token 代理作品请求，不依赖 OJ 会话 Cookie。"""

    manager = get_runtime_manager()
    if request.method == "OPTIONS":
        return _runtime_preflight(manager, token)
    content_length = request.content_length
    if content_length is not None and content_length > manager.request_max_bytes:
        return Response("request body too large", status=413, content_type="text/plain")
    try:
        proxied = manager.proxy_from_reader(
            token,
            request.method,
            _proxy_target(path),
            tuple(request.headers.items()),
            request.stream.read,
        )
    except VibeHubRequestTooLarge:
        return Response("request body too large", status=413, content_type="text/plain")
    except VibeHubLeaseError:
        return Response("runtime lease unavailable", status=404, content_type="text/plain")
    except VibeHubCapacityError:
        response = Response("runtime proxy busy", status=429, content_type="text/plain")
        response.headers["Retry-After"] = "1"
        return response
    except VibeHubRuntimeError:
        current_app.logger.warning("VibeHub 代理请求失败")
        return Response("runtime proxy unavailable", status=502, content_type="text/plain")
    return Response(
        proxied.body,
        status=proxied.status,
        headers=list(proxied.headers),
    )


__all__ = ["vibehub_bp"]
