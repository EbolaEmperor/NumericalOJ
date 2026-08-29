"""VibeHub 服务端页面适配层。"""

from __future__ import annotations

from urllib.parse import urlencode, urlsplit

from flask import Blueprint, Response, current_app, jsonify, make_response, redirect
from flask import render_template, request, url_for

from oj_modules.security.auth import (
    current_user,
    login_required,
)
from oj_modules.security.origin_guard import is_same_origin
from oj_modules.vibehub import services
from oj_modules.vibehub.guide import render_developer_guide
from oj_modules.vibehub.runtime import (
    VibeHubCapacityError,
    VibeHubLeaseError,
    VibeHubRequestTooLarge,
    VibeHubRuntimeError,
    RUNTIME_CORS_METHODS,
    RUNTIME_CORS_REQUEST_HEADERS,
    get_runtime_manager,
)


vibehub_bp = Blueprint("vibehub", __name__, url_prefix="/vibehub")


# 只限制播放页被站外嵌入，不限制作品访问网络。
_PLAYER_CONTENT_SECURITY_POLICY = "frame-ancestors 'self'"


def _log_page_failure(operation):
    current_app.logger.exception(
        "VibeHub 页面数据加载失败",
        extra={"operation": operation},
    )


@vibehub_bp.get("")
@vibehub_bp.get("/")
def index():
    user = current_user()
    allowed_filters = {"all", "featured"}
    if user:
        allowed_filters.add("mine")
    if user and int(user.get("is_admin") or 0) == 1:
        allowed_filters.add("pending")
    requested_filter = str(request.args.get("view") or "").strip()
    initial_filter = requested_filter if requested_filter in allowed_filters else "all"
    load_error = None
    try:
        projects = services.list_gallery_projects(user)
    except Exception:
        _log_page_failure("personalized_gallery")
        projects = []
        load_error = "社区作品暂时没有载入。"
    response = make_response(
        render_template(
            "vibehub/index.html", user=user, projects=projects, load_error=load_error,
            initial_filter=initial_filter,
            edit_slug=(request.args.get("edit") or "").strip(),
        )
    )
    if user:
        response.headers["Cache-Control"] = "private, no-store"
    return response


@vibehub_bp.get("/guide")
def guide():
    guide_html, guide_toc_html = render_developer_guide()
    response = make_response(
        render_template(
            "vibehub/guide.html", user=current_user(),
            guide_html=guide_html, guide_toc_html=guide_toc_html,
        )
    )
    # 手册和目录都从 tracked Markdown 即时生成，刷新时必须重新验证内容。
    response.headers["Cache-Control"] = "no-cache"
    return response


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
        return render_template(
            "vibehub/not_found.html",
            user=user,
            message=str(exc),
        ), exc.status_code
    except Exception:
        _log_page_failure("project_redirect")
        return render_template(
            "vibehub/not_found.html",
            user=user,
            message="作品暂时无法打开，请稍后再试。",
        ), 503

    response = redirect(project.get("play_url") or url_for("vibehub.index"))
    # 跳转目标会因作者、管理员和普通用户的可见版本不同而变化。
    response.headers["Cache-Control"] = "private, no-store"
    return response


@vibehub_bp.get("/<slug>/play")
@login_required
def play(slug):
    user = current_user()
    channel = str(request.args.get("channel") or "public").strip().lower()
    if channel not in {"public", "latest", "review"}:
        channel = "public"
    try:
        project = services.get_project(slug, actor=user, audience=channel)
    except services.VibeHubError as exc:
        return render_template(
            "vibehub/not_found.html",
            user=user,
            message=str(exc),
        ), exc.status_code
    except Exception:
        _log_page_failure("project_player")
        return render_template(
            "vibehub/not_found.html",
            user=user,
            message="作品运行信息暂时无法读取，请稍后再试。",
        ), 503

    mine = channel == "latest"
    return_url = url_for("vibehub.index", **({"view": "mine"} if mine else {}))
    return_label = "我的作品" if mine else "作品列表"

    response = render_template(
        "vibehub/player.html",
        user=user,
        project=project,
        embedded_url=None,
        acquire_url=f"/vibehub/{project['slug']}/runtime/acquire?{urlencode({'channel': channel})}",
        heartbeat_url_template="/vibehub/runtime/__TOKEN__/heartbeat",
        release_url_template="/vibehub/runtime/__TOKEN__/release",
        return_url=return_url,
        return_label=return_label,
    )
    return response, 200, {
        "Cache-Control": "no-store",
        "Content-Security-Policy": _PLAYER_CONTENT_SECURITY_POLICY,
    }


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
        )
    except services.VibeHubError as exc:
        return jsonify(success=False, message=str(exc), code=exc.code), exc.status_code
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
