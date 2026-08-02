#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""站点动态配置管理页与 JSON API。"""

from functools import wraps

from flask import Blueprint, current_app, jsonify, render_template, request

from oj_modules.auth_helpers import admin_required, current_user
from oj_modules import dynamic_config_services as config_service
from oj_modules import dynamic_config_testers


_dynamic_config_testers = {
    "llm_endpoint": dynamic_config_testers.test_llm_endpoint,
    "mail": dynamic_config_testers.test_mail_settings,
    "web_search": dynamic_config_testers.test_web_search_settings,
}


def configure_dynamic_config_testers(*, llm_endpoint=None, mail=None, web_search=None):
    """在应用组合根注入真实测试适配器；未注入时测试接口 fail-closed。"""
    if llm_endpoint is not None:
        _dynamic_config_testers["llm_endpoint"] = llm_endpoint
    if mail is not None:
        _dynamic_config_testers["mail"] = mail
    if web_search is not None:
        _dynamic_config_testers["web_search"] = web_search


def _json_body():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise config_service.DynamicConfigValidationError("请求体必须是 JSON 对象")
    return payload


def _api_errors(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except config_service.DynamicConfigTestFailedError as exc:
            response = {"success": False, "message": str(exc)}
            if exc.result is not None:
                response["test"] = exc.result
            return jsonify(response), exc.status_code
        except config_service.DynamicConfigError as exc:
            return jsonify(success=False, message=str(exc)), exc.status_code
        except Exception:
            current_app.logger.exception("站点动态配置操作失败")
            return jsonify(success=False, message="操作失败，请稍后再试"), 500
    return wrapper


def create_admin_dynamic_config_blueprint(
    *, llm_endpoint_tester=None, mail_tester=None, web_search_tester=None
):
    """创建管理 Blueprint，tester 参数便于应用组合和隔离测试。"""
    blueprint = Blueprint("admin_dynamic_config", __name__)

    def tester(kind):
        local = {
            "llm_endpoint": llm_endpoint_tester,
            "mail": mail_tester,
            "web_search": web_search_tester,
        }[kind]
        return local if local is not None else _dynamic_config_testers[kind]

    @blueprint.get("/admin/site-config")
    @admin_required
    def site_config():
        user = current_user()
        return render_template(
            "admin/site_config.html",
            user=user,
            current_user=user,
        )

    @blueprint.get("/api/admin/dynamic-config/meta")
    @admin_required
    @_api_errors
    def metadata():
        return jsonify(success=True, **config_service.get_dynamic_config_meta())

    @blueprint.get("/api/admin/dynamic-config/llm-endpoints")
    @admin_required
    @_api_errors
    def llm_endpoint_list():
        user = current_user()
        category = request.args.get("category") or None
        endpoints = config_service.list_llm_endpoints(
            category=category,
            actor_user_id=user["id"],
        )
        return jsonify(success=True, endpoints=endpoints)

    @blueprint.post("/api/admin/dynamic-config/llm-endpoints/test")
    @admin_required
    @_api_errors
    def llm_endpoint_test():
        user = current_user()
        payload = _json_body()
        endpoint_id = payload.get("endpoint_id", payload.get("id"))
        result = config_service.test_llm_endpoint(
            payload,
            user_id=user["id"],
            endpoint_id=endpoint_id,
            tester=tester("llm_endpoint"),
        )
        public_test = {
            key: value
            for key, value in result.items()
            if key not in {"test_token", "expires_in_seconds"}
        }
        return jsonify(
            success=True,
            test=public_test,
            test_token=result["test_token"],
            expires_in_seconds=result["expires_in_seconds"],
        )

    @blueprint.post("/api/admin/dynamic-config/llm-endpoints")
    @admin_required
    @_api_errors
    def llm_endpoint_create():
        user = current_user()
        payload = _json_body()
        endpoint = config_service.save_llm_endpoint(
            payload,
            user_id=user["id"],
            test_token=payload.get("test_token"),
        )
        return jsonify(success=True, endpoint=endpoint), 201

    @blueprint.put("/api/admin/dynamic-config/llm-endpoints/<int:endpoint_id>")
    @admin_required
    @_api_errors
    def llm_endpoint_update(endpoint_id):
        user = current_user()
        payload = _json_body()
        endpoint = config_service.save_llm_endpoint(
            payload,
            user_id=user["id"],
            endpoint_id=endpoint_id,
            test_token=payload.get("test_token"),
        )
        return jsonify(success=True, endpoint=endpoint)

    @blueprint.delete("/api/admin/dynamic-config/llm-endpoints/<int:endpoint_id>")
    @admin_required
    @_api_errors
    def llm_endpoint_delete(endpoint_id):
        config_service.delete_llm_endpoint(endpoint_id)
        return jsonify(success=True)

    @blueprint.post("/api/admin/dynamic-config/llm-endpoints/<int:endpoint_id>/lock")
    @admin_required
    @_api_errors
    def llm_endpoint_lock(endpoint_id):
        user = current_user()
        payload = _json_body()
        endpoint = config_service.lock_llm_endpoint(
            endpoint_id,
            user_id=user["id"],
            reason=payload.get("reason", payload.get("lock_reason")),
        )
        return jsonify(success=True, endpoint=endpoint)

    @blueprint.post("/api/admin/dynamic-config/llm-endpoints/<int:endpoint_id>/unlock")
    @admin_required
    @_api_errors
    def llm_endpoint_unlock(endpoint_id):
        user = current_user()
        payload = _json_body()
        endpoint = config_service.unlock_llm_endpoint(
            endpoint_id,
            user=user,
            password=payload.get("password"),
            confirmation=payload.get("confirmation"),
        )
        return jsonify(success=True, endpoint=endpoint)

    @blueprint.get("/api/admin/dynamic-config/feature-bindings")
    @admin_required
    @_api_errors
    def feature_binding_list():
        user = current_user()
        bindings = config_service.list_feature_bindings(actor_user_id=user["id"])
        return jsonify(success=True, bindings=bindings)

    @blueprint.put("/api/admin/dynamic-config/feature-bindings/<feature_key>")
    @admin_required
    @_api_errors
    def feature_binding_update(feature_key):
        user = current_user()
        payload = _json_body()
        binding = config_service.set_feature_binding(
            feature_key,
            payload.get("endpoint_id"),
            user_id=user["id"],
        )
        return jsonify(success=True, binding=binding)

    @blueprint.post(
        "/api/admin/dynamic-config/feature-bindings/repository_embedding/lock"
    )
    @blueprint.post("/api/admin/dynamic-config/feature-bindings/embedding/lock")
    @admin_required
    @_api_errors
    def embedding_binding_lock():
        user = current_user()
        payload = _json_body()
        binding = config_service.lock_embedding_binding(
            user_id=user["id"],
            reason=payload.get("reason", payload.get("lock_reason")),
        )
        return jsonify(success=True, binding=binding)

    @blueprint.post(
        "/api/admin/dynamic-config/feature-bindings/repository_embedding/unlock"
    )
    @blueprint.post("/api/admin/dynamic-config/feature-bindings/embedding/unlock")
    @admin_required
    @_api_errors
    def embedding_binding_unlock():
        user = current_user()
        payload = _json_body()
        binding = config_service.unlock_embedding_binding(
            user=user,
            password=payload.get("password"),
            confirmation=payload.get("confirmation"),
        )
        return jsonify(success=True, binding=binding)

    @blueprint.get("/api/admin/dynamic-config/mail")
    @admin_required
    @_api_errors
    def mail_get():
        return jsonify(success=True, settings=config_service.get_mail_settings())

    @blueprint.post("/api/admin/dynamic-config/mail/test")
    @admin_required
    @_api_errors
    def mail_test():
        user = current_user()
        result = config_service.test_mail_settings(
            _json_body(),
            user_id=user["id"],
            recipient_email=user.get("email"),
            tester=tester("mail"),
        )
        return jsonify(success=True, test=result)

    @blueprint.put("/api/admin/dynamic-config/mail")
    @admin_required
    @_api_errors
    def mail_save():
        user = current_user()
        settings = config_service.save_mail_settings(
            _json_body(), user_id=user["id"]
        )
        return jsonify(success=True, settings=settings)

    @blueprint.delete("/api/admin/dynamic-config/mail")
    @admin_required
    @_api_errors
    def mail_clear():
        config_service.clear_mail_settings()
        return jsonify(success=True)

    @blueprint.get("/api/admin/dynamic-config/web-search")
    @admin_required
    @_api_errors
    def web_search_get():
        return jsonify(success=True, settings=config_service.get_web_search_settings())

    @blueprint.post("/api/admin/dynamic-config/web-search/test")
    @admin_required
    @_api_errors
    def web_search_test():
        user = current_user()
        result = config_service.test_web_search_settings(
            _json_body(),
            user_id=user["id"],
            tester=tester("web_search"),
        )
        return jsonify(success=True, test=result)

    @blueprint.put("/api/admin/dynamic-config/web-search")
    @admin_required
    @_api_errors
    def web_search_save():
        user = current_user()
        settings = config_service.save_web_search_settings(
            _json_body(), user_id=user["id"]
        )
        return jsonify(success=True, settings=settings)

    @blueprint.delete("/api/admin/dynamic-config/web-search")
    @admin_required
    @_api_errors
    def web_search_clear():
        config_service.clear_web_search_settings()
        return jsonify(success=True)

    return blueprint


admin_dynamic_config_bp = create_admin_dynamic_config_blueprint()
