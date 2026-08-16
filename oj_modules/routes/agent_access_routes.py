#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Agent 额度、自有端点与全站运行设置 JSON API。"""

from __future__ import annotations

from functools import wraps

from flask import Blueprint, current_app, jsonify, request

from oj_modules.agents import quota
from oj_modules.agents import runtime_settings
from oj_modules.agents import user_endpoints
from oj_modules.security.auth import admin_required, current_user, is_admin, login_required
from oj_modules.site_config import services as config_service


_agent_concurrency_runtime_applier = None


def configure_agent_concurrency_runtime_applier(applier):
    """配置保存并发上限后的即时应用回调。"""

    if applier is not None and not callable(applier):
        raise TypeError("Agent 并发运行时应用器必须可调用")
    global _agent_concurrency_runtime_applier
    _agent_concurrency_runtime_applier = applier


def _json_body():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise quota.AgentQuotaValidationError("请求体必须是 JSON 对象")
    return payload


def _api_errors(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except quota.AgentQuotaError as exc:
            payload = {
                "success": False,
                "message": str(exc),
                "code": exc.code,
            }
            if isinstance(exc, quota.AgentQuotaAccessDeniedError):
                payload["decision"] = exc.decision
            return jsonify(payload), exc.status_code
        except runtime_settings.AgentRuntimeSettingsError as exc:
            return jsonify(
                success=False,
                message=str(exc),
                code=exc.code,
            ), exc.status_code
        except config_service.DynamicConfigTestFailedError as exc:
            payload = {"success": False, "message": str(exc)}
            if exc.result is not None:
                payload["test"] = exc.result
            return jsonify(payload), exc.status_code
        except config_service.DynamicConfigError as exc:
            return jsonify(success=False, message=str(exc)), exc.status_code
        except Exception:
            current_app.logger.exception("Agent 额度或自有端点操作失败")
            return jsonify(success=False, message="操作失败，请稍后再试"), 500

    return wrapper


def _priced_global_endpoints():
    endpoints = config_service.list_llm_endpoints(include_secrets=False)
    result = []
    for endpoint in endpoints:
        category = str(endpoint.get("category") or "").strip().lower()
        if category not in {"text", "omni"}:
            continue
        if not endpoint.get("api_key_configured"):
            continue
        fields = (
            "input_price_per_million",
            "cached_input_price_per_million",
            "output_price_per_million",
        )
        if any(str(endpoint.get(field) or "").strip() == "" for field in fields):
            continue
        result.append({
            "id": int(endpoint["id"]),
            "model": str(endpoint.get("model") or ""),
            "protocol": str(endpoint.get("protocol") or "openai").strip().lower(),
            **{field: str(endpoint[field]) for field in fields},
        })
    return result


def create_agent_access_blueprint(
    *,
    endpoint_tester=None,
    concurrency_runtime_applier=None,
):
    blueprint = Blueprint("agent_access", __name__)
    tester = endpoint_tester or user_endpoints.test_user_agent_endpoint

    if concurrency_runtime_applier is not None and not callable(
        concurrency_runtime_applier
    ):
        raise TypeError("Agent 并发运行时应用器必须可调用")

    def apply_concurrency_limit(limit):
        applier = (
            concurrency_runtime_applier
            if concurrency_runtime_applier is not None
            else _agent_concurrency_runtime_applier
        )
        if applier is None:
            return False
        try:
            return bool(applier(limit))
        except Exception:
            current_app.logger.exception("Agent 并发上限已保存，但未能即时应用")
            return False

    @blueprint.get("/api/agent/quota")
    @login_required
    @_api_errors
    def quota_summary():
        user = current_user()
        summary = quota.get_agent_quota_summary(
            user["id"],
            is_admin=is_admin(user),
        )
        return jsonify(success=True, summary=summary)

    @blueprint.post("/api/agent/quota/requests")
    @login_required
    @_api_errors
    def quota_request_create():
        user = current_user()
        if is_admin(user):
            raise quota.AgentQuotaValidationError("管理员无需申请 Agent 额度")
        payload = _json_body()
        created = quota.create_agent_quota_request(
            user["id"],
            payload.get("reason"),
        )
        summary = quota.get_agent_quota_summary(user["id"])
        return jsonify(success=True, request=created, summary=summary), 201

    @blueprint.get("/api/agent/endpoints/prices")
    @login_required
    @_api_errors
    def endpoint_prices():
        return jsonify(success=True, endpoints=_priced_global_endpoints())

    @blueprint.get("/api/agent/endpoints")
    @login_required
    @_api_errors
    def personal_endpoint_list():
        user = current_user()
        endpoints = user_endpoints.list_user_agent_endpoints(user["id"])
        return jsonify(success=True, endpoints=endpoints)

    @blueprint.post("/api/agent/endpoints/test")
    @login_required
    @_api_errors
    def personal_endpoint_test():
        user = current_user()
        payload = _json_body()
        endpoint_id = payload.get("endpoint_id", payload.get("id"))
        result = user_endpoints.test_user_agent_endpoint_payload(
            payload,
            user_id=user["id"],
            endpoint_id=endpoint_id,
            tester=tester,
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

    @blueprint.post("/api/agent/endpoints")
    @login_required
    @_api_errors
    def personal_endpoint_create():
        user = current_user()
        payload = _json_body()
        endpoint = user_endpoints.save_user_agent_endpoint(
            payload,
            user_id=user["id"],
            test_token=payload.get("test_token"),
        )
        return jsonify(success=True, endpoint=endpoint), 201

    @blueprint.put("/api/agent/endpoints/<int:endpoint_id>")
    @login_required
    @_api_errors
    def personal_endpoint_update(endpoint_id):
        user = current_user()
        payload = _json_body()
        endpoint = user_endpoints.save_user_agent_endpoint(
            payload,
            user_id=user["id"],
            endpoint_id=endpoint_id,
            test_token=payload.get("test_token"),
        )
        return jsonify(success=True, endpoint=endpoint)

    @blueprint.delete("/api/agent/endpoints/<int:endpoint_id>")
    @login_required
    @_api_errors
    def personal_endpoint_delete(endpoint_id):
        user = current_user()
        user_endpoints.delete_user_agent_endpoint(endpoint_id, user["id"])
        return jsonify(success=True)

    @blueprint.get("/api/agent/quota/requests/pending")
    @admin_required
    @_api_errors
    def quota_request_pending():
        user = current_user()
        return jsonify(
            success=True,
            requests=quota.list_pending_agent_quota_requests(user["id"]),
            classes=quota.list_agent_quota_grant_classes(),
        )

    @blueprint.post("/api/agent/quota/requests/<int:request_id>/review")
    @admin_required
    @_api_errors
    def quota_request_review(request_id):
        user = current_user()
        payload = _json_body()
        action = str(payload.get("action") or "").strip().lower()
        if action not in {"approve", "reject"}:
            raise quota.AgentQuotaValidationError("审核动作无效")
        reviewed = quota.review_agent_quota_request(
            request_id,
            reviewer_user_id=user["id"],
            approved=action == "approve",
            approved_amount=payload.get("approved_amount"),
            review_note=payload.get("review_note"),
        )
        return jsonify(success=True, request=reviewed)

    @blueprint.post("/api/agent/quota/grants/class-batch")
    @admin_required
    @_api_errors
    def quota_class_batch_grant():
        user = current_user()
        payload = _json_body()
        result = quota.batch_grant_quota_by_classes(
            payload.get("classes"),
            payload.get("amount_rmb"),
            user["id"],
        )
        return jsonify(
            success=True,
            grant=result,
            granted_user_count=result["affected_users"],
            total_amount=result["total_rmb"],
        )

    @blueprint.get("/api/admin/dynamic-config/agent-public-access")
    @admin_required
    @_api_errors
    def agent_public_access_get():
        return jsonify(success=True, enabled=quota.get_agent_public_enabled())

    @blueprint.put("/api/admin/dynamic-config/agent-public-access")
    @admin_required
    @_api_errors
    def agent_public_access_update():
        payload = _json_body()
        enabled = quota.set_agent_public_enabled(payload.get("enabled"))
        return jsonify(success=True, enabled=enabled)

    @blueprint.get("/api/admin/dynamic-config/agent-concurrency")
    @admin_required
    @_api_errors
    def agent_concurrency_get():
        return jsonify(
            success=True,
            limit=runtime_settings.get_agent_concurrency_limit(),
        )

    @blueprint.put("/api/admin/dynamic-config/agent-concurrency")
    @admin_required
    @_api_errors
    def agent_concurrency_update():
        payload = _json_body()
        limit = runtime_settings.set_agent_concurrency_limit(payload.get("limit"))
        applied = apply_concurrency_limit(limit)
        return jsonify(success=True, limit=limit, applied=applied)

    return blueprint


agent_access_bp = create_agent_access_blueprint()


__all__ = [
    "agent_access_bp",
    "configure_agent_concurrency_runtime_applier",
    "create_agent_access_blueprint",
]
