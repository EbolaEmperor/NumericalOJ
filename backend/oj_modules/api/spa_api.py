"""React SPA 的版本化引导 API。

业务资源继续由各领域 API 提供；这里仅暴露建立应用外壳所需的会话、导航和
能力信息，避免前端为了绘制 layout 并发请求多个服务端模板上下文。
"""

from __future__ import annotations

from flask import Blueprint, request

from backend.oj_modules.api.helpers import json_success, public_user
from backend.oj_modules.api.problem_api import PROBLEM_LIST_CLASS_COOKIE
from backend.oj_modules.classroom.dashboard import get_layout_navigation_context
from backend.oj_modules.db_services import is_class_adjust_enabled
from backend.oj_modules.security.auth import current_user
from backend.oj_modules.site_config.services import get_mail_settings


spa_api_bp = Blueprint("spa_api", __name__, url_prefix="/api/v1")


def _navigation_items(user):
    items = [
        {"id": "library", "label": "总题库", "path": "/problems?view=library", "icon": "library", "group": "workspace", "spa": True},
        {"id": "problems", "label": "班级作业" if int(user.get("is_admin") or 0) == 1 else "我的作业", "path": "/problems", "icon": "homework", "group": "workspace", "spa": True},
        {"id": "submissions", "label": "提交记录", "path": "/submissions", "icon": "submissions", "group": "workspace", "spa": True},
        {"id": "rankings", "label": "打榜赛", "path": "/rankings", "icon": "ranking", "group": "workspace", "spa": True},
        {"id": "agents", "label": "Agent 任务", "path": "/agents", "icon": "agent", "group": "workspace", "spa": True},
        {"id": "vibehub", "label": "VibeHub", "path": "/vibehub", "icon": "vibehub", "group": "workspace", "spa": True},
        {"id": "forum", "label": "讨论区", "path": "/forum", "icon": "forum", "group": "workspace", "spa": True},
        {"id": "repository", "label": "代码仓库", "path": "/repository", "icon": "repository", "group": "workspace", "spa": True},
    ]
    if user and int(user.get("is_admin") or 0) == 1:
        items.extend([
            {"id": "admin", "label": "用户管理", "path": "/admin", "icon": "users", "group": "admin", "spa": True},
            {"id": "admin_homework", "label": "作业管理", "path": "/admin/homework", "icon": "admin-homework", "group": "admin", "spa": True},
            {"id": "ai_detection", "label": "AI 检测", "path": "/admin/ai-detection", "icon": "ai", "group": "admin", "spa": True},
            {"id": "site_config", "label": "全站配置", "path": "/admin/site-config", "icon": "site-config", "group": "admin", "spa": True},
        ])
    return items


@spa_api_bp.get("/session")
def session_bootstrap():
    """返回 SPA 首屏所需的最小会话快照；未登录也是成功响应。"""

    user = current_user()
    selected_class = (
        str(request.args.get("class_en") or "").strip()
        or str(request.cookies.get(PROBLEM_LIST_CLASS_COOKIE) or "").strip()
        or None
    )
    navigation = (
        get_layout_navigation_context(user, selected_class_en=selected_class)
        if user
        else {"counts": {}, "agent_active": False}
    )
    class_adjust_enabled = False
    mail_service_configured = False
    if user:
        try:
            class_adjust_enabled = is_class_adjust_enabled(wait_timeout_seconds=0.0)
        except Exception:
            # 读取站点设置失败时沿用可用性降级，避免把原本可见的班级管理入口
            # 从 SPA 中静默移除。
            class_adjust_enabled = True
        try:
            mail_service_configured = bool(get_mail_settings(wait_timeout_seconds=0.0))
        except Exception:
            mail_service_configured = False
    navigation_payload = {
        "items": _navigation_items(user) if user else [],
        "counts": navigation.get("counts") or {},
        "agent_active": bool(navigation.get("agent_active")),
    }
    if navigation.get("selected_class_en"):
        navigation_payload["selected_class_en"] = navigation["selected_class_en"]
    return json_success(
        api_version="v1",
        user=public_user(user),
        navigation=navigation_payload,
        capabilities={
            "spa": True,
            "legacy_ui_available": False,
            "streaming": True,
            "class_adjust_enabled": bool(class_adjust_enabled),
            "mail_service_configured": mail_service_configured,
        },
    )


__all__ = ["spa_api_bp"]
