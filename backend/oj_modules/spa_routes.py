"""React 前端的正式页面路由与临时旧版对照路由。"""

from __future__ import annotations

import re


_SPA_EXACT_PATHS = frozenset({
    "/login",
    "/register",
    "/forgot-password",
    "/problems",
    "/submissions",
    "/rankings",
    "/agents",
    "/forum",
    "/repository",
    "/vibehub",
    "/admin",
    "/admin/homework",
    "/admin/ai-detection",
    "/admin/site-config",
})

_SPA_PATH_PATTERNS = (
    re.compile(r"^/problems/\d+/?$"),
    re.compile(r"^/submissions/\d+/?$"),
    re.compile(r"^/rankings/\d+/?$"),
    re.compile(r"^/rankings/\d+/appeals/\d+/?$"),
    re.compile(r"^/agents/[A-Za-z0-9_.-]+/?$"),
    re.compile(r"^/forum/\d+/?$"),
    re.compile(r"^/vibehub/guide/?$"),
    re.compile(r"^/vibehub/[A-Za-z0-9_-]+(?:/play)?/?$"),
    re.compile(r"^/admin/problems/(?:new|\d+/edit)/?$"),
    re.compile(r"^/admin/ai-detection/problems/\d+/?$"),
    re.compile(r"^/admin/ai-detection/students/[^/]+/?$"),
)


def is_spa_document_path(path: str) -> bool:
    """只匹配明确已交给 React Router 的页面。

    不使用全站 catch-all，避免把下载、流式输出或尚未迁移的后端路由
    误当成 index.html。
    """

    normalized = path.rstrip("/") or "/"
    return normalized in _SPA_EXACT_PATHS or any(
        pattern.fullmatch(path) for pattern in _SPA_PATH_PATTERNS
    )


def migrated_legacy_page_target(path: str) -> str | None:
    """把旧版书签的只读页面地址导向 React 正式地址。"""

    exact = {
        "/my_submissions": "/submissions",
        "/problems/all": "/problems?view=library",
        "/ranking": "/rankings",
        "/ranking/": "/rankings",
        "/code_repository": "/repository",
        "/forgot_password": "/forgot-password",
        "/admin/users": "/admin",
        "/admin/add_problem": "/admin/problems/new",
        "/admin/agent_tasks": "/agents",
        "/admin/ai_detection": "/admin/ai-detection",
        "/agent/tasks": "/agents",
        "/agent/tasks/": "/agents",
    }
    if path in exact:
        return exact[path]

    patterns = (
        (r"^/problem/(\d+)/?$", "/problems/{}"),
        (r"^/submission_detail/(\d+)/?$", "/submissions/{}"),
        (r"^/ranking/(\d+)/?$", "/rankings/{}"),
        (r"^/forum/thread/(\d+)/?$", "/forum/{}"),
        (r"^/admin/edit_problem/(\d+)/?$", "/admin/problems/{}/edit"),
        (r"^/admin/agent_tasks/([A-Za-z0-9_.-]+)/?$", "/agents/{}"),
        (r"^/agent/tasks/([A-Za-z0-9_.-]+)/?$", "/agents/{}"),
    )
    for pattern, target in patterns:
        matched = re.fullmatch(pattern, path)
        if matched:
            return target.format(matched.group(1))

    ai_problem = re.fullmatch(r"^/admin/ai_detection/problem/(\d+)/?$", path)
    if ai_problem:
        return f"/admin/ai-detection/problems/{ai_problem.group(1)}"
    ai_student = re.fullmatch(r"^/admin/ai_detection/student/([^/]+)/?$", path)
    if ai_student:
        return f"/admin/ai-detection/students/{ai_student.group(1)}"
    appeal = re.fullmatch(r"^/ranking/(\d+)/appeal/(\d+)/review/?$", path)
    if appeal:
        return f"/rankings/{appeal.group(1)}/appeals/{appeal.group(2)}"
    return None


__all__ = ["is_spa_document_path", "migrated_legacy_page_target"]
