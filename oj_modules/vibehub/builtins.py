"""VibeHub 内置示例作品目录。

内置作品由仓库维护，不经过用户上传或审核流程。这里是 HTML 页面与 JSON API
共用的展示元数据；实际程序包由部署脚本从 ``vibehub_examples/`` 同步后进入统一容器链。
"""

from __future__ import annotations

from copy import deepcopy


_BUILTIN_PROJECTS = (
    {
        "id": -1,
        "slug": "circle-cat",
        "title": "围住小猫",
        "summary": "在离线蜂巢棋盘上封锁最短逃生分支，赶在小猫抵达边缘前围住它。",
        "description": (
            "一局很短、但每一步都需要预判的六边形策略游戏。小猫会沿可达的最短路线"
            "中优先选择后续分支最多的一步；你需要逐步切断出口，用尽可能少的回合完成"
            "包围。隔离版不接入 OJ 排行榜或持久保存战绩，每次重开、刷新或容器回收后"
            "都会开始独立新局。"
        ),
        "owner_username": "Numerical OJ",
        "latest_version": 1,
        "public_version": 1,
        "review_status": "approved",
        "featured_status": "approved",
        "is_featured": True,
        "visibility": "public",
        "cover_image": "static/cover.jpg",
        "cover_url": "/api/vibehub/projects/circle-cat/cover?view=public&v=1",
        "cover_kind": "cat",
        "tags": ["策略", "小游戏", "六边形"],
        "created_at": None,
        "updated_at": None,
        "updated_at_label": "内置示例",
        "project_kind": "builtin",
        "builtin_entrypoint": None,
        "play_url": "/vibehub/circle-cat/play",
    },
    {
        "id": -2,
        "slug": "arc-agi-3",
        "title": "ARC-AGI-3 公开挑战",
        "summary": "进入 25 个没有文字规则的交互环境，在试错中发现目标与规律。",
        "description": (
            "ARC-AGI-3 是一个交互式推理基准。环境不会直接给出规则、操作说明或目标；"
            "玩家需要观察每次操作前后的变化，建立假设，并把发现的规律迁移到后续关卡。"
            "公开集完全从本地缓存运行，游玩过程不访问官方 API。"
        ),
        "owner_username": "ARC Prize Foundation",
        "latest_version": 1,
        "public_version": 1,
        "review_status": "approved",
        "featured_status": "approved",
        "is_featured": True,
        "visibility": "public",
        "cover_image": "static/cover.jpg",
        "cover_url": "/api/vibehub/projects/arc-agi-3/cover?view=public&v=1",
        "cover_kind": "arc",
        "tags": ["推理", "探索", "ARC"],
        "created_at": None,
        "updated_at": None,
        "updated_at_label": "内置公开集",
        "project_kind": "builtin",
        "builtin_entrypoint": None,
        "play_url": "/vibehub/arc-agi-3/play",
    },
)


def list_builtin_projects():
    """返回可安全修改和 JSON 序列化的内置作品副本。"""

    return [deepcopy(project) for project in _BUILTIN_PROJECTS]


def get_builtin_project(slug):
    """按 slug 查找内置作品，找不到时返回 ``None``。"""

    normalized = str(slug or "").strip().lower()
    for project in _BUILTIN_PROJECTS:
        if project["slug"] == normalized:
            return deepcopy(project)
    return None


__all__ = ["get_builtin_project", "list_builtin_projects"]
