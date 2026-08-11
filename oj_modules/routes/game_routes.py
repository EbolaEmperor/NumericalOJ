#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""已退役游戏入口的兼容路由。

围住小猫和 ARC-AGI-3 已迁移为独立 VibeHub 程序包。这里仅保留旧书签的
永久跳转，并明确拒绝旧游戏 API，避免两套实现继续并存。
"""

from flask import Blueprint, jsonify, redirect, url_for


game_bp = Blueprint("game", __name__)

_RETIRED_MESSAGE = "旧游戏接口已停用，请从 VibeHub 进入作品。"


def _vibehub_redirect(slug):
    return redirect(url_for("vibehub.play", slug=slug), code=301)


def _retired_api_response():
    return jsonify(success=False, code="legacy_game_retired", message=_RETIRED_MESSAGE), 410


@game_bp.get("/games/circle-cat")
def circle_cat_bookmark():
    """将旧围住小猫书签永久迁移到 VibeHub 试玩页。"""

    return _vibehub_redirect("circle-cat")


@game_bp.get("/games/circle-cat/<path:legacy_path>")
def circle_cat_legacy_bookmark(legacy_path):
    del legacy_path
    return _vibehub_redirect("circle-cat")


@game_bp.route(
    "/games/circle-cat/<path:legacy_path>",
    methods=["POST", "PUT", "PATCH", "DELETE"],
)
def circle_cat_retired_api(legacy_path):
    del legacy_path
    return _retired_api_response()


@game_bp.get("/games/arc-agi-3")
def arc_agi_3_bookmark():
    """将旧 ARC-AGI-3 书签永久迁移到 VibeHub 试玩页。"""

    return _vibehub_redirect("arc-agi-3")


@game_bp.get("/games/arc-agi-3/<path:legacy_path>")
def arc_agi_3_legacy_bookmark(legacy_path):
    del legacy_path
    return _vibehub_redirect("arc-agi-3")


@game_bp.route(
    "/games/arc-agi-3/<path:legacy_path>",
    methods=["POST", "PUT", "PATCH", "DELETE"],
)
def arc_agi_3_retired_api(legacy_path):
    del legacy_path
    return _retired_api_response()
