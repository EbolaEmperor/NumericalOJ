#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint

from config import REPOSITORY_MAX_FILE_BYTES
from oj_modules.api.helpers import json_error, json_success, public_user
from oj_modules.security.auth import current_user
from oj_modules.repository.settings import (
    DEFAULT_SEARCH_SCORE_THRESHOLD,
    DEFAULT_SEARCH_TOP_K,
)


repository_api_bp = Blueprint("repository_api", __name__, url_prefix="/api/repository")


@repository_api_bp.route("/context", methods=["GET"])
def repository_context():
    user = current_user()
    if not user:
        return json_error("未登录", 401)
    return json_success(
        user=public_user(user),
        page="code_repository",
        files_api="/api/repository/files",
        tree_api="/api/repository/tree",
        file_api="/api/repository/file/<file_id>",
        upload_api="/api/repository/upload",
        upload_session_api="/api/repository/upload/session",
        index_apis={
            "build": "/api/repository/index/build",
            "rebuild_file": "/api/repository/index/rebuild_file",
            "active_status": "/api/repository/index/status/active",
            "search": "/api/repository/index/search",
            "classes": "/api/repository/index/classes",
        },
        defaults={
            "search_top_k": DEFAULT_SEARCH_TOP_K,
            "search_score_threshold": DEFAULT_SEARCH_SCORE_THRESHOLD,
        },
        allowed_extensions=None,
        indexable_extensions=[".h", ".hpp", ".c", ".cpp"],
        max_file_size_bytes=REPOSITORY_MAX_FILE_BYTES,
    )
