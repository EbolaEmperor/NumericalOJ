#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from backend.oj_modules.api.admin_api import admin_api_bp
from backend.oj_modules.api.ai_detection_api import ai_detection_api_bp
from backend.oj_modules.api.forum_api import forum_api_bp
from backend.oj_modules.api.homework_api import homework_api_bp
from backend.oj_modules.api.problem_api import problem_api_bp
from backend.oj_modules.api.ranking_api import ranking_api_bp
from backend.oj_modules.api.repository_api import repository_api_bp
from backend.oj_modules.api.submission_api import submission_api_bp
from backend.oj_modules.api.vibehub_api import vibehub_api_bp
from backend.oj_modules.api.spa_api import spa_api_bp


API_BLUEPRINTS = (
    spa_api_bp,
    admin_api_bp,
    ai_detection_api_bp,
    forum_api_bp,
    homework_api_bp,
    problem_api_bp,
    ranking_api_bp,
    repository_api_bp,
    submission_api_bp,
    vibehub_api_bp,
)
