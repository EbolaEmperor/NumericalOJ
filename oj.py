#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, redirect, url_for, session
from celery import Celery

# config.py
from config import *
from oj_modules.db_services import (
    get_user_by_username,
    init_submission_snapshot_cache,
    is_class_adjust_enabled,
)
from oj_modules.routes.submission_routes import submission_bp
from oj_modules.routes.admin_problem_routes import admin_problem_bp
from oj_modules.routes.repository_routes import repository_bp
from oj_modules.routes.forum_routes import forum_bp
from oj_modules.routes.grading_routes import grading_bp
from oj_modules.routes.ai_routes import ai_bp
from oj_modules.routes.class_management_routes import class_management_bp
from oj_modules.routes.rejudge_routes import rejudge_bp, init_rejudge_module
from oj_modules.routes.admin_user_routes import admin_user_bp
from oj_modules.routes.homework_routes import homework_bp, init_homework_module
from oj_modules.routes.auth_routes import auth_bp
from oj_modules.routes.problem_core_routes import problem_core_bp, init_problem_core_module
from oj_modules.tasks import (
    init_agent_progress_cache,
    register_agent_solve_problem_task,
    register_evaluate_submission_task,
    register_written_homework_task,
)

import redis

# 假设 Redis 跑在 localhost:6379
# 根据需要添加密码、db 等
rds = redis.StrictRedis(host='127.0.0.1', port=6379, decode_responses=True)
# 用于存储二进制数据（如 ZIP 文件）的 Redis 连接
rds_binary = redis.StrictRedis(host='127.0.0.1', port=6379, decode_responses=False)

app = Flask(__name__)
app.secret_key = 'some_secret_key_for_session'
app.config['DEBUG'] = True
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024

# Celery 配置
CELERY_BROKER_URL = 'redis://localhost:6379/0'  # 根据您的 Redis 配置调整
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

# Blueprint 注册（路径保持不变）
app.register_blueprint(submission_bp)
app.register_blueprint(admin_problem_bp)
app.register_blueprint(repository_bp)
app.register_blueprint(forum_bp)
app.register_blueprint(grading_bp)
app.register_blueprint(ai_bp)
app.register_blueprint(class_management_bp)
app.register_blueprint(rejudge_bp)
app.register_blueprint(admin_user_bp)
app.register_blueprint(homework_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(problem_core_bp)

###############################################################################
#  站点设置（全局开关）
###############################################################################
@app.context_processor
def inject_globals():
    # 提供到所有模板：class_adjust_enabled
    try:
        return { 'class_adjust_enabled': is_class_adjust_enabled() }
    except Exception:
        return { 'class_adjust_enabled': True }

###############################################################################
#  会话 / 权限
###############################################################################
def current_user():
    """
    返回当前登录用户的完整记录(包含 is_admin 字段),或 None
    """
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)

###############################################################################
#  路由
###############################################################################
@app.route('/')
def index():
    user = current_user()
    if user:
        # 用户已登录，则跳转到题库列表
        return redirect(url_for('problem_core.problem_list'))
    else:
        # 用户未登录，则跳转到登录页
        return redirect(url_for('auth.login'))

###############################################################################
#  Celery 任务定义
###############################################################################
celery = Celery('oj', 
                broker=CELERY_BROKER_URL, 
                backend=CELERY_RESULT_BACKEND)
celery.conf.task_routes = {
    'oj.agent.solve_problem': {'queue': 'agent'},
}
evaluate_submission = register_evaluate_submission_task(celery)
transcribe_written_homework_to_latex = register_written_homework_task(celery)
agent_solve_problem = register_agent_solve_problem_task(celery, evaluate_submission)

# 初始化重测模块（依赖 Celery、Redis、评测函数）
init_rejudge_module(celery, rds, evaluate_submission)
# 初始化作业管理模块（依赖 Celery、Redis）
init_homework_module(celery, rds, rds_binary)
# 初始化题目核心模块（依赖 Celery 任务）
init_problem_core_module(evaluate_submission, transcribe_written_homework_to_latex, agent_solve_problem)
# 初始化 submission 状态快照缓存（Redis）
init_submission_snapshot_cache(rds)
# 初始化 agent 运行状态缓存（Redis）
init_agent_progress_cache(rds)

###############################################################################
#  班级管理
###############################################################################
if __name__ == '__main__':
    # 在生产环境中，请先开放 2025 端口并在安全组、系统防火墙中放行。
    app.run(host='0.0.0.0', port=2025)
