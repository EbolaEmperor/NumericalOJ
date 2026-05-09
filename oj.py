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
from oj_modules.routes.repository_routes import repository_bp, init_repository_index_module
from oj_modules.routes.forum_routes import forum_bp
from oj_modules.routes.grading_routes import grading_bp
from oj_modules.routes.ai_routes import ai_bp
from oj_modules.routes.class_management_routes import class_management_bp
from oj_modules.routes.rejudge_routes import rejudge_bp, init_rejudge_module
from oj_modules.routes.admin_user_routes import admin_user_bp
from oj_modules.routes.homework_routes import homework_bp, init_homework_module
from oj_modules.routes.auth_routes import auth_bp
from oj_modules.routes.problem_core_routes import problem_core_bp, init_problem_core_module
from oj_modules.routes.ai_detection_routes import ai_detection_bp, init_ai_detection_module
from oj_modules.routes.game_routes import game_bp
from oj_modules.routes.ranking_routes import ranking_bp, init_ranking_module
from oj_modules.tasks import (
    init_agent_progress_cache,
    register_agent_generate_testdata_task,
    register_repository_index_build_task,
    register_agent_solve_problem_task,
    register_evaluate_submission_task,
    register_written_homework_task,
    register_ai_detection_tasks,
    register_ranking_evaluate_task,
    register_ranking_elo_match_task,
    register_ranking_elo_initial_burst_task,
    register_ranking_elo_matchmaker_tick_task,
    seed_elo_matchmaker_tick,
)

import redis

# Redis 连接
rds = redis.StrictRedis(host=REDIS_HOST, port=int(REDIS_PORT), db=int(REDIS_DB), decode_responses=True)
# 用于存储二进制数据（如 ZIP 文件）的 Redis 连接
rds_binary = redis.StrictRedis(
    host=REDIS_HOST,
    port=int(REDIS_PORT),
    db=int(REDIS_DB),
    decode_responses=False,
)

app = Flask(__name__)
app.secret_key = 'some_secret_key_for_session'
app.config['DEBUG'] = True
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024

# Celery 配置
_REDIS_URL = f"redis://{REDIS_HOST}:{int(REDIS_PORT)}/{int(REDIS_DB)}"
CELERY_BROKER_URL = _REDIS_URL
CELERY_RESULT_BACKEND = _REDIS_URL

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
app.register_blueprint(ai_detection_bp)
app.register_blueprint(game_bp)
app.register_blueprint(ranking_bp)

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
    'oj.agent.generate_testdata': {'queue': 'agent'},
}
evaluate_submission = register_evaluate_submission_task(celery)
transcribe_written_homework_to_latex = register_written_homework_task(celery)
agent_solve_problem = register_agent_solve_problem_task(celery, evaluate_submission)
agent_generate_testdata = register_agent_generate_testdata_task(celery, evaluate_submission)
build_repository_index = register_repository_index_build_task(celery)
detect_single_submission, detect_batch_for_problem, detect_batch_for_user, detect_filtered_submissions = register_ai_detection_tasks(celery)
evaluate_ranking_submission = register_ranking_evaluate_task(celery)
ranking_elo_match = register_ranking_elo_match_task(celery)
ranking_elo_initial_burst = register_ranking_elo_initial_burst_task(celery, ranking_elo_match)
ranking_elo_matchmaker_tick = register_ranking_elo_matchmaker_tick_task(celery, ranking_elo_match)

# 初始化重测模块（依赖 Celery、Redis、评测函数）
init_rejudge_module(celery, rds, evaluate_submission)
# 初始化作业管理模块（依赖 Celery、Redis）
init_homework_module(celery, rds, rds_binary)
# 初始化题目核心模块（依赖 Celery 任务）
init_problem_core_module(
    evaluate_submission,
    transcribe_written_homework_to_latex,
    agent_solve_problem,
    agent_generate_testdata,
)
# 初始化代码仓库结构化整理模块（依赖 Celery 任务）
init_repository_index_module(build_repository_index)
# 初始化 AI 检测模块（依赖 Celery 任务）
init_ai_detection_module(detect_single_submission, detect_batch_for_problem, detect_batch_for_user, detect_filtered_submissions)
# 初始化打榜赛模块（依赖 Celery 评测任务、ELO 即时补战任务）
init_ranking_module(evaluate_ranking_submission, ranking_elo_initial_burst)
# 启动 ELO 匹配 tick 链路（自调度，全局单链）
seed_elo_matchmaker_tick(rds, ranking_elo_matchmaker_tick)
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
