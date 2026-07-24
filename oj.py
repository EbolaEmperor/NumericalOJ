#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import secrets

from flask import Flask, jsonify, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException
from celery import Celery

# config.py
from config import *
import config as _cfg
from oj_modules.observability import (
    configure_logging,
    install_celery_observability,
    install_flask_observability,
)
os.environ.setdefault('NUMOJ_SERVICE_NAME', 'web')
configure_logging(level=getattr(_cfg, 'LOG_LEVEL', 'INFO'))

from oj_modules.db_services import (
    get_db_connection,
    init_submission_snapshot_cache,
    is_class_adjust_enabled,
)
from oj_modules.auth_helpers import current_user
from oj_modules.routes.submission_routes import submission_bp
from oj_modules.routes.admin_problem_routes import admin_problem_bp
from oj_modules.routes.repository_routes import repository_bp, init_repository_index_module
from oj_modules.routes.forum_routes import forum_bp
from oj_modules.routes.grading_routes import grading_bp
from oj_modules.routes.ai_routes import ai_bp, init_ai_module
from oj_modules.routes.class_management_routes import class_management_bp
from oj_modules.routes.rejudge_routes import rejudge_bp, init_rejudge_module
from oj_modules.routes.admin_user_routes import admin_user_bp
from oj_modules.routes.homework_routes import homework_bp, init_homework_module
from oj_modules.routes.auth_routes import auth_bp, init_auth_module
from oj_modules.routes.editor_language_routes import (
    editor_language_bp,
    init_editor_language_module,
)
from oj_modules.routes.problem_core_routes import problem_core_bp, init_problem_core_module
from oj_modules.routes.ai_detection_routes import ai_detection_bp, init_ai_detection_module
from oj_modules.routes.game_routes import game_bp
from oj_modules.routes.ranking_routes import ranking_bp, init_ranking_module
from oj_modules.routes.health_routes import create_health_blueprint
from oj_modules.request_auth import install_global_login_guard
from oj_modules.request_security import install_same_origin_protection
from oj_modules.redis_clients import (
    create_binary_redis_client,
    create_blocking_redis_client,
    create_text_redis_client,
)
from oj_modules.api import API_BLUEPRINTS
from oj_modules.tasks import (
    init_agent_progress_cache,
    register_agent_generate_testdata_task,
    register_repository_index_build_task,
    register_agent_solve_problem_task,
    register_evaluate_submission_task,
    register_promptly_generate_submission_task,
    register_written_homework_task,
    register_ai_detection_tasks,
    register_ranking_evaluate_task,
    register_ranking_elo_match_task,
    register_ranking_elo_initial_burst_task,
    register_ranking_elo_matchmaker_tick_task,
    seed_elo_matchmaker_tick,
    register_ranking_agent_judge_task,
    register_ranking_agent_judge_paused_probe_task,
    seed_agent_judge_paused_probe,
    init_judge_progress_cache,
    register_ranking_reverse_judge_task,
    init_reverse_judge_progress_cache,
    register_ranking_batch_tasks,
    init_batch_progress_cache,
    register_ranking_bulk_rejudge_task,
    init_bulk_rejudge_progress_cache,
)
from oj_modules.startup_requeue import (
    requeue_pending_on_startup,
    register_pending_requeue_watchdog_task,
    seed_pending_requeue_watchdog,
)

# Redis 连接
rds = create_text_redis_client()
# 用于存储二进制数据（如 ZIP 文件）的 Redis 连接
rds_binary = create_binary_redis_client()
# 用于 Pub/Sub 等可能阻塞的读取，避免普通请求的短读超时中断长轮询。
rds_blocking = create_blocking_redis_client()

def _load_secret_key():
    """会话签名密钥来源（按优先级）：
    1. .env 的 SECRET_KEY（生产环境必须设置固定值）；
    2. <OJ_ROOT>/tmp/secret_key 文件（首次自动生成并持久化，跨重启稳定、且不入 git）。
    绝不再使用历史硬编码常量，否则任何人都能伪造管理员会话 cookie。"""
    key = getattr(_cfg, 'SECRET_KEY', None)
    if key:
        return key
    key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp', 'secret_key')
    try:
        with open(key_path, 'r') as f:
            saved = f.read().strip()
        if saved:
            return saved
    except FileNotFoundError:
        pass
    new_key = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        with open(key_path, 'w') as f:
            f.write(new_key)
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    return new_key


app = Flask(__name__)
app.secret_key = _load_secret_key()
# DEBUG 默认关闭：生产环境绝不能开 Werkzeug 交互式调试器（源码/变量泄露 + RCE 控制台）。
# 本地开发可在 .env 设 FLASK_DEBUG=true。
app.config['DEBUG'] = bool(getattr(_cfg, 'FLASK_DEBUG', False))
# 即便 DEBUG 关闭也保留模板热重载，保证「scp 模板即生效」的前端快速路径不受影响。
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024
# 会话 Cookie 加固：HttpOnly 防 JS 窃取；SameSite=Lax 阻断跨站 POST CSRF；
# Secure 仅在 HTTPS 下回传（默认关闭以兼容内网 HTTP，部署 HTTPS 后可在 .env 置 true）。
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=bool(getattr(_cfg, 'SESSION_COOKIE_SECURE', False)),
)
install_flask_observability(
    app,
    trusted_proxy_cidrs=getattr(_cfg, 'LOG_TRUSTED_PROXY_CIDRS', ()),
)
install_global_login_guard(app, user_loader=current_user)
install_same_origin_protection(
    app,
    trusted_origins=getattr(_cfg, 'CSRF_TRUSTED_ORIGINS', ()),
)

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
app.register_blueprint(editor_language_bp)
app.register_blueprint(problem_core_bp)
app.register_blueprint(ai_detection_bp)
app.register_blueprint(game_bp)
app.register_blueprint(ranking_bp)
app.register_blueprint(create_health_blueprint(rds, get_db_connection))
for _api_bp in API_BLUEPRINTS:
    app.register_blueprint(_api_bp)

###############################################################################
#  站点设置（全局开关）
###############################################################################
@app.context_processor
def inject_globals():
    try:
        class_adjust_enabled = is_class_adjust_enabled()
    except Exception:
        class_adjust_enabled = True
    return {'class_adjust_enabled': class_adjust_enabled}


# 默认 CSP：考虑到现有页面大量内联脚本/样式与本地打包资源，采用「不破坏现网」的宽松策略，
# 但仍通过 object-src/frame-ancestors/base-uri 缓解点击劫持与 base 标签劫持。可在 .env
# 用 CONTENT_SECURITY_POLICY 覆盖以逐步收紧。
_DEFAULT_CSP = (
    "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:; "
    "img-src 'self' data: blob: https:; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
)
_CONTENT_SECURITY_POLICY = (
    getattr(_cfg, 'CONTENT_SECURITY_POLICY', None) or _DEFAULT_CSP
)


@app.errorhandler(Exception)
def _handle_unexpected_error(e):
    # HTTP 异常（404/403/abort 等）按原样返回，保持各自语义。
    if isinstance(e, HTTPException):
        return e
    # 其余为未处理异常：服务端记录完整堆栈，对外只返回通用文案，绝不泄露堆栈/SQL 片段。
    try:
        app.logger.exception('未处理的服务器错误')
    except Exception:
        pass
    accept = request.headers.get('Accept', '') or ''
    wants_json = ('application/json' in accept and 'text/html' not in accept) \
        or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if wants_json:
        return jsonify(success=False, message='服务器内部错误，请稍后再试'), 500
    try:
        return render_template('shared/error.html', message='服务器内部错误，请稍后再试'), 500
    except Exception:
        return '服务器内部错误，请稍后再试', 500


@app.after_request
def _set_security_headers(resp):
    # 这些响应头不破坏现有功能，提供基础纵深防御。
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    if _CONTENT_SECURITY_POLICY:
        resp.headers.setdefault('Content-Security-Policy', _CONTENT_SECURITY_POLICY)
    return resp

###############################################################################
#  会话 / 权限
###############################################################################
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
install_celery_observability(
    celery,
    level=getattr(_cfg, 'LOG_LEVEL', 'INFO'),
)
celery.conf.task_routes = {
    'oj.agent.solve_problem': {'queue': 'agent'},
    'oj.agent.generate_testdata': {'queue': 'agent'},
    'oj.promptly.generate_submission': {'queue': 'agent'},
    'oj.ranking_agent_judge': {'queue': 'judge'},
    'oj.ranking_agent_judge_paused_probe': {'queue': 'judge'},
    'oj.ranking_reverse_judge': {'queue': 'judge'},
}
# 任务执行完才 ack：worker 崩溃/被硬超时 SIGKILL 时，消息不会丢失而是重新投递。
# 配合各任务的 Redis 幂等锁，重投不会导致重复评测；reject_on_worker_lost 让「worker 丢失」
# 的任务被重新入队而非静默丢弃。（各任务 wall-clock 上限远小于 broker 可见性超时，安全。）
celery.conf.task_acks_late = True
celery.conf.task_reject_on_worker_lost = True
evaluate_submission = register_evaluate_submission_task(celery)
transcribe_written_homework_to_latex = register_written_homework_task(celery)
promptly_generate_submission = register_promptly_generate_submission_task(celery, evaluate_submission)
agent_solve_problem = register_agent_solve_problem_task(celery, evaluate_submission)
agent_generate_testdata = register_agent_generate_testdata_task(celery, evaluate_submission)
build_repository_index = register_repository_index_build_task(celery)
detect_single_submission, detect_batch_for_problem, detect_batch_for_user, detect_filtered_submissions = register_ai_detection_tasks(celery)
evaluate_ranking_submission = register_ranking_evaluate_task(celery)
ranking_elo_match = register_ranking_elo_match_task(celery)
ranking_elo_initial_burst = register_ranking_elo_initial_burst_task(celery, ranking_elo_match)
ranking_elo_matchmaker_tick = register_ranking_elo_matchmaker_tick_task(celery, ranking_elo_match)
evaluate_ranking_agent_judge = register_ranking_agent_judge_task(celery)
ranking_agent_judge_paused_probe = register_ranking_agent_judge_paused_probe_task(celery)
evaluate_ranking_reverse_judge = register_ranking_reverse_judge_task(celery)
# 打榜赛「批量评测」：探测仓库 + 串行批量拉取/创建（拉取完成后接力 Agent 评测）
ranking_batch_probe, ranking_batch_run = register_ranking_batch_tasks(
    celery,
    agent_judge_task=evaluate_ranking_agent_judge,
    reverse_judge_task=evaluate_ranking_reverse_judge,
)
ranking_bulk_rejudge = register_ranking_bulk_rejudge_task(
    celery,
    evaluate_ranking_submission,
    agent_judge_task=evaluate_ranking_agent_judge,
    reverse_judge_task=evaluate_ranking_reverse_judge,
    elo_initial_burst_task=ranking_elo_initial_burst,
)
pending_requeue_watchdog = register_pending_requeue_watchdog_task(
    celery,
    evaluate_submission,
    transcribe_written_homework_to_latex,
    promptly_task=promptly_generate_submission,
    ranking_task=evaluate_ranking_submission,
    elo_initial_burst_task=ranking_elo_initial_burst,
    agent_judge_task=evaluate_ranking_agent_judge,
    reverse_judge_task=evaluate_ranking_reverse_judge,
)

# 初始化重测模块（依赖 Celery、Redis、程序题评测 + 书面作业转写评分任务）
init_rejudge_module(celery, rds, evaluate_submission, transcribe_written_homework_to_latex)
# 初始化作业管理模块（依赖 Celery、Redis）
init_homework_module(celery, rds, rds_binary)
# 初始化题目核心模块（依赖 Celery 任务）
init_problem_core_module(
    evaluate_submission,
    transcribe_written_homework_to_latex,
    promptly_generate_submission,
    agent_solve_problem,
    agent_generate_testdata,
)
# 初始化代码仓库结构化整理模块（依赖 Celery 任务）
init_repository_index_module(build_repository_index)
# 初始化 AI 检测模块（依赖 Celery 任务）
init_ai_detection_module(detect_single_submission, detect_batch_for_problem, detect_batch_for_user, detect_filtered_submissions)
# 初始化打榜赛模块（依赖 Celery 评测任务、ELO 即时补战任务、Agent 评测任务、批量评测任务）
init_ranking_module(
    evaluate_ranking_submission, ranking_elo_initial_burst, evaluate_ranking_agent_judge,
    reverse_judge_task=evaluate_ranking_reverse_judge,
    redis_client=rds,
    batch_probe_task=ranking_batch_probe, batch_run_task=ranking_batch_run,
    bulk_rejudge_task=ranking_bulk_rejudge,
)
# 初始化认证模块（登录/发码限流依赖 Redis）
init_auth_module(rds)
# 初始化 AI 模块（ask_ai_code_marks 限流依赖 Redis）
init_ai_module(rds)
init_editor_language_module(rds)
# 初始化 submission 状态快照缓存（Redis）
init_submission_snapshot_cache(rds, blocking_client=rds_blocking)
# 初始化 agent 运行状态缓存（Redis）
init_agent_progress_cache(rds, blocking_client=rds_blocking)
# 初始化打榜赛 Agent 评测进度缓存（Redis）
init_judge_progress_cache(rds, blocking_client=rds_blocking)
# 初始化打榜赛反向评测进度缓存（Redis）
init_reverse_judge_progress_cache(rds, blocking_client=rds_blocking)
# 初始化打榜赛「批量评测」探测进度缓存（Redis）
init_batch_progress_cache(rds)
# 初始化打榜赛「批量重测」进度缓存（Redis）
init_bulk_rejudge_progress_cache(rds)

###############################################################################
#  班级管理
###############################################################################


def ensure_background_schedulers():
    """幂等确保后台自调度链存在；Web worker 重建时重复调用也安全。"""
    # 启动 ELO 匹配 tick 链路（自调度，全局单链）。
    seed_elo_matchmaker_tick(
        rds,
        ranking_elo_matchmaker_tick,
        reset_owner=False,
    )

    # 不重置已有 owner。Gunicorn worker 重建不等于 Celery 已全部停止，不能借此
    # 清运行锁或另起一条调度链。
    seed_pending_requeue_watchdog(
        rds,
        pending_requeue_watchdog,
        reset_owner=False,
        countdown=180,
    )
    seed_agent_judge_paused_probe(
        rds,
        ranking_agent_judge_paused_probe,
        reset_owner=False,
        countdown=300,
    )


def recover_pending_after_all_workers_stopped():
    """在已确认所有 Celery worker 停止后执行破坏性恢复并重建调度链。

    该入口会清理运行锁、重置 Running 状态并重新投递任务，不能挂到 Web/Gunicorn
    生命周期。运维只能通过带停机确认的 ``scripts/recover_pending_tasks.py`` 调用。
    """
    requeue_pending_on_startup(
        evaluate_task=evaluate_submission,
        written_task=transcribe_written_homework_to_latex,
        promptly_task=promptly_generate_submission,
        ranking_task=evaluate_ranking_submission,
        elo_initial_burst_task=ranking_elo_initial_burst,
        agent_judge_task=evaluate_ranking_agent_judge,
        reverse_judge_task=evaluate_ranking_reverse_judge,
    )
    seed_elo_matchmaker_tick(
        rds,
        ranking_elo_matchmaker_tick,
        reset_owner=True,
    )
    # 完整 worker 停机后，旧链已经死亡；换新 owner，让残留 ETA 消息醒来后 no-op。
    seed_pending_requeue_watchdog(
        rds,
        pending_requeue_watchdog,
        reset_owner=True,
        countdown=180,
    )
    # 每小时探测暂停的 Agent 评测端点并按健康度自动恢复。
    seed_agent_judge_paused_probe(
        rds,
        ranking_agent_judge_paused_probe,
        reset_owner=True,
        countdown=300,
    )


if __name__ == '__main__':
    # 仅确保幂等的后台调度链存在；破坏性任务恢复必须走显式运维脚本。
    # 只在真正提供服务的进程里执行：
    #   - Celery worker 以 `oj.celery` 方式 import 本模块，__name__ != '__main__'，
    #     不会进入这里；
    #   - debug 模式下 Werkzeug reloader 会让父子两个进程都跑 __main__，用
    #     WERKZEUG_RUN_MAIN 守卫，只在真正服务的子进程里跑一次。
    if (not app.debug) or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        ensure_background_schedulers()
    # 在生产环境中，请先开放 2025 端口并在安全组、系统防火墙中放行。
    app.run(host='0.0.0.0', port=2025)
