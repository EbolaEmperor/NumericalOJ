#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打榜赛（Ranking Competition）路由。
"""

import copy
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime

from flask import (
    Blueprint, Response, abort, current_app, flash, jsonify, redirect,
    render_template, request, send_file, stream_with_context, url_for,
)
from werkzeug.utils import secure_filename

from oj_modules import config as _cfg
from oj_modules.db_services import (
    get_all_classes, get_user_by_username, get_users_in_classes,
)
from oj_modules.infrastructure.redis import create_optional_redis_client
from oj_modules.security.auth import current_user
from oj_modules.security.throttling import rate_limit_hit
from oj_modules.ranking.db import (
    activate_elo_submission,
    competition_attachments_dir,
    competition_dir,
    competition_reference_dir,
    competition_scoring_dir,
    copy_competition,
    create_appeal,
    create_competition,
    create_competition_file,
    create_ranking_artifact_submission,
    delete_competition,
    delete_competition_file,
    delete_elo_match_and_revert,
    delete_ranking_submission,
    get_appeal,
    get_appeal_by_submission,
    get_appeal_stats,
    begin_agent_judge_attempt,
    get_competition,
    get_competition_file,
    get_competition_match,
    get_leaderboard,
    get_ranking_navigation_state,
    get_ranking_submission,
    get_submission_quota,
    get_submission_stats,
    invalidate_ranking_submission_attempt,
    list_submissions_for_bulk_rejudge,
    list_appeals,
    list_all_submissions,
    list_competition_files,
    list_competition_matches,
    list_competitions,
    list_elo_matches_for_submission,
    list_user_submissions,
    rebuild_elo_history,
    reset_competition_limit_window,
    reset_elo_state,
    release_standard_ranking_evaluation,
    reserve_standard_ranking_evaluation,
    resolve_appeal,
    RankingSubmissionCommitUnknown,
    RankingSubmissionQuotaExceeded,
    set_elo_running,
    set_agent_judge_task_id,
    set_submission_status,
    submission_dir,
    update_competition,
    update_competition_reference_answer,
    update_competition_scoring_script,
    update_submission_result,
)
from oj_modules.ranking.agent_judge.db import (
    agent_judge_trace_id,
    apply_rule_overrides,
    build_judge_snapshot,
    global_agent_endpoint_candidates,
    list_agent_judge_endpoints,
    list_competition_rules,
    list_quality_gate_endpoints,
    replace_competition_rules,
    save_agent_judge_configuration,
    save_reverse_quality_gate_configuration,
)
from oj_modules.ranking.agent_judge.rules import max_score as _aj_max_score
from oj_modules.ranking.agent_judge.rules import normalize_orchestration_mode as _normalize_aj_orchestration
from oj_modules.ranking.agent_judge.rules import render_snapshot_html as _render_snapshot_html
from oj_modules.ranking.artifacts import (
    INLINE_MEDIA_MIME as _INLINE_MEDIA_MIME,
    attachment_media_kind as _attachment_media_kind,
    can_access_submission as _can_access_submission,
    resolve_reverse_agent_answer_archive,
    send_reverse_agent_answer_archive,
)
from oj_modules.ranking.batch import (
    BATCH_DEFAULT_TEMPLATE,
    PLACEHOLDER as BATCH_PLACEHOLDER,
    USERNAME_RE as BATCH_USERNAME_RE,
    build_repo_url,
    repo_last_commit,
)
from oj_modules.ranking.match_details import normalize_match_detail_output
from oj_modules.ranking.matches import (
    fetch_competition_match_detail_cached,
    fetch_competition_matches_cached,
    init_match_cache,
    invalidate_competition_match_caches as _invalidate_competition_match_caches,
)
from oj_modules.ranking.presentation import (
    ALLOWED_TABS,
    MATCHES_PER_PAGE,
    SUBMISSIONS_PER_PAGE,
    competition_answer_format as _competition_answer_format,
    competition_scoring_mode as _competition_scoring_mode,
    masked_agent_endpoints as _canonical_masked_agent_endpoints,
    normalize_answer_format as _normalize_answer_format,
    normalize_scoring_mode as _normalize_scoring_mode,
    page_window as _page_window,
    render_description as _render_description,
    submission_quota_message as _submission_quota_message,
)
from oj_modules.ranking.readiness import (
    agent_judge_endpoint_ready as _agent_judge_endpoint_ready,
    configured_file as _configured_file,
    fake_agent_judge_enabled as _fake_agent_judge_enabled,
    quality_gate_endpoint_ready as _quality_gate_endpoint_ready,
    ranking_submit_block_reason as _ranking_submit_block_reason,
    reverse_quality_gate_block_reason as _canonical_reverse_quality_gate_block_reason,
    reverse_quality_gate_enabled as _reverse_quality_gate_enabled,
    reverse_quality_gate_ready as _canonical_reverse_quality_gate_ready,
)
from oj_modules.ranking.reverse_judge.service import build_reverse_judge_snapshot


ranking_bp = Blueprint('ranking', __name__, url_prefix='/ranking')

# 标签页、分页和批量仓库文案由 ranking.presentation / ranking.batch 统一提供。
# 对战列表 / 详情的 Redis 缓存
# scope 用于区分 "全部" 和 "与我相关"：scope = '' 或 user:<username>
# 所有可见客户端共享同一份全局导航快照，避免每个 10s 轮询都重复执行多表聚合。
# 生产 Web 是单进程 gthread；按比赛分锁既能合并并发 miss，也不会阻塞其它比赛。
RANKING_NAVIGATION_STATE_CACHE_TTL = 5.0
RANKING_NAVIGATION_STATE_CACHE_MAX = 256
_ranking_navigation_state_cache = {}
_ranking_navigation_state_cache_guard = threading.Lock()
_ranking_navigation_state_locks = tuple(threading.Lock() for _ in range(32))
ANSWER_MAX_BYTES = 64 * 1024 * 1024        # 64MB
CODE_ZIP_MAX_BYTES = 128 * 1024 * 1024     # 128MB
ATTACHMENT_MAX_BYTES = 256 * 1024 * 1024   # 256MB
SCORING_SCRIPT_MAX_BYTES = 4 * 1024 * 1024 # 4MB
REFERENCE_MAX_BYTES = 64 * 1024 * 1024     # 64MB

# ELO 参数取值范围
ELO_INITIAL_RATING_RANGE = (100.0, 5000.0)
ELO_K_FACTOR_RANGE = (1.0, 200.0)
ELO_MAX_MATCHES_RANGE = (1, 10000)
ELO_MATCH_INTERVAL_RANGE = (5, 3600)
ELO_INITIAL_BURST_RANGE = (0, 50)
ELO_MAX_PAIRS_PER_ROUND_RANGE = (1, 8)   # 与 tasks.ranking.elo.MAX_PAIRS_PER_ROUND 保持一致
# 回合制比赛整场时限 ≈ 回合上限 × 2 × 单回合时限 + 启动余量，600 秒不够。
SCORING_SCRIPT_TIMEOUT_RANGE = (5, 1800)
REVERSE_FINALIZE_TIMEOUT_DEFAULT = 180
REVERSE_FINALIZE_TIMEOUT_RANGE = (30, 7200)
REVERSE_JUDGE_SCRIPT_TIMEOUT_DEFAULT = int(
    getattr(_cfg, 'REVERSE_JUDGE_SCRIPT_TIMEOUT', 300)
)
REVERSE_AGENT_TIMEOUT_DEFAULT = int(
    getattr(_cfg, 'AGENT_JUDGE_DEFAULT_TIMEOUT', 1800)
)
REVERSE_QUALITY_GATE_TIMEOUT_DEFAULT = max(
    10, int(getattr(_cfg, 'REVERSE_QUALITY_GATE_TIMEOUT_SECONDS', 300))
)
REVERSE_STREAM_MIN_TIMEOUT_SECONDS = 3600
# 与任务侧的两个模型槽位 TTL 余量保持同一数量级，覆盖容器收尾、SSE 发布延迟
# 以及 abort 重试前后的状态切换。
REVERSE_STREAM_TIMEOUT_BUFFER_SECONDS = max(
    120,
    int(getattr(_cfg, 'REVERSE_JUDGE_STREAM_TIMEOUT_BUFFER_SECONDS', 1200)),
)


def _reverse_judge_stream_timeout_seconds(comp):
    """返回覆盖反向评测完整合法执行路径的 SSE 等待上限。"""
    comp = comp or {}
    judge_timeout = int(
        comp.get('scoring_script_timeout_seconds')
        or REVERSE_JUDGE_SCRIPT_TIMEOUT_DEFAULT
    )
    agent_timeout = int(
        comp.get('agent_judge_timeout_seconds')
        or REVERSE_AGENT_TIMEOUT_DEFAULT
    )
    finalize_timeout = int(
        comp.get('reverse_judge_finalize_timeout_seconds')
        or REVERSE_FINALIZE_TIMEOUT_DEFAULT
    )
    quality_gate_timeout = (
        REVERSE_QUALITY_GATE_TIMEOUT_DEFAULT
        if _reverse_quality_gate_enabled(comp) else 0
    )
    legal_upper_bound = (
        judge_timeout * 2
        + agent_timeout * 2
        + finalize_timeout
        + quality_gate_timeout
        + REVERSE_STREAM_TIMEOUT_BUFFER_SECONDS
    )
    return max(REVERSE_STREAM_MIN_TIMEOUT_SECONDS, legal_upper_bound)


def _reverse_quality_gate_block_reason(competition_id, comp):
    return _canonical_reverse_quality_gate_block_reason(competition_id, comp)


def _reverse_quality_gate_ready(competition_id, comp):
    return _canonical_reverse_quality_gate_ready(competition_id, comp)


def _masked_agent_endpoints(endpoints):
    return _canonical_masked_agent_endpoints(endpoints)


def _request_agent_endpoint_id():
    raw = request.form.get('agent_endpoint_id')
    if raw is None and request.is_json:
        data = request.get_json(silent=True) or {}
        raw = data.get('agent_endpoint_id')
    try:
        eid = int(str(raw or '').strip())
    except (TypeError, ValueError):
        return None
    return eid if eid > 0 else None


def _validate_reverse_endpoint_choice(competition_id):
    endpoint_id = _request_agent_endpoint_id()
    if endpoint_id is None:
        return None, '请选择 AI 作答节点'
    try:
        endpoints = list_agent_judge_endpoints(competition_id)
    except Exception:
        endpoints = []
    for ep in endpoints:
        if int(ep.get('id') or 0) != endpoint_id:
            continue
        if str(ep.get('status') or '').lower() != 'enabled':
            return None, '选择的 AI 作答节点当前不可用'
        return endpoint_id, ''
    return None, '选择的 AI 作答节点不存在'


def _wants_json_response():
    if str(request.args.get('fragment') or '').strip() == '1':
        return True
    if request.path.rstrip('/').endswith('/navigation-state'):
        return True
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    accept = (request.headers.get('Accept') or '').lower()
    return 'application/json' in accept and 'text/html' not in accept


def _submit_error_response(competition_id, message, category='warning', status=400):
    if _wants_json_response():
        return jsonify(success=False, message=message), status
    flash(message, category)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))


def _submit_commit_unknown_response(competition_id, exc):
    """把 commit 结果未知呈现为可恢复的待确认状态，避免用户立即重复提交。"""
    submission_id = int(exc.submission_id)
    message = (
        f'提交 #{submission_id} 的状态暂时无法确认，请勿立即重复提交。'
        '系统会自动核验并补发评测；15 分钟后若历史提交仍不可见，再重试或联系管理员。'
    )
    current_app.logger.error(
        '打榜赛提交 commit 结果待确认',
        extra={'submission_id': submission_id, 'competition_id': int(competition_id)},
    )
    if _wants_json_response():
        return jsonify(
            success=False,
            pending_confirmation=True,
            submission_id=submission_id,
            message=message,
        ), 202
    flash(message, 'warning')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))


def _fake_agent_judge_delay_seconds():
    raw = os.getenv('NUMOJ_FAKE_AGENT_JUDGE_DELAY_SECONDS')
    if raw is None:
        raw = getattr(_cfg, 'NUMOJ_FAKE_AGENT_JUDGE_DELAY_SECONDS', 3600)
    try:
        delay = int(float(raw))
    except (TypeError, ValueError):
        delay = 3600
    return max(0, delay)


def _clamp(value, lo, hi):
    if value is None:
        return None
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _redis_client():
    return create_optional_redis_client(verify_connection=False)


def _ranking_navigation_state_lock(competition_id):
    key = int(competition_id)
    return _ranking_navigation_state_locks[key % len(_ranking_navigation_state_locks)]


def _get_ranking_navigation_state_cached(competition_id):
    """短暂复用不含用户配额的全局快照；返回副本，禁止请求间互相修改。"""
    key = int(competition_id)
    lock = _ranking_navigation_state_lock(key)
    with lock:
        now = time.monotonic()
        with _ranking_navigation_state_cache_guard:
            cached = _ranking_navigation_state_cache.get(key)
        if cached is not None and cached[0] > now:
            return copy.deepcopy(cached[1])

        state = get_ranking_navigation_state(key, None)
        if state is None:
            with _ranking_navigation_state_cache_guard:
                _ranking_navigation_state_cache.pop(key, None)
            return None
        snapshot = copy.deepcopy(state)
        with _ranking_navigation_state_cache_guard:
            expired = [
                cache_key
                for cache_key, (expires_at, _) in _ranking_navigation_state_cache.items()
                if expires_at <= now
            ]
            for cache_key in expired:
                _ranking_navigation_state_cache.pop(cache_key, None)
            while (
                len(_ranking_navigation_state_cache)
                >= RANKING_NAVIGATION_STATE_CACHE_MAX
                and key not in _ranking_navigation_state_cache
            ):
                oldest_key = min(
                    _ranking_navigation_state_cache,
                    key=lambda cache_key: _ranking_navigation_state_cache[cache_key][0],
                )
                _ranking_navigation_state_cache.pop(oldest_key, None)
            _ranking_navigation_state_cache[key] = (
                time.monotonic() + RANKING_NAVIGATION_STATE_CACHE_TTL,
                snapshot,
            )
        return copy.deepcopy(snapshot)


def _get_ranking_navigation_state_for_request(comp, user, is_admin, state=None):
    """组合共享全局快照与当前学生的轻量配额计数。"""
    competition_id = int((comp or {}).get('id') or 0)
    if state is None:
        state = _get_ranking_navigation_state_cached(competition_id)
    else:
        state = copy.deepcopy(state)
    if state is None:
        return None

    # 详情上下文使用刚读取的 competition；权限和 rail 模式必须与它保持一致，
    # 全局计数/revision 最多允许落后短 TTL。
    state['scoring_mode'] = _competition_scoring_mode(comp)
    state['is_active'] = int((comp or {}).get('is_active') or 0)
    if is_admin:
        state['quota'] = None
        return state

    # 测试/调用方可能已经提供了当前用户配额；生产共享快照不会包含它。
    if state.get('quota') is not None:
        return state
    quota = get_submission_quota(
        competition_id,
        (user or {}).get('username'),
        comp=comp,
    )
    if quota is None:
        state['quota'] = None
        return state

    state['quota'] = {
        'limit': int(quota.get('limit') or 0),
        'remaining': int(quota.get('remaining') or 0),
    }
    # 配额变化也必须触发学生端 rail badge/提交历史刷新，但不污染共享快照。
    state['revision'] = '{}:quota:{}:{}:{}'.format(
        state.get('revision') or '',
        int(quota.get('limit') or 0),
        int(quota.get('used') or 0),
        quota.get('window_start') or '',
    )
    return state


def _ranking_task_ref_for_mode(scoring_mode):
    mode = _normalize_scoring_mode(scoring_mode)
    if mode == 'reverse_judge' and _reverse_judge_task is not None:
        return _reverse_judge_task
    if mode == 'agent_judge' and _agent_judge_task is not None:
        return _agent_judge_task
    if mode == 'absolute' and _evaluate_ranking_task is not None:
        return _evaluate_ranking_task
    for task_ref in (_reverse_judge_task, _agent_judge_task, _evaluate_ranking_task):
        if task_ref is not None:
            return task_ref
    return None


def _revoke_ranking_task(task_id, scoring_mode):
    task_id = str(task_id or '').strip()
    if not task_id:
        return None
    task_ref = _ranking_task_ref_for_mode(scoring_mode)
    if task_ref is None:
        return '评测任务未初始化，无法撤销 Celery 任务'
    try:
        task_ref.app.control.revoke(task_id, terminate=True, signal='SIGTERM')
        return None
    except Exception as e:
        return f'撤销 Celery 任务失败：{e}'


def _docker_command(args, timeout=15):
    try:
        return subprocess.run(
            ['docker'] + list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
        ), None
    except FileNotFoundError:
        return None, 'Docker CLI 不存在'
    except subprocess.TimeoutExpired:
        return None, 'Docker 命令超时'
    except Exception as e:
        return None, f'Docker 命令失败：{e}'


def _docker_container_names_for_submission(submission_id):
    sid = int(submission_id)
    names = [f'aj_{sid}', f'rj_agent_{sid}']
    proc, error = _docker_command(['ps', '-a', '--format', '{{.Names}}'], timeout=10)
    if error:
        return names, error
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or '').strip()
        return names, f'Docker 容器列表读取失败：{message[-300:]}'
    prefixes = (f'aj_{sid}_', f'rj_judge_{sid}_')
    for line in (proc.stdout or '').splitlines():
        name = line.strip()
        if name.startswith(prefixes) and name not in names:
            names.append(name)
    return names, None


def _kill_ranking_submission_containers(submission_id):
    names, list_error = _docker_container_names_for_submission(submission_id)
    if list_error == 'Docker CLI 不存在':
        return [list_error]
    warnings = [list_error] if list_error else []
    seen = set()
    for name in names:
        if not name or name in seen:
            continue
        seen.add(name)
        proc, error = _docker_command(['rm', '-f', name], timeout=20)
        if error:
            warnings.append(f'清理容器 {name} 失败：{error}')
            continue
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout or '').strip()
            if 'No such container' not in message:
                warnings.append(f'清理容器 {name} 失败：{message[-300:]}')
    return warnings


def _clear_ranking_submission_runtime_keys(submission_id):
    sid = int(submission_id)
    client = _rds or _redis_client()
    if client is None:
        return ['Redis 不可用，无法清理评测锁和端点槽位']
    warnings = []
    keys = {
        f'ranking:judge:lock:{sid}',
        f'ranking:reverse_judge:lock:{sid}',
        f'ranking_submission:{sid}:pending_requeue',
        f'ranking_judge:{sid}',
        f'ranking_reverse_judge:{sid}',
    }
    try:
        for pattern in (
            f'ranking:judge:lock:{sid}:*',
            f'ranking:reverse_judge:lock:{sid}:*',
        ):
            for key in client.scan_iter(match=pattern, count=50):
                keys.add(key)
        for key in client.scan_iter(match='aj:ep:*:slot:*', count=200):
            try:
                value = client.get(key)
            except Exception:
                value = None
            if str(value or '').startswith(f'{sid}:'):
                keys.add(key)
        if keys:
            client.delete(*list(keys))
    except Exception as e:
        warnings.append(f'清理 Redis 运行态失败：{e}')
    return warnings


def _cancel_ranking_submission_runtime(submission, competition):
    """删除提交前中止仍在运行的后台评测。返回非致命清理告警。"""
    if not submission:
        return []
    status = str(submission.get('status') or '').strip()
    if status not in ('Queued', 'Judging'):
        return []

    sid = int(submission.get('id'))
    scoring_mode = _competition_scoring_mode(competition)
    task_id = str(submission.get('judge_task_id') or '').strip()
    warnings = []

    try:
        invalidate_ranking_submission_attempt(sid)
    except Exception as e:
        warnings.append(f'失效评测 attempt 失败：{e}')

    warning = _revoke_ranking_task(task_id, scoring_mode)
    if warning:
        warnings.append(warning)

    warnings.extend(_kill_ranking_submission_containers(sid))
    warnings.extend(_clear_ranking_submission_runtime_keys(sid))
    return [w for w in warnings if w]


def _normalize_dt(raw):
    text = str(raw or '').strip().replace('T', ' ')
    if not text:
        return None
    for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(text, fmt).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
    return None


def _format_dt(value):
    if not value:
        return ''
    try:
        return value.strftime('%Y-%m-%d %H:%M:%S')
    except AttributeError:
        return str(value)


def _normalize_bulk_status_groups(raw_groups):
    if raw_groups is None:
        return []
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]
    groups = []
    for item in raw_groups:
        key = str(item or '').strip().lower()
        if key in ('judging', 'waiting', 'accepted', 'abnormal') and key not in groups:
            groups.append(key)
    return groups


def _parse_submission_ids(raw_ids):
    ids = []
    seen = set()
    if not isinstance(raw_ids, list):
        return ids
    for item in raw_ids:
        try:
            sid = int(item)
        except (TypeError, ValueError):
            continue
        if sid > 0 and sid not in seen:
            seen.add(sid)
            ids.append(sid)
    return ids


def _serialize_bulk_ranking_submission(row, is_elo=False):
    score = row.get('elo_rating') if is_elo else row.get('score')
    return {
        'id': int(row.get('id') or 0),
        'username': row.get('username') or '',
        'status': row.get('status') or '',
        'score': score,
        'elo_match_count': int(row.get('elo_match_count') or 0),
        'base_model': row.get('base_model') or '',
        'created_at': _format_dt(row.get('created_at')),
    }


_evaluate_ranking_task = None
_elo_initial_burst_task = None
_agent_judge_task = None
_reverse_judge_task = None
_batch_probe_task = None
_batch_run_task = None
_bulk_rejudge_task = None


def _no_runtime_value(*_args, **_kwargs):
    return None


build_current_judge_snapshot = build_judge_snapshot
get_judge_progress_snapshot = build_judge_snapshot
subscribe_judge_run_events = _no_runtime_value
get_reverse_judge_progress_snapshot = build_reverse_judge_snapshot
subscribe_reverse_judge_events = _no_runtime_value
get_probe_job = _no_runtime_value
get_bulk_rejudge_job = _no_runtime_value
save_bulk_rejudge_job = _no_runtime_value

# Redis 客户端（提交限流）。由 oj.py 注入；为空时 fail-open。
_rds = None
# 打榜赛提交（尤其 agent_judge 每次起一个 Docker 评测）成本高，按用户+比赛限流。
_RANK_SUBMIT_MAX_PER_WINDOW = 10
_RANK_SUBMIT_WINDOW = 300
_BULK_REJUDGE_MAX_FILTER_RESULTS = 1000
_BULK_REJUDGE_MAX_SELECTED = 500
_BULK_REJUDGE_INTERVAL_SECONDS = 2


def init_ranking_module(evaluate_ranking_task, elo_initial_burst_task=None, agent_judge_task=None,
                        reverse_judge_task=None,
                        redis_client=None, batch_probe_task=None, batch_run_task=None,
                        bulk_rejudge_task=None,
                        judge_progress_reader=None, judge_event_subscriber=None,
                        current_judge_snapshot_builder=None,
                        reverse_progress_reader=None, reverse_event_subscriber=None,
                        batch_job_reader=None, bulk_job_reader=None,
                        bulk_job_writer=None):
    global _evaluate_ranking_task, _elo_initial_burst_task, _agent_judge_task, _reverse_judge_task, _rds
    global _batch_probe_task, _batch_run_task, _bulk_rejudge_task
    global build_current_judge_snapshot, get_judge_progress_snapshot
    global subscribe_judge_run_events, get_reverse_judge_progress_snapshot
    global subscribe_reverse_judge_events, get_probe_job
    global get_bulk_rejudge_job, save_bulk_rejudge_job
    _evaluate_ranking_task = evaluate_ranking_task
    _elo_initial_burst_task = elo_initial_burst_task
    _agent_judge_task = agent_judge_task
    _reverse_judge_task = reverse_judge_task
    _batch_probe_task = batch_probe_task
    _batch_run_task = batch_run_task
    _bulk_rejudge_task = bulk_rejudge_task
    build_current_judge_snapshot = current_judge_snapshot_builder or build_judge_snapshot
    get_judge_progress_snapshot = judge_progress_reader or build_judge_snapshot
    subscribe_judge_run_events = judge_event_subscriber or _no_runtime_value
    get_reverse_judge_progress_snapshot = (
        reverse_progress_reader or build_reverse_judge_snapshot
    )
    subscribe_reverse_judge_events = reverse_event_subscriber or _no_runtime_value
    get_probe_job = batch_job_reader or _no_runtime_value
    get_bulk_rejudge_job = bulk_job_reader or _no_runtime_value
    save_bulk_rejudge_job = bulk_job_writer or _no_runtime_value
    if redis_client is not None:
        _rds = redis_client
        init_match_cache(redis_client)


def _current_user():
    return current_user()


def _require_user():
    user = _current_user()
    if not user:
        if _wants_json_response():
            return None, (jsonify(success=False, message='请先登录'), 401)
        return None, redirect(url_for('auth.login'))
    return user, None


def _require_admin():
    user, resp = _require_user()
    if resp is not None:
        return None, resp
    if (user or {}).get('is_admin') != 1:
        if _wants_json_response():
            return None, (jsonify(success=False, message='需要管理员权限'), 403)
        flash('需要管理员权限', 'danger')
        return None, redirect(url_for('ranking.ranking_list'))
    return user, None


def _safe_filename(filename, fallback='file'):
    name = secure_filename(filename or '') or fallback
    # secure_filename 会把中文去掉，这里兜底一个默认名
    if not name.strip():
        name = fallback
    return name


def _ensure_dir(path):
    if path and not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)


def _create_uploaded_ranking_submission(
        competition_id, username, *, code_file, code_name,
        answer_file=None, answer_name=None, base_model=None,
        enforce_quota=False, agent_endpoint_id=None,
        code_label='代码文件', answer_label='答案文件'):
    """先完整暂存并校验上传文件，再在配额事务内登记提交。

    临时目录与最终提交目录位于同一文件系统，因此数据层可以用 ``os.replace`` 安装文件；
    无论上传、大小校验、配额检查或数据库元数据更新在哪一步失败，临时目录都会清理。
    """
    staging_root = os.path.dirname(submission_dir('staging'))
    _ensure_dir(staging_root)
    staging_dir = tempfile.mkdtemp(prefix='.upload-', dir=staging_root)

    # 答案格式也可能是 zip；两个上传使用同名文件时必须拆成不同目标名，避免后者覆盖前者。
    if answer_name and answer_name == code_name:
        answer_name = f'answer_{answer_name}'

    def _stage(upload, filename, max_bytes, label):
        path = os.path.join(staging_dir, filename)
        upload.save(path)
        size = os.path.getsize(path)
        if size > max_bytes:
            raise ValueError(f'{label}超过 {max_bytes // (1024 * 1024)}MB 限制')
        return path

    try:
        code_staged_path = _stage(
            code_file, code_name, CODE_ZIP_MAX_BYTES, code_label,
        )
        answer_staged_path = None
        if answer_file is not None:
            answer_staged_path = _stage(
                answer_file, answer_name, ANSWER_MAX_BYTES, answer_label,
            )
        return create_ranking_artifact_submission(
            competition_id,
            username,
            code_staged_path=code_staged_path,
            code_filename=code_name,
            answer_staged_path=answer_staged_path,
            answer_filename=answer_name,
            base_model=base_model,
            enforce_quota=enforce_quota,
            agent_endpoint_id=agent_endpoint_id,
        )
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


# ---------- 列表页 ----------

@ranking_bp.route('/', methods=['GET'])
def ranking_list():
    user, resp = _require_user()
    if resp is not None:
        return resp
    is_admin = user.get('is_admin') == 1
    competitions = list_competitions(include_inactive=is_admin)
    return render_template(
        'ranking/list.html',
        user=user,
        competitions=competitions,
    )


@ranking_bp.route('/create', methods=['POST'])
def ranking_create():
    user, resp = _require_admin()
    if resp is not None:
        return resp
    title = (request.form.get('title') or '').strip()
    summary = (request.form.get('summary') or '').strip()[:500] or None
    description = request.form.get('description') or ''
    max_score = request.form.get('max_score') or '100'
    if not title:
        flash('比赛标题不能为空', 'danger')
        return redirect(url_for('ranking.ranking_list'))
    try:
        max_score_int = int(max_score)
        if max_score_int <= 0:
            raise ValueError
    except ValueError:
        flash('满分必须是正整数', 'danger')
        return redirect(url_for('ranking.ranking_list'))
    new_id = create_competition(
        title=title,
        summary=summary,
        description=description,
        max_score=max_score_int,
        created_by=user.get('username'),
    )
    return redirect(url_for('ranking.ranking_detail', competition_id=new_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/copy', methods=['POST'])
def ranking_copy(competition_id):
    """管理员把一个打榜赛仅复制配置为一个「非公开」副本（不含提交记录与排行榜）。"""
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'danger')
        return redirect(url_for('ranking.ranking_list'))
    try:
        copy_competition(competition_id, created_by=user.get('username'))
    except Exception as e:
        flash(f'复制失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_list'))
    return redirect(url_for('ranking.ranking_list'))


# ---------- 详情页（带侧边栏标签） ----------

def _normalize_ranking_detail_tab(comp, is_admin, raw_tab):
    tab = str(raw_tab or 'description').strip().lower()
    if tab not in ALLOWED_TABS:
        return 'description'
    scoring_mode = _competition_scoring_mode(comp)
    if tab in ('all_submissions', 'appeals', 'edit', 'batch_eval') and not is_admin:
        return 'description'
    if tab == 'matches' and scoring_mode != 'elo':
        return 'description'
    if tab == 'appeals' and scoring_mode != 'agent_judge':
        return 'description'
    if tab == 'batch_eval' and scoring_mode not in ('agent_judge', 'reverse_judge'):
        return 'description'
    return tab


def _ranking_query_page(args):
    try:
        value = args.get('page', 1, type=int)
    except TypeError:
        try:
            value = int(args.get('page', 1))
        except (TypeError, ValueError):
            value = 1
    return max(1, int(value or 1))


def _build_ranking_detail_context(competition_id, user, comp, args):
    """构建完整详情页与 HTML Fragment 共用的单一模板上下文。"""
    is_admin = user.get('is_admin') == 1
    tab = _normalize_ranking_detail_tab(comp, is_admin, args.get('tab'))
    scoring_mode = _competition_scoring_mode(comp)
    is_agent_judge = scoring_mode == 'agent_judge'
    is_reverse_judge = scoring_mode == 'reverse_judge'
    is_ai_judge = is_agent_judge or is_reverse_judge

    files = list_competition_files(competition_id)
    for item in files:
        # 标注可直接预览的图片/视频，模板据此显示「播放/查看」按钮。
        item['media_kind'] = _attachment_media_kind(item.get('filename'))

    rendered_description = (
        _render_description(comp.get('description') or '') if tab == 'description' else ''
    )
    user_submissions = []
    all_submissions = []
    all_appeals = []
    appeal_stats = None
    leaderboard = []
    submission_stats = None
    current_page = 1
    total_pages = 1
    page_numbers = []
    submission_search_q = ''
    matches = []
    matches_total = 0
    matches_mine = False

    judge_rules = list_competition_rules(competition_id) if is_agent_judge else []
    aj_endpoints = []
    quality_gate_endpoints = []
    agent_global_endpoint_candidates = {}
    agent_judge_ready = False
    quality_gate_ready = (
        _reverse_quality_gate_ready(competition_id, comp) if is_reverse_judge else True
    )
    if is_ai_judge:
        try:
            raw_endpoints = list_agent_judge_endpoints(competition_id)
        except Exception:
            raw_endpoints = []
        aj_endpoints = _masked_agent_endpoints(raw_endpoints)
        agent_judge_ready = (
            _agent_judge_endpoint_ready(competition_id, comp) and bool(judge_rules)
        )
        if is_reverse_judge:
            agent_judge_ready = (
                _agent_judge_endpoint_ready(competition_id, comp) and quality_gate_ready
            )
            if is_admin:
                try:
                    quality_gate_endpoints = _masked_agent_endpoints(
                        list_quality_gate_endpoints(competition_id)
                    )
                except Exception:
                    quality_gate_endpoints = []
        if is_admin:
            try:
                agent_global_endpoint_candidates = global_agent_endpoint_candidates()
            except Exception:
                agent_global_endpoint_candidates = {}

    batch_classes = get_all_classes() if tab == 'batch_eval' else []

    submission_method = (comp.get('submission_method') or 'zip').strip().lower()
    if submission_method not in ('zip', 'git'):
        submission_method = 'zip'

    submit_quota = None
    submit_block_reason = ''
    git_repo_url = None
    if tab == 'submit':
        user_submissions = list_user_submissions(competition_id, user.get('username'))
        submit_block_reason = _ranking_submit_block_reason(
            comp, competition_id, user=user,
        )
        if not is_admin:
            submit_quota = get_submission_quota(
                competition_id, user.get('username'), comp=comp,
            )
            if (
                not submit_block_reason
                and submit_quota is not None
                and submit_quota['remaining'] <= 0
            ):
                submit_block_reason = _submission_quota_message(submit_quota)
        if is_ai_judge and (submission_method == 'git' or is_reverse_judge):
            username = (user.get('username') or '').strip()
            template = (comp.get('git_format') or '').strip()
            if template and BATCH_USERNAME_RE.match(username):
                git_repo_url = build_repo_url(template, username)
    elif tab == 'leaderboard':
        leaderboard = get_leaderboard(competition_id)
    elif tab == 'matches':
        requested_page = _ranking_query_page(args)
        matches_mine = str(args.get('mine') or '').strip().lower() in (
            '1', 'true', 'on', 'yes',
        )
        username_filter = user.get('username') if matches_mine else None
        # 对战列表会由 Celery 跨进程持续追加，不能把旧列表与最新 revision
        # 组合后缓存为“已同步”。分页查询直接读 DB；单场 immutable 详情仍缓存。
        matches, current_page, matches_total = list_competition_matches(
            competition_id,
            page=requested_page,
            per_page=MATCHES_PER_PAGE,
            username=username_filter,
        )
        total_pages = max(
            1, (matches_total + MATCHES_PER_PAGE - 1) // MATCHES_PER_PAGE,
        )
        page_numbers = _page_window(current_page, total_pages)
    elif tab == 'all_submissions':
        submission_search_q = (args.get('q') or '').strip()[:50]
        requested_page = _ranking_query_page(args)
        all_submissions, current_page, total_filtered = list_all_submissions(
            competition_id,
            page=requested_page,
            per_page=SUBMISSIONS_PER_PAGE,
            username_q=submission_search_q or None,
        )
        total_pages = max(
            1, (total_filtered + SUBMISSIONS_PER_PAGE - 1) // SUBMISSIONS_PER_PAGE,
        )
        page_numbers = _page_window(current_page, total_pages)
        submission_stats = get_submission_stats(competition_id)
    elif tab == 'appeals':
        submission_search_q = (args.get('q') or '').strip()[:50]
        requested_page = _ranking_query_page(args)
        all_appeals, current_page, total_filtered = list_appeals(
            competition_id,
            page=requested_page,
            per_page=SUBMISSIONS_PER_PAGE,
            status_q=(args.get('status') or '').strip().lower() or None,
            username_q=submission_search_q or None,
        )
        total_pages = max(
            1, (total_filtered + SUBMISSIONS_PER_PAGE - 1) // SUBMISSIONS_PER_PAGE,
        )
        page_numbers = _page_window(current_page, total_pages)
        appeal_stats = get_appeal_stats(competition_id)

    return {
        'user': user,
        'is_admin': is_admin,
        'competition': comp,
        'files': files,
        'tab': tab,
        'rendered_description': rendered_description,
        'user_submissions': user_submissions,
        'submit_quota': submit_quota,
        'all_submissions': all_submissions,
        'all_appeals': all_appeals,
        'appeal_stats': appeal_stats,
        'leaderboard': leaderboard,
        'submission_stats': submission_stats,
        'current_page': current_page,
        'total_pages': total_pages,
        'page_numbers': page_numbers,
        'submission_search_q': submission_search_q,
        'submissions_per_page': SUBMISSIONS_PER_PAGE,
        'matches': matches,
        'matches_total': matches_total,
        'matches_mine': matches_mine,
        'matches_per_page': MATCHES_PER_PAGE,
        'judge_rules': judge_rules,
        'aj_endpoints': aj_endpoints,
        'quality_gate_endpoints': quality_gate_endpoints,
        'agent_global_endpoint_candidates': agent_global_endpoint_candidates,
        'agent_judge_ready': agent_judge_ready,
        'quality_gate_ready': quality_gate_ready,
        'is_reverse_judge': is_reverse_judge,
        'is_ai_judge': is_ai_judge,
        'batch_classes': batch_classes,
        'batch_default_template': BATCH_DEFAULT_TEMPLATE,
        'submission_method': submission_method,
        'git_repo_url': git_repo_url,
        'submit_block_reason': submit_block_reason,
    }


def _ranking_navigation_payload(state, is_admin):
    scoring_mode = _normalize_scoring_mode((state or {}).get('scoring_mode'))
    is_ai_judge = scoring_mode in ('agent_judge', 'reverse_judge')
    counts = (state or {}).get('counts') or {}
    return {
        'competition_id': int((state or {}).get('competition_id') or 0),
        'scoring_mode': scoring_mode,
        'is_admin': bool(is_admin),
        'is_active': int((state or {}).get('is_active') or 0) == 1,
        'permissions': {
            'description': True,
            'submit': True,
            'leaderboard': True,
            'matches': scoring_mode == 'elo',
            'all_submissions': bool(is_admin),
            'appeals': bool(is_admin and scoring_mode == 'agent_judge'),
            'batch_eval': bool(is_admin and is_ai_judge),
            'edit': bool(is_admin),
        },
        'counts': {
            'submit': None if is_admin else (state or {}).get('quota'),
            'leaderboard': int(counts.get('leaderboard') or 0),
            'matches': int(counts.get('matches') or 0),
            'all_submissions': (
                int(counts.get('all_submissions') or 0) if is_admin else None
            ),
            'appeals': int(counts.get('appeals') or 0) if is_admin else None,
            'attachments': int(counts.get('attachments') or 0),
        },
    }


@ranking_bp.route('/<int:competition_id>/', methods=['GET'])
def ranking_detail(competition_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    fragment_requested = str(request.args.get('fragment') or '').strip() == '1'
    # revision 快照必须早于 competition 与 tab 内容读取：并发写入时允许
    # “新内容 + 旧 revision”（下轮仍会检测），禁止“旧内容 + 新 revision”。
    global_state = _get_ranking_navigation_state_cached(competition_id)
    if not global_state:
        if fragment_requested:
            return jsonify(success=False, message='比赛不存在或已被删除'), 404
        flash('比赛不存在或已被删除', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    comp = get_competition(competition_id)
    if not comp:
        if fragment_requested:
            return jsonify(success=False, message='比赛不存在或已被删除'), 404
        flash('比赛不存在或已被删除', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    is_admin = user.get('is_admin') == 1
    if not is_admin and comp.get('is_active') != 1:
        if fragment_requested:
            return jsonify(success=False, message='该比赛未开放'), 403
        flash('该比赛未开放', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    state = _get_ranking_navigation_state_for_request(
        comp,
        user,
        is_admin,
        state=global_state,
    )
    if not state:
        if fragment_requested:
            return jsonify(success=False, message='比赛不存在或已被删除'), 404
        flash('比赛不存在或已被删除', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    if not is_admin and state.get('is_active') != 1:
        if fragment_requested:
            return jsonify(success=False, message='该比赛未开放'), 403
        flash('该比赛未开放', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    # 先固定响应携带的 revision，再读取 tab 内容。这样并发写入最多得到
    # “较新 HTML + 较旧 revision”，下一轮轮询仍会再次检测；不能反过来把
    # 较旧 HTML 标成最新 revision 而永久漏掉刷新。
    context = _build_ranking_detail_context(
        competition_id, user, comp, request.args,
    )
    navigation = _ranking_navigation_payload(state, is_admin)
    context['navigation'] = navigation
    context['revision'] = state['revision']

    if fragment_requested:
        return jsonify(
            success=True,
            tab=context['tab'],
            html=render_template('ranking/components/detail_panel.html', **context),
            revision=state['revision'],
            navigation=navigation,
        )
    return render_template('ranking/detail.html', **context)


@ranking_bp.route('/<int:competition_id>/navigation-state', methods=['GET'])
def ranking_navigation_state(competition_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    is_admin = user.get('is_admin') == 1
    comp = get_competition(competition_id)
    if not comp:
        return jsonify(success=False, message='比赛不存在或已被删除'), 404
    if not is_admin and comp.get('is_active') != 1:
        return jsonify(success=False, message='该比赛未开放'), 403
    state = _get_ranking_navigation_state_for_request(
        comp,
        user,
        is_admin,
    )
    if not state:
        return jsonify(success=False, message='比赛不存在或已被删除'), 404
    if not is_admin and state.get('is_active') != 1:
        return jsonify(success=False, message='该比赛未开放'), 403
    return jsonify(
        success=True,
        revision=state['revision'],
        navigation=_ranking_navigation_payload(state, is_admin),
    )


# ---------- 对战详情 JSON（公开给登录用户） ----------

@ranking_bp.route('/<int:competition_id>/match/<int:match_id>/details.json', methods=['GET'])
def ranking_match_details(competition_id, match_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        return jsonify({'success': False, 'message': '比赛不存在'}), 404
    is_admin = user.get('is_admin') == 1
    if not is_admin and comp.get('is_active') != 1:
        return jsonify({'success': False, 'message': '比赛未开放'}), 403
    row = fetch_competition_match_detail_cached(match_id, competition_id)
    if not row:
        return jsonify({'success': False, 'message': '对战记录不存在'}), 404
    # 保留原始 details 以兼容 CLI；detail_output 是网页使用的稳定 text/html 协议。
    detail_output = normalize_match_detail_output(
        row.get('details'),
        error_message=row.get('error_message'),
    )
    return jsonify({
        'success': True,
        'id': int(row.get('id')),
        'created_at': str(row.get('created_at')),
        'username_a': row.get('username_a'),
        'username_b': row.get('username_b'),
        'winner': int(row.get('winner') or 0),
        'rating_a_before': float(row.get('rating_a_before') or 0),
        'rating_a_after': float(row.get('rating_a_after') or 0),
        'rating_b_before': float(row.get('rating_b_before') or 0),
        'rating_b_after': float(row.get('rating_b_after') or 0),
        'details': row.get('details'),
        'detail_output': detail_output,
        'error_message': row.get('error_message'),
    })


# ---------- 管理员：删除对战并撤销分数变动 ----------

@ranking_bp.route('/<int:competition_id>/match/<int:match_id>/delete', methods=['POST'])
def ranking_delete_match(competition_id, match_id):
    """管理员删除某场 ELO 对战；该对战导致的双方分数变动从当前 rating 里"反加回去"，
    elo_match_count 也各减 1。winner == -1（评测失败）的对战只删行，不动分数。"""
    wants_json = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )
    user, resp = _require_admin()
    if resp is not None:
        if wants_json:
            return jsonify({'success': False, 'message': '需要管理员权限'}), 403
        return resp
    comp = get_competition(competition_id)
    if not comp:
        if wants_json:
            return jsonify({'success': False, 'message': '比赛不存在'}), 404
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    result = delete_elo_match_and_revert(int(match_id), int(competition_id))
    if result is None:
        if wants_json:
            return jsonify({'success': False, 'message': '对战记录不存在'}), 404
        flash('对战记录不存在', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='matches'))

    _invalidate_competition_match_caches(competition_id, match_id=match_id)

    raw_winner = result.get('winner')
    winner = int(raw_winner) if raw_winner is not None else -1
    if winner in (0, 1, 2):
        msg = (
            '已删除对战 #{} ：A 分数 {:+.2f}，B 分数 {:+.2f}，'
            '已从当前 ELO 中撤销该变化，并把双方对战次数各减 1。'.format(
                int(match_id),
                -float(result.get('delta_a') or 0),
                -float(result.get('delta_b') or 0),
            )
        )
    else:
        msg = f'已删除对战 #{int(match_id)}（评测失败的记录，未影响分数）'

    if wants_json:
        return jsonify({
            'success': True,
            'winner': winner,
            'delta_a': float(result.get('delta_a') or 0),
            'delta_b': float(result.get('delta_b') or 0),
            'message': msg,
        })
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='matches'))


# ---------- 管理员：重构历史 rating 轨迹 ----------

@ranking_bp.route('/<int:competition_id>/elo/rebuild', methods=['POST'])
def ranking_elo_rebuild_history(competition_id):
    """重新计算该赛事所有现存对战记录中的 before / after rating 快照，并把每份
    提交的当前 ELO 分数与对战次数同步到重放终态。

    用途：删除若干场对战之后，遗留对战行里的快照（rating_a_before 等）不再与
    时序逻辑一致，这里通过重放修正。
    """
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    if str(comp.get('scoring_mode') or 'absolute').lower() != 'elo':
        flash('该比赛不是 ELO 模式', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='matches'))

    result = rebuild_elo_history(int(competition_id))
    if result is None:
        flash('比赛不存在或重构失败', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='matches'))

    _invalidate_competition_match_caches(competition_id)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='matches'))


# ---------- 所有提交（管理员）异步分页 / 搜索 API ----------

@ranking_bp.route('/<int:competition_id>/submissions_json', methods=['GET'])
def ranking_submissions_json(competition_id):
    """供「所有提交」标签页的分页与按用户名搜索使用的 AJAX 端点。

    返回 ``rows_html`` / ``pagination_html`` 两段已渲染好的 HTML，由前端直接替换 DOM 内容；
    服务端是 row 模板的唯一真理源，避免前后端再写一遍。
    """
    user = _current_user()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    if user.get('is_admin') != 1:
        return jsonify({'error': 'forbidden'}), 403
    comp = get_competition(competition_id)
    if not comp:
        return jsonify({'error': 'not_found'}), 404

    q = (request.args.get('q') or '').strip()[:50]
    requested_page = max(1, request.args.get('page', 1, type=int))
    per_page = SUBMISSIONS_PER_PAGE
    rows, page, total = list_all_submissions(
        competition_id,
        page=requested_page,
        per_page=per_page,
        username_q=q or None,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)
    page_numbers = _page_window(page, total_pages)

    is_elo = (str(comp.get('scoring_mode') or 'absolute').lower() == 'elo')
    max_score = comp.get('max_score') or 100

    is_agent_judge = (str(comp.get('scoring_mode') or 'absolute').lower() == 'agent_judge')
    is_reverse_judge = (str(comp.get('scoring_mode') or 'absolute').lower() == 'reverse_judge')
    rows_html = render_template(
        'ranking/components/submission_rows.html',
        all_submissions=rows,
        competition=comp,
        is_elo=is_elo,
        max_score=max_score,
        is_agent_judge=is_agent_judge,
        is_reverse_judge=is_reverse_judge,
    )
    pagination_html = render_template(
        'ranking/components/pagination.html',
        competition=comp,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        submission_search_q=q,
    )
    return jsonify({
        'rows_html': rows_html,
        'pagination_html': pagination_html,
        'page': page,
    })


@ranking_bp.route('/<int:competition_id>/bulk_rejudge/filter', methods=['POST'])
def ranking_bulk_rejudge_filter(competition_id):
    user = _current_user()
    if not user:
        return jsonify(success=False, message='请先登录'), 401
    if user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403
    comp = get_competition(competition_id)
    if not comp:
        return jsonify(success=False, message='比赛不存在或已被删除'), 404

    payload = request.get_json(silent=True) or request.form
    start = _normalize_dt(payload.get('start'))
    end = _normalize_dt(payload.get('end'))
    if start and end and start > end:
        return jsonify(success=False, message='起始时间不能晚于结束时间'), 400
    username_q = str(payload.get('username') or '').strip()
    status_groups = _normalize_bulk_status_groups(
        payload.get('statuses') or payload.get('status_groups'),
    )

    rows, total = list_submissions_for_bulk_rejudge(
        competition_id,
        start=start,
        end=end,
        username_q=username_q,
        status_groups=status_groups,
        limit=_BULK_REJUDGE_MAX_FILTER_RESULTS + 1,
    )
    too_many = len(rows) > _BULK_REJUDGE_MAX_FILTER_RESULTS
    if too_many:
        rows = rows[:_BULK_REJUDGE_MAX_FILTER_RESULTS]
    is_elo = (_competition_scoring_mode(comp) == 'elo')
    return jsonify(
        success=True,
        submissions=[_serialize_bulk_ranking_submission(row, is_elo=is_elo) for row in rows],
        total=total,
        shown=len(rows),
        too_many=too_many,
        max_results=_BULK_REJUDGE_MAX_FILTER_RESULTS,
        max_selected=_BULK_REJUDGE_MAX_SELECTED,
    )


@ranking_bp.route('/<int:competition_id>/bulk_rejudge/start', methods=['POST'])
def ranking_bulk_rejudge_start(competition_id):
    user = _current_user()
    if not user:
        return jsonify(success=False, message='请先登录'), 401
    if user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403
    comp = get_competition(competition_id)
    if not comp:
        return jsonify(success=False, message='比赛不存在或已被删除'), 404
    if _bulk_rejudge_task is None:
        return jsonify(success=False, message='批量重测任务未初始化'), 500

    payload = request.get_json(silent=True) or request.form
    source_ids = _parse_submission_ids(payload.get('submission_ids'))
    if not source_ids:
        return jsonify(success=False, message='请选择要重测的提交'), 400
    if len(source_ids) > _BULK_REJUDGE_MAX_SELECTED:
        return jsonify(
            success=False,
            message=f'单次最多重测 {_BULK_REJUDGE_MAX_SELECTED} 条提交，请缩小筛选范围',
        ), 400

    invalid_ids = []
    valid_ids = []
    for sid in source_ids:
        sub = get_ranking_submission(sid)
        if not sub or int(sub.get('competition_id') or 0) != int(competition_id):
            invalid_ids.append(sid)
        else:
            valid_ids.append(sid)
    if invalid_ids:
        return jsonify(
            success=False,
            message='包含不存在或不属于本比赛的提交：' + ', '.join(str(x) for x in invalid_ids[:10]),
        ), 400

    job_id = uuid.uuid4().hex
    now_text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    save_bulk_rejudge_job(job_id, {
        'status': 'queued',
        'competition_id': int(competition_id),
        'total': len(valid_ids),
        'processed': 0,
        'requeued': 0,
        'created': 0,
        'failed': 0,
        'progress': 0,
        'requeued_ids': [],
        'created_ids': [],
        'started_by': user.get('username') or '',
        'started_at': now_text,
        'interval_seconds': _BULK_REJUDGE_INTERVAL_SECONDS,
    })
    _bulk_rejudge_task.apply_async(
        args=[int(competition_id), valid_ids, job_id, user.get('username') or ''],
    )
    return jsonify(
        success=True,
        message='已开始重新入队原提交',
        job_id=job_id,
        total=len(valid_ids),
        interval_seconds=_BULK_REJUDGE_INTERVAL_SECONDS,
    )


@ranking_bp.route('/<int:competition_id>/bulk_rejudge/status/<job_id>', methods=['GET'])
def ranking_bulk_rejudge_status(competition_id, job_id):
    user = _current_user()
    if not user:
        return jsonify(success=False, message='请先登录'), 401
    if user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403
    job = get_bulk_rejudge_job(str(job_id or '').strip())
    if not job or int(job.get('competition_id') or 0) != int(competition_id):
        return jsonify(success=False, message='任务不存在或已过期'), 404

    total = int(job.get('total') or 0)
    processed = int(job.get('processed') or 0)
    progress = int(job.get('progress') or (processed / max(1, total) * 100))
    return jsonify(
        success=True,
        status=job.get('status') or 'queued',
        total=total,
        processed=processed,
        requeued=int(job.get('requeued') or job.get('created') or 0),
        created=int(job.get('created') or 0),
        failed=int(job.get('failed') or 0),
        progress=progress,
        done=(total > 0 and processed >= total and job.get('status') == 'finished'),
        requeued_ids=job.get('requeued_ids') or job.get('created_ids') or [],
        created_ids=job.get('created_ids') or [],
        last_error=job.get('last_error') or '',
        interval_seconds=job.get('interval_seconds') or _BULK_REJUDGE_INTERVAL_SECONDS,
    )


# ---------- 对战数据：分页 AJAX 局部刷新（删除后保持当前页用） ----------

@ranking_bp.route('/<int:competition_id>/matches_json', methods=['GET'])
def ranking_matches_json(competition_id):
    """对战数据标签页的 AJAX 端点：返回某一页对战列表 + 分页的已渲染 HTML 片段。
    管理员删除某场对战后，前端据此就地刷新「当前页」，不跳回第 1 页。"""
    user = _current_user()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    comp = get_competition(competition_id)
    if not comp:
        return jsonify({'error': 'not_found'}), 404
    is_admin = user.get('is_admin') == 1
    if not is_admin and comp.get('is_active') != 1:
        return jsonify({'error': 'forbidden'}), 403

    requested_page = max(1, request.args.get('page', 1, type=int))
    matches_mine = str(request.args.get('mine') or '').strip() in ('1', 'true', 'on', 'yes')
    username_filter = user.get('username') if matches_mine else None
    matches, current_page, matches_total = list_competition_matches(
        competition_id,
        page=requested_page,
        per_page=MATCHES_PER_PAGE,
        username=username_filter,
    )
    total_pages = max(1, (matches_total + MATCHES_PER_PAGE - 1) // MATCHES_PER_PAGE)
    page_numbers = _page_window(current_page, total_pages)

    html = render_template(
        'ranking/components/matches.html',
        matches=matches,
        competition=comp,
        user=user,
        is_admin=is_admin,
        matches_mine=matches_mine,
        current_page=current_page,
        total_pages=total_pages,
        page_numbers=page_numbers,
    )
    return jsonify({
        'html': html,
        'total': matches_total,
        'page': current_page,
        'total_pages': total_pages,
    })


# ---------- 用户提交作品 ----------

@ranking_bp.route('/<int:competition_id>/submit', methods=['POST'])
def ranking_submit(competition_id):
    user, resp = _require_user()
    if resp is not None:
        if _wants_json_response():
            return jsonify(success=False, message='请先登录'), 401
        return resp
    comp = get_competition(competition_id)
    if not comp:
        if _wants_json_response():
            return jsonify(success=False, message='比赛不存在或已被删除'), 404
        flash('比赛不存在或已被删除', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    is_admin = user.get('is_admin') == 1
    block_reason = _ranking_submit_block_reason(comp, competition_id, user=user)
    if block_reason:
        status = 403 if block_reason == '该比赛未开放' else 400
        return _submit_error_response(competition_id, block_reason, status=status)

    # 提交限流（管理员豁免）：防止刷量耗尽 Docker 评测队列、主机资源与付费 token 预算。
    if not is_admin:
        allowed, retry = rate_limit_hit(
            _rds,
            f"rank:submit:{competition_id}:{user.get('username')}",
            _RANK_SUBMIT_MAX_PER_WINDOW,
            _RANK_SUBMIT_WINDOW,
        )
        if not allowed:
            return _submit_error_response(competition_id, f'提交过于频繁，请 {retry} 秒后再试', status=429)
        # 每 48 小时窗口提交次数限制（管理员豁免）
        quota = get_submission_quota(competition_id, user.get('username'), comp=comp)
        if quota is not None and quota['remaining'] <= 0:
            return _submit_error_response(competition_id, _submission_quota_message(quota), status=429)

    scoring_mode = _competition_scoring_mode(comp)
    submission_method = (comp.get('submission_method') or 'zip').strip().lower()
    if scoring_mode == 'agent_judge' and submission_method == 'git':
        return _submit_error_response(competition_id, '该比赛启用 Git 提交方式，请使用 Git 提交。')

    if scoring_mode == 'reverse_judge':
        endpoint_id, endpoint_error = _validate_reverse_endpoint_choice(competition_id)
        if endpoint_error:
            return _submit_error_response(competition_id, endpoint_error, category='danger')
        code_file = request.files.get('code_file')
        if not code_file or not (code_file.filename or '').strip():
            return _submit_error_response(competition_id, '请上传反向评测题目包（.zip）', category='danger')
        if not (code_file.filename or '').lower().endswith('.zip'):
            return _submit_error_response(competition_id, '反向评测题目包必须是 .zip', category='danger')
        code_name = _safe_filename(code_file.filename, fallback='reverse_judge.zip')
        if not code_name.lower().endswith('.zip'):
            code_name += '.zip'
        try:
            submission_id = _create_uploaded_ranking_submission(
                competition_id,
                user.get('username'),
                code_file=code_file,
                code_name=code_name,
                code_label='题目包',
                enforce_quota=not is_admin,
                agent_endpoint_id=endpoint_id,
            )
        except RankingSubmissionQuotaExceeded as e:
            return _submit_error_response(competition_id, _submission_quota_message(e.quota), status=429)
        except RankingSubmissionCommitUnknown as exc:
            return _submit_commit_unknown_response(competition_id, exc)
        except Exception as e:
            return _submit_error_response(competition_id, f'文件保存失败：{e}', category='danger')
        attempt_id = begin_agent_judge_attempt(submission_id, status='Queued', reset_result=True)
        if _reverse_judge_task is None:
            flash('已接收提交，但反向评测任务未初始化，请联系管理员', 'warning')
        else:
            try:
                async_result = _reverse_judge_task.apply_async(args=[submission_id, attempt_id, endpoint_id])
                set_agent_judge_task_id(submission_id, attempt_id, async_result.id)
            except Exception as e:
                flash(f'已接收提交，但反向评测任务入队失败：{e}', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    base_model_raw = (request.form.get('base_model') or '').strip()
    if not base_model_raw:
        return _submit_error_response(
            competition_id,
            '请填写基座模型（多个用逗号分隔，例如：deepseek-v4-pro, qwen3.6-plus）',
            category='danger',
        )
    if len(base_model_raw) > 500:
        return _submit_error_response(competition_id, '基座模型字段过长（不超过 500 字）', category='danger')
    base_model = base_model_raw

    # Agent 评测模式：只需上传代码 zip（不需要 answer 文件），但要求已配置模型与规则
    if scoring_mode == 'agent_judge':
        fake_agent_judge = _fake_agent_judge_enabled()
        code_file = request.files.get('code_file')
        if not code_file or not (code_file.filename or '').strip():
            return _submit_error_response(competition_id, '请上传代码文件（.zip）', category='danger')
        if not (code_file.filename or '').lower().endswith('.zip'):
            return _submit_error_response(competition_id, '代码文件必须是 .zip', category='danger')
        code_name = _safe_filename(code_file.filename, fallback='code.zip')
        if not code_name.lower().endswith('.zip'):
            code_name += '.zip'
        try:
            submission_id = _create_uploaded_ranking_submission(
                competition_id,
                user.get('username'),
                code_file=code_file,
                code_name=code_name,
                base_model=base_model,
                enforce_quota=not is_admin,
            )
        except RankingSubmissionQuotaExceeded as e:
            return _submit_error_response(competition_id, _submission_quota_message(e.quota), status=429)
        except RankingSubmissionCommitUnknown as exc:
            return _submit_commit_unknown_response(competition_id, exc)
        except Exception as e:
            return _submit_error_response(competition_id, f'文件保存失败：{e}', category='danger')
        # agent_judge：入队即置「等待评测(Queued)」，被评测 worker 取到执行时才转「评测中」。
        attempt_id = begin_agent_judge_attempt(submission_id, status='Queued', reset_result=True)
        if _agent_judge_task is None:
            flash('已接收提交，但评测任务未初始化，请联系管理员', 'warning')
        else:
            try:
                task_kwargs = {'args': [submission_id, attempt_id]}
                if fake_agent_judge:
                    task_kwargs['countdown'] = _fake_agent_judge_delay_seconds()
                async_result = _agent_judge_task.apply_async(**task_kwargs)
                set_agent_judge_task_id(submission_id, attempt_id, async_result.id)
            except Exception as e:
                flash(f'已接收提交，但评测任务入队失败：{e}', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    # ELO 只接收一个 ZIP 作品包，沿用 code_file/code_path 存储；
    # 不读取 answer_file，也不依赖比赛的 answer_format 字段。
    if scoring_mode == 'elo':
        code_file = request.files.get('code_file')
        if not code_file or not (code_file.filename or '').strip():
            return _submit_error_response(competition_id, '请上传作品压缩包（.zip）', category='danger')
        if not (code_file.filename or '').lower().endswith('.zip'):
            return _submit_error_response(competition_id, '作品压缩包必须是 .zip', category='danger')
        code_name = _safe_filename(code_file.filename, fallback='submission.zip')
        if not code_name.lower().endswith('.zip'):
            code_name += '.zip'
        try:
            submission_id = _create_uploaded_ranking_submission(
                competition_id,
                user.get('username'),
                code_file=code_file,
                code_name=code_name,
                code_label='作品压缩包',
                base_model=base_model,
                enforce_quota=not is_admin,
            )
        except RankingSubmissionQuotaExceeded as e:
            return _submit_error_response(competition_id, _submission_quota_message(e.quota), status=429)
        except RankingSubmissionCommitUnknown as exc:
            return _submit_commit_unknown_response(competition_id, exc)
        except Exception as e:
            return _submit_error_response(competition_id, f'文件保存失败：{e}', category='danger')

        initial_rating = float(comp.get('elo_initial_rating') or 1500)
        activate_elo_submission(
            submission_id,
            competition_id,
            user.get('username'),
            initial_rating,
            keep_count=2,
        )
        if _elo_initial_burst_task is not None:
            try:
                _elo_initial_burst_task.apply_async(
                    args=[competition_id, submission_id], countdown=3,
                )
            except Exception as e:
                flash(f'已加入 ELO 池，但即时补战入队失败：{e}', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    answer_format = _competition_answer_format(comp)
    answer_ext = '.' + answer_format
    answer_file = request.files.get('answer_file')
    code_file = request.files.get('code_file')
    if not answer_file or not (answer_file.filename or '').strip():
        return _submit_error_response(competition_id, f'请上传答案文件（{answer_ext}）', category='danger')
    if not code_file or not (code_file.filename or '').strip():
        return _submit_error_response(competition_id, '请上传代码文件（.zip）', category='danger')

    answer_name_raw = answer_file.filename
    code_name_raw = code_file.filename
    if not answer_name_raw.lower().endswith(answer_ext):
        return _submit_error_response(competition_id, f'答案文件必须是 {answer_ext}', category='danger')
    if not code_name_raw.lower().endswith('.zip'):
        return _submit_error_response(competition_id, '代码文件必须是 .zip', category='danger')

    answer_name = _safe_filename(answer_name_raw, fallback=f'answer{answer_ext}')
    if not answer_name.lower().endswith(answer_ext):
        answer_name += answer_ext

    code_name = _safe_filename(code_name_raw, fallback='code.zip')
    if not code_name.lower().endswith('.zip'):
        code_name += '.zip'

    try:
        submission_id = _create_uploaded_ranking_submission(
            competition_id,
            user.get('username'),
            code_file=code_file,
            code_name=code_name,
            answer_file=answer_file,
            answer_name=answer_name,
            base_model=base_model,
            enforce_quota=not is_admin,
        )
    except RankingSubmissionQuotaExceeded as e:
        return _submit_error_response(competition_id, _submission_quota_message(e.quota), status=429)
    except RankingSubmissionCommitUnknown as exc:
        return _submit_commit_unknown_response(competition_id, exc)
    except Exception as e:
        return _submit_error_response(competition_id, f'文件保存失败：{e}', category='danger')

    if _evaluate_ranking_task is None:
        flash('已接收提交，但评测任务未初始化，请联系管理员', 'warning')
    else:
        dispatch_task_id = str(uuid.uuid4())
        try:
            if not reserve_standard_ranking_evaluation(
                    submission_id,
                    dispatch_task_id,
            ):
                raise RuntimeError('无法取得普通评测数据库租约')
            _evaluate_ranking_task.apply_async(
                args=[submission_id],
                task_id=dispatch_task_id,
            )
        except Exception as e:
            try:
                release_standard_ranking_evaluation(submission_id, dispatch_task_id)
            except Exception:
                pass
            flash(f'已接收提交，但评测任务入队失败：{e}', 'warning')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))


# ---------- git 提交方式：学生检查自己的仓库 / 确认提交 ----------

def _user_git_repo_context(competition_id):
    """git 提交方式公共校验：登录用户 + 比赛存在 + agent_judge + git 方式 + 已配置命名。
    仓库地址由「标准命名」中的 <username> 替换为**本人**用户名得到（不接受前端传入），
    天然无注入风险。返回 (user, comp, url, None) 或 (None, None, None, (resp, code))。"""
    user = _current_user()
    if not user:
        return None, None, None, (jsonify(success=False, message='请先登录'), 401)
    comp = get_competition(competition_id)
    if not comp:
        return None, None, None, (jsonify(success=False, message='比赛不存在或已被删除'), 404)
    is_admin = user.get('is_admin') == 1
    if not is_admin and comp.get('is_active') != 1:
        return None, None, None, (jsonify(success=False, message='该比赛未开放'), 403)
    scoring_mode = _competition_scoring_mode(comp)
    if scoring_mode not in ('agent_judge', 'reverse_judge'):
        return None, None, None, (jsonify(success=False, message='该比赛不支持 git 提交'), 400)
    method = (comp.get('submission_method') or 'zip').strip().lower()
    if scoring_mode == 'agent_judge' and method != 'git':
        return None, None, None, (jsonify(success=False, message='该比赛未启用 git 提交方式'), 400)
    uname = (user.get('username') or '').strip()
    tmpl = (comp.get('git_format') or '').strip()
    if not tmpl or BATCH_PLACEHOLDER not in tmpl:
        return None, None, None, (jsonify(success=False, message='管理员尚未配置 git 仓库标准命名'), 400)
    if not BATCH_USERNAME_RE.match(uname):
        return None, None, None, (jsonify(success=False, message='你的用户名不符合 git 仓库命名要求'), 400)
    return user, comp, build_repo_url(tmpl, uname), None


@ranking_bp.route('/<int:competition_id>/check_repo', methods=['POST'])
def ranking_check_repo(competition_id):
    """学生检查自己的 git 仓库：返回是否存在 + 最后一条 commit 的明细（JSON）。"""
    user, comp, url, err = _user_git_repo_context(competition_id)
    if err is not None:
        return err
    # 轻量限流：检查仓库会起 git 子进程，防止狂点
    allowed, retry = rate_limit_hit(
        _rds, f"rank:checkrepo:{competition_id}:{user.get('username')}", 20, 60,
    )
    if not allowed:
        return jsonify(success=False, message=f'操作过于频繁，请 {retry} 秒后再试'), 429
    exists, info, message = repo_last_commit(url)
    return jsonify(success=True, exists=bool(exists), url=url, info=info, message=message)


@ranking_bp.route('/<int:competition_id>/git_submit', methods=['POST'])
def ranking_git_submit(competition_id):
    """学生确认 git 提交：复用批量评测逻辑，入队一次单仓库的拉取 / 创建提交 / 评测（JSON）。"""
    user, comp, url, err = _user_git_repo_context(competition_id)
    if err is not None:
        return err
    block_reason = _ranking_submit_block_reason(comp, competition_id, user=user)
    if block_reason:
        return jsonify(success=False, message=block_reason), 400
    if _batch_run_task is None:
        return jsonify(success=False, message='评测任务未初始化，请联系管理员'), 500
    endpoint_id = None
    if _competition_scoring_mode(comp) == 'reverse_judge':
        endpoint_id, endpoint_error = _validate_reverse_endpoint_choice(competition_id)
        if endpoint_error:
            return jsonify(success=False, message=endpoint_error), 400

    is_admin = user.get('is_admin') == 1
    if not is_admin:
        allowed, retry = rate_limit_hit(
            _rds, f"rank:submit:{competition_id}:{user.get('username')}",
            _RANK_SUBMIT_MAX_PER_WINDOW, _RANK_SUBMIT_WINDOW,
        )
        if not allowed:
            return jsonify(success=False, message=f'提交过于频繁，请 {retry} 秒后再试'), 429
        quota = get_submission_quota(competition_id, user.get('username'), comp=comp)
        if quota is not None and quota['remaining'] <= 0:
            return jsonify(
                success=False,
                message=_submission_quota_message(quota),
            ), 429

    item = {'username': user.get('username'), 'url': url, 'source': 'self'}
    if endpoint_id is not None:
        item['agent_endpoint_id'] = endpoint_id
    items = [item]
    try:
        _batch_run_task.delay(competition_id, items)
    except Exception as e:
        return jsonify(success=False, message=f'提交入队失败：{e}'), 500
    return jsonify(success=True,
                   message='已提交：系统正在拉取你的仓库并评测，稍后可在「我的历史提交」查看进展。')


# ---------- 管理员：批量评测（按 Git 仓库批量拉取参赛者代码） ----------

def _admin_json_guard():
    """JSON 接口的「登录 + 管理员」校验。返回 (user, None) 或 (None, (resp, code))。"""
    user = _current_user()
    if not user:
        return None, (jsonify(success=False, message='请先登录'), 401)
    if user.get('is_admin') != 1:
        return None, (jsonify(success=False, message='需要管理员权限'), 403)
    return user, None


def _require_admin_agent_judge(competition_id):
    """批量评测公共校验：管理员 + 比赛存在 + AI 评测类模式。
    返回 (comp, None) 或 (None, (resp, code))。"""
    user, err = _admin_json_guard()
    if err is not None:
        return None, err
    comp = get_competition(competition_id)
    if not comp:
        return None, (jsonify(success=False, message='比赛不存在或已被删除'), 404)
    if _competition_scoring_mode(comp) not in ('agent_judge', 'reverse_judge'):
        return None, (jsonify(success=False, message='仅 Agent 评测或反向评测模式支持批量评测'), 400)
    return comp, None


@ranking_bp.route('/<int:competition_id>/batch_eval/probe', methods=['POST'])
def ranking_batch_probe_start(competition_id):
    """启动一次仓库探测任务：枚举所选班级名单，逐个把 <username> 替换为用户名后
    用 git ls-remote 并发探测。返回 job_id，前端轮询 probe_status。"""
    comp, err = _require_admin_agent_judge(competition_id)
    if err is not None:
        return err
    if _batch_probe_task is None:
        return jsonify(success=False, message='批量评测任务未初始化，请联系管理员'), 500
    data = request.get_json(silent=True) or {}
    classes = data.get('classes') or []
    template = (data.get('template') or '').strip()
    if not isinstance(classes, list):
        classes = []
    classes = [str(c).strip() for c in classes if str(c).strip()][:50]
    if not classes:
        return jsonify(success=False, message='请至少选择一个班级'), 400
    if BATCH_PLACEHOLDER not in template:
        return jsonify(success=False, message=f'仓库命名必须包含 {BATCH_PLACEHOLDER} 占位符'), 400
    if len(template) > 500:
        return jsonify(success=False, message='仓库命名过长（不超过 500 字）'), 400
    job_id = secrets.token_hex(8)
    try:
        _batch_probe_task.delay(job_id, competition_id, classes, template)
    except Exception as e:
        return jsonify(success=False, message=f'任务入队失败：{e}'), 500
    return jsonify(success=True, job_id=job_id)


@ranking_bp.route('/<int:competition_id>/batch_eval/probe_status', methods=['GET'])
def ranking_batch_probe_status(competition_id):
    comp, err = _require_admin_agent_judge(competition_id)
    if err is not None:
        return err
    job_id = (request.args.get('job') or '').strip()
    if not job_id:
        return jsonify(success=False, message='缺少 job 参数'), 400
    job = get_probe_job(job_id)
    if job is None:
        # 任务可能尚未开始写入进度，按「排队中」返回，前端继续轮询。
        return jsonify(success=True, state='queued', total=0, checked=0, found=[], skipped=0, truncated=False)
    return jsonify(
        success=True,
        state=job.get('state', 'running'),
        total=int(job.get('total') or 0),
        checked=int(job.get('checked') or 0),
        found=job.get('found') or [],
        skipped=int(job.get('skipped') or 0),
        truncated=bool(job.get('truncated')),
    )


@ranking_bp.route('/<int:competition_id>/batch_eval/create', methods=['POST'])
def ranking_batch_create(competition_id):
    """对管理员勾选的仓库，入队一个「串行批量处理」任务：由后台逐个拉取 / 创建提交 / 入队评测。

    不在此处预创建提交、也不并发拉取——所有仓库交给单个 ``ranking_batch_run`` 任务一个一个地处理
    （每个：拉取重试≤3 → 创建并校验，失败删档重试≤3 → 入队评测 → sleep 1s）。
    """
    comp, err = _require_admin_agent_judge(competition_id)
    if err is not None:
        return err
    if _batch_run_task is None:
        return jsonify(success=False, message='批量评测任务未初始化，请联系管理员'), 500
    scoring_mode = _competition_scoring_mode(comp)
    if scoring_mode == 'agent_judge' and not list_competition_rules(competition_id):
        return jsonify(success=False, message='该比赛尚未设置评分规则，无法评测'), 400
    if not _agent_judge_endpoint_ready(competition_id, comp):
        return jsonify(success=False, message='该比赛尚未配置 Agent 评测模型端点'), 400
    if scoring_mode == 'reverse_judge':
        quality_gate_reason = _reverse_quality_gate_block_reason(competition_id, comp)
        if quality_gate_reason:
            return jsonify(success=False, message=quality_gate_reason), 400
    data = request.get_json(silent=True) or {}
    endpoint_id = None
    if scoring_mode == 'reverse_judge':
        endpoint_id, endpoint_error = _validate_reverse_endpoint_choice(competition_id)
        if endpoint_error:
            return jsonify(success=False, message=endpoint_error), 400
    template = (data.get('template') or '').strip()
    usernames = data.get('usernames') or []
    if BATCH_PLACEHOLDER not in template:
        return jsonify(success=False, message=f'仓库命名必须包含 {BATCH_PLACEHOLDER} 占位符'), 400
    if len(template) > 500:
        return jsonify(success=False, message='仓库命名过长（不超过 500 字）'), 400
    if not isinstance(usernames, list) or not usernames:
        return jsonify(success=False, message='请至少勾选一个仓库'), 400

    seen = set()
    items = []
    invalid = []
    for raw in usernames[:1000]:
        uname = str(raw).strip()
        if not uname or uname in seen:
            continue
        seen.add(uname)
        if not BATCH_USERNAME_RE.match(uname) or not get_user_by_username(uname):
            invalid.append(uname)
            continue
        item = {'username': uname, 'url': build_repo_url(template, uname)}
        if endpoint_id is not None:
            item['agent_endpoint_id'] = endpoint_id
        items.append(item)

    if not items:
        return jsonify(success=False, message='没有可处理的有效仓库', invalid=invalid), 400
    try:
        _batch_run_task.delay(competition_id, items)
    except Exception as e:
        return jsonify(success=False, message=f'任务入队失败：{e}'), 500
    return jsonify(success=True, queued=len(items), invalid=invalid)


# ---------- 管理员：编辑比赛 ----------

@ranking_bp.route('/<int:competition_id>/edit', methods=['POST'])
def ranking_edit(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    title = (request.form.get('title') or '').strip()
    summary = (request.form.get('summary') or '').strip()[:500]
    description = request.form.get('description') or ''
    max_score_raw = request.form.get('max_score')
    is_active_raw = request.form.get('is_active')
    scoring_mode_raw = request.form.get('scoring_mode')
    elo_initial_rating_raw = request.form.get('elo_initial_rating')
    elo_k_factor_raw = request.form.get('elo_k_factor')
    elo_max_matches_raw = request.form.get('elo_max_matches')
    elo_match_interval_raw = request.form.get('elo_match_interval_seconds')
    elo_initial_burst_raw = request.form.get('elo_initial_burst')
    elo_max_pairs_per_round_raw = request.form.get('elo_max_pairs_per_round')
    elo_runtime_mode_raw = request.form.get('elo_runtime_mode')
    script_timeout_raw = request.form.get('scoring_script_timeout_seconds')
    submit_limit_raw = request.form.get('submit_limit_per_window')
    reset_limit_window_raw = request.form.get('reset_limit_window')
    submission_method_raw = request.form.get('submission_method')
    git_format_raw = request.form.get('git_format')

    if not title:
        flash('标题不能为空', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    try:
        max_score_int = int(max_score_raw) if max_score_raw is not None else int(comp.get('max_score') or 100)
        if max_score_int <= 0:
            raise ValueError
    except ValueError:
        flash('满分必须是正整数', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    is_active = 1 if (is_active_raw and str(is_active_raw).lower() in ('1', 'on', 'true', 'yes')) else 0

    old_mode = _competition_scoring_mode(comp)
    new_mode = _normalize_scoring_mode(scoring_mode_raw, default=old_mode)
    mode_changed = (new_mode != old_mode)
    if new_mode == 'reverse_judge':
        max_score_int = 100

    if new_mode == 'absolute':
        old_format = _competition_answer_format(comp)
        answer_format_raw = request.form.get('answer_format')
        new_format = _normalize_answer_format(answer_format_raw, default=old_format)
        format_changed = (new_format != old_format)
    else:
        new_format = None
        format_changed = False

    # 解析 ELO 参数（缺省继承当前值）
    def _parse_float(raw, fallback, lo, hi):
        try:
            v = float(raw) if raw is not None and str(raw).strip() != '' else float(fallback)
        except (TypeError, ValueError):
            v = float(fallback)
        return _clamp(v, lo, hi)

    def _parse_int(raw, fallback, lo, hi):
        try:
            v = int(raw) if raw is not None and str(raw).strip() != '' else int(fallback)
        except (TypeError, ValueError):
            v = int(fallback)
        return int(_clamp(v, lo, hi))

    elo_initial_rating = _parse_float(
        elo_initial_rating_raw, comp.get('elo_initial_rating') or 1500,
        ELO_INITIAL_RATING_RANGE[0], ELO_INITIAL_RATING_RANGE[1],
    )
    elo_k_factor = _parse_float(
        elo_k_factor_raw, comp.get('elo_k_factor') or 32,
        ELO_K_FACTOR_RANGE[0], ELO_K_FACTOR_RANGE[1],
    )
    elo_max_matches = _parse_int(
        elo_max_matches_raw, comp.get('elo_max_matches') or 200,
        ELO_MAX_MATCHES_RANGE[0], ELO_MAX_MATCHES_RANGE[1],
    )
    elo_match_interval = _parse_int(
        elo_match_interval_raw, comp.get('elo_match_interval_seconds') or 60,
        ELO_MATCH_INTERVAL_RANGE[0], ELO_MATCH_INTERVAL_RANGE[1],
    )
    elo_initial_burst = _parse_int(
        elo_initial_burst_raw, comp.get('elo_initial_burst') or 5,
        ELO_INITIAL_BURST_RANGE[0], ELO_INITIAL_BURST_RANGE[1],
    )
    elo_max_pairs_per_round = _parse_int(
        elo_max_pairs_per_round_raw, comp.get('elo_max_pairs_per_round') or 1,
        ELO_MAX_PAIRS_PER_ROUND_RANGE[0], ELO_MAX_PAIRS_PER_ROUND_RANGE[1],
    )
    script_timeout = _parse_int(
        script_timeout_raw, comp.get('scoring_script_timeout_seconds') or 120,
        SCORING_SCRIPT_TIMEOUT_RANGE[0], SCORING_SCRIPT_TIMEOUT_RANGE[1],
    )

    # ELO 对局运行时：仅在显式给出时更新；legacy=旧版单容器，isolated=仲裁者隔离运行时
    elo_runtime_mode = None
    if elo_runtime_mode_raw is not None and str(elo_runtime_mode_raw).strip() != '':
        mode = str(elo_runtime_mode_raw).strip().lower()
        elo_runtime_mode = mode if mode in ('legacy', 'isolated') else 'legacy'

    # Agent 评测的模型配置只由端点池管理；这里仅保存比赛级运行参数。
    aj_timeout_raw = request.form.get('agent_judge_timeout_seconds')
    finalize_timeout_raw = request.form.get('reverse_judge_finalize_timeout_seconds')
    aj_orchestration_raw = request.form.get('agent_judge_orchestration_mode')
    aj_timeout = None
    if aj_timeout_raw is not None and str(aj_timeout_raw).strip() != '':
        try:
            aj_timeout = int(_clamp(int(aj_timeout_raw), 60, 7200))
        except (TypeError, ValueError):
            aj_timeout = None
    finalize_timeout = None
    if finalize_timeout_raw is not None and str(finalize_timeout_raw).strip() != '':
        try:
            finalize_timeout = int(_clamp(
                int(finalize_timeout_raw),
                REVERSE_FINALIZE_TIMEOUT_RANGE[0],
                REVERSE_FINALIZE_TIMEOUT_RANGE[1],
            ))
        except (TypeError, ValueError):
            finalize_timeout = None

    # 每 48 小时窗口提交次数限制：空/0 表示不限制；范围 0~100000
    submit_limit = None
    if submit_limit_raw is not None:
        try:
            submit_limit = int(submit_limit_raw) if str(submit_limit_raw).strip() != '' else 0
        except (TypeError, ValueError):
            submit_limit = 0
        submit_limit = int(_clamp(submit_limit, 0, 100000))
    # 兼容 CLI/API 的 reset_limit_window 参数；界面刷新走独立 reset_submit_limit 路由。
    reset_window = str(reset_limit_window_raw or '').strip().lower() in ('1', 'on', 'true', 'yes')
    set_window_now = reset_window or (
        submit_limit is not None and submit_limit > 0 and not comp.get('limit_window_start')
    )

    # Agent 评测提交方式（zip 上传 / git 拉取）+ git 仓库标准命名（含 <username> 占位符）
    submission_method = None
    if submission_method_raw is not None:
        m = str(submission_method_raw).strip().lower()
        submission_method = m if m in ('zip', 'git') else 'zip'
    git_format = git_format_raw if git_format_raw is not None else None

    update_competition(
        competition_id,
        title=title,
        summary=summary,
        description=description,
        max_score=max_score_int,
        is_active=is_active,
        answer_format=new_format,
        scoring_mode=new_mode,
        elo_initial_rating=elo_initial_rating,
        elo_k_factor=elo_k_factor,
        elo_max_matches=elo_max_matches,
        elo_match_interval_seconds=elo_match_interval,
        elo_initial_burst=elo_initial_burst,
        elo_max_pairs_per_round=elo_max_pairs_per_round,
        elo_runtime_mode=elo_runtime_mode,
        scoring_script_timeout_seconds=script_timeout,
        agent_judge_timeout_seconds=aj_timeout,
        reverse_judge_finalize_timeout_seconds=finalize_timeout,
        agent_judge_orchestration_mode=(
            _normalize_aj_orchestration(aj_orchestration_raw)
            if aj_orchestration_raw is not None else None
        ),
        submit_limit_per_window=submit_limit,
        set_limit_window_now=set_window_now,
        submission_method=submission_method,
        git_format=git_format,
    )

    # 切换答案格式后，旧的标准答案文件后缀已不匹配新格式，自动清理以避免歧义
    if format_changed:
        old_ref = (comp.get('reference_answer_path') or '').strip()
        if old_ref and os.path.isfile(old_ref):
            try:
                os.remove(old_ref)
            except Exception:
                pass
        if comp.get('reference_answer_path') or comp.get('reference_answer_name'):
            update_competition_reference_answer(competition_id, None, None)
        flash(f'答案格式已切换为 {new_format.upper()}，请重新上传对应的标准答案文件。', 'warning')
    if mode_changed:
        _mode_label = {'elo': 'ELO 对战', 'agent_judge': 'Agent 评测',
                       'reverse_judge': '反向评测',
                       'absolute': '标准答案评分'}.get(new_mode, '标准答案评分')
        flash(
            f'评分模式已切换为 {_mode_label}。'
            '请注意切换前后的提交记录可能因评分语义不同导致排行榜混合显示。',
            'warning',
        )
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


# ---------- 管理员：手动刷新提交次数配额窗口 ----------

@ranking_bp.route('/<int:competition_id>/reset_submit_limit', methods=['POST'])
def ranking_reset_submit_limit(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    reset_competition_limit_window(competition_id)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


# ---------- 管理员：Agent 评测规则保存（AJAX） ----------

@ranking_bp.route('/<int:competition_id>/agent_judge/rules', methods=['POST'])
def ranking_save_judge_rules(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return jsonify({'success': False, 'message': '需要管理员权限'}), 403
    comp = get_competition(competition_id)
    if not comp:
        return jsonify({'success': False, 'message': '比赛不存在'}), 404
    payload = request.get_json(silent=True) or {}
    rules_in = payload.get('rules')
    if not isinstance(rules_in, list):
        return jsonify({'success': False, 'message': '规则格式非法'}), 400
    # DB 层会按当前列表顺序重算 rule_id，并把 dependencies 从旧编号映射到新编号。
    rules = []
    for idx, r in enumerate(rules_in):
        if not isinstance(r, dict):
            return jsonify({'success': False, 'message': f'第 {idx + 1} 条规则格式非法'}), 400
        rules.append({
            'rule_id': r.get('rule_id') or (idx + 1),
            'rule_name': (r.get('rule_name') or '').strip(),
            'rule_text': (r.get('rule_text') or '').strip(),
            'value': r.get('value'),
            'dependencies': r.get('dependencies') or [],
        })
    try:
        normalized = replace_competition_rules(competition_id, rules)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    # 同步 max_score = 规则分值之和（至少为 1，满足满分正整数约束）
    try:
        update_competition(competition_id, max_score=max(1, int(round(_aj_max_score(normalized)))))
    except Exception:
        pass
    return jsonify({'success': True, 'count': len(normalized),
                    'max_score': _aj_max_score(normalized)})


@ranking_bp.route('/<int:competition_id>/agent_judge/endpoints', methods=['POST'])
def ranking_save_agent_endpoints(competition_id):
    """保存某比赛的 Agent 评测端点池（多个 模型 url + api_key，各带并发上限）+ 整体超时。

    JSON：{timeout_seconds?, orchestration_mode?, endpoints:[{id?, harness, base_url,
    api_key, model, context_window_tokens?, max_output_tokens?,
    thinking_compatibility?, concurrency_limit, status|enabled}]}。
    实际 agent 评测并发 = 各启用端点 concurrency_limit 之和（由判题侧 Redis 槽位限流，改完即生效、无需重启）。"""
    user, err = _admin_json_guard()
    if err is not None:
        return err
    comp = get_competition(competition_id)
    if not comp:
        return jsonify(success=False, message='比赛不存在或已被删除'), 404
    payload = request.get_json(silent=True) or {}
    endpoints = payload.get('endpoints')
    timeout_raw = payload.get('timeout_seconds')
    finalize_timeout_raw = payload.get('reverse_judge_finalize_timeout_seconds')
    if finalize_timeout_raw is None:
        finalize_timeout_raw = payload.get('finalize_timeout_seconds')
    orchestration_raw = payload.get('orchestration_mode')
    if orchestration_raw is None:
        orchestration_raw = payload.get('agent_judge_orchestration_mode')
    timeout_value = None
    if timeout_raw is not None and str(timeout_raw).strip() != '':
        try:
            timeout_value = int(_clamp(int(timeout_raw), 60, 7200))
        except (TypeError, ValueError):
            pass
    finalize_timeout_value = None
    if finalize_timeout_raw is not None and str(finalize_timeout_raw).strip() != '':
        try:
            finalize_timeout_value = int(_clamp(
                int(finalize_timeout_raw),
                REVERSE_FINALIZE_TIMEOUT_RANGE[0],
                REVERSE_FINALIZE_TIMEOUT_RANGE[1],
            ))
        except (TypeError, ValueError):
            pass
    orchestration_value = (
        _normalize_aj_orchestration(orchestration_raw)
        if orchestration_raw is not None else None
    )
    try:
        save_agent_judge_configuration(
            competition_id,
            endpoints if isinstance(endpoints, list) else [],
            timeout_seconds=timeout_value,
            reverse_finalize_timeout_seconds=finalize_timeout_value,
            orchestration_mode=orchestration_value,
        )
    except ValueError as e:
        return jsonify(success=False, message=str(e)), 400
    # 重新读取（拿到新 id），回传脱敏列表（api_key 只给 has_key 标记）
    saved = list_agent_judge_endpoints(competition_id)
    masked = _masked_agent_endpoints(saved)
    total_conc = sum(e['concurrency_limit'] for e in saved if (e.get('status') == 'enabled'))
    comp_after = get_competition(competition_id) or comp
    return jsonify(success=True, count=len(saved),
                   enabled=sum(1 for e in saved if e.get('status') == 'enabled'),
                   paused=sum(1 for e in saved if e.get('status') == 'paused'),
                   disabled=sum(1 for e in saved if e.get('status') == 'disabled'),
                   total_concurrency=total_conc, endpoints=masked,
                   reverse_judge_finalize_timeout_seconds=(
                       comp_after.get('reverse_judge_finalize_timeout_seconds')
                       or REVERSE_FINALIZE_TIMEOUT_DEFAULT
                   ),
                   orchestration_mode=_normalize_aj_orchestration(
                       comp_after.get('agent_judge_orchestration_mode')))


def _quality_gate_payload_enabled(value):
    if isinstance(value, bool):
        return value
    text = str(value or '').strip().lower()
    if text in ('1', 'true', 'on', 'yes'):
        return True
    if text in ('0', 'false', 'off', 'no'):
        return False
    raise ValueError('enabled 必须是布尔值')


@ranking_bp.route('/<int:competition_id>/reverse_judge/quality_gate', methods=['POST'])
def ranking_save_reverse_quality_gate(competition_id):
    """部分更新反向评测质量门禁开关、审核标准和独立端点池。"""
    user, err = _admin_json_guard()
    if err is not None:
        return err
    comp = get_competition(competition_id)
    if not comp:
        return jsonify(success=False, message='比赛不存在或已被删除'), 404
    if _competition_scoring_mode(comp) != 'reverse_judge':
        return jsonify(success=False, message='仅反向评测模式支持质量门禁'), 400
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(success=False, message='请求体必须是 JSON 对象'), 400

    proposed_enabled = None
    if 'enabled' in payload:
        try:
            proposed_enabled = _quality_gate_payload_enabled(payload.get('enabled'))
        except ValueError as e:
            return jsonify(success=False, message=str(e)), 400
    proposed_prompt = None
    if 'prompt' in payload:
        proposed_prompt = str(payload.get('prompt') or '').strip()
        if len(proposed_prompt) > 20000:
            return jsonify(success=False, message='审核标准不能超过 20000 字'), 400
    proposed_endpoints = payload.get('endpoints') if 'endpoints' in payload else None
    if proposed_endpoints is not None and not isinstance(proposed_endpoints, list):
        return jsonify(success=False, message='endpoints 必须是数组'), 400

    update_fields = {}
    if 'enabled' in payload:
        update_fields['enabled'] = proposed_enabled
    if 'prompt' in payload:
        update_fields['prompt'] = proposed_prompt
    if proposed_endpoints is not None:
        update_fields['endpoints'] = proposed_endpoints
    try:
        save_reverse_quality_gate_configuration(competition_id, **update_fields)
    except ValueError as e:
        return jsonify(success=False, message=str(e)), 400

    comp_after = get_competition(competition_id) or comp
    saved = list_quality_gate_endpoints(competition_id)
    masked = _masked_agent_endpoints(saved)
    gate_enabled = _reverse_quality_gate_enabled(comp_after)
    prompt = str(comp_after.get('reverse_quality_gate_prompt') or '')
    enabled_count = sum(1 for e in saved if e.get('status') == 'enabled')
    paused_count = sum(1 for e in saved if e.get('status') == 'paused')
    disabled_count = sum(1 for e in saved if e.get('status') == 'disabled')
    total_concurrency = sum(
        int(e.get('concurrency_limit') or 1)
        for e in saved if e.get('status') == 'enabled'
    )
    ready = (not gate_enabled) or (bool(prompt.strip()) and enabled_count > 0)
    return jsonify(
        success=True,
        enabled=gate_enabled,
        quality_gate_enabled=gate_enabled,
        prompt=prompt,
        ready=ready,
        count=len(saved),
        enabled_count=enabled_count,
        paused_count=paused_count,
        disabled_count=disabled_count,
        total_concurrency=total_concurrency,
        endpoints=masked,
        quality_gate_endpoints=masked,
    )


# ---------- Agent 评测：实时进展 SSE + 管理员重测 ----------

_AGENT_TRACE_RESULT_FILE_RE = re.compile(
    r'result_[0-9a-fA-F]{32}\.jsonl(?:\.rule_\d+\.jsonl)?', re.I,
)
_AGENT_TRACE_PUBLIC_PHASE_RE = re.compile(r'^(?:setup|final|rule_\d+)$')


def _public_agent_trace_message(message):
    """普通参赛者只看事件形态/阶段；自由文本完整轨迹仅管理员可见。"""
    if not isinstance(message, dict):
        return None
    kind = str(message.get('kind') or 'assistant')
    if kind not in {'assistant', 'thinking', 'tool', 'subagent'}:
        kind = 'assistant'
    titles = {
        'assistant': 'AI 回复',
        'thinking': '思考片段',
        'tool': '工具调用',
        'subagent': '派出 subagent',
    }
    phase = str(message.get('phase') or '')
    if not _AGENT_TRACE_PUBLIC_PHASE_RE.fullmatch(phase):
        phase = ''
    projected = {
        'kind': kind,
        'title': titles[kind],
        'text': phase.replace('_', ' ') if phase else '',
        'meta': phase,
        'format': 'text',
    }
    for key in ('line', 'offset', 'event_index'):
        value = message.get(key)
        if isinstance(value, int):
            projected[key] = value
    source = str(message.get('source') or '')
    if re.fullmatch(r'(?:claude|codex|opencode|docker)(?:-[A-Za-z0-9]+)*', source):
        projected['source'] = source
    if phase:
        projected['phase'] = phase
    return projected


def _redact_agent_trace_value(value, sensitive_values=()):
    if isinstance(value, dict):
        return {
            key: _redact_agent_trace_value(item, sensitive_values)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_agent_trace_value(item, sensitive_values) for item in value]
    if isinstance(value, str):
        text = value
        for secret in sensitive_values:
            secret = str(secret or '')
            if secret:
                text = text.replace(secret, '[redacted]')
        return _AGENT_TRACE_RESULT_FILE_RE.sub('[result-file]', text)
    return value


def _project_agent_judge_snapshot(snapshot, *, include_internal=False,
                                  sensitive_values=(), redaction_ready=True):
    """投影评分轨迹：所有查看者都隐藏随机结果文件名，普通选手不拿原始文件。"""
    if not isinstance(snapshot, dict):
        return snapshot
    projected = copy.deepcopy(snapshot)
    trace = projected.get('execution_trace')
    if isinstance(trace, dict):
        trace = _redact_agent_trace_value(
            trace, tuple(sensitive_values or ()),
        )
        projected['execution_trace'] = trace
    if isinstance(trace, dict) and not include_internal:
        trace['trace_files'] = []
        trace['stdout'] = ''
        trace['stderr'] = ''
        trace['trace_messages'] = [
            safe for safe in (
                _public_agent_trace_message(message)
                for message in trace.get('trace_messages') or []
            ) if safe is not None
        ]
        projected['error_message'] = _redact_agent_trace_value(
            projected.get('error_message'), tuple(sensitive_values or ()),
        ) if redaction_ready else ''
        for rule in projected.get('rules') or []:
            if not isinstance(rule, dict):
                continue
            for field in ('evidence', 'evidence_html'):
                if field in rule:
                    rule[field] = (_redact_agent_trace_value(
                        rule.get(field), tuple(sensitive_values or ()),
                    ) if redaction_ready else '')
    return projected


def _canonical_terminal_judge_snapshot(submission_id, snapshot, attempt_trace_id):
    """终态事件关闭 SSE 前，从 DB/磁盘重建一次，避免把旧缓存固化在页面。"""
    if (not isinstance(snapshot, dict)
            or snapshot.get('status') in ('Judging', 'Pending', 'Queued')):
        return snapshot
    canonical = build_current_judge_snapshot(submission_id)
    if (isinstance(canonical, dict)
            and canonical.get('attempt_trace_id') == attempt_trace_id):
        return canonical
    # attempt 已切换时不能用旧终态关闭 SSE；继续等待新 attempt 的事件。
    return None

@ranking_bp.route('/<int:competition_id>/judge_stream/<int:submission_id>')
def ranking_judge_stream(competition_id, submission_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    sub = get_ranking_submission(submission_id)
    if not sub or int(sub.get('competition_id')) != competition_id:
        return Response('not found', status=404)
    if user.get('is_admin') != 1 and sub.get('username') != user.get('username'):
        return Response('forbidden', status=403)

    trace_sensitive_values = []
    trace_redaction_ready = True
    try:
        for endpoint in list_agent_judge_endpoints(competition_id, enabled_only=False):
            trace_sensitive_values.extend([
                endpoint.get('api_key'), endpoint.get('base_url'),
            ])
    except Exception:
        trace_redaction_ready = False

    def _encode(name, payload):
        payload = _project_agent_judge_snapshot(
            payload, include_internal=user.get('is_admin') == 1,
            sensitive_values=trace_sensitive_values,
            redaction_ready=trace_redaction_ready,
        )
        # 快照在下发前实时渲染 Markdown/LaTeX（仅传输时渲染，不持久化 HTML）
        if name in ('progress', 'done', 'timeout') and isinstance(payload, dict):
            payload = _render_snapshot_html(payload)
        return f"event: {name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

    @stream_with_context
    def generate():
        import time as _t
        snap = get_judge_progress_snapshot(submission_id) or build_judge_snapshot(submission_id)
        if snap is None:
            yield _encode('error', {'error': 'not found'})
            return
        yield _encode('progress', snap)
        if snap.get('status') not in ('Judging', 'Pending', 'Queued'):
            yield _encode('done', snap)
            return
        start = _t.time()
        pubsub = subscribe_judge_run_events(submission_id)
        if pubsub is None:
            last = json.dumps(snap, ensure_ascii=False)
            while True:
                s = build_judge_snapshot(submission_id)
                cur = json.dumps(s, ensure_ascii=False) if s else last
                if cur != last:
                    yield _encode('progress', s)
                    last = cur
                if s and s.get('status') not in ('Judging', 'Pending', 'Queued'):
                    yield _encode('done', s)
                    return
                if _t.time() - start > 3600:
                    yield _encode('timeout', s or snap)
                    return
                _t.sleep(2)
        try:
            while True:
                msg = pubsub.get_message(timeout=15.0)
                if _t.time() - start > 3600:
                    yield _encode('timeout', build_judge_snapshot(submission_id) or snap)
                    return
                if not msg:
                    yield ": keepalive\n\n"
                    continue
                if msg.get('type') != 'message':
                    continue
                raw = msg.get('data')
                if isinstance(raw, bytes):
                    raw = raw.decode('utf-8', 'ignore')
                try:
                    s = json.loads(raw)
                except Exception:
                    continue
                current_submission = get_ranking_submission(submission_id)
                current_trace_id = agent_judge_trace_id(
                    (current_submission or {}).get('judge_attempt_id'),
                )
                if s.get('attempt_trace_id') != current_trace_id:
                    s = build_judge_snapshot(submission_id)
                    if not s:
                        continue
                s = _canonical_terminal_judge_snapshot(
                    submission_id, s, current_trace_id,
                )
                if s is None:
                    continue
                yield _encode('progress', s)
                if s.get('status') not in ('Judging', 'Pending', 'Queued'):
                    yield _encode('done', s)
                    return
        finally:
            try:
                pubsub.close()
            except Exception:
                pass

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no',
                             'Connection': 'keep-alive'})


def _project_reverse_judge_snapshot(snapshot, *, include_internal=False):
    """按查看者权限投影反向评测快照，避免泄露质量门禁私有标准。"""
    if include_internal or not isinstance(snapshot, dict):
        return snapshot

    projected = copy.deepcopy(snapshot)
    steps = projected.get('steps')
    if not isinstance(steps, list):
        return projected

    gate_rejected = False
    for step in steps:
        if not isinstance(step, dict) or step.get('step_key') != 'quality_gate':
            continue
        result = step.get('result')
        if not isinstance(result, dict):
            continue

        passed = result.get('passed') if isinstance(result.get('passed'), bool) else None
        verdict = str(result.get('verdict') or '').strip().lower()
        if step.get('status') == 'skipped' or result.get('skipped') is True:
            verdict = 'skipped'
            passed = None
        elif verdict not in ('pass', 'reject', 'skipped'):
            verdict = 'pass' if passed is True else ('reject' if passed is False else '')
        if verdict == 'pass':
            summary = '题目已通过质量门禁'
        elif verdict == 'reject':
            summary = '题目未通过质量门禁，请检查题目包后重试'
            gate_rejected = True
        elif verdict == 'skipped':
            summary = '本次评测未执行质量门禁'
        else:
            summary = '质量门禁审核中'

        raw_violations = result.get('violations')
        violation_count = len(raw_violations) if isinstance(raw_violations, list) else 0
        step['result'] = {
            'passed': passed,
            'verdict': verdict,
            'summary': summary,
            # 模型生成的 rule/reason/evidence 都可能复述私有审核标准；仅公开数量。
            'violations': [
                {'reason': '检测到不符合质量门禁的行为'}
                for _ in range(violation_count)
            ],
        }
        # 当前门禁不产生日志；这里同时约束未来实现，避免经旁路泄露审核上下文。
        step['stdout'] = ''
        step['stderr'] = ''
        step['trace_files'] = []
        step['trace_messages'] = []
        if gate_rejected and step.get('error_message'):
            step['error_message'] = summary
    if gate_rejected and projected.get('error_message'):
        projected['error_message'] = '质量门禁未通过，请检查题目包后重试'
    return projected


@ranking_bp.route('/<int:competition_id>/reverse_judge_stream/<int:submission_id>')
def ranking_reverse_judge_stream(competition_id, submission_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    sub = get_ranking_submission(submission_id)
    if not sub or int(sub.get('competition_id')) != competition_id:
        return Response('not found', status=404)
    if user.get('is_admin') != 1 and sub.get('username') != user.get('username'):
        return Response('forbidden', status=403)

    include_internal = user.get('is_admin') == 1
    stream_timeout = _reverse_judge_stream_timeout_seconds(
        get_competition(competition_id) or {},
    )

    def _encode(name, payload):
        projected = _project_reverse_judge_snapshot(
            payload, include_internal=include_internal,
        )
        return f"event: {name}\ndata: {json.dumps(projected, ensure_ascii=False)}\n\n"

    @stream_with_context
    def generate():
        import time as _t
        snap = get_reverse_judge_progress_snapshot(submission_id) or build_reverse_judge_snapshot(submission_id)
        if snap is None:
            yield _encode('error', {'error': 'not found'})
            return
        yield _encode('progress', snap)
        if snap.get('status') not in ('Judging', 'Pending', 'Queued'):
            yield _encode('done', snap)
            return
        start = _t.time()
        pubsub = subscribe_reverse_judge_events(submission_id)
        if pubsub is None:
            last = json.dumps(snap, ensure_ascii=False)
            while True:
                s = build_reverse_judge_snapshot(submission_id)
                cur = json.dumps(s, ensure_ascii=False) if s else last
                if cur != last:
                    yield _encode('progress', s)
                    last = cur
                if s and s.get('status') not in ('Judging', 'Pending', 'Queued'):
                    yield _encode('done', s)
                    return
                if _t.time() - start > stream_timeout:
                    yield _encode('timeout', s or snap)
                    return
                _t.sleep(2)
        try:
            while True:
                msg = pubsub.get_message(timeout=15.0)
                if _t.time() - start > stream_timeout:
                    yield _encode('timeout', build_reverse_judge_snapshot(submission_id) or snap)
                    return
                if not msg:
                    yield ": keepalive\n\n"
                    continue
                if msg.get('type') != 'message':
                    continue
                raw = msg.get('data')
                if isinstance(raw, bytes):
                    raw = raw.decode('utf-8', 'ignore')
                try:
                    s = json.loads(raw)
                except Exception:
                    continue
                yield _encode('progress', s)
                if s.get('status') not in ('Judging', 'Pending', 'Queued'):
                    yield _encode('done', s)
                    return
        finally:
            try:
                pubsub.close()
            except Exception:
                pass

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no',
                             'Connection': 'keep-alive'})


@ranking_bp.route('/<int:competition_id>/submission/<int:submission_id>/rejudge_agent', methods=['POST'])
def ranking_rejudge_agent(competition_id, submission_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    sub = get_ranking_submission(submission_id)
    if not sub or int(sub.get('competition_id')) != competition_id:
        if _wants_json_response():
            return jsonify(success=False, message='提交不存在'), 404
        flash('提交不存在', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='all_submissions'))
    comp = get_competition(competition_id) or {}
    scoring_mode = _competition_scoring_mode(comp)
    if scoring_mode == 'reverse_judge':
        task_ref = _reverse_judge_task
        attempt_id = begin_agent_judge_attempt(
            submission_id, status='Queued', reset_result=True,
            clear_reverse_steps=True,
        )
    else:
        task_ref = _agent_judge_task
        attempt_id = begin_agent_judge_attempt(
            submission_id, status='Queued', reset_result=True,
            clear_agent_results=True,
        )
    if task_ref is not None:
        try:
            async_result = task_ref.apply_async(args=[submission_id, attempt_id])
            set_agent_judge_task_id(submission_id, attempt_id, async_result.id)
        except Exception as e:
            if _wants_json_response():
                return jsonify(success=False, message=f'重测入队失败：{e}'), 500
            flash(f'重测入队失败：{e}', 'warning')
    if _wants_json_response():
        return jsonify(
            success=True,
            message='已触发重新评测',
            competition_id=competition_id,
            submission_id=submission_id,
            attempt_id=attempt_id,
        )
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='all_submissions'))


# ---------- 申诉：学生发起 + 管理员审阅/处理 ----------

@ranking_bp.route('/<int:competition_id>/submission/<int:submission_id>/appeal', methods=['POST'])
def ranking_submit_appeal(competition_id, submission_id):
    """学生在「评分详情」里发起申诉。返回 JSON。"""
    user, resp = _require_user()
    if resp is not None:
        return jsonify({'ok': False, 'message': '请先登录'}), 401
    sub = get_ranking_submission(submission_id)
    if not sub or int(sub.get('competition_id')) != competition_id:
        return jsonify({'ok': False, 'message': '提交不存在'}), 404
    is_admin = user.get('is_admin') == 1
    if not is_admin and (sub.get('username') or '') != (user.get('username') or ''):
        return jsonify({'ok': False, 'message': '只能对自己的提交申诉'}), 403
    # 硬性一次：该提交已存在申诉（任何状态）→ 不能再申诉
    if get_appeal_by_submission(submission_id):
        return jsonify({'ok': False, 'already': True,
                        'message': '该提交已申诉过，每份提交只能申诉一次。'}), 409
    reason = (request.form.get('reason') or '').strip()
    if not reason:
        return jsonify({'ok': False, 'message': '请填写申诉意见'}), 400
    reason = reason[:4000]
    try:
        new_id = create_appeal(competition_id, submission_id, sub.get('username') or user.get('username'), reason)
    except Exception as e:
        return jsonify({'ok': False, 'message': f'提交失败：{e}'}), 500
    if not new_id:
        return jsonify({'ok': False, 'already': True,
                        'message': '该提交已申诉过，每份提交只能申诉一次。'}), 409
    return jsonify({'ok': True, 'status': 'pending', 'message': '申诉已提交，请等待管理员处理。'})


@ranking_bp.route('/<int:competition_id>/submission/<int:submission_id>/appeal_status', methods=['GET'])
def ranking_appeal_status(competition_id, submission_id):
    """学生/管理员查询某提交的申诉状态（用于评分详情弹窗里回显结果）。"""
    user, resp = _require_user()
    if resp is not None:
        return jsonify({'ok': False, 'success': False, 'message': '请先登录'}), 401
    sub = get_ranking_submission(submission_id)
    if not sub or int(sub.get('competition_id')) != competition_id:
        return jsonify({'ok': False, 'success': False, 'message': '提交不存在'}), 404
    is_admin = user.get('is_admin') == 1
    if not is_admin and (sub.get('username') or '') != (user.get('username') or ''):
        return jsonify({'ok': False, 'success': False, 'message': '无权查看该申诉状态'}), 403
    a = get_appeal_by_submission(submission_id)
    if not a:
        return jsonify({'ok': True, 'has_appeal': False})
    labels = {'pending': '待处理', 'rejected': '已驳回', 'resolved': '已处理'}
    return jsonify({
        'ok': True,
        'has_appeal': True,
        'status': a.get('status'),
        'status_label': labels.get(a.get('status'), a.get('status')),
        'reason': a.get('reason') or '',
        'admin_response': a.get('admin_response') or '',
    })


@ranking_bp.route('/<int:competition_id>/appeals_json', methods=['GET'])
def ranking_appeals_json(competition_id):
    """「申诉处理」标签页的分页/筛选 AJAX（返回已渲染的 rows/pagination HTML）。"""
    user = _current_user()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    if user.get('is_admin') != 1:
        return jsonify({'error': 'forbidden'}), 403
    comp = get_competition(competition_id)
    if not comp:
        return jsonify({'error': 'not_found'}), 404
    q = (request.args.get('q') or '').strip()[:50]
    status_q = (request.args.get('status') or '').strip().lower() or None
    requested_page = max(1, request.args.get('page', 1, type=int))
    rows, page, total = list_appeals(
        competition_id, page=requested_page, per_page=SUBMISSIONS_PER_PAGE,
        status_q=status_q, username_q=q or None,
    )
    total_pages = max(1, (total + SUBMISSIONS_PER_PAGE - 1) // SUBMISSIONS_PER_PAGE)
    page_numbers = _page_window(page, total_pages)
    rows_html = render_template(
        'ranking/components/appeal_rows.html',
        all_appeals=rows,
        competition=comp,
    )
    pagination_html = render_template(
        'ranking/components/pagination.html',
        competition=comp, current_page=page, total_pages=total_pages,
        page_numbers=page_numbers, submission_search_q=q, tab='appeals',
    )
    return jsonify({'rows_html': rows_html, 'pagination_html': pagination_html, 'page': page})


@ranking_bp.route('/<int:competition_id>/appeal/<int:appeal_id>/review', methods=['GET'])
def ranking_appeal_review(competition_id, appeal_id):
    """管理员申诉审阅页：左=可编辑评分详情，右=申诉意见+回复+驳回/处理+重测。"""
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        if _wants_json_response():
            return jsonify(success=False, message='比赛不存在'), 404
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    appeal = get_appeal(appeal_id)
    if not appeal or int(appeal.get('competition_id')) != competition_id:
        flash('申诉记录不存在', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='appeals'))
    submission = get_ranking_submission(appeal.get('submission_id'))
    snapshot = build_judge_snapshot(appeal.get('submission_id')) or {}
    if snapshot:
        snapshot = _render_snapshot_html(snapshot)
    return render_template(
        'ranking/appeal_review.html',
        user=user, is_admin=True, competition=comp,
        appeal=appeal, submission=submission, snapshot=snapshot,
    )


@ranking_bp.route('/<int:competition_id>/appeal/<int:appeal_id>/handle', methods=['POST'])
def ranking_appeal_handle(competition_id, appeal_id):
    """管理员「驳回」/「处理」提交：把暂存的规则状态覆盖 + 回复 + 申诉状态一并写库。
    只有这个路由（点击驳回/处理）才写库；preview/编辑都在前端暂存。"""
    user, resp = _require_admin()
    if resp is not None:
        return jsonify({'ok': False, 'message': '需要管理员权限'}), 403
    appeal = get_appeal(appeal_id)
    if not appeal or int(appeal.get('competition_id')) != competition_id:
        return jsonify({'ok': False, 'message': '申诉记录不存在'}), 404
    data = request.get_json(silent=True) or {}
    decision = 'resolved' if str(data.get('decision') or '').strip().lower() == 'resolved' else 'rejected'
    admin_response = (data.get('admin_response') or '').strip()[:8000]
    overrides = data.get('overrides') or {}
    submission_id = appeal.get('submission_id')
    try:
        # 1) 若有规则状态改动 → 写 ranking_judge_results 并回写提交分数（保留 timed_out 标记）
        if isinstance(overrides, dict) and overrides:
            total, maxs, payloads = apply_rule_overrides(submission_id, overrides)
            timed_out = False
            sub = get_ranking_submission(submission_id)
            gd = (sub or {}).get('grade_details')
            if gd:
                try:
                    parsed = json.loads(gd) if isinstance(gd, str) else gd
                    timed_out = bool(parsed.get('timed_out')) if isinstance(parsed, dict) else False
                except Exception:
                    timed_out = False
            details = {'total_score': total, 'max_score': maxs, 'timed_out': timed_out, 'rules': payloads}
            update_submission_result(submission_id, total, 'Accepted', grade_details=details)
        # 2) 写申诉状态 + 回复
        resolve_appeal(appeal_id, decision, admin_response, user.get('username'))
    except Exception as e:
        return jsonify({'ok': False, 'message': f'处理失败：{e}'}), 500
    return jsonify({
        'ok': True,
        'redirect': url_for('ranking.ranking_detail', competition_id=competition_id, tab='appeals'),
    })


# ---------- 管理员：ELO 运行控制（启动 / 停止 / 重置） ----------

def _require_elo_competition(competition_id):
    """要求当前用户是管理员且比赛存在且为 ELO 模式。返回 (comp, resp)；resp 非 None 时直接 return。"""
    user, resp = _require_admin()
    if resp is not None:
        return None, resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return None, redirect(url_for('ranking.ranking_list'))
    if _competition_scoring_mode(comp) != 'elo':
        flash('该比赛不是 ELO 评分模式', 'warning')
        return None, redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    return comp, None


@ranking_bp.route('/<int:competition_id>/elo/start', methods=['POST'])
def ranking_elo_start(competition_id):
    comp, resp = _require_elo_competition(competition_id)
    if resp is not None:
        return resp
    if not _configured_file(comp.get('scoring_script_path')):
        flash('尚未上传评测脚本，无法启动动态评分', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    set_elo_running(competition_id, True)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/elo/stop', methods=['POST'])
def ranking_elo_stop(competition_id):
    comp, resp = _require_elo_competition(competition_id)
    if resp is not None:
        return resp
    set_elo_running(competition_id, False)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/elo/reset', methods=['POST'])
def ranking_elo_reset(competition_id):
    comp, resp = _require_elo_competition(competition_id)
    if resp is not None:
        return resp
    reset_elo_state(competition_id)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/delete', methods=['POST'])
def ranking_delete(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        if _wants_json_response():
            return jsonify(success=False, message='比赛不存在'), 404
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    delete_competition(competition_id)
    # 清理磁盘文件
    comp_dir = competition_dir(competition_id)
    shutil.rmtree(comp_dir, ignore_errors=True)
    if _wants_json_response():
        return jsonify(success=True, message='已删除比赛', competition_id=competition_id)
    return redirect(url_for('ranking.ranking_list'))


@ranking_bp.route('/<int:competition_id>/upload_attachment', methods=['POST'])
def ranking_upload_attachment(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    f = request.files.get('attachment')
    if not f or not (f.filename or '').strip():
        flash('请选择要上传的附件', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    original_name = f.filename
    safe_name = _safe_filename(original_name, fallback='attachment.bin')
    target_dir = competition_attachments_dir(competition_id)
    _ensure_dir(target_dir)
    # 避免同名覆盖：前缀递增
    base, ext = os.path.splitext(safe_name)
    final_name = safe_name
    i = 1
    while os.path.exists(os.path.join(target_dir, final_name)):
        final_name = f'{base}_{i}{ext}'
        i += 1
    target_path = os.path.join(target_dir, final_name)
    try:
        f.save(target_path)
    except Exception as e:
        flash(f'上传失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    size = 0
    try:
        size = os.path.getsize(target_path)
    except Exception:
        pass
    if size > ATTACHMENT_MAX_BYTES:
        try:
            os.remove(target_path)
        except Exception:
            pass
        flash(f'附件超过 {ATTACHMENT_MAX_BYTES // (1024*1024)}MB 限制', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    create_competition_file(competition_id, original_name, target_path, size)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/attachment/<int:file_id>/delete', methods=['POST'])
def ranking_delete_attachment(competition_id, file_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    rec = get_competition_file(file_id)
    if not rec or rec.get('competition_id') != competition_id:
        if _wants_json_response():
            return jsonify(success=False, message='附件不存在'), 404
        flash('附件不存在', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    stored = rec.get('stored_path') or ''
    if stored and os.path.isfile(stored):
        try:
            os.remove(stored)
        except Exception:
            pass
    delete_competition_file(file_id)
    if _wants_json_response():
        return jsonify(success=True, message='已删除附件', competition_id=competition_id, file_id=file_id)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


# 可在浏览器里直接预览（图片/视频）的扩展名 -> 显式 MIME。仅白名单类型允许 inline 展示，且强制
# nosniff，避免上传的任意文件被浏览器当 HTML/SVG 在本站点 origin 下执行（存储型 XSS）。
# SVG 故意不在其列（可内嵌 <script>，直接打开 URL 会执行）。
@ranking_bp.route('/<int:competition_id>/attachment/<int:file_id>/download', methods=['GET'])
def ranking_download_attachment(competition_id, file_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    rec = get_competition_file(file_id)
    if not rec or rec.get('competition_id') != competition_id:
        abort(404)
    stored = rec.get('stored_path') or ''
    if not stored or not os.path.isfile(stored):
        abort(404)
    filename = rec.get('filename') or os.path.basename(stored)
    ext = os.path.splitext(filename.lower())[1]
    # inline=1：图片/视频在线预览（供查看器/播放器内联加载）。仅白名单类型，显式 MIME + nosniff
    # 防止被当 HTML 执行；conditional=True 让 send_file 支持 Range 请求，视频可拖动进度。
    # 非白名单或未带 inline 一律按附件下载（沿用原行为）。
    if request.args.get('inline') == '1' and ext in _INLINE_MEDIA_MIME:
        resp = send_file(
            os.path.abspath(stored),
            mimetype=_INLINE_MEDIA_MIME[ext],
            as_attachment=False,
            download_name=filename,
            conditional=True,
        )
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        return resp
    return send_file(
        os.path.abspath(stored),
        as_attachment=True,
        download_name=filename,
    )


@ranking_bp.route('/<int:competition_id>/upload_reference', methods=['POST'])
def ranking_upload_reference(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    if _competition_scoring_mode(comp) != 'absolute':
        flash('仅标准答案评分模式需要标准答案', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    answer_format = _competition_answer_format(comp)
    answer_ext = '.' + answer_format

    f = request.files.get('reference')
    if not f or not (f.filename or '').strip():
        flash(f'请选择标准答案文件（{answer_ext}）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    if not f.filename.lower().endswith(answer_ext):
        flash(f'标准答案必须是 {answer_ext} 文件', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    target_dir = competition_reference_dir(competition_id)
    _ensure_dir(target_dir)
    # 清理旧的
    old_path = comp.get('reference_answer_path') or ''
    safe_name = _safe_filename(f.filename, fallback=f'reference{answer_ext}')
    if not safe_name.lower().endswith(answer_ext):
        safe_name += answer_ext
    target_path = os.path.join(target_dir, safe_name)
    try:
        f.save(target_path)
    except Exception as e:
        flash(f'上传失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    if os.path.getsize(target_path) > REFERENCE_MAX_BYTES:
        os.remove(target_path)
        flash(f'标准答案超过 {REFERENCE_MAX_BYTES // (1024*1024)}MB 限制', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    if old_path and old_path != target_path and os.path.isfile(old_path):
        try:
            os.remove(old_path)
        except Exception:
            pass
    update_competition_reference_answer(competition_id, target_path, f.filename)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/upload_scoring_script', methods=['POST'])
def ranking_upload_scoring_script(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    mode = _competition_scoring_mode(comp)
    if mode == 'agent_judge':
        flash('Agent 评测不使用评测脚本', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    if mode == 'reverse_judge':
        flash('反向评测不使用后台评测脚本，请将 judge.sh 放入提交包。', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    f = request.files.get('scoring_script')
    if not f or not (f.filename or '').strip():
        flash('请选择评测脚本（.py）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))
    if not f.filename.lower().endswith('.py'):
        flash('评测脚本必须是 .py 文件', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    target_dir = competition_scoring_dir(competition_id)
    _ensure_dir(target_dir)
    old_path = comp.get('scoring_script_path') or ''
    safe_name = _safe_filename(f.filename, fallback='scoring.py')
    if not safe_name.lower().endswith('.py'):
        safe_name += '.py'
    target_path = os.path.join(target_dir, safe_name)
    try:
        f.save(target_path)
    except Exception as e:
        flash(f'上传失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    if os.path.getsize(target_path) > SCORING_SCRIPT_MAX_BYTES:
        os.remove(target_path)
        flash(f'评测脚本超过 {SCORING_SCRIPT_MAX_BYTES // (1024*1024)}MB 限制', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))

    if old_path and old_path != target_path and os.path.isfile(old_path):
        try:
            os.remove(old_path)
        except Exception:
            pass
    update_competition_scoring_script(competition_id, target_path, f.filename)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/clear_scoring_script', methods=['POST'])
def ranking_clear_scoring_script(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    old = comp.get('scoring_script_path') or ''
    if old and os.path.isfile(old):
        try:
            os.remove(old)
        except Exception:
            pass
    update_competition_scoring_script(competition_id, None, None)
    if _competition_scoring_mode(comp) in ('absolute', 'elo'):
        flash('已清除评测脚本；当前评分模式需重新上传', 'warning')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


# ---------- 提交文件下载 ----------

@ranking_bp.route(
    '/<int:competition_id>/submission/<int:submission_id>/reverse_agent_answer',
    methods=['GET'],
)
def download_reverse_agent_answer(competition_id, submission_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    archive_path = resolve_reverse_agent_answer_archive(
        user, submission_id, competition_id=competition_id,
    )
    if not archive_path:
        abort(404)
    return send_reverse_agent_answer_archive(archive_path, submission_id)


@ranking_bp.route('/submission/<int:submission_id>/answer', methods=['GET'])
def download_submission_answer(submission_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    sub = get_ranking_submission(submission_id)
    if not sub or not _can_access_submission(user, sub):
        abort(404)
    path = sub.get('answer_path') or ''
    if not path or not os.path.isfile(path):
        abort(404)
    return send_file(
        os.path.abspath(path),
        as_attachment=True,
        download_name=sub.get('answer_filename') or os.path.basename(path),
    )


@ranking_bp.route('/submission/<int:submission_id>/code', methods=['GET'])
def download_submission_code(submission_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    sub = get_ranking_submission(submission_id)
    if not sub or not _can_access_submission(user, sub):
        abort(404)
    path = sub.get('code_path') or ''
    if not path or not os.path.isfile(path):
        abort(404)
    return send_file(
        os.path.abspath(path),
        as_attachment=True,
        download_name=sub.get('code_filename') or os.path.basename(path),
    )


@ranking_bp.route('/<int:competition_id>/submission/<int:submission_id>/delete', methods=['POST'])
def ranking_delete_submission(competition_id, submission_id):
    """管理员删除一条提交记录及其存档文件。

    排行榜由 MAX(score) 动态聚合，删除本条后下一次渲染即自动反映受影响用户的新最高分。
    """
    user, resp = _require_admin()
    if resp is not None:
        return resp
    sub = get_ranking_submission(submission_id)
    if not sub or sub.get('competition_id') != competition_id:
        if _wants_json_response():
            return jsonify(success=False, message='提交记录不存在'), 404
        flash('提交记录不存在', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='all_submissions'))

    username = sub.get('username') or ''
    comp = get_competition(competition_id)
    cleanup_warnings = _cancel_ranking_submission_runtime(sub, comp)
    # 清理磁盘上的答案 + 代码文件
    target_dir = submission_dir(submission_id)
    if os.path.isdir(target_dir):
        shutil.rmtree(target_dir, ignore_errors=True)
    # 删除数据库行
    delete_ranking_submission(submission_id)
    if _wants_json_response():
        return jsonify(
            success=True,
            message='已删除提交',
            competition_id=competition_id,
            submission_id=submission_id,
            username=username,
            warnings=cleanup_warnings,
        )
    for warning in cleanup_warnings[:3]:
        flash(warning, 'warning')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='all_submissions'))
