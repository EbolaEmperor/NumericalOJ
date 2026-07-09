#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打榜赛（Ranking Competition）路由。
"""

import json
import os
import secrets
import shutil
import subprocess
import uuid
from datetime import datetime

import markdown
from flask import (
    Blueprint, Response, abort, flash, jsonify, redirect, render_template, request,
    send_file, session, stream_with_context, url_for,
)
from werkzeug.utils import secure_filename

try:
    import redis as _redis
except Exception:  # pragma: no cover
    _redis = None

import config as _cfg
from config import REDIS_DB, REDIS_HOST, REDIS_PORT
from oj_modules.db_services import (
    get_all_classes_except_admin, get_user_by_username, get_users_in_classes,
)
from oj_modules.markdown_utils import sanitize_html
from oj_modules.security_utils import rate_limit_hit
from oj_modules.ranking_db import (
    competition_attachments_dir,
    competition_dir,
    competition_reference_dir,
    competition_scoring_dir,
    copy_competition,
    create_appeal,
    create_competition,
    create_competition_file,
    create_ranking_submission,
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
    get_ranking_submission,
    get_submission_quota,
    get_submission_stats,
    invalidate_ranking_submission_attempt,
    init_submission_elo_state,
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
    resolve_appeal,
    retire_excess_user_submissions,
    RankingSubmissionQuotaExceeded,
    set_elo_running,
    set_agent_judge_task_id,
    set_submission_status,
    submission_dir,
    update_competition,
    update_competition_reference_answer,
    update_competition_scoring_script,
    update_submission_files,
    update_submission_result,
)
from oj_modules.ranking_agent_judge_db import (
    apply_rule_overrides,
    build_judge_snapshot,
    clear_judge_results,
    list_agent_judge_endpoints,
    list_competition_rules,
    replace_competition_rules,
    save_agent_judge_endpoints,
)
from oj_modules.ranking_agent_judge import max_score as _aj_max_score
from oj_modules.ranking_agent_judge import normalize_orchestration_mode as _normalize_aj_orchestration
from oj_modules.ranking_agent_judge import render_snapshot_html as _render_snapshot_html
from oj_modules.tasks import get_judge_progress_snapshot, subscribe_judge_run_events
from oj_modules.tasks import get_reverse_judge_progress_snapshot, subscribe_reverse_judge_events
from oj_modules.tasks import get_probe_job
from oj_modules.tasks import get_bulk_rejudge_job, save_bulk_rejudge_job
from oj_modules.tasks.ranking_batch_pull_tasks import (
    PLACEHOLDER as BATCH_PLACEHOLDER, USERNAME_RE as BATCH_USERNAME_RE, build_repo_url,
    repo_last_commit,
)
from oj_modules.ranking_reverse_judge_db import (
    build_reverse_judge_snapshot,
)


ranking_bp = Blueprint('ranking', __name__, url_prefix='/ranking')

ALLOWED_TABS = ('description', 'submit', 'leaderboard', 'matches', 'all_submissions', 'appeals', 'edit', 'batch_eval')
SUBMISSIONS_PER_PAGE = 50
MATCHES_PER_PAGE = 20
# 「批量评测」标签页预填的 Git 仓库标准命名示例（可在 config.py 覆盖）。
BATCH_DEFAULT_TEMPLATE = getattr(
    _cfg, 'RANKING_BATCH_DEFAULT_TEMPLATE', 'gitea@10.72.190.121:<username>/FinalProject.git',
)

# 对战列表 / 详情的 Redis 缓存
# scope 用于区分 "全部" 和 "与我相关"：scope = '' 或 user:<username>
ELO_MATCHES_LIST_CACHE_KEY = "ranking:elo:matches_list:{comp}:{scope}:{page}:{per_page}"
ELO_MATCHES_LIST_CACHE_TTL = 30           # 列表频繁追加新对战，TTL 短一些；可接受最多 30s 旧数据
ELO_MATCH_DETAIL_CACHE_KEY = "ranking:elo:match_detail:{match_id}"
ELO_MATCH_DETAIL_CACHE_TTL = 3600         # 单场记录写入后不变（immutable），缓 1 小时
ANSWER_MAX_BYTES = 64 * 1024 * 1024        # 64MB
CODE_ZIP_MAX_BYTES = 128 * 1024 * 1024     # 128MB
ATTACHMENT_MAX_BYTES = 256 * 1024 * 1024   # 256MB
SCORING_SCRIPT_MAX_BYTES = 4 * 1024 * 1024 # 4MB
REFERENCE_MAX_BYTES = 64 * 1024 * 1024     # 64MB

ALLOWED_ANSWER_FORMATS = ('json', 'zip')
ALLOWED_SCORING_MODES = ('absolute', 'elo', 'agent_judge', 'reverse_judge')

# ELO 参数取值范围
ELO_INITIAL_RATING_RANGE = (100.0, 5000.0)
ELO_K_FACTOR_RANGE = (1.0, 200.0)
ELO_MAX_MATCHES_RANGE = (1, 10000)
ELO_MATCH_INTERVAL_RANGE = (5, 3600)
ELO_INITIAL_BURST_RANGE = (0, 50)
ELO_MAX_PAIRS_PER_ROUND_RANGE = (1, 8)   # 与 ranking_elo_tasks.MAX_PAIRS_PER_ROUND 保持一致
SCORING_SCRIPT_TIMEOUT_RANGE = (5, 600)
REVERSE_FINALIZE_TIMEOUT_DEFAULT = 180
REVERSE_FINALIZE_TIMEOUT_RANGE = (30, 7200)


def _normalize_answer_format(value, default='json'):
    fmt = str(value or '').strip().lower()
    return fmt if fmt in ALLOWED_ANSWER_FORMATS else default


def _competition_answer_format(comp):
    return _normalize_answer_format((comp or {}).get('answer_format'))


def _normalize_scoring_mode(value, default='absolute'):
    mode = str(value or '').strip().lower()
    return mode if mode in ALLOWED_SCORING_MODES else default


def _competition_scoring_mode(comp):
    return _normalize_scoring_mode((comp or {}).get('scoring_mode'))


def _configured_file(path):
    path = str(path or '').strip()
    return bool(path and os.path.isfile(path))


def _agent_judge_endpoint_ready(competition_id, comp):
    """Agent 评测是否就绪：要求端点池中至少有一个**启用**端点（不再回退旧的单端点字段）。"""
    try:
        return bool(list_agent_judge_endpoints(competition_id, enabled_only=True))
    except Exception:
        return False


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


def _submission_quota_message(quota):
    return (
        f"本轮提交次数已用完（每 48 小时上限 {quota['limit']} 次），"
        f"将于 {quota['next_reset']:%Y-%m-%d %H:%M} 刷新。"
    )


def _fake_agent_judge_enabled():
    raw = os.getenv('NUMOJ_FAKE_AGENT_JUDGE')
    if raw is None:
        raw = getattr(_cfg, 'NUMOJ_FAKE_AGENT_JUDGE', False)
    return str(raw).strip().lower() in {'1', 'true', 'yes', 'on'}


def _ranking_submit_block_reason(comp, competition_id, user=None):
    if not comp:
        return '比赛不存在或已被删除'

    is_admin = bool(user and user.get('is_admin') == 1)
    if not is_admin and comp.get('is_active') != 1:
        return '该比赛未开放'

    scoring_mode = _competition_scoring_mode(comp)
    if scoring_mode == 'absolute':
        missing_ref = not _configured_file(comp.get('reference_answer_path'))
        missing_script = not _configured_file(comp.get('scoring_script_path'))
        if missing_ref and missing_script:
            return '该比赛为标准答案评分模式，但管理员尚未上传标准答案和评测脚本，暂时无法提交。'
        if missing_ref:
            return '该比赛为标准答案评分模式，但管理员尚未上传标准答案，暂时无法提交。'
        if missing_script:
            return '该比赛为标准答案评分模式，但管理员尚未上传评测脚本，暂时无法提交。'
        return ''

    if scoring_mode == 'elo':
        if not _configured_file(comp.get('scoring_script_path')):
            return '该比赛为 ELO 模式，但管理员尚未上传评测脚本，暂时无法提交。'
        return ''

    if scoring_mode == 'agent_judge':
        if not _fake_agent_judge_enabled():
            if not _agent_judge_endpoint_ready(competition_id, comp):
                return '该比赛为 Agent 评测模式，但管理员尚未配置模型端点，暂时无法提交。'
            if not list_competition_rules(competition_id):
                return '该比赛尚未设置评分规则，暂时无法提交。'
        method = (comp.get('submission_method') or 'zip').strip().lower()
        if method == 'git':
            tmpl = (comp.get('git_format') or '').strip()
            if not tmpl or BATCH_PLACEHOLDER not in tmpl:
                return '该比赛启用 Git 提交方式，但管理员尚未配置 Git 仓库标准命名，暂时无法提交。'
            if user:
                uname = (user.get('username') or '').strip()
                if not BATCH_USERNAME_RE.match(uname):
                    return '你的用户名不符合 Git 仓库命名要求，暂时无法提交。'
        return ''

    if scoring_mode == 'reverse_judge':
        if not _agent_judge_endpoint_ready(competition_id, comp):
            return '该比赛为反向评测模式，但管理员尚未配置模型端点，暂时无法提交。'
        return ''

    return '该比赛评分模式配置异常，暂时无法提交。'


def _wants_json_response():
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    accept = (request.headers.get('Accept') or '').lower()
    return 'application/json' in accept and 'text/html' not in accept


def _submit_error_response(competition_id, message, category='warning', status=400):
    if _wants_json_response():
        return jsonify(success=False, message=message), status
    flash(message, category)
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


def _page_window(current_page, total_pages, radius=5):
    start = max(1, current_page - radius)
    end = min(total_pages, current_page + radius)
    return list(range(start, end + 1))


def _redis_client():
    if _redis is None:
        return None
    try:
        return _redis.StrictRedis(
            host=REDIS_HOST, port=int(REDIS_PORT), db=int(REDIS_DB),
            decode_responses=True,
        )
    except Exception:
        return None


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
    prefix = f'rj_judge_{sid}_'
    for line in (proc.stdout or '').splitlines():
        name = line.strip()
        if name.startswith(prefix) and name not in names:
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


def _serialize_for_cache(obj):
    """datetime → str；其余按默认 json 处理。"""
    return json.dumps(obj, default=str, ensure_ascii=False)


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


def fetch_competition_matches_cached(competition_id, page, per_page, username=None):
    """先看 Redis，命中返回；未命中查 DB 再回填。
    username 不为空时只返回该用户参与的对战，cache key 隔离开。
    返回 (rows, page, total)。"""
    rds = _redis_client()
    scope = ('user:' + str(username)) if username else ''
    cache_key = ELO_MATCHES_LIST_CACHE_KEY.format(
        comp=int(competition_id), scope=scope, page=int(page), per_page=int(per_page),
    )
    if rds is not None:
        try:
            cached = rds.get(cache_key)
            if cached:
                payload = json.loads(cached)
                return payload['rows'], int(payload['page']), int(payload['total'])
        except Exception:
            pass
    rows, eff_page, total = list_competition_matches(
        int(competition_id), page=int(page), per_page=int(per_page), username=username,
    )
    if rds is not None:
        try:
            rds.set(
                cache_key,
                _serialize_for_cache({'rows': rows, 'page': eff_page, 'total': total}),
                ex=ELO_MATCHES_LIST_CACHE_TTL,
            )
        except Exception:
            pass
    return rows, eff_page, total


def fetch_competition_match_detail_cached(match_id, competition_id):
    """单场对战详情：缓存 1h。返回 dict 或 None。"""
    rds = _redis_client()
    cache_key = ELO_MATCH_DETAIL_CACHE_KEY.format(match_id=int(match_id))
    if rds is not None:
        try:
            cached = rds.get(cache_key)
            if cached:
                row = json.loads(cached)
                # 命中后再校验属于此 comp（防止跨比赛猜 ID）
                if int(row.get('competition_id') or 0) != int(competition_id):
                    return None
                return row
        except Exception:
            pass
    row = get_competition_match(int(match_id), int(competition_id))
    if not row:
        return None
    if rds is not None:
        try:
            rds.set(
                cache_key,
                _serialize_for_cache(row),
                ex=ELO_MATCH_DETAIL_CACHE_TTL,
            )
        except Exception:
            pass
    return row


_evaluate_ranking_task = None
_elo_initial_burst_task = None
_agent_judge_task = None
_reverse_judge_task = None
_batch_probe_task = None
_batch_run_task = None
_bulk_rejudge_task = None
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
                        bulk_rejudge_task=None):
    global _evaluate_ranking_task, _elo_initial_burst_task, _agent_judge_task, _reverse_judge_task, _rds
    global _batch_probe_task, _batch_run_task, _bulk_rejudge_task
    _evaluate_ranking_task = evaluate_ranking_task
    _elo_initial_burst_task = elo_initial_burst_task
    _agent_judge_task = agent_judge_task
    _reverse_judge_task = reverse_judge_task
    _batch_probe_task = batch_probe_task
    _batch_run_task = batch_run_task
    _bulk_rejudge_task = bulk_rejudge_task
    if redis_client is not None:
        _rds = redis_client


def _current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


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


def _render_description(text):
    if not text:
        return ''
    return sanitize_html(markdown.markdown(
        text,
        extensions=['extra', 'fenced_code', 'tables'],
    ))


# ---------- 列表页 ----------

@ranking_bp.route('/', methods=['GET'])
def ranking_list():
    user, resp = _require_user()
    if resp is not None:
        return resp
    is_admin = user.get('is_admin') == 1
    competitions = list_competitions(include_inactive=is_admin)
    return render_template(
        'ranking_list.html',
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
    flash('已创建打榜赛', 'success')
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
        new_id = copy_competition(competition_id, created_by=user.get('username'))
    except Exception as e:
        flash(f'复制失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_list'))
    flash(f'已复制为非公开副本《{comp.get("title")}（副本）》（#{new_id}），当前为下线状态，'
          f'可进入编辑后再上线。', 'success')
    return redirect(url_for('ranking.ranking_list'))


# ---------- 详情页（带侧边栏标签） ----------

@ranking_bp.route('/<int:competition_id>/', methods=['GET'])
def ranking_detail(competition_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在或已被删除', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    is_admin = user.get('is_admin') == 1
    if not is_admin and comp.get('is_active') != 1:
        flash('该比赛未开放', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    tab = (request.args.get('tab') or 'description').strip().lower()
    if tab not in ALLOWED_TABS:
        tab = 'description'
    if tab in ('all_submissions', 'appeals', 'edit', 'batch_eval') and not is_admin:
        tab = 'description'
    # 「申诉处理」仅 Agent 评测模式 + 管理员
    if tab == 'appeals' and _competition_scoring_mode(comp) != 'agent_judge':
        tab = 'description'

    files = list_competition_files(competition_id)
    for _f in files:   # 标注可直接预览的图片/视频，模板据此显示「播放/查看」按钮
        _f['media_kind'] = _attachment_media_kind(_f.get('filename'))
    # markdown 解析仅在「比赛说明」标签下做；其它标签传空串避免每次切换都要解析一遍。
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

    scoring_mode = _competition_scoring_mode(comp)
    is_agent_judge = scoring_mode == 'agent_judge'
    is_reverse_judge = scoring_mode == 'reverse_judge'
    is_ai_judge = is_agent_judge or is_reverse_judge
    judge_rules = list_competition_rules(competition_id) if is_agent_judge else []
    agent_judge_api_key_set = bool((comp.get('agent_judge_api_key') or '').strip())
    # Agent 评测端点池（编辑器用；api_key 不回传明文，仅给 has_key 标记）+ 就绪标志
    aj_endpoints = []
    agent_judge_ready = False
    if is_ai_judge:
        try:
            _raw_eps = list_agent_judge_endpoints(competition_id)
        except Exception:
            _raw_eps = []
        aj_endpoints = [{'id': e['id'], 'harness': e.get('harness') or 'claude_code',
                         'base_url': e['base_url'], 'model': e['model'],
                         'concurrency_limit': e['concurrency_limit'], 'status': e.get('status') or 'enabled',
                         'enabled': e['enabled'],
                         'has_key': bool(e['api_key'])} for e in _raw_eps]
        agent_judge_ready = _agent_judge_endpoint_ready(competition_id, comp) and bool(judge_rules)
        if is_reverse_judge:
            agent_judge_ready = _agent_judge_endpoint_ready(competition_id, comp)

    # 「批量评测」对 Agent 评测 / 反向评测开放，共用 Git 标准命名与端点池
    if tab == 'batch_eval' and not is_ai_judge:
        tab = 'description'

    batch_classes = []
    if tab == 'batch_eval':
        batch_classes = get_all_classes_except_admin()

    # Agent 评测打榜赛的提交方式（zip 上传 / git 拉取）
    submission_method = (comp.get('submission_method') or 'zip').strip().lower()
    if submission_method not in ('zip', 'git'):
        submission_method = 'zip'

    submit_quota = None
    submit_block_reason = ''
    git_repo_url = None
    if tab == 'submit':
        user_submissions = list_user_submissions(competition_id, user.get('username'))
        submit_block_reason = _ranking_submit_block_reason(comp, competition_id, user=user)
        if not is_admin:
            submit_quota = get_submission_quota(competition_id, user.get('username'), comp=comp)
            if not submit_block_reason and submit_quota is not None and submit_quota['remaining'] <= 0:
                submit_block_reason = _submission_quota_message(submit_quota)
        # git 提交方式：把标准命名里的 <username> 换成本人学号，算出本人仓库地址
        if is_ai_judge and (submission_method == 'git' or is_reverse_judge):
            uname = (user.get('username') or '').strip()
            tmpl = (comp.get('git_format') or '').strip()
            if tmpl and BATCH_USERNAME_RE.match(uname):
                git_repo_url = build_repo_url(tmpl, uname)
    elif tab == 'leaderboard':
        leaderboard = get_leaderboard(competition_id)
    elif tab == 'matches':
        requested_page = max(1, request.args.get('page', 1, type=int))
        matches_mine = str(request.args.get('mine') or '').strip() in ('1', 'true', 'on', 'yes')
        username_filter = user.get('username') if matches_mine else None
        matches, current_page, matches_total = fetch_competition_matches_cached(
            competition_id, requested_page, MATCHES_PER_PAGE, username=username_filter,
        )
        total_pages = max(1, (matches_total + MATCHES_PER_PAGE - 1) // MATCHES_PER_PAGE)
        page_numbers = _page_window(current_page, total_pages)
    elif tab == 'all_submissions':
        submission_search_q = (request.args.get('q') or '').strip()[:50]
        requested_page = max(1, request.args.get('page', 1, type=int))
        all_submissions, current_page, total_filtered = list_all_submissions(
            competition_id,
            page=requested_page,
            per_page=SUBMISSIONS_PER_PAGE,
            username_q=submission_search_q or None,
        )
        total_pages = max(1, (total_filtered + SUBMISSIONS_PER_PAGE - 1) // SUBMISSIONS_PER_PAGE)
        page_numbers = _page_window(current_page, total_pages)
        submission_stats = get_submission_stats(competition_id)
    elif tab == 'appeals':
        submission_search_q = (request.args.get('q') or '').strip()[:50]
        requested_page = max(1, request.args.get('page', 1, type=int))
        all_appeals, current_page, total_filtered = list_appeals(
            competition_id,
            page=requested_page,
            per_page=SUBMISSIONS_PER_PAGE,
            status_q=(request.args.get('status') or '').strip().lower() or None,
            username_q=submission_search_q or None,
        )
        total_pages = max(1, (total_filtered + SUBMISSIONS_PER_PAGE - 1) // SUBMISSIONS_PER_PAGE)
        page_numbers = _page_window(current_page, total_pages)
        appeal_stats = get_appeal_stats(competition_id)

    return render_template(
        'ranking_detail.html',
        user=user,
        is_admin=is_admin,
        competition=comp,
        files=files,
        tab=tab,
        rendered_description=rendered_description,
        user_submissions=user_submissions,
        submit_quota=submit_quota,
        all_submissions=all_submissions,
        all_appeals=all_appeals,
        appeal_stats=appeal_stats,
        leaderboard=leaderboard,
        submission_stats=submission_stats,
        current_page=current_page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        submission_search_q=submission_search_q,
        submissions_per_page=SUBMISSIONS_PER_PAGE,
        matches=matches,
        matches_total=matches_total,
        matches_mine=matches_mine,
        matches_per_page=MATCHES_PER_PAGE,
        judge_rules=judge_rules,
        agent_judge_api_key_set=agent_judge_api_key_set,
        aj_endpoints=aj_endpoints,
        agent_judge_ready=agent_judge_ready,
        is_reverse_judge=is_reverse_judge,
        is_ai_judge=is_ai_judge,
        batch_classes=batch_classes,
        batch_default_template=BATCH_DEFAULT_TEMPLATE,
        submission_method=submission_method,
        git_repo_url=git_repo_url,
        submit_block_reason=submit_block_reason,
    )


def _invalidate_competition_match_caches(competition_id, match_id=None):
    """删除/撤销对战后，清掉该赛事的对战列表与详情缓存。
    列表 key 形如 ranking:elo:matches_list:<comp>:*；详情 key 形如
    ranking:elo:match_detail:<match_id>。"""
    rds = _redis_client()
    if rds is None:
        return
    try:
        list_pattern = ELO_MATCHES_LIST_CACHE_KEY.format(
            comp=int(competition_id), scope='*', page='*', per_page='*',
        )
        for key in rds.scan_iter(match=list_pattern, count=200):
            try:
                rds.delete(key)
            except Exception:
                pass
    except Exception:
        pass
    if match_id is not None:
        try:
            rds.delete(ELO_MATCH_DETAIL_CACHE_KEY.format(match_id=int(match_id)))
        except Exception:
            pass


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
    # 只暴露需要的字段；details 可能是 JSON-as-string 也可能就是普通文本
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
        'error_message': row.get('error_message'),
    })


# ---------- 管理员：删除对战并撤销分数变动 ----------

@ranking_bp.route('/<int:competition_id>/match/<int:match_id>/delete', methods=['POST'])
def ranking_delete_match(competition_id, match_id):
    """管理员删除某场 ELO 对战；该对战导致的双方分数变动从当前 rating 里"反加回去"，
    elo_match_count 也各减 1。winner == 0（评测失败）的对战只删行，不动分数。"""
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

    if int(result.get('winner') or 0) in (1, 2):
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
            'winner': int(result.get('winner') or 0),
            'delta_a': float(result.get('delta_a') or 0),
            'delta_b': float(result.get('delta_b') or 0),
            'message': msg,
        })
    flash(msg, 'success')
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

    flash(
        '已按时间顺序重放 {n} 场对战，{u} 份提交的 ELO 分数与对战次数已同步到重放终态。'
        '（初始分 {init:.0f}，K = {k:.0f}）'.format(
            n=int(result.get('matches_replayed') or 0),
            u=int(result.get('submissions_updated') or 0),
            init=float(result.get('initial_rating') or 1500),
            k=float(result.get('k_factor') or 32),
        ),
        'success',
    )
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
        '_ranking_submission_rows.html',
        all_submissions=rows,
        competition=comp,
        is_elo=is_elo,
        max_score=max_score,
        is_agent_judge=is_agent_judge,
        is_reverse_judge=is_reverse_judge,
    )
    pagination_html = render_template(
        '_ranking_submission_pagination.html',
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
    matches, current_page, matches_total = fetch_competition_matches_cached(
        competition_id, requested_page, MATCHES_PER_PAGE, username=username_filter,
    )
    total_pages = max(1, (matches_total + MATCHES_PER_PAGE - 1) // MATCHES_PER_PAGE)
    page_numbers = _page_window(current_page, total_pages)

    html = render_template(
        '_ranking_matches_inner.html',
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

    answer_format = _competition_answer_format(comp)
    answer_ext = '.' + answer_format
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
        try:
            submission_id = create_ranking_submission(
                competition_id, user.get('username'), enforce_quota=not is_admin,
                agent_endpoint_id=endpoint_id,
            )
        except RankingSubmissionQuotaExceeded as e:
            return _submit_error_response(competition_id, _submission_quota_message(e.quota), status=429)
        target_dir = submission_dir(submission_id)
        _ensure_dir(target_dir)
        code_name = _safe_filename(code_file.filename, fallback='reverse_judge.zip')
        if not code_name.lower().endswith('.zip'):
            code_name += '.zip'
        code_path = os.path.join(target_dir, code_name)
        try:
            code_file.save(code_path)
            if os.path.getsize(code_path) > CODE_ZIP_MAX_BYTES:
                raise ValueError(f'题目包超过 {CODE_ZIP_MAX_BYTES // (1024*1024)}MB 限制')
        except Exception as e:
            shutil.rmtree(target_dir, ignore_errors=True)
            return _submit_error_response(competition_id, f'文件保存失败：{e}', category='danger')
        update_submission_files(submission_id, None, None, code_name, code_path, base_model=None)
        attempt_id = begin_agent_judge_attempt(submission_id, status='Queued', reset_result=True)
        if _reverse_judge_task is None:
            flash('已接收提交，但反向评测任务未初始化，请联系管理员', 'warning')
        else:
            try:
                async_result = _reverse_judge_task.apply_async(args=[submission_id, attempt_id, endpoint_id])
                set_agent_judge_task_id(submission_id, attempt_id, async_result.id)
            except Exception as e:
                flash(f'已接收提交，但反向评测任务入队失败：{e}', 'warning')
        flash('提交成功，反向评测进行中，可在"我的历史提交"查看三步详情。', 'success')
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
        try:
            submission_id = create_ranking_submission(
                competition_id, user.get('username'), enforce_quota=not is_admin,
            )
        except RankingSubmissionQuotaExceeded as e:
            return _submit_error_response(competition_id, _submission_quota_message(e.quota), status=429)
        target_dir = submission_dir(submission_id)
        _ensure_dir(target_dir)
        code_name = _safe_filename(code_file.filename, fallback='code.zip')
        if not code_name.lower().endswith('.zip'):
            code_name += '.zip'
        code_path = os.path.join(target_dir, code_name)
        try:
            code_file.save(code_path)
            if os.path.getsize(code_path) > CODE_ZIP_MAX_BYTES:
                raise ValueError(f'代码文件超过 {CODE_ZIP_MAX_BYTES // (1024*1024)}MB 限制')
        except Exception as e:
            shutil.rmtree(target_dir, ignore_errors=True)
            return _submit_error_response(competition_id, f'文件保存失败：{e}', category='danger')
        update_submission_files(submission_id, None, None, code_name, code_path, base_model=base_model)
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
        flash('提交成功，Agent 评测进行中，可在"我的历史提交"点击"查看详情"查看实时进展。', 'success')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

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

    try:
        submission_id = create_ranking_submission(
            competition_id, user.get('username'), enforce_quota=not is_admin,
        )
    except RankingSubmissionQuotaExceeded as e:
        return _submit_error_response(competition_id, _submission_quota_message(e.quota), status=429)
    target_dir = submission_dir(submission_id)
    _ensure_dir(target_dir)

    answer_name = _safe_filename(answer_name_raw, fallback=f'answer{answer_ext}')
    if not answer_name.lower().endswith(answer_ext):
        answer_name += answer_ext
    code_name = _safe_filename(code_name_raw, fallback='code.zip')
    if not code_name.lower().endswith('.zip'):
        code_name += '.zip'

    answer_path = os.path.join(target_dir, answer_name)
    code_path = os.path.join(target_dir, code_name)
    try:
        answer_file.save(answer_path)
        code_file.save(code_path)
    except Exception as e:
        return _submit_error_response(competition_id, f'文件保存失败：{e}', category='danger')

    try:
        if os.path.getsize(answer_path) > ANSWER_MAX_BYTES:
            raise ValueError(f'答案文件超过 {ANSWER_MAX_BYTES // (1024*1024)}MB 限制')
        if os.path.getsize(code_path) > CODE_ZIP_MAX_BYTES:
            raise ValueError(f'代码文件超过 {CODE_ZIP_MAX_BYTES // (1024*1024)}MB 限制')
    except Exception as e:
        shutil.rmtree(target_dir, ignore_errors=True)
        return _submit_error_response(competition_id, str(e), category='danger')

    update_submission_files(submission_id, answer_name, answer_path, code_name, code_path, base_model=base_model)

    if scoring_mode == 'elo':
        # 初始化 ELO 状态、退役同用户更早提交、调度即时补战
        initial_rating = float(comp.get('elo_initial_rating') or 1500)
        init_submission_elo_state(submission_id, initial_rating)
        retire_excess_user_submissions(competition_id, user.get('username'), keep_count=2)
        if _elo_initial_burst_task is not None:
            try:
                _elo_initial_burst_task.apply_async(
                    args=[competition_id, submission_id], countdown=3,
                )
            except Exception as e:
                flash(f'已加入 ELO 池，但即时补战入队失败：{e}', 'warning')
        flash('提交成功，已加入 ELO 对战池，将与池中其他用户的提交两两 PK。', 'success')
    else:
        if _evaluate_ranking_task is None:
            flash('已接收提交，但评测任务未初始化，请联系管理员', 'warning')
        else:
            try:
                async_result = _evaluate_ranking_task.apply_async(args=[submission_id])
                set_agent_judge_task_id(submission_id, None, async_result.id)
            except Exception as e:
                flash(f'已接收提交，但评测任务入队失败：{e}', 'warning')
        flash('提交成功，正在评测中', 'success')
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
    answer_format_raw = request.form.get('answer_format')
    scoring_mode_raw = request.form.get('scoring_mode')
    elo_initial_rating_raw = request.form.get('elo_initial_rating')
    elo_k_factor_raw = request.form.get('elo_k_factor')
    elo_max_matches_raw = request.form.get('elo_max_matches')
    elo_match_interval_raw = request.form.get('elo_match_interval_seconds')
    elo_initial_burst_raw = request.form.get('elo_initial_burst')
    elo_max_pairs_per_round_raw = request.form.get('elo_max_pairs_per_round')
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

    old_format = _competition_answer_format(comp)
    new_format = _normalize_answer_format(answer_format_raw, default=old_format)
    format_changed = (new_format != old_format)

    old_mode = _competition_scoring_mode(comp)
    new_mode = _normalize_scoring_mode(scoring_mode_raw, default=old_mode)
    mode_changed = (new_mode != old_mode)
    if new_mode == 'reverse_judge':
        max_score_int = 100

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

    # Agent 评测配置：base_url / model 直接保存；api_key 留空表示不变；timeout 范围 60~7200
    aj_base_url = request.form.get('agent_judge_base_url')
    aj_model = request.form.get('agent_judge_model')
    aj_timeout_raw = request.form.get('agent_judge_timeout_seconds')
    finalize_timeout_raw = request.form.get('reverse_judge_finalize_timeout_seconds')
    aj_api_key_raw = request.form.get('agent_judge_api_key')
    aj_orchestration_raw = request.form.get('agent_judge_orchestration_mode')
    aj_api_key = None
    if aj_api_key_raw is not None and str(aj_api_key_raw).strip() != '':
        aj_api_key = str(aj_api_key_raw).strip()
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
        scoring_script_timeout_seconds=script_timeout,
        agent_judge_base_url=(aj_base_url if aj_base_url is not None else None),
        agent_judge_model=(aj_model if aj_model is not None else None),
        agent_judge_api_key=aj_api_key,
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
    if not format_changed and not mode_changed:
        flash('已保存比赛信息', 'success')
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
    flash('已刷新提交次数', 'success')
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


# ---------- 管理员：Agent 评测模型配置（专用端点，仅改 agent_judge_* 字段） ----------

@ranking_bp.route('/<int:competition_id>/agent_judge/config', methods=['POST'])
def ranking_save_agent_config(competition_id):
    """仅更新 Agent 评测的 base_url / api_key / model / 整体超时；
    不触碰标题、摘要、描述、上线状态等其它字段（避免被部分表单清空）。"""
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    base_url = request.form.get('agent_judge_base_url')
    model = request.form.get('agent_judge_model')
    api_key_raw = request.form.get('agent_judge_api_key')
    timeout_raw = request.form.get('agent_judge_timeout_seconds')
    finalize_timeout_raw = request.form.get('reverse_judge_finalize_timeout_seconds')
    orchestration_raw = request.form.get('agent_judge_orchestration_mode')
    api_key = None
    if api_key_raw is not None and str(api_key_raw).strip() != '':
        api_key = str(api_key_raw).strip()
    timeout = None
    if timeout_raw is not None and str(timeout_raw).strip() != '':
        try:
            timeout = int(_clamp(int(timeout_raw), 60, 7200))
        except (TypeError, ValueError):
            timeout = None
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
    update_competition(
        competition_id,
        agent_judge_base_url=(base_url if base_url is not None else None),
        agent_judge_model=(model if model is not None else None),
        agent_judge_api_key=api_key,
        agent_judge_timeout_seconds=timeout,
        reverse_judge_finalize_timeout_seconds=finalize_timeout,
        agent_judge_orchestration_mode=(
            _normalize_aj_orchestration(orchestration_raw)
            if orchestration_raw is not None else None
        ),
    )
    flash('已保存 Agent 评测设置', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/agent_judge/endpoints', methods=['POST'])
def ranking_save_agent_endpoints(competition_id):
    """保存某比赛的 Agent 评测端点池（多个 模型 url + api_key，各带并发上限）+ 整体超时。

    JSON：{timeout_seconds?, orchestration_mode?, endpoints:[{id?, harness, base_url, api_key, model, concurrency_limit, status|enabled}]}。
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
    if timeout_raw is not None and str(timeout_raw).strip() != '':
        try:
            update_competition(competition_id,
                               agent_judge_timeout_seconds=int(_clamp(int(timeout_raw), 60, 7200)))
        except (TypeError, ValueError):
            pass
    if finalize_timeout_raw is not None and str(finalize_timeout_raw).strip() != '':
        try:
            update_competition(
                competition_id,
                reverse_judge_finalize_timeout_seconds=int(_clamp(
                    int(finalize_timeout_raw),
                    REVERSE_FINALIZE_TIMEOUT_RANGE[0],
                    REVERSE_FINALIZE_TIMEOUT_RANGE[1],
                )),
            )
        except (TypeError, ValueError):
            pass
    if orchestration_raw is not None:
        update_competition(
            competition_id,
            agent_judge_orchestration_mode=_normalize_aj_orchestration(orchestration_raw),
        )
    try:
        save_agent_judge_endpoints(
            competition_id, endpoints if isinstance(endpoints, list) else [])
    except ValueError as e:
        return jsonify(success=False, message=str(e)), 400
    # 重新读取（拿到新 id），回传脱敏列表（api_key 只给 has_key 标记）
    saved = list_agent_judge_endpoints(competition_id)
    masked = [{'id': e['id'], 'harness': e.get('harness') or 'claude_code',
               'base_url': e['base_url'], 'model': e['model'],
               'concurrency_limit': e['concurrency_limit'], 'status': e.get('status') or 'enabled',
               'enabled': e['enabled'],
               'has_key': bool(e['api_key'])} for e in saved]
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


# ---------- Agent 评测：实时进展 SSE + 管理员重测 ----------

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

    def _encode(name, payload):
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

    def _encode(name, payload):
        return f"event: {name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

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
                if _t.time() - start > 3600:
                    yield _encode('timeout', s or snap)
                    return
                _t.sleep(2)
        try:
            while True:
                msg = pubsub.get_message(timeout=15.0)
                if _t.time() - start > 3600:
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
    clear_judge_results(submission_id)
    attempt_id = begin_agent_judge_attempt(submission_id, status='Queued', reset_result=True)
    if _agent_judge_task is not None:
        try:
            async_result = _agent_judge_task.apply_async(args=[submission_id, attempt_id])
            set_agent_judge_task_id(submission_id, attempt_id, async_result.id)
        except Exception as e:
            if _wants_json_response():
                return jsonify(success=False, message=f'重测入队失败：{e}'), 500
            flash(f'重测入队失败：{e}', 'warning')
    flash('已触发重新评测', 'success')
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
    rows_html = render_template('_ranking_appeal_rows.html', all_appeals=rows, competition=comp)
    pagination_html = render_template(
        '_ranking_submission_pagination.html',
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
        'ranking_appeal_review.html',
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
    flash('动态评分已启动，匹配引擎将在下一次 tick 拉起对战。', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/elo/stop', methods=['POST'])
def ranking_elo_stop(competition_id):
    comp, resp = _require_elo_competition(competition_id)
    if resp is not None:
        return resp
    set_elo_running(competition_id, False)
    flash('动态评分已停止，分数保留；正在排队的对战会被丢弃。', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/elo/reset', methods=['POST'])
def ranking_elo_reset(competition_id):
    comp, resp = _require_elo_competition(competition_id)
    if resp is not None:
        return resp
    matches_deleted, submissions_reset = reset_elo_state(competition_id)
    flash(
        f'动态评分已重置：清空 {matches_deleted} 场对战历史，'
        f'{submissions_reset} 份在池提交分数恢复到初始分。'
        ' 当前为停止状态，需手动启动。',
        'success',
    )
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


@ranking_bp.route('/<int:competition_id>/delete', methods=['POST'])
def ranking_delete(competition_id):
    user, resp = _require_admin()
    if resp is not None:
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    delete_competition(competition_id)
    # 清理磁盘文件
    comp_dir = competition_dir(competition_id)
    shutil.rmtree(comp_dir, ignore_errors=True)
    flash('已删除比赛', 'success')
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
    flash('已上传附件', 'success')
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
    flash('已删除附件', 'success')
    if _wants_json_response():
        return jsonify(success=True, message='已删除附件', competition_id=competition_id, file_id=file_id)
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


# 可在浏览器里直接预览（图片/视频）的扩展名 -> 显式 MIME。仅白名单类型允许 inline 展示，且强制
# nosniff，避免上传的任意文件被浏览器当 HTML/SVG 在本站点 origin 下执行（存储型 XSS）。
# SVG 故意不在其列（可内嵌 <script>，直接打开 URL 会执行）。
_INLINE_MEDIA_MIME = {
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.gif': 'image/gif', '.webp': 'image/webp', '.bmp': 'image/bmp',
    '.mp4': 'video/mp4', '.webm': 'video/webm', '.ogv': 'video/ogg',
    '.ogg': 'video/ogg', '.mov': 'video/quicktime', '.m4v': 'video/x-m4v',
}
_IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'}


def _attachment_media_kind(filename):
    """按扩展名判断附件能否在浏览器里直接预览：返回 'image' / 'video' / None。"""
    ext = os.path.splitext((filename or '').lower())[1]
    if ext in _IMAGE_EXTS:
        return 'image'
    if ext in _INLINE_MEDIA_MIME:   # 余下白名单均为视频
        return 'video'
    return None


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
    flash('已更新标准答案', 'success')
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
    flash('已更新评测脚本', 'success')
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
    else:
        flash('已清除评测脚本', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


# ---------- 提交文件下载 ----------

def _can_access_submission(user, submission):
    if not submission:
        return False
    if user.get('is_admin') == 1:
        return True
    return submission.get('username') == user.get('username')


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
    flash(f'已删除提交 #{submission_id}（用户 {username}）；该用户最高分与排行榜已随之更新。', 'success')
    for warning in cleanup_warnings[:3]:
        flash(warning, 'warning')
    if _wants_json_response():
        return jsonify(
            success=True,
            message='已删除提交',
            competition_id=competition_id,
            submission_id=submission_id,
            username=username,
            warnings=cleanup_warnings,
        )
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='all_submissions'))
