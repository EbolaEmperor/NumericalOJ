#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打榜赛（Ranking Competition）路由。
"""

import json
import os
import shutil

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

from config import REDIS_DB, REDIS_HOST, REDIS_PORT
from oj_modules.db_services import get_user_by_username
from oj_modules.ranking_db import (
    competition_attachments_dir,
    competition_dir,
    competition_reference_dir,
    competition_scoring_dir,
    create_competition,
    create_competition_file,
    create_ranking_submission,
    delete_competition,
    delete_competition_file,
    delete_elo_match_and_revert,
    delete_ranking_submission,
    get_competition,
    get_competition_file,
    get_competition_match,
    get_leaderboard,
    get_ranking_submission,
    get_submission_stats,
    init_submission_elo_state,
    list_all_submissions,
    list_competition_files,
    list_competition_matches,
    list_competitions,
    list_elo_matches_for_submission,
    list_user_submissions,
    rebuild_elo_history,
    reset_elo_state,
    retire_excess_user_submissions,
    set_elo_running,
    submission_dir,
    update_competition,
    update_competition_reference_answer,
    update_competition_scoring_script,
    update_submission_files,
    update_submission_result,
)
from oj_modules.ranking_agent_judge_db import (
    build_judge_snapshot,
    clear_judge_results,
    list_competition_rules,
    replace_competition_rules,
)
from oj_modules.ranking_agent_judge import max_score as _aj_max_score
from oj_modules.tasks import get_judge_progress_snapshot, subscribe_judge_run_events


ranking_bp = Blueprint('ranking', __name__, url_prefix='/ranking')

ALLOWED_TABS = ('description', 'submit', 'leaderboard', 'matches', 'all_submissions', 'edit', 'judge')
SUBMISSIONS_PER_PAGE = 50
MATCHES_PER_PAGE = 20

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
ALLOWED_SCORING_MODES = ('absolute', 'elo', 'agent_judge')

# ELO 参数取值范围
ELO_INITIAL_RATING_RANGE = (100.0, 5000.0)
ELO_K_FACTOR_RANGE = (1.0, 200.0)
ELO_MAX_MATCHES_RANGE = (1, 10000)
ELO_MATCH_INTERVAL_RANGE = (5, 3600)
ELO_INITIAL_BURST_RANGE = (0, 50)
ELO_MAX_PAIRS_PER_ROUND_RANGE = (1, 8)   # 与 ranking_elo_tasks.MAX_PAIRS_PER_ROUND 保持一致
SCORING_SCRIPT_TIMEOUT_RANGE = (5, 600)


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


def _serialize_for_cache(obj):
    """datetime → str；其余按默认 json 处理。"""
    return json.dumps(obj, default=str, ensure_ascii=False)


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


def init_ranking_module(evaluate_ranking_task, elo_initial_burst_task=None, agent_judge_task=None):
    global _evaluate_ranking_task, _elo_initial_burst_task, _agent_judge_task
    _evaluate_ranking_task = evaluate_ranking_task
    _elo_initial_burst_task = elo_initial_burst_task
    _agent_judge_task = agent_judge_task


def _current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def _require_user():
    user = _current_user()
    if not user:
        return None, redirect(url_for('auth.login'))
    return user, None


def _require_admin():
    user, resp = _require_user()
    if resp is not None:
        return None, resp
    if (user or {}).get('is_admin') != 1:
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
    return markdown.markdown(
        text,
        extensions=['extra', 'md_in_html', 'fenced_code', 'tables'],
    )


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
    if tab in ('all_submissions', 'edit') and not is_admin:
        tab = 'description'

    files = list_competition_files(competition_id)
    # markdown 解析仅在「比赛说明」标签下做；其它标签传空串避免每次切换都要解析一遍。
    rendered_description = (
        _render_description(comp.get('description') or '') if tab == 'description' else ''
    )

    user_submissions = []
    all_submissions = []
    leaderboard = []
    submission_stats = None
    current_page = 1
    total_pages = 1
    page_numbers = []
    submission_search_q = ''
    matches = []
    matches_total = 0
    matches_mine = False

    is_agent_judge = _competition_scoring_mode(comp) == 'agent_judge'
    judge_rules = list_competition_rules(competition_id) if is_agent_judge else []
    agent_judge_api_key_set = bool((comp.get('agent_judge_api_key') or '').strip())
    judge_snapshot = None

    if tab == 'submit':
        user_submissions = list_user_submissions(competition_id, user.get('username'))
    elif tab == 'judge' and is_agent_judge:
        # 展示当前用户最近一次提交的评分细则（含实时进展）
        my_subs = list_user_submissions(competition_id, user.get('username'))
        if my_subs:
            judge_snapshot = build_judge_snapshot(my_subs[0]['id'])
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

    return render_template(
        'ranking_detail.html',
        user=user,
        is_admin=is_admin,
        competition=comp,
        files=files,
        tab=tab,
        rendered_description=rendered_description,
        user_submissions=user_submissions,
        all_submissions=all_submissions,
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
        judge_snapshot=judge_snapshot,
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

    rows_html = render_template(
        '_ranking_submission_rows.html',
        all_submissions=rows,
        competition=comp,
        is_elo=is_elo,
        max_score=max_score,
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
        return resp
    comp = get_competition(competition_id)
    if not comp:
        flash('比赛不存在或已被删除', 'warning')
        return redirect(url_for('ranking.ranking_list'))
    is_admin = user.get('is_admin') == 1
    if not is_admin and comp.get('is_active') != 1:
        flash('该比赛未开放', 'warning')
        return redirect(url_for('ranking.ranking_list'))

    answer_format = _competition_answer_format(comp)
    answer_ext = '.' + answer_format
    scoring_mode = _competition_scoring_mode(comp)
    has_script = bool((comp.get('scoring_script_path') or '').strip())

    base_model_raw = (request.form.get('base_model') or '').strip()
    if not base_model_raw:
        flash('请填写基座模型（多个用逗号分隔，例如：deepseek-v4-pro, qwen3.6-plus）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
    if len(base_model_raw) > 500:
        flash('基座模型字段过长（不超过 500 字）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
    base_model = base_model_raw

    # Agent 评测模式：只需上传代码 zip（不需要 answer 文件），但要求已配置模型与规则
    if scoring_mode == 'agent_judge':
        if not all([(comp.get('agent_judge_base_url') or '').strip(),
                    (comp.get('agent_judge_api_key') or '').strip(),
                    (comp.get('agent_judge_model') or '').strip()]):
            flash('该比赛为 Agent 评测模式，但管理员尚未完成模型配置，暂时无法提交。', 'warning')
            return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
        if not list_competition_rules(competition_id):
            flash('该比赛尚未设置评分规则，暂时无法提交。', 'warning')
            return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
        code_file = request.files.get('code_file')
        if not code_file or not (code_file.filename or '').strip():
            flash('请上传代码文件（.zip）', 'danger')
            return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
        if not (code_file.filename or '').lower().endswith('.zip'):
            flash('代码文件必须是 .zip', 'danger')
            return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
        submission_id = create_ranking_submission(competition_id, user.get('username'))
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
            flash(f'文件保存失败：{e}', 'danger')
            return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
        update_submission_files(submission_id, None, None, code_name, code_path, base_model=base_model)
        if _agent_judge_task is None:
            flash('已接收提交，但评测任务未初始化，请联系管理员', 'warning')
        else:
            try:
                _agent_judge_task.delay(submission_id)
            except Exception as e:
                flash(f'已接收提交，但评测任务入队失败：{e}', 'warning')
        flash('提交成功，Agent 评测进行中，可在"评分细则"查看实时进展。', 'success')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='judge'))

    # ZIP 模式必须配套自定义评测脚本（默认 JSON 评分器无法处理 zip）
    if scoring_mode == 'absolute' and answer_format == 'zip' and not has_script:
        flash('该比赛答案格式为 ZIP 但管理员尚未上传评测脚本，暂时无法提交。', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    # ELO 模式必须配套评测脚本（用于两两比较）
    if scoring_mode == 'elo' and not has_script:
        flash('该比赛为 ELO 评分模式，但管理员尚未上传评测脚本，暂时无法接收提交。', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    answer_file = request.files.get('answer_file')
    code_file = request.files.get('code_file')
    if not answer_file or not (answer_file.filename or '').strip():
        flash(f'请上传答案文件（{answer_ext}）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
    if not code_file or not (code_file.filename or '').strip():
        flash('请上传代码文件（.zip）', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    answer_name_raw = answer_file.filename
    code_name_raw = code_file.filename
    if not answer_name_raw.lower().endswith(answer_ext):
        flash(f'答案文件必须是 {answer_ext}', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))
    if not code_name_raw.lower().endswith('.zip'):
        flash('代码文件必须是 .zip', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    submission_id = create_ranking_submission(competition_id, user.get('username'))
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
        flash(f'文件保存失败：{e}', 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

    try:
        if os.path.getsize(answer_path) > ANSWER_MAX_BYTES:
            raise ValueError(f'答案文件超过 {ANSWER_MAX_BYTES // (1024*1024)}MB 限制')
        if os.path.getsize(code_path) > CODE_ZIP_MAX_BYTES:
            raise ValueError(f'代码文件超过 {CODE_ZIP_MAX_BYTES // (1024*1024)}MB 限制')
    except Exception as e:
        shutil.rmtree(target_dir, ignore_errors=True)
        flash(str(e), 'danger')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))

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
                _evaluate_ranking_task.delay(submission_id)
            except Exception as e:
                flash(f'已接收提交，但评测任务入队失败：{e}', 'warning')
        flash('提交成功，正在评测中', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='submit'))


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
    aj_api_key_raw = request.form.get('agent_judge_api_key')
    aj_api_key = None
    if aj_api_key_raw is not None and str(aj_api_key_raw).strip() != '':
        aj_api_key = str(aj_api_key_raw).strip()
    aj_timeout = None
    if aj_timeout_raw is not None and str(aj_timeout_raw).strip() != '':
        try:
            aj_timeout = int(_clamp(int(aj_timeout_raw), 60, 7200))
        except (TypeError, ValueError):
            aj_timeout = None

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
        flash(
            f'评分模式已切换为 {"ELO 对战" if new_mode == "elo" else "绝对分"}。'
            '请注意切换前后的提交记录可能因评分语义不同导致排行榜混合显示。',
            'warning',
        )
    if not format_changed and not mode_changed:
        flash('已保存比赛信息', 'success')
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
    # 归一：rule_id 按顺序 1..n，dependencies 为前端给出的 rule_id 列表
    rules = []
    for idx, r in enumerate(rules_in):
        rules.append({
            'rule_id': int(r.get('rule_id') or (idx + 1)),
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


# ---------- Agent 评测：实时进展 SSE + 管理员重测 ----------

@ranking_bp.route('/<int:competition_id>/judge_stream/<int:submission_id>')
def ranking_judge_stream(competition_id, submission_id):
    user, resp = _require_user()
    if resp is not None:
        return resp
    sub = get_ranking_submission(submission_id)
    if not sub or int(sub.get('competition_id')) != competition_id:
        return Response('not found', status=404)

    def _encode(name, payload):
        return f"event: {name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

    @stream_with_context
    def generate():
        import time as _t
        snap = get_judge_progress_snapshot(submission_id) or build_judge_snapshot(submission_id)
        if snap is None:
            yield _encode('error', {'error': 'not found'})
            return
        yield _encode('progress', snap)
        if snap.get('status') not in ('Judging', 'Pending'):
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
                if s and s.get('status') not in ('Judging', 'Pending'):
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
                if s.get('status') not in ('Judging', 'Pending'):
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
        flash('提交不存在', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='all_submissions'))
    clear_judge_results(submission_id)
    update_submission_result(submission_id, None, 'Judging', grade_details=None, error_message=None)
    if _agent_judge_task is not None:
        try:
            _agent_judge_task.delay(submission_id)
        except Exception as e:
            flash(f'重测入队失败：{e}', 'warning')
    flash('已触发重新评测', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='all_submissions'))


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
    if not (comp.get('scoring_script_path') or '').strip():
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
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='edit'))


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
    return send_file(
        os.path.abspath(stored),
        as_attachment=True,
        download_name=rec.get('filename') or os.path.basename(stored),
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
    fmt = _competition_answer_format(comp)
    if fmt == 'zip':
        flash('已清除评测脚本。当前答案格式为 ZIP，缺少脚本将导致用户无法提交，请尽快重新上传。', 'warning')
    else:
        flash('已清除评测脚本（将使用默认 JSON 对比打分）', 'success')
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
        flash('提交记录不存在', 'warning')
        return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='all_submissions'))

    username = sub.get('username') or ''
    # 清理磁盘上的答案 + 代码文件
    target_dir = submission_dir(submission_id)
    if os.path.isdir(target_dir):
        shutil.rmtree(target_dir, ignore_errors=True)
    # 删除数据库行
    delete_ranking_submission(submission_id)
    flash(f'已删除提交 #{submission_id}（用户 {username}）；该用户最高分与排行榜已随之更新。', 'success')
    return redirect(url_for('ranking.ranking_detail', competition_id=competition_id, tab='all_submissions'))
