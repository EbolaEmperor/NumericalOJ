#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, request

from oj_modules.api.helpers import apply_limit, clamp_limit, clamp_page, json_error, json_success, public_user
from oj_modules.auth_helpers import current_user
from oj_modules.ranking_agent_judge import (
    normalize_orchestration_mode as _normalize_aj_orchestration,
    render_snapshot_html as _render_snapshot_html,
)
from oj_modules.ranking_agent_judge_db import (
    build_judge_snapshot,
    list_agent_judge_endpoints,
    list_competition_rules,
    list_quality_gate_endpoints,
)
from oj_modules.ranking_db import (
    get_appeal,
    get_appeal_stats,
    get_competition,
    get_leaderboard,
    get_ranking_submission,
    get_submission_quota,
    get_submission_stats,
    list_all_submissions,
    list_appeals,
    list_competition_files,
    list_competitions,
    list_user_submissions,
)
from oj_modules.routes.ranking_routes import (
    ALLOWED_TABS,
    BATCH_DEFAULT_TEMPLATE,
    BATCH_USERNAME_RE,
    MATCHES_PER_PAGE,
    SUBMISSIONS_PER_PAGE,
    _agent_judge_endpoint_ready,
    _attachment_media_kind,
    _competition_scoring_mode,
    _masked_agent_endpoints,
    _normalize_answer_format,
    _page_window,
    _ranking_submit_block_reason,
    _render_description,
    _reverse_quality_gate_ready,
    _submission_quota_message,
    build_repo_url,
    fetch_competition_matches_cached,
)


ranking_api_bp = Blueprint("ranking_api", __name__, url_prefix="/api/ranking")


def _require_user():
    user = current_user()
    if not user:
        return None, json_error("请先登录", 401)
    return user, None


def _competition_for_user(user, competition_id):
    comp = get_competition(competition_id)
    if not comp:
        return None, json_error("比赛不存在或已被删除", 404)
    if user.get("is_admin") != 1 and comp.get("is_active") != 1:
        return None, json_error("该比赛未开放", 403)
    return comp, None


_PUBLIC_COMPETITION_FIELDS = (
    "id",
    "title",
    "summary",
    "description",
    "answer_format",
    "scoring_mode",
    "submit_limit_per_window",
    "submission_method",
    "max_score",
    "is_active",
    "created_by",
    "created_at",
    "updated_at",
)


def _safe_competition(comp, include_admin=False):
    if not comp:
        return None
    out = dict(comp) if include_admin else {
        key: comp.get(key)
        for key in _PUBLIC_COMPETITION_FIELDS
        if key in comp
    }
    out.pop("agent_judge_api_key", None)
    if not include_admin:
        # 防御性过滤：即便未来公共字段扩展，也不向参赛者暴露审核标准。
        out.pop("reverse_quality_gate_prompt", None)
        out.pop("reverse_quality_gate_enabled", None)
    out["answer_format"] = _normalize_answer_format(out.get("answer_format"))
    out["scoring_mode"] = _competition_scoring_mode(out)
    if "agent_judge_orchestration_mode" in out:
        out["agent_judge_orchestration_mode"] = _normalize_aj_orchestration(
            out.get("agent_judge_orchestration_mode")
        )
    if include_admin:
        out["agent_judge_api_key_set"] = bool((comp.get("agent_judge_api_key") or "").strip())
    return out


def _public_answer_endpoints(endpoints):
    """返回反向评测参赛者可选择的主端点，不暴露连接配置。"""
    out = []
    harness_labels = {
        "claude_code": "Claude Code",
        "codex": "Codex",
        "opencode": "OpenCode",
    }
    for endpoint in endpoints or []:
        if endpoint.get("pool_kind") != "primary" or endpoint.get("status") != "enabled":
            continue
        try:
            endpoint_id = int(endpoint.get("id"))
        except (TypeError, ValueError):
            continue
        harness = str(endpoint.get("harness") or "claude_code").strip().lower()
        model = str(endpoint.get("model") or "").strip()
        harness_label = harness_labels.get(harness, harness)
        label = f"{harness_label} ({model or f'节点 #{endpoint_id}'})"
        out.append({
            "id": endpoint_id,
            "harness": harness,
            "model": model,
            "label": label,
        })
    return out


def _files_with_media(files):
    out = []
    for item in files or []:
        row = dict(item)
        row["media_kind"] = _attachment_media_kind(row.get("filename"))
        row["download_url"] = f"/ranking/{row.get('competition_id')}/attachment/{row.get('id')}/download"
        out.append(row)
    return out


def _submission_download_urls(row):
    out = dict(row or {})
    sid = out.get("id")
    if sid:
        out["answer_download_url"] = f"/ranking/submission/{sid}/answer"
        out["code_download_url"] = f"/ranking/submission/{sid}/code"
    return out


def _safe_submission(row, include_admin=False):
    out = _submission_download_urls(row)
    if not include_admin:
        for key in (
            "elo_rating",
            "elo_match_count",
            "elo_in_pool",
            "judge_log",
            "traceback",
        ):
            out.pop(key, None)
    return out


@ranking_api_bp.route("/competitions", methods=["GET"])
def competitions():
    user, error = _require_user()
    if error is not None:
        return error
    is_admin = user.get("is_admin") == 1
    limit = clamp_limit(request.args.get("limit"), default=None)
    rows = list_competitions(include_inactive=is_admin)
    rows = [_safe_competition(row, include_admin=is_admin) for row in rows]
    visible = apply_limit(rows, limit)
    for row in visible:
        row["url"] = f"/ranking/{row.get('id')}/"
    return json_success(
        user=public_user(user),
        competitions=visible,
        count=len(visible),
        total=len(rows),
    )


@ranking_api_bp.route("/competitions/<int:competition_id>", methods=["GET"])
def competition_detail(competition_id):
    user, error = _require_user()
    if error is not None:
        return error
    comp, error = _competition_for_user(user, competition_id)
    if error is not None:
        return error

    is_admin = user.get("is_admin") == 1
    tab = (request.args.get("tab") or "description").strip().lower()
    if tab not in ALLOWED_TABS:
        return json_error("未知标签", 400)
    if tab in ("all_submissions", "appeals", "edit", "batch_eval") and not is_admin:
        return json_error("无权限", 403)
    if tab == "appeals" and _competition_scoring_mode(comp) != "agent_judge":
        return json_error("该比赛不支持申诉标签", 400)
    scoring_mode = _competition_scoring_mode(comp)
    is_agent_judge = scoring_mode == "agent_judge"
    is_reverse_judge = scoring_mode == "reverse_judge"
    is_ai_judge = is_agent_judge or is_reverse_judge
    if tab == "batch_eval" and not is_ai_judge:
        return json_error("该比赛不支持批量评测标签", 400)

    files = _files_with_media(list_competition_files(competition_id))
    judge_rules = list_competition_rules(competition_id) if (is_agent_judge and is_admin) else []
    aj_endpoints = []
    answer_endpoints = []
    quality_gate_endpoints = []
    quality_gate_ready = _reverse_quality_gate_ready(competition_id, comp) if is_reverse_judge else True
    agent_judge_ready = False
    if is_ai_judge:
        agent_judge_ready = _agent_judge_endpoint_ready(competition_id, comp)
        if is_agent_judge:
            agent_judge_ready = agent_judge_ready and bool(judge_rules)
        elif is_reverse_judge:
            agent_judge_ready = agent_judge_ready and quality_gate_ready
            try:
                answer_endpoints = _public_answer_endpoints(
                    list_agent_judge_endpoints(competition_id, enabled_only=True)
                )
            except Exception:
                answer_endpoints = []
        if is_admin:
            try:
                raw_eps = list_agent_judge_endpoints(competition_id)
            except Exception:
                raw_eps = []
            aj_endpoints = _masked_agent_endpoints(raw_eps)
            if is_reverse_judge:
                try:
                    quality_gate_endpoints = _masked_agent_endpoints(
                        list_quality_gate_endpoints(competition_id)
                    )
                except Exception:
                    quality_gate_endpoints = []
        else:
            if is_agent_judge:
                agent_judge_ready = (
                    _agent_judge_endpoint_ready(competition_id, comp)
                    and bool(list_competition_rules(competition_id))
                )

    payload = {
        "user": public_user(user),
        "is_admin": is_admin,
        "competition": _safe_competition(comp, include_admin=is_admin),
        "files": files,
        "tab": tab,
        "rendered_description": _render_description(comp.get("description") or "") if tab == "description" else "",
        "submission_method": (comp.get("submission_method") or "zip").strip().lower(),
    }
    if is_reverse_judge:
        payload["answer_endpoints"] = answer_endpoints
    if is_admin:
        payload.update({
            "agent_judge_ready": agent_judge_ready,
            "quality_gate_ready": quality_gate_ready,
            "quality_gate_endpoints": quality_gate_endpoints,
            "judge_rules": judge_rules,
            "aj_endpoints": aj_endpoints,
            "batch_default_template": BATCH_DEFAULT_TEMPLATE,
        })
    else:
        payload["judge_ready"] = agent_judge_ready

    if tab == "submit":
        submissions = [
            _safe_submission(row, include_admin=is_admin)
            for row in list_user_submissions(competition_id, user.get("username"))
        ]
        submit_block_reason = _ranking_submit_block_reason(comp, competition_id, user=user)
        submit_quota = None if is_admin else get_submission_quota(competition_id, user.get("username"), comp=comp)
        if not submit_block_reason and submit_quota is not None and submit_quota["remaining"] <= 0:
            submit_block_reason = _submission_quota_message(submit_quota)
        payload["user_submissions"] = submissions
        payload["submit_quota"] = submit_quota
        payload["can_submit"] = not bool(submit_block_reason)
        payload["submit_block_reason"] = submit_block_reason or ""
        if is_ai_judge and (payload["submission_method"] == "git" or is_reverse_judge):
            uname = (user.get("username") or "").strip()
            tmpl = (comp.get("git_format") or "").strip()
            payload["git_repo_url"] = build_repo_url(tmpl, uname) if tmpl and BATCH_USERNAME_RE.match(uname) else None
    elif tab == "leaderboard":
        payload["leaderboard"] = get_leaderboard(competition_id)
    elif tab == "matches":
        requested_page = clamp_page(request.args.get("page", 1))
        matches_mine = str(request.args.get("mine") or "").strip() in ("1", "true", "on", "yes")
        username_filter = user.get("username") if matches_mine else None
        matches, current_page, matches_total = fetch_competition_matches_cached(
            competition_id, requested_page, MATCHES_PER_PAGE, username=username_filter,
        )
        total_pages = max(1, (matches_total + MATCHES_PER_PAGE - 1) // MATCHES_PER_PAGE)
        payload.update({
            "matches": matches,
            "matches_total": matches_total,
            "matches_mine": matches_mine,
            "current_page": current_page,
            "total_pages": total_pages,
            "page_numbers": _page_window(current_page, total_pages),
            "matches_per_page": MATCHES_PER_PAGE,
        })
    elif tab == "all_submissions":
        q = (request.args.get("q") or "").strip()[:50]
        requested_page = clamp_page(request.args.get("page", 1))
        rows, current_page, total = list_all_submissions(
            competition_id,
            page=requested_page,
            per_page=SUBMISSIONS_PER_PAGE,
            username_q=q or None,
        )
        total_pages = max(1, (total + SUBMISSIONS_PER_PAGE - 1) // SUBMISSIONS_PER_PAGE)
        payload.update({
            "all_submissions": [_submission_download_urls(row) for row in rows],
            "submission_stats": get_submission_stats(competition_id),
            "submission_search_q": q,
            "current_page": current_page,
            "total": total,
            "total_pages": total_pages,
            "page_numbers": _page_window(current_page, total_pages),
            "submissions_per_page": SUBMISSIONS_PER_PAGE,
        })
    elif tab == "appeals":
        q = (request.args.get("q") or "").strip()[:50]
        status_q = (request.args.get("status") or "").strip().lower() or None
        requested_page = clamp_page(request.args.get("page", 1))
        rows, current_page, total = list_appeals(
            competition_id,
            page=requested_page,
            per_page=SUBMISSIONS_PER_PAGE,
            status_q=status_q,
            username_q=q or None,
        )
        total_pages = max(1, (total + SUBMISSIONS_PER_PAGE - 1) // SUBMISSIONS_PER_PAGE)
        payload.update({
            "all_appeals": rows,
            "appeal_stats": get_appeal_stats(competition_id),
            "submission_search_q": q,
            "status": status_q,
            "current_page": current_page,
            "total": total,
            "total_pages": total_pages,
            "page_numbers": _page_window(current_page, total_pages),
        })

    return json_success(**payload)


@ranking_api_bp.route("/competitions/<int:competition_id>/my-submissions", methods=["GET"])
def my_submissions(competition_id):
    user, error = _require_user()
    if error is not None:
        return error
    comp, error = _competition_for_user(user, competition_id)
    if error is not None:
        return error
    limit = clamp_limit(request.args.get("limit"), default=None)
    rows = [_submission_download_urls(row) for row in list_user_submissions(competition_id, user.get("username"))]
    visible = apply_limit(rows, limit)
    return json_success(
        competition=_safe_competition(comp, include_admin=user.get("is_admin") == 1),
        competition_id=competition_id,
        submissions=[_safe_submission(row, include_admin=user.get("is_admin") == 1) for row in visible],
        count=len(visible),
        total=len(rows),
    )


@ranking_api_bp.route("/competitions/<int:competition_id>/leaderboard", methods=["GET"])
def leaderboard(competition_id):
    user, error = _require_user()
    if error is not None:
        return error
    comp, error = _competition_for_user(user, competition_id)
    if error is not None:
        return error
    limit = clamp_limit(request.args.get("limit"), default=None)
    rows = get_leaderboard(competition_id)
    visible = apply_limit(rows, limit)
    return json_success(
        competition=_safe_competition(comp, include_admin=user.get("is_admin") == 1),
        competition_id=competition_id,
        leaderboard=visible,
        count=len(visible),
        total=len(rows),
    )


@ranking_api_bp.route("/competitions/<int:competition_id>/matches", methods=["GET"])
def matches(competition_id):
    user, error = _require_user()
    if error is not None:
        return error
    comp, error = _competition_for_user(user, competition_id)
    if error is not None:
        return error
    page = clamp_page(request.args.get("page", 1))
    mine = str(request.args.get("mine") or "").strip() in ("1", "true", "on", "yes")
    rows, current_page, total = fetch_competition_matches_cached(
        competition_id,
        page,
        MATCHES_PER_PAGE,
        username=user.get("username") if mine else None,
    )
    total_pages = max(1, (total + MATCHES_PER_PAGE - 1) // MATCHES_PER_PAGE)
    return json_success(
        competition=_safe_competition(comp, include_admin=user.get("is_admin") == 1),
        competition_id=competition_id,
        matches=rows,
        total=total,
        page=current_page,
        total_pages=total_pages,
        page_numbers=_page_window(current_page, total_pages),
        mine=mine,
    )


@ranking_api_bp.route("/competitions/<int:competition_id>/submissions", methods=["GET"])
def all_submissions(competition_id):
    user, error = _require_user()
    if error is not None:
        return error
    if user.get("is_admin") != 1:
        return json_error("无权限", 403)
    comp, error = _competition_for_user(user, competition_id)
    if error is not None:
        return error
    page = clamp_page(request.args.get("page", 1))
    q = (request.args.get("q") or request.args.get("username") or "").strip()[:50]
    rows, current_page, total = list_all_submissions(
        competition_id,
        page=page,
        per_page=SUBMISSIONS_PER_PAGE,
        username_q=q or None,
    )
    total_pages = max(1, (total + SUBMISSIONS_PER_PAGE - 1) // SUBMISSIONS_PER_PAGE)
    return json_success(
        competition=_safe_competition(comp, include_admin=True),
        competition_id=competition_id,
        submissions=[_submission_download_urls(row) for row in rows],
        count=len(rows),
        total=total,
        page=current_page,
        total_pages=total_pages,
        page_numbers=_page_window(current_page, total_pages),
        username=q,
        submission_stats=get_submission_stats(competition_id),
    )


@ranking_api_bp.route("/competitions/<int:competition_id>/appeals", methods=["GET"])
def appeals(competition_id):
    user, error = _require_user()
    if error is not None:
        return error
    if user.get("is_admin") != 1:
        return json_error("无权限", 403)
    comp, error = _competition_for_user(user, competition_id)
    if error is not None:
        return error
    page = clamp_page(request.args.get("page", 1))
    q = (request.args.get("q") or "").strip()[:50]
    status_q = (request.args.get("status") or "").strip().lower() or None
    rows, current_page, total = list_appeals(
        competition_id,
        page=page,
        per_page=SUBMISSIONS_PER_PAGE,
        status_q=status_q,
        username_q=q or None,
    )
    total_pages = max(1, (total + SUBMISSIONS_PER_PAGE - 1) // SUBMISSIONS_PER_PAGE)
    return json_success(
        competition=_safe_competition(comp, include_admin=True),
        competition_id=competition_id,
        appeals=rows,
        count=len(rows),
        total=total,
        page=current_page,
        total_pages=total_pages,
        page_numbers=_page_window(current_page, total_pages),
        appeal_stats=get_appeal_stats(competition_id),
    )


@ranking_api_bp.route("/competitions/<int:competition_id>/appeals/<int:appeal_id>/review", methods=["GET"])
def appeal_review(competition_id, appeal_id):
    user, error = _require_user()
    if error is not None:
        return error
    if user.get("is_admin") != 1:
        return json_error("无权限", 403)
    comp, error = _competition_for_user(user, competition_id)
    if error is not None:
        return error
    appeal = get_appeal(appeal_id)
    if not appeal or int(appeal.get("competition_id") or 0) != int(competition_id):
        return json_error("申诉记录不存在", 404)
    submission = get_ranking_submission(appeal.get("submission_id"))
    snapshot = build_judge_snapshot(appeal.get("submission_id")) or {}
    rendered_snapshot = _render_snapshot_html(snapshot) if snapshot else {}
    return json_success(
        competition=_safe_competition(comp, include_admin=True),
        appeal=appeal,
        submission=_submission_download_urls(submission),
        snapshot=snapshot,
        rendered_snapshot=rendered_snapshot,
    )
