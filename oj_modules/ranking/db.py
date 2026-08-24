#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打榜赛（Ranking Competition）相关的数据库访问层。

表：
  - ranking_competitions       比赛元数据
  - ranking_competition_files  比赛附件
  - ranking_submissions        用户提交记录
"""

import os
import json
import hashlib
import logging
import shutil
import uuid
from datetime import datetime, timedelta

from oj_modules.db_services import bump_daily_submission_count
from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.observability import emit_audit, safe_file_fingerprint
from oj_modules.ranking.agent_judge.rules import normalize_orchestration_mode


_ranking_tables_ready = False
logger = logging.getLogger(__name__)

RANKING_UPLOAD_ROOT = 'ranking_uploads'
ATTACHMENT_SUBDIR = 'attachments'
REFERENCE_SUBDIR = 'reference'
SCORING_SUBDIR = 'scoring'
SUBMISSION_SUBDIR = 'submissions'

# 打榜赛「每窗口提交次数限制」的窗口固定为 48 小时，到点自动刷新；管理员也可手动刷新。
RANK_LIMIT_WINDOW_SECONDS = 48 * 3600


class RankingSubmissionQuotaExceeded(Exception):
    """Raised when a self-submission would exceed the current ranking quota window."""

    def __init__(self, quota):
        self.quota = quota
        super().__init__('ranking submission quota exceeded')


class RankingSubmissionCommitUnknown(RuntimeError):
    """数据库 commit 结果无法确认；文件会保留以避免破坏可能已提交的记录。"""

    def __init__(self, submission_id):
        self.submission_id = int(submission_id)
        super().__init__(
            f'提交 {self.submission_id} 的数据库结果无法确认；文件已保留待核验'
        )


def quota_window_bounds(anchor, now, window_seconds=RANK_LIMIT_WINDOW_SECONDS):
    """纯函数：给定窗口锚点 anchor 与当前时间 now，返回当前固定窗口的
    (window_start, next_reset)。窗口自 anchor 起每 window_seconds 固定推进一格。
    anchor 为空或在未来时，窗口从 anchor/now 起算。无副作用，便于单测。"""
    win = timedelta(seconds=window_seconds)
    if anchor is None:
        return now, now + win
    elapsed = (now - anchor).total_seconds()
    if elapsed < 0:
        start = anchor
    else:
        k = int(elapsed // window_seconds)
        start = anchor + win * k
    return start, start + win


def ensure_ranking_tables():
    global _ranking_tables_ready
    _ranking_tables_ready = True


# ---------- Competitions ----------

def list_competitions(include_inactive=False):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if include_inactive:
                cursor.execute(
                    """
                    SELECT c.id, c.title, c.summary, c.description, c.max_score, c.is_active,
                           c.scoring_mode,
                           c.created_by, c.created_at, c.updated_at,
                           (SELECT COUNT(*) FROM ranking_submissions s WHERE s.competition_id = c.id) AS submission_count,
                           (SELECT COUNT(DISTINCT s.username) FROM ranking_submissions s WHERE s.competition_id = c.id) AS participant_count
                    FROM ranking_competitions c
                    ORDER BY c.created_at DESC
                    """
                )
            else:
                cursor.execute(
                    """
                    SELECT c.id, c.title, c.summary, c.description, c.max_score, c.is_active,
                           c.scoring_mode,
                           c.created_by, c.created_at, c.updated_at,
                           (SELECT COUNT(*) FROM ranking_submissions s WHERE s.competition_id = c.id) AS submission_count,
                           (SELECT COUNT(DISTINCT s.username) FROM ranking_submissions s WHERE s.competition_id = c.id) AS participant_count
                    FROM ranking_competitions c
                    WHERE c.is_active = 1
                    ORDER BY c.created_at DESC
                    """
                )
            return cursor.fetchall() or []
    finally:
        conn.close()


def get_competition(competition_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, summary, description, answer_format,
                       scoring_mode, elo_initial_rating, elo_k_factor,
                       elo_max_matches, elo_match_interval_seconds, elo_initial_burst,
                       elo_max_pairs_per_round, elo_runtime_mode, elo_running,
                       scoring_script_timeout_seconds,
                       agent_judge_timeout_seconds,
                       reverse_judge_finalize_timeout_seconds,
                       reverse_quality_gate_enabled, reverse_quality_gate_prompt,
                       agent_judge_orchestration_mode,
                       submit_limit_per_window, limit_window_start,
                       submission_method, git_format,
                       reference_answer_path, reference_answer_name,
                       scoring_script_path, scoring_script_name, max_score, is_active,
                       created_by, created_at, updated_at
                FROM ranking_competitions
                WHERE id = %s
                """,
                (competition_id,),
            )
            return cursor.fetchone()
    finally:
        conn.close()


_RANKING_NAVIGATION_REVISION_FIELDS = (
    'competition_fingerprint',
    'submission_count',
    'leaderboard_count',
    'submission_fingerprint_sum',
    'submission_fingerprint_xor',
    'match_count',
    'valid_match_count',
    'match_fingerprint_sum',
    'match_fingerprint_xor',
    'appeal_count',
    'pending_appeal_count',
    'appeal_fingerprint_sum',
    'appeal_fingerprint_xor',
    'attachment_count',
    'attachment_fingerprint_sum',
    'attachment_fingerprint_xor',
    'rule_count',
    'rule_fingerprint_sum',
    'rule_fingerprint_xor',
    'endpoint_count',
    'endpoint_fingerprint_sum',
    'endpoint_fingerprint_xor',
)


def _ranking_navigation_revision(row, *, include_quota=False):
    """把单次导航聚合查询的结果变成稳定、不泄漏配置内容的版本指纹。"""
    parts = []
    for field in _RANKING_NAVIGATION_REVISION_FIELDS:
        value = (row or {}).get(field)
        if isinstance(value, datetime):
            value = value.isoformat(timespec='microseconds')
        elif isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        else:
            value = str(value if value is not None else '')
        parts.append(f'{field}={value}')
    if include_quota:
        for field in ('quota_window_start', 'quota_used'):
            value = (row or {}).get(field)
            if isinstance(value, datetime):
                value = value.isoformat(timespec='microseconds')
            else:
                value = str(value if value is not None else '')
            parts.append(f'{field}={value}')
    return hashlib.sha256('\n'.join(parts).encode('utf-8')).hexdigest()


def get_ranking_navigation_state(competition_id, username=None):
    """一次只读查询返回详情页 Function Rail 所需计数及稳定 revision。

    ``ranking_submissions`` 没有 ``updated_at``，因此 revision 不能只依赖最新 id 或
    创建时间。查询同时聚合每条提交的 status / score / ELO 状态指纹；对战、申诉、
    附件、评分规则和端点配置也各自参与指纹。CRC32 的 SUM 与 BIT_XOR 配合行数及
    主键，避免列表顺序影响结果，并把实际碰撞概率降到足够低。
    """
    include_quota = bool(username)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                WITH target AS (
                    SELECT
                        c.*,
                        CASE
                            WHEN c.submit_limit_per_window IS NULL
                              OR c.submit_limit_per_window <= 0
                            THEN NULL
                            ELSE TIMESTAMPADD(
                                SECOND,
                                FLOOR(
                                    GREATEST(
                                        TIMESTAMPDIFF(
                                            SECOND,
                                            COALESCE(c.limit_window_start, c.created_at),
                                            NOW()
                                        ),
                                        0
                                    ) / %s
                                ) * %s,
                                COALESCE(c.limit_window_start, c.created_at)
                            )
                        END AS quota_window_start,
                        SHA2(
                            CONCAT_WS(
                                CHAR(31),
                                CAST(c.id AS CHAR),
                                COALESCE(c.title, ''),
                                COALESCE(c.summary, ''),
                                COALESCE(c.description, ''),
                                COALESCE(c.answer_format, ''),
                                COALESCE(c.scoring_mode, ''),
                                COALESCE(CAST(c.elo_initial_rating AS CHAR), ''),
                                COALESCE(CAST(c.elo_k_factor AS CHAR), ''),
                                COALESCE(CAST(c.elo_max_matches AS CHAR), ''),
                                COALESCE(CAST(c.elo_match_interval_seconds AS CHAR), ''),
                                COALESCE(CAST(c.elo_initial_burst AS CHAR), ''),
                                COALESCE(CAST(c.elo_max_pairs_per_round AS CHAR), ''),
                                COALESCE(CAST(c.elo_running AS CHAR), ''),
                                COALESCE(CAST(c.scoring_script_timeout_seconds AS CHAR), ''),
                                COALESCE(CAST(c.agent_judge_timeout_seconds AS CHAR), ''),
                                COALESCE(CAST(c.reverse_judge_finalize_timeout_seconds AS CHAR), ''),
                                COALESCE(CAST(c.reverse_quality_gate_enabled AS CHAR), ''),
                                COALESCE(c.reverse_quality_gate_prompt, ''),
                                COALESCE(c.agent_judge_orchestration_mode, ''),
                                COALESCE(CAST(c.submit_limit_per_window AS CHAR), ''),
                                COALESCE(DATE_FORMAT(c.limit_window_start, '%%Y-%%m-%%d %%H:%%i:%%s.%%f'), ''),
                                COALESCE(c.submission_method, ''),
                                COALESCE(c.git_format, ''),
                                COALESCE(c.reference_answer_path, ''),
                                COALESCE(c.reference_answer_name, ''),
                                COALESCE(c.scoring_script_path, ''),
                                COALESCE(c.scoring_script_name, ''),
                                COALESCE(CAST(c.max_score AS CHAR), ''),
                                COALESCE(CAST(c.is_active AS CHAR), ''),
                                COALESCE(c.created_by, ''),
                                COALESCE(DATE_FORMAT(c.updated_at, '%%Y-%%m-%%d %%H:%%i:%%s.%%f'), '')
                            ),
                            256
                        ) AS competition_fingerprint
                    FROM ranking_competitions c
                    WHERE c.id = %s
                ),
                submission_rows AS (
                    SELECT
                        s.id,
                        s.username,
                        s.score,
                        s.source,
                        t.scoring_mode,
                        s.status,
                        s.elo_in_pool,
                        s.created_at,
                        t.quota_window_start,
                        CAST(CRC32(CONCAT_WS(
                            CHAR(31),
                            CAST(s.id AS CHAR),
                            COALESCE(s.username, ''),
                            COALESCE(s.status, ''),
                            COALESCE(CAST(s.score AS CHAR), '<null>'),
                            COALESCE(CAST(s.elo_rating AS CHAR), '<null>'),
                            COALESCE(CAST(s.elo_match_count AS CHAR), ''),
                            COALESCE(CAST(s.elo_in_pool AS CHAR), ''),
                            COALESCE(s.judge_attempt_id, ''),
                            COALESCE(s.agent_endpoint_harness, ''),
                            COALESCE(s.agent_endpoint_model, '')
                        )) AS UNSIGNED) AS fingerprint
                    FROM target t
                    JOIN ranking_submissions s ON s.competition_id = t.id
                ),
                submission_state AS (
                    SELECT
                        COUNT(s.id) AS submission_count,
                        COUNT(DISTINCT CASE
                            WHEN s.score IS NOT NULL
                              AND (
                                  COALESCE(s.scoring_mode, 'absolute') <> 'elo'
                                  OR (s.status = 'Active' AND s.elo_in_pool = 1)
                              )
                            THEN s.username
                        END)
                            AS leaderboard_count,
                        COALESCE(SUM(s.fingerprint), 0) AS submission_fingerprint_sum,
                        COALESCE(BIT_XOR(s.fingerprint), 0) AS submission_fingerprint_xor,
                        COALESCE(SUM(
                            CASE
                                WHEN %s IS NOT NULL
                                  AND s.username = %s
                                  AND s.source = 'self'
                                  AND s.created_at >= s.quota_window_start
                                THEN 1
                                ELSE 0
                            END
                        ), 0) AS quota_used
                    FROM submission_rows s
                ),
                match_rows AS (
                    SELECT
                        m.id,
                        m.winner,
                        CAST(CRC32(CONCAT_WS(
                            CHAR(31),
                            CAST(m.id AS CHAR),
                            COALESCE(CAST(m.submission_a_id AS CHAR), ''),
                            COALESCE(CAST(m.submission_b_id AS CHAR), ''),
                            COALESCE(CAST(m.winner AS CHAR), ''),
                            COALESCE(CAST(m.rating_a_before AS CHAR), ''),
                            COALESCE(CAST(m.rating_a_after AS CHAR), ''),
                            COALESCE(CAST(m.rating_b_before AS CHAR), ''),
                            COALESCE(CAST(m.rating_b_after AS CHAR), '')
                        )) AS UNSIGNED) AS fingerprint
                    FROM target t
                    JOIN ranking_elo_matches m ON m.competition_id = t.id
                ),
                match_state AS (
                    SELECT
                        COUNT(m.id) AS match_count,
                        COALESCE(SUM(
                            CASE WHEN m.winner IN (0, 1, 2) THEN 1 ELSE 0 END
                        ), 0) AS valid_match_count,
                        COALESCE(SUM(m.fingerprint), 0) AS match_fingerprint_sum,
                        COALESCE(BIT_XOR(m.fingerprint), 0) AS match_fingerprint_xor
                    FROM match_rows m
                ),
                appeal_rows AS (
                    SELECT
                        a.id,
                        a.status,
                        CAST(CRC32(CONCAT_WS(
                            CHAR(31),
                            CAST(a.id AS CHAR),
                            COALESCE(CAST(a.submission_id AS CHAR), ''),
                            COALESCE(a.username, ''),
                            COALESCE(a.status, ''),
                            COALESCE(a.admin_response, ''),
                            COALESCE(a.admin_username, ''),
                            COALESCE(DATE_FORMAT(a.updated_at, '%%Y-%%m-%%d %%H:%%i:%%s.%%f'), '')
                        )) AS UNSIGNED) AS fingerprint
                    FROM target t
                    JOIN ranking_appeals a ON a.competition_id = t.id
                ),
                appeal_state AS (
                    SELECT
                        COUNT(a.id) AS appeal_count,
                        COALESCE(SUM(CASE WHEN a.status = 'pending' THEN 1 ELSE 0 END), 0)
                            AS pending_appeal_count,
                        COALESCE(SUM(a.fingerprint), 0) AS appeal_fingerprint_sum,
                        COALESCE(BIT_XOR(a.fingerprint), 0) AS appeal_fingerprint_xor
                    FROM appeal_rows a
                ),
                attachment_state AS (
                    SELECT
                        COUNT(f.id) AS attachment_count,
                        COALESCE(SUM(
                            CASE
                                WHEN f.id IS NULL THEN 0
                                ELSE CAST(CRC32(CONCAT_WS(
                                    CHAR(31),
                                    CAST(f.id AS CHAR),
                                    COALESCE(f.filename, ''),
                                    COALESCE(f.stored_path, ''),
                                    COALESCE(CAST(f.file_size AS CHAR), ''),
                                    COALESCE(DATE_FORMAT(f.uploaded_at, '%%Y-%%m-%%d %%H:%%i:%%s.%%f'), '')
                                )) AS UNSIGNED)
                            END
                        ), 0) AS attachment_fingerprint_sum,
                        COALESCE(BIT_XOR(
                            CASE
                                WHEN f.id IS NULL THEN 0
                                ELSE CAST(CRC32(CONCAT_WS(
                                    CHAR(31),
                                    CAST(f.id AS CHAR),
                                    COALESCE(f.filename, ''),
                                    COALESCE(f.stored_path, ''),
                                    COALESCE(CAST(f.file_size AS CHAR), ''),
                                    COALESCE(DATE_FORMAT(f.uploaded_at, '%%Y-%%m-%%d %%H:%%i:%%s.%%f'), '')
                                )) AS UNSIGNED)
                            END
                        ), 0) AS attachment_fingerprint_xor
                    FROM target t
                    LEFT JOIN ranking_competition_files f ON f.competition_id = t.id
                ),
                rule_state AS (
                    SELECT
                        COUNT(r.id) AS rule_count,
                        COALESCE(SUM(
                            CASE
                                WHEN r.id IS NULL THEN 0
                                ELSE CAST(CRC32(CONCAT_WS(
                                    CHAR(31),
                                    CAST(r.id AS CHAR),
                                    COALESCE(CAST(r.rule_id AS CHAR), ''),
                                    COALESCE(r.rule_name, ''),
                                    COALESCE(r.rule_text, ''),
                                    COALESCE(CAST(r.value AS CHAR), ''),
                                    COALESCE(r.dependencies, ''),
                                    COALESCE(CAST(r.ordering AS CHAR), '')
                                )) AS UNSIGNED)
                            END
                        ), 0) AS rule_fingerprint_sum,
                        COALESCE(BIT_XOR(
                            CASE
                                WHEN r.id IS NULL THEN 0
                                ELSE CAST(CRC32(CONCAT_WS(
                                    CHAR(31),
                                    CAST(r.id AS CHAR),
                                    COALESCE(CAST(r.rule_id AS CHAR), ''),
                                    COALESCE(r.rule_name, ''),
                                    COALESCE(r.rule_text, ''),
                                    COALESCE(CAST(r.value AS CHAR), ''),
                                    COALESCE(r.dependencies, ''),
                                    COALESCE(CAST(r.ordering AS CHAR), '')
                                )) AS UNSIGNED)
                            END
                        ), 0) AS rule_fingerprint_xor
                    FROM target t
                    LEFT JOIN ranking_judge_rules r ON r.competition_id = t.id
                ),
                endpoint_state AS (
                    SELECT
                        COUNT(e.id) AS endpoint_count,
                        COALESCE(SUM(
                            CASE
                                WHEN e.id IS NULL THEN 0
                                ELSE CAST(CRC32(CONCAT_WS(
                                    CHAR(31),
                                    CAST(e.id AS CHAR),
                                    COALESCE(e.pool_kind, ''),
                                    COALESCE(e.harness, ''),
                                    COALESCE(e.protocol, ''),
                                    COALESCE(e.base_url, ''),
                                    COALESCE(e.api_key, ''),
                                    COALESCE(e.model, ''),
                                    COALESCE(CAST(e.context_window_tokens AS CHAR), ''),
                                    COALESCE(CAST(e.max_output_tokens AS CHAR), ''),
                                    COALESCE(CAST(e.thinking_compatibility AS CHAR), ''),
                                    COALESCE(e.thinking_format, ''),
                                    COALESCE(CAST(e.concurrency_limit AS CHAR), ''),
                                    COALESCE(CAST(e.enabled AS CHAR), ''),
                                    COALESCE(e.status, ''),
                                    COALESCE(CAST(e.ordering AS CHAR), '')
                                )) AS UNSIGNED)
                            END
                        ), 0) AS endpoint_fingerprint_sum,
                        COALESCE(BIT_XOR(
                            CASE
                                WHEN e.id IS NULL THEN 0
                                ELSE CAST(CRC32(CONCAT_WS(
                                    CHAR(31),
                                    CAST(e.id AS CHAR),
                                    COALESCE(e.pool_kind, ''),
                                    COALESCE(e.harness, ''),
                                    COALESCE(e.protocol, ''),
                                    COALESCE(e.base_url, ''),
                                    COALESCE(e.api_key, ''),
                                    COALESCE(e.model, ''),
                                    COALESCE(CAST(e.context_window_tokens AS CHAR), ''),
                                    COALESCE(CAST(e.max_output_tokens AS CHAR), ''),
                                    COALESCE(CAST(e.thinking_compatibility AS CHAR), ''),
                                    COALESCE(e.thinking_format, ''),
                                    COALESCE(CAST(e.concurrency_limit AS CHAR), ''),
                                    COALESCE(CAST(e.enabled AS CHAR), ''),
                                    COALESCE(e.status, ''),
                                    COALESCE(CAST(e.ordering AS CHAR), '')
                                )) AS UNSIGNED)
                            END
                        ), 0) AS endpoint_fingerprint_xor
                    FROM target t
                    LEFT JOIN ranking_agent_judge_endpoints e ON e.competition_id = t.id
                )
                SELECT
                    t.id AS competition_id,
                    t.scoring_mode,
                    t.is_active,
                    t.submit_limit_per_window,
                    t.quota_window_start,
                    t.competition_fingerprint,
                    s.submission_count,
                    s.leaderboard_count,
                    s.submission_fingerprint_sum,
                    s.submission_fingerprint_xor,
                    s.quota_used,
                    m.match_count,
                    m.valid_match_count,
                    m.match_fingerprint_sum,
                    m.match_fingerprint_xor,
                    a.appeal_count,
                    a.pending_appeal_count,
                    a.appeal_fingerprint_sum,
                    a.appeal_fingerprint_xor,
                    f.attachment_count,
                    f.attachment_fingerprint_sum,
                    f.attachment_fingerprint_xor,
                    r.rule_count,
                    r.rule_fingerprint_sum,
                    r.rule_fingerprint_xor,
                    e.endpoint_count,
                    e.endpoint_fingerprint_sum,
                    e.endpoint_fingerprint_xor
                FROM target t
                CROSS JOIN submission_state s
                CROSS JOIN match_state m
                CROSS JOIN appeal_state a
                CROSS JOIN attachment_state f
                CROSS JOIN rule_state r
                CROSS JOIN endpoint_state e
                """,
                (
                    RANK_LIMIT_WINDOW_SECONDS,
                    RANK_LIMIT_WINDOW_SECONDS,
                    int(competition_id),
                    username,
                    username,
                ),
            )
            row = cursor.fetchone()
    finally:
        conn.close()

    if not row:
        return None

    limit_raw = row.get('submit_limit_per_window')
    try:
        quota_limit = int(limit_raw or 0)
    except (TypeError, ValueError):
        quota_limit = 0
    quota = None
    if include_quota and quota_limit > 0:
        quota_used = int(row.get('quota_used') or 0)
        quota = {
            'limit': quota_limit,
            'remaining': max(0, quota_limit - quota_used),
        }

    return {
        'competition_id': int(row.get('competition_id') or competition_id),
        'scoring_mode': str(row.get('scoring_mode') or 'absolute').strip().lower(),
        'is_active': int(row.get('is_active') or 0),
        'revision': _ranking_navigation_revision(row, include_quota=include_quota),
        'quota': quota,
        'counts': {
            'leaderboard': int(row.get('leaderboard_count') or 0),
            'matches': int(row.get('valid_match_count') or 0),
            'all_submissions': int(row.get('submission_count') or 0),
            'appeals': int(row.get('pending_appeal_count') or 0),
            'attachments': int(row.get('attachment_count') or 0),
        },
    }


def create_competition(title, description, max_score, created_by, summary=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ranking_competitions (title, summary, description, max_score, created_by)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (title, (summary or None), description or '', int(max_score or 100), created_by),
            )
            new_id = cursor.lastrowid
        conn.commit()
        return int(new_id)
    finally:
        conn.close()


# 复制比赛时，自增/时间戳列不照搬（由数据库生成）。
_COMPETITION_COPY_EXCLUDE_COLS = {'id', 'created_at', 'updated_at'}
_COMPETITION_COPY_TITLE_SUFFIX = '（副本）'


def copy_competition(src_id, *, created_by=None):
    """把一个打榜赛**仅复制配置**为一个新的「非公开」副本，返回新比赛 id。

    复制：ranking_competitions 行（is_active=0、标题追加「（副本）」）
          + ranking_judge_rules + ranking_competition_files（含物理附件文件）
          + ranking_agent_judge_endpoints。
    绝不复制：ranking_submissions / ranking_judge_results / ranking_elo_matches（学生数据）。

    所有库写在单事务内，任何异常整体回滚；物理附件只往新比赛目录写，失败则清掉新目录。
    绝不修改源比赛或任何既有数据（只读源 + 只新增）。
    """
    conn = get_db_connection()
    created_comp_dir = None
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM ranking_competitions WHERE id = %s", (int(src_id),))
            comp = cursor.fetchone()
            if not comp:
                raise ValueError(f'源比赛 {src_id} 不存在')
            cursor.execute(
                "SELECT rule_id, rule_name, rule_text, value, dependencies, ordering "
                "FROM ranking_judge_rules WHERE competition_id = %s ORDER BY ordering, rule_id",
                (int(src_id),),
            )
            rules = cursor.fetchall() or []
            cursor.execute(
                "SELECT filename, stored_path, file_size "
                "FROM ranking_competition_files WHERE competition_id = %s ORDER BY id",
                (int(src_id),),
            )
            files = cursor.fetchall() or []
            cursor.execute(
                "SELECT pool_kind, harness, protocol, base_url, api_key, model, context_window_tokens, "
                "max_output_tokens, thinking_compatibility, thinking_format, "
                "concurrency_limit, enabled, status, ordering "
                "FROM ranking_agent_judge_endpoints WHERE competition_id = %s ORDER BY ordering, id",
                (int(src_id),),
            )
            endpoints = cursor.fetchall() or []

            # —— 1) 复制比赛主行（is_active=0 不公开、标题追加后缀、created_by 记为复制者）——
            cols = [c for c in comp.keys() if c not in _COMPETITION_COPY_EXCLUDE_COLS]
            new_title = (str(comp.get('title') or '') + _COMPETITION_COPY_TITLE_SUFFIX)[:255]
            vals = []
            for c in cols:
                v = comp[c]
                if c == 'is_active':
                    v = 0
                elif c == 'title':
                    v = new_title
                elif c == 'created_by' and created_by is not None:
                    v = created_by
                vals.append(v)
            collist = ','.join('`' + c + '`' for c in cols)
            placeholders = ','.join(['%s'] * len(cols))
            cursor.execute(
                f"INSERT INTO ranking_competitions ({collist}) VALUES ({placeholders})", vals)
            new_id = int(cursor.lastrowid)

            # —— 2) 复制附件（物理文件 + 行）到新比赛自己的目录 ——
            if files:
                dest_dir = competition_attachments_dir(new_id)
                created_comp_dir = competition_dir(new_id)
                os.makedirs(dest_dir, exist_ok=True)
                for f in files:
                    sp, fn = f.get('stored_path'), f.get('filename')
                    if sp and os.path.isfile(sp):
                        dp = os.path.join(dest_dir, os.path.basename(sp))
                        shutil.copy2(sp, dp)
                    else:
                        dp = os.path.join(dest_dir, fn or 'attachment')
                    cursor.execute(
                        "INSERT INTO ranking_competition_files "
                        "(competition_id, filename, stored_path, file_size) VALUES (%s, %s, %s, %s)",
                        (new_id, fn, dp, int(f.get('file_size') or 0)),
                    )

            # —— 3) 复制评测规则 ——
            for r in rules:
                if has_rule_name:
                    cursor.execute(
                        "INSERT INTO ranking_judge_rules "
                        "(competition_id, rule_id, rule_name, rule_text, value, dependencies, ordering) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (new_id, r['rule_id'], r.get('rule_name') or None, r['rule_text'],
                         r['value'], r['dependencies'], r['ordering']),
                    )
                else:
                    cursor.execute(
                        "INSERT INTO ranking_judge_rules "
                        "(competition_id, rule_id, rule_text, value, dependencies, ordering) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (new_id, r['rule_id'], r['rule_text'], r['value'],
                         r['dependencies'], r['ordering']),
                    )

            # —— 4) 复制 Agent 评测端点（含 api_key）——
            for e in endpoints:
                status = e.get('status') if e.get('status') in ('enabled', 'disabled', 'paused') else (
                    'enabled' if int(e.get('enabled') or 0) == 1 else 'disabled'
                )
                cursor.execute(
                    "INSERT INTO ranking_agent_judge_endpoints "
                    "(competition_id, pool_kind, harness, protocol, base_url, api_key, model, "
                    "context_window_tokens, max_output_tokens, thinking_compatibility, thinking_format, "
                    "concurrency_limit, enabled, status, ordering) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (new_id, e.get('pool_kind') or 'primary',
                     e.get('harness') or 'claude_code', e.get('protocol'),
                     e['base_url'], e['api_key'], e['model'],
                     int(e.get('context_window_tokens') or 1_000_000),
                     int(e.get('max_output_tokens') or 384_000),
                     1 if e.get('thinking_compatibility', True) else 0,
                     e.get('thinking_format'),
                     e['concurrency_limit'], 1 if status == 'enabled' else 0, status, e['ordering']),
                )
        conn.commit()
        return new_id
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        # 仅清理本次为新比赛新建的目录（防止物理文件残留），绝不碰其它路径。
        if created_comp_dir and os.path.isdir(created_comp_dir) and '/competitions/' in created_comp_dir:
            shutil.rmtree(created_comp_dir, ignore_errors=True)
        raise
    finally:
        conn.close()


def update_competition(competition_id, *, title=None, summary=None, description=None,
                        max_score=None, is_active=None, answer_format=None,
                        scoring_mode=None, elo_initial_rating=None, elo_k_factor=None,
                        elo_max_matches=None, elo_match_interval_seconds=None,
                        elo_initial_burst=None, elo_max_pairs_per_round=None,
                        elo_runtime_mode=None,
                        scoring_script_timeout_seconds=None,
                        agent_judge_timeout_seconds=None,
                        reverse_judge_finalize_timeout_seconds=None,
                        reverse_quality_gate_enabled=None,
                        reverse_quality_gate_prompt=None,
                        agent_judge_orchestration_mode=None,
                        submit_limit_per_window=None, set_limit_window_now=False,
                        submission_method=None, git_format=None):
    fields = []
    params = []
    if title is not None:
        fields.append("title = %s")
        params.append(title)
    if summary is not None:
        fields.append("summary = %s")
        params.append(summary or None)
    if description is not None:
        fields.append("description = %s")
        params.append(description)
    if max_score is not None:
        fields.append("max_score = %s")
        params.append(int(max_score))
    if is_active is not None:
        fields.append("is_active = %s")
        params.append(1 if is_active else 0)
    if answer_format is not None:
        fmt = str(answer_format or '').strip().lower()
        if fmt not in ('json', 'zip'):
            fmt = 'json'
        fields.append("answer_format = %s")
        params.append(fmt)
    if scoring_mode is not None:
        mode = str(scoring_mode or '').strip().lower()
        if mode not in ('absolute', 'elo', 'agent_judge', 'reverse_judge'):
            mode = 'absolute'
        fields.append("scoring_mode = %s")
        params.append(mode)
    if elo_initial_rating is not None:
        fields.append("elo_initial_rating = %s")
        params.append(float(elo_initial_rating))
    if elo_k_factor is not None:
        fields.append("elo_k_factor = %s")
        params.append(float(elo_k_factor))
    if elo_max_matches is not None:
        fields.append("elo_max_matches = %s")
        params.append(int(elo_max_matches))
    if elo_match_interval_seconds is not None:
        fields.append("elo_match_interval_seconds = %s")
        params.append(int(elo_match_interval_seconds))
    if elo_initial_burst is not None:
        fields.append("elo_initial_burst = %s")
        params.append(int(elo_initial_burst))
    if elo_max_pairs_per_round is not None:
        fields.append("elo_max_pairs_per_round = %s")
        params.append(int(elo_max_pairs_per_round))
    if elo_runtime_mode is not None:
        mode = str(elo_runtime_mode or '').strip().lower()
        if mode not in ('legacy', 'isolated'):
            mode = 'legacy'
        fields.append("elo_runtime_mode = %s")
        params.append(mode)
    if scoring_script_timeout_seconds is not None:
        fields.append("scoring_script_timeout_seconds = %s")
        params.append(int(scoring_script_timeout_seconds))
    if agent_judge_timeout_seconds is not None:
        fields.append("agent_judge_timeout_seconds = %s")
        params.append(int(agent_judge_timeout_seconds))
    if reverse_judge_finalize_timeout_seconds is not None:
        fields.append("reverse_judge_finalize_timeout_seconds = %s")
        params.append(int(reverse_judge_finalize_timeout_seconds))
    if reverse_quality_gate_enabled is not None:
        fields.append("reverse_quality_gate_enabled = %s")
        params.append(1 if reverse_quality_gate_enabled else 0)
    if reverse_quality_gate_prompt is not None:
        fields.append("reverse_quality_gate_prompt = %s")
        params.append(str(reverse_quality_gate_prompt))
    if agent_judge_orchestration_mode is not None:
        fields.append("agent_judge_orchestration_mode = %s")
        params.append(normalize_orchestration_mode(agent_judge_orchestration_mode))
    if submit_limit_per_window is not None:
        try:
            v = int(submit_limit_per_window)
        except (TypeError, ValueError):
            v = 0
        fields.append("submit_limit_per_window = %s")
        params.append(v if v > 0 else None)   # NULL/<=0 表示不限制
    if set_limit_window_now:
        # 用数据库 NOW() 作为窗口锚点，与 ranking_submissions.created_at 同源、避免时区漂移
        fields.append("limit_window_start = NOW()")
    if submission_method is not None:
        method = str(submission_method or '').strip().lower()
        if method not in ('zip', 'git'):
            method = 'zip'
        fields.append("submission_method = %s")
        params.append(method)
    if git_format is not None:
        fields.append("git_format = %s")
        params.append((str(git_format).strip() or None))
    if not fields:
        return
    params.append(competition_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"UPDATE ranking_competitions SET {', '.join(fields)} WHERE id = %s",
                tuple(params),
            )
        conn.commit()
    finally:
        conn.close()


def reset_competition_limit_window(competition_id):
    """管理员手动刷新：把窗口锚点设为当前时刻，相当于立刻开启新一轮 48 小时配额。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE ranking_competitions SET limit_window_start = NOW() WHERE id = %s",
                (competition_id,),
            )
        conn.commit()
    finally:
        conn.close()


def get_submission_quota(competition_id, username, comp=None):
    """返回某用户在当前 48 小时窗口内的提交配额：
    {'limit', 'used', 'remaining', 'window_start', 'next_reset'}；
    未设置限制（NULL/<=0）时返回 None（表示不限制）。"""
    if comp is None:
        comp = get_competition(competition_id)
    if not comp:
        return None
    raw = comp.get('submit_limit_per_window')
    try:
        limit = int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        limit = 0
    if limit <= 0:
        return None
    anchor = comp.get('limit_window_start') or comp.get('created_at')
    window_start, next_reset = quota_window_bounds(anchor, datetime.now())
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 只数学生自交（source='self'）：管理员批量拉取（source='batch'）不占用学生配额。
            cursor.execute(
                "SELECT COUNT(*) AS c FROM ranking_submissions"
                " WHERE competition_id = %s AND username = %s AND created_at >= %s"
                " AND source = 'self'",
                (competition_id, username, window_start),
            )
            row = cursor.fetchone() or {}
            used = int(row.get('c') or 0)
    finally:
        conn.close()
    return {
        'limit': limit,
        'used': used,
        'remaining': max(0, limit - used),
        'window_start': window_start,
        'next_reset': next_reset,
    }


def _submission_limit_from_comp(comp):
    raw = (comp or {}).get('submit_limit_per_window')
    try:
        limit = int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        limit = 0
    return max(0, limit)


def _ranking_submission_quota_with_cursor(cursor, competition_id, username, comp, now):
    limit = _submission_limit_from_comp(comp)
    if limit <= 0:
        return None
    anchor = comp.get('limit_window_start') or comp.get('created_at')
    window_start, next_reset = quota_window_bounds(anchor, now)
    cursor.execute(
        "SELECT COUNT(*) AS c FROM ranking_submissions"
        " WHERE competition_id = %s AND username = %s AND created_at >= %s"
        " AND source = 'self'",
        (competition_id, username, window_start),
    )
    row = cursor.fetchone() or {}
    used = int(row.get('c') or 0)
    return {
        'limit': limit,
        'used': used,
        'remaining': max(0, limit - used),
        'window_start': window_start,
        'next_reset': next_reset,
    }


def update_competition_reference_answer(competition_id, stored_path, original_name):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_competitions
                SET reference_answer_path = %s, reference_answer_name = %s
                WHERE id = %s
                """,
                (stored_path, original_name, competition_id),
            )
        conn.commit()
    finally:
        conn.close()


def update_competition_scoring_script(competition_id, stored_path, original_name):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_competitions
                SET scoring_script_path = %s, scoring_script_name = %s
                WHERE id = %s
                """,
                (stored_path, original_name, competition_id),
            )
        conn.commit()
    finally:
        conn.close()


def delete_competition(competition_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 先清理无外键级联的从属记录。尤其端点表含明文 API Key；若留下孤儿，
            # paused 恢复任务还会继续对已删除比赛的端点发起 hello。
            cursor.execute(
                """
                DELETE steps
                FROM ranking_reverse_judge_steps steps
                JOIN ranking_submissions submissions
                  ON submissions.id = steps.submission_id
                WHERE submissions.competition_id = %s
                """,
                (competition_id,),
            )
            cursor.execute(
                "DELETE FROM ranking_agent_judge_endpoints WHERE competition_id = %s",
                (competition_id,),
            )
            cursor.execute("DELETE FROM ranking_submissions WHERE competition_id = %s", (competition_id,))
            cursor.execute("DELETE FROM ranking_competition_files WHERE competition_id = %s", (competition_id,))
            cursor.execute("DELETE FROM ranking_competitions WHERE id = %s", (competition_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------- Attachments ----------

def list_competition_files(competition_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, filename, stored_path, file_size, uploaded_at
                FROM ranking_competition_files
                WHERE competition_id = %s
                ORDER BY uploaded_at ASC, id ASC
                """,
                (competition_id,),
            )
            return cursor.fetchall() or []
    finally:
        conn.close()


def get_competition_file(file_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, filename, stored_path, file_size
                FROM ranking_competition_files
                WHERE id = %s
                """,
                (file_id,),
            )
            return cursor.fetchone()
    finally:
        conn.close()


def create_competition_file(competition_id, filename, stored_path, file_size):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ranking_competition_files (competition_id, filename, stored_path, file_size)
                VALUES (%s, %s, %s, %s)
                """,
                (competition_id, filename, stored_path, int(file_size or 0)),
            )
            new_id = cursor.lastrowid
        conn.commit()
        return int(new_id)
    finally:
        conn.close()


def delete_competition_file(file_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_competition_files WHERE id = %s", (file_id,))
        conn.commit()
    finally:
        conn.close()


# ---------- Submissions ----------

def _agent_endpoint_snapshot_with_cursor(cursor, competition_id, endpoint_id):
    if endpoint_id in (None, '', 'null'):
        return None, None
    try:
        eid = int(endpoint_id)
    except (TypeError, ValueError):
        return None, None
    cursor.execute(
        """
        SELECT harness, model
        FROM ranking_agent_judge_endpoints
        WHERE id = %s AND competition_id = %s AND pool_kind = 'primary'
        """,
        (eid, int(competition_id)),
    )
    row = cursor.fetchone() or {}
    return row.get('harness') or None, row.get('model') or None


def _agent_endpoint_harness_label(harness):
    value = str(harness or '').strip().lower().replace('-', '_')
    if value == 'claude_code':
        return 'Claude Code'
    if value == 'codex':
        return 'Codex'
    if value == 'opencode':
        return 'OpenCode'
    if value == 'pi':
        return 'Pi'
    return str(harness or '').strip()


def _agent_endpoint_label(harness, model):
    harness_label = _agent_endpoint_harness_label(harness)
    model_text = str(model or '').strip()
    if harness_label and model_text:
        return f'{harness_label} ({model_text})'
    if harness_label:
        return harness_label
    if model_text:
        return model_text
    return None


def _attach_agent_endpoint_labels(rows, *, label_key='agent_endpoint_label',
                                  harness_key='agent_endpoint_harness',
                                  model_key='agent_endpoint_model'):
    for row in rows or []:
        row[label_key] = _agent_endpoint_label(row.get(harness_key), row.get(model_key))
    return rows


def _normalize_submission_source(source):
    return 'batch' if str(source or '').strip().lower() == 'batch' else 'self'


def _record_submission_metric(submission_id):
    """每日计数是派生指标，失败不得让调用方误判业务提交失败。"""
    try:
        bump_daily_submission_count()
    except Exception:
        logger.exception(
            '打榜赛提交已成功，但每日提交计数更新失败',
            extra={'submission_id': int(submission_id)},
        )


def _artifact_audit_metadata(path, artifact_type):
    return safe_file_fingerprint(path, artifact_type=artifact_type)


def _audit_ranking_submission_created(
        submission_id, competition_id, username, *, source, status,
        origin, agent_endpoint_id=None, base_model=None, artifacts=None,
        parent_submission_id=None):
    emit_audit(
        'submissions',
        action='submission.created',
        outcome='success',
        message='打榜赛提交已创建',
        submission={
            'id': int(submission_id),
            'kind': 'ranking',
            'origin': origin,
            'source': source,
            'initial_status': status,
            'parent_id': parent_submission_id,
            'agent_endpoint_id': agent_endpoint_id,
            'base_model': base_model,
        },
        competition={'id': int(competition_id)},
        user={'name': username},
        artifacts=[artifact for artifact in (artifacts or ()) if artifact],
    )


def _audit_ranking_artifacts_attached(
        submission_id, *, status, base_model=None, origin=None, artifacts=None):
    submission = {
        'id': int(submission_id),
        'kind': 'ranking',
        'base_model': base_model,
        'status': status,
    }
    if origin:
        submission['origin'] = origin
    emit_audit(
        'submissions',
        action='submission.artifacts.attached',
        outcome='success',
        message='打榜赛提交文件已关联',
        submission=submission,
        artifacts=[artifact for artifact in (artifacts or ()) if artifact],
    )


def _lock_submission_quota(cursor, competition_id, username, *, source, enforce_quota):
    """在当前事务内按用户串行化并执行权威配额检查。

    文件型提交会在拿锁前先把上传内容写入同文件系统的临时目录，随后在这把锁保护的
    事务中插入行、安装文件并写元数据。这样既不延长网络上传阶段的锁持有时间，也不
    会让同一用户的并发提交绕过 48 小时窗口上限。锁定稳定的 ``users`` 行而不是比赛
    行，避免不同学生向同一比赛提交时被全局串行化。
    """
    if not enforce_quota or source != 'self':
        return
    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE username = %s
        FOR UPDATE
        """,
        (username,),
    )
    if not cursor.fetchone():
        raise LookupError('提交用户不存在')
    cursor.execute(
        """
        SELECT id, submit_limit_per_window, limit_window_start, created_at
        FROM ranking_competitions
        WHERE id = %s
        """,
        (competition_id,),
    )
    comp = cursor.fetchone()
    if not comp:
        return
    cursor.execute("SELECT NOW() AS now")
    now_row = cursor.fetchone() or {}
    now = now_row.get('now') or datetime.now()
    quota = _ranking_submission_quota_with_cursor(
        cursor, competition_id, username, comp, now,
    )
    if quota is not None and quota['remaining'] <= 0:
        raise RankingSubmissionQuotaExceeded(quota)


def _insert_ranking_submission(cursor, competition_id, username, *, source,
                               agent_endpoint_id=None):
    endpoint_id = None
    if agent_endpoint_id not in (None, '', 'null'):
        try:
            endpoint_id = int(agent_endpoint_id)
        except (TypeError, ValueError):
            endpoint_id = None
    endpoint_harness, endpoint_model = _agent_endpoint_snapshot_with_cursor(
        cursor, competition_id, endpoint_id,
    )
    cursor.execute(
        """
        INSERT INTO ranking_submissions
            (competition_id, username, status, source, agent_endpoint_id,
             agent_endpoint_harness, agent_endpoint_model)
        VALUES (%s, %s, 'Pending', %s, %s, %s, %s)
        """,
        (
            competition_id, username, source, endpoint_id,
            endpoint_harness, endpoint_model,
        ),
    )
    return int(cursor.lastrowid)


def create_ranking_submission(competition_id, username, source='self', enforce_quota=False,
                              agent_endpoint_id=None):
    """新建一条打榜赛提交。source：'self'=学生自交（计入 48h 配额）、
    'batch'=管理员批量拉取（不计入学生配额）。

    当 enforce_quota=True 且 source='self' 时，使用同一事务里的 ``SELECT ... FOR UPDATE``
    锁住用户行，重新计算当前窗口用量并插入提交，避免同一用户的并发请求同时通过前置
    COUNT 检查，同时不阻塞其他学生提交。
    """
    src = _normalize_submission_source(source)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            _lock_submission_quota(
                cursor, competition_id, username,
                source=src, enforce_quota=enforce_quota,
            )
            new_id = _insert_ranking_submission(
                cursor, competition_id, username, source=src,
                agent_endpoint_id=agent_endpoint_id,
            )
        conn.commit()
        _record_submission_metric(new_id)
        _audit_ranking_submission_created(
            new_id,
            competition_id,
            username,
            source=src,
            status='Pending',
            origin='git_or_batch',
            agent_endpoint_id=agent_endpoint_id,
        )
        return int(new_id)
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def _artifact_destination(target_dir, filename):
    """返回提交文件目标路径，并拒绝任何目录穿越或空文件名。"""
    name = str(filename or '')
    if not name or name in ('.', '..') or os.path.basename(name) != name:
        raise ValueError(f'非法提交文件名：{name!r}')
    return os.path.join(target_dir, name)


def _artifact_commit_matches(submission_id, installed, code_filename, answer_filename):
    """用新连接确认一次结果不确定的 commit 是否已经对外可见。"""
    row = get_ranking_submission(submission_id)
    if not row:
        return False
    expected = {
        'code_filename': code_filename,
        'code_path': installed['code'],
        'answer_filename': answer_filename,
        'answer_path': installed.get('answer'),
    }
    if any(row.get(key) != value for key, value in expected.items()):
        return False
    return all(os.path.isfile(path) for path in installed.values())


def create_ranking_artifact_submission(
        competition_id, username, *, code_staged_path, code_filename,
        answer_staged_path=None, answer_filename=None, base_model=None,
        source='self', enforce_quota=False, agent_endpoint_id=None):
    """原子登记一条已经完成落盘与大小校验的文件型提交。

    调用方先把上传内容放到 ``ranking_uploads/submissions`` 下的临时目录并完成校验；
    本函数再在配额锁所在的数据库事务内创建提交行、原子移动文件、写入最终路径。
    文件安装或元数据更新失败时，数据库回滚并移除目标目录。若 ``commit()`` 本身返回
    错误，结果可能已在服务端提交：此时用新连接确认，已提交则按成功返回；无法确认则
    保留目标目录并抛出明确异常，绝不删除可能已被数据库引用的文件。每日计数是派生
    指标，不影响业务提交结果。
    """
    staged_artifacts = [('code', code_staged_path, code_filename)]
    if answer_staged_path is not None or answer_filename is not None:
        staged_artifacts.append(('answer', answer_staged_path, answer_filename))
    filenames = [str(item[2] or '') for item in staged_artifacts]
    if len(set(filenames)) != len(filenames):
        raise ValueError('提交文件名不能重复')
    for kind, staged_path, filename in staged_artifacts:
        if not staged_path or not os.path.isfile(staged_path):
            raise ValueError(f'{kind} 暂存文件不存在')
        # 在开启事务前验证文件名；目标目录要等拿到自增 ID 后才能确定。
        _artifact_destination('', filename)

    src = _normalize_submission_source(source)
    conn = get_db_connection()
    target_dir = None
    target_created = False
    commit_attempted = False
    installed = {}
    try:
        with conn.cursor() as cursor:
            _lock_submission_quota(
                cursor, competition_id, username,
                source=src, enforce_quota=enforce_quota,
            )
            new_id = _insert_ranking_submission(
                cursor, competition_id, username, source=src,
                agent_endpoint_id=agent_endpoint_id,
            )
            target_dir = submission_dir(new_id)
            os.makedirs(target_dir, exist_ok=False)
            target_created = True

            for kind, staged_path, filename in staged_artifacts:
                destination = _artifact_destination(target_dir, filename)
                os.replace(staged_path, destination)
                installed[kind] = destination

            cursor.execute(
                """
                UPDATE ranking_submissions
                SET answer_filename = %s, answer_path = %s,
                    code_filename = %s, code_path = %s,
                    base_model = %s,
                    status = 'Judging'
                WHERE id = %s
                """,
                (
                    answer_filename, installed.get('answer'),
                    code_filename, installed['code'],
                    (base_model or None), new_id,
                ),
            )
            if int(cursor.rowcount or 0) != 1:
                raise RuntimeError(f'提交 {new_id} 的文件元数据写入失败')
        commit_attempted = True
        conn.commit()
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        if commit_attempted:
            try:
                committed = _artifact_commit_matches(
                    new_id,
                    installed,
                    code_filename,
                    answer_filename,
                )
            except Exception as verification_exc:
                raise RankingSubmissionCommitUnknown(new_id) from verification_exc
            if committed:
                logger.warning(
                    '打榜赛提交 commit 返回错误，但已由新连接确认成功',
                    extra={'submission_id': int(new_id)},
                )
            else:
                raise RankingSubmissionCommitUnknown(new_id) from exc
        elif target_created:
            shutil.rmtree(target_dir, ignore_errors=True)
            raise
        else:
            raise
    finally:
        conn.close()

    _record_submission_metric(new_id)
    _audit_ranking_submission_created(
        new_id,
        competition_id,
        username,
        source=src,
        status='Judging',
        origin='artifact_upload',
        agent_endpoint_id=agent_endpoint_id,
        base_model=base_model,
        artifacts=(
            _artifact_audit_metadata(installed.get('code'), 'code'),
            _artifact_audit_metadata(installed.get('answer'), 'answer'),
        ),
    )
    return int(new_id)


def update_submission_files(submission_id, answer_filename, answer_path, code_filename, code_path, base_model=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET answer_filename = %s, answer_path = %s,
                    code_filename = %s, code_path = %s,
                    base_model = %s,
                    status = 'Judging'
                WHERE id = %s
                """,
                (answer_filename, answer_path, code_filename, code_path,
                 (base_model or None), submission_id),
            )
            affected = int(cursor.rowcount or 0)
        conn.commit()
    finally:
        conn.close()
    if affected:
        _audit_ranking_artifacts_attached(
            submission_id,
            status='Judging',
            base_model=base_model,
            artifacts=(
                _artifact_audit_metadata(code_path, 'code'),
                _artifact_audit_metadata(answer_path, 'answer'),
            ),
        )


def set_submission_agent_endpoint(submission_id, endpoint_id):
    endpoint_id = int(endpoint_id) if endpoint_id not in (None, '', 'null') else None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            competition_id = None
            cursor.execute(
                "SELECT competition_id FROM ranking_submissions WHERE id = %s",
                (submission_id,),
            )
            row = cursor.fetchone() or {}
            if row.get('competition_id') is not None:
                competition_id = int(row.get('competition_id'))
            endpoint_harness, endpoint_model = _agent_endpoint_snapshot_with_cursor(
                cursor, competition_id, endpoint_id,
            ) if competition_id is not None else (None, None)
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET agent_endpoint_id = %s,
                    agent_endpoint_harness = %s,
                    agent_endpoint_model = %s
                WHERE id = %s
                """,
                (endpoint_id, endpoint_harness, endpoint_model, submission_id),
            )
        conn.commit()
    finally:
        conn.close()


def _serialize_grade_details(grade_details):
    if grade_details is None or isinstance(grade_details, str):
        return grade_details
    try:
        return json.dumps(grade_details, ensure_ascii=False)
    except Exception:
        return str(grade_details)


def update_submission_result(submission_id, score, status, grade_details=None, error_message=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            details_text = _serialize_grade_details(grade_details)
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET score = %s, status = %s, grade_details = %s, error_message = %s
                WHERE id = %s
                """,
                (score, status, details_text, error_message, submission_id),
            )
        conn.commit()
    finally:
        conn.close()


def update_standard_ranking_result_for_task(
        submission_id, task_id, score, status, grade_details=None, error_message=None):
    """仅允许仍持有数据库租约的普通评测任务写入终态。"""
    normalized_task_id = str(task_id or '').strip()[:64]
    if not normalized_task_id:
        raise ValueError('task_id 不能为空')
    details_text = _serialize_grade_details(grade_details)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET score = %s,
                    status = %s,
                    grade_details = %s,
                    error_message = %s,
                    judge_heartbeat_at = CURRENT_TIMESTAMP
                WHERE id = %s AND judge_task_id = %s
                """,
                (
                    score, status, details_text, error_message,
                    int(submission_id), normalized_task_id,
                ),
            )
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def set_submission_status(submission_id, status):
    """只更新提交状态（不动 score/grade_details/error_message）。

    用于 agent_judge 的「等待评测(Queued) → 评测中(Judging)」状态切换：提交入队时置
    'Queued'，真正被评测 worker 取到开始执行时置 'Judging'。这样在 judge 并发上限（2）已满时，
    排队中的提交显示「等待评测」，而非误报「评测中」。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE ranking_submissions SET status = %s WHERE id = %s",
                (status, submission_id),
            )
        conn.commit()
    finally:
        conn.close()


def begin_agent_judge_attempt(submission_id, status='Queued', reset_result=False, *,
                              clear_agent_results=False,
                              clear_reverse_steps=False):
    """为一次 Agent-as-Judge 评测生成新的 attempt，并返回 attempt_id。

    重测时可在同一事务中清空 Agent 规则结果或反向评测步骤。必须先写入新 attempt
    再清旧结果，且二者原子提交：这样旧 worker 立即失效，也不存在进程在两步之间
    崩溃后让新 attempt 继承旧门禁结果的窗口。
    """
    attempt_id = str(uuid.uuid4())
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if reset_result:
                cursor.execute(
                    """
                    UPDATE ranking_submissions
                    SET status = %s,
                        score = NULL,
                        grade_details = NULL,
                        error_message = NULL,
                        judge_attempt_id = %s,
                        judge_task_id = NULL,
                        judge_heartbeat_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    """,
                    (status, attempt_id, submission_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE ranking_submissions
                    SET status = %s,
                        judge_attempt_id = %s,
                        judge_task_id = NULL,
                        judge_heartbeat_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    """,
                    (status, attempt_id, submission_id),
                )
            if clear_agent_results:
                cursor.execute(
                    "DELETE FROM ranking_judge_results WHERE submission_id = %s",
                    (submission_id,),
                )
            if clear_reverse_steps:
                cursor.execute(
                    "DELETE FROM ranking_reverse_judge_steps WHERE submission_id = %s",
                    (submission_id,),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return attempt_id


def invalidate_ranking_submission_attempt(submission_id, status='Cancelled'):
    """让当前评测 attempt 失效，用于删除前阻止旧 Celery 消息继续落库或启动容器。"""
    attempt_id = str(uuid.uuid4())
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET status = %s,
                    judge_attempt_id = %s,
                    judge_task_id = NULL,
                    judge_heartbeat_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (status, attempt_id, submission_id),
            )
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0), attempt_id
    finally:
        conn.close()


def set_agent_judge_task_id(submission_id, attempt_id, task_id):
    """记录当前 attempt 对应的 Celery task id。仅用于诊断和启动恢复判断。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET judge_task_id = %s, judge_heartbeat_at = CURRENT_TIMESTAMP
                WHERE id = %s AND judge_attempt_id <=> %s
                """,
                (str(task_id or '')[:64] or None, submission_id, attempt_id),
            )
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
    finally:
        conn.close()


def reserve_standard_ranking_evaluation(
        submission_id, task_id, *, stale_after_seconds=1800, force=False):
    """为普通打榜评测持久预留一个 Celery task id。

    首次领取只接受 ``Judging + task_id=NULL``；已有任务只有心跳超过租约后才能被新
    task id 替换。数据库 CAS 是防重真相，Redis claim 只负责削减竞争。
    """
    normalized_task_id = str(task_id or '').strip()[:64]
    if not normalized_task_id:
        raise ValueError('task_id 不能为空')
    stale_after_seconds = max(1, int(stale_after_seconds))
    eligibility_sql = "status IN ('Judging', 'Queued')" if force else """
        (
            (status = 'Judging' AND judge_task_id IS NULL)
            OR (
                status IN ('Judging', 'Queued')
                AND TIMESTAMPDIFF(
                    SECOND,
                    COALESCE(judge_heartbeat_at, created_at),
                    CURRENT_TIMESTAMP
                ) >= %s
            )
        )
    """
    eligibility_params = () if force else (stale_after_seconds,)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE ranking_submissions
                SET status = 'Queued',
                    judge_task_id = %s,
                    judge_heartbeat_at = CURRENT_TIMESTAMP
                WHERE id = %s
                  AND {eligibility_sql}
                """,
                (normalized_task_id, int(submission_id), *eligibility_params),
            )
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def release_standard_ranking_evaluation(submission_id, task_id):
    """仅由仍持有 task id 的发送方释放尚未成功入 broker 的预留。"""
    normalized_task_id = str(task_id or '').strip()[:64]
    if not normalized_task_id:
        return 0
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET status = 'Judging',
                    judge_task_id = NULL,
                    judge_heartbeat_at = CURRENT_TIMESTAMP
                WHERE id = %s
                  AND status = 'Queued'
                  AND judge_task_id = %s
                """,
                (int(submission_id), normalized_task_id),
            )
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def claim_standard_ranking_evaluation(submission_id, task_id):
    """评测任务开始时确认自身仍是数据库记录的当前所有者。"""
    normalized_task_id = str(task_id or '').strip()[:64]
    if not normalized_task_id:
        raise ValueError('task_id 不能为空')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET status = 'Judging',
                    judge_task_id = %s,
                    judge_heartbeat_at = CURRENT_TIMESTAMP
                WHERE id = %s
                  AND status IN ('Judging', 'Queued')
                  AND (judge_task_id IS NULL OR judge_task_id = %s)
                """,
                (normalized_task_id, int(submission_id), normalized_task_id),
            )
            affected = cursor.rowcount
            if not affected:
                cursor.execute(
                    """
                    SELECT 1
                    FROM ranking_submissions
                    WHERE id = %s
                      AND status IN ('Judging', 'Queued')
                      AND judge_task_id = %s
                    LIMIT 1
                    """,
                    (int(submission_id), normalized_task_id),
                )
                affected = 1 if cursor.fetchone() else 0
        conn.commit()
        return int(affected or 0)
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def set_submission_status_for_attempt(submission_id, attempt_id, status):
    """只在 attempt 仍是当前 attempt 时更新状态，返回匹配行数。

    PyMySQL 默认 rowcount 是 changed rows；当状态本来就是目标值且 heartbeat
    落在同一秒时，UPDATE 会返回 0。这里再查一次 attempt 是否仍匹配，避免把
    “无改动”误判成“旧 attempt”。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET status = %s, judge_heartbeat_at = CURRENT_TIMESTAMP
                WHERE id = %s AND judge_attempt_id <=> %s
                """,
                (status, submission_id, attempt_id),
            )
            affected = cursor.rowcount
            if not affected:
                cursor.execute(
                    """
                    SELECT 1
                    FROM ranking_submissions
                    WHERE id = %s AND judge_attempt_id <=> %s
                    LIMIT 1
                    """,
                    (submission_id, attempt_id),
                )
                if cursor.fetchone():
                    affected = 1
        conn.commit()
        return int(affected or 0)
    finally:
        conn.close()


def update_submission_result_for_attempt(submission_id, attempt_id, score, status,
                                         grade_details=None, error_message=None):
    """只在 attempt 仍是当前 attempt 时写入终态，返回受影响行数。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            details_text = None
            if grade_details is not None:
                if isinstance(grade_details, str):
                    details_text = grade_details
                else:
                    try:
                        details_text = json.dumps(grade_details, ensure_ascii=False)
                    except Exception:
                        details_text = str(grade_details)
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET score = %s,
                    status = %s,
                    grade_details = %s,
                    error_message = %s,
                    judge_heartbeat_at = CURRENT_TIMESTAMP
                WHERE id = %s AND judge_attempt_id <=> %s
                """,
                (score, status, details_text, error_message, submission_id, attempt_id),
            )
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
    finally:
        conn.close()


def _copy_submission_artifact(src_path, src_name, target_dir):
    """复制打榜赛提交文件到新的提交目录；源路径为空时保留为空。"""
    if not src_path:
        return src_name, None
    if not os.path.isfile(src_path):
        raise FileNotFoundError(f"提交文件不存在：{src_path}")
    filename = src_name or os.path.basename(src_path)
    os.makedirs(target_dir, exist_ok=True)
    dst_path = os.path.join(target_dir, filename)
    shutil.copy2(src_path, dst_path)
    return filename, dst_path


def clone_ranking_submission_for_rejudge(source_submission_id, *, competition_id=None, status='Judging'):
    """复制一条打榜赛提交为新的管理员重测提交。

    只复制提交记录和落盘文件，不计入学生 48 小时提交配额；新提交的评测入队由调用方负责。
    """
    new_status = status if status in ('Pending', 'Queued', 'Judging') else 'Judging'
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, username,
                       answer_filename, answer_path, code_filename, code_path,
                       base_model,
                       agent_endpoint_id, agent_endpoint_harness, agent_endpoint_model
                FROM ranking_submissions
                WHERE id = %s
                """,
                (int(source_submission_id),),
            )
            source = cursor.fetchone()
            if not source:
                raise ValueError(f"source ranking submission {source_submission_id} not found")
            if competition_id is not None and int(source.get('competition_id')) != int(competition_id):
                raise ValueError("source submission does not belong to this competition")

            cursor.execute(
                """
                INSERT INTO ranking_submissions
                    (competition_id, username, answer_filename, code_filename, base_model,
                     agent_endpoint_id, agent_endpoint_harness, agent_endpoint_model,
                     score, status, grade_details, error_message,
                     elo_rating, elo_match_count, elo_in_pool, source)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s,
                        NULL, %s, NULL, NULL,
                        NULL, 0, 0, 'batch')
                """,
                (
                    source['competition_id'],
                    source.get('username') or '',
                    source.get('answer_filename'),
                    source.get('code_filename'),
                    source.get('base_model'),
                    source.get('agent_endpoint_id'),
                    source.get('agent_endpoint_harness'),
                    source.get('agent_endpoint_model'),
                    new_status,
                ),
            )
            new_id = cursor.lastrowid
        conn.commit()
    finally:
        conn.close()

    if not new_id:
        raise RuntimeError("clone_ranking_submission_for_rejudge: failed to get valid submission id")

    _audit_ranking_submission_created(
        new_id,
        source['competition_id'],
        source.get('username') or '',
        source='batch',
        status=new_status,
        origin='admin_rejudge_clone',
        agent_endpoint_id=source.get('agent_endpoint_id'),
        base_model=source.get('base_model'),
        parent_submission_id=int(source_submission_id),
    )

    target_dir = submission_dir(new_id)
    try:
        answer_name, answer_path = _copy_submission_artifact(
            source.get('answer_path'), source.get('answer_filename'), target_dir,
        )
        code_name, code_path = _copy_submission_artifact(
            source.get('code_path'), source.get('code_filename'), target_dir,
        )
    except Exception as e:
        try:
            update_submission_result(new_id, None, 'Error', error_message=str(e)[:1000])
        except Exception:
            pass
        raise

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET answer_filename = %s, answer_path = %s,
                    code_filename = %s, code_path = %s
                WHERE id = %s
                """,
                (answer_name, answer_path, code_name, code_path, new_id),
            )
        conn.commit()
        _record_submission_metric(new_id)
        _audit_ranking_artifacts_attached(
            new_id,
            status=new_status,
            origin='admin_rejudge_clone',
            base_model=source.get('base_model'),
            artifacts=(
                _artifact_audit_metadata(code_path, 'code'),
                _artifact_audit_metadata(answer_path, 'answer'),
            ),
        )
        return int(new_id), source
    finally:
        conn.close()


def delete_ranking_submission(submission_id):
    """删除一条提交记录。返回被删除的行数（0 或 1）。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_submissions WHERE id = %s", (submission_id,))
            affected = cursor.rowcount
        conn.commit()
        affected = int(affected or 0)
        if affected:
            emit_audit(
                'submissions',
                action='submission.deleted',
                outcome='success',
                message='打榜赛提交已删除',
                submission={'id': int(submission_id), 'kind': 'ranking'},
            )
        return affected
    finally:
        conn.close()


def get_ranking_submission(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, username,
                       answer_filename, answer_path, code_filename, code_path,
                       base_model, score, status, grade_details, error_message,
                       judge_attempt_id, judge_task_id, judge_heartbeat_at,
                       agent_endpoint_id, agent_endpoint_harness, agent_endpoint_model,
                       elo_rating, elo_match_count, elo_in_pool,
                       created_at
                FROM ranking_submissions
                WHERE id = %s
                """,
                (submission_id,),
            )
            return cursor.fetchone()
    finally:
        conn.close()


def get_incomplete_ranking_submissions():
    """返回所有卡在 'Judging' / 'Queued' 的打榜赛提交，用于进程启动时重新入队。

    'Judging' = 文件已上传或 worker 已开始执行；'Queued' = 已取得持久 task-id 租约但
    worker 尚未开始。连带返回所属比赛和用户信息，便于按模式恢复：
      - 绝对分模式：以数据库 task-id 租约防重后重新入队；
      - ELO 模式：同事务激活新提交并退役超额旧提交，再补发 initial-burst。
    'Pending'（尚未上传文件，无可评内容）与 'Active' ELO（已由 matchmaker tick 接管）
    不在此列。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT s.id, s.competition_id, s.username, s.status,
                       s.score, s.grade_details,
                       s.judge_attempt_id, s.judge_task_id, s.judge_heartbeat_at,
                       s.agent_endpoint_id,
                       s.created_at,
                       c.scoring_mode, c.elo_initial_rating
                FROM ranking_submissions s
                JOIN ranking_competitions c ON c.id = s.competition_id
                WHERE s.status IN ('Judging', 'Queued')
                ORDER BY
                    CASE
                        WHEN s.created_at IS NOT NULL
                         AND s.created_at >= (NOW() - INTERVAL 24 HOUR)
                        THEN 0
                        ELSE 1
                    END ASC,
                    s.created_at ASC,
                    s.id ASC
                """
            )
            return cursor.fetchall()
    finally:
        conn.close()


def list_user_submissions(competition_id, username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT s.id, s.competition_id, s.username,
                       s.answer_filename, s.code_filename, s.base_model,
                       s.score, s.status, s.judge_attempt_id,
                       s.agent_endpoint_id,
                       COALESCE(s.agent_endpoint_harness, ep.harness) AS agent_endpoint_harness,
                       COALESCE(s.agent_endpoint_model, ep.model) AS agent_endpoint_model,
                       s.elo_rating, s.elo_match_count, s.elo_in_pool,
                       s.created_at
                FROM ranking_submissions s
                LEFT JOIN ranking_agent_judge_endpoints ep
                  ON ep.id = s.agent_endpoint_id AND ep.pool_kind = 'primary'
                WHERE s.competition_id = %s AND s.username = %s
                ORDER BY s.created_at DESC, s.id DESC
                """,
                (competition_id, username),
            )
            return _attach_agent_endpoint_labels(cursor.fetchall() or [])
    finally:
        conn.close()


def list_all_submissions(competition_id, *, page=1, per_page=50, username_q=None):
    """返回 ``(rows, page, total)``。``page`` 在越界时被 clamp 到最后一页（保证只走一次 SELECT）。"""
    page = max(1, int(page or 1))
    per_page = max(1, int(per_page or 50))
    q = (username_q or '').strip()
    where_sql = "WHERE s.competition_id = %s"
    params = [int(competition_id)]
    if q:
        where_sql += " AND s.username LIKE %s"
        params.append(f"%{q}%")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) AS total FROM ranking_submissions s {where_sql}",
                tuple(params),
            )
            total = int((cursor.fetchone() or {}).get('total') or 0)
            total_pages = max(1, (total + per_page - 1) // per_page)
            if page > total_pages:
                page = total_pages
            offset = (page - 1) * per_page
            cursor.execute(
                f"""
                SELECT s.id, s.competition_id, s.username,
                       s.answer_filename, s.code_filename, s.base_model,
                       s.score, s.status, s.judge_attempt_id,
                       s.agent_endpoint_id,
                       COALESCE(s.agent_endpoint_harness, ep.harness) AS agent_endpoint_harness,
                       COALESCE(s.agent_endpoint_model, ep.model) AS agent_endpoint_model,
                       s.elo_rating, s.elo_match_count, s.elo_in_pool,
                       s.created_at
                FROM ranking_submissions s
                LEFT JOIN ranking_agent_judge_endpoints ep
                  ON ep.id = s.agent_endpoint_id AND ep.pool_kind = 'primary'
                {where_sql}
                ORDER BY s.created_at DESC, s.id DESC
                LIMIT %s OFFSET %s
                """,
                tuple(params) + (per_page, offset),
            )
            rows = _attach_agent_endpoint_labels(cursor.fetchall() or [])
            return rows, page, total
    finally:
        conn.close()


def _bulk_status_condition(status_groups):
    groups = []
    for item in status_groups or []:
        key = str(item or '').strip().lower()
        if key in ('judging', 'waiting', 'accepted', 'abnormal') and key not in groups:
            groups.append(key)

    conditions = []
    params = []
    status_sets = {
        'judging': ('Judging',),
        'waiting': ('Queued', 'Pending'),
        'accepted': ('Accepted', 'Active', 'Retired'),
    }
    normal_statuses = ('Queued', 'Pending', 'Judging', 'Accepted', 'Active', 'Retired')
    for group in groups:
        if group in status_sets:
            values = status_sets[group]
            conditions.append("status IN (" + ",".join(["%s"] * len(values)) + ")")
            params.extend(values)
        elif group == 'abnormal':
            conditions.append("status NOT IN (" + ",".join(["%s"] * len(normal_statuses)) + ")")
            params.extend(normal_statuses)
    if not conditions:
        return "", []
    return "(" + " OR ".join(conditions) + ")", params


def list_submissions_for_bulk_rejudge(competition_id, *, start=None, end=None,
                                      username_q=None, status_groups=None, limit=1001):
    """按管理员批量重测筛选条件返回 ``(rows, total)``。"""
    conditions = ["competition_id = %s"]
    params = [int(competition_id)]
    if start:
        conditions.append("created_at >= %s")
        params.append(start)
    if end:
        conditions.append("created_at <= %s")
        params.append(end)
    q = (username_q or '').strip()
    if q:
        conditions.append("username LIKE %s")
        params.append(f"%{q}%")
    status_sql, status_params = _bulk_status_condition(status_groups or [])
    if status_sql:
        conditions.append(status_sql)
        params.extend(status_params)

    where_sql = "WHERE " + " AND ".join(conditions)
    count_params = tuple(params)
    query_params = list(params)
    limit_sql = ""
    if limit:
        limit_sql = " LIMIT %s"
        query_params.append(int(limit))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) AS total FROM ranking_submissions {where_sql}",
                count_params,
            )
            total = int((cursor.fetchone() or {}).get('total') or 0)
            cursor.execute(
                f"""
                SELECT id, competition_id, username,
                       answer_filename, code_filename, base_model,
                       score, status,
                       elo_rating, elo_match_count, elo_in_pool,
                       created_at
                FROM ranking_submissions
                {where_sql}
                ORDER BY created_at DESC, id DESC
                {limit_sql}
                """,
                tuple(query_params),
            )
            return cursor.fetchall() or [], total
    finally:
        conn.close()


def get_submission_stats(competition_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(DISTINCT username) AS unique_users,
                    SUM(CASE WHEN status = 'Accepted' THEN 1 ELSE 0 END) AS accepted,
                    MAX(score) AS top_score
                FROM ranking_submissions
                WHERE competition_id = %s
                """,
                (int(competition_id),),
            )
            row = cursor.fetchone() or {}
            top_raw = row.get('top_score')
            return {
                'total': int(row.get('total') or 0),
                'unique_users': int(row.get('unique_users') or 0),
                'accepted': int(row.get('accepted') or 0),
                'top_score': float(top_raw) if top_raw is not None else None,
            }
    finally:
        conn.close()


def get_leaderboard(competition_id):
    """
    返回按每位用户最高分排序的排行榜。分数相同排名一致（标准竞赛并列排名）。
    ELO 赛事只统计仍在役且位于 ELO 池中的提交；其他模式统计所有已评分提交。
    每行附带 `best_base_model`：取得最高分那一份提交所填写的基座模型；
    若该用户的多份提交并列最高分，取最近一次。

    实现：单遍窗口函数。``ROW_NUMBER OVER (PARTITION BY username ORDER BY score DESC,
    created_at DESC, id DESC)`` 在 rn=1 的位置给出每位用户「最高分中最近一次」那条；
    同一窗口里再算 ``COUNT/MIN/MAX`` 给出 submission_count / first_submitted_at /
    best_score，避免历史版本里那条相关子查询带来的 N×扫描。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                WITH ranked AS (
                    SELECT
                        s.username, s.score, s.base_model, s.created_at, s.id,
                        s.agent_endpoint_id, s.agent_endpoint_harness, s.agent_endpoint_model,
                        ROW_NUMBER() OVER (
                            PARTITION BY s.username
                            ORDER BY s.score DESC, s.created_at DESC, s.id DESC
                        ) AS rn,
                        COUNT(*) OVER (PARTITION BY s.username) AS user_submission_count,
                        MIN(s.created_at) OVER (PARTITION BY s.username) AS user_first_submitted_at,
                        MAX(s.score) OVER (PARTITION BY s.username) AS user_best_score
                    FROM ranking_submissions s
                    JOIN ranking_competitions c ON c.id = s.competition_id
                    WHERE s.competition_id = %s
                      AND s.score IS NOT NULL
                      AND (
                          COALESCE(c.scoring_mode, 'absolute') <> 'elo'
                          OR (s.status = 'Active' AND s.elo_in_pool = 1)
                      )
                )
                SELECT
                    r.username,
                    r.user_best_score AS best_score,
                    r.user_submission_count AS submission_count,
                    r.user_first_submitted_at AS first_submitted_at,
                    r.base_model AS best_base_model,
                    r.agent_endpoint_id AS best_agent_endpoint_id,
                    COALESCE(r.agent_endpoint_harness, ep.harness) AS best_agent_endpoint_harness,
                    COALESCE(r.agent_endpoint_model, ep.model) AS best_agent_endpoint_model
                FROM ranked r
                LEFT JOIN ranking_agent_judge_endpoints ep
                  ON ep.id = r.agent_endpoint_id AND ep.pool_kind = 'primary'
                WHERE r.rn = 1
                ORDER BY user_best_score DESC, user_first_submitted_at ASC, username ASC
                """,
                (competition_id,),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()

    # 并列排名：分数相同的用户排名一致
    leaderboard = []
    prev_score = None
    rank = 0
    for idx, row in enumerate(rows, start=1):
        score = row.get('best_score')
        if prev_score is None or (score is not None and float(score) != float(prev_score)):
            rank = idx
            prev_score = score
        leaderboard.append({
            'rank': rank,
            'username': row.get('username') or '',
            'best_score': float(score) if score is not None else None,
            'submission_count': int(row.get('submission_count') or 0),
            'first_submitted_at': row.get('first_submitted_at'),
            'best_base_model': row.get('best_base_model'),
            'best_agent_endpoint_id': row.get('best_agent_endpoint_id'),
            'best_agent_endpoint_harness': row.get('best_agent_endpoint_harness'),
            'best_agent_endpoint_model': row.get('best_agent_endpoint_model'),
            'best_agent_endpoint_label': _agent_endpoint_label(
                row.get('best_agent_endpoint_harness'),
                row.get('best_agent_endpoint_model'),
            ),
        })
    return leaderboard


# ---------- File path helpers ----------

def competition_dir(competition_id):
    return os.path.join(RANKING_UPLOAD_ROOT, 'competitions', str(competition_id))


def competition_attachments_dir(competition_id):
    return os.path.join(competition_dir(competition_id), ATTACHMENT_SUBDIR)


def competition_reference_dir(competition_id):
    return os.path.join(competition_dir(competition_id), REFERENCE_SUBDIR)


def competition_scoring_dir(competition_id):
    return os.path.join(competition_dir(competition_id), SCORING_SUBDIR)


def submission_dir(submission_id):
    return os.path.join(RANKING_UPLOAD_ROOT, SUBMISSION_SUBDIR, str(submission_id))


# ---------- ELO Mode ----------

def _retire_excess_user_submissions_with_cursor(
        cursor, competition_id, username, keep_count):
    cursor.execute(
        """
        SELECT id FROM ranking_submissions
        WHERE competition_id = %s AND username = %s AND elo_in_pool = 1
        ORDER BY created_at DESC, id DESC
        """,
        (competition_id, username),
    )
    rows = cursor.fetchall() or []
    ids = [int(row['id']) for row in rows]
    keep = set(ids[:max(0, int(keep_count))])
    retire = [submission_id for submission_id in ids if submission_id not in keep]
    if retire:
        placeholders = ','.join(['%s'] * len(retire))
        cursor.execute(
            f"UPDATE ranking_submissions"
            f" SET elo_in_pool = 0, status = 'Retired'"
            f" WHERE id IN ({placeholders})",
            tuple(retire),
        )
    return retire


def activate_elo_submission(submission_id, competition_id, username, rating, *, keep_count=2):
    """原子激活 ELO 提交并退役同用户超出保留数的旧提交。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 与打榜提交配额使用同一稳定用户行，串行化同用户的并发 ELO 激活。
            cursor.execute(
                "SELECT id FROM users WHERE username = %s FOR UPDATE",
                (username,),
            )
            if not cursor.fetchone():
                raise LookupError('ELO 提交用户不存在')
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET elo_rating = %s, score = %s,
                    elo_match_count = 0, elo_in_pool = 1,
                    status = 'Active'
                WHERE id = %s AND competition_id = %s AND username = %s
                """,
                (
                    float(rating), float(rating), int(submission_id),
                    int(competition_id), username,
                ),
            )
            if int(cursor.rowcount or 0) != 1:
                raise LookupError('ELO 提交不存在或归属不匹配')
            retired = _retire_excess_user_submissions_with_cursor(
                cursor,
                int(competition_id),
                username,
                keep_count,
            )
        conn.commit()
        return retired
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def set_elo_running(competition_id, running):
    """切换赛事的 ELO 运行开关。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE ranking_competitions SET elo_running = %s WHERE id = %s",
                (1 if running else 0, int(competition_id)),
            )
        conn.commit()
    finally:
        conn.close()


def reset_elo_state(competition_id):
    """重置赛事的 ELO 状态：
      - 把 elo_running 置 0；
      - 删除该赛事所有对战历史 ranking_elo_matches；
      - 把该赛事所有"在池中（elo_in_pool=1）"的提交分数 / 对战次数恢复到初始分。
    返回 (matches_deleted, submissions_reset)。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT elo_initial_rating FROM ranking_competitions WHERE id = %s",
                (int(competition_id),),
            )
            row = cursor.fetchone()
            if not row:
                return (0, 0)
            initial_rating = float(row.get('elo_initial_rating') or 1500)

            cursor.execute(
                "UPDATE ranking_competitions SET elo_running = 0 WHERE id = %s",
                (int(competition_id),),
            )
            cursor.execute(
                "DELETE FROM ranking_elo_matches WHERE competition_id = %s",
                (int(competition_id),),
            )
            matches_deleted = cursor.rowcount or 0
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET elo_rating = %s, score = %s, elo_match_count = 0
                WHERE competition_id = %s AND elo_in_pool = 1
                """,
                (initial_rating, initial_rating, int(competition_id)),
            )
            submissions_reset = cursor.rowcount or 0
        conn.commit()
        return (matches_deleted, submissions_reset)
    finally:
        conn.close()


def list_active_elo_competitions():
    """所有启用了 ELO 模式、已被管理员手动启动、且配置了评测脚本的赛事。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, scoring_mode, is_active, elo_running,
                       scoring_script_path, scoring_script_timeout_seconds,
                       elo_initial_rating, elo_k_factor, elo_max_matches,
                       elo_match_interval_seconds, elo_initial_burst,
                       elo_max_pairs_per_round
                FROM ranking_competitions
                WHERE scoring_mode = 'elo' AND is_active = 1 AND elo_running = 1
                  AND scoring_script_path IS NOT NULL AND scoring_script_path <> ''
                """
            )
            return cursor.fetchall() or []
    finally:
        conn.close()


def list_eligible_elo_submissions(competition_id, max_matches):
    """池中、Active、且对战次数还没满的提交。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, elo_rating, elo_match_count, code_path
                FROM ranking_submissions
                WHERE competition_id = %s AND elo_in_pool = 1
                  AND status = 'Active' AND elo_rating IS NOT NULL
                  AND elo_match_count < %s
                """,
                (int(competition_id), int(max_matches)),
            )
            return cursor.fetchall() or []
    finally:
        conn.close()


def get_last_elo_match_time(competition_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT MAX(created_at) AS last_at FROM ranking_elo_matches WHERE competition_id = %s",
                (int(competition_id),),
            )
            row = cursor.fetchone()
            return (row or {}).get('last_at')
    finally:
        conn.close()


def record_elo_match(competition_id, sub_a_id, sub_b_id, winner,
                     rating_a_before, rating_b_before,
                     rating_a_after, rating_b_after,
                     details=None, error_message=None):
    """记录一场 ELO 对战，并在 winner ∈ {0,1,2} 时更新两份提交的分数与对战次数。
    winner 取值：1=A 胜，2=B 胜，0=平局（双方按 ELO 公式各取 s=0.5 调整），
    -1=评测脚本失败的占位行（分数与计数不变）。
    调用方应持有按 competition_id 划分的并发锁。"""
    details_text = None
    if details is not None:
        if isinstance(details, str):
            details_text = details
        else:
            try:
                details_text = json.dumps(details, ensure_ascii=False)
            except Exception:
                details_text = str(details)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ranking_elo_matches
                  (competition_id, submission_a_id, submission_b_id, winner,
                   rating_a_before, rating_b_before, rating_a_after, rating_b_after,
                   details, error_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (int(competition_id), int(sub_a_id), int(sub_b_id), int(winner),
                 float(rating_a_before), float(rating_b_before),
                 float(rating_a_after), float(rating_b_after),
                 details_text, error_message),
            )
            if int(winner) in (0, 1, 2):
                cursor.execute(
                    "UPDATE ranking_submissions"
                    " SET elo_rating = %s, score = %s, elo_match_count = elo_match_count + 1"
                    " WHERE id = %s",
                    (float(rating_a_after), float(rating_a_after), int(sub_a_id)),
                )
                cursor.execute(
                    "UPDATE ranking_submissions"
                    " SET elo_rating = %s, score = %s, elo_match_count = elo_match_count + 1"
                    " WHERE id = %s",
                    (float(rating_b_after), float(rating_b_after), int(sub_b_id)),
                )
        conn.commit()
    finally:
        conn.close()


def record_elo_match_locked(competition_id, sub_a_id, sub_b_id, winner,
                            initial_rating, compute_new_ratings,
                            details=None, error_message=None):
    """原子地记录一场 ELO 对战：在单个事务里对两条提交行加 FOR UPDATE 行锁、重读最新 elo_rating，
    调用 compute_new_ratings(rating_a, rating_b) -> (new_a, new_b) 算分后写回并插入历史。

    这样即便不依赖 Redis 写锁，并发对战也不会读到同一旧分而互相覆盖（丢更新）。两行按 id 升序加锁，
    避免与反向对战死锁。compute_new_ratings 由调用方提供，保持 ELO 公式单一实现。
    返回 (rating_a_before, rating_b_before, rating_a_after, rating_b_after)。"""
    details_text = None
    if details is not None:
        if isinstance(details, str):
            details_text = details
        else:
            try:
                details_text = json.dumps(details, ensure_ascii=False)
            except Exception:
                details_text = str(details)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            lo, hi = sorted((int(sub_a_id), int(sub_b_id)))
            cursor.execute(
                "SELECT id, elo_rating FROM ranking_submissions"
                " WHERE id IN (%s, %s) ORDER BY id FOR UPDATE",
                (lo, hi),
            )
            rows = {int(r['id']): r for r in cursor.fetchall()}

            def _rating(sid):
                r = rows.get(int(sid))
                v = r.get('elo_rating') if r else None
                return float(v) if v is not None else float(initial_rating)

            rating_a = _rating(sub_a_id)
            rating_b = _rating(sub_b_id)
            new_a, new_b = compute_new_ratings(rating_a, rating_b)
            new_a = float(new_a)
            new_b = float(new_b)

            cursor.execute(
                """
                INSERT INTO ranking_elo_matches
                  (competition_id, submission_a_id, submission_b_id, winner,
                   rating_a_before, rating_b_before, rating_a_after, rating_b_after,
                   details, error_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (int(competition_id), int(sub_a_id), int(sub_b_id), int(winner),
                 rating_a, rating_b, new_a, new_b, details_text, error_message),
            )
            if int(winner) in (0, 1, 2):
                cursor.execute(
                    "UPDATE ranking_submissions"
                    " SET elo_rating = %s, score = %s, elo_match_count = elo_match_count + 1"
                    " WHERE id = %s",
                    (new_a, new_a, int(sub_a_id)),
                )
                cursor.execute(
                    "UPDATE ranking_submissions"
                    " SET elo_rating = %s, score = %s, elo_match_count = elo_match_count + 1"
                    " WHERE id = %s",
                    (new_b, new_b, int(sub_b_id)),
                )
        conn.commit()
        return rating_a, rating_b, new_a, new_b
    finally:
        conn.close()


def list_competition_matches(competition_id, *, page=1, per_page=20, username=None):
    """分页拉某场赛事的对战记录，并 JOIN 出双方用户名，省掉前端再查表。
    若提供 username，只返回该用户参与的对战（任一方）。
    返回 (rows, page, total)。created_at DESC 排序，新对战在前。
    rows 不带 details / error_message —— 这两个走单条详情接口取，以免列表查询拽着大文本。"""
    page = max(1, int(page or 1))
    per_page = max(1, int(per_page or 20))
    user_filter_sql = ""
    extra_params = ()
    if username:
        user_filter_sql = " AND (sa.username = %s OR sb.username = %s)"
        extra_params = (str(username), str(username))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # COUNT(*) 与 SELECT 用同样的 JOIN + 过滤，确保 total 与列表一致
            cursor.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM ranking_elo_matches m
                LEFT JOIN ranking_submissions sa ON sa.id = m.submission_a_id
                LEFT JOIN ranking_submissions sb ON sb.id = m.submission_b_id
                WHERE m.competition_id = %s{user_filter_sql}
                """,
                (int(competition_id),) + extra_params,
            )
            total = int((cursor.fetchone() or {}).get('total') or 0)
            total_pages = max(1, (total + per_page - 1) // per_page)
            if page > total_pages:
                page = total_pages
            offset = (page - 1) * per_page
            cursor.execute(
                f"""
                SELECT m.id, m.submission_a_id, m.submission_b_id, m.winner,
                       m.rating_a_before, m.rating_a_after,
                       m.rating_b_before, m.rating_b_after,
                       m.created_at,
                       sa.username AS username_a,
                       sb.username AS username_b
                FROM ranking_elo_matches m
                LEFT JOIN ranking_submissions sa ON sa.id = m.submission_a_id
                LEFT JOIN ranking_submissions sb ON sb.id = m.submission_b_id
                WHERE m.competition_id = %s{user_filter_sql}
                ORDER BY m.created_at DESC, m.id DESC
                LIMIT %s OFFSET %s
                """,
                (int(competition_id),) + extra_params + (int(per_page), int(offset)),
            )
            rows = cursor.fetchall() or []
            return rows, page, total
    finally:
        conn.close()


def get_competition_match(match_id, competition_id):
    """单场对战详情（含 details / error_message + 双方用户名）。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT m.id, m.competition_id, m.submission_a_id, m.submission_b_id, m.winner,
                       m.rating_a_before, m.rating_a_after,
                       m.rating_b_before, m.rating_b_after,
                       m.details, m.error_message, m.created_at,
                       sa.username AS username_a,
                       sb.username AS username_b
                FROM ranking_elo_matches m
                LEFT JOIN ranking_submissions sa ON sa.id = m.submission_a_id
                LEFT JOIN ranking_submissions sb ON sb.id = m.submission_b_id
                WHERE m.id = %s AND m.competition_id = %s
                """,
                (int(match_id), int(competition_id)),
            )
            return cursor.fetchone()
    finally:
        conn.close()


def list_elo_matches_for_submission(submission_id, limit=20):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, submission_a_id, submission_b_id, winner,
                       rating_a_before, rating_b_before, rating_a_after, rating_b_after,
                       details, error_message, created_at
                FROM ranking_elo_matches
                WHERE submission_a_id = %s OR submission_b_id = %s
                ORDER BY created_at DESC, id DESC
                LIMIT %s
                """,
                (int(submission_id), int(submission_id), int(limit)),
            )
            return cursor.fetchall() or []
    finally:
        conn.close()


def rebuild_elo_history(competition_id):
    """重放该赛事现存的所有 ranking_elo_matches，按 (created_at ASC, id ASC) 顺序
    重新计算每场的 rating_a_before / after / rating_b_before / after，并把每份
    提交的当前 elo_rating / score / elo_match_count 同步到重放结束后的值。

    与 reset_elo_state 的区别：
      - reset_elo_state 删行 + 清零；
      - 这里保留对战行，只是按现存 winner 走一遍 ELO 公式，修正因 delete_elo_match_
        and_revert 导致的"历史 rating 快照漂移"。

    返回 dict：matches_replayed / submissions_updated / k_factor / initial_rating。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT elo_initial_rating, elo_k_factor FROM ranking_competitions WHERE id = %s",
                (int(competition_id),),
            )
            comp = cursor.fetchone()
            if not comp:
                return None
            initial_rating = float(comp.get('elo_initial_rating') or 1500)
            k_factor = float(comp.get('elo_k_factor') or 32)

            # 1. 把所有曾经被 ELO 初始化过的提交先重置到初始分（match_count=0）。
            #    elo_in_pool / status 不动；已退役的提交也参与重放，因为它们的对战
            #    历史依然在表里。
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET elo_rating = %s, score = %s, elo_match_count = 0
                WHERE competition_id = %s AND elo_rating IS NOT NULL
                """,
                (initial_rating, initial_rating, int(competition_id)),
            )

            # 2. 按时间顺序拉所有对战行。
            cursor.execute(
                """
                SELECT id, submission_a_id, submission_b_id, winner
                FROM ranking_elo_matches
                WHERE competition_id = %s
                ORDER BY created_at ASC, id ASC
                """,
                (int(competition_id),),
            )
            matches = cursor.fetchall() or []

            # 3. 在内存里维护"当前 rating"和"match_count"，逐场重放并回写每场快照。
            current = {}
            counts = {}
            for m in matches:
                a = int(m['submission_a_id'])
                b = int(m['submission_b_id'])
                # 注意：winner 可能合法地是 0（平局），不能用 `m.get('winner') or 0`
                # 兜底，否则 None 会和 0 混淆。这里显式判 None。
                raw_w = m.get('winner')
                winner = int(raw_w) if raw_w is not None else -1
                r_a = current.get(a, initial_rating)
                r_b = current.get(b, initial_rating)
                if winner in (0, 1, 2):
                    e_a = 1.0 / (1.0 + 10.0 ** ((r_b - r_a) / 400.0))
                    if winner == 1:
                        s_a = 1.0
                    elif winner == 2:
                        s_a = 0.0
                    else:
                        s_a = 0.5
                    new_a = r_a + k_factor * (s_a - e_a)
                    new_b = r_b + k_factor * ((1.0 - s_a) - (1.0 - e_a))
                    current[a] = new_a
                    current[b] = new_b
                    counts[a] = counts.get(a, 0) + 1
                    counts[b] = counts.get(b, 0) + 1
                else:
                    # 评测失败 (winner=-1)：分数不变，但仍重写快照让 before == after。
                    new_a = r_a
                    new_b = r_b
                cursor.execute(
                    """
                    UPDATE ranking_elo_matches
                    SET rating_a_before = %s, rating_a_after = %s,
                        rating_b_before = %s, rating_b_after = %s
                    WHERE id = %s
                    """,
                    (float(r_a), float(new_a), float(r_b), float(new_b), int(m['id'])),
                )

            # 4. 把重放终态写回 ranking_submissions（只更新有变化的提交，避免无谓更新）。
            for sub_id, rating in current.items():
                cursor.execute(
                    """
                    UPDATE ranking_submissions
                    SET elo_rating = %s, score = %s, elo_match_count = %s
                    WHERE id = %s
                    """,
                    (float(rating), float(rating), int(counts.get(sub_id, 0)), int(sub_id)),
                )
        conn.commit()
        return {
            'matches_replayed': len(matches),
            'submissions_updated': len(current),
            'k_factor': k_factor,
            'initial_rating': initial_rating,
        }
    finally:
        conn.close()


def delete_elo_match_and_revert(match_id, competition_id):
    """管理员删除一场 ELO 对战，同时把它对两份提交分数和对战次数的影响**从当前值里**撤销。

    撤销规则：
      - 若 winner ∈ {0, 1, 2}（正常结算的对战，含平局）：
            delta_a = rating_a_after - rating_a_before
            delta_b = rating_b_after - rating_b_before
            elo_rating_A := elo_rating_A - delta_a；score 跟随；elo_match_count -= 1。
            B 同理。平局时 delta_a / delta_b 可能很小但仍需撤销。
      - 若 winner == -1（评测脚本失败的对战，分数本就没动）：仅删行，不动分数 / 计数。

    全部在一个事务里完成。返回一个 dict 描述本次撤销的内容，便于路由给管理员展示
    （或者 None 表示没有这条记录）。

    设计取舍：用户的语义是"在当前排行榜分数基础上 -delta"，因此我们故意 **不**
    重放后续对战来"重写历史"——只是简单地把这一场带来的变化从当前数字里减去。
    若后续对战引用了某方的中间 rating（作为 rating_before），那些记录里的快照依然
    保留，但之后再删它们时也是同样的"从当前减 delta"逻辑——多个删除按顺序应用是
    可交换的（加减法）。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, submission_a_id, submission_b_id, winner,
                       rating_a_before, rating_a_after, rating_b_before, rating_b_after
                FROM ranking_elo_matches
                WHERE id = %s AND competition_id = %s
                FOR UPDATE
                """,
                (int(match_id), int(competition_id)),
            )
            row = cursor.fetchone()
            if not row:
                conn.commit()
                return None

            raw_w = row.get('winner')
            winner = int(raw_w) if raw_w is not None else -1
            sub_a_id = int(row.get('submission_a_id') or 0)
            sub_b_id = int(row.get('submission_b_id') or 0)
            delta_a = 0.0
            delta_b = 0.0
            if winner in (0, 1, 2):
                delta_a = float(row.get('rating_a_after') or 0) - float(row.get('rating_a_before') or 0)
                delta_b = float(row.get('rating_b_after') or 0) - float(row.get('rating_b_before') or 0)
                # 撤销 A：分数 -= delta_a，对战次数 -= 1（不低于 0），score 同步 elo_rating
                cursor.execute(
                    """
                    UPDATE ranking_submissions
                    SET score = elo_rating - %s,
                        elo_rating = elo_rating - %s,
                        elo_match_count = GREATEST(elo_match_count - 1, 0)
                    WHERE id = %s
                    """,
                    (delta_a, delta_a, sub_a_id),
                )
                cursor.execute(
                    """
                    UPDATE ranking_submissions
                    SET score = elo_rating - %s,
                        elo_rating = elo_rating - %s,
                        elo_match_count = GREATEST(elo_match_count - 1, 0)
                    WHERE id = %s
                    """,
                    (delta_b, delta_b, sub_b_id),
                )
            cursor.execute(
                "DELETE FROM ranking_elo_matches WHERE id = %s AND competition_id = %s",
                (int(match_id), int(competition_id)),
            )
        conn.commit()
        return {
            'match_id': int(match_id),
            'competition_id': int(competition_id),
            'winner': winner,
            'submission_a_id': sub_a_id,
            'submission_b_id': sub_b_id,
            'delta_a': delta_a,
            'delta_b': delta_b,
        }
    finally:
        conn.close()


# ---------- 申诉（Appeals） ----------

def create_appeal(competition_id, submission_id, username, reason):
    """学生发起一条评分申诉。硬性一次：一份提交只能申诉一次。
    若该提交已存在申诉记录（任何状态）→ 不覆盖、不重开，返回 0；否则插入并返回新行 id。
    UNIQUE(submission_id) + INSERT IGNORE 保证并发下也只会有一条。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT IGNORE INTO ranking_appeals
                    (competition_id, submission_id, username, reason, status)
                VALUES (%s, %s, %s, %s, 'pending')
                """,
                (int(competition_id), int(submission_id), username, reason),
            )
            new_id = cursor.lastrowid if cursor.rowcount == 1 else 0
        conn.commit()
        return int(new_id or 0)
    finally:
        conn.close()


def get_appeal(appeal_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM ranking_appeals WHERE id = %s", (int(appeal_id),))
            return cursor.fetchone()
    finally:
        conn.close()


def get_appeal_by_submission(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM ranking_appeals WHERE submission_id = %s",
                           (int(submission_id),))
            return cursor.fetchone()
    finally:
        conn.close()


def list_appeals(competition_id, *, page=1, per_page=50, status_q=None, username_q=None):
    """分页列出某比赛的申诉，LEFT JOIN 提交以带出 score/状态/基座模型供卡片展示。
    返回 (rows, page, total)。"""
    page = max(1, int(page or 1))
    per_page = max(1, int(per_page or 50))
    where = ["a.competition_id = %s"]
    params = [int(competition_id)]
    if status_q in ('pending', 'rejected', 'resolved'):
        where.append("a.status = %s")
        params.append(status_q)
    if username_q:
        where.append("a.username LIKE %s")
        params.append('%' + str(username_q) + '%')
    where_sql = " AND ".join(where)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) AS c FROM ranking_appeals a WHERE {where_sql}", params)
            total = int((cursor.fetchone() or {}).get('c') or 0)
            total_pages = max(1, (total + per_page - 1) // per_page)
            if page > total_pages:
                page = total_pages
            offset = (page - 1) * per_page
            cursor.execute(
                f"""
                SELECT a.id, a.competition_id, a.submission_id, a.username, a.reason,
                       a.status, a.admin_response, a.admin_username,
                       a.created_at, a.updated_at,
                       rs.score AS sub_score, rs.status AS sub_status, rs.base_model
                FROM ranking_appeals a
                LEFT JOIN ranking_submissions rs ON rs.id = a.submission_id
                WHERE {where_sql}
                ORDER BY a.created_at DESC, a.id DESC
                LIMIT %s OFFSET %s
                """,
                params + [per_page, offset],
            )
            rows = cursor.fetchall() or []
        return rows, page, total
    finally:
        conn.close()


def get_appeal_stats(competition_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'pending'  THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
                    SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved
                FROM ranking_appeals
                WHERE competition_id = %s
                """,
                (int(competition_id),),
            )
            row = cursor.fetchone() or {}
            return {
                'total': int(row.get('total') or 0),
                'pending': int(row.get('pending') or 0),
                'rejected': int(row.get('rejected') or 0),
                'resolved': int(row.get('resolved') or 0),
            }
    finally:
        conn.close()


def resolve_appeal(appeal_id, status, admin_response, admin_username):
    """管理员处理（'resolved'）或驳回（'rejected'）申诉，写入回复与处理人。"""
    status = 'resolved' if str(status).strip().lower() == 'resolved' else 'rejected'
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE ranking_appeals SET status=%s, admin_response=%s, admin_username=%s"
                " WHERE id=%s",
                (status, (admin_response or ''), admin_username, int(appeal_id)),
            )
        conn.commit()
    finally:
        conn.close()
