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
import shutil
import uuid
from datetime import datetime, timedelta

from oj_modules.db_services import bump_daily_submission_count, get_db_connection
from oj_modules.ranking_agent_judge import normalize_orchestration_mode


_ranking_tables_ready = False

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
    if _ranking_tables_ready:
        return

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ranking_competitions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    summary VARCHAR(500) DEFAULT NULL,
                    description MEDIUMTEXT,
                    answer_format VARCHAR(8) NOT NULL DEFAULT 'json',
                    reference_answer_path VARCHAR(512) DEFAULT NULL,
                    reference_answer_name VARCHAR(255) DEFAULT NULL,
                    scoring_script_path VARCHAR(512) DEFAULT NULL,
                    scoring_script_name VARCHAR(255) DEFAULT NULL,
                    max_score INT NOT NULL DEFAULT 100,
                    is_active TINYINT(1) NOT NULL DEFAULT 1,
                    created_by VARCHAR(50) DEFAULT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_rc_active_created (is_active, created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            # 兼容：为已存在的老表补加 summary 列
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'summary'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions ADD COLUMN summary VARCHAR(500) DEFAULT NULL AFTER title"
                )
            # 兼容：为已存在的老表补加 answer_format 列
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'answer_format'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions ADD COLUMN answer_format VARCHAR(8) NOT NULL DEFAULT 'json' AFTER description"
                )
            # 兼容：为已存在的老表补加 ELO 模式相关列
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'scoring_mode'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions"
                    " ADD COLUMN scoring_mode VARCHAR(16) NOT NULL DEFAULT 'absolute' AFTER answer_format,"
                    " ADD COLUMN elo_initial_rating DOUBLE NOT NULL DEFAULT 1500,"
                    " ADD COLUMN elo_k_factor DOUBLE NOT NULL DEFAULT 32,"
                    " ADD COLUMN elo_max_matches INT NOT NULL DEFAULT 200,"
                    " ADD COLUMN elo_match_interval_seconds INT NOT NULL DEFAULT 60,"
                    " ADD COLUMN elo_initial_burst INT NOT NULL DEFAULT 5"
                )
            # 兼容：为已存在的老表补加评测脚本超时列
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'scoring_script_timeout_seconds'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions"
                    " ADD COLUMN scoring_script_timeout_seconds INT NOT NULL DEFAULT 120"
                )
            # 兼容：为已存在的老表补加 ELO 运行开关（管理员手动启动 / 停止 / 重置）
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'elo_running'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions"
                    " ADD COLUMN elo_running TINYINT(1) NOT NULL DEFAULT 0"
                )
            # 兼容：为已存在的老表补加每个匹配间隔可调度的对子数
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'elo_max_pairs_per_round'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions"
                    " ADD COLUMN elo_max_pairs_per_round INT NOT NULL DEFAULT 1"
                )
            # 兼容：为已存在的老表补加 Agent 评测模式相关列
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'agent_judge_base_url'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions"
                    " ADD COLUMN agent_judge_base_url VARCHAR(512) DEFAULT NULL,"
                    " ADD COLUMN agent_judge_api_key VARCHAR(512) DEFAULT NULL,"
                    " ADD COLUMN agent_judge_model VARCHAR(128) DEFAULT NULL,"
                    " ADD COLUMN agent_judge_timeout_seconds INT NOT NULL DEFAULT 1800"
                )
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'agent_judge_orchestration_mode'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions"
                    " ADD COLUMN agent_judge_orchestration_mode VARCHAR(16) NOT NULL DEFAULT 'single'"
                )
            # 兼容：每 48 小时窗口提交次数限制（NULL/<=0 表示不限制）+ 窗口锚点
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'submit_limit_per_window'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions"
                    " ADD COLUMN submit_limit_per_window INT DEFAULT NULL,"
                    " ADD COLUMN limit_window_start DATETIME DEFAULT NULL"
                )
            # 兼容：Agent 评测打榜赛的提交方式（zip 上传 / git 拉取）+ git 仓库命名模板
            cursor.execute("SHOW COLUMNS FROM ranking_competitions LIKE 'submission_method'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_competitions"
                    " ADD COLUMN submission_method VARCHAR(8) NOT NULL DEFAULT 'zip',"
                    " ADD COLUMN git_format VARCHAR(512) DEFAULT NULL"
                )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ranking_competition_files (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    competition_id INT NOT NULL,
                    filename VARCHAR(255) NOT NULL,
                    stored_path VARCHAR(512) NOT NULL,
                    file_size BIGINT NOT NULL DEFAULT 0,
                    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_rcf_comp (competition_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ranking_submissions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    competition_id INT NOT NULL,
                    username VARCHAR(50) NOT NULL,
                    answer_filename VARCHAR(255) DEFAULT NULL,
                    answer_path VARCHAR(512) DEFAULT NULL,
                    code_filename VARCHAR(255) DEFAULT NULL,
                    code_path VARCHAR(512) DEFAULT NULL,
                    base_model VARCHAR(500) DEFAULT NULL,
                    score DOUBLE DEFAULT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'Judging',
                    judge_attempt_id VARCHAR(36) DEFAULT NULL,
                    judge_task_id VARCHAR(64) DEFAULT NULL,
                    judge_heartbeat_at TIMESTAMP NULL DEFAULT NULL,
                    grade_details MEDIUMTEXT,
                    error_message TEXT,
                    elo_rating DOUBLE DEFAULT NULL,
                    elo_match_count INT NOT NULL DEFAULT 0,
                    elo_in_pool TINYINT(1) NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_rs_comp_user (competition_id, username),
                    INDEX idx_rs_comp_score (competition_id, score),
                    INDEX idx_rs_comp_created (competition_id, created_at),
                    INDEX idx_rs_judge_attempt (judge_attempt_id),
                    INDEX idx_rs_judge_task (judge_task_id),
                    INDEX idx_rs_elo_pool (competition_id, elo_in_pool)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            # 兼容：为已存在的老表补加 ELO 列
            cursor.execute("SHOW COLUMNS FROM ranking_submissions LIKE 'elo_rating'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_submissions"
                    " ADD COLUMN elo_rating DOUBLE DEFAULT NULL,"
                    " ADD COLUMN elo_match_count INT NOT NULL DEFAULT 0,"
                    " ADD COLUMN elo_in_pool TINYINT(1) NOT NULL DEFAULT 0,"
                    " ADD INDEX idx_rs_elo_pool (competition_id, elo_in_pool)"
                )
            # 兼容：为已存在的老表补加 base_model 列
            cursor.execute("SHOW COLUMNS FROM ranking_submissions LIKE 'base_model'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_submissions"
                    " ADD COLUMN base_model VARCHAR(500) DEFAULT NULL AFTER code_path"
                )
            # 兼容：补加 source 列，区分提交来源（'self'=学生自交、'batch'=管理员批量拉取）。
            # 默认 'self'：历史行与学生自交都按 self 计入配额；只有批量创建标 'batch' 不计配额。
            cursor.execute("SHOW COLUMNS FROM ranking_submissions LIKE 'source'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_submissions"
                    " ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'self'"
                )
            cursor.execute("SHOW COLUMNS FROM ranking_submissions LIKE 'judge_attempt_id'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_submissions"
                    " ADD COLUMN judge_attempt_id VARCHAR(36) DEFAULT NULL AFTER status"
                )
            cursor.execute("SHOW COLUMNS FROM ranking_submissions LIKE 'judge_task_id'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_submissions"
                    " ADD COLUMN judge_task_id VARCHAR(64) DEFAULT NULL AFTER judge_attempt_id"
                )
            cursor.execute("SHOW COLUMNS FROM ranking_submissions LIKE 'judge_heartbeat_at'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_submissions"
                    " ADD COLUMN judge_heartbeat_at TIMESTAMP NULL DEFAULT NULL AFTER judge_task_id"
                )
            cursor.execute(
                "SHOW INDEX FROM ranking_submissions WHERE Key_name = 'idx_rs_judge_attempt'"
            )
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_submissions ADD INDEX idx_rs_judge_attempt (judge_attempt_id)"
                )
            cursor.execute(
                "SHOW INDEX FROM ranking_submissions WHERE Key_name = 'idx_rs_judge_task'"
            )
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE ranking_submissions ADD INDEX idx_rs_judge_task (judge_task_id)"
                )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ranking_elo_matches (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    competition_id INT NOT NULL,
                    submission_a_id INT NOT NULL,
                    submission_b_id INT NOT NULL,
                    winner SMALLINT NOT NULL,
                    rating_a_before DOUBLE NOT NULL,
                    rating_b_before DOUBLE NOT NULL,
                    rating_a_after DOUBLE NOT NULL,
                    rating_b_after DOUBLE NOT NULL,
                    details MEDIUMTEXT,
                    error_message TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_rem_comp_created (competition_id, created_at),
                    INDEX idx_rem_sub_a (submission_a_id),
                    INDEX idx_rem_sub_b (submission_b_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            # 一次性迁移：早期版本用 winner=0 表示"评测脚本失败"，新版本里 0 改为
            # "平局"，-1 才表示失败。把现存带 error_message 的 winner=0 行搬到 -1，
            # 避免老数据被新逻辑当成平局误处理。
            cursor.execute(
                "UPDATE ranking_elo_matches SET winner = -1"
                " WHERE winner = 0 AND error_message IS NOT NULL"
            )
            # 申诉表：学生对某条提交的评分申诉；管理员在「申诉处理」标签里审阅、回复、驳回/处理。
            # UNIQUE(submission_id)：一条提交一条申诉记录，重复申诉用 upsert 重开为 pending。
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ranking_appeals (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    competition_id INT NOT NULL,
                    submission_id INT NOT NULL,
                    username VARCHAR(50) NOT NULL,
                    reason TEXT NOT NULL,
                    status VARCHAR(16) NOT NULL DEFAULT 'pending',
                    admin_response MEDIUMTEXT,
                    admin_username VARCHAR(50),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                                          ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_ra_sub (submission_id),
                    INDEX idx_ra_comp_status (competition_id, status),
                    INDEX idx_ra_comp_created (competition_id, created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
        conn.commit()
        _ranking_tables_ready = True
    finally:
        conn.close()


# ---------- Competitions ----------

def list_competitions(include_inactive=False):
    ensure_ranking_tables()
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
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, summary, description, answer_format,
                       scoring_mode, elo_initial_rating, elo_k_factor,
                       elo_max_matches, elo_match_interval_seconds, elo_initial_burst,
                       elo_max_pairs_per_round, elo_running,
                       scoring_script_timeout_seconds,
                       agent_judge_base_url, agent_judge_api_key,
                       agent_judge_model, agent_judge_timeout_seconds,
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


def create_competition(title, description, max_score, created_by, summary=None):
    ensure_ranking_tables()
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
    ensure_ranking_tables()
    conn = get_db_connection()
    created_comp_dir = None
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM ranking_competitions WHERE id = %s", (int(src_id),))
            comp = cursor.fetchone()
            if not comp:
                raise ValueError(f'源比赛 {src_id} 不存在')
            cursor.execute("SHOW COLUMNS FROM ranking_judge_rules LIKE 'rule_name'")
            has_rule_name = bool(cursor.fetchone())
            rule_name_select = "rule_name, " if has_rule_name else "'' AS rule_name, "
            cursor.execute(
                "SELECT rule_id, " + rule_name_select + "rule_text, value, dependencies, ordering "
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
            cursor.execute("SHOW TABLES LIKE 'ranking_agent_judge_endpoints'")
            has_endpoint_table = bool(cursor.fetchone())
            endpoints = []
            if has_endpoint_table:
                cursor.execute("SHOW COLUMNS FROM ranking_agent_judge_endpoints LIKE 'status'")
                if not cursor.fetchone():
                    cursor.execute(
                        "ALTER TABLE ranking_agent_judge_endpoints"
                        " ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'enabled' AFTER enabled"
                    )
                    cursor.execute(
                        "UPDATE ranking_agent_judge_endpoints"
                        " SET status = CASE WHEN enabled = 1 THEN 'enabled' ELSE 'disabled' END"
                    )
                cursor.execute(
                    "SELECT harness, base_url, api_key, model, concurrency_limit, enabled, status, ordering "
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
                    "(competition_id, harness, base_url, api_key, model, concurrency_limit, enabled, status, ordering) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (new_id, e.get('harness') or 'claude_code', e['base_url'], e['api_key'], e['model'],
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
                        scoring_script_timeout_seconds=None,
                        agent_judge_base_url=None, agent_judge_api_key=None,
                        agent_judge_model=None, agent_judge_timeout_seconds=None,
                        agent_judge_orchestration_mode=None,
                        submit_limit_per_window=None, set_limit_window_now=False,
                        submission_method=None, git_format=None):
    ensure_ranking_tables()
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
        if mode not in ('absolute', 'elo', 'agent_judge'):
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
    if scoring_script_timeout_seconds is not None:
        fields.append("scoring_script_timeout_seconds = %s")
        params.append(int(scoring_script_timeout_seconds))
    if agent_judge_base_url is not None:
        fields.append("agent_judge_base_url = %s")
        params.append((str(agent_judge_base_url).strip() or None))
    if agent_judge_api_key is not None:
        fields.append("agent_judge_api_key = %s")
        params.append((str(agent_judge_api_key).strip() or None))
    if agent_judge_model is not None:
        fields.append("agent_judge_model = %s")
        params.append((str(agent_judge_model).strip() or None))
    if agent_judge_timeout_seconds is not None:
        fields.append("agent_judge_timeout_seconds = %s")
        params.append(int(agent_judge_timeout_seconds))
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_submissions WHERE competition_id = %s", (competition_id,))
            cursor.execute("DELETE FROM ranking_competition_files WHERE competition_id = %s", (competition_id,))
            cursor.execute("DELETE FROM ranking_competitions WHERE id = %s", (competition_id,))
        conn.commit()
    finally:
        conn.close()


# ---------- Attachments ----------

def list_competition_files(competition_id):
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_competition_files WHERE id = %s", (file_id,))
        conn.commit()
    finally:
        conn.close()


# ---------- Submissions ----------

def create_ranking_submission(competition_id, username, source='self', enforce_quota=False):
    """新建一条打榜赛提交。source：'self'=学生自交（计入 48h 配额）、
    'batch'=管理员批量拉取（不计入学生配额）。

    当 enforce_quota=True 且 source='self' 时，使用同一事务里的 ``SELECT ... FOR UPDATE``
    锁住比赛行，重新计算当前窗口用量并插入提交，避免并发请求同时通过前置 COUNT 检查。
    """
    ensure_ranking_tables()
    src = 'batch' if str(source or '').strip().lower() == 'batch' else 'self'
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if enforce_quota and src == 'self':
                cursor.execute(
                    """
                    SELECT id, submit_limit_per_window, limit_window_start, created_at
                    FROM ranking_competitions
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (competition_id,),
                )
                comp = cursor.fetchone()
                if comp:
                    cursor.execute("SELECT NOW() AS now")
                    now_row = cursor.fetchone() or {}
                    now = now_row.get('now') or datetime.now()
                    quota = _ranking_submission_quota_with_cursor(
                        cursor, competition_id, username, comp, now,
                    )
                    if quota is not None and quota['remaining'] <= 0:
                        conn.rollback()
                        raise RankingSubmissionQuotaExceeded(quota)
            cursor.execute(
                """
                INSERT INTO ranking_submissions (competition_id, username, status, source)
                VALUES (%s, %s, 'Pending', %s)
                """,
                (competition_id, username, src),
            )
            new_id = cursor.lastrowid
        conn.commit()
        bump_daily_submission_count()
        return int(new_id)
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def update_submission_files(submission_id, answer_filename, answer_path, code_filename, code_path, base_model=None):
    ensure_ranking_tables()
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
        conn.commit()
    finally:
        conn.close()


def update_submission_result(submission_id, score, status, grade_details=None, error_message=None):
    ensure_ranking_tables()
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
                SET score = %s, status = %s, grade_details = %s, error_message = %s
                WHERE id = %s
                """,
                (score, status, details_text, error_message, submission_id),
            )
        conn.commit()
    finally:
        conn.close()


def set_submission_status(submission_id, status):
    """只更新提交状态（不动 score/grade_details/error_message）。

    用于 agent_judge 的「等待评测(Queued) → 评测中(Judging)」状态切换：提交入队时置
    'Queued'，真正被评测 worker 取到开始执行时置 'Judging'。这样在 judge 并发上限（2）已满时，
    排队中的提交显示「等待评测」，而非误报「评测中」。
    """
    ensure_ranking_tables()
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


def begin_agent_judge_attempt(submission_id, status='Queued', reset_result=False):
    """为一次 Agent-as-Judge 评测生成新的 attempt，并返回 attempt_id。

    管理员重测会先清空旧规则结果，再调用本函数把当前提交切到新的 attempt；
    旧 Celery 消息即使之后醒来，也会因 attempt 不匹配而 no-op。
    """
    ensure_ranking_tables()
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
        conn.commit()
    finally:
        conn.close()
    return attempt_id


def set_agent_judge_task_id(submission_id, attempt_id, task_id):
    """记录当前 attempt 对应的 Celery task id。仅用于诊断和启动恢复判断。"""
    ensure_ranking_tables()
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


def set_submission_status_for_attempt(submission_id, attempt_id, status):
    """只在 attempt 仍是当前 attempt 时更新状态，返回匹配行数。

    PyMySQL 默认 rowcount 是 changed rows；当状态本来就是目标值且 heartbeat
    落在同一秒时，UPDATE 会返回 0。这里再查一次 attempt 是否仍匹配，避免把
    “无改动”误判成“旧 attempt”。
    """
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
    new_status = status if status in ('Pending', 'Queued', 'Judging') else 'Judging'
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, username,
                       answer_filename, answer_path, code_filename, code_path,
                       base_model
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
                     score, status, grade_details, error_message,
                     elo_rating, elo_match_count, elo_in_pool, source)
                VALUES (%s, %s, %s, %s, %s,
                        NULL, %s, NULL, NULL,
                        NULL, 0, 0, 'batch')
                """,
                (
                    source['competition_id'],
                    source.get('username') or '',
                    source.get('answer_filename'),
                    source.get('code_filename'),
                    source.get('base_model'),
                    new_status,
                ),
            )
            new_id = cursor.lastrowid
        conn.commit()
    finally:
        conn.close()

    if not new_id:
        raise RuntimeError("clone_ranking_submission_for_rejudge: failed to get valid submission id")

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
        bump_daily_submission_count()
        return int(new_id), source
    finally:
        conn.close()


def delete_ranking_submission(submission_id):
    """删除一条提交记录。返回被删除的行数（0 或 1）。"""
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_submissions WHERE id = %s", (submission_id,))
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
    finally:
        conn.close()


def get_ranking_submission(submission_id):
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, username,
                       answer_filename, answer_path, code_filename, code_path,
                       base_model, score, status, grade_details, error_message,
                       judge_attempt_id, judge_task_id, judge_heartbeat_at,
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

    'Judging' = 文件已上传、评测任务已入队，但重启时丢失。'Queued' = agent_judge 已入队但
    评测 worker 并发已满、尚未开始（重启后队列清空，同样需要补入队）。连带返回所属比赛的
    scoring_mode 与 elo_initial_rating，便于按模式分派：
      - 绝对分模式：重新 .delay() 给评测任务；
      - ELO 模式：补做入池（init_submission_elo_state -> Active）+ 补发 initial-burst。
    'Pending'（尚未上传文件，无可评内容）与 'Active' ELO（已由 matchmaker tick 接管）
    不在此列。
    """
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT s.id, s.competition_id, s.status,
                       s.score, s.grade_details,
                       s.judge_attempt_id, s.judge_task_id, s.judge_heartbeat_at,
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
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, username,
                       answer_filename, code_filename, base_model,
                       score, status,
                       elo_rating, elo_match_count, elo_in_pool,
                       created_at
                FROM ranking_submissions
                WHERE competition_id = %s AND username = %s
                ORDER BY created_at DESC, id DESC
                """,
                (competition_id, username),
            )
            return cursor.fetchall() or []
    finally:
        conn.close()


def list_all_submissions(competition_id, *, page=1, per_page=50, username_q=None):
    """返回 ``(rows, page, total)``。``page`` 在越界时被 clamp 到最后一页（保证只走一次 SELECT）。"""
    ensure_ranking_tables()
    page = max(1, int(page or 1))
    per_page = max(1, int(per_page or 50))
    q = (username_q or '').strip()
    where_sql = "WHERE competition_id = %s"
    params = [int(competition_id)]
    if q:
        where_sql += " AND username LIKE %s"
        params.append(f"%{q}%")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) AS total FROM ranking_submissions {where_sql}",
                tuple(params),
            )
            total = int((cursor.fetchone() or {}).get('total') or 0)
            total_pages = max(1, (total + per_page - 1) // per_page)
            if page > total_pages:
                page = total_pages
            offset = (page - 1) * per_page
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
                LIMIT %s OFFSET %s
                """,
                tuple(params) + (per_page, offset),
            )
            rows = cursor.fetchall() or []
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    每行附带 `best_base_model`：取得最高分那一份提交所填写的基座模型；
    若该用户的多份提交并列最高分，取最近一次。

    实现：单遍窗口函数。``ROW_NUMBER OVER (PARTITION BY username ORDER BY score DESC,
    created_at DESC, id DESC)`` 在 rn=1 的位置给出每位用户「最高分中最近一次」那条；
    同一窗口里再算 ``COUNT/MIN/MAX`` 给出 submission_count / first_submitted_at /
    best_score，避免历史版本里那条相关子查询带来的 N×扫描。
    """
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                WITH ranked AS (
                    SELECT
                        username, score, base_model, created_at, id,
                        ROW_NUMBER() OVER (
                            PARTITION BY username
                            ORDER BY score DESC, created_at DESC, id DESC
                        ) AS rn,
                        COUNT(*) OVER (PARTITION BY username) AS user_submission_count,
                        MIN(created_at) OVER (PARTITION BY username) AS user_first_submitted_at,
                        MAX(score) OVER (PARTITION BY username) AS user_best_score
                    FROM ranking_submissions
                    WHERE competition_id = %s AND score IS NOT NULL
                )
                SELECT
                    username,
                    user_best_score AS best_score,
                    user_submission_count AS submission_count,
                    user_first_submitted_at AS first_submitted_at,
                    base_model AS best_base_model
                FROM ranked
                WHERE rn = 1
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

def init_submission_elo_state(submission_id, rating):
    """新提交进入 ELO 池：写入初始分、清零对战次数、置入池标志，状态切换为 Active。"""
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET elo_rating = %s, score = %s,
                    elo_match_count = 0, elo_in_pool = 1,
                    status = 'Active'
                WHERE id = %s
                """,
                (float(rating), float(rating), int(submission_id)),
            )
        conn.commit()
    finally:
        conn.close()


def retire_excess_user_submissions(competition_id, username, keep_count=2):
    """同一用户在某场赛事的池内提交超过 keep_count 份时，把更早的退役。
    退役提交：elo_in_pool=0，status='Retired'。返回被退役的提交 id 列表。"""
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id FROM ranking_submissions
                WHERE competition_id = %s AND username = %s AND elo_in_pool = 1
                ORDER BY created_at DESC, id DESC
                """,
                (competition_id, username),
            )
            rows = cursor.fetchall() or []
            ids = [int(r['id']) for r in rows]
            keep = set(ids[: max(0, int(keep_count))])
            retire = [i for i in ids if i not in keep]
            if retire:
                placeholders = ','.join(['%s'] * len(retire))
                cursor.execute(
                    f"UPDATE ranking_submissions"
                    f" SET elo_in_pool = 0, status = 'Retired'"
                    f" WHERE id IN ({placeholders})",
                    tuple(retire),
                )
        conn.commit()
        return retire
    finally:
        conn.close()


def set_elo_running(competition_id, running):
    """切换赛事的 ELO 运行开关。"""
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, elo_rating, elo_match_count, answer_path
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, submission_a_id, submission_b_id, winner,
                       rating_a_before, rating_a_after, rating_b_before, rating_b_after
                FROM ranking_elo_matches
                WHERE id = %s AND competition_id = %s
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
                    SET elo_rating = elo_rating - %s,
                        score = elo_rating - %s,
                        elo_match_count = GREATEST(elo_match_count - 1, 0)
                    WHERE id = %s
                    """,
                    (delta_a, delta_a, sub_a_id),
                )
                cursor.execute(
                    """
                    UPDATE ranking_submissions
                    SET elo_rating = elo_rating - %s,
                        score = elo_rating - %s,
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM ranking_appeals WHERE id = %s", (int(appeal_id),))
            return cursor.fetchone()
    finally:
        conn.close()


def get_appeal_by_submission(submission_id):
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
    ensure_ranking_tables()
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
