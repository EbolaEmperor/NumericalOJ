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

from oj_modules.db_services import get_db_connection


_ranking_tables_ready = False

RANKING_UPLOAD_ROOT = 'ranking_uploads'
ATTACHMENT_SUBDIR = 'attachments'
REFERENCE_SUBDIR = 'reference'
SCORING_SUBDIR = 'scoring'
SUBMISSION_SUBDIR = 'submissions'


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
                    score DOUBLE DEFAULT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'Judging',
                    grade_details MEDIUMTEXT,
                    error_message TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_rs_comp_user (competition_id, username),
                    INDEX idx_rs_comp_score (competition_id, score),
                    INDEX idx_rs_comp_created (competition_id, created_at)
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
                SELECT id, title, summary, description, reference_answer_path, reference_answer_name,
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


def update_competition(competition_id, *, title=None, summary=None, description=None, max_score=None, is_active=None):
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

def create_ranking_submission(competition_id, username):
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ranking_submissions (competition_id, username, status)
                VALUES (%s, %s, 'Pending')
                """,
                (competition_id, username),
            )
            new_id = cursor.lastrowid
        conn.commit()
        return int(new_id)
    finally:
        conn.close()


def update_submission_files(submission_id, answer_filename, answer_path, code_filename, code_path):
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE ranking_submissions
                SET answer_filename = %s, answer_path = %s,
                    code_filename = %s, code_path = %s,
                    status = 'Judging'
                WHERE id = %s
                """,
                (answer_filename, answer_path, code_filename, code_path, submission_id),
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


def get_ranking_submission(submission_id):
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, username,
                       answer_filename, answer_path, code_filename, code_path,
                       score, status, grade_details, error_message, created_at
                FROM ranking_submissions
                WHERE id = %s
                """,
                (submission_id,),
            )
            return cursor.fetchone()
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
                       answer_filename, code_filename,
                       score, status, created_at
                FROM ranking_submissions
                WHERE competition_id = %s AND username = %s
                ORDER BY created_at DESC, id DESC
                """,
                (competition_id, username),
            )
            return cursor.fetchall() or []
    finally:
        conn.close()


def list_all_submissions(competition_id):
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, username,
                       answer_filename, code_filename,
                       score, status, created_at
                FROM ranking_submissions
                WHERE competition_id = %s
                ORDER BY created_at DESC, id DESC
                """,
                (competition_id,),
            )
            return cursor.fetchall() or []
    finally:
        conn.close()


def get_leaderboard(competition_id):
    """
    返回按每位用户最高分排序的排行榜。分数相同排名一致（标准竞赛并列排名）。
    """
    ensure_ranking_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT username,
                       MAX(score) AS best_score,
                       COUNT(*) AS submission_count,
                       MIN(created_at) AS first_submitted_at
                FROM ranking_submissions
                WHERE competition_id = %s AND score IS NOT NULL
                GROUP BY username
                ORDER BY best_score DESC, first_submitted_at ASC, username ASC
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
