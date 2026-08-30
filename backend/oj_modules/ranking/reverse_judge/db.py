#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反向评测步骤与答案归档路径的数据访问层。"""

import json
import os
import stat

from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.ranking.db import get_ranking_submission, submission_dir


STEP_SOLUTION = 'solution_check'
STEP_QUALITY_GATE = 'quality_gate'
STEP_AGENT = 'agent_answer'
STEP_AI_JUDGE = 'ai_judge'
STEP_DEFS = (
    (STEP_SOLUTION, 1, '标准答案自检'),
    (STEP_QUALITY_GATE, 2, '质量门禁'),
    (STEP_AGENT, 3, 'AI 作答'),
    (STEP_AI_JUDGE, 4, '评测 AI 答案'),
)
STEP_DEF_BY_KEY = {key: {'step_key': key, 'step_order': order, 'title': title}
                   for key, order, title in STEP_DEFS}
STEP_KEYS = tuple(key for key, _, _ in STEP_DEFS)
TERMINAL_STEP_STATUSES = {'passed', 'failed', 'error', 'skipped'}
_REVERSE_AGENT_ANSWER_SUBDIR = 'reverse_agent_answers'


def safe_attempt_component(attempt_id):
    text = ''.join(
        ch for ch in str(attempt_id or 'legacy')
        if ch.isalnum() or ch in ('-', '_')
    )
    return text[:80] or 'legacy'


def reverse_agent_answer_archive_path(submission_id, attempt_id):
    """返回当前提交/attempt 的可信 AI 解答 ZIP 路径。"""
    root = os.path.realpath(os.path.join(
        submission_dir(int(submission_id)), _REVERSE_AGENT_ANSWER_SUBDIR,
    ))
    # 不解析最终文件本身的 symlink；调用方必须用 lstat 校验。若在这里 realpath，
    # 恶意/损坏链接会把“是否可用”查询变成 ValueError，并使详情接口 500。
    archive_path = os.path.abspath(os.path.join(
        root, safe_attempt_component(attempt_id) + '.zip',
    ))
    if archive_path == root or not archive_path.startswith(root + os.sep):
        raise ValueError('AI 解答归档路径非法')
    return archive_path


def available_reverse_agent_answer_archive_path(submission_id, attempt_id, status):
    """返回可下载的当前 attempt AI 解答 ZIP；不可用时返回 ``None``。"""
    if status not in {'Accepted', 'Error'}:
        return None
    try:
        archive_path = reverse_agent_answer_archive_path(submission_id, attempt_id)
        archive_stat = os.lstat(archive_path)
    except (OSError, TypeError, ValueError):
        return None
    # lstat 的普通文件判定天然排除符号链接，避免下载越出提交目录。
    if not stat.S_ISREG(archive_stat.st_mode):
        return None
    return archive_path


def clear_reverse_judge_steps(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM ranking_reverse_judge_steps WHERE submission_id = %s",
                (int(submission_id),),
            )
        conn.commit()
    finally:
        conn.close()


def init_reverse_judge_steps_for_attempt(submission_id, attempt_id):
    """重置并预置四步记录。仅在 submission 当前 attempt 仍匹配时生效。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                DELETE r
                FROM ranking_reverse_judge_steps r
                JOIN ranking_submissions s ON s.id = r.submission_id
                WHERE r.submission_id = %s AND s.judge_attempt_id <=> %s
                """,
                (int(submission_id), attempt_id),
            )
            affected_total = cursor.rowcount
            for key, order, title in STEP_DEFS:
                cursor.execute(
                    """
                    INSERT INTO ranking_reverse_judge_steps
                        (submission_id, step_key, step_order, title, status)
                    SELECT %s, %s, %s, %s, 'pending'
                    FROM ranking_submissions
                    WHERE id = %s AND judge_attempt_id <=> %s
                    ON DUPLICATE KEY UPDATE
                        step_order = VALUES(step_order),
                        title = VALUES(title),
                        status = VALUES(status),
                        max_score = NULL,
                        score = NULL,
                        result_json = NULL,
                        stdout = NULL,
                        stderr = NULL,
                        error_message = NULL,
                        trace_dir = NULL,
                        started_at = NULL,
                        finished_at = NULL
                    """,
                    (int(submission_id), key, int(order), title,
                     int(submission_id), attempt_id),
                )
                affected_total += cursor.rowcount
        conn.commit()
        return int(affected_total or 0)
    finally:
        conn.close()


def ensure_reverse_judge_steps_for_attempt(submission_id, attempt_id):
    """补齐当前 attempt 的步骤记录，但保留已经完成的阶段。

    反向评测在端点繁忙时会通过 Celery retry 重新排队。重排后必须沿用已经通过的
    标准答案自检和质量门禁，否则每次等待模型槽位都会重复执行用户脚本和消耗审核
    token。新的 attempt 会在入队前清空旧步骤，因此这里只做幂等补齐即可。
    """
    conn = get_db_connection()
    try:
        affected_total = 0
        with conn.cursor() as cursor:
            for key, order, title in STEP_DEFS:
                cursor.execute(
                    """
                    INSERT INTO ranking_reverse_judge_steps
                        (submission_id, step_key, step_order, title, status)
                    SELECT %s, %s, %s, %s, 'pending'
                    FROM ranking_submissions
                    WHERE id = %s AND judge_attempt_id <=> %s
                    ON DUPLICATE KEY UPDATE
                        step_order = VALUES(step_order),
                        title = VALUES(title)
                    """,
                    (int(submission_id), key, int(order), title,
                     int(submission_id), attempt_id),
                )
                affected_total += cursor.rowcount
        conn.commit()
        return int(affected_total or 0)
    finally:
        conn.close()


def update_reverse_judge_step_for_attempt(submission_id, attempt_id, step_key, *,
                                          status=None, max_score=None, score=None,
                                          result_json=None, stdout=None, stderr=None,
                                          error_message=None, trace_dir=None):
    """只在 submission 当前 attempt 未变化时写入步骤状态，返回受影响行数。"""
    if step_key not in STEP_DEF_BY_KEY:
        raise ValueError(f'unknown reverse judge step: {step_key}')
    step = STEP_DEF_BY_KEY[step_key]
    status = status or 'pending'
    result_text = None
    if result_json is not None:
        if isinstance(result_json, str):
            result_text = result_json
        else:
            result_text = json.dumps(result_json, ensure_ascii=False)
    started_expr = (
        "COALESCE(started_at, CURRENT_TIMESTAMP)"
        if status == 'running'
        else "COALESCE(started_at, CURRENT_TIMESTAMP)" if status in TERMINAL_STEP_STATUSES else "started_at"
    )
    finished_expr = "CURRENT_TIMESTAMP" if status in TERMINAL_STEP_STATUSES else "NULL"
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"""
                INSERT INTO ranking_reverse_judge_steps
                    (submission_id, step_key, step_order, title, status,
                     max_score, score, result_json, stdout, stderr,
                     error_message, trace_dir, started_at, finished_at)
                SELECT %s, %s, %s, %s, %s,
                       %s, %s, %s, %s, %s,
                       %s, %s,
                       CASE WHEN %s = 'running' THEN CURRENT_TIMESTAMP ELSE NULL END,
                       CASE WHEN %s IN ('passed', 'failed', 'error', 'skipped') THEN CURRENT_TIMESTAMP ELSE NULL END
                FROM ranking_submissions
                WHERE id = %s AND judge_attempt_id <=> %s
                ON DUPLICATE KEY UPDATE
                    step_order = VALUES(step_order),
                    title = VALUES(title),
                    status = VALUES(status),
                    max_score = VALUES(max_score),
                    score = VALUES(score),
                    result_json = VALUES(result_json),
                    stdout = VALUES(stdout),
                    stderr = VALUES(stderr),
                    error_message = VALUES(error_message),
                    trace_dir = VALUES(trace_dir),
                    started_at = {started_expr},
                    finished_at = {finished_expr}
            """
            cursor.execute(
                sql,
                (int(submission_id), step_key, int(step['step_order']), step['title'], status,
                 max_score, score, result_text, stdout, stderr,
                 error_message, trace_dir, status, status,
                 int(submission_id), attempt_id),
            )
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
    finally:
        conn.close()


def list_reverse_judge_steps(submission_id):
    submission = get_ranking_submission(submission_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT step_key, step_order, title, status, max_score, score,
                       result_json, stdout, stderr, error_message, trace_dir,
                       started_at, finished_at, updated_at
                FROM ranking_reverse_judge_steps
                WHERE submission_id = %s
                ORDER BY step_order ASC, id ASC
                """,
                (int(submission_id),),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()

    by_key = {r.get('step_key'): r for r in rows}
    out = []
    for key, order, title in STEP_DEFS:
        row = dict(by_key.get(key) or {})
        # 历史三步记录仍保存着旧的 1/2/3 顺序；对外始终投影为当前四步定义，
        # 避免质量门禁和 AI 作答同时显示 step_order=2。
        row['step_key'] = key
        row['step_order'] = order
        row['title'] = title
        if 'status' not in row:
            # 质量门禁上线前的历史提交没有对应 DB 行。终态历史记录应明确展示为
            # “未执行”，而不是永久多出一个 pending 步骤；新排队/评测中的提交仍
            # 等待 worker 通过 ensure_reverse_judge_steps_for_attempt 补齐真实记录。
            if key == STEP_QUALITY_GATE and str((submission or {}).get('status') or '') not in (
                    'Judging', 'Pending', 'Queued'):
                row['status'] = 'skipped'
                row['result_json'] = {
                    'enabled': False,
                    'skipped': True,
                    'summary': '历史评测未执行质量门禁',
                }
            else:
                row['status'] = 'pending'
        out.append(row)
    return out


__all__ = [
    "STEP_SOLUTION",
    "STEP_QUALITY_GATE",
    "STEP_AGENT",
    "STEP_AI_JUDGE",
    "STEP_DEFS",
    "STEP_DEF_BY_KEY",
    "STEP_KEYS",
    "TERMINAL_STEP_STATUSES",
    "safe_attempt_component",
    "reverse_agent_answer_archive_path",
    "available_reverse_agent_answer_archive_path",
    "clear_reverse_judge_steps",
    "init_reverse_judge_steps_for_attempt",
    "ensure_reverse_judge_steps_for_attempt",
    "update_reverse_judge_step_for_attempt",
    "list_reverse_judge_steps",
]
