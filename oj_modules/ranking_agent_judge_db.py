#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛 Agent-as-Judge 的 DB 层：评分规则表 + 逐条结果表 + 快照构造。"""
import json
import time

from oj_modules.db_services import get_db_connection
from oj_modules.ranking_db import get_ranking_submission
from oj_modules import ranking_agent_judge as aj

_aj_tables_ready = False


def ensure_agent_judge_tables():
    global _aj_tables_ready
    if _aj_tables_ready:
        return
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ranking_judge_rules (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    competition_id INT NOT NULL,
                    rule_id INT NOT NULL,
                    rule_text MEDIUMTEXT NOT NULL,
                    value DOUBLE NOT NULL DEFAULT 0,
                    dependencies TEXT,
                    ordering INT NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_rjr_comp_rule (competition_id, rule_id),
                    INDEX idx_rjr_comp (competition_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ranking_judge_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    submission_id INT NOT NULL,
                    rule_id INT NOT NULL,
                    raw_result VARCHAR(16) DEFAULT NULL,
                    effective_result VARCHAR(16) DEFAULT NULL,
                    score DOUBLE NOT NULL DEFAULT 0,
                    evidence MEDIUMTEXT,
                    reported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_rjres_sub_rule (submission_id, rule_id),
                    INDEX idx_rjres_sub (submission_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
        conn.commit()
        _aj_tables_ready = True
    finally:
        conn.close()


def replace_competition_rules(competition_id, rules):
    """整体替换某比赛的评分规则（先 normalize 校验 DAG，再删旧插新）。抛 ValueError 表示校验失败。"""
    normalized = aj.normalize_rules(rules)  # 校验在事务外，失败则不动 DB
    ensure_agent_judge_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_judge_rules WHERE competition_id = %s",
                           (competition_id,))
            for r in normalized:
                cursor.execute(
                    """
                    INSERT INTO ranking_judge_rules
                        (competition_id, rule_id, rule_text, value, dependencies, ordering)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (competition_id, r['rule_id'], r['rule_text'], float(r['value']),
                     json.dumps(r['dependencies']), r['ordering']),
                )
        conn.commit()
    finally:
        conn.close()
    return normalized


def list_competition_rules(competition_id):
    """返回该比赛的规则列表（按 ordering），dependencies 已解析为 int 列表。"""
    ensure_agent_judge_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT rule_id, rule_text, value, dependencies, ordering
                FROM ranking_judge_rules
                WHERE competition_id = %s
                ORDER BY ordering ASC, rule_id ASC
                """,
                (competition_id,),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()
    out = []
    for row in rows:
        try:
            deps = json.loads(row.get('dependencies') or '[]')
        except Exception:
            deps = []
        out.append({'rule_id': int(row['rule_id']), 'rule_text': row['rule_text'],
                    'value': float(row['value']),
                    'dependencies': [int(d) for d in deps],
                    'ordering': int(row['ordering'] or 0)})
    return out


def upsert_judge_result(submission_id, rule_id, raw_result, effective_result, score, evidence):
    ensure_agent_judge_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ranking_judge_results
                    (submission_id, rule_id, raw_result, effective_result, score, evidence)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    raw_result = VALUES(raw_result),
                    effective_result = VALUES(effective_result),
                    score = VALUES(score),
                    evidence = VALUES(evidence)
                """,
                (submission_id, rule_id, raw_result, effective_result,
                 float(score or 0), (evidence or '')),
            )
        conn.commit()
    finally:
        conn.close()


def list_judge_results(submission_id):
    ensure_agent_judge_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT rule_id, raw_result, effective_result, score, evidence
                FROM ranking_judge_results
                WHERE submission_id = %s
                ORDER BY rule_id ASC
                """,
                (submission_id,),
            )
            return cursor.fetchall() or []
    finally:
        conn.close()


def clear_judge_results(submission_id):
    ensure_agent_judge_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_judge_results WHERE submission_id = %s",
                           (submission_id,))
        conn.commit()
    finally:
        conn.close()


def _format_now():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())


def build_judge_snapshot(submission_id):
    """组合提交 + 规则 + 已上报结果 → SSE 快照（effective 由纯逻辑按 DAG 重算）。"""
    submission = get_ranking_submission(submission_id)
    if not submission:
        return None
    competition_id = submission.get('competition_id')
    rules = list_competition_rules(competition_id)
    raw_rows = list_judge_results(submission_id)
    raw_by_id = {int(r['rule_id']): r.get('raw_result') for r in raw_rows
                 if r.get('raw_result') in (aj.RESULT_PASS, aj.RESULT_FAILED)}
    evidence_by_id = {int(r['rule_id']): (r.get('evidence') or '') for r in raw_rows}
    status = submission.get('status')
    finalize = status not in ('Judging', 'Pending')
    computed = aj.compute_results(rules, raw_by_id, finalize=finalize) if rules else {}
    rule_payloads = []
    for r in rules:
        rid = r['rule_id']
        c = computed.get(rid, {'effective': aj.EFF_PENDING, 'score': 0.0})
        evidence = evidence_by_id.get(rid, '')
        # 仅存 markdown 源（rule_text / evidence）；HTML 在前端请求时实时渲染（见 render_snapshot_html）
        rule_payloads.append({
            'rule_id': rid, 'rule_text': r['rule_text'], 'value': float(r['value']),
            'dependencies': r['dependencies'],
            'effective': c['effective'], 'score': c['score'],
            'evidence': evidence,
        })
    timed_out = False
    gd = submission.get('grade_details')
    if gd:
        try:
            parsed = json.loads(gd) if isinstance(gd, str) else gd
            timed_out = bool(parsed.get('timed_out')) if isinstance(parsed, dict) else False
        except Exception:
            timed_out = False
    return {
        'submission_id': int(submission_id),
        'status': status,
        'max_score': aj.max_score(rules) if rules else 0.0,
        'total_score': aj.total_score(computed) if computed else 0.0,
        'timed_out': timed_out,
        'rules': rule_payloads,
        'last_updated': _format_now(),
    }
