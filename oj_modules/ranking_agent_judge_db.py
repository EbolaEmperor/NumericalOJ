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
            # 每比赛的多模型端点池：每个端点 (base_url, api_key, model) 各自带并发上限。
            # 判题时按端点分别用 Redis 槽位限流，从而把 agent 评测并发提升到「各端点上限之和」。
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ranking_agent_judge_endpoints (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    competition_id INT NOT NULL,
                    base_url VARCHAR(512) NOT NULL,
                    api_key VARCHAR(512) NOT NULL,
                    model VARCHAR(128) DEFAULT NULL,
                    concurrency_limit INT NOT NULL DEFAULT 1,
                    enabled TINYINT(1) NOT NULL DEFAULT 1,
                    ordering INT NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_aje_comp (competition_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
        conn.commit()
        _aj_tables_ready = True
    finally:
        conn.close()


def list_agent_judge_endpoints(competition_id, enabled_only=False):
    """返回某比赛的 agent 评测端点列表（含 api_key 明文，仅供判题侧使用）。
    enabled_only=True 时只返回启用的端点。按 ordering, id 排序。"""
    ensure_agent_judge_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = ("SELECT id, base_url, api_key, model, concurrency_limit, enabled, ordering "
                   "FROM ranking_agent_judge_endpoints WHERE competition_id = %s")
            if enabled_only:
                sql += " AND enabled = 1"
            sql += " ORDER BY ordering ASC, id ASC"
            cursor.execute(sql, (competition_id,))
            rows = cursor.fetchall() or []
    finally:
        conn.close()
    out = []
    for r in rows:
        out.append({
            'id': int(r['id']),
            'base_url': r['base_url'] or '',
            'api_key': r['api_key'] or '',
            'model': (r.get('model') or ''),
            'concurrency_limit': int(r['concurrency_limit'] or 1),
            'enabled': int(r['enabled'] or 0),
            'ordering': int(r['ordering'] or 0),
        })
    return out


def save_agent_judge_endpoints(competition_id, items):
    """整体替换某比赛的端点列表。校验在事务外，失败抛 ValueError（不动 DB）。

    items 中每项：{id?, base_url, api_key, model, concurrency_limit, enabled}。
    api_key 留空且带已存在的 id → 沿用旧 key（前端编辑器不回显明文）；
    api_key 留空且无对应 id → 报错（新端点必须填 key）。返回归一化后的列表。"""
    ensure_agent_judge_tables()
    if not isinstance(items, list):
        raise ValueError('端点格式非法')
    existing = {e['id']: e['api_key'] for e in list_agent_judge_endpoints(competition_id)}
    normalized = []
    for idx, it in enumerate(items):
        if not isinstance(it, dict):
            raise ValueError('端点格式非法')
        base_url = str(it.get('base_url') or '').strip()
        if not base_url:
            raise ValueError('端点 URL 不能为空')
        if not (base_url.startswith('http://') or base_url.startswith('https://')):
            raise ValueError(f'端点 URL 必须以 http(s):// 开头：{base_url[:60]}')
        if len(base_url) > 512:
            raise ValueError('端点 URL 过长（不超过 512 字）')
        eid = it.get('id')
        try:
            eid = int(eid) if eid not in (None, '', 'null') else None
        except (TypeError, ValueError):
            eid = None
        key_in = str(it.get('api_key') or '').strip()
        if key_in:
            api_key = key_in
        elif eid is not None and existing.get(eid):
            api_key = existing[eid]          # 沿用旧 key（编辑器未改动该行 key）
        else:
            raise ValueError('新端点必须填写 API Key')
        if len(api_key) > 512:
            raise ValueError('API Key 过长（不超过 512 字）')
        model = (str(it.get('model') or '').strip() or None)
        if model and len(model) > 128:
            raise ValueError('模型名过长（不超过 128 字）')
        try:
            climit = int(it.get('concurrency_limit'))
        except (TypeError, ValueError):
            climit = 1
        climit = max(1, min(64, climit))
        ev = it.get('enabled')
        enabled = 1 if (ev is True or str(ev).strip().lower() in ('1', 'true', 'on', 'yes')) else 0
        # 不去重：同一厂商(同 url)可能有多个账号 → 不同 api_key，应允许并存（各自独立并发槽位）。
        normalized.append({'base_url': base_url, 'api_key': api_key, 'model': model,
                           'concurrency_limit': climit, 'enabled': enabled, 'ordering': idx})
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_agent_judge_endpoints WHERE competition_id = %s",
                           (competition_id,))
            for e in normalized:
                cursor.execute(
                    "INSERT INTO ranking_agent_judge_endpoints"
                    " (competition_id, base_url, api_key, model, concurrency_limit, enabled, ordering)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (competition_id, e['base_url'], e['api_key'], e['model'],
                     e['concurrency_limit'], e['enabled'], e['ordering']),
                )
        conn.commit()
    finally:
        conn.close()
    return normalized


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


def apply_rule_overrides(submission_id, overrides):
    """申诉处理「提交」时落库：把管理员手动设置的规则 effective 写入 ranking_judge_results。

    overrides: {rule_id(int): 'pass'|'failed'|'skipped'}。仅覆盖管理员动过的规则
    （effective 直接采用管理员所选，score = 满分 if pass else 0，raw/evidence 保留），
    其它规则保持原状。返回 (total_score, max_score, rule_payloads)，供调用方回写提交分数。
    与系统计分口径一致：score 为二元（满分/0），总分 = 各规则 score 之和。
    """
    submission = get_ranking_submission(submission_id)
    if not submission:
        return 0.0, 0.0, []
    competition_id = submission.get('competition_id')
    rules = list_competition_rules(competition_id) or []
    current = {int(r['rule_id']): r for r in (list_judge_results(submission_id) or [])}
    norm = {}
    for k, v in (overrides or {}).items():
        try:
            rid = int(k)
        except (TypeError, ValueError):
            continue
        eff = str(v or '').strip().lower()
        if eff in (aj.EFF_PASS, aj.EFF_FAILED, aj.EFF_SKIPPED):
            norm[rid] = eff

    total = 0.0
    max_total = 0.0
    payloads = []
    for r in rules:
        rid = int(r['rule_id'])
        value = float(r['value'])
        max_total += value
        cur = current.get(rid, {})
        if rid in norm:
            eff = norm[rid]
            score = value if eff == aj.EFF_PASS else 0.0
            upsert_judge_result(
                submission_id, rid,
                cur.get('raw_result'), eff, score, cur.get('evidence') or '',
            )
        else:
            eff = cur.get('effective_result') or aj.EFF_PENDING
            try:
                score = float(cur.get('score') or 0)
            except (TypeError, ValueError):
                score = 0.0
        total += score
        payloads.append({'rule_id': rid, 'effective': eff, 'score': score})
    return total, max_total, payloads
