#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛 Agent-as-Judge 的 DB 层：评分规则表 + 逐条结果表 + 快照构造。"""
import json
import time

from oj_modules.db_services import get_db_connection
from oj_modules.ranking_db import get_ranking_submission
from oj_modules import ranking_agent_judge as aj

_aj_tables_ready = False

HARNESS_CLAUDE_CODE = 'claude_code'
HARNESS_CODEX = 'codex'
HARNESS_OPENCODE = 'opencode'
ALLOWED_AGENT_HARNESSES = (HARNESS_CLAUDE_CODE, HARNESS_CODEX, HARNESS_OPENCODE)
DEFAULT_OPENCODE_GO_BASE_URL = 'https://opencode.ai/zen/go/v1'
DEFAULT_OPENCODE_GO_MODEL = 'mimo-v2.5-pro'
ENDPOINT_STATUS_ENABLED = 'enabled'
ENDPOINT_STATUS_DISABLED = 'disabled'
ENDPOINT_STATUS_PAUSED = 'paused'
ENDPOINT_STATUSES = (
    ENDPOINT_STATUS_ENABLED,
    ENDPOINT_STATUS_DISABLED,
    ENDPOINT_STATUS_PAUSED,
)
ENDPOINT_POOL_PRIMARY = 'primary'
ENDPOINT_POOL_QUALITY_GATE = 'quality_gate'
ENDPOINT_POOL_KINDS = (
    ENDPOINT_POOL_PRIMARY,
    ENDPOINT_POOL_QUALITY_GATE,
)
_QUALITY_GATE_UNSET = object()


def normalize_agent_harness(value):
    harness = str(value or '').strip().lower().replace('-', '_')
    return harness if harness in ALLOWED_AGENT_HARNESSES else HARNESS_CLAUDE_CODE


def normalize_endpoint_status(value, *, fallback_enabled=None):
    """端点状态归一化。

    enabled：参与评测；paused：自动暂停，可被健康检查恢复；disabled：人工停用，不自动恢复。
    fallback_enabled 用于兼容旧 payload / 旧表里的 enabled 布尔。
    """
    status = str(value or '').strip().lower()
    if status in ENDPOINT_STATUSES:
        return status
    if fallback_enabled is not None:
        return ENDPOINT_STATUS_ENABLED if bool(fallback_enabled) else ENDPOINT_STATUS_DISABLED
    return ENDPOINT_STATUS_ENABLED


def _status_enabled(status):
    return 1 if normalize_endpoint_status(status) == ENDPOINT_STATUS_ENABLED else 0


def _payload_enabled(value):
    return value is True or str(value).strip().lower() in ('1', 'true', 'on', 'yes')


def _normalize_endpoint_pool_kind(value):
    pool_kind = str(value or '').strip().lower()
    return pool_kind if pool_kind in ENDPOINT_POOL_KINDS else ENDPOINT_POOL_PRIMARY


def _endpoint_row(row):
    status = normalize_endpoint_status(
        row.get('status'),
        fallback_enabled=bool(int(row.get('enabled') or 0)),
    )
    return {
        'id': int(row['id']),
        'competition_id': int(row.get('competition_id') or 0),
        'pool_kind': _normalize_endpoint_pool_kind(row.get('pool_kind')),
        'harness': normalize_agent_harness(row.get('harness')),
        'base_url': row['base_url'] or '',
        'api_key': row['api_key'] or '',
        'model': (row.get('model') or ''),
        'concurrency_limit': int(row['concurrency_limit'] or 1),
        'status': status,
        'enabled': _status_enabled(status),
        'ordering': int(row['ordering'] or 0),
    }


def ensure_agent_judge_tables():
    global _aj_tables_ready
    _aj_tables_ready = True


def _list_endpoints(competition_id, pool_kind, enabled_only=False):
    """按池返回端点；pool_kind 只接受本模块定义的固定常量。"""
    pool_kind = _normalize_endpoint_pool_kind(pool_kind)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = ("SELECT id, competition_id, pool_kind, harness, base_url, api_key, model,"
                   " concurrency_limit, enabled, status, ordering "
                   "FROM ranking_agent_judge_endpoints "
                   "WHERE competition_id = %s AND pool_kind = %s")
            if enabled_only:
                sql += " AND status = 'enabled'"
            sql += " ORDER BY ordering ASC, id ASC"
            cursor.execute(sql, (competition_id, pool_kind))
            rows = cursor.fetchall() or []
    finally:
        conn.close()
    return [_endpoint_row(r) for r in rows]


def list_agent_judge_endpoints(competition_id, enabled_only=False):
    """返回主评测端点池（含 api_key 明文，仅供判题侧使用）。"""
    return _list_endpoints(
        competition_id,
        ENDPOINT_POOL_PRIMARY,
        enabled_only=enabled_only,
    )


def list_quality_gate_endpoints(competition_id, enabled_only=False):
    """返回反向评测质量门禁的独立端点池。"""
    return _list_endpoints(
        competition_id,
        ENDPOINT_POOL_QUALITY_GATE,
        enabled_only=enabled_only,
    )


def list_paused_agent_judge_endpoints():
    """返回两个池中所有自动暂停的端点，供周期性恢复探测任务使用。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, competition_id, pool_kind, harness, base_url, api_key, model,
                       concurrency_limit, enabled, status, ordering
                FROM ranking_agent_judge_endpoints
                WHERE status = 'paused'
                ORDER BY id ASC
                """
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()
    return [_endpoint_row(r) for r in rows]


def set_agent_judge_endpoint_status(endpoint_id, status, *, only_from_status=None):
    """设置单个端点状态，并同步旧 enabled 字段。返回受影响行数。

    only_from_status 用于避免后台任务覆盖管理员刚刚做出的人工状态修改。
    """
    status = normalize_endpoint_status(status)
    enabled = _status_enabled(status)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "UPDATE ranking_agent_judge_endpoints"
                " SET status = %s, enabled = %s"
                " WHERE id = %s"
            )
            params = [status, enabled, int(endpoint_id)]
            if only_from_status is not None:
                sql += " AND status = %s"
                params.append(normalize_endpoint_status(only_from_status))
            cursor.execute(sql, params)
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
    finally:
        conn.close()


def set_agent_judge_endpoint_enabled(endpoint_id, enabled):
    """启用/关闭单个 Agent 评测端点。返回受影响行数。"""
    status = ENDPOINT_STATUS_ENABLED if enabled else ENDPOINT_STATUS_DISABLED
    return set_agent_judge_endpoint_status(endpoint_id, status)


def pause_agent_judge_endpoint(endpoint_id):
    """后台健康检查失败时把启用端点转为暂停；不会覆盖人工停用。"""
    return set_agent_judge_endpoint_status(
        endpoint_id,
        ENDPOINT_STATUS_PAUSED,
        only_from_status=ENDPOINT_STATUS_ENABLED,
    )


def resume_paused_agent_judge_endpoint(endpoint_id):
    """后台恢复检查通过时只把 paused 端点重新启用；不会覆盖人工停用。"""
    return set_agent_judge_endpoint_status(
        endpoint_id,
        ENDPOINT_STATUS_ENABLED,
        only_from_status=ENDPOINT_STATUS_PAUSED,
    )


def _normalize_endpoint_items(pool_kind, items, existing_rows):
    """纯函数式归一化一个端点池，保留已有端点的密钥和人工状态语义。"""
    if not isinstance(items, list):
        raise ValueError('端点格式非法')
    pool_kind = _normalize_endpoint_pool_kind(pool_kind)
    existing = {
        e['id']: e
        for e in (existing_rows or [])
    }
    normalized = []
    seen_existing_ids = set()
    for idx, it in enumerate(items):
        if not isinstance(it, dict):
            raise ValueError('端点格式非法')
        harness = normalize_agent_harness(it.get('harness'))
        base_url = str(it.get('base_url') or '').strip()
        if (pool_kind == ENDPOINT_POOL_PRIMARY
                and harness == HARNESS_OPENCODE and not base_url):
            base_url = DEFAULT_OPENCODE_GO_BASE_URL
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
        if eid in existing:
            if eid in seen_existing_ids:
                raise ValueError(f'端点 ID {eid} 重复')
            seen_existing_ids.add(eid)
        key_in = str(it.get('api_key') or '').strip()
        if key_in:
            api_key = key_in
        elif eid is not None and existing.get(eid, {}).get('api_key'):
            api_key = existing[eid]['api_key']          # 沿用旧 key（编辑器未改动该行 key）
        else:
            raise ValueError('新端点必须填写 API Key')
        if len(api_key) > 512:
            raise ValueError('API Key 过长（不超过 512 字）')
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in api_key):
            raise ValueError('API Key 不能包含换行或控制字符')
        model = (str(it.get('model') or '').strip() or None)
        if (pool_kind == ENDPOINT_POOL_PRIMARY
                and harness == HARNESS_OPENCODE and not model):
            model = DEFAULT_OPENCODE_GO_MODEL
        if pool_kind == ENDPOINT_POOL_QUALITY_GATE and not model:
            raise ValueError('质量门禁端点模型不能为空')
        if model and len(model) > 128:
            raise ValueError('模型名过长（不超过 128 字）')
        try:
            climit = int(it.get('concurrency_limit'))
        except (TypeError, ValueError):
            climit = 1
        climit = max(1, min(64, climit))
        if 'status' in it:
            status = normalize_endpoint_status(it.get('status'))
        elif 'enabled' in it:
            status = normalize_endpoint_status(None, fallback_enabled=_payload_enabled(it.get('enabled')))
        elif eid is not None and existing.get(eid):
            status = existing[eid].get('status') or ENDPOINT_STATUS_ENABLED
        else:
            status = ENDPOINT_STATUS_ENABLED
        enabled = _status_enabled(status)
        # 不去重：同一厂商(同 url)可能有多个账号 → 不同 api_key，应允许并存（各自独立并发槽位）。
        normalized.append({'id': eid if eid in existing else None,
                           'pool_kind': pool_kind,
                           'harness': harness, 'base_url': base_url, 'api_key': api_key, 'model': model,
                           'concurrency_limit': climit, 'status': status,
                           'enabled': enabled, 'ordering': idx})
    return normalized


def _replace_endpoint_pool_with_cursor(cursor, competition_id, pool_kind, normalized):
    """使用调用方事务整体替换一个端点池；调用方负责 commit/rollback。"""
    keep_ids = [e['id'] for e in normalized if e.get('id') is not None]
    if keep_ids:
        cursor.execute(
            "DELETE FROM ranking_agent_judge_endpoints "
            f"WHERE competition_id = %s AND pool_kind = %s "
            f"AND id NOT IN ({','.join(['%s'] * len(keep_ids))})",
            tuple([competition_id, pool_kind] + keep_ids),
        )
    else:
        cursor.execute(
            "DELETE FROM ranking_agent_judge_endpoints "
            "WHERE competition_id = %s AND pool_kind = %s",
            (competition_id, pool_kind),
        )
    for endpoint in normalized:
        if endpoint.get('id') is not None:
            cursor.execute(
                """
                UPDATE ranking_agent_judge_endpoints
                SET harness = %s,
                    base_url = %s,
                    api_key = %s,
                    model = %s,
                    concurrency_limit = %s,
                    enabled = %s,
                    status = %s,
                    ordering = %s
                WHERE id = %s AND competition_id = %s AND pool_kind = %s
                """,
                (endpoint['harness'], endpoint['base_url'], endpoint['api_key'], endpoint['model'],
                 endpoint['concurrency_limit'], endpoint['enabled'], endpoint['status'],
                 endpoint['ordering'], endpoint['id'], competition_id, pool_kind),
            )
        else:
            cursor.execute(
                "INSERT INTO ranking_agent_judge_endpoints"
                " (competition_id, pool_kind, harness, base_url, api_key, model,"
                " concurrency_limit, enabled, status, ordering)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (competition_id, pool_kind, endpoint['harness'], endpoint['base_url'],
                 endpoint['api_key'], endpoint['model'], endpoint['concurrency_limit'],
                 endpoint['enabled'], endpoint['status'], endpoint['ordering']),
            )


def _save_endpoints(competition_id, pool_kind, items):
    """整体替换某比赛的单个端点池。校验在事务外，失败不动 DB。

    items 中每项：{id?, harness, base_url, api_key, model, concurrency_limit, status|enabled}。
    api_key 留空且带已存在的 id → 沿用旧 key（前端编辑器不回显明文）；
    api_key 留空且无对应 id → 报错（新端点必须填 key）。返回归一化后的列表。"""
    pool_kind = _normalize_endpoint_pool_kind(pool_kind)
    normalized = _normalize_endpoint_items(
        pool_kind,
        items,
        _list_endpoints(competition_id, pool_kind),
    )
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            _replace_endpoint_pool_with_cursor(
                cursor, competition_id, pool_kind, normalized,
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return normalized


def save_agent_judge_endpoints(competition_id, items):
    """整体替换主评测端点池；不会读取、修改或删除质量门禁池。"""
    return _save_endpoints(competition_id, ENDPOINT_POOL_PRIMARY, items)


def save_quality_gate_endpoints(competition_id, items):
    """整体替换质量门禁端点池；不会读取、修改或删除主评测池。"""
    return _save_endpoints(competition_id, ENDPOINT_POOL_QUALITY_GATE, items)


def save_reverse_quality_gate_configuration(
        competition_id, *, enabled=_QUALITY_GATE_UNSET,
        prompt=_QUALITY_GATE_UNSET, endpoints=_QUALITY_GATE_UNSET):
    """原子地部分更新质量门禁配置及其独立端点池。

    先锁定比赛配置与质量门禁端点，再按最终合并状态完成校验；端点正规化、
    旧密钥继承、端点池替换和比赛配置更新均处于同一事务，任何一步失败都会
    回滚。这样既避免半成功，也避免两个并发的部分更新互相覆盖。
    """
    competition_id = int(competition_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT reverse_quality_gate_enabled, reverse_quality_gate_prompt
                FROM ranking_competitions
                WHERE id = %s
                FOR UPDATE
                """,
                (competition_id,),
            )
            competition = cursor.fetchone()
            if not competition:
                raise ValueError('比赛不存在或已被删除')

            cursor.execute(
                """
                SELECT id, competition_id, pool_kind, harness, base_url, api_key, model,
                       concurrency_limit, enabled, status, ordering
                FROM ranking_agent_judge_endpoints
                WHERE competition_id = %s AND pool_kind = %s
                ORDER BY ordering ASC, id ASC
                FOR UPDATE
                """,
                (competition_id, ENDPOINT_POOL_QUALITY_GATE),
            )
            current_endpoints = [_endpoint_row(row) for row in (cursor.fetchall() or [])]

            merged_enabled = (
                bool(int(competition.get('reverse_quality_gate_enabled') or 0))
                if enabled is _QUALITY_GATE_UNSET else bool(enabled)
            )
            merged_prompt = (
                str(competition.get('reverse_quality_gate_prompt') or '')
                if prompt is _QUALITY_GATE_UNSET else str(prompt or '').strip()
            )
            if len(merged_prompt) > 20000:
                raise ValueError('审核标准不能超过 20000 字')

            normalized = current_endpoints
            if endpoints is not _QUALITY_GATE_UNSET:
                normalized = _normalize_endpoint_items(
                    ENDPOINT_POOL_QUALITY_GATE,
                    endpoints,
                    current_endpoints,
                )

            enabled_count = sum(
                1 for endpoint in normalized
                if endpoint.get('status') == ENDPOINT_STATUS_ENABLED
            )
            if merged_enabled and not merged_prompt.strip():
                raise ValueError('启用质量门禁前必须设置审核标准')
            if merged_enabled and enabled_count <= 0:
                raise ValueError('启用质量门禁前必须配置至少一个启用端点')

            if endpoints is not _QUALITY_GATE_UNSET:
                _replace_endpoint_pool_with_cursor(
                    cursor,
                    competition_id,
                    ENDPOINT_POOL_QUALITY_GATE,
                    normalized,
                )

            updates = []
            params = []
            if enabled is not _QUALITY_GATE_UNSET:
                updates.append('reverse_quality_gate_enabled = %s')
                params.append(1 if merged_enabled else 0)
            if prompt is not _QUALITY_GATE_UNSET:
                updates.append('reverse_quality_gate_prompt = %s')
                params.append(merged_prompt)
            if updates:
                params.append(competition_id)
                cursor.execute(
                    'UPDATE ranking_competitions SET ' + ', '.join(updates) + ' WHERE id = %s',
                    tuple(params),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        'enabled': merged_enabled,
        'prompt': merged_prompt,
        'enabled_endpoint_count': enabled_count,
    }


def replace_competition_rules(competition_id, rules):
    """整体替换某比赛的评分规则（先 normalize 校验 DAG，再删旧插新）。抛 ValueError 表示校验失败。"""
    normalized = aj.reindex_rules_by_order(rules)  # 校验在事务外，失败则不动 DB
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_judge_rules WHERE competition_id = %s",
                           (competition_id,))
            for r in normalized:
                cursor.execute(
                    """
                    INSERT INTO ranking_judge_rules
                        (competition_id, rule_id, rule_name, rule_text, value, dependencies, ordering)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (competition_id, r['rule_id'], r.get('rule_name') or None,
                     r['rule_text'], float(r['value']),
                     json.dumps(r['dependencies']), r['ordering']),
                )
        conn.commit()
    finally:
        conn.close()
    return normalized


def list_competition_rules(competition_id):
    """返回该比赛的规则列表（按 ordering），dependencies 已解析为 int 列表。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT rule_id, rule_name, rule_text, value, dependencies, ordering
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
        out.append({'rule_id': int(row['rule_id']), 'rule_name': row.get('rule_name') or '',
                    'rule_text': row['rule_text'],
                    'value': float(row['value']),
                    'dependencies': [int(d) for d in deps],
                    'ordering': int(row['ordering'] or 0)})
    return out


def upsert_judge_result(submission_id, rule_id, raw_result, effective_result, score, evidence):
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


def upsert_judge_result_for_attempt(submission_id, attempt_id, rule_id,
                                    raw_result, effective_result, score, evidence):
    """只在 submission 当前 attempt 未变化时写入规则结果，返回受影响行数。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ranking_judge_results
                    (submission_id, rule_id, raw_result, effective_result, score, evidence)
                SELECT %s, %s, %s, %s, %s, %s
                FROM ranking_submissions
                WHERE id = %s AND judge_attempt_id <=> %s
                ON DUPLICATE KEY UPDATE
                    raw_result = VALUES(raw_result),
                    effective_result = VALUES(effective_result),
                    score = VALUES(score),
                    evidence = VALUES(evidence)
                """,
                (submission_id, rule_id, raw_result, effective_result, float(score or 0),
                 (evidence or ''), submission_id, attempt_id),
            )
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
    finally:
        conn.close()


def list_judge_results(submission_id):
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
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM ranking_judge_results WHERE submission_id = %s",
                           (submission_id,))
        conn.commit()
    finally:
        conn.close()


def clear_judge_results_for_attempt(submission_id, attempt_id):
    """只在 submission 当前 attempt 未变化时清空规则结果，返回受影响行数。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                DELETE r
                FROM ranking_judge_results r
                JOIN ranking_submissions s ON s.id = r.submission_id
                WHERE r.submission_id = %s AND s.judge_attempt_id <=> %s
                """,
                (submission_id, attempt_id),
            )
            affected = cursor.rowcount
        conn.commit()
        return int(affected or 0)
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
    finalize = status not in ('Judging', 'Pending', 'Queued')
    computed = aj.compute_results(rules, raw_by_id, finalize=finalize) if rules else {}
    rule_payloads = []
    for r in rules:
        rid = r['rule_id']
        c = computed.get(rid, {'effective': aj.EFF_PENDING, 'score': 0.0})
        evidence = evidence_by_id.get(rid, '')
        # 仅存 markdown 源（rule_text / evidence）；HTML 在前端请求时实时渲染（见 render_snapshot_html）
        rule_payloads.append({
            'rule_id': rid, 'rule_name': r.get('rule_name') or '',
            'rule_text': r['rule_text'], 'value': float(r['value']),
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
