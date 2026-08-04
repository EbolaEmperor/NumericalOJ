#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛 Agent-as-Judge 的 DB 层：评分规则表 + 逐条结果表 + 快照构造。"""
import hashlib
import json
import os
import re
import time

from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.ranking.db import get_ranking_submission, submission_dir
from oj_modules.ranking.agent_judge import rules as aj
from oj_modules.ranking.reverse_judge.traces import (
    collect_agent_token_usage,
    collect_agent_trace_files,
    collect_agent_trace_messages,
)

_aj_tables_ready = False

HARNESS_CLAUDE_CODE = 'claude_code'
HARNESS_CODEX = 'codex'
HARNESS_OPENCODE = 'opencode'
HARNESS_PI = 'pi'
ALLOWED_AGENT_HARNESSES = (
    HARNESS_CLAUDE_CODE,
    HARNESS_CODEX,
    HARNESS_OPENCODE,
    HARNESS_PI,
)
ENDPOINT_PROTOCOL_OPENAI = 'openai'
ENDPOINT_PROTOCOL_ANTHROPIC = 'anthropic'
ALLOWED_ENDPOINT_PROTOCOLS = (
    ENDPOINT_PROTOCOL_OPENAI,
    ENDPOINT_PROTOCOL_ANTHROPIC,
)
DEFAULT_ENDPOINT_CONTEXT_WINDOW_TOKENS = 1_000_000
DEFAULT_ENDPOINT_MAX_OUTPUT_TOKENS = 384_000
DEFAULT_ENDPOINT_THINKING_COMPATIBILITY = True
ENDPOINT_THINKING_FORMATS = frozenset((
    'enable_thinking',
    'thinking_type',
    'none',
))
MAX_ENDPOINT_TOKEN_COUNT = 1_000_000
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
_AGENT_TRACE_SUBDIR = 'agent_judge_trace'


def normalize_agent_harness(value):
    harness = str(value or '').strip().lower().replace('-', '_')
    if harness == 'pi_agent':
        harness = HARNESS_PI
    return harness if harness in ALLOWED_AGENT_HARNESSES else HARNESS_CLAUDE_CODE


def allowed_agent_endpoint_protocols(harness):
    """返回 harness 实际支持的上游协议。"""

    harness = normalize_agent_harness(harness)
    if harness == HARNESS_CLAUDE_CODE:
        return (ENDPOINT_PROTOCOL_ANTHROPIC,)
    if harness in (HARNESS_CODEX, HARNESS_OPENCODE):
        return (ENDPOINT_PROTOCOL_OPENAI,)
    return ALLOWED_ENDPOINT_PROTOCOLS


def infer_agent_endpoint_protocol(harness, protocol=None):
    """解析有效协议；旧 NULL 记录保持历史 harness 推断。"""

    normalized = str(protocol or '').strip().lower()
    if normalized in ALLOWED_ENDPOINT_PROTOCOLS:
        return normalized
    harness = normalize_agent_harness(harness)
    if harness == HARNESS_CLAUDE_CODE:
        return ENDPOINT_PROTOCOL_ANTHROPIC
    # Codex、opencode 以及历史 Pi 都一直走 OpenAI 兼容链路。
    return ENDPOINT_PROTOCOL_OPENAI


def _normalize_endpoint_protocol(value, *, harness, existing_endpoint=None):
    existing_endpoint = existing_endpoint or {}
    supplied = value is not None and str(value).strip() != ''
    if supplied:
        protocol = str(value).strip().lower()
        if protocol not in ALLOWED_ENDPOINT_PROTOCOLS:
            raise ValueError('端点协议必须是 openai 或 anthropic')
        if protocol not in allowed_agent_endpoint_protocols(harness):
            raise ValueError(f'{normalize_agent_harness(harness)} 不支持 {protocol} 协议')
        return protocol

    # 编辑旧记录时保留真正的 NULL，不把“兼容推断”悄悄写回数据库。
    if existing_endpoint:
        existing_protocol = existing_endpoint.get('protocol')
        if str(existing_protocol or '').strip().lower() in ALLOWED_ENDPOINT_PROTOCOLS:
            existing_protocol = str(existing_protocol).strip().lower()
            if existing_protocol not in allowed_agent_endpoint_protocols(harness):
                raise ValueError(
                    f'{normalize_agent_harness(harness)} 不支持 {existing_protocol} 协议'
                )
            return existing_protocol
        return None

    if normalize_agent_harness(harness) == HARNESS_PI:
        raise ValueError('新 Pi 端点必须明确选择 openai 或 anthropic 协议')
    return allowed_agent_endpoint_protocols(harness)[0]


def _get_global_endpoint_for_copy(endpoint_id):
    from oj_modules.site_config.services import get_llm_endpoint

    return get_llm_endpoint(endpoint_id, include_secret=True)


def list_global_endpoints_for_agent_harness(harness, endpoints=None):
    """返回可复制到指定 harness 的全局候选，且绝不包含密钥。"""

    harness = normalize_agent_harness(harness)
    if endpoints is None:
        from oj_modules.site_config.services import list_llm_endpoints

        endpoints = list_llm_endpoints(include_secrets=False)
    allowed_protocols = set(allowed_agent_endpoint_protocols(harness))
    candidates = []
    for endpoint in endpoints or []:
        category = str(endpoint.get('category') or '').strip().lower()
        protocol = str(endpoint.get('protocol') or '').strip().lower()
        if category not in {'omni', 'text'} or protocol not in allowed_protocols:
            continue
        candidates.append({
            'id': int(endpoint['id']),
            'protocol': protocol,
            'category': category,
            'base_url': str(endpoint.get('base_url') or '').strip(),
            'model': str(endpoint.get('model') or '').strip(),
            'thinking_enabled': bool(endpoint.get('thinking_enabled')),
            'thinking_format': str(endpoint.get('thinking_format') or 'none'),
        })
    return candidates


def global_agent_endpoint_candidates():
    """一次查询生成各 harness 的安全候选上下文。"""

    from oj_modules.site_config.services import list_llm_endpoints

    endpoints = list_llm_endpoints(include_secrets=False)
    return {
        harness: list_global_endpoints_for_agent_harness(harness, endpoints=endpoints)
        for harness in ALLOWED_AGENT_HARNESSES
    }


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


def _strict_bool(value, field_name):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ('1', 'true'):
            return True
        if normalized in ('0', 'false'):
            return False
    raise ValueError(f'{field_name} 必须是布尔值')


def _positive_integer(value, field_name):
    error_message = (
        f'{field_name} 必须是正整数且不超过 {MAX_ENDPOINT_TOKEN_COUNT}'
    )
    if isinstance(value, bool):
        raise ValueError(error_message)
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r'[0-9]+', value.strip()):
        parsed = int(value.strip())
    else:
        raise ValueError(error_message)
    if parsed <= 0 or parsed > MAX_ENDPOINT_TOKEN_COUNT:
        raise ValueError(error_message)
    return parsed


def normalize_endpoint_model_capabilities(payload, existing_endpoint=None):
    """归一化端点的模型容量与 thinking 兼容配置。

    编辑已有端点时，旧客户端省略新字段必须沿用数据库中的值；新增端点省略
    字段则使用稳定默认值。显式传入的值始终严格校验，不把非法输入静默改写。
    """
    payload = payload or {}
    existing_endpoint = existing_endpoint or {}

    if 'context_window_tokens' in payload:
        context_window_tokens = _positive_integer(
            payload.get('context_window_tokens'), '上下文窗口',
        )
    else:
        context_window_tokens = _positive_integer(
            existing_endpoint.get(
                'context_window_tokens',
                DEFAULT_ENDPOINT_CONTEXT_WINDOW_TOKENS,
            ),
            '上下文窗口',
        )

    if 'max_output_tokens' in payload:
        max_output_tokens = _positive_integer(
            payload.get('max_output_tokens'), '最大输出 Token 数',
        )
    else:
        max_output_tokens = _positive_integer(
            existing_endpoint.get(
                'max_output_tokens', DEFAULT_ENDPOINT_MAX_OUTPUT_TOKENS,
            ),
            '最大输出 Token 数',
        )

    if max_output_tokens > context_window_tokens:
        raise ValueError('最大输出 Token 数不能超过上下文窗口')

    if 'thinking_compatibility' in payload:
        thinking_compatibility = _strict_bool(
            payload.get('thinking_compatibility'), 'Thinking 兼容',
        )
    else:
        thinking_compatibility = _strict_bool(
            existing_endpoint.get(
                'thinking_compatibility',
                DEFAULT_ENDPOINT_THINKING_COMPATIBILITY,
            ),
            'Thinking 兼容',
        )

    return {
        'context_window_tokens': context_window_tokens,
        'max_output_tokens': max_output_tokens,
        'thinking_compatibility': thinking_compatibility,
    }


def default_endpoint_thinking_format(protocol, thinking_compatibility):
    """只按协议与显式能力开关生成统一 wire contract。"""

    if not thinking_compatibility:
        return 'none'
    if protocol == ENDPOINT_PROTOCOL_ANTHROPIC:
        return 'thinking_type'
    return 'enable_thinking'


def normalize_endpoint_thinking_format(
        value, *, protocol, thinking_compatibility, field_provided=False):
    """归一化协议级思考字段，不读取 URL、厂商或模型名。"""

    normalized = str(value or '').strip().lower()
    if not normalized:
        return default_endpoint_thinking_format(
            protocol,
            thinking_compatibility,
        )
    if normalized not in ENDPOINT_THINKING_FORMATS:
        if field_provided:
            raise ValueError(
                '思考参数格式必须是 enable_thinking、thinking_type 或 none'
            )
        return default_endpoint_thinking_format(
            protocol,
            thinking_compatibility,
        )
    if (
        protocol == ENDPOINT_PROTOCOL_ANTHROPIC
        and normalized == 'enable_thinking'
    ):
        raise ValueError('Anthropic 端点不能使用 enable_thinking 思考格式')
    return normalized


def _normalize_endpoint_pool_kind(value):
    pool_kind = str(value or '').strip().lower()
    return pool_kind if pool_kind in ENDPOINT_POOL_KINDS else ENDPOINT_POOL_PRIMARY


def _endpoint_row(row):
    status = normalize_endpoint_status(
        row.get('status'),
        fallback_enabled=bool(int(row.get('enabled') or 0)),
    )
    raw_protocol = str(row.get('protocol') or '').strip().lower() or None
    harness = normalize_agent_harness(row.get('harness'))
    effective_protocol = infer_agent_endpoint_protocol(harness, raw_protocol)
    thinking_compatibility = bool(int(
        row.get('thinking_compatibility')
        if row.get('thinking_compatibility') is not None
        else DEFAULT_ENDPOINT_THINKING_COMPATIBILITY
    ))
    thinking_format = normalize_endpoint_thinking_format(
        row.get('thinking_format'),
        protocol=effective_protocol,
        thinking_compatibility=thinking_compatibility,
    )
    return {
        'id': int(row['id']),
        'competition_id': int(row.get('competition_id') or 0),
        'pool_kind': _normalize_endpoint_pool_kind(row.get('pool_kind')),
        'harness': harness,
        'protocol': raw_protocol,
        'effective_protocol': effective_protocol,
        'base_url': row['base_url'] or '',
        'api_key': row['api_key'] or '',
        'model': (row.get('model') or ''),
        'context_window_tokens': int(
            row.get('context_window_tokens') or DEFAULT_ENDPOINT_CONTEXT_WINDOW_TOKENS
        ),
        'max_output_tokens': int(
            row.get('max_output_tokens') or DEFAULT_ENDPOINT_MAX_OUTPUT_TOKENS
        ),
        'thinking_compatibility': thinking_compatibility,
        'thinking_format': thinking_format,
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
            sql = ("SELECT id, competition_id, pool_kind, harness, protocol, base_url, api_key, model,"
                   " context_window_tokens, max_output_tokens, thinking_compatibility, thinking_format,"
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
                SELECT id, competition_id, pool_kind, harness, protocol, base_url, api_key, model,
                       context_window_tokens, max_output_tokens, thinking_compatibility, thinking_format,
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
    """归一化一个端点池，保留旧密钥/NULL 协议并支持从全局端点复制。"""
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
        eid = it.get('id')
        try:
            eid = int(eid) if eid not in (None, '', 'null') else None
        except (TypeError, ValueError):
            eid = None
        if eid in existing:
            if eid in seen_existing_ids:
                raise ValueError(f'端点 ID {eid} 重复')
            seen_existing_ids.add(eid)

        source_endpoint_id = (
            it.get('global_endpoint_id')
            if it.get('global_endpoint_id') not in (None, '', 'null')
            else it.get('source_global_endpoint_id')
        )
        source_endpoint = None
        if source_endpoint_id not in (None, '', 'null'):
            if eid in existing:
                raise ValueError('只能在新建独立端点时从全局端点复制')
            try:
                source_endpoint_id = int(source_endpoint_id)
            except (TypeError, ValueError) as exc:
                raise ValueError('全局端点 ID 不合法') from exc
            if source_endpoint_id <= 0:
                raise ValueError('全局端点 ID 不合法')
            source_endpoint = _get_global_endpoint_for_copy(source_endpoint_id)
            if not source_endpoint:
                raise ValueError(f'全局端点不存在（ID: {source_endpoint_id}）')
            source_category = str(source_endpoint.get('category') or '').strip().lower()
            if source_category not in {'omni', 'text'}:
                raise ValueError('Agent 端点只能从全模态或纯文本全局端点复制')
            source_protocol = str(source_endpoint.get('protocol') or '').strip().lower()
            if source_protocol not in allowed_agent_endpoint_protocols(harness):
                raise ValueError(f'{harness} 不支持所选全局端点的 {source_protocol} 协议')

        existing_endpoint = existing.get(eid) or {}
        protocol_input = (
            source_endpoint.get('protocol') if source_endpoint else it.get('protocol')
        )
        protocol = _normalize_endpoint_protocol(
            protocol_input,
            harness=harness,
            existing_endpoint=existing_endpoint,
        )
        effective_protocol = infer_agent_endpoint_protocol(harness, protocol)

        base_url = str(
            source_endpoint.get('base_url') if source_endpoint else it.get('base_url') or ''
        ).strip()
        if not base_url:
            raise ValueError('端点 URL 不能为空')
        if not (base_url.startswith('http://') or base_url.startswith('https://')):
            raise ValueError(f'端点 URL 必须以 http(s):// 开头：{base_url[:60]}')
        if len(base_url) > 512:
            raise ValueError('端点 URL 过长（不超过 512 字）')
        key_in = str(
            source_endpoint.get('api_key') if source_endpoint else it.get('api_key') or ''
        ).strip()
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
        model = (
            str(source_endpoint.get('model') if source_endpoint else it.get('model') or '').strip()
            or None
        )
        if not model:
            raise ValueError('端点模型不能为空')
        if model and len(model) > 128:
            raise ValueError('模型名过长（不超过 128 字）')
        capability_payload = dict(it)
        if source_endpoint is not None:
            # 把全局端点当时的开关与 wire format 一并冻结到独立副本。
            capability_payload['thinking_compatibility'] = bool(
                source_endpoint.get('thinking_enabled')
            )
        model_options = normalize_endpoint_model_capabilities(
            capability_payload, existing_endpoint,
        )
        if source_endpoint is not None:
            raw_thinking_format = source_endpoint.get('thinking_format')
            format_was_provided = True
        elif 'thinking_format' in it:
            raw_thinking_format = it.get('thinking_format')
            format_was_provided = True
        else:
            raw_thinking_format = existing_endpoint.get('thinking_format')
            format_was_provided = False
        thinking_format = normalize_endpoint_thinking_format(
            raw_thinking_format,
            protocol=effective_protocol,
            thinking_compatibility=model_options['thinking_compatibility'],
            field_provided=format_was_provided,
        )
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
                           'harness': harness, 'protocol': protocol,
                           'effective_protocol': effective_protocol,
                           'base_url': base_url, 'api_key': api_key, 'model': model,
                           **model_options,
                           'thinking_format': thinking_format,
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
                    protocol = %s,
                    base_url = %s,
                    api_key = %s,
                    model = %s,
                    context_window_tokens = %s,
                    max_output_tokens = %s,
                    thinking_compatibility = %s,
                    thinking_format = %s,
                    concurrency_limit = %s,
                    enabled = %s,
                    status = %s,
                    ordering = %s
                WHERE id = %s AND competition_id = %s AND pool_kind = %s
                """,
                (endpoint['harness'], endpoint.get('protocol'), endpoint['base_url'], endpoint['api_key'], endpoint['model'],
                 endpoint['context_window_tokens'], endpoint['max_output_tokens'],
                 1 if endpoint['thinking_compatibility'] else 0,
                 endpoint.get('thinking_format'),
                 endpoint['concurrency_limit'], endpoint['enabled'], endpoint['status'],
                 endpoint['ordering'], endpoint['id'], competition_id, pool_kind),
            )
        else:
            cursor.execute(
                "INSERT INTO ranking_agent_judge_endpoints"
                " (competition_id, pool_kind, harness, protocol, base_url, api_key, model,"
                " context_window_tokens, max_output_tokens, thinking_compatibility, thinking_format,"
                " concurrency_limit, enabled, status, ordering)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (competition_id, pool_kind, endpoint['harness'], endpoint.get('protocol'), endpoint['base_url'],
                 endpoint['api_key'], endpoint['model'], endpoint['context_window_tokens'],
                 endpoint['max_output_tokens'], 1 if endpoint['thinking_compatibility'] else 0,
                 endpoint.get('thinking_format'),
                 endpoint['concurrency_limit'],
                 endpoint['enabled'], endpoint['status'], endpoint['ordering']),
            )


def _save_endpoints(competition_id, pool_kind, items):
    """整体替换某比赛的单个端点池。校验在事务外，失败不动 DB。

    items 中每项：{id?, harness, protocol?, global_endpoint_id?, base_url, api_key,
    model, context_window_tokens?, max_output_tokens?, thinking_compatibility?,
    thinking_format?,
    concurrency_limit, status|enabled}。
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


def save_agent_judge_configuration(
        competition_id, items, *, timeout_seconds=None,
        reverse_finalize_timeout_seconds=None, orchestration_mode=None):
    """原子保存主端点池及同页比赛设置，任何校验失败均不产生部分更新。"""
    competition_id = int(competition_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM ranking_competitions WHERE id = %s FOR UPDATE",
                (competition_id,),
            )
            if not cursor.fetchone():
                raise ValueError('比赛不存在或已被删除')
            cursor.execute(
                """
                SELECT id, competition_id, pool_kind, harness, protocol, base_url, api_key, model,
                       context_window_tokens, max_output_tokens, thinking_compatibility, thinking_format,
                       concurrency_limit, enabled, status, ordering
                FROM ranking_agent_judge_endpoints
                WHERE competition_id = %s AND pool_kind = %s
                ORDER BY ordering ASC, id ASC
                FOR UPDATE
                """,
                (competition_id, ENDPOINT_POOL_PRIMARY),
            )
            existing = [_endpoint_row(row) for row in (cursor.fetchall() or [])]
            normalized = _normalize_endpoint_items(
                ENDPOINT_POOL_PRIMARY, items, existing,
            )
            _replace_endpoint_pool_with_cursor(
                cursor, competition_id, ENDPOINT_POOL_PRIMARY, normalized,
            )

            assignments = []
            params = []
            if timeout_seconds is not None:
                assignments.append('agent_judge_timeout_seconds = %s')
                params.append(int(timeout_seconds))
            if reverse_finalize_timeout_seconds is not None:
                assignments.append('reverse_judge_finalize_timeout_seconds = %s')
                params.append(int(reverse_finalize_timeout_seconds))
            if orchestration_mode is not None:
                assignments.append('agent_judge_orchestration_mode = %s')
                params.append(aj.normalize_orchestration_mode(orchestration_mode))
            if assignments:
                cursor.execute(
                    'UPDATE ranking_competitions SET '
                    + ', '.join(assignments)
                    + ' WHERE id = %s',
                    tuple(params + [competition_id]),
                )
        conn.commit()
        return normalized
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


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
                SELECT id, competition_id, pool_kind, harness, protocol, base_url, api_key, model,
                       context_window_tokens, max_output_tokens, thinking_compatibility, thinking_format,
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


def _safe_attempt_component(attempt_id):
    value = str(attempt_id or 'legacy').strip()
    value = re.sub(r'[^A-Za-z0-9_.-]+', '_', value).strip('._')
    return value[:96] or 'legacy'


def agent_judge_trace_dir(submission_id, attempt_id):
    """返回当前评测 attempt 的受信任轨迹目录。

    目录不在选手 ZIP 解压出的 workspace 内，不能被附件预置；attempt 隔离也保证
    旧 worker 无法把上一轮轨迹混入重测后的评分详情。
    """
    return os.path.join(
        submission_dir(int(submission_id)),
        _AGENT_TRACE_SUBDIR,
        _safe_attempt_component(attempt_id),
    )


def agent_judge_trace_id(attempt_id):
    """返回可安全下发给前端的 attempt 标识，不暴露数据库中的原始 UUID。"""
    value = str(attempt_id or 'legacy').encode('utf-8', 'replace')
    return hashlib.sha256(value).hexdigest()[:16]


def _execution_trace_status(submission_status):
    status = str(submission_status or '')
    if status in ('Judging', 'Pending', 'Queued'):
        return 'running' if status == 'Judging' else 'pending'
    if status == 'Accepted':
        return 'passed'
    if status == 'Error':
        return 'error'
    return 'pending'


def _build_execution_trace_payload(submission):
    trace_dir = agent_judge_trace_dir(
        submission.get('id'), submission.get('judge_attempt_id'),
    )
    return {
        'trace_id': agent_judge_trace_id(submission.get('judge_attempt_id')),
        'status': _execution_trace_status(submission.get('status')),
        'error_message': submission.get('error_message') or '',
        'stdout': '',
        'stderr': '',
        'trace_files': collect_agent_trace_files(trace_dir),
        'trace_messages': collect_agent_trace_messages(trace_dir),
        'token_usage': collect_agent_token_usage(trace_dir),
    }


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
        'attempt_trace_id': agent_judge_trace_id(submission.get('judge_attempt_id')),
        'status': status,
        'error_message': submission.get('error_message') or '',
        'max_score': aj.max_score(rules) if rules else 0.0,
        'total_score': aj.total_score(computed) if computed else 0.0,
        'timed_out': timed_out,
        'rules': rule_payloads,
        'execution_trace': _build_execution_trace_payload(submission),
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
