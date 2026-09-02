#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import logging
import re
import time
from datetime import datetime
from io import BytesIO
from uuid import uuid4
from urllib.parse import quote

from flask import Blueprint, Response, current_app, flash, jsonify, redirect, request, send_file, stream_with_context, url_for
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from backend.oj_modules.db_services import (
    SubmissionLimitExceeded,
    archive_submission_by_id,
    archive_submission_file_by_id,
    can_submit,
    create_submission,
    get_agent_run_by_task_id,
    get_db_connection,
    get_latest_written_submission,
    get_problem,
    mark_submission_archive_failed,
    overwrite_written_submission,
    upsert_agent_run_snapshot,
)
from backend.oj_modules.agents.sessions import (
    AgentSessionMessageConflictError,
    AgentSessionMessageNotFoundError,
    AgentSessionBusyError,
    AgentSessionNotFoundError,
    agent_status_is_terminal,
    begin_agent_session_retry,
    begin_agent_session_turn,
    cancel_queued_agent_session_message,
    create_agent_session,
    continue_agent_session_queue,
    enqueue_agent_session_message,
    get_agent_session,
    get_agent_session_by_task_id,
    get_agent_session_message,
    get_agent_session_turns,
    get_agent_session_queue_snapshot,
    get_agent_sessions_paginated,
    list_agent_session_messages,
    mark_agent_turn_enqueue_failed,
    mark_agent_turn_runtime_restore_failed,
    normalize_agent_message_id,
    reorder_queued_agent_session_messages,
    steer_queued_agent_session_message,
    update_queued_agent_session_message,
    normalize_agent_access_role,
    rename_agent_session_title,
)
from backend.oj_modules.agents.quota import (
    AgentQuotaError,
    get_agent_quota_summary,
    get_agent_runtime_quota_summary,
    get_agent_session_token_usage,
    list_pending_agent_quota_requests,
    require_agent_start_eligibility,
)
from backend.oj_modules.agents.user_endpoints import list_user_agent_endpoints
from backend.oj_modules.agents.runtime_checkpoints import (
    create_agent_runtime_checkpoint,
    create_empty_agent_runtime_checkpoint,
    remove_agent_runtime_checkpoint,
    restore_agent_runtime_checkpoint,
)
from backend.oj_modules.agents.workspace import (
    build_agent_workspace_tree,
    clear_agent_session_state_file,
    initialize_agent_task_workspace,
    inspect_agent_workspace_file,
    open_agent_workspace_file,
    remove_agent_attachments,
    save_agent_attachments,
)
from backend.oj_modules.agents.trace_store import (
    get_agent_trace_work_block,
    get_last_agent_trace_assistant,
)
from backend.oj_modules.security.auth import current_user, is_admin
from backend.oj_modules.infrastructure.mysql import MySQLPoolExhausted
from backend.oj_modules.shared.sse import (
    guard_sse_stream,
    sse_capacity_response,
    try_acquire_sse_slot,
)
from backend.oj_modules.project_paths import PROJECT_ROOT
from backend.oj_modules.problems.lean_workspace import (
    LeanWorkspaceError,
    LeanWorkspaceStaleError,
    normalize_lean_submission_payload,
)
from backend.oj_modules.classroom.dashboard import (
    get_class_activity,
    get_layout_navigation_context,
    select_visible_class,
    visible_classes_for_user_cached,
)
from backend.oj_modules.problems.agent_runs import (
    aggregate_agent_session_token_usage,
    hydrate_agent_run_snapshot,
)
from backend.oj_modules.problems.agent_launch import (
    AgentLaunchValidationError,
    build_solution_agent_prompt,
    build_testdata_agent_prompt,
    default_reasoning_effort_for_harness,
    harness_options,
    list_launch_endpoints_by_harness,
    normalize_agent_task_kind,
    normalize_agent_reasoning_effort,
    normalize_launch_harness,
    reasoning_effort_options_by_harness,
    resolve_launch_endpoint,
)
from backend.oj_modules.site_config.services import DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
from backend.oj_modules.problems.agent_preferences import (
    get_agent_launch_preference,
    save_agent_launch_preference,
)
from backend.oj_modules.problems.catalog import get_user_classes_cached
from backend.oj_modules.problems.context import (
    build_homework_deadline_warning,
    build_problem_detail_context,
    get_problem_homework_assignments,
)
from backend.oj_modules.problems.presentation import (
    strip_problem_title_tags as _strip_problem_title_tags,
)
from backend.oj_modules.submissions.written_artifacts import (
    WrittenSubmissionArtifactError,
    publish_manual_written_submission,
)
from backend.oj_modules.shared.markdown import render_rich_markdown
from backend.oj_modules.shared.archive import build_directory_zip
problem_core_bp = Blueprint('problem_core', __name__)
logger = logging.getLogger(__name__)

_evaluate_submission_task = None
_promptly_generate_submission_task = None
_transcribe_written_homework_task = None
_agent_solve_problem_task = None
_agent_generate_testdata_task = None
_agent_run_turn_task = None
_agent_queue_dispatch_task = None
_get_agent_run_snapshot = None
_subscribe_agent_run_events = None
_terminate_agent_run = None
read_agent_steer_capability = lambda _session_id, _harness: (
    False,
    '当前 Harness 的插话能力状态不可用',
)


def _parse_agent_test_point_count(value):
    if type(value) is int:
        count = value
    elif type(value) is str and re.fullmatch(r"[1-9][0-9]*", value):
        count = int(value)
    else:
        raise ValueError("测试点数量无效")
    if count < 1:
        raise ValueError("测试点数量必须是正整数")
    return count


def _read_agent_standard_solution(upload):
    raw_filename = str(getattr(upload, 'filename', '') or '').strip()
    if not raw_filename:
        raise ValueError('请选择标准程序文件')

    basename = raw_filename.replace('\\', '/').rsplit('/', 1)[-1]
    safe_filename = secure_filename(basename)
    suffix = secure_filename(os.path.splitext(basename)[1].lstrip('.')).lower()
    if suffix and '.' not in safe_filename:
        safe_filename = f'standard_solution.{suffix}'
    if not safe_filename:
        safe_filename = 'standard_solution.txt'
    if len(safe_filename.encode('utf-8')) > 240:
        safe_filename = f"standard_solution.{suffix or 'txt'}"

    try:
        payload = upload.stream.read()
    except OSError as exc:
        raise ValueError('无法读取标准程序文件') from exc
    if not payload:
        raise ValueError('标准程序文件不能为空')
    try:
        source = payload.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise ValueError('标准程序文件必须是 UTF-8 文本') from exc
    if '\x00' in source:
        raise ValueError('标准程序文件不能包含 NUL 字符')
    if not source.strip():
        raise ValueError('标准程序文件不能为空')
    return source, safe_filename


_AGENT_MESSAGE_MAX_CHARS = 100_000
_AGENT_MESSAGE_STREAM_POLL_INTERVAL_SECONDS = 2.0
_AGENT_MESSAGE_STREAM_QUOTA_REFRESH_INTERVAL_SECONDS = 10.0
_AGENT_MESSAGE_STREAM_OVERLOAD_RETRY_SECONDS = 5.0


def _agent_actor(user=None):
    """返回 Agent 路由统一使用的登录主体，便于叠加额度等策略。"""

    actor_user = user if user is not None else current_user()
    if not actor_user:
        return None
    return {
        "user": actor_user,
        "username": str(actor_user.get("username") or ""),
        "is_admin": int(actor_user.get("is_admin") or 0) == 1,
    }


def _agent_actor_can_view_session(actor, agent_session):
    if not actor or not agent_session:
        return False
    return bool(
        actor["is_admin"]
        or str(agent_session.get("requested_by") or "") == actor["username"]
    )


def _agent_session_for_actor(session_id, actor):
    """读取会话并收紧普通用户的可见范围；管理员可查看全站会话。"""

    try:
        agent_session = get_agent_session(session_id)
    except ValueError:
        agent_session = None
    if not agent_session:
        raise AgentSessionMessageNotFoundError("Agent 会话不存在")
    if not _agent_actor_can_view_session(actor, agent_session):
        raise PermissionError("只能查看自己发起的 Agent 会话")
    return agent_session


def _agent_task_for_actor(task_id, actor, *, allow_unknown_for_admin=False):
    """把单轮 task 映射到所属会话后执行统一所有权校验。"""

    if actor and actor["is_admin"] and allow_unknown_for_admin:
        return None
    try:
        agent_session = (
            get_agent_session_by_task_id(task_id)
            or get_agent_session(task_id)
        )
    except ValueError:
        agent_session = None
    if not agent_session:
        if actor and actor["is_admin"] and allow_unknown_for_admin:
            return None
        raise AgentSessionMessageNotFoundError("Agent 任务不存在")
    if not _agent_actor_can_view_session(actor, agent_session):
        raise PermissionError("只能查看自己发起的 Agent 任务")
    return agent_session


def _agent_session_cookie():
    cookie_name = str(current_app.config.get('SESSION_COOKIE_NAME') or 'session')
    session_cookie = str(request.cookies.get(cookie_name) or '')
    if not session_cookie:
        raise ValueError('当前登录身份不可用于 Agent')
    return cookie_name, session_cookie


def _agent_launch_page_options(user_id):
    endpoints_by_harness = list_launch_endpoints_by_harness(user_id=user_id)
    preference = get_agent_launch_preference(user_id) or {}
    preferred_harness = str(preference.get('harness') or '')
    preferred_endpoint_ref = str(preference.get('endpoint_ref') or '')
    valid = any(
        str(item.get('ref') or '') == preferred_endpoint_ref
        for item in endpoints_by_harness.get(preferred_harness, [])
    )
    if not valid:
        preferred_harness = next(
            (
                option['value']
                for option in harness_options()
                if endpoints_by_harness.get(option['value'])
            ),
            '',
        )
        candidates = endpoints_by_harness.get(preferred_harness, [])
        preferred_endpoint_ref = str(candidates[0].get('ref') or '') if candidates else ''
    return {
        'harnesses': harness_options(),
        'endpoints_by_harness': endpoints_by_harness,
        'reasoning_efforts_by_harness': reasoning_effort_options_by_harness(),
        'preference': {
            'harness': preferred_harness,
            'endpoint_id': preferred_endpoint_ref or None,
        },
    }


def _resolve_agent_endpoint_for_user(harness, endpoint_ref, user_id, *, include_secret):
    kwargs = {'include_secret': include_secret}
    if str(endpoint_ref or '').strip().startswith('user:'):
        kwargs['user_id'] = user_id
    return resolve_launch_endpoint(harness, endpoint_ref, **kwargs)


def _agent_quota_gate(user, *, endpoint_source):
    return require_agent_start_eligibility(
        user['id'],
        is_admin=int(user.get('is_admin') or 0) == 1,
        uses_personal_endpoint=str(endpoint_source or 'global') == 'user',
    )


def _agent_quota_error_response(exc):
    return jsonify(
        success=False,
        message=str(exc),
        code=getattr(exc, 'code', 'agent_quota_error'),
        decision=getattr(exc, 'decision', None),
    ), getattr(exc, 'status_code', 403)


def _agent_message_from_request():
    message = str(request.form.get('message') or '').strip()
    if not message:
        raise ValueError('请输入任务内容')
    if len(message) > _AGENT_MESSAGE_MAX_CHARS:
        raise ValueError(f'任务内容不能超过 {_AGENT_MESSAGE_MAX_CHARS} 个字符')
    return message


def _agent_client_message_id(*, generate=True):
    raw = str(request.form.get('message_id') or '').strip()
    if raw:
        return normalize_agent_message_id(raw)
    return uuid4().hex if generate else ''


def _agent_runtime_checkpoint_generation_id(message_id):
    """为一次 HTTP 尝试分配只属于它的 runtime checkpoint 名称。

    ``message_id`` 是客户端幂等键，两个相同请求可以在第一个事务提交前并发
    到达。如果直接把它当 checkpoint 名称，后到请求会把先到请求创建的目录
    误判为自己的失败产物并在补偿时删除。独立 generation 让每个请求只能
    清理自己创建的 checkpoint；最终由 turn 事务保存的 ID 才是权威引用。
    """

    owner = normalize_agent_message_id(message_id)
    return f"{owner[:31]}-{uuid4().hex}"


def _agent_prompt_with_attachments(message, attachments):
    entries = [
        str(item.get('path') or '').strip()
        for item in attachments or []
        if isinstance(item, dict) and str(item.get('path') or '').strip()
    ]
    if not entries:
        return str(message or '')
    paths = '\n'.join(f'- /workspace/{path}' for path in entries)
    return (
        f"{str(message or '').strip()}\n\n"
        "用户随本轮消息上传了以下附件，文件已经放入 workspace。"
        "请在需要时直接读取：\n"
        f"{paths}"
    )


def _agent_state_display_conclusion(state, stored_conclusion):
    """新版任务从 v2 事件表读取 conclude，不回退旧 JSONL。"""

    stored = str(stored_conclusion or '').strip()
    if stored:
        return stored
    if str((state or {}).get('status') or '').strip().lower() != 'completed':
        return ''
    task_id = str((state or {}).get('task_id') or '').strip()
    traced = ''
    if task_id:
        try:
            traced = get_last_agent_trace_assistant(task_id)
        except Exception:
            logger.warning(
                '读取 Agent v2 conclude 失败',
                extra={'task_id': task_id},
                exc_info=True,
            )
    return traced


_AGENT_PUBLIC_TRACE_KINDS = frozenset({
    'assistant', 'user', 'work_summary',
})
_AGENT_RICH_TRACE_KINDS = frozenset({'assistant', 'user'})
_AGENT_TRACE_STABLE_MESSAGE_FIELDS = (
    'kind',
    'type',
    'title',
    'name',
    'tool_name',
    'text',
    'content',
    'input',
    'output',
    'meta',
    'format',
    'is_error',
    'message_id',
    'attachments',
    'item_id',
    'item_index',
    'block_id',
    'summary',
    'thinking_count',
    'tool_count',
    'is_running',
    'has_error',
    'event_count',
    'last_event_order',
)


def _agent_trace_text(message):
    if not isinstance(message, dict):
        return ''
    value = message.get('text')
    if value is None:
        value = message.get('content')
    return str(value or '')


def _agent_trace_messages(trace):
    if not isinstance(trace, dict):
        return []
    messages = trace.get('trace_messages') or []
    return messages if isinstance(messages, list) else []


def _agent_trace_harness(state, fallback=''):
    if isinstance(state, dict):
        harness = str(state.get('harness') or '').strip().lower()
        if harness:
            return harness
        trace = state.get('execution_trace')
        usage = trace.get('token_usage') if isinstance(trace, dict) else None
        if isinstance(usage, dict):
            source = str(usage.get('source') or '').strip().lower()
            if source:
                return source
    return str(fallback or '').strip().lower()


def _agent_trace_message_signature(message):
    """返回不含 HTML 与日志位置的稳定展示消息签名。"""

    if not isinstance(message, dict):
        return ''
    stable = {
        field: message.get(field)
        for field in _AGENT_TRACE_STABLE_MESSAGE_FIELDS
        if field in message
    }
    return json.dumps(
        stable,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':'),
        default=str,
    )


def _decorate_agent_state_markdown(raw_state):
    """只把受信任的服务端 Markdown HTML 投影到 Agent 展示状态。"""

    if not isinstance(raw_state, dict):
        return raw_state
    state = dict(raw_state)
    raw_trace = state.get('execution_trace')
    has_trace = isinstance(raw_trace, dict)
    trace = dict(raw_trace) if has_trace else {}
    trace.pop('conclusion_html', None)
    trace.pop('final_response_html', None)
    raw_messages = trace.get('trace_messages') or []
    messages = []
    if isinstance(raw_messages, list):
        for raw_message in raw_messages:
            if not isinstance(raw_message, dict):
                continue
            message = dict(raw_message)
            # v2 事件文本仍由不可信 Agent 产生；随状态传入的 HTML 不能直送浏览器。
            message.pop('html', None)
            kind = str(
                message.get('kind') or message.get('type') or 'assistant'
            ).strip().lower()
            if kind not in _AGENT_PUBLIC_TRACE_KINDS:
                continue
            text = _agent_trace_text(message)
            if kind in _AGENT_RICH_TRACE_KINDS and text:
                message['html'] = str(render_rich_markdown(text))
            messages.append(message)
    if has_trace:
        trace['trace_messages'] = messages
        state['execution_trace'] = trace

    # 同样不信任任务快照中自带的 *_html，只根据规范纯文本重新生成。
    state.pop('conclusion_html', None)
    state.pop('final_response_html', None)
    stored_conclusion = str(
        state.get('conclusion')
        or state.get('final_response')
        or trace.get('conclusion')
        or trace.get('final_response')
        or ''
    ).strip()
    # worker 已把 Completed 的末条 assistant 固化为 conclude；历史迁移也会
    # 补齐缺失值。仅当状态字段缺失时再查 v2 事件表。
    conclusion = _agent_state_display_conclusion(
        state,
        stored_conclusion,
    )
    if conclusion:
        state['conclusion'] = conclusion
        state['conclusion_html'] = str(render_rich_markdown(conclusion))
        if state.get('final_response'):
            state['final_response_html'] = state['conclusion_html']
    return state


def _decorate_agent_turns(
    turns,
    *,
    current_task_id='',
    current_state=None,
    steer_records=None,
):
    decorated = []
    current_task_id = str(current_task_id or '').strip()
    for raw_turn in turns or []:
        turn = dict(raw_turn)
        reuse_current_state = bool(
            isinstance(current_state, dict)
            and current_task_id
            and str(turn.get('task_id') or '').strip() == current_task_id
        )
        base_state = current_state if reuse_current_state else {
            'task_id': turn.get('task_id'),
            'session_id': turn.get('session_id'),
            'harness': turn.get('harness'),
            'endpoint_id': turn.get('endpoint_id'),
            'endpoint_model': turn.get('endpoint_model'),
            'status': turn.get('status'),
            'message': turn.get('conclusion') or '',
        }
        # 历史首屏只投影 conclude。公开回复与工作块摘要在用户首次展开
        # “工作详情”时通过任务状态接口加载，避免为每轮同步 hydrate 时间线。
        snapshot = _decorate_agent_state_markdown({
            **base_state,
            'execution_trace': {},
        })
        conclusion = str(
            turn.get('conclusion') or snapshot.get('conclusion') or ''
        ).strip()
        if agent_status_is_terminal(turn.get('status')):
            conclusion = _agent_state_display_conclusion(
                {**turn, 'task_id': turn.get('task_id')},
                conclusion,
            )
        turn['has_detail'] = bool(str(turn.get('task_id') or '').strip())
        turn['detail_messages'] = []
        turn['_accepted_steer_messages'] = []
        turn['execution_trace'] = {}
        turn['user_message_html'] = render_rich_markdown(turn.get('user_message'))
        turn['conclusion'] = conclusion
        turn['conclusion_html'] = render_rich_markdown(conclusion)
        decorated.append(turn)
    return decorated


def _agent_token_usage_from_state(state):
    if not isinstance(state, dict):
        return None
    trace = state.get('execution_trace')
    if not isinstance(trace, dict):
        return None
    usage = trace.get('token_usage')
    return usage if isinstance(usage, dict) else None


def _agent_last_context_tokens(usage):
    """读取最近一次模型交互占用的上下文；与会话累计用量独立。"""

    if not isinstance(usage, dict):
        return None
    values = (
        usage.get('last_input_total_tokens'),
        usage.get('last_output_tokens', 0),
    )
    tokens = 0
    for value in values:
        if isinstance(value, bool):
            return None
        try:
            count = int(value)
        except (TypeError, ValueError):
            return None
        if count < 0:
            return None
        tokens += count
    return tokens


class _AgentHistoricalTokenUsages(list):
    """历史用量及请求 task 是否仍属于这条会话 lineage。"""

    def __init__(self, values=(), *, current_task_visible=True):
        super().__init__(values)
        self.current_task_visible = bool(current_task_visible)


def _load_agent_historical_token_usages(
    session_id,
    current_task_id,
    *,
    exclude_task_ids=(),
):
    """读取整场会话用量；重试替换的轮次也属于实际消耗。"""

    current_task_id = str(current_task_id or '').strip()
    excluded = {
        str(task_id or '').strip()
        for task_id in exclude_task_ids or ()
        if str(task_id or '').strip()
    }
    usages = []
    current_task_visible = False
    for turn in get_agent_session_turns(
        session_id,
        include_superseded=True,
    ):
        task_id = str(turn.get('task_id') or '').strip()
        if task_id == current_task_id:
            current_task_visible = True
            continue
        if not task_id or task_id in excluded:
            continue
        persisted = get_agent_run_by_task_id(task_id)
        if not isinstance(persisted, dict):
            # 入队前失败的轮次没有模型调用，也不会有 agent_task_run 快照。
            continue
        usage = _agent_token_usage_from_state(
            hydrate_agent_run_snapshot(persisted)
        )
        if usage is not None:
            usages.append((task_id, usage))
    return _AgentHistoricalTokenUsages(
        usages,
        current_task_visible=current_task_visible,
    )


def _agent_session_context(state, task_id=''):
    """从状态或任务归属解析 session / harness。"""

    if not isinstance(state, dict):
        return '', ''
    resolved_task_id = str(task_id or state.get('task_id') or '').strip()
    session_id = str(state.get('session_id') or '').strip()
    harness = _agent_trace_harness(state)
    if session_id and harness:
        return session_id, harness
    if not resolved_task_id:
        return session_id, harness
    owning_session = get_agent_session_by_task_id(resolved_task_id)
    if isinstance(owning_session, dict):
        session_id = session_id or str(
            owning_session.get('session_id') or ''
        ).strip()
        harness = harness or str(
            owning_session.get('harness') or ''
        ).strip().lower()
    return session_id, harness


def _agent_state_with_session_token_usage(
    state,
    historical_usages=(),
    *,
    ledger_usage=None,
):
    """把历史基线与当前任务实时快照合成为会话级权威用量。"""

    if not isinstance(state, dict):
        return state
    projected = dict(state)
    ledger_usage = dict(ledger_usage) if isinstance(ledger_usage, dict) else None
    current_task_id = str(projected.get('task_id') or '').strip()
    ledger_context_task_id = str(
        (ledger_usage or {}).pop('_latest_context_task_id', '') or ''
    ).strip()
    ledger_context_tokens = (ledger_usage or {}).pop(
        '_latest_context_tokens', None
    )
    ledger_context_request_count = (ledger_usage or {}).pop(
        '_latest_context_request_count', 0
    )
    ledger_task_ids = {
        str(task_id or '').strip()
        for task_id in (ledger_usage or {}).pop('_task_ids', ())
        if str(task_id or '').strip()
    }
    current_task_visible = bool(
        getattr(historical_usages, 'current_task_visible', True)
    )
    task_usages = [
        item for item in historical_usages or ()
        if (
            isinstance(item, (tuple, list))
            and len(item) == 2
            and str(item[0] or '').strip() not in ledger_task_ids
        )
    ]
    current_usage = _agent_token_usage_from_state(projected)
    if (
        current_task_visible
        and current_task_id
        and current_task_id not in ledger_task_ids
        and current_usage is not None
    ):
        # aggregate helper 按 task_id 最后写入覆盖，避免历史/current 重复计数。
        task_usages.append((current_task_id, current_usage))
    if ledger_usage is not None:
        ledger_usage['incremental'] = True
        task_usages.append(('__quota_ledger__', ledger_usage))
    session_usage = aggregate_agent_session_token_usage(task_usages)
    if session_usage is not None and ledger_usage is not None:
        session_usage = dict(session_usage)
        session_usage['turn_count'] += max(
            0,
            int(ledger_usage.get('turn_count') or 0) - 1,
        )
    ledger_cost = projected.get('session_charged_amount_rmb')
    if (
        session_usage is not None
        and ledger_usage is None
        and ledger_cost is not None
    ):
        session_usage = dict(session_usage)
        session_usage['cost_rmb'] = str(ledger_cost)
        session_usage['cost_complete'] = True
    projected['session_token_usage'] = session_usage

    current_context_tokens = _agent_last_context_tokens(current_usage)
    current_request_count = int((current_usage or {}).get('request_count') or 0)
    ledger_context_is_current = bool(
        current_task_id and ledger_context_task_id == current_task_id
    )
    current_trace_is_fresh = bool(
        current_context_tokens is not None
        and (
            not ledger_context_is_current
            or (
                (current_usage or {}).get('incremental') is True
                and current_request_count >= int(ledger_context_request_count or 0)
            )
        )
    )
    if current_trace_is_fresh:
        context_tokens = current_context_tokens
    elif ledger_context_is_current:
        try:
            context_tokens = max(0, int(ledger_context_tokens))
        except (TypeError, ValueError):
            context_tokens = None
    else:
        context_tokens = current_context_tokens
    try:
        context_window_tokens = int(
            projected.get('context_window_tokens')
            or DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
        )
    except (TypeError, ValueError):
        context_window_tokens = DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
    if context_window_tokens <= 0:
        context_window_tokens = DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
    projected['context_usage'] = {
        'used_tokens': context_tokens,
        'window_tokens': context_window_tokens,
    }
    return projected


def _agent_state_with_loaded_session_token_usage(state):
    """有可信 session_id 时补齐历史；普通旧任务保持当前任务统计。"""

    if not isinstance(state, dict):
        return state
    session_id = str(state.get('session_id') or '').strip()
    current_task_id = str(state.get('task_id') or '').strip()
    projected = dict(state)
    historical_usages = ()
    ledger_usage = None
    if session_id:
        try:
            ledger_usage = get_agent_session_token_usage(session_id)
            if ledger_usage is not None:
                projected['session_charged_amount_rmb'] = ledger_usage['cost_rmb']
        except Exception:
            logger.warning(
                '读取 Agent 会话计费账本失败',
                extra={'session_id': session_id},
                exc_info=True,
            )
    if session_id and current_task_id:
        try:
            historical_usages = _load_agent_historical_token_usages(
                session_id,
                current_task_id,
                **({
                    'exclude_task_ids': ledger_usage['_task_ids'],
                } if (ledger_usage or {}).get('_task_ids') else {}),
            )
        except Exception:
            # 用量展示不能阻断状态接口。历史读取失败时，只在数据层仍能确认
            # 请求 task 属于该会话时保留它自己的实时统计；其它历史轮次待
            # 下一次成功读取后再补齐。
            logger.warning(
                '读取 Agent 会话历史用量失败',
                extra={
                    'session_id': session_id,
                    'task_id': current_task_id,
                },
                exc_info=True,
            )
            current_task_visible = False
            try:
                owning_session = get_agent_session_by_task_id(current_task_id)
                current_task_visible = bool(
                    isinstance(owning_session, dict)
                    and str(owning_session.get('session_id') or '').strip()
                    == session_id
                )
            except Exception:
                logger.warning(
                    '确认 Agent 会话当前轮次失败',
                    extra={
                        'session_id': session_id,
                        'task_id': current_task_id,
                    },
                    exc_info=True,
                )
            historical_usages = _AgentHistoricalTokenUsages(
                (),
                current_task_visible=current_task_visible,
            )
    return _agent_state_with_session_token_usage(
        projected,
        historical_usages,
        ledger_usage=ledger_usage,
    )


def _decorate_agent_session_message(message):
    if not isinstance(message, dict):
        return message
    projected = dict(message)
    projected['user_message_html'] = render_rich_markdown(
        projected.get('user_message')
    )
    return projected


def _agent_session_message_snapshot(agent_session, current_state=None):
    """构造页面与会话 SSE 共用的 MySQL 权威消息快照。"""

    session_id = str((agent_session or {}).get('session_id') or '').strip()
    snapshot = get_agent_session_queue_snapshot(
        session_id,
        loaded_session=agent_session,
    )
    messages = [
        _decorate_agent_session_message(message)
        for message in snapshot.get('messages') or []
    ]
    snapshot['messages'] = messages
    snapshot['queued_messages'] = [
        message for message in messages
        if str(message.get('delivery_mode') or '').lower() == 'queue'
    ]
    snapshot['steer_messages'] = [
        message for message in messages
        if str(message.get('delivery_mode') or '').lower() == 'steer'
    ]
    current_task_id = str(snapshot.get('current_task_id') or '')
    snapshot['active_message'] = next((
        message for message in snapshot['queued_messages']
        if str(message.get('final_task_id') or '') == current_task_id
    ), None)
    if (agent_session or {}).get('is_legacy'):
        steer_supported = False
        steer_reason = '旧任务不支持中途插话'
    else:
        try:
            steer_supported, steer_reason = read_agent_steer_capability(
                session_id,
                agent_session.get('harness'),
            )
        except Exception:
            steer_supported = False
            steer_reason = '当前 Harness 的插话能力状态不可用'
    snapshot['steer_supported'] = bool(steer_supported)
    snapshot['steer_unavailable_reason'] = str(steer_reason or '')
    if isinstance(current_state, dict):
        snapshot['session_token_usage'] = current_state.get(
            'session_token_usage'
        )
    return snapshot


def _pending_agent_run_state(session, task_id):
    return {
        'task_id': task_id,
        'session_id': session['session_id'],
        'problem_id': session.get('problem_id'),
        'problem_title': session.get('problem_title'),
        'requested_by': session.get('requested_by'),
        'task_kind': session.get('task_kind') or 'custom',
        'harness': session.get('harness'),
        'endpoint_id': session.get('endpoint_id'),
        'endpoint_model': session.get('endpoint_model'),
        'reasoning_effort': session.get('reasoning_effort') or 'default',
        'status': 'Pending',
        'message': '任务排队中',
        'best_score': 0,
        'latest_submission_id': None,
        'final_submission_id': None,
        'attempts': [],
    }


def _mark_agent_dispatch_failed(session_id, task_id, pending_state, message):
    """尽力把“已建轮次但未入队”收束为可诊断的失败终态。"""

    failure_message = str(message or '任务入队失败')
    failure_state = dict(pending_state or {})
    failure_state.update(status='Failed', message=failure_message)
    try:
        if failure_state.get('task_id'):
            upsert_agent_run_snapshot(failure_state)
    except Exception:
        logger.exception(
            '更新 Agent 调度失败快照失败',
            extra={'session_id': session_id, 'task_id': task_id},
        )
    try:
        mark_agent_turn_enqueue_failed(session_id, task_id, failure_message)
    except Exception:
        logger.exception(
            '更新 Agent 会话调度失败状态失败',
            extra={'session_id': session_id, 'task_id': task_id},
        )
    return failure_message


def _mark_agent_runtime_restore_failed(
    session_id,
    task_id,
    pending_state,
    message,
):
    """runtime 无法恢复时阻止后续消息混用不一致的 native 状态。"""

    failure_message = str(message or 'Agent 运行时恢复失败')
    failure_state = dict(pending_state or {})
    failure_state.update(status='CleanupFailed', message=failure_message)
    try:
        if failure_state.get('task_id'):
            upsert_agent_run_snapshot(failure_state)
    except Exception:
        logger.exception(
            '更新 Agent runtime 恢复失败快照失败',
            extra={'session_id': session_id, 'task_id': task_id},
        )
    try:
        mark_agent_turn_runtime_restore_failed(
            session_id,
            task_id,
            failure_message,
        )
    except Exception:
        logger.exception(
            '更新 Agent runtime 恢复失败状态失败',
            extra={'session_id': session_id, 'task_id': task_id},
        )
    return failure_message


def _remove_agent_runtime_checkpoint_best_effort(session_id, checkpoint_id):
    checkpoint_id = str(checkpoint_id or '').strip()
    if not checkpoint_id:
        return
    try:
        remove_agent_runtime_checkpoint(
            session_id,
            checkpoint_id,
            missing_ok=True,
        )
    except Exception:
        # checkpoint 清理失败不能撤销已经提交的会话事务；保留不可见的
        # 私有快照比误删当前恢复点更安全，后续可由维护任务回收。
        logger.warning(
            '清理未引用的 Agent runtime checkpoint 失败',
            extra={
                'session_id': str(session_id or ''),
                'checkpoint_id': checkpoint_id,
            },
            exc_info=True,
        )


def _remove_agent_attachments_best_effort(session_id, attachments):
    attachments = list(attachments or [])
    if not attachments:
        return
    try:
        remove_agent_attachments(session_id, attachments)
    except Exception:
        # 每批附件拥有独立 generation；补偿失败只会留下不可引用的孤儿批次，
        # 不能覆盖原始业务错误或触碰其它请求已经提交的附件。
        logger.warning(
            '清理未引用的 Agent 附件批次失败',
            extra={'session_id': str(session_id or '')},
            exc_info=True,
        )
def init_problem_core_module(
    evaluate_submission_task,
    transcribe_written_homework_task,
    promptly_generate_submission_task=None,
    agent_solve_problem_task=None,
    agent_generate_testdata_task=None,
    agent_run_turn_task=None,
    get_agent_run_snapshot=None,
    subscribe_agent_run_events=None,
    terminate_agent_run=None,
    agent_queue_dispatch_task=None,
    agent_steer_capability_reader=None,
):
    global _evaluate_submission_task, _promptly_generate_submission_task
    global _transcribe_written_homework_task
    global _agent_solve_problem_task, _agent_generate_testdata_task
    global _agent_run_turn_task, _agent_queue_dispatch_task
    global _get_agent_run_snapshot, _subscribe_agent_run_events
    global _terminate_agent_run
    global read_agent_steer_capability
    _evaluate_submission_task = evaluate_submission_task
    _promptly_generate_submission_task = promptly_generate_submission_task
    _transcribe_written_homework_task = transcribe_written_homework_task
    _agent_solve_problem_task = agent_solve_problem_task
    _agent_generate_testdata_task = agent_generate_testdata_task
    _agent_run_turn_task = agent_run_turn_task
    _agent_queue_dispatch_task = agent_queue_dispatch_task
    _get_agent_run_snapshot = get_agent_run_snapshot
    _subscribe_agent_run_events = subscribe_agent_run_events
    _terminate_agent_run = terminate_agent_run
    if agent_steer_capability_reader is not None:
        read_agent_steer_capability = agent_steer_capability_reader


def _is_agent_state_finished(state):
    if not isinstance(state, dict):
        return False
    status = str(state.get("status") or "").strip().lower()
    return status in (
        "completed",
        "failed",
        "canceled",
        "cancelled",
        "cleanupfailed",
        "cleanup_failed",
    )


def _build_agent_state_from_async_result(task_id):
    if not task_id or _agent_solve_problem_task is None:
        return None
    try:
        async_result = _agent_solve_problem_task.AsyncResult(task_id)
    except Exception:
        return None

    celery_state = str(async_result.state or "PENDING").upper()
    now = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    state = {
        "task_id": task_id,
        "status": "Pending",
        "message": "任务排队中",
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "updated_at": now,
        "celery_state": celery_state,
    }

    if celery_state in ("RECEIVED", "STARTED", "RETRY"):
        state["status"] = "Running"
        state["message"] = "任务执行中"
        return state

    if celery_state == "FAILURE":
        state["status"] = "Failed"
        state["message"] = str(async_result.result) if async_result.result is not None else "任务执行失败"
        return state

    if celery_state == "SUCCESS":
        result_data = async_result.result if isinstance(async_result.result, dict) else {}
        state["status"] = "Completed" if result_data.get("success") else "Failed"
        state["message"] = result_data.get("message") or "任务已结束"
        state["final_submission_id"] = result_data.get("final_submission_id")
        state["latest_submission_id"] = (
            result_data.get("latest_submission_id")
            or result_data.get("final_submission_id")
        )
        state["attempts"] = result_data.get("attempts") or []
        return state

    return state


def _overlay_agent_celery_terminal(task_id, state):
    if _is_agent_state_finished(state):
        return state
    celery_state = _build_agent_state_from_async_result(task_id)
    if not _is_agent_state_finished(celery_state):
        return state
    merged = dict(state)
    for key in (
        "status",
        "message",
        "final_submission_id",
        "latest_submission_id",
        "attempts",
        "celery_state",
    ):
        merged[key] = celery_state.get(key)
    return merged


def _overlay_agent_session_cleanup_failure(task_id, raw_state, agent_session=None):
    """让会话清理失败覆盖 agent_task_runs 中为撤销保留的 Canceled。"""

    if not isinstance(raw_state, dict):
        return raw_state
    state = dict(raw_state)
    state_status = str(state.get('status') or '').strip().lower()
    if agent_session is None and state_status in {'canceled', 'cancelled'}:
        try:
            agent_session = get_agent_session_by_task_id(task_id)
        except Exception:
            # 状态接口仍可退回已持久化的 Canceled；详情页会使用已读取的会话
            # 再覆盖一次，确保刷新后的交互边界保持 fail-closed。
            agent_session = None
    if not isinstance(agent_session, dict):
        return state
    session_status = str(agent_session.get('status') or '').strip().lower()
    if (
        session_status not in {'cleanupfailed', 'cleanup_failed'}
        or str(agent_session.get('current_task_id') or '').strip() != str(task_id)
    ):
        return state
    state.update(
        status='CleanupFailed',
        message=(
            str(agent_session.get('message') or '').strip()
            or '任务运行时清理失败，需管理员处理'
        ),
        stage='finished',
        harness_status='cleanup_failed',
    )
    return state


def _agent_state_for_response(
    task_id,
    raw_state,
    agent_session=None,
    *,
    decorate_markdown=True,
):
    state = _overlay_agent_session_cleanup_failure(
        task_id,
        raw_state,
        agent_session=agent_session,
    )
    return _decorate_agent_state_markdown(state) if decorate_markdown else state


def _hydrate_agent_state_trace_if_needed(state):
    """Redis 已有 v2 公开时间线时避免重复查询数据库。"""

    if not isinstance(state, dict):
        return hydrate_agent_run_snapshot(state)
    trace = state.get('execution_trace')
    expected_status = {
        'running': 'running',
        'pending': 'pending',
        'completed': 'passed',
        'failed': 'error',
        'canceled': 'error',
        'cancelled': 'error',
        'cleanupfailed': 'error',
        'cleanup_failed': 'error',
    }.get(str(state.get('status') or '').strip().lower(), 'pending')
    if (
        expected_status in {'running', 'pending'}
        and isinstance(trace, dict)
        and int(trace.get('schema_version') or 0) == 2
        and trace.get('status') == expected_status
        and bool(_agent_trace_messages(trace))
    ):
        snapshot = dict(state)
        snapshot.pop('events', None)
        snapshot.pop('token_pricing', None)
        return snapshot
    return hydrate_agent_run_snapshot(state)


def _agent_state_without_trace_messages(state):
    if not isinstance(state, dict):
        return state
    projected = dict(state)
    trace = projected.get('execution_trace')
    if isinstance(trace, dict):
        trace = dict(trace)
        trace.pop('trace_messages', None)
        projected['execution_trace'] = trace
    return projected


def _get_agent_run_state(
    task_id,
    *,
    decorate_markdown=True,
    include_trace=True,
):
    state = _get_agent_run_snapshot(task_id) if _get_agent_run_snapshot is not None else None
    if isinstance(state, dict):
        if not _is_agent_state_finished(state):
            try:
                persisted = get_agent_run_by_task_id(task_id)
            except Exception:
                persisted = None
                logger.warning(
                    '读取 Agent 任务持久终止状态失败',
                    extra={'task_id': task_id},
                    exc_info=True,
                )
            if _is_agent_state_finished(persisted):
                state = {**state, **persisted}
        projected = _overlay_agent_celery_terminal(task_id, state)
        projected = (
            _hydrate_agent_state_trace_if_needed(projected)
            if include_trace else _agent_state_without_trace_messages(projected)
        )
        return _agent_state_for_response(
            task_id,
            projected,
            decorate_markdown=decorate_markdown,
        )
    state = get_agent_run_by_task_id(task_id)
    if isinstance(state, dict):
        projected = _overlay_agent_celery_terminal(task_id, state)
        projected = (
            hydrate_agent_run_snapshot(projected)
            if include_trace else _agent_state_without_trace_messages(projected)
        )
        return _agent_state_for_response(
            task_id,
            projected,
            decorate_markdown=decorate_markdown,
        )
    projected = _build_agent_state_from_async_result(task_id)
    projected = (
        hydrate_agent_run_snapshot(projected)
        if include_trace else _agent_state_without_trace_messages(projected)
    )
    return _agent_state_for_response(
        task_id,
        projected,
        decorate_markdown=decorate_markdown,
    )


def _submission_limit_redirect(problem_id, submission_limit):
    flash(f'您对此题的提交次数已达到上限（{submission_limit}次）！', 'danger')
    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))


def _request_wants_json():
    return (
        request.path.startswith('/api/')
        or request.is_json
        or 'application/json' in request.headers.get('Accept', '')
    )


def _submission_success_response(submission_id, deadline_warning=None):
    if _request_wants_json():
        payload = {
            'success': True,
            'submission_id': int(submission_id),
        }
        if deadline_warning:
            payload['warning'] = deadline_warning
        return jsonify(payload), 201
    if deadline_warning:
        flash(deadline_warning['message'], 'warning')
    return redirect(url_for(
        'submission.submission_detail', submission_id=submission_id,
    ))


def _record_archive_failure(submission_id, counted_submission_limit):
    try:
        mark_submission_archive_failed(
            submission_id,
            release_quota=counted_submission_limit is not None,
        )
    except Exception:
        # 保留最初的归档错误响应，同时把原子补偿失败作为可运维告警记录。
        logger.exception(
            '提交归档失败状态与配额补偿写入失败',
            extra={'submission_id': submission_id},
        )


def _load_expected_written_submission(username, problem_id, expected_id):
    latest = get_latest_written_submission(username, problem_id)
    if latest and int(latest['id']) == int(expected_id):
        return latest
    return None


@problem_core_bp.route('/problems', methods=['GET'])
def problem_list():
    return jsonify(
        success=False,
        message='该页面由 React 前端提供',
        path='/problems',
    ), 406


@problem_core_bp.route('/api/class-activity', methods=['GET'])
def class_activity_data():
    user = current_user()
    if not user:
        return jsonify(success=False, message='请先登录'), 401

    classes = visible_classes_for_user_cached(user)
    requested_class_en = str(request.args.get('class_en') or '').strip()
    if requested_class_en:
        selected_class = next(
            (
                item
                for item in classes
                if item.get('class_en') == requested_class_en
            ),
            None,
        )
        if not selected_class:
            return jsonify(success=False, message='无权查看该班级'), 403
    else:
        selected_class = select_visible_class(classes)

    if not selected_class:
        return jsonify(
            success=True,
            class_en=None,
            class_cn=None,
            activity=[],
        )

    class_en = selected_class['class_en']
    try:
        activity = get_class_activity(class_en)
    except Exception:
        logger.exception('加载班级活跃度失败：class_en=%s', class_en)
        return jsonify(success=False, message='班级活跃度加载失败'), 500

    return jsonify(
        success=True,
        class_en=class_en,
        class_cn=selected_class.get('class_cn'),
        activity=[
            {
                'day': item['day'].isoformat(),
                'count': int(item.get('count') or 0),
                'intensity': int(item.get('intensity') or 0),
                'future': bool(item.get('future')),
            }
            for item in activity
        ],
    )


@problem_core_bp.route('/api/layout-navigation', methods=['GET'])
def layout_navigation_data():
    user = current_user()
    if not user:
        return jsonify(success=False, message='请先登录'), 401
    try:
        context = get_layout_navigation_context(
            user,
            selected_class_en=request.args.get('class_en'),
        )
    except Exception:
        logger.exception('加载桌面导航计数失败')
        context = {"counts": {}, "agent_active": False}
    return jsonify(success=True, **context)


@problem_core_bp.route('/problems/all', methods=['GET'])
def problem_library():
    return redirect('/problems?view=library')


@problem_core_bp.get('/api/downloads/numoj-cli.zip')
@problem_core_bp.get('/downloads/numoj-cli.zip')
def download_numoj_cli_skill():
    user = current_user()
    if not user:
        return Response('请先登录', status=401)

    skill_name = 'numoj-admin' if is_admin(user) else 'numoj-user'
    skill_directory = PROJECT_ROOT / 'skills' / skill_name
    try:
        archive = build_directory_zip(
            skill_directory,
            archive_root=skill_name,
        )
    except (FileNotFoundError, NotADirectoryError, OSError, ValueError):
        logger.exception('生成 %s 下载包失败', skill_name)
        return Response('下载资源暂不可用', status=404)

    response = send_file(
        archive,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'{skill_name}.zip',
        max_age=0,
    )
    response.headers['Cache-Control'] = 'private, no-store'
    response.headers['Vary'] = 'Cookie'
    return response


@problem_core_bp.route('/problem/<int:problem_id>', methods=['GET'])
def problem_detail(problem_id):
    return redirect(f'/problems/{problem_id}')


@problem_core_bp.get('/api/agent/launch-options')
@problem_core_bp.get('/agent/launch-options')
def agent_launch_options():
    """返回本次启动可选项和当前用户在此类任务中的上次选择。"""

    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        task_kind = normalize_agent_task_kind(request.args.get('task_kind'))
        if task_kind == 'custom':
            launch_options = _agent_launch_page_options(user['id'])
            response = jsonify(
                success=True,
                task_kind=task_kind,
                harnesses=launch_options['harnesses'],
                endpoints_by_harness=launch_options['endpoints_by_harness'],
                preference=launch_options['preference'],
            )
            response.headers['Cache-Control'] = 'private, no-store'
            return response
        endpoints_by_harness = list_launch_endpoints_by_harness()
        preference = get_agent_launch_preference(user['id']) or {}
    except AgentLaunchValidationError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except Exception:
        logger.exception('读取 Agent 启动选项失败')
        return jsonify(success=False, message='无法读取 Agent 启动选项'), 500

    # 偏好引用的节点被删除或协议被修改后，只在响应中回退，不把无效值回写数据库。
    preferred_harness = str(preference.get('harness') or '')
    preferred_endpoint_id = preference.get('endpoint_id')
    valid_preference = any(
        int(item.get('id') or 0) == int(preferred_endpoint_id or 0)
        for item in endpoints_by_harness.get(preferred_harness, [])
    ) and str(preference.get('endpoint_source') or 'global') == 'global'
    if not valid_preference:
        fallback_harness = next(
            (
                item['value']
                for item in harness_options()
                if endpoints_by_harness.get(item['value'])
            ),
            '',
        )
        fallback_endpoints = endpoints_by_harness.get(fallback_harness, [])
        preference = {
            'harness': fallback_harness,
            'endpoint_id': (
                int(fallback_endpoints[0]['id']) if fallback_endpoints else None
            ),
        }
    else:
        preference = {
            'harness': preferred_harness,
            'endpoint_id': int(preferred_endpoint_id),
        }

    response = jsonify(
        success=True,
        task_kind=task_kind,
        harnesses=harness_options(),
        endpoints_by_harness=endpoints_by_harness,
        preference=preference,
    )
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@problem_core_bp.post('/api/problems/<int:problem_id>/agent/solve')
@problem_core_bp.post('/agent/problems/<int:problem_id>/solve')
def agent_solve_problem(problem_id):
    user = current_user()
    if not user or user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message='题目不存在'), 404
    if int(problem.get('type') or 1) != 1:
        return jsonify(success=False, message='仅支持编程题'), 400
    if _agent_run_turn_task is None or _agent_queue_dispatch_task is None:
        return jsonify(success=False, message='Agent 任务未初始化'), 500

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify(success=False, message='请求参数格式无效'), 400
    try:
        harness = normalize_launch_harness(payload.get('harness'))
        endpoint = resolve_launch_endpoint(
            harness,
            payload.get('endpoint_id'),
            include_secret=False,
        )
        endpoint_id = int(endpoint['id'])
        save_agent_launch_preference(user['id'], harness, endpoint_id)
    except AgentLaunchValidationError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except Exception:
        logger.exception('保存解题 Agent 启动选择失败')
        return jsonify(success=False, message='无法保存 Agent 启动选择'), 500

    cookie_name = str(current_app.config.get('SESSION_COOKIE_NAME') or 'session')
    session_cookie = str(request.cookies.get(cookie_name) or '')
    if not session_cookie:
        return jsonify(success=False, message='当前登录身份不可用于 Agent'), 401

    task_id = uuid4().hex
    problem_id_value = int(problem.get('id') or problem_id)
    problem_title = str(problem.get('title') or '').strip()
    user_message = build_solution_agent_prompt(
        problem_id=problem_id_value,
        problem_title=problem_title,
    )
    runtime_checkpoint_id = ''
    try:
        initialize_agent_task_workspace(
            task_id,
            harness=harness,
            access_role="user",
        )
        runtime_checkpoint_id = task_id
        create_empty_agent_runtime_checkpoint(task_id, runtime_checkpoint_id)
        agent_session = create_agent_session(
            session_id=task_id,
            task_id=task_id,
            requested_by=user['username'],
            harness=harness,
            endpoint_id=endpoint_id,
            endpoint_revision=endpoint.get('revision'),
            endpoint_model=endpoint.get("model"),
            user_message=user_message,
            task_kind="solve",
            access_role="user",
            problem_id=problem_id_value,
            problem_title=problem.get("title"),
            base_runtime_checkpoint_id=runtime_checkpoint_id,
            base_native_session_id='',
        )
    except Exception:
        _remove_agent_runtime_checkpoint_best_effort(
            task_id,
            runtime_checkpoint_id,
        )
        logger.exception('创建解题 Agent 会话失败')
        return jsonify(success=False, message='无法创建 Agent 会话'), 500

    try:
        upsert_agent_run_snapshot(_pending_agent_run_state(agent_session, task_id))
    except Exception:
        logger.warning(
            '写入解题 Agent 首轮兼容快照失败，dispatcher 将重建',
            extra={'session_id': task_id, 'task_id': task_id},
            exc_info=True,
        )

    try:
        _agent_queue_dispatch_task.apply_async(args=(task_id,))
    except Exception:
        logger.warning(
            '唤醒解题 Agent outbox 失败，等待周期恢复',
            extra={'session_id': task_id, 'task_id': task_id},
            exc_info=True,
        )

    return jsonify(
        success=True,
        message='Agent 任务已启动',
        task_id=task_id,
        view_url=url_for(
            'problem_core.agent_task_detail',
            session_id=task_id,
        ),
    )


@problem_core_bp.post('/api/problems/<int:problem_id>/agent/generate-testdata')
@problem_core_bp.post('/agent/problems/<int:problem_id>/generate-testdata')
def agent_generate_testdata(problem_id):
    user = current_user()
    if not user or user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message='题目不存在'), 404
    if int(problem.get('type') or 1) != 1:
        return jsonify(success=False, message='仅支持编程题'), 400
    programming_mode = int(problem.get('programming_grading_mode') or 1)
    if programming_mode == 3:
        return jsonify(success=False, message='Promptly 评分题不支持造数据 Agent'), 400
    if programming_mode != 1:
        return jsonify(success=False, message='造数据 Agent 仅支持标准测试点评分模式'), 400
    if _agent_run_turn_task is None or _agent_queue_dispatch_task is None:
        return jsonify(success=False, message='数据生成 Agent 任务未初始化'), 500

    if request.mimetype != 'multipart/form-data':
        return jsonify(success=False, message='请使用 multipart/form-data 上传标准程序'), 415

    payload = request.form
    standard_solution = request.files.get('standard_solution')
    if standard_solution is None:
        return jsonify(success=False, message='请选择标准程序文件'), 400
    try:
        standard_code, standard_filename = _read_agent_standard_solution(
            standard_solution,
        )
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400

    data_requirement = str(payload.get('data_requirement') or '').strip()
    try:
        test_point_count = _parse_agent_test_point_count(
            payload.get('test_point_count'),
        )
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400

    try:
        harness = normalize_launch_harness(payload.get('harness'))
        endpoint = resolve_launch_endpoint(
            harness,
            payload.get('endpoint_id'),
            include_secret=False,
        )
        endpoint_id = int(endpoint['id'])
        save_agent_launch_preference(user['id'], harness, endpoint_id)
    except AgentLaunchValidationError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except Exception:
        logger.exception('保存造数据 Agent 启动选择失败')
        return jsonify(success=False, message='无法保存 Agent 启动选择'), 500

    cookie_name = str(current_app.config.get('SESSION_COOKIE_NAME') or 'session')
    session_cookie = str(request.cookies.get(cookie_name) or '')
    if not session_cookie:
        return jsonify(success=False, message='当前登录身份不可用于 Agent'), 401

    task_id = uuid4().hex
    problem_id_value = int(problem.get('id') or problem_id)
    problem_title = str(problem.get('title') or '').strip()
    user_message = build_testdata_agent_prompt(
        problem_id=problem_id_value,
        problem_title=problem_title,
        test_point_count=test_point_count,
        data_requirement=data_requirement,
    )
    attachments = []
    runtime_checkpoint_id = ''
    try:
        initialize_agent_task_workspace(
            task_id,
            harness=harness,
            access_role="admin",
        )
        runtime_checkpoint_id = task_id
        create_empty_agent_runtime_checkpoint(task_id, runtime_checkpoint_id)
        attachment_upload = FileStorage(
            stream=BytesIO(standard_code.encode('utf-8')),
            filename=standard_filename,
            content_type='text/plain; charset=utf-8',
        )
        attachments = save_agent_attachments(
            task_id,
            task_id,
            [attachment_upload],
        )
        agent_session = create_agent_session(
            session_id=task_id,
            task_id=task_id,
            requested_by=user['username'],
            harness=harness,
            endpoint_id=endpoint_id,
            endpoint_revision=endpoint.get('revision'),
            endpoint_model=endpoint.get("model"),
            user_message=user_message,
            attachments=attachments,
            task_kind="testdata",
            access_role="admin",
            problem_id=problem_id_value,
            problem_title=problem.get("title"),
            base_runtime_checkpoint_id=runtime_checkpoint_id,
            base_native_session_id='',
        )
    except Exception:
        _remove_agent_attachments_best_effort(task_id, attachments)
        _remove_agent_runtime_checkpoint_best_effort(
            task_id,
            runtime_checkpoint_id,
        )
        logger.exception('创建造数据 Agent 会话失败')
        return jsonify(success=False, message='无法创建 Agent 会话'), 500

    try:
        upsert_agent_run_snapshot(_pending_agent_run_state(agent_session, task_id))
    except Exception:
        logger.warning(
            '写入造数据 Agent 首轮兼容快照失败，dispatcher 将重建',
            extra={'session_id': task_id, 'task_id': task_id},
            exc_info=True,
        )

    try:
        _agent_queue_dispatch_task.apply_async(args=(task_id,))
    except Exception:
        logger.warning(
            '唤醒造数据 Agent outbox 失败，等待周期恢复',
            extra={'session_id': task_id, 'task_id': task_id},
            exc_info=True,
        )

    return jsonify(
        success=True,
        message='数据生成 Agent 任务已启动',
        task_id=task_id,
        view_url=url_for(
            'problem_core.agent_task_detail',
            session_id=task_id,
        ),
    )


@problem_core_bp.get('/api/agent/runs/<task_id>')
@problem_core_bp.get('/agent/runs/<task_id>/state')
def agent_run_status(task_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        _agent_task_for_actor(
            task_id,
            _agent_actor(user),
            allow_unknown_for_admin=True,
        )
    except PermissionError as exc:
        return jsonify(success=False, message=str(exc)), 403
    except AgentSessionMessageNotFoundError as exc:
        return jsonify(success=False, message=str(exc)), 404

    state = _get_agent_run_state(task_id)
    if state is None:
        state = _agent_state_for_response(
            task_id,
            hydrate_agent_run_snapshot({
                "task_id": task_id,
                "status": "Pending",
                "message": "任务排队中",
                "latest_submission_id": None,
                "final_submission_id": None,
                "attempts": [],
            })
        )
    state = _agent_state_with_loaded_session_token_usage(state)
    return jsonify(success=True, state=state)


@problem_core_bp.get('/agent/runs/<task_id>/work-blocks/<block_id>')
def agent_run_work_block(task_id, block_id):
    """按需返回一个 v2 工作块的内部事件；常规状态/SSE 不包含这些内容。"""

    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        _agent_task_for_actor(
            task_id,
            _agent_actor(user),
            allow_unknown_for_admin=True,
        )
        block = get_agent_trace_work_block(task_id, block_id)
    except PermissionError as exc:
        return jsonify(success=False, message=str(exc)), 403
    except AgentSessionMessageNotFoundError as exc:
        return jsonify(success=False, message=str(exc)), 404
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400
    if not block:
        return jsonify(success=False, message='工作详情不存在'), 404

    messages = []
    for raw_message in block.get('messages') or ():
        if not isinstance(raw_message, dict):
            continue
        message = dict(raw_message)
        message.pop('html', None)
        kind = str(message.get('kind') or '').strip().lower()
        text = _agent_trace_text(message)
        if kind in {'thinking', 'reasoning'} and text:
            message['html'] = str(render_rich_markdown(text))
        messages.append(message)
    return jsonify(
        success=True,
        block={
            'block_id': block_id,
            'messages': messages,
        },
    )


@problem_core_bp.post('/agent/runs/<task_id>/cancel')
def agent_run_cancel(task_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        _agent_task_for_actor(
            task_id,
            _agent_actor(user),
            allow_unknown_for_admin=True,
        )
    except PermissionError as exc:
        return jsonify(success=False, message=str(exc)), 403
    except AgentSessionMessageNotFoundError as exc:
        return jsonify(success=False, message=str(exc)), 404
    if _terminate_agent_run is None:
        return jsonify(success=False, message='Agent 终止操作未初始化'), 500

    try:
        result = _terminate_agent_run(task_id)
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except Exception:
        logger.exception('终止 Agent 任务失败', extra={'task_id': task_id})
        return jsonify(success=False, message='终止 Agent 任务失败'), 500

    if not result.get('exists'):
        return jsonify(success=False, message='Agent 任务不存在'), 404

    state = _agent_state_with_loaded_session_token_usage(
        _agent_state_for_response(task_id, result.get('state'))
    )
    session_state = None
    session_id = str(state.get('session_id') or '').strip()
    if session_id:
        try:
            agent_session = get_agent_session(session_id)
            if isinstance(agent_session, dict):
                session_state = _agent_session_message_snapshot(
                    agent_session,
                    current_state=state,
                )
        except Exception:
            logger.warning(
                '终止 Agent 任务后读取消息队列状态失败',
                extra={'task_id': task_id, 'session_id': session_id},
                exc_info=True,
            )
    if not result.get('canceled'):
        return jsonify(
            success=False,
            message='Agent 任务已经结束，无法终止',
            state=state,
            session_state=session_state,
        ), 409

    errors = [str(item) for item in result.get('errors') or [] if str(item)]
    if errors:
        return jsonify(
            success=False,
            message='任务已被手动终止，但运行时清理失败',
            state=state,
            session_state=session_state,
            errors=errors,
        ), 500

    return jsonify(
        success=True,
        message='任务已被手动终止',
        state=state,
        session_state=session_state,
    )


@problem_core_bp.get('/api/agent/runs/<task_id>/events')
@problem_core_bp.get('/agent/runs/<task_id>/stream')
def agent_run_stream(task_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        _agent_task_for_actor(
            task_id,
            _agent_actor(user),
            allow_unknown_for_admin=True,
        )
    except PermissionError:
        return jsonify({'error': 'Access denied'}), 403
    except AgentSessionMessageNotFoundError:
        return jsonify({'error': 'Agent task not found'}), 404

    fallback_state = {
        "task_id": task_id,
        "status": "Pending",
        "message": "任务排队中",
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
    }

    def _encode_sse(event_name, payload):
        return f"event: {event_name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

    def _snapshot_marker(snapshot):
        trace = snapshot.get("execution_trace") or {}
        messages = trace.get("trace_messages") or []
        files = trace.get("trace_files") or []
        usage = trace.get("token_usage") or {}
        session_usage = snapshot.get("session_token_usage") or {}
        last_message = messages[-1] if messages else {}
        return (
            snapshot.get("status"),
            snapshot.get("message"),
            snapshot.get("latest_submission_id"),
            snapshot.get("updated_at"),
            trace.get("trace_id"),
            len(messages),
            last_message.get("source"),
            last_message.get("offset"),
            last_message.get("event_index"),
            _agent_trace_message_signature(last_message),
            usage.get("request_count"),
            usage.get("input_total_tokens"),
            usage.get("input_cached_tokens"),
            usage.get("output_tokens"),
            usage.get("cost_rmb"),
            session_usage.get("request_count"),
            session_usage.get("input_total_tokens"),
            session_usage.get("input_cached_tokens"),
            session_usage.get("output_tokens"),
            session_usage.get("cost_rmb"),
            tuple(
                (item.get("path"), item.get("size"))
                for item in files if isinstance(item, dict)
            ),
        )

    def _source_snapshot_marker(snapshot):
        """在 Markdown 渲染前识别 worker 重复发布的同一份轨迹。"""

        trace = snapshot.get("execution_trace") or {}
        messages = trace.get("trace_messages") or []
        files = trace.get("trace_files") or []
        usage = trace.get("token_usage") or {}
        last_message = messages[-1] if messages else {}
        return (
            snapshot.get("status"),
            snapshot.get("message"),
            snapshot.get("latest_submission_id"),
            snapshot.get("updated_at"),
            trace.get("trace_id"),
            len(messages),
            _agent_trace_message_signature(last_message),
            usage.get("request_count"),
            usage.get("input_total_tokens"),
            usage.get("input_cached_tokens"),
            usage.get("output_tokens"),
            usage.get("cost_rmb"),
            snapshot.get("session_charged_amount_rmb"),
            tuple(
                (item.get("path"), item.get("size"))
                for item in files if isinstance(item, dict)
            ),
        )

    @stream_with_context
    def generate():
        historical_usages = ()
        loaded_session_id = ''
        loaded_usage_task_ids = frozenset()
        ledger_cache_key = None
        ledger_usage_cache = None
        loaded_context_session_id = ''
        loaded_context_harness = ''

        def with_session_projection(snapshot):
            nonlocal historical_usages, loaded_session_id
            nonlocal loaded_usage_task_ids
            nonlocal ledger_cache_key, ledger_usage_cache
            nonlocal loaded_context_session_id, loaded_context_harness
            if not isinstance(snapshot, dict):
                return snapshot
            session_id = str(snapshot.get('session_id') or '').strip()
            harness = _agent_trace_harness(snapshot)
            if not session_id or not harness:
                try:
                    resolved_session_id, resolved_harness = (
                        _agent_session_context(snapshot, task_id)
                    )
                    session_id = session_id or resolved_session_id
                    harness = harness or resolved_harness
                except Exception:
                    logger.warning(
                        '读取 Agent SSE 会话轨迹上下文失败',
                        extra={'task_id': task_id},
                        exc_info=True,
                    )
            session_id = session_id or loaded_context_session_id
            harness = harness or loaded_context_harness
            if session_id:
                loaded_context_session_id = session_id
            if harness:
                loaded_context_harness = harness
            ledger_usage = None
            if (
                session_id
                and snapshot.get('session_charged_amount_rmb') is not None
            ):
                next_ledger_key = (
                    session_id,
                    str(snapshot.get('session_charged_amount_rmb')),
                )
                if (
                    next_ledger_key != ledger_cache_key
                    or next_ledger_key[1] == '0'
                ):
                    try:
                        ledger_usage_cache = get_agent_session_token_usage(
                            session_id
                        )
                        ledger_cache_key = next_ledger_key
                    except Exception:
                        logger.warning(
                            '读取 Agent SSE 会话计费账本失败',
                            extra={
                                'session_id': session_id,
                                'task_id': task_id,
                            },
                            exc_info=True,
                        )
                if ledger_cache_key == next_ledger_key:
                    ledger_usage = ledger_usage_cache
            ledger_task_ids = frozenset(
                str(covered_task_id or '').strip()
                for covered_task_id in (ledger_usage or {}).get(
                    '_task_ids', ()
                )
                if str(covered_task_id or '').strip()
            )
            if (
                session_id
                and (
                    session_id != loaded_session_id
                    or ledger_task_ids != loaded_usage_task_ids
                )
            ):
                try:
                    historical_usages = _load_agent_historical_token_usages(
                        session_id,
                        task_id,
                        **({
                            'exclude_task_ids': ledger_task_ids,
                        } if ledger_task_ids else {}),
                    )
                except Exception:
                    historical_usages = ()
                    logger.warning(
                        '读取 Agent SSE 会话历史用量失败',
                        extra={
                            'session_id': session_id,
                            'task_id': task_id,
                        },
                        exc_info=True,
                    )
                loaded_session_id = session_id
                loaded_usage_task_ids = ledger_task_ids
            return _agent_state_with_session_token_usage(
                snapshot,
                historical_usages,
                ledger_usage=ledger_usage,
            )

        pubsub = (
            _subscribe_agent_run_events(task_id)
            if _subscribe_agent_run_events is not None
            else None
        )
        try:
            # 必须先订阅再重读快照，避免终态 publish 落在“初始读取 → 订阅”
            # 的窗口内而永久丢失。即使已有 Pub/Sub，空闲时也定期回读，作为
            # Redis 断线或单条消息丢失时的收敛保障。
            first_payload = _get_agent_run_state(task_id) or (
                _agent_state_for_response(
                    task_id,
                    hydrate_agent_run_snapshot(fallback_state)
                )
            )
            first_payload = with_session_projection(first_payload)
            yield _encode_sse("status", first_payload)
            if _is_agent_state_finished(first_payload):
                yield _encode_sse("done", first_payload)
                return
            last_marker = _snapshot_marker(first_payload)
            last_source_marker = _source_snapshot_marker(first_payload)

            if pubsub is None:
                while True:
                    snapshot = _get_agent_run_state(task_id) or first_payload
                    snapshot = with_session_projection(snapshot)
                    current_marker = _snapshot_marker(snapshot)
                    if current_marker != last_marker:
                        yield _encode_sse("status", snapshot)
                        last_marker = current_marker
                    if _is_agent_state_finished(snapshot):
                        yield _encode_sse("done", snapshot)
                        return
                    time.sleep(1.0)

            while True:
                msg = pubsub.get_message(timeout=15.0)
                if not msg:
                    snapshot = _get_agent_run_state(task_id) or first_payload
                    snapshot = with_session_projection(snapshot)
                    current_marker = _snapshot_marker(snapshot)
                    if current_marker != last_marker:
                        yield _encode_sse("status", snapshot)
                        last_marker = current_marker
                    if _is_agent_state_finished(snapshot):
                        yield _encode_sse("done", snapshot)
                        return
                    yield ": keepalive\n\n"
                    continue

                if msg.get("type") != "message":
                    continue

                raw = msg.get("data")
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="ignore")
                try:
                    snapshot = json.loads(raw) if isinstance(raw, str) else raw
                except Exception:
                    continue
                if not isinstance(snapshot, dict):
                    continue

                source_marker = _source_snapshot_marker(snapshot)
                if source_marker == last_source_marker:
                    continue
                snapshot = _agent_state_for_response(
                    task_id,
                    _hydrate_agent_state_trace_if_needed(snapshot)
                )
                snapshot = with_session_projection(snapshot)
                yield _encode_sse("status", snapshot)
                last_marker = _snapshot_marker(snapshot)
                last_source_marker = source_marker
                if _is_agent_state_finished(snapshot):
                    yield _encode_sse("done", snapshot)
                    return
        finally:
            if pubsub is not None:
                try:
                    pubsub.close()
                except Exception:
                    pass

    lease = try_acquire_sse_slot()
    if lease is None:
        return sse_capacity_response()

    return Response(
        guard_sse_stream(generate(), lease),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
    )


@problem_core_bp.route('/api/problems/<int:problem_id>/submissions', methods=['POST'])
@problem_core_bp.route('/submit/<int:problem_id>', methods=['GET', 'POST'])
def submit_solution(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    problem = get_problem(problem_id)
    if not problem:
        return "<h3>题目不存在</h3>"

    deadline_warning = None
    if user['is_admin'] != 1 and request.method == 'POST':
        deadline_warning = build_homework_deadline_warning(
            get_problem_homework_assignments(user, problem_id)
        )
        if (
            deadline_warning
            and not _request_wants_json()
            and request.form.get('deadline_warning_ack') != '1'
        ):
            flash('请先确认已截止作业提示，再继续提交。', 'warning')
            return redirect(url_for(
                'problem_core.problem_detail', problem_id=problem_id,
            ))

    submission_limit = problem.get('submission_limit', 10)
    counted_submission_limit = submission_limit if user['is_admin'] != 1 else None

    if request.method == 'GET' and user['is_admin'] != 1:
        if not can_submit(user['username'], problem_id, submission_limit):
            return _submission_limit_redirect(problem_id, submission_limit)

    if request.method == 'POST':
        if problem['type'] == 1:
            try:
                programming_mode = int(problem.get('programming_grading_mode') or 1)
            except Exception:
                programming_mode = 1
            if programming_mode == 3:
                prompt_text = request.form.get('prompt', '')
                if not prompt_text.strip():
                    flash('Prompt 不能为空。', 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

                try:
                    submission_id = create_submission(
                        problem_id=problem_id,
                        problem_title=problem['title'],
                        username=user['username'],
                        code="",
                        score=0,
                        test_points=[],
                        status="Generating",
                        prompt_text=prompt_text,
                        generated_from_prompt=True,
                        submission_limit=counted_submission_limit,
                        user_id=user['id'],
                    )
                except SubmissionLimitExceeded:
                    return _submission_limit_redirect(problem_id, submission_limit)
                try:
                    archive_submission_by_id(submission_id, raise_errors=True)
                except Exception as e:
                    _record_archive_failure(submission_id, counted_submission_limit)
                    flash(f'提交归档失败，已停止入队：{str(e)}', 'danger')
                    return redirect(url_for('submission.submission_detail', submission_id=submission_id))

                if _promptly_generate_submission_task is None:
                    flash('提交成功，但 Promptly 生成任务未初始化。', 'warning')
                else:
                    _promptly_generate_submission_task.delay(submission_id)

                return _submission_success_response(
                    submission_id, deadline_warning,
                )

            is_lean4 = str(problem.get('lang') or '').strip().lower() in {'lean', 'lean4'}
            if is_lean4:
                payload = request.get_json(silent=True) if request.is_json else None
                if not isinstance(payload, dict):
                    raw_workspace = request.form.get('lean_workspace', '')
                    try:
                        payload = json.loads(raw_workspace)
                    except (TypeError, json.JSONDecodeError):
                        payload = None
                if not isinstance(payload, dict):
                    message = 'Lean 4 提交必须包含工作区版本和可写文件。'
                    if request.is_json or 'application/json' in request.headers.get('Accept', ''):
                        return jsonify(success=False, message=message), 400
                    flash(message, 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
                try:
                    workspace, writable_files = normalize_lean_submission_payload(
                        problem_id=problem_id,
                        revision=payload.get('revision'),
                        files=payload.get('files'),
                    )
                except LeanWorkspaceStaleError as exc:
                    if request.is_json or 'application/json' in request.headers.get('Accept', ''):
                        return jsonify(success=False, code='lean_workspace_stale', message=str(exc)), 409
                    flash(str(exc), 'warning')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
                except LeanWorkspaceError as exc:
                    if request.is_json or 'application/json' in request.headers.get('Accept', ''):
                        return jsonify(success=False, message=str(exc)), 400
                    flash(str(exc), 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

                default_file = str(workspace.get('default_file') or '')
                code = writable_files.get(default_file, '')
                try:
                    submission_id = create_submission(
                        problem_id=problem_id,
                        problem_title=problem['title'],
                        username=user['username'],
                        code=code,
                        score=0,
                        test_points=[],
                        submission_limit=counted_submission_limit,
                        user_id=user['id'],
                        lean_workspace={
                            'revision': workspace['revision'],
                            'files': writable_files,
                        },
                    )
                except SubmissionLimitExceeded:
                    return _submission_limit_redirect(problem_id, submission_limit)
                except LeanWorkspaceStaleError as exc:
                    if request.is_json or 'application/json' in request.headers.get('Accept', ''):
                        return jsonify(success=False, code='lean_workspace_stale', message=str(exc)), 409
                    flash(str(exc), 'warning')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
                try:
                    archive_submission_by_id(submission_id, raise_errors=True)
                except Exception as exc:
                    _record_archive_failure(submission_id, counted_submission_limit)
                    flash(f'提交归档失败，已停止入队：{str(exc)}', 'danger')
                    return redirect(url_for('submission.submission_detail', submission_id=submission_id))
                if _evaluate_submission_task is None:
                    flash('提交成功，但评测任务未初始化。', 'warning')
                else:
                    _evaluate_submission_task.delay(submission_id)
                return _submission_success_response(
                    submission_id, deadline_warning,
                )

            code = request.form.get('code', '')
            if not code.strip():
                flash('代码不能为空。', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

            try:
                submission_id = create_submission(
                    problem_id=problem_id,
                    problem_title=problem['title'],
                    username=user['username'],
                    code=code,
                    score=0,
                    test_points=[],
                    submission_limit=counted_submission_limit,
                    user_id=user['id'],
                )
            except SubmissionLimitExceeded:
                return _submission_limit_redirect(problem_id, submission_limit)
            try:
                archive_submission_by_id(submission_id, raise_errors=True)
            except Exception as e:
                _record_archive_failure(submission_id, counted_submission_limit)
                flash(f'提交归档失败，已停止入队：{str(e)}', 'danger')
                return redirect(url_for('submission.submission_detail', submission_id=submission_id))

            if _evaluate_submission_task is None:
                flash('提交成功，但评测任务未初始化。', 'warning')
            else:
                _evaluate_submission_task.delay(submission_id)

            return _submission_success_response(
                submission_id, deadline_warning,
            )

        if problem['type'] == 2:
            if 'file' not in request.files:
                flash('请上传文件。', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
            file = request.files['file']
            if file.filename == '':
                flash('未选择文件。', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
            filename = secure_filename(f"file_{file.filename}")

            try:
                written_mode = int(problem.get('written_grading_mode') or 1)
            except Exception:
                written_mode = 1

            lower_filename = filename.lower()
            if written_mode == 3:
                if not lower_filename.endswith('.zip'):
                    flash(f'错误：{filename} 不是 ZIP 文件（tex 文本批改模式仅支持 .zip）', 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
            else:
                if not lower_filename.endswith('.pdf'):
                    flash(f'错误：{filename} 不是 PDF 文件', 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

            # 纯人工批改：覆盖上一次提交
            if written_mode == 4:
                existing = get_latest_written_submission(user['username'], problem_id)
                if existing:
                    submission_id = existing['id']

                    def overwrite_record(expected_id, new_filename, expected_snapshot):
                        return overwrite_written_submission(
                            expected_id,
                            new_filename,
                            submission_limit=counted_submission_limit,
                            username=user['username'],
                            problem_id=problem_id,
                            user_id=user['id'],
                            expected_submission=expected_snapshot,
                        )

                    try:
                        publish_manual_written_submission(
                            uploaded_file=file,
                            filename=filename,
                            previous_submission=existing,
                            problem=problem,
                            user=user,
                            classes=get_user_classes_cached(user['id']),
                            overwrite_record=overwrite_record,
                            load_current_record=lambda expected_id: (
                                _load_expected_written_submission(
                                    existing['username'], problem_id, expected_id,
                                )
                            ),
                            max_bytes=int(
                                current_app.config.get('MAX_CONTENT_LENGTH')
                                or 256 * 1024 * 1024
                            ),
                        )
                    except Exception as exc:
                        if isinstance(exc.__cause__, SubmissionLimitExceeded):
                            return _submission_limit_redirect(problem_id, submission_limit)
                        if isinstance(exc, (WrittenSubmissionArtifactError, ValueError)):
                            error_message = str(exc)
                        else:
                            logger.exception(
                                '人工作业覆盖出现未预期异常',
                                extra={'submission_id': submission_id},
                            )
                            error_message = '新作业发布失败，已保留上一份有效作业'
                        flash(error_message, 'danger')
                        return redirect(url_for('submission.submission_detail', submission_id=submission_id))
                    return _submission_success_response(
                        submission_id, deadline_warning,
                    )
                # 首次提交：走普通 INSERT 流程（下方）

            try:
                submission_id = create_submission(
                    problem_id=problem_id,
                    problem_title=problem['title'],
                    username=user['username'],
                    code=" ",
                    score=0,
                    test_points=[filename],
                    submission_limit=counted_submission_limit,
                    user_id=user['id'],
                )
            except SubmissionLimitExceeded:
                return _submission_limit_redirect(problem_id, submission_limit)

            upload_folder = os.path.join('uploads', f"{submission_id}")
            try:
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)

                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)
                archive_submission_file_by_id(submission_id, file_path, filename, raise_errors=True)
            except Exception as e:
                _record_archive_failure(submission_id, counted_submission_limit)
                flash(f'提交归档失败，已停止入队：{str(e)}', 'danger')
                return redirect(url_for('submission.submission_detail', submission_id=submission_id))

            if written_mode != 4:
                try:
                    if _transcribe_written_homework_task is None:
                        raise RuntimeError("自动评分任务未初始化")
                    _transcribe_written_homework_task.delay(submission_id)
                except Exception as e:
                    flash(f'文件已提交，但自动评分任务入队失败：{str(e)}', 'warning')

            return _submission_success_response(
                submission_id, deadline_warning,
            )

    return redirect(f'/problems/{problem_id}')


@problem_core_bp.route('/api/agent/sessions', methods=['GET', 'POST'])
@problem_core_bp.route('/agent/tasks', methods=['GET', 'POST'])
def agent_tasks():
    user = current_user()
    if not user:
        if request.method == 'GET':
            return redirect(url_for('auth.login'))
        return jsonify(success=False, message='未登录'), 401
    actor = _agent_actor(user)

    if request.method == 'POST':
        if _agent_run_turn_task is None or _agent_queue_dispatch_task is None:
            return jsonify(success=False, message='通用 Agent 任务未初始化'), 500
        if request.mimetype != 'multipart/form-data':
            return jsonify(success=False, message='请使用 multipart/form-data'), 415
        try:
            message = _agent_message_from_request()
            access_role = (
                normalize_agent_access_role(request.form.get('access_role'))
                if actor['is_admin']
                else 'user'
            )
            harness = normalize_launch_harness(request.form.get('harness'))
            reasoning_effort = normalize_agent_reasoning_effort(
                request.form.get('reasoning_effort'),
                harness,
                default=default_reasoning_effort_for_harness(harness),
            )
            endpoint = _resolve_agent_endpoint_for_user(
                harness,
                request.form.get('endpoint_id'),
                user['id'],
                include_secret=False,
            )
            endpoint_id = int(endpoint['id'])
            endpoint_source = str(endpoint.get('source') or 'global')
            _agent_quota_gate(user, endpoint_source=endpoint_source)
            cookie_name, session_cookie = _agent_session_cookie()
            session_id = _agent_client_message_id()
        except AgentQuotaError as exc:
            return _agent_quota_error_response(exc)
        except (AgentLaunchValidationError, ValueError) as exc:
            return jsonify(success=False, message=str(exc)), 400

        try:
            existing_message = (
                get_agent_session_message(session_id)
                if str(request.form.get('message_id') or '').strip()
                else None
            )
        except Exception:
            logger.exception('读取通用 Agent 首轮幂等键失败')
            return jsonify(success=False, message='无法确认 Agent 会话状态'), 500
        if existing_message is not None:
            existing_session = get_agent_session(session_id)
            if not existing_session or not (
                str(existing_message.get('session_id') or '') == session_id
                and str(existing_message.get('created_by') or '')
                == str(user.get('username') or '')
                and str(existing_message.get('user_message') or '') == message
                and str(existing_session.get('harness') or '') == harness
                and str(existing_session.get('endpoint_source') or 'global')
                == endpoint_source
                and int(existing_session.get('endpoint_id') or 0) == endpoint_id
                and str(existing_session.get('access_role') or '') == access_role
                and str(existing_session.get('reasoning_effort') or 'default')
                == reasoning_effort
            ):
                return jsonify(
                    success=False,
                    message='Agent message_id 已被其它消息使用',
                ), 409
            try:
                _agent_queue_dispatch_task.apply_async(args=(session_id,))
            except Exception:
                logger.warning(
                    '重新唤醒通用 Agent 首轮 outbox 失败，等待周期恢复',
                    extra={'session_id': session_id, 'task_id': session_id},
                    exc_info=True,
                )
            detail_url = url_for(
                'problem_core.agent_task_detail',
                session_id=session_id,
            )
            return jsonify(
                success=True,
                message='Agent 会话已创建',
                session_id=session_id,
                task_id=session_id,
                detail_url=detail_url,
                view_url=detail_url,
                idempotent=True,
            )

        attachments = []
        runtime_checkpoint_id = ''
        try:
            save_agent_launch_preference(
                user['id'],
                harness,
                endpoint.get('ref') or endpoint_id,
            )
            initialize_agent_task_workspace(
                session_id,
                harness=harness,
                access_role=access_role,
            )
            runtime_checkpoint_id = _agent_runtime_checkpoint_generation_id(
                session_id
            )
            create_empty_agent_runtime_checkpoint(
                session_id,
                runtime_checkpoint_id,
            )
            attachments = save_agent_attachments(
                session_id,
                session_id,
                request.files.getlist('attachments'),
            )
            agent_session = create_agent_session(
                session_id=session_id,
                task_id=session_id,
                requested_by=user['username'],
                harness=harness,
                reasoning_effort=reasoning_effort,
                endpoint_source=endpoint_source,
                endpoint_id=endpoint_id,
                endpoint_revision=endpoint.get('revision'),
                endpoint_model=endpoint.get('model'),
                user_message=message,
                attachments=attachments,
                task_kind='custom',
                access_role=access_role,
                base_runtime_checkpoint_id=runtime_checkpoint_id,
                base_native_session_id='',
            )
        except (ValueError, OSError) as exc:
            remove_agent_attachments(session_id, attachments)
            _remove_agent_runtime_checkpoint_best_effort(
                session_id,
                runtime_checkpoint_id,
            )
            return jsonify(success=False, message=str(exc)), 400
        except Exception:
            remove_agent_attachments(session_id, attachments)
            _remove_agent_runtime_checkpoint_best_effort(
                session_id,
                runtime_checkpoint_id,
            )
            logger.exception('创建通用 Agent 会话失败')
            return jsonify(success=False, message='无法创建 Agent 会话'), 500

        pending_state = _pending_agent_run_state(agent_session, session_id)
        try:
            upsert_agent_run_snapshot(pending_state)
        except Exception:
            logger.warning(
                '写入通用 Agent 首轮兼容快照失败，dispatcher 将重建',
                extra={'session_id': session_id, 'task_id': session_id},
                exc_info=True,
            )
        try:
            _agent_queue_dispatch_task.apply_async(args=(session_id,))
        except Exception:
            logger.warning(
                '唤醒通用 Agent 首轮 outbox 失败，等待周期恢复',
                extra={'session_id': session_id, 'task_id': session_id},
                exc_info=True,
            )

        detail_url = url_for(
            'problem_core.agent_task_detail',
            session_id=session_id,
        )
        return jsonify(
            success=True,
            message='Agent 会话已创建',
            session_id=session_id,
            task_id=session_id,
            detail_url=detail_url,
            view_url=detail_url,
        )

    page = max(1, request.args.get('page', 1, type=int))
    per_page = 20
    requested_scope = str(request.args.get('scope') or '').strip().lower()
    if actor['is_admin']:
        scope = requested_scope if requested_scope in {'all', 'mine'} else 'all'
    else:
        scope = 'mine'
    sessions, page, total_pages = get_agent_sessions_paginated(
        page=page,
        per_page=per_page,
        requested_by=(actor['username'] if scope == 'mine' else None),
    )

    page_start = max(1, page - 8)
    page_end = min(total_pages, page + 8)
    page_numbers = list(range(page_start, page_end + 1))

    open_task_id = str(request.args.get('task_id') or '').strip()
    open_session = None
    if re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', open_task_id):
        open_session = (
            get_agent_session_by_task_id(open_task_id)
            or get_agent_session(open_task_id)
        )
    if open_session is not None and _agent_actor_can_view_session(
        actor,
        open_session,
    ):
        return redirect(url_for(
            'problem_core.agent_task_detail',
            session_id=open_session['session_id'],
        ))

    try:
        launch_options = _agent_launch_page_options(user['id'])
    except Exception:
        logger.exception('读取通用 Agent 启动选项失败')
        launch_options = {
            'harnesses': harness_options(),
            'endpoints_by_harness': {},
            'reasoning_efforts_by_harness': (
                reasoning_effort_options_by_harness()
            ),
            'preference': {'harness': '', 'endpoint_id': None},
        }

    try:
        agent_quota_summary = get_agent_quota_summary(
            user['id'],
            is_admin=actor['is_admin'],
        )
        agent_personal_endpoints = list_user_agent_endpoints(user['id'])
        pending_requests = (
            list_pending_agent_quota_requests(user['id'])
            if actor['is_admin']
            else []
        )
    except Exception:
        logger.exception('读取 Agent 额度页面信息失败')
        agent_quota_summary = {
            'total_amount': '0',
            'used_amount': '0',
            'remaining_amount': '0',
            'public_enabled': True,
            'can_start': actor['is_admin'],
            'can_continue': actor['is_admin'],
        }
        agent_personal_endpoints = []
        pending_requests = []

    page_payload = {
        'user': user,
        'agent_sessions': sessions,
        'current_page': page,
        'total_pages': total_pages,
        'page_numbers': page_numbers,
        'agent_scope': scope,
        'agent_quota_summary': agent_quota_summary,
        'agent_personal_endpoints': agent_personal_endpoints,
        'agent_quota_pending_count': len(pending_requests),
        'agent_quota_pending_requests': pending_requests,
        **launch_options,
    }
    if _request_wants_json():
        return jsonify(success=True, **page_payload)
    return redirect('/agents')


@problem_core_bp.get('/admin/agent_tasks')
def legacy_agent_tasks():
    """兼容旧收藏链接；站内只生成新的 Agent Tasks URL。"""

    query = request.query_string.decode('latin-1')
    target = url_for('problem_core.agent_tasks')
    return redirect(f'{target}?{query}' if query else target, code=308)


@problem_core_bp.route('/api/agent/sessions/<session_id>', methods=['GET', 'POST'])
@problem_core_bp.route('/agent/tasks/<session_id>', methods=['GET', 'POST'])
def agent_task_detail(session_id):
    user = current_user()
    if not user:
        if request.method == 'GET':
            return redirect(url_for('auth.login'))
        return jsonify(success=False, message='未登录'), 401
    actor = _agent_actor(user)

    try:
        agent_session = get_agent_session(session_id)
        # agent_task_runs 会为每一轮保留兼容快照。只有命中 legacy fallback 时
        # 才额外检查它是否其实属于一个新式多轮会话，避免规范 URL 每次多查表。
        mapped_session = (
            get_agent_session_by_task_id(session_id)
            if agent_session and agent_session.get('is_legacy')
            else None
        )
        if mapped_session and mapped_session.get('session_id') != session_id:
            canonical_url = url_for(
                'problem_core.agent_task_detail',
                session_id=mapped_session['session_id'],
            )
            if request.method == 'GET':
                return redirect(canonical_url)
            return jsonify(
                success=False,
                message='请在当前 Agent 会话中继续发送消息',
                detail_url=canonical_url,
            ), 409
    except ValueError:
        agent_session = None
    if not agent_session:
        if request.method == 'GET':
            return '<h3>Agent 会话不存在</h3>', 404
        return jsonify(success=False, message='Agent 会话不存在'), 404
    if not _agent_actor_can_view_session(actor, agent_session):
        if request.method == 'GET':
            return '<h3>无权查看该 Agent 会话</h3>', 403
        return jsonify(success=False, message='只能管理自己发起的 Agent 会话'), 403

    if request.method == 'POST':
        if agent_session.get('is_legacy'):
            return jsonify(
                success=False,
                message='旧任务没有可恢复的 workspace，无法继续会话',
            ), 409
        if str(agent_session.get('requested_by') or '') != str(user.get('username') or ''):
            return jsonify(success=False, message='只能继续自己发起的 Agent 会话'), 403
        try:
            _agent_quota_gate(
                user,
                endpoint_source=agent_session.get('endpoint_source'),
            )
        except AgentQuotaError as exc:
            return _agent_quota_error_response(exc)
        if _agent_run_turn_task is None or _agent_queue_dispatch_task is None:
            return jsonify(success=False, message='通用 Agent 任务未初始化'), 500
        if request.mimetype != 'multipart/form-data':
            return jsonify(success=False, message='请使用 multipart/form-data'), 415
        if str(agent_session.get('status') or '').strip().lower() in {
            'cleanupfailed',
            'cleanup_failed',
        }:
            return jsonify(
                success=False,
                message='上一轮 Agent 任务尚未结束：容器清理状态未知',
            ), 409
        default_delivery_mode = (
            'turn'
            if agent_status_is_terminal(agent_session.get('status'))
            else 'queue'
        )
        retry_last = str(request.form.get('retry_last') or '').strip() == '1'
        delivery_mode = str(
            request.form.get('delivery_mode')
            or ('turn' if retry_last else default_delivery_mode)
        ).strip().lower()
        if delivery_mode not in {'turn', 'queue', 'steer'}:
            return jsonify(success=False, message='Agent 消息投递模式无效'), 400
        if retry_last and delivery_mode != 'turn':
            return jsonify(success=False, message='重试只能作为新的执行轮次发送'), 400

        try:
            message = '' if retry_last else _agent_message_from_request()
            message_id = _agent_client_message_id(generate=False)
            existing_message = (
                get_agent_session_message(message_id)
                if str(request.form.get('message_id') or '').strip()
                else None
            )
        except ValueError as exc:
            return jsonify(success=False, message=str(exc)), 400
        except Exception:
            logger.exception(
                '读取 Agent 消息幂等键失败',
                extra={'session_id': session_id},
            )
            return jsonify(success=False, message='无法确认 Agent 消息状态'), 500

        if existing_message is not None:
            existing_mode = str(existing_message.get('delivery_mode') or '')
            explicit_mode = str(request.form.get('delivery_mode') or '').strip().lower()
            existing_task_id = str(
                existing_message.get('final_task_id') or message_id
            )
            existing_turn = {}
            if existing_mode == 'turn':
                existing_turn = next(
                    (
                        item for item in get_agent_session_turns(
                            session_id,
                            include_superseded=True,
                        )
                        if str(item.get('task_id') or '') == existing_task_id
                    ),
                    {},
                )
            same_request = bool(
                str(existing_message.get('session_id') or '') == session_id
                and str(existing_message.get('created_by') or '')
                == str(user.get('username') or '')
                and (not explicit_mode or explicit_mode == existing_mode)
            )
            if retry_last:
                same_request = bool(
                    same_request
                    and existing_mode == 'turn'
                    and str(existing_turn.get('retry_of_task_id') or '')
                    == str(request.form.get('expected_task_id') or '').strip()
                )
                message = str(existing_message.get('user_message') or '').strip()
            else:
                same_request = bool(
                    same_request
                    and str(existing_message.get('user_message') or '') == message
                )
            if existing_mode == 'steer':
                same_request = same_request and str(
                    existing_message.get('target_task_id') or ''
                ) == str(request.form.get('expected_task_id') or '').strip()
            if not same_request:
                return jsonify(
                    success=False,
                    message='Agent message_id 已被其它消息使用',
                ), 409
            if existing_mode in {'turn', 'queue'}:
                try:
                    _agent_queue_dispatch_task.apply_async(args=(session_id,))
                except Exception:
                    logger.warning(
                        '重新唤醒 Agent outbox 失败，等待周期恢复',
                        extra={
                            'session_id': session_id,
                            'message_id': message_id,
                        },
                        exc_info=True,
                    )
            if existing_mode in {'queue', 'steer'}:
                refreshed_session = get_agent_session(session_id) or agent_session
                return jsonify(
                    success=True,
                    message='插话已接收' if existing_mode == 'steer' else '',
                    delivery_mode=existing_mode,
                    agent_message=_decorate_agent_session_message(existing_message),
                    session_state=_agent_session_message_snapshot(refreshed_session),
                    idempotent=True,
                )
            return jsonify(
                success=True,
                message='消息已发送',
                delivery_mode='turn',
                session_id=session_id,
                task_id=existing_task_id,
                turn_index=int(existing_turn.get('turn_index') or 1),
                user_message=message,
                user_message_html=render_rich_markdown(message),
                attachments=existing_message.get('attachments') or [],
                agent_message=_decorate_agent_session_message(existing_message),
                replaced_task_id=str(
                    existing_turn.get('retry_of_task_id') or ''
                ),
                idempotent=True,
            )

        if delivery_mode in {'queue', 'steer'}:
            if _agent_queue_dispatch_task is None:
                return jsonify(success=False, message='Agent 消息队列未初始化'), 500
            expected_task_id = str(
                request.form.get('expected_task_id') or ''
            ).strip()
            message_id = message_id or uuid4().hex
            if delivery_mode == 'steer':
                try:
                    steer_supported, steer_reason = read_agent_steer_capability(
                        session_id,
                        agent_session.get('harness'),
                    )
                except Exception:
                    steer_supported = False
                    steer_reason = '当前 Harness 的插话能力状态不可用'
                if not steer_supported:
                    return jsonify(
                        success=False,
                        message=steer_reason or '当前 Harness 暂不支持中途插话',
                    ), 409
                if not expected_task_id:
                    return jsonify(
                        success=False,
                        message='插话缺少当前任务标识，请刷新后重试',
                    ), 409

            attachments = []
            try:
                attachments = save_agent_attachments(
                    session_id,
                    message_id,
                    request.files.getlist('attachments'),
                )
                agent_message = enqueue_agent_session_message(
                    session_id,
                    message_id=message_id,
                    created_by=user['username'],
                    user_message=message,
                    attachments=attachments,
                    delivery_mode=delivery_mode,
                    target_task_id=(
                        expected_task_id if delivery_mode == 'steer' else None
                    ),
                )
            except AgentSessionMessageConflictError as exc:
                remove_agent_attachments(session_id, attachments)
                return jsonify(success=False, message=str(exc)), 409
            except AgentSessionMessageNotFoundError as exc:
                remove_agent_attachments(session_id, attachments)
                return jsonify(success=False, message=str(exc)), 404
            except (ValueError, OSError) as exc:
                remove_agent_attachments(session_id, attachments)
                return jsonify(success=False, message=str(exc)), 400
            except Exception:
                remove_agent_attachments(session_id, attachments)
                logger.exception(
                    '保存 Agent 排队消息失败',
                    extra={
                        'session_id': session_id,
                        'message_id': message_id,
                        'delivery_mode': delivery_mode,
                    },
                )
                return jsonify(success=False, message='无法保存 Agent 消息'), 500

            if delivery_mode == 'queue':
                try:
                    # 与当前执行任务使用同一 agent 队列：活动轮结束后此唤醒
                    # 才会运行；若 broker 瞬时失败，周期恢复仍会扫描 MySQL。
                    _agent_queue_dispatch_task.apply_async(args=(session_id,))
                except Exception:
                    logger.warning(
                        '唤醒 Agent 会话队列失败，等待周期恢复',
                        extra={
                            'session_id': session_id,
                            'message_id': message_id,
                        },
                        exc_info=True,
                    )
            refreshed_session = get_agent_session(session_id) or agent_session
            session_state = _agent_session_message_snapshot(refreshed_session)
            return jsonify(
                success=True,
                message='插话已接收' if delivery_mode == 'steer' else '',
                delivery_mode=delivery_mode,
                agent_message=_decorate_agent_session_message(agent_message),
                session_state=session_state,
            )

        # stale 页面不能用 turn 绕过已经开始的任务；运行中主发送应走 queue。
        if not agent_status_is_terminal(agent_session.get('status')):
            return jsonify(success=False, message='上一轮 Agent 任务尚未结束'), 409
        if retry_last and any(
            str(getattr(upload, 'filename', '') or '').strip()
            for _field, uploads in request.files.lists()
            for upload in uploads
        ):
            return jsonify(
                success=False,
                message='重试会复用上一条消息的附件，不能同时上传新附件',
            ), 400
        if (
            not retry_last
            and not str(agent_session.get('native_session_id') or '').strip()
        ):
            return jsonify(
                success=False,
                message='上一轮未建立可恢复的原生会话，无法继续；请新建 Agent 会话',
            ), 409
        try:
            endpoint_source = str(
                agent_session.get('endpoint_source') or 'global'
            )
            endpoint_ref = (
                f"user:{agent_session.get('endpoint_id')}"
                if endpoint_source == 'user'
                else agent_session.get('endpoint_id')
            )
            _resolve_agent_endpoint_for_user(
                agent_session.get('harness'),
                endpoint_ref,
                user['id'],
                include_secret=False,
            )
        except AgentLaunchValidationError as exc:
            return jsonify(success=False, message=str(exc)), 409
        try:
            message = '' if retry_last else _agent_message_from_request()
            message_id = _agent_client_message_id()
        except ValueError as exc:
            return jsonify(success=False, message=str(exc)), 400

        task_id = message_id
        attachments = []
        created_checkpoint_id = ''
        restore_checkpoint_id = ''
        try:
            if retry_last:
                # 旧部署产生的逻辑首轮没有保存空 runtime 基线。为它创建一个
                # 明确的空 checkpoint；数据层只允许 turn_index=1 使用该兼容
                # 入口，后续旧轮缺少基线时仍 fail closed。
                created_checkpoint_id = _agent_runtime_checkpoint_generation_id(
                    task_id
                )
                create_empty_agent_runtime_checkpoint(
                    session_id,
                    created_checkpoint_id,
                )
                turn_claim = begin_agent_session_retry(
                    session_id,
                    task_id=task_id,
                    expected_task_id=request.form.get('expected_task_id'),
                    fallback_base_checkpoint_id=created_checkpoint_id,
                )
                message = str(turn_claim.get('user_message') or '').strip()
                attachments = list(turn_claim.get('attachments') or [])
                restore_checkpoint_id = str(
                    turn_claim.get('base_runtime_checkpoint_id') or ''
                ).strip()
                if created_checkpoint_id != restore_checkpoint_id:
                    _remove_agent_runtime_checkpoint_best_effort(
                        session_id,
                        created_checkpoint_id,
                    )
                    created_checkpoint_id = ''
            else:
                created_checkpoint_id = _agent_runtime_checkpoint_generation_id(
                    task_id
                )
                create_agent_runtime_checkpoint(
                    session_id,
                    created_checkpoint_id,
                )
                # 先把整批附件原子发布到独立 generation，再在一个数据库事务
                # 中创建 turn/outbox。恢复扫描因此永远看不到 attachments=[] 的
                # 半成品消息；begin 失败时只补偿本请求自己的 generation。
                attachments = save_agent_attachments(
                    session_id,
                    task_id,
                    request.files.getlist('attachments'),
                )
                turn_claim = begin_agent_session_turn(
                    session_id,
                    task_id=task_id,
                    user_message=message,
                    attachments=attachments,
                    base_runtime_checkpoint_id=created_checkpoint_id,
                )
        except AgentSessionBusyError as exc:
            _remove_agent_attachments_best_effort(session_id, attachments)
            _remove_agent_runtime_checkpoint_best_effort(
                session_id,
                created_checkpoint_id,
            )
            return jsonify(success=False, message=str(exc)), 409
        except AgentSessionNotFoundError as exc:
            _remove_agent_attachments_best_effort(session_id, attachments)
            _remove_agent_runtime_checkpoint_best_effort(
                session_id,
                created_checkpoint_id,
            )
            return jsonify(success=False, message=str(exc)), 404
        except (ValueError, OSError) as exc:
            _remove_agent_attachments_best_effort(session_id, attachments)
            _remove_agent_runtime_checkpoint_best_effort(
                session_id,
                created_checkpoint_id,
            )
            return jsonify(success=False, message=str(exc)), 400
        except Exception:
            _remove_agent_attachments_best_effort(session_id, attachments)
            _remove_agent_runtime_checkpoint_best_effort(
                session_id,
                created_checkpoint_id,
            )
            logger.exception(
                '创建 Agent 消息轮次失败',
                extra={'session_id': session_id},
            )
            return jsonify(success=False, message='无法创建 Agent 消息轮次'), 500

        if not retry_last:
            previous_checkpoint_id = str(
                turn_claim.get('previous_base_runtime_checkpoint_id') or ''
            ).strip()
            if (
                previous_checkpoint_id
                and previous_checkpoint_id != created_checkpoint_id
            ):
                _remove_agent_runtime_checkpoint_best_effort(
                    session_id,
                    previous_checkpoint_id,
                )

        # 只使用 begin_agent_session_turn 在行锁内返回的权威冻结值，避免
        # 并发终态投影后仍用请求开始时读到的旧 native session。
        frozen_session = {**agent_session, **turn_claim}
        turn_index = int(turn_claim["turn_index"])
        pending_state = _pending_agent_run_state(frozen_session, task_id)
        if retry_last:
            try:
                # DB claim 已把会话置为 Pending，因此同步恢复期间不会接受
                # 其它消息；在任何可取消、可入队或 worker 前置失败点之前，
                # 先让磁盘 runtime 与回退后的 native session 保持一致。
                restore_agent_runtime_checkpoint(
                    session_id,
                    restore_checkpoint_id,
                )
                clear_agent_session_state_file(session_id)
            except Exception:
                logger.exception(
                    '恢复 Agent 重试 runtime 失败',
                    extra={'session_id': session_id, 'task_id': task_id},
                )
                failure_message = _mark_agent_runtime_restore_failed(
                    session_id,
                    task_id,
                    pending_state,
                    'Agent 运行时恢复失败，已阻止继续会话',
                )
                return jsonify(
                    success=False,
                    message=failure_message,
                    detail_url=url_for(
                        'problem_core.agent_task_detail',
                        session_id=session_id,
                    ),
                ), 500
        try:
            upsert_agent_run_snapshot(pending_state)
        except Exception:
            logger.warning(
                '写入 Agent 续聊兼容快照失败，dispatcher 将重建',
                extra={'session_id': session_id, 'task_id': task_id},
                exc_info=True,
            )
        try:
            _agent_queue_dispatch_task.apply_async(args=(session_id,))
        except Exception:
            logger.warning(
                '唤醒 Agent 续聊 outbox 失败，等待周期恢复',
                extra={'session_id': session_id, 'task_id': task_id},
                exc_info=True,
            )

        return jsonify(
            success=True,
            message='消息已发送',
            delivery_mode='turn',
            session_id=session_id,
            task_id=task_id,
            turn_index=turn_index,
            user_message=message,
            user_message_html=render_rich_markdown(message),
            attachments=attachments,
            agent_message=_decorate_agent_session_message(
                turn_claim.get('agent_message')
            ),
            replaced_task_id=(
                str(turn_claim.get('replaced_task_id') or '').strip()
                if retry_last
                else ''
            ),
        )

    raw_turns = get_agent_session_turns(session_id)
    current_task_id = str(agent_session.get('current_task_id') or session_id)
    current_state = _get_agent_run_state(
        current_task_id,
        decorate_markdown=False,
        include_trace=not agent_status_is_terminal(agent_session.get('status')),
    )
    if current_state:
        # 已结束会话首屏只携带 conclude；运行中仍需公开时间线供 SSE 接续。
        current_state = _overlay_agent_session_cleanup_failure(
            current_task_id,
            current_state,
            agent_session=agent_session,
        )
    else:
        current_state = _agent_state_for_response(
            current_task_id,
            {
                'task_id': current_task_id,
                'session_id': session_id,
                'status': agent_session.get('status') or 'Pending',
                'message': agent_session.get('message') or '任务排队中',
                'native_session_id': agent_session.get('native_session_id') or '',
                'execution_trace': {},
            },
            agent_session=agent_session,
            decorate_markdown=False,
        )
    try:
        steer_records = list_agent_session_messages(
            session_id,
            delivery_modes='steer',
        )
    except Exception:
        steer_records = []
        logger.warning(
            '读取 Agent 历史插话失败',
            extra={'session_id': session_id},
            exc_info=True,
        )
    turns = _decorate_agent_turns(
        raw_turns,
        current_task_id=current_task_id,
        current_state=current_state,
        steer_records=steer_records,
    )
    steers_by_task = {}
    for record in steer_records:
        if str(record.get('status') or '').strip().lower() != 'sent':
            continue
        target_task_id = str(record.get('target_task_id') or '')
        steers_by_task.setdefault(target_task_id, []).append(
            _decorate_agent_session_message(record)
        )
    for turn in turns:
        task_id = str(turn.get('task_id') or '')
        accepted = list(turn.pop('_accepted_steer_messages', ()) or ())
        accepted_ids = {
            str(message.get('message_id') or '').strip()
            for message in accepted
        }
        turn['steer_messages'] = accepted + [
            message
            for message in steers_by_task.get(task_id, ())
            if str(message.get('message_id') or '').strip() not in accepted_ids
        ]
    # 持久 run 快照带有 endpoint_id，能为每个历史轮次按规范价格重建成本；
    # 不能直接拿用于展示的 turn 简版状态汇总，否则 priced 会话会被误判未定价。
    current_state = dict(current_state)
    current_state['session_id'] = session_id
    current_state = _agent_state_with_loaded_session_token_usage(current_state)
    try:
        agent_quota_summary = get_agent_quota_summary(
            user['id'],
            is_admin=actor['is_admin'],
        )
    except Exception:
        logger.exception('读取 Agent 会话额度失败')
        agent_quota_summary = {
            'remaining_amount': '0',
            'public_enabled': True,
            'can_start': actor['is_admin'],
            'can_continue': actor['is_admin'],
        }
    current_state['quota_summary'] = agent_quota_summary
    try:
        agent_message_state = _agent_session_message_snapshot(
            agent_session,
            current_state=current_state,
        )
    except Exception:
        logger.warning(
            '读取 Agent 会话消息快照失败',
            extra={'session_id': session_id},
            exc_info=True,
        )
        agent_message_state = {
            'session_id': session_id,
            'current_task_id': current_task_id,
            'status': agent_session.get('status') or 'Pending',
            'running': not agent_status_is_terminal(agent_session.get('status')),
            'queue_paused': bool(agent_session.get('queue_paused')),
            'queue_pause_reason': agent_session.get('queue_pause_reason') or '',
            'messages': [],
            'steer_supported': False,
            'steer_unavailable_reason': '消息队列状态暂不可用',
            'session_token_usage': current_state.get('session_token_usage'),
        }
    agent_message_state['quota_summary'] = agent_quota_summary
    # Workspace 目录可能在 Agent 运行中持续变化；首屏不同步
    # 遍历它，由前端在页面框架返回后通过 workspace 路由异步加载。
    owns_session = (
        str(agent_session.get('requested_by') or '')
        == str(user.get('username') or '')
    )
    latest_turn = raw_turns[-1] if raw_turns else {}
    retry_has_baseline = bool(
        str(latest_turn.get('base_runtime_checkpoint_id') or '').strip()
    ) or (
        int(latest_turn.get('turn_index') or 1) == 1
        and not str(latest_turn.get('base_native_session_id') or '').strip()
    )
    preupgrade_testdata_first_turn = bool(
        str(agent_session.get('task_kind') or '').strip().lower() == 'testdata'
        and str(agent_session.get('access_role') or '').strip().lower() == 'user'
        and int(latest_turn.get('turn_index') or 1) == 1
    )
    can_retry = bool(
        owns_session
        and not agent_session.get('is_legacy')
        and not preupgrade_testdata_first_turn
        and str(latest_turn.get('task_id') or '') == current_task_id
        and retry_has_baseline
    )
    can_retry_now = bool(
        can_retry and agent_status_is_terminal(agent_session.get('status'))
    )
    page_current_state = dict(current_state)
    page_current_state.pop('execution_trace', None)
    page_current_state.pop('conclusion_html', None)
    page_current_state.pop('final_response_html', None)
    if agent_status_is_terminal(current_state.get('status')):
        # 已结束轮次的 conclude 已经渲染在 turns 中，首屏 JSON 只保留
        # 状态、恢复点与会话用量。
        for key in (
            'conclusion',
            'final_response',
        ):
            page_current_state.pop(key, None)
    agent_message_urls = {
        'state': f'/api/agent/sessions/{quote(session_id, safe="")}/state',
        'stream': f'/api/agent/sessions/{quote(session_id, safe="")}/stream',
        'update': f'/api/agent/sessions/{quote(session_id, safe="")}/messages/__MESSAGE_ID__/update',
        'delete': f'/api/agent/sessions/{quote(session_id, safe="")}/messages/__MESSAGE_ID__/delete',
        'send_now': f'/api/agent/sessions/{quote(session_id, safe="")}/messages/__MESSAGE_ID__/send-now',
        'resume': f'/api/agent/sessions/{quote(session_id, safe="")}/queue/resume',
        'rename': f'/api/agent/sessions/{quote(session_id, safe="")}/title',
    }
    if _request_wants_json():
        response = jsonify(
            success=True,
            user=user,
            agent_session=agent_session,
            turns=turns,
            current_state=page_current_state,
            agent_message_state=agent_message_state,
            agent_message_urls=agent_message_urls,
            can_resume=owns_session,
            can_retry=can_retry,
            can_retry_now=can_retry_now,
            agent_quota_summary=agent_quota_summary,
            agent_context_window_tokens=int(
                (current_state.get('context_usage') or {}).get('window_tokens')
                or DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
            ),
        )
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    return redirect(f'/agents/{session_id}')


@problem_core_bp.patch('/api/agent/sessions/<session_id>/title')
@problem_core_bp.patch('/agent/tasks/<session_id>/title')
def agent_task_rename(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        _agent_session_for_actor(session_id, _agent_actor(user))
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise ValueError('请求参数格式无效')
        changed = rename_agent_session_title(session_id, payload.get('title'))
        if not changed:
            return jsonify(success=False, message='Agent 会话不支持重命名'), 409
        renamed = get_agent_session(session_id)
    except AgentSessionMessageNotFoundError as exc:
        return jsonify(success=False, message=str(exc)), 404
    except PermissionError as exc:
        return jsonify(success=False, message=str(exc)), 403
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except Exception:
        logger.exception('重命名 Agent 会话失败', extra={'session_id': session_id})
        return jsonify(success=False, message='无法重命名 Agent 会话'), 500
    return jsonify(success=True, title=renamed.get('title') or '')


@problem_core_bp.get('/admin/agent_tasks/<session_id>')
def legacy_agent_task_detail(session_id):
    """兼容部署前创建的会话详情链接。"""

    return redirect(
        url_for('problem_core.agent_task_detail', session_id=session_id),
        code=308,
    )


def _agent_message_route_session(session_id, user, *, require_owner=True):
    actor = _agent_actor(user)
    try:
        agent_session = _agent_session_for_actor(session_id, actor)
    except AgentSessionMessageNotFoundError:
        agent_session = None
    if not agent_session or agent_session.get('is_legacy'):
        raise AgentSessionMessageNotFoundError('Agent 会话不存在')
    if require_owner and str(agent_session.get('requested_by') or '') != str(
        actor['username'] if actor else ''
    ):
        raise PermissionError('只能管理自己发起的 Agent 会话')
    return agent_session


def _agent_message_mutation_error(exc):
    if isinstance(exc, AgentQuotaError):
        return _agent_quota_error_response(exc)
    if isinstance(exc, PermissionError):
        return jsonify(success=False, message=str(exc)), 403
    if isinstance(exc, AgentSessionMessageNotFoundError):
        return jsonify(success=False, message=str(exc)), 404
    if isinstance(exc, AgentSessionMessageConflictError):
        return jsonify(success=False, message=str(exc)), 409
    if isinstance(exc, (ValueError, OSError)):
        return jsonify(success=False, message=str(exc)), 400
    raise exc


@problem_core_bp.get('/api/agent/sessions/<session_id>/state')
@problem_core_bp.get('/agent/tasks/<session_id>/state')
def agent_task_message_state(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        agent_session = _agent_message_route_session(
            session_id,
            user,
            require_owner=False,
        )
        task_id = str(agent_session.get('current_task_id') or '')
        current_state = _get_agent_run_state(task_id) or {}
        current_state = dict(current_state)
        current_state.setdefault('task_id', task_id)
        current_state['session_id'] = session_id
        current_state = _agent_state_with_loaded_session_token_usage(
            current_state
        )
        state = _agent_session_message_snapshot(
            agent_session,
            current_state=current_state,
        )
        state['quota_summary'] = get_agent_runtime_quota_summary(
            user['id'],
            is_admin=int(user.get('is_admin') or 0) == 1,
        )
    except MySQLPoolExhausted:
        # 交给应用级处理器返回统一的 503 + Retry-After，不能把预期背压
        # 伪装成不可重试的业务 500。
        raise
    except Exception as exc:
        try:
            return _agent_message_mutation_error(exc)
        except Exception:
            logger.exception(
                '读取 Agent 会话消息状态失败',
                extra={'session_id': session_id},
            )
            return jsonify(success=False, message='无法读取消息队列'), 500
    response = jsonify(success=True, state=state)
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@problem_core_bp.get('/api/agent/sessions/<session_id>/stream')
@problem_core_bp.get('/agent/tasks/<session_id>/stream')
def agent_task_message_stream(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        initial_session = _agent_message_route_session(
            session_id,
            user,
            require_owner=False,
        )
    except MySQLPoolExhausted:
        raise
    except Exception as exc:
        return _agent_message_mutation_error(exc)

    lease = try_acquire_sse_slot()
    if lease is None:
        return sse_capacity_response()

    try:
        initial_state = _agent_session_message_snapshot(initial_session)
        initial_quota_summary = get_agent_runtime_quota_summary(
            user['id'],
            is_admin=int(user.get('is_admin') or 0) == 1,
        )
        initial_state['quota_summary'] = initial_quota_summary
        initial_payload = json.dumps(
            initial_state,
            ensure_ascii=False,
            sort_keys=True,
        )
    except MySQLPoolExhausted:
        # 首帧所需的数据在发送 200 前完成；池已饱和时由全局处理器明确
        # 返回 503，避免建立一个随即断开的 EventSource。
        lease.release()
        raise
    except Exception as exc:
        lease.release()
        return _agent_message_mutation_error(exc)

    @stream_with_context
    def generate():
        previous_payload = initial_payload
        heartbeat_at = time.monotonic()
        quota_refreshed_at = heartbeat_at
        quota_summary = initial_quota_summary
        next_poll_delay = _AGENT_MESSAGE_STREAM_POLL_INTERVAL_SECONDS
        yield f"event: session\ndata: {initial_payload}\n\n"
        while True:
            time.sleep(next_poll_delay)
            next_poll_delay = _AGENT_MESSAGE_STREAM_POLL_INTERVAL_SECONDS
            try:
                current_session = get_agent_session(session_id)
                if not current_session or current_session.get('is_legacy'):
                    break
                state = _agent_session_message_snapshot(current_session)
                now = time.monotonic()
                if (
                    now - quota_refreshed_at
                    >= _AGENT_MESSAGE_STREAM_QUOTA_REFRESH_INTERVAL_SECONDS
                ):
                    quota_summary = get_agent_runtime_quota_summary(
                        user['id'],
                        is_admin=int(user.get('is_admin') or 0) == 1,
                    )
                    quota_refreshed_at = now
                state['quota_summary'] = quota_summary
                payload = json.dumps(state, ensure_ascii=False, sort_keys=True)
            except GeneratorExit:
                break
            except MySQLPoolExhausted:
                # 已发出 200 后无法改写 HTTP 状态。保持连接并降低轮询频率，
                # 同时给 EventSource 写入重连退避，避免数据库过载时形成重连风暴。
                retry_seconds = _AGENT_MESSAGE_STREAM_OVERLOAD_RETRY_SECONDS
                retry_ms = int(retry_seconds * 1000)
                overloaded = json.dumps({
                    'code': 'mysql_pool_exhausted',
                    'message': '服务器繁忙，实时消息将在稍后继续同步',
                    'retry_after_ms': retry_ms,
                }, ensure_ascii=False)
                yield (
                    f"retry: {retry_ms}\n"
                    f"event: overloaded\n"
                    f"data: {overloaded}\n\n"
                )
                previous_payload = None
                heartbeat_at = time.monotonic()
                next_poll_delay = retry_seconds
                continue
            except Exception:
                logger.warning(
                    'Agent 会话消息流读取失败',
                    extra={'session_id': session_id},
                    exc_info=True,
                )
                break
            if payload != previous_payload:
                yield f"event: session\ndata: {payload}\n\n"
                previous_payload = payload
                heartbeat_at = time.monotonic()
            elif time.monotonic() - heartbeat_at >= 15:
                yield ': keep-alive\n\n'
                heartbeat_at = time.monotonic()

    response = Response(
        guard_sse_stream(generate(), lease),
        mimetype='text/event-stream',
    )
    response.headers['Cache-Control'] = 'private, no-cache, no-store'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


@problem_core_bp.post(
    '/api/agent/sessions/<session_id>/messages/<message_id>/update'
)
@problem_core_bp.post(
    '/agent/tasks/<session_id>/messages/<message_id>/update'
)
def agent_task_message_update(session_id, message_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    added_attachments = []
    update_committed = False
    try:
        agent_session = _agent_message_route_session(session_id, user)
        _agent_quota_gate(
            user,
            endpoint_source=agent_session.get('endpoint_source'),
        )
        message = _agent_message_from_request()
        records = list_agent_session_messages(
            session_id,
            delivery_modes='queue',
            statuses='queued',
        )
        current = next((
            item for item in records
            if str(item.get('message_id') or '') == str(message_id)
        ), None)
        if not current:
            raise AgentSessionMessageNotFoundError('Agent 排队消息不存在')
        removed_paths = {
            str(value or '').strip()
            for value in request.form.getlist('remove_attachment')
            if str(value or '').strip()
        }
        existing_attachments = current.get('attachments') or []
        kept_attachments = [
            item for item in existing_attachments
            if str((item or {}).get('path') or '') not in removed_paths
        ]
        added_attachments = save_agent_attachments(
            session_id,
            message_id,
            request.files.getlist('attachments'),
        )
        attachments = [*kept_attachments, *added_attachments]
        removed_attachments = update_queued_agent_session_message(
            session_id,
            message_id,
            user_message=message,
            attachments=attachments,
            expected_attachments=existing_attachments,
        )
        update_committed = True
        _remove_agent_attachments_best_effort(
            session_id,
            removed_attachments,
        )
        updated = next(
            item for item in list_agent_session_messages(
                session_id,
                delivery_modes='queue',
                statuses='queued',
            )
            if str(item.get('message_id') or '') == str(message_id)
        )
        state = _agent_session_message_snapshot(agent_session)
    except Exception as exc:
        if added_attachments and not update_committed:
            try:
                remove_agent_attachments(session_id, added_attachments)
            except OSError:
                logger.warning(
                    '回滚 Agent 排队附件失败',
                    extra={
                        'session_id': session_id,
                        'message_id': message_id,
                    },
                    exc_info=True,
                )
        try:
            return _agent_message_mutation_error(exc)
        except Exception:
            logger.exception(
                '编辑 Agent 排队消息失败',
                extra={'session_id': session_id, 'message_id': message_id},
            )
            return jsonify(success=False, message='无法编辑排队消息'), 500
    return jsonify(
        success=True,
        agent_message=_decorate_agent_session_message(updated),
        session_state=state,
    )


@problem_core_bp.post(
    '/api/agent/sessions/<session_id>/messages/<message_id>/delete'
)
@problem_core_bp.post(
    '/agent/tasks/<session_id>/messages/<message_id>/delete'
)
def agent_task_message_delete(session_id, message_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        agent_session = _agent_message_route_session(session_id, user)
        _agent_quota_gate(
            user,
            endpoint_source=agent_session.get('endpoint_source'),
        )
        current = next((
            item for item in list_agent_session_messages(
                session_id,
                delivery_modes='queue',
                statuses='queued',
            )
            if str(item.get('message_id') or '') == str(message_id)
        ), None)
        if not current:
            raise AgentSessionMessageNotFoundError('Agent 排队消息不存在')
        removed_attachments = cancel_queued_agent_session_message(
            session_id,
            message_id,
            expected_attachments=current.get('attachments') or [],
        )
        _remove_agent_attachments_best_effort(
            session_id,
            removed_attachments,
        )
        state = _agent_session_message_snapshot(agent_session)
    except Exception as exc:
        try:
            return _agent_message_mutation_error(exc)
        except Exception:
            logger.exception(
                '删除 Agent 排队消息失败',
                extra={'session_id': session_id, 'message_id': message_id},
            )
            return jsonify(success=False, message='无法删除排队消息'), 500
    return jsonify(success=True, session_state=state)


@problem_core_bp.post(
    '/api/agent/sessions/<session_id>/messages/<message_id>/send-now'
)
@problem_core_bp.post(
    '/agent/tasks/<session_id>/messages/<message_id>/send-now'
)
def agent_task_message_send_now(session_id, message_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        agent_session = _agent_message_route_session(session_id, user)
        _agent_quota_gate(
            user,
            endpoint_source=agent_session.get('endpoint_source'),
        )
        expected_task_id = str(
            request.form.get('expected_task_id') or ''
        ).strip()
        if not expected_task_id:
            raise AgentSessionMessageConflictError(
                '立刻发送缺少当前任务标识，请刷新后重试'
            )
        steer_supported, steer_reason = read_agent_steer_capability(
            session_id,
            agent_session.get('harness'),
        )
        if not steer_supported:
            raise AgentSessionMessageConflictError(
                steer_reason or '当前 Harness 暂不支持中途插话'
            )
        updated = steer_queued_agent_session_message(
            session_id,
            message_id,
            task_id=expected_task_id,
        )
        refreshed_session = get_agent_session(session_id) or agent_session
        state = _agent_session_message_snapshot(refreshed_session)
    except Exception as exc:
        try:
            return _agent_message_mutation_error(exc)
        except Exception:
            logger.exception(
                '立刻发送 Agent 排队消息失败',
                extra={
                    'session_id': session_id,
                    'message_id': message_id,
                },
            )
            return jsonify(success=False, message='无法立刻发送排队消息'), 500
    return jsonify(
        success=True,
        agent_message=_decorate_agent_session_message(updated),
        session_state=state,
    )


@problem_core_bp.post('/api/agent/sessions/<session_id>/queue/reorder')
@problem_core_bp.post('/agent/tasks/<session_id>/queue/reorder')
def agent_task_queue_reorder(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        agent_session = _agent_message_route_session(session_id, user)
        _agent_quota_gate(
            user,
            endpoint_source=agent_session.get('endpoint_source'),
        )
        if request.is_json:
            body = request.get_json(silent=True) or {}
            message_ids = body.get('message_ids') or []
        else:
            message_ids = request.form.getlist('message_ids')
        reorder_queued_agent_session_messages(session_id, message_ids)
        state = _agent_session_message_snapshot(agent_session)
    except Exception as exc:
        try:
            return _agent_message_mutation_error(exc)
        except Exception:
            logger.exception(
                '重排 Agent 消息队列失败',
                extra={'session_id': session_id},
            )
            return jsonify(success=False, message='无法调整队列顺序'), 500
    return jsonify(success=True, session_state=state)


@problem_core_bp.post('/api/agent/sessions/<session_id>/queue/resume')
@problem_core_bp.post('/agent/tasks/<session_id>/queue/resume')
def agent_task_queue_resume(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        agent_session = _agent_message_route_session(session_id, user)
        _agent_quota_gate(
            user,
            endpoint_source=agent_session.get('endpoint_source'),
        )
        normalized_status = str(agent_session.get('status') or '').strip().lower()
        if normalized_status in {'cleanupfailed', 'cleanup_failed'}:
            raise AgentSessionMessageConflictError(
                '上一轮 Agent 容器尚未完成清理，不能继续队列'
            )
        continue_agent_session_queue(session_id)
        try:
            if _agent_queue_dispatch_task is None:
                raise RuntimeError('Agent 消息队列未初始化')
            _agent_queue_dispatch_task.apply_async(args=(session_id,))
        except Exception:
            logger.warning(
                '唤醒已继续的 Agent 消息队列失败，等待周期恢复',
                extra={'session_id': session_id},
                exc_info=True,
            )
        agent_session = get_agent_session(session_id) or agent_session
        state = _agent_session_message_snapshot(agent_session)
    except Exception as exc:
        try:
            return _agent_message_mutation_error(exc)
        except Exception:
            logger.exception(
                '继续 Agent 消息队列失败',
                extra={'session_id': session_id},
            )
            return jsonify(success=False, message='无法继续消息队列'), 500
    return jsonify(success=True, session_state=state)


@problem_core_bp.get('/api/agent/sessions/<session_id>/workspace')
@problem_core_bp.get('/agent/tasks/<session_id>/workspace')
def agent_workspace_tree(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        agent_session = _agent_session_for_actor(
            session_id,
            _agent_actor(user),
        )
        if not agent_session:
            return jsonify(success=False, message='Agent 会话不存在'), 404
        if agent_session.get('is_legacy'):
            return jsonify(success=True, tree=[], unavailable=True)
        tree = build_agent_workspace_tree(session_id)
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except PermissionError as exc:
        return jsonify(success=False, message=str(exc)), 403
    except AgentSessionMessageNotFoundError as exc:
        return jsonify(success=False, message=str(exc)), 404
    except OSError:
        logger.exception('读取 Agent workspace 目录失败')
        return jsonify(success=False, message='无法读取 workspace'), 500
    response = jsonify(success=True, tree=tree)
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@problem_core_bp.get('/api/agent/sessions/<session_id>/workspace/file')
@problem_core_bp.get('/agent/tasks/<session_id>/workspace/file')
def agent_workspace_file(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    try:
        agent_session = _agent_session_for_actor(
            session_id,
            _agent_actor(user),
        )
        if not agent_session or agent_session.get('is_legacy'):
            return jsonify(success=False, message='Agent workspace 不存在'), 404
        relative_path = str(request.args.get('path') or '')
        if request.args.get('raw') == '1' or request.args.get('download') == '1':
            stream, metadata = open_agent_workspace_file(
                session_id,
                relative_path,
            )
            response = send_file(
                stream,
                mimetype=metadata.get('mime_type') or 'application/octet-stream',
                as_attachment=request.args.get('download') == '1',
                download_name=metadata.get('name') or 'download',
                conditional=False,
                etag=False,
                max_age=0,
            )
            response.call_on_close(stream.close)
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['Cache-Control'] = 'private, no-store'
            if request.args.get('download') != '1':
                response.headers['Content-Disposition'] = (
                    "inline; filename*=UTF-8''"
                    + quote(metadata.get('name') or 'preview', safe='')
                )
            return response

        metadata = inspect_agent_workspace_file(session_id, relative_path)
        if metadata.get('preview_kind') == 'markdown':
            metadata['html'] = render_rich_markdown(metadata.get('content'))
        response = jsonify(success=True, file=metadata)
        response.headers['Cache-Control'] = 'private, no-store'
        return response
    except FileNotFoundError:
        return jsonify(success=False, message='文件不存在'), 404
    except PermissionError as exc:
        return jsonify(success=False, message=str(exc)), 403
    except AgentSessionMessageNotFoundError as exc:
        return jsonify(success=False, message=str(exc)), 404
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except OSError:
        logger.exception(
            '读取 Agent workspace 文件失败',
            extra={'session_id': session_id},
        )
        return jsonify(success=False, message='无法读取文件'), 500


# Python 调用方的过渡别名不参与 Flask endpoint 注册；canonical endpoint
# 与页面生成的 URL 均使用上面的无 admin 名称。
admin_agent_launch_options = agent_launch_options
admin_agent_solve_problem = agent_solve_problem
admin_agent_generate_testdata = agent_generate_testdata
admin_agent_run_status = agent_run_status
admin_agent_run_work_block = agent_run_work_block
admin_agent_run_cancel = agent_run_cancel
admin_agent_run_stream = agent_run_stream
admin_agent_tasks = agent_tasks
admin_agent_task_detail = agent_task_detail
admin_agent_task_message_state = agent_task_message_state
admin_agent_task_message_stream = agent_task_message_stream
admin_agent_task_message_update = agent_task_message_update
admin_agent_task_message_delete = agent_task_message_delete
admin_agent_task_message_send_now = agent_task_message_send_now
admin_agent_task_queue_reorder = agent_task_queue_reorder
admin_agent_task_queue_resume = agent_task_queue_resume
admin_agent_workspace_tree = agent_workspace_tree
admin_agent_workspace_file = agent_workspace_file


@problem_core_bp.route('/my_submissions')
def all_submissions():
    return redirect('/submissions')
