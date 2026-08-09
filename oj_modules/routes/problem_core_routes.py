#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import logging
import re
import time
from datetime import datetime
from uuid import uuid4
from urllib.parse import quote

from flask import Blueprint, Response, current_app, flash, jsonify, redirect, render_template, request, send_file, stream_with_context, url_for
from werkzeug.utils import secure_filename

from oj_modules.db_services import (
    SubmissionLimitExceeded,
    archive_submission_by_id,
    archive_submission_file_by_id,
    can_submit,
    create_submission,
    get_agent_run_by_task_id,
    get_db_connection,
    get_filtered_submissions_paginated,
    get_latest_written_submission,
    get_problem,
    get_submission_problem_options,
    mark_submission_archive_failed,
    normalize_submission_list_status_filter,
    overwrite_written_submission,
    upsert_agent_run_snapshot,
)
from oj_modules.agents.sessions import (
    AgentSessionBusyError,
    AgentSessionNotFoundError,
    agent_status_is_terminal,
    begin_agent_session_turn,
    create_agent_session,
    get_agent_session,
    get_agent_session_by_task_id,
    get_agent_session_turns,
    get_agent_sessions_paginated,
    mark_agent_turn_enqueue_failed,
    set_agent_turn_attachments,
    normalize_agent_access_role,
)
from oj_modules.agents.workspace import (
    build_agent_workspace_tree,
    ensure_agent_workspace,
    inspect_agent_workspace_file,
    open_agent_workspace_file,
    remove_agent_attachments,
    save_agent_attachments,
)
from oj_modules.security.auth import current_user
from oj_modules.classroom.dashboard import (
    get_class_activity,
    get_layout_navigation_context,
    select_visible_class,
    visible_classes_for_user_cached,
)
from oj_modules.problems.agent_runs import (
    aggregate_agent_session_token_usage,
    hydrate_agent_run_snapshot,
)
from oj_modules.problems.agent_launch import (
    AgentLaunchValidationError,
    harness_options,
    list_launch_endpoints_by_harness,
    normalize_agent_task_kind,
    normalize_launch_harness,
    resolve_launch_endpoint,
    validate_launch_endpoint_revision,
)
from oj_modules.problems.agent_preferences import (
    get_agent_launch_preference,
    save_agent_launch_preference,
)
from oj_modules.problems.catalog import get_homeworks, get_user_classes_cached
from oj_modules.problems.context import (
    build_problem_detail_context,
    build_problem_library_context,
    build_problem_list_context,
)
from oj_modules.problems.presentation import (
    strip_problem_title_tags as _strip_problem_title_tags,
)
from oj_modules.submissions.written_artifacts import (
    WrittenSubmissionArtifactError,
    publish_manual_written_submission,
)
from oj_modules.shared.markdown import render_rich_markdown


problem_core_bp = Blueprint('problem_core', __name__)
logger = logging.getLogger(__name__)

_evaluate_submission_task = None
_promptly_generate_submission_task = None
_transcribe_written_homework_task = None
_agent_solve_problem_task = None
_agent_generate_testdata_task = None
_agent_run_turn_task = None
_get_agent_run_snapshot = None
_subscribe_agent_run_events = None
_terminate_agent_run = None


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


def _agent_session_cookie():
    cookie_name = str(current_app.config.get('SESSION_COOKIE_NAME') or 'session')
    session_cookie = str(request.cookies.get(cookie_name) or '')
    if not session_cookie:
        raise ValueError('当前登录身份不可用于 Agent')
    return cookie_name, session_cookie


def _agent_launch_page_options(user_id):
    endpoints_by_harness = list_launch_endpoints_by_harness()
    preference = get_agent_launch_preference(user_id) or {}
    preferred_harness = str(preference.get('harness') or '')
    try:
        preferred_endpoint_id = int(preference.get('endpoint_id') or 0)
    except (TypeError, ValueError):
        preferred_endpoint_id = 0
    valid = any(
        int(item.get('id') or 0) == preferred_endpoint_id
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
        preferred_endpoint_id = int(candidates[0]['id']) if candidates else 0
    return {
        'harnesses': harness_options(),
        'endpoints_by_harness': endpoints_by_harness,
        'preference': {
            'harness': preferred_harness,
            'endpoint_id': preferred_endpoint_id or None,
        },
    }


def _agent_message_from_request():
    message = str(request.form.get('message') or '').strip()
    if not message:
        raise ValueError('请输入任务内容')
    if len(message) > _AGENT_MESSAGE_MAX_CHARS:
        raise ValueError(f'任务内容不能超过 {_AGENT_MESSAGE_MAX_CHARS} 个字符')
    return message


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


def _agent_trace_conclusion(execution_trace):
    messages = (
        execution_trace.get('trace_messages')
        if isinstance(execution_trace, dict)
        else []
    ) or []
    for item in reversed(messages):
        if not isinstance(item, dict):
            continue
        kind = str(item.get('kind') or item.get('type') or '').strip().lower()
        text = item.get('text')
        if text is None:
            text = item.get('content')
        if kind == 'assistant' and str(text or '').strip():
            return str(text).strip()
    return ''


_AGENT_RICH_TRACE_KINDS = frozenset({'assistant', 'thinking', 'reasoning'})
_AGENT_CUMULATIVE_TRACE_HARNESSES = frozenset({'claude_code', 'pi'})
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


def _agent_trace_common_prefix_length(previous_messages, current_messages):
    limit = min(len(previous_messages), len(current_messages))
    for index in range(limit):
        if (
            _agent_trace_message_signature(previous_messages[index])
            != _agent_trace_message_signature(current_messages[index])
        ):
            return index
    return limit


def _agent_state_with_trace_delta(state, previous_messages=(), harness=''):
    """只投影累计 resume 轨迹的本轮增量，不改变 token usage。"""

    if not isinstance(state, dict):
        return state
    resolved_harness = _agent_trace_harness(state, harness)
    if resolved_harness not in _AGENT_CUMULATIVE_TRACE_HARNESSES:
        return state
    raw_trace = state.get('execution_trace')
    if not isinstance(raw_trace, dict):
        return state
    current_messages = _agent_trace_messages(raw_trace)
    if not current_messages:
        return state
    prefix_length = _agent_trace_common_prefix_length(
        list(previous_messages or ()),
        current_messages,
    )
    projected = dict(state)
    trace = dict(raw_trace)
    trace['trace_messages'] = current_messages[prefix_length:]
    projected['execution_trace'] = trace
    return projected


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
            # JSONL 由不可信 Agent 产生；任何随轨迹传入的 HTML 都不能直送浏览器。
            message.pop('html', None)
            kind = str(
                message.get('kind') or message.get('type') or 'assistant'
            ).strip().lower()
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
    conclusion = str(
        state.get('conclusion')
        or state.get('final_response')
        or trace.get('conclusion')
        or trace.get('final_response')
        or _agent_trace_conclusion(trace)
        or ''
    ).strip()
    if conclusion:
        state['conclusion'] = conclusion
        state['conclusion_html'] = str(render_rich_markdown(conclusion))
        if state.get('final_response'):
            state['final_response_html'] = state['conclusion_html']
    return state


def _decorate_agent_turns(turns):
    decorated = []
    previous_full_trace_by_harness = {}
    for raw_turn in turns or []:
        turn = dict(raw_turn)
        hydrated = hydrate_agent_run_snapshot({
            'task_id': turn.get('task_id'),
            'harness': turn.get('harness'),
            'endpoint_id': turn.get('endpoint_id'),
            'endpoint_model': turn.get('endpoint_model'),
            'status': turn.get('status'),
            'message': turn.get('conclusion') or '',
        })
        harness = _agent_trace_harness(hydrated, turn.get('harness'))
        full_messages = list(_agent_trace_messages(
            hydrated.get('execution_trace') if isinstance(hydrated, dict) else None
        ))
        hydrated = _agent_state_with_trace_delta(
            hydrated,
            previous_full_trace_by_harness.get(harness, ()),
            harness,
        )
        # Pi / Claude Code 的空失败轮不代表原生会话历史被清空；下一轮仍需
        # 以上一份非空完整轨迹为 baseline。
        if (
            harness in _AGENT_CUMULATIVE_TRACE_HARNESSES
            and full_messages
        ):
            previous_full_trace_by_harness[harness] = full_messages
        snapshot = _decorate_agent_state_markdown(hydrated)
        trace = snapshot.get('execution_trace') or {}
        conclusion = str(turn.get('conclusion') or '').strip()
        if not conclusion and agent_status_is_terminal(turn.get('status')):
            conclusion = _agent_trace_conclusion(trace)
        turn['execution_trace'] = trace
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


def _load_agent_historical_token_usages(session_id, current_task_id):
    """为 SSE/状态响应一次性读取历史轮次的规范任务轨迹。"""

    current_task_id = str(current_task_id or '').strip()
    usages = []
    for turn in get_agent_session_turns(session_id):
        task_id = str(turn.get('task_id') or '').strip()
        if not task_id or task_id == current_task_id:
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
    return usages


def _load_agent_previous_trace_messages(session_id, current_task_id, harness):
    """按轮次顺序读取当前轮之前最近一份非空完整 resume 轨迹。"""

    current_task_id = str(current_task_id or '').strip()
    harness = str(harness or '').strip().lower()
    if harness not in _AGENT_CUMULATIVE_TRACE_HARNESSES:
        return []
    previous_messages = []
    for turn in get_agent_session_turns(session_id):
        task_id = str(turn.get('task_id') or '').strip()
        if task_id == current_task_id:
            break
        if not task_id:
            continue
        turn_harness = str(turn.get('harness') or harness).strip().lower()
        if turn_harness != harness:
            continue
        persisted = get_agent_run_by_task_id(task_id)
        state = {
            'task_id': task_id,
            'harness': turn_harness,
            'endpoint_id': turn.get('endpoint_id'),
            'endpoint_model': turn.get('endpoint_model'),
            'status': turn.get('status'),
            'message': turn.get('conclusion') or '',
        }
        if isinstance(persisted, dict):
            state.update(persisted)
        hydrated = hydrate_agent_run_snapshot(state)
        messages = _agent_trace_messages(
            hydrated.get('execution_trace')
            if isinstance(hydrated, dict) else None
        )
        if messages:
            previous_messages = list(messages)
    return previous_messages


def _agent_trace_session_context(state, task_id=''):
    """从状态或会话映射解析增量轨迹所需的 session / harness。"""

    if not isinstance(state, dict):
        return '', ''
    resolved_task_id = str(task_id or state.get('task_id') or '').strip()
    session_id = str(state.get('session_id') or '').strip()
    harness = _agent_trace_harness(state)
    if session_id and harness:
        return session_id, harness
    if not session_id and not harness:
        return '', ''
    if harness and harness not in _AGENT_CUMULATIVE_TRACE_HARNESSES:
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


def _agent_state_with_loaded_session_trace_delta(state):
    """为状态/停止响应按会话历史投影本轮新增轨迹。"""

    if not isinstance(state, dict):
        return state
    current_task_id = str(state.get('task_id') or '').strip()
    try:
        session_id, harness = _agent_trace_session_context(
            state,
            current_task_id,
        )
        previous_messages = (
            _load_agent_previous_trace_messages(
                session_id,
                current_task_id,
                harness,
            )
            if session_id else []
        )
    except Exception:
        logger.warning(
            '读取 Agent 会话历史轨迹失败',
            extra={
                'session_id': str(state.get('session_id') or ''),
                'task_id': current_task_id,
            },
            exc_info=True,
        )
        return state
    return _agent_state_with_trace_delta(state, previous_messages, harness)


def _agent_state_with_session_token_usage(state, historical_usages=()):
    """把历史基线与当前任务实时快照合成为会话级权威用量。"""

    if not isinstance(state, dict):
        return state
    projected = dict(state)
    task_usages = list(historical_usages or ())
    current_usage = _agent_token_usage_from_state(projected)
    current_task_id = str(projected.get('task_id') or '').strip()
    if current_task_id and current_usage is not None:
        # aggregate helper 按 task_id 最后写入覆盖，避免历史/current 重复计数。
        task_usages.append((current_task_id, current_usage))
    projected['session_token_usage'] = aggregate_agent_session_token_usage(
        task_usages
    )
    return projected


def _agent_state_with_loaded_session_token_usage(state):
    """有可信 session_id 时补齐历史；普通旧任务保持当前任务统计。"""

    if not isinstance(state, dict):
        return state
    session_id = str(state.get('session_id') or '').strip()
    current_task_id = str(state.get('task_id') or '').strip()
    historical_usages = ()
    if session_id and current_task_id:
        try:
            historical_usages = _load_agent_historical_token_usages(
                session_id,
                current_task_id,
            )
        except Exception:
            # 用量展示不能阻断状态接口；失败时仍返回当前任务的规范统计。
            logger.warning(
                '读取 Agent 会话历史用量失败',
                extra={
                    'session_id': session_id,
                    'task_id': current_task_id,
                },
                exc_info=True,
            )
    return _agent_state_with_session_token_usage(state, historical_usages)


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
):
    global _evaluate_submission_task, _promptly_generate_submission_task
    global _transcribe_written_homework_task
    global _agent_solve_problem_task, _agent_generate_testdata_task
    global _agent_run_turn_task
    global _get_agent_run_snapshot, _subscribe_agent_run_events
    global _terminate_agent_run
    _evaluate_submission_task = evaluate_submission_task
    _promptly_generate_submission_task = promptly_generate_submission_task
    _transcribe_written_homework_task = transcribe_written_homework_task
    _agent_solve_problem_task = agent_solve_problem_task
    _agent_generate_testdata_task = agent_generate_testdata_task
    _agent_run_turn_task = agent_run_turn_task
    _get_agent_run_snapshot = get_agent_run_snapshot
    _subscribe_agent_run_events = subscribe_agent_run_events
    _terminate_agent_run = terminate_agent_run


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


def _agent_state_for_response(task_id, raw_state, agent_session=None):
    return _decorate_agent_state_markdown(
        _overlay_agent_session_cleanup_failure(
            task_id,
            raw_state,
            agent_session=agent_session,
        )
    )


def _get_agent_run_state(task_id):
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
        return _agent_state_for_response(
            task_id,
            hydrate_agent_run_snapshot(
                _overlay_agent_celery_terminal(task_id, state),
            )
        )
    state = get_agent_run_by_task_id(task_id)
    if isinstance(state, dict):
        return _agent_state_for_response(
            task_id,
            hydrate_agent_run_snapshot(
                _overlay_agent_celery_terminal(task_id, state),
            )
        )
    return _agent_state_for_response(
        task_id,
        hydrate_agent_run_snapshot(
            _build_agent_state_from_async_result(task_id),
        )
    )


def _submission_limit_redirect(problem_id, submission_limit):
    flash(f'您对此题的提交次数已达到上限（{submission_limit}次）！', 'danger')
    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))


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
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    context = build_problem_list_context(
        user,
        admin_class_view=(int(user.get('is_admin') or 0) == 1),
        selected_class_en=request.args.get('class_en'),
        include_dashboard=True,
        include_class_activity=False,
    )
    return render_template('problems/list.html', **context)


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
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))
    if int(user.get('is_admin') or 0) != 1:
        flash('无权限访问总题库', 'danger')
        return redirect(url_for('problem_core.problem_list'))
    return render_template(
        'problems/list.html',
        **build_problem_library_context(user),
    )


@problem_core_bp.route('/problem/<int:problem_id>', methods=['GET'])
def problem_detail(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    context, error_code = build_problem_detail_context(
        user,
        problem_id,
        selected_class_en=request.args.get('class_en'),
    )
    if error_code == "not_found":
        return "<h3>题目不存在</h3>"
    if error_code == "forbidden":
        flash('无权限访问该题目', 'danger')
        return redirect(url_for('problem_core.problem_list'))

    return render_template('problems/detail.html', **context)


@problem_core_bp.route('/admin/agent_launch_options', methods=['GET'])
def admin_agent_launch_options():
    """返回本次启动可选项和当前管理员在此类任务中的上次选择。"""

    user = current_user()
    if not user or int(user.get('is_admin') or 0) != 1:
        return jsonify(success=False, message='无权限'), 403
    try:
        task_kind = normalize_agent_task_kind(request.args.get('task_kind'))
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
    )
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


@problem_core_bp.route('/admin/agent_solve_problem/<int:problem_id>', methods=['POST'])
def admin_agent_solve_problem(problem_id):
    user = current_user()
    if not user or user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message='题目不存在'), 404
    if int(problem.get('type') or 1) != 1:
        return jsonify(success=False, message='仅支持编程题'), 400
    if _agent_solve_problem_task is None:
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
    pending_state = {
        "task_id": task_id,
        "session_id": task_id,
        "problem_id": int(problem.get("id") or problem_id),
        "problem_title": problem.get("title"),
        "requested_by": user.get("username"),
        "task_kind": "solve",
        "harness": harness,
        "endpoint_id": endpoint_id,
        "endpoint_model": endpoint.get("model"),
        "status": "Pending",
        "message": "任务排队中",
        "best_score": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
    }
    upsert_agent_run_snapshot(pending_state)
    try:
        create_agent_session(
            session_id=task_id,
            task_id=task_id,
            requested_by=user['username'],
            harness=harness,
            endpoint_id=endpoint_id,
            endpoint_revision=endpoint.get('revision'),
            endpoint_model=endpoint.get("model"),
            user_message=(
                f"解决题目 #{int(problem.get('id') or problem_id)}："
                f"{str(problem.get('title') or '').strip()}"
            ),
            task_kind="solve",
            access_role="user",
            problem_id=int(problem.get("id") or problem_id),
            problem_title=problem.get("title"),
        )
    except Exception:
        logger.exception('创建解题 Agent 会话失败')
        pending_state["status"] = "Failed"
        pending_state["message"] = "无法创建 Agent 会话"
        upsert_agent_run_snapshot(pending_state)
        return jsonify(success=False, message=pending_state["message"]), 500

    try:
        _agent_solve_problem_task.apply_async(
            args=(
                problem_id,
                user['username'],
                harness,
                endpoint_id,
                session_cookie,
                cookie_name,
                endpoint.get('revision'),
            ),
            task_id=task_id,
        )
    except Exception:
        logger.exception('解题 Agent 任务入队失败')
        failure_message = _mark_agent_dispatch_failed(
            task_id,
            task_id,
            pending_state,
            "任务入队失败，请检查 Celery agent 队列",
        )
        return jsonify(success=False, message=failure_message), 500

    return jsonify(
        success=True,
        message='Agent 任务已启动',
        task_id=task_id,
        view_url=url_for(
            'problem_core.admin_agent_task_detail',
            session_id=task_id,
        ),
    )


@problem_core_bp.route('/admin/agent_generate_testdata/<int:problem_id>', methods=['POST'])
def admin_agent_generate_testdata(problem_id):
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
    if _agent_generate_testdata_task is None:
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
    pending_state = {
        "task_id": task_id,
        "session_id": task_id,
        "problem_id": int(problem.get("id") or problem_id),
        "problem_title": problem.get("title"),
        "requested_by": user.get("username"),
        "task_kind": "testdata",
        "harness": harness,
        "endpoint_id": endpoint_id,
        "endpoint_model": endpoint.get("model"),
        "status": "Pending",
        "message": "数据生成 Agent 任务排队中",
        "best_score": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
    }
    upsert_agent_run_snapshot(pending_state)
    try:
        requirement_summary = data_requirement or "请自行覆盖边界、典型与压力场景"
        create_agent_session(
            session_id=task_id,
            task_id=task_id,
            requested_by=user['username'],
            harness=harness,
            endpoint_id=endpoint_id,
            endpoint_revision=endpoint.get('revision'),
            endpoint_model=endpoint.get("model"),
            user_message=(
                f"为题目 #{int(problem.get('id') or problem_id)} 生成 "
                f"{test_point_count} 个测试点。\n\n{requirement_summary}"
            ),
            task_kind="testdata",
            access_role="user",
            problem_id=int(problem.get("id") or problem_id),
            problem_title=problem.get("title"),
        )
    except Exception:
        logger.exception('创建造数据 Agent 会话失败')
        pending_state["status"] = "Failed"
        pending_state["message"] = "无法创建 Agent 会话"
        upsert_agent_run_snapshot(pending_state)
        return jsonify(success=False, message=pending_state["message"]), 500

    try:
        _agent_generate_testdata_task.apply_async(
            args=(
                problem_id,
                user['username'],
                test_point_count,
                standard_code,
                data_requirement,
                standard_filename,
                harness,
                endpoint_id,
                session_cookie,
                cookie_name,
                endpoint.get('revision'),
            ),
            task_id=task_id,
        )
    except Exception:
        logger.exception('造数据 Agent 任务入队失败')
        failure_message = _mark_agent_dispatch_failed(
            task_id,
            task_id,
            pending_state,
            "任务入队失败，请检查 Celery agent 队列",
        )
        return jsonify(success=False, message=failure_message), 500

    return jsonify(
        success=True,
        message='数据生成 Agent 任务已启动',
        task_id=task_id,
        view_url=url_for(
            'problem_core.admin_agent_task_detail',
            session_id=task_id,
        ),
    )


@problem_core_bp.route('/admin/agent_run_status/<task_id>', methods=['GET'])
def admin_agent_run_status(task_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    if user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

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
    state = _agent_state_with_loaded_session_trace_delta(state)
    return jsonify(success=True, state=state)


@problem_core_bp.route('/admin/agent_run_cancel/<task_id>', methods=['POST'])
def admin_agent_run_cancel(task_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    if user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403
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
    state = _agent_state_with_loaded_session_trace_delta(state)
    if not result.get('canceled'):
        return jsonify(
            success=False,
            message='Agent 任务已经结束，无法终止',
            state=state,
        ), 409

    errors = [str(item) for item in result.get('errors') or [] if str(item)]
    if errors:
        return jsonify(
            success=False,
            message='任务已标记为终止，但运行时清理失败',
            state=state,
            errors=errors,
        ), 500

    return jsonify(
        success=True,
        message=('任务已终止' if result.get('changed') else '任务已经终止'),
        state=state,
    )


@problem_core_bp.route('/admin/agent_run_stream/<task_id>', methods=['GET'])
def admin_agent_run_stream(task_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if user.get('is_admin') != 1:
        return jsonify({'error': 'Access denied'}), 403

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

    @stream_with_context
    def generate():
        historical_usages = ()
        loaded_session_id = ''
        previous_trace_messages = ()
        loaded_trace_session_id = ''
        loaded_trace_harness = ''

        def with_session_projection(snapshot):
            nonlocal historical_usages, loaded_session_id
            nonlocal previous_trace_messages
            nonlocal loaded_trace_session_id, loaded_trace_harness
            if not isinstance(snapshot, dict):
                return snapshot
            session_id = str(snapshot.get('session_id') or '').strip()
            harness = _agent_trace_harness(snapshot)
            if not session_id or not harness:
                try:
                    resolved_session_id, resolved_harness = (
                        _agent_trace_session_context(snapshot, task_id)
                    )
                    session_id = session_id or resolved_session_id
                    harness = harness or resolved_harness
                except Exception:
                    logger.warning(
                        '读取 Agent SSE 会话轨迹上下文失败',
                        extra={'task_id': task_id},
                        exc_info=True,
                    )
            session_id = session_id or loaded_trace_session_id
            harness = harness or loaded_trace_harness
            if session_id and session_id != loaded_session_id:
                try:
                    historical_usages = _load_agent_historical_token_usages(
                        session_id,
                        task_id,
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
            trace_context_changed = (
                session_id != loaded_trace_session_id
                or harness != loaded_trace_harness
            )
            if session_id and trace_context_changed:
                try:
                    previous_trace_messages = (
                        _load_agent_previous_trace_messages(
                            session_id,
                            task_id,
                            harness,
                        )
                    )
                except Exception:
                    previous_trace_messages = ()
                    logger.warning(
                        '读取 Agent SSE 会话历史轨迹失败',
                        extra={
                            'session_id': session_id,
                            'task_id': task_id,
                        },
                        exc_info=True,
                    )
                loaded_trace_session_id = session_id
                loaded_trace_harness = harness
            projected = _agent_state_with_session_token_usage(
                snapshot,
                historical_usages,
            )
            return _agent_state_with_trace_delta(
                projected,
                previous_trace_messages,
                harness or loaded_trace_harness,
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

                snapshot = _agent_state_for_response(
                    task_id,
                    hydrate_agent_run_snapshot(snapshot)
                )
                snapshot = with_session_projection(snapshot)
                yield _encode_sse("status", snapshot)
                last_marker = _snapshot_marker(snapshot)
                if _is_agent_state_finished(snapshot):
                    yield _encode_sse("done", snapshot)
                    return
        finally:
            if pubsub is not None:
                try:
                    pubsub.close()
                except Exception:
                    pass

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
    )


@problem_core_bp.route('/submit/<int:problem_id>', methods=['GET', 'POST'])
def submit_solution(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    problem = get_problem(problem_id)
    if not problem:
        return "<h3>题目不存在</h3>"

    if user['is_admin'] != 1:
        homeworks = get_homeworks(user)
        ddls = []
        for hw in homeworks:
            if hw['problem_id'] == problem_id:
                if hw['ddl']:
                    ddls.append(hw['ddl'])

        if ddls:
            latest_ddl = max(ddls)
            if latest_ddl < datetime.now():
                flash('无法提交已过期的作业', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

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

                return redirect(url_for('submission.submission_detail', submission_id=submission_id))

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

            return redirect(url_for('submission.submission_detail', submission_id=submission_id))

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
                    return redirect(url_for('submission.submission_detail', submission_id=submission_id))
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

            return redirect(url_for('submission.submission_detail', submission_id=submission_id))

    context, error_code = build_problem_detail_context(user, problem_id)
    if error_code == "not_found":
        return "<h3>题目不存在</h3>"
    if error_code == "forbidden":
        flash('无权限访问该题目', 'danger')
        return redirect(url_for('problem_core.problem_list'))
    return render_template('problems/detail.html', **context)


@problem_core_bp.route('/admin/agent_tasks', methods=['GET', 'POST'])
def admin_agent_tasks():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))
    if user.get('is_admin') != 1:
        flash('无权限访问该页面', 'danger')
        return redirect(url_for('problem_core.problem_list'))

    if request.method == 'POST':
        if _agent_run_turn_task is None:
            return jsonify(success=False, message='通用 Agent 任务未初始化'), 500
        if request.mimetype != 'multipart/form-data':
            return jsonify(success=False, message='请使用 multipart/form-data'), 415
        try:
            message = _agent_message_from_request()
            access_role = normalize_agent_access_role(
                request.form.get('access_role')
            )
            harness = normalize_launch_harness(request.form.get('harness'))
            endpoint = resolve_launch_endpoint(
                harness,
                request.form.get('endpoint_id'),
                include_secret=False,
            )
            endpoint_id = int(endpoint['id'])
            cookie_name, session_cookie = _agent_session_cookie()
        except (AgentLaunchValidationError, ValueError) as exc:
            return jsonify(success=False, message=str(exc)), 400

        session_id = uuid4().hex
        attachments = []
        try:
            save_agent_launch_preference(user['id'], harness, endpoint_id)
            ensure_agent_workspace(session_id)
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
                endpoint_id=endpoint_id,
                endpoint_revision=endpoint.get('revision'),
                endpoint_model=endpoint.get('model'),
                user_message=message,
                attachments=attachments,
                task_kind='custom',
                access_role=access_role,
            )
        except (ValueError, OSError) as exc:
            remove_agent_attachments(session_id, attachments)
            return jsonify(success=False, message=str(exc)), 400
        except Exception:
            remove_agent_attachments(session_id, attachments)
            logger.exception('创建通用 Agent 会话失败')
            return jsonify(success=False, message='无法创建 Agent 会话'), 500

        pending_state = _pending_agent_run_state(agent_session, session_id)
        try:
            upsert_agent_run_snapshot(pending_state)
            _agent_run_turn_task.apply_async(
                args=(
                    session_id,
                    user['username'],
                    access_role,
                    harness,
                    endpoint_id,
                    session_cookie,
                    _agent_prompt_with_attachments(message, attachments),
                    cookie_name,
                    '',
                    True,
                ),
                task_id=session_id,
            )
        except Exception:
            logger.exception('通用 Agent 首轮任务入队失败')
            failure_message = _mark_agent_dispatch_failed(
                session_id,
                session_id,
                pending_state,
                '任务入队失败，请检查 Celery agent 队列',
            )
            return jsonify(success=False, message=failure_message), 500

        detail_url = url_for(
            'problem_core.admin_agent_task_detail',
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
    sessions, page, total_pages = get_agent_sessions_paginated(
        page=page,
        per_page=per_page,
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
    if open_session is not None:
        return redirect(url_for(
            'problem_core.admin_agent_task_detail',
            session_id=open_session['session_id'],
        ))

    try:
        launch_options = _agent_launch_page_options(user['id'])
    except Exception:
        logger.exception('读取通用 Agent 启动选项失败')
        launch_options = {
            'harnesses': harness_options(),
            'endpoints_by_harness': {},
            'preference': {'harness': '', 'endpoint_id': None},
        }

    return render_template(
        'admin/agent_tasks.html',
        user=user,
        agent_sessions=sessions,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        **launch_options,
    )


@problem_core_bp.route(
    '/admin/agent_tasks/<session_id>',
    methods=['GET', 'POST'],
)
def admin_agent_task_detail(session_id):
    user = current_user()
    if not user:
        if request.method == 'GET':
            return redirect(url_for('auth.login'))
        return jsonify(success=False, message='未登录'), 401
    if int(user.get('is_admin') or 0) != 1:
        if request.method == 'GET':
            flash('无权限访问该页面', 'danger')
            return redirect(url_for('problem_core.problem_list'))
        return jsonify(success=False, message='无权限'), 403

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
                'problem_core.admin_agent_task_detail',
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

    if request.method == 'POST':
        if agent_session.get('is_legacy'):
            return jsonify(
                success=False,
                message='旧任务没有可恢复的 workspace，无法继续会话',
            ), 409
        if str(agent_session.get('requested_by') or '') != str(user.get('username') or ''):
            return jsonify(success=False, message='只能继续自己发起的 Agent 会话'), 403
        if _agent_run_turn_task is None:
            return jsonify(success=False, message='通用 Agent 任务未初始化'), 500
        if request.mimetype != 'multipart/form-data':
            return jsonify(success=False, message='请使用 multipart/form-data'), 415
        if not agent_status_is_terminal(agent_session.get('status')):
            return jsonify(success=False, message='上一轮 Agent 任务尚未结束'), 409
        if not str(agent_session.get('native_session_id') or '').strip():
            return jsonify(
                success=False,
                message='上一轮未建立可恢复的原生会话，无法继续；请新建 Agent 会话',
            ), 409
        try:
            frozen_endpoint = resolve_launch_endpoint(
                agent_session.get('harness'),
                agent_session.get('endpoint_id'),
                include_secret=False,
            )
            validate_launch_endpoint_revision(
                frozen_endpoint,
                agent_session.get('endpoint_revision'),
            )
        except AgentLaunchValidationError as exc:
            return jsonify(success=False, message=str(exc)), 409
        try:
            message = _agent_message_from_request()
            cookie_name, session_cookie = _agent_session_cookie()
        except ValueError as exc:
            return jsonify(success=False, message=str(exc)), 400

        task_id = uuid4().hex
        try:
            turn_claim = begin_agent_session_turn(
                session_id,
                task_id=task_id,
                user_message=message,
                attachments=[],
            )
        except AgentSessionBusyError as exc:
            return jsonify(success=False, message=str(exc)), 409
        except AgentSessionNotFoundError as exc:
            return jsonify(success=False, message=str(exc)), 404
        except (ValueError, OSError) as exc:
            return jsonify(success=False, message=str(exc)), 400
        except Exception:
            logger.exception(
                '创建 Agent 续聊轮次失败',
                extra={'session_id': session_id},
            )
            return jsonify(success=False, message='无法创建 Agent 续聊轮次'), 500

        # 只使用 begin_agent_session_turn 在行锁内返回的权威冻结值，避免
        # 并发终态投影后仍用请求开始时读到的旧 native session。
        frozen_session = {**agent_session, **turn_claim}
        turn_index = int(turn_claim["turn_index"])
        pending_state = _pending_agent_run_state(frozen_session, task_id)
        attachments = []
        try:
            attachments = save_agent_attachments(
                session_id,
                task_id,
                request.files.getlist('attachments'),
            )
            set_agent_turn_attachments(session_id, task_id, attachments)
        except (ValueError, OSError) as exc:
            remove_agent_attachments(session_id, attachments)
            _mark_agent_dispatch_failed(
                session_id,
                task_id,
                pending_state,
                f'附件保存失败：{str(exc)}',
            )
            return jsonify(
                success=False,
                message=str(exc),
                detail_url=url_for(
                    'problem_core.admin_agent_task_detail',
                    session_id=session_id,
                ),
            ), 400
        except Exception:
            remove_agent_attachments(session_id, attachments)
            logger.exception(
                '保存 Agent 续聊附件失败',
                extra={'session_id': session_id, 'task_id': task_id},
            )
            failure_message = _mark_agent_dispatch_failed(
                session_id,
                task_id,
                pending_state,
                '附件保存失败，请重新发送消息',
            )
            return jsonify(
                success=False,
                message=failure_message,
                detail_url=url_for(
                    'problem_core.admin_agent_task_detail',
                    session_id=session_id,
                ),
            ), 500
        try:
            upsert_agent_run_snapshot(pending_state)
            _agent_run_turn_task.apply_async(
                args=(
                    session_id,
                    user['username'],
                    frozen_session.get('access_role') or 'user',
                    frozen_session.get('harness'),
                    int(frozen_session.get('endpoint_id')),
                    session_cookie,
                    _agent_prompt_with_attachments(message, attachments),
                    cookie_name,
                    frozen_session.get('native_session_id') or '',
                    False,
                ),
                task_id=task_id,
            )
        except Exception:
            logger.exception(
                'Agent 续聊任务入队失败',
                extra={'session_id': session_id, 'task_id': task_id},
            )
            failure_message = _mark_agent_dispatch_failed(
                session_id,
                task_id,
                pending_state,
                '任务入队失败，请检查 Celery agent 队列',
            )
            return jsonify(
                success=False,
                message=failure_message,
                detail_url=url_for(
                    'problem_core.admin_agent_task_detail',
                    session_id=session_id,
                ),
            ), 500

        return jsonify(
            success=True,
            message='消息已发送',
            session_id=session_id,
            task_id=task_id,
            turn_index=turn_index,
            user_message=message,
            user_message_html=render_rich_markdown(message),
            attachments=attachments,
        )

    turns = _decorate_agent_turns(get_agent_session_turns(session_id))
    current_task_id = str(agent_session.get('current_task_id') or session_id)
    current_state = _get_agent_run_state(current_task_id) or (
        _agent_state_for_response(current_task_id, {
            'task_id': current_task_id,
            'session_id': session_id,
            'status': agent_session.get('status') or 'Pending',
            'message': agent_session.get('message') or '任务排队中',
            'native_session_id': agent_session.get('native_session_id') or '',
            'execution_trace': {},
        })
    )
    current_state = _agent_state_for_response(
        current_task_id,
        current_state,
        agent_session=agent_session,
    )
    # 持久 run 快照带有 endpoint_id，能为每个历史轮次按规范价格重建成本；
    # 不能直接拿用于展示的 turn 简版状态汇总，否则 priced 会话会被误判未定价。
    current_state = dict(current_state)
    current_state['session_id'] = session_id
    current_state = _agent_state_with_loaded_session_token_usage(current_state)
    current_state = _agent_state_with_loaded_session_trace_delta(current_state)
    try:
        workspace_tree = (
            []
            if agent_session.get('is_legacy')
            else build_agent_workspace_tree(session_id)
        )
    except (ValueError, OSError):
        workspace_tree = []
    response = current_app.make_response(render_template(
        'admin/agent_task_detail.html',
        user=user,
        agent_session=agent_session,
        turns=turns,
        current_state=current_state,
        workspace_tree=workspace_tree,
        can_resume=(
            str(agent_session.get('requested_by') or '')
            == str(user.get('username') or '')
        ),
    ))
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@problem_core_bp.get('/admin/agent_tasks/<session_id>/workspace')
def admin_agent_workspace_tree(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    if int(user.get('is_admin') or 0) != 1:
        return jsonify(success=False, message='无权限'), 403
    try:
        agent_session = get_agent_session(session_id)
        if not agent_session:
            return jsonify(success=False, message='Agent 会话不存在'), 404
        if agent_session.get('is_legacy'):
            return jsonify(success=True, tree=[], unavailable=True)
        tree = build_agent_workspace_tree(session_id)
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except OSError:
        logger.exception('读取 Agent workspace 目录失败')
        return jsonify(success=False, message='无法读取 workspace'), 500
    response = jsonify(success=True, tree=tree)
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@problem_core_bp.get('/admin/agent_tasks/<session_id>/workspace/file')
def admin_agent_workspace_file(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    if int(user.get('is_admin') or 0) != 1:
        return jsonify(success=False, message='无权限'), 403
    try:
        agent_session = get_agent_session(session_id)
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
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except OSError:
        logger.exception(
            '读取 Agent workspace 文件失败',
            extra={'session_id': session_id},
        )
        return jsonify(success=False, message='无法读取文件'), 500


@problem_core_bp.route('/my_submissions')
def all_submissions():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    page = max(1, request.args.get('page', 1, type=int))
    per_page = 30
    query = str(request.args.get('q') or '').strip()[:120]
    status_filter = normalize_submission_list_status_filter(
        request.args.get('status')
    )
    problem_id = request.args.get('problem_id', type=int)
    if not problem_id or problem_id < 1:
        problem_id = None

    scope_username = None if user['is_admin'] else user['username']
    submissions, page, total_pages = get_filtered_submissions_paginated(
        username=scope_username,
        page=page,
        per_page=per_page,
        query=query,
        status_filter=status_filter,
        problem_id=problem_id,
        include_test_points=True,
    )
    for sub in submissions:
        sub['display_problem_title'] = _strip_problem_title_tags(sub.get('problem_title'))
        sub['is_ac'] = (sub.get('status') == 'Accepted')
        sub['display_language'] = str(sub.get('lang') or '—').upper()
        max_score = sub.get('max_score')
        try:
            max_score = int(max_score) if max_score is not None else None
        except (TypeError, ValueError):
            max_score = None
        sub['display_max_score'] = (
            max_score
            if max_score is not None and max_score > 0
            else (sub.get('test_points_count') or None)
        )

    problem_options = get_submission_problem_options(username=scope_username)
    current_problem_label = ''
    for option in problem_options:
        option['display_problem_title'] = _strip_problem_title_tags(
            option.get('problem_title')
        )
        option['filter_label'] = (
            f"P{int(option['problem_id']):04d} · "
            f"{option['display_problem_title']}"
        )
        if int(option['problem_id']) == int(problem_id or 0):
            current_problem_label = option['filter_label']

    page_start = max(1, page - 3)
    page_end = min(total_pages, page + 3)
    page_numbers = list(range(page_start, page_end + 1))

    return render_template(
        'submissions/all.html',
        submissions=submissions,
        user=user,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        problem_options=problem_options,
        current_problem_label=current_problem_label,
        filters={
            'q': query,
            'status': status_filter,
            'problem_id': problem_id,
        },
    )
