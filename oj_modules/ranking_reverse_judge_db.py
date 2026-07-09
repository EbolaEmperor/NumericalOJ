#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛反向评测的步骤结果表与快照构造。"""

import json
import os
import time

from oj_modules.db_services import get_db_connection
from oj_modules.ranking_agent_judge import render_md_math
from oj_modules.ranking_db import get_ranking_submission


STEP_SOLUTION = 'solution_check'
STEP_AGENT = 'agent_answer'
STEP_AI_JUDGE = 'ai_judge'

STEP_DEFS = (
    (STEP_SOLUTION, 1, '标准答案自检'),
    (STEP_AGENT, 2, 'AI 作答'),
    (STEP_AI_JUDGE, 3, '评测 AI 答案'),
)
STEP_DEF_BY_KEY = {key: {'step_key': key, 'step_order': order, 'title': title}
                   for key, order, title in STEP_DEFS}
STEP_KEYS = tuple(key for key, _, _ in STEP_DEFS)
TERMINAL_STEP_STATUSES = {'passed', 'failed', 'error'}

_TRACE_MAX_FILES = 16
_TRACE_MAX_FILE_BYTES = 64 * 1024
_TRACE_MAX_TOTAL_BYTES = 256 * 1024
_TRACE_JSONL_PARSE_MAX_BYTES = 1024 * 1024
_TRACE_MAX_MESSAGES = 80
_TRACE_THINKING_MAX_CHARS = 1200
_TRACE_TOOL_MAX_CHARS = 1200
_TRACE_TEXT_EXTS = {
    '.json', '.jsonl', '.md', '.txt', '.log', '.toml', '.yaml', '.yml',
    '.xml', '.html', '.htm', '.csv',
}


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
    """重置并预置三步记录。仅在 submission 当前 attempt 仍匹配时生效。"""
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
                       CASE WHEN %s IN ('passed', 'failed', 'error') THEN CURRENT_TIMESTAMP ELSE NULL END
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
        row.setdefault('step_key', key)
        row.setdefault('step_order', order)
        row.setdefault('title', title)
        row.setdefault('status', 'pending')
        out.append(row)
    return out


def _format_now():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())


def _parse_result(raw):
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _short_text(value, limit=120000):
    text = '' if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + f'\n...（已截断，原始长度 {len(text)} 字符）'


def _looks_text_file(path):
    _, ext = os.path.splitext(path.lower())
    if ext in _TRACE_TEXT_EXTS:
        return True
    base = os.path.basename(path).lower()
    return base in {'.aj_session_state.json', '.aj_session_state.jsonl'}


def _latest_claude_jsonl(trace_dir):
    trace_dir = str(trace_dir or '').strip()
    if not trace_dir or not os.path.isdir(trace_dir):
        return None
    base = os.path.realpath(trace_dir)
    candidates = []
    preferred_root = os.path.join(base, '.claude', 'projects', '-workspace')
    combined = os.path.join(preferred_root, 'reverse_solve_combined.jsonl')
    if os.path.isfile(combined):
        return combined
    roots = [preferred_root] if os.path.isdir(preferred_root) else []
    if not roots:
        roots = [base]
    for root in roots:
        for walk_root, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in {'node_modules', '__pycache__'}]
            for name in names:
                if not name.endswith('.jsonl'):
                    continue
                path = os.path.realpath(os.path.join(walk_root, name))
                if path != base and not path.startswith(base + os.sep):
                    continue
                rel = os.path.relpath(path, base)
                if '.claude/projects/-workspace/' not in rel.replace(os.sep, '/'):
                    continue
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                candidates.append((mtime, path))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def _latest_codex_jsonl(trace_dir):
    trace_dir = str(trace_dir or '').strip()
    if not trace_dir or not os.path.isdir(trace_dir):
        return None
    base = os.path.realpath(trace_dir)
    preferred = os.path.join(base, 'codex_reverse_solve.jsonl')
    if os.path.isfile(preferred):
        return preferred
    codex_root = os.path.join(base, '.codex')
    roots = [codex_root] if os.path.isdir(codex_root) else []
    candidates = []
    for root in roots:
        for walk_root, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in {'node_modules', '__pycache__'}]
            for name in names:
                if not name.endswith('.jsonl'):
                    continue
                path = os.path.realpath(os.path.join(walk_root, name))
                if path != base and not path.startswith(base + os.sep):
                    continue
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                candidates.append((mtime, path))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def _read_limited_text(path, limit):
    try:
        size = os.path.getsize(path)
    except OSError:
        return '', 0, 0
    try:
        with open(path, 'rb') as f:
            raw = f.read(min(size, limit))
        text = raw.decode('utf-8', 'replace')
    except Exception:
        return '', int(size), 0
    if size > limit:
        text += f'\n...（已截断，文件大小 {size} 字节）'
    return text, int(size), min(int(size), int(limit))


def _collect_trace_files(trace_dir):
    claude_jsonl = _latest_claude_jsonl(trace_dir)
    if claude_jsonl:
        text, size, _read_bytes = _read_limited_text(claude_jsonl, _TRACE_MAX_TOTAL_BYTES)
        if text:
            return [{
                'path': os.path.relpath(claude_jsonl, os.path.realpath(trace_dir)),
                'size': size,
                'content': text,
            }]
    codex_jsonl = _latest_codex_jsonl(trace_dir)
    if codex_jsonl:
        text, size, _read_bytes = _read_limited_text(codex_jsonl, _TRACE_MAX_TOTAL_BYTES)
        if text:
            return [{
                'path': os.path.relpath(codex_jsonl, os.path.realpath(trace_dir)),
                'size': size,
                'content': text,
            }]
    trace_dir = str(trace_dir or '').strip()
    if not trace_dir or not os.path.isdir(trace_dir):
        return []
    files = []
    total = 0
    base = os.path.realpath(trace_dir)
    for root, dirs, names in os.walk(base):
        dirs[:] = [d for d in dirs if d not in {'node_modules', '__pycache__'}]
        names = sorted(names)
        for name in names:
            path = os.path.realpath(os.path.join(root, name))
            if path != base and not path.startswith(base + os.sep):
                continue
            rel = os.path.relpath(path, base)
            if not _looks_text_file(path):
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            remaining = _TRACE_MAX_TOTAL_BYTES - total
            if remaining <= 0 or len(files) >= _TRACE_MAX_FILES:
                return files
            read_bytes = min(size, _TRACE_MAX_FILE_BYTES, remaining)
            try:
                with open(path, 'rb') as f:
                    raw = f.read(read_bytes)
                text = raw.decode('utf-8', 'replace')
            except Exception:
                continue
            if size > read_bytes:
                text += f'\n...（已截断，文件大小 {size} 字节）'
            files.append({'path': rel, 'size': int(size), 'content': text})
            total += read_bytes
    return files


def _content_text(content):
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ''
    parts = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get('type') == 'text':
            text = str(item.get('text') or '').strip()
            if text:
                parts.append(text)
    return '\n\n'.join(parts).strip()


def _codex_text(value):
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ('text', 'message', 'content', 'output_text', 'summary'):
            text = _codex_text(value.get(key))
            if text:
                return text
        return ''
    if isinstance(value, list):
        parts = []
        for item in value:
            text = _codex_text(item)
            if text:
                parts.append(text)
        return '\n\n'.join(parts).strip()
    return ''


def _thinking_text(item):
    if not isinstance(item, dict) or item.get('type') != 'thinking':
        return ''
    text = str(item.get('thinking') or '').strip()
    if len(text) > _TRACE_THINKING_MAX_CHARS:
        text = text[:_TRACE_THINKING_MAX_CHARS] + '…'
    return text


def _truncate_trace_text(text, limit):
    text = str(text or '').strip()
    if len(text) > int(limit):
        text = text[:int(limit)] + '…'
    return text


def _dump_trace_json(value):
    try:
        raw_json = json.dumps(value, ensure_ascii=False, indent=2)
    except Exception:
        raw_json = str(value)
    return _truncate_trace_text(raw_json, _TRACE_TOOL_MAX_CHARS)


def _tool_line(label, value):
    text = str(value or '').strip()
    if not text:
        return ''
    return f'{label}：{text}'


def _tool_block(label, value, limit=900):
    text = _truncate_trace_text(value, limit)
    if not text:
        return ''
    return f'{label}：\n{text}'


def _join_tool_lines(parts):
    return '\n'.join([p for p in parts if p]).strip()


def _tool_message(title, text, meta, *, kind='tool', line_no=None, fmt='text'):
    msg = {
        'kind': kind,
        'title': title,
        'text': text,
        'meta': str(meta or ''),
        'format': fmt,
    }
    if line_no is not None:
        msg['line'] = line_no
    return msg


def _unknown_tool_message(name, raw, *, kind='tool', line_no=None, title=None):
    return _tool_message(
        title or f'调用 {name or "工具"}',
        _dump_trace_json(raw),
        name or '工具',
        kind=kind,
        line_no=line_no,
        fmt='json',
    )


def _parse_json_object(value):
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    try:
        obj = json.loads(value)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _format_todos(todos):
    if not isinstance(todos, list):
        return ''
    lines = []
    for idx, todo in enumerate(todos[:12], start=1):
        if not isinstance(todo, dict):
            continue
        status = str(todo.get('status') or '').strip()
        content = str(todo.get('content') or '').strip()
        if content:
            lines.append(f'{idx}. [{status or "-"}] {content}')
    if len(todos) > 12:
        lines.append(f'... 另有 {len(todos) - 12} 项')
    return '\n'.join(lines)


def _known_claude_tool_message(name, payload):
    key = str(name or '').strip().lower()
    if key == 'bash':
        text = _join_tool_lines([
            _tool_line('说明', payload.get('description')),
            _tool_block('命令', payload.get('command')),
            _tool_line('超时', payload.get('timeout')),
        ])
        return _tool_message('运行命令', text, 'Bash') if text else None
    if key in {'read', 'readfile'}:
        text = _join_tool_lines([
            _tool_line('文件', payload.get('file_path') or payload.get('path')),
            _tool_line('起始行', payload.get('offset')),
            _tool_line('行数', payload.get('limit')),
        ])
        return _tool_message('读取文件', text, name) if text else None
    if key in {'write', 'writefile'}:
        text = _join_tool_lines([
            _tool_line('文件', payload.get('file_path') or payload.get('path')),
            _tool_block('内容预览', payload.get('content'), limit=500),
        ])
        return _tool_message('写入文件', text, name) if text else None
    if key == 'edit':
        text = _join_tool_lines([
            _tool_line('文件', payload.get('file_path') or payload.get('path')),
            _tool_block('查找', payload.get('old_string'), limit=360),
            _tool_block('替换为', payload.get('new_string'), limit=360),
        ])
        return _tool_message('修改文件', text, name) if text else None
    if key == 'multiedit':
        edits = payload.get('edits') if isinstance(payload.get('edits'), list) else []
        text = _join_tool_lines([
            _tool_line('文件', payload.get('file_path') or payload.get('path')),
            _tool_line('修改数', len(edits) if edits else ''),
        ])
        return _tool_message('批量修改文件', text, name) if text else None
    if key == 'glob':
        text = _join_tool_lines([
            _tool_line('目录', payload.get('path')),
            _tool_line('模式', payload.get('pattern')),
        ])
        return _tool_message('查找文件', text, name) if text else None
    if key == 'grep':
        text = _join_tool_lines([
            _tool_line('目录', payload.get('path')),
            _tool_line('模式', payload.get('pattern')),
            _tool_line('文件过滤', payload.get('glob') or payload.get('include')),
            _tool_line('输出模式', payload.get('output_mode')),
        ])
        return _tool_message('搜索文本', text, name) if text else None
    if key in {'ls', 'list'}:
        text = _join_tool_lines([
            _tool_line('目录', payload.get('path')),
            _tool_line('忽略', ', '.join(payload.get('ignore')) if isinstance(payload.get('ignore'), list) else payload.get('ignore')),
        ])
        return _tool_message('列出目录', text, name) if text else None
    if key == 'todowrite':
        text = _format_todos(payload.get('todos'))
        return _tool_message('更新待办', text, name) if text else None
    if key == 'webfetch':
        text = _join_tool_lines([
            _tool_line('URL', payload.get('url')),
            _tool_block('请求', payload.get('prompt'), limit=500),
        ])
        return _tool_message('读取网页', text, name) if text else None
    if key == 'websearch':
        text = _join_tool_lines([
            _tool_line('查询', payload.get('query')),
            _tool_line('允许域名', ', '.join(payload.get('allowed_domains')) if isinstance(payload.get('allowed_domains'), list) else payload.get('allowed_domains')),
            _tool_line('排除域名', ', '.join(payload.get('blocked_domains')) if isinstance(payload.get('blocked_domains'), list) else payload.get('blocked_domains')),
        ])
        return _tool_message('搜索网页', text, name) if text else None
    return None


def _tool_use_message(item):
    if not isinstance(item, dict) or item.get('type') != 'tool_use':
        return None
    name = str(item.get('name') or '').strip()
    payload = item.get('input') if isinstance(item.get('input'), dict) else {}
    is_task = name.lower() == 'task' or 'subagent' in name.lower() or payload.get('subagent_type')
    if is_task:
        meta = str(payload.get('subagent_type') or name or 'subagent').strip()
        text = _join_tool_lines([
            _tool_line('类型', payload.get('subagent_type')),
            _tool_line('任务', payload.get('description')),
            _tool_block('提示', payload.get('prompt'), limit=900),
        ])
        if text:
            return _tool_message('派出 subagent', text, meta, kind='subagent')
        return _unknown_tool_message(name or 'subagent', item, kind='subagent', title='派出 subagent')
    parsed = _known_claude_tool_message(name, payload)
    if parsed:
        return parsed
    return _unknown_tool_message(name, item)


def _trace_message(kind, title, text, meta, line_no):
    msg = {
        'kind': kind,
        'title': title,
        'text': text,
        'meta': str(meta or ''),
        'line': line_no,
    }
    if kind in {'assistant', 'thinking'}:
        msg['html'] = render_md_math(text)
    return msg


def _codex_tool_name(event, item):
    for obj in (item, event):
        if isinstance(obj, dict):
            for key in ('name', 'tool_name', 'command', 'cmd'):
                value = str(obj.get(key) or '').strip()
                if value:
                    return 'Shell' if key in {'command', 'cmd'} else value
    typ = str((item or {}).get('type') or event.get('type') or '').strip()
    if 'exec' in typ or 'command' in typ:
        return 'Shell'
    if typ:
        return typ
    return '工具'


def _codex_tool_payload(event, item):
    args = {}
    for key in ('arguments', 'args', 'input', 'parameters'):
        value = item.get(key) if isinstance(item, dict) else None
        parsed = _parse_json_object(value)
        if parsed:
            args.update(parsed)
        elif isinstance(value, dict):
            args.update(value)
    for key in ('command', 'cmd'):
        value = str((item or {}).get(key) or event.get(key) or '').strip()
        if value and 'command' not in args:
            args['command'] = value
    return args


def _known_codex_tool_message(name, event, item, line_no):
    key = str(name or '').strip().lower()
    payload = _codex_tool_payload(event, item)
    if key == 'shell':
        command = payload.get('command') or payload.get('cmd')
        if command:
            return _tool_message(
                '运行命令',
                _join_tool_lines([
                    _tool_line('命令', command),
                    _tool_line('工作目录', payload.get('workdir') or payload.get('cwd')),
                ]),
                'Shell',
                line_no=line_no,
            )
    if key in {'apply_patch', 'update_plan', 'view_image'}:
        text = _dump_trace_json(payload) if payload else _dump_trace_json(item or event)
        return _tool_message(f'调用 {name}', text, name, line_no=line_no)
    if payload:
        # 对普通 function_call，至少把已解析参数展示出来；解析不出参数的才回退原始 JSON。
        return _tool_message(f'调用 {name}', _dump_trace_json(payload), name, line_no=line_no)
    return None


def _codex_tool_message(event, item, line_no):
    name = _codex_tool_name(event, item)
    parsed = _known_codex_tool_message(name, event, item, line_no)
    if parsed:
        return parsed
    return _unknown_tool_message(name, event, line_no=line_no)


def _codex_error_message(event, line_no, meta):
    return _tool_message(
        'Codex 错误',
        _dump_trace_json(event),
        str(meta or 'error'),
        line_no=line_no,
        fmt='json',
    )


def _codex_event_messages(event, line_no):
    typ = str(event.get('type') or '').strip()
    item = event.get('item') if isinstance(event.get('item'), dict) else {}
    item_type = str(item.get('type') or '').strip()
    messages = []

    if typ == 'error' or item_type == 'error' or typ in {'turn.failed', 'turn.error'}:
        messages.append(_codex_error_message(event, line_no, item_type or typ))
        return messages

    if typ in {'agent_message', 'assistant_message'}:
        text = _codex_text(event.get('message') or event.get('text') or event.get('content'))
        if text:
            messages.append(_trace_message('assistant', 'AI 回复', text, event.get('model') or typ, line_no))
        return messages

    if typ in {'agent_reasoning', 'reasoning'}:
        text = _codex_text(event.get('message') or event.get('text') or event.get('content') or event.get('summary'))
        if text:
            messages.append(_trace_message('thinking', '思考片段', text, event.get('model') or typ, line_no))
        return messages

    if item_type == 'message' and str(item.get('role') or '').lower() == 'assistant':
        text = _codex_text(item.get('content') or item.get('message') or item.get('text'))
        if text:
            messages.append(_trace_message('assistant', 'AI 回复', text, event.get('model') or typ, line_no))
        return messages

    if item_type in {'reasoning', 'reasoning_summary'}:
        text = _codex_text(item.get('summary') or item.get('content') or item.get('text'))
        if text:
            messages.append(_trace_message('thinking', '思考片段', text, event.get('model') or typ, line_no))
        return messages

    tool_markers = ('tool', 'function_call', 'exec_command', 'command')
    if item_type in {'function_call', 'tool_call', 'custom_tool_call'} or any(marker in typ for marker in tool_markers):
        messages.append(_codex_tool_message(event, item, line_no))
    return messages


def _collect_claude_trace_messages(path):
    if not path:
        return []
    text, _size, _read_bytes = _read_limited_text(path, _TRACE_JSONL_PARSE_MAX_BYTES)
    if not text:
        return []
    messages = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        raw = raw.strip()
        if not raw or raw.startswith('...（已截断'):
            continue
        try:
            event = json.loads(raw)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        if event.get('type') != 'assistant':
            continue
        msg = event.get('message') if isinstance(event.get('message'), dict) else {}
        content = msg.get('content')
        visible_text = _content_text(content)
        if visible_text:
            messages.append(_trace_message(
                'assistant',
                'AI 回复',
                visible_text,
                msg.get('model') or event.get('timestamp') or '',
                line_no,
            ))
        if isinstance(content, list):
            for item in content:
                thinking = _thinking_text(item)
                if thinking:
                    messages.append(_trace_message(
                        'thinking',
                        '思考片段',
                        thinking,
                        msg.get('model') or event.get('timestamp') or '',
                        line_no,
                    ))
                tool_msg = _tool_use_message(item)
                if tool_msg:
                    tool_msg['line'] = line_no
                    tool_msg['meta'] = str(tool_msg.get('meta') or '')
                    messages.append(tool_msg)
        if len(messages) >= _TRACE_MAX_MESSAGES:
            messages = messages[-_TRACE_MAX_MESSAGES:]
    return messages[-_TRACE_MAX_MESSAGES:]


def _collect_codex_trace_messages(path):
    text, _size, _read_bytes = _read_limited_text(path, _TRACE_JSONL_PARSE_MAX_BYTES)
    if not text:
        return []
    messages = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        raw = raw.strip()
        if not raw or raw.startswith('...（已截断'):
            continue
        try:
            event = json.loads(raw)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        messages.extend(_codex_event_messages(event, line_no))
        if len(messages) >= _TRACE_MAX_MESSAGES:
            messages = messages[-_TRACE_MAX_MESSAGES:]
    return messages[-_TRACE_MAX_MESSAGES:]


def _collect_trace_messages(trace_dir):
    claude_path = _latest_claude_jsonl(trace_dir)
    if claude_path:
        return _collect_claude_trace_messages(claude_path)
    codex_path = _latest_codex_jsonl(trace_dir)
    if codex_path:
        return _collect_codex_trace_messages(codex_path)
    return []


def build_reverse_judge_snapshot(submission_id):
    submission = get_ranking_submission(submission_id)
    if not submission:
        return None
    steps = []
    for row in list_reverse_judge_steps(submission_id):
        result = _parse_result(row.get('result_json'))
        item = {
            'step_key': row.get('step_key'),
            'step_order': int(row.get('step_order') or 0),
            'title': row.get('title') or '',
            'status': row.get('status') or 'pending',
            'max_score': row.get('max_score'),
            'score': row.get('score'),
            'result': result,
            'stdout': _short_text(row.get('stdout')),
            'stderr': _short_text(row.get('stderr')),
            'error_message': row.get('error_message') or '',
            'trace_files': _collect_trace_files(row.get('trace_dir')),
            'trace_messages': _collect_trace_messages(row.get('trace_dir')),
            'started_at': str(row.get('started_at') or ''),
            'finished_at': str(row.get('finished_at') or ''),
        }
        steps.append(item)
    return {
        'submission_id': int(submission_id),
        'status': submission.get('status') or '',
        'total_score': submission.get('score'),
        'max_score': 100.0,
        'error_message': submission.get('error_message') or '',
        'steps': steps,
        'last_updated': _format_now(),
    }
