#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Claude、Codex 与 Pi 运行轨迹的安全发现、读取和展示投影。"""

import json
import os
from decimal import Decimal, InvalidOperation

from oj_modules.ranking.agent_judge.rules import render_md_math


_TRACE_MAX_FILES = 16
_TRACE_MAX_FILE_BYTES = 64 * 1024
_TRACE_MAX_TOTAL_BYTES = 256 * 1024
_TRACE_JSONL_PARSE_MAX_BYTES = 2 * 1024 * 1024
_TRACE_MAX_MESSAGES = 240
_TRACE_THINKING_MAX_CHARS = 1200
_TRACE_TOOL_MAX_CHARS = 1200
_TRACE_TOOL_RESULT_MAX_CHARS = 1200
_PI_NON_TEXT_OMITTED = '（已省略图片或非文本内容）'
_TRACE_TEXT_EXTS = {
    '.json', '.jsonl', '.md', '.txt', '.log', '.toml', '.yaml', '.yml',
    '.xml', '.html', '.htm', '.csv',
}


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
    for combined_name in ('agent_judge_combined.jsonl', 'reverse_solve_combined.jsonl'):
        combined = os.path.join(preferred_root, combined_name)
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
    for preferred_name in (
            'codex_agent_judge.jsonl', 'opencode_agent_judge.jsonl',
            'codex_reverse_solve.jsonl'):
        preferred = os.path.join(base, preferred_name)
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


def _is_pi_session_jsonl(path):
    """只把带 v3 session header 的 JSONL 识别为 Pi 原生会话。"""
    try:
        with open(path, 'rb') as f:
            first_line = f.readline(256 * 1024)
        header = json.loads(first_line.decode('utf-8', 'replace'))
    except Exception:
        return False
    if not isinstance(header, dict) or header.get('type') != 'session':
        return False
    try:
        return int(header.get('version')) == 3
    except (TypeError, ValueError):
        return False


def _latest_pi_jsonl(trace_dir):
    trace_dir = str(trace_dir or '').strip()
    if not trace_dir or not os.path.isdir(trace_dir):
        return None
    base = os.path.realpath(trace_dir)

    # reverse worker 会把容器内 ~/.pi/agent/sessions 原样镜像到 trace_dir，
    # 并生成一个稳定的合并 journal。根目录文件仅用于兼容早期实现和 fixture。
    preferred_paths = (
        os.path.join(
            base, '.pi', 'agent', 'sessions', 'reverse_solve_combined.jsonl',
        ),
        os.path.join(base, 'pi_reverse_solve.jsonl'),
    )
    for preferred in preferred_paths:
        path = os.path.realpath(preferred)
        if (path == base or path.startswith(base + os.sep)) and os.path.isfile(path):
            return path

    sessions_root = os.path.join(base, '.pi', 'agent', 'sessions')
    if not os.path.isdir(sessions_root):
        return None
    candidates = []
    for walk_root, dirs, names in os.walk(sessions_root):
        dirs[:] = [d for d in dirs if d not in {'node_modules', '__pycache__'}]
        for name in names:
            if not name.endswith('.jsonl'):
                continue
            path = os.path.realpath(os.path.join(walk_root, name))
            if path != base and not path.startswith(base + os.sep):
                continue
            if not _is_pi_session_jsonl(path):
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


def _read_jsonl_tail(path, limit):
    """返回 JSONL 尾部完整行及其绝对字节偏移，内存占用严格受 limit 约束。"""
    try:
        size = int(os.path.getsize(path))
    except OSError:
        return []
    if size <= 0:
        return []
    start = max(0, size - max(1, int(limit)))
    read_start = max(0, start - 1)
    try:
        with open(path, 'rb') as f:
            f.seek(read_start)
            raw = f.read(size - read_start)
    except Exception:
        return []

    base_offset = read_start
    if start > 0:
        previous = raw[:1]
        raw = raw[1:]
        base_offset = start
        if previous != b'\n':
            boundary = raw.find(b'\n')
            if boundary < 0:
                return []
            raw = raw[boundary + 1:]
            base_offset += boundary + 1

    rows = []
    offset = base_offset
    for encoded in raw.splitlines(keepends=True):
        line = encoded.rstrip(b'\r\n')
        if line:
            rows.append((offset, line.decode('utf-8', 'replace')))
        offset += len(encoded)
    return rows


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
    pi_jsonl = _latest_pi_jsonl(trace_dir)
    if pi_jsonl:
        # Pi session 允许工具结果携带图片等非文本 payload。原始 JSONL
        # 保留在磁盘用于审计，但不得经 snapshot / SSE 的 raw trace 投影泄露。
        return []
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
    part = event.get('part') if isinstance(event.get('part'), dict) else {}
    part_type = str(part.get('type') or '').strip().lower().replace('-', '_')
    messages = []

    if typ == 'error' or item_type == 'error' or typ in {'turn.failed', 'turn.error'}:
        messages.append(_codex_error_message(event, line_no, item_type or typ))
        return messages

    if typ in {'agent_message', 'assistant_message'}:
        text = _codex_text(event.get('message') or event.get('text') or event.get('content'))
        if text:
            messages.append(_trace_message('assistant', 'AI 回复', text, event.get('model') or typ, line_no))
        return messages

    if (typ in {'agent_reasoning', 'reasoning', 'thinking'}
            or part_type in {'thinking', 'reasoning'}):
        text = _codex_text(
            event.get('message') or event.get('text') or event.get('content')
            or event.get('summary') or part
        )
        if text:
            messages.append(_trace_message(
                'thinking', '思考片段', text,
                event.get('model') or part.get('model')
                or ('opencode' if part else typ), line_no,
            ))
        return messages

    # OpenCode 的 JSON stream 使用顶层 type + part；在公共解析层直接兼容，
    # 避免任一调用方为了展示而重写、截断原始 journal。
    if typ in {'text', 'message'} or part_type in {'text', 'message'}:
        text = _codex_text(part or event)
        if text:
            messages.append(_trace_message(
                'assistant', 'AI 回复', text,
                event.get('model') or part.get('model') or 'opencode', line_no,
            ))
        return messages

    if 'tool' in typ.lower() or part_type == 'tool':
        state = part.get('state') if isinstance(part.get('state'), dict) else {}
        tool_item = {
            'type': 'tool_call',
            'name': (
                part.get('tool') or part.get('name')
                or event.get('tool') or event.get('name') or '工具'
            ),
            'input': (
                state.get('input')
                if isinstance(state.get('input'), dict)
                else part.get('input')
            ),
        }
        messages.append(_codex_tool_message(event, tool_item, line_no))
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


def _pi_tool_call_message(item, line_no):
    name = str(item.get('name') or '').strip()
    payload = item.get('arguments') if isinstance(item.get('arguments'), dict) else {}
    parsed = _known_claude_tool_message(name, payload)
    if parsed:
        parsed['line'] = line_no
        return parsed
    return _tool_message(
        f'调用 {name or "工具"}',
        _dump_trace_json(payload),
        name or '工具',
        line_no=line_no,
        fmt='json',
    )


def _truncate_pi_tool_result(text, limit=_TRACE_TOOL_RESULT_MAX_CHARS):
    text = str(text or '').strip()
    limit = max(1, int(limit))
    if len(text) <= limit:
        return text
    # 上限包含截断符，保证单条 toolResult 投影严格不超过 1200 字符。
    return text[:limit - 1] + '…'


def _pi_tool_result_text(content):
    parts = []
    omitted_non_text = False
    if isinstance(content, str):
        if content.strip():
            parts.append(content.strip())
    elif isinstance(content, list):
        for block in content:
            if (isinstance(block, dict)
                    and str(block.get('type') or '').strip().lower() == 'text'
                    and isinstance(block.get('text'), str)):
                text = block['text'].strip()
                if text:
                    parts.append(text)
            else:
                # image.data、details 及任意未知结构都不得进入 snapshot / SSE。
                omitted_non_text = True
    elif content is not None:
        omitted_non_text = True
    text = '\n\n'.join(parts)
    if not omitted_non_text:
        return _truncate_pi_tool_result(text)
    if not text:
        return _PI_NON_TEXT_OMITTED
    separator = '\n\n'
    text_limit = (
        _TRACE_TOOL_RESULT_MAX_CHARS
        - len(separator)
        - len(_PI_NON_TEXT_OMITTED)
    )
    return (
        _truncate_pi_tool_result(text, text_limit)
        + separator
        + _PI_NON_TEXT_OMITTED
    )


def _pi_tool_result_message(message, line_no):
    text = _pi_tool_result_text(message.get('content'))
    if not text:
        return None
    tool_name = str(message.get('toolName') or '').strip()
    is_error = message.get('isError') is True
    return {
        'kind': 'tool_result',
        'title': '工具执行失败' if is_error else '工具结果',
        'text': text,
        'meta': tool_name,
        'format': 'text',
        'is_error': is_error,
        'line': line_no,
    }


def _pi_model_error_message(message, line_no):
    error_text = str(message.get('errorMessage') or '').strip()
    stop_reason = str(message.get('stopReason') or '').strip().lower()
    if not error_text and stop_reason not in {'error', 'aborted'}:
        return None
    if not error_text:
        error_text = f'模型调用以 stopReason={stop_reason} 结束'
    meta = ' / '.join(filter(None, (
        str(message.get('provider') or '').strip(),
        str(message.get('model') or '').strip(),
    )))
    return {
        'kind': 'tool_result',
        'title': '模型调用失败',
        'text': _truncate_pi_tool_result(error_text),
        'meta': meta,
        'format': 'text',
        'is_error': True,
        'line': line_no,
    }


def _pi_event_messages(event, line_no):
    """把 Pi session v3 的完成态 message entry 投影为共享轨迹消息。"""
    # JSON mode 的 message_start/message_update/message_end 与 token delta 不是
    # 原生 session entry；只接收 session-manager 持久化的 type="message"。
    if event.get('type') != 'message':
        return []
    message = event.get('message')
    if not isinstance(message, dict):
        return []
    role = str(message.get('role') or '').strip().lower().replace('_', '')
    if role == 'toolresult':
        result = _pi_tool_result_message(message, line_no)
        return [result] if result else []
    if role != 'assistant':
        return []

    content = message.get('content')
    meta = message.get('model') or message.get('provider') or event.get('timestamp') or ''
    messages = []
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            item_type = str(item.get('type') or '').strip().lower().replace('_', '').replace('-', '')
            if item_type == 'text' and isinstance(item.get('text'), str):
                text = item['text'].strip()
                if text:
                    messages.append(_trace_message(
                        'assistant', 'AI 回复', text, meta, line_no,
                    ))
            elif item_type == 'thinking' and isinstance(item.get('thinking'), str):
                thinking = _thinking_text({
                    'type': 'thinking',
                    'thinking': item.get('thinking'),
                })
                if thinking:
                    messages.append(_trace_message(
                        'thinking', '思考片段', thinking, meta, line_no,
                    ))
            elif item_type == 'toolcall':
                messages.append(_pi_tool_call_message(item, line_no))
    error = _pi_model_error_message(message, line_no)
    if error:
        messages.append(error)
    return messages


def _collect_claude_trace_messages(path):
    if not path:
        return []
    messages = []
    # Claude resume/fork 会把父会话历史完整复制进新的 JSONL。事件 uuid 在各 fork
    # 间保持稳定，因此在共享渲染层按 uuid 去重，既保留每次 resume 的新增轨迹，
    # 也避免旧历史随阶段数成倍重复。没有 uuid 的兼容事件仍按原样保留。
    seen_event_uuids = set()
    rows = _read_jsonl_tail(path, _TRACE_JSONL_PARSE_MAX_BYTES)
    for line_no, (source_offset, raw) in enumerate(
            rows, start=1):
        message_start = len(messages)
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        event_uuid = event.get('uuid')
        if isinstance(event_uuid, str) and 0 < len(event_uuid) <= 128:
            if event_uuid in seen_event_uuids:
                continue
            seen_event_uuids.add(event_uuid)
        event_offset = event.get('_trace_offset', source_offset)
        event_source = str(event.get('_trace_source') or '')
        event_phase = str(event.get('_trace_phase') or '')
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
        for event_index, item in enumerate(messages[message_start:]):
            item['offset'] = event_offset
            item['event_index'] = event_index
            if event_source:
                item['source'] = event_source
            if event_phase:
                item['phase'] = event_phase
        if len(messages) >= _TRACE_MAX_MESSAGES:
            messages = messages[-_TRACE_MAX_MESSAGES:]
    return messages[-_TRACE_MAX_MESSAGES:]


def _collect_codex_trace_messages(path):
    messages = []
    rows = _read_jsonl_tail(path, _TRACE_JSONL_PARSE_MAX_BYTES)
    for line_no, (source_offset, raw) in enumerate(
            rows, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        parsed = _codex_event_messages(event, line_no)
        event_offset = event.get('_trace_offset', source_offset)
        event_source = str(event.get('_trace_source') or '')
        event_phase = str(event.get('_trace_phase') or '')
        for event_index, item in enumerate(parsed):
            item['offset'] = event_offset
            item['event_index'] = event_index
            if event_source:
                item['source'] = event_source
            if event_phase:
                item['phase'] = event_phase
        messages.extend(parsed)
        if len(messages) >= _TRACE_MAX_MESSAGES:
            messages = messages[-_TRACE_MAX_MESSAGES:]
    return messages[-_TRACE_MAX_MESSAGES:]


def _collect_pi_trace_messages(path):
    messages = []
    rows = _read_jsonl_tail(path, _TRACE_JSONL_PARSE_MAX_BYTES)
    for line_no, (source_offset, raw) in enumerate(rows, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        parsed = _pi_event_messages(event, line_no)
        event_offset = event.get('_trace_offset')
        if (not isinstance(event_offset, int)
                or isinstance(event_offset, bool) or event_offset < 0):
            event_offset = source_offset
        event_source = str(event.get('_trace_source') or '').strip()
        if (not event_source.startswith('pi')
                or len(event_source) > 80
                or any(not (ch.isalnum() or ch in '-_') for ch in event_source)):
            event_source = 'pi'
        event_phase = str(event.get('_trace_phase') or '').strip()[:80]
        for event_index, item in enumerate(parsed):
            item['offset'] = event_offset
            item['event_index'] = event_index
            item['source'] = event_source
            if event_phase:
                item['phase'] = event_phase
        messages.extend(parsed)
        if len(messages) >= _TRACE_MAX_MESSAGES:
            messages = messages[-_TRACE_MAX_MESSAGES:]
    return messages[-_TRACE_MAX_MESSAGES:]


def _collect_trace_messages(trace_dir):
    claude_path = _latest_claude_jsonl(trace_dir)
    if claude_path:
        return _collect_claude_trace_messages(claude_path)
    pi_path = _latest_pi_jsonl(trace_dir)
    if pi_path:
        return _collect_pi_trace_messages(pi_path)
    codex_path = _latest_codex_jsonl(trace_dir)
    if codex_path:
        return _collect_codex_trace_messages(codex_path)
    return []


def _nonnegative_token_count(value):
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _usage_record(source, event):
    """把四种 harness 的单次模型调用归一化为同一 token 口径。"""

    event_type = str(event.get('type') or '').strip().lower().replace('-', '_')
    message = event.get('message') if isinstance(event.get('message'), dict) else {}

    if source == 'claude_code':
        if event_type != 'assistant':
            return None
        usage = message.get('usage') if isinstance(message.get('usage'), dict) else None
        if usage is None:
            return None
        message_id = str(message.get('id') or '').strip()
        event_uuid = str(event.get('uuid') or '').strip()
        return {
            'key': ('claude', message_id or event_uuid) if message_id or event_uuid else None,
            'input_uncached_tokens': _nonnegative_token_count(usage.get('input_tokens')),
            'input_cached_tokens': _nonnegative_token_count(
                usage.get('cache_read_input_tokens')
            ),
            'input_cache_write_tokens': _nonnegative_token_count(
                usage.get('cache_creation_input_tokens')
            ),
            'output_tokens': _nonnegative_token_count(usage.get('output_tokens')),
            'reasoning_output_tokens': 0,
        }

    if source == 'pi':
        role = str(message.get('role') or '').strip().lower()
        usage = message.get('usage') if isinstance(message.get('usage'), dict) else None
        if event_type != 'message' or role != 'assistant' or usage is None:
            return None
        event_id = str(event.get('id') or '').strip()
        response_id = str(message.get('responseId') or '').strip()
        return {
            'key': ('pi', event_id or response_id) if event_id or response_id else None,
            'input_uncached_tokens': _nonnegative_token_count(usage.get('input')),
            'input_cached_tokens': _nonnegative_token_count(usage.get('cacheRead')),
            'input_cache_write_tokens': _nonnegative_token_count(usage.get('cacheWrite')),
            'output_tokens': _nonnegative_token_count(usage.get('output')),
            'reasoning_output_tokens': _nonnegative_token_count(usage.get('reasoning')),
        }

    if event_type == 'turn.completed':
        usage = event.get('usage') if isinstance(event.get('usage'), dict) else None
        if usage is None:
            return None
        input_total = _nonnegative_token_count(usage.get('input_tokens'))
        cached = min(
            input_total,
            _nonnegative_token_count(usage.get('cached_input_tokens')),
        )
        event_id = str(event.get('turn_id') or event.get('id') or '').strip()
        return {
            'key': ('codex', event_id) if event_id else None,
            'input_uncached_tokens': input_total - cached,
            'input_cached_tokens': cached,
            'input_cache_write_tokens': 0,
            'output_tokens': _nonnegative_token_count(usage.get('output_tokens')),
            'reasoning_output_tokens': _nonnegative_token_count(
                usage.get('reasoning_output_tokens')
            ),
        }

    if event_type == 'step_finish':
        part = event.get('part') if isinstance(event.get('part'), dict) else {}
        tokens = part.get('tokens') if isinstance(part.get('tokens'), dict) else None
        if tokens is None and isinstance(event.get('tokens'), dict):
            tokens = event['tokens']
        if tokens is None:
            return None
        cache = tokens.get('cache') if isinstance(tokens.get('cache'), dict) else {}
        reasoning = _nonnegative_token_count(tokens.get('reasoning'))
        part_id = str(part.get('id') or event.get('id') or '').strip()
        return {
            'key': ('opencode', part_id) if part_id else None,
            'input_uncached_tokens': _nonnegative_token_count(tokens.get('input')),
            'input_cached_tokens': _nonnegative_token_count(cache.get('read')),
            'input_cache_write_tokens': _nonnegative_token_count(cache.get('write')),
            'output_tokens': _nonnegative_token_count(tokens.get('output')) + reasoning,
            'reasoning_output_tokens': reasoning,
        }
    return None


def _collect_usage_from_jsonl(path, source):
    if not path:
        return None
    totals = {
        'request_count': 0,
        'input_uncached_tokens': 0,
        'input_cached_tokens': 0,
        'input_cache_write_tokens': 0,
        'input_total_tokens': 0,
        'output_tokens': 0,
        'reasoning_output_tokens': 0,
    }
    seen = set()
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as stream:
            for raw in stream:
                try:
                    event = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(event, dict):
                    continue
                record = _usage_record(source, event)
                if record is None:
                    continue
                key = record.pop('key')
                if key is not None:
                    if key in seen:
                        continue
                    seen.add(key)
                totals['request_count'] += 1
                for field in (
                    'input_uncached_tokens',
                    'input_cached_tokens',
                    'input_cache_write_tokens',
                    'output_tokens',
                    'reasoning_output_tokens',
                ):
                    totals[field] += record[field]
    except OSError:
        return None
    if totals['request_count'] == 0:
        return None
    totals['input_total_tokens'] = (
        totals['input_uncached_tokens']
        + totals['input_cached_tokens']
        + totals['input_cache_write_tokens']
    )
    totals['source'] = source
    return totals


def collect_agent_token_usage(trace_dir):
    claude_path = _latest_claude_jsonl(trace_dir)
    if claude_path:
        return _collect_usage_from_jsonl(claude_path, 'claude_code')
    pi_path = _latest_pi_jsonl(trace_dir)
    if pi_path:
        return _collect_usage_from_jsonl(pi_path, 'pi')
    codex_path = _latest_codex_jsonl(trace_dir)
    if codex_path:
        source = (
            'opencode'
            if 'opencode' in os.path.basename(codex_path).lower()
            else 'codex'
        )
        return _collect_usage_from_jsonl(codex_path, source)
    return None


def calculate_agent_token_cost_rmb(usage, pricing):
    if not isinstance(usage, dict) or not isinstance(pricing, dict):
        return None
    fields = (
        'input_price_per_million',
        'cached_input_price_per_million',
        'output_price_per_million',
    )
    try:
        prices = [Decimal(str(pricing.get(field))) for field in fields]
    except (InvalidOperation, TypeError, ValueError):
        return None
    if any(not price.is_finite() or price < 0 for price in prices):
        return None
    uncached_input = (
        _nonnegative_token_count(usage.get('input_uncached_tokens'))
        + _nonnegative_token_count(usage.get('input_cache_write_tokens'))
    )
    cached_input = _nonnegative_token_count(usage.get('input_cached_tokens'))
    output = _nonnegative_token_count(usage.get('output_tokens'))
    cost = (
        Decimal(uncached_input) * prices[0]
        + Decimal(cached_input) * prices[1]
        + Decimal(output) * prices[2]
    ) / Decimal(1_000_000)
    return format(cost.normalize(), 'f') if cost else '0'


def collect_agent_trace_files(trace_dir):
    return _collect_trace_files(trace_dir)


def collect_agent_trace_messages(trace_dir):
    return _collect_trace_messages(trace_dir)


__all__ = [
    "collect_agent_trace_files",
    "collect_agent_trace_messages",
    "collect_agent_token_usage",
    "calculate_agent_token_cost_rmb",
]
