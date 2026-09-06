"""从旧 Judge 原生日志恢复真实输入边界，定位已导入的轨迹；不访问数据库。"""

from datetime import datetime, timezone
import json
from pathlib import Path
import re

from backend.oj_modules.agents.trace_store import _normalize_canonical_record
from backend.oj_modules.ranking.reverse_judge import traces


def _object(value):
    return value if isinstance(value, dict) else {}


def _event_time(event, fallback):
    value = event.get('timestamp') or _object(event.get('message')).get('timestamp')
    try:
        if isinstance(value, (int, float)):
            return value / 1000 if value > 1e12 else float(value)
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()
    except (ValueError, TypeError, OverflowError):
        return fallback


def _read_events(path, warnings):
    events, session_id = [], ''
    try:
        with path.open('r', encoding='utf-8') as stream:
            for line, raw in enumerate(stream, 1):
                try:
                    event = json.loads(raw)
                except ValueError:
                    warnings.append(f'跳过无法解析的历史日志行：{path}:{line}')
                    continue
                if not isinstance(event, dict):
                    continue
                if event.get('type') == 'session':
                    session_id = str(event.get('id') or '')
                events.append((line, event, str(event.get('sessionId') or session_id)))
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError) as exc:
        warnings.append(f'历史日志无法读取：{path}（{exc}）')
    return events


def _input_record(path, line, event, session_id):
    message = _object(event.get('message'))
    if (event.get('type') not in {'user', 'message'} or message.get('role') != 'user'
            or event.get('isSidechain') or event.get('isMeta') or event.get('isCompactSummary')
            or 'toolUseResult' in event):
        return None
    content = message.get('content')
    if isinstance(content, list):
        if any(isinstance(block, dict) and block.get('type') == 'tool_result' for block in content):
            return None
        content = '\n'.join(block['text'] for block in content
                            if isinstance(block, dict) and block.get('type') == 'text' and isinstance(block.get('text'), str))
    if not isinstance(content, str) or not content.strip():
        return None
    identifier = event.get('uuid') or event.get('id')
    identity = (session_id, str(identifier)) if identifier else (str(path), str(line - 1))
    return {'identity': identity, 'time': _event_time(event, line - 1),
            'text': content, 'source': str(path)}


def input_records(path, warnings):
    """兼容原提示词补齐脚本的输入提取接口。"""
    path = Path(path)
    return [record for line, event, session_id in _read_events(path, warnings)
            if (record := _input_record(path, line, event, session_id)) is not None]


_input_records = input_records


def _native_id(event, session_id):
    # Claude fork 会复制相同 uuid；Pi 的短 id 则只在本原生会话中唯一。
    if event.get('uuid'):
        return ('claude', str(event['uuid']))
    if event.get('id'):
        return ('pi', session_id, str(event['id']))
    return None


def _trace_root(path):
    for marker in ('.claude', '.pi'):
        if marker in path.parts:
            return Path(*path.parts[:path.parts.index(marker)])
    return path.parent


def _phase(event, row):
    value = str(event.get('_trace_phase') or '')
    if not value and '_trace_phase' in event and row.get('judge_kind') == 'agent_judge':
        return 'single_prompt'
    return value


def _stable_id(*values, suffix=''):
    # 与冻结前 run_harness 的稳定原生事件 ID 规则相同；不是按正文猜测。
    value = next((str(value).strip() for value in values if str(value or '').strip()), '')
    return value[:max(1, 512 - len(suffix))] + suffix if value else ''


def _canonical_ids(event):
    """常见 Claude/Pi 原生消息能确定的 adapter 事件 ID 与类别。"""
    message = _object(event.get('message'))
    content = message.get('content')
    blocks = [{'type': 'text', 'text': content}] if isinstance(content, str) else content
    blocks = blocks if isinstance(blocks, list) else []
    role = str(message.get('role') or '')
    if role == 'assistant' or event.get('type') == 'assistant':
        message_id = _stable_id(message.get('id'), message.get('responseId'), event.get('uuid'), event.get('id'))
        for index, block in enumerate(blocks):
            if not isinstance(block, dict):
                continue
            kind = block.get('type')
            block_id = _stable_id(block.get('id'), message_id, suffix=f':{kind or "block"}:{index}')
            if kind in {'text', 'thinking', 'reasoning'} and block_id:
                yield block_id, 'assistant' if kind == 'text' else 'thinking'
            elif kind == 'tool_use':
                yield _stable_id(block.get('id'), block_id, suffix=':call'), 'tool'
            elif kind in {'toolCall', 'toolcall'}:
                yield _stable_id(block.get('id'), suffix=':call'), 'tool'
    elif role == 'user':
        for block in blocks:
            if isinstance(block, dict) and block.get('type') == 'tool_result':
                yield _stable_id(block.get('tool_use_id'), event.get('uuid'), event.get('id'), suffix=':result'), 'tool_result'
    elif role.lower().replace('_', '') == 'toolresult':
        yield _stable_id(message.get('toolCallId'), message.get('tool_use_id'), suffix=':result'), 'tool_result'


def recover_trace_turns(row, trace_paths):
    """返回实际输入/阶段及旧 v2 event_id 的所属轮次；不猜测未保存的边界。"""
    if row.get('judge_kind') == 'reverse_quality':
        return {'turns': [], 'event_turns': {}, 'event_signatures': {}, 'warnings': []}
    warnings, candidates, file_events = [], {}, {}
    # 相同逻辑输入可以同时出现在原生文件和 combined 中，只建一轮。
    for path in sorted({Path(path) for path in trace_paths}):
        entries = file_events[path] = _read_events(path, warnings)
        for line, event, session_id in entries:
            record = _input_record(path, line, event, session_id)
            if record is None:
                continue
            key = _native_id(event, session_id) or ('line', str(path), line)
            candidate = candidates.setdefault(key, {
                'text': record['text'], 'phase': _phase(event, row),
                'sources': [], 'warnings': [], '_time': record['time'],
            })
            if str(path) not in candidate['sources']:
                candidate['sources'].append(str(path))
            if candidate['text'] != record['text']:
                candidate['warnings'].append('同一原始输入 ID 的正文不一致，保留首次原文')

    assignments, native_owners = {}, {}
    for path, entries in file_events.items():
        active, active_session = None, ''
        for line, event, session_id in entries:
            if event.get('type') == 'session' or (session_id and active_session and session_id != active_session):
                active = None
            record = _input_record(path, line, event, session_id)
            if record is not None:
                active = _native_id(event, session_id) or ('line', str(path), line)
                active_session = session_id
            owner = None if event.get('isSidechain') or event.get('isMeta') else active
            if (owner is not None and _phase(event, row) and candidates[owner]['phase']
                    and _phase(event, row) != candidates[owner]['phase']):
                owner = None
            assignments[(path, line)] = owner
            native_id = _native_id(event, session_id)
            if owner is not None and native_id:
                native_owners.setdefault(native_id, set()).add(owner)

    roots = {_trace_root(path) for path in file_events}
    selected, canonical, messages = None, None, []
    if len(roots) == 1:
        root = roots.pop()
        try:
            canonical = traces._canonical_trace_path(root)
            if not canonical:
                selected = traces._latest_claude_jsonl(root) or traces._latest_pi_jsonl(root)
                if selected:
                    selected = Path(selected)
                    # 必须沿用旧导入所选文件与全量顺序，history-N 才对应原 DB ID。
                    messages = traces.collect_agent_trace_messages(root, full_history=True)
        except (OSError, UnicodeError) as exc:
            warnings.append(f'历史轨迹无法读取，保留为轮次未知历史轨迹：{exc}')
    elif roots:
        warnings.append('历史日志来自不同轨迹目录，无法确定旧导入顺序')

    selected_events = {line: (event, sid) for line, event, sid in file_events.get(selected, [])}
    event_keys, event_signatures = {}, {}
    unmapped = 0
    for index, message in enumerate(messages, 1):
        line = message.get('line')
        event, session_id = selected_events.get(line, ({}, ''))
        if event.get('isSidechain') or event.get('isMeta'):
            unmapped += 1
            continue
        native_id = _native_id(event, session_id)
        owners = native_owners.get(native_id, set()) if native_id else set()
        key = next(iter(owners)) if len(owners) == 1 else assignments.get((selected, line))
        if len(owners) > 1:
            key = None
        phase = _phase(event, row)
        # 旧拓扑流程只发送 setup/rule_N；final 仅用于 finally 中收尾同步，
        # 不能据此虚构一次输入。single 模式的实际 AJ_PHASE 明确为空。
        sent_phase = (phase == 'setup' or re.fullmatch(r'rule_[1-9][0-9]*', phase)
                      or ('_trace_phase' in event and event['_trace_phase'] == ''))
        if (key is None and not owners and native_id and sent_phase
                and row.get('judge_kind') == 'agent_judge' and not event.get('isSidechain')):
            key = ('phase', phase, session_id or str(event.get('_trace_source') or ''))
            candidates.setdefault(key, {'text': '', 'phase': phase, 'sources': [str(selected)],
                                       'warnings': ['该阶段实际输入原文未保存'],
                                       '_time': _event_time(event, line or index)})
        if key is None:
            unmapped += 1
            continue
        normalized = _normalize_canonical_record(str(row.get('task_id') or row['session_id']), {
            'type': 'numoj_trace', 'version': 1, 'sequence': index,
            'event': {**message, 'id': f'history-{index}'},
        })
        if normalized:
            event_keys[normalized['event_id']] = key
            event_signatures[normalized['event_id']] = {field: normalized[field] for field in ('kind', 'text')}
    if canonical:
        # adapter 保留 provider message/block/tool id，原生文本的工具格式无需
        # 与展示摘要相同。只认相同 ID 与类别，缺失或冲突仍归入未知轮次。
        canonical_owners = {}
        for path, entries in file_events.items():
            for line, event, sid in entries:
                owner = assignments.get((path, line))
                if owner is None:
                    continue
                for source_id, kind in _canonical_ids(event):
                    if source_id:
                        canonical_owners.setdefault((source_id, kind), set()).add(owner)
        canonical_path = Path(canonical)
        entries = file_events.get(canonical_path)
        if entries is None:
            entries = _read_events(canonical_path, warnings)
        canonical_unmapped = 0
        for line, record, _sid in entries:
            if record.get('type') != 'numoj_trace':
                continue
            event = _object(record.get('event'))
            owners = canonical_owners.get((str(event.get('id') or ''), event.get('kind')), set())
            try:
                normalized = _normalize_canonical_record(str(row.get('task_id') or row['session_id']), record)
            except ValueError:
                normalized = None
            if normalized is None:
                continue
            if len(owners) == 1:
                event_keys[normalized['event_id']] = next(iter(owners))
                event_signatures[normalized['event_id']] = {field: normalized[field] for field in ('kind', 'text')}
            else:
                canonical_unmapped += 1
        if canonical_unmapped:
            warnings.append(f'{canonical_unmapped} 条规范轨迹缺少可靠的原生事件映射，保留为轮次未知历史轨迹')
    if unmapped:
        warnings.append(f'{unmapped} 条历史轨迹缺少可靠的输入边界，保留为轮次未知历史轨迹')
    ordered = sorted(candidates, key=lambda key: candidates[key]['_time'])
    positions = {key: index for index, key in enumerate(ordered)}
    return {
        'turns': [{key: value for key, value in candidates[identity].items() if key != '_time'}
                  for identity in ordered],
        'event_turns': {event_id: positions[key] for event_id, key in event_keys.items()},
        'event_signatures': event_signatures,
        'warnings': warnings,
    }
