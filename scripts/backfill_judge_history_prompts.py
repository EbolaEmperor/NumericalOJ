#!/usr/bin/env python3
"""下一次停服部署补齐已导入 Judge 的历史输入；恢复真实发送轮次及对应轨迹，不重新评测。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.oj_modules.agents.trace_store import AGENT_SUBAGENT_STATUS_META, _work_block_id
from backend.oj_modules.agents.workspace import AGENT_WORKSPACE_ROOT
from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.ranking.db import submission_dir
from deploy.backup.orchestrator import read_manifest, validate_manifest_artifact
from deploy.preflight import validate_production_config
from scripts.judge_history_trace import input_records as _input_records

VERSION = 2
MERGED_PREFIX = '以下为该次历史评测实际发送的输入，按原始顺序汇总；未重建历史轮次。'
UNASSIGNED_PROMPT = '历史轨迹归档：以下记录的发送轮次未保存，无法归入任何一轮实际输入。'
PLACEHOLDER = '导入历史评测记录（不重新执行）'
MISSING_PROMPT = '历史提示词原文未保存，无法恢复实际发送内容。旧记录可能只保留了模型输出或提交材料；本会话不以当前评测规则替代历史输入。'


def _progress(message):
    print(f'[judge-prompts] {str(message).encode("utf-8", errors="backslashreplace").decode("utf-8")}', flush=True)


def _object(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _read_object(path):
    try:
        return _object(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError):
        return {}


def _trace_files(row):
    # 只读评测服务导出的对应 attempt 日志，不搜索学生上传包内的 .claude。
    kind = row['judge_kind']
    attempt = row.get('attempt_id')
    if kind == 'reverse_quality' or str(attempt).startswith('unknown-workspace-'):
        return []
    root = Path(submission_dir(row['submission_id'])) / (
        'agent_judge_trace' if kind == 'agent_judge' else 'reverse_agent_trace'
    ) / str(attempt or 'legacy')
    paths = []
    for directory in (root / '.claude/projects/-workspace', root / '.pi/agent/sessions'):
        try:
            paths.extend(directory.glob('*.jsonl'))
            if directory.name == 'sessions':
                paths.extend(directory.glob('*/*.jsonl'))
        except OSError:
            continue
    paths.extend((root / 'pi_reverse_solve.jsonl', root / 'numoj_trace_v1.jsonl'))
    return sorted(set(paths))


def _synthetic_prompt(value):
    return not value or value in {PLACEHOLDER, MISSING_PROMPT} or str(value).startswith(MERGED_PREFIX)


def recover_prompt(row):
    from scripts.judge_history_templates import (
        _quality_gate_saved_reply, recover_fixed_history_prompts, recover_quality_history_prompt,
    )
    from scripts.judge_history_trace import recover_trace_turns

    workspace = Path(AGENT_WORKSPACE_ROOT) / 'sessions' / row['session_id'] / 'workspace'
    history = _read_object(workspace / 'historical_record.json')
    for field in ('turn_prompt', 'message_prompt'):
        existing = row.get(field)
        if not _synthetic_prompt(existing):
            conclusion = (_quality_gate_saved_reply(_object(_object(history.get('result')).get('result_json')))
                          if row['judge_kind'] == 'reverse_quality' else '')
            return {'turns': [{'text': existing, 'conclusion': conclusion}], 'event_turns': {}, 'status': 'existing',
                    'prompt_count': 1, 'sources': [field], 'warnings': []}
    trace = recover_trace_turns(row, _trace_files(row))
    warnings = list(trace.get('warnings') or [])
    turns = trace['turns']
    fixed = recover_fixed_history_prompts(row, workspace_root=workspace, history=history, phase_records=turns)
    reconstructed = False
    if turns:
        for turn in turns:
            if not turn.get('text'):
                restored = next((item for item in fixed if item.get('phase') == turn.get('phase')), None)
                if restored:
                    turn.update(text=restored['text'], sources=restored.get('sources', []))
                    warnings.extend(restored.get('warnings', []))
                    reconstructed = True
                else:
                    turn['text'] = MISSING_PROMPT
    else:
        # 第一版已经写入的原文也是历史记录；拆回原来的发送框，不再次合并。
        merged = next((str(row.get(key) or '') for key in ('turn_prompt', 'message_prompt')
                       if str(row.get(key) or '').startswith(MERGED_PREFIX)), '')
        if merged:
            turns = [{'text': text, 'sources': ['第一版回填保存的原始输入']}
                     for text in re.split(r'\n\n### 第 \d+ 次输入\n\n', merged)[1:]]
        elif fixed:
            turns = fixed
            reconstructed = True
    if not turns:
        quality = recover_quality_history_prompt(row, workspace, history)
        if quality:
            turns = [quality]
            reconstructed = True
    for turn in turns:
        warnings.extend(turn.get('warnings', []))
    return {'turns': turns or [{'text': MISSING_PROMPT}], 'event_turns': trace.get('event_turns', {}),
            'event_signatures': trace.get('event_signatures', {}),
            'status': ('reconstructed' if reconstructed else 'restored') if turns else 'missing',
            'prompt_count': len(turns),
            'sources': sorted({source for turn in turns for source in turn.get('sources', [])}),
            'warnings': sorted(set(warnings))}


def load_candidates():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''SELECT s.session_id, s.submission_id, s.attempt_id, s.judge_kind, s.harness,
                t.task_id, t.user_message AS turn_prompt, m.message_id, m.user_message AS message_prompt,
                c.reverse_quality_gate_prompt
                FROM agent_sessions s JOIN agent_session_turns t ON t.session_id=s.session_id AND t.turn_index=1
                LEFT JOIN agent_session_messages m ON m.session_id=s.session_id AND m.final_task_id=t.task_id AND m.delivery_mode='turn'
                LEFT JOIN ranking_competitions c ON c.id=s.competition_id
                WHERE s.task_kind='judge' AND JSON_EXTRACT(s.runtime_config_json, '$.historical_import')=true
                  AND COALESCE(JSON_EXTRACT(s.runtime_config_json, '$.historical_prompt_version'), 0) < %s
                ORDER BY s.submission_id, s.session_id''',
                (VERSION,))
            return cursor.fetchall() or []
    finally:
        conn.close()


def _historical_task_id(session_id, index):
    return 'jh-' + hashlib.sha256(f'{session_id}:{index}'.encode()).hexdigest()[:40]


def _move_trace(cursor, task_id, events):
    """保留全部事件正文，只按其实际轮次重建通用时间线/工作块索引。"""
    item_index, block_id, updates = 0, None, []
    for event in events:
        subagent_status = (event['kind'] == 'subagent' and event.get('meta') == AGENT_SUBAGENT_STATUS_META
                           and event.get('format') == 'json')
        internal = event['kind'] not in {'assistant', 'user'} and not subagent_status
        if internal:
            if block_id is None:
                item_index += 1
                block_id = _work_block_id(task_id, event['event_id'])
            assigned_block = block_id
        else:
            assigned_block = None
            if not subagent_status:
                item_index += 1
                block_id = None
        # event_order 保留原序号（允许空隙），避免同事务内唯一索引相互碰撞。
        updates.append((task_id, max(1, item_index), assigned_block, event['id']))
    if updates:
        cursor.executemany('UPDATE agent_trace_events SET task_id=%s, item_index=%s, block_id=%s WHERE id=%s', updates)
    cursor.execute('''INSERT INTO agent_trace_sync_state (task_id,last_event_order,next_item_index,migration_completed)
        VALUES (%s,%s,%s,1) ON DUPLICATE KEY UPDATE last_event_order=VALUES(last_event_order),
        next_item_index=VALUES(next_item_index), active_block_id=NULL,active_item_index=NULL,
        updated_at=updated_at''', (task_id, max((event['event_order'] for event in events), default=0), item_index + 1))


def _insert_historical_turn(cursor, session, original, original_message, task_id, index, prompt, conclusion):
    cursor.execute('''INSERT INTO agent_session_turns
        (session_id,task_id,turn_index,user_message,status,conclusion,created_at,updated_at)
        VALUES (%s,%s,%s,%s,'Completed',%s,%s,%s)''',
        (session['session_id'], task_id, index, prompt, conclusion, original['created_at'], original['updated_at']))
    cursor.execute('''INSERT INTO agent_session_messages
        (message_id,session_id,created_by,user_message,delivery_mode,status,final_task_id,
         queue_position,delivered_at,created_at,updated_at)
        VALUES (%s,%s,%s,%s,'turn','sent',%s,%s,%s,%s,%s)''',
        (task_id, session['session_id'], session['requested_by'], prompt, task_id, index * 1024,
         original_message.get('delivered_at'), original['created_at'], original['updated_at']))
    # 直接归档，不走发送/恢复/记账入口；详情接口通过已完成快照读取每轮轨迹。
    cursor.execute('''INSERT INTO agent_task_runs
        (task_id,requested_by,harness,endpoint_id,endpoint_model,status,message,created_at,updated_at)
        VALUES (%s,%s,%s,%s,%s,'Completed','历史评测已归档',%s,%s)''',
        (task_id, session['requested_by'], session['harness'], session['endpoint_id'],
         session['endpoint_model'], original['created_at'], original['updated_at']))


def backfill_one(row):
    recovered = recover_prompt(row)
    report = {key: row.get(key) for key in ('session_id', 'task_id', 'message_id', 'turn_prompt', 'message_prompt')}
    report.update({key: value for key, value in recovered.items()
                   if key not in {'turns', 'event_turns', 'event_signatures'}})
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM agent_sessions WHERE session_id=%s FOR UPDATE', (row['session_id'],))
            session = cursor.fetchone()
            cursor.execute('SELECT * FROM agent_session_turns WHERE session_id=%s ORDER BY turn_index FOR UPDATE', (row['session_id'],))
            originals = cursor.fetchall() or []
            cursor.execute("SELECT * FROM agent_session_messages WHERE session_id=%s AND final_task_id=%s AND delivery_mode='turn' FOR UPDATE",
                           (row['session_id'], row['task_id']))
            original_message = cursor.fetchone() or {}
            runtime = _object(session.get('runtime_config_json')) if session else {}
            if (not session or not runtime.get('historical_import') or len(originals) != 1
                    or originals[0]['task_id'] != row['task_id']
                    or originals[0]['user_message'] != row.get('turn_prompt')
                    or original_message.get('user_message') != row.get('message_prompt')
                    or runtime.get('historical_prompt_version', 0) >= VERSION):
                conn.rollback()
                report['status'] = 'skipped_changed'
                return report
            original = originals[0]
            cursor.execute('SELECT * FROM agent_trace_events WHERE task_id=%s ORDER BY event_order FOR UPDATE', (row['task_id'],))
            events = cursor.fetchall() or []
            turns = list(recovered['turns'])
            grouped = [[] for _ in turns]
            unknown = []
            for event in events:
                turn_index = recovered.get('event_turns', {}).get(event['event_id'])
                signature = recovered.get('event_signatures', {}).get(event['event_id'])
                if signature and any(event[key] != signature[key] for key in ('kind', 'text')):
                    turn_index = None
                if turn_index is not None and 0 <= turn_index < len(turns):
                    grouped[turn_index].append(event)
                elif len(turns) == 1 and recovered['status'] in {'existing', 'missing'}:
                    grouped[0].append(event)
                else:
                    unknown.append(event)
            if unknown:
                turns.append({'text': UNASSIGNED_PROMPT})
                grouped.append(unknown)
                report['warnings'] = list(report.get('warnings', [])) + [f'{len(unknown)} 条轨迹未保存发送边界，单独归档']
            count = len(turns)
            conclusions = [next((event['text'] for event in reversed(trace) if event['kind'] == 'assistant'), turn.get('conclusion', ''))
                           for turn, trace in zip(turns, grouped)]
            report['previous_conclusion'] = original.get('conclusion')
            # 保留原 task_id/current_task_id 和汇总用量在最后一轮，已有链接继续有效。
            cursor.execute('''UPDATE agent_session_turns SET turn_index=%s,user_message=%s,conclusion=%s,updated_at=updated_at
                WHERE task_id=%s''', (count, turns[-1]['text'], conclusions[-1], row['task_id']))
            if original_message:
                cursor.execute('''UPDATE agent_session_messages SET user_message=%s,queue_position=%s,updated_at=updated_at
                    WHERE message_id=%s''', (turns[-1]['text'], count * 1024, original_message['message_id']))
            task_ids = []
            for index, (turn, trace) in enumerate(zip(turns, grouped), 1):
                task_id = row['task_id'] if index == count else _historical_task_id(row['session_id'], index)
                task_ids.append(task_id)
                if index < count:
                    _insert_historical_turn(cursor, session, original, original_message, task_id, index, turn['text'], conclusions[index - 1])
                _move_trace(cursor, task_id, trace)
            runtime['historical_prompt_version'] = VERSION
            cursor.execute('''UPDATE agent_sessions SET turn_count=%s,runtime_config_json=%s,updated_at=updated_at
                WHERE session_id=%s''', (count, json.dumps(runtime, ensure_ascii=True), row['session_id']))
            report.update(turn_task_ids=task_ids, trace_counts=[len(trace) for trace in grouped], unassigned_trace_count=len(unknown))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-writers-stopped', action='store_true', required=True)
    parser.add_argument('--backup-manifest', type=Path, required=True)
    parser.add_argument('--backup-plan', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(argv)
    previous = _read_object(args.report)
    if previous.get('version') == VERSION and previous.get('completed'):
        _progress('历史提示词已补齐，跳过')
        return 0
    validate_production_config(ROOT / '.env')
    backup = read_manifest(args.backup_manifest)
    if (backup.get('backup_status') != 'complete' or not backup.get('completed_at')
            or not (backup.get('gzip_crc_verified') is True or backup.get('prepared') is True)):
        raise ValueError('必须先完成并核验数据库备份')
    validate_manifest_artifact(args.backup_manifest, backup, plan_path=args.backup_plan)
    entries = list(previous.get('sessions') or []) if previous.get('version') == VERSION else []
    completed = False
    changed = False
    current = None
    try:
        rows = load_candidates()
        _progress(f'待补齐 {len(rows)} 个历史会话')
        for index, row in enumerate(rows, 1):
            current = row['session_id']
            result = backfill_one(row)
            entries.append(result)
            changed = changed or result['status'] == 'skipped_changed'
            if index % 100 == 0 or index == len(rows):
                _progress(f'已处理 {index}/{len(rows)} 个会话')
        completed = not changed
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.report.parent, prefix='.judge-prompts-', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump({'version': VERSION, 'completed': completed, 'sessions': entries,
                       'interrupted_at': None if completed else current}, stream, ensure_ascii=True, indent=2)
        os.replace(temporary, args.report)
    counts = {status: sum(item['status'] == status for item in entries) for status in ('restored', 'reconstructed', 'existing', 'missing', 'skipped_changed')}
    _progress(f'完成：恢复 {counts["restored"]}，旧模板重建 {counts["reconstructed"]}，同步已有正文 {counts["existing"]}，原文缺失 {counts["missing"]}；报告 {args.report}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
