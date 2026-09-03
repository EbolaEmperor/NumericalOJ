#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反向评测详情快照聚合。"""

import json
import time

from backend.oj_modules.ranking.db import get_ranking_submission
from backend.oj_modules.ranking.reverse_judge.db import (
    STEP_AGENT,
    available_reverse_agent_answer_archive_path,
    list_reverse_judge_steps,
)
from backend.oj_modules.ranking.reverse_judge.traces import (
    collect_agent_token_usage,
    collect_agent_trace_messages,
)


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


def build_reverse_judge_snapshot(submission_id):
    submission = get_ranking_submission(submission_id)
    if not submission:
        return None
    current_answer_archive = available_reverse_agent_answer_archive_path(
        submission_id,
        submission.get('judge_attempt_id'),
        submission.get('status'),
    )
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
            # 原始 JSONL 只留在服务端，不作为评测详情的一部分提供。
            'trace_files': [],
            'trace_messages': collect_agent_trace_messages(row.get('trace_dir')),
            'token_usage': collect_agent_token_usage(row.get('trace_dir')),
            'started_at': str(row.get('started_at') or ''),
            'finished_at': str(row.get('finished_at') or ''),
        }
        if item['step_key'] == STEP_AGENT:
            # ZIP 由临时文件完成后再原子发布；评测终态前不开放，避免执行中的
            # 产物被提前取走，也使按钮状态与最终提交状态保持一致。
            item['answer_available'] = bool(current_answer_archive)
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


__all__ = ["build_reverse_judge_snapshot"]
