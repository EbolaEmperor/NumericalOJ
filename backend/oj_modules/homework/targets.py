#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""作业查重目标与请求 payload 规则。"""

from backend.oj_modules.db_services import get_class_by_en
from backend.oj_modules.infrastructure.mysql import get_db_connection, safe_table_name


_PLAGIARISM_TARGET_PROBLEM = "problem"
_PLAGIARISM_TARGET_RANKING = "ranking"


def _parse_threshold(raw_value):
    try:
        threshold = float(raw_value)
    except (TypeError, ValueError):
        raise ValueError("查重阈值必须是数字")
    if threshold > 1:
        threshold = threshold / 100.0
    if threshold <= 0 or threshold > 1:
        raise ValueError("查重阈值必须在 0 到 100 之间")
    return threshold

def _plagiarism_target_key(kind, target_id):
    return f"{str(kind or '').strip()}:{int(target_id)}"

def _normalize_plagiarism_target(raw_value):
    if isinstance(raw_value, dict):
        kind = str(raw_value.get('kind') or raw_value.get('type') or '').strip().lower()
        target_id = raw_value.get('id') or raw_value.get('target_id') or raw_value.get('problem_id') or raw_value.get('competition_id')
    else:
        text = str(raw_value or '').strip()
        if not text:
            raise ValueError('作业项非法')
        if ':' in text:
            kind, target_id = text.split(':', 1)
            kind = kind.strip().lower()
        else:
            kind, target_id = _PLAGIARISM_TARGET_PROBLEM, text

    if kind in ('problem', 'ordinary'):
        kind = _PLAGIARISM_TARGET_PROBLEM
    elif kind in ('ranking', 'competition'):
        kind = _PLAGIARISM_TARGET_RANKING
    else:
        raise ValueError('作业项类型非法')

    try:
        target_id = int(target_id)
    except (TypeError, ValueError):
        raise ValueError('作业项 ID 非法')
    if target_id <= 0:
        raise ValueError('作业项 ID 非法')

    return {
        'kind': kind,
        'id': target_id,
        'key': _plagiarism_target_key(kind, target_id),
    }

def _get_class_homework_target_map(class_en):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT hw.problem_id,
                       hw.ranking_competition_id,
                       COALESCE(p.title, hw.problem_title) AS problem_title,
                       COALESCE(rc.title, hw.problem_title) AS ranking_title
                FROM {safe_table_name(class_en)} hw
                LEFT JOIN problems p ON p.id = hw.problem_id
                LEFT JOIN ranking_competitions rc ON rc.id = hw.ranking_competition_id
                WHERE hw.problem_id IS NOT NULL
                   OR hw.ranking_competition_id IS NOT NULL
                ORDER BY hw.id ASC
                """
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    target_map = {}
    for row in rows:
        if row.get('problem_id') is not None:
            try:
                pid = int(row.get('problem_id'))
            except (TypeError, ValueError):
                pid = None
            if pid:
                key = _plagiarism_target_key(_PLAGIARISM_TARGET_PROBLEM, pid)
                target_map.setdefault(key, {
                    'kind': _PLAGIARISM_TARGET_PROBLEM,
                    'id': pid,
                    'key': key,
                    'title': row.get('problem_title') or f'题目 {pid}',
                })
        if row.get('ranking_competition_id') is not None:
            try:
                cid = int(row.get('ranking_competition_id'))
            except (TypeError, ValueError):
                cid = None
            if cid:
                key = _plagiarism_target_key(_PLAGIARISM_TARGET_RANKING, cid)
                target_map.setdefault(key, {
                    'kind': _PLAGIARISM_TARGET_RANKING,
                    'id': cid,
                    'key': key,
                    'title': row.get('ranking_title') or f'打榜赛 {cid}',
                })
    return target_map

def _get_class_homework_problem_map(class_en):
    target_map = _get_class_homework_target_map(class_en)
    problem_map = {}
    for target in target_map.values():
        if target.get('kind') == _PLAGIARISM_TARGET_PROBLEM:
            problem_map[int(target['id'])] = target.get('title') or f"题目 {target['id']}"
    return problem_map

def parse_plagiarism_mark_payload(data):
    data = data or {}
    class_en = str(data.get('class_en') or '').strip()
    mode = str(data.get('mode') or 'threshold').strip()
    if mode not in ('threshold', 'byte'):
        raise ValueError('查重规则非法')

    class_info = get_class_by_en(class_en)
    if not class_info:
        raise ValueError('班级不存在')

    threshold = _parse_threshold(data.get('threshold', 90)) if mode == 'threshold' else 1.0

    raw_targets = data.get('targets')
    selected_targets = []
    if raw_targets:
        if not isinstance(raw_targets, (list, tuple)):
            raise ValueError('作业项非法')
        selected_targets = [_normalize_plagiarism_target(item) for item in raw_targets]
    else:
        try:
            selected_problem_ids = [int(pid) for pid in (data.get('problem_ids') or [])]
        except (TypeError, ValueError):
            raise ValueError('题目 ID 非法')
        selected_targets = [
            {
                'kind': _PLAGIARISM_TARGET_PROBLEM,
                'id': pid,
                'key': _plagiarism_target_key(_PLAGIARISM_TARGET_PROBLEM, pid),
            }
            for pid in selected_problem_ids
        ]

    deduped_targets = []
    seen_keys = set()
    for target in selected_targets:
        key = target.get('key')
        if key and key not in seen_keys:
            seen_keys.add(key)
            deduped_targets.append(target)
    selected_targets = deduped_targets

    homework_target_map = _get_class_homework_target_map(class_en)
    valid_target_keys = set(homework_target_map.keys())
    if not selected_targets:
        raise ValueError('请至少选择一道作业题')
    if any(target.get('key') not in valid_target_keys for target in selected_targets):
        raise ValueError('只能选择该班级已布置的作业')
    if mode == 'threshold' and any(target.get('kind') == _PLAGIARISM_TARGET_RANKING for target in selected_targets):
        raise ValueError('相似度查重暂不支持打榜赛，请改用字节级一致或取消打榜赛')

    resolved_targets = [dict(homework_target_map[target['key']]) for target in selected_targets]
    selected_problem_ids = [
        int(target['id'])
        for target in resolved_targets
        if target.get('kind') == _PLAGIARISM_TARGET_PROBLEM
    ]

    return {
        'class_en': class_en,
        'class_cn': class_info.get('class_cn'),
        'mode': mode,
        'threshold': threshold,
        'targets': resolved_targets,
        'problem_ids': selected_problem_ids,
    }

normalize_plagiarism_target = _normalize_plagiarism_target
get_class_homework_target_map = _get_class_homework_target_map
get_class_homework_problem_map = _get_class_homework_problem_map

__all__ = [
    "get_class_homework_problem_map",
    "get_class_homework_target_map",
    "normalize_plagiarism_target",
    "parse_plagiarism_mark_payload",
]

