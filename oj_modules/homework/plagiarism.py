#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""作业查重材料采集、比较算法与文本报告。"""

import hashlib
import json
import os
import posixpath
import zipfile
from collections import defaultdict
from datetime import datetime
from difflib import SequenceMatcher

from oj_modules.homework.records import (
    _build_plagiarism_record_rows,
    _save_plagiarism_records,
)
from oj_modules.homework.runtime import update_export_progress
from oj_modules.homework.targets import (
    _PLAGIARISM_TARGET_PROBLEM,
    _PLAGIARISM_TARGET_RANKING,
    _normalize_plagiarism_target,
    _plagiarism_target_key,
)
from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.repository.includes import (
    extract_includes_from_code,
    get_user_repository_files_by_names,
)


_PLAGIARISM_TEX_MAX_FILES = 256
_PLAGIARISM_TEX_MAX_TOTAL_BYTES = 20 * 1024 * 1024


def normalize_code(code):
    import re

    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
    code = re.sub(r'#.*?$', '', code, flags=re.MULTILINE)
    code = re.sub(r'%.*?$', '', code, flags=re.MULTILINE)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
    code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
    code = re.sub(r'\s+', ' ', code)
    return code.strip()

def calculate_code_similarity(code1, code2):
    norm_code1 = normalize_code(code1)
    norm_code2 = normalize_code(code2)

    if not norm_code1 or not norm_code2:
        return 0.0

    return SequenceMatcher(None, norm_code1, norm_code2).ratio()

def _format_threshold_rule(threshold):
    return f"{float(threshold):.2f}"

def _json_lines_to_list(value):
    if not value:
        return []
    items = []
    for line in str(value or '').strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except Exception:
            items.append(line)
    return items

def _submission_upload_file_path(submission_id, test_points):
    points = _json_lines_to_list(test_points)
    if not points:
        return ''
    first = points[0]
    filename = ''
    if isinstance(first, str):
        filename = first
    elif isinstance(first, dict):
        filename = first.get('filename') or first.get('file') or first.get('name') or ''
    filename = os.path.basename(str(filename or '').strip())
    if not filename:
        return ''
    return os.path.join('uploads', str(submission_id), filename)

def _file_sha256_fingerprint(path, label='file'):
    if not path or not os.path.isfile(path):
        return ''
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            if chunk:
                digest.update(chunk)
    return f"{label}:{digest.hexdigest()}"

def _zip_content_sha256_fingerprint(path, label='zip-content'):
    if not path or not os.path.isfile(path):
        return ''
    digest = hashlib.sha256()
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            infos = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = _safe_zip_member_name(info.filename)
                if name:
                    infos.append((name, info))
            for name, info in sorted(infos, key=lambda item: item[0]):
                try:
                    content = zf.read(info)
                except Exception:
                    return ''
                digest.update(name.encode('utf-8', errors='replace'))
                digest.update(b'\0')
                digest.update(content)
                digest.update(b'\0')
    except (OSError, zipfile.BadZipFile):
        return ''
    return f"{label}:{digest.hexdigest()}"

def _safe_zip_member_name(name):
    raw = str(name or '').replace('\\', '/')
    normalized = posixpath.normpath(raw)
    if not normalized or normalized == '.':
        return ''
    if normalized.startswith('../') or normalized.startswith('/') or '/../' in f"/{normalized}/":
        return ''
    return normalized

def _read_tex_files_from_zip(zip_path):
    if not zip_path or not os.path.isfile(zip_path):
        return {}
    tex_files = {}
    total_bytes = 0
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for info in sorted(zf.infolist(), key=lambda item: str(item.filename or '')):
                if info.is_dir():
                    continue
                name = _safe_zip_member_name(info.filename)
                if not name or not name.lower().endswith('.tex'):
                    continue
                if len(tex_files) >= _PLAGIARISM_TEX_MAX_FILES:
                    break
                total_bytes += int(info.file_size or 0)
                if total_bytes > _PLAGIARISM_TEX_MAX_TOTAL_BYTES:
                    break
                try:
                    content = zf.read(info)
                except Exception:
                    continue
                tex_files[name] = content.decode('utf-8', errors='replace')
    except (OSError, zipfile.BadZipFile):
        return {}
    return tex_files

def _calculate_tex_files_similarity(files1, files2):
    left = files1 or {}
    right = files2 or {}
    common_names = sorted(set(left.keys()) & set(right.keys()))
    if not common_names:
        return 0.0
    best = 0.0
    for name in common_names:
        score = calculate_code_similarity(left.get(name) or '', right.get(name) or '')
        if score > best:
            best = score
    return best

def _class_users_cte_sql():
    return """
        SELECT u.id AS user_id, u.username
        FROM user_class_map m
        JOIN users u ON u.id = m.user_id
        WHERE m.class_en = %s
          AND u.is_admin = 0
    """

def _problem_plagiarism_target_title(row):
    return row.get('problem_title') or f"题目 {row.get('problem_id')}"

def _build_problem_plagiarism_item(row, include_includes=False):
    problem_id = int(row.get('problem_id') or 0)
    problem_type = int(row.get('problem_type') or 1)
    programming_mode = int(row.get('programming_grading_mode') or 1)
    written_mode = int(row.get('written_grading_mode') or 1)
    raw_code = row.get('code') or ''
    compare_code = raw_code
    compare_kind = 'code'
    compare_files = None
    byte_fingerprints = []
    material_label = '代码'

    if problem_type == 1 and programming_mode == 3:
        raw_code = row.get('prompt_text') or ''
        compare_code = raw_code
        compare_kind = 'prompt'
        material_label = 'Prompt'
    elif problem_type == 2:
        file_path = _submission_upload_file_path(row.get('submission_id'), row.get('test_points'))
        byte_fp = _file_sha256_fingerprint(file_path, label='submission-file')
        if byte_fp:
            byte_fingerprints.append(byte_fp)
        raw_code = ''
        compare_code = ''
        compare_kind = 'none'
        material_label = '提交文件'
        if written_mode == 3:
            compare_files = _read_tex_files_from_zip(file_path)
            compare_kind = 'tex_files' if compare_files else 'none'
            material_label = 'TeX'
    else:
        if include_includes:
            included_files = extract_includes_from_code(raw_code)
            if included_files and row.get('user_id'):
                repository_files = get_user_repository_files_by_names(
                    row.get('user_id'),
                    included_files,
                    submission_id=row.get('submission_id'),
                )
                if repository_files:
                    compare_code += "\n\n// ===== 以下是引用的代码仓库文件 =====\n"
                    for filename, content in repository_files.items():
                        compare_code += f"\n// ===== {filename} =====\n{content or ''}\n"

    return {
        'target_kind': _PLAGIARISM_TARGET_PROBLEM,
        'target_key': _plagiarism_target_key(_PLAGIARISM_TARGET_PROBLEM, problem_id),
        'user_id': row.get('user_id'),
        'username': row.get('username'),
        'submission_id': row.get('submission_id'),
        'problem_id': problem_id,
        'problem_title': _problem_plagiarism_target_title(row),
        'raw_code': raw_code,
        'compare_code': compare_code,
        'compare_kind': compare_kind,
        'compare_files': compare_files,
        'byte_fingerprints': byte_fingerprints,
        'material_label': material_label,
    }

def _collect_best_first_submissions_for_plagiarism(class_en, problem_targets, include_includes=False):
    problem_ids = [int(target['id']) for target in (problem_targets or [])]
    if not problem_ids:
        return []

    placeholders = ','.join(['%s'] * len(problem_ids))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                WITH class_users AS (
                    {_class_users_cte_sql()}
                ),
                ranked_submissions AS (
                    SELECT cu.user_id,
                           cu.username,
                           s.id AS submission_id,
                           s.problem_id,
                           s.code,
                           s.prompt_text,
                           s.test_points,
                           s.score,
                           s.created_at,
                           p.title AS problem_title,
                           p.type AS problem_type,
                           p.programming_grading_mode,
                           p.written_grading_mode,
                           ROW_NUMBER() OVER (
                               PARTITION BY cu.user_id, s.problem_id
                               ORDER BY s.score DESC, s.created_at ASC, s.id ASC
                           ) AS rn
                    FROM class_users cu
                    JOIN submissions s ON s.username = cu.username
                    LEFT JOIN problems p ON p.id = s.problem_id
                    WHERE s.problem_id IN ({placeholders})
                )
                SELECT user_id, username, submission_id, problem_id, code, prompt_text, test_points,
                       score, created_at, problem_title, problem_type, programming_grading_mode, written_grading_mode
                FROM ranked_submissions
                WHERE rn = 1
                ORDER BY problem_id ASC, username ASC
                """,
                tuple([class_en] + list(problem_ids)),
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    return [_build_problem_plagiarism_item(row, include_includes=include_includes) for row in rows]

def _ranking_byte_fingerprints_for_submission(row):
    scoring_mode = str(row.get('scoring_mode') or 'absolute').strip().lower()
    fingerprints = []
    if scoring_mode == 'agent_judge':
        code_fp = _zip_content_sha256_fingerprint(row.get('code_path'), label='agent-files')
        if not code_fp:
            code_fp = _file_sha256_fingerprint(row.get('code_path'), label='agent-code-zip')
        if code_fp:
            fingerprints.append(code_fp)
    elif scoring_mode == 'elo':
        answer_fp = _file_sha256_fingerprint(row.get('answer_path'), label='answer-zip')
        code_fp = _file_sha256_fingerprint(row.get('code_path'), label='code-zip')
        if answer_fp:
            fingerprints.append(answer_fp)
        if code_fp:
            fingerprints.append(code_fp)
    else:
        code_fp = _file_sha256_fingerprint(row.get('code_path'), label='code-zip')
        if code_fp:
            fingerprints.append(code_fp)
    return fingerprints

def _collect_best_first_ranking_submissions_for_plagiarism(class_en, ranking_targets):
    competition_ids = [int(target['id']) for target in (ranking_targets or [])]
    if not competition_ids:
        return []

    placeholders = ','.join(['%s'] * len(competition_ids))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                WITH class_users AS (
                    {_class_users_cte_sql()}
                ),
                ranked_submissions AS (
                    SELECT cu.user_id,
                           cu.username,
                           rs.id AS submission_id,
                           rs.competition_id,
                           rs.answer_path,
                           rs.code_path,
                           rs.score,
                           rs.created_at,
                           rc.title AS competition_title,
                           rc.scoring_mode,
                           ROW_NUMBER() OVER (
                               PARTITION BY cu.user_id, rs.competition_id
                               ORDER BY (rs.score IS NULL) ASC, rs.score DESC, rs.created_at ASC, rs.id ASC
                           ) AS rn
                    FROM class_users cu
                    JOIN ranking_submissions rs ON rs.username = cu.username
                    LEFT JOIN ranking_competitions rc ON rc.id = rs.competition_id
                    WHERE rs.competition_id IN ({placeholders})
                )
                SELECT user_id, username, submission_id, competition_id, answer_path, code_path,
                       score, created_at, competition_title, scoring_mode
                FROM ranked_submissions
                WHERE rn = 1
                ORDER BY competition_id ASC, username ASC
                """,
                tuple([class_en] + list(competition_ids)),
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    submissions = []
    for row in rows:
        competition_id = int(row.get('competition_id') or 0)
        scoring_mode = str(row.get('scoring_mode') or 'absolute').strip().lower()
        title = row.get('competition_title') or f"打榜赛 {competition_id}"
        submissions.append({
            'target_kind': _PLAGIARISM_TARGET_RANKING,
            'target_key': _plagiarism_target_key(_PLAGIARISM_TARGET_RANKING, competition_id),
            'user_id': row.get('user_id'),
            'username': row.get('username'),
            'submission_id': row.get('submission_id'),
            # 负数写入 plagiarism_records.problem_id，避免与普通题记录唯一键冲突。
            'problem_id': -competition_id,
            'competition_id': competition_id,
            'problem_title': f"打榜赛：{title}",
            'raw_code': '',
            'compare_code': '',
            'compare_kind': 'ranking_zip',
            'byte_fingerprints': _ranking_byte_fingerprints_for_submission(row),
            'material_label': '打榜赛提交',
            'scoring_mode': scoring_mode,
        })
    return submissions

def _byte_fingerprints_for_plagiarism_item(item):
    if '_byte_fingerprints_cache' in item:
        return item.get('_byte_fingerprints_cache') or []

    fingerprints = []
    for value in item.get('byte_fingerprints') or []:
        text = str(value or '').strip()
        if text:
            fingerprints.append(text)
    if fingerprints:
        item['_byte_fingerprints_cache'] = sorted(set(fingerprints))
        return item['_byte_fingerprints_cache']

    raw_code = item.get('raw_code') or ''
    if not raw_code:
        item['_byte_fingerprints_cache'] = []
        return []
    payload = raw_code.encode('utf-8')
    item['_byte_fingerprints_cache'] = [f"submission:{hashlib.sha256(payload).hexdigest()}"]
    return item['_byte_fingerprints_cache']

def _plagiarism_similarity(item1, item2):
    kind1 = str(item1.get('compare_kind') or 'code')
    kind2 = str(item2.get('compare_kind') or 'code')
    if kind1 == 'tex_files' and kind2 == 'tex_files':
        return _calculate_tex_files_similarity(item1.get('compare_files'), item2.get('compare_files'))
    if kind1 == 'none' or kind2 == 'none':
        return 0.0
    return calculate_code_similarity(item1.get('compare_code') or '', item2.get('compare_code') or '')

def _build_plagiarism_components(codes_data, mode='threshold', threshold=0.9, progress_callback=None):
    problem_groups = defaultdict(list)
    for item in codes_data:
        group_key = item.get('target_key') or _plagiarism_target_key(
            item.get('target_kind') or _PLAGIARISM_TARGET_PROBLEM,
            abs(int(item.get('problem_id') or 0)),
        )
        problem_groups[group_key].append(item)

    if mode == 'byte':
        total_items = sum(len(group) for group in problem_groups.values())
        completed_items = 0
        progress_step = max(1, total_items // 100) if total_items else 1
        components = []

        if progress_callback and total_items == 0:
            progress_callback(1, 1, '没有需要计算哈希的提交代码')

        for _, group in problem_groups.items():
            by_hash = defaultdict(list)
            parent = list(range(len(group)))

            def find(x):
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            def union(a, b):
                ra = find(a)
                rb = find(b)
                if ra != rb:
                    parent[rb] = ra

            for idx, item in enumerate(group):
                for fingerprint in _byte_fingerprints_for_plagiarism_item(item):
                    by_hash[fingerprint].append(idx)
                completed_items += 1
                if progress_callback and (
                    completed_items == total_items
                    or completed_items % progress_step == 0
                ):
                    problem_title = item.get('problem_title') or f"题目 {item.get('problem_id')}"
                    progress_callback(
                        completed_items,
                        total_items,
                        f"正在计算字节哈希 {problem_title}: {item.get('username')}",
                    )
            for indexes in by_hash.values():
                if len(indexes) >= 2:
                    first = indexes[0]
                    for other in indexes[1:]:
                        union(first, other)

            by_root = defaultdict(list)
            for idx, item in enumerate(group):
                if _byte_fingerprints_for_plagiarism_item(item):
                    by_root[find(idx)].append(item)
            for members in by_root.values():
                if len(members) >= 2:
                    components.append(members)

        return components

    total_comparisons = sum(len(group) * (len(group) - 1) // 2 for group in problem_groups.values() if len(group) >= 2)
    completed_comparisons = 0
    progress_step = max(1, total_comparisons // 100) if total_comparisons else 1
    if progress_callback and total_comparisons == 0:
        progress_callback(1, 1, '没有需要比较的提交代码')

    components = []
    for _, group in problem_groups.items():
        if len(group) < 2:
            continue

        parent = list(range(len(group)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra = find(a)
            rb = find(b)
            if ra != rb:
                parent[rb] = ra

        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                if mode == 'byte':
                    code1 = group[i].get('raw_code') or ''
                    code2 = group[j].get('raw_code') or ''
                    matched = bool(code1) and code1 == code2
                else:
                    matched = _plagiarism_similarity(group[i], group[j]) >= threshold
                if matched:
                    union(i, j)
                completed_comparisons += 1
                if progress_callback and (
                    completed_comparisons == total_comparisons
                    or completed_comparisons % progress_step == 0
                ):
                    problem_title = group[i].get('problem_title') or f"题目 {group[i].get('problem_id')}"
                    progress_callback(
                        completed_comparisons,
                        total_comparisons,
                        f"正在比较 {problem_title}: {group[i].get('username')} vs {group[j].get('username')}",
                    )

        by_root = defaultdict(list)
        for idx, item in enumerate(group):
            by_root[find(idx)].append(item)
        for members in by_root.values():
            if len(members) >= 2:
                components.append(members)

    return components

def mark_class_plagiarism(class_en, class_cn, targets, mode, threshold, progress_callback=None, status_callback=None):
    if status_callback:
        status_callback('collecting', 0, 100, '正在收集提交材料...')
    include_includes = False
    normalized_targets = []
    for target in (targets or []):
        if isinstance(target, dict):
            normalized_targets.append(target)
        else:
            normalized_targets.append(_normalize_plagiarism_target(target))

    problem_targets = [target for target in normalized_targets if target.get('kind') == _PLAGIARISM_TARGET_PROBLEM]
    ranking_targets = [target for target in normalized_targets if target.get('kind') == _PLAGIARISM_TARGET_RANKING]
    if mode == 'threshold' and ranking_targets:
        raise ValueError('相似度查重暂不支持打榜赛')

    codes_data = _collect_best_first_submissions_for_plagiarism(
        class_en,
        problem_targets,
        include_includes=include_includes,
    )
    if mode == 'byte' and ranking_targets:
        codes_data.extend(_collect_best_first_ranking_submissions_for_plagiarism(class_en, ranking_targets))
    if status_callback:
        action = '开始计算字节哈希...' if mode == 'byte' else '开始比较...'
        status_callback('checking', 0, 1, f'已收集 {len(codes_data)} 份提交，{action}')
    comparison_rule = 'byte-identical' if mode == 'byte' else _format_threshold_rule(threshold)
    components = _build_plagiarism_components(
        codes_data,
        mode=mode,
        threshold=threshold,
        progress_callback=progress_callback,
    )
    if status_callback:
        status_callback('saving', 0, 1, '正在写入抄袭记录...')
    records = _build_plagiarism_record_rows(components, class_en, class_cn, comparison_rule)
    inserted_count = _save_plagiarism_records(records)
    if status_callback:
        status_callback('saving', 1, 1, '抄袭记录写入完成')
    return {
        'submission_count': len(codes_data),
        'group_count': len(components),
        'record_count': inserted_count,
        'comparison_rule': comparison_rule,
    }

def detect_plagiarism(codes_data, threshold=0.9, task_id=None):
    results = []
    problem_groups = {}
    for item in codes_data:
        pid = item['problem_id']
        if pid not in problem_groups:
            problem_groups[pid] = []
        problem_groups[pid].append(item)

    total_comparisons = 0
    for group in problem_groups.values():
        if len(group) >= 2:
            total_comparisons += len(group) * (len(group) - 1) // 2

    if total_comparisons == 0:
        if task_id:
            update_export_progress(task_id, 'plagiarism_check', 1, 1, '没有需要查重的代码')
        return results

    completed_comparisons = 0
    for pid, group in problem_groups.items():
        if len(group) < 2:
            continue

        problem_title = group[0]['problem_title']
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                user1 = group[i]['username']
                user2 = group[j]['username']
                code1 = group[i]['code']
                code2 = group[j]['code']

                if task_id:
                    message = f'正在比较: 题目 {problem_title} - {user1} vs {user2}'
                    sub_progress = {
                        'problem_check': {
                            'current': completed_comparisons,
                            'total': total_comparisons,
                            'percentage': int((completed_comparisons / total_comparisons * 100)) if total_comparisons > 0 else 0,
                            'message': message,
                        }
                    }
                    update_export_progress(
                        task_id,
                        'plagiarism_check',
                        completed_comparisons,
                        total_comparisons,
                        '题目代码查重中...',
                        sub_progress,
                    )

                similarity = calculate_code_similarity(code1, code2)
                if similarity >= threshold:
                    results.append({
                        'problem_id': pid,
                        'problem_title': problem_title,
                        'user1': user1,
                        'user2': user2,
                        'similarity': similarity,
                    })

                completed_comparisons += 1

    if task_id:
        sub_progress = {
            'problem_check': {
                'current': total_comparisons,
                'total': total_comparisons,
                'percentage': 100,
                'message': f'题目代码查重完成，发现 {len(results)} 组相似代码',
            }
        }
        update_export_progress(
            task_id,
            'plagiarism_check',
            total_comparisons,
            total_comparisons,
            f'题目代码查重完成，发现 {len(results)} 组相似代码',
            sub_progress,
        )

    return results

def detect_repository_plagiarism(students_data, threshold=0.9, task_id=None):
    results = []
    students_with_files = [s for s in students_data if s['files']]

    if len(students_with_files) < 2:
        if task_id:
            update_export_progress(task_id, 'plagiarism_check', 1, 1, '代码仓库文件不足，跳过查重')
        return results

    total_comparisons = 0
    for i in range(len(students_with_files)):
        for j in range(i + 1, len(students_with_files)):
            files1 = students_with_files[i]['files']
            files2 = students_with_files[j]['files']
            total_comparisons += len(files1) * len(files2)

    if total_comparisons == 0:
        if task_id:
            update_export_progress(task_id, 'plagiarism_check', 1, 1, '没有需要比较的代码仓库文件')
        return results

    completed_comparisons = 0
    for i in range(len(students_with_files)):
        for j in range(i + 1, len(students_with_files)):
            student1 = students_with_files[i]
            student2 = students_with_files[j]
            user1 = student1['username']
            user2 = student2['username']

            for file1 in student1['files']:
                for file2 in student2['files']:
                    if task_id:
                        message = f'正在比较: {user1}/{file1["filename"]} vs {user2}/{file2["filename"]}'
                        sub_progress = {
                            'repo_check': {
                                'current': completed_comparisons,
                                'total': total_comparisons,
                                'percentage': int((completed_comparisons / total_comparisons * 100)) if total_comparisons > 0 else 0,
                                'message': message,
                            }
                        }
                        update_export_progress(
                            task_id,
                            'plagiarism_check',
                            completed_comparisons,
                            total_comparisons,
                            '代码仓库查重中...',
                            sub_progress,
                        )

                    similarity = calculate_code_similarity(file1['content'], file2['content'])
                    if similarity >= threshold:
                        results.append({
                            'user1': user1,
                            'user2': user2,
                            'file1': file1['filename'],
                            'file2': file2['filename'],
                            'similarity': similarity,
                            'type': 'repository',
                        })

                    completed_comparisons += 1

    if task_id:
        sub_progress = {
            'repo_check': {
                'current': total_comparisons,
                'total': total_comparisons,
                'percentage': 100,
                'message': f'代码仓库查重完成，发现 {len(results)} 组相似文件',
            }
        }
        update_export_progress(
            task_id,
            'plagiarism_check',
            total_comparisons,
            total_comparisons,
            f'代码仓库查重完成，发现 {len(results)} 组相似文件',
            sub_progress,
        )

    return results

def generate_plagiarism_report(plagiarism_results, repository_results=None):
    if not plagiarism_results and not repository_results:
        return "未发现相似度达到90%以上的代码。\n"

    report = "=" * 80 + "\n"
    report += "代码查重报告\n"
    report += "=" * 80 + "\n"
    report += f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += "查重阈值: 90%\n"
    report += f"题目代码: 发现 {len(plagiarism_results) if plagiarism_results else 0} 组疑似相似代码\n"
    report += f"代码仓库: 发现 {len(repository_results) if repository_results else 0} 组疑似相似文件\n"
    report += "=" * 80 + "\n\n"

    if plagiarism_results:
        report += "\n" + "=" * 80 + "\n"
        report += "一、题目代码查重结果\n"
        report += "=" * 80 + "\n\n"

        by_problem = {}
        for result in plagiarism_results:
            pid = result['problem_id']
            if pid not in by_problem:
                by_problem[pid] = []
            by_problem[pid].append(result)

        for pid, items in by_problem.items():
            report += f"\n题目 ID: {pid}\n"
            report += f"题目标题: {items[0]['problem_title']}\n"
            report += "-" * 80 + "\n"

            for idx, item in enumerate(items, 1):
                report += f"  [{idx}] 学生1: {item['user1']}  <-->  学生2: {item['user2']}\n"
                report += f"       相似度: {item['similarity'] * 100:.2f}%\n\n"

            report += "\n"

    if repository_results:
        report += "\n" + "=" * 80 + "\n"
        report += "二、代码仓库查重结果\n"
        report += "=" * 80 + "\n\n"

        by_student_pair = {}
        for result in repository_results:
            key = f"{result['user1']} <--> {result['user2']}"
            if key not in by_student_pair:
                by_student_pair[key] = []
            by_student_pair[key].append(result)

        for pair, items in by_student_pair.items():
            report += f"\n学生对: {pair}\n"
            report += "-" * 80 + "\n"

            for idx, item in enumerate(items, 1):
                report += f"  [{idx}] 文件1: {item['file1']}  <-->  文件2: {item['file2']}\n"
                report += f"       相似度: {item['similarity'] * 100:.2f}%\n\n"

            report += "\n"

    report += "=" * 80 + "\n"
    report += "说明:\n"
    report += "1. 本报告列出了相似度达到90%以上的代码对和文件对\n"
    report += "2. 相似度计算基于代码文本比对，已排除注释和空白的影响\n"
    report += "3. 题目代码查重：比较同一题目内不同学生的提交代码\n"
    report += "4. 代码仓库查重：比较不同学生代码仓库中的所有文件\n"
    report += "5. 高相似度可能由于：代码抄袭、共同参考答案、题目简单导致解法相似等\n"
    report += "6. 建议人工审核高相似度代码，结合提交时间等信息综合判断\n"
    report += "=" * 80 + "\n"
    return report

__all__ = [
    "calculate_code_similarity",
    "detect_plagiarism",
    "detect_repository_plagiarism",
    "generate_plagiarism_report",
    "mark_class_plagiarism",
    "normalize_code",
]
