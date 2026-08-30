#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""作业查重记录的持久化、序列化与 CSV 表示。"""

import codecs
import csv
import json
from dataclasses import dataclass
from io import BytesIO

from backend.oj_modules.homework.targets import (
    _PLAGIARISM_TARGET_PROBLEM,
    _PLAGIARISM_TARGET_RANKING,
)
from backend.oj_modules.infrastructure.mysql import get_db_connection


def _build_plagiarism_record_rows(components, class_en, class_cn, comparison_rule):
    rows = []
    for members in components:
        ordered_members = sorted(members, key=lambda item: str(item.get('username') or ''))
        usernames = [item.get('username') for item in ordered_members if item.get('username')]
        for item in ordered_members:
            username = item.get('username')
            matched_usernames = [name for name in usernames if name != username]
            if not username or not matched_usernames:
                continue
            rows.append({
                'user_id': int(item.get('user_id') or 0),
                'username': username,
                'class_en': class_en,
                'class_cn': class_cn,
                'problem_id': int(item.get('problem_id') or 0),
                'problem_title': item.get('problem_title') or f"题目 {item.get('problem_id')}",
                'submission_id': int(item.get('submission_id') or 0),
                'comparison_rule': comparison_rule,
                'matched_usernames': matched_usernames,
                'target_kind': item.get('target_kind') or _PLAGIARISM_TARGET_PROBLEM,
            })
    return rows

def _save_plagiarism_records(records):
    if not records:
        return 0

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO plagiarism_records
                    (user_id, username, class_en, class_cn, problem_id, problem_title,
                     submission_id, comparison_rule, matched_usernames)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    user_id=VALUES(user_id),
                    class_cn=VALUES(class_cn),
                    problem_title=VALUES(problem_title),
                    matched_usernames=VALUES(matched_usernames),
                    created_at=CURRENT_TIMESTAMP
                """,
                [
                    (
                        record['user_id'],
                        record['username'],
                        record['class_en'],
                        record['class_cn'],
                        record['problem_id'],
                        record['problem_title'],
                        record['submission_id'],
                        record['comparison_rule'],
                        json.dumps(record['matched_usernames'], ensure_ascii=False),
                    )
                    for record in records
                ],
            )
        conn.commit()
    finally:
        conn.close()
    return len(records)

def _decode_matched_usernames(raw_value):
    if not raw_value:
        return []
    if isinstance(raw_value, list):
        return raw_value
    try:
        value = json.loads(raw_value)
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
    except Exception:
        pass
    return [part.strip() for part in str(raw_value).split(',') if part.strip()]

def _serialize_plagiarism_record(row):
    matched_usernames = _decode_matched_usernames(row.get('matched_usernames'))
    created_at = row.get('created_at')
    raw_problem_id = int(row.get('problem_id') or 0)
    title = row.get('problem_title') or ''
    target_kind = _PLAGIARISM_TARGET_RANKING if raw_problem_id < 0 or str(title).startswith('打榜赛：') else _PLAGIARISM_TARGET_PROBLEM
    display_problem_id = abs(raw_problem_id) if target_kind == _PLAGIARISM_TARGET_RANKING else raw_problem_id
    return {
        'id': row.get('id'),
        'user_id': row.get('user_id'),
        'username': row.get('username'),
        'class_en': row.get('class_en'),
        'class_cn': row.get('class_cn'),
        'problem_id': display_problem_id,
        'problem_title': title,
        'submission_id': row.get('submission_id'),
        'comparison_rule': row.get('comparison_rule'),
        'matched_usernames': matched_usernames,
        'matched_usernames_text': '、'.join(matched_usernames),
        'target_kind': target_kind,
        'competition_id': display_problem_id if target_kind == _PLAGIARISM_TARGET_RANKING else None,
        'created_at': created_at.strftime('%Y-%m-%d %H:%M:%S') if created_at else '',
    }

def _load_plagiarism_records_for_class(class_en):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id, username, class_en, class_cn, problem_id, problem_title,
                       submission_id, comparison_rule, matched_usernames, created_at
                FROM plagiarism_records
                WHERE class_en=%s
                ORDER BY created_at DESC, id DESC
                """,
                (class_en,),
            )
            return [_serialize_plagiarism_record(row) for row in cursor.fetchall()]
    finally:
        conn.close()

@dataclass(frozen=True)
class PlagiarismRecordsCsv:
    content: bytes
    filename: str
    content_type: str = "text/csv; charset=GBK"


def build_plagiarism_records_csv(class_en):
    records = _load_plagiarism_records_for_class(class_en)
    output = BytesIO()
    writer = csv.writer(codecs.getwriter("gbk")(output))
    headers = [
        "抄袭记录ID",
        "用户ID",
        "用户名",
        "班级",
        "题目ID",
        "题目名称",
        "提交ID",
        "比较规则",
        "相同用户名",
        "标记时间",
    ]
    writer.writerow([
        header.encode("gbk", "replace").decode("gbk")
        for header in headers
    ])
    for record in records:
        row = [
            record.get("id"),
            record.get("user_id"),
            record.get("username"),
            record.get("class_cn") or record.get("class_en"),
            record.get("problem_id"),
            record.get("problem_title") or "",
            record.get("submission_id"),
            record.get("comparison_rule"),
            record.get("matched_usernames_text") or "",
            record.get("created_at") or "",
        ]
        writer.writerow([
            str(cell if cell is not None else "")
            .encode("gbk", "replace")
            .decode("gbk")
            for cell in row
        ])

    return PlagiarismRecordsCsv(
        content=output.getvalue(),
        filename=f"{class_en}_plagiarism_records.csv",
    )


def delete_plagiarism_records_for_class(
    class_en,
    record_ids,
    *,
    invalidate_callback=None,
):
    placeholders = ",".join(["%s"] * len(record_ids))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"DELETE FROM plagiarism_records "
                f"WHERE class_en=%s AND id IN ({placeholders})",
                tuple([class_en] + record_ids),
            )
            deleted = cursor.rowcount
        conn.commit()
    finally:
        conn.close()

    if invalidate_callback is not None:
        invalidate_callback(class_en)
    return deleted


load_plagiarism_records_for_class = _load_plagiarism_records_for_class

__all__ = [
    "PlagiarismRecordsCsv",
    "build_plagiarism_records_csv",
    "delete_plagiarism_records_for_class",
    "load_plagiarism_records_for_class",
]

