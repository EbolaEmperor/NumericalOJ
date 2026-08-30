#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""作业导出与查重任务的 Redis 进度状态。"""

import json


def _load_progress(redis_client, key):
    if not redis_client:
        return None
    progress_data = redis_client.get(key)
    if not progress_data:
        return None
    if isinstance(progress_data, bytes):
        progress_data = progress_data.decode("utf-8")
    return json.loads(progress_data)


def get_export_progress_payload(redis_client, task_id):
    return _load_progress(redis_client, f"export_progress:{task_id}")


def get_plagiarism_progress_payload(redis_client, task_id):
    return _load_progress(redis_client, f"plagiarism_progress:{task_id}")


def update_export_progress(
    redis_client,
    task_id,
    stage,
    current,
    total,
    message,
    sub_progress=None,
):
    progress_data = {
        "stage": stage,
        "current": current,
        "total": total,
        "message": message,
        "percentage": int((current / total * 100)) if total > 0 else 0,
        "sub_progress": sub_progress or {},
    }
    redis_client.setex(
        f"export_progress:{task_id}",
        600,
        json.dumps(progress_data),
    )


def update_plagiarism_progress(
    redis_client,
    task_id,
    stage,
    current,
    total,
    message,
    result=None,
):
    progress_data = {
        "stage": stage,
        "current": current,
        "total": total,
        "message": message,
        "percentage": int((current / total * 100)) if total > 0 else 0,
    }
    if result is not None:
        progress_data["result"] = result
    redis_client.setex(
        f"plagiarism_progress:{task_id}",
        1800,
        json.dumps(progress_data, ensure_ascii=False),
    )


__all__ = [
    "get_export_progress_payload",
    "get_plagiarism_progress_payload",
    "update_export_progress",
    "update_plagiarism_progress",
]
