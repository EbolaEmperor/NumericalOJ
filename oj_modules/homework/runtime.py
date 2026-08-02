#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""由组合根注入的作业任务、Redis 与跨领域缓存失效端口。"""

from oj_modules.homework import progress


_text_redis_client = None
_binary_redis_client = None
_export_task = None
_plagiarism_task = None
_problem_list_cache_invalidator = None


def configure_homework_runtime(
    text_redis_client,
    binary_redis_client,
    export_task,
    plagiarism_task,
    *,
    problem_list_cache_invalidator=None,
):
    global _text_redis_client
    global _binary_redis_client
    global _export_task
    global _plagiarism_task
    global _problem_list_cache_invalidator

    _text_redis_client = text_redis_client
    _binary_redis_client = binary_redis_client
    _export_task = export_task
    _plagiarism_task = plagiarism_task
    _problem_list_cache_invalidator = problem_list_cache_invalidator


def start_export_codes_task(selected_class):
    if _export_task is None:
        raise RuntimeError("导出模块未初始化")
    task = _export_task.delay(selected_class)
    return task.id


def start_plagiarism_mark_task(class_en, mode, threshold, targets):
    if _plagiarism_task is None:
        raise RuntimeError("查重模块未初始化")
    task = _plagiarism_task.delay(
        class_en,
        mode,
        float(threshold),
        list(targets or []),
    )
    return task.id


def get_export_progress_payload(task_id):
    return progress.get_export_progress_payload(_text_redis_client, task_id)


def get_plagiarism_progress_payload(task_id):
    return progress.get_plagiarism_progress_payload(_text_redis_client, task_id)


def get_export_zip(task_id):
    if not _binary_redis_client:
        return None
    return _binary_redis_client.get(f"export_zip:{task_id}")


def update_export_progress(
    task_id,
    stage,
    current,
    total,
    message,
    sub_progress=None,
):
    return progress.update_export_progress(
        _text_redis_client,
        task_id,
        stage,
        current,
        total,
        message,
        sub_progress,
    )


def update_plagiarism_progress(
    task_id,
    stage,
    current,
    total,
    message,
    result=None,
):
    return progress.update_plagiarism_progress(
        _text_redis_client,
        task_id,
        stage,
        current,
        total,
        message,
        result,
    )


def invalidate_problem_list_cache_for_class(class_en):
    callback = _problem_list_cache_invalidator
    if callback is None:
        return
    try:
        callback(class_en)
    except Exception:
        # 缓存失效失败不影响作业或查重主流程。
        pass


__all__ = [
    "configure_homework_runtime",
    "get_export_progress_payload",
    "get_export_zip",
    "get_plagiarism_progress_payload",
    "invalidate_problem_list_cache_for_class",
    "start_export_codes_task",
    "start_plagiarism_mark_task",
    "update_export_progress",
    "update_plagiarism_progress",
]
