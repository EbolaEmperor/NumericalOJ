#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from backend.oj_modules.repository.index import (
    REPOSITORY_INDEX_TASK_HARD_TIME_LIMIT_SECONDS,
    REPOSITORY_INDEX_TASK_SOFT_TIME_LIMIT_SECONDS,
    run_repository_index_job,
)


REPOSITORY_INDEX_BUILD_TASK_NAME = 'oj.repository.build_index'


def register_repository_index_build_task(celery_app):
    existing = celery_app.tasks.get(REPOSITORY_INDEX_BUILD_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(
        name=REPOSITORY_INDEX_BUILD_TASK_NAME,
        time_limit=REPOSITORY_INDEX_TASK_HARD_TIME_LIMIT_SECONDS,
        soft_time_limit=REPOSITORY_INDEX_TASK_SOFT_TIME_LIMIT_SECONDS,
    )
    def build_repository_index(user_id, job_id, file_id=None):
        return run_repository_index_job(user_id=user_id, job_id=job_id, file_id=file_id)

    return build_repository_index
