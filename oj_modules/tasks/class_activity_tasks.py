#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""班级活跃度 Redis 快照的全局自调度刷新任务。"""

from __future__ import annotations

import logging
import uuid

from oj_modules.classroom.dashboard import refresh_class_activity_snapshot


CLASS_ACTIVITY_REFRESH_TASK_NAME = "oj.class_activity.refresh_snapshot"
CLASS_ACTIVITY_REFRESH_INTERVAL_SECONDS = 20 * 60
CLASS_ACTIVITY_REFRESH_OWNER_KEY = "numoj:class-activity:refresh-owner:v1"
_OWNER_TTL_SECONDS = CLASS_ACTIVITY_REFRESH_INTERVAL_SECONDS * 5

logger = logging.getLogger(__name__)


def register_class_activity_refresh_task(celery_app, redis_client):
    """注册每 20 分钟刷新一次全部班级活跃度的普通队列任务。"""

    @celery_app.task(
        name=CLASS_ACTIVITY_REFRESH_TASK_NAME,
        bind=True,
        ignore_result=True,
    )
    def refresh_class_activity(self, owner_id):
        def schedule_next():
            try:
                self.apply_async(
                    args=[owner_id],
                    countdown=CLASS_ACTIVITY_REFRESH_INTERVAL_SECONDS,
                )
            except Exception:
                logger.exception("续排下一次班级活跃度刷新任务失败")

        try:
            current_owner = redis_client.get(CLASS_ACTIVITY_REFRESH_OWNER_KEY)
            if current_owner is None:
                redis_client.set(
                    CLASS_ACTIVITY_REFRESH_OWNER_KEY,
                    owner_id,
                    ex=_OWNER_TTL_SECONDS,
                    nx=True,
                )
                current_owner = redis_client.get(
                    CLASS_ACTIVITY_REFRESH_OWNER_KEY
                )
            if str(current_owner) != str(owner_id):
                return {
                    "success": True,
                    "reason": "not the active refresh owner",
                }
            redis_client.set(
                CLASS_ACTIVITY_REFRESH_OWNER_KEY,
                owner_id,
                ex=_OWNER_TTL_SECONDS,
            )
        except Exception:
            logger.exception("校验班级活跃度刷新任务所有权失败")
            schedule_next()
            return {"success": False, "reason": "redis owner unavailable"}

        try:
            result = refresh_class_activity_snapshot(redis_client)
            logger.info(
                "班级活跃度 Redis 快照刷新完成",
                extra={"class_count": result.get("class_count", 0)},
            )
            return {"success": True, **result}
        except Exception:
            # publish 使用临时键 + RENAME，异常不会破坏上一版正式快照。
            logger.exception("刷新班级活跃度 Redis 快照失败")
            return {"success": False, "reason": "refresh failed"}
        finally:
            schedule_next()

    return refresh_class_activity


def seed_class_activity_refresh(
    redis_client,
    refresh_task,
    *,
    reset_owner=False,
    countdown=0,
):
    """幂等启动一条全局刷新链；默认立即预热第一版快照。"""
    if refresh_task is None or redis_client is None:
        return
    try:
        if reset_owner:
            redis_client.delete(CLASS_ACTIVITY_REFRESH_OWNER_KEY)
        owner_id = uuid.uuid4().hex
        if redis_client.set(
            CLASS_ACTIVITY_REFRESH_OWNER_KEY,
            owner_id,
            ex=_OWNER_TTL_SECONDS,
            nx=True,
        ):
            refresh_task.apply_async(args=[owner_id], countdown=countdown)
    except Exception:
        logger.exception("启动班级活跃度刷新任务失败")


__all__ = [
    "CLASS_ACTIVITY_REFRESH_INTERVAL_SECONDS",
    "CLASS_ACTIVITY_REFRESH_OWNER_KEY",
    "CLASS_ACTIVITY_REFRESH_TASK_NAME",
    "register_class_activity_refresh_task",
    "seed_class_activity_refresh",
]
