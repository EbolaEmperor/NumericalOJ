#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进程启动时重新入队历史 pending 任务。

两个 app supervisor 进程（web / celery）重启后，Celery 队列里原本累积的任务
会丢失，导致数据库里仍处于“排队中 / 评测中”的提交永远卡住。本模块在 web 进程启动
时扫描 MySQL，把这些未完成的提交重新发回 Celery 队列。

只应在 web 进程启动时调用一次（见 oj.py 的 __main__ 守卫），不要在 Celery worker
里运行；任何异常都不会向外抛出——重新入队失败绝不能阻止 web 进程启动。

注意：清僵尸锁 + 重跑 Running 的前提是“所有 worker 都已死亡”（标准部署流程会同时
重启两个 app supervisor）。若只重启 web 进程而 Celery worker 仍在评测，理论上可能对某条
正在评测的 Running 提交造成重复评测；现行部署流程不会出现这种情况。
"""

from oj_modules.db_services import (
    get_incomplete_submissions,
    update_submission_status,
)
from oj_modules.ranking_db import (
    get_incomplete_ranking_submissions,
    init_submission_elo_state,
)
from oj_modules.tasks.evaluate_tasks import clear_submission_lock


_STARTUP_REQUEUE_STAGGER_SECONDS = 1


def _startup_countdown(index):
    """启动恢复任务错峰入队，避免大量 worker 同时打到 MySQL 连接池。"""
    return max(0, int(index or 0)) * _STARTUP_REQUEUE_STAGGER_SECONDS


def _requeue_programming_submissions(evaluate_task, written_task):
    """重新入队 submissions 表里未完成的程序题（type 1）/ 书面作业（type 2）提交。"""
    requeued = 0
    try:
        rows = get_incomplete_submissions()
    except Exception as e:
        print(f"[StartupRequeue] 查询未完成提交失败：{e}")
        return 0

    for row in rows:
        sub_id = row.get('id')
        problem_type = row.get('problem_type')
        status = row.get('status')
        if sub_id is None:
            continue
        try:
            # 评测中途被杀的提交：清掉僵尸锁并把状态重置回 Pending，使其能干净重跑。
            if status == 'Running':
                clear_submission_lock(sub_id)
                update_submission_status(sub_id, 'Pending')

            if problem_type == 2:
                if written_task is not None:
                    written_task.apply_async(args=[sub_id], countdown=_startup_countdown(requeued))
                    requeued += 1
            else:
                if evaluate_task is not None:
                    evaluate_task.apply_async(args=[sub_id], countdown=_startup_countdown(requeued))
                    requeued += 1
        except Exception as e:
            print(f"[StartupRequeue] 提交 #{sub_id} 重新入队失败：{e}")

    return requeued


def _requeue_ranking_submissions(ranking_task, elo_initial_burst_task):
    """重新入队卡在 'Judging' 的打榜赛提交。

    - 绝对分模式：直接 .delay() 给评测任务；
    - ELO 模式：正式带入对战池（init_submission_elo_state -> Active）并补发
      initial-burst；池中 Active 的提交由已重新 seed 的 matchmaker tick 接管。
    """
    requeued = 0
    try:
        rows = get_incomplete_ranking_submissions()
    except Exception as e:
        print(f"[StartupRequeue] 查询未完成打榜赛提交失败：{e}")
        return 0

    for row in rows:
        sub_id = row.get('id')
        competition_id = row.get('competition_id')
        scoring_mode = str(row.get('scoring_mode') or '').strip().lower()
        if sub_id is None:
            continue
        try:
            if scoring_mode == 'elo':
                initial_rating = float(row.get('elo_initial_rating') or 1500)
                init_submission_elo_state(sub_id, initial_rating)
                if elo_initial_burst_task is not None:
                    elo_initial_burst_task.apply_async(
                        args=[competition_id, sub_id], countdown=3 + _startup_countdown(requeued),
                    )
                    requeued += 1
            else:
                if ranking_task is not None:
                    ranking_task.apply_async(args=[sub_id], countdown=_startup_countdown(requeued))
                    requeued += 1
        except Exception as e:
            print(f"[StartupRequeue] 打榜赛提交 #{sub_id} 重新入队失败：{e}")

    return requeued


def requeue_pending_on_startup(*, evaluate_task, written_task,
                               ranking_task, elo_initial_burst_task):
    """启动时扫描 MySQL 并重新入队所有未完成任务（程序题 / 书面作业 / 打榜赛）。"""
    try:
        prog = _requeue_programming_submissions(evaluate_task, written_task)
        rank = _requeue_ranking_submissions(ranking_task, elo_initial_burst_task)
        print(
            f"[StartupRequeue] 启动重新入队完成："
            f"程序题/书面作业 {prog} 条，打榜赛 {rank} 条。"
        )
    except Exception as e:
        print(f"[StartupRequeue] 启动重新入队异常（已忽略，不影响启动）：{e}")
