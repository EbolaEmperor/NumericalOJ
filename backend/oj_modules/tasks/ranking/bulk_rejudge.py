#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛「所有提交」批量重测任务。"""

from contextlib import nullcontext
import json
import time
import uuid

from backend.oj_modules import config as _cfg
from backend.oj_modules.infrastructure.redis import create_optional_redis_client
from backend.oj_modules.ranking.judge_control import JudgeCancellationError, stopped_judge_submission
from backend.oj_modules.tasks.agent.control import build_agent_run_terminator
from backend.oj_modules.ranking.db import (
    activate_elo_submission,
    begin_agent_judge_attempt,
    get_competition,
    get_ranking_submission,
    release_standard_ranking_evaluation,
    reserve_standard_ranking_evaluation,
    set_agent_judge_task_id,
    update_submission_result,
)


TASK_NAME = 'oj.ranking_bulk_rejudge'
JOB_PREFIX = 'ranking:bulk_rejudge:'
JOB_TTL = int(getattr(_cfg, 'RANKING_BULK_REJUDGE_JOB_TTL', 6 * 3600))
ITEM_SLEEP_SECONDS = float(getattr(_cfg, 'RANKING_BULK_REJUDGE_ITEM_SLEEP_SECONDS', 2.0))

_bulk_rds = None


def init_bulk_rejudge_progress_cache(redis_client):
    global _bulk_rds
    _bulk_rds = redis_client


def _ensure_rds():
    global _bulk_rds
    if _bulk_rds is not None:
        return _bulk_rds
    _bulk_rds = create_optional_redis_client()
    return _bulk_rds


def bulk_rejudge_job_key(job_id):
    return JOB_PREFIX + str(job_id)


def get_bulk_rejudge_job(job_id):
    rds = _ensure_rds()
    if rds is None:
        return None
    try:
        raw = rds.get(bulk_rejudge_job_key(job_id))
        return json.loads(raw) if raw else None
    except Exception:
        return None


def save_bulk_rejudge_job(job_id, payload):
    rds = _ensure_rds()
    if rds is None:
        return
    try:
        rds.setex(bulk_rejudge_job_key(job_id), JOB_TTL, json.dumps(payload, ensure_ascii=False))
    except Exception:
        pass


def _mode(comp):
    mode = str((comp or {}).get('scoring_mode') or 'absolute').strip().lower()
    return mode if mode in ('absolute', 'elo', 'agent_judge', 'reverse_judge') else 'absolute'


def _reset_submission_for_rejudge(comp, submission_id, *, username=None):
    """在原提交记录上清空旧结果，并切回可评测状态。"""
    mode = _mode(comp)
    if mode == 'agent_judge':
        return begin_agent_judge_attempt(
            submission_id, status='Queued', reset_result=True,
            clear_agent_results=True,
        )
    if mode == 'reverse_judge':
        return begin_agent_judge_attempt(
            submission_id, status='Queued', reset_result=True,
            clear_reverse_steps=True,
        )
    if mode == 'elo':
        initial_rating = float(comp.get('elo_initial_rating') or 1500)
        activate_elo_submission(
            submission_id,
            int(comp['id']),
            username,
            initial_rating,
            keep_count=2,
        )
        return None
    update_submission_result(submission_id, None, 'Judging',
                             grade_details=None, error_message=None)
    return None


def _enqueue_submission(comp, submission_id,
                        evaluate_task, agent_judge_task, reverse_judge_task,
                        elo_initial_burst_task, attempt_id=None):
    mode = _mode(comp)
    if mode == 'agent_judge':
        if agent_judge_task is None:
            raise RuntimeError('Agent 评测任务未初始化')
        async_result = agent_judge_task.apply_async(args=[submission_id, attempt_id])
        set_agent_judge_task_id(submission_id, attempt_id, async_result.id)
        return

    if mode == 'reverse_judge':
        if reverse_judge_task is None:
            raise RuntimeError('反向评测任务未初始化')
        async_result = reverse_judge_task.apply_async(args=[submission_id, attempt_id])
        set_agent_judge_task_id(submission_id, attempt_id, async_result.id)
        return

    if mode == 'elo':
        if elo_initial_burst_task is not None:
            elo_initial_burst_task.apply_async(args=[int(comp['id']), submission_id], countdown=3)
        return

    if evaluate_task is None:
        raise RuntimeError('打榜赛评测任务未初始化')
    dispatch_task_id = str(uuid.uuid4())
    if not reserve_standard_ranking_evaluation(
            submission_id,
            dispatch_task_id,
            force=True,
    ):
        raise RuntimeError(f'提交 #{submission_id} 无法取得普通评测数据库租约')
    try:
        evaluate_task.apply_async(args=[submission_id], task_id=dispatch_task_id)
    except Exception:
        release_standard_ranking_evaluation(submission_id, dispatch_task_id)
        raise


def register_ranking_bulk_rejudge_task(celery_app, evaluate_ranking_task,
                                       agent_judge_task=None, reverse_judge_task=None,
                                       elo_initial_burst_task=None):
    @celery_app.task(name=TASK_NAME)
    def ranking_bulk_rejudge(competition_id, source_ids, job_id, started_by=None):
        source_ids = [int(x) for x in (source_ids or [])]
        comp = get_competition(int(competition_id))
        if not comp:
            job = get_bulk_rejudge_job(job_id) or {}
            job.update({'status': 'failed', 'last_error': '比赛不存在或已被删除'})
            save_bulk_rejudge_job(job_id, job)
            return

        mode = _mode(comp)
        job = get_bulk_rejudge_job(job_id) or {}
        job.update({
            'status': 'running',
            'total': len(source_ids),
            'processed': int(job.get('processed') or 0),
            'requeued': int(job.get('requeued') or job.get('created') or 0),
            'created': int(job.get('created') or 0),  # 旧前端兼容；不再表示新建提交。
            'failed': int(job.get('failed') or 0),
            'requeued_ids': job.get('requeued_ids') or job.get('created_ids') or [],
            'created_ids': job.get('created_ids') or [],  # 旧前端兼容；不再表示新建提交。
            'started_by': started_by or job.get('started_by') or '',
            'interval_seconds': ITEM_SLEEP_SECONDS,
        })
        save_bulk_rejudge_job(job_id, job)

        for idx, source_id in enumerate(source_ids):
            if idx > 0:
                time.sleep(ITEM_SLEEP_SECONDS)

            requeued_id = int(source_id)
            try:
                source = get_ranking_submission(requeued_id)
                if not source:
                    raise ValueError(f"ranking submission {requeued_id} not found")
                if int(source.get('competition_id') or 0) != int(competition_id):
                    raise ValueError("submission does not belong to this competition")
                stopping = (
                    stopped_judge_submission(
                        source, mode, redis_client=_ensure_rds(),
                        terminate_agent=build_agent_run_terminator(celery_app),
                    ) if mode in {'agent_judge', 'reverse_judge'} else nullcontext()
                )
                with stopping:
                    attempt_id = _reset_submission_for_rejudge(
                        comp,
                        requeued_id,
                        username=source.get('username'),
                    )
                    _enqueue_submission(
                        comp, requeued_id,
                        evaluate_ranking_task, agent_judge_task, reverse_judge_task,
                        elo_initial_burst_task, attempt_id,
                    )
                job['requeued'] = int(job.get('requeued') or 0) + 1
                requeued_ids = job.get('requeued_ids')
                if not isinstance(requeued_ids, list):
                    requeued_ids = []
                requeued_ids.append(int(requeued_id))
                job['requeued_ids'] = requeued_ids[-200:]
            except Exception as e:
                job['failed'] = int(job.get('failed') or 0) + 1
                job['last_error'] = str(e)[:500]
                if not isinstance(e, JudgeCancellationError):
                    try:
                        update_submission_result(requeued_id, None, 'Error', error_message=str(e)[:1000])
                    except Exception:
                        pass
            finally:
                job['processed'] = int(job.get('processed') or 0) + 1
                job['progress'] = int(job['processed'] / max(1, len(source_ids)) * 100)
                save_bulk_rejudge_job(job_id, job)

        job['status'] = 'finished'
        job['progress'] = 100 if source_ids else 0
        save_bulk_rejudge_job(job_id, job)

    return ranking_bulk_rejudge
