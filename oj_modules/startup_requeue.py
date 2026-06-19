#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进程启动时重新入队历史 pending 任务，并周期性回收卡住的 pending。

两个 app supervisor 进程（web / celery）重启后，Celery 队列里原本累积的任务
会丢失，导致数据库里仍处于“排队中 / 评测中”的提交永远卡住。本模块在 web 进程启动
时扫描 MySQL，把这些未完成的提交重新发回 Celery 队列。

只应在 web 进程启动时调用一次（见 oj.py 的 __main__ 守卫），不要在 Celery worker
里运行；任何异常都不会向外抛出——重新入队失败绝不能阻止 web 进程启动。

注意：清僵尸锁 + 重跑 Running 的前提是“所有 worker 都已死亡”（标准部署流程会同时
重启两个 app supervisor）。若只重启 web 进程而 Celery worker 仍在评测，理论上可能对某条
正在评测的 Running 提交造成重复评测；现行部署流程不会出现这种情况。
"""

import json
import uuid
from datetime import datetime

try:
    import redis
except Exception:
    redis = None

from config import REDIS_DB, REDIS_HOST, REDIS_PORT
from oj_modules.db_services import (
    get_incomplete_submissions,
    update_submission_status,
)
from oj_modules.ranking_db import (
    begin_agent_judge_attempt,
    get_incomplete_ranking_submissions,
    init_submission_elo_state,
    set_agent_judge_task_id,
)
from oj_modules.tasks.evaluate_tasks import clear_submission_lock, has_submission_lock
from oj_modules.tasks.ranking_agent_judge_tasks import (
    clear_all_judge_slots,
    clear_judge_lock,
    is_completed_agent_judge_submission,
)


_STARTUP_REQUEUE_STAGGER_SECONDS = 1
_AGENT_JUDGE_RECOVERY_BASE_DELAY_SECONDS = 10
_AGENT_JUDGE_ORPHAN_REQUEUE_AFTER_SECONDS = 15 * 60
PENDING_REQUEUE_WATCHDOG_TASK_NAME = "oj.pending_requeue_watchdog"
_PENDING_REQUEUE_OWNER_KEY = "submission:pending_requeue:owner"
_PENDING_REQUEUE_SEED_LOCK_KEY = "submission:pending_requeue:seed_lock"
_PENDING_REQUEUE_RUN_LOCK_KEY = "submission:pending_requeue:run_lock"
_PENDING_REQUEUE_ITEM_KEY_FMT = "submission:{submission_id}:pending_requeue"
_RANKING_REQUEUE_ITEM_KEY_FMT = "ranking_submission:{submission_id}:pending_requeue"
_AGENT_JUDGE_STARTUP_GUARD_KEY = "ranking:agent_judge:startup_recovery_guard"
_AGENT_JUDGE_TASK_NAME = "oj.ranking_agent_judge"
_BROKER_PURGE_TASK_NAMES = {_AGENT_JUDGE_TASK_NAME, PENDING_REQUEUE_WATCHDOG_TASK_NAME}
_PENDING_REQUEUE_INTERVAL_SECONDS = 300
_PENDING_REQUEUE_OWNER_TTL_SECONDS = _PENDING_REQUEUE_INTERVAL_SECONDS * 3
_PENDING_REQUEUE_GRACE_SECONDS = 180
_PENDING_REQUEUE_ITEM_TTL_SECONDS = 600
_PENDING_REQUEUE_MAX_PER_TICK = 50
_AGENT_JUDGE_STARTUP_GUARD_SECONDS = 20 * 60


def _startup_countdown(index):
    """启动恢复任务错峰入队，避免大量 worker 同时打到 MySQL 连接池。"""
    return max(0, int(index or 0)) * _STARTUP_REQUEUE_STAGGER_SECONDS


def _agent_judge_recovery_countdown(index):
    """Agent 评测恢复任务稍后再投递，给新提交的即时任务保留队首优先级。"""
    return _AGENT_JUDGE_RECOVERY_BASE_DELAY_SECONDS + _startup_countdown(index)


def _redis_client():
    if redis is None:
        return None
    try:
        return redis.StrictRedis(
            host=REDIS_HOST,
            port=int(REDIS_PORT),
            db=int(REDIS_DB),
            decode_responses=True,
        )
    except Exception:
        return None


def _submission_age_seconds(row, now=None):
    timestamp = (row or {}).get('judge_heartbeat_at') or (row or {}).get('created_at')
    if not timestamp:
        return None
    if now is None:
        now = datetime.now()

    if isinstance(timestamp, datetime):
        value = timestamp
    else:
        text = str(timestamp).strip()
        value = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                value = datetime.strptime(text[:19], fmt)
                break
            except Exception:
                pass
        if value is None:
            return None

    try:
        return max(0, int((now - value).total_seconds()))
    except Exception:
        return None


def _old_enough_for_watchdog(row):
    age_seconds = _submission_age_seconds(row)
    return age_seconds is None or age_seconds >= _PENDING_REQUEUE_GRACE_SECONDS


def _claim_watchdog_requeue(redis_client, submission_id, *,
                            key_fmt=_PENDING_REQUEUE_ITEM_KEY_FMT):
    if redis_client is None:
        return True
    key = key_fmt.format(submission_id=int(submission_id))
    try:
        return bool(redis_client.set(key, "1", ex=_PENDING_REQUEUE_ITEM_TTL_SECONDS, nx=True))
    except Exception:
        return True


def _release_watchdog_requeue_claim(redis_client, submission_id, *,
                                    key_fmt=_PENDING_REQUEUE_ITEM_KEY_FMT):
    if redis_client is None:
        return
    key = key_fmt.format(submission_id=int(submission_id))
    try:
        redis_client.delete(key)
    except Exception:
        pass


def _decode_broker_message(raw):
    value = raw
    for _ in range(4):
        if isinstance(value, bytes):
            try:
                value = value.decode('utf-8')
            except Exception:
                return None
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except Exception:
                return None
            continue
        if isinstance(value, list) and value:
            value = value[0]
            continue
        break
    return value if isinstance(value, dict) else None


def _is_agent_judge_broker_message(raw):
    msg = _decode_broker_message(raw)
    if not msg:
        return False
    headers = msg.get('headers') or {}
    return headers.get('task') in _BROKER_PURGE_TASK_NAMES


def _broker_list_keys(redis_client):
    """返回 Redis broker 中所有 list 队列键，覆盖 Celery priority 子队列。"""
    if redis_client is None:
        return []
    keys = []
    try:
        for key in redis_client.scan_iter(count=500):
            try:
                if redis_client.type(key) == 'list':
                    keys.append(key)
            except Exception:
                continue
    except Exception as e:
        print(f"[StartupRequeue] 扫描 Redis broker list 键失败：{e}")
    return keys


def _purge_agent_judge_broker_messages(redis_client):
    """受控重启恢复前，丢弃 Redis broker 里的旧 Agent Judge retry/投递消息。

    DB 是 Agent Judge 的恢复源。重启时如果保留旧 Celery retry/ETA/unacked 消息，
    它们会和新 attempt 竞争，导致新入队任务被旧消息刷新/跳过。这里只精确删除
    `oj.ranking_agent_judge`，不清普通评测队列和 Celery backend。
    """
    if redis_client is None:
        return {'ready': 0, 'unacked': 0, 'claims': 0}

    removed_ready = 0
    removed_unacked = 0
    removed_claims = 0
    removed_ready_by_key = {}

    for queue_key in _broker_list_keys(redis_client):
        try:
            items = redis_client.lrange(queue_key, 0, -1)
            if not items:
                continue
            kept = []
            removed_for_key = 0
            for raw in items:
                if _is_agent_judge_broker_message(raw):
                    removed_for_key += 1
                    removed_ready += 1
                else:
                    kept.append(raw)
            if removed_for_key:
                pipe = redis_client.pipeline()
                pipe.delete(queue_key)
                if kept:
                    pipe.rpush(queue_key, *kept)
                pipe.execute()
                removed_ready_by_key[str(queue_key)] = removed_for_key
        except Exception as e:
            print(f"[StartupRequeue] 清理 broker 队列 {queue_key} 失败：{e}")

    try:
        pipe = redis_client.pipeline()
        for delivery_tag, raw in redis_client.hscan_iter('unacked', count=200):
            if not _is_agent_judge_broker_message(raw):
                continue
            pipe.hdel('unacked', delivery_tag)
            pipe.zrem('unacked_index', delivery_tag)
            removed_unacked += 1
        if removed_unacked:
            pipe.execute()
    except Exception as e:
        print(f"[StartupRequeue] 清理 judge unacked 队列失败：{e}")

    try:
        keys = list(redis_client.scan_iter(match='ranking_submission:*:pending_requeue', count=200))
        if keys:
            removed_claims = len(keys)
            redis_client.delete(*keys)
    except Exception as e:
        print(f"[StartupRequeue] 清理打榜赛重排抢占键失败：{e}")

    try:
        redis_client.setex(
            _AGENT_JUDGE_STARTUP_GUARD_KEY,
            _AGENT_JUDGE_STARTUP_GUARD_SECONDS,
            '1',
        )
    except Exception:
        pass

    if removed_ready or removed_unacked or removed_claims:
        print(
            f"[StartupRequeue] 清理旧 Agent Judge broker 消息："
            f"ready {removed_ready} 条，unacked {removed_unacked} 条，"
            f"requeue-claim {removed_claims} 条。"
        )
    return {
        'ready': removed_ready,
        'unacked': removed_unacked,
        'claims': removed_claims,
        'ready_by_key': removed_ready_by_key,
    }


def _active_agent_judge_submission_ids(redis_client):
    """从 Redis 幂等锁和端点槽位里收集仍在运行的 Agent 评测提交。"""
    if redis_client is None:
        return set()
    active_ids = set()
    try:
        for key in redis_client.scan_iter(match='ranking:judge:lock:*', count=200):
            parts = str(key or '').split(':')
            if len(parts) >= 4:
                try:
                    active_ids.add(int(parts[3]))
                except Exception:
                    pass
    except Exception:
        pass
    try:
        for key in redis_client.scan_iter(match='aj:ep:*:slot:*', count=200):
            try:
                value = redis_client.get(key)
            except Exception:
                value = None
            sid_text = str(value or '').split(':', 1)[0].strip()
            if sid_text:
                try:
                    active_ids.add(int(sid_text))
                except Exception:
                    pass
    except Exception:
        pass
    return active_ids


def _task_result_ready(task, task_id):
    """Celery backend 已有终态结果，说明这条 DB 记录不该继续停在 Queued/Judging。"""
    task_id = str(task_id or '').strip()
    if not task or not task_id:
        return False
    try:
        return bool(task.AsyncResult(task_id).ready())
    except Exception:
        return False


def _agent_judge_orphaned(row, active_submission_ids, agent_judge_task):
    """判断 Agent 评测记录是否已经没有对应的活任务。"""
    try:
        sub_id = int(row.get('id'))
    except Exception:
        return False
    if sub_id in active_submission_ids:
        return False

    age_seconds = _submission_age_seconds(row)
    if age_seconds is None or age_seconds < _AGENT_JUDGE_ORPHAN_REQUEUE_AFTER_SECONDS:
        return False

    if _task_result_ready(agent_judge_task, row.get('judge_task_id')):
        return True

    status = str(row.get('status') or '').strip()
    if status == 'Judging':
        return True
    if status == 'Queued' and not row.get('judge_task_id'):
        return True
    return False


def _enqueue_agent_judge_recovery(agent_judge_task, row, *, requeue_index):
    """在同一条 ranking_submissions 记录上刷新 attempt 并重新投递评测任务。"""
    if agent_judge_task is None:
        return False
    sub_id = row.get('id')
    if sub_id is None:
        return False

    attempt_id = begin_agent_judge_attempt(sub_id, status='Queued', reset_result=False)
    clear_judge_lock(sub_id)
    async_result = agent_judge_task.apply_async(
        args=[sub_id, attempt_id],
        countdown=_agent_judge_recovery_countdown(requeue_index),
    )
    set_agent_judge_task_id(sub_id, attempt_id, async_result.id)
    return True


def _requeue_stale_pending_submissions(evaluate_task, written_task, *, source):
    """周期性回收仍停在 Pending/Waiting 的提交。

    该守护任务用于兜底 MySQL/worker 短暂故障：任务如果失败后把提交留在 Pending，
    这里会重新发回 Celery。Running 只有在评测锁已不存在时才会回收，避免仍在运行
    的程序题或书面作业被重复执行。
    """
    redis_client = _redis_client()
    requeued = 0
    skipped_locked = 0
    skipped_young = 0
    skipped_claimed = 0

    try:
        rows = get_incomplete_submissions()
    except Exception as e:
        print(f"[PendingRequeue] 查询未完成提交失败：{e}")
        return 0

    for row in rows:
        if requeued >= _PENDING_REQUEUE_MAX_PER_TICK:
            break
        sub_id = row.get('id')
        if sub_id is None:
            continue
        status = str(row.get('status') or '').strip()
        problem_type = row.get('problem_type')

        if status in ('Pending', 'Waiting'):
            if not _old_enough_for_watchdog(row):
                skipped_young += 1
                continue
        elif status == 'Running':
            if has_submission_lock(sub_id):
                skipped_locked += 1
                continue
            try:
                clear_submission_lock(sub_id)
                update_submission_status(sub_id, 'Pending')
            except Exception as e:
                print(f"[PendingRequeue] 提交 #{sub_id} Running 回收失败：{e}")
                continue
        else:
            continue

        if not _claim_watchdog_requeue(redis_client, sub_id):
            skipped_claimed += 1
            continue

        task = written_task if int(problem_type or 0) == 2 else evaluate_task
        if task is None:
            _release_watchdog_requeue_claim(redis_client, sub_id)
            continue

        try:
            task.apply_async(args=[sub_id], countdown=_startup_countdown(requeued))
            requeued += 1
        except Exception as e:
            _release_watchdog_requeue_claim(redis_client, sub_id)
            print(f"[PendingRequeue] 提交 #{sub_id} 重新入队失败：{e}")

    if requeued or skipped_locked or skipped_young or skipped_claimed:
        print(
            f"[PendingRequeue] {source} 扫描完成：重新入队 {requeued} 条，"
            f"跳过活跃锁 {skipped_locked} 条，跳过新提交 {skipped_young} 条，"
            f"跳过已抢占 {skipped_claimed} 条。"
        )
    return requeued


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


def _requeue_ranking_submissions(ranking_task, elo_initial_burst_task, agent_judge_task=None):
    """重新入队卡在 'Judging' 的打榜赛提交。

    - 绝对分模式：直接 .delay() 给评测任务；
    - ELO 模式：正式带入对战池（init_submission_elo_state -> Active）并补发
      initial-burst；池中 Active 的提交由已重新 seed 的 matchmaker tick 接管。
    - Agent 评测模式：重新 .apply_async() 给 Agent 评测任务。
    """
    requeued = 0
    try:
        rows = get_incomplete_ranking_submissions()
    except Exception as e:
        print(f"[StartupRequeue] 查询未完成打榜赛提交失败：{e}")
        return 0

    # 启动时（约定所有 worker 已死）清掉残留的 agent 评测端点槽位僵尸键，给重排一个干净基线。
    try:
        _cleared = clear_all_judge_slots()
        if _cleared:
            print(f"[StartupRequeue] 清理残留 agent 评测端点槽位 {_cleared} 个。")
    except Exception:
        pass

    for row in rows:
        sub_id = row.get('id')
        competition_id = row.get('competition_id')
        scoring_mode = str(row.get('scoring_mode') or '').strip().lower()
        if sub_id is None:
            continue
        try:
            if scoring_mode == 'agent_judge':
                if agent_judge_task is not None:
                    if is_completed_agent_judge_submission(row):
                        continue
                    if _enqueue_agent_judge_recovery(
                        agent_judge_task, row, requeue_index=requeued,
                    ):
                        requeued += 1
            elif scoring_mode == 'elo':
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


def _requeue_orphaned_agent_judge_submissions(agent_judge_task):
    """周期性回收 DB 停在 Queued/Judging、但已没有活任务的 Agent 评测记录。"""
    if agent_judge_task is None:
        return 0

    redis_client = _redis_client()
    if redis_client is not None:
        try:
            if redis_client.exists(_AGENT_JUDGE_STARTUP_GUARD_KEY):
                return 0
        except Exception:
            pass
    active_submission_ids = _active_agent_judge_submission_ids(redis_client)
    requeued = 0
    skipped_active = 0
    skipped_claimed = 0

    try:
        rows = get_incomplete_ranking_submissions()
    except Exception as e:
        print(f"[PendingRequeue] 查询未完成打榜赛提交失败：{e}")
        return 0

    for row in rows:
        if requeued >= _PENDING_REQUEUE_MAX_PER_TICK:
            break
        if str(row.get('scoring_mode') or '').strip().lower() != 'agent_judge':
            continue
        sub_id = row.get('id')
        if sub_id is None:
            continue
        if is_completed_agent_judge_submission(row):
            continue
        if int(sub_id) in active_submission_ids:
            skipped_active += 1
            continue
        if not _agent_judge_orphaned(row, active_submission_ids, agent_judge_task):
            continue
        if not _claim_watchdog_requeue(
            redis_client,
            sub_id,
            key_fmt=_RANKING_REQUEUE_ITEM_KEY_FMT,
        ):
            skipped_claimed += 1
            continue

        try:
            if _enqueue_agent_judge_recovery(
                agent_judge_task, row, requeue_index=requeued,
            ):
                requeued += 1
            else:
                _release_watchdog_requeue_claim(
                    redis_client,
                    sub_id,
                    key_fmt=_RANKING_REQUEUE_ITEM_KEY_FMT,
                )
        except Exception as e:
            _release_watchdog_requeue_claim(
                redis_client,
                sub_id,
                key_fmt=_RANKING_REQUEUE_ITEM_KEY_FMT,
            )
            print(f"[PendingRequeue] 打榜赛 Agent 评测 #{sub_id} 重新入队失败：{e}")

    if requeued or skipped_active or skipped_claimed:
        print(
            f"[PendingRequeue] agent_judge 扫描完成：重新入队 {requeued} 条，"
            f"跳过活跃任务 {skipped_active} 条，跳过已抢占 {skipped_claimed} 条。"
        )
    return requeued


def requeue_pending_on_startup(*, evaluate_task, written_task,
                               ranking_task, elo_initial_burst_task, agent_judge_task=None):
    """启动时扫描 MySQL 并重新入队所有未完成任务（程序题 / 书面作业 / 打榜赛）。"""
    try:
        _purge_agent_judge_broker_messages(_redis_client())
        prog = _requeue_programming_submissions(evaluate_task, written_task)
        rank = _requeue_ranking_submissions(ranking_task, elo_initial_burst_task, agent_judge_task)
        print(
            f"[StartupRequeue] 启动重新入队完成："
            f"程序题/书面作业 {prog} 条，打榜赛 {rank} 条。"
        )
    except Exception as e:
        print(f"[StartupRequeue] 启动重新入队异常（已忽略，不影响启动）：{e}")


def register_pending_requeue_watchdog_task(celery_app, evaluate_task, written_task,
                                           agent_judge_task=None):
    """注册周期性 Pending 回收任务。

    不依赖 celery beat：任务运行结束前会自我调度下一跳，和 ELO matchmaker 一样用
    Redis owner key 保证全局只有一条活动链。
    """
    existing = celery_app.tasks.get(PENDING_REQUEUE_WATCHDOG_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(name=PENDING_REQUEUE_WATCHDOG_TASK_NAME, bind=True)
    def pending_requeue_watchdog(self, owner_id):
        redis_client = _redis_client()
        run_lock_acquired = False
        if redis_client is not None:
            try:
                current = redis_client.get(_PENDING_REQUEUE_OWNER_KEY)
                if current is None:
                    redis_client.set(
                        _PENDING_REQUEUE_OWNER_KEY,
                        owner_id,
                        ex=_PENDING_REQUEUE_OWNER_TTL_SECONDS,
                    )
                elif current != owner_id:
                    return {'success': True, 'reason': 'not the active pending requeue owner'}
                else:
                    redis_client.set(
                        _PENDING_REQUEUE_OWNER_KEY,
                        owner_id,
                        ex=_PENDING_REQUEUE_OWNER_TTL_SECONDS,
                    )
                run_lock_acquired = bool(redis_client.set(
                    _PENDING_REQUEUE_RUN_LOCK_KEY,
                    owner_id,
                    ex=max(60, _PENDING_REQUEUE_INTERVAL_SECONDS - 5),
                    nx=True,
                ))
                if not run_lock_acquired:
                    return {'success': True, 'reason': 'pending requeue already running'}
            except Exception:
                pass

        requeued = 0
        agent_requeued = 0
        try:
            requeued = _requeue_stale_pending_submissions(
                evaluate_task,
                written_task,
                source='watchdog',
            )
            agent_requeued = _requeue_orphaned_agent_judge_submissions(agent_judge_task)
        finally:
            try:
                self.apply_async(args=[owner_id], countdown=_PENDING_REQUEUE_INTERVAL_SECONDS)
            except Exception:
                pass
        return {
            'success': True,
            'requeued': requeued,
            'agent_judge_requeued': agent_requeued,
        }

    return pending_requeue_watchdog


def seed_pending_requeue_watchdog(redis_client, watchdog_task, *,
                                  reset_owner=False, countdown=30):
    """启动一条全局唯一的 Pending 回收链。多次/多进程调用安全。"""
    if watchdog_task is None:
        return
    try:
        if redis_client is None:
            owner_id = uuid.uuid4().hex
            watchdog_task.apply_async(args=[owner_id], countdown=countdown)
            return

        if reset_owner:
            owner_id = uuid.uuid4().hex
            try:
                redis_client.delete(_PENDING_REQUEUE_SEED_LOCK_KEY, _PENDING_REQUEUE_RUN_LOCK_KEY)
            except Exception:
                pass
            redis_client.set(
                _PENDING_REQUEUE_OWNER_KEY,
                owner_id,
                ex=_PENDING_REQUEUE_OWNER_TTL_SECONDS,
            )
            watchdog_task.apply_async(args=[owner_id], countdown=countdown)
            return

        if not redis_client.set(
            _PENDING_REQUEUE_SEED_LOCK_KEY,
            "1",
            ex=60,
            nx=True,
        ):
            return

        owner_id = redis_client.get(_PENDING_REQUEUE_OWNER_KEY)
        if owner_id:
            watchdog_task.apply_async(args=[owner_id], countdown=countdown)
            return

        new_owner_id = uuid.uuid4().hex
        if redis_client.set(
            _PENDING_REQUEUE_OWNER_KEY,
            new_owner_id,
            ex=_PENDING_REQUEUE_OWNER_TTL_SECONDS,
            nx=True,
        ):
            watchdog_task.apply_async(args=[new_owner_id], countdown=countdown)
    except Exception:
        pass
