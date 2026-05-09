#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打榜赛 ELO 评分模式相关 Celery 任务。

设计：
  - 每份用户提交在数据库中持有自己的 ELO 评分；用户每次只在池中保留最近 2 份。
  - 全局 tick 任务（self-scheduling，30s 一跳）扫描所有 ELO 模式赛事，
    挑选若干对 \"对战次数较少 / 分数相近\" 的提交配对进入对战队列。
  - 用户上传后立即调度一轮 \"初始爆发\"（默认 5 场）让其与池中已有提交快速对战。
  - 单场对战由评测脚本判定：python <script> <answer_a_path> <answer_b_path> →
    stdout 一行 JSON {\"winner\": 1 | 2, \"details\": <可选>}；
    脚本中段失败则记录错误、不调整分数。

并发：
  - Tick 链路通过 Redis 中的 owner key 保证全局只有一条活动链；
    重启 Web 进程时若旧链 key 已过期会自动接管。
  - 单场结算用按 competition_id 划分的 Redis 锁串行化避免分数被覆盖。
"""

import json
import os
import random
import subprocess
import sys
import time
import uuid

try:
    import redis as _redis
except Exception:  # pragma: no cover
    _redis = None

from config import REDIS_DB, REDIS_HOST, REDIS_PORT
from oj_modules.ranking_db import (
    get_competition,
    get_last_elo_match_time,
    get_ranking_submission,
    list_active_elo_competitions,
    list_eligible_elo_submissions,
    record_elo_match,
)


ELO_MATCH_TASK_NAME = "oj.ranking_elo_match"
ELO_INITIAL_BURST_TASK_NAME = "oj.ranking_elo_initial_burst"
ELO_MATCHMAKER_TICK_TASK_NAME = "oj.ranking_elo_matchmaker_tick"

GLOBAL_TICK_INTERVAL_SECONDS = 30
DEFAULT_SCORING_SCRIPT_TIMEOUT_SECONDS = 120
DEFAULT_MATCH_LOCK_TTL_SECONDS = 240
MAX_PAIRS_PER_ROUND = 8


def _match_lock_ttl(timeout_seconds):
    """锁 TTL 至少要覆盖脚本最大可能运行时间，并留点余量。"""
    return max(DEFAULT_MATCH_LOCK_TTL_SECONDS, int(timeout_seconds) * 2 + 60)

TICK_OWNER_KEY = "ranking:elo:tick_owner"
COMPETITION_LOCK_KEY_FMT = "ranking:elo:comp_lock:{competition_id}"


def _redis_client():
    if _redis is None:
        return None
    try:
        return _redis.StrictRedis(
            host=REDIS_HOST, port=int(REDIS_PORT), db=int(REDIS_DB),
            decode_responses=True,
        )
    except Exception:
        return None


# ---------- ELO math ----------

def _expected_score(rating_a, rating_b):
    return 1.0 / (1.0 + 10.0 ** ((rating_b - rating_a) / 400.0))


def _new_ratings(rating_a, rating_b, winner, k):
    e_a = _expected_score(rating_a, rating_b)
    s_a = 1.0 if int(winner) == 1 else 0.0
    return (
        rating_a + k * (s_a - e_a),
        rating_b + k * ((1.0 - s_a) - (1.0 - e_a)),
    )


# ---------- Pair selection ----------

def _pick_partner(eligibles, anchor):
    """从 eligibles 中给 anchor 挑一个搭档。"""
    candidates = [
        s for s in eligibles
        if int(s['id']) != int(anchor['id']) and s['username'] != anchor['username']
    ]
    if not candidates:
        return None
    anchor_rating = float(anchor.get('elo_rating') or 0)
    candidates.sort(key=lambda s: (
        abs(float(s.get('elo_rating') or 0) - anchor_rating),
        int(s.get('elo_match_count') or 0),
    ))
    top = candidates[: min(3, len(candidates))]
    return random.choice(top)


def _pick_pair(eligibles):
    """挑一对 (A, B)。锚点按对战次数倒数加权抽取（场次少的更易被选）。"""
    if len(eligibles) < 2:
        return None
    if len({s['username'] for s in eligibles}) < 2:
        return None
    weights = [1.0 / (int(s.get('elo_match_count') or 0) + 1) for s in eligibles]
    a = random.choices(eligibles, weights=weights, k=1)[0]
    b = _pick_partner(eligibles, a)
    if b is None:
        return None
    return a, b


# ---------- Scoring script ----------

def _run_scoring_script(script_path, path_a, path_b, timeout_seconds=None):
    """运行 ELO 评分脚本，返回 (winner∈{1,2}, details_obj_or_str)。失败抛 RuntimeError。"""
    timeout_s = int(timeout_seconds) if timeout_seconds else DEFAULT_SCORING_SCRIPT_TIMEOUT_SECONDS
    try:
        proc = subprocess.run(
            [sys.executable, script_path, path_a, path_b],
            capture_output=True, text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"评测脚本执行超时（>{timeout_s}s）")

    if proc.returncode != 0:
        stderr = (proc.stderr or '').strip()[-2000:]
        raise RuntimeError(f"评测脚本退出码 {proc.returncode}: {stderr}")

    stdout = (proc.stdout or '').strip()
    if not stdout:
        raise RuntimeError("评测脚本未输出任何内容")

    last_line = None
    for line in stdout.splitlines()[::-1]:
        line = line.strip()
        if line.startswith('{') and line.endswith('}'):
            last_line = line
            break
    if last_line is None:
        raise RuntimeError(f"评测脚本 stdout 不是合法 JSON：{stdout[-500:]}")

    try:
        parsed = json.loads(last_line)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"评测脚本输出 JSON 解析失败：{e}")

    winner = parsed.get('winner')
    try:
        winner_int = int(winner)
    except (TypeError, ValueError):
        winner_int = None
    if winner_int not in (1, 2):
        raise RuntimeError(f"评测脚本返回的 winner 非法（应为 1 或 2）：{winner!r}")
    return winner_int, parsed.get('details')


# ---------- Match task ----------

def register_ranking_elo_match_task(celery_app):
    @celery_app.task(name=ELO_MATCH_TASK_NAME, bind=True)
    def evaluate_ranking_elo_match(self, competition_id, submission_a_id, submission_b_id):
        rds = _redis_client()
        lock_key = COMPETITION_LOCK_KEY_FMT.format(competition_id=int(competition_id))
        # 锁 TTL 在拿到 competition 之前先用一个保守值；之后实际读到 timeout 后通常足够覆盖
        if rds is not None:
            if not rds.set(lock_key, "1", ex=DEFAULT_MATCH_LOCK_TTL_SECONDS, nx=True):
                # 锁未拿到，稍后重排
                try:
                    self.apply_async(
                        args=[int(competition_id), int(submission_a_id), int(submission_b_id)],
                        countdown=3,
                    )
                except Exception:
                    pass
                return {'success': False, 'requeued': True}
        try:
            comp = get_competition(int(competition_id))
            if not comp or str(comp.get('scoring_mode') or '').lower() != 'elo':
                return {'success': False, 'message': '不是 ELO 模式'}
            if int(comp.get('elo_running') or 0) != 1:
                # 管理员已停止 / 重置：丢弃这场对战，不写入历史
                return {'success': False, 'message': '动态评分已停止'}
            script = (comp.get('scoring_script_path') or '').strip()
            if not script or not os.path.isfile(script):
                return {'success': False, 'message': '评测脚本缺失'}
            sub_a = get_ranking_submission(int(submission_a_id))
            sub_b = get_ranking_submission(int(submission_b_id))
            if not sub_a or not sub_b:
                return {'success': False, 'message': '提交不存在'}
            if sub_a.get('competition_id') != int(competition_id) or sub_b.get('competition_id') != int(competition_id):
                return {'success': False, 'message': '提交不属于此比赛'}
            if sub_a.get('username') == sub_b.get('username'):
                return {'success': False, 'message': '同一用户提交不应对战'}
            answer_a = sub_a.get('answer_path') or ''
            answer_b = sub_b.get('answer_path') or ''
            if not (answer_a and os.path.isfile(answer_a) and answer_b and os.path.isfile(answer_b)):
                return {'success': False, 'message': '答案文件缺失'}

            initial_rating = float(comp.get('elo_initial_rating') or 1500)
            rating_a = float(sub_a.get('elo_rating') if sub_a.get('elo_rating') is not None else initial_rating)
            rating_b = float(sub_b.get('elo_rating') if sub_b.get('elo_rating') is not None else initial_rating)
            script_timeout = int(comp.get('scoring_script_timeout_seconds') or DEFAULT_SCORING_SCRIPT_TIMEOUT_SECONDS)
            # 若用户设置的超时较长，重新延长一下锁 TTL，避免锁过期后并行重叠
            if rds is not None:
                try:
                    rds.expire(lock_key, _match_lock_ttl(script_timeout))
                except Exception:
                    pass

            try:
                winner, details = _run_scoring_script(script, answer_a, answer_b, timeout_seconds=script_timeout)
            except Exception as e:
                # 失败也记录一条对战，但不调整分数（winner=0）
                record_elo_match(
                    int(competition_id), int(submission_a_id), int(submission_b_id), 0,
                    rating_a, rating_b, rating_a, rating_b,
                    details=None, error_message=str(e)[:1500],
                )
                return {'success': False, 'message': f'评测脚本异常：{e}'}

            k = float(comp.get('elo_k_factor') or 32)
            new_a, new_b = _new_ratings(rating_a, rating_b, winner, k)
            record_elo_match(
                int(competition_id), int(submission_a_id), int(submission_b_id), winner,
                rating_a, rating_b, new_a, new_b, details=details,
            )
            return {
                'success': True,
                'winner': winner,
                'rating_a_before': rating_a, 'rating_a_after': new_a,
                'rating_b_before': rating_b, 'rating_b_after': new_b,
            }
        finally:
            if rds is not None:
                try:
                    rds.delete(lock_key)
                except Exception:
                    pass

    return evaluate_ranking_elo_match


# ---------- Initial burst (immediate after submit) ----------

def register_ranking_elo_initial_burst_task(celery_app, match_task):
    @celery_app.task(name=ELO_INITIAL_BURST_TASK_NAME, bind=True)
    def ranking_elo_initial_burst(self, competition_id, submission_id):
        comp = get_competition(int(competition_id))
        if not comp or str(comp.get('scoring_mode') or '').lower() != 'elo':
            return {'success': False, 'message': '不是 ELO 模式'}
        if int(comp.get('elo_running') or 0) != 1:
            return {'success': False, 'message': '动态评分尚未启动'}
        if not (comp.get('scoring_script_path') or '').strip():
            return {'success': False, 'message': '没有评测脚本'}
        burst = max(0, int(comp.get('elo_initial_burst') or 5))
        if burst == 0:
            return {'success': True, 'scheduled': 0}
        anchor = get_ranking_submission(int(submission_id))
        if not anchor or anchor.get('elo_in_pool') != 1:
            return {'success': False, 'message': '该提交不在 ELO 池中'}
        pool = list_eligible_elo_submissions(
            int(competition_id), int(comp.get('elo_max_matches') or 200)
        )
        pool = [
            s for s in pool
            if int(s['id']) != int(submission_id) and s['username'] != anchor['username']
        ]
        if not pool:
            return {'success': True, 'scheduled': 0}

        scheduled = 0
        used_ids = set()
        for _ in range(burst):
            available = [s for s in pool if int(s['id']) not in used_ids]
            if not available:
                # 池小于 burst 数：允许复用
                available = pool
            partner = _pick_partner(available, anchor)
            if partner is None:
                break
            used_ids.add(int(partner['id']))
            try:
                match_task.apply_async(
                    args=[int(competition_id), int(submission_id), int(partner['id'])],
                    countdown=2 + scheduled,  # 错开几秒避免锁竞争
                )
                scheduled += 1
            except Exception:
                pass
        return {'success': True, 'scheduled': scheduled}

    return ranking_elo_initial_burst


# ---------- Periodic matchmaker tick ----------

def register_ranking_elo_matchmaker_tick_task(celery_app, match_task):
    @celery_app.task(name=ELO_MATCHMAKER_TICK_TASK_NAME, bind=True)
    def ranking_elo_matchmaker_tick(self, owner_id):
        rds = _redis_client()
        # 单链路所有权检查：避免重启后多条 tick 链并行
        if rds is not None:
            try:
                current = rds.get(TICK_OWNER_KEY)
                if current is None:
                    rds.set(TICK_OWNER_KEY, owner_id, ex=GLOBAL_TICK_INTERVAL_SECONDS * 5)
                elif current != owner_id:
                    return {'success': True, 'reason': 'not the active tick owner'}
                else:
                    rds.set(TICK_OWNER_KEY, owner_id, ex=GLOBAL_TICK_INTERVAL_SECONDS * 5)
            except Exception:
                pass
        try:
            now_ts = time.time()
            for comp in list_active_elo_competitions():
                interval = max(5, int(comp.get('elo_match_interval_seconds') or 60))
                last_at = get_last_elo_match_time(int(comp['id']))
                if last_at is not None:
                    try:
                        last_ts = last_at.timestamp()
                    except Exception:
                        last_ts = 0
                    if now_ts - last_ts < interval:
                        continue
                eligibles = list_eligible_elo_submissions(
                    int(comp['id']), int(comp.get('elo_max_matches') or 200)
                )
                if len(eligibles) < 2:
                    continue
                n_pairs = max(1, min(MAX_PAIRS_PER_ROUND, len(eligibles) // 2))
                seen_ids = set()
                for _ in range(n_pairs):
                    pool = [s for s in eligibles if int(s['id']) not in seen_ids]
                    if len(pool) < 2:
                        pool = eligibles  # 允许复用，但通常不会到这一步
                    pair = _pick_pair(pool)
                    if pair is None:
                        break
                    a, b = pair
                    seen_ids.add(int(a['id']))
                    seen_ids.add(int(b['id']))
                    try:
                        match_task.apply_async(
                            args=[int(comp['id']), int(a['id']), int(b['id'])]
                        )
                    except Exception:
                        pass
        finally:
            try:
                self.apply_async(args=[owner_id], countdown=GLOBAL_TICK_INTERVAL_SECONDS)
            except Exception:
                pass
        return {'success': True}

    return ranking_elo_matchmaker_tick


def seed_elo_matchmaker_tick(redis_client, tick_task):
    """启动一条全局唯一的 tick 链。多次/多进程调用安全：靠 Redis owner key 上锁。"""
    if tick_task is None:
        return
    if redis_client is None:
        # 没有 Redis 时直接调度（开发环境可能出现重复链，可接受）
        try:
            tick_task.apply_async(args=[uuid.uuid4().hex], countdown=10)
        except Exception:
            pass
        return
    try:
        new_owner = uuid.uuid4().hex
        if redis_client.set(
            TICK_OWNER_KEY, new_owner,
            ex=GLOBAL_TICK_INTERVAL_SECONDS * 5, nx=True,
        ):
            tick_task.apply_async(args=[new_owner], countdown=10)
    except Exception:
        pass
