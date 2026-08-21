#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打榜赛 ELO 评分模式相关 Celery 任务。

设计：
  - 每份用户提交在数据库中持有自己的 ELO 评分；用户每次只在池中保留最近 2 份。
  - 全局 tick 任务（self-scheduling，30s 一跳）扫描所有 ELO 模式赛事，
    每个赛事每 elo_match_interval_seconds 调度 elo_max_pairs_per_round 对
    "对战次数较少 / 分数相近" 的提交进入对战队列（默认每个间隔 1 对）；
    冷却用 Redis 键（SET NX EX）抢占，避免多次 tick 在同一个间隔内重复调度。
  - 用户上传后立即触发 \"即时补战\"（默认 5 场，串行链式：每场打完、rating 更新
    之后，再用最新分数现挑下一对手），让新提交逐步收敛到合理分数段。
  - 单场对战由评测脚本判定：python <script> <submission_a_path> <submission_b_path> →
    stdout 一行 JSON {\"winner\": 0 | 1 | 2, \"details\": <可选>}；details 可沿用
    字符串/普通对象，也可显式输出 {\"format\": \"text|html\", \"content\": \"...\"}；
    winner=1/2 表示对应一方胜出，winner=0 表示平局（两份提交不分伯仲）。
    脚本中段失败则记录一条 winner=-1 的占位历史、不调整分数。

并发：
  - Tick 链路通过 Redis 中的 owner key 保证全局只有一条活动链；
    重启 Web 进程时若旧链 key 已过期会自动接管。
  - 单场结算用按 competition_id 划分的 Redis 锁串行化避免分数被覆盖。
"""

import json
import math
import os
import random
import subprocess
import sys
import time
import uuid

from oj_modules.infrastructure.redis import create_optional_redis_client
from oj_modules.ranking.db import (
    get_competition,
    get_last_elo_match_time,
    get_ranking_submission,
    list_active_elo_competitions,
    list_eligible_elo_submissions,
    record_elo_match,
    record_elo_match_locked,
)


ELO_MATCH_TASK_NAME = "oj.ranking_elo_match"
ELO_INITIAL_BURST_TASK_NAME = "oj.ranking_elo_initial_burst"
ELO_MATCHMAKER_TICK_TASK_NAME = "oj.ranking_elo_matchmaker_tick"

GLOBAL_TICK_INTERVAL_SECONDS = 30
DEFAULT_SCORING_SCRIPT_TIMEOUT_SECONDS = 120
DEFAULT_MATCH_LOCK_TTL_SECONDS = 240
MAX_PAIRS_PER_ROUND = 8       # 单赛事单 tick 最多调度的对子数（全局上限，防止管理员配置失误）
INITIAL_BURST_POLL_SECONDS = 15   # 即时补战串行链等待"上一场已结算"的轮询间隔
INITIAL_BURST_MAX_DEFERS = 40     # 单一轮等待的最多延期次数（≈ 10 分钟），防止脚本卡死时无限轮询


def _match_lock_ttl(timeout_seconds):
    """锁 TTL 至少要覆盖脚本最大可能运行时间，并留点余量。"""
    return max(DEFAULT_MATCH_LOCK_TTL_SECONDS, int(timeout_seconds) * 2 + 60)

TICK_OWNER_KEY = "ranking:elo:tick_owner"
COMPETITION_LOCK_KEY_FMT = "ranking:elo:comp_lock:{competition_id}"
# tick 调度对战时占用的冷却键。TTL = elo_match_interval_seconds，
# 保证一个间隔内只调度一场（下面 matchmaker tick 用 SET NX EX 抢占该键）。
TICK_COOLDOWN_KEY_FMT = "ranking:elo:tick_cooldown:{competition_id}"


def _redis_client():
    return create_optional_redis_client(verify_connection=False)


# ---------- ELO math ----------

def _expected_score(rating_a, rating_b):
    return 1.0 / (1.0 + 10.0 ** ((rating_b - rating_a) / 400.0))


def _new_ratings(rating_a, rating_b, winner, k):
    """winner ∈ {0, 1, 2}：0 = 平局（双方各得 0.5），1 = A 胜，2 = B 胜。
    传入其它值视为平局以免触发分数突变。"""
    w = int(winner)
    if w == 1:
        s_a = 1.0
    elif w == 2:
        s_a = 0.0
    else:
        s_a = 0.5
    e_a = _expected_score(rating_a, rating_b)
    return (
        rating_a + k * (s_a - e_a),
        rating_b + k * ((1.0 - s_a) - (1.0 - e_a)),
    )


# ---------- Pair selection ----------

def _pick_partner(eligibles, anchor):
    """从 eligibles 中给 anchor 挑一个搭档。
    候选先按 (|rating 差|, match_count) 排序，再从前 max(3, ceil(10% * 候选数))
    名中随机抽，避免在大池子里总是匹配几乎相同的几个对手。"""
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
    n = len(candidates)
    top_k = max(3, math.ceil(n / 10))
    top = candidates[: min(top_k, n)]
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
    """运行 ELO 评分脚本，返回 (winner∈{0,1,2}, details_obj_or_str)。
    winner=1/2 表示一方胜出，winner=0 表示平局。
    details 可为兼容格式，也可为 {"format": "text|html", "content": "..."}；
    HTML 的隔离与网络权限由对战详情页负责，不在 worker 中改写内容。
    脚本端不允许返回 -1（-1 由后端在脚本异常时落盘，作为"评测失败"占位）。
    其他取值或脚本本身报错都会抛 RuntimeError。"""
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
    if winner_int not in (0, 1, 2):
        raise RuntimeError(f"评测脚本返回的 winner 非法（应为 0=平局 / 1 / 2）：{winner!r}")
    return winner_int, parsed.get('details')


# ---------- Match task ----------

# ELO 分数写回用的短锁：只串行化“读分→算分→写回”这一小段（毫秒级），
# 评测脚本本身在锁外并行运行，让一轮里多场对战可以完全并行。
RATING_WRITE_LOCK_TTL_SECONDS = 30
RATING_WRITE_LOCK_MAX_WAIT_SECONDS = 25


def _acquire_rating_write_lock(rds, key):
    """自旋抢占短写锁（写回极快、竞争极低）。返回 token（成功）或 None
    （Redis 不可用或等待超时——退化为不加锁写回；这种情况极罕见且影响有限，
    远好于此前“评测脚本全程串行”导致的卡顿）。"""
    if rds is None:
        return None
    token = uuid.uuid4().hex
    waited = 0.0
    while waited < RATING_WRITE_LOCK_MAX_WAIT_SECONDS:
        try:
            if rds.set(key, token, nx=True, ex=RATING_WRITE_LOCK_TTL_SECONDS):
                return token
        except Exception:
            return None
        time.sleep(0.05)
        waited += 0.05
    return None


def _release_rating_write_lock(rds, key, token):
    if rds is None or not token:
        return
    try:
        rds.eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] "
            "then return redis.call('del', KEYS[1]) else return 0 end",
            1, key, token,
        )
    except Exception:
        pass


def register_ranking_elo_match_task(celery_app):
    @celery_app.task(name=ELO_MATCH_TASK_NAME, bind=True)
    def evaluate_ranking_elo_match(self, competition_id, submission_a_id, submission_b_id):
        competition_id = int(competition_id)
        submission_a_id = int(submission_a_id)
        submission_b_id = int(submission_b_id)

        # ===== 校验（无锁，多场对战完全并行）=====
        comp = get_competition(competition_id)
        if not comp or str(comp.get('scoring_mode') or '').lower() != 'elo':
            return {'success': False, 'message': '不是 ELO 模式'}
        if int(comp.get('elo_running') or 0) != 1:
            # 管理员已停止 / 重置：丢弃这场对战，不写入历史
            return {'success': False, 'message': '动态评分已停止'}
        script = (comp.get('scoring_script_path') or '').strip()
        if not script or not os.path.isfile(script):
            return {'success': False, 'message': '评测脚本缺失'}
        sub_a = get_ranking_submission(submission_a_id)
        sub_b = get_ranking_submission(submission_b_id)
        if not sub_a or not sub_b:
            return {'success': False, 'message': '提交不存在'}
        if sub_a.get('competition_id') != competition_id or sub_b.get('competition_id') != competition_id:
            return {'success': False, 'message': '提交不属于此比赛'}
        if sub_a.get('username') == sub_b.get('username'):
            return {'success': False, 'message': '同一用户提交不应对战'}
        archive_a = sub_a.get('code_path') or ''
        archive_b = sub_b.get('code_path') or ''
        if not (archive_a and os.path.isfile(archive_a) and archive_b and os.path.isfile(archive_b)):
            return {'success': False, 'message': '作品压缩包缺失'}

        initial_rating = float(comp.get('elo_initial_rating') or 1500)
        k = float(comp.get('elo_k_factor') or 32)
        script_timeout = int(comp.get('scoring_script_timeout_seconds') or DEFAULT_SCORING_SCRIPT_TIMEOUT_SECONDS)

        # ===== 运行评测脚本（无锁，多场对战完全并行）=====
        try:
            winner, details = _run_scoring_script(script, archive_a, archive_b, timeout_seconds=script_timeout)
        except Exception as e:
            # 脚本异常：落一条 winner=-1 占位行、不调分（仅插入历史，不存在分数竞争，无需串行）
            rating_a = float(sub_a.get('elo_rating') if sub_a.get('elo_rating') is not None else initial_rating)
            rating_b = float(sub_b.get('elo_rating') if sub_b.get('elo_rating') is not None else initial_rating)
            record_elo_match(
                competition_id, submission_a_id, submission_b_id, -1,
                rating_a, rating_b, rating_a, rating_b,
                details=None, error_message=str(e)[:1500],
            )
            return {'success': False, 'message': f'评测脚本异常：{e}'}

        # ===== 仅“读分→算分→写回”串行（短锁；锁内重读最新分数，避免并行脏写覆盖）=====
        rds = _redis_client()
        lock_key = COMPETITION_LOCK_KEY_FMT.format(competition_id=competition_id)
        token = _acquire_rating_write_lock(rds, lock_key)
        try:
            # 正确性由 DB 行级 FOR UPDATE 保证：即便没拿到 Redis 写锁（Redis 抖动/抢锁超时），
            # 也在事务内重读最新分数再算分写回，不会与并发对战互相覆盖（丢更新）。
            rating_a, rating_b, new_a, new_b = record_elo_match_locked(
                competition_id, submission_a_id, submission_b_id, winner,
                initial_rating, lambda ra, rb: _new_ratings(ra, rb, winner, k),
                details=details,
            )
        finally:
            _release_rating_write_lock(rds, lock_key, token)

        return {
            'success': True,
            'winner': winner,
            'rating_a_before': rating_a, 'rating_a_after': new_a,
            'rating_b_before': rating_b, 'rating_b_after': new_b,
        }

    return evaluate_ranking_elo_match


# ---------- Initial burst (immediate after submit) ----------

def register_ranking_elo_initial_burst_task(celery_app, match_task):
    @celery_app.task(name=ELO_INITIAL_BURST_TASK_NAME, bind=True)
    def ranking_elo_initial_burst(self, competition_id, submission_id,
                                  remaining=None, last_count=None, defers=0):
        """并行版即时补战：新提交进池后，一次性给它安排 elo_initial_burst 场对战，
        全部并行调度，不再一场一场等上一场结算。

        对战本身在 worker 池上并行执行，ELO 分数写回由短锁串行（见
        evaluate_ranking_elo_match：锁内重读最新分数），所以并行安全——锚点分数会
        随各场陆续结算被后续写回逐步收敛。

        参数 remaining/last_count/defers 仅为兼容旧的串行链式调用签名而保留；本实现
        不再自我重排，直接一次性把全部补战排进队列。
        """
        competition_id = int(competition_id)
        submission_id = int(submission_id)
        comp = get_competition(competition_id)
        if not comp or str(comp.get('scoring_mode') or '').lower() != 'elo':
            return {'success': False, 'message': '不是 ELO 模式'}
        if int(comp.get('elo_running') or 0) != 1:
            return {'success': False, 'message': '动态评分尚未启动'}
        script = (comp.get('scoring_script_path') or '').strip()
        if not script or not os.path.isfile(script):
            return {'success': False, 'message': '没有评测脚本'}

        n = int(remaining) if remaining is not None else int(comp.get('elo_initial_burst') or 5)
        n = max(0, n)
        if n <= 0:
            return {'success': True, 'completed': True, 'scheduled': 0}

        anchor = get_ranking_submission(submission_id)
        if not anchor or anchor.get('elo_in_pool') != 1:
            return {'success': False, 'message': '该提交不在 ELO 池中'}

        pool = list_eligible_elo_submissions(
            competition_id, int(comp.get('elo_max_matches') or 200)
        )
        pool = [
            s for s in pool
            if int(s['id']) != submission_id and s['username'] != anchor['username']
        ]
        if not pool:
            return {'success': True, 'scheduled': 0, 'reason': 'pool empty'}

        # 一次性挑 n 个不同的对手并行调度（每个都在锚点当前分附近、带随机性）
        scheduled = 0
        seen_ids = set()
        for _ in range(n):
            candidates = [s for s in pool if int(s['id']) not in seen_ids]
            if not candidates:
                break
            partner = _pick_partner(candidates, anchor)
            if partner is None:
                break
            seen_ids.add(int(partner['id']))
            try:
                match_task.apply_async(
                    args=[competition_id, submission_id, int(partner['id'])],
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
                comp_id = int(comp['id'])

                # 一个间隔内只调度一场：在调度时就 SET NX EX=interval 抢冷却键。
                # 拿不到键直接跳过；Redis 不可用时退回 DB 时间戳判断（精度差点但不会卡死）。
                cooldown_key = TICK_COOLDOWN_KEY_FMT.format(competition_id=comp_id)
                cooldown_ok = None  # None=Redis 不可用; True=本 tick 抢到; False=还在冷却
                if rds is not None:
                    try:
                        cooldown_ok = bool(rds.set(cooldown_key, "1", ex=interval, nx=True))
                    except Exception:
                        cooldown_ok = None
                if cooldown_ok is False:
                    continue
                if cooldown_ok is None:
                    last_at = get_last_elo_match_time(comp_id)
                    if last_at is not None:
                        try:
                            last_ts = last_at.timestamp()
                        except Exception:
                            last_ts = 0
                        if now_ts - last_ts < interval:
                            continue

                def _release_cooldown():
                    if cooldown_ok and rds is not None:
                        try:
                            rds.delete(cooldown_key)
                        except Exception:
                            pass

                eligibles = list_eligible_elo_submissions(
                    comp_id, int(comp.get('elo_max_matches') or 200)
                )
                if len(eligibles) < 2:
                    _release_cooldown()
                    continue

                # 本轮要调度的对子数：取 (赛事配置, 全局上限, 池规模/2) 三者最小，至少 1。
                comp_max_pairs = int(comp.get('elo_max_pairs_per_round') or 1)
                n_pairs = min(
                    max(1, comp_max_pairs),
                    MAX_PAIRS_PER_ROUND,
                    max(1, len(eligibles) // 2),
                )
                seen_ids = set()
                scheduled_any = False
                for _ in range(n_pairs):
                    pool = [s for s in eligibles if int(s['id']) not in seen_ids]
                    if len(pool) < 2:
                        pool = eligibles  # 池小于 n_pairs * 2 时允许复用
                    pair = _pick_pair(pool)
                    if pair is None:
                        break
                    a, b = pair
                    seen_ids.add(int(a['id']))
                    seen_ids.add(int(b['id']))
                    try:
                        match_task.apply_async(args=[comp_id, int(a['id']), int(b['id'])])
                        scheduled_any = True
                    except Exception:
                        pass
                if not scheduled_any:
                    _release_cooldown()
        finally:
            try:
                self.apply_async(args=[owner_id], countdown=GLOBAL_TICK_INTERVAL_SECONDS)
            except Exception:
                pass
        return {'success': True}

    return ranking_elo_matchmaker_tick


def seed_elo_matchmaker_tick(redis_client, tick_task, *, reset_owner=False):
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
        if reset_owner:
            redis_client.delete(TICK_OWNER_KEY)
        new_owner = uuid.uuid4().hex
        if redis_client.set(
            TICK_OWNER_KEY, new_owner,
            ex=GLOBAL_TICK_INTERVAL_SECONDS * 5, nx=True,
        ):
            tick_task.apply_async(args=[new_owner], countdown=10)
    except Exception:
        pass
