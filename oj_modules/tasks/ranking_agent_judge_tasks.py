#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛 Agent-as-Judge 评测任务：起 Docker 容器跑 claude，tail result.jsonl 实时回传。"""
import json
import os
import random
import secrets
import shutil
import subprocess
import time
import zipfile

try:
    import redis as _redis
except Exception:  # pragma: no cover
    _redis = None

try:
    from celery.exceptions import MaxRetriesExceededError
except Exception:  # pragma: no cover
    class MaxRetriesExceededError(Exception):
        pass

import config as _cfg
from config import REDIS_DB, REDIS_HOST, REDIS_PORT
from oj_modules import ranking_agent_judge as aj
from oj_modules.ranking_db import (
    get_competition, get_ranking_submission, list_competition_files,
    set_submission_status, submission_dir, update_submission_result,
)
from oj_modules.ranking_agent_judge_db import (
    build_judge_snapshot, clear_judge_results, list_agent_judge_endpoints,
    list_competition_rules, list_judge_results, upsert_judge_result,
)

RANKING_AGENT_JUDGE_TASK_NAME = 'oj.ranking_agent_judge'

# 配置读取（用 getattr 回退，远端 config.py 无需改动）
JUDGE_IMAGE = getattr(_cfg, 'AGENT_JUDGE_DOCKER_IMAGE', 'numericaloj-agent-judge:latest')
JUDGE_WORKSPACE_ROOT = getattr(_cfg, 'AGENT_JUDGE_WORKSPACE_ROOT', 'ranking_uploads/judge_workspace')
JUDGE_DEFAULT_TIMEOUT = int(getattr(_cfg, 'AGENT_JUDGE_DEFAULT_TIMEOUT', 1800))
JUDGE_MEM_LIMIT = getattr(_cfg, 'AGENT_JUDGE_MEM_LIMIT', '4g')
JUDGE_CPU_LIMIT = str(getattr(_cfg, 'AGENT_JUDGE_CPU_LIMIT', '2'))
JUDGE_PIDS_LIMIT = str(getattr(_cfg, 'AGENT_JUDGE_PIDS_LIMIT', '512'))
JUDGE_POLL_INTERVAL = float(getattr(_cfg, 'AGENT_JUDGE_RESULT_POLL_INTERVAL', 1.5))
JUDGE_PROGRESS_TTL = int(getattr(_cfg, 'AGENT_JUDGE_PROGRESS_TTL', 21600))
# 多端点并发：未配置端点池时，回退用比赛单端点 + 这个默认并发上限（沿用旧 -c 2 的语义）。
JUDGE_LEGACY_CONCURRENCY = max(1, int(getattr(_cfg, 'AGENT_JUDGE_CONCURRENCY', 2)))
# 所有端点都满时，任务延迟重排（back-pressure）的基准秒数 + 上限重试次数 + 槽位 TTL 余量。
JUDGE_QUEUE_RETRY_BASE = max(2, int(getattr(_cfg, 'AGENT_JUDGE_QUEUE_RETRY_SECONDS', 8)))
JUDGE_MAX_QUEUE_RETRIES = max(1, int(getattr(_cfg, 'AGENT_JUDGE_MAX_QUEUE_RETRIES', 2000)))
JUDGE_SLOT_TTL_BUFFER = max(60, int(getattr(_cfg, 'AGENT_JUDGE_SLOT_TTL_BUFFER', 600)))

_judge_rds = None


def init_judge_progress_cache(redis_client):
    global _judge_rds
    _judge_rds = redis_client


def _ensure_judge_redis():
    global _judge_rds
    if _judge_rds is not None:
        return _judge_rds
    if _redis is None:
        return None
    try:
        _judge_rds = _redis.StrictRedis(host=REDIS_HOST, port=int(REDIS_PORT),
                                        db=int(REDIS_DB), decode_responses=True)
        _judge_rds.ping()
    except Exception:
        _judge_rds = None
    return _judge_rds


def _judge_progress_key(submission_id):
    return f'ranking_judge:{submission_id}'


def _judge_progress_channel(submission_id):
    return f'ranking_judge_events:{submission_id}'


def subscribe_judge_run_events(submission_id):
    client = _ensure_judge_redis()
    if client is None:
        return None
    try:
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(_judge_progress_channel(submission_id))
        return pubsub
    except Exception:
        return None


def get_judge_progress_snapshot(submission_id):
    client = _ensure_judge_redis()
    if client is not None:
        try:
            raw = client.get(_judge_progress_key(submission_id))
            if raw:
                data = json.loads(raw)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return build_judge_snapshot(submission_id)


def _publish_snapshot(submission_id):
    snap = build_judge_snapshot(submission_id)
    if snap is None:
        return None
    client = _ensure_judge_redis()
    if client is not None:
        try:
            payload = json.dumps(snap, ensure_ascii=False)
            client.setex(_judge_progress_key(submission_id), JUDGE_PROGRESS_TTL, payload)
            client.publish(_judge_progress_channel(submission_id), payload)
        except Exception:
            pass
    return snap


# ---------- 多端点选择与 Redis 槽位限流 ----------

def _resolve_endpoints(competition_id, competition=None):
    """返回该比赛**启用的**判题端点（dict: id, base_url, api_key, model, concurrency_limit）。
    要求至少配置一个启用端点；为空则返回 []（判题侧据此置 Error）。不再回退到旧的比赛单端点字段。"""
    try:
        eps = list_agent_judge_endpoints(competition_id, enabled_only=True)
    except Exception:
        eps = []
    return [{'id': e['id'], 'base_url': e['base_url'], 'api_key': e['api_key'],
             'model': e.get('model') or '',
             'concurrency_limit': max(1, int(e.get('concurrency_limit') or 1))}
            for e in eps]


def _slot_key(endpoint_id, i):
    return f'aj:ep:{endpoint_id}:slot:{i}'


_RELEASE_LUA = ("if redis.call('get', KEYS[1]) == ARGV[1] then "
                "return redis.call('del', KEYS[1]) else return 0 end")


def _acquire_endpoint_slot(client, endpoints, submission_id, ttl):
    """在某端点上抢一个并发槽位（Redis SET NX EX，crash 安全靠 TTL 自动释放）。
    返回 (endpoint, slot_key, token)；所有端点都满返回 (None, None, None)。
    Redis 不可用时 fail-open：返回第一个端点、slot_key=None（退化为仅受 celery -c 限制）。"""
    if not endpoints:
        return None, None, None
    if client is None:
        return endpoints[0], None, None
    order = list(endpoints)
    random.shuffle(order)                       # 打散，把负载摊到各端点
    token = f'{submission_id}:{secrets.token_hex(4)}'
    for ep in order:
        limit = max(1, int(ep.get('concurrency_limit') or 1))
        for i in range(limit):
            key = _slot_key(ep['id'], i)
            try:
                if client.set(key, token, nx=True, ex=int(ttl)):
                    return ep, key, token
            except Exception:
                return ep, None, None            # Redis 出错 → fail-open 用该端点
    return None, None, None


def _release_slot(client, slot_key, token):
    if client is None or not slot_key:
        return
    try:
        client.eval(_RELEASE_LUA, 1, slot_key, token)   # CAS 释放，避免误删他人槽位
    except Exception:
        pass


def clear_judge_lock(submission_id):
    """删除某提交的 agent 评测幂等锁。进程重启重排前调用：上次被杀的 worker 会留下
    僵尸锁（TTL 内有效），不清的话重排任务 set(nx) 失败、直接返回，提交会一直卡住。"""
    client = _ensure_judge_redis()
    if client is None:
        return
    try:
        client.delete(f'ranking:judge:lock:{int(submission_id)}')
    except Exception:
        pass


def clear_all_judge_slots():
    """删除所有端点并发槽位（aj:ep:*:slot:*）。进程启动时（按部署约定所有 worker 均已死）
    残留槽位都是僵尸，清掉以免新评测被假「满」挡住而反复重排。返回清理条数。"""
    client = _ensure_judge_redis()
    if client is None:
        return 0
    n = 0
    try:
        for key in client.scan_iter(match='aj:ep:*:slot:*', count=200):
            try:
                client.delete(key)
                n += 1
            except Exception:
                pass
    except Exception:
        pass
    return n


def _safe_extract_zip(zip_path, dest_dir):
    """安全解包 zip：跳过绝对路径/越界条目。"""
    os.makedirs(dest_dir, exist_ok=True)
    base = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = os.path.realpath(os.path.join(dest_dir, member))
            if target != base and not target.startswith(base + os.sep):
                continue
            zf.extract(member, dest_dir)


def _prepare_workspace(submission, competition, rules):
    """准备宿主工作目录，返回 (绝对路径, 随机结果文件名)。

    结果文件名随机生成，仅通过提示词/AJ_RESULT_FILE 告知评测 Agent；参赛者代码无法预先猜到该
    文件名，从而无法把伪造的 pass 结果写进去（防止刷满分）。不再把工作目录/结果文件改为 world-writable
    —— 容器内 root + 默认能力集（含 CAP_DAC_OVERRIDE）足以写宿主属主的挂载文件。"""
    sid = submission['id']
    ws = os.path.realpath(os.path.join(JUDGE_WORKSPACE_ROOT, str(sid)))
    if os.path.isdir(ws):
        shutil.rmtree(ws, ignore_errors=True)
    os.makedirs(ws, exist_ok=True)
    # 代码
    code_path = submission.get('code_path')
    sub_dir = os.path.join(ws, 'submission')
    os.makedirs(sub_dir, exist_ok=True)
    if code_path and os.path.isfile(code_path):
        try:
            _safe_extract_zip(code_path, sub_dir)
        except Exception:
            shutil.copy(code_path, os.path.join(sub_dir, os.path.basename(code_path)))
    # 描述
    with open(os.path.join(ws, 'description.md'), 'w', encoding='utf-8') as f:
        f.write(competition.get('description') or '')
    # 附件
    att_dir = os.path.join(ws, 'attachment')
    os.makedirs(att_dir, exist_ok=True)
    for fr in (list_competition_files(competition['id']) or []):
        sp = fr.get('stored_path')
        if sp and os.path.isfile(sp):
            try:
                shutil.copy(sp, os.path.join(att_dir, fr.get('filename') or os.path.basename(sp)))
            except Exception:
                pass
    # rules.json
    with open(os.path.join(ws, 'rules.json'), 'w', encoding='utf-8') as f:
        json.dump(aj.build_rules_json(rules), f, ensure_ascii=False, indent=2)
    # 随机结果文件名，预创建空文件（不放开 world 权限）
    result_name = f'result_{secrets.token_hex(16)}.jsonl'
    open(os.path.join(ws, result_name), 'w').close()
    return ws, result_name


def _dump_container_claude(container_name, ws):
    """容器回收前，把容器内 ~/.claude（claude 的会话/transcript 目录）docker cp 到宿主
    <ws>/submission/.claude，供事后归因。尽力而为：源不存在或 cp 失败都静默跳过，不影响判题。
    注意：docker cp 可作用于「已退出但未删除」的容器，这正是去掉 --rm 的原因。"""
    dest_dir = os.path.join(ws, 'submission')
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except Exception:
        return
    dest = os.path.join(dest_dir, '.claude')
    # 目标已存在先删，避免 docker cp 把 .claude 套进已有的 .claude/ 里。
    if os.path.exists(dest):
        shutil.rmtree(dest, ignore_errors=True)
    # 容器内 claude 家目录为 /root（镜像默认 root 用户）；保险再退一个 /workspace。
    for src in ('/root/.claude', '/workspace/.claude'):
        try:
            r = subprocess.run(['docker', 'cp', f'{container_name}:{src}', dest_dir],
                               capture_output=True, text=True, timeout=60)
            if r.returncode == 0 and os.path.isdir(dest):
                return
        except Exception:
            pass


def _run_container_and_tail(submission_id, ws, result_name, competition, rules, timeout_s,
                            endpoint=None):
    """起 docker 容器跑 claude，tail 随机结果文件，逐条 upsert + 广播。
    返回 (timed_out, container_ok)。可被集成测试整体 monkeypatch。
    容器回收前会把容器内 ~/.claude（会话/transcript）docker cp 到宿主 <ws>/submission/.claude，
    便于事后归因。endpoint：本次使用的模型端点（base_url/api_key/model）；为空时回退到比赛单端点字段。"""
    ep = endpoint or {}
    base_url = ep.get('base_url') or competition.get('agent_judge_base_url') or ''
    api_key = ep.get('api_key') or competition.get('agent_judge_api_key') or ''
    model = ep.get('model') or competition.get('agent_judge_model') or ''
    prompt = aj.build_prompt(competition.get('title'), result_name)
    container_name = f'aj_{submission_id}'
    # 同名残留容器（上次 worker 被杀留下的孤儿、或异常未清的旧容器）先强制清掉，否则下面
    # docker run 同名会冲突。去掉 --rm 后（容器退出不再自动删），这一步尤其必要。
    try:
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
    except Exception:
        pass
    docker_args = [
        # 不再用 --rm：容器退出后保留，给「回收前 docker cp 出 ~/.claude」留窗口；改由本函数
        # finally 中的 docker rm -f 统一回收（覆盖正常退出/超时/异常各路径）。
        'docker', 'run', '-d', '--name', container_name,
        # 注意：不可用 --cap-drop ALL —— 那会移除 CAP_DAC_OVERRIDE，导致容器内 root
        # 既无法写宿主属主(非 root)的挂载文件、也无法 apt 装包。
        # 用 Docker 默认能力集 + 非特权 + pids/内存/CPU 限制 + 仅挂载本提交工作目录做隔离。
        # no-new-privileges：禁止容器内进程通过 setuid 提权。
        '--security-opt', 'no-new-privileges',
        '--pids-limit', JUDGE_PIDS_LIMIT,
        '--memory', JUDGE_MEM_LIMIT, '--cpus', JUDGE_CPU_LIMIT,
        '-v', f'{ws}:/workspace', '-w', '/workspace',
        '-e', 'IS_SANDBOX=1',
        # 关闭 claude 的非必要外联（遥测/自动更新/错误上报），否则在受限容器内会卡住
        '-e', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1',
        '-e', 'DISABLE_TELEMETRY=1',
        '-e', 'DISABLE_AUTOUPDATER=1',
        '-e', 'DISABLE_ERROR_REPORTING=1',
        '-e', 'AJ_PROMPT',
        # report 命令据此写入随机结果文件名；参赛者代码无法预先猜到。
        '-e', f'AJ_RESULT_FILE=/workspace/{result_name}',
        '-e', f'ANTHROPIC_BASE_URL={base_url}',
        '-e', f'ANTHROPIC_AUTH_TOKEN={api_key}',
        '-e', f'ANTHROPIC_API_KEY={api_key}',
        '-e', f'ANTHROPIC_MODEL={model}',
        JUDGE_IMAGE,
        'bash', '-lc',
        'claude -p "$AJ_PROMPT" --dangerously-skip-permissions '
        '${ANTHROPIC_MODEL:+--model "$ANTHROPIC_MODEL"} --add-dir /workspace || true',
    ]
    run_env = dict(os.environ, AJ_PROMPT=prompt)
    try:
        subprocess.run(docker_args, check=True, capture_output=True, text=True,
                       env=run_env, timeout=120)
    except Exception:
        # 启动失败：清掉可能的半残同名容器后返回。
        try:
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
        except Exception:
            pass
        return (False, False)

    result_path = os.path.join(ws, result_name)
    rule_ids = {r['rule_id'] for r in rules}
    seen = set()
    start = time.time()
    timed_out = False
    try:
        while True:
            try:
                with open(result_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except Exception:
                lines = []
            for line in lines:
                parsed = aj.parse_result_line(line)
                if not parsed or parsed['rule_id'] not in rule_ids or parsed['rule_id'] in seen:
                    continue
                seen.add(parsed['rule_id'])
                raw = parsed['result']
                upsert_judge_result(submission_id, parsed['rule_id'], raw, raw,
                                    0.0, parsed['evidence'])
                _publish_snapshot(submission_id)
            try:
                running = subprocess.run(
                    ['docker', 'inspect', '-f', '{{.State.Running}}', container_name],
                    capture_output=True, text=True, timeout=15).stdout.strip()
            except Exception:
                running = 'false'
            if running != 'true':
                break
            if time.time() - start > timeout_s:
                timed_out = True
                try:
                    subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
                except Exception:
                    pass
                break
            time.sleep(JUDGE_POLL_INTERVAL)
    finally:
        # 回收容器前，先把容器内 ~/.claude 拉到宿主 submission 目录（事后归因），再统一回收。
        _dump_container_claude(container_name, ws)
        try:
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
        except Exception:
            pass
    return (timed_out, True)


def _finalize(submission_id, rules, timed_out, container_ok):
    """终态：拓扑重算 effective+score，回写 effective、提交分数与状态，广播 done。"""
    raw_rows = list_judge_results(submission_id)
    raw_by_id = {int(r['rule_id']): r.get('raw_result') for r in raw_rows
                 if r.get('raw_result') in (aj.RESULT_PASS, aj.RESULT_FAILED)}
    evidence_by_id = {int(r['rule_id']): (r.get('evidence') or '') for r in raw_rows}
    computed = aj.compute_results(rules, raw_by_id, finalize=True) if rules else {}
    for rid, c in computed.items():
        raw = raw_by_id.get(rid)
        upsert_judge_result(submission_id, rid, raw, c['effective'], c['score'],
                            evidence_by_id.get(rid, ''))
    total = aj.total_score(computed)
    maxs = aj.max_score(rules) if rules else 0.0
    if not container_ok and not raw_by_id:
        update_submission_result(submission_id, None, 'Error', grade_details=None,
                                 error_message='评测容器启动失败')
    elif not raw_by_id:
        # 容器跑了但没有任何规则结果上报：基本是模型端故障 / Agent 崩溃 / 超时未产出，
        # 判为 Error 而非 Accepted 0 分，避免在基础设施异常时把选手误判 0 分污染榜单（可重测）。
        update_submission_result(submission_id, None, 'Error', grade_details=None,
                                 error_message=('评测超时且未产出任何结果' if timed_out
                                                else '评测未产出任何结果（模型或 Agent 异常）'))
    else:
        details = {'total_score': total, 'max_score': maxs, 'timed_out': timed_out,
                   'rules': [{'rule_id': rid, 'effective': c['effective'], 'score': c['score']}
                             for rid, c in computed.items()]}
        update_submission_result(submission_id, total, 'Accepted', grade_details=details)
    _publish_snapshot(submission_id)


def _judge(submission_id, endpoint=None):
    submission = get_ranking_submission(submission_id)
    if not submission:
        return {'success': False, 'message': '提交不存在'}
    # 评测 worker 已取到本任务并开始执行 → 置「评测中」。在此之前（入队后、被取到前）提交为
    # 'Queued'（等待评测）。judge 队列 worker 并发上限为 2，故同时最多 2 个显示「评测中」，其余排队显示「等待评测」。
    set_submission_status(submission_id, 'Judging')
    competition = get_competition(submission.get('competition_id'))
    if not competition:
        update_submission_result(submission_id, None, 'Error', error_message='比赛不存在')
        return {'success': False, 'message': '比赛不存在'}
    rules = list_competition_rules(competition['id'])
    clear_judge_results(submission_id)
    _publish_snapshot(submission_id)
    if not rules:
        update_submission_result(submission_id, 0.0, 'Accepted',
                                 grade_details={'total_score': 0, 'max_score': 0,
                                                'note': '未配置评分规则'})
        _publish_snapshot(submission_id)
        return {'success': True, 'score': 0.0}
    timeout_s = int(competition.get('agent_judge_timeout_seconds') or JUDGE_DEFAULT_TIMEOUT)
    ws, result_name = _prepare_workspace(submission, competition, rules)
    timed_out, container_ok = _run_container_and_tail(
        submission_id, ws, result_name, competition, rules, timeout_s, endpoint)
    _finalize(submission_id, rules, timed_out, container_ok)
    return {'success': True}


def register_ranking_agent_judge_task(celery_app):
    @celery_app.task(name=RANKING_AGENT_JUDGE_TASK_NAME, bind=True)
    def evaluate_ranking_agent_judge(self, submission_id):
        sid = int(submission_id)
        client = _ensure_judge_redis()
        submission = get_ranking_submission(sid)
        if not submission:
            return {'success': False, 'message': '提交不存在'}
        competition = get_competition(submission.get('competition_id'))
        if not competition:
            update_submission_result(sid, None, 'Error', error_message='比赛不存在')
            _publish_snapshot(sid)
            return {'success': False, 'message': '比赛不存在'}

        # 选端点：优先端点池，回退比赛单端点；都没有则判 Error（避免无限重排）。
        endpoints = _resolve_endpoints(competition['id'], competition)
        if not endpoints:
            update_submission_result(sid, None, 'Error',
                                     error_message='未配置 Agent 评测端点（请在比赛设置里添加模型端点）')
            _publish_snapshot(sid)
            return {'success': False, 'message': '未配置评测端点'}

        # 抢端点并发槽位；全满 → 延迟重排（提交保持「等待评测」，不占用 worker）。
        ttl = int(competition.get('agent_judge_timeout_seconds') or JUDGE_DEFAULT_TIMEOUT) + JUDGE_SLOT_TTL_BUFFER
        ep, slot_key, slot_token = _acquire_endpoint_slot(client, endpoints, sid, ttl)
        if ep is None:
            countdown = JUDGE_QUEUE_RETRY_BASE + random.randint(0, JUDGE_QUEUE_RETRY_BASE)
            try:
                self.retry(countdown=countdown, max_retries=JUDGE_MAX_QUEUE_RETRIES)
            except MaxRetriesExceededError:
                update_submission_result(sid, None, 'Error',
                                         error_message='评测排队超时：所有模型端点持续繁忙，请稍后重测')
                _publish_snapshot(sid)
                return {'success': False, 'message': '端点持续繁忙'}

        # 已拿到槽位 → 取幂等锁（防同一提交被并发重复评测）。
        lock_key = f'ranking:judge:lock:{sid}'
        lock_token = str(self.request.id or sid)
        got_lock = True
        if client is not None:
            try:
                # 锁 TTL 与槽位 TTL 对齐（timeout+buffer）：worker 被硬杀时，僵尸锁与槽位同时过期，
                # 不会出现「槽位已放、锁还占着」的窗口；正常完成则在 finally 主动释放。
                got_lock = bool(client.set(lock_key, lock_token, nx=True, ex=int(ttl)))
            except Exception:
                got_lock = True
        if not got_lock:
            _release_slot(client, slot_key, slot_token)
            return {'success': False, 'message': '已有评测在进行'}
        try:
            # 幂等复查：拿到锁后再读一次状态。acks_late=True 下，worker 被杀的任务会被 broker
            # 重投，同时 startup_requeue 也会补入队 —— 两条恢复消息并发时由锁互斥（只一条评测），
            # 但「顺序」到达（前者评完释放锁后后者才跑）会重复评测。这里若发现已判到终态就跳过，
            # 彻底消除顺序重投导致的重复评测；正常提交('Queued')、重测('Judging') 均为非终态，不受影响。
            fresh = get_ranking_submission(sid)
            if fresh and str(fresh.get('status')) in ('Accepted', 'Error'):
                return {'success': True, 'message': '已完成，跳过重复评测'}
            return _judge(sid, ep)
        except Exception as e:
            try:
                update_submission_result(sid, None, 'Error', error_message=f'评测任务异常：{e}')
                _publish_snapshot(sid)
            except Exception:
                pass
            raise
        finally:
            _release_slot(client, slot_key, slot_token)
            if client is not None and got_lock:
                try:
                    if client.get(lock_key) == lock_token:
                        client.delete(lock_key)
                except Exception:
                    pass

    return evaluate_ranking_agent_judge
