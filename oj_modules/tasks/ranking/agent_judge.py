#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛 Agent-as-Judge 评测任务：起 Docker 容器跑所选 harness，tail result.jsonl 实时回传。"""
from contextlib import contextmanager
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request
import zipfile

try:
    from celery.exceptions import MaxRetriesExceededError, Retry
except Exception:  # pragma: no cover
    class MaxRetriesExceededError(Exception):
        pass
    class Retry(Exception):
        pass

from oj_modules import config as _cfg
from oj_modules.shared.archive import ZipExtractionPolicy, extract_zip
from oj_modules.ranking.agent_judge import rules as aj
from oj_modules.infrastructure.redis import (
    RedisClientProfile,
    create_optional_redis_client,
)
from oj_modules.tasks.agent.secret_relay import run_agent_secret_relays
from oj_modules.ranking.db import (
    get_competition, get_ranking_submission, list_competition_files,
    set_agent_judge_task_id, set_submission_status_for_attempt,
    submission_dir, update_submission_result_for_attempt,
)
from oj_modules.ranking.agent_judge.db import (
    ENDPOINT_STATUS_PAUSED,
    HARNESS_CLAUDE_CODE, HARNESS_CODEX, HARNESS_OPENCODE, HARNESS_PI,
    agent_judge_trace_dir, agent_judge_trace_id,
    build_judge_snapshot, clear_judge_results_for_attempt,
    list_agent_judge_endpoints, list_competition_rules, list_judge_results,
    infer_agent_endpoint_protocol, normalize_endpoint_model_capabilities,
    list_paused_agent_judge_endpoints, pause_agent_judge_endpoint,
    resume_paused_agent_judge_endpoint, upsert_judge_result_for_attempt,
)

RANKING_AGENT_JUDGE_TASK_NAME = 'oj.ranking_agent_judge'
RANKING_AGENT_JUDGE_PAUSED_PROBE_TASK_NAME = 'oj.ranking_agent_judge_paused_probe'

# 配置读取：环境变量优先，其次 oj_modules/config.py，最后内置默认。这样本机可用环境变量切 lite 镜像，
# 生产 oj_modules/config.py 不设置时仍默认使用原版 numericaloj-agent-judge:latest。
def _config_value(name, default):
    env_value = os.environ.get(name)
    if env_value is not None and str(env_value).strip() != '':
        return env_value
    return getattr(_cfg, name, default)


JUDGE_IMAGE = _config_value('AGENT_JUDGE_DOCKER_IMAGE', 'numericaloj-agent-judge:latest')
JUDGE_WORKSPACE_ROOT = _config_value('AGENT_JUDGE_WORKSPACE_ROOT', 'ranking_uploads/judge_workspace')
JUDGE_DEFAULT_TIMEOUT = int(_config_value('AGENT_JUDGE_DEFAULT_TIMEOUT', 1800))
JUDGE_MEM_LIMIT = _config_value('AGENT_JUDGE_MEM_LIMIT', '4g')
JUDGE_CPU_LIMIT = str(_config_value('AGENT_JUDGE_CPU_LIMIT', '2'))
JUDGE_PIDS_LIMIT = str(_config_value('AGENT_JUDGE_PIDS_LIMIT', '512'))
JUDGE_POLL_INTERVAL = float(_config_value('AGENT_JUDGE_RESULT_POLL_INTERVAL', 1.5))
JUDGE_PROGRESS_TTL = int(_config_value('AGENT_JUDGE_PROGRESS_TTL', 21600))
JUDGE_TRACE_SYNC_INTERVAL = max(
    2.0, float(_config_value('AGENT_JUDGE_TRACE_SYNC_INTERVAL_SECONDS', 5.0)),
)
# 多端点并发：未配置端点池时，回退用比赛单端点 + 这个默认并发上限（沿用旧 -c 2 的语义）。
JUDGE_LEGACY_CONCURRENCY = max(1, int(_config_value('AGENT_JUDGE_CONCURRENCY', 2)))
# 所有端点都满时，任务延迟重排（back-pressure）的基准秒数 + 上限重试次数 + 槽位 TTL 余量。
JUDGE_QUEUE_RETRY_BASE = max(2, int(_config_value('AGENT_JUDGE_QUEUE_RETRY_SECONDS', 8)))
JUDGE_MAX_QUEUE_RETRIES = max(1, int(_config_value('AGENT_JUDGE_MAX_QUEUE_RETRIES', 2000)))
JUDGE_SLOT_TTL_BUFFER = max(60, int(_config_value('AGENT_JUDGE_SLOT_TTL_BUFFER', 600)))
JUDGE_PACKAGE_MAX_MEMBERS = max(
    16, int(_config_value('AGENT_JUDGE_PACKAGE_MAX_MEMBERS', 4096)),
)
JUDGE_PACKAGE_MAX_FILE_BYTES = max(
    1024 * 1024,
    int(_config_value('AGENT_JUDGE_PACKAGE_MAX_FILE_BYTES', 256 * 1024 * 1024)),
)
JUDGE_PACKAGE_MAX_TOTAL_BYTES = max(
    JUDGE_PACKAGE_MAX_FILE_BYTES,
    int(_config_value('AGENT_JUDGE_PACKAGE_MAX_TOTAL_BYTES', 512 * 1024 * 1024)),
)
JUDGE_PACKAGE_MAX_COMPRESSION_RATIO = max(
    10.0, float(_config_value('AGENT_JUDGE_PACKAGE_MAX_COMPRESSION_RATIO', 500.0)),
)
JUDGE_HELLO_RETRIES = 5
JUDGE_HELLO_TIMEOUT_SECONDS = max(1.0, float(_config_value('AGENT_JUDGE_HELLO_TIMEOUT_SECONDS', 8.0)))
JUDGE_HELLO_RETRY_SLEEP_SECONDS = max(0.0, float(_config_value('AGENT_JUDGE_HELLO_RETRY_SLEEP_SECONDS', 1.0)))
PAUSED_PROBE_INTERVAL_SECONDS = max(
    60,
    int(_config_value('AGENT_JUDGE_PAUSED_PROBE_INTERVAL_SECONDS', 3600)),
)
PAUSED_PROBE_ATTEMPTS = 5
PAUSED_PROBE_MIN_SUCCESS = 3
PAUSED_PROBE_OWNER_TTL_SECONDS = max(300, PAUSED_PROBE_INTERVAL_SECONDS * 2)
PAUSED_PROBE_OWNER_KEY = 'ranking:agent_judge:paused_probe_owner'
PAUSED_PROBE_SEED_LOCK_KEY = 'ranking:agent_judge:paused_probe_seed_lock'
PAUSED_PROBE_RUN_LOCK_KEY = 'ranking:agent_judge:paused_probe_run_lock'
_judge_rds = None
_judge_blocking_rds = None
_TERMINAL_STATUSES = {'Accepted', 'Error'}
_UNTRUSTED_RESULT_MAX_BYTES = 1024 * 1024
_UNTRUSTED_SESSION_STATE_MAX_BYTES = 256 * 1024


def init_judge_progress_cache(redis_client, blocking_client=None):
    global _judge_rds, _judge_blocking_rds
    _judge_rds = redis_client
    _judge_blocking_rds = redis_client if blocking_client is None else blocking_client


def _ensure_judge_redis():
    global _judge_rds
    if _judge_rds is not None:
        return _judge_rds
    _judge_rds = create_optional_redis_client()
    return _judge_rds


def _ensure_judge_blocking_redis():
    global _judge_blocking_rds
    if _judge_blocking_rds is not None:
        return _judge_blocking_rds
    _judge_blocking_rds = create_optional_redis_client(
        RedisClientProfile.BLOCKING,
    )
    return _judge_blocking_rds


def _read_untrusted_regular_file(path, max_bytes):
    """读取容器可写目录中的文件；拒绝 symlink/非普通文件/超限内容。"""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = None
    try:
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > int(max_bytes):
            return None
        chunks = []
        remaining = int(max_bytes) + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b''.join(chunks)
        return payload if len(payload) <= int(max_bytes) else None
    except Exception:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _reset_untrusted_output_file(path):
    """安全重置容器可写目录中的结果文件，不跟随 Agent 植入的 symlink。"""
    nofollow = getattr(os, 'O_NOFOLLOW', 0)
    nonblock = getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(path, os.O_WRONLY | nofollow | nonblock)
    except FileNotFoundError:
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | nonblock, 0o600,
        )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError('agent judge result path is not a regular file')
        os.ftruncate(fd, 0)
    finally:
        os.close(fd)


def _judge_progress_key(submission_id):
    return f'ranking_judge:{submission_id}'


def _judge_progress_channel(submission_id):
    return f'ranking_judge_events:{submission_id}'


def subscribe_judge_run_events(submission_id):
    client = _ensure_judge_blocking_redis()
    if client is None:
        return None
    try:
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(_judge_progress_channel(submission_id))
        return pubsub
    except Exception:
        return None


def get_judge_progress_snapshot(submission_id):
    current = get_ranking_submission(submission_id)
    # 终态必须以 DB + 规范化轨迹目录实时重建。Redis 只用于评测中的低延迟快照；
    # worker 热重启或最终轨迹补全后，缓存中的同 attempt 终态也可能已经过时。
    if current and str(current.get('status') or '') in _TERMINAL_STATUSES:
        return build_current_judge_snapshot(submission_id)

    client = _ensure_judge_redis()
    if client is not None:
        try:
            raw = client.get(_judge_progress_key(submission_id))
            if raw:
                data = json.loads(raw)
                current_trace_id = agent_judge_trace_id(
                    (current or {}).get('judge_attempt_id'),
                )
                if (isinstance(data, dict)
                        and data.get('attempt_trace_id') == current_trace_id):
                    return data
                client.delete(_judge_progress_key(submission_id))
        except Exception:
            pass
    return build_judge_snapshot(submission_id)


def snapshot_matches_current_attempt(submission_id, snapshot):
    if not isinstance(snapshot, dict):
        return False
    current = get_ranking_submission(submission_id)
    return snapshot.get('attempt_trace_id') == agent_judge_trace_id(
        (current or {}).get('judge_attempt_id'),
    )


def build_current_judge_snapshot(submission_id):
    """构造与当前 attempt 一致的快照；切换竞态下最多重读一次。"""
    for _ in range(2):
        snap = build_judge_snapshot(submission_id)
        if snap is None:
            return None
        if snapshot_matches_current_attempt(submission_id, snap):
            return snap
    return None


def _publish_snapshot(submission_id):
    snap = build_current_judge_snapshot(submission_id)
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


def _normalize_attempt_id(attempt_id):
    text = str(attempt_id or '').strip()
    return text or None


def _attempt_matches(submission, attempt_id):
    current = _normalize_attempt_id((submission or {}).get('judge_attempt_id'))
    expected = _normalize_attempt_id(attempt_id)
    return current == expected


def is_completed_agent_judge_submission(submission, competition=None, rules=None):
    """判断 Agent 评测是否已有完整结果。

    score=0 也可能是合法完成结果；必须同时有 grade_details，且已有规则结果集合
    与当前比赛规则集合完全一致，才把 Queued/Judging 视为已完成但状态被污染。
    """
    if not submission:
        return False
    if str(submission.get('status') or '') in _TERMINAL_STATUSES:
        return True
    if submission.get('score') is None or not submission.get('grade_details'):
        return False
    try:
        sid = int(submission.get('id'))
        competition_id = int(submission.get('competition_id'))
    except Exception:
        return False
    if rules is None:
        rules = list_competition_rules(competition_id)
    rule_ids = {int(r.get('rule_id')) for r in (rules or []) if r.get('rule_id') is not None}
    if not rule_ids:
        return False
    rows = list_judge_results(sid)
    result_ids = {int(r.get('rule_id')) for r in (rows or []) if r.get('rule_id') is not None}
    return result_ids == rule_ids


def _task_should_skip(submission, attempt_id, competition=None, rules=None):
    if not submission:
        return True, '提交不存在'
    if not _attempt_matches(submission, attempt_id):
        return True, '旧评测 attempt，跳过'
    if is_completed_agent_judge_submission(submission, competition=competition, rules=rules):
        return True, '已完成，跳过重复评测'
    return False, ''


def _attempt_still_current(submission_id, attempt_id):
    submission = get_ranking_submission(submission_id)
    return bool(submission and _attempt_matches(submission, attempt_id))


def _write_error_for_attempt(submission_id, attempt_id, error_message):
    return update_submission_result_for_attempt(
        submission_id, attempt_id, None, 'Error',
        grade_details=None, error_message=error_message,
    )


def _fake_agent_judge_enabled():
    raw = os.getenv('NUMOJ_FAKE_AGENT_JUDGE')
    if raw is None:
        raw = getattr(_cfg, 'NUMOJ_FAKE_AGENT_JUDGE', False)
    return str(raw).strip().lower() in {'1', 'true', 'yes', 'on'}


def _fake_agent_judge_full_score(competition, rules):
    if rules:
        total = 0.0
        for rule in rules:
            try:
                total += float(rule.get('value') or 0)
            except (TypeError, ValueError):
                pass
        if total > 0:
            return total
    try:
        score = float((competition or {}).get('max_score') or 100)
    except (TypeError, ValueError):
        score = 100.0
    return max(0.0, score)


def _finish_fake_agent_judge(submission_id, attempt_id, competition):
    """本地限额测试用假评测：不探活端点、不启动 Docker、不启动 agent。"""
    if set_submission_status_for_attempt(submission_id, attempt_id, 'Judging') <= 0:
        return {'success': True, 'message': '旧评测 attempt，跳过'}
    rules = list_competition_rules(competition['id']) if competition else []
    clear_judge_results_for_attempt(submission_id, attempt_id)
    score = _fake_agent_judge_full_score(competition, rules)
    evidence = '本地假评测：模拟排队结束后直接给满分。'
    for rule in rules:
        upsert_judge_result_for_attempt(
            submission_id, attempt_id, rule.get('rule_id'),
            'yes', 'yes', rule.get('value') or 0, evidence,
        )
    update_submission_result_for_attempt(
        submission_id, attempt_id, score, 'Accepted',
        grade_details={
            'total_score': score,
            'max_score': score,
            'fake_agent_judge': True,
            'note': evidence,
        },
    )
    _publish_snapshot(submission_id)
    return {'success': True, 'fake_agent_judge': True, 'score': score}


# ---------- 多端点选择与 Redis 槽位限流 ----------

def _resolve_endpoints(competition_id, competition=None):
    """返回该比赛状态为 enabled 的判题端点。

    paused / disabled 都不会参与评测；disabled 只由管理员手动设置，不由后台恢复任务处理。
    """
    try:
        eps = list_agent_judge_endpoints(competition_id, enabled_only=True)
    except Exception:
        eps = []
    resolved = []
    for endpoint in eps:
        resolved.append({
            'id': endpoint['id'],
            'harness': endpoint.get('harness') or HARNESS_CLAUDE_CODE,
            'protocol': endpoint.get('protocol'),
            'base_url': endpoint['base_url'],
            'api_key': endpoint['api_key'],
            'model': endpoint.get('model') or '',
            'thinking_format': endpoint.get('thinking_format'),
            **normalize_endpoint_model_capabilities(endpoint),
            'concurrency_limit': max(
                1, int(endpoint.get('concurrency_limit') or 1),
            ),
        })
    return resolved


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


# ---------- 端点连通性预检 ----------

def _append_api_path(base_url, path):
    base = str(base_url or '').strip().rstrip('/')
    if not base:
        return ''
    suffix = '/' + str(path or '').strip('/')
    if base.endswith(suffix):
        return base
    if suffix.startswith('/v1/') and base.endswith('/v1'):
        return base + suffix[len('/v1'):]
    return base + suffix


def _hello_probe_request(endpoint):
    harness = str(endpoint.get('harness') or HARNESS_CLAUDE_CODE).strip().lower()
    protocol = infer_agent_endpoint_protocol(harness, endpoint.get('protocol'))
    base_url = str(endpoint.get('base_url') or '').strip()
    api_key = str(endpoint.get('api_key') or '').strip()
    model = str(endpoint.get('model') or '').strip()
    if not base_url or not api_key or not model:
        return None, '端点 URL、API Key 或模型为空'

    if protocol == 'anthropic':
        payload = {
            'model': model,
            'max_tokens': 8,
            'messages': [{'role': 'user', 'content': 'hello'}],
        }
        headers = {
            'Content-Type': 'application/json',
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
        }
        url = _append_api_path(base_url, '/v1/messages')
    else:
        payload = {
            'model': model,
            'messages': [{'role': 'user', 'content': 'hello'}],
            'max_tokens': 8,
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
        }
        url = _append_api_path(base_url, '/v1/chat/completions')

    body = json.dumps(payload).encode('utf-8')
    return urllib.request.Request(url, data=body, headers=headers, method='POST'), None


def _probe_endpoint_once(endpoint):
    req, err = _hello_probe_request(endpoint)
    if err:
        return False, err
    try:
        with urllib.request.urlopen(req, timeout=JUDGE_HELLO_TIMEOUT_SECONDS) as resp:
            code = int(getattr(resp, 'status', resp.getcode()))
            if 200 <= code < 300:
                return True, 'ok'
            return False, f'HTTP {code}'
    except urllib.error.HTTPError as e:
        return False, f'HTTP {getattr(e, "code", "error")}'
    except Exception as e:
        return False, str(e)[:200]


def _sanitize_probe_message(endpoint, message):
    """健康检查错误可写日志，但绝不能携带端点密钥或控制字符。"""
    text = str(message or 'unknown error')
    api_key = str((endpoint or {}).get('api_key') or '')
    if api_key:
        text = text.replace(api_key, '[redacted]')
    text = ''.join(ch if ch >= ' ' and ch != '\x7f' else ' ' for ch in text)
    return text[:200]


def _probe_endpoint(endpoint, attempts=None):
    tries = max(1, int(attempts or JUDGE_HELLO_RETRIES))
    last_error = ''
    for i in range(tries):
        ok, msg = _probe_endpoint_once(endpoint)
        msg = _sanitize_probe_message(endpoint, msg)
        if ok:
            return True, msg
        last_error = msg or 'unknown error'
        if i + 1 < tries and JUDGE_HELLO_RETRY_SLEEP_SECONDS > 0:
            time.sleep(JUDGE_HELLO_RETRY_SLEEP_SECONDS)
    return False, last_error


def _disable_unhealthy_endpoint(endpoint, reason):
    try:
        pause_agent_judge_endpoint(int(endpoint.get('id')))
    except Exception:
        pass
    eid = endpoint.get('id')
    print(f'[agent_judge] paused endpoint {eid} after hello probe failures: {reason}', flush=True)


def _probe_paused_endpoint_for_resume(endpoint):
    success = 0
    errors = []
    for i in range(PAUSED_PROBE_ATTEMPTS):
        ok, msg = _probe_endpoint_once(endpoint)
        msg = _sanitize_probe_message(endpoint, msg)
        if ok:
            success += 1
        else:
            errors.append(msg or 'unknown error')
        if i + 1 < PAUSED_PROBE_ATTEMPTS and JUDGE_HELLO_RETRY_SLEEP_SECONDS > 0:
            time.sleep(JUDGE_HELLO_RETRY_SLEEP_SECONDS)
    return success, errors[-1] if errors else 'ok'


def register_ranking_agent_judge_paused_probe_task(celery_app):
    existing = getattr(celery_app, 'tasks', {}).get(RANKING_AGENT_JUDGE_PAUSED_PROBE_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(name=RANKING_AGENT_JUDGE_PAUSED_PROBE_TASK_NAME, bind=True)
    def ranking_agent_judge_paused_probe(self, owner_id):
        def schedule_next_probe():
            try:
                self.apply_async(args=[owner_id], countdown=PAUSED_PROBE_INTERVAL_SECONDS)
            except Exception:
                pass

        client = _ensure_judge_redis()
        run_lock_acquired = False
        if client is not None:
            try:
                current = client.get(PAUSED_PROBE_OWNER_KEY)
                if current is None:
                    client.set(PAUSED_PROBE_OWNER_KEY, owner_id, ex=PAUSED_PROBE_OWNER_TTL_SECONDS)
                elif current != owner_id:
                    return {'success': True, 'reason': 'not the active paused probe owner'}
                else:
                    client.set(PAUSED_PROBE_OWNER_KEY, owner_id, ex=PAUSED_PROBE_OWNER_TTL_SECONDS)
                run_lock_acquired = bool(client.set(
                    PAUSED_PROBE_RUN_LOCK_KEY,
                    owner_id,
                    ex=PAUSED_PROBE_OWNER_TTL_SECONDS,
                    nx=True,
                ))
                if not run_lock_acquired:
                    schedule_next_probe()
                    return {'success': True, 'reason': 'paused probe already running'}
            except Exception:
                pass

        checked = 0
        resumed = 0
        try:
            endpoints = list_paused_agent_judge_endpoints()
            for ep in endpoints:
                # 只恢复仍处于 paused 的端点；管理员若已手动停用，条件更新不会覆盖。
                if ep.get('status') != ENDPOINT_STATUS_PAUSED:
                    continue
                checked += 1
                ok_count, last_msg = _probe_paused_endpoint_for_resume(ep)
                if ok_count >= PAUSED_PROBE_MIN_SUCCESS:
                    if resume_paused_agent_judge_endpoint(int(ep.get('id'))):
                        resumed += 1
                        print(
                            f'[agent_judge] resumed paused endpoint {ep.get("id")} '
                            f'after {ok_count}/{PAUSED_PROBE_ATTEMPTS} hello probes',
                            flush=True,
                        )
                else:
                    print(
                        f'[agent_judge] endpoint {ep.get("id")} remains paused: '
                        f'{ok_count}/{PAUSED_PROBE_ATTEMPTS} hello probes ok; last={last_msg}',
                        flush=True,
                    )
        finally:
            if client is not None and run_lock_acquired:
                try:
                    if client.get(PAUSED_PROBE_RUN_LOCK_KEY) == owner_id:
                        client.delete(PAUSED_PROBE_RUN_LOCK_KEY)
                except Exception:
                    pass
            schedule_next_probe()
        return {'success': True, 'checked': checked, 'resumed': resumed}

    return ranking_agent_judge_paused_probe


def seed_agent_judge_paused_probe(redis_client, paused_probe_task, *,
                                  reset_owner=False, countdown=300):
    """启动一条全局唯一的暂停端点恢复检查链路。"""
    if paused_probe_task is None:
        return
    try:
        if redis_client is None:
            paused_probe_task.apply_async(args=[secrets.token_hex(16)], countdown=countdown)
            return

        if reset_owner:
            owner_id = secrets.token_hex(16)
            try:
                redis_client.delete(PAUSED_PROBE_SEED_LOCK_KEY, PAUSED_PROBE_RUN_LOCK_KEY)
            except Exception:
                pass
            redis_client.set(PAUSED_PROBE_OWNER_KEY, owner_id, ex=PAUSED_PROBE_OWNER_TTL_SECONDS)
            paused_probe_task.apply_async(args=[owner_id], countdown=countdown)
            return

        if not redis_client.set(PAUSED_PROBE_SEED_LOCK_KEY, '1', ex=60, nx=True):
            return

        owner_id = redis_client.get(PAUSED_PROBE_OWNER_KEY)
        if owner_id:
            # 已有 owner 时不补发同 owner 任务，避免 Web worker 重建制造永久
            # 并行的自调度链；完整停机恢复由 reset_owner=True 显式重建。
            return

        owner_id = secrets.token_hex(16)
        if redis_client.set(PAUSED_PROBE_OWNER_KEY, owner_id, ex=PAUSED_PROBE_OWNER_TTL_SECONDS, nx=True):
            paused_probe_task.apply_async(args=[owner_id], countdown=countdown)
    except Exception:
        pass


def clear_judge_lock(submission_id):
    """删除某提交的 Agent / 反向评测幂等锁。

    进程重启重排前调用：上次被杀的 worker 会留下僵尸锁（TTL 内有效），不清的话
    重排任务 set(nx) 失败、直接返回，提交会一直卡住。
    """
    client = _ensure_judge_redis()
    if client is None:
        return
    try:
        sid = int(submission_id)
        for prefix in ('ranking:judge:lock', 'ranking:reverse_judge:lock'):
            client.delete(f'{prefix}:{sid}')
            for key in client.scan_iter(match=f'{prefix}:{sid}:*', count=50):
                client.delete(key)
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


def _retry_queued_submission(task, submission_id, attempt_id=None,
                             message='所有模型端点并发均已满，重新排队'):
    submission = get_ranking_submission(submission_id)
    skip, skip_msg = _task_should_skip(submission, attempt_id)
    if skip:
        return {'success': True, 'message': skip_msg}
    if set_submission_status_for_attempt(submission_id, attempt_id, 'Queued') <= 0:
        return {'success': True, 'message': '旧评测 attempt，跳过'}
    _publish_snapshot(submission_id)
    countdown = JUDGE_QUEUE_RETRY_BASE + random.randint(0, JUDGE_QUEUE_RETRY_BASE)
    try:
        task.retry(countdown=countdown, max_retries=JUDGE_MAX_QUEUE_RETRIES)
    except MaxRetriesExceededError:
        _write_error_for_attempt(
            submission_id, attempt_id, '评测排队超时：所有模型端点持续繁忙，请稍后重测',
        )
        _publish_snapshot(submission_id)
        return {'success': False, 'message': '端点持续繁忙'}
    return {'success': False, 'message': message}


def _safe_extract_zip(zip_path, dest_dir):
    """安全解包 ZIP；沿用既有语义，忽略越界成员并继续处理其余文件。"""
    extract_zip(
        zip_path,
        dest_dir,
        policy=ZipExtractionPolicy(
            max_members=JUDGE_PACKAGE_MAX_MEMBERS,
            max_file_bytes=JUDGE_PACKAGE_MAX_FILE_BYTES,
            max_total_bytes=JUDGE_PACKAGE_MAX_TOTAL_BYTES,
            max_compression_ratio=JUDGE_PACKAGE_MAX_COMPRESSION_RATIO,
            unsafe_member_action='skip',
            cleanup_on_error=True,
        ),
    )


def _prepare_workspace(submission, competition, rules, attempt_id=None):
    """准备宿主工作目录，返回 (绝对路径, 随机结果文件名)。

    结果文件名随机生成，仅通过提示词/AJ_RESULT_FILE 告知评测 Agent；参赛者代码无法预先猜到该
    文件名，从而无法把伪造的 pass 结果写进去（防止刷满分）。不再把工作目录/结果文件改为 world-writable
    —— 容器内 root + 默认能力集（含 CAP_DAC_OVERRIDE）足以写宿主属主的挂载文件。"""
    sid = submission['id']
    attempt_component = agent_judge_trace_id(attempt_id)
    submission_root = os.path.realpath(os.path.join(JUDGE_WORKSPACE_ROOT, str(sid)))
    ws = os.path.realpath(os.path.join(submission_root, attempt_component))
    if ws != submission_root and not ws.startswith(submission_root + os.sep):
        raise ValueError('invalid agent judge workspace')
    if os.path.isdir(ws):
        shutil.rmtree(ws, ignore_errors=True)
    os.makedirs(ws, exist_ok=True)
    # 代码
    code_path = submission.get('code_path')
    sub_dir = os.path.join(ws, 'submission')
    os.makedirs(sub_dir, exist_ok=True)
    if code_path and os.path.isfile(code_path):
        # 当前上传契约要求代码包使用 .zip；is_zipfile 兼容历史上扩展名丢失的有效包。
        # 一旦判定为压缩包，任何解压异常都必须拒绝，不能把损坏/危险 ZIP 原样交给容器。
        if str(code_path).lower().endswith('.zip') or zipfile.is_zipfile(code_path):
            _safe_extract_zip(code_path, sub_dir)
        else:
            # 兼容历史数据中的单个源码文件；当前上传路由不会再产生这种提交。
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


def _resolve_harness_config(endpoint):
    ep = endpoint or {}
    harness = ep.get('harness') or HARNESS_CLAUDE_CODE
    base_url = ep.get('base_url') or ''
    api_key = ep.get('api_key') or ''
    model = ep.get('model') or ''
    return harness, base_url, api_key, model


@contextmanager
def _agent_judge_endpoint_relay(endpoint):
    """仅向评测容器提供本轮临时凭据，长期模型密钥只留在宿主代理内存。"""
    host_endpoint = dict(endpoint or {})
    harness = host_endpoint.get('harness') or HARNESS_CLAUDE_CODE
    host_endpoint['protocol'] = infer_agent_endpoint_protocol(
        harness, host_endpoint.get('protocol'),
    )
    with run_agent_secret_relays(host_endpoint) as relay:
        container_endpoint = dict(host_endpoint)
        container_endpoint.update({
            'base_url': relay.endpoint_base_url,
            'api_key': relay.endpoint_api_key,
        })
        yield container_endpoint


def _agent_env_args(
        harness, base_url, api_key, model, result_name, include_prompt=False,
        endpoint=None):
    capabilities = normalize_endpoint_model_capabilities(endpoint)
    protocol = infer_agent_endpoint_protocol(
        harness, (endpoint or {}).get('protocol'),
    )
    copied_thinking_format = str(
        (endpoint or {}).get('thinking_format') or ''
    ).strip().lower()
    if copied_thinking_format not in {'enable_thinking', 'thinking_type', 'none'}:
        copied_thinking_format = ''
    args = [
        '-e', 'IS_SANDBOX=1',
        # 关闭 claude 的非必要外联（遥测/自动更新/错误上报），否则在受限容器内会卡住
        '-e', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1',
        '-e', 'DISABLE_TELEMETRY=1',
        '-e', 'DISABLE_AUTOUPDATER=1',
        '-e', 'DISABLE_ERROR_REPORTING=1',
        '-e', f'AJ_HARNESS={harness}',
        '-e', f'AJ_ENDPOINT_PROTOCOL={protocol}',
        '-e', f'AJ_ENDPOINT_BASE_URL={base_url}',
        '-e', f'AJ_ENDPOINT_API_KEY={api_key}',
        '-e', f'AJ_ENDPOINT_MODEL={model}',
        '-e', (
            'AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS='
            f"{capabilities['context_window_tokens']}"
        ),
        '-e', f"AJ_ENDPOINT_MAX_OUTPUT_TOKENS={capabilities['max_output_tokens']}",
        '-e', (
            'AJ_ENDPOINT_THINKING_ENABLED='
            f"{1 if capabilities['thinking_compatibility'] else 0}"
        ),
        '-e', f'AJ_ENDPOINT_THINKING_FORMAT={copied_thinking_format}',
        '-e', f'AJ_RESULT_FILE=/workspace/{result_name}',
        '-e', 'AJ_SESSION_STATE=/workspace/.aj_session_state.json',
    ]
    if include_prompt:
        args.extend(['-e', 'AJ_PROMPT'])
    return args


def _docker_container_args(
        container_name, ws, harness, base_url, api_key, model, result_name,
        include_prompt=False, endpoint=None):
    return [
        'docker', 'run', '-d', '--name', container_name,
        # 注意：不可用 --cap-drop ALL —— 那会移除 CAP_DAC_OVERRIDE，导致容器内 root
        # 既无法写宿主属主(非 root)的挂载文件、也无法 apt 装包。
        '--security-opt', 'no-new-privileges',
        '--log-opt', 'max-size=16m', '--log-opt', 'max-file=1',
        '--pids-limit', JUDGE_PIDS_LIMIT,
        '--memory', JUDGE_MEM_LIMIT, '--cpus', JUDGE_CPU_LIMIT,
        # 与通用 Agent 的宿主 relay 契约一致；Linux Docker 不会默认解析
        # host.docker.internal，必须显式映射到本机 bridge 网关。
        '--add-host', 'host.docker.internal:host-gateway',
        '-v', f'{ws}:/workspace', '-w', '/workspace',
    ] + _agent_env_args(
        harness, base_url, api_key, model, result_name,
        include_prompt=include_prompt, endpoint=endpoint,
    ) + [
        JUDGE_IMAGE,
    ]


def _read_session_id(ws):
    try:
        raw = _read_untrusted_regular_file(
            os.path.join(ws, '.aj_session_state.json'), 16 * 1024,
        )
        data = json.loads((raw or b'').decode('utf-8'))
        sid = str(data.get('session_id') or '').strip()
        return sid if re.fullmatch(
            r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', sid,
        ) else None
    except Exception:
        return None


_TRACE_RESULT_FILE_RE = re.compile(
    r'result_[0-9a-fA-F]{32}\.jsonl(?:\.rule_\d+\.jsonl)?', re.I,
)
_TRACE_ENV_SECRET_RE = re.compile(
    r'((?:AJ_ENDPOINT_API_KEY|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY|'
    r'OPENAI_API_KEY|OPENCODE_API_KEY)\s*[=:]\s*)[^\s"\'<>]+',
    re.I,
)
_TRACE_LOG_CAPTURE_MAX_BYTES = 2 * 1024 * 1024
_TRACE_EXPORT_CAPTURE_MAX_BYTES = 12 * 1024 * 1024
_TRACE_EXPORT_MAX_ITEMS = 48
_TRACE_EXPORT_MAX_EVENTS = 4096
_TRACE_EXPORT_MAX_EVENT_BYTES = 256 * 1024
_TRACE_PHASE_CAPTURE_MAX_BYTES = 8 * 1024 * 1024
_TRACE_JOURNAL_MAX_BYTES = 32 * 1024 * 1024


def _trace_text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return str(value or '')


def _split_docker_log_line(raw):
    raw = raw if isinstance(raw, bytes) else _trace_text(raw).encode('utf-8')
    stamp, separator, content = raw.partition(b' ')
    if separator and b'T' in stamp and stamp.endswith(b'Z'):
        identity = int(hashlib.sha256(stamp).hexdigest()[:15], 16)
        return identity, content
    identity = int(hashlib.sha256(raw).hexdigest()[:15], 16)
    return identity, raw


def _capture_process_output_limited(args, *, timeout=8, max_bytes=None):
    """持续 drain 子进程输出但只保留尾部，防止 docker logs 把 worker 内存撑爆。"""
    limit = max(1024, int(max_bytes or _TRACE_LOG_CAPTURE_MAX_BYTES))
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = bytearray()
    stderr = bytearray()
    truncated = {'stdout': False, 'stderr': False}

    def _drain(source, target, key):
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            target.extend(chunk)
            if len(target) > limit:
                truncated[key] = True
                del target[:-limit]

    threads = [
        threading.Thread(target=_drain, args=(proc.stdout, stdout, 'stdout'), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, stderr, 'stderr'), daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        returncode = proc.wait(timeout=max(1, float(timeout)))
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        returncode = proc.wait(timeout=3)
    for thread in threads:
        thread.join(timeout=3)
    result = subprocess.CompletedProcess(args, returncode, bytes(stdout), bytes(stderr))
    result.stdout_truncated = truncated['stdout']
    result.stderr_truncated = truncated['stderr']
    result.timed_out = timed_out
    return result


def _run_process_with_input_limited(args, input_text, *, timeout, max_bytes=None):
    """带 stdin 执行并有界收集 stdout/stderr；超时时保留尾部后抛 TimeoutExpired。"""
    limit = max(1024, int(max_bytes or _TRACE_PHASE_CAPTURE_MAX_BYTES))
    proc = subprocess.Popen(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    stdout = bytearray()
    stderr = bytearray()

    def _drain(source, target):
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            target.extend(chunk)
            if len(target) > limit:
                del target[:-limit]

    readers = [
        threading.Thread(target=_drain, args=(proc.stdout, stdout), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        try:
            proc.stdin.write(_trace_text(input_text).encode('utf-8'))
            proc.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass
        try:
            returncode = proc.wait(timeout=max(1, float(timeout)))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
            for reader in readers:
                reader.join(timeout=3)
            raise subprocess.TimeoutExpired(
                args, timeout,
                output=bytes(stdout).decode('utf-8', 'replace'),
                stderr=bytes(stderr).decode('utf-8', 'replace'),
            )
    finally:
        if proc.poll() is None:
            proc.kill()
    for reader in readers:
        reader.join(timeout=3)
    return subprocess.CompletedProcess(
        args, returncode,
        bytes(stdout).decode('utf-8', 'replace'),
        bytes(stderr).decode('utf-8', 'replace'),
    )


def _agent_judge_container_name(submission_id, attempt_id):
    """为每次评测生成独立容器名，避免旧 worker 清理时误杀重测容器。"""
    return f'aj_{int(submission_id)}_{agent_judge_trace_id(attempt_id)}'


def _remove_stale_agent_containers(submission_id, current_name):
    """清理同一提交的 legacy/旧 attempt 容器，名称前缀严格限定 sid。"""
    legacy = f'aj_{int(submission_id)}'
    prefix = legacy + '_'
    try:
        listed = subprocess.run(
            ['docker', 'ps', '-a', '--format', '{{.Names}}'],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return
    if int(getattr(listed, 'returncode', 1) or 0) != 0:
        return
    for raw_name in (listed.stdout or '').splitlines():
        name = raw_name.strip()
        if not name or name == current_name:
            continue
        if name != legacy and not name.startswith(prefix):
            continue
        try:
            subprocess.run(
                ['docker', 'rm', '-f', name], capture_output=True, timeout=20,
            )
        except Exception:
            pass


def _prune_stale_attempt_workspaces(submission_id, current_ws):
    root = os.path.realpath(os.path.join(JUDGE_WORKSPACE_ROOT, str(int(submission_id))))
    try:
        os.makedirs(root, exist_ok=True)
        for name in os.listdir(root):
            path = os.path.realpath(os.path.join(root, name))
            if path == current_ws or not path.startswith(root + os.sep):
                continue
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            elif os.path.isfile(path):
                os.remove(path)
    except Exception:
        pass


def _sanitize_trace_payload(value, *, api_key='', extra_secrets=()):
    """轨迹落盘前永久脱敏。

    参赛内容不可信，可能诱导 Agent 输出环境变量；因此不能只在路由层遮盖，原始
    JSONL 和日志在写入受信任目录前就必须去掉本次端点密钥与随机结果文件名。
    """
    text = _trace_text(value)
    secrets_to_redact = [api_key] + list(extra_secrets or ())
    for secret in secrets_to_redact:
        secret = str(secret or '')
        if len(secret) >= 8:
            text = text.replace(secret, '[redacted]')
    text = _TRACE_RESULT_FILE_RE.sub('[result-file]', text)
    text = _TRACE_ENV_SECRET_RE.sub(r'\1[redacted]', text)
    return text.encode('utf-8')


def _atomic_write_trace(path, payload):
    payload = payload if isinstance(payload, bytes) else _trace_text(payload).encode('utf-8')
    try:
        with open(path, 'rb') as f:
            if f.read() == payload:
                return False
    except OSError:
        pass
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(payload)
        os.replace(tmp, path)
        return True
    except Exception:
        try:
            if os.path.exists(path + '.tmp'):
                os.remove(path + '.tmp')
        except Exception:
            pass
        return False


def _append_bounded_trace_journal(path, payload):
    payload = payload if isinstance(payload, bytes) else _trace_text(payload).encode('utf-8')
    marker = json.dumps({
        'type': 'assistant_message',
        'message': '执行轨迹已达到持久化上限，后续事件不再记录。',
        '_trace_source': 'trace-journal',
        '_trace_offset': 0,
        '_trace_phase': 'final',
    }, ensure_ascii=False).encode('utf-8') + b'\n'
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        if size:
            try:
                with open(path, 'rb') as f:
                    f.seek(max(0, size - 65536))
                    if marker.rstrip(b'\n') in f.read():
                        return False
            except OSError:
                pass
        if size + len(payload) > _TRACE_JOURNAL_MAX_BYTES:
            payload = marker if size + len(marker) <= _TRACE_JOURNAL_MAX_BYTES else b''
        if not payload:
            return False
        with open(path, 'ab') as f:
            f.write(payload)
        return True
    except Exception:
        return False


def _claude_trace_order(ws):
    ordered = []
    seen = set()
    path = os.path.join(ws, '.aj_session_state.jsonl')
    try:
        raw = _read_untrusted_regular_file(path, _UNTRUSTED_SESSION_STATE_MAX_BYTES)
        if raw is None:
            return ordered
        for line in raw.decode('utf-8', 'replace').splitlines():
            try:
                event = json.loads(line)
            except Exception:
                continue
            if not isinstance(event, dict):
                continue
            session_id = str(event.get('session_id') or '').strip()
            if (re.fullmatch(
                    r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',
                    session_id,
                ) and session_id not in seen):
                seen.add(session_id)
                ordered.append((session_id, str(event.get('phase') or '').strip()))
    except Exception:
        pass
    return ordered


def _load_claude_trace_cursor_state(trace_dir):
    cursor_path = os.path.join(trace_dir, '.claude_trace_cursors.json')
    try:
        with open(cursor_path, 'r', encoding='utf-8') as f:
            loaded = json.load(f)
        cursors = {
            str(key): int(value)
            for key, value in loaded.items()
            if isinstance(key, str) and isinstance(value, int)
        } if isinstance(loaded, dict) else {}
        seen_event_uuids = {
            value for value in loaded.get('__seen_event_uuids__', [])
            if isinstance(value, str) and 0 < len(value) <= 128
        } if isinstance(loaded, dict) else set()
    except Exception:
        cursors = {}
        seen_event_uuids = set()
    return cursor_path, cursors, seen_event_uuids


def _export_container_claude_jsonl(container_name, cursor_state=None):
    """一次有界导出 Claude JSONL，避免逐文件 cat 的无界内存与超时放大。"""
    incremental_cursors = {
        str(key): int(value)
        for key, value in (cursor_state or {}).items()
        if isinstance(key, str) and isinstance(value, int)
    }
    export_cmd = (
        "python3 - <<'PY'\n"
        "import hashlib, json, os, stat\n"
        "MAX_SCAN=512; MAX_FILES=48; MAX_FILE=2*1024*1024; MAX_TOTAL=8*1024*1024; BACKTRACK=256*1024\n"
        f"CURSORS={incremental_cursors!r}\n"
        "bases=['/root/.claude/projects/-workspace',"
        "'/home/node/.claude/projects/-workspace']\n"
        "items=[]\n"
        "complete=True\n"
        "for base in bases:\n"
        "  try:\n"
        "    scanned=0\n"
        "    with os.scandir(base) as entries:\n"
        "      for entry in entries:\n"
        "        scanned += 1\n"
        "        if scanned > MAX_SCAN: complete=False; break\n"
        "        if not entry.name.endswith('.jsonl') or entry.is_symlink(): continue\n"
        "        st=entry.stat(follow_symlinks=False)\n"
        "        if stat.S_ISREG(st.st_mode): items.append({'path':entry.path,'mtime':st.st_mtime,'size':st.st_size})\n"
        "  except FileNotFoundError:\n"
        "    pass\n"
        "  except Exception:\n"
        "    complete=False\n"
        "items.sort(key=lambda item:(item['mtime'],item['path']))\n"
        "truncated=len(items) > MAX_FILES\n"
        "items=items[-MAX_FILES:]\n"
        "selected=[]; total=0\n"
        "for item in reversed(items):\n"
        "  source='claude-'+hashlib.sha256(os.path.basename(item['path']).encode('utf-8','replace')).hexdigest()[:16]\n"
        "  size=int(item['size']); previous_size=CURSORS.get('__size__:'+source)\n"
        "  if isinstance(previous_size,int) and previous_size == size: continue\n"
        "  remaining=MAX_TOTAL-total\n"
        "  if remaining <= 0: truncated=True; break\n"
        "  try:\n"
        "    aligned=False; previous_offset=CURSORS.get(source,-1)\n"
        "    if isinstance(previous_size,int) and 0 <= previous_size < size:\n"
        "      start=max(0,previous_size-BACKTRACK); aligned=(start == 0)\n"
        "    elif isinstance(previous_offset,int) and 0 <= previous_offset < size:\n"
        "      start=previous_offset\n"
        "    else:\n"
        "      start=0\n"
        "    available=max(0,size-start); take=min(available,MAX_FILE,remaining)\n"
        "    was_truncated=take < available\n"
        "    if was_truncated: start=max(start,size-take); aligned=False\n"
        "    with open(item['path'],'rb') as f:\n"
        "      f.seek(start); data=f.read(take)\n"
        "    if start and not aligned:\n"
        "      cut=data.find(b'\\n')\n"
        "      if cut >= 0: start += cut + 1; data=data[cut+1:]\n"
        "      else: data=b''\n"
        "    events=[]; cursor=start\n"
        "    for line in data.splitlines(keepends=True):\n"
        "      stripped=line.strip()\n"
        "      try: event=json.loads(stripped)\n"
        "      except Exception: event=None\n"
        "      if isinstance(event,dict) and event.get('type') == 'assistant':\n"
        "        events.append({'offset':cursor,'event':event})\n"
        "      cursor += len(line)\n"
        "    selected.append({'path':item['path'],'mtime':item['mtime'],'size':size,'events':events,'truncated':was_truncated})\n"
        "    total += len(data)\n"
        "  except Exception:\n"
        "    complete=False\n"
        "selected.reverse()\n"
        "print(json.dumps({'complete':complete,'truncated':truncated,'has_files':bool(items),'items':selected}, ensure_ascii=False))\n"
        "PY"
    )
    try:
        exported = _capture_process_output_limited(
            ['docker', 'exec', container_name, 'bash', '-lc', export_cmd],
            timeout=8, max_bytes=_TRACE_EXPORT_CAPTURE_MAX_BYTES,
        )
        if (int(getattr(exported, 'returncode', 1) or 0) != 0
                or getattr(exported, 'stdout_truncated', False)
                or getattr(exported, 'timed_out', False)):
            return {'complete': False, 'items': []}
        bundle = json.loads((exported.stdout or b'{}').decode('utf-8', 'replace'))
    except Exception:
        return {'complete': False, 'items': []}
    if not isinstance(bundle, dict) or not isinstance(bundle.get('items'), list):
        return {'complete': False, 'items': []}
    items = bundle['items']
    if len(items) > _TRACE_EXPORT_MAX_ITEMS:
        return {'complete': False, 'items': []}
    decoded = []
    total_events = 0
    for item in items:
        if (not isinstance(item, dict) or not item.get('path')
                or len(str(item.get('path'))) > 512):
            continue
        try:
            item_size = max(0, int(item.get('size') or 0))
        except Exception:
            continue
        events = []
        for wrapped in item.get('events') or []:
            if not isinstance(wrapped, dict) or not isinstance(wrapped.get('event'), dict):
                continue
            try:
                offset = max(0, int(wrapped.get('offset') or 0))
            except Exception:
                continue
            try:
                event_size = len(json.dumps(
                    wrapped['event'], ensure_ascii=False,
                ).encode('utf-8'))
            except Exception:
                continue
            if event_size > _TRACE_EXPORT_MAX_EVENT_BYTES:
                continue
            total_events += 1
            if total_events > _TRACE_EXPORT_MAX_EVENTS:
                return {'complete': False, 'items': []}
            events.append({'offset': offset, 'event': wrapped['event']})
        decoded.append({
            'path': str(item['path']),
            'mtime': float(item.get('mtime') or 0),
            'size': item_size,
            'events': events,
            'truncated': item.get('truncated') is True,
        })
    return {
        'complete': bundle.get('complete') is True,
        'truncated': bundle.get('truncated') is True,
        'has_files': bundle.get('has_files') is True,
        'items': decoded,
    }


def _sync_claude_log_fallback(container_name, trace_dir, *, api_key='',
                              extra_secrets=()):
    """容器已停止时从有界 docker logs 补入 Claude 的最终回复。"""
    try:
        logs = _capture_process_output_limited(
            ['docker', 'logs', '--timestamps', '--tail', '200', container_name], timeout=8,
        )
    except Exception:
        return False
    raw = _sanitize_trace_payload(
        getattr(logs, 'stdout', b''), api_key=api_key,
        extra_secrets=extra_secrets,
    )
    text = ''
    for raw_line in reversed(raw.splitlines()):
        _identity, content = _split_docker_log_line(raw_line)
        line = _trace_text(content)
        try:
            event = json.loads(line)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        candidate = event.get('result') or event.get('message') or event.get('text')
        if isinstance(candidate, str) and candidate.strip():
            text = candidate.strip()
            break
    if not text:
        text = _trace_text(raw).strip()[-8000:]
    if not text:
        return False
    marker = int(hashlib.sha256(text.encode('utf-8')).hexdigest()[:15], 16)
    event = {
        'type': 'assistant',
        'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': text}]},
        '_trace_source': 'docker-logs',
        '_trace_offset': marker,
        '_trace_phase': 'final',
    }
    line = _sanitize_trace_payload(
        json.dumps(event, ensure_ascii=False).encode('utf-8'),
        api_key=api_key, extra_secrets=extra_secrets,
    )
    combined_path = os.path.join(
        trace_dir, '.claude', 'projects', '-workspace',
        'agent_judge_combined.jsonl',
    )
    try:
        size = os.path.getsize(combined_path)
        if size + len(line) + 1 > _TRACE_JOURNAL_MAX_BYTES:
            return False
        with open(combined_path, 'rb') as f:
            f.seek(max(0, size - 2 * 1024 * 1024))
            existing_tail = f.read()
    except OSError:
        existing_tail = b''
    if text in existing_tail.decode('utf-8', 'replace') or line in existing_tail.splitlines():
        return False
    try:
        os.makedirs(os.path.dirname(combined_path), exist_ok=True)
        with open(combined_path, 'ab') as f:
            f.write(line + b'\n')
        return True
    except Exception:
        return False


def _sync_claude_execution_trace(container_name, ws, trace_dir, *, api_key='',
                                 extra_secrets=(), default_phase=''):
    """把各 Claude fork 的新增 assistant 事件追加到规范化 journal。"""
    cursor_path, cursors, seen_event_uuids = _load_claude_trace_cursor_state(
        trace_dir,
    )
    bundle = _export_container_claude_jsonl(container_name, cursors)
    items = bundle.get('items') or []
    if not items:
        if bundle.get('has_files'):
            return False
        return _sync_claude_log_fallback(
            container_name, trace_dir, api_key=api_key,
            extra_secrets=extra_secrets,
        )
    if not bundle.get('complete'):
        return False
    session_order = _claude_trace_order(ws)
    order_by_session = {sid: index for index, (sid, _phase) in enumerate(session_order)}
    phase_by_session = {sid: phase for sid, phase in session_order if phase}

    def item_order(item):
        path = str(item.get('path') or '')
        matched = next(
            (order_by_session[sid] for sid, _phase in session_order if sid in path),
            len(session_order),
        )
        return matched, float(item.get('mtime') or 0), path

    def item_phase(item):
        path = str(item.get('path') or '')
        return next(
            (phase for sid, phase in session_order if sid in path),
            str(default_phase or ''),
        )

    def cursor_state_payload():
        state = dict(cursors)
        if seen_event_uuids:
            state['__seen_event_uuids__'] = sorted(seen_event_uuids)
        return json.dumps(state, ensure_ascii=False, sort_keys=True).encode('utf-8')
    initial_cursor_state = cursor_state_payload()
    if cursors.get('__journal_full__'):
        return False

    chunks = []
    for item in sorted(items, key=item_order):
        source_name = os.path.basename(str(item.get('path') or ''))
        source = 'claude-' + hashlib.sha256(
            source_name.encode('utf-8', 'replace'),
        ).hexdigest()[:16]
        phase = item_phase(item)
        events = item.get('events') or []
        previous_offset = int(cursors.get(source, -1))
        cursors['__size__:' + source] = max(0, int(item.get('size') or 0))
        if item.get('truncated') and events:
            first_offset = int(events[0].get('offset') or 0)
            if previous_offset < first_offset:
                marker = {
                    'type': 'assistant',
                    'message': {
                        'role': 'assistant',
                        'content': [{'type': 'text', 'text': '该阶段轨迹过长，仅保留最近内容。'}],
                    },
                    '_trace_source': source,
                    '_trace_offset': max(0, first_offset - 1),
                    '_trace_phase': phase,
                }
                chunks.append(json.dumps(marker, ensure_ascii=False).encode('utf-8'))
        for wrapped in events:
            event_offset = int(wrapped.get('offset') or 0)
            if event_offset <= previous_offset:
                continue
            event = dict(wrapped.get('event') or {})
            event_uuid = event.get('uuid')
            stable_uuid = (
                event_uuid if isinstance(event_uuid, str) and
                0 < len(event_uuid) <= 128 else ''
            )
            if stable_uuid and stable_uuid in seen_event_uuids:
                previous_offset = max(previous_offset, event_offset)
                continue
            event_session_id = str(
                event.get('sessionId') or event.get('session_id') or '',
            ).strip()
            event_phase = phase_by_session.get(event_session_id, phase)
            event['_trace_source'] = source
            event['_trace_offset'] = event_offset
            event['_trace_phase'] = event_phase
            payload = _sanitize_trace_payload(
                json.dumps(event, ensure_ascii=False).encode('utf-8'),
                api_key=api_key, extra_secrets=extra_secrets,
            ).rstrip(b'\n')
            if payload:
                chunks.append(payload)
                if stable_uuid:
                    seen_event_uuids.add(stable_uuid)
                previous_offset = max(previous_offset, event_offset)
        cursors[source] = previous_offset
    if bundle.get('truncated') and not cursors.get('__export_truncated__'):
        chunks.append(json.dumps({
            'type': 'assistant',
            'message': {
                'role': 'assistant',
                'content': [{'type': 'text', 'text': '轨迹文件数量超过采集上限，仅追加最近会话。'}],
            },
            '_trace_source': 'claude-export',
            '_trace_offset': 0,
            '_trace_phase': 'final',
        }, ensure_ascii=False).encode('utf-8'))
        cursors['__export_truncated__'] = 1
    combined_path = os.path.join(
        trace_dir, '.claude', 'projects', '-workspace',
        'agent_judge_combined.jsonl',
    )
    batch = b'\n'.join(chunks) + (b'\n' if chunks else b'')
    try:
        journal_size = os.path.getsize(combined_path)
    except OSError:
        journal_size = 0
    if journal_size + len(batch) > _TRACE_JOURNAL_MAX_BYTES:
        marker = json.dumps({
            'type': 'assistant',
            'message': {
                'role': 'assistant',
                'content': [{'type': 'text', 'text': '执行轨迹已达到持久化上限，后续事件不再记录。'}],
            },
            '_trace_source': 'claude-journal',
            '_trace_offset': 0,
            '_trace_phase': 'final',
        }, ensure_ascii=False).encode('utf-8') + b'\n'
        batch = marker if journal_size + len(marker) <= _TRACE_JOURNAL_MAX_BYTES else b''
        cursors['__journal_full__'] = 1
    if not batch:
        next_cursor_state = cursor_state_payload()
        if next_cursor_state != initial_cursor_state:
            _atomic_write_trace(
                cursor_path,
                next_cursor_state,
            )
        return False
    try:
        os.makedirs(os.path.dirname(combined_path), exist_ok=True)
        with open(combined_path, 'ab') as f:
            f.write(batch)
        changed = True
        _atomic_write_trace(
            cursor_path,
            cursor_state_payload(),
        )
    except Exception:
        changed = False
    return changed


def _append_phase_execution_trace(trace_dir, harness, phase, proc, *, api_key='',
                                  extra_secrets=()):
    stdout = _sanitize_trace_payload(
        getattr(proc, 'stdout', b''), api_key=api_key, extra_secrets=extra_secrets,
    )
    stderr = _trace_text(_sanitize_trace_payload(
        getattr(proc, 'stderr', b''), api_key=api_key,
        extra_secrets=extra_secrets,
    ))
    if harness == HARNESS_CODEX:
        annotated = []
        for raw in stdout.splitlines():
            try:
                event = json.loads(raw.decode('utf-8', 'replace'))
            except Exception:
                continue
            if not isinstance(event, dict):
                continue
            event['_trace_source'] = 'codex'
            event['_trace_phase'] = phase
            annotated.append(json.dumps(event, ensure_ascii=False).encode('utf-8'))
        payload = b'\n'.join(annotated)
    elif harness == HARNESS_OPENCODE:
        visible = _trace_text(stdout).strip()
        if stderr:
            visible = (visible + '\n' + stderr).strip()
        if not visible:
            return False
        payload = json.dumps({
            'type': 'assistant_message',
            'message': f'[{phase}]\n{visible}',
            'model': 'opencode',
            '_trace_source': 'opencode',
            '_trace_phase': phase,
        }, ensure_ascii=False).encode('utf-8')
    else:
        return False
    if not payload:
        return False
    name = 'codex_agent_judge.jsonl' if harness == HARNESS_CODEX else 'opencode_agent_judge.jsonl'
    path = os.path.join(trace_dir, name)
    return _append_bounded_trace_journal(path, payload.rstrip(b'\n') + b'\n')


def _sync_live_execution_trace(container_name, ws, trace_dir, harness, *, api_key='',
                               extra_secrets=()):
    if harness == HARNESS_CLAUDE_CODE:
        return _sync_claude_execution_trace(
            container_name, ws, trace_dir,
            api_key=api_key, extra_secrets=extra_secrets,
        )
    try:
        logs = _capture_process_output_limited(
            ['docker', 'logs', '--timestamps', '--tail', '2000', container_name], timeout=8,
        )
    except Exception:
        return False
    stdout = _sanitize_trace_payload(
        getattr(logs, 'stdout', b''), api_key=api_key, extra_secrets=extra_secrets,
    )
    if harness == HARNESS_CODEX:
        encoded_events = []
        for raw in stdout.splitlines():
            log_offset, content = _split_docker_log_line(raw)
            try:
                event = json.loads(content.decode('utf-8', 'replace'))
            except Exception:
                continue
            if not isinstance(event, dict):
                continue
            event['_trace_source'] = 'codex-logs'
            event['_trace_offset'] = log_offset
            encoded_events.append(json.dumps(event, ensure_ascii=False).encode('utf-8'))
        payload = b'\n'.join(encoded_events) + (b'\n' if encoded_events else b'')
        stderr = _sanitize_trace_payload(
            getattr(logs, 'stderr', b''), api_key=api_key,
            extra_secrets=extra_secrets,
        )
        if stderr.strip():
            stderr_text = _trace_text(stderr).strip()[-4000:]
            payload += json.dumps({
                'type': 'error',
                'message': stderr_text,
                '_trace_source': 'codex-stderr',
                '_trace_offset': int(hashlib.sha256(
                    stderr_text.encode('utf-8'),
                ).hexdigest()[:15], 16),
            }, ensure_ascii=False).encode('utf-8') + b'\n'
        path = os.path.join(trace_dir, 'codex_agent_judge.jsonl')
    else:
        visible_lines = []
        for raw_line in stdout.splitlines():
            log_offset, content = _split_docker_log_line(raw_line)
            line = _trace_text(content).strip()
            if line:
                visible_lines.append((log_offset, line))
        stderr = _sanitize_trace_payload(
            getattr(logs, 'stderr', b''), api_key=api_key,
            extra_secrets=extra_secrets,
        )
        for raw_line in stderr.splitlines():
            log_offset, content = _split_docker_log_line(raw_line)
            line = _trace_text(content).strip()
            if line:
                visible_lines.append((log_offset, '[stderr] ' + line))
        payload_parts = []
        for log_offset, line in visible_lines:
            payload_parts.append(json.dumps({
                'type': 'assistant_message', 'message': line, 'model': 'opencode',
                '_trace_source': 'opencode-logs',
                '_trace_offset': log_offset,
            }, ensure_ascii=False).encode('utf-8') + b'\n')
        payload = b''.join(payload_parts)
        path = os.path.join(trace_dir, 'opencode_agent_judge.jsonl')
    return _atomic_write_trace(path, payload) if payload else False


def _prepare_agent_trace_attempt(submission_id, attempt_id):
    trace_dir = agent_judge_trace_dir(submission_id, attempt_id)
    root = os.path.dirname(trace_dir)
    current_name = os.path.basename(trace_dir)
    try:
        os.makedirs(root, exist_ok=True)
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if name != current_name and os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
        if os.path.isdir(trace_dir):
            shutil.rmtree(trace_dir, ignore_errors=True)
        os.makedirs(trace_dir, exist_ok=True)
    except Exception:
        os.makedirs(trace_dir, exist_ok=True)
    return trace_dir


def _exec_harness_phase(container_name, ws, phase, prompt, timeout_s,
                        resume_session_id=None, result_filename=None):
    args = [
        'docker', 'exec', '-i',
        '-e', 'DEBIAN_FRONTEND=noninteractive',
        '-e', f'AJ_PHASE={phase}',
        '-e', 'AJ_SESSION_STATE=/workspace/.aj_session_state.json',
    ]
    if resume_session_id:
        args.extend(['-e', f'AJ_RESUME_SESSION_ID={resume_session_id}'])
    if result_filename:
        args.extend(['-e', f'AJ_RESULT_FILE=/workspace/{result_filename}'])
    args.extend([
        container_name, 'bash', '-lc',
        'IFS= read -r -d "" AJ_PROMPT || true; export AJ_PROMPT; run_harness',
    ])
    proc = _run_process_with_input_limited(
        args, prompt or '', timeout=max(1, int(timeout_s)),
    )
    return proc


def _exec_container_apt_setup(container_name, timeout_s=120):
    """在后续 docker exec phase 的同类环境里同步重建 apt 索引。"""
    return subprocess.run(
        [
            'docker', 'exec',
            '-e', 'DEBIAN_FRONTEND=noninteractive',
            container_name, 'bash', '-lc',
            'apt-get update >/tmp/aj_apt_setup.log 2>&1 || true',
        ],
        check=True, capture_output=True, text=True,
        timeout=max(1, int(timeout_s)),
    )


def _ingest_result_file(submission_id, attempt_id, result_path, allowed_rule_ids, seen):
    allowed = {int(x) for x in allowed_rule_ids}
    parsed_by_id = {}
    raw = _read_untrusted_regular_file(result_path, _UNTRUSTED_RESULT_MAX_BYTES)
    lines = (raw or b'').decode('utf-8', 'replace').splitlines()
    for line in lines:
        parsed = aj.parse_result_line(line)
        if not parsed or parsed['rule_id'] not in allowed or parsed['rule_id'] in seen:
            continue
        seen.add(parsed['rule_id'])
        raw = parsed['result']
        affected = upsert_judge_result_for_attempt(
            submission_id, attempt_id, parsed['rule_id'], raw, raw, 0.0, parsed['evidence'],
        )
        if affected <= 0:
            return parsed_by_id, False
        parsed_by_id[parsed['rule_id']] = parsed
        _publish_snapshot(submission_id)
    return parsed_by_id, True


def _write_backend_rule_effect(submission_id, attempt_id, rule_id, effective, evidence):
    affected = upsert_judge_result_for_attempt(
        submission_id, attempt_id, rule_id, None, effective, 0.0, evidence,
    )
    if affected > 0:
        _publish_snapshot(submission_id)
    return affected


def _run_container_and_tail(submission_id, ws, result_name, competition, rules, timeout_s,
                            endpoint=None, attempt_id=None, trace_dir=None):
    """起 docker 容器跑所选 Agent Harness，tail 随机结果文件，逐条 upsert + 广播。
    返回 (timed_out, container_ok)。可被集成测试整体 monkeypatch。
    轨迹经脱敏后写入 attempt 隔离的受信任目录，不再把含凭据风险的原始会话目录
    复制回选手 workspace。endpoint：本次使用的模型端点
    （harness/base_url/api_key/model）。"""
    harness, base_url, api_key, model = _resolve_harness_config(endpoint)
    trace_dir = trace_dir or os.path.join(ws, 'agent_trace')
    os.makedirs(trace_dir, exist_ok=True)
    prompt = aj.build_prompt(competition.get('title'), result_name)
    container_name = _agent_judge_container_name(submission_id, attempt_id)
    # 同名残留容器（上次 worker 被杀留下的孤儿、或异常未清的旧容器）先强制清掉，否则下面
    # docker run 同名会冲突。去掉 --rm 后（容器退出不再自动删），这一步尤其必要。
    try:
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
    except Exception:
        pass
    docker_args = _docker_container_args(
        container_name, ws, harness, base_url, api_key, model, result_name,
        include_prompt=True, endpoint=endpoint,
    ) + [
        'bash', '-lc',
        # 启动 claude 前先 apt-get update：镜像各 apt 层都清空了 /var/lib/apt/lists，判题时
        # apt-get install 会报「Unable to locate package」；这里只重建包索引（不做 upgrade，避免
        # 拖慢/扰动已固定的包版本），使判题 Agent 能按需现装环境包（如 xvfb/x11 等无头 GUI 依赖）。
        # DEBIAN_FRONTEND=noninteractive 也会被 claude 继承，其后续 apt-get install 同样不卡交互。
        # 失败不阻断（|| true），随后照常启动 claude；apt 输出落到容器内 /tmp（随容器回收丢弃）。
        'export DEBIAN_FRONTEND=noninteractive; '
        'apt-get update >/tmp/aj_apt_setup.log 2>&1 || true; '
        'run_harness || true',
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
    last_trace_sync = 0.0
    timed_out = False
    try:
        while True:
            if not _attempt_still_current(submission_id, attempt_id):
                try:
                    subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
                except Exception:
                    pass
                return (False, True)
            now = time.time()
            if now - last_trace_sync >= JUDGE_TRACE_SYNC_INTERVAL:
                changed = _sync_live_execution_trace(
                    container_name, ws, trace_dir, harness,
                    api_key=api_key, extra_secrets=(result_name, base_url),
                )
                last_trace_sync = now
                if changed:
                    _publish_snapshot(submission_id)
            _, current = _ingest_result_file(
                submission_id, attempt_id, result_path, rule_ids, seen,
            )
            if not current:
                try:
                    subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
                except Exception:
                    pass
                return (False, True)
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
        if _attempt_still_current(submission_id, attempt_id):
            if _sync_live_execution_trace(
                    container_name, ws, trace_dir, harness,
                    api_key=api_key, extra_secrets=(result_name, base_url)):
                _publish_snapshot(submission_id)
        try:
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
        except Exception:
            pass
    return (timed_out, True)


def _run_container_topological(submission_id, ws, result_name, competition, rules, timeout_s,
                               endpoint=None, attempt_id=None, trace_dir=None):
    """拓扑编排模式：一个常驻容器，多次 docker exec resume 同一 harness 会话。

    后端只在前置依赖 effective=pass 时调用 Agent；失败、跳过、错误都会直接把后继规则
    标为 skipped。每个 Agent 阶段只采纳当前 rule_id 的 report，避免模型提前上报未来规则。
    """
    harness, base_url, api_key, model = _resolve_harness_config(endpoint)
    trace_dir = trace_dir or os.path.join(ws, 'agent_trace')
    os.makedirs(trace_dir, exist_ok=True)
    container_name = _agent_judge_container_name(submission_id, attempt_id)
    try:
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
    except Exception:
        pass
    docker_args = _docker_container_args(
        container_name, ws, harness, base_url, api_key, model, result_name,
        include_prompt=False, endpoint=endpoint,
    ) + [
        'bash', '-lc', 'tail -f /dev/null',
    ]
    try:
        subprocess.run(docker_args, check=True, capture_output=True, text=True, timeout=120)
        _exec_container_apt_setup(container_name, timeout_s=120)
    except Exception:
        try:
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
        except Exception:
            pass
        return (False, False)

    seen = set()
    by_id = {int(r['rule_id']): r for r in rules}
    effective = {}
    session_id = None
    start = time.time()
    timed_out = False
    trace_lock = threading.Lock()
    trace_monitor_stop = threading.Event()
    trace_monitor_thread = None
    current_trace_phase = {'value': 'setup'}

    def _remaining():
        return max(0.0, float(timeout_s) - (time.time() - start))

    def _record_trace(phase, proc=None, extra_result_name=None):
        if not _attempt_still_current(submission_id, attempt_id):
            return False
        with trace_lock:
            if not _attempt_still_current(submission_id, attempt_id):
                return False
            secrets_to_redact = tuple(
                value for value in (
                    result_name, extra_result_name, base_url,
                ) if value
            )
            if harness == HARNESS_CLAUDE_CODE:
                changed = _sync_claude_execution_trace(
                    container_name, ws, trace_dir,
                    api_key=api_key, extra_secrets=secrets_to_redact,
                    default_phase=phase,
                )
            else:
                changed = False
                if proc is not None:
                    changed = _append_phase_execution_trace(
                        trace_dir, harness, phase, proc,
                        api_key=api_key, extra_secrets=secrets_to_redact,
                    )
            if changed:
                _publish_snapshot(submission_id)
            return changed

    def _monitor_trace():
        while not trace_monitor_stop.wait(JUDGE_TRACE_SYNC_INTERVAL):
            _record_trace(current_trace_phase['value'])

    if harness == HARNESS_CLAUDE_CODE:
        trace_monitor_thread = threading.Thread(
            target=_monitor_trace,
            name=f'agent-judge-trace-{submission_id}',
            daemon=True,
        )
        trace_monitor_thread.start()

    try:
        if not _attempt_still_current(submission_id, attempt_id):
            return (False, True)
        if _remaining() <= 0:
            return (True, True)
        try:
            setup_proc = _exec_harness_phase(
                container_name, ws, 'setup',
                aj.build_setup_prompt(competition.get('title')),
                _remaining(),
            )
            _record_trace('setup', setup_proc)
            session_id = _read_session_id(ws)
        except subprocess.TimeoutExpired as e:
            _record_trace('setup', e)
            timed_out = True
            try:
                subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
            except Exception:
                pass
            return (timed_out, True)

        for rid in aj.topo_order(rules):
            if not _attempt_still_current(submission_id, attempt_id):
                try:
                    subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
                except Exception:
                    pass
                return (False, True)
            if _remaining() <= 0:
                timed_out = True
                try:
                    subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
                except Exception:
                    pass
                break

            rule = by_id[rid]
            blocked = [dep for dep in rule.get('dependencies') or []
                       if effective.get(int(dep)) != aj.EFF_PASS]
            if blocked:
                evidence = (
                    '后端按拓扑序编排评测：前置规则 '
                    + ', '.join(str(x) for x in blocked)
                    + ' 未通过或未完成，因此本规则跳过，得 0 分。'
                )
                if _write_backend_rule_effect(
                    submission_id, attempt_id, rid, aj.EFF_SKIPPED, evidence,
                ) <= 0:
                    return (False, True)
                effective[rid] = aj.EFF_SKIPPED
                continue

            try:
                phase_result_name = f'{result_name}.rule_{rid}.jsonl'
                _reset_untrusted_output_file(os.path.join(ws, phase_result_name))
                current_trace_phase['value'] = f'rule_{rid}'
                proc = _exec_harness_phase(
                    container_name, ws, f'rule_{rid}',
                    aj.build_rule_prompt(competition.get('title'), rule, phase_result_name),
                    _remaining(),
                    resume_session_id=session_id,
                    result_filename=phase_result_name,
                )
                _record_trace(f'rule_{rid}', proc, phase_result_name)
                session_id = _read_session_id(ws) or session_id
            except subprocess.TimeoutExpired as e:
                _record_trace(f'rule_{rid}', e, phase_result_name)
                timed_out = True
                try:
                    subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
                except Exception:
                    pass
                break

            parsed, current = _ingest_result_file(
                submission_id, attempt_id, os.path.join(ws, phase_result_name), {rid}, seen,
            )
            if not current:
                try:
                    subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
                except Exception:
                    pass
                return (False, True)
            raw = (parsed.get(rid) or {}).get('result')
            if raw == aj.RESULT_PASS:
                effective[rid] = aj.EFF_PASS
            elif raw == aj.RESULT_FAILED:
                effective[rid] = aj.EFF_FAILED
            else:
                evidence = (
                    f'Agent 本轮未按要求上报规则 {rid} 的结果；'
                    f'run_harness 退出码 {getattr(proc, "returncode", "unknown")}。'
                )
                if _write_backend_rule_effect(
                    submission_id, attempt_id, rid, aj.EFF_ERROR, evidence,
                ) <= 0:
                    return (False, True)
                effective[rid] = aj.EFF_ERROR
    finally:
        trace_monitor_stop.set()
        if trace_monitor_thread is not None:
            trace_monitor_thread.join(timeout=10)
        current_trace_phase['value'] = 'final'
        if _attempt_still_current(submission_id, attempt_id):
            _record_trace('final')
        try:
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
        except Exception:
            pass
    return (timed_out, True)


def _finalize(submission_id, rules, timed_out, container_ok, attempt_id=None):
    """终态：拓扑重算 effective+score，回写 effective、提交分数与状态，广播 done。"""
    if not _attempt_still_current(submission_id, attempt_id):
        return {'success': True, 'message': '旧评测 attempt，跳过 finalize'}
    raw_rows = list_judge_results(submission_id)
    raw_by_id = {int(r['rule_id']): r.get('raw_result') for r in raw_rows
                 if r.get('raw_result') in (aj.RESULT_PASS, aj.RESULT_FAILED)}
    evidence_by_id = {int(r['rule_id']): (r.get('evidence') or '') for r in raw_rows}
    computed = aj.compute_results(rules, raw_by_id, finalize=True) if rules else {}
    for rid, c in computed.items():
        raw = raw_by_id.get(rid)
        upsert_judge_result_for_attempt(
            submission_id, attempt_id, rid, raw, c['effective'], c['score'],
            evidence_by_id.get(rid, ''),
        )
    total = aj.total_score(computed)
    maxs = aj.max_score(rules) if rules else 0.0
    if not container_ok and not raw_by_id:
        _write_error_for_attempt(submission_id, attempt_id, '评测容器启动失败')
    elif not raw_by_id:
        # 容器跑了但没有任何规则结果上报：基本是模型端故障 / Agent 崩溃 / 超时未产出，
        # 判为 Error 而非 Accepted 0 分，避免在基础设施异常时把选手误判 0 分污染榜单（可重测）。
        _write_error_for_attempt(
            submission_id, attempt_id,
            ('评测超时且未产出任何结果' if timed_out else '评测未产出任何结果（模型或 Agent 异常）'),
        )
    else:
        details = {'total_score': total, 'max_score': maxs, 'timed_out': timed_out,
                   'rules': [{'rule_id': rid, 'effective': c['effective'], 'score': c['score']}
                             for rid, c in computed.items()]}
        update_submission_result_for_attempt(
            submission_id, attempt_id, total, 'Accepted', grade_details=details,
        )
    _publish_snapshot(submission_id)
    return {'success': True}


def _judge(submission_id, endpoint=None, attempt_id=None):
    submission = get_ranking_submission(submission_id)
    if not submission:
        return {'success': False, 'message': '提交不存在'}
    skip, skip_msg = _task_should_skip(submission, attempt_id)
    if skip:
        return {'success': True, 'message': skip_msg}
    # 评测 worker 已取到本任务并开始执行 → 置「评测中」。在此之前（入队后、被取到前）提交为
    # 'Queued'（等待评测）。judge 队列 worker 并发上限为 2，故同时最多 2 个显示「评测中」，其余排队显示「等待评测」。
    if set_submission_status_for_attempt(submission_id, attempt_id, 'Judging') <= 0:
        return {'success': True, 'message': '旧评测 attempt，跳过'}
    competition = get_competition(submission.get('competition_id'))
    if not competition:
        _write_error_for_attempt(submission_id, attempt_id, '比赛不存在')
        return {'success': False, 'message': '比赛不存在'}
    rules = list_competition_rules(competition['id'])
    clear_judge_results_for_attempt(submission_id, attempt_id)
    _publish_snapshot(submission_id)
    if not rules:
        update_submission_result_for_attempt(
            submission_id, attempt_id, 0.0, 'Accepted',
            grade_details={'total_score': 0, 'max_score': 0, 'note': '未配置评分规则'},
        )
        _publish_snapshot(submission_id)
        return {'success': True, 'score': 0.0}
    timeout_s = int(competition.get('agent_judge_timeout_seconds') or JUDGE_DEFAULT_TIMEOUT)
    current_container = _agent_judge_container_name(submission_id, attempt_id)
    _remove_stale_agent_containers(submission_id, current_container)
    ws, result_name = _prepare_workspace(
        submission, competition, rules, attempt_id,
    )
    _prune_stale_attempt_workspaces(submission_id, ws)
    trace_dir = _prepare_agent_trace_attempt(submission_id, attempt_id)
    _publish_snapshot(submission_id)
    orchestration_mode = aj.normalize_orchestration_mode(
        competition.get('agent_judge_orchestration_mode')
    )
    # 端点预检仍在宿主侧使用真实配置；从这里进入参赛执行域后，单阶段和
    # 拓扑阶段统一只接收本 attempt 的短生命周期 relay 地址与临时凭据。
    with _agent_judge_endpoint_relay(endpoint) as container_endpoint:
        if orchestration_mode == aj.ORCH_TOPOLOGICAL:
            timed_out, container_ok = _run_container_topological(
                submission_id, ws, result_name, competition, rules, timeout_s,
                container_endpoint, attempt_id, trace_dir)
        else:
            timed_out, container_ok = _run_container_and_tail(
                submission_id, ws, result_name, competition, rules, timeout_s,
                container_endpoint, attempt_id, trace_dir)
    _finalize(submission_id, rules, timed_out, container_ok, attempt_id)
    return {'success': True}


def register_ranking_agent_judge_task(celery_app):
    @celery_app.task(name=RANKING_AGENT_JUDGE_TASK_NAME, bind=True)
    def evaluate_ranking_agent_judge(self, submission_id, attempt_id=None):
        sid = int(submission_id)
        attempt_id = _normalize_attempt_id(attempt_id)
        client = _ensure_judge_redis()
        submission = get_ranking_submission(sid)
        if not submission:
            return {'success': False, 'message': '提交不存在'}
        skip, skip_msg = _task_should_skip(submission, attempt_id)
        if skip:
            return {'success': True, 'message': skip_msg}
        try:
            set_agent_judge_task_id(sid, attempt_id, self.request.id)
        except Exception:
            pass
        competition = get_competition(submission.get('competition_id'))
        if not competition:
            _write_error_for_attempt(sid, attempt_id, '比赛不存在')
            _publish_snapshot(sid)
            return {'success': False, 'message': '比赛不存在'}
        skip, skip_msg = _task_should_skip(submission, attempt_id, competition=competition)
        if skip:
            return {'success': True, 'message': skip_msg}

        if _fake_agent_judge_enabled():
            return _finish_fake_agent_judge(sid, attempt_id, competition)

        # 端点池是唯一模型配置入口；未配置则判 Error（避免无限重排）。
        endpoints = _resolve_endpoints(competition['id'], competition)
        if not endpoints:
            _write_error_for_attempt(sid, attempt_id, '未配置 Agent 评测端点（请在比赛设置里添加模型端点）')
            _publish_snapshot(sid)
            return {'success': False, 'message': '未配置评测端点'}

        # 抢端点并发槽位；全满 → 延迟重排（提交保持「等待评测」，不占用 worker）。
        ttl = int(competition.get('agent_judge_timeout_seconds') or JUDGE_DEFAULT_TIMEOUT) + JUDGE_SLOT_TTL_BUFFER
        ep, slot_key, slot_token = _acquire_endpoint_slot(client, endpoints, sid, ttl)
        if ep is None:
            return _retry_queued_submission(self, sid, attempt_id)

        # 已拿到槽位 → 取幂等锁（防同一提交被并发重复评测）。
        lock_key = f'ranking:judge:lock:{sid}:{attempt_id or "legacy"}'
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
        failed_endpoint_ids = set()
        try:
            while True:
                # 幂等复查：拿到锁后再读一次状态。acks_late=True 下，worker 被杀的任务会被 broker
                # 重投，同时 runtime.pending_recovery 也会补入队 —— 两条恢复消息并发时由锁互斥（只一条评测），
                # 但「顺序」到达（前者评完释放锁后后者才跑）会重复评测。这里若发现已判到终态就跳过，
                # 彻底消除顺序重投导致的重复评测；Queued/Judging 均为非终态，不受影响。
                fresh = get_ranking_submission(sid)
                skip, skip_msg = _task_should_skip(fresh, attempt_id, competition=competition)
                if skip:
                    return {'success': True, 'message': skip_msg}

                ok, probe_msg = _probe_endpoint(ep)
                if ok:
                    return _judge(sid, ep, attempt_id)

                failed_endpoint_ids.add(int(ep.get('id')))
                _disable_unhealthy_endpoint(ep, probe_msg)
                _release_slot(client, slot_key, slot_token)
                slot_key = None
                slot_token = None

                endpoints = [e for e in _resolve_endpoints(competition['id'], competition)
                             if int(e.get('id')) not in failed_endpoint_ids]
                if not endpoints:
                    _write_error_for_attempt(
                        sid, attempt_id,
                        '所有 Agent 评测端点 hello 预检失败，已自动暂停；请检查端点配置后重测',
                    )
                    _publish_snapshot(sid)
                    return {'success': False, 'message': '所有端点预检失败'}

                ep, slot_key, slot_token = _acquire_endpoint_slot(client, endpoints, sid, ttl)
                if ep is None:
                    return _retry_queued_submission(self, sid, attempt_id)
        except Retry:
            raise
        except Exception as e:
            try:
                _write_error_for_attempt(sid, attempt_id, f'评测任务异常：{e}')
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
