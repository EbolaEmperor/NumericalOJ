"""Judge 端点池、短任务编排与记分；所有模型执行交给通用 Agent。"""

import json
import os
import random
import secrets
import time
import urllib.error
import urllib.request
import zipfile

from pathlib import Path
from tempfile import TemporaryDirectory

from backend.oj_modules.agents.judge import judge_session_id, submit_judge_turn
from backend.oj_modules.agents.sessions import (
    get_agent_session, get_agent_session_by_task_id, get_agent_session_turns,
)
from backend.oj_modules.agents.workspace import open_agent_workspace_file
from backend.oj_modules.tasks.agent.control import build_agent_run_terminator
from backend.oj_modules.tasks.agent.shared import get_agent_run_snapshot


try:
    from celery.exceptions import MaxRetriesExceededError, Retry
except Exception:  # pragma: no cover
    class MaxRetriesExceededError(Exception):
        pass
    class Retry(Exception):
        pass

from backend.oj_modules import config as _cfg

from backend.oj_modules.shared.archive import ArchiveExtractionError, ZipExtractionPolicy, extract_zip

from backend.oj_modules.ranking.agent_judge import rules as aj

from backend.oj_modules.infrastructure.redis import (
    RedisClientProfile,
    create_optional_redis_client,
)

from backend.oj_modules.ranking.db import (
    get_competition, get_ranking_submission, list_competition_files,
    set_agent_judge_task_id, set_submission_status_for_attempt,
    update_submission_result_for_attempt,
)

from backend.oj_modules.ranking.agent_judge.db import (
    ENDPOINT_STATUS_PAUSED,
    HARNESS_CLAUDE_CODE, HARNESS_PI,
    agent_judge_trace_id,
    build_judge_snapshot, clear_judge_results_for_attempt,
    list_agent_judge_endpoints, list_competition_rules, list_judge_results,
    infer_agent_endpoint_protocol, normalize_endpoint_model_capabilities,
    list_paused_agent_judge_endpoints, pause_agent_judge_endpoint,
    resume_paused_agent_judge_endpoint, upsert_judge_result_for_attempt,
)

RANKING_AGENT_JUDGE_TASK_NAME = 'oj.ranking_agent_judge'

RANKING_AGENT_JUDGE_PAUSED_PROBE_TASK_NAME = 'oj.ranking_agent_judge_paused_probe'

def _config_value(name, default):
    env_value = os.environ.get(name)
    if env_value is not None and str(env_value).strip() != '':
        return env_value
    return getattr(_cfg, name, default)

JUDGE_IMAGE = _config_value('AGENT_JUDGE_DOCKER_IMAGE', 'numericaloj-agent-judge:latest')


JUDGE_DEFAULT_TIMEOUT = int(_config_value('AGENT_JUDGE_DEFAULT_TIMEOUT', 1800))

JUDGE_MEM_LIMIT = _config_value('AGENT_JUDGE_MEM_LIMIT', '4g')

JUDGE_CPU_LIMIT = str(_config_value('AGENT_JUDGE_CPU_LIMIT', '2'))

JUDGE_PIDS_LIMIT = str(_config_value('AGENT_JUDGE_PIDS_LIMIT', '512'))


JUDGE_PROGRESS_TTL = int(_config_value('AGENT_JUDGE_PROGRESS_TTL', 21600))


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
            'competition_id': competition_id,
            'harness': endpoint.get('harness') or HARNESS_CLAUDE_CODE,
            'protocol': endpoint.get('protocol'),
            'base_url': endpoint['base_url'],
            'api_key': endpoint['api_key'],
            'model': endpoint.get('model') or '',
            'thinking_format': endpoint.get('thinking_format'),
            **{key: endpoint.get(key, 0) for key in (
                'input_price_per_million', 'cached_input_price_per_million', 'output_price_per_million',
            )},
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

def _release_slot(client, slot_key, token):
    if client is None or not slot_key:
        return
    try:
        client.eval(_RELEASE_LUA, 1, slot_key, token)   # CAS 释放，避免误删他人槽位
    except Exception:
        pass

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


def _write_backend_rule_effect(submission_id, attempt_id, rule_id, effective, evidence):
    affected = upsert_judge_result_for_attempt(
        submission_id, attempt_id, rule_id, None, effective, 0.0, evidence,
    )
    if affected > 0:
        _publish_snapshot(submission_id)
    return affected

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
        _write_error_for_attempt(submission_id, attempt_id, '通用 Agent 启动失败')
    elif not raw_by_id:
        # 没有任何规则结果上报时属于模型故障 / Agent 失败 / 超时，
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



def _slot_owner(token):
    text = token.decode() if isinstance(token, bytes) else str(token or '')
    parts = text.split('|', 2)
    return (parts[2], float(parts[1])) if len(parts) == 3 and parts[0] == 'turn' else ('', 0)


def _slot_finished(token):
    """只回收确认完成的轮次；尚无会话的材料准备预留不能按时间回收。"""
    owner, _reserved_at = _slot_owner(token)
    if not owner:
        return False
    session = get_agent_session_by_task_id(owner)
    if not session:
        # 尚在注入文件或 worker 已中断的预留只由同 attempt 恢复/停止处理。
        return False
    turn = next((row for row in get_agent_session_turns(session['session_id'])
                 if row['task_id'] == owner), None)
    return bool(turn and str(turn.get('status')).lower() in {
        'completed', 'failed',
    })


def _acquire_endpoint_slot(client, endpoints, submission_id, ttl, *, owner=None):
    """端点池放行后保留名额到通用轮次终态，Redis 不可用时停止派发。"""
    if client is None or not endpoints:
        return None, None, None
    order = list(endpoints)
    random.shuffle(order)
    token = f'turn|{time.time()}|{owner}' if owner else f'{submission_id}:{secrets.token_hex(4)}'
    for endpoint in order:
        for index in range(max(1, int(endpoint.get('concurrency_limit') or 1))):
            key = _slot_key(endpoint['id'], index)
            existing = client.get(key)
            if existing:
                current_owner, _ = _slot_owner(existing)
                if owner and current_owner == owner:
                    return endpoint, key, existing
                if _slot_finished(existing):
                    _release_slot(client, key, existing)
            options = {'nx': True} if owner else {'nx': True, 'ex': int(ttl)}
            if client.set(key, token, **options):
                return endpoint, key, token
    return None, None, None


def _slot_reservation_matches(client, slot_key, token):
    actual = client.get(slot_key)
    normalize = lambda value: value.decode() if isinstance(value, bytes) else value
    return actual is not None and normalize(actual) == normalize(token)


def _release_task_slot(client, task_id):
    if client is None:
        return
    for key in client.scan_iter(match='aj:ep:*:slot:*', count=200):
        token = client.get(key)
        owner, _ = _slot_owner(token)
        if owner == task_id:
            _release_slot(client, key, token)


def _judge_input_files(submission, competition, rules, staging):
    """仅在宿主临时目录解包，随后由通用 workspace 复制输入。"""
    staging = Path(staging)
    source = submission.get('code_path')
    files = {
        'description.md': str(competition.get('description') or '').encode(),
        'rules.json': json.dumps(aj.build_rules_json(rules), ensure_ascii=False).encode(),
    }
    if source:
        if str(source).lower().endswith('.zip') or zipfile.is_zipfile(source):
            unpacked = staging / 'submission'
            _safe_extract_zip(source, str(unpacked))
            files.update({f'submission/{path.relative_to(unpacked).as_posix()}': path
                          for path in unpacked.rglob('*') if path.is_file()})
        else:
            files[f'submission/{Path(source).name}'] = Path(source)
    for attachment in list_competition_files(competition['id']) or ():
        source = attachment.get('stored_path')
        if source:
            name = Path(attachment.get('filename') or source).name
            files[f'attachment/{name}'] = Path(source)
    return files


def _parse_rule_conclusion(conclusion, rule_id):
    """仅兼容部署前已发送的旧回复协议，不用于新轮次。"""
    text = str(conclusion or '').strip()
    if text.startswith('```') and text.endswith('```'):
        text = text.split('\n', 1)[-1].rsplit('```', 1)[0].strip()
    result = aj.parse_result_line(text)
    return result if result and result['rule_id'] == int(rule_id) else None


def _read_judge_result(session_id, filename):
    """运行中可能正在替换模板；尚未写完整时等下次编排读取。"""
    try:
        stream, _metadata = open_agent_workspace_file(session_id, filename)
        with stream:
            data = stream.read(_UNTRUSTED_RESULT_MAX_BYTES + 1)
        if len(data) > _UNTRUSTED_RESULT_MAX_BYTES:
            return None
        return json.loads(data)
    except (OSError, ValueError, UnicodeError):
        return None


def _ingest_single_results(submission_id, attempt, session_id, rules):
    data = _read_judge_result(session_id, 'judge_results.json')
    if not isinstance(data, list):
        return True
    known = {int(rule['rule_id']): rule for rule in rules}
    raw = {int(row['rule_id']): row['raw_result'] for row in list_judge_results(submission_id)
           if row.get('raw_result') in (aj.RESULT_PASS, aj.RESULT_FAILED)}
    accepted = []
    for item in data:
        result = aj.parse_result_line(json.dumps(item, ensure_ascii=False))
        if not result or result['rule_id'] not in known or result['rule_id'] in raw:
            continue
        raw[result['rule_id']] = result['result']
        accepted.append(result)
    effects = aj.compute_results(rules, raw)
    for result in accepted:
        rid = result['rule_id']
        if upsert_judge_result_for_attempt(submission_id, attempt, rid, result['result'],
                effects[rid]['effective'], effects[rid]['score'], result['evidence']) <= 0:
            return False
    if accepted:
        _publish_snapshot(submission_id)
    return True


def _wait_for_judge_turn(task, submission_id, attempt_id, *, queued=False):
    set_submission_status_for_attempt(submission_id, attempt_id, 'Queued' if queued else 'Judging')
    _publish_snapshot(submission_id)
    raise task.retry(countdown=JUDGE_QUEUE_RETRY_BASE, max_retries=None)


def _dispatch_judge_phase(task, client, submission, competition, rules, session, phase, prompt):
    sid, attempt = submission['id'], submission.get('judge_attempt_id')
    session_id = judge_session_id(sid, attempt, 'agent_judge')
    task_id = f'{session_id}-{phase}'
    endpoints = _resolve_endpoints(competition['id'], competition)
    # 续聊始终绑定最初放行的端点；暂停后在池侧等待管理员/探活恢复。
    if session:
        endpoints = [ep for ep in endpoints if int(ep['id']) == int(session['endpoint_id'])]
    if not endpoints:
        configured = list_agent_judge_endpoints(competition['id'])
        if session and not any(int(ep['id']) == int(session['endpoint_id']) for ep in configured):
            raise ValueError('本会话绑定的评测端点已被删除，请重新评测')
        if configured:
            return _wait_for_judge_turn(task, sid, attempt, queued=True)
        raise ValueError('未配置 Agent 评测端点')
    endpoint, slot, token = _acquire_endpoint_slot(
        client, endpoints, sid, JUDGE_DEFAULT_TIMEOUT, owner=task_id,
    )
    if endpoint is None:
        return _wait_for_judge_turn(task, sid, attempt, queued=True)
    dispatched = False
    try:
        ok, message = _probe_endpoint(endpoint)
        if not ok:
            _disable_unhealthy_endpoint(endpoint, message)
            return _wait_for_judge_turn(task, sid, attempt, queued=True)
        timeout = int(competition.get('agent_judge_timeout_seconds') or JUDGE_DEFAULT_TIMEOUT)
        with TemporaryDirectory(prefix='numoj-judge-') as staging:
            files = None if session else _judge_input_files(submission, competition, rules, staging)
            if phase == 'single':
                template = [{'rule_id': int(rule['rule_id']), 'result': None, 'evidence': ''} for rule in rules]
                files = {**(files or {}), 'judge_results.json': json.dumps(template, ensure_ascii=False, indent=2).encode()}
            elif phase.startswith('rule-'):
                rid = int(phase.removeprefix('rule-'))
                files = {f'judge_result_{rid}.json': json.dumps({'rule_id': rid, 'result': None, 'evidence': ''}, indent=2).encode()}
            submit_judge_turn(
                session_id=session_id, task_id=task_id, requested_by=submission['username'],
                judge_kind='agent_judge', submission_id=sid, attempt_id=attempt,
                competition_id=competition['id'], harness=endpoint['harness'],
                endpoint=endpoint, prompt=prompt, files=files,
                title=f'Judge · {competition.get("title") or sid}'[:64],
                timeout_seconds=timeout, celery_app=task.app,
                dispatch_guard=lambda: (
                    _attempt_still_current(sid, attempt) and _slot_reservation_matches(client, slot, token)
                ),
            )
        dispatched = True
    finally:
        # 提交结果未知时查询持久会话；已经创建的 outbox 仍占端点池名额。
        if not dispatched and not get_agent_session_by_task_id(task_id):
            _release_slot(client, slot, token)
    return _wait_for_judge_turn(task, sid, attempt)


def _advance_agent_judge(task, client, submission, competition):
    sid, attempt = submission['id'], submission.get('judge_attempt_id')
    rules = list_competition_rules(competition['id'])
    if not rules:
        update_submission_result_for_attempt(sid, attempt, 0, 'Accepted', grade_details={'rules': []})
        return {'success': True}
    session_id = judge_session_id(sid, attempt, 'agent_judge')
    session = get_agent_session(session_id)
    if not session:
        single = aj.normalize_orchestration_mode(competition.get('agent_judge_orchestration_mode')) == aj.ORCH_SINGLE
        return _dispatch_judge_phase(task, client, submission, competition, rules, None,
                                     'single' if single else 'setup',
                                     aj.build_prompt(competition.get('title')) if single else aj.build_setup_prompt(competition.get('title')))
    turns = {turn['task_id']: turn for turn in get_agent_session_turns(session_id)}
    current = turns.get(session['current_task_id'])
    status = str((current or {}).get('status') or '').lower()
    if status in {'cleanupfailed', 'cleanup_failed'}:
        raise ValueError('通用 Agent 清理失败，端点名额保留，需管理员处理')
    # 已开始的会话按实际首轮固定模式，管理端改配置只影响下一次评测。
    single = f'{session_id}-single' in turns
    if single and not _ingest_single_results(sid, attempt, session_id, rules):
        return {'success': True, 'message': '旧评测 attempt，跳过'}
    if status not in {'completed', 'failed', 'canceled', 'cancelled'}:
        return _wait_for_judge_turn(task, sid, attempt, queued=status == 'pending')
    _release_task_slot(client, session['current_task_id'])
    if single:
        snapshot = get_agent_run_snapshot(session['current_task_id']) or {}
        timed_out = (snapshot.get('harness_status') == 'timeout'
                     or session.get('message') == 'Agent harness 超时')
        return _finalize(sid, rules, timed_out, status == 'completed' or timed_out, attempt)
    if status != 'completed':
        raise ValueError(f'通用 Agent 轮次未完成：{session.get("message") or status}')
    raw_rows = {int(row['rule_id']): row for row in list_judge_results(sid)}
    by_id = {int(rule['rule_id']): rule for rule in rules}
    effective = {}
    for rid in aj.topo_order(rules):
        rule = by_id[rid]
        if rid in raw_rows:
            effective[rid] = raw_rows[rid].get('effective_result') or raw_rows[rid].get('raw_result')
            continue
        blocked = [dep for dep in rule.get('dependencies') or [] if effective.get(int(dep)) != aj.EFF_PASS]
        if blocked:
            if _write_backend_rule_effect(sid, attempt, rid, aj.EFF_SKIPPED,
                    '前置规则 ' + ', '.join(map(str, blocked)) + ' 未通过，本规则跳过。') <= 0:
                return {'success': True, 'message': '旧评测 attempt，跳过'}
            effective[rid] = aj.EFF_SKIPPED
            continue
        turn = turns.get(f'{session_id}-rule-{rid}')
        if turn:
            if str(turn.get('user_message') or '').strip().endswith('多行证据使用 JSON 字符串转义。'):
                parsed = _parse_rule_conclusion(turn.get('conclusion'), rid)
            else:
                data = _read_judge_result(session_id, f'judge_result_{rid}.json')
                parsed = aj.parse_result_line(json.dumps(data, ensure_ascii=False))
                if parsed and parsed['rule_id'] != rid:
                    parsed = None
            raw = parsed['result'] if parsed else None
            effect = raw or aj.EFF_ERROR
            evidence = parsed['evidence'] if parsed else f'Agent 未在 judge_result_{rid}.json 中填写有效评分结果。'
            if upsert_judge_result_for_attempt(sid, attempt, rid, raw, effect,
                    float(rule.get('value') or 0) if raw == aj.RESULT_PASS else 0, evidence) <= 0:
                return {'success': True, 'message': '旧评测 attempt，跳过'}
            effective[rid] = effect
            _publish_snapshot(sid)
            continue
        prompt = aj.build_rule_prompt(
            competition.get('title'), rule,
            continuation=any(task_id.startswith(f'{session_id}-rule-') for task_id in turns),
        )
        return _dispatch_judge_phase(task, client, submission, competition, rules, session,
                                    f'rule-{rid}', prompt)
    return _finalize(sid, rules, False, True, attempt)


def register_ranking_agent_judge_task(celery_app):
    @celery_app.task(name=RANKING_AGENT_JUDGE_TASK_NAME, bind=True, max_retries=None)
    def evaluate_ranking_agent_judge(self, submission_id, attempt_id=None):
        sid = int(submission_id)
        attempt_id = _normalize_attempt_id(attempt_id)
        client = _ensure_judge_redis()
        if client is None:
            raise self.retry(countdown=JUDGE_QUEUE_RETRY_BASE)
        lock = f'ranking:judge:lock:{sid}:{attempt_id or "legacy"}'
        token = secrets.token_hex(16)
        if not client.set(lock, token, nx=True, ex=120):
            raise self.retry(countdown=JUDGE_QUEUE_RETRY_BASE)
        try:
            submission = get_ranking_submission(sid)
            skip, message = _task_should_skip(submission, attempt_id)
            if skip:
                session = get_agent_session(judge_session_id(sid, attempt_id, 'agent_judge'))
                if session and str(session.get('status')).lower() not in {
                    'completed', 'failed', 'canceled', 'cancelled', 'cleanupfailed',
                }:
                    result = build_agent_run_terminator(celery_app)(session['current_task_id'])
                    if not result.get('errors'):
                        _release_task_slot(client, session['current_task_id'])
                return {'success': True, 'message': message}
            set_agent_judge_task_id(sid, attempt_id, self.request.id)
            competition = get_competition(submission['competition_id'])
            if not competition:
                raise ValueError('比赛不存在')
            if _fake_agent_judge_enabled():
                return _finish_fake_agent_judge(sid, attempt_id, competition)
            return _advance_agent_judge(self, client, submission, competition)
        except Retry:
            raise
        except (ValueError, OSError, ArchiveExtractionError) as exc:
            _write_error_for_attempt(sid, attempt_id, f'评测任务异常：{exc}')
            _publish_snapshot(sid)
            return {'success': False, 'message': str(exc)}
        except Exception as exc:
            # 数据库/投递结果不明确时继续同一幂等轮次，不把活动会话遗留在终态提交下。
            raise self.retry(exc=exc, countdown=JUDGE_QUEUE_RETRY_BASE, max_retries=None)
        finally:
            _release_slot(client, lock, token)
    return evaluate_ranking_agent_judge
