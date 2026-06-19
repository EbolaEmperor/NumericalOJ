#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛 Agent-as-Judge 评测任务：起 Docker 容器跑所选 harness，tail result.jsonl 实时回传。"""
import json
import os
import random
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

try:
    import redis as _redis
except Exception:  # pragma: no cover
    _redis = None

try:
    from celery.exceptions import MaxRetriesExceededError, Retry
except Exception:  # pragma: no cover
    class MaxRetriesExceededError(Exception):
        pass
    class Retry(Exception):
        pass

import config as _cfg
from config import REDIS_DB, REDIS_HOST, REDIS_PORT
from oj_modules import ranking_agent_judge as aj
from oj_modules.ranking_db import (
    get_competition, get_ranking_submission, list_competition_files,
    set_agent_judge_task_id, set_submission_status_for_attempt,
    submission_dir, update_submission_result_for_attempt,
)
from oj_modules.ranking_agent_judge_db import (
    DEFAULT_OPENCODE_GO_BASE_URL, DEFAULT_OPENCODE_GO_MODEL,
    HARNESS_CLAUDE_CODE, HARNESS_CODEX, HARNESS_OPENCODE,
    build_judge_snapshot, clear_judge_results_for_attempt,
    list_agent_judge_endpoints, list_competition_rules, list_judge_results,
    set_agent_judge_endpoint_enabled, upsert_judge_result_for_attempt,
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
JUDGE_HELLO_RETRIES = 5
JUDGE_HELLO_TIMEOUT_SECONDS = max(1.0, float(getattr(_cfg, 'AGENT_JUDGE_HELLO_TIMEOUT_SECONDS', 8.0)))
JUDGE_HELLO_RETRY_SLEEP_SECONDS = max(0.0, float(getattr(_cfg, 'AGENT_JUDGE_HELLO_RETRY_SLEEP_SECONDS', 1.0)))
OPENCODE_GO_HELLO_MODEL = 'opencode-go/deepseek-v4-flash'
OPENCODE_HELLO_TIMEOUT_SECONDS = max(
    JUDGE_HELLO_TIMEOUT_SECONDS,
    float(getattr(_cfg, 'AGENT_JUDGE_OPENCODE_HELLO_TIMEOUT_SECONDS', 30.0)),
)

_judge_rds = None
_TERMINAL_STATUSES = {'Accepted', 'Error'}


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


# ---------- 多端点选择与 Redis 槽位限流 ----------

def _resolve_endpoints(competition_id, competition=None):
    """返回该比赛**启用的**判题端点（dict: id, base_url, api_key, model, concurrency_limit）。
    要求至少配置一个启用端点；为空则返回 []（判题侧据此置 Error）。不再回退到旧的比赛单端点字段。"""
    try:
        eps = list_agent_judge_endpoints(competition_id, enabled_only=True)
    except Exception:
        eps = []
    return [{'id': e['id'], 'harness': e.get('harness') or HARNESS_CLAUDE_CODE,
             'base_url': e['base_url'], 'api_key': e['api_key'],
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
    base_url = str(endpoint.get('base_url') or '').strip()
    api_key = str(endpoint.get('api_key') or '').strip()
    model = str(endpoint.get('model') or '').strip()
    if not base_url or not api_key or not model:
        return None, '端点 URL、API Key 或模型为空'

    if harness == HARNESS_CLAUDE_CODE:
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


def _opencode_probe_config_content():
    return json.dumps({
        '$schema': 'https://opencode.ai/config.json',
        'model': OPENCODE_GO_HELLO_MODEL,
        'small_model': OPENCODE_GO_HELLO_MODEL,
        'enabled_providers': ['opencode-go'],
        'provider': {
            'opencode-go': {
                'options': {
                    'apiKey': '{env:OPENCODE_API_KEY}',
                },
            },
        },
    }, ensure_ascii=False)


def _probe_opencode_once(endpoint):
    api_key = str(endpoint.get('api_key') or '').strip()
    if not api_key:
        return False, 'OpenCode Go API Key 为空'
    container_name = 'aj_opencode_probe_%s_%s' % (
        str(endpoint.get('id') or 'x').replace('-', '_'),
        secrets.token_hex(4),
    )
    try:
        env = os.environ.copy()
        env['OPENCODE_API_KEY'] = api_key
        env['OPENCODE_CONFIG_CONTENT'] = _opencode_probe_config_content()
        r = subprocess.run(
            [
                'docker', 'run', '--rm', '--name', container_name,
                '--security-opt', 'no-new-privileges',
                '--cap-drop', 'ALL',
                '--pids-limit', '128',
                '--memory', '512m',
                '--cpus', '1',
                '--read-only',
                '--tmpfs', '/tmp:rw,nosuid,size=128m',
                # 探针只用容器内 tmpfs 和环境变量注入配置；不挂载 OJ 代码、提交目录或 Docker socket。
                '-e', 'OPENCODE_API_KEY',
                '-e', 'OPENCODE_CONFIG_CONTENT',
                '-e', 'HOME=/tmp/opencode_home',
                '-e', 'XDG_CONFIG_HOME=/tmp/opencode_config',
                '-e', 'XDG_DATA_HOME=/tmp/opencode_data',
                '-e', 'XDG_STATE_HOME=/tmp/opencode_state',
                '-e', 'XDG_CACHE_HOME=/tmp/opencode_cache',
                JUDGE_IMAGE,
                'bash', '-lc',
                'mkdir -p /tmp/opencode_work /tmp/opencode_home /tmp/opencode_config '
                '/tmp/opencode_data /tmp/opencode_state /tmp/opencode_cache && '
                f'cd /tmp/opencode_work && opencode run --model {OPENCODE_GO_HELLO_MODEL} hello',
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=OPENCODE_HELLO_TIMEOUT_SECONDS,
        )
        if r.returncode == 0:
            return True, 'ok'
        msg = (r.stderr or r.stdout or f'opencode exited {r.returncode}').strip()
        return False, msg[:200]
    except subprocess.TimeoutExpired:
        try:
            subprocess.run(['docker', 'rm', '-f', container_name],
                           capture_output=True, text=True, timeout=10)
        except Exception:
            pass
        return False, 'opencode hello 超时'
    except FileNotFoundError:
        return False, 'Docker CLI 不存在'
    except Exception as e:
        return False, str(e)[:200]


def _probe_endpoint_once(endpoint):
    harness = str(endpoint.get('harness') or HARNESS_CLAUDE_CODE).strip().lower()
    if harness == HARNESS_OPENCODE:
        return _probe_opencode_once(endpoint)
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


def _probe_endpoint(endpoint, attempts=None):
    tries = max(1, int(attempts or JUDGE_HELLO_RETRIES))
    last_error = ''
    for i in range(tries):
        ok, msg = _probe_endpoint_once(endpoint)
        if ok:
            return True, msg
        last_error = msg or 'unknown error'
        if i + 1 < tries and JUDGE_HELLO_RETRY_SLEEP_SECONDS > 0:
            time.sleep(JUDGE_HELLO_RETRY_SLEEP_SECONDS)
    return False, last_error


def _disable_unhealthy_endpoint(endpoint, reason):
    try:
        set_agent_judge_endpoint_enabled(int(endpoint.get('id')), False)
    except Exception:
        pass
    eid = endpoint.get('id')
    print(f'[agent_judge] disabled endpoint {eid} after hello probe failures: {reason}', flush=True)


def clear_judge_lock(submission_id):
    """删除某提交的 agent 评测幂等锁。进程重启重排前调用：上次被杀的 worker 会留下
    僵尸锁（TTL 内有效），不清的话重排任务 set(nx) 失败、直接返回，提交会一直卡住。"""
    client = _ensure_judge_redis()
    if client is None:
        return
    try:
        client.delete(f'ranking:judge:lock:{int(submission_id)}')
        for key in client.scan_iter(match=f'ranking:judge:lock:{int(submission_id)}:*', count=50):
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


def _dump_container_harness_state(container_name, ws, harness=HARNESS_CLAUDE_CODE):
    """容器回收前，把所选 Agent Harness 的会话目录 docker cp 到宿主 submission 目录。
    尽力而为：源不存在或 cp 失败都静默跳过，不影响判题。docker cp 可作用于「已退出但未删除」
    的容器，这正是去掉 --rm 的原因。"""
    dest_dir = os.path.join(ws, 'submission')
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except Exception:
        return
    harness = str(harness or HARNESS_CLAUDE_CODE).strip().lower()
    if harness == HARNESS_CODEX:
        sources = [('/workspace/.codex', '.codex'), ('/root/.codex', '.codex'),
                   ('/tmp/aj_codex_home', '.codex')]
        dest_name = '.codex'
    elif harness == HARNESS_OPENCODE:
        sources = [('/workspace/.opencode', '.opencode'),
                   ('/root/.local/share/opencode', '.opencode'),
                   ('/tmp/aj_opencode_home/.local/share/opencode', '.opencode')]
        dest_name = '.opencode'
    else:
        sources = [('/root/.claude', '.claude'), ('/workspace/.claude', '.claude')]
        dest_name = '.claude'
    dest = os.path.join(dest_dir, dest_name)
    # 目标已存在先删，避免 docker cp 把目录套进已有目录里。
    if os.path.exists(dest):
        shutil.rmtree(dest, ignore_errors=True)
    for src, expected_name in sources:
        try:
            r = subprocess.run(['docker', 'cp', f'{container_name}:{src}', dest_dir],
                               capture_output=True, text=True, timeout=60)
            copied = os.path.join(dest_dir, os.path.basename(src))
            if r.returncode == 0 and os.path.isdir(copied):
                if copied != dest:
                    if os.path.exists(dest):
                        shutil.rmtree(dest, ignore_errors=True)
                    os.replace(copied, dest)
                return
            if r.returncode == 0 and os.path.isdir(os.path.join(dest_dir, expected_name)):
                return
        except Exception:
            pass


def _dump_container_claude(container_name, ws):
    """兼容旧单测/调用名：拷出 Claude Code 会话目录。"""
    return _dump_container_harness_state(container_name, ws, HARNESS_CLAUDE_CODE)


def _run_container_and_tail(submission_id, ws, result_name, competition, rules, timeout_s,
                            endpoint=None, attempt_id=None):
    """起 docker 容器跑所选 Agent Harness，tail 随机结果文件，逐条 upsert + 广播。
    返回 (timed_out, container_ok)。可被集成测试整体 monkeypatch。
    容器回收前会按 harness 把会话/transcript 目录 docker cp 到宿主 <ws>/submission/.claude、
    .codex 或 .opencode，便于事后归因。endpoint：本次使用的模型端点
    （harness/base_url/api_key/model）；为空时回退到比赛单端点字段。"""
    ep = endpoint or {}
    harness = ep.get('harness') or HARNESS_CLAUDE_CODE
    base_url = ep.get('base_url') or competition.get('agent_judge_base_url') or ''
    api_key = ep.get('api_key') or competition.get('agent_judge_api_key') or ''
    model = ep.get('model') or competition.get('agent_judge_model') or ''
    if harness == HARNESS_OPENCODE:
        base_url = base_url or DEFAULT_OPENCODE_GO_BASE_URL
        model = model or DEFAULT_OPENCODE_GO_MODEL
    prompt = aj.build_prompt(competition.get('title'), result_name)
    container_name = f'aj_{submission_id}'
    # 同名残留容器（上次 worker 被杀留下的孤儿、或异常未清的旧容器）先强制清掉，否则下面
    # docker run 同名会冲突。去掉 --rm 后（容器退出不再自动删），这一步尤其必要。
    try:
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
    except Exception:
        pass
    docker_args = [
        # 不再用 --rm：容器退出后保留，给「回收前 docker cp 出 harness 会话目录」留窗口；改由本函数
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
        '-e', f'AJ_HARNESS={harness}',
        # report 命令据此写入随机结果文件名；参赛者代码无法预先猜到。
        '-e', f'AJ_RESULT_FILE=/workspace/{result_name}',
        '-e', f'ANTHROPIC_BASE_URL={base_url}',
        '-e', f'ANTHROPIC_AUTH_TOKEN={api_key}',
        '-e', f'ANTHROPIC_API_KEY={api_key}',
        '-e', f'ANTHROPIC_MODEL={model}',
        '-e', f'OPENAI_BASE_URL={base_url}',
        '-e', f'OPENAI_API_KEY={api_key}',
        '-e', f'OPENAI_MODEL={model}',
        '-e', f'OPENCODE_BASE_URL={base_url}',
        '-e', f'OPENCODE_API_KEY={api_key}',
        '-e', f'OPENCODE_MODEL={model}',
        JUDGE_IMAGE,
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
    timed_out = False
    try:
        while True:
            if not _attempt_still_current(submission_id, attempt_id):
                try:
                    subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
                except Exception:
                    pass
                return (False, True)
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
                affected = upsert_judge_result_for_attempt(
                    submission_id, attempt_id, parsed['rule_id'], raw, raw, 0.0, parsed['evidence'],
                )
                if affected <= 0:
                    try:
                        subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
                    except Exception:
                        pass
                    return (False, True)
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
        # 回收容器前，先把所选 harness 的会话目录拉到宿主 submission 目录（事后归因），再统一回收。
        _dump_container_harness_state(container_name, ws, harness)
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
    ws, result_name = _prepare_workspace(submission, competition, rules)
    timed_out, container_ok = _run_container_and_tail(
        submission_id, ws, result_name, competition, rules, timeout_s, endpoint, attempt_id)
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

        # 选端点：优先端点池，回退比赛单端点；都没有则判 Error（避免无限重排）。
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
                # 重投，同时 startup_requeue 也会补入队 —— 两条恢复消息并发时由锁互斥（只一条评测），
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
                        '所有 Agent 评测端点 hello 预检失败，已自动关闭；请检查端点配置后重测',
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
