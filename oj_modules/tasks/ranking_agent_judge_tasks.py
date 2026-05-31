#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛 Agent-as-Judge 评测任务：起 Docker 容器跑 claude，tail result.jsonl 实时回传。"""
import json
import os
import shutil
import subprocess
import time
import zipfile

try:
    import redis as _redis
except Exception:  # pragma: no cover
    _redis = None

import config as _cfg
from config import REDIS_DB, REDIS_HOST, REDIS_PORT
from oj_modules import ranking_agent_judge as aj
from oj_modules.ranking_db import (
    get_competition, get_ranking_submission, list_competition_files,
    submission_dir, update_submission_result,
)
from oj_modules.ranking_agent_judge_db import (
    build_judge_snapshot, clear_judge_results, list_competition_rules,
    list_judge_results, upsert_judge_result,
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
    """准备宿主工作目录，返回绝对路径。"""
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
    # result.jsonl 预创建
    open(os.path.join(ws, 'result.jsonl'), 'w').close()
    return ws


def _run_container_and_tail(submission_id, ws, competition, rules, timeout_s):
    """起 docker 容器跑 claude，tail result.jsonl，逐条 upsert + 广播。
    返回 (timed_out, container_ok)。可被集成测试整体 monkeypatch。"""
    prompt = aj.build_prompt(competition.get('title'))
    container_name = f'aj_{submission_id}'
    docker_args = [
        'docker', 'run', '--rm', '-d', '--name', container_name,
        '--cap-drop', 'ALL', '--pids-limit', JUDGE_PIDS_LIMIT,
        '--memory', JUDGE_MEM_LIMIT, '--cpus', JUDGE_CPU_LIMIT,
        '-v', f'{ws}:/workspace', '-w', '/workspace',
        '-e', 'IS_SANDBOX=1',
        # 关闭 claude 的非必要外联（遥测/自动更新/错误上报），否则在受限容器内会卡住
        '-e', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1',
        '-e', 'DISABLE_TELEMETRY=1',
        '-e', 'DISABLE_AUTOUPDATER=1',
        '-e', 'DISABLE_ERROR_REPORTING=1',
        '-e', 'AJ_PROMPT',
        '-e', f'ANTHROPIC_BASE_URL={competition.get("agent_judge_base_url") or ""}',
        '-e', f'ANTHROPIC_AUTH_TOKEN={competition.get("agent_judge_api_key") or ""}',
        '-e', f'ANTHROPIC_API_KEY={competition.get("agent_judge_api_key") or ""}',
        '-e', f'ANTHROPIC_MODEL={competition.get("agent_judge_model") or ""}',
        JUDGE_IMAGE,
        'bash', '-lc',
        'claude -p "$AJ_PROMPT" --dangerously-skip-permissions '
        '--model "$ANTHROPIC_MODEL" --add-dir /workspace || true',
    ]
    run_env = dict(os.environ, AJ_PROMPT=prompt)
    try:
        subprocess.run(docker_args, check=True, capture_output=True, text=True,
                       env=run_env, timeout=120)
    except Exception:
        return (False, False)

    result_path = os.path.join(ws, 'result.jsonl')
    rule_ids = {r['rule_id'] for r in rules}
    seen = set()
    start = time.time()
    timed_out = False
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
    else:
        details = {'total_score': total, 'max_score': maxs, 'timed_out': timed_out,
                   'rules': [{'rule_id': rid, 'effective': c['effective'], 'score': c['score']}
                             for rid, c in computed.items()]}
        update_submission_result(submission_id, total, 'Accepted', grade_details=details)
    _publish_snapshot(submission_id)


def _judge(submission_id):
    submission = get_ranking_submission(submission_id)
    if not submission:
        return {'success': False, 'message': '提交不存在'}
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
    ws = _prepare_workspace(submission, competition, rules)
    timed_out, container_ok = _run_container_and_tail(submission_id, ws, competition, rules, timeout_s)
    _finalize(submission_id, rules, timed_out, container_ok)
    return {'success': True}


def register_ranking_agent_judge_task(celery_app):
    @celery_app.task(name=RANKING_AGENT_JUDGE_TASK_NAME, bind=True)
    def evaluate_ranking_agent_judge(self, submission_id):
        client = _ensure_judge_redis()
        lock_key = f'ranking:judge:lock:{submission_id}'
        token = str(self.request.id or submission_id)
        if client is not None:
            try:
                if not client.set(lock_key, token, nx=True, ex=7200):
                    return {'success': False, 'message': '已有评测在进行'}
            except Exception:
                pass
        try:
            return _judge(int(submission_id))
        except Exception as e:
            try:
                update_submission_result(int(submission_id), None, 'Error',
                                         error_message=f'评测任务异常：{e}')
                _publish_snapshot(int(submission_id))
            except Exception:
                pass
            raise
        finally:
            if client is not None:
                try:
                    if client.get(lock_key) == token:
                        client.delete(lock_key)
                except Exception:
                    pass

    return evaluate_ranking_agent_judge
