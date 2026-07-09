#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛反向评测任务：学生出题考 AI，AI 得分越低，学生得分越高。"""

import json
import os
import secrets
import shutil
import subprocess
import time
from urllib.parse import urlsplit, urlunsplit
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
from oj_modules.ranking_db import (
    get_competition,
    get_ranking_submission,
    set_agent_judge_task_id,
    set_submission_status_for_attempt,
    submission_dir,
    update_submission_result_for_attempt,
)
from oj_modules.ranking_reverse_judge_db import (
    STEP_AGENT,
    STEP_AI_JUDGE,
    STEP_SOLUTION,
    build_reverse_judge_snapshot,
    init_reverse_judge_steps_for_attempt,
    update_reverse_judge_step_for_attempt,
)
from oj_modules.tasks.ranking_agent_judge_tasks import (
    HARNESS_CLAUDE_CODE,
    JUDGE_CPU_LIMIT,
    JUDGE_DEFAULT_TIMEOUT,
    JUDGE_IMAGE,
    JUDGE_MAX_QUEUE_RETRIES,
    JUDGE_MEM_LIMIT,
    JUDGE_PIDS_LIMIT,
    JUDGE_QUEUE_RETRY_BASE,
    JUDGE_SLOT_TTL_BUFFER,
    _acquire_endpoint_slot,
    _agent_env_args,
    _disable_unhealthy_endpoint,
    _ensure_judge_redis,
    _exec_container_apt_setup,
    _probe_endpoint,
    _release_slot,
)
from oj_modules.ranking_agent_judge_db import (
    HARNESS_CODEX,
    HARNESS_OPENCODE,
    list_agent_judge_endpoints,
)


RANKING_REVERSE_JUDGE_TASK_NAME = 'oj.ranking_reverse_judge'
REVERSE_PROGRESS_TTL = int(getattr(_cfg, 'REVERSE_JUDGE_PROGRESS_TTL', 21600))
REVERSE_WORKSPACE_ROOT = getattr(
    _cfg, 'REVERSE_JUDGE_WORKSPACE_ROOT', 'ranking_uploads/reverse_judge_workspace',
)
REVERSE_JUDGE_SCRIPT_TIMEOUT = int(getattr(_cfg, 'REVERSE_JUDGE_SCRIPT_TIMEOUT', 300))
REVERSE_TRACE_SYNC_INTERVAL = float(getattr(_cfg, 'REVERSE_JUDGE_TRACE_SYNC_INTERVAL', 2.0))
REVERSE_FORCE_FINALIZE_TIMEOUT_DEFAULT = 180
REVERSE_FORCE_FINALIZE_PROMPT = getattr(
    _cfg, 'REVERSE_FORCE_FINALIZE_PROMPT',
    '无论你当前已经实现了什么，无论正确性与性能是否达标，都请停下你的工作。'
    '现在请立刻整理代码，形成一个可运行的交付物。',
)
_HARNESS_TIMEOUT_EXIT_CODES = {124, 137}
_TERMINAL_STATUSES = {'Accepted', 'Error'}

_reverse_rds = None


def init_reverse_judge_progress_cache(redis_client):
    global _reverse_rds
    _reverse_rds = redis_client


def _ensure_reverse_redis():
    global _reverse_rds
    if _reverse_rds is not None:
        return _reverse_rds
    if _redis is None:
        return None
    try:
        _reverse_rds = _redis.StrictRedis(
            host=REDIS_HOST, port=int(REDIS_PORT), db=int(REDIS_DB),
            decode_responses=True,
        )
        _reverse_rds.ping()
    except Exception:
        _reverse_rds = None
    return _reverse_rds


def _reverse_progress_key(submission_id):
    return f'ranking_reverse_judge:{submission_id}'


def _reverse_progress_channel(submission_id):
    return f'ranking_reverse_judge_events:{submission_id}'


def subscribe_reverse_judge_events(submission_id):
    client = _ensure_reverse_redis()
    if client is None:
        return None
    try:
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(_reverse_progress_channel(submission_id))
        return pubsub
    except Exception:
        return None


def get_reverse_judge_progress_snapshot(submission_id):
    client = _ensure_reverse_redis()
    if client is not None:
        try:
            raw = client.get(_reverse_progress_key(submission_id))
            if raw:
                data = json.loads(raw)
                if isinstance(data, dict):
                    if data.get('status') not in ('Judging', 'Pending', 'Queued'):
                        return build_reverse_judge_snapshot(submission_id) or data
                    return data
        except Exception:
            pass
    return build_reverse_judge_snapshot(submission_id)


def _publish_snapshot(submission_id):
    snap = build_reverse_judge_snapshot(submission_id)
    if snap is None:
        return None
    client = _ensure_reverse_redis()
    if client is not None:
        try:
            payload = json.dumps(snap, ensure_ascii=False)
            client.setex(_reverse_progress_key(submission_id), REVERSE_PROGRESS_TTL, payload)
            client.publish(_reverse_progress_channel(submission_id), payload)
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


def _attempt_still_current(submission_id, attempt_id):
    submission = get_ranking_submission(submission_id)
    return bool(submission and _attempt_matches(submission, attempt_id))


def _task_should_skip(submission, attempt_id):
    if not submission:
        return True, '提交不存在'
    if not _attempt_matches(submission, attempt_id):
        return True, '旧评测 attempt，跳过'
    if str(submission.get('status') or '') in _TERMINAL_STATUSES:
        return True, '已完成，跳过重复评测'
    return False, ''


def _write_error_for_attempt(submission_id, attempt_id, error_message):
    return update_submission_result_for_attempt(
        submission_id, attempt_id, None, 'Error',
        grade_details=None, error_message=(error_message or '')[:2000],
    )


def _safe_extract_zip(zip_path, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    base = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = os.path.realpath(os.path.join(dest_dir, member))
            if target != base and not target.startswith(base + os.sep):
                continue
            zf.extract(member, dest_dir)


def _has_reverse_package_shape(path):
    return (
        os.path.isdir(os.path.join(path, 'problem'))
        and os.path.isdir(os.path.join(path, 'template'))
        and os.path.isdir(os.path.join(path, 'solution'))
        and os.path.isfile(os.path.join(path, 'judge.sh'))
    )


def _find_package_root(extract_dir):
    if _has_reverse_package_shape(extract_dir):
        return extract_dir
    try:
        children = [
            os.path.join(extract_dir, name)
            for name in os.listdir(extract_dir)
            if not name.startswith('__MACOSX')
        ]
    except OSError:
        children = []
    dirs = [p for p in children if os.path.isdir(p)]
    files = [p for p in children if os.path.isfile(p)]
    if len(dirs) == 1 and not files and _has_reverse_package_shape(dirs[0]):
        return dirs[0]
    return extract_dir


def _prepare_workspace(submission):
    sid = int(submission['id'])
    code_path = submission.get('code_path')
    if not code_path or not os.path.isfile(code_path):
        raise RuntimeError('提交文件不存在')
    ws = os.path.realpath(os.path.join(REVERSE_WORKSPACE_ROOT, str(sid)))
    if os.path.isdir(ws):
        shutil.rmtree(ws, ignore_errors=True)
    os.makedirs(ws, exist_ok=True)
    extract_dir = os.path.join(ws, 'package')
    _safe_extract_zip(code_path, extract_dir)
    package_root = os.path.realpath(_find_package_root(extract_dir))
    if not _has_reverse_package_shape(package_root):
        raise RuntimeError('提交包必须包含 problem/、template/、solution/ 和 judge.sh')
    return ws, package_root


def _limit_text(text, limit=120000):
    text = '' if text is None else str(text)
    return text if len(text) <= limit else text[:limit] + f'\n...（已截断，原始长度 {len(text)} 字符）'


def _normalize_test_points(raw):
    if raw is None:
        return {}
    if isinstance(raw, list):
        items = {}
        for idx, item in enumerate(raw, start=1):
            if isinstance(item, dict):
                items[str(idx)] = item
        raw = items
    if not isinstance(raw, dict):
        raise ValueError('result.json 的 test_points 必须是对象或数组')
    out = {}
    for key, item in raw.items():
        if not isinstance(item, dict):
            raise ValueError(f'得分点 {key} 必须是对象')
        desc = str(item.get('description') or '').strip()
        try:
            max_score = float(item.get('max_score'))
            score = float(item.get('score'))
        except (TypeError, ValueError):
            raise ValueError(f'得分点 {key} 的 max_score/score 必须是数字')
        if max_score < 0 or score < 0:
            raise ValueError(f'得分点 {key} 的分数不能为负')
        out[str(key)] = {
            'description': desc,
            'max_score': max_score,
            'score': min(score, max_score),
        }
    return out


def _load_result_json(package_root):
    path = os.path.join(package_root, 'result.json')
    if not os.path.isfile(path):
        raise ValueError('评测脚本未生成 result.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            result = json.load(f)
    except Exception as e:
        raise ValueError(f'result.json 不是合法 JSON：{e}')
    if not isinstance(result, dict):
        raise ValueError('result.json 根节点必须是对象')
    try:
        max_score = float(result.get('max_score'))
        score = float(result.get('score'))
    except (TypeError, ValueError):
        raise ValueError('result.json 必须包含数字 max_score 和 score')
    if max_score <= 0:
        raise ValueError('result.json 的 max_score 必须大于 0')
    if score < 0:
        raise ValueError('result.json 的 score 不能为负')
    test_points = _normalize_test_points(result.get('test_points') or {})
    return {
        'max_score': max_score,
        'score': min(score, max_score),
        'test_points': test_points,
    }


def _run_judge_script(submission_id, package_root, answer_dir, timeout_s):
    result_path = os.path.join(package_root, 'result.json')
    try:
        os.remove(result_path)
    except FileNotFoundError:
        pass
    container_name = f'rj_judge_{int(submission_id)}_{secrets.token_hex(4)}'
    answer_dir = str(answer_dir).strip().rstrip('/') + '/'
    args = [
        'docker', 'run', '--rm', '--name', container_name,
        '--security-opt', 'no-new-privileges',
        '--pids-limit', JUDGE_PIDS_LIMIT,
        '--memory', JUDGE_MEM_LIMIT,
        '--cpus', JUDGE_CPU_LIMIT,
        '-v', f'{package_root}:/workspace',
        '-w', '/workspace',
        '-e', f'RJ_ANSWER_DIR={answer_dir}',
        JUDGE_IMAGE,
        'bash', '-lc',
        'chmod +x judge.sh 2>/dev/null || true; bash judge.sh "$RJ_ANSWER_DIR"',
    ]
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=max(1, int(timeout_s)),
        )
    except subprocess.TimeoutExpired as e:
        try:
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
        except Exception:
            pass
        return {
            'ok': False,
            'returncode': None,
            'stdout': e.stdout or '',
            'stderr': e.stderr or '',
            'error': f'评测脚本超时（>{int(timeout_s)}s）',
            'result': None,
        }
    except FileNotFoundError:
        return {
            'ok': False,
            'returncode': None,
            'stdout': '',
            'stderr': '',
            'error': 'Docker CLI 不存在',
            'result': None,
        }
    except Exception as e:
        return {
            'ok': False,
            'returncode': None,
            'stdout': '',
            'stderr': '',
            'error': f'评测容器启动失败：{e}',
            'result': None,
        }
    if proc.returncode != 0:
        return {
            'ok': False,
            'returncode': int(proc.returncode),
            'stdout': proc.stdout or '',
            'stderr': proc.stderr or '',
            'error': f'评测脚本退出码 {proc.returncode}',
            'result': None,
        }
    try:
        result = _load_result_json(package_root)
    except Exception as e:
        return {
            'ok': False,
            'returncode': int(proc.returncode),
            'stdout': proc.stdout or '',
            'stderr': proc.stderr or '',
            'error': str(e),
            'result': None,
        }
    return {
        'ok': True,
        'returncode': int(proc.returncode),
        'stdout': proc.stdout or '',
        'stderr': proc.stderr or '',
        'error': '',
        'result': result,
    }


def _resolve_harness_config(endpoint):
    ep = endpoint or {}
    return (
        ep.get('harness') or HARNESS_CLAUDE_CODE,
        ep.get('base_url') or '',
        ep.get('api_key') or '',
        ep.get('model') or '',
    )


def _normalize_endpoint_id(value):
    if value in (None, '', 'null'):
        return None
    try:
        endpoint_id = int(value)
    except (TypeError, ValueError):
        return None
    return endpoint_id if endpoint_id > 0 else None


def _endpoint_payload(ep):
    return {
        'id': ep['id'],
        'harness': ep.get('harness') or HARNESS_CLAUDE_CODE,
        'base_url': ep.get('base_url') or '',
        'api_key': ep.get('api_key') or '',
        'model': ep.get('model') or '',
        'concurrency_limit': max(1, int(ep.get('concurrency_limit') or 1)),
    }


def _endpoint_snapshot_matches(ep, snapshot):
    if not snapshot:
        return False
    harness = str(snapshot.get('agent_endpoint_harness') or '').strip().lower()
    model = str(snapshot.get('agent_endpoint_model') or '').strip()
    if not harness or not model:
        return False
    ep_harness = str(ep.get('harness') or HARNESS_CLAUDE_CODE).strip().lower()
    ep_model = str(ep.get('model') or '').strip()
    return ep_harness == harness and ep_model == model


def _resolve_selected_endpoint(competition_id, endpoint_id, endpoint_snapshot=None):
    endpoint_id = _normalize_endpoint_id(endpoint_id)
    if endpoint_id is None:
        return None, '未选择 AI 作答节点，请重新提交并选择节点'
    try:
        endpoints = list_agent_judge_endpoints(competition_id)
    except Exception:
        endpoints = []
    for ep in endpoints:
        if int(ep.get('id') or 0) != endpoint_id:
            continue
        if str(ep.get('status') or '').lower() != 'enabled':
            return None, '所选 AI 作答节点当前不可用，请选择其它节点或等待恢复'
        return _endpoint_payload(ep), ''
    matched_disabled = False
    for ep in endpoints:
        if not _endpoint_snapshot_matches(ep, endpoint_snapshot):
            continue
        if str(ep.get('status') or '').lower() != 'enabled':
            matched_disabled = True
            continue
        return _endpoint_payload(ep), ''
    if matched_disabled:
        return None, '所选 AI 作答节点当前不可用，请选择其它节点或等待恢复'
    return None, '所选 AI 作答节点不存在，请重新选择'


def _agent_container_base_url(base_url):
    """把宿主 localhost 端点改写为容器可访问的 host.docker.internal。"""
    text = str(base_url or '').strip()
    if not text:
        return text
    try:
        parts = urlsplit(text)
    except Exception:
        return text
    if parts.hostname not in {'127.0.0.1', 'localhost', '::1'}:
        return text
    netloc = 'host.docker.internal'
    if parts.port:
        netloc += f':{parts.port}'
    if parts.username or parts.password:
        userinfo = parts.username or ''
        if parts.password:
            userinfo += ':' + parts.password
        netloc = userinfo + '@' + netloc
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _reverse_prompt():
    return (
        '当前工作目录 /workspace 是可写的答案目录；/workspace/problem 是只读的题目描述目录。'
        '请阅读 /workspace/problem 中的题面、说明、样例或其它材料，'
        '按照题目要求在 /workspace 内完成可评测交付物。'
        '可以修改模板文件、补充代码或新增必要文件，但不要修改 /workspace/problem。'
        '最终评测会把 /workspace 作为答案目录。'
        '请直接完成答案，不要用说明性文档替代可评测文件。'
    )


def _copy_tree_from_container(container_name, src, dest):
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.exists(dest):
            shutil.rmtree(dest, ignore_errors=True)
        tmp_parent = os.path.dirname(dest)
        r = subprocess.run(
            ['docker', 'cp', f'{container_name}:{src}', tmp_parent],
            capture_output=True, text=True, timeout=60,
        )
        copied = os.path.join(tmp_parent, os.path.basename(src))
        if r.returncode == 0 and os.path.isdir(copied):
            if copied != dest:
                if os.path.exists(dest):
                    shutil.rmtree(dest, ignore_errors=True)
                os.replace(copied, dest)
            return True
    except Exception:
        pass
    return False


def _claude_project_jsonl_dest(trace_dir, filename):
    return os.path.join(trace_dir, '.claude', 'projects', '-workspace', filename)


def _sync_claude_project_jsonl(container_name, trace_dir):
    """同步 Claude Code 的 workspace 会话 JSONL，并生成第二阶段合并轨迹。

    超时后 resume 可能产生新的会话文件；前端需要把这些 JSONL 视为同一个
    “AI 作答”阶段，因此这里按 mtime 合并成稳定的 reverse_solve_combined.jsonl。
    """
    os.makedirs(trace_dir, exist_ok=True)
    find_cmd = (
        "python3 - <<'PY'\n"
        "import json, os\n"
        "base='/home/node/.claude/projects/-workspace'\n"
        "try:\n"
        "    items=[os.path.join(base,n) for n in os.listdir(base) if n.endswith('.jsonl')]\n"
        "except Exception:\n"
        "    items=[]\n"
        "items=[p for p in items if os.path.isfile(p)]\n"
        "items.sort(key=lambda p: os.path.getmtime(p))\n"
        "print(json.dumps(items, ensure_ascii=False))\n"
        "PY"
    )
    try:
        located = subprocess.run(
            ['docker', 'exec', container_name, 'bash', '-lc', find_cmd],
            capture_output=True, text=True, timeout=8,
        )
        remote_paths = json.loads((located.stdout or '[]').strip() or '[]')
    except Exception:
        return False
    if not isinstance(remote_paths, list):
        return False
    remote_paths = [str(p).strip() for p in remote_paths if str(p).strip().endswith('.jsonl')]
    if not remote_paths:
        return False
    combined_chunks = []
    try:
        for remote_path in remote_paths:
            data = subprocess.run(
                ['docker', 'exec', container_name, 'cat', remote_path],
                capture_output=True, timeout=12,
            )
            if data.returncode != 0:
                continue
            payload = data.stdout or b''
            dest = _claude_project_jsonl_dest(trace_dir, os.path.basename(remote_path))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            tmp = dest + '.tmp'
            with open(tmp, 'wb') as f:
                f.write(payload)
            os.replace(tmp, dest)
            if payload:
                combined_chunks.append(payload.rstrip(b'\n'))
        if not combined_chunks:
            return False
        combined = b'\n'.join(combined_chunks) + b'\n'
        combined_dest = _claude_project_jsonl_dest(trace_dir, 'reverse_solve_combined.jsonl')
        tmp = combined_dest + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(combined)
        os.replace(tmp, combined_dest)
        return True
    except Exception:
        return False


def _sync_codex_stdout_trace(template_dir, trace_dir):
    src = os.path.join(template_dir, '.aj_reverse_solve.stdout.tmp')
    if not os.path.isfile(src):
        return False
    dest = os.path.join(trace_dir, 'codex_reverse_solve.jsonl')
    try:
        os.makedirs(trace_dir, exist_ok=True)
        tmp = dest + '.tmp'
        shutil.copyfile(src, tmp)
        os.replace(tmp, dest)
        return True
    except Exception:
        return False


def _dump_harness_trace(container_name, trace_dir, template_dir, harness):
    os.makedirs(trace_dir, exist_ok=True)
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
        _sync_claude_project_jsonl(container_name, trace_dir)
        sources = []
        dest_name = ''
    for src, _expected in sources:
        if dest_name and _copy_tree_from_container(container_name, src, os.path.join(trace_dir, dest_name)):
            break
    for name in ('.aj_harness.log', '.aj_session_state.json', '.aj_session_state.jsonl'):
        src = os.path.join(template_dir, name)
        if os.path.isfile(src):
            try:
                shutil.copy2(src, os.path.join(trace_dir, name))
            except Exception:
                pass


def _prepare_agent_workspace_for_node(container_name):
    return subprocess.run(
        [
            'docker', 'exec', container_name, 'bash', '-lc',
            'mkdir -p /home/node && chown node:node /home/node /workspace && '
            'find /workspace -mindepth 1 -maxdepth 1 ! -name problem '
            '-exec chown -R node:node {} +',
        ],
        check=True, capture_output=True, text=True, timeout=60,
    )


def _read_text_file(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception:
        return ''


def _read_session_id_from_workspace(ws):
    state_path = os.path.join(ws, '.aj_session_state.json')
    try:
        with open(state_path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except Exception:
        return ''
    if not isinstance(data, dict):
        return ''
    return str(data.get('session_id') or '').strip()


def _latest_claude_session_id_from_container(container_name):
    find_cmd = (
        "python3 - <<'PY'\n"
        "import os\n"
        "base='/home/node/.claude/projects/-workspace'\n"
        "try:\n"
        "    items=[os.path.join(base,n) for n in os.listdir(base) if n.endswith('.jsonl')]\n"
        "except Exception:\n"
        "    items=[]\n"
        "items=[p for p in items if os.path.isfile(p)]\n"
        "if items:\n"
        "    items.sort(key=lambda p: os.path.getmtime(p), reverse=True)\n"
        "    print(os.path.splitext(os.path.basename(items[0]))[0])\n"
        "PY"
    )
    try:
        located = subprocess.run(
            ['docker', 'exec', container_name, 'bash', '-lc', find_cmd],
            capture_output=True, text=True, timeout=8,
        )
    except Exception:
        return ''
    if located.returncode != 0:
        return ''
    return (located.stdout or '').strip().splitlines()[0].strip() if (located.stdout or '').strip() else ''


def _resolve_resume_session_id(container_name, ws, harness):
    session_id = _read_session_id_from_workspace(ws)
    if session_id:
        return session_id
    if str(harness or '').strip().lower() == HARNESS_CLAUDE_CODE:
        return _latest_claude_session_id_from_container(container_name)
    return ''


def _merge_proc_output(*values):
    parts = [str(v or '').rstrip() for v in values if str(v or '').strip()]
    return '\n\n'.join(parts)


def _exec_reverse_harness_phase(
    container_name, ws, phase, prompt, timeout_s, on_tick=None,
    resume_session_id='', fork_session=True,
):
    timeout_s = max(1, int(timeout_s))
    args = [
        'docker', 'exec', '-i', '--user', 'node',
        '-e', 'HOME=/home/node',
        '-e', 'DEBIAN_FRONTEND=noninteractive',
        '-e', f'AJ_PHASE={phase}',
        '-e', f'AJ_HARNESS_TIMEOUT_SECONDS={timeout_s}',
        '-e', 'AJ_SESSION_STATE=/workspace/.aj_session_state.json',
    ]
    if resume_session_id:
        args.extend(['-e', f'AJ_RESUME_SESSION_ID={resume_session_id}'])
    if not fork_session:
        args.extend(['-e', 'AJ_FORK_SESSION=0'])
    args.extend([
        container_name, 'bash', '-lc',
        'IFS= read -r -d "" AJ_PROMPT || true; export AJ_PROMPT; '
        'timeout -k 10s "${AJ_HARNESS_TIMEOUT_SECONDS}s" run_harness',
    ])
    stdout_path = os.path.join(ws, f'.aj_{phase}.stdout.tmp')
    stderr_path = os.path.join(ws, f'.aj_{phase}.stderr.tmp')
    started = time.monotonic()
    last_tick = 0.0
    outer_timeout_s = timeout_s + 60
    with open(stdout_path, 'w+', encoding='utf-8', errors='replace') as out_f, \
            open(stderr_path, 'w+', encoding='utf-8', errors='replace') as err_f:
        proc_handle = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=out_f, stderr=err_f, text=True,
        )
        try:
            try:
                proc_handle.stdin.write(prompt or '')
                proc_handle.stdin.close()
            except Exception:
                pass
            while proc_handle.poll() is None:
                now = time.monotonic()
                if callable(on_tick) and now - last_tick >= max(0.5, REVERSE_TRACE_SYNC_INTERVAL):
                    try:
                        on_tick()
                    except Exception:
                        pass
                    last_tick = now
                if now - started > outer_timeout_s:
                    try:
                        proc_handle.kill()
                    except Exception:
                        pass
                    try:
                        proc_handle.wait(timeout=10)
                    except Exception:
                        pass
                    out_f.flush()
                    err_f.flush()
                    raise subprocess.TimeoutExpired(
                        args, outer_timeout_s,
                        output=_read_text_file(stdout_path),
                        stderr=_read_text_file(stderr_path),
                    )
                time.sleep(0.25)
            if callable(on_tick):
                try:
                    on_tick()
                except Exception:
                    pass
        finally:
            try:
                proc_handle.wait(timeout=5)
            except Exception:
                pass
        out_f.flush()
        err_f.flush()
        if callable(on_tick):
            try:
                on_tick()
            except Exception:
                pass
    proc = subprocess.CompletedProcess(
        args, proc_handle.returncode,
        stdout=_read_text_file(stdout_path),
        stderr=_read_text_file(stderr_path),
    )
    proc.aj_timed_out = int(proc_handle.returncode or 0) in _HARNESS_TIMEOUT_EXIT_CODES
    for path in (stdout_path, stderr_path):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    try:
        from oj_modules.tasks.ranking_agent_judge_tasks import _append_phase_log
        _append_phase_log(ws, phase, proc)
    except Exception:
        pass
    return proc


def _run_agent(submission_id, attempt_id, package_root, endpoint, timeout_s, finalize_timeout_s):
    harness, base_url, api_key, model = _resolve_harness_config(endpoint)
    container_base_url = _agent_container_base_url(base_url)
    template_dir = os.path.realpath(os.path.join(package_root, 'template'))
    problem_dir = os.path.realpath(os.path.join(package_root, 'problem'))
    trace_dir = os.path.join(submission_dir(submission_id), 'reverse_agent_trace')
    os.makedirs(trace_dir, exist_ok=True)
    container_name = f'rj_agent_{int(submission_id)}'
    try:
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
    except Exception:
        pass
    docker_args = [
        'docker', 'run', '-d', '--name', container_name,
        '--security-opt', 'no-new-privileges',
        '--pids-limit', JUDGE_PIDS_LIMIT,
        '--memory', JUDGE_MEM_LIMIT,
        '--cpus', JUDGE_CPU_LIMIT,
        '--add-host', 'host.docker.internal:host-gateway',
        '-v', f'{template_dir}:/workspace',
        '-v', f'{problem_dir}:/workspace/problem:ro',
        '-w', '/workspace',
    ] + _agent_env_args(
        harness, container_base_url, api_key, model, 'reverse_unused.jsonl', include_prompt=False,
    ) + [JUDGE_IMAGE, 'bash', '-lc', 'tail -f /dev/null']
    try:
        subprocess.run(docker_args, check=True, capture_output=True, text=True, timeout=120)
        _exec_container_apt_setup(container_name, timeout_s=120)
        _prepare_agent_workspace_for_node(container_name)
        trace_registered = False

        def sync_trace():
            nonlocal trace_registered
            if harness == HARNESS_CLAUDE_CODE:
                _sync_claude_project_jsonl(container_name, trace_dir)
            elif harness == HARNESS_CODEX:
                _sync_codex_stdout_trace(template_dir, trace_dir)
            if not trace_registered:
                update_reverse_judge_step_for_attempt(
                    submission_id, attempt_id, STEP_AGENT,
                    status='running', trace_dir=trace_dir,
                )
                trace_registered = True
            _publish_snapshot(submission_id)

        sync_trace()
        proc = _exec_reverse_harness_phase(
            container_name, template_dir, 'reverse_solve',
            _reverse_prompt(), max(1, int(timeout_s)), on_tick=sync_trace,
        )
        sync_trace()
        if getattr(proc, 'aj_timed_out', False):
            session_id = _resolve_resume_session_id(container_name, template_dir, harness)
            if not session_id:
                return {
                    'ok': False,
                    'stdout': proc.stdout or '',
                    'stderr': proc.stderr or '',
                    'error': f'Agent 作答超时（>{int(timeout_s)}s），且未找到可恢复会话',
                    'trace_dir': trace_dir,
                }
            finalize_proc = _exec_reverse_harness_phase(
                container_name, template_dir, 'reverse_finalize',
                REVERSE_FORCE_FINALIZE_PROMPT,
                max(1, int(finalize_timeout_s)),
                on_tick=sync_trace,
                resume_session_id=session_id,
                fork_session=False,
            )
            sync_trace()
            ok = finalize_proc.returncode == 0 and not getattr(finalize_proc, 'aj_timed_out', False)
            error = ''
            if not ok:
                if getattr(finalize_proc, 'aj_timed_out', False):
                    error = (
                        f'Agent 作答超时（>{int(timeout_s)}s），恢复收尾也超时'
                        f'（>{int(finalize_timeout_s)}s）'
                    )
                else:
                    error = f'Agent 作答超时后恢复收尾失败，退出码 {finalize_proc.returncode}'
            return {
                'ok': ok,
                'stdout': _merge_proc_output(proc.stdout, finalize_proc.stdout),
                'stderr': _merge_proc_output(proc.stderr, finalize_proc.stderr),
                'error': error,
                'trace_dir': trace_dir,
            }
        ok = proc.returncode == 0
        return {
            'ok': ok,
            'stdout': proc.stdout or '',
            'stderr': proc.stderr or '',
            'error': '' if ok else f'Agent 退出码 {proc.returncode}',
            'trace_dir': trace_dir,
        }
    except subprocess.TimeoutExpired as e:
        try:
            subprocess.run(['docker', 'kill', container_name], capture_output=True, timeout=15)
        except Exception:
            pass
        return {
            'ok': False,
            'stdout': e.stdout or '',
            'stderr': e.stderr or '',
            'error': f'Agent 作答超时（>{int(timeout_s)}s）',
            'trace_dir': trace_dir,
        }
    except Exception as e:
        return {
            'ok': False,
            'stdout': '',
            'stderr': '',
            'error': f'Agent 容器启动失败：{e}',
            'trace_dir': trace_dir,
        }
    finally:
        _dump_harness_trace(container_name, trace_dir, template_dir, harness)
        try:
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=20)
        except Exception:
            pass


def _retry_queued_submission(task, submission_id, attempt_id,
                             message='所有模型端点并发均已满，重新排队'):
    submission = get_ranking_submission(submission_id)
    skip, skip_msg = _task_should_skip(submission, attempt_id)
    if skip:
        return {'success': True, 'message': skip_msg}
    if set_submission_status_for_attempt(submission_id, attempt_id, 'Queued') <= 0:
        return {'success': True, 'message': '旧评测 attempt，跳过'}
    _publish_snapshot(submission_id)
    countdown = JUDGE_QUEUE_RETRY_BASE + secrets.randbelow(JUDGE_QUEUE_RETRY_BASE + 1)
    try:
        task.retry(countdown=countdown, max_retries=JUDGE_MAX_QUEUE_RETRIES)
    except MaxRetriesExceededError:
        _write_error_for_attempt(
            submission_id, attempt_id, '反向评测排队超时：所有模型端点持续繁忙，请稍后重测',
        )
        _publish_snapshot(submission_id)
        return {'success': False, 'message': '端点持续繁忙'}
    return {'success': False, 'message': message}


def _finish_error(submission_id, attempt_id, step_key, message, *,
                  stdout='', stderr='', result=None, trace_dir=None):
    update_reverse_judge_step_for_attempt(
        submission_id, attempt_id, step_key,
        status='error', result_json=result, stdout=_limit_text(stdout), stderr=_limit_text(stderr),
        error_message=message, trace_dir=trace_dir,
    )
    _write_error_for_attempt(submission_id, attempt_id, message)
    _publish_snapshot(submission_id)
    return {'success': False, 'message': message}


def _score_full(result):
    return abs(float(result.get('score') or 0) - float(result.get('max_score') or 0)) <= 1e-7


def _reverse_user_score(ai_score, ai_max_score):
    max_score = float(ai_max_score)
    if max_score <= 0:
        raise ValueError('AI 评分满分必须大于 0')
    ai_percent = float(ai_score) * 100.0 / max_score
    ai_percent = max(0.0, min(100.0, ai_percent))
    return 100.0 - ai_percent, ai_percent


def _run_reverse_judge(submission_id, attempt_id, endpoint):
    if set_submission_status_for_attempt(submission_id, attempt_id, 'Judging') <= 0:
        return {'success': True, 'message': '旧评测 attempt，跳过'}
    init_reverse_judge_steps_for_attempt(submission_id, attempt_id)
    _publish_snapshot(submission_id)

    submission = get_ranking_submission(submission_id)
    if not submission:
        return {'success': False, 'message': '提交不存在'}
    competition = get_competition(submission.get('competition_id'))
    if not competition:
        _write_error_for_attempt(submission_id, attempt_id, '比赛不存在')
        _publish_snapshot(submission_id)
        return {'success': False, 'message': '比赛不存在'}
    try:
        ws, package_root = _prepare_workspace(submission)
    except Exception as e:
        return _finish_error(submission_id, attempt_id, STEP_SOLUTION, str(e))

    judge_timeout = int(competition.get('scoring_script_timeout_seconds') or REVERSE_JUDGE_SCRIPT_TIMEOUT)
    agent_timeout = int(competition.get('agent_judge_timeout_seconds') or JUDGE_DEFAULT_TIMEOUT)
    finalize_timeout = int(
        competition.get('reverse_judge_finalize_timeout_seconds')
        or REVERSE_FORCE_FINALIZE_TIMEOUT_DEFAULT
    )

    update_reverse_judge_step_for_attempt(
        submission_id, attempt_id, STEP_SOLUTION, status='running',
    )
    _publish_snapshot(submission_id)
    solution_run = _run_judge_script(submission_id, package_root, 'solution', judge_timeout)
    if not solution_run['ok']:
        return _finish_error(
            submission_id, attempt_id, STEP_SOLUTION,
            solution_run['error'], stdout=solution_run['stdout'], stderr=solution_run['stderr'],
        )
    solution_result = solution_run['result']
    step1_status = 'passed' if _score_full(solution_result) else 'failed'
    update_reverse_judge_step_for_attempt(
        submission_id, attempt_id, STEP_SOLUTION,
        status=step1_status,
        max_score=solution_result['max_score'],
        score=solution_result['score'],
        result_json=solution_result,
        stdout=_limit_text(solution_run['stdout']),
        stderr=_limit_text(solution_run['stderr']),
        error_message='' if step1_status == 'passed' else '标准答案自检未达到满分',
    )
    _publish_snapshot(submission_id)
    if step1_status != 'passed':
        _write_error_for_attempt(submission_id, attempt_id, '标准答案自检未达到满分，反向评测已停止')
        _publish_snapshot(submission_id)
        return {'success': False, 'message': '标准答案自检未达到满分'}

    update_reverse_judge_step_for_attempt(
        submission_id, attempt_id, STEP_AGENT, status='running',
    )
    _publish_snapshot(submission_id)
    agent_run = _run_agent(
        submission_id, attempt_id, package_root, endpoint, agent_timeout, finalize_timeout,
    )
    if not agent_run['ok']:
        return _finish_error(
            submission_id, attempt_id, STEP_AGENT,
            agent_run['error'], trace_dir=agent_run.get('trace_dir'),
        )
    update_reverse_judge_step_for_attempt(
        submission_id, attempt_id, STEP_AGENT,
        status='passed', trace_dir=agent_run.get('trace_dir'),
    )
    _publish_snapshot(submission_id)

    update_reverse_judge_step_for_attempt(
        submission_id, attempt_id, STEP_AI_JUDGE, status='running',
    )
    _publish_snapshot(submission_id)
    ai_run = _run_judge_script(submission_id, package_root, 'template', judge_timeout)
    if not ai_run['ok']:
        return _finish_error(
            submission_id, attempt_id, STEP_AI_JUDGE,
            ai_run['error'], stdout=ai_run['stdout'], stderr=ai_run['stderr'],
        )
    ai_result = ai_run['result']
    update_reverse_judge_step_for_attempt(
        submission_id, attempt_id, STEP_AI_JUDGE,
        status='passed',
        max_score=ai_result['max_score'],
        score=ai_result['score'],
        result_json=ai_result,
        stdout=_limit_text(ai_run['stdout']),
        stderr=_limit_text(ai_run['stderr']),
    )
    user_score, ai_percent = _reverse_user_score(ai_result['score'], ai_result['max_score'])
    details = {
        'reverse_judge': True,
        'ai_score': float(ai_result['score']),
        'ai_max_score': float(ai_result['max_score']),
        'ai_percent': ai_percent,
        'user_score': user_score,
        'workspace': ws,
    }
    update_submission_result_for_attempt(
        submission_id, attempt_id, user_score, 'Accepted', grade_details=details,
    )
    _publish_snapshot(submission_id)
    return {'success': True, 'score': user_score}


def register_ranking_reverse_judge_task(celery_app):
    @celery_app.task(name=RANKING_REVERSE_JUDGE_TASK_NAME, bind=True)
    def evaluate_ranking_reverse_judge(self, submission_id, attempt_id=None, endpoint_id=None):
        sid = int(submission_id)
        attempt_id = _normalize_attempt_id(attempt_id)
        client = _ensure_judge_redis() or _ensure_reverse_redis()
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

        endpoint_id = _normalize_endpoint_id(endpoint_id) or _normalize_endpoint_id(
            submission.get('agent_endpoint_id'),
        )
        ep, endpoint_error = _resolve_selected_endpoint(
            competition['id'], endpoint_id, endpoint_snapshot=submission,
        )
        if endpoint_error:
            _write_error_for_attempt(sid, attempt_id, endpoint_error)
            _publish_snapshot(sid)
            return {'success': False, 'message': endpoint_error}
        endpoints = [ep]

        ttl = int(competition.get('agent_judge_timeout_seconds') or JUDGE_DEFAULT_TIMEOUT) + JUDGE_SLOT_TTL_BUFFER
        ep, slot_key, slot_token = _acquire_endpoint_slot(client, endpoints, sid, ttl)
        if ep is None:
            return _retry_queued_submission(self, sid, attempt_id)

        lock_key = f'ranking:reverse_judge:lock:{sid}:{attempt_id or "legacy"}'
        lock_token = str(self.request.id or sid)
        got_lock = True
        if client is not None:
            try:
                got_lock = bool(client.set(lock_key, lock_token, nx=True, ex=int(ttl)))
            except Exception:
                got_lock = True
        if not got_lock:
            _release_slot(client, slot_key, slot_token)
            return {'success': False, 'message': '已有反向评测在进行'}
        try:
            fresh = get_ranking_submission(sid)
            skip, skip_msg = _task_should_skip(fresh, attempt_id)
            if skip:
                return {'success': True, 'message': skip_msg}

            ok, probe_msg = _probe_endpoint(ep)
            if ok:
                return _run_reverse_judge(sid, attempt_id, ep)

            _disable_unhealthy_endpoint(ep, probe_msg)
            message = '所选 AI 作答节点 hello 预检失败，已自动暂停；请选择其它节点或等待恢复'
            _write_error_for_attempt(sid, attempt_id, message)
            _publish_snapshot(sid)
            return {'success': False, 'message': message}
        except Retry:
            raise
        except Exception as e:
            try:
                _write_error_for_attempt(sid, attempt_id, f'反向评测任务异常：{e}')
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

    return evaluate_ranking_reverse_judge
