#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛「批量评测」任务。

两个任务：
  - ``oj.ranking_batch_probe``：按管理员选定的班级名单 + Git 仓库标准命名（含
    ``<username>`` 占位符），逐个把占位符替换成学生用户名后用 ``git ls-remote`` 并发探测
    仓库是否存在，进度与结果写入 Redis 供前端轮询。
  - ``oj.ranking_batch_run``：**串行**处理管理员勾选的仓库列表——逐个拉取（``git clone
    --depth 1``，失败重试至多 3 次）、打包 zip 落盘、创建提交并校验（失败则删除该提交后重试至多
    3 次）、入队 Agent 评测，然后 sleep 1 秒再处理下一个。**不并发拉取**，避免一次性打满主机/网络。
    用户在「我的历史提交」里下载到的就是这份落盘 zip——即真正交给评测系统的代码，而非二次拉取。

设计要点：
  - 所有 git 调用 ``shell=False`` 传 argv，URL/用户名不经过 shell，避免命令注入；用户名在
    入口处用白名单正则校验。
  - SSH 走 BatchMode（绝不交互、不弹密码），失败/超时即判为「不存在/不可访问」。
  - Redis 仅用于「探测任务」的进度展示；落盘 zip 与提交状态以 MySQL 为准。
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import redis as _redis
except Exception:  # pragma: no cover
    _redis = None

import config as _cfg
from config import REDIS_DB, REDIS_HOST, REDIS_PORT
from oj_modules.db_services import get_users_in_classes
from oj_modules.ranking_db import (
    begin_agent_judge_attempt,
    create_ranking_submission, delete_ranking_submission, get_ranking_submission,
    RankingSubmissionQuotaExceeded,
    set_agent_judge_task_id, submission_dir, update_submission_files, update_submission_result,
)

PROBE_TASK_NAME = 'oj.ranking_batch_probe'
RUN_TASK_NAME = 'oj.ranking_batch_run'

# 仓库命名里的用户名占位符
PLACEHOLDER = '<username>'
# 安全用户名：仅允许字母/数字/下划线/点/连字符，且不以 '-' 开头（防止被 git 当作选项）。
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.][A-Za-z0-9_.\-]*$')

# 配置（getattr 回退，远端 config.py 无需改动）
GIT_LSREMOTE_TIMEOUT = int(getattr(_cfg, 'RANKING_BATCH_LSREMOTE_TIMEOUT', 20))
GIT_CLONE_TIMEOUT = int(getattr(_cfg, 'RANKING_BATCH_CLONE_TIMEOUT', 180))
PROBE_CONCURRENCY = max(1, int(getattr(_cfg, 'RANKING_BATCH_PROBE_CONCURRENCY', 12)))
PROBE_MAX_USERS = int(getattr(_cfg, 'RANKING_BATCH_PROBE_MAX_USERS', 1000))
CLONE_ZIP_MAX_BYTES = int(getattr(_cfg, 'RANKING_BATCH_CLONE_ZIP_MAX_BYTES', 128 * 1024 * 1024))
JOB_TTL = int(getattr(_cfg, 'RANKING_BATCH_JOB_TTL', 6 * 3600))
# 串行批量创建：拉取/创建各自的重试次数，以及处理完一个仓库后 sleep 的秒数。
PULL_RETRY = max(1, int(getattr(_cfg, 'RANKING_BATCH_PULL_RETRY', 3)))
CREATE_RETRY = max(1, int(getattr(_cfg, 'RANKING_BATCH_CREATE_RETRY', 3)))
ITEM_SLEEP_SECONDS = float(getattr(_cfg, 'RANKING_BATCH_ITEM_SLEEP_SECONDS', 1.0))

_batch_rds = None


def init_batch_progress_cache(redis_client):
    """由 oj.py 注入 Redis 客户端（web 与 worker 进程都会调用一次）。"""
    global _batch_rds
    _batch_rds = redis_client


def _ensure_rds():
    global _batch_rds
    if _batch_rds is not None:
        return _batch_rds
    if _redis is None:
        return None
    try:
        _batch_rds = _redis.StrictRedis(
            host=REDIS_HOST, port=int(REDIS_PORT), db=int(REDIS_DB), decode_responses=True,
        )
        _batch_rds.ping()
    except Exception:
        _batch_rds = None
    return _batch_rds


def probe_job_key(job_id):
    return f'ranking:batch:probe:{job_id}'


def get_probe_job(job_id):
    """读取探测任务进度/结果，返回 dict 或 None（不存在/未开始）。"""
    rds = _ensure_rds()
    if rds is None:
        return None
    try:
        raw = rds.get(probe_job_key(str(job_id)))
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _save_probe_job(job_id, payload):
    rds = _ensure_rds()
    if rds is None:
        return
    try:
        rds.setex(probe_job_key(str(job_id)), JOB_TTL, json.dumps(payload, ensure_ascii=False))
    except Exception:
        pass


def _git_env():
    env = dict(os.environ)
    env['GIT_TERMINAL_PROMPT'] = '0'          # 绝不弹凭据交互（否则会挂起）
    env.setdefault(
        'GIT_SSH_COMMAND',
        'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10',
    )
    return env


def build_repo_url(template, username):
    """把命名模板里的 ``<username>`` 占位符替换为用户名。"""
    return (template or '').replace(PLACEHOLDER, username)


def repo_exists(url):
    """用 ``git ls-remote`` 探测仓库是否存在/可访问。返回 ``(exists, message)``。"""
    if not url or url.startswith('-'):
        return False, '非法的仓库地址'
    try:
        proc = subprocess.run(
            ['git', 'ls-remote', url],
            env=_git_env(), capture_output=True, text=True,
            timeout=GIT_LSREMOTE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, '探测超时'
    except Exception as e:  # pragma: no cover
        return False, f'探测失败：{e}'
    if proc.returncode == 0:
        return True, 'ok'
    lines = (proc.stderr or proc.stdout or '').strip().splitlines()
    return False, (lines[0].strip() if lines else f'git 退出码 {proc.returncode}')


def repo_last_commit(url):
    """浅克隆仓库并取最后一条 commit 的信息。返回 ``(exists, info, message)``：

    - ``exists``：仓库是否存在/可访问；
    - ``info``：成功时为 ``{'hash','short','author','date_iso','subject','body'}``，否则 ``None``；
    - ``message``：失败原因（成功时为 ``'ok'``）。

    用 ``git clone --depth 1`` 而非 ``ls-remote``，以便拿到提交的作者/时间/标题等明细。
    """
    if not url or url.startswith('-'):
        return False, None, '非法的仓库地址'
    tmp = tempfile.mkdtemp(prefix='rankcheck_')
    clone_dir = os.path.join(tmp, 'repo')
    try:
        ok, err = _clone_to_dir(url, clone_dir)
        if not ok:
            return False, None, err
        try:
            sep = '\x1f'  # 单元分隔符，避免与提交内容里的字符冲突
            fmt = sep.join(['%H', '%h', '%an', '%aI', '%s', '%b'])
            proc = subprocess.run(
                ['git', '-C', clone_dir, 'log', '-1', '--pretty=format:' + fmt],
                env=_git_env(), capture_output=True, text=True, timeout=GIT_LSREMOTE_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return True, None, '读取提交信息超时'
        except Exception as e:  # pragma: no cover
            return True, None, f'读取提交信息失败：{str(e)[:200]}'
        if proc.returncode != 0:
            # 克隆成功但没有提交（空仓库）
            return True, None, '仓库为空（无任何提交）'
        parts = (proc.stdout or '').split(sep)
        while len(parts) < 6:
            parts.append('')
        info = {
            'hash': parts[0].strip(),
            'short': parts[1].strip(),
            'author': parts[2].strip(),
            'date_iso': parts[3].strip(),
            'subject': parts[4].strip(),
            'body': parts[5].strip(),
        }
        return True, info, 'ok'
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _zip_tree(src_dir, zip_path):
    """把 ``src_dir`` 下的内容打包为 zip（排除 ``.git`` 与符号链接），文件位于 zip 根部，
    从而 Agent 评测解包后直接落在 ``submission/`` 下（与手工上传 zip 行为一致）。"""
    src_dir = os.path.realpath(src_dir)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(src_dir):
            dirs[:] = [d for d in dirs if d != '.git']
            for fn in files:
                fp = os.path.join(root, fn)
                if os.path.islink(fp):
                    continue
                arc = os.path.relpath(fp, src_dir)
                try:
                    zf.write(fp, arc)
                except Exception:
                    pass


def _clone_to_dir(url, clone_dir):
    """git clone --depth 1 到 clone_dir。返回 (ok, err_msg)。"""
    try:
        proc = subprocess.run(
            ['git', 'clone', '--depth', '1', url, clone_dir],
            env=_git_env(), capture_output=True, text=True, timeout=GIT_CLONE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, f'git clone 超时（>{GIT_CLONE_TIMEOUT}s）'
    except Exception as e:  # pragma: no cover
        return False, f'git clone 异常：{str(e)[:200]}'
    if proc.returncode != 0:
        lines = [l.strip() for l in (proc.stderr or proc.stdout or '').splitlines() if l.strip()]
        # 优先取最具信息量的一行（Gitea/fatal/denied/not found），否则退回最后一行
        pick = ''
        for l in lines:
            low = l.lower()
            if ('gitea:' in low or 'cannot find' in low or l.startswith('fatal:')
                    or 'denied' in low or 'not found' in low):
                pick = l
                break
        if not pick:
            pick = lines[-1] if lines else f'退出码 {proc.returncode}'
        pick = pick.replace('remote:', '').strip()
        return False, ('git clone 失败：' + pick[:200])
    return True, ''


def _pull_and_zip(url, zip_path):
    """拉取仓库并打包到 zip_path，失败重试至多 PULL_RETRY 次。返回 (ok, err_msg)。"""
    if not url or url.startswith('-'):
        return False, '非法的仓库地址'
    last_err = ''
    for _attempt in range(PULL_RETRY):
        tmp = tempfile.mkdtemp(prefix='rankclone_')
        clone_dir = os.path.join(tmp, 'repo')
        try:
            ok, err = _clone_to_dir(url, clone_dir)
            if not ok:
                last_err = err
                continue
            try:
                if os.path.exists(zip_path):
                    os.remove(zip_path)
                _zip_tree(clone_dir, zip_path)
                size = os.path.getsize(zip_path) if os.path.isfile(zip_path) else 0
            except Exception as e:
                last_err = f'打包失败：{str(e)[:200]}'
                continue
            if size == 0:
                last_err = '仓库为空或打包失败（无可评测文件）'
                continue
            if size > CLONE_ZIP_MAX_BYTES:
                # 体积超限不是可重试的瞬时失败，直接判失败
                return False, f'代码打包超过 {CLONE_ZIP_MAX_BYTES // (1024 * 1024)}MB 限制'
            return True, ''
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return False, (last_err or '拉取失败')


def _create_submission_with_retry(competition_id, username, zip_path, pull_err, agent_judge_task,
                                  source='batch'):
    """创建提交并校验，失败则删除已建提交后重试，至多 CREATE_RETRY 次。

    - 拉取成功（zip_path 有效）：落盘 zip → 置 'Queued'（等待评测）→ 入队 Agent 评测；
    - 拉取失败（zip_path=None）：建一条 'Error' 提交记录该用户拉取失败，便于核对。
    返回 (ok, submission_id|None)。
    """
    src = 'self' if str(source or '').strip().lower() == 'self' else 'batch'
    for _attempt in range(CREATE_RETRY):
        sid = None
        try:
            # source='batch'：管理员批量拉取，不占用学生的 48h 自交配额；
            # source='self'：学生 git 提交，占用配额并走数据库侧原子限额。
            sid = create_ranking_submission(
                competition_id, username, source=src, enforce_quota=(src == 'self'),
            )
            if not sid:
                continue
            if zip_path:
                target_dir = submission_dir(sid)
                os.makedirs(target_dir, exist_ok=True)
                code_name = 'FinalProject.zip'
                code_path = os.path.join(target_dir, code_name)
                shutil.copy(zip_path, code_path)
                update_submission_files(sid, None, None, code_name, code_path, base_model=None)
                attempt_id = begin_agent_judge_attempt(sid, status='Queued', reset_result=True)
                sub = get_ranking_submission(sid)       # 校验：行存在 + code_path 落盘成功
                if not sub or not sub.get('code_path') or not os.path.isfile(sub.get('code_path')):
                    raise RuntimeError('提交创建校验失败（code_path 缺失）')
                if agent_judge_task is not None:
                    async_result = agent_judge_task.apply_async(args=[sid, attempt_id])
                    set_agent_judge_task_id(sid, attempt_id, async_result.id)
            else:
                update_submission_result(sid, None, 'Error',
                                         error_message=(pull_err or 'git clone 失败')[:300])
                sub = get_ranking_submission(sid)
                if not sub or sub.get('status') != 'Error':
                    raise RuntimeError('提交创建校验失败')
            return True, sid
        except RankingSubmissionQuotaExceeded:
            return False, None
        except Exception:
            # 删掉这次没建成功的提交（行 + 落盘文件），然后重试
            if sid:
                try:
                    td = submission_dir(sid)
                    if os.path.isdir(td):
                        shutil.rmtree(td, ignore_errors=True)
                except Exception:
                    pass
                try:
                    delete_ranking_submission(sid)
                except Exception:
                    pass
    return False, None


def _process_one(competition_id, username, url, agent_judge_task, source='batch'):
    """串行处理单个仓库：拉取(重试) → 创建提交(校验+重试) → 入队评测。"""
    tmp = tempfile.mkdtemp(prefix='rankrun_')
    zip_path = os.path.join(tmp, 'code.zip')
    try:
        ok, err = _pull_and_zip(url, zip_path)
        _create_submission_with_retry(
            competition_id, username, zip_path if ok else None, err, agent_judge_task,
            source=source,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def register_ranking_batch_tasks(celery_app, agent_judge_task=None):
    """注册并返回 ``(probe_task, run_task)``。

    ``run_task`` 串行处理勾选的仓库列表；``agent_judge_task`` 为已注册的 Agent 评测任务引用，
    拉取成功后由它接力评测（任务名路由到 ``judge`` 队列，并发上限 2）。
    """

    @celery_app.task(name=PROBE_TASK_NAME, bind=True)
    def ranking_batch_probe(self, job_id, competition_id, class_list, template):
        users = get_users_in_classes(class_list)
        truncated = len(users) > PROBE_MAX_USERS
        users = users[:PROBE_MAX_USERS]

        candidates = []  # (username, class_cn, url)
        skipped = 0
        for u in users:
            uname = (u.get('username') or '').strip()
            if not uname or not USERNAME_RE.match(uname):
                skipped += 1
                continue
            candidates.append((uname, u.get('class_cn') or '', build_repo_url(template, uname)))

        total = len(candidates)
        payload = {
            'state': 'running', 'total': total, 'checked': 0,
            'found': [], 'skipped': skipped, 'truncated': truncated,
        }
        _save_probe_job(job_id, payload)
        if total == 0:
            payload['state'] = 'done'
            _save_probe_job(job_id, payload)
            return {'total': 0, 'found': 0}

        found = []
        checked = 0
        with ThreadPoolExecutor(max_workers=min(PROBE_CONCURRENCY, total)) as ex:
            fut_map = {ex.submit(repo_exists, url): (uname, cn, url)
                       for (uname, cn, url) in candidates}
            for fut in as_completed(fut_map):
                uname, cn, url = fut_map[fut]
                checked += 1
                try:
                    exists, _msg = fut.result()
                except Exception:
                    exists = False
                if exists:
                    found.append({'username': uname, 'class_cn': cn, 'url': url})
                # 限制 Redis 写频率：每 3 个或最后一个刷新一次进度
                if checked % 3 == 0 or checked == total:
                    payload['checked'] = checked
                    payload['found'] = sorted(found, key=lambda x: x['username'])
                    _save_probe_job(job_id, payload)

        payload['state'] = 'done'
        payload['checked'] = total
        payload['found'] = sorted(found, key=lambda x: x['username'])
        _save_probe_job(job_id, payload)
        return {'total': total, 'found': len(found)}

    @celery_app.task(name=RUN_TASK_NAME, bind=True, acks_late=False)
    def ranking_batch_run(self, competition_id, items):
        """串行处理勾选的仓库列表：逐个拉取/创建/入队，处理完一个 sleep 1 秒再下一个。

        acks_late=False：本任务非幂等（每次运行都会新建提交），故不让 broker 在 worker
        丢失时重投以免重复创建；worker 异常退出则整批中止，由管理员重新发起即可。
        """
        done = 0
        for it in (items or []):
            if not isinstance(it, dict):
                continue
            username = str(it.get('username') or '').strip()
            url = str(it.get('url') or '').strip()
            source = 'self' if str(it.get('source') or '').strip().lower() == 'self' else 'batch'
            if not username or not USERNAME_RE.match(username) or not url:
                continue
            try:
                _process_one(competition_id, username, url, agent_judge_task, source=source)
            except Exception:
                pass
            done += 1
            time.sleep(ITEM_SLEEP_SECONDS)
        return {'count': done}

    return ranking_batch_probe, ranking_batch_run
