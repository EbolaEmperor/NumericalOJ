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
import shutil
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

from oj_modules import config as _cfg
from oj_modules.db_services import get_users_in_classes
from oj_modules.infrastructure.redis import create_optional_redis_client
from oj_modules.ranking.batch import (
    GIT_CLONE_TIMEOUT,
    GIT_LSREMOTE_TIMEOUT,
    PLACEHOLDER,
    USERNAME_RE,
    _clone_to_dir,
    build_repo_url,
    repo_exists,
    repo_last_commit,
)
from oj_modules.ranking.db import (
    begin_agent_judge_attempt,
    create_ranking_submission, delete_ranking_submission, get_competition, get_ranking_submission,
    RankingSubmissionQuotaExceeded,
    set_agent_judge_task_id, submission_dir, update_submission_files, update_submission_result,
)

PROBE_TASK_NAME = 'oj.ranking_batch_probe'
RUN_TASK_NAME = 'oj.ranking_batch_run'

# 配置（getattr 回退，远端 oj_modules/config.py 无需改动）
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
    _batch_rds = create_optional_redis_client()
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


def _mode_for_competition(competition_id):
    comp = get_competition(int(competition_id))
    mode = str((comp or {}).get('scoring_mode') or 'absolute').strip().lower()
    return mode if mode in ('agent_judge', 'reverse_judge') else 'agent_judge'


def _create_submission_with_retry(competition_id, username, zip_path, pull_err, judge_task,
                                  source='batch', mode='agent_judge', agent_endpoint_id=None):
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
                agent_endpoint_id=agent_endpoint_id if mode == 'reverse_judge' else None,
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
                if judge_task is not None:
                    args = [sid, attempt_id]
                    if mode == 'reverse_judge':
                        args.append(agent_endpoint_id)
                    async_result = judge_task.apply_async(args=args)
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


def _process_one(competition_id, username, url, judge_task, source='batch',
                 mode='agent_judge', agent_endpoint_id=None):
    """串行处理单个仓库：拉取(重试) → 创建提交(校验+重试) → 入队评测。"""
    tmp = tempfile.mkdtemp(prefix='rankrun_')
    zip_path = os.path.join(tmp, 'code.zip')
    try:
        ok, err = _pull_and_zip(url, zip_path)
        _create_submission_with_retry(
            competition_id, username, zip_path if ok else None, err, judge_task,
            source=source, mode=mode, agent_endpoint_id=agent_endpoint_id,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def register_ranking_batch_tasks(celery_app, agent_judge_task=None, reverse_judge_task=None):
    """注册并返回 ``(probe_task, run_task)``。

    ``run_task`` 串行处理勾选的仓库列表；``agent_judge_task`` 为已注册的 Agent 评测任务引用，
    拉取成功后由它接力评测（任务名路由到 ``judge`` 队列，并发上限 2）。
    """

    @celery_app.task(name=PROBE_TASK_NAME, bind=True)
    def ranking_batch_probe(self, job_id, competition_id, class_list, template):
        users = get_users_in_classes(class_list)
        truncated = len(users) > PROBE_MAX_USERS
        users = users[:PROBE_MAX_USERS]

        candidates = []  # (username, classes_display, url)
        skipped = 0
        for u in users:
            uname = (u.get('username') or '').strip()
            if not uname or not USERNAME_RE.match(uname):
                skipped += 1
                continue
            candidates.append((
                uname,
                u.get('classes_display') or '',
                build_repo_url(template, uname),
            ))

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
            fut_map = {
                ex.submit(repo_exists, url): (uname, classes_display, url)
                for (uname, classes_display, url) in candidates
            }
            for fut in as_completed(fut_map):
                uname, classes_display, url = fut_map[fut]
                checked += 1
                try:
                    exists, _msg = fut.result()
                except Exception:
                    exists = False
                if exists:
                    found.append({
                        'username': uname,
                        'classes_display': classes_display,
                        'url': url,
                    })
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
        mode = _mode_for_competition(competition_id)
        judge_task = reverse_judge_task if mode == 'reverse_judge' else agent_judge_task
        for it in (items or []):
            if not isinstance(it, dict):
                continue
            username = str(it.get('username') or '').strip()
            url = str(it.get('url') or '').strip()
            source = 'self' if str(it.get('source') or '').strip().lower() == 'self' else 'batch'
            endpoint_id = it.get('agent_endpoint_id')
            if not username or not USERNAME_RE.match(username) or not url:
                continue
            try:
                _process_one(
                    competition_id, username, url, judge_task, source=source,
                    mode=mode, agent_endpoint_id=endpoint_id,
                )
            except Exception:
                pass
            done += 1
            time.sleep(ITEM_SLEEP_SECONDS)
        return {'count': done}

    return ranking_batch_probe, ranking_batch_run
