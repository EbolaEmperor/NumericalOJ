#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打榜赛评测 Celery 任务。

标准答案评分任务只评测用户上传的答案文件，不处理代码压缩包。
答案格式只影响上传约束；评分一律以子进程运行管理员配置的脚本，不存在兜底评分路径。
"""

import json
import math
import os
import subprocess
import sys
import traceback

import pymysql

from oj_modules.ranking_db import (
    claim_standard_ranking_evaluation,
    get_competition,
    get_ranking_submission,
    update_standard_ranking_result_for_task,
)


RANKING_EVALUATE_TASK_NAME = "oj.evaluate_ranking_submission"
DEFAULT_SCORING_SCRIPT_TIMEOUT_SECONDS = 120
_MYSQL_RETRY_ERRORS = (
    pymysql.err.OperationalError,
    pymysql.err.InterfaceError,
    pymysql.err.InternalError,
)


def _run_scoring_script(script_path, user_answer_path, reference_answer_path, max_score, timeout_seconds=None):
    """
    运行管理员提供的 python 评测脚本。约定：
        python <script> <user_answer_path> <reference_answer_path> <max_score>
    脚本需在 stdout 打印一行 JSON，形如：
        {"score": <number>, "details": <optional object/string>}
    """
    timeout_s = int(timeout_seconds) if timeout_seconds else DEFAULT_SCORING_SCRIPT_TIMEOUT_SECONDS
    try:
        proc = subprocess.run(
            [sys.executable, script_path, user_answer_path, reference_answer_path, str(max_score)],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'评测脚本执行超时（>{timeout_s}s）')

    if proc.returncode != 0:
        stderr = (proc.stderr or '').strip()[-2000:]
        raise RuntimeError(f'评测脚本退出码 {proc.returncode}: {stderr}')

    stdout = (proc.stdout or '').strip()
    if not stdout:
        raise RuntimeError('评测脚本未输出任何内容')

    # 只取最后一行有效 JSON，兼容脚本打印额外日志
    last_line = None
    for line in stdout.splitlines()[::-1]:
        line = line.strip()
        if line.startswith('{') and line.endswith('}'):
            last_line = line
            break
    if last_line is None:
        raise RuntimeError(f'评测脚本 stdout 不是合法 JSON：{stdout[-500:]}')

    try:
        parsed = json.loads(last_line)
    except json.JSONDecodeError as e:
        raise RuntimeError(f'评测脚本输出 JSON 解析失败：{e}')

    score = parsed.get('score')
    if score is None:
        raise RuntimeError('评测脚本输出缺少 score 字段')
    try:
        score_num = float(score)
    except (TypeError, ValueError):
        raise RuntimeError(f'评测脚本输出的 score 非数值：{score!r}')

    details = parsed.get('details')
    return score_num, details


def _finish_task(
        submission_id, task_id, score, status, response, *,
        grade_details=None, error_message=None):
    if not update_standard_ranking_result_for_task(
            submission_id,
            task_id,
            score,
            status,
            grade_details=grade_details,
            error_message=error_message,
    ):
        return {
            'success': True,
            'skipped': True,
            'message': '评测租约已被新任务替换，丢弃旧任务结果',
        }
    return response


def _evaluate(submission_id, task_id):
    submission = get_ranking_submission(submission_id)
    if not submission:
        return {'success': False, 'message': f'提交 #{submission_id} 不存在'}

    competition = get_competition(submission.get('competition_id'))
    if not competition:
        return _finish_task(
            submission_id,
            task_id,
            None,
            'Error',
            {'success': False, 'message': '比赛不存在'},
            error_message='比赛不存在或已被删除',
        )

    answer_path = submission.get('answer_path')
    if not answer_path or not os.path.isfile(answer_path):
        return _finish_task(
            submission_id,
            task_id,
            None,
            'Error',
            {'success': False, 'message': '用户答案文件不存在'},
            error_message='用户答案文件不存在',
        )

    ref_path = competition.get('reference_answer_path')
    if not ref_path or not os.path.isfile(ref_path):
        return _finish_task(
            submission_id,
            task_id,
            None,
            'Error',
            {'success': False, 'message': '赛事尚未配置标准答案'},
            error_message='赛事尚未配置标准答案文件',
        )

    max_score = int(competition.get('max_score') or 100)
    scoring_script = competition.get('scoring_script_path')
    has_script = bool(scoring_script and os.path.isfile(scoring_script))
    script_timeout = int(competition.get('scoring_script_timeout_seconds')
                         or DEFAULT_SCORING_SCRIPT_TIMEOUT_SECONDS)
    if not has_script:
        return _finish_task(
            submission_id,
            task_id,
            None,
            'Error',
            {'success': False, 'message': '赛事尚未配置评分脚本'},
            error_message='赛事尚未配置评分脚本',
        )

    try:
        score, details = _run_scoring_script(
            scoring_script, answer_path, ref_path, max_score,
            timeout_seconds=script_timeout,
        )
    except Exception as e:
        return _finish_task(
            submission_id,
            task_id,
            None,
            'Error',
            {'success': False, 'message': str(e)},
            error_message=f'评测失败：{e}\n{traceback.format_exc()[-1000:]}',
        )

    # 封顶/下限保护
    try:
        score_num = float(score)
    except (TypeError, ValueError):
        score_num = 0.0
    if math.isnan(score_num):
        score_num = 0.0
    score_num = max(0.0, min(score_num, float(max_score)))

    return _finish_task(
        submission_id,
        task_id,
        score_num,
        'Accepted',
        {'success': True, 'score': score_num},
        grade_details=details,
    )


def register_ranking_evaluate_task(celery_app):
    @celery_app.task(
        name=RANKING_EVALUATE_TASK_NAME,
        bind=True,
        autoretry_for=_MYSQL_RETRY_ERRORS,
        retry_backoff=True,
        retry_jitter=True,
        retry_kwargs={'max_retries': 3},
    )
    def evaluate_ranking_submission(self, submission_id):
        try:
            normalized_submission_id = int(submission_id)
            task_id = str(getattr(self.request, 'id', '') or '').strip()
            if not task_id:
                raise RuntimeError('普通打榜评测缺少 Celery task id')
            if not claim_standard_ranking_evaluation(normalized_submission_id, task_id):
                return {
                    'success': True,
                    'skipped': True,
                    'message': '旧任务已失去数据库租约，跳过重复评测',
                }
            return _evaluate(normalized_submission_id, task_id)
        except Exception as e:
            if isinstance(e, _MYSQL_RETRY_ERRORS):
                raise
            # 捕获再抛出，以便 Celery 正常记录异常
            try:
                update_standard_ranking_result_for_task(
                    int(submission_id),
                    str(getattr(self.request, 'id', '') or '').strip(),
                    None,
                    'Error',
                    error_message=f'评测任务异常：{e}',
                )
            except Exception:
                pass
            raise

    return evaluate_ranking_submission
