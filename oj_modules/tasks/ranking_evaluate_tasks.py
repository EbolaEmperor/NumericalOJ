#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打榜赛评测 Celery 任务。

仅评测用户上传的答案 JSON 文件，不处理代码压缩包。
若赛事配置了评测脚本，则以子进程运行脚本；否则使用默认的 JSON 数值对比打分。
"""

import json
import math
import os
import subprocess
import sys
import traceback

from oj_modules.ranking_db import (
    get_competition,
    get_ranking_submission,
    update_submission_result,
)


RANKING_EVALUATE_TASK_NAME = "oj.evaluate_ranking_submission"
SCORING_SCRIPT_TIMEOUT_SECONDS = 120
DEFAULT_NUMERIC_TOLERANCE = 1e-6


def _load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _numbers_match(a, b, tol=DEFAULT_NUMERIC_TOLERANCE):
    try:
        a_f = float(a)
        b_f = float(b)
    except (TypeError, ValueError):
        return False
    if math.isnan(a_f) or math.isnan(b_f):
        return False
    if math.isinf(a_f) or math.isinf(b_f):
        return a_f == b_f
    scale = max(1.0, abs(a_f), abs(b_f))
    return abs(a_f - b_f) <= tol * scale


def _count_leaves(value):
    if isinstance(value, dict):
        return sum(_count_leaves(v) for v in value.values())
    if isinstance(value, list):
        return sum(_count_leaves(v) for v in value)
    return 1


def _compare_recursive(user_val, ref_val):
    """返回 (matched, total)。"""
    if isinstance(ref_val, dict):
        if not isinstance(user_val, dict):
            return 0, _count_leaves(ref_val)
        matched = 0
        total = 0
        for key, ref_child in ref_val.items():
            user_child = user_val.get(key)
            m, t = _compare_recursive(user_child, ref_child)
            matched += m
            total += t
        return matched, total

    if isinstance(ref_val, list):
        total = _count_leaves(ref_val)
        if not isinstance(user_val, list):
            return 0, total
        matched = 0
        limit = min(len(user_val), len(ref_val))
        for i in range(limit):
            m, _ = _compare_recursive(user_val[i], ref_val[i])
            matched += m
        return matched, total

    # leaf
    if _is_number(ref_val):
        return (1 if _numbers_match(user_val, ref_val) else 0), 1
    if isinstance(ref_val, bool):
        return (1 if user_val is ref_val else 0), 1
    if ref_val is None:
        return (1 if user_val is None else 0), 1
    return (1 if user_val == ref_val else 0), 1


def _default_grade(user_answer, reference_answer, max_score):
    matched, total = _compare_recursive(user_answer, reference_answer)
    if total <= 0:
        return 0.0, {'matched': 0, 'total': 0, 'note': '参考答案为空，无法评分。'}
    ratio = matched / total
    score = round(ratio * float(max_score), 4)
    return score, {
        'matched': matched,
        'total': total,
        'ratio': round(ratio, 6),
        'max_score': float(max_score),
        'mode': 'default_json_compare',
        'tolerance': DEFAULT_NUMERIC_TOLERANCE,
    }


def _run_scoring_script(script_path, user_answer_path, reference_answer_path, max_score):
    """
    运行管理员提供的 python 评测脚本。约定：
        python <script> <user_answer_path> <reference_answer_path> <max_score>
    脚本需在 stdout 打印一行 JSON，形如：
        {"score": <number>, "details": <optional object/string>}
    """
    try:
        proc = subprocess.run(
            [sys.executable, script_path, user_answer_path, reference_answer_path, str(max_score)],
            capture_output=True,
            text=True,
            timeout=SCORING_SCRIPT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'评测脚本执行超时（>{SCORING_SCRIPT_TIMEOUT_SECONDS}s）')

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


def _evaluate(submission_id):
    submission = get_ranking_submission(submission_id)
    if not submission:
        return {'success': False, 'message': f'提交 #{submission_id} 不存在'}

    competition = get_competition(submission.get('competition_id'))
    if not competition:
        update_submission_result(
            submission_id, None, 'Error',
            grade_details=None, error_message='比赛不存在或已被删除',
        )
        return {'success': False, 'message': '比赛不存在'}

    answer_path = submission.get('answer_path')
    if not answer_path or not os.path.isfile(answer_path):
        update_submission_result(
            submission_id, None, 'Error',
            grade_details=None, error_message='用户答案文件不存在',
        )
        return {'success': False, 'message': '用户答案文件不存在'}

    ref_path = competition.get('reference_answer_path')
    if not ref_path or not os.path.isfile(ref_path):
        update_submission_result(
            submission_id, None, 'Error',
            grade_details=None, error_message='赛事尚未配置标准答案文件',
        )
        return {'success': False, 'message': '赛事尚未配置标准答案'}

    try:
        user_answer = _load_json(answer_path)
    except Exception as e:
        update_submission_result(
            submission_id, 0.0, 'Wrong Answer',
            grade_details=None, error_message=f'用户答案 JSON 解析失败：{e}',
        )
        return {'success': False, 'message': '用户答案 JSON 解析失败'}

    max_score = int(competition.get('max_score') or 100)

    scoring_script = competition.get('scoring_script_path')
    try:
        if scoring_script and os.path.isfile(scoring_script):
            score, details = _run_scoring_script(
                scoring_script, answer_path, ref_path, max_score,
            )
        else:
            reference_answer = _load_json(ref_path)
            score, details = _default_grade(user_answer, reference_answer, max_score)
    except Exception as e:
        update_submission_result(
            submission_id, None, 'Error',
            grade_details=None,
            error_message=f'评测失败：{e}\n{traceback.format_exc()[-1000:]}',
        )
        return {'success': False, 'message': str(e)}

    # 封顶/下限保护
    try:
        score_num = float(score)
    except (TypeError, ValueError):
        score_num = 0.0
    if math.isnan(score_num):
        score_num = 0.0
    score_num = max(0.0, min(score_num, float(max_score)))

    update_submission_result(
        submission_id, score_num, 'Accepted',
        grade_details=details, error_message=None,
    )
    return {'success': True, 'score': score_num}


def register_ranking_evaluate_task(celery_app):
    @celery_app.task(name=RANKING_EVALUATE_TASK_NAME, bind=True)
    def evaluate_ranking_submission(self, submission_id):
        try:
            return _evaluate(int(submission_id))
        except Exception as e:
            # 捕获再抛出，以便 Celery 正常记录异常
            try:
                update_submission_result(
                    int(submission_id), None, 'Error',
                    grade_details=None,
                    error_message=f'评测任务异常：{e}',
                )
            except Exception:
                pass
            raise

    return evaluate_ranking_submission
