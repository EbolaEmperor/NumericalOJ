#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import math
import os
import re

import requests
import pymysql

from celery.exceptions import SoftTimeLimitExceeded

from oj_modules.judging import core

from oj_modules.ai.grading import evaluate_program_output_image_with_ai
from oj_modules.db_services import (
    get_db_connection,
    insert_user_problem_ac_record_if_absent,
    get_problem,
    get_submission_by_id,
    safe_table_name,
    set_submission_status_snapshot,
    get_user_classes,
    get_user_by_id,
    upsert_user_problem_max_score_if_higher,
    update_submission_evaluation,
    update_submission_status,
)
from oj_modules.submissions import locks as submission_locks
from oj_modules.submissions.repository_snapshots import (
    RepositorySnapshotError,
    load_submission_repository_entries,
    resolve_submission_repository_user_id,
)


EVALUATE_TASK_NAME = "oj.evaluate_submission"
_MYSQL_RETRY_ERRORS = (
    pymysql.err.OperationalError,
    pymysql.err.InterfaceError,
    pymysql.err.InternalError,
)


def _normalize_programming_grading_mode(problem):
    try:
        mode = int((problem or {}).get('programming_grading_mode') or 1)
    except Exception:
        mode = 1
    return mode if mode in (1, 2, 3) else 1


def _extract_output_image_filename(files_dict, preferred_prefix=None):
    if not isinstance(files_dict, dict):
        return False, ""

    image_names = []
    for key, value in files_dict.items():
        name = str(key or "").strip()
        if not name or not value:
            continue
        if name in ("stdout", "stderr"):
            continue
        lower = name.lower()
        if lower.endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp")):
            image_names.append(name)

    if preferred_prefix:
        prefix = str(preferred_prefix).strip()
        for name in image_names:
            if name.startswith(prefix):
                return True, name
    if image_names:
        return True, image_names[0]
    return False, ""


def _resolve_saved_output_image_path(sid, filename):
    clean_sid = str(sid or "").strip()
    clean_name = os.path.basename(str(filename or "").strip())
    if not clean_sid or not clean_name:
        return None

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    cwd = os.getcwd()
    possible_paths = [
        os.path.join(core.run_dir_for(clean_sid), clean_name),
        os.path.join(project_root, "judger", clean_sid, clean_name),
        os.path.join(cwd, "judger", clean_sid, clean_name),
        os.path.join("/tmp", clean_sid, clean_name),
        os.path.join(cwd, clean_sid, clean_name),
        os.path.expanduser(os.path.join("~", "oj", "judger", clean_sid, clean_name)),
    ]
    seen = set()
    for raw_path in possible_paths:
        path = os.path.abspath(os.path.expanduser(raw_path))
        if path in seen:
            continue
        seen.add(path)
        if core.is_safe_regular_artifact(path):
            return path
    return None


def _build_image_mode_comment_from_run_result(run_status, stderr, expected_filename):
    status_text = str(run_status or "Error").strip() or "Error"
    stderr_text = str(stderr or "").strip()
    if status_text == "Accepted":
        return f"程序运行完成，但未生成要求的输出图片文件 `{expected_filename}`。"
    if stderr_text:
        return f"程序未能生成可批改图片。运行状态：{status_text}。\n\n运行信息：\n{stderr_text}"
    return f"程序未能生成可批改图片。运行状态：{status_text}。"


def _normalize_image_mode_test_point_status(run_status, image_grading_score):
    status_text = str(run_status or "Error").strip() or "Error"
    if status_text == "Accepted":
        return "Accepted" if int(image_grading_score or 0) == 1 else "Wrong Answer"
    return status_text


def _build_terminal_test_point_statuses(test_cases, status, stderr="", stdout=""):
    test_point_count = len(test_cases or []) or 1
    return [{
        "status": status,
        "stderr": stderr,
        "stdout": stdout,
        "time": 0,
        "has_output_image": False,
        "test_index": idx,
    } for idx in range(1, test_point_count + 1)]


def _finalize_programming_terminal_submission(
    submission,
    problem_id,
    test_cases,
    final_status,
    stderr="",
    stdout="",
):
    test_point_statuses = _build_terminal_test_point_statuses(
        test_cases,
        final_status,
        stderr=stderr,
        stdout=stdout,
    )
    _finalize_programming_submission(
        submission=submission,
        problem_id=problem_id,
        test_point_statuses=test_point_statuses,
        score=0,
        final_status=final_status,
    )
    return test_point_statuses


def _mark_repository_snapshot_terminal_error(submission):
    """把不可恢复的仓库快照错误固化为终态，禁止 watchdog 无限重投。"""
    message = (
        "提交绑定的代码仓库快照缺失、损坏或无法安全读取，评测已停止。"
        "请联系管理员检查仓库存储。"
    )
    test_points = _build_terminal_test_point_statuses(
        [],
        "Error",
        stderr=message,
    )
    update_submission_evaluation(
        int(submission["id"]),
        test_points,
        0,
        "Error",
    )
    # DB helper 会刷新一次缓存；这里再以本次已知终态显式覆盖，避免前一条
    # Running SSE 快照在 Redis 短暂抖动或刷新读取延迟时继续留在前端。
    set_submission_status_snapshot(
        submission_id=int(submission["id"]),
        username=submission.get("username"),
        problem_id=submission.get("problem_id"),
        problem_type=submission.get("problem_type"),
        status="Error",
        score=0,
        test_points=test_points,
    )
    return test_points


def _finalize_programming_submission(submission, problem_id, test_point_statuses, score, final_status):
    user_id = resolve_submission_repository_user_id(int(submission["id"]))
    user = get_user_by_id(user_id)
    if not user:
        raise RuntimeError("提交绑定的用户不存在，无法结算评测结果")
    if final_status == "Accepted":
        if insert_user_problem_ac_record_if_absent(user['id'], problem_id):
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = 'UPDATE problems SET cnt=cnt+1 WHERE id=%s'
                    cursor.execute(sql, (problem_id,))
                conn.commit()
            finally:
                conn.close()
            if user['is_admin'] != 1:
                bump_complete_cnt_for_user_classes(user, problem_id)

    upsert_user_problem_max_score_if_higher(user['id'], problem_id, score)
    update_submission_evaluation(submission['id'], test_point_statuses, score, final_status)


def _submission_lock_key(submission_id):
    return submission_locks.submission_lock_key(submission_id)


def _acquire_submission_lock(submission_id):
    return submission_locks.acquire_submission_lock(submission_id)


def _release_submission_lock(client, key, token):
    submission_locks.release_submission_lock(client, key, token)


def acquire_submission_lock(submission_id):
    return _acquire_submission_lock(submission_id)


def release_submission_lock(client, key, token):
    _release_submission_lock(client, key, token)


def clear_submission_lock(submission_id):
    """无条件清除某条提交的评测幂等锁。

    仅用于进程启动时的重新入队：此时 Celery worker 都是刚启动的，不存在真正在
    评测中的任务，残留的 submission:{id}:lock 必然是上次进程被杀留下的“僵尸锁”。
    清掉它，重新入队的任务才能拿到锁正常重跑（否则会被幂等逻辑跳过）。
    """
    submission_locks.clear_submission_lock(submission_id)


def has_submission_lock(submission_id):
    """返回某条提交是否仍持有评测幂等锁。"""
    return submission_locks.has_submission_lock(submission_id)


def compare_float_strings(str1, str2, tolerance=1e-5):
    split_pattern = r'[\s,]+'

    try:
        list1 = [float(x) for x in re.split(split_pattern, str1.strip()) if x]
        list2 = [float(x) for x in re.split(split_pattern, str2.strip()) if x]
    except ValueError:
        return str1 == str2

    if len(list1) != len(list2):
        return False

    for a, b in zip(list1, list2):
        if math.isnan(a) or math.isnan(b):
            return False
        if a == 0 and b == 0:
            continue
        max_val = max(abs(a), abs(b))
        abs_error = abs(a - b)
        relative_error = abs_error / max_val
        if relative_error > tolerance and abs_error > tolerance:
            return False
    return True


def bump_complete_cnt_for_user_classes(user, problem_id):
    classes = get_user_classes(user['id'])
    conn = get_db_connection()
    try:
        for cls in classes:
            try:
                class_en = safe_table_name(cls['class_en'])
            except ValueError:
                continue
            with conn.cursor() as cursor:
                cursor.execute(f"SELECT id FROM {class_en} WHERE problem_id=%s", (problem_id,))
                row = cursor.fetchone()
                if row:
                    cursor.execute(
                        f"UPDATE {class_en} SET complete_cnt = complete_cnt + 1 WHERE problem_id=%s",
                        (problem_id,),
                    )
        conn.commit()
    finally:
        conn.close()


def register_evaluate_submission_task(celery_app):
    existing = celery_app.tasks.get(EVALUATE_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(
        name=EVALUATE_TASK_NAME,
        bind=True,
        time_limit=300,
        soft_time_limit=240,
        autoretry_for=_MYSQL_RETRY_ERRORS,
        retry_backoff=True,
        retry_jitter=True,
        retry_kwargs={'max_retries': 3},
    )
    def evaluate_submission(self, submission_id):
        submission = get_submission_by_id(submission_id)
        if not submission:
            return

        lock_client, lock_key, lock_token = _acquire_submission_lock(submission_id)
        if lock_client is not None and lock_token is None:
            print(f"[Idempotency] Skip duplicate evaluation for submission_id={submission_id}")
            return

        if lock_client is None:
            print(f"[Idempotency] Redis lock unavailable, run without lock for submission_id={submission_id}")

        try:
            # 重新读取，避免使用加锁前的旧快照
            submission = get_submission_by_id(submission_id)
            if not submission:
                return
            if submission.get('status') not in ('Pending', 'Waiting', 'Running'):
                print(
                    f"[Idempotency] Skip evaluation for submission_id={submission_id}, "
                    f"status={submission.get('status')}"
                )
                return

            update_submission_status(submission_id, 'Running')
            set_submission_status_snapshot(
                submission_id=submission_id,
                username=submission.get('username'),
                problem_id=submission.get('problem_id'),
                problem_type=submission.get('problem_type'),
                status='Running',
                score=0,
                test_points=[],
            )

            problem_id = submission['problem_id']
            raw_submission_code = submission['code'] or ''
            code = raw_submission_code
            # 安全：用户代码若混入评测包裹标记串，会截断禁用函数检查的扫描区间从而绕过过滤。
            # 包裹前先剥离这些标记串，使标记不可被用户伪造。
            for _marker in ("here_is_user_code_fuck_fuck_fuck_hahaha", "user_code_end_fuck_hahaha_fuck"):
                if _marker in code:
                    code = code.replace(_marker, "")
            problem = get_problem(problem_id)
            programming_grading_mode = _normalize_programming_grading_mode(problem)
            required_output_image_filename = (
                str(problem.get('programming_output_filename') or 'output.png').strip()
                or 'output.png'
            )
            lang = (problem.get('lang') or 'matlab').strip().lower()
            test_code = problem.get('test_code') or ''

            user_files = []

            if lang in ['c', 'cpp']:
                # 新提交必须读取创建时绑定的不可变仓库树；快照损坏或缺失时评测
                # fail-closed。仅迁移边界明确标记的历史提交由 helper 记录警告并
                # 兼容读取实时仓库。
                repository_user_id = resolve_submission_repository_user_id(
                    int(submission_id)
                )
                user_files = load_submission_repository_entries(
                    submission_id=int(submission_id),
                    user_id=repository_user_id,
                )

            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = "SELECT forbidden_func FROM problems WHERE id=%s"
                    cursor.execute(sql, (problem_id,))
                    fbd_func_row = cursor.fetchone()
                    fbd_func = (fbd_func_row or {}).get("forbidden_func", "") if fbd_func_row else ""
            finally:
                conn.close()

            if lang == 'matlab':
                if test_code and "%%user_code_here" in test_code:
                    wrapped_user_code = (
                        "%here_is_user_code_fuck_fuck_fuck_hahaha\n"
                        + code
                        + "\n%user_code_end_fuck_hahaha_fuck\n"
                    )
                    final_code = test_code.replace("%%user_code_here", wrapped_user_code)
                else:
                    final_code = (
                        "%here_is_user_code_fuck_fuck_fuck_hahaha\n"
                        + code
                        + "\n%user_code_end_fuck_hahaha_fuck\n"
                    )

            elif lang == 'c':
                if test_code and "%%user_code_here" in test_code:
                    wrapped_user_code = (
                        "/*here_is_user_code_fuck_fuck_fuck_hahaha*/\n"
                        + code
                        + "\n/*user_code_end_fuck_hahaha_fuck*/\n"
                    )
                    final_code = test_code.replace("%%user_code_here", wrapped_user_code)
                else:
                    final_code = (
                        "/*here_is_user_code_fuck_fuck_fuck_hahaha*/\n"
                        + code
                        + "\n/*user_code_end_fuck_hahaha_fuck*/\n"
                    )

            elif lang == 'cpp':
                if test_code and "%%user_code_here" in test_code:
                    wrapped_user_code = (
                        "/*here_is_user_code_fuck_fuck_fuck_hahaha*/\n"
                        + code
                        + "\n/*user_code_end_fuck_hahaha_fuck*/\n"
                    )
                    final_code = test_code.replace("%%user_code_here", wrapped_user_code)
                else:
                    final_code = (
                        "/*here_is_user_code_fuck_fuck_fuck_hahaha*/\n"
                        + code
                        + "\n/*user_code_end_fuck_hahaha_fuck*/\n"
                    )

            elif lang in ['python', 'py']:
                if test_code and "%%user_code_here" in test_code:
                    wrapped_user_code = (
                        "#here_is_user_code_fuck_fuck_fuck_hahaha\n"
                        + code
                        + "\n#user_code_end_fuck_hahaha_fuck\n"
                    )
                    final_code = test_code.replace("%%user_code_here", wrapped_user_code)
                else:
                    final_code = (
                        "#here_is_user_code_fuck_fuck_fuck_hahaha\n"
                        + code
                        + "\n#user_code_end_fuck_hahaha_fuck\n"
                    )
            else:
                update_submission_status(submission_id, 'Error')
                return

            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = "SELECT testdata FROM problems WHERE id=%s"
                    cursor.execute(sql, (problem_id,))
                    result = cursor.fetchone()
                    testdata_json = (result or {}).get('testdata')
            finally:
                conn.close()

            test_cases = []
            if testdata_json:
                try:
                    parsed_test_cases = json.loads(testdata_json)
                    if isinstance(parsed_test_cases, list):
                        test_cases = parsed_test_cases
                except json.JSONDecodeError:
                    if programming_grading_mode != 2:
                        update_submission_status(submission_id, 'Error')
                        return

            if programming_grading_mode != 2 and not test_cases:
                update_submission_status(submission_id, 'Error')
                return

            test_point_statuses = []
            all_accepted = True

            time_limit_ms = problem.get('time_limit_ms') or 2000
            time_limit_ns = int(time_limit_ms) * 1000000
            batch_result = None

            if programming_grading_mode == 2:
                single_case = test_cases[0] if test_cases else {}
                single_input = ""
                if isinstance(single_case, dict):
                    single_input = str(single_case.get("input", "") or "")
                single_sid = f"eoj-{submission_id}-1"
                single_payload = {
                    "code": final_code,
                    "submittedCode": raw_submission_code,
                    "checkerCode": test_code,
                    "input": single_input,
                    "forbidden": fbd_func,
                    "sid": single_sid,
                    "timeLimit": time_limit_ns,
                    "memoryLimit": 512 * 1024 * 1024,
                    "user_files": user_files,
                    "outputImageFilename": required_output_image_filename,
                }

                run_status = "Error"
                run_stderr = ""
                run_stdout = ""
                exec_time = 0
                has_output_image = False
                output_image_filename = ""
                image_grading_score = 0
                image_comment = ""

                try:
                    result = core.run_single(lang, single_payload)
                except Exception as e:
                    image_comment = f"判题失败：{str(e)}"
                    result = None

                if result is not None:
                    run_status = str(result.get('status') or 'Error').strip() or 'Error'
                    files = (result.get('files') or {}) if isinstance(result.get('files'), dict) else {}
                    run_stderr = str(files.get('stderr') or '').strip()
                    run_stdout = str(files.get('stdout') or '').strip()
                    try:
                        exec_time = int(round(int(result.get('time', "0")) / 1_000_000))
                    except Exception:
                        exec_time = 0

                    has_output_image, output_image_filename = _extract_output_image_filename(files, preferred_prefix="output")
                    if run_status == "Accepted" and has_output_image and output_image_filename:
                        image_path = _resolve_saved_output_image_path(single_sid, output_image_filename)
                        if image_path:
                            try:
                                image_grading_score, image_comment = evaluate_program_output_image_with_ai(
                                    problem=problem,
                                    student_username=submission.get('username'),
                                    image_path=image_path,
                                )
                            except requests.RequestException as e:
                                image_comment = f"图片批改 API 调用失败：{str(e)}"
                            except Exception as e:
                                image_comment = f"图片批改失败：{str(e)}"
                        else:
                            image_comment = "程序运行后检测到图片标记，但未在评测目录中找到对应图片文件。"
                    else:
                        image_comment = _build_image_mode_comment_from_run_result(
                            run_status,
                            run_stderr,
                            required_output_image_filename,
                        )

                image_grading_score = 1 if int(image_grading_score or 0) == 1 else 0
                tp_status = _normalize_image_mode_test_point_status(run_status, image_grading_score)
                final_status = "Accepted" if tp_status == "Accepted" else "Unaccepted"
                test_point_statuses = [{
                    "status": tp_status,
                    "stderr": run_stderr,
                    "stdout": run_stdout[:200] + "..." if len(run_stdout) > 200 else run_stdout,
                    "comment": str(image_comment or "").strip(),
                    "time": exec_time,
                    "has_output_image": has_output_image,
                    "output_image_filename": output_image_filename,
                    "test_index": 1,
                }]
                set_submission_status_snapshot(
                    submission_id=submission_id,
                    username=submission.get('username'),
                    problem_id=submission.get('problem_id'),
                    problem_type=submission.get('problem_type'),
                    status='Running',
                    score=image_grading_score,
                    test_points=test_point_statuses,
                )
                _finalize_programming_submission(
                    submission=submission,
                    problem_id=problem_id,
                    test_point_statuses=test_point_statuses,
                    score=image_grading_score,
                    final_status=final_status,
                )
                return

            if lang in ['c', 'cpp', 'matlab', 'python', 'py']:
                quick_compile_payload = {
                    "code": final_code,
                    "submittedCode": raw_submission_code,
                    "checkerCode": test_code,
                    "input": "",
                    "forbidden": fbd_func,
                    "sid": f"eoj-quick-compile-{submission_id}",
                    "timeLimit": 1000000000,
                    "memoryLimit": 512 * 1024 * 1024,
                    "user_files": user_files,
                    "outputImageFilename": required_output_image_filename,
                }
    
                quick_result = {}
                if lang in ['c', 'cpp']:
                    try:
                        # 仅 c/cpp 需要预编译探测；解释型语言（matlab/python）无编译步骤，
                        # 跳过以免多跑一次容器，直接进入常驻容器批量评测。
                        quick_result = core.run_single(lang, quick_compile_payload)
                    except Exception:
                        quick_result = {}

                quick_status = quick_result.get('status')
                if quick_status in ('Compile Error', 'Forbidden'):
                    files = quick_result.get('files', {}) or {}
                    terminal_stderr = files.get('stderr') or quick_status
                    terminal_stdout = files.get('stdout') if quick_status == 'Forbidden' else ""
                    _finalize_programming_terminal_submission(
                        submission=submission,
                        problem_id=problem_id,
                        test_cases=test_cases,
                        final_status=quick_status,
                        stderr=terminal_stderr,
                        stdout=terminal_stdout or "",
                    )
                    return
    
                batch_payload = {
                    "code": final_code,
                    "submittedCode": raw_submission_code,
                    "checkerCode": test_code,
                    "test_cases": test_cases,
                    "forbidden": fbd_func,
                    "sid": f"eoj-batch-{submission_id}",
                    "timeLimit": time_limit_ns,
                    "memoryLimit": 512 * 1024 * 1024,
                    "user_files": user_files,
                    "outputImageFilename": required_output_image_filename,
                }
                stream_skip_fallback = False
                try:
                    stream_handled = False
                    for evt in core.batch_evaluate_stream(lang, batch_payload):
                        event_type = evt.get("event")
                        if event_type == "compile":
                            compile_status = evt.get("status")
                            if compile_status == "error":
                                compile_stderr = evt.get("stderr", "Compile Error")
                                _finalize_programming_terminal_submission(
                                    submission=submission,
                                    problem_id=problem_id,
                                    test_cases=test_cases,
                                    final_status="Compile Error",
                                    stderr=compile_stderr,
                                )
                                return
                            if compile_status == "forbidden":
                                forbidden_msg = evt.get("stderr", "Forbidden Function")
                                _finalize_programming_terminal_submission(
                                    submission=submission,
                                    problem_id=problem_id,
                                    test_cases=test_cases,
                                    final_status="Forbidden",
                                    stderr=forbidden_msg,
                                    stdout=forbidden_msg,
                                )
                                return
                        elif event_type == "test_result":
                            result = evt.get("result") or {}
                            tc_index = result.get("test_case_index", len(test_point_statuses))
                            try:
                                tc_index = int(tc_index)
                            except Exception:
                                tc_index = len(test_point_statuses)
                            idx = tc_index + 1
                            tc = test_cases[tc_index] if 0 <= tc_index < len(test_cases) else {}
    
                            status = result.get('status', 'Error')
                            actual_output = (result.get('files', {}) or {}).get('stdout', "")
                            actual_output = actual_output.strip() if isinstance(actual_output, str) else ""
    
                            if status == 'Accepted':
                                expected_output = tc.get("output", "").strip()
                                if compare_float_strings(actual_output, expected_output):
                                    status = 'Accepted'
                                else:
                                    status = 'Wrong Answer'
                                    all_accepted = False
                            else:
                                all_accepted = False
    
                            stderr = (result.get('files', {}) or {}).get('stderr', "")
                            stderr = stderr.strip() if isinstance(stderr, str) else ""
                            exec_time = int(round(int(result.get('time', "0")) / 1_000_000))
    
                            if len(actual_output) > 200:
                                actual_output = actual_output[:200] + "..."
    
                            output_image_filename = ""
                            has_output_image = False
                            if 'files' in result and isinstance(result['files'], dict):
                                has_output_image, output_image_filename = _extract_output_image_filename(
                                    result['files'],
                                    preferred_prefix=f"output_{idx - 1}",
                                )

                            test_point_statuses.append({
                                "status": status,
                                "stderr": stderr,
                                "stdout": actual_output,
                                "time": exec_time,
                                "has_output_image": has_output_image,
                                "output_image_filename": output_image_filename,
                                "test_index": idx,
                            })
                            set_submission_status_snapshot(
                                submission_id=submission_id,
                                username=submission.get('username'),
                                problem_id=submission.get('problem_id'),
                                problem_type=submission.get('problem_type'),
                                status='Running',
                                score=sum(1 for tp in test_point_statuses if tp.get("status") == "Accepted"),
                                test_points=test_point_statuses,
                            )
                        elif event_type == "done":
                            stream_handled = True
                            break
                        elif event_type == "error":
                            break
    
                    if stream_handled:
                        stream_skip_fallback = True
                        batch_result = {"compile_result": {"status": "success"}, "stream_mode": True}
                except Exception as e:
                    print(f"[Warning] In-process stream batch evaluation failed for submission {submission_id}: {str(e)}")
    
                if not stream_skip_fallback:
                    if test_point_statuses:
                        test_point_statuses = []
                        all_accepted = True
                        set_submission_status_snapshot(
                            submission_id=submission_id,
                            username=submission.get('username'),
                            problem_id=submission.get('problem_id'),
                            problem_type=submission.get('problem_type'),
                            status='Running',
                            score=0,
                            test_points=[],
                        )
                    try:
                        batch_result = core.batch_evaluate(lang, batch_payload)
                    except Exception as e:
                        print(f"[Warning] Batch evaluation failed for submission {submission_id}: {str(e)}")
                        batch_result = None
    
                    if batch_result and batch_result.get('compile_result', {}).get('status') == 'success':
                        test_results = batch_result.get('test_results', [])
    
                        for idx, (tc, result) in enumerate(zip(test_cases, test_results), start=1):
                            status = result.get('status', 'Error')
                            actual_output = (result.get('files', {}) or {}).get('stdout', "")
                            actual_output = actual_output.strip() if isinstance(actual_output, str) else ""
    
                            if status == 'Accepted':
                                expected_output = tc.get("output", "").strip()
                                if compare_float_strings(actual_output, expected_output):
                                    status = 'Accepted'
                                else:
                                    status = 'Wrong Answer'
                                    all_accepted = False
                            else:
                                all_accepted = False
    
                            stderr = (result.get('files', {}) or {}).get('stderr', "")
                            stderr = stderr.strip() if isinstance(stderr, str) else ""
                            exec_time = int(round(int(result.get('time', "0")) / 1_000_000))
    
                            if len(actual_output) > 200:
                                actual_output = actual_output[:200] + "..."
    
                            output_image_filename = ""
                            has_output_image = False
                            if 'files' in result and isinstance(result['files'], dict):
                                has_output_image, output_image_filename = _extract_output_image_filename(
                                    result['files'],
                                    preferred_prefix=f"output_{idx - 1}",
                                )

                            test_point_statuses.append({
                                "status": status,
                                "stderr": stderr,
                                "stdout": actual_output,
                                "time": exec_time,
                                "has_output_image": has_output_image,
                                "output_image_filename": output_image_filename,
                                "test_index": idx,
                            })
                            set_submission_status_snapshot(
                                submission_id=submission_id,
                                username=submission.get('username'),
                                problem_id=submission.get('problem_id'),
                                problem_type=submission.get('problem_type'),
                                status='Running',
                                score=sum(1 for tp in test_point_statuses if tp.get("status") == "Accepted"),
                                test_points=test_point_statuses,
                            )
    
                    elif batch_result and batch_result.get('compile_result', {}).get('status') == 'error':
                        compile_stderr = batch_result.get('compile_result', {}).get('stderr', 'Compile Error')
                        _finalize_programming_terminal_submission(
                            submission=submission,
                            problem_id=problem_id,
                            test_cases=test_cases,
                            final_status="Compile Error",
                            stderr=compile_stderr,
                        )
                        return
    
                    elif batch_result and batch_result.get('compile_result', {}).get('status') == 'forbidden':
                        forbidden_msg = batch_result.get('compile_result', {}).get('stderr', 'Forbidden Function')
                        _finalize_programming_terminal_submission(
                            submission=submission,
                            problem_id=problem_id,
                            test_cases=test_cases,
                            final_status="Forbidden",
                            stderr=forbidden_msg,
                            stdout=forbidden_msg,
                        )
                        return
                    else:
                        print(f"[Warning] Falling back to individual evaluation for submission {submission_id}")
                        batch_result = None

            if lang not in ['c', 'cpp', 'matlab', 'python', 'py'] or not batch_result or batch_result.get('compile_result', {}).get('status') != 'success':
                for idx, tc in enumerate(test_cases, start=1):
                    payload = {
                        "code": final_code,
                        "submittedCode": raw_submission_code,
                        "checkerCode": test_code,
                        "input": tc.get("input", ""),
                        "forbidden": fbd_func,
                        "sid": f"eoj-{submission_id}-{idx}",
                        "timeLimit": time_limit_ns,
                        "memoryLimit": 512 * 1024 * 1024,
                        "user_files": user_files,
                        "outputImageFilename": required_output_image_filename,
                    }
    
                    try:
                        result = core.run_single(lang, payload)
                    except Exception:
                        test_point_statuses.append({"status": "Error"})
                        all_accepted = False
                        set_submission_status_snapshot(
                            submission_id=submission_id,
                            username=submission.get('username'),
                            problem_id=submission.get('problem_id'),
                            problem_type=submission.get('problem_type'),
                            status='Running',
                            score=sum(1 for tp in test_point_statuses if tp.get("status") == "Accepted"),
                            test_points=test_point_statuses,
                        )
                        continue
    
                    status = result.get('status', 'Error')
                    actual_output = (result.get('files', {}) or {}).get('stdout', "")
                    actual_output = actual_output.strip() if isinstance(actual_output, str) else ""
    
                    if status == 'Accepted':
                        expected_output = tc.get("output", "").strip()
                        if compare_float_strings(actual_output, expected_output):
                            status = 'Accepted'
                        else:
                            status = 'Wrong Answer'
                            all_accepted = False
                    else:
                        all_accepted = False
    
                    stderr = (result.get('files', {}) or {}).get('stderr', "")
                    stderr = stderr.strip() if isinstance(stderr, str) else ""
                    lines = stderr.split('\n')
                    exec_time = int(round(int(result.get('time', "0")) / 1_000_000))
    
                    if lang == 'matlab':
                        if len(lines) < 3:
                            stderr = ""
                        else:
                            lines = lines[2:-1]
                            stderr = '\n'.join(lines)
    
                    if len(actual_output) > 200:
                        actual_output = actual_output[:200] + "..."
    
                    output_image_filename = ""
                    has_output_image = False
                    if 'files' in result and isinstance(result['files'], dict):
                        has_output_image, output_image_filename = _extract_output_image_filename(
                            result['files'],
                            preferred_prefix="output",
                        )

                    test_point_statuses.append({
                        "status": status,
                        "stderr": stderr,
                        "stdout": actual_output,
                        "time": exec_time,
                        "has_output_image": has_output_image,
                        "output_image_filename": output_image_filename,
                        "test_index": idx,
                    })
                    set_submission_status_snapshot(
                        submission_id=submission_id,
                        username=submission.get('username'),
                        problem_id=submission.get('problem_id'),
                        problem_type=submission.get('problem_type'),
                        status='Running',
                        score=sum(1 for tp in test_point_statuses if tp.get("status") == "Accepted"),
                        test_points=test_point_statuses,
                    )

            score = sum(1 for tp in test_point_statuses if tp["status"] == "Accepted")
            final_status = "Accepted" if all_accepted else "Unaccepted"
            _finalize_programming_submission(
                submission=submission,
                problem_id=problem_id,
                test_point_statuses=test_point_statuses,
                score=score,
                final_status=final_status,
            )
        except RepositorySnapshotError:
            # 快照缺失/摘要不一致/清单损坏均是该提交的永久完整性错误；重跑同一
            # 不可变快照不会自愈。若写 Error 终态时遇到 MySQL 瞬时错误，则让
            # Celery 的 autoretry_for 正常接管。
            _mark_repository_snapshot_terminal_error(submission)
        except SoftTimeLimitExceeded:
            # 软超时（先于硬 time_limit 触发）：标记 Error 并让 finally 正常释放锁，
            # 避免被硬超时 SIGKILL 导致锁泄露、提交长期卡在 Running。
            try:
                update_submission_status(submission_id, 'Error')
            except Exception:
                pass
        finally:
            # 清理本次提交的运行目录临时产物（保留输出图片），兜底磁盘增长。
            try:
                core.cleanup_run_artifacts_for_submission(submission_id)
            except Exception:
                pass
            _release_submission_lock(lock_client, lock_key, lock_token)

    return evaluate_submission
