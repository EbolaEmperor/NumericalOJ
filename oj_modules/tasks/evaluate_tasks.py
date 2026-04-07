#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import math
import os
import re
import uuid

import requests

try:
    import redis
except Exception:
    redis = None

from config import (
    EVALUATE_SUBMISSION_LOCK_TTL_SECONDS,
    REDIS_DB,
    REDIS_HOST,
    REDIS_PORT,
)
from oj_modules.ai_utils import evaluate_program_output_image_with_ai
from oj_modules.db_services import (
    get_db_connection,
    insert_user_problem_ac_record_if_absent,
    get_problem,
    get_submission_by_id,
    set_submission_status_snapshot,
    get_user_classes,
    get_user_by_username,
    upsert_user_problem_max_score_if_higher,
    update_submission_evaluation,
    update_submission_status,
)


EVALUATE_TASK_NAME = "oj.evaluate_submission"
_LOCK_TTL_SECONDS = max(60, int(EVALUATE_SUBMISSION_LOCK_TTL_SECONDS))
_lock_rds = None


def _normalize_programming_grading_mode(problem):
    try:
        mode = int((problem or {}).get('programming_grading_mode') or 1)
    except Exception:
        mode = 1
    return mode if mode in (1, 2) else 1


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
        if os.path.isfile(path):
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


def _finalize_programming_submission(submission, problem_id, test_point_statuses, score, final_status):
    user = get_user_by_username(submission['username'])
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


def _get_lock_redis_client():
    global _lock_rds
    if _lock_rds is not None:
        return _lock_rds
    if redis is None:
        return None

    try:
        _lock_rds = redis.StrictRedis(
            host=REDIS_HOST,
            port=int(REDIS_PORT),
            db=int(REDIS_DB),
            decode_responses=True,
        )
        _lock_rds.ping()
    except Exception:
        _lock_rds = None
    return _lock_rds


def _submission_lock_key(submission_id):
    return f"submission:{submission_id}:lock"


def _acquire_submission_lock(submission_id):
    client = _get_lock_redis_client()
    if client is None:
        return None, None, None

    key = _submission_lock_key(submission_id)
    token = uuid.uuid4().hex
    try:
        acquired = client.set(key, token, nx=True, ex=_LOCK_TTL_SECONDS)
    except Exception:
        return None, None, None

    if not acquired:
        return client, key, None
    return client, key, token


def _release_submission_lock(client, key, token):
    if client is None or not key or not token:
        return
    try:
        client.eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
            "return redis.call('del', KEYS[1]) else return 0 end",
            1,
            key,
            token,
        )
    except Exception:
        pass


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
            class_en = cls['class_en']
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

    @celery_app.task(name=EVALUATE_TASK_NAME, time_limit=300, soft_time_limit=240)
    def evaluate_submission(submission_id):
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
            code = submission['code']
            problem = get_problem(problem_id)
            programming_grading_mode = _normalize_programming_grading_mode(problem)
            required_output_image_filename = (
                str(problem.get('programming_output_filename') or 'output.png').strip()
                or 'output.png'
            )
            lang = (problem.get('lang') or 'matlab').strip().lower()
            test_code = problem.get('test_code') or ''

            user = get_user_by_username(submission['username'])
            user_files = {}

            if user and lang in ['c', 'cpp']:
                conn = get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        sql = """
                        SELECT filename, file_content
                        FROM user_code_repository
                        WHERE user_id = %s
                        """
                        cursor.execute(sql, (user['id'],))
                        files = cursor.fetchall()
                        for file_data in files:
                            user_files[file_data['filename']] = file_data['file_content']
                except Exception as e:
                    print(f"Warning: Failed to load user repository files: {e}")
                finally:
                    conn.close()

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
                judge_url = 'http://localhost:5050/run-hello'

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
                judge_url = 'http://localhost:5050/run-c'

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
                judge_url = 'http://localhost:5050/run-cpp'

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
                judge_url = 'http://localhost:5050/run-py'
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
                    response = requests.post(judge_url, json=single_payload, timeout=60)
                    response.raise_for_status()
                    result = response.json()
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
                            image_grading_score, image_comment = evaluate_program_output_image_with_ai(
                                problem=problem,
                                student_username=submission.get('username'),
                                image_path=image_path,
                            )
                        else:
                            image_comment = "程序运行后检测到图片标记，但未在评测目录中找到对应图片文件。"
                    else:
                        image_comment = _build_image_mode_comment_from_run_result(
                            run_status,
                            run_stderr,
                            required_output_image_filename,
                        )
                except requests.RequestException as e:
                    image_comment = f"判题服务调用失败：{str(e)}"
                except Exception as e:
                    image_comment = f"图片批改失败：{str(e)}"

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

            if lang in ['c', 'cpp']:
                quick_compile_payload = {
                    "code": final_code,
                    "input": "",
                    "forbidden": fbd_func,
                    "sid": f"eoj-quick-compile-{submission_id}",
                    "timeLimit": 1000000000,
                    "memoryLimit": 512 * 1024 * 1024,
                    "user_files": user_files,
                    "outputImageFilename": required_output_image_filename,
                }
    
                try:
                    quick_response = requests.post(
                        f'http://localhost:5050/run-{lang}',
                        json=quick_compile_payload,
                        timeout=15,
                    )
                    quick_result = quick_response.json()
    
                    if quick_result.get('status') == 'Compile Error':
                        compile_stderr = quick_result.get('files', {}).get('stderr', 'Compile Error')
                        all_accepted = False
    
                        for idx, _ in enumerate(test_cases, start=1):
                            test_point_statuses.append({
                                "status": "Compile Error",
                                "stderr": compile_stderr,
                                "stdout": "",
                                "time": 0,
                                "has_output_image": False,
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
    
                        update_submission_status(submission_id, 'Compile Error')
                        update_submission_evaluation(submission_id, test_point_statuses, 0, 'Compile Error')
                        return
    
                except requests.RequestException:
                    pass
    
                batch_judge_url = f'http://localhost:5050/batch-evaluate-{lang}'
                batch_payload = {
                    "code": final_code,
                    "test_cases": test_cases,
                    "forbidden": fbd_func,
                    "sid": f"eoj-batch-{submission_id}",
                    "timeLimit": time_limit_ns,
                    "memoryLimit": 512 * 1024 * 1024,
                    "user_files": user_files,
                    "outputImageFilename": required_output_image_filename,
                }
                stream_skip_fallback = False
                stream_judge_url = f'http://localhost:5050/batch-evaluate-stream-{lang}'
                try:
                    stream_response = requests.post(
                        stream_judge_url,
                        json=batch_payload,
                        stream=True,
                        timeout=(10, 240),
                    )
                    stream_response.raise_for_status()
    
                    stream_handled = False
                    for raw_line in stream_response.iter_lines(decode_unicode=True):
                        if not raw_line:
                            continue
                        try:
                            evt = json.loads(raw_line)
                        except Exception:
                            continue
    
                        event_type = evt.get("event")
                        if event_type == "compile":
                            compile_status = evt.get("status")
                            if compile_status == "error":
                                compile_stderr = evt.get("stderr", "Compile Error")
                                all_accepted = False
                                for idx, _ in enumerate(test_cases, start=1):
                                    test_point_statuses.append({
                                        "status": "Compile Error",
                                        "stderr": compile_stderr,
                                        "stdout": "",
                                        "time": 0,
                                        "has_output_image": False,
                                        "test_index": idx,
                                    })
                                    set_submission_status_snapshot(
                                        submission_id=submission_id,
                                        username=submission.get('username'),
                                        problem_id=submission.get('problem_id'),
                                        problem_type=submission.get('problem_type'),
                                        status='Running',
                                        score=0,
                                        test_points=test_point_statuses,
                                    )
                                stream_handled = True
                                break
                            if compile_status == "forbidden":
                                forbidden_msg = evt.get("stderr", "Forbidden Function")
                                all_accepted = False
                                for idx, _ in enumerate(test_cases, start=1):
                                    test_point_statuses.append({
                                        "status": "Forbidden",
                                        "stderr": forbidden_msg,
                                        "stdout": forbidden_msg,
                                        "time": 0,
                                        "has_output_image": False,
                                        "test_index": idx,
                                    })
                                    set_submission_status_snapshot(
                                        submission_id=submission_id,
                                        username=submission.get('username'),
                                        problem_id=submission.get('problem_id'),
                                        problem_type=submission.get('problem_type'),
                                        status='Running',
                                        score=0,
                                        test_points=test_point_statuses,
                                    )
                                stream_handled = True
                                break
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
                except requests.RequestException as e:
                    print(f"[Warning] Stream batch evaluation failed for submission {submission_id}: {str(e)}")
    
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
                        response = requests.post(batch_judge_url, json=batch_payload, timeout=120)
                        response.raise_for_status()
                        batch_result = response.json()
                    except requests.RequestException as e:
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
                        all_accepted = False
    
                        for idx, _ in enumerate(test_cases, start=1):
                            test_point_statuses.append({
                                "status": "Compile Error",
                                "stderr": compile_stderr,
                                "stdout": "",
                                "time": 0,
                                "has_output_image": False,
                                "test_index": idx,
                            })
                            set_submission_status_snapshot(
                                submission_id=submission_id,
                                username=submission.get('username'),
                                problem_id=submission.get('problem_id'),
                                problem_type=submission.get('problem_type'),
                                status='Running',
                                score=0,
                                test_points=test_point_statuses,
                            )
    
                    elif batch_result and batch_result.get('compile_result', {}).get('status') == 'forbidden':
                        forbidden_msg = batch_result.get('compile_result', {}).get('stderr', 'Forbidden Function')
                        all_accepted = False
    
                        for idx, _ in enumerate(test_cases, start=1):
                            test_point_statuses.append({
                                "status": "Forbidden",
                                "stderr": forbidden_msg,
                                "stdout": forbidden_msg,
                                "time": 0,
                                "has_output_image": False,
                                "test_index": idx,
                            })
                            set_submission_status_snapshot(
                                submission_id=submission_id,
                                username=submission.get('username'),
                                problem_id=submission.get('problem_id'),
                                problem_type=submission.get('problem_type'),
                                status='Running',
                                score=0,
                                test_points=test_point_statuses,
                            )
                    else:
                        print(f"[Warning] Falling back to individual evaluation for submission {submission_id}")
                        batch_result = None

            if lang not in ['c', 'cpp'] or not batch_result or batch_result.get('compile_result', {}).get('status') != 'success':
                for idx, tc in enumerate(test_cases, start=1):
                    payload = {
                        "code": final_code,
                        "input": tc.get("input", ""),
                        "forbidden": fbd_func,
                        "sid": f"eoj-{submission_id}-{idx}",
                        "timeLimit": time_limit_ns,
                        "memoryLimit": 512 * 1024 * 1024,
                        "user_files": user_files,
                        "outputImageFilename": required_output_image_filename,
                    }
    
                    try:
                        response = requests.post(judge_url, json=payload, timeout=15)
                        response.raise_for_status()
                        result = response.json()
                    except requests.RequestException:
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
        finally:
            _release_submission_lock(lock_client, lock_key, lock_token)

    return evaluate_submission
