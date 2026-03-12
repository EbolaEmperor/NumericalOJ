#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import math
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
                    if not result or not result['testdata']:
                        update_submission_status(submission_id, 'Error')
                        return
                    testdata_json = result['testdata']
            finally:
                conn.close()

            try:
                test_cases = json.loads(testdata_json)
            except json.JSONDecodeError:
                update_submission_status(submission_id, 'Error')
                return

            test_point_statuses = []
            all_accepted = True

            time_limit_ms = problem.get('time_limit_ms') or 2000
            time_limit_ns = int(time_limit_ms) * 1000000
            batch_result = None

            if lang in ['c', 'cpp']:
                quick_compile_payload = {
                    "code": final_code,
                    "input": "",
                    "forbidden": fbd_func,
                    "sid": f"eoj-quick-compile-{submission_id}",
                    "timeLimit": 1000000000,
                    "memoryLimit": 512 * 1024 * 1024,
                    "user_files": user_files,
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
    
                            has_output_image = False
                            if 'files' in result and isinstance(result['files'], dict):
                                if f'output_{idx - 1}.png' in result['files']:
                                    has_output_image = True
    
                            test_point_statuses.append({
                                "status": status,
                                "stderr": stderr,
                                "stdout": actual_output,
                                "time": exec_time,
                                "has_output_image": has_output_image,
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
    
                            has_output_image = False
                            if 'files' in result and isinstance(result['files'], dict):
                                if f'output_{idx - 1}.png' in result['files']:
                                    has_output_image = True
    
                            test_point_statuses.append({
                                "status": status,
                                "stderr": stderr,
                                "stdout": actual_output,
                                "time": exec_time,
                                "has_output_image": has_output_image,
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
    
                    has_output_image = False
                    if 'files' in result and isinstance(result['files'], dict):
                        if 'output.png' in result['files'] or any(key.endswith('output.png') for key in result['files'].keys()):
                            has_output_image = True
    
                    test_point_statuses.append({
                        "status": status,
                        "stderr": stderr,
                        "stdout": actual_output,
                        "time": exec_time,
                        "has_output_image": has_output_image,
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
            user = get_user_by_username(submission['username'])

            final_status = "Accepted" if all_accepted else "Unaccepted"
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

            update_submission_evaluation(submission_id, test_point_statuses, score, final_status)
        finally:
            _release_submission_lock(lock_client, lock_key, lock_token)

    return evaluate_submission
