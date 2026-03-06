#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import math
import re

import requests

from oj_modules.db_services import (
    get_db_connection,
    insert_user_problem_ac_record_if_absent,
    get_problem,
    get_submission_by_id,
    get_user_classes,
    get_user_by_username,
    upsert_user_problem_max_score_if_higher,
    update_submission_evaluation,
    update_submission_status,
)


EVALUATE_TASK_NAME = "oj.evaluate_submission"


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

        update_submission_status(submission_id, 'Running')

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

    return evaluate_submission
