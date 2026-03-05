#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os

from oj_modules.db_services import (
    get_db_connection,
    get_submission_by_id,
    get_user_by_username,
    update_submission_status,
)


def get_file_path_for_submission(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT username, problem_id, test_points FROM submissions WHERE id=%s"
            cursor.execute(sql, (submission_id,))
            submission = cursor.fetchone()
            if not submission:
                return None
            if submission['test_points']:
                submission['test_points'] = [
                    json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                ]
            file_path = os.path.join('uploads', f"{submission_id}", submission['test_points'][0])
            return file_path
    finally:
        conn.close()


def update_submission_score_and_comment(submission_id, score, comment):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """UPDATE submissions
                     SET score = %s, code = %s
                     WHERE id = %s"""
            cursor.execute(sql, (score, comment, submission_id))
        conn.commit()

        submission = get_submission_by_id(submission_id)
        problem_id = submission["problem_id"]
        user = get_user_by_username(submission["username"])

        with conn.cursor() as cursor:
            sql = f'UPDATE max_score SET P{problem_id}={score} WHERE userid={user["id"]} AND (P{problem_id} IS NULL OR P{problem_id} < {score})'
            cursor.execute(sql)
        conn.commit()

        if score == 5:
            with conn.cursor() as cursor:
                sql = f'UPDATE ac_record SET ACP{problem_id}=1 WHERE userid={user["id"]}'
                cursor.execute(sql)
            conn.commit()
    finally:
        conn.close()


def update_submission_comment(submission_id, comment):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE submissions SET code = %s WHERE id = %s"
            cursor.execute(sql, (comment, submission_id))
        conn.commit()
    finally:
        conn.close()


def invalidate_previous_pending_submissions(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT id, username
                FROM submissions
                WHERE problem_id = %s AND status = 'Pending'
                ORDER BY created_at DESC
            """
            cursor.execute(sql, (problem_id,))
            pending_submissions = cursor.fetchall()

            user_submissions = {}
            for submission in pending_submissions:
                user_submissions.setdefault(submission['username'], []).append(submission['id'])

            for _, submissions in user_submissions.items():
                if len(submissions) > 1:
                    for submission_id in submissions[1:]:
                        update_submission_status(submission_id, 'Unaccepted')
            conn.commit()
    finally:
        conn.close()
