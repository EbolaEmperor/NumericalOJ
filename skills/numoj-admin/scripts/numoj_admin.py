#!/usr/bin/env python3
"""NumericalOJ administrator CLI over authenticated NumericalOJ HTTP APIs."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from numoj_admin_cli import (  # noqa: E402
    ai,
    ai_detection,
    auth,
    common,
    forum,
    grading,
    homework,
    me,
    problem,
    ranking,
    repository,
    site,
    site_config,
    submission,
    user,
)


requests = common.requests
CliError = common.CliError
client_from_args = common.client_from_args

login = auth.login
init_cli = auth.init_cli
logout = auth.logout
status = auth.status
auth_send_password_code = auth.auth_send_password_code
auth_change_password = auth.auth_change_password
site_home = site.site_home

me_classes = me.me_classes
me_join_class = me.me_join_class
me_leave_class = me.me_leave_class
me_grades = me.me_grades

submission_list = submission.submission_list
submission_problem_list = submission.submission_problem_list
submission_status_cmd = submission.submission_status_cmd
submission_stream = submission.submission_stream
submission_detail_cmd = submission.submission_detail_cmd
submission_last_code = submission.submission_last_code
submission_output_image = submission.submission_output_image
submission_download_file = submission.submission_download_file

wait_promptly_review_result = problem.wait_promptly_review_result
build_promptly_grading_prompt_arg = problem.build_promptly_grading_prompt_arg
problem_list = problem.problem_list
problem_detail = problem.problem_detail
problem_submit_page = problem.problem_submit_page
problem_submit = problem.problem_submit
problem_create_form = problem.problem_create_form
problem_create = problem.problem_create
problem_edit_form = problem.problem_edit_form
problem_edit = problem.problem_edit
problem_delete = problem.problem_delete
problem_upload_testdata = problem.problem_upload_testdata
problem_rejudge = problem.problem_rejudge
problem_rejudge_status = problem.problem_rejudge_status
problem_rejudge_time_range = problem.problem_rejudge_time_range
problem_rejudge_time_range_status = problem.problem_rejudge_time_range_status
problem_agent_run_status = problem.problem_agent_run_status
problem_agent_run = problem.problem_agent_run
problem_agent_run_stream = problem.problem_agent_run_stream
problem_agent_tasks = problem.problem_agent_tasks
problem_agent_solve = problem.problem_agent_solve
problem_agent_generate_data = problem.problem_agent_generate_data
problem_scores = problem.problem_scores

homework_add = homework.homework_add
homework_list = homework.homework_list
homework_update_ddl = homework.homework_update_ddl
homework_delete = homework.homework_delete
homework_export_scores = homework.homework_export_scores
homework_export_codes = homework.homework_export_codes
homework_export_progress = homework.homework_export_progress
homework_download_export = homework.homework_download_export
homework_plagiarism_start = homework.homework_plagiarism_start
homework_plagiarism_progress = homework.homework_plagiarism_progress
homework_plagiarism_records = homework.homework_plagiarism_records
homework_plagiarism_download = homework.homework_plagiarism_download
homework_plagiarism_delete = homework.homework_plagiarism_delete
homework_upload_exam = homework.homework_upload_exam
class_adjust = homework.class_adjust

user_add_class_type = user.user_add_class_type
user_list = user.user_list
user_grant_admin = user.user_grant_admin
user_rename = user.user_rename
user_add_to_class = user.user_add_to_class
user_remove_from_class = user.user_remove_from_class
user_grades = user.user_grades
user_update_grade = user.user_update_grade

grading_submit = grading.grading_submit
grading_next_pending = grading.grading_next_pending
grading_invalidate = grading.grading_invalidate

forum_list = forum.forum_list
forum_thread = forum.forum_thread
forum_new_page = forum.forum_new_page
forum_new = forum.forum_new
forum_reply = forum.forum_reply
forum_reply_thread = forum.forum_reply_thread

repository_page = repository.repository_page
repository_files = repository.repository_files
repository_get_file = repository.repository_get_file
repository_save_file = repository.repository_save_file
repository_delete_file = repository.repository_delete_file
repository_upload = repository.repository_upload
repository_build_index = repository.repository_build_index
repository_rebuild_file = repository.repository_rebuild_file
repository_index_status = repository.repository_index_status
repository_active_status = repository.repository_active_status
repository_search = repository.repository_search
repository_classes = repository.repository_classes

ai_code_marks = ai.ai_code_marks

ai_filter_payload = ai_detection.ai_filter_payload
ai_preview = ai_detection.ai_preview
ai_run_filtered = ai_detection.ai_run_filtered
ai_run_problem = ai_detection.ai_run_problem
ai_run_single = ai_detection.ai_run_single
ai_run_user = ai_detection.ai_run_user
ai_api_get = ai_detection.ai_api_get
ai_detection_page = ai_detection.ai_detection_page
ai_detection_problem_page = ai_detection.ai_detection_problem_page
ai_detection_student_page = ai_detection.ai_detection_student_page
ai_task_post = ai_detection.ai_task_post

ranking_list = ranking.ranking_list
ranking_detail = ranking.ranking_detail
ranking_create = ranking.ranking_create
ranking_copy = ranking.ranking_copy
ranking_edit = ranking.ranking_edit
ranking_delete = ranking.ranking_delete
ranking_upload_attachment = ranking.ranking_upload_attachment
ranking_delete_attachment = ranking.ranking_delete_attachment
ranking_download_attachment = ranking.ranking_download_attachment
ranking_upload_reference = ranking.ranking_upload_reference
ranking_upload_script = ranking.ranking_upload_script
ranking_clear_script = ranking.ranking_clear_script
ranking_reset_limit = ranking.ranking_reset_limit
ranking_rules = ranking.ranking_rules
ranking_endpoints = ranking.ranking_endpoints
ranking_save_quality_gate = ranking.ranking_save_quality_gate
ranking_save_quality_gate_endpoints = ranking.ranking_save_quality_gate_endpoints
ranking_save_quality_gate_endpoint = ranking.ranking_save_quality_gate_endpoint
ranking_batch_probe = ranking.ranking_batch_probe
ranking_batch_status = ranking.ranking_batch_status
ranking_batch_create = ranking.ranking_batch_create
ranking_bulk_filter = ranking.ranking_bulk_filter
ranking_bulk_start = ranking.ranking_bulk_start
ranking_bulk_status = ranking.ranking_bulk_status
ranking_matches = ranking.ranking_matches
ranking_match_detail = ranking.ranking_match_detail
ranking_rejudge_agent = ranking.ranking_rejudge_agent
ranking_submit_appeal = ranking.ranking_submit_appeal
ranking_appeal_status = ranking.ranking_appeal_status
ranking_appeals = ranking.ranking_appeals
ranking_appeal_review = ranking.ranking_appeal_review
ranking_appeal_handle = ranking.ranking_appeal_handle
ranking_elo_action = ranking.ranking_elo_action
ranking_elo_delete_match = ranking.ranking_elo_delete_match
ranking_elo_rebuild = ranking.ranking_elo_rebuild
ranking_delete_submission = ranking.ranking_delete_submission
ranking_download_submission = ranking.ranking_download_submission
ranking_judge_stream = ranking.ranking_judge_stream
ranking_my_submissions = ranking.ranking_my_submissions
ranking_all_submissions = ranking.ranking_all_submissions
ranking_leaderboard = ranking.ranking_leaderboard
ranking_submit_zip = ranking.ranking_submit_zip
ranking_git_submit = ranking.ranking_git_submit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="numoj-admin",
        description="NumericalOJ administrator CLI over authenticated HTTP APIs.",
        formatter_class=common.HELP_FORMATTER,
    )
    common.add_common_http_args(parser)
    subparsers = parser.add_subparsers(dest="group", required=True)

    auth.register_init(subparsers)
    site.register(subparsers)
    site_config.register(subparsers)
    auth.register(subparsers)
    me.register(subparsers)
    submission.register(subparsers)
    problem.register(subparsers)
    homework.register(subparsers)
    user.register(subparsers)
    grading.register(subparsers)
    forum.register(subparsers)
    repository.register(subparsers)
    ai.register(subparsers)
    ai_detection.register(subparsers)
    ranking.register(subparsers)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except KeyboardInterrupt:
        common.eprint("Interrupted")
        return 130
    except common.CliHttpError as exc:
        common.output_json(exc.payload)
        return 2
    except common.CliError as exc:
        common.output_json({"success": False, "message": str(exc)})
        return 2
    except common.requests.RequestException as exc:
        common.output_json({"success": False, "message": f"Request failed: {exc}"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
