#!/usr/bin/env python3
"""NumericalOJ regular-user CLI over authenticated NumericalOJ HTTP APIs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from numoj_user_cli import ai, auth, common, forum, me, problem, ranking, repository, submission  # noqa: E402


requests = common.requests
CliError = common.CliError
client_from_args = common.client_from_args

login = auth.login
logout = auth.logout
status = auth.status
auth_send_password_code = auth.auth_send_password_code
auth_change_password = auth.auth_change_password

me_classes = me.me_classes
me_join_class = me.me_join_class
me_leave_class = me.me_leave_class
me_set_primary_class = me.me_set_primary_class
necessary_classes_payload = me.necessary_classes_payload
me_submissions = me.me_submissions
me_grades = me.me_grades

submission_list = submission.submission_list
necessary_submission_list_payload = submission.necessary_submission_list_payload
necessary_submission_problem_payload = submission.necessary_submission_problem_payload
necessary_submission_detail_payload = submission.necessary_submission_detail_payload
necessary_last_code_payload = submission.necessary_last_code_payload
submission_problem_list = submission.submission_problem_list
submission_status_cmd = submission.submission_status_cmd
submission_stream = submission.submission_stream
submission_detail = submission.submission_detail
submission_last_code = submission.submission_last_code
submission_output_image = submission.submission_output_image

wait_promptly_review_result = problem.wait_promptly_review_result
necessary_problem_list_payload = problem.necessary_problem_list_payload
necessary_problem_detail_payload = problem.necessary_problem_detail_payload
problem_list = problem.problem_list
problem_detail = problem.problem_detail
problem_submit_page = problem.problem_submit_page
problem_submit = problem.problem_submit

forum_list = forum.forum_list
necessary_forum_list_payload = forum.necessary_forum_list_payload
necessary_forum_thread_payload = forum.necessary_forum_thread_payload
necessary_forum_new_context_payload = forum.necessary_forum_new_context_payload
forum_thread = forum.forum_thread
forum_new_page = forum.forum_new_page
forum_new = forum.forum_new
forum_reply = forum.forum_reply
forum_reply_thread = forum.forum_reply_thread

repository_page = repository.repository_page
necessary_repository_context_payload = repository.necessary_repository_context_payload
necessary_repository_files_payload = repository.necessary_repository_files_payload
necessary_repository_file_payload = repository.necessary_repository_file_payload
necessary_repository_index_start_payload = repository.necessary_repository_index_start_payload
necessary_repository_index_status_payload = repository.necessary_repository_index_status_payload
necessary_repository_active_status_payload = repository.necessary_repository_active_status_payload
necessary_repository_search_payload = repository.necessary_repository_search_payload
necessary_repository_classes_payload = repository.necessary_repository_classes_payload
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
necessary_ai_code_marks_payload = ai.necessary_ai_code_marks_payload

ranking_list = ranking.ranking_list
necessary_ranking_list_payload = ranking.necessary_ranking_list_payload
necessary_ranking_detail_payload = ranking.necessary_ranking_detail_payload
necessary_ranking_submissions_payload = ranking.necessary_ranking_submissions_payload
necessary_ranking_leaderboard_payload = ranking.necessary_ranking_leaderboard_payload
necessary_ranking_matches_payload = ranking.necessary_ranking_matches_payload
necessary_ranking_match_detail_payload = ranking.necessary_ranking_match_detail_payload
ranking_detail = ranking.ranking_detail
ranking_matches = ranking.ranking_matches
ranking_match_detail = ranking.ranking_match_detail
ranking_submit = ranking.ranking_submit
ranking_git = ranking.ranking_git
ranking_my_submissions = ranking.ranking_my_submissions
ranking_leaderboard = ranking.ranking_leaderboard
ranking_download_submission = ranking.ranking_download_submission
ranking_judge_stream = ranking.ranking_judge_stream
ranking_submit_appeal = ranking.ranking_submit_appeal
ranking_appeal_status = ranking.ranking_appeal_status


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="numoj-user",
        description="NumericalOJ regular-user CLI over existing HTTP routes.",
        formatter_class=common.HELP_FORMATTER,
    )
    common.add_common_http_args(parser)
    subparsers = parser.add_subparsers(dest="group", required=True)

    auth.register_init(subparsers)
    auth.register(subparsers)
    me.register(subparsers)
    problem.register(subparsers)
    submission.register(subparsers)
    forum.register(subparsers)
    repository.register(subparsers)
    ai.register(subparsers)
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
    except common.CliError as exc:
        common.eprint(f"error: {exc}")
        return 2
    except common.requests.RequestException as exc:
        common.eprint(f"request error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
