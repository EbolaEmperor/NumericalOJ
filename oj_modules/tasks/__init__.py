#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oj_modules.tasks.evaluate_tasks import register_evaluate_submission_task
from oj_modules.tasks.written_homework_tasks import register_written_homework_task
from oj_modules.tasks.agent_tasks import (
    get_agent_run_snapshot,
    init_agent_progress_cache,
    register_agent_generate_testdata_task,
    register_agent_solve_problem_task,
    subscribe_agent_run_events,
)
from oj_modules.tasks.repository_index_tasks import register_repository_index_build_task
from oj_modules.tasks.ai_detection_tasks import register_ai_detection_tasks
from oj_modules.tasks.ranking_evaluate_tasks import register_ranking_evaluate_task

__all__ = [
    "register_evaluate_submission_task",
    "register_written_homework_task",
    "register_agent_solve_problem_task",
    "register_agent_generate_testdata_task",
    "register_repository_index_build_task",
    "register_ai_detection_tasks",
    "register_ranking_evaluate_task",
    "init_agent_progress_cache",
    "get_agent_run_snapshot",
    "subscribe_agent_run_events",
]
