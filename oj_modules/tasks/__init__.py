#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oj_modules.tasks.evaluate_tasks import register_evaluate_submission_task
from oj_modules.tasks.written_homework_tasks import register_written_homework_task
from oj_modules.tasks.promptly_tasks import register_promptly_generate_submission_task
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
from oj_modules.tasks.ranking_elo_tasks import (
    register_ranking_elo_match_task,
    register_ranking_elo_initial_burst_task,
    register_ranking_elo_matchmaker_tick_task,
    seed_elo_matchmaker_tick,
)
from oj_modules.tasks.ranking_agent_judge_tasks import (
    register_ranking_agent_judge_task,
    init_judge_progress_cache,
    subscribe_judge_run_events,
    get_judge_progress_snapshot,
)
from oj_modules.tasks.ranking_batch_pull_tasks import (
    register_ranking_batch_tasks,
    init_batch_progress_cache,
    get_probe_job,
)
from oj_modules.tasks.ranking_bulk_rejudge_tasks import (
    register_ranking_bulk_rejudge_task,
    init_bulk_rejudge_progress_cache,
    get_bulk_rejudge_job,
    save_bulk_rejudge_job,
)

__all__ = [
    "register_evaluate_submission_task",
    "register_written_homework_task",
    "register_promptly_generate_submission_task",
    "register_agent_solve_problem_task",
    "register_agent_generate_testdata_task",
    "register_repository_index_build_task",
    "register_ai_detection_tasks",
    "register_ranking_evaluate_task",
    "register_ranking_elo_match_task",
    "register_ranking_elo_initial_burst_task",
    "register_ranking_elo_matchmaker_tick_task",
    "seed_elo_matchmaker_tick",
    "register_ranking_agent_judge_task",
    "init_judge_progress_cache",
    "subscribe_judge_run_events",
    "get_judge_progress_snapshot",
    "register_ranking_batch_tasks",
    "init_batch_progress_cache",
    "get_probe_job",
    "register_ranking_bulk_rejudge_task",
    "init_bulk_rejudge_progress_cache",
    "get_bulk_rejudge_job",
    "save_bulk_rejudge_job",
    "init_agent_progress_cache",
    "get_agent_run_snapshot",
    "subscribe_agent_run_events",
]
