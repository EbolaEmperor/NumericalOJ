#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oj_modules.tasks.evaluate_tasks import register_evaluate_submission_task
from oj_modules.tasks.written_homework_tasks import register_written_homework_task
from oj_modules.tasks.homework_admin_tasks import (
    HomeworkTaskOperations,
    build_homework_task_operations,
    register_homework_admin_tasks,
)
from oj_modules.tasks.rejudge_tasks import register_rejudge_task
from oj_modules.tasks.promptly_tasks import register_promptly_generate_submission_task
from oj_modules.tasks.agent.registry import (
    apply_agent_concurrency_limit,
    build_agent_run_terminator,
    get_agent_run_snapshot,
    init_agent_queue_dispatcher,
    init_agent_progress_cache,
    install_agent_concurrency_control,
    register_agent_generate_testdata_task,
    register_agent_run_turn_task,
    register_agent_queue_tasks,
    register_agent_solve_problem_task,
    read_agent_steer_capability,
    subscribe_agent_run_events,
)
from oj_modules.tasks.repository_index_tasks import register_repository_index_build_task
from oj_modules.tasks.ai_detection_tasks import register_ai_detection_tasks
from oj_modules.tasks.class_activity_tasks import (
    register_class_activity_refresh_task,
    seed_class_activity_refresh,
)
from oj_modules.tasks.ranking.evaluate import register_ranking_evaluate_task
from oj_modules.tasks.ranking.elo import (
    register_ranking_elo_match_task,
    register_ranking_elo_initial_burst_task,
    register_ranking_elo_matchmaker_tick_task,
    seed_elo_matchmaker_tick,
)
from oj_modules.tasks.ranking.agent_judge import (
    register_ranking_agent_judge_task,
    register_ranking_agent_judge_paused_probe_task,
    seed_agent_judge_paused_probe,
    init_judge_progress_cache,
    subscribe_judge_run_events,
    get_judge_progress_snapshot,
    build_current_judge_snapshot,
)
from oj_modules.tasks.ranking.reverse_judge import (
    register_ranking_reverse_judge_task,
    init_reverse_judge_progress_cache,
    subscribe_reverse_judge_events,
    get_reverse_judge_progress_snapshot,
)
from oj_modules.tasks.ranking.batch_pull import (
    register_ranking_batch_tasks,
    init_batch_progress_cache,
    get_probe_job,
)
from oj_modules.tasks.ranking.bulk_rejudge import (
    register_ranking_bulk_rejudge_task,
    init_bulk_rejudge_progress_cache,
    get_bulk_rejudge_job,
    save_bulk_rejudge_job,
)

__all__ = [
    "register_evaluate_submission_task",
    "register_written_homework_task",
    "HomeworkTaskOperations",
    "build_homework_task_operations",
    "register_homework_admin_tasks",
    "register_rejudge_task",
    "register_promptly_generate_submission_task",
    "apply_agent_concurrency_limit",
    "register_agent_solve_problem_task",
    "register_agent_generate_testdata_task",
    "register_agent_run_turn_task",
    "register_agent_queue_tasks",
    "register_repository_index_build_task",
    "register_ai_detection_tasks",
    "register_class_activity_refresh_task",
    "seed_class_activity_refresh",
    "register_ranking_evaluate_task",
    "register_ranking_elo_match_task",
    "register_ranking_elo_initial_burst_task",
    "register_ranking_elo_matchmaker_tick_task",
    "seed_elo_matchmaker_tick",
    "register_ranking_agent_judge_task",
    "register_ranking_agent_judge_paused_probe_task",
    "seed_agent_judge_paused_probe",
    "init_judge_progress_cache",
    "subscribe_judge_run_events",
    "get_judge_progress_snapshot",
    "build_current_judge_snapshot",
    "register_ranking_reverse_judge_task",
    "init_reverse_judge_progress_cache",
    "subscribe_reverse_judge_events",
    "get_reverse_judge_progress_snapshot",
    "register_ranking_batch_tasks",
    "init_batch_progress_cache",
    "get_probe_job",
    "register_ranking_bulk_rejudge_task",
    "init_bulk_rejudge_progress_cache",
    "get_bulk_rejudge_job",
    "save_bulk_rejudge_job",
    "init_agent_progress_cache",
    "init_agent_queue_dispatcher",
    "install_agent_concurrency_control",
    "get_agent_run_snapshot",
    "subscribe_agent_run_events",
    "build_agent_run_terminator",
    "read_agent_steer_capability",
]
