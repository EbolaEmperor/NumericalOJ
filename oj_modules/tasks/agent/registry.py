#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oj_modules.tasks.agent.shared import (
    AGENT_GENERATE_TESTDATA_TASK_NAME,
    AGENT_RUN_TURN_TASK_NAME,
    AGENT_SOLVE_TASK_NAME,
    get_agent_run_snapshot,
    init_agent_queue_dispatcher,
    init_agent_progress_cache,
    subscribe_agent_run_events,
)
from oj_modules.tasks.agent.control import build_agent_run_terminator
from oj_modules.tasks.agent.solve import register_agent_solve_problem_task
from oj_modules.tasks.agent.generate_testdata import register_agent_generate_testdata_task
from oj_modules.tasks.agent.generic import register_agent_run_turn_task
from oj_modules.tasks.agent.queue import (
    AGENT_QUEUE_DISPATCH_TASK_NAME,
    AGENT_QUEUE_RECOVERY_TASK_NAME,
    register_agent_queue_tasks,
)
from oj_modules.tasks.agent.harness_runtime import read_agent_steer_capability

__all__ = [
    "AGENT_SOLVE_TASK_NAME",
    "AGENT_GENERATE_TESTDATA_TASK_NAME",
    "AGENT_RUN_TURN_TASK_NAME",
    "AGENT_QUEUE_DISPATCH_TASK_NAME",
    "AGENT_QUEUE_RECOVERY_TASK_NAME",
    "register_agent_solve_problem_task",
    "register_agent_generate_testdata_task",
    "register_agent_run_turn_task",
    "register_agent_queue_tasks",
    "init_agent_progress_cache",
    "init_agent_queue_dispatcher",
    "get_agent_run_snapshot",
    "subscribe_agent_run_events",
    "build_agent_run_terminator",
    "read_agent_steer_capability",
]
