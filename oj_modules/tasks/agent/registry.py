#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oj_modules.tasks.agent.shared import (
    AGENT_GENERATE_TESTDATA_TASK_NAME,
    AGENT_SOLVE_TASK_NAME,
    get_agent_run_snapshot,
    init_agent_progress_cache,
    subscribe_agent_run_events,
)
from oj_modules.tasks.agent.control import build_agent_run_terminator
from oj_modules.tasks.agent.solve import register_agent_solve_problem_task
from oj_modules.tasks.agent.generate_testdata import register_agent_generate_testdata_task

__all__ = [
    "AGENT_SOLVE_TASK_NAME",
    "AGENT_GENERATE_TESTDATA_TASK_NAME",
    "register_agent_solve_problem_task",
    "register_agent_generate_testdata_task",
    "init_agent_progress_cache",
    "get_agent_run_snapshot",
    "subscribe_agent_run_events",
    "build_agent_run_terminator",
]
