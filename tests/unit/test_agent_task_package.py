#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import inspect

from backend.oj_modules.tasks import agent
from backend.oj_modules.tasks.agent.generate_testdata import (
    register_agent_generate_testdata_task,
)
from backend.oj_modules.tasks.agent.generic import register_agent_run_turn_task
from backend.oj_modules.tasks.agent.shared import (
    AGENT_GENERATE_TESTDATA_TASK_NAME,
    AGENT_RUN_TURN_TASK_NAME,
    AGENT_SOLVE_TASK_NAME,
)
from backend.oj_modules.tasks.agent.solve import register_agent_solve_problem_task


def test_agent_package_preserves_public_task_contract():
    assert AGENT_SOLVE_TASK_NAME == "oj.agent.solve_problem"
    assert AGENT_GENERATE_TESTDATA_TASK_NAME == "oj.agent.generate_testdata"
    assert AGENT_RUN_TURN_TASK_NAME == "oj.agent.run_turn"
    assert agent.register_agent_solve_problem_task is register_agent_solve_problem_task
    assert (
        agent.register_agent_generate_testdata_task
        is register_agent_generate_testdata_task
    )
    assert agent.register_agent_run_turn_task is register_agent_run_turn_task
    assert str(inspect.signature(register_agent_solve_problem_task)) == "(celery_app)"
    assert str(inspect.signature(register_agent_generate_testdata_task)) == (
        "(celery_app)"
    )
    assert str(inspect.signature(register_agent_run_turn_task)) == "(celery_app)"
