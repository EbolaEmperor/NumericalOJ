#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oj_modules.tasks.evaluate_tasks import register_evaluate_submission_task
from oj_modules.tasks.written_homework_tasks import register_written_homework_task

__all__ = [
    "register_evaluate_submission_task",
    "register_written_homework_task",
]
