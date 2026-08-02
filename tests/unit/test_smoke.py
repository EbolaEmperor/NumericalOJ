# -*- coding: utf-8 -*-
from oj_modules.judging import core as judger_core


def test_check_forbidden_blocks_listed_call():
    code = "x = sin(1)\n"
    assert judger_core.check_forbidden(code, "sin") is not None


def test_check_forbidden_allows_when_absent():
    code = "x = 1 + 2\n"
    assert judger_core.check_forbidden(code, "sin") is None
