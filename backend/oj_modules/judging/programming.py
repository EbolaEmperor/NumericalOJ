#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编程题普通测试点评分共用语义。"""

from __future__ import annotations

import math
import re


_USER_CODE_START_MARKER = "here_is_user_code_fuck_fuck_fuck_hahaha"
_USER_CODE_END_MARKER = "user_code_end_fuck_hahaha_fuck"


def compare_float_strings(str1, str2, tolerance=1e-5):
    """按普通编程题判题契约比较两段文本中的浮点数。"""

    split_pattern = r"[\s,]+"

    try:
        list1 = [float(x) for x in re.split(split_pattern, str(str1).strip()) if x]
        list2 = [float(x) for x in re.split(split_pattern, str(str2).strip()) if x]
    except ValueError:
        return str1 == str2

    if len(list1) != len(list2):
        return False

    for a, b in zip(list1, list2):
        if math.isnan(a) or math.isnan(b):
            return False
        if a == 0 and b == 0:
            continue
        max_val = max(abs(a), abs(b))
        abs_error = abs(a - b)
        relative_error = abs_error / max_val
        if relative_error > tolerance and abs_error > tolerance:
            return False
    return True


def build_programming_source(language, submitted_code, test_code=""):
    """将用户源码按普通判题规则注入题目 ``test_code``。

    包裹标记供禁用函数检查定位用户源码。提交内容中的同名标记会先被移除，
    避免伪造边界提前结束扫描。
    """

    lang = str(language or "").strip().lower()
    if lang == "octave":
        lang = "matlab"
    elif lang == "c++":
        lang = "cpp"
    elif lang == "python3":
        lang = "python"

    code = str(submitted_code or "")
    for marker in (_USER_CODE_START_MARKER, _USER_CODE_END_MARKER):
        code = code.replace(marker, "")

    if lang == "matlab":
        wrapped = (
            f"%{_USER_CODE_START_MARKER}\n"
            f"{code}\n"
            f"%{_USER_CODE_END_MARKER}\n"
        )
    elif lang in {"c", "cpp"}:
        wrapped = (
            f"/*{_USER_CODE_START_MARKER}*/\n"
            f"{code}\n"
            f"/*{_USER_CODE_END_MARKER}*/\n"
        )
    elif lang in {"python", "py"}:
        wrapped = (
            f"#{_USER_CODE_START_MARKER}\n"
            f"{code}\n"
            f"#{_USER_CODE_END_MARKER}\n"
        )
    else:
        raise ValueError(f"不支持的编程语言：{language}")

    checker = str(test_code or "")
    if checker and "%%user_code_here" in checker:
        return checker.replace("%%user_code_here", wrapped)
    return wrapped


__all__ = ["build_programming_source", "compare_float_strings"]
