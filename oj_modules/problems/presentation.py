"""不依赖 HTTP 上下文的题目展示 helper。"""

import re


def strip_problem_title_tags(title):
    """去掉题目标题中的短分组标签，如 ``「NA-1」``。"""
    if title is None:
        return title
    original = str(title).strip()
    text = re.sub(r"\s*「[^」]{1,32}」\s*", " ", original)
    text = re.sub(r"\s+", " ", text).strip()
    return text if text else original


__all__ = ["strip_problem_title_tags"]
