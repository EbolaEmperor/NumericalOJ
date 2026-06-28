#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Configuration helpers for Promptly prompt review."""

import json


def _as_text(value):
    return str(value or "").strip()


def _as_text_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (list, tuple)):
        items = []
        for item in value:
            text = _as_text(item)
            if text:
                items.append(text)
        return items
    return []


def _parse_json_object(text):
    raw = _as_text(text)
    if not raw:
        return None
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def parse_promptly_review_config(problem_or_text):
    """Parse Promptly review JSON stored in programming_grading_prompt.

    JSON form:
        {
          "brief": "题目简要描述",
          "prompt_requirements": "学生 prompt 需要满足的要求",
          "example_replies": ["提示回复 1", "提示回复 2"]
        }

    Plain text is treated as the brief description for backward compatibility.
    Older "context" JSON is also accepted as a brief.
    """

    if isinstance(problem_or_text, dict):
        raw = _as_text(problem_or_text.get("programming_grading_prompt"))
    else:
        raw = _as_text(problem_or_text)

    obj = _parse_json_object(raw)
    if not obj:
        return {
            "brief": raw,
            "prompt_requirements": "",
            "example_replies": [],
            "raw_is_json": False,
        }

    brief = _as_text(
        obj.get("brief")
        or obj.get("problem_brief")
        or obj.get("summary")
        or obj.get("context")
    )
    requirements = _as_text(
        obj.get("prompt_requirements")
        or obj.get("requirements")
        or obj.get("prompt_rules")
    )
    examples_raw = (
        obj.get("example_replies")
        or obj.get("examples")
        or obj.get("sample_replies")
        or []
    )
    examples = _as_text_list(examples_raw)

    return {
        "brief": brief,
        "prompt_requirements": requirements,
        "example_replies": examples,
        "raw_is_json": True,
    }
