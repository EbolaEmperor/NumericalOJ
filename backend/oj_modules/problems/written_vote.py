#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""书面题多模型一致性投票配置。"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from backend.oj_modules.problems.llm_bindings import (
    DIRECT_IMAGE_GRADING_ENDPOINT_ID,
    TEXT_GRADING_ENDPOINT_ID,
    deserialize_problem_llm_bindings,
)


MAX_VOTES_PER_ENDPOINT = 5
MAX_TOTAL_VOTES = 10


class WrittenVoteConfigError(ValueError):
    pass


def normalize_written_vote_config(value):
    if value in (None, ""):
        return []
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise WrittenVoteConfigError("评委配置必须是合法的 JSON 数组") from exc
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise WrittenVoteConfigError("评委配置必须是数组")

    result = []
    seen = set()
    total = 0
    for item in value:
        if not isinstance(item, Mapping):
            raise WrittenVoteConfigError("每个评委配置都必须是对象")
        if isinstance(item.get("endpoint_id"), bool) or isinstance(item.get("count"), bool):
            raise WrittenVoteConfigError("评委端点和 Vote 次数必须是整数")
        try:
            endpoint_id = int(item.get("endpoint_id"))
            count = int(item.get("count"))
        except (TypeError, ValueError) as exc:
            raise WrittenVoteConfigError("评委端点和 Vote 次数必须是整数") from exc
        if endpoint_id <= 0:
            raise WrittenVoteConfigError("评委端点必须是正整数")
        if endpoint_id in seen:
            raise WrittenVoteConfigError("同一个评委模型只能配置一行")
        if count < 1 or count > MAX_VOTES_PER_ENDPOINT:
            raise WrittenVoteConfigError(
                f"每个评委模型的 Vote 次数必须在 1 到 {MAX_VOTES_PER_ENDPOINT} 之间"
            )
        seen.add(endpoint_id)
        total += count
        result.append({"endpoint_id": endpoint_id, "count": count})
    if total > MAX_TOTAL_VOTES:
        raise WrittenVoteConfigError(f"Vote 总次数不能超过 {MAX_TOTAL_VOTES}")
    return result


def deserialize_written_vote_config(value):
    try:
        return normalize_written_vote_config(value)
    except WrittenVoteConfigError:
        return []


def serialize_written_vote_config(value):
    normalized = normalize_written_vote_config(value)
    if not normalized:
        return None
    return json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))


def written_vote_config_from_form(form, *, existing=None):
    if "written_vote_config" not in form:
        return normalize_written_vote_config(existing or [])
    return normalize_written_vote_config(form.get("written_vote_config"))


def copyable_written_vote_config(problem, *, allowed_endpoint_ids):
    """返回可完整复制的书面题 Vote 配置；不兼容时不返回部分评委。

    旧题未保存多评委配置时，沿用批改链路的单端点 1 Vote 语义。
    完全未指定评委的题目返回空数组，供目标题目恢复为默认配置。
    """

    try:
        problem_type = int(problem.get("type") or 1)
        raw_mode = problem.get("written_grading_mode")
        written_mode = int(1 if raw_mode is None else raw_mode)
    except (TypeError, ValueError):
        return None
    if problem_type != 2 or written_mode not in {1, 2, 3}:
        return None

    try:
        config = normalize_written_vote_config(problem.get("written_vote_config"))
    except WrittenVoteConfigError:
        return None
    if not config:
        binding_key = (
            DIRECT_IMAGE_GRADING_ENDPOINT_ID
            if written_mode == 2
            else TEXT_GRADING_ENDPOINT_ID
        )
        endpoint_id = deserialize_problem_llm_bindings(
            problem.get("llm_endpoint_bindings")
        ).get(binding_key)
        if endpoint_id is not None:
            config = [{"endpoint_id": endpoint_id, "count": 1}]

    if any(item["endpoint_id"] not in allowed_endpoint_ids for item in config):
        return None
    return config


__all__ = [
    "MAX_TOTAL_VOTES",
    "MAX_VOTES_PER_ENDPOINT",
    "WrittenVoteConfigError",
    "copyable_written_vote_config",
    "deserialize_written_vote_config",
    "normalize_written_vote_config",
    "serialize_written_vote_config",
    "written_vote_config_from_form",
]
