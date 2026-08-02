"""AI 检测页面与 JSON API 共用的结果展示 helper。"""

import json

from oj_modules.problems.presentation import strip_problem_title_tags


def decode_detection_result_details(row):
    """原地补充模板使用的结构化证据与行为信号。"""
    for source_key, display_key in (
        ("llm_evidence", "_evidence"),
        ("behavior_detail", "_signals"),
    ):
        try:
            row[display_key] = json.loads(row.get(source_key) or "[]")
        except Exception:
            row[display_key] = []
    return row


def serialize_detection_result(row):
    """复制一条检测结果，生成 JSON API 所需的安全展示字段。"""
    result = decode_detection_result_details(dict(row or {}))
    result["problem_title"] = strip_problem_title_tags(
        result.get("problem_title") or ""
    )
    return result


__all__ = ["decode_detection_result_details", "serialize_detection_result"]
