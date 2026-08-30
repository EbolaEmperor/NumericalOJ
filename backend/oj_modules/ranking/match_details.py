"""ELO 对战详情输出协议。

评分脚本的 ``details`` 既要兼容历史上的字符串/任意 JSON 对象，也允许作者显式选择
纯文本或沙箱 HTML。这个模块只负责把数据库中的值规范化为稳定的 API 结构；HTML 的
权限隔离由详情页中的 sandbox iframe 与 CSP 共同完成。
"""

import json


DETAIL_FORMAT_TEXT = "text"
DETAIL_FORMAT_HTML = "html"
DEFAULT_HTML_HEIGHT = 520
MIN_HTML_HEIGHT = 240
MAX_HTML_HEIGHT = 1200

_PREFERRED_TEXT_KEYS = (
    "reason",
    "verdict",
    "explanation",
    "justification",
    "message",
)
_EMPTY_DETAILS_MESSAGE = "（评测脚本未输出 details 字段）"


def _decode_stored_details(details):
    if not isinstance(details, str):
        return details
    stripped = details.strip()
    if not stripped:
        return ""
    try:
        return json.loads(stripped)
    except (TypeError, ValueError):
        return details


def _stringify_text(value):
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            pass
    return str(value)


def _html_height(value):
    try:
        height = int(value)
    except (TypeError, ValueError):
        height = DEFAULT_HTML_HEIGHT
    return max(MIN_HTML_HEIGHT, min(MAX_HTML_HEIGHT, height))


def normalize_match_detail_output(details, *, error_message=None):
    """返回 ``{"format": "text|html", "content": ...}``。

    新协议要求 ``details`` 同时包含 ``format`` 和 ``content`` 才会被识别为显式输出，
    避免历史对象里偶然存在 ``format`` 字段时改变展示行为。HTML 可额外给出 ``height``，
    页面会把它限制在 240–1200px。
    """
    if error_message:
        return {
            "format": DETAIL_FORMAT_TEXT,
            "content": f"【脚本错误】\n{error_message}",
        }

    value = _decode_stored_details(details)
    if value is None or value == "":
        return {
            "format": DETAIL_FORMAT_TEXT,
            "content": _EMPTY_DETAILS_MESSAGE,
        }

    if isinstance(value, dict):
        output_format = str(value.get("format") or "").strip().lower()
        if "content" in value and output_format in (
            DETAIL_FORMAT_TEXT,
            DETAIL_FORMAT_HTML,
        ):
            output = {
                "format": output_format,
                "content": _stringify_text(value.get("content")),
            }
            if output_format == DETAIL_FORMAT_HTML:
                output["height"] = _html_height(value.get("height"))
            return output

        for key in _PREFERRED_TEXT_KEYS:
            preferred = value.get(key)
            if preferred is not None and preferred != "":
                return {
                    "format": DETAIL_FORMAT_TEXT,
                    "content": _stringify_text(preferred),
                }

    return {
        "format": DETAIL_FORMAT_TEXT,
        "content": _stringify_text(value),
    }


__all__ = [
    "DEFAULT_HTML_HEIGHT",
    "DETAIL_FORMAT_HTML",
    "DETAIL_FORMAT_TEXT",
    "MAX_HTML_HEIGHT",
    "MIN_HTML_HEIGHT",
    "normalize_match_detail_output",
]
