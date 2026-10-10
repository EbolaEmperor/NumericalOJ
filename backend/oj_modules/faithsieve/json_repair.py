"""一次局部 JSON 格式修复；不提供题目或角色任务，也不改写叶子内容。"""

from copy import deepcopy
import json
import re

from .artifacts import MAX_RESPONSE_BYTES, FaithSieveProtocolError


_COMPLETE_FINISH = {"stop", "end_turn", "stop_sequence", "tool_calls", "function_call", "tool_use"}
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
REPAIR_SYSTEM_PROMPT = """你只修复下面原始回传的 JSON 语法，不重新执行原任务。
原始回传和解析错误是全部输入。只修引号、转义、逗号、冒号和闭合括号等必要格式问题。
不得重做数学、增删断言、修改字段/数值/状态/文件正文、总结文本或补缺失内容。
保留所有已有对象/数组的类型和出现顺序，保留全部字符串与其他叶子值的顺序和内容。
非法反斜杠转义按字面反斜杠保留，字符串内裸换行按原换行保留；合法转义仍表示原来的字符。
只能按本次请求指定的回传格式提交修复后的同一完整对象：有结果函数时只调用一次 faithsieve_result，无正文；JSON mode时只返回一个纯JSON对象，无工具调用或围栏。
无法只改格式而保留内容时不要编造内容。"""


def has_complete_response(response):
    finish = getattr(response, "finish_reason", None)
    return isinstance(finish, str) and finish in _COMPLETE_FINISH


def _bounded_text(raw):
    if not isinstance(raw, str):
        raise FaithSieveProtocolError("JSON 格式修复原文必须是字符串")
    try:
        if len(raw.encode("utf-8")) > MAX_RESPONSE_BYTES:
            raise FaithSieveProtocolError("JSON 格式修复原文过大")
    except UnicodeError:
        raise FaithSieveProtocolError("JSON 格式修复原文不是有效 Unicode") from None


def _string_token(raw, start):
    result, cursor = [], start + 1
    while cursor < len(raw):
        character = raw[cursor]
        if character == '"':
            value = "".join(result)
            try:
                # 合法 JSON 的 surrogate pair 与字面 Unicode 使用相同值比较。
                value = value.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
            except UnicodeError:
                raise FaithSieveProtocolError("JSON 格式修复原文含歧义 Unicode 字符串") from None
            return value, cursor + 1
        if character != "\\":
            result.append(character)
            cursor += 1
            continue
        if cursor + 1 >= len(raw):
            break
        escaped = raw[cursor + 1]
        if escaped == "u":
            digits = raw[cursor + 2:cursor + 6]
            if len(digits) != 4 or not re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                raise FaithSieveProtocolError("JSON 格式修复原文含歧义 Unicode 转义")
            result.append(chr(int(digits, 16)))
            cursor += 6
        else:
            result.append(_ESCAPES.get(escaped, "\\" + escaped))
            cursor += 2
    raise FaithSieveProtocolError("JSON 格式修复原文含未闭合或歧义字符串")


def _preserved_tokens(tokens):
    """不改变旧词法的容器身份、叶子顺序和根闭合兼容规则。"""
    last_content = max((index for index, token in enumerate(tokens) if token[0] != "close"), default=-1)
    preserved, ancestors, opening = [], [], 0
    for index, token in enumerate(tokens):
        if token[0] == "close":
            if not ancestors:
                continue  # 根之后多出的尾部闭合符可删除，不能恢复任何子容器。
            expected = "}" if ancestors[-1][1] == "{" else "]"
            if token[1] != expected:
                raise FaithSieveProtocolError("JSON 格式修复原文的容器闭合存在歧义")
            if len(ancestors) == 1 and index < last_content:
                continue  # 唯一根提前闭合：尾部原字段仍属于根，不重开子容器。
            ancestors.pop()
            continue
        preserved.append((*token, tuple(item[0] for item in ancestors)))
        if token[0] == "container":
            ancestors.append((opening, token[1]))
            opening += 1
    return preserved


def _legacy_content_tokens(raw):
    _bounded_text(raw)
    try:
        _first, end = json.JSONDecoder().raw_decode(raw.lstrip())
    except (ValueError, RecursionError):
        pass
    else:
        if raw.lstrip()[end:].lstrip().startswith(("{", "[")):
            raise FaithSieveProtocolError("JSON 格式修复不能合并或删除多个顶层对象")
    tokens, cursor = [], 0
    while cursor < len(raw):
        character = raw[cursor]
        if character in " \t\r\n ,:":
            cursor += 1
        elif character in "}]":
            tokens.append(("close", character))
            cursor += 1
        elif character in "{[":
            tokens.append(("container", character))
            cursor += 1
        elif character == '"':
            value, cursor = _string_token(raw, cursor)
            tokens.append(("string", value))
            if cursor < len(raw) and raw[cursor] == '"':
                raise FaithSieveProtocolError("JSON 格式修复原文含歧义引号")
        elif character in "-0123456789":
            match = _NUMBER.match(raw, cursor)
            if not match or (match.end() < len(raw) and raw[match.end()] not in " \t\r\n{}[],:\""):
                raise FaithSieveProtocolError("JSON 格式修复原文含歧义数字")
            tokens.append(("number", match.group()))
            cursor = match.end()
        else:
            literal = next((value for value in ("true", "false", "null") if raw.startswith(value, cursor)), None)
            if literal is None or (cursor + len(literal) < len(raw) and raw[cursor + len(literal)] not in " \t\r\n{}[],:\""):
                raise FaithSieveProtocolError("JSON 格式修复原文含未知裸词或歧义引号")
            tokens.append((literal, literal))
            cursor += len(literal)
    return _preserved_tokens(tokens)


def _bracketed_quoted_text(raw, start):
    """仅识别字符串正文中的 [\"文字\", \"文字\"]；不接受对象字段或裸词。"""
    cursor, result = start + 1, ["["]

    def whitespace():
        nonlocal cursor
        begin = cursor
        while cursor < len(raw) and raw[cursor] in " \t\r\n":
            cursor += 1
        result.append(raw[begin:cursor])

    whitespace()
    if cursor >= len(raw) or raw[cursor] != '"':
        return None
    while True:
        value, cursor = _string_token(raw, cursor)
        result.extend(('"', value, '"'))
        whitespace()
        if cursor < len(raw) and raw[cursor] == "]":
            return "".join(result) + "]", cursor + 1
        if cursor >= len(raw) or raw[cursor] != ",":
            raise FaithSieveProtocolError("JSON 格式修复原文含歧义引号")
        result.append(",")
        cursor += 1
        whitespace()
        if cursor >= len(raw) or raw[cursor] != '"':
            raise FaithSieveProtocolError("JSON 格式修复原文含歧义引号")


def _object_value_string_token(raw, start):
    result, cursor, found = [], start + 1, False
    while cursor < len(raw):
        if raw[cursor] == "[":
            bracketed = _bracketed_quoted_text(raw, cursor)
            if bracketed is not None:
                value, cursor = bracketed
                result.append(value)
                found = True
                continue
        if raw[cursor] == '"':
            value = "".join(result)
            try:
                value = value.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
            except UnicodeError:
                raise FaithSieveProtocolError("JSON 格式修复原文含歧义 Unicode 字符串") from None
            return value, cursor + 1, found
        if raw[cursor] != "\\":
            result.append(raw[cursor])
            cursor += 1
            continue
        if cursor + 1 >= len(raw):
            break
        escaped = raw[cursor + 1]
        if escaped == "u":
            digits = raw[cursor + 2:cursor + 6]
            if len(digits) != 4 or not re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                raise FaithSieveProtocolError("JSON 格式修复原文含歧义 Unicode 转义")
            result.append(chr(int(digits, 16)))
            cursor += 6
        else:
            result.append(_ESCAPES.get(escaped, "\\" + escaped))
            cursor += 2
    raise FaithSieveProtocolError("JSON 格式修复原文含未闭合或歧义字符串")


def _bracketed_value_content_tokens(raw):
    """父容器语法完整时才识别对象字符串值内的括号引用，不猜测字段边界。"""
    tokens, cursor, found = [], 0, False

    def whitespace():
        nonlocal cursor
        while cursor < len(raw) and raw[cursor] in " \t\r\n":
            cursor += 1

    def require(character):
        nonlocal cursor
        whitespace()
        if cursor >= len(raw) or raw[cursor] != character:
            raise FaithSieveProtocolError("JSON 格式修复原文含未知裸词或歧义引号")
        cursor += 1

    def value(*, object_value=False):
        nonlocal cursor, found
        whitespace()
        if cursor >= len(raw):
            raise FaithSieveProtocolError("JSON 格式修复原文含未闭合或歧义字符串")
        character = raw[cursor]
        if character in "{[":
            cursor += 1
            tokens.append(("container", character))
            close = "}" if character == "{" else "]"
            whitespace()
            if cursor < len(raw) and raw[cursor] == close:
                cursor += 1
                tokens.append(("close", close))
                return
            while True:
                if character == "{":
                    whitespace()
                    if cursor >= len(raw) or raw[cursor] != '"':
                        raise FaithSieveProtocolError("JSON 格式修复原文含未知裸词或歧义引号")
                    key, cursor = _string_token(raw, cursor)
                    tokens.append(("string", key))
                    require(":")
                value(object_value=character == "{")
                whitespace()
                if cursor < len(raw) and raw[cursor] == close:
                    cursor += 1
                    tokens.append(("close", close))
                    return
                require(",")
        elif character == '"':
            if object_value:
                text, cursor, bracketed = _object_value_string_token(raw, cursor)
                found |= bracketed
            else:
                text, cursor = _string_token(raw, cursor)
            tokens.append(("string", text))
        elif character in "-0123456789":
            match = _NUMBER.match(raw, cursor)
            if not match:
                raise FaithSieveProtocolError("JSON 格式修复原文含歧义数字")
            tokens.append(("number", match.group()))
            cursor = match.end()
        else:
            literal = next((item for item in ("true", "false", "null") if raw.startswith(item, cursor)), None)
            if literal is None:
                raise FaithSieveProtocolError("JSON 格式修复原文含未知裸词或歧义引号")
            tokens.append((literal, literal))
            cursor += len(literal)

    value()
    whitespace()
    if cursor != len(raw) or not found:
        raise FaithSieveProtocolError("JSON 格式修复原文含未知裸词或歧义引号")
    return _preserved_tokens(tokens)


def content_tokens(raw):
    """优先保持旧词法；仅在明确对象字符串值内补识别方括号引用。"""
    try:
        return _legacy_content_tokens(raw)
    except FaithSieveProtocolError as exc:
        if str(exc) not in {"JSON 格式修复原文含未知裸词或歧义引号", "JSON 格式修复原文含歧义引号"}:
            raise
        try:
            return _bracketed_value_content_tokens(raw)
        except RecursionError:
            raise FaithSieveProtocolError("JSON 格式修复原文的父容器层次无法安全识别") from None


def assert_repair_content_unchanged(original, repaired):
    if content_tokens(original) != content_tokens(repaired):
        raise FaithSieveProtocolError("JSON 格式修复改变了已有容器、字段或叶子内容，不能采用")


def strict_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(strict_equal(left[key], right[key]) for key in left)
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(strict_equal(a, b) for a, b in zip(left, right))
    return left == right


def build_repair_request(raw, error, endpoint_identity, call_options):
    _bounded_text(raw)
    if not isinstance(error, str) or not error or len(error) > 4096:
        raise FaithSieveProtocolError("JSON 格式修复解析错误说明无效")
    fence = "`" * (max((len(match.group()) for match in re.finditer(r"`+", raw)), default=2) + 1)
    user = "原始回传（字面全文）\n" + fence + "text\n" + raw + "\n" + fence + "\n\n解析错误\n" + error
    return {"endpoint": deepcopy(endpoint_identity), "messages": [
        {"role": "system", "content": REPAIR_SYSTEM_PROMPT}, {"role": "user", "content": user}],
        "call_options": deepcopy(call_options)}


def validate_repair_state(saved, endpoint_identity, call_options):
    if (not isinstance(saved, dict) or set(saved) - {
            "state", "raw_response", "parse_error", "request", "original_finish_reason", "repaired_response", "error"}
            or not {"state", "raw_response", "parse_error", "request", "original_finish_reason"} <= set(saved)
            or not isinstance(saved["original_finish_reason"], str)
            or saved["original_finish_reason"] not in _COMPLETE_FINISH
            or not isinstance(saved["state"], str)
            or saved["state"] not in {"pending", "completed", "protocol_error", "endpoint_error"}):
        raise FaithSieveProtocolError("JSON 格式修复 checkpoint 元数据无效")
    expected = build_repair_request(saved["raw_response"], saved["parse_error"], endpoint_identity, call_options)
    if not strict_equal(saved["request"], expected):
        raise FaithSieveProtocolError("JSON 格式修复重入请求与已保存完整输入不一致")
    if saved["state"] == "completed":
        assert_repair_content_unchanged(saved["raw_response"], saved.get("repaired_response"))
    if "error" in saved and not isinstance(saved["error"], str):
        raise FaithSieveProtocolError("JSON 格式修复错误状态无效")
    return saved
