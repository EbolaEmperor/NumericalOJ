"""完整空结果函数的一次流式回退；原数学请求和所有配置保持冻结。"""

from copy import deepcopy
from types import SimpleNamespace

from .artifacts import FaithSieveProtocolError, parse_json_response
from .json_repair import has_complete_response, strict_equal
from .prompts import IMAGE_ROLE_NAMES, TOOL_ROLES
from .transport import RESULT_TOOL_NAME


EMPTY_RESULT_RETRY_VERSION = 1


def response_snapshot(response):
    """只冻结两个回传通道和终止信号；结果函数不执行，无需供应商调用 ID。"""
    if type(response) is dict:
        value = deepcopy(response)
        if set(value) != {"text", "finish_reason", "tool_calls"}:
            raise FaithSieveProtocolError("空结果重试回传快照字段无效")
    else:
        calls = getattr(response, "tool_calls", None)
        if type(calls) not in {list, tuple}:
            raise FaithSieveProtocolError("空结果重试回传工具清单无效")
        value = {"text": getattr(response, "text", None), "finish_reason": getattr(response, "finish_reason", None),
                 "tool_calls": [{"name": getattr(call, "name", None), "arguments": getattr(call, "arguments", None)}
                                for call in calls]}
    if (type(value["text"]) is not str or type(value["finish_reason"]) not in {str, type(None)}
            or type(value["tool_calls"]) is not list
            or any(type(call) is not dict or set(call) != {"name", "arguments"}
                   or type(call["name"]) is not str or type(call["arguments"]) is not str
                   for call in value["tool_calls"])):
        raise FaithSieveProtocolError("空结果重试回传快照类型无效")
    return value


def restore_response(snapshot):
    value = response_snapshot(snapshot)
    return SimpleNamespace(text=value["text"], finish_reason=value["finish_reason"],
                           tool_calls=tuple(SimpleNamespace(**call) for call in value["tool_calls"]))


def empty_result_response(response, options):
    """只识别非流式、完整且唯一的纯空对象函数参数，不解释或采用旁白。"""
    if (type(options) is not dict or "response_format" in options
            or "stream" in options and options["stream"] is not False):
        return None
    tools = options.get("tools")
    if (type(tools) is not list or len(tools) != 1 or type(tools[0]) is not dict
            or tools[0].get("type") != "function" or type(tools[0].get("function")) is not dict
            or tools[0]["function"].get("name") != RESULT_TOOL_NAME):
        return None
    try:
        value = response_snapshot(response)
        if (not has_complete_response(restore_response(value)) or len(value["tool_calls"]) != 1
                or value["tool_calls"][0]["name"] != RESULT_TOOL_NAME
                or parse_json_response(value["tool_calls"][0]["arguments"], strict_constants=True) != {}):
            return None
    except FaithSieveProtocolError:
        return None
    return value


def empty_result_retry_options(request):
    if (type(request) is not dict or type(request.get("proof_graph_version")) is not int
            or request["proof_graph_version"] != 3 or type(request.get("node_selection_version")) is not int
            or request["node_selection_version"] != 1 or type(request.get("role")) is not str
            or request["role"] not in IMAGE_ROLE_NAMES
            or request["role"] in TOOL_ROLES or type(request.get("messages")) is not list
            or type(request.get("call_options")) is not dict or type(request.get("endpoint")) is not dict
            or type(request["endpoint"].get("protocol")) is not str
            or request["endpoint"].get("protocol") not in {"openai", "anthropic"}):
        raise FaithSieveProtocolError("空结果流式重试不能升级原角色或协议")
    options = request["call_options"]
    if empty_result_response({"text": "", "finish_reason": "tool_use",
                              "tool_calls": [{"name": RESULT_TOOL_NAME, "arguments": "{}"}]}, options) is None:
        raise FaithSieveProtocolError("空结果流式重试的原函数请求无效或已使用流式")
    retry = deepcopy(options)
    retry.update(stream=True, require_complete_stream=True)
    if request["endpoint"]["protocol"] == "openai":
        usage = retry.get("stream_options", {})
        if type(usage) is not dict:
            raise FaithSieveProtocolError("空结果流式重试的原 usage 选项无效")
        retry["stream_options"] = {**usage, "include_usage": True}
    return retry


def build_empty_result_retry_state(request, response):
    options = empty_result_retry_options(request)
    original = empty_result_response(response, request["call_options"])
    if original is None:
        raise FaithSieveProtocolError("只有完整且唯一的空结果函数可进入流式重试")
    return {"version": EMPTY_RESULT_RETRY_VERSION, "state": "pending", "original_request": deepcopy(request),
            "original_response": original, "retry_request": {**deepcopy(request), "call_options": options}}


def validate_empty_result_retry_state(saved, request):
    required = {"version", "state", "original_request", "original_response", "retry_request"}
    if (type(saved) is not dict or not required <= set(saved) or set(saved) - (required | {"response", "error"})
            or type(saved.get("version")) is not int or saved["version"] != EMPTY_RESULT_RETRY_VERSION
            or type(saved.get("state")) is not str
            or saved["state"] not in {"pending", "completed", "protocol_error", "endpoint_error"}
            or not strict_equal(saved["original_request"], request)):
        raise FaithSieveProtocolError("空结果流式重试 checkpoint 合同无效")
    expected = build_empty_result_retry_state(request, saved["original_response"])
    if not strict_equal(saved["retry_request"], expected["retry_request"]):
        raise FaithSieveProtocolError("空结果流式重试完整输入或配置已变化")
    if "response" in saved:
        response_snapshot(saved["response"])
    if saved["state"] == "completed" and ("response" not in saved
            or not has_complete_response(restore_response(saved["response"]))):
        raise FaithSieveProtocolError("空结果流式重试缺少完整的实际回传")
    if saved["state"] == "pending" and ("response" in saved or "error" in saved):
        raise FaithSieveProtocolError("空结果流式重试未完成状态含终态回传")
    if saved["state"] in {"protocol_error", "endpoint_error"} and not saved.get("error"):
        raise FaithSieveProtocolError("空结果流式重试失败状态缺少错误记录")
    if "error" in saved and type(saved["error"]) is not str:
        raise FaithSieveProtocolError("空结果流式重试错误状态无效")
    return saved
