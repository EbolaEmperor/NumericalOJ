"""单次模型请求的 JSON 或结果函数回传；不执行工具或续聊。"""

from backend.oj_modules.ai.endpoints import LLMEndpointSnapshot, LLMProtocol

from .artifacts import FaithSieveJSONSyntaxError, FaithSieveProtocolError, parse_json_response
from .json_repair import has_complete_response
from .local_diagnostics import local_diagnostics_schema
from .external_results import validate_external_results_version


RESULT_TOOL_NAME = "faithsieve_result"
TREE_STREAM_MAX_BYTES = 8 * 1024 * 1024


def _object(properties, required=None):
    return {"type": "object", "properties": properties,
            "required": list(properties) if required is None else list(required), "additionalProperties": False}


def _tree_schema(proof_graph_version=1, *, external_results_version=None):
    external_version = validate_external_results_version(external_results_version)
    if external_version is not None and proof_graph_version != 3:
        raise FaithSieveProtocolError("外部结果仅适用于图像证明依赖图")
    text = {"type": "string", "minLength": 1}
    texts = {"type": "array", "items": text}
    if proof_graph_version in {2, 3}:
        node = _object({"id": text, "kind": {"type": "string", "enum": ["given", "claim"]},
                        "label": text, "statement": text,
                        "source_type": {"type": "string", "enum": ["problem", "submission"]},
                        "step_ids": texts, "source_location": text, "source_text": text})
        if proof_graph_version == 3:
            node = _object({name: node["properties"][name] for name in ("id", "kind", "label", "statement")})
            if external_version is not None:
                node["properties"]["kind"]["enum"] = ["given", "claim", "external"]
        return _object({"schema_version": {"type": "integer", "enum": [proof_graph_version]},
                        "nodes": {"type": "array", "items": node},
                        "edges": {"type": "array", "items": _object({"id": text, "from": text, "to": text})},
                        "target_ids": texts, "ambiguities": texts})
    if proof_graph_version != 1:
        raise FaithSieveProtocolError("FaithSieve 证明图协议版本无效")
    reference = _object({"inherit_from": text})
    conditions = _object({"inherit_from": text,
                          "remove": {"type": "array", "items": {"anyOf": [{"type": "integer", "minimum": 0}, text]}},
                          "add": texts})
    node = _object({"id": text, "label": text, "conditions": {"anyOf": [texts, conditions]},
                    "goal": {"anyOf": [text, reference]}, "scope": texts})
    edge = _object({**{name: text for name in ("id", "from", "to", "step_id", "source_location", "source_text",
                                             "goal_relation", "transition_type")},
                    "changes": _object({name: texts for name in ("retained", "added", "consumed", "transformed")}),
                    "scope": texts})
    return _object({"schema_version": {"type": "integer", "enum": [1]}, "root_id": text,
                    "nodes": {"type": "array", "items": node}, "edges": {"type": "array", "items": edge},
                    "ambiguities": texts})


def result_tool_options(endpoint, *, fields=None, statuses=None, artifact=None, scoring=False, proof_graph_version=1,
                        external_results_version=None):
    """只声明本次结果字段；完整语义、图结构与大小仍由原校验器决定。"""
    if scoring:
        schema = _object({"verdict": {"type": "string", "enum": ["correct", "incorrect", "inconclusive"]},
                          "score": {"type": "integer", "minimum": 0, "maximum": 5},
                          "comment": {"type": "string", "minLength": 1}})
    else:
        properties = {"status": {"type": "string", "enum": sorted(statuses)},
                      "artifact": {"type": "string", "enum": [artifact]},
                      "report": {"type": "string", "minLength": 1},
                      "focus_unit": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                      "candidate_units": {"type": "array", "items": {"type": "string"}},
                      "diagnostics": local_diagnostics_schema(),
                      "verdict": {"type": "string", "enum": ["correct", "incorrect", "inconclusive"]}}
        artifact_schema = _object({artifact: _tree_schema(proof_graph_version, external_results_version=external_results_version)
                                  if artifact == "faithsieve-work/tree.json" else {"type": "string"}})
        if artifact.startswith("faithsieve-work/obligations/"):
            # 义务数量由本次分析确定；实际允许的路径仍须经宿主逐项核验。
            artifact_schema["additionalProperties"] = {"type": "string"}
        schema = _object({"result": _object({name: properties[name] for name in sorted(fields)}),
                          "artifacts": artifact_schema, "control": {"type": "object"}}, ["result", "artifacts"])
        if artifact == "faithsieve-work/tree.json":
            schema["properties"].pop("control")
    tool = {"type": "function", "function": {
        "name": RESULT_TOOL_NAME, "description": "提交本任务的完整结果与文件正文；仅用于回传，不执行操作。",
        "parameters": schema,
    }}
    snapshot = LLMEndpointSnapshot.from_mapping(endpoint) if isinstance(endpoint, dict) else endpoint
    # thinking ON 使用 auto，避免强制工具与供应商思考协议冲突；不改变管理员的思考配置。
    thinking = isinstance(snapshot, LLMEndpointSnapshot) and snapshot.thinking_enabled
    choice = "auto" if thinking else {"type": "function", "function": {"name": RESULT_TOOL_NAME}}
    return {"tools": [tool], "tool_choice": choice}


def result_request_options(endpoint, *, fields=None, statuses=None, artifact=None, scoring=False, proof_graph_version=1,
                           external_results_version=None):
    """非思考 OpenAI 使用 JSON mode；思考模式保守沿用单次结果函数回传。"""
    snapshot = LLMEndpointSnapshot.from_mapping(endpoint) if isinstance(endpoint, dict) else endpoint
    if (isinstance(snapshot, LLMEndpointSnapshot) and snapshot.protocol is LLMProtocol.OPENAI
            and not snapshot.thinking_enabled):
        return {"response_format": {"type": "json_object"}}
    return result_tool_options(snapshot, fields=fields, statuses=statuses, artifact=artifact, scoring=scoring,
                               proof_graph_version=proof_graph_version, external_results_version=external_results_version)


def tree_stream_request_options(endpoint, *, proof_graph_version=1):
    """仅树生成请求使用受限流式接收；最终工件仍经完整 JSON 与树校验。"""
    snapshot = LLMEndpointSnapshot.from_mapping(endpoint) if isinstance(endpoint, dict) else endpoint
    options = {"stream": True, "require_complete_stream": True}
    if proof_graph_version != 3:
        options["max_stream_bytes"] = TREE_STREAM_MAX_BYTES
    if isinstance(snapshot, LLMEndpointSnapshot) and snapshot.protocol is LLMProtocol.OPENAI:
        options["stream_options"] = {"include_usage": True}
    return options


def validate_tree_stream_request_options(options, *, proof_graph_version=1):
    """额外校验冻结选项类型，避免 Python 相等比较把 1 或浮点视为原值。"""
    fields = {"stream", "require_complete_stream", "max_stream_bytes", "stream_options"}
    if not isinstance(options, dict) or not fields.intersection(options):
        # 完整旧普通请求由 completed-only 候选比对，不加入新的流式选项。
        return
    if (type(options.get("stream")) is not bool or options["stream"] is not True
            or type(options.get("require_complete_stream")) is not bool
            or options["require_complete_stream"] is not True):
        raise FaithSieveProtocolError("FaithSieve 冻结流式请求选项的类型无效")
    if proof_graph_version == 3:
        if "max_stream_bytes" in options:
            raise FaithSieveProtocolError("图像工作流不能新增模块输出额度")
    elif type(options.get("max_stream_bytes")) is not int or options["max_stream_bytes"] <= 0:
        raise FaithSieveProtocolError("FaithSieve 冻结流式请求选项的类型无效")
    if "timeout" in options and (type(options["timeout"]) is not int or options["timeout"] <= 0):
        raise FaithSieveProtocolError("FaithSieve 冻结流式请求等待时间的类型无效")
    if "stream_options" in options:
        usage = options["stream_options"]
        if (not isinstance(usage, dict) or set(usage) != {"include_usage"}
                or type(usage["include_usage"]) is not bool or usage["include_usage"] is not True):
            raise FaithSieveProtocolError("FaithSieve 冻结流式 usage 选项的类型无效")


def _without_execution(payload):
    if "execution" in payload:
        raise FaithSieveProtocolError("FaithSieve 纯模型结果不得自报工具执行证据")
    return payload


def parse_function_result(response):
    text, calls = getattr(response, "text", None), getattr(response, "tool_calls", None)
    if not isinstance(text, str) or text.strip():
        raise FaithSieveProtocolError("FaithSieve 结果函数回传不得包含正文或旁白")
    if not isinstance(calls, (tuple, list)) or len(calls) != 1:
        raise FaithSieveProtocolError("FaithSieve 必须且只能调用一次结果函数 faithsieve_result")
    call = calls[0]
    if getattr(call, "name", None) != RESULT_TOOL_NAME:
        raise FaithSieveProtocolError("FaithSieve 结果函数名称必须为 faithsieve_result")
    arguments = getattr(call, "arguments", None)
    if not isinstance(arguments, str) or not arguments.lstrip().startswith("{"):
        raise FaithSieveProtocolError("FaithSieve 结果函数参数必须是纯 JSON 对象")
    return _without_execution(parse_json_response(arguments, strict_constants=True))


def model_result_raw(response, options, *, allow_tool_commentary=False, allow_result_body=False):
    """提取唯一 JSON 原文；兼容通道先核对完整合法内容，不修补语法。"""
    if type(allow_tool_commentary) is not bool:
        raise FaithSieveProtocolError("FaithSieve 结果函数旁白兼容开关必须为布尔值")
    if type(allow_result_body) is not bool:
        raise FaithSieveProtocolError("FaithSieve 自动回传正文兼容开关必须为布尔值")
    finish_reason = getattr(response, "finish_reason", None)
    if isinstance(finish_reason, str) and finish_reason in {"length", "max_tokens"}:
        raise FaithSieveProtocolError("FaithSieve 模型结果已达到输出上限，不能将截断回传作为完整结果")
    if "response_format" not in options:
        text, calls = getattr(response, "text", None), getattr(response, "tool_calls", None)
        if (allow_result_body and type(options.get("tool_choice")) is str and options["tool_choice"] == "auto"
                and isinstance(calls, (tuple, list)) and not calls):
            # auto 可选择一个完整正文结果；只接受唯一合法 JSON，不与函数参数拼接。
            if not isinstance(text, str) or not text.lstrip().startswith("{") or not has_complete_response(response):
                raise FaithSieveProtocolError("FaithSieve 自动回传正文必须是完整的纯 JSON 对象")
            try:
                payload = parse_json_response(text, strict_constants=True)
            except FaithSieveJSONSyntaxError:
                raise FaithSieveProtocolError("FaithSieve 自动回传正文只接受完整且合法的 JSON 参数") from None
            _without_execution(payload)
            return text
        if not isinstance(text, str) or (text.strip() and not allow_tool_commentary):
            raise FaithSieveProtocolError("FaithSieve 结果函数回传不得包含正文或旁白")
        if not isinstance(calls, (tuple, list)) or len(calls) != 1:
            raise FaithSieveProtocolError("FaithSieve 必须且只能调用一次结果函数 faithsieve_result")
        if getattr(calls[0], "name", None) != RESULT_TOOL_NAME:
            raise FaithSieveProtocolError("FaithSieve 结果函数名称必须为 faithsieve_result")
        raw = getattr(calls[0], "arguments", None)
        if not isinstance(raw, str) or not raw.lstrip().startswith("{"):
            raise FaithSieveProtocolError("FaithSieve 结果函数参数必须是纯 JSON 对象")
        if text.strip():
            # 仅忽略完整合法函数结果之外的旁白，绝不从旁白补全参数或修复任务。
            if not has_complete_response(response):
                raise FaithSieveProtocolError("FaithSieve 结果函数旁白兼容需要完整终止信号")
            try:
                payload = parse_json_response(raw, strict_constants=True)
            except FaithSieveJSONSyntaxError:
                raise FaithSieveProtocolError("FaithSieve 结果函数旁白兼容只接受完整且合法的 JSON 参数") from None
            _without_execution(payload)
        return raw
    if options["response_format"] != {"type": "json_object"} or any(
        key in options for key in ("tools", "tool_choice")
    ):
        raise FaithSieveProtocolError("FaithSieve JSON mode 请求格式无效")
    text, calls = getattr(response, "text", None), getattr(response, "tool_calls", None)
    if not isinstance(calls, (tuple, list)) or calls:
        raise FaithSieveProtocolError("FaithSieve JSON mode 回传不得包含工具调用")
    if not isinstance(text, str) or not text.lstrip().startswith("{"):
        raise FaithSieveProtocolError("FaithSieve JSON mode 回传必须是纯 JSON 对象")
    return text


def parse_model_result(response, options, *, allow_tool_commentary=False, allow_result_body=False):
    """按冻结格式读取唯一结果；auto 正文兼容必须由调用方显式开启。"""
    return _without_execution(parse_json_response(
        model_result_raw(response, options, allow_tool_commentary=allow_tool_commentary,
                         allow_result_body=allow_result_body), strict_constants=True))


def function_response_diagnostic(response):
    """提取原回传参数供现有受限私有诊断脱敏，不复制请求或端点。"""
    calls = getattr(response, "tool_calls", ())
    calls = calls if isinstance(calls, (tuple, list)) else ()
    return {"text": getattr(response, "text", ""), "tool_call_count": len(calls),
            "tool_calls": [{"name": getattr(call, "name", None), "arguments": getattr(call, "arguments", None)}
                           for call in calls[:8]]}


def model_response_diagnostic(response, options):
    """JSON mode 保存正文；异常工具混返仍保存可定位的参数摘要。"""
    if "response_format" in options and not getattr(response, "tool_calls", ()):
        return getattr(response, "text", "")
    return function_response_diagnostic(response)


__all__ = ["RESULT_TOOL_NAME", "TREE_STREAM_MAX_BYTES", "result_tool_options", "result_request_options",
           "tree_stream_request_options", "validate_tree_stream_request_options", "parse_function_result",
           "model_result_raw", "parse_model_result", "function_response_diagnostic", "model_response_diagnostic"]
