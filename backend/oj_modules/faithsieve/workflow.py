"""将 FaithSieve 的原角色职责与控制流程编成显式工作流。

纯文本角色各使用一次普通 LLM 请求；需要实际数学工具的角色交给独立
Judge Agent。待完成任务向宿主抛出 pending，成功步骤按原文 checkpoint 重放。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
from typing import Callable

from backend.oj_modules.ai.endpoints import LLMEndpointError, LLMEndpointSnapshot, LLMEndpointValidationError, call_chat
from backend.oj_modules.observability import redact_text
from backend.oj_modules.submissions.faithsieve import parse_result

from .artifacts import ArtifactStore, FaithSieveJSONSyntaxError, FaithSieveProtocolError, parse_json_response, validate_role_response
from .checkpoints import CheckpointStore, atomic_write
from .budgets import SOURCE_TIMEOUT_SECONDS
from .errors import FaithSieveEndpointError, endpoint_error_metadata
from .empty_result_retry import (
    build_empty_result_retry_state, empty_result_response, response_snapshot,
    restore_response, validate_empty_result_retry_state,
)
from .lean_source import (
    LeanSourceError, contains_forbidden_lean, is_fixed_proof_appendix, lean_tokens,
    statement_prop_name,
)
from .json_repair import (
    assert_repair_content_unchanged, build_repair_request, content_tokens, has_complete_response, strict_equal, validate_repair_state,
)
from .prompts import (
    IMAGE_ROLE_NAMES, LEGACY_SCORE_PROMPT, SCORE_PROMPT, TOOL_ROLES, function_result_prompt, input_message,
    legacy_json_input_message, model_result_prompt, render_role_prompt,
)
from .proof_tree import TREE_PATH, edge_contexts, expand_proof_tree_transport, parse_proof_tree, step_ids
from .result_metadata import project_role_result
from .transport import (
    model_response_diagnostic, model_result_raw, parse_model_result, result_request_options, result_tool_options,
    tree_stream_request_options, validate_tree_stream_request_options,
)


WORK = "faithsieve-work"
SOURCE = f"{WORK}/source/submission.md"
STEPS = f"{WORK}/steps.md"
TREE = TREE_PATH
SCAN = f"{WORK}/scan.md"
EVIDENCE = f"{WORK}/evidence-map.md"
PREFIX = f"{WORK}/prefix-review.md"
FINAL = f"{WORK}/final.md"
RESULT = "faithsieve_result.json"
ROLE_TIMEOUT_SECONDS = 600
GENERATOR_REVISION_LIMIT = 3
FORMAL_REVISION_LIMIT = 3
_DIAGNOSTIC_HEAD_CHARS = 65536
_DIAGNOSTIC_TAIL_CHARS = 131072
_EDGE = re.compile(r"E[1-9][0-9]*\Z")
_OBLIGATION = re.compile(r"E[1-9][0-9]*-O[1-9][0-9]*\Z")
_ROLE_LABELS = {
    "image-render": "渲染原稿图片", "local-verifier": "验证局部命题",
    "verification-auditor": "审核局部验证",
    "node-selector": "选择验证顺序",
    "source-extraction": "看图核对并整理学生原稿", "decomposer": "忠实拆分证明",
    "decomposition-auditor": "独立审计证明拆分", "tree-builder": "建立证明依赖图",
    "tree-auditor": "独立审计证明依赖图", "suspicion-scanner": "扫描证明风险",
    "local-reviewer": "局部复核证明步骤", "obligation-builder": "生成数学义务",
    "check-object-generator": "忠实转换检查对象", "numeric-evaluator": "执行数值验证",
    "statement-formalizer": "形式化数学命题", "semantic-checker": "独立核对形式化语义",
    "proof-searcher": "搜索并编译 Lean 证明", "evidence-mapper": "映射验证证据",
    "prefix-auditor": "复查首错前缀", "final-synthesizer": "综合数学结论",
    "consistency-auditor": "独立审计最终证据链", "scoring": "按原量表评分",
}


class _Inconclusive(Exception):
    pass


@dataclass
class RoleOutput:
    result: dict
    control: dict
    execution: dict
    key: str = ""


_ROLE_STATUSES = {
    "local-verifier": {"passed", "refuted", "inconclusive"},
    "verification-auditor": {"ok", "needs_revision", "graph_defect", "inconclusive"},
    "node-selector": {"ok", "inconclusive"},
    "decomposer": {"ok", "needs_revision", "inconclusive"},
    "decomposition-auditor": {"ok", "needs_revision", "inconclusive"},
    "tree-builder": {"ok", "needs_revision", "inconclusive"},
    "tree-auditor": {"ok", "needs_revision", "inconclusive"},
    "suspicion-scanner": {"ok", "inconclusive"},
    "local-reviewer": {"ok", "inconclusive"},
    "obligation-builder": {"ok", "inconclusive"},
    "check-object-generator": {"ok", "inconclusive"},
    "numeric-evaluator": {"passed", "refuted", "inconclusive"},
    "statement-formalizer": {"ok", "inconclusive"},
    "semantic-checker": {"ok", "needs_revision", "inconclusive"},
    "proof-searcher": {"passed", "refuted", "inconclusive"},
    "evidence-mapper": {"ok", "inconclusive"},
    "prefix-auditor": {"ok", "inconclusive"},
    "final-synthesizer": {"ok", "failed"},
    "consistency-auditor": {"ok", "needs_revision", "inconclusive"},
}


def _check_object_route(markdown, expected_route):
    """只读取独立的 route 元数据行，允许值上的 Markdown 行内样式。"""

    def unstyled(value):
        value = value.strip()
        if len(value) > 128:
            return value
        for _ in range(4):
            wrapped = re.fullmatch(r"(?P<mark>`+|\*{1,3}|_{1,3})(?P<body>.+)(?P=mark)", value)
            if not wrapped:
                return value
            value = wrapped.group("body").strip()
        return value

    routes = []
    fence = None
    in_comment = False
    for line in markdown.splitlines():
        if fence is not None:
            if re.fullmatch(rf"[ ]{{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*", line):
                fence = None
            continue
        if in_comment or "<!--" in line:
            for marker in re.finditer(r"<!--|-->", line):
                if in_comment and marker.group() == "-->":
                    in_comment = False
                elif not in_comment and marker.group() == "<!--":
                    in_comment = True
            continue
        opening = re.match(r"^[ ]{0,3}(`{3,}|~{3,})", line)
        if opening:
            fence = opening.group(1)
            continue
        indentation = line[:len(line) - len(line.lstrip(" \t"))]
        if len(indentation.expandtabs(4)) >= 4:
            continue
        candidate = re.sub(r"^[-*+][ \t]+", "", line.strip())
        declaration = re.split(r"[:=]", candidate, maxsplit=1)
        if len(declaration) != 2 or unstyled(declaration[0]).lower() != "route":
            continue
        route = unstyled(declaration[1]).lower()
        if route not in {"numeric", "lean"}:
            raise FaithSieveProtocolError("检查对象的 route 元数据没有明确 numeric/lean 路径")
        routes.append(route)
    if not isinstance(expected_route, str) or expected_route not in {"numeric", "lean"} or routes != [expected_route]:
        raise FaithSieveProtocolError("检查对象的 route 元数据缺失、重复或与控制路径不一致")
    return expected_route


def _role_paths(role, parameters):
    edge = parameters.get("node_id") or parameters.get("edge_id")
    obligation = parameters.get("obligation_id")
    branch = parameters.get("branch")
    artifact = {
        "decomposer": STEPS,
        "decomposition-auditor": f"{WORK}/review/decomposition.md",
        "tree-builder": TREE,
        "tree-auditor": f"{WORK}/review/tree.md",
        "suspicion-scanner": SCAN,
        "local-reviewer": f"{WORK}/review/{edge}.md",
        "local-verifier": f"{WORK}/verification/{edge}.md",
        "verification-auditor": f"{WORK}/review/{edge}-verification.md",
        "node-selector": f"{WORK}/node-selection.json",
        "obligation-builder": f"{WORK}/obligations/{edge}/index.md",
        "check-object-generator": parameters.get("check_object_path"),
        "numeric-evaluator": parameters.get("numeric_result_path"),
        "statement-formalizer": parameters.get("statement_path"),
        "semantic-checker": parameters.get("semantic_report_path"),
        "proof-searcher": parameters.get("proof_path"),
        "evidence-mapper": EVIDENCE,
        "prefix-auditor": PREFIX,
        "final-synthesizer": FINAL,
        "consistency-auditor": f"{WORK}/review/final.md",
    }[role]
    result_id = role
    if role in {"local-reviewer", "local-verifier", "verification-auditor", "obligation-builder"}:
        result_id = f"{edge}-{role}"
    elif role in {"check-object-generator", "numeric-evaluator"}:
        result_id = f"{obligation}-{role}"
    elif role in {"statement-formalizer", "semantic-checker", "proof-searcher"}:
        result_id = f"{obligation}-{branch}-{role}"
    return artifact, f"{WORK}/results/{result_id}.json"


class FaithSieveWorkflow:
    proof_graph_version = 1
    def __init__(self, *, endpoint, verification_agent, workspace, progress=None, chat=None,
                 initial_reasoning_effort=None, _artifact_store=None, usage_recorder=None):
        if initial_reasoning_effort is not None and (
            not isinstance(initial_reasoning_effort, str) or initial_reasoning_effort not in {"low", "medium"}
        ):
            raise ValueError("FaithSieve 初始思考强度必须为 low、medium 或 None")
        self.endpoint = endpoint
        self.initial_reasoning_effort = initial_reasoning_effort
        self.agent = verification_agent
        self.store = _artifact_store if _artifact_store is not None else ArtifactStore(workspace)
        self.checkpoints = CheckpointStore(workspace)
        self.progress = progress
        self.chat = chat or call_chat
        self.usage_recorder = usage_recorder
        self.edges = []
        self.edge_contexts = {}
        self.scan_units = {}
        self.checked_edges = set()
        self.prefix_checked = set()
        self.verification = {}
        self._obligation_definitions = {}
        self.edge_obligations = {}
        self._role_counter = 0
        self._compile_counter = 0
        self._latest_role_keys = {}
        self._verification_keys = {}
        self._last_compile_key = ""
        self._last_step_key = ""

    def _chat(self, invocation_key, kind, endpoint, messages, **options):
        def call():
            return self.chat(endpoint, messages, **options)
        if self.usage_recorder is None:
            return call()
        return self.usage_recorder.call(invocation_key, kind, call)

    def _endpoint_identity(self):
        if callable(getattr(self.endpoint, "to_public_dict", None)):
            return self.endpoint.to_public_dict()
        if isinstance(self.endpoint, dict):
            fields = {
                "id", "endpoint_id", "category", "protocol", "base_url", "model",
                "thinking_enabled", "thinking_format", "openai_thinking_format",
                "context_window_tokens", "max_output_tokens",
            }
            return {key: self.endpoint[key] for key in sorted(fields & self.endpoint.keys())}
        return {}

    def _event(self, role, **values):
        if callable(self.progress):
            action = self._role_label(role)
            state = "已完成" if values.get("state") == "completed" else "正在"
            self.progress({"role": role, "message": f"{state}{action}", **values})

    def _role_label(self, role):
        return _ROLE_LABELS.get(role, role)

    def _role_key(self, role, parameters=None):
        _artifact, result_path = _role_paths(role, parameters or {})
        return self._latest_role_keys.get(result_path, "")

    def _control_dependencies(self, role, parameters):
        """记录代码实际放行的前置阶段，不把展示信息加入模型输入。"""
        edge = parameters.get("edge_id") or str(parameters.get("obligation_id") or "").split("-O", 1)[0]
        context = {**parameters, "edge_id": edge}
        predecessors = {
            "tree-builder": ("decomposition-auditor",), "suspicion-scanner": ("tree-auditor",),
            "local-reviewer": ("suspicion-scanner",), "obligation-builder": ("local-reviewer",),
            "check-object-generator": ("obligation-builder",), "numeric-evaluator": ("check-object-generator",),
            "statement-formalizer": ("check-object-generator",), "proof-searcher": ("semantic-checker",),
        }.get(role, ())
        dependencies = [self._role_key(predecessor, context) for predecessor in predecessors]
        if role == "semantic-checker":
            dependencies.append(self._last_compile_key)
        elif role == "evidence-mapper":
            dependencies.extend(key for keys in self._verification_keys.values() for key in keys)
            dependencies.append(self._role_key("suspicion-scanner"))
        return {key for key in dependencies if key}

    def _normalize_proof_graph(self, graph, expected_steps):
        return expand_proof_tree_transport(graph, expected_steps=expected_steps)

    def _parse_proof_graph(self, content, expected_steps):
        return parse_proof_tree(content, expected_steps=expected_steps)

    def _proof_graph_control(self, graph):
        return {"edge_units": [edge["id"] for edge in graph["edges"]],
                "edge_contexts": edge_contexts(graph)}

    def _input_content(self, text):
        return text

    def _agent_files(self, files):
        return files

    def _freeze_agent_images(self):
        return None

    def _score_prompt(self):
        return SCORE_PROMPT

    def _render_role_prompt(self, role, parameters, **options):
        return render_role_prompt(role, parameters, proof_graph_version=self.proof_graph_version, **options)

    def _role_request_context(self, role):
        return {}

    def _allow_function_commentary(self, role):
        return False

    def _allow_result_body(self, role):
        return False

    def _allow_json_repair_after_retry(self, role):
        return False

    def _allow_empty_result_retry(self, role):
        return (type(self.proof_graph_version) is int and self.proof_graph_version == 3
                and type(getattr(self, "node_selection_version", None)) is int
                and self.node_selection_version == 1 and role in IMAGE_ROLE_NAMES and role not in TOOL_ROLES)

    def _stream_empty_result_retry(self, role, key, request, metadata, *, response=None):
        saved = metadata.get("empty_result_retry")
        if saved is None:
            saved = build_empty_result_retry_state(request, response)
            metadata["empty_result_retry"] = saved
            self._save_protocol_diagnostic(role, key + "-empty-result", model_response_diagnostic(response, request["call_options"]),
                                           FaithSieveProtocolError("完整结果函数参数为空，使用一次同输入流式重试"),
                                           chat_result=response)
        validate_empty_result_retry_state(saved, request)
        if saved["state"] == "completed":
            return restore_response(saved["response"])
        if saved["state"] == "endpoint_error":
            raise FaithSieveEndpointError(_ROLE_LABELS[role], metadata.get("endpoint_error"))
        if saved["state"] == "protocol_error":
            raise FaithSieveProtocolError(saved["error"])
        self.checkpoints.put(key, request, state="pending", metadata=metadata)
        retry = saved["retry_request"]
        result = None
        try:
            result = self._chat(key, "empty_result_retry", self.endpoint, retry["messages"],
                               **{"timeout": ROLE_TIMEOUT_SECONDS, **retry["call_options"]})
            saved["response"] = response_snapshot(result)
            if not has_complete_response(result):
                raise FaithSieveProtocolError("空结果流式重试回传没有完整终止信号")
            # HTTP 回传完成不等于角色通过；语法修复和数学校验仍独立执行。
            saved["state"] = "completed"
            self.checkpoints.put(key, request, state="pending", metadata=metadata)
            return result
        except LLMEndpointError:
            saved.update(state="endpoint_error", error="空结果流式重试端点调用失败")
            raise
        except FaithSieveProtocolError as exc:
            saved.update(state="protocol_error", error=str(exc))
            if result is not None:
                self._save_protocol_diagnostic(role, key, model_response_diagnostic(result, retry["call_options"]),
                                               exc, chat_result=result)
            raise

    def _parse_role_model_response(self, role, key, request, metadata, options, response, attempt):
        try:
            return parse_model_result(response, options,
                                      allow_tool_commentary=self._allow_function_commentary(role),
                                      allow_result_body=self._allow_result_body(role)), response
        except FaithSieveJSONSyntaxError as syntax_error:
            if ((attempt and not self._allow_json_repair_after_retry(role)) or not has_complete_response(response)):
                raise
            self._save_protocol_diagnostic(role, key, model_response_diagnostic(response, options), syntax_error,
                                           chat_result=response)
            return self._repair_json(role, key, request, metadata, options, response=response, error=syntax_error)

    def _validate_role_result(self, role, result, parameters):
        pass

    def _validate_role_artifacts(self, role, result, artifacts, control, parameters):
        pass

    def _expected_steps(self, files):
        return step_ids(files.get(STEPS))

    def _model_response_summary(self, response):
        """仅保留结束原因及有效 token 计数，不复制正文或供应商扩展字段。"""
        summary = {}
        finish = getattr(response, "finish_reason", None)
        if isinstance(finish, str):
            finish = finish.encode("utf-8", errors="backslashreplace").decode("utf-8")
            secret = self.endpoint.get("api_key") if isinstance(self.endpoint, dict) else getattr(self.endpoint, "api_key", None)
            if isinstance(secret, str) and secret:
                finish = finish.replace(secret, "<redacted>")
                finish = finish.replace(json.dumps(secret)[1:-1], "<redacted>")
            summary["finish_reason"] = redact_text(finish, max_chars=128)
        usage = getattr(response, "usage", None)
        for field in ("input_tokens", "output_tokens", "total_tokens"):
            value = getattr(usage, field, None)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                summary[field] = value
        return summary

    def _save_protocol_diagnostic(self, role, key, response, error, *, chat_result=None):
        """只保存受限、脱敏的回传诊断，不复制请求、提示词或端点配置。"""
        if isinstance(response, str):
            text = response
        elif isinstance(response, dict):
            try:
                text = json.dumps(response, ensure_ascii=True)
            except (TypeError, ValueError, RecursionError):
                text = "<无法序列化的回传对象>"
        else:
            text = "<非文本或对象回传>"
        text = text.encode("utf-8", errors="backslashreplace").decode("utf-8")
        secret = self.endpoint.get("api_key") if isinstance(self.endpoint, dict) else getattr(self.endpoint, "api_key", None)
        def clean(value, limit):
            if isinstance(secret, str) and secret:
                value = value.replace(secret, "<redacted>")
                value = value.replace(json.dumps(secret)[1:-1], "<redacted>")
            return redact_text(value, max_chars=limit)
        text = clean(text, len(text))
        truncated = len(text) > _DIAGNOSTIC_HEAD_CHARS + _DIAGNOSTIC_TAIL_CHARS
        diagnostic = {
            "schema_version": 1, "invocation_key": key, "role": role,
            "error": clean(str(error), 2048), "response_chars": len(text), "truncated": truncated,
            "response_head": text[:_DIAGNOSTIC_HEAD_CHARS] if truncated else text,
            "response_tail": text[-_DIAGNOSTIC_TAIL_CHARS:] if truncated else "",
        }
        diagnostic.update(self._model_response_summary(chat_result))
        path = self.store.path(f"{WORK}/protocol-diagnostics/{key}.json")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(path, json.dumps(diagnostic, ensure_ascii=False, indent=2).encode("utf-8"))

    def _reasoning_retry_allowed(self, role):
        if role in TOOL_ROLES:
            return False
        endpoint = self.endpoint
        if isinstance(endpoint, dict):
            try:
                endpoint = LLMEndpointSnapshot.from_mapping(endpoint)
            except LLMEndpointValidationError:
                return False
        return isinstance(endpoint, LLMEndpointSnapshot) and endpoint.thinking_enabled

    def _initial_reasoning_options(self, role):
        if self.initial_reasoning_effort is None or not self._reasoning_retry_allowed(role):
            return {}
        return {"reasoning_effort": self.initial_reasoning_effort}

    def _reasoning_retry_metadata(self, role, response):
        text = getattr(response, "text", None)
        finish = getattr(response, "finish_reason", None)
        if (not self._reasoning_retry_allowed(role) or not isinstance(finish, str)
                or finish not in {"max_tokens", "length"}
                or not isinstance(text, str) or text.strip() or getattr(response, "tool_calls", ())):
            return None
        return {"finish_reason": finish, "empty_text": True, "tool_call_count": 0,
                "call_options": {"reasoning_effort": "low"}}

    def _reasoning_retry_options(self, role, metadata):
        if metadata is None:
            return {}
        if (not self._reasoning_retry_allowed(role) or not isinstance(metadata, dict)
                or set(metadata) != {"finish_reason", "empty_text", "tool_call_count", "call_options"}
                or not isinstance(metadata["finish_reason"], str)
                or metadata["finish_reason"] not in {"max_tokens", "length"}
                or metadata["empty_text"] is not True
                or type(metadata["tool_call_count"]) is not int or metadata["tool_call_count"] != 0
                or metadata["call_options"] != {"reasoning_effort": "low"}):
            raise FaithSieveProtocolError("FaithSieve 已保存的思考重试选择无效")
        return dict(metadata["call_options"])

    def _repair_json(self, role, key, request, metadata, options, *, response=None, error=None):
        """同一逻辑角色只修复一次 JSON；重入不重新调用原角色。"""
        saved = metadata.get("json_repair")
        if saved is None:
            if not isinstance(error, FaithSieveJSONSyntaxError) or not has_complete_response(response):
                raise FaithSieveProtocolError("JSON 格式修复只能用于完整回传的语法错误")
            raw = model_result_raw(response, options, allow_tool_commentary=self._allow_function_commentary(role),
                                   allow_result_body=self._allow_result_body(role))
            repair_request = build_repair_request(raw, str(error), self._endpoint_identity(), options)
            saved = {"state": "pending", "raw_response": raw, "parse_error": str(error),
                     "original_finish_reason": response.finish_reason, "request": repair_request}
            metadata["json_repair"] = saved
        validate_repair_state(saved, self._endpoint_identity(), options)
        if saved["state"] == "endpoint_error":
            raise FaithSieveEndpointError(_ROLE_LABELS[role], metadata.get("endpoint_error"))
        if saved["state"] == "protocol_error":
            raise FaithSieveProtocolError(saved.get("error") or "JSON 格式修复未通过")
        if saved["state"] == "completed":
            payload = parse_json_response(saved["repaired_response"], strict_constants=True)
            if "execution" in payload:
                raise FaithSieveProtocolError("FaithSieve 纯模型结果不得自报工具执行证据")
            return payload, None
        self.checkpoints.put(key, request, state="pending", metadata=metadata)
        repaired_response = None
        try:
            content_tokens(saved["raw_response"])  # 歧义原文拒绝，不浪费请求或重做原任务。
            repaired_response = self._chat(
                key, "json_repair", self.endpoint, saved["request"]["messages"],
                **{"timeout": ROLE_TIMEOUT_SECONDS, **saved["request"]["call_options"]},
            )
            payload = parse_model_result(repaired_response, options,
                                         allow_tool_commentary=self._allow_function_commentary(role),
                                         allow_result_body=self._allow_result_body(role))
            if not has_complete_response(repaired_response):
                raise FaithSieveProtocolError("JSON 格式修复回传没有完整终止信号")
            repaired_raw = model_result_raw(repaired_response, options,
                                            allow_tool_commentary=self._allow_function_commentary(role),
                                            allow_result_body=self._allow_result_body(role))
            assert_repair_content_unchanged(saved["raw_response"], repaired_raw)
            saved.update(state="completed", repaired_response=repaired_raw)
            # 修复完成和角色完整校验之间若重入，可恢复原修复正文而不再发请求。
            self.checkpoints.put(key, request, state="pending", metadata=metadata)
            return payload, repaired_response
        except LLMEndpointError as exc:
            metadata["endpoint_error"] = endpoint_error_metadata(exc)
            failure = FaithSieveEndpointError(_ROLE_LABELS[role], metadata["endpoint_error"])
            saved.update(state="endpoint_error", error=str(failure))
            self.checkpoints.put(key, request, state="endpoint_error", error=str(failure), metadata=metadata)
            self._event(role, state="failed", status="failed", message=str(failure))
            raise failure from None
        except FaithSieveProtocolError as exc:
            saved.update(state="protocol_error", error=str(exc))
            if repaired_response is not None:
                self._save_protocol_diagnostic(role, key, model_response_diagnostic(repaired_response, options), exc,
                                               chat_result=repaired_response)
            self.checkpoints.put(key, request, state="protocol_error", error=str(exc), metadata=metadata)
            raise

    def _preserve_frozen_role_prompt(self, key, request, *, original_prompt=None):
        """重放原请求的提示词；其他输入及消息正文仍由本次上下文严格核对。"""
        if self.proof_graph_version not in {2, 3}:
            return request
        try:
            record, _size = self.checkpoints._read_record(key, strict=True)
        except FileNotFoundError:
            return request
        saved = record.get("request") if type(record) is dict else None
        if (type(saved) is not dict or type(saved.get("prompt")) is not str
                or not saved["prompt"].strip()):
            raise FaithSieveProtocolError("FaithSieve 冻结角色提示词无效")
        if original_prompt is not None and saved["prompt"] != original_prompt:
            raise FaithSieveProtocolError("FaithSieve 同一角色重试的冻结职责不一致")
        restored = {**request, "prompt": saved["prompt"]}
        if request["role"] in TOOL_ROLES:
            restored["agent_prompt"] = saved["prompt"] + "\n\n" + input_message(
                request["files"], revision_report=request["revision_report"],
            )
        else:
            restored["messages"] = [{"role": "system", "content": saved["prompt"]},
                                    dict(request["messages"][1])]
        if not strict_equal(saved, restored):
            raise FaithSieveProtocolError("FaithSieve 重入请求与已保存的完整输入不一致")
        return restored

    def _invoke(self, role, *, files, parameters=None, revision_report="", dependency_keys=()):
        parameters = parameters or {}
        artifact, result_path = _role_paths(role, parameters)
        files = dict(files)
        if role in {"decomposition-auditor", "tree-auditor", "semantic-checker", "consistency-auditor"}:
            # 独立复审只读待审核产物及来源；不能在删文件前的输入快照中保留
            # 自己上一轮结论而形成答案锚定。
            files.pop(artifact, None)
            files.pop(result_path, None)
            files.pop(result_path + ".transport.json", None)
        fields = {"status", "artifact", "report"}
        if role == "suspicion-scanner":
            fields.add("focus_unit")
        elif role == "prefix-auditor":
            fields.add("candidate_units")
        elif role == "final-synthesizer":
            fields.add("verdict")
        statuses = _ROLE_STATUSES[role]
        diagnostic_version = getattr(self, "local_diagnostic_version", None)
        projection_version = getattr(self, "result_projection_version", None)
        if role == "verification-auditor" or (role == "local-verifier" and diagnostic_version is not None):
            from .local_diagnostics import LOCAL_DIAGNOSTIC_STATUSES
            fields.add("diagnostics")
            if role == "local-verifier":
                statuses = LOCAL_DIAGNOSTIC_STATUSES
        prompt = self._render_role_prompt(role, parameters)
        legacy_prompt = self._render_role_prompt(role, parameters, legacy_input=True)
        transport_options = {}
        legacy_transport_options = {}
        if role not in TOOL_ROLES:
            legacy_transport_options = result_request_options(
                self.endpoint, fields=fields, statuses=statuses, artifact=artifact,
                proof_graph_version=self.proof_graph_version,
                external_results_version=getattr(self, "external_results_version", None),
            )
            transport_options = dict(legacy_transport_options)
            if role == "tree-builder":
                transport_options.update(tree_stream_request_options(self.endpoint, proof_graph_version=self.proof_graph_version))
                transport_options["timeout"] = ROLE_TIMEOUT_SECONDS
            prompt = model_result_prompt(prompt, transport_options, tree=role == "tree-builder")
        self._role_counter += 1
        call_number = self._role_counter
        initial_options = self._initial_reasoning_options(role)
        call_options = {}
        for attempt in range(2):
            invocation_key = f"role-{call_number:06d}-attempt-{attempt + 1}"
            request = {
                "role": role, "prompt": prompt, "files": files,
                "parameters": parameters, "revision_report": revision_report,
                "expected_result_path": result_path, "endpoint": self._endpoint_identity(),
            }
            if self.proof_graph_version in {2, 3}:
                request["proof_graph_version"] = self.proof_graph_version
            request.update(self._role_request_context(role))
            effort_options = {**initial_options, **call_options}
            actual_options = {**transport_options, **effort_options}
            legacy_actual_options = {**legacy_transport_options, **effort_options}
            if actual_options:
                # 回传格式、工具 schema/choice 和显式强度均冻结，重入不得改变。
                request["call_options"] = actual_options
            legacy_base = {**request, "prompt": legacy_prompt}
            if role in TOOL_ROLES:
                request["agent_prompt"] = prompt + "\n\n" + input_message(files, revision_report=revision_report)
                images = self._freeze_agent_images()
                if images is not None:
                    request["images"] = images
            else:
                request["messages"] = [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": self._input_content(input_message(files, revision_report=revision_report))},
                ]
            legacy_request = dict(legacy_base)
            if effort_options:
                legacy_request["call_options"] = dict(effort_options)
            else:
                legacy_request.pop("call_options", None)
            legacy_requests = [legacy_request]
            if role not in TOOL_ROLES:
                # 旧角色记录没有保存 user 消息，但完整文件和修订意见已冻结；
                # 仅已完成记录可按其原 system/JSON 输入协议只读重放。
                legacy_requests.append({**legacy_base, "prompt": model_result_prompt(legacy_prompt, legacy_transport_options, legacy_result=True),
                                        "call_options": legacy_actual_options})
                # 旧 raw 回传提示只允许已完成缓存只读恢复；完整文件、实际
                # user 消息、端点及调用选项均不改变，未完成记录不能换外层说明。
                legacy_raw_prompt = model_result_prompt(
                    self._render_role_prompt(role, parameters), transport_options, legacy_result=True,
                )
                legacy_raw_request = {
                    **request, "prompt": legacy_raw_prompt,
                    "messages": [{"role": "system", "content": legacy_raw_prompt},
                                 dict(request["messages"][1])],
                }
                legacy_requests.append(legacy_raw_request)
            if role == "tree-builder":
                # 普通请求只允许完整已完成缓存只读恢复，不把 pending 或失败
                # 请求改成新流式调用；实际消息及全部旧选项仍须精确相同。
                legacy_requests.append({**legacy_raw_request, "call_options": legacy_actual_options})
                # 旧 raw 请求完整保存了实际消息，只兼容此前的树传输说明；
                # 文件、修订意见、端点与调用选项仍须逐项相同，未完成记录不能换提示词。
                legacy_tree_prompt = model_result_prompt(
                    self._render_role_prompt(role, parameters, legacy_tree_transport=True), legacy_transport_options,
                    legacy_result=True,
                )
                legacy_requests.append({
                    **request, "prompt": legacy_tree_prompt, "call_options": legacy_actual_options,
                    "messages": [{"role": "system", "content": legacy_tree_prompt},
                                 dict(request["messages"][1])],
                })
            if role not in TOOL_ROLES and "response_format" in transport_options:
                legacy_requests.append({**legacy_base, "prompt": function_result_prompt(legacy_prompt, legacy_result=True),
                                        "call_options": {**result_tool_options(self.endpoint, fields=fields,
                                            statuses=statuses, artifact=artifact,
                                            proof_graph_version=self.proof_graph_version), **effort_options}})
            elif role not in TOOL_ROLES and request["endpoint"].get("protocol") == "openai":
                # 只读重放旧思考模式 JSON 请求；未完成记录仍必须保持原传输。
                json_options = {"response_format": {"type": "json_object"}}
                legacy_requests.append({**legacy_base, "prompt": model_result_prompt(legacy_prompt, json_options, legacy_result=True),
                                        "call_options": {**json_options, **effort_options}})
            if self.proof_graph_version in {2, 3}:
                # 新依赖图任务不得沿用状态树时代的提示词、回传 schema 或调用身份。
                legacy_requests = []
                request = self._preserve_frozen_role_prompt(
                    invocation_key, request, original_prompt=prompt if attempt else None,
                )
                # 同一角色的第二次请求沿用首次冻结的职责，只有强度可以按原协议改变。
                prompt = request["prompt"]
            if role == "node-selector":
                # 回退只能依附精确相同的冻结请求，不能吞掉重入身份错误。
                self._node_selection_request = (invocation_key, request)
            record = self.checkpoints.get(invocation_key, request, completed_legacy_requests=legacy_requests)
            if self.proof_graph_version in {2, 3} and record and not strict_equal(record["request"], request):
                raise FaithSieveProtocolError("证明依赖图重入请求的完整字段或类型不一致")
            if role == "tree-builder":
                validate_tree_stream_request_options(actual_options, proof_graph_version=self.proof_graph_version)
                if record:
                    validate_tree_stream_request_options(record["request"].get("call_options", {}), proof_graph_version=self.proof_graph_version)
            dependencies = self._control_dependencies(role, parameters) | {key for key in dependency_keys if key}
            if attempt:
                dependencies.add(f"role-{call_number:06d}-attempt-{attempt}")
            metadata = {"dependency_keys": sorted(dependencies)}
            if self.proof_graph_version == 3 and role == "local-verifier":
                metadata["node_id"] = parameters["node_id"]
            if record and isinstance(record.get("metadata"), dict) and "empty_result_retry" in record["metadata"]:
                if not self._allow_empty_result_retry(role):
                    raise FaithSieveProtocolError("空结果流式重试不能升级已冻结的角色协议")
                metadata.update(record["metadata"])
                saved_empty = validate_empty_result_retry_state(metadata["empty_result_retry"], request)
                if ((record["state"] == "completed" and saved_empty["state"] != "completed")
                        or (record["state"] == "pending" and saved_empty["state"] not in {"pending", "completed"})
                        or (record["state"] in {"protocol_error", "endpoint_error"}
                            and saved_empty["state"] not in {record["state"], "completed"})):
                    raise FaithSieveProtocolError("空结果流式重试状态与原 checkpoint 不一致")
                actual_options = dict(saved_empty["retry_request"]["call_options"])
            if record and isinstance(record.get("metadata"), dict) and "json_repair" in record["metadata"]:
                allowed_requests = [request, *legacy_requests] if record["state"] == "completed" else [request]
                if not any(strict_equal(record["request"], candidate) for candidate in allowed_requests):
                    raise FaithSieveProtocolError("JSON 格式修复原角色重入请求的字段类型或完整输入不一致")
                metadata.update(record["metadata"])
                validate_repair_state(metadata["json_repair"], self._endpoint_identity(), actual_options)
                if record["state"] != "pending" and metadata["json_repair"]["state"] != record["state"]:
                    raise FaithSieveProtocolError("JSON 格式修复状态与原 checkpoint 终态不一致")
            if not attempt and record and record["state"] == "protocol_error":
                saved_retry = (record.get("metadata") or {}).get("reasoning_retry")
                if saved_retry is not None:
                    self._reasoning_retry_options(role, saved_retry)
                    metadata["reasoning_retry"] = saved_retry
            raw_response, chat_result = None, None
            try:
                if metadata.get("empty_result_retry") is not None and record["state"] in {"protocol_error", "endpoint_error"}:
                    if record["state"] == "endpoint_error":
                        raise FaithSieveEndpointError(_ROLE_LABELS[role], metadata.get("endpoint_error"))
                    raise FaithSieveProtocolError(str(record.get("error") or "空结果流式重试未通过"))
                elif metadata.get("json_repair") is not None and record["state"] != "completed":
                    payload, chat_result = self._repair_json(role, invocation_key, request, metadata, actual_options)
                elif record and record["state"] == "endpoint_error":
                    if not attempt and role not in TOOL_ROLES and role != "node-selector" and getattr(self, "_allow_endpoint_recovery", True):
                        from .recovery import authorize_endpoint_retry
                        if authorize_endpoint_retry(self.store.root, invocation_key, record, request):
                            # 管理员只追加第二次调用；原错误记录及完整请求不修改。
                            continue
                    saved = record.get("metadata")
                    summary = saved.get("endpoint_error") if isinstance(saved, dict) else None
                    raise FaithSieveEndpointError(_ROLE_LABELS[role], summary)
                elif record and record["state"] == "protocol_error":
                    raise FaithSieveProtocolError(str(record.get("error") or "角色回传协议错误"))
                elif record and record["state"] == "completed":
                    # 缓存命中先于清理，重放成功响应恢复本轮可见工件。
                    if metadata.get("empty_result_retry") is not None:
                        if metadata.get("json_repair") is not None:
                            payload, chat_result = self._repair_json(role, invocation_key, request, metadata, actual_options)
                        else:
                            response = restore_response(metadata["empty_result_retry"]["response"])
                            payload = parse_model_result(response, actual_options,
                                                         allow_tool_commentary=self._allow_function_commentary(role),
                                                         allow_result_body=self._allow_result_body(role))
                    else:
                        payload = record.get("response")
                elif metadata.get("empty_result_retry") is not None:
                    response = self._stream_empty_result_retry(role, invocation_key, request, metadata)
                    raw_response, chat_result = model_response_diagnostic(response, actual_options), response
                    payload, chat_result = self._parse_role_model_response(
                        role, invocation_key, request, metadata, actual_options, response, attempt)
                else:
                    # 原流程要求真正重试先删除原 result/outputs；已完成缓存不可删除。
                    self.store.remove(result_path)
                    self.store.remove(artifact)
                    if role == "obligation-builder":
                        folder = self.store.path(artifact).parent
                        if folder.exists():
                            for path in folder.glob("*.md"):
                                self.store.remove(path.relative_to(self.store.root).as_posix())
                    self.checkpoints.put(invocation_key, request, state="pending", metadata=metadata)
                    self._event(role, state="running", attempt=attempt + 1, **parameters)
                    if role in TOOL_ROLES:
                        # pending 由 adapter 抛出并原样透出；宿主立即 retry 释放 worker。
                        payload = self.agent.run_role(
                            role=role,
                            prompt=request["agent_prompt"],
                            files=self._agent_files(files),
                            expected_result_path=result_path,
                            invocation_key=invocation_key,
                            **({"proof_graph_version": self.proof_graph_version} if self.proof_graph_version in {2, 3} else {}),
                            **({"local_diagnostic_version": diagnostic_version}
                               if role == "local-verifier" and diagnostic_version is not None else {}),
                            **({"result_projection_version": projection_version}
                               if role == "local-verifier" and projection_version is not None else {}),
                            **({"external_results_version": self.external_results_version}
                               if role == "local-verifier" and getattr(self, "external_results_version", None) is not None else {}),
                        )
                        raw_response = payload
                    else:
                        response = self._chat(
                            invocation_key, "role", self.endpoint,
                            request["messages"],
                            **{"timeout": ROLE_TIMEOUT_SECONDS, **actual_options},
                        )
                        if self._allow_empty_result_retry(role) and empty_result_response(response, actual_options) is not None:
                            response = self._stream_empty_result_retry(role, invocation_key, request, metadata, response=response)
                            actual_options = dict(metadata["empty_result_retry"]["retry_request"]["call_options"])
                        raw_response, chat_result = model_response_diagnostic(response, actual_options), response
                        payload, chat_result = self._parse_role_model_response(
                            role, invocation_key, request, metadata, actual_options, response, attempt)
                payload = parse_json_response(payload)
                if projection_version is not None:
                    payload, ignored_metadata = project_role_result(payload, fields)
                    if ignored_metadata:
                        # 只隔离 result 未声明的附加字段；工件与数学控制仍严格验证。
                        metadata["ignored_result_metadata"] = ignored_metadata

                def allowed_output(path):
                    if role == "obligation-builder":
                        prefix = f"{WORK}/obligations/{parameters['edge_id']}/"
                        return path == artifact or (
                            path.startswith(prefix)
                            and re.fullmatch(rf"{parameters['edge_id']}-O[1-9][0-9]*\.md", path.removeprefix(prefix))
                        )
                    if self.proof_graph_version == 1 and role == "numeric-evaluator" and path == result_path + ".expressions.json":
                        return True
                    return path == artifact

                result, artifacts, control = validate_role_response(
                    payload,
                    fields=fields,
                    statuses=statuses,
                    expected_artifact=artifact,
                    allowed_outputs=allowed_output,
                    structured_outputs={TREE} if role == "tree-builder" else (),
                    structured_normalizers={TREE: lambda tree: self._normalize_proof_graph(
                        tree, self._expected_steps(files)
                    )} if role == "tree-builder" else None,
                )
                self._validate_role_result(role, result, parameters)
                self._validate_role_artifacts(role, result, artifacts, control, parameters)
                if role == "tree-builder":
                    # 错误 JSON 不能写入工件，也不能先发布为已完成检查点。
                    tree = self._parse_proof_graph(artifacts[TREE], self._expected_steps(files))
                    if control and not (record and record["state"] == "completed"):
                        raise FaithSieveProtocolError("证明图的 control 必须为空，验证上下文由代码生成")
                    control = self._proof_graph_control(tree)
                execution = payload.get("execution", {})
                if not isinstance(execution, dict):
                    raise FaithSieveProtocolError("FaithSieve 工具执行记录无效")
                completed = {"result": result, "artifacts": artifacts, "control": control, "execution": execution}
                if (record and record["state"] == "completed" and metadata.get("empty_result_retry") is not None
                        and not strict_equal(completed, record.get("response"))):
                    raise FaithSieveProtocolError("空结果流式重试实际回传与完成 checkpoint 不一致")
                if not record or record["state"] != "completed":
                    metadata.update(self._model_response_summary(chat_result))
                    self.checkpoints.put(invocation_key, request, state="completed", response=completed, metadata=metadata)
                for path, content in artifacts.items():
                    self.store.write(path, content)
                self.store.write_json(result_path, result)
                # 每个阶段实际重新读取 JSON，而不是信任上一请求的对话摘要。
                result = self.store.read_json(result_path)
                self.store.write_json(result_path + ".transport.json", {
                    "control": control, "execution": execution,
                })
                self._event(role, state="completed", status=result["status"], **parameters)
                self._latest_role_keys[result_path] = invocation_key
                self._last_step_key = invocation_key
                return RoleOutput(result, control, execution, invocation_key)
            except LLMEndpointError as exc:
                metadata["endpoint_error"] = endpoint_error_metadata(exc)
                failure = FaithSieveEndpointError(_ROLE_LABELS[role], metadata["endpoint_error"])
                self.checkpoints.put(invocation_key, request, state="endpoint_error", error=str(failure), metadata=metadata)
                self._event(role, state="failed", status="failed", message=str(failure), **parameters)
                raise failure from None
            except FaithSieveProtocolError as exc:
                if raw_response is not None:
                    self._save_protocol_diagnostic(role, invocation_key, raw_response, exc, chat_result=chat_result)
                self.store.remove(result_path)
                if record and record["state"] == "completed":
                    raise
                if metadata.get("json_repair") is not None:
                    metadata["json_repair"].update(state="protocol_error", error=str(exc))
                    if not record or record["state"] == "pending":
                        self.checkpoints.put(invocation_key, request, state="protocol_error", error=str(exc), metadata=metadata)
                    raise  # 修复已占用第二次机会，绝不再生成原角色任务。
                if metadata.get("empty_result_retry") is not None:
                    if not record or record["state"] == "pending":
                        self.checkpoints.put(invocation_key, request, state="protocol_error", error=str(exc), metadata=metadata)
                    raise  # 流式回退只能使用一次，不能再重做原角色。
                if not attempt and chat_result is not None:
                    retry = self._reasoning_retry_metadata(role, chat_result)
                    if retry is not None:
                        metadata["reasoning_retry"] = retry
                if not record or record["state"] == "pending":
                    self.checkpoints.put(invocation_key, request, state="protocol_error", error=str(exc), metadata=metadata)
                if attempt or role == "node-selector" or (self.proof_graph_version == 3 and role == "local-verifier"):
                    raise
                # 缓存 protocol_error 时没有 chat_result，必须恢复当时已保存的选择。
                call_options = self._reasoning_retry_options(role, metadata.get("reasoning_retry"))
                revision_report = str(exc)
        raise FaithSieveProtocolError("FaithSieve 角色回传无效")

    def _files(self, *paths):
        return self.store.bundle(paths)

    def _source_files(self):
        return self._files("problem.md", SOURCE)

    def _audit_pair(self, generator, auditor, *, generator_files, auditor_files,
                    revision_report="", dependency_keys=()):
        generated = self._invoke(generator, files=generator_files(), revision_report=revision_report,
                                 dependency_keys=dependency_keys)
        if generated.result["status"] == "inconclusive":
            raise _Inconclusive(generated.result["report"])
        for revision in range(GENERATOR_REVISION_LIMIT + 1):
            audit = self._invoke(auditor, files=auditor_files())
            if audit.result["status"] == "ok":
                return generated
            if audit.result["status"] != "needs_revision" or revision == GENERATOR_REVISION_LIMIT:
                raise _Inconclusive(audit.result["report"])
            artifact, _result_path = _role_paths(generator, {})
            # 修订保留上一版全文，但换成只读参考路径，避免与本轮输出冲突。
            suffix = artifact.rsplit(".", 1)[-1]
            files = dict(generator_files())
            files.pop(artifact, None)
            files[f"{WORK}/reference/{generator}-previous.{suffix}"] = self.store.read(artifact)
            generated = self._invoke(
                generator,
                files=files,
                revision_report=audit.result["report"] + "\n" + self.store.read(audit.result["artifact"]),
                dependency_keys=(audit.key,),
            )
            if generated.result["status"] == "inconclusive":
                raise _Inconclusive(generated.result["report"])
        raise _Inconclusive("独立审计仍未通过")

    def _read_edges(self, output):
        tree = parse_proof_tree(self.store.read(TREE), expected_steps=step_ids(self.store.read(STEPS)))
        self.edge_contexts = edge_contexts(tree)
        return [edge["id"] for edge in tree["edges"]]

    def _scan_window(self, output):
        if output.result["status"] != "ok":
            raise _Inconclusive(output.result["report"])
        units = output.control.get("units")
        if not isinstance(units, list) or [unit.get("edge_id") for unit in units if isinstance(unit, dict)] != self.edges:
            raise FaithSieveProtocolError("风险扫描未完整覆盖全部 EdgeUnit")
        for unit in units:
            suspicion = unit.get("suspicion")
            if (
                isinstance(suspicion, bool)
                or not isinstance(suspicion, (int, float))
                or not math.isfinite(suspicion)
                or not 0 <= suspicion <= 1
                or not isinstance(unit.get("uncertain"), bool)
                or not isinstance(unit.get("reason"), str)
                or not unit["reason"].strip()
            ):
                raise FaithSieveProtocolError("风险扫描流程数据无效")
        self.scan_units = {unit["edge_id"]: unit for unit in units}
        focus = next((unit["edge_id"] for unit in units if unit["suspicion"] > 0.6), None)
        if output.result.get("focus_unit") != focus:
            raise FaithSieveProtocolError("风险扫描没有选择最早超过 0.6 的 EdgeUnit")
        if focus:
            index = self.edges.index(focus)
            return self.edges[max(0, index - 6):index + 1]
        return [unit["edge_id"] for unit in units if unit["uncertain"]]

    def _edge_context(self, edge, window=None):
        files = self._files("problem.md", SOURCE, f"{WORK}/review/{edge}.md")
        window = window or [edge]
        files[TREE] = json.dumps({"schema_version": 1, "edge_contexts": [self.edge_contexts[item] for item in window]}, ensure_ascii=False)
        return files

    def _window_files(self, window):
        steps = self.store.read(STEPS)
        matches = list(re.finditer(r"(?m)^##\s+(S[1-9][0-9]*)\b[^\n]*$", steps))
        if not matches:
            raise FaithSieveProtocolError("证明拆分缺少可忠实截取的稳定步骤标题")
        selected_steps = {"S" + edge[1:] for edge in window}
        excerpts = [steps[:matches[0].start()]]
        found = set()
        for index, match in enumerate(matches):
            if match.group(1) in selected_steps:
                end = matches[index + 1].start() if index + 1 < len(matches) else len(steps)
                excerpts.append(steps[match.start():end])
                found.add(match.group(1))
        if found != selected_steps:
            raise FaithSieveProtocolError("证明窗口无法完整映射回学生步骤")
        scan_lines = self.store.read(SCAN).splitlines()
        selected_scan = []
        for line in scan_lines:
            ids = set(re.findall(r"\bE[1-9][0-9]*\b", line))
            if (ids and ids.issubset(set(window))) or (line.startswith("|") and not ids and not selected_scan):
                selected_scan.append(line)
        return {STEPS: "\n\n".join(excerpts), SCAN: "\n".join(selected_scan)}

    def _obligation_context(self, obligation, path, *, include_review=True):
        edge = obligation.split("-O", 1)[0]
        files = self._edge_context(edge)
        if not include_review:
            files.pop(f"{WORK}/review/{edge}.md", None)
        files.update(self._files(path, f"{WORK}/formal/{obligation}-check.md"))
        dependencies = self._obligation_definitions.get(obligation, {}).get("depends_on", ())
        pending, included = list(reversed(dependencies)), set()
        while pending:
            dependency = pending.pop()
            if dependency in included:
                continue
            definition = self._obligation_definitions.get(dependency)
            verified = self.verification.get(dependency, {})
            if definition is None or verified.get("status") != "passed":
                raise FaithSieveProtocolError("依赖义务缺少已通过的来源与验证证据")
            verification_path = f"{WORK}/formal/{dependency}-verification.json"
            if self.store.read_json(verification_path) != verified:
                raise FaithSieveProtocolError("依赖义务的验证工件与实际结果不一致")
            evidence_paths = [definition["path"], verification_path]
            for field, suffix in (
                ("statement", "original-statement.lean"),
                ("semantic_audit", "original-semantics.md"),
            ):
                if field in verified:
                    expected = f"{WORK}/formal/{dependency}-{suffix}"
                    if verified[field] != expected:
                        raise FaithSieveProtocolError("依赖义务的语义证据路径不一致")
                    evidence_paths.append(expected)
            if verified.get("route") == "numeric":
                expected = f"{WORK}/formal/{dependency}-numeric.md"
                if verified.get("artifact") != expected:
                    raise FaithSieveProtocolError("依赖义务的数值证据路径不一致")
                evidence_paths.append(expected)
            for evidence_path in evidence_paths:
                files[evidence_path] = self.store.read(evidence_path)
            included.add(dependency)
            pending.extend(reversed(definition["depends_on"]))
        return files

    def _read_obligations(self, edge, output):
        obligations = output.control.get("obligations")
        if not isinstance(obligations, list) or not obligations:
            raise FaithSieveProtocolError("证明转换未回传最小义务清单")
        previous = set()
        index_text = self.store.read(output.result["artifact"])
        for number, obligation in enumerate(obligations, 1):
            if not isinstance(obligation, dict) or set(obligation) != {"id", "path", "depends_on"}:
                raise FaithSieveProtocolError("数学义务流程数据无效")
            expected_id = f"{edge}-O{number}"
            expected_path = f"{WORK}/obligations/{edge}/{expected_id}.md"
            dependencies = obligation["depends_on"]
            if (
                obligation["id"] != expected_id
                or obligation["path"] != expected_path
                or not isinstance(dependencies, list)
                or any(not isinstance(item, str) or item not in previous for item in dependencies)
                or expected_path not in index_text
                or not self.store.path(expected_path).is_file()
            ):
                raise FaithSieveProtocolError("数学义务 ID、路径或依赖顺序无效")
            previous.add(expected_id)
        expected_paths = {item["path"] for item in obligations}
        folder = self.store.path(output.result["artifact"]).parent
        actual_paths = {
            file.relative_to(self.store.root).as_posix() for file in folder.glob("*.md")
            if file.name != "index.md"
            and (self.store.visible_paths is None or file.relative_to(self.store.root).as_posix() in self.store.visible_paths)
        }
        indexed_paths = set(re.findall(r"faithsieve-work/obligations/E[1-9][0-9]*/E[1-9][0-9]*-O[1-9][0-9]*\.md", index_text))
        if actual_paths != expected_paths or indexed_paths != expected_paths:
            raise FaithSieveProtocolError("数学义务清单与全部输出工件不一致")
        self._obligation_definitions.update({
            item["id"]: {"path": item["path"], "depends_on": tuple(item["depends_on"])}
            for item in obligations
        })
        return obligations

    def _record_verification(self, obligation, *, status, dependency_keys=None, **values):
        record = {"status": status, **values}
        self.verification[obligation] = record
        self._verification_keys[obligation] = tuple(key for key in (dependency_keys if dependency_keys is not None else (self._last_step_key,)) if key)
        self.store.write_json(f"{WORK}/formal/{obligation}-verification.json", record)
        return status

    def _compile(self, files, path, *, diagnostics_path):
        self._compile_counter += 1
        key = f"compile-{self._compile_counter:06d}"
        request = {"files": files, "statement_path": path}
        if self.proof_graph_version == 2:
            request["proof_graph_version"] = 2
        metadata = {"role": "lean-compiler", "diagnostics_path": diagnostics_path}
        record = self.checkpoints.get(key, request)
        if self.proof_graph_version == 2 and record and not strict_equal(record["request"], request):
            raise FaithSieveProtocolError("依赖图 Lean 编译请求的完整字段或类型不一致")
        if record and record["state"] == "completed":
            compiled = record.get("response")
        else:
            self.checkpoints.put(key, request, state="pending", metadata=metadata)
            compiled = self.agent.compile_lean(files=files, statement_path=path)
        if not isinstance(compiled, dict) or isinstance(compiled.get("exit_code"), bool) or not isinstance(compiled.get("exit_code"), int):
            raise FaithSieveProtocolError("Lean 独立编译未返回实际退出码")
        if not record or record["state"] != "completed":
            self.checkpoints.put(key, request, state="completed", response=compiled, metadata=metadata)
        diagnostics = str(compiled.get("diagnostics") or "")
        self._last_compile_key = key
        self._last_step_key = key
        self.store.write(diagnostics_path, diagnostics)
        return compiled["exit_code"] == 0, diagnostics

    def _verify_lean_branch(self, obligation, path, branch, *, dependency_keys=()):
        statement_path = f"{WORK}/formal/{obligation}-{branch}-statement.lean"
        previous_statement_path = f"{WORK}/formal/{obligation}-{branch}-previous-statement.lean"
        diagnostics_path = f"{WORK}/formal/{obligation}-{branch}-diagnostics.txt"
        semantics_path = f"{WORK}/formal/{obligation}-{branch}-semantics.md"
        proof_path = f"{WORK}/formal/{obligation}-{branch}-proof.lean"
        parameters = {
            "obligation_id": obligation,
            "obligation_path": path,
            "check_object_path": f"{WORK}/formal/{obligation}-check.md",
            "branch": branch,
            "statement_path": statement_path,
            "diagnostics_path": diagnostics_path,
            "semantic_report_path": semantics_path,
            "branch_statement_path": statement_path,
            "proof_path": proof_path,
        }
        self.store.write(diagnostics_path, "")
        revision_report = ""
        revision_key = ""
        for _revision in range(FORMAL_REVISION_LIMIT):
            files = self._obligation_context(obligation, path)
            files.update(self._files(diagnostics_path))
            previous = self._files(statement_path)
            if statement_path in previous:
                # 前稿是只读参考；不能将需要修订的输出路径同时登记为
                # Judge 的不可变输入，否则合法改稿也会被判为篡改材料。
                files[previous_statement_path] = previous[statement_path]
            if branch != "original":
                files.update(self._files(f"{WORK}/formal/{obligation}-original-statement.lean"))
            formalized = self._invoke(
                "statement-formalizer", files=files, parameters=parameters, revision_report=revision_report,
                dependency_keys=(*dependency_keys, revision_key),
            )
            if formalized.result["status"] != "ok":
                return {"status": "inconclusive", "branch": branch, "report": formalized.result["report"]}
            statement = self.store.read(statement_path)
            try:
                statement_tokens = lean_tokens(statement)
            except LeanSourceError as error:
                return {"status": "inconclusive", "branch": branch, "report": str(error)}
            if contains_forbidden_lean(statement_tokens):
                return {"status": "inconclusive", "branch": branch, "report": "Lean statement 含禁用占位或公理"}
            compiled, diagnostics = self._compile(
                self._files(statement_path), statement_path, diagnostics_path=diagnostics_path,
            )
            if not compiled:
                revision_report = "独立 Lean 编译失败，请按 diagnostics 修订。\n" + diagnostics
                revision_key = self._last_compile_key
                continue
            semantic_files = self._obligation_context(obligation, path, include_review=False)
            semantic_files.update(self._files(statement_path))
            if branch != "original":
                semantic_files.update(self._files(f"{WORK}/formal/{obligation}-original-statement.lean"))
            semantic = self._invoke("semantic-checker", files=semantic_files, parameters=parameters)
            if semantic.result["status"] == "needs_revision":
                revision_report = semantic.result["report"] + "\n" + self.store.read(semantics_path)
                revision_key = semantic.key
                continue
            if semantic.result["status"] != "ok":
                return {"status": "inconclusive", "branch": branch, "report": semantic.result["report"]}
            # 独立语义审计通过后，搜索者只能读固定 statement，不见其他验证分支。
            proof_files = self._obligation_context(obligation, path, include_review=False)
            proof_files.update(self._files(statement_path))
            proof = self._invoke("proof-searcher", files=proof_files, parameters=parameters)
            if self.store.read(statement_path) != statement:
                raise FaithSieveProtocolError("证明搜索修改了已审计 statement")
            proof_text = self.store.read(proof_path)
            expected_status = "passed" if branch == "original" else "refuted"
            if proof.result["status"] == "inconclusive":
                return {"status": "inconclusive", "branch": branch, "report": proof.result["report"]}
            if proof.result["status"] != expected_status:
                raise FaithSieveProtocolError("证明搜索状态与指定 branch 不一致")
            if not proof_text.startswith(statement):
                return {"status": "inconclusive", "branch": branch, "report": "证明文件改变了命题或包含禁用占位"}
            appended = proof_text[len(statement):]
            try:
                proof_tokens = lean_tokens(proof_text)
                appended_tokens = lean_tokens(appended)
            except LeanSourceError as error:
                return {"status": "inconclusive", "branch": branch, "report": str(error)}
            if contains_forbidden_lean(proof_tokens):
                return {"status": "inconclusive", "branch": branch, "report": "证明文件改变了命题或包含禁用占位"}
            # 注释不参与声明识别；类型必须仍是已审计文件中的唯一 Prop。
            if not is_fixed_proof_appendix(appended_tokens, statement_prop_name(statement_tokens)):
                return {"status": "inconclusive", "branch": branch, "report": "证明文件未仅追加已审计同一 Prop 的 FaithSieveProof"}
            compiled, diagnostics = self._compile(
                self._files(proof_path), proof_path,
                diagnostics_path=f"{WORK}/formal/{obligation}-{branch}-proof-diagnostics.txt",
            )
            if compiled:
                return {
                    "status": expected_status, "route": "lean", "branch": branch,
                    "artifact": proof_path, "statement": statement_path,
                    "semantic_audit": semantics_path, "statement_compiled": True,
                    "proof_compiled": True, "no_placeholders": True,
                    "report": proof.result["report"],
                }
            return {"status": "inconclusive", "branch": branch, "report": "独立 Lean proof 编译失败：" + diagnostics}
        return {"status": "inconclusive", "branch": branch, "report": "形式化编译或语义修订达到任务限制"}

    def _verify_obligation(self, obligation):
        identifier, path = obligation["id"], obligation["path"]
        dependencies = obligation["depends_on"]
        dependency_keys = tuple(key for item in dependencies for key in self._verification_keys.get(item, ()))
        if any(self.verification.get(item, {}).get("status") != "passed" for item in dependencies):
            return self._record_verification(
                identifier, status="inconclusive", report="前置义务未通过，不能提前使用新事实", depends_on=dependencies,
                dependency_keys=(*dependency_keys, self._role_key("obligation-builder", {"edge_id": identifier.split("-O", 1)[0]})),
            )
        parameters = {
            "obligation_id": identifier, "obligation_path": path,
            "check_object_path": f"{WORK}/formal/{identifier}-check.md",
            "numeric_result_path": f"{WORK}/formal/{identifier}-numeric.md",
        }
        check = self._invoke(
            "check-object-generator", files=self._obligation_context(identifier, path), parameters=parameters,
            dependency_keys=dependency_keys,
        )
        if check.result["status"] != "ok":
            return self._record_verification(identifier, status="inconclusive", report=check.result["report"])
        route = _check_object_route(
            self.store.read(parameters["check_object_path"]), check.control.get("route"),
        )
        if route == "numeric":
            evaluated = self._invoke(
                "numeric-evaluator", files=self._obligation_context(identifier, path), parameters=parameters,
            )
            status = self._numeric_status(evaluated)
            return self._record_verification(
                identifier, status=status, route="numeric", artifact=evaluated.result["artifact"],
                **self._numeric_verification_metadata(evaluated), report=evaluated.result["report"],
            )
        branches = []
        previous_branch_key = ""
        for branch in ("original", "negation", "counterexample"):
            verified = self._verify_lean_branch(identifier, path, branch, dependency_keys=(previous_branch_key,))
            branches.append(verified)
            previous_branch_key = self._last_step_key
            if verified["status"] in {"passed", "refuted"}:
                return self._record_verification(identifier, **verified)
        return self._record_verification(identifier, status="inconclusive", route="lean", branches=branches, report="所有验证分支均未得到可靠证据")

    def _numeric_status(self, evaluated):
        verified = evaluated.execution.get("verified") is True and evaluated.execution.get("exit_code") == 0
        return evaluated.result["status"] if verified else "inconclusive"

    def _numeric_verification_metadata(self, evaluated):
        return {"tool_verified": evaluated.execution.get("verified") is True and evaluated.execution.get("exit_code") == 0}

    def _check_window(self, window, *, force_units=(), dependency_keys=()):
        # 每条边先独立 local review，然后生成义务，不能将其他 reviewer 的结论
        # 提前放进该角色上下文；互不依赖的角色可由任务宿主并行扩展。
        pending = [edge for edge in window if edge not in self.checked_edges or edge in force_units]
        previous_passed = {}
        for edge in pending:
            for identifier in self.edge_obligations.get(edge, []):
                record = self.verification.get(identifier, {})
                if record.get("status") == "passed":
                    path = f"{WORK}/obligations/{edge}/{identifier}.md"
                    previous_passed[identifier] = (self.store.read(path), record)
        reviews = {}
        for edge in pending:
            review_files = {
                **self._edge_context(edge, window),
                **self._window_files(window),
            }
            review_files.pop(f"{WORK}/review/{edge}.md", None)
            review = self._invoke(
                "local-reviewer", files=review_files,
                parameters={"edge_id": edge, "window": json.dumps(window, ensure_ascii=False)},
                dependency_keys=dependency_keys,
            )
            outcome = review.control.get("review_outcome")
            if review.result["status"] == "ok" and (
                outcome not in {"supported", "suspect", "uncertain"}
                or not re.search(rf"review_outcome\s*:\s*{outcome}\b", self.store.read(review.result["artifact"]))
            ):
                raise FaithSieveProtocolError("局部复核结论与原工件不一致")
            reviews[edge] = review
        for edge in pending:
            review = reviews[edge]
            self.checked_edges.add(edge)
            if review.result["status"] != "ok":
                self.edge_obligations[edge] = []
                continue
            built = self._invoke("obligation-builder", files=self._edge_context(edge), parameters={"edge_id": edge})
            if built.result["status"] != "ok":
                self.edge_obligations[edge] = []
                continue
            obligations = self._read_obligations(edge, built)
            self.edge_obligations[edge] = [obligation["id"] for obligation in obligations]
            for obligation in obligations:
                identifier = obligation["id"]
                prior = previous_passed.get(identifier)
                if prior and self.store.read(obligation["path"]) == prior[0]:
                    # 已可靠通过且原义务未改变的证据继续使用，不重复搜索。
                    self.verification[identifier] = prior[1]
                    continue
                if edge in force_units:
                    self.verification.pop(identifier, None)
                    for path in self.store.path(f"{WORK}/formal/{identifier}-verification.json").parent.glob(f"{identifier}-*"):
                        if path.is_file():
                            self.store.remove(path.relative_to(self.store.root).as_posix())
                self._verify_obligation(obligation)

    def _edge_status(self, edge):
        ids = self.edge_obligations.get(edge)
        if ids:
            statuses = [self.verification.get(item, {}).get("status", "inconclusive") for item in ids]
            if "refuted" in statuses:
                return "refuted"
            if all(status == "passed" for status in statuses):
                return "passed"
            return "inconclusive"
        scan = self.scan_units[edge]
        if edge not in self.checked_edges and scan["suspicion"] <= 0.6 and not scan["uncertain"]:
            # 低风险自然语言覆盖不是形式化 passed。
            return "low_risk"
        return "inconclusive"

    def _map_evidence(self):
        files = self.store.bundle(
            (STEPS, TREE, PREFIX),
            prefixes=(f"{WORK}/review", f"{WORK}/obligations", f"{WORK}/formal"),
        )
        # 独立编译/数值核验由主编排落盘，mapper只能依据这些现有证据。
        output = self._invoke("evidence-mapper", files=files)
        if output.result["status"] != "ok":
            raise _Inconclusive(output.result["report"])
        units = output.control.get("units")
        if not isinstance(units, list) or [unit.get("edge_id") for unit in units if isinstance(unit, dict)] != self.edges:
            raise FaithSieveProtocolError("证据映射未完整覆盖全部 EdgeUnit")
        for unit in units:
            expected = self._edge_status(unit["edge_id"])
            if unit.get("status") not in {"passed", "refuted", "inconclusive"} or (
                unit["status"] == "refuted" and expected != "refuted"
            ) or (unit["status"] == "passed" and expected != "passed"):
                raise FaithSieveProtocolError("证据映射把未独立核验的结论当成数学证据")
        earliest = next((edge for edge in self.edges if self._edge_status(edge) == "refuted"), None)
        prefix = [edge for edge in self.edges[:self.edges.index(earliest)] if self._edge_status(edge) == "inconclusive"] if earliest else []
        if output.control.get("provisional_error_unit") != earliest or output.control.get("prefix_units") != prefix:
            raise FaithSieveProtocolError("证据映射首错或不确定前缀与可靠证据不一致")
        return earliest, prefix

    def _prefix_check(self, earliest, prefix):
        if not earliest:
            return
        # 每次只检查暂定错误之前的新候选；最多全部边一次，避免重复循环。
        for _iteration in range(len(self.edges) + 1):
            output = self._invoke(
                "prefix-auditor", files=self._files(SOURCE, STEPS, TREE, EVIDENCE),
                parameters={"provisional_error_unit": earliest, "prefix_units": json.dumps(prefix, ensure_ascii=False)},
            )
            if output.result["status"] != "ok":
                raise _Inconclusive(output.result["report"])
            candidates = output.result.get("candidate_units")
            if not isinstance(candidates, list) or any(
                not isinstance(edge, str) or edge not in prefix for edge in candidates
            ) or len(candidates) != len(set(candidates)) or candidates != [edge for edge in prefix if edge in candidates]:
                raise FaithSieveProtocolError("前缀审计返回了范围之外或顺序错误的候选")
            candidates = [edge for edge in candidates if edge not in self.prefix_checked]
            if candidates:
                self.prefix_checked.update(candidates)
                first, last = self.edges.index(candidates[0]), self.edges.index(candidates[-1])
                window = self.edges[max(0, first - 6):last + 1]
                # 审计明确选中的旧 inconclusive 必须实际补查，不能因已局部看过
                # 就直接跳过；同一前缀边最多补查一次，可靠 passed 不重做。
                extra = {"dependency_keys": (output.key,)} if output.key else {}
                self._check_window(window, force_units=set(candidates), **extra)
            new_earliest, new_prefix = self._map_evidence()
            if new_earliest == earliest or not candidates:
                return
            earliest, prefix = new_earliest, new_prefix
        raise _Inconclusive("首错前缀复查未能收敛")

    def _final_files(self):
        return self.store.bundle(
            ("problem.md", SOURCE, STEPS, TREE, SCAN, EVIDENCE, PREFIX),
            prefixes=(f"{WORK}/review", f"{WORK}/obligations", f"{WORK}/formal"),
        )

    def _synthesize(self):
        final = self._invoke("final-synthesizer", files=self._final_files())
        for revision in range(2):
            if final.result["status"] != "ok" or final.result.get("verdict") not in {"correct", "incorrect", "inconclusive"}:
                raise _Inconclusive(final.result["report"])
            verdict = final.result["verdict"]
            statuses = {edge: self._edge_status(edge) for edge in self.edges}
            if verdict == "correct" and any(status not in {"passed", "low_risk"} for status in statuses.values()):
                raise _Inconclusive("存在未解决的数学义务或缺少明确覆盖的证明步骤，不能认证整份证明")
            earliest = next((edge for edge, status in statuses.items() if status == "refuted"), None)
            if verdict == "incorrect" and not earliest:
                raise _Inconclusive("没有忠实检查对象上的可靠反证，不能将怀疑或工具失败判为学生错误")
            audit_files = self._final_files()
            audit_files.update(self._files(FINAL))
            audited = self._invoke("consistency-auditor", files=audit_files)
            if audited.result["status"] == "ok":
                return verdict
            if audited.result["status"] != "needs_revision" or revision:
                raise _Inconclusive(audited.result["report"])
            final = self._invoke(
                "final-synthesizer", files=self._final_files(),
                revision_report=audited.result["report"] + "\n" + self.store.read(audited.result["artifact"]),
            )
        raise _Inconclusive("最终结论独立审计仍未通过")

    def _score_files(self):
        return self._files("problem.md", SOURCE, STEPS, TREE, EVIDENCE, FINAL, f"{WORK}/review/final.md")

    def _score(self, verdict):
        self._event("scoring", state="running")
        files = self._score_files()
        user_message = self._input_content(input_message(files, approved_verdict=verdict))
        legacy_messages = [
            {"role": "system", "content": LEGACY_SCORE_PROMPT},
            {"role": "user", "content": legacy_json_input_message(files, approved_verdict=verdict)},
        ]
        initial_options = self._initial_reasoning_options("scoring")
        call_options = {**result_request_options(self.endpoint, scoring=True, proof_graph_version=self.proof_graph_version), **initial_options}
        messages = [{"role": "system", "content": model_result_prompt(self._score_prompt(), call_options, scoring=True)},
                    {"role": "user", "content": user_message}]
        request = {"messages": messages, "files": files,
                   "endpoint": self._endpoint_identity(), "call_options": call_options}
        if self.proof_graph_version in {2, 3}:
            request["proof_graph_version"] = self.proof_graph_version
        request.update(self._role_request_context("scoring"))
        legacy_request = {"messages": legacy_messages, "endpoint": self._endpoint_identity()}
        if initial_options:
            legacy_request["call_options"] = dict(initial_options)
        legacy_requests = [legacy_request]
        legacy_requests.append({"messages": [{**legacy_messages[0], "content": model_result_prompt(LEGACY_SCORE_PROMPT, call_options, legacy_result=True)},
                                              legacy_messages[1]], "endpoint": self._endpoint_identity(),
                                "call_options": call_options})
        if "response_format" in call_options:
            legacy_requests.append({"messages": [{**legacy_messages[0], "content": function_result_prompt(LEGACY_SCORE_PROMPT, legacy_result=True)},
                                                 legacy_messages[1]], "endpoint": self._endpoint_identity(),
                                    "call_options": {**result_tool_options(self.endpoint, scoring=True, proof_graph_version=self.proof_graph_version), **initial_options}})
        elif request["endpoint"].get("protocol") == "openai":
            json_options = {"response_format": {"type": "json_object"}}
            legacy_requests.append({"messages": [{**legacy_messages[0], "content": model_result_prompt(LEGACY_SCORE_PROMPT, json_options, legacy_result=True)},
                                    legacy_messages[1]], "endpoint": self._endpoint_identity(),
                                    "call_options": {**json_options, **initial_options}})
        legacy_requests.append({
            **request, "messages": [{"role": "system", "content": model_result_prompt(SCORE_PROMPT, call_options, legacy_result=True)},
                                     dict(messages[1])],
        })
        metadata = {"dependency_keys": [self._role_key("consistency-auditor")]}
        if self.proof_graph_version in {2, 3}:
            legacy_requests = []
        record = self.checkpoints.get("final-scoring", request, completed_legacy_requests=legacy_requests)
        if self.proof_graph_version in {2, 3} and record and not strict_equal(record["request"], request):
            raise FaithSieveProtocolError("证明依赖图评分重入请求的完整字段或类型不一致")
        if record and isinstance(record.get("metadata"), dict) and "json_repair" in record["metadata"]:
            allowed_requests = [request, *legacy_requests] if record["state"] == "completed" else [request]
            if not any(strict_equal(record["request"], candidate) for candidate in allowed_requests):
                raise FaithSieveProtocolError("JSON 格式修复原评分重入请求的字段类型或完整输入不一致")
            metadata.update(record["metadata"])
            validate_repair_state(metadata["json_repair"], self._endpoint_identity(), call_options)
            if record["state"] != "pending" and metadata["json_repair"]["state"] != record["state"]:
                raise FaithSieveProtocolError("JSON 格式修复状态与原 checkpoint 终态不一致")
        if record and record["state"] == "endpoint_error":
            saved = record.get("metadata")
            summary = saved.get("endpoint_error") if isinstance(saved, dict) else None
            raise FaithSieveEndpointError(_ROLE_LABELS["scoring"], summary)
        if record and record["state"] == "protocol_error":
            raise FaithSieveProtocolError(str(record.get("error") or "评分回传协议错误"))
        response = None
        if record and record["state"] == "completed":
            payload = record.get("response")
        elif metadata.get("json_repair") is not None:
            payload, response = self._repair_json("scoring", "final-scoring", request, metadata, call_options)
        else:
            self.checkpoints.put("final-scoring", request, state="pending", metadata=metadata)
            try:
                response = self._chat("final-scoring", "role", self.endpoint, messages,
                                      timeout=ROLE_TIMEOUT_SECONDS, **call_options)
            except LLMEndpointError as exc:
                metadata["endpoint_error"] = endpoint_error_metadata(exc)
                failure = FaithSieveEndpointError(_ROLE_LABELS["scoring"], metadata["endpoint_error"])
                self.checkpoints.put("final-scoring", request, state="endpoint_error", error=str(failure), metadata=metadata)
                self._event("scoring", state="failed", status="failed", message=str(failure))
                raise failure from None
        try:
            if response is not None:
                try:
                    payload = parse_model_result(response, call_options,
                                                 allow_tool_commentary=self._allow_function_commentary("scoring"),
                                                 allow_result_body=self._allow_result_body("scoring"))
                except FaithSieveJSONSyntaxError as syntax_error:
                    if metadata.get("json_repair") is not None or not has_complete_response(response):
                        raise
                    self._save_protocol_diagnostic("scoring", "final-scoring", model_response_diagnostic(response, call_options),
                                                   syntax_error, chat_result=response)
                    payload, response = self._repair_json("scoring", "final-scoring", request, metadata, call_options,
                                                          response=response, error=syntax_error)
            if getattr(self, "result_projection_version", None) is not None:
                canonical, ignored_metadata = project_role_result(
                    {"result": parse_json_response(payload)}, {"verdict", "score", "comment"},
                )
                payload = canonical["result"]
                if ignored_metadata:
                    metadata["ignored_result_metadata"] = ignored_metadata
            result = parse_result(payload)
            if result["verdict"] != verdict:
                raise FaithSieveProtocolError("评分改变了已经独立审计通过的数学判断")
            if (verdict == "incorrect" and result["score"] == 5) or (verdict == "correct" and result["score"] < 4):
                raise FaithSieveProtocolError("评分与原量表关于正确且充分证明的定义不一致")
        except FaithSieveEndpointError:
            raise
        except ValueError as exc:
            if metadata.get("json_repair") is not None:
                metadata["json_repair"].update(state="protocol_error", error=str(exc))
            if response is not None:
                self._save_protocol_diagnostic("scoring", "final-scoring", model_response_diagnostic(response, call_options), exc, chat_result=response)
            if not record or record["state"] != "completed":
                self.checkpoints.put("final-scoring", request, state="protocol_error", error=str(exc), metadata=metadata)
            raise FaithSieveProtocolError(str(exc)) from None
        if not record or record["state"] != "completed":
            metadata.update(self._model_response_summary(response))
            self.checkpoints.put("final-scoring", request, state="completed", response=result, metadata=metadata)
        self.store.write_json(RESULT, result)
        return parse_result(self.store.read_json(RESULT))

    def run(self):
        """要求题面、忠实提取原稿已落盘；单元测试可直接注入这些输入。"""
        self.edges = []
        self.edge_contexts = {}
        self.scan_units = {}
        self.checked_edges = set()
        self.prefix_checked = set()
        self.verification = {}
        self.edge_obligations = {}
        self._role_counter = 0
        self._compile_counter = 0
        self._latest_role_keys = {}
        self._verification_keys = {}
        self._last_compile_key = ""
        self._last_step_key = ""
        self.store.begin_replay({"problem.md", SOURCE})
        try:
            self.store.read("problem.md")
            self.store.read(SOURCE)
            self._audit_pair(
                "decomposer", "decomposition-auditor",
                generator_files=self._source_files,
                auditor_files=lambda: self._files("problem.md", SOURCE, STEPS),
            )
            tree = self._audit_pair(
                "tree-builder", "tree-auditor",
                generator_files=lambda: self._files("problem.md", SOURCE, STEPS),
                auditor_files=lambda: self._files("problem.md", SOURCE, STEPS, TREE),
            )
            self.edges = self._read_edges(tree)
            scan = self._invoke("suspicion-scanner", files=self._files("problem.md", STEPS, TREE))
            self._check_window(self._scan_window(scan))
            earliest, prefix = self._map_evidence()
            self._prefix_check(earliest, prefix)
            verdict = self._synthesize()
            return self._score(verdict)
        except (_Inconclusive, FaithSieveProtocolError) as exc:
            result = {
                "verdict": "inconclusive", "score": 0,
                "comment": "FaithSieve 暂时无法安全判断这份证明：" + str(exc)[:8000],
            }
            self.store.write_json(RESULT, result)
            return parse_result(self.store.read_json(RESULT))


def _run_dependency_workflow(*, problem_text, submission_pdf, endpoint, verification_agent, workspace, progress=None,
                          initial_reasoning_effort=None, usage_recorder=None):
    from .dependency_workflow import DependencyWorkflow
    workflow = DependencyWorkflow(
        endpoint=endpoint, verification_agent=verification_agent, workspace=workspace, progress=progress,
        initial_reasoning_effort=initial_reasoning_effort,
        usage_recorder=usage_recorder,
    )
    if not isinstance(problem_text, str) or not problem_text.strip():
        raise ValueError("FaithSieve 题面不能为空")
    if not isinstance(submission_pdf, bytes) or not submission_pdf.startswith(b"%PDF-"):
        raise ValueError("FaithSieve 提交必须是有效 PDF")
    workflow.store.write("problem.md", problem_text)
    workflow.checkpoints.preserve_pdf(submission_pdf)
    workflow._event("source-extraction", state="running")
    legacy_source_request = {"problem_text": problem_text, "pdf_path": "submission.pdf"}
    previous_source_request = {**legacy_source_request, "timeout_seconds": SOURCE_TIMEOUT_SECONDS}
    source_request = {**previous_source_request, "proof_graph_version": 2}
    source_record = workflow.checkpoints.get(
        "source-extraction", source_request, completed_legacy_requests=(legacy_source_request, previous_source_request),
    )
    if source_record:
        allowed_source_requests = [source_request]
        if source_record["state"] == "completed":
            allowed_source_requests.extend((legacy_source_request, previous_source_request))
        if not any(strict_equal(source_record["request"], expected) for expected in allowed_source_requests):
            raise FaithSieveProtocolError("FaithSieve 原稿 checkpoint 的冻结输入字段或类型不一致")
    if source_record and "timeout_seconds" in source_record["request"] and type(
        source_record["request"]["timeout_seconds"]
    ) is not int:
        raise FaithSieveProtocolError("FaithSieve 原稿 checkpoint 的冻结预算必须是整数")
    if source_record and source_record["state"] == "completed":
        extracted = source_record.get("response")
    else:
        workflow.checkpoints.put("source-extraction", source_request, state="pending")
        extracted = verification_agent.extract_submission(
            submission_pdf, problem_text=problem_text, invocation_key="source-extraction",
            timeout_seconds=SOURCE_TIMEOUT_SECONDS,
        )
    if not isinstance(extracted, dict):
        extracted = {}
    if not source_record or source_record["state"] != "completed":
        workflow.checkpoints.put("source-extraction", source_request, state="completed", response=extracted)
    if isinstance(extracted.get("text"), str) and extracted["text"].strip():
        workflow.store.write(SOURCE, extracted["text"])
    workflow.store.write(f"{WORK}/source/extraction.txt", str(extracted.get("report") or ""))
    workflow.store.write_json(f"{WORK}/source/extraction.json", {
        "status": extracted.get("status"),
        "report": str(extracted.get("report") or ""),
        "execution": extracted.get("execution") if isinstance(extracted.get("execution"), dict) else {},
    })
    if extracted.get("status") != "ok" or not isinstance(extracted.get("text"), str) or not extracted["text"].strip():
        result = {
            "verdict": "inconclusive", "score": 0,
            "comment": "学生原稿无法忠实确认，暂不覆盖人工成绩。" + str(extracted.get("report") or "提取任务未提供可信的原稿状态。")[:8000],
        }
        workflow.store.write_json(RESULT, result)
        workflow._event("source-extraction", state="completed", status="inconclusive")
        return parse_result(workflow.store.read_json(RESULT))
    workflow._event("source-extraction", state="completed")
    return workflow.run()


def run_faithsieve_workflow(*, problem_text, submission_pdf, endpoint, verification_agent, workspace, progress=None,
                          initial_reasoning_effort=None, usage_recorder=None):
    """新运行仅按原稿图片执行；旧冻结任务沿原入口严格重放。"""
    from .image_workflow import ImageWorkflow, render_workflow_images
    if not isinstance(problem_text, str) or not problem_text.strip():
        raise ValueError("FaithSieve 题面不能为空")
    if not isinstance(submission_pdf, bytes) or not submission_pdf.startswith(b"%PDF-"):
        raise ValueError("FaithSieve 提交必须是有效 PDF")
    checkpoints = CheckpointStore(workspace)
    if checkpoints._path("source-extraction").exists():
        return _run_dependency_workflow(
            problem_text=problem_text, submission_pdf=submission_pdf, endpoint=endpoint,
            verification_agent=verification_agent, workspace=workspace, progress=progress,
            initial_reasoning_effort=initial_reasoning_effort,
            usage_recorder=usage_recorder,
        )
    workflow = ImageWorkflow(endpoint=endpoint, verification_agent=verification_agent, workspace=workspace,
                             progress=progress, initial_reasoning_effort=initial_reasoning_effort,
                             usage_recorder=usage_recorder)
    render_workflow_images(workflow, problem_text=problem_text, submission_pdf=submission_pdf)
    workflow.store.write("problem.md", problem_text)
    return workflow.run()


__all__ = ["FaithSieveWorkflow", "run_faithsieve_workflow"]
