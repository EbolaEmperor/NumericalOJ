"""直接从原稿图片构图、独立审核，再由完整 Judge 验证局部联合蕴含。"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import re

from backend.oj_modules.ai.endpoints import LLMImage
from backend.oj_modules.submissions.faithsieve import parse_result

from .artifacts import FaithSieveProtocolError, parse_json_response
from .dependency_workflow import DependencyWorkflow, NODE_VERIFICATION
from .json_repair import strict_equal
from .local_diagnostics import LOCAL_DIAGNOSTIC_VERSION, validate_local_verifier_result
from .node_selection import (
    NODE_SELECTION_FALLBACK_REASON, NODE_SELECTION_PATH, NODE_SELECTION_VERSION,
    default_node_selection_order, parse_node_selection, validate_node_selection_fallback,
    validate_node_selection_version,
)
from .errors import FaithSieveEndpointError
from .graph_context_revision import (
    read_graph_context_revision, graph_context_revision_input_paths,
    validate_graph_context_revision_prefix,
)
from .graph_repair_policy import GraphRepairProgress, select_graph_repair_policy
from .prompts import IMAGE_ROLE_NAMES, IMAGE_SCORE_PROMPT, render_image_role_prompt
from .proof_dag import parse_image_proof_dag, validate_image_proof_dag, node_contexts, topological_node_ids
from .external_results import EXTERNAL_RESULTS_VERSION, validate_external_results_version
from .result_metadata import RESULT_PROJECTION_VERSION, validate_result_projection_version
from .verification_audit import VERIFICATION_AUDIT_VERSION, validate_verification_audit_version
from .verification_method_policy import (
    VERIFICATION_METHOD_VERSION, read_verification_method_policy,
    validate_verification_method_policy_prefix, validate_verification_method_version,
)
from .workflow import EVIDENCE, FINAL, GENERATOR_REVISION_LIMIT, RESULT, TREE, WORK, _Inconclusive


IMAGE_RENDER_TIMEOUT_SECONDS = 600
_PNG = b"\x89PNG\r\n\x1a\n"


def image_render_request(problem_text):
    return {"role": "image-render", "problem_text": problem_text, "pdf_path": "submission.pdf",
            "timeout_seconds": IMAGE_RENDER_TIMEOUT_SECONDS, "proof_graph_version": 3}


def freeze_rendered_images(rendered):
    """将实际 PNG 原字节保存为一次性冻结输入，不能用文本转录替代。"""
    if type(rendered) is not dict or set(rendered) != {"files", "pages"}:
        raise FaithSieveProtocolError("FaithSieve 原稿图片渲染回传无效")
    files, pages = rendered["files"], rendered["pages"]
    if type(files) is not dict or type(pages) is not list or not 1 <= len(pages) <= 100:
        raise FaithSieveProtocolError("FaithSieve 原稿图片清单无效")
    expected = {"pages.json"}
    frozen = {}
    for number, page in enumerate(pages, 1):
        path = f"source-pages/page-{number}.png"
        if (type(page) is not dict or set(page) != {"page", "rendered", "image_path"}
                or type(page["page"]) is not int or page["page"] != number
                or page["rendered"] is not True or page["image_path"] != path):
            raise FaithSieveProtocolError("FaithSieve 原稿图片页序或路径无效")
        data = files.get(path)
        if type(data) is not bytes or not data.startswith(_PNG):
            raise FaithSieveProtocolError("FaithSieve 原稿页面必须是实际 PNG")
        expected.add(path)
        frozen[path] = base64.b64encode(data).decode("ascii")
    if set(files) != expected or type(files["pages.json"]) is not str:
        raise FaithSieveProtocolError("FaithSieve 原稿渲染不能包含转录或额外文件")
    if not strict_equal(parse_json_response("{\"pages\":" + files["pages.json"] + "}")["pages"], pages):
        raise FaithSieveProtocolError("FaithSieve 原稿图片清单与实际页面不一致")
    return {"pages": pages, "pages_json": files["pages.json"], "images": frozen}


def restore_rendered_images(frozen):
    if type(frozen) is not dict or set(frozen) != {"pages", "pages_json", "images"} or type(frozen["images"]) is not dict:
        raise FaithSieveProtocolError("FaithSieve 冻结原稿图片结构无效")
    files = {"pages.json": frozen["pages_json"]}
    try:
        for path, value in frozen["images"].items():
            if type(path) is not str or type(value) is not str:
                raise ValueError
            files[path] = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise FaithSieveProtocolError("FaithSieve 冻结 PNG 字节无效") from None
    rendered = {"files": files, "pages": frozen["pages"]}
    if not strict_equal(freeze_rendered_images(rendered), frozen):
        raise FaithSieveProtocolError("FaithSieve 冻结原稿图片不是精确原字节")
    return rendered


class ImageWorkflow(DependencyWorkflow):
    proof_graph_version = 3
    local_diagnostic_version = LOCAL_DIAGNOSTIC_VERSION
    result_projection_version = RESULT_PROJECTION_VERSION
    node_selection_version = NODE_SELECTION_VERSION
    verification_audit_version = VERIFICATION_AUDIT_VERSION
    _graph_context_revision = None
    _graph_context_revision_done = False
    _graph_repair_progress = None
    verification_method_version = None
    external_results_version = EXTERNAL_RESULTS_VERSION
    _verification_method_policy = None

    def _select_local_diagnostic_version(self):
        # 首次请求固定新旧协议；已开始的历史任务不能换提示词或 Judge 责任。
        try:
            record, _size = self.checkpoints._read_record("role-000001-attempt-1", strict=True)
        except FileNotFoundError:
            return LOCAL_DIAGNOSTIC_VERSION
        request = record.get("request") if type(record) is dict else None
        if type(request) is not dict or request.get("role") != "tree-builder":
            raise FaithSieveProtocolError("图像工作流首个冻结请求无效")
        version = request.get("local_diagnostic_version")
        if version is not None and (type(version) is not int or version != LOCAL_DIAGNOSTIC_VERSION):
            raise FaithSieveProtocolError("图像工作流冻结诊断版本无效")
        return version

    def _select_result_projection_version(self):
        try:
            record, _size = self.checkpoints._read_record("role-000001-attempt-1", strict=True)
        except FileNotFoundError:
            return RESULT_PROJECTION_VERSION if self.local_diagnostic_version is not None else None
        request = record.get("request") if type(record) is dict else None
        if type(request) is not dict or request.get("role") != "tree-builder":
            raise FaithSieveProtocolError("图像工作流首个冻结请求无效")
        return validate_result_projection_version(request.get("result_projection_version"))

    def _select_node_selection_version(self):
        try:
            record, _size = self.checkpoints._read_record("role-000001-attempt-1", strict=True)
        except FileNotFoundError:
            return NODE_SELECTION_VERSION if self.local_diagnostic_version is not None else None
        request = record.get("request") if type(record) is dict else None
        if type(request) is not dict or request.get("role") != "tree-builder":
            raise FaithSieveProtocolError("图像工作流首个冻结请求无效")
        version = validate_node_selection_version(request.get("node_selection_version"))
        if version is not None and self.local_diagnostic_version is None:
            raise FaithSieveProtocolError("局部命题排序不能升级历史图像验证协议")
        return version

    def _select_verification_audit_version(self):
        try:
            record, _size = self.checkpoints._read_record("role-000001-attempt-1", strict=True)
        except FileNotFoundError:
            return (VERIFICATION_AUDIT_VERSION
                    if self.local_diagnostic_version is not None and self.node_selection_version is not None else None)
        request = record.get("request") if type(record) is dict else None
        if type(request) is not dict or request.get("role") != "tree-builder":
            raise FaithSieveProtocolError("图像工作流首个冻结请求无效")
        version = validate_verification_audit_version(request.get("verification_audit_version"))
        if version is not None and (self.local_diagnostic_version is None or self.node_selection_version is None):
            raise FaithSieveProtocolError("局部验证报告审核不能升级历史图像验证协议")
        return version

    def _select_verification_method_version(self):
        try:
            record, _size = self.checkpoints._read_record("role-000001-attempt-1", strict=True)
        except FileNotFoundError:
            return VERIFICATION_METHOD_VERSION if self.verification_audit_version is not None else None
        request = record.get("request") if type(record) is dict else None
        if type(request) is not dict or request.get("role") != "tree-builder":
            raise FaithSieveProtocolError("图像工作流首个冻结请求无效")
        version = validate_verification_method_version(request.get("verification_method_version"))
        if version is not None and self.verification_audit_version is None:
            raise FaithSieveProtocolError("验证方法审核不能升级历史图像验证协议")
        return version

    def _verification_method_for_call(self, *, upcoming=False):
        if self.verification_method_version is not None:
            return validate_verification_method_version(self.verification_method_version)
        policy = self._verification_method_policy
        if policy is None:
            return None
        counter = self._role_counter + int(upcoming)
        if counter > policy["after_role_counter"]:
            return VERIFICATION_METHOD_VERSION
        return None

    def _select_external_results_version(self):
        try:
            record, _size = self.checkpoints._read_record("role-000001-attempt-1", strict=True)
        except FileNotFoundError:
            return EXTERNAL_RESULTS_VERSION if self.verification_audit_version is not None else None
        request = record.get("request") if type(record) is dict else None
        if type(request) is not dict or request.get("role") != "tree-builder":
            raise FaithSieveProtocolError("图像工作流首个冻结请求无效")
        version = validate_external_results_version(request.get("external_results_version"))
        if version is not None and self.verification_audit_version is None:
            raise FaithSieveProtocolError("外部结果协议不能升级历史图像验证协议")
        return version

    def _render_role_prompt(self, role, parameters, **_options):
        return render_image_role_prompt(role, parameters, legacy=self.local_diagnostic_version is None,
                                        node_selection_version=self.node_selection_version,
                                        verification_audit_version=self.verification_audit_version,
                                        verification_method_version=self._verification_method_for_call(upcoming=True),
                                        external_results_version=self.external_results_version)

    def _role_request_context(self, role):
        context = ({"local_diagnostic_version": self.local_diagnostic_version}
                   if self.local_diagnostic_version is not None else {})
        if self.result_projection_version is not None:
            context["result_projection_version"] = self.result_projection_version
        if self.node_selection_version is not None:
            context["node_selection_version"] = validate_node_selection_version(self.node_selection_version)
        if self.verification_audit_version is not None:
            if self.local_diagnostic_version is None or self.node_selection_version is None:
                raise FaithSieveProtocolError("局部验证报告审核不能升级历史图像验证协议")
            context["verification_audit_version"] = validate_verification_audit_version(self.verification_audit_version)
        method_version = self._verification_method_for_call()
        if method_version is not None:
            if self.verification_audit_version is None:
                raise FaithSieveProtocolError("验证方法审核缺少完整局部报告审核协议")
            context["verification_method_version"] = method_version
        if self.external_results_version is not None:
            if self.verification_audit_version is None:
                raise FaithSieveProtocolError("外部结果协议缺少完整局部报告审核协议")
            context["external_results_version"] = validate_external_results_version(self.external_results_version)
        return context

    def _allow_function_commentary(self, role):
        return (validate_node_selection_version(self.node_selection_version) is not None
                and (role == "scoring" or (role in IMAGE_ROLE_NAMES and role != "local-verifier")))

    def _allow_result_body(self, role):
        return (validate_node_selection_version(self.node_selection_version) is not None
                and (role == "scoring" or (role in IMAGE_ROLE_NAMES and role != "local-verifier")))

    def _allow_json_repair_after_retry(self, role):
        return (validate_node_selection_version(self.node_selection_version) is not None
                and role in IMAGE_ROLE_NAMES and role != "local-verifier")

    def _validate_role_result(self, role, result, parameters):
        if role not in {"local-verifier", "verification-auditor"}:
            return
        context = self.node_contexts.get(parameters.get("node_id"))
        if context is None:
            raise FaithSieveProtocolError("局部验证结果没有对应的完整命题上下文")
        known = {context["node"]["id"], *(node["id"] for node in context["premises"])}
        if role == "local-verifier":
            validate_local_verifier_result(result, diagnostic_version=self.local_diagnostic_version,
                                           known_node_ids=known)
        elif role == "verification-auditor":
            from .local_diagnostics import validate_verification_auditor_result
            validate_verification_auditor_result(result, known_node_ids=known)

    def _validate_role_artifacts(self, role, result, artifacts, control, parameters):
        if role == "node-selector":
            if self.node_selection_version is None or control:
                raise FaithSieveProtocolError("局部命题排序不能改变验证控制或升级旧协议")
            parse_node_selection(artifacts[NODE_SELECTION_PATH],
                                 required_node_ids=default_node_selection_order(self.proof_dag))

    def _role_label(self, role):
        return {"tree-builder": "生成证明依赖图", "tree-auditor": "审核证明依赖图"}.get(role, super()._role_label(role))

    def set_images(self, frozen):
        rendered = restore_rendered_images(frozen)
        self.image_files = {path: content for path, content in rendered["files"].items() if type(content) is bytes}
        self.image_frozen = dict(frozen["images"])
        self.pages = rendered["pages"]
        self.pages_json = rendered["files"]["pages.json"]

    def _files(self, *paths):
        files = super()._files(*(path for path in paths if path != "pages.json"))
        if "pages.json" in paths:
            files["pages.json"] = self.pages_json
        return files

    def _input_content(self, text):
        return [{"type": "text", "text": text}, *[
            {"type": "image_url", "image_url": {"url": LLMImage.from_bytes(self.image_files[page["image_path"]], "image/png").source}}
            for page in self.pages
        ]]

    def _agent_files(self, files):
        return {**files, **self.image_files}

    def _freeze_agent_images(self):
        return {path: base64.b64encode(content).decode("ascii") for path, content in self.image_files.items()}

    def _score_prompt(self):
        return IMAGE_SCORE_PROMPT

    def _expected_steps(self, files):
        return None

    def _normalize_proof_graph(self, graph, expected_steps):
        return validate_image_proof_dag(graph, allow_external_results=self.external_results_version is not None)

    def _parse_proof_graph(self, content, expected_steps):
        return parse_image_proof_dag(content, allow_external_results=self.external_results_version is not None)

    def _load_graph(self):
        self.proof_dag = self._parse_proof_graph(self.store.read(TREE), None)
        self.nodes = {node["id"]: node for node in self.proof_dag["nodes"]}
        self.claims = [node["id"] for node in self.proof_dag["nodes"] if node["kind"] == "claim"]
        self.node_contexts = node_contexts(self.proof_dag)

    def _control_dependencies(self, role, parameters):
        if role == "tree-builder":
            return {"image-render"}
        if role == "tree-auditor":
            return {key for key in (self._role_key("tree-builder"),) if key}
        if role == "node-selector":
            return {key for key in (self._role_key("tree-auditor"),) if key}
        if role == "local-verifier":
            # 联合前提是假设条件，不需要先等待前驱验证任务，也不添加虚假任务依赖。
            return {key for key in (self._role_key("tree-auditor"), getattr(self, "_node_selection_key", "")) if key}
        if role == "verification-auditor":
            return {key for key in (self._role_key("local-verifier", parameters),) if key}
        return super()._control_dependencies(role, parameters)

    def _fixed_obligation(self, identifier):
        context = self.node_contexts[identifier]
        path = f"{WORK}/obligations/{identifier}/{identifier}-O1.md"
        contract = ("全部直接前驱完整命题共同推出本节点完整命题；共享参数和见证统一绑定。"
                    "前驱作为局部条件不表示已证明。不能借用题面或原图中未登记的额外数学假设。"
                    "自主选择 Lean 或数值方法并完成验证，不能只检验目标真假。")
        if self.node_selection_version is not None:
            contract = contract.replace("不能借用题面或原图中未登记的额外数学假设。",
                                        "不能借用题面、原图或其他节点中未列明为直接前驱的额外数学假设。")
            contract = contract.replace("自主选择 Lean 或数值方法并完成验证，不能只检验目标真假。",
                                        "自主选择合适的数学验证方法，给出覆盖完整目标的充分证据；不能只检验目标真假。")
        if self.local_diagnostic_version is not None:
            contract += ("可以搜索并使用已有数学定理，但必须核对陈述和全部适用条件；这不等于补假设。"
                         "允许无歧义的绑定变量改名，不能改变原命题含义、量词范围或变量绑定。"
                         "原稿与图不一致时返回 graph_defect 和构图诊断，不将其当作作者证明错误。")
        if self.external_results_version is not None:
            contract = ("全部直接前驱完整命题共同推出本节点完整命题；共享参数和见证统一绑定。"
                        "前驱作为局部条件不表示其已经证明或原题已成立。"
                        "题面事实用 given、原稿中间结论用 claim；必要已有数学结果用 external 完整登记，"
                        "只有列明的直接前驱可作当前局部前置结论，不能借用未登记的事实、实质性外部定理或其他分支。"
                        "可以搜索并核对已有定理的完整陈述和全部适用条件，不能把作者待证引理当成 external。"
                        "需要未登记的外部结果时返回 graph_defect，diagnostics.kind=missing_premise，交由返修图和重新审核。"
                        "使用 Lean 时允许列明的直接前驱（包括 external）以完整声明和 sorry 引入，"
                        "分别命名 premise_N编号 或 external_N编号，报告逐项映射声明与节点；"
                        "这些 sorry 不代替其适用条件的推导，目标须在当前条件下实际应用定理。"
                        "当前完整目标命名 FaithSieveProof，不能在目标、定义或新的辅助引理中使用 sorry、admit、axiom 或其他占位。"
                        "只完整证明当前局部步骤，实际编译并记录退出码 0，核对完整目标与全部声明语义对应。"
                        "自主选择合适的数学验证方法，给出覆盖完整目标的充分证据；允许无歧义的绑定变量改名，"
                        "不能改变原命题含义、量词范围或变量绑定。原稿与图不一致时返回 graph_defect。")
        payload = {
            "node": context["node"], "premises": context["premises"],
            "verification_contract": contract,
        }
        content = json.dumps(payload, ensure_ascii=False, indent=2)
        # 既有调用继续使用当时的职责说明，节点及全部前提仍按当前图核对。
        try:
            record, _size = self.checkpoints._read_record(
                f"role-{self._role_counter + 1:06d}-attempt-1", strict=True,
            )
        except FileNotFoundError:
            record = None
        if record is not None:
            request = record.get("request") if type(record) is dict else None
            files = request.get("files") if type(request) is dict else None
            frozen_content = files.get(path) if type(files) is dict else None
            frozen = parse_json_response(frozen_content, strict_constants=True)
            if (request.get("role") != "local-verifier"
                    or not strict_equal(request.get("parameters"), {"node_id": identifier})
                    or type(frozen_content) is not str or type(frozen) is not dict
                    or set(frozen) != set(payload)
                    or not strict_equal(frozen.get("node"), payload["node"])
                    or not strict_equal(frozen.get("premises"), payload["premises"])
                    or type(frozen.get("verification_contract")) is not str
                    or not frozen["verification_contract"].strip()):
                raise FaithSieveProtocolError("FaithSieve 冻结局部义务与当前完整命题不一致")
            content = frozen_content
        self.store.write(path, content)
        return {"id": f"{identifier}-O1", "path": path}

    def _context_snapshot(self, identifier):
        context = self.node_contexts.get(identifier)
        if context is None:
            return None
        # 标签和边编号不改变局部蕴含；对象、完整命题和直接前提集合必须逐项相同。
        def proposition(node):
            return {name: node[name] for name in ("id", "kind", "statement")}
        return {"node": proposition(context["node"]),
                "premises": sorted((proposition(node) for node in context["premises"]), key=lambda node: node["id"])}

    def _accept_verification(self, identifier, cached):
        for path, content in cached["files"].items():
            self.store.write(path, content)
        values = dict(cached["verification"])
        status = values.pop("status")
        self._record_verification(f"{identifier}-O1", status=status,
                                  dependency_keys=cached["keys"], **values)
        self.local_statuses[identifier] = status
        self._publish_node_verification()

    def _adopt_graph(self):
        self._load_graph()
        self.verification, self._verification_keys = {}, {}
        self.local_statuses = {identifier: "not_checked" for identifier in self.claims}
        if self.store.visible_paths is not None:
            self.store.visible_paths = {path for path in self.store.visible_paths
                                        if not (path.startswith((f"{WORK}/verification/", f"{WORK}/formal/",
                                                                 f"{WORK}/obligations/"))
                                                or re.fullmatch(rf"{WORK}/review/N[1-9][0-9]*-verification\.md", path)
                                                or re.fullmatch(rf"{WORK}/results/N[1-9][0-9]*-(?:local-verifier|verification-auditor)\.json(?:\.transport\.json)?", path))}
        self._publish_node_verification()
        for identifier in self.claims:
            cached = self._node_result_cache.get(identifier)
            if cached and strict_equal(cached["context"], self._context_snapshot(identifier)):
                self._accept_verification(identifier, cached)

    def _verify_node(self, identifier, obligation):
        files = self._files("problem.md", "pages.json", obligation["path"])
        revision_report, dependencies = "", ()
        for revision in range(2):
            output = self._invoke("local-verifier", parameters={"node_id": identifier}, files=files,
                                  revision_report=revision_report, dependency_keys=dependencies)
            if output.result["status"] == "graph_defect":
                return output, None, None
            audit = None
            if (self.local_diagnostic_version is not None
                    and (output.result["status"] in {"passed", "refuted"}
                         or (self.verification_audit_version is not None and output.result["status"] == "inconclusive"))):
                report_files = {**files, **self._files(output.result["artifact"],
                                f"{WORK}/results/{identifier}-local-verifier.json")}
                audit = self._invoke("verification-auditor", parameters={"node_id": identifier}, files=report_files)
                if audit.result["status"] == "graph_defect":
                    return audit, None, None
                if audit.result["status"] == "needs_revision" and not revision:
                    revision_report = audit.result["report"] + "\n" + self.store.read(audit.result["artifact"])
                    if self.verification_audit_version is not None and output.result["status"] == "inconclusive":
                        if self._verification_method_for_call() is not None:
                            if self.external_results_version is not None:
                                revision_report += ("\n纠正上述具体的任务或证据误解，保持原完整命题与全部直接前提；"
                                                    "需要未登记的外部定理时返回 graph_defect/missing_premise，返修登记后再验证。"
                                                    "Lean 只允许列明前驱和 external 的完整声明用 sorry，当前目标必须完整证明。"
                                                    "仍无法可靠判断时保留 inconclusive，不强求明确结论。")
                            else:
                                revision_report += "\n纠正上述具体的任务或证据误解，保持原完整命题与全部直接前提，自主完成尚缺的验证；已有数学定理可搜索核对，不需要登记为前驱。仍无法可靠判断时保留 inconclusive，不强求明确结论。"
                        else:
                            revision_report += "\n只澄清上述对象、条件范围或无结论分类；保持原完整命题与直接前提，数学问题仍未解决时保留 inconclusive，不强求明确结论。"
                    dependencies = (audit.key,)
                    previous_report = f"{WORK}/reference/{identifier}-verification-previous.md"
                    self.store.write(previous_report, self.store.read(output.result["artifact"]))
                    files = {**files, **self._files(previous_report)}
                    continue
            status = output.result["status"]
            report = output.result["report"]
            if audit is not None and audit.result["status"] != "ok":
                status = "inconclusive"
                report = "局部验证证据尚未通过完整命题审核：" + audit.result["report"]
            values = {"status": status, "report": report, "artifact": output.result["artifact"],
                      "verification_mode": "agent"}
            keys = (output.key,)
            paths = [output.result["artifact"], f"{WORK}/results/{identifier}-local-verifier.json",
                     f"{WORK}/results/{identifier}-local-verifier.json.transport.json"]
            if audit is not None:
                values.update(agent_status=output.result["status"], semantic_audit_status=audit.result["status"],
                              semantic_audit_artifact=audit.result["artifact"])
                keys += (audit.key,)
                paths += [audit.result["artifact"], f"{WORK}/results/{identifier}-verification-auditor.json",
                          f"{WORK}/results/{identifier}-verification-auditor.json.transport.json"]
            cached = {"context": copy.deepcopy(self._context_snapshot(identifier)),
                      "verification": values, "keys": keys, "files": self.store.bundle(paths)}
            return None, cached, output
        raise _Inconclusive("局部验证证据审核仍未通过")

    def _check_nodes(self):
        while True:
            changed, defect = self._check_node_order()
            if not changed:
                return defect

    def _check_node_order(self):
        required = self._target_ancestors()
        order = self.node_selection_order if self.node_selection_version is not None else reversed(topological_node_ids(self.proof_dag))
        for identifier in order:
            if identifier not in required or self.nodes[identifier]["kind"] != "claim":
                continue
            if f"{identifier}-O1" in self.verification:
                continue
            if self._revise_graph_context():
                return True, None
            obligation = self._fixed_obligation(identifier)
            defect, cached, _output = self._verify_node(identifier, obligation)
            if defect is not None:
                return False, (identifier, defect)
            self._node_result_cache[identifier] = cached
            self._accept_verification(identifier, cached)
            if cached["verification"]["status"] == "refuted":
                break
        # 一份已完成前缀也可以在汇总前接受显式冻结的看图复核意见。
        if self._revise_graph_context():
            return True, None
        return False, None

    def _revise_graph_context(self):
        instruction = self._graph_context_revision
        if instruction is None or self._graph_context_revision_done:
            return False
        boundary = instruction["after_role_counter"]
        if self._role_counter < boundary:
            return False
        if self._role_counter != boundary:
            raise FaithSieveProtocolError("看图返修意见没有命中冻结的完整角色前缀")
        current_instruction = read_graph_context_revision(self.checkpoints, after_role_counter=boundary,
                                                           known_node_ids=set(self.nodes))
        if not strict_equal(current_instruction, instruction):
            raise FaithSieveProtocolError("看图返修意见在冻结前缀重放期间发生改变")
        if any(self.nodes[node]["kind"] != "claim" for node in instruction["affected_node_ids"]):
            raise FaithSieveProtocolError("看图返修意见只能针对已有待证节点")
        before = {node: copy.deepcopy(self._context_snapshot(node)) for node in instruction["affected_node_ids"]}
        paths = graph_context_revision_input_paths(instruction)
        self.store.write_json(paths["previous_graph"], self.proof_dag)
        self.store.write(paths["review"], instruction["report"])
        # 这是宿主保存的审图意见，不是 Judge 的数学结果；真正修图与审核仍读取全部原稿。
        primary = instruction["affected_node_ids"][0]
        self._graph_repair_progress.before_repair(primary, before[primary])
        self._audit_pair("tree-builder", "tree-auditor",
                         generator_files=lambda: self._files("problem.md", "pages.json", paths["previous_graph"], paths["review"]),
                         auditor_files=lambda: self._files("problem.md", "pages.json", TREE),
                         revision_report=instruction["report"],
                         dependency_keys=(self._role_key("tree-auditor"),))
        self._read_target_coverage()
        self._adopt_graph()
        for node, previous in before.items():
            if node not in self.nodes or self.nodes[node]["kind"] != "claim":
                raise FaithSieveProtocolError("看图返修删除了指定的待证节点：" + node)
            if strict_equal(previous, self._context_snapshot(node)):
                raise FaithSieveProtocolError("看图返修没有改变指定节点的完整命题或直接前提：" + node)
        self._graph_repair_progress.after_repair(primary, self._context_snapshot(primary))
        self._graph_context_revision_done = True
        self._select_nodes()
        return True

    def _node_selection_record(self, key):
        identity = getattr(self, "_node_selection_request", None)
        if type(identity) is not tuple or len(identity) != 2 or identity[0] != key:
            raise FaithSieveProtocolError("局部命题排序缺少原始冻结请求")
        request = identity[1]
        record = self.checkpoints.get(key, request)
        if (type(record) is not dict or not strict_equal(record["request"], request)
                or request.get("role") != "node-selector"
                or type(request.get("node_selection_version")) is not int
                or request["node_selection_version"] != NODE_SELECTION_VERSION):
            raise FaithSieveProtocolError("局部命题排序回退与冻结请求不一致")
        return record

    def _restore_node_selection_fallback(self, key, record, order):
        metadata = record.get("metadata") if type(record.get("metadata")) is dict else {}
        fallback = metadata.get("node_selection_fallback")
        if fallback is None:
            fallback = {"version": NODE_SELECTION_VERSION, "code_validated": True, "node_ids": list(order),
                        "reason": NODE_SELECTION_FALLBACK_REASON}
            validate_node_selection_fallback(fallback, expected_node_ids=order)
            metadata = {**metadata, "node_selection_fallback": fallback}
            # 只追加本次确定的回退，不重写原失败、回传或诊断，也不再次请求模型。
            self.checkpoints.put(key, record["request"], state=record["state"],
                                 response=record.get("response"), error=record.get("error"), metadata=metadata)
        else:
            validate_node_selection_fallback(fallback, expected_node_ids=order)
        self.node_selection_order = list(fallback["node_ids"])
        content = json.dumps({"node_ids": self.node_selection_order}, ensure_ascii=False, indent=2)
        path = self.store.path(NODE_SELECTION_PATH)
        if not path.exists() or self.store.read(NODE_SELECTION_PATH) != content:
            self.store.write(NODE_SELECTION_PATH, content)
        elif self.store.visible_paths is not None:
            self.store.visible_paths.add(NODE_SELECTION_PATH)
        self._node_selection_key = key
        self._latest_role_keys[f"{WORK}/results/node-selector.json"] = key

    def _select_nodes(self):
        fallback_order = default_node_selection_order(self.proof_dag)
        if self.node_selection_version is None:
            self.node_selection_order = fallback_order
            return
        key = f"role-{self._role_counter + 1:06d}-attempt-1"
        try:
            output = self._invoke("node-selector", files=self._files("problem.md", "pages.json", TREE))
        except (FaithSieveProtocolError, FaithSieveEndpointError):
            record = self._node_selection_record(key)
            if record["state"] not in {"protocol_error", "endpoint_error"}:
                # 完成后材料或身份被篡改不能作为普通排序失败继续。
                raise
            self._restore_node_selection_fallback(key, record, fallback_order)
            return
        record = self._node_selection_record(output.key)
        if output.result["status"] != "ok":
            self._restore_node_selection_fallback(output.key, record, fallback_order)
            return
        metadata = record.get("metadata") if type(record.get("metadata")) is dict else {}
        if "node_selection_fallback" in metadata:
            raise FaithSieveProtocolError("正常局部命题排序不能附带冻结失败回退")
        self.node_selection_order = parse_node_selection(self.store.read(NODE_SELECTION_PATH),
                                                        required_node_ids=fallback_order)["node_ids"]
        self._node_selection_key = output.key

    def _read_target_coverage(self):
        control = self.store.read_json(f"{WORK}/results/tree-auditor.json.transport.json").get("control")
        if (type(control) is not dict or set(control) != {"target_coverage"}
                or type(control["target_coverage"]) is not str
                or control["target_coverage"] not in {"matched", "missing", "inconclusive"}):
            raise FaithSieveProtocolError("原图 DAG 审计未明确核对题目全部目标")
        self.target_coverage = control["target_coverage"]

    def _repair_graph(self, identifier, defect, revision):
        before = {node: copy.deepcopy(self._context_snapshot(node)) for node in self.nodes}
        graph_path = f"{WORK}/graphs/revision-{revision}-previous.json"
        diagnosis_path = f"{WORK}/graph-diagnostics/revision-{revision}.json"
        self.store.write_json(graph_path, self.proof_dag)
        self.store.write_json(diagnosis_path, {"node_id": identifier, "diagnostics": defect.result["diagnostics"],
                                               "report": defect.result["report"]})
        base_files = lambda: self._files("problem.md", "pages.json", graph_path, diagnosis_path)
        self._audit_pair("tree-builder", "tree-auditor", generator_files=base_files,
                         auditor_files=lambda: self._files("problem.md", "pages.json", TREE),
                         revision_report=defect.result["report"] + "\n" + self.store.read(defect.result["artifact"]),
                         dependency_keys=(defect.key, self._role_key("tree-auditor")))
        self._read_target_coverage()
        self._adopt_graph()
        affected = {identifier, *(node for item in defect.result["diagnostics"] for node in item["affected_node_ids"])}
        if all(strict_equal(before.get(node), self._context_snapshot(node)) for node in affected):
            raise _Inconclusive("局部复核发现的构图差异尚未解决；修订没有改变受影响的局部命题或直接前提")
        self._select_nodes()

    def _map_evidence(self):
        # 保留原调用身份与模型报告快照；数学状态只取真实 Judge 账本及代码传播。
        self._invoke("evidence-mapper", files=self._final_files())
        self._publish_node_verification()
        control = {
            "units": [{"node_id": identifier, "status": self.local_statuses[identifier]}
                      for identifier in self.claims],
            "provisional_error_node": self._reliable_error(),
            "unresolved_ancestors": self._unresolved_ancestors(),
        }
        ledger = {
            "schema_version": 1,
            "target_ids": list(self.proof_dag["target_ids"]),
            "target_coverage": self.target_coverage,
            "targets_established": self.node_verification["targets_established"],
            "nodes": self.node_verification["nodes"],
            "control": control,
            "verification": {identifier: self.verification.get(f"{identifier}-O1")
                             for identifier in self.claims},
        }
        # 后续只读取规范摘要和原始验证报告；模型的错误重算仍留在原 checkpoint。
        self.store.write(EVIDENCE, "```json\n" + json.dumps(ledger, ensure_ascii=False, indent=2) + "\n```\n")

    def _final_files(self):
        return {**self.store.bundle(("problem.md", TREE, NODE_VERIFICATION, EVIDENCE),
                                   prefixes=(f"{WORK}/verification", f"{WORK}/formal", f"{WORK}/review")),
                "pages.json": self.pages_json}

    def _score_files(self):
        return {**self._final_files(), **self._files(FINAL)}

    def run(self):
        self._role_counter = self._compile_counter = 0
        self._latest_role_keys, self._verification_keys = {}, {}
        self._last_compile_key = self._last_step_key = ""
        self.verification, self.local_statuses, self.node_contexts = {}, {}, {}
        self._node_result_cache = {}
        self.local_diagnostic_version = None
        self.result_projection_version = None
        self.node_selection_version = None
        self.verification_audit_version = None
        self.verification_method_version = None
        self.external_results_version = None
        self._verification_method_policy = None
        self.node_selection_order = []
        self._node_selection_key = ""
        self._graph_context_revision_done = False
        self.store.begin_replay({"problem.md"})
        try:
            policy = select_graph_repair_policy(self.checkpoints, revision_limit=GENERATOR_REVISION_LIMIT)
            self._graph_repair_progress = GraphRepairProgress(policy) if policy is not None else None
            self._graph_context_revision = read_graph_context_revision(self.checkpoints)
            if self._graph_context_revision is not None and self._graph_repair_progress is None:
                raise FaithSieveProtocolError("看图返修续跑必须明确冻结新的宿主返修策略")
            if self._graph_context_revision is not None:
                validate_graph_context_revision_prefix(self.checkpoints, self._graph_context_revision)
            self.local_diagnostic_version = self._select_local_diagnostic_version()
            self.result_projection_version = self._select_result_projection_version()
            self.node_selection_version = self._select_node_selection_version()
            self.verification_audit_version = self._select_verification_audit_version()
            self.verification_method_version = self._select_verification_method_version()
            self.external_results_version = self._select_external_results_version()
            self._verification_method_policy = read_verification_method_policy(self.checkpoints)
            if self._verification_method_policy is not None:
                if self.verification_audit_version is None or self.verification_method_version is not None:
                    raise FaithSieveProtocolError("续跑方法审核策略不能替换已冻结的首个验证协议")
                validate_verification_method_policy_prefix(self.checkpoints, self._verification_method_policy)
            self.store.read("problem.md")
            if not self.image_files:
                raise FaithSieveProtocolError("原稿图片未加载")
            self._audit_pair("tree-builder", "tree-auditor",
                             generator_files=lambda: self._files("problem.md", "pages.json"),
                             auditor_files=lambda: self._files("problem.md", "pages.json", TREE))
            self._read_target_coverage()
            self._adopt_graph()
            self._select_nodes()
            revision = 0
            while True:
                defect = self._check_nodes()
                if defect is None:
                    break
                if self._graph_repair_progress is None and revision == GENERATOR_REVISION_LIMIT:
                    raise _Inconclusive("依赖图经局部复核返修后仍不能忠实表达原稿")
                identifier = defect[0]
                if self._graph_repair_progress is not None:
                    revision = self._graph_repair_progress.before_repair(identifier, self._context_snapshot(identifier))
                else:
                    revision += 1
                self._repair_graph(*defect, revision)
                if self._graph_repair_progress is not None:
                    self._graph_repair_progress.after_repair(identifier, self._context_snapshot(identifier))
            if self._graph_context_revision is not None and not self._graph_context_revision_done:
                raise FaithSieveProtocolError("看图返修没有到达指定完整前缀，不能提前汇总")
            self._map_evidence()
            return self._score(self._synthesize())
        except (_Inconclusive, FaithSieveProtocolError) as exc:
            result = {"verdict": "inconclusive", "score": 0,
                      "comment": "FaithSieve 暂时无法安全判断这份证明：" + str(exc)[:8000]}
            self.store.write_json(RESULT, result)
            return parse_result(self.store.read_json(RESULT))


def render_workflow_images(workflow, *, problem_text, submission_pdf):
    request = image_render_request(problem_text)
    workflow.checkpoints.preserve_pdf(submission_pdf)
    record = workflow.checkpoints.get("image-render", request)
    if record and not strict_equal(record["request"], request):
        raise FaithSieveProtocolError("原稿图片渲染重入的完整输入或字段类型不一致")
    if record and record["state"] != "completed":
        if record["state"] != "pending":
            raise FaithSieveProtocolError("原稿图片渲染已失败，不能替换冻结输入")
    if record and record["state"] == "completed":
        frozen = record.get("response")
    else:
        workflow.checkpoints.put("image-render", request, state="pending", metadata={"role": "image-render"})
        workflow._event("image-render", state="running")
        rendered = workflow.agent.render_submission_images(
            submission_pdf, invocation_key="image-render", timeout_seconds=IMAGE_RENDER_TIMEOUT_SECONDS,
        )
        frozen = freeze_rendered_images(rendered)
        workflow.checkpoints.put("image-render", request, state="completed", response=frozen,
                                 metadata={"role": "image-render"})
    workflow.set_images(frozen)
    workflow._event("image-render", state="completed")


__all__ = ["ImageWorkflow", "image_render_request", "freeze_rendered_images", "restore_rendered_images", "render_workflow_images"]
