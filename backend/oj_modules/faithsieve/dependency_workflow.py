"""按直接证明依赖验证结论节点；局部蕴含与全局建立状态分别记录。"""

from __future__ import annotations

import json
import math
import re

from backend.oj_modules.submissions.faithsieve import parse_result

from .artifacts import FaithSieveProtocolError
from .proof_dag import (
    node_contexts, parse_proof_dag, propagate_node_verdicts,
    topological_node_ids, validate_proof_dag,
)
from .proof_tree import step_ids
from .workflow import (
    EVIDENCE, FINAL, RESULT, SCAN, SOURCE, STEPS, TREE, WORK,
    FaithSieveWorkflow, _Inconclusive,
)

NODE_VERIFICATION = f"{WORK}/node-verification.json"


class DependencyWorkflow(FaithSieveWorkflow):
    proof_graph_version = 2

    def _normalize_proof_graph(self, graph, expected_steps):
        return validate_proof_dag(graph, expected_steps=expected_steps)

    def _parse_proof_graph(self, content, expected_steps):
        return parse_proof_dag(content, expected_steps=expected_steps)

    def _proof_graph_control(self, graph):
        return {"claim_nodes": [node["id"] for node in graph["nodes"] if node["kind"] == "claim"],
                "node_contexts": node_contexts(graph)}

    def _control_dependencies(self, role, parameters):
        identifier = parameters.get("node_id") or str(parameters.get("obligation_id") or "").split("-O", 1)[0]
        context = {**parameters, "node_id": identifier}
        predecessors = {
            "tree-builder": ("decomposition-auditor",), "suspicion-scanner": ("tree-auditor",),
            "local-reviewer": ("suspicion-scanner",), "check-object-generator": ("local-reviewer",),
            "numeric-evaluator": ("check-object-generator",), "statement-formalizer": ("check-object-generator",),
            "proof-searcher": ("semantic-checker",),
        }.get(role, ())
        dependencies = {self._role_key(predecessor, context) for predecessor in predecessors}
        if role == "semantic-checker":
            dependencies.add(self._last_compile_key)
        if role == "local-reviewer":
            # 这是实际调度的依赖；数学上下文仍仅是直接前驱的完整原声称。
            for premise in self.node_contexts.get(identifier, {}).get("premises", ()):
                dependencies.update(self._verification_keys.get(f"{premise['id']}-O1", ()))
        if role in {"evidence-mapper", "final-synthesizer"}:
            dependencies.update(key for keys in self._verification_keys.values() for key in keys)
            dependencies.add(self._role_key("suspicion-scanner"))
        if role == "final-synthesizer":
            dependencies.add(self._role_key("evidence-mapper"))
        if role == "consistency-auditor":
            dependencies.add(self._role_key("final-synthesizer"))
        return {key for key in dependencies if key}

    def _load_graph(self):
        self.proof_dag = parse_proof_dag(self.store.read(TREE), expected_steps=step_ids(self.store.read(STEPS)))
        self.nodes = {node["id"]: node for node in self.proof_dag["nodes"]}
        self.claims = [node["id"] for node in self.proof_dag["nodes"] if node["kind"] == "claim"]
        self.node_contexts = node_contexts(self.proof_dag)

    def _read_scan(self, output):
        if output.result["status"] != "ok":
            raise _Inconclusive(output.result["report"])
        units = output.control.get("units")
        if not isinstance(units, list) or [unit.get("node_id") for unit in units if isinstance(unit, dict)] != self.claims:
            raise FaithSieveProtocolError("风险扫描未完整覆盖全部结论节点")
        for unit in units:
            if set(unit) != {"node_id", "suspicion", "uncertain", "reason"}:
                raise FaithSieveProtocolError("结论节点风险字段无效")
            score = unit["suspicion"]
            if (isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score)
                    or not 0 <= score <= 1 or type(unit["uncertain"]) is not bool
                    or not isinstance(unit["reason"], str) or not unit["reason"].strip()):
                raise FaithSieveProtocolError("结论节点风险分数或理由无效")
            self.scan_units[unit["node_id"]] = unit
        focus = output.result.get("focus_unit")
        if focus is not None and focus not in self.claims:
            raise FaithSieveProtocolError("风险扫描返回未知结论节点")

    def _node_context(self, identifier, *, include_review=True):
        if identifier not in self.node_contexts:
            raise FaithSieveProtocolError("待验证结论节点不存在")
        context = self.node_contexts[identifier]
        files = self._files("problem.md")
        # 原文保持只读用于定位；图只提供直接前驱，不递归混入其他待证结论。
        files[TREE] = json.dumps({"schema_version": 2, "node_contexts": [context]}, ensure_ascii=False)
        selected = set(context["node"]["step_ids"])
        selected.update(step for premise in context["premises"] for step in premise["step_ids"])
        steps = self.store.read(STEPS)
        parts = re.split(r"(?m)(?=^## S[1-9][0-9]*\b)", steps)
        files[STEPS] = "".join(part for part in parts if part.startswith("## S")
                              and re.match(r"## (S[1-9][0-9]*)\b", part).group(1) in selected)
        files[SOURCE] = "\n\n".join(
            f"## {node['id']} 原稿摘录\n来源：{node['source_location']}\n\n{node['source_text']}"
            for node in [*context["premises"], context["node"]] if node["source_type"] == "submission"
        )
        if include_review:
            files.update(self._files(f"{WORK}/review/{identifier}.md"))
        return files

    def _obligation_context(self, obligation, path, *, include_review=True):
        identifier = obligation.split("-O", 1)[0]
        if obligation != f"{identifier}-O1" or path != f"{WORK}/obligations/{identifier}/{obligation}.md":
            raise FaithSieveProtocolError("依赖图只允许节点唯一的固定主义务")
        files = self._node_context(identifier, include_review=include_review)
        files.update(self._files(path, f"{WORK}/formal/{obligation}-check.md"))
        return files

    def _fixed_obligation(self, identifier):
        context = self.node_contexts[identifier]
        obligation = f"{identifier}-O1"
        path = f"{WORK}/obligations/{identifier}/{obligation}.md"
        # JSON 将每个完整命题区分为独立值，禁止把一个前驱删成其局部片段。
        content = "# 节点验证义务\n\n" + json.dumps({
            "id": obligation, "node_id": identifier,
            "premises": [{"node_id": node["id"], "statement": node["statement"],
                          "source_type": node["source_type"], "source_location": node["source_location"],
                          "source_text": node["source_text"], "step_ids": node["step_ids"]}
                         for node in context["premises"]],
            "goal": context["node"]["statement"],
            "source_location": context["node"]["source_location"],
            "source_text": context["node"]["source_text"], "step_ids": context["node"]["step_ids"],
            "direction": "全部直接前驱结论共同推出本节点完整结论",
            "depends_on": [],
        }, ensure_ascii=False, indent=2) + "\n\n" + (
            "只验证上述局部蕴含；前驱中作者声称可作为此局部检查的条件，未验证不等于已成立。\n"
            "必须保留每个完整前提和目标中的量词、局部假设与对象，不把待证目标缩为条件较弱的引理。\n"
            "无直接前驱时验证完整目标本身。表示不能忠实确定、额外数学前提或对象替换不能忠实证明时，"
            "返回 inconclusive；不能把表示失败或辅助命题反证认作原节点反证。\n"
            "纯定义或类型适配允许在同一完整形式化中证明等价，不额外派出义务。\n"
        )
        self.store.write(path, content)
        self.store.write(f"{WORK}/obligations/{identifier}/index.md", path + "\n")
        self._obligation_definitions[obligation] = {"path": path, "depends_on": ()}
        return {"id": obligation, "path": path, "depends_on": []}

    def _numeric_status(self, evaluated):
        # 通用 Judge 独立选择数值工具并报告完整局部蕴含；不另强制 SymPy 协议。
        return evaluated.result["status"]

    def _numeric_verification_metadata(self, evaluated):
        return {"verification_mode": "agent"}

    def _check_nodes(self):
        # 稳定拓扑顺序，unknown 不截断分支；低风险也必须实际验证。
        for identifier in topological_node_ids(self.proof_dag):
            if self.nodes[identifier]["kind"] == "given":
                continue
            review = self._invoke("local-reviewer", files=self._node_context(identifier, include_review=False),
                                  parameters={"node_id": identifier})
            if review.result["status"] == "ok":
                outcome = review.control.get("review_outcome")
                if outcome not in {"supported", "suspect", "uncertain"} or not re.search(
                        rf"review_outcome\s*:\s*{outcome}\b", self.store.read(review.result["artifact"])):
                    raise FaithSieveProtocolError("节点局部复核与报告不一致")
            obligation = self._fixed_obligation(identifier)
            if review.result["status"] != "ok":
                self._record_verification(obligation["id"], status="inconclusive", report=review.result["report"])
            else:
                self._verify_obligation(obligation)
            self.local_statuses[identifier] = self.verification[obligation["id"]]["status"]
            self._publish_node_verification()

    def _publish_node_verification(self):
        nodes = propagate_node_verdicts(self.proof_dag, self.local_statuses)
        self.node_verification = {
            "schema_version": 1, "proof_dag": self.proof_dag, "nodes": nodes,
            "target_coverage": self.target_coverage,
            "target_ids": list(self.proof_dag["target_ids"]),
            "targets_established": all(nodes[target]["established"] for target in self.proof_dag["target_ids"]),
        }
        self.store.write_json(NODE_VERIFICATION, self.node_verification)

    def _target_ancestors(self):
        ancestors, pending = set(), list(self.proof_dag["target_ids"])
        while pending:
            identifier = pending.pop()
            if identifier in ancestors:
                continue
            ancestors.add(identifier)
            pending.extend(node["id"] for node in self.node_contexts.get(identifier, {}).get("premises", ()))
        return ancestors

    def _reliable_error(self):
        required = self._target_ancestors()
        return next((identifier for identifier in self.claims if identifier in required
                     and self.local_statuses.get(identifier) == "refuted"), None)

    def _unresolved_ancestors(self):
        required = self._target_ancestors()
        return [identifier for identifier in self.claims if identifier in required
                and not self.node_verification["nodes"][identifier]["established"]]

    def _map_evidence(self):
        output = self._invoke("evidence-mapper", files=self._final_files())
        if output.result["status"] != "ok":
            raise _Inconclusive(output.result["report"])
        control = output.control
        units = control.get("units")
        if set(control) != {"units", "provisional_error_node", "unresolved_ancestors"} or not isinstance(units, list):
            raise FaithSieveProtocolError("节点证据映射字段无效")
        expected = [{"node_id": identifier, "status": self.local_statuses[identifier]} for identifier in self.claims]
        if units != expected or any(set(unit) != {"node_id", "status"} for unit in units):
            raise FaithSieveProtocolError("节点证据映射与唯一主义务的实际验证不一致")
        if control["provisional_error_node"] != self._reliable_error() or control["unresolved_ancestors"] != self._unresolved_ancestors():
            raise FaithSieveProtocolError("节点反证或依赖祖先缺口与宿主状态不一致")

    def _final_files(self):
        return self.store.bundle(
            ("problem.md", SOURCE, STEPS, TREE, SCAN, EVIDENCE, NODE_VERIFICATION),
            prefixes=(f"{WORK}/review", f"{WORK}/obligations", f"{WORK}/formal"),
        )

    def _score_files(self):
        return {**super()._score_files(), **self._files(NODE_VERIFICATION)}

    def _synthesize(self):
        final = self._invoke("final-synthesizer", files=self._final_files())
        for revision in range(2):
            if final.result["status"] != "ok" or final.result.get("verdict") not in {"correct", "incorrect", "inconclusive"}:
                raise _Inconclusive(final.result["report"])
            verdict = final.result["verdict"]
            if verdict == "correct" and self.target_coverage != "matched":
                raise _Inconclusive("作者真实目标尚未覆盖题目全部目标，不能认证证明")
            if verdict == "correct" and not self.node_verification["targets_established"]:
                raise _Inconclusive("题目目标的依赖祖先尚未全部建立，不能认证证明")
            if verdict == "incorrect" and self._reliable_error() is None:
                raise _Inconclusive("没有固定节点局部蕴含上的可靠反证，不能把表示或工具失败当作学生错误")
            audit_files = {**self._final_files(), **self._files(FINAL)}
            audited = self._invoke("consistency-auditor", files=audit_files)
            if audited.result["status"] == "ok":
                return verdict
            if audited.result["status"] != "needs_revision" or revision:
                raise _Inconclusive(audited.result["report"])
            final = self._invoke(
                "final-synthesizer", files=self._final_files(), dependency_keys=(audited.key,),
                revision_report=audited.result["report"] + "\n" + self.store.read(audited.result["artifact"]),
            )
        raise _Inconclusive("节点证据综合的独立审计未通过")

    def run(self):
        self._role_counter = self._compile_counter = 0
        self._latest_role_keys, self._verification_keys = {}, {}
        self._last_compile_key = self._last_step_key = ""
        self.verification, self._obligation_definitions = {}, {}
        self.scan_units, self.local_statuses, self.node_contexts = {}, {}, {}
        self.store.begin_replay({"problem.md", SOURCE})
        try:
            self.store.read("problem.md")
            self.store.read(SOURCE)
            self._audit_pair("decomposer", "decomposition-auditor", generator_files=self._source_files,
                             auditor_files=lambda: self._files("problem.md", SOURCE, STEPS))
            self._audit_pair("tree-builder", "tree-auditor",
                             generator_files=lambda: self._files("problem.md", SOURCE, STEPS),
                             auditor_files=lambda: self._files("problem.md", SOURCE, STEPS, TREE))
            audited = self.store.read_json(f"{WORK}/results/tree-auditor.json.transport.json").get("control")
            if (not isinstance(audited, dict) or set(audited) != {"target_coverage"}
                    or not isinstance(audited["target_coverage"], str)
                    or audited["target_coverage"] not in {"matched", "missing", "inconclusive"}):
                raise FaithSieveProtocolError("DAG 审计未明确核对全部原题目标覆盖")
            self.target_coverage = audited["target_coverage"]
            self._load_graph()
            self._publish_node_verification()
            scan = self._invoke("suspicion-scanner", files=self._files("problem.md", SOURCE, STEPS, TREE))
            self._read_scan(scan)
            self._check_nodes()
            self._map_evidence()
            return self._score(self._synthesize())
        except (_Inconclusive, FaithSieveProtocolError) as exc:
            result = {"verdict": "inconclusive", "score": 0,
                      "comment": "FaithSieve 暂时无法安全判断这份证明：" + str(exc)[:8000]}
            self.store.write_json(RESULT, result)
            return parse_result(self.store.read_json(RESULT))
