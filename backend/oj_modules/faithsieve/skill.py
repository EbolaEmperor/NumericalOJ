"""恢复原 FaithSieve skill 主 Judge；与显式 workflow 分别执行。"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat

from backend.oj_modules.agents.judge import judge_session_id, submit_judge_turn
from backend.oj_modules.agents.sessions import (
    get_agent_session, get_agent_session_runtime_config, get_agent_session_turns,
)
from backend.oj_modules.agents.workspace import ensure_agent_workspace, open_agent_workspace_file
from backend.oj_modules.submissions.faithsieve import RESULT_FILENAME, RUN_TIMEOUT_SECONDS, normalize_execution_mode, parse_result

from .judge import DockerFaithSieveTools, FaithSievePending, render_submission_images
from .artifacts import MAX_ARTIFACT_BYTES
from .proof_tree import TREE_PATH, parse_proof_tree, step_ids
from .proof_dag import parse_proof_dag, parse_image_proof_dag
from .node_verification import NODE_VERIFICATION_PATH, validate_conclusive_node_verdict


_LEGACY_TASK_PROMPT = (
    "请使用 faithsieve skill 批改 problem.md 中的题目与 "
    "submission.pdf 中的学生证明，并严格按 skill 规定覆盖写入 "
    "faithsieve_result.json。"
)
_IMAGE_TASK_PROMPT = (
    "请使用 faithsieve skill 批改 problem.md 中的题目与 pages.json 列出的逐页原稿图像，"
    "用图像工具逐页核对，不调用 PDF 文本提取或 OCR；并严格按 skill 规定覆盖写入 "
    "faithsieve_result.json。"
)
_STATE_TREE_TASK_PROMPT = (
    _IMAGE_TASK_PROMPT + "证明状态树必须使用 skill 规定的 schema_version:1 纯 JSON 格式，"
    "写入 faithsieve-work/tree.json，重新解析并校验结构和全部步骤对应后再继续。"
)
_DEPENDENCY_TASK_PROMPT = (
    _IMAGE_TASK_PROMPT + "证明依赖图必须使用 skill 规定的 schema_version:2 纯 JSON 格式，"
    "写入 faithsieve-work/tree.json；节点是题设或作者声称的结论，边仅表示直接前提依赖。"
    "重新解析并校验无环结构、来源、全部步骤覆盖和最终目标后，以全部直接前驱为前提逐节点验证。"
    "局部推理通过不等于其前提成立，推理被反驳不等于结论本身为假。"
)
SKILL_TASK_PROMPT = (
    _IMAGE_TASK_PROMPT + "直接阅读全部原稿图片生成 schema_version:3 的命题依赖 DAG，"
    "写入 faithsieve-work/tree.json，再对照原稿图片和题面独立审核。"
    "不要转录、整理原稿或拆分步骤，不生成 source_text 引文、原句位置或局部摘录。"
    "节点仅含 id、kind、label、statement；边表示全部直接前提共同推出目标。"
    "局部验证者可读取全部原稿图片，并接收目标节点和全部直接前驱的完整命题，"
    "自主完成验证及必要的数值计算或 Lean 搜索、编码与编译。"
    "按 skill 规定保存节点验证摘要；局部推理通过不等于其前提已成立。"
)
_TERMINAL = {"completed", "failed", "canceled", "cancelled", "cleanupfailed"}
_MAX_RESULT_BYTES = 256 * 1024


def skill_identity(run):
    """沿用旧主会话编号，已有运行记录能够恢复原轮次。"""
    attempt = str(run.get("attempt_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", attempt):
        raise ValueError("FaithSieve 请求编号无效")
    session_id = judge_session_id(int(run["submission_id"]), attempt, "faithsieve")
    if run.get("session_id") and run["session_id"] != session_id:
        raise ValueError("FaithSieve skill 工作区身份不一致")
    return session_id, f"fs-{attempt}"


def skill_problem_material(problem):
    return (
        f"# {str(problem.get('title') or '').strip()}\n\n"
        f"{str(problem.get('content') or '').strip()}\n\n"
        "## 评分\n\n满分 5 分。请按 FaithSieve skill 的量表评分。\n"
    ).encode("utf-8")


class FaithSieveSkillAgent:
    def __init__(self, *, run, submission, problem=None, celery_app=None, workspace=None, tool_runner=None):
        self.run, self.submission, self.problem = dict(run), dict(submission or {}), dict(problem or {})
        self.celery_app = celery_app
        self.workspace = Path(workspace) if workspace is not None else None
        self.tools = tool_runner
        self.session_id, self.task_id = skill_identity(run)
        if normalize_execution_mode(run.get("execution_mode"), default="skill") != "skill":
            raise ValueError("FaithSieve skill 执行模式与持久记录不一致")

    def _audit(self, session):
        expected = {
            "session_id": self.session_id, "current_task_id": self.task_id,
            "task_kind": "judge", "judge_kind": "faithsieve", "access_role": "user",
            "attempt_id": self.run["attempt_id"], "submission_id": self.run["submission_id"],
            "requested_by": self.submission.get("username"), "competition_id": None,
            "problem_id": self.run["problem_id"], "harness": self.run["harness"],
            "endpoint_id": int(self.run["endpoint_id"]),
        }
        if not expected["requested_by"] or any(str(session.get(name)) != str(value) for name, value in expected.items()):
            raise ValueError("FaithSieve skill Judge 会话关联或执行参数不一致")
        runtime = get_agent_session_runtime_config(self.session_id)
        # 旧技能会话没有此字段；False 明确表示新 workflow 的禁用技能投影。
        if runtime.get("project_skill") is False or runtime.get("endpoint_source", "global") != "global":
            raise ValueError("FaithSieve skill Judge 的技能投影设置不一致")
        turns = get_agent_session_turns(self.session_id)
        if (len(turns) != 1 or turns[0].get("task_id") != self.task_id
                or turns[0].get("user_message") not in {SKILL_TASK_PROMPT, _DEPENDENCY_TASK_PROMPT, _STATE_TREE_TASK_PROMPT, _IMAGE_TASK_PROMPT, _LEGACY_TASK_PROMPT}):
            raise ValueError("FaithSieve skill Judge 轮次或原始任务指令不一致")
        turn = turns[0]
        if str(turn.get("status") or "").strip().lower() == "completed":
            for name in ("harness", "endpoint_id", "endpoint_model"):
                if str(turn.get(name)) != str(session.get(name)):
                    raise ValueError("FaithSieve skill Judge 实际执行参数不一致")
        return turn

    def _read_result(self):
        try:
            stream, metadata = open_agent_workspace_file(self.session_id, RESULT_FILENAME)
            with stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or metadata.get("size", info.st_size) > _MAX_RESULT_BYTES:
                    raise ValueError("FaithSieve 结果文件不是受限的独立普通文件")
                raw = stream.read(_MAX_RESULT_BYTES + 1)
                if len(raw) > _MAX_RESULT_BYTES or os.fstat(stream.fileno()).st_nlink != 1:
                    raise ValueError("FaithSieve 结果文件过大或不安全")
        except (OSError, ValueError):
            raise ValueError("Agent 未写入可安全读取的 FaithSieve 结果文件") from None
        try:
            result = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise ValueError("FaithSieve 结果不是有效 JSON") from None
        return parse_result(result)

    def _validate_tree(self, *, proof_graph_version=3, verdict=None):
        """新 Skill 读取依赖图；历史任务按原状态树契约读取，不补写工件。"""
        def read(path):
            try:
                stream, _metadata = open_agent_workspace_file(self.session_id, path)
                with stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_ARTIFACT_BYTES:
                        raise ValueError("证明状态树输入不是受限的独立普通文件")
                    raw = stream.read(MAX_ARTIFACT_BYTES + 1)
                    if len(raw) > MAX_ARTIFACT_BYTES or os.fstat(stream.fileno()).st_nlink != 1:
                        raise ValueError("证明状态树输入过大或不安全")
                    return raw.decode("utf-8")
            except (OSError, ValueError, UnicodeError):
                raise ValueError("Agent 未写入可安全读取的证明状态树及步骤") from None
        if proof_graph_version == 3:
            dag = parse_image_proof_dag(read(TREE_PATH))
        else:
            parser = parse_proof_dag if proof_graph_version == 2 else parse_proof_tree
            dag = parser(read(TREE_PATH), expected_steps=step_ids(read("faithsieve-work/steps.md")))
        if proof_graph_version in {2, 3}:
            validate_conclusive_node_verdict(read(NODE_VERIFICATION_PATH), dag, verdict)

    def execute(self, *, endpoint_loader, pdf_loader):
        session = get_agent_session(self.session_id)
        if session is None:
            remaining = RUN_TIMEOUT_SECONDS - int(self.run.get("elapsed_seconds") or 0)
            if remaining <= 0:
                raise ValueError("FaithSieve 评测已超过整体时限")
            endpoint = endpoint_loader()
            if endpoint.get("category") != "omni":
                raise ValueError("逐页原稿图像核对需要选择全模态 LLM 节点")
            workspace = self.workspace or Path(ensure_agent_workspace(f"faithsieve-{self.run['attempt_id']}"))
            tools = self.tools or DockerFaithSieveTools(workspace)
            image_files, _pages = render_submission_images(
                pdf_loader(), workspace=workspace / "faithsieve-work/judge-invocations/skill-source/rendered",
                tools=tools, timeout_seconds=min(remaining, 600),
            )
            template = {"verdict": "inconclusive", "score": 0,
                        "comment": "请按 faithsieve skill 完成评测后覆盖本文件。"}
            submit_judge_turn(
                session_id=self.session_id, task_id=self.task_id,
                requested_by=self.submission["username"], judge_kind="faithsieve",
                submission_id=int(self.run["submission_id"]), attempt_id=self.run["attempt_id"],
                competition_id=None, harness=self.run["harness"], endpoint=endpoint,
                prompt=SKILL_TASK_PROMPT,
                files={**{path: value if isinstance(value, bytes) else value.encode("utf-8") for path, value in image_files.items()},
                       "problem.md": skill_problem_material(self.problem),
                       RESULT_FILENAME: json.dumps(template, ensure_ascii=False, indent=2).encode("utf-8")},
                title=f"FaithSieve · {self.problem.get('title') or self.run['submission_id']}"[:64],
                timeout_seconds=remaining, celery_app=self.celery_app,
                problem_id=int(self.run["problem_id"]), problem_title=self.problem.get("title"),
                project_skill=True,
            )
            raise FaithSievePending(session_id=self.session_id, task_id=self.task_id, role="skill", invocation_key="skill")
        turn = self._audit(session)
        statuses = [str(record.get("status") or "").strip().lower().replace("_", "") for record in (session, turn)]
        if any(status in _TERMINAL and status != "completed" for status in statuses):
            raise ValueError("FaithSieve skill Judge 未正常完成，未覆盖原人工成绩")
        if any(status != "completed" for status in statuses):
            raise FaithSievePending(session_id=self.session_id, task_id=self.task_id, role="skill", invocation_key="skill")
        result = self._read_result()
        if result["verdict"] != "inconclusive":
            if turn.get("user_message") == SKILL_TASK_PROMPT:
                self._validate_tree(verdict=result["verdict"])
            elif turn.get("user_message") == _DEPENDENCY_TASK_PROMPT:
                self._validate_tree(proof_graph_version=2, verdict=result["verdict"])
            elif turn.get("user_message") == _STATE_TREE_TASK_PROMPT:
                self._validate_tree(proof_graph_version=1)
        return result

    def cancel_pending(self):
        session = get_agent_session(self.session_id)
        if session is None:
            return
        self._audit(session)
        if str(session.get("status") or "").strip().lower().replace("_", "") in _TERMINAL:
            return
        from backend.oj_modules.tasks.agent.control import build_agent_run_terminator
        result = build_agent_run_terminator(self.celery_app)(self.task_id)
        if result.get("errors") or not result.get("canceled"):
            raise ValueError("无法确认 FaithSieve skill Judge 已安全终止")


__all__ = ["FaithSieveSkillAgent", "SKILL_TASK_PROMPT", "skill_identity", "skill_problem_material"]
