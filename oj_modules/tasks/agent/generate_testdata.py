#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""使用所选 CLI harness 与 numoj-user skill 生成并验证测试数据。"""

from __future__ import annotations

from pathlib import Path
import re
import tempfile
import time

from config import AGENT_WORKSPACE_ROOT
from oj_modules.db_services import get_problem, get_user_by_username
from oj_modules.problems.agent_launch import (
    AGENT_TASK_TESTDATA,
    resolve_launch_endpoint,
)
from oj_modules.problems.testdata import (
    TESTDATA_TEXT_MAX_TOTAL_BYTES,
    TESTDATA_ZIP_MAX_TOTAL_BYTES,
    get_problem_testdata_state,
    parse_testdata_zip,
    publish_staged_testdata,
)
from oj_modules.tasks.agent.harness_runtime import run_agent_harness
from oj_modules.tasks.agent.shared import (
    AGENT_GENERATE_TESTDATA_TASK_NAME,
    _clamp_int,
    _format_local_time,
    _push_agent_event,
)
from oj_modules.tasks.agent.testdata_validation import validate_staged_testdata


_LANGUAGE_SUFFIXES = {
    "c": ".c",
    "cpp": ".cpp",
    "c++": ".cpp",
    "python": ".py",
    "python3": ".py",
    "matlab": ".m",
    "octave": ".m",
}
_STAGED_ZIP_RELATIVE_PATH = "agent-output/testdata.zip"
_STAGED_ZIP_CONTAINER_PATH = f"/workspace/{_STAGED_ZIP_RELATIVE_PATH}"
# ZIP 只允许承载受 TESTDATA_TEXT_MAX_TOTAL_BYTES 限制的文本测试点；额外空间
# 留给 ZIP 目录和压缩开销，同时不得突破通用解压总量上限。
_STAGED_ZIP_MAX_BYTES = min(
    TESTDATA_ZIP_MAX_TOTAL_BYTES,
    TESTDATA_TEXT_MAX_TOTAL_BYTES + 8 * 1024 * 1024,
)

__all__ = ["build_testdata_agent_prompt", "register_agent_generate_testdata_task"]


def build_testdata_agent_prompt(
    *,
    problem_id,
    problem_title,
    problem_language="",
    test_point_count,
    standard_solution_path,
    interactor_path="/workspace/task-input/problem_interactor.txt",
    time_limit_ms=2000,
    data_requirement="",
):
    requirement = str(data_requirement or "").strip()
    requirement_text = (
        requirement
        if requirement
        else "无额外要求，请自行覆盖边界、典型与压力场景。"
    )
    limit_ms = int(time_limit_ms)
    limit_seconds = limit_ms / 1000.0
    language = str(problem_language or "").strip().lower()
    if language == "matlab":
        test_method = (
            "将 i.in 重命名为 input.txt，放在完整代码同目录下，运行完整代码，"
            "然后将输出的 output.txt 与 i.out 进行逐字节比较"
        )
    else:
        test_method = (
            "将 i.in 作为完整源码的标准输入流，运行后将标准输出流与 i.out "
            "进行逐字节比较"
        )
    return (
        f"请使用 numoj-user skill 读取问题：{problem_title}（题号 {int(problem_id)}），"
        f"为这个问题生成 {int(test_point_count)} 个有强度、高质量的测试点。\n"
        f"这是正解程序：{standard_solution_path}\n"
        f"这是题目给的交互程序：{interactor_path}\n"
        f"每个测试点的时间限制是 {limit_ms} ms（{limit_seconds:g} 秒）。\n"
        "本地验证时，请先复制交互程序，再将其中唯一的 `%%user_code_here` 占位符整体替换为正解文件的完整源码。"
        "如果交互程序为空，则直接运行正解文件。\n"
        f"对于第 i 个测试点，测试方式是：{test_method}。\n\n"
        "特别地，我希望测试点满足如下要求："
        f"{requirement_text}\n\n"
        "请将测试点以 1.in/1.out 至 n.in/n.out 的形式直接放在 ZIP 根目录，最终 ZIP 必须保存到："
        f"{_STAGED_ZIP_CONTAINER_PATH}\n"
        "再次强调：请确保你的测试点有足够的强度，并确保正解能在规定时间内通过全部测试。"
    )


def _safe_standard_solution_filename(value, fallback_suffix):
    filename = str(value or "").strip()
    if not filename:
        return f"standard_solution{fallback_suffix}"
    if (
        filename in {".", ".."}
        or filename.startswith(".")
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
        or len(filename.encode("utf-8")) > 255
    ):
        raise ValueError("标准程序文件名无效")
    return filename


def _require_testdata_state(problem_id):
    snapshot = get_problem_testdata_state(problem_id)
    if snapshot is None:
        raise RuntimeError("题目测试数据状态不存在")
    return snapshot


def _problem_time_limit_ms(problem):
    try:
        limit_ms = int((problem or {}).get("time_limit_ms") or 2000)
    except (TypeError, ValueError):
        raise ValueError("题目时间限制无效") from None
    if limit_ms <= 0:
        raise ValueError("题目时间限制必须为正整数")
    return limit_ms


def _harness_failure_reason(run_result):
    if run_result.timed_out:
        return "harness 超时"
    if run_result.returncode != 0:
        detail = (run_result.stderr or run_result.stdout).strip()[-600:]
        reason = f"harness 异常退出（{run_result.returncode}）"
        return f"{reason}：{detail}" if detail else reason
    return "harness 未生成预期的测试数据 ZIP"


def _validation_failure_message(validation):
    message = str((validation or {}).get("message") or "标准程序未通过候选测试数据")
    status = str((validation or {}).get("status") or "Unaccepted")
    return f"候选测试数据未发布：{message}（{status}）"


def register_agent_generate_testdata_task(celery_app):
    existing = celery_app.tasks.get(AGENT_GENERATE_TESTDATA_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(
        bind=True,
        name=AGENT_GENERATE_TESTDATA_TASK_NAME,
        time_limit=3600,
        soft_time_limit=3480,
    )
    def agent_generate_testdata(
        self,
        problem_id,
        requested_by,
        test_point_count,
        standard_code,
        data_requirement="",
        standard_filename="",
        harness=None,
        endpoint_id=None,
        session_cookie="",
        session_cookie_name="session",
    ):
        task_id = str(
            getattr(getattr(self, "request", None), "id", None) or ""
        ).strip() or f"unknown-{int(time.time())}"
        point_count = _clamp_int(
            test_point_count,
            10,
            min_value=1,
            max_value=5000,
        )
        standard_program = str(standard_code or "")
        requirement = str(data_requirement or "").strip()
        state = {
            "task_id": task_id,
            "problem_id": int(problem_id),
            "problem_title": "",
            "requested_by": requested_by,
            "task_kind": AGENT_TASK_TESTDATA,
            "harness": str(harness or ""),
            "endpoint_id": endpoint_id,
            "status": "Running",
            "message": "造数据 Agent 启动中",
            "best_score": 0,
            "latest_submission_id": None,
            "final_submission_id": None,
            "attempts": [],
            "events": [],
            "updated_at": _format_local_time(),
        }
        _push_agent_event(state, "造数据 Agent 任务已启动")

        user = get_user_by_username(requested_by)
        if not user or int(user.get("is_admin") or 0) != 1:
            message = "无权限执行造数据 Agent"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        problem = get_problem(problem_id)
        if not problem:
            message = "题目不存在"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}
        if int(problem.get("type") or 1) != 1:
            message = "仅支持编程题"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}
        if int(problem.get("programming_grading_mode") or 1) != 1:
            message = "造数据 Agent 仅支持标准测试点评分模式"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}
        if not standard_program.strip():
            message = "标准程序不能为空"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}
        if len(requirement) > 4000:
            message = "造数据要求不能超过 4000 个字符"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}
        if not str(session_cookie or "").strip():
            message = "Agent 任务身份已失效"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        try:
            endpoint = resolve_launch_endpoint(
                harness,
                endpoint_id,
                include_secret=True,
            )
        except Exception as exc:
            message = str(exc) or "所选 LLM 节点不可用"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        try:
            before_testdata_state = _require_testdata_state(problem_id)
        except Exception as exc:
            message = f"无法读取任务启动前的测试数据状态：{str(exc)[:500]}"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        title = str(problem.get("title") or f"题目 {problem_id}")
        suffix = _LANGUAGE_SUFFIXES.get(
            str(problem.get("lang") or "").strip().lower(),
            ".txt",
        )
        try:
            solution_filename = _safe_standard_solution_filename(
                standard_filename,
                suffix,
            )
            time_limit_ms = _problem_time_limit_ms(problem)
        except ValueError as exc:
            message = str(exc)
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        relative_solution_path = f"task-input/{solution_filename}"
        container_solution_path = f"/workspace/{relative_solution_path}"
        relative_interactor_path = f"task-input/problem_interactor{suffix}"
        if relative_interactor_path == relative_solution_path:
            relative_interactor_path = f"task-input/numoj_problem_interactor{suffix}"
        container_interactor_path = f"/workspace/{relative_interactor_path}"
        state.update({
            "problem_title": title,
            "harness": str(harness),
            "endpoint_id": int(endpoint["id"]),
            "endpoint_model": str(endpoint.get("model") or ""),
        })
        _push_agent_event(
            state,
            f"正在用 {harness} / {endpoint.get('model')} 生成 {point_count} 个测试点",
            event_type="harness_started",
        )

        prompt = build_testdata_agent_prompt(
            problem_id=problem_id,
            problem_title=title,
            problem_language=problem.get("lang"),
            test_point_count=point_count,
            standard_solution_path=container_solution_path,
            interactor_path=container_interactor_path,
            time_limit_ms=time_limit_ms,
            data_requirement=requirement,
        )
        try:
            run_result = run_agent_harness(
                task_id=task_id,
                task_kind=AGENT_TASK_TESTDATA,
                problem_id=int(problem_id),
                requested_by=requested_by,
                harness=harness,
                endpoint=endpoint,
                session_cookie=session_cookie,
                session_cookie_name=session_cookie_name,
                prompt=prompt,
                workspace_files={
                    relative_solution_path: standard_program,
                    relative_interactor_path: str(problem.get("test_code") or ""),
                },
                artifact_files={
                    _STAGED_ZIP_RELATIVE_PATH: _STAGED_ZIP_MAX_BYTES,
                },
            )
        except Exception as exc:
            message = f"造数据 harness 运行失败：{str(exc)[:800]}"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        if run_result.timed_out or run_result.returncode != 0:
            message = f"造数据 Agent 未完成：{_harness_failure_reason(run_result)}"
            _push_agent_event(state, message, level="warning", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        zip_payload = run_result.artifacts.get(_STAGED_ZIP_RELATIVE_PATH)
        if not zip_payload:
            message = f"造数据 Agent 未完成：{_harness_failure_reason(run_result)}"
            _push_agent_event(state, message, level="warning", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        workspace_root = Path(AGENT_WORKSPACE_ROOT).expanduser().resolve()
        workspace_root.mkdir(parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(
                prefix=f"testdata-stage-{re.sub(r'[^a-zA-Z0-9_.-]', '-', task_id)}-",
                dir=workspace_root,
            ) as staging_dir:
                zip_path = Path(staging_dir) / "testdata.zip"
                zip_path.write_bytes(zip_payload)
                zip_path.chmod(0o600)
                parsed = parse_testdata_zip(
                    str(zip_path),
                    str(Path(staging_dir) / "extracted"),
                )
        except Exception as exc:
            message = f"候选测试数据 ZIP 校验失败：{str(exc)[:800]}"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        if int(parsed.get("count") or 0) != point_count:
            message = (
                f"候选测试数据未发布：要求 {point_count} 个测试点，"
                f"实际生成 {int(parsed.get('count') or 0)} 个"
            )
            _push_agent_event(state, message, level="warning", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        _push_agent_event(
            state,
            "候选 ZIP 已安全解析，正在用上传的正解逐点验证",
            event_type="staged_validation_started",
            details={"test_point_count": point_count},
        )
        try:
            validation = validate_staged_testdata(
                problem,
                standard_program,
                parsed["testdata"],
                task_id=task_id,
            )
        except Exception as exc:
            message = f"候选测试数据判题失败：{str(exc)[:800]}"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}

        state["best_score"] = int(validation.get("score") or 0)
        if not validation.get("success"):
            message = _validation_failure_message(validation)
            _push_agent_event(
                state,
                message,
                level="warning",
                status="Failed",
                event_type="staged_validation_failed",
                details={
                    "status": validation.get("status"),
                    "score": validation.get("score"),
                    "test_point_count": point_count,
                },
            )
            return {"success": False, "message": message, "task_id": task_id}

        try:
            published = publish_staged_testdata(
                problem_id,
                before_state=before_testdata_state,
                testdata=parsed["testdata"],
            )
        except Exception as exc:
            message = f"已验证测试数据发布失败：{str(exc)[:800]}"
            _push_agent_event(state, message, level="error", status="Failed")
            return {"success": False, "message": message, "task_id": task_id}
        if not published:
            message = "题目测试数据已被其他管理员修改，本次已验证产物未发布"
            _push_agent_event(
                state,
                message,
                level="warning",
                status="Failed",
                event_type="staged_publish_conflict",
            )
            return {"success": False, "message": message, "task_id": task_id}

        message = f"测试数据已验证并一次性发布，共 {point_count} 个测试点"
        _push_agent_event(
            state,
            message,
            level="success",
            status="Completed",
            event_type="staged_publish_completed",
            details={"test_point_count": point_count},
        )
        return {
            "success": True,
            "message": message,
            "task_id": task_id,
            "test_point_count": point_count,
        }

    return agent_generate_testdata
