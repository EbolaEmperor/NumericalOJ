#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import time

from config import AGENT_MAX_ROUNDS
from oj_modules.db_services import get_problem, get_user_by_username
from oj_modules.tasks.agent.generate_helpers import (
    _build_data_generation_initial_prompt,
    _build_data_generation_tools,
    _resolve_workspace_path,
    _tool_data_agent_create_file,
    _tool_data_agent_diff_text,
    _tool_data_agent_edit_file,
    _tool_data_agent_list_files,
    _tool_data_agent_merge_interactor_with_user_code,
    _tool_data_agent_read_file,
    _tool_data_agent_run_command,
    _tool_data_agent_upload_testdata,
    _tool_data_agent_zip_testdata,
    _truncate_block_text,
)
from oj_modules.tasks.agent.shared import (
    AGENT_GENERATE_TESTDATA_TASK_NAME,
    _AGENT_CONTEXT_KEEP_ROUNDS,
    _AGENT_CONTEXT_MAX_CHARS,
    _AGENT_SUBMIT_LIMIT,
    _append_api_call_log,
    _build_api_request_payload,
    _call_qwen3_coder_plus_with_tools,
    _clamp_int,
    _compact_summary,
    _conversation_total_chars,
    _format_local_time,
    _push_agent_event,
    _safe_json_copy,
    _safe_load_tool_arguments,
    _tool_query_test_results,
    _tool_submit_code,
    _trim_conversation_by_budget,
    _truncate_text,
)


__all__ = ["register_agent_generate_testdata_task"]


def register_agent_generate_testdata_task(celery_app, evaluate_submission_task):
    existing = celery_app.tasks.get(AGENT_GENERATE_TESTDATA_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(bind=True, name=AGENT_GENERATE_TESTDATA_TASK_NAME, time_limit=3600, soft_time_limit=3480)
    def agent_generate_testdata(self, problem_id, requested_by, test_point_count, standard_code, data_requirement=""):
        task_id = str((getattr(getattr(self, "request", None), "id", None) or "")).strip()
        if not task_id:
            task_id = f"unknown-{int(time.time())}"

        n_points = _clamp_int(test_point_count, 10, min_value=1, max_value=5000)
        standard_program = str(standard_code or "")
        data_requirement_text = str(data_requirement or "").strip()
        submit_limit = _AGENT_SUBMIT_LIMIT

        state = {
            "task_id": task_id,
            "problem_id": int(problem_id),
            "problem_title": "",
            "requested_by": requested_by,
            "status": "Running",
            "message": "数据生成 Agent 启动中",
            "round": 0,
            "max_rounds": max(1, int(AGENT_MAX_ROUNDS or 32)),
            "best_score": 0,
            "latest_submission_id": None,
            "final_submission_id": None,
            "attempts": [],
            "events": [],
            "api_calls": [],
            "updated_at": _format_local_time(),
        }
        _push_agent_event(state, "数据生成 Agent 任务已启动")

        user = get_user_by_username(requested_by)
        if not user or user.get("is_admin") != 1:
            _push_agent_event(state, "无权限执行数据生成 Agent", level="error", status="Failed")
            return {"success": False, "message": "无权限执行数据生成 Agent", "task_id": task_id}

        problem = get_problem(problem_id)
        if not problem:
            _push_agent_event(state, "题目不存在", level="error", status="Failed")
            return {"success": False, "message": "题目不存在", "task_id": task_id}
        if int(problem.get("type") or 1) != 1:
            _push_agent_event(state, "仅支持编程题", level="error", status="Failed")
            return {"success": False, "message": "仅支持编程题", "task_id": task_id}
        if evaluate_submission_task is None:
            _push_agent_event(state, "评测任务未初始化", level="error", status="Failed")
            return {"success": False, "message": "评测任务未初始化", "task_id": task_id}
        if not standard_program.strip():
            _push_agent_event(state, "标准程序不能为空", level="error", status="Failed")
            return {"success": False, "message": "标准程序不能为空", "task_id": task_id}

        problem_id_int = int(problem.get("id") or problem_id)
        interactor_code = str(problem.get("test_code") or "")
        workspace_dir = os.path.abspath(os.path.join("tmp", "agent_data_runs", f"{problem_id_int}_{task_id}"))
        os.makedirs(workspace_dir, exist_ok=True)

        _push_agent_event(
            state,
            f"开始生成数据：{problem.get('title', '')}",
            problem_id=problem_id_int,
            problem_title=problem.get("title"),
            event_type="data_gen_start",
            details={"workspace_dir": workspace_dir, "test_point_count": n_points},
        )

        attempts = []
        runtime = {
            "workspace_dir": workspace_dir,
            "test_point_count": n_points,
            "problem_id": problem_id_int,
            "problem_lang": (problem.get("lang") or "cpp").lower(),
            "problem_content": str(problem.get("content") or ""),
            "interactor_code": interactor_code,
            "standard_code": standard_program,
            "data_requirement": data_requirement_text,
            "last_zip_abs_path": "",
            "uploaded": False,
            "uploaded_count": 0,
            "latest_submission_id": None,
            "judge_passed": False,
            "submit_calls": 0,
            "submit_limit": submit_limit,
            "force_fail_submit_limit": False,
            "force_fail_message": "",
        }

        conversation = [{
            "role": "user",
            "content": _build_data_generation_initial_prompt(
                problem=problem,
                interactor_code=interactor_code,
                standard_code=standard_program,
                test_point_count=n_points,
                data_requirement=data_requirement_text,
            ),
        }]
        tools = _build_data_generation_tools()
        total_tool_calls = 0

        system_message = {
            "role": "system",
            "content": (
                "你是一个严格执行流程的数据生成 Agent，你需要为在线评测系统的编程题生成测试数据。"
                "你必须先调用 get_context 获取完整上下文，再进行后续操作。"
                "你只能基于工具返回的真实结果做决策，不能臆造文件、编译结果或评测结果。"
                "当 upload_testdata 与 submit_solution（或 submit_standard_solution）都成功并且评测通过时，任务才完成。"
                f"你最多只能调用 {submit_limit} 次 submit_solution；"
                f"第 {submit_limit} 次返回后若仍未通过，任务会被强制终止并判定失败。"
            ),
        }

        try:
            round_idx = 0
            while True:
                round_idx += 1
                state["round"] = round_idx
                # 强制最大轮数上限，避免无限循环烧 worker/token。
                if round_idx > state["max_rounds"]:
                    msg = f"已达最大轮数 {state['max_rounds']}，数据生成 Agent 停止"
                    _push_agent_event(state, msg, level="warning", status="Failed")
                    return {
                        "success": False,
                        "message": msg,
                        "task_id": task_id,
                        "attempts": attempts,
                    }
                before_chars = _conversation_total_chars(conversation)
                trimmed_conversation = _trim_conversation_by_budget(
                    conversation,
                    max_chars=_AGENT_CONTEXT_MAX_CHARS,
                    keep_rounds=_AGENT_CONTEXT_KEEP_ROUNDS,
                    state=state,
                    round_idx=round_idx,
                )
                if trimmed_conversation != conversation:
                    conversation = trimmed_conversation
                    _push_agent_event(
                        state,
                        (
                            f"上下文裁剪：{before_chars} -> {_conversation_total_chars(conversation)} 字符，"
                            f"保留消息数={len(conversation)}"
                        ),
                    )

                messages = [system_message] + list(conversation)
                api_request_body = _build_api_request_payload(messages, tools=tools)
                _append_api_call_log(state, round_idx, api_request_body, api_type="data_generation")
                _push_agent_event(
                    state,
                    f"第 {round_idx} 轮：数据生成决策中",
                    round=round_idx,
                    event_type="api_request",
                    details={
                        "round": round_idx,
                        "api_type": "data_generation",
                        "request_body": api_request_body,
                    },
                )

                try:
                    assistant_output = _call_qwen3_coder_plus_with_tools(messages, tools=tools)
                except Exception as e:
                    msg = f"第 {round_idx} 轮模型调用失败: {e}"
                    _push_agent_event(state, msg, level="error", status="Failed")
                    return {
                        "success": False,
                        "message": msg,
                        "task_id": task_id,
                        "attempts": attempts,
                    }

                assistant_text = str(assistant_output.get("content") or "").strip()
                tool_calls = assistant_output.get("tool_calls") if isinstance(assistant_output.get("tool_calls"), list) else []

                assistant_message = {"role": "assistant", "content": assistant_text}
                if tool_calls:
                    assistant_message["tool_calls"] = _safe_json_copy(tool_calls, default=[])
                conversation.append(assistant_message)

                if assistant_text:
                    _push_agent_event(state, f"第 {round_idx} 轮模型回复：{_truncate_text(assistant_text, limit=240)}")

                if not tool_calls:
                    _push_agent_event(state, f"第 {round_idx} 轮未调用工具", level="warning")
                    if runtime.get("uploaded") and runtime.get("judge_passed"):
                        break
                    continue

                for tool_call in tool_calls:
                    total_tool_calls += 1

                    call_id = str(tool_call.get("id") or "").strip() or f"tool_call_{round_idx}_{total_tool_calls}"
                    function_data = tool_call.get("function") if isinstance(tool_call.get("function"), dict) else {}
                    func_name = str((function_data or {}).get("name") or "").strip()
                    arguments = _safe_load_tool_arguments((function_data or {}).get("arguments"))

                    _push_agent_event(
                        state,
                        f"第 {round_idx} 轮调用工具：{func_name}",
                        event_type="tool_call",
                        details={
                            "round": round_idx,
                            "tool_name": func_name,
                            "tool_call_id": call_id,
                            "arguments": arguments,
                            "model_tool_call": _safe_json_copy(tool_call, default={}),
                        },
                    )

                    tool_result = {"success": False, "message": f"未知工具：{func_name}"}
                    try:
                        if func_name == "get_context":
                            max_problem_chars = arguments.get("max_problem_chars", 12000)
                            max_interactor_chars = arguments.get("max_interactor_chars", 12000)
                            max_standard_chars = arguments.get("max_standard_chars", 12000)
                            tool_result = {
                                "success": True,
                                "problem_id": runtime["problem_id"],
                                "language": runtime["problem_lang"],
                                "test_point_count": runtime["test_point_count"],
                                "workspace_dir": runtime["workspace_dir"],
                                "problem_requirement": _truncate_block_text(runtime["problem_content"], limit=max_problem_chars),
                                "data_requirement": _truncate_block_text(runtime["data_requirement"], limit=max_problem_chars),
                                "interactor_code": _truncate_block_text(runtime["interactor_code"], limit=max_interactor_chars),
                                "standard_code": _truncate_block_text(runtime["standard_code"], limit=max_standard_chars),
                                "placeholder_count": str(runtime["interactor_code"]).count("%%user_code_here"),
                            }
                        elif func_name == "create_file":
                            created = _tool_data_agent_create_file(
                                workspace_dir=runtime["workspace_dir"],
                                path=arguments.get("path", ""),
                                content=arguments.get("content", ""),
                                overwrite=arguments.get("overwrite", True),
                            )
                            tool_result = {"success": True, **created}
                        elif func_name == "edit_file":
                            edited = _tool_data_agent_edit_file(
                                workspace_dir=runtime["workspace_dir"],
                                path=arguments.get("path", ""),
                                new_content=arguments.get("new_content"),
                                find_text=arguments.get("find_text"),
                                replace_text=arguments.get("replace_text"),
                                replace_all=arguments.get("replace_all", True),
                            )
                            tool_result = {"success": True, **edited}
                        elif func_name == "read_file":
                            read_result = _tool_data_agent_read_file(
                                workspace_dir=runtime["workspace_dir"],
                                path=arguments.get("path", ""),
                                max_chars=arguments.get("max_chars", 12000),
                            )
                            tool_result = {"success": True, **read_result}
                        elif func_name == "list_files":
                            list_result = _tool_data_agent_list_files(
                                workspace_dir=runtime["workspace_dir"],
                                path=arguments.get("path", ""),
                                recursive=arguments.get("recursive", True),
                                max_entries=arguments.get("max_entries", 500),
                            )
                            tool_result = {"success": True, **list_result}
                        elif func_name == "run_command":
                            run_result = _tool_data_agent_run_command(
                                workspace_dir=runtime["workspace_dir"],
                                command=arguments.get("command", ""),
                                timeout_seconds=arguments.get("timeout_seconds", 60),
                            )
                            tool_result = {"success": True, **run_result}
                        elif func_name == "diff_text":
                            diff_result = _tool_data_agent_diff_text(
                                workspace_dir=runtime["workspace_dir"],
                                left_file=arguments.get("left_file", ""),
                                right_file=arguments.get("right_file", ""),
                                context_lines=arguments.get("context_lines", 3),
                            )
                            tool_result = {"success": True, **diff_result}
                        elif func_name == "merge_interactor_with_user_code":
                            interactor_for_merge = arguments.get("interactor_code")
                            if interactor_for_merge is None:
                                interactor_for_merge = runtime["interactor_code"]
                            user_for_merge = arguments.get("user_code")
                            if user_for_merge is None:
                                user_for_merge = runtime["standard_code"]
                            merged_code = _tool_data_agent_merge_interactor_with_user_code(
                                interactor_code=interactor_for_merge,
                                user_code=user_for_merge,
                            )
                            output_path = str(arguments.get("output_path") or "").strip()
                            output_rel_path = ""
                            if output_path:
                                write_result = _tool_data_agent_create_file(
                                    workspace_dir=runtime["workspace_dir"],
                                    path=output_path,
                                    content=merged_code,
                                    overwrite=True,
                                )
                                output_rel_path = write_result.get("path")
                            tool_result = {
                                "success": True,
                                "merged_code": _truncate_block_text(merged_code, limit=20000),
                                "output_path": output_rel_path,
                            }
                        elif func_name == "zip_testdata":
                            zip_result = _tool_data_agent_zip_testdata(
                                workspace_dir=runtime["workspace_dir"],
                                test_point_count=runtime["test_point_count"],
                                data_dir=arguments.get("data_dir", ""),
                                zip_name=arguments.get("zip_name", "testdata.zip"),
                            )
                            runtime["last_zip_abs_path"] = str(zip_result.get("zip_abs_path") or "")
                            tool_result = {
                                "success": True,
                                "zip_path": zip_result.get("zip_path"),
                                "count": zip_result.get("count"),
                            }
                        elif func_name == "upload_testdata":
                            zip_path = str(arguments.get("zip_path") or "").strip()
                            if zip_path:
                                zip_abs_path = _resolve_workspace_path(runtime["workspace_dir"], zip_path)
                            else:
                                zip_abs_path = str(runtime.get("last_zip_abs_path") or "").strip()
                            if not zip_abs_path:
                                raise RuntimeError("缺少 zip_path，且当前没有可用的最近 zip。")
                            upload_result = _tool_data_agent_upload_testdata(
                                problem_id=runtime["problem_id"],
                                zip_abs_path=zip_abs_path,
                                workspace_dir=runtime["workspace_dir"],
                            )
                            runtime["uploaded"] = True
                            runtime["uploaded_count"] = int(upload_result.get("uploaded_count") or 0)
                            _push_agent_event(
                                state,
                                f"测试数据上传成功，共 {runtime['uploaded_count']} 个测试点",
                                level="success",
                                event_type="upload_ok",
                                details={"uploaded_count": runtime["uploaded_count"]},
                            )
                            tool_result = {
                                "success": True,
                                "uploaded_count": runtime["uploaded_count"],
                            }
                        elif func_name in ("submit_standard_solution", "submit_solution"):
                            code_text = str(arguments.get("code") or runtime["standard_code"])
                            if not code_text.strip():
                                raise RuntimeError("缺少可提交的标准程序代码。")
                            timeout_seconds = _clamp_int(arguments.get("timeout_seconds"), 300, min_value=60, max_value=1800)
                            submission_id = _tool_submit_code(
                                problem=problem,
                                username=requested_by,
                                code=code_text,
                                evaluate_submission_task=evaluate_submission_task,
                            )
                            runtime["latest_submission_id"] = int(submission_id)
                            state["latest_submission_id"] = int(submission_id)
                            state["final_submission_id"] = int(submission_id)
                            _push_agent_event(
                                state,
                                f"标准程序已提交，submission_id={submission_id}",
                                latest_submission_id=submission_id,
                                final_submission_id=submission_id,
                                event_type="submission_created",
                            )
                            summary = _tool_query_test_results(submission_id, timeout_seconds=timeout_seconds)
                            compact_summary = _compact_summary(summary)
                            runtime["submit_calls"] = int(runtime.get("submit_calls") or 0) + 1
                            current_submit_calls = int(runtime["submit_calls"])
                            runtime["judge_passed"] = str(compact_summary.get("status") or "") == "Accepted"
                            attempts.append({
                                "round": len(attempts) + 1,
                                "model_round": round_idx,
                                "submission_id": submission_id,
                                "summary": compact_summary,
                            })
                            state["attempts"] = attempts
                            if runtime["judge_passed"]:
                                _push_agent_event(
                                    state,
                                    f"submission_id={submission_id} 已通过全部测试点",
                                    level="success",
                                    event_type="judge_passed",
                                    details={"submission_id": submission_id, "summary": compact_summary},
                                    latest_submission_id=submission_id,
                                    final_submission_id=submission_id,
                                )
                            else:
                                _push_agent_event(
                                    state,
                                    (
                                        f"submission_id={submission_id} 未通过："
                                        f"status={compact_summary.get('status')} score={compact_summary.get('score')}"
                                    ),
                                    level="warning",
                                    event_type="judge_failed",
                                    details={"submission_id": submission_id, "summary": compact_summary},
                                    latest_submission_id=submission_id,
                                    final_submission_id=submission_id,
                                )
                            tool_result = {
                                "success": True,
                                "submission_id": submission_id,
                                "submit_calls": current_submit_calls,
                                "submit_limit": runtime["submit_limit"],
                                "timeout": bool(summary.get("timeout")),
                                "completed": bool(summary.get("completed")),
                                "test_points": summary.get("test_points") or [],
                                **compact_summary,
                            }
                            if (not runtime["judge_passed"]) and current_submit_calls >= int(runtime["submit_limit"]):
                                limit_msg = (
                                    f"submit_solution 调用已达到上限 {runtime['submit_limit']} 次，"
                                    "且仍未通过，任务将被强制终止。"
                                )
                                runtime["force_fail_submit_limit"] = True
                                runtime["force_fail_message"] = limit_msg
                                tool_result["force_terminate"] = True
                                tool_result["message"] = limit_msg
                                _push_agent_event(
                                    state,
                                    limit_msg,
                                    level="warning",
                                    event_type="submit_limit_reached",
                                    details={
                                        "submit_calls": current_submit_calls,
                                        "submit_limit": runtime["submit_limit"],
                                        "submission_id": submission_id,
                                    },
                                )
                        elif func_name == "get_submission_result":
                            try:
                                submission_id = int(arguments.get("submission_id"))
                            except Exception as e:
                                raise RuntimeError("submission_id 无效。") from e
                            if submission_id < 1:
                                raise RuntimeError("submission_id 必须为正整数。")
                            timeout_seconds = _clamp_int(arguments.get("timeout_seconds"), 300, min_value=30, max_value=1800)
                            summary = _tool_query_test_results(submission_id, timeout_seconds=timeout_seconds)
                            compact_summary = _compact_summary(summary)
                            tool_result = {
                                "success": True,
                                "submission_id": submission_id,
                                "timeout": bool(summary.get("timeout")),
                                "completed": bool(summary.get("completed")),
                                "test_points": summary.get("test_points") or [],
                                **compact_summary,
                            }
                        else:
                            tool_result = {"success": False, "message": f"未知工具：{func_name}"}
                    except Exception as tool_err:
                        tool_result = {"success": False, "message": f"{func_name} 执行失败: {tool_err}"}
                        _push_agent_event(
                            state,
                            tool_result["message"],
                            level="warning",
                            event_type="tool_error",
                            details={"round": round_idx, "tool_name": func_name},
                        )

                    tool_content = json.dumps(tool_result, ensure_ascii=False)
                    conversation.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": func_name,
                        "content": tool_content,
                    })
                    if runtime.get("force_fail_submit_limit"):
                        break

                if runtime.get("force_fail_submit_limit"):
                    break

                if runtime.get("uploaded") and runtime.get("judge_passed"):
                    _push_agent_event(
                        state,
                        "数据生成与验证均已完成，结束任务",
                        level="success",
                        status="Completed",
                        event_type="completed",
                        latest_submission_id=runtime.get("latest_submission_id"),
                        final_submission_id=runtime.get("latest_submission_id"),
                    )
                    return {
                        "success": True,
                        "message": "数据生成 Agent 执行成功",
                        "task_id": task_id,
                        "final_submission_id": runtime.get("latest_submission_id"),
                        "attempts": attempts,
                        "workspace_dir": workspace_dir,
                    }

            _push_agent_event(
                state,
                runtime.get("force_fail_message")
                or (
                    "数据生成 Agent 结束，未达到成功条件："
                    f"uploaded={runtime.get('uploaded')} judge_passed={runtime.get('judge_passed')}"
                ),
                level="warning",
                status="Failed",
                final_submission_id=runtime.get("latest_submission_id"),
            )
            return {
                "success": False,
                "message": runtime.get("force_fail_message") or "数据生成 Agent 未完成目标",
                "task_id": task_id,
                "final_submission_id": runtime.get("latest_submission_id"),
                "attempts": attempts,
                "workspace_dir": workspace_dir,
            }
        except Exception as e:
            _push_agent_event(state, f"任务异常：{e}", level="error", status="Failed")
            return {
                "success": False,
                "message": f"任务异常：{e}",
                "task_id": task_id,
                "attempts": attempts,
                "workspace_dir": workspace_dir,
            }

    return agent_generate_testdata
