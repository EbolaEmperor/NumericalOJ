#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oj_modules.db_services import get_problem, get_user_by_username
from oj_modules.tasks.agent_shared import *
from oj_modules.tasks.agent_solve_helpers import *

def register_agent_solve_problem_task(celery_app, evaluate_submission_task):
    existing = celery_app.tasks.get(AGENT_SOLVE_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(bind=True, name=AGENT_SOLVE_TASK_NAME, time_limit=1800, soft_time_limit=1680)
    def agent_solve_problem(self, problem_id, requested_by):
        task_id = str((getattr(getattr(self, "request", None), "id", None) or "")).strip()
        if not task_id:
            task_id = f"unknown-{int(time.time())}"

        submit_limit = _AGENT_SUBMIT_LIMIT

        state = {
            "task_id": task_id,
            "problem_id": int(problem_id),
            "problem_title": "",
            "requested_by": requested_by,
            "status": "Running",
            "message": "Agent 任务启动中",
            "round": 0,
            "max_rounds": 0,
            "best_score": 0,
            "latest_submission_id": None,
            "final_submission_id": None,
            "attempts": [],
            "events": [],
            "api_calls": [],
            "working_memory": _init_working_memory() if _AGENT_MEMORY_ENABLED else {},
            "updated_at": _format_local_time(),
        }
        _push_agent_event(state, "Agent 任务已启动")

        user = get_user_by_username(requested_by)
        if not user or user.get("is_admin") != 1:
            _push_agent_event(state, "无权限执行 Agent 任务", level="error", status="Failed")
            return {
                "success": False,
                "message": "无权限执行 Agent 任务",
                "task_id": task_id,
            }

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

        _push_agent_event(
            state,
            f"开始解题：{problem.get('title', '')}",
            problem_id=problem.get("id"),
            problem_title=problem.get("title"),
        )

        attempts = []
        final_submission_id = None
        core_hints = _extract_problem_hints(problem)
        working_memory = _init_working_memory(core_hints=core_hints)
        state["working_memory"] = working_memory
        if core_hints:
            _push_agent_event(
                state,
                f"已提取题目提示 {len(core_hints)} 条，并作为最高优先级记忆",
                event_type="core_hints",
                details={"core_hints": core_hints},
            )

        initial_code = str(problem.get("initial_code") or "")
        workspace = _initialize_solver_workspace(
            user_id=user["id"],
            problem_id=int(problem.get("id") or problem_id),
            task_id=task_id,
            lang=(problem.get("lang") or "cpp").lower(),
            initial_code=initial_code,
        )
        workspace_dir = str(workspace.get("workspace_dir") or "")
        main_code_path = str(workspace.get("main_code_path") or "")
        workspace_files = workspace.get("synced_files") if isinstance(workspace.get("synced_files"), list) else []

        _push_agent_event(
            state,
            f"已创建工作区：{workspace_dir}",
            event_type="workspace_ready",
            details={
                "workspace_dir": workspace_dir,
                "main_code_path": main_code_path,
                "synced_file_count": len(workspace_files),
            },
        )

        if initial_code.strip():
            _push_agent_event(
                state,
                f"已写入题目初始代码到 {main_code_path}，长度={len(initial_code)} 字符",
                event_type="initial_code",
            )

        runtime = {
            "workspace_dir": workspace_dir,
            "main_code_path": main_code_path,
            "latest_submission_id": None,
            "latest_summary": None,
            "repository_knn_memory": "",
            "accepted": False,
            "submit_calls": 0,
            "submit_limit": submit_limit,
            "force_fail_submit_limit": False,
            "force_fail_message": "",
        }
        knn_memory_text, knn_hits = _build_repository_knn_memory_message(
            user_id=user["id"],
            problem=problem,
        )
        runtime["repository_knn_memory"] = knn_memory_text
        if knn_memory_text:
            _push_agent_event(
                state,
                f"已注入代码仓库向量记忆（KNN 命中 {knn_hits} 条）",
                event_type="repository_knn_memory",
                details={"hit_count": int(knn_hits), "top_k": int(_AGENT_REPOSITORY_MEMORY_TOP_K)},
            )

        conversation = [{
            "role": "user",
            "content": _build_initial_prompt(
                problem,
                workspace_dir=workspace_dir,
                main_code_path=main_code_path,
                core_hints=core_hints,
            ),
        }]
        tools = _build_agent_react_tools()
        total_tool_calls = 0

        round_idx = 0
        while True:
            round_idx += 1
            state["round"] = round_idx
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
            messages = _build_conversation_messages(
                conversation,
                round_idx=round_idx,
                working_memory=working_memory,
                latest_submission_id=runtime.get("latest_submission_id"),
                latest_summary=runtime.get("latest_summary"),
                workspace_dir=runtime.get("workspace_dir") or "",
                main_code_path=runtime.get("main_code_path") or "",
                repository_knn_memory=runtime.get("repository_knn_memory") or "",
            )
            api_request_body = _build_api_request_payload(messages, tools=tools)
            _append_api_call_log(state, round_idx, api_request_body, api_type="solve")
            _push_agent_event(
                state,
                f"第 {round_idx} 轮：ReAct 决策中",
                round=round_idx,
                event_type="api_request",
                details={
                    "round": round_idx,
                    "api_type": "solve",
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
                _push_agent_event(state, f"第 {round_idx} 轮模型回复：{_truncate_text(assistant_text, limit=200)}")

            if not tool_calls:
                _push_agent_event(state, f"第 {round_idx} 轮未调用工具")
                if runtime.get("accepted"):
                    break
                continue

            for tool_call in tool_calls:
                total_tool_calls += 1

                call_id = str(tool_call.get("id") or "").strip()
                if not call_id:
                    call_id = f"tool_call_{round_idx}_{total_tool_calls}"
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
                        tool_result = {
                            "success": True,
                            "language": (problem.get("lang") or "matlab").lower(),
                            "workspace_dir": runtime.get("workspace_dir"),
                            "main_code_path": runtime.get("main_code_path"),
                            "problem_title": problem.get("title"),
                            "problem_content": str(problem.get("content") or ""),
                        }
                    elif func_name == "list_files":
                        files = _tool_workspace_list_files(
                            workspace_dir=runtime["workspace_dir"],
                            path=arguments.get("path", ""),
                            recursive=arguments.get("recursive", True),
                            max_entries=arguments.get("max_entries", 500),
                        )
                        tool_result = {"success": True, **files}
                    elif func_name == "read_file":
                        read_result = _tool_workspace_read_file(
                            workspace_dir=runtime["workspace_dir"],
                            path=arguments.get("path", ""),
                            max_chars=arguments.get("max_chars", 12000),
                        )
                        tool_result = {"success": True, **read_result}
                    elif func_name == "create_file":
                        created = _tool_workspace_create_file(
                            workspace_dir=runtime["workspace_dir"],
                            path=arguments.get("path", ""),
                            content=arguments.get("content", ""),
                            overwrite=arguments.get("overwrite", True),
                        )
                        tool_result = {"success": True, **created}
                    elif func_name == "edit_file":
                        edited = _tool_workspace_edit_file(
                            workspace_dir=runtime["workspace_dir"],
                            path=arguments.get("path", ""),
                            new_content=arguments.get("new_content"),
                            find_text=arguments.get("find_text"),
                            replace_text=arguments.get("replace_text"),
                            replace_all=arguments.get("replace_all", True),
                        )
                        tool_result = {"success": True, **edited}
                    elif func_name == "run_command":
                        run_result = _tool_workspace_run_command(
                            workspace_dir=runtime["workspace_dir"],
                            command=arguments.get("command", ""),
                            timeout_seconds=arguments.get("timeout_seconds", 60),
                        )
                        tool_result = {"success": True, **run_result}
                    elif func_name == "search_useful_code":
                        search_result = _tool_search_useful_code(
                            user_id=user["id"],
                            description=arguments.get("description", ""),
                            top_k=arguments.get("top_k", _AGENT_REPOSITORY_MEMORY_TOP_K),
                        )
                        tool_result = {"success": True, **search_result}
                    elif func_name == "submit_evaluation":
                        source_path = str(arguments.get("source_path") or runtime.get("main_code_path") or "").strip()
                        if not source_path:
                            raise RuntimeError("缺少 source_path，且未配置默认主代码文件。")
                        source_abs = _resolve_workspace_path(runtime["workspace_dir"], source_path)
                        if not os.path.isfile(source_abs):
                            raise RuntimeError(f"待提交代码文件不存在：{source_path}")
                        with open(source_abs, "r", encoding="utf-8", errors="replace") as f:
                            code_text = f.read()
                        if not code_text.strip():
                            raise RuntimeError("待提交代码为空。")

                        timeout_seconds = _clamp_int(arguments.get("timeout_seconds"), 300, min_value=60, max_value=900)
                        synced_headers = _tool_sync_workspace_headers_to_repository(
                            user_id=user["id"],
                            workspace_dir=runtime["workspace_dir"],
                        )
                        synced_count = int(synced_headers.get("synced_count") or 0)
                        skipped_headers = synced_headers.get("skipped_files") if isinstance(synced_headers.get("skipped_files"), list) else []
                        submission_id = _tool_submit_code(problem, requested_by, code_text, evaluate_submission_task)
                        final_submission_id = submission_id
                        runtime["latest_submission_id"] = submission_id
                        _push_agent_event(
                            state,
                            f"第 {round_idx} 轮已提交，submission_id={submission_id}",
                            latest_submission_id=submission_id,
                            final_submission_id=submission_id,
                        )

                        summary = _tool_query_test_results(submission_id, timeout_seconds=timeout_seconds)
                        compact_summary = _compact_summary(summary)
                        runtime["latest_summary"] = compact_summary
                        is_accepted = str(compact_summary.get("status") or "").strip() == "Accepted"
                        runtime["accepted"] = is_accepted
                        runtime["submit_calls"] = int(runtime.get("submit_calls") or 0) + 1
                        current_submit_calls = int(runtime["submit_calls"])

                        diag = _extract_retry_diagnosis(assistant_text) or _truncate_text(assistant_text, limit=360)
                        failure_signature = _build_failure_signature(compact_summary)
                        attempt_item = {
                            "round": len(attempts) + 1,
                            "model_round": round_idx,
                            "submission_id": submission_id,
                            "summary": compact_summary,
                            "diagnosis": diag,
                            "failure_signature": failure_signature,
                            "api_request_body": api_request_body,
                        }
                        attempts.append(attempt_item)
                        state["attempts"] = attempts

                        if _AGENT_MEMORY_ENABLED:
                            memory_delta = _update_working_memory(
                                working_memory,
                                round_idx=round_idx,
                                diagnosis=diag,
                                eval_summary=compact_summary,
                            )
                            state["working_memory"] = working_memory
                            attempts[-1]["memory"] = _compact_working_memory_for_attempt(working_memory)
                            _push_agent_event(
                                state,
                                (
                                    f"工作记忆更新：signature={memory_delta.get('signature')} "
                                    f"patterns={memory_delta.get('pattern_count')}"
                                ),
                            )

                        _push_agent_event(
                            state,
                            (
                                f"第 {round_idx} 轮评测完成："
                                f"状态={compact_summary.get('status')} 分数={compact_summary.get('score')}"
                            ),
                            latest_submission_id=submission_id,
                            final_submission_id=submission_id,
                        )

                        if summary.get("timeout"):
                            _push_agent_event(
                                state,
                                f"第 {round_idx} 轮评测等待超时",
                                level="warning",
                                event_type="judge_timeout",
                                details={"round": round_idx, "submission_id": submission_id},
                            )

                        if is_accepted:
                            msg = "任务已成功完成"
                            _push_agent_event(
                                state,
                                f"第 {round_idx} 轮提交已通过全部测试点，结束任务",
                                level="success",
                                status="Completed",
                                event_type="accepted",
                                details={
                                    "round": round_idx,
                                    "submission_id": submission_id,
                                    "status": compact_summary.get("status"),
                                    "score": compact_summary.get("score"),
                                },
                                final_submission_id=submission_id,
                            )
                            return {
                                "success": True,
                                "message": msg,
                                "task_id": task_id,
                                "final_submission_id": submission_id,
                                "attempts": attempts,
                            }

                        raw_test_points = summary.get("test_points") if isinstance(summary.get("test_points"), list) else []
                        raw_failed_points = summary.get("failed_points") if isinstance(summary.get("failed_points"), list) else []
                        judge_result = {
                            "status": compact_summary.get("status"),
                            "score": compact_summary.get("score"),
                            "accepted_count": compact_summary.get("accepted_count"),
                            "total_count": compact_summary.get("total_count"),
                            "timeout": bool(summary.get("timeout")),
                            "completed": bool(summary.get("completed")),
                            "failed_points": raw_failed_points,
                        }
                        if not raw_test_points:
                            judge_result["note"] = "当前评测未返回测试点明细（可能是编译阶段失败，或题目尚未配置测试点）。"

                        tool_result = {
                            "success": True,
                            "source_path": os.path.relpath(source_abs, runtime["workspace_dir"]),
                            "header_sync": {
                                "synced_count": synced_count,
                                "skipped_count": len(skipped_headers),
                            },
                            "submission_id": submission_id,
                            "submit_calls": current_submit_calls,
                            "submit_limit": runtime["submit_limit"],
                            "judge_result": judge_result,
                            "timeout": bool(summary.get("timeout")),
                            "completed": bool(summary.get("completed")),
                            "test_points": raw_test_points,
                            "failed_points": raw_failed_points,
                            **compact_summary,
                        }
                        if (not is_accepted) and current_submit_calls >= int(runtime["submit_limit"]):
                            limit_msg = (
                                f"submit_evaluation 调用已达到上限 {runtime['submit_limit']} 次，"
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

        if runtime.get("accepted"):
            msg = "任务已成功完成"
            _push_agent_event(
                state,
                msg,
                level="success",
                status="Completed",
                event_type="accepted",
                final_submission_id=final_submission_id,
            )
            return {
                "success": True,
                "message": msg,
                "task_id": task_id,
                "final_submission_id": final_submission_id,
                "attempts": attempts,
            }

        fail_message = runtime.get("force_fail_message") or "Agent 任务结束，未通过全部测试点"
        _push_agent_event(
            state,
            fail_message,
            level="warning",
            status="Failed",
            final_submission_id=final_submission_id,
        )
        return {
            "success": False,
            "message": fail_message,
            "task_id": task_id,
            "final_submission_id": final_submission_id,
            "attempts": attempts,
        }

    return agent_solve_problem
