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

        try:
            cfg_rounds = int(AGENT_MAX_ROUNDS)
        except Exception:
            cfg_rounds = 8
        max_rounds = max(1, cfg_rounds)
        max_tool_calls = max(8, max_rounds * 8)

        state = {
            "task_id": task_id,
            "problem_id": int(problem_id),
            "problem_title": "",
            "requested_by": requested_by,
            "status": "Running",
            "message": "Agent 任务启动中",
            "round": 0,
            "max_rounds": max_rounds,
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

        latest_code = str(problem.get("initial_code") or "")
        runtime = {
            "latest_code": latest_code,
            "latest_submission_id": None,
            "latest_summary": None,
            "last_ai_tutor_feedback": "",
            "submission_code_map": {},
            "accepted": False,
        }

        if latest_code.strip():
            _push_agent_event(
                state,
                f"检测到题目初始代码，长度={len(latest_code)} 字符",
                event_type="initial_code",
            )

        repository_filenames = []
        try:
            repo_rows = _tool_list_repository_files(user_id=user["id"], limit=200)
            if isinstance(repo_rows, list):
                for row in repo_rows:
                    if isinstance(row, dict):
                        name = str(row.get("filename") or "").strip()
                        if name:
                            repository_filenames.append(name)
            if repository_filenames:
                _push_agent_event(
                    state,
                    f"已读取代码仓库文件列表，共 {len(repository_filenames)} 个文件",
                    event_type="repository_files",
                )
        except Exception as repo_err:
            _push_agent_event(
                state,
                f"读取代码仓库文件列表失败: {repo_err}",
                level="warning",
                event_type="repository_files_error",
            )

        conversation = [{
            "role": "user",
            "content": _build_initial_prompt(
                problem,
                core_hints=core_hints,
                repository_filenames=repository_filenames,
            ),
        }]
        tools = _build_agent_react_tools()
        total_tool_calls = 0

        for round_idx in range(1, max_rounds + 1):
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
                last_ai_tutor_feedback=runtime.get("last_ai_tutor_feedback") or "",
            )
            api_request_body = _build_api_request_payload(messages, tools=tools)
            _append_api_call_log(state, round_idx, api_request_body, api_type="solve")
            _push_agent_event(
                state,
                f"第 {round_idx}/{max_rounds} 轮：ReAct 决策中",
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
                break

            for tool_call in tool_calls:
                if total_tool_calls >= max_tool_calls:
                    break
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
                    if func_name == "read_latest_code":
                        code_text = str(runtime.get("latest_code") or "")
                        tool_result = {
                            "success": True,
                            "has_code": bool(code_text.strip()),
                            "language": (problem.get("lang") or "matlab").lower(),
                            "chars": len(code_text),
                            "latest_code": code_text,
                        }
                    elif func_name == "update_code":
                        code_text = str(arguments.get("code") or "")
                        if not code_text.strip():
                            raise RuntimeError("code 不能为空。")
                        runtime["latest_code"] = code_text
                        tool_result = {
                            "success": True,
                            "message": "代码已更新",
                            "chars": len(code_text),
                            "note": _truncate_text(arguments.get("note"), limit=200),
                        }
                    elif func_name == "submit_evaluation":
                        if arguments.get("code") is not None:
                            incoming_code = str(arguments.get("code") or "")
                            if incoming_code.strip():
                                runtime["latest_code"] = incoming_code
                        code_text = str(runtime.get("latest_code") or "")
                        if not code_text.strip():
                            raise RuntimeError("当前没有可提交代码，请先调用 update_code。")

                        timeout_seconds = _clamp_int(arguments.get("timeout_seconds"), 300, min_value=60, max_value=900)
                        submission_id = _tool_submit_code(problem, requested_by, code_text, evaluate_submission_task)
                        final_submission_id = submission_id
                        runtime["latest_submission_id"] = submission_id
                        runtime["submission_code_map"][str(submission_id)] = code_text
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
                                latest_code=code_text,
                            )
                            state["working_memory"] = working_memory
                            attempts[-1]["memory"] = _compact_working_memory_for_attempt(working_memory)
                            _push_agent_event(
                                state,
                                (
                                    f"工作记忆更新：signature={memory_delta.get('signature')} "
                                    f"patterns={memory_delta.get('pattern_count')} "
                                    f"high_risk={memory_delta.get('high_risk_count')} "
                                    f"do_not_repeat={memory_delta.get('do_not_repeat_count')}"
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

                        tool_result = {
                            "success": True,
                            "submission_id": submission_id,
                            "timeout": bool(summary.get("timeout")),
                            "completed": bool(summary.get("completed")),
                            "test_points": summary.get("test_points") or [],
                            **compact_summary,
                        }
                    elif func_name == "ask_ai_tutor":
                        tool_result = {
                            "success": False,
                            "disabled": True,
                            "message": "ask_ai_tutor 功能暂时禁用",
                        }
                    elif func_name == "list_repository_files":
                        files = _tool_list_repository_files(
                            user_id=user["id"],
                            limit=arguments.get("limit", 200),
                        )
                        tool_result = {"success": True, "count": len(files), "files": files}
                    elif func_name == "read_repository_file":
                        file_content = _tool_read_repository_file(
                            user_id=user["id"],
                            filename=arguments.get("filename", ""),
                            file_id=arguments.get("file_id"),
                            max_chars=arguments.get("max_chars", 12000),
                        )
                        tool_result = {"success": True, "content": file_content}
                    elif func_name == "read_repository_file_full":
                        file_content = _tool_read_repository_file_full(
                            user_id=user["id"],
                            filename=arguments.get("filename", ""),
                            file_id=arguments.get("file_id"),
                        )
                        tool_result = {"success": True, "content": file_content}
                    elif func_name == "update_repository_file":
                        updated = _tool_update_repository_file(
                            user_id=user["id"],
                            filename=arguments.get("filename", ""),
                            file_id=arguments.get("file_id"),
                            content=arguments.get("content", ""),
                        )
                        tool_result = {"success": True, **updated}
                    elif func_name == "search_repository":
                        result = _tool_search_repository(
                            user_id=user["id"],
                            pattern=arguments.get("pattern", ""),
                            max_files=arguments.get("max_files", 500),
                            max_matches=arguments.get("max_matches", 120),
                        )
                        tool_result = {"success": True, **result}
                    elif func_name == "get_knowledge":
                        knowledge = _tool_get_knowledge(
                            question=arguments.get("question", ""),
                            max_chars=arguments.get("max_chars", 1800),
                        )
                        tool_result = {"success": True, **knowledge}
                    elif func_name == "planning":
                        planning_result = _tool_planning(messages=messages)
                        tool_result = {"success": True, **planning_result}
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

            if total_tool_calls >= max_tool_calls:
                _push_agent_event(
                    state,
                    f"工具调用次数已达上限({max_tool_calls})，结束任务",
                    level="warning",
                )
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

        _push_agent_event(
            state,
            "Agent 任务结束，未通过全部测试点",
            level="warning",
            status="Failed",
            final_submission_id=final_submission_id,
        )
        return {
            "success": False,
            "message": "Agent 任务结束，未通过全部测试点",
            "task_id": task_id,
            "final_submission_id": final_submission_id,
            "attempts": attempts,
        }

    return agent_solve_problem

