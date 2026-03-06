#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import time

import requests

from config import AGENT_MAX_ROUNDS, DASHSCOPE_API_KEY
from oj_modules.db_services import (
    create_submission,
    get_problem,
    get_submission_by_id,
    get_user_by_username,
)

try:
    from openai import OpenAI
except Exception:
    OpenAI = None

try:
    import redis
except Exception:
    redis = None


AGENT_SOLVE_TASK_NAME = "oj.agent.solve_problem"
_DEFAULT_DASHSCOPE_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
_agent_progress_rds = None
_AGENT_PROGRESS_TTL_SECONDS = 21600


def init_agent_progress_cache(redis_client, ttl_seconds=None):
    global _agent_progress_rds, _AGENT_PROGRESS_TTL_SECONDS
    _agent_progress_rds = redis_client
    if ttl_seconds is not None:
        try:
            _AGENT_PROGRESS_TTL_SECONDS = max(300, int(ttl_seconds))
        except Exception:
            pass


def _ensure_agent_progress_redis():
    global _agent_progress_rds
    if _agent_progress_rds is not None:
        return _agent_progress_rds
    if redis is None:
        return None

    try:
        _agent_progress_rds = redis.StrictRedis(
            host=os.getenv('REDIS_HOST', '127.0.0.1'),
            port=int(os.getenv('REDIS_PORT', '6379')),
            db=int(os.getenv('REDIS_DB', '0')),
            decode_responses=True,
        )
        _agent_progress_rds.ping()
    except Exception:
        _agent_progress_rds = None
    return _agent_progress_rds


def _agent_progress_key(task_id):
    return f"agent_run:{task_id}"


def _agent_progress_channel(task_id):
    return f"agent_run_events:{task_id}"


def get_agent_run_snapshot(task_id):
    if not task_id:
        return None
    client = _ensure_agent_progress_redis()
    if client is None:
        return None
    try:
        raw = client.get(_agent_progress_key(task_id))
        if not raw:
            return None
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def subscribe_agent_run_events(task_id):
    if not task_id:
        return None
    client = _ensure_agent_progress_redis()
    if client is None:
        return None
    try:
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(_agent_progress_channel(task_id))
        return pubsub
    except Exception:
        return None


def _format_local_time(ts=None):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts or time.time()))


def _persist_agent_state(state):
    if not isinstance(state, dict):
        return
    client = _ensure_agent_progress_redis()
    if client is None:
        return
    task_id = str(state.get("task_id") or "").strip()
    if not task_id:
        return
    state["updated_at"] = _format_local_time()
    payload = json.dumps(state, ensure_ascii=False)
    try:
        client.setex(_agent_progress_key(task_id), _AGENT_PROGRESS_TTL_SECONDS, payload)
        client.publish(_agent_progress_channel(task_id), payload)
    except Exception:
        pass


def _push_agent_event(state, event_message, level="info", **updates):
    if not isinstance(state, dict):
        return
    for k, v in updates.items():
        state[k] = v

    state["message"] = updates.get("message", event_message)
    events = state.get("events") or []
    events.append({
        "time": _format_local_time(),
        "level": level,
        "message": str(event_message or "").strip(),
    })
    if len(events) > 120:
        events = events[-120:]
    state["events"] = events
    _persist_agent_state(state)


def _compact_summary(summary):
    if not isinstance(summary, dict):
        return {
            "status": "Error",
            "score": 0,
            "accepted_count": 0,
            "total_count": 0,
            "timeout": False,
            "failed_points": [],
        }
    failed_points = summary.get("failed_points") or []
    return {
        "status": summary.get("status"),
        "score": summary.get("score", 0),
        "accepted_count": summary.get("accepted_count", 0),
        "total_count": summary.get("total_count", 0),
        "timeout": bool(summary.get("timeout")),
        "failed_points": failed_points[:5],
    }


def _ensure_dashscope_api_key():
    api_key = os.getenv("DASHSCOPE_API_KEY") or DASHSCOPE_API_KEY
    if not api_key or str(api_key).strip() == "" or "YOUR" in str(api_key).upper():
        raise RuntimeError("未配置 DASHSCOPE_API_KEY。")
    return api_key


def _extract_text_from_content(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    return ""


def _call_qwen3_coder_plus(messages, timeout=180):
    api_key = _ensure_dashscope_api_key()
    base_url = os.getenv("DASHSCOPE_BASE_URL", _DEFAULT_DASHSCOPE_BASE_URL).rstrip("/")
    model = os.getenv("QWEN_CODER_MODEL", "qwen3-coder-plus")

    if OpenAI is not None:
        try:
            client = OpenAI(api_key=api_key, base_url=base_url)
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                stream=False,
            )
            choices = getattr(resp, "choices", None) or []
            if choices and getattr(choices[0], "message", None):
                content = choices[0].message.content
                text = _extract_text_from_content(content).strip()
                if text:
                    return text
        except Exception as e:
            print(f"[Agent] OpenAI SDK 调用失败，尝试 requests 回退: {e}")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
    }
    resp = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("模型未返回有效结果。")
    message = choices[0].get("message") or {}
    content = message.get("content")
    text = _extract_text_from_content(content).strip()
    if not text:
        raise RuntimeError("模型未返回有效代码文本。")
    return text


def _extract_code_from_model_reply(reply_text, lang):
    text = (reply_text or "").strip()
    if not text:
        return ""

    lang_map = {
        "cpp": ["cpp", "c++", "cc", "cxx"],
        "c": ["c"],
        "python": ["python", "py"],
        "py": ["python", "py"],
        "matlab": ["matlab", "octave", "m"],
    }
    aliases = lang_map.get((lang or "").lower(), [])

    for alias in aliases:
        m = re.search(rf"```{re.escape(alias)}\s*(.*?)\s*```", text, flags=re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip()

    m = re.search(r"```(?:\w+)?\s*(.*?)\s*```", text, flags=re.DOTALL)
    if m:
        return m.group(1).strip()

    return text


def _truncate_text(value, limit=300):
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _extract_retry_diagnosis(reply_text):
    text = str(reply_text or "").strip()
    if not text:
        return ""

    marker = re.search(r"【诊断】\s*(.*?)\s*(【代码】|```)", text, flags=re.DOTALL)
    if marker:
        return _truncate_text(marker.group(1), limit=600)

    fence_pos = text.find("```")
    if fence_pos > 0:
        return _truncate_text(text[:fence_pos], limit=600)

    return ""


def _summarize_submission(submission):
    if not submission:
        return {
            "status": "Error",
            "score": 0,
            "accepted_count": 0,
            "total_count": 0,
            "failed_points": [],
        }

    points = submission.get("test_points") or []
    if not isinstance(points, list):
        points = []

    accepted = 0
    failed_points = []
    for idx, tp in enumerate(points, start=1):
        status = str((tp or {}).get("status") or "Error")
        if status == "Accepted":
            accepted += 1
            continue
        failed_points.append({
            "index": idx,
            "status": status,
            "stderr": _truncate_text((tp or {}).get("stderr")),
            "stdout": _truncate_text((tp or {}).get("stdout")),
            "time": (tp or {}).get("time", 0),
        })

    return {
        "status": submission.get("status"),
        "score": submission.get("score", 0),
        "accepted_count": accepted,
        "total_count": len(points),
        "failed_points": failed_points,
    }


def _tool_submit_code(problem, username, code, evaluate_submission_task):
    print(f"[AgentTool] submit_code by {username} for problem={problem['id']}")
    submission_id = create_submission(
        problem_id=problem["id"],
        problem_title=problem["title"],
        username=username,
        code=code,
        score=0,
        test_points=[],
    )
    if not submission_id or int(submission_id) <= 0:
        raise RuntimeError(f"invalid submission id: {submission_id}")
    evaluate_submission_task.delay(submission_id)
    return submission_id


def _tool_query_test_results(submission_id, timeout_seconds=240):
    print(f"[AgentTool] query_test_results submission_id={submission_id}")
    deadline = time.time() + max(30, int(timeout_seconds))
    not_found_count = 0
    while time.time() < deadline:
        sub = get_submission_by_id(submission_id)
        if not sub:
            # 提交刚创建后，短时间内可能读不到（事务可见性/连接瞬时异常），先容错重试
            not_found_count += 1
            if not_found_count < 10:
                time.sleep(0.6)
                continue
            return {"timeout": True, **_summarize_submission(None)}

        not_found_count = 0
        status = sub.get("status")
        if status not in ("Pending", "Waiting", "Running"):
            return {"timeout": False, **_summarize_submission(sub)}
        time.sleep(1.5)

    # 超时后返回当前快照
    sub = get_submission_by_id(submission_id)
    return {"timeout": True, **_summarize_submission(sub)}


def _build_initial_prompt(problem):
    lang = (problem.get("lang") or "matlab").lower()
    initial_code = (problem.get("initial_code") or "").strip()
    initial_code_part = (
        f"\n\n题目初始代码（你必须基于此代码继续实现，而不是忽略它）：\n{initial_code}\n"
        if initial_code else
        "\n\n题目未提供初始代码，可自行从零实现。\n"
    )
    return (
        "你是一个 ACM/OJ 解题助手。"
        "请根据题目描述输出可通过评测的完整代码。"
        "输出必须是最终代码，不要解释。\n\n"
        f"目标语言: {lang}\n"
        f"题目标题: {problem.get('title', '')}\n"
        "题目描述如下：\n"
        f"{problem.get('content', '')}\n\n"
        "如果题目提供了模板，你必须在模板风格下补全可运行代码。"
        f"{initial_code_part}"
    )


def _build_retry_prompt(problem, last_code, eval_summary):
    failed_text = []
    for fp in eval_summary.get("failed_points", [])[:6]:
        failed_text.append(
            f"测试点#{fp['index']} 状态={fp['status']} "
            f"stderr={fp['stderr']} stdout={fp['stdout']}"
        )
    failed_joined = "\n".join(failed_text) if failed_text else "无失败详情"
    lang = (problem.get("lang") or "matlab").lower()
    initial_code = (problem.get("initial_code") or "").strip()
    initial_code_part = (
        f"\n\n题目初始代码（必须保持其接口/结构约束）：\n{initial_code}\n"
        if initial_code else
        ""
    )
    return (
        "请基于上一版代码修复错误并输出完整新代码。\n"
        "请按以下格式输出：\n"
        "【诊断】\n"
        "1) 根因：...\n"
        "2) 修复：...\n"
        "3) 风险：...\n"
        "【代码】\n"
        "```语言\n"
        "<完整代码>\n"
        "```\n\n"
        f"目标语言: {lang}\n"
        f"题目标题: {problem.get('title', '')}\n"
        "题目描述：\n"
        f"{problem.get('content', '')}\n\n"
        "上一版代码：\n"
        f"{last_code}\n\n"
        "最新评测反馈：\n"
        f"状态={eval_summary.get('status')} 分数={eval_summary.get('score')}\n"
        f"{failed_joined}\n"
        f"{initial_code_part}"
    )


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
            cfg_rounds = 3
        max_rounds = max(1, cfg_rounds)

        state = {
            "task_id": task_id,
            "problem_id": int(problem_id),
            "requested_by": requested_by,
            "status": "Running",
            "message": "Agent 任务启动中",
            "round": 0,
            "max_rounds": max_rounds,
            "latest_submission_id": None,
            "final_submission_id": None,
            "attempts": [],
            "events": [],
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
        )

        attempts = []
        last_code = ""
        final_submission_id = None

        for round_idx in range(1, max_rounds + 1):
            _push_agent_event(
                state,
                f"第 {round_idx}/{max_rounds} 轮：生成代码中",
                round=round_idx,
            )

            if round_idx == 1:
                user_prompt = _build_initial_prompt(problem)
            else:
                prev = attempts[-1]["summary"] if attempts else {}
                user_prompt = _build_retry_prompt(problem, last_code, prev)

            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a helpful coding agent. Return only final source code."
                        if round_idx == 1 else
                        (
                            "You are a helpful coding agent. "
                            "For retry rounds, provide a concise structured diagnosis first, "
                            "then provide complete final source code in a fenced code block."
                        )
                    ),
                },
                {"role": "user", "content": user_prompt},
            ]

            try:
                model_reply = _call_qwen3_coder_plus(messages)
            except Exception as e:
                msg = f"第 {round_idx} 轮模型调用失败: {e}"
                _push_agent_event(state, msg, level="error", status="Failed")
                return {
                    "success": False,
                    "message": msg,
                    "task_id": task_id,
                    "attempts": attempts,
                }

            code = _extract_code_from_model_reply(model_reply, problem.get("lang"))
            if round_idx > 1:
                diag = _extract_retry_diagnosis(model_reply)
                if diag:
                    _push_agent_event(state, f"模型诊断摘要：{diag}")
            if not code.strip():
                msg = f"第 {round_idx} 轮未生成有效代码"
                _push_agent_event(state, msg, level="error", status="Failed")
                return {
                    "success": False,
                    "message": msg,
                    "task_id": task_id,
                    "attempts": attempts,
                }

            last_code = code
            _push_agent_event(state, f"第 {round_idx} 轮代码已生成，准备提交")

            try:
                submission_id = _tool_submit_code(problem, requested_by, code, evaluate_submission_task)
            except Exception as e:
                msg = f"第 {round_idx} 轮提交失败: {e}"
                _push_agent_event(state, msg, level="error", status="Failed")
                return {
                    "success": False,
                    "message": msg,
                    "task_id": task_id,
                    "attempts": attempts,
                }

            final_submission_id = submission_id
            _push_agent_event(
                state,
                f"第 {round_idx} 轮已提交，submission_id={submission_id}",
                latest_submission_id=submission_id,
                final_submission_id=submission_id,
            )

            summary = _tool_query_test_results(submission_id, timeout_seconds=300)
            compact_summary = _compact_summary(summary)
            attempts.append({
                "round": round_idx,
                "submission_id": submission_id,
                "summary": compact_summary,
            })
            state["attempts"] = attempts
            _push_agent_event(
                state,
                (
                    f"第 {round_idx} 轮评测完成："
                    f"状态={compact_summary.get('status')} 分数={compact_summary.get('score')}"
                ),
            )

            if summary.get("status") == "Accepted":
                msg = f"Agent 在第 {round_idx} 轮通过"
                _push_agent_event(
                    state,
                    msg,
                    level="success",
                    status="Completed",
                    final_submission_id=submission_id,
                )
                return {
                    "success": True,
                    "message": msg,
                    "task_id": task_id,
                    "final_submission_id": submission_id,
                    "attempts": attempts,
                }

            if summary.get("timeout"):
                _push_agent_event(
                    state,
                    f"第 {round_idx} 轮评测超时，提前结束",
                    level="warning",
                )
                break

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
