"""已完成 Harbor Trial 的输出保存故障恢复；不放宽普通 Agent 终态。"""

import json

from backend.oj_modules.infrastructure.mysql import get_db_connection


PRESERVATION_FAILURES = frozenset({
    "解答记录保存失败，请联系管理员处理。",
    "解答过程暂时无法查看，请联系管理员处理。",
    "Harbor 原生会话保存失败，已保留执行目录与端点名额",
    "Harbor 完整会话导入失败，已保留执行目录与端点名额",
})
STEP_FAILURE = "评测未完成，请联系管理员处理。"
_STEP_FAILURE_MESSAGES = frozenset({
    STEP_FAILURE,
    "通用 Agent 清理失败，端点名额已保留，请管理员处理后重测",
})
RECOVERY_MESSAGE = "解答记录已保存，等待评分。"


class HarborRecoveryError(ValueError):
    pass


def _object(value):
    result = json.loads(value) if isinstance(value, (str, bytes)) else value
    if not isinstance(result, dict):
        raise HarborRecoveryError("Harbor 恢复关联记录不是有效对象")
    return result


def _read_candidate(cursor, task_id, *, locked=False):
    cursor.execute("""
        SELECT s.session_id, s.current_task_id, s.task_kind, s.judge_kind,
               s.submission_id, s.attempt_id, s.competition_id, s.harness,
               s.native_session_id, s.runtime_config_json, s.endpoint_id,
               s.status AS session_status, s.message AS session_message,
               t.task_id, t.status AS turn_status, t.conclusion,
               r.status AS run_status, r.message AS run_message,
               b.status AS submission_status, b.judge_attempt_id,
               b.competition_id AS submission_competition_id,
               c.scoring_mode,
               p.status AS agent_step_status, p.result_json AS agent_step_result,
               p.error_message AS agent_step_error
        FROM agent_sessions AS s
        JOIN agent_session_turns AS t
          ON t.session_id=s.session_id AND t.task_id=s.current_task_id
             AND t.superseded_at IS NULL
        JOIN agent_task_runs AS r ON r.task_id=t.task_id
        JOIN ranking_submissions AS b ON b.id=s.submission_id
        JOIN ranking_competitions AS c ON c.id=b.competition_id
        JOIN ranking_reverse_judge_steps AS p
          ON p.submission_id=b.id AND p.step_key='agent_answer'
        WHERE t.task_id=%s
        LIMIT 1
    """ + (" FOR UPDATE" if locked else ""), (task_id,))
    row = cursor.fetchone()
    if not row:
        raise HarborRecoveryError("找不到当前 Harbor 反向作答轮次")
    row = dict(row)
    row["runtime_config"] = _object(row["runtime_config_json"])
    row["agent_result"] = _object(row["agent_step_result"])
    validate_harbor_recovery_candidate(row, task_id)
    return row


def validate_harbor_recovery_candidate(row, task_id):
    if (row.get("task_id") != task_id or row.get("current_task_id") != task_id
            or row.get("task_kind") != "judge" or row.get("judge_kind") != "reverse_answer"
            or row.get("scoring_mode") != "reverse_judge"
            or not row.get("attempt_id") or row.get("attempt_id") != row.get("judge_attempt_id")
            or row.get("competition_id") != row.get("submission_competition_id")):
        raise HarborRecoveryError("拒绝恢复：任务不是原提交的当前 Harbor Judge attempt")
    runtime_config = row.get("runtime_config") or {}
    if (not isinstance(runtime_config.get("harbor_runtime"), dict)
            or runtime_config.get("endpoint_source") != "competition"):
        raise HarborRecoveryError("Judge 轮次没有冻结的 Harbor 运行配置")
    state = (row.get("agent_result") or {}).get("_agent") or {}
    if state.get("task_id") != task_id or state.get("session_id") != row.get("session_id"):
        raise HarborRecoveryError("反向评测 agent_answer 与 Judge 任务不一致")
    if state.get("endpoint_id") != row.get("endpoint_id"):
        raise HarborRecoveryError("反向评测端点与冻结 Judge 轮次不一致")
    statuses = {str(row.get(key) or "").lower() for key in ("run_status", "session_status", "turn_status")}
    audit = state.get("output_recovery") or {}
    already_repaired = (
        statuses == {"completed"} and row.get("submission_status") == "Judging"
        and row.get("agent_step_status") == "running"
        and audit.get("outputs_preserved") is True and audit.get("task_id") == task_id
        and audit.get("attempt_id") == row.get("attempt_id")
        and audit.get("session_id") == row.get("session_id")
        and audit.get("native_session_id") == row.get("native_session_id")
    )
    if already_repaired:
        return "already_repaired"
    if (not statuses <= {"cleanupfailed", "cleanup_failed"}
            or row.get("submission_status") != "Error" or row.get("agent_step_status") != "error"
            or row.get("run_message") not in PRESERVATION_FAILURES
            or row.get("session_message") not in PRESERVATION_FAILURES
            or row.get("agent_step_error") not in _STEP_FAILURE_MESSAGES):
        raise HarborRecoveryError("仅允许恢复原 Trial 的输出保存或导入故障，不能恢复取消或其他终态")
    return "pending"


def get_harbor_recovery_candidate(task_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            return _read_candidate(cursor, task_id)
    finally:
        connection.close()


def complete_preserved_harbor_judge(candidate, *, native_session_id, conclusion, manifest, cleanup_audit=None):
    """重新核对绑定后，在同一事务修复三份 Agent 状态并恢复原编排。"""
    from backend.oj_modules.agents.sessions import sync_agent_session_state_in_transaction

    expected = manifest.get("events_expected")
    imported = manifest.get("events_imported")
    if (not native_session_id or manifest.get("complete") is not True
            or manifest.get("session_id") != native_session_id
            or type(expected) is not int or expected < 0
            or type(imported) is not int or imported < 0
            or expected != imported):
        raise HarborRecoveryError("Harbor 完整输出证明无效")
    task_id = candidate["task_id"]
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            current = _read_candidate(cursor, task_id, locked=True)
            for key in ("session_id", "submission_id", "attempt_id", "competition_id", "harness", "endpoint_id", "runtime_config"):
                if current.get(key) != candidate.get(key):
                    raise HarborRecoveryError("输出保存期间当前 Judge 身份或冻结配置已改变")
            if current.get("native_session_id") not in (None, "", native_session_id):
                raise HarborRecoveryError("Harbor 原生会话 ID 与持久化轮次不一致")
            if validate_harbor_recovery_candidate(current, task_id) == "already_repaired":
                return {"already_repaired": True}
            cursor.execute("""
                UPDATE agent_task_runs SET status='Completed', message=%s
                WHERE task_id=%s AND LOWER(status) IN ('cleanupfailed','cleanup_failed')
            """, (RECOVERY_MESSAGE, task_id))
            if cursor.rowcount != 1:
                raise HarborRecoveryError("Harbor 当前 run 状态已改变，未恢复")
            if not sync_agent_session_state_in_transaction(cursor, {
                "task_id": task_id, "session_id": current["session_id"], "status": "Completed",
                "message": RECOVERY_MESSAGE, "native_session_id": native_session_id,
                "conclusion": conclusion, "_preserve_conclusion": True,
            }, cleanup_confirmed=True):
                raise HarborRecoveryError("Harbor 当前会话或轮次状态未修复")
            # 没有最终聊天回复也是合法官方结果；清掉旧保存故障结论，不制造回复。
            cursor.execute("""
                UPDATE agent_session_turns SET conclusion=%s
                WHERE session_id=%s AND task_id=%s AND status='Completed'
            """, (conclusion, current["session_id"], task_id))
            cursor.execute("""
                UPDATE agent_sessions SET queue_paused=0, queue_pause_reason=NULL
                WHERE session_id=%s AND current_task_id=%s AND status='Completed'
            """, (current["session_id"], task_id))
            result = current["agent_result"]
            result["_agent"]["output_recovery"] = {
                "outputs_preserved": True, "task_id": task_id,
                "attempt_id": current["attempt_id"], "session_id": current["session_id"],
                "native_session_id": native_session_id, "previous_failure": current["run_message"],
                "import_counts": manifest["counts"],
                "post_completion_cleanup": cleanup_audit,
            }
            cursor.execute("""
                UPDATE ranking_reverse_judge_steps
                SET status='running', error_message='', finished_at=NULL, result_json=%s
                WHERE submission_id=%s AND step_key='agent_answer' AND status='error'
            """, (json.dumps(result, ensure_ascii=False), current["submission_id"]))
            if cursor.rowcount != 1:
                raise HarborRecoveryError("Harbor 原作答步骤状态已改变")
            cursor.execute("""
                UPDATE ranking_submissions
                SET status='Judging', error_message='', judge_heartbeat_at=CURRENT_TIMESTAMP
                WHERE id=%s AND judge_attempt_id=%s AND status='Error'
            """, (current["submission_id"], current["attempt_id"]))
            if cursor.rowcount != 1:
                raise HarborRecoveryError("Harbor 原提交 attempt 已改变")
        connection.commit()
        return {"already_repaired": False}
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
