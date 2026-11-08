"""显式停机后的 Harbor 输出恢复；只消费已有官方结果，绝不启动模型。"""

import json
import os
from pathlib import Path
import re
import stat
from datetime import datetime, timezone

from backend.oj_modules import config
from backend.oj_modules.agents.judge import judge_session_write_lock, resolve_judge_endpoint
from backend.oj_modules.agents.trace_store import get_last_agent_trace_assistant, ingest_agent_trace_records
from backend.oj_modules.agents.workspace import merge_agent_temporary_redaction_candidates
from backend.oj_modules.db_services import get_agent_run_by_task_id, is_agent_run_canceled
from backend.oj_modules.infrastructure.redis import create_optional_redis_client
from backend.oj_modules.integrations import harbor_runtime
from backend.oj_modules.problems.agent_runs import normalize_agent_task_id
from backend.oj_modules.ranking.db import get_ranking_submission, set_agent_judge_task_id
from backend.oj_modules.ranking.reverse_judge.db import safe_attempt_component
from backend.oj_modules.ranking.reverse_judge.recovery import (
    HarborRecoveryError, RECOVERY_MESSAGE, complete_preserved_harbor_judge,
    get_harbor_recovery_candidate,
)
from backend.oj_modules.tasks.agent.shared import publish_agent_run_snapshot


def _read_json(path, *, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8 * 1024 * 1024
                or private and (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600})):
            raise HarborRecoveryError("Harbor 恢复文件类型、大小或私有权限无效")
        raw = source.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise HarborRecoveryError("Harbor 恢复文件超过大小限制")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise HarborRecoveryError("Harbor 恢复文件格式无效")
    return value


def _runtime_for_candidate(candidate):
    runtime = harbor_runtime.normalize_harbor_runtime(candidate["runtime_config"]["harbor_runtime"])
    root = Path(config.REVERSE_JUDGE_WORKSPACE_ROOT).absolute().resolve()
    expected = root / str(int(candidate["submission_id"])) / safe_attempt_component(candidate["attempt_id"])
    if (Path(runtime["trial_dir"]) != expected / "agent_trial"
            or Path(runtime["task_path"]) != expected / "quality_gate_source"):
        raise HarborRecoveryError("Harbor 运行目录与原提交 attempt 不一致")
    return runtime


def _official_result(runtime):
    from harbor.models.trial.result import TrialResult

    trial_dir = Path(runtime["trial_dir"])
    if not harbor_runtime.harbor_trial_physically_stopped(runtime):
        raise HarborRecoveryError("Harbor 执行进程或容器尚未确认停止")
    result = harbor_runtime.load_harbor_result(trial_dir)
    if result.get("ok") is not True:
        raise HarborRecoveryError("原 Harbor Trial 没有有效成功结果")
    name_path = trial_dir / ".run-name"
    if name_path.is_symlink() or name_path.stat().st_size > 128:
        raise HarborRecoveryError("Harbor 原执行身份无效")
    name = name_path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"numoj-harbor-[a-f0-9]{20}", name):
        raise HarborRecoveryError("Harbor 原执行身份无效")
    official_dir = trial_dir / name
    if (official_dir != official_dir.resolve()
            or Path(result.get("official_trial_dir") or "") != official_dir):
        raise HarborRecoveryError("Harbor 官方结果来源目录不一致")
    official = TrialResult.model_validate(_read_json(official_dir / "result.json"))
    if not official.finished_at or not official.reward_valid or official.trial_name != name:
        raise HarborRecoveryError("官方 Harbor Trial 尚未结束或奖励无效")
    if official.verifier_result.rewards != result["result"]["rewards"]:
        raise HarborRecoveryError("平台奖励与原官方结果不一致，拒绝恢复")
    _post_completion_cleanup_audit(runtime, official.finished_at)
    return result, official_dir


def _post_completion_cleanup_audit(runtime, finished_at):
    """旧停止入口也写取消标记；只允许明确晚于官方完成的物理清理标记。"""
    marker = Path(runtime["trial_dir"]) / ".cancel-requested"
    try:
        metadata = marker.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise HarborRecoveryError("Harbor 取消标记必须是普通文件，不能是符号链接")
    if isinstance(finished_at, str):
        finished_at = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
    if not isinstance(finished_at, datetime) or finished_at.utcoffset() is None:
        raise HarborRecoveryError("官方 Harbor 完成时间缺少明确时区，不能判断取消标记")
    completed = finished_at.astimezone(timezone.utc)
    delta = completed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    completed_ns = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
    if metadata.st_mtime_ns <= completed_ns:
        raise HarborRecoveryError("Harbor 取消标记早于或等于官方完成时间，不能恢复为完成")
    return {"classification": "post_completion_cleanup", "official_finished_at": completed.isoformat(),
            "cancel_marker_mtime_ns": metadata.st_mtime_ns}


def _recovery_secrets(candidate, runtime):
    # CLI 配置正常结束后已删除；复用已有私有脱敏历史，不重新启动 relay 或访问端点。
    values = list(merge_agent_temporary_redaction_candidates(candidate["session_id"], ()))
    try:
        configuration = _read_json(Path(runtime["trial_dir"]) / ".harbor-cli.json", private=True)
    except FileNotFoundError:
        pass
    else:
        environment = (configuration.get("agent") or {}).get("env") or {}
        values.append(str(environment.get("NUMOJ_HARBOR_API_KEY") or ""))
    endpoint = resolve_judge_endpoint(candidate)
    values.append(str(endpoint.get("api_key") or ""))
    return tuple(value for value in values if value)


def _refresh_public_state(candidate, native_session_id, conclusion):
    client = create_optional_redis_client()
    if client is None:
        raise HarborRecoveryError("无法刷新恢复后的 Redis 状态，保留恢复标记等待重试")
    # 先删除旧 CleanupFailed 快照；即使 SSE 发布失败，后续读取也会回源新 DB 终态。
    client.delete("agent_run:" + candidate["task_id"],
                  "ranking_reverse_judge:" + str(candidate["submission_id"]))
    state = get_agent_run_by_task_id(candidate["task_id"])
    if not state or str(state.get("status") or "").lower() != "completed":
        raise HarborRecoveryError("恢复后当前 Agent DB 状态不是 Completed")
    state.update(session_id=candidate["session_id"], native_session_id=native_session_id,
                 task_kind="judge", judge_kind="reverse_answer", endpoint_source="competition",
                 competition_id=candidate["competition_id"], submission_id=candidate["submission_id"],
                 attempt_id=candidate["attempt_id"],
                 conclusion=conclusion, status="Completed", stage="finished", harness_status="completed",
                 message=RECOVERY_MESSAGE)
    publish_agent_run_snapshot(state)
    try:
        observed = json.loads(client.get("agent_run:" + candidate["task_id"]) or "null")
    except (TypeError, ValueError) as exc:
        raise HarborRecoveryError("恢复后的 Redis 快照无效，保留恢复标记等待重试") from exc
    required = {key: state[key] for key in (
        "task_id", "session_id", "status", "task_kind", "judge_kind", "endpoint_source",
        "native_session_id", "competition_id", "submission_id", "attempt_id", "endpoint_id", "endpoint_model",
    )}
    if not isinstance(observed, dict) or any(observed.get(key) != value for key, value in required.items()):
        raise HarborRecoveryError("恢复后的 Redis Completed/Judge 快照未确认写入，保留恢复标记等待重试")


def finalize_completed_harbor_task(task_id, *, celery_app):
    """仅供 recover_pending_tasks.py 完整停机守卫通过后调用。"""
    task_id = normalize_agent_task_id(task_id)
    candidate = get_harbor_recovery_candidate(task_id)
    with judge_session_write_lock(candidate["session_id"]):
        candidate = get_harbor_recovery_candidate(task_id)
        if is_agent_run_canceled(task_id):
            raise HarborRecoveryError("任务已取消，不能恢复为完成")
        runtime = _runtime_for_candidate(candidate)
        result, official_dir = _official_result(runtime)
        official_finished_at = _read_json(official_dir / "result.json").get("finished_at")
        cleanup_audit = _post_completion_cleanup_audit(runtime, official_finished_at)
        secrets = _recovery_secrets(candidate, runtime)
        native_session_id = str(candidate.get("native_session_id") or "")

        def emit(event):
            nonlocal native_session_id
            if event.get("type") == "native":
                observed = str(event.get("session_id") or "")
                if native_session_id and native_session_id != observed:
                    raise HarborRecoveryError("恢复轨迹的原生会话 ID 与当前 Judge 不一致")
                native_session_id = observed
            elif event.get("type") == "trace":
                records = event.get("records") or []
                inserted = ingest_agent_trace_records(task_id, records, final=bool(event.get("final")))
                if event.get("final") and inserted != len(records):
                    raise HarborRecoveryError("Harbor 完整轨迹没有全部提交")

        harbor_runtime.finalize_harbor_trial_outputs(
            runtime=runtime, session_id=candidate["session_id"], result=result, secrets=secrets, emit=emit,
        )
        manifest = _read_json(official_dir / "agent" / "numoj-import-manifest.json", private=True)
        conclusion = get_last_agent_trace_assistant(task_id)
        repaired = complete_preserved_harbor_judge(
            candidate, native_session_id=native_session_id, conclusion=conclusion, manifest=manifest,
            cleanup_audit=cleanup_audit,
        )
        _refresh_public_state(candidate, native_session_id, conclusion)
        # 所有输出与领域状态已提交；失败不会机械清 marker，重试由 _agent 审计识别。
        marker = Path(runtime["trial_dir"]) / ".preservation-failed"
        if marker.is_symlink():
            raise HarborRecoveryError("Harbor 恢复标记不能是符号链接")
        queued = celery_app.send_task("oj.ranking_reverse_judge", args=[
            candidate["submission_id"], candidate["attempt_id"],
            candidate["agent_result"]["_agent"].get("endpoint_id"),
        ], queue="celery")
        changed = set_agent_judge_task_id(candidate["submission_id"], candidate["attempt_id"], queued.id)
        if changed != 1:
            # 相同 ID、同秒 heartbeat 可返回 changed rows=0；必须用当前 DB 绑定证明无变化。
            current = get_ranking_submission(candidate["submission_id"]) or {}
            if (changed != 0 or current.get("judge_attempt_id") != candidate["attempt_id"]
                    or current.get("judge_task_id") != queued.id or current.get("status") != "Judging"):
                raise HarborRecoveryError("原评测编排任务 ID 未确认持久化，保留恢复标记等待重试")
        marker.unlink(missing_ok=True)
        return {"success": True, "task_id": task_id, "session_id": candidate["session_id"],
                "submission_id": candidate["submission_id"], "attempt_id": candidate["attempt_id"],
                "native_session_id": native_session_id, "already_repaired": repaired["already_repaired"],
                "orchestrator_task_id": queued.id, "import_counts": manifest["counts"],
                "model_reexecuted": False, "post_completion_cleanup": cleanup_audit}
