import pytest

from scripts import repair_agent_cleanup_sessions_20260829 as repair


def _target_row(target, *, status="CleanupFailed"):
    failed = status == "CleanupFailed"
    return {
        "session_id": target.session_id,
        "current_task_id": target.task_id,
        "session_requested_by": "admin",
        "run_requested_by": "admin",
        "native_session_id": target.native_session_id,
        "session_status": status,
        "run_status": status,
        "turn_status": status,
        "session_message": (
            repair._FAILED_MESSAGE if failed else repair._COMPLETED_MESSAGE
        ),
        "run_message": (
            repair._FAILED_MESSAGE if failed else repair._COMPLETED_MESSAGE
        ),
        "turn_count": 1,
        "turn_index": 1,
        "queue_paused": 1 if failed else 0,
        "queue_pause_reason": repair._FAILED_MESSAGE if failed else None,
        "fresh_native_session_pending": 0,
        "conclusion": "任务结论",
    }


def test_target_classifier_accepts_only_expected_failure_and_completed_states():
    target = repair._TARGETS[0]

    assert repair._classify_target(_target_row(target), target) == "repair"
    assert (
        repair._classify_target(
            _target_row(target, status="Completed"),
            target,
        )
        == "complete"
    )


def test_target_classifier_rejects_mixed_terminal_state():
    target = repair._TARGETS[0]
    row = _target_row(target)
    row["turn_status"] = "Completed"

    with pytest.raises(RuntimeError, match="三层终态不一致"):
        repair._classify_target(row, target)


def test_target_classifier_rejects_identity_drift():
    target = repair._TARGETS[0]
    row = _target_row(target)
    row["native_session_id"] = "unexpected"

    with pytest.raises(RuntimeError, match="native_session_id"):
        repair._classify_target(row, target)
