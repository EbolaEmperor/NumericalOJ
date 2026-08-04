import json

import pytest

from oj_modules.problems import agent_runs


def test_agent_trace_dir_is_task_scoped_and_rejects_untrusted_ids(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))

    assert agent_runs.agent_run_trace_dir("task-1") == (
        tmp_path.resolve() / "traces" / "task-1"
    )
    for task_id in ("", "../escape", "a/b", "task id", "x" * 65):
        with pytest.raises(ValueError):
            agent_runs.agent_run_trace_dir(task_id)


def test_hydrate_agent_run_snapshot_reads_canonical_jsonl_only(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))
    trace_dir = agent_runs.agent_run_trace_dir("task-2")
    trace_dir.mkdir(parents=True)
    (trace_dir / "codex_agent_judge.jsonl").write_text(
        json.dumps({"type": "agent_message", "message": "真实 harness 回复"})
        + "\n",
        encoding="utf-8",
    )

    original = {
        "task_id": "task-2",
        "status": "Running",
        "message": "正在运行",
        "events": [{"message": "旧自建轨迹"}],
    }
    snapshot = agent_runs.hydrate_agent_run_snapshot(original)

    assert "events" not in snapshot
    assert "events" in original
    trace = snapshot["execution_trace"]
    assert trace["status"] == "running"
    assert [message["text"] for message in trace["trace_messages"]] == [
        "真实 harness 回复"
    ]
    assert trace["trace_files"][0]["path"] == "codex_agent_judge.jsonl"


@pytest.mark.parametrize(
    ("task_status", "trace_status"),
    [
        ("Pending", "pending"),
        ("Running", "running"),
        ("Completed", "passed"),
        ("Failed", "error"),
    ],
)
def test_agent_snapshot_maps_task_status_to_shared_trace_status(
    monkeypatch,
    tmp_path,
    task_status,
    trace_status,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))

    trace = agent_runs.build_agent_execution_trace({
        "task_id": "task-3",
        "status": task_status,
        "message": "状态说明",
    })

    assert trace["status"] == trace_status
    assert trace["error_message"] == (
        "状态说明" if trace_status == "error" else ""
    )
