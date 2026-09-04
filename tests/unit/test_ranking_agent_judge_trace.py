# -*- coding: utf-8 -*-
"""Agent Judge 执行轨迹：attempt 隔离、累计同步、脱敏与快照投影。"""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask

import backend.oj_modules.ranking.agent_judge.db as db
import backend.oj_modules.ranking.reverse_judge.traces as reverse_db
import backend.oj_modules.routes.ranking_routes as routes
import backend.oj_modules.tasks.ranking.agent_judge as tasks


def _app():
    app = Flask(__name__)
    app.secret_key = "test"
    return app


def _claude_event(text):
    return (json.dumps({
        "type": "assistant",
        "message": {
            "model": "trace-test",
            "content": [{"type": "text", "text": text}],
        },
    }, ensure_ascii=False) + "\n").encode("utf-8")


def _claude_event_with_uuid(text, event_uuid, session_id=None):
    event = {
        "type": "assistant",
        "uuid": event_uuid,
        "message": {
            "model": "trace-test",
            "content": [{"type": "text", "text": text}],
        },
    }
    if session_id:
        event["sessionId"] = session_id
    return (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")


def _export_item(path, mtime, payload, *, truncated=False):
    events = []
    offset = 0
    for raw in payload.splitlines(keepends=True):
        event = json.loads(raw)
        events.append({"offset": offset, "event": event})
        offset += len(raw)
    return {
        "path": path,
        "mtime": mtime,
        "size": len(payload),
        "events": events,
        "truncated": truncated,
    }


def test_agent_judge_trace_dir_is_attempt_scoped_outside_uploaded_code(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "submission_dir", lambda sid: str(tmp_path / f"submission-{sid}"))

    first = Path(db.agent_judge_trace_dir(7, "attempt-a"))
    second = Path(db.agent_judge_trace_dir(7, "attempt-b"))

    assert first != second
    assert first.parts[-2:] == ("agent_judge_trace", "attempt-a")
    assert "submission" not in first.parts[-2:]


def test_build_judge_snapshot_includes_shared_trace_payload(monkeypatch, tmp_path):
    submission = {
        "id": 9,
        "competition_id": 3,
        "status": "Judging",
        "judge_attempt_id": "attempt-live",
        "error_message": "",
        "grade_details": None,
    }
    expected_dir = tmp_path / "agent_judge_trace" / "attempt-live"
    seen = []
    monkeypatch.setattr(db, "get_ranking_submission", lambda _sid: submission)
    monkeypatch.setattr(db, "list_competition_rules", lambda _cid: [])
    monkeypatch.setattr(db, "list_judge_results", lambda _sid: [])
    monkeypatch.setattr(
        db, "agent_judge_trace_dir", lambda _sid, _attempt: str(expected_dir),
    )
    monkeypatch.setattr(
        db, "collect_agent_trace_messages",
        lambda path: seen.append(("messages", path)) or [{"kind": "assistant", "text": "ok"}],
    )
    monkeypatch.setattr(
        db, "collect_agent_token_usage",
        lambda path: seen.append(("usage", path)) or {"input_total_tokens": 12},
    )

    snapshot = db.build_judge_snapshot(9)

    assert snapshot["execution_trace"] == {
        "trace_id": db.agent_judge_trace_id("attempt-live"),
        "status": "running",
        "error_message": "",
        "stdout": "",
        "stderr": "",
        "trace_files": [],
        "trace_messages": [{"kind": "assistant", "text": "ok"}],
        "token_usage": {"input_total_tokens": 12},
    }
    assert seen == [
        ("messages", str(expected_dir)),
        ("usage", str(expected_dir)),
    ]
    assert "trace_dir" not in snapshot["execution_trace"]


def test_claude_resume_trace_rebuilds_in_phase_order_and_redacts(monkeypatch, tmp_path):
    ws = tmp_path / "workspace"
    trace_dir = tmp_path / "trusted-trace"
    ws.mkdir()
    state_path = ws / ".aj_session_state.jsonl"
    sessions = [
        ("11111111-1111-1111-1111-111111111111", "setup"),
        ("22222222-2222-2222-2222-222222222222", "rule_1"),
    ]
    state_path.write_text("".join(
        json.dumps({"session_id": sid, "phase": phase}) + "\n"
        for sid, phase in sessions
    ), encoding="utf-8")
    remote = {
        f"/root/.claude/projects/-workspace/{sessions[0][0]}.jsonl": _claude_event(
            "setup CANARY_API_KEY result_0123456789abcdef0123456789abcdef.jsonl"
        ),
        f"/root/.claude/projects/-workspace/{sessions[1][0]}.jsonl": _claude_event("rule one"),
    }

    def locate(_container, *_args):
        # 故意逆序，必须按 .aj_session_state.jsonl 的 phase/session 顺序重排。
        return {"complete": True, "truncated": False, "items": [
            _export_item(path, index, remote[path])
            for index, path in enumerate(reversed(list(remote)))
        ]}

    monkeypatch.setattr(tasks, "_export_container_claude_jsonl", locate)

    changed = tasks._sync_claude_execution_trace(
        "aj_9", str(ws), str(trace_dir), api_key="CANARY_API_KEY",
    )
    combined = (
        trace_dir / ".claude" / "projects" / "-workspace" /
        "agent_judge_combined.jsonl"
    ).read_text(encoding="utf-8")

    assert changed is True
    assert combined.index("setup") < combined.index("rule one")
    assert "CANARY_API_KEY" not in combined
    assert "result_0123456789abcdef0123456789abcdef.jsonl" not in combined
    assert "[redacted]" in combined and "[result-file]" in combined
    messages = reverse_db.collect_agent_trace_messages(str(trace_dir))
    assert [m["text"] for m in messages] == [
        "setup [redacted] [result-file]", "rule one",
    ]
    assert [m["phase"] for m in messages] == ["setup", "rule_1"]
    assert not any(session_id in combined for session_id, _phase in sessions)


def test_claude_resume_trace_deduplicates_parent_history_by_event_uuid(monkeypatch, tmp_path):
    ws = tmp_path / "workspace"
    trace_dir = tmp_path / "trusted-trace"
    ws.mkdir()
    sessions = [
        ("11111111-1111-1111-1111-111111111111", "setup"),
        ("22222222-2222-2222-2222-222222222222", "rule_1"),
    ]
    (ws / ".aj_session_state.jsonl").write_text("".join(
        json.dumps({"session_id": sid, "phase": phase}) + "\n"
        for sid, phase in sessions
    ), encoding="utf-8")
    parent = _claude_event_with_uuid("setup once", "event-parent")
    child = _claude_event_with_uuid("rule once", "event-child")
    remote = {
        f"/root/.claude/projects/-workspace/{sessions[0][0]}.jsonl": parent,
        f"/root/.claude/projects/-workspace/{sessions[1][0]}.jsonl": parent + child,
    }
    monkeypatch.setattr(tasks, "_export_container_claude_jsonl", lambda _container, *_args: {
        "complete": True,
        "truncated": False,
        "items": [
            _export_item(path, index, remote[path])
            for index, path in enumerate(remote)
        ],
    })

    assert tasks._sync_claude_execution_trace("aj_9", str(ws), str(trace_dir))

    messages = reverse_db.collect_agent_trace_messages(str(trace_dir))
    assert [message["text"] for message in messages] == ["setup once", "rule once"]
    assert [message["phase"] for message in messages] == ["setup", "rule_1"]
    cursor = json.loads((trace_dir / ".claude_trace_cursors.json").read_text())
    assert cursor["__seen_event_uuids__"] == ["event-child", "event-parent"]


def test_claude_resume_trace_persists_uuid_dedup_across_sync_rounds(monkeypatch, tmp_path):
    ws = tmp_path / "workspace"
    trace_dir = tmp_path / "trusted-trace"
    ws.mkdir()
    sessions = [
        ("11111111-1111-1111-1111-111111111111", "setup"),
        ("22222222-2222-2222-2222-222222222222", "rule_1"),
        ("33333333-3333-3333-3333-333333333333", "rule_2"),
    ]
    (ws / ".aj_session_state.jsonl").write_text("".join(
        json.dumps({"session_id": sid, "phase": phase}) + "\n"
        for sid, phase in sessions
    ), encoding="utf-8")
    setup = _claude_event_with_uuid("setup once", "event-setup", sessions[0][0])
    rule_one = _claude_event_with_uuid("rule one", "event-rule-1", sessions[1][0])
    rule_two = _claude_event_with_uuid("rule two", "event-rule-2", sessions[2][0])
    exports = [
        {
            "complete": True, "truncated": False,
            "items": [_export_item(f"/remote/{sessions[0][0]}.jsonl", 1, setup)],
        },
        {
            # 原始父文件未出现在本轮导出中；child fork 自带完整父历史。
            "complete": True, "truncated": False,
            "items": [_export_item(
                f"/remote/{sessions[1][0]}.jsonl", 2, setup + rule_one,
            )],
        },
        {
            "complete": True, "truncated": False,
            "items": [_export_item(
                f"/remote/{sessions[2][0]}.jsonl", 3,
                setup + rule_one + rule_two,
            )],
        },
    ]
    monkeypatch.setattr(
        tasks, "_export_container_claude_jsonl", lambda _container, *_args: exports.pop(0),
    )

    for _ in range(3):
        assert tasks._sync_claude_execution_trace(
            "aj_9", str(ws), str(trace_dir),
        )

    combined_path = (
        trace_dir / ".claude" / "projects" / "-workspace" /
        "agent_judge_combined.jsonl"
    )
    combined = combined_path.read_text(encoding="utf-8")
    assert combined.count('"event-setup"') == 1
    assert combined.count('"event-rule-1"') == 1
    assert combined.count('"event-rule-2"') == 1
    messages = reverse_db.collect_agent_trace_messages(str(trace_dir))
    assert [message["text"] for message in messages] == [
        "setup once", "rule one", "rule two",
    ]
    assert [message["phase"] for message in messages] == [
        "setup", "rule_1", "rule_2",
    ]
    cursor = json.loads((trace_dir / ".claude_trace_cursors.json").read_text())
    assert cursor["__seen_event_uuids__"] == [
        "event-rule-1", "event-rule-2", "event-setup",
    ]


def test_duplicate_only_resume_persists_advanced_source_cursor(monkeypatch, tmp_path):
    ws = tmp_path / "workspace"
    trace_dir = tmp_path / "trusted-trace"
    ws.mkdir()
    sessions = [
        ("11111111-1111-1111-1111-111111111111", "setup"),
        ("22222222-2222-2222-2222-222222222222", "rule_1"),
    ]
    (ws / ".aj_session_state.jsonl").write_text("".join(
        json.dumps({"session_id": sid, "phase": phase}) + "\n"
        for sid, phase in sessions
    ), encoding="utf-8")
    setup = _claude_event_with_uuid("setup once", "event-setup", sessions[0][0])
    exports = [
        {
            "complete": True, "truncated": False,
            "items": [_export_item(f"/remote/{sessions[0][0]}.jsonl", 1, setup)],
        },
        {
            "complete": True, "truncated": False,
            "items": [_export_item(f"/remote/{sessions[1][0]}.jsonl", 2, setup)],
        },
    ]
    monkeypatch.setattr(
        tasks, "_export_container_claude_jsonl", lambda _container, *_args: exports.pop(0),
    )

    assert tasks._sync_claude_execution_trace("aj_9", str(ws), str(trace_dir))
    assert not tasks._sync_claude_execution_trace("aj_9", str(ws), str(trace_dir))

    cursor = json.loads((trace_dir / ".claude_trace_cursors.json").read_text())
    source_cursors = {
        key: value for key, value in cursor.items() if key.startswith("claude-")
    }
    assert len(source_cursors) == 2
    assert set(source_cursors.values()) == {0}


def test_shared_trace_parser_keeps_messages_added_after_tail_window(tmp_path):
    trace_dir = tmp_path / "trace"
    combined = trace_dir / ".claude" / "projects" / "-workspace" / "agent_judge_combined.jsonl"
    combined.parent.mkdir(parents=True)
    ignored = json.dumps({
        "type": "user",
        "padding": "x" * (reverse_db._TRACE_JSONL_PARSE_MAX_BYTES + 1024),
    }) + "\n"
    combined.write_bytes(ignored.encode("utf-8") + _claude_event("late resume message"))

    messages = reverse_db.collect_agent_trace_messages(str(trace_dir))

    assert messages[-1]["text"] == "late resume message"
    assert messages[-1]["offset"] == len(ignored.encode("utf-8"))


def test_failed_claude_resume_sync_keeps_last_complete_trace(monkeypatch, tmp_path):
    ws = tmp_path / "workspace"
    trace_dir = tmp_path / "trusted-trace"
    combined = trace_dir / ".claude" / "projects" / "-workspace" / "agent_judge_combined.jsonl"
    ws.mkdir()
    combined.parent.mkdir(parents=True)
    previous = _claude_event("previous complete trace")
    combined.write_bytes(previous)
    monkeypatch.setattr(tasks, "_export_container_claude_jsonl", lambda _container, *_args: {
        "complete": False,
        "truncated": False,
        "items": [_export_item("/remote/old.jsonl", 1, previous)],
    })

    changed = tasks._sync_claude_execution_trace("aj_9", str(ws), str(trace_dir))

    assert changed is False
    assert combined.read_bytes() == previous


def test_public_trace_projection_hides_raw_files_and_random_result_name():
    secret_name = "result_0123456789abcdef0123456789abcdef.jsonl.rule_7.jsonl"
    api_key = "CANARY_ENDPOINT_API_KEY"
    base_url = "https://private-model.example/v1"
    snapshot = {
        "rules": [{
            "rule_text": f"题目允许提到 {base_url}",
            "evidence": f"evidence {api_key}",
            "evidence_html": f"<p>{api_key}</p>",
        }],
        "execution_trace": {
            "trace_messages": [{
                "kind": "assistant",
                "text": f"write {secret_name} with {api_key} at {base_url}",
            }],
            "trace_files": [{"path": "/private/trace.jsonl", "content": secret_name}],
            "stdout": secret_name,
            "stderr": "",
        },
    }

    owner = routes._project_agent_judge_snapshot(
        snapshot, include_internal=False, sensitive_values=(api_key, base_url),
    )
    admin = routes._project_agent_judge_snapshot(
        snapshot, include_internal=True, sensitive_values=(api_key, base_url),
    )

    assert owner["execution_trace"]["trace_files"] == []
    assert owner["execution_trace"]["stdout"] == ""
    assert owner["execution_trace"]["trace_messages"][0]["text"] == ""
    assert owner["execution_trace"]["trace_messages"][0]["title"] == "AI 回复"
    assert owner["rules"][0]["rule_text"] == f"题目允许提到 {base_url}"
    assert owner["rules"][0]["evidence"] == "evidence [redacted]"
    assert owner["rules"][0]["evidence_html"] == "<p>[redacted]</p>"
    assert admin["rules"][0]["evidence"] == f"evidence {api_key}"
    assert admin["execution_trace"]["trace_files"] == []
    assert secret_name not in json.dumps(owner, ensure_ascii=False)
    assert secret_name not in json.dumps(admin, ensure_ascii=False)
    assert api_key not in json.dumps(owner, ensure_ascii=False)
    assert base_url not in json.dumps(owner["execution_trace"], ensure_ascii=False)


def test_judge_stream_owner_sees_messages_but_not_endpoint_or_raw_trace(monkeypatch):
    api_key = "CANARY_STREAM_KEY"
    base_url = "https://private-model.example/v1"
    secret_name = "result_0123456789abcdef0123456789abcdef.jsonl"
    snapshot = {
        "submission_id": 41,
        "status": "Accepted",
        "max_score": 10,
        "total_score": 10,
        "rules": [],
        "execution_trace": {
            "status": "passed",
            "trace_messages": [{
                "kind": "assistant", "title": "AI 回复",
                "text": f"visible {secret_name} {api_key} {base_url}",
            }],
            "trace_files": [{
                "path": "/private/trace.jsonl", "content": "raw-internal-trace",
            }],
            "stdout": "raw stdout",
            "stderr": "",
        },
    }
    monkeypatch.setattr(
        routes, "_require_user", lambda: ({"username": "u1", "is_admin": 0}, None),
    )
    monkeypatch.setattr(
        routes, "get_ranking_submission",
        lambda sid: {"id": sid, "competition_id": 7, "username": "u1"},
    )
    monkeypatch.setattr(routes, "get_competition", lambda _cid: {})
    monkeypatch.setattr(
        routes, "list_agent_judge_endpoints",
        lambda *_args, **_kwargs: [{"api_key": api_key, "base_url": base_url}],
    )
    monkeypatch.setattr(routes, "get_judge_progress_snapshot", lambda _sid: snapshot)

    with _app().test_request_context():
        body = routes.ranking_judge_stream(7, 41).get_data(as_text=True)

    assert "AI 回复" in body and "visible" not in body
    assert api_key not in body and base_url not in body and secret_name not in body
    assert "raw-internal-trace" not in body
    assert "/private/trace.jsonl" not in body
    assert "raw stdout" not in body


def test_judge_stream_rejects_non_owner(monkeypatch):
    monkeypatch.setattr(
        routes, "_require_user", lambda: ({"username": "other", "is_admin": 0}, None),
    )
    monkeypatch.setattr(
        routes, "get_ranking_submission",
        lambda sid: {"id": sid, "competition_id": 7, "username": "u1"},
    )

    with _app().test_request_context():
        response = routes.ranking_judge_stream(7, 41)

    assert response.status_code == 403


def test_terminal_stream_snapshot_is_rebuilt_from_canonical_trace(monkeypatch):
    attempt_trace_id = db.agent_judge_trace_id("attempt-current")
    stale = {
        "status": "Accepted",
        "attempt_trace_id": attempt_trace_id,
        "execution_trace": {"trace_messages": [{"text": "rule 17 before setup"}]},
    }
    canonical = {
        "status": "Accepted",
        "attempt_trace_id": attempt_trace_id,
        "execution_trace": {"trace_messages": [{"text": "setup before rule 17"}]},
    }
    monkeypatch.setattr(
        routes, "build_current_judge_snapshot", lambda _sid: canonical,
    )

    assert routes._canonical_terminal_judge_snapshot(
        26, stale, attempt_trace_id,
    ) == canonical


def test_running_stream_snapshot_does_not_force_disk_rebuild(monkeypatch):
    running = {
        "status": "Judging",
        "attempt_trace_id": db.agent_judge_trace_id("attempt-current"),
    }
    monkeypatch.setattr(
        routes, "build_current_judge_snapshot",
        lambda _sid: pytest.fail("running snapshots must keep the low-latency path"),
    )

    assert routes._canonical_terminal_judge_snapshot(
        26, running, running["attempt_trace_id"],
    ) is running


def test_terminal_stream_does_not_close_after_attempt_switch(monkeypatch):
    stale_attempt = db.agent_judge_trace_id("attempt-stale")
    stale = {"status": "Accepted", "attempt_trace_id": stale_attempt}
    current = {
        "status": "Judging",
        "attempt_trace_id": db.agent_judge_trace_id("attempt-new"),
    }
    monkeypatch.setattr(
        routes, "build_current_judge_snapshot", lambda _sid: current,
    )

    assert routes._canonical_terminal_judge_snapshot(
        26, stale, stale_attempt,
    ) is None


def test_cached_terminal_snapshot_is_rejected_after_new_attempt(monkeypatch):
    old = {"status": "Accepted", "attempt_trace_id": db.agent_judge_trace_id("old")}

    class FakeRedis:
        def __init__(self):
            self.deleted = []

        def get(self, _key):
            return json.dumps(old)

        def delete(self, key):
            self.deleted.append(key)

    fake = FakeRedis()
    monkeypatch.setattr(tasks, "_judge_rds", fake)
    monkeypatch.setattr(
        tasks, "get_ranking_submission",
        lambda _sid: {"judge_attempt_id": "new"},
    )
    fresh = {"status": "Queued", "attempt_trace_id": db.agent_judge_trace_id("new")}
    monkeypatch.setattr(tasks, "build_judge_snapshot", lambda _sid: fresh)

    assert tasks.get_judge_progress_snapshot(8) == fresh
    assert fake.deleted == [tasks._judge_progress_key(8)]


def test_terminal_snapshot_is_rebuilt_even_when_cached_attempt_matches(monkeypatch):
    attempt_id = "terminal-attempt"
    cached = {
        "status": "Accepted",
        "attempt_trace_id": db.agent_judge_trace_id(attempt_id),
        "execution_trace": {"trace_messages": [{"text": "stale order"}]},
    }

    class FakeRedis:
        def __init__(self):
            self.get_calls = 0

        def get(self, _key):
            self.get_calls += 1
            return json.dumps(cached)

    fake = FakeRedis()
    monkeypatch.setattr(tasks, "_judge_rds", fake)
    monkeypatch.setattr(
        tasks, "get_ranking_submission",
        lambda _sid: {
            "judge_attempt_id": attempt_id,
            "status": "Accepted",
        },
    )
    canonical = {
        "status": "Accepted",
        "attempt_trace_id": db.agent_judge_trace_id(attempt_id),
        "execution_trace": {"trace_messages": [{"text": "canonical order"}]},
    }
    monkeypatch.setattr(tasks, "build_judge_snapshot", lambda _sid: canonical)

    assert tasks.get_judge_progress_snapshot(8) == canonical
    assert fake.get_calls == 0


def test_attempt_container_names_and_stale_cleanup_are_isolated(monkeypatch):
    current = tasks._agent_judge_container_name(7, "new-attempt")
    old = tasks._agent_judge_container_name(7, "old-attempt")
    assert current != old
    calls = []

    def run(args, **_kwargs):
        calls.append(list(args))
        if args[1:3] == ["ps", "-a"]:
            return SimpleNamespace(
                returncode=0,
                stdout=f"aj_7\n{old}\n{current}\naj_70_deadbeef\naj_8_other\n",
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tasks.subprocess, "run", run)
    tasks._remove_stale_agent_containers(7, current)

    removed = [call[-1] for call in calls if call[:3] == ["docker", "rm", "-f"]]
    assert removed == ["aj_7", old]


def test_attempt_workspaces_do_not_share_files(monkeypatch, tmp_path):
    monkeypatch.setattr(tasks, "JUDGE_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setattr(tasks, "list_competition_files", lambda _cid: [])
    submission = {"id": 12, "code_path": None}
    competition = {"id": 5, "description": "desc"}

    first, first_result = tasks._prepare_workspace(
        submission, competition, [], "attempt-a",
    )
    Path(first, ".aj_harness.log").write_text("old", encoding="utf-8")
    second, second_result = tasks._prepare_workspace(
        submission, competition, [], "attempt-b",
    )

    assert first != second and first_result != second_result
    assert Path(first, ".aj_harness.log").read_text(encoding="utf-8") == "old"
    assert not Path(second, ".aj_harness.log").exists()


def test_claude_resume_sync_appends_new_sessions_without_rewriting(monkeypatch, tmp_path):
    ws = tmp_path / "workspace"
    trace_dir = tmp_path / "trace"
    ws.mkdir()
    sessions = [
        ("11111111-1111-1111-1111-111111111111", "setup", "setup message"),
        ("22222222-2222-2222-2222-222222222222", "rule_1", "rule one"),
        ("33333333-3333-3333-3333-333333333333", "rule_2", "rule two"),
    ]
    (ws / ".aj_session_state.jsonl").write_text("".join(
        json.dumps({"session_id": sid, "phase": phase}) + "\n"
        for sid, phase, _text in sessions
    ), encoding="utf-8")
    exports = []
    for count in (1, 2, 3):
        exports.append({
            "complete": True,
            "truncated": False,
            "items": [
                _export_item(
                    f"/root/.claude/projects/-workspace/{sid}.jsonl",
                    index,
                    _claude_event(text),
                )
                for index, (sid, _phase, text) in enumerate(sessions[:count])
            ],
        })
    monkeypatch.setattr(
        tasks, "_export_container_claude_jsonl", lambda _container, *_args: exports.pop(0),
    )

    sizes = []
    for _ in range(3):
        assert tasks._sync_claude_execution_trace("container", str(ws), str(trace_dir))
        sizes.append((
            trace_dir / ".claude" / "projects" / "-workspace" /
            "agent_judge_combined.jsonl"
        ).stat().st_size)

    messages = reverse_db.collect_agent_trace_messages(str(trace_dir))
    assert [message["text"] for message in messages] == [
        "setup message", "rule one", "rule two",
    ]
    assert [message["phase"] for message in messages] == ["setup", "rule_1", "rule_2"]
    assert sizes[0] < sizes[1] < sizes[2]
    serialized = json.dumps(messages, ensure_ascii=False)
    assert not any(session_id in serialized for session_id, _phase, _text in sessions)




def test_route_container_scan_includes_attempt_scoped_agent_names(monkeypatch):
    monkeypatch.setattr(
        routes, "_docker_command",
        lambda *_args, **_kwargs: (
            SimpleNamespace(
                returncode=0,
                stdout="aj_5_deadbeef\naj_50_other\nrj_judge_5_attempt\n",
                stderr="",
            ),
            None,
        ),
    )

    names, error = routes._docker_container_names_for_submission(5)

    assert error is None
    assert "aj_5_deadbeef" in names and "rj_judge_5_attempt" in names
    assert "aj_50_other" not in names


def test_untrusted_file_helpers_reject_symlink_fifo_and_oversize(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    link = tmp_path / "result-link"
    link.symlink_to(victim)

    assert tasks._read_untrusted_regular_file(str(link), 1024) is None
    with pytest.raises(OSError):
        tasks._reset_untrusted_output_file(str(link))
    assert victim.read_text(encoding="utf-8") == "keep"

    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"x" * 1025)
    assert tasks._read_untrusted_regular_file(str(oversized), 1024) is None

    regular = tmp_path / "regular"
    regular.write_text("old", encoding="utf-8")
    tasks._reset_untrusted_output_file(str(regular))
    assert regular.read_bytes() == b""

    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        with pytest.raises((OSError, RuntimeError)):
            tasks._reset_untrusted_output_file(str(fifo))


def test_publish_snapshot_rebuilds_if_attempt_changes_mid_publish(monkeypatch):
    old = {"status": "Accepted", "attempt_trace_id": db.agent_judge_trace_id("old")}
    new = {"status": "Queued", "attempt_trace_id": db.agent_judge_trace_id("new")}
    snapshots = [old, new]
    stored = []

    class FakeRedis:
        def setex(self, _key, _ttl, payload):
            stored.append(json.loads(payload))

        def publish(self, _channel, payload):
            stored.append(json.loads(payload))

    monkeypatch.setattr(tasks, "_judge_rds", FakeRedis())
    monkeypatch.setattr(tasks, "build_judge_snapshot", lambda _sid: snapshots.pop(0))
    monkeypatch.setattr(
        tasks, "get_ranking_submission",
        lambda _sid: {"judge_attempt_id": "new"},
    )

    assert tasks._publish_snapshot(4) == new
    assert stored == [new, new]


def test_trace_journal_cap_is_explicit_and_never_exceeded(monkeypatch, tmp_path):
    path = tmp_path / "trace.jsonl"
    marker_size = len(json.dumps({
        "type": "assistant_message",
        "message": "执行轨迹已达到持久化上限，后续事件不再记录。",
        "_trace_source": "trace-journal",
        "_trace_offset": 0,
        "_trace_phase": "final",
    }, ensure_ascii=False).encode("utf-8")) + 1
    monkeypatch.setattr(tasks, "_TRACE_JOURNAL_MAX_BYTES", marker_size + 16)
    path.write_bytes(b"old\n")

    assert tasks._append_bounded_trace_journal(str(path), b"x" * (marker_size + 16))
    first_size = path.stat().st_size
    assert first_size <= tasks._TRACE_JOURNAL_MAX_BYTES
    assert "持久化上限" in path.read_text(encoding="utf-8")
    assert not tasks._append_bounded_trace_journal(str(path), b"more")
    assert path.stat().st_size == first_size


def test_claude_export_rejects_host_capture_truncation(monkeypatch):
    exported = SimpleNamespace(
        returncode=0,
        stdout=b'{"complete":true,"items":[]}',
        stderr=b"",
        stdout_truncated=True,
        timed_out=False,
    )
    monkeypatch.setattr(
        tasks, "_capture_process_output_limited",
        lambda *_args, **_kwargs: exported,
    )

    assert tasks._export_container_claude_jsonl("container") == {
        "complete": False,
        "items": [],
    }


def test_claude_export_uses_persisted_size_cursor_for_incremental_reads(monkeypatch):
    captured = {}

    def run(args, **_kwargs):
        captured["script"] = args[-1]
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "complete": True,
                "truncated": False,
                "has_files": True,
                "items": [],
            }).encode(),
            stderr=b"",
            stdout_truncated=False,
            timed_out=False,
        )

    monkeypatch.setattr(tasks, "_capture_process_output_limited", run)
    cursor = {
        "claude-deadbeef": 123,
        "__size__:claude-deadbeef": 456,
    }

    assert tasks._export_container_claude_jsonl("container", cursor) == {
        "complete": True,
        "truncated": False,
        "has_files": True,
        "items": [],
    }
    assert "'claude-deadbeef': 123" in captured["script"]
    assert "'__size__:claude-deadbeef': 456" in captured["script"]
    assert "BACKTRACK=256*1024" in captured["script"]
    assert "previous_size == size" in captured["script"]


def test_public_projection_fails_closed_when_endpoint_secrets_unavailable():
    snapshot = {
        "error_message": "internal endpoint error",
        "rules": [{"rule_text": "keep", "evidence": "secret", "evidence_html": "secret"}],
        "execution_trace": {
            "trace_messages": [{"kind": "assistant", "text": "secret"}],
            "trace_files": [], "stdout": "", "stderr": "",
        },
    }

    projected = routes._project_agent_judge_snapshot(
        snapshot, include_internal=False, redaction_ready=False,
    )

    assert projected["error_message"] == ""
    assert projected["rules"] == [{"rule_text": "keep", "evidence": "", "evidence_html": ""}]
    assert projected["execution_trace"]["trace_messages"][0]["text"] == ""
