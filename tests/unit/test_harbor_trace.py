"""官方 Harbor 会话的完整导入、来源保留和修订契约。"""

import json
import os

import pytest

from backend.oj_modules.integrations import harbor_trace as trace


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _trajectory(steps=None):
    steps = list(steps or [])
    if not any(step.get("source") == "user" for step in steps):
        steps.insert(0, {"step_id": 0, "source": "user", "message": "初始任务指令"})
    return {"schema_version": "ATIF-v1.7", "session_id": "official-session-1",
            "agent": {"name": "pi", "model_name": "deepseek-flash"},
            "final_metrics": {"total_prompt_tokens": 100, "total_completion_tokens": 23,
                              "extra": {"reasoning_tokens": 9}},
            "steps": steps}


def _sync(tmp_path, trajectory, *, secrets=(), final=True):
    _write(tmp_path / "trajectory.json", trajectory)
    emitted = []
    importer = trace.HarborTraceImporter(tmp_path, secrets=secrets, emit=emitted.append)
    assert importer.sync(final=final)
    return emitted, emitted[-1]["records"]


def test_atif_preserves_full_text_sources_metrics_ids_and_tool_errors(tmp_path):
    reasoning = "长推理" * 3000
    arguments = {"command": "x" * 4000}
    original = _trajectory([
        {"step_id": 1, "source": "user", "message": "原题目"},
        {"step_id": 2, "source": "system", "message": "原系统事件"},
        {"step_id": 3, "source": "agent", "message": "先运行命令", "reasoning_content": reasoning,
         "timestamp": "2026-11-08T01:00:00Z", "metrics": {"prompt_tokens": 100},
         "extra": {"native_id": "native-event", "anything": [1, 2]},
         "tool_calls": [{"tool_call_id": "call-1", "function_name": "bash", "arguments": arguments}],
         "observation": {"results": [{"source_call_id": "call-1", "content": "完整错误结果",
                                      "extra": {"is_error": True, "exit_code": 7}}]}},
    ])
    emitted, records = _sync(tmp_path, original)
    events = [record["event"] for record in records]
    assert emitted[0] == {"type": "native", "session_id": "official-session-1"}
    assert [event["kind"] for event in events] == ["system", "thinking", "assistant", "tool_call", "tool_result"]
    assert next(event for event in events if event["kind"] == "thinking")["text"] == reasoning
    call = next(event for event in events if event["kind"] == "tool_call")
    assert json.loads(call["text"]) == arguments
    assert call["source_payload"]["tool_call"]["tool_call_id"] == "call-1"
    assert events[-1]["is_error"] is True
    assert events[-1]["source_payload"]["observation"]["source_call_id"] == "call-1"
    assert events[1]["source_payload"]["atif_step"] == original["steps"][2]
    assert "原题目" not in json.dumps(records, ensure_ascii=False)
    assert emitted[-1]["complete"] is True
    counts = emitted[-1]["counts"]
    assert counts["atif_steps"] == 3
    assert counts["preserved_atif_steps"] == 2
    assert counts["skipped_initial_atif_steps"] == 1
    assert counts["native_events"] == counts["preserved_native_events"] == 0
    assert counts["imported_events"] == 5
    assert not any(key.startswith("excluded_") for key in counts)
    assert all(record["replace_snapshot"] and record["full_text"] and record["source"] == "harbor" for record in records)


def test_native_pi_keeps_branches_content_order_and_error_messages(tmp_path):
    entries = [
        {"type": "session", "id": "native-session"},
        {"type": "message", "id": "u1", "parentId": None,
         "message": {"role": "user", "content": [{"type": "text", "text": "题目"}]}},
        {"type": "message", "id": "a1", "parentId": "u1", "message": {
            "role": "assistant", "content": [
                {"type": "text", "text": "工具前的回复"},
                {"type": "thinking", "thinking": "完整思考"},
                {"type": "toolCall", "id": "tc1", "name": "bash", "arguments": {"command": "false"}},
            ], "usage": {"input": 11, "output": 22}, "stopReason": "toolUse"}},
        {"type": "message", "id": "t1", "parentId": "a1", "message": {
            "role": "toolResult", "toolCallId": "tc1", "toolName": "bash", "isError": True,
            "content": [{"type": "text", "text": "失败正文"}]}},
        # 旧分支不在官方当前 root-to-leaf ATIF 中，仍须保留。
        {"type": "message", "id": "abandoned", "parentId": "u1", "message": {
            "role": "assistant", "content": [], "stopReason": "error", "errorMessage": "原生 API 错误正文"}},
        {"type": "compaction", "id": "compact", "parentId": "t1", "summary": "压缩摘要",
         "usage": {"input": 7}, "tokensBefore": 123},
    ]
    sessions = tmp_path / "pi" / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "session.jsonl").write_text("\n".join(json.dumps(entry) for entry in entries))
    original = _trajectory([{"step_id": 1, "source": "agent", "message": "工具前的回复",
                             "extra": {"pi_event_id": "a1", "pi_parent_id": "u1"}}])
    emitted, records = _sync(tmp_path, original)
    events = [record["event"] for record in records]
    assert [event["kind"] for event in events] == ["assistant", "thinking", "tool_call", "tool_result", "assistant", "error", "system"]
    assert events[0]["text"] == "工具前的回复"
    assert events[3]["is_error"] is True
    assert events[3]["source_payload"]["native_event"]["message"]["toolCallId"] == "tc1"
    assert events[5]["text"] == "原生 API 错误正文"
    assert events[0]["source_payload"]["atif_steps"] == original["steps"][1:]
    preserved = [event["source_payload"]["native_event"] for event in events if "native_event" in event["source_payload"]]
    assert preserved == entries[2:]
    assert events[1]["text"] == "完整思考"
    assert emitted[-1]["counts"]["native_events"] == 6
    assert emitted[-1]["counts"]["skipped_initial_native_events"] == 2
    assert not any(key.startswith("excluded_") for key in emitted[-1]["counts"])


def test_atif_starts_after_initial_user_and_keeps_later_user_and_system(tmp_path):
    original = _trajectory([
        {"step_id": 1, "source": "system", "message": "SKIP-SYSTEM"},
        {"step_id": 2, "source": "agent", "message": "SKIP-STARTUP"},
        {"step_id": 3, "source": "user", "message": "SKIP-INSTRUCTION"},
        {"step_id": 4, "source": "system", "message": "工作中的系统记录"},
        {"step_id": 5, "source": "agent", "message": "开始解题"},
        {"step_id": 6, "source": "user", "message": "后续补充"},
        {"step_id": 7, "source": "agent", "message": "完成"},
    ])
    emitted, records = _sync(tmp_path, original)
    assert [record["event"]["kind"] for record in records] == ["system", "assistant", "user", "assistant"]
    assert [record["event"]["text"] for record in records] == ["工作中的系统记录", "开始解题", "后续补充", "完成"]
    assert "SKIP-" not in json.dumps(emitted, ensure_ascii=False)
    assert json.loads((tmp_path / "trajectory.json").read_text()) == original
    counts = emitted[-1]["counts"]
    assert counts["atif_steps"] == 7
    assert counts["skipped_initial_atif_steps"] == 3
    assert counts["preserved_atif_steps"] == 4


@pytest.mark.parametrize("native_files", [1, 2])
def test_native_and_atif_both_skip_whole_instruction_and_prefix(tmp_path, native_files):
    prefix = [
        {"type": "session", "id": "native-session"},
        {"type": "model_change", "id": "settings", "content": "SKIP-SETTINGS"},
        {"type": "message", "id": "instruction", "message": {"role": "user", "content": [
            {"type": "text", "text": "SKIP-INSTRUCTION-A"},
            {"type": "text", "text": "SKIP-INSTRUCTION-B"},
        ]}},
    ]
    trajectory = _trajectory([
        {"step_id": 1, "source": "system", "message": "SKIP-ATIF-SYSTEM"},
        {"step_id": 2, "source": "user", "message": "SKIP-ATIF-INSTRUCTION",
         "extra": {"pi_event_id": "instruction"}},
        {"step_id": 3, "source": "agent", "message": "正文",
         "extra": {"pi_event_id": "answer-0"}},
        {"step_id": 4, "source": "system", "message": "边界后的补充指标"},
    ])
    expected = []
    for index in range(native_files):
        work = [{"type": "message", "id": f"answer-{index}", "message": {
            "role": "assistant", "content": [{"type": "text", "text": f"回复-{index}"}],
        }}]
        path = tmp_path / "pi" / "sessions" / f"session-{index}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(json.dumps(entry) for entry in prefix + work))
        expected.append((path, prefix + work))
    emitted, records = _sync(tmp_path, trajectory)
    assert "SKIP-" not in json.dumps(emitted, ensure_ascii=False)
    assert [record["event"]["text"] for record in records if record["event"]["kind"] == "assistant"] == [f"回复-{index}" for index in range(native_files)]
    for path, original in expected:
        assert [json.loads(line) for line in path.read_text().splitlines()] == original
    counts = emitted[-1]["counts"]
    assert counts["skipped_initial_native_events"] == 3 * native_files
    assert counts["preserved_native_events"] == native_files
    assert counts["skipped_initial_atif_steps"] == 2
    assert counts["preserved_atif_steps"] == 2


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("instruction_seen", [False, True])
def test_prefix_only_waits_in_preview_and_allows_empty_final_import(tmp_path, native, instruction_seen):
    if native:
        path = tmp_path / "pi" / "sessions" / "session.jsonl"
        path.parent.mkdir(parents=True)
        entries = [{"type": "session", "id": "native-session"},
                   {"type": "model_change", "id": "settings", "content": "SKIP-SETTINGS"}]
        if instruction_seen:
            entries.append({"type": "message", "id": "instruction", "message": {
                "role": "user", "content": "SKIP-INSTRUCTION",
            }})
        path.write_text("\n".join(json.dumps(entry) for entry in entries))
    else:
        value = _trajectory()
        value["steps"] = [{"step_id": 1, "source": "system", "message": "SKIP-SETTINGS"}]
        if instruction_seen:
            value["steps"].append({"step_id": 2, "source": "user", "message": "SKIP-INSTRUCTION"})
        _write(tmp_path / "trajectory.json", value)
    emitted = []
    importer = trace.HarborTraceImporter(tmp_path, emit=emitted.append)
    assert importer.sync() is False
    assert [event["type"] for event in emitted] == ["native"]
    assert not (tmp_path / "numoj-import-manifest.json").exists()
    manifest = importer.sync(final=True)
    assert manifest["complete"] is True
    assert manifest["events_expected"] == manifest["events_imported"] == 0
    assert manifest["source_event_ids"] == []
    assert emitted[-1]["records"] == []
    assert "SKIP-" not in json.dumps(emitted, ensure_ascii=False)


def test_native_preview_keeps_ids_when_initial_instruction_is_not_imported(tmp_path):
    path = tmp_path / "pi" / "sessions" / "session.jsonl"
    _native_session(path, "第一条工作回复")
    emitted = []
    importer = trace.HarborTraceImporter(tmp_path, emit=emitted.append)
    assert importer.sync() is True
    first = emitted[-1]["records"][0]["event"]
    with path.open("a") as target:
        target.write("\n" + json.dumps({"type": "message", "id": "reply-2", "message": {
            "role": "assistant", "content": [{"type": "text", "text": "后续回复"}],
        }}))
    assert importer.sync() is True
    assert emitted[-1]["records"][0]["event"]["id"] == first["id"]
    assert len(emitted[-1]["records"]) == 2
    assert importer.sync(final=True)["events_imported"] == 2


def test_same_step_growth_republishes_same_ids_and_final_authoritative_snapshot(tmp_path):
    path = tmp_path / "trajectory.json"
    original = _trajectory([{"step_id": 1, "source": "agent", "message": "预览"}])
    _write(path, original)
    messages = []
    importer = trace.HarborTraceImporter(tmp_path, emit=messages.append)
    assert importer.sync() is True
    first = messages[-1]["records"][-1]["event"]
    assert importer.sync() is False
    original["steps"][-1]["message"] = "最终完整回复" * 3000
    _write(path, original)
    assert importer.sync() is True
    updated = messages[-1]["records"][-1]["event"]
    assert first["id"] == updated["id"]
    assert updated["text"] == original["steps"][-1]["message"]
    manifest = importer.sync(final=True)
    assert manifest["complete"] is True
    assert manifest["events_expected"] == manifest["events_imported"]
    assert messages[-1]["final"] is True
    assert messages[-1]["records"][0]["event"]["source_payload"]["import"]["complete"] is True


def test_recursive_redaction_keeps_token_counters_and_native_tuple_payloads(tmp_path):
    secret = "temporary-relay-credential"
    values = {"api_key": "long-term-value", "input_tokens": 123,
              "nested": [("x", {"authorization": "Bearer long-term-key", "message": secret})],
              "text": "Bearer another-secret sk-abcdefghijklmnop https://user:pass@example.org/api"}
    result = trace.redact_harbor_value(values, (secret,))
    serialized = json.dumps(result)
    assert "long-term-value" not in serialized and secret not in serialized
    assert "another-secret" not in serialized and "abcdefghijklmnop" not in serialized
    assert "user:pass" not in serialized
    assert result["input_tokens"] == 123
    assert result["nested"][0][1]["authorization"] == "[REDACTED]"


def test_redacts_old_relay_environment_assignments_without_a_saved_token():
    text = "NUMOJ_HARBOR_API_KEY=retired-url-safe-value\nOPENAI_API_KEY='quoted-secret'\nPASSWORD=\"another secret\"\n"
    cleaned = trace.redact_harbor_value(text)
    assert "retired-url-safe-value" not in cleaned
    assert "quoted-secret" not in cleaned and "another secret" not in cleaned
    assert cleaned.count("[REDACTED]") == 3


def test_atif_only_reasoning_and_real_replies_tools_are_complete(tmp_path):
    intermediate, final = "中间完整公开回复" * 12000, "最终完整公开回复" * 12000
    emitted, records = _sync(tmp_path, _trajectory([
        {"step_id": 1, "source": "agent", "message": "", "reasoning_content": "纯思考正文",
         "metrics": {"completion_tokens": 9, "extra": {"reasoning_tokens": 9}}},
        {"step_id": 2, "source": "agent", "message": intermediate,
         "tool_calls": [{"tool_call_id": "call-1", "function_name": "bash", "arguments": {"reasoning": "工具字面数据"}}],
         "observation": {"results": [{"source_call_id": "call-1", "content": "完整工具结果"}]}},
        {"step_id": 3, "source": "agent", "message": final},
    ]))
    events = [record["event"] for record in records]
    assert [event["kind"] for event in events] == ["thinking", "assistant", "tool_call", "tool_result", "assistant"]
    assert [event["text"] for event in events if event["kind"] == "assistant"] == [intermediate, final]
    assert events[0]["source_payload"]["atif_step"]["metrics"]["extra"]["reasoning_tokens"] == 9
    assert json.loads(events[2]["text"])["reasoning"] == "工具字面数据"
    assert events[0]["text"] == "纯思考正文"
    manifest = json.loads((tmp_path / "numoj-import-manifest.json").read_text())
    assert manifest["complete"] is True
    assert "content_policy" not in manifest
    assert not any(key.startswith("excluded_") for key in manifest["counts"])


@pytest.mark.parametrize("value", [None, "not-json", {"steps": "bad"}])
def test_missing_or_malformed_final_trace_is_explicit_error(tmp_path, value):
    if value is not None:
        (tmp_path / "trajectory.json").write_text(value if isinstance(value, str) else json.dumps(value))
    importer = trace.HarborTraceImporter(tmp_path, emit=lambda _event: None)
    assert importer.sync() is False
    with pytest.raises(trace.HarborTraceImportError):
        importer.sync(final=True)


def test_over_limit_or_symlink_final_trace_is_not_silently_ignored(tmp_path, monkeypatch):
    _write(tmp_path / "trajectory.json", _trajectory([{"step_id": 1, "source": "agent", "message": "x" * 4000}]))
    importer = trace.HarborTraceImporter(tmp_path, emit=lambda _event: None)
    monkeypatch.setattr(trace, "MAX_EVENT_BYTES", 1000)
    with pytest.raises(trace.HarborTraceImportError, match="8 MiB"):
        importer.sync(final=True)
    monkeypatch.setattr(trace, "MAX_TRACE_BYTES", 100)
    with pytest.raises(trace.HarborTraceImportError, match="64 MiB"):
        importer.sync(final=True)
    (tmp_path / "trajectory.json").unlink()
    target = tmp_path / "other.json"
    _write(target, _trajectory())
    (tmp_path / "trajectory.json").symlink_to(target)
    with pytest.raises(trace.HarborTraceImportError, match="符号链接"):
        importer.sync(final=True)


def test_native_only_error_log_can_be_imported_without_atif(tmp_path):
    path = tmp_path / "pi" / "sessions" / "failed.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"type": "session", "id": "native-session"}) + "\n" + json.dumps({
        "type": "message", "id": "u1", "message": {"role": "user", "content": "任务指令"},
    }) + "\n" + json.dumps({
        "type": "message", "id": "error-1", "message": {
            "role": "assistant", "stopReason": "error", "errorMessage": "上游错误", "content": [],
        },
    }))
    emitted = []
    importer = trace.HarborTraceImporter(tmp_path, emit=emitted.append)
    assert importer.sync(final=True)
    assert importer.native_session_id == "native-session"
    assert any(record["event"]["kind"] == "error" for record in emitted[-1]["records"])


def test_native_payloads_are_redacted_before_import_and_duplicate_step_ids_fail(tmp_path):
    secret = "temporary-private-value"
    sessions = tmp_path / "pi" / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "session.jsonl").write_text("\n".join(json.dumps(entry) for entry in [
        {"type": "session", "id": "session-1"},
        {"type": "message", "id": "u1", "message": {"role": "user", "content": "任务指令"}},
        {"type": "message", "id": "a1", "message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": secret},
            {"type": "text", "text": "Bearer unknown-password"},
        ], "details": {"api_key": "another-long-term-secret"}}},
    ]))
    emitted, _ = _sync(tmp_path, _trajectory(), secrets=(secret,))
    all_text = json.dumps(emitted)
    assert secret not in all_text and "unknown-password" not in all_text
    assert "another-long-term-secret" not in all_text
    assert emitted[-1]["counts"]["native_events"] == 3
    assert emitted[-1]["counts"]["preserved_native_events"] == 1
    (sessions / "session.jsonl").unlink()
    _write(tmp_path / "trajectory.json", _trajectory([
        {"step_id": 1, "source": "agent", "message": "one"},
        {"step_id": 1, "source": "agent", "message": "two"},
    ]))
    with pytest.raises(trace.HarborTraceImportError, match="重复"):
        trace.HarborTraceImporter(tmp_path, emit=lambda _event: None).sync(final=True)


def test_manifest_is_private_and_only_published_after_successful_final_persistence(tmp_path):
    _write(tmp_path / "trajectory.json", _trajectory([{"step_id": 1, "source": "agent", "message": "完整回复"}]))
    path = tmp_path / "numoj-import-manifest.json"
    seen = []

    def persist(event):
        if event["type"] == "trace":
            assert not path.exists()
            seen.extend(event["records"])

    importer = trace.HarborTraceImporter(tmp_path, emit=persist)
    assert importer.sync() is True
    assert not path.exists()
    manifest = importer.sync(final=True)
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == manifest == importer.import_manifest
    assert manifest["source_event_ids"] == [record["event"]["id"] for record in seen[-1:]]
    assert manifest["counts"]["preserved_atif_steps"] == 1

    def fail(_event):
        raise RuntimeError("database not committed")

    with pytest.raises(RuntimeError, match="not committed"):
        trace.HarborTraceImporter(tmp_path, emit=fail).sync(final=True)
    assert not path.exists()


def _native_session(path, text="可信日志"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(entry) for entry in [
        {"type": "session", "id": "native-session"},
        {"type": "message", "id": "u1", "message": {"role": "user", "content": "初始任务指令"}},
        {"type": "message", "id": "message-1", "message": {
            "role": "assistant", "content": [{"type": "text", "text": text}],
        }},
    ]))


@pytest.mark.parametrize("unsafe", ["pi-link", "sessions-link", "file-link", "pi-fifo", "file-fifo"])
def test_secure_native_reads_reject_symlink_ancestors_leaf_and_fifo(tmp_path, unsafe):
    agent = tmp_path / "agent"
    outside = tmp_path / "outside"
    agent.mkdir()
    _write(agent / "trajectory.json", _trajectory())
    _native_session(outside / "sessions" / "session.jsonl", "宿主私有内容")
    if unsafe == "pi-link":
        (agent / "pi").symlink_to(outside, target_is_directory=True)
    elif unsafe == "sessions-link":
        (agent / "pi").mkdir()
        (agent / "pi" / "sessions").symlink_to(outside / "sessions", target_is_directory=True)
    elif unsafe == "pi-fifo":
        os.mkfifo(agent / "pi")
    else:
        sessions = agent / "pi" / "sessions"
        sessions.mkdir(parents=True)
        if unsafe == "file-link":
            (sessions / "session.jsonl").symlink_to(outside / "sessions" / "session.jsonl")
        else:
            os.mkfifo(sessions / "session.jsonl")
    emitted = []
    importer = trace.HarborTraceImporter(agent, emit=emitted.append)
    assert importer.sync() is False
    assert not emitted
    with pytest.raises(trace.HarborTraceImportError):
        importer.sync(final=True)
    assert not (agent / "numoj-import-manifest.json").exists()


@pytest.mark.parametrize("phase", ["before-child-open", "after-listdir"])
def test_open_directory_fds_pin_native_ancestry_during_replacement(tmp_path, monkeypatch, phase):
    agent = tmp_path / "agent"
    agent.mkdir()
    original = agent / "pi"
    _native_session(original / "sessions" / "session.jsonl", "可信原目录内容")
    outside = tmp_path / "outside"
    _native_session(outside / "sessions" / "session.jsonl", "不能读取的宿主内容")
    actual_open, actual_listdir = os.open, os.listdir
    replaced = False

    def replace_ancestor():
        nonlocal replaced
        if not replaced:
            original.rename(agent / "pi-original")
            original.symlink_to(outside, target_is_directory=True)
            replaced = True

    def open_at(path, flags, *args, **kwargs):
        if kwargs.get("dir_fd") is not None:
            assert flags & os.O_NOFOLLOW
            if path in {"pi", "sessions"}:
                assert flags & os.O_DIRECTORY
            if phase == "before-child-open" and path == "sessions":
                replace_ancestor()
        return actual_open(path, flags, *args, **kwargs)

    def list_at(directory):
        assert isinstance(directory, int)
        if phase == "after-listdir":
            replace_ancestor()
        return actual_listdir(directory)

    monkeypatch.setattr(trace.os, "open", open_at)
    monkeypatch.setattr(trace.os, "listdir", list_at)
    emitted = []
    assert trace.HarborTraceImporter(agent, emit=emitted.append).sync(final=True)["complete"] is True
    assert replaced
    serialized = json.dumps(emitted, ensure_ascii=False)
    assert "可信原目录内容" in serialized
    assert "不能读取的宿主内容" not in serialized


def test_leaf_replacement_with_symlink_is_rejected_at_open(tmp_path, monkeypatch):
    native = tmp_path / "pi" / "sessions" / "session.jsonl"
    _native_session(native)
    outside = tmp_path / "private.jsonl"
    _native_session(outside, "不能读取的宿主内容")
    actual_open = os.open
    replaced = False

    def open_at(path, flags, *args, **kwargs):
        nonlocal replaced
        if path == "session.jsonl" and kwargs.get("dir_fd") is not None and not replaced:
            native.unlink()
            native.symlink_to(outside)
            replaced = True
        return actual_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(trace.os, "open", open_at)
    emitted = []
    importer = trace.HarborTraceImporter(tmp_path, emit=emitted.append)
    assert importer.sync() is False
    assert replaced and not emitted
    with pytest.raises(trace.HarborTraceImportError, match="符号链接"):
        importer.sync(final=True)


def test_native_partial_json_retries_in_preview_but_final_is_strict(tmp_path):
    native = tmp_path / "pi" / "sessions" / "session.jsonl"
    _native_session(native)
    complete = native.read_text()
    native.write_text(complete + '\n{"type":"message"')
    emitted = []
    importer = trace.HarborTraceImporter(tmp_path, emit=emitted.append)
    assert importer.sync() is False
    assert not emitted
    with pytest.raises(trace.HarborTraceImportError, match="解析失败"):
        importer.sync(final=True)
    native.write_text(complete)
    assert importer.sync(final=True)["complete"] is True


def test_native_file_disappearance_after_fd_enumeration_is_not_silently_skipped(tmp_path, monkeypatch):
    native = tmp_path / "pi" / "sessions" / "session.jsonl"
    _native_session(native)
    _write(tmp_path / "trajectory.json", _trajectory())
    actual_listdir = os.listdir

    def list_at(directory):
        names = actual_listdir(directory)
        native.unlink()
        return names

    monkeypatch.setattr(trace.os, "listdir", list_at)
    with pytest.raises(trace.HarborTraceImportError, match="读取或解析失败"):
        trace.HarborTraceImporter(tmp_path, emit=lambda _event: None).sync(final=True)
