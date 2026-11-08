"""Agent v2 轨迹存储的分块、公开投影与用量快照契约。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.oj_modules.agents import trace_store


class _Cursor:
    def __init__(self, handler):
        self.handler = handler
        self.rowcount = 0
        self.queries = []
        self._one = None
        self._all = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        self.queries.append((normalized, params))
        result = self.handler(normalized, params) or {}
        self.rowcount = int(result.get("rowcount", 0))
        self._one = result.get("one")
        self._all = list(result.get("all") or ())

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


class _Connection:
    def __init__(self, handler):
        self.cursor_instance = _Cursor(handler)
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def _record(sequence, kind, text, **event):
    return {
        "type": "numoj_trace",
        "version": 1,
        "sequence": sequence,
        "event": {
            "id": f"source-{sequence}",
            "kind": kind,
            "text": text,
            **event,
        },
    }


def test_ingest_groups_internal_events_between_public_messages(monkeypatch):
    inserted = []
    updated = []

    def handler(sql, params):
        if sql.startswith("SELECT schema_version"):
            return {"one": {
                "schema_version": 2,
                "last_event_order": 0,
                "next_item_index": 1,
                "active_block_id": None,
                "active_item_index": None,
            }}
        if sql.startswith("INSERT IGNORE INTO agent_trace_events"):
            inserted.append(params)
            return {"rowcount": 1}
        if sql.startswith("UPDATE agent_trace_sync_state"):
            updated.append((sql, params))
            return {"rowcount": 1}
        return {"rowcount": 1}

    connection = _Connection(handler)
    monkeypatch.setattr(trace_store, "get_db_connection", lambda: connection)
    records = [
        _record(1, "thinking", "先分析"),
        _record(2, "tool", "运行 rg", title="已搜索代码"),
        _record(3, "tool_result", "找到 3 处"),
        _record(4, "assistant", "我已经定位到入口。"),
        _record(5, "reasoning", "继续核对边界"),
        {
            "type": "numoj_steer",
            "version": 1,
            "sequence": 6,
            "message_id": "steer-1",
        },
    ]

    assert trace_store.ingest_agent_trace_records(
        "task-1", records, final=True
    ) == 6

    # INSERT 参数顺序：task/event/order/item/block/kind/...
    assert [params[3] for params in inserted] == [1, 1, 1, 2, 3, 4]
    assert inserted[0][4] == inserted[1][4] == inserted[2][4]
    assert inserted[0][4].startswith("work-")
    assert inserted[3][4] is None
    assert inserted[4][4].startswith("work-")
    assert inserted[4][4] != inserted[0][4]
    assert inserted[5][4] is None
    assert [params[5] for params in inserted] == [
        "thinking", "tool", "tool_result", "assistant", "reasoning", "user",
    ]
    update_sql, update_params = updated[-1]
    assert "migration_completed" not in update_sql
    assert update_params == (6, 5, None, None, "task-1")
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.closed is True


def test_ingest_ignores_malformed_record_versions(monkeypatch):
    def handler(sql, _params):
        if sql.startswith("SELECT schema_version"):
            return {"one": {
                "schema_version": 2,
                "last_event_order": 0,
                "next_item_index": 1,
                "active_block_id": None,
                "active_item_index": None,
            }}
        return {"rowcount": 1}

    connection = _Connection(handler)
    monkeypatch.setattr(trace_store, "get_db_connection", lambda: connection)

    inserted = trace_store.ingest_agent_trace_records(
        "task-2",
        [{"version": "broken"}, {"version": None}],
    )

    assert inserted == 0
    assert not any(
        sql.startswith("INSERT IGNORE INTO agent_trace_events")
        for sql, _params in connection.cursor_instance.queries
    )


def test_subagent_status_is_persisted_without_splitting_work_block(monkeypatch):
    inserted = []
    updates = []

    def handler(sql, params):
        if sql.startswith("SELECT schema_version"):
            return {"one": {
                "schema_version": 2,
                "last_event_order": 0,
                "next_item_index": 1,
                "active_block_id": None,
                "active_item_index": None,
            }}
        if sql.startswith("INSERT IGNORE INTO agent_trace_events"):
            inserted.append(params)
            return {"rowcount": 1}
        if sql.startswith("UPDATE agent_trace_sync_state"):
            updates.append(params)
            return {"rowcount": 1}
        return {"rowcount": 1}

    monkeypatch.setattr(
        trace_store,
        "get_db_connection",
        lambda: _Connection(handler),
    )
    status_payload = json.dumps({
        "schema_version": 1,
        "subagent_id": "worker-a",
        "name": "检索免费模型",
        "status": "running",
    }, ensure_ascii=False)

    assert trace_store.ingest_agent_trace_records("task-subagent", [
        _record(1, "thinking", "先制定计划"),
        _record(
            2,
            "subagent",
            status_payload,
            title="检索免费模型",
            meta=trace_store.AGENT_SUBAGENT_STATUS_META,
            format="json",
        ),
        _record(3, "tool", "继续主任务"),
    ]) == 3

    assert inserted[0][4] == inserted[2][4]
    assert inserted[1][4] is None
    assert updates[-1][1:4] == (2, inserted[0][4], 1)


def test_list_subagents_returns_latest_status_in_first_seen_order(monkeypatch):
    rows = [
        {
            "event_order": 2,
            "title": "资料检索",
            "text": json.dumps({
                "schema_version": 1,
                "subagent_id": "worker-a",
                "name": "资料检索",
                "status": "running",
            }, ensure_ascii=False),
        },
        {
            "event_order": 3,
            "title": "限流核对",
            "text": json.dumps({
                "schema_version": 1,
                "subagent_id": "worker-b",
                "name": "限流核对",
                "status": "running",
            }, ensure_ascii=False),
        },
        {
            "event_order": 8,
            "title": "资料检索",
            "text": json.dumps({
                "schema_version": 1,
                "subagent_id": "worker-a",
                "name": "资料检索",
                "status": "completed",
            }, ensure_ascii=False),
        },
    ]

    def handler(sql, params):
        assert "kind='subagent' AND meta=%s" in sql
        assert params == (
            "task-subagents", trace_store.AGENT_SUBAGENT_STATUS_META,
        )
        return {"all": rows}

    monkeypatch.setattr(
        trace_store,
        "get_db_connection",
        lambda: _Connection(handler),
    )

    assert trace_store.list_agent_trace_subagents("task-subagents") == [
        {
            "subagent_id": "worker-a",
            "name": "资料检索",
            "status": "completed",
        },
        {
            "subagent_id": "worker-b",
            "name": "限流核对",
            "status": "running",
        },
    ]


def test_public_timeline_contains_only_replies_steers_and_work_summaries(
    monkeypatch,
):
    public_rows = [
        {
            "item_index": 1,
            "event_order": 1,
            "event_id": "event-a",
            "kind": "assistant",
            "text": "我先检查配置。",
            "message_id": None,
        },
        {
            "item_index": 3,
            "event_order": 5,
            "event_id": "event-b",
            "kind": "user",
            "text": "",
            "message_id": "steer-1",
        },
        {
            "item_index": 4,
            "event_order": 6,
            "event_id": "event-c",
            "kind": "assistant",
            "text": "最终结论",
            "message_id": None,
        },
    ]
    block_rows = [{
        "item_index": 2,
        "block_id": "work-1234567890abcdef",
        "event_order": 2,
        "thinking_count": 3,
        "tool_count": 2,
        "has_error": 0,
        "event_count": 7,
        "last_event_order": 8,
    }]

    def handler(sql, _params):
        if "block_id IS NULL" in sql:
            return {"all": public_rows}
        if "GROUP BY item_index, block_id" in sql:
            return {"all": block_rows}
        if "SELECT active_block_id" in sql:
            return {"one": {"active_block_id": "work-1234567890abcdef"}}
        raise AssertionError(sql)

    monkeypatch.setattr(
        trace_store,
        "get_db_connection",
        lambda: _Connection(handler),
    )
    steer_records = [{
        "message_id": "steer-1",
        "user_message": "请再核对一次",
        "attachments": [{"name": "notes.txt"}],
    }]

    running = trace_store.list_agent_trace_timeline(
        "task-3", status="Running", steer_records=steer_records
    )
    assert [item["kind"] for item in running] == [
        "assistant", "work_summary", "user", "assistant",
    ]
    assert running[1]["summary"] == "工作中…3 thinkings, 2 tool calls"
    assert running[1]["event_count"] == 7
    assert running[1]["last_event_order"] == 8
    assert running[2]["text"] == "请再核对一次"

    completed = trace_store.list_agent_trace_timeline(
        "task-3", status="Completed", steer_records=steer_records
    )
    assert [item["kind"] for item in completed] == [
        "assistant", "work_summary", "user",
    ]
    assert completed[1]["summary"] == "3 thinkings, 2 tool calls"


def test_token_usage_round_trips_through_v2_sync_state(monkeypatch):
    stored_payload = {"value": None}

    def handler(sql, params):
        if sql.startswith("SELECT schema_version"):
            return {"one": {
                "schema_version": 2,
                "last_event_order": 0,
                "next_item_index": 1,
                "active_block_id": None,
                "active_item_index": None,
            }}
        if sql.startswith("UPDATE agent_trace_sync_state"):
            stored_payload["value"] = params[0]
            return {"rowcount": 1}
        if sql.startswith("SELECT token_usage_json"):
            return {"one": {"token_usage_json": stored_payload["value"]}}
        return {"rowcount": 1}

    monkeypatch.setattr(
        trace_store,
        "get_db_connection",
        lambda: _Connection(handler),
    )
    usage = {
        "source": "pi",
        "request_count": 2,
        "input_uncached_tokens": 120,
        "input_cached_tokens": 30,
        "output_tokens": 15,
        "incremental": True,
    }

    assert trace_store.save_agent_trace_token_usage("task-4", usage) is True
    assert json.loads(stored_payload["value"])["incremental"] is True
    restored = trace_store.get_agent_trace_token_usage("task-4")
    assert restored["source"] == "pi"
    assert restored["request_count"] == 2
    assert restored["input_total_tokens"] == 150
    assert restored["incremental"] is True


def test_ordinary_tool_result_keeps_original_write_and_read_behavior(monkeypatch):
    text = "工具结果开始\n" + "x" * (32 * 1024) + "\n工具结果末尾"
    normalized = trace_store._normalize_canonical_record(
        "task-full-result", _record(1, "tool_result", text),
    )
    assert normalized['text'] == text
    connection = _Connection(lambda _sql, _params: {"all": [normalized]})
    monkeypatch.setattr(trace_store, "get_db_connection", lambda: connection)
    block = trace_store.get_agent_trace_work_block("task-full-result", "work-0123456789abcdef")
    assert block["messages"][0]["text"] == text
    assert 'truncated' not in block['messages'][0]


def _harbor_record(sequence, kind, text, **event):
    record = _record(sequence, kind, text, role=kind, source_payload={
        "native_event": {"id": f"native-{sequence}", "extra": {"kept": True}},
    }, **event)
    record.update(source="harbor", full_text=True, replace_snapshot=True,
                  snapshot_id="official-session")
    return record


def _harbor_owner():
    from backend.oj_modules.integrations import harbor_runtime

    root = Path(harbor_runtime.config.REVERSE_JUDGE_WORKSPACE_ROOT).resolve()
    return {"task_kind": "judge", "judge_kind": "reverse_answer",
            "runtime_config_json": json.dumps({"harbor_runtime": {
                "task_path": str(root / "full-text-task"),
                "trial_dir": str(root / "full-text-trial"),
            }})}


@pytest.mark.parametrize("kind", ["tool_call", "assistant", "tool_result", "user", "system", "error"])
def test_harbor_envelope_preserves_full_utf8_body_role_and_source(kind):
    text = "  原文\n" + "长正文" * 24000 + "\n结尾-SENTINEL  "
    record = _harbor_record(1, kind, text)
    normalized = trace_store._normalize_canonical_record("harbor-full", record)
    restored = trace_store._stored_event_content(normalized)
    assert restored['text'] == text
    assert restored['full_text'] is True
    assert not {'truncated', 'original_bytes', 'source_payload_truncated'} & restored.keys()
    assert restored["kind"] == restored["role"] == kind
    assert restored["source_event_id"] == record["event"]["id"]
    assert restored["snapshot_id"] == "official-session"
    assert restored['source_payload'] == record['event']['source_payload']
    assert normalized["kind"] == ("tool_result" if kind in {"system", "error"} else kind)
    assert normalized["is_error"] is (kind == "error")


@pytest.mark.parametrize("kind", ["thinking", "reasoning"])
@pytest.mark.parametrize("length", [1199, 1200, 1201, 10000])
def test_harbor_cot_uses_ordinary_agent_character_limit_before_storage(kind, length):
    original = "思" * length
    record = _harbor_record(1, kind, original)
    normalized = trace_store._normalize_canonical_record("harbor-cot", record)
    ordinary = trace_store._normalize_canonical_record("ordinary-cot", _record(1, kind, original))
    restored = trace_store._stored_event_content(normalized)
    assert restored["text"] == ordinary["text"]
    assert len(restored["text"]) <= 1200
    assert record["event"]["text"] == original


def test_harbor_cot_source_copies_are_limited_without_changing_raw_sources_or_tool_data(monkeypatch):
    original = "完整思考" * 3000
    clipped = original[:1199] + "…"
    tool_data = {"reasoning": original, "reasoning_content": original}
    step = {"step_id": 1, "source": "agent", "reasoning_content": original,
            "message": original, "tool_calls": [{"arguments": tool_data}]}
    payload = {
        "native_event": {"id": "native-1", "message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": original},
            {"type": "reasoning", "reasoning": original, "text": original},
            {"type": "text", "text": original},
            {"type": "toolCall", "name": "bash", "arguments": tool_data},
        ]}},
        "atif_step": step, "atif_steps": [step],
        "block": {"type": "thinking", "thinking": original},
    }
    records = [_harbor_record(1, "thinking", original), _harbor_record(2, "assistant", original)]
    for record in records:
        record["event"]["source_payload"] = payload
    before = json.dumps(records, ensure_ascii=False)
    inserted = []

    def handler(sql, params):
        if sql.startswith("SELECT schema_version"):
            return {"one": {"schema_version": 2}}
        if sql.startswith("SELECT s.task_kind"):
            return {"one": _harbor_owner()}
        if sql.startswith("INSERT IGNORE INTO agent_trace_events"):
            inserted.append(json.loads(params[7]))
        return {"rowcount": 1}

    connection = _Connection(handler)
    monkeypatch.setattr(trace_store, "get_db_connection", lambda: connection)
    assert trace_store.ingest_agent_trace_records("harbor-cot-source", records, final=True) == 2
    assert connection.commits == 1
    assert inserted[0]["text"] == clipped
    assert inserted[1]["text"] == original
    for content in inserted:
        source = content["source_payload"]
        blocks = source["native_event"]["message"]["content"]
        assert blocks[0]["thinking"] == clipped
        assert blocks[1]["reasoning"] == blocks[1]["text"] == clipped
        assert blocks[2]["text"] == original
        assert blocks[3]["arguments"] == tool_data
        assert source["atif_step"]["reasoning_content"] == clipped
        assert source["atif_steps"][0]["reasoning_content"] == clipped
        assert source["atif_step"]["message"] == original
        assert source["atif_step"]["tool_calls"][0]["arguments"] == tool_data
        assert source["block"]["thinking"] == clipped
    assert json.dumps(records, ensure_ascii=False) == before


def test_harbor_snapshot_replaces_revised_events_under_the_same_task_lock(monkeypatch):
    inserted, deleted = [], []
    state = {"schema_version": 2, "last_event_order": 900, "next_item_index": 42}

    def handler(sql, params):
        if sql.startswith("SELECT schema_version"):
            return {"one": dict(state)}
        if sql.startswith("SELECT s.task_kind"):
            return {"one": _harbor_owner()}
        if sql.startswith("DELETE FROM agent_trace_events"):
            deleted.append(params)
        if sql.startswith("INSERT IGNORE INTO agent_trace_events"):
            inserted.append(params)
        if sql.startswith("UPDATE agent_trace_sync_state"):
            state.update(last_event_order=params[0], next_item_index=params[1])
        return {"rowcount": 1}

    connections = []
    def connect():
        connection = _Connection(handler)
        connections.append(connection)
        return connection
    monkeypatch.setattr(trace_store, "get_db_connection", connect)
    preview = _harbor_record(1, "assistant", "预览")
    revised = _harbor_record(1, "assistant", "修订后的完整正文-SENTINEL")
    assert trace_store.ingest_agent_trace_records("harbor-revision", [preview]) == 1
    assert trace_store.ingest_agent_trace_records("harbor-revision", [revised], final=True) == 1
    assert deleted == [("harbor-revision",), ("harbor-revision",)]
    assert inserted[0][1] == inserted[1][1]
    assert inserted[0][2:4] == inserted[1][2:4] == (1, 1)
    assert json.loads(inserted[1][7])["text"] == "修订后的完整正文-SENTINEL"
    for connection in connections:
        queries = [sql for sql, _ in connection.cursor_instance.queries]
        assert next(i for i, sql in enumerate(queries) if "FOR UPDATE" in sql) < next(i for i, sql in enumerate(queries) if sql.startswith("DELETE"))
        assert connection.commits == 1 and connection.rollbacks == 0


@pytest.mark.parametrize("changes", [
    {"task_kind": "custom"}, {"judge_kind": "reverse_quality"},
    {"runtime_config_json": "{}"}, {"runtime_config_json": "not-json"},
])
def test_harbor_snapshot_rejects_foreign_or_unconfigured_task_before_delete(monkeypatch, changes):
    def handler(sql, _params):
        if sql.startswith("SELECT schema_version"):
            return {"one": {"schema_version": 2}}
        if sql.startswith("SELECT s.task_kind"):
            return {"one": _harbor_owner() | changes}
        return {"rowcount": 1}
    connection = _Connection(handler)
    monkeypatch.setattr(trace_store, "get_db_connection", lambda: connection)
    with pytest.raises(trace_store.AgentTraceStoreError):
        trace_store.ingest_agent_trace_records("foreign-task", [_harbor_record(1, "assistant", "full")])
    assert not any(sql.startswith("DELETE") for sql, _ in connection.cursor_instance.queries)
    assert connection.rollbacks == 1 and connection.commits == 0


def test_harbor_snapshot_rolls_back_if_insert_ignore_omits_any_event(monkeypatch):
    def handler(sql, _params):
        if sql.startswith("SELECT schema_version"):
            return {"one": {"schema_version": 2}}
        if sql.startswith("SELECT s.task_kind"):
            return {"one": _harbor_owner()}
        if sql.startswith("INSERT IGNORE INTO agent_trace_events"):
            return {"rowcount": 0}
        return {"rowcount": 1}
    connection = _Connection(handler)
    monkeypatch.setattr(trace_store, "get_db_connection", lambda: connection)
    with pytest.raises(trace_store.AgentTraceStoreError, match="未全部保存"):
        trace_store.ingest_agent_trace_records("full-rollback", [_harbor_record(1, "assistant", "full")])
    assert connection.rollbacks == 1 and connection.commits == 0


@pytest.mark.parametrize("case", ["single", "total", "duplicate", "mixed"])
def test_harbor_limits_and_invalid_batches_fail_before_opening_database(monkeypatch, case):
    def no_connection():
        raise AssertionError("must validate full snapshot before database writes")
    monkeypatch.setattr(trace_store, "get_db_connection", no_connection)
    records = [_harbor_record(1, "thinking", "x" * 1000)]
    if case == "single":
        monkeypatch.setattr(trace_store, "_MAX_FULL_EVENT_BYTES", 512)
    elif case == "total":
        monkeypatch.setattr(trace_store, "_MAX_FULL_TRACE_BYTES", 1024)
        records.append(_harbor_record(2, "tool_call", "y" * 1000))
    elif case == "duplicate":
        records.append(dict(records[0]))
    else:
        records.append(_record(2, "assistant", "ordinary"))
    with pytest.raises(trace_store.AgentTraceStoreError):
        trace_store.ingest_agent_trace_records("invalid-full", records)


def test_harbor_user_and_full_final_assistant_remain_in_completed_timeline(monkeypatch):
    user = trace_store._normalize_canonical_record("full-public", _harbor_record(1, "user", "  独立题目指令\n"))
    final = "完整答案\n" + "z" * 70000 + "FINAL-SENTINEL"
    assistant = trace_store._normalize_canonical_record("full-public", _harbor_record(2, "assistant", final))
    rows = [dict(user, item_index=1), dict(assistant, item_index=2)]
    def handler(sql, _params):
        if "block_id IS NULL" in sql:
            return {"all": rows}
        if "GROUP BY item_index, block_id" in sql:
            return {"all": []}
        if "SELECT active_block_id" in sql:
            return {"one": {}}
        if sql.startswith("SELECT text"):
            return {"one": assistant}
        raise AssertionError(sql)
    monkeypatch.setattr(trace_store, "get_db_connection", lambda: _Connection(handler))
    timeline = trace_store.list_agent_trace_timeline("full-public", status="Completed")
    assert [item["kind"] for item in timeline] == ["user", "assistant"]
    assert timeline[0]["text"] == "  独立题目指令\n"
    assert timeline[-1]['text'] == final
    assert timeline[-1]['full_text'] is True
    assert not {'truncated', 'original_bytes', 'source_payload_truncated'} & timeline[-1].keys()
    assert timeline[-1]["source_event_id"] == "source-2"
    assert trace_store.get_last_agent_trace_assistant("full-public") == timeline[-1]['text']


def test_harbor_full_work_block_survives_domain_and_http_readback(monkeypatch):
    from flask import Flask
    from backend.oj_modules.routes import problem_core_routes as routes

    expected = []
    kinds = ("system", "tool_call", "tool_result", "error")
    for sequence, kind in enumerate(kinds, 1):
        record = _harbor_record(sequence, kind, kind + "-" + "中" * 24000 + "-SENTINEL")
        expected.append(trace_store._normalize_canonical_record("full-block", record))
    monkeypatch.setattr(trace_store, "get_db_connection", lambda: _Connection(lambda *_: {"all": expected}))
    block = trace_store.get_agent_trace_work_block("full-block", "work-0123456789abcdef")
    assert [message["kind"] for message in block["messages"]] == list(kinds)
    assert [message["event_order"] for message in block["messages"]] == list(range(1, 5))
    monkeypatch.setattr(routes, "current_user", lambda: {"username": "admin", "is_admin": 1})
    monkeypatch.setattr(routes, "_agent_task_for_actor", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(routes, "get_agent_trace_work_block", lambda *_args: block)
    monkeypatch.setattr(routes, "render_rich_markdown", lambda text: "<safe>" + text + "</safe>")
    app = Flask(__name__)
    with app.test_request_context("/agent/runs/full-block/work-blocks/work-0123456789abcdef"):
        payload = routes.agent_run_work_block("full-block", "work-0123456789abcdef").get_json()
    for sequence, message in enumerate(payload["block"]["messages"], 1):
        assert message["text"] == kinds[sequence - 1] + "-" + "中" * 24000 + "-SENTINEL"
        assert message["source_event_id"] == f"source-{sequence}"
        assert message['source_payload'] == {'native_event': {
            'id': f'native-{sequence}', 'extra': {'kept': True},
        }}
        assert message['full_text'] is True
        assert not {'truncated', 'original_bytes', 'source_payload_truncated'} & message.keys()
    assert payload["block"]["messages"][-1]["is_error"] is True


def test_harbor_full_tool_arguments_metadata_and_source_payload_are_preserved():
    body = json.dumps({'command': '超长工具参数' * 30000}, ensure_ascii=False)
    record = _harbor_record(7, 'tool_call', body)
    record['event']['title'] = '标题' * 5000
    record['event']['meta'] = 'meta' * 30000
    record['event']['source_payload'] = {
        'native_file': 'pi/sessions/original.jsonl', 'native_line': 42,
        'native_event': {'id': 'native-7', 'parentId': 'native-parent', 'timestamp': '2026-11-08T00:00:00Z',
            'message': {'role': 'assistant', 'stopReason': 'toolUse',
                'content': [{'type': 'toolCall', 'id': 'call-7', 'arguments': {'command': body}}],
                'usage': {'input': 11, 'output': 22, 'extra': ['huge'] * 10000}}},
        'atif_steps': [{'step_id': 3, 'extra': {'huge': '额外' * 100000}},
                       {'step_id': 4, 'message': body}],
        'extra': {'huge': ['metadata'] * 100000},
    }
    normalized = trace_store._normalize_canonical_record('full-metadata', record)
    content = trace_store._stored_event_content(normalized)
    assert content['text'] == body
    assert content['title'] == record['event']['title']
    assert content['meta'] == record['event']['meta']
    assert content['source_payload'] == record['event']['source_payload']
    assert content['full_text'] is True
    assert not {'truncated', 'original_bytes', 'source_payload_truncated'} & content.keys()


def test_harbor_full_tool_result_keeps_call_relationship_and_error():
    record = _harbor_record(3, 'tool_result', '输出' * 20000, is_error=True)
    record['event']['source_payload'] = {'native_file': 'pi/sessions/log.jsonl', 'native_line': 9,
        'native_event': {'id': 'result-3', 'parentId': 'assistant-2', 'message': {
            'role': 'toolResult', 'toolCallId': 'call-2', 'content': [{'type': 'text', 'text': '输出' * 20000}]}},
        'observation': {'source_call_id': 'call-2', 'extra': {'is_error': True}}, 'atif_step_id': 2}
    normalized = trace_store._normalize_canonical_record('result-relationships', record)
    content = trace_store._stored_event_content(normalized)
    assert content['text'] == record['event']['text']
    assert content['source_payload'] == record['event']['source_payload']
    assert content['source_payload']['native_event']['message']['toolCallId'] == 'call-2'
    assert content['source_payload']['observation']['source_call_id'] == 'call-2'
    assert normalized['is_error'] is True


def test_harbor_full_batch_over_sixteen_mib_is_saved_without_truncation(monkeypatch):
    inserted = []
    def handler(sql, params):
        if sql.startswith('SELECT schema_version'):
            return {'one': {'schema_version': 2}}
        if sql.startswith('SELECT s.task_kind'):
            return {'one': _harbor_owner()}
        if sql.startswith('INSERT IGNORE INTO agent_trace_events'):
            inserted.append(params)
        return {'rowcount': 1}
    connection = _Connection(handler)
    monkeypatch.setattr(trace_store, 'get_db_connection', lambda: connection)
    body = '完整中间输出' * 110000
    records = [_harbor_record(sequence, 'assistant' if sequence in {1, 9} else 'tool_result', body)
               for sequence in range(1, 10)]
    assert sum(len(json.dumps(record, ensure_ascii=False).encode()) for record in records) > 16 * 1024 * 1024
    assert trace_store.ingest_agent_trace_records('full-large-batch', records, final=True) == 9
    assert len(inserted) == 9 and connection.commits == 1
    for values in inserted:
        content = json.loads(values[7])
        assert content['text'] == body
        assert 'truncated' not in content


def test_legacy_full_envelope_returns_original_long_body_and_source():
    original = '原文头' + '字' * 20000 + '原文尾'
    row = {'meta': trace_store._FULL_TEXT_META, 'format': 'json', 'text': json.dumps({
        'schema': trace_store._FULL_TEXT_SCHEMA, 'source': 'harbor', 'kind': 'thinking',
        'role': 'assistant', 'text': original, 'title': '旧记录', 'source_event_id': 'legacy-1',
        'snapshot_id': 'legacy-session', 'source_payload': {'native_event': {'id': 'native-old', 'content': original}},
    }, ensure_ascii=False)}
    restored = trace_store._stored_event_content(row)
    assert restored['text'] == original
    assert restored['full_text'] is True and 'truncated' not in restored
    assert restored['source_event_id'] == 'legacy-1'
    assert restored['source_payload'] == {'native_event': {'id': 'native-old', 'content': original}}


def test_short_harbor_assistant_is_not_marked_truncated():
    normalized = trace_store._normalize_canonical_record('short-answer', _harbor_record(1, 'assistant', '已完成'))
    content = trace_store._stored_event_content(normalized)
    assert content['text'] == '已完成'
    assert content['full_text'] is True
    assert not {'truncated', 'original_bytes', 'source_payload_truncated'} & content.keys()


@pytest.mark.parametrize('kind', ['tool_result', 'thinking', 'assistant', 'user'])
def test_legacy_plain_row_read_returns_original_long_body(kind):
    original = '开头' + '汉字' * 20000 + '结尾'
    content = trace_store._stored_event_content({'kind': kind, 'text': original, 'meta': '', 'format': 'text'})
    assert content == {'text': original}


def test_legacy_plain_rows_remain_unmodified_through_all_three_read_entries(monkeypatch):
    original = '头' + '普通旧正文' * 20000 + '尾'
    assistant = {'kind': 'assistant', 'text': original, 'meta': '', 'format': 'text',
                 'event_id': 'old-assistant', 'item_index': 1, 'event_order': 1}
    tool = {'kind': 'tool_result', 'text': original, 'meta': '', 'format': 'text', 'title': '旧工具'}
    def handler(sql, _params):
        if 'block_id IS NULL' in sql:
            return {'all': [assistant]}
        if 'GROUP BY item_index, block_id' in sql:
            return {'all': []}
        if 'SELECT active_block_id' in sql:
            return {'one': {}}
        if sql.startswith('SELECT kind, title'):
            return {'all': [tool]}
        if sql.startswith('SELECT text'):
            return {'one': assistant}
        raise AssertionError(sql)
    connections = []
    def connect():
        result = _Connection(handler)
        connections.append(result)
        return result
    monkeypatch.setattr(trace_store, 'get_db_connection', connect)
    timeline = trace_store.list_agent_trace_timeline('legacy-read', status='Running')
    block = trace_store.get_agent_trace_work_block('legacy-read', 'work-0123456789abcdef')
    last = trace_store.get_last_agent_trace_assistant('legacy-read')
    assert timeline[0]['text'] == block['messages'][0]['text'] == last == original
    assert 'truncated' not in timeline[0] and 'truncated' not in block['messages'][0]
    assert all(connection.commits == 0 for connection in connections)


def test_legacy_small_internal_body_is_unchanged():
    original = '  小记录\n' + 'x' * 1200 + '\n末尾  '
    content = trace_store._stored_event_content({'kind': 'tool_result', 'text': original})
    assert content == {'text': original}


@pytest.mark.parametrize('kind,limit', [('assistant', 64 * 1024), ('thinking', 1200), ('tool_call', 1200)])
def test_ordinary_agent_keeps_original_character_based_write_limits(kind, limit):
    original = '正文' * 100000
    normalized = trace_store._normalize_canonical_record('ordinary-write', _record(1, kind, original))
    assert normalized['text'] == original[:limit - 1] + '…'
    assert normalized['meta'] == '' and normalized['format'] == 'text'


def test_ordinary_batch_behavior_is_unchanged(monkeypatch):
    def handler(sql, _params):
        if sql.startswith('SELECT schema_version'):
            return {'one': {'schema_version': 2}}
        return {'rowcount': 1}
    connection = _Connection(handler)
    monkeypatch.setattr(trace_store, 'get_db_connection', lambda: connection)
    assert trace_store.ingest_agent_trace_records('ordinary-batch', [_record(1, 'tool_result', 'x' * 4096)]) == 1
    assert connection.commits == 1
