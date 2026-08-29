"""Agent v2 轨迹存储的分块、公开投影与用量快照契约。"""

from __future__ import annotations

import json

from oj_modules.agents import trace_store


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
        "source": "codex",
        "request_count": 2,
        "input_uncached_tokens": 120,
        "input_cached_tokens": 30,
        "output_tokens": 15,
        "incremental": True,
    }

    assert trace_store.save_agent_trace_token_usage("task-4", usage) is True
    assert json.loads(stored_payload["value"])["incremental"] is True
    restored = trace_store.get_agent_trace_token_usage("task-4")
    assert restored["source"] == "codex"
    assert restored["request_count"] == 2
    assert restored["input_total_tokens"] == 150
    assert restored["incremental"] is True
