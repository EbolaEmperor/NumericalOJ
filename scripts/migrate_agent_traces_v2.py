#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一次性把部署前 Agent trace 迁移到 v2 数据库链路。

脚本只读取受信任的任务级 trace 目录，不修改或删除原始 JSONL。写入过程按
task_id 幂等：事件表依靠稳定 event_id / event_order 去重，每个任务完成后
单独落迁移标记；所有任务成功后再写全局完成标记。部署失败重跑时会从未完成
任务继续。deploy.sh 会在服务停止、数据库备份完成并创建 v2 表之后调用本
脚本；回滚沿用该次部署备份，原始 JSONL 始终保留为审计源。
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oj_modules.agents.trace_store import (  # noqa: E402
    get_last_agent_trace_assistant,
    ingest_agent_trace_records,
    mark_agent_trace_migration_completed,
    save_agent_trace_token_usage,
)
from oj_modules.infrastructure.mysql import get_db_connection  # noqa: E402
from oj_modules.problems.agent_runs import agent_run_trace_dir  # noqa: E402
from oj_modules.ranking.reverse_judge import traces as legacy_traces  # noqa: E402


MIGRATION_KEY = "agent-trace-v2-20260822"
MIGRATION_LOCK = "numericaloj:migrate_agent_traces_v2"
_TERMINAL_STATUSES = frozenset({
    "completed", "failed", "canceled", "cancelled",
    "cleanupfailed", "cleanup_failed",
})
_BATCH_SIZE = 500


def _canonical_records(path):
    """完整读取规范 journal，并按原始行序补迁移所需的稳定 sequence/ID。"""

    records = []
    sequence = 0
    with open(path, "r", encoding="utf-8", errors="replace") as stream:
        for line_number, raw in enumerate(stream, 1):
            try:
                record = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            try:
                version = int(record.get("version") or 0)
            except (TypeError, ValueError):
                continue
            record_type = str(record.get("type") or "").strip()
            if version != 1 or record_type not in {"numoj_trace", "numoj_steer"}:
                continue
            migrated = copy.deepcopy(record)
            sequence += 1
            migrated["sequence"] = sequence
            if record_type == "numoj_trace":
                event = migrated.get("event")
                if not isinstance(event, dict):
                    continue
                if not str(event.get("id") or "").strip():
                    event["id"] = f"migration-line-{line_number}"
            records.append(migrated)
    return records


@contextmanager
def _unbounded_legacy_parser(path):
    """仅在一次性迁移中关闭页面解析器的尾读/240 条展示裁剪。"""

    previous_max_messages = legacy_traces._TRACE_MAX_MESSAGES
    previous_parse_bytes = legacy_traces._TRACE_JSONL_PARSE_MAX_BYTES
    try:
        legacy_traces._TRACE_MAX_MESSAGES = 10_000_000
        legacy_traces._TRACE_JSONL_PARSE_MAX_BYTES = max(
            previous_parse_bytes,
            int(os.path.getsize(path)) + 1,
        )
        yield
    finally:
        legacy_traces._TRACE_MAX_MESSAGES = previous_max_messages
        legacy_traces._TRACE_JSONL_PARSE_MAX_BYTES = previous_parse_bytes


def _legacy_source(trace_dir, harness):
    harness = str(harness or "").strip().lower()
    if harness == "pi":
        path = legacy_traces._latest_pi_jsonl(trace_dir)
        return (path, "pi", legacy_traces._collect_pi_trace_messages)
    if harness == "claude_code":
        path = legacy_traces._latest_claude_jsonl(trace_dir)
        return (path, "claude_code", legacy_traces._collect_claude_trace_messages)
    if harness == "opencode":
        path = legacy_traces._latest_codex_jsonl(trace_dir)
        return (path, "opencode", legacy_traces._collect_codex_trace_messages)
    if harness == "codex":
        path = legacy_traces._latest_codex_jsonl(trace_dir)
        return (path, "codex", legacy_traces._collect_codex_trace_messages)

    # 最早的任务没有持久化 harness；沿用当时的受信任发现优先级。
    path = legacy_traces._latest_claude_jsonl(trace_dir)
    if path:
        return (path, "claude_code", legacy_traces._collect_claude_trace_messages)
    path = legacy_traces._latest_pi_jsonl(trace_dir)
    if path:
        return (path, "pi", legacy_traces._collect_pi_trace_messages)
    path = legacy_traces._latest_codex_jsonl(trace_dir)
    source = (
        "opencode"
        if path and "opencode" in os.path.basename(path).lower()
        else "codex"
    )
    return (path, source, legacy_traces._collect_codex_trace_messages)


def _legacy_records(trace_dir, harness):
    path, source, parser = _legacy_source(trace_dir, harness)
    if not path:
        return [], None, "missing"
    with _unbounded_legacy_parser(path):
        messages = parser(path)
        usage = legacy_traces._collect_usage_from_jsonl(path, source)
    records = []
    for sequence, message in enumerate(messages, 1):
        if not isinstance(message, dict):
            continue
        records.append({
            "type": "numoj_trace",
            "version": 1,
            "sequence": sequence,
            "event": {
                "id": f"legacy-{sequence}",
                "kind": str(message.get("kind") or ""),
                "title": str(message.get("title") or ""),
                "text": str(message.get("text") or ""),
                "meta": str(message.get("meta") or ""),
                "format": str(message.get("format") or "text"),
                "is_error": bool(message.get("is_error")),
            },
        })
    return records, usage, source


def _canonical_usage(path):
    return legacy_traces._collect_canonical_token_usage(path)


def _migration_completed(cursor):
    cursor.execute(
        """
        SELECT 1
        FROM agent_trace_migrations
        WHERE migration_key=%s
        LIMIT 1
        """,
        (MIGRATION_KEY,),
    )
    return bool(cursor.fetchone())


def _load_tasks(cursor):
    cursor.execute(
        """
        SELECT r.task_id, LOWER(COALESCE(r.harness, '')) AS harness,
               LOWER(r.status) AS status, COALESCE(r.message, '') AS message
        FROM agent_task_runs AS r
        LEFT JOIN agent_trace_sync_state AS s ON s.task_id=r.task_id
        WHERE COALESCE(s.migration_completed, 0)=0
        ORDER BY r.id ASC
        """
    )
    return list(cursor.fetchall() or ())


def _backfill_turn_conclusion(task, conclusion):
    conclusion = str(conclusion or "").strip()
    if not conclusion:
        return False
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_session_turns
                SET conclusion=%s
                WHERE task_id=%s
                  AND (conclusion IS NULL OR conclusion='')
                """,
                (conclusion, task["task_id"]),
            )
            changed = cursor.rowcount > 0
        conn.commit()
        return changed
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _migration_conclusion(task, last_assistant):
    run_message = str((task or {}).get("message") or "").strip()
    assistant = str(last_assistant or "").strip()
    if str((task or {}).get("status") or "").strip().lower() == "completed":
        return assistant or run_message
    return run_message or assistant


def _ingest_batches(task_id, records):
    records = list(records or ())
    if not records:
        return ingest_agent_trace_records(task_id, (), final=True)
    inserted = 0
    for start in range(0, len(records), _BATCH_SIZE):
        batch = records[start:start + _BATCH_SIZE]
        inserted += ingest_agent_trace_records(
            task_id,
            batch,
            final=start + _BATCH_SIZE >= len(records),
        )
    return inserted


def _task_payload(task):
    trace_dir = agent_run_trace_dir(task["task_id"])
    canonical_path = trace_dir / "numoj_trace_v1.jsonl"
    if canonical_path.is_file():
        return (
            _canonical_records(canonical_path),
            _canonical_usage(canonical_path),
            "canonical",
        )
    if trace_dir.is_dir():
        return _legacy_records(str(trace_dir), task.get("harness"))
    return [], None, "missing"


def migrate(*, apply):
    lock_conn = get_db_connection()
    summary = {
        "tasks": 0,
        "canonical_tasks": 0,
        "legacy_tasks": 0,
        "missing_trace_tasks": 0,
        "events": 0,
        "usage_tasks": 0,
        "conclusions_backfilled": 0,
    }
    try:
        with lock_conn.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0) AS acquired", (MIGRATION_LOCK,))
            row = cursor.fetchone() or {}
            if int(row.get("acquired") or 0) != 1:
                raise RuntimeError("另一个 Agent trace v2 迁移正在运行")
            if _migration_completed(cursor):
                print("Agent trace v2 一次性迁移已完成，跳过。")
                return summary
            tasks = _load_tasks(cursor)

        active = [
            task for task in tasks
            if str(task.get("status") or "").lower() not in _TERMINAL_STATUSES
        ]
        if active:
            raise RuntimeError(
                f"仍有 {len(active)} 个非终态旧任务，拒绝迁移以免破坏事件顺序"
            )

        for task in tasks:
            records, usage, source = _task_payload(task)
            summary["tasks"] += 1
            if source == "canonical":
                summary["canonical_tasks"] += 1
            elif source == "missing":
                summary["missing_trace_tasks"] += 1
            else:
                summary["legacy_tasks"] += 1
            summary["events"] += len(records)
            if usage is not None:
                summary["usage_tasks"] += 1
            if not apply:
                continue

            _ingest_batches(task["task_id"], records)
            if usage is not None:
                save_agent_trace_token_usage(task["task_id"], usage)
            last_assistant = get_last_agent_trace_assistant(task["task_id"])
            conclusion = _migration_conclusion(task, last_assistant)
            if _backfill_turn_conclusion(task, conclusion):
                summary["conclusions_backfilled"] += 1
            mark_agent_trace_migration_completed(task["task_id"])

        if apply:
            payload = json.dumps(
                summary,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            with lock_conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO agent_trace_migrations (
                        migration_key, summary_json
                    ) VALUES (%s, %s)
                    """,
                    (MIGRATION_KEY, payload),
                )
            lock_conn.commit()
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return summary
    except Exception:
        lock_conn.rollback()
        raise
    finally:
        try:
            with lock_conn.cursor() as cursor:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (MIGRATION_LOCK,))
        except Exception:
            pass
        lock_conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="一次性迁移部署前 Agent trace 到 v2 数据库存储",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="执行数据库写入；不传时只解析并输出统计",
    )
    args = parser.parse_args(argv)
    migrate(apply=args.apply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
