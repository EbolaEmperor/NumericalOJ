"""一次性 Agent trace v2 迁移脚本契约。"""

from __future__ import annotations

import json
from pathlib import Path

from scripts import migrate_agent_traces_v2 as migration


ROOT = Path(__file__).resolve().parents[2]


def test_canonical_migration_reads_full_file_and_adds_stable_order_and_ids(
    tmp_path,
):
    path = tmp_path / "numoj_trace_v1.jsonl"
    rows = [
        {
            "type": "numoj_trace",
            "version": 1,
            "event": {"kind": "thinking", "text": "分析"},
        },
        {"type": "numoj_usage", "version": 1, "usage": {}},
        {
            "type": "numoj_steer",
            "version": 1,
            "message_id": "steer-1",
        },
        {
            "type": "numoj_trace",
            "version": 1,
            "event": {
                "id": "existing-id",
                "kind": "assistant",
                "text": "回复",
            },
        },
    ]
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
        + "not-json\n",
        encoding="utf-8",
    )

    records = migration._canonical_records(path)

    assert [record["sequence"] for record in records] == [1, 2, 3]
    assert records[0]["event"]["id"] == "migration-line-1"
    assert records[1]["message_id"] == "steer-1"
    assert records[2]["event"]["id"] == "existing-id"


def test_legacy_migration_temporarily_disables_display_tail_limits(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "legacy.jsonl"
    path.write_text("{}\n", encoding="utf-8")
    observed = []

    def parser(_path):
        observed.append((
            migration.legacy_traces._TRACE_MAX_MESSAGES,
            migration.legacy_traces._TRACE_JSONL_PARSE_MAX_BYTES,
        ))
        return [
            {"kind": "thinking", "title": "思考", "text": f"step-{index}"}
            for index in range(260)
        ]

    previous_limits = (
        migration.legacy_traces._TRACE_MAX_MESSAGES,
        migration.legacy_traces._TRACE_JSONL_PARSE_MAX_BYTES,
    )
    monkeypatch.setattr(
        migration,
        "_legacy_source",
        lambda _trace_dir, _harness: (str(path), "pi", parser),
    )
    monkeypatch.setattr(
        migration.legacy_traces,
        "_collect_usage_from_jsonl",
        lambda _path, _source: None,
    )

    records, usage, source = migration._legacy_records(tmp_path, "pi")

    assert len(records) == 260
    assert records[0]["event"]["id"] == "legacy-1"
    assert records[-1]["event"]["id"] == "legacy-260"
    assert usage is None
    assert source == "pi"
    assert observed[0][0] == 10_000_000
    assert observed[0][1] >= path.stat().st_size + 1
    assert (
        migration.legacy_traces._TRACE_MAX_MESSAGES,
        migration.legacy_traces._TRACE_JSONL_PARSE_MAX_BYTES,
    ) == previous_limits


def test_migration_batches_are_idempotent_and_only_last_batch_is_final(
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(
        migration,
        "ingest_agent_trace_records",
        lambda task_id, records, *, final: calls.append(
            (task_id, len(records), final)
        ) or len(records),
    )

    inserted = migration._ingest_batches("task-1", [{}] * 1201)

    assert inserted == 1201
    assert calls == [
        ("task-1", 500, False),
        ("task-1", 500, False),
        ("task-1", 201, True),
    ]


def test_migration_conclusion_prefers_final_reply_but_keeps_failure_reason():
    assert migration._migration_conclusion(
        {"status": "completed", "message": "任务完成"},
        "Agent 的最终回复",
    ) == "Agent 的最终回复"
    assert migration._migration_conclusion(
        {"status": "completed", "message": "无 trace 时的完成说明"},
        "",
    ) == "无 trace 时的完成说明"
    assert migration._migration_conclusion(
        {"status": "failed", "message": "发布失败"},
        "候选文件已生成",
    ) == "发布失败"


def test_deploy_runs_trace_migration_after_schema_and_before_services():
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
    schema = deploy.index('"$CANDIDATE_PYTHON" scripts/init_db_schema.py')
    migrate = deploy.index(
        '"$CANDIDATE_PYTHON" -B scripts/migrate_agent_traces_v2.py --apply'
    )
    start_celery = deploy.index("phase='启动 Celery 服务'")

    assert schema < migrate < start_celery
    assert "phase='迁移 Agent v2 轨迹'" in deploy
