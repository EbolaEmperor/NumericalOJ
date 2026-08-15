#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bring the configured MySQL database up to the current NumericalOJ schema.

This script is intentionally non-destructive:
- it creates missing databases/tables;
- it adds missing columns;
- it modifies columns only when the stored data type differs from the current
  schema definition;
- it adds missing indexes;
- it never drops tables, drops columns, truncates rows, imports seed data, or
  updates existing row content.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mysql_admin import (  # noqa: E402
    IDENTIFIER_RE,
    connect_mysql,
    database_exists,
    database_name_from_config,
    load_config,
    settings_from_config,
)

DATABASE_BOOTSTRAP_SQL = ROOT / "database" / "bootstrap.sql"
SKIP_DUMP_TABLES = {"Cdemo2024", "Ctest"}
SCHEMA_LOCK_NAME = "numericaloj:init_db_schema"
SCHEMA_LOCK_TIMEOUT_SECONDS = 120
REQUIRED_AGENT_QUOTA_TABLES = (
    "agent_quota_accounts",
    "agent_quota_requests",
    "agent_quota_grants",
    "agent_usage_ledger",
)
REQUIRED_AGENT_PUBLIC_TABLES = (
    "agent_user_endpoints",
)

CLASS_HOMEWORK_CREATE_SQL = """
CREATE TABLE `{table}` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `problem_id` INT DEFAULT NULL,
  `ddl` DATETIME DEFAULT NULL,
  `complete_cnt` INT DEFAULT 0,
  `problem_title` TEXT,
  `ranking_competition_id` INT DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
"""


@dataclass
class TableSpec:
    name: str
    create_sql: str
    columns: OrderedDict[str, str] = field(default_factory=OrderedDict)
    indexes: OrderedDict[str, str] = field(default_factory=OrderedDict)


def _load_config():
    return load_config()


def _connect(config, with_db=True):
    return connect_mysql(
        settings_from_config(config),
        with_database=with_db,
        dict_rows=True,
    )


def _normalize_create_sql(sql: str) -> str:
    sql = sql.strip().rstrip(";")
    sql = re.sub(r"\bAUTO_INCREMENT=\d+\s*", "", sql, flags=re.IGNORECASE)
    return sql


def _iter_create_table_sql(sql_text: str):
    pattern = re.compile(
        r"CREATE\s+TABLE\s+`(?P<name>[^`]+)`\s*\((?P<body>.*?)\)\s*ENGINE\s*=\s*[^;]+;",
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(sql_text):
        name = match.group("name")
        if name in SKIP_DUMP_TABLES:
            continue
        yield name, _normalize_create_sql(match.group(0))


def _split_top_level(body: str) -> list[str]:
    items = []
    start = 0
    depth = 0
    quote = None
    i = 0
    while i < len(body):
        ch = body[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        else:
            if ch in ("'", '"', "`"):
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif ch == "," and depth == 0:
                item = body[start:i].strip()
                if item:
                    items.append(" ".join(item.split()))
                start = i + 1
        i += 1
    tail = body[start:].strip()
    if tail:
        items.append(" ".join(tail.split()))
    return items


def _create_body(create_sql: str) -> str:
    start = create_sql.find("(")
    end = create_sql.rfind(")")
    if start < 0 or end < start:
        raise ValueError(f"cannot parse CREATE TABLE body: {create_sql[:80]}")
    return create_sql[start + 1:end]


def _index_name(definition: str) -> str | None:
    text = definition.strip()
    upper = text.upper()
    if upper.startswith("PRIMARY KEY"):
        return "PRIMARY"
    match = re.match(r"(?:UNIQUE\s+)?(?:KEY|INDEX)\s+`?([A-Za-z0-9_]+)`?", text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _parse_table_spec(name: str, create_sql: str) -> TableSpec:
    spec = TableSpec(name=name, create_sql=_normalize_create_sql(create_sql))
    for item in _split_top_level(_create_body(create_sql)):
        if item.startswith("`"):
            match = re.match(r"`([^`]+)`\s+(.+)", item, re.DOTALL)
            if match:
                column_name = match.group(1)
                definition = match.group(2).strip()
                has_inline_primary = re.search(r"\bPRIMARY\s+KEY\b", definition, re.IGNORECASE)
                if has_inline_primary:
                    definition = re.sub(r"\s+\bPRIMARY\s+KEY\b", "", definition, flags=re.IGNORECASE).strip()
                spec.columns[column_name] = definition
                if has_inline_primary:
                    spec.indexes.setdefault("PRIMARY", f"PRIMARY KEY (`{column_name}`)")
            continue
        index_name = _index_name(item)
        if index_name:
            spec.indexes[index_name] = item
    return spec


def _parse_dump_alter_indexes(sql_text: str, specs: OrderedDict[str, TableSpec]) -> None:
    pattern = re.compile(
        r"ALTER\s+TABLE\s+`?(?P<table>[A-Za-z0-9_]+)`?\s+ADD\s+"
        r"(?P<index>(?:UNIQUE\s+)?(?:INDEX|KEY)\s+[^;]+);",
        re.IGNORECASE,
    )
    for match in pattern.finditer(sql_text):
        table = match.group("table")
        spec = specs.get(table)
        if not spec:
            continue
        definition = " ".join(match.group("index").split())
        name = _index_name(definition)
        if name:
            spec.indexes.setdefault(name, definition)


def _load_schema_specs() -> OrderedDict[str, TableSpec]:
    sql_text = DATABASE_BOOTSTRAP_SQL.read_text(encoding="utf-8")
    specs: OrderedDict[str, TableSpec] = OrderedDict()
    for name, create_sql in _iter_create_table_sql(sql_text):
        specs[name] = _parse_table_spec(name, create_sql)
    _parse_dump_alter_indexes(sql_text, specs)
    missing_agent_tables = [
        table
        for table in (*REQUIRED_AGENT_QUOTA_TABLES, *REQUIRED_AGENT_PUBLIC_TABLES)
        if table not in specs
    ]
    if missing_agent_tables:
        raise RuntimeError(
            "Agent public schema is incomplete: "
            + ", ".join(missing_agent_tables)
        )
    return specs


def _table_exists(cursor, table: str) -> bool:
    cursor.execute("SHOW TABLES LIKE %s", (table,))
    return cursor.fetchone() is not None


def _quote_identifier(name: str) -> str:
    if not IDENTIFIER_RE.fullmatch(name):
        raise ValueError(f"invalid identifier: {name!r}")
    return f"`{name}`"


def _column_type(definition: str) -> str:
    tokens = definition.strip().split()
    if not tokens:
        return ""
    first = tokens[0]
    pieces = [first]
    if len(tokens) > 1 and tokens[1].lower() == "unsigned":
        pieces.append(tokens[1])
    return " ".join(pieces)


def _normalize_type(value: str) -> str:
    text = " ".join(str(value or "").strip().lower().split())
    text = re.sub(r"\b(bigint|int|integer|mediumint|smallint|tinyint)\(\d+\)", r"\1", text)
    text = text.replace("integer", "int")
    return text


def _column_needs_type_change(existing_type: str, desired_definition: str) -> bool:
    return _normalize_type(existing_type) != _normalize_type(_column_type(desired_definition))


def _existing_columns(cursor, table: str) -> dict[str, dict]:
    cursor.execute(f"SHOW COLUMNS FROM {_quote_identifier(table)}")
    return {row["Field"]: row for row in cursor.fetchall()}


def _existing_indexes(cursor, table: str) -> set[str]:
    cursor.execute(f"SHOW INDEX FROM {_quote_identifier(table)}")
    return {row["Key_name"] for row in cursor.fetchall()}


def _run(cursor, sql: str, dry_run: bool, actions: list[str]) -> None:
    actions.append(sql)
    if dry_run:
        return
    cursor.execute(sql)


def _acquire_schema_lock(cursor) -> None:
    cursor.execute("SELECT GET_LOCK(%s, %s) AS locked", (SCHEMA_LOCK_NAME, SCHEMA_LOCK_TIMEOUT_SECONDS))
    row = cursor.fetchone() or {}
    if int(row.get("locked") or 0) != 1:
        raise RuntimeError(f"failed to acquire schema init lock {SCHEMA_LOCK_NAME!r}")


def _release_schema_lock(cursor) -> None:
    cursor.execute("SELECT RELEASE_LOCK(%s)", (SCHEMA_LOCK_NAME,))


def _create_table(cursor, spec: TableSpec, dry_run: bool, actions: list[str]) -> None:
    _run(cursor, spec.create_sql, dry_run, actions)


def _sync_table(cursor, spec: TableSpec, dry_run: bool, actions: list[str]) -> None:
    table = spec.name
    if not _table_exists(cursor, table):
        _create_table(cursor, spec, dry_run, actions)
        return

    existing = _existing_columns(cursor, table)
    previous_col = None
    for column, definition in spec.columns.items():
        quoted_table = _quote_identifier(table)
        quoted_column = _quote_identifier(column)
        if column not in existing:
            position = f" AFTER {_quote_identifier(previous_col)}" if previous_col else " FIRST"
            _run(cursor, f"ALTER TABLE {quoted_table} ADD COLUMN {quoted_column} {definition}{position}", dry_run, actions)
        elif _column_needs_type_change(existing[column].get("Type"), definition):
            _run(cursor, f"ALTER TABLE {quoted_table} MODIFY COLUMN {quoted_column} {definition}", dry_run, actions)
        previous_col = column

    existing_index_names = _existing_indexes(cursor, table)
    for index_name, definition in spec.indexes.items():
        if index_name not in existing_index_names:
            _run(cursor, f"ALTER TABLE {_quote_identifier(table)} ADD {definition}", dry_run, actions)


def _class_table_spec(table: str) -> TableSpec:
    create_sql = CLASS_HOMEWORK_CREATE_SQL.format(table=table)
    return _parse_table_spec(table, create_sql)


def _sync_dynamic_class_tables(cursor, dry_run: bool, actions: list[str]) -> None:
    if not _table_exists(cursor, "class_table"):
        return
    cursor.execute("SELECT class_en FROM class_table")
    for row in cursor.fetchall() or []:
        class_en = str(row.get("class_en") or "").strip()
        if not class_en or not IDENTIFIER_RE.fullmatch(class_en):
            continue
        _sync_table(cursor, _class_table_spec(class_en), dry_run, actions)


def _ensure_database(config, dry_run: bool, actions: list[str]) -> bool:
    db_name = database_name_from_config(config)
    conn = _connect(config, with_db=False)
    try:
        with conn.cursor() as cursor:
            exists = database_exists(cursor, db_name)
            sql = (
                f"CREATE DATABASE IF NOT EXISTS {_quote_identifier(db_name)} "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
            )
            _run(cursor, sql, dry_run, actions)
        if dry_run:
            conn.rollback()
        else:
            conn.commit()
    finally:
        conn.close()
    return exists


def _plan_empty_database(config, specs, actions: list[str]) -> None:
    """为空服务器生成完整计划，避免 dry-run 连接尚不存在的数据库。"""
    db_name = database_name_from_config(config)
    actions.append(f"USE {_quote_identifier(db_name)}")
    actions.append("SET FOREIGN_KEY_CHECKS=0")
    actions.extend(spec.create_sql for spec in specs.values())
    actions.append("SET FOREIGN_KEY_CHECKS=1")


def init_schema(dry_run: bool = False) -> list[str]:
    config = _load_config()
    specs = _load_schema_specs()
    actions: list[str] = []

    database_exists = _ensure_database(config, dry_run, actions)
    if dry_run and not database_exists:
        _plan_empty_database(config, specs, actions)
        return actions
    conn = _connect(config, with_db=True)

    try:
        with conn.cursor() as cursor:
            if not dry_run:
                _acquire_schema_lock(cursor)
            try:
                _run(cursor, "SET FOREIGN_KEY_CHECKS=0", dry_run, actions)
                for spec in specs.values():
                    _sync_table(cursor, spec, dry_run, actions)
                _sync_dynamic_class_tables(cursor, dry_run, actions)
                _run(cursor, "SET FOREIGN_KEY_CHECKS=1", dry_run, actions)
            finally:
                if not dry_run:
                    _release_schema_lock(cursor)
        if dry_run:
            conn.rollback()
        else:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return actions


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize or migrate NumericalOJ database schema.")
    parser.add_argument("--dry-run", action="store_true", help="Print planned DDL without applying it.")
    args = parser.parse_args()

    try:
        actions = init_schema(dry_run=args.dry_run)
    except Exception as exc:
        print(f"[init_db_schema] failed: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        for sql in actions:
            print(sql.rstrip(";") + ";")
    else:
        print(f"[init_db_schema] schema ready, {len(actions)} DDL/check statements executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
