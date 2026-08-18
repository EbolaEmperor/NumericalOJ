#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一次性迁移 problems.output_image_filename。

部署流程会在停止 Web/Celery、创建并验证数据库回滚点之后调用本脚本。它把旧列
``programming_output_filename`` 重命名为 ``output_image_filename``，并清除历史
``output.txt`` 配置；后者不是可捕获的图片产物。脚本幂等，只能在本次字段迁移期间保留。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mysql_admin import (  # noqa: E402
    connect_mysql,
    load_config,
    settings_from_config,
)


TABLE_NAME = "problems"
OLD_COLUMN = "programming_output_filename"
NEW_COLUMN = "output_image_filename"
MIGRATION_LOCK_NAME = "numericaloj:migrate_output_image_filename:v1"
LOCK_TIMEOUT_SECONDS = 120


def _columns(cursor, database: str) -> set[str]:
    cursor.execute(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s "
        "AND COLUMN_NAME IN (%s, %s)",
        (database, TABLE_NAME, OLD_COLUMN, NEW_COLUMN),
    )
    return {
        str(row.get("COLUMN_NAME") or "")
        for row in cursor.fetchall() or []
    }


def migrate() -> str:
    config = load_config()
    settings = settings_from_config(config)
    conn = connect_mysql(settings, with_database=True, dict_rows=True)
    locked = False
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT GET_LOCK(%s, %s) AS locked",
                (MIGRATION_LOCK_NAME, LOCK_TIMEOUT_SECONDS),
            )
            locked = int((cursor.fetchone() or {}).get("locked") or 0) == 1
            if not locked:
                raise RuntimeError("无法获取输出图片文件名迁移锁")

            columns = _columns(cursor, settings.database)
            if not columns:
                return "problems 表尚未创建，跳过一次性字段迁移"
            if OLD_COLUMN in columns and NEW_COLUMN in columns:
                # 唯一可能来源是之前被中断的 schema 同步：新列全为默认值，旧列
                # 仍是唯一的业务真值。先复制再删除旧列，避免丢失自定义图片名。
                cursor.execute(
                    "UPDATE `problems` SET `output_image_filename`="
                    "`programming_output_filename`"
                )
                cursor.execute(
                    "ALTER TABLE `problems` DROP COLUMN `programming_output_filename`"
                )
                status = "已合并中断迁移留下的双列状态"
            elif OLD_COLUMN in columns:
                cursor.execute(
                    "ALTER TABLE `problems` CHANGE COLUMN "
                    "`programming_output_filename` `output_image_filename` "
                    "VARCHAR(255) NOT NULL DEFAULT 'output.png'"
                )
                status = "已重命名输出图片文件名列"
            elif NEW_COLUMN in columns:
                status = "输出图片文件名列已迁移"
            else:
                raise RuntimeError("problems 表缺少输出图片文件名列，拒绝继续")

            cursor.execute(
                "UPDATE `problems` SET `output_image_filename`='' "
                "WHERE LOWER(TRIM(`output_image_filename`))='output.txt'"
            )
            cleared = int(cursor.rowcount or 0)
            columns = _columns(cursor, settings.database)
            if OLD_COLUMN in columns or NEW_COLUMN not in columns:
                raise RuntimeError("输出图片文件名列迁移后的结构校验失败")
        conn.commit()
        return f"{status}；已清空 {cleared} 条 output.txt 旧配置"
    except Exception:
        conn.rollback()
        raise
    finally:
        if locked:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK(%s)", (MIGRATION_LOCK_NAME,))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        conn.close()


def main() -> int:
    try:
        print(f"[migrate_output_image_filename] {migrate()}")
    except Exception as exc:
        print(f"[migrate_output_image_filename] failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
