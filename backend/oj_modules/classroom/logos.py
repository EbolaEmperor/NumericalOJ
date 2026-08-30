#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""班级随机 Identicon 的生成、展示映射与历史数据回填。

数据库只保存不可执行的随机种子。展示层使用 dgraham/identicon 的 MIT
开源 5x5 对称网格算法生成黑白图案，既不持久化 SVG/HTML，也不依赖固定
图标库。第三方许可见项目根目录 THIRD_PARTY_NOTICES.md。
"""

from __future__ import annotations

import hashlib
import re
import secrets

from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.shared.identicon import nibble_identicon_presentation


LOGO_SEED_PATTERN = re.compile(r"^[0-9a-f]{32}$")
IDENTICON_GRID_SIZE = 5


def generate_class_logo_seed() -> str:
    """生成可持久化的 128-bit 随机 logo 种子。"""
    return secrets.token_hex(16)


def is_valid_class_logo_seed(value) -> bool:
    return bool(LOGO_SEED_PATTERN.fullmatch(str(value or "")))


def class_logo_presentation(seed, *, fallback="") -> dict:
    """把持久化种子映射为模板可直接使用的黑白对称网格。

    尚未完成回填或数据异常时，用班级标识的哈希作为只读降级，不在页面
    渲染期间写数据库。
    """
    raw_seed = str(seed or "")
    if is_valid_class_logo_seed(raw_seed):
        material = bytes.fromhex(raw_seed)
    else:
        material = hashlib.blake2s(
            str(fallback or "numericaloj-class").encode("utf-8"),
            digest_size=16,
        ).digest()

    return nibble_identicon_presentation(
        material,
        grid_size=IDENTICON_GRID_SIZE,
    )


def attach_class_logos(classes) -> list[dict]:
    """复制班级行并附加展示属性，不把内部种子暴露给模板/API。"""
    decorated = []
    for item in classes or []:
        row = dict(item)
        seed = row.pop("logo_seed", None)
        row["logo"] = class_logo_presentation(
            seed,
            fallback=row.get("class_en"),
        )
        decorated.append(row)
    return decorated


def backfill_missing_class_logo_seeds() -> int:
    """为缺失 logo 的历史班级补齐随机种子，重复执行不会改写已有值。"""
    conn = get_db_connection()
    updated = 0
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT class_en
                FROM class_table
                WHERE logo_seed IS NULL OR logo_seed = ''
                ORDER BY class_en ASC
                FOR UPDATE
                """
            )
            for row in cursor.fetchall() or []:
                cursor.execute(
                    """
                    UPDATE class_table
                    SET logo_seed=%s
                    WHERE class_en=%s
                      AND (logo_seed IS NULL OR logo_seed = '')
                    """,
                    (
                        generate_class_logo_seed(),
                        row["class_en"],
                    ),
                )
                updated += int(cursor.rowcount or 0)
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
