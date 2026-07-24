#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""无状态、无数据库依赖的对称 Identicon 生成原语。

这里同时保留班级 logo 的历史 dgraham/nibble 契约，以及浏览器易复刻的
FNV-1a + xorshift32 文本头像契约。调用方负责决定种子来源、持久化方式和展示格式。
"""

from __future__ import annotations


_UINT32_MASK = 0xFFFFFFFF
_FNV1A_OFFSET_BASIS = 0x811C9DC5
_FNV1A_PRIME = 0x01000193
_XORSHIFT_ZERO_FALLBACK = 0x9E3779B9


def _positive_grid_size(grid_size: int) -> int:
    try:
        value = int(grid_size)
    except (TypeError, ValueError) as exc:
        raise ValueError("grid_size 必须是正整数") from exc
    if value < 1:
        raise ValueError("grid_size 必须是正整数")
    return value


def nibble_mirror_cells(
    material: bytes,
    *,
    grid_size: int = 5,
) -> list[tuple[int, int]]:
    """按历史 dgraham 规则把二进制材料映射为左右对称坐标。

    字节依次拆成高、低半字节，以半字节奇偶性决定是否填充。列从中轴/左半边
    的内侧向外遍历，这个顺序是现有 5×5 班级 logo 输出契约的一部分。
    """
    size = _positive_grid_size(grid_size)
    try:
        raw_material = bytes(material)
    except (TypeError, ValueError) as exc:
        raise ValueError("material 必须是 bytes-like 数据") from exc

    paint_values = (
        nibble % 2 == 0
        for byte in raw_material
        for nibble in (byte >> 4, byte & 0x0F)
    )
    cells: list[tuple[int, int]] = []
    for column in range((size - 1) // 2, -1, -1):
        for row in range(size):
            if not next(paint_values, False):
                continue
            cells.append((column, row))
            mirror_column = size - 1 - column
            if mirror_column != column:
                cells.append((mirror_column, row))
    return cells


def nibble_identicon_presentation(
    material: bytes,
    *,
    grid_size: int = 5,
) -> dict:
    """返回兼容模板使用的 ``{"cells": [(column, row), ...]}``。"""
    return {"cells": nibble_mirror_cells(material, grid_size=grid_size)}


def _fnv1a_32(value: str) -> int:
    state = _FNV1A_OFFSET_BASIS
    for byte in str(value).encode("utf-8"):
        state ^= byte
        state = (state * _FNV1A_PRIME) & _UINT32_MASK
    return state


def _xorshift32(state: int) -> int:
    state &= _UINT32_MASK
    state ^= (state << 13) & _UINT32_MASK
    state ^= state >> 17
    state ^= (state << 5) & _UINT32_MASK
    return state & _UINT32_MASK


def text_mirror_cells(
    value,
    *,
    grid_size: int = 8,
) -> list[int]:
    """把 UTF-8 文本稳定映射为偶数网格的左右对称一维 cell 下标。

    哈希与伪随机步骤固定为 FNV-1a 32-bit + xorshift32，可由浏览器用
    ``TextEncoder``、``Math.imul`` 和无符号位运算逐位复刻。返回下标使用
    ``row * grid_size + column``，并按升序排列。
    """
    size = _positive_grid_size(grid_size)
    if size % 2:
        raise ValueError("文本 Identicon 的 grid_size 必须是偶数")

    state = _fnv1a_32(str(value or ""))
    if state == 0:
        state = _XORSHIFT_ZERO_FALLBACK

    cells: list[int] = []
    for row in range(size):
        for column in range(size // 2):
            state = _xorshift32(state)
            if state & 1:
                cells.extend(
                    (
                        row * size + column,
                        row * size + (size - 1 - column),
                    )
                )

    if not cells:
        top = max(0, size // 2 - 1)
        bottom = min(size - 1, size // 2)
        left = max(0, size // 2 - 1)
        right = min(size - 1, size // 2)
        cells = sorted(
            {
                top * size + left,
                top * size + right,
                bottom * size + left,
                bottom * size + right,
            }
        )
    else:
        cells.sort()
    return cells


def text_identicon_presentation(value, *, grid_size: int = 8) -> dict:
    """返回前端/API 可直接使用的 ``{"cells": [index, ...]}``。"""
    return {"cells": text_mirror_cells(value, grid_size=grid_size)}


__all__ = [
    "nibble_identicon_presentation",
    "nibble_mirror_cells",
    "text_identicon_presentation",
    "text_mirror_cells",
]
