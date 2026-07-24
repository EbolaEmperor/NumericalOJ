# -*- coding: utf-8 -*-

import pytest

from oj_modules import class_logo_services, identicon_utils


def test_legacy_5x5_helper_preserves_exact_class_logo_cell_order():
    material = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = [
        (2, 0),
        (2, 1),
        (2, 4),
        (1, 0),
        (3, 0),
        (1, 3),
        (3, 3),
        (1, 4),
        (3, 4),
        (0, 2),
        (4, 2),
        (0, 3),
        (4, 3),
    ]

    assert identicon_utils.nibble_mirror_cells(material) == expected
    assert identicon_utils.nibble_identicon_presentation(material) == {
        "cells": expected
    }
    assert class_logo_services.class_logo_presentation(
        material.hex()
    ) == {"cells": expected}


def test_class_logo_service_delegates_seed_material_to_pure_generator(monkeypatch):
    calls = []

    def fake_presentation(material, *, grid_size):
        calls.append((material, grid_size))
        return {"cells": [(0, 0)]}

    monkeypatch.setattr(
        class_logo_services,
        "nibble_identicon_presentation",
        fake_presentation,
    )

    result = class_logo_services.class_logo_presentation(
        "0123456789abcdef0123456789abcdef"
    )

    assert result == {"cells": [(0, 0)]}
    assert calls == [
        (
            bytes.fromhex("0123456789abcdef0123456789abcdef"),
            class_logo_services.IDENTICON_GRID_SIZE,
        )
    ]


def test_8x8_text_identicon_is_deterministic_symmetric_and_browser_compatible():
    expected = [
        0, 7, 9, 11, 12, 14, 24, 25, 30, 31, 34, 35, 36, 37,
        43, 44, 49, 50, 51, 52, 53, 54, 56, 59, 60, 63,
    ]

    first = identicon_utils.text_mirror_cells("Alice")
    second = identicon_utils.text_mirror_cells("Alice")

    assert first == second == expected
    assert identicon_utils.text_identicon_presentation("Alice") == {
        "cells": expected
    }
    assert first == sorted(set(first))
    for cell in first:
        row, column = divmod(cell, 8)
        assert row * 8 + (7 - column) in first


def test_8x8_text_identicon_hashes_utf8_not_python_codepoints():
    assert identicon_utils.text_mirror_cells("匿名甲") == [
        1, 3, 4, 6, 8, 9, 10, 13, 14, 15, 16, 18, 19, 20, 21, 23,
        24, 31, 32, 33, 34, 37, 38, 39, 40, 41, 46, 47, 48, 49,
        54, 55, 56, 57, 58, 61, 62, 63,
    ]


@pytest.mark.parametrize("grid_size", [0, -1, "bad"])
def test_identicon_helpers_reject_invalid_grid_sizes(grid_size):
    with pytest.raises(ValueError, match="grid_size"):
        identicon_utils.nibble_mirror_cells(b"\x00", grid_size=grid_size)
    with pytest.raises(ValueError, match="grid_size"):
        identicon_utils.text_mirror_cells("Alice", grid_size=grid_size)


def test_text_identicon_requires_an_even_grid():
    with pytest.raises(ValueError, match="必须是偶数"):
        identicon_utils.text_mirror_cells("Alice", grid_size=5)
