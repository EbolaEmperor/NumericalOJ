#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""部署期幂等补齐历史班级的持久化 logo 种子。"""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oj_modules.class_logo_services import backfill_missing_class_logo_seeds  # noqa: E402


def main() -> int:
    try:
        updated = backfill_missing_class_logo_seeds()
    except Exception as exc:
        print(f"[backfill_class_logos] failed: {exc}", file=sys.stderr)
        return 1
    print(f"[backfill_class_logos] completed, {updated} class logos generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
