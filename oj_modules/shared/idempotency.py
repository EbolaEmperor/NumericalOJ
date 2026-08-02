#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""跨领域写操作共用的幂等键与请求指纹原语。"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any


class InvalidClientRequestId(ValueError):
    pass


def normalize_client_request_id(value: Any) -> str:
    raw = str(value or "").strip()
    try:
        parsed = uuid.UUID(raw)
    except (AttributeError, TypeError, ValueError) as exc:
        raise InvalidClientRequestId("client_request_id 必须是有效的 UUID") from exc
    canonical = str(parsed)
    if raw.lower() != canonical:
        raise InvalidClientRequestId("client_request_id 必须使用标准 UUID 格式")
    return canonical


def request_fingerprint(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "InvalidClientRequestId",
    "normalize_client_request_id",
    "request_fingerprint",
]
