"""Bounded process-local cache and singleflight guard for semantic tokens."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import threading
import time
from typing import Any, Callable, Literal


_ClaimState = Literal["hit", "owner", "pending"]


@dataclass(frozen=True)
class SemanticTokenCacheClaim:
    state: _ClaimState
    result: dict[str, Any] | None = None


@dataclass(frozen=True)
class _CacheEntry:
    expires_at: float
    weight_bytes: int
    result: dict[str, Any]


def _clone_result(result: dict[str, Any]) -> dict[str, Any]:
    cloned = dict(result)
    data = result.get("data")
    if isinstance(data, list):
        cloned["data"] = list(data)
    return cloned


def _result_weight_bytes(result: dict[str, Any]) -> int:
    """Approximate retained Python memory, not the compact JSON wire size."""
    data = result.get("data")
    token_data_weight = len(data) * 32 if isinstance(data, list) else 0
    result_id_weight = len(str(result.get("result_id") or "").encode("utf-8"))
    return 256 + token_data_weight + result_id_weight


class SemanticTokenResultCache:
    """LRU cache whose claim step also collapses identical concurrent work."""

    def __init__(
        self,
        *,
        max_entries: int = 256,
        max_weight_bytes: int = 64 * 1024 * 1024,
        ttl_seconds: float = 10 * 60,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_entries < 1:
            raise ValueError("语义令牌缓存条目数必须大于零")
        if max_weight_bytes < 1:
            raise ValueError("语义令牌缓存容量必须大于零")
        if ttl_seconds <= 0:
            raise ValueError("语义令牌缓存 TTL 必须大于零")
        self._max_entries = max_entries
        self._max_weight_bytes = max_weight_bytes
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._inflight: set[str] = set()
        self._weight_bytes = 0
        self._lock = threading.Lock()

    def _remove_locked(self, key: str) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            self._weight_bytes -= entry.weight_bytes

    def _purge_expired_locked(self, now: float) -> None:
        for key, entry in tuple(self._entries.items()):
            if entry.expires_at <= now:
                self._remove_locked(key)

    def claim(self, key: str) -> SemanticTokenCacheClaim:
        """Return a cached result, reserve ownership, or report in-flight work."""
        now = self._clock()
        with self._lock:
            self._purge_expired_locked(now)
            entry = self._entries.get(key)
            if entry is not None:
                self._entries.move_to_end(key)
                return SemanticTokenCacheClaim("hit", _clone_result(entry.result))
            if key in self._inflight:
                return SemanticTokenCacheClaim("pending")
            self._inflight.add(key)
            return SemanticTokenCacheClaim("owner")

    def store(self, key: str, result: dict[str, Any]) -> None:
        """Publish one successful owner result and release its singleflight key."""
        cloned = _clone_result(result)
        weight_bytes = _result_weight_bytes(cloned)
        with self._lock:
            self._inflight.discard(key)
            self._remove_locked(key)
            if weight_bytes > self._max_weight_bytes:
                return
            self._entries[key] = _CacheEntry(
                expires_at=self._clock() + self._ttl_seconds,
                weight_bytes=weight_bytes,
                result=cloned,
            )
            self._weight_bytes += weight_bytes
            while (
                len(self._entries) > self._max_entries
                or self._weight_bytes > self._max_weight_bytes
            ):
                oldest_key = next(iter(self._entries))
                self._remove_locked(oldest_key)

    def cancel(self, key: str) -> None:
        """Release a failed owner claim without caching its result."""
        with self._lock:
            self._inflight.discard(key)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._inflight.clear()
            self._weight_bytes = 0
