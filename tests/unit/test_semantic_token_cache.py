from __future__ import annotations

from oj_modules.semantic_token_cache import SemanticTokenResultCache


def test_cache_collapses_inflight_work_and_copies_successful_results():
    cache = SemanticTokenResultCache()
    assert cache.claim("same-source").state == "owner"
    assert cache.claim("same-source").state == "pending"

    original = {"data": [0, 0, 3, 1, 0], "result_id": "1:cached"}
    cache.store("same-source", original)
    original["data"][0] = 99

    first = cache.claim("same-source")
    assert first.state == "hit"
    assert first.result == {"data": [0, 0, 3, 1, 0], "result_id": "1:cached"}
    first.result["data"][0] = 88
    assert cache.claim("same-source").result["data"][0] == 0


def test_cache_cancel_and_expiry_allow_new_owners():
    now = [100.0]
    cache = SemanticTokenResultCache(ttl_seconds=10, clock=lambda: now[0])

    assert cache.claim("retry").state == "owner"
    cache.cancel("retry")
    assert cache.claim("retry").state == "owner"
    cache.store("retry", {"data": [], "result_id": "1:retry"})
    assert cache.claim("retry").state == "hit"

    now[0] = 111.0
    assert cache.claim("retry").state == "owner"


def test_cache_enforces_lru_entry_and_memory_budgets():
    cache = SemanticTokenResultCache(max_entries=2, max_weight_bytes=10_000)
    cache.claim("a")
    cache.store("a", {"data": [], "result_id": "a"})
    cache.claim("b")
    cache.store("b", {"data": [], "result_id": "b"})
    assert cache.claim("a").state == "hit"
    cache.claim("c")
    cache.store("c", {"data": [], "result_id": "c"})

    assert cache.claim("b").state == "owner"
    cache.cancel("b")
    assert cache.claim("a").state == "hit"
    assert cache.claim("c").state == "hit"

    tiny = SemanticTokenResultCache(max_weight_bytes=300)
    assert tiny.claim("oversized").state == "owner"
    tiny.store("oversized", {"data": [0, 0, 1, 0, 0], "result_id": "large"})
    assert tiny.claim("oversized").state == "owner"
