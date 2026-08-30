"""ELO 对战列表与详情的共享读取缓存。"""

import json

from backend.oj_modules.infrastructure.redis import create_optional_redis_client
from backend.oj_modules.ranking.db import get_competition_match, list_competition_matches


ELO_MATCHES_LIST_CACHE_KEY = "ranking:elo:matches_list:{comp}:{scope}:{page}:{per_page}"
ELO_MATCHES_LIST_CACHE_TTL = 30
ELO_MATCH_DETAIL_CACHE_KEY = "ranking:elo:match_detail:{match_id}"
ELO_MATCH_DETAIL_CACHE_TTL = 3600

_redis = None


def init_match_cache(redis_client):
    global _redis
    _redis = redis_client


def _redis_client():
    return _redis or create_optional_redis_client(verify_connection=False)


def _serialize_for_cache(value):
    return json.dumps(value, default=str, ensure_ascii=False)


def fetch_competition_matches_cached(competition_id, page, per_page, username=None):
    redis_client = _redis_client()
    scope = "user:" + str(username) if username else ""
    cache_key = ELO_MATCHES_LIST_CACHE_KEY.format(
        comp=int(competition_id),
        scope=scope,
        page=int(page),
        per_page=int(per_page),
    )
    if redis_client is not None:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                payload = json.loads(cached)
                return payload["rows"], int(payload["page"]), int(payload["total"])
        except Exception:
            pass
    rows, effective_page, total = list_competition_matches(
        int(competition_id),
        page=int(page),
        per_page=int(per_page),
        username=username,
    )
    if redis_client is not None:
        try:
            redis_client.set(
                cache_key,
                _serialize_for_cache({
                    "rows": rows,
                    "page": effective_page,
                    "total": total,
                }),
                ex=ELO_MATCHES_LIST_CACHE_TTL,
            )
        except Exception:
            pass
    return rows, effective_page, total


def fetch_competition_match_detail_cached(match_id, competition_id):
    redis_client = _redis_client()
    cache_key = ELO_MATCH_DETAIL_CACHE_KEY.format(match_id=int(match_id))
    if redis_client is not None:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                row = json.loads(cached)
                if int(row.get("competition_id") or 0) != int(competition_id):
                    return None
                return row
        except Exception:
            pass
    row = get_competition_match(int(match_id), int(competition_id))
    if not row:
        return None
    if redis_client is not None:
        try:
            redis_client.set(
                cache_key,
                _serialize_for_cache(row),
                ex=ELO_MATCH_DETAIL_CACHE_TTL,
            )
        except Exception:
            pass
    return row


def invalidate_competition_match_caches(competition_id, match_id=None):
    redis_client = _redis_client()
    if redis_client is None:
        return
    try:
        pattern = ELO_MATCHES_LIST_CACHE_KEY.format(
            comp=int(competition_id), scope="*", page="*", per_page="*",
        )
        for key in redis_client.scan_iter(match=pattern, count=200):
            try:
                redis_client.delete(key)
            except Exception:
                pass
    except Exception:
        pass
    if match_id is not None:
        try:
            redis_client.delete(ELO_MATCH_DETAIL_CACHE_KEY.format(match_id=int(match_id)))
        except Exception:
            pass


__all__ = [
    "ELO_MATCHES_LIST_CACHE_KEY",
    "ELO_MATCHES_LIST_CACHE_TTL",
    "ELO_MATCH_DETAIL_CACHE_KEY",
    "ELO_MATCH_DETAIL_CACHE_TTL",
    "init_match_cache",
    "fetch_competition_matches_cached",
    "fetch_competition_match_detail_cached",
    "invalidate_competition_match_caches",
]
