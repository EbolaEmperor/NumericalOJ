"""ELO 对战列表与详情缓存的直接单元契约。"""

import fnmatch

import pytest

from oj_modules.ranking import matches


class _FakeRedis:
    def __init__(self, values=None):
        self.values = dict(values or {})
        self.set_calls = []
        self.scan_calls = []
        self.delete_calls = []

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, *, ex):
        self.set_calls.append((key, value, ex))
        self.values[key] = value

    def scan_iter(self, *, match, count):
        self.scan_calls.append((match, count))
        for key in list(self.values):
            if fnmatch.fnmatchcase(str(key), match):
                yield key

    def delete(self, key):
        self.delete_calls.append(key)
        return int(self.values.pop(key, None) is not None)


class _FailingRedis:
    def get(self, _key):
        raise RuntimeError("redis get failed")

    def set(self, _key, _value, *, ex):
        raise RuntimeError(f"redis set failed: {ex}")

    def scan_iter(self, *, match, count):
        raise RuntimeError(f"redis scan failed: {match}:{count}")

    def delete(self, _key):
        raise RuntimeError("redis delete failed")


@pytest.fixture(autouse=True)
def _reset_injected_redis(monkeypatch):
    monkeypatch.setattr(matches, "_redis", None)


def test_list_cache_miss_populates_cache_and_next_read_hits(monkeypatch):
    redis_client = _FakeRedis()
    matches.init_match_cache(redis_client)
    calls = []

    def load_rows(competition_id, *, page, per_page, username=None):
        calls.append((competition_id, page, per_page, username))
        return ([{"id": 41, "competition_id": competition_id}], 2, 21)

    monkeypatch.setattr(matches, "list_competition_matches", load_rows)

    first = matches.fetch_competition_matches_cached("7", "2", "10", "alice")
    second = matches.fetch_competition_matches_cached(7, 2, 10, "alice")

    assert first == second == ([{"id": 41, "competition_id": 7}], 2, 21)
    assert calls == [(7, 2, 10, "alice")]
    assert len(redis_client.set_calls) == 1
    cache_key, _payload, ttl = redis_client.set_calls[0]
    assert cache_key == "ranking:elo:matches_list:7:user:alice:2:10"
    assert ttl == matches.ELO_MATCHES_LIST_CACHE_TTL


def test_detail_cache_miss_populates_cache_and_next_read_hits(monkeypatch):
    redis_client = _FakeRedis()
    matches.init_match_cache(redis_client)
    calls = []

    def load_detail(match_id, competition_id):
        calls.append((match_id, competition_id))
        return {
            "id": match_id,
            "competition_id": competition_id,
            "details": {"winner": 1},
        }

    monkeypatch.setattr(matches, "get_competition_match", load_detail)

    first = matches.fetch_competition_match_detail_cached("41", "7")
    second = matches.fetch_competition_match_detail_cached(41, 7)

    expected = {
        "id": 41,
        "competition_id": 7,
        "details": {"winner": 1},
    }
    assert first == second == expected
    assert calls == [(41, 7)]
    assert len(redis_client.set_calls) == 1
    cache_key, _payload, ttl = redis_client.set_calls[0]
    assert cache_key == "ranking:elo:match_detail:41"
    assert ttl == matches.ELO_MATCH_DETAIL_CACHE_TTL


def test_detail_cache_rejects_row_from_another_competition(monkeypatch):
    cache_key = matches.ELO_MATCH_DETAIL_CACHE_KEY.format(match_id=41)
    redis_client = _FakeRedis({
        cache_key: matches._serialize_for_cache({
            "id": 41,
            "competition_id": 7,
        }),
    })
    matches.init_match_cache(redis_client)

    monkeypatch.setattr(
        matches,
        "get_competition_match",
        lambda *_args: pytest.fail("跨比赛的缓存项不应进入 DB 回退"),
    )

    assert matches.fetch_competition_match_detail_cached(41, 8) is None


def test_redis_errors_fail_open_for_list_detail_and_invalidation(monkeypatch):
    matches.init_match_cache(_FailingRedis())
    list_calls = []
    detail_calls = []

    monkeypatch.setattr(
        matches,
        "list_competition_matches",
        lambda competition_id, *, page, per_page, username=None: (
            list_calls.append((competition_id, page, per_page, username))
            or ([{"id": 51}], 1, 1)
        ),
    )
    monkeypatch.setattr(
        matches,
        "get_competition_match",
        lambda match_id, competition_id: (
            detail_calls.append((match_id, competition_id))
            or {"id": match_id, "competition_id": competition_id}
        ),
    )

    assert matches.fetch_competition_matches_cached(9, 1, 20) == (
        [{"id": 51}],
        1,
        1,
    )
    assert matches.fetch_competition_match_detail_cached(51, 9) == {
        "id": 51,
        "competition_id": 9,
    }
    matches.invalidate_competition_match_caches(9, match_id=51)

    assert list_calls == [(9, 1, 20, None)]
    assert detail_calls == [(51, 9)]


def test_invalidation_deletes_only_competition_lists_and_selected_detail():
    competition_list_keys = {
        "ranking:elo:matches_list:7::1:20",
        "ranking:elo:matches_list:7:user:alice:2:20",
    }
    other_competition_key = "ranking:elo:matches_list:8::1:20"
    selected_detail_key = "ranking:elo:match_detail:41"
    other_detail_key = "ranking:elo:match_detail:42"
    redis_client = _FakeRedis({
        **{key: "{}" for key in competition_list_keys},
        other_competition_key: "{}",
        selected_detail_key: "{}",
        other_detail_key: "{}",
    })
    matches.init_match_cache(redis_client)

    matches.invalidate_competition_match_caches(7, match_id=41)

    assert competition_list_keys.isdisjoint(redis_client.values)
    assert selected_detail_key not in redis_client.values
    assert other_competition_key in redis_client.values
    assert other_detail_key in redis_client.values
    assert set(redis_client.delete_calls) == {
        *competition_list_keys,
        selected_detail_key,
    }
    assert redis_client.scan_calls == [
        ("ranking:elo:matches_list:7:*:*:*", 200),
    ]
