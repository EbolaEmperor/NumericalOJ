from oj_modules.submissions import locks


class _FakeRedis:
    def __init__(self):
        self.values = {}
        self.eval_calls = []

    def set(self, key, value, *, nx, ex):
        assert nx is True
        assert ex == locks.LOCK_TTL_SECONDS
        if key in self.values:
            return False
        self.values[key] = value
        return True

    def exists(self, key):
        return key in self.values

    def delete(self, key):
        self.values.pop(key, None)

    def eval(self, script, key_count, key, token):
        self.eval_calls.append((script, key_count, key, token))
        if self.values.get(key) == token:
            self.values.pop(key)
            return 1
        return 0


def test_submission_lock_lifecycle(monkeypatch):
    client = _FakeRedis()
    monkeypatch.setattr(locks, "_lock_redis_client", client)

    acquired_client, key, token = locks.acquire_submission_lock(42)
    assert acquired_client is client
    assert key == "submission:42:lock"
    assert token
    assert locks.has_submission_lock(42) is True

    _, duplicate_key, duplicate_token = locks.acquire_submission_lock(42)
    assert duplicate_key == key
    assert duplicate_token is None

    locks.release_submission_lock(client, key, token)
    assert client.eval_calls
    assert locks.has_submission_lock(42) is False


def test_submission_lock_is_fail_open_when_redis_is_unavailable(monkeypatch):
    monkeypatch.setattr(locks, "_lock_redis_client", None)
    monkeypatch.setattr(locks, "create_optional_redis_client", lambda: None)

    assert locks.acquire_submission_lock(7) == (None, None, None)
    assert locks.has_submission_lock(7) is False
    locks.clear_submission_lock(7)

