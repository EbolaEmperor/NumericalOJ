from backend.oj_modules.tasks import class_activity_tasks


class _FakeRedis:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, *, ex=None, nx=False):
        del ex
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def delete(self, key):
        self.values.pop(key, None)


class _RegisteredTask:
    def __init__(self, function, options):
        self.function = function
        self.options = options
        self.calls = []

    def __call__(self, *args):
        return self.function(self, *args)

    def apply_async(self, *, args, countdown):
        self.calls.append((list(args), countdown))


class _FakeCelery:
    def task(self, **options):
        def decorator(function):
            return _RegisteredTask(function, options)

        return decorator


def test_refresh_task_uses_twenty_minute_self_scheduling_chain(monkeypatch):
    redis_client = _FakeRedis()
    owner_id = "owner-1"
    redis_client.set(
        class_activity_tasks.CLASS_ACTIVITY_REFRESH_OWNER_KEY,
        owner_id,
    )
    refresh = []
    monkeypatch.setattr(
        class_activity_tasks,
        "refresh_class_activity_snapshot",
        lambda client: refresh.append(client)
        or {"class_count": 3, "generated_at": "2026-08-29T10:00:00+08:00"},
    )
    task = class_activity_tasks.register_class_activity_refresh_task(
        _FakeCelery(), redis_client
    )

    result = task(owner_id)

    assert result["success"] is True
    assert result["class_count"] == 3
    assert refresh == [redis_client]
    assert task.calls == [
        (
            [owner_id],
            class_activity_tasks.CLASS_ACTIVITY_REFRESH_INTERVAL_SECONDS,
        )
    ]
    assert task.options["name"] == "oj.class_activity.refresh_snapshot"


def test_refresh_failure_keeps_chain_alive(monkeypatch):
    redis_client = _FakeRedis()
    owner_id = "owner-1"
    redis_client.set(
        class_activity_tasks.CLASS_ACTIVITY_REFRESH_OWNER_KEY,
        owner_id,
    )

    def fail(_client):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(
        class_activity_tasks,
        "refresh_class_activity_snapshot",
        fail,
    )
    task = class_activity_tasks.register_class_activity_refresh_task(
        _FakeCelery(), redis_client
    )

    result = task(owner_id)

    assert result == {"success": False, "reason": "refresh failed"}
    assert task.calls == [
        (
            [owner_id],
            class_activity_tasks.CLASS_ACTIVITY_REFRESH_INTERVAL_SECONDS,
        )
    ]


def test_owner_check_failure_keeps_chain_alive():
    class _UnavailableRedis(_FakeRedis):
        def get(self, key):
            del key
            raise OSError("redis unavailable")

    redis_client = _UnavailableRedis()
    owner_id = "owner-1"
    task = class_activity_tasks.register_class_activity_refresh_task(
        _FakeCelery(), redis_client
    )

    result = task(owner_id)

    assert result == {"success": False, "reason": "redis owner unavailable"}
    assert task.calls == [
        (
            [owner_id],
            class_activity_tasks.CLASS_ACTIVITY_REFRESH_INTERVAL_SECONDS,
        )
    ]


def test_safe_seed_is_idempotent_and_recovery_can_replace_owner():
    redis_client = _FakeRedis()
    task = _RegisteredTask(lambda *_args: None, {})

    class_activity_tasks.seed_class_activity_refresh(redis_client, task)
    class_activity_tasks.seed_class_activity_refresh(redis_client, task)

    assert len(task.calls) == 1
    assert task.calls[0][1] == 0

    class_activity_tasks.seed_class_activity_refresh(
        redis_client,
        task,
        reset_owner=True,
    )
    assert len(task.calls) == 2
