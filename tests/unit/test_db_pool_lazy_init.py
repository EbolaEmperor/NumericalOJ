from oj_modules import db_services


class _FakePool:
    def __init__(self, **settings):
        self.settings = settings
        self.acquire_count = 0

    def acquire(self):
        self.acquire_count += 1
        return self


def test_db_pool_is_created_once_on_first_connection_request(monkeypatch):
    created = []

    def pool_factory(**settings):
        pool = _FakePool(**settings)
        created.append(pool)
        return pool

    monkeypatch.setattr(db_services, '_db_pool', None)
    monkeypatch.setattr(db_services, '_MySQLConnectionPool', pool_factory)

    assert created == []
    first_connection = db_services.get_db_connection()
    second_connection = db_services.get_db_connection()

    assert len(created) == 1
    assert first_connection is second_connection is created[0]
    assert created[0].acquire_count == 2


def test_pooled_connection_discard_physically_removes_connection_from_pool():
    raw_connection = object()

    class Pool:
        def __init__(self):
            self.released = []
            self.discarded = []

        def release(self, connection):
            self.released.append(connection)

        def _discard(self, connection):
            self.discarded.append(connection)

    pool = Pool()
    proxy = db_services._PooledConnectionProxy(pool, raw_connection)

    proxy.discard()
    proxy.close()

    assert pool.discarded == [raw_connection]
    assert pool.released == []
