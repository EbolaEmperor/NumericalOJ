from oj_modules import db_services
from oj_modules.infrastructure import mysql


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

    monkeypatch.setattr(mysql, '_db_pool', None)
    monkeypatch.setattr(mysql, '_MySQLConnectionPool', pool_factory)

    assert created == []
    first_connection = mysql.get_db_connection()
    second_connection = mysql.get_db_connection()

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
    proxy = mysql._PooledConnectionProxy(pool, raw_connection)

    proxy.discard()
    proxy.close()

    assert pool.discarded == [raw_connection]
    assert pool.released == []


def test_db_services_compatibly_reexports_mysql_entrypoints():
    assert db_services.get_db_connection is mysql.get_db_connection
    assert db_services.safe_table_name is mysql.safe_table_name
    assert db_services._create_raw_mysql_connection is mysql._create_raw_mysql_connection
    assert db_services._PooledConnectionProxy is mysql._PooledConnectionProxy
    assert db_services._MySQLConnectionPool is mysql._MySQLConnectionPool
    assert db_services._get_db_pool is mysql._get_db_pool


def test_db_services_business_functions_keep_connection_monkeypatch_seam(monkeypatch):
    replacement = object()
    monkeypatch.setattr(db_services, "get_db_connection", replacement)

    assert db_services.get_user_by_username.__globals__["get_db_connection"] is replacement
