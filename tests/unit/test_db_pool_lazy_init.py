import threading

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


def test_pool_exhaustion_tracking_is_explicit_and_nested():
    # 构造异常本身不应让普通 CLI/Celery 上下文长期持有它。
    mysql.MySQLPoolExhausted(1040, "outside request")
    assert mysql.current_mysql_pool_exhaustion() is None

    outer_token = mysql.begin_mysql_pool_exhaustion_tracking()
    try:
        outer_error = mysql.MySQLPoolExhausted(1040, "outer request")
        assert mysql.current_mysql_pool_exhaustion() is outer_error

        inner_token = mysql.begin_mysql_pool_exhaustion_tracking()
        try:
            assert mysql.current_mysql_pool_exhaustion() is None
            inner_error = mysql.MySQLPoolExhausted(1040, "inner request")
            assert mysql.current_mysql_pool_exhaustion() is inner_error
        finally:
            mysql.end_mysql_pool_exhaustion_tracking(inner_token)

        assert mysql.current_mysql_pool_exhaustion() is outer_error
    finally:
        mysql.end_mysql_pool_exhaustion_tracking(outer_token)

    assert mysql.current_mysql_pool_exhaustion() is None


def test_pool_exhaustion_tracking_is_isolated_between_threads():
    barrier = threading.Barrier(2)
    observed = {}

    def worker(name, exhaust):
        token = mysql.begin_mysql_pool_exhaustion_tracking()
        try:
            barrier.wait()
            if exhaust:
                mysql.MySQLPoolExhausted(1040, name)
            barrier.wait()
            observed[name] = mysql.current_mysql_pool_exhaustion() is not None
        finally:
            mysql.end_mysql_pool_exhaustion_tracking(token)

    busy = threading.Thread(target=worker, args=("busy", True))
    healthy = threading.Thread(target=worker, args=("healthy", False))
    busy.start()
    healthy.start()
    busy.join()
    healthy.join()

    assert observed == {"busy": True, "healthy": False}


class _FakeRawConnection:
    def __init__(self):
        self.open = True
        self.ping_error = None
        self.ping_count = 0
        self.rollback_count = 0
        self.close_count = 0

    def ping(self, reconnect=False):
        assert reconnect is False
        self.ping_count += 1
        if self.ping_error is not None:
            raise self.ping_error

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.open = False
        self.close_count += 1


def test_pool_connection_is_pinged_on_every_checkout(monkeypatch):
    raw = _FakeRawConnection()
    monkeypatch.setattr(mysql, "_create_raw_mysql_connection", lambda: raw)
    pool = mysql._MySQLConnectionPool(
        min_size=1,
        max_size=1,
    )

    first = pool.acquire()
    first.close()
    second = pool.acquire()
    second.close()

    assert raw.ping_count == 2
    assert raw.rollback_count == 2
    pool.close_idle_connections()


def test_recently_successful_but_closed_idle_connection_is_replaced(monkeypatch):
    initial = _FakeRawConnection()
    replacement = _FakeRawConnection()
    raw_connections = iter((initial, replacement))
    monkeypatch.setattr(
        mysql,
        "_create_raw_mysql_connection",
        lambda: next(raw_connections),
    )
    pool = mysql._MySQLConnectionPool(
        min_size=1,
        max_size=1,
    )

    first = pool.acquire()
    first.close()
    initial.close()

    second = pool.acquire()
    try:
        assert second._raw_conn is replacement
        assert initial.ping_count == 1
    finally:
        second.close()
        pool.close_idle_connections()


def test_remotely_killed_idle_connection_is_replaced_before_business_sql(
    monkeypatch,
):
    initial = _FakeRawConnection()
    replacement = _FakeRawConnection()
    raw_connections = iter((initial, replacement))
    monkeypatch.setattr(
        mysql,
        "_create_raw_mysql_connection",
        lambda: next(raw_connections),
    )
    pool = mysql._MySQLConnectionPool(min_size=1, max_size=1)

    first = pool.acquire()
    first.close()
    # 服务端 KILL/重启后 PyMySQL 可能仍认为 socket open，只有 pre-ping
    # 才能在业务 cursor.execute() 前发现远端断链。
    initial.ping_error = mysql.pymysql.err.OperationalError(
        2013,
        "lost connection",
    )

    second = pool.acquire()
    try:
        assert second._raw_conn is replacement
        assert initial.ping_count == 2
        assert initial.open is False
    finally:
        second.close()
        pool.close_idle_connections()


def test_slow_connection_creation_does_not_block_reusing_idle_connection(monkeypatch):
    initial = _FakeRawConnection()
    created = _FakeRawConnection()
    monkeypatch.setattr(mysql, "_create_raw_mysql_connection", lambda: initial)
    pool = mysql._MySQLConnectionPool(min_size=1, max_size=2)
    held = pool.acquire()

    creation_started = threading.Event()
    allow_creation = threading.Event()

    def slow_create():
        creation_started.set()
        assert allow_creation.wait(2)
        return created

    monkeypatch.setattr(mysql, "_create_raw_mysql_connection", slow_create)
    acquired = []
    first_thread = threading.Thread(target=lambda: acquired.append(pool.acquire()))
    first_thread.start()
    assert creation_started.wait(1)

    held.close()
    reuse_finished = threading.Event()

    def reuse_idle():
        acquired.append(pool.acquire())
        reuse_finished.set()

    second_thread = threading.Thread(target=reuse_idle)
    second_thread.start()
    try:
        assert reuse_finished.wait(0.5)
    finally:
        allow_creation.set()
        first_thread.join(2)
        second_thread.join(2)
        for connection in acquired:
            connection.close()
        pool.close_idle_connections()


def test_web_process_uses_independent_high_concurrency_pool_settings(monkeypatch):
    created = []

    def pool_factory(**settings):
        pool = _FakePool(**settings)
        created.append(pool)
        return pool

    monkeypatch.setenv("NUMOJ_SERVICE_NAME", "web")
    monkeypatch.setattr(mysql, "_db_pool", None)
    monkeypatch.setattr(mysql, "_MySQLConnectionPool", pool_factory)
    monkeypatch.setattr(mysql, "MYSQL_WEB_POOL_MAX_SIZE", 24)
    monkeypatch.setattr(mysql, "MYSQL_WEB_POOL_WAIT_TIMEOUT_SECONDS", 0.05)

    mysql.get_db_connection()

    assert created[0].settings["max_size"] == 24
    assert created[0].settings["wait_timeout"] == 0.05


def test_pool_exhaustion_uses_retryable_specific_error(monkeypatch):
    raw = _FakeRawConnection()
    monkeypatch.setattr(mysql, "_create_raw_mysql_connection", lambda: raw)
    pool = mysql._MySQLConnectionPool(
        min_size=1,
        max_size=1,
        wait_timeout=0.01,
    )
    held = pool.acquire()
    try:
        try:
            pool.acquire()
        except mysql.MySQLPoolExhausted as error:
            assert error.args[0] == 1040
        else:
            raise AssertionError("连接池耗尽必须抛出 MySQLPoolExhausted")
    finally:
        held.close()
        pool.close_idle_connections()


def test_mysql_server_connection_limit_is_translated_to_backpressure(monkeypatch):
    def reject_connection():
        raise mysql.pymysql.err.OperationalError(1040, "too many connections")

    monkeypatch.setattr(mysql, "_create_raw_mysql_connection", reject_connection)
    pool = mysql._MySQLConnectionPool(min_size=1, max_size=1)

    try:
        pool.acquire()
    except mysql.MySQLPoolExhausted as error:
        assert error.args[0] == 1040
    else:
        raise AssertionError("MySQL 连接上限必须转换为可重试背压")
