# -*- coding: utf-8 -*-
"""安全修复的回归单测（纯逻辑，不需 DB/Redis 实例）。

覆盖：
- safe_table_name：动态表名白名单（防 SQL 注入，对应 admin add_class 死正则修复）
- 口令哈希：历史 sha256 兼容校验 + 透明重哈希标志；werkzeug 带盐哈希
- rate_limit_hit / cooldown：基于假 Redis 的限流语义 + Redis 缺失 fail-open
- sanitize_html：去除 script / 事件属性 / 危险协议，保留良性标签（防存储型 XSS）
- safe_user_header_filename：用户头文件名白名单（防目录穿越写入）
- validate_username：用户身份字段白名单，防用户名进入管理员页面形成存储型 XSS
"""
import hashlib
from concurrent.futures import Future
from pathlib import Path
from threading import Barrier, Event, Lock, Thread

import pytest
from flask import Flask, session


# ---------------- 会话用户请求内复用 ----------------
def test_current_user_reuses_request_lookup_and_tracks_session_changes(monkeypatch):
    from backend.oj_modules.security import auth

    app = Flask(__name__)
    app.secret_key = 'test'
    lookups = []

    def load_user(username):
        lookups.append(username)
        return {'username': username}

    monkeypatch.setattr(auth, 'get_user_by_username', load_user)
    with app.test_request_context('/'):
        session['username'] = 'alice'
        assert auth.current_user() == {'username': 'alice'}
        assert auth.current_user() == {'username': 'alice'}
        session['username'] = 'bob'
        assert auth.current_user() == {'username': 'bob'}

    assert lookups == ['alice', 'bob']


def test_current_user_short_cache_reuses_normal_user_across_requests(monkeypatch):
    from backend.oj_modules.security import auth

    app = Flask(__name__)
    app.secret_key = 'test'
    lookups = []

    def load_user(username):
        lookups.append(username)
        return {'id': 7, 'username': username, 'is_admin': 0}

    auth.invalidate_cached_browser_user()
    monkeypatch.setattr(auth, 'get_user_by_username', load_user)
    for _ in range(2):
        with app.test_request_context('/'):
            session['username'] = 'alice'
            user = auth.current_user()
            user['username'] = 'mutated-locally'

    assert lookups == ['alice']
    with app.test_request_context('/'):
        session['username'] = 'alice'
        assert auth.current_user()['username'] == 'alice'


def test_current_user_does_not_cross_request_cache_admin(monkeypatch):
    from backend.oj_modules.security import auth

    app = Flask(__name__)
    app.secret_key = 'test'
    lookups = []

    def load_user(username):
        lookups.append(username)
        return {'id': 1, 'username': username, 'is_admin': 1}

    auth.invalidate_cached_browser_user()
    monkeypatch.setattr(auth, 'get_user_by_username', load_user)
    for _ in range(2):
        with app.test_request_context('/'):
            session['username'] = 'admin'
            assert auth.current_user()['is_admin'] == 1

    assert lookups == ['admin', 'admin']


def test_current_user_cache_can_be_invalidated_by_user_id(monkeypatch):
    from backend.oj_modules.security import auth

    app = Flask(__name__)
    app.secret_key = 'test'
    roles = [0, 1]

    def load_user(username):
        return {'id': 7, 'username': username, 'is_admin': roles.pop(0)}

    auth.invalidate_cached_browser_user()
    monkeypatch.setattr(auth, 'get_user_by_username', load_user)
    with app.test_request_context('/'):
        session['username'] = 'alice'
        assert auth.current_user()['is_admin'] == 0

    auth.invalidate_cached_browser_user(user_id=7)
    with app.test_request_context('/'):
        session['username'] = 'alice'
        assert auth.current_user()['is_admin'] == 1

    assert roles == []


def test_current_user_cache_loader_identity_change_forces_reload(monkeypatch):
    from backend.oj_modules.security import auth

    auth.invalidate_cached_browser_user()
    monkeypatch.setattr(
        auth,
        'get_user_by_username',
        lambda username: {
            'id': 7,
            'username': username,
            'email': 'old@test',
            'is_admin': 0,
        },
    )
    assert auth._cached_browser_user('alice')['email'] == 'old@test'

    lookups = []

    def replacement(username):
        lookups.append(username)
        return {
            'id': 7,
            'username': username,
            'email': 'new@test',
            'is_admin': 0,
        }

    monkeypatch.setattr(auth, 'get_user_by_username', replacement)
    assert auth._cached_browser_user('alice')['email'] == 'new@test'
    assert lookups == ['alice']


def test_current_user_cache_does_not_negative_cache_missing_user(monkeypatch):
    from backend.oj_modules.security import auth

    lookups = []

    def load_user(username):
        lookups.append(username)
        return None

    auth.invalidate_cached_browser_user()
    monkeypatch.setattr(auth, 'get_user_by_username', load_user)

    assert auth._cached_browser_user('missing') is None
    assert auth._cached_browser_user('missing') is None
    assert lookups == ['missing', 'missing']


def test_current_user_cache_fans_out_one_loader_failure_without_retry_convoy(
    monkeypatch,
):
    from backend.oj_modules.security import auth

    worker_count = 8
    start = Barrier(worker_count)
    loader_started = Event()
    release_loader = Event()
    all_waiters_ready = Event()
    state_lock = Lock()
    calls = 0
    waiter_count = 0
    now = [100.0]

    class TrackingFuture(Future):
        def result(self, *args, **kwargs):
            nonlocal waiter_count
            with state_lock:
                waiter_count += 1
                if waiter_count == worker_count - 1:
                    all_waiters_ready.set()
            return super().result(*args, **kwargs)

    def load_user(username):
        nonlocal calls
        with state_lock:
            calls += 1
            attempt = calls
        if attempt == 1:
            loader_started.set()
            assert release_loader.wait(timeout=2)
            raise RuntimeError('database unavailable')
        return {'id': 7, 'username': username, 'is_admin': 0}

    auth.invalidate_cached_browser_user()
    monkeypatch.setattr(auth, '_browser_user_cache_now', lambda: now[0])
    monkeypatch.setattr(
        auth,
        '_BROWSER_USER_SINGLEFLIGHT_WAIT_SECONDS',
        1.0,
    )
    monkeypatch.setattr(auth, 'Future', TrackingFuture)
    monkeypatch.setattr(auth, 'get_user_by_username', load_user)
    errors = []

    def read_user():
        start.wait(timeout=2)
        try:
            auth._cached_browser_user('alice')
        except RuntimeError as exc:
            errors.append(str(exc))

    workers = [Thread(target=read_user) for _ in range(worker_count)]
    for worker in workers:
        worker.start()
    assert loader_started.wait(timeout=2)
    assert all_waiters_ready.wait(timeout=2)
    release_loader.set()
    for worker in workers:
        worker.join(timeout=2)

    assert all(not worker.is_alive() for worker in workers)
    assert errors == ['database unavailable'] * worker_count
    assert calls == 1
    assert auth._browser_user_cache_inflight == {}

    with pytest.raises(RuntimeError, match='database unavailable'):
        auth._cached_browser_user('alice')
    assert calls == 1

    now[0] += auth._BROWSER_USER_FAILURE_COOLDOWN_SECONDS + 0.001
    assert auth._cached_browser_user('alice')['username'] == 'alice'
    assert calls == 2


def test_current_user_cache_waiter_timeout_uses_fast_mysql_backpressure(
    monkeypatch,
):
    from backend.oj_modules.infrastructure.mysql import MySQLPoolExhausted
    from backend.oj_modules.security import auth

    loader_started = Event()
    release_loader = Event()
    owner_result = []
    calls = 0

    def load_user(username):
        nonlocal calls
        calls += 1
        loader_started.set()
        assert release_loader.wait(timeout=2)
        return {'id': 7, 'username': username, 'is_admin': 0}

    auth.invalidate_cached_browser_user()
    monkeypatch.setattr(auth, 'get_user_by_username', load_user)
    monkeypatch.setattr(
        auth,
        '_BROWSER_USER_SINGLEFLIGHT_WAIT_SECONDS',
        0.01,
    )

    owner = Thread(
        target=lambda: owner_result.append(auth._cached_browser_user('alice')),
    )
    owner.start()
    assert loader_started.wait(timeout=2)

    with pytest.raises(MySQLPoolExhausted, match='用户认证读取繁忙'):
        auth._cached_browser_user('alice')
    assert owner.is_alive()
    assert calls == 1

    release_loader.set()
    owner.join(timeout=2)
    assert not owner.is_alive()
    assert owner_result[0]['username'] == 'alice'
    assert auth._cached_browser_user('alice')['username'] == 'alice'
    assert calls == 1


def test_current_user_cache_invalidation_detaches_inflight_stale_load(monkeypatch):
    from backend.oj_modules.security import auth

    first_started = Event()
    release_first = Event()
    second_finished = Event()
    state_lock = Lock()
    calls = 0
    results = {}

    def load_user(username):
        nonlocal calls
        with state_lock:
            calls += 1
            attempt = calls
        if attempt == 1:
            first_started.set()
            assert release_first.wait(timeout=2)
            email = 'stale@test'
        else:
            email = 'fresh@test'
        return {
            'id': 7,
            'username': username,
            'email': email,
            'is_admin': 0,
        }

    auth.invalidate_cached_browser_user()
    monkeypatch.setattr(auth, 'get_user_by_username', load_user)

    first = Thread(
        target=lambda: results.setdefault(
            'first', auth._cached_browser_user('alice')['email'],
        )
    )
    first.start()
    assert first_started.wait(timeout=2)

    # 写路径常只知道 user_id；运行中的查询尚未发布映射，也必须被 generation
    # 隔离并从 singleflight 索引摘除。
    auth.invalidate_cached_browser_user(user_id=7)

    def read_fresh():
        results['second'] = auth._cached_browser_user('alice')['email']
        second_finished.set()

    second = Thread(target=read_fresh)
    second.start()
    assert second_finished.wait(timeout=2)
    assert results['second'] == 'fresh@test'

    release_first.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert results['first'] == 'stale@test'
    assert auth._cached_browser_user('alice')['email'] == 'fresh@test'
    assert calls == 2
    assert auth._browser_user_cache_inflight == {}


# ---------------- safe_table_name ----------------
def test_safe_table_name_accepts_valid():
    from backend.oj_modules.infrastructure.mysql import safe_table_name
    assert safe_table_name('C2024class') == 'C2024class'
    assert safe_table_name('abc_123') == 'abc_123'


def test_safe_table_name_rejects_injection():
    from backend.oj_modules.infrastructure.mysql import safe_table_name
    for bad in ['', 'a b', 'a;b', "a'", 'a-b', 'a.b', 'DROP TABLE x', '班级', 'x);--', None]:
        with pytest.raises(ValueError):
            safe_table_name(bad)


# ---------------- 口令哈希 ----------------
def test_legacy_sha256_verifies_and_flags_rehash():
    from backend.oj_modules.security.credentials import verify_password
    pw = "secret123"
    legacy = hashlib.sha256(pw.encode()).hexdigest()
    ok, needs_rehash = verify_password(legacy, pw)
    assert ok and needs_rehash          # 历史哈希校验通过 → 需升级
    assert verify_password(legacy, "wrong")[0] is False


def test_werkzeug_hash_roundtrip_no_rehash():
    from backend.oj_modules.security.credentials import hash_password, verify_password
    h = hash_password("secret123")
    assert ':' in h                      # werkzeug 形如 pbkdf2:sha256:... / scrypt:...
    ok, needs_rehash = verify_password(h, "secret123")
    assert ok and not needs_rehash
    assert verify_password(h, "nope")[0] is False


def test_verify_password_empty_stored():
    from backend.oj_modules.security.credentials import verify_password
    assert verify_password(None, "x") == (False, False)
    assert verify_password("", "x") == (False, False)


# ---------------- 限流 ----------------
class _FakeRedis:
    def __init__(self):
        self.store = {}
        self.ttls = {}

    def incr(self, key):
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    def expire(self, key, seconds):
        self.ttls[key] = int(seconds)
        return True

    def ttl(self, key):
        return self.ttls.get(key, -1)

    def set(self, key, val, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = val
        if ex:
            self.ttls[key] = int(ex)
        return True


def test_rate_limit_blocks_after_max():
    from backend.oj_modules.security.throttling import rate_limit_hit
    r = _FakeRedis()
    for _ in range(3):
        assert rate_limit_hit(r, 'k', 3, 60)[0] is True
    allowed, retry = rate_limit_hit(r, 'k', 3, 60)
    assert allowed is False
    assert retry >= 0


def test_rate_limit_fail_open_without_redis():
    from backend.oj_modules.security.throttling import rate_limit_hit
    assert rate_limit_hit(None, 'k', 1, 60)[0] is True


def test_cooldown_blocks_second_call():
    from backend.oj_modules.security.throttling import cooldown_active
    r = _FakeRedis()
    assert cooldown_active(r, 'cd', 60)[0] is True
    assert cooldown_active(r, 'cd', 60)[0] is False


# ---------------- sanitize_html ----------------
def test_sanitize_strips_script_and_events_and_protocols():
    from backend.oj_modules.shared.markdown import sanitize_html
    out = sanitize_html('<script>alert(1)</script><b>hi</b>')
    assert '<script' not in out.lower()
    assert 'hi' in out

    out2 = sanitize_html('<img src=x onerror="alert(1)">')
    assert '<img' not in out2.lower() or 'onerror' not in out2.lower()

    out3 = sanitize_html('<a href="javascript:alert(1)">x</a>')
    assert '<a' not in out3.lower() or 'javascript:' not in out3.lower()


def test_sanitize_keeps_benign_markup():
    from backend.oj_modules.shared.markdown import sanitize_html
    out = sanitize_html('<pre><code>vector&lt;int&gt;</code></pre>')
    assert '<code' in out.lower() or '&lt;code' in out.lower()
    out2 = sanitize_html('<a href="https://example.com">link</a>')
    assert 'https://example.com' in out2


@pytest.mark.parametrize(
    'payload',
    (
        '<a href=javascript:alert(1)>click</a>',
        '<a href=vbscript:msgbox(1)>click</a>',
        '<img src=data:text/html,test onerror=alert(1)>',
        '<svg><a href=javascript:alert(1)>click</a>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
    ),
)
def test_sanitize_fails_closed_when_bleach_is_unavailable(monkeypatch, payload):
    from backend.oj_modules.shared import markdown

    monkeypatch.setattr(markdown, 'bleach', None)
    out = markdown.sanitize_html(payload)

    assert '<a' not in out.lower()
    assert '<img' not in out.lower()
    assert '<svg' not in out.lower()
    assert '<script' not in out.lower()
    assert '&lt;' in out


def test_sanitize_fails_closed_when_bleach_raises(monkeypatch):
    from backend.oj_modules.shared import markdown

    class BrokenBleach:
        @staticmethod
        def clean(*_args, **_kwargs):
            raise RuntimeError('simulated sanitizer failure')

    monkeypatch.setattr(markdown, 'bleach', BrokenBleach())
    out = markdown.sanitize_html(
        '<a href=javascript:alert(1)>click</a>'
    )

    assert out == '&lt;a href=javascript:alert(1)&gt;click&lt;/a&gt;'


# ---------------- 用户名白名单 / 管理员页 XSS 回归 ----------------
def test_validate_username_accepts_safe_identifiers():
    from backend.oj_modules.security.credentials import validate_username
    for username in ('alice', 'student_001', 'u-2026.07'):
        ok, cleaned, msg = validate_username(f' {username} ')
        assert ok is True
        assert cleaned == username
        assert msg == ''


def test_validate_username_rejects_xss_and_paths():
    from backend.oj_modules.security.credentials import validate_username
    for bad in (
        '',
        '-starts-with-dash',
        '<svg onload=alert(1)>',
        "x');alert(1)//",
        '../../admin',
        '中文用户名',
        'a' * 51,
    ):
        ok, _, msg = validate_username(bad)
        assert ok is False
        assert msg


def test_validate_email_accepts_deliverable_addresses_and_rejects_unsafe_values():
    from backend.oj_modules.security.credentials import validate_email

    assert validate_email(' Alice.Tag+oj@example.edu ') == (
        True,
        'Alice.Tag+oj@example.edu',
        '',
    )
    for bad in (
        '',
        'not-an-email',
        'a@localhost',
        'a..b@example.com',
        'x@example.com<script>',
        ('a' * 65) + '@example.com',
    ):
        ok, _, message = validate_email(bad)
        assert ok is False
        assert message


def test_class_membership_routes_never_change_admin_privileges():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'backend' / 'oj_modules' / 'routes' / 'class_management_routes.py').read_text(encoding='utf-8')
    assert 'UPDATE users SET is_admin' not in text
    assert 'grant_user_admin_ajax' not in text


def test_admin_privilege_grant_is_explicit_and_one_way():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'backend' / 'oj_modules' / 'routes' / 'admin_user_routes.py').read_text(encoding='utf-8')
    assert "def grant_user_admin_ajax" in text
    assert "UPDATE users SET is_admin=1" in text
    assert "SET is_admin=0" not in text


def test_class_routes_do_not_contain_a_pseudo_admin_class():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'backend' / 'oj_modules' / 'routes' / 'class_management_routes.py').read_text(encoding='utf-8')
    assert 'Cadmin' not in text


def test_register_offers_every_real_class_from_the_data_layer():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'backend' / 'oj_modules' / 'routes' / 'auth_routes.py').read_text(encoding='utf-8')
    assert 'attach_class_logos(get_all_classes())' in text
    assert 'get_all_classes_except_admin' not in text
    assert 'Cadmin' not in text


# ---------------- 用户头文件名白名单 ----------------
def test_safe_user_header_filename():
    from backend.oj_modules.judging import core as judger_core
    assert judger_core.safe_user_header_filename('mylib.h') == 'mylib.h'
    assert judger_core.safe_user_header_filename('include/helper.hpp') == 'include/helper.hpp'
    assert judger_core.safe_user_header_filename('notes/read me.inc') == 'notes/read me.inc'
    # 绝对路径和目录穿越必须拒绝，不能再 basename 扁平化。
    assert judger_core.safe_user_header_filename('/abs/path.h') is None
    assert judger_core.safe_user_header_filename('../../etc/passwd') is None
    assert judger_core.safe_user_header_filename('notes.txt') == 'notes.txt'
    assert judger_core.safe_user_header_filename('') is None
