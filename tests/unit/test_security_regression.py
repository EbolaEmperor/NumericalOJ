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
from pathlib import Path

import pytest
from flask import Flask, session


# ---------------- 会话用户请求内复用 ----------------
def test_current_user_reuses_request_lookup_and_tracks_session_changes(monkeypatch):
    from oj_modules import auth_helpers

    app = Flask(__name__)
    app.secret_key = 'test'
    lookups = []

    def load_user(username):
        lookups.append(username)
        return {'username': username}

    monkeypatch.setattr(auth_helpers, 'get_user_by_username', load_user)
    with app.test_request_context('/'):
        session['username'] = 'alice'
        assert auth_helpers.current_user() == {'username': 'alice'}
        assert auth_helpers.current_user() == {'username': 'alice'}
        session['username'] = 'bob'
        assert auth_helpers.current_user() == {'username': 'bob'}

    assert lookups == ['alice', 'bob']


# ---------------- safe_table_name ----------------
def test_safe_table_name_accepts_valid():
    from oj_modules.db_services import safe_table_name
    assert safe_table_name('C2024class') == 'C2024class'
    assert safe_table_name('abc_123') == 'abc_123'


def test_safe_table_name_rejects_injection():
    from oj_modules.db_services import safe_table_name
    for bad in ['', 'a b', 'a;b', "a'", 'a-b', 'a.b', 'DROP TABLE x', '班级', 'x);--', None]:
        with pytest.raises(ValueError):
            safe_table_name(bad)


# ---------------- 口令哈希 ----------------
def test_legacy_sha256_verifies_and_flags_rehash():
    from oj_modules.security_utils import verify_password
    pw = "secret123"
    legacy = hashlib.sha256(pw.encode()).hexdigest()
    ok, needs_rehash = verify_password(legacy, pw)
    assert ok and needs_rehash          # 历史哈希校验通过 → 需升级
    assert verify_password(legacy, "wrong")[0] is False


def test_werkzeug_hash_roundtrip_no_rehash():
    from oj_modules.security_utils import hash_password, verify_password
    h = hash_password("secret123")
    assert ':' in h                      # werkzeug 形如 pbkdf2:sha256:... / scrypt:...
    ok, needs_rehash = verify_password(h, "secret123")
    assert ok and not needs_rehash
    assert verify_password(h, "nope")[0] is False


def test_verify_password_empty_stored():
    from oj_modules.security_utils import verify_password
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
    from oj_modules.security_utils import rate_limit_hit
    r = _FakeRedis()
    for _ in range(3):
        assert rate_limit_hit(r, 'k', 3, 60)[0] is True
    allowed, retry = rate_limit_hit(r, 'k', 3, 60)
    assert allowed is False
    assert retry >= 0


def test_rate_limit_fail_open_without_redis():
    from oj_modules.security_utils import rate_limit_hit
    assert rate_limit_hit(None, 'k', 1, 60)[0] is True


def test_cooldown_blocks_second_call():
    from oj_modules.security_utils import cooldown_active
    r = _FakeRedis()
    assert cooldown_active(r, 'cd', 60)[0] is True
    assert cooldown_active(r, 'cd', 60)[0] is False


# ---------------- sanitize_html ----------------
def test_sanitize_strips_script_and_events_and_protocols():
    from oj_modules.markdown_utils import sanitize_html
    out = sanitize_html('<script>alert(1)</script><b>hi</b>')
    assert '<script' not in out.lower()
    assert 'hi' in out

    out2 = sanitize_html('<img src=x onerror="alert(1)">')
    assert '<img' not in out2.lower() or 'onerror' not in out2.lower()

    out3 = sanitize_html('<a href="javascript:alert(1)">x</a>')
    assert '<a' not in out3.lower() or 'javascript:' not in out3.lower()


def test_sanitize_keeps_benign_markup():
    from oj_modules.markdown_utils import sanitize_html
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
    from oj_modules import markdown_utils

    monkeypatch.setattr(markdown_utils, 'bleach', None)
    out = markdown_utils.sanitize_html(payload)

    assert '<a' not in out.lower()
    assert '<img' not in out.lower()
    assert '<svg' not in out.lower()
    assert '<script' not in out.lower()
    assert '&lt;' in out


def test_sanitize_fails_closed_when_bleach_raises(monkeypatch):
    from oj_modules import markdown_utils

    class BrokenBleach:
        @staticmethod
        def clean(*_args, **_kwargs):
            raise RuntimeError('simulated sanitizer failure')

    monkeypatch.setattr(markdown_utils, 'bleach', BrokenBleach())
    out = markdown_utils.sanitize_html(
        '<a href=javascript:alert(1)>click</a>'
    )

    assert out == '&lt;a href=javascript:alert(1)&gt;click&lt;/a&gt;'


# ---------------- 用户名白名单 / 管理员页 XSS 回归 ----------------
def test_validate_username_accepts_safe_identifiers():
    from oj_modules.security_utils import validate_username
    for username in ('alice', 'student_001', 'u-2026.07'):
        ok, cleaned, msg = validate_username(f' {username} ')
        assert ok is True
        assert cleaned == username
        assert msg == ''


def test_validate_username_rejects_xss_and_paths():
    from oj_modules.security_utils import validate_username
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


def test_admin_score_template_does_not_innerhtml_user_fields():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'templates' / 'problems' / 'detail.html').read_text(encoding='utf-8')
    assert '${score.username}' not in text
    assert '${score.classes_display}' not in text
    assert 'appendScoreCell(row, score.username' in text
    assert 'appendScoreCell(row, score.classes_display' in text


def test_admin_user_template_uses_json_args_for_username():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'templates' / 'admin' / 'users.html').read_text(encoding='utf-8')
    assert "showGradesModal('{{ u.id }}', '{{ u.username }}')" not in text
    assert "showEditUsernameModal('{{ u.id }}', '{{ u.username }}')" not in text
    assert '{{ u.username|tojson }}' in text


def test_class_membership_routes_never_change_admin_privileges():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'oj_modules' / 'routes' / 'class_management_routes.py').read_text(encoding='utf-8')
    assert 'UPDATE users SET is_admin' not in text
    assert 'grant_user_admin_ajax' not in text


def test_admin_privilege_grant_is_explicit_and_one_way():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'oj_modules' / 'routes' / 'admin_user_routes.py').read_text(encoding='utf-8')
    assert "def grant_user_admin_ajax" in text
    assert "UPDATE users SET is_admin=1" in text
    assert "SET is_admin=0" not in text


def test_class_routes_do_not_contain_a_pseudo_admin_class():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'oj_modules' / 'routes' / 'class_management_routes.py').read_text(encoding='utf-8')
    assert 'Cadmin' not in text


def test_register_offers_every_real_class_from_the_data_layer():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'oj_modules' / 'routes' / 'auth_routes.py').read_text(encoding='utf-8')
    assert 'attach_class_logos(get_all_classes())' in text
    assert 'get_all_classes_except_admin' not in text
    assert 'Cadmin' not in text


# ---------------- 用户头文件名白名单 ----------------
def test_safe_user_header_filename():
    from oj_modules import judger_core
    assert judger_core.safe_user_header_filename('mylib.h') == 'mylib.h'
    assert judger_core.safe_user_header_filename('include/helper.hpp') == 'include/helper.hpp'
    assert judger_core.safe_user_header_filename('notes/read me.inc') == 'notes/read me.inc'
    # 绝对路径和目录穿越必须拒绝，不能再 basename 扁平化。
    assert judger_core.safe_user_header_filename('/abs/path.h') is None
    assert judger_core.safe_user_header_filename('../../etc/passwd') is None
    assert judger_core.safe_user_header_filename('notes.txt') == 'notes.txt'
    assert judger_core.safe_user_header_filename('') is None
