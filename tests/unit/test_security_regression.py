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
    assert 'onerror' not in out2.lower()

    out3 = sanitize_html('<a href="javascript:alert(1)">x</a>')
    assert 'javascript:' not in out3.lower()


def test_sanitize_keeps_benign_markup():
    from oj_modules.markdown_utils import sanitize_html
    out = sanitize_html('<pre><code>vector&lt;int&gt;</code></pre>')
    assert '<code' in out.lower()
    out2 = sanitize_html('<a href="https://example.com">link</a>')
    assert 'https://example.com' in out2


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
    text = (root / 'templates' / 'problem_detail.html').read_text(encoding='utf-8')
    assert '${score.username}' not in text
    assert '${score.class_cn}' not in text
    assert 'appendScoreCell(row, score.username' in text


def test_admin_user_template_uses_json_args_for_username():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'templates' / 'admin_user_management.html').read_text(encoding='utf-8')
    assert "showGradesModal('{{ u.id }}', '{{ u.username }}')" not in text
    assert "showEditUsernameModal('{{ u.id }}', '{{ u.username }}')" not in text
    assert '{{ u.username|tojson }}' in text


def test_class_self_service_cannot_promote_via_cadmin_membership():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'oj_modules' / 'routes' / 'class_management_routes.py').read_text(encoding='utf-8')
    assert "class_en == 'Cadmin' and not is_admin(user)" in text
    assert '不能自助切换到管理员班级' in text
    assert "cls['class_en'] == 'Cadmin' and not is_admin(user)" in text


def test_admin_primary_class_change_preserves_existing_admin_flag():
    root = Path(__file__).resolve().parents[2]
    class_text = (root / 'oj_modules' / 'routes' / 'class_management_routes.py').read_text(encoding='utf-8')
    admin_text = (root / 'oj_modules' / 'routes' / 'admin_user_routes.py').read_text(encoding='utf-8')
    expected = "1 if is_admin(user) else (1 if"
    assert expected in class_text
    assert expected in admin_text


def test_admin_extra_class_endpoint_rejects_cadmin():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'oj_modules' / 'routes' / 'class_management_routes.py').read_text(encoding='utf-8')
    assert "class_en == 'Cadmin'" in text
    assert '管理员班级不能作为附加班级添加' in text


def test_register_never_offers_or_accepts_cadmin_class():
    root = Path(__file__).resolve().parents[2]
    text = (root / 'oj_modules' / 'routes' / 'auth_routes.py').read_text(encoding='utf-8')
    assert 'get_all_classes_except_admin()' in text
    assert 'get_all_classes()' not in text
    assert "user_class.get('class_en') == 'Cadmin'" in text


# ---------------- 用户头文件名白名单 ----------------
def test_safe_user_header_filename():
    from oj_modules import judger_core
    assert judger_core.safe_user_header_filename('mylib.h') == 'mylib.h'
    assert judger_core.safe_user_header_filename('helper.hpp') == 'helper.hpp'
    # 路径分量被剥离，仅留基名（且扩展名合法）
    assert judger_core.safe_user_header_filename('/abs/path.h') == 'path.h'
    # 目录穿越 / 非头文件 / 含空格 / 空 → 拒绝
    assert judger_core.safe_user_header_filename('../../etc/passwd') is None
    assert judger_core.safe_user_header_filename('notes.txt') is None
    assert judger_core.safe_user_header_filename('bad name.h') is None
    assert judger_core.safe_user_header_filename('') is None
