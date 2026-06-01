# -*- coding: utf-8 -*-
"""auth_routes.py 集成测试（§4a）：登录/登出/发码/注册/改密/忘记密码。

约定：
- conftest 已 mock smtplib.SMTP_SSL（send_verification_code 永不真正发信），
  故 /send_code 等仍会向 verification_codes 写入真实 6 位 code，可直接 SQL 读回。
- DB 每个用例前 truncate+reseed（admin / Cadmin / Cclass1 / class_adjust_enabled）。
"""
import hashlib

import pytest

from oj_modules import db_services as db
from oj_modules.security_utils import verify_password
from tests.conftest import ADMIN_USERNAME, ADMIN_PASSWORD


def _sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _code_for(email):
    """读 verification_codes 里某邮箱的验证码（注册/改密/忘记密码用）。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT code FROM verification_codes WHERE email=%s", (email,))
            row = cur.fetchone()
            return row['code'] if row else None
    finally:
        conn.close()


def _password_hash_of(username):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT password_hash FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            return row['password_hash'] if row else None
    finally:
        conn.close()


# --------------------------- login ---------------------------

def test_login_success(client):
    r = client.post('/login',
                    data={'username': ADMIN_USERNAME, 'password': ADMIN_PASSWORD})
    assert r.status_code in (301, 302)
    # 跳转到题目列表
    assert '/problems' in r.headers.get('Location', '')
    with client.session_transaction() as s:
        assert s.get('username') == ADMIN_USERNAME


def test_login_wrong_password(client):
    r = client.post('/login',
                    data={'username': ADMIN_USERNAME, 'password': 'bad-password'})
    assert r.status_code == 200
    assert '用户名或密码错误' in r.get_data(as_text=True)
    with client.session_transaction() as s:
        assert 'username' not in s


def test_login_unknown_user(client):
    r = client.post('/login',
                    data={'username': 'no-such-user', 'password': 'whatever'})
    assert r.status_code == 200
    assert '用户名或密码错误' in r.get_data(as_text=True)
    with client.session_transaction() as s:
        assert 'username' not in s


# --------------------------- logout ---------------------------

def test_logout(client, login):
    login(ADMIN_USERNAME)
    with client.session_transaction() as s:
        assert s.get('username') == ADMIN_USERNAME
    r = client.get('/logout')
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')
    with client.session_transaction() as s:
        assert 'username' not in s


# --------------------------- send_code ---------------------------

def test_send_code_ok(client):
    # 全新邮箱（未注册）→ 成功并写入验证码
    r = client.post('/send_code', data={'email': 'newcomer@example.com'})
    assert r.status_code == 200
    payload = r.get_json()
    assert payload['success'] is True
    assert payload['message'] == '验证码已发送'
    code = _code_for('newcomer@example.com')
    assert code is not None and len(code) == 6 and code.isdigit()


def test_send_code_empty_email(client):
    r = client.post('/send_code', data={'email': ''})
    assert r.status_code == 200
    payload = r.get_json()
    assert payload['success'] is False
    assert payload['message'] == '邮箱不能为空'


def test_send_code_email_already_registered(client):
    # admin 的邮箱已注册
    r = client.post('/send_code', data={'email': 'admin@example.com'})
    assert r.status_code == 200
    payload = r.get_json()
    assert payload['success'] is False
    assert payload['message'] == '邮箱已被注册'


# --------------------------- register ---------------------------

def test_register_success(client):
    email = 'register-ok@example.com'
    # 先发码取真实验证码
    client.post('/send_code', data={'email': email})
    code = _code_for(email)
    assert code is not None

    r = client.post('/register', data={
        'username': 'fresh_user',
        'password': 'secret-pw',
        'email': email,
        'verification_code': code,
        'class': 'Cclass1',
    })
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')

    user = db.get_user_by_username('fresh_user')
    assert user is not None
    assert user['email'] == email
    # 密码以带盐慢哈希存储（不再是无盐 sha256），且能正确校验。
    assert user['password_hash'] != _sha256('secret-pw')
    assert verify_password(user['password_hash'], 'secret-pw')[0] is True


def test_register_duplicate_username(client):
    email = 'dup-user@example.com'
    client.post('/send_code', data={'email': email})
    code = _code_for(email)

    # 已存在用户名 admin（邮箱用全新的，以隔离“用户名已被注册”分支）
    r = client.post('/register', data={
        'username': ADMIN_USERNAME,
        'password': 'secret-pw',
        'email': email,
        'verification_code': code,
        'class': 'Cclass1',
    })
    assert r.status_code == 200
    assert '用户名或邮箱已被注册' in r.get_data(as_text=True)


def test_register_wrong_code(client):
    email = 'register-badcode@example.com'
    client.post('/send_code', data={'email': email})

    r = client.post('/register', data={
        'username': 'another_user',
        'password': 'secret-pw',
        'email': email,
        'verification_code': '000000-not-the-code',
        'class': 'Cclass1',
    })
    assert r.status_code == 200
    assert '验证码错误或已过期' in r.get_data(as_text=True)
    assert db.get_user_by_username('another_user') is None


# --------------------------- change_password ---------------------------

def test_change_password(client, login):
    # admin 已登录，向其邮箱发改密验证码
    login(ADMIN_USERNAME)
    r = client.post('/send_password_code')
    assert r.get_json()['success'] is True
    code = _code_for('admin@example.com')
    assert code is not None

    r = client.post('/change_password', data={
        'code': code,
        'new_password': 'brand-new-pw',
        'confirm_password': 'brand-new-pw',
    })
    assert r.status_code in (301, 302)
    assert '/problems' in r.headers.get('Location', '')

    # 密码已更新（带盐慢哈希，可校验）；验证码记录被删除
    assert verify_password(_password_hash_of(ADMIN_USERNAME), 'brand-new-pw')[0] is True
    assert _code_for('admin@example.com') is None


def test_change_password_mismatch(client, login):
    login(ADMIN_USERNAME)
    r = client.post('/change_password', data={
        'code': '123456',
        'new_password': 'aaaaaa',
        'confirm_password': 'bbbbbb',
    })
    assert r.status_code == 200
    assert '两次输入的密码不一致' in r.get_data(as_text=True)
    # 密码保持原值
    assert _password_hash_of(ADMIN_USERNAME) == _sha256(ADMIN_PASSWORD)


def test_change_password_not_logged_in(client):
    r = client.post('/change_password', data={
        'code': '123456',
        'new_password': 'aaaaaa',
        'confirm_password': 'aaaaaa',
    })
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')


# --------------------------- forgot_password (两步) ---------------------------

def test_forgot_password_flow(client):
    email = 'admin@example.com'  # 已注册邮箱

    # step=email：提交邮箱 → 发码并跳转到 step=verify
    r = client.post('/forgot_password', data={'email': email})
    assert r.status_code in (301, 302)
    loc = r.headers.get('Location', '')
    assert 'step=verify' in loc
    code = _code_for(email)
    assert code is not None

    # step=verify：用真实验证码重置密码 → 跳转到 login
    r = client.post('/forgot_password?step=verify&email=' + email, data={
        'code': code,
        'new_password': 'reset-pw-123',
        'confirm_password': 'reset-pw-123',
    })
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')

    # 密码已重置（带盐慢哈希，可校验）；验证码记录被删除
    assert verify_password(_password_hash_of(ADMIN_USERNAME), 'reset-pw-123')[0] is True
    assert _code_for(email) is None


def test_forgot_password_unregistered_email(client):
    r = client.post('/forgot_password', data={'email': 'nobody@example.com'})
    assert r.status_code in (301, 302)
    # 跳回 forgot_password（email 步），未生成验证码
    assert _code_for('nobody@example.com') is None


def test_forgot_password_verify_mismatch(client):
    email = 'admin@example.com'
    client.post('/forgot_password', data={'email': email})
    code = _code_for(email)

    r = client.post('/forgot_password?step=verify&email=' + email, data={
        'code': code,
        'new_password': 'one-pw',
        'confirm_password': 'other-pw',
    })
    assert r.status_code in (301, 302)
    # 跳回 verify 步，密码未变
    assert 'step=verify' in r.headers.get('Location', '')
    assert _password_hash_of(ADMIN_USERNAME) == _sha256(ADMIN_PASSWORD)
