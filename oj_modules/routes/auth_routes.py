#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

from config import MAIL_PASSWORD, MAIL_PORT, MAIL_SERVER, MAIL_USERNAME
from oj_modules.db_services import (
    create_user,
    get_all_classes_except_admin,
    get_class_by_en,
    get_current_user,
    get_db_connection,
    get_user_by_email,
    get_user_by_username,
)
from oj_modules.security_utils import (
    cooldown_active,
    hash_password,
    rate_limit_hit,
    validate_username,
    verify_password,
)


auth_bp = Blueprint('auth', __name__)

# Redis 客户端（限流）。由 oj.py 的 init_auth_module 注入；为空时限流 fail-open。
_rds = None


def init_auth_module(redis_client):
    global _rds
    _rds = redis_client


def _wants_json_response():
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    accept = (request.headers.get('Accept') or '').lower()
    return 'application/json' in accept and 'text/html' not in accept


def _json_or_error(message, status=400):
    if _wants_json_response():
        return jsonify(success=False, message=message), status
    return render_template('error.html', message=message), status


# ---- 限流参数 ----
_VCODE_COOLDOWN_SECONDS = 60          # 同一邮箱两次发码最小间隔
_VCODE_MAX_PER_HOUR = 5               # 同一邮箱每小时最多发码次数
_VCODE_IP_MAX_PER_HOUR = 60          # 同一 IP 每小时最多发码次数（放宽以兼容机房/NAT）
_VCODE_VERIFY_MAX_ATTEMPTS = 10       # 同一邮箱 10 分钟内验证码错误尝试上限
_VCODE_VERIFY_WINDOW = 600
_LOGIN_MAX_ATTEMPTS = 30             # 同一用户名 15 分钟内登录尝试上限
_LOGIN_WINDOW = 900


def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _update_password_hash(*, user_id=None, email=None, new_hash=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if user_id is not None:
                cursor.execute('UPDATE users SET password_hash=%s WHERE id=%s', (new_hash, user_id))
            else:
                cursor.execute('UPDATE users SET password_hash=%s WHERE email=%s', (new_hash, email))
        conn.commit()
    finally:
        conn.close()


def _check_send_code_allowed(email):
    """发码前的限流：邮箱冷却 + 邮箱每小时上限 + IP 每小时上限。
    返回 (是否允许, 提示语)。"""
    ok, retry = cooldown_active(_rds, f'vcode:cd:{email}', _VCODE_COOLDOWN_SECONDS)
    if not ok:
        return False, f'发送过于频繁，请 {retry} 秒后再试'
    ok, _ = rate_limit_hit(_rds, f'vcode:cnt:{email}', _VCODE_MAX_PER_HOUR, 3600)
    if not ok:
        return False, '今日发送次数过多，请稍后再试'
    ok, _ = rate_limit_hit(_rds, f'vcode:ip:{_client_ip()}', _VCODE_IP_MAX_PER_HOUR, 3600)
    if not ok:
        return False, '操作过于频繁，请稍后再试'
    return True, ''


def _verify_attempt_allowed(email):
    """校验验证码前的错误次数闸：超过上限直接拒绝，防止 6 位码被暴力枚举。"""
    ok, _ = rate_limit_hit(_rds, f'vcode:try:{email}', _VCODE_VERIFY_MAX_ATTEMPTS, _VCODE_VERIFY_WINDOW)
    return ok


def send_verification_code(email, code_type):
    code = ''.join(random.choices('0123456789', k=6))
    expires_at = datetime.now() + timedelta(minutes=5)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = 'REPLACE INTO verification_codes (email, code, expires_at) VALUES (%s, %s, %s)'
            cursor.execute(sql, (email, code, expires_at))
        conn.commit()
    finally:
        conn.close()

    msg = MIMEText(f'您的验证码是：{code}，有效期5分钟。', 'plain', 'utf-8')
    msg['Subject'] = code_type
    msg['From'] = MAIL_USERNAME
    msg['To'] = email

    try:
        with smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT) as server:
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(MAIL_USERNAME, [email], msg.as_string())
        return True
    except Exception as e:
        print(f"邮件发送失败: {e}")
        return False


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        username_ok, username, username_msg = validate_username(username)
        if not username_ok:
            return render_template('login.html', error_message=username_msg, success_message=None)

        # 登录尝试限流（按用户名），减缓离线/在线暴力破解。
        if not rate_limit_hit(_rds, f'login:{username}', _LOGIN_MAX_ATTEMPTS, _LOGIN_WINDOW)[0]:
            return render_template('login.html', error_message="尝试过于频繁，请稍后再试", success_message=None)

        user_record = get_user_by_username(username)
        if user_record:
            ok, needs_rehash = verify_password(user_record.get('password_hash'), password)
            if ok:
                # 历史无盐 sha256 校验通过后，透明升级为带盐慢哈希。
                if needs_rehash:
                    try:
                        _update_password_hash(user_id=user_record['id'], new_hash=hash_password(password))
                    except Exception:
                        pass
                session['username'] = username
                return redirect(url_for('problem_core.problem_list'))
        return render_template('login.html', error_message="用户名或密码错误", success_message=None)

    success_message = request.args.get('success')
    return render_template('login.html', error_message=None, success_message=success_message)


@auth_bp.route('/send_code', methods=['POST'])
def send_verification():
    email = request.form.get('email', '').strip()
    if not email:
        return jsonify(success=False, message="邮箱不能为空")

    if get_user_by_email(email):
        return jsonify(success=False, message="邮箱已被注册")

    allowed, reason = _check_send_code_allowed(email)
    if not allowed:
        return jsonify(success=False, message=reason)

    if send_verification_code(email, "注册验证码"):
        return jsonify(success=True, message="验证码已发送")
    return jsonify(success=False, message="验证码发送失败")


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    public_classes = get_all_classes_except_admin()
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()
        email = (request.form.get('email') or '').strip()
        code = (request.form.get('verification_code') or '').strip()
        user_class = get_class_by_en(request.form.get('class'))

        if user_class and user_class.get('class_en') == 'Cadmin':
            user_class = None

        if not all([username, password, email, code, user_class]):
            return render_template('register.html', error_message="所有字段不能为空", classes=public_classes)

        username_ok, username, username_msg = validate_username(username)
        if not username_ok:
            return render_template('register.html', error_message=username_msg, classes=public_classes)

        if not _verify_attempt_allowed(email):
            return render_template('register.html', error_message="验证次数过多，请稍后再试", classes=public_classes)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "SELECT * FROM verification_codes WHERE email = %s"
                cursor.execute(sql, (email,))
                record = cursor.fetchone()
        finally:
            conn.close()

        if not record or record['code'] != code or datetime.now() > record['expires_at']:
            return render_template('register.html', error_message="验证码错误或已过期", classes=public_classes)

        if get_user_by_username(username) or get_user_by_email(email):
            return render_template('register.html', error_message="用户名或邮箱已被注册", classes=public_classes)

        create_user(username, hash_password(password), email, user_class)
        return redirect(url_for('auth.login', success="注册成功，请登录"))

    return render_template('register.html', classes=public_classes)


@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    step = request.args.get('step', 'email')

    if request.method == 'POST':
        if step == 'email':
            email = request.form.get('email').strip()

            if not email:
                flash('邮箱不能为空', 'danger')
                return redirect(url_for('auth.forgot_password'))

            user = get_user_by_email(email)
            # 不区分「邮箱未注册」与「已发送」，避免账号枚举；仅对已注册邮箱真正发码。
            if user:
                allowed, reason = _check_send_code_allowed(email)
                if not allowed:
                    flash(reason, 'danger')
                    return redirect(url_for('auth.forgot_password'))
                send_verification_code(email, '重置密码验证码')

            flash('如果该邮箱已注册，验证码已发送，请检查邮箱', 'success')
            return redirect(url_for('auth.forgot_password', step='verify', email=email))

        if step == 'verify':
            email = request.args.get('email', '').strip()

            code = request.form.get('code').strip()
            new_password = request.form.get('new_password').strip()
            confirm_password = request.form.get('confirm_password').strip()

            if new_password != confirm_password:
                flash('两次输入的密码不一致', 'danger')
                return redirect(url_for('auth.forgot_password', step='verify', email=email))

            if not _verify_attempt_allowed(email):
                flash('验证次数过多，请稍后再试', 'danger')
                return redirect(url_for('auth.forgot_password', step='verify', email=email))

            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = "SELECT * FROM verification_codes WHERE email=%s"
                    cursor.execute(sql, (email,))
                    record = cursor.fetchone()
            finally:
                conn.close()

            if not record or record['code'] != code or datetime.now() > record['expires_at']:
                flash('验证码错误或已过期', 'danger')
                return redirect(url_for('auth.forgot_password', step='verify', email=email))

            _update_password_hash(email=email, new_hash=hash_password(new_password))

            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = 'DELETE FROM verification_codes WHERE email = %s'
                    cursor.execute(sql, (email,))
                conn.commit()
            finally:
                conn.close()

            flash('密码重置成功，请重新登录', 'success')
            return redirect(url_for('auth.login'))

    return render_template('forgot_password.html', step=step, email=request.args.get('email'))


@auth_bp.route('/send_password_code', methods=['POST'])
def send_password_code():
    if 'username' not in session:
        return jsonify(success=False, message="请先登录"), 401

    user = get_current_user()
    if not user:
        return jsonify(success=False, message="用户不存在"), 404

    allowed, reason = _check_send_code_allowed(user['email'])
    if not allowed:
        return jsonify(success=False, message=reason), 429

    if not send_verification_code(user['email'], "重置密码验证码"):
        return jsonify(success=False, message="验证码发送失败"), 500

    return jsonify(success=True, message="验证码已发送")


@auth_bp.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        if _wants_json_response():
            return jsonify(success=False, message="请先登录"), 401
        return redirect(url_for('auth.login'))

    user = get_current_user()
    if not user:
        return _json_or_error("用户不存在", 404)
    code = request.form.get('code', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if new_password != confirm_password:
        return _json_or_error("两次输入的密码不一致", 400)

    if not _verify_attempt_allowed(user['email']):
        return _json_or_error("验证次数过多，请稍后再试", 429)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM verification_codes WHERE email=%s"
            cursor.execute(sql, (user['email'],))
            record = cursor.fetchone()
    finally:
        conn.close()

    if not record or record['code'] != code or datetime.now() > record['expires_at']:
        return _json_or_error("验证码错误或已过期", 400)

    _update_password_hash(user_id=user['id'], new_hash=hash_password(new_password))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = 'DELETE FROM verification_codes WHERE email = %s'
            cursor.execute(sql, (user['email'],))
        conn.commit()
    finally:
        conn.close()

    if _wants_json_response():
        return jsonify(success=True, message="密码修改成功")
    return redirect(url_for('problem_core.problem_list', success="密码修改成功"))


@auth_bp.post('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('auth.login'))
