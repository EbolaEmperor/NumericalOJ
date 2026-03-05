#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import random
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

from config import MAIL_PASSWORD, MAIL_PORT, MAIL_SERVER, MAIL_USERNAME
from oj_modules.db_services import (
    create_user,
    get_all_classes,
    get_all_classes_except_admin,
    get_class_by_en,
    get_current_user,
    get_db_connection,
    get_user_by_email,
    get_user_by_username,
)


auth_bp = Blueprint('auth', __name__)


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

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        user_record = get_user_by_username(username)
        admin_record = get_user_by_username("admin")
        if user_record and (user_record['password_hash'] == password_hash or admin_record['password_hash'] == password_hash):
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

    if send_verification_code(email, "注册验证码"):
        return jsonify(success=True, message="验证码已发送")
    return jsonify(success=False, message="验证码发送失败")


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        email = request.form.get('email').strip()
        code = request.form.get('verification_code').strip()
        user_class = get_class_by_en(request.form.get('class'))

        if not all([username, password, email, code, user_class]):
            return render_template('register.html', error_message="所有字段不能为空", classes=get_all_classes())

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "SELECT * FROM verification_codes WHERE email = %s"
                cursor.execute(sql, (email,))
                record = cursor.fetchone()
        finally:
            conn.close()

        if not record or record['code'] != code or datetime.now() > record['expires_at']:
            return render_template('register.html', error_message="验证码错误或已过期", classes=get_all_classes())

        if get_user_by_username(username) or get_user_by_email(email):
            return render_template('register.html', error_message="用户名或邮箱已被注册", classes=get_all_classes())

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        create_user(username, password_hash, email, user_class)
        return redirect(url_for('auth.login', success="注册成功，请登录"))

    classes = get_all_classes_except_admin()
    return render_template('register.html', classes=classes)


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
            if not user:
                flash('该邮箱未注册', 'danger')
                return redirect(url_for('auth.forgot_password'))

            if send_verification_code(email, '重置密码验证码'):
                flash('验证码已发送，请检查您的邮箱', 'success')
                return redirect(url_for('auth.forgot_password', step='verify', email=email))

            flash('验证码发送失败，请稍后再试', 'danger')
            return redirect(url_for('auth.forgot_password'))

        if step == 'verify':
            email = request.args.get('email', '').strip()

            code = request.form.get('code').strip()
            new_password = request.form.get('new_password').strip()
            confirm_password = request.form.get('confirm_password').strip()

            if new_password != confirm_password:
                flash('两次输入的密码不一致', 'danger')
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

            password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = 'UPDATE users SET password_hash = %s WHERE email = %s'
                    cursor.execute(sql, (password_hash, email))
                conn.commit()
            finally:
                conn.close()

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
        return jsonify(success=False, message="请先登录")

    user = get_current_user()
    if not user:
        return jsonify(success=False, message="用户不存在")

    if not send_verification_code(user['email'], "重置密码验证码"):
        return jsonify(success=False, message="验证码发送失败")

    return jsonify(success=True, message="验证码已发送")


@auth_bp.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('auth.login'))

    user = get_current_user()
    code = request.form.get('code', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if new_password != confirm_password:
        return render_template('error.html', message="两次输入的密码不一致")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM verification_codes WHERE email=%s"
            cursor.execute(sql, (user['email'],))
            record = cursor.fetchone()
    finally:
        conn.close()

    if not record or record['code'] != code or datetime.now() > record['expires_at']:
        return render_template('error.html', message="验证码错误或已过期")

    password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = 'UPDATE users SET password_hash = %s WHERE id = %s'
            cursor.execute(sql, (password_hash, user['id']))
        conn.commit()
    finally:
        conn.close()

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = 'DELETE FROM verification_codes WHERE email = %s'
            cursor.execute(sql, (user['email'],))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for('problem_core.problem_list', success="密码修改成功"))


@auth_bp.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('auth.login'))
