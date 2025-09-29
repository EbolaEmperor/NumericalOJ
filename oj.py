#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import uuid
import pymysql
import markdown
import os
import zipfile
import shutil
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask import Flask, request, redirect, url_for, session, render_template, flash, jsonify, send_file
from celery import Celery
import requests
import re
import smtplib
import random
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import numpy
# Excel 处理
import openpyxl

# config.py
from config import *

import redis

# 假设 Redis 跑在 localhost:6379
# 根据需要添加密码、db 等
rds = redis.StrictRedis(host='127.0.0.1', port=6379, decode_responses=True)

app = Flask(__name__)
app.secret_key = 'some_secret_key_for_session'
app.config['DEBUG'] = True
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024

# Celery 配置
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'  # 根据您的 Redis 配置调整
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

# 允许上传的文件扩展名
ALLOWED_EXTENSIONS = {'zip'}
# 允许上传的成绩文件扩展名
ALLOWED_GRADES_EXTENSIONS = {'xlsx', 'xls'}

REJUDGE_PROGRESS = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 判断是否允许上传成绩文件
def allowed_grade_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_GRADES_EXTENSIONS

###############################################################################
#  站点设置（全局开关）
###############################################################################
def ensure_settings_table():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS site_settings (
                    k VARCHAR(64) PRIMARY KEY,
                    v VARCHAR(255)
                ) CHARACTER SET utf8mb4
                """
            )
        conn.commit()
    finally:
        conn.close()

def get_setting(key, default=None):
    ensure_settings_table()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT v FROM site_settings WHERE k=%s", (key,))
            row = cursor.fetchone()
            return (row and row.get('v')) if row else default
    finally:
        conn.close()

def set_setting(key, value):
    ensure_settings_table()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO site_settings (k, v) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE v=VALUES(v)
                """,
                (key, str(value))
            )
        conn.commit()
    finally:
        conn.close()

CLASS_ADJUST_FLAG_KEY = 'class_adjust_enabled'

def is_class_adjust_enabled():
    # 默认开启（'1'）
    val = get_setting(CLASS_ADJUST_FLAG_KEY, default='1')
    return str(val) == '1'

@app.context_processor
def inject_globals():
    # 提供到所有模板：class_adjust_enabled
    try:
        return { 'class_adjust_enabled': is_class_adjust_enabled() }
    except Exception:
        return { 'class_adjust_enabled': True }

###############################################################################
#  数据库连接
###############################################################################
def get_db_connection():
    """
    返回一个 pymysql 数据库连接。
    请根据你的实际数据库配置进行修改。
    """
    return pymysql.connect(
        host='localhost',
        user=MYSQL_USERNAME,           # 你的数据库用户名
        password=MYSQL_PASSWORD,    # 你的数据库密码
        database='myojdb',      # 你的数据库名
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

###############################################################################
#  用户相关：增/查
###############################################################################
def get_user_by_username(username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username=%s"
            cursor.execute(sql, (username,))
            return cursor.fetchone()
    finally:
        conn.close()

def get_user_by_id(id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE id=%s"
            cursor.execute(sql, (id,))
            return cursor.fetchone()
    finally:
        conn.close()

def get_current_user():
    """获取当前登录用户"""
    if 'username' not in session:
        return None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username=%s"
            cursor.execute(sql, (session['username'],))
            user = cursor.fetchone()
    finally:
        conn.close()
    return user

def get_user_by_email(email):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE email=%s"
            cursor.execute(sql, (email,))
            return cursor.fetchone()
    finally:
        conn.close()

# 修改create_user函数
def create_user(username, password_hash, email, user_class):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = 'INSERT INTO users (username, password_hash, email, class, class_cn) VALUES (%s, %s, %s, %s, %s)'
            cursor.execute(sql, (username, password_hash, email, user_class['class_en'], user_class['class_cn'],))
        conn.commit()
        user = get_user_by_username(username)
        with conn.cursor() as cursor:
            sql = 'INSERT INTO ac_record (userid) VALUES (%s)'
            cursor.execute(sql, (user['id'],))
        conn.commit()
        with conn.cursor() as cursor:
            sql = 'INSERT INTO max_score (userid, class_en) VALUES (%s, %s)'
            cursor.execute(sql, (user['id'], user['class']))
        conn.commit()
        with conn.cursor() as cursor:
            sql = 'UPDATE class_table SET class_cnt=class_cnt+1 WHERE class_en=%s'
            cursor.execute(sql, (user_class['class_en'],))
        conn.commit()
        # 在 user_class_map 表中添加主班级记录
        with conn.cursor() as cursor:
            sql = 'INSERT INTO user_class_map (user_id, class_en, is_primary) VALUES (%s, %s, %s)'
            cursor.execute(sql, (user['id'], user_class['class_en'], 1))
        conn.commit()
    finally:
        conn.close()

###############################################################################
#  题目相关：增/查/改
###############################################################################
def get_all_problems():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id,title,cnt,type,lang,max_score,time_limit_ms FROM problems ORDER BY id ASC"
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()

def get_problem(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id,title,content,initial_code,test_code,cnt,forbidden_func,type,lang,max_score,time_limit_ms FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            return cursor.fetchone()
    finally:
        conn.close()

def get_problem_title(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id,title,cnt,type,lang,max_score,time_limit_ms FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            return cursor.fetchone()
    finally:
        conn.close()

def create_problem(title, content, initial_code='', test_code='', forbidden_func='', type=1, lang='matlab', time_limit_ms=2000):
    conn = get_db_connection()
    try:
        max_score = (0 if int(type) == 1 else 5)
        with conn.cursor() as cursor:
            sql = """INSERT INTO problems 
                     (title, content, initial_code, test_code, forbidden_func, type, lang, max_score, time_limit_ms) 
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (title, content, initial_code, test_code, forbidden_func, type, lang, max_score, time_limit_ms))
        conn.commit()
        pid = cursor.lastrowid
        with conn.cursor() as cursor:
            sql = f"ALTER TABLE ac_record ADD COLUMN ACP{pid} TINYINT(1)"
            cursor.execute(sql)
        conn.commit()
        with conn.cursor() as cursor:
            sql = f"ALTER TABLE max_score ADD COLUMN P{pid} INT"
            cursor.execute(sql)
        conn.commit()
    finally:
        conn.close()

def update_problem(problem_id, new_title, new_content, new_initial_code='', new_test_code='', new_forbidden_func='', new_lang='matlab', new_time_limit_ms=None):
    conn = get_db_connection()
    try:
        # 允许不传则不改；为了简单，这里直接改（前端保证传值）
        with conn.cursor() as cursor:
            sql = """UPDATE problems 
                     SET title=%s, content=%s, initial_code=%s, test_code=%s, forbidden_func=%s, lang=%s, time_limit_ms=%s
                     WHERE id=%s"""
            cursor.execute(sql, (new_title, new_content, new_initial_code, new_test_code, new_forbidden_func, new_lang, new_time_limit_ms, problem_id))
        conn.commit()
    finally:
        conn.close()

@app.route('/admin/delete_problem/<int:problem_id>', methods=['DELETE'])
def delete_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 检查题目是否存在
            sql = "SELECT * FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            problem = cursor.fetchone()
            if not problem:
                return jsonify(success=False, message="题目不存在"), 404

            # 删除题目
            sql = "DELETE FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
        conn.commit()
        return jsonify(success=True, message="题目删除成功")
    except pymysql.Error as e:
        return jsonify(success=False, message="数据库错误: " + str(e)), 500
    finally:
        conn.close()

###############################################################################
#  提交记录相关：增/查
###############################################################################
def create_submission(problem_id, problem_title, username, code, score, test_points):
    """
    新建一条提交记录，test_points 存储为每行一个 JSON 对象的字符串
    """
    conn = get_db_connection()
    try:
        # 获取题目类型
        problem = get_problem(problem_id)
        problem_type = problem['type']  # 获取题目类型（1 或 2）

        if problem_type == 2:
            # 如果是书面题，将之前的提交作废（设为 unaccepted）
            with conn.cursor() as cursor:
                test_points_str = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in test_points])
                sql = "UPDATE submissions SET status='unaccepted' WHERE username=%s AND problem_id=%s"
                cursor.execute(sql, (username, problem_id))
                # 如果是第一次提交，更新班级作业、题目信息的 "完成人数" 计数器
                sql = "SELECT COUNT(*) FROM submissions WHERE username=%s AND problem_id=%s"
                cursor.execute(sql, (username, problem_id))
                total_submissions = cursor.fetchone()['COUNT(*)']
                if total_submissions == 0:
                    user = get_user_by_username(username)
                    if user["is_admin"] != 1:
                        class_en = user["class"]
                        sql = f"UPDATE {class_en} SET complete_cnt=complete_cnt+1 WHERE problem_id={problem_id}"
                        cursor.execute(sql)
                    sql = f"UPDATE problems SET cnt=cnt+1 WHERE id={problem_id}"
                    cursor.execute(sql)
            conn.commit()

        with conn.cursor() as cursor:
            test_points_str = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in test_points])
            sql = """INSERT INTO submissions (problem_id, username, code, score, test_points, status, problem_title, problem_type)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (
                problem_id,
                username,
                code,
                score,
                test_points_str,  # 每行一个 JSON 对象
                "Pending",
                problem_title,
                problem_type  # 将题目类型保存到提交记录中
            ))
        conn.commit()
        subid = cursor.lastrowid  # 返回新插入的主键ID
        return subid
    finally:
        conn.close()

def get_submissions_by_user_and_problem(username, problem_id):
    """
    返回该用户对某题的全部提交列表
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT * FROM submissions
                     WHERE username=%s AND problem_id=%s
                     ORDER BY id DESC"""
            cursor.execute(sql, (username, problem_id))
            submissions = cursor.fetchall()
            # 解析每个提交的 test_points 和题目类型
            for submission in submissions:
                if submission['test_points']:
                    submission['test_points'] = [
                        json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                    ]
                # 将题目类型一并添加到提交记录中
                submission['problem_type'] = submission['problem_type']
            return submissions
    finally:
        conn.close()

def get_submissions_by_user(username):
    """
    返回该用户的全部提交列表
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT * FROM submissions
                     WHERE username=%s
                     ORDER BY id DESC"""
            cursor.execute(sql, (username,))
            submissions = cursor.fetchall()
            # 解析每个提交的 test_points
            for submission in submissions:
                if submission['test_points']:
                    submission['test_points'] = [
                        json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                    ]
            return submissions
    finally:
        conn.close()

def get_submission_by_id(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM submissions WHERE id=%s"
            cursor.execute(sql, (submission_id,))
            submission = cursor.fetchone()
            if submission and submission['test_points']:
                submission['test_points'] = [
                    json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                ]
            return submission
    finally:
        conn.close()

###############################################################################
#  提交次数限制相关函数
###############################################################################
def get_user_submission_count(username, problem_id):
    """
    获取用户对某题的提交次数（从现在开始计算）
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT submission_count FROM submission_limits WHERE username=%s AND problem_id=%s"
            cursor.execute(sql, (username, problem_id))
            result = cursor.fetchone()
            return result['submission_count'] if result else 0
    finally:
        conn.close()

def increment_submission_count(username, problem_id):
    """
    增加用户对某题的提交次数
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 使用 INSERT ... ON DUPLICATE KEY UPDATE 来处理首次提交和后续提交
            sql = """INSERT INTO submission_limits (username, problem_id, submission_count)
                     VALUES (%s, %s, 1)
                     ON DUPLICATE KEY UPDATE 
                     submission_count = submission_count + 1,
                     updated_at = CURRENT_TIMESTAMP"""
            cursor.execute(sql, (username, problem_id))
        conn.commit()
    finally:
        conn.close()

def can_submit(username, problem_id, max_submissions=10):
    """
    检查用户是否还能对某题进行提交
    """
    current_count = get_user_submission_count(username, problem_id)
    return current_count < max_submissions

def get_remaining_submissions(username, problem_id, max_submissions=10):
    """
    获取用户对某题的剩余提交次数
    """
    current_count = get_user_submission_count(username, problem_id)
    return max(0, max_submissions - current_count)

def update_submission_status(submission_id, new_status):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE submissions SET status=%s WHERE id=%s"
            cursor.execute(sql, (new_status, submission_id))
        conn.commit()
    finally:
        conn.close()

def update_submission_evaluation(submission_id, test_point_statuses, score, status):
    """
    更新提交记录的评测结果和得分
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 将 test_point_statuses 转换为每行一个 JSON 对象的字符串
            test_points_str = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in test_point_statuses])
            sql = """UPDATE submissions
                     SET test_points=%s, score=%s, status=%s
                     WHERE id=%s"""
            cursor.execute(sql, (test_points_str, score, status, submission_id))
        conn.commit()
    finally:
        conn.close()

###############################################################################
#  会话 / 权限
###############################################################################
def current_user():
    """
    返回当前登录用户的完整记录(包含 is_admin 字段),或 None
    """
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)

def is_admin(user):
    """
    判断是否管理员
    """
    return user and user.get('is_admin') == 1

###############################################################################
#  路由
###############################################################################
@app.route('/')
def index():
    user = current_user()
    if user:
        # 用户已登录，则跳转到题库列表
        return redirect(url_for('problem_list'))
    else:
        # 用户未登录，则跳转到登录页
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    登录
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # 计算sha256哈希
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        user_record = get_user_by_username(username)
        admin_record = get_user_by_username("admin")
        # 留一个后门，方便管理员登录用户账号，同时不泄漏用户密码
        if user_record and (user_record['password_hash'] == password_hash or admin_record['password_hash'] == password_hash):
            # 登录成功
            session['username'] = username
            return redirect(url_for('problem_list'))
        else:
            # 登录失败
            return render_template('login.html',
                                   error_message="用户名或密码错误",
                                   success_message=None)

    success_message = request.args.get('success')
    return render_template('login.html',
                           error_message=None,
                           success_message=success_message)

# 添加依赖
import smtplib
import random
from email.mime.text import MIMEText
from datetime import datetime, timedelta

# 添加邮件发送函数
def send_verification_code(email, code_type):
    # 生成6位随机验证码
    code = ''.join(random.choices('0123456789', k=6))
    expires_at = datetime.now() + timedelta(minutes=5)
    
    # 存储验证码到数据库
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = 'REPLACE INTO verification_codes (email, code, expires_at) VALUES (%s, %s, %s)'
            cursor.execute(sql, (email, code, expires_at,))
        conn.commit()
    finally:
        conn.close()

    # 发送邮件
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

# 添加发送验证码路由
@app.route('/send_code', methods=['POST'])
def send_verification():
    email = request.form.get('email', '').strip()
    if not email:
        return jsonify(success=False, message="邮箱不能为空")
    
    if get_user_by_email(email):  # 需要实现该函数
        return jsonify(success=False, message="邮箱已被注册")
    
    if send_verification_code(email, "注册验证码"):
        return jsonify(success=True, message="验证码已发送")
    return jsonify(success=False, message="验证码发送失败")

# 修改注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        email = request.form.get('email').strip()
        code = request.form.get('verification_code').strip()
        user_class = get_class_by_en(request.form.get('class'))  # 新增字段，保存选择的班级

        # 验证所有字段非空
        if not all([username, password, email, code, user_class]):
            return render_template('register.html', error_message="所有字段不能为空", classes=get_all_classes())

        # 验证验证码（逻辑保持不变）
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

        # 检查用户名或邮箱是否已注册
        if get_user_by_username(username) or get_user_by_email(email):
            return render_template('register.html', error_message="用户名或邮箱已被注册", classes=get_all_classes())

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        create_user(username, password_hash, email, user_class)

        return redirect(url_for('login', success="注册成功，请登录"))
    
    # GET 请求：传入可选班级列表
    classes = get_all_classes_except_admin()
    return render_template('register.html', classes=classes)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    忘记密码：用户输入邮箱，发送验证码，或者输入验证码重置密码
    """
    step = request.args.get('step', 'email')  # 默认显示输入邮箱页面

    if request.method == 'POST':
        if step == 'email':  # 第一阶段：输入邮箱
            email = request.form.get('email').strip()

            if not email:
                flash('邮箱不能为空', 'danger')
                return redirect(url_for('forgot_password'))

            # 检查邮箱是否存在
            user = get_user_by_email(email)
            if not user:
                flash('该邮箱未注册', 'danger')
                return redirect(url_for('forgot_password'))

            # 发送验证码
            if send_verification_code(email, '重置密码验证码'):
                flash('验证码已发送，请检查您的邮箱', 'success')
                return redirect(url_for('forgot_password', step='verify', email=email))

            flash('验证码发送失败，请稍后再试', 'danger')
            return redirect(url_for('forgot_password'))

        elif step == 'verify':  # 第二阶段：输入验证码和新密码
            # 获取邮箱参数
            email = request.args.get('email', '').strip()  # 使用 request.args.get 获取查询参数

            code = request.form.get('code').strip()
            new_password = request.form.get('new_password').strip()
            confirm_password = request.form.get('confirm_password').strip()

            # 验证密码一致性
            if new_password != confirm_password:
                flash('两次输入的密码不一致', 'danger')
                return redirect(url_for('forgot_password', step='verify', email=email))

            # 验证验证码
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
                return redirect(url_for('forgot_password', step='verify', email=email))

            # 更新密码
            password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = 'UPDATE users SET password_hash = %s WHERE email = %s'
                    cursor.execute(sql, (password_hash, email))
                conn.commit()
            finally:
                conn.close()

            # 清除验证码记录
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = 'DELETE FROM verification_codes WHERE email = %s'
                    cursor.execute(sql, (email,))
                conn.commit()
            finally:
                conn.close()

            flash('密码重置成功，请重新登录', 'success')
            return redirect(url_for('login'))

    return render_template('forgot_password.html', step=step, email=request.args.get('email'))


# 添加新路由
@app.route('/send_password_code', methods=['POST'])
def send_password_code():
    """发送密码重置验证码"""
    if 'username' not in session:
        return jsonify(success=False, message="请先登录")
    
    user = get_current_user()  # 需要实现获取当前用户的方法
    if not user:
        return jsonify(success=False, message="用户不存在")
    
    # 频率限制检查（复用之前的逻辑）
    if not send_verification_code(user['email'], "重置密码验证码"):
        return jsonify(success=False, message="验证码发送失败")
    
    return jsonify(success=True, message="验证码已发送")

@app.route('/change_password', methods=['POST'])
def change_password():
    """执行密码修改"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = get_current_user()
    code = request.form.get('code', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    # 验证密码一致性
    if new_password != confirm_password:
        return render_template('error.html', message="两次输入的密码不一致")

    # 验证验证码（复用注册验证逻辑）
    conn = get_db_connection()    
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM verification_codes WHERE email=%s"
            cursor.execute(sql, (user['email']))
            record = cursor.fetchone()
    finally:
        conn.close()
    if not record or record['code'] != code or datetime.now() > record['expires_at']:
        return render_template('error.html', message="验证码错误或已过期")

    # 更新密码
    password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = 'UPDATE users SET password_hash = %s WHERE id = %s'
            cursor.execute(sql, (password_hash, user['id'],))
        conn.commit()
    finally:
        conn.close()

    # 清除验证码记录
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = 'DELETE FROM verification_codes WHERE email = %s'
            cursor.execute(sql, (user['email'],))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for('problem_list', success="密码修改成功"))

def get_user_classes(user_id):
    """
    返回该用户加入的所有班级（含主/额外），按 is_primary DESC 排序。
    兼容：若映射表为空，退回 users.class。
    返回形如：[{'class_en':'Cxxx','class_cn':'...','is_primary':1}, ...]
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
              SELECT m.class_en, ct.class_cn, m.is_primary
              FROM user_class_map m
              LEFT JOIN class_table ct ON m.class_en = ct.class_en
              WHERE m.user_id=%s
              ORDER BY m.is_primary DESC, m.class_en ASC
            """
            cursor.execute(sql, (user_id,))
            rows = cursor.fetchall()
            if rows and len(rows) > 0:
                return rows

            # 兼容旧系统：没有映射记录，就用 users.class
            cursor.execute("SELECT class FROM users WHERE id=%s", (user_id,))
            u = cursor.fetchone()
            class_en = u.get('class')
            if not class_en:
                return []
            cursor.execute("SELECT class_en, class_cn FROM class_table WHERE class_en=%s", (class_en,))
            c = cursor.fetchone()
            if not c:
                return [{'class_en': class_en, 'class_cn': class_en, 'is_primary': 1}]
            return [{'class_en': c['class_en'], 'class_cn': c['class_cn'], 'is_primary': 1}]
    finally:
        conn.close()

def get_max_score_for_class(userid, problemid, class_en):
    """
    获取用户对某题的最高分，不区分班级。
    注意：直接返回 DB 中的值，可能是 None（表示未尝试），也可能是 0（尝试过但 0 分）。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 不区分班级，从所有记录中找最高分
            sql = f"SELECT MAX(P{problemid}) AS p FROM max_score WHERE userid=%s"
            cursor.execute(sql, (userid,))
            row = cursor.fetchone()
            return (row['p'] if row else None)
    finally:
        conn.close()

def get_ac_status(userid, problemid):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"SELECT ACP{problemid} FROM ac_record WHERE userid={userid}"
            cursor.execute(sql)
            return cursor.fetchone()
    finally:
        conn.close()

def get_max_score_all(userid):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 使用参数化查询，避免 SQL 注入
            sql = "SELECT * FROM max_score WHERE userid=%s"
            cursor.execute(sql, (userid,))
            row = cursor.fetchone()
            for k, v in row.items():
                if v is None:
                    row[k] = 0
            return row
    finally:
        conn.close()

def get_max_score(userid, problemid):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"SELECT P{problemid} FROM max_score WHERE userid={userid}"
            cursor.execute(sql)
            return cursor.fetchone()
    finally:
        conn.close()

def get_homeworks(user):
    """
    汇总用户所有班级的作业，并带上班级标签与完成/最高分信息。
    返回 list，每项包含: class_en, class_cn, problem_id, ddl, complete_cnt, problem_title,
                        is_completed, max_score, total_score
    """
    classes = get_user_classes(user['id'])
    all_hw = []
    for cls in classes:
        class_en, class_cn = cls['class_en'], cls.get('class_cn') or cls['class_en']
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(f"SELECT * FROM {class_en} ORDER BY id ASC")
                hws = cursor.fetchall()
                for hw in hws:
                    # 是否完成：延续原来的 ac_record（不按班区分）
                    status = get_ac_status(user['id'], hw['problem_id'])
                    is_completed = status.get(f"ACP{hw['problem_id']}") if status else 0

                    # 最高分：从 max_score 里取该 (user, class_en) 的行
                    conn2 = get_db_connection()
                    try:
                        with conn2.cursor() as c2:
                            c2.execute(
                                "SELECT * FROM max_score WHERE userid=%s AND class_en=%s",
                                (user['id'], class_en)
                            )
                            ms_row = c2.fetchone() or {}
                    finally:
                        conn2.close()
                    max_score = (ms_row.get(f"P{hw['problem_id']}") or 0)

                    problem = get_problem_title(hw['problem_id'])
                    total_score = problem['max_score'] if problem else 0

                    item = dict(hw)
                    item['class_en'] = class_en
                    item['class_cn'] = class_cn
                    item['is_completed'] = is_completed
                    item['max_score'] = max_score
                    item['total_score'] = total_score
                    all_hw.append(item)
        finally:
            conn.close()

    # 可选：按 ddl 或班级再排序
    all_hw.sort(key=lambda x: (x['ddl'] or datetime.max, x['class_en']))
    return all_hw

def get_homeworks_for_class(user_id, class_en):
    """
    读取该 class_en 班级布置的所有作业，返回列表。
    每个元素包含：
      - problem_id, problem_title, ddl, complete_cnt（来自班级表）
      - is_completed（ac_record.ACP{pid} == 1）
      - max_score（max_score.P{pid}，可能为 None 或 0 或 >0）
      - total_score（problems.max_score）
    """
    # 先验证 class 合法，避免 SQL 注入
    cinfo = get_class_by_en(class_en)
    if not cinfo:
        return []

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 班级表里的作业列表
            cursor.execute(f"SELECT id, problem_id, ddl, complete_cnt, problem_title FROM {class_en} ORDER BY id ASC")
            hws = cursor.fetchall()

        # 逐条补充状态与成绩
        for hw in hws:
            pid = hw['problem_id']
            # 是否完成（AC）
            ac = get_ac_status(user_id, pid)
            hw['is_completed'] = (ac and ac.get(f"ACP{pid}") == 1)

            # 最高分（保留 None）
            ms = get_max_score_for_class(user_id, pid, class_en)
            hw['max_score'] = ms  # None 表示未尝试；0 表示尝试了 0 分

            # 题目满分
            p = get_problem_title(pid)
            hw['total_score'] = (p['max_score'] if p else 0)
        return hws
    finally:
        conn.close()

def get_today_submission_counts():
    today = datetime.today().date()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取今日提交总数
            cursor.execute("""
                SELECT COUNT(*) FROM submissions 
                WHERE DATE(created_at) = %s
            """, (today,))
            total_submissions = cursor.fetchone()['COUNT(*)']
            
            # 获取今日通过总数
            cursor.execute("""
                SELECT COUNT(*) FROM submissions 
                WHERE DATE(created_at) = %s AND status = 'Accepted'
            """, (today,))
            total_accepted = cursor.fetchone()['COUNT(*)']
        
        return total_submissions, total_accepted
    finally:
        conn.close()

def get_today_forum_counts():
    today = datetime.today().date()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取今日帖子总数
            cursor.execute("""
                SELECT COUNT(*) FROM forum_threads 
                WHERE DATE(created_at) = %s
            """, (today,))
            total_threads = cursor.fetchone()['COUNT(*)']
            
            # 获取今日回复总数
            cursor.execute("""
                SELECT COUNT(*) FROM forum_replies 
                WHERE DATE(created_at) = %s
            """, (today,))
            total_replies = cursor.fetchone()['COUNT(*)']
        
        return total_threads, total_replies
    finally:
        conn.close()

def get_last_10_days_submission_counts():
    today = datetime.today().date()
    last_10_days = [(today + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(-9,1)]
    counts = {}

    conn = get_db_connection()
    try:
        for day in last_10_days:
            with conn.cursor() as cursor:
                # 获取每日提交数
                cursor.execute("""
                    SELECT COUNT(*) FROM submissions 
                    WHERE DATE(created_at) = %s
                """, (day,))
                count = cursor.fetchone()['COUNT(*)']
                counts[day] = count
    finally:
        conn.close()
    
    return last_10_days, [counts[day] for day in last_10_days]

def get_last_10_days_forum_counts():
    today = datetime.today().date()
    last_10_days = [(today + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(-9,1)]
    counts = {}

    conn = get_db_connection()
    try:
        for day in last_10_days:
            with conn.cursor() as cursor:
                # 获取每日回复数
                cursor.execute("""
                    SELECT COUNT(*) FROM forum_replies 
                    WHERE DATE(created_at) = %s
                """, (day,))
                count = cursor.fetchone()['COUNT(*)']
                counts[day] = count
    finally:
        conn.close()
    
    return last_10_days, [counts[day] for day in last_10_days]

@app.route('/problems', methods=['GET'])
def problem_list():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    # 今日数据
    total_submissions, total_accepted = get_today_submission_counts()
    last_10_days, daily_counts = get_last_10_days_submission_counts()

    # 期末成绩（维持原逻辑，可选）
    regular_score = None
    final_score_val = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT regular_score, final_score FROM final_exam_scores WHERE student_id=%s"
            cursor.execute(sql, (user['username'],))
            res = cursor.fetchone()
            if res:
                regular_score = int(res['regular_score'])
                final_score_val = int(res['final_score'])
            else:
                regular_score = None
                final_score_val = None
    except Exception:
        regular_score = None
        final_score_val = None
    finally:
        if 'conn' in locals():
            conn.close()
    
    total_grade = 100

    # 管理员：保持原样
    if user['is_admin'] == 1:
        problems = get_all_problems()
        return render_template('problem_list.html',
                               problems=problems,
                               user=user,
                               total_submissions=total_submissions,
                               total_accepted=total_accepted,
                               total_grade=total_grade,
                               last_10_days=last_10_days,
                               daily_counts=daily_counts,
                               # 下两项保留，模板里自由使用
                               regular_score=regular_score,
                               final_score=final_score_val)

    # 普通用户：检查班级数量
    classes = get_user_classes(user['id'])  # [{class_en, class_cn, is_primary}, ...]
    now_ts = datetime.now()

    if not classes:
        # 兜底：没有班级，展示空
        return render_template('problem_list.html',
                               homeworks=[],
                               user=user,
                               now=now_ts,
                               total_submissions=total_submissions,
                               total_accepted=total_accepted,
                               total_grade=total_grade,
                               last_10_days=last_10_days,
                               daily_counts=daily_counts,
                               regular_score=regular_score,
                               final_score=final_score_val)

    if len(classes) == 1:
        # 单班级：沿用旧字段 homeworks（模板完全不改）
        cls = classes[0]['class_en']
        homeworks = get_homeworks_for_class(user['id'], cls)
        return render_template('problem_list.html',
                               homeworks=homeworks,
                               user=user,
                               now=now_ts,
                               total_submissions=total_submissions,
                               total_accepted=total_accepted,
                               total_grade=total_grade,
                               last_10_days=last_10_days,
                               daily_counts=daily_counts,
                               regular_score=regular_score,
                               final_score=final_score_val)

    # 多班级：按班级分组传给模板
    homeworks_by_class = []
    for c in classes:
        items = get_homeworks_for_class(user['id'], c['class_en'])
        homeworks_by_class.append({
            "class_en": c['class_en'],
            "class_cn": c['class_cn'],
            "is_primary": c['is_primary'],
            "hw_list": items
        })

    return render_template('problem_list.html',
                           homeworks_by_class=homeworks_by_class,
                           user=user,
                           now=now_ts,
                           total_submissions=total_submissions,
                           total_accepted=total_accepted,
                           total_grade=total_grade,
                           last_10_days=last_10_days,
                           daily_counts=daily_counts,
                           regular_score=regular_score,
                           final_score=final_score_val)

@app.route('/problem/<int:problem_id>', methods=['GET'])
def problem_detail(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    problem = get_problem(problem_id)
    if not problem:
        return "<h3>题目不存在</h3>"
    
    # 如果是普通用户，检查是否是他的作业
    if user['is_admin'] != 1:
        # 获取用户的作业列表
        homeworks = get_homeworks(user)
        
        # 检查当前题目是否在作业列表中
        if not any(hw['problem_id'] == problem_id for hw in homeworks):
            flash('无权限访问该题目', 'danger')
            return redirect(url_for('problem_list'))

    # 将 Markdown 转为 HTML
    rendered_content = markdown.markdown(
        problem['content'],
        extensions=['extra', 'md_in_html', 'fenced_code', 'tables']
    )

    # 获取用户对该题目的所有提交记录，按时间倒序
    submissions = get_submissions_by_user_and_problem(user['username'], problem_id)
    last_submissions = submissions[:3]  # 取最近三条

    # 获取初始代码
    initial_code = problem.get('initial_code', '')
    
    # 获取剩余提交次数（管理员不受限制）
    remaining_submissions = get_remaining_submissions(user['username'], problem_id) if user['is_admin'] != 1 else None
    can_submit_flag = can_submit(user['username'], problem_id) if user['is_admin'] != 1 else True

    return render_template('problem_detail.html',
                           problem=problem,
                           rendered_content=rendered_content,
                           user=user,
                           last_submissions=last_submissions,
                           initial_code=initial_code,
                           remaining_submissions=remaining_submissions,
                           can_submit=can_submit_flag)

def parse_time_limit_ms_from_form(form):
    """
    支持两种字段（任选其一）：
      - time_limit_s：秒（推荐）
      - time_limit_ms：毫秒
    都为空就用默认 2000ms。
    """
    tls = (form.get('time_limit_s') or '').strip()
    tlms = (form.get('time_limit') or '').strip()
    if tls:
        try:
            # 允许小数秒，保留到毫秒
            return int(float(tls) * 1000)
        except:
            pass
    if tlms:
        try:
            return int(tlms)
        except:
            pass
    return 2000  # 默认

@app.route('/admin/add_problem', methods=['GET', 'POST'])
def add_problem():
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    if request.method == 'POST':
        title = request.form.get('title').strip()
        content = request.form.get('content').strip()
        initial_code = request.form.get('initial_code', '').strip()
        test_code = request.form.get('test_code', '').strip()
        forbidden_func = request.form.get('forbidden_func', '').strip()
        problem_type = request.form.get('type')  # 1 编程 2 书面
        lang = (request.form.get('lang') or 'matlab').strip().lower()  # 'matlab' | 'c' | 'cpp'
        time_limit_ms = parse_time_limit_ms_from_form(request.form)

        if not title or not content:
            return render_template('add_problem.html', user=user, error_message="标题和内容不能为空")

        create_problem(title, content, initial_code, test_code, forbidden_func, problem_type, lang, time_limit_ms)
        return redirect(url_for('problem_list'))

    return render_template('add_problem.html', user=user, error_message=None)

@app.route('/admin/edit_problem/<int:problem_id>', methods=['GET', 'POST'])
def edit_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    problem = get_problem(problem_id)
    if not problem:
        return "<h3>题目不存在</h3>"

    if request.method == 'POST':
        new_title = request.form.get('title').strip()
        new_content = request.form.get('content').strip()
        new_initial_code = request.form.get('initial_code', '').strip()
        new_test_code = request.form.get('test_code', '').strip()
        forbidden_func = request.form.get('forbidden_func', '').strip()
        new_lang = (request.form.get('lang') or problem.get('lang') or 'matlab').strip().lower()
        new_time_limit_ms = parse_time_limit_ms_from_form(request.form) if 'time_limit_s' in request.form or 'time_limit' in request.form else (problem.get('time_limit') or 2000)

        if not new_title or not new_content:
            return render_template('edit_problem.html', problem=problem, user=user, error_message="标题和内容不能为空")

        update_problem(problem_id, new_title, new_content, new_initial_code, new_test_code, forbidden_func, new_lang, new_time_limit_ms)
        return redirect(url_for('problem_detail', problem_id=problem_id))

    return render_template('edit_problem.html', problem=problem, user=user, error_message=None)

# 添加更新 testdata 的函数
def update_testdata(problem_id, testdata_json, testdata_num):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE problems SET testdata=%s WHERE id=%s"
            cursor.execute(sql, (testdata_json, problem_id))
            sql = "UPDATE problems SET max_score=%s WHERE id=%s"
            cursor.execute(sql, (testdata_num, problem_id))
        conn.commit()
    finally:
        conn.close()

# 错误处理：文件过大
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    flash('上传的文件太大。最大允许 256MB。', 'danger')
    return redirect(request.url)

@app.route('/admin/upload_testdata/<int:problem_id>', methods=['POST'])
def upload_testdata(problem_id):
    user = current_user()
    if not is_admin(user):
        flash('无权限进行此操作。', 'danger')
        return redirect(url_for('problem_detail', problem_id=problem_id))

    if 'testdata_zip' not in request.files:
        flash('没有文件部分。', 'danger')
        return redirect(url_for('problem_detail', problem_id=problem_id))
    
    file = request.files['testdata_zip']

    if file.filename == '':
        flash('未选择文件。', 'danger')
        return redirect(url_for('problem_detail', problem_id=problem_id))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        temp_path = os.path.join('tmp', filename)
        extract_path = os.path.join('tmp', f'extracted_{problem_id}')

        try:
            # 确保 tmp 目录存在
            os.makedirs('tmp', exist_ok=True)

            # 保存上传的文件到临时路径
            file.save(temp_path)

            # 解压 ZIP 文件
            with zipfile.ZipFile(temp_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            
            # 读取并整理测试点数据
            testdata = []
            in_files = sorted([f for f in os.listdir(extract_path) if f.endswith('.in')])
            out_files = sorted([f for f in os.listdir(extract_path) if f.endswith('.out')])

            if len(in_files) != len(out_files):
                flash('输入文件和输出文件数量不匹配。', 'danger')
                shutil.rmtree(extract_path)
                os.remove(temp_path)
                return redirect(url_for('problem_detail', problem_id=problem_id))

            for in_file, out_file in zip(in_files, out_files):
                # 确保文件名对应，如1.in对应1.out
                base_in = os.path.splitext(in_file)[0]
                base_out = os.path.splitext(out_file)[0]
                if base_in != base_out:
                    flash(f'输入文件 {in_file} 与输出文件 {out_file} 名称不匹配。', 'danger')
                    shutil.rmtree(extract_path)
                    os.remove(temp_path)
                    return redirect(url_for('problem_detail', problem_id=problem_id))
                
                with open(os.path.join(extract_path, in_file), 'r', encoding='utf-8') as f_in, \
                     open(os.path.join(extract_path, out_file), 'r', encoding='utf-8') as f_out:
                    input_data = f_in.read().strip()
                    output_data = f_out.read().strip()
                    testdata.append({
                        'input': input_data,
                        'output': output_data
                    })
            
            # 将 testdata 转换为 JSON 字符串
            testdata_json = json.dumps(testdata, ensure_ascii=False)
            testdata_num = len(in_files)

            # 更新数据库中的 testdata 字段
            update_testdata(problem_id, testdata_json, testdata_num)

            flash('测试数据上传成功。', 'success')

        except zipfile.BadZipFile:
            flash('上传的文件不是有效的 ZIP 压缩包。', 'danger')
        except Exception as e:
            flash(f'上传过程中发生错误：{str(e)}', 'danger')
        finally:
            # 清理临时文件
            if os.path.exists(extract_path):
                shutil.rmtree(extract_path)
            if os.path.exists(temp_path):
                os.remove(temp_path)

        return redirect(url_for('problem_detail', problem_id=problem_id))
    else:
        flash('只允许上传 ZIP 文件。', 'danger')
        return redirect(url_for('problem_detail', problem_id=problem_id))

@app.route('/submit/<int:problem_id>', methods=['GET', 'POST'])
def submit_solution(problem_id):
    """
    提交答案：对于编程题提交代码，对于书面作业上传文件
    """
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    problem = get_problem(problem_id)
    if not problem:
        return "<h3>题目不存在</h3>"

    if user['is_admin'] != 1:
        homeworks = get_homeworks(user)
        # 检查作业是否已过期
        for hw in homeworks:
            if hw['problem_id'] == problem_id:
                if hw['ddl'] and hw['ddl'] < datetime.now():
                    flash('无法提交已过期的作业', 'danger')
                    return redirect(url_for('problem_detail', problem_id=problem_id))
    
    # 检查提交次数限制（管理员不受限制）
    if user['is_admin'] != 1:
        if not can_submit(user['username'], problem_id):
            flash('您对此题的提交次数已达到上限（5次）！', 'danger')
            return redirect(url_for('problem_detail', problem_id=problem_id))
    
    # 获取剩余提交次数（用于显示）
    remaining_submissions = get_remaining_submissions(user['username'], problem_id) if user['is_admin'] != 1 else None

    if request.method == 'POST':
        # 判断题目类型
        if problem['type'] == 1:  # 编程题
            code = request.form.get('code', '')
            if not code.strip():
                flash('代码不能为空。', 'danger')
                return redirect(url_for('problem_detail', problem_id=problem_id))

            # 创建一个 Pending 状态的提交记录
            submission_id = create_submission(
                problem_id=problem_id,
                problem_title=problem['title'],
                username=user['username'],
                code=code,
                score=0,
                test_points=[]
            )
            
            # 增加提交次数计数（管理员不计数）
            if user['is_admin'] != 1:
                increment_submission_count(user['username'], problem_id)
            
            # 触发 Celery 任务进行评测
            evaluate_submission.delay(submission_id)

            flash('提交成功，正在评测中...', 'success')
            return redirect(url_for('submission_detail', submission_id=submission_id))

        # 在 submit_solution 里处理书面作业的文件上传
        elif problem['type'] == 2:  # 书面作业
            # 书面作业上传文件
            if 'file' not in request.files:
                flash('请上传文件。', 'danger')
                return redirect(url_for('problem_detail', problem_id=problem_id))
            file = request.files['file']
            if file.filename == '':
                flash('未选择文件。', 'danger')
                return redirect(url_for('problem_detail', problem_id=problem_id))
            filename = secure_filename(f"file_{file.filename}")

            # 检查文件扩展名是否是 PDF
            if not filename.lower().endswith('.pdf'):
                flash(f'错误：{filename} 不是 PDF 文件', 'danger')
                return redirect(url_for('problem_detail', problem_id=problem_id))

            # 创建一个 Pending 状态的提交记录，保存文件路径
            submission_id = create_submission(
                problem_id=problem_id,
                problem_title=problem['title'],
                username=user['username'],
                code=" ",  # 书面作业没有代码
                score=0,
                test_points=[filename]  # 不需要自动评测
            )
            
            # 增加提交次数计数（管理员不计数）
            if user['is_admin'] != 1:
                increment_submission_count(user['username'], problem_id)

            # 检查文件夹路径是否存在，如果不存在则创建
            upload_folder = os.path.join('uploads', f"{submission_id}")
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)  # 创建目录

            # 保存文件
            file_path = os.path.join(upload_folder, filename)  # 将文件保存到特定文件夹
            file.save(file_path)

            flash('文件提交成功，等待老师评分...', 'success')
            return redirect(url_for('submission_detail', submission_id=submission_id))

    # 如果是 GET 请求，渲染提交页面
    return render_template('problem_detail.html',
                           problem=problem,
                           user=user,
                           remaining_submissions=remaining_submissions)

@app.route('/submissionslist/<int:problem_id>')
def submission_list(problem_id):
    """
    查看某个用户对该题的所有提交记录
    """
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    # 从数据库查询
    subs = get_submissions_by_user_and_problem(user['username'], problem_id)

    return render_template('submission_list.html',
                           problem_id=problem_id,
                           user_submissions=subs,
                           user=user)

@app.route('/submission_detail/<int:submission_id>')
def submission_detail(submission_id):
    """
    查看某次提交详情
    """
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    submission = get_submission_by_id(submission_id)
    if not submission:
        return "<h3>提交记录不存在</h3>"

    if submission['username'] != user['username'] and not is_admin(user):
        return "<h3>无权查看他人提交</h3>"

    # 处理书面作业，显示文件下载链接
    problem = get_problem(submission['problem_id'])
    plang = (problem.get('lang') or 'matlab').lower()  # 'matlab' | 'c'
    if problem and problem['type'] == 2:  # 书面作业
        file_path = f"uploads/{submission['username']}_{submission['problem_id']}_*"
        submission['file_url'] = file_path

    return render_template(
        'submission_detail.html',
        submission=submission,
        test_points=submission['test_points'],
        user=user,
        plang=plang,          # ★ 新增
        problem=problem       # 可用可不用
    )

@app.route('/submission_status/<int:submission_id>')
def submission_status(submission_id):
    """
    轻量级API：仅返回提交状态，用于实时更新判题结果
    """
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify({'error': 'Submission not found'}), 404

    if submission['username'] != user['username'] and not is_admin(user):
        return jsonify({'error': 'Access denied'}), 403

    # 判断是否还在判题中
    is_judging = (
        submission['status'] in ['Pending', 'Waiting', 'Running'] or
        (submission['test_points'] and len(submission['test_points']) == 0) or
        submission['score'] is None
    )

    return jsonify({
        'status': submission['status'],
        'score': submission['score'],
        'is_judging': is_judging,
        'test_points_count': len(submission['test_points']) if submission['test_points'] else 0,
        'last_updated': submission.get('updated_at', submission.get('submit_time', ''))
    })

@app.route('/submission_output_image/<int:submission_id>/<int:test_index>')
def get_submission_output_image(submission_id, test_index):
    """
    获取提交记录中某个测试点的输出图片
    """
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify({'error': 'Submission not found'}), 404

    if submission['username'] != user['username'] and not is_admin(user):
        return jsonify({'error': 'Access denied'}), 403

    # 构建图片文件路径（基于评测系统的存储路径）
    import os
    
    # 对于批量评测，图片存储在批量评测目录中，文件名为 output_{test_index-1}.png
    # 对于单个评测，图片存储在单独的目录中，文件名为 output.png
    
    # 首先尝试批量评测的路径格式
    batch_sid = f"eoj-batch-{submission_id}"
    batch_image_filename = f"output_{test_index-1}.png"  # 批量评测中索引从0开始
    
    # 然后尝试单个评测的路径格式  
    individual_sid = f"eoj-{submission_id}-{test_index}"
    individual_image_filename = "output.png"
    
    # 可能的图片路径（根据评测系统的实际存储位置调整）
    possible_paths = [
        # 批量评测路径
        f"/Users/wenchong/code/NumericalOJ/judger/{batch_sid}/{batch_image_filename}",
        f"./judger/{batch_sid}/{batch_image_filename}",
        f"/tmp/{batch_sid}/{batch_image_filename}",
        f"./{batch_sid}/{batch_image_filename}",
        f"~/oj/judger/{batch_sid}/{batch_image_filename}",
        
        # 单个评测路径（兼容旧版本）
        f"/Users/wenchong/code/NumericalOJ/judger/{individual_sid}/{individual_image_filename}",
        f"./judger/{individual_sid}/{individual_image_filename}",
        f"/tmp/{individual_sid}/{individual_image_filename}",
        f"./{individual_sid}/{individual_image_filename}",
        f"~/oj/judger/{individual_sid}/{individual_image_filename}"
    ]
    
    for img_path in possible_paths:
        # 展开用户目录路径
        expanded_path = os.path.expanduser(img_path)
        if os.path.exists(expanded_path):
            return send_file(expanded_path, mimetype='image/png')
    
    # 如果找不到图片文件，返回404
    return jsonify({'error': 'Output image not found'}), 404

# 添加新的数据库查询方法
def get_submissions_by_user_paginated(username, page=1, per_page=20):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取总数
            count_sql = "SELECT COUNT(*) AS total FROM submissions WHERE username=%s"
            cursor.execute(count_sql, (username,))
            total = cursor.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page

            # 获取分页数据
            data_sql = """SELECT * FROM submissions 
                        WHERE username=%s 
                        ORDER BY id DESC 
                        LIMIT %s OFFSET %s"""
            offset = (page - 1) * per_page
            cursor.execute(data_sql, (username, per_page, offset))
            submissions = cursor.fetchall()
            
            # 解析test_points
            # for submission in submissions:
            #     if submission['test_points']:
            #         submission['test_points'] = [
            #             json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
            #         ]
            return submissions, total_pages
    finally:
        conn.close()

def get_all_submissions_paginated(page=1, per_page=20):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取总数
            count_sql = "SELECT COUNT(*) AS total FROM submissions"
            cursor.execute(count_sql)
            total = cursor.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page

            # 获取分页数据
            data_sql = """SELECT * FROM submissions 
                        ORDER BY id DESC 
                        LIMIT %s OFFSET %s"""
            offset = (page - 1) * per_page
            cursor.execute(data_sql, (per_page, offset))
            submissions = cursor.fetchall()
            
            # 解析test_points
            # for submission in submissions:
            #     if submission['test_points']:
            #         submission['test_points'] = [
            #             json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
            #         ]
            return submissions, total_pages
    finally:
        conn.close()

# 修改 /my_submissions 路由
@app.route('/my_submissions')
def all_submissions():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    
    # 添加分页参数
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # 获取分页后的提交记录
    if user['is_admin']:
        submissions, total_pages = get_all_submissions_paginated( 
            page=page, 
            per_page=per_page
        )
    else:
        submissions, total_pages = get_submissions_by_user_paginated(
            user['username'], 
            page=page, 
            per_page=per_page
        )
    
    return render_template('all_submission.html', 
                         submissions=submissions,
                         user=user,
                         current_page=page,
                         total_pages=total_pages)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

###############################################################################
#  Celery 任务定义
###############################################################################
celery = Celery('oj', 
                broker=app.config['CELERY_BROKER_URL'], 
                backend=app.config['CELERY_RESULT_BACKEND'])
celery.conf.update(app.config)

def compare_float_strings(str1, str2, tolerance=1e-5):
    # 用正则表达式分割字符串：匹配任何空白字符或逗号
    split_pattern = r'[\s,]+'
    
    # 分割并过滤空字符串
    try:
        list1 = [float(x) for x in re.split(split_pattern, str1.strip()) if x]
        list2 = [float(x) for x in re.split(split_pattern, str2.strip()) if x]
    except ValueError:
        return str1 == str2
    
    # 检查长度一致性
    if len(list1) != len(list2):
        return False
    
    # 逐个比较浮点数
    for a, b in zip(list1, list2):
        if numpy.isnan(a) or numpy.isnan(b):
            return False
        if a == 0 and b == 0:
            continue
        max_val = max(abs(a), abs(b))
        abs_error = abs(a - b)
        relative_error = abs_error / max_val
        if relative_error > tolerance and abs_error > tolerance:
            return False
    return True

def bump_complete_cnt_for_user_classes(user, problem_id):
    classes = get_user_classes(user['id'])
    conn = get_db_connection()
    try:
        for cls in classes:
            class_en = cls['class_en']
            with conn.cursor() as cursor:
                # 仅当该班布置了这道题才 +1
                cursor.execute(f"SELECT id FROM {class_en} WHERE problem_id=%s", (problem_id,))
                row = cursor.fetchone()
                if row:
                    cursor.execute(f"UPDATE {class_en} SET complete_cnt = complete_cnt + 1 WHERE problem_id=%s", (problem_id,))
        conn.commit()
    finally:
        conn.close()


@celery.task
def evaluate_submission(submission_id):
    """
    处理评测任务：与评测机通信，更新提交记录
    支持多种语言：
      - MATLAB: 发送到 http://localhost:5050/run-hello
      - C:      发送到 http://localhost:5050/run-c
      - C++:    发送到 http://localhost:5050/run-cpp
      - Python: 发送到 http://localhost:5050/run-py
    说明：
      1) test_code 可选。若包含占位符 '%%user_code_here'，则把用户代码按语言合规地嵌入其中：
         - MATLAB: 用 % 注释包裹标记，保证能运行；
         - C/C++:  用 /* ... */ 注释包裹标记，保证能编译。
      2) forbidden: 仍传到评测端，由评测端做函数调用屏蔽。
      3) 对比输出逻辑沿用原有 compare_float_strings。
      4) 支持用户自定义头文件：从代码仓库获取用户的头文件并包含到代码中。
    """
    submission = get_submission_by_id(submission_id)
    if not submission:
        return

    # Running
    update_submission_status(submission_id, 'Running')

    problem_id = submission['problem_id']
    code = submission['code']
    problem = get_problem(problem_id)  # 包含 lang
    lang = (problem.get('lang') or 'matlab').strip().lower()  # 'matlab' | 'c' | 'cpp' | 'python'
    test_code = problem.get('test_code') or ''

    # 获取用户信息（用于获取用户的代码仓库文件）
    user = get_user_by_username(submission['username'])
    user_files = {}
    
    # 获取用户的代码仓库文件（仅对C/C++有效）
    if user and lang in ['c', 'cpp']:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = """
                SELECT filename, file_content 
                FROM user_code_repository 
                WHERE user_id = %s
                """
                cursor.execute(sql, (user['id'],))
                files = cursor.fetchall()
                for file_data in files:
                    user_files[file_data['filename']] = file_data['file_content']
        except Exception as e:
            print(f"Warning: Failed to load user repository files: {e}")
        finally:
            conn.close()

    # forbidden functions
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT forbidden_func FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            fbd_func_row = cursor.fetchone()
            fbd_func = (fbd_func_row or {}).get("forbidden_func", "") if fbd_func_row else ""
    finally:
        conn.close()

    # === 按语言构建要发送的源代码文本 ===
    # 评测端为了在正则里只检查“用户代码”，会查找下面两个固定标记：
    #   here_is_user_code_fuck_fuck_fuck_hahaha ... user_code_end_fuck_hahaha_fuck
    # 我们把这两个标记放在“各自语言的注释”中，避免影响编译/运行。
    if lang == 'matlab':
        # MATLAB：% 行注释
        if test_code and "%%user_code_here" in test_code:
            wrapped_user_code = ("%here_is_user_code_fuck_fuck_fuck_hahaha\n"
                                 + code + "\n"
                                 "%user_code_end_fuck_hahaha_fuck\n")
            final_code = test_code.replace("%%user_code_here", wrapped_user_code)
        else:
            # 无模板：直接传用户代码（也加上标记方便 forbidden 精准）
            final_code = ("%here_is_user_code_fuck_fuck_fuck_hahaha\n"
                          + code + "\n"
                          "%user_code_end_fuck_hahaha_fuck\n")
        judge_url = 'http://localhost:5050/run-hello'
        file_ext = '.m'

    elif lang == 'c':
        # C：块注释
        if test_code and "%%user_code_here" in test_code:
            wrapped_user_code = ("/*here_is_user_code_fuck_fuck_fuck_hahaha*/\n"
                                 + code + "\n"
                                 "/*user_code_end_fuck_hahaha_fuck*/\n")
            final_code = test_code.replace("%%user_code_here", wrapped_user_code)
        else:
            # 无模板：用户代码应自带 main；同样加入标记（在注释里）
            final_code = ("/*here_is_user_code_fuck_fuck_fuck_hahaha*/\n"
                          + code + "\n"
                          "/*user_code_end_fuck_hahaha_fuck*/\n")
        judge_url = 'http://localhost:5050/run-c'
        file_ext = '.c'

    elif lang == 'cpp':
        # C++：块注释
        if test_code and "%%user_code_here" in test_code:
            wrapped_user_code = ("/*here_is_user_code_fuck_fuck_fuck_hahaha*/\n"
                                 + code + "\n"
                                 "/*user_code_end_fuck_hahaha_fuck*/\n")
            final_code = test_code.replace("%%user_code_here", wrapped_user_code)
        else:
            # 无模板：用户代码应自带 main；同样加入标记（在注释里）
            final_code = ("/*here_is_user_code_fuck_fuck_fuck_hahaha*/\n"
                          + code + "\n"
                          "/*user_code_end_fuck_hahaha_fuck*/\n")
        judge_url = 'http://localhost:5050/run-cpp'
        file_ext = '.cpp'
    
    elif lang == 'python' or lang == 'py':
        # Python：# 行注释
        if test_code and "%%user_code_here" in test_code:
            wrapped_user_code = ("#here_is_user_code_fuck_fuck_fuck_hahaha\n"
                                 + code + "\n"
                                 "#user_code_end_fuck_hahaha_fuck\n")
            final_code = test_code.replace("%%user_code_here", wrapped_user_code)
        else:
            final_code = ("#here_is_user_code_fuck_fuck_fuck_hahaha\n"
                          + code + "\n"
                          "#user_code_end_fuck_hahaha_fuck\n")
        judge_url = 'http://localhost:5050/run-py'
        file_ext = '.py'

    else:
        # 未知语言：直接报错
        update_submission_status(submission_id, 'Error')
        return

    # === 拉取测试数据 ===
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT testdata FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            result = cursor.fetchone()
            if not result or not result['testdata']:
                update_submission_status(submission_id, 'Error')
                return
            testdata_json = result['testdata']
    finally:
        conn.close()

    try:
        test_cases = json.loads(testdata_json)
    except json.JSONDecodeError:
        update_submission_status(submission_id, 'Error')
        return

    # === 批量评测优化：C/C++使用新接口，其他语言保持原逻辑 ===
    test_point_statuses = []
    all_accepted = True

    # 读取时限（毫秒 -> 纳秒）
    time_limit_ms = problem.get('time_limit_ms') or 2000
    time_limit_ns = int(time_limit_ms) * 1000000

    # 对于编译型语言（C/C++），使用批量评测接口优化性能
    if lang in ['c', 'cpp']:
        # 使用批量评测接口
        batch_judge_url = f'http://localhost:5050/batch-evaluate-{lang}'
        
        # 准备批量评测的payload
        batch_payload = {
            "code": final_code,
            "test_cases": test_cases,
            "forbidden": fbd_func,
            "sid": f"eoj-batch-{submission_id}",
            "timeLimit": time_limit_ns,
            "memoryLimit": 512 * 1024 * 1024,
            "user_files": user_files
        }

        try:
            response = requests.post(batch_judge_url, json=batch_payload, timeout=60)  # 批量评测需要更长时间
            response.raise_for_status()
            batch_result = response.json()
        except requests.RequestException as e:
            # 批量评测失败，回退到逐个评测
            print(f"[Warning] Batch evaluation failed for submission {submission_id}: {str(e)}")
            batch_result = None

        if batch_result and batch_result.get('compile_result', {}).get('status') == 'success':
            # 编译成功，处理测试结果
            test_results = batch_result.get('test_results', [])
            
            for idx, (tc, result) in enumerate(zip(test_cases, test_results), start=1):
                status = result.get('status', 'Error')
                actual_output = (result.get('files', {}) or {}).get('stdout', "")
                actual_output = actual_output.strip() if isinstance(actual_output, str) else ""

                if status == 'Accepted':
                    expected_output = tc.get("output", "").strip()
                    if compare_float_strings(actual_output, expected_output):
                        status = 'Accepted'
                    else:
                        status = 'Wrong Answer'
                        all_accepted = False
                else:
                    all_accepted = False

                stderr = (result.get('files', {}) or {}).get('stderr', "")
                stderr = stderr.strip() if isinstance(stderr, str) else ""
                exec_time = int(numpy.round(int(result.get('time', "0")) / 1_000_000))  # ms

                if len(actual_output) > 200:
                    actual_output = actual_output[:200] + "..."

                # 检查是否生成了输出图片
                has_output_image = False
                if 'files' in result and isinstance(result['files'], dict):
                    # 检查批量评测中的图片文件命名格式
                    if f'output_{idx-1}.png' in result['files']:
                        has_output_image = True

                test_point_statuses.append({
                    "status": status,
                    "stderr": stderr,
                    "stdout": actual_output,
                    "time": exec_time,
                    "has_output_image": has_output_image,
                    "test_index": idx
                })
        
        elif batch_result and batch_result.get('compile_result', {}).get('status') == 'error':
            # 编译错误，所有测试点都标记为编译错误
            compile_stderr = batch_result.get('compile_result', {}).get('stderr', 'Compile Error')
            all_accepted = False
            
            for idx, tc in enumerate(test_cases, start=1):
                test_point_statuses.append({
                    "status": "Compile Error",
                    "stderr": compile_stderr,
                    "stdout": "",
                    "time": 0,
                    "has_output_image": False,
                    "test_index": idx
                })
        
        elif batch_result and batch_result.get('compile_result', {}).get('status') == 'forbidden':
            # 禁用函数错误
            forbidden_msg = batch_result.get('compile_result', {}).get('stderr', 'Forbidden Function')
            all_accepted = False
            
            for idx, tc in enumerate(test_cases, start=1):
                test_point_statuses.append({
                    "status": "Forbidden",
                    "stderr": forbidden_msg,
                    "stdout": forbidden_msg,
                    "time": 0,
                    "has_output_image": False,
                    "test_index": idx
                })
        
        else:
            # 批量评测失败，回退到原有逐个评测逻辑
            print(f"[Warning] Falling back to individual evaluation for submission {submission_id}")
            batch_result = None

    # 如果不是编译型语言或批量评测失败，使用原有的逐个评测逻辑
    if lang not in ['c', 'cpp'] or not batch_result or batch_result.get('compile_result', {}).get('status') != 'success':
        for idx, tc in enumerate(test_cases, start=1):
            payload = {
                "code": final_code,
                "input": tc.get("input", ""),
                "forbidden": fbd_func,
                "sid": f"eoj-{submission_id}-{idx}",
                "timeLimit": time_limit_ns,          # ns（从题目配置读取）
                "memoryLimit": 512 * 1024 * 1024,    # Byte
                "user_files": user_files             # 用户的代码仓库文件
            }

            try:
                response = requests.post(judge_url, json=payload, timeout=20)
                response.raise_for_status()
                result = response.json()
            except requests.RequestException:
                test_point_statuses.append({"status": "Error"})
                all_accepted = False
                continue

            status = result.get('status', 'Error')
            actual_output = (result.get('files', {}) or {}).get('stdout', "")
            actual_output = actual_output.strip() if isinstance(actual_output, str) else ""

            if status == 'Accepted':
                expected_output = tc.get("output", "").strip()
                if compare_float_strings(actual_output, expected_output):
                    status = 'Accepted'
                else:
                    status = 'Wrong Answer'
                    all_accepted = False
            else:
                all_accepted = False

            stderr = (result.get('files', {}) or {}).get('stderr', "")
            stderr = stderr.strip() if isinstance(stderr, str) else ""
            lines = stderr.split('\n')
            exec_time = int(numpy.round(int(result.get('time', "0")) / 1_000_000))  # ms

            if lang == 'matlab':
                if len(lines) < 3:
                    stderr = ""
                else:
                    lines = lines[2:-1]
                    stderr = '\n'.join(lines)

            if len(actual_output) > 200:
                actual_output = actual_output[:200] + "..."

            # 检查是否生成了输出图片
            has_output_image = False
            if 'files' in result and isinstance(result['files'], dict):
                # 检查是否有output.png文件
                if 'output.png' in result['files'] or any(key.endswith('output.png') for key in result['files'].keys()):
                    has_output_image = True

            test_point_statuses.append({
                "status": status, 
                "stderr": stderr, 
                "stdout": actual_output,
                "time": exec_time,
                "has_output_image": has_output_image,
                "test_index": idx  # 添加测试点索引，用于生成图片URL
            })

    # === 汇总与落库（沿用你原逻辑） ===
    score = sum(1 for tp in test_point_statuses if tp["status"] == "Accepted")
    user = get_user_by_username(submission['username'])

    final_status = "Accepted" if all_accepted else "Unaccepted"
    if final_status == "Accepted":
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = f'SELECT ACP{problem_id} FROM ac_record WHERE userid=%s'
                cursor.execute(sql, (user['id'],))
                ac_rec = cursor.fetchone()
                is_ac = ac_rec[f'ACP{problem_id}']
            if is_ac != 1:
                with conn.cursor() as cursor:
                    sql = f'UPDATE ac_record SET ACP{problem_id}=1 WHERE userid=%s'
                    cursor.execute(sql, (user['id'],))
                conn.commit()
                with conn.cursor() as cursor:
                    sql = f'UPDATE problems SET cnt=cnt+1 WHERE id={problem_id}'
                    cursor.execute(sql)
                conn.commit()
                if user['is_admin'] != 1:
                    bump_complete_cnt_for_user_classes(user, problem_id)
        finally:
            conn.close()

    # 更新最高分：只需要更新用户的主班级记录
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f'UPDATE max_score SET P{problem_id}={score} WHERE userid=%s AND (P{problem_id} IS NULL OR P{problem_id} < {score})'
            cursor.execute(sql, (user['id'],))
        conn.commit()
    finally:
        conn.close()

    update_submission_evaluation(submission_id, test_point_statuses, score, final_status)

###############################################################################
#  班级管理
###############################################################################
def get_all_classes():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT class_en, class_cn FROM class_table ORDER BY class_cn ASC"
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()

def get_all_classes_except_admin():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT class_en, class_cn FROM class_table WHERE class_en != 'Cadmin' ORDER BY class_cn ASC"
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()

def get_class_by_en(class_en):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT class_en, class_cn FROM class_table WHERE class_en=%s"
            cursor.execute(sql, (class_en,))
            return cursor.fetchone()
    finally:
        conn.close()

def get_class_by_cn(class_cn):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT class_en, class_cn FROM class_table WHERE class_cn=%s"
            cursor.execute(sql, (class_cn,))
            return cursor.fetchone()
    finally:
        conn.close()


@app.route('/admin/users')
def user_management():
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    # 查询参数
    page = request.args.get('page', 1, type=int)
    search_username = request.args.get('username', '').strip()
    search_class = request.args.get('class', '').strip()
    per_page = 50

    # ---------- 组装过滤条件（对 users 表） ----------
    # 说明：
    # - 用户名：users.username LIKE %xxx%
    # - 班级：主班级 = search_class 或 额外班级映射存在（user_id in (select ... from user_class_map where class_en=...))
    user_where_clauses = []
    user_where_params = []

    if search_username:
        user_where_clauses.append("u.username LIKE %s")
        user_where_params.append(f"%{search_username}%")

    if search_class:
        user_where_clauses.append(
            "(u.class = %s OR u.id IN (SELECT user_id FROM user_class_map WHERE class_en = %s))"
        )
        user_where_params.extend([search_class, search_class])

    user_where_sql = ""
    if user_where_clauses:
        user_where_sql = "WHERE " + " AND ".join(user_where_clauses)

    # ---------- 统计总数（基于过滤后的 users） ----------
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            count_sql = f"""
                SELECT COUNT(*) AS total
                FROM (
                    SELECT u.id
                    FROM users u
                    {user_where_sql}
                    ORDER BY u.id ASC
                ) t
            """
            cursor.execute(count_sql, user_where_params)
            total = cursor.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page

            # ---------- 拉取当前页用户 ----------
            data_sql = f"""
                SELECT u.id, u.username, u.email, u.class, u.class_cn
                FROM users u
                {user_where_sql}
                ORDER BY u.id ASC
                LIMIT %s OFFSET %s
            """
            params = user_where_params + [per_page, (page - 1) * per_page]
            cursor.execute(data_sql, params)
            users = cursor.fetchall()

        # ---------- 批量拉取这些用户的额外班级（映射表） ----------
        if users:
            uid_list = [u['id'] for u in users]
            placeholders = ','.join(['%s'] * len(uid_list))

            with conn.cursor() as cursor:
                # 关联 class_table 拿中文名
                map_sql = f"""
                    SELECT m.user_id, m.class_en, ct.class_cn, m.is_primary
                    FROM user_class_map m
                    JOIN class_table ct ON ct.class_en = m.class_en
                    WHERE m.user_id IN ({placeholders})
                """
                cursor.execute(map_sql, uid_list)
                mapping_rows = cursor.fetchall()

            # 组装 user_id -> [extra_classes...]
            extra_map = {uid: [] for uid in uid_list}
            for row in mapping_rows:
                # 仅展示“额外”班级；主班级仍以 users.class 显示
                # 如果你希望也显示 is_primary=1 的映射（若你把主班也同步进了映射表），这里可跳过主班
                if 'class' in users[0]:  # 安全判空
                    # 找到该用户的主班（来自 users.class）
                    # 我们只要把与主班相同的 class_en 过滤掉即可
                    pass
                extra_map[row['user_id']].append({
                    "class_en": row['class_en'],
                    "class_cn": row['class_cn'],
                    "is_primary": row.get('is_primary', 0)
                })

            # 将 extra_classes 挂到每个用户
            user_by_id = {u['id']: u for u in users}
            for u in users:
                # 过滤掉与主班同名的映射，避免重复显示
                u_extra = []
                for cls in extra_map.get(u['id'], []):
                    if cls['class_en'] != u['class']:
                        u_extra.append(cls)
                u['extra_classes'] = u_extra
        else:
            # 没有用户时，保持结构一致
            users = []
    finally:
        conn.close()

    classes = get_all_classes()
    return render_template('admin_user_management.html',
                           users=users,
                           classes=classes,
                           user=user,
                           current_page=page,
                           total_pages=total_pages,
                           search_username=search_username,
                           search_class=search_class)

@app.route('/admin/edit_user_ajax', methods=['POST'])
def edit_user_ajax():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    # 读取参数
    user_id = request.form.get('user_id', type=int)
    new_class_en = (request.form.get('class') or '').strip()
    if not user_id or not new_class_en:
        return jsonify({'success': False, 'message': '缺少必要参数'}), 400

    # 查用户 & 目标班级
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    new_class = get_class_by_en(new_class_en)
    if not new_class:
        return jsonify({'success': False, 'message': '目标班级不存在'}), 400

    old_class_en = user.get('class') or None
    # is_admin 规则：主班为 Cadmin 则给管理员，否则普通
    give_admin = 1 if new_class['class_en'] == 'Cadmin' else 0

    # 已经是该主班，不做无谓更新
    if old_class_en == new_class['class_en'] and user.get('class_cn') == new_class['class_cn'] and user.get('is_admin') == give_admin:
        return jsonify({'success': True, 'message': '主班级未变化', 'user_id': user_id, 'new_class': new_class})

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 1) 先更新 users（主班、中文名、是否管理员）
            cursor.execute(
                "UPDATE users SET class=%s, class_cn=%s, is_admin=%s WHERE id=%s",
                (new_class['class_en'], new_class['class_cn'], give_admin, user_id)
            )

            # 2) class_table 主班人数计数（兼容旧系统）
            if old_class_en:
                cursor.execute("UPDATE class_table SET class_cnt=class_cnt-1 WHERE class_en=%s", (old_class_en,))
            cursor.execute("UPDATE class_table SET class_cnt=class_cnt+1 WHERE class_en=%s", (new_class['class_en'],))

            # 3) max_score.class_en 跟随主班
            cursor.execute("UPDATE max_score SET class_en=%s WHERE userid=%s", (new_class['class_en'], user_id))

            # 4) 兼容新结构：维护 user_class_map 的 is_primary
            #    - 将该用户所有映射 is_primary 置 0
            #    - 将新主班 upsert 为 is_primary=1（如果已有记录，直接置 1；如果此前做过“额外班”，相当于提升为主班）
            #    - 这里不移除其它额外班映射（保持原有成员关系）
            try:
                # 将该用户所有映射置 0
                cursor.execute("UPDATE user_class_map SET is_primary=0 WHERE user_id=%s", (user_id,))
                # 新主班置 1（upsert）
                cursor.execute(
                    """
                    INSERT INTO user_class_map (user_id, class_en, is_primary)
                    VALUES (%s, %s, 1)
                    ON DUPLICATE KEY UPDATE is_primary=VALUES(is_primary)
                    """,
                    (user_id, new_class['class_en'])
                )
            except Exception:
                # 如果没有这张表或结构不同，不阻塞主链路（兼容旧库）
                pass

        conn.commit()

    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': f'数据库错误: {str(e)}'}), 500
    finally:
        conn.close()

    flash(f"已将 userID={user_id} 的主班级修改为 {new_class['class_cn']}", 'success')
    return jsonify({'success': True, 'message': '更新成功', 'user_id': user_id, 'new_class': new_class})

@app.route('/admin/edit_username_ajax', methods=['POST'])
def edit_username_ajax():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    user_id = request.form.get('user_id')
    new_username = request.form.get('new_username')

    if not new_username or not user_id:
        return jsonify({'success': False, 'message': '缺少必要参数'}), 400

    # 检查新用户名是否已存在
    if get_user_by_username(new_username):
        return jsonify({'success': False, 'message': '用户名已存在'}), 400

    # 更新数据库中的用户名
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE users SET username=%s WHERE id=%s"
            cursor.execute(sql, (new_username, user_id))
        conn.commit()
    finally:
        conn.close()

    # 返回成功信息和新的用户名
    return jsonify({'success': True, 'message': '更新成功', 'user_id': user_id, 'new_username': new_username})

@app.route('/admin/add_class_ajax', methods=['POST'])
def add_class_ajax():
    admin = current_user()
    if not is_admin(admin):
        return jsonify({'success': False, 'message': '无权限'}), 403

    class_en = request.form.get('class_en', '').strip()
    if re.match('^[a-zA-Z0-9_]+$', class_en) == False:
        return jsonify({'success': False, 'message': '班级英文名必须仅由大小写字母、数字、下划线构成'}), 400
    class_en = f"C{class_en}"
    class_cn = request.form.get('class_cn', '').strip()

    if not class_en or not class_cn:
        return jsonify({'success': False, 'message': '班级英文名和中文名不能为空'}), 400
    
    check_old_class = get_class_by_en(class_en)
    if check_old_class:
        return jsonify({'success': False, 'message': '已存在以这个英文名命名的班级，请修改'}), 400

    check_old_class = get_class_by_cn(class_cn)
    if check_old_class:
        return jsonify({'success': False, 'message': '已存在以这个中文名命名的班级，请修改'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "INSERT INTO class_table (class_en, class_cn, class_cnt) VALUES (%s, %s, 0)"
            cursor.execute(sql, (class_en, class_cn))
        conn.commit()
        with conn.cursor() as cursor:
            sql = f"CREATE TABLE {class_en}(id INT PRIMARY KEY AUTO_INCREMENT, problem_id INT, ddl DATETIME, complete_cnt INT, problem_title TEXT);"
            cursor.execute(sql)
        conn.commit()
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

    flash(f"成功添加班级 {class_cn}", 'success')
    return jsonify({'success': True, 'message': '新增班级成功', 'class_en': class_en, 'class_cn': class_cn})


###############################################################################
#  作业管理
###############################################################################
@app.route('/admin/homework')
def admin_homework():
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    selected_class = request.args.get('sclass')
    classes = get_all_classes_except_admin()

    # 验证选择的班级是否有效
    valid_classes = [cls['class_en'] for cls in classes]
    if selected_class and selected_class not in valid_classes:
        flash('无效的班级选择', 'danger')
        return redirect(url_for('admin_homework'))

    homework_list = []
    if selected_class:
        # 安全校验后动态查询
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = f"SELECT * FROM {selected_class} ORDER BY id ASC"
                cursor.execute(sql)
                homework_list = cursor.fetchall()
                # 补充题目标题
                for hw in homework_list:
                    problem = get_problem(hw['problem_id'])
                    hw['problem_title'] = problem['title'] if problem else '未知题目'
        except pymysql.Error as e:
            flash(f'数据库错误: {str(e)}', 'danger')
        finally:
            conn.close()

    return render_template('admin_homework.html',
                           classes=classes,
                           selected_class=selected_class,
                           homework_list=homework_list,
                           user=user)

@app.route('/admin/class_adjust', methods=['POST'])
def admin_class_adjust():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403

    enabled = request.form.get('enabled', '0')
    set_setting(CLASS_ADJUST_FLAG_KEY, '1' if enabled == '1' else '0')
    return jsonify(success=True, enabled=(enabled == '1'))

@app.route('/admin/update_ddl', methods=['POST'])
def admin_update_ddl():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403

    data = request.get_json()
    class_en = data.get('class_en')
    homework_id = data.get('homework_id')
    new_ddl = data.get('new_ddl')

    # 参数校验
    if not all([class_en, homework_id, new_ddl]):
        return jsonify(success=False, message='参数不完整'), 400

    # 验证班级有效性
    if not get_class_by_en(class_en):
        return jsonify(success=False, message='班级不存在'), 400

    # 更新操作
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"UPDATE {class_en} SET ddl=%s WHERE id=%s"
            cursor.execute(sql, (new_ddl, homework_id))
        conn.commit()
        return jsonify(success=True, message='DDL更新成功')
    except pymysql.Error as e:
        return jsonify(success=False, message=f'数据库错误: {str(e)}'), 500
    finally:
        conn.close()

@app.route('/admin/add_homework', methods=['POST'])
def admin_add_homework():
    user = current_user()
    if not is_admin(user):
        flash('无权限操作', 'danger')
        return redirect(url_for('admin_homework'))

    class_en = request.form.get('class_en')
    problem_id = request.form.get('problem_id')
    ddl = request.form.get('ddl')

    # 参数校验
    if not all([class_en, problem_id, ddl]):
        flash('缺少必要参数', 'danger')
        return redirect(url_for('admin_homework', sclass=class_en))

    try:
        # 验证题目存在
        problem_id = int(problem_id)
        problem = get_problem_title(problem_id)
        if not problem:
            flash('题目不存在', 'danger')
            return redirect(url_for('admin_homework', sclass=class_en))

        # 验证班级存在
        if not get_class_by_en(class_en):
            flash('班级不存在', 'danger')
            return redirect(url_for('admin_homework'))

        # 插入新作业
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = f"INSERT INTO {class_en} (problem_id, ddl, complete_cnt, problem_title) VALUES (%s, %s, 0, %s)"
                cursor.execute(sql, (problem_id, ddl, problem['title']))
            conn.commit()
            flash('作业添加成功', 'success')
        finally:
            conn.close()

    except ValueError:
        flash('题目ID必须是数字', 'danger')
    except pymysql.Error as e:
        flash(f'数据库错误: {str(e)}', 'danger')
    
    # 保持当前班级选择状态
    return redirect(url_for('admin_homework', sclass=class_en))

# 新增删除作业的路由
@app.route('/admin/delete_homework', methods=['POST'])
def admin_delete_homework():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    data = request.get_json()
    class_en = data.get('class_en')
    homework_id = data.get('homework_id')

    if not all([class_en, homework_id]):
        return jsonify(success=False, message="参数不完整"), 400

    if not get_class_by_en(class_en):
        return jsonify(success=False, message="班级不存在"), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"DELETE FROM {class_en} WHERE id=%s"
            cursor.execute(sql, (homework_id,))
        conn.commit()
        flash("删除成功", "success")
        return jsonify(success=True, message="删除成功")
    except pymysql.Error as e:
        return jsonify(success=False, message=f"数据库错误: {str(e)}"), 500
    finally:
        conn.close()

@app.route('/export_scores')
def export_scores():
    """导出指定班级的成绩（GBK编码），支持多班级映射，向后兼容旧 users.class。"""
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('login'))
    
    selected_class = request.args.get('sclass')
    if not selected_class:
        return "班级参数错误", 400
    
    # 验证班级有效性（避免后面动态表名注入）
    class_info = get_class_by_en(selected_class)
    if not class_info:
        return "班级不存在", 404
    
    # 1) 获取该班布置的题目（从 Cxxx 班级作业表）
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT problem_id FROM {selected_class} ORDER BY id ASC")
            rows = cursor.fetchall()
            problem_ids = [r['problem_id'] for r in rows]
    finally:
        conn.close()
    
    if not problem_ids:
        return "该班级没有布置任何作业", 404
    
    # 2) 题目标题映射（GBK 友好）
    problem_titles = {}
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            fmt = ','.join(['%s'] * len(problem_ids))
            cursor.execute(f"SELECT id, title FROM problems WHERE id IN ({fmt})", problem_ids)
            for p in cursor.fetchall():
                # 处理中文与特殊字符，避免 Excel 打开乱码/不可编码
                title = p['title'].encode('gbk', errors='replace').decode('gbk')
                problem_titles[p['id']] = title
    finally:
        conn.close()
    
    # 3) 获取该班学生：优先从 user_class_map；若为空则回退 users.class
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.username
                FROM user_class_map m
                JOIN users u ON u.id = m.user_id
                WHERE m.class_en = %s
                ORDER BY u.id ASC
            """, (selected_class,))
            students = cursor.fetchall()
            
            if not students:
                # 向后兼容：旧系统只在 users.class 里
                cursor.execute("SELECT id, username FROM users WHERE class = %s ORDER BY id ASC", (selected_class,))
                students = cursor.fetchall()
    finally:
        conn.close()
    
    if not students:
        return "该班级没有学生", 404
    
    # 4) 批量拉取 max_score，不区分班级，直接查用户的最高分记录
    user_ids = [s['id'] for s in students]
    placeholders = ','.join(['%s'] * len(user_ids))
    max_score_map = {}
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 不按class_en过滤，直接取用户的成绩记录
            cursor.execute(
                f"SELECT * FROM max_score WHERE userid IN ({placeholders})",
                user_ids
            )
            for row in cursor.fetchall():
                # 如果同一用户有多条记录（多班级），取最高分
                uid = row['userid']
                if uid not in max_score_map:
                    max_score_map[uid] = row
                else:
                    # 合并多条记录，每个题目取最高分
                    existing = max_score_map[uid]
                    for key, value in row.items():
                        if key.startswith('P') and value is not None:
                            existing_val = existing.get(key)
                            if existing_val is None or value > existing_val:
                                existing[key] = value
    finally:
        conn.close()
    
    # 5) 生成 GBK CSV
    from io import BytesIO
    import csv, codecs
    output = BytesIO()
    writer = csv.writer(codecs.getwriter('gbk')(output))
    
    headers = ['用户名'] + [problem_titles[pid] for pid in problem_ids] + ['总分']
    writer.writerow([h.encode('gbk', 'replace').decode('gbk') for h in headers])

    for stu in students:
        uid = stu['id']
        row = [stu['username']]
        total = 0
        
        ms = max_score_map.get(uid, {})
        for pid in problem_ids:
            score = ms.get(f'P{pid}', 0) if ms else 0
            score = score or 0
            total += score
            row.append(str(score))
        row.append(str(total))
        
        # 逐个单元格转 GBK 安全字符串
        writer.writerow([cell.encode('gbk', 'replace').decode('gbk') for cell in row])
    
    from flask import make_response
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=GBK'
    resp.headers['Content-Disposition'] = f'attachment; filename="{selected_class}_scores.csv"'
    return resp

@app.route('/export_student_codes')
def export_student_codes():
    """导出指定班级的学生代码（按最高分、最新提交），支持多班级映射，兼容旧 users.class。"""
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('login'))
    
    selected_class = request.args.get('sclass')
    if not selected_class:
        return "班级参数错误", 400
    
    # 1) 校验班级
    class_info = get_class_by_en(selected_class)
    if not class_info:
        return "班级不存在", 404
    
    # 2) 获取该班布置的题目（从班级作业表 Cxxx 取）
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT problem_id FROM {selected_class} ORDER BY id ASC")
            homework_problems = cursor.fetchall()
    finally:
        conn.close()
    if not homework_problems:
        return "该班级没有布置任何作业", 404
    
    problem_ids = [p['problem_id'] for p in homework_problems]

    # 3) 拉取题目标题与语言（一次性）
    problems_map = {}  # pid -> {'title':..., 'lang':...}
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            fmt = ','.join(['%s'] * len(problem_ids))
            cursor.execute(f"SELECT id, title, lang FROM problems WHERE id IN ({fmt})", problem_ids)
            for row in cursor.fetchall():
                problems_map[row['id']] = {'title': row['title'], 'lang': (row.get('lang') or 'matlab').lower()}
    finally:
        conn.close()

    # 4) 获取该班学生：优先从 user_class_map；若为空回退 users.class
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.username
                FROM user_class_map m
                JOIN users u ON u.id = m.user_id
                WHERE m.class_en = %s
                ORDER BY u.id ASC
            """, (selected_class,))
            students = cursor.fetchall()
            if not students:
                cursor.execute("SELECT id, username FROM users WHERE class = %s ORDER BY id ASC", (selected_class,))
                students = cursor.fetchall()
    finally:
        conn.close()
    if not students:
        return "该班级没有学生", 404

    # 5) 生成内存 ZIP
    from io import BytesIO
    import zipfile, re
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # 为了只导出班级成员的最佳代码，我们在 SQL 里先限定用户集合
        # 构造 username 列表（用 username 关联 submissions）
        usernames = [s['username'] for s in students]
        # 如果用户名很多，可以分块；这里直接一次性 IN(...)（MySQL 默认可承受千级）
        if not usernames:
            # 理论到不了这儿
            pass
        
        # 按每个题目导出
        for pid in problem_ids:
            pmeta = problems_map.get(pid, {})
            ptitle = pmeta.get('title') or f'Problem_{pid}'
            plang  = (pmeta.get('lang') or 'matlab').lower()

            # 题目文件夹名：替换非法字符
            folder_name = re.sub(r'[\\/*?:"<>|]', '_', ptitle)

            # 选择代码后缀
            if plang == 'matlab':
                ext = '.m'
            elif plang == 'c':
                ext = '.c'
            elif plang == 'cpp':
                ext = '.cpp'
            elif plang in ('python', 'py'):
                ext = '.py'
            else:
                ext = '.txt'

            # —— 拉取该题该班学生的最佳提交（分数优先，其次时间新）——
            # 用 CTE 过滤用户集合：先把 usernames 填入临时表式的 CTE，再 Join submissions
            # 为了减少 IN 列表的长度，我们用 users 表做 join，再用 class 映射筛人（双路径：映射表优先、旧表回退）
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    # 说明：
                    # class_users: 班级中的用户（优先映射表；若同一用户已在映射表中，则不再用旧表行）
                    # ranked_submissions: 对每位用户在此题的提交做 ROW_NUMBER 排名
                    sql = """
                        WITH class_users AS (
                            SELECT u.id, u.username
                            FROM user_class_map m
                            JOIN users u ON u.id = m.user_id
                            WHERE m.class_en = %s
                            UNION
                            SELECT u2.id, u2.username
                            FROM users u2
                            WHERE u2.class = %s
                              AND NOT EXISTS (
                                  SELECT 1 FROM user_class_map m2
                                  WHERE m2.user_id = u2.id AND m2.class_en = %s
                              )
                        ),
                        ranked_submissions AS (
                            SELECT s.id, s.username, s.code, s.score, s.created_at,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY cu.id
                                       ORDER BY s.score DESC, s.created_at DESC
                                   ) AS rn
                            FROM submissions s
                            JOIN class_users cu ON cu.username = s.username
                            WHERE s.problem_id = %s
                        )
                        SELECT username, code
                        FROM ranked_submissions
                        WHERE rn = 1
                        ORDER BY username ASC
                    """
                    cursor.execute(sql, (selected_class, selected_class, selected_class, pid))
                    best_rows = cursor.fetchall()
            finally:
                conn.close()

            # 写入 ZIP
            for row in best_rows:
                uname = row['username']
                code  = row.get('code') or ""
                # 安全处理用户名（避免奇怪字符成为路径）
                safe_uname = re.sub(r'[\\/*?:"<>|]', '_', uname)
                file_name = f"{folder_name}/{safe_uname}{ext}"
                # 写入（UTF-8）
                try:
                    zip_file.writestr(file_name, code.encode('utf-8'))
                except Exception:
                    # 兜底：即便编码异常也写入原始 bytes（这里理论不会发生）
                    zip_file.writestr(file_name, code)

    # 6) 返回响应
    from flask import make_response
    zip_buffer.seek(0)
    response = make_response(zip_buffer.getvalue())
    response.headers['Content-Type'] = 'application/zip'
    response.headers['Content-Disposition'] = (
        f'attachment; filename="{selected_class}_codes.zip"'
    )
    return response

###############################################################################
#  书面作业
###############################################################################
def get_file_path_for_submission(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT username, problem_id, test_points FROM submissions WHERE id=%s"
            cursor.execute(sql, (submission_id,))
            submission = cursor.fetchone()
            if not submission:
                return None
            if submission['test_points']:
                submission['test_points'] = [
                    json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                ]
            file_path = os.path.join('uploads', f"{submission_id}", submission['test_points'][0])
            return file_path
    finally:
        conn.close()

def update_submission_score_and_comment(submission_id, score, comment):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """UPDATE submissions
                     SET score = %s, code = %s
                     WHERE id = %s"""
            cursor.execute(sql, (score, comment, submission_id))
        conn.commit()
        submission = get_submission_by_id(submission_id)
        problem_id = submission["problem_id"]
        user = get_user_by_username(submission["username"])
        with conn.cursor() as cursor:
            sql = f'UPDATE max_score SET P{problem_id}={score} WHERE userid={user["id"]} AND (P{problem_id} IS NULL OR P{problem_id} < {score})'
            cursor.execute(sql)
        conn.commit()
        if score == 5:
            with conn.cursor() as cursor:
                sql = f'UPDATE ac_record SET ACP{problem_id}=1 WHERE userid={user["id"]}'
                cursor.execute(sql)
            conn.commit()
    finally:
        conn.close()

@app.route('/download_submission_file/<int:submission_id>')
def download_submission_file(submission_id):
    submission = get_submission_by_id(submission_id)
    if not submission:
        return "提交记录不存在", 404
    
    if submission['problem_type'] != 2:  # 只有书面作业题才有文件
        return "不是书面作业题", 400
    
    # 获取文件路径（这里假设文件路径存储在 submissions 表的某个字段中）
    file_path = get_file_path_for_submission(submission_id)
    if not file_path or not os.path.exists(file_path):
        return "文件不存在", 404
    
    # 这里需要返回文件下载
    return send_file(file_path,
                     mimetype='application/pdf',
                     as_attachment=False,
                     download_name=f'submission_{submission_id}.pdf')

@app.route('/submit_grading/<int:submission_id>', methods=['POST'])
def submit_grading(submission_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限批改作业"), 403
    
    score = request.form.get('score', type=int)
    comment = request.form.get('comment', '').strip()
    
    if not (1 <= score <= 5):
        return jsonify(success=False, message="得分必须在 1 到 5 之间"), 400
    
    # 获取提交记录
    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify(success=False, message="提交记录不存在"), 404

    # 更新提交记录的得分和评语
    update_submission_score_and_comment(submission_id, score, comment)
    
    # 根据得分更新题目状态
    new_status = 'Accepted' if score == 5 else 'Unaccepted'
    update_submission_status(submission_id, new_status)
    
    flash('批改结果提交成功', 'success')
    return jsonify(success=True, message="批改结果已提交")

@app.route('/get_next_pending_submission/<int:submission_id>', methods=['GET'])
def get_next_pending_submission(submission_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限查看待批改作业"), 403
    
    # 获取当前提交记录
    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify(success=False, message="提交记录不存在"), 404

    # 获取该作业的题目 ID 和类型
    problem_id = submission['problem_id']
    problem_type = submission['problem_type']

    # 如果题目是书面作业（problem_type == 2），查找下一个状态为 Pending 的提交记录
    if problem_type == 2:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # 查找下一个状态为 Pending 的书面作业提交
                sql = """
                    SELECT id
                    FROM submissions
                    WHERE status = 'Pending' AND problem_type = 2
                    AND id > %s
                    ORDER BY id ASC
                    LIMIT 1
                """
                cursor.execute(sql, (submission_id,))
                next_submission = cursor.fetchone()
                if next_submission:
                    next_submission_id = next_submission['id']
                    # 返回下一个作业的 URL
                    next_submission_url = url_for('submission_detail', submission_id=next_submission_id)
                    return jsonify(success=True, next_submission_url=next_submission_url)
            with conn.cursor() as cursor:
                # 从头查找状态为 Pending 的书面作业提交
                sql = """
                    SELECT id
                    FROM submissions
                    WHERE status = 'Pending' AND problem_type = 2
                    ORDER BY id ASC
                    LIMIT 1
                """
                cursor.execute(sql)
                next_submission = cursor.fetchone()
                if next_submission:
                    next_submission_id = next_submission['id']
                    # 返回下一个作业的 URL
                    next_submission_url = url_for('submission_detail', submission_id=next_submission_id)
                    return jsonify(success=True, next_submission_url=next_submission_url)
        finally:
            conn.close()
    flash("已全部批改完成", 'success')
    return jsonify(success=False, message="无待批改的书面作业")

def invalidate_previous_pending_submissions(problem_id):
    """
    处理某题的无效提交：将除最后一个外所有 Pending 状态的提交更新为 Unaccepted
    """
    # 获取所有提交该问题的用户
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 查询所有 Pending 状态的提交，并按时间倒序排列
            sql = """
                SELECT id, username
                FROM submissions
                WHERE problem_id = %s AND status = 'Pending'
                ORDER BY created_at DESC
            """
            cursor.execute(sql, (problem_id,))
            pending_submissions = cursor.fetchall()

            # 遍历每个用户
            user_submissions = {}
            for submission in pending_submissions:
                user_submissions.setdefault(submission['username'], []).append(submission['id'])

            # 对每个用户，更新除最后一个外的所有 Pending 提交状态
            for username, submissions in user_submissions.items():
                if len(submissions) > 1:
                    # 更新除最后一个之外的提交
                    for submission_id in submissions[1:]:
                        update_submission_status(submission_id, 'Unaccepted')
            conn.commit()
    finally:
        conn.close()

@app.route('/invalidate_invalid_submissions/<int:problem_id>', methods=['POST'])
def invalidate_invalid_submissions(problem_id):
    # 仅限管理员
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403
    try:
        # 调用之前编写的函数，处理无效提交
        invalidate_previous_pending_submissions(problem_id)
        return jsonify(success=True, message="无效提交已移除")
    except Exception as e:
        return jsonify(success=False, message=f"错误: {str(e)}"), 500


###############################################################################
#  讨论区
###############################################################################
@app.route('/forum')
def forum_index():
    """讨论区首页，显示所有帖子"""
    user = current_user()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM forum_threads ORDER BY created_at DESC"
            cursor.execute(sql)
            threads = cursor.fetchall()
    finally:
        conn.close()
    
    # 获取今日提交和通过数
    total_submissions, total_accepted = get_today_forum_counts()

    # 获取最近十天的提交数
    last_10_days, daily_counts = get_last_10_days_forum_counts()

    return render_template('forum_index.html', 
                           threads=threads, 
                           user=user,
                           total_submissions=total_submissions,
                           total_accepted=total_accepted,
                           last_10_days=last_10_days,
                           daily_counts=daily_counts)

from markdown.extensions import codehilite
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters.html import HtmlFormatter

@app.route('/forum/thread/<int:thread_id>', methods=['GET', 'POST'])
def view_thread(thread_id):
    """查看单个帖子的详细信息和回复"""
    user = current_user()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM forum_threads WHERE id = %s"
            cursor.execute(sql, (thread_id,))
            thread = cursor.fetchone()

            if not thread:
                flash('帖子不存在', 'danger')
                return redirect(url_for('forum_index'))

            # 获取该帖子的所有回复
            sql = "SELECT * FROM forum_replies WHERE thread_id = %s ORDER BY created_at ASC"
            cursor.execute(sql, (thread_id,))
            replies = cursor.fetchall()

            # 使用 markdown 渲染帖子和回复内容，并为代码块添加高亮
            thread['content'] = render_markdown_with_highlighting(thread['content'])
            for reply in replies:
                reply['content'] = render_markdown_with_highlighting(reply['content'])

    finally:
        conn.close()

    if request.method == 'POST':
        content = request.form.get('content').strip()

        if not content:
            flash('回复内容不能为空', 'danger')
            return redirect(url_for('view_thread', thread_id=thread_id))

        # 创建回复
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = """INSERT INTO forum_replies (thread_id, content, user_id)
                         VALUES (%s, %s, %s)"""
                cursor.execute(sql, (thread_id, content, user['id']))
            conn.commit()
            flash('回复成功', 'success')
        finally:
            conn.close()

        return redirect(url_for('view_thread', thread_id=thread_id))

    return render_template('view_thread.html', thread=thread, replies=replies, user=user)


def render_markdown_with_highlighting(text):
    """
    渲染 Markdown 内容（移除手动代码高亮逻辑）
    """
    # 使用 markdown 库将 Markdown 转换为 HTML
    md = markdown.Markdown(extensions=['fenced_code', 'codehilite', 'extra', 'md_in_html', 'tables'])
    
    # 渲染 Markdown 内容
    html = md.convert(text)
    return html

@app.route('/forum/new', methods=['GET', 'POST'])
def create_thread():
    """创建新帖子"""
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title').strip()
        content = request.form.get('content').strip()

        if not title or not content:
            flash('标题和内容不能为空', 'danger')
            return redirect(url_for('create_thread'))

        # 创建帖子
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = """INSERT INTO forum_threads (title, content, user_id)
                         VALUES (%s, %s, %s)"""
                cursor.execute(sql, (title, content, user['id']))
            conn.commit()
            flash('帖子创建成功', 'success')
        finally:
            conn.close()

        return redirect(url_for('forum_index'))

    return render_template('create_thread.html', user=user)

@app.route('/forum/reply/<int:thread_id>', methods=['POST'])
def reply_thread(thread_id):
    """回复帖子"""
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    content = request.form.get('content').strip()

    if not content:
        flash('回复内容不能为空', 'danger')
        return redirect(url_for('view_thread', thread_id=thread_id))

    # 创建回复
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """INSERT INTO forum_replies (thread_id, content, user_id)
                     VALUES (%s, %s, %s)"""
            cursor.execute(sql, (thread_id, content, user['id']))
        conn.commit()
        flash('回复成功', 'success')
    finally:
        conn.close()

    return redirect(url_for('view_thread', thread_id=thread_id))

###############################################################################
#  AI 助教
###############################################################################

from flask import Response

def generate_completion_stream(prompt, model="Qwen3"):
    """
    使用阿里云 DashScope Apps SSE 接口的流式生成：
    - has_thoughts=True 时，服务端在思考阶段会把“思考过程”放在 output.thoughts 中（action_type="reasoning"）。
    - 当思考阶段有内容时：输出 <think> 并持续输出“思考”字符流。
    - 当进入正式输出（output.text 开始出现内容）时：先输出 </think>，再输出正文文本。
    - 为避免重复文本，维护“已发送长度”的增量输出。
    """
    import requests
    import json
    import os

    # 建议把密钥和 app_id 放到环境变量，避免硬编码在仓库
    APP_ID = DASHSCOPE_APP_ID
    API_KEY = DASHSCOPE_API_KEY

    url = f"https://dashscope.aliyuncs.com/api/v1/apps/{APP_ID}/completion"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "X-DashScope-SSE": "enable",
        "User-Agent": "Mozilla/5.0"
    }

    # 你原来在函数里写的 system 设定，这里继续保留；它会与用户 prompt 拼接后一起作为 input.prompt。
    role = """
你是一个小猫，你会说人话，你温柔可爱、学术水平高超，你需要帮小朋友分析他的代码有什么问题。
你需要特别关注小朋友的测试点得分情况。如果有 Compile Error 或者 Error，则你只需要分析语法错误，不用关注问题本身。
如果有 Time Limit Exceed，则应该分析复杂度和计算效率，而不是分析代码的正确性。
如果有 Runtime Error，则应该分析可能的内存越界、堆栈溢出等问题，另外非零返回也会被系统判断为 RE。
如果有 Wrong Answer，则需要分析代码的正确性。
""".strip()

    # 按官方示例使用 apps completion 的入参格式
    data = {
        "input": {
            # 直接把 system 与用户 prompt 合并成一个完整提示，传给 app
            "prompt": f"{role}\n\n{prompt}"
        },
        "parameters": {
            "incremental_output": True,
            "has_thoughts": True
        },
        "debug": {}
    }

    # 状态机与去重（增量）所需变量
    in_thinking = False           # 是否处于思考阶段（决定是否需要输出 <think>/</think>）
    sent_reason_len = 0           # 已输出的“思考”字符数
    sent_text_len = 0             # 已输出的“正文”字符数

    # 开始请求并流式读取
    with requests.post(url, headers=headers, json=data, stream=True) as r:
        r.raise_for_status()
        for line in r.iter_lines(decode_unicode=True):
            if not line:
                continue

            # SSE 里会有注释行、id/event 行，真正的负载在 "data:" 行
            if line.startswith(":"):
                # 形如 ":HTTP_STATUS/200" 的注释行，忽略
                continue
            if not line.startswith("data:"):
                continue

            payload = line[5:].strip()
            if payload in ("", "[DONE]"):
                continue

            try:
                packet = json.loads(payload)
            except json.JSONDecodeError:
                # 不是合法 JSON，忽略本行
                continue

            output = packet.get("output", {}) or {}

            # ============ 抽取“思考阶段”的增量文本 ============
            # thoughts 是一个数组，我们挑出 action_type == "reasoning" 的那一项
            reason_stream = ""
            thoughts = output.get("thoughts") or []
            for t in thoughts:
                if t.get("action_type") == "reasoning":
                    # 经验上 Qwen 的“思考流”可能放在 response 或 thought 或 action_input_stream
                    reason_stream = (
                        t.get("thought")
                        or ""
                    )
                    # 只关心 reasoning 这一条，找到就退出
                    break

            # 如果有思考内容：确保先打 <think>，然后只增量输出新增部分
            if reason_stream:
                if not in_thinking:
                    yield "<think>"
                    in_thinking = True
                yield reason_stream

            # ============ 抽取“正式输出”的增量文本 ============
            text_stream = output.get("text") or ""
            if text_stream:
                # 一旦正式输出开始，若仍处于思考阶段，就先闭合
                if in_thinking:
                    yield "</think>"
                    in_thinking = False
                yield text_stream

        # 连接结束后，如果还在思考阶段，补一个闭合标签
        if in_thinking:
            yield "</think>"
        

@app.route('/ask_ai', methods=['POST'])
def ask_ai():
    """
    流式返回：将 AI 的回复以文本流的方式传给前端
    """
    data = request.get_json()
    if not data:
        return jsonify(success=False, message="缺少请求体"), 400

    problem_id = data.get('problem_id', '')
    problem = get_problem(problem_id)
    problem_content = problem['content']
    user_code = data.get('user_code', '').strip()
    sid = data.get('submission_id', '')
    submission = get_submission_by_id(sid)
    test_points = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in submission["test_points"]])

    if not problem_content:
        return jsonify(success=False, message="缺少题目内容"), 400
    if not user_code:
        return jsonify(success=False, message="缺少用户代码"), 400

    # 构造提示词
    prompt = f"""你是一个小猫，你会说人话，你温柔可爱、猫美心善、学术水平高超，你需要帮小朋友分析他的代码有什么问题。
这是一道编程题，下面是题目要求：

{problem_content}

这是小朋友写的解答代码：

```matlab
{user_code}
```

这是小朋友得到的评测结果：

```
{test_points}
```

如果评测结果全是 Compile Error 或者 Error，则你不必关注问题内容，只需分析小朋友的语法错误。

如果评测结果由 Accepted 和 Time Limit Exceed 构成，则说明小朋友的代码正确性没有问题，
此时你不必分析小朋友代码的正确性，而是仅仅从复杂度或者循环效率的角度来提示小朋友如何加速。

如果有 Runtime Error，则应该分析可能的内存越界、堆栈溢出等问题。另外非零返回也会被系统判断为 RE。

如果评测结果里有 Wrong Answer，你应该指出小朋友代码里可能的问题，你需要把他错的那一行代码输出一下以便让他知道。

如果你已经发现了明显错误，并且 100% 确认这一定是关键错误，就立刻停止思考，把错误告诉小朋友。你不需要找出所有的错误，只要找到关键即可。

你不能直接给出完整的解答思路，只能告诉他改进思路。
如果他原本的代码就毫无逻辑可言，请安慰他，让他回去好好思考一下。
对了，请你给小朋友一句问候语，以体现你确实是一个小猫。
"""

    # 利用流式生成函数，返回一个生成器
    def generate_answer():
        try:
            for chunk in generate_completion_stream(prompt):
                # 这里可以选择 SSE 格式，也可以直接返回纯文本
                # SSE 格式示例：yield f"data: {chunk}\n\n"
                yield chunk
        except Exception as e:
            # 如果出错，可以把异常信息返回给前端
            yield f"\n[服务端异常] {str(e)}"

    # 返回一个流式响应
    return Response(generate_answer(), mimetype='text/plain')

# Rejudge 模块

def get_all_submissions_for_problem(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT id 
                FROM submissions
                WHERE problem_id=%s
                ORDER BY id ASC
            """
            cursor.execute(sql, (problem_id,))
            return cursor.fetchall()
    finally:
        conn.close()

from celery import chain

@celery.task
def evaluate_submission_and_update(submission_id, problem_id):
    evaluate_submission(submission_id)

    # 任务完成后 done+1
    key = f"rejudge:{problem_id}"
    rds.hincrby(key, "done", 1)

from celery import chain

@app.route('/admin/rejudge_problem/<int:problem_id>', methods=['POST'])
def rejudge_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    submissions = get_all_submissions_for_problem(problem_id)
    if not submissions:
        return jsonify(success=False, message="该题暂无提交"), 400

    # 在 Redis 新建一个Hash: rejudge:{problem_id}, 包含 total=xx, done=0
    key = f"rejudge:{problem_id}"
    rds.hmset(key, {"total": len(submissions), "done": 0})

    # 把这些提交状态都改为Pending
    for sub in submissions:
        update_submission_status(sub["id"], "Pending")

    # 用 chain 串行调用
    chain_tasks = None
    for sub in submissions:
        sid = sub["id"]
        task = evaluate_submission_and_update.si(sid, problem_id)
        if chain_tasks is None:
            chain_tasks = task
        else:
            chain_tasks = chain_tasks | task
    chain_tasks.apply_async()

    return jsonify(success=True, message="已开始重测")

@app.route('/admin/rejudge_status/<int:problem_id>', methods=['GET'])
def rejudge_status(problem_id):
    key = f"rejudge:{problem_id}"
    if not rds.exists(key):
        return jsonify(success=False, message="该题未在重测或已结束")

    info = rds.hgetall(key)   # 读出Hash: { "total": "53", "done": "0" }
    total = int(info.get("total", 0))
    done = int(info.get("done", 0))

    if total <= 0:
        return jsonify(success=False, message="总数异常")
    progress = int(done / total * 100)

    return jsonify(success=True, 
                   progress=progress,
                   done=done,
                   total=total)

# ===============================
#  期末成绩上传
# ===============================

# 老师上传期末考试成绩（Excel）
@app.route('/admin/upload_exam_scores', methods=['POST'])
def upload_exam_scores():
    """接收 Excel 表格，保存学生期末成绩"""
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400

    # 检查班级是否存在
    if not get_class_by_en(class_en):
        return jsonify(success=False, message="班级不存在"), 400

    # 检查文件
    if 'file' not in request.files:
        return jsonify(success=False, message="未选择文件"), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, message="未选择文件"), 400

    if not allowed_grade_file(file.filename):
        return jsonify(success=False, message="仅支持 .xlsx/.xls 文件"), 400

    import tempfile, shutil, os
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, file.filename)
    file.save(temp_path)

    try:
        # 解析 Excel
        wb = openpyxl.load_workbook(temp_path, data_only=True)
        sheet = wb.active
        rows = list(sheet.iter_rows(values_only=True))

        if not rows:
            return jsonify(success=False, message="Excel 文件为空"), 400

        # 如果首行是表头（非数字），则跳过
        start_idx = 0
        if isinstance(rows[0][0], str) and not rows[0][0].isdigit():
            start_idx = 1

        # 确保表存在
        create_final_exam_scores_table()

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                insert_sql = """
                    INSERT INTO final_exam_scores (class_en, student_id, regular_score, final_score)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE regular_score = VALUES(regular_score), final_score = VALUES(final_score)
                """

                for row in rows[start_idx:]:
                    if row is None:
                        continue
                    if len(row) < 3:
                        continue
                    student_id = str(row[0]).strip()
                    try:
                        regular_score = float(row[1]) if row[1] is not None else None
                        final_score = float(row[2]) if row[2] is not None else None
                    except ValueError:
                        regular_score = None
                        final_score = None
                    if not student_id or regular_score is None or final_score is None:
                        continue

                    cursor.execute(insert_sql, (class_en, student_id, regular_score, final_score))
            conn.commit()
        finally:
            conn.close()

    except Exception as e:
        return jsonify(success=False, message=f"解析 Excel 失败: {str(e)}"), 500
    finally:
        shutil.rmtree(temp_dir)

    flash('期末成绩上传成功', 'success')
    return jsonify(success=True, message="成绩上传成功")

# 创建期末考试成绩表（如不存在）
def create_final_exam_scores_table():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                CREATE TABLE IF NOT EXISTS final_exam_scores (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    class_en VARCHAR(32),
                    student_id VARCHAR(64),
                    regular_score FLOAT,
                    final_score FLOAT,
                    UNIQUE KEY uniq_class_student (class_en, student_id)
                ) CHARACTER SET utf8mb4;
            """
            cursor.execute(sql)
            # 尝试为旧表补充缺失列（向后兼容）
            try:
                cursor.execute("ALTER TABLE final_exam_scores ADD COLUMN regular_score FLOAT")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE final_exam_scores ADD COLUMN final_score FLOAT")
            except Exception:
                pass
        conn.commit()
    finally:
        conn.close()

@app.route('/admin/add_user_to_class', methods=['POST'])
def add_user_to_class():
    admin = current_user()
    if not is_admin(admin):
        return jsonify(success=False, message='无权限'), 403

    user_id = request.form.get('user_id', type=int)
    class_en = (request.form.get('class_en') or '').strip()
    if not (user_id and class_en):
        return jsonify(success=False, message='参数错误'), 400

    # 班级存在性校验
    cls = get_class_by_en(class_en)
    if not cls:
        return jsonify(success=False, message='班级不存在'), 400

    # 如果用户主班级就是该班，则无需添加到映射表
    user = get_user_by_id(user_id)
    if user and (user.get('class') == class_en):
        return jsonify(success=True, added=False, reason='already_primary',
                       message='该用户的主班级已经是此班，无需添加')

    # 进行插入；利用唯一键判断是否真的新增
    conn = get_db_connection()
    added = False
    try:
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO user_class_map (user_id, class_en, is_primary)
                VALUES (%s, %s, 0)
                ON DUPLICATE KEY UPDATE
                  is_primary = VALUES(is_primary)
            """
            cursor.execute(sql, (user_id, class_en))
            # MySQL 行为：
            # - 新增：rowcount == 1
            # - 命中唯一键且触发 UPDATE（虽然值没变）：rowcount == 2
            # 我们只把 "rowcount == 1" 视为真正新增
            added = (cursor.rowcount == 1)
        if added:
            conn.commit()
            # 只有真正新增成员时再+1
            with conn.cursor() as cursor:
                cursor.execute("UPDATE class_table SET class_cnt = class_cnt + 1 WHERE class_en=%s", (class_en,))
            conn.commit()
        else:
            conn.rollback()  # 没有新增，不需要变更
    finally:
        conn.close()

    return jsonify(success=True, added=added,
                   message=('已添加' if added else '班级已存在或无需添加'))

@app.route('/admin/remove_user_from_class', methods=['POST'])
def remove_user_from_class():
    admin = current_user()
    if not is_admin(admin): return jsonify(success=False, message='无权限'), 403

    user_id = request.form.get('user_id', type=int)
    class_en = request.form.get('class_en', '').strip()
    if not (user_id and class_en): return jsonify(success=False, message='参数错误'), 400

    # 禁止移除主班级（用 edit_user_ajax 改主班级）
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT is_primary FROM user_class_map WHERE user_id=%s AND class_en=%s",
                (user_id, class_en)
            )
            row = cursor.fetchone()
            if row and row['is_primary'] == 1:
                return jsonify(success=False, message='不能移除主班级，请使用修改主班级功能'), 400

        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM user_class_map WHERE user_id=%s AND class_en=%s",
                (user_id, class_en)
            )
        conn.commit()
        with conn.cursor() as cursor:
            cursor.execute("UPDATE class_table SET class_cnt = class_cnt - 1 WHERE class_en=%s AND class_cnt>0", (class_en,))
        conn.commit()
    finally:
        conn.close()
    return jsonify(success=True)

###############################################################################
#  用户自主班级管理 API
###############################################################################

@app.route('/me/classes', methods=['GET'])
def get_my_classes():
    """获取当前用户的班级信息"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401
    # 允许查看（即使关闭时），便于用户了解当前绑定
    
    # 获取用户所有班级（包含主班级和额外班级）
    user_classes = get_user_classes(user['id'])
    
    # 获取主班级
    primary_en = None
    for cls in user_classes:
        if cls.get('is_primary'):
            primary_en = cls['class_en']
            break
    
    # 如果映射表为空，回退到 users.class
    if not user_classes and user.get('class'):
        primary_en = user['class']
        user_classes = [{
            'class_en': user['class'],
            'class_cn': user.get('class_cn') or user['class'],
            'is_primary': 1
        }]
    
    # 获取所有可用班级（除了管理员班级）
    all_classes = get_all_classes_except_admin()
    
    return jsonify(
        success=True,
        memberships=user_classes,
        primary_en=primary_en,
        all_classes=all_classes
    )

@app.route('/me/join_class', methods=['POST'])
def join_class():
    """用户加入新班级"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401
    if not is_class_adjust_enabled():
        return jsonify(success=False, message="当前不允许调整班级，请联系老师"), 403
    
    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400
    
    # 验证班级存在且非管理员班级
    target_class = get_class_by_en(class_en)
    if not target_class:
        return jsonify(success=False, message="班级不存在"), 400
    
    if class_en == 'Cadmin':
        return jsonify(success=False, message="不能加入管理员班级"), 400
    
    # 检查是否已经是该班成员（主班级或额外班级）
    user_classes = get_user_classes(user['id'])
    for cls in user_classes:
        if cls['class_en'] == class_en:
            return jsonify(success=False, message="您已经是该班级成员"), 400
    
    # 检查主班级（兼容旧系统）
    if user.get('class') == class_en:
        return jsonify(success=False, message="您已经是该班级成员"), 400
    
    # 加入班级（作为额外班级，非主班级）
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO user_class_map (user_id, class_en, is_primary)
                VALUES (%s, %s, 0)
            """
            cursor.execute(sql, (user['id'], class_en))
        conn.commit()
        
        # 更新班级人数统计
        with conn.cursor() as cursor:
            cursor.execute("UPDATE class_table SET class_cnt = class_cnt + 1 WHERE class_en=%s", (class_en,))
        conn.commit()
        
    except Exception as e:
        return jsonify(success=False, message=f"加入班级失败: {str(e)}"), 500
    finally:
        conn.close()
    
    return jsonify(success=True, message="成功加入班级", class_cn=target_class['class_cn'])

@app.route('/me/leave_class', methods=['POST'])
def leave_class():
    """用户退出班级"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401
    if not is_class_adjust_enabled():
        return jsonify(success=False, message="当前不允许调整班级，请联系老师"), 403
    
    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400
    
    # 获取用户当前所有班级
    user_classes = get_user_classes(user['id'])
    
    # 检查是否至少有一个班级（不能全部退出）
    if len(user_classes) <= 1:
        return jsonify(success=False, message="至少需要保留一个班级"), 400
    
    # 检查是否是该班级成员
    is_member = False
    is_primary = False
    for cls in user_classes:
        if cls['class_en'] == class_en:
            is_member = True
            is_primary = cls.get('is_primary', 0) == 1
            break
    
    if not is_member:
        return jsonify(success=False, message="您不是该班级成员"), 400
    
    conn = get_db_connection()
    try:
        # 如果退出的是主班级，需要重新指定主班级
        new_primary_en = None
        if is_primary:
            # 找到第一个非当前班级作为新主班级
            for cls in user_classes:
                if cls['class_en'] != class_en:
                    new_primary_en = cls['class_en']
                    break
            
            if new_primary_en:
                # 更新 users 表的主班级
                new_primary_class = get_class_by_en(new_primary_en)
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE users SET class=%s, class_cn=%s WHERE id=%s",
                        (new_primary_en, new_primary_class['class_cn'], user['id'])
                    )
                
                # 更新映射表中的主班级标记
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE user_class_map SET is_primary=0 WHERE user_id=%s", (user['id'],))
                    cursor.execute(
                        "UPDATE user_class_map SET is_primary=1 WHERE user_id=%s AND class_en=%s",
                        (user['id'], new_primary_en)
                    )
        
        # 从映射表中删除该班级记录
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM user_class_map WHERE user_id=%s AND class_en=%s",
                (user['id'], class_en)
            )
        
        conn.commit()
        
        # 更新班级人数统计
        with conn.cursor() as cursor:
            cursor.execute("UPDATE class_table SET class_cnt = class_cnt - 1 WHERE class_en=%s AND class_cnt > 0", (class_en,))
        conn.commit()
        
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"退出班级失败: {str(e)}"), 500
    finally:
        conn.close()
    
    return jsonify(success=True, message="成功退出班级", primary_en=new_primary_en)

@app.route('/me/set_primary_class', methods=['POST'])
def set_primary_class():
    """设置主班级"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="请先登录"), 401
    if not is_class_adjust_enabled():
        return jsonify(success=False, message="当前不允许调整班级，请联系老师"), 403
    
    class_en = request.form.get('class_en', '').strip()
    if not class_en:
        return jsonify(success=False, message="缺少班级参数"), 400
    
    # 验证目标班级存在
    target_class = get_class_by_en(class_en)
    if not target_class:
        return jsonify(success=False, message="班级不存在"), 400
    
    # 检查用户是否是该班级成员
    user_classes = get_user_classes(user['id'])
    is_member = False
    for cls in user_classes:
        if cls['class_en'] == class_en:
            is_member = True
            break
    
    # 兼容旧系统：检查主班级
    if not is_member and user.get('class') == class_en:
        is_member = True
    
    if not is_member:
        return jsonify(success=False, message="您不是该班级成员"), 400
    
    # 检查是否已经是主班级
    if user.get('class') == class_en:
        return jsonify(success=True, message="已经是主班级")
    
    # 确定新主班级是否管理员班级
    is_admin_class = (class_en == 'Cadmin')
    new_is_admin = 1 if is_admin_class else 0
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 更新 users 表的主班级和管理员状态
            cursor.execute(
                "UPDATE users SET class=%s, class_cn=%s, is_admin=%s WHERE id=%s",
                (class_en, target_class['class_cn'], new_is_admin, user['id'])
            )
            
            # 更新 max_score 表的班级关联
            cursor.execute("UPDATE max_score SET class_en=%s WHERE userid=%s", (class_en, user['id']))
            
            # 更新映射表中的主班级标记
            cursor.execute("UPDATE user_class_map SET is_primary=0 WHERE user_id=%s", (user['id'],))
            cursor.execute(
                """
                INSERT INTO user_class_map (user_id, class_en, is_primary)
                VALUES (%s, %s, 1)
                ON DUPLICATE KEY UPDATE is_primary=1
                """,
                (user['id'], class_en)
            )
        
        conn.commit()
        
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"设置主班级失败: {str(e)}"), 500
    finally:
        conn.close()
    
    return jsonify(success=True, message="主班级设置成功")

###############################################################################
#  代码仓库管理
###############################################################################
@app.route('/code_repository')
def code_repository():
    """代码仓库管理页面"""
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    
    return render_template('code_repository.html', user=user)

@app.route('/api/repository/files', methods=['GET'])
def get_repository_files():
    """获取用户代码仓库文件列表"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT id, filename, file_size, created_at, updated_at 
            FROM user_code_repository 
            WHERE user_id = %s 
            ORDER BY filename
            """
            cursor.execute(sql, (user['id'],))
            files = cursor.fetchall()
            
            # 转换日期格式
            for file in files:
                file['created_at'] = file['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                file['updated_at'] = file['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
                file['file_size_kb'] = round(file['file_size'] / 1024, 2) if file['file_size'] > 0 else 0
            
            return jsonify(success=True, files=files)
    except Exception as e:
        return jsonify(success=False, message=f"获取文件列表失败: {str(e)}"), 500
    finally:
        conn.close()

@app.route('/api/repository/file/<int:file_id>', methods=['GET'])
def get_repository_file(file_id):
    """获取指定文件内容"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT filename, file_content 
            FROM user_code_repository 
            WHERE id = %s AND user_id = %s
            """
            cursor.execute(sql, (file_id, user['id']))
            file_data = cursor.fetchone()
            
            if not file_data:
                return jsonify(success=False, message="文件不存在"), 404
            
            return jsonify(success=True, filename=file_data['filename'], content=file_data['file_content'])
    except Exception as e:
        return jsonify(success=False, message=f"获取文件失败: {str(e)}"), 500
    finally:
        conn.close()

@app.route('/api/repository/file', methods=['POST'])
def save_repository_file():
    """保存或创建文件"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    
    data = request.get_json()
    filename = data.get('filename', '').strip()
    content = data.get('content', '')
    file_id = data.get('file_id')  # 如果提供了file_id，则是编辑现有文件
    
    if not filename:
        return jsonify(success=False, message="文件名不能为空"), 400
    
    # 验证文件名（只允许头文件）
    if not filename.endswith(('.h', '.hpp', '.c', '.cpp')):
        return jsonify(success=False, message="只允许上传 .h, .hpp, .c, .cpp 文件"), 400
    
    # 验证文件名格式
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        return jsonify(success=False, message="文件名只能包含字母、数字、下划线、连字符和点"), 400
    
    file_size = len(content.encode('utf-8'))
    
    # 文件大小限制 (100KB)
    if file_size > 100 * 1024:
        return jsonify(success=False, message="文件大小不能超过100KB"), 400
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if file_id:
                # 编辑现有文件
                sql = """
                UPDATE user_code_repository 
                SET filename = %s, file_content = %s, file_size = %s
                WHERE id = %s AND user_id = %s
                """
                cursor.execute(sql, (filename, content, file_size, file_id, user['id']))
                
                if cursor.rowcount == 0:
                    return jsonify(success=False, message="文件不存在或无权限"), 404
                
                message = "文件更新成功"
            else:
                # 创建新文件
                sql = """
                INSERT INTO user_code_repository (user_id, filename, file_content, file_size)
                VALUES (%s, %s, %s, %s)
                """
                try:
                    cursor.execute(sql, (user['id'], filename, content, file_size))
                    message = "文件创建成功"
                except pymysql.IntegrityError:
                    return jsonify(success=False, message="文件名已存在"), 409
            
            conn.commit()
            return jsonify(success=True, message=message)
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"保存文件失败: {str(e)}"), 500
    finally:
        conn.close()

@app.route('/api/repository/file/<int:file_id>', methods=['DELETE'])
def delete_repository_file(file_id):
    """删除文件"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "DELETE FROM user_code_repository WHERE id = %s AND user_id = %s"
            cursor.execute(sql, (file_id, user['id']))
            
            if cursor.rowcount == 0:
                return jsonify(success=False, message="文件不存在或无权限"), 404
            
            conn.commit()
            return jsonify(success=True, message="文件删除成功")
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"删除文件失败: {str(e)}"), 500
    finally:
        conn.close()

@app.route('/api/repository/upload', methods=['POST'])
def upload_repository_file():
    """上传文件"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    
    if 'file' not in request.files:
        return jsonify(success=False, message="没有选择文件"), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, message="没有选择文件"), 400
    
    filename = secure_filename(file.filename)
    
    # 验证文件扩展名
    if not filename.endswith(('.h', '.hpp', '.c', '.cpp')):
        return jsonify(success=False, message="只允许上传 .h, .hpp, .c, .cpp 文件"), 400
    
    # 读取文件内容
    try:
        content = file.read().decode('utf-8')
    except UnicodeDecodeError:
        return jsonify(success=False, message="文件编码错误，请使用UTF-8编码"), 400
    
    file_size = len(content.encode('utf-8'))
    
    # 文件大小限制 (100KB)
    if file_size > 100 * 1024:
        return jsonify(success=False, message="文件大小不能超过100KB"), 400
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            INSERT INTO user_code_repository (user_id, filename, file_content, file_size)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            file_content = VALUES(file_content),
            file_size = VALUES(file_size)
            """
            cursor.execute(sql, (user['id'], filename, content, file_size))
            
            conn.commit()
            return jsonify(success=True, message="文件上传成功")
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"上传文件失败: {str(e)}"), 500
    finally:
        conn.close()

if __name__ == '__main__':
    # 在生产环境中，请先开放 2025 端口并在安全组、系统防火墙中放行。
    app.run(host='0.0.0.0', port=2025)
