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

# config.py
from config import *

app = Flask(__name__)
app.secret_key = 'some_secret_key_for_session'
app.config['DEBUG'] = True
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024

# Celery 配置
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'  # 根据您的 Redis 配置调整
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

# 允许上传的文件扩展名
ALLOWED_EXTENSIONS = {'zip'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    finally:
        conn.close()

###############################################################################
#  题目相关：增/查/改
###############################################################################
def get_all_problems():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id,title,cnt,type FROM problems ORDER BY id ASC"
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()

def get_problem(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id,title,content,initial_code,cnt,forbidden_func,type FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            return cursor.fetchone()
    finally:
        conn.close()

def get_problem_title(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id,title,cnt,type FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            return cursor.fetchone()
    finally:
        conn.close()

# 修改 create_problem 和 update_problem 函数，添加 type 字段
def create_problem(title, content, initial_code='', forbidden_func='', type=1):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """INSERT INTO problems (title, content, initial_code, forbidden_func, type) 
                     VALUES (%s, %s, %s, %s, %s)"""
            cursor.execute(sql, (title, content, initial_code, forbidden_func, type))
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

def update_problem(problem_id, new_title, new_content, new_initial_code='', new_forbidden_func=''):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """UPDATE problems 
                     SET title=%s, content=%s, initial_code=%s, forbidden_func=%s
                     WHERE id=%s"""
            cursor.execute(sql, (new_title, new_content, new_initial_code, new_forbidden_func, problem_id))
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
                # 如果是第一次提交，更新班级作业、题目信息的 “完成人数” 计数器
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
        if user_record and user_record['password_hash'] == password_hash:
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

def get_ac_status(userid, problemid):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"SELECT ACP{problemid} FROM ac_record WHERE userid={userid}"
            cursor.execute(sql)
            return cursor.fetchone()
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
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"SELECT * FROM {user['class']}"
            cursor.execute(sql)
            hws = cursor.fetchall()
            for hw in hws:
                status = get_ac_status(user['id'], hw['problem_id'])
                hw['is_completed'] = status[f"ACP{hw['problem_id']}"]
                max_score = get_max_score(user['id'], hw['problem_id'])
                hw['max_score'] = max_score[f"P{hw['problem_id']}"]
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

@app.route('/problems', methods=['GET'])
def problem_list():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    # 获取今日提交和通过数
    total_submissions, total_accepted = get_today_submission_counts()

    # 获取最近十天的提交数
    last_10_days, daily_counts = get_last_10_days_submission_counts()

    if user['is_admin'] == 1:
        problems = get_all_problems()
        return render_template('problem_list.html',
                               problems=problems,
                               user=user,
                               total_submissions=total_submissions,
                               total_accepted=total_accepted,
                               last_10_days=last_10_days,
                               daily_counts=daily_counts)
    else:
        homeworks = get_homeworks(user)
        return render_template('problem_list.html',
                               homeworks=homeworks,
                               now=datetime.now(),
                               user=user,
                               total_submissions=total_submissions,
                               total_accepted=total_accepted,
                               last_10_days=last_10_days,
                               daily_counts=daily_counts)

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

        # 检查作业是否已过期
        for hw in homeworks:
            if hw['problem_id'] == problem_id:
                if hw['ddl'] and hw['ddl'] < datetime.now():
                    flash('作业已过期', 'danger')
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

    return render_template('problem_detail.html',
                           problem=problem,
                           rendered_content=rendered_content,
                           user=user,
                           last_submissions=last_submissions,
                           initial_code=initial_code)

@app.route('/admin/add_problem', methods=['GET', 'POST'])
def add_problem():
    """
    添加题目：管理员可以添加编程题或者书面作业
    """
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    if request.method == 'POST':
        title = request.form.get('title').strip()
        content = request.form.get('content').strip()
        initial_code = request.form.get('initial_code', '').strip()
        forbidden_func = request.form.get('forbidden_func', '').strip()
        problem_type = request.form.get('type')  # 获取题目类型：编程题或书面作业

        if not title or not content:
            return render_template('add_problem.html', user=user, error_message="标题和内容不能为空")

        # 创建题目
        create_problem(title, content, initial_code, forbidden_func, problem_type)

        return redirect(url_for('problem_list'))

    return render_template('add_problem.html', user=user, error_message=None)

@app.route('/admin/edit_problem/<int:problem_id>', methods=['GET', 'POST'])
def edit_problem(problem_id):
    """
    编辑题目：管理员可以修改题目的标题、内容、初始代码、禁用函数及题目类型
    """
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
        forbidden_func = request.form.get('forbidden_func', '').strip()

        if not new_title or not new_content:
            return render_template('edit_problem.html', problem=problem, user=user, error_message="标题和内容不能为空")

        # 更新题目
        update_problem(problem_id, new_title, new_content, new_initial_code, forbidden_func)
        return redirect(url_for('problem_detail', problem_id=problem_id))

    return render_template('edit_problem.html', problem=problem, user=user, error_message=None)

# 添加更新 testdata 的函数
def update_testdata(problem_id, testdata_json):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE problems SET testdata=%s WHERE id=%s"
            cursor.execute(sql, (testdata_json, problem_id))
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

            # 更新数据库中的 testdata 字段
            update_testdata(problem_id, testdata_json)

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
                           user=user)

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
    if problem and problem['type'] == 2:  # 书面作业
        file_path = f"uploads/{submission['username']}_{submission['problem_id']}_*"
        submission['file_url'] = file_path

    return render_template('submission_detail.html',
                           submission=submission,
                           test_points=submission['test_points'],
                           user=user)

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


@celery.task
def evaluate_submission(submission_id):
    """
    处理评测任务：与评测机通信，更新提交记录
    """
    submission = get_submission_by_id(submission_id)
    if not submission:
        return

    # 更新提交状态为 Running
    update_submission_status(submission_id, 'Running')

    problem_id = submission['problem_id']
    code = submission['code']

    # 获取测试数据
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
        with conn.cursor() as cursor:
            sql = "SELECT forbidden_func FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            fbd_func = cursor.fetchone()
    finally:
        conn.close()

    # 解析测试数据
    try:
        test_cases = json.loads(testdata_json)
    except json.JSONDecodeError:
        update_submission_status(submission_id, 'Error')
        return

    # 评测结果列表
    test_point_statuses = []
    all_accepted = True

    for idx, tc in enumerate(test_cases, start=1):
        payload = {
            "code": code,
            "input": tc.get("input", ""),
            "forbidden": fbd_func["forbidden_func"],
            "sid": f"eoj-{submission_id}",
            "timeLimit": 10000000000,          # 根据需要调整，单位纳秒
            "memoryLimit": 512 * 1024 * 1024  # 根据需要调整，单位字节（256MB）
        }

        try:
            response = requests.post('http://localhost:5050/run-hello', json=payload, timeout=15)
            response.raise_for_status()
            result = response.json()
        except requests.RequestException:
            # 网络错误或超时
            test_point_statuses.append({"status": "Error"})
            all_accepted = False
            continue

        status = result.get('status', 'Error')

        if status == 'Accepted':
            expected_output = tc.get("output", "").strip()
            actual_output = result.get('files', {}).get('stdout', "").strip()
            if compare_float_strings(actual_output, expected_output):
                status = 'Accepted'
            else:
                status = 'Wrong Answer'
                all_accepted = False
        else:
            all_accepted = False

        # 记录测试点状态
        test_point_statuses.append({"status": status})

    # 计算总得分
    score = sum(1 for tp in test_point_statuses if tp["status"] == "Accepted")
    user = get_user_by_username(submission['username'])

    # 更新提交记录
    if all_accepted:
        final_status = "Accepted"
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
                    with conn.cursor() as cursor:
                        sql = f"UPDATE {user['class']} SET complete_cnt=complete_cnt+1 WHERE problem_id={problem_id}"
                        cursor.execute(sql)
                    conn.commit()
        finally:
            conn.close()
    else:
        final_status = "Unaccepted"

    # 更新最高得分
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


# 修改 /admin/users 路由
@app.route('/admin/users')
def user_management():
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    # 获取查询参数
    page = request.args.get('page', 1, type=int)
    search_username = request.args.get('username', '').strip()
    search_class = request.args.get('class', '').strip()
    per_page = 50

    # 构建查询条件
    conditions = []
    params = []
    if search_username:
        conditions.append("username LIKE %s")
        params.append(f"%{search_username}%")
    if search_class:
        conditions.append("class = %s")
        params.append(search_class)

    # 基础查询语句
    base_query = "FROM users"
    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取总数
            count_sql = f"SELECT COUNT(*) AS total {base_query}"
            cursor.execute(count_sql, params)
            total = cursor.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page

            # 获取分页数据
            data_sql = f"""
                SELECT id, username, email, class, class_cn
                {base_query}
                ORDER BY id ASC
                LIMIT %s OFFSET %s
            """
            params.extend([per_page, (page-1)*per_page])
            cursor.execute(data_sql, params)
            users = cursor.fetchall()
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

    user_id = request.form.get('user_id')
    new_class = get_class_by_en(request.form.get('class'))
    user = get_user_by_id(user_id)

    if not user_id or not new_class:
        return jsonify({'success': False, 'message': '缺少必要参数'}), 400

    if new_class['class_en'] == "Cadmin":
        give_admin = 1
    else:
        give_admin = 0

    # 更新用户班级
    conn = get_db_connection()
    try:
        if user['class']:
            with conn.cursor() as cursor:
                sql = "UPDATE class_table SET class_cnt=class_cnt-1 WHERE class_en=%s"
                cursor.execute(sql, (user['class'],))
            conn.commit()
        with conn.cursor() as cursor:
            sql = "UPDATE users SET class=%s, class_cn=%s, is_admin=%s WHERE id=%s"
            cursor.execute(sql, (new_class['class_en'], new_class['class_cn'], give_admin, user_id))
        conn.commit()
        with conn.cursor() as cursor:
            sql = "UPDATE max_score SET class_en=%s WHERE userid=%s"
            cursor.execute(sql, (new_class['class_en'], user_id))
        conn.commit()
        with conn.cursor() as cursor:
            sql = "UPDATE class_table SET class_cnt=class_cnt+1 WHERE class_en=%s"
            cursor.execute(sql, (new_class['class_en'],))
        conn.commit()
    finally:
        conn.close()

    flash(f"已将 userID={user_id} 的班级修改为 {new_class['class_cn']}", 'success')
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
            sql = f"CREATE TABLE {class_en}(id INT PRIMARY KEY AUTO_INCREMENT, problem_id INT, ddl DATETIME, complete_cnt INT);"
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
    """导出指定班级的成绩（GBK编码）"""
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('login'))
    
    selected_class = request.args.get('sclass')
    if not selected_class:
        return "班级参数错误", 400
    
    # 验证班级有效性
    class_info = get_class_by_en(selected_class)
    if not class_info:
        return "班级不存在", 404
    
    # 获取该班级所有布置的题目
    homework_problems = []
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT problem_id FROM {selected_class}")
            homework_problems = cursor.fetchall()
    finally:
        conn.close()
    
    if not homework_problems:
        return "该班级没有布置任何作业", 404
    
    # 获取题目标题映射（处理中文编码问题）
    problem_ids = [p['problem_id'] for p in homework_problems]
    problem_titles = {}
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id, title FROM problems WHERE id IN (%s)" % ','.join(['%s']*len(problem_ids))
            cursor.execute(sql, problem_ids)
            for p in cursor.fetchall():
                # 处理特殊字符，替换无法编码的字符
                title = p['title'].encode('gbk', errors='replace').decode('gbk')
                problem_titles[p['id']] = title
    finally:
        conn.close()
    
    # 获取班级所有学生
    students = []
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username FROM users WHERE class = %s", (selected_class,))
            students = cursor.fetchall()
    finally:
        conn.close()
    
    # 收集成绩数据
    from io import BytesIO
    import csv
    import codecs
    
    output = BytesIO()
    # 使用GBK编码写入器
    writer = csv.writer(codecs.getwriter('gbk')(output))
    
    # 表头处理
    headers = ['用户名'] + list(problem_titles.values()) + ['总分']
    writer.writerow([h.encode('gbk', 'replace').decode('gbk') for h in headers])

    for student in students:
        conn = get_db_connection()
        max_score = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM max_score WHERE userid = %s AND class_en = %s",
                    (student['id'], selected_class)
                )
                max_score = cursor.fetchone()
        finally:
            conn.close()
        
        row = [student['username']]
        total = 0
        
        for pid in problem_ids:
            score = max_score.get(f'P{pid}', 0) if max_score else 0
            score = score or 0
            total += score
            row.append(str(score))
        
        row.append(str(total))
        # 处理每行数据的编码
        encoded_row = [cell.encode('gbk', 'replace').decode('gbk') for cell in row]
        writer.writerow(encoded_row)
    
    from flask import make_response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=GBK'
    response.headers['Content-Disposition'] = f'attachment; filename="{selected_class}_scores.csv"'
    
    return response

@app.route('/export_student_codes')
def export_student_codes():
    """导出指定班级的学生代码（按最高分最新提交）"""
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('login'))
    
    selected_class = request.args.get('sclass')
    if not selected_class:
        return "班级参数错误", 400
    
    # 验证班级有效性
    class_info = get_class_by_en(selected_class)
    if not class_info:
        return "班级不存在", 404
    
    # 获取该班级所有布置的题目
    homework_problems = []
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT problem_id FROM {selected_class}")
            homework_problems = cursor.fetchall()
    finally:
        conn.close()
    
    if not homework_problems:
        return "该班级没有布置任何作业", 404
    
    # 创建内存中的ZIP文件
    from io import BytesIO
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # 遍历每个作业题目
        for hw in homework_problems:
            problem_id = hw['problem_id']
            
            # 获取题目标题
            problem = get_problem_title(problem_id)
            if not problem:
                continue
                
            # 安全处理题目标题（替换非法字符）
            folder_name = re.sub(r'[\\/*?:"<>|]', '_', problem['title'])
            
            # 获取该题所有学生的最佳提交
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = """
                        WITH ranked_submissions AS (
                            SELECT s.id, s.username, s.code, s.score, s.created_at, u.id as userid,
                                ROW_NUMBER() OVER (
                                    PARTITION BY u.id 
                                    ORDER BY s.score DESC, s.created_at DESC
                                ) as rn
                            FROM submissions s
                            INNER JOIN users u ON s.username = u.username
                            WHERE u.class = %s AND s.problem_id = %s
                        )
                        SELECT * FROM ranked_submissions WHERE rn = 1
                    """
                    cursor.execute(sql, (selected_class, problem_id))
                    submissions = cursor.fetchall()
            finally:
                conn.close()
            
            # 将代码写入ZIP
            for sub in submissions:
                code = sub['code']
                user_id = sub['username']
                file_name = f"{folder_name}/{user_id}.m"
                zip_file.writestr(file_name, code.encode('utf-8'))
    
    # 准备响应
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

if __name__ == '__main__':
    # 在生产环境中，请先开放 2025 端口并在安全组、系统防火墙中放行。
    app.run(host='0.0.0.0', port=2025)
