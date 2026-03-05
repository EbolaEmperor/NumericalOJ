# NumericalOJ 部署指南

## 系统概述

NumericalOJ 是一个支持多语言编程（MATLAB、C/C++、Python）的在线判题系统，具有以下特性：

- 用户管理系统：创建班级、按班级布置作业、导出成绩、代码查重。
- 题目系统：
  - 编程题：与传统 OJ 类似，需配置标准输入输出、checker。评测完成后，系统会调用 AI 将用户的问题代码指出。
  - 书面作业题：用户提交手写作业后，系统调用 AI 自动进行 Latex 转写、评分。
- 代码仓库系统：用户可以创建并在线编辑自己的头文件，并在编程题中引用。

## 环境要求

### 系统要求
- Linux/macOS/Windows
- Python 3.8+
- MySQL 8.0+
- Redis 6.0+

### Python 依赖
```bash
pip install flask pymysql markdown celery redis openpyxl werkzeug requests numpy pygments
```

## 快速部署

### 1. 数据库初始化

```bash
# 创建数据库
mysql -u root -p -e "CREATE DATABASE myojdb CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"

# 导入数据库结构和初始数据
mysql -u root -p myojdb < myojdb.sql
```

### 2. 配置文件

创建 `config.py` 文件：

```python
# 数据库配置
MYSQL_USERNAME = 'root'
MYSQL_PASSWORD = 'your_mysql_password'

# 邮件服务配置（用于验证码发送）
MAIL_SERVER = 'smtp.qq.com'
MAIL_PORT = 465
MAIL_USERNAME = 'your_email@qq.com'
MAIL_PASSWORD = 'your_email_password'

# AI 配置
DASHSCOPE_APP_ID = 'your_dashscope_app_id'
DASHSCOPE_API_KEY = 'your_dashscope_api_key'
```

### 3. 启动服务

```bash
# 启动 Redis（如果未启动）
redis-server
# 启动 Celery 工作进程
supervisord -c celery.conf
# 启动 Web 服务
supervisord -c web.conf
# 启动评测端
cd judger
supervisord -c judger.conf
```

系统将在 `http://localhost:2025` 启动。

## 默认账号

系统导入后包含以下默认账号：

- **管理员账号**
  - 用户名: `admin`
  - 密码: `admin123`
  - 邮箱: `admin@example.com`
