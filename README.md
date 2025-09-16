# NumericalOJ 部署指南

## 系统概述

NumericalOJ 是一个支持多语言编程（MATLAB、C/C++、Python）的在线判题系统，具有以下特性：

- 用户管理（支持多班级系统）
- 题目管理（编程题和书面作业）
- 自动评测系统
- 讨论区功能
- 成绩管理和导出

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

# AI 助教配置（可选）
DASHSCOPE_APP_ID = 'your_dashscope_app_id'
DASHSCOPE_API_KEY = 'your_dashscope_api_key'
```

### 3. 启动服务

```bash
# 启动 Redis（如果未启动）
redis-server

# 启动 Celery 工作进程（用于评测任务）
celery -A oj.celery worker --loglevel=info &

# 启动 Web 服务
python oj.py
```

系统将在 `http://localhost:2025` 启动。

### 4. 评测机配置

系统需要配合评测机使用，评测机应提供以下 API：

- `http://localhost:5050/run-hello` (MATLAB)
- `http://localhost:5050/run-c` (C)
- `http://localhost:5050/run-cpp` (C++)
- `http://localhost:5050/run-py` (Python)

## 默认账号

系统导入后包含以下默认账号：

- **管理员账号**
  - 用户名: `admin`
  - 密码: `admin123`
  - 邮箱: `admin@example.com`

## 初始数据

数据库导入后包含：

1. **默认班级**：
   - `Cadmin` - 管理员班级
   - `Cdemo2024` - 演示班级2024
   - `Ctest` - 测试班级

2. **示例题目**：
   - Hello World 问题（ID: 1）
   - 支持 MATLAB 语言
   - 包含测试数据

3. **示例作业**：
   - 演示班级包含 Hello World 作业

## 系统功能

### 用户功能
- 注册/登录（邮箱验证）
- 多班级管理（用户可自主加入/退出班级）
- 题目浏览和提交
- 查看提交记录和评测结果
- 参与讨论区
- 修改密码

### 管理员功能
- 用户管理（修改用户班级、权限）
- 班级管理（创建班级、管理作业）
- 题目管理（创建/编辑题目、上传测试数据）
- 成绩管理（查看/导出成绩）
- 书面作业批改
- 重测功能

### 支持的编程语言
- MATLAB
- C/C++
- Python

## 目录结构

```
NumericalOJ/
├── oj.py                 # 主程序
├── config.py            # 配置文件
├── myojdb.sql           # 数据库初始化脚本
├── templates/           # HTML 模板
├── static/             # 静态资源
├── uploads/            # 上传文件存储
└── tmp/                # 临时文件
```

## 安全配置

1. **修改默认密码**：首次登录后立即修改管理员密码
2. **数据库安全**：设置强密码，限制访问权限
3. **文件权限**：确保上传目录权限正确
4. **防火墙**：开放必要端口（2025, 5050）

## 故障排除

### 常见问题

1. **数据库连接失败**
   - 检查 `config.py` 中的数据库配置
   - 确认 MySQL 服务正在运行

2. **评测功能不工作**
   - 检查 Celery 工作进程是否启动
   - 确认 Redis 服务正在运行
   - 检查评测机 API 是否可访问

3. **邮件发送失败**
   - 检查邮件服务器配置
   - 确认邮箱密码/授权码正确

### 日志查看

```bash
# 查看 Web 服务日志
python oj.py

# 查看 Celery 日志
celery -A oj.celery worker --loglevel=debug
```

## 生产环境部署

对于生产环境，建议：

1. 使用 Gunicorn + Nginx 部署 Web 服务
2. 使用 Supervisor 管理进程
3. 配置 SSL 证书
4. 设置日志轮转
5. 定期备份数据库

## 技术支持

如有问题，请检查：
1. 系统日志
2. 数据库连接
3. 依赖包安装
4. 配置文件设置

## 版本信息

- 系统版本: 2.0
- 数据库版本: MySQL 8.0+
- Python 版本: 3.8+
