# NumericalOJ 部署指南

## 系统概述

NumericalOJ 是一个面向教学场景的中文在线判题系统，支持 MATLAB / Octave、C、C++、Python 四种语言。除了常规 OJ 的题目管理、判题与排行外，还集成了多项 AI 辅助教学能力。

### 核心功能

- **用户与班级管理**：注册、邮箱验证、班级创建与管理、按班级布置作业、成绩导出、提交次数限制。
- **代码查重与 AI 生成代码检测**：
  - 传统代码相似度查重。
  - LLM + 行为信号双通道的 AI 生成代码检测（最终分数 = `min(1.0, llm_score + behavior_score * 0.3)`）。
  - 针对 MATLAB 的专用本地 vLLM 微调检测模型。
- **编程题**：
  - 标准输入输出 + checker 评测，支持每题禁用函数白/黑名单。
  - C/C++ 编译时附带项目内 `library/` 公共头文件路径，并链接 Intel MKL。
  - 评测完成后由 AI 助教自动给出错误定位与改进建议。
- **AI 解题 / 出题智能体**：以 ReAct 循环驱动的多轮智能体，可以自动尝试解题、生成测试数据，支持图像理解与 Web 搜索（ModelScope MCP）。
- **书面作业题**：用户上传手写作业图片，系统调用大模型完成 LaTeX OCR 转写并自动评分。
- **图片批改 / 代码批注**：基于多模态模型对图片提交进行批注与评分。
- **用户头文件仓库**：每个用户可以在线编辑自己的 C/C++/MATLAB 头文件，编程题提交时可 `#include`；仓库内容会被解析为函数 / 类粒度的代码片段，并通过 FAISS + Qwen 向量嵌入提供语义检索，供智能体与用户搜索复用。
- **排行赛与 ELO 排位赛**：
  - 普通排行赛：按得分 / 用时排名。
  - ELO 模式：自动撮合用户提交两两对局并更新评分，含初始 burst 撮合、节流、单对最多 3 次 rematch、平局、管理员启停 / 重置 / 删除对局并回滚评分，以及公开的对局历史页面。
- **论坛**：题目讨论、回复、置顶等。
- **小游戏**：教学辅助的小游戏入口（如 circle-cat）。

## 系统架构

整套系统由 **三个进程** + Redis + MySQL 组成，三个进程必须同时运行：

1. **Web 服务**（`oj.py`，Flask，端口 `2025`）：承载所有 UI 与 API，并注册 Celery 任务。
2. **Celery Worker**：分为两个队列——`celery`（判题、AIGC 检测、向量索引等）与 `agent`（AI 智能体，限制并发为 1）。
3. **判题沙箱服务**（`judger/app.py`，Flask，端口 `5050`）：使用 `timeout` + `RLIMIT_CPU` / `RLIMIT_AS` 隔离运行用户代码，并在编译/执行前进行禁用函数过滤。仅允许 `127.0.0.1` 访问，必须与 Celery worker 部署在同一主机。

Redis 同时承担 Celery broker/backend、提交快照缓存、评测幂等锁、智能体进度与事件流。MySQL 库为 `myojdb`，所有持久化数据（用户、题目、提交、班级、AC 记录、智能体运行、论坛、AIGC 检测结果、用户代码仓库与向量索引元数据等）均存放于此。

## 环境要求

### 系统

- Linux / macOS / Windows
- Python 3.8+
- MySQL 8.0+
- Redis 6.0+
- 编译器：`gcc` / `g++`（C/C++ 评测，需可链接 Intel MKL）、`octave`（MATLAB/Octave 评测）、`python3`（Python 评测）
- 可选：本地 vLLM 部署（如启用 MATLAB AI 生成代码检测模型）

### Python 依赖

```bash
pip install flask pymysql markdown celery redis openpyxl werkzeug \
            requests numpy pygments faiss-cpu openai dashscope pillow
```

如需启用 `agent` 队列的 Web 搜索 MCP，还需要 `npx`（Node.js 环境）。

## 快速部署

### 1. 初始化数据库

```bash
mysql -u root -p -e "CREATE DATABASE myojdb CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"
mysql -u root -p myojdb < myojdb.sql
```

### 2. 配置 `config.py`

仓库内的 `config.py` 是模板，需要把占位符替换成真实凭据。关键字段：

```python
# 数据库
MYSQL_USERNAME = 'root'
MYSQL_PASSWORD = 'your_mysql_password'

# 邮件（验证码 / 通知）
MAIL_SERVER = 'smtp.qq.com'
MAIL_PORT = 465
MAIL_USERNAME = 'your_email@qq.com'
MAIL_PASSWORD = 'your_smtp_authorize_code'

# 阿里云 DashScope（AI 助教、智能体、书面作业评分、向量嵌入等）
DASHSCOPE_APP_ID = 'your_dashscope_app_id'
DASHSCOPE_API_KEY = 'your_dashscope_api_key'

# Coding Plan（用于 AI 编程相关接口）
CODING_PLAN_KEY = 'your_coding_plan_api_key'

# Redis
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_DB = 0
```

其他可调项（保持默认即可）：

- `QWEN_*_MODEL` / `AI_TUTOR_MODEL`：各处使用的 Qwen 模型版本。
- `MATLAB_AI_DETECT_*`：本地 vLLM 部署的 MATLAB AI 检测模型，未启用时保持占位。
- `REPOSITORY_*`：用户头文件仓库的向量化与 FAISS 索引参数。
- `AGENT_*`：AI 智能体的最大轮数、提交上限、上下文与记忆大小等。
- `MODELSCOPE_WEB_SEARCH_MCP_*`：智能体使用的网页搜索 MCP 工具配置。

### 3. 启动服务

```bash
# Redis（如未启动）
redis-server

# 判题沙箱（端口 5050）
cd judger
supervisord -c judger.conf
cd ..

# Web 服务（端口 2025）
supervisord -c web.conf

# Celery worker（两个队列）
supervisord -c celery.conf
```

系统将在 `http://localhost:2025` 启动。

## 默认账号

系统导入后包含以下默认账号：

- **管理员**
  - 用户名：`admin`
  - 密码：`admin123`
  - 邮箱：`admin@example.com`

首次登录后请立即修改密码。

## 目录结构（节选）

- `oj.py`：Flask 入口，注册所有蓝图与 Celery 任务。
- `oj_modules/routes/`：按功能划分的路由模块（题目、提交、作业、班级、排行、论坛、小游戏、AIGC 检测、AI 助教等）。
- `oj_modules/tasks/`：Celery 任务（判题、AI 智能体、书面作业评分、AIGC 检测、向量索引、ELO 撮合等）。
- `oj_modules/db_services.py`：MySQL 连接池与全部数据库访问入口。
- `oj_modules/ai_utils.py` / `oj_modules/ai_detection/` / `oj_modules/repository_index_services.py`：AI 与向量检索相关基础设施。
- `judger/`：独立的代码沙箱服务。
- `library/`、`user_libraries/`：公共与按用户的 C/C++/MATLAB 头文件库。
- `templates/`、`static/`：Web 前端模板与静态资源。
