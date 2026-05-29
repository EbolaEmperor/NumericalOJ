# NumericalOJ 部署指南

## 项目简介

我们做的是一个轻量化的 Online Judge 系统，用于大学本科 coding 作业的自动化评分。支持各种作业类型，包括：传统算法题、理论推导题、开放性工程问题。

传统 OJ（Codeforces、LeetCode）只能判定"唯一正确答案"的算法题。随着 AI 发展，简单的算法题作为作业已经没有什么价值，学生全都用 AI 生成代码直接提交，学不到任何知识；而 ACM 中 hard 级别的算法题不适合作为作业。作为老师与助教，我们需要重新思考：什么样的 coding 作业，才能锻炼学生在 AI 时代下的 coding 能力？

我们的答案是：让学生做开放性工程问题。这类问题没有标准答案，只有谁更优，而且通常需要结合各类 AI 工具去迭代调优。但是这类问题难以用传统 OJ 去评分。Kaggle 风格的打榜平台契合此趋势，但闭源、无法部署到校内轻量服务器，也不支持 MATLAB 等教学语言与手写作业批改。

于是我们做了一个轻量化的系统：把 Kaggle 风格打榜赛首次带进开源、可单机部署的教学 OJ。同时也支持传统算法题、手写的理论作业题。支持 MATLAB/C/C++/Python 四语言判题，附带班级管理、作业管理、代码查重、手写作业 OCR 批改等教学功能。内嵌了多种 AI 功能，包括：

1. 自动出题、自动造数据、自动解题的 Agent
2. 帮学生找代码 bug、划出错误代码的 AI 助教
3. 支持传统文本比对、LLM-as-Judge 等多模式结合的自动化评分系统

目前已应用于"数据结构与算法"、"数值分析"、"计算方法"、"数学软件"、"数学软件与人工智能"等多门本科课程，注册用户 900+，累计提交 4 万+ 份。

## 核心功能

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

整套系统由 **两个进程** + Redis + MySQL 组成，两个进程必须同时运行：

1. **Web 服务**（`oj.py`，Flask，端口 `2025`）：承载所有 UI 与 API，并注册 Celery 任务。
2. **Celery Worker**：分为两个队列——`celery`（判题、AIGC 检测、向量索引等）与 `agent`（AI 智能体，限制并发为 1）。判题沙箱已集成到 `celery` 队列 worker 内部，由 `oj_modules/judger_core.py` 直接调用，使用 `timeout` + `RLIMIT_CPU` / `RLIMIT_AS` 隔离运行用户代码，并在编译/执行前进行禁用函数过滤。

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
DASHSCOPE_BASE_URL = 'https://dashscope.aliyuncs.com/compatible-mode/v1'

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
- `oj_modules/judger_core.py`：集成在 Celery worker 内的判题沙箱核心。
- `oj_modules/db_services.py`：MySQL 连接池与全部数据库访问入口。
- `oj_modules/ai_utils.py` / `oj_modules/ai_detection/` / `oj_modules/repository_index_services.py`：AI 与向量检索相关基础设施。
- `library/`、`user_libraries/`：公共与按用户的 C/C++/MATLAB 头文件库。
- `templates/`、`static/`：Web 前端模板与静态资源。
