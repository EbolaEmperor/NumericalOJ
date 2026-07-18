# NumericalOJ

NumericalOJ 是面向高校教学的中文在线评测系统，支持 MATLAB/Octave、C、C++、Python。除传统编程题外，系统还提供班级与作业管理、书面作业 OCR/AI 评分、代码查重与 AI 生成检测、用户代码仓库、论坛，以及普通打榜赛、ELO 和 Agent-as-Judge 等排行模式。

## 核心能力

- 编程题：标准输入输出、checker、多测试点实时状态、禁用函数检查、C/C++ 数值库支持。
- 教学管理：班级、作业、截止时间、提交次数、成绩导出和期末成绩。
- AI 能力：代码助教、自动解题、测试数据生成、书面作业 OCR/评分、AI 生成代码检测。
- 代码仓库：用户级代码文件、函数/类结构化解析、FAISS + Qwen embedding 语义检索。
- 打榜赛：分数排名、ELO、Agent-as-Judge、反向评测、批量评测与申诉。
- 协作功能：题目论坛和教学小游戏。

## 运行架构

系统有两个逻辑执行边界，二者必须同时可用：

1. **Web 服务**：`oj.py` 创建 Flask 应用，生产由 `web.conf` 通过 Gunicorn 监听 `2025`，提供页面、HTTP API、健康检查，并完成 Celery 任务注册与依赖装配。
2. **Celery worker 组**：`celery.conf` 管理三个独立 worker：
   - `celery`：普通判题、书面作业、检测、索引等常规后台任务；
   - `agent`：耗时较长的 AI 智能体任务，生产配置并发为 1；
   - `judge`：打榜赛 Agent-as-Judge 与反向评测任务。

普通判题没有独立的 `5050` HTTP 服务。`evaluate_tasks.py` 在 `celery` worker 内调用 `oj_modules/judger_core.py`，后者通过 `oj_modules/docker_sandbox.py` 启动 Docker 容器执行用户代码。容器默认断网、只读根文件系统、非 root 运行，并设置内存、CPU 和进程数限制。

外部基础设施：

- MySQL：持久化业务数据，默认库名 `myojdb`；
- Redis：Celery broker/backend、提交快照、幂等锁、任务恢复、智能体进度和事件流；
- Docker：普通判题和 Agent-as-Judge 的隔离执行环境。

## 环境基线

- Python **3.12**（见 `.python-version` 和 GitHub Actions）；
- MySQL 8.x；
- Redis 7（CI 与本地编排基线）；
- Docker Engine；
- Linux 为生产部署目标，macOS 可用于本地开发。

`gcc`、`g++`、Octave、LaTeX、MKL/OpenBLAS 等判题工具链位于判题镜像内，不要求直接安装到 Web 进程环境。运行 Celery worker 的用户必须能访问 Docker daemon。

## 安装依赖

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

依赖按用途分层，文件中的直接依赖使用精确版本：

- `requirements.txt`：生产运行依赖；
- `requirements-test.txt`：pytest 等测试工具；
- `requirements-optional.txt`：非默认的本地 embedding 后端等重量级能力。

开发环境通常安装前两层：

```bash
python -m pip install -r requirements.txt -r requirements-test.txt
```

升级依赖时必须显式修改版本，并至少通过全部纯单元测试；涉及数据库、Redis、Docker 或外部协议时，还要通过对应的隔离测试。

当前尚未提交带哈希的完整传递依赖锁文件，因此直接依赖固定减少了漂移，但不等于位级可复现；完整锁定仍属于后续治理项。

## 配置

仓库中的 `config.py` 是可运行模板，生产部署的同名文件包含私密配置，部署时不得覆盖。至少确认以下设置：

- `MYSQL_HOST` / `MYSQL_PORT` / `MYSQL_DB` / `MYSQL_USERNAME` / `MYSQL_PASSWORD`；
- `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB`；
- `SECRET_KEY`、SMTP 和 DashScope/Qwen 配置；
- `JUDGER_*` 与 `AGENT_JUDGE_*` 镜像、资源和超时设置。

浏览器写请求统一校验 `Origin` / `Referer`。反向代理下若公开 Origin 与应用看到的 Host 不同，用 `CSRF_TRUSTED_ORIGINS` 显式列出可信 Origin；不要用通配符放开。

`config.py` 会读取仓库根目录下可选的 `.env`，并且不会覆盖进程中已经存在的环境变量。需要注意：它不是自动映射全部配置项的通用设置系统；只有显式使用 `os.getenv(...)` 或“环境变量优先”的配置读取器的选项才会生效。数据库、邮件等直接赋值项仍应在部署专用的 `config.py` 中配置。`.env` 已被 Git 忽略，不得提交密钥。

## 数据库初始化与结构同步

首次安装：

```bash
mysql -u root -p -e "CREATE DATABASE myojdb CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"
mysql -u root -p myojdb < myojdb.sql
python scripts/init_db_schema.py
```

`scripts/init_db_schema.py` 会基于 `myojdb.sql` 创建缺失的库、表、列和索引，并同步已识别的列类型；启动配置也会先运行它。它目前**不是版本化迁移系统**：没有 migration 版本表，也不负责删除/重命名、数据回填或任意约束变更。涉及这些操作时必须编写显式、可审计的迁移方案，并准备备份与回滚路径，不能仅依赖启动脚本。

默认管理员为 `admin` / `admin123`，首次登录后必须立即修改密码。

## 构建判题镜像

普通判题生产镜像包含 MKL 与完整 TeX 环境：

```bash
docker build -t numericaloj-judger:latest docker/judger
```

本地开发可使用 OpenBLAS 轻量镜像：

```bash
docker build -t numericaloj-judger-lite:latest docker/judger-lite
```

打榜赛 Agent-as-Judge 镜像：

```bash
docker build -t numericaloj-agent-judge:latest docker/agent_judge
docker build -f docker/agent_judge-lite/Dockerfile \
  -t numericaloj-agent-judge-lite:latest docker
```

`local_dev.conf` 已把两个沙箱切换为 lite 镜像；生产默认使用完整镜像。修改 `docker/agent_judge/report` 或 `docker/agent_judge/run_harness` 后必须重建 Agent-as-Judge 镜像。

## 启动

生产风格的双边界启动：

```bash
supervisord -c web.conf
supervisord -c celery.conf
```

`web.conf` 会依次执行结构同步、一次性启动恢复任务，再以 Gunicorn `gthread` worker 提供 Web 服务；`python oj.py` 仅作为本地开发入口。

本地 `.venv` + lite 镜像可以使用单个开发配置：

```bash
supervisord -c local_dev.conf
```

也可以在完成结构同步后手工启动：

```bash
python oj.py
celery -A oj.celery worker -Q celery
celery -A oj.celery worker -Q agent -c 1
celery -A oj.celery worker -Q judge -c 2
```

健康检查：

```bash
curl -f http://127.0.0.1:2025/health/live
curl -f http://127.0.0.1:2025/health/ready
```

- `/health/live` 只证明 Web 进程能响应；
- `/health/ready` 会检查 MySQL 与 Redis，任一不可用时返回 HTTP 503。

## 测试

纯单元测试不连接 MySQL/Redis：

```bash
python -m compileall -q oj.py oj_modules tests
python -m pytest -q tests/unit
```

`tests/db` 和 `tests/e2e` 会清空目标测试库及 Redis DB，受 fail-closed 安全门保护。它们只允许在明确的非生产环境运行，并同时要求：

- `NUMOJ_TEST_ENV=1`；
- MySQL 库名符合测试库命名（例如 `myojdb_test`，禁止 `myojdb`）；
- Redis 使用大于 0 的专用 DB；
- MySQL/Redis 指向 loopback 或测试 Compose 服务；
- 主机和检出路径不是 `why-server` / `computing` / `/home/ebola/oj`。

推荐使用隔离的 Docker Compose 完整测试：

```bash
docker compose -f tests/ci/docker-compose.local.yml \
  up --build --abort-on-container-exit --exit-code-from test
docker compose -f tests/ci/docker-compose.local.yml down -v --remove-orphans
```

任何测试（包括纯单元测试和容器测试）都禁止在生产主机 `why-server`（hostname `computing`）上运行。

## 目录边界

- `oj.py`：应用装配、Celery 注册、启动恢复任务；
- `oj_modules/routes/`、`oj_modules/api/`：页面与 HTTP API；
- `oj_modules/tasks/`：Celery 后台任务；
- `oj_modules/db_services.py`、`oj_modules/ranking*_db.py`：数据访问；
- `oj_modules/judger_core.py`、`oj_modules/docker_sandbox.py`：普通判题与容器沙箱；
- `oj_modules/*_services.py`：可复用业务服务；
- `templates/`、`static/`：服务端模板和静态资源；
- `scripts/init_db_schema.py`、`myojdb.sql`：当前数据库结构基线与同步工具；
- `tests/unit`、`tests/db`、`tests/e2e`：按基础设施依赖分层的测试。

维护规则、变更清单、测试矩阵和发布/回滚原则见 [`docs/maintenance.md`](docs/maintenance.md)。生产部署约束见 [`CLAUDE.md`](CLAUDE.md)。
