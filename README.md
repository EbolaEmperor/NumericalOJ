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

1. **Web 服务**：`oj.py` 创建 Flask 应用，生产由 `deploy/supervisor/web.conf` 通过 Gunicorn 监听 `2025`，提供页面、HTTP API、健康检查，并完成 Celery 任务注册与依赖装配。
2. **Celery worker 组**：`deploy/supervisor/celery.conf` 管理三个独立 worker：
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
python -m pip install -r requirements/production.txt
```

依赖按用途分层，文件中的直接依赖使用精确版本：

- `requirements/production.txt`：生产运行依赖；
- `requirements/test.txt`：pytest 等测试工具；
- `requirements/optional.txt`：非默认的本地 embedding 后端等重量级能力。

开发环境通常安装前两层：

```bash
python -m pip install -r requirements/production.txt -r requirements/test.txt
```

升级依赖时必须显式修改版本，并至少通过全部纯单元测试；涉及数据库、Redis、Docker 或外部协议时，还要通过对应的隔离测试。

当前尚未提交带哈希的完整传递依赖锁文件，因此直接依赖固定减少了漂移，但不等于位级可复现；完整锁定仍属于后续治理项。

## 配置

仓库中的 `config.py` 只负责严格解析和类型转换，配置值集中在 `.env` 中。首次配置先
复制受版本控制的 `.env.tmpl`，再填入当前环境的真实值；`.env` 已被 Git 忽略，正常的
`git pull --ff-only` 不会覆盖生产密钥：

```bash
cp .env.tmpl .env
chmod 600 .env
```

至少确认以下设置：

- `MYSQL_HOST` / `MYSQL_PORT` / `MYSQL_DB` / `MYSQL_USERNAME` / `MYSQL_PASSWORD`；
- `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` 与普通、阻塞读取的超时；
- `SECRET_KEY`、SMTP 和 DashScope/Qwen 配置；
- `JUDGER_*` 与 `AGENT_JUDGE_*` 镜像、资源和超时设置。

浏览器写请求统一校验 `Origin` / `Referer`。反向代理下若公开 Origin 与应用看到的 Host 不同，用 `CSRF_TRUSTED_ORIGINS` 显式列出可信 Origin；不要用通配符放开。

配置优先级为“进程环境变量 > `.env` > `.env.tmpl` 默认值”。字符串使用 JSON 双引号，
布尔值使用 `true` / `false`，列表使用 JSON 数组；值中的 `#`、`=`、`$` 不会被 shell
执行或插值。生产 `.env` 必须归部署用户所有，权限为 `0400` 或 `0600`，不得提交密钥。
旧的 `config_local.py` 不再被执行。

## 数据库初始化与结构同步

首次安装：

```bash
mysql -u root -p -e "CREATE DATABASE myojdb CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"
mysql -u root -p myojdb < database/bootstrap.sql
python scripts/init_db_schema.py
```

`scripts/init_db_schema.py` 会解析 `database/bootstrap.sql` 中的结构定义，创建缺失的库、表、列和索引，并同步已识别的列类型。生产进程启动不会隐式执行它；结构同步只有部署状态机一个所有者。它目前**不是版本化迁移系统**：没有 migration 版本表，也不负责删除/重命名、数据回填或任意约束变更。

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

`deploy/supervisor/local-dev.conf` 已把两个沙箱切换为 lite 镜像；生产默认使用完整镜像。修改 `docker/agent_judge/report` 或 `docker/agent_judge/run_harness` 后必须重建 Agent-as-Judge 镜像。

## 启动

生产首次安装与升级统一执行 `bash deploy.sh`。下面两个 Supervisor 配置使用项目内 `.deploy/current-venv`，只适合在至少一次成功部署后做人工重启，不是本地开发入口：

```bash
supervisord -c deploy/supervisor/web.conf
supervisord -c deploy/supervisor/celery.conf
```

生产 Supervisor 只管理进程，不执行 DDL。Web 通过 `deploy/gunicorn.py` 启动；worker 的 `post_worker_init` 只幂等确保后台自调度链存在，不会清理或重投正在执行的 Celery 任务。当前配置使用单 worker、64 个 `gthread` 线程承载 SSE，不按请求数回收 worker；`python oj.py` 仅作为本地开发入口。

完整停止两个应用边界后，如需人工恢复停机前的未完成任务，必须在 Celery 仍处于停止状态时使用当前部署虚拟环境显式执行：

```bash
.deploy/current-venv/bin/python3 scripts/init_db_schema.py
.deploy/current-venv/bin/python3 \
  scripts/recover_pending_tasks.py --confirm-celery-stopped
supervisord -c deploy/supervisor/web.conf
supervisord -c deploy/supervisor/celery.conf
```

恢复脚本会检查本机进程和 Celery ping；只重启 Web、Gunicorn worker 重建或 HUP reload 时不得运行它。

本地 `.venv` + lite 镜像可以使用单个开发配置：

```bash
supervisord -c deploy/supervisor/local-dev.conf
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

`tests/db` 和 `tests/e2e` 会清空目标测试库及 Redis DB，受 fail-closed 安全门保护，只能指向明确可丢弃的非生产基础设施。完整测试矩阵、安全门判定条件和按改动选测规则统一维护在 [`docs/maintenance.md`](docs/maintenance.md#3-测试矩阵)。

推荐使用隔离的 Docker Compose 完整测试：

```bash
docker compose -f tests/ci/docker-compose.local.yml \
  up --build --abort-on-container-exit --exit-code-from test
docker compose -f tests/ci/docker-compose.local.yml down -v --remove-orphans
```

任何测试（包括纯单元测试和容器测试）都禁止在生产主机 `why-server`（hostname `computing`）上运行。

## 一键部署

在部署目录拉取目标版本后原地执行：

```bash
git pull --ff-only
bash deploy.sh
```

`deploy.sh` 不负责拉取或同步代码，也不校验主机名、用户名、固定安装目录和 Git 状态；它以脚本所在目录为项目根，因此同一份 checkout 放在任意目录都可执行。脚本中没有测试、HTTP 探针或业务请求。

部署需要 Python 3.12。脚本依次查找 `NUMOJ_PYTHON`、项目内
`.deploy/bootstrap-python/bin/python3.12`、PATH 中的 `python3.12` 和 `python3`，
并拒绝使用其他版本。系统 Python 不是 3.12 时，可预先在 Git 忽略的
`.deploy/bootstrap-python/` 准备专用解释器，不需要修改系统 Python 或全局 PATH。
在安装依赖、构建镜像或连接数据库前，脚本还会要求 `.env` 已成功加载、是归当前部署
用户所有的普通文件、权限为 `0400` 或 `0600`，并检查必要的 MySQL、Redis 和会话配置；校验失败会
在停服前直接退出。

每次部署先清理由本脚本标记、因异常中断遗留的候选镜像标签，再在项目内 `.deploy/` 的非活动虚拟环境槽安装固定生产依赖。构建普通判题和 Agent-as-Judge 候选镜像时，脚本会先检测对应的本地 `latest` 稳定镜像：存在就通过 `--cache-from` 导入并写入 BuildKit inline cache 元数据，缺失时才冷构建。随后脚本以 `--single-transaction` 原子备份当前数据库；这些步骤不会修改仍在运行的环境。脚本再确认两套 Supervisor 均可管理，依次停止 Celery/Web，切换虚拟环境，执行一次非破坏性的 `scripts/init_db_schema.py` 和停机任务恢复，再切换两个 `latest` 镜像标签并依次启动 Celery/Web。最后再次确认两组 Supervisor 实际配置中的全部进程稳定进入 `RUNNING`，这是启动结果确认，不是测试；成功后只清理由本脚本标记的旧 dangling 镜像。

主机级锁会拒绝来自不同 checkout 的并发部署；两个虚拟环境槽循环复用，数据库备份保存在 `.deploy/backups/`。首次从根目录 `web.conf` / `celery.conf` 迁移时，脚本只会终止 UID、工作目录、入口和配置参数都精确匹配的旧 Supervisor，不会用模糊进程名发信号。脚本不会修改 `.env`、业务数据文件、系统 Python 或全局 site-packages，也不会导入 `database/bootstrap.sql`、删除表、清空表或回灌备份。失败时会报告准确阶段并保留部署前备份；如果失败发生在停服之后，修复原因后重新执行脚本，不要在没有判断 schema 兼容性的情况下自动回灌。

## 目录边界

- `oj.py`：应用装配、Celery 注册、幂等调度引导与显式停机恢复入口；
- `oj_modules/routes/`、`oj_modules/api/`：页面与 HTTP API；
- `oj_modules/tasks/`：Celery 后台任务；
- `oj_modules/db_services.py`、`oj_modules/ranking*_db.py`：数据访问；
- `oj_modules/judger_core.py`、`oj_modules/docker_sandbox.py`：普通判题与容器沙箱；
- `oj_modules/*_services.py`：可复用业务服务；
- `templates/`、`static/`：按业务域组织的服务端模板和静态资源；
- `deploy/`、`deploy.sh`：生产进程配置、数据库备份和原地一键部署；
- `database/bootstrap.sql`：新安装结构与开发种子基线；
- `requirements/`：生产、测试和可选依赖分层；
- `scripts/mysql_admin.py`、`scripts/init_db_schema.py`、`scripts/recover_pending_tasks.py`：运维数据库连接、结构同步与显式停机恢复工具；
- `tests/unit`、`tests/db`、`tests/e2e`：按基础设施依赖分层的测试。

维护规则、变更清单、测试矩阵和发布/回滚原则见 [`docs/maintenance.md`](docs/maintenance.md)。生产部署约束见 [`CLAUDE.md`](CLAUDE.md)。
治理前基线与本轮逐项验收分别见 [`docs/reviews/initial-maintainability-review.md`](docs/reviews/initial-maintainability-review.md) 和 [`docs/reviews/2026-07-maintainability-follow-up.md`](docs/reviews/2026-07-maintainability-follow-up.md)。
