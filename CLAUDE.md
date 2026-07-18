# CLAUDE.md

本文件是本仓库的开发与运维约束。系统概览见 `README.md`，长期维护规则见 `docs/maintenance.md`。

## 不可违反的边界

- 工作语言为中文；用户可见文案和既有中文注释保持同一风格。
- Python 基线是 **3.12**，以 `.python-version` 和 GitHub Actions 为准。
- 生产部署位于 `why-server:/home/ebola/oj/`，该主机的 hostname 是 `computing`。
- 未经用户明确要求，不得向生产部署、写生产数据、运行迁移或重启服务。
- **生产主机禁止运行任何测试**，包括纯单测、pytest、Compose、CI 脚本和测试容器。
- 生产 `config.py` 和 `static/` 可能包含本地仓库没有的内容，不得用全量同步覆盖或删除。

## 运行架构

系统有两个逻辑执行边界：Web 服务和 Celery worker 组。整体依赖 MySQL 与 Redis；执行判题任务的 worker 还必须能访问 Docker daemon。

```bash
# 0. 同步数据库结构；web.conf / celery.conf 也会在启动 worker 前执行
python3 scripts/init_db_schema.py

# 1. 本地开发 Web，端口 2025
python3 oj.py
# 生产由 web.conf 启动 Gunicorn
supervisord -c web.conf

# 2. Celery worker 组
supervisord -c celery.conf
# 等价的队列边界：
celery -A oj.celery worker -Q celery -c 16
celery -A oj.celery worker -Q agent -c 1
celery -A oj.celery worker -Q judge -c 16
```

- `celery`：普通判题、书面作业、检测、索引等常规后台任务；
- `agent`：AI 解题、造数据和 Promptly 等长任务；
- `judge`：打榜赛 Agent-as-Judge、反向评测等隔离任务。

普通判题的调用链是 `evaluate_tasks.py -> judger_core.py -> docker_sandbox.py -> Docker`。`judger_core.py` 作为库在 `celery` worker 内运行，但**用户代码在 Docker 容器内执行**；不存在旧的 `5050` 判题 HTTP 服务，也不再使用宿主进程 RLIMIT 沙箱。默认运行目录为 `<OJ_ROOT>/judger/<sid>`。

`oj.py` 在导入时创建 Flask/Celery 对象并注册任务；恢复、ELO tick 和 watchdog 等有副作用的启动工作统一由 `run_startup_jobs()` 完成。本地直接执行 `python oj.py` 时由主入口调用，生产 `web.conf` 则先执行 `scripts/run_startup_jobs.py`，再启动 Gunicorn。新增启动行为不得重新变成 import-time 写操作。

健康检查：

- `GET /health/live`：仅检查 Web 进程能否响应；
- `GET /health/ready`：执行 Redis `PING` 和 MySQL `SELECT 1`，任一失败返回 503。

## 依赖与配置

依赖文件中的直接依赖使用精确版本，职责如下：

- `requirements.txt`：生产运行依赖；
- `requirements-test.txt`：测试工具；
- `requirements-optional.txt`：默认路径不需要的重量级可选能力。

不要通过在文档中列出零散 `pip install` 命令来绕过依赖文件。新增默认功能的 import 必须同步进入 `requirements.txt`；仅用于测试或可选后端的包分别进入对应分层。依赖升级必须作为显式变更并运行相应测试。

仓库尚未提供带哈希的完整传递依赖锁文件；不得把直接 pin 描述为位级可复现构建，后续应在 Python 3.12 上生成并由 CI 校验 lock。

`config.py` 是受版本控制的模板。它会读取根目录下可选的 `.env`，但这不是全部配置的自动映射：只有显式调用 `os.getenv` 或环境变量优先读取器的选项才接受环境覆盖；MySQL、邮件等直接赋值项仍由部署专用 `config.py` 配置。已有进程环境变量优先于 `.env`，`.env` 不得入库。

关键设置：

- `MYSQL_*`、`REDIS_*`：基础设施；
- `DASHSCOPE_*`、`QWEN_*`、`AI_TUTOR_MODEL`：AI 调用；
- `REPOSITORY_*`：代码仓库解析、embedding 与 FAISS；
- `JUDGER_DOCKER_*`：普通判题镜像和容器资源；
- `AGENT_JUDGE_*`：Agent-as-Judge 镜像、资源与超时；
- `SECRET_KEY`、`SESSION_COOKIE_SECURE`、`CONTENT_SECURITY_POLICY`：Web 安全；
- `CSRF_TRUSTED_ORIGINS`：反向代理导致应用内外 Origin 不同时，显式列出可信的公开站点 Origin。

`REDIS_SOCKET_TIMEOUT_SECONDS` 默认 3 秒，避免健康检查和请求线程在 Redis 网络故障时无限等待。

## 数据库结构与迁移能力

`myojdb.sql` 是当前结构基线，`scripts/init_db_schema.py` 会：

- 创建缺失的数据库、表和动态班级作业表；
- 添加缺失列和索引；
- 在识别到列类型差异时修改列类型；
- 使用 MySQL advisory lock 避免多个进程同时同步。

它不会删除或重命名表/列，不负责数据回填，也没有 migration 版本表或已执行迁移账本。换言之，仓库目前**没有版本化迁移系统**。涉及删除、重命名、回填、约束或语义变化时：

1. 编写单独、幂等、可审计的迁移；
2. 在一次性数据库验证并记录前后置条件；
3. 部署前备份，定义代码与数据回滚路径；
4. 不要假设启动脚本能表达或回滚该变更。

所有业务连接必须经 `oj_modules.db_services.get_db_connection()` 或相应数据层取得，不要直接新建 PyMySQL 连接。动态表名必须先经 `safe_table_name()` 校验。

## 测试与数据安全

测试分层：

- `tests/unit`：无 MySQL/Redis 的纯逻辑测试；GitHub Actions 在每次 push/PR 运行全部该目录测试；
- `tests/db`：真实 MySQL/Redis 数据层测试，会重置目标数据；
- `tests/e2e`：启动本地 Flask 与 Celery，通过 `numoj-admin` / `numoj-user` CLI 走真实 HTTP；
- `tests/ci`：在本地或独立非生产服务器编排一次性 MySQL/Redis 和完整测试。

日常最低门禁：

```bash
python3 -m compileall -q oj.py oj_modules tests
python3 -m pytest -q tests/unit
```

推荐的完整测试：

```bash
docker compose -f tests/ci/docker-compose.local.yml \
  up --build --abort-on-container-exit --exit-code-from test
docker compose -f tests/ci/docker-compose.local.yml down -v --remove-orphans
```

任何会建库、清表、删动态班级表或 `FLUSHDB` 的 fixture 都必须先通过 `tests/environment_guard.py` 的 fail-closed 校验。直接运行 `tests/db` / `tests/e2e` 时必须同时满足：

- 显式设置 `NUMOJ_TEST_ENV=1`；
- MySQL 名称含测试标记，例如 `myojdb_test`，禁止默认库 `myojdb`；
- Redis 使用大于 0 的专用 DB；
- MySQL/Redis 仅指向 loopback 或测试 Compose 服务名；
- 当前主机不是 `why-server` / `computing`，检出目录不是 `/home/ebola/oj`。

不能证明目标可丢弃时必须停止，不能通过放宽 guard、捕获错误或改名绕过。

### 生产安全边界

历史上曾发生测试误连生产并清库的事故，因此：

- 不得在生产路径或读取生产 `config.py` 的 shell 中运行测试；
- 不得针对生产执行测试 fixture、seed、SQL import、修复脚本或数据重置；
- 生产默认只允许只读检查：`SELECT`、`SHOW`、`EXPLAIN`、日志和进程检查；
- 生产写入、DDL、导入和修复必须由用户明确授权，并先给出备份与回滚方案。

## 模块边界与复用约定

- `oj.py`：应用组合根；负责注册 Blueprint、Celery 任务和显式启动工作，不承载新业务逻辑。
- `oj_modules/routes/`、`oj_modules/api/`：HTTP 适配层；解析请求、鉴权、调用服务并构造响应。
- `oj_modules/tasks/`：Celery 适配层；处理重试、进度、锁和后台工作流。
- `db_services.py`、`ranking_db.py`、`ranking_*_db.py`：数据访问与事务边界。
- `*_services.py` 及领域 helper：可复用业务逻辑，不依赖 Flask request/session。
- `judger_core.py`、`docker_sandbox.py`：普通判题协议和容器执行原语。
- `templates/`、`static/`：服务端页面；不要继续把大型页面逻辑堆进单个模板。

新增后台任务继续使用现有 `register -> init` 模式：任务模块提供 `register_xxx_task(celery, ...)` 并返回绑定任务，`oj.py` 再把任务注入路由。路由不得直接导入任务私有实现。

跨模块 helper：

- `auth_helpers.py`：`current_user` / `is_admin` 与登录、管理员装饰器；
- `security_utils.py`：密码哈希、旧哈希升级、限流与冷却；
- `markdown_utils.py`：Markdown 渲染和 HTML 清洗；所有配合 `| safe` 的内容必须先清洗；
- `archive_utils.py`：带成员数、单文件大小、总大小、压缩率和路径校验的 ZIP 解压；
- `db_services.safe_table_name()`：动态 SQL 标识符校验。

禁止在路由/任务里复制这些能力。三个以上同前缀同职责文件应考虑归入子目录并简化名称，但不要为目录整齐引入无意义实体。

## Docker 镜像

普通判题：

```bash
docker build -t numericaloj-judger:latest docker/judger
docker build -t numericaloj-judger-lite:latest docker/judger-lite
```

lite 镜像使用 OpenBLAS/LAPACKE；完整镜像提供 Intel MKL 与完整 TeX。`local_dev.conf` 使用 lite，生产默认使用 `numericaloj-judger:latest`。

Agent-as-Judge：

```bash
docker build -t numericaloj-agent-judge:latest docker/agent_judge
docker build -f docker/agent_judge-lite/Dockerfile \
  -t numericaloj-agent-judge-lite:latest docker
```

修改 `docker/agent_judge/report` 或 `run_harness` 后必须重建镜像。不要给 Agent-as-Judge 的 `docker run` 增加 `--cap-drop ALL`：它会移除容器写结果和运行期 apt 所需的 `CAP_DAC_OVERRIDE`。每个比赛的 harness、base URL、API key、model 位于 MySQL，不在 `config.py`。

## 部署到 why-server

只有用户明确要求部署时才执行以下流程。

### 1. 部署前检查

- 确认当前提交、变更文件、配置兼容性和对应测试结果；
- 结构或数据变更先做生产备份并准备回滚脚本；
- Dockerfile 或镜像内脚本变更，记录旧镜像 ID/标签以便回滚；
- 确认远端目标严格为 `why-server:/home/ebola/oj/`。

### 2. 同步代码

使用 `rsync -avz` 或逐文件 `scp`，至少排除：

```text
config.py
static/
.git/
__pycache__/
tmp/
uploads/
judger/
ranking_uploads/
```

不得使用 `--delete`。生产 `config.py` 含密钥，只能由用户手工维护或在明确授权下增量修改。生产 `static/` 可能包含仓库外资产，只能按明确清单增量添加，不能批量覆盖或删除。

### 3. 重建必要镜像

- 修改 `docker/judger/**`：重建 `numericaloj-judger:latest`；
- 修改 `docker/agent_judge/**`：重建 `numericaloj-agent-judge:latest`；
- 仅 Python/模板变更不需要重建镜像。

若 `requirements*.txt` 发生变化，必须在重启前用生产服务实际使用的 Python 解释器安装对应依赖；不要临时安装未记录版本。本分支首次部署需要安装新增的 Gunicorn。

### 4. 重启

在远端用 `ps` 找到分别使用 `web.conf` 和 `celery.conf` 的两个应用 supervisord PID，只 kill 明确 PID。不要使用 `pkill -f`；不要停止 root 管理的 `/etc/supervisor/supervisord.conf`。旧版若仍有 `judger.conf` / `judger/app.py` 进程，也只能按明确 PID 清理。

从 `/home/ebola/oj/` 按顺序启动：

```bash
supervisord -c web.conf
supervisord -c celery.conf
```

`web.conf` 与 `celery.conf` 使用独立的 pidfile 和 supervisord 日志，排障时不要混淆两组进程。
`web.conf` 使用单进程、八线程的 Gunicorn `gthread` worker，以兼容现有进程内缓存和流式响应；修改 worker 数、线程数或超时前必须验证这些约束。

### 5. 验证

```bash
curl -f http://127.0.0.1:2025/health/live
curl -f http://127.0.0.1:2025/health/ready
```

随后检查三类 Celery worker 进程和对应日志，并做一个不修改生产数据的页面/API 冒烟检查。不得用 pytest 代替生产验证。

### 6. 回滚

- 代码异常：同步上一个已知正常提交并按同样顺序重启；
- 镜像异常：恢复部署前记录的镜像 ID/标签，再重启 Celery；
- 数据库异常：只执行部署前设计并验证过的回滚方案；启动同步脚本没有自动 down migration；
- 回滚后重新检查 `/health/live`、`/health/ready` 和 worker 日志。

### 前端快速路径

仅修改模板时，可以逐文件 `scp` 到 `templates/`，无需重启。生产 `FLASK_DEBUG` 应保持关闭；模板实时生效依赖 `TEMPLATES_AUTO_RELOAD=True`，不是 debug reloader。静态资产仍受上面的远端保护规则约束。

## 其他约定

- 禁用函数列表以逗号分隔，`judger_core.check_forbidden()` 按函数调用模式匹配；新增语言应保持该契约。
- 判题时间限制在任务与核心之间以纳秒传递；不要在边界中悄悄改单位。
- `competitions/` 是 gitignored 的数据集/临时工作区，不属于部署代码。
- `fix-tools/` 是一次性修复脚本，不会自动运行，生产执行必须单独授权。
- `.codex/skills/matlab-problem-setter/` 描述 MATLAB 题包格式，可作为出题结构参考。
