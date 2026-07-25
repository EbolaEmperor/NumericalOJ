# CLAUDE.md

本文件是本仓库的开发与运维约束。系统概览见 `README.md`，长期维护规则见 `docs/maintenance.md`。

## 不可违反的边界

- 工作语言为中文；用户可见文案和既有中文注释保持同一风格。
- Python 基线是 **3.12**，以 `.python-version` 和 GitHub Actions 为准。
- 生产部署位于 `why-server:/home/ebola/oj/`，该主机的 hostname 是 `computing`。
- 未经用户明确要求，不得向生产部署、写生产数据、运行迁移或重启服务。
- **生产主机禁止运行任何测试**，包括纯单测、pytest、Compose、CI 脚本和测试容器。
- 生产 `.env` 和 `static/` 的额外资产可能包含本地仓库没有的内容，不得用全量同步覆盖或删除。

## 运行架构

系统有两个逻辑执行边界：Web 服务和 Celery worker 组。整体依赖 MySQL 与 Redis；执行判题任务的 worker 还必须能访问 Docker daemon。

```bash
# 0. 本地显式同步数据库结构；生产由 deploy.sh 在停机窗口执行
python3 scripts/init_db_schema.py

# 1. 本地开发 Web，端口 2025
python3 oj.py
# 生产由 deploy.sh 准备项目内 .deploy/current-venv 后启动 Gunicorn
supervisord -c deploy/supervisor/web.conf

# 2. 生产 Celery worker 组（同样要求已有成功部署的 .deploy/current-venv）
supervisord -c deploy/supervisor/celery.conf
# 等价的队列边界：
celery -A oj.celery worker -Q celery -c 16
celery -A oj.celery worker -Q agent -c 1
celery -A oj.celery worker -Q judge -c 16
```

- `celery`：普通判题、书面作业、检测、索引等常规后台任务；
- `agent`：AI 解题、造数据和 Promptly 等长任务；
- `judge`：打榜赛 Agent-as-Judge、反向评测等隔离任务。

普通判题的调用链是 `evaluate_tasks.py -> judger_core.py -> docker_sandbox.py -> Docker`。`judger_core.py` 作为库在 `celery` worker 内运行，但**用户代码在 Docker 容器内执行**；不存在旧的 `5050` 判题 HTTP 服务，也不再使用宿主进程 RLIMIT 沙箱。默认运行目录为 `<OJ_ROOT>/judger/<sid>`。

`oj.py` 在导入时创建 Flask/Celery 对象并注册任务，但不执行外部写操作。幂等的 ELO tick、watchdog 和暂停端点探测链由 `ensure_background_schedulers()` 确保存在；本地入口和 `deploy/gunicorn.py` 的 `post_worker_init` 都可以安全调用。会清锁、重置 Running 状态和重投任务的恢复逻辑严格隔离在 `recover_pending_after_all_workers_stopped()`，只能由 `scripts/recover_pending_tasks.py --confirm-celery-stopped` 在全部 Celery worker 停止后显式执行。新增启动行为不得重新变成 import-time 写操作，也不得把破坏性恢复绑定到 Web worker 生命周期。

健康检查：

- `GET /health/live`：仅检查 Web 进程能否响应；
- `GET /health/ready`：执行 Redis `PING` 和 MySQL `SELECT 1`，任一失败返回 503。

## 依赖与配置

依赖文件中的直接依赖使用精确版本，职责如下：

- `requirements/production.txt`：生产运行依赖；
- `requirements/test.txt`：测试工具；
- `requirements/optional.txt`：默认路径不需要的重量级可选能力。

不要通过在文档中列出零散 `pip install` 命令来绕过依赖文件。新增默认功能的 import 必须同步进入 `requirements/production.txt`；仅用于测试或可选后端的包分别进入对应分层。依赖升级必须作为显式变更并运行相应测试。

仓库尚未提供带哈希的完整传递依赖锁文件；不得把直接 pin 描述为位级可复现构建，后续应在 Python 3.12 上生成并由 CI 校验 lock。

`config.py` 是受版本控制的严格类型桥接层，默认值和完整键清单位于 `.env.tmpl`；部署时复制为 Git 忽略的 `.env` 并填写真实值。配置优先级为“已有进程环境变量 > `.env` > `.env.tmpl`”，字符串使用 JSON 双引号，布尔值使用 `true` / `false`，列表使用 JSON 数组。`config_local.py` 已停用，不得把密钥写入 tracked 文件。

关键设置：

- `MYSQL_*`、`REDIS_*`：基础设施；
- `DASHSCOPE_*`、`QWEN_*`、`AI_TUTOR_MODEL`：AI 调用；
- `REPOSITORY_*`：代码仓库解析、embedding 与 FAISS；
- `JUDGER_DOCKER_*`：普通判题镜像和容器资源；
- `AGENT_JUDGE_*`：Agent-as-Judge 镜像、资源与超时；
- `SECRET_KEY`、`SESSION_COOKIE_SECURE`、`CONTENT_SECURITY_POLICY`：Web 安全；
- `CSRF_TRUSTED_ORIGINS`：反向代理导致应用内外 Origin 不同时，显式列出可信的公开站点 Origin。

Redis 客户端统一由 `oj_modules/redis_clients.py` 创建。普通命令的 `REDIS_SOCKET_TIMEOUT_SECONDS` 与 `REDIS_CONNECT_TIMEOUT_SECONDS` 默认 3 秒；Pub/Sub 使用独立的 `REDIS_BLOCKING_SOCKET_TIMEOUT_SECONDS`，默认 30 秒。业务模块不得自行构造 `Redis` / `StrictRedis`。

`TESTDATA_TEXT_MAX_TOTAL_BYTES` 是 `.env` 中可选的非敏感整数，默认 64 MiB，限制一次测试数据导入实际读入内存的 `.in/.out` 文本总量；修改后需要重启 Web 进程。

## 数据库结构与迁移能力

`database/bootstrap.sql` 是当前新安装结构与开发种子基线，`scripts/init_db_schema.py` 会：

- 创建缺失的数据库、表和动态班级作业表；
- 添加缺失列和索引；
- 在识别到列类型差异时修改列类型；
- 使用 MySQL advisory lock 避免多个进程同时同步。

它不会删除或重命名表/列，不负责数据回填，也没有 migration 版本表或已执行迁移账本。换言之，仓库目前**没有版本化迁移系统**。涉及删除、重命名、回填、约束或语义变化时，必须使用可审计的显式迁移并准备备份与回滚，不能假设启动脚本能够表达或撤销。完整数据库变更流程统一维护在 `docs/maintenance.md` 第 4 节。

所有业务连接必须经 `oj_modules.db_services.get_db_connection()` 或相应数据层取得，不要直接新建 PyMySQL 连接。动态表名必须先经 `safe_table_name()` 校验。

## 测试与数据安全

GitHub Actions 在每次 push/PR 运行语法检查、全部 `tests/unit`，并在 GitHub-hosted runner 的一次性 MySQL/Redis 上运行全部 `tests/db` 与 `tests/e2e`。判题 E2E 使用 CI 构建的 lite Docker 镜像；真实外部 AI 因无测试密钥而跳过。`tests/db`、`tests/e2e` 和 `tests/ci` 会操作真实 MySQL/Redis，只能使用一次性基础设施；完整分层、命令和选测规则以 `docs/maintenance.md` 第 3 节为唯一详细来源。

日常最低门禁：

```bash
python3 -m compileall -q oj.py oj_modules deploy tests
python3 -m pytest -q tests/unit
```

推荐的完整测试：

```bash
docker compose -f tests/ci/docker-compose.local.yml \
  up --build --abort-on-container-exit --exit-code-from test
docker compose -f tests/ci/docker-compose.local.yml down -v --remove-orphans
```

任何会建库、清表、删动态班级表或 `FLUSHDB` 的 fixture 都必须在第一次写操作前通过 `tests/environment_guard.py`。不能证明目标可丢弃时必须停止，不能通过放宽 guard、捕获错误或改名绕过；具体判定条件只在维护手册中维护。

### 生产安全边界

历史上曾发生测试误连生产并清库的事故，因此：

- 不得在生产路径或加载生产 `config.py` / `.env` 的 shell 中运行测试；
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
- `redis_clients.py`：普通、二进制、阻塞订阅和 fail-open 可选 Redis 客户端的唯一构造入口；
- `class_membership_services.py`：班级成员关系与人数计数的事务边界；
- `written_submission_artifacts.py`：人工书面作业不可变代次、DB 快照 CAS、发布 journal 与崩溃恢复；
- `db_services.safe_table_name()`：动态 SQL 标识符校验。

禁止在路由/任务里复制这些能力。三个以上同前缀同职责文件应考虑归入子目录并简化名称，但不要为目录整齐引入无意义实体。

## Docker 镜像

普通判题：

```bash
docker build -t numericaloj-judger:latest docker/judger
docker build -t numericaloj-judger-lite:latest docker/judger-lite
```

lite 镜像使用 OpenBLAS/LAPACKE；完整镜像提供 Intel MKL 与完整 TeX。`deploy/supervisor/local-dev.conf` 使用 lite，生产默认使用 `numericaloj-judger:latest`。

Agent-as-Judge：

```bash
docker build -t numericaloj-agent-judge:latest docker/agent_judge
docker build -f docker/agent_judge-lite/Dockerfile \
  -t numericaloj-agent-judge-lite:latest docker
```

修改 `docker/agent_judge/report` 或 `run_harness` 后必须重建镜像。不要给 Agent-as-Judge 的 `docker run` 增加 `--cap-drop ALL`：它会移除容器写结果和运行期 apt 所需的 `CAP_DAC_OVERRIDE`。每个比赛的 harness、base URL、API key、model 位于 MySQL，不在 `config.py`。

## 生产目录内原地部署

只有用户明确要求部署时才能操作生产。运维人员先进入目标 checkout，拉取目标版本，再原地执行：

```bash
git pull --ff-only
bash deploy.sh
```

`deploy.sh` 是唯一生产发布入口，但不负责 `git pull`，也不检测 hostname、用户名、固定安装目录或 Git 状态。它从自身路径确定项目根，可在任意目录中的 checkout 执行。脚本内部禁止运行 pytest、Compose、HTTP 探针或其他测试逻辑。

部署引导解释器必须是 Python 3.12。脚本依次接受 `NUMOJ_PYTHON`、项目内
`.deploy/bootstrap-python/bin/python3.12`、PATH 中的 `python3.12` 或版本恰当的
`python3`；不得为了部署修改系统 Python 或全局 site-packages。
生产部署还必须在任何数据库连接前 fail-closed 校验 `.env` 已加载、属于当前部署用户、
是普通文件且权限为 `0400` 或 `0600`；不得把缺失本地配置静默降级为模板默认值。

1. 持有主机级锁并校验生产配置；若 `clangd --version` 或 `bwrap --version` 不可用，先模拟并通过 Debian APT 安装精确 candidate 版本，拒绝卸载、改动既有依赖或触碰宿主关键包；再清理异常中断遗留的受管候选镜像标签，在 `.deploy/venvs/` 的非活动槽安装固定生产依赖，并核验受沙箱保护的 clangd、BasedPyright 与 Tree-sitter MATLAB 解析器；
2. 每次都为普通判题与 Agent-as-Judge 准备候选镜像；构建输入指纹未变化时复用稳定镜像并创建候选标签，变化时才重新构建；
3. 停服前以服务端 `SELECT VERSION()` 等查询为准生成唯一备份计划。兼容的本机 MySQL 8.0/8.4 使用仓库固定版本的 XtraBackup；缺失或版本不匹配时，通过交互式 `sudo` 和 Debian APT 自动安装。服务器不兼容，或自动安装失败时，计划才允许回退到 `mysqldump`；
4. 确认两套 Supervisor 可管理，再依次停止 Celery/Web；首次迁移只终止身份精确匹配的旧版 Supervisor，不使用 `pkill -f`；
5. 在全部应用写入者停止后严格执行既定计划：XtraBackup 备份整个实例并完成 `--prepare`，或只对 `MYSQL_DB` 执行 gzip level 1 的逻辑备份和完整 gzip 校验。备份未验证成功不得更新 schema；
6. 切换 `.deploy/current-venv`，执行一次非破坏性 schema 同步、过期上传暂存清理和仓库存储 doctor，再执行停机任务恢复；
7. 切换两个生产镜像标签，最佳努力启动统一日志采集器，再依次启动 Celery/Web，并在两组业务服务均启动后再次确认 Supervisor 配置中的精确进程集合全部稳定进入 `RUNNING`；重新核验真实备份产物后才把回滚点标记为成功。

脚本不复制、覆盖或删除代码文件，因此生产 `.env`、`static/` 的额外资产、上传和运行目录的保留责任属于执行 `git pull` 的 checkout 配置。除按需通过 APT 管理 clangd、Bubblewrap 的精确 candidate 版本、固定版本 XtraBackup 及其 Percona 软件源外，脚本只写 `.deploy/`、数据库备份、Docker 标签和进程状态。正常拉取只更新 tracked 的 `config.py` 解析逻辑和 `.env.tmpl` 模板，不覆盖 `.env`。部署用 Python 辅助程序统一放在 `deploy/`，不得在 `deploy.sh` 中内嵌 Python 源码或 `python -c`。

部署脚本不修改系统 Python 或全局 site-packages；两个项目内 venv 槽轮换，避免安装依赖时改变仍在运行的解释器。数据库备份保存在 `.deploy/backups/`：物理备份为 root 所有且权限 `0700`，其受管根与 `physical/` 由特权 helper 固定为 root:root `0711`；逻辑备份与清单为部署用户私有。留存顺序使用持久化单调 generation，不使用可能回拨的墙上时钟，并始终显式保护本次 run。只有业务服务全部恢复为 `RUNNING` 且真实产物再次通过 CRC/SHA 或 prepared 校验后，才按清单保留最近 2 个成功部署回滚点；失败或待人工处理的回滚点永不自动删除。脚本不自动回灌。若结构同步或启动在停服后失败，立即停止、记录失败阶段并保留现场；先判断 DDL 是否已提交，再由人工决定向前修复或恢复备份。`deploy/supervisor/web.conf`、`celery.conf` 与 `observability.conf` 使用独立 socket、pidfile 和项目内日志；Web 保持单进程、64 线程的 Gunicorn `gthread` 配置，修改并发或回收策略前必须重新验证 SSE 与进程内状态约束。

数据库部署辅助能力集中在 `deploy/backup/`：`policy.py` 是版本兼容矩阵唯一事实源，`apt.py` 只管理 Debian 软件包，`physical.py` 只执行和验证物理备份，`paths.py` 统一受管路径边界，`privileged.py` 以 dirfd 固定 inode 后完成最小特权目录硬化与删除，`orchestrator.py` 管理 plan、逻辑 fallback、manifest 与留存状态机。`deploy/backup_database.py` 仅作为稳定 CLI 入口，不得重新堆入业务实现。

## 日志与审计

统一日志实现位于 `oj_modules/observability/`，管理入口是 `scripts/log_admin.py`。所有持久
日志写入 Git 忽略的项目内 `logs/`；共享 JSONL 只能由单写采集器轮转，Web/Celery 同时
保留组件 stdout 作为采集器故障时的降级副本。新增事件必须沿用版本化 schema、递归脱敏
和 request/task 上下文，不得自行拼 JSON 或直接创建共享文件 handler。

登录审计必须记录可信客户端 IP、peer IP、User-Agent/Client Hints 和结果；提交审计必须
覆盖普通、Promptly、Agent、书面覆盖、打榜、批量和重测创建入口，但只能记录 ID、状态、
来源、长度和 SHA-256。严禁写入密码、验证码、Cookie、Authorization、API key、源码、
Prompt、答案、任务参数/返回值和评测 stdout/stderr 原文。

`LOG_TRUSTED_PROXY_CIDRS` 是唯一可信代理名单；默认不信任 `X-Forwarded-For`。基础设施采集
只读 systemd journal 中的 MySQL/Redis/Docker daemon 日志，不自动开启查询日志、Redis
`MONITOR`、Docker debug 或容器 stdout。生产日志账号的 journal 权限由运维显式配置，权限
不足必须在 `python scripts/log_admin.py doctor` 中可见，但不阻断业务部署。

### 前端快速路径

仅修改模板时，在生产 checkout 完成 `git pull` 后无需运行部署脚本或重启。生产 `FLASK_DEBUG` 应保持关闭；模板实时生效依赖 `TEMPLATES_AUTO_RELOAD=True`，不是 debug reloader。

页面统一从 `templates/layouts/base.html` 派生的 site/embedded 布局继承。MathJax 是显式 opt-in 资源；新增公式页面覆盖 `mathjax` block，普通页面不得把它重新放回全局布局。排名规则拓扑统一调用 `static/app/ranking/topology.js`；统一提交页的表格与详情面板由 `templates/submissions/components/table.html` 维护，不要在页面模板中复制私有版本。

## 其他约定

- 禁用函数列表以逗号分隔，`judger_core.check_forbidden()` 按函数调用模式匹配；新增语言应保持该契约。
- 判题时间限制在任务与核心之间以纳秒传递；不要在边界中悄悄改单位。
- `competitions/` 是 gitignored 的数据集/临时工作区，不属于部署代码。
- `.codex/skills/matlab-problem-setter/` 描述 MATLAB 题包格式，可作为出题结构参考。
