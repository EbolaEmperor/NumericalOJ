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

生产首次安装与升级统一执行 `bash deploy.sh`。下面三个 Supervisor 配置使用项目内 `.deploy/current-venv`，只适合在至少一次成功部署后做人工重启，不是本地开发入口：

```bash
supervisord -c deploy/supervisor/observability.conf
supervisord -c deploy/supervisor/web.conf
supervisord -c deploy/supervisor/celery.conf
```

生产 Supervisor 只管理进程，不执行 DDL。Web 通过 `deploy/gunicorn.py` 启动；worker 的 `post_worker_init` 只幂等确保后台自调度链存在，不会清理或重投正在执行的 Celery 任务。当前配置使用单 worker、64 个 `gthread` 线程承载 SSE，不按请求数回收 worker；`python oj.py` 仅作为本地开发入口。

完整停止两个应用边界，并已按维护手册创建、验证数据库回滚点后，如需人工恢复停机前的未完成任务，必须在 Celery 仍处于停止状态时使用当前部署虚拟环境显式执行：

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
python scripts/log_admin.py init
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

## 日志与审计

所有持久日志都位于 Git 忽略的项目内 `logs/`，PID、Supervisor socket 和部署锁仍放在
`/tmp`，它们不是日志，且需要维持跨 checkout 的主机级进程识别语义。目录由
`deploy.sh` 或以下命令以 `0700` 权限创建：

```bash
python scripts/log_admin.py init
python scripts/log_admin.py status
python scripts/log_admin.py tail audit.auth --lines 50
python scripts/log_admin.py find --submission-id 123
python scripts/log_admin.py validate
python scripts/log_admin.py doctor
```

日志按用途分开，活动 JSONL 由单个采集进程写入并轮转，避免 Gunicorn 线程和 Celery
prefork 进程竞争同一个文件：

```text
logs/
├── access/http.jsonl
├── audit/auth.jsonl
├── audit/submissions.jsonl
├── infrastructure/{mysql,redis,docker,collector}.jsonl
├── runtime/{application,tasks}.jsonl
├── services/*.log
├── supervisor/*.log
├── state/
└── run/events.sock
```

结构化事件使用版本化 schema，并通过 request ID、Celery task ID、submission ID 关联。
登录成功、失败、限流与退出会记录可信来源 IP、直连 peer、原始 User-Agent 和浏览器
Client Hints；普通、Promptly、Agent、书面覆盖及打榜提交会记录业务 ID、来源、初始状态、
内容字节数与 SHA-256，不记录源码、Prompt、答案、密码、验证码、Cookie、Authorization
或 API key。应用始终同时写组件 stdout；采集器暂时不可用时业务继续运行，事件仍可在
`logs/services/` 的组件日志中追查。

默认不信任客户端提供的 `X-Forwarded-For`。反向代理部署必须在 `.env` 的
`LOG_TRUSTED_PROXY_CIDRS` 中明确列出与应用直连的代理网段，否则登录限流和审计会使用
代理的直连地址。这是安全默认值，不能配置成无边界的公网网段。

独立的 `observability.conf` 最佳努力读取 systemd journal 中的
`mysql/mysqld/mariadb`、`redis/redis-server` 与 `docker` daemon 日志，游标和状态保存在
`logs/state/`。生产部署用户必须具有 journal 只读权限；`doctor` 会显示采集器状态，权限
不足不会阻止 Web/Celery 启动。此链路只采集 daemon 诊断日志，不会自动开启 MySQL
general/slow query log、Redis `MONITOR`、Docker debug 或判题容器 stdout，因为这些模式既
有显著 IO 成本，也可能泄露用户代码和凭据。远程/托管基础设施需要由服务方把日志送到
本机 journal 或另行接入外部日志平台。

## 测试

纯单元测试不连接 MySQL/Redis：

```bash
python -m compileall -q oj.py oj_modules deploy tests
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

Web 端的 C/C++ Monaco 编辑器通过常驻 `clangd` 进程取得实时语义令牌。clangd 与
BasedPyright 都在禁网、仅暴露运行时和临时工作区的进程沙箱中解析不可信源码；生产
Linux 使用 Bubblewrap，macOS 本地开发使用系统 Sandbox。部署脚本会在停服前核验
clangd 的实际主版本至少为 17，并核验 `bwrap --version`；缺失时才通过交互式
`sudo` 和 Debian APT 安装版本化 `clangd-19` 当前 candidate 的精确版本，不替换
系统已有的旧版 `clangd`。应用依次选择可用的 `clangd-20`、`clangd-19`、
`clangd-18`、`clangd-17`，最后才回退到版本合格的无后缀 `clangd`。安装前必须完成
APT 模拟，拒绝卸载、改动既有
依赖或触碰 MySQL、Docker、Python 等宿主关键包，安装后同时核验 dpkg 版本与可执行
文件。普通判题候选镜像构建完成后，部署脚本还会读取镜像内 gcc/g++ 的真实 include
search，把 `/usr/include`、GCC internal include、`/opt/mkl/include` 与
`/opt/library` 等头文件解引用导出到
`.deploy/editor-toolchains/` 的非活动槽，拒绝符号链接、特殊文件、路径逃逸和异常
体积，再让 clangd 对 STL、Eigen、CBLAS、LAPACKE 与 MKL 做真实语义自检。这样编辑器
认可的官方库集合始终以判题镜像为准，不依赖 Web 宿主偶然安装的开发包。任一步失败
都会在现有服务仍运行时终止部署。

Python 编辑器复用同一套持久化 LSP 桥接层，由固定版本的 BasedPyright 提供真实语义
令牌；MATLAB/Octave 编辑器使用固定版本的 Tree-sitter MATLAB 解析函数、参数、赋值、
属性和方法等结构，但不执行用户代码，也不把这种结构化高亮描述为动态类型推断。
两项运行时都随生产 venv 安装，并在停服前完成可执行文件或解析器自检；
任一服务不可用时，桌面编辑器保留本地 Shiki 词法高亮作为降级路径。

每次部署先创建安全日志目录，再清理由本脚本标记、因异常中断遗留的候选镜像标签，并在项目内 `.deploy/` 的非活动虚拟环境槽安装固定生产依赖。ARC-AGI-3 官方游戏不保存在 Git 仓库；部署会先逐文件校验 `.deploy/arc-agi-3/` 的现有完整缓存并直接复用，首次安装才通过官方 API 下载全部公开游戏，在终端显示进度条，完成环境初始化与预览生成后按内容指纹缓存。处理普通判题和 Agent-as-Judge 候选镜像时，脚本先计算 Dockerfile 与实际 `COPY` 输入的精确指纹；稳定镜像的指纹相同时直接复用，不调用构建。确需更新镜像时，脚本显式使用 `default` BuildKit builder（可通过 `NUMOJ_DOCKER_BUILDER` 覆盖）及其 Docker daemon 全局步骤缓存；生产默认缓存位于 Docker data root，而不是项目目录。脚本还会检测本地 `latest` 稳定镜像和各镜像的关键重型步骤缓存线索，并在候选镜像中写入 inline cache 元数据；任一前提缺失时会在停服前失败关闭。

候选环境和镜像就绪后，脚本以 MySQL 服务端查询结果选择备份方案。本机 Oracle MySQL / Percona Server 8.0.34+ 固定使用 XtraBackup `8.0.35-36`，8.4.x 固定使用 `8.4.0-6`；缺少或版本不匹配时会先通过交互式 `sudo` 与 Debian APT 自动安装。服务器版本或发行方不兼容，或自动安装失败时，才改为带进度的 `mysqldump` 计划。APT 变更以及版本、身份、权限和容量预检都发生在停服前；物理计划会在 Celery 排空期间维持已取得的 sudo ticket，真正执行时只接受非交互认证，避免全停服后再次等待密码。

脚本确认两套业务 Supervisor 可管理后，依次停止 Celery/Web，并再次拒绝任何额外漂移的 Gunicorn/Celery 进程，再创建零写入窗口内的数据库回滚点。XtraBackup 备份整个实例且必须完成 prepare；逻辑 fallback 只备份配置的 `MYSQL_DB`，采用 gzip level 1，并在原子发布前完整重读校验 gzip CRC。备份有效后，脚本再次确认写入者全部停止，以双确认参数幂等执行等价多班级显式迁移；迁移成功后才原子切换虚拟环境、编辑器官方头文件工具链与 ARC-AGI-3 本地公开集，执行一次非破坏性的 `scripts/init_db_schema.py`，清理过期上传暂存并运行仓库存储 doctor，再执行停机任务恢复和切换两个 `latest` 镜像标签。Web 请求和游玩过程只读取本机 ARC-AGI-3 缓存，不访问官方 API。统一日志采集 Supervisor 以最佳努力先行启动，随后依次启动 Celery/Web；最后按 Web 和 Celery 的精确 namespec 集合确认全部进程稳定进入 `RUNNING`，并重新核验真实备份产物后才将回滚点标记为成功。这是启动结果确认和备份完整性校验，不是测试。

主机级锁会拒绝来自不同 checkout 的并发部署；两个虚拟环境槽循环复用，数据库备份保存在 `.deploy/backups/`。物理备份路径由最小特权 helper 以 dirfd 固定 inode 并硬化，留存按持久化单调 generation 排序且显式保护本次 run，不依赖主机墙上时钟。成功启动全部业务进程后，按清单保留最近 2 个成功部署回滚点；失败、待处理和旧格式备份不自动删除。首次从根目录 `web.conf` / `celery.conf` 迁移时，脚本只会终止 UID、工作目录、入口和配置参数都精确匹配的旧 Supervisor，不会用模糊进程名发信号。

脚本不会修改 `.env`、业务数据文件、系统 Python 或全局 site-packages，也不会导入 `database/bootstrap.sql`、清空业务表或自动回灌备份；等价多班级显式迁移只在旧结构标记存在时删除精确限定的旧字段、索引及空的遗留 `Cadmin` 伪班级表，非空表会失败关闭。其余系统包变更仅限按需通过 APT 管理 clangd、Bubblewrap 的精确 candidate 版本和固定版本的 XtraBackup。部署辅助 Python 全部位于 `deploy/`，`deploy.sh` 本身不内嵌 Python。schema 或启动失败会记录准确阶段、保持业务停服并保留现场，必须先判断 DDL 是否已经提交，再由人工决定向前修复或恢复。

## 目录边界

- `oj.py`：应用装配、Celery 注册、幂等调度引导与显式停机恢复入口；
- `oj_modules/routes/`、`oj_modules/api/`：页面与 HTTP API；
- `oj_modules/tasks/`：Celery 后台任务；
- `oj_modules/db_services.py`、`oj_modules/ranking*_db.py`：数据访问；
- `oj_modules/judger_core.py`、`oj_modules/docker_sandbox.py`：普通判题与容器沙箱；
- `oj_modules/*_services.py`：可复用业务服务；
- `oj_modules/observability/`、`scripts/log_admin.py`：结构化事件、上下文传播、日志采集与运维查询；
- `templates/`、`static/`：按业务域组织的服务端模板和静态资源；
- `deploy/`、`deploy.sh`：生产进程配置、数据库备份和原地一键部署；
- `database/bootstrap.sql`：新安装结构与开发种子基线；
- `requirements/`：生产、测试和可选依赖分层；
- `scripts/mysql_admin.py`、`scripts/init_db_schema.py`、`scripts/migrate_remove_primary_class.py`、`scripts/recover_pending_tasks.py`：运维数据库连接、结构同步、显式数据迁移与停机恢复工具；
- `tests/unit`、`tests/db`、`tests/e2e`：按基础设施依赖分层的测试。

维护规则、变更清单、测试矩阵和发布/回滚原则见 [`docs/maintenance.md`](docs/maintenance.md)。生产部署约束见 [`CLAUDE.md`](CLAUDE.md)。
治理前基线与本轮逐项验收分别见 [`docs/reviews/initial-maintainability-review.md`](docs/reviews/initial-maintainability-review.md) 和 [`docs/reviews/2026-07-maintainability-follow-up.md`](docs/reviews/2026-07-maintainability-follow-up.md)。
