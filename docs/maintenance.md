# NumericalOJ 可维护性治理手册

本文定义新代码与渐进式重构的共同标准。目标不是一次性“重写干净”，而是在不破坏教学业务和生产数据的前提下，持续降低理解、修改、验证和回滚成本。

当前运行方式与目录概览以 `README.md` 为准，必须遵守的开发和生产边界以 `CLAUDE.md` 为准；本手册只维护跨版本仍应成立的设计、验证、发布与恢复规则。`docs/reviews/` 是带日期的历史审阅快照，不作为当前操作说明。

## 1. 架构边界

NumericalOJ 保持模块化单体，不因文件较大就拆微服务。只有当独立部署、资源隔离或故障隔离带来可验证收益时，才新增进程边界。

| 边界 | 位置 | 职责 | 不应承担 |
| --- | --- | --- | --- |
| 组合根 | `oj.py` | 创建 Flask/Celery、注册 Blueprint/任务、注入依赖、显式启动工作 | 业务规则、复杂 SQL、请求级流程 |
| HTTP 适配层 | `oj_modules/routes/`、`oj_modules/api/` | 解析请求、鉴权、校验、调用服务、返回响应 | 后台任务实现、跨功能 SQL、可复用算法 |
| 后台适配层 | `oj_modules/tasks/` | Celery 重试、幂等锁、进度、超时、任务编排 | Flask request/session、页面响应 |
| 领域/应用服务 | `classroom/`、`forum/`、`homework/`、`problems/`、`ranking/`、`submissions/` 等领域包 | 可复用业务规则、事务用例、纯计算 | Blueprint 注册、Celery 装饰器 |
| 数据访问层 | 各领域包中的 `db.py`，以及尚在渐进收口的 `db_services.py` | 查询、持久化、事务和行锁 | HTTP/Celery 对象、模板 |
| 基础设施层 | `infrastructure/` | MySQL/Redis 客户端、连接池和通用连接原语 | 业务查询、HTTP/Celery 对象 |
| 能力边界 | `editor/`、`judging/`、`repository/` | 编辑器协议、判题与沙箱、代码仓库解析和索引 | Web 会话、业务页面 |
| 外部能力 | `ai/`、`integrations/` | 模型应用流程与第三方服务协议适配 | Blueprint/Celery 注册、领域持久化 |
| 跨域公共层 | `security/`、`shared/` | 安全策略和经确认的通用 helper | 某一个业务域的专有规则 |
| 运行期编排 | `runtime/` | 显式恢复、watchdog 和进程运行期协调 | import-time 写入、领域业务算法 |
| 展示层 | `templates/`、`static/` | HTML、样式、浏览器交互 | SQL、任务注册、服务端业务规则 |

期望依赖方向：

```text
routes / api ─┐
              ├─> application/domain services ─> data access
Celery tasks ─┘

evaluate task ─> judging.core ─> judging.sandbox ─> Docker

oj.py 只负责把上述组件装配起来
```

该方向用于约束新增代码和高频修改点的渐进收口。不要为了“分层”创建只转发一次调用的空壳类。

### 依赖与复用规则

- 路由和任务共享的逻辑下沉到服务/helper，不互相导入私有函数。
- `routes/`、`api/` 与 `tasks/` 是并列适配层，不允许相互导入实现；需要共享的逻辑下沉到领域包。
- 数据连接统一从 `get_db_connection()` 获取；一个业务用例需要原子性时，在同一个连接与事务中完成。
- 动态 SQL 标识符必须用 `safe_table_name()`；值始终使用参数化 SQL。
- 新任务使用 `register_xxx_task -> oj.py 注入 -> init_xxx_module`，避免路由导入绑定任务。
- Blueprint/任务的全量聚合只放在 `api/registry.py`、`tasks/registry.py` 并由组合根导入；包级 `__init__.py` 必须保持轻量，不承担历史路径重导出。
- 归档解压统一使用 `shared/archive.py` 的策略与校验，不自行调用 `ZipFile.extractall()`。
- Markdown 配合模板 `| safe` 前必须经过 `shared/markdown.py` 清洗。
- 新增状态值、事件名或跨模块字典字段时，应先寻找现有定义；同一概念出现三处后应建立唯一来源。
- 代码只导入规范包路径。根级旧模块和旧任务模块不提供导入门面；调整目录时必须同步更新仓库内调用方、测试、CLI 与运维脚本，并保持 HTTP 和 Celery wire contract。
- 函数超过约 80 行、文件超过约 800 行或同时承担三个以上职责时，触发边界复核；数字是评审信号，不是机械拆分指标。

## 2. 变更检查清单

### 设计前

- 写清业务不变量、失败语义、并发行为和兼容范围。
- 确认改动属于哪个边界，是否已有 helper、服务或协议可复用。
- 找出数据源真相：MySQL、Redis 或运行目录只能有一个权威来源，其余只能是缓存/派生数据。
- 对生产数据、外部 API、Docker 镜像或队列协议有影响时，先设计回滚路径。

### 实现时

- HTTP 层只做输入/输出适配；后台长任务进入 Celery。
- `GET` / `HEAD` 必须无副作用；写状态、注销和启动后台任务使用 `POST` / `PUT` / `PATCH` / `DELETE`，避免跨站导航和预取触发业务动作。
- 不新增 import-time 网络连接、数据库写入、任务投递或 schema 修改。
- 跨表写入、重命名、计数与配额更新使用单事务；并发配额依赖数据库锁/唯一约束，而不是“先查后写”。
- 捕获异常时记录足够上下文，并保留失败语义；禁止无说明的 `except Exception: pass`。
- 对用户、题目、提交、比赛等标识使用稳定主键；用户名等可变字段不能充当隐式外键而没有统一更新策略。
- 新增 ZIP/上传处理时设置成员数、单文件、总解压大小、压缩率与路径穿越限制。
- 临时上传和解压目录必须按请求/任务隔离，并在所有成功、失败和提前返回路径清理；需要长期保留的产物先显式复制到稳定目录。
- 文件系统与数据库共同发布时，必须明确提交点和崩溃恢复依据，并按故障模型选择不可变代次、CAS、outbox 或持久 journal；不能用进程内回调或无条件“写回旧快照”猜测最终状态。已有书面作业产物应复用 `submissions/written_artifacts.py` 的既定协议，不得复制一套近似实现。
- UI 改动优先拆模板 partial 和独立静态模块，不继续扩大单文件内联 JS/CSS。

### 依赖与配置

- 默认运行路径所需包进入 `requirements/production.txt`，测试工具进入 `requirements/test.txt`，重量级非默认能力进入 `requirements/optional.txt`。
- 直接依赖必须精确 pin；在 Python 3.12 上生成并校验完整传递依赖 lock 之前，不得宣称构建已位级可复现。升级时记录原因与兼容验证，不在生产临时 `pip install`。
- 新配置必须定义来源、类型、默认值、敏感性和是否需要重启；环境覆盖规则要有测试。
- 密钥不得写入仓库、日志、测试 fixture、镜像层或示例输出。

### 提交前

- 运行 `git diff`，确认没有无关文件、密钥、运行产物或生产配置。
- 对修改的 Python 文件运行语法检查，并按下方矩阵选择测试。
- 数据库变更同时更新结构基线、同步/迁移逻辑和数据库测试。
- API/任务协议变更验证旧调用方或给出明确迁移窗口。
- 更新 README、维护手册或运维说明中受影响的事实，不复制一份会漂移的新说明。

## 3. 测试矩阵

| 层级 | 基础设施 | 是否破坏数据 | 典型命令 | 使用场景 |
| --- | --- | --- | --- | --- |
| 语法 | 无 | 否 | `python -m compileall -q config.py oj.py oj_modules deploy scripts skills tests && python -m py_compile docker/agent_judge/report docker/agent_judge/run_harness` | 所有受版本控制的 Python 源码变更 |
| 单元 | 无 | 否 | `python -m pytest -q tests/unit` | 所有逻辑、边界和回归变更 |
| DB | 一次性 MySQL + Redis | **是** | `NUMOJ_TEST_ENV=1 python -m pytest tests/db` | 查询、事务、schema、缓存一致性 |
| E2E | 一次性 MySQL + Redis，本地 Flask/Celery，部分场景需 Docker | **是** | `NUMOJ_TEST_ENV=1 python -m pytest tests/e2e` | 路由、CLI、跨进程工作流 |
| 完整隔离 | Docker Compose | **只破坏测试数据卷** | `docker compose -f tests/ci/docker-compose.local.yml up --build --abort-on-container-exit --exit-code-from test` | 合并前或高风险变更 |

GitHub Actions 对每次 push/PR 执行语法、unit、DB 和 E2E。集成 job 使用 GitHub-hosted runner 上的一次性 MySQL 8.4/Redis 服务，构建 `numericaloj-judger-lite` 后运行真实 C/C++/Python/Octave 判题；JUnit 结果作为 artifact 保留。只有需要外部密钥的 live AI 测试默认跳过，平台具备 Node、loopback、符号链接、FIFO 与 Docker 的测试不得仅因运行在 GitHub 上而跳过。

真实反向评测浏览器 E2E 位于 `tests/e2e/test_reverse_judge_live_ui.py`。它会真实创建比赛和算法题包，用 Claude Code、Pi 各提交一次，并通过 Chromium 点击排行榜、详情四步和下载入口。该用例会产生真实模型费用，只允许在本地一次性 MySQL/Redis 上显式运行：先从 `requirements/test.txt` 安装测试依赖并执行 `python -m playwright install chromium`，再通过测试专用环境变量 `NUMOJ_REVERSE_LIVE_API_KEY` 提供密钥（不要写入站点 `.env`），最后运行：

```bash
NUMOJ_TEST_ENV=1 OJ_LIVE_AI=1 NUMOJ_REVERSE_LIVE_API_KEY='...' python -m pytest -q \
  --basetemp=tmp/reverse-live-pytest \
  tests/e2e/test_reverse_judge_live_ui.py
```

`--basetemp` 必须位于 Docker daemon 可双向访问的宿主路径；macOS + Colima 不要使用 pytest 默认的 `/private/var/...` 临时目录，否则容器内写入不会回写到宿主测试进程。GitHub CI 固定 `OJ_LIVE_AI=0`，不会下载浏览器或调用外部模型。

该用例在任何容器变更前都会校验当前 Docker context 与 `DOCKER_HOST`，只接受本机 Unix socket、Windows named pipe 或 loopback TCP，拒绝 SSH 和非 loopback daemon；测试 Web 也只监听 `127.0.0.1`。结束时会显式删除提交、比赛和端点 Key，并验证相应 DB 行与 workspace 目录均已消失，清理失败会让用例失败而不是静默遗留。

生产健康检查不属于测试矩阵，也不得嵌入 `deploy.sh`。部署完成后，运维人员可以在生产主机人工执行只读的 `curl -f http://127.0.0.1:2025/health/live` 与 `curl -f http://127.0.0.1:2025/health/ready`；前者只证明 Web 可响应，后者还检查 MySQL 与 Redis。它们不能替代发布前测试。

DB/E2E 命令只有在 `config.py` 加载后的有效配置明确指向一次性测试服务时才能执行；配置来源可以是显式环境变量、测试 `.env`，或测试镜像构建时由 `tests/ci/config.ci.py` 提供的隔离配置，不得为测试手工改写受版本控制的生产配置桥接层。安全门同时要求：

- `NUMOJ_TEST_ENV=1`；
- MySQL 库名为 `*_test`、`test_*` 或含 `_test_`，且绝不能是 `myojdb`；
- Redis DB 大于 0；
- MySQL/Redis 是 loopback 或测试 Compose 服务；
- 主机、路径均不是生产环境。

推荐优先使用 `tests/ci/docker-compose.local.yml`，它会注入安全开关和隔离配置。任何测试都不得在 `why-server` / `computing` 上运行。新增破坏性 fixture 或维护脚本时，必须在第一次写操作之前复用同等强度的 fail-closed 守卫。

### 按改动选择测试

- 纯 helper/算法：相关单测 + 全部 `tests/unit`。
- 路由/API：单测 + 对应 E2E 文件。
- SQL/事务/Redis：单测 + 对应 `tests/db` + 相关 E2E。
- 普通判题/Docker：判题与容器生命周期单测 + 有镜像环境下的对应 E2E。
- Celery 路由/恢复/幂等：任务单测 + 跨进程 E2E，检查三个队列归属。
- 模板/前端：相关路由测试 + 浏览器关键流程；至少检查桌面与窄屏。
- 依赖升级：全部单测；涉及 native wheel、MySQL/Redis 或 Docker 时跑完整隔离套件。

## 4. 数据库变更规则

### 同步器支持范围

仓库以 `database/bootstrap.sql` 为新安装结构与开发种子基线，`scripts/init_db_schema.py` 在显式调用时补齐缺失库/表/列/索引，并同步可识别的列类型。它使用 advisory lock，但**没有版本化 migration、迁移历史或自动 down migration**，也不表达删除、重命名、数据回填和复杂约束演进。生产 Supervisor 不执行结构同步；生产中只有部署状态机拥有这一职责。

因此，“启动成功”不等于所有历史数据库都完成了语义迁移，`--dry-run` 也只能显示当前同步器能识别的 DDL。

### 数据库变更流程

1. 先选择兼容策略，优先 expand-contract：新增兼容结构，双读/双写或回填，切换读取，最后在后续版本清理旧结构。
2. 更新 `database/bootstrap.sql` 作为新安装基线。
3. 只涉及缺失列/索引或列类型时，验证 `python3 scripts/init_db_schema.py --dry-run` 与实际执行结果。
4. 涉及重命名、删除、回填、约束或大表操作时，新增独立迁移脚本，包含前置检查、幂等判断、分批策略和失败恢复。
5. 在一次性数据库覆盖“旧结构 -> 新代码”和“新结构 -> 回滚代码”的兼容窗口。
6. 生产执行需要单独授权。由 `deploy.sh` 发布时，必须使用停服后、结构变更前创建并验证的回滚点；脚本之外的人工 schema/data 操作必须另行准备备份、恢复步骤与验证标准。

### LLM 端点 ID 身份迁移

`llm_endpoints.id` 是端点的唯一身份；`model` 只是发给供应商的模型标识，
允许同一模型通过不同 Base URL、账号、区域、协议或思考配置建立多个端点。
`llm_endpoints` 不保留独立 `name`，新安装由 `database/bootstrap.sql` 为 `model`
创建普通索引 `idx_llm_endpoint_model`，不创建唯一约束。

已有数据库由 `scripts/migrate_llm_endpoint_model_identity.py` 收缩旧 `name`
结构，并将 `uq_llm_endpoint_model` 替换为普通索引。脚本默认只读检查，
前向迁移只拒绝空 model、非预期字段类型和无法安全识别的索引，不拒绝重复
model。`deploy.sh` 只会在回滚点验证成功且 Web/Celery 全部停止后执行：

```bash
python3 scripts/migrate_llm_endpoint_model_identity.py
python3 scripts/migrate_llm_endpoint_model_identity.py \
  --apply --confirm-app-writers-stopped --confirm-backup-verified
```

需要向上一版代码回滚结构时，保持全部写入者停止并使用同一份已验证备份，先检查再执行：

```bash
python3 scripts/migrate_llm_endpoint_model_identity.py --rollback
python3 scripts/migrate_llm_endpoint_model_identity.py \
  --rollback --apply \
  --confirm-app-writers-stopped --confirm-backup-verified
```

结构回滚会恢复 `model` 唯一索引。如果新版本已产生重复 model，脚本会在
任何 DDL 前 fail-closed；此时应恢复部署前数据库回滚点，或先由人工合并/改名冲突端点。

### 仓库存储运维

仓库存储运维入口默认只读：

```bash
python3 scripts/repository_storage_admin.py doctor
python3 scripts/repository_storage_admin.py recover-journal
python3 scripts/repository_storage_admin.py cleanup-expired-uploads
python3 scripts/repository_storage_admin.py quarantine-orphans
```

`doctor` 核对 state/entry 数量、父子路径、大小与 SHA-256、UTF-8/LF 规范、符号链接、上传暂存、journal 和提交快照的孤儿/缺失关系。上传会话从最后活动起 24 小时过期，现有 5 分钟 watchdog 会幂等自动回收；部署停服窗口也会在 `doctor` 前补做一次清理。单用户同时最多保留 4 个活跃上传会话，活跃 staging 中原始文件与规范化副本合计不得超过仓库配额的 5 倍。手工清理需要 `--apply --confirm-expired-staging-delete`。journal 恢复和孤儿隔离都需要 `--apply --confirm-app-writers-stopped`；隔离使用同一文件系统内的原子 rename，把内容移到 `REPOSITORY_STORAGE_ROOT/quarantine/<batch>/items/`，绝不删除，并在同批 `manifest.json` 记录原路径、inode 与目标。恢复隔离项前保持应用停止，先解决导致 metadata 不一致的根因，再按 manifest 将单个 numbered item 原子移回 `source_relative`；目标已存在、inode/类型无法核对或 metadata 仍冲突时必须停止，不得覆盖猜测。

### 版本化迁移前置要求

引入版本化迁移工具前，应先定义：迁移编号与不可变性、执行账本、锁、超时、大表策略、数据迁移与 DDL 分离、备份验证、向前修复原则。不要把现有启动同步器直接包装成“已版本化迁移”。

## 5. 发布与回滚

### 发布原则

- 发布对象必须对应已知提交；禁止把未记录的远端手改当作新基线。
- `.env`、`static/` 的生产额外资产、上传、运行目录和密钥不随代码全量覆盖。
- Web 与 Celery 是两个发布边界；Python 变更按项目既定顺序完成显式停机恢复后再启动 `celery -> web`，避免 Web 在 worker 尚不可用时接受新任务。
- Gunicorn worker 重建、Web-only 重启和 HUP reload 只能执行幂等调度引导；清锁、重置 Running 或重投任务的恢复必须确认全部 Celery worker 已停止，并由独立命令触发。
- schema 先采用向后兼容扩展，再发布读取新结构的代码；没有验证兼容窗口时不做不可逆 DDL。
- 代码或镜像回退必须视为一次新的已知提交部署，并先验证当前 schema 与数据语义兼容。当前流程不持久保留旧镜像标签，不得假设本机仍存在可直接恢复的旧镜像。

### 发布步骤

生产发布由运维人员先在目标 checkout 执行 `git pull --ff-only`，再运行根目录的 `bash deploy.sh`。脚本不拉取代码，也不校验主机名、用户名、固定目录或 Git 状态；调用方负责确认当前版本。其原地部署顺序为：

1. 取得覆盖主机共享 Supervisor、Docker 和备份状态的主机级锁。引导解释器必须是 Python 3.12；在安装依赖、构建镜像或连接数据库前，fail-closed 校验生产 `.env` 的加载状态、属主、文件类型、权限与必填配置。
2. 在停服前核验 clangd 实际主版本至少为 17，并核验 `bwrap --version`。若没有合格 clangd，只允许在 Debian 上先模拟再通过 APT 安装版本化 `clangd-19` 仓库 candidate 的精确版本；不得替换或升级既有的旧版无后缀 `clangd`。应用运行时按 `clangd-20`、`clangd-19`、`clangd-18`、`clangd-17` 的顺序选择版本化可执行文件，最后才回退到版本合格的无后缀 `clangd`。模拟必须拒绝卸载、升级或降级既有依赖，以及 MySQL、Docker、Python 等宿主关键包的变更，安装后核验 dpkg 版本和 `clangd-19` 可执行文件。clangd 与 BasedPyright 必须在禁网、只读运行时加可写临时工作区的 Bubblewrap 沙箱内运行；缺少沙箱时失败关闭。随后重建非活动 venv，并准备 ARC-AGI-3 公开集和普通判题、Agent-as-Judge 候选镜像。普通判题候选镜像是官方 C/C++ 库集合的唯一事实源：部署必须分别读取镜像内 gcc/g++ 的真实 include search，把 `/usr/include`、GCC internal include、`/opt/mkl/include` 与 `/opt/library` 等头文件安全导出到 `.deploy/editor-toolchains/` 的非活动槽，解引用镜像内软链并拒绝导出结果中的软链、特殊文件、路径逃逸或异常体积；clangd 对 C/C++ 都禁用宿主默认 include search，只显式读取该槽位，再对 STL、Eigen、CBLAS、LAPACKE 与 MKL 做真实语义自检，同时核验 BasedPyright 与 Tree-sitter MATLAB。完整候选环境准备成功后才允许继续。ARC-AGI-3 已有缓存须逐文件校验哈希后直接复用；首次安装才从 ARC Prize 官方 API 下载，下载过程显示进度，初始化全部环境并生成预览。镜像构建输入未变化时可以复用稳定镜像；发生变化时必须证明本地稳定镜像和关键构建缓存可用，否则在停服前退出。具体指纹、缓存条件和基础镜像由 `deploy.sh`、Dockerfile 与契约测试维护，不在手册复制。
3. 以 MySQL 服务端查询结果生成唯一备份计划，兼容矩阵只在 `deploy/backup/policy.py` 维护。兼容的本机 Oracle MySQL/Percona Server 使用固定版本 XtraBackup；无兼容映射时使用逻辑备份。XtraBackup 缺失或版本不匹配时，先通过交互式 `sudo` 与 Debian APT 供应固定版本；APT 动作必须先模拟、限制在审核后的包集合内，并拒绝连带改动 MySQL、Docker 等宿主关键服务。供应阶段的 sudo、APT、仓库、dpkg 或二进制校验失败可以把计划确定为逻辑备份。一旦供应成功，物理 plan 的 MySQL 身份、socket/datadir、本地 socket 认证、容量或后续执行条件验证失败都必须直接停止；计划冻结后不得因备份或 prepare 失败临时换策略。MySQL 认证复用严格加载的部署配置，并通过位于私有 plans 目录、权限 `0600` 的短期 option file 交给提权后的客户端；凭据值不得进入 plan、manifest、argv、环境或输出，option file 无论成功失败都必须删除。sudo 交互认证与凭据保活必须在停服前完成，停服后只能使用 `sudo -n`，凭据失效立即停止。
4. 确认 Web/Celery 均可由受管 Supervisor 精确管理后，先优雅停止 Celery，再停止 Web，并最佳努力停止日志采集器。停止完成后再次拒绝任何漂移的 Web/worker 进程；不能证明应用写入者已全部停止时不得备份或更新结构。
5. 在零应用写入窗口创建结构变更前回滚点。物理路径备份整个 MySQL 实例、不压缩且必须完成 `xtrabackup --prepare` 与产物验证；它直接写入隔离的 run-id 目录，失败目录保留现场，只有 prepare 和验证完成后才发布 complete manifest。逻辑路径只导出配置的 `MYSQL_DB`，使用 gzip level 1、显示进度，并完整校验 gzip CRC、大小与 SHA-256；逻辑产物和 manifest 均原子发布。凭据不得进入备份子进程 argv/环境、输出或清单。相对于已停止且作为唯一写入者的 NumericalOJ，这一回滚点是 RPO 0。
6. 只有回滚点验证成功后，才再次确认 Web/Celery 仍全部停止，然后原子切换 `.deploy/current-venv`、`.deploy/current-editor-toolchain` 与 `.deploy/arc-agi-3/current`，执行带独立前置检查的显式迁移和一次非破坏性结构同步，显式清理过期上传暂存并运行仓库存储 doctor，再执行停机任务恢复，最后切换生产镜像标签。过期暂存清理必须携带 `--apply --confirm-expired-staging-delete`，文件系统审计失败时必须停止。ARC-AGI-3 的 Web 请求和游玩过程只读取该本地缓存，不访问官方 API。任一步骤失败都立即保持业务服务停止并保留现场，不自动恢复数据库，也不自动重启业务服务；先判断迁移、结构同步或其他写入是否已提交，再向前修复或使用本次已验证的数据库回滚点人工恢复。
7. 最佳努力启动日志采集器，再依次启动 Celery、Web，并按 Supervisor 的精确进程集合确认两组业务服务稳定进入 `RUNNING`。随后重新核验真实备份产物，成功后才把本次 deployment 标记为成功并执行留存清理。日志采集异常必须告警，但不能阻断健康的业务服务。

`deploy.sh` 不负责拉取代码，不检查 hostname、用户名、固定目录或 Git 状态，也不运行测试、Compose 或 HTTP 探针。它可以写入项目内受管的 `.deploy/` 与 `logs/`，其中 ARC-AGI-3 的官方游戏源码、清单和预览只作为部署缓存存在于 `.deploy/arc-agi-3/`，判题镜像导出的编辑器头文件只存在于 `.deploy/editor-toolchains/`，均不进入 Git 仓库。脚本还会更新数据库结构和停机任务恢复状态，管理 Docker 标签/缓存、Supervisor 进程与 `/tmp` 运行态文件，并在缺少合格 clangd 时通过 APT 旁路安装版本化 `clangd-19` 的精确 candidate、在缺少 Bubblewrap 时安装其精确 candidate、在需要 XtraBackup 时管理固定的 Percona 软件源和包。它不因代码发布而全量同步或清理 `.env`、`static/` 额外资产、上传与业务运行目录，也不修改系统 Python 或全局 site-packages；显式停机任务恢复仍会按照既有持久 journal 协议完成或回滚受管业务产物。

部署专用 Python 辅助实现统一维护在 `deploy/`；日志、结构同步和停机恢复继续复用 `scripts/` 中的通用运维入口。`deploy.sh` 只做 Shell 流程编排，不允许 heredoc Python 或 `python -c`。数据库备份实现按兼容策略、APT、物理执行、路径安全、特权操作和状态编排分层；稳定入口是 `deploy/backup_database.py`，服务端兼容判断不得在 `policy.py` 之外复制。

`.deploy/venvs/` 只使用两个轮换槽。数据库备份按物理产物、逻辑产物、计划与 manifest 分区；留存使用持久化单调 generation，而不是可能回拨的墙上时间，并始终保护本次 run。只有 Web/Celery 恢复且真实产物再次验证成功后，才保留最近 2 个成功部署回滚点；`pending`、`failed`、未知或旧格式产物永不自动删除。停服前失败可能留下候选 venv/镜像、日志目录、APT 或备份目录状态，但现有 Web/Celery 不会被停止；停服后失败则保持服务停止和现场。任何失败都不得触发机械回灌，应先判断 DDL 是否已提交，再选择向前修复或人工恢复。

逻辑产物、计划和 manifest 只能由部署用户读取，物理产物只能由 root 读取。备份路径出现符号链接、属主、设备或 inode 漂移时必须 fail-closed；任何特权清理只能作用于身份已重新绑定并验证的受管备份根，禁止退化为对字符串路径直接执行 `sudo rm`。

### 人工恢复 Runbook

恢复是独立的破坏性生产操作，必须在获得本次恢复的单独授权后才能执行。`deploy.sh` 只创建和管理回滚点，永远不自动回灌，也不得把下列步骤嵌入部署流程。

1. 选择 `backup_status=complete` 的 manifest，保留当前数据和失败现场，核对 manifest/plan 中的备份方式、MySQL 版本和产物路径；物理备份还必须核对 `server_uuid`、规范化 `datadir` 和 XtraBackup 精确包版本。`deployment_status=pending/failed` 不代表备份本身无效，但必须先结合 `failure_phase` 和 DDL 已提交状态完成人工判断；不得使用 `backup_status=failed`、`retention_status=deleting` 或缺失完整性事实的产物。
2. 在演练和生产恢复前，把 manifest、plan、run-id、generation 与真实产物重新绑定，并执行与部署成功前等价的只读验证。逻辑备份必须复核普通文件/属主/权限、压缩大小，并完整解压校验 gzip CRC、原始字节数和 SHA-256；物理备份必须复核 root 属主、full-prepared checkpoint、文件数/总大小、工具版本和服务器身份。`mark-success` 会修改状态，不是恢复校验命令；在提供独立只读 verify 子命令前，必须使用经过审阅且不改写清单的验证流程。
3. 先在独立的一次性 MySQL 实例上演练完整恢复：使用与 manifest 相同的 MySQL 发行方和精确版本，物理备份还要使用清单记录的 XtraBackup 精确版本。验证表数、关键业务读取和应用兼容性，记录演练结果后再进入生产操作。
4. 生产恢复前停止 Web 和全部 Celery worker，确认 NumericalOJ 不再写入。物理恢复还必须停止 MySQL，确认没有 `mysqld` 进程使用目标 `datadir`；先把现有 `datadir` 作为独立现场保留，不得直接删除或覆盖。

`database_existed=false` 的逻辑产物只是经过完整性校验的“原数据库不存在”占位记录，不包含可恢复 SQL，禁止按普通逻辑备份导入。若确需恢复到“数据库不存在”的状态，必须保留当前实例并取得单独的破坏性操作授权。

普通逻辑备份只能导入到新建或已确认清空、且与审批记录和 manifest 一致的目标库；禁止叠加到状态未知的旧库，否则备份中不存在的表会被错误保留。MySQL 凭据放在权限 `0600` 的临时 option file，禁止出现在 argv 或环境变量中。完成上述 manifest-bound 验证后，导入前仍要就地检查 gzip，并在开启 `pipefail` 的 shell 中导入：

```bash
gzip -t -- "$ARTIFACT"
set -o pipefail
gzip -dc -- "$ARTIFACT" | \
  /usr/bin/mysql --defaults-extra-file="$CREDENTIALS" --database="$DATABASE"
```

物理备份的 `$ARTIFACT` 必须是 manifest 指向且已 prepare 的 run-id 目录，目标 MySQL 的发行方、精确版本和规范化 `$DATADIR` 必须与 manifest/plan 核对一致。在 MySQL 停止、目标 `datadir` 已安全腾空且 XtraBackup 版本已校验的前提下，才能执行：

```bash
sudo /usr/bin/xtrabackup --copy-back --target-dir="$ARTIFACT"
sudo /usr/bin/chown -R mysql:mysql "$DATADIR"
sudo /usr/bin/systemctl start mysql
```

恢复后首先执行只读查询 `SELECT VERSION(), @@server_uuid, @@datadir`。精确版本必须与 manifest 一致；物理恢复的 UUID 和规范化数据目录还必须与 plan 一致，逻辑恢复则与导入前审批记录的目标实例一致。再完成表数、关键数据和应用只读验证。任一身份或数据校验失败时立即停止，不启动业务服务；全部验证通过后再按经过审批的恢复计划启动 Celery/Web。

### 回滚原则

- 代码或镜像失败：选择上一个已知正常提交，先确认 schema 与数据语义兼容，再按完整发布流程重新部署；不得假设旧镜像标签仍存在。
- 只影响单一运行边界且不涉及代码、依赖、镜像或 schema 变化时，才允许只重启该边界；不能证明隔离性时按完整发布处理。
- schema 失败：只执行预先验证的回滚或向前修复；启动同步器无法自动降级。
- 数据写入语义已变化时，不能只回滚代码；先判断新旧版本能否共同读取现有数据。
- 回滚完成后重复健康、worker 和只读业务验证，并保留故障现场日志。

## 6. 日志与审计规则

- 运行时日志根固定为项目内 `logs/`，整个目录不入 Git；Supervisor 活动日志和组件
  stdout 也不得回退到 `/tmp`。Supervisor 的 PID/socket 和部署锁继续使用 `/tmp`；日志采集器自己的 socket/lock 位于 `logs/run/`，不得混为一谈。
- 应用事件采用 `numericaloj.log` v1 单行 JSON。业务事实在数据库 commit 成功后的数据层
  出口记录，HTTP 动作在路由/请求钩子记录，Celery 生命周期由 signals 记录；同一事实
  不得在三层重复冒充成功。
- 每次登录 POST 都必须产生 success/failure/denied 之一，并记录可信客户端 IP、直连 peer IP、User-Agent 与 Client Hints；每次普通、书面覆盖、Agent、
  Promptly、打榜、后台批量和重测创建都必须产生提交审计事件。日志不是业务事实库；若未来要求
  与事务严格零丢失，应引入数据库 outbox，不能假设文件写入和 MySQL commit 原子。
- request ID 由服务端生成并通过 Celery header 白名单传播。客户端 IP 只在直连 peer 属于
  `LOG_TRUSTED_PROXY_CIDRS` 时解析 `X-Forwarded-For`；认证限流和审计必须共用同一解析器。
- 只允许记录必要元数据。源码、Prompt、答案、请求体、任务 args/result、评测 stdout/stderr 原文、密码、验证码、
  Cookie、Authorization、API key 和带凭据 URL 禁止入日志；内容只记字节数和 SHA-256。
- 共享 JSONL 只能由 `scripts/log_admin.py serve` 单写和轮转，多进程业务代码不得直接挂
  `RotatingFileHandler` 写同一文件。采集器失败时应用走 stdout 降级，不能影响业务事务。
- MySQL、Redis、Docker 默认只读取 systemd journal 中的 daemon 诊断日志。禁止为了本
  项目自动开启 MySQL general query、Redis `MONITOR`、Docker debug 或全容器 stdout。
  journal 权限由主机运维显式授予；远程服务必须配置外部日志出口。
- 日常用 `scripts/log_admin.py status|tail|find|validate|doctor` 检查。轮转上限是容量边界，
  不是合规留存承诺；若有固定留存期或跨主机灾备要求，应接入外部不可变日志平台。

## 7. 前端模板结构

模板按“布局 → 跨域组件 → 业务域页面 → 业务域局部组件”组织：

```text
templates/
├── layouts/                 # 页面骨架，不包含具体业务流程
├── components/              # 跨业务域复用的导航、编辑器、全局弹窗
├── shared/                  # 错误页等通用完整页面
├── auth|admin|problems|…/   # 路由直接渲染的业务页面
└── ranking/
    ├── tabs/                # 打榜详情各独立功能面板
    ├── components/          # AJAX 与页面共用的行、卡片、分页
    ├── modals/              # 页面级单例弹窗
    ├── settings/            # 比赛设置中的端点、规则等职责片段
    └── scripts/             # 同一业务域内复用且幂等的浏览器模块
```

维护规则：

- 路由始终用完整域路径调用 `render_template()`；常规业务页面从 `layouts/site.html` 或 `layouts/embedded.html` 继承，不依赖根目录兼容别名。partial 不继承布局，独立完整错误页等明确例外保持自包含。
- 跨页面且不包含业务分支的 UI 才进入 `components/`；只被一个页面使用的片段留在该业务域，避免制造全局碎片。
- AJAX 返回的 HTML 与首屏必须复用同一 component，不能复制第二套行/卡片实现。
- Modal 是页面级单例，由页面骨架包含一次；tab 只触发它，不各自携带一份同名 DOM 和脚本。
- 业务脚本使用唯一 `window` namespace 或模块入口，并保证重复 include 不会重复注册全局监听器。AJAX 请求应在业务域入口集中处理鉴权、错误与 JSON 解析；同一处理逻辑跨页面重复时再建立共享请求封装，不在模板中继续复制。
- 重型展示依赖默认不进入基础布局；MathJax 等资源由确实需要它的页面显式覆盖 block。共享算法只保留一个参数化实现，页面不得复制后再改常量。
- 大页面先沿用户可独立理解和测试的功能面拆分；不要按任意行数切成缺少语义的碎片。
- 模板移动、include 契约、单例 DOM 与 MathJax 边界由前端契约测试保护；列入前端资产清单的关键静态 JavaScript 必须通过语法检查。交互变化仍需补对应路由测试和浏览器关键流程验证。

## 8. 周期性维护指标

每个版本或每月在带日期的审阅记录、发布复盘或监控系统中记录趋势，不把易变数值写回本手册，也不把指标本身当目标：

- 最大文件/函数及其变更频率；
- 宽泛异常捕获和静默失败数量；
- 单元、DB、E2E 的用例数、耗时与不稳定率；
- 未固定依赖、过期依赖和镜像构建可重复性；
- schema 变更中具备迁移、备份、回滚验证的比例；
- 生产健康检查、队列积压、任务失败/重试和判题耗时分位数；
- 事故恢复时间，以及同类事故是否有自动化回归测试。

指标变差时先定位导致长期总成本上升的边界，再决定重构；不要为了降低行数或提高覆盖率制造更多间接层。
