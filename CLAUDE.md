# CLAUDE.md

本文件只记录维护 NumericalOJ 时必须先知道的约束。系统概览见 `README.md`，运行参数见
`docs/runtime-configuration.md`，测试、数据库和生产运维细节统一见 `docs/maintenance.md`。
Docker 与通用 Agent 的局部约束分别见 `docker/AGENTS.md` 和
`backend/oj_modules/agents/AGENTS.md`。

## 不可违反的边界

- 工作语言为中文；用户可见文案和既有中文注释保持同一风格。
- Python 基线是 **3.12**，以 `.python-version` 和 GitHub Actions 为准。
- 生产部署位于 `why-server:/home/ebola/oj/`，主机 hostname 为 `computing`。
- 未经用户明确要求，不得部署生产、写生产数据、运行迁移或重启服务。
- **生产主机禁止运行任何测试**，包括单测、pytest、Compose、CI 脚本和测试容器。
- 生产 `.env`、根目录 `static/` 的额外资产、上传和运行数据可能不在 Git 中，禁止全量覆盖或删除。

## 架构与代码边界

系统由 Flask Web、Celery worker、MySQL、Redis 和 Docker 组成。Celery 队列职责固定为：

- `celery`：普通判题、作业、检测和索引等常规任务；
- `agent`：通用 Agent 等长任务，单 worker 按全站设置动态伸缩（默认 8，最高 100）；
- `judge`：打榜赛 Agent-as-Judge 和反向评测。

普通判题调用链为
`backend/oj_modules/tasks/evaluate_tasks.py -> backend/oj_modules/judging/core.py -> backend/oj_modules/judging/sandbox.py -> Docker`。
用户代码只在 Docker 中执行；不得恢复旧的 `5050` HTTP 判题服务或宿主 RLIMIT 沙箱。

`backend/oj.py` 是应用组合根，只负责创建对象、注册 Blueprint/任务和显式启动工作，不承载业务逻辑。
模块导入不得执行外部写操作。会清锁、改状态或重投任务的恢复操作，只能在全部 Celery worker
停止后通过 `scripts/recover_pending_tasks.py --confirm-celery-stopped` 显式执行。

主要后端模块均位于 `backend/oj_modules/`，职责如下：

- `routes/`、`api/`：HTTP 解析、鉴权和响应；
- `tasks/`：Celery 重试、进度、锁和工作流适配；复杂任务放入相应子包；
- `classroom/`、`forum/`、`homework/`、`problems/`、`ranking/`、`submissions/`：领域逻辑和事务；
- `ai/`、`integrations/`：模型协议与外部服务，统一 LLM 协议在 `ai/endpoints.py`；
- `infrastructure/`：MySQL、Redis 等连接原语；`security/`、`shared/`：跨域安全与通用能力；
- `frontend/src/`：唯一的 React 页面层、路由和数据状态；`frontend/public/static/`：受 Git 管理的视觉资产与浏览器运行时。
  生产根目录 `static/` 仅作为未跟踪历史附件的只读 URL 回退，不得迁入、覆盖或清理。

新增后台任务沿用 `register -> init` 模式，由 `tasks/registry.py` 聚合，路由不得导入任务私有实现。
新增能力前先复用规范入口：认证用 `security/auth.py`，Markdown 清洗用 `shared/markdown.py`，
压缩包处理用 `shared/archive.py`，Redis/MySQL 连接用 `infrastructure/`，动态站点配置用
`site_config/services.py`。所有返回给 React 的富文本 HTML 必须先清洗。

健康检查为 `GET /health/live`（进程存活）和 `GET /health/ready`（MySQL、Redis 就绪）。

## 配置、依赖与数据库

- 直接依赖使用精确版本：生产、测试、可选依赖分别写入 `backend/requirements/production.txt`、
  `backend/requirements/test.txt`、`backend/requirements/optional.txt`；不要用文档里的零散 `pip install` 代替。
- 配置优先级是“进程环境变量 > `.env` > `backend/oj_modules/config.py` 默认值”。密钥不得写入 tracked 文件。
- LLM、Embedding、SMTP 和 WebSearch MCP 只从 MySQL 动态配置读取，不得增加环境变量回退。
- Redis 客户端只能由 `backend/oj_modules/infrastructure/redis.py` 创建。

`backend/database/bootstrap.sql` 与 `scripts/init_db_schema.py` 可创建缺失对象、添加列/索引并调整识别到的
列类型，但仓库**没有版本化迁移系统**，也不会自动删除、重命名或回填。涉及这些语义变化时，
必须提供可审计迁移、备份和回滚方案。业务连接统一经
`backend.oj_modules.infrastructure.mysql.get_db_connection()`；动态表名必须先用 `safe_table_name()` 校验。

## 测试与数据安全

日常最低门禁：

```bash
python3 -m compileall -q backend deploy tests
cd frontend && npm run typecheck && npm test && npm run build
cd ..
python3 -m pytest -q tests/unit
```

`tests/db`、`tests/e2e` 和 `tests/ci` 会修改真实 MySQL/Redis，只能连接明确可丢弃的一次性基础设施。
任何建库、清表、删除动态表或 `FLUSHDB` 的 fixture，必须在第一次写入前通过
`tests/environment_guard.py`；不得放宽、捕获或绕过 guard。完整本地 CI 命令和测试分层见
`docs/maintenance.md`。

生产默认只允许 `SELECT`、`SHOW`、`EXPLAIN`、日志和进程检查。生产写入、DDL、导入或修复必须
获得明确授权，并先准备备份与回滚方案。

## 生产部署

只有用户明确要求时才可操作生产。唯一发布入口是：

```bash
git pull --ff-only
bash deploy.sh
```

不要绕过 `deploy.sh` 手工拼接发布步骤，也不要在部署脚本中运行测试。部署使用 Python 3.12 和项目内
轮换 venv；连接数据库前必须 fail-closed 校验生产 `.env` 已加载、属于部署用户且权限为 `0400`
或 `0600`。停服、备份、schema 同步、镜像切换、任务恢复和服务启动顺序由部署流程统一管理；失败时
保留现场，不自动回灌数据库。详细备份与回滚规则只维护在 `docs/maintenance.md`。

## 日志与前端

日志统一走 `backend/oj_modules/observability/`，管理入口为 `scripts/log_admin.py`。新增事件沿用版本化 schema、
递归脱敏和 request/task 上下文，不自行创建共享文件 handler。默认不信任 `X-Forwarded-For`；可信
代理只由 `LOG_TRUSTED_PROXY_CIDRS` 配置。

用户主工作区由 `frontend/src/` 下的 React SPA 提供，直接使用无统一前缀的业务路径；`/app` 与
`/app/*` 必须保持 404，不得重定向到无前缀路径。视觉必须继续复用
`frontend/public/static/` 中的既有 DOM/CSS 契约，不得因技术栈迁移重新设计页面。React 查询缓存、
路由预取和闲时预热不得绕过权限或把写请求缓存为读响应。服务端不再维护 Jinja 页面；MathJax 必须
由 React 页面显式 opt-in，复用现有 Markdown、编辑器、选择器和提交组件，不复制私有版本。所有
前端改动都必须重新构建。

## 领域不变量

- 禁用函数配置以逗号分隔，`judger_core.check_forbidden()` 按函数调用模式匹配。
- 判题时间限制在任务与核心之间以纳秒传递，不得静默改单位。
- `competitions/` 是 gitignored 数据/临时工作区，不属于部署代码。
