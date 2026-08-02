# NumericalOJ 初始可维护性审阅

> 这是治理开始前的原始审阅快照，保留当时的文件路径、行号、统计与结论，作为后续验收基线；当前完成度与剩余路线见同目录的复审报告。

## 总结判断

这个系统的可维护性约 **5/10**。

更准确地说：**“稳定运行”的能力明显强于“低成本演进”的能力**。现有代码不是没有架构，而是功能增长已经超过结构治理速度，形成了“模块化外观 + 全局状态、裸字典、手工事务、人工运维”的内部形态。

不建议推倒重写、微服务化或改成大型前端框架。正确方向是保留 Flask/Jinja/Celery/MySQL/Docker，渐进治理成边界清晰的模块化单体。

| 维度 | 评分 | 判断 |
|---|---:|---|
| 后端架构边界 | 5.5/10 | 分层已存在，但全局注入和跨层私有依赖较多 |
| 数据一致性与迁移 | 4/10 | 连接池不错，事务、迁移和关系完整性不足 |
| 测试资产 | 7/10 | 621 个测试，unit/db/e2e 分层较完整 |
| CI 与测试数据安全 | 3/10 | PR 门禁覆盖窄，清库保护存在严重缺口 |
| 前端 | 3/10 | God template、内联 JS/CSS、重复实现明显 |
| 依赖与构建复现 | 3/10 | Python、Docker、npm 依赖基本未锁定 |
| 运维与可观测性 | 3.5/10 | 恢复逻辑丰富，但发布、日志、健康检查薄弱 |
| 安全策略维护性 | 5/10 | 有扎实硬化，但鉴权、CSRF、CSP 尚未闭环 |
| 文档与开发体验 | 4/10 | 文档丰富，但多个关键事实已经漂移 |

## 做得好的地方

- Blueprint、任务模块、数据库层、API 层已经形成基本结构，当前静态依赖图没有明显循环导入。
- 数据库连接池考虑了 Celery prefork，动态表名有统一校验；密码、Markdown 消毒、限流等横切能力已经集中。
- Celery 使用 late ack、幂等锁、attempt ID、启动恢复和 watchdog，可靠性设计明显经过真实事故打磨。
- Docker 判题边界相对独立，现位于 `oj_modules/judging/sandbox.py` 的职责和安全参数都比较清晰。
- 测试规模不小：约 1.78 万行测试、621 个测试函数；新的 ranking 代码已经出现同事务 `FOR UPDATE` 控制配额的良好实现，可作为旧代码重构范本，现位于 `oj_modules/ranking/db.py`。

## 最关键的问题

### P0：测试仍可能清空错误的数据库

根 fixture 会对配置中的 Redis 执行 `flushdb()`，并枚举数据库全部表进行 `DROP/TRUNCATE`；这里没有 hostname、生产路径、数据库名后缀或显式测试模式校验，[tests/conftest.py](/Users/bytedance/personal-codes/NumericalOJ/tests/conftest.py:121)。

e2e 虽然有环境检查，但它位于 e2e fixture 内，[tests/e2e/conftest.py](/Users/bytedance/personal-codes/NumericalOJ/tests/e2e/conftest.py:160)，不能保护 `tests/db`，也不是任何 destructive fixture 的统一前置闸门。这与文档中记录过的生产清库事故属于同一风险。

这是全仓第一优先级：测试必须 fail-closed，要求显式 `NUMOJ_TEST_ENV=1`、数据库名以 `_test` 结尾、独立 Redis DB，并拒绝 `computing`、生产目录和默认 `myojdb`。

### P1：应用启动和依赖注入依赖全局副作用

导入 `oj` 会创建 Flask/Celery/Redis、注册所有任务、修改多个 route 模块的全局变量，并立即尝试启动 ELO 调度链，[oj.py](/Users/bytedance/personal-codes/NumericalOJ/oj.py:220)。导入 `db_services` 又会立即构造并预热 MySQL 池，[db_services.py](/Users/bytedance/personal-codes/NumericalOJ/oj_modules/db_services.py:278)。

后果是：

- 测试必须在导入前 monkeypatch；
- Celery worker 被迫加载全部 Web 路由；
- 初始化顺序决定运行结果；
- 第二个测试 app/Celery app 很容易复用上一个 app 的任务对象；
- 缺失依赖在首个请求时才暴露。

应增加兼容式 `create_app()` / `create_celery()`，把 Redis、任务 dispatcher、repository 放入 `app.extensions` 或小型 `Services` 对象，保留现有 `oj.app`、`oj.celery` 出口。

### P1：数据库事务边界不足

几个代表性问题：

- `create_user` 分三次 commit，中间还另开连接查询用户，任一步失败都可能留下半状态，[db_services.py](/Users/bytedance/personal-codes/NumericalOJ/oj_modules/db_services.py:865)。
- 普通提交先 `can_submit`，之后再创建、归档、计数，存在并发 TOCTOU，[problem_core_routes.py](/Users/bytedance/personal-codes/NumericalOJ/oj_modules/routes/problem_core_routes.py:1045)。
- 用户改名只更新 `users.username`，[admin_user_routes.py](/Users/bytedance/personal-codes/NumericalOJ/oj_modules/routes/admin_user_routes.py:200)，但大量提交、配额、检测、排行数据仍以 username 作为业务键，改名会割裂历史。
- DB、文件落盘、Celery 投递缺少统一状态机和补偿策略。

应按“一个业务命令一个事务”提取 `SubmissionService`、`UserService`；长期以不可变 `user_id` 建立关系，username 只作展示快照。消息投递最终可用 outbox，Redis 只做优化而不是最终幂等保证。

### P1：数据模型和迁移体系承受不了长期增长

每个班级一张物理表，使创建班级变成 DDL，删除题目需要遍历所有班级表，所有查询都必须拼动态 SQL，[init_db_schema.py](/Users/bytedance/personal-codes/NumericalOJ/scripts/init_db_schema.py:31)。`safe_table_name` 解决了注入风险，但没有解决模型复杂度。

迁移器也只比较列类型、只按索引名称判断，[init_db_schema.py](/Users/bytedance/personal-codes/NumericalOJ/scripts/init_db_schema.py:222)，无法处理默认值、NULL、索引定义、数据回填、rename、FK 和可审计迁移历史。`myojdb.sql` 又混合了 schema、默认管理员、demo 数据和历史 AUTO_INCREMENT。

长期方案应是：

- `class_homeworks(class_en, problem_id, ...)` 单表；
- `schema_migrations` + 有序 SQL；
- schema、生产初始化、开发 seed、demo 数据分离；
- 自动启动只验证版本，生产迁移成为独立发布步骤。

### P1：核心热点已经超过可人工掌控的规模

后端约 4.07 万行，存在 7 个超过 2000 行的生产文件：

- `ranking_routes.py`：3363 行、46 个端点；
- `ranking_reverse_judge_tasks.py`：3174 行；
- `oj_modules/repository/index.py`：2770 行；
- `db_services.py`：2254 行；
- `ranking_db.py`：2181 行；
- `homework_routes.py`：2144 行。

普通评测的任务注册体约 648 行，[evaluate_tasks.py](/Users/bytedance/personal-codes/NumericalOJ/oj_modules/tasks/evaluate_tasks.py:324)。约 590 处捕获 `Exception`，其中约 177 处静默吞错；完整类型标注不足 1%，跨层接口基本都是裸 `dict` 和魔法状态字符串。

建议先拆 `prepare → execute → normalize → persist`，Celery task 只做适配；给 Submission、Problem、JudgeResult、AgentState 等跨层对象增加 `TypedDict`/数据类和状态迁移函数，不需要全仓强行 OO 化。

### P1：前端是当前最明显的维护热点

模板约 2.25 万行，其中约 1.15 万行内联 JS、4300 行内联 CSS。

[ranking_detail.html](/Users/bytedance/personal-codes/NumericalOJ/templates/ranking_detail.html:28) 单文件 7615 行，包含 16 个脚本块、8 个样式块，同时承载提交、榜单、对战、申诉、批量评测和编辑。它还与 `_judge_detail_modal.html` 复制了大量同名函数。

不需要 React/Vue 重写。继续用 Jinja，优先：

- 拆 ranking tab partial；
- 提取共享 `judge-detail.js`；
- 建立统一 `apiFetch`；
- 抽共享 problem form、submission row、导航宏；
- 将 `_ranking_*` 归入 `templates/ranking/`。

### P1：安全公共组件已经建立，但执行仍靠人工约定

认证 helper 已提供 `login_required/admin_required`，现位于 `oj_modules/security/auth.py`；但审计到的 176 个路由中使用次数为 0，ranking、AI detection 等仍各自重新实现权限判断。

全站也没有统一 CSRF token；CSP 因大量内联脚本仍允许 `unsafe-inline/unsafe-eval`。这意味着每个新增端点、模板和脚本都要依赖开发者记得处理安全细节，长期一定会漂移。

### P1：构建、部署和文档不可复现

- [requirements.txt](/Users/bytedance/personal-codes/NumericalOJ/requirements.txt:1) 全部未锁版本；默认 FAISS、Tree-sitter、PDF 渲染等实际能力的依赖不完整或被错误放在测试依赖中。
- Docker base、pip、npm Agent CLI 大量使用浮动版本，同一 commit 不同日期可能构建出不同镜像。
- README 宣称 Python 3.8+，但迁移脚本使用 `str | None`，至少要求 3.10；CI 只测 3.12。
- README 仍写两个 Celery 队列，实际是 `celery/agent/judge` 三个。
- [CLAUDE.md](/Users/bytedance/personal-codes/NumericalOJ/CLAUDE.md:85) 对 `static/` 是否被 rsync 排除前后矛盾，引用的 `.claude/settings.local.json` 当前也不存在。
- `web.conf` 和 `celery.conf` 两套 supervisord 共用 `/tmp/supervisord.pid` 和日志文件；生产 Web 仍由 Flask `app.run` 提供。
- 发布依赖 rsync、手工找 PID、kill、重启，没有 release 标识、健康检查、原子切换或回滚。

从 Git 历史看，246 个提交几乎都来自同一姓名的不同拼写，推断 bus factor 约为 1。文档漂移因此会迅速转化为个人记忆依赖。

## 推荐治理顺序

1. **立即处理**：测试 fail-closed 护栏；修复关键文档矛盾；明确 Python 3.12 基线并补全依赖。
2. **第一阶段**：全部 468 个 infra-free unit 进入 PR CI；锁 Python/npm 依赖；加入真实 Docker 判题门禁；统一结构化日志、健康检查、CSRF 和鉴权装饰器。
3. **第二阶段**：应用工厂、服务容器、显式启动动作；把 homework/rejudge 的任务定义移出 route。
4. **第三阶段**：优先提取普通提交、ranking 提交、评测终结三个 application service，修复事务、文件和消息一致性。
5. **第四阶段**：版本化迁移、`user_id` 关系化、`class_homeworks` 单表、Redis 分域、向量索引 generation 发布。
6. **持续治理**：ranking 按 feature package 归档，跨层私有导入归零，控制器/任务主体不超过约 150 行。

本次只读审计中，我执行了 `compileall` 和 GitHub CI 当前配置的 74 个纯逻辑测试，均通过；未运行 DB/e2e 测试，因为当前 destructive fixture 的安全闸不足。工作区保持干净，未连接生产环境。
