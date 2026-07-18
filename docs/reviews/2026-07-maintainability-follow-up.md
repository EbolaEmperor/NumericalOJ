# NumericalOJ 可维护性复审（2026-07）

## 结论

对照初始审阅，本轮治理后系统的可维护性约为 **6.5/10**，从“依赖个人记忆才能安全变更”进入了“已有明确边界、门禁与发布状态机，但核心数据模型和后端热点仍需持续治理”的阶段。

这不是把分数从 5 调成 6.5 的主观乐观：可验证的变化包括测试清库 fail-closed、一键部署与可验证回滚、生产 DDL 单一所有者、依赖分层、统一 Redis 客户端、关键提交文件/数据库一致性、模板领域化和前端结构契约。分数仍被 7 个超过 2000 行的后端文件、无版本账本的迁移器、可变 username 关系、应用组合根、结构化日志、完整 CSRF/CSP 和传递依赖锁明显限制。

| 维度 | 初审 | 当前 | 判断 |
| --- | ---: | ---: | --- |
| 后端架构边界 | 5.5 | 5.5 | 规则和复用组件更清楚，但组合根与超大模块尚未拆 |
| 数据一致性与迁移 | 4.0 | 6.0 | 代表性事务、行锁和跨文件/DB 发布已修，正式 migration 与关系模型仍缺失 |
| 测试与数据安全 | 3.0 | 8.0 | 破坏性测试统一 fail-closed，全部纯单测进入 CI |
| 前端 | 3.0 | 6.5 | 页面、布局、表格和拓扑算法已有单一来源，热点页内联 JS/CSS 仍需继续下沉 |
| 依赖与构建复现 | 3.0 | 5.5 | 直接依赖和 Harness 已固定，传递 lock、base/apt/pip 漂移仍在 |
| 部署与运维 | 3.5 | 7.5 | 已有持锁、磁盘门禁、备份、健康验证、所有权激活和回滚的一键状态机 |
| 安全策略维护性 | 5.0 | 5.5 | 同源写保护已统一，鉴权装饰器、token CSRF 和严格 CSP 未闭环 |
| 文档与开发体验 | 4.0 | 7.0 | 运行事实、目录和维护规则已有唯一来源，生成文档不再版本化漂移 |

## 初始审阅逐项验收

| 初始审阅事项 | 状态 | 当前结果 |
| --- | --- | --- |
| 测试可能误清生产 | 已完成 | MySQL、Redis、hostname、路径、库名与显式测试开关统一 fail-closed |
| import/startup 外部写副作用 | 部分完成 | DB 池和恢复动作已显式化；`create_app/create_celery` 与服务容器仍待实施 |
| 关键事务一致性 | 部分完成 | 用户创建、普通提交配额、改名、归档、打榜 ZIP、班级成员/人数更新已治理；人工书面作业覆盖采用不可变代次、DB 快照 CAS 和持久发布 journal；其他文件/DB/任务状态机仍需逐项处理 |
| 数据模型与迁移体系 | 未完成 | `database/bootstrap.sql` 仍混合结构与首次安装种子；没有 migration ledger，动态班级表仍存在 |
| 超大后端热点 | 未完成 | 仍有 7 个生产 Python 文件超过 2000 行，优先按领域用例拆分而非机械切文件 |
| 前端 God template | 本阶段完成 | 根模板目录不再放页面；打榜详情/设置、全局布局、提交表格、共享编辑器、拓扑算法和 Modal 已建立单一来源 |
| 鉴权、CSRF、CSP | 部分完成 | 统一同源写请求保护已落地；全面装饰器、token CSRF、去除 `unsafe-inline/eval` 尚未完成 |
| Python/CI 依赖基线 | 大部分完成 | Python 3.12、直接依赖精确版本、全部纯单测 CI 已完成；带哈希传递 lock 未完成 |
| Docker 判题复现 | 部分完成 | Harness 版本和部署候选镜像标识已收口；基础镜像、apt 与部分 pip 能力仍浮动 |
| Gunicorn、健康检查、Supervisor | 已完成 | Web/Celery 独立进程边界、socket、节点名、优雅停机和 live/ready 已落地 |
| 自动化部署 | 已完成 | `bash deploy.sh` 完成不可变 staging、依赖摘要寻址并封印的 venv、磁盘门禁、镜像冒烟、精确停机、原子备份、结构同步、恢复、重启、验证和失败回滚 |
| 文档漂移 | 已完成 | README、开发约束、维护手册与实际路径一致；旧 DeepWiki 生成物停止入库 |
| 统一 Redis 客户端 | 已完成 | 文本、二进制、阻塞订阅三种 profile 统一超时，生产模块不再自行构造客户端 |
| 结构化日志与关联 ID | 未完成 | 仍有 84 个直接 `print()` 和约 605 个 `except Exception`，需要按故障面渐进收口 |
| route 内注册 Celery task | 未完成 | homework/rejudge 仍应迁入 `oj_modules/tasks/` |
| `user_id`、单表班级作业、索引 generation | 未完成 | 都涉及兼容窗口和生产数据迁移，应作为独立 Epic |

## 二次复审发现与处理

| 复审发现 | 处理结果 |
| --- | --- |
| 部署工件持续增长可能耗尽磁盘 | 停服前对代码目录、状态目录和 Docker data-root 二次 fail-closed 检查；留存清理继续保持人工白名单策略 |
| 每个提交重复安装完全相同的 Python 依赖 | venv 改为按生产 requirements SHA-256 寻址复用，并以只读权限、全树哈希、Python 版本、`pip check` 和关键 import 校验 |
| 发布中 Git 文件与目录互换会破坏 rsync/回滚 | 新旧 manifest 成为所有权真相；备份、激活和回滚均按叶子身份 journal 执行并拒绝覆盖清单外路径 |
| 首次部署到空数据库时 dry-run/备份语义不完整 | dry-run 可对不存在的库生成计划；备份明确记录“原数据库不存在”而非伪装成正常 dump |
| 人工书面作业上传在进程崩溃时可能出现文件与 DB 指针分裂 | 先完整安装不可变代次和归档，再以锁定快照 CAS 更新 DB；持久 journal 让启动恢复能按 DB 当前指针决定完成或回滚 |
| 管理员编辑班级会重复增加人数且绕过事务 helper | 统一委托班级成员事务服务，只在新增 membership 时增加人数，保留原有多班级关系 |
| 同一比赛的提交配额锁串行化所有参赛者 | 配额锁改到用户行，仍在单事务内校验比赛配置，减少无关用户竞争 |
| 文件型打榜提交遇到 `commit()` 响应丢失时可能删除已被数据库引用的文件 | 用新连接核对提交元数据与文件；确认成功则正常返回，无法确认则保留文件并返回“待确认、勿重试”；守护任务宽限后补入队，普通评测的领取与终态均用数据库 task-id CAS，ELO 激活与超额退役同事务完成 |
| 排名拓扑算法三份复制、MathJax 全站加载、提交表格重复 | 拓扑算法收口到一个参数化静态模块；MathJax 仅 8 个页面显式启用；提交列表共用 macro 和样式 |
| 可选 Redis 客户端的 create/ping/fail-open 流程重复 | 统一由 Redis client factory 提供普通、二进制、阻塞和可选连接 profile |

## 可量化的结构变化

- 根目录 Git 跟踪文件从 19 个降到 11 个；运行入口和仓库级配置保留，部署、Supervisor、依赖和数据库基线分别归入专用目录。
- `templates/` 根目录 HTML 从 36 个降到 0；页面与 partial 全部按业务域组织。
- 模板总代码当前为 18216 行；`ranking/detail.html` 从 7615 行降到 1808 行，拆成 8 个 tab、3 类 Modal、业务组件和共享脚本；`ranking/tabs/settings.html` 又从 2959 行降到 565 行。
- `submissions/list.html` 从 173 行降到 17 行、`submissions/all.html` 从 377 行降到 215 行，两者共用表格与分页 macro；模板 `<style>` 块从 24 个降到 20 个。
- `layouts/base.html` 提供最小页面骨架，site/embedded 只表达各自差异；MathJax 从全局约 1.17 MiB 依赖改为 8 个有公式页面显式 opt-in。
- 排名规则拓扑只保留 `static/app/ranking/topology.js` 一份算法，三个消费者通过不同几何参数复用；确定性布局与环检测由 Node 契约测试保护。
- 生产 Supervisor 中隐式结构同步入口从 4 个降到 0，结构同步只有部署状态机一个所有者。
- 生产代码自行构造 Redis 客户端的位置从多套实现降到 0，由 `oj_modules/redis_clients.py` 统一。
- 删除无调用方模板、停用动画、重复/残缺 vendor 资源、孤儿课程数据和过期生成式 Wiki；生产 `static/` 仍按追加式边界保护，不会随删除动作清理远端额外资产。

当前仍有 7 个生产 Python 文件超过 2000 行；模板中仍有 20 个 `<style>` 块和 46 个内联事件属性。当前最大的四个模板是 `ranking/detail.html`（1808 行）、`submissions/detail.html`（1607 行）、`games/circle_cat.html`（1435 行）和 `admin/homework.html`（1251 行）。这说明前端已经从一个 7615 行的单点热点变为若干可独立治理的领域热点，但尚未结束。

## 剩余治理顺序

### P1：先降低数据与故障成本

1. **引入正式版本化迁移**：建立 `schema_migrations`、有序不可变迁移、执行锁、超时、备份验证和 expand-contract 规则；随后拆分 schema、生产 bootstrap、开发 seed 和 demo 数据。
2. **继续治理文件/DB/任务一致性**：Repository/FAISS 应采用 generation 构建完成后原子切换，不能先删旧索引；其余跨数据库、文件系统与任务队列的流程按状态机逐项审计。
3. **稳定关系键**：逐步增加不可变 `user_id` 并双读/回填，username 只保留展示快照；不能做一次性大爆炸迁移。
4. **结构化可观测性**：统一 JSON/键值日志、异常分类、request ID、Celery task ID、submission/competition ID 和关键耗时；逐步清理静默吞错。
5. **发布工件留存自动化**：维护手册已定义 `runs/venvs/backups/releases` 的保留与白名单规则；下一步接入容量告警和持锁清理工具，在完成外部备份恢复抽查前不自动删除数据库备份。

### P1：降低核心变更半径

1. 为 `oj.py` 增加兼容式 `create_app()` / `create_celery()` 和小型服务容器，保留 `oj.app` / `oj.celery` 公共出口。
2. 把 homework/rejudge 的任务注册移出 route；API 不再反向导入 route 私有函数。
3. 按 `prepare → execute → normalize → persist` 拆普通评测注册体；优先拆 `ranking_routes.py`、两类 ranking judge task、`repository_index_services.py` 和 `db_services.py` 的高频子域。
4. 给 Submission、JudgeResult、AgentState 等跨层协议增加数据类或 `TypedDict` 与唯一状态定义，不做全仓强制 OO 化。

### P2：前端与安全闭环

1. 优先把 `submissions/detail.html` 的评测轨迹、书面批注和刷新状态脚本按功能边界下沉到静态模块。
2. 依次治理 `games/circle_cat.html`、`admin/homework.html`、`repository/index.html` 的内联 JS/CSS，并把纯逻辑放入可独立测试的静态模块。
3. 建立统一 `apiFetch`，让 AJAX 首屏与增量响应继续复用同一 component；再收口桌面/移动导航中仍重复的状态逻辑。
4. 本地化剩余 CDN 依赖，逐步移除 46 个内联事件和 `unsafe-eval/unsafe-inline`，再启用 token 型 CSRF 与严格 CSP。
5. 在 Python 3.12 上生成带哈希的传递依赖 lock，固定 Docker base digest 和关键 apt/pip 包，并增加定期 disposable-infrastructure 构建验证。

## 边界判断

本轮没有把应用工厂、全库 `user_id`、动态班级表迁移、版本化 migration 和严格 CSP 同时塞进一个提交。这些方向正确，但它们都需要独立兼容窗口、生产数据验证和回滚方案；与部署和前端大规模重构捆绑会显著提高不可逆回归概率。长期正确的做法是把上述清单变成可逐项验收的 Epic，而不是制造一次“看起来彻底”的高风险重写。
