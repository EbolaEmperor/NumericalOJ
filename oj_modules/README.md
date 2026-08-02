# `oj_modules` 目录约定

`oj_modules` 是模块化单体的服务端实现。目录首先按架构角色分层，再在领域或能力内部按职责拆分；HTTP、CLI 和 Celery 的外部契约不由 Python 文件路径决定。

## 目录地图

| 目录 | 放置内容 | 不放置内容 |
| --- | --- | --- |
| `routes/`、`api/` | Flask Blueprint、请求解析、鉴权、响应适配 | 可复用业务算法、后台任务实现 |
| `tasks/` | Celery 注册、重试、锁、进度和任务编排 | Flask request/session、页面响应 |
| `classroom/` | 班级成员、班级标识、工作台聚合 | 通用用户认证 |
| `forum/` | 讨论区身份、帖子和回复规则 | HTTP JSON/HTML 适配 |
| `homework/` | 作业目标、查重、导出与进度状态 | Blueprint 和 Celery 注册 |
| `problems/` | 题目配置、测试数据和题目展示规则 | 提交产物生命周期 |
| `ranking/` | 打榜赛、ELO、Agent Judge、反向评测的领域与数据访问 | Celery task 装饰器 |
| `submissions/` | 普通提交、书面作业、仓库快照与批改 | 判题容器原语 |
| `editor/` | 语言服务、语义令牌、受管工具链 | 页面路由 |
| `judging/` | 普通判题协议、Docker 沙箱、case runner | 排名赛业务规则 |
| `repository/` | 代码仓库存储、解析、索引和工作区 | 提交或比赛专有规则 |
| `ai/` | 模型客户端、Promptly、转写、批改与代码反馈 | Blueprint 和 Celery 注册 |
| `integrations/` | ModelScope 等第三方协议适配 | 领域展示或持久化规则 |
| `security/` | 登录、凭据、限流、同源策略 | 某一领域的权限业务规则 |
| `infrastructure/` | MySQL、Redis 等连接与客户端原语 | 业务 SQL |
| `runtime/` | 显式恢复、watchdog 与进程运行期编排 | import-time 写入或隐式任务投递 |
| `shared/` | 无领域依赖且确实跨域复用的基础 helper | 为了缩短 import 临时堆放的函数 |
| `observability/` | 事件 schema、上下文、采集与 Web/Celery 接入 | 业务日志拼装捷径 |

`db_services.py` 暂时承载尚未安全分域的跨领域数据访问和旧 monkeypatch 接缝。它不是新代码的默认落点：新增查询应进入拥有该数据语义的领域包；只有经过相应事务与回归测试后，现有函数才分批迁出。

## 依赖方向

```text
routes / api ─┐
              ├─> domain/capability packages ─> infrastructure
Celery tasks ─┘

oj.py ─> routes / api / tasks（注册与依赖注入）
```

- `routes/`、`api/`、`tasks/` 是并列适配层，不相互导入实现。共享行为应下沉到对应领域包。
- 领域包可以依赖 `security/`、`shared/`、`infrastructure/`，反向依赖不允许。
- `infrastructure/` 只提供连接原语；查询、事务和行锁放在拥有该数据语义的领域模块。
- 包级 `__init__.py` 保持轻量，不建立数据库连接，不注册 Blueprint/任务，也不加载重量级可选依赖。
- `api/registry.py`、`tasks/registry.py` 是组合根专用聚合器；业务模块应导入具体实现，包初始化不重导出历史符号。

## 新文件如何归类

1. 先判断它是否只是在适配 HTTP 或 Celery；是则进入对应适配层。
2. 否则判断它属于哪个业务领域或独立能力，优先进入已有包。
3. 只有同时被多个领域使用、且自身没有领域语义的代码，才进入 `shared/`。
4. 只有连接池、客户端构造和协议适配等技术原语进入 `infrastructure/`。
5. 同一前缀出现三个以上同职责文件时，建立子包并去掉重复前缀；不要为目录整齐创建没有行为的类。

## 导入路径

迁移前位于 `oj_modules` 或 `oj_modules/tasks` 根部的旧模块路径已经删除，不提供重导出门面。所有 Python 调用方必须使用目录地图中的规范包路径；HTTP、CLI 与 Celery wire contract 不依赖 Python 文件布局。
