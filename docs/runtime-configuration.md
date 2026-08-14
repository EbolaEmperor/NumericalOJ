# 启动配置参考

NumericalOJ 把配置分成两类：

- `.env.tmpl` 只列出新部署必须明确填写的九项启动配置：`SECRET_KEY`、五项
  `MYSQL_*` 和三项 `REDIS_*`。
- 本文列出的高级运行参数在 `oj_modules/config.py` 中有类型化默认值。只有需要覆盖默认行为时，
  才把同名键写入 `.env` 或进程环境；修改后需要重启对应 Web/Celery 进程。

优先级为“进程环境变量 > `.env` > 代码默认值”。字符串使用 JSON 双引号，布尔值使用
`true` / `false`，字符串列表使用 JSON 数组。未在本文和 `oj_modules/config.py` 中声明的键不会被
自动导出为应用配置。

LLM、Embedding、SMTP 与 WebSearch MCP 的地址、密钥和模型不属于启动配置。它们只从
管理员“全站配置”页面及 MySQL 读取；旧 `.env` 同名键不会回退生效。

## Web、日志与数据库连接

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `FLASK_DEBUG` | bool | `false` | 本地调试开关；生产必须关闭。 |
| `SESSION_COOKIE_SECURE` | bool | `false` | 仅 HTTPS 部署时开启 Secure Cookie。 |
| `CONTENT_SECURITY_POLICY` | string/空 | 空 | 空值使用应用内兼容性 CSP。 |
| `CSRF_TRUSTED_ORIGINS` | string[] | `[]` | 反向代理造成内外 Origin 不同时的可信公开 Origin。 |
| `LOG_LEVEL` | string | `INFO` | 应用日志级别。 |
| `LOG_TRUSTED_PROXY_CIDRS` | string[] | `[]` | 唯一可信反向代理网段；空值不信任转发 IP。 |
| `MYSQL_CONNECT_TIMEOUT` | int | `5` | MySQL 建连超时，单位秒。 |
| `MYSQL_POOL_MIN_SIZE` | int | `2` | 每进程连接池最小连接数。 |
| `MYSQL_POOL_MAX_SIZE` | int | `6` | 每进程连接池最大连接数。 |
| `MYSQL_POOL_WAIT_TIMEOUT` | int | `3` | 等待池连接的超时，单位秒。 |
| `MYSQL_POOL_RECYCLE_SECONDS` | int | `1200` | 连接回收周期，单位秒。 |

## Redis 与任务快照

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `REDIS_SOCKET_TIMEOUT_SECONDS` | float | `3` | 普通 Redis 读写超时。 |
| `REDIS_CONNECT_TIMEOUT_SECONDS` | float | `3` | Redis 建连超时。 |
| `REDIS_BLOCKING_SOCKET_TIMEOUT_SECONDS` | float | `30` | Pub/Sub 等阻塞连接超时。 |
| `SUBMISSION_SNAPSHOT_TTL_SECONDS` | int | `21600` | 提交快照 TTL。 |
| `EVALUATE_SUBMISSION_LOCK_TTL_SECONDS` | int | `900` | 普通评测互斥锁 TTL。 |

## AI 工作流的非业务限制

这些参数只控制资源和工作流边界，不选择模型或供应商。

| 配置项 | 类型 | 默认值 |
| --- | --- | --- |
| `AI_CODE_MARKS_IMAGE_ANALYSIS_TIMEOUT` | int | `180` |
| `LATEX_OCR_MAX_IMAGES_PER_REQUEST` | int | `20` |
| `LATEX_OCR_STREAM_EMIT_INTERVAL` | float | `0.6` |
| `LATEX_OCR_STREAM_EMIT_MIN_DELTA` | int | `60` |
| `AGENT_REPOSITORY_KNN_TOP_K` | int | `5` |
| `AGENT_REPOSITORY_KNN_SCORE_THRESHOLD` | float | `0.08` |
| `AGENT_WORKSPACE_ROOT` | string | `tmp/agent_workspaces` |
| `AGENT_WORKSPACE_MAX_BYTES` | int | `536870912` |
| `AGENT_WORKSPACE_MAX_FILES` | int | `20000` |
| `AGENT_WORKSPACE_MAX_ENTRIES` | int | `25000` |
| `AGENT_WORKSPACE_MAX_DEPTH` | int | `64` |
| `AGENT_WORKSPACE_MIN_FREE_BYTES` | int | `2147483648` |
| `AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS` | float | `2.0` |
| `AGENT_CONTAINER_SITE_URL` | string | `http://host.docker.internal:2025` |
| `MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS` | int | `90` |

每个持久 Agent workspace 同时受总字节数、普通文件数、目录在内的总 entry 数和目录深度限制；任何一项超限都会
阻止启动或终止正在运行的 Harness。附件与宿主注入文件也经过同一配额边界，
并且所在文件系统始终保留 `AGENT_WORKSPACE_MIN_FREE_BYTES` 可用空间。无法安全统计
工作区或无法确认可用空间时会拒绝继续，不会降级为无限额模式。符号链接、FIFO 与
socket 只按 `lstat` 的 entry 和 inode 大小计入配额；硬链接按每个入口重复计算完整
逻辑大小。扫描与只读文件服务不会跟随链接，无法安全预览的入口不会出现在 workspace
文件树中。

通用 Agent 任务（包括解题与造数据兼容入口）启动时会读取全站 WebSearch MCP 的 URL 和 Authorization，
并注入管理员在弹窗中选择的 Harness。Codex、Claude Code 和 OpenCode 使用各自的
远程 MCP 配置；Pi 通过镜像内受信任扩展注册同一个 `web_search` 工具。模型 API Key
与 WebSearch Authorization 只保存在本轮宿主 relay 的内存中；容器环境只获得相互
隔离、随 relay 关闭立即失效的临时凭据，生成到任务工作区的配置文件仅引用变量名。

## 代码仓库与向量索引

| 配置项 | 类型 | 默认值 |
| --- | --- | --- |
| `REPOSITORY_STORAGE_ROOT` | string | `repository_storage` |
| `REPOSITORY_MAX_FILE_BYTES` | int | `2097152` |
| `REPOSITORY_MAX_TOTAL_BYTES` | int | `33554432` |
| `REPOSITORY_MAX_ENTRIES` | int | `10000` |
| `REPOSITORY_MAX_DEPTH` | int | `32` |
| `REPOSITORY_MAX_PATH_BYTES` | int | `1024` |
| `REPOSITORY_UPLOAD_SESSION_TTL_SECONDS` | int | `86400` |
| `REPOSITORY_EMBEDDING_DIM` | int | `1024` |
| `REPOSITORY_STRUCTURED_TIMEOUT` | int | `240` |
| `REPOSITORY_STRUCTURED_MAX_INPUT_CHARS` | int | `120000` |
| `REPOSITORY_EMBEDDING_TIMEOUT` | int | `120` |
| `REPOSITORY_EMBEDDING_BATCH_SIZE` | int | `16` |
| `REPOSITORY_VECTOR_BACKEND` | string | `faiss` |
| `REPOSITORY_FAISS_INDEX_ROOT` | string | `tmp/repository_vector_index` |

仓库结构化、检索摘要和 Embedding 模型均由全站功能绑定决定。上述维度、批量和超时值
只控制本地索引格式与资源上限。

## 普通判题与 Agent-as-Judge 容器

| 配置项 | 类型 | 默认值 |
| --- | --- | --- |
| `AGENT_JUDGE_DOCKER_IMAGE` | string | `numericaloj-agent-judge:latest` |
| `AGENT_JUDGE_WORKSPACE_ROOT` | string | `ranking_uploads/judge_workspace` |
| `AGENT_JUDGE_CONCURRENCY` | int | `2` |
| `AGENT_JUDGE_DEFAULT_TIMEOUT` | int | `1800` |
| `AGENT_JUDGE_MEM_LIMIT` | string | `4g` |
| `AGENT_JUDGE_CPU_LIMIT` | string | `2` |
| `AGENT_JUDGE_PIDS_LIMIT` | string | `512` |
| `AGENT_JUDGE_RESULT_POLL_INTERVAL` | float | `1.5` |
| `AGENT_JUDGE_PROGRESS_TTL` | int | `21600` |
| `JUDGER_DOCKER_IMAGE` | string | `numericaloj-judger:latest` |
| `JUDGER_DOCKER_MEM_LIMIT` | string | `1g` |
| `JUDGER_DOCKER_CPU_LIMIT` | string | `2` |
| `JUDGER_DOCKER_PIDS_LIMIT` | string | `128` |
| `JUDGER_DOCKER_NETWORK` | string | `none` |
| `JUDGER_DOCKER_RUNNER_UID` | int | `65532` |
| `JUDGER_DOCKER_RUNNER_GID` | int | `65532` |
| `JUDGER_DOCKER_CASE_TMPFS_BYTES` | int | `134217728` |
| `JUDGER_DOCKER_EXPORT_TMPFS_BYTES` | int | `100663296` |
| `JUDGER_CASE_INPUT_MAX_BYTES` | int | `67108864` |
| `JUDGER_STDOUT_MAX_BYTES` | int | `1048576` |
| `JUDGER_STDERR_MAX_BYTES` | int | `1048576` |
| `LEAN4_DOCKER_IMAGE` | string | `numericaloj-lean4:latest` |
| `LEAN4_JUDGE_MEM_LIMIT` | string | `4g` |
| `LEAN4_INTERACTIVE_MEM_LIMIT` | string | `4g` |
| `LEAN4_INTERACTIVE_CPU_LIMIT` | string | `2` |
| `LEAN4_INTERACTIVE_PIDS_LIMIT` | int | `128` |
| `LEAN4_INTERACTIVE_MAX_SESSIONS` | int | `8` |
| `LEAN4_INTERACTIVE_IDLE_SECONDS` | int | `600` |
| `LEAN4_INTERACTIVE_TIMEOUT_SECONDS` | int | `180` |
| `OJ_ROOT_PATH` | string/空 | 空 |
| `JUDGER_RUN_ROOT` | string/空 | 空 |
| `JUDGER_TIMEOUT_KILL_AFTER_SEC` | float | `1.0` |
| `JUDGER_OCTAVE_PLOT_WARMUP` | bool | `true` |
| `JUDGER_TARGET_ARCH` | string/空 | 空 |
| `JUDGER_NUMERIC_BACKEND` | string/空 | 空 |
| `JUDGER_ENABLE_MKL` | bool/空 | 空 |

## VibeHub 作品容器

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `VIBEHUB_RUNTIME_ROOT` | string | `tmp/vibehub_runtime` | 权限为 0700 的跨 worker 状态与锁目录；不会挂入作品容器。 |
| `VIBEHUB_ALLOWED_BASE_IMAGES` | string[] | `["numericaloj-vibehub-runtime:1"]` | 唯一允许出现在用户 Dockerfile 外部 `FROM` 中、且必须已在本机预置的镜像。 |
| `VIBEHUB_BUILD_BUILDER` | string/空 | 开发为空；生产 `numoj-vibehub-online` | 正式部署自动创建缺失的 VibeHub 专属 Buildx builder；已有实例只校验、不替换。 |
| `VIBEHUB_REQUIRE_DEDICATED_BUILDER` | bool | 开发 `false`；生产 `true` | 正式部署始终拒绝复用普通 builder。 |
| `VIBEHUB_BASE_OCI_LAYOUT_ROOT` | string | `.deploy/vibehub-base-oci` | deploy 原子发布的受管基础镜像 OCI layout 根；生产通过 `current` 指向与 daemon base image ID 一致的 release。 |
| `VIBEHUB_LEASE_TTL_SECONDS` | float | `90` | 玩家 heartbeat 租约 TTL，范围 10–3600 秒。 |
| `VIBEHUB_IDLE_GRACE_SECONDS` | float | `300` | 最后一个玩家离开后的容器空闲宽限，范围 0–3600 秒；宽限内同版本玩家返回会复用容器并取消原回收截止时间。 |
| `VIBEHUB_REAPER_INTERVAL_SECONDS` | float | `15` | 后台过期回收间隔，必须小于 lease TTL。 |
| `VIBEHUB_STORAGE_GC_INTERVAL_SECONDS` | float | `900` | 退役版本快照与过期上传暂存的后台回收周期，范围 60–86400 秒；Web worker 启动后会先立即执行一轮。 |
| `VIBEHUB_REQUEST_TIMEOUT_SECONDS` | float | `15` | relay HTTP 端到端单请求总时限，范围 0.1–120 秒。 |
| `VIBEHUB_REQUEST_MAX_BYTES` | int | `16777216` | 单请求体上限；硬上限 64 MiB。 |
| `VIBEHUB_RESPONSE_MAX_BYTES` | int | `16777216` | 单响应体上限；硬上限 64 MiB。 |
| `VIBEHUB_PROXY_TRANSPORT` | string | `docker-exec` | 只允许有界、可复用的 `docker exec` relay；`auto` 是兼容别名，`host-uds` 被拒绝。 |
| `VIBEHUB_BUILD_TIMEOUT_SECONDS` | float | `480` | 创建或更新作品时的单次镜像构建时限，范围 1–540 秒；硬上限低于 Gunicorn 的 600 秒请求超时。 |
| `VIBEHUB_PROXY_SLOT_TIMEOUT_SECONDS` | float | `0.25` | 等待宿主 8 个代理槽之一的最长时间；范围 0–10 秒，超时返回 429。 |
| `VIBEHUB_MAX_ACTIVE_RUNTIMES` | int | `8` | 单台宿主同时运行的作品容器总上限，范围 1–64；容量满时新作品返回 429，已有同版本容器仍可共享。 |
| `VIBEHUB_STORAGE_MUTATION_SLOTS` | int | `2` | 全宿主同时处理 VibeHub 持久变更的上限，严格范围 1–8；同一槽覆盖 DB 预检、multipart spool 和全局存储锁等待，跨 gthread/worker 共享。 |
| `VIBEHUB_STORAGE_MUTATION_SLOT_WAIT_SECONDS` | float | `0.1` | 持久变更槽等待上限，范围 0–1 秒；容量满时快速返回 429 和 `Retry-After`。 |

VibeHub 用户镜像构建和运行容器都使用 Docker bridge 联网，作品可以主动访问外部网络。
运行时不发布端口，使用只读根文件系统，也不允许作品选择宿主路径或 Docker volume。平台按数据库
project id 与 `public/latest/review` 通道创建受管 local volume，唯一挂到 `/data`，因此容器重建后数据仍保留。

`/run/vibehub` 是容器内 16 MiB 有界 tmpfs，宿主只通过受信基础镜像内的有界
`docker exec` relay 访问 `app.sock`。同一 Web worker 会为活跃容器复用最多 4 个固定命令、固定用户的
relay 进程，避免每个静态资源和游戏操作都重新启动 Python 与 `docker exec`；协议仍逐请求执行完整
长度、超时和响应上限校验。容器回收或 relay 异常时进程池立即失效，各 worker 的 reaper 也会清理
已不在共享 runtime state 中的本地池。普通作品另限制为 20 GiB 完整镜像、4 GiB 内存和 2 CPU；
精品翻倍。每个 Web worker 启动时都会显式启动容器 reaper 与存储 GC daemon，
跨进程通过同一宿主 `flock` 和原子 state 协调，因此 Web 重启后即使无人再次访问，也会按
TTL 回收旧容器。每个作品只维护 `latest`、`public` 两个受管镜像别名；保存时构建 `latest` 并
自动送审，`review` 复用其 image ID。审核通过让 `public` 指向已确认的 `latest`，不重新构建。
玩家访问用同一次镜像 inspect 核验受管标记和当前包摘要，再启动或复用容器；缺失或不匹配时
失败关闭，不扫描作品目录。最后一个玩家离开后进入默认
5 分钟空闲宽限；同版本玩家返回会复用容器，宽限到期仍无人使用才由 reaper 删除。稳定镜像
别名和 Docker 构建缓存由 Docker 自身管理；进入作品始终不构建镜像。宽限到期后无人游玩时
没有作品容器占用 CPU 或内存，磁盘缓存与运行
资源的生命周期彼此独立。运行容器使用 Docker `none`
日志驱动，不会把不可信作品的 stdout/stderr 持久写入宿主日志；平台只记录受控的生命周期
与代理元数据。运行容器总上限和代理槽通过 runtime root 中的 `flock` 与
原子 state 跨 worker 共享，不会因增加 Web worker 而成倍放大宿主资源占用。
创建、上传、元数据编辑和管理员审核共用私有 `flock` 持久变更槽。保存路径先预检，再解析
multipart/form、构建并自动送审；审核路径先验证管理员。事务最终重检作者、版本与配额。
存储 GC 始终按“全局 `storage_mutation_lock` → 数据库作品/版本
`FOR UPDATE` live-set → 存储层 device/inode/ctime_ns 绑定回收”的顺序执行。超过 1 小时的退役
marker 不再依赖作者后续写入才删除；同一轮还会回收超过 1 小时的受管上传
staging。安装快照后、DB commit 前崩溃所留的未提交 `vN`、clone 或完全无 DB 行的
社区项目也会先写入根级严格 marker；只有同一 device/inode/ctime_ns 连续超过 1 小时才会
删除，同路径目录被替换后即使文件系统复用了 inode，也会重新开始宽限。旧格式 marker 会先
安全刷新为新身份格式，不会沿用旧时间删除目录。控制锁和上传 staging 不会被当成
项目孤儿。启动在单进程内幂等，生产保持
单 worker；单轮 DB 或存储异常只记录日志并在
下一周期重试，不会终止 Web 服务。
作品的 `/tmp` 与 `/run/vibehub` 都是内存与容器资源限制内的有界 tmpfs，不存在可借 Unix socket
目录消耗宿主文件系统的 bind 窗口；持久数据只进入平台命名并核验 label 的 local volume。
生产构建只接受全部 node 都为 running、
`docker-container` driver 且 builder 容器 `HostConfig.NetworkMode=bridge` 的专属 builder；已核验的
daemon base image 通过本地受管 OCI layout named context 注入。玩家访问、
作品构建和容器回收都不会自动清理受管镜像或专属 builder 缓存；如未来需要释放磁盘，只能由
显式运维操作按 VibeHub label 与专属 builder 范围清理，绝不执行全局
`docker builder prune`。
生产 `deploy.sh` 会在停服前只读核验 builder 的 driver、全部节点状态及其容器
`NetworkMode=bridge`，再把候选 daemon image 通过 `docker image save` 流式转换为标准 OCI
layout；转换器不解包路径、不导入模块、不运行镜像内容，并复核 config ID、每层 diff-id、全部
blob 的 SHA-256 与大小。候选 release 此时不会出现在 `current` 下；数据库回滚点成功后才与
stable tag 一起切换 `current`，失败时两者一并恢复，成功后保留 current 和上一代 release。
部署流程遵守生产禁测规则，不运行临时 Dockerfile、构建 probe 或候选容器；部署后的下一次作品
创建或更新构建仍会重新核验同一 builder 与 OCI metadata，并在任何能力或完整性不匹配时失败关闭。
完整作品接口见 `docs/vibehub-developer-guide.md`。

Agent-as-Judge 高级通信和压缩包边界：

| 配置项 | 类型 | 默认值 |
| --- | --- | --- |
| `AGENT_JUDGE_TRACE_SYNC_INTERVAL_SECONDS` | float | `5.0` |
| `AGENT_JUDGE_QUEUE_RETRY_SECONDS` | int | `8` |
| `AGENT_JUDGE_MAX_QUEUE_RETRIES` | int | `2000` |
| `AGENT_JUDGE_SLOT_TTL_BUFFER` | int | `600` |
| `AGENT_JUDGE_PACKAGE_MAX_MEMBERS` | int | `4096` |
| `AGENT_JUDGE_PACKAGE_MAX_FILE_BYTES` | int | `268435456` |
| `AGENT_JUDGE_PACKAGE_MAX_TOTAL_BYTES` | int | `536870912` |
| `AGENT_JUDGE_PACKAGE_MAX_COMPRESSION_RATIO` | float | `500.0` |
| `AGENT_JUDGE_HELLO_TIMEOUT_SECONDS` | float | `8.0` |
| `AGENT_JUDGE_HELLO_RETRY_SLEEP_SECONDS` | float | `1.0` |
| `AGENT_JUDGE_PAUSED_PROBE_INTERVAL_SECONDS` | int | `3600` |

## 上传、批量打榜与反向评测

| 配置项 | 类型 | 默认值 |
| --- | --- | --- |
| `RANKING_BATCH_LSREMOTE_TIMEOUT` | int | `20` |
| `RANKING_BATCH_CLONE_TIMEOUT` | int | `180` |
| `RANKING_BATCH_PROBE_CONCURRENCY` | int | `12` |
| `RANKING_BATCH_PROBE_MAX_USERS` | int | `1000` |
| `RANKING_BATCH_CLONE_ZIP_MAX_BYTES` | int | `134217728` |
| `RANKING_BATCH_JOB_TTL` | int | `21600` |
| `RANKING_BATCH_PULL_RETRY` | int | `3` |
| `RANKING_BATCH_CREATE_RETRY` | int | `3` |
| `RANKING_BATCH_ITEM_SLEEP_SECONDS` | float | `1.0` |
| `RANKING_BULK_REJUDGE_JOB_TTL` | int | `21600` |
| `RANKING_BULK_REJUDGE_ITEM_SLEEP_SECONDS` | float | `2.0` |

`RANKING_BATCH_DEFAULT_TEMPLATE` 是界面消费处的产品文案常量，不是配置项。

| 配置项 | 类型 | 默认值 |
| --- | --- | --- |
| `REVERSE_JUDGE_PROGRESS_TTL` | int | `21600` |
| `REVERSE_JUDGE_WORKSPACE_ROOT` | string | `ranking_uploads/reverse_judge_workspace` |
| `REVERSE_JUDGE_SCRIPT_TIMEOUT` | int | `300` |
| `REVERSE_JUDGE_TRACE_SYNC_INTERVAL` | float | `2.0` |
| `REVERSE_JUDGE_STREAM_TIMEOUT_BUFFER_SECONDS` | int | `1200` |
| `REVERSE_QUALITY_GATE_TIMEOUT_SECONDS` | int | `300` |
| `REVERSE_QUALITY_GATE_MAX_PROMPT_CHARS` | int | `20000` |
| `REVERSE_QUALITY_GATE_RESULT_MAX_BYTES` | int | `2097152` |
| `REVERSE_PACKAGE_MAX_MEMBERS` | int | `4096` |
| `REVERSE_PACKAGE_MAX_FILE_BYTES` | int | `268435456` |
| `REVERSE_PACKAGE_MAX_TOTAL_BYTES` | int | `536870912` |
| `REVERSE_PACKAGE_MAX_COMPRESSION_RATIO` | float | `500.0` |
| `REVERSE_ANSWER_MAX_FILES` | int | `4096` |
| `REVERSE_ANSWER_MAX_FILE_BYTES` | int | `268435456` |
| `REVERSE_ANSWER_MAX_TOTAL_BYTES` | int | `536870912` |
| `REVERSE_ENDPOINT_PROXY_MAX_REQUEST_BYTES` | int | `8388608` |
| `REVERSE_ENDPOINT_PROXY_MAX_CONNECTIONS` | int | `2` |
| `REVERSE_ENDPOINT_PROXY_CLIENT_TIMEOUT_SECONDS` | int | `30` |
| `REVERSE_ENDPOINT_PROXY_TIMEOUT_SECONDS` | int | `600` |
| `REVERSE_ENDPOINT_PROXY_BIND_HOST` | string | `0.0.0.0` |
| `REVERSE_ENDPOINT_PROXY_CONTAINER_HOST` | string | `host.docker.internal` |
| `REVERSE_TRACE_RETENTION_SECONDS` | int | `1209600` |
| `REVERSE_TRACE_MAX_ATTEMPTS` | int | `8` |
| `REVERSE_TRACE_MIN_DELETE_AGE_SECONDS` | int | `21600` |

Reverse Judge 的默认 effort、重试 effort 和强制收尾提示词是实现内部常量，不属于启动
配置，也不在全站配置页面开放。
