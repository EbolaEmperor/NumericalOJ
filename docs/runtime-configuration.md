# 启动配置参考

NumericalOJ 把配置分成两类：

- `.env.tmpl` 只列出新部署必须明确填写的九项启动配置：`SECRET_KEY`、五项
  `MYSQL_*` 和三项 `REDIS_*`。
- 本文列出的高级运行参数在 `config.py` 中有类型化默认值。只有需要覆盖默认行为时，
  才把同名键写入 `.env` 或进程环境；修改后需要重启对应 Web/Celery 进程。

优先级为“进程环境变量 > `.env` > 代码默认值”。字符串使用 JSON 双引号，布尔值使用
`true` / `false`，字符串列表使用 JSON 数组。未在本文和 `config.py` 中声明的键不会被
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
| `AGENT_CONTAINER_SITE_URL` | string | `http://host.docker.internal:2025` |
| `MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS` | int | `90` |

解题与造数据任务启动时会读取全站 WebSearch MCP 的 URL 和 Authorization，
并注入管理员在弹窗中选择的 Harness。Codex、Claude Code 和 OpenCode 使用各自的
远程 MCP 配置；Pi 通过镜像内受信任扩展注册同一个 `web_search` 工具。凭证只通过
容器环境变量传递，生成到任务工作区的配置文件仅引用变量名。

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
| `OJ_ROOT_PATH` | string/空 | 空 |
| `JUDGER_RUN_ROOT` | string/空 | 空 |
| `JUDGER_TIMEOUT_KILL_AFTER_SEC` | float | `1.0` |
| `JUDGER_OCTAVE_PLOT_WARMUP` | bool | `true` |
| `JUDGER_TARGET_ARCH` | string/空 | 空 |
| `JUDGER_NUMERIC_BACKEND` | string/空 | 空 |
| `JUDGER_ENABLE_MKL` | bool/空 | 空 |

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
| `AGENT_JUDGE_OPENCODE_HELLO_TIMEOUT_SECONDS` | float | `30.0` |

## 上传、批量打榜与反向评测

| 配置项 | 类型 | 默认值 |
| --- | --- | --- |
| `TESTDATA_ZIP_MAX_MEMBERS` | int | `4096` |
| `TESTDATA_ZIP_MAX_FILE_BYTES` | int | `134217728` |
| `TESTDATA_ZIP_MAX_TOTAL_BYTES` | int | `268435456` |
| `TESTDATA_ZIP_MAX_COMPRESSION_RATIO` | float | `500.0` |
| `TESTDATA_TEXT_MAX_TOTAL_BYTES` | int | `67108864` |
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
