# VibeHub 开发者手册

VibeHub 接受一个包含前端、后端和运行声明的完整 ZIP 程序包。作品在可联网的隔离容器中运行，
通过 Unix domain socket 提供 HTTP/1.1 服务。本手册只说明作品协议和 NumOJ CLI 工作流。

## CLI 准备

用户 CLI 位于 `skills/numoj-user`。第一次使用先保存站点地址并登录；省略用户名或密码时会安全地
交互输入：

```bash
cd skills/numoj-user
python3 scripts/numoj_user.py init --base-url http://127.0.0.1:2025
python3 scripts/numoj_user.py vibehub --help
```

需要离线保存当前服务器的手册时运行：

```bash
python3 scripts/numoj_user.py vibehub guide -o vibehub-developer-guide.md
```

## 最小作品包

上传 ZIP 最多 **5 GiB**（5 × 1024³ 字节），解压后的所有文件合计最多 **8 GiB**。
普通成员文件不设单独大小上限，仍受解压总量及操作系统限制；封面图片继续遵守下文的格式与大小要求。
平台保留文件数量、压缩比、路径和文件类型检查。CLI 以流式 multipart 上传，完整包无需读入内存。

ZIP 解压后的根目录必须直接包含 `Dockerfile` 和 `vibehub.json`，不能再套一层目录：

```text
my-vibe/
├── Dockerfile
├── vibehub.json
├── app.py
└── static/
    └── cover.jpg
```

### 作品清单

`vibehub.json` 的运行协议固定如下，不要添加端口字段：

```json
{
  "schema_version": 1,
  "transport": "unix",
  "socket_path": "/run/vibehub/app.sock",
  "health_path": "/healthz",
  "title": "我的作品",
  "summary": "一句话简介",
  "tags": ["游戏", "创意"],
  "cover_image": "static/cover.jpg"
}
```

`cover_image` 必填，只接受包内真实的 PNG、JPEG 或 WebP 相对路径。平台会从原图中心裁切并生成
1280×720、严格 16:9、最多 400 KiB 的安全封面；原图不会被改写。原图不得超过 16 MiB、
8192×8192 或 1600 万像素。

### Dockerfile 与网络依赖

作品镜像必须基于平台提供的受信任基础镜像。最小 Dockerfile：

```dockerfile
FROM numericaloj-vibehub-runtime:1
COPY --chown=65532:65532 . /app
CMD ["python", "/app/app.py"]
```

Dockerfile 只允许一个位于首行的固定 `FROM`，以及 `RUN`、`COPY`、`CMD`、`ENTRYPOINT`、
`WORKDIR`、`ENV`、`LABEL`。禁止 `ADD`、`USER`、`VOLUME`、`ONBUILD`、`HEALTHCHECK`、多阶段构建、
外部 frontend 和 `COPY --from`。`COPY` flag 只允许精确的 `--chown=65532:65532`，目标必须
位于 `/app`。

构建步骤可以访问网络，因此可在 `RUN` 中下载或安装依赖。默认基础镜像带 pip，且构建步骤以
非 root 用户运行；Python 依赖可安装到 `/app/vendor` 并用 `PYTHONPATH` 引用。基础镜像仍由
平台预置；建议使用 lockfile 和精确版本，保证重建结果可复现。

### 基础镜像预装环境

`numericaloj-vibehub-runtime:1` 预装 Python 3.12。普通作品直接使用 `python`，无需重复安装下表中的库：

| 用途 | 预装库与版本 |
| --- | --- |
| 数值、图像与 ARC | NumPy 2.5.0、Pillow 12.2.0、arcengine 0.9.3 |
| Web 框架 | Flask 3.1.2、FastAPI 0.141.1 |
| HTTP 服务 | Gunicorn 23.0.0、Uvicorn 0.52.4、Waitress 3.0.2 |
| HTTP 客户端 | Requests 2.34.2、HTTPX 0.28.1 |
| 模板、数据校验与存储 | Jinja2 3.1.6、Pydantic 2.13.5、SQLAlchemy 2.0.48 |
| 表单、WebSocket 与配置 | python-multipart 0.0.32、websockets 17.1、PyYAML 6.0.3 |

GPU 推理依赖预装在独立环境 `/opt/vibehub-gpu`：vLLM 0.18.0（CUDA 12.6 源码构建）、PyTorch 2.10.0+cu126、
Transformers 4.57.6、huggingface-hub 0.36.0，以及宿主缺少的 cuDNN 9.10.2.21、
NCCL 2.27.5、cuSPARSELT 0.7.1、NVSHMEM 3.4.5。
该环境的 NumPy 为 2.2.6，以满足 vLLM 的版本约束；普通 `python` 的 NumPy 2.5.0 不变。
GPU 环境可以使用上表中的 Web 库。GPU 作品显式选择它的解释器，例如：

```dockerfile
FROM numericaloj-vibehub-runtime:1
COPY --chown=65532:65532 . /app
ENV PATH=/opt/vibehub-gpu/bin:/usr/local/cuda-12.6/bin:$PATH
ENV TRITON_CACHE_DIR=/data/triton-cache
CMD ["/opt/vibehub-gpu/bin/python", "/app/serve.py"]
```

仅对缺少的作品依赖追加安装步骤，不要重复下载 PyTorch、vLLM、cuBLAS 或 cuDNN。
预装环境不包含模型权重；权重和测试集由作品自行提供。依赖的完整版本与 SHA-256 锁文件位于
`docker/vibehub-runtime/requirements-web.lock` 和 `requirements-gpu.lock`。后者保留完整依赖图；
构建脚本排除宿主已提供的 CUDA 发行包，并从固定源码提交编译 vLLM。不会下载预编译 vLLM
或重复安装 Toolkit。源码归档及子模块由 `sources-gpu.json` 固定版本和 SHA-256，
网络下载支持重试；GPU 依赖安装与源码编译分层缓存。构建记录位于镜像内
`/opt/vibehub-runtime/gpu-build.json`。

## 容器运行协议

镜像默认命令必须以前台进程启动 HTTP/1.1 服务，并监听环境变量 `VIBEHUB_SOCKET`，当前固定为
`/run/vibehub/app.sock`。启动前删除自己遗留的同名 socket，再以运行 UID 65532 bind；
`GET /healthz` 必须快速返回 `200`。

不要监听 `0.0.0.0`、`127.0.0.1` 或任意 TCP 端口；平台只通过 UDS 访问作品，不发布容器端口。
容器可以主动访问公网、局域网、CDN 和包仓库。

### 基础路径与玩家会话

每次转发请求都包含两个由平台覆盖写入的可信请求头：

- `X-VibeHub-Base-Path`：当前外部 URL 前缀。链接、表单和静态资源应使用相对 URL，或显式拼接该前缀。
- `X-VibeHub-Session-Id`：当前玩家的匿名会话 ID。多人会共享同一个容器，内存状态必须按它隔离。

玩家不能伪造这两个值。平台不会把 NumericalOJ 的 Cookie、登录身份或密钥交给作品。
容器根文件系统只读，`/tmp` 和 `/run/vibehub` 是临时内存盘。
需要跨重建保留的文件必须写到 `/data` 或 `$HOME`（固定为 `/data/home`）。同一 project id 的
`public`、`latest`、`review` 各有独立数据盘；`review` 复用 `latest` 镜像。作品不能声明
`VOLUME` 或选择宿主路径。

### 请求边界

支持普通 HTTP/1.1 的 `GET`、`HEAD`、`POST`、`PUT`、`PATCH`、`DELETE` 和 `OPTIONS`，
平台代理作品自身接口时不支持 WebSocket 或 CONNECT。请求体和响应体默认各最多 16 MiB，
单次请求默认最多 15 秒。作品后端可直接访问外部网络；前端也可加载外部资源、调用
HTTP(S) API 或连接外部 WebSocket。跨域 fetch/WebSocket 仍受对方服务器 CORS/Origin 策略与浏览器
混合内容规则影响。
作品运行在不含 `allow-same-origin` 的 sandbox iframe 中，不能读取站点页面、浏览器 Cookie 或控制
顶层窗口。这一隔离边界不禁止作品联网。

## edu 可视化作业

### 声明作品类型

普通作品保持原清单格式。可由管理员布置为作业的作品，增加以下声明：

```json
{
  "schema_version": 1,
  "transport": "unix",
  "socket_path": "/run/vibehub/app.sock",
  "health_path": "/healthz",
  "title": "动态平衡术",
  "summary": "用两棵堆维护动态中位数",
  "tags": ["教学", "堆"],
  "cover_image": "static/cover.png",
  "kind": "edu",
  "education": {
    "protocol": "vibehub-edu/1",
    "socket_path": "/run/vibehub/edu.sock"
  }
}
```

作品启动时同时监听两个 HTTP/1.1 Unix socket：`app.sock` 提供页面及普通作品接口，
`edu.sock` 提供下述教学接口。两个路径固定，不能声明 TCP 端口。浏览器的普通作品请求只会
连接 `app.sock`，不能指定或切换到 `edu.sock`。不要把教学内部接口再挂到 `app.sock`。

### 开发者负责的三个函数

建议将 HTTP 适配、题目规则和评分分别保存；下面只展示后端结构：

```text
my-edu/
├── Dockerfile
├── vibehub.json
├── server.py          # 两个 socket 的 HTTP 服务与 JSON 校验
├── exercise.py        # start(context)、step(context, state, action)
├── grading.py         # grade(context, actions)，从初始条件重放评分
└── static/
```

平台在内部调用以下接口，消息均为 JSON。`context` 由平台生成，字段为 `attempt_id`、
`assignment_id`、`project_version_id`、`rubric_version`、`challenge_seed`、`parameters`；
作品不得依赖其中有学生学号、姓名或 OJ 登录 Cookie。

| 内部接口 | 请求 | 成功响应 |
| --- | --- | --- |
| `POST /v1/start` | `{ "context": {...} }` | `{ "state": {...}, "view": {...} }` |
| `POST /v1/step` | `{ "context": {...}, "state": {...}, "action": {...}, "seq": 1 }` | `{ "state": {...}, "view": {...} }` |
| `POST /v1/grade` | `{ "context": {...}, "actions": [...] }` | `{ "verdict": "passed", "score_bp": 10000, "metrics": {...}, "feedback": "..." }` |

`state` 是平台保存的内部 JSON 状态；`view` 才交给学生浏览器。答案、未公开题目和隐藏测试不要
放进 `view` 或静态文件。`score_bp` 必须是 `0～10000` 的整数，平台将其折算为作业分数。
`verdict` 为 `passed` 或 `failed`。`metrics` 用于保存轮数、操作次数等证据，
`feedback` 为给学生看的纯文本反馈。

`start` 使用 `context` 中的平台随机种子生成题目；`step` 只根据平台提供的旧状态和操作计算
新状态，不接受浏览器上传的完整状态。三个接口应可重复调用且不产生外部写入；需要随机数时
使用传入种子，避免重试或评分重放时得到不同结果。评分从初始条件及按序记录的操作重新计算，
不要采用浏览器提交的 `score`、`completed`、步数或最终状态。

### 页面怎样操作与交作业

从作业列表进入时，平台先根据 OJ 登录身份创建或恢复作答，并把运行租约绑定到该作答。
作品页面在 `X-VibeHub-Base-Path` 前缀下使用平台保留的 `/_edu/v1/` 接口：

| 页面接口 | 消息或结果 |
| --- | --- |
| `GET ./_edu/v1/state` | 读取 `seq`、`view` 与作答状态 |
| `POST ./_edu/v1/actions` | `{ "command_id": "本次操作唯一编号", "expected_seq": 0, "action": {...} }` |
| `POST ./_edu/v1/submit` | `{ "request_id": "本次提交唯一编号", "expected_seq": 1 }` |
| `GET ./_edu/v1/result` | 读取本次作答最新提交的判定、成绩和反馈 |

这些路径由平台处理，不转发到作品页面服务。`action` 的业务字段由作品定义，例如交换节点或
提交一份候选程序。学生不填写学号，也不能通过请求参数决定成绩属于谁。

每次操作必须带上当前 `seq`。平台调用内部 `step`，保存操作和新状态后才更新序号；版本冲突
返回 `409`，此时重新读取状态。网络重试应复用原 `command_id` 和原请求内容，不能为同一次
操作生成新编号。提交的 `request_id` 同理：平台冻结记录后评分，重试查询同一次提交，
不会把浏览器声称的分数写入成绩。

OJ 登录态客户端也可使用以下接口，权限同样绑定当前账号：

```text
POST /api/vibehub/projects/{slug}/edu/launch    {assignment_id?}
GET  /api/vibehub/edu/attempts/{attempt_id}
POST /api/vibehub/edu/attempts/{attempt_id}/actions
POST /api/vibehub/edu/attempts/{attempt_id}/submit
GET  /api/vibehub/edu/attempts/{attempt_id}/result
GET  /api/vibehub/edu/submissions/{submission_id}
```

`launch` 返回 `attempt_id`、`seq` 和运行租约。`assignment_id` 是 edu 全局作业编号，取作业行的
`vibehub_edu_assignment_id` 或 demo URL 的 `assignment` 参数，不是班级动态表的作业行 ID；省略则为自由练习。
自由练习成绩不计入班级作业。CLI 无需持有作品内部教学接口的访问凭据。

教学固定版本首次启动会优先复用包标识完全匹配的已发布或最新镜像，直接按镜像 ID 固定别名，
不重复构建或导出已经存在的镜像。已有固定版本别名保持不变；只有找不到相同作品包镜像的历史
版本才从保留的快照补建。镜像准备锁等待超时时会明确提示“教学作品镜像正在准备”。

### 动态平衡术与学生 C++ 程序

随仓库提供的“动态平衡术”示例使用平台白名单执行器，在清单 `education` 中增加
`"executor": "cpp-heap-median-v1"`。学生实现 `int step(int x)`，每次收到下一个整数，
可调用 `A.insert(x)`、`A.pop()`、`A.top()`、`A.size()` 及对应的 `B` 操作。`A` 为大顶堆，`B` 为小顶堆；
要求返回所有已输入整数的当前中位数，偶数个元素取两个中间值中较小的一个。
只提交函数及需要的辅助代码，不编写 `main`，也不自行输出内容。堆 API 的 `insert(int)` 和
`pop()` 返回 `void`，`top()` 和 `size()` 返回 `int`；空堆上的 `pop`、`top` 会报错，
`size()` 返回当前元素个数，空堆返回 0。同一输入序列中的函数调用共享全局变量及两棵堆。

页面显示两棵堆的树结构和执行轨迹。平台通过受控的 `docker exec`，在已经启动的 VibeHub
作品容器中编译、运行学生程序，不再额外启动判题容器，也不给作品 Docker socket。固定执行
驱动由平台提供，每次使用不同于作品服务的随机 UID 和权限为 0700 的临时目录；容器原有的
只读根目录、`/tmp` 的 `noexec`、资源上限和应用 socket 权限保持不变。编译产物通过匿名
memfd 执行，源码和产物不落入持久化 `/data`。完成后清理该 UID 的全部进程与临时文件；若
无法确认清理完成，平台回收该作品实例。执行请求共享作品容器的 CPU、内存、进程和网络边界。
编译标准输出限 16 KiB，程序标准输出限 1 MiB，两个阶段的标准错误各限 64 KiB；超限作为
学生编译或运行错误处理。这些结果经 base64 编码后合计仍在执行响应的 2 MiB 上限之内。
学生源码仍限 64 KiB；包含平台驱动和输入的内部 JSON 请求限 512 KiB，以容纳源码最坏六倍的
控制字符转义，不会因合法长度的源码需要转义而错误地判定执行服务不可用。
自定义任意执行器名称不会获得执行能力；开发新的编程类教学作品前，先确认平台已有受支持
的执行器。

该执行器的操作格式固定为：

```json
{
  "type": "run_code",
  "source": "int step(int x) { /* 学生实现 */ }"
}
```

试玩输入由 `context.parameters.inputs` 给出。平台先编译执行，再将可信的执行结果放入内部
`context.execution` 交给作品生成展示状态；浏览器不能填写 `execution`。提交评分时，平台
从冻结记录取得源代码，使用独立隐藏输入再次执行，并把这次结果交给 `/v1/grade`。因此本地
伪造堆画面或试玩输出不会改变提交成绩，作品评分器也不应只依据试玩是否通过。

### 发布、布置与成绩

edu 作品沿用普通作品的创建、构建、审核与公开发布流程。管理员布置作业时可选择已公开的
edu 作品；作业冻结当时的公开版本，作者后续更新作品不会替换已有作业的评分规则。

学生在 homework list 点击该项，直接进入 `/vibehub/{slug}/play?assignment={作业编号}`。
edu 提交独立保存，不显示在普通 submission list；班级成绩导出会包含 edu 作业成绩，并沿用
作业的截止时间与计分规则。评分的可信规则来自管理员指定的作品版本；平台验证身份、记录和
调用通道，不能替一个规则有误的自定义评分器证明教学目标已经完成。

管理员 CLI 布置与导出示例：

```bash
python3 skills/numoj-admin/scripts/numoj_admin.py vibehub list
python3 skills/numoj-admin/scripts/numoj_admin.py homework add \
  --class-en C2026A --vibehub-project-id 7 --ddl 2026-12-31T23:59
python3 skills/numoj-admin/scripts/numoj_admin.py homework export-scores \
  --class-en C2026A -o scores.csv
```

登录后的学生可通过 CLI 进行相同作答。操作 JSON 必须遵守具体作品的规则：

```bash
python3 scripts/numoj_user.py vibehub edu launch dynamic-balance --assignment-id 12
python3 scripts/numoj_user.py vibehub edu state <attempt_id>
python3 scripts/numoj_user.py vibehub edu action <attempt_id> \
  --expected-seq 0 --command-id command-1 --action @action.json
python3 scripts/numoj_user.py vibehub edu submit <attempt_id> \
  --expected-seq 1 --request-id submit-1
python3 scripts/numoj_user.py vibehub edu result --attempt-id <attempt_id>
```

提交时平台锁定作答行并冻结连续操作记录；同一最终序号的重交只返回原提交，不会创建重复成绩。
若数据库保存后队列派发失败，待处理提交由现有后台巡检补投；评分使用退避重试，失败后也可
在示例页面点击“重试评分”。重新评分始终使用原快照，不采纳新代码或新分数。
作业及其历史作答引用的作品版本会保留，已有教学记录的作品不能直接删除。

## 使用 CLI 管理作品

### 查看作品

```bash
# 公开作品
python3 scripts/numoj_user.py vibehub list

# 自己的作品与最新版本
python3 scripts/numoj_user.py vibehub mine

# 查看公开版本或自己的最新版本
python3 scripts/numoj_user.py vibehub detail <slug> --view public
python3 scripts/numoj_user.py vibehub detail <slug> --view latest
```

### 创建并自动送审

`create` 会在一次操作中构建不可变的 v1、更新 `latest`，并自动提交审核：

```bash
python3 scripts/numoj_user.py vibehub create ./my-vibe.zip \
  --title "我的作品" \
  --summary "一句话简介" \
  --tags "游戏,创意"
```

可用 `--slug` 指定稳定地址；只允许小写字母、数字和连字符，长度为 3–63。未指定时平台自动生成。
`--description @README.md` 可从文件读取详细说明，`--cover-image` 可覆盖清单中的包内封面路径。

### 从 Git 仓库提交

创建和编辑作品页面都可选择「ZIP 文件」或「Git 仓库」。Git 模式填写仓库地址后自动读取远端默认分支，使用自定义下拉菜单选择其他分支或标签；切换地址会取消旧查询，读取失败可重试。CLI 的分支参数仍可省略，默认使用远端默认分支。提交后由服务器浅克隆并固定为一个 commit，再进入与 ZIP 相同的校验、构建和审核流程。

```bash
python3 scripts/numoj_user.py vibehub create --git-url git@example.org:owner/project.git \
  --git-ref main --title "我的作品"
python3 scripts/numoj_user.py vibehub update <slug> --git-url git@example.org:owner/project.git --git-ref main
```

管理员 CLI 的参数相同。ZIP 路径与 `--git-url` 必须二选一。仓库根目录需包含 `Dockerfile` 和 `vibehub.json`；支持 HTTPS、HTTP、SSH 及 SCP 风格地址，不支持本地路径、子模块或自动拉取 Git LFS 对象。地址不能包含密码或查询参数。私有仓库需预先允许服务器部署用户的 SSH 身份只读访问；客户端本机能访问并不代表服务器能访问。Git 操作限时 180 秒，对象与源码归档各限制 5 GiB，解压限制沿用 8 GiB。

每次提交仅固定当时的 commit，不会自动跟随分支变化。作者和管理员可在作品详情 API 的 `source` 中查看仓库、分支和 commit；公开接口不暴露私有仓库地址。

### 实时构建进度

创建作品、提交新 ZIP/Git 版本以及保存作品编辑时，网页会打开构建进度弹窗，实时显示准备阶段、BuildKit 输出（包括 `CACHED`）和最终成功或失败结果。作品包、构建上下文（含 Dockerfile）和基础镜像 ID 均未变化，且对应成品镜像仍存在时，会显示“复用已有镜像”，直接跳过构建、导出和加载。需要构建时，日志间歇没有新行的连接仍通过心跳保持。

两个 CLI 的 `vibehub create`、`update`、`edit` 默认消费同一进度流。进度立即写入 **stderr**，最终作品 JSON 写入 **stdout**，可以使用 `> result.json` 保存结果而继续在终端查看构建过程。进度流中断时不会自动重复提交；请先用 `vibehub detail <slug> --view latest` 核对最终版本。

自定义客户端可在创建、版本更新或编辑请求中设置 `Accept: application/x-ndjson`。每行是一个独立 JSON 事件：`progress`（`phase`、`message`）、`log`（`message`）、`heartbeat`（`elapsed_seconds`）、`result`（`success: true`、`project`）或 `error`（`success: false`、`message`、`code`/`http_status`）。流式响应开始后业务错误通过 `error` 事件返回，不能仅按 HTTP 200 判断成功；必须收到 `result`。未请求该格式的客户端仍收到原有 JSON 响应。

进度只返回本次已鉴权请求，不公开日志；输出经过脱敏及长度限制。关闭页面或断开 CLI 不会撤销已经开始的构建事务。重新连接后先查看最新版本，避免重复创建。

### 缓存依赖和模型下载

平台先检查 Docker Engine 中已有的成品镜像，核对受管标签、作品包摘要、构建上下文摘要和基础镜像不可变 ID；全部一致时直接复用，仍校验当前镜像大小预算与 VOLUME 限制。此机制同样适用于部署时同步的预置作品。只有内容或基础镜像变化、镜像丢失时才进入构建；Docker 查询失败会明确报错，不会被当成缓存缺失。

需要构建时使用持久化 BuildKit 步骤缓存。把变化较少的依赖清单、下载脚本和模型哈希清单单独复制并执行，再复制业务源码；不要把 `COPY .` 放在安装或下载之前。只有对应输入或基础镜像变化才需要重做相应步骤。

```dockerfile
FROM numericaloj-vibehub-runtime:1
ENV PIP_INDEX_URL=https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple
COPY --chown=65532:65532 requirements.txt /app/requirements.txt
RUN python -m pip install --target /app/vendor -r /app/requirements.txt
COPY --chown=65532:65532 download_model.py model-files.json /app/
RUN python /app/download_model.py
COPY --chown=65532:65532 . /app
```

权重和安装包无需提交到 Git。中国大陆部署可用清华 PyPI 镜像安装 Python 包，用 ModelScope 下载模型；下载脚本应固定版本、校验大小与 SHA-256，并支持失败重试。构建成功后模型保存在作品镜像中，运行时无需再次下载。缓存属于宿主持久构建缓存，管理员清理缓存、替换构建器或更换基础镜像后可能重新执行；运行时的 JIT 缓存另写入 `/data`。

### 更新并自动重新送审

提交新 ZIP 或 Git 仓库会构建递增的不可变版本、更新 `latest` 并自动重新送审，不会覆盖旧版本：

```bash
python3 scripts/numoj_user.py vibehub update <slug> ./my-vibe-v2.zip
```

只修改标题、简介、说明、标签或封面路径时使用 `edit`。保存同样会准备 `latest` 镜像、生成新版本
并自动重新送审：

```bash
python3 scripts/numoj_user.py vibehub edit <slug> \
  --title "新的名称" \
  --description @README.md
```

作品只维护 `latest`、`public` 两个镜像别名；保存时构建 `latest` 并自动送审，`review` 复用
`latest`。审核通过让 `public` 指向已确认的 `latest`，不重新构建；通过前其他用户仍看到旧版本。

## 版本、配额与运行资源

- 精品资格只能由管理员设置或取消，作者不能主动申请。
- 普通用户同时最多拥有 2 个未获精品资格的作品。
- 每个用户的持久作品快照逻辑用量上限为 20 GiB；每个作品的版本数量也受站点配额限制。
- 普通作品运行上限为 4 GiB 内存、2 CPU、256 PID 和 20 GiB 镜像。
- 精品作品运行上限为 8 GiB 内存、4 CPU、512 PID 和 40 GiB 镜像。
- `/tmp` 和 `/run/vibehub` 是有界 tmpfs；`/data` 持久保存，但当前没有可移植的硬配额。
- 首位玩家打开作品时按需启动已构建的作品。最后一位玩家离开、在途请求结束后，默认立即停止容器，释放 CPU、内存和显存；保留停止的容器、镜像及 `/data`。下一位玩家访问同一版本时重新启动该容器，无需重新构建或下载。断网等未正常退出的情况在访问租约过期后处理；平台可配置关闭宽限。停止会结束进程，应用内存状态不会保留，需恢复的数据和缓存应写入 `/data`。
- GPU 宿主通过 NVIDIA Container Toolkit Base 1.20.0 的 CDI 描述将现有显卡与驱动接入 Docker；部署脚本固定安装包 SHA-256，并核验 GPU UUID。运行时使用 `--device nvidia.com/gpu=<GPU UUID>` 显式选择 NVIDIA 设备。该组件不安装 CUDA Toolkit 或显卡驱动，也不要求重启 Docker。

## GPU

生产环境最近核验于 **2026-09-07**：RTX 3090 Ti，NVIDIA 驱动 **560.35.05**，
宿主机 CUDA Toolkit **12.6**（`/usr/local/cuda-12.6`，nvcc **12.6.85**）。平台为获得
GPU 额度的容器将这个固定目录只读挂载到同一路径；CPU 容器没有此挂载。CUDA Runtime、
cuBLAS、cuFFT、cuRAND、cuSOLVER、cuSPARSE、NVRTC、nvJitLink 等复用宿主库。
NVIDIA Container Toolkit 注入宿主驱动和 NVML，作品无需安装驱动或另一套 CUDA。
平台设置 `CUDA_HOME`、`LD_LIBRARY_PATH` 和 `TRITON_PTXAS_PATH`，不会加载 Toolkit 的驱动桩库。

共享 vLLM 使用 PyTorch cu126 和宿主 nvcc 从源码编译，目标为当前 RTX 3090 Ti 的 SM 8.6。
管理员通过 `deploy.sh` 传入 `host_cuda=/usr/local/cuda-12.6` 构建上下文；该目录只在受信基础
镜像编译时临时挂载，既不复制进镜像，也不开放给作品构建步骤。更换 GPU 架构或宿主 Toolkit
需要同步重建基础镜像、更新平台挂载及本文记录。CUDA 版本不能仅靠更改环境变量切换。
运行时 JIT 缓存应放到 `/data` 下（如 `TRITON_CACHE_DIR=/data/triton-cache`），因为 `/tmp` 禁止执行。

- 创建或编辑作品时开启 GPU 并申请显存，管理员创建作品也一样。每次保存的新版本重新送审；普通作者审核前不能运行 GPU 版本，管理员可以试玩，包括自己的作品。旧公开版本不受待审核修改影响。
- 审核可批准或下调显存，也可只发布 CPU 版本；意见在作者的编辑弹窗中查看。CLI 使用 `--gpu-memory-mib`（256–24576 MiB），`0` 关闭 GPU；省略时创建默认关闭，更新沿用申请值。
- 当前使用 RTX 3090 Ti（24 GiB），仅开放 CUDA 计算。优先使用基础镜像中的 GPU 环境，仅对缺失库追加兼容依赖；构建阶段不使用 GPU。运行时 `VIBEHUB_GPU_MEMORY_MIB` 表示当前显存额度。
- 显存为超限回收，非硬隔离。同一作品的多进程、多容器合计计量；新旧额度并存时总量取较高的有效额度，各容器仍受自身额度约束。目标采样间隔为 1 秒，超限或监测失败会停止该作品的 GPU 容器，60 秒后可重试。额度不保证设备空闲显存。

## 提交前检查

1. ZIP 根目录直接包含 `Dockerfile` 和 `vibehub.json`，没有额外外层目录。
2. 程序包不含密钥、隐私数据、符号链接、FIFO 或 socket；ZIP 和解压总量符合大小上限。
3. `cover_image` 指向包内真实 PNG、JPEG 或 WebP，主体位于 16:9 中央安全区。
4. 需要联网安装的依赖使用 lockfile 或精确版本。
5. 容器以非 root 身份在 `VIBEHUB_SOCKET` 上提供 HTTP/1.1，`GET /healthz` 返回 `200`。
6. 所有 URL 尊重 `X-VibeHub-Base-Path`，多人状态按 `X-VibeHub-Session-Id` 隔离。
7. 需要持久化的数据只写入 `/data` 或 `$HOME`，临时数据写入 `/tmp`。
