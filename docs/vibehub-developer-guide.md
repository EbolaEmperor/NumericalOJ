# VibeHub 开发者手册

VibeHub 接受一个完整 ZIP 作品包。作品的前端和后端位于同一个 Docker 镜像中，
但运行时没有 TCP/UDP 网络，也不会发布端口。作品监听容器内 Unix domain socket；
NumericalOJ 通过受信任的有界 `docker exec` relay 转发浏览器请求。

## 最小作品包

ZIP 解压后的根目录必须直接包含 `Dockerfile` 和 `vibehub.json`：

```text
my-vibe/
├── Dockerfile
├── vibehub.json
├── app.py
└── static/
    └── cover.jpg
```

`vibehub.json` 的运行协议固定如下。不得添加 `port`：

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

`cover_image` 必填，只接受包内真实的 PNG、JPEG 或 WebP 相对路径。平台不会改写包内
原图，而会生成固定 1280×720、严格 16:9、最多 400 KiB 的 JPEG 安全副本供卡片和详情页
使用。原图窄于 16:9 时保持宽度并上下对称裁切，宽于 16:9 时保持高度并左右对称裁切；
奇数余量固定把较多的 1 像素留在下侧或右侧。为限制解码资源，原图仍不得超过 16 MiB、
8192×8192 或 1600 万像素。

镜像默认命令必须以前台进程启动 HTTP/1.1 服务，并监听环境变量
`VIBEHUB_SOCKET`（当前固定为 `/run/vibehub/app.sock`）。启动前先删除自己遗留的同名
socket，再以运行 UID 65532 bind；`0600` 即可，因为应用与受信 relay 使用同一 UID。
`/run/vibehub` 是容器内 16 MiB tmpfs，不会挂载到宿主，容器回收时一并消失。
`GET /healthz` 必须快速返回 `200`。不要监听 `0.0.0.0`、`127.0.0.1` 或任意端口，
因为容器使用 `--network none`，这些端口不会被转发。

管理员先预置受信任基础镜像：

```bash
docker build -t numericaloj-vibehub-runtime:1 docker/vibehub-runtime
```

生产发布不直接用构建命令覆盖这个 stable 标签：`deploy.sh` 会先构建并核验带
run-id 的候选镜像，停服并完成数据库回滚点后才切换 stable；后续部署失败时恢复
切换前的镜像 ID。上面的命令只用于首次本地开发环境预置。

作品 Dockerfile 的最小写法：

```dockerfile
FROM numericaloj-vibehub-runtime:1
COPY --chown=65532:65532 . /app
CMD ["python", "/app/app.py"]
```

构建完全离线。MVP Dockerfile 只允许一个位于首行的固定 `FROM`，以及 `COPY`、`CMD`、
`ENTRYPOINT`、`WORKDIR`、`ENV`、`LABEL`；禁止 `RUN`、`USER`、`VOLUME`、`ONBUILD`、
`HEALTHCHECK`、`ADD`、多阶段构建、外部 frontend 和 `COPY --from`。COPY flags 只允许精确
`--chown=65532:65532`；上传快照按最小权限保存，作品应使用该 flag 让运行 UID 能读取文件。
`FROM` 必须命中管理员白名单且已存在于本机，`COPY` 目标只能位于 `/app`。Python wheel、
JavaScript bundle、模型或其它依赖必须随作品包直接提供；先在可信开发机生成 lockfile、
vendor 依赖和前端产物，再上传自包含包。缺失基础镜像会直接失败，不会自动 pull。

构建器优先使用 BuildKit。若 Docker CLI 精确报告“BuildKit 已启用但 buildx component
missing or broken”，运行器只针对这一种本地安装缺陷重试一次 legacy builder；重试仍
使用完全相同的 `--network none`、`--pull=false`、内存/CPU、ulimit 和超时参数。任何
其它 BuildKit、Dockerfile 或构建错误都失败关闭，不会切换 builder。legacy 路径只是本地
兼容回退，生产应安装和维护可用的 buildx/BuildKit。

`--network none`、4 GiB 内存、2 CPU、ulimit、构建总时限和全宿主单构建槽共同约束构建。
生产环境仍不得与 Web/数据库共用无配额的 Docker data-root；应在独立构建节点或独立
配额文件系统中构建，并持续清理失败构建缓存。基础镜像、最终镜像和每次运行前都会
inspect `Config.Volumes`，且最终镜像强制执行 20/40 GiB 上限；这些检查不能替代节点硬配额。
作品镜像缓存键同时绑定作品上下文摘要与基础镜像的不可变 image ID；管理员更新同名基础
镜像 tag 后，下一次启动会自动重建作品镜像，不会继续误用旧 base。

## HTTP 请求约定

外部 URL 带有短期随机 lease token。应用不要猜测公开 URL，应读取每个请求中由可信
代理覆盖写入的头：

- `X-VibeHub-Base-Path`：当前 lease 的外部 URL 前缀；生成静态资源、表单和 API URL
  时必须以它为前缀。
- `X-VibeHub-Session-Id`：当前玩家的不可伪造匿名会话 ID。多个玩家可能共享同一个
  容器，后端应以此隔离内存会话；它不包含用户名，也不能用于访问 NumericalOJ API。

客户端传入的同名头会被丢弃。代理同样不会把 OJ 的 Cookie、Authorization、CSRF
token 或用户身份交给作品。响应头采用严格白名单：作品返回的 `Set-Cookie`、任意自定义
安全头、hop-by-hop 头和 CORS 放宽头都不会透传；站内相对 `Location` 会重写到当前 lease
前缀，外站重定向会丢弃。需要会话状态时，请以 `X-VibeHub-Session-Id` 为键保存在容器
内存或 `/tmp`；容器回收后这些状态会消失。

当前协议支持普通 HTTP/1.1 的 `GET`、`HEAD`、`POST`、`PUT`、`PATCH`、`DELETE` 和
`OPTIONS`，不支持 WebSocket、CONNECT 或任意外联。请求体默认最多 16 MiB，响应体
默认最多 16 MiB（可配置硬上限均为 64 MiB），单次请求默认 15 秒端到端总时限。代理会
先验证 capability 与活跃 lease、取得全宿主共享的有界转发槽，再从 WSGI 流限量读取请求体；
无效 token 或容量拒绝不会预先缓冲 body。作品页面在不含 `allow-same-origin` 的 sandbox
iframe 中运行；不要依赖顶层导航、弹窗控制、OJ DOM、浏览器 Cookie 或同源权限。

## 版本、发布与精品

创建作品或上传完整新包都会生成不可变版本。`latest` 始终指向作者最新草稿，`public`
指向所有已登录站点用户实际游玩的已发布副本；两者可以是不同版本。作者提交审核时会固定
当时的版本，即使随后继续编辑，管理员审核的仍是已提交副本，线上版本也不会被草稿覆盖。
普通用户的更新必须再次提交并通过审核；管理员只可免审发布自己拥有的作品，不能越权修改
其他作者的草稿。精品申请只针对已经公开的版本，审核通过后运行资源翻倍。

普通用户同时最多占用 2 个普通作品名额；处于精品申请审核中的作品仍占名额，管理员批准为
精品后才释放该名额。已存在的作品即使后来超过上限也不会被删除，编辑、上传新版本和重新
提交审核不受作品数量门槛影响。管理员创建作品不受此数量限制，但仍遵守存储、版本、作品包
与容器安全边界。

持久作品快照按用户 20 GiB 的逻辑用量硬限制执行；硬链接按每个目录入口重复计数，符号链接、
特殊节点和嵌套挂载会失败关闭。上传先进入严格命名的私有
`.staging/upload-<32 位十六进制 ID>/snapshot`。平台在同一个全局存储变更锁内、每次上传
配额计算前完整审计该命名空间：当前请求的精确暂存无论耗时多久都不会被清理，未超过一小时
宽限的其它会话会保留，超过一小时的崩溃孤儿才会按目录 fd 安全回收并记录受控
审计日志。未知入口、符号链接、特殊节点、设备或属主漂移都会停止回收和本次上传，不会执行
宽泛递归删除。
路由先做不触发 body 或 DB 的登录/管理员身份检查，再取得全宿主共享的有界
持久变更槽。创建、上传、元数据编辑和发布申请会在槽内先做适用的 DB 名额/作者预检，
再解析 `request.files`/`request.form` 并等待全局存储锁；管理员发布审核没有 multipart，
会在无 DB 管理员鉴权后进入槽，解析小型决策 body，再在事务中锁定并复核待审版本。
上传请求的槽会一直保持到作品包已搬入受管 `.staging` 并完成处理，释放前显式关闭
全部 FileStorage；异常也会释放。容量满时快速返回 429，避免多 worker/gthread 把
256 MiB 请求同时 spool 到宿主临时目录，也避免大量请求阻塞在存储变更锁上。

版本不再被 `latest`、`public` 或待审 `review` 引用后，平台只会在数据库提交成功后写入退役
marker；marker 同时绑定版本号、物理设备号和 inode。若进程恰好在 DB 提交与常规
marker 写入之间退出，下一次配额前审计会为 DB 已知、非 live 的物理快照补写绑定
marker；该次仍计入用量，绝不会立即删除。宽限一小时后，下一次该用户的上传或
元数据编辑会先锁定其全部版本事实、完整审计作品树，再精确回收过期死快照，之后才计算用户
存储配额，因此退役副本不会反过来卡住清理本身。任何仍属 live-set 的版本都不会删除；异常
marker、缺失 DB 历史、未知入口或 inode 漂移均失败关闭。

## API 与 CLI

API 使用 NumericalOJ 现有登录会话和 CSRF/同源保护。创建与上传版本采用
`multipart/form-data`，ZIP 文件字段名为 `package`；其余元数据可放在同一个表单中。
所有变更接口都要求登录，管理员队列和决策接口还要求管理员身份。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/vibehub/developer-guide` | 获取这份 Markdown 手册 |
| `GET` | `/api/vibehub/projects` | 列出公开作品 |
| `GET` | `/api/vibehub/projects/mine` | 列出自己的作品和最新草稿 |
| `GET` | `/api/vibehub/projects/<slug>?view=public\|latest\|review` | 查看公开副本、本人草稿；`review` 仅管理员查看当前待审副本 |
| `POST` | `/api/vibehub/projects` | 以完整 ZIP 创建作品 |
| `POST` | `/api/vibehub/projects/<slug>/versions` | 上传新的不可变版本 |
| `PATCH` | `/api/vibehub/projects/<slug>` | 编辑元数据并生成新版本 |
| `POST` | `/api/vibehub/projects/<slug>/review` | 固定最新版本并提交发布审核 |
| `POST` | `/api/vibehub/projects/<slug>/featured` | 为已发布作品申请精品 |
| `GET/POST` | `/api/vibehub/admin/reviews[/<slug>]` | 管理员列出并通过或拒绝发布审核 |
| `GET/POST` | `/api/vibehub/admin/featured[/<slug>]` | 管理员列出并通过或拒绝精品申请 |

用户 CLI 和管理员 CLI 都提供 `vibehub guide`、公开列表、本人作品、创建、更新、元数据编辑、
提交审核和申请精品。先按各自 skill 的说明执行 `init`，再查看服务器实际支持的命令：

```bash
python3 skills/numoj-user/scripts/numoj_user.py vibehub --help
python3 skills/numoj-user/scripts/numoj_user.py vibehub guide -o vibehub-developer-guide.md
python3 skills/numoj-user/scripts/numoj_user.py vibehub create my-vibe.zip --title "我的作品"
python3 skills/numoj-user/scripts/numoj_user.py vibehub update <slug> my-vibe-v2.zip
python3 skills/numoj-user/scripts/numoj_user.py vibehub submit-review <slug>
python3 skills/numoj-user/scripts/numoj_user.py vibehub request-featured <slug>
```

管理员在此基础上还可执行审核；`decision` 只接受 `approve` 或 `reject`：

```bash
python3 skills/numoj-admin/scripts/numoj_admin.py vibehub pending
python3 skills/numoj-admin/scripts/numoj_admin.py vibehub review <slug> approve --note "审核意见"
python3 skills/numoj-admin/scripts/numoj_admin.py vibehub featured-pending
python3 skills/numoj-admin/scripts/numoj_admin.py vibehub featured-review <slug> approve
```

## 生命周期与资源

首位玩家取得 lease 时容器按需启动；同一作品版本的后续玩家复用该容器。前端定期发送
heartbeat，并在 `pagehide` 时 release。最后一个 lease 释放且没有进行中的请求时，
宿主立即执行 `docker rm -f`，并在确认没有其它启动中或运行中的实例引用相同 image ID 后
移除该通道的稳定镜像 tag；下次游玩会从权威作品包重新离线构建。浏览器崩溃时由短 TTL
和定时 reaper 兜底。heartbeat 健康检查使用独立的宿主并发槽；容量满时返回 429 且不会续租。
宿主默认最多同时运行 8 个作品容器（运维可用 `VIBEHUB_MAX_ACTIVE_RUNTIMES` 在 1–64
范围内配置）；达到上限后，新作品启动会收到 HTTP 429，但已运行的同作品、同版本仍可
继续取得 lease 并共享现有容器。

普通作品限制为 4 GiB 内存、2 CPU、256 PID 和 20 GiB 完整镜像；审核为精品后翻倍为
8 GiB、4 CPU、512 PID 和 40 GiB 镜像。20/40 GiB 是只读、不可变的完整镜像预算，
不是持久可写硬盘。根文件系统只读，只有有界 `/tmp` 和 `/run/vibehub` tmpfs 可写；
容器重启或回收后数据全部消失。应用 socket 位于独立的 16 MiB 容器 tmpfs；Linux 与
Darwin 都只由基础镜像内置的有界 relay 通过 `docker exec` 连接。作品没有任何宿主可写
bind，因此不能借 `app.sock` 所在目录创建、隐藏或持续写入宿主文件。

容器同时启用 `--cap-drop ALL`、`no-new-privileges`、非 root UID、只读 rootfs、私有
cgroup/IPC、默认 seccomp、PID/内存/CPU/ulimit、受限日志和 `--pull never`。不会挂载
Docker socket、OJ 源码、上传根目录、系统包目录、数据库凭据或任何其它作品目录。
生产环境强制安装 gVisor，并把运行器的 `oci_runtime` 配置为 `runsc`，增加一层用户态内核
隔离；运行器只接受简单 runtime 名称并显式传给 `docker run --runtime`。生产镜像构建还使用
断网的专属 `docker-container` Buildx builder，基础镜像由 deploy 以绑定 daemon image ID 的
本地 OCI layout 注入，构建缓存只在该 builder 内按预算清理。本地开发没有 gVisor/Buildx 时
可将 runtime 与 builder 留空，继续走 Docker 默认 OCI runtime 和兼容 builder；这不具备生产
隔离强度，也不会调用任何全局 builder prune。

## 本地检查

上传前至少确认：

1. ZIP 根目录层级正确，且没有符号链接、FIFO、socket 或超大文件。
2. `cover_image` 已声明真实 PNG/JPEG/WebP；主体位于画面中央安全区。
3. 受信任基础镜像已由管理员预置，所有依赖均已 vendor。
4. 容器以非 root 身份启动，能在固定 UDS 上响应 `GET /healthz`。
5. 所有 URL 都基于 `X-VibeHub-Base-Path`，多人状态以
   `X-VibeHub-Session-Id` 隔离。
6. 停止容器后不需要保留任何本地状态。
