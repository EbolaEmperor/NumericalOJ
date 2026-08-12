# VibeHub 开发者手册

VibeHub 接受一个包含前端、后端和运行声明的完整 ZIP 程序包。作品在无网络的隔离容器中运行，
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

### Dockerfile 与离线依赖

作品镜像必须基于平台提供的受信任基础镜像。最小 Dockerfile：

```dockerfile
FROM numericaloj-vibehub-runtime:1
COPY --chown=65532:65532 . /app
CMD ["python", "/app/app.py"]
```

Dockerfile 只允许一个位于首行的固定 `FROM`，以及 `COPY`、`CMD`、`ENTRYPOINT`、`WORKDIR`、
`ENV`、`LABEL`。禁止 `RUN`、`ADD`、`USER`、`VOLUME`、`ONBUILD`、`HEALTHCHECK`、多阶段构建、
外部 frontend 和 `COPY --from`。`COPY` flag 只允许精确的 `--chown=65532:65532`，目标必须
位于 `/app`。

构建完全离线，不会下载基础镜像、依赖、字体或前端资源。请先在可信开发机生成 lockfile、
vendor 依赖和前端产物，再把运行所需文件一起放进 ZIP。

## 容器运行协议

镜像默认命令必须以前台进程启动 HTTP/1.1 服务，并监听环境变量 `VIBEHUB_SOCKET`，当前固定为
`/run/vibehub/app.sock`。启动前删除自己遗留的同名 socket，再以运行 UID 65532 bind；
`GET /healthz` 必须快速返回 `200`。

不要监听 `0.0.0.0`、`127.0.0.1` 或任意 TCP 端口。容器使用 `--network none`，端口不会被
转发，也不能访问公网、局域网、CDN 或包仓库。

### 基础路径与玩家会话

每次转发请求都包含两个由平台覆盖写入的可信请求头：

- `X-VibeHub-Base-Path`：当前外部 URL 前缀。链接、表单和静态资源应使用相对 URL，或显式拼接该前缀。
- `X-VibeHub-Session-Id`：当前玩家的匿名会话 ID。多人会共享同一个容器，内存状态必须按它隔离。

玩家不能伪造这两个值。平台不会把 NumericalOJ 的 Cookie、登录身份或密钥交给作品。
容器根文件系统可写，但容器回收后，内存、根层、`/tmp` 和 `/run/vibehub` 中的数据都会消失。
需要跨重建保留的文件必须写到 `/data` 或 `$HOME`（固定为 `/data/home`）。同一数据库 project id
的 `public`、`latest`、`review` 各有独立数据盘，作品不能声明 `VOLUME` 或选择宿主路径。

### 请求边界

支持普通 HTTP/1.1 的 `GET`、`HEAD`、`POST`、`PUT`、`PATCH`、`DELETE` 和 `OPTIONS`，
不支持 WebSocket、CONNECT 或外联。请求体和响应体默认各最多 16 MiB，单次请求默认最多 15 秒。
作品运行在不含 `allow-same-origin` 的 sandbox iframe 中，不能读取站点页面、浏览器 Cookie 或控制
顶层窗口。用户主动点击的 HTTPS 外部链接可以在不受 sandbox 限制的新标签页中打开；这只影响
浏览器导航，作品脚本的跨站请求仍由 `connect-src 'self'` 禁止，容器本身也仍使用
`--network none`。

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

### 创建并提交审核

`create` 先创建不可变的 v1 草稿并返回作品 `slug`，再用返回的 `slug` 提交审核：

```bash
python3 scripts/numoj_user.py vibehub create ./my-vibe.zip \
  --title "我的作品" \
  --summary "一句话简介" \
  --tags "游戏,创意"

python3 scripts/numoj_user.py vibehub submit-review <slug>
```

可用 `--slug` 指定稳定地址；只允许小写字母、数字和连字符，长度为 3–63。未指定时平台自动生成。
`--description @README.md` 可从文件读取详细说明，`--cover-image` 可覆盖清单中的包内封面路径。

### 更新并重新提交审核

上传新 ZIP 会生成递增的不可变版本，不会覆盖旧版本：

```bash
python3 scripts/numoj_user.py vibehub update <slug> ./my-vibe-v2.zip
python3 scripts/numoj_user.py vibehub submit-review <slug>
```

只修改标题、简介、说明、标签或封面路径时使用 `edit`。这同样会生成新版本，修改后仍需提交审核：

```bash
python3 scripts/numoj_user.py vibehub edit <slug> \
  --title "新的名称" \
  --description @README.md
python3 scripts/numoj_user.py vibehub submit-review <slug>
```

`latest` 始终指向作者最新版本，`public` 始终指向审核通过的稳定版本。更新处于审核中时，其他用户
仍会看到旧的公开版本。

### 申请精品

作品已经公开后，作者可以申请精品资源规格：

```bash
python3 scripts/numoj_user.py vibehub request-featured <slug>
```

## 版本、配额与运行资源

- 普通用户同时最多拥有 2 个未获精品资格的作品。
- 每个用户的持久作品快照逻辑用量上限为 20 GiB；每个作品的版本数量也受站点配额限制。
- 普通作品运行上限为 4 GiB 内存、2 CPU、256 PID、20 GiB 镜像和 4 GiB 可写根层。
- 精品作品运行上限为 8 GiB 内存、4 CPU、512 PID、40 GiB 镜像和 8 GiB 可写根层。
- `/tmp` 和 `/run/vibehub` 是有界 tmpfs；`/data` 持久保存，但当前没有可移植的硬配额。
- 首位玩家打开作品时容器按需启动；最后一个玩家离开后进入 5 分钟空闲宽限，期间再次进入会复用容器并取消原回收计划；宽限到期仍无人使用才回收容器，只有 `/data` 长期保留。

## 提交前检查

1. ZIP 根目录直接包含 `Dockerfile` 和 `vibehub.json`，没有额外外层目录。
2. 程序包不含密钥、隐私数据、符号链接、FIFO、socket 或超大文件。
3. `cover_image` 指向包内真实 PNG、JPEG 或 WebP，主体位于 16:9 中央安全区。
4. 所有依赖和前端资源已随包提供，不依赖网络下载。
5. 容器以非 root 身份在 `VIBEHUB_SOCKET` 上提供 HTTP/1.1，`GET /healthz` 返回 `200`。
6. 所有 URL 尊重 `X-VibeHub-Base-Path`，多人状态按 `X-VibeHub-Session-Id` 隔离。
7. 需要持久化的数据只写入 `/data` 或 `$HOME`，临时数据写入 `/tmp`。
