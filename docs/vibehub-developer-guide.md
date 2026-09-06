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

### 更新并自动重新送审

上传新 ZIP 会构建递增的不可变版本、更新 `latest` 并自动重新送审，不会覆盖旧版本：

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
- 首位玩家打开作品时只按需启动保存阶段已经构建好的容器，不会触发镜像构建；最后一个玩家离开后进入 5 分钟空闲宽限，期间再次进入会复用容器并取消原回收计划；宽限到期仍无人使用才回收容器，只有 `/data` 长期保留。

## GPU

- 创建或编辑作品时开启 GPU 并申请显存，管理员创建作品也一样。每次保存的新版本重新送审；普通作者审核前不能运行 GPU 版本，管理员可以试玩，包括自己的作品。旧公开版本不受待审核修改影响。
- 审核可批准或下调显存，也可只发布 CPU 版本；意见在作者的编辑弹窗中查看。CLI 使用 `--gpu-memory-mib`（256–24576 MiB），`0` 关闭 GPU；省略时创建默认关闭，更新沿用申请值。
- 当前使用 RTX 3090 Ti（24 GiB），仅开放 CUDA 计算。容器自行安装兼容驱动的 CUDA 用户态依赖；构建阶段不使用 GPU。运行时 `VIBEHUB_GPU_MEMORY_MIB` 表示当前显存额度。
- 显存为超限回收，非硬隔离。同一作品的多进程、多容器合计计量；新旧额度并存时总量取较高的有效额度，各容器仍受自身额度约束。目标采样间隔为 1 秒，超限或监测失败会停止该作品的 GPU 容器，60 秒后可重试。额度不保证设备空闲显存。

## 提交前检查

1. ZIP 根目录直接包含 `Dockerfile` 和 `vibehub.json`，没有额外外层目录。
2. 程序包不含密钥、隐私数据、符号链接、FIFO 或 socket；ZIP 和解压总量符合大小上限。
3. `cover_image` 指向包内真实 PNG、JPEG 或 WebP，主体位于 16:9 中央安全区。
4. 需要联网安装的依赖使用 lockfile 或精确版本。
5. 容器以非 root 身份在 `VIBEHUB_SOCKET` 上提供 HTTP/1.1，`GET /healthz` 返回 `200`。
6. 所有 URL 尊重 `X-VibeHub-Base-Path`，多人状态按 `X-VibeHub-Session-Id` 隔离。
7. 需要持久化的数据只写入 `/data` 或 `$HOME`，临时数据写入 `/tmp`。
