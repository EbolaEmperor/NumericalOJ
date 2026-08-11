# ARC-AGI-3 VibeHub 离线作品

这个目录是可构建、可健康检查、可实际游玩的完整 VibeHub 规范源，但不把会变化的
ARC Prize 官方环境源码、元数据或目录缩略图提交进 Git。

每次部署都会先匿名请求官方目录并精确核对 25 个 game ID；本地清单完全一致时才复用，
不一致则重新下载并逐文件校验许可、大小和 SHA256。同步脚本随后把完整缓存复制到本包的
`offline_data/`，让镜像在 `--network none` 下提供目录、预览、`start` 与 `action` 接口。
官方 Python 源码不会在部署宿主执行，只在 VibeHub 的只读、非 root、无网络容器里加载。

ARC Engine、NumPy 与 Pillow 固化在管理员预置的受信基础镜像中；作品构建本身仍完全
离线。服务在 `/run/vibehub/app.sock` 提供 HTTP/1.1 与 `GET /healthz`，所有前端请求
均为相对 URL。
