# ARC-AGI-3 VibeHub 离线作品

这个目录是可构建、可健康检查、可游玩的 VibeHub 作品，不把会变化的 ARC Prize
环境源码或元数据提交进 Git。

首次种入作品前，部署流程会核对 25 个 game ID，并把逐文件校验后的缓存写入
`offline_data/`。缓存只含清单与官方环境源码，不含宿主伪造的预览。镜像在
`--network none` 下提供目录、预览、`start` 与 `action`；
上游 Python 源码只在非 root、无网络的隔离容器里加载。

目录、帮助弹窗、榜单与玩家操作台保留迁入 VibeHub 前的原版界面。目录缩略图由
容器内的官方环境执行 `RESET` 后生成；内存中只保留固定数量、由高熵随机 token 标识的
对局，不读取 OJ Cookie、认证、身份或数据库。

游戏帧以“宽度、高度、Base64 索引像素”传输，避免二维 JSON 的重复数字与分隔符；浏览器一次
解码到复用的 `ImageData` 并通过 `putImageData` 提交整帧，不再逐像素调用 Canvas 绘制 API。

ARC Engine、NumPy 与 Pillow 固化在管理员预置的受信基础镜像中；作品构建本身仍完全
离线。服务在 `/run/vibehub/app.sock` 提供 HTTP/1.1 与 `GET /healthz`，所有前端请求
均为相对 URL。
