# VibeHub 示例包

这里保存三套可直接阅读、构建和打包的完整作品；每个目录都包含 `Dockerfile`、
`vibehub.json`、前后端，并只通过固定 Unix Socket 提供 HTTP/1.1。

- `circle-cat/`：完全独立、仅使用 Python 标准库的围住小猫游戏。
- `arc-agi-3/`：ARC-AGI-3 本地数据目录与 start/action 服务。
- `guess-who/`：通过操作步数猜测黑盒数据结构的推理游戏。

部署会把示例种入 `admin` 的普通 VibeHub 作品；仓库内容变化时通过普通作品链路创建新版本、
审核并发布。
