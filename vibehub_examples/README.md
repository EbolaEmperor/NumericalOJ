# VibeHub 示例包

这里保存两套可直接阅读、构建和打包的完整作品；每个目录都包含 `Dockerfile`、
`vibehub.json`、前后端，并只通过固定 Unix Socket 提供 HTTP/1.1。

- `circle-cat/`：完全独立、仅使用 Python 标准库的围住小猫游戏。
- `arc-agi-3/`：ARC-AGI-3 离线目录与 start/action 服务。

首次部署会把示例种入 `admin` 的普通 VibeHub 作品；之后通过普通作品链路编辑、审核和运行，
再次部署不会覆盖管理员的修改。
