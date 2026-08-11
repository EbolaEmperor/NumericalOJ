# VibeHub 内置示例包

这里保存 VibeHub 开发者可以直接阅读、构建和打包的两套完整示例。每个子目录都把
`Dockerfile`、`vibehub.json`、前端和后端放在同一个作品包根目录，并只通过固定 Unix
Socket 提供 HTTP/1.1。

- `circle-cat/`：完全独立、仅使用 Python 标准库的围住小猫游戏。
- `arc-agi-3/`：完整的 ARC-AGI-3 离线目录与 start/action 游戏服务；部署时把每次在线
  核对后的 25 个官方环境固化到 ignored 安装包，远端源码只在隔离容器内执行。

这些目录不会在模块导入时执行任何构建或外部写操作。通用作品依然必须通过 VibeHub
上传、版本、审核和隔离运行流程。部署脚本按 Git 跟踪源的确定性 SHA256 同步到
`uploads/vibehub`，相同内容不动、不同内容原子切换；内置 descriptor 位于
`oj_modules/vibehub/builtins.py`。
