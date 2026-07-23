# ARC-AGI-3 公开游戏

仓库只保存 ARC-AGI-3 的本地运行适配层，不保存官方游戏源码、元数据或预览图。

生产部署通过 `deploy/prepare_arc_agi_3.py` 在停服前准备完整公开集：

- 已存在且哈希校验完整时直接复用，不重复下载；
- 首次安装时通过 ARC Prize 官方 API 下载，并在终端显示进度条；
- 下载后使用 `arcengine` 初始化每个环境、生成预览并校验格式；
- 最终内容按指纹保存到 `.deploy/arc-agi-3/sets/`，再由部署脚本原子切换
  `.deploy/arc-agi-3/current`。

Web 请求和实际游玩只读取本机缓存，不访问官方 API。下载得到的每个环境源码均保留
上游 MIT 许可头。
