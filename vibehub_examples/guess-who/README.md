# 猜猜我是谁 VibeHub 示例包

这是一个黑盒数据结构辨认游戏。作品使用 Python 标准库 HTTP 服务，通过
`/run/vibehub/app.sock` 提供页面和 JSON API，不监听 TCP 端口。

每个 VibeHub 玩家会话拥有独立的一局游戏。新一局随机选择隐藏结构；清空仅移除当前
结构中的元素，便于在同一结构上重新设计实验。页面只根据后端每次响应返回的完整元素
集合绘制棋子，不从前端推演结构状态。

前端使用以下相对接口：

- `GET api/state`
- `POST api/action`
- `POST api/reset`
- `POST api/guess`
- `POST api/new`

`static/cover.jpg` 是必填的 16:9 作品封面，由平台生成安全副本。
