# 书面作业逐轮评分记录

书面作业的每次评测 attempt 下，每位评委每轮评分、讨论及失败重试都单独保留，
不覆盖之前的记录。普通提交详情、实时状态和学生页面仍只展示各评委最后一轮的总评，
完整记录只能由管理员通过专用 API 或 numoj-admin 查看。

## 保存范围

私有业务工件位于项目根目录 `written_grading_traces/<submission_id>/<record_id>/`，
目录权限为 `0700`，文件为 `0600`，不入 Git，不写入常规日志，不经静态文件路由发布。
`record_id` 是随机 UUID，不依赖内容散列。一个目录对应一个评委、一个评分轮次和一次尝试：

- `round.json`：attempt、评委、轮次、评分尝试、端点 ID/修订号、模型、起止时间、状态，
  以及本轮成功解析的分数、总评、完整评分 JSON 和逐一回复 `peer_replies`。
- `call-N.json`：本轮第 N 次 HTTP 调用的用途（`grading` 或 `json_repair`）、HTTP 状态、
  Content-Type、开始/结束时间及 body 是否读完。每次 JSON 修复和修复重试也各占一项。
- `call-N.request.json`：实际发送的完整 JSON body，包括原图 data URL、原题、评分规则、
  其他评委意见、历次续聊及全部模型参数。先在发送前落盘，收到响应后以
  `PreparedRequest.body` 的实际字节覆盖确认。没有收到响应的连接失败保留发送前编码的 body。
- `call-N.response.body`：requests 解压后的完整 HTTP body 字节，不是只提取 assistant 文本；
  流式调用保留 SSE 原文，包含事件、思考、usage 和结束标记，非流式保留完整 JSON。
  不保存认证请求头、Cookie、API key 或带凭据的请求 URL。

响应按读取块立即追加到文件；断流、解析失败、JSON 修复失败、软超时等均保留已收到部分，
并记录失败状态和错误类型。`body_complete` 只表示 HTTP body 读到 EOF，
不等同于供应商协议存在正常的结束标记，应结合原始 SSE 和轮次状态排查。
强制杀死 worker 或机器掉电可能留下 `running`/`pending`/`receiving` 且没有结束时间的记录；
这些状态不能当作成功，需结合 attempt 与任务生命周期检查。写入工件失败会使评分失败，
不会静默跳过记录继续评分。文件和 JSON 不设置静默截断，图片和长响应都完整保存。

此前已经完成的提交没有原始请求、响应和讨论历史，无法补回；接口对这类提交返回空记录列表。
新增记录不改变既有投票表结构、全体一致结算规则和人工复核流程。

## 管理员查看

```bash
python3 skills/numoj-admin/scripts/numoj_admin.py submission grading-trace 46323
```

结果按 attempt、轮次、评委和尝试排序，包含本轮解析结果与每次调用的元数据，
以及原始请求、响应的下载 URL。大 body 通过单独文件按需下载，不随普通提交详情返回。

```bash
python3 skills/numoj-admin/scripts/numoj_admin.py submission grading-trace 46323 \
  --record <record_id> --file call-1.request.json -o request.json
python3 skills/numoj-admin/scripts/numoj_admin.py submission grading-trace 46323 \
  --record <record_id> --file call-1.response.body -o response.body
```

也可下载 `round.json` 或 `call-N.json`。列表 JSON 用 shell 重定向保存。
API 为 `GET /api/admin/submissions/<submission_id>/grading-trace` 和
`GET /api/admin/submissions/<submission_id>/grading-trace/<record_id>/<filename>`。
两者均重新验证管理员身份；下载拒绝路径越界、符号链接和跨提交读取，响应禁止缓存。

## 发布、备份与回滚

本次只新增私有工件目录和读取接口，不新增表、列或回填，不需要执行数据库迁移。
发布仍须按 `docs/maintenance.md` 的唯一发布流程执行。该目录由应用用户按需建立，
部署不得清理或覆盖；应用回退时保留目录，旧代码会忽略这些工件。

该目录含完整学生答案、教师评分规则与模型讨论，应作为业务数据备份，
与对应数据库 attempt 一起恢复。数据库备份不会自动包含该目录。
一致备份须在全部 Celery worker 停止后，同时保存数据库与本目录；
备份和恢复操作沿用维护手册的授权、权限和验证要求。
本功能不自动删除历史；图片会随请求完整重复保留，运维需监控磁盘容量，
未经明确留存策略和授权不得清理历史。
