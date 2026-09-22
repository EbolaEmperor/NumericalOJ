# 书面题多模型 Vote 结构变更

## 变更范围

本次是向后兼容的 expand-only 变更：

- `problems` 新增可空 JSON 列 `written_vote_config`；
- 新增 `written_grading_attempts`，保存每轮评测的冻结配置、共识状态与人工覆盖；
- 新增 `written_grading_votes`，保存每位评委的模型快照、得分、评语和重试结果；
- `submissions.score` 继续保持 `NOT NULL`。等待人工复核时写 0，但 `Pending` 状态的该值不计入成绩。

旧代码不会读取这些新结构；旧书面题没有 `written_vote_config` 时继续把既有单一批改端点视为 1 票。

## Vote 结算流程

- 首轮全部评委成功且给分一致时直接结算；任一评委连续重试失败时转人工复核。
- 首轮全部成功但给分不一致时，每位评委进入一次第二轮复评。第二轮请求保持该评委的首轮题目、图片和原始回复为不变前缀，只追加其他评委的首轮给分与原始回复，不注入自己的结果。
- 第二轮全部成功且给分一致时结算；第二轮仍有失败时转人工复核；第二轮仍分歧时，每位评委进入一次第三轮复评：在前两轮完整对话的基础上，追加其他评委的第二轮给分与原始回复，再要求其核对并解决争议，仍按同样的 JSON 格式返回。
- 第三轮全部成功且给分一致时结算；第三轮仍有失败或分歧时转人工复核。
- `written_grading_votes` 展示和保存最终一轮结果；先前轮次的完整对话只在当前任务内用于续聊复评，不改变数据库结构。

## 发布前验证

1. 按 `docs/maintenance.md` 创建并验证数据库回滚点；不得只依赖逻辑导出文件存在。
2. 在一次性数据库运行 `python3 scripts/init_db_schema.py --dry-run`，确认计划只包含新增列、表和索引。
3. 在一次性数据库实际执行结构同步，并验证外键、唯一索引及级联删除。
4. 完成后端单测和前端 typecheck、test、build；生产主机禁止运行这些测试。

## 发布与验证

生产只允许由 `deploy.sh` 在停服、备份验证后执行结构同步。发布后只读检查：

```sql
SHOW COLUMNS FROM problems LIKE 'written_vote_config';
SHOW CREATE TABLE written_grading_attempts;
SHOW CREATE TABLE written_grading_votes;
```

功能验证使用新建的非生产测试提交，确认一致、分歧、模型失败及人工覆盖四条路径。不得直接修改生产提交制造状态。

## 回滚

应用回滚时优先部署上一个已知正常提交。新增列和表对旧代码无影响，应原地保留，避免丢失已经产生的 Vote 审计数据；无需执行 down migration。

若结构本身导致数据库异常，应保持服务停止，并从本次发布前已验证的数据库回滚点恢复。不要在未另行备份 `written_grading_attempts` 与 `written_grading_votes` 的情况下执行 `DROP TABLE` 或 `DROP COLUMN`。需要向前修复时，先在一次性数据库复现并验证 SQL，再按维护文档取得生产写入授权。
