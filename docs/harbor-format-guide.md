# Harbor 格式说明

反向评测提交的是一个可运行的 Linux 任务。可先从题目附件下载 `harbor-template.zip`，再替换为自己的题目；Git 仓库与 ZIP 压缩包使用相同结构。

## 目录结构

将以下文件放在仓库或 ZIP 的根目录：

```text
task.toml
instruction.md
environment/
  Dockerfile
solution/
  solve.sh
tests/
  test.sh
```

| 文件 | 用途 |
| --- | --- |
| `task.toml` | 任务配置及交付物归档路径。 |
| `instruction.md` | AI 看到的题面：任务目标、输入输出、文件或函数接口。 |
| `environment/Dockerfile` | 安装依赖、准备初始文件。 |
| `solution/solve.sh` | 出题者的参考解，必须通过验证并获得满分。 |
| `tests/test.sh` | 验证 AI 的作答并写出奖励分数。 |

## 题面与初始环境

`instruction.md` 就是评测时原样发送给 AI 的提示词。你可以理解为：系统按照你的要求配置好 Docker 环境，准备好初始文件，然后就把 `instruction.md` 作为提示词直接发送给 Agent，然后 Agent 开始工作。

默认 Dockerfile 使用平台提供的通用任务环境，强烈建议**非必要保持不变**：

```dockerfile
FROM numericaloj-harbor-base:1
WORKDIR /app
```

如果一定要追加依赖或初始文件，请尽可能在后面追加，不要破坏构建缓存。

## 评分与交付物

`tests/test.sh` 将奖励写入 `/logs/verifier/reward.txt`，取值为 `0` 到 `1` 之间的实数。

也可在 `/logs/verifier/reward.json` 中提供多个指标，总分定义为 `reward` 或 `score`。参考解的总分必须为 `1`。

若希望下载 AI 的作答文件，你必须在 `task.toml` 顶层声明交付物，例如：

```toml
schema_version = "1.4"
artifacts = ["/app"]
```

`artifacts` 可省略或留空，只影响交付物下载，不影响评分。

## 提交与评测

在题目页面选择 Git 仓库或 ZIP 提交，并选择 AI 节点。平台依次构建环境、验证参考解、执行题目质量审核（若启用）、运行 AI 并评分。

完整格式见 [Harbor 官方文档](https://docs.harborframework.com/tasks/overview)。
