# Harbor 格式说明

你需要提交一个完整的题目包：题目描述、让 AI 开始工作的环境、你自己写的正确答案，以及判断答案是否正确的评测程序。

可以先从比赛附件下载 `harbor-template.zip`。它是一道可以直接运行的小题，你可以在它的格式基础上创建你自己的题目。

## 提交目录结构

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

- `instruction.md`：AI 作答时收到的提示词。
- `environment/`：AI 工作时的环境。`Dockerfile` 用来安装依赖、放入题目附件。
- `solution/`：你自己写的正确答案。
- `tests/`：你的评测程序。平台通过 `test.sh` 检查作答结果，并读取它写出的分数。
- `task.toml`：题目的配置文件，具体见下文。

`solution/` 和 `tests/` 可以有多个文件，`solve.sh`、`test.sh` 是它们各自的入口。

## 平台评测流程

首先，平台按照 `environment/Dockerfile` 准备一个临时的 Linux 环境，也就是下文所说的“容器”。下面的脚本都在这个容器里运行。

### 第一步：检查你的正确答案

平台从初始环境启动一个容器，把 `solution/` 提供到容器的 `/solution/`，先执行参考解入口；然后把 `tests/` 提供到 `/tests/`，执行评测入口：
```bash
bash /solution/solve.sh
bash /tests/test.sh
```
`solve.sh` 负责把答案放置到约定的作答目录。例如，你的题目约定的作答文件是 `/app/main.cpp`，你可以在 `solve.sh` 中写一句 `cp /solution/main.cpp /app/main.cpp`，从而把正确答案复制到约定作答目录。

`test.sh` 随后检查约定目录里的作答文件，并把分数写入 `/logs/verifier/reward.txt`。这样，同一个评测脚本既能检查参考解，也能检查 AI 的答案。参考解必须得到 `1`，也就是满分，题目才会继续往下评测。

注意：作答目录是通过 `task.toml` 来约定的，通常建议约定为 `/app`，具体详见下文。

### 第二步：让 AI 作答，再用同一套程序评测

参考解满分通过、且题目通过比赛要求的质量审核后，平台会从**相同的初始环境重新启动一个容器**，把 `instruction.md` 作为提示词发送给所选 AI Agent。

AI 在这个环境里修改文件、编译程序、运行命令，完成题目要求。AI 结束后，平台才把 `tests/` 提供到 `/tests/`，并执行：
```bash
bash /tests/test.sh
```
这一轮**不会运行 `solve.sh`**，也不会把参考解上一轮生成的文件带进来。AI 正常作答时看不到 `solution/` 和 `tests/`，除非你自己把其中的内容复制进了初始环境。

**这两个入口都不接收答案目录参数。** `test.sh` 直接检查题面约定的位置；无论前面运行的是参考解还是 AI，交付物都应该放在同一个位置。

## task.toml 格式说明

`task.toml` 是题目的配置文件。下面是一个示例写法
```toml
schema_version = "1.4"
artifacts = ["/app"]

[task]
name = "example/my-task"
version = "1.0.0"
description = "题目的简短说明"

[agent]
timeout_sec = 600

[verifier]
timeout_sec = 60

[environment]
workdir = "/app"
cpus = 2
memory_mb = 2048
```
| 配置 | 含义 |
| --- | --- |
| `schema_version` | 格式版本，保持 `"1.4"` 即可。 |
| `[task]` | 题目的名称、版本和简短说明。 |
| `[agent].timeout_sec` | Agent 的作答时限，单位为秒。 |
| `[verifier].timeout_sec` | `test.sh` 的执行时限，单位为秒。 |
| `[environment].workdir` | Agent 的工作目录，本例为 `/app`。 |
| `[environment].cpus` | CPU 数量，本平台最多提供 2 CPU。 |
| `[environment].memory_mb` | 内存大小，单位为 MB；本例申请 2048 MB，平台上限为 4096 MB。 |
| `artifacts` | 约定的作答目录，不建议更改。 |

  特别注意：实际 Agent 作答时限和 `test.sh` 执行时限还会受到比赛配置的影响，若比赛中没有说明，可随时询问管理员（助教）。
