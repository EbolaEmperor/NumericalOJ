# Lean 4 多文件证明题

当题目详情中的 `problem.lang` 为 `lean` 或 `lean4` 时，使用本参考下载题目文件、在本地验证完整证明并提交。

## 工作目录与 CLI

下载命令只投影线上题面、题目文件和提交元数据，不会创建 Lake 工程。
不要进入 skill 目录运行命令；下载、编译和提交都在 `/workspace` 中完成。

先根据 `SKILL.md` 的绝对路径解析 CLI：

```bash
NUMOJ_USER_CLI=/absolute/path/to/numoj-user/scripts/numoj_user.py
```

后续始终通过 `python3 "$NUMOJ_USER_CLI" ...` 调用它，不要依赖 `scripts/numoj_user.py` 相对于当前目录的位置。

## 获取题目和文件

先定位题目编号，再把题目描述和全部 Lean 源文件下载到当前工作区：

```bash
python3 "$NUMOJ_USER_CLI" problem detail <problem_id>
python3 "$NUMOJ_USER_CLI" problem download <problem_id> -o /workspace
```

`/workspace/numoj-problem.json` 是无秘密的下载快照，记录题号、题目版本、文件模式、构建顺序和验证要求：

- `readonly` 文件是题目提供的定义和工具，可以阅读和 import，不得修改。
- `writable` 文件是答案的一部分，可以在其中添加定义、辅助引理和完整证明。
- `default_file` 是网页默认打开的可写文件，不代表只能提交这一个文件。

提交解答时，NumOJ 只接收可写文件。请保留题目要求的证明入口和必要 import。

## 本地构建和验证

被其他模块 import 的文件需要先生成路径匹配的 `.olean`。例如：

```bash
cd /workspace
lean -o Problem/Statement.olean Problem/Statement.lean
lean -o Submission.olean Submission.lean
```

根据快照中 `build_order` 所指定的顺序用 `lean -o <模块路径>.olean <源文件>` 编译各项。每次提交前修复全部 Lean 诊断。不要使用 `sorry`、`admit`、自行声明的 `axiom` 或其他绕过 Lean 内核及题目公理策略的机制。

## 提交和查看结果

从同一个工作区提交：

```bash
python3 "$NUMOJ_USER_CLI" problem submit <problem_id> --workspace /workspace
```

CLI 读取 `numoj-problem.json` 中的题目版本与可写文件表，只上传所有可写文件；只读文件不会上传。

然后查看判题状态和诊断：

```bash
python3 "$NUMOJ_USER_CLI" submission status <submission_id>
python3 "$NUMOJ_USER_CLI" submission stream <submission_id> --max-lines 20
```

如果服务器提示题目版本过期，先保留当前证明，再下载最新文件并对照迁移；不要直接用 `--force` 覆盖尚未备份的解答。

## 版本说明

线上评测环境使用 Lean 4 `v4.32.0` 和 Mathlib `v4.32.0`。
