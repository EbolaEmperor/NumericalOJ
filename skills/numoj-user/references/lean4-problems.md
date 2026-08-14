# Lean 4 多文件证明题

当题目详情中的 `problem.lang` 为 `lean` 或 `lean4` 时，使用本参考读取、初始化、验证和提交完整工作区。

## 读取并初始化

先查看题目和工作区文件表：

```bash
python3 scripts/numoj_user.py problem detail <problem_id>
python3 scripts/numoj_user.py problem lean-workspace <problem_id>
```

需要直接检查所有初始源码时使用：

```bash
python3 scripts/numoj_user.py problem lean-workspace <problem_id> --full
```

开始解题时，把服务器当前版本初始化为本地目录：

```bash
python3 scripts/numoj_user.py problem lean-init <problem_id> ./lean-workspace
```

目录根部的 `numoj-lean.json` 记录当前 `problem_id`、`revision`、构建顺序以及每个文件的 `mode`：

- `readonly` 是题目提供的受信定义，可以阅读和 import；服务器不会接受对它的修改。
- `writable` 是答案的一部分。可以在任何可写文件中添加自己的定义、辅助引理和证明。
- `default_file` 是默认打开的可写文件，不代表只能提交这一个文件。

提交的是完整可写文件，不是单独的 `by ...` 片段。保留 manifest 要求的入口定理和必要 import。

## 本地验证

按 `numoj-lean.json` 的 `build_order` 编译源码。被其他模块 import 的文件需要先生成路径匹配的 `.olean`。例如：

```bash
cd ./lean-workspace
lean -o Problem/Statement.olean Problem/Statement.lean
lean -o Submission.olean Submission.lean
```

根据实际文件表继续以 `lean -o <模块路径>.olean <源文件>` 的方式编译每个条目。每次提交前修复全部 Lean 诊断。不要使用 `sorry`、`admit`、自行声明的 `axiom` 或其他绕过 Lean 内核及题目公理策略的机制。

## 提交和查看结果

以整个初始化目录提交：

```bash
python3 scripts/numoj_user.py problem submit <problem_id> --workspace ./lean-workspace
```

CLI 会读取本地 `numoj-lean.json`，把 `revision` 和其中标记为 `writable` 的文件放入 `lean_workspace` 表单字段发送给 API。所有可写文件都必须存在；只读文件不会上传。

然后查看判题状态和诊断：

```bash
python3 scripts/numoj_user.py submission status <submission_id>
python3 scripts/numoj_user.py submission stream <submission_id> --max-lines 20
```

若服务器提示工作区版本过期，先保留自己的可写文件，再把当前题目初始化到一个新目录，将证明迁移到新版本后重新编译和提交。不要用 `--force` 直接覆盖尚未备份的解答。
