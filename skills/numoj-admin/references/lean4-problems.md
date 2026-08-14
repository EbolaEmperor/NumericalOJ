# Lean 4 多文件证明题

处理 Lean 4 题目的创建、题目包更新、下载、工作区初始化或管理员试交时，使用本参考。

- [题目包格式](#题目包格式)
- [创建和发布](#创建和发布)
- [检查、下载和初始化工作区](#检查下载和初始化工作区)
- [本地验证和管理员试交](#本地验证和管理员试交)

## 题目包格式

上传一个 ZIP，根目录必须直接包含 `numoj-lean.json` 以及 manifest 声明的全部 `.lean` 文件；不要在 ZIP 外再套一层目录，也不要加入未声明文件。

最小 manifest 示例：

```json
{
  "schema_version": 1,
  "default_file": "Submission.lean",
  "files": [
    {"path": "Problem/Statement.lean", "mode": "readonly"},
    {"path": "Submission.lean", "mode": "writable"}
  ],
  "build_order": [
    "Problem/Statement.lean",
    "Submission.lean"
  ],
  "verification": {
    "target_module": "Problem.Statement",
    "target_decl": "Problem.Statement.Target",
    "entry_module": "Submission",
    "entry_decl": "Submission.solution",
    "permitted_axioms": ["propext", "Quot.sound", "Classical.choice"]
  }
}
```

配置约束：

- `schema_version` 固定为 `1`。
- `default_file` 必须是一个 `writable` 文件。
- `files` 中每个路径必须是可映射为 Lean 模块名的相对 `.lean` 路径；`mode` 只能是 `readonly` 或 `writable`。
- `build_order` 必须恰好列出全部文件，并将所有只读文件排在所有可写文件之前。被 import 的模块应排在引用它的模块之前。
- `target_decl` 是只读模块里的命题定义，`entry_decl` 是学生必须完成的定理；二者均使用完全限定名。目标模块必须只读，入口模块必须可写。
- `target_decl` 必须是 safe、无 universe 参数的 `def : Prop`；`entry_decl` 必须是无 universe 参数的 `theorem`，其类型必须与 target 常量精确可定义等同。
- `permitted_axioms` 是该证明允许依赖的公理完全限定名。一般保留示例中的 Mathlib 常用三项；需要更严格时显式缩小列表。
- 学生可以编辑全部 `writable` 文件并自定义辅助引理，但提交 API 不接收、也不会信任任何只读文件内容。
- Lean 学生模块的单次构建最多运行 300 秒；创建题目时请把 `--time-limit-ms` 设为不超过 `300000`。

一个典型入口文件可以是：

```lean
import Problem.Statement

namespace Submission

theorem solution : Problem.Statement.Target := by
  -- 学生在这里完成证明，也可以在本文件或其他可写文件中添加辅助引理。
  sorry

end Submission
```

模板中的 `sorry` 只表示待完成位置；参考答案和正式提交不得使用 `sorry`、`admit`、自行声明的 `axiom` 或其他绕过内核检查的机制。

从题目包根目录只打包 manifest 声明的文件，避免把本地生成的 `.olean` 或编辑器文件带入 ZIP。例如：

```bash
python3 -m zipfile -c ../problem-package.zip \
  numoj-lean.json Problem/Statement.lean Submission.lean
```

## 创建和发布

先查看实际参数：

```bash
python3 scripts/numoj_admin.py problem create --help
python3 scripts/numoj_admin.py problem lean-upload --help
```

创建题目并立即发布首个题目包：

```bash
python3 scripts/numoj_admin.py problem create \
  --title "Lean 4 证明题" \
  --content @PROBLEM.md \
  --type 1 \
  --lang lean4 \
  --time-limit-ms 120000 \
  --submission-limit 10 \
  --lean-package ./problem-package.zip
```

也可以先创建 `--lang lean4` 题目，再单独发布题目包：

```bash
python3 scripts/numoj_admin.py problem lean-upload <problem_id> ./problem-package.zip
```

每个不同的有效题目包都会生成新的不可变版本；重复上传内容相同的包保持当前版本不变。更新后，旧本地工作区不能继续提交，必须重新初始化并迁移学生改动。

## 检查、下载和初始化工作区

查看当前版本和文件读写属性；只在确实需要读取全部源码时使用 `--full`：

```bash
python3 scripts/numoj_admin.py problem lean-workspace <problem_id>
python3 scripts/numoj_admin.py problem lean-workspace <problem_id> --full
```

下载服务器保存的规范题目包：

```bash
python3 scripts/numoj_admin.py problem lean-download <problem_id> -o ./problem-package.zip
```

初始化一个可供本地编译或管理员试交的完整目录：

```bash
python3 scripts/numoj_admin.py problem lean-init <problem_id> ./lean-workspace
```

`lean-init` 会写入全部只读和可写源码，并在根目录的 `numoj-lean.json` 中加入当前 `problem_id` 与 `revision`。这两个字段是 CLI 的本地提交元数据，重新上传题目包时会被规范化忽略。目标路径已有文件时，只有显式传入 `--force` 才会替换。

## 本地验证和管理员试交

按 `build_order` 编译模块，并为被 import 的模块生成对应 `.olean`。例如上面的两文件结构可在工作区根目录运行：

```bash
lean -o Problem/Statement.olean Problem/Statement.lean
lean -o Submission.olean Submission.lean
```

对 `build_order` 中的每个条目都使用同样的 `lean -o <模块路径>.olean <源文件>` 形式，使本地模块搜索与线上构建顺序一致。

完成所有可写文件后，以目录提交：

```bash
python3 scripts/numoj_admin.py problem submit <problem_id> --workspace ./lean-workspace
```

CLI 从根目录 `numoj-lean.json` 读取版本和文件权限，把 `{revision, files}` JSON 放入 `lean_workspace` 表单字段提交，其中只包含全部 `writable` 文件；只读定义不会被上传。随后照常查看判题状态和日志：

```bash
python3 scripts/numoj_admin.py submission status <submission_id>
python3 scripts/numoj_admin.py submission stream <submission_id> --max-lines 20
```
