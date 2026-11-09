"""每场反向评测提供的只读 Harbor 入门题包；无需附件记录或磁盘产物。"""

from io import BytesIO
import stat
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


HARBOR_TEMPLATE_ID = "harbor-template"
HARBOR_TEMPLATE_FILENAME = "harbor-template.zip"
DEFAULT_HARBOR_DOCKERFILE = "FROM numericaloj-harbor-base:1\nWORKDIR /app\n"

_FILES = {
    "task.toml": '''schema_version = "1.4"
artifacts = ["/app"]

[task]
name = "numericaloj/harbor-example"
version = "1.0.0"
description = "NumericalOJ 反向评测入门示例"

[agent]
timeout_sec = 600

[verifier]
timeout_sec = 60

[environment]
cpus = 2
memory_mb = 2048
''',
    "instruction.md": '''# 写入答案文件

请在 `/app/answer.txt` 中写入整数 `42`，文件只包含 `42` 和末尾换行。
''',
    "environment/Dockerfile": DEFAULT_HARBOR_DOCKERFILE,
    "solution/solve.sh": '''#!/bin/bash
set -euo pipefail
mkdir -p /app
printf '42\\n' > /app/answer.txt
''',
    "tests/test.sh": '''#!/bin/bash
set -euo pipefail
mkdir -p /logs/verifier
if [[ -f /app/answer.txt ]] && [[ "$(cat /app/answer.txt)" == 42 ]]; then
    printf '1\\n' > /logs/verifier/reward.txt
else
    printf '0\\n' > /logs/verifier/reward.txt
fi
''',
    "README.md": '''# NumericalOJ 反向评测 Harbor 模板

这是一个可直接运行的最小题目：让 AI 在 `/app/answer.txt` 写入 `42`。
请先保持示例完整跑通，再替换成自己的任务。

## 文件用途

- `instruction.md`：给 AI 的题面和必要的函数、文件及输入输出接口，不写隐藏测试数量、分组或运维指引。
- `task.toml`：任务配置、超时和交付物归档路径；按需声明 `artifacts`，也可省略或留空。
- `environment/Dockerfile`：准备 AI 的初始环境。平台部署会提供
  `numericaloj-harbor-base:1` 基础镜像，可在其上添加题目依赖与初始文件。
  题目需要的额外依赖，请在 Dockerfile 中显式安装。
- `solution/solve.sh`：出题者参考解。平台先执行参考解并验证满分。
- `tests/test.sh`：在同一作答环境中验证完成状态，将分数写入 `/logs/verifier/reward.txt`。
  本例使用 `1` 表示满分、`0` 表示未完成。

## 提交

将这些文件直接放在 ZIP 根目录，或放在配置好的 Git 仓库根目录。
选择比赛中可用的 AI 作答节点后提交。平台依次构建环境、检查参考解、
按比赛配置审核题目、运行 AI 并验证答案。

`artifacts` 仅用于归档 AI 的交付物，本例归档 `/app`。验证脚本仅在验证阶段由 Harbor
提供，并在该轮作答环境中执行；参考解在 Oracle 阶段提供，不要将它们复制进 AI 的初始环境。

任务须在相同环境中可复现，参考解必须获得满分。AI 的得分百分比越低，
出题者的反向评测得分越高。
''',
}


def build_harbor_template_archive():
    archive = BytesIO()
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as output:
        for name, content in _FILES.items():
            info = ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | (0o755 if name.endswith(".sh") else 0o644)) << 16
            output.writestr(info, content.encode("utf-8"))
    archive.seek(0)
    return archive


def harbor_template_attachment(competition_id):
    return {
        "id": HARBOR_TEMPLATE_ID,
        "competition_id": int(competition_id),
        "filename": HARBOR_TEMPLATE_FILENAME,
        "file_size": len(build_harbor_template_archive().getbuffer()),
        "uploaded_at": None,
        "media_kind": None,
        "builtin": True,
        "download_url": f"/api/ranking/competitions/{int(competition_id)}/attachments/{HARBOR_TEMPLATE_ID}/download",
    }
