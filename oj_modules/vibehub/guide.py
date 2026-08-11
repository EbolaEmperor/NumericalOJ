"""VibeHub 开发者手册的单一内容源与安全网页投影。"""

from __future__ import annotations

from oj_modules.project_paths import PROJECT_ROOT
from oj_modules.shared.markdown import render_rich_markdown_with_toc


DEVELOPER_GUIDE_PATH = PROJECT_ROOT / "docs" / "vibehub-developer-guide.md"


def render_developer_guide() -> tuple[str, str]:
    """实时读取唯一 Markdown 源并用题面同款管线生成正文与目录。"""

    return render_rich_markdown_with_toc(
        DEVELOPER_GUIDE_PATH.read_text(encoding="utf-8"),
        toc_depth="2-3",
    )
