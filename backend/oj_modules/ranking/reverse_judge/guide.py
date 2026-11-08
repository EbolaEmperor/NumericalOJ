"""Harbor 格式说明的单一 Markdown 内容源与安全网页投影。"""

from backend.oj_modules.project_paths import PROJECT_ROOT
from backend.oj_modules.shared.markdown import render_rich_markdown_with_toc


HARBOR_GUIDE_PATH = PROJECT_ROOT / "docs" / "harbor-format-guide.md"


def render_harbor_guide() -> tuple[str, str]:
    return render_rich_markdown_with_toc(
        HARBOR_GUIDE_PATH.read_text(encoding="utf-8"),
        toc_depth="2-3",
    )
