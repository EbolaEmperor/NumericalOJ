"""VibeHub 开发者手册的单一内容源与安全网页投影。"""

from __future__ import annotations

from markdown import Markdown
from markdown.extensions.toc import slugify_unicode

from oj_modules.project_paths import PROJECT_ROOT
from oj_modules.shared.markdown import sanitize_html


DEVELOPER_GUIDE_PATH = PROJECT_ROOT / "docs" / "vibehub-developer-guide.md"


def render_developer_guide() -> tuple[str, str]:
    """用同一次 Markdown 解析生成正文与 h2–h3 目录并分别消毒。"""

    renderer = Markdown(
        extensions=["extra", "sane_lists", "toc"],
        extension_configs={"toc": {"toc_depth": "2-3", "slugify": slugify_unicode}},
    )
    content_html = renderer.convert(DEVELOPER_GUIDE_PATH.read_text(encoding="utf-8"))
    return sanitize_html(content_html), sanitize_html(renderer.toc)
