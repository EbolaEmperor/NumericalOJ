#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""统一的 HTML 消毒，用于所有「Markdown 渲染后 + 模板 |safe 下发」的出口。

历史上论坛帖子、打榜赛评分证据、题面等都把 python-markdown 的输出直接 |safe 渲染，
而 python-markdown 默认原样透传裸 HTML，导致存储型 XSS（学生/参赛者可注入 <script>）。

这里不改各处的 Markdown 渲染特性，只在输出上做白名单消毒：
- 优先用 bleach（白名单标签/属性/协议，能正确保留代码块里的 <、表格、图片）；
- bleach 缺失或异常时 fail-closed，把整段输出转义为纯文本，绝不把正则清洗
  当成可供 ``|safe`` / ``innerHTML`` 使用的安全边界。
bleach 已加入 requirements/production.txt；生产安装后获得完整 Markdown 展示。
"""

import html
import re
import secrets
import threading
from collections import OrderedDict

from pygments.formatters import HtmlFormatter

try:
    import bleach
except Exception:  # bleach 未安装时进入纯文本 fail-closed 路径
    bleach = None


# 允许的标签：覆盖 Markdown 常见产物 + 代码高亮（pre/code/span.class）+ 表格 + 图片。
_ALLOWED_TAGS = [
    'p', 'br', 'hr', 'pre', 'code', 'span', 'div', 'blockquote',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd',
    'strong', 'em', 'b', 'i', 'u', 's', 'del', 'ins', 'mark', 'sub', 'sup', 'small',
    'a', 'img', 'figure', 'figcaption',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption', 'colgroup', 'col',
]
_ALLOWED_ATTRS = {
    '*': ['class', 'id', 'title'],
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    'td': ['align', 'colspan', 'rowspan'],
    'th': ['align', 'colspan', 'rowspan'],
    'col': ['span', 'width'],
    'ol': ['start'],
}
_ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

_RICH_MARKDOWN_EXTENSIONS = [
    "extra",
    "fenced_code",
    "codehilite",
    "tables",
    "sane_lists",
]
_LANGUAGE_CLASS_RE = re.compile(r"^language-[A-Za-z0-9_+#.-]+$")
_FENCE_OPEN_RE = re.compile(r"^[ ]{0,3}(?P<fence>`{3,}|~{3,})")
_MATH_RE = re.compile(
    r"(?s)"
    r"(\$\$.*?\$\$"
    r"|\\\[.*?\\\]"
    r"|\\\(.*?\\\)"
    r"|(?<!\$)\$(?!\$)(?:\\.|[^$\n])+?(?<!\\)\$(?!\$))"
)


class _LanguageClassHtmlFormatter(HtmlFormatter):
    """保留 fenced code 的安全语言类，供共享样式和 Mermaid 识别。"""

    def __init__(self, **options):
        language_class = str(options.get("lang_str") or "").strip()
        if _LANGUAGE_CLASS_RE.fullmatch(language_class):
            css_class = str(options.get("cssclass") or "codehilite").strip()
            options["cssclass"] = f"{css_class} {language_class.lower()}"
        super().__init__(**options)


_RICH_MARKDOWN_EXTENSION_CONFIGS = {
    "codehilite": {
        "css_class": "codehilite",
        "guess_lang": False,
        "linenums": False,
        "noclasses": False,
        "pygments_formatter": _LanguageClassHtmlFormatter,
        # 最终颜色由共享 GitHub Light CSS 统一提供；这里也选择浅色 formatter
        # 默认值，避免未来启用内联样式时意外回到深色画布。
        "pygments_style": "default",
        "use_pygments": True,
    },
}


# 富 Markdown 会执行解析、Pygments 高亮和两轮 HTML 清洗，长题面单次即可占用
# 数十毫秒 CPU。缓存以完整原文为键，因此内容更新后天然生成新条目，不需要写路径
# 额外失效；条目数和近似字节数双重限制避免论坛/Agent 的大量唯一文本挤爆进程。
_RICH_MARKDOWN_CACHE_MAX_ENTRIES = 256
_RICH_MARKDOWN_CACHE_MAX_BYTES = 32 * 1024 * 1024
_rich_markdown_cache: OrderedDict[str, tuple[str, int]] = OrderedDict()
_rich_markdown_inflight: dict[str, threading.Event] = {}
_rich_markdown_cache_bytes = 0
_rich_markdown_cache_lock = threading.Lock()


def _rich_markdown_weight(raw, rendered):
    return len(raw.encode("utf-8")) + len(rendered.encode("utf-8"))


def _clear_rich_markdown_cache():
    """清空已完成的富 Markdown 缓存；主要供测试与受控维护使用。"""
    global _rich_markdown_cache_bytes
    with _rich_markdown_cache_lock:
        _rich_markdown_cache.clear()
        _rich_markdown_cache_bytes = 0


def _publish_rich_markdown_cache(raw, rendered, pending):
    global _rich_markdown_cache_bytes
    weight = _rich_markdown_weight(raw, rendered)
    with _rich_markdown_cache_lock:
        if weight <= _RICH_MARKDOWN_CACHE_MAX_BYTES:
            previous = _rich_markdown_cache.pop(raw, None)
            if previous is not None:
                _rich_markdown_cache_bytes -= previous[1]
            _rich_markdown_cache[raw] = (rendered, weight)
            _rich_markdown_cache_bytes += weight
            while (
                len(_rich_markdown_cache) > _RICH_MARKDOWN_CACHE_MAX_ENTRIES
                or _rich_markdown_cache_bytes > _RICH_MARKDOWN_CACHE_MAX_BYTES
            ):
                _, (_, removed_weight) = _rich_markdown_cache.popitem(last=False)
                _rich_markdown_cache_bytes -= removed_weight
        _rich_markdown_inflight.pop(raw, None)
        pending.set()


def _cancel_rich_markdown_render(raw, pending):
    with _rich_markdown_cache_lock:
        _rich_markdown_inflight.pop(raw, None)
        pending.set()


def sanitize_html(html_str):
    """对「将以 |safe 下发」的 HTML 做消毒；清洗能力异常时严格转义。"""
    s = str(html_str or "")
    if not s:
        return ""
    if bleach is not None:
        try:
            return bleach.clean(
                s,
                tags=_ALLOWED_TAGS,
                attributes=_ALLOWED_ATTRS,
                protocols=_ALLOWED_PROTOCOLS,
                strip=True,
            )
        except Exception:
            # 安全依赖异常不能退化成一套不完备的 HTML 解析器。转义的是已经
            # 渲染出的整段 HTML，显示效果会变成纯文本，但不会形成可执行 DOM。
            return html.escape(s, quote=False)
    return html.escape(s, quote=False)


def render_markdown(text, extensions=None, extension_configs=None):
    """渲染 Markdown 并消毒输出；可透传扩展配置。"""
    import markdown as _markdown
    raw = str(text or "")
    if not raw.strip():
        return ""
    exts = extensions if extensions is not None else ['extra', 'fenced_code', 'tables', 'sane_lists']
    try:
        rendered = _markdown.markdown(
            raw,
            extensions=exts,
            extension_configs=extension_configs or {},
        )
    except Exception:
        import html as _html
        return _html.escape(raw, quote=False).replace("\n", "<br>")
    return sanitize_html(rendered)


def _replace_math_outside_fences(raw, replacer):
    """只保护正文公式，避免把 Bash/PHP 等代码里的 ``$`` 当成 LaTeX。"""
    output = []
    prose = []
    closing_fence = None

    def flush_prose():
        if prose:
            output.append(_MATH_RE.sub(replacer, "".join(prose)))
            prose.clear()

    for line in raw.splitlines(keepends=True):
        line_without_ending = line.rstrip("\r\n")
        if closing_fence is None:
            opening = _FENCE_OPEN_RE.match(line_without_ending)
            if opening is None:
                prose.append(line)
                continue
            flush_prose()
            fence = opening.group("fence")
            closing_fence = re.compile(
                rf"^[ ]{{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$"
            )
            output.append(line)
            continue

        output.append(line)
        if closing_fence.fullmatch(line_without_ending):
            closing_fence = None

    flush_prose()
    return "".join(output)


def _protect_rich_markdown_math(raw):
    """把代码围栏外的公式替换为不可碰撞占位符。"""
    token_prefix = f"NUMOJMARKDOWNMATH{secrets.token_hex(8)}"
    protected = {}

    def protect_math(match):
        token = f"{token_prefix}{len(protected)}TOKEN"
        protected[token] = html.escape(match.group(0), quote=False)
        return token

    return _replace_math_outside_fences(raw, protect_math), protected


def _restore_rich_markdown_math(rendered, protected):
    """恢复公式后再做最终清洗，保持所有 ``|safe`` 出口 fail-closed。"""
    restored = str(rendered or "")
    for token, formula in protected.items():
        restored = restored.replace(token, formula)

    # 占位符必须在最终一次 HTML 清洗之前恢复；否则公式若出现在链接属性中，
    # 恢复出的引号可能绕过第一次清洗并重新形成事件属性。
    return sanitize_html(restored)


def _render_rich_markdown_uncached(raw):
    if not raw.strip():
        return ""

    markdown_source, protected = _protect_rich_markdown_math(raw)
    rendered = render_markdown(
        markdown_source,
        extensions=_RICH_MARKDOWN_EXTENSIONS,
        extension_configs=_RICH_MARKDOWN_EXTENSION_CONFIGS,
    )
    return _restore_rich_markdown_math(rendered, protected)


def render_rich_markdown(text):
    """渲染支持代码高亮、Mermaid 源码标记与 LaTeX 的安全 Markdown。"""
    raw = str(text or "")
    if not raw.strip():
        return ""

    while True:
        with _rich_markdown_cache_lock:
            cached = _rich_markdown_cache.get(raw)
            if cached is not None:
                _rich_markdown_cache.move_to_end(raw)
                return cached[0]
            pending = _rich_markdown_inflight.get(raw)
            if pending is None:
                pending = threading.Event()
                _rich_markdown_inflight[raw] = pending
                break
        pending.wait()

    try:
        rendered = _render_rich_markdown_uncached(raw)
    except BaseException:
        _cancel_rich_markdown_render(raw, pending)
        raise
    _publish_rich_markdown_cache(raw, rendered, pending)
    return rendered


def render_rich_markdown_with_toc(text, *, toc_depth="2-3"):
    """用题面同款富 Markdown 管线生成正文及同次解析得到的目录。"""

    from markdown import Markdown
    from markdown.extensions.toc import slugify_unicode

    raw = str(text or "")
    if not raw.strip():
        return "", ""

    markdown_source, protected = _protect_rich_markdown_math(raw)
    extension_configs = {
        name: dict(config)
        for name, config in _RICH_MARKDOWN_EXTENSION_CONFIGS.items()
    }

    def slugify_with_restored_math(value, separator):
        restored = str(value or "")
        for token, formula in protected.items():
            restored = restored.replace(token, html.unescape(formula))
        return slugify_unicode(restored, separator)

    extension_configs["toc"] = {
        "toc_depth": str(toc_depth),
        "slugify": slugify_with_restored_math,
    }
    try:
        renderer = Markdown(
            extensions=[*_RICH_MARKDOWN_EXTENSIONS, "toc"],
            extension_configs=extension_configs,
        )
        rendered = renderer.convert(markdown_source)
    except Exception:
        # 正文仍沿用共享渲染器的安全降级；解析失败时不伪造可能错位的目录。
        return render_rich_markdown(raw), ""

    return (
        _restore_rich_markdown_math(rendered, protected),
        _restore_rich_markdown_math(renderer.toc, protected),
    )
