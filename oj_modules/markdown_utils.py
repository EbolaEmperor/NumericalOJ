#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""统一的 HTML 消毒，用于所有「Markdown 渲染后 + 模板 |safe 下发」的出口。

历史上论坛帖子、打榜赛评分证据、题面等都把 python-markdown 的输出直接 |safe 渲染，
而 python-markdown 默认原样透传裸 HTML，导致存储型 XSS（学生/参赛者可注入 <script>）。

这里不改各处的 Markdown 渲染特性，只在输出上做白名单消毒：
- 优先用 bleach（白名单标签/属性/协议，能正确保留代码块里的 <、表格、图片）；
- 未安装 bleach 时退化为基于正则的尽力清洗（移除 script/危险标签/事件属性/危险协议）。
bleach 已加入 requirements.txt；生产机器 `pip install bleach` 后即获得严格白名单消毒。
"""

import re

try:
    import bleach
except Exception:  # bleach 未安装时退化到正则清洗
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

# ---- 正则兜底（bleach 不可用时）----
_DANGEROUS_PROTO_RE = re.compile(r"(?i)(href|src)\s*=\s*(['\"])\s*(?:javascript:|vbscript:|data:)")
_SCRIPT_BLOCK_RE = re.compile(r"(?is)<\s*script\b.*?<\s*/\s*script\s*>")
_STYLE_BLOCK_RE = re.compile(r"(?is)<\s*style\b.*?<\s*/\s*style\s*>")
_DANGER_TAG_RE = re.compile(r"(?is)<\s*/?\s*(?:script|style|iframe|object|embed|link|meta|base|form|input|button)\b[^>]*>")
_EVENT_ATTR_RE = re.compile(r"(?is)\son\w+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)")


def strip_dangerous_protocols(html_str):
    """把 href/src 中的 javascript:/vbscript:/data: 协议替换为 #。"""
    return _DANGEROUS_PROTO_RE.sub(r"\1=\2#", html_str or "")


def _scrub_html(html_str):
    """正则尽力清洗：保留良性 HTML，移除 script/style/危险标签、事件处理属性、危险协议。
    正则清洗非绝对可靠，仅作 bleach 缺失时的兜底。"""
    s = str(html_str or "")
    s = _SCRIPT_BLOCK_RE.sub("", s)
    s = _STYLE_BLOCK_RE.sub("", s)
    s = _DANGER_TAG_RE.sub("", s)
    s = _EVENT_ATTR_RE.sub("", s)
    s = strip_dangerous_protocols(s)
    return s


def sanitize_html(html_str):
    """对「将以 |safe 下发」的 HTML 做消毒。bleach 优先，否则正则兜底。"""
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
            pass
    return _scrub_html(s)


def render_markdown(text, extensions=None):
    """渲染 Markdown 并消毒输出。extensions 不传时用一组常见扩展。"""
    import markdown as _markdown
    raw = str(text or "")
    if not raw.strip():
        return ""
    exts = extensions if extensions is not None else ['extra', 'fenced_code', 'tables', 'sane_lists']
    try:
        rendered = _markdown.markdown(raw, extensions=exts)
    except Exception:
        import html as _html
        return _html.escape(raw, quote=False).replace("\n", "<br>")
    return sanitize_html(rendered)
