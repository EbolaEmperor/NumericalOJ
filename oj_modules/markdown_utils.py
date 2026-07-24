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
