# -*- coding: utf-8 -*-

"""共享富 Markdown 渲染器的功能与安全契约。"""

import pytest
from threading import Event, Thread

from oj_modules.shared import markdown as markdown_module
from oj_modules.shared.markdown import render_rich_markdown


def test_rich_markdown_is_sanitized_and_external_images_are_allowed():
    rendered = render_rich_markdown(
        "公式 $x^2$\n\n![追踪像素](https://tracker.invalid/pixel.png)"
        "\n\n<img src=https://tracker.invalid/raw.png onerror=alert(1)>"
        "\n\n<script>alert(1)</script>"
    )

    assert "$x^2$" in rendered
    assert rendered.lower().count("<img") == 2
    assert "https://tracker.invalid/pixel.png" in rendered
    assert "https://tracker.invalid/raw.png" in rendered
    assert "onerror" not in rendered.lower()
    assert "<script" not in rendered.lower()


def test_rich_markdown_resanitizes_formula_placeholders_after_restoring_them():
    rendered = render_rich_markdown('[链接](<$x" onmouseover="alert(1)$>)')

    assert "onmouseover" not in rendered.lower()
    assert "<script" not in rendered.lower()


def test_rich_markdown_preserves_inline_and_block_latex_delimiters():
    rendered = render_rich_markdown(
        r"行内 \(x_i^2 < y\)；块级：\[\frac{a_b}{c_d}\]"
    )

    assert r"\(x_i^2 &lt; y\)" in rendered
    assert r"\[\frac{a_b}{c_d}\]" in rendered


@pytest.mark.parametrize(
    ("language", "source"),
    (
        ("c", "int main(void) { return 0; }"),
        ("cpp", "std::vector<int> values;"),
        ("python", "def solve(x):\n    return x + 1"),
        ("matlab", "function y = f(x)\ny = x.^2;\nend"),
        ("bash", 'echo "$HOME"'),
        ("json", '{"ok": true}'),
        ("js", "const answer = 42;"),
        ("html", '<section class="result">ok</section>'),
        ("css", ".result { color: #ea580c; }"),
        ("go", 'func main() { fmt.Println("hi") }'),
        ("tsx", "const App = () => <main>Hello</main>;"),
        ("rust", 'fn main() { println!("hi"); }'),
        ("php", "<?php $foo = $bar; ?>"),
        ("sql", "SELECT id FROM users WHERE active = TRUE;"),
    ),
)
def test_rich_markdown_highlights_common_fenced_languages(language, source):
    rendered = render_rich_markdown(f"```{language}\n{source}\n```")

    assert f'class="codehilite language-{language}"' in rendered
    assert '<span class="' in rendered


def test_rich_markdown_keeps_dollar_syntax_inside_code_fences():
    rendered = render_rich_markdown(
        "正文 $x^2$。\n\n"
        '```bash\necho "$HOME $name"\n```\n\n'
        "```php\n<?php $foo = $bar; ?>\n```"
    )

    assert "$x^2$" in rendered
    assert "$HOME" in rendered
    assert "$name" in rendered
    assert "$foo" in rendered
    assert "$bar" in rendered
    assert "NUMOJMARKDOWNMATH" not in rendered


def test_rich_markdown_marks_mermaid_as_safe_source_without_server_svg():
    rendered = render_rich_markdown(
        "```mermaid\n"
        "flowchart LR\n"
        '  A[\"<script>alert(1)</script>\"] --> B\n'
        "```"
    )

    assert 'class="codehilite language-mermaid"' in rendered
    assert "flowchart LR" in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script" not in rendered.lower()
    assert "<svg" not in rendered.lower()


def test_rich_markdown_cache_reuses_identical_render(monkeypatch):
    markdown_module._clear_rich_markdown_cache()
    original = markdown_module._render_rich_markdown_uncached
    calls = []

    def counted(raw):
        calls.append(raw)
        return original(raw)

    monkeypatch.setattr(markdown_module, "_render_rich_markdown_uncached", counted)
    source = "缓存题面：$x^2$\n\n```python\nprint(1)\n```"

    first = render_rich_markdown(source)
    second = render_rich_markdown(source)

    assert second == first
    assert calls == [source]
    markdown_module._clear_rich_markdown_cache()


def test_rich_markdown_cache_coalesces_concurrent_misses(monkeypatch):
    markdown_module._clear_rich_markdown_cache()
    started = Event()
    release = Event()
    calls = []

    def render_once(raw):
        calls.append(raw)
        started.set()
        assert release.wait(timeout=2)
        return "<p>共享结果</p>"

    monkeypatch.setattr(markdown_module, "_render_rich_markdown_uncached", render_once)
    results = []
    first = Thread(target=lambda: results.append(render_rich_markdown("并发缓存题面")))
    second = Thread(target=lambda: results.append(render_rich_markdown("并发缓存题面")))

    first.start()
    assert started.wait(timeout=2)
    second.start()
    release.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert results == ["<p>共享结果</p>", "<p>共享结果</p>"]
    assert calls == ["并发缓存题面"]
    markdown_module._clear_rich_markdown_cache()
