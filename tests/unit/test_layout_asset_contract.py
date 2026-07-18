"""全局布局的静态资产边界契约。"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LAYOUT = (ROOT / "templates" / "layout.html").read_text(encoding="utf-8")
LAYOUT_CSS = (ROOT / "static" / "app" / "layout.css").read_text(encoding="utf-8")
LAYOUT_JS = (ROOT / "static" / "app" / "layout.js").read_text(encoding="utf-8")


def test_layout_loads_shared_static_assets_instead_of_inline_app_code():
    assert "filename='app/layout.css'" in LAYOUT
    assert "filename='app/layout.js'" in LAYOUT
    assert "<style" not in LAYOUT
    assert "style=" not in LAYOUT
    assert "onclick=" not in LAYOUT

    inline_scripts = re.findall(
        r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", LAYOUT, flags=re.DOTALL
    )
    assert len(inline_scripts) == 1
    assert "window.MathJax" in inline_scripts[0]


def test_layout_passes_server_values_to_javascript_through_data_attributes():
    attributes = (
        "data-password-code-url",
        "data-user-email",
        "data-classes-url",
        "data-join-class-url",
        "data-leave-class-url",
        "data-set-primary-class-url",
        "data-class-adjust-url",
    )
    for attribute in attributes:
        assert attribute in LAYOUT

    assert "{{" not in LAYOUT_JS
    assert "fetch('/" not in LAYOUT_JS
    assert "modalEl.dataset.classesUrl" in LAYOUT_JS
    assert "form.dataset.passwordCodeUrl" in LAYOUT_JS


def test_layout_styles_and_behaviors_live_in_their_responsible_assets():
    for selector in (
        ".layout-navbar",
        ".layout-offcanvas-nav.layout-nav-compact",
        ".class-row",
        ".class-join-select",
    ):
        assert selector in LAYOUT_CSS

    for initializer in (
        "initAdaptiveNavigation()",
        "initClassManager()",
        "initPasswordForm()",
    ):
        assert initializer in LAYOUT_JS
