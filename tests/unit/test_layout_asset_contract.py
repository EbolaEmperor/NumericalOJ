"""全局布局的静态资产边界契约。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_LAYOUT = (ROOT / "templates" / "layouts" / "base.html").read_text(
    encoding="utf-8"
)
SITE_LAYOUT = (ROOT / "templates" / "layouts" / "site.html").read_text(
    encoding="utf-8"
)
EMBEDDED_LAYOUT = (ROOT / "templates" / "layouts" / "embedded.html").read_text(
    encoding="utf-8"
)
MATHJAX_COMPONENT = (
    ROOT / "templates" / "components" / "layout" / "mathjax.html"
).read_text(encoding="utf-8")
LAYOUT_COMPONENTS = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted((ROOT / "templates" / "components" / "layout").glob("*.html"))
)
LAYOUT_CSS = (ROOT / "static" / "app" / "layout.css").read_text(encoding="utf-8")
LAYOUT_JS = (ROOT / "static" / "app" / "layout.js").read_text(encoding="utf-8")


def test_layout_loads_shared_static_assets_instead_of_inline_app_code():
    assert SITE_LAYOUT.count('{% extends "layouts/base.html" %}') == 1
    assert EMBEDDED_LAYOUT.count('{% extends "layouts/base.html" %}') == 1
    for asset in (
        "bootstrap/bootstrap.min.css",
        "vendor/fontawesome/css/all.min.css",
        "math-curve-loaders/loader.css",
        "math-curve-loaders/loader.js",
        "bootstrap/bootstrap.bundle.min.js",
    ):
        assert BASE_LAYOUT.count(asset) == 1

    assert "filename='app/layout.css'" in SITE_LAYOUT
    assert "filename='app/layout.js'" in SITE_LAYOUT
    for layout in (BASE_LAYOUT, SITE_LAYOUT, EMBEDDED_LAYOUT):
        assert "<style" not in layout
        assert "style=" not in layout
        assert "onclick=" not in layout


def test_mathjax_is_an_explicit_page_level_capability():
    assert "window.MathJax" not in BASE_LAYOUT
    assert "vendor/mathjax" not in BASE_LAYOUT
    assert "window.MathJax" in MATHJAX_COMPONENT
    assert "vendor/mathjax/tex-mml-chtml.js" in MATHJAX_COMPONENT

    consumers = {
        "problems/create.html",
        "problems/detail.html",
        "problems/edit.html",
        "forum/create.html",
        "forum/thread.html",
        "submissions/detail.html",
        "ranking/detail.html",
        "ranking/appeal_review.html",
    }
    include = "{% include 'components/layout/mathjax.html' %}"
    for name in consumers:
        source = (ROOT / "templates" / name).read_text(encoding="utf-8")
        assert source.count(include) == 1

    non_consumers = {
        "auth/login.html",
        "games/circle_cat.html",
        "submissions/list.html",
        "submissions/all.html",
    }
    for name in non_consumers:
        source = (ROOT / "templates" / name).read_text(encoding="utf-8")
        assert include not in source


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
        assert attribute in LAYOUT_COMPONENTS

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


def test_desktop_sidebar_width_and_collapsed_items_share_one_center_axis():
    assert "--numoj-sidebar-width: 186px;" in LAYOUT_CSS
    collapsed_rule = LAYOUT_CSS.split(
        ".numoj-site-shell.is-sidebar-collapsed .numoj-nav-item {",
        1,
    )[1].split("}", 1)[0]
    assert "width: calc(100% - 26px);" in collapsed_rule
    assert "margin-inline: 13px;" in collapsed_rule
    assert "justify-content: center;" in collapsed_rule
