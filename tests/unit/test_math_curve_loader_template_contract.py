"""数学曲线加载动画的前端接入契约。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "templates"
LOADER_JS = (ROOT / "static" / "math-curve-loaders" / "loader.js").read_text(
    encoding="utf-8"
)


def test_layout_family_loads_shared_math_curve_assets_once_from_base():
    base = (TEMPLATES / "layouts" / "base.html").read_text(encoding="utf-8")
    assert base.count("math-curve-loaders/loader.css") == 1
    assert base.count("math-curve-loaders/loader.js") == 1
    for filename in ("layouts/site.html", "layouts/embedded.html"):
        template = (TEMPLATES / filename).read_text(encoding="utf-8")
        assert template.count('{% extends "layouts/base.html" %}') == 1
        assert "math-curve-loaders/loader.css" not in template
        assert "math-curve-loaders/loader.js" not in template


def test_loader_randomizes_among_the_selected_seven_gallery_curves():
    assert "customRose(7, 64" in LOADER_JS
    assert "customRose(5, 62" in LOADER_JS
    assert "customRose(9, 68" in LOADER_JS
    assert "polarRose(2, 74" in LOADER_JS
    assert "polarRose(3, 76" in LOADER_JS
    assert "spiralSearch()" in LOADER_JS
    assert "particleCount: 86" in LOADER_JS
    assert "config.rotate === false" in LOADER_JS
    assert "polarRose(5, 78" not in LOADER_JS
    assert "polarRose(4, 78" not in LOADER_JS
    assert "Math.floor(Math.random() * CURVES.length)" in LOADER_JS
    assert "const DEFAULT_PALETTE = ['#111111', '#000000']" in LOADER_JS
    assert ": DEFAULT_PALETTE;" in LOADER_JS
    assert "const PALETTES = [" in LOADER_JS
    assert "path.setAttribute('opacity', '0')" in LOADER_JS


def test_templates_no_longer_use_legacy_loading_spinners():
    legacy_markers = (
        "spinner-border",
        "fa-spinner",
        "gitsub-spin",
        "progress-bar-animated",
    )
    for path in TEMPLATES.rglob("*.html"):
        template = path.read_text(encoding="utf-8")
        for marker in legacy_markers:
            assert marker not in template, f"{path.name} 仍包含旧加载动画 {marker}"


def test_loader_covers_navigation_fetch_and_dynamic_content():
    assert "installFetchTracking()" in LOADER_JS
    assert "installNavigationTracking()" in LOADER_JS
    assert "link.hasAttribute('download')" in LOADER_JS
    assert "new MutationObserver" in LOADER_JS
    assert "prefers-reduced-motion: reduce" in (
        ROOT / "static" / "math-curve-loaders" / "loader.css"
    ).read_text(encoding="utf-8")


def test_submission_detail_uses_large_bold_loaders():
    template = (TEMPLATES / "submissions" / "detail.html").read_text(encoding="utf-8")
    assert 'data-math-curve-stroke-scale="1.2"' in template
    assert 'data-size="lg"' in template
    assert 'data-size="md"' in template
    assert "element.dataset.colorA || scopedColorA || palette[0]" in LOADER_JS
    assert "element.dataset.strokeScale || scopedStrokeScale" in LOADER_JS
    assert "instance.config.strokeWidth * instance.strokeScale" in LOADER_JS


def test_score_export_is_marked_as_a_download_navigation():
    template = (TEMPLATES / "admin" / "homework.html").read_text(encoding="utf-8")
    assert (
        "url_for('homework.export_scores', sclass=selected_class) }}\" download"
        in template
    )


def test_lean_workspace_export_is_marked_as_a_download_navigation():
    template = (TEMPLATES / "problems" / "detail.html").read_text(encoding="utf-8")
    assert (
        "url_for('admin_problem.download_lean_workspace', problem_id=problem.id) }}\" download"
        in template
    )
