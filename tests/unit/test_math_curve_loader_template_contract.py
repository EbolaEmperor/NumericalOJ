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


def test_loader_randomizes_among_the_selected_seven_gallery_curves():
    assert "customRose(7, 64" in LOADER_JS
    assert "customRose(5, 62" in LOADER_JS
    assert "customRose(9, 68" in LOADER_JS
    assert "polarRose(2, 74" in LOADER_JS
    assert "polarRose(3, 76" in LOADER_JS
    assert "spiralSearch()" in LOADER_JS
    assert "particleCount: 86" in LOADER_JS
    assert "config.rotate === false" in LOADER_JS
    assert "Math.floor(Math.random() * CURVES.length)" in LOADER_JS
    assert "const DEFAULT_PALETTE = ['#111111', '#000000']" in LOADER_JS
    assert ": DEFAULT_PALETTE;" in LOADER_JS
    assert "const PALETTES = [" in LOADER_JS
    assert "path.setAttribute('opacity', '0')" in LOADER_JS




def test_loader_covers_navigation_fetch_and_dynamic_content():
    assert "installFetchTracking()" in LOADER_JS
    assert "installNavigationTracking()" in LOADER_JS
    assert "link.hasAttribute('download')" in LOADER_JS
    assert "isDownloadDestination(destination)" in LOADER_JS
    assert "destination.searchParams.get('download') === '1'" in LOADER_JS
    assert "(?:download|export)" in LOADER_JS
    assert "new MutationObserver" in LOADER_JS
    assert "markNavigationPending(link)" in LOADER_JS
    assert "clearNavigationPending()" in LOADER_JS
    assert "data-numoj-navigation-pending" in LOADER_JS
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


def test_problem_detail_only_warns_about_expired_homework_on_submit():
    detail = (TEMPLATES / "problems" / "detail.html").read_text(encoding="utf-8")
    deadline_script = (
        ROOT / "static" / "app" / "problem-deadline-warning.js"
    ).read_text(encoding="utf-8")

    assert 'class="problem-homework-statuses"' not in detail
    assert "本次提交不计入作业成绩" not in detail
    assert 'id="homeworkDeadlineWarningModal"' in detail
    assert "我明白了" in detail
    assert "problem-deadline-warning.js" in detail
    assert "problem_api.deadline_warning" in detail
    assert "problem_api.submit_context" not in detail
    assert "window.confirm" not in deadline_script
    assert "window.alert" not in deadline_script


def test_dynamic_and_ranking_downloads_opt_out_of_page_navigation_loader():
    ranking_detail = (TEMPLATES / "ranking" / "detail.html").read_text(encoding="utf-8")
    ranking_settings = (TEMPLATES / "ranking" / "tabs" / "settings.html").read_text(
        encoding="utf-8"
    )
    agent_detail = (TEMPLATES / "admin" / "agent_task_detail.html").read_text(
        encoding="utf-8"
    )
    homework = (TEMPLATES / "admin" / "homework.html").read_text(encoding="utf-8")
    agent_controller = (ROOT / "static" / "app" / "agents" / "conversation.js").read_text(
        encoding="utf-8"
    )

    assert 'class="ranking-file-download"\n                   download' in ranking_detail
    assert 'class="btn btn-sm btn-outline-primary me-1" download' in ranking_settings
    assert 'download title="下载 {{ attachment_name }}"' in agent_detail
    assert 'id="downloadPlagiarismRecordsBtn"' in homework and 'href="#" download' in homework
    assert "download.download = name;" in agent_controller


def test_every_file_download_surface_is_explicitly_marked_or_url_classified():
    """下载端点不触发全页导航遮罩，哪怕路径本身不含 download。"""
    ranking_card = (TEMPLATES / "ranking" / "components" / "submission_card.html").read_text(
        encoding="utf-8"
    )
    reverse_detail = (TEMPLATES / "ranking" / "modals" / "reverse_judge_detail.html").read_text(
        encoding="utf-8"
    )
    media_preview = (TEMPLATES / "ranking" / "modals" / "media_preview.html").read_text(
        encoding="utf-8"
    )
    submission_detail = (TEMPLATES / "submissions" / "detail.html").read_text(
        encoding="utf-8"
    )

    assert "download_submission_answer" in ranking_card and "download title=" in ranking_card
    assert "download_submission_code" in ranking_card and "download title=" in ranking_card
    assert 'id="rjAnswerDownload"' in reverse_detail and "download hidden" in reverse_detail
    assert 'id="rkMediaDownload"' in media_preview and 'href="#" download' in media_preview
    assert 'id="downloadImageBtn" href="" download' in submission_detail
