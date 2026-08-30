"""打榜赛提交卡片 V2 的视觉与交互契约。"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "backend" / "templates" / "ranking"
STYLESHEET = ROOT / "frontend" / "public" / "static" / "app" / "ranking" / "content-v2.css"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_submission_history_and_admin_list_share_the_identity_card_structure():
    submit = _read(TEMPLATES / "tabs" / "submit.html")
    rows = _read(TEMPLATES / "components" / "submission_rows.html")

    assert (
        "render_sub_card(s, competition, is_elo, is_agent_judge, "
        "max_score, true, false, is_reverse_judge)"
    ) in submit
    assert (
        "render_sub_card(s, competition, is_elo, _is_aj, "
        "max_score, true, true, _is_rj)"
    ) in rows


def test_submission_avatar_grid_is_not_limited_to_the_desktop_site_sidebar():
    card = _read(TEMPLATES / "components" / "submission_card.html")
    stylesheet = _read(STYLESHEET)

    assert 'class="numoj-avatar aj-sub-ava"' in card
    assert ".ranking-v2-detail .aj-sub-ava > span.is-filled" in stylesheet
    assert "grid-template-columns: repeat(8, 1fr);" in stylesheet
    assert "grid-template-rows: repeat(8, 1fr);" in stylesheet
    assert "place-items: stretch;" in stylesheet
    assert "background: var(--avatar-cell);" in stylesheet


def test_submission_model_is_plain_metadata_and_cards_keep_a_small_radius():
    card = _read(TEMPLATES / "components" / "submission_card.html")
    stylesheet = _read(STYLESHEET)

    assert card.count('class="aj-card-meta"') == 2
    assert "model_logo(s.base_model)" in card
    assert "model_logo(s.agent_endpoint_model)" in card
    assert ".ranking-v2-detail .aj-card-meta" in stylesheet
    assert re.search(
        r"\.ranking-v2-detail \.aj-sub \{[^}]*border-radius: 5px;",
        stylesheet,
        re.DOTALL,
    )


def test_repository_check_loader_uses_an_explicit_nonduplicated_label():
    submit = _read(TEMPLATES / "tabs" / "submit.html")

    assert 'data-loader-label="正在检查仓库…"' in submit


def test_reverse_submit_endpoint_shows_harness_and_model_as_separate_identity_parts():
    submit = _read(TEMPLATES / "tabs" / "submit.html")
    stylesheet = _read(STYLESHEET)

    assert "rj_harness_label(ep)" in submit
    assert "rj-endpoint-harness-name" in submit
    assert "rj-endpoint-plus" in submit
    assert "rj-endpoint-model-name" in submit
    assert "data-endpoint-harness-name" in submit
    assert "data-endpoint-model" in submit
    assert submit.index("rj-endpoint-harness-name") < submit.index(
        "rj-endpoint-plus"
    ) < submit.index("rj-endpoint-model-logo") < submit.index(
        "data-rj-endpoint-model-name"
    )
    assert ".ranking-v2-detail .rj-endpoint-plus" in stylesheet


def test_reverse_zip_submit_survives_missing_git_repository_controls():
    submit = _read(TEMPLATES / "tabs" / "submit.html")

    guard = (
        "if (!checkBtn || !checkSpin || !checkLabel || !resultEl ||\n"
        "              !confirmEl || !submitBtn || !submitSpin || !submitLabel ||\n"
        "              !confirmHint) return;"
    )
    assert guard in submit
    assert submit.index(guard) < submit.index(
        "checkBtn.addEventListener('click'"
    )
    assert submit.index(guard) < submit.index(
        "if (!confirmEl.hidden && submitBtn)"
    )
