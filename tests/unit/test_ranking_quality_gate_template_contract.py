"""质量门禁与主评测池共享端点弹窗时的前端契约。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = "\n".join(
    path.read_text(encoding="utf-8")
    for path in (
        ROOT / "templates" / "ranking" / "settings" / "endpoint_pool.html",
        ROOT / "static" / "app" / "ranking" / "endpoints.js",
    )
)
MODAL_TEMPLATE = (
    ROOT
    / "templates"
    / "ranking"
    / "modals"
    / "reverse_judge_detail.html"
).read_text(encoding="utf-8")


def test_shared_endpoint_modal_distinguishes_primary_and_quality_gate_pools():
    assert "poolKind:config.poolKind || 'primary'" in TEMPLATE
    assert "poolKind:'primary'" in TEMPLATE
    assert "poolKind:'quality_gate'" in TEMPLATE
    assert (
        "harness === 'opencode' && (!manager || manager.poolKind === 'primary')"
        in TEMPLATE
    )


def test_quality_gate_opencode_keeps_and_displays_configured_api_url():
    assert "endpointText(manager, e)" in TEMPLATE
    assert (
        "base_url: usesFixedOpenCodeEndpoint(activeManager, h) ? '' : "
        "(editBaseUrl.value || '').trim()"
        in TEMPLATE
    )
    assert (
        "var openAiCompatible = h === 'codex' || "
        "(h === 'opencode' && !fixedOpenCode);"
        in TEMPLATE
    )


def test_reverse_detail_hides_quality_gate_when_snapshot_marks_it_skipped():
    assert 'data-rj-step="quality_gate" disabled hidden' in MODAL_TEMPLATE
    assert ".rj-tab[hidden] { display:none; }" in MODAL_TEMPLATE
    assert "step.status !== 'skipped'" in MODAL_TEMPLATE
    assert "!(step.result && step.result.skipped)" in MODAL_TEMPLATE
    assert "btn.hidden = !renderable;" in MODAL_TEMPLATE
