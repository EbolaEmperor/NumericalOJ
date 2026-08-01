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
SETTINGS_STYLESHEET = (
    ROOT / "static" / "app" / "ranking" / "settings.css"
).read_text(encoding="utf-8")
HARNESS_STYLESHEET = (
    ROOT / "static" / "app" / "ranking" / "harness-logos.css"
).read_text(encoding="utf-8")
HARNESS_MACROS = (
    ROOT / "templates" / "ranking" / "components" / "harness_logo.html"
).read_text(encoding="utf-8")
HARNESS_LOGOS = ROOT / "static" / "app" / "ranking" / "harness-logos"


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
        "var openAiCompatible = h === 'codex' || h === 'pi' ||"
        in TEMPLATE
    )
    assert (
        "(h === 'opencode' && !fixedOpenCode);"
        in TEMPLATE
    )


def test_shared_endpoint_modal_exposes_pi_as_openai_compatible_harness():
    assert 'data-choice-value="pi"' in TEMPLATE
    assert "if (h === 'pi') return 'Pi';" in TEMPLATE


def test_endpoint_modal_roundtrips_model_capabilities_without_model_special_cases():
    for field_id in (
        "ajeEditContextWindowTokens",
        "ajeEditMaxOutputTokens",
        "ajeEditThinkingCompatibility",
    ):
        assert f'id="{field_id}"' in TEMPLATE

    assert "DEFAULT_CONTEXT_WINDOW_TOKENS = 1000000" in TEMPLATE
    assert "DEFAULT_MAX_OUTPUT_TOKENS = 384000" in TEMPLATE
    assert "DEFAULT_THINKING_COMPATIBILITY = true" in TEMPLATE
    assert "MAX_TOKEN_SETTING = 1000000" in TEMPLATE
    assert TEMPLATE.count('max="1000000"') >= 2
    for field in (
        "context_window_tokens",
        "max_output_tokens",
        "thinking_compatibility",
    ):
        # 服务端加载、脏状态、保存 payload 与弹窗应用都必须携带能力字段。
        assert TEMPLATE.count(field) >= 5

    assert "最大输出不能超过上下文窗口" in TEMPLATE
    assert "Thinking 兼容" in TEMPLATE
    assert "Thinking 常规" in TEMPLATE
    assert "PI_DEEPSEEK" not in TEMPLATE
    assert "deepseek-v4" not in TEMPLATE.lower()


def test_harness_picker_and_cards_share_the_bound_brand_logo_contract():
    assert "harness-logo--' + key" in TEMPLATE
    assert "harness_logo_class('claude_code')" in TEMPLATE
    for harness in ("claude_code", "codex", "opencode", "pi"):
        assert f"harness_logo('{harness}')" in TEMPLATE

    assert "normalized in ('codex', 'opencode', 'pi')" in HARNESS_MACROS
    assert "else 'claude-code'" in HARNESS_MACROS
    assert "pi-brand-icon" not in TEMPLATE
    assert "pi-brand-icon" not in SETTINGS_STYLESHEET


def test_harness_logos_are_local_monochrome_assets():
    for name in ("claude-code", "codex", "opencode", "pi"):
        logo = HARNESS_LOGOS / f"{name}.svg"
        assert logo.is_file()
        assert f'url("harness-logos/{name}.svg")' in HARNESS_STYLESHEET

    claude = (HARNESS_LOGOS / "claude-code.svg").read_text(encoding="utf-8")
    codex = (HARNESS_LOGOS / "codex.svg").read_text(encoding="utf-8")
    opencode = (HARNESS_LOGOS / "opencode.svg").read_text(encoding="utf-8")
    pi = (HARNESS_LOGOS / "pi.svg").read_text(encoding="utf-8")

    assert 'fill="#000"' in claude
    assert "#D97757" not in claude
    assert '<svg fill="#000"' in codex
    assert "currentColor" not in codex
    assert "fill='#CFCECD'" in opencode
    assert "fill='#211E1E'" in opencode
    assert '<rect width="800"' not in pi
    assert pi.count('fill="#000"') == 2
    assert 'viewBox="140 140 520 520"' in pi


def test_reverse_detail_hides_quality_gate_when_snapshot_marks_it_skipped():
    assert 'data-rj-step="quality_gate" disabled hidden' in MODAL_TEMPLATE
    assert ".rj-tab[hidden] { display:none; }" in MODAL_TEMPLATE
    assert "step.status !== 'skipped'" in MODAL_TEMPLATE
    assert "!(step.result && step.result.skipped)" in MODAL_TEMPLATE
    assert "btn.hidden = !renderable;" in MODAL_TEMPLATE
