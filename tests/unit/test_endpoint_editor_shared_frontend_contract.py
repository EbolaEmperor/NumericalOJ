from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SHARED_TEMPLATE = ROOT / "templates/components/endpoint_editor.html"
SHARED_SCRIPT = ROOT / "static/app/endpoint-editor.js"
SHARED_STYLESHEET = ROOT / "static/app/endpoint-editor.css"
SITE_TEMPLATE = ROOT / "templates/admin/site_config.html"
AGENT_COMPONENT = ROOT / "templates/agents/components/access_control.html"
AGENT_PAGES = (
    ROOT / "templates/admin/agent_tasks.html",
    ROOT / "templates/admin/agent_task_detail.html",
)


def _read(path):
    return path.read_text(encoding="utf-8")


def _assert_asset_before(template, shared_asset, host_asset):
    assert shared_asset in template
    assert host_asset in template
    assert template.index(shared_asset) < template.index(host_asset)


def test_global_and_personal_endpoints_render_the_same_editor_macro():
    shared = _read(SHARED_TEMPLATE)
    site = _read(SITE_TEMPLATE)
    agent = _read(AGENT_COMPONENT)

    import_contract = (
        "{% from 'components/endpoint_editor.html' import endpoint_editor %}"
    )
    assert import_contract in site
    assert import_contract in agent
    assert "{% macro endpoint_editor(id_prefix, mode='global'" in shared
    assert "endpoint_editor('endpointModal', mode='global'" in site
    assert "endpoint_editor('agentPersonalEndpoint', mode='personal'" in agent
    assert 'id="endpointModal"' in site
    assert 'id="agentPersonalEndpointModal"' in agent
    modal_shell = 'class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"'
    assert modal_shell in site
    assert modal_shell in agent

    for field in (
        "model",
        "protocol",
        "category",
        "base_url",
        "api_key",
        "thinking_enabled",
        "thinking_format",
    ):
        assert f'name="{field}"' in shared
    assert 'name="model"' not in site
    assert 'name="model"' not in agent
    assert shared.count("data-endpoint-editor-test") == 1
    assert "data-endpoint-editor-dismiss" not in shared
    assert "numoj-endpoint-editor--layer" not in shared
    assert "data-agent-personal-endpoint-layer" not in agent


def test_endpoint_editor_assets_load_before_each_host_controller_and_stylesheet():
    site = _read(SITE_TEMPLATE)
    _assert_asset_before(site, "app/endpoint-editor.css", "app/site-config.css")
    _assert_asset_before(site, "app/endpoint-editor.js", "app/site-config.js")

    for page_path in AGENT_PAGES:
        page = _read(page_path)
        _assert_asset_before(
            page, "app/endpoint-editor.css", "app/agents/access-control.css"
        )
        _assert_asset_before(
            page, "app/endpoint-editor.js", "app/agents/access-control.js"
        )


def test_shared_controller_owns_choices_thinking_validation_and_values():
    shared = _read(SHARED_TEMPLATE)
    script = _read(SHARED_SCRIPT)
    stylesheet = _read(SHARED_STYLESHEET)

    for contract in (
        'data-endpoint-editor-choice="protocol"',
        'data-endpoint-editor-choice="category"',
        "data-endpoint-editor-thinking",
        "data-endpoint-editor-key-note",
        "data-endpoint-editor-result",
        "data-endpoint-editor-save",
    ):
        assert contract in shared
    for contract in (
        "global.ChoicePicker.configure",
        "function setThinking(enabled)",
        "function values()",
        "function validate()",
        "global.NumOJEndpointEditor = Object.freeze({mount: mount})",
    ):
        assert contract in script
    assert ".numoj-endpoint-editor" in stylesheet
    assert ".numoj-endpoint-editor__thinking" in stylesheet
    assert ".numoj-endpoint-editor__prices" in stylesheet


def test_legacy_endpoint_form_and_personal_protocol_contracts_are_gone():
    sources = "\n".join(
        _read(path)
        for path in (
            SHARED_TEMPLATE,
            SHARED_SCRIPT,
            SITE_TEMPLATE,
            AGENT_COMPONENT,
            ROOT / "static/app/site-config.js",
            ROOT / "static/app/agents/access-control.js",
        )
    )
    for stale_contract in (
        "data-endpoint-form",
        "data-agent-personal-endpoint-form",
        "data-agent-protocol-option",
    ):
        assert stale_contract not in sources


def test_host_adapters_ignore_stale_editor_requests():
    site_script = _read(ROOT / "static/app/site-config.js")
    agent_script = _read(ROOT / "static/app/agents/access-control.js")

    assert "const testedFingerprint = fingerprint(payload)" in site_script
    assert "fingerprint(endpointPayload()) !== testedFingerprint" in site_script
    assert "var personalEditorRevision = 0" in agent_script
    assert "editorRevision === personalEditorRevision" in agent_script
    assert "editorRevision !== personalEditorRevision" in agent_script
    assert "personalFormFingerprint" in agent_script
    assert "endpointFingerprint(personalEndpointPayload()) !== testedFingerprint" in agent_script
    assert "personalModalNode.classList.contains('show')" in agent_script


def test_personal_editor_keeps_shared_fields_but_omits_platform_prices():
    shared = _read(SHARED_TEMPLATE)
    script = _read(SHARED_SCRIPT)

    assert 'data-endpoint-editor-choice="category"' in shared
    assert "{% if mode == 'global' %}" in shared
    for field in (
        "input_price_per_million",
        "cached_input_price_per_million",
        "output_price_per_million",
    ):
        assert shared.count(f'name="{field}"') == 2
    assert "settings.mode === 'personal'" not in script


def test_shared_endpoint_controls_use_one_rounded_focus_ring():
    endpoint_styles = _read(SHARED_STYLESHEET)
    choice_styles = _read(ROOT / "static/app/choice-picker.css")
    site_styles = _read(ROOT / "static/app/site-config.css")

    endpoint_input_focus = endpoint_styles.split(
        '.numoj-endpoint-editor input:not([type="hidden"]):focus {', 1
    )[1].split("}", 1)[0]
    endpoint_button_focus = endpoint_styles.split(
        ".numoj-endpoint-editor button:focus-visible {", 1
    )[1].split("}", 1)[0]
    for rule in (endpoint_input_focus, endpoint_button_focus):
        assert "outline: 0" in rule
        assert "box-shadow: 0 0 0 2px #c2410c" in rule
    endpoint_invalid_focus = endpoint_styles.split(
        ".numoj-endpoint-editor input.is-invalid:focus,", 1
    )[1].split("}", 1)[0]
    assert "box-shadow: 0 0 0 2px var(--endpoint-danger)" in endpoint_invalid_focus

    choice_focus = choice_styles.split(
        ".rk-choice-trigger:focus-visible,", 1
    )[1].split("}", 1)[0]
    assert "outline: 0" in choice_focus
    assert "box-shadow: 0 0 0 2px #c2410c" in choice_focus
    assert ".rk-choice.is-invalid .rk-choice-trigger:focus-visible" in choice_styles

    site_focus = site_styles.split(
        ".site-config-v2 button:focus-visible,", 1
    )[1].split("}", 1)[0]
    assert "outline: 0" in site_focus
    assert "box-shadow: 0 0 0 2px #c2410c" in site_focus
    assert "@media (forced-colors: active)" in endpoint_styles
    assert "@media (forced-colors: active)" in choice_styles
