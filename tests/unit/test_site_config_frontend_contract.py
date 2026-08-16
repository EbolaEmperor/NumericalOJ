from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "templates/admin/site_config.html"
SCRIPT = ROOT / "static/app/site-config.js"
STYLESHEET = ROOT / "static/app/site-config.css"
ENDPOINT_EDITOR_TEMPLATE = ROOT / "templates/components/endpoint_editor.html"
ENDPOINT_EDITOR_SCRIPT = ROOT / "static/app/endpoint-editor.js"
ENDPOINT_EDITOR_STYLESHEET = ROOT / "static/app/endpoint-editor.css"
CHOICE_PICKER = ROOT / "static/app/choice-picker.js"
CHOICE_PICKER_TEMPLATE = ROOT / "templates/components/choice_picker.html"
PROBLEM_ENDPOINT_SELECT = ROOT / "templates/problems/components/llm_endpoint_select.html"
AI_DETECTION_TEMPLATE = ROOT / "templates/admin/ai_detection.html"
RANKING_ENDPOINTS_SCRIPT = ROOT / "static/app/ranking/endpoints.js"
RANKING_DETAIL_STYLESHEET = ROOT / "static/app/ranking/detail-v2.css"


def _read(path):
    return path.read_text(encoding="utf-8")


def _css_rule(source, selector):
    start = source.index(f"{selector} {{")
    return source[start : source.index("\n}", start) + 2]


def test_site_config_has_exactly_three_internal_pages():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)

    assert template.count("data-config-tab=") == 3
    assert 'data-config-tab="endpoints"' in template
    assert 'data-config-tab="features"' in template
    assert 'data-config-tab="other"' in template
    assert "LLM 端点" in template
    assert "功能配置" in template
    assert "其他配置" in template
    assert "data-feature-count" in template
    assert "state.meta.features.length" in script


def test_site_config_has_custom_agent_concurrency_control():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)
    stylesheet = _read(STYLESHEET)

    for contract in (
        'data-agent-concurrency-url="/api/admin/dynamic-config/agent-concurrency"',
        "data-agent-concurrency",
        "data-agent-concurrency-decrement",
        "data-agent-concurrency-input",
        "data-agent-concurrency-increment",
        "data-agent-concurrency-save",
        'role="spinbutton"',
        'aria-valuemin="1"',
        'aria-valuemax="100"',
    ):
        assert contract in template
    assert "Agent 任务并发上限" in template
    input_at = template.index("data-agent-concurrency-input")
    input_markup = template[
        template.rfind("<input", 0, input_at) : template.index(">", input_at)
    ]
    assert 'type="text"' in input_markup
    assert 'inputmode="numeric"' in input_markup
    assert "body: {limit}" in script
    assert "loadAgentConcurrency()" in script
    assert "settings.limit ?? 8" in script
    assert "data.applied === false" in script
    assert "配置已保存，Agent worker 重启后生效" in script
    assert "Agent 任务并发上限已生效" in script
    assert "event.key === 'ArrowDown'" in script
    assert "event.key === 'ArrowUp'" in script
    assert ".site-config-agent-stepper" in stylesheet
    assert ".site-config-agent-stepper:focus-within" in stylesheet


def test_site_config_keeps_decorative_labels_without_explanatory_copy():
    template = _read(TEMPLATE)
    endpoint_editor = _read(ENDPOINT_EDITOR_TEMPLATE)
    script = _read(SCRIPT)
    combined = f"{template}\n{endpoint_editor}\n{script}"

    for decoration in (
        "GLOBAL CONFIGURATION",
        "ENDPOINT POOL",
        "RUNTIME BINDINGS",
        "OTHER SERVICES",
        "CHANGE PROTECTION",
        "PROTECTED CONFIG",
        "DELETE ENDPOINT",
    ):
        assert decoration in template
    assert "ENDPOINT EDITOR" in endpoint_editor





def test_site_config_uses_content_left_and_function_rail_right():
    template = _read(TEMPLATE)
    stylesheet = _read(STYLESHEET)

    assert template.index('<main class="site-config-content-scroll"') < template.index(
        '<aside class="site-config-function-rail"'
    )
    assert 'aria-orientation="vertical"' in template
    workspace = _css_rule(stylesheet, ".site-config-workspace")
    content = _css_rule(stylesheet, ".site-config-content-scroll")
    rail = _css_rule(stylesheet, ".site-config-function-rail")
    header = _css_rule(stylesheet, ".site-config-header")
    assert "grid-template-columns: minmax(0, 1fr) var(--cfg-rail)" in workspace
    assert "grid-column: 1" in content
    assert "grid-column: 2" in rail
    assert "border-left:" in rail
    assert "min-height: 88px" in header
    assert "background: rgba(255, 255, 255, 0.98)" in header


def test_site_config_rail_typography_matches_ranking_detail():
    stylesheet = _read(STYLESHEET)
    ranking_stylesheet = _read(RANKING_DETAIL_STYLESHEET)

    compared_rules = (
        (
            ".site-config-rail-group-label",
            ".ranking-rail-group-label",
            ("font: 500 9.5px/1.5",),
        ),
        (
            ".site-config-rail-button",
            ".ranking-rail-button",
            (
                "min-height: 38px",
                "font-size: 13px",
                "font-weight: 450",
                "line-height: 1.35",
            ),
        ),
        (
            ".site-config-rail-count",
            ".ranking-rail-count",
            ("font: 10.5px/1",),
        ),
    )
    for config_selector, ranking_selector, declarations in compared_rules:
        config_rule = _css_rule(stylesheet, config_selector)
        ranking_rule = _css_rule(ranking_stylesheet, ranking_selector)
        for declaration in declarations:
            assert declaration in config_rule
            assert declaration in ranking_rule


def test_site_config_choice_pickers_are_custom_and_accessible():
    template = _read(TEMPLATE)
    endpoint_editor = _read(ENDPOINT_EDITOR_TEMPLATE)
    script = _read(SCRIPT)
    picker = _read(CHOICE_PICKER)

    assert "components/endpoint_editor.html" in template
    assert "endpoint_editor('endpointModal', mode='global'" in template
    assert endpoint_editor.count('role="combobox"') == 2
    assert endpoint_editor.count('role="listbox"') == 2
    for trigger, menu in (
        ("{{ id_prefix }}-protocol-trigger", "{{ id_prefix }}-protocol-menu"),
        ("{{ id_prefix }}-category-trigger", "{{ id_prefix }}-category-menu"),
    ):
        assert f'id="{trigger}"' in endpoint_editor
        assert f'aria-controls="{menu}"' in endpoint_editor
        assert f'id="{menu}"' in endpoint_editor
        assert f'aria-labelledby="{trigger}"' in endpoint_editor
    for name in ("protocol", "category", "thinking_format"):
        name_at = endpoint_editor.index(f'name="{name}"')
        field = endpoint_editor[
            endpoint_editor.rfind("<input", 0, name_at) : endpoint_editor.index(">", name_at)
        ]
        assert 'type="hidden"' in field

    assert "data-feature-choice" in script
    assert "window.ChoicePicker.configure" in script
    assert "data-choice-value" in picker
    for contract in (
        "setAttribute('role', 'combobox')",
        "setAttribute('aria-haspopup', 'listbox')",
        "setAttribute('aria-controls'",
        "setAttribute('role', 'listbox')",
        "setAttribute('role', 'option')",
        "setAttribute('aria-expanded'",
        "setAttribute('aria-activedescendant'",
        "setAttribute('aria-selected'",
        "setAttribute('aria-disabled'",
    ):
        assert contract in picker


def test_site_config_choice_picker_supports_full_keyboard_navigation():
    picker = _read(CHOICE_PICKER)
    script = _read(SCRIPT)

    for key in ("ArrowDown", "ArrowUp", "Home", "End", "Enter", "Escape", "Tab"):
        assert f"event.key === '{key}'" in picker
    assert "event.key === ' '" in picker
    assert "event.preventDefault()" in picker
    assert "trigger.focus()" in picker
    assert "scrollIntoView({block: 'nearest'})" in picker
    assert "button.tabIndex = active ? 0 : -1" in script
    assert "next.focus()" in script


def test_mobile_function_rail_opens_from_right_and_manages_focus():
    template = _read(TEMPLATE)
    stylesheet = _read(STYLESHEET)
    script = _read(SCRIPT)

    assert 'aria-controls="siteConfigRail"' in template
    assert "data-config-rail-close" in template
    assert "data-config-rail-backdrop hidden" in template
    mobile = stylesheet[
        stylesheet.index("@media (max-width: 991.98px)") : stylesheet.index(
            "@media (max-width: 760px)"
        )
    ]
    for declaration in (
        "position: fixed",
        "right: 0",
        "left: auto",
        "transform: translateX(105%)",
        "transform: translateX(0)",
        "body.site-config-rail-is-open",
        "overflow: hidden",
    ):
        assert declaration in mobile
    for behavior in (
        "window.matchMedia",
        "rail.setAttribute('aria-hidden', 'false')",
        "backdrop.hidden = false",
        "backdrop.hidden = true",
        "site-config-rail-is-open",
        "event.key === 'Escape'",
        "restoreFocus: true",
        "focusable[0]",
    ):
        assert behavior in script


def test_locked_cards_use_a_single_unlock_overlay_action():
    script = _read(SCRIPT)

    assert "site-config-lock-overlay" in script
    assert 'data-endpoint-action="unlock"' in script
    assert "data-feature-unlock" in script
    assert "data-unlock-reason" in script
    assert "你无法解锁" in _read(TEMPLATE)


def test_endpoint_secrets_are_never_rendered_from_list_payload():
    script = _read(SCRIPT)

    assert "endpoint.api_key_configured" in script
    assert "endpoint.api_key}" not in script
    assert "endpoint.api_key)" not in script
    assert "密钥已配置" in script


def test_endpoint_model_is_the_only_display_name():
    template = _read(TEMPLATE)
    endpoint_editor = _read(ENDPOINT_EDITOR_TEMPLATE)
    script = _read(SCRIPT)
    external_displays = "\n".join(
        _read(path)
        for path in (
            PROBLEM_ENDPOINT_SELECT,
            AI_DETECTION_TEMPLATE,
            RANKING_ENDPOINTS_SCRIPT,
        )
    )

    assert '<input type="hidden" name="name" value="" disabled>' in endpoint_editor
    assert '<input name="model" maxlength="200" required' in endpoint_editor
    assert "modelIconClass(endpoint.model)" in script
    assert "${escapeHtml(endpoint.model)}</span></h3>" in script
    assert "label: endpoint.model" in script
    assert "model: endpoint.model" in script


def test_duplicate_models_are_disambiguated_by_stable_endpoint_id():
    script = _read(SCRIPT)
    picker_template = _read(CHOICE_PICKER_TEMPLATE)
    problem_select = _read(PROBLEM_ENDPOINT_SELECT)
    detection_template = _read(AI_DETECTION_TEMPLATE)
    ranking_script = _read(RANKING_ENDPOINTS_SCRIPT)

    assert "节点 #${Number(endpoint.id)}" in script
    assert "meta: `节点 #${endpoint.id}" in script
    assert "endpoint_choice(" in problem_select
    assert "endpoint_choice(" in detection_template
    assert "'节点 #' ~ endpoint.id" in picker_template
    assert "meta:'节点 #' + endpoint.id" in ranking_script


def test_ai_detection_uses_shared_choice_pickers_in_each_view():
    template = _read(AI_DETECTION_TEMPLATE)
    lowered = template.lower()

    assert template.count("endpoint_choice(") == 3
    assert template.count("simple_choice(") == 2

    dashboard = template[
        template.index('<div class="filter-card') : template.index(
            '{# ---- Summary Cards', template.index('<div class="filter-card')
        )
    ]
    assert "'f_endpoint'" in dashboard
    assert "'f_class'" in dashboard
    assert "'f_problem'" in dashboard

    problem_view = template[
        template.index("{% if view == 'problem' %}") : template.index(
            "{% elif view == 'student' %}"
        )
    ]
    student_view = template[
        template.index("{% elif view == 'student' %}") : template.index(
            "{% else %}\n{# ============================================================ Dashboard"
        )
    ]
    for detail_view, action in (
        (problem_view, 'onclick="runBatchDetection('),
        (student_view, "onclick='runUserDetection("),
    ):
        assert 'class="detection-action-bar mb-3"' in detail_view
        assert "endpoint_choice(" in detail_view
        assert action in detail_view

    assert "function _getEndpointLabel()" in template
    assert "closest('[data-rk-choice]')" in template
    assert "querySelector('[data-rk-choice-label]')" in template
    assert "const endpointName = _getEndpointLabel();" in template


def test_endpoint_protection_actions_name_the_stable_endpoint_id():
    script = _read(SCRIPT)

    assert script.count("escapeHtml(identity)") == 4
    assert "toast(`“${endpointIdentity(endpoint)}”连接正常`)" in script
    assert "`加锁 · ${endpointIdentity(item)}`" in script
    assert "`解锁 · ${endpointIdentity(item)}`" in script
    assert "textContent = endpointIdentity(endpoint)" in script


def test_endpoint_thinking_wire_format_is_derived_from_protocol():
    template = _read(TEMPLATE)
    endpoint_editor = _read(ENDPOINT_EDITOR_TEMPLATE)
    endpoint_editor_script = _read(ENDPOINT_EDITOR_SCRIPT)

    assert 'data-endpoint-editor-thinking' in endpoint_editor
    assert "form.elements.protocol.value === 'anthropic'" in endpoint_editor_script
    assert "'thinking_type' : 'enable_thinking'" in endpoint_editor_script
    assert ": 'none'" in endpoint_editor_script
    assert "category !== 'embedding'" in endpoint_editor_script


def test_endpoint_editor_requires_and_summarizes_all_three_prices():
    template = _read(ENDPOINT_EDITOR_TEMPLATE)
    script = _read(SCRIPT)
    endpoint_editor_script = _read(ENDPOINT_EDITOR_SCRIPT)
    stylesheet = _read(ENDPOINT_EDITOR_STYLESHEET)

    assert template.count('class="numoj-endpoint-editor__prices wide"') == 1
    for field in (
        "input_price_per_million",
        "cached_input_price_per_million",
        "output_price_per_million",
    ):
        assert f'name="{field}" type="number"' in template
        price_input = template.split(f'name="{field}"', 1)[1].split(">", 1)[0]
        assert "required" in price_input
        assert f"form.elements.{field}.value.trim()" in endpoint_editor_script
        assert f"decimalText(endpoint.{field})" in script
        assert f"moneyText(endpoint.{field})" in script
    assert "grid-template-columns: repeat(3, minmax(0, 1fr))" in stylesheet
    assert "function endpointCard(endpoint)" in script
    assert 'class="site-config-endpoint-prices"' in script


def test_endpoint_editor_exposes_capacity_and_applies_tested_upstream_limits():
    template = _read(ENDPOINT_EDITOR_TEMPLATE)
    shared = _read(ENDPOINT_EDITOR_SCRIPT)
    host = _read(SCRIPT)

    assert 'name="context_window_tokens" type="number"' in template
    assert 'name="max_output_tokens" type="number"' in template
    assert 'value="384000"' in template
    assert 'value="32000"' in template
    assert "function applyTestedLimits(value)" in shared
    assert "endpointEditor.applyTestedLimits(test)" in host
    assert "state.endpointFormFingerprint = fingerprint(endpointPayload())" in host
    assert "已按上游上限调整容量" in host


def test_endpoint_save_is_gated_by_matching_test_token():
    script = _read(SCRIPT)

    assert "endpointFormFingerprint" in script
    assert "test_token" in script
    assert "字段已经变化，请重新测试连接" in script
    assert "[data-endpoint-editor-save]', endpointForm).disabled = true" in script
