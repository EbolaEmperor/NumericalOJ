from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "templates/admin/site_config.html"
SCRIPT = ROOT / "static/app/site-config.js"
STYLESHEET = ROOT / "static/app/site-config.css"
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
    for removed_feature in (
        "solution_agent",
        "testdata_agent",
        "agent_summary",
        "repository_query_summary",
    ):
        assert removed_feature not in script
    assert ".env" not in template


def test_site_config_keeps_decorative_labels_without_explanatory_copy():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)
    combined = f"{template}\n{script}"

    for decoration in (
        "GLOBAL CONFIGURATION",
        "ENDPOINT POOL",
        "RUNTIME BINDINGS",
        "OTHER SERVICES",
        "ENDPOINT EDITOR",
        "CHANGE PROTECTION",
        "PROTECTED CONFIG",
        "DELETE ENDPOINT",
    ):
        assert decoration in template

    for explanatory_copy in (
        "邮件与联网搜索可独立保存、测试或整组清除，不依赖模型端点池。",
        "造数据 Agent 的分析与测试数据生成端点。",
        "加锁后不可编辑、复测或删除，只有你本人可以通过密码与确认文本解锁。",
        "每个端点对应一种兼容协议",
        "八项全站能力独立选择端点",
        "为 Agent 提供联网检索能力",
        "为此项全站能力选择模型端点",
        "留空则保留当前密钥",
        "留空则保留当前密码",
        "留空则保留当前认证信息",
        "首次创建时必填",
        "首次保存必须填写",
        "presentation.description",
        "description:",
    ):
        assert explanatory_copy not in combined


def test_site_config_has_no_native_select_or_endpoint_filter_controls():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)
    combined = f"{template}\n{script}".lower()

    assert "<select" not in combined
    assert "<option" not in combined
    for stale_contract in (
        "data-endpoint-search",
        "data-endpoint-protocol-filter",
        "data-endpoint-category-filter",
        "data-endpoint-lock-filter",
        "filteredendpoints",
        "selectoptions",
    ):
        assert stale_contract not in combined


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
    assert "border-right:" not in rail
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
    script = _read(SCRIPT)
    picker = _read(CHOICE_PICKER)

    assert template.count('role="combobox"') == 2
    assert template.count('role="listbox"') == 2
    for trigger, menu in (
        ("endpointProtocolTrigger", "endpointProtocolMenu"),
        ("endpointCategoryTrigger", "endpointCategoryMenu"),
    ):
        assert f'id="{trigger}"' in template
        assert f'aria-controls="{menu}"' in template
        assert f'id="{menu}"' in template
        assert f'aria-labelledby="{trigger}"' in template
    for name in ("protocol", "category", "thinking_format"):
        assert f'name="{name}" type="hidden"' in template or (
            f'<input type="hidden" name="{name}"' in template
        )

    assert "data-feature-choice" in script
    assert "window.ChoicePicker.configure" in script
    assert "function configureChoice" not in script
    assert "function choiceOptionMarkup" not in script
    assert "app/choice-picker.js" not in template
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
    script = _read(SCRIPT)
    external_displays = "\n".join(
        _read(path)
        for path in (
            PROBLEM_ENDPOINT_SELECT,
            AI_DETECTION_TEMPLATE,
            RANKING_ENDPOINTS_SCRIPT,
        )
    )

    assert "端点名称" not in template
    assert 'name="name"' not in template
    assert "form.elements.name" not in script
    assert "endpoint.name" not in script
    assert "item.name" not in script
    assert "site-config-endpoint-name" not in f"{script}\n{_read(STYLESHEET)}"
    assert "site-config-endpoint-model" not in f"{script}\n{_read(STYLESHEET)}"
    assert "endpoint.name" not in external_displays
    assert "{{ endpoint.name }}" not in external_displays
    assert '<input name="model" required' in template
    assert "${escapeHtml(endpoint.model)}</h3>" in script
    assert "label: endpoint.model" in script


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

    assert '<select' not in lowered
    assert '<option' not in lowered
    assert 'selectedoptions' not in lowered
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
    script = _read(SCRIPT)

    assert "思考参数格式" not in template
    assert "form.elements.protocol.value === 'anthropic'" in script
    assert "'thinking_type' : 'enable_thinking'" in script
    assert ": 'none'" in script
    assert "form.elements.category.value !== 'embedding'" in script


def test_endpoint_editor_has_one_optional_three_price_row():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)
    stylesheet = _read(STYLESHEET)

    assert template.count('class="site-config-price-row"') == 1
    for field in (
        "input_price_per_million",
        "cached_input_price_per_million",
        "output_price_per_million",
    ):
        assert f'name="{field}" type="number"' in template
        assert f"form.elements.{field}.value.trim()" in script
        assert f"endpoint?.{field} ?? ''" in script
    assert "grid-template-columns: repeat(3, minmax(0, 1fr))" in stylesheet


def test_endpoint_save_is_gated_by_matching_test_token():
    script = _read(SCRIPT)

    assert "endpointFormFingerprint" in script
    assert "test_token" in script
    assert "字段已经变化，请重新测试连接" in script
    assert "[data-endpoint-save]').disabled = true" in script
