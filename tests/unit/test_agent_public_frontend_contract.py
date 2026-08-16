from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENDPOINT_EDITOR_TEMPLATE = "templates/components/endpoint_editor.html"
ENDPOINT_EDITOR_SCRIPT = "static/app/endpoint-editor.js"
ENDPOINT_EDITOR_STYLESHEET = "static/app/endpoint-editor.css"


def _read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_agent_navigation_is_visible_in_workspace_for_every_logged_in_user():
    navigation = _read("templates/components/layout/navigation.html")

    workspace = navigation.split('id="{{ id_prefix }}-workspace"', 1)[1].split(
        "{% if current_user.is_admin == 1 %}", 1
    )[0]
    admin = navigation.split("{% if current_user.is_admin == 1 %}", 1)[1]
    assert "problem_core.agent_tasks" in workspace
    assert ">Agent 任务</span>" in workspace


def test_workspace_navigation_uses_the_product_order():
    navigation = _read("templates/components/layout/navigation.html")
    workspace = navigation.split('id="{{ id_prefix }}-workspace"', 1)[1].split(
        "{% if current_user.is_admin == 1 %}", 1
    )[0]
    ordered_endpoints = (
        "problem_core.problem_list",
        "problem_core.all_submissions",
        "ranking.ranking_list",
        "problem_core.agent_tasks",
        "vibehub.index",
        "forum.forum_index",
        "repository.code_repository",
    )

    positions = [workspace.index(endpoint) for endpoint in ordered_endpoints]
    assert positions == sorted(positions)


def test_agent_home_has_quota_aware_composer_wallet_and_admin_scope_switch():
    template = _read("templates/admin/agent_tasks.html")
    controller = _read("static/app/agents/task-list.js")
    styles = _read("static/app/agents/task-list.css")

    for contract in (
        "data-agent-public-enabled",
        "data-agent-quota-can-start",
        "data-agent-quota-has-account",
        "data-agent-quota-remaining",
        "data-agent-create-access-note",
    ):
        assert contract in template
    assert "{% if agent_is_admin %}" in template
    assert 'name="access_role" value="user"' in template
    assert "agents/components/access_control.html" in template
    assert "app/agents/access-control.js" in template
    assert "scope='all'" in template
    assert "scope='mine'" in template
    assert "全站会话" in template
    assert "我的会话" in template
    assert "scope=history_scope" in template
    assert "function accessAllowed()" in controller
    assert "endpoint.isPersonal || quotaCanStart" in controller
    assert "numoj:agent-quota-change" in controller
    assert ".agent-history-scope" in styles


def test_agent_access_component_covers_wallet_rates_personal_endpoints_and_reviews():
    template = _read("templates/agents/components/access_control.html")
    controller = _read("static/app/agents/access-control.js")
    styles = _read("static/app/agents/access-control.css")
    endpoint_editor = _read(ENDPOINT_EDITOR_TEMPLATE)
    endpoint_editor_controller = _read(ENDPOINT_EDITOR_SCRIPT)

    for contract in (
        "data-agent-access-root",
        "data-agent-access-summary-url",
        "data-agent-access-request-url",
        "data-agent-access-prices-url",
        "data-agent-access-personal-endpoints-url",
        "data-agent-access-personal-endpoint-test-url",
        "data-agent-access-reviews-url",
        "data-agent-access-review-url-template",
        "data-agent-access-class-grant-url",
        "data-agent-quota-used",
        "data-agent-quota-remaining",
        "data-agent-rate-list",
        "data-agent-review-list",
        "data-agent-class-grant-form",
    ):
        assert contract in template
    assert "fa-wallet" in template
    assert "data-agent-review-badge" in template
    assert "hidden{% endif %}" in template
    for tab_name in ("quota", "prices", "personal"):
        assert f'data-agent-user-tab="{tab_name}"' in template
        assert f'data-agent-user-panel="{tab_name}"' in template
    assert 'data-agent-admin-tab="personal"' in template
    assert 'data-agent-admin-panel="personal"' in template
    assert 'grid-template-columns: repeat(3, minmax(0, 1fr));' in styles
    assert '[data-agent-admin-panel="personal"]' in styles
    assert 'role="tablist"' in template
    assert "data-agent-personal-endpoint-layer" in template
    assert "agent-access-layer--endpoint" in template
    assert "data-agent-personal-delete-layer" in template
    assert "data-agent-personal-endpoint-create" in template
    assert "components/endpoint_editor.html" in template
    assert "agent-quota-request-reason" in template
    assert "agent-quota-request-submit" in template
    assert '"reason reason"' in styles
    assert '". submit"' in styles
    assert "name=\"approved_amount\"" in controller
    assert "赠送额度" in controller
    assert "endpoint_editor('agentPersonalEndpoint', mode='personal', title='新建端点', surface='layer')" in template
    assert 'data-endpoint-editor data-endpoint-editor-mode="{{ mode }}"' in endpoint_editor
    assert 'data-endpoint-editor-thinking' in endpoint_editor
    for class_picker_contract in (
        "data-agent-class-picker-trigger",
        "data-agent-class-picker-search",
        "data-agent-class-picker-all",
        "data-agent-class-picker-none",
        "data-agent-class-picker-done",
    ):
        assert class_picker_contract in template
    assert 'aria-multiselectable="true"' in template
    assert template.count("novalidate") >= 2
    assert "novalidate" in endpoint_editor
    assert "function decimalText(value)" in controller
    assert "replace(/0+$/, '').replace(/\\.$/, '')" in controller
    assert "function multiplyDecimal(value, multiplier)" in controller
    assert "new Set()" in controller
    assert "user_ids" in controller
    assert "global.NumojModelFamily.iconClass(model)" in controller
    assert "function protocolText(value)" in controller
    assert "protocolText(endpoint.protocol)" in controller
    assert "agent-rate-logo" in controller
    assert "action: action" in controller
    assert "amount_rmb: grantForm.elements.amount_rmb.value" in controller
    assert "ArrowLeft" in controller
    assert "ArrowRight" in controller
    assert "event.stopPropagation()" in controller
    assert "node.inert = inert" in controller
    assert "global.NumOJEndpointEditor.mount(personalForm," in controller
    assert "personalEditor.values()" in controller
    assert "personalTestToken" in controller
    assert "personalFormFingerprint" in controller
    assert "agentAccessPersonalEndpointTestUrl" in controller
    assert "openLayer(personalEditorLayer, opener, '[data-endpoint-editor-title]')" in controller
    assert "activeLayer === personalEditorLayer" in controller
    assert "function closePersonalEditorLayer(restoreFocus)" in controller
    assert "modalNode.addEventListener('hide.bs.modal'" in controller
    assert "personalDeleteRequestRevision" in controller
    assert "global.NumOJEndpointEditor = Object.freeze({mount: mount})" in endpoint_editor_controller
    assert ".agent-access-fab" in styles
    assert ".agent-access-fab-badge" in styles
    assert ".agent-class-grant-options" in styles
    assert ".agent-rate-card" in styles
    assert ".agent-rate-logo" in styles
    assert "grid-template-columns: minmax(0, 1fr) minmax(168px, auto)" in styles
    assert ".agent-rate-values" in styles
    assert "grid-template-columns: repeat(3, minmax(0, 1fr))" in styles
    assert "grid-template-rows: auto auto" in styles
    assert "justify-items: center" in styles
    assert "border-left: 1px solid #e9e4db" in styles
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in styles
    assert "@media (max-width: 767.98px)" in styles
    assert "width: 67vw" in styles
    assert "height: 88dvh" in styles
    assert ".agent-class-picker-panel" in styles
    assert ".agent-personal-endpoint-card" in styles
    assert ".agent-access-layer" in styles
    assert "grid-template-columns: repeat(auto-fill, minmax(360px, 1fr))" in styles


def test_agent_access_composite_fields_draw_only_the_outer_rounded_focus_ring():
    template = _read("templates/agents/components/access_control.html")
    styles = _read("static/app/agents/access-control.css")
    layout = _read("static/app/layout.css")

    desktop_focus_rule = layout.split(":focus-visible {", 1)[1].split("}", 1)[0]
    assert 'class="agent-class-picker-search agent-access-input-shell"' in template

    shell_focus_rule = styles.split(
        ".agent-access-input-shell:focus-within {", 1
    )[1].split("}", 1)[0]
    assert "box-shadow: 0 0 0 2px #c2410c" in shell_focus_rule

    shell_control_rule = styles.split(
        ".agent-access-input-shell input,", 1
    )[1].split("}", 1)[0]
    assert "outline: 0" in shell_control_rule
    assert "box-shadow: none" in shell_control_rule
    invalid_focus_rule = styles.split(
        ".agent-access-input-shell.is-invalid:focus-within {", 1
    )[1].split("}", 1)[0]
    assert "box-shadow: 0 0 0 2px var(--agent-access-danger)" in invalid_focus_rule
    icon_rule = styles.split(
        ".agent-access-input-shell > i,", 1
    )[1].split("}", 1)[0]
    assert "font-size: 10px" in icon_rule
    amount_rule = styles.rsplit(
        "\n.agent-access-input-shell > b {", 1
    )[1].split("}", 1)[0]
    assert "font-family: var(--agent-access-mono)" in amount_rule
    assert "font-weight: 700" in amount_rule
    assert "@media (forced-colors: active)" in styles


def test_agent_detail_is_quota_aware_and_can_be_renamed_without_a_new_page():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")

    for contract in (
        "data-agent-uses-personal-endpoint",
        "data-agent-quota-can-continue",
        "data-agent-quota-has-account",
        "data-agent-quota-remaining",
        "data-agent-rename-url",
        "data-agent-rename-form",
        "data-agent-rename-input",
        "data-agent-rename-submit",
    ):
        assert contract in template
    assert "method: 'PATCH'" in controller
    assert "JSON.stringify({title: nextTitle})" in controller
    assert "function accessIsBlocked()" in controller
    assert "!usesPersonalEndpoint && !quotaCanContinue" in controller
    assert "额度已达到 -5 元" in controller
    assert "NumOJAgentAccess.update(summary)" in controller


def test_site_config_has_public_agent_switch_and_adaptive_price_formatting():
    template = _read("templates/admin/site_config.html")
    controller = _read("static/app/site-config.js")
    styles = _read("static/app/site-config.css")

    assert "data-agent-public-access-url" in template
    assert "data-agent-public-access-switch" in template
    assert "允许用户使用 Agent" in template
    assert "loadAgentPublicAccess()" in controller
    assert "saveAgentPublicAccess(event.currentTarget)" in controller
    assert "body: {enabled: next}" in controller
    assert "const decimalText = (value) =>" in controller
    assert "const moneyText = (value) =>" in controller
    assert "site-config-endpoint-prices" in controller
    assert ".site-config-agent-access" in styles
    assert ".site-config-endpoint-prices" in styles
