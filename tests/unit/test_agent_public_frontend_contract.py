from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


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
    assert "problem_core.admin_agent_tasks" not in navigation
    assert ">Agent 任务</span>" not in admin


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

    for contract in (
        "data-agent-access-root",
        "data-agent-access-summary-url",
        "data-agent-access-request-url",
        "data-agent-access-prices-url",
        "data-agent-access-personal-endpoints-url",
        "data-agent-access-reviews-url",
        "data-agent-access-review-url-template",
        "data-agent-access-class-grant-url",
        "data-agent-quota-used",
        "data-agent-quota-remaining",
        "data-agent-rate-list",
        "data-agent-personal-endpoint-form",
        "data-agent-review-list",
        "data-agent-class-grant-form",
    ):
        assert contract in template
    assert "fa-wallet" in template
    assert "data-agent-review-badge" in template
    assert "hidden{% endif %}" in template
    assert "data-agent-fab-balance" not in template
    assert "data-agent-quota-total" not in template
    assert "累计额度" not in template
    assert "使用全站端点时，每次模型请求完成后实时扣减。" not in template
    for tab_name in ("quota", "prices", "personal"):
        assert f'data-agent-user-tab="{tab_name}"' in template
        assert f'data-agent-user-panel="{tab_name}"' in template
    assert 'role="tablist"' in template
    assert "data-agent-personal-endpoint-layer" in template
    assert "data-agent-personal-delete-layer" in template
    assert "data-agent-personal-endpoint-create" in template
    assert "data-agent-protocol-option" in template
    assert '<select name="protocol"' not in template
    assert '<details class="agent-personal-endpoint-editor"' not in template
    assert template.count("novalidate") >= 3
    assert "function decimalText(value)" in controller
    assert "replace(/0+$/, '').replace(/\\.$/, '')" in controller
    assert "function multiplyDecimal(value, multiplier)" in controller
    assert "new Set()" in controller
    assert "user_ids" in controller
    assert "action: action" in controller
    assert "amount_rmb: grantForm.elements.amount_rmb.value" in controller
    assert "ArrowLeft" in controller
    assert "ArrowRight" in controller
    assert "event.stopPropagation()" in controller
    assert "node.inert = inert" in controller
    assert "global.confirm(" not in controller
    assert "reportValidity(" not in controller
    assert "global.location.reload" not in controller
    assert ".agent-access-fab" in styles
    assert ".agent-access-fab-badge" in styles
    assert ".agent-class-grant-options" in styles
    assert "width: 67vw" in styles
    assert ".agent-personal-endpoint-card" in styles
    assert ".agent-access-layer" in styles
    assert "grid-template-columns: repeat(auto-fill, minmax(360px, 1fr))" in styles


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
