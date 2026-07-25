# -*- coding: utf-8 -*-

"""讨论区正式工作台的静态契约。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (ROOT / "templates" / "forum" / "index.html").read_text(
    encoding="utf-8"
)
CSS = (ROOT / "static" / "app" / "forum.css").read_text(encoding="utf-8")
JAVASCRIPT = (ROOT / "static" / "app" / "forum.js").read_text(encoding="utf-8")
MARKDOWN_JAVASCRIPT = (
    ROOT / "static" / "app" / "forum-markdown.js"
).read_text(encoding="utf-8")
ROUTES = (ROOT / "oj_modules" / "routes" / "forum_routes.py").read_text(
    encoding="utf-8"
)
MATHJAX = (
    ROOT / "templates" / "components" / "layout" / "mathjax.html"
).read_text(encoding="utf-8")
BASE_LAYOUT = (ROOT / "templates" / "layouts" / "base.html").read_text(
    encoding="utf-8"
)
PACKAGE = (ROOT / "package.json").read_text(encoding="utf-8")
FORUM_ASSET_BUILD = (
    ROOT / "scripts" / "build_forum_rendering.mjs"
).read_text(encoding="utf-8")
CI_WORKFLOW = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
    encoding="utf-8"
)


def test_forum_uses_one_master_detail_workbench_and_canonical_thread_route():
    assert 'id="forumApp"' in TEMPLATE
    assert 'class="forum-workspace"' in TEMPLATE
    assert 'id="threadList"' in TEMPLATE
    assert 'id="conversation"' in TEMPLATE
    assert 'data-initial-thread-id=' in TEMPLATE
    assert "`/forum/thread/${Number(id)}`" in JAVASCRIPT
    assert "window.history.pushState" in JAVASCRIPT
    assert "window.history.replaceState" in JAVASCRIPT
    assert '@forum_bp.route("/forum/thread/<int:thread_id>", methods=["GET"])' in ROUTES


def test_list_column_is_seventy_percent_of_the_selected_mockup_width():
    assert "0.82fr / 1.18fr" in CSS
    assert "grid-template-columns: minmax(300px, 0.402fr) minmax(0, 1fr);" in CSS
    assert "约 28.7% / 71.3%" in CSS


def test_forum_has_only_the_confirmed_filters_and_no_role_labels():
    assert TEMPLATE.count('data-scope="all"') == 1
    assert TEMPLATE.count('data-scope="mine"') == 1
    for removed_label in ("待回复", "学生回复", "官方回复", "最近有回复"):
        assert removed_label not in TEMPLATE
        assert removed_label not in JAVASCRIPT


def test_browser_writes_use_json_apis_without_html_form_fallback():
    assert "request.form" not in ROUTES
    assert 'methods=["POST"]' not in ROUTES
    assert 'const API_ROOT = "/api/forum";' in JAVASCRIPT
    for endpoint in ("/threads", "/replies", "/preview", "/identity"):
        assert endpoint in JAVASCRIPT
    assert '"Content-Type"] = "application/json"' in JAVASCRIPT
    assert "client_request_id" in JAVASCRIPT


def test_reliable_submission_keeps_tab_drafts_and_retries_with_one_uuid():
    assert "window.sessionStorage" in JAVASCRIPT
    assert "crypto.randomUUID" in JAVASCRIPT
    assert "RETRY_DELAYS_MS" in JAVASCRIPT
    assert "草稿和请求标识仍在本标签页" in JAVASCRIPT
    assert "pending_attempt" in JAVASCRIPT
    assert "clearDraft(submittedDraftKey)" in JAVASCRIPT
    assert "clearDraft(draftKey)" in JAVASCRIPT
    assert "expected_identity_token" in JAVASCRIPT
    assert "base_version" in JAVASCRIPT
    assert 'id="rebaseEditorDraftButton"' in TEMPLATE


def test_reply_submission_sends_the_frozen_api_body_not_the_draft_envelope():
    reply_call = (
        "requestJson(`${API_ROOT}/threads/${submittedThreadId}/replies`, {\n"
        '        method: "POST",\n'
        "        body,"
    )
    assert reply_call in JAVASCRIPT
    assert (
        "requestJson(`${API_ROOT}/threads/${submittedThreadId}/replies`, {\n"
        '        method: "POST",\n'
        "        body: draft,"
    ) not in JAVASCRIPT


def test_anonymous_identity_and_avatar_controls_match_the_domain_rules():
    assert 'id="anonymousToggle"' in TEMPLATE
    assert 'id="refreshIdentityButton"' in TEMPLATE
    assert 'id="identityDialog"' in TEMPLATE
    assert "weightedAliasLength" in JAVASCRIPT
    assert "normalize(\"NFKC\")" in JAVASCRIPT
    assert "new TextEncoder()" in JAVASCRIPT
    assert "grid-template-columns: repeat(8, 1fr)" in CSS
    assert "previous_anonymous_name" in JAVASCRIPT
    assert "attemptedName === previousName" in JAVASCRIPT


def test_mobile_switches_between_list_and_detail_instead_of_squeezing_columns():
    assert ".forum-page.is-mobile-detail-open .forum-detail-pane" in CSS
    assert 'id="mobileBackButton"' in TEMPLATE
    assert "showMobileDetail" in JAVASCRIPT
    assert "forum-mobile-locked" in CSS
    assert "currentPathThreadId() !== numericId" in JAVASCRIPT
    assert "const fromForumList = /^\\/forum\\/?$/.test(window.location.pathname);" in JAVASCRIPT
    assert ".forum-post {\n  position: relative;" in CSS


def test_mobile_header_controls_keep_accessible_names_when_copy_is_hidden():
    assert 'aria-label="发起讨论"' in TEMPLATE
    assert 'aria-label="匿名身份开关"' in TEMPLATE
    assert 'aria-label="搜索讨论"' in TEMPLATE


def test_button_color_reset_does_not_override_component_variants():
    assert ".forum-page :where(button) {\n  color: inherit;" in CSS
    assert ".forum-page button {\n  color: inherit;" not in CSS
    assert ".forum-button-primary {\n" in CSS
    assert ".forum-button-dark {\n" in CSS


def test_editor_completion_cannot_mutate_a_newly_opened_edit_context():
    assert "function editorContextMatches(mode, targetId, draftKey)" in JAVASCRIPT
    assert "const submittedMode = state.editorMode;" in JAVASCRIPT
    assert "const submittedTargetId = submittedMode === \"new\"" in JAVASCRIPT
    assert "if (editorContextMatches(submittedMode, submittedTargetId, draftKey))" in JAVASCRIPT


def test_reply_completion_only_updates_the_original_thread_context():
    assert "const submittedThreadId = state.thread.id;" in JAVASCRIPT
    assert "const submittedDraftKey = replyDraftKey();" in JAVASCRIPT
    assert "if (state.thread && state.thread.id === submittedThreadId)" in JAVASCRIPT
    assert "const latestDraft = readDraft(submittedDraftKey);" in JAVASCRIPT


def test_mathjax_uses_an_explicit_non_html_package_allowlist():
    assert "packages: ['base', 'ams', 'newcommand', 'noundefined']" in MATHJAX
    assert "load: []" in MATHJAX


def test_forum_loads_pinned_self_hosted_mermaid_only_on_its_page():
    mermaid_asset = ROOT / "static" / "vendor" / "mermaid" / "mermaid.min.js"
    mermaid_license = ROOT / "static" / "vendor" / "mermaid" / "LICENSE"

    assert TEMPLATE.count("vendor/mermaid/mermaid.min.js") == 1
    assert TEMPLATE.count("app/forum-markdown.js") == 1
    assert TEMPLATE.index("vendor/mermaid/mermaid.min.js") < TEMPLATE.index(
        "app/forum-markdown.js"
    )
    assert TEMPLATE.index("app/forum-markdown.js") < TEMPLATE.index("app/forum.js")
    assert "vendor/mermaid" not in BASE_LAYOUT
    assert '"mermaid": "11.16.0"' in PACKAGE
    assert "node_modules/mermaid/dist/mermaid.min.js" in FORUM_ASSET_BUILD
    assert "npm run build:frontend" in CI_WORKFLOW
    assert "static/vendor/mermaid" in CI_WORKFLOW
    assert mermaid_asset.stat().st_size > 1_000_000
    assert mermaid_license.is_file()


def test_forum_mermaid_uses_sandbox_limits_and_handles_dynamic_html():
    for contract in (
        'securityLevel: "sandbox"',
        "startOnLoad: false",
        "maxTextSize: MERMAID_MAX_TEXT_SIZE",
        "maxEdges: MERMAID_MAX_EDGES",
        "suppressErrorRendering: true",
        'const source = String(code.textContent || "");',
        "await mermaidRenderer.parse(source, { suppressErrors: true });",
        "await mermaidRenderer.run({ nodes: [diagram] });",
        "container.dataset.mermaidGeneration !== generation",
        "if (root.isConnected) await typesetMath(root);",
    ):
        assert contract in MARKDOWN_JAVASCRIPT

    assert "enhanceRenderedMarkdown(elements.conversation)" in JAVASCRIPT
    assert ".then(settleScrollPosition)" in JAVASCRIPT
    assert "renderSequence !== state.conversationRenderSequence" in JAVASCRIPT
    assert "await enhanceRenderedMarkdown(target);" in JAVASCRIPT
    assert "window.NumericalOJForumMarkdown.enhance(root)" in JAVASCRIPT
    assert 'querySelectorAll("img")' not in MARKDOWN_JAVASCRIPT
    assert ".forum-markdown img {\n  display: block;" in CSS

    assert ".forum-markdown .codehilite .k" in CSS
    assert ".forum-markdown .codehilite .s" in CSS
    assert ".forum-markdown .codehilite .c" in CSS
    assert ".forum-mermaid-diagram > iframe" in CSS
