# -*- coding: utf-8 -*-

"""讨论区正式工作台的静态契约。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PREVIEW = (ROOT / "forum-ui-preview.html").read_text(encoding="utf-8")
TEMPLATE = (ROOT / "templates" / "forum" / "index.html").read_text(
    encoding="utf-8"
)
PROBLEM_TEMPLATE = (ROOT / "templates" / "problems" / "detail.html").read_text(
    encoding="utf-8"
)
CSS = (ROOT / "static" / "app" / "forum.css").read_text(encoding="utf-8")
AGENT_CONVERSATION_CSS = (
    ROOT / "static" / "app" / "agents" / "conversation.css"
).read_text(encoding="utf-8")
MARKDOWN_CSS = (
    ROOT / "static" / "app" / "markdown-rendering.css"
).read_text(encoding="utf-8")
JAVASCRIPT = (ROOT / "static" / "app" / "forum.js").read_text(encoding="utf-8")
IDENTICON_JAVASCRIPT = (
    ROOT / "static" / "app" / "identicon.js"
).read_text(encoding="utf-8")
MARKDOWN_JAVASCRIPT = (
    ROOT / "static" / "app" / "markdown-rendering.js"
).read_text(encoding="utf-8")
SEMANTIC_JAVASCRIPT = (
    ROOT / "static" / "app" / "editor-semantic-tokens.js"
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
MONACO_COMPONENT = (
    ROOT / "templates" / "components" / "editor" / "monaco.html"
).read_text(encoding="utf-8")
PACKAGE = (ROOT / "package.json").read_text(encoding="utf-8")
MERMAID_ASSET_BUILD = (
    ROOT / "scripts" / "build_mermaid.mjs"
).read_text(encoding="utf-8")
CODE_HIGHLIGHTER_ENTRY = (
    ROOT / "frontend" / "markdown" / "code-highlighter.js"
).read_text(encoding="utf-8")
CODE_HIGHLIGHTER_THEME = (
    ROOT / "frontend" / "markdown" / "github-light-theme.js"
).read_text(encoding="utf-8")
CODE_HIGHLIGHTER_BUILD = (
    ROOT / "scripts" / "build_markdown_code_highlighter.mjs"
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


def test_forum_workbench_is_full_bleed_without_the_decorative_page_heading():
    workspace_rules = CSS[
        CSS.index(".forum-workspace {") : CSS.index(".forum-list-pane {")
    ]

    assert "forum-command-bar" not in TEMPLATE
    assert ".forum-command-bar" not in CSS
    assert "COMMUNITY WORKBENCH · GLOBAL" not in TEMPLATE
    assert "<h1>讨论区</h1>" not in TEMPLATE
    assert "forumHeaderCount" not in TEMPLATE
    assert "forumHeaderCount" not in JAVASCRIPT
    assert "updateHeaderCount" not in JAVASCRIPT
    assert ".numoj-content.forum-content-container {\n  padding: 0;" in CSS
    assert "flex: 1 1 auto;" in workspace_rules
    assert "border: 0;" in workspace_rules
    assert "border-radius: 0;" in workspace_rules
    assert "box-shadow: none;" in workspace_rules


def test_forum_preview_reuses_the_real_template_assets_and_component_classes():
    for asset in (
        "./static/bootstrap/bootstrap.min.css",
        "./static/vendor/fontawesome/css/all.min.css",
        "./static/app/layout.css",
        "./static/app/markdown-rendering.css",
        "./static/app/forum.css",
        "./static/app/layout.js",
        "./static/app/editor-semantic-tokens.js",
        "./static/app/markdown-rendering.js",
        "./static/app/forum.js",
    ):
        assert asset in PREVIEW

    assert "<style>" not in PREVIEW
    assert 'class="numoj-site-shell numoj-site-shell-authenticated"' in PREVIEW
    assert 'class="numoj-sidebar d-none d-lg-flex"' in PREVIEW
    assert 'class="forum-workspace"' in PREVIEW
    assert 'data-initial-thread-id="42"' in PREVIEW
    assert "codehilite language-cpp" in PREVIEW
    assert 'url.pathname === "/api/editor/semantic-tokens"' in PREVIEW
    assert 'class="shell"' not in PREVIEW
    assert 'class="sidebar"' not in PREVIEW
    assert "code-head" not in PREVIEW
    assert "code-language" not in PREVIEW
    assert 'class="ln"' not in PREVIEW


def test_reply_composer_matches_the_agent_conversation_input_surface():
    forum_surface_rules = CSS[
        CSS.index(".forum-reply-surface {") : CSS.index(
            ".forum-reply-surface:focus-within {"
        )
    ]
    forum_send_rules = CSS[
        CSS.index(".forum-reply-send {") : CSS.index(
            ".forum-reply-send:hover:not(:disabled) {"
        )
    ]
    agent_send_start = AGENT_CONVERSATION_CSS.index(".agent-resume-send {")
    agent_send_end = AGENT_CONVERSATION_CSS.index(
        ".agent-resume-send.is-queue-mode {"
    )
    agent_send_rules = AGENT_CONVERSATION_CSS[agent_send_start:agent_send_end]

    assert 'class="forum-reply-surface"' in TEMPLATE
    assert 'class="forum-reply-send"' in TEMPLATE
    assert 'aria-label="发送回复"' in TEMPLATE
    assert 'class="fas fa-arrow-up"' in TEMPLATE
    assert (
        '将以\n                <span class="forum-identicon '
        'forum-identicon-xs"'
    ) not in TEMPLATE
    assert "MD / CODE / TEX / MERMAID" not in TEMPLATE
    assert "forum-reply-meta" not in TEMPLATE
    assert "forum-composer-identity" not in TEMPLATE
    assert "forum-format-hint" not in TEMPLATE
    assert "setReplyPostingIdentity" not in JAVASCRIPT
    assert "previewReplyButton" not in TEMPLATE
    assert "previewReplyButton" not in JAVASCRIPT
    assert "replyPreview" not in TEMPLATE
    assert "replyPreview" not in JAVASCRIPT
    assert "width: min(100%, 700px);" in forum_surface_rules
    assert "border-radius: 14px;" in forum_surface_rules
    assert "function resizeReplyInput()" in JAVASCRIPT
    assert "elements.replyInput.scrollHeight" in JAVASCRIPT
    for declaration in (
        "border: 1px solid #252524;",
        "background: #252524;",
        "color: #fff;",
    ):
        assert declaration in forum_send_rules
        assert declaration in agent_send_rules


def test_reply_composer_floats_over_a_scrollable_extended_conversation():
    detail_rules = CSS[
        CSS.index(".forum-detail-pane {") : CSS.index(".forum-detail-header {")
    ]
    conversation_rules = CSS[
        CSS.index(".forum-conversation {") : CSS.index(".forum-load-earlier {")
    ]
    composer_rules = CSS[
        CSS.index(".forum-reply-composer {") : CSS.index(
            ".forum-reply-composer[hidden] {"
        )
    ]
    surface_rules = CSS[
        CSS.index(".forum-reply-surface {") : CSS.index(
            ".forum-reply-surface:focus-within {"
        )
    ]

    assert "--forum-reply-overlay-height: 0px;" in detail_rules
    assert "position: relative;" in detail_rules
    assert "grid-template-rows: auto minmax(0, 1fr);" in detail_rules
    assert "overflow: hidden;" in detail_rules
    assert (
        "padding: 22px 24px calc(32px + "
        "var(--forum-reply-overlay-height));"
    ) in conversation_rules
    for declaration in (
        "position: absolute;",
        "bottom: 0;",
        "background: transparent;",
        "pointer-events: none;",
    ):
        assert declaration in composer_rules
    assert "pointer-events: auto;" in surface_rules
    assert ".forum-reply-surface > .forum-field-error:empty {" in CSS
    assert "display: none;" in CSS[
        CSS.index(".forum-reply-surface > .forum-field-error:empty {") :
        CSS.index(".forum-dialog {")
    ]
    assert "function syncReplyComposerClearance()" in JAVASCRIPT
    assert "function setReplyComposerVisible(visible)" in JAVASCRIPT
    assert "state.replyComposerObserver = new window.ResizeObserver(" in JAVASCRIPT
    assert "state.replyComposerObserver.observe(elements.replyForm);" in JAVASCRIPT


def test_forum_markdown_uses_a_lighter_balanced_reading_font_stack():
    markdown_rules = CSS[
        CSS.index(".forum-markdown {") : CSS.index(
            ".forum-markdown > :first-child {"
        )
    ]

    assert '--forum-reading-sans: "Helvetica Neue", "PingFang SC"' in CSS
    assert "font-family: var(--forum-reading-sans);" in markdown_rules
    assert "font-synthesis: none;" in markdown_rules
    assert "font-weight: 400;" in markdown_rules


def test_forum_titles_balance_latin_and_chinese_stroke_weight():
    thread_title_rules = CSS[
        CSS.index(".forum-thread-title {") : CSS.index(".forum-thread-preview {")
    ]
    detail_title_rules = CSS[
        CSS.index(".forum-detail-header h2 {") : CSS.index(
            ".forum-detail-actions {"
        )
    ]

    assert (
        '--forum-title-sans: "PingFang SC", "Hiragino Sans GB", '
        '"Microsoft YaHei", "Helvetica Neue", sans-serif;'
    ) in CSS
    for rules in (thread_title_rules, detail_title_rules):
        assert "font-family: var(--forum-title-sans);" in rules
        assert "font-synthesis: none;" in rules
        assert "font-weight: 600;" in rules


def test_thread_list_titles_do_not_show_thread_numbers():
    assert 'title.textContent = thread.title;' in JAVASCRIPT
    assert 'class="forum-thread-id"' not in JAVASCRIPT
    assert ".forum-thread-id {" not in CSS


def test_thread_search_does_not_show_a_manual_refresh_button():
    pane_tool_rules = CSS[
        CSS.index(".forum-pane-tools {") : CSS.index(".forum-search {")
    ]
    search_rules = CSS[
        CSS.index(".forum-search {") : CSS.index(".forum-search i {")
    ]

    assert 'id="refreshListButton"' not in TEMPLATE
    assert 'id="refreshListButton"' not in PREVIEW
    assert "refreshListButton" not in JAVASCRIPT
    assert "刷新讨论列表" not in TEMPLATE
    assert "刷新讨论列表" not in PREVIEW
    assert "display: block;" in pane_tool_rules
    assert "display: block;" in search_rules


def test_identity_dialog_omits_the_explanatory_note():
    for source in (TEMPLATE, PREVIEW):
        assert "可使用中文、英文字母、数字、下划线和连字符" not in source
        assert "保存后，本次身份会永久保留在已经发布的内容上" not in source
        assert 'class="forum-identity-note"' not in source
    assert ".forum-identity-note {" not in CSS


def test_identity_refresh_uses_the_edit_action_icon_color():
    identity_refresh_rules = CSS[
        CSS.index(".forum-identity-refresh {") : CSS.index(
            ".forum-identity-refresh:hover {"
        )
    ]
    identity_refresh_hover_rules = CSS[
        CSS.index(".forum-identity-refresh:hover {") : CSS.index(
            ".forum-identity-refresh:disabled {"
        )
    ]
    quiet_button_start = CSS.index(".forum-button-quiet {")
    quiet_button_rules = CSS[
        quiet_button_start : CSS.index(".forum-icon-button {", quiet_button_start)
    ]

    assert "color: var(--forum-ink-3);" in identity_refresh_rules
    assert "color: var(--forum-ink-3);" in quiet_button_rules
    assert "var(--forum-accent-ink)" not in identity_refresh_rules
    assert "var(--forum-accent-soft)" not in identity_refresh_hover_rules


def test_editor_identity_is_compact_and_lives_in_the_dialog_header():
    for source in (TEMPLATE, PREVIEW):
        editor_start = source.index('<dialog class="forum-dialog forum-editor-dialog"')
        header_start = source.index(
            '<header class="forum-dialog-header forum-editor-dialog-header">',
            editor_start,
        )
        identity_start = source.index('id="editorIdentityRow"', header_start)
        header_end = source.index("</header>", header_start)
        body_start = source.index('<div class="forum-dialog-body">', header_end)

        assert header_start < identity_start < header_end < body_start
        assert 'class="forum-identicon forum-identicon-sm" data-posting-avatar' in source
        assert "安全预览" not in source
        assert "MARKDOWN + CODE + LATEX + MERMAID" not in source
        assert "草稿已保存在当前标签页" not in source
        assert "草稿仅保存在当前标签页" not in source
        assert '>预览</button>' in source

    posting_identity_rules = CSS[
        CSS.index(".forum-editor-posting-identity {") : CSS.index(
            ".forum-editor-posting-copy {"
        )
    ]
    assert "grid-template-columns: 32px minmax(0, 1fr);" in posting_identity_rules
    assert ".forum-editor-tabs > span {" not in CSS
    assert '"草稿已保存在当前标签页"' not in JAVASCRIPT
    assert '"草稿仅保存在当前标签页"' not in JAVASCRIPT


def test_editor_textarea_hides_the_native_resize_handle():
    textarea_rules = CSS[
        CSS.index(".forum-field textarea {") : CSS.index(".forum-editor-tabs {")
    ]

    assert "resize: none;" in textarea_rules
    assert "resize: vertical;" not in textarea_rules


def test_editor_placeholders_are_open_ended_and_playful():
    for source in (TEMPLATE, PREVIEW):
        assert 'placeholder="今天讨论点什么呢……？"' in source
        assert 'placeholder="啊哒哒……啊哒哒……啊哒啊哒……喵喵喵喵喵！"' in source
        assert "一句话说明你想讨论的问题" not in source
        assert "补充你的思路、代码，或者已经尝试过的方法" not in source


def test_list_column_is_seventy_percent_of_the_selected_mockup_width():
    assert "0.82fr / 1.18fr" in CSS
    assert "grid-template-columns: minmax(300px, 0.402fr) minmax(0, 1fr);" in CSS
    assert "约 28.7% / 71.3%" in CSS


def test_forum_has_only_the_confirmed_filters_and_no_role_labels():
    assert TEMPLATE.count('data-scope="all"') == 1
    assert TEMPLATE.count('data-scope="mine"') == 1


def test_identity_sits_below_the_thread_list_and_compose_replaces_sort_copy():
    new_thread_rules = CSS[
        CSS.index(".forum-new-thread-button {") : CSS.index(
            ".forum-new-thread-button:hover:not(:disabled) {"
        )
    ]
    anonymous_control_rules = CSS[
        CSS.index(".forum-switch-label {") : CSS.index(
            ".forum-switch-label input {"
        )
    ]

    assert TEMPLATE.index('id="threadList"') < TEMPLATE.index('id="identityControl"')
    assert 'class="forum-list-footer"' in TEMPLATE
    assert "LAST ACTIVE" not in TEMPLATE
    assert "forum-sort-note" not in TEMPLATE
    assert 'class="forum-new-thread-button"' in TEMPLATE
    assert 'id="openComposeButton"' in TEMPLATE
    assert "margin-left: auto;" in new_thread_rules
    assert "font-size: 8.5px;" in new_thread_rules
    assert "font-weight: 620;" in new_thread_rules
    assert "margin-left: auto;" in anonymous_control_rules


def test_forum_scope_filters_use_compact_rounded_rectangles():
    chip_rules = CSS[
        CSS.index(".forum-chip {") : CSS.index(".forum-chip:hover {")
    ]
    quiet_button_start = CSS.index(".forum-button {")
    quiet_button_rules = CSS[
        quiet_button_start : CSS.index(
            ".forum-button:hover:not(:disabled)", quiet_button_start
        )
    ]

    assert "padding: 4px 7px;" in chip_rules
    assert "border-radius: 5px;" in chip_rules
    assert "font-size: 8.5px;" in chip_rules
    assert "font-weight: 620;" in chip_rules
    assert "font-size: 11.5px;" in quiet_button_rules
    assert "font-weight: 700;" in quiet_button_rules
    assert ".forum-page :where(button, input, textarea) {" in CSS
    assert ".forum-page button,\n.forum-page input" not in CSS


def test_thread_uses_the_header_edit_action_without_a_duplicate_post_icon():
    assert 'id="editThreadButton"' in TEMPLATE
    assert 'if (item.is_owner && kind === "reply") {' in JAVASCRIPT
    assert 'edit.dataset.editKind = "reply";' in JAVASCRIPT
    assert 'edit.setAttribute("aria-label", "编辑回复");' in JAVASCRIPT
    assert 'kind === "thread" ? "编辑主题" : "编辑回复"' not in JAVASCRIPT


def test_browser_writes_use_json_apis_without_html_form_fallback():
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
    assert "window.NumojIdenticon" in JAVASCRIPT
    assert "new TextEncoder()" in IDENTICON_JAVASCRIPT
    assert "Math.imul(hash, 0x01000193)" in IDENTICON_JAVASCRIPT
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
    assert ".forum-button-primary {\n" in CSS
    assert ".forum-button-dark {\n" in CSS


def test_share_button_copies_directly_and_uses_the_forum_notice():
    assert 'aria-label="分享讨论"' in TEMPLATE
    assert 'id="forumToastEyebrow"' in TEMPLATE
    assert 'id="forumToastMessage"' in TEMPLATE
    assert "async function writeClipboardText(text)" in JAVASCRIPT
    assert "renderer.copyText(text)" in JAVASCRIPT
    assert 'navigator.clipboard.writeText(value)' in MARKDOWN_JAVASCRIPT
    assert 'document.execCommand("copy")' in MARKDOWN_JAVASCRIPT
    assert "copyText: writeClipboardText" in MARKDOWN_JAVASCRIPT
    assert 'showToast("链接已复制到剪贴板，快去分享吧！", "share")' in JAVASCRIPT
    assert ".forum-toast.is-share .forum-toast-mark" in CSS
    assert '.forum-toast.is-share .forum-toast-mark::before' in CSS


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


def test_rich_markdown_pages_load_the_shared_pinned_resources_explicitly():
    mermaid_asset = ROOT / "static" / "vendor" / "mermaid" / "mermaid.min.js"
    mermaid_license = ROOT / "static" / "vendor" / "mermaid" / "LICENSE"
    code_highlighter_asset = (
        ROOT / "static" / "vendor" / "shiki-markdown" / "highlighter.js"
    )
    code_highlighter_license = (
        ROOT / "static" / "vendor" / "shiki-markdown" / "LICENSE"
    )

    for page_template in (TEMPLATE, PROBLEM_TEMPLATE):
        assert page_template.count("app/markdown-rendering.css") == 1
        assert page_template.count("app/editor-semantic-tokens.js") == 1
        assert page_template.count("vendor/mermaid/mermaid.min.js") == 1
        assert page_template.count("vendor/shiki-markdown/highlighter.js") == 1
        assert page_template.count("app/markdown-rendering.js") == 1
        assert page_template.index(
            "app/editor-semantic-tokens.js"
        ) < page_template.index("app/markdown-rendering.js")
        assert page_template.index(
            "vendor/mermaid/mermaid.min.js"
        ) < page_template.index("app/markdown-rendering.js")
        assert page_template.index(
            "vendor/shiki-markdown/highlighter.js"
        ) < page_template.index("app/markdown-rendering.js")
    assert TEMPLATE.index("app/markdown-rendering.js") < TEMPLATE.index("app/forum.js")
    assert (
        'class="problem-content numoj-markdown '
        'numoj-problem-code-rendering my-3"'
    ) in PROBLEM_TEMPLATE
    assert "data-numoj-markdown" in PROBLEM_TEMPLATE
    assert "app/editor-semantic-tokens.js" in MONACO_COMPONENT
    assert "标准编程题由上方 Monaco 组件加载语义客户端" in PROBLEM_TEMPLATE
    assert (
        "{% if problem.type != 1 "
        "or (problem.programming_grading_mode or 1)|int == 3 %}"
        in PROBLEM_TEMPLATE
    )
    assert '"mermaid": "11.16.0"' in PACKAGE
    assert '"build:mermaid": "node scripts/build_mermaid.mjs"' in PACKAGE
    assert (
        '"build:markdown-highlighter": '
        '"node scripts/build_markdown_code_highlighter.mjs"'
        in PACKAGE
    )
    assert "node_modules/mermaid/dist/mermaid.min.js" in MERMAID_ASSET_BUILD
    assert "frontend/markdown/code-highlighter.js" in CODE_HIGHLIGHTER_BUILD
    assert "node_modules/shiki/LICENSE" in CODE_HIGHLIGHTER_BUILD
    assert "npm run build:frontend" in CI_WORKFLOW
    assert "static/vendor/mermaid" in CI_WORKFLOW
    assert "static/vendor/shiki-markdown" in CI_WORKFLOW
    assert mermaid_asset.stat().st_size > 1_000_000
    assert mermaid_license.is_file()
    assert 900_000 < code_highlighter_asset.stat().st_size < 1_200_000
    assert code_highlighter_license.is_file()


def test_shared_markdown_code_blocks_have_accessible_copy_controls():
    assert 'root.querySelectorAll("pre code")' in MARKDOWN_JAVASCRIPT
    assert "directCopyButton(frame)" in MARKDOWN_JAVASCRIPT
    assert MARKDOWN_JAVASCRIPT.count("ensureCodeCopyButtons(root);") == 2
    assert (
        "container.replaceChildren(status, diagram, sourceDetails);\n"
        "    ensureCodeCopyButtons(container);"
        in MARKDOWN_JAVASCRIPT
    )
    assert (
        'await writeClipboardText(String(code.textContent || ""));'
        in MARKDOWN_JAVASCRIPT
    )
    assert 'icon.className = `numoj-code-copy-icon fas ${' in MARKDOWN_JAVASCRIPT
    assert '"fa-check" : "fa-copy"' in MARKDOWN_JAVASCRIPT
    assert 'announcement.setAttribute("aria-live", "polite");' in MARKDOWN_JAVASCRIPT
    assert "Mermaid 会重组容器并移动源码节点" in MARKDOWN_JAVASCRIPT
    assert 'button.removeAttribute("title");' in MARKDOWN_JAVASCRIPT
    assert ".numoj-code-frame:hover > .numoj-code-copy" in MARKDOWN_CSS
    assert ".numoj-code-frame:focus-within > .numoj-code-copy" in MARKDOWN_CSS
    assert ".numoj-code-copy:focus-visible" in MARKDOWN_CSS
    copy_rule = MARKDOWN_CSS[
        MARKDOWN_CSS.index(".numoj-markdown .numoj-code-copy {") :
        MARKDOWN_CSS.index(
            ".numoj-markdown .numoj-code-frame:hover > .numoj-code-copy"
        )
    ]
    assert "border: 1px solid transparent;" in copy_rule
    assert "background: transparent;" in copy_rule
    assert "box-shadow: none;" in copy_rule
    copy_hover_rule = MARKDOWN_CSS[
        MARKDOWN_CSS.index(".numoj-markdown .numoj-code-copy:hover {") :
        MARKDOWN_CSS.index(".numoj-markdown .numoj-code-copy:focus-visible {")
    ]
    assert "background: #252524;" in copy_hover_rule
    assert "color: #fff;" in copy_hover_rule
    assert "@media (hover: none), (pointer: coarse)" in MARKDOWN_CSS
    assert "@media (prefers-reduced-motion: reduce)" in MARKDOWN_CSS


def test_editor_languages_use_one_csp_safe_github_light_markdown_bundle():
    for contract in (
        'from "shiki/core"',
        'from "shiki/engine/javascript"',
        'from "@shikijs/langs/bash"',
        'from "@shikijs/langs/c"',
        'from "@shikijs/langs/cpp"',
        'from "@shikijs/langs/python"',
        'from "@shikijs/langs/matlab"',
        'from "../lean4-grammar.js"',
        'from "./github-light-theme.js"',
        "let highlighterPromise;",
        "highlighter.codeToTokens",
        "LANGUAGE_ALIASES",
        'theme: "github-light-default"',
    ):
        assert contract in CODE_HIGHLIGHTER_ENTRY

    assert 'from "@shikijs/themes/github-light-default"' in CODE_HIGHLIGHTER_THEME
    assert 'settings: { foreground: "#0550AE" }' in CODE_HIGHLIGHTER_THEME
    assert 'settings: { foreground: "#8250DF" }' in CODE_HIGHLIGHTER_THEME

    for language_class in (
        "language-bash",
        "language-sh",
        "language-shell",
        "language-shellscript",
        "language-zsh",
        "language-ksh",
        "language-openrc",
        "language-c",
        "language-cpp",
        "language-c++",
        "language-cc",
        "language-cxx",
        "language-py",
        "language-py3",
        "language-python",
        "language-python3",
        "language-m",
        "language-matlab",
        "language-octave",
        "language-lean",
        "language-lean4",
    ):
        assert language_class in MARKDOWN_JAVASCRIPT
        assert language_class in MARKDOWN_CSS

    for contract in (
        "BASH_TEXTMATE_MAX_BLOCKS_PER_ROOT",
        "BASH_TEXTMATE_MAX_SOURCE_BYTES",
        "BASH_TEXTMATE_MAX_TOTAL_SOURCE_BYTES_PER_ROOT",
        "STRUCTURED_TEXTMATE_MAX_BLOCKS_PER_ROOT",
        "STRUCTURED_TEXTMATE_MAX_SOURCE_BYTES",
        "STRUCTURED_TEXTMATE_MAX_TOTAL_SOURCE_BYTES_PER_ROOT",
        "window.NumOJMarkdownCodeHighlighter",
        'await client.tokenize(source, "bash")',
        "await client.tokenize(source, language)",
        "shikiTokenFragment(result)",
        'document.createTextNode(content)',
        'block.dataset.numojBashState = "fallback";',
        'block.dataset.numojStructuredTextmateState = "fallback";',
        "已保留 Pygments 着色",
        "SHIKI_GITHUB_LIGHT_COLORS",
        'block.dataset.numojBashState = "skipped-total-size";',
        'block.dataset.numojStructuredTextmateState = "skipped-total-size";',
        "await new Promise((resolve) => window.setTimeout(resolve, 0));",
    ):
        assert contract in MARKDOWN_JAVASCRIPT

    assert "--numoj-code-canvas: #f6f8fa;" in MARKDOWN_CSS
    assert "--numoj-code-ink: #1f2328;" in MARKDOWN_CSS
    assert "--numoj-code-border: #d0d7de;" in MARKDOWN_CSS
    assert "background: var(--numoj-code-canvas);" in MARKDOWN_CSS
    assert ".numoj-shiki-color-0550ae" in MARKDOWN_CSS
    assert ".numoj-shiki-color-8250df" in MARKDOWN_CSS
    assert ".numoj-shiki-color-cf222e" in MARKDOWN_CSS
    assert ".numoj-shiki-token.is-italic" in MARKDOWN_CSS


def test_markdown_cpp_inactive_regions_keep_token_colors_and_only_dim():
    assert "function decodeInactiveRanges(source, regions)" in MARKDOWN_JAVASCRIPT
    assert "function applyInactiveRanges(code, ranges)" in MARKDOWN_JAVASCRIPT
    assert "payload.inactive_regions" in MARKDOWN_JAVASCRIPT
    assert 'span.className = "numoj-clangd-inactive-code";' in (
        MARKDOWN_JAVASCRIPT
    )

    declaration = MARKDOWN_CSS.split(
        ".numoj-markdown .codehilite .numoj-clangd-inactive-code {",
        1,
    )[1].split("}", 1)[0]
    assert "opacity: 0.55;" in declaration


def test_markdown_github_light_keeps_the_backend_semantic_color_layer():
    assert 'context: "markdown"' in MARKDOWN_JAVASCRIPT
    assert "await client.requestTokens({" in MARKDOWN_JAVASCRIPT
    assert "applySemanticRanges(code, ranges);" in MARKDOWN_JAVASCRIPT

    semantic_theme = MARKDOWN_CSS.split(
        "C/C++、Python、MATLAB/Octave 的语言服务语义层使用 GitHub Light",
        1,
    )[1].split(
        ".numoj-markdown .codehilite .numoj-clangd-inactive-code {",
        1,
    )[0]
    for token_class in (
        "numoj-semantic-class",
        "numoj-semantic-method",
        "numoj-semantic-variable",
        "numoj-semantic-keyword",
        "numoj-semantic-comment",
    ):
        assert token_class in semantic_theme
    for color in ("#0550ae", "#8250df", "#953800", "#cf222e", "#6e7781"):
        assert f"color: {color};" in semantic_theme


def test_shared_markdown_renderer_is_safe_idempotent_and_handles_dynamic_html():
    for contract in (
        'securityLevel: "sandbox"',
        "startOnLoad: false",
        "maxTextSize: MERMAID_MAX_TEXT_SIZE",
        "maxEdges: MERMAID_MAX_EDGES",
        "suppressErrorRendering: true",
        'const source = String(code.textContent || "");',
        "await renderer.parse(source, { suppressErrors: true });",
        "await renderer.run({ nodes: [diagram] });",
        "container.dataset.numojMermaidGeneration !== generation",
        'block.dataset.numojMermaidState = "queued";',
        'context: "markdown"',
        "STRUCTURED_SEMANTIC_MAX_INFLIGHT_PER_PAGE = 2",
        "STRUCTURED_SEMANTIC_MAX_SOURCE_BYTES",
        "STRUCTURED_SEMANTIC_MAX_TOKENS_PER_BLOCK",
        "scheduleSemanticTask(",
        "semanticController.abort();",
        "const enhancementGenerations = new WeakMap();",
        "const structuredTextMateTasks = new WeakMap();",
        "invalidateEnhancement(root);",
        "sharedStructuredTextMateTask(root)",
        "enhancementIsCurrent(root, enhancementGeneration)",
        "root.contains(block)",
        'String(code.textContent || "") === source',
        'block.dataset.numojSemanticState = "queued";',
        "applySemanticRanges(code, ranges);",
        "await structuredHighlighting;",
        "renderStructuredSemanticHighlights(root)",
        "await typesetMath(root, enhancementGeneration);",
        "mathJax.typesetClear([root]);",
        'root.matches("[data-numoj-markdown]")',
        'root.querySelectorAll("[data-numoj-markdown]")',
        "window.NumericalOJMarkdownRenderer = Object.freeze({",
    ):
        assert contract in MARKDOWN_JAVASCRIPT

    assert MARKDOWN_JAVASCRIPT.index(
        "    await structuredHighlighting;"
    ) < MARKDOWN_JAVASCRIPT.index(
        "    renderStructuredSemanticHighlights(root).catch"
    )
    assert "enhanceRenderedMarkdown(elements.conversation)" in JAVASCRIPT
    assert ".then(settleScrollPosition)" in JAVASCRIPT
    assert "renderSequence !== state.conversationRenderSequence" in JAVASCRIPT
    assert "await enhanceRenderedMarkdown(target);" in JAVASCRIPT
    assert "window.NumericalOJMarkdownRenderer.enhance(root)" in JAVASCRIPT
    assert "window.NumericalOJMarkdownRenderer.clear(root)" in JAVASCRIPT
    assert ".forum-markdown img {\n  display: block;" in CSS

    assert ".numoj-markdown .codehilite .k" in MARKDOWN_CSS
    assert ".numoj-markdown .codehilite .s" in MARKDOWN_CSS
    assert ".numoj-markdown .codehilite .c" in MARKDOWN_CSS
    assert ".numoj-semantic-token.numoj-semantic-class" in MARKDOWN_CSS
    assert ".numoj-semantic-token.numoj-semantic-method" in MARKDOWN_CSS
    assert ".numoj-semantic-token.numoj-semantic-variable" in MARKDOWN_CSS
    assert ".numoj-mermaid-diagram > iframe" in MARKDOWN_CSS


def test_shared_semantic_client_supports_editor_and_markdown_callers():
    for contract in (
        "async function getLegend(language, options)",
        "async function requestTokens(options)",
        "MARKDOWN_LANGUAGE_ALIASES",
        'context === "markdown" && markdownLanguage',
        "body.language = markdownLanguage",
        "body.context = context",
        "body.problem_id = problemId",
        "signal: settings.signal",
        "getLegend: getLegend",
        "requestTokens: requestTokens",
        "register: register",
    ):
        assert contract in SEMANTIC_JAVASCRIPT
