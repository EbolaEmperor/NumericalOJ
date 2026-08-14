# -*- coding: utf-8 -*-

"""讨论区正式工作台的静态契约。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (ROOT / "templates" / "forum" / "index.html").read_text(
    encoding="utf-8"
)
PROBLEM_TEMPLATE = (ROOT / "templates" / "problems" / "detail.html").read_text(
    encoding="utf-8"
)
CSS = (ROOT / "static" / "app" / "forum.css").read_text(encoding="utf-8")
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


def test_forum_scope_filters_use_compact_rounded_rectangles():
    chip_rules = CSS[
        CSS.index(".forum-chip {") : CSS.index(".forum-chip:hover {")
    ]

    assert "padding: 5px 8px;" in chip_rules
    assert "border-radius: 5px;" in chip_rules
    assert "font-size: 9.5px;" in chip_rules
    assert "border-radius: 999px;" not in chip_rules


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
    assert ".forum-page button {\n  color: inherit;" not in CSS
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
    assert "window.prompt(" not in JAVASCRIPT
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
    assert "vendor/mermaid" not in BASE_LAYOUT
    assert "vendor/shiki-markdown" not in BASE_LAYOUT
    assert "app/editor-semantic-tokens.js" not in BASE_LAYOUT
    assert "app/markdown-rendering.js" not in BASE_LAYOUT
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
    assert ".numoj-code-frame:hover > .numoj-code-copy" in MARKDOWN_CSS
    assert ".numoj-code-frame:focus-within > .numoj-code-copy" in MARKDOWN_CSS
    assert ".numoj-code-copy:focus-visible" in MARKDOWN_CSS
    assert "@media (hover: none), (pointer: coarse)" in MARKDOWN_CSS
    assert "@media (prefers-reduced-motion: reduce)" in MARKDOWN_CSS


def test_editor_languages_use_one_csp_safe_dark_plus_bundle():
    for contract in (
        'from "shiki/core"',
        'from "shiki/engine/javascript"',
        'from "@shikijs/langs/bash"',
        'from "@shikijs/langs/c"',
        'from "@shikijs/langs/cpp"',
        'from "@shikijs/langs/python"',
        'from "@shikijs/langs/matlab"',
        'from "../lean4-grammar.js"',
        'from "@shikijs/themes/dark-plus"',
        "let highlighterPromise;",
        "highlighter.codeToTokens",
        "LANGUAGE_ALIASES",
    ):
        assert contract in CODE_HIGHLIGHTER_ENTRY

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
        "SHIKI_DARK_PLUS_COLORS",
        'block.dataset.numojBashState = "skipped-total-size";',
        'block.dataset.numojStructuredTextmateState = "skipped-total-size";',
        "await new Promise((resolve) => window.setTimeout(resolve, 0));",
    ):
        assert contract in MARKDOWN_JAVASCRIPT

    target_canvas = MARKDOWN_CSS.split(
        "编辑器支持的文章语言",
        1,
    )[1].split(".numoj-markdown .numoj-code-frame", 1)[0]
    assert "background: #1e1e1e;" in target_canvas
    assert "color: #d4d4d4;" in target_canvas
    assert "language-json" not in target_canvas
    assert "language-js" not in target_canvas
    assert "background: #0d1117;" in MARKDOWN_CSS
    assert "span.style.color" not in MARKDOWN_JAVASCRIPT
    assert ".numoj-shiki-color-dcdcaa" in MARKDOWN_CSS
    assert ".numoj-shiki-color-9cdcfe" in MARKDOWN_CSS
    assert ".numoj-shiki-color-c586c0" in MARKDOWN_CSS
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
    assert "color:" not in declaration


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
    assert 'querySelectorAll("img")' not in MARKDOWN_JAVASCRIPT
    assert ".forum-markdown img {\n  display: block;" in CSS

    assert ".numoj-markdown .codehilite .k" in MARKDOWN_CSS
    assert ".numoj-markdown .codehilite .s" in MARKDOWN_CSS
    assert ".numoj-markdown .codehilite .c" in MARKDOWN_CSS
    assert ".numoj-semantic-token.numoj-semantic-class" in MARKDOWN_CSS
    assert ".numoj-semantic-token.numoj-semantic-method" in MARKDOWN_CSS
    assert ".numoj-semantic-token.numoj-semantic-variable" in MARKDOWN_CSS
    assert ".numoj-mermaid-diagram > iframe" in MARKDOWN_CSS
    assert "Pygments 2.20 class theme" not in CSS
    assert ".forum-mermaid" not in CSS


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

    assert "problemId" not in MARKDOWN_JAVASCRIPT
    assert "#include <bits/stdc++.h>" not in MARKDOWN_JAVASCRIPT
