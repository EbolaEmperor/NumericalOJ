"""无需浏览器状态的前端静态 JavaScript 契约。"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
JAVASCRIPT_ASSETS = (
    "frontend/markdown/code-highlighter.js",
    "frontend/markdown/github-light-theme.js",
    "frontend/lean4-grammar.js",
    "frontend/lean4-theme.js",
    "frontend/lean4-unicode-input.js",
    "static/app/code-editor-runtime.js",
    "static/app/editor-semantic-tokens.js",
    "static/app/lean-workbench.js",
    "static/app/markdown-rendering.js",
    "static/app/model-family.js",
    "static/app/rich-content-assets.js",
    "static/app/ranking/topology.js",
)


def test_frontend_node_runtime_is_pinned_consistently():
    expected = (ROOT / ".node-version").read_text().strip()
    package = json.loads((ROOT / "frontend" / "package.json").read_text())
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text())
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    assert expected == "22.23.2"
    assert package["engines"]["node"] == expected
    assert package["volta"]["node"] == expected
    assert lock["packages"][""]["engines"]["node"] == expected
    assert workflow.count("node-version: '22.23.2'") == 2


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
@pytest.mark.parametrize("relative_path", JAVASCRIPT_ASSETS)
def test_frontend_javascript_has_valid_syntax(relative_path):
    path = Path(relative_path)
    if path.parts[0] == "static":
        path = Path("frontend/public") / path
    subprocess.run(
        [NODE, "--check", str(ROOT / path)],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_lazy_rich_assets_skip_plain_content_and_fail_open():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "rich-content-assets.js"
    script = f"""
global.window = global;
global.Node = {{TEXT_NODE: 3}};
global.NodeFilter = {{SHOW_TEXT: 4}};
const appended = [];
function scriptElement() {{
  const listeners = Object.create(null);
  return {{
    dataset: {{}},
    addEventListener: function(name, callback) {{ listeners[name] = callback; }},
    fire: function(name) {{ listeners[name](); }}
  }};
}}
global.document = {{
  currentScript: {{dataset: {{
    highlighterSrc: "/highlighter.js",
    mathjaxSrc: "/mathjax.js",
    mermaidSrc: "/mermaid.js",
    semanticTokensSrc: "/semantic-tokens.js"
  }}}},
  createTreeWalker: function(root) {{
    let index = 0;
    return {{
      nextNode: function() {{ return (root._nodes || [])[index++] || null; }}
    }};
  }},
  createElement: function() {{ return scriptElement(); }},
  head: {{appendChild: function(script) {{ appended.push(script); }}}}
}};
function textNode(value) {{
  return {{
    data: value,
    parentElement: {{closest: function() {{ return null; }}}}
  }};
}}
function root(value, selectorNeedle) {{
  return {{
    nodeType: 1,
    _nodes: value ? [textNode(value)] : [],
    matches: function() {{ return false; }},
    querySelector: function(selector) {{
      return selectorNeedle && selector.includes(selectorNeedle) ? {{}} : null;
    }}
  }};
}}
require({str(asset)!r});
(async function() {{
  const plain = root("题目正文没有公式和结构化代码", "");
  const skipped = await Promise.all([
    NumOJRichContentAssets.ensureMathJax(plain),
    NumOJRichContentAssets.ensureMermaid(plain),
    NumOJRichContentAssets.ensureCodeAssets(plain)
  ]);
  if (skipped.some(Boolean) || appended.length !== 0) process.exit(1);

  const mermaid = NumOJRichContentAssets.ensureMermaid(
    root("graph TD", "language-mermaid")
  );
  if (appended.length !== 1 || appended[0].dataset.numojRichAsset !== "mermaid") {{
    process.exit(2);
  }}
  appended[0].fire("error");
  if (await mermaid) process.exit(3);

  const structured = NumOJRichContentAssets.ensureCodeAssets(
    root("int main() {{}}", "language-cpp")
  );
  if (
    appended.length !== 3
    || appended[1].dataset.numojRichAsset !== "highlighter"
    || appended[2].dataset.numojRichAsset !== "semanticTokens"
  ) process.exit(4);
  appended[1].fire("error");
  appended[2].fire("error");
  if (await structured) process.exit(5);

  const math = NumOJRichContentAssets.ensureMathJax(root("公式 $x + 1$", ""));
  if (appended.length !== 4 || appended[3].dataset.numojRichAsset !== "mathjax") {{
    process.exit(6);
  }}
  appended[3].fire("error");
  if (await math) process.exit(7);
}})().catch(function(error) {{
  console.error(error);
  process.exit(8);
}});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_lazy_mathjax_waits_for_startup_before_typesetting():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "markdown-rendering.js"
    script = f"""
global.window = global;
global.document = {{
  readyState: "loading",
  addEventListener: function() {{}}
}};
let releaseStartup = null;
let typesetCalls = 0;
let typesetTarget = null;
global.MathJax = {{
  startup: {{promise: new Promise(function(resolve) {{ releaseStartup = resolve; }})}},
  typesetPromise: async function(targets) {{
    typesetCalls += 1;
    typesetTarget = targets[0];
  }}
}};
global.NumOJRichContentAssets = {{
  ensureCodeAssets: function() {{ return Promise.resolve(false); }},
  ensureMathJax: function() {{ return Promise.resolve(true); }},
  ensureMermaid: function() {{ return Promise.resolve(false); }}
}};
const root = {{
  isConnected: true,
  contains: function() {{ return true; }},
  matches: function() {{ return false; }},
  querySelectorAll: function() {{ return []; }}
}};
require({str(asset)!r});
(async function() {{
  const enhancement = NumericalOJMarkdownRenderer.enhance(root);
  await new Promise(function(resolve) {{ setImmediate(resolve); }});
  if (typesetCalls !== 0) process.exit(1);
  releaseStartup();
  await enhancement;
  if (typesetCalls !== 1 || typesetTarget !== root) process.exit(2);
}})().catch(function(error) {{
  console.error(error);
  process.exit(3);
}});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


def test_lazy_rich_asset_failures_preserve_renderer_fallbacks():
    source = (ROOT / "frontend" / "public" / "static" / "app" / "markdown-rendering.js").read_text()

    # 资源加载器以 false 结算时仍执行增强流程；缺少 Shiki 客户端会保留
    # 服务端生成的 Pygments DOM，Mermaid 则展开并保留原始源码。
    assert "const mermaidRendering = mermaidAssetReady.then(" in source
    assert "() => renderMermaidDiagrams(root)," in source
    assert 'block.dataset.numojBashState = "fallback";' in source
    assert 'block.dataset.numojStructuredTextmateState = "fallback";' in source
    assert "diagram.remove();" in source
    assert "sourceDetails.open = true;" in source
    assert 'container.dataset.numojMermaidState = "error";' in source


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_markdown_highlighter_bundle_uses_github_light_for_rich_languages():
    asset = ROOT / "frontend" / "public" / "static" / "vendor" / "shiki-markdown" / "highlighter.js"
    script = f"""
const fs = require("fs");
const vm = require("vm");
vm.runInThisContext(fs.readFileSync({str(asset)!r}, "utf8"));
(async function() {{
  const samples = [
    ["bash", 'curl -fsSL "$URL"', ["#953800", "#0550AE", "#0A3069"]],
    ["c", "struct Widget {{ int value; }};", ["#CF222E", "#1F2328"]],
    ["cpp", "std::vector<int> values;", ["#953800", "#CF222E"]],
    [
      "python",
      "def solve(value: int) -> int:\\n    return value + 1",
      ["#CF222E", "#8250DF", "#0550AE", "#1F2328"],
    ],
    [
      "matlab",
      "function y = solve(x)\\n  y = zeros(size(x));\\nend",
      ["#CF222E", "#8250DF", "#953800", "#1F2328"],
    ],
    ["octave", "function y = solve(x)\\n  y = x;\\nend", ["#CF222E"]],
    [
      "lean4",
      "theorem answer (n : Nat) : n + 0 = n := by\\n  simpa -- done\\n\\nsorry",
      [
        "#CF222E", "#8250DF", "#953800", "#0550AE", "#1F2328",
        "#6E7781", "#82071E",
      ],
    ],
  ];
  for (const sample of samples) {{
    const language = sample[0];
    const source = sample[1];
    const expectedColors = sample[2];
    const result = await NumOJMarkdownCodeHighlighter.tokenize(
      source,
      language,
    );
    const tokens = result.tokens.flat();
    const rebuilt = result.tokens
      .map(function(line) {{ return line.map(function(token) {{
        return token.content;
      }}).join(""); }})
      .join("\\n");
    if (rebuilt !== source) process.exit(1);
    const colors = new Set(tokens.map(function(token) {{
      return String(token.color).toUpperCase();
    }}));
    for (const color of expectedColors) {{
      if (!colors.has(color)) process.exit(2);
    }}
  }}
}})().catch(function() {{ process.exit(3); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_lean4_monarch_fallback_enables_unicode_identifiers():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "code-editor-runtime.js"
    script = f"""
global.window = global;
let leanDefinition = null;
const monaco = {{
  languages: {{
    getLanguages: function() {{ return []; }},
    register: function() {{}},
    setLanguageConfiguration: function() {{}},
    setMonarchTokensProvider: function(language, definition) {{
      if (language === "lean4") leanDefinition = definition;
    }}
  }}
}};
require({str(asset)!r});
NumOJCodeEditorRuntime.registerLean4(monaco);
if (!leanDefinition || leanDefinition.unicode !== true) process.exit(1);
if (!leanDefinition.keywords.includes("theorem")) process.exit(2);
if (!leanDefinition.tacticKeywords.includes("simpa")) process.exit(3);
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_lean4_uses_official_unicode_abbreviations():
    asset = ROOT / "frontend" / "lean4-unicode-input.js"
    script = f"""
const {{ pathToFileURL }} = require("url");
(async function() {{
  const input = await import(pathToFileURL({str(asset)!r}).href);
  const symbols = input.getLean4UnicodeAbbreviations();
  if (symbols.alpha !== "α") process.exit(1);
  if (symbols.forall !== "∀") process.exit(2);
  if (symbols["<>"] !== "⟨$CURSOR⟩") process.exit(3);
  if (Object.keys(symbols).length < 1_800) process.exit(4);
}})().catch(function() {{ process.exit(5); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_lean4_semantic_token_bridge_tracks_monaco_model_version():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "lean-workbench.js"
    script = f"""
global.window = global;
require({str(asset)!r});
let version = 3;
let provider = null;
let registrationDisposed = false;
const model = {{getVersionId: function() {{ return version; }}}};
const monaco = {{
  languages: {{
    registerDocumentSemanticTokensProvider: function(language, value) {{
      if (language !== "lean4") process.exit(1);
      provider = value;
      return {{dispose: function() {{ registrationDisposed = true; }}}};
    }}
  }}
}};
const bridge = NumOJLeanWorkbench.createSemanticTokenBridge(monaco, model);
if (bridge.accept(3, null)) process.exit(21);
const first = {{
  legend: {{
    tokenTypes: ["keyword", "function", "leanSorryLike"],
    tokenModifiers: ["declaration"]
  }},
  data: [0, 0, 7, 0, 0, 0, 8, 6, 1, 1],
  result_id: "1:abc"
}};
if (!bridge.accept(3, first) || !provider) process.exit(2);
if (provider.getLegend().tokenTypes[1] !== "lean4.function") process.exit(3);
let refreshes = 0;
provider.onDidChange(function() {{ refreshes += 1; }});
let result = provider.provideDocumentSemanticTokens(model, null, {{
  isCancellationRequested: false
}});
if (!(result.data instanceof Uint32Array) || result.data[8] !== 1) process.exit(4);
const firstProviderResultId = result.resultId;
bridge.accept(3, first);
if (refreshes !== 0) process.exit(5);
version = 4;
bridge.invalidate();
if (refreshes !== 0) process.exit(6);
let busy = false;
try {{
  provider.provideDocumentSemanticTokens(model, null, {{
    isCancellationRequested: false
  }});
}} catch (error) {{
  busy = String(error && error.message || "").includes("busy");
}}
if (!busy) process.exit(7);
if (bridge.accept(3, first)) process.exit(8);
const second = {{
  ...first,
  data: [0, 0, 7, 0, 0, 0, 8, 9, 1, 1],
  result_id: "2:def"
}};
if (!bridge.accept(4, second)) process.exit(9);
if (refreshes !== 1) process.exit(10);
result = provider.provideDocumentSemanticTokens(model, firstProviderResultId, {{
  isCancellationRequested: false
}});
if (
  !Array.isArray(result.edits) ||
  result.edits.length !== 1 ||
  result.edits[0].start !== 7 ||
  result.edits[0].deleteCount !== 1 ||
  !(result.edits[0].data instanceof Uint32Array) ||
  result.edits[0].data[0] !== 9
) process.exit(13);
const secondProviderResultId = result.resultId;
version = 5;
bridge.invalidate();
if (bridge.getResultId() !== "2:def") process.exit(14);
if (!bridge.accept(5, {{
  previous_result_id: "2:def",
  result_id: "3:ghi",
  edits: [{{start: 7, deleteCount: 1, data: [10]}}]
}})) process.exit(15);
result = provider.provideDocumentSemanticTokens(model, secondProviderResultId, {{
  isCancellationRequested: false
}});
if (
  result.edits.length !== 1 ||
  result.edits[0].start !== 7 ||
  result.edits[0].deleteCount !== 1 ||
  result.edits[0].data[0] !== 10
) process.exit(16);
const thirdProviderResultId = result.resultId;
version = 6;
bridge.invalidate();
if (!bridge.accept(6, null)) process.exit(17);
result = provider.provideDocumentSemanticTokens(model, thirdProviderResultId, {{
  isCancellationRequested: false
}});
if (!Array.isArray(result.edits) || result.edits.length !== 0) process.exit(18);
provider.releaseDocumentSemanticTokens(result.resultId);
result = provider.provideDocumentSemanticTokens(model, result.resultId, {{
  isCancellationRequested: false
}});
if (!(result.data instanceof Uint32Array) || result.data[7] !== 10) process.exit(20);
version = 7;
bridge.invalidate();
if (bridge.accept(7, {{
  previous_result_id: "wrong-result",
  result_id: "4:jkl",
  edits: []
}})) process.exit(19);
if (provider.provideDocumentSemanticTokens(model, null, {{
  isCancellationRequested: true
}}) !== null) process.exit(11);
bridge.dispose();
if (!registrationDisposed) process.exit(12);
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


def test_lean4_workbench_separates_source_and_cursor_requests():
    source = (
        ROOT / "frontend" / "public" / "static" / "app" / "lean-workbench.js"
    ).read_text()

    assert 'request_kind: kind' in source
    assert 'client_session_id: clientSessionId' in source
    assert 'requestPayload.files = writableFiles();' in source
    assert 'requestPayload.source_state_id = sourceStateId;' in source
    assert 'requestPayload.document_version = requestedState.documentVersion;' in source
    assert 'known_semantic_result_id:' in source
    assert 'payload.code === "resync_required"' in source
    assert 'inFlightRequestFingerprint' in source
    assert 'lastCompletedRequestFingerprints[kind]' in source
    assert 'lastCompletedRequestFingerprints.cursor = requestFingerprint(' in source
    assert 'lastCompletedRequestFingerprints.source = "";' in source
    assert 'checkDocument("source")' in source
    assert 'checkDocument("cursor")' in source
    assert 'kind === "source" && payload.diagnostics !== null' in source


def test_lean4_lexical_and_semantic_themes_use_the_same_core_colors():
    lexical_theme = (ROOT / "frontend" / "lean4-theme.js").read_text()
    semantic_theme = (ROOT / "frontend" / "monaco" / "runtime.js").read_text()

    assert '"keyword.other.lean4"' in lexical_theme
    assert '"storage.modifier.lean4"' in lexical_theme
    assert 'settings: { foreground: "#C586C0" }' in lexical_theme
    assert '{ token: "lean4.keyword", foreground: "C586C0" }' in semantic_theme
    assert '{ token: "lean4.modifier", foreground: "C586C0" }' in semantic_theme
    assert '{ token: "lean4.operator", foreground: "D7BA7D" }' in semantic_theme
    assert '{ token: "lean4.function", foreground: "DCDCAA" }' in semantic_theme


def test_oj_monaco_bundle_keeps_only_supported_languages_and_a_size_budget():
    minimal_entry = (
        ROOT / "frontend" / "monaco" / "editor-minimal.js"
    ).read_text()
    full_entry = (ROOT / "frontend" / "monaco" / "editor.js").read_text()
    runtime = (ROOT / "frontend" / "monaco" / "runtime.js").read_text()
    build_script = (ROOT / "frontend" / "scripts" / "build_monaco.mjs").read_text()
    component = (
        ROOT / "frontend" / "src" / "components" / "MonacoEditor.tsx"
    ).read_text()

    assert "/static/vendor/monaco/editor-minimal.css" in component
    assert "/static/vendor/monaco/editor-minimal.js" in component

    for language in ("c", "cpp", "python", "matlab"):
        assert f'from "@shikijs/langs/{language}"' in minimal_entry
    assert 'from "../lean4-grammar.js"' in minimal_entry
    assert (
        "configureTextMateLanguages([c, cpp, python, matlab, lean4])"
        in minimal_entry
    )
    assert 'definitions/cpp/register.js"' in minimal_entry
    assert 'definitions/python/register.js"' in minimal_entry
    for language in ("java", "javascript", "rust", "typescript"):
        assert f'from "@shikijs/langs/{language}"' not in minimal_entry
        assert f'from "@shikijs/langs/{language}"' in full_entry

    assert 'monaco-editor/editor/editor.api.js' in minimal_entry
    assert 'monaco-editor/editor/editor.main.js' not in minimal_entry
    assert 'semanticTokens/browser/documentSemanticTokens.js' in minimal_entry
    assert 'semanticTokens/browser/viewportSemanticTokens.js' in minimal_entry
    assert "attachLean4UnicodeInput" in runtime
    assert "getLean4UnicodeAbbreviations" in runtime
    assert '["monaco/editor.js", "editor"]' in build_script
    assert (
        '["monaco/editor-minimal.js", "editor-minimal"]'
        in build_script
    )

    full_asset = ROOT / "frontend" / "public" / "static" / "vendor" / "monaco" / "editor.js"
    minimal_asset = (
        ROOT / "frontend" / "public" / "static" / "vendor" / "monaco" / "editor-minimal.js"
    )
    assert minimal_asset.stat().st_size < full_asset.stat().st_size * 0.60
    built_minimal = minimal_asset.read_text()
    for symbol in (
        "attachLean4UnicodeInput",
        "getLean4UnicodeAbbreviations",
        "prepareTextMateHighlighting",
        "registerDocumentSemanticTokensProvider",
        "dark-plus",
        "4EC9B0",
        "DCDCAA",
    ):
        assert symbol in built_minimal


def test_monaco_distribution_carries_the_upstream_license():
    build_script = (ROOT / "frontend" / "scripts" / "build_monaco.mjs").read_text()
    license_asset = ROOT / "frontend" / "public" / "static" / "vendor" / "monaco" / "LICENSE"

    assert '"node_modules/monaco-editor/LICENSE"' in build_script
    assert '`${outputDirectory}/LICENSE`' in build_script
    license_text = license_asset.read_text()
    assert "The MIT License (MIT)" in license_text
    assert "Copyright (c) 2016 - present Microsoft Corporation" in license_text
    assert "The above copyright notice and this permission notice" in license_text

    notices_asset = (
        ROOT / "frontend" / "public" / "static" / "vendor" / "monaco" / "ThirdPartyNotices.txt"
    )
    assert '"node_modules/monaco-editor/ThirdPartyNotices.txt"' in build_script
    assert '`${outputDirectory}/ThirdPartyNotices.txt`' in build_script
    notices_text = notices_asset.read_text()
    assert "THIRD-PARTY SOFTWARE NOTICES AND INFORMATION" in notices_text
    assert "nodejs path library" in notices_text
    assert "END OF vscode-swift NOTICES AND INFORMATION" in notices_text


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_lean4_markdown_highlighter_uses_structural_scopes():
    asset = ROOT / "frontend" / "public" / "static" / "vendor" / "shiki-markdown" / "highlighter.js"
    script = f"""
const fs = require("fs");
const vm = require("vm");
vm.runInThisContext(fs.readFileSync({str(asset)!r}, "utf8"));
(async function() {{
  const source = [
    "/-! Fibonacci docs -/",
    "import Mathlib",
    "namespace Mathlib.Data.Nat",
    "structure {{u}} Box where",
    "structure Point where",
    "  x : Nat",
    "  y : ℕ",
    "theorem fib_add (n : Nat) : Nat.fib n = Nat.fib n := by",
    "  simpa <;> first | rfl | exact n - 1 × 2 ^ 3 % 2",
    "#check Mathlib.Data.Nat.Basic",
    "· exact n",
    "sorry"
  ].join("\\n");
  const result = await NumOJMarkdownCodeHighlighter.tokenize(source, "lean4");
  const tokens = result.tokens.flat();
  function has(content, color, style) {{
    return tokens.some(function(token) {{
      return token.content === content &&
        String(token.color).toUpperCase() === color &&
        Number(token.fontStyle || 0) === style;
    }});
  }}
  if (!has("/-! Fibonacci docs -/", "#6E7781", 1)) process.exit(1);
  if (!has("Point", "#0550AE", 2)) process.exit(2);
  if (!has("Box", "#0550AE", 2)) process.exit(11);
  if (!has("Mathlib.Data.Nat", "#0550AE", 2)) process.exit(12);
  if (!has("Mathlib.Data.Nat.Basic", "#0550AE", 0)) process.exit(13);
  if (!has("x", "#953800", 0) || !has("n", "#953800", 0)) process.exit(3);
  if (!has("Nat", "#0550AE", 0) || !has("ℕ", "#0550AE", 0)) process.exit(4);
  if (!has("Nat.", "#0550AE", 0) || !has("fib", "#8250DF", 0)) process.exit(5);
  if (!has("fib_add", "#8250DF", 2)) process.exit(6);
  if (!has("by", "#CF222E", 0) || !has("simpa", "#CF222E", 0)) process.exit(7);
  if (!has("import", "#CF222E", 0) || !has("namespace", "#CF222E", 0)) process.exit(16);
  if (!has("=", "#0550AE", 0)) process.exit(8);
  for (const operator of ["<;>", "-", "×", "^", "%", "·"]) {{
    if (!has(operator, "#0550AE", 0)) process.exit(14);
  }}
  if (!has("sorry", "#82071E", 4)) process.exit(9);
}})().catch(function() {{ process.exit(15); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_rule_topology_factory_is_deterministic_and_rejects_cycles():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "ranking" / "topology.js"
    script = f"""
global.window = global;
require({str(asset)!r});
const topology = RuleTopology.create({{
  nodeWidth: 168,
  nodeHeight: 100,
  marginX: 24,
  marginY: 20,
  columnGap: 88,
  rowGap: 80,
  slotPadding: 42,
  maxSlotStep: 17
}});
const rules = [
  {{rule_id: 1, dependencies: []}},
  {{rule_id: 2, dependencies: [1]}},
  {{rule_id: 3, dependencies: [1]}}
];
const layout = topology.layout(rules);
if (!layout || layout.width !== 472 || layout.height !== 320) process.exit(1);
if (layout.positions[1].x !== 24 || layout.positions[1].y !== 20) process.exit(2);
if (layout.positions[2].y !== 200 || layout.positions[3].y !== 200) process.exit(3);
const routes = topology.buildRoutes([{{from: 1, to: 2}}, {{from: 1, to: 3}}], layout);
for (const key of ['1:2', '1:3']) {{
  if (!routes[key] || !topology.edgePath(routes[key]).startsWith('M ')) process.exit(4);
}}
const cycle = topology.layout([
  {{rule_id: 1, dependencies: [2]}},
  {{rule_id: 2, dependencies: [1]}}
]);
if (cycle !== null) process.exit(5);
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_semantic_token_client_separates_editor_and_markdown_payloads():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "editor-semantic-tokens.js"
    script = f"""
global.window = global;
const calls = [];
global.fetch = async function(url, options) {{
  calls.push({{url, options: options || {{}}}});
  if (String(url).includes("semantic-token-legend")) {{
    return {{
      ok: true,
      json: async function() {{
        return {{
          success: true,
          legend: {{tokenTypes: ["class"], tokenModifiers: []}}
        }};
      }}
    }};
  }}
  return {{
    ok: true,
    json: async function() {{
      return {{success: true, data: [0, 0, 3, 0, 0], result_id: "1:test"}};
    }}
  }};
}};
require({str(asset)!r});
(async function() {{
  await NumOJSemanticTokens.getLegend("cpp");
  await NumOJSemanticTokens.requestTokens({{
    context: "markdown",
    language: "cpp",
    source: "std::vector<std::string> values;"
  }});
  await NumOJSemanticTokens.requestTokens({{
    context: "markdown",
    language: "c",
    source: "int value;"
  }});
  await NumOJSemanticTokens.requestTokens({{
    context: "markdown",
    language: "python",
    source: "value: int = 1"
  }});
  await NumOJSemanticTokens.requestTokens({{
    context: "markdown",
    language: "octave",
    source: "value = 1;"
  }});
  await NumOJSemanticTokens.requestTokens({{
    problemId: 42,
    language: "cpp",
    source: "int main() {{}}"
  }});
  await NumOJSemanticTokens.requestTokens({{
    context: "repository",
    repositoryEntryId: 42,
    language: "cpp",
    source: "int repository_value;"
  }});
  const requests = calls
    .filter(function(call) {{ return call.options.method === "POST"; }})
    .map(function(call) {{ return JSON.parse(call.options.body); }});
  if (requests.length !== 6) process.exit(1);
  if (
    requests[0].context !== "markdown" ||
    requests[0].source !== "std::vector<std::string> values;"
  ) process.exit(2);
  if (Object.prototype.hasOwnProperty.call(requests[0], "problem_id")) {{
    process.exit(3);
  }}
  if (
    requests[1].context !== "markdown" ||
    requests[1].language !== "c" ||
    requests[2].context !== "markdown" ||
    requests[2].language !== "python" ||
    requests[3].context !== "markdown" ||
    requests[3].language !== "matlab"
  ) {{
    process.exit(4);
  }}
  if (requests[4].problem_id !== 42) process.exit(5);
  if (Object.prototype.hasOwnProperty.call(requests[4], "context")) {{
    process.exit(6);
  }}
  if (
    requests[5].context !== "repository" ||
    requests[5].repository_entry_id !== 42 ||
    Object.prototype.hasOwnProperty.call(requests[5], "problem_id")
  ) {{
    process.exit(7);
  }}
  if (Object.prototype.hasOwnProperty.call(requests[1], "problem_id")) {{
    process.exit(8);
  }}
  if (Object.prototype.hasOwnProperty.call(requests[2], "problem_id")) {{
    process.exit(9);
  }}
  if (Object.prototype.hasOwnProperty.call(requests[3], "problem_id")) {{
    process.exit(10);
  }}
}})().catch(function() {{ process.exit(11); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_shared_code_editor_runtime_has_one_language_and_theme_mapping():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "code-editor-runtime.js"
    script = f"""
global.window = global;
require({str(asset)!r});
const header = NumOJCodeEditorRuntime.forFilename("include/value.h");
const cSource = NumOJCodeEditorRuntime.forFilename("main.c");
const python = NumOJCodeEditorRuntime.forLanguage("py");
const plain = NumOJCodeEditorRuntime.forFilename("README");
const options = NumOJCodeEditorRuntime.monacoOptions({{wordWrap: "off"}});
if (
  header.language !== "cpp" ||
  header.monacoLanguage !== "cpp" ||
  cSource.language !== "c" ||
  python.monacoLanguage !== "python" ||
  plain.monacoLanguage !== "plaintext"
) {{
  process.exit(1);
}}
if (
  options.theme !== "dark-plus" ||
  options["semanticHighlighting.enabled"] !== true ||
  options.wordWrap !== "off"
) {{
  process.exit(2);
}}
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_code_editor_runtime_upgrades_delayed_textmate_theme_once_ready():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "code-editor-runtime.js"
    script = f"""
global.window = global;
let resolvePreparation = null;
let preparationCalls = 0;
const appliedThemes = [];
const monaco = {{
  editor: {{
    setTheme: function(theme) {{ appliedThemes.push(theme); }}
  }},
  languages: {{
    getLanguages: function() {{ return [{{id: "matlab"}}]; }}
  }},
  prepareTextMateHighlighting: function() {{
    preparationCalls += 1;
    return new Promise(function(resolve) {{ resolvePreparation = resolve; }});
  }}
}};
require({str(asset)!r});
(async function() {{
  const themes = await Promise.all([
    NumOJCodeEditorRuntime.prepareMonaco(monaco),
    NumOJCodeEditorRuntime.prepareMonaco(monaco)
  ]);
  if (themes[0] !== "vs-dark" || themes[1] !== "vs-dark") process.exit(1);
  if (preparationCalls !== 1 || appliedThemes.length !== 0) process.exit(2);

  resolvePreparation();
  await new Promise(function(resolve) {{ setTimeout(resolve, 10); }});
  if (
    appliedThemes.length !== 1 ||
    appliedThemes[0] !== "dark-plus"
  ) process.exit(3);

  const readyTheme = await NumOJCodeEditorRuntime.prepareMonaco(monaco);
  if (readyTheme !== "dark-plus" || preparationCalls !== 1) process.exit(4);
}})().catch(function() {{ process.exit(5); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_semantic_requests_retry_service_busy_but_not_rate_limits():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "editor-semantic-tokens.js"
    script = f"""
global.window = global;
Math.random = function() {{ return 0; }};
let mode = "busy";
let calls = 0;
global.fetch = async function() {{
  calls += 1;
  if ((mode === "busy" || mode === "repository-changed") && calls === 1) {{
    return {{
      ok: false,
      status: 503,
      headers: {{get: function() {{ return null; }}}},
      json: async function() {{
        return {{
          code: mode === "busy" ? "service_busy" : "repository_changed",
          message: "稍后重试"
        }};
      }}
    }};
  }}
  if (mode === "rate-limited") {{
    return {{
      ok: false,
      status: 429,
      headers: {{get: function() {{ return null; }}}},
      json: async function() {{
        return {{code: "rate_limited", message: "请求过于频繁"}};
      }}
    }};
  }}
  return {{
    ok: true,
    json: async function() {{
      return {{success: true, data: [0, 0, 3, 0, 0], result_id: "1"}};
    }}
  }};
}};
require({str(asset)!r});
(async function() {{
  await NumOJSemanticTokens.requestTokens({{
    context: "repository",
    repositoryEntryId: 42,
    language: "cpp",
    source: "int value;"
  }});
  if (calls !== 2) process.exit(1);

  mode = "repository-changed";
  calls = 0;
  await NumOJSemanticTokens.requestTokens({{
    context: "repository",
    repositoryEntryId: 42,
    language: "cpp",
    source: "int value;"
  }});
  if (calls !== 2) process.exit(2);

  mode = "rate-limited";
  calls = 0;
  let error = null;
  try {{
    await NumOJSemanticTokens.requestTokens({{
      problemId: 42,
      language: "cpp",
      source: "int main() {{}}"
    }});
  }} catch (caught) {{
    error = caught;
  }}
  if (!error || error.code !== "rate_limited" || calls !== 1) process.exit(3);
}})().catch(function() {{ process.exit(4); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_semantic_provider_derives_repository_entry_id_from_model():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "editor-semantic-tokens.js"
    script = f"""
global.window = global;
let provider = null;
let tokenBody = null;
global.fetch = async function(url, options) {{
  if (String(url).includes("semantic-token-legend")) {{
    return {{
      ok: true,
      json: async function() {{
        return {{
          success: true,
          legend: {{tokenTypes: ["variable"], tokenModifiers: []}}
        }};
      }}
    }};
  }}
  tokenBody = JSON.parse(options.body);
  return {{
    ok: true,
    json: async function() {{
      return {{success: true, data: [0, 0, 3, 0, 0], result_id: "1"}};
    }}
  }};
}};
require({str(asset)!r});
(async function() {{
  const monaco = {{
    languages: {{
      registerDocumentSemanticTokensProvider: function(_language, value) {{
        provider = value;
        return {{dispose: function() {{}}}};
      }}
    }}
  }};
  await NumOJSemanticTokens.register(monaco, {{
    context: "repository",
    repositoryEntryId: function() {{ return 7; }},
    language: "cpp",
    monacoLanguage: "cpp"
  }});
  if (!provider) process.exit(1);
  await provider.provideDocumentSemanticTokens(
    {{getValue: function() {{ return "int value;"; }}}},
    null,
    {{
      onCancellationRequested: function() {{
        return {{dispose: function() {{}}}};
      }}
    }}
  );
  if (
    !tokenBody ||
    tokenBody.context !== "repository" ||
    tokenBody.repository_entry_id !== 7 ||
    tokenBody.language !== "cpp" ||
    tokenBody.source !== "int value;"
  ) {{
    process.exit(2);
  }}
}})().catch(function() {{ process.exit(3); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_cpp_semantic_provider_tracks_inactive_regions_as_model_decorations():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "editor-semantic-tokens.js"
    script = f"""
global.window = global;
console.warn = function() {{}};
let provider = null;
let registrationDisposed = false;
let nextDecorationId = 0;
let validateRangeCalls = 0;
let modelDisposeHandler = null;
let modelDisposeListenerDisposals = 0;
let modelDisposed = false;
let liveModelListenerDisposals = 0;
const responses = [];
const decorationCalls = [];
class Range {{
  constructor(startLineNumber, startColumn, endLineNumber, endColumn) {{
    this.startLineNumber = startLineNumber;
    this.startColumn = startColumn;
    this.endLineNumber = endLineNumber;
    this.endColumn = endColumn;
  }}
}}
function success(regions, includeRegions) {{
  const payload = {{success: true, data: [0, 0, 3, 0, 0], result_id: "server"}};
  if (includeRegions !== false) payload.inactive_regions = regions;
  return {{
    ok: true,
    json: async function() {{ return payload; }}
  }};
}}
function failure() {{
  return {{
    ok: false,
    status: 400,
    headers: {{get: function() {{ return null; }}}},
    json: async function() {{
      return {{success: false, code: "invalid_request", message: "bad"}};
    }}
  }};
}}
function cancellation() {{
  let handler = null;
  return {{
    token: {{
      onCancellationRequested: function(value) {{
        handler = value;
        return {{dispose: function() {{}}}};
      }}
    }},
    cancel: function() {{ if (handler) handler(); }}
  }};
}}
global.fetch = async function(url, options) {{
  if (String(url).includes("semantic-token-legend")) {{
    return {{
      ok: true,
      json: async function() {{
        return {{
          success: true,
          legend: {{tokenTypes: ["variable"], tokenModifiers: []}}
        }};
      }}
    }};
  }}
  if (!responses.length) throw new Error("missing response");
  return responses.shift()(options || {{}});
}};
global.monaco = {{
  Range: Range,
  languages: {{
    registerDocumentSemanticTokensProvider: function(_language, value) {{
      provider = value;
      return {{
        dispose: function() {{ registrationDisposed = true; }}
      }};
    }}
  }}
}};
const model = {{
  getValue: function() {{ return "#if 0\\nint disabled;\\n#endif"; }},
  isDisposed: function() {{ return modelDisposed; }},
  onWillDispose: function(handler) {{
    let listenerActive = true;
    modelDisposeHandler = handler;
    return {{
      dispose: function() {{
        if (!listenerActive) return;
        listenerActive = false;
        modelDisposeListenerDisposals += 1;
        modelDisposeHandler = null;
      }}
    }};
  }},
  validateRange: function(range) {{
    validateRangeCalls += 1;
    const maxColumns = [6, 14, 7];
    const startLine = Math.max(1, Math.min(3, range.startLineNumber));
    const endLine = Math.max(1, Math.min(3, range.endLineNumber));
    return new Range(
      startLine,
      Math.max(1, Math.min(maxColumns[startLine - 1], range.startColumn)),
      endLine,
      Math.max(1, Math.min(maxColumns[endLine - 1], range.endColumn))
    );
  }},
  deltaDecorations: function(oldIds, decorations) {{
    decorationCalls.push({{
      oldIds: oldIds.slice(),
      decorations: decorations.slice()
    }});
    return decorations.map(function() {{
      nextDecorationId += 1;
      return "decoration-" + String(nextDecorationId);
    }});
  }}
}};
require({str(asset)!r});
(async function() {{
  const registration = await NumOJSemanticTokens.register(monaco, {{
    problemId: 42,
    language: "cpp",
    monacoLanguage: "cpp"
  }});
  if (!provider || !registration) process.exit(1);

  responses.push(function() {{
    return success([
      {{
        start: {{line: 1, character: 0}},
        end: {{line: 1, character: 11}}
      }},
      {{
        start: {{line: 1, character: 8}},
        end: {{line: 1, character: 100}}
      }},
      {{
        start: {{line: 0, character: 0}},
        end: {{line: 0, character: 0}}
      }},
      {{
        start: {{line: 99, character: 99}},
        end: {{line: 100, character: 0}}
      }}
    ]);
  }});
  const first = await provider.provideDocumentSemanticTokens(
    model,
    null,
    cancellation().token
  );
  if (decorationCalls.length !== 1) process.exit(2);
  const decoration = decorationCalls[0].decorations[0];
  if (
    !decoration ||
    decorationCalls[0].decorations.length !== 1 ||
    validateRangeCalls !== 4 ||
    decoration.range.startLineNumber !== 2 ||
    decoration.range.startColumn !== 1 ||
    decoration.range.endLineNumber !== 2 ||
    decoration.range.endColumn !== 14 ||
    decoration.options.isWholeLine !== true ||
    decoration.options.inlineClassName !== "numoj-clangd-inactive-code" ||
    Object.prototype.hasOwnProperty.call(decoration.options, "foreground")
  ) {{
    process.exit(3);
  }}

  responses.push(function() {{ return success(undefined, false); }});
  await provider.provideDocumentSemanticTokens(
    model,
    first.resultId,
    cancellation().token
  );
  if (
    decorationCalls.length !== 2 ||
    decorationCalls[1].oldIds[0] !== "decoration-1" ||
    decorationCalls[1].decorations.length !== 0
  ) {{
    process.exit(4);
  }}
  provider.releaseDocumentSemanticTokens(first.resultId);
  if (decorationCalls.length !== 2) process.exit(5);

  responses.push(function() {{ return success([]); }});
  await provider.provideDocumentSemanticTokens(
    model,
    null,
    cancellation().token
  );
  if (
    decorationCalls.length !== 3 ||
    decorationCalls[2].decorations.length !== 0
  ) {{
    process.exit(6);
  }}

  responses.push(function() {{
    return success([{{
      start: {{line: 1, character: 0}},
      end: {{line: 1, character: 3}}
    }}]);
  }});
  await provider.provideDocumentSemanticTokens(
    model,
    null,
    cancellation().token
  );
  responses.push(function() {{ return failure(); }});
  await provider.provideDocumentSemanticTokens(
    model,
    null,
    cancellation().token
  );
  if (
    decorationCalls.length !== 5 ||
    decorationCalls[4].decorations.length !== 0
  ) {{
    process.exit(7);
  }}

  let resolveOld = null;
  responses.push(function() {{
    return new Promise(function(resolve) {{ resolveOld = resolve; }});
  }});
  const oldCancellation = cancellation();
  const oldRequest = provider.provideDocumentSemanticTokens(
    model,
    null,
    oldCancellation.token
  );
  oldCancellation.cancel();
  responses.push(function() {{
    return success([{{
      start: {{line: 1, character: 4}},
      end: {{line: 1, character: 12}}
    }}]);
  }});
  const fresh = await provider.provideDocumentSemanticTokens(
    model,
    null,
    cancellation().token
  );
  const callsAfterFreshResult = decorationCalls.length;
  resolveOld(success([{{
    start: {{line: 0, character: 0}},
    end: {{line: 0, character: 5}}
  }}]));
  await oldRequest;
  if (decorationCalls.length !== callsAfterFreshResult) process.exit(8);

  provider.releaseDocumentSemanticTokens(fresh.resultId);
  if (
    decorationCalls.length !== callsAfterFreshResult + 1 ||
    decorationCalls.at(-1).decorations.length !== 0
  ) {{
    process.exit(9);
  }}

  responses.push(function() {{
    return success([{{
      start: {{line: 1, character: 0}},
      end: {{line: 1, character: 3}}
    }}]);
  }});
  await provider.provideDocumentSemanticTokens(
    model,
    null,
    cancellation().token
  );
  const callsBeforeDispose = decorationCalls.length;
  const disposeHandler = modelDisposeHandler;
  if (!disposeHandler) process.exit(10);
  disposeHandler();
  modelDisposed = true;
  if (
    modelDisposeListenerDisposals !== 1 ||
    decorationCalls.length !== callsBeforeDispose + 1 ||
    decorationCalls.at(-1).decorations.length !== 0
  ) {{
    process.exit(10);
  }}
  const callsAfterModelDispose = decorationCalls.length;

  const liveModel = {{
    getValue: model.getValue,
    isDisposed: function() {{ return false; }},
    onWillDispose: function() {{
      let listenerActive = true;
      return {{
        dispose: function() {{
          if (!listenerActive) return;
          listenerActive = false;
          liveModelListenerDisposals += 1;
        }}
      }};
    }},
    validateRange: model.validateRange,
    deltaDecorations: model.deltaDecorations
  }};
  responses.push(function() {{
    return success([{{
      start: {{line: 1, character: 0}},
      end: {{line: 1, character: 3}}
    }}]);
  }});
  await provider.provideDocumentSemanticTokens(
    liveModel,
    null,
    cancellation().token
  );
  if (decorationCalls.length !== callsAfterModelDispose + 1) process.exit(11);
  const callsBeforeProviderDispose = decorationCalls.length;
  registration.dispose();
  if (
    !registrationDisposed ||
    decorationCalls.length !== callsBeforeProviderDispose + 1 ||
    modelDisposeListenerDisposals !== 1 ||
    liveModelListenerDisposals !== 1
  ) {{
    process.exit(12);
  }}

  const callsAfterCppDispose = decorationCalls.length;
  const pythonModel = {{
    getValue: function() {{ return "print('active')"; }},
    deltaDecorations: model.deltaDecorations
  }};
  const pythonRegistration = await NumOJSemanticTokens.register(monaco, {{
    problemId: 42,
    language: "python",
    monacoLanguage: "python"
  }});
  responses.push(function() {{
    return success([{{
      start: {{line: 1, character: 0}},
      end: {{line: 1, character: 3}}
    }}]);
  }});
  await provider.provideDocumentSemanticTokens(
    pythonModel,
    null,
    cancellation().token
  );
  pythonRegistration.dispose();
  if (decorationCalls.length !== callsAfterCppDispose) process.exit(13);
}})().catch(function(error) {{
  console.error(error);
  process.exit(14);
}});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


def test_inactive_code_style_dims_without_replacing_syntax_colors():
    stylesheet = (ROOT / "frontend" / "public" / "static" / "styles" / "code-editor.css").read_text()
    match = re.search(
        r"\.monaco-editor \.numoj-clangd-inactive-code\s*\{([^}]*)\}",
        stylesheet,
    )
    assert match is not None
    declaration = match.group(1)
    assert "opacity: 0.55;" in declaration


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_markdown_semantic_client_retries_busy_but_not_rate_limits():
    asset = ROOT / "frontend" / "public" / "static" / "app" / "editor-semantic-tokens.js"
    script = f"""
global.window = global;
Math.random = function() {{ return 0; }};
let mode = "busy";
let calls = 0;
global.fetch = async function() {{
  calls += 1;
  if (mode === "busy" && calls === 1) {{
    return {{
      ok: false,
      status: 429,
      headers: {{get: function() {{ return "0.001"; }}}},
      json: async function() {{
        return {{success: false, code: "result_pending", message: "pending"}};
      }}
    }};
  }}
  if (mode === "rate") {{
    return {{
      ok: false,
      status: 429,
      headers: {{get: function() {{ return "1"; }}}},
      json: async function() {{
        return {{success: false, code: "rate_limited", message: "limited"}};
      }}
    }};
  }}
  return {{
    ok: true,
    status: 200,
    json: async function() {{
      return {{success: true, data: [0, 0, 3, 0, 0]}};
    }}
  }};
}};
require({str(asset)!r});
(async function() {{
  await NumOJSemanticTokens.requestTokens({{
    context: "markdown",
    language: "cpp",
    source: "int value;"
  }});
  if (calls !== 2) process.exit(1);
  mode = "rate";
  calls = 0;
  try {{
    await NumOJSemanticTokens.requestTokens({{
      context: "markdown",
      language: "cpp",
      source: "int other;"
    }});
    process.exit(2);
  }} catch (error) {{
    if (error.code !== "rate_limited") process.exit(3);
    if (calls !== 1) process.exit(4);
  }}
}})().catch(function() {{ process.exit(5); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
