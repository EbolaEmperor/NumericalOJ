"""无需浏览器状态的前端静态 JavaScript 契约。"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
JAVASCRIPT_ASSETS = (
    "frontend/markdown/code-highlighter.js",
    "frontend/lean4-grammar.js",
    "frontend/lean4-unicode-input.js",
    "static/app/auth.js",
    "static/app/class-select.js",
    "static/app/class-picker.js",
    "static/app/choice-picker.js",
    "static/app/code-editor-runtime.js",
    "static/app/editor-semantic-tokens.js",
    "static/app/markdown-rendering.js",
    "static/app/model-family.js",
    "static/app/problem-editor.js",
    "static/app/problem-form-editors.js",
    "static/app/repository/workbench.js",
    "static/app/sidebar-state.js",
    "static/app/forum.js",
    "static/app/layout.js",
    "static/app/vibehub.js",
    "static/app/vibehub-player.js",
    "static/app/ranking/detail-v2.js",
    "static/app/ranking/endpoints.js",
    "static/app/ranking/rules-editor.js",
    "static/app/ranking/topology.js",
    "static/app/site-config.js",
    "static/app/submissions/detail.js",
)


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
@pytest.mark.parametrize("relative_path", JAVASCRIPT_ASSETS)
def test_frontend_javascript_has_valid_syntax(relative_path):
    subprocess.run(
        [NODE, "--check", str(ROOT / relative_path)],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_markdown_highlighter_bundle_matches_editor_dark_plus_languages():
    asset = ROOT / "static" / "vendor" / "shiki-markdown" / "highlighter.js"
    script = f"""
const fs = require("fs");
const vm = require("vm");
vm.runInThisContext(fs.readFileSync({str(asset)!r}, "utf8"));
(async function() {{
  const samples = [
    ["bash", 'curl -fsSL "$URL"', ["#DCDCAA", "#569CD6", "#9CDCFE"]],
    ["c", "struct Widget {{ int value; }};", ["#569CD6"]],
    ["cpp", "std::vector<int> values;", ["#4EC9B0"]],
    [
      "python",
      "def solve(value: int) -> int:\\n    return value + 1",
      ["#569CD6", "#DCDCAA", "#9CDCFE", "#4EC9B0", "#B5CEA8"],
    ],
    [
      "matlab",
      "function y = solve(x)\\n  y = zeros(size(x));\\nend",
      ["#569CD6", "#DCDCAA", "#9CDCFE", "#C586C0"],
    ],
    ["octave", "function y = solve(x)\\n  y = x;\\nend", ["#569CD6"]],
    [
      "lean4",
      "theorem answer (n : Nat) : n + 0 = n := by\\n  simpa -- done\\n\\nsorry",
      ["#569CD6", "#DCDCAA", "#B5CEA8", "#C586C0", "#6A9955", "#F44747"],
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
    asset = ROOT / "static" / "app" / "code-editor-runtime.js"
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
def test_rule_topology_factory_is_deterministic_and_rejects_cycles():
    asset = ROOT / "static" / "app" / "ranking" / "topology.js"
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
    asset = ROOT / "static" / "app" / "editor-semantic-tokens.js"
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
    source: "std::vector<int> values;"
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
  if (requests[0].context !== "markdown") process.exit(2);
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
    asset = ROOT / "static" / "app" / "code-editor-runtime.js"
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
    asset = ROOT / "static" / "app" / "code-editor-runtime.js"
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
    asset = ROOT / "static" / "app" / "editor-semantic-tokens.js"
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
    asset = ROOT / "static" / "app" / "editor-semantic-tokens.js"
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
    asset = ROOT / "static" / "app" / "editor-semantic-tokens.js"
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
    stylesheet = (ROOT / "static" / "styles" / "code-editor.css").read_text()
    match = re.search(
        r"\.monaco-editor \.numoj-clangd-inactive-code\s*\{([^}]*)\}",
        stylesheet,
    )
    assert match is not None
    declaration = match.group(1)
    assert "opacity: 0.55;" in declaration
    assert "color:" not in declaration


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_markdown_semantic_client_retries_busy_but_not_rate_limits():
    asset = ROOT / "static" / "app" / "editor-semantic-tokens.js"
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
