const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const {spawnSync} = require('node:child_process')
const test = require('node:test')

const ROOT = path.resolve(__dirname, '../..')
const FRONTEND = path.join(ROOT, 'frontend')

const javascriptAssets = [
  'frontend/markdown/code-highlighter.js',
  'frontend/markdown/github-light-theme.js',
  'frontend/lean4-grammar.js',
  'frontend/lean4-theme.js',
  'frontend/lean4-unicode-input.js',
  'frontend/public/static/app/code-editor-runtime.js',
  'frontend/public/static/app/editor-semantic-tokens.js',
  'frontend/public/static/app/lean-workbench.js',
  'frontend/public/static/app/model-family.js',
  'frontend/public/static/app/ranking/topology.js',
]

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), 'utf8')
}

function asset(relativePath) {
  return path.join(FRONTEND, 'public', 'static', relativePath)
}

function runIsolated(script) {
  const result = spawnSync(process.execPath, ['-e', script], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 60_000,
  })
  assert.equal(
    result.status,
    0,
    [result.error?.stack, result.stderr, result.stdout].filter(Boolean).join('\n'),
  )
}

test('前端 Node 运行时版本在仓库中保持一致', () => {
  const expected = read('.node-version').trim()
  const packageJson = JSON.parse(read('frontend/package.json'))
  const lock = JSON.parse(read('frontend/package-lock.json'))
  const workflow = read('.github/workflows/ci.yml')

  assert.equal(expected, '22.23.2')
  assert.equal(packageJson.engines.node, expected)
  assert.equal(packageJson.volta.node, expected)
  assert.equal(lock.packages[''].engines.node, expected)
  assert.equal((workflow.match(/node-version: '22\.23\.2'/g) || []).length, 2)
})

for (const relativePath of javascriptAssets) {
  test(`${relativePath} 语法有效`, () => {
    const result = spawnSync(process.execPath, ['--check', path.join(ROOT, relativePath)], {
      cwd: ROOT,
      encoding: 'utf8',
      timeout: 30_000,
    })
    assert.equal(result.status, 0, result.stderr || result.stdout)
  })
}

test('SPA 按需加载 MathJax 底层运行时', () => {
  const document = read('frontend/index.html')
  const runtime = read('frontend/src/markdown/mathjaxRuntime.ts')

  assert.ok(document.includes('<script type="module" src="/src/main.tsx"></script>'))
  assert.equal(document.includes('/static/vendor/mathjax/tex-mml-chtml.js'), false)
  assert.equal(document.includes('src="/static/app/rich-content-assets.js"'), false)
  assert.equal(document.includes('src="/static/app/markdown-rendering.js"'), false)
  assert.ok(runtime.includes("const SCRIPT_URL = '/static/vendor/mathjax/tex-mml-chtml.js'"))
  assert.ok(runtime.includes("document.createElement('script')"))
  assert.ok(runtime.includes("script.dataset.numojReactAsset = 'true'"))
  assert.ok(runtime.includes('document.head.appendChild(script)'))
  assert.ok(runtime.includes('runtime?.startup?.defaultReady?.()'))
  assert.ok(runtime.includes('runtime?.startup?.promise?.then('))
})

test('React Hook 独立调度公式、代码和 Mermaid 增强', () => {
  const source = read('frontend/src/components/useMarkdownEnhancements.ts')
  const component = read('frontend/src/components/MarkdownContent.tsx')
  const mathHook = source.indexOf('function useMathJax(')
  const codeEffect = source.indexOf('void highlightCode(')
  const mermaidEffect = source.indexOf('void renderMermaid(')

  assert.ok(mathHook > 0)
  assert.ok(codeEffect > mathHook)
  assert.ok(mermaidEffect > codeEffect)
  assert.ok(source.includes('useLayoutEffect(() => {'))
  assert.ok(source.includes('.then(() => enhanceSemanticCode('))
  assert.equal(source.includes('NumericalOJMarkdownRenderer'), false)
  assert.ok(component.includes('memo(function MarkdownContent'))
})

test('React MathJax Hook 等待启动并校验当前挂载实例', () => {
  const hook = read('frontend/src/components/useMarkdownEnhancements.ts')
  const runtime = read('frontend/src/markdown/mathjaxRuntime.ts')

  assert.ok(hook.includes("import {clearMath, typesetMath} from '../markdown/mathjaxRuntime'"))
  assert.ok(hook.includes('void typesetMath(root).then(() => {'))
  assert.ok(hook.includes('if (active && root.isConnected)'))
  assert.ok(hook.includes("root.dataset.numojMathState = 'rendered'"))
  assert.ok(hook.includes('clearMath(root)'))
  assert.ok(runtime.includes('if (!root.isConnected) return'))
  assert.ok(runtime.includes('runtime.typesetClear?.([root])'))
  assert.ok(runtime.includes('await runtime.typesetPromise?.([root])'))
})

test('React 富内容增强失败时保留当前正文与代码配色', () => {
  const source = read('frontend/src/components/useMarkdownEnhancements.ts')

  assert.ok(source.includes('已保留当前配色'))
  assert.ok(source.includes('已保留词法配色'))
  assert.ok(source.includes("root.dataset.numojMathState = 'error'"))
  assert.ok(source.includes("block.classList.add('is-error')"))
})

test('Markdown 高亮产物为常用语言使用 GitHub Light 配色', () => {
  const source = JSON.stringify(asset('vendor/shiki-markdown/highlighter.js'))
  runIsolated(`
const assert = require("node:assert/strict");
const fs = require("node:fs");
(async function() {
  const moduleSource = fs.readFileSync(${source}, "base64");
  const highlighter = await import("data:text/javascript;base64," + moduleSource);
  const githubLightColors = new Set([
    "#0550AE", "#0A3069", "#116329", "#1F2328", "#57606A", "#6E7781",
    "#82071E", "#8250DF", "#953800", "#CF222E", "#EAEEF2", "#F6F8FA"
  ]);
  const samples = [
    ["bash", 'curl -fsSL "$URL"'],
    ["c", "struct Widget { int value; };"],
    ["cpp", "if (values.empty()) return;"],
    ["python", "def solve(value: int) -> int:\\n    return value + 1"],
    ["matlab", "function y = solve(x)\\n  y = zeros(size(x));\\nend"],
    ["octave", "function y = solve(x)\\n  y = x;\\nend"],
    ["lean4", "theorem answer (n : Nat) : n + 0 = n := by\\n  simpa -- done\\n\\nsorry"]
  ];
  for (const [language, code] of samples) {
    const result = await highlighter.tokenize(code, language);
    const tokens = result.tokens.flat();
    const rebuilt = result.tokens.map((line) => line.map((token) => token.content).join("")).join("\\n");
    assert.equal(rebuilt, code);
    const colors = new Set(tokens.map((token) => String(token.color).toUpperCase()));
    assert.ok(colors.size >= 2, language + ": expected syntax highlighting");
    for (const color of colors) assert.ok(githubLightColors.has(color), language + ": " + color);
  }
})().catch((error) => { console.error(error); process.exit(1); });
`)
})

test('提交静态只读查看器为 MATLAB 与 Lean 使用 Dark+ 配色', () => {
  const source = JSON.stringify(asset('vendor/shiki-markdown/highlighter.js'))
  runIsolated(`
const assert = require("node:assert/strict");
const fs = require("node:fs");
(async function() {
  const moduleSource = fs.readFileSync(${source}, "base64");
  const highlighter = await import("data:text/javascript;base64," + moduleSource);
  const darkPlusColors = new Set([
    "#4EC9B0", "#4FC1FF", "#569CD6", "#608B4E", "#646695", "#6A9955",
    "#808080", "#9CDCFE", "#B5CEA8", "#C586C0", "#C8C8C8", "#CE9178",
    "#D16969", "#D4D4D4", "#D7BA7D", "#DCDCAA", "#F44747"
  ]);
  const samples = [
    ["matlab", "% comment\\nfunction y = solve(x)\\n  y = sin(x) + 3.14;\\nend"],
    ["lean4", "/- comment -/\\ntheorem demo (n : Nat) : n = n := by\\n  rfl"]
  ];
  for (const [language, code] of samples) {
    const result = await highlighter.tokenize(code, language, "dark");
    const tokens = result.tokens.flat();
    const rebuilt = result.tokens.map((line) => line.map((token) => token.content).join("")).join("\\n");
    assert.equal(rebuilt, code);
    const colors = new Set(tokens.map((token) => String(token.color).toUpperCase()));
    assert.ok(colors.size >= 2, language + ": expected syntax highlighting");
    for (const color of colors) assert.ok(darkPlusColors.has(color), language + ": " + color);
  }
})().catch((error) => { console.error(error); process.exit(1); });
`)
})

test('Lean4 Monarch 回退支持 Unicode 标识符', () => {
  const source = JSON.stringify(asset('app/code-editor-runtime.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
let leanDefinition = null;
const monaco = {languages: {
  getLanguages() { return []; },
  register() {},
  setLanguageConfiguration() {},
  setMonarchTokensProvider(language, definition) { if (language === "lean4") leanDefinition = definition; }
}};
require(${source});
NumOJCodeEditorRuntime.registerLean4(monaco);
assert.ok(leanDefinition);
assert.equal(leanDefinition.unicode, true);
assert.ok(leanDefinition.keywords.includes("theorem"));
assert.ok(leanDefinition.tacticKeywords.includes("simpa"));
`)
})

test('Lean4 使用官方 Unicode 缩写表', () => {
  const source = JSON.stringify(path.join(FRONTEND, 'lean4-unicode-input.js'))
  runIsolated(`
const assert = require("node:assert/strict");
const {pathToFileURL} = require("node:url");
(async function() {
  const input = await import(pathToFileURL(${source}).href);
  const symbols = input.getLean4UnicodeAbbreviations();
  assert.equal(symbols.alpha, "α");
  assert.equal(symbols.forall, "∀");
  assert.equal(symbols["<>"], "⟨$CURSOR⟩");
  assert.ok(Object.keys(symbols).length >= 1_800);
})().catch((error) => { console.error(error); process.exit(1); });
`)
})

test('Lean4 语义 token 桥按 Monaco 模型版本更新', () => {
  const source = JSON.stringify(asset('app/lean-workbench.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
require(${source});
let version = 3;
let provider = null;
let registrationDisposed = false;
const model = {getVersionId() { return version; }};
const monaco = {languages: {
  registerDocumentSemanticTokensProvider(language, value) {
    assert.equal(language, "lean4");
    provider = value;
    return {dispose() { registrationDisposed = true; }};
  }
}};
const bridge = NumOJLeanWorkbench.createSemanticTokenBridge(monaco, model);
assert.equal(bridge.accept(3, null), false);
const first = {
  legend: {tokenTypes: ["keyword", "function", "leanSorryLike"], tokenModifiers: ["declaration"]},
  data: [0, 0, 7, 0, 0, 0, 8, 6, 1, 1],
  result_id: "1:abc"
};
assert.equal(bridge.accept(3, first), true);
assert.ok(provider);
assert.equal(provider.getLegend().tokenTypes[1], "lean4.function");
let refreshes = 0;
provider.onDidChange(() => { refreshes += 1; });
let result = provider.provideDocumentSemanticTokens(model, null, {isCancellationRequested: false});
assert.ok(result.data instanceof Uint32Array);
assert.equal(result.data[8], 1);
const firstProviderResultId = result.resultId;
bridge.accept(3, first);
assert.equal(refreshes, 0);
version = 4;
bridge.invalidate();
assert.equal(refreshes, 0);
assert.throws(
  () => provider.provideDocumentSemanticTokens(model, null, {isCancellationRequested: false}),
  /busy/,
);
assert.equal(bridge.accept(3, first), false);
const second = {...first, data: [0, 0, 7, 0, 0, 0, 8, 9, 1, 1], result_id: "2:def"};
assert.equal(bridge.accept(4, second), true);
assert.equal(refreshes, 1);
result = provider.provideDocumentSemanticTokens(model, firstProviderResultId, {isCancellationRequested: false});
assert.equal(result.edits.length, 1);
assert.equal(result.edits[0].start, 7);
assert.equal(result.edits[0].deleteCount, 1);
assert.ok(result.edits[0].data instanceof Uint32Array);
assert.equal(result.edits[0].data[0], 9);
const secondProviderResultId = result.resultId;
version = 5;
bridge.invalidate();
assert.equal(bridge.getResultId(), "2:def");
assert.equal(bridge.accept(5, {
  previous_result_id: "2:def",
  result_id: "3:ghi",
  edits: [{start: 7, deleteCount: 1, data: [10]}]
}), true);
result = provider.provideDocumentSemanticTokens(model, secondProviderResultId, {isCancellationRequested: false});
assert.equal(result.edits.length, 1);
assert.equal(result.edits[0].start, 7);
assert.equal(result.edits[0].deleteCount, 1);
assert.equal(result.edits[0].data[0], 10);
const thirdProviderResultId = result.resultId;
version = 6;
bridge.invalidate();
assert.equal(bridge.accept(6, null), true);
result = provider.provideDocumentSemanticTokens(model, thirdProviderResultId, {isCancellationRequested: false});
assert.deepEqual(result.edits, []);
provider.releaseDocumentSemanticTokens(result.resultId);
result = provider.provideDocumentSemanticTokens(model, result.resultId, {isCancellationRequested: false});
assert.ok(result.data instanceof Uint32Array);
assert.equal(result.data[7], 10);
version = 7;
bridge.invalidate();
assert.equal(bridge.accept(7, {previous_result_id: "wrong-result", result_id: "4:jkl", edits: []}), false);
assert.equal(provider.provideDocumentSemanticTokens(model, null, {isCancellationRequested: true}), null);
bridge.dispose();
assert.equal(registrationDisposed, true);
`)
})

test('Lean4 workbench 分离源码与光标请求', () => {
  const source = read('frontend/public/static/app/lean-workbench.js')
  const expectedFragments = [
    'request_kind: kind',
    'client_session_id: clientSessionId',
    'requestPayload.files = writableFiles();',
    'requestPayload.source_state_id = sourceStateId;',
    'requestPayload.document_version = requestedState.documentVersion;',
    'known_semantic_result_id:',
    'payload.code === "resync_required"',
    'inFlightRequestFingerprint',
    'lastCompletedRequestFingerprints[kind]',
    'lastCompletedRequestFingerprints.cursor = requestFingerprint(',
    'lastCompletedRequestFingerprints.source = "";',
    'checkDocument("source")',
    'checkDocument("cursor")',
    'kind === "source" && payload.diagnostics !== null',
  ]
  for (const fragment of expectedFragments) assert.ok(source.includes(fragment), fragment)
})

test('Lean4 词法与语义主题使用相同核心颜色', () => {
  const lexicalTheme = read('frontend/lean4-theme.js')
  const semanticTheme = read('frontend/monaco/runtime.js')

  for (const fragment of [
    '"keyword.other.lean4"',
    '"storage.modifier.lean4"',
    'settings: { foreground: "#C586C0" }',
  ]) assert.ok(lexicalTheme.includes(fragment), fragment)
  for (const fragment of [
    '{ token: "lean4.keyword", foreground: "C586C0" }',
    '{ token: "lean4.modifier", foreground: "C586C0" }',
    '{ token: "lean4.operator", foreground: "D7BA7D" }',
    '{ token: "lean4.function", foreground: "DCDCAA" }',
  ]) assert.ok(semanticTheme.includes(fragment), fragment)
})

test('精简 Monaco 包仅保留支持语言并满足体积预算', () => {
  const minimalEntry = read('frontend/monaco/editor-minimal.js')
  const fullEntry = read('frontend/monaco/editor.js')
  const runtime = read('frontend/monaco/runtime.js')
  const buildScript = read('frontend/scripts/build_monaco.mjs')
  const loader = read('frontend/src/editor/monacoLoader.ts')

  assert.ok(loader.includes('/static/vendor/monaco/editor-minimal.css'))
  assert.ok(loader.includes("const source = '/static/vendor/monaco/editor-minimal.js'"))
  for (const language of ['c', 'cpp', 'python', 'matlab']) {
    assert.ok(minimalEntry.includes(`from "@shikijs/langs/${language}"`))
  }
  assert.ok(minimalEntry.includes('from "../lean4-grammar.js"'))
  assert.ok(minimalEntry.includes('configureTextMateLanguages([c, cpp, python, matlab, lean4])'))
  assert.ok(minimalEntry.includes('definitions/cpp/register.js"'))
  assert.ok(minimalEntry.includes('definitions/python/register.js"'))
  for (const language of ['java', 'javascript', 'rust', 'typescript']) {
    assert.equal(minimalEntry.includes(`from "@shikijs/langs/${language}"`), false)
    assert.ok(fullEntry.includes(`from "@shikijs/langs/${language}"`))
  }
  assert.ok(minimalEntry.includes('monaco-editor/editor/editor.api.js'))
  assert.equal(minimalEntry.includes('monaco-editor/editor/editor.main.js'), false)
  assert.ok(minimalEntry.includes('semanticTokens/browser/documentSemanticTokens.js'))
  assert.ok(minimalEntry.includes('semanticTokens/browser/viewportSemanticTokens.js'))
  assert.ok(runtime.includes('attachLean4UnicodeInput'))
  assert.ok(runtime.includes('getLean4UnicodeAbbreviations'))
  assert.ok(buildScript.includes('["monaco/editor.js", "editor"]'))
  assert.ok(buildScript.includes('["monaco/editor-minimal.js", "editor-minimal"]'))

  const fullAsset = asset('vendor/monaco/editor.js')
  const minimalAsset = asset('vendor/monaco/editor-minimal.js')
  assert.ok(fs.statSync(minimalAsset).size < fs.statSync(fullAsset).size * 0.60)
  const builtMinimal = fs.readFileSync(minimalAsset, 'utf8')
  for (const symbol of [
    'attachLean4UnicodeInput',
    'getLean4UnicodeAbbreviations',
    'prepareTextMateHighlighting',
    'registerDocumentSemanticTokensProvider',
    'dark-plus',
    '4EC9B0',
    'DCDCAA',
  ]) assert.ok(builtMinimal.includes(symbol), symbol)
})

test('Monaco 分发产物携带上游许可证', () => {
  const buildScript = read('frontend/scripts/build_monaco.mjs')
  assert.ok(buildScript.includes('"node_modules/monaco-editor/LICENSE"'))
  assert.ok(buildScript.includes('`${outputDirectory}/LICENSE`'))
  const license = fs.readFileSync(asset('vendor/monaco/LICENSE'), 'utf8')
  assert.ok(license.includes('The MIT License (MIT)'))
  assert.ok(license.includes('Copyright (c) 2016 - present Microsoft Corporation'))
  assert.ok(license.includes('The above copyright notice and this permission notice'))

  assert.ok(buildScript.includes('"node_modules/monaco-editor/ThirdPartyNotices.txt"'))
  assert.ok(buildScript.includes('`${outputDirectory}/ThirdPartyNotices.txt`'))
  const notices = fs.readFileSync(asset('vendor/monaco/ThirdPartyNotices.txt'), 'utf8')
  assert.ok(notices.includes('THIRD-PARTY SOFTWARE NOTICES AND INFORMATION'))
  assert.ok(notices.includes('nodejs path library'))
  assert.ok(notices.includes('END OF vscode-swift NOTICES AND INFORMATION'))
})

test('Lean4 Markdown 高亮使用结构化 scope', () => {
  const source = JSON.stringify(asset('vendor/shiki-markdown/highlighter.js'))
  runIsolated(`
const assert = require("node:assert/strict");
const fs = require("node:fs");
(async function() {
  const moduleSource = fs.readFileSync(${source}, "base64");
  const highlighter = await import("data:text/javascript;base64," + moduleSource);
  const code = [
    "/-! Fibonacci docs -/",
    "import Mathlib",
    "namespace Mathlib.Data.Nat",
    "structure {u} Box where",
    "structure Point where",
    "  x : Nat",
    "  y : ℕ",
    "theorem fib_add (n : Nat) : Nat.fib n = Nat.fib n := by",
    "  simpa <;> first | rfl | exact n - 1 × 2 ^ 3 % 2",
    "#check Mathlib.Data.Nat.Basic",
    "· exact n",
    "sorry"
  ].join("\\n");
  const result = await highlighter.tokenize(code, "lean4");
  const tokens = result.tokens.flat();
  function has(content, color, style) {
    return tokens.some((token) => token.content === content
      && String(token.color).toUpperCase() === color
      && Number(token.fontStyle || 0) === style);
  }
  assert.ok(has("/-! Fibonacci docs -/", "#6E7781", 1));
  assert.ok(has("Point", "#0550AE", 2));
  assert.ok(has("Box", "#0550AE", 2));
  assert.ok(has("Mathlib.Data.Nat", "#0550AE", 2));
  assert.ok(has("Mathlib.Data.Nat.Basic", "#0550AE", 0));
  assert.ok(has("x", "#953800", 0));
  assert.ok(has("n", "#953800", 0));
  assert.ok(has("Nat", "#0550AE", 0));
  assert.ok(has("ℕ", "#0550AE", 0));
  assert.ok(has("Nat.", "#0550AE", 0));
  assert.ok(has("fib", "#8250DF", 0));
  assert.ok(has("fib_add", "#8250DF", 2));
  assert.ok(has("by", "#CF222E", 0));
  assert.ok(has("simpa", "#CF222E", 0));
  assert.ok(has("import", "#CF222E", 0));
  assert.ok(has("namespace", "#CF222E", 0));
  assert.ok(has("=", "#0550AE", 0));
  for (const operator of ["<;>", "-", "×", "^", "%", "·"]) assert.ok(has(operator, "#0550AE", 0), operator);
  assert.ok(has("sorry", "#82071E", 4));
})().catch((error) => { console.error(error); process.exit(1); });
`)
})

test('规则拓扑布局确定且拒绝环', () => {
  const source = JSON.stringify(asset('app/ranking/topology.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
require(${source});
const topology = RuleTopology.create({
  nodeWidth: 168,
  nodeHeight: 100,
  marginX: 24,
  marginY: 20,
  columnGap: 88,
  rowGap: 80,
  slotPadding: 42,
  maxSlotStep: 17
});
const rules = [
  {rule_id: 1, dependencies: []},
  {rule_id: 2, dependencies: [1]},
  {rule_id: 3, dependencies: [1]}
];
const layout = topology.layout(rules);
assert.ok(layout);
assert.equal(layout.width, 472);
assert.equal(layout.height, 320);
assert.equal(layout.positions[1].x, 24);
assert.equal(layout.positions[1].y, 20);
assert.equal(layout.positions[2].y, 200);
assert.equal(layout.positions[3].y, 200);
const routes = topology.buildRoutes([{from: 1, to: 2}, {from: 1, to: 3}], layout);
for (const key of ["1:2", "1:3"]) {
  assert.ok(routes[key]);
  assert.ok(topology.edgePath(routes[key]).startsWith("M "));
}
assert.equal(topology.layout([
  {rule_id: 1, dependencies: [2]},
  {rule_id: 2, dependencies: [1]}
]), null);
`)
})

test('语义 token 客户端区分编辑器和 Markdown 请求', () => {
  const source = JSON.stringify(asset('app/editor-semantic-tokens.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
const calls = [];
global.fetch = async function(url, options) {
  calls.push({url, options: options || {}});
  if (String(url).includes("semantic-token-legend")) {
    return {ok: true, async json() { return {success: true, legend: {tokenTypes: ["class"], tokenModifiers: []}}; }};
  }
  return {ok: true, async json() { return {success: true, data: [0, 0, 3, 0, 0], result_id: "1:test"}; }};
};
require(${source});
(async function() {
  await NumOJSemanticTokens.getLegend("cpp");
  await NumOJSemanticTokens.requestTokens({context: "markdown", language: "cpp", source: "std::vector<std::string> values;"});
  await NumOJSemanticTokens.requestTokens({context: "markdown", language: "c", source: "int value;"});
  await NumOJSemanticTokens.requestTokens({context: "markdown", language: "python", source: "value: int = 1"});
  await NumOJSemanticTokens.requestTokens({context: "markdown", language: "octave", source: "value = 1;"});
  await NumOJSemanticTokens.requestTokens({problemId: 42, language: "cpp", source: "int main() {}"});
  await NumOJSemanticTokens.requestTokens({context: "repository", repositoryEntryId: 42, language: "cpp", source: "int repository_value;"});
  const requests = calls.filter((call) => call.options.method === "POST").map((call) => JSON.parse(call.options.body));
  assert.equal(requests.length, 6);
  assert.equal(requests[0].context, "markdown");
  assert.equal(requests[0].source, "std::vector<std::string> values;");
  assert.equal(Object.hasOwn(requests[0], "problem_id"), false);
  assert.equal(requests[1].context, "markdown");
  assert.equal(requests[1].language, "c");
  assert.equal(requests[2].context, "markdown");
  assert.equal(requests[2].language, "python");
  assert.equal(requests[3].context, "markdown");
  assert.equal(requests[3].language, "matlab");
  assert.equal(requests[4].problem_id, 42);
  assert.equal(Object.hasOwn(requests[4], "context"), false);
  assert.equal(requests[5].context, "repository");
  assert.equal(requests[5].repository_entry_id, 42);
  assert.equal(Object.hasOwn(requests[5], "problem_id"), false);
  for (const index of [1, 2, 3]) assert.equal(Object.hasOwn(requests[index], "problem_id"), false);
})().catch((error) => { console.error(error); process.exit(1); });
`)
})

test('共享代码编辑器运行时统一语言和主题映射', () => {
  const source = JSON.stringify(asset('app/code-editor-runtime.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
require(${source});
const header = NumOJCodeEditorRuntime.forFilename("include/value.h");
const cSource = NumOJCodeEditorRuntime.forFilename("main.c");
const python = NumOJCodeEditorRuntime.forLanguage("py");
const plain = NumOJCodeEditorRuntime.forFilename("README");
const options = NumOJCodeEditorRuntime.monacoOptions({wordWrap: "off"});
assert.equal(header.language, "cpp");
assert.equal(header.monacoLanguage, "cpp");
assert.equal(cSource.language, "c");
assert.equal(python.monacoLanguage, "python");
assert.equal(plain.monacoLanguage, "plaintext");
assert.equal(options.theme, "dark-plus");
assert.equal(options["semanticHighlighting.enabled"], true);
assert.equal(options.wordWrap, "off");
`)
})

test('代码编辑器在 TextMate 就绪后只升级一次主题', () => {
  const source = JSON.stringify(asset('app/code-editor-runtime.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
let resolvePreparation = null;
let preparationCalls = 0;
const appliedThemes = [];
const monaco = {
  editor: {setTheme(theme) { appliedThemes.push(theme); }},
  languages: {getLanguages() { return [{id: "matlab"}]; }},
  prepareTextMateHighlighting() {
    preparationCalls += 1;
    return new Promise((resolve) => { resolvePreparation = resolve; });
  }
};
require(${source});
(async function() {
  const themes = await Promise.all([
    NumOJCodeEditorRuntime.prepareMonaco(monaco),
    NumOJCodeEditorRuntime.prepareMonaco(monaco)
  ]);
  assert.deepEqual(themes, ["vs-dark", "vs-dark"]);
  assert.equal(preparationCalls, 1);
  assert.deepEqual(appliedThemes, []);
  resolvePreparation();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(appliedThemes, ["dark-plus"]);
  assert.equal(await NumOJCodeEditorRuntime.prepareMonaco(monaco), "dark-plus");
  assert.equal(preparationCalls, 1);
})().catch((error) => { console.error(error); process.exit(1); });
`)
})

test('语义请求重试服务繁忙但不重试限流', () => {
  const source = JSON.stringify(asset('app/editor-semantic-tokens.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
Math.random = () => 0;
let mode = "busy";
let calls = 0;
global.fetch = async function() {
  calls += 1;
  if ((mode === "busy" || mode === "repository-changed") && calls === 1) {
    return {
      ok: false,
      status: 503,
      headers: {get() { return null; }},
      async json() { return {code: mode === "busy" ? "service_busy" : "repository_changed", message: "稍后重试"}; }
    };
  }
  if (mode === "rate-limited") {
    return {
      ok: false,
      status: 429,
      headers: {get() { return null; }},
      async json() { return {code: "rate_limited", message: "请求过于频繁"}; }
    };
  }
  return {ok: true, async json() { return {success: true, data: [0, 0, 3, 0, 0], result_id: "1"}; }};
};
require(${source});
(async function() {
  await NumOJSemanticTokens.requestTokens({context: "repository", repositoryEntryId: 42, language: "cpp", source: "int value;"});
  assert.equal(calls, 2);
  mode = "repository-changed";
  calls = 0;
  await NumOJSemanticTokens.requestTokens({context: "repository", repositoryEntryId: 42, language: "cpp", source: "int value;"});
  assert.equal(calls, 2);
  mode = "rate-limited";
  calls = 0;
  await assert.rejects(
    NumOJSemanticTokens.requestTokens({problemId: 42, language: "cpp", source: "int main() {}"}),
    (error) => error.code === "rate_limited",
  );
  assert.equal(calls, 1);
})().catch((error) => { console.error(error); process.exit(1); });
`)
})

test('语义 provider 从模型上下文获取仓库条目 ID', () => {
  const source = JSON.stringify(asset('app/editor-semantic-tokens.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
let provider = null;
let tokenBody = null;
global.fetch = async function(url, options) {
  if (String(url).includes("semantic-token-legend")) {
    return {ok: true, async json() { return {success: true, legend: {tokenTypes: ["variable"], tokenModifiers: []}}; }};
  }
  tokenBody = JSON.parse(options.body);
  return {ok: true, async json() { return {success: true, data: [0, 0, 3, 0, 0], result_id: "1"}; }};
};
require(${source});
(async function() {
  const monaco = {languages: {
    registerDocumentSemanticTokensProvider(_language, value) {
      provider = value;
      return {dispose() {}};
    }
  }};
  await NumOJSemanticTokens.register(monaco, {
    context: "repository",
    repositoryEntryId() { return 7; },
    language: "cpp",
    monacoLanguage: "cpp"
  });
  assert.ok(provider);
  await provider.provideDocumentSemanticTokens(
    {getValue() { return "int value;"; }},
    null,
    {onCancellationRequested() { return {dispose() {}}; }}
  );
  assert.deepEqual(tokenBody, {
    context: "repository",
    repository_entry_id: 7,
    language: "cpp",
    source: "int value;"
  });
})().catch((error) => { console.error(error); process.exit(1); });
`)
})

test('C++ 语义 provider 用模型装饰追踪 inactive 区域', () => {
  const source = JSON.stringify(asset('app/editor-semantic-tokens.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
console.warn = function() {};
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
class Range {
  constructor(startLineNumber, startColumn, endLineNumber, endColumn) {
    this.startLineNumber = startLineNumber;
    this.startColumn = startColumn;
    this.endLineNumber = endLineNumber;
    this.endColumn = endColumn;
  }
}
function success(regions, includeRegions) {
  const payload = {success: true, data: [0, 0, 3, 0, 0], result_id: "server"};
  if (includeRegions !== false) payload.inactive_regions = regions;
  return {ok: true, async json() { return payload; }};
}
function failure() {
  return {
    ok: false,
    status: 400,
    headers: {get() { return null; }},
    async json() { return {success: false, code: "invalid_request", message: "bad"}; }
  };
}
function cancellation() {
  let handler = null;
  return {
    token: {onCancellationRequested(value) { handler = value; return {dispose() {}}; }},
    cancel() { if (handler) handler(); }
  };
}
global.fetch = async function(url, options) {
  if (String(url).includes("semantic-token-legend")) {
    return {ok: true, async json() { return {success: true, legend: {tokenTypes: ["variable"], tokenModifiers: []}}; }};
  }
  if (!responses.length) throw new Error("missing response");
  return responses.shift()(options || {});
};
global.monaco = {
  Range,
  languages: {
    registerDocumentSemanticTokensProvider(_language, value) {
      provider = value;
      return {dispose() { registrationDisposed = true; }};
    }
  }
};
const model = {
  getValue() { return "#if 0\\nint disabled;\\n#endif"; },
  isDisposed() { return modelDisposed; },
  onWillDispose(handler) {
    let listenerActive = true;
    modelDisposeHandler = handler;
    return {dispose() {
      if (!listenerActive) return;
      listenerActive = false;
      modelDisposeListenerDisposals += 1;
      modelDisposeHandler = null;
    }};
  },
  validateRange(range) {
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
  },
  deltaDecorations(oldIds, decorations) {
    decorationCalls.push({oldIds: oldIds.slice(), decorations: decorations.slice()});
    return decorations.map(() => {
      nextDecorationId += 1;
      return "decoration-" + String(nextDecorationId);
    });
  }
};
require(${source});
(async function() {
  const registration = await NumOJSemanticTokens.register(monaco, {
    problemId: 42,
    language: "cpp",
    monacoLanguage: "cpp"
  });
  assert.ok(provider);
  assert.ok(registration);

  responses.push(() => success([
    {start: {line: 1, character: 0}, end: {line: 1, character: 11}},
    {start: {line: 1, character: 8}, end: {line: 1, character: 100}},
    {start: {line: 0, character: 0}, end: {line: 0, character: 0}},
    {start: {line: 99, character: 99}, end: {line: 100, character: 0}}
  ]));
  const first = await provider.provideDocumentSemanticTokens(model, null, cancellation().token);
  assert.equal(decorationCalls.length, 1);
  const decoration = decorationCalls[0].decorations[0];
  assert.ok(decoration);
  assert.equal(decorationCalls[0].decorations.length, 1);
  assert.equal(validateRangeCalls, 4);
  assert.equal(decoration.range.startLineNumber, 2);
  assert.equal(decoration.range.startColumn, 1);
  assert.equal(decoration.range.endLineNumber, 2);
  assert.equal(decoration.range.endColumn, 14);
  assert.equal(decoration.options.isWholeLine, true);
  assert.equal(decoration.options.inlineClassName, "numoj-clangd-inactive-code");
  assert.equal(Object.hasOwn(decoration.options, "foreground"), false);

  responses.push(() => success(undefined, false));
  await provider.provideDocumentSemanticTokens(model, first.resultId, cancellation().token);
  assert.equal(decorationCalls.length, 2);
  assert.equal(decorationCalls[1].oldIds[0], "decoration-1");
  assert.deepEqual(decorationCalls[1].decorations, []);
  provider.releaseDocumentSemanticTokens(first.resultId);
  assert.equal(decorationCalls.length, 2);

  responses.push(() => success([]));
  await provider.provideDocumentSemanticTokens(model, null, cancellation().token);
  assert.equal(decorationCalls.length, 3);
  assert.deepEqual(decorationCalls[2].decorations, []);

  responses.push(() => success([{start: {line: 1, character: 0}, end: {line: 1, character: 3}}]));
  await provider.provideDocumentSemanticTokens(model, null, cancellation().token);
  responses.push(() => failure());
  await provider.provideDocumentSemanticTokens(model, null, cancellation().token);
  assert.equal(decorationCalls.length, 5);
  assert.deepEqual(decorationCalls[4].decorations, []);

  let resolveOld = null;
  responses.push(() => new Promise((resolve) => { resolveOld = resolve; }));
  const oldCancellation = cancellation();
  const oldRequest = provider.provideDocumentSemanticTokens(model, null, oldCancellation.token);
  oldCancellation.cancel();
  responses.push(() => success([{start: {line: 1, character: 4}, end: {line: 1, character: 12}}]));
  const fresh = await provider.provideDocumentSemanticTokens(model, null, cancellation().token);
  const callsAfterFreshResult = decorationCalls.length;
  resolveOld(success([{start: {line: 0, character: 0}, end: {line: 0, character: 5}}]));
  await oldRequest;
  assert.equal(decorationCalls.length, callsAfterFreshResult);

  provider.releaseDocumentSemanticTokens(fresh.resultId);
  assert.equal(decorationCalls.length, callsAfterFreshResult + 1);
  assert.deepEqual(decorationCalls.at(-1).decorations, []);

  responses.push(() => success([{start: {line: 1, character: 0}, end: {line: 1, character: 3}}]));
  await provider.provideDocumentSemanticTokens(model, null, cancellation().token);
  const callsBeforeDispose = decorationCalls.length;
  const disposeHandler = modelDisposeHandler;
  assert.ok(disposeHandler);
  disposeHandler();
  modelDisposed = true;
  assert.equal(modelDisposeListenerDisposals, 1);
  assert.equal(decorationCalls.length, callsBeforeDispose + 1);
  assert.deepEqual(decorationCalls.at(-1).decorations, []);
  const callsAfterModelDispose = decorationCalls.length;

  const liveModel = {
    getValue: model.getValue,
    isDisposed() { return false; },
    onWillDispose() {
      let listenerActive = true;
      return {dispose() {
        if (!listenerActive) return;
        listenerActive = false;
        liveModelListenerDisposals += 1;
      }};
    },
    validateRange: model.validateRange,
    deltaDecorations: model.deltaDecorations
  };
  responses.push(() => success([{start: {line: 1, character: 0}, end: {line: 1, character: 3}}]));
  await provider.provideDocumentSemanticTokens(liveModel, null, cancellation().token);
  assert.equal(decorationCalls.length, callsAfterModelDispose + 1);
  const callsBeforeProviderDispose = decorationCalls.length;
  registration.dispose();
  assert.equal(registrationDisposed, true);
  assert.equal(decorationCalls.length, callsBeforeProviderDispose + 1);
  assert.equal(modelDisposeListenerDisposals, 1);
  assert.equal(liveModelListenerDisposals, 1);

  const callsAfterCppDispose = decorationCalls.length;
  const pythonModel = {getValue() { return "print('active')"; }, deltaDecorations: model.deltaDecorations};
  const pythonRegistration = await NumOJSemanticTokens.register(monaco, {
    problemId: 42,
    language: "python",
    monacoLanguage: "python"
  });
  responses.push(() => success([{start: {line: 1, character: 0}, end: {line: 1, character: 3}}]));
  await provider.provideDocumentSemanticTokens(pythonModel, null, cancellation().token);
  pythonRegistration.dispose();
  assert.equal(decorationCalls.length, callsAfterCppDispose);
})().catch((error) => { console.error(error); process.exit(1); });
`)
})

test('inactive code 样式降低透明度但不覆盖语法颜色', () => {
  const stylesheet = read('frontend/public/static/styles/code-editor.css')
  const match = stylesheet.match(/\.monaco-editor \.numoj-clangd-inactive-code\s*\{([^}]*)\}/)
  assert.ok(match)
  assert.ok(match[1].includes('opacity: 0.55;'))
})

test('Markdown 语义客户端重试 pending 但不重试限流', () => {
  const source = JSON.stringify(asset('app/editor-semantic-tokens.js'))
  runIsolated(`
const assert = require("node:assert/strict");
global.window = global;
Math.random = () => 0;
let mode = "busy";
let calls = 0;
global.fetch = async function() {
  calls += 1;
  if (mode === "busy" && calls === 1) {
    return {
      ok: false,
      status: 429,
      headers: {get() { return "0.001"; }},
      async json() { return {success: false, code: "result_pending", message: "pending"}; }
    };
  }
  if (mode === "rate") {
    return {
      ok: false,
      status: 429,
      headers: {get() { return "1"; }},
      async json() { return {success: false, code: "rate_limited", message: "limited"}; }
    };
  }
  return {ok: true, status: 200, async json() { return {success: true, data: [0, 0, 3, 0, 0]}; }};
};
require(${source});
(async function() {
  await NumOJSemanticTokens.requestTokens({context: "markdown", language: "cpp", source: "int value;"});
  assert.equal(calls, 2);
  mode = "rate";
  calls = 0;
  await assert.rejects(
    NumOJSemanticTokens.requestTokens({context: "markdown", language: "cpp", source: "int other;"}),
    (error) => error.code === "rate_limited",
  );
  assert.equal(calls, 1);
})().catch((error) => { console.error(error); process.exit(1); });
`)
})
