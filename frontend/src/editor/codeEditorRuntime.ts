import type {MonacoApi, MonacoEditorInstance} from './types'

export type LanguageSpec = {language: string | null; monacoLanguage: string; label: string}

const LANGUAGE_SPECS: Record<string, LanguageSpec> = {
  c: {language: 'c', monacoLanguage: 'c', label: 'C'},
  cpp: {language: 'cpp', monacoLanguage: 'cpp', label: 'C++'},
  python: {language: 'python', monacoLanguage: 'python', label: 'Python'},
  matlab: {language: 'matlab', monacoLanguage: 'matlab', label: 'MATLAB / Octave'},
  lean4: {language: 'lean4', monacoLanguage: 'lean4', label: 'Lean 4'},
  javascript: {language: 'javascript', monacoLanguage: 'javascript', label: 'JavaScript'},
  jsx: {language: 'jsx', monacoLanguage: 'jsx', label: 'JavaScript JSX'},
  typescript: {language: 'typescript', monacoLanguage: 'typescript', label: 'TypeScript'},
  tsx: {language: 'tsx', monacoLanguage: 'tsx', label: 'TypeScript TSX'},
  java: {language: 'java', monacoLanguage: 'java', label: 'Java'},
  csharp: {language: 'csharp', monacoLanguage: 'csharp', label: 'C#'},
  go: {language: 'go', monacoLanguage: 'go', label: 'Go'},
  rust: {language: 'rust', monacoLanguage: 'rust', label: 'Rust'},
  php: {language: 'php', monacoLanguage: 'php', label: 'PHP'},
  ruby: {language: 'ruby', monacoLanguage: 'ruby', label: 'Ruby'},
  shell: {language: 'shell', monacoLanguage: 'shell', label: 'Shell'},
  powershell: {language: 'powershell', monacoLanguage: 'powershell', label: 'PowerShell'},
  bat: {language: 'bat', monacoLanguage: 'bat', label: 'Batch'},
  sql: {language: 'sql', monacoLanguage: 'sql', label: 'SQL'},
  html: {language: 'html', monacoLanguage: 'html', label: 'HTML'},
  css: {language: 'css', monacoLanguage: 'css', label: 'CSS'},
  scss: {language: 'scss', monacoLanguage: 'scss', label: 'SCSS'},
  less: {language: 'less', monacoLanguage: 'less', label: 'Less'},
  json: {language: 'json', monacoLanguage: 'json', label: 'JSON'},
  yaml: {language: 'yaml', monacoLanguage: 'yaml', label: 'YAML'},
  xml: {language: 'xml', monacoLanguage: 'xml', label: 'XML'},
  dockerfile: {language: 'dockerfile', monacoLanguage: 'dockerfile', label: 'Dockerfile'},
  latex: {language: 'latex', monacoLanguage: 'latex', label: 'LaTeX'},
  lua: {language: 'lua', monacoLanguage: 'lua', label: 'Lua'},
  kotlin: {language: 'kotlin', monacoLanguage: 'kotlin', label: 'Kotlin'},
  swift: {language: 'swift', monacoLanguage: 'swift', label: 'Swift'},
  r: {language: 'r', monacoLanguage: 'r', label: 'R'},
  julia: {language: 'julia', monacoLanguage: 'julia', label: 'Julia'},
  dart: {language: 'dart', monacoLanguage: 'dart', label: 'Dart'},
  scala: {language: 'scala', monacoLanguage: 'scala', label: 'Scala'},
  perl: {language: 'perl', monacoLanguage: 'perl', label: 'Perl'},
  solidity: {language: 'solidity', monacoLanguage: 'solidity', label: 'Solidity'},
  protobuf: {language: 'protobuf', monacoLanguage: 'protobuf', label: 'Protocol Buffers'},
  graphql: {language: 'graphql', monacoLanguage: 'graphql', label: 'GraphQL'},
  ini: {language: 'ini', monacoLanguage: 'ini', label: 'INI'},
  cmake: {language: 'cmake', monacoLanguage: 'cmake', label: 'CMake'},
  makefile: {language: 'makefile', monacoLanguage: 'makefile', label: 'Makefile'},
  asm: {language: 'asm', monacoLanguage: 'asm', label: 'Assembly'},
  fsharp: {language: 'fsharp', monacoLanguage: 'fsharp', label: 'F#'},
  vb: {language: 'vb', monacoLanguage: 'vb', label: 'Visual Basic'},
  clojure: {language: 'clojure', monacoLanguage: 'clojure', label: 'Clojure'},
  coffeescript: {language: 'coffeescript', monacoLanguage: 'coffeescript', label: 'CoffeeScript'},
  elixir: {language: 'elixir', monacoLanguage: 'elixir', label: 'Elixir'},
  erlang: {language: 'erlang', monacoLanguage: 'erlang', label: 'Erlang'},
  groovy: {language: 'groovy', monacoLanguage: 'groovy', label: 'Groovy'},
  haskell: {language: 'haskell', monacoLanguage: 'haskell', label: 'Haskell'},
  'objective-c': {language: 'objective-c', monacoLanguage: 'objective-c', label: 'Objective-C'},
  pascal: {language: 'pascal', monacoLanguage: 'pascal', label: 'Pascal'},
  scheme: {language: 'scheme', monacoLanguage: 'scheme', label: 'Scheme'},
  systemverilog: {language: 'systemverilog', monacoLanguage: 'systemverilog', label: 'SystemVerilog'},
  tcl: {language: 'tcl', monacoLanguage: 'tcl', label: 'Tcl'},
  toml: {language: 'toml', monacoLanguage: 'toml', label: 'TOML'},
  verilog: {language: 'verilog', monacoLanguage: 'verilog', label: 'Verilog'},
  plaintext: {language: null, monacoLanguage: 'plaintext', label: 'Plain Text'},
}

const aliases: Record<string, string> = {
  py: 'python', octave: 'matlab', lean: 'lean4', js: 'javascript', ts: 'typescript',
  cs: 'csharp', 'c#': 'csharp', sh: 'shell', bash: 'shell', zsh: 'shell', tex: 'latex',
  objective_c: 'objective-c', objc: 'objective-c', 'system-verilog': 'systemverilog', sv: 'systemverilog',
}
const filenameLanguages: Record<string, string> = {
  dockerfile: 'dockerfile', 'dockerfile.dev': 'dockerfile', gemfile: 'ruby', makefile: 'makefile',
  gnumakefile: 'makefile', rakefile: 'ruby', cmakelists: 'cmake', 'cmakelists.txt': 'cmake',
}
const extensionLanguages: Record<string, string> = {
  c: 'c', cc: 'cpp', cpp: 'cpp', cxx: 'cpp', h: 'cpp', hh: 'cpp', hpp: 'cpp', hxx: 'cpp',
  py: 'python', pyw: 'python', pyi: 'python', m: 'matlab', lean: 'lean4',
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'jsx', ts: 'typescript', mts: 'typescript', cts: 'typescript', tsx: 'tsx',
  java: 'java', cs: 'csharp', go: 'go', rs: 'rust', php: 'php', rb: 'ruby',
  sh: 'shell', bash: 'shell', zsh: 'shell', fish: 'shell', ps1: 'powershell', bat: 'bat', cmd: 'bat', sql: 'sql',
  html: 'html', htm: 'html', xhtml: 'html', vue: 'html', css: 'css', scss: 'scss', sass: 'scss', less: 'less',
  json: 'json', jsonc: 'json', jsonl: 'json', ipynb: 'json', yaml: 'yaml', yml: 'yaml',
  xml: 'xml', xsd: 'xml', xsl: 'xml', svg: 'xml', tex: 'latex', sty: 'latex', cls: 'latex', bib: 'latex',
  lua: 'lua', kt: 'kotlin', kts: 'kotlin', swift: 'swift', r: 'r', jl: 'julia', dart: 'dart',
  scala: 'scala', sc: 'scala', pl: 'perl', pm: 'perl', sol: 'solidity', proto: 'protobuf',
  graphql: 'graphql', gql: 'graphql', ini: 'ini', cfg: 'ini', conf: 'ini', toml: 'toml', cmake: 'cmake', dockerfile: 'dockerfile',
  asm: 'asm', s: 'asm', fs: 'fsharp', fsx: 'fsharp', vb: 'vb', clj: 'clojure', cljs: 'clojure',
  coffee: 'coffeescript', ex: 'elixir', exs: 'elixir', erl: 'erlang', hrl: 'erlang', groovy: 'groovy',
  hs: 'haskell', lhs: 'haskell', mm: 'objective-c', pas: 'pascal', scm: 'scheme', sv: 'systemverilog',
  svh: 'systemverilog', tcl: 'tcl', v: 'verilog', vh: 'verilog',
}
const textMateStates = new WeakMap<MonacoApi, {promise: Promise<boolean>; status: 'pending' | 'ready' | 'failed'; themeScheduled: boolean}>()

export function languageSpec(value: string) {
  const normalized = aliases[String(value || '').toLowerCase()] || String(value || '').toLowerCase()
  return {...(LANGUAGE_SPECS[normalized] || LANGUAGE_SPECS.plaintext)}
}

export function languageSpecForFilename(filename: string) {
  const basename = String(filename || '').split(/[\\/]/).pop()?.toLowerCase() || ''
  const pieces = basename.split('.')
  const extension = pieces.length > 1 ? pieces.pop() || '' : ''
  const language = filenameLanguages[basename]
    || filenameLanguages[basename.replace(/\.[^.]+$/, '')]
    || extensionLanguages[extension]
    || 'plaintext'
  const spec = languageSpec(language)
  if (extension === 'c') spec.label = 'C Source'
  if (extension === 'h') spec.label = 'C++ Header'
  if (['cc', 'cpp', 'cxx'].includes(extension)) spec.label = 'C++ Source'
  if (['hh', 'hpp', 'hxx'].includes(extension)) spec.label = 'C++ Header'
  return spec
}

function registerMatlab(monaco: MonacoApi) {
  if (monaco.languages.getLanguages().some((item) => item.id === 'matlab')) return
  monaco.languages.register({id: 'matlab', extensions: ['.m'], aliases: ['MATLAB', 'matlab']})
  monaco.languages.setLanguageConfiguration('matlab', {
    comments: {lineComment: '%'}, brackets: [['(', ')'], ['[', ']'], ['{', '}']],
    autoClosingPairs: [{open: '(', close: ')'}, {open: '[', close: ']'}, {open: '{', close: '}'}, {open: "'", close: "'", notIn: ['string', 'comment']}, {open: '"', close: '"', notIn: ['string', 'comment']}],
    indentationRules: {increaseIndentPattern: /^\s*(?:if|for|while|switch|try|function|classdef|properties|methods|events|enumeration)\b(?!.*\bend\b).*$/i, decreaseIndentPattern: /^\s*(?:end|else|elseif|case|otherwise|catch)\b/i},
  })
  monaco.languages.setMonarchTokensProvider('matlab', {defaultToken: '', tokenPostfix: '.matlab', keywords: ['break', 'case', 'catch', 'classdef', 'continue', 'else', 'elseif', 'end', 'for', 'function', 'global', 'if', 'otherwise', 'return', 'switch', 'try', 'while'], constants: ['true', 'false', 'NaN', 'Inf', 'pi', 'eps'], tokenizer: {root: [[/%\{/, 'comment', '@commentBlock'], [/%.*$/, 'comment'], [/[a-zA-Z_]\w*/, {cases: {'@keywords': 'keyword', '@constants': 'constant', '@default': 'identifier'}}], [/\d*\.\d+(?:[eE][+-]?\d+)?[ij]?/, 'number.float'], [/\d+(?:[eE][+-]?\d+)?[ij]?/, 'number'], [/'(?:[^']|'')*'/, 'string'], [/"(?:[^"]|"")*"/, 'string'], [/[{}()[\]]/, '@brackets'], [/[+\-*/\\^~<>=&|:@.]+/, 'operator'], [/[;,]/, 'delimiter']], commentBlock: [[/%\}/, 'comment', '@pop'], [/./, 'comment']]}})
}

function registerLean4(monaco: MonacoApi) {
  if (monaco.languages.getLanguages().some((item) => item.id === 'lean4')) return
  monaco.languages.register({id: 'lean4', extensions: ['.lean'], aliases: ['Lean 4', 'lean4', 'lean']})
  monaco.languages.setLanguageConfiguration('lean4', {comments: {lineComment: '--', blockComment: ['/-', '-/']}, brackets: [['(', ')'], ['[', ']'], ['{', '}']], autoClosingPairs: [{open: '(', close: ')'}, {open: '[', close: ']'}, {open: '{', close: '}'}, {open: '"', close: '"', notIn: ['string', 'comment']}], indentationRules: {increaseIndentPattern: /(?:\b(?:by|do|where|match|with|then|else)\s*$|:=\s*$|=>\s*$)/, decreaseIndentPattern: /^\s*(?:end\b|\|)/}})
  monaco.languages.setMonarchTokensProvider('lean4', {defaultToken: '', tokenPostfix: '.lean4', keywords: ['abbrev', 'axiom', 'class', 'def', 'do', 'else', 'end', 'example', 'fun', 'if', 'import', 'in', 'inductive', 'instance', 'let', 'match', 'namespace', 'open', 'section', 'structure', 'theorem', 'variable', 'where', 'with'], tacticKeywords: ['aesop', 'apply', 'assumption', 'by', 'cases', 'constructor', 'exact', 'have', 'induction', 'intro', 'linarith', 'norm_num', 'omega', 'rfl', 'ring', 'rw', 'simp', 'simpa'], tokenizer: {root: [[/\/-/, 'comment', '@comment'], [/--.*$/, 'comment'], [/"/, 'string', '@string'], [/[0-9]+(?:\.[0-9]+)?/, 'number'], [/[\p{L}\p{Nl}_][\p{L}\p{Nl}\p{Nd}_'\u2080-\u209f\u2070-\u207f]*/u, {cases: {'@keywords': 'keyword', '@tacticKeywords': 'keyword.flow', '@default': 'identifier'}}], [/[{}()[\]]/, '@brackets'], [/[,:;.]/, 'delimiter'], [/[!#$%&*+\-./:<=>?@\\^|~\u2190-\u22ff]+/, 'operator']], comment: [[/\/-/, 'comment', '@push'], [/-\//, 'comment', '@pop'], [/./, 'comment']], string: [[/[^\\"]+/, 'string'], [/\\./, 'string.escape'], [/"/, 'string', '@pop']]}})
}

function textMateState(monaco: MonacoApi) {
  const current = textMateStates.get(monaco)
  if (current) return current
  const state = {status: 'pending' as const, themeScheduled: false, promise: Promise.resolve(false)} as {promise: Promise<boolean>; status: 'pending' | 'ready' | 'failed'; themeScheduled: boolean}
  state.promise = Promise.resolve(monaco.prepareTextMateHighlighting?.()).then(() => {state.status = 'ready'; return true}, (error) => {state.status = 'failed'; console.warn('VS Code 语法 grammar 初始化失败，已降级为 Monaco 基础着色。', error); return false})
  textMateStates.set(monaco, state)
  return state
}

export function prepareMonaco(monaco: MonacoApi) {
  registerMatlab(monaco)
  registerLean4(monaco)
  if (!monaco.prepareTextMateHighlighting) return 'vs-dark'
  const state = textMateState(monaco)
  if (state.status === 'ready') return 'dark-plus'
  if (state.status === 'failed') return 'vs-dark'
  if (!state.themeScheduled) {
    state.themeScheduled = true
    void state.promise.then((ready) => {if (ready) setTimeout(() => monaco.editor.setTheme?.('dark-plus'), 0)})
  }
  return 'vs-dark'
}

export function monacoOptions(overrides: Record<string, unknown>) {
  return {theme: 'dark-plus', 'semanticHighlighting.enabled': true, automaticLayout: true, fontFamily: 'SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace', fontSize: 14, lineHeight: 22, lineNumbersMinChars: 3, minimap: {enabled: false}, padding: {top: 14, bottom: 14}, roundedSelection: false, scrollBeyondLastLine: false, smoothScrolling: true, tabSize: 4, insertSpaces: true, detectIndentation: false, wordWrap: 'on', bracketPairColorization: {enabled: true}, guides: {bracketPairs: true, indentation: true}, quickSuggestions: false, suggestOnTriggerCharacters: false, contextmenu: true, find: {addExtraSpaceOnTop: false}, ...overrides}
}

export function attachLeanUnicodeInput(monaco: MonacoApi, editor: MonacoEditorInstance) {
  return monaco.attachLean4UnicodeInput?.(editor) || null
}
