import type {MonacoApi, MonacoEditorInstance} from './types'

export type LanguageSpec = {language: string | null; monacoLanguage: string; label: string}

const LANGUAGE_SPECS: Record<string, LanguageSpec> = {
  c: {language: 'c', monacoLanguage: 'c', label: 'C'},
  cpp: {language: 'cpp', monacoLanguage: 'cpp', label: 'C++'},
  python: {language: 'python', monacoLanguage: 'python', label: 'Python'},
  matlab: {language: 'matlab', monacoLanguage: 'matlab', label: 'MATLAB / Octave'},
  lean4: {language: 'lean4', monacoLanguage: 'lean4', label: 'Lean 4'},
  plaintext: {language: null, monacoLanguage: 'plaintext', label: 'Plain Text'},
}

const aliases: Record<string, string> = {py: 'python', octave: 'matlab', lean: 'lean4'}
const textMateStates = new WeakMap<MonacoApi, {promise: Promise<boolean>; status: 'pending' | 'ready' | 'failed'; themeScheduled: boolean}>()

export function languageSpec(value: string) {
  const normalized = aliases[String(value || '').toLowerCase()] || String(value || '').toLowerCase()
  return {...(LANGUAGE_SPECS[normalized] || {language: normalized || null, monacoLanguage: normalized || 'plaintext', label: normalized || 'Plain Text'})}
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
