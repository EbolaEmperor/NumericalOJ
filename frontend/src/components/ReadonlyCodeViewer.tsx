import {useEffect, useMemo, useState} from 'react'

type HighlightToken = {color?: string; content?: string; fontStyle?: number}
type HighlightResult = {tokens?: HighlightToken[][]}
type CodeHighlighter = {tokenize: (source: string, language: string, theme?: 'light' | 'dark') => Promise<HighlightResult>}

const DARK_TOKEN_COLORS = new Set([
  '4ec9b0', '4fc1ff', '569cd6', '608b4e', '646695', '6a9955', '808080',
  '9cdcfe', 'b5cea8', 'c586c0', 'c8c8c8', 'ce9178', 'd16969', 'd4d4d4',
  'd7ba7d', 'dcdcaa', 'f44747',
])
const highlightCache = new Map<string, HighlightToken[][]>()
let highlighterPromise: Promise<CodeHighlighter> | null = null

function loadHighlighter() {
  if (highlighterPromise) return highlighterPromise
  const source = '/static/vendor/shiki-markdown/highlighter.js'
  highlighterPromise = import(/* @vite-ignore */ source)
    .then((module) => module as unknown as CodeHighlighter)
    .catch((error) => {highlighterPromise = null; throw error})
  return highlighterPromise
}

export function normalizeCodeSource(source: string) {
  return String(source || '').replace(/\r\n?/g, '\n')
}

export function highlightedLinesMatchSource(sourceLines: string[], tokens?: HighlightToken[][]) {
  return Array.isArray(tokens)
    && tokens.length === sourceLines.length
    && tokens.every((line, index) => line.map((token) => String(token.content || '')).join('') === sourceLines[index])
}

export function readonlyTokenClass(token: HighlightToken) {
  const classes = ['submission-code-token']
  const color = String(token.color || '').replace(/^#/, '').toLowerCase()
  const fontStyle = Number(token.fontStyle || 0)
  if (DARK_TOKEN_COLORS.has(color)) classes.push(`is-color-${color}`)
  if (fontStyle & 1) classes.push('is-italic')
  if (fontStyle & 2) classes.push('is-bold')
  if (fontStyle & 4) classes.push('is-underlined')
  return classes.join(' ')
}

export function readonlyIssueReasons(lineCount: number, issues: unknown) {
  const reasons = new Map<number, string[]>()
  if (!Array.isArray(issues)) return reasons
  issues.forEach((raw) => {
    const issue = raw && typeof raw === 'object' ? raw as Record<string, unknown> : {}
    let start = Number.parseInt(String(issue.line_start || 1), 10)
    let end = Number.parseInt(String(issue.line_end || start), 10)
    if (!Number.isFinite(start)) start = 1
    if (!Number.isFinite(end)) end = start
    if (start > end) [start, end] = [end, start]
    start = Math.max(1, Math.min(lineCount || 1, start))
    end = Math.max(1, Math.min(lineCount || 1, end))
    const reason = String(issue.reason || '这里可能有问题').trim()
    for (let line = start; line <= end; line += 1) {
      const current = reasons.get(line) || []
      if (!current.includes(reason)) current.push(reason)
      reasons.set(line, current)
    }
  })
  return reasons
}

function cachedHighlight(key: string) {
  return highlightCache.get(key) || null
}

function rememberHighlight(key: string, tokens: HighlightToken[][]) {
  highlightCache.set(key, tokens)
  while (highlightCache.size > 12) highlightCache.delete(highlightCache.keys().next().value as string)
}

export function ReadonlyCodeViewer({language, value, ariaLabel, issues}: {language: string; value: string; ariaLabel: string; issues?: unknown}) {
  const source = useMemo(() => normalizeCodeSource(value), [value])
  const sourceLines = useMemo(() => source.split('\n'), [source])
  const issueReasons = useMemo(() => readonlyIssueReasons(sourceLines.length, issues), [issues, sourceLines.length])
  const cacheKey = `${String(language || '').toLowerCase()}\u0000${source}`
  const [tokens, setTokens] = useState<HighlightToken[][] | null>(() => cachedHighlight(cacheKey))

  useEffect(() => {
    let cancelled = false
    const cached = cachedHighlight(cacheKey)
    if (cached) {
      setTokens(cached)
      return () => {cancelled = true}
    }
    setTokens(null)
    void loadHighlighter().then((highlighter) => highlighter.tokenize(source, language, 'dark')).then((result) => {
      if (cancelled || !highlightedLinesMatchSource(sourceLines, result.tokens)) return
      rememberHighlight(cacheKey, result.tokens!)
      setTokens(result.tokens!)
    }).catch((error) => {
      if (!cancelled) console.warn('提交代码词法高亮失败，已保留纯文本显示。', error)
    })
    return () => {cancelled = true}
  }, [cacheKey, language, source, sourceLines])

  return <div className="submission-static-code-viewer" role="region" aria-label={ariaLabel} data-language={language}>
    <pre className="submission-static-code"><code>
      {sourceLines.map((line, lineIndex) => {const reasons = issueReasons.get(lineIndex + 1); return <span className="submission-static-code-line" key={lineIndex}>
        <span className="submission-static-code-line-number" aria-hidden="true">{lineIndex + 1}</span>
        <span className={`submission-static-code-line-content${reasons ? ' monaco-ai-issue-underline' : ''}`} title={reasons?.join('\n')}>{tokens ? tokens[lineIndex].map((token, tokenIndex) => <span className={readonlyTokenClass(token)} key={tokenIndex}>{token.content}</span>) : line}</span>
      </span>})}
    </code></pre>
  </div>
}
