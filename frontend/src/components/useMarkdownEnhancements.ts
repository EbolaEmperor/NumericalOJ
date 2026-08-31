import {useEffect, useLayoutEffect, type RefObject} from 'react'

import {getSemanticLegend, requestSemanticTokens, type SemanticLegend, type SemanticPayload, type TextPosition} from '../editor/semanticTokens'
import {clearMath, typesetMath} from '../markdown/mathjaxRuntime'

type HighlightToken = {content?: string; color?: string; fontStyle?: number}
type HighlightResult = {tokens?: HighlightToken[][]}
type CodeHighlighter = {tokenize: (source: string, language: string) => Promise<HighlightResult>}
type MermaidRuntime = {
  initialize: (options: Record<string, unknown>) => void
  parse: (source: string, options?: Record<string, unknown>) => Promise<boolean>
  run: (options: {nodes: Element[]}) => Promise<void>
}
type SourceRange = {start: number; end: number}
type SemanticRange = SourceRange & {type: string; modifiers: string[]}

const LANGUAGE_BY_CLASS = new Map([
  ['language-bash', 'bash'], ['language-sh', 'bash'], ['language-shell', 'bash'],
  ['language-shellscript', 'bash'], ['language-zsh', 'bash'], ['language-ksh', 'bash'],
  ['language-openrc', 'bash'], ['language-c', 'c'], ['language-cpp', 'cpp'],
  ['language-c++', 'cpp'], ['language-cc', 'cpp'], ['language-cxx', 'cpp'],
  ['language-py', 'python'], ['language-py3', 'python'], ['language-python', 'python'],
  ['language-python3', 'python'], ['language-m', 'matlab'], ['language-matlab', 'matlab'],
  ['language-octave', 'matlab'], ['language-lean', 'lean4'], ['language-lean4', 'lean4'],
])
const SHIKI_COLORS = new Set(['0550ae', '0a3069', '116329', '1f2328', '57606a', '6e7781', '82071e', '8250df', '953800', 'cf222e'])
const MAX_CODE_BLOCKS = 64
const MAX_SEMANTIC_BLOCKS = 16
const MAX_SOURCE_BYTES = 512 * 1024
const MAX_SEMANTIC_TOKENS = 12_000
const MAX_INACTIVE_RANGES = 4_096
let highlighterPromise: Promise<CodeHighlighter> | null = null
let mermaidPromise: Promise<MermaidRuntime> | null = null
let mermaidInitialized = false

function loadHighlighter() {
  if (highlighterPromise) return highlighterPromise
  const source = '/static/vendor/shiki-markdown/highlighter.js'
  highlighterPromise = import(/* @vite-ignore */ source)
    .then((module) => module as unknown as CodeHighlighter)
    .catch((error) => {highlighterPromise = null; throw error})
  return highlighterPromise
}

function loadMermaid() {
  if (mermaidPromise) return mermaidPromise
  mermaidPromise = import('mermaid')
    .then((module) => module.default as unknown as MermaidRuntime)
    .catch((error) => {mermaidPromise = null; throw error})
  return mermaidPromise
}

function languageFor(block: Element) {
  for (const className of block.classList) {
    const language = LANGUAGE_BY_CLASS.get(className.toLowerCase())
    if (language) return language
  }
  return ''
}

function enhanceLinks(root: HTMLElement) {
  root.querySelectorAll<HTMLAnchorElement>('a[href]').forEach((link) => {
    try {
      const url = new URL(link.href, window.location.href)
      if (url.origin !== window.location.origin) {
        link.target = '_blank'
        link.rel = 'noopener noreferrer'
      }
    } catch {
      link.removeAttribute('href')
    }
  })
}

async function copyText(text: string) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return
    } catch { /* Safari 的非安全上下文继续走兼容复制。 */ }
  }
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.readOnly = true
  textarea.setAttribute('aria-hidden', 'true')
  Object.assign(textarea.style, {position: 'fixed', left: '-9999px', opacity: '0'})
  document.body.appendChild(textarea)
  textarea.select()
  const copied = document.execCommand('copy')
  textarea.remove()
  if (!copied) throw new Error('clipboard-unavailable')
}

function ensureCopyButtons(root: HTMLElement) {
  root.querySelectorAll<HTMLElement>('pre code').forEach((code) => {
    const frame = code.closest<HTMLElement>('.codehilite') || code.closest<HTMLElement>('pre')
    if (!frame) return
    frame.classList.add('numoj-code-frame')
    if (Array.from(frame.children).some((child) => child.classList.contains('numoj-code-copy'))) return
    const button = document.createElement('button')
    const icon = document.createElement('i')
    const announcement = document.createElement('span')
    button.type = 'button'
    button.className = 'numoj-code-copy'
    button.setAttribute('aria-label', '复制代码')
    button.title = '复制代码'
    icon.className = 'numoj-code-copy-icon fas fa-copy'
    icon.setAttribute('aria-hidden', 'true')
    announcement.className = 'numoj-code-copy-announcement'
    announcement.setAttribute('aria-live', 'polite')
    announcement.setAttribute('aria-atomic', 'true')
    button.append(icon, announcement)
    button.addEventListener('click', async (event) => {
      event.preventDefault()
      event.stopPropagation()
      if (button.getAttribute('aria-busy') === 'true') return
      button.setAttribute('aria-busy', 'true')
      try {
        await copyText(code.textContent || '')
        button.classList.add('is-copied')
        icon.className = 'numoj-code-copy-icon fas fa-check'
        button.setAttribute('aria-label', '代码已复制')
        announcement.textContent = '代码已复制'
      } catch {
        button.classList.add('is-error')
        button.setAttribute('aria-label', '复制失败，请重试')
        announcement.textContent = '复制失败，请重试'
      } finally {
        button.removeAttribute('aria-busy')
        window.setTimeout(() => {
          button.classList.remove('is-copied', 'is-error')
          icon.className = 'numoj-code-copy-icon fas fa-copy'
          button.setAttribute('aria-label', '复制代码')
          announcement.textContent = ''
        }, 1800)
      }
    })
    frame.appendChild(button)
  })
}

function sourceBytes(source: string) {
  return new TextEncoder().encode(source).byteLength
}

function tokenFragment(result: HighlightResult) {
  if (!Array.isArray(result.tokens)) return null
  const fragment = document.createDocumentFragment()
  result.tokens.forEach((line, lineIndex) => {
    line.forEach((token) => {
      const content = String(token.content || '')
      if (!content) return
      const color = String(token.color || '').replace(/^#/, '').toLowerCase()
      const fontStyle = Number(token.fontStyle || 0)
      const colorClass = SHIKI_COLORS.has(color) ? `numoj-shiki-color-${color}` : ''
      if (!colorClass && !fontStyle) {
        fragment.appendChild(document.createTextNode(content))
        return
      }
      const span = document.createElement('span')
      span.className = 'numoj-shiki-token'
      if (colorClass) span.classList.add(colorClass)
      if (fontStyle & 1) span.classList.add('is-italic')
      if (fontStyle & 2) span.classList.add('is-bold')
      if (fontStyle & 4) span.classList.add('is-underlined')
      span.textContent = content
      fragment.appendChild(span)
    })
    if (lineIndex < result.tokens!.length - 1) fragment.appendChild(document.createTextNode('\n'))
  })
  return fragment
}

async function highlightCode(root: HTMLElement, signal: AbortSignal) {
  const blocks = Array.from(root.querySelectorAll<HTMLElement>('.codehilite'))
    .filter((block) => languageFor(block)).slice(0, MAX_CODE_BLOCKS)
  if (!blocks.length) return
  const highlighter = await loadHighlighter()
  if (signal.aborted) return
  for (const block of blocks) {
    if (signal.aborted || !root.isConnected || !root.contains(block)) return
    const code = block.querySelector<HTMLElement>('pre code')
    const language = languageFor(block)
    const source = code?.textContent || ''
    if (!code || !source || sourceBytes(source) > MAX_SOURCE_BYTES) continue
    try {
      const result = await highlighter.tokenize(source, language)
      if (signal.aborted || !root.isConnected || !code.isConnected || code.textContent !== source) continue
      const fragment = tokenFragment(result)
      if (!fragment || fragment.textContent !== source) continue
      code.replaceChildren(fragment)
      block.classList.add(language === 'bash' ? 'has-bash-textmate-highlighting' : 'has-structured-textmate-highlighting')
    } catch (error) {
      console.warn('文章代码块词法高亮失败，已保留当前配色。', error)
    }
    await new Promise((resolve) => window.setTimeout(resolve, 0))
  }
}

function lineOffsets(source: string) {
  const offsets = [0]
  for (let index = 0; index < source.length; index += 1) if (source.charCodeAt(index) === 10) offsets.push(index + 1)
  return offsets
}

function semanticName(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '')
}

function decodeSemantic(source: string, legend: SemanticLegend, data: number[]) {
  const offsets = lineOffsets(source)
  const types = legend.tokenTypes || []
  const modifiers = legend.tokenModifiers || []
  const ranges: SemanticRange[] = []
  let line = 0
  let column = 0
  for (let index = 0; index + 4 < data.length && ranges.length < MAX_SEMANTIC_TOKENS; index += 5) {
    const [deltaLine, deltaColumn, length, typeIndex, modifierBits] = data.slice(index, index + 5)
    if (![deltaLine, deltaColumn, length, typeIndex, modifierBits].every(Number.isInteger) || deltaLine < 0 || deltaColumn < 0 || length <= 0) continue
    line += deltaLine
    column = deltaLine === 0 ? column + deltaColumn : deltaColumn
    const type = types[typeIndex]
    if (!type || line >= offsets.length) continue
    const start = offsets[line] + column
    const nextLine = line + 1 < offsets.length ? offsets[line + 1] - 1 : source.length
    const end = start + length
    if (start < offsets[line] || end > nextLine) continue
    const activeModifiers = modifiers.filter((_, modifierIndex) => modifierIndex < 31 && (modifierBits & (1 << modifierIndex)) !== 0)
    ranges.push({start, end, type, modifiers: activeModifiers})
  }
  ranges.sort((left, right) => left.start - right.start || left.end - right.end)
  let previousEnd = 0
  return ranges.filter((range) => range.start >= previousEnd && (previousEnd = range.end) > 0)
}

function positionOffset(source: string, offsets: number[], position?: TextPosition) {
  const line = Number(position?.line)
  const character = Number(position?.character)
  if (!Number.isInteger(line) || !Number.isInteger(character) || line < 0 || character < 0 || line >= offsets.length) return null
  const end = line + 1 < offsets.length ? offsets[line + 1] - 1 : source.length
  return character <= end - offsets[line] ? offsets[line] + character : null
}

function decodeInactive(source: string, regions: SemanticPayload['inactive_regions']) {
  const offsets = lineOffsets(source)
  return (regions || []).slice(0, MAX_INACTIVE_RANGES).flatMap((region) => {
    const start = positionOffset(source, offsets, region.start)
    const end = positionOffset(source, offsets, region.end)
    return start !== null && end !== null && start < end ? [{start, end}] : []
  }).sort((left, right) => left.start - right.start || left.end - right.end)
}

function textEntries(code: HTMLElement) {
  const entries: Array<{node: Text; start: number; end: number}> = []
  const walker = document.createTreeWalker(code, NodeFilter.SHOW_TEXT)
  let offset = 0
  let node = walker.nextNode() as Text | null
  while (node) {
    entries.push({node, start: offset, end: offset + node.data.length})
    offset += node.data.length
    node = walker.nextNode() as Text | null
  }
  return entries
}

function wrapRanges(code: HTMLElement, ranges: SourceRange[], classFor: (range: SourceRange) => string[]) {
  let applied = 0
  for (const entry of textEntries(code)) {
    const segments = ranges.flatMap((range) => {
      const start = Math.max(range.start, entry.start)
      const end = Math.min(range.end, entry.end)
      return start < end ? [{start: start - entry.start, end: end - entry.start, range}] : []
    }).sort((left, right) => right.start - left.start)
    for (const segment of segments) {
      const selected = entry.node.splitText(segment.start)
      selected.splitText(segment.end - segment.start)
      const span = document.createElement('span')
      span.classList.add(...classFor(segment.range))
      selected.replaceWith(span)
      span.appendChild(selected)
      applied += 1
    }
  }
  return applied
}

async function enhanceSemanticCode(root: HTMLElement, signal: AbortSignal) {
  const blocks = Array.from(root.querySelectorAll<HTMLElement>('.codehilite'))
    .filter((block) => languageFor(block)).slice(0, MAX_SEMANTIC_BLOCKS)
  if (!blocks.length || signal.aborted) return
  if (signal.aborted) return
  for (const block of blocks) {
    const code = block.querySelector<HTMLElement>('pre code')
    const language = languageFor(block)
    const source = code?.textContent || ''
    if (!code || !source || sourceBytes(source) > MAX_SOURCE_BYTES) continue
    block.setAttribute('aria-busy', 'true')
    try {
      const legend = await getSemanticLegend(language, {signal})
      const payload = await requestSemanticTokens({context: 'markdown', language, source, signal})
      if (signal.aborted || !root.isConnected || !code.isConnected || code.textContent !== source) continue
      const semanticRanges = decodeSemantic(source, legend, payload.data || [])
      wrapRanges(code, semanticRanges, (range) => {
        const semantic = range as SemanticRange
        return ['numoj-semantic-token', `numoj-semantic-${semanticName(semantic.type)}`, ...semantic.modifiers.map((modifier) => `numoj-semantic-${semanticName(modifier)}`)]
      })
      if (wrapRanges(code, decodeInactive(source, payload.inactive_regions), () => ['numoj-clangd-inactive-code'])) block.classList.add('has-inactive-regions')
      block.classList.add('has-semantic-highlighting')
    } catch (error) {
      if (!signal.aborted) console.warn('文章代码块语义高亮失败，已保留词法配色。', error)
    } finally {
      block.removeAttribute('aria-busy')
    }
  }
}

async function renderMermaid(root: HTMLElement, signal: AbortSignal) {
  const blocks = Array.from(root.querySelectorAll<HTMLElement>('.codehilite.language-mermaid, .codehilite.language-mmd')).slice(0, 64)
  if (!blocks.length) return
  const mermaid = await loadMermaid()
  if (signal.aborted) return
  if (!mermaidInitialized) {
    mermaid.initialize({startOnLoad: false, securityLevel: 'sandbox', suppressErrorRendering: true, maxTextSize: 50_000, maxEdges: 500, htmlLabels: false, logLevel: 'fatal', theme: 'base'})
    mermaidInitialized = true
  }
  for (const block of blocks) {
    if (signal.aborted || !root.isConnected) return
    const source = block.querySelector('pre code')?.textContent || ''
    if (!source || source.length > 50_000) continue
    const diagram = document.createElement('div')
    diagram.className = 'numoj-mermaid-diagram mermaid'
    diagram.textContent = source
    block.classList.add('numoj-mermaid-source')
    block.replaceChildren(diagram)
    try {
      if (!await mermaid.parse(source, {suppressErrors: true})) throw new Error('invalid-mermaid')
      if (!signal.aborted && block.isConnected) await mermaid.run({nodes: [diagram]})
    } catch {
      if (!signal.aborted && block.isConnected) {
        block.classList.add('is-error')
        block.replaceChildren(document.createTextNode(source))
      }
    }
  }
}

function useMathJax(rootRef: RefObject<HTMLElement | null>, html: string) {
  useLayoutEffect(() => {
    const root = rootRef.current
    if (!root) return
    let active = true
    root.dataset.numojMathState = 'pending'
    void typesetMath(root).then(() => {
      if (active && root.isConnected) root.dataset.numojMathState = 'rendered'
    }).catch((error) => {
      if (active) {
        root.dataset.numojMathState = 'error'
        console.warn('公式排版失败，已保留原始内容。', error)
      }
    })
    return () => {
      active = false
      clearMath(root)
    }
  }, [html, rootRef])
}

export function useMarkdownEnhancements(rootRef: RefObject<HTMLElement | null>, html: string) {
  useMathJax(rootRef, html)
  useEffect(() => {
    const root = rootRef.current
    if (!root) return
    const controller = new AbortController()
    enhanceLinks(root)
    ensureCopyButtons(root)
    void highlightCode(root, controller.signal)
      .then(() => enhanceSemanticCode(root, controller.signal))
      .catch((error) => {if (!controller.signal.aborted) console.warn('代码高亮增强失败，已保留当前配色。', error)})
    void renderMermaid(root, controller.signal)
      .catch((error) => {if (!controller.signal.aborted) console.warn('Mermaid 图表渲染失败，已保留源码。', error)})
    return () => controller.abort()
  }, [html, rootRef])
}
