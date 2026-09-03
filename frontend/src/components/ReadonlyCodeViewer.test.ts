import {describe, expect, it} from 'vitest'

import {highlightedLinesMatchSource, normalizeCodeSource, readonlyIssueReasons, readonlyTokenClass} from './ReadonlyCodeViewer'

describe('ReadonlyCodeViewer', () => {
  it('统一换行后仍保留空行和末尾空行', () => {
    expect(normalizeCodeSource('a\r\n\r\nb\r').split('\n')).toEqual(['a', '', 'b', ''])
  })

  it('只接受逐行完全对应原代码的高亮结果', () => {
    expect(highlightedLinesMatchSource(['x = 1', ''], [[{content: 'x = '}, {content: '1'}], []])).toBe(true)
    expect(highlightedLinesMatchSource(['x = 1'], [[{content: 'x = 2'}]])).toBe(false)
  })

  it('只把 Dark+ 固定色板转换为 CSP 安全类名', () => {
    expect(readonlyTokenClass({color: '#569CD6', content: 'function', fontStyle: 2})).toBe('submission-code-token is-color-569cd6 is-bold')
    expect(readonlyTokenClass({color: '#123456', content: 'value'})).toBe('submission-code-token')
  })

  it('把 AI 诊断范围限制到只读代码的实际行号内', () => {
    const reasons = readonlyIssueReasons(4, [
      {line_start: 3, line_end: 2, reason: '边界错误'},
      {line_start: 99, reason: '末行错误'},
    ])
    expect(reasons.get(1)).toBeUndefined()
    expect(reasons.get(2)).toEqual(['边界错误'])
    expect(reasons.get(3)).toEqual(['边界错误'])
    expect(reasons.get(4)).toEqual(['末行错误'])
  })
})
