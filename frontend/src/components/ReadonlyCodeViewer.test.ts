import {describe, expect, it} from 'vitest'

import {highlightedLinesMatchSource, normalizeCodeSource, readonlyTokenClass} from './ReadonlyCodeViewer'

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
})
