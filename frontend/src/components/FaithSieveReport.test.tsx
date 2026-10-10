// @vitest-environment jsdom

import {cleanup, render} from '@testing-library/react'
import {afterEach, describe, expect, it, vi} from 'vitest'

import {FaithSieveReport} from './FaithSieveReport'

vi.mock('./useMarkdownEnhancements', () => ({useMarkdownEnhancements: vi.fn()}))

afterEach(() => cleanup())

describe('Faith Sieve 报告', () => {
  it('复用既有 Markdown 结构与增强入口', () => {
    const text = '## 结论\n\n**成立**\n\n\\[x_1 + x_2 = 2\\]'
    const html = '<h2>结论</h2><p><strong>成立</strong></p><p>\\[x_1 + x_2 = 2\\]</p>'
    const {container} = render(<FaithSieveReport text={text} html={html} className="stage-evidence" />)
    const root = container.querySelector('[data-numoj-markdown]')
    expect(root?.classList.contains('numoj-markdown')).toBe(true)
    expect(root?.classList.contains('stage-evidence')).toBe(true)
    expect(root?.querySelector('h2')?.textContent).toBe('结论')
    expect(root?.querySelector('strong')?.textContent).toBe('成立')
    expect(root?.textContent).toContain('\\[x_1 + x_2 = 2\\]')
  })

  it('无清洗 HTML 时将模型文本作为文本保留，防止执行标签', () => {
    const text = '<script>alert(1)</script>\n<img src=x onerror=alert(2)>\n\\[\\|v\\|_2^2 = 0\\]'
    const {container} = render(<FaithSieveReport text={text} />)
    expect(container.querySelector('script, img')).toBeNull()
    expect(container.textContent).toBe(text)
    expect(container.firstElementChild?.getAttribute('style')).toContain('white-space: pre-wrap')
  })

  it('报告更新时保留原始数学内容，不推断或改写公式', () => {
    const {container, rerender} = render(<FaithSieveReport text={'$a_b$'} />)
    const text = '||a_b||\n\\[e^{-2\\pi i f_\\ell t_n}\\to 1\\]'
    rerender(<FaithSieveReport text={text} />)
    expect(container.textContent).toBe(text)
  })
})
