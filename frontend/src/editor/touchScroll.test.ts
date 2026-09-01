import {describe, expect, it} from 'vitest'

import {shouldHandOffTouchScroll} from './touchScroll'

describe('shouldHandOffTouchScroll', () => {
  it('代码框滚到底后把继续向下的手势交给页面', () => {
    expect(shouldHandOffTouchScroll({deltaX: 1, deltaY: 18, scrollTop: 600, scrollHeight: 900, viewportHeight: 300})).toBe(true)
  })

  it('代码框在顶部时把继续向上的手势交给页面', () => {
    expect(shouldHandOffTouchScroll({deltaX: 0, deltaY: -16, scrollTop: 0, scrollHeight: 900, viewportHeight: 300})).toBe(true)
  })

  it('代码框内部仍优先处理纵向滚动', () => {
    expect(shouldHandOffTouchScroll({deltaX: 1, deltaY: 20, scrollTop: 240, scrollHeight: 900, viewportHeight: 300})).toBe(false)
  })

  it('横向手势不会误触发页面滚动接力', () => {
    expect(shouldHandOffTouchScroll({deltaX: 24, deltaY: 8, scrollTop: 600, scrollHeight: 900, viewportHeight: 300})).toBe(false)
  })
})
