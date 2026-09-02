// @vitest-environment jsdom

import {afterEach, describe, expect, it, vi} from 'vitest'

import {copyText} from './clipboard'

afterEach(() => {
  vi.restoreAllMocks()
  Object.defineProperty(navigator, 'clipboard', {configurable: true, value: undefined})
  Reflect.deleteProperty(document, 'execCommand')
})

describe('copyText', () => {
  it('在安全上下文中优先使用 Clipboard API', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {writeText}})

    await copyText('https://example.test')

    expect(writeText).toHaveBeenCalledWith('https://example.test')
  })

  it('HTTP 环境回退到临时文本框复制', async () => {
    Object.defineProperty(navigator, 'clipboard', {configurable: true, value: undefined})
    const execute = vi.fn().mockReturnValue(true)
    Object.defineProperty(document, 'execCommand', {configurable: true, value: execute})

    await copyText('plain http text')

    expect(execute).toHaveBeenCalledWith('copy')
    expect(document.querySelector('textarea')).toBeNull()
  })

  it('两种复制能力均不可用时明确失败', async () => {
    Object.defineProperty(navigator, 'clipboard', {configurable: true, value: undefined})
    Object.defineProperty(document, 'execCommand', {configurable: true, value: vi.fn().mockReturnValue(false)})

    await expect(copyText('cannot copy')).rejects.toThrow('复制失败')
  })
})
