// @vitest-environment jsdom

import {cleanup, render} from '@testing-library/react'
import {afterEach, describe, expect, it} from 'vitest'

import {ModelLogo} from './ModelLogo'

afterEach(() => {
  cleanup()
})

describe('ModelLogo', () => {
  it('使用 TypeScript 模型厂商解析器生成并刷新 Logo', () => {
    const view = render(<ModelLogo model="qwen3.6-plus" />)
    const logo = view.container.querySelector('i')

    expect(logo?.classList.contains('model-family-logo')).toBe(true)
    expect(logo?.classList.contains('model-family-logo--qwen')).toBe(true)

    view.rerender(<ModelLogo model="deepseek-v4-pro" />)

    expect(view.container.querySelector('i')?.classList.contains('model-family-logo--deepseek')).toBe(true)
  })

  it('无法识别厂商时保留通用芯片图标', () => {
    const view = render(<ModelLogo model="unknown-local-model" />)

    expect(view.container.querySelector('i')?.classList.contains('fas')).toBe(true)
    expect(view.container.querySelector('i')?.classList.contains('fa-microchip')).toBe(true)
  })
})
