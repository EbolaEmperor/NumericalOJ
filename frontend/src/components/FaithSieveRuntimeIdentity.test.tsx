// @vitest-environment jsdom

import {cleanup, render} from '@testing-library/react'
import {afterEach, describe, expect, it} from 'vitest'

import {FaithSieveHarness, FaithSieveModel} from './FaithSieveRuntimeIdentity'

afterEach(() => cleanup())
describe('Faith Sieve 运行身份', () => {
  it.each([['pi', 'pi', 'Pi'], ['claude_code', 'claude-code', 'Claude Code'], ['claude-code', 'claude-code', 'Claude Code']])('Harness %s复用现有名称和logo映射', (harness, family, label) => {
    const {container} = render(<FaithSieveHarness harness={harness} />)
    expect(container.querySelector('[data-harness-logo]')?.classList.contains(`harness-logo--${family}`)).toBe(true)
    expect(container.textContent).toBe(label)
  })
  it.each([['pi', 'pi', 'Pi'], ['claude_code', 'claude-code', 'Claude Code'], ['claude-code', 'claude-code', 'Claude Code']])('列表中的%s只显示logo，不添加悬停提示', (harness, family, label) => {
    const {container, getByRole} = render(<FaithSieveHarness harness={harness} iconOnly />)
    expect(container.textContent).toBe('')
    expect(getByRole('img', {name: label})).toBeTruthy()
    expect(container.querySelector('[title]')).toBeNull()
    expect(container.querySelector('[data-harness-logo]')?.classList.contains(`harness-logo--${family}`)).toBe(true)
  })
  it.each([['qwen3.5', 'qwen'], ['claude-sonnet', 'claude'], ['gpt-5.5', 'openai']])('模型%s复用现有名称解析', (model, family) => {
    const {container} = render(<FaithSieveModel model={model} />)
    expect(container.querySelector('[data-model-family-logo]')?.getAttribute('data-model-family')).toBe(family)
    expect(container.textContent).toBe(model)
  })
  it('未知模型使用现有通用芯片图标', () => {
    const {container} = render(<FaithSieveModel model="unbranded-model" />)
    expect(container.querySelector('[data-model-family-logo]')?.classList.contains('fa-microchip')).toBe(true)
  })
})
