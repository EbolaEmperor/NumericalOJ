// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {useRef} from 'react'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {usePersistentVerticalSplitter} from './usePersistentVerticalSplitter'

const valueText = (leading: number, trailing: number) => `信息 ${leading}%，内容 ${trailing}%`

function SplitPane() {
  const containerRef = useRef<HTMLDivElement>(null)
  const splitterRef = useRef<HTMLDivElement>(null)
  usePersistentVerticalSplitter({
    containerRef,
    splitterRef,
    storageKey: 'numoj.test.splitRatio',
    cssVariable: '--test-leading-width',
    defaultRatio: 0.5,
    minimumLeadingPixels: 300,
    minimumTrailingPixels: 400,
    resizingClassName: 'is-test-pane-resizing',
    valueText,
  })
  return <div ref={containerRef} data-testid="split-container">
    <section>信息</section>
    <div ref={splitterRef} role="separator" tabIndex={0} aria-label="调整宽度" />
    <section>内容</section>
  </div>
}

beforeEach(() => {
  window.localStorage.clear()
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: vi.fn(() => ({
      matches: true,
      media: '(min-width: 992px)',
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  })
  vi.stubGlobal('ResizeObserver', class {
    observe() {}
    unobserve() {}
    disconnect() {}
  })
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
    if (this.getAttribute('role') === 'separator') {
      const leading = Number.parseFloat(this.parentElement?.style.getPropertyValue('--test-leading-width') || '596')
      return {x: leading, y: 0, top: 0, right: leading + 8, bottom: 800, left: leading, width: 8, height: 800, toJSON: () => ({})}
    }
    return {x: 0, y: 0, top: 0, right: 1200, bottom: 800, left: 0, width: 1200, height: 800, toJSON: () => ({})}
  })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  document.documentElement.classList.remove('is-test-pane-resizing')
})

describe('usePersistentVerticalSplitter', () => {
  it('恢复记忆比例，并在拖拽结束后保存新比例', () => {
    window.localStorage.setItem('numoj.test.splitRatio', '0.6000')
    render(<SplitPane />)

    const container = screen.getByTestId('split-container')
    const splitter = screen.getByRole('separator', {name: '调整宽度'})
    expect(container.style.getPropertyValue('--test-leading-width')).toBe('715.20px')
    expect(splitter.getAttribute('aria-valuetext')).toBe('信息 60%，内容 40%')

    fireEvent.pointerDown(splitter, {button: 0, pointerId: 7, clientX: 717.2})
    expect(document.documentElement.classList.contains('is-test-pane-resizing')).toBe(true)
    fireEvent.pointerMove(window, {pointerId: 7, clientX: 760})
    fireEvent.pointerUp(window, {pointerId: 7})

    expect(container.style.getPropertyValue('--test-leading-width')).toBe('758.00px')
    expect(window.localStorage.getItem('numoj.test.splitRatio')).toBe('0.6359')
    expect(document.documentElement.classList.contains('is-test-pane-resizing')).toBe(false)
  })

  it('支持键盘调整，并可双击恢复默认比例', () => {
    render(<SplitPane />)

    const container = screen.getByTestId('split-container')
    const splitter = screen.getByRole('separator', {name: '调整宽度'})
    fireEvent.keyDown(splitter, {key: 'ArrowRight'})
    expect(container.style.getPropertyValue('--test-leading-width')).toBe('612.00px')
    expect(window.localStorage.getItem('numoj.test.splitRatio')).toBe('0.5134')

    fireEvent.doubleClick(splitter)
    expect(container.style.getPropertyValue('--test-leading-width')).toBe('596.00px')
    expect(window.localStorage.getItem('numoj.test.splitRatio')).toBe('0.5000')
  })
})
