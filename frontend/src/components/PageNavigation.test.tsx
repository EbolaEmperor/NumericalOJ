// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, describe, expect, it, vi} from 'vitest'

import {Link} from './PageNavigation'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.restoreAllMocks()
  Reflect.deleteProperty(document, 'startViewTransition')
  document.querySelector('[data-numoj-page-transition-snapshot]')?.remove()
  document.documentElement.classList.remove('numoj-page-transition-entering')
  document.getElementById('root')?.remove()
})

describe('PageNavigation', () => {
  it('始终使用旧页 DOM 快照遮住新页加载态，并冻结已显示的图片像素', () => {
    vi.useFakeTimers()
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
      x: 186,
      y: 0,
      top: 0,
      right: 1280,
      bottom: 720,
      left: 186,
      width: 1094,
      height: 720,
      toJSON: () => ({}),
    })
    const drawImage = vi.fn()
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue({drawImage} as unknown as CanvasRenderingContext2D)
    const nativeTransition = vi.fn()
    Object.defineProperty(document, 'startViewTransition', {
      configurable: true,
      value: nativeTransition,
    })
    const root = document.createElement('div')
    root.id = 'root'
    document.body.appendChild(root)

    render(
      <MemoryRouter initialEntries={['/first']}>
        <aside>固定侧栏</aside>
        <div className="numoj-content">
          <Routes>
            <Route path="/first" element={<main className="numoj-spa-route"><h1>第一页</h1><img src="/cover.webp" alt="旧页封面" /><Link to="/second">下一页</Link></main>} />
            <Route path="/second" element={<main className="numoj-spa-route"><div className="numoj-spa-state">数学曲线加载</div></main>} />
          </Routes>
        </div>
      </MemoryRouter>,
      {container: root},
    )

    const sourceImage = screen.getByRole('img', {name: '旧页封面'})
    Object.defineProperties(sourceImage, {
      complete: {configurable: true, value: true},
      naturalWidth: {configurable: true, value: 1600},
      naturalHeight: {configurable: true, value: 900},
    })
    fireEvent.click(screen.getByRole('link', {name: '下一页'}))

    expect(screen.getByText('数学曲线加载')).toBeTruthy()
    const snapshot = document.querySelector('[data-numoj-page-transition-snapshot]')
    expect(snapshot).toBeTruthy()
    expect(snapshot?.textContent).toContain('第一页')
    expect(snapshot?.textContent).not.toContain('固定侧栏')
    expect(snapshot?.querySelector('img')).toBeNull()
    expect(snapshot?.querySelector('canvas[data-numoj-snapshot-image]')).toBeTruthy()
    expect(drawImage).toHaveBeenCalledWith(sourceImage, 0, 0, 1094, 720)
    expect(document.documentElement.classList.contains('numoj-page-transition-entering')).toBe(true)
    expect(nativeTransition).not.toHaveBeenCalled()

    vi.advanceTimersByTime(300)
    expect(document.querySelector('[data-numoj-page-transition-snapshot]')).toBeNull()
    expect(document.documentElement.classList.contains('numoj-page-transition-entering')).toBe(true)

    vi.advanceTimersByTime(130)
    expect(document.documentElement.classList.contains('numoj-page-transition-entering')).toBe(false)
  })
})
