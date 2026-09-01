// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {BrowserRouter, MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, describe, expect, it, vi} from 'vitest'

import {Link, useNavigate} from './PageNavigation'

function ProgrammaticNavigation() {
  const navigate = useNavigate()
  return <button type="button" onClick={() => navigate('/second', {viewTransition: true})}>打开第二页</button>
}

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.restoreAllMocks()
  Reflect.deleteProperty(document, 'startViewTransition')
  document.querySelector('[data-numoj-page-transition-snapshot]')?.remove()
  document.documentElement.classList.remove('numoj-page-transition-entering')
  document.getElementById('root')?.remove()
  window.history.replaceState({}, '', '/')
})

describe('PageNavigation', () => {
  it('优先使用浏览器合成层快照保留旧页退场动画', () => {
    let contentDuringUpdate = ''
    const nativeTransition = vi.fn((update: () => void) => {
      update()
      contentDuringUpdate = document.getElementById('root')?.textContent || ''
      return {
        ready: Promise.resolve(),
        finished: Promise.resolve(),
        updateCallbackDone: Promise.resolve(),
        skipTransition: vi.fn(),
        types: new Set<string>(),
      }
    })
    Object.defineProperty(document, 'startViewTransition', {
      configurable: true,
      value: nativeTransition,
    })
    const root = document.createElement('div')
    root.id = 'root'
    document.body.appendChild(root)
    window.history.replaceState({}, '', '/first')

    render(
      <BrowserRouter useTransitions={false}>
        <aside>固定侧栏</aside>
        <div className="numoj-content">
          <Routes>
            <Route path="/first" element={<main className="numoj-spa-route"><h1>第一页</h1><Link to="/second">下一页</Link></main>} />
            <Route path="/second" element={<main className="numoj-spa-route"><h1>第二页</h1></main>} />
          </Routes>
        </div>
      </BrowserRouter>,
      {container: root},
    )

    fireEvent.click(screen.getByRole('link', {name: '下一页'}))

    expect(screen.getByRole('heading', {name: '第二页'})).toBeTruthy()
    expect(screen.queryByRole('heading', {name: '第一页'})).toBeNull()
    expect(document.querySelector('[data-numoj-page-transition-snapshot]')).toBeNull()
    expect(document.documentElement.classList.contains('numoj-page-transition-entering')).toBe(false)
    expect(nativeTransition).toHaveBeenCalledOnce()
    expect(contentDuringUpdate).toContain('第二页')
  })

  it('程序化导航使用相同的合成层过渡', () => {
    const nativeTransition = vi.fn((update: () => void) => {
      update()
      return {
        ready: Promise.resolve(),
        finished: Promise.resolve(),
        updateCallbackDone: Promise.resolve(),
        skipTransition: vi.fn(),
        types: new Set<string>(),
      }
    })
    Object.defineProperty(document, 'startViewTransition', {
      configurable: true,
      value: nativeTransition,
    })

    render(
      <MemoryRouter initialEntries={['/first']}>
        <Routes>
          <Route path="/first" element={<ProgrammaticNavigation />} />
          <Route path="/second" element={<h1>第二页</h1>} />
        </Routes>
      </MemoryRouter>,
    )

    fireEvent.click(screen.getByRole('button', {name: '打开第二页'}))

    expect(screen.getByRole('heading', {name: '第二页'})).toBeTruthy()
    expect(nativeTransition).toHaveBeenCalledOnce()
  })

  it('旧浏览器仍按原时序使用正文 DOM 快照退场', () => {
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
    const root = document.createElement('div')
    root.id = 'root'
    document.body.appendChild(root)

    render(
      <MemoryRouter initialEntries={['/first']}>
        <div className="numoj-content">
          <Routes>
            <Route path="/first" element={<main className="numoj-spa-route"><h1>第一页</h1><Link to="/second">下一页</Link></main>} />
            <Route path="/second" element={<main className="numoj-spa-route"><h1>第二页</h1></main>} />
          </Routes>
        </div>
      </MemoryRouter>,
      {container: root},
    )

    fireEvent.click(screen.getByRole('link', {name: '下一页'}))

    const snapshot = document.querySelector('[data-numoj-page-transition-snapshot]')
    expect(snapshot?.textContent).toContain('第一页')
    expect(screen.getByRole('heading', {name: '第二页'})).toBeTruthy()
    expect(document.documentElement.classList.contains('numoj-page-transition-entering')).toBe(true)

    vi.advanceTimersByTime(300)
    expect(document.querySelector('[data-numoj-page-transition-snapshot]')).toBeNull()

    vi.advanceTimersByTime(130)
    expect(document.documentElement.classList.contains('numoj-page-transition-entering')).toBe(false)
  })
})
