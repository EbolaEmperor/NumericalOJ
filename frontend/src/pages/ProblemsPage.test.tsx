// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {Link, MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {SessionProvider, useSession} from '../session'
import ProblemsPage from './ProblemsPage'

const classes = [
  {class_en: 'C1', class_cn: '一班', logo: {cells: []}},
  {class_en: 'C2', class_cn: '二班', logo: {cells: []}},
]
let delayClassPrefetch = false

function jsonResponse(payload: object) {
  return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {
    status: 200,
    headers: {'Content-Type': 'application/json'},
  }))
}

function TestRoutes() {
  const {loading} = useSession()
  if (loading) return <div role="status">正在建立安全会话</div>
  return <>
    <Link to="/elsewhere">离开作业页</Link>
    <Routes>
      <Route path="/problems" element={<ProblemsPage />} />
      <Route path="/elsewhere" element={<Link to="/problems">返回班级作业</Link>} />
    </Routes>
  </>
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: {
      queries: {retry: false, staleTime: 15_000},
      mutations: {retry: false},
    },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/problems']}>
        <SessionProvider>
          <TestRoutes />
        </SessionProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  delayClassPrefetch = false
  let rememberedClass = 'C1'
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    })),
  })
  vi.stubGlobal('fetch', vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url.startsWith('/api/v1/session')) {
      const selected = new URL(url, 'http://numoj.test').searchParams.get('class_en') || rememberedClass
      return jsonResponse({
        api_version: '1',
        user: {id: 1, username: 'admin', is_admin: 1},
        navigation: {items: [], counts: {}, agent_active: false, selected_class_en: selected},
        capabilities: {spa: true, legacy_ui_available: false, streaming: true, class_adjust_enabled: false, mail_service_configured: false},
      })
    }
    if (url.startsWith('/api/problems')) {
      const parsed = new URL(url, 'http://numoj.test')
      const explicitClass = parsed.searchParams.get('class_en')
      const selected = explicitClass || rememberedClass
      if (explicitClass && parsed.searchParams.get('remember') !== '0') rememberedClass = explicitClass
      const payload = {
        problems: [],
        count: 0,
        classes,
        selected_class_en: selected,
        selected_class_cn: selected === 'C2' ? '二班' : '一班',
      }
      if (delayClassPrefetch && parsed.searchParams.get('remember') === '0') {
        return new Promise((resolve, reject) => {
          const timer = window.setTimeout(() => { void jsonResponse(payload).then(resolve) }, 100)
          init?.signal?.addEventListener('abort', () => {
            window.clearTimeout(timer)
            reject(new DOMException('Aborted', 'AbortError'))
          }, {once: true})
        })
      }
      return jsonResponse(payload)
    }
    if (url.startsWith('/api/class-activity')) return jsonResponse({activity: []})
    throw new Error(`unexpected fetch: ${url}`)
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('班级作业记忆', () => {
  it('悬停只按目标班级预取，不会改变真正记住的班级', async () => {
    renderPage()
    const picker = await screen.findByRole('button', {name: /一班/})
    fireEvent.click(picker)
    fireEvent.pointerEnter(screen.getByRole('option', {name: '二班'}))

    await waitFor(() => expect(vi.mocked(fetch).mock.calls
      .map(([input]) => String(input)))
      .toContain('/api/problems?class_en=C2&remember=0'))
    fireEvent.click(screen.getByRole('link', {name: '离开作业页'}))
    fireEvent.click(await screen.findByRole('link', {name: '返回班级作业'}))
    expect(await screen.findByRole('button', {name: /一班/})).toBeTruthy()
  })

  it('预取尚未完成时点击班级仍写入记忆，返回时恢复该班级', async () => {
    delayClassPrefetch = true
    renderPage()
    const picker = await screen.findByRole('button', {name: /一班/})
    fireEvent.click(picker)
    const secondClass = screen.getByRole('option', {name: '二班'})

    // 先制造仍在进行的悬停预取，再立即点击，覆盖最容易复现旧回归的竞态。
    fireEvent.pointerEnter(secondClass)
    fireEvent.click(secondClass)
    await screen.findByRole('button', {name: /二班/})

    fireEvent.click(screen.getByRole('link', {name: '离开作业页'}))
    fireEvent.click(await screen.findByRole('link', {name: '返回班级作业'}))
    expect(await screen.findByRole('button', {name: /二班/})).toBeTruthy()

    await waitFor(() => {
      const problemCalls = vi.mocked(fetch).mock.calls
        .map(([input]) => String(input))
        .filter((url) => url.startsWith('/api/problems'))
      expect(problemCalls).toContain('/api/problems?class_en=C2')
      expect(problemCalls).toContain('/api/problems?class_en=C2&remember=0')
      expect(problemCalls.filter((url) => url === '/api/problems').length).toBeGreaterThanOrEqual(2)
    })
  })
})
