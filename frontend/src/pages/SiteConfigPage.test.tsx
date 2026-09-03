// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import SiteConfigPage, {normalizeDeploymentCommit} from './SiteConfigPage'

vi.mock('../session', () => ({
  useSession: () => ({session: {user: {id: 1, username: 'admin', is_admin: true}}}),
}))

function response(payload: object) {
  return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {
    status: 200,
    headers: {'Content-Type': 'application/json'},
  }))
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: {queries: {retry: false}, mutations: {retry: false}},
  })
  return render(<QueryClientProvider client={client}><SiteConfigPage /></QueryClientProvider>)
}

beforeEach(() => {
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
    if (init?.method === 'POST' && url === '/api/admin/dynamic-config/mail/test') {
      return response({test: {latency_ms: 18}})
    }
    if (url.endsWith('/llm-endpoints')) return response({endpoints: []})
    if (url.endsWith('/feature-bindings')) return response({bindings: []})
    if (url.endsWith('/mail')) return response({settings: {smtp_server: 'smtp.example.com', smtp_port: 465, smtp_username: 'admin@example.com', password_configured: true}})
    if (url.endsWith('/web-search')) return response({settings: {base_url: 'http://search.example.com', authorization_configured: true}})
    if (url.endsWith('/agent-public-access')) return response({settings: {public_enabled: true}})
    if (url.endsWith('/agent-concurrency')) return response({settings: {limit: 8}})
    throw new Error(`unexpected fetch: ${url}`)
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

describe('全站配置部署版本', () => {
  it('只接受完整 commit，并在 LIVE 右侧显示前六位', async () => {
    const commit = 'ABCDEF1234567890ABCDEF1234567890ABCDEF12'
    expect(normalizeDeploymentCommit(commit)).toBe(commit.toLowerCase())
    expect(normalizeDeploymentCommit('abcdef')).toBe('')
    vi.stubEnv('VITE_NUMOJ_COMMIT_SHA', commit)

    renderPage()

    const badge = await screen.findByLabelText('当前部署 commit abcdef')
    expect(badge.textContent).toBe('abcdef')
    expect(badge.getAttribute('title')).toContain(commit.toLowerCase())
  })
})

describe('全站配置服务测试反馈', () => {
  it('把邮件和联网搜索并入功能配置，并用旧版短时 toast 显示测试结果', async () => {
    const view = renderPage()
    fireEvent.click(await screen.findByRole('tab', {name: /功能配置/}))

    const featureGrid = view.container.querySelector('.site-config-services-panel .site-config-feature-grid')
    const mailForm = (await screen.findByText('邮件服务')).closest('form')
    const searchForm = screen.getByText('联网搜索').closest('form')
    expect(screen.queryByRole('tab', {name: /其他配置/})).toBeNull()
    expect(featureGrid).not.toBeNull()
    expect(mailForm).not.toBeNull()
    expect(searchForm).not.toBeNull()
    expect(featureGrid?.contains(mailForm)).toBe(true)
    expect(featureGrid?.contains(searchForm)).toBe(true)
    expect(mailForm?.classList.contains('site-config-feature-card')).toBe(true)
    expect(mailForm?.classList.contains('site-config-service-card')).toBe(true)
    expect(searchForm?.classList.contains('site-config-feature-card')).toBe(true)
    expect(searchForm?.classList.contains('site-config-service-card')).toBe(true)
    expect(within(mailForm as HTMLFormElement).getByText('SMTP 服务器').closest('label')?.classList.contains('wide')).toBe(false)
    expect(within(mailForm as HTMLFormElement).getByText('密码').closest('label')?.classList.contains('wide')).toBe(false)
    fireEvent.click(within(mailForm as HTMLFormElement).getByRole('button', {name: '测试'}))

    expect((await screen.findByRole('status')).textContent).toContain('测试邮件已发送（18 ms）')
    expect(view.container.querySelector('.site-config-form-status')).toBeNull()
    await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/admin/dynamic-config/mail/test', expect.objectContaining({method: 'POST'})))
  })
})
