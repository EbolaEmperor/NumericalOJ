// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, render, screen, waitFor} from '@testing-library/react'
import {MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import AgentSessionPage from './AgentSessionPage'
import AgentTasksPage from './AgentTasksPage'

beforeEach(() => {
  vi.stubGlobal('EventSource', undefined)
  vi.stubGlobal('matchMedia', vi.fn(() => ({matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn()})))
  Element.prototype.scrollTo = vi.fn()
})
afterEach(() => {cleanup(); vi.unstubAllGlobals()})

function show(path: string, node: React.ReactNode, route: string) {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes><Route path={route} element={node} /></Routes></MemoryRouter></QueryClientProvider>)
}

function fetchPayloads(payload: Record<string, unknown>) {
  return vi.fn(async (url: string, _options?: RequestInit) => new Response(JSON.stringify(
    url.endsWith('/workspace') ? {success: true, tree: []}
      : url.endsWith('/state') ? {success: true, state: {status: 'completed'}}
        : payload,
  ), {status: 200, headers: {'Content-Type': 'application/json'}}))
}

describe('Judge 会话浏览与只读交互', () => {
  it.each([0, 1])('查看者 is_admin=%s 时均保留禁用回复框并隐藏人工修改入口', async (isAdmin) => {
    const fetch = fetchPayloads({
      success: true, user: {username: 'student', is_admin: isAdmin},
      agent_session: {session_id: 'judge-session', title: '反向评测 AI 作答', category: 'judge', task_kind: 'judge', requested_by: 'student', native_session_id: 'native', harness: 'pi'},
      current_state: {status: 'completed'}, agent_message_state: {},
      turns: [{task_id: 'turn-1', user_message: '完成题目', conclusion: '已完成'}],
      // Judge 类型本身也必须保护界面，不能依赖单个后端 capability 字段。
      can_resume: true, can_retry: true, can_retry_now: true,
    })
    vi.stubGlobal('fetch', fetch)
    show('/agents/judge-session', <AgentSessionPage />, '/agents/:sessionId')

    await waitFor(() => expect(screen.getByRole('textbox', {name: '继续会话'})).toBeTruthy())
    expect((screen.getByRole('textbox', {name: '继续会话'}) as HTMLTextAreaElement).disabled).toBe(true)
    expect((screen.getByRole('button', {name: '发送消息'}) as HTMLButtonElement).disabled).toBe(true)
    for (const name of ['重命名会话', '重试上一条消息', '停止任务', '添加附件']) expect(screen.queryByRole('button', {name})).toBeNull()
    expect(screen.getByText('Judge 会话由评测流程自动推进，不允许人工发送消息或插话。')).toBeTruthy()
    expect(fetch.mock.calls.every(([, options]) => !options || !(options as RequestInit).method || (options as RequestInit).method === 'GET')).toBe(true)
  })

  it.each([0, 1])('会话列表 is_admin=%s 时按管理员权限展示 Judge 栏', async (isAdmin) => {
    vi.stubGlobal('fetch', fetchPayloads({success: true, user: {is_admin: isAdmin}, agent_scope: isAdmin ? 'judge' : 'mine', agent_sessions: [], harnesses: ['pi'], endpoints_by_harness: {}, reasoning_efforts_by_harness: {}, agent_quota_summary: {}}))
    show(isAdmin ? '/agents?scope=judge' : '/agents', <AgentTasksPage />, '/agents')
    await waitFor(() => expect(screen.getByRole('heading', {name: '历史会话'})).toBeTruthy())
    if (isAdmin) {
      expect(screen.getByRole('link', {name: 'Judge 会话'}).getAttribute('aria-current')).toBe('page')
      expect(screen.getByRole('link', {name: '全站会话'}).getAttribute('aria-current')).toBeNull()
      expect(screen.getByRole('link', {name: '我的会话'})).toBeTruthy()
    } else expect(screen.queryByRole('link', {name: 'Judge 会话'})).toBeNull()
  })
})
