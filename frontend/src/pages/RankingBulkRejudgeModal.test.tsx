// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react'
import {MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {SessionProvider} from '../session'
import RankingDetailPage from './RankingDetailPage'

const clients: QueryClient[] = []

function response(payload: object) {
  return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {status: 200, headers: {'Content-Type': 'application/json'}}))
}

async function openBulkRejudge() {
  const submissions = [
    {id: 71, username: 'alice', status: 'Accepted', score: 100, created_at: '2026-11-09 09:00:00'},
    {id: 72, username: 'alice2', status: 'Accepted', score: 80, created_at: '2026-11-09 12:00:00'},
  ]
  const filterPosts = vi.fn((_body: object) => response({submissions, total: 2, max_selected: 500, max_results: 500, too_many: false}))
  const startPosts = vi.fn((_body: object) => response({job_id: 'bulk-test'}))
  vi.stubGlobal('fetch', vi.fn((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/session') return response({user: {id: 1, username: 'admin', is_admin: 1}, navigation: {counts: {}}})
    if (url === '/ranking/7/navigation-state') return response({navigation: {scoring_mode: 'absolute', is_active: true}})
    if (url === '/api/ranking/competitions/7?tab=all_submissions') return response({competition: {id: 7, title: '测试批量重测', scoring_mode: 'absolute', is_active: 1}, tab: 'all_submissions', is_admin: true, all_submissions: submissions, submission_stats: {total: 2, accepted: 2, unique_users: 2}})
    if (url === '/api/ranking/competitions/7/rejudge/filter' && init?.method === 'POST') return filterPosts(JSON.parse(String(init.body)))
    if (url === '/api/ranking/competitions/7/rejudge/jobs' && init?.method === 'POST') return startPosts(JSON.parse(String(init.body)))
    if (url === '/api/ranking/competitions/7/rejudge/jobs/bulk-test') return response({job_id: 'bulk-test', total: 1, processed: 1, requeued: 1, failed: 0, progress: 100, done: true})
    throw new Error(`unexpected fetch: ${url}`)
  }))
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  clients.push(client)
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/rankings/7?tab=all_submissions']}><SessionProvider><Routes><Route path="/rankings/:competitionId" element={<RankingDetailPage />} /></Routes></SessionProvider></MemoryRouter></QueryClientProvider>)
  await screen.findByRole('heading', {name: '测试批量重测'})
  const opener = screen.getByRole('button', {name: '批量重测'})
  opener.focus()
  fireEvent.click(opener)
  return {dialog: screen.getByRole('dialog', {name: '批量重测'}), filterPosts, startPosts, opener}
}

beforeEach(() => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn()})))
})

afterEach(() => {
  cleanup()
  clients.splice(0).forEach((client) => client.clear())
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('批量重测弹窗', () => {
  it('时间、用户和状态筛选只查询提交，确认后才为勾选项创建重测任务', async () => {
    const {dialog, filterPosts, startPosts} = await openBulkRejudge()
    const modal = within(dialog)
    const confirm = modal.getByRole('button', {name: '确认重测'}) as HTMLButtonElement
    expect(confirm.disabled).toBe(true)

    fireEvent.click(modal.getByRole('combobox', {name: '筛选提交时间'}))
    fireEvent.change(modal.getByRole('textbox', {name: '起始时间'}), {target: {value: '2026-11-09 08:30'}})
    fireEvent.change(modal.getByRole('textbox', {name: '结束时间'}), {target: {value: '2026-11-09 18:00'}})
    fireEvent.keyDown(modal.getByRole('textbox', {name: '结束时间'}), {key: 'Enter'})
    fireEvent.change(modal.getByRole('textbox', {name: '用户'}), {target: {value: ' alice '}})
    fireEvent.click(modal.getByRole('checkbox', {name: '通过'}))
    fireEvent.click(modal.getByRole('button', {name: /^筛选$/}))

    await modal.findByRole('checkbox', {name: '#72'})
    expect(filterPosts).toHaveBeenCalledExactlyOnceWith({start: '2026-11-09T08:30', end: '2026-11-09T18:00', username: 'alice', statuses: ['accepted']})
    expect(startPosts).not.toHaveBeenCalled()
    expect(confirm.disabled).toBe(true)
    fireEvent.click(modal.getByRole('checkbox', {name: '#72'}))
    expect((modal.getByRole('checkbox', {name: '#71'}) as HTMLInputElement).checked).toBe(false)
    expect(confirm.disabled).toBe(false)
    fireEvent.click(confirm)
    await waitFor(() => expect(startPosts).toHaveBeenCalledExactlyOnceWith({submission_ids: [72]}))
  })

  it('Escape 先关闭时间选择面板，再关闭弹窗并恢复入口焦点', async () => {
    const {dialog, opener} = await openBulkRejudge()
    const picker = within(dialog).getByRole('combobox', {name: '筛选提交时间'})
    fireEvent.click(picker)
    expect(within(dialog).getByRole('dialog', {name: '时间范围'})).toBeTruthy()
    fireEvent.keyDown(within(dialog).getByRole('textbox', {name: '起始时间'}), {key: 'Escape'})
    expect(screen.getByRole('dialog', {name: '批量重测'})).toBe(dialog)
    expect(within(dialog).queryByRole('dialog', {name: '时间范围'})).toBeNull()
    expect(document.activeElement).toBe(picker)
    fireEvent.keyDown(picker, {key: 'Escape'})
    expect(screen.queryByRole('dialog', {name: '批量重测'})).toBeNull()
    await waitFor(() => expect(document.activeElement).toBe(opener))
  })
})
