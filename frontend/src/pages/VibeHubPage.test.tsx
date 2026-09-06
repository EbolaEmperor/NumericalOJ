// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react'
import {MemoryRouter} from 'react-router-dom'
import {afterEach, beforeEach, expect, it, vi} from 'vitest'

import VibeHubPage from './VibeHubPage'

vi.mock('../session', () => ({useSession: () => ({session: {user: {id: 1, is_admin: true}}})}))
vi.mock('../components/PageNavigation', async () => ({Link: (await import('react-router-dom')).Link}))

const project = {
  slug: 'gpu-demo', title: 'GPU 作品', owner_username: 'admin', is_mine: true, can_edit: true,
  can_approve: true, submitted_version: 2, gpu_memory_mib: 4096, play_url: '/vibehub/gpu-demo/play?channel=review',
  last_reviewed_version: 1, last_review_note: '请减少显存\n再提交审核。',
}
const writes: {url: string; init: RequestInit}[] = []

function renderPage() {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  return render(<MemoryRouter><QueryClientProvider client={client}><VibeHubPage /></QueryClientProvider></MemoryRouter>)
}

beforeEach(() => {
  writes.length = 0
  vi.stubGlobal('matchMedia', vi.fn(() => ({matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn()})))
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', {configurable: true, value: function (this: HTMLDialogElement) {this.open = true}})
  Object.defineProperty(HTMLDialogElement.prototype, 'close', {configurable: true, value: function (this: HTMLDialogElement) {this.open = false}})
  vi.stubGlobal('fetch', vi.fn((input: string, init?: RequestInit) => {
    if (init?.method && init.method !== 'GET') writes.push({url: String(input), init})
    return Promise.resolve(new Response(JSON.stringify({success: true, projects: [project], project}), {headers: {'Content-Type': 'application/json'}}))
  }))
})
afterEach(() => {cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal'); Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')})

it('管理员创建时 GPU 默认关闭，申请随原表单提交，使用自定义控件', async () => {
  const view = renderPage()
  fireEvent.click(await screen.findByRole('button', {name: '创建作品'}))
  const dialog = screen.getByRole('dialog', {name: '创建作品'})
  const control = within(dialog).getByRole('switch', {name: '使用 GPU'})
  expect(control.getAttribute('aria-checked')).toBe('false')
  fireEvent.click(control)
  expect(within(dialog).getByText('4 GiB')).toBeTruthy()
  expect(dialog.querySelector('select,input[type="number"],input[type="checkbox"]')).toBeNull()
  fireEvent.change(within(dialog).getByLabelText('游戏名称'), {target: {value: 'GPU 新作'}})
  fireEvent.change(dialog.querySelector('input[type="file"]')!, {target: {files: [new File(['zip'], 'demo.zip')]}})
  fireEvent.submit(dialog.querySelector('form')!)
  await waitFor(() => expect(writes.length).toBe(1))
  expect((writes[0].init.body as FormData).get('gpu_memory_mib')).toBe('4096')
  expect(view.container.querySelectorAll('dialog').length).toBe(4)
})

it('编辑弹窗回填 GPU 并显示审核意见，重新创建时清空', async () => {
  renderPage()
  fireEvent.click(await screen.findByRole('button', {name: '编辑 GPU 作品'}))
  const dialog = screen.getByRole('dialog', {name: '编辑作品'})
  await waitFor(() => expect(within(dialog).getByRole('switch').getAttribute('aria-checked')).toBe('true'))
  expect(within(dialog).getByLabelText('管理员审核意见').textContent).toContain('v1')
  expect(within(dialog).getByLabelText('管理员审核意见').textContent).toContain('请减少显存\n再提交审核。')
  fireEvent.click(within(dialog).getByRole('button', {name: '关闭'}))
  fireEvent.click(screen.getByRole('button', {name: '创建作品'}))
  expect(screen.queryByLabelText('管理员审核意见')).toBeNull()
  expect(screen.getByRole('switch').getAttribute('aria-checked')).toBe('false')
})

it('审核弹窗支持下调显存、填写意见并通过同一次审核提交', async () => {
  renderPage()
  fireEvent.click(await screen.findByRole('button', {name: '审核 GPU 作品'}))
  const dialog = screen.getByRole('dialog', {name: '审核作品'})
  fireEvent.click(within(dialog).getByRole('button', {name: '减少批准显存'}))
  fireEvent.change(within(dialog).getByLabelText('审核意见'), {target: {value: '额度调整为 3 GiB'}})
  fireEvent.submit(dialog.querySelector('form')!)
  await waitFor(() => expect(writes.length).toBe(1))
  expect(JSON.parse(writes[0].init.body as string)).toEqual({decision: 'approve', note: '额度调整为 3 GiB', gpu_memory_mib: 3072, expected_version: 2})
})

it('审核驳回复用弹窗并提交意见', async () => {
  renderPage()
  fireEvent.click(await screen.findByRole('button', {name: '审核 GPU 作品'}))
  const dialog = screen.getByRole('dialog', {name: '审核作品'})
  fireEvent.change(within(dialog).getByLabelText('审核意见'), {target: {value: '请修复启动错误'}})
  fireEvent.click(within(dialog).getByRole('button', {name: '驳回'}))
  await waitFor(() => expect(writes.length).toBe(1))
  expect(JSON.parse(writes[0].init.body as string)).toMatchObject({decision: 'reject', note: '请修复启动错误'})
})
