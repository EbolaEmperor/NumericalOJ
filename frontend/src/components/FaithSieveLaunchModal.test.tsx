// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {afterEach, expect, it, vi} from 'vitest'

import {FaithSieveLaunchModal} from './FaithSieveLaunchModal'

afterEach(() => {cleanup(); vi.unstubAllGlobals()})

const launchOptions = {
  success: true,
  harnesses: [{value: 'claude_code', label: 'Claude Code'}, {value: 'pi', label: 'Pi'}],
  endpoints_by_harness: {
    claude_code: [{id: 9, model: 'claude-sonnet', category: 'omni', protocol: 'anthropic'}],
    pi: [{id: 10, model: 'text-only-model', category: 'text', protocol: 'openai'}, {id: 8, model: 'qwen-text', category: 'omni', protocol: 'openai'}],
  },
  preference: {harness: 'pi', endpoint_id: 8},
}

function setup(options: object = launchOptions) {
  const onClose = vi.fn()
  const onQueued = vi.fn()
  vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => window.setTimeout(() => callback(0), 0))
  vi.stubGlobal('cancelAnimationFrame', (id: number) => window.clearTimeout(id))
  vi.stubGlobal('fetch', vi.fn((_input: string | URL | Request, init?: RequestInit) => Promise.resolve(new Response(JSON.stringify(init?.method === 'POST' ? {success: true, queued: 1} : options), {status: 200, headers: {'Content-Type': 'application/json'}}))))
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  const view = render(<QueryClientProvider client={client}><FaithSieveLaunchModal open action="/api/admin/submissions/12/faithsieve" onClose={onClose} onQueued={onQueued} /></QueryClientProvider>)
  return {client, onClose, onQueued, ...view}
}

it('复用通用 Agent 启动选项，切换 Harness 后投递对应模型', async () => {
  const {onClose, onQueued, container} = setup()
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'LLM 节点'}).textContent).toContain('qwen-text'))
  expect(fetch).toHaveBeenCalledWith('/api/agent/launch-options?task_kind=judge', expect.anything())
  expect(container.querySelector('select')).toBeNull()
  expect(screen.getAllByRole('combobox')).toHaveLength(3)
  expect(screen.getByRole('combobox', {name: '执行方式'}).textContent).toContain('Workflow')
  expect(screen.getByRole('combobox', {name: '执行方式'}).querySelector('svg[data-execution-mode-logo="workflow"]')).toBeTruthy()
  expect(screen.getByText('FAITHSIEVE')).toBeTruthy()
  fireEvent.click(screen.getByRole('combobox', {name: 'Harness'}))
  fireEvent.click(screen.getByRole('option', {name: 'Claude Code'}))
  expect(screen.getByRole('combobox', {name: 'LLM 节点'}).textContent).toContain('claude-sonnet')
  fireEvent.click(screen.getByRole('button', {name: '启动 FaithSieve'}))

  await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/admin/submissions/12/faithsieve', expect.objectContaining({method: 'POST', body: JSON.stringify({harness: 'claude_code', endpoint_id: 9, execution_mode: 'workflow'})})))
  await waitFor(() => expect(onQueued).toHaveBeenCalledWith(expect.objectContaining({queued: 1})))
  expect(onClose).toHaveBeenCalled()
})

it('偏好模型已失效时回退到该 Harness 的有效模型', async () => {
  setup({...launchOptions, preference: {harness: 'pi', endpoint_id: 99}})
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'LLM 节点'}).textContent).toContain('qwen-text'))
  fireEvent.click(screen.getByRole('button', {name: '启动 FaithSieve'}))
  await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/admin/submissions/12/faithsieve', expect.objectContaining({method: 'POST', body: JSON.stringify({harness: 'pi', endpoint_id: 8, execution_mode: 'workflow'})})))
})

it('没有兼容且有价格的模型时禁用启动并提示配置', async () => {
  setup({...launchOptions, endpoints_by_harness: {claude_code: [], pi: []}})
  expect((await screen.findByRole('alert')).textContent).toContain('兼容且已配置完整价格')
  expect((screen.getByRole('button', {name: '启动 FaithSieve'}) as HTMLButtonElement).disabled).toBe(true)
})

it('纯文本偏好回退到全模态模型，避免派发无法看图的任务', async () => {
  setup({...launchOptions, preference: {harness: 'pi', endpoint_id: 10}})
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'LLM 节点'}).textContent).toContain('qwen-text'))
  fireEvent.click(screen.getByRole('combobox', {name: 'LLM 节点'}))
  expect(screen.queryByRole('option', {name: 'text-only-model'})).toBeNull()
  expect(screen.getByRole('option', {name: 'qwen-text'})).not.toBeNull()
})

it('同样式执行方式选择器切换Skill并保留所选Harness和模型', async () => {
  setup()
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'LLM 节点'}).textContent).toContain('qwen-text'))
  fireEvent.click(screen.getByRole('combobox', {name: '执行方式'}))
  const skill = screen.getByRole('option', {name: 'Skill'})
  expect(skill.querySelector('svg[data-execution-mode-logo="skill"]')).toBeTruthy()
  fireEvent.click(skill)
  expect(screen.getByRole('combobox', {name: '执行方式'}).textContent).toContain('Skill')
  expect(screen.getByRole('combobox', {name: 'Harness'}).textContent).toContain('Pi')
  expect(screen.getByRole('combobox', {name: 'LLM 节点'}).textContent).toContain('qwen-text')
  fireEvent.click(screen.getByRole('button', {name: '启动 FaithSieve'}))
  await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/admin/submissions/12/faithsieve', expect.objectContaining({method: 'POST', body: JSON.stringify({harness: 'pi', endpoint_id: 8, execution_mode: 'skill'})})))
})

it('重新打开弹窗仍默认Workflow', async () => {
  const {client, onClose, onQueued, rerender} = setup()
  await waitFor(() => expect(screen.getByRole('combobox', {name: 'LLM 节点'}).textContent).toContain('qwen-text'))
  fireEvent.click(screen.getByRole('combobox', {name: '执行方式'}))
  fireEvent.click(screen.getByRole('option', {name: 'Skill'}))
  expect(screen.getByRole('combobox', {name: '执行方式'}).textContent).toContain('Skill')
  rerender(<QueryClientProvider client={client}><FaithSieveLaunchModal open={false} action="/api/admin/submissions/12/faithsieve" onClose={onClose} onQueued={onQueued} /></QueryClientProvider>)
  rerender(<QueryClientProvider client={client}><FaithSieveLaunchModal open action="/api/admin/submissions/12/faithsieve" onClose={onClose} onQueued={onQueued} /></QueryClientProvider>)
  await waitFor(() => expect(screen.getByRole('combobox', {name: '执行方式'}).textContent).toContain('Workflow'))
})
