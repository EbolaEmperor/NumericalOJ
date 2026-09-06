// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {act, cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {SessionProvider} from '../session'
import RankingDetailPage from './RankingDetailPage'

function response(payload: object) {
  return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {status: 200, headers: {'Content-Type': 'application/json'}}))
}

async function showSubmit(scoringMode = 'reverse_judge', endpoints = [{id: 11, harness: 'pi', model: 'first-model'}, {id: 22, harness: 'claude_code', model: 'selected-model'}]) {
  const posts = vi.fn((_body: FormData) => response({submission_id: 73}))
  vi.stubGlobal('fetch', vi.fn((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/session') return response({user: {id: 1, username: 'student', is_admin: 0}, navigation: {counts: {}}})
    if (url === '/ranking/7/navigation-state') return response({navigation: {scoring_mode: scoringMode, is_active: true}})
    if (url === '/api/ranking/competitions/7?tab=submit') return response({competition: {id: 7, title: '测试评测', scoring_mode: scoringMode, is_active: 1}, tab: 'submit', answer_endpoints: endpoints, user_submissions: []})
    if (url === '/api/ranking/competitions/7/submissions' && init?.method === 'POST') return posts(init.body as FormData)
    throw new Error(`unexpected fetch: ${url}`)
  }))
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/rankings/7?tab=submit']}><SessionProvider><Routes><Route path="/rankings/:competitionId" element={<RankingDetailPage />} /></Routes></SessionProvider></MemoryRouter></QueryClientProvider>)
  await screen.findByRole('heading', {name: '测试评测'})
  if (scoringMode === 'reverse_judge') {
    fireEvent.click(screen.getByRole('button', {name: '提交方式'}))
    fireEvent.click(screen.getByRole('option', {name: 'ZIP 压缩包'}))
  }
  return posts
}

async function showJudgeSettings(orchestration?: string, scoringMode = 'agent_judge') {
  const competition = {id: 7, title: '测试编排设置', scoring_mode: scoringMode, is_active: 1, agent_judge_orchestration_mode: orchestration}
  const posts = vi.fn((body: {orchestration_mode?: string}) => {
    if (body.orchestration_mode) competition.agent_judge_orchestration_mode = body.orchestration_mode
    return response({endpoints: [], orchestration_mode: competition.agent_judge_orchestration_mode})
  })
  vi.stubGlobal('fetch', vi.fn((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/session') return response({user: {id: 1, username: 'admin', is_admin: 1}, navigation: {counts: {}}})
    if (url === '/ranking/7/navigation-state') return response({navigation: {scoring_mode: scoringMode, is_active: true}})
    if (url === '/api/ranking/competitions/7?tab=edit') return response({competition, tab: 'edit', is_admin: true, aj_endpoints: [], judge_rules: []})
    if (url === '/api/ranking/competitions/7/agent-judge/endpoints' && init?.method === 'POST') return posts(JSON.parse(String(init.body)))
    throw new Error(`unexpected fetch: ${url}`)
  }))
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/rankings/7?tab=edit']}><SessionProvider><Routes><Route path="/rankings/:competitionId" element={<RankingDetailPage />} /></Routes></SessionProvider></MemoryRouter></QueryClientProvider>)
  await screen.findByRole('heading', {name: '测试编排设置'})
  return {posts, client, competition}
}

function fileInput(kind: string) {
  return document.querySelector<HTMLInputElement>(`input[name="${kind}_file"]`)!
}

beforeEach(() => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn()})))
})
afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks()})

describe('打榜赛提交文件', () => {
  it.each(['拖入', '点选'])('反向 ZIP %s文件后点击提交会发送文件与选中节点', async (method) => {
    const posts = await showSubmit()
    fireEvent.click(screen.getByRole('button', {name: /^AI 节点：/}))
    fireEvent.click(screen.getByRole('option', {name: /selected-model/}))
    const archive = new File(['ZIP CONTENT'], 'problem.zip', {type: 'application/zip'})
    const input = fileInput('code')
    if (method === '拖入') fireEvent.drop(input.closest('label')!, {dataTransfer: {files: [archive]}})
    else fireEvent.change(input, {target: {files: [archive]}})
    expect(screen.getByText('problem.zip')).toBeTruthy()
    const submit = screen.getByRole('button', {name: '提交评测'}) as HTMLButtonElement
    expect(submit.disabled).toBe(false)
    if (method === '拖入') {
      expect(input.files?.length).toBe(0)
      const required = input.required
      input.required = true // 重演旧页面：React 已有文件，隐藏的原生控件仍被判断为空。
      expect(input.validity.valueMissing).toBe(true)
      fireEvent.click(submit)
      expect(posts).not.toHaveBeenCalled()
      input.required = required
    }
    // 点击真实 submit 按钮，保留浏览器原生表单校验，不能 fireEvent.submit 绕过它。
    fireEvent.click(submit)
    await waitFor(() => expect(posts).toHaveBeenCalledTimes(1))
    const body = posts.mock.calls[0][0]
    expect(body).toBeInstanceOf(FormData)
    expect((body.get('code_file') as File).name).toBe('problem.zip')
    expect((body.get('code_file') as File).size).toBe(archive.size)
    expect(body.get('agent_endpoint_id')).toBe('22')
    expect(body.has('base_model')).toBe(false)
  })

  it('普通评测仍要求答案、代码和非空基座模型', async () => {
    const posts = await showSubmit('absolute')
    const submit = screen.getByRole('button', {name: '提交评测'}) as HTMLButtonElement
    const archive = new File(['CODE'], 'code.zip')
    const answer = new File(['{}'], 'answer.json')
    expect(submit.disabled).toBe(true)
    fireEvent.drop(fileInput('code').closest('label')!, {dataTransfer: {files: [archive]}})
    expect(submit.disabled).toBe(true)
    fireEvent.drop(fileInput('answer').closest('label')!, {dataTransfer: {files: [answer]}})
    expect(submit.disabled).toBe(true)
    fireEvent.change(screen.getByRole('textbox', {name: /基座模型/}), {target: {value: '   '}})
    expect(submit.disabled).toBe(true)
    fireEvent.change(screen.getByRole('textbox', {name: /基座模型/}), {target: {value: ' model-name '}})
    expect(submit.disabled).toBe(false)
    fireEvent.click(submit)
    await waitFor(() => expect(posts).toHaveBeenCalledTimes(1))
    const body = posts.mock.calls[0][0]
    expect(body.get('base_model')).toBe('model-name')
    expect((body.get('answer_file') as File).name).toBe('answer.json')
    expect((body.get('code_file') as File).name).toBe('code.zip')
    expect(body.has('agent_endpoint_id')).toBe(false)
  })

  it('反向评测未选文件或没有可用节点时仍不能提交', async () => {
    const posts = await showSubmit('reverse_judge', [])
    const submit = screen.getByRole('button', {name: '提交评测'}) as HTMLButtonElement
    expect(submit.disabled).toBe(true)
    fireEvent.drop(fileInput('code').closest('label')!, {dataTransfer: {files: [new File(['ZIP'], 'problem.zip')]}})
    expect(submit.disabled).toBe(true)
    fireEvent.click(submit)
    expect(posts).not.toHaveBeenCalled()
  })
})

describe('Agent Judge 编排设置', () => {
  it.each([undefined, 'single', 'topological'])('读取 %s 模式、切换保存，并同步服务端更新', async (initial) => {
    const {posts, client, competition} = await showJudgeSettings(initial)
    const currentLabel = initial === 'topological' ? '拓扑序编排' : '一次性评测'
    const nextMode = initial === 'topological' ? 'single' : 'topological'
    const nextLabel = nextMode === 'single' ? '一次性评测' : '拓扑序编排'
    const choice = screen.getByRole('combobox', {name: '评测编排'})
    expect(choice.textContent).toContain(currentLabel)
    fireEvent.click(choice)
    fireEvent.click(screen.getByRole('option', {name: nextLabel}))
    fireEvent.click(screen.getByRole('button', {name: '保存'}))
    await waitFor(() => expect(posts).toHaveBeenCalledTimes(1))
    expect(posts.mock.calls[0][0].orchestration_mode).toBe(nextMode)
    await screen.findByText('已保存')
    expect(choice.textContent).toContain(nextLabel)
    competition.agent_judge_orchestration_mode = initial || 'single'
    await act(() => client.invalidateQueries({queryKey: ['ranking', '7']}))
    await waitFor(() => expect(choice.textContent).toContain(currentLabel))
  })

  it('反向评测不展示或提交 Agent Judge 编排配置', async () => {
    const {posts, competition} = await showJudgeSettings('topological', 'reverse_judge')
    expect(screen.queryByRole('combobox', {name: '评测编排'})).toBeNull()
    fireEvent.click(screen.getAllByRole('button', {name: '保存'})[0])
    await waitFor(() => expect(posts).toHaveBeenCalledTimes(1))
    expect(posts.mock.calls[0][0]).not.toHaveProperty('orchestration_mode')
    expect(competition.agent_judge_orchestration_mode).toBe('topological')
  })
})
