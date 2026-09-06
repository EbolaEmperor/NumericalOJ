// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
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
