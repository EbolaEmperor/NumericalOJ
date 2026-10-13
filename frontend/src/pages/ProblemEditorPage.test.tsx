// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {SessionProvider} from '../session'
import ProblemEditorPage from './ProblemEditorPage'

let savedBody: FormData | undefined
let seed: Record<string, unknown>

function response(payload: object) {
  return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {status: 200, headers: {'Content-Type': 'application/json'}}))
}

function renderPage(editing = false) {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[editing ? '/admin/problems/11/edit' : '/admin/problems/new']}><SessionProvider><Routes><Route path="/admin/problems/new" element={<ProblemEditorPage />} /><Route path="/admin/problems/:problemId/edit" element={<ProblemEditorPage />} /><Route path="/problems/:problemId" element={<div>题目已保存</div>} /></Routes></SessionProvider></MemoryRouter></QueryClientProvider>)
}

beforeEach(() => {
  Object.defineProperty(window, 'matchMedia', {configurable: true, value: vi.fn().mockImplementation((query: string) => ({matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn()}))})
  savedBody = undefined
  seed = {type: 2, title: '书面题', content: '题面', submission_limit: 10, written_grading_mode: 1, written_vote_config: [{endpoint_id: 7, count: 1}]}
  vi.stubGlobal('fetch', vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/session') return response({api_version: '1', user: {id: 1, username: 'admin', is_admin: 1}, navigation: {items: [], counts: {}, agent_active: false}, capabilities: {spa: true}})
    if (url.endsWith('/create-form') || url.endsWith('/edit-form')) return response({action: url.includes('edit-form') ? '/api/admin/problems/11' : '/api/admin/problems', defaults: seed, form: seed, options: {languages: [], problem_types: [{value: '1', label: '编程题'}, {value: '2', label: '书面题'}], programming_grading_modes: [], default_written_grading_prompt: '', llm_endpoint_candidates: {text_grading_endpoint_id: [{id: 7, model: 'qwen'}]}}})
    if (init?.method === 'POST') {savedBody = init.body as FormData; return response({problem_id: 11})}
    throw new Error(`unexpected fetch: ${url}`)
  }))
})

afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks()})

describe('题目公开评分开关', () => {
  it('默认公开，点击只修改表单，现有保存才把关闭状态送到服务器', async () => {
    const {container} = renderPage()
    const toggle = await screen.findByRole('switch', {name: '公开评分'})
    expect(toggle.getAttribute('aria-checked')).toBe('true')
    expect(toggle.closest('.written-vote-heading')?.textContent).toContain('AI 评委 Vote')

    fireEvent.click(toggle)
    expect(toggle.getAttribute('aria-checked')).toBe('false')
    expect(savedBody).toBeUndefined()
    fireEvent.submit(container.querySelector('#addProblemForm')!)
    await screen.findByText('题目已保存')
    expect(savedBody?.get('written_score_public')).toBe('0')
    expect(savedBody?.get('written_vote_config')).toBe('[{"endpoint_id":7,"count":1}]')
  })

  it('编辑回显关闭状态，开启后沿用原保存按钮提交', async () => {
    seed.written_score_public = 0
    const {container} = renderPage(true)
    const toggle = await screen.findByRole('switch', {name: '公开评分'})
    await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('false'))
    fireEvent.click(toggle)
    fireEvent.submit(container.querySelector('#editProblemForm')!)
    await screen.findByText('题目已保存')
    expect(savedBody?.get('written_score_public')).toBe('1')
  })

  it('纯人工书面题不显示公开评分开关', async () => {
    seed.written_grading_mode = 4
    renderPage()
    await screen.findByText('题面')
    expect(screen.queryByRole('switch', {name: '公开评分'})).toBeNull()
  })
})
