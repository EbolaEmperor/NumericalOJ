// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {SessionProvider} from '../session'
import ProblemEditorPage from './ProblemEditorPage'

vi.mock('../components/MonacoEditor', () => ({MonacoEditor: () => null}))

let savedBody: FormData | undefined
let seed: Record<string, unknown>
let copySources: Array<Record<string, unknown>>
let sourceRequests: string[]
let copyError: boolean
let sourceResponse: Promise<Response> | undefined

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
  sourceRequests = []
  copyError = false
  sourceResponse = undefined
  copySources = [{id: 42, title: '来源书面题', written_vote_config: [{endpoint_id: 7, count: 2}, {endpoint_id: 8, count: 3}]}]
  seed = {type: 2, title: '书面题', content: '题面', submission_limit: 10, written_grading_mode: 1, written_vote_config: [{endpoint_id: 7, count: 1}]}
  vi.stubGlobal('fetch', vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/session') return response({api_version: '1', user: {id: 1, username: 'admin', is_admin: 1}, navigation: {items: [], counts: {}, agent_active: false}, capabilities: {spa: true}})
    if (url.startsWith('/api/admin/problems/written-vote-configs')) {
      sourceRequests.push(url)
      if (sourceResponse) return sourceResponse
      if (copyError) return Promise.resolve(new Response(JSON.stringify({success: false, message: '来源配置读取失败'}), {status: 503, headers: {'Content-Type': 'application/json'}}))
      return response({problems: copySources})
    }
    if (url.endsWith('/create-form') || url.endsWith('/edit-form')) return response({action: url.includes('edit-form') ? '/api/admin/problems/11' : '/api/admin/problems', defaults: seed, form: seed, options: {languages: [], problem_types: [{value: '1', label: '编程题'}, {value: '2', label: '书面题'}], programming_grading_modes: [], default_written_grading_prompt: '', llm_endpoint_candidates: {text_grading_endpoint_id: [{id: 7, model: 'qwen'}, {id: 8, model: 'claude'}]}}})
    if (init?.method === 'POST') {savedBody = init.body as FormData; return response({problem_id: 11})}
    throw new Error(`unexpected fetch: ${url}`)
  }))
})

describe('从其它题目复制 AI Vote 配置', () => {
  it.each([0, 1])('仅复制评委模型和票数，当前公开状态为 %s 时保持不变且保存前不写服务器', async (publicScore) => {
    seed.written_score_public = publicScore
    seed.written_grading_prompt = '当前评分标准'
    seed.ocr_endpoint_id = 13
    copySources[0].written_score_public = publicScore ? 0 : 1
    copySources[0].written_grading_prompt = '来源评分标准'
    const {container} = renderPage()
    const toggle = await screen.findByRole('switch', {name: '公开评分'})
    await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe(String(Boolean(publicScore))))
    const button = screen.getByRole('button', {name: '复制 AI Vote 配置'})
    expect(button.closest('.aje-head-tools')).toBe(screen.getByRole('button', {name: '添加评委模型'}).closest('.aje-head-tools'))
    expect(sourceRequests).toHaveLength(0)
    fireEvent.click(button)
    await screen.findByRole('dialog', {name: '从其它题目里复制配置'})
    expect((screen.getByRole('button', {name: '确认'}) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.queryByText('选择题目')).toBeNull()
    expect(screen.queryByText(/仅显示评委配置/)).toBeNull()
    const input = await screen.findByRole('combobox', {name: '搜索题目'})
    expect(input.closest('.numoj-content')).not.toBeNull()
    fireEvent.change(input, {target: {value: ' 来源 '}})
    fireEvent.click(await screen.findByRole('option', {name: '#42 来源书面题'}))
    expect(screen.getByRole('dialog', {name: '从其它题目里复制配置'})).not.toBeNull()
    expect(screen.getByRole('listitem', {name: 'qwen · 节点 7 · 2 票'})).not.toBeNull()
    expect(screen.getByRole('listitem', {name: 'claude · 节点 8 · 3 票'})).not.toBeNull()
    expect(screen.getByRole('list', {name: '评委配置预览'}).querySelectorAll('[data-model-family-logo]')).toHaveLength(2)
    expect(screen.getByRole('spinbutton', {name: '评委模型 1 Vote 次数'}).getAttribute('value')).toBe('1')
    expect(savedBody).toBeUndefined()
    fireEvent.click(screen.getByRole('button', {name: '确认'}))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByRole('spinbutton', {name: '评委模型 1 Vote 次数'}).getAttribute('value')).toBe('2')
    expect(screen.getByRole('spinbutton', {name: '评委模型 2 Vote 次数'}).getAttribute('value')).toBe('3')
    expect(toggle.getAttribute('aria-checked')).toBe(String(Boolean(publicScore)))
    expect(savedBody).toBeUndefined()
    fireEvent.submit(container.querySelector('#addProblemForm')!)
    await screen.findByText('题目已保存')
    expect(savedBody?.get('written_vote_config')).toBe('[{"endpoint_id":7,"count":2},{"endpoint_id":8,"count":3}]')
    expect(savedBody?.get('written_score_public')).toBe(String(publicScore))
    expect(savedBody?.get('written_grading_prompt')).toBe('当前评分标准')
    expect(savedBody?.get('ocr_endpoint_id')).toBe('13')
    expect(savedBody?.get('title')).toBe('书面题')
  })

  it('编辑页请求排除当前题目，关闭弹窗不替换已配置的评委', async () => {
    renderPage(true)
    fireEvent.click(await screen.findByRole('button', {name: '复制 AI Vote 配置'}))
    const search = await screen.findByRole('combobox', {name: '搜索题目'})
    expect(sourceRequests[0]).toContain('grading_mode=1')
    expect(sourceRequests[0]).toContain('exclude_problem_id=11')
    fireEvent.focus(search)
    fireEvent.click(await screen.findByRole('option', {name: '#42 来源书面题'}))
    expect(screen.getByRole('listitem', {name: 'qwen · 节点 7 · 2 票'})).not.toBeNull()
    fireEvent.click(screen.getByRole('button', {name: '关闭'}))
    expect(screen.getAllByRole('spinbutton', {name: /评委模型/})).toHaveLength(1)
    expect(screen.getByRole('spinbutton', {name: '评委模型 1 Vote 次数'}).getAttribute('value')).toBe('1')
    expect(savedBody).toBeUndefined()
  })

  it.each([1, 2, 3])('模式 %s 复制空配置会清除当前评委及旧绑定，保留公开状态和其它用途绑定', async (mode) => {
    copySources[0].written_vote_config = []
    seed.written_grading_mode = mode
    seed.written_score_public = 0
    seed.text_grading_endpoint_id = 7
    seed.direct_image_grading_endpoint_id = 8
    seed.ocr_endpoint_id = 13
    const {container} = renderPage()
    fireEvent.click(await screen.findByRole('button', {name: '复制 AI Vote 配置'}))
    fireEvent.focus(await screen.findByRole('combobox', {name: '搜索题目'}))
    fireEvent.click(await screen.findByRole('option', {name: '#42 来源书面题'}))
    expect(screen.getByText('此题目未配置评委')).not.toBeNull()
    fireEvent.click(screen.getByRole('button', {name: '确认'}))
    fireEvent.submit(container.querySelector('#addProblemForm')!)
    await screen.findByText('题目已保存')
    expect(savedBody?.get('written_vote_config')).toBe('[]')
    expect(savedBody?.get('written_score_public')).toBe('0')
    expect(savedBody?.get(mode === 2 ? 'direct_image_grading_endpoint_id' : 'text_grading_endpoint_id')).toBe('')
    expect(savedBody?.get(mode === 2 ? 'text_grading_endpoint_id' : 'direct_image_grading_endpoint_id')).toBe(mode === 2 ? '7' : '8')
    expect(savedBody?.get('ocr_endpoint_id')).toBe('13')
  })

  it('重新打开时等待读取最新来源，不允许从旧缓存选择已移除的配置', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', {name: '复制 AI Vote 配置'}))
    await screen.findByRole('combobox', {name: '搜索题目'})
    fireEvent.click(screen.getByRole('button', {name: '关闭'}))
    let resolveSource!: (value: Response) => void
    sourceResponse = new Promise<Response>((resolve) => {resolveSource = resolve})
    fireEvent.click(screen.getByRole('button', {name: '复制 AI Vote 配置'}))
    await waitFor(() => expect(sourceRequests).toHaveLength(2))
    expect(screen.queryByRole('combobox', {name: '搜索题目'})).toBeNull()
    resolveSource(await response({problems: []}))
    fireEvent.focus(await screen.findByRole('combobox', {name: '搜索题目'}))
    expect(screen.queryByRole('option', {name: '#42 来源书面题'})).toBeNull()
    expect(screen.getByRole('spinbutton', {name: '评委模型 1 Vote 次数'}).getAttribute('value')).toBe('1')
    expect(savedBody).toBeUndefined()
  })

  it('来源配置请求失败时保留当前评委，重试成功后可继续选择', async () => {
    copyError = true
    renderPage()
    fireEvent.click(await screen.findByRole('button', {name: '复制 AI Vote 配置'}))
    await screen.findByText('来源配置读取失败')
    expect(screen.getByRole('spinbutton', {name: '评委模型 1 Vote 次数'}).getAttribute('value')).toBe('1')
    expect(savedBody).toBeUndefined()
    copyError = false
    fireEvent.click(screen.getByRole('button', {name: '重试'}))
    await screen.findByRole('combobox', {name: '搜索题目'})
    expect(screen.getByRole('spinbutton', {name: '评委模型 1 Vote 次数'}).getAttribute('value')).toBe('1')
  })
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
