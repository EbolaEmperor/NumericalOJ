// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {act, cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react'
import {MemoryRouter, Route, Routes, useLocation, useNavigate} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {SessionProvider} from '../session'
import SubmissionsPage from './SubmissionsPage'

const rows = [
  {id: 1, problem_id: 11, problem_title: '第一题', display_problem_title: '第一题', status: 'Accepted', score: 2, display_max_score: 2, display_language: 'PYTHON', created_at: '2026-09-03 12:00:00', test_points: [{test_index: 1, status: 'Accepted'}]},
  {id: 2, problem_id: 12, problem_title: '第二题', display_problem_title: '第二题', status: 'Wrong Answer', score: 0, display_max_score: 2, display_language: 'CPP', created_at: '2026-09-03 12:01:00', test_points: [{test_index: 1, status: 'Wrong Answer'}]},
]

function response(payload: object) {
  return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {status: 200, headers: {'Content-Type': 'application/json'}}))
}

function TestNavigation() {
  const location = useLocation()
  const navigate = useNavigate()
  return <><output aria-label="当前列表地址">{location.pathname}{location.search}</output><button type="button" onClick={() => navigate(-1)}>后退（测试）</button><button type="button" onClick={() => navigate(1)}>前进（测试）</button></>
}

function renderPage(initialEntry = '/submissions') {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[initialEntry]}><TestNavigation /><SessionProvider><Routes><Route path="/submissions" element={<SubmissionsPage />} /><Route path="/submissions/:id" element={<div>完整详情</div>} /></Routes></SessionProvider></MemoryRouter></QueryClientProvider>)
}

beforeEach(() => {
  Object.defineProperty(window, 'matchMedia', {configurable: true, value: vi.fn().mockImplementation((query: string) => ({matches: query.includes('min-width: 1200px'), media: query, addEventListener: vi.fn(), removeEventListener: vi.fn()}))})
  vi.stubGlobal('fetch', vi.fn().mockImplementation((input: string | URL | Request) => {
    const url = String(input)
    if (url === '/api/v1/session') return response({api_version: '1', user: {id: 1, username: 'alice', is_admin: 0}, navigation: {items: [], counts: {}, agent_active: false}, capabilities: {spa: true, legacy_ui_available: false, streaming: true, class_adjust_enabled: false, mail_service_configured: false}})
    if (url.startsWith('/api/submissions?')) {
      const problemOptions = rows.map((row) => ({problem_id: row.problem_id, filter_label: `P${String(row.problem_id).padStart(4, '0')} · ${row.problem_title}`}))
      const problemId = new URL(url, 'http://localhost').searchParams.get('problem_id')
      return response({submissions: rows, page: 1, total_pages: 1, scope: 'mine', problem_options: problemOptions, current_problem_label: problemOptions.find((option) => String(option.problem_id) === problemId)?.filter_label || ''})
    }
    const match = url.match(/^\/api\/submissions\/(\d+)\?view=panel$/)
    if (match) {
      const row = rows.find((item) => item.id === Number(match[1]))!
      return response({submission: {...row, username: 'alice'}, problem: {id: row.problem_id, title: row.problem_title, lang: row.display_language, max_score: 2}, test_points: row.test_points, detail_url: `/submissions/${row.id}`, status_stream_url: `/api/submissions/${row.id}/events?view=panel`})
    }
    throw new Error(`unexpected fetch: ${url}`)
  }))
})

describe('提交列表题目自定义筛选', () => {
  it('用可搜索菜单选择题目，应用时保留其它筛选并回到第一页', async () => {
    const {container} = renderPage('/submissions?page=3&q=作业&status=wrong_answer')
    const picker = await screen.findByRole('combobox', {name: '按题目筛选'})
    expect(container.querySelector('select, datalist, input[list]')).toBeNull()
    fireEvent.click(picker)
    const input = screen.getByRole('textbox', {name: '搜索题目'})
    fireEvent.change(input, {target: {value: ' 第一题 '}})
    expect(screen.getAllByRole('option')).toHaveLength(1)
    fireEvent.click(screen.getByRole('option', {name: 'P0011 · 第一题'}))
    expect(picker.textContent).toContain('P0011 · 第一题')
    expect(screen.queryByRole('listbox')).toBeNull()
    expect(vi.mocked(fetch).mock.calls.filter(([input]) => String(input).startsWith('/api/submissions?'))).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', {name: '应用筛选'}))
    await waitFor(() => expect(screen.getByLabelText('当前列表地址').textContent).toContain('problem_id=11'))
    const params = new URLSearchParams(screen.getByLabelText('当前列表地址').textContent!.split('?')[1])
    expect(params.get('q')).toBe('作业')
    expect(params.get('status')).toBe('wrong_answer')
    expect(params.has('page')).toBe(false)
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.some(([input]) => {
      const url = String(input)
      if (!url.startsWith('/api/submissions?')) return false
      const query = new URL(url, 'http://localhost').searchParams
      return query.get('problem_id') === '11' && query.get('page') === '1'
    })).toBe(true))
  })

  it('保留未在候选里的当前题号，选择全部清空，前进后退同步已应用筛选', async () => {
    renderPage('/submissions?q=作业&status=accepted&problem_id=999')
    let picker = await screen.findByRole('combobox', {name: '按题目筛选'})
    expect(picker.textContent).toContain('P0999')
    fireEvent.click(screen.getByRole('button', {name: '应用筛选'}))
    expect(screen.getByLabelText('当前列表地址').textContent).toContain('problem_id=999')
    fireEvent.click(picker)
    fireEvent.click(screen.getByRole('option', {name: '全部题目'}))
    fireEvent.click(screen.getByRole('button', {name: '应用筛选'}))
    await waitFor(() => expect(screen.getByLabelText('当前列表地址').textContent).not.toContain('problem_id='))
    fireEvent.click(screen.getByRole('button', {name: '后退（测试）'}))
    await waitFor(() => expect(screen.getByRole('combobox', {name: '按题目筛选'}).textContent).toContain('P0999'))
    fireEvent.click(screen.getByRole('button', {name: '前进（测试）'}))
    await waitFor(() => expect(screen.getByRole('combobox', {name: '按题目筛选'}).textContent).toContain('全部题目'))
    picker = screen.getByRole('combobox', {name: '按题目筛选'})
    expect(picker.getAttribute('aria-expanded')).toBe('false')
    const params = new URLSearchParams(screen.getByLabelText('当前列表地址').textContent!.split('?')[1])
    expect(params.get('q')).toBe('作业')
    expect(params.get('status')).toBe('accepted')
  })

  it('搜索框支持键盘选择和取消，Enter 不会提前提交筛选', async () => {
    renderPage()
    const picker = await screen.findByRole('combobox', {name: '按题目筛选'})
    fireEvent.click(picker)
    let input = screen.getByRole('textbox', {name: '搜索题目'}) as HTMLInputElement
    fireEvent.change(input, {target: {value: '不存在的题目'}})
    expect(screen.getByText('没有匹配的选项')).toBeTruthy()
    fireEvent.keyDown(input, {key: 'Enter'})
    expect(screen.getByLabelText('当前列表地址').textContent).toBe('/submissions')
    fireEvent.keyDown(input, {key: 'Escape'})
    expect(screen.queryByRole('listbox')).toBeNull()
    expect(document.activeElement).toBe(picker)
    fireEvent.click(picker)
    input = screen.getByRole('textbox', {name: '搜索题目'}) as HTMLInputElement
    expect(input.value).toBe('')
    fireEvent.keyDown(input, {key: 'ArrowDown'})
    const all = screen.getByRole('option', {name: '全部题目'})
    expect(document.activeElement).toBe(all)
    fireEvent.keyDown(all, {key: 'ArrowDown'})
    expect(document.activeElement).toBe(screen.getByRole('option', {name: 'P0011 · 第一题'}))
    fireEvent.keyDown(document.activeElement!, {key: 'Escape'})
    fireEvent.click(picker)
    input = screen.getByRole('textbox', {name: '搜索题目'}) as HTMLInputElement
    fireEvent.change(input, {target: {value: 'p0012'}})
    fireEvent.keyDown(input, {key: 'Enter'})
    expect(picker.textContent).toContain('P0012 · 第二题')
    expect(screen.queryByRole('listbox')).toBeNull()
    expect(screen.getByLabelText('当前列表地址').textContent).toBe('/submissions')
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('提交列表主从视图', () => {
  it('书面题保留 Pending 状态但已停止批改时，不重新建立判题流', async () => {
    const eventSource = vi.fn(function () {return {addEventListener: vi.fn(), close: vi.fn()}})
    vi.stubGlobal('EventSource', eventSource)
    vi.mocked(fetch).mockImplementation((input: string | URL | Request) => {
      const url = String(input)
      if (url === '/api/v1/session') return response({api_version: '1', user: {id: 1, username: 'alice', is_admin: 0}, navigation: {items: [], counts: {}, agent_active: false}, capabilities: {spa: true}})
      const submission = {id: 1, problem_id: 11, problem_type: 2, written_grading_mode: 1, problem_title: '书面题', status: 'Pending', score: null, result_visible: false, is_judging: false}
      if (url.startsWith('/api/submissions?')) return response({submissions: [submission], page: 1, total_pages: 1, scope: 'mine', problem_options: []})
      if (url === '/api/submissions/1?view=panel') return response({submission, problem: {id: 11, title: '书面题', type: 2, written_grading_mode: 1, max_score: 5}, test_points: [], detail_url: '/submissions/1'})
      throw new Error(`unexpected fetch: ${url}`)
    })
    renderPage()
    await screen.findByRole('heading', {name: '书面题'})
    await act(async () => undefined)
    expect(eventSource).not.toHaveBeenCalled()
    expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).endsWith('/status'))).toBe(false)
  })

  it('学生书面评分显示占位，终态列表和预览定时同步公开开关', async () => {
    vi.useFakeTimers()
    let visible = false
    vi.mocked(fetch).mockImplementation((input: string | URL | Request) => {
      const url = String(input)
      if (url === '/api/v1/session') return response({api_version: '1', user: {id: 1, username: 'alice', is_admin: 0}, navigation: {items: [], counts: {}, agent_active: false}, capabilities: {spa: true}})
      const submission = {id: 1, problem_id: 11, problem_type: 2, written_grading_mode: 1, problem_title: '书面题', status: visible ? 'Accepted' : '评分未公开', score: visible ? 5 : null, result_visible: visible, display_max_score: 5}
      if (url.startsWith('/api/submissions?')) return response({submissions: [submission], page: 1, total_pages: 1, scope: 'mine', problem_options: []})
      if (url === '/api/submissions/1?view=panel') return response({submission, problem: {id: 11, title: '书面题', max_score: 5}, test_points: [], detail_url: '/submissions/1'})
      throw new Error(`unexpected fetch: ${url}`)
    })
    const {container} = renderPage()
    await act(async () => {await vi.advanceTimersByTimeAsync(50)})
    expect(screen.getByLabelText('提交 #1，评分未公开')).toBeTruthy()
    expect(container.querySelector('.submission-col-score .submission-score')?.textContent).toBe('—')
    expect(container.querySelector('.submission-detail-panel .submission-detail-score strong')?.textContent).toBe('—')

    visible = true
    await act(async () => {await vi.advanceTimersByTimeAsync(15_050)})
    expect(screen.getByLabelText('提交 #1，Accepted')).toBeTruthy()
    expect(container.querySelector('.submission-col-score .submission-score')?.textContent).toBe('5')
    expect(container.querySelector('.submission-detail-panel .submission-detail-score strong')?.textContent).toBe('5')
  })

  it('保留表格语义但不显示旧版已移除的表头行', async () => {
    renderPage()
    await screen.findByLabelText('提交 #1，Accepted')

    const table = screen.getByRole('table', {name: '提交记录'})
    expect(table.querySelector('thead')?.classList.contains('visually-hidden')).toBe(true)
  })

  it('桌面点击和键盘选择只切换右侧预览，不离开列表', async () => {
    renderPage()
    const first = await screen.findByLabelText('提交 #1，Accepted')
    const second = screen.getByLabelText('提交 #2，Wrong Answer')
    const panel = document.querySelector('.submission-detail-panel') as HTMLElement
    expect(await within(panel).findByRole('heading', {name: '第一题'})).toBeTruthy()
    expect(first.getAttribute('aria-selected')).toBe('true')

    fireEvent.click(second)
    expect(await within(panel).findByRole('heading', {name: '第二题'})).toBeTruthy()
    expect(second.getAttribute('aria-selected')).toBe('true')
    expect(screen.queryByText('完整详情')).toBeNull()

    fireEvent.keyDown(first, {key: ' '})
    await waitFor(() => expect(first.getAttribute('aria-selected')).toBe('true'))
    expect(await within(panel).findByRole('heading', {name: '第一题'})).toBeTruthy()
  })

  it('手机端不建立隐藏的详情连接，整行点击进入完整详情', async () => {
    vi.mocked(window.matchMedia).mockImplementation((query: string) => ({matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn()} as unknown as MediaQueryList))
    renderPage()

    const first = await screen.findByLabelText('提交 #1，Accepted')
    await waitFor(() => {
      const calls = vi.mocked(fetch).mock.calls.map(([input]) => String(input))
      expect(calls.some((url) => url.includes('?view=panel'))).toBe(false)
    })

    fireEvent.click(first)
    expect(await screen.findByText('完整详情')).toBeTruthy()
  })
})
