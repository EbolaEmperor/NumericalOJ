// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {MemoryRouter} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {SessionProvider} from '../session'
import HomeworkAdminPage from './HomeworkAdminPage'

let savedBody: FormData | undefined

function response(payload: object) {
  return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {status: 200, headers: {'Content-Type': 'application/json'}}))
}

beforeEach(() => {
  Object.defineProperty(window, 'matchMedia', {configurable: true, value: vi.fn().mockImplementation((query: string) => ({matches: true, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn()}))})
  savedBody = undefined
  vi.stubGlobal('fetch', vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/session') return response({api_version: '1', user: {id: 1, username: 'admin', is_admin: 1}, navigation: {items: [], counts: {}, agent_active: false}, capabilities: {spa: true}})
    if (url.startsWith('/api/admin/homework')) {
      if (init?.method === 'POST') {savedBody = init.body as FormData; return response({})}
      return response({classes: [{class_en: 'test', class_cn: '测试班'}], selected_class: 'test', homework_list: [], all_problems: [{id: 12, title: '矩阵练习'}], all_competitions: [{id: 7, title: '数值积分赛'}], all_edu_projects: [{id: 8, title: '动态平衡术', slug: 'balance'}]})
    }
    throw new Error(`unexpected fetch: ${url}`)
  }))
})

afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks()})

function renderPage() {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/admin/homework?sclass=test']}><SessionProvider><HomeworkAdminPage /></SessionProvider></MemoryRouter></QueryClientProvider>)
}

describe('作业管理共享搜索选择', () => {
  it('可选择教学作品布置作业，并只提交作品编号', async () => {
    const {container} = renderPage()
    fireEvent.click(await screen.findByRole('button', {name: '布置新作业'}))
    fireEvent.click(screen.getByRole('radio', {name: 'VibeHub 教学作品'}))
    const search = screen.getByRole('combobox', {name: '选择VibeHub 教学作品'})
    fireEvent.change(search, {target: {value: '平衡'}})
    fireEvent.click(screen.getByRole('option', {name: '#8 动态平衡术'}))
    fireEvent.change(container.ownerDocument.querySelector('#homeworkAddForm input[type="datetime-local"]')!, {target: {value: '2026-10-28T20:00'}})
    fireEvent.submit(container.ownerDocument.querySelector('#homeworkAddForm')!)
    await waitFor(() => expect(savedBody?.get('vibehub_project_id')).toBe('8'))
    expect(savedBody?.get('problem_id')).toBeNull()
    expect(savedBody?.get('ranking_competition_id')).toBeNull()
  })

  it('切换作业类型时清空搜索和选择，仍通过原确认按钮提交正确编号', async () => {
    const {container} = renderPage()
    fireEvent.click(await screen.findByRole('button', {name: '布置新作业'}))
    const problemSearch = screen.getByRole('combobox', {name: '选择题目'}) as HTMLInputElement
    expect(problemSearch.id).toBe('hwSearchSpa')
    expect(problemSearch.placeholder).toBe('按编号或标题搜索题目…')
    fireEvent.change(problemSearch, {target: {value: '12'}})
    fireEvent.click(screen.getByRole('option', {name: '#12 矩阵练习'}))
    expect(problemSearch.value).toBe('#12 矩阵练习')

    fireEvent.click(screen.getByRole('radio', {name: '打榜赛'}))
    const rankingSearch = screen.getByRole('combobox', {name: '选择打榜赛'}) as HTMLInputElement
    expect(rankingSearch.value).toBe('')
    expect((screen.getByRole('button', {name: '确认添加'}) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(rankingSearch, {target: {value: '积分'}})
    fireEvent.click(screen.getByRole('option', {name: '#7 数值积分赛'}))
    fireEvent.change(container.ownerDocument.querySelector('#homeworkAddForm input[type="datetime-local"]')!, {target: {value: '2026-10-20T20:00'}})
    fireEvent.submit(container.ownerDocument.querySelector('#homeworkAddForm')!)
    await waitFor(() => expect(savedBody?.get('ranking_competition_id')).toBe('7'))
    expect(savedBody?.get('problem_id')).toBeNull()
    expect(savedBody?.get('class_en')).toBe('test')
    expect(savedBody?.get('ddl')).toBe('2026-10-20T20:00')
  })
})
