// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, render, screen} from '@testing-library/react'
import {MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

vi.mock('../components/WrittenSubmissionPdf', () => ({WrittenSubmissionPdf: () => <div>学生原稿 PDF</div>}))
vi.mock('../markdown/mathjaxRuntime', () => ({clearMath: vi.fn(), typesetMath: vi.fn(async () => undefined)}))

import SubmissionDetailPage from './SubmissionDetailPage'

beforeEach(() => {
  Object.defineProperty(window, 'matchMedia', {configurable: true, value: vi.fn().mockImplementation((query: string) => ({matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn()}))})
  vi.stubGlobal('fetch', vi.fn().mockImplementation((input: string | URL | Request) => {
    const url = String(input)
    const payload = url.endsWith('/status') ? {status: '评分未公开', score: null, written_comment: '', written_vote: null, result_visible: false, is_judging: false} : {
      user: {is_admin: 0},
      result_visible: false,
      submission: {id: 7, problem_id: 2, problem_type: 2, username: '学生', status: '评分未公开', score: null, code: '', result_visible: false},
      problem: {id: 2, title: '书面题', type: 2, max_score: 5, written_grading_mode: 1},
      test_points: [],
      written_submission: {show_latex_transcription: true, vote: null},
      submission_latex_html: '<p>学生答案转写</p>',
    }
    return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {status: 200, headers: {'Content-Type': 'application/json'}}))
  }))
})

afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks()})

describe('学生书面题隐藏结果', () => {
  it('未公开评分显示占位且保留原稿和OCR，不显示空评语或判题转圈', async () => {
    const client = new QueryClient({defaultOptions: {queries: {retry: false}}})
    const {container} = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/submissions/7']}><Routes><Route path="/submissions/:submissionId" element={<SubmissionDetailPage />} /></Routes></MemoryRouter></QueryClientProvider>)
    await screen.findByText('学生原稿 PDF')
    expect(screen.getAllByText('评分未公开')).toHaveLength(2)
    expect(screen.getByText('学生答案转写')).toBeTruthy()
    expect(container.querySelector('.submission-detail-score > strong')?.textContent).toBe('—')
    expect(screen.queryByText('暂无评语')).toBeNull()
    expect(screen.queryByRole('button', {name: '编辑'})).toBeNull()
    expect(screen.queryByRole('button', {name: /下一个/})).toBeNull()
    expect(container.querySelector('.submission-judging-state')).toBeNull()
  })
})
