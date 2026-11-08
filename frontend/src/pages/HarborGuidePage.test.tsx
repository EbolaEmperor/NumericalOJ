// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, render, screen, within} from '@testing-library/react'
import {MemoryRouter} from 'react-router-dom'
import {afterEach, expect, it, vi} from 'vitest'

import HarborGuidePage from './HarborGuidePage'

afterEach(() => {cleanup(); vi.unstubAllGlobals()})

it('以手册版式显示 Markdown 正文和目录，并提供返回入口', async () => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn()})))
  vi.stubGlobal('fetch', vi.fn((input) => {
    expect(String(input)).toBe('/api/ranking/harbor-guide/rendered')
    return Promise.resolve(new Response(JSON.stringify({success: true,
      html: '<h1>Harbor 格式说明</h1><h2 id="submit">提交</h2><p>从题目附件下载模板。</p>',
      toc_html: '<div class="toc"><ul><li><a href="#submit">提交</a></li></ul></div>',
    }), {headers: {'Content-Type': 'application/json'}}))
  }))
  const client = new QueryClient({defaultOptions: {queries: {retry: false}}})
  render(<QueryClientProvider client={client}><MemoryRouter><HarborGuidePage /></MemoryRouter></QueryClientProvider>)
  expect(await screen.findByRole('heading', {name: 'Harbor 格式说明'})).toBeTruthy()
  const toc = screen.getByRole('complementary', {name: 'Harbor 格式说明目录'})
  expect(within(toc).getByRole('link', {name: '提交'}).getAttribute('href')).toBe('#submit')
  expect(screen.getByRole('link', {name: '返回打榜赛列表'}).getAttribute('href')).toBe('/rankings')
  expect(document.querySelector('.vibe-guide-markdown-body')).toBeTruthy()
  expect(document.title).toBe('Harbor 格式说明 - Numerical OJ')
})
