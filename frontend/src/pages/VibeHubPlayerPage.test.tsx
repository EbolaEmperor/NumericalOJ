// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, render, waitFor} from '@testing-library/react'
import {MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, beforeEach, expect, it, vi} from 'vitest'

import VibeHubPlayerPage from './VibeHubPlayerPage'

const {displayMode} = vi.hoisted(() => ({displayMode: vi.fn()}))
vi.mock('../components/AppShell', () => ({usePageDisplayMode: () => displayMode}))
let publicKind = 'edu'

beforeEach(() => {
  publicKind = 'edu'
  Object.defineProperty(window, 'matchMedia', {configurable: true, value: vi.fn().mockImplementation((query: string) => ({matches: true, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn()}))})
  vi.stubGlobal('fetch', vi.fn().mockImplementation((input: string | URL | Request) => {
    const url = String(input)
    const payload = url.includes('/edu/launch') || url.includes('/runtime/leases')
      ? {lease_token: 'lease', proxy_url: '/vibehub/runtime/lease/', heartbeat_url: '/heartbeat', release_url: '/release'}
      : {project: {title: '动态平衡术', kind: publicKind}}
    return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {status: 200, headers: {'Content-Type': 'application/json'}}))
  }))
})

afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks()})

it.each(['edu', 'game'])('教学作业在当前公开作品类型为 %s 时仍通过教育入口启动', async (kind) => {
  publicKind = kind
  const client = new QueryClient({defaultOptions: {queries: {retry: false}}})
  const {container} = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/vibehub/balance/play?assignment=7']}><Routes><Route path="/vibehub/:slug/play" element={<VibeHubPlayerPage />} /></Routes></MemoryRouter></QueryClientProvider>)
  await waitFor(() => expect(container.querySelector('iframe')?.getAttribute('src')).toBe('/vibehub/runtime/lease/'))
  const launch = vi.mocked(fetch).mock.calls.find(([input]) => String(input).endsWith('/edu/launch'))
  expect(launch).toBeTruthy()
  expect(JSON.parse(String(launch?.[1]?.body))).toMatchObject({assignment_id: 7})
  expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).includes('/runtime/leases'))).toBe(false)
})
