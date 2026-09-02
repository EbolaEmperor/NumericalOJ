// @vitest-environment jsdom

import {act, cleanup, render, screen} from '@testing-library/react'
import {afterEach, describe, expect, it, vi} from 'vitest'

import {submissionStatusIsActive, type SubmissionStatusSnapshot, useSubmissionStatusStream} from './submissionStatusStream'

type Listener = (event: MessageEvent) => void

class MockEventSource {
  static instances: MockEventSource[] = []

  readonly url: string
  readonly listeners = new Map<string, Listener[]>()
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  closed = false

  constructor(url: string | URL) {
    this.url = String(url)
    MockEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: EventListener) {
    const listeners = this.listeners.get(type) || []
    listeners.push(listener as Listener)
    this.listeners.set(type, listeners)
  }

  close() {
    this.closed = true
  }

  emit(type: string, payload: unknown) {
    const event = new MessageEvent(type, {data: JSON.stringify(payload)})
    this.listeners.get(type)?.forEach((listener) => listener(event))
  }
}

function Harness({fallbackPolling = true, streamUrl, onSnapshot, onDone}: {fallbackPolling?: boolean; streamUrl?: string; onSnapshot: (snapshot: SubmissionStatusSnapshot) => void; onDone: () => void}) {
  const state = useSubmissionStatusStream({
    submissionId: 42,
    enabled: true,
    fallbackPolling,
    streamUrl,
    startDelayMs: 300,
    onSnapshot,
    onDone,
  })
  return <output aria-label="stream-state">{state.transport}|{state.message}</output>
}

afterEach(() => {
  cleanup()
  MockEventSource.instances = []
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('提交评测状态流', () => {
  it('为所有旧版运行态建立 SSE，并把测试点快照立即交给页面', async () => {
    expect(['Pending', 'Waiting', 'Running', 'Generating'].every(submissionStatusIsActive)).toBe(true)
    vi.useFakeTimers()
    vi.stubGlobal('EventSource', MockEventSource)
    const onSnapshot = vi.fn()
    const onDone = vi.fn()
    render(<Harness onSnapshot={onSnapshot} onDone={onDone} />)

    expect(MockEventSource.instances).toHaveLength(0)
    await act(() => vi.advanceTimersByTimeAsync(300))
    const source = MockEventSource.instances[0]
    expect(source.url).toBe('/api/submissions/42/events')

    act(() => source.emit('status', {
      status: 'Running',
      score: null,
      is_judging: true,
      test_points: [{test_index: 1, status: 'Accepted'}],
    }))
    expect(onSnapshot).toHaveBeenLastCalledWith(expect.objectContaining({status: 'Running', test_points: [{test_index: 1, status: 'Accepted'}]}))
    expect(screen.getByLabelText('stream-state').textContent).toContain('streaming|正在编译和初始化...')

    act(() => source.emit('done', {
      status: 'Accepted',
      score: 1,
      is_judging: false,
      test_points: [{test_index: 1, status: 'Accepted'}],
    }))
    expect(source.closed).toBe(true)
    expect(onDone).toHaveBeenCalledTimes(1)
    expect(onSnapshot).toHaveBeenCalledTimes(2)
  })

  it('SSE 建连失败时按旧版节奏回退状态轮询', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('EventSource', MockEventSource)
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      status: 'Wrong Answer',
      score: 0,
      is_judging: false,
      test_points: [{test_index: 1, status: 'Wrong Answer'}],
    }), {status: 200, headers: {'Content-Type': 'application/json'}}))
    vi.stubGlobal('fetch', fetchMock)
    const onSnapshot = vi.fn()
    const onDone = vi.fn()
    render(<Harness onSnapshot={onSnapshot} onDone={onDone} />)

    await act(() => vi.advanceTimersByTimeAsync(300))
    act(() => MockEventSource.instances[0].onerror?.())
    expect(MockEventSource.instances[0].closed).toBe(true)
    await act(() => vi.advanceTimersByTimeAsync(500))

    expect(fetchMock).toHaveBeenCalledWith('/api/submissions/42/status', expect.objectContaining({credentials: 'same-origin', cache: 'no-store'}))
    expect(onSnapshot).toHaveBeenCalledWith(expect.objectContaining({status: 'Wrong Answer', is_judging: false}))
    expect(onDone).toHaveBeenCalledTimes(1)
  })

  it('列表侧栏断线时保留原生 EventSource 自动重连', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('EventSource', MockEventSource)
    render(<Harness fallbackPolling={false} streamUrl="/api/submissions/42/events?view=panel" onSnapshot={vi.fn()} onDone={vi.fn()} />)

    await act(() => vi.advanceTimersByTimeAsync(300))
    expect(MockEventSource.instances[0].url).toBe('/api/submissions/42/events?view=panel')
    act(() => MockEventSource.instances[0].onerror?.())

    expect(MockEventSource.instances[0].closed).toBe(false)
    expect(screen.getByLabelText('stream-state').textContent).toContain('reconnecting|')
  })
})
