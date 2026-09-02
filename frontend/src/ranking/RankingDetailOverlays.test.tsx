// @vitest-environment jsdom

import {act, cleanup, render, screen} from '@testing-library/react'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {JudgeDetailModal, ReverseJudgeDetailModal} from './RankingDetailOverlays'

type Listener = (event: MessageEvent) => void

class MockEventSource {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSED = 2
  static instances: MockEventSource[] = []

  readonly listeners = new Map<string, Listener[]>()
  readyState = MockEventSource.CONNECTING
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  closed = false

  constructor(readonly url: string | URL) {
    MockEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: EventListener) {
    const listeners = this.listeners.get(type) || []
    listeners.push(listener as Listener)
    this.listeners.set(type, listeners)
  }

  close() {
    this.closed = true
    this.readyState = MockEventSource.CLOSED
  }

  emit(type: string, payload: unknown) {
    const event = new MessageEvent(type, {data: JSON.stringify(payload)})
    this.listeners.get(type)?.forEach((listener) => listener(event))
  }
}

beforeEach(() => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn()})))
})

afterEach(() => {
  cleanup()
  MockEventSource.instances = []
  vi.unstubAllGlobals()
})

describe('打榜赛评测详情实时连接', () => {
  it('反向评测在单次 SSE 租约超时后保留快照并交给浏览器续接', () => {
    vi.stubGlobal('EventSource', MockEventSource)
    render(<ReverseJudgeDetailModal competitionId={7} target={{id: 42, status: 'Judging'}} onClose={vi.fn()} />)
    const source = MockEventSource.instances[0]

    act(() => source.emit('timeout', {
      status: 'Judging',
      total_score: 20,
      steps: [{step_key: 'agent_answer', status: 'running', answer_available: true}],
    }))

    expect(source.closed).toBe(false)
    expect(screen.getByText(/正在自动续接评测进度/)).toBeTruthy()
    expect(screen.getByRole('link', {name: /下载 AI 解答/}).getAttribute('href')).toBe('/api/ranking/submissions/42/reverse-agent-answer')
  })

  it('普通 Agent 评测沿用旧版超时后关闭并提示重新打开', () => {
    vi.stubGlobal('EventSource', MockEventSource)
    render(<JudgeDetailModal competitionId={7} target={{id: 43, status: 'Judging'}} canAppeal={false} onClose={vi.fn()} />)
    const source = MockEventSource.instances[0]

    act(() => source.emit('timeout', {status: 'Judging'}))

    expect(source.closed).toBe(true)
    expect(screen.getByText(/实时连接超时，请关闭弹窗后重试/)).toBeTruthy()
  })
})
