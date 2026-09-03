// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {act, cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {StrictMode, useLayoutEffect, type ReactNode} from 'react'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {JudgeDetailModal, MatchDetailModal, ReverseJudgeDetailModal} from './RankingDetailOverlays'

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

function withQueryClient(node: ReactNode) {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}}})
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>)
}

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

  it('Agent Judge 弹窗用共享工作块按需渲染并随 SSE 刷新', async () => {
    vi.stubGlobal('EventSource', MockEventSource)
    withQueryClient(<JudgeDetailModal competitionId={7} target={{id: 44, status: 'Judging'}} canAppeal={false} onClose={vi.fn()} />)
    const source = MockEventSource.instances[0]

    act(() => source.emit('progress', {
      status: 'Judging', total_score: 0, max_score: 10, rules: [],
      execution_trace: {
        trace_id: 'attempt-a', status: 'running',
        trace_files: [{path: 'private.jsonl', content: 'raw'}],
        trace_messages: [{kind: 'thinking', text: '检查提交目录'}],
      },
    }))

    expect(screen.getByText('工作中…1 thinking')).toBeTruthy()
    expect(screen.queryByText('检查提交目录')).toBeNull()
    expect(screen.queryByText(/private\.jsonl/)).toBeNull()
    fireEvent.click(screen.getByText('工作中…1 thinking'))
    await waitFor(() => expect(screen.getByText('检查提交目录')).toBeTruthy())

    act(() => source.emit('progress', {
      status: 'Judging', total_score: 0, max_score: 10, rules: [],
      execution_trace: {
        trace_id: 'attempt-a', status: 'running',
        trace_messages: [
          {kind: 'thinking', text: '检查提交目录'},
          {kind: 'tool', text: '运行测试命令'},
        ],
      },
    }))
    await waitFor(() => expect(screen.getByText('运行测试命令')).toBeTruthy())
  })

  it('反向评测 AI 作答步骤使用同一个分段轨迹组件', async () => {
    vi.stubGlobal('EventSource', MockEventSource)
    withQueryClient(<ReverseJudgeDetailModal competitionId={7} target={{id: 45, status: 'Judging'}} onClose={vi.fn()} />)
    const source = MockEventSource.instances[0]

    act(() => source.emit('progress', {
      status: 'Judging', total_score: 0,
      steps: [{
        step_key: 'agent_answer', step_order: 3, title: 'AI 作答', status: 'running',
        trace_files: [{path: 'answer.jsonl', content: 'raw'}],
        trace_messages: [{kind: 'tool', text: '读取题目附件'}],
      }],
    }))

    await waitFor(() => expect(screen.getByText('工作中…1 tool call')).toBeTruthy())
    expect(screen.queryByText('读取题目附件')).toBeNull()
    expect(screen.queryByText(/answer\.jsonl/)).toBeNull()
    fireEvent.click(screen.getByText('工作中…1 tool call'))
    await waitFor(() => expect(screen.getByText('读取题目附件')).toBeTruthy())
  })
})

describe('ELO 互动详情 Safari 生命周期', () => {
  it('Blob 子文档保留原生视口，不重复补偿 Safari 页面缩放', () => {
    const documents: string[] = []
    const createObjectURL = vi.fn(() => 'blob:numoj-native-viewport')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('Blob', class {
      constructor(parts: BlobPart[] = []) {
        documents.push(parts.map(String).join(''))
      }
    })
    vi.stubGlobal('URL', {...URL, createObjectURL, revokeObjectURL})

    render(<MatchDetailModal
      open
      detail={{success: true, id: 5965, detail_output: {format: 'html', content: '<main style="height:100dvh">replay</main>', height: 540}}}
      pending={false}
      onClose={vi.fn()}
      retry={vi.fn()}
    />)

    expect(documents).toHaveLength(1)
    expect(documents[0]).toContain('<main style="height:100dvh">replay</main>')
    expect(documents[0]).toContain('numoj:html-detail-ready')
    expect(documents[0]).not.toContain('data-numoj-viewport-fix')
    expect(documents[0]).not.toContain('data-numoj-embedded-scale')
    expect(documents[0]).not.toContain('transform:scale(')
  })

  it('在父级 layout effect 运行前已把 Blob URL 交给挂载后的全新 iframe', async () => {
    const onParentLayout = vi.fn()
    const createObjectURL = vi.fn(() => 'blob:numoj-match-detail')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', {...URL, createObjectURL, revokeObjectURL})

    function LayoutProbe() {
      useLayoutEffect(() => {
        const frame = document.querySelector<HTMLIFrameElement>('#matchDetailModal iframe')
        onParentLayout({
          connected: frame?.isConnected,
          src: frame?.getAttribute('src'),
          visibility: frame?.style.visibility,
          pointerEvents: frame?.style.pointerEvents,
        })
      }, [])
      return <MatchDetailModal
        open
        detail={{success: true, id: 5965, detail_output: {format: 'html', content: '<main>replay</main>', height: 540}}}
        pending={false}
        onClose={vi.fn()}
        retry={vi.fn()}
      />
    }

    const view = render(<LayoutProbe />)

    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(onParentLayout).toHaveBeenCalledWith({
      connected: true,
      src: 'blob:numoj-match-detail',
      visibility: 'hidden',
      pointerEvents: 'none',
    })

    const firstFrame = document.querySelector<HTMLIFrameElement>('#matchDetailModal iframe')
    view.rerender(<MatchDetailModal
      open
      detail={{success: true, id: 5964, detail_output: {format: 'html', content: '<main>next replay</main>', height: 580}}}
      pending={false}
      onClose={vi.fn()}
      retry={vi.fn()}
    />)
    const secondFrame = document.querySelector<HTMLIFrameElement>('#matchDetailModal iframe')
    expect(secondFrame).not.toBe(firstFrame)
    await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith('blob:numoj-match-detail'))
  })

  it('StrictMode 重放 layout effect 时不会用旧 cleanup 清空最新 Blob', async () => {
    const objectUrls = ['blob:numoj-first', 'blob:numoj-current']
    const createObjectURL = vi.fn(() => objectUrls.shift() || 'blob:numoj-unexpected')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', {...URL, createObjectURL, revokeObjectURL})

    render(<StrictMode><MatchDetailModal
      open
      detail={{success: true, id: 5965, detail_output: {format: 'html', content: '<main>replay</main>', height: 540}}}
      pending={false}
      onClose={vi.fn()}
      retry={vi.fn()}
    /></StrictMode>)

    const frame = document.querySelector<HTMLIFrameElement>('#matchDetailModal iframe')
    expect(createObjectURL).toHaveBeenCalledTimes(2)
    expect(frame?.getAttribute('src')).toBe('blob:numoj-current')
    await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith('blob:numoj-first'))
    expect(frame?.getAttribute('src')).toBe('blob:numoj-current')
  })
})
