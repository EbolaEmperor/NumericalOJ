// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {act, cleanup, render, screen, waitFor} from '@testing-library/react'
import type {ReactNode} from 'react'
import {afterEach, describe, expect, it, vi} from 'vitest'

import {
  agentRunQueryKey,
  cacheAgentRunSnapshot,
  fetchAgentRun,
  synchronizeFinalAgentRun,
  useAgentRunEvents,
  workBlockQueryKey,
  type AgentRunResponse,
  type WorkBlockResponse,
} from './runEvents'

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

function testClient() {
  return new QueryClient({
    defaultOptions: {queries: {retry: false}},
  })
}

function Provider({client, children}: {client: QueryClient; children: ReactNode}) {
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function StreamHarness({onSnapshot = () => undefined, onDone, onConnectionChange}: {onSnapshot?: (state: Record<string, unknown>) => void; onDone: () => void; onConnectionChange: (connected: boolean) => void}) {
  const revision = useAgentRunEvents({
    taskId: 'task-1',
    enabled: true,
    onSnapshot,
    onDone,
    onConnectionChange,
  })
  return <output aria-label="revision">{revision}</output>
}

afterEach(() => {
  cleanup()
  MockEventSource.instances = []
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('Agent 运行事件流', () => {
  it('稀疏会话终态不会覆盖 SSE 已缓存的执行轨迹', async () => {
    const client = testClient()
    const trace = {
      trace_messages: [{kind: 'work_summary', block_id: 'work-0123456789abcdef', is_running: false}],
      subagents: [{subagent_id: 'agent-a', name: '检查架构', status: 'completed'}],
    }
    await cacheAgentRunSnapshot(client, 'task-1', {
      task_id: 'task-1',
      status: 'Running',
      execution_trace: trace,
    })

    await cacheAgentRunSnapshot(client, 'task-1', {
      task_id: 'task-1',
      status: 'Completed',
      session_token_usage: {input_tokens: 12},
    })

    expect(client.getQueryData<AgentRunResponse>(agentRunQueryKey('task-1'))?.state).toMatchObject({
      status: 'Completed',
      execution_trace: trace,
      session_token_usage: {input_tokens: 12},
    })
  })

  it('首次载入的稀疏终态不阻止历史详情按需请求', async () => {
    const client = testClient()
    await cacheAgentRunSnapshot(client, 'task-1', {task_id: 'task-1', status: 'Completed'})
    expect(client.getQueryData(agentRunQueryKey('task-1'))).toBeUndefined()

    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      success: true,
      state: {
        task_id: 'task-1',
        status: 'Completed',
        execution_trace: {
          trace_messages: [],
          subagents: [{subagent_id: 'agent-a', name: '检查架构', status: 'completed'}],
        },
      },
    }), {status: 200, headers: {'Content-Type': 'application/json'}}))
    vi.stubGlobal('fetch', fetchMock)

    await synchronizeFinalAgentRun(client, 'task-1')

    expect(fetchMock).toHaveBeenCalledWith('/api/agent/runs/task-1', expect.any(Object))
    expect(client.getQueryData<AgentRunResponse>(agentRunQueryKey('task-1'))?.state.execution_trace).toMatchObject({
      subagents: [{subagent_id: 'agent-a', name: '检查架构', status: 'completed'}],
    })
  })

  it('收到 status 后直接更新运行详情缓存，不再等待轮询', async () => {
    vi.stubGlobal('EventSource', MockEventSource)
    const client = testClient()
    const connection = vi.fn()
    const onSnapshot = vi.fn()
    render(<Provider client={client}><StreamHarness onSnapshot={onSnapshot} onDone={vi.fn()} onConnectionChange={connection} /></Provider>)

    const source = MockEventSource.instances[0]
    expect(source.url).toBe('/api/agent/runs/task-1/events')
    const snapshot = {
      task_id: 'task-1',
      status: 'Running',
      execution_trace: {trace_messages: [{kind: 'work_summary', block_id: 'work-0123456789abcdef', is_running: true}]},
    }
    act(() => source.emit('status', snapshot))

    await waitFor(() => expect(screen.getByLabelText('revision').textContent).toBe('1'))
    expect(client.getQueryData<AgentRunResponse>(agentRunQueryKey('task-1'))?.state).toEqual(snapshot)
    expect(onSnapshot).toHaveBeenCalledWith(snapshot)
    expect(connection).toHaveBeenLastCalledWith(true)
  })

  it('done 前最终同步用户已经展开的运行中工作块，再冻结终态缓存', async () => {
    vi.stubGlobal('EventSource', MockEventSource)
    const client = testClient()
    const blockId = 'work-0123456789abcdef'
    client.setQueryData<AgentRunResponse>(agentRunQueryKey('task-1'), {
      success: true,
      state: {
        task_id: 'task-1',
        status: 'Running',
        execution_trace: {trace_messages: [{kind: 'work_summary', block_id: blockId, is_running: true}]},
      },
    })
    client.setQueryData<WorkBlockResponse>(workBlockQueryKey('task-1', blockId), {
      success: true,
      block: {block_id: blockId, messages: [{kind: 'tool', text: '旧快照'}]},
    })
    const blockQueryKey = workBlockQueryKey('task-1', blockId)
    await client.invalidateQueries({queryKey: blockQueryKey, exact: true, refetchType: 'none'})
    let staleRequestAborted = false
    const staleRequest = client.fetchQuery<WorkBlockResponse>({
      queryKey: blockQueryKey,
      queryFn: ({signal}) => new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          staleRequestAborted = true
          reject(new DOMException('aborted', 'AbortError'))
        })
      }),
      staleTime: 0,
    }).catch(() => undefined)
    await waitFor(() => expect(client.getQueryState(blockQueryKey)?.fetchStatus).toBe('fetching'))

    let resolveFetch: ((response: Response) => void) | undefined
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => { resolveFetch = resolve }))
    vi.stubGlobal('fetch', fetchMock)
    const done = vi.fn()
    render(<Provider client={client}><StreamHarness onDone={done} onConnectionChange={vi.fn()} /></Provider>)

    const source = MockEventSource.instances[0]
    const terminal = {
      task_id: 'task-1',
      status: 'Completed',
      execution_trace: {trace_messages: [{kind: 'work_summary', block_id: blockId, is_running: false}]},
    }
    act(() => source.emit('status', terminal))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    expect(staleRequestAborted).toBe(true)

    act(() => source.emit('done', terminal))
    expect(done).not.toHaveBeenCalled()
    resolveFetch?.(new Response(JSON.stringify({
      success: true,
      block: {block_id: blockId, messages: [{kind: 'tool_result', text: '最终快照'}]},
    }), {status: 200, headers: {'Content-Type': 'application/json'}}))

    await waitFor(() => expect(done).toHaveBeenCalledTimes(1))
    await staleRequest
    expect(source.closed).toBe(true)
    expect(client.getQueryData<WorkBlockResponse>(workBlockQueryKey('task-1', blockId))?.block.messages).toEqual([
      {kind: 'tool_result', text: '最终快照'},
    ])
    expect(client.getQueryData<AgentRunResponse>(agentRunQueryKey('task-1'))?.state.status).toBe('Completed')
  })

  it('已经缓存完整终态时再次展开不会重复请求后端', async () => {
    const client = testClient()
    client.setQueryData<AgentRunResponse>(agentRunQueryKey('task-1'), {
      success: true,
      state: {
        task_id: 'task-1',
        status: 'Completed',
        execution_trace: {trace_messages: [], subagents: []},
      },
    })
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    await synchronizeFinalAgentRun(client, 'task-1')
    const reopened = await client.fetchQuery({
      queryKey: agentRunQueryKey('task-1'),
      queryFn: () => fetchAgentRun('task-1'),
      staleTime: Infinity,
      gcTime: Infinity,
    })

    expect(fetchMock).not.toHaveBeenCalled()
    expect(reopened.state.status).toBe('Completed')
  })
})
