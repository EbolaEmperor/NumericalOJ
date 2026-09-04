// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import type {JsonRecord} from '../../api/types'
import {AgentExecutionTrace, normalizeAgentExecutionTrace} from './AgentExecutionTrace'

function renderTrace(trace: JsonRecord, liveRevision = 1) {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}}})
  const view = render(<QueryClientProvider client={client}><AgentExecutionTrace trace={trace} traceScope="judge:7:42" live liveRevision={liveRevision} /></QueryClientProvider>)
  return {client, ...view}
}

beforeEach(() => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn()})))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('共享 Agent 执行轨迹', () => {
  it('把旧的平铺评测轨迹投影成与 Agent 任务一致的按需工作块', async () => {
    renderTrace({
      status: 'running',
      trace_files: [{path: 'private.jsonl', content: 'raw'}],
      trace_messages: [
        {kind: 'thinking', title: '分析', text: '先检查目录'},
        {kind: 'tool', title: '调用工具', text: 'ls -la'},
        {kind: 'tool_result', title: '工具结果', text: 'README.md'},
        {kind: 'assistant', text: '检查完成'},
      ],
    })

    expect(screen.getByText('1 thinking, 1 tool call')).toBeTruthy()
    expect(screen.getByText('检查完成')).toBeTruthy()
    expect(screen.queryByText('ls -la')).toBeNull()
    expect(screen.queryByText(/private\.jsonl/)).toBeNull()

    fireEvent.click(screen.getByText('1 thinking, 1 tool call'))
    await waitFor(() => expect(screen.getByText('ls -la')).toBeTruthy())
    expect(screen.getByText('README.md')).toBeTruthy()
  })

  it('已展开的运行中工作块随 SSE revision 增量刷新', async () => {
    const initial: JsonRecord = {status: 'running', trace_messages: [{kind: 'thinking', text: '第一步'}]}
    const {rerender, client} = renderTrace(initial, 1)
    fireEvent.click(screen.getByText('工作中…1 thinking'))
    await waitFor(() => expect(screen.getByText('第一步')).toBeTruthy())

    const updated: JsonRecord = {status: 'running', trace_messages: [{kind: 'thinking', text: '第一步'}, {kind: 'tool', text: '执行检查'}]}
    rerender(<QueryClientProvider client={client}><AgentExecutionTrace trace={updated} traceScope="judge:7:42" live liveRevision={2} /></QueryClientProvider>)

    await waitFor(() => expect(screen.getByText('执行检查')).toBeTruthy())
  })

  it('把 subagent 生命周期汇总在轨迹底部并保留最后状态', () => {
    const status = (sequence: number, value: JsonRecord) => ({
      kind: 'subagent', meta: 'numoj-subagent-status-v1', format: 'json',
      id: `subagent-${sequence}`, text: JSON.stringify(value),
    })
    const trace = normalizeAgentExecutionTrace({status: 'passed', trace_messages: [
      status(1, {subagent_id: 'worker-a', name: '检查规则', status: 'running'}),
      status(2, {subagent_id: 'worker-a', name: '检查规则', status: 'completed'}),
    ]})

    expect(trace.messages).toEqual([])
    expect(trace.subagents).toEqual([{subagent_id: 'worker-a', name: '检查规则', status: 'completed'}])

    renderTrace({status: 'passed', subagents: trace.subagents})
    expect(screen.getByText('SUBAGENTS')).toBeTruthy()
    expect(screen.getByText('检查规则')).toBeTruthy()
    expect(screen.getByText('已完成')).toBeTruthy()
    expect(document.querySelector('.agent-subagent-completed-dot')).toBeTruthy()
  })

  it('父任务终止后不再把缺少完成事件的 subagent 显示为运行中', () => {
    renderTrace({
      status: 'error',
      subagents: [{subagent_id: 'worker-stale', name: '未收束的检索', status: 'running'}],
    })

    expect(screen.queryByText('正在运行')).toBeNull()
    expect(screen.getByText('已结束')).toBeTruthy()
    expect(document.querySelector('.agent-subagent-loader')).toBeNull()
    expect(document.querySelector('.agent-subagent-completed-dot')).toBeTruthy()
  })

  it('为运行中的 subagent 使用更连续的高密度数学曲线', () => {
    renderTrace({
      status: 'running',
      subagents: [{subagent_id: 'worker-running', name: '正在检查', status: 'running'}],
    })

    expect(document.querySelectorAll('.agent-subagent-loader circle')).toHaveLength(42)
  })
})
