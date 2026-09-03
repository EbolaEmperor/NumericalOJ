import {afterEach, describe, expect, it, vi} from 'vitest'

import {
  agentComposerEnterAction,
  agentSessionUrl,
  cachedFallbackMessage,
  createAgentMessageId,
  formatTokenCount,
  queuedMessages,
  usageDisplay,
} from './legacyBehavior'

describe('Agent 旧版浏览器行为兼容', () => {
  afterEach(() => {vi.restoreAllMocks(); vi.unstubAllGlobals()})

  it('使用旧版 randomUUID 规则并移除连字符', () => {
    vi.stubGlobal('crypto', {randomUUID: () => '12345678-1234-1234-1234-123456789abc'})
    expect(createAgentMessageId()).toBe('12345678123412341234123456789abc')
  })

  it('把旧版 Agent 详情地址规范化到 React 会话路由', () => {
    expect(agentSessionUrl('session / 1', '/agent/tasks/stale')).toBe('/agents/session%20%2F%201')
    expect(agentSessionUrl('', '/agent/tasks/abc?turn=2')).toBe('/agents/abc?turn=2')
    expect(agentSessionUrl('', '/admin/agent_tasks/legacy')).toBe('/agents/legacy')
    expect(agentSessionUrl('', '/api/agent/sessions/native')).toBe('/agents/native')
    expect(agentSessionUrl('', '')).toBe('/agents')
  })

  it('HTTP 环境沿用旧版 getRandomValues UUID 并移除连字符', () => {
    vi.stubGlobal('crypto', {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(0)
        return bytes
      },
    })
    expect(createAgentMessageId('retry')).toBe('00000000000040008000000000000000')
  })

  it('保持旧版输入框快捷键：Enter 排队、Ctrl/Cmd+Enter 插话、Shift+Enter 换行', () => {
    const action = (overrides: Partial<Parameters<typeof agentComposerEnterAction>[0]> = {}) => agentComposerEnterAction({
      key: 'Enter', keyCode: 13, composing: false, shiftKey: false,
      ctrlKey: false, metaKey: false, running: true, ...overrides,
    })
    expect(action()).toBe('send')
    expect(action({ctrlKey: true})).toBe('steer')
    expect(action({metaKey: true})).toBe('steer')
    expect(action({shiftKey: true})).toBeNull()
    expect(action({composing: true})).toBeNull()
    expect(action({keyCode: 229})).toBeNull()
    expect(action({running: false, ctrlKey: true})).toBe('send')
  })

  it('只使用旧版会话用量字段计算 INPUT、CACHED、OUTPUT 与 COST', () => {
    expect(usageDisplay({
      input_total_tokens: 2_000,
      input_cached_tokens: 500,
      output_tokens: 750,
      cost_rmb: '001.2300',
      input_tokens: 999_999,
      cached_input_tokens: 999_999,
      cost: 999,
    }, false)).toEqual({input: '2.00 K', cached: '25.00%', output: '750.00', cost: '1.23 元'})
  })

  it('保留旧版 cached 字段回退计费提示和 Token 格式', () => {
    expect(cachedFallbackMessage({cached_fallback_request_count: 2, cached_fallback_input_tokens: 1_500}))
      .toBe('您的本次对话中，有 2 次 LLM 调用没有返回可识别的 cached 字段，因此有 1.50 K 的 input tokens 按照 90% 的默认命中率来计费。')
    expect(formatTokenCount(0)).toBe('0.00')
  })

  it('按照旧版状态与 queue_position 筛选排队消息', () => {
    expect(queuedMessages({queued_messages: [
      {message_id: 'done', status: 'sent', queue_position: 0},
      {message_id: 'second', status: 'queued', queue_position: 2},
      {message_id: 'first', status: 'dispatching', queue_position: 1},
    ]}).map((message) => message.message_id)).toEqual(['first', 'second'])
  })
})
