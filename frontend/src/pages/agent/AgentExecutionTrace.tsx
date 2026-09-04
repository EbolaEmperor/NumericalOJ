import {useQuery} from '@tanstack/react-query'
import {useEffect, useMemo, useRef, useState} from 'react'

import type {JsonRecord} from '../../api/types'
import {MarkdownContent} from '../../components/MarkdownContent'
import {MathCurveLoader} from '../../components/MathCurveLoader'
import {SavedAttachments} from './AgentAttachments'
import {messageAttachments, messageCopy, messageId, statusKey} from './legacyBehavior'

type WorkBlockResponse = {block: {block_id: string; messages: JsonRecord[]}}
type WorkBlockLoader = (blockId: string, signal?: AbortSignal) => Promise<WorkBlockResponse>

type AgentExecutionTraceProps = {
  trace?: JsonRecord | null
  traceScope: string
  live?: boolean
  liveRevision?: number
  loadWorkBlock?: WorkBlockLoader
  workBlockQueryKey?: (blockId: string) => readonly unknown[]
  sessionId?: string
  openFile?: (path: string) => void
  emptyLabel?: string
}

type NormalizedTrace = {
  messages: JsonRecord[]
  blocks: Map<string, JsonRecord[]>
  subagents: JsonRecord[]
}

export function agentTraceText(message: JsonRecord) {
  const value = message.text ?? message.content ?? message.input ?? message.output ?? message.arguments ?? message.data ?? ''
  if (typeof value === 'string') return value
  try {return JSON.stringify(value, null, 2)} catch {return String(value)}
}

export function agentTraceKind(message: JsonRecord) {
  return statusKey(message.kind || message.type || message.role || 'assistant')
}

function isSubagentStatus(message: JsonRecord) {
  return agentTraceKind(message) === 'subagent' && String(message.meta || '') === 'numoj-subagent-status-v1'
}

function subagentStatus(message: JsonRecord) {
  if (!isSubagentStatus(message)) return null
  try {
    const value = JSON.parse(agentTraceText(message)) as JsonRecord
    const subagentId = String(value.subagent_id || '').trim()
    if (!subagentId) return null
    return {
      subagent_id: subagentId,
      name: String(value.name || message.title || 'Subagent'),
      status: ['running', 'ended'].includes(statusKey(value.status)) ? statusKey(value.status) : 'completed',
    } satisfies JsonRecord
  } catch {
    return null
  }
}

function workSummary(messages: JsonRecord[], running: boolean) {
  const thinkingCount = messages.filter((message) => ['thinking', 'reasoning'].includes(agentTraceKind(message))).length
  const toolCount = messages.filter((message) => ['tool', 'tool_call', 'subagent'].includes(agentTraceKind(message))).length
  const parts: string[] = []
  if (thinkingCount) parts.push(`${thinkingCount} thinking${thinkingCount === 1 ? '' : 's'}`)
  if (toolCount) parts.push(`${toolCount} tool call${toolCount === 1 ? '' : 's'}`)
  const prefix = running ? '工作中…' : ''
  const detail = parts.join(', ')
  return `${prefix}${detail}` || (running ? '工作中…' : '工作详情')
}

function embeddedBlockId(message: JsonRecord, index: number) {
  const source = String(message.event_id || message.id || `${message.offset || ''}-${message.event_index || ''}-${index}`)
  return `embedded-${source.replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, 96) || index}`
}

/**
 * Agent 会话已经从服务端收到 v2 work_summary；评测轨迹仍可能是旧的平铺事件。
 * 这里把平铺事件投影成同一种公开时间线，确保三处 UI 共用完全相同的渲染器。
 */
export function normalizeAgentExecutionTrace(trace?: JsonRecord | null): NormalizedTrace {
  const rawMessages = Array.isArray(trace?.trace_messages) ? trace.trace_messages as JsonRecord[] : []
  const blocks = new Map<string, JsonRecord[]>()
  const messages: JsonRecord[] = []
  const explicitSubagents = Array.isArray(trace?.subagents) ? trace.subagents as JsonRecord[] : []
  const subagentOrder: string[] = []
  const subagents = new Map<string, JsonRecord>()
  explicitSubagents.forEach((item, index) => {
    const id = String(item.subagent_id || `explicit-${index}`)
    subagentOrder.push(id)
    subagents.set(id, item)
  })

  const lastTimelineIndex = rawMessages.reduce((last, message, index) => isSubagentStatus(message) ? last : index, -1)
  let pending: {id: string; last: number; messages: JsonRecord[]} | null = null
  const flush = () => {
    if (!pending?.messages.length) {pending = null; return}
    const runningStatuses = new Set(['running', 'pending', 'judging', 'queued'])
    const running = runningStatuses.has(statusKey(trace?.status)) && pending.last === lastTimelineIndex
    const blockMessages = pending.messages
    blocks.set(pending.id, blockMessages)
    messages.push({
      kind: 'work_summary',
      item_id: pending.id,
      block_id: pending.id,
      summary: workSummary(blockMessages, running),
      is_running: running,
      event_count: blockMessages.length,
      has_error: blockMessages.some((message) => message.is_error === true || message.error === true),
    })
    pending = null
  }

  rawMessages.forEach((message, index) => {
    const parsedSubagent = subagentStatus(message)
    if (parsedSubagent) {
      const id = String(parsedSubagent.subagent_id)
      if (!subagents.has(id)) subagentOrder.push(id)
      subagents.set(id, parsedSubagent)
      return
    }
    const kind = agentTraceKind(message)
    if (kind === 'work_summary' || kind === 'assistant' || kind === 'user' || kind === 'steer') {
      flush()
      messages.push(kind === 'steer' ? {...message, kind: 'user'} : message)
      return
    }
    if (!pending) pending = {id: embeddedBlockId(message, index), last: index, messages: []}
    pending.last = index
    pending.messages.push(message)
  })
  flush()

  const traceRunning = new Set(['running', 'pending', 'judging', 'queued']).has(statusKey(trace?.status))
  const normalizedSubagents = subagentOrder.map((id) => subagents.get(id)).filter(Boolean).map((item) => (
    !traceRunning && statusKey(item?.status) === 'running' ? {...item, status: 'ended'} : item
  )) as JsonRecord[]
  return {messages, blocks, subagents: normalizedSubagents}
}

function SteerMessage({message, sessionId, openFile}: {message: JsonRecord; sessionId?: string; openFile?: (path: string) => void}) {
  const html = String(message.html || message.user_message_html || message.message_html || '')
  return <section className="agent-user-message agent-timeline-steer agent-timeline-steer--detail" data-message-id={messageId(message)}><div className={`agent-user-bubble${html ? ' numoj-markdown' : ''}`}>{html ? <MarkdownContent className="numoj-markdown" html={html} /> : <p>{messageCopy(message) || agentTraceText(message)}</p>}</div>{sessionId ? <SavedAttachments attachments={messageAttachments(message)} sessionId={sessionId} openFile={openFile || (() => undefined)} /> : null}</section>
}

function TraceWorkDetail({message}: {message: JsonRecord}) {
  const kind = agentTraceKind(message)
  const result = kind === 'tool_result'
  const failed = result && (message.is_error === true || message.error === true)
  const visualKind = result ? (failed ? 'error' : 'result') : kind.replaceAll('_', '-')
  const title = String(message.title || message.name || message.tool_name || (['thinking', 'reasoning'].includes(kind) ? '思考过程' : kind === 'tool' || kind === 'tool_call' ? '工具调用' : result ? failed ? '工具执行失败' : '工具结果' : kind === 'subagent' ? '子 Agent' : '工作详情'))
  const icon = ['thinking', 'reasoning'].includes(kind) ? 'fa-circle-notch' : result ? failed ? 'fa-times-circle' : 'fa-check' : kind === 'subagent' ? 'fa-code-branch' : 'fa-terminal'
  const html = String(message.html || '')
  return <section className={`agent-work-detail agent-work-detail--${visualKind}`}><header><i className={`fas ${icon}`} aria-hidden="true" /><strong>{title}</strong></header><div className="agent-work-detail-body">{html && ['thinking', 'reasoning', 'assistant'].includes(kind) ? <MarkdownContent className="agent-trace-copy numoj-markdown" html={html} /> : <pre>{agentTraceText(message)}</pre>}</div></section>
}

function WorkBlock({summary, traceScope, embedded, loadWorkBlock, queryKey, liveRevision}: {summary: JsonRecord; traceScope: string; embedded?: JsonRecord[]; loadWorkBlock?: WorkBlockLoader; queryKey?: (blockId: string) => readonly unknown[]; liveRevision: number}) {
  const [open, setOpen] = useState(false)
  const blockId = String(summary.block_id || '')
  const running = summary.is_running === true
  const lastRevision = useRef(liveRevision)
  const result = useQuery({
    queryKey: queryKey?.(blockId) || ['agent-execution-trace', traceScope, 'work-block', blockId],
    queryFn: ({signal}) => loadWorkBlock ? loadWorkBlock(blockId, signal) : Promise.resolve({block: {block_id: blockId, messages: embedded || []}}),
    enabled: open && Boolean(blockId),
    staleTime: Infinity,
    gcTime: Infinity,
    refetchOnReconnect: false,
  })
  useEffect(() => {
    if (!open || liveRevision === lastRevision.current) return
    lastRevision.current = liveRevision
    if (result.data !== undefined || result.isError) void result.refetch()
  }, [liveRevision, open, result])
  return <details className={`agent-work-block${running ? ' is-running' : ''}`} onToggle={(event) => setOpen(event.currentTarget.open)}><summary><i className="fas fa-wrench" aria-hidden="true" /><span>{String(summary.summary || '工作详情')}</span></summary>{open ? <div className="agent-work-block-body">{result.isPending ? <div className="agent-work-block-placeholder"><MathCurveLoader size="xs" label="正在加载工作详情…" /></div> : result.isError ? <div className="agent-work-block-placeholder">工作详情加载失败，请收起后重试。</div> : result.data.block.messages.length ? result.data.block.messages.map((message, index) => <TraceWorkDetail message={message} key={String(message.event_id || `${agentTraceKind(message)}-${index}`)} />) : <div className="agent-work-block-placeholder">这个工作块没有可展示的详情。</div>}</div> : null}</details>
}

function AgentSubagents({items}: {items: JsonRecord[]}) {
  if (!items.length) return null
  return <section className="agent-subagent-list" aria-label="Subagent 状态"><header>SUBAGENTS</header><ul>{items.map((item, index) => {
    const subagentId = String(item.subagent_id || '')
    const normalizedStatus = statusKey(item.status)
    const running = normalizedStatus === 'running'
    const ended = normalizedStatus === 'ended'
    return <li className={running ? 'is-running' : ended ? 'is-ended' : 'is-completed'} key={subagentId || String(index)}>{running ? <MathCurveLoader className="agent-subagent-loader" size="xs" particleCount={42} iconOnly ariaLabel={`${String(item.name || 'Subagent')} 正在运行`} colorA="#8c7251" colorB="#c19a66" /> : <span className="agent-subagent-completed-dot" aria-hidden="true" />}<span>{String(item.name || `Subagent ${subagentId.slice(-8)}`)}</span><small>{running ? '正在运行' : ended ? '已结束' : '已完成'}</small></li>
  })}</ul></section>
}

export function AgentExecutionTrace({trace, traceScope, live = false, liveRevision = 0, loadWorkBlock, workBlockQueryKey, sessionId, openFile, emptyLabel = '本轮没有可展示的工作详情。'}: AgentExecutionTraceProps) {
  const normalized = useMemo(() => normalizeAgentExecutionTrace(trace), [trace])
  if (!trace) return <div className="agent-working-placeholder"><MathCurveLoader size="sm" label="正在加载工作详情" /></div>
  const status = statusKey(trace.status)
  const awaiting = live && ['running', 'pending', 'judging', 'queued'].includes(status) && !normalized.messages.length && !normalized.subagents.length
  return <div className="agent-trace-surface">{trace.error_message ? <div className="rj-alert">{String(trace.error_message)}</div> : null}<div className="agent-turn-trace">{normalized.messages.map((message, index) => {
    const kind = agentTraceKind(message)
    if (kind === 'work_summary') {
      const blockId = String(message.block_id || '')
      return <WorkBlock summary={message} traceScope={traceScope} embedded={normalized.blocks.get(blockId)} loadWorkBlock={loadWorkBlock} queryKey={workBlockQueryKey} liveRevision={liveRevision} key={blockId || String(index)} />
    }
    if (kind === 'user') return <SteerMessage message={message} sessionId={sessionId} openFile={openFile} key={messageId(message) || String(message.event_id || index)} />
    if (kind !== 'assistant') return null
    const html = String(message.html || '')
    return <section className="agent-trace-reply" key={String(message.item_id || message.event_id || index)}>{html ? <MarkdownContent className="agent-trace-copy numoj-markdown" html={html} /> : <div className="agent-trace-copy"><pre>{agentTraceText(message)}</pre></div>}</section>
  })}{awaiting ? <div className="agent-working-placeholder"><MathCurveLoader size="sm" label="正在等待 Agent 产生工作记录" /></div> : !normalized.messages.length && !normalized.subagents.length ? <div className="agent-workspace-empty">{emptyLabel}</div> : null}<AgentSubagents items={normalized.subagents} /></div></div>
}
