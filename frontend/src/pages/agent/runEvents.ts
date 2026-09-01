import {type QueryClient, useQueryClient} from '@tanstack/react-query'
import {useEffect, useRef, useState} from 'react'

import {apiFetch} from '../../api/client'
import type {ApiEnvelope, JsonRecord} from '../../api/types'

export interface AgentRunResponse extends ApiEnvelope {state: JsonRecord}
export interface WorkBlockResponse extends ApiEnvelope {block: {block_id: string; messages: JsonRecord[]}}

const terminalStatuses = new Set([
  'completed',
  'failed',
  'canceled',
  'cancelled',
  'cleanupfailed',
  'cleanup_failed',
])

export const agentRunQueryKey = (taskId: string) => ['agent-run', taskId] as const
export const workBlockQueryKey = (taskId: string, blockId: string) => ['agent-run', taskId, 'work-block', blockId] as const

export function fetchAgentRun(taskId: string, signal?: AbortSignal) {
  return apiFetch<AgentRunResponse>(`/api/agent/runs/${encodeURIComponent(taskId)}`, {signal})
}

export function fetchAgentWorkBlock(taskId: string, blockId: string, signal?: AbortSignal) {
  return apiFetch<WorkBlockResponse>(`/agent/runs/${encodeURIComponent(taskId)}/work-blocks/${encodeURIComponent(blockId)}`, {signal})
}

function traceMessages(state: JsonRecord) {
  const trace = state.execution_trace && typeof state.execution_trace === 'object'
    ? state.execution_trace as JsonRecord
    : {}
  return Array.isArray(trace.trace_messages) ? trace.trace_messages as JsonRecord[] : []
}

export function runningWorkBlockId(state: JsonRecord) {
  const messages = traceMessages(state)
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index]
    if (String(message.kind || '').toLowerCase() !== 'work_summary') continue
    if (message.is_running === true) return String(message.block_id || '')
  }
  return ''
}

export function agentRunIsTerminal(state: JsonRecord) {
  return terminalStatuses.has(String(state.status || '').trim().toLowerCase())
}

function workBlockWasOpened(queryClient: QueryClient, taskId: string, blockId: string) {
  const query = queryClient.getQueryState<WorkBlockResponse>(workBlockQueryKey(taskId, blockId))
  return query?.data !== undefined || query?.fetchStatus === 'fetching'
}

async function refreshFinalWorkBlock(queryClient: QueryClient, taskId: string, blockId: string) {
  if (!blockId || !workBlockWasOpened(queryClient, taskId, blockId)) return
  const queryKey = workBlockQueryKey(taskId, blockId)
  await queryClient.cancelQueries({queryKey, exact: true})
  await queryClient.invalidateQueries({queryKey, exact: true, refetchType: 'none'})
  try {
    await queryClient.fetchQuery({
      queryKey,
      queryFn: ({signal}) => fetchAgentWorkBlock(taskId, blockId, signal),
      staleTime: 0,
      gcTime: Infinity,
    })
  } catch {
    // 最终同步失败时保持 invalidated；用户下次展开会重新请求，而不会把
    // 一个可能缺少末尾事件的旧快照永久当成最终缓存。
  }
}

export function cacheAgentRunSnapshot(queryClient: QueryClient, taskId: string, state: JsonRecord) {
  const previous = queryClient.getQueryData<AgentRunResponse>(agentRunQueryKey(taskId))
  const previousBlockId = runningWorkBlockId(previous?.state || {})
  const nextBlockId = runningWorkBlockId(state)
  queryClient.setQueryData<AgentRunResponse>(agentRunQueryKey(taskId), (current) => ({
    ...(current || {}),
    success: true,
    state,
  }))
  return previousBlockId && previousBlockId !== nextBlockId
    ? refreshFinalWorkBlock(queryClient, taskId, previousBlockId)
    : Promise.resolve()
}

export async function synchronizeFinalAgentRun(queryClient: QueryClient, taskId: string) {
  const queryKey = agentRunQueryKey(taskId)
  const current = queryClient.getQueryData<AgentRunResponse>(queryKey)
  if (agentRunIsTerminal(current?.state || {})) return

  const previousBlockId = runningWorkBlockId(current?.state || {})
  await queryClient.cancelQueries({queryKey, exact: true})
  await queryClient.invalidateQueries({queryKey, exact: true, refetchType: 'none'})
  try {
    const response = await queryClient.fetchQuery({
      queryKey,
      queryFn: ({signal}) => fetchAgentRun(taskId, signal),
      staleTime: 0,
      gcTime: Infinity,
    })
    const nextBlockId = runningWorkBlockId(response.state || {})
    if (previousBlockId && previousBlockId !== nextBlockId) {
      await refreshFinalWorkBlock(queryClient, taskId, previousBlockId)
    }
  } catch (error) {
    await queryClient.invalidateQueries({queryKey, exact: true, refetchType: 'none'})
    throw error
  }
}

interface AgentRunEventsOptions {
  taskId: string
  enabled: boolean
  onSnapshot: (state: JsonRecord) => void | Promise<void>
  onDone: () => void
  onConnectionChange: (connected: boolean) => void
}

export function useAgentRunEvents({taskId, enabled, onSnapshot, onDone, onConnectionChange}: AgentRunEventsOptions) {
  const queryClient = useQueryClient()
  const callbacksRef = useRef({onSnapshot, onDone, onConnectionChange})
  const [revision, setRevision] = useState(0)

  callbacksRef.current = {onSnapshot, onDone, onConnectionChange}

  useEffect(() => {
    callbacksRef.current.onConnectionChange(false)
    if (!enabled || !taskId || typeof window === 'undefined' || !window.EventSource) {
      return undefined
    }

    let disposed = false
    let settled = false
    let snapshotQueue = Promise.resolve()
    const source = new EventSource(`/api/agent/runs/${encodeURIComponent(taskId)}/events`)

    const parseSnapshot = (event: MessageEvent) => {
      try {
        const snapshot = JSON.parse(event.data) as JsonRecord
        return snapshot && typeof snapshot === 'object' ? snapshot : null
      } catch {
        return null
      }
    }

    const enqueueSnapshot = (snapshot: JsonRecord, bumpRevision: boolean, notifySnapshot: boolean) => {
      snapshotQueue = snapshotQueue.catch(() => undefined).then(async () => {
        await queryClient.cancelQueries({queryKey: agentRunQueryKey(taskId), exact: true})
        const finalWorkBlock = cacheAgentRunSnapshot(queryClient, taskId, snapshot)
        if (!disposed && notifySnapshot) await callbacksRef.current.onSnapshot(snapshot)
        if (!disposed && bumpRevision) setRevision((value) => value + 1)
        await finalWorkBlock
      })
      return snapshotQueue
    }

    source.onopen = () => {
      if (!disposed) callbacksRef.current.onConnectionChange(true)
    }
    source.addEventListener('status', ((event: MessageEvent) => {
      const snapshot = parseSnapshot(event)
      if (!snapshot || disposed) return
      callbacksRef.current.onConnectionChange(true)
      void enqueueSnapshot(snapshot, true, true)
    }) as EventListener)
    source.addEventListener('done', ((event: MessageEvent) => {
      if (settled || disposed) return
      settled = true
      const snapshot = parseSnapshot(event)
      const finalSync = snapshot ? enqueueSnapshot(snapshot, false, false) : snapshotQueue
      void finalSync.catch(() => undefined).then(() => {
        source.close()
        if (disposed) return
        callbacksRef.current.onConnectionChange(false)
        callbacksRef.current.onDone()
      })
    }) as EventListener)
    source.onerror = () => {
      if (!disposed && !settled) callbacksRef.current.onConnectionChange(false)
      // 不主动 close：原生 EventSource 会按服务端 retry/浏览器退避自动重连，
      // 重连后的首个 status 快照可自然补齐中断期间的更新。
    }

    return () => {
      disposed = true
      source.close()
      callbacksRef.current.onConnectionChange(false)
    }
  }, [enabled, queryClient, taskId])

  return revision
}
