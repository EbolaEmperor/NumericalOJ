import {useEffect, useRef, useState} from 'react'

import type {JsonRecord} from '../../api/types'

export interface SubmissionStatusSnapshot extends JsonRecord {
  status?: string
  score?: number | null
  is_judging?: boolean
  test_points?: JsonRecord[]
}

interface SubmissionStatusStreamOptions {
  submissionId?: number
  enabled: boolean
  streamUrl?: string
  fallbackPolling?: boolean
  startDelayMs?: number
  initialMessage?: string
  onSnapshot: (snapshot: SubmissionStatusSnapshot) => void
  onDone?: () => void
}

type SubmissionStreamTransport = 'idle' | 'connecting' | 'streaming' | 'polling' | 'reconnecting'

const activeStatuses = new Set(['Pending', 'Waiting', 'Running', 'Generating'])

export function submissionStatusIsActive(status: unknown) {
  return activeStatuses.has(String(status || '').trim())
}

function progressMessage(updateCount: number) {
  if (updateCount < 5) return '正在编译和初始化...'
  if (updateCount < 15) return '正在运行测试点...'
  if (updateCount < 30) return '判题进行中，请耐心等待...'
  return '判题时间较长，正在处理复杂测试...'
}

function pollingInterval(updateCount: number) {
  if (updateCount < 20) return 500
  if (updateCount < 40) return 1_000
  return 5_000
}

function parseSnapshot(value: unknown): SubmissionStatusSnapshot | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as SubmissionStatusSnapshot
    : null
}

async function fetchSubmissionStatus(submissionId: number, signal: AbortSignal) {
  const response = await fetch(`/api/submissions/${submissionId}/status`, {
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {Accept: 'application/json'},
    signal,
  })
  const payload = parseSnapshot(await response.json())
  if (!response.ok || !payload || payload.error) {
    throw new Error(String(payload?.error || `请求失败（${response.status}）`))
  }
  return payload
}

export function useSubmissionStatusStream({
  submissionId,
  enabled,
  streamUrl,
  fallbackPolling = false,
  startDelayMs = 0,
  initialMessage = '正在编译和初始化...',
  onSnapshot,
  onDone = () => undefined,
}: SubmissionStatusStreamOptions) {
  const callbacksRef = useRef({onSnapshot, onDone})
  const [message, setMessage] = useState(initialMessage)
  const [transport, setTransport] = useState<SubmissionStreamTransport>('idle')

  callbacksRef.current = {onSnapshot, onDone}

  useEffect(() => {
    setMessage(initialMessage)
    setTransport(enabled ? 'connecting' : 'idle')
    if (!enabled || !submissionId || typeof window === 'undefined') return undefined

    let disposed = false
    let settled = false
    let closedByClient = false
    let hasMessage = false
    let updateCount = 0
    let source: EventSource | null = null
    let timer: ReturnType<typeof setTimeout> | null = null
    let pollingRequest: AbortController | null = null

    const clearTimer = () => {
      if (timer !== null) window.clearTimeout(timer)
      timer = null
    }
    const closeStream = () => {
      if (!source || closedByClient) return
      closedByClient = true
      source.close()
    }
    const finish = () => {
      if (settled) return
      settled = true
      clearTimer()
      pollingRequest?.abort()
      closeStream()
      if (disposed) return
      setMessage('判题完成')
      setTransport('idle')
      callbacksRef.current.onDone()
    }
    const applySnapshot = (snapshot: SubmissionStatusSnapshot) => {
      if (disposed || settled) return false
      updateCount += 1
      setMessage(progressMessage(updateCount))
      callbacksRef.current.onSnapshot(snapshot)
      if (snapshot.is_judging === false) {
        finish()
        return false
      }
      return true
    }

    const schedulePoll = (delay: number) => {
      if (disposed || settled || !fallbackPolling) return
      clearTimer()
      timer = window.setTimeout(() => {
        timer = null
        if (disposed || settled) return
        setTransport('polling')
        pollingRequest = new AbortController()
        void fetchSubmissionStatus(submissionId, pollingRequest.signal).then((snapshot) => {
          pollingRequest = null
          if (!applySnapshot(snapshot) || disposed || settled) return
          if (updateCount >= 60) {
            setMessage('判题时间过长，正在刷新页面...')
            timer = window.setTimeout(() => window.location.replace(window.location.href), 1_000)
            return
          }
          schedulePoll(pollingInterval(updateCount))
        }).catch((error: unknown) => {
          pollingRequest = null
          if (disposed || settled || (error instanceof DOMException && error.name === 'AbortError')) return
          updateCount += 1
          setMessage('网络连接不稳定，正在重试...')
          if (updateCount >= 60) {
            setMessage('网络错误，正在刷新页面...')
            timer = window.setTimeout(() => window.location.replace(window.location.href), 2_000)
            return
          }
          schedulePoll(Math.min(5_000, pollingInterval(updateCount) * 2))
        })
      }, delay)
    }

    const startStream = () => {
      if (disposed || settled) return
      if (!window.EventSource) {
        schedulePoll(500)
        return
      }

      setTransport('connecting')
      source = new EventSource(streamUrl || `/api/submissions/${submissionId}/events`)
      source.onopen = () => {
        if (!disposed && !settled) setTransport('streaming')
      }
      source.addEventListener('status', ((event: MessageEvent) => {
        if (disposed || settled) return
        hasMessage = true
        let snapshot: SubmissionStatusSnapshot | null = null
        try {
          snapshot = parseSnapshot(JSON.parse(event.data))
        } catch {
          snapshot = null
        }
        if (!snapshot) return
        setTransport('streaming')
        applySnapshot(snapshot)
      }) as EventListener)
      source.addEventListener('done', ((event: MessageEvent) => {
        if (disposed || settled) return
        try {
          const snapshot = parseSnapshot(JSON.parse(event.data))
          if (snapshot) callbacksRef.current.onSnapshot(snapshot)
        } catch {
          // 终态帧解析失败时保留最后一个有效快照。
        }
        finish()
      }) as EventListener)

      if (fallbackPolling) {
        source.addEventListener('timeout', (() => {
          if (disposed || settled) return
          closeStream()
          schedulePoll(500)
        }) as EventListener)
        source.onerror = () => {
          if (disposed || settled || closedByClient) return
          closeStream()
          schedulePoll(hasMessage ? 1_000 : 500)
        }
      } else {
        source.onerror = () => {
          if (!disposed && !settled) setTransport('reconnecting')
          // 列表侧栏和书面提交沿用旧版行为：交给 EventSource 自动重连。
        }
      }
    }

    timer = window.setTimeout(startStream, startDelayMs)
    return () => {
      disposed = true
      clearTimer()
      pollingRequest?.abort()
      closeStream()
    }
  }, [enabled, fallbackPolling, initialMessage, startDelayMs, streamUrl, submissionId])

  return {message, transport}
}
