import {ApiError} from './client'
import type {ApiEnvelope} from './types'

export interface BuildEvent {
  event: 'progress' | 'log' | 'heartbeat' | 'result' | 'error'
  phase?: string
  message?: string
  elapsed_seconds?: number
  success?: boolean
  http_status?: number
}

export async function submitVibeHubBuild(path: string, init: RequestInit, onEvent: (event: BuildEvent) => void): Promise<ApiEnvelope> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/x-ndjson')
  headers.set('X-Requested-With', 'XMLHttpRequest')
  const response = await fetch(path, {...init, headers, credentials: 'same-origin'})
  if (!response.headers.get('content-type')?.includes('application/x-ndjson')) {
    const payload = await response.json() as ApiEnvelope
    if (!response.ok || !payload.success) throw new ApiError(payload.message || '作品提交失败', response.status, payload)
    return payload
  }
  if (!response.ok || !response.body) throw new Error('无法读取构建进度，请检查作品最新版本。')
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let pending = ''
  function consume(line: string): ApiEnvelope | undefined {
    if (!line.trim()) return
    const event = JSON.parse(line) as BuildEvent & ApiEnvelope
    onEvent(event)
    if (event.event === 'error') throw new ApiError(event.message || '作品构建失败', event.http_status || 500, event)
    if (event.event === 'result') {
      if (!event.success) throw new Error(event.message || '作品构建失败')
      return event
    }
  }
  try {
    while (true) {
      const {value, done} = await reader.read()
      pending += decoder.decode(value, {stream: !done})
      const lines = pending.split('\n')
      pending = lines.pop() || ''
      if (pending.length > 256 * 1024) throw new Error('构建进度响应过长')
      for (const line of lines) {
        const result = consume(line)
        if (result) return result
      }
      if (done) {
        const result = consume(pending)
        if (result) return result
        throw new Error('构建进度连接已断开，最终结果尚未确认。请先检查作品最新版本，避免重复提交。')
      }
    }
  } finally {
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}
