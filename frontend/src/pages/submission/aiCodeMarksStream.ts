import type {JsonRecord} from '../../api/types'

export type AiCodeMarksEvent = {name: string; payload: JsonRecord}

function decodeFrame(frame: string): AiCodeMarksEvent | null {
  let name = 'message'
  const data: string[] = []
  frame.split(/\r?\n/).forEach((line) => {
    if (line.startsWith('event:')) name = line.slice(6).trim()
    else if (line.startsWith('data:')) data.push(line.slice(5).trimStart())
  })
  if (!data.length) return null
  try {
    const payload = JSON.parse(data.join('\n'))
    return payload && typeof payload === 'object' && !Array.isArray(payload)
      ? {name, payload: payload as JsonRecord}
      : null
  } catch {
    return null
  }
}

export async function streamAiCodeMarks(
  submissionId: number,
  onEvent: (event: AiCodeMarksEvent) => void,
  signal?: AbortSignal,
) {
  const response = await fetch('/ask_ai_code_marks_stream', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', Accept: 'text/event-stream'},
    body: JSON.stringify({submission_id: submissionId}),
    signal,
  })
  if (!response.ok) {
    let message = `HTTP ${response.status}`
    try {
      const payload = await response.json() as {message?: unknown}
      if (payload.message) message = String(payload.message)
    } catch { /* 非 JSON 错误由 HTTP 状态兜底。 */ }
    throw new Error(message)
  }
  if (!response.body) throw new Error('浏览器不支持流式响应')

  const reader = response.body.getReader()
  const decoder = new TextDecoder('utf-8')
  let buffer = ''
  let gotResult = false
  let gotDone = false
  const handle = (frame: string) => {
    const event = decodeFrame(frame)
    if (!event) return
    if (event.name === 'error') throw new Error(String(event.payload.message || 'AI 分析失败'))
    if (event.name === 'result') gotResult = true
    if (event.name === 'done') gotDone = true
    onEvent(event)
  }

  while (!gotDone) {
    const chunk = await reader.read()
    if (chunk.done) break
    buffer += decoder.decode(chunk.value, {stream: true})
    const frames = buffer.split(/\r?\n\r?\n/)
    buffer = frames.pop() || ''
    frames.forEach(handle)
  }
  buffer += decoder.decode()
  if (buffer.trim()) handle(buffer)
  if (!gotResult) throw new Error('AI 流式响应意外结束')
}

export const aiCodeMarksStreamInternals = {decodeFrame}
