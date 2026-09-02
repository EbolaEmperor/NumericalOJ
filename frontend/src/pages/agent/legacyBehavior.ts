import type {JsonRecord} from '../../api/types'

export type AgentDeliveryMode = 'turn' | 'queue' | 'steer'
export type AgentComposerEnterAction = 'send' | 'steer' | null

export function agentComposerEnterAction({
  key,
  keyCode,
  composing,
  shiftKey,
  ctrlKey,
  metaKey,
  running,
}: {
  key: string
  keyCode: number
  composing: boolean
  shiftKey: boolean
  ctrlKey: boolean
  metaKey: boolean
  running: boolean
}): AgentComposerEnterAction {
  if (key !== 'Enter' || composing || keyCode === 229 || shiftKey) return null
  return running && (ctrlKey || metaKey) ? 'steer' : 'send'
}

export function createAgentMessageId(prefix = 'msg') {
  const browserCrypto = globalThis.crypto
  if (browserCrypto && typeof browserCrypto.randomUUID === 'function') {
    return browserCrypto.randomUUID().replace(/-/g, '')
  }
  return `${prefix}${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`
}

export function fileIdentity(file: File) {
  return `${file.name}:${file.size}:${file.lastModified}`
}

export function mergeFiles(current: File[], incoming: FileList | File[]) {
  const next = [...current]
  const seen = new Set(next.map(fileIdentity))
  Array.from(incoming || []).forEach((file) => {
    if (!file || seen.has(fileIdentity(file))) return
    seen.add(fileIdentity(file))
    next.push(file)
  })
  return next
}

export function humanFileSize(value: unknown) {
  const bytes = Number(value)
  if (!Number.isFinite(bytes) || bytes < 0) return ''
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)}K`
  return `${(bytes / 1024 / 1024).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)}M`
}

export function composerFileSize(value: unknown) {
  const bytes = Number(value || 0)
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KB`
  return `${(bytes / 1024 / 1024).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)} MB`
}

function measuredValue(value: number) {
  if (!Number.isFinite(value) || value < 0) return '—'
  if (value === 0) return '0.00'
  return value >= 1 ? value.toFixed(2) : value.toPrecision(2)
}

export function formatTokenCount(value: unknown) {
  const tokens = Number(value)
  if (!Number.isFinite(tokens) || tokens < 0) return '—'
  if (tokens < 1_000) return measuredValue(tokens)
  if (tokens < 1_000_000) return `${measuredValue(tokens / 1_000)} K`
  if (tokens < 1_000_000_000) return `${measuredValue(tokens / 1_000_000)} M`
  return `${measuredValue(tokens / 1_000_000_000_000)} T`
}

export function decimalText(value: unknown) {
  let text = String(value ?? '').trim()
  if (!text) return ''
  if (!/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(text)) return text
  text = text.replace(/^([+-]?)0+(?=\d)/, '$1')
  if (text.includes('.')) text = text.replace(/0+$/, '').replace(/\.$/, '')
  if (text === '-0' || text === '+0' || text === '') return '0'
  return text
}

export function multiplyDecimal(value: unknown, multiplier: number) {
  const source = decimalText(value)
  if (!source || !Number.isSafeInteger(multiplier) || multiplier < 0) return ''
  const match = source.match(/^(-?)(\d+)(?:\.(\d+))?$/)
  if (!match) return decimalText(Number(value) * multiplier)
  try {
    const decimals = match[3]?.length || 0
    const digits = `${match[2]}${match[3] || ''}`
    const product = BigInt(digits || '0') * BigInt(multiplier)
    const padded = product.toString().padStart(decimals + 1, '0')
    const output = decimals
      ? `${padded.slice(0, -decimals)}.${padded.slice(-decimals)}`
      : padded
    return decimalText(`${match[1]}${output}`)
  } catch {
    return decimalText(Number(value) * multiplier)
  }
}

export function usageDisplay(usage: JsonRecord | null | undefined, usesPersonalEndpoint: boolean) {
  if (!usage) {
    return {input: '—', cached: '—', output: '—', cost: usesPersonalEndpoint ? '用户自费' : '—'}
  }
  const input = Number(usage.input_total_tokens)
  const cached = Number(usage.input_cached_tokens)
  const cachedPercent = input > 0 && cached >= 0 ? Math.min(100, cached / input * 100) : 0
  const rawCost = usage.cost_rmb
  const hasCost = rawCost !== null && rawCost !== undefined && rawCost !== ''
    && Number.isFinite(Number(rawCost)) && Number(rawCost) >= 0
  return {
    input: formatTokenCount(input),
    cached: `${cachedPercent.toFixed(2)}%`,
    output: formatTokenCount(usage.output_tokens),
    cost: usesPersonalEndpoint ? '用户自费' : hasCost ? `${decimalText(rawCost)} 元` : '—',
  }
}

export function cachedFallbackMessage(usage: JsonRecord | null | undefined) {
  const count = Number(usage?.cached_fallback_request_count)
  const tokens = Number(usage?.cached_fallback_input_tokens)
  if (!Number.isFinite(count) || count <= 0 || !Number.isFinite(tokens) || tokens < 0) return ''
  return `您的本次对话中，有 ${count} 次 LLM 调用没有返回可识别的 cached 字段，因此有 ${formatTokenCount(tokens)} 的 input tokens 按照 90% 的默认命中率来计费。`
}

export function statusKey(value: unknown) {
  return String(value || '').trim().toLowerCase().replaceAll('-', '_')
}

export function messageId(message: JsonRecord) {
  return String(message.message_id || message.id || '').trim()
}

export function messageMode(message: JsonRecord) {
  return statusKey(message.delivery_mode || message.mode)
}

export function messageStatus(message: JsonRecord) {
  return statusKey(message.status || 'queued')
}

export function messageCopy(message: JsonRecord) {
  return String(message.user_message ?? message.message ?? message.text ?? '')
}

export function messageAttachments(message: JsonRecord) {
  return Array.isArray(message.attachments) ? message.attachments as JsonRecord[] : []
}

export function attachmentPath(attachment: JsonRecord) {
  return String(attachment.path || attachment.workspace_path || '')
}

export function attachmentName(attachment: JsonRecord) {
  const path = attachmentPath(attachment)
  return String(attachment.name || attachment.filename || path.split('/').pop() || '附件')
}

export function uniqueMessages(messages: JsonRecord[]) {
  const seen = new Set<string>()
  return messages.filter((message) => {
    const id = messageId(message)
    if (!id || seen.has(id)) return false
    seen.add(id)
    return true
  })
}

export function stateMessages(state: JsonRecord | null | undefined) {
  const messages = Array.isArray(state?.messages) ? [...state.messages] as JsonRecord[] : []
  for (const key of ['queued_messages', 'steer_messages']) {
    const values = state?.[key]
    if (Array.isArray(values)) messages.push(...values as JsonRecord[])
  }
  return uniqueMessages(messages)
}

export function queuedMessages(state: JsonRecord | null | undefined) {
  const explicit = state?.queued_messages
  const source = Array.isArray(explicit)
    ? explicit as JsonRecord[]
    : stateMessages(state).filter((message) => messageMode(message) === 'queue')
  return uniqueMessages(source).filter((message) => ['queued', 'dispatching'].includes(messageStatus(message))).sort((left, right) => {
    const leftPosition = Number(left.queue_position)
    const rightPosition = Number(right.queue_position)
    if (Number.isFinite(leftPosition) && Number.isFinite(rightPosition) && leftPosition !== rightPosition) return leftPosition - rightPosition
    return String(left.created_at || '').localeCompare(String(right.created_at || ''))
  })
}

export function steerMessages(state: JsonRecord | null | undefined, currentTaskId = '') {
  const explicit = state?.steer_messages
  const source = Array.isArray(explicit)
    ? explicit as JsonRecord[]
    : stateMessages(state).filter((message) => messageMode(message) === 'steer')
  return uniqueMessages(source).filter((message) => {
    const target = String(message.target_task_id || message.final_task_id || '').trim()
    return !target || !currentTaskId || target === currentTaskId
  })
}

export function stableAgentDocumentId(sessionId: string, path: string) {
  const value = `${sessionId}\u0000${path}`
  const hash = (seed: number) => {
    let result = seed >>> 0
    for (let index = 0; index < value.length; index += 1) {
      result ^= value.charCodeAt(index)
      result = Math.imul(result, 16777619)
    }
    return (result >>> 0).toString(16).padStart(8, '0')
  }
  return `aw-${hash(2166136261)}-${hash(2246822519)}`
}
