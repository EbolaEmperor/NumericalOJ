import type {Disposable, MonacoApi, MonacoModel} from './types'

type RawLegend = {tokenTypes: string[]; tokenModifiers: string[]}
type SemanticPayload = {
  data?: number[]
  edits?: Array<{start?: number; deleteCount?: number; delete_count?: number; data?: number[]}>
  legend?: RawLegend
  result_id?: string
  previous_result_id?: string
  unchanged?: boolean
  kind?: string
}

function validLegend(value: unknown): value is RawLegend {
  const legend = value as RawLegend | null
  return Boolean(legend && Array.isArray(legend.tokenTypes) && legend.tokenTypes.length && legend.tokenTypes.every((item) => typeof item === 'string') && Array.isArray(legend.tokenModifiers) && legend.tokenModifiers.every((item) => typeof item === 'string'))
}

function validData(value: unknown): value is number[] {
  return Array.isArray(value) && value.length % 5 === 0 && value.every((item) => Number.isInteger(item) && item >= 0)
}

function applyEdits(previous: Uint32Array, edits: SemanticPayload['edits']) {
  if (!Array.isArray(edits)) return null
  const normalized = edits.map((edit) => {
    const start = Number(edit.start)
    const deleteCount = Number(edit.deleteCount ?? edit.delete_count)
    const data = edit.data ?? []
    if (!Number.isInteger(start) || start < 0 || !Number.isInteger(deleteCount) || deleteCount < 0 || !validData(data)) return null
    return {start, deleteCount, data: Uint32Array.from(data)}
  })
  if (normalized.some((edit) => !edit)) return null
  const ordered = normalized as Array<{start: number; deleteCount: number; data: Uint32Array}>
  ordered.sort((left, right) => left.start - right.start)
  let length = previous.length
  let previousEnd = 0
  for (const edit of ordered) {
    if (edit.start < previousEnd || edit.start + edit.deleteCount > previous.length) return null
    previousEnd = edit.start + edit.deleteCount
    length += edit.data.length - edit.deleteCount
  }
  if (length < 0 || length % 5 !== 0) return null
  const output = new Uint32Array(length)
  let sourceOffset = 0
  let outputOffset = 0
  for (const edit of ordered) {
    const unchanged = previous.subarray(sourceOffset, edit.start)
    output.set(unchanged, outputOffset)
    outputOffset += unchanged.length
    output.set(edit.data, outputOffset)
    outputOffset += edit.data.length
    sourceOffset = edit.start + edit.deleteCount
  }
  output.set(previous.subarray(sourceOffset), outputOffset)
  return output
}

function singleEdit(previous: Uint32Array, next: Uint32Array) {
  let prefix = 0
  const shared = Math.min(previous.length, next.length)
  while (prefix < shared && previous[prefix] === next[prefix]) prefix += 1
  let suffix = 0
  while (suffix < shared - prefix && previous[previous.length - 1 - suffix] === next[next.length - 1 - suffix]) suffix += 1
  if (prefix === previous.length && prefix === next.length) return []
  return [{start: prefix, deleteCount: previous.length - prefix - suffix, data: next.slice(prefix, next.length - suffix)}]
}

export function createLeanSemanticTokens(monaco: MonacoApi, model: MonacoModel) {
  let registration: Disposable | null = null
  let rawLegend: RawLegend | null = null
  let legendSignature = ''
  let cachedData = new Uint32Array(0)
  let cachedVersion = 0
  let cachedResultId = ''
  let generation = 0
  let servedSerial = 0
  let hasData = false
  let stale = false
  let disposed = false
  const servedResults = new Map<string, Uint32Array>()
  const listeners = new Set<() => void>()

  const fireChange = () => listeners.forEach((listener) => listener())
  const subscribe = (listener: () => void) => {
    listeners.add(listener)
    return {dispose: () => listeners.delete(listener)}
  }
  const register = (legend: RawLegend, signature: string) => {
    registration = monaco.languages.registerDocumentSemanticTokensProvider?.('lean4', {
      onDidChange: subscribe,
      getLegend: () => ({tokenTypes: legend.tokenTypes.map((tokenType) => `lean4.${tokenType}`), tokenModifiers: [...legend.tokenModifiers]}),
      provideDocumentSemanticTokens: (requestedModel: MonacoModel, lastResultId: string, cancellationToken?: {isCancellationRequested?: boolean}) => {
        if (disposed || requestedModel !== model || cancellationToken?.isCancellationRequested) return null
        if (!hasData) return {data: new Uint32Array(0)}
        if (stale || cachedVersion !== model.getVersionId()) throw new Error('Lean semantic tokens busy')
        const resultId = `lean4:${cachedResultId || cachedVersion}:${generation}:${++servedSerial}`
        const previous = servedResults.get(String(lastResultId || ''))
        const next = new Uint32Array(cachedData)
        servedResults.set(resultId, next)
        return previous ? {edits: singleEdit(previous, next), resultId} : {data: next, resultId}
      },
      releaseDocumentSemanticTokens: (resultId: string) => servedResults.delete(String(resultId || '')),
    }) || null
    legendSignature = signature
  }

  return {
    accept(version: number, value: unknown) {
      const payload = value as SemanticPayload | null
      const unchanged = payload === null || value === 'unchanged' || payload?.unchanged === true || payload?.kind === 'unchanged'
      if (unchanged) {
        if (!hasData) return false
        const changed = cachedVersion !== version || stale
        cachedVersion = version
        stale = false
        if (changed) {
          generation += 1
          registration && fireChange()
        }
        return true
      }
      const nextLegend = payload?.legend || rawLegend
      const nextData = Array.isArray(payload?.edits)
        ? (hasData && String(payload.previous_result_id || '') === cachedResultId ? applyEdits(cachedData, payload.edits) : null)
        : (validData(payload?.data) ? Uint32Array.from(payload.data) : null)
      if (disposed || version !== model.getVersionId() || !validLegend(nextLegend) || !nextData) return false
      const signature = JSON.stringify(nextLegend)
      const resultId = String(payload?.result_id || '')
      if (registration && cachedVersion === version && cachedResultId === resultId && legendSignature === signature) return true
      cachedData = nextData
      cachedVersion = version
      cachedResultId = resultId
      rawLegend = {tokenTypes: [...nextLegend.tokenTypes], tokenModifiers: [...nextLegend.tokenModifiers]}
      hasData = true
      stale = false
      generation += 1
      if (registration && legendSignature !== signature) {
        registration.dispose()
        registration = null
        servedResults.clear()
      }
      if (!registration) register(nextLegend, signature)
      else fireChange()
      return true
    },
    invalidate() {
      if (!disposed && hasData) stale = true
    },
    getResultId() {
      return cachedResultId
    },
    dispose() {
      if (disposed) return
      disposed = true
      registration?.dispose()
      registration = null
      listeners.clear()
      servedResults.clear()
    },
  }
}
