import type {Disposable, MonacoApi, MonacoModel} from './types'

const SUPPORTED_LANGUAGES = new Set(['c', 'cpp', 'py', 'python', 'matlab', 'octave'])
const MARKDOWN_ALIASES: Record<string, string> = {c: 'c', cpp: 'cpp', py: 'python', python: 'python', matlab: 'matlab', octave: 'matlab'}
const RETRYABLE_CODES = new Set(['legend_pending', 'repository_changed', 'result_pending', 'service_busy'])
const RETRY_CAPS = [500, 1_000, 2_000, 4_000, 8_000, 12_000, 16_000, 20_000]
const RETRY_BUDGET = 60_000

export type SemanticLegend = {tokenTypes: string[]; tokenModifiers: string[]}
export type TextPosition = {line?: number; character?: number}
export type SemanticPayload = {success?: boolean; data?: number[]; result_id?: string; inactive_regions?: Array<{start?: TextPosition; end?: TextPosition}>; message?: string; code?: string}
export type SemanticRequest = {language: string; source: string; signal?: AbortSignal; problemId?: number; context?: string; documentId?: string; repositoryEntryId?: number}

const legends = new Map<string, SemanticLegend>()

function normalized(value: unknown) {return String(value || '').toLowerCase()}
function abortError() {return new DOMException('请求已取消', 'AbortError')}

function wait(delay: number, signal?: AbortSignal) {
  if (signal?.aborted) return Promise.reject(abortError())
  return new Promise<void>((resolve, reject) => {
    const aborted = () => {clearTimeout(timer); reject(abortError())}
    const timer = setTimeout(() => {signal?.removeEventListener('abort', aborted); resolve()}, delay)
    signal?.addEventListener('abort', aborted, {once: true})
  })
}

async function fetchJsonWithBusyRetry<T extends {message?: string; code?: string}>(url: string, init: RequestInit, signal?: AbortSignal) {
  const startedAt = Date.now()
  for (let attempt = 0; ; attempt += 1) {
    if (signal?.aborted) throw abortError()
    const response = await fetch(url, init)
    const payload = await response.json().catch(() => null) as T | null
    if (response.ok && payload) return payload
    const error = Object.assign(new Error(payload?.message || `语言服务返回 ${response.status}`), {status: response.status, code: String(payload?.code || '')})
    if (!RETRYABLE_CODES.has(error.code) || attempt >= RETRY_CAPS.length) throw error
    const retryAfter = Math.ceil(Math.max(0, Number.parseFloat(response.headers.get('Retry-After') || '0')) * 1_000)
    const delay = retryAfter + Math.floor(Math.random() * RETRY_CAPS[attempt])
    if (Date.now() - startedAt + delay > RETRY_BUDGET) throw error
    await wait(delay, signal)
  }
}

export async function getSemanticLegend(language: string, options: {signal?: AbortSignal} = {}) {
  const value = normalized(language)
  if (!SUPPORTED_LANGUAGES.has(value)) throw new Error('该语言暂不支持结构化高亮')
  const cached = legends.get(value)
  if (cached) return {tokenTypes: [...cached.tokenTypes], tokenModifiers: [...cached.tokenModifiers]}
  const payload = await fetchJsonWithBusyRetry<{success?: boolean; legend?: SemanticLegend; message?: string; code?: string}>(`/api/editor/semantic-token-legend?language=${encodeURIComponent(value)}`, {credentials: 'same-origin', headers: {Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest'}, signal: options.signal}, options.signal)
  if (!payload.success || !Array.isArray(payload.legend?.tokenTypes) || !Array.isArray(payload.legend.tokenModifiers)) throw new Error('结构化高亮 legend 格式无效')
  legends.set(value, {tokenTypes: [...payload.legend.tokenTypes], tokenModifiers: [...payload.legend.tokenModifiers]})
  return {tokenTypes: [...payload.legend.tokenTypes], tokenModifiers: [...payload.legend.tokenModifiers]}
}

export async function requestSemanticTokens(options: SemanticRequest) {
  const language = normalized(options.language)
  if (!SUPPORTED_LANGUAGES.has(language) || typeof options.source !== 'string') throw new Error('结构化高亮请求参数无效')
  const body: Record<string, unknown> = {language, source: options.source}
  if (options.context === 'markdown' && MARKDOWN_ALIASES[language]) Object.assign(body, {language: MARKDOWN_ALIASES[language], context: 'markdown'})
  else if (options.context === 'repository' && Number.isInteger(options.repositoryEntryId) && Number(options.repositoryEntryId) > 0) Object.assign(body, {context: 'repository', repository_entry_id: options.repositoryEntryId})
  else if (options.context && options.documentId) Object.assign(body, {context: options.context, document_id: options.documentId})
  else if (Number.isInteger(options.problemId) && Number(options.problemId) > 0 && !options.context) body.problem_id = options.problemId
  else throw new Error('结构化高亮请求参数无效')
  const payload = await fetchJsonWithBusyRetry<SemanticPayload>('/api/editor/semantic-tokens', {method: 'POST', credentials: 'same-origin', headers: {Accept: 'application/json', 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}, body: JSON.stringify(body), signal: options.signal}, options.signal)
  if (!payload.success || !Array.isArray(payload.data) || payload.data.length % 5 !== 0) throw new Error('结构化高亮 token 数据格式无效')
  return payload
}

type RegisterOptions = {language: string; monacoLanguage: string; problemId?: number; context?: string; documentId?: string | ((model: MonacoModel) => string); repositoryEntryId?: number | ((model: MonacoModel) => number); onRequestStart?: () => void; onRequestEnd?: () => void; signal?: AbortSignal}
type ModelState = {controller: AbortController | null; version: number; decorationIds: string[]; disposeListener?: Disposable}

export async function registerSemanticTokens(monaco: MonacoApi, options: RegisterOptions) {
  const language = normalized(options.language)
  if (!SUPPORTED_LANGUAGES.has(language) || !monaco.languages.registerDocumentSemanticTokensProvider) return null
  const legend = await getSemanticLegend(language, {signal: options.signal})
  if (options.signal?.aborted) return null
  const states = new Map<MonacoModel, ModelState>()
  let disposed = false
  let warned = false

  const stateFor = (model: MonacoModel) => {
    let state = states.get(model)
    if (state) return state
    state = {controller: null, version: 0, decorationIds: []}
    state.disposeListener = model.onWillDispose?.(() => {state?.controller?.abort(); states.delete(model)})
    states.set(model, state)
    return state
  }
  const clearInactive = (model: MonacoModel, state: ModelState) => {
    if (!model.deltaDecorations || model.isDisposed?.()) return
    try {state.decorationIds = model.deltaDecorations(state.decorationIds, [])} catch {state.decorationIds = []}
  }
  const applyInactive = (model: MonacoModel, state: ModelState, regions: SemanticPayload['inactive_regions']) => {
    if (!['c', 'cpp'].includes(language) || !model.deltaDecorations || model.isDisposed?.()) return
    const decorations = (regions || []).flatMap((region) => {
      const startLine = Number(region.start?.line); const startColumn = Number(region.start?.character); const endLine = Number(region.end?.line); const endColumn = Number(region.end?.character)
      if (![startLine, startColumn, endLine, endColumn].every(Number.isInteger) || startLine < 0 || startColumn < 0 || endLine < startLine || endColumn < 0) return []
      const range = new monaco.Range(startLine + 1, startColumn + 1, endLine + 1, endColumn + 1)
      return [{range, options: {description: 'numoj-clangd-inactive-code', isWholeLine: true, inlineClassName: 'numoj-clangd-inactive-code', inlineClassNameAffectsLetterSpacing: false}}]
    })
    try {state.decorationIds = model.deltaDecorations(state.decorationIds, decorations)} catch {state.decorationIds = []}
  }

  const registration = monaco.languages.registerDocumentSemanticTokensProvider(options.monacoLanguage, {
    getLegend: () => legend,
    provideDocumentSemanticTokens: async (model: MonacoModel, _lastResultId: string, cancellationToken?: {onCancellationRequested?: (listener: () => void) => Disposable}) => {
      const state = stateFor(model)
      state.controller?.abort()
      const controller = new AbortController()
      state.controller = controller
      const requestVersion = ++state.version
      const cancellation = cancellationToken?.onCancellationRequested?.(() => controller.abort())
      options.onRequestStart?.()
      try {
        const documentId = typeof options.documentId === 'function' ? options.documentId(model) : options.documentId
        const repositoryEntryId = typeof options.repositoryEntryId === 'function' ? options.repositoryEntryId(model) : options.repositoryEntryId
        const payload = await requestSemanticTokens({language, source: model.getValue(), signal: controller.signal, problemId: options.problemId, context: options.context, documentId, repositoryEntryId})
        if (disposed || controller.signal.aborted || state.version !== requestVersion) return null
        applyInactive(model, state, payload.inactive_regions)
        warned = false
        return {data: new Uint32Array(payload.data || []), resultId: String(payload.result_id || `${requestVersion}`)}
      } catch (error) {
        if (!disposed && state.version === requestVersion) clearInactive(model, state)
        if (error instanceof DOMException && error.name === 'AbortError') return null
        if (!warned) {console.warn('结构化高亮失败，已保留 TextMate 着色。', error); warned = true}
        return {data: new Uint32Array(0)}
      } finally {
        if (state.controller === controller) state.controller = null
        cancellation?.dispose()
        options.onRequestEnd?.()
      }
    },
    releaseDocumentSemanticTokens: () => undefined,
  })
  return {dispose: () => {if (disposed) return; disposed = true; registration.dispose(); for (const [model, state] of states) {state.controller?.abort(); clearInactive(model, state); state.disposeListener?.dispose()} states.clear()}}
}
