import {useCallback, useEffect, useMemo, useRef, useState, type RefObject} from 'react'

import {createLeanSemanticTokens} from '../editor/leanSemanticTokens'
import type {Disposable, MonacoApi, MonacoEditorInstance, MonacoEditorReadyContext, MonacoModel} from '../editor/types'
import {MonacoEditor} from './MonacoEditor'

export type LeanSubmissionPayload = {revision: string; files: Record<string, string>}

export type LeanWorkbenchController = {
  checkNow: () => void
  dispose: () => void
  focus: () => void
  getActiveValue: () => string
  layout: () => void
  prepareSubmission: () => LeanSubmissionPayload
  setActiveValue: (value: string) => void
  setWritableFiles: (files: Record<string, string>) => void
}

type LeanWorkspace = Record<string, unknown> & {
  revision_number?: number
  revision?: string
  default_file?: string
  files?: Array<Record<string, unknown>>
}
type WorkspaceFile = {path: string; mode: 'readonly' | 'writable'; content: string; buildOrder: number}
type NormalizedWorkspace = {revision: string; defaultFile: string; files: WorkspaceFile[]}
type TextPoint = {line: number; character: number}
type Diagnostic = {path?: string; file?: string; file_path?: string; filename?: string; uri?: string; severity?: string | number; message?: string; range?: {start?: Partial<TextPoint>; end?: Partial<TextPoint>}}
type Goal = string | {text?: string; hyps?: Array<string | {name?: string; type?: string}>; hypotheses?: Array<string | {name?: string; type?: string}>; target?: string}
type SemanticBridge = ReturnType<typeof createLeanSemanticTokens>
type FileState = WorkspaceFile & {originalContent: string; model: MonacoModel | null; viewState: unknown; documentVersion: number | null; semanticTokens: SemanticBridge | null}
type Status = {state: 'idle' | 'checking' | 'ready' | 'problems' | 'offline'; text: string}
type TreeNode = {folders: Map<string, TreeNode>; files: Array<{name: string; path: string}>}

const SOURCE_DEBOUNCE_MS = 700
const CURSOR_DEBOUNCE_MS = 250

function createClientSessionId() {
  return crypto.randomUUID?.() || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`
}

function normalizeWorkspace(workspace: LeanWorkspace | null | undefined, value: string): NormalizedWorkspace {
  const rawFiles = Array.isArray(workspace?.files) && workspace.files.length
    ? workspace.files
    : [{path: 'Submission.lean', mode: 'writable', content: value, build_order: 0}]
  const seen = new Set<string>()
  const files = rawFiles.flatMap((rawFile, index) => {
    const path = String(rawFile.path || '').trim()
    if (!path || seen.has(path)) return []
    seen.add(path)
    return [{
      path,
      mode: rawFile.mode === 'readonly' ? 'readonly' as const : 'writable' as const,
      content: String(rawFile.content || ''),
      buildOrder: Number.isFinite(Number(rawFile.build_order)) ? Number(rawFile.build_order) : index,
    }]
  })
  if (!files.length) files.push({path: 'Submission.lean', mode: 'writable', content: value, buildOrder: 0})
  const requestedDefault = String(workspace?.default_file || '')
  const defaultFile = files.some((file) => file.path === requestedDefault)
    ? requestedDefault
    : (files.find((file) => file.mode === 'writable') || files[0]).path
  return {revision: String(workspace?.revision || ''), defaultFile, files}
}

function useLeanSplitter(rootRef: RefObject<HTMLDivElement | null>, splitterRef: RefObject<HTMLDivElement | null>, problemId: number) {
  useEffect(() => {
    const root = rootRef.current
    const splitter = splitterRef.current
    if (!root || !splitter) return
    const desktop = window.matchMedia('(min-width: 992px)')
    const storageKey = 'numoj.problemDetail.leanSourceRatio'
    const stored = Number(window.localStorage.getItem(storageKey))
    let preferredRatio = stored > 0 && stored < 1 ? stored : 0.63
    let currentWidth = 0
    let pointerId: number | null = null
    let pointerOffset = 0
    const bounds = () => {
      const rect = root.getBoundingClientRect()
      const splitterWidth = Math.max(1, splitter.getBoundingClientRect().width || 7)
      const available = Math.max(1, rect.width - splitterWidth)
      const minimum = Math.min(240, available * 0.42)
      const maximum = Math.max(minimum, available - Math.min(220, available * 0.48))
      return {rect, available, minimum, maximum}
    }
    const apply = (requested: number, remember = false) => {
      if (!desktop.matches) return
      const range = bounds()
      currentWidth = Math.min(range.maximum, Math.max(range.minimum, requested))
      if (remember) preferredRatio = currentWidth / range.available
      root.style.setProperty('--lean-source-width', `${currentWidth.toFixed(2)}px`)
      const percent = Math.round(currentWidth / range.available * 100)
      splitter.setAttribute('aria-valuemin', String(Math.round(range.minimum / range.available * 100)))
      splitter.setAttribute('aria-valuemax', String(Math.round(range.maximum / range.available * 100)))
      splitter.setAttribute('aria-valuenow', String(percent))
      splitter.setAttribute('aria-valuetext', `代码 ${percent}%，证明状态 ${100 - percent}%`)
      window.dispatchEvent(new CustomEvent('numoj:problem-detail-resize'))
    }
    const refresh = () => {const range = bounds(); apply(preferredRatio * range.available)}
    const save = () => window.localStorage.setItem(storageKey, preferredRatio.toFixed(4))
    const finish = (event: PointerEvent) => {
      if (event.pointerId !== pointerId) return
      pointerId = null
      splitter.classList.remove('is-dragging')
      document.documentElement.classList.remove('is-problem-pane-resizing')
      save()
    }
    const pointerDown = (event: PointerEvent) => {
      if (!desktop.matches || event.button !== 0) return
      pointerId = event.pointerId
      pointerOffset = event.clientX - splitter.getBoundingClientRect().left
      splitter.setPointerCapture(pointerId)
      splitter.classList.add('is-dragging')
      document.documentElement.classList.add('is-problem-pane-resizing')
      event.preventDefault()
    }
    const pointerMove = (event: PointerEvent) => {
      if (event.pointerId !== pointerId) return
      const range = bounds()
      apply(event.clientX - range.rect.left - pointerOffset, true)
      event.preventDefault()
    }
    const keyDown = (event: KeyboardEvent) => {
      const range = bounds()
      let next = currentWidth
      if (event.key === 'ArrowLeft') next -= event.shiftKey ? 48 : 16
      else if (event.key === 'ArrowRight') next += event.shiftKey ? 48 : 16
      else if (event.key === 'Home') next = range.minimum
      else if (event.key === 'End') next = range.maximum
      else return
      event.preventDefault()
      apply(next, true)
      save()
    }
    const doubleClick = () => {preferredRatio = 0.63; refresh(); save()}
    const mediaChange = () => {if (desktop.matches) refresh(); else root.style.removeProperty('--lean-source-width')}
    const observer = new ResizeObserver(() => desktop.matches && refresh())
    observer.observe(root)
    splitter.addEventListener('pointerdown', pointerDown)
    splitter.addEventListener('keydown', keyDown)
    splitter.addEventListener('dblclick', doubleClick)
    window.addEventListener('pointermove', pointerMove)
    window.addEventListener('pointerup', finish)
    window.addEventListener('pointercancel', finish)
    desktop.addEventListener('change', mediaChange)
    refresh()
    return () => {
      observer.disconnect()
      splitter.removeEventListener('pointerdown', pointerDown)
      splitter.removeEventListener('keydown', keyDown)
      splitter.removeEventListener('dblclick', doubleClick)
      window.removeEventListener('pointermove', pointerMove)
      window.removeEventListener('pointerup', finish)
      window.removeEventListener('pointercancel', finish)
      desktop.removeEventListener('change', mediaChange)
    }
  }, [problemId, rootRef, splitterRef])
}

function severityName(value: Diagnostic['severity']) {
  if (typeof value === 'number') return ['', 'error', 'warning', 'info', 'hint'][value] || 'info'
  const normalized = String(value || 'error').toLowerCase()
  return normalized === 'information' ? 'info' : normalized
}

function point(value?: Partial<TextPoint>) {
  return {line: Math.max(0, Number(value?.line) || 0), character: Math.max(0, Number(value?.character) || 0)}
}

function diagnosticRange(diagnostic: Diagnostic) {
  const start = point(diagnostic.range?.start)
  let end = point(diagnostic.range?.end || diagnostic.range?.start)
  if (end.line < start.line || (end.line === start.line && end.character <= start.character)) end = {line: start.line, character: start.character + 1}
  return {start, end}
}

function useLeanWorkbench({
  problemId,
  workspace,
  value,
  onChange,
  onController,
}: {
  problemId: number
  workspace?: LeanWorkspace | null
  value: string
  onChange: (value: string) => void
  onController: (controller: LeanWorkbenchController | null) => void
}) {
  const normalized = useMemo(() => normalizeWorkspace(workspace, value), [problemId, workspace])
  const initialStates = useMemo(() => new Map(normalized.files.map((file) => [file.path, {...file, originalContent: file.content, model: null, viewState: null, documentVersion: null, semanticTokens: null}])), [normalized])
  const statesRef = useRef<Map<string, FileState>>(initialStates)
  const activePathRef = useRef(normalized.defaultFile)
  const editorRef = useRef<MonacoEditorInstance | null>(null)
  const monacoRef = useRef<MonacoApi | null>(null)
  const onChangeRef = useRef(onChange)
  const onControllerRef = useRef(onController)
  const sourceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const cursorTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const requestRef = useRef<{serial: number; kind: 'source' | 'cursor'; controller: AbortController} | null>(null)
  const serialRef = useRef(0)
  const clientSessionIdRef = useRef(createClientSessionId())
  const sourcePendingRef = useRef(true)
  const sourceStateIdRef = useRef('')
  const forceSemanticResyncRef = useRef(false)
  const queuedSourceRef = useRef(false)
  const queuedCursorRef = useRef(false)
  const completedRef = useRef({source: '', cursor: ''})
  const suppressChangesRef = useRef(false)
  const disposedRef = useRef(false)
  const checkRef = useRef<(kind: 'source' | 'cursor') => void>(() => undefined)
  const [activePath, setActivePath] = useState(normalized.defaultFile)
  const [activeTab, setActiveTab] = useState<'goals' | 'problems'>('goals')
  const [cursor, setCursor] = useState<TextPoint>({line: 0, character: 0})
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([])
  const [goals, setGoals] = useState<Goal[]>([])
  const [hasGoalResult, setHasGoalResult] = useState(false)
  const [status, setStatus] = useState<Status>({state: 'idle', text: '准备中'})
  const [, renderFiles] = useState(0)

  onChangeRef.current = onChange
  onControllerRef.current = onController

  const stateValue = useCallback((state?: FileState | null) => state?.model?.getValue() ?? state?.content ?? '', [])
  const currentState = useCallback(() => statesRef.current.get(activePathRef.current) || null, [])
  const currentVersion = useCallback(() => currentState()?.model?.getVersionId() || 1, [currentState])
  const currentPosition = useCallback(() => {
    const position = editorRef.current?.getPosition?.()
    return position ? {line: position.lineNumber - 1, character: position.column - 1} : {line: 0, character: 0}
  }, [])
  const writableFiles = useCallback(() => Object.fromEntries(normalized.files.flatMap((file) => {
    const state = statesRef.current.get(file.path)
    return state?.mode === 'writable' ? [[file.path, stateValue(state)]] : []
  })), [normalized.files, stateValue])
  const sourceFingerprint = useCallback(() => `${normalized.revision}|${normalized.files.map((file) => {
    const state = statesRef.current.get(file.path)
    return state?.mode === 'writable' ? `${file.path}:${state.model?.getVersionId() || 1}` : `${file.path}:readonly`
  }).join('|')}`, [normalized.files, normalized.revision])
  const diagnosticPath = useCallback((diagnostic: Diagnostic) => {
    const raw = diagnostic.path || diagnostic.file || diagnostic.file_path || diagnostic.filename || diagnostic.uri || activePathRef.current
    let path = String(raw).replace(/^file:\/\//, '').replace(/^\/workspace\//, '').split('?')[0]
    try {path = decodeURIComponent(path)} catch { /* 服务端原路径可继续用于后缀匹配。 */ }
    if (!statesRef.current.has(path)) path = [...statesRef.current.keys()].find((candidate) => path.endsWith(`/${candidate}`)) || activePathRef.current
    return path
  }, [])

  const updateCursor = useCallback(() => setCursor(currentPosition()), [currentPosition])
  const clearTimers = useCallback(() => {
    if (sourceTimerRef.current) clearTimeout(sourceTimerRef.current)
    if (cursorTimerRef.current) clearTimeout(cursorTimerRef.current)
    sourceTimerRef.current = null
    cursorTimerRef.current = null
  }, [])
  const applyMarkers = useCallback((items: Diagnostic[]) => {
    const monaco = monacoRef.current
    if (!monaco) return
    for (const [path, state] of statesRef.current) {
      if (!state.model) continue
      const fileDiagnostics = items.filter((diagnostic) => diagnosticPath(diagnostic) === path)
      monaco.editor.setModelMarkers(state.model, 'lean4', fileDiagnostics.map((diagnostic) => {
        const range = diagnosticRange(diagnostic)
        const severity = severityName(diagnostic.severity)
        const markerSeverity = severity === 'warning' ? monaco.MarkerSeverity.Warning : severity === 'info' ? monaco.MarkerSeverity.Info : severity === 'hint' ? monaco.MarkerSeverity.Hint : monaco.MarkerSeverity.Error
        return {startLineNumber: range.start.line + 1, startColumn: range.start.character + 1, endLineNumber: range.end.line + 1, endColumn: range.end.character + 1, message: String(diagnostic.message || 'Lean 检查失败'), severity: markerSeverity, source: 'Lean 4'}
      }))
    }
  }, [diagnosticPath])
  const normalizeDiagnostics = useCallback((value: unknown) => {
    if (Array.isArray(value)) return value as Diagnostic[]
    if (!value || typeof value !== 'object') return []
    return Object.entries(value).flatMap(([path, items]) => Array.isArray(items) ? items.map((item) => ({path, ...(item as Diagnostic)})) : [])
  }, [])

  const scheduleSource = useCallback((delay = SOURCE_DEBOUNCE_MS) => {
    sourcePendingRef.current = true
    if (sourceTimerRef.current) clearTimeout(sourceTimerRef.current)
    if (cursorTimerRef.current) clearTimeout(cursorTimerRef.current)
    setStatus({state: 'idle', text: '等待检查'})
    sourceTimerRef.current = setTimeout(() => checkRef.current('source'), delay)
  }, [])
  const scheduleCursor = useCallback((delay = CURSOR_DEBOUNCE_MS) => {
    updateCursor()
    if (sourcePendingRef.current) return
    if (cursorTimerRef.current) clearTimeout(cursorTimerRef.current)
    cursorTimerRef.current = setTimeout(() => checkRef.current('cursor'), delay)
  }, [updateCursor])

  const switchFile = useCallback((path: string, shouldCheck = true) => {
    const next = statesRef.current.get(path)
    const editor = editorRef.current
    if (!next || !editor || !next.model) return false
    const previous = currentState()
    if (previous && previous.path !== path) previous.viewState = editor.saveViewState?.() || null
    activePathRef.current = path
    setActivePath(path)
    if (editor.getModel?.() !== next.model) editor.setModel?.(next.model)
    editor.updateOptions?.({readOnly: next.mode === 'readonly', domReadOnly: next.mode === 'readonly', ariaLabel: `Lean 4 文件 ${path}${next.mode === 'readonly' ? '，只读' : '，可编辑'}`})
    if (next.viewState) editor.restoreViewState?.(next.viewState)
    editor.layout()
    onChangeRef.current(stateValue(next))
    updateCursor()
    renderFiles((version) => version + 1)
    if (shouldCheck) scheduleSource(40)
    return true
  }, [currentState, scheduleSource, stateValue, updateCursor])

  const runCheck = useCallback(async (requestedKind: 'source' | 'cursor') => {
    if (disposedRef.current) return
    if (requestedKind === 'cursor' && requestRef.current?.kind === 'source') {
      queuedCursorRef.current = true
      return
    }
    let kind = requestedKind
    const requestedState = currentState()
    if (kind === 'cursor' && (sourcePendingRef.current || !sourceStateIdRef.current || requestedState?.documentVersion === null)) kind = 'source'
    if (!requestedState) return
    clearTimers()
    if (requestRef.current) requestRef.current.controller.abort()
    if (kind === 'source') sourcePendingRef.current = false
    const requestedPath = activePathRef.current
    const requestedVersion = currentVersion()
    const requestedPosition = currentPosition()
    const requestedSourceFingerprint = sourceFingerprint()
    const fingerprint = kind === 'source'
      ? `source|${requestedSourceFingerprint}|${requestedPath}|${requestedVersion}|${requestedPosition.line}:${requestedPosition.character}`
      : `cursor|${sourceStateIdRef.current}|${requestedState.documentVersion}|${requestedPath}|${requestedPosition.line}:${requestedPosition.character}`
    if (completedRef.current[kind] === fingerprint) return
    const controller = new AbortController()
    const serial = ++serialRef.current
    requestRef.current = {serial, kind, controller}
    setStatus({state: 'checking', text: '正在检查'})
    try {
      const payload: Record<string, unknown> = {
        request_kind: kind,
        client_session_id: clientSessionIdRef.current,
        problem_id: problemId,
        revision: normalized.revision,
        active_file: requestedPath,
        version: requestedVersion,
        position: requestedPosition,
        known_semantic_result_id: forceSemanticResyncRef.current ? '' : requestedState.semanticTokens?.getResultId() || '',
      }
      if (kind === 'source') payload.files = writableFiles()
      else {
        payload.source_state_id = sourceStateIdRef.current
        payload.document_version = requestedState.documentVersion
      }
      const response = await fetch('/api/lean/check', {method: 'POST', credentials: 'same-origin', headers: {Accept: 'application/json', 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}, body: JSON.stringify(payload), signal: controller.signal})
      const result = await response.json() as Record<string, unknown>
      if (controller.signal.aborted || serial !== serialRef.current || requestedPath !== activePathRef.current || requestedVersion !== currentVersion() || (kind === 'source' && requestedSourceFingerprint !== sourceFingerprint())) return
      if (Number.isFinite(Number(result.version)) && Number(result.version) !== requestedVersion) return
      if (!response.ok || !result.success) {
        if (result.code === 'resync_required') {
          sourceStateIdRef.current = ''
          requestedState.documentVersion = null
          forceSemanticResyncRef.current = true
          completedRef.current = {source: '', cursor: ''}
          queuedSourceRef.current = true
          setStatus({state: 'checking', text: '正在重新同步 Lean'})
          return
        }
        if (result.code === 'service_busy') {
          setStatus({state: 'checking', text: '正在等待 Lean'})
          sourceTimerRef.current = setTimeout(() => checkRef.current(kind), 500)
          return
        }
        throw new Error(String(result.message || 'Lean 服务暂时不可用'))
      }
      if (kind === 'source') sourceStateIdRef.current = String(result.source_state_id || '')
      if (Number.isFinite(Number(result.document_version))) requestedState.documentVersion = Number(result.document_version)
      if (Object.prototype.hasOwnProperty.call(result, 'semantic_tokens') && requestedState.semanticTokens) {
        if (requestedState.semanticTokens.accept(requestedVersion, result.semantic_tokens)) forceSemanticResyncRef.current = false
        else {
          forceSemanticResyncRef.current = true
          completedRef.current.source = ''
          queuedSourceRef.current = true
        }
      }
      let nextDiagnostics = diagnostics
      if (kind === 'source' && Object.prototype.hasOwnProperty.call(result, 'diagnostics') && result.diagnostics !== null) {
        nextDiagnostics = normalizeDiagnostics(result.diagnostics)
        setDiagnostics(nextDiagnostics)
        applyMarkers(nextDiagnostics)
        renderFiles((version) => version + 1)
      }
      const now = currentPosition()
      if (now.line === requestedPosition.line && now.character === requestedPosition.character) {
        setGoals(Array.isArray(result.goals) ? result.goals as Goal[] : [])
        setHasGoalResult(true)
        if (kind === 'source') queuedCursorRef.current = false
      } else queuedCursorRef.current = true
      setStatus({state: nextDiagnostics.length ? 'problems' : 'ready', text: nextDiagnostics.length ? `${nextDiagnostics.length} 个问题` : '已同步'})
      if (!forceSemanticResyncRef.current) completedRef.current[kind] = fingerprint
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return
      if (serial !== serialRef.current) return
      const message = error instanceof Error ? error.message : 'Lean 服务暂时不可用'
      const failure = [{path: requestedPath, severity: 'error', message, range: {start: requestedPosition, end: requestedPosition}}]
      sourcePendingRef.current = true
      setStatus({state: 'offline', text: '检查失败'})
      setDiagnostics(failure)
      applyMarkers(failure)
      renderFiles((version) => version + 1)
      setActiveTab('problems')
    } finally {
      if (requestRef.current?.serial !== serial) return
      requestRef.current = null
      if (queuedSourceRef.current) {
        queuedSourceRef.current = false
        queuedCursorRef.current = false
        setTimeout(() => checkRef.current('source'), 0)
      } else if (queuedCursorRef.current) {
        queuedCursorRef.current = false
        setTimeout(() => checkRef.current('cursor'), 0)
      }
    }
  }, [applyMarkers, clearTimers, currentPosition, currentState, currentVersion, diagnostics, normalizeDiagnostics, normalized.revision, problemId, sourceFingerprint, writableFiles])
  checkRef.current = (kind) => {void runCheck(kind)}

  const setWritableFiles = useCallback((files: Record<string, string>) => {
    suppressChangesRef.current = true
    for (const [path, state] of statesRef.current) {
      if (state.mode !== 'writable' || !(path in files)) continue
      const nextValue = String(files[path] || '')
      state.content = nextValue
      state.model?.setValue?.(nextValue)
      state.semanticTokens?.invalidate()
    }
    suppressChangesRef.current = false
    const state = currentState()
    if (state) onChangeRef.current(stateValue(state))
    renderFiles((version) => version + 1)
    scheduleSource()
  }, [currentState, scheduleSource, stateValue])

  const onEditorReady = useCallback((context: MonacoEditorReadyContext) => {
    disposedRef.current = false
    clientSessionIdRef.current = createClientSessionId()
    sourcePendingRef.current = true
    sourceStateIdRef.current = ''
    forceSemanticResyncRef.current = false
    queuedSourceRef.current = false
    queuedCursorRef.current = false
    completedRef.current = {source: '', cursor: ''}
    setDiagnostics([])
    setGoals([])
    setHasGoalResult(false)
    setActiveTab('goals')
    setStatus({state: 'idle', text: '准备中'})
    const {monaco, editor} = context
    monacoRef.current = monaco
    editorRef.current = editor
    const disposables: Disposable[] = []
    const bootstrapModel = editor.getModel?.() || null
    const completion = monaco.languages.registerCompletionItemProvider('lean4', {
      triggerCharacters: ['\\'],
      provideCompletionItems: (model: MonacoModel, position: {lineNumber: number; column: number}) => {
        const before = model.getLineContent?.(position.lineNumber)?.slice(0, position.column - 1) || ''
        const match = before.match(/\\[^\\\s]*$/)
        if (!match) return {suggestions: []}
        const abbreviations = monaco.getLean4UnicodeAbbreviations?.() || {}
        const typed = match[0]
        return {suggestions: Object.entries(abbreviations).filter(([abbreviation]) => `\\${abbreviation}`.startsWith(typed)).map(([abbreviation, replacement]) => ({
          label: `\\${abbreviation}  ${String(replacement).replace('$CURSOR', '▏')}`,
          filterText: `\\${abbreviation}`,
          insertText: String(replacement).replace('$CURSOR', '$0'),
          insertTextRules: String(replacement).includes('$CURSOR') ? monaco.languages.CompletionItemInsertTextRule?.InsertAsSnippet : undefined,
          detail: 'Lean Unicode abbreviation',
          kind: monaco.languages.CompletionItemKind?.Text,
          range: new monaco.Range(position.lineNumber, position.column - typed.length, position.lineNumber, position.column),
        }))}
      },
    })
    disposables.push(completion)
    statesRef.current = new Map(normalized.files.map((file) => {
      const encodedPath = file.path.split('/').map(encodeURIComponent).join('/')
      const model = monaco.editor.createModel(file.content, 'lean4', monaco.Uri.parse(`file:///workspace/numoj-${problemId}/${encodedPath}`))
      const state: FileState = {...file, originalContent: file.content, model, viewState: null, documentVersion: null, semanticTokens: createLeanSemanticTokens(monaco, model)}
      disposables.push(model.onDidChangeContent(() => {
        state.content = model.getValue()
        state.semanticTokens?.invalidate()
        renderFiles((version) => version + 1)
        if (!suppressChangesRef.current) scheduleSource()
      }))
      return [file.path, state]
    }))
    activePathRef.current = normalized.defaultFile
    setActivePath(normalized.defaultFile)
    switchFile(normalized.defaultFile, false)
    if (bootstrapModel && bootstrapModel !== currentState()?.model) bootstrapModel.dispose()
    disposables.push(editor.onDidChangeCursorPosition?.(() => scheduleCursor()) || {dispose: () => undefined})
    sourceTimerRef.current = setTimeout(() => checkRef.current('source'), 80)

    const cleanup = () => {
      if (disposedRef.current) return
      disposedRef.current = true
      clearTimers()
      serialRef.current += 1
      requestRef.current?.controller.abort()
      requestRef.current = null
      disposables.forEach((disposable) => disposable.dispose())
      for (const state of statesRef.current.values()) {
        state.semanticTokens?.dispose()
        if (state.model) {
          monaco.editor.setModelMarkers(state.model, 'lean4', [])
          state.model.dispose()
        }
      }
      monacoRef.current = null
      editorRef.current = null
      onControllerRef.current(null)
    }
    const controller: LeanWorkbenchController = {
      checkNow: () => checkRef.current('source'),
      dispose: cleanup,
      focus: () => editorRef.current?.focus(),
      getActiveValue: () => stateValue(currentState()),
      layout: () => editorRef.current?.layout(),
      prepareSubmission: () => ({revision: normalized.revision, files: writableFiles()}),
      setActiveValue: (nextValue) => {
        const preferred = statesRef.current.get(normalized.defaultFile)
        const state = preferred?.mode === 'writable' ? preferred : [...statesRef.current.values()].find((candidate) => candidate.mode === 'writable')
        if (!state) return
        switchFile(state.path, false)
        setWritableFiles({[state.path]: String(nextValue || '')})
      },
      setWritableFiles,
    }
    onControllerRef.current(controller)
    return cleanup
  }, [clearTimers, currentState, normalized.defaultFile, normalized.files, normalized.revision, problemId, scheduleCursor, scheduleSource, setWritableFiles, stateValue, switchFile, writableFiles])

  const revealDiagnostic = useCallback((diagnostic: Diagnostic) => {
    const path = diagnosticPath(diagnostic)
    if (!switchFile(path, true)) return
    const range = diagnosticRange(diagnostic)
    const editor = editorRef.current
    editor?.setPosition?.({lineNumber: range.start.line + 1, column: range.start.character + 1})
    editor?.revealLineInCenter?.(range.start.line + 1)
    editor?.focus()
  }, [diagnosticPath, switchFile])

  return {activePath, activeTab, cursor, diagnostics, goals, hasGoalResult, normalized, onEditorReady, setActiveTab, status, statesRef, switchFile, currentVersion, diagnosticPath, revealDiagnostic}
}

function buildTree(files: WorkspaceFile[]) {
  const root: TreeNode = {folders: new Map(), files: []}
  for (const file of files) {
    const parts = file.path.split('/')
    let node = root
    for (const folder of parts.slice(0, -1)) {
      if (!node.folders.has(folder)) node.folders.set(folder, {folders: new Map(), files: []})
      node = node.folders.get(folder)!
    }
    node.files.push({name: parts.at(-1) || file.path, path: file.path})
  }
  return root
}

function FileTree({node, activePath, states, errorCounts, expanded, onToggle, onSelect}: {node: TreeNode; activePath: string; states: Map<string, FileState>; errorCounts: Map<string, number>; expanded: Set<string>; onToggle: (path: string) => void; onSelect: (path: string) => void}) {
  const renderNode = (current: TreeNode, parentPath: string) => <ul className="lean-file-tree-list" role="group">
    {[...current.folders.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([name, child]) => {
      const path = parentPath ? `${parentPath}/${name}` : name
      const open = expanded.has(path)
      return <li key={path}><button type="button" className="lean-file-tree-row" role="treeitem" aria-expanded={open} onClick={() => onToggle(path)}><span className="lean-file-tree-chevron" aria-hidden="true">{open ? '▾' : '▸'}</span><i className="lean-file-tree-icon fas fa-folder" aria-hidden="true" /><span className="lean-file-tree-label">{name}</span></button>{open ? renderNode(child, path) : null}</li>
    })}
    {[...current.files].sort((left, right) => left.name.localeCompare(right.name)).map((file) => {
      const state = states.get(file.path)
      if (!state) return null
      const dirty = state.mode === 'writable' && stateValueForRender(state) !== state.originalContent
      const errors = errorCounts.get(file.path) || 0
      return <li key={file.path}><button type="button" className={`lean-file-tree-row ${state.mode === 'readonly' ? 'is-readonly' : 'is-writable'}${activePath === file.path ? ' is-active' : ''}`} role="treeitem" aria-current={activePath === file.path} title={`${file.path}${state.mode === 'readonly' ? '（只读）' : '（可写）'}`} onClick={() => onSelect(file.path)}><span className="lean-file-tree-chevron" aria-hidden="true" /><i className={`lean-file-tree-icon fas ${state.mode === 'readonly' ? 'fa-lock' : 'fa-pen'}`} aria-hidden="true" /><span className="lean-file-tree-label">{file.name}</span><span className="lean-file-dirty" hidden={!dirty} title="有未提交的修改" /><span className="lean-file-error-count" hidden={!errors}>{errors}</span></button></li>
    })}
  </ul>
  return renderNode(node, '')
}

function stateValueForRender(state: FileState) {
  return state.model?.getValue() ?? state.content
}

export function LeanWorkbench({problemId, workspace, value, onChange, onController}: {problemId: number; workspace?: LeanWorkspace | null; value: string; onChange: (value: string) => void; onController: (controller: LeanWorkbenchController | null) => void}) {
  const rootRef = useRef<HTMLDivElement>(null)
  const splitterRef = useRef<HTMLDivElement>(null)
  useLeanSplitter(rootRef, splitterRef, problemId)
  const workbench = useLeanWorkbench({problemId, workspace, value, onChange, onController})
  const tree = useMemo(() => buildTree(workbench.normalized.files), [workbench.normalized.files])
  const allFolders = useMemo(() => {
    const result = new Set<string>()
    const collect = (node: TreeNode, parent = '') => node.folders.forEach((child, name) => {const path = parent ? `${parent}/${name}` : name; result.add(path); collect(child, path)})
    collect(tree)
    return result
  }, [tree])
  const [expanded, setExpanded] = useState(allFolders)
  useEffect(() => setExpanded(allFolders), [allFolders])
  const activeState = workbench.statesRef.current.get(workbench.activePath)
  const errorCounts = useMemo(() => {
    const counts = new Map<string, number>()
    workbench.diagnostics.forEach((diagnostic) => {
      if (severityName(diagnostic.severity) !== 'error') return
      const path = workbench.diagnosticPath(diagnostic)
      counts.set(path, (counts.get(path) || 0) + 1)
    })
    return counts
  }, [workbench.diagnosticPath, workbench.diagnostics])
  return <div ref={rootRef} className="lean-workbench" id="leanWorkbench" data-problem-id={problemId} data-check-url="/api/lean/check">
    <input type="hidden" id="leanWorkspaceInput" name="lean_workspace" value="" readOnly />
    <section className="lean-source-pane" id="leanSourcePane" aria-label="Lean 4 证明文件编辑器">
      <header className="lean-pane-bar lean-source-bar"><span className="lean-file-name"><span className="lean-file-mark" aria-hidden="true">λ</span><span className="lean-active-file-name" id="leanActiveFileName" title={workbench.activePath}>{workbench.activePath}</span><span className={`lean-active-file-mode${activeState?.mode === 'readonly' ? ' is-readonly' : ''}`} id="leanActiveFileMode">{activeState?.mode === 'readonly' ? '只读' : '可写'}</span></span><span className="lean-source-meta"><span className="lean-unicode-hint" title={'输入 Lean 缩写后按空格或 Tab，例如 \\alpha → α'}>\alpha → α</span><span className="lean-cursor-position" id="leanCursorPosition">Ln {workbench.cursor.line + 1}, Col {workbench.cursor.character + 1}</span></span></header>
      <div className="lean-editor-body"><MonacoEditor key={`${problemId}:${workbench.normalized.revision}:${workbench.normalized.files.map((file) => file.path).join('|')}`} language="lean4" problemId={problemId} value={value} onChange={onChange} idPrefix="lean" ariaLabel="Lean 4 证明编辑器" onReady={workbench.onEditorReady} /></div>
    </section>
    <div ref={splitterRef} className="lean-workbench-splitter" id="leanWorkbenchSplitter" role="separator" tabIndex={0} aria-label="调整代码与证明状态宽度" aria-orientation="vertical" aria-controls="leanSourcePane leanInspectorPane" aria-valuemin={20} aria-valuemax={80} aria-valuenow={63} data-lean-workbench-splitter />
    <aside className="lean-inspector" id="leanInspectorPane" aria-label="Lean 证明状态">
      <section className="lean-file-explorer" aria-label="Lean 工作区文件"><header className="lean-file-explorer-bar"><span>Files</span><span className="lean-file-count" id="leanFileCount">{workbench.normalized.files.length}</span></header><div className="lean-file-tree" id="leanFileTree" role="tree"><FileTree node={tree} activePath={workbench.activePath} states={workbench.statesRef.current} errorCounts={errorCounts} expanded={expanded} onToggle={(path) => setExpanded((current) => {const next = new Set(current); if (next.has(path)) next.delete(path); else next.add(path); return next})} onSelect={(path) => workbench.switchFile(path, true)} /></div></section>
      <header className="lean-pane-bar lean-inspector-bar"><div className="lean-inspector-tabs" role="tablist" aria-label="证明检查结果"><button type="button" className={`lean-inspector-tab${workbench.activeTab === 'goals' ? ' is-active' : ''}`} id="leanGoalsTab" role="tab" aria-selected={workbench.activeTab === 'goals'} aria-controls="leanGoalsPanel" onClick={() => workbench.setActiveTab('goals')}>Goals <span className="lean-tab-count" id="leanGoalCount">{workbench.goals.length}</span></button><button type="button" className={`lean-inspector-tab${workbench.activeTab === 'problems' ? ' is-active' : ''}${workbench.diagnostics.some((item) => severityName(item.severity) === 'error') ? ' has-errors' : ''}`} id="leanProblemsTab" role="tab" aria-selected={workbench.activeTab === 'problems'} aria-controls="leanProblemsPanel" onClick={() => workbench.setActiveTab('problems')}>Problems <span className="lean-tab-count" id="leanProblemCount">{workbench.diagnostics.length}</span></button></div><span className="lean-check-status" id="leanCheckStatus" data-state={workbench.status.state} role="status" aria-live="polite"><span className="lean-status-dot" aria-hidden="true" /><span data-lean-status-text>{workbench.status.text}</span></span></header>
      <div className="lean-inspector-body">
        <section className={`lean-inspector-panel${workbench.activeTab === 'goals' ? ' is-active' : ''}`} id="leanGoalsPanel" role="tabpanel" aria-labelledby="leanGoalsTab" hidden={workbench.activeTab !== 'goals'}>{workbench.goals.length ? <div className="lean-goal-list" id="leanGoalList">{workbench.goals.map((goal, index) => <article className="lean-goal-card" key={index}><header className="lean-goal-heading">Goal {index + 1}</header>{typeof goal === 'string' || goal.text ? <pre className="lean-goal-code">{typeof goal === 'string' ? goal : goal.text}</pre> : <>{(goal.hyps || goal.hypotheses || []).length ? <pre className="lean-goal-hypotheses">{(goal.hyps || goal.hypotheses || []).map((item) => typeof item === 'string' ? item : `${item.name || ''} : ${item.type || ''}`).join('\n')}</pre> : null}<pre className="lean-goal-target">{goal.target || ''}</pre></>}</article>)}</div> : <div className="lean-panel-empty" id="leanGoalsEmpty"><span className="lean-empty-glyph" aria-hidden="true">{workbench.hasGoalResult ? '✓' : '⊢'}</span><strong>{workbench.hasGoalResult ? '当前没有目标' : '等待证明状态'}</strong><span>{workbench.hasGoalResult ? '光标位置没有未完成的证明目标。' : '把光标放在 tactic 中，这里会显示当前目标。'}</span></div>}</section>
        <section className={`lean-inspector-panel${workbench.activeTab === 'problems' ? ' is-active' : ''}`} id="leanProblemsPanel" role="tabpanel" aria-labelledby="leanProblemsTab" hidden={workbench.activeTab !== 'problems'}>{workbench.diagnostics.length ? <ol className="lean-problem-list" id="leanProblemList">{workbench.diagnostics.map((diagnostic, index) => {const range = diagnosticRange(diagnostic); const severity = severityName(diagnostic.severity); return <li className="lean-problem-item" data-severity={severity} tabIndex={0} key={index} onClick={() => workbench.revealDiagnostic(diagnostic)} onKeyDown={(event) => {if (event.key === 'Enter' || event.key === ' ') {event.preventDefault(); workbench.revealDiagnostic(diagnostic)}}}><span className="lean-problem-severity" aria-hidden="true" /><div><p className="lean-problem-message">{diagnostic.message || 'Lean 检查失败'}</p><span className="lean-problem-location">{workbench.diagnosticPath(diagnostic)} · {severity.toUpperCase()} · Ln {range.start.line + 1}, Col {range.start.character + 1}</span></div></li>})}</ol> : <div className="lean-panel-empty" id="leanProblemsEmpty"><span className="lean-empty-glyph is-check" aria-hidden="true">✓</span><strong>暂时没有问题</strong><span>Lean 的错误与警告会列在这里。</span></div>}</section>
      </div>
      <footer className="lean-inspector-footer"><span><kbd>Ctrl</kbd><span aria-hidden="true">+</span><kbd>Space</kbd> 补全符号</span><span id="leanDocumentVersion">v{workbench.currentVersion()}</span></footer>
    </aside>
  </div>
}
