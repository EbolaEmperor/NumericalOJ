import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type CSSProperties,
  type FormEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from 'react'
import {createPortal} from 'react-dom'
import {useParams} from 'react-router-dom'

import {apiFetch, ApiError, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {Identicon} from '../components/Identicon'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {MarkdownContent} from '../components/MarkdownContent'
import {ModelLogo} from '../components/ModelLogo'
import {Link} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'
import {AgentFilePreview} from './agent/AgentFilePreview'
import {PendingAttachmentStrip, SavedAttachments} from './agent/AgentAttachments'
import {AgentExecutionTrace} from './agent/AgentExecutionTrace'
import {AgentMessageQueue} from './agent/AgentMessageQueue'
import {AgentWorkspaceTree} from './agent/AgentWorkspace'
import {
  agentRunIsTerminal,
  agentRunQueryKey,
  cacheAgentRunSnapshot,
  fetchAgentRun,
  fetchAgentWorkBlock,
  synchronizeFinalAgentRun,
  useAgentRunEvents,
  workBlockQueryKey,
} from './agent/runEvents'
import {
  agentComposerDeliveryMode,
  agentComposerEnterAction,
  agentSessionUrl,
  cachedFallbackMessage,
  createAgentMessageId,
  mergeFiles,
  messageAttachments,
  messageCopy,
  messageId,
  messageMode,
  queuedMessages,
  statusKey,
  usageDisplay,
  type AgentDeliveryMode,
} from './agent/legacyBehavior'
import {useAutosizeTextarea} from './agent/useAutosizeTextarea'

interface SessionResponse extends ApiEnvelope {
  user?: JsonRecord
  agent_session: JsonRecord
  turns: JsonRecord[]
  current_state: JsonRecord
  agent_message_state: JsonRecord
  agent_message_urls?: JsonRecord
  can_resume: boolean
  can_retry?: boolean
  can_retry_now?: boolean
  agent_quota_summary?: JsonRecord
  agent_context_window_tokens?: number
}

interface WorkspaceResponse extends ApiEnvelope {
  tree?: JsonRecord[]
  entries?: JsonRecord[]
  files?: JsonRecord[]
  unavailable?: boolean
}

interface SessionStateResponse extends ApiEnvelope {state: JsonRecord}
interface DispatchResponse extends ApiEnvelope {
  delivery_mode?: string
  detail_url?: string
  task_id?: string
  current_task_id?: string
  user_message?: string
  user_message_html?: string
  attachments?: JsonRecord[]
  agent_message?: JsonRecord
  session_state?: JsonRecord
  state?: JsonRecord
  replaced_task_id?: string
  title?: string
}

interface DispatchRequest {
  body: FormData
  deliveryMode: AgentDeliveryMode
  expectedTaskId: string
  files: File[]
  message: string
  messageId: string
  retrying: boolean
}

const statusLabels: Record<string, string> = {
  pending: '等待中', running: '运行中', completed: '已完成', failed: '失败',
  canceled: '已停止', cancelled: '已停止', cleanupfailed: '清理失败，需管理员处理',
  cleanup_failed: '清理失败，需管理员处理',
}
const harnessLabels: Record<string, string> = {claude_code: 'Claude Code', 'claude-code': 'Claude Code', pi: 'Pi'}
const effortLabels: Record<string, string> = {default: '默认', off: '关闭', minimal: '最少', low: '低', medium: '中', high: '高', xhigh: '极高', max: '最大'}

function harnessName(value: unknown) {const text = String(value || 'Harness'); return harnessLabels[text] || text}
function harnessIcon(value: unknown) {const key = String(value || '').toLowerCase().replaceAll('_', '-') === 'pi' ? 'pi' : 'claude-code'; return `harness-logo harness-logo--${key}`}
function isRunningStatus(value: unknown) {return ['pending', 'running'].includes(statusKey(value))}
function isBlockedStatus(value: unknown) {return ['cleanupfailed', 'cleanup_failed'].includes(statusKey(value))}
function asRecord(value: unknown): JsonRecord {return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : {}}
function mobileLayout() {return typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia('(max-width: 991.98px)').matches}

function RichHtml({html, fallback}: {html: unknown; fallback?: unknown}) {
  const rendered = String(html || '')
  return rendered ? <MarkdownContent className="numoj-markdown" html={rendered} /> : <div className="numoj-markdown"><p>{String(fallback || '')}</p></div>
}

function SteerMessage({message, sessionId, openFile, variant}: {message: JsonRecord; sessionId: string; openFile: (path: string) => void; variant: 'summary' | 'detail'}) {
  const html = String(message.html || message.user_message_html || message.message_html || '')
  return <section className={`agent-user-message agent-timeline-steer agent-timeline-steer--${variant}`} data-message-id={messageId(message)}><div className={`agent-user-bubble${html ? ' numoj-markdown' : ''}`}>{html ? <MarkdownContent className="numoj-markdown" html={html} /> : <p>{messageCopy(message)}</p>}</div><SavedAttachments attachments={messageAttachments(message)} sessionId={sessionId} openFile={openFile} /></section>
}

function AgentTurnDetails({taskId, duration, running = false, defaultOpen = false, liveRevision = 0, sessionId, openFile}: {taskId: string; duration?: unknown; running?: boolean; defaultOpen?: boolean; liveRevision?: number; sessionId: string; openFile: (path: string) => void}) {
  const [open, setOpen] = useState(defaultOpen)
  const result = useQuery({queryKey: agentRunQueryKey(taskId), queryFn: ({signal}) => fetchAgentRun(taskId, signal), enabled: open && Boolean(taskId), staleTime: Infinity, gcTime: Infinity, refetchOnReconnect: false})
  const trace = asRecord(result.data?.state?.execution_trace)
  return <details className="agent-turn-details" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}><summary><span><i className="fas fa-chevron-right" aria-hidden="true" />{running ? 'Agent 正在工作' : '工作详情'}</span>{running ? <span className="agent-live-mark"><i />LIVE</span> : duration ? <small>{String(duration)}</small> : null}</summary><div>{result.isPending ? <div className="agent-working-placeholder"><MathCurveLoader size="sm" label="正在加载工作详情" /></div> : result.isError ? <div className="agent-work-block-placeholder">工作详情加载失败，请收起后重试。</div> : <AgentExecutionTrace trace={trace} traceScope={taskId} live={running && open} liveRevision={liveRevision} loadWorkBlock={(blockId, signal) => fetchAgentWorkBlock(taskId, blockId, signal)} workBlockQueryKey={(blockId) => workBlockQueryKey(taskId, blockId)} sessionId={sessionId} openFile={openFile} />}</div></details>
}

function AgentUsage({usage, personal}: {usage: JsonRecord | null; personal: boolean}) {
  const display = usageDisplay(usage, personal)
  const warning = cachedFallbackMessage(usage)
  return <dl className="agent-session-usage" aria-label="会话累计 Token 用量"><div className="agent-session-usage-fact agent-session-usage-fact--input"><dt><span aria-hidden="true">INPUT</span><span className="visually-hidden">输入 Token</span></dt><dd>{display.input}</dd></div><div className="agent-session-usage-fact agent-session-usage-fact--cached"><dt><span aria-hidden="true">CACHED</span><span className="visually-hidden">缓存输入占比</span></dt><dd><span>{display.cached}</span>{warning ? <button className="agent-usage-warning" type="button" aria-label={warning} aria-describedby="agentUsageWarningTooltip"><span className="agent-usage-warning-mark" aria-hidden="true">!</span><span className="agent-usage-tooltip" id="agentUsageWarningTooltip" role="tooltip"><span>{warning}</span></span></button> : null}</dd></div><div className="agent-session-usage-fact agent-session-usage-fact--output"><dt><span aria-hidden="true">OUTPUT</span><span className="visually-hidden">输出 Token</span></dt><dd>{display.output}</dd></div><div className="agent-session-usage-fact agent-session-usage-fact--cost"><dt><span aria-hidden="true">COST</span><span className="visually-hidden">费用（人民币）</span></dt><dd>{display.cost}</dd></div></dl>
}

function RenameModal({sessionId, initialTitle, close, renamed}: {sessionId: string; initialTitle: string; close: () => void; renamed: (title: string) => void}) {
  const [title, setTitle] = useState(initialTitle)
  const modalRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const returnFocus = useRef<HTMLElement | null>(null)
  const mutation = useMutation({mutationFn: () => apiFetch<DispatchResponse>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/title`, {method: 'PATCH', body: JSON.stringify({title: title.trim()})}), onSuccess: (payload) => {renamed(String(payload.title || title.trim())); close()}})
  useEffect(() => {
    returnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    requestAnimationFrame(() => inputRef.current?.select())
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {event.preventDefault(); close(); return}
      if (event.key !== 'Tab' || !modalRef.current) return
      const focusable = Array.from(modalRef.current.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled])'))
      if (!focusable.length) return
      const first = focusable[0]; const last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last.focus()}
      else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first.focus()}
    }
    document.addEventListener('keydown', keydown)
    return () => {document.removeEventListener('keydown', keydown); if (returnFocus.current?.isConnected) returnFocus.current.focus()}
  }, [close])
  const submit = (event: FormEvent) => {event.preventDefault(); if (title.trim() && !mutation.isPending) mutation.mutate()}
  return createPortal(<><div className="modal-backdrop fade show" /><div ref={modalRef} className="modal fade show agent-rename-modal" role="dialog" aria-modal="true" aria-labelledby="agentRenameModalTitle" style={{display: 'block'}}><div className="modal-dialog modal-sm modal-dialog-centered"><form className="modal-content" onSubmit={submit}><header><div><span>SESSION NAME</span><h2 id="agentRenameModalTitle">重命名会话</h2></div><button type="button" className="btn-close" aria-label="关闭" onClick={close} /></header><div className="agent-rename-modal-body"><label htmlFor="agentSessionRename">会话名称</label><input ref={inputRef} id="agentSessionRename" name="title" maxLength={64} required value={title} autoComplete="off" onChange={(event) => setTitle(event.target.value)} />{mutation.isError ? <p role="status" aria-live="polite">{errorMessage(mutation.error)}</p> : null}</div><footer><button type="button" onClick={close}>取消</button><button type="submit" disabled={!title.trim() || mutation.isPending}>{mutation.isPending ? '保存中…' : '保存'}</button></footer></form></div></div></>, document.body)
}

export default function AgentSessionPage() {
  const {sessionId = ''} = useParams()
  const queryClient = useQueryClient()
  const queryKey = useMemo(() => ['agent-session', sessionId] as const, [sessionId])
  const [message, setMessage] = useState('')
  const [attachments, setAttachments] = useState<File[]>([])
  const [workspaceOpen, setWorkspaceOpen] = useState(false)
  const [selectedPath, setSelectedPath] = useState('')
  const [feedback, setFeedback] = useState('')
  const [feedbackError, setFeedbackError] = useState(false)
  const [messageState, setMessageState] = useState<JsonRecord>({})
  const [messageStreamConnected, setMessageStreamConnected] = useState(false)
  const [runStreamConnected, setRunStreamConnected] = useState(false)
  const [renameOpen, setRenameOpen] = useState(false)
  const [draggingSplitter, setDraggingSplitter] = useState<'conversation' | 'workspace' | ''>('')
  const [workspacePercent, setWorkspacePercent] = useState(22)
  const [conversationPercent, setConversationPercent] = useState(45)
  const rootRef = useRef<HTMLElement>(null)
  const conversationPaneRef = useRef<HTMLElement>(null)
  const workspacePaneRef = useRef<HTMLElement>(null)
  const conversationScrollRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const pointerRef = useRef<{kind: 'conversation' | 'workspace'; id: number} | null>(null)
  const attemptRef = useRef({fingerprint: '', id: '', mode: '' as AgentDeliveryMode | '', expectedTaskId: ''})
  const retryRef = useRef({id: '', expectedTaskId: ''})
  useAutosizeTextarea(textareaRef, message, 48, 180)

  const result = useQuery({queryKey, queryFn: ({signal}) => apiFetch<SessionResponse>(`/api/agent/sessions/${encodeURIComponent(sessionId)}`, {signal}), refetchInterval: (query) => isRunningStatus(query.state.data?.current_state?.status) && !runStreamConnected ? 5_000 : false})
  const workspace = useQuery({queryKey: ['agent-session', sessionId, 'workspace'], queryFn: ({signal}) => apiFetch<WorkspaceResponse>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/workspace`, {signal}), enabled: result.isSuccess, refetchInterval: isRunningStatus(messageState.status || result.data?.current_state?.status) ? 3_000 : false})
  const stateResult = useQuery({queryKey: ['agent-session', sessionId, 'message-state'], queryFn: ({signal}) => apiFetch<SessionStateResponse>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/state`, {signal}), enabled: result.isSuccess && !messageStreamConnected, refetchInterval: messageStreamConnected ? false : isRunningStatus(messageState.status) || queuedMessages(messageState).length ? 2_400 : 6_000})

  const applyMessageState = useCallback((state: JsonRecord) => {
    setMessageState(state)
    const nextTaskId = String(state.current_task_id || '')
    const nextStatus = state.status
    queryClient.setQueryData<SessionResponse>(queryKey, (current) => current ? ({...current, agent_session: {...current.agent_session, ...(nextTaskId ? {current_task_id: nextTaskId} : {}), ...(nextStatus ? {status: nextStatus} : {}), ...(state.native_session_id ? {native_session_id: state.native_session_id} : {})}, current_state: {...current.current_state, ...(nextTaskId ? {task_id: nextTaskId} : {}), ...(nextStatus ? {status: nextStatus} : {}), ...(state.session_token_usage ? {session_token_usage: state.session_token_usage} : {}), ...(state.context_usage ? {context_usage: state.context_usage} : {}), ...(state.quota_summary ? {quota_summary: state.quota_summary} : {})}}) : current)
  }, [queryClient, queryKey])
  useEffect(() => {if (result.data?.agent_message_state) applyMessageState(result.data.agent_message_state)}, [applyMessageState, result.data?.agent_message_state])
  useEffect(() => {if (stateResult.data?.state) applyMessageState(stateResult.data.state)}, [applyMessageState, stateResult.data?.state])
  useEffect(() => {
    setMessageStreamConnected(false)
    if (!result.isSuccess || typeof window === 'undefined' || !window.EventSource) return
    const source = new EventSource(`/api/agent/sessions/${encodeURIComponent(sessionId)}/stream`)
    source.onopen = () => setMessageStreamConnected(true)
    source.addEventListener('session', ((event: MessageEvent) => {try {const state = JSON.parse(event.data) as JsonRecord; if (state && typeof state === 'object') {setMessageStreamConnected(true); applyMessageState(state)}} catch {/** 下一帧会覆盖。 */}}) as EventListener)
    source.onerror = () => setMessageStreamConnected(false)
    return () => {source.close(); setMessageStreamConnected(false)}
  }, [applyMessageState, result.isSuccess, sessionId])

  const session = result.data?.agent_session || {}
  const currentState = result.data?.current_state || {}
  const currentTaskId = String(messageState.current_task_id || currentState.task_id || session.current_task_id || '')
  const status = statusKey(messageState.status || currentState.status || session.status || 'completed')
  const running = typeof messageState.running === 'boolean' ? messageState.running : isRunningStatus(status)
  const handleRunDone = useCallback(() => {void queryClient.invalidateQueries({queryKey}); void queryClient.invalidateQueries({queryKey: ['agent-session', sessionId, 'message-state']}); void queryClient.invalidateQueries({queryKey: ['agent-session', sessionId, 'workspace']})}, [queryClient, queryKey, sessionId])
  const handleRunSnapshot = useCallback(async (snapshot: JsonRecord) => {if (agentRunIsTerminal(snapshot)) return; await queryClient.cancelQueries({queryKey, exact: true}); queryClient.setQueryData<SessionResponse>(queryKey, (current) => current ? ({...current, current_state: {...current.current_state, ...snapshot}}) : current)}, [queryClient, queryKey])
  const liveRevision = useAgentRunEvents({taskId: currentTaskId, enabled: running, onSnapshot: handleRunSnapshot, onDone: handleRunDone, onConnectionChange: setRunStreamConnected})
  useEffect(() => {
    if (!currentTaskId || !Object.keys(currentState).length) return
    void cacheAgentRunSnapshot(queryClient, currentTaskId, currentState)
  }, [currentState, currentTaskId, queryClient])
  const previousRunningTaskId = useRef('')
  useEffect(() => {
    const previous = previousRunningTaskId.current
    if (running && currentTaskId) {if (previous && previous !== currentTaskId) {void synchronizeFinalAgentRun(queryClient, previous).catch(() => undefined); void queryClient.invalidateQueries({queryKey})}; previousRunningTaskId.current = currentTaskId; return}
    if (!previous) return
    previousRunningTaskId.current = ''
    void synchronizeFinalAgentRun(queryClient, previous).catch(() => undefined)
  }, [currentTaskId, queryClient, queryKey, running])
  useEffect(() => {if (session.title) document.title = `${String(session.title)} - Numerical OJ`}, [session.title])
  useEffect(() => {const scroll = conversationScrollRef.current; if (scroll) requestAnimationFrame(() => scroll.scrollTo({top: scroll.scrollHeight, behavior: 'auto'}))}, [result.isSuccess])

  const user = result.data?.user || {}
  const quota = asRecord(messageState.quota_summary || currentState.quota_summary || result.data?.agent_quota_summary)
  const isAdmin = Number(user.is_admin || 0) === 1
  const personalEndpoint = session.uses_personal_endpoint === true || statusKey(session.endpoint_source) === 'user'
  const publicEnabled = quota.public_enabled !== false
  const quotaCanContinue = quota.can_continue !== false && !(Number.isFinite(Number(quota.remaining_amount)) && Number(quota.remaining_amount) < 0)
  const quotaHasAccount = quota.has_account !== false
  const accessBlocked = !isAdmin && (!publicEnabled || (!personalEndpoint && !quotaCanContinue))
  const queue = queuedMessages(messageState)
  const queuePaused = messageState.queue_paused === true && queue.length > 0
  const canResume = result.data?.can_resume === true
  const legacy = session.is_legacy === true
  const nativeSessionId = String(messageState.native_session_id || currentState.native_session_id || session.native_session_id || '').trim()
  const hardBlocked = !canResume || legacy || isBlockedStatus(status) || accessBlocked
  // 失败轮次会暂停既有队列，但没有真实排队消息时，普通发送必须直接以
  // 新轮次续接原生会话；不能被一个孤立的 queue_paused 标志降级为 queue。
  const queueMode = running || queue.length > 0
  const blocked = hardBlocked || (!running && !nativeSessionId && !queueMode)
  const steerSupported = messageState.steer_supported !== false
  const steerUnavailableReason = String(messageState.steer_unavailable_reason || session.steer_unavailable_reason || '').trim()
  const usage = asRecord(messageState.session_token_usage || currentState.session_token_usage)
  const contextUsage = asRecord(messageState.context_usage || currentState.context_usage)
  const contextWindow = Number(contextUsage.window_tokens || result.data?.agent_context_window_tokens)
  const contextUsed = Number(contextUsage.used_tokens)
  const contextHasUsed = Number.isFinite(contextUsed) && contextUsed >= 0
  const contextHasWindow = Number.isFinite(contextWindow) && contextWindow > 0
  const contextText = `${contextHasUsed ? `${Math.round(contextUsed / 1000)}k` : '—'} / ${contextHasWindow ? `${Math.round(contextWindow / 1000)}k` : '—'}`
  const contextPercent = contextHasUsed && contextHasWindow ? Math.min(100, Math.max(0, contextUsed / contextWindow * 100)) : 0
  const accessBlockedMessage = !accessBlocked ? '' : !publicEnabled ? 'Agent 暂停向普通用户开放，当前会话仅可查看。' : !quotaHasAccount ? '你还没有平台额度；请先申请额度再继续此会话。' : Number(quota.remaining_amount) <= -5 ? '额度已达到 -5 元，系统正在停止任务；补充额度后才能继续。' : '额度低于 0 元，请申请额度后继续。此会话使用全站端点，不能切换为自有端点。'
  const blockedMessage = accessBlockedMessage || (legacy ? '旧任务没有可恢复的 workspace，无法继续会话' : !canResume ? '只有会话发起者可以继续发送消息' : isBlockedStatus(status) ? '身份配置清理失败，请管理员处理后再继续' : result.data?.can_retry_now ? '本轮未建立可恢复的原生会话，可以重试上一条消息' : '本轮未建立可恢复的原生会话，请新建 Agent 会话')
  const reportFeedback = useCallback((copy: string, isError = true) => {setFeedback(copy); setFeedbackError(isError)}, [])
  const stateSyncWarning = '实时状态连接暂时中断，正在自动重试。'
  useEffect(() => {
    if (stateResult.isError && !messageStreamConnected && !blocked) {
      setFeedback((current) => current || stateSyncWarning)
      setFeedbackError(true)
      return
    }
    setFeedback((current) => current === stateSyncWarning ? '' : current)
  }, [blocked, messageStreamConnected, stateResult.isError])
  const clearComposer = () => {setMessage(''); setAttachments([]); attemptRef.current = {fingerprint: '', id: '', mode: '', expectedTaskId: ''}; if (fileInputRef.current) fileInputRef.current.value = ''}
  const scrollToLatest = () => requestAnimationFrame(() => conversationScrollRef.current?.scrollTo({top: conversationScrollRef.current.scrollHeight, behavior: 'smooth'}))

  const dispatch = useMutation({
    mutationFn: (request: DispatchRequest) => apiFetch<DispatchResponse>(`/api/agent/sessions/${encodeURIComponent(sessionId)}`, {method: 'POST', body: request.body}),
    onSuccess: (payload, request) => {
      if (payload.detail_url) {window.location.assign(agentSessionUrl('', payload.detail_url)); return}
      const record = payload.agent_message || {}
      const actualMode = (messageMode(record) || statusKey(payload.delivery_mode || request.deliveryMode)) as AgentDeliveryMode
      if (!request.retrying && ['queue', 'steer'].includes(actualMode)) {if (payload.session_state) applyMessageState(payload.session_state); clearComposer(); reportFeedback('', false); if (actualMode === 'steer') scrollToLatest(); return}
      const taskId = String(payload.task_id || payload.current_task_id || '')
      if (!taskId) {window.location.reload(); return}
      queryClient.setQueryData<SessionResponse>(queryKey, (current) => {
        if (!current) return current
        const withoutRetried = request.retrying ? current.turns.filter((turn) => String(turn.task_id || '') !== String(payload.replaced_task_id || request.expectedTaskId)) : current.turns
        const turn: JsonRecord = {task_id: taskId, message_id: messageId(record) || request.messageId || taskId, user_message: String(payload.user_message ?? request.message), user_message_html: payload.user_message_html, attachments: payload.attachments || request.files.map((file) => ({name: file.name, size: file.size}))}
        return {...current, turns: [...withoutRetried.filter((item) => String(item.task_id || '') !== taskId), turn], agent_session: {...current.agent_session, current_task_id: taskId, status: 'Pending'}, current_state: {...current.current_state, task_id: taskId, status: 'Pending'}, can_retry: true, can_retry_now: false}
      })
      applyMessageState({...messageState, current_task_id: taskId, status: 'Pending', running: true, active_message: record})
      if (request.retrying) retryRef.current = {id: '', expectedTaskId: ''}; else clearComposer()
      reportFeedback('', false); scrollToLatest()
    },
    onError: (error, request) => {
      if (!request.retrying && error instanceof ApiError && error.status >= 400 && error.status < 500) attemptRef.current = {fingerprint: '', id: '', mode: '', expectedTaskId: ''}
      const detailUrl = error instanceof ApiError ? String(error.payload?.detail_url || '') : ''
      if (detailUrl) {window.location.assign(agentSessionUrl('', detailUrl)); return}
      reportFeedback(errorMessage(error))
    },
  })

  const sendMessage = (intent: 'send' | 'steer' = 'send') => {
    if (blocked || dispatch.isPending || !message.trim()) return
    const computedMode = agentComposerDeliveryMode({intent, running, queuedCount: queue.length})
    if (computedMode === 'steer' && (!running || !currentTaskId)) {reportFeedback('当前任务已经结束，无法插话。'); return}
    if (computedMode === 'steer' && !steerSupported) {reportFeedback(steerUnavailableReason || '当前 Harness 暂不支持中途插话。'); return}
    const copy = message.trim(); const files = [...attachments]
    const fingerprint = JSON.stringify([intent, copy, files.map((file) => [file.name, file.size, file.lastModified])])
    if (!attemptRef.current.id || attemptRef.current.fingerprint !== fingerprint) attemptRef.current = {fingerprint, id: createAgentMessageId('msg'), mode: computedMode, expectedTaskId: computedMode === 'steer' ? currentTaskId : ''}
    const attempt = attemptRef.current; const deliveryMode = attempt.mode || computedMode; const body = new FormData()
    body.append('message', copy); body.append('delivery_mode', deliveryMode); body.append('message_id', attempt.id)
    if (deliveryMode === 'steer' && attempt.expectedTaskId) body.append('expected_task_id', attempt.expectedTaskId)
    files.forEach((file) => body.append('attachments', file, file.name))
    reportFeedback('', false)
    dispatch.mutate({body, deliveryMode, expectedTaskId: attempt.expectedTaskId, files, message: copy, messageId: attempt.id, retrying: false})
  }
  const retryLast = () => {
    if (!currentTaskId || dispatch.isPending || hardBlocked || running) return
    if (!retryRef.current.id || retryRef.current.expectedTaskId !== currentTaskId) retryRef.current = {id: createAgentMessageId('retry'), expectedTaskId: currentTaskId}
    const body = new FormData(); body.append('retry_last', '1'); body.append('expected_task_id', currentTaskId); body.append('message_id', retryRef.current.id)
    dispatch.mutate({body, deliveryMode: 'turn', expectedTaskId: currentTaskId, files: [], message: '', messageId: retryRef.current.id, retrying: true})
  }
  const stop = useMutation({
    mutationFn: async () => {const response = await fetch(`/agent/runs/${encodeURIComponent(currentTaskId)}/cancel`, {method: 'POST', headers: {Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest'}, credentials: 'same-origin'}); const payload = await response.json().catch(() => ({})) as DispatchResponse; if (!payload.state) throw new Error(String(payload.message || '停止任务失败')); return {...payload, warning: response.ok && payload.success !== false ? '' : String(payload.message || '')}},
    onSuccess: (payload) => {queryClient.setQueryData<SessionResponse>(queryKey, (current) => current ? ({...current, current_state: {...current.current_state, ...payload.state}}) : current); if (payload.session_state) applyMessageState(payload.session_state); else applyMessageState({...messageState, status: payload.state?.status, running: isRunningStatus(payload.state?.status)}); if (payload.warning) reportFeedback(String(payload.warning))},
    onError: (error) => reportFeedback(errorMessage(error)),
  })
  const chooseFiles = (event: ChangeEvent<HTMLInputElement>) => {setAttachments((current) => mergeFiles(current, event.target.files || [])); event.target.value = ''}
  const keydown = (event: ReactKeyboardEvent<HTMLTextAreaElement>) => {
    const action = agentComposerEnterAction({key: event.key, keyCode: event.keyCode, composing: event.nativeEvent.isComposing, shiftKey: event.shiftKey, ctrlKey: event.ctrlKey, metaKey: event.metaKey, running})
    if (!action) return
    event.preventDefault()
    if (!blocked && !dispatch.isPending && message.trim()) sendMessage(action)
  }
  const submit = (event: FormEvent) => {event.preventDefault(); sendMessage('send')}

  const paneWidths = useCallback(() => {const root = rootRef.current; const workspacePane = workspacePaneRef.current; const conversationPane = conversationPaneRef.current; return root && workspacePane && conversationPane ? {total: root.getBoundingClientRect().width, workspace: workspacePane.getBoundingClientRect().width, conversation: conversationPane.getBoundingClientRect().width} : null}, [])
  const applyPaneWidths = useCallback((conversationWidth: number, workspaceWidth: number) => {
    const root = rootRef.current; if (!root || mobileLayout()) return
    const total = root.getBoundingClientRect().width; const clamp = (value: number, minimum: number, maximum: number) => Math.min(maximum, Math.max(minimum, value))
    if (selectedPath) {const workspaceValue = clamp(workspaceWidth, 160, Math.max(160, total * .36)); const remaining = total - workspaceValue - 10; const conversationValue = clamp(conversationWidth, 280, Math.max(280, remaining - 280)); const fileValue = Math.max(280, remaining - conversationValue); root.style.gridTemplateColumns = `${conversationValue}px 5px ${fileValue}px 5px ${workspaceValue}px`; setConversationPercent(Math.round(conversationValue / total * 100)); setWorkspacePercent(Math.round(workspaceValue / total * 100))} else {const sidebar = clamp(workspaceWidth, 190, Math.max(190, total * .43)); root.style.gridTemplateColumns = `minmax(0, 1fr) 5px ${sidebar}px`; setWorkspacePercent(Math.round(sidebar / total * 100))}
  }, [selectedPath])
  useEffect(() => {
    if (rootRef.current) rootRef.current.style.gridTemplateColumns = ''
    const readAriaValues = () => {const widths = paneWidths(); if (widths?.total) {setWorkspacePercent(Math.round(widths.workspace / widths.total * 100)); setConversationPercent(Math.round(widths.conversation / widths.total * 100))}}
    const update = () => {if (mobileLayout()) {if (rootRef.current) rootRef.current.style.gridTemplateColumns = ''; return}; const widths = paneWidths(); if (widths) applyPaneWidths(widths.conversation, widths.workspace)}
    requestAnimationFrame(readAriaValues); window.addEventListener('resize', update); return () => window.removeEventListener('resize', update)
  }, [applyPaneWidths, paneWidths, selectedPath])
  const splitterHandlers = (kind: 'conversation' | 'workspace') => ({
    onPointerDown: (event: ReactPointerEvent<HTMLDivElement>) => {if (mobileLayout()) return; pointerRef.current = {kind, id: event.pointerId}; event.currentTarget.setPointerCapture(event.pointerId); setDraggingSplitter(kind); event.preventDefault()},
    onPointerMove: (event: ReactPointerEvent<HTMLDivElement>) => {if (pointerRef.current?.id !== event.pointerId || pointerRef.current.kind !== kind || !rootRef.current) return; const widths = paneWidths(); if (!widths) return; const rect = rootRef.current.getBoundingClientRect(); if (kind === 'workspace') applyPaneWidths(widths.conversation, rect.right - event.clientX); else applyPaneWidths(event.clientX - rect.left, widths.workspace)},
    onPointerUp: (event: ReactPointerEvent<HTMLDivElement>) => {if (pointerRef.current?.id === event.pointerId) {pointerRef.current = null; setDraggingSplitter('')}},
    onPointerCancel: (event: ReactPointerEvent<HTMLDivElement>) => {if (pointerRef.current?.id === event.pointerId) {pointerRef.current = null; setDraggingSplitter('')}},
    onKeyDown: (event: ReactKeyboardEvent<HTMLDivElement>) => {if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return; event.preventDefault(); const widths = paneWidths(); if (!widths) return; const direction = event.key === 'ArrowRight' ? 1 : -1; if (kind === 'workspace') applyPaneWidths(widths.conversation, widths.workspace - direction * 16); else applyPaneWidths(widths.conversation + direction * 16, widths.workspace)},
  })

  if (result.isPending) return <LoadingState label="正在读取 Agent 会话" />
  if (result.isError) return <ErrorState message={result.error.message} retry={() => void result.refetch()} />
  const turns = result.data.turns || []
  const reasoningEffort = statusKey(session.reasoning_effort || 'default')
  const workspacePayload = workspace.data?.tree || workspace.data?.entries || workspace.data?.files || []
  const openFile = (path: string) => {setSelectedPath(path); if (mobileLayout()) setWorkspaceOpen(false)}
  const renameTitle = (title: string) => queryClient.setQueryData<SessionResponse>(queryKey, (current) => current ? ({...current, agent_session: {...current.agent_session, title}}) : current)
  const retryAvailable = result.data.can_retry === true && result.data.can_retry_now === true && !running && !hardBlocked
  const hasMessage = Boolean(message.trim())

  return <><main ref={rootRef} className={`agent-session${workspaceOpen ? ' workspace-open' : ''}${selectedPath ? ' has-file' : ''}`} data-agent-session data-running={running} data-status={status}>
    <section ref={conversationPaneRef} className="agent-conversation-pane" aria-label="Agent 会话">
      <header className="agent-session-header"><Link className="agent-session-back" to="/agents" aria-label="返回 Agent 任务列表" title="返回会话列表"><i className="fas fa-chevron-left" /></Link><div className="agent-session-title"><h1 title={String(session.title || 'Agent 会话')}>{String(session.title || 'Agent 会话')}</h1>{!legacy ? <button className="agent-session-rename" type="button" title="重命名会话" aria-label="重命名会话" onClick={() => setRenameOpen(true)}><i className="fas fa-pen" /></button> : null}<span className={`agent-status-chip agent-status-chip--${status}`} role="status" aria-live="polite" aria-label={statusLabels[status] || status}><i /><span>{statusLabels[status] || status}</span></span></div><div className="agent-session-header-side"><AgentUsage usage={Object.keys(usage).length ? usage : null} personal={personalEndpoint} /><div className="agent-session-requester" role="group" aria-label={`发起者：${String(session.requested_by || '')}`} title={`发起者：${String(session.requested_by || '')}`}><Identicon seed={String(session.requested_by || '')} className="numoj-avatar agent-session-avatar" /><span className="agent-session-requester-copy"><small>发起者</small><strong>{String(session.requested_by || '')}</strong></span></div><button className="agent-workspace-mobile-toggle" type="button" aria-label={workspaceOpen ? '关闭 Workspace' : '打开 Workspace'} aria-expanded={workspaceOpen} onClick={() => setWorkspaceOpen((value) => !value)}><i className="fas fa-folder-tree" /></button></div></header>
      <div ref={conversationScrollRef} className="agent-conversation-scroll"><div className="agent-conversation-feed">{turns.map((turn, index) => {const taskId = String(turn.task_id || ''); const currentRunningTurn = running && taskId === currentTaskId; const historicalSteers = Array.isArray(turn.steer_messages) ? turn.steer_messages as JsonRecord[] : []; const last = index === turns.length - 1; return <article className="agent-turn" data-message-id={String(turn.message_id || taskId)} key={taskId || String(index)}><section className="agent-user-message"><div className="agent-user-message-row">{last && taskId === currentTaskId && result.data.can_retry ? <button className="agent-message-retry" type="button" title="重试" aria-label="重试上一条消息" hidden={!retryAvailable} disabled={!retryAvailable || dispatch.isPending} onClick={retryLast}><i className="fas fa-redo-alt" /></button> : null}<div className="agent-user-bubble"><RichHtml html={turn.user_message_html} fallback={turn.user_message} /></div></div><SavedAttachments attachments={Array.isArray(turn.attachments) ? turn.attachments as JsonRecord[] : []} sessionId={sessionId} openFile={openFile} /></section>{historicalSteers.length && !currentRunningTurn ? <div className="agent-steer-messages agent-steer-messages--historical">{historicalSteers.map((item, steerIndex) => <SteerMessage message={item} sessionId={sessionId} openFile={openFile} variant="summary" key={messageId(item) || String(steerIndex)} />)}</div> : null}{!currentRunningTurn ? <section className="agent-response">{turn.has_detail && taskId ? <AgentTurnDetails taskId={taskId} duration={turn.duration} sessionId={sessionId} openFile={openFile} /> : null}<div className="agent-conclusion"><RichHtml html={turn.conclusion_html || turn.final_response_html} fallback={turn.conclusion || turn.final_response} /></div></section> : null}</article>})}{running && currentTaskId ? <article className="agent-turn agent-turn--live"><div className="agent-steer-messages" /><section className="agent-response"><AgentTurnDetails taskId={currentTaskId} running defaultOpen liveRevision={liveRevision} sessionId={sessionId} openFile={openFile} /></section></article> : null}</div></div>
      <footer className="agent-resume-dock"><AgentMessageQueue sessionId={sessionId} state={messageState} currentTaskId={currentTaskId} running={running} hardBlocked={hardBlocked} blocked={blocked} applyState={applyMessageState} reportError={reportFeedback} /><form className={`agent-resume-composer${running ? ' is-running' : ''}${blocked ? ' is-blocked' : ''}${dispatch.isPending ? ' is-submitting' : ''}`} autoComplete="off" onSubmit={submit} onDragEnter={(event) => {if (!blocked && event.dataTransfer.types.includes('Files')) {event.preventDefault(); event.currentTarget.classList.add('is-dragging')}}} onDragOver={(event) => {if (!blocked && event.dataTransfer.types.includes('Files')) {event.preventDefault(); event.dataTransfer.dropEffect = 'copy'}}} onDragLeave={(event) => {if (!event.currentTarget.contains(event.relatedTarget as Node | null)) event.currentTarget.classList.remove('is-dragging')}} onDrop={(event) => {event.preventDefault(); event.currentTarget.classList.remove('is-dragging'); if (!blocked) setAttachments((current) => mergeFiles(current, event.dataTransfer.files))}}><label className="visually-hidden" htmlFor="agentResumeMessage">继续会话</label><textarea ref={textareaRef} id="agentResumeMessage" name="message" rows={2} maxLength={100000} placeholder={running ? '安排下一条消息…' : queuePaused ? '队列已暂停，消息仍可排队…' : '继续这项任务…'} aria-keyshortcuts="Enter Shift+Enter Control+Enter Meta+Enter" value={message} onChange={(event) => {setMessage(event.target.value); if (event.target.value.trim()) reportFeedback('', false)}} onKeyDown={keydown} disabled={blocked || dispatch.isPending} required /><PendingAttachmentStrip files={attachments} variant="resume" remove={(index) => setAttachments((current) => current.filter((_file, fileIndex) => fileIndex !== index))} /><div className="agent-resume-footer"><div className="agent-resume-runtime"><span className="agent-resume-harness"><i className={harnessIcon(session.harness)} />{harnessName(session.harness_label || session.harness)}</span><span className="agent-resume-model"><ModelLogo model={session.endpoint_model || session.model} />{String(session.endpoint_model || session.model || '模型节点')}</span><span className="agent-resume-effort" aria-label={`推理等级：${reasoningEffort === 'default' ? '使用 Harness 原生默认' : effortLabels[reasoningEffort] || reasoningEffort}`}><span className="agent-effort-logo" aria-hidden="true" />{effortLabels[reasoningEffort] || reasoningEffort}</span><button className="agent-context-meter" type="button" style={{'--agent-context-percent': String(contextPercent)} as CSSProperties} aria-label={contextHasUsed ? `上下文 ${contextText}` : `上下文用量暂不可用，上限 ${contextHasWindow ? `${Math.round(contextWindow / 1000)}k` : '未知'}`} aria-describedby="agentContextTooltip"><svg viewBox="0 0 20 20" aria-hidden="true" focusable="false"><circle className="agent-context-meter-track" cx="10" cy="10" r="7.5" /><circle className="agent-context-meter-value" cx="10" cy="10" r="7.5" pathLength="100" /></svg><span className="agent-context-tooltip" id="agentContextTooltip" role="tooltip"><span>上下文</span><strong>{contextText}</strong></span></button></div><div className="agent-resume-actions"><input ref={fileInputRef} id="agentResumeAttachments" className="visually-hidden" type="file" name="attachments" multiple onChange={chooseFiles} disabled={blocked || dispatch.isPending} /><label className="agent-resume-attach" htmlFor="agentResumeAttachments" title="添加附件" aria-label="添加附件"><i className="fas fa-plus" /></label><button className="agent-stop-button" type="button" aria-label={stop.isPending ? '正在停止任务' : '停止任务'} title={stop.isPending ? '正在停止任务' : '停止任务'} hidden={!running || (hasMessage && !stop.isPending)} disabled={stop.isPending} onClick={() => stop.mutate()}>{stop.isPending ? <span className="spinner-border spinner-border-sm" /> : <i className="fas fa-stop" />}</button><button className={`agent-resume-send${queueMode ? ' is-queue-mode' : ''}`} type="submit" aria-label={queueMode ? '加入队列' : '发送消息'} title={queueMode ? '加入队列' : '发送'} hidden={running && (!hasMessage || stop.isPending)} disabled={blocked || dispatch.isPending || stop.isPending || !hasMessage}>{dispatch.isPending ? <span className="spinner-border spinner-border-sm" /> : <i className="fas fa-arrow-up" />}</button></div></div>{feedback || blocked ? <p className={`agent-resume-feedback${feedbackError || blocked ? ' is-error' : ''}`} role="status" aria-live="polite">{feedback || blockedMessage}</p> : null}</form></footer>
    </section>
    {selectedPath ? <div className={`agent-splitter agent-splitter--conversation${draggingSplitter === 'conversation' ? ' is-dragging' : ''}`} role="separator" tabIndex={0} aria-label="调整对话与文件预览宽度" aria-orientation="vertical" aria-valuemin={20} aria-valuemax={70} aria-valuenow={conversationPercent} {...splitterHandlers('conversation')} /> : null}
    {selectedPath ? <AgentFilePreview sessionId={sessionId} path={selectedPath} close={() => setSelectedPath('')} /> : null}
    <div className={`agent-splitter agent-splitter--workspace${draggingSplitter === 'workspace' ? ' is-dragging' : ''}`} role="separator" tabIndex={0} aria-label="调整 Workspace 宽度" aria-orientation="vertical" aria-valuemin={12} aria-valuemax={45} aria-valuenow={workspacePercent} {...splitterHandlers('workspace')} />
    <button className="agent-workspace-backdrop" type="button" aria-label="关闭 Workspace" hidden={!workspaceOpen} onClick={() => setWorkspaceOpen(false)} />
    <aside ref={workspacePaneRef} className="agent-workspace-pane" aria-label="Workspace 文件"><header className="agent-workspace-header"><div><span>WORKSPACE</span><strong>文件</strong></div><div><span className={`agent-workspace-sync${workspace.isFetching ? ' is-syncing' : workspace.isError ? ' is-error' : ''}`} title={workspace.isFetching ? '正在同步 Workspace' : workspace.isError ? '无法读取 Workspace' : 'Workspace 已同步'}><i className={`fas ${workspace.isFetching ? 'fa-sync-alt' : workspace.isError ? 'fa-times-circle' : 'fa-check'}`} /></span><button type="button" aria-label="关闭 Workspace" onClick={() => setWorkspaceOpen(false)}><i className="fas fa-times" /></button></div></header><div className="agent-workspace-tree" aria-label="Workspace 目录结构">{workspace.isPending ? <div className="agent-workspace-loading"><MathCurveLoader size="xs" label="正在读取 Workspace" /></div> : workspace.isError && !workspace.data ? <div className="agent-workspace-empty" role="alert"><span>无法读取 Workspace</span><button type="button" onClick={() => void workspace.refetch()} disabled={workspace.isFetching}>{workspace.isFetching ? '重试中…' : '重试'}</button></div> : <AgentWorkspaceTree payload={workspacePayload} selectedPath={selectedPath} openFile={openFile} />}</div></aside>
  </main>{renameOpen ? <RenameModal sessionId={sessionId} initialTitle={String(session.title || 'Agent 会话')} close={() => setRenameOpen(false)} renamed={renameTitle} /> : null}</>
}
