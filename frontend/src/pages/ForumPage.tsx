import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useLayoutEffect, useMemo, useRef, useState, type FormEvent} from 'react'
import {useParams} from 'react-router-dom'

import {ApiError, apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {Identicon} from '../components/Identicon'
import {MarkdownContent} from '../components/MarkdownContent'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {ErrorState, LoadingState} from '../components/PageState'
import {useNativeDialog} from '../components/useNativeDialog'
import {useNavigate} from '../components/PageNavigation'
import {browserUuid} from '../lib/browserUuid'
import {useSession} from '../session'

interface ListResponse extends ApiEnvelope {threads?: JsonRecord[]; items?: JsonRecord[]}
interface ThreadResponse extends ApiEnvelope {thread: JsonRecord; replies?: JsonRecord[]}
interface IdentityResponse extends ApiEnvelope {identity: JsonRecord}
interface PreviewResponse extends ApiEnvelope {rendered_content?: string}
type ReliableDraft = {title?: string; content?: string; client_request_id?: string; base_version?: number | null; previous_anonymous_name?: string; pending_attempt?: {body: JsonRecord; submitted_at: string} | null}
type ReliableVariables = {body: JsonRecord; key: string}

const FORUM_RETRY_DELAYS = [350, 900, 1800]

function readForumDraft(key: string): ReliableDraft | null {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(key) || 'null')
    return value && typeof value === 'object' ? value as ReliableDraft : null
  } catch { return null }
}

function writeForumDraft(key: string, value: ReliableDraft) {
  window.sessionStorage.setItem(key, JSON.stringify(value))
}

function pendingBody(draft: ReliableDraft | null): JsonRecord | null {
  const body = draft?.pending_attempt?.body
  return body && typeof body.client_request_id === 'string' ? body : null
}

function definiteForumRejection(error: unknown) {
  return error instanceof ApiError && error.status >= 400 && error.status < 500
}

async function reliableForumRequest<T extends ApiEnvelope>(path: string, method: 'POST' | 'PATCH', body: JsonRecord): Promise<T> {
  let lastError: unknown
  for (let attempt = 0; attempt <= FORUM_RETRY_DELAYS.length; attempt += 1) {
    try {
      return await apiFetch<T>(path, {method, body: JSON.stringify(body)})
    } catch (error) {
      lastError = error
      const retriable = !(error instanceof ApiError) || error.status === 0 || error.status >= 500
      if (!retriable || attempt >= FORUM_RETRY_DELAYS.length) throw error
      await new Promise((resolve) => window.setTimeout(resolve, FORUM_RETRY_DELAYS[attempt]))
    }
  }
  throw lastError
}

function author(item: JsonRecord) {return String(item.display_name || item.author_name || item.username || '未知用户')}
function html(item: JsonRecord) {return String(item.rendered_content || item.content_html || item.content || '')}

function parseDate(value: unknown) {
  if (!value) return null
  const text = String(value)
  const date = new Date(text.includes('T') ? text : text.replace(' ', 'T'))
  return Number.isNaN(date.getTime()) ? null : date
}

function relativeTime(value: unknown) {
  const date = parseDate(value)
  if (!date) return String(value || '未知时间')
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000))
  if (seconds < 45) return '刚刚'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  if (seconds < 604800) return `${Math.floor(seconds / 86400)} 天前`
  return new Intl.DateTimeFormat('zh-CN', {month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'}).format(date)
}

function absoluteTime(value: unknown) {
  const date = parseDate(value)
  if (!date) return String(value || '未知时间')
  return new Intl.DateTimeFormat('zh-CN', {year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'}).format(date)
}

function ForumAvatar({avatar, name, className = ''}: {avatar?: unknown; name: string; className?: string}) {
  return <Identicon seed={name} avatar={avatar} className={`forum-identicon${className ? ` ${className}` : ''}`} />
}

function Post({item, kind, onEdit}: {item: JsonRecord; kind: string; onEdit?: (item: JsonRecord) => void}) {
  const name = author(item)
  return <article className="forum-post" data-post-kind={kind} data-post-id={String(item.id || '')}><ForumAvatar avatar={item.avatar} name={name} /><div className="forum-post-content"><header className="forum-post-head"><strong>{name}</strong>{item.is_anonymous ? <span className="forum-anonymous-mark">ANON</span> : null}{Number(item.edit_version || 1) > 1 ? <span className="forum-edited-mark" title={item.updated_at ? `最后编辑：${absoluteTime(item.updated_at)}` : '内容已编辑'}>已编辑</span> : null}<time className="forum-post-time" dateTime={String(item.created_at || '')} title={absoluteTime(item.created_at)}>{relativeTime(item.created_at)}</time>{item.is_owner && kind === 'reply' && onEdit ? <button className="forum-icon-button forum-post-edit" type="button" aria-label="编辑回复" title="编辑回复" onClick={() => onEdit(item)}><i className="fas fa-pen" /></button> : null}</header><MarkdownContent className="forum-markdown numoj-markdown" html={html(item)} /></div></article>
}

export default function ForumPage() {
  const {threadId} = useParams()
  const {session} = useSession()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [query, setQuery] = useState('')
  const [scope, setScope] = useState<'all' | 'mine'>('all')
  const [composerOpen, setComposerOpen] = useState(false)
  const [editorMode, setEditorMode] = useState<'new' | 'edit-thread' | 'edit-reply'>('new')
  const [editorTarget, setEditorTarget] = useState<JsonRecord | null>(null)
  const [previewOpen, setPreviewOpen] = useState(false)
  const [identityDialogOpen, setIdentityDialogOpen] = useState(false)
  const [aliasName, setAliasName] = useState('')
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [replyContent, setReplyContent] = useState('')
  const [editorFrozen, setEditorFrozen] = useState(false)
  const [replyFrozen, setReplyFrozen] = useState(false)
  const [identityFrozen, setIdentityFrozen] = useState(false)
  const [storageError, setStorageError] = useState('')
  const detailPaneRef = useRef<HTMLElement>(null)
  const replyComposerRef = useRef<HTMLFormElement>(null)
  const composerRef = useNativeDialog(composerOpen)
  const identityDialogRef = useNativeDialog(identityDialogOpen)
  const list = useQuery({queryKey: ['forum', scope], queryFn: () => apiFetch<ListResponse>(`/api/forum?scope=${scope}`)})
  const identity = useQuery({queryKey: ['forum', 'identity'], queryFn: () => apiFetch<IdentityResponse>('/api/forum/identity')})
  const rows = list.data?.threads || list.data?.items || []
  const activeId = threadId || (rows[0]?.id ? String(rows[0].id) : '')
  const thread = useQuery({queryKey: ['forum', activeId], queryFn: () => apiFetch<ThreadResponse>(`/api/forum/threads/${activeId}`), enabled: Boolean(activeId)})
  const active = thread.data?.thread
  const replies = thread.data?.replies || []
  const useAnonymous = identity.data?.identity.use_anonymous === true || Number(identity.data?.identity.use_anonymous) === 1
  const storageNamespace = identity.data?.identity.draft_namespace ? `numoj.forum.v2.${encodeURIComponent(String(identity.data.identity.draft_namespace))}` : ''
  const draftKey = (suffix: string) => `${storageNamespace}.${suffix}`
  const clearDraft = (key: string) => {try {window.sessionStorage.removeItem(key)} catch { /* 成功响应不应因清理失败而重发 */ }}
  const markSubmissionFailure = (error: unknown, variables: ReliableVariables, setFrozen: (value: boolean) => void) => {
    if (!definiteForumRejection(error)) {
      setFrozen(true)
      return
    }
    const draft = readForumDraft(variables.key) || {}
    try {
      writeForumDraft(variables.key, {...draft, client_request_id: browserUuid(), pending_attempt: null})
    } catch {
      setStorageError('当前浏览器禁止标签页存储，无法保存待重试内容；请允许站点存储后刷新页面。')
    }
    setFrozen(false)
  }
  const create = useMutation({
    mutationFn: ({body}: ReliableVariables) => reliableForumRequest<ApiEnvelope & {thread?: JsonRecord}>('/api/forum/threads', 'POST', body),
    onSuccess: async (data, variables) => {clearDraft(variables.key); setEditorFrozen(false); await queryClient.invalidateQueries({queryKey: ['forum']}); setComposerOpen(false); setPreviewOpen(false); setTitle(''); setContent(''); const id = Number(data.thread?.id); if (id) navigate(`/forum/${id}`)},
    onError: (error, variables) => markSubmissionFailure(error, variables, setEditorFrozen),
  })
  const editThread = useMutation({
    mutationFn: ({body}: ReliableVariables) => reliableForumRequest<ApiEnvelope & {thread?: JsonRecord}>(`/api/forum/threads/${String(editorTarget?.id || activeId)}`, 'PATCH', body),
    onSuccess: async (_data, variables) => {clearDraft(variables.key); setEditorFrozen(false); setComposerOpen(false); setPreviewOpen(false); await Promise.all([queryClient.invalidateQueries({queryKey: ['forum']}), queryClient.invalidateQueries({queryKey: ['forum', activeId]})])},
    onError: (error, variables) => markSubmissionFailure(error, variables, setEditorFrozen),
  })
  const editReply = useMutation({
    mutationFn: ({body}: ReliableVariables) => reliableForumRequest<ApiEnvelope>(`/api/forum/replies/${String(editorTarget?.id || '')}`, 'PATCH', body),
    onSuccess: async (_data, variables) => {clearDraft(variables.key); setEditorFrozen(false); setComposerOpen(false); setPreviewOpen(false); await queryClient.invalidateQueries({queryKey: ['forum', activeId]})},
    onError: (error, variables) => markSubmissionFailure(error, variables, setEditorFrozen),
  })
  const updateIdentity = useMutation({mutationFn: (enabled: boolean) => apiFetch<IdentityResponse>('/api/forum/identity/mode', {method: 'PUT', body: JSON.stringify({use_anonymous: enabled})}), onSuccess: (data) => queryClient.setQueryData(['forum', 'identity'], data)})
  const rotateIdentity = useMutation({
    mutationFn: (input: ReliableVariables | string) => {
      if (typeof input !== 'string') return reliableForumRequest<IdentityResponse>('/api/forum/identity/anonymous', 'POST', input.body)
      const key = draftKey('identity.rotate')
      const stored = readForumDraft(key) || {}
      const body = pendingBody(stored) || {display_name: input, enable: true, client_request_id: stored.client_request_id || browserUuid()}
      writeForumDraft(key, {...stored, content: String(body.display_name), client_request_id: String(body.client_request_id), previous_anonymous_name: String(identity.data?.identity.anonymous_name || ''), pending_attempt: {body, submitted_at: new Date().toISOString()}})
      setIdentityFrozen(true)
      return reliableForumRequest<IdentityResponse>('/api/forum/identity/anonymous', 'POST', body)
    },
    onSuccess: (data, input) => {clearDraft(typeof input === 'string' ? draftKey('identity.rotate') : input.key); setIdentityFrozen(false); queryClient.setQueryData(['forum', 'identity'], data); setIdentityDialogOpen(false); setAliasName('')},
    onError: (error, input) => markSubmissionFailure(error, typeof input === 'string' ? {key: draftKey('identity.rotate'), body: pendingBody(readForumDraft(draftKey('identity.rotate'))) || {}} : input, setIdentityFrozen),
  })
  const preview = useMutation({mutationFn: () => apiFetch<PreviewResponse>('/api/forum/preview', {method: 'POST', body: JSON.stringify({content})})})
  const reply = useMutation({
    mutationFn: ({body}: ReliableVariables) => reliableForumRequest<ApiEnvelope>(`/api/forum/threads/${activeId}/replies`, 'POST', body),
    onSuccess: async (_data, variables) => {clearDraft(variables.key); setReplyFrozen(false); setReplyContent(''); await Promise.all([queryClient.invalidateQueries({queryKey: ['forum', activeId]}), queryClient.invalidateQueries({queryKey: ['forum', scope]})])},
    onError: (error, variables) => markSubmissionFailure(error, variables, setReplyFrozen),
  })
  useLayoutEffect(() => {
    const pane = detailPaneRef.current
    const composer = replyComposerRef.current
    if (!pane) return
    const syncOverlayHeight = () => pane.style.setProperty('--forum-reply-overlay-height', `${Math.ceil(composer?.getBoundingClientRect().height || 0)}px`)
    syncOverlayHeight()
    if (!composer || typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(syncOverlayHeight)
    observer.observe(composer)
    return () => observer.disconnect()
  }, [active, activeId, threadId])
  const persistDraft = (key: string, value: ReliableDraft) => {
    if (!storageNamespace) return false
    try {
      writeForumDraft(key, value)
      setStorageError('')
      return true
    } catch {
      setStorageError('当前浏览器禁止标签页存储，无法启用可靠提交；请允许站点存储后刷新页面。')
      return false
    }
  }
  const editorKeyFor = (mode: typeof editorMode, target: JsonRecord | null) => mode === 'new'
    ? draftKey('thread.new')
    : draftKey(`edit.${mode}.${String(target?.id || '')}`)
  useEffect(() => {
    if (!storageNamespace || !activeId) return
    const stored = readForumDraft(draftKey(`reply.${activeId}`))
    const pending = pendingBody(stored)
    setReplyContent(String(pending?.content ?? stored?.content ?? ''))
    setReplyFrozen(Boolean(pending))
  }, [activeId, storageNamespace])
  useEffect(() => {
    if (!storageNamespace || !activeId || replyFrozen) return
    const key = draftKey(`reply.${activeId}`)
    const stored = readForumDraft(key) || {}
    if (!replyContent && !Object.keys(stored).length) return
    persistDraft(key, {...stored, content: replyContent, client_request_id: stored.client_request_id || browserUuid(), pending_attempt: null})
  }, [activeId, replyContent, replyFrozen, storageNamespace])
  useEffect(() => {
    if (!composerOpen || !storageNamespace || editorFrozen) return
    const key = editorKeyFor(editorMode, editorTarget)
    const stored = readForumDraft(key) || {}
    persistDraft(key, {
      ...stored,
      title,
      content,
      client_request_id: stored.client_request_id || browserUuid(),
      base_version: editorMode === 'new' ? null : Number(stored.base_version || editorTarget?.edit_version || 1),
      pending_attempt: null,
    })
  }, [composerOpen, content, editorFrozen, editorMode, editorTarget?.id, storageNamespace, title])
  useEffect(() => {
    if (!composerOpen) return
    const titleInput = document.getElementById('forumTitle') as HTMLInputElement | null
    const contentInput = document.getElementById('forumContent') as HTMLTextAreaElement | null
    if (titleInput) titleInput.readOnly = editorFrozen
    if (contentInput) contentInput.readOnly = editorFrozen
  }, [composerOpen, editorFrozen, previewOpen])
  useEffect(() => {
    if (!identityDialogOpen || !storageNamespace) return
    const stored = readForumDraft(draftKey('identity.rotate'))
    const pending = pendingBody(stored)
    if (pending) setAliasName(String(pending.display_name || ''))
    setIdentityFrozen(Boolean(pending))
    const aliasInput = document.getElementById('forumAlias') as HTMLInputElement | null
    if (aliasInput) aliasInput.readOnly = Boolean(pending)
  }, [identityDialogOpen, identityFrozen, storageNamespace])
  const filtered = useMemo(() => rows.filter((item) => !query.trim() || `${String(item.title || '')} ${String(item.excerpt || item.preview || '')}`.toLowerCase().includes(query.trim().toLowerCase())), [query, rows])
  const restoreEditor = (mode: typeof editorMode, target: JsonRecord | null) => {
    const stored = storageNamespace ? readForumDraft(editorKeyFor(mode, target)) : null
    const pending = pendingBody(stored)
    const restored = pending || stored
    setEditorMode(mode)
    setEditorTarget(target)
    setTitle(String(restored?.title ?? (mode === 'edit-thread' ? target?.title : '') ?? ''))
    setContent(String(restored?.content ?? target?.content ?? ''))
    setEditorFrozen(Boolean(pending))
    setPreviewOpen(false)
    setComposerOpen(true)
  }
  const openNewThread = () => restoreEditor('new', null)
  const openThreadEditor = () => {if (active) restoreEditor('edit-thread', active)}
  const openReplyEditor = (item: JsonRecord) => restoreEditor('edit-reply', item)
  const closeEditor = () => {setComposerOpen(false); setPreviewOpen(false)}
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!event.currentTarget.reportValidity() || !storageNamespace) {
      if (!storageNamespace) setStorageError('发布身份尚未就绪，无法建立可靠草稿空间。')
      return
    }
    const key = editorKeyFor(editorMode, editorTarget)
    const stored = readForumDraft(key) || {}
    const frozen = pendingBody(stored)
    const body: JsonRecord = frozen || (editorMode === 'new'
      ? {title: title.trim(), content: content.trim(), client_request_id: stored.client_request_id || browserUuid(), expected_identity_token: identity.data?.identity.posting_token}
      : editorMode === 'edit-thread'
        ? {title: title.trim(), content: content.trim(), edit_version: Number(stored.base_version || editorTarget?.edit_version || active?.edit_version || 1), client_request_id: stored.client_request_id || browserUuid()}
        : {content: content.trim(), edit_version: Number(stored.base_version || editorTarget?.edit_version || 1), client_request_id: stored.client_request_id || browserUuid()})
    if (!persistDraft(key, {...stored, title: String(body.title || ''), content: String(body.content || ''), client_request_id: String(body.client_request_id), base_version: body.edit_version == null ? null : Number(body.edit_version), pending_attempt: {body, submitted_at: new Date().toISOString()}})) return
    setEditorFrozen(true)
    const variables = {body, key}
    if (editorMode === 'edit-thread') editThread.mutate(variables)
    else if (editorMode === 'edit-reply') editReply.mutate(variables)
    else create.mutate(variables)
  }
  const submitReply = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!replyContent.trim() || !storageNamespace) return
    const key = draftKey(`reply.${activeId}`)
    const stored = readForumDraft(key) || {}
    const body = pendingBody(stored) || {content: replyContent.trim(), client_request_id: stored.client_request_id || browserUuid(), expected_identity_token: identity.data?.identity.posting_token}
    if (!persistDraft(key, {...stored, content: String(body.content), client_request_id: String(body.client_request_id), pending_attempt: {body, submitted_at: new Date().toISOString()}})) return
    setReplyFrozen(true)
    reply.mutate({body, key})
  }
  if (list.isPending) return <LoadingState label="正在读取讨论区" />
  if (list.isError) return <ErrorState message={list.error.message} />
  return <div className={`forum-page${threadId ? ' is-mobile-detail-open' : ''}`} id="forumApp">
    <section className="forum-workspace" aria-label="讨论区工作台">
      <aside className="forum-list-pane"><div className="forum-pane-tools"><label className="forum-search"><i className="fas fa-search" /><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} autoComplete="off" aria-label="搜索讨论" placeholder="搜索公开讨论内容" /></label></div><div className="forum-filter-strip"><div className="forum-filter-tabs" role="tablist" aria-label="讨论筛选"><button className={`forum-chip${scope === 'all' ? ' is-active' : ''}`} type="button" role="tab" aria-selected={scope === 'all'} onClick={() => setScope('all')}>全部讨论</button><button className={`forum-chip${scope === 'mine' ? ' is-active' : ''}`} type="button" role="tab" aria-selected={scope === 'mine'} onClick={() => setScope('mine')}>我的讨论</button></div><button className="forum-new-thread-button" type="button" onClick={openNewThread}><i className="fas fa-plus" /><span>发起讨论</span></button></div>
        <div className="forum-thread-list" role="listbox" aria-label="讨论列表">{filtered.map((item) => {const id = String(item.id); const name = author(item); const activity = item.last_activity_at || item.updated_at || item.created_at; return <button type="button" className={`forum-thread-row${id === activeId ? ' is-selected' : ''}`} role="option" aria-selected={id === activeId} onClick={() => navigate(`/forum/${id}`)} key={id}><h3 className="forum-thread-title">{String(item.title || '无标题讨论')}</h3><span className="forum-thread-meta"><span className="forum-thread-identity"><ForumAvatar avatar={item.avatar} name={name} className="forum-identicon-xs" /><span className="forum-thread-author">{name}</span>{item.is_anonymous ? <span className="forum-anonymous-mark">匿名</span> : null}</span><span className="forum-thread-active-time" title={absoluteTime(activity)}>{relativeTime(activity)}</span><span className="forum-reply-count"><i className="far fa-comment" />{String(item.reply_count || 0)}</span></span></button>})}{!filtered.length ? <div className="forum-list-empty"><span className="forum-empty-mark"><i className="fas fa-magnifying-glass" /></span><strong>{query ? '没有匹配的讨论' : '讨论区还是空的'}</strong><p>{query ? '换个关键词后再试。' : '从一个具体问题开始，会更容易得到有用的回应。'}</p></div> : null}</div>
        <footer className="forum-list-footer"><div className="forum-identity-control"><ForumAvatar avatar={identity.data?.identity.posting_avatar} name={String(identity.data?.identity.posting_name || session?.user?.username || '')} className="forum-identicon-sm" /><span className="forum-identity-copy"><small>CURRENT IDENTITY</small><strong>{String(identity.data?.identity.posting_name || session?.user?.username || '')}</strong></span><label className="forum-switch-label" title="打开后使用匿名身份"><input type="checkbox" aria-label="匿名身份开关" checked={useAnonymous} disabled={identity.isPending || updateIdentity.isPending} onChange={(event) => updateIdentity.mutate(event.target.checked)} /><span className="forum-switch" aria-hidden="true" /><span>匿名</span></label><button className="forum-identity-refresh" type="button" title="更换匿名身份" aria-label="更换匿名身份" disabled={!useAnonymous || !(identity.data?.identity.can_change_anonymous === true || Number(identity.data?.identity.can_change_anonymous) === 1) || rotateIdentity.isPending} onClick={() => {setAliasName(''); setIdentityDialogOpen(true)}}><i className="fas fa-rotate" /></button></div></footer>
      </aside>
      <article ref={detailPaneRef} className="forum-detail-pane" aria-live="polite"><header className="forum-detail-header"><button className="forum-icon-button forum-mobile-back" type="button" aria-label="返回讨论列表" onClick={() => navigate('/forum')}><i className="fas fa-arrow-left" /></button><div className="forum-detail-heading"><div className="forum-detail-kicker">{active ? `THREAD · F${String(active.id || activeId).padStart(4, '0')} · ${String(active.reply_count ?? replies.length)} REPLIES` : 'THREAD · SELECT'}</div><h2>{active ? String(active.title || '讨论') : '选择一条讨论开始阅读'}</h2></div><div className="forum-detail-actions">{active?.is_owner ? <button className="forum-button forum-button-quiet" type="button" onClick={openThreadEditor}><i className="fas fa-pen" />编辑主题</button> : null}<button className="forum-icon-button" type="button" aria-label="分享讨论" title="分享讨论" disabled={!active} onClick={() => void navigator.clipboard?.writeText(window.location.href)}><i className="fas fa-link" /></button></div></header>
        <div className="forum-conversation">{active ? <><Post item={active} kind="thread" /><div className="forum-reply-divider">{String(active.reply_count ?? replies.length)} REPLIES</div>{replies.length ? replies.map((item, index) => <Post item={item} kind="reply" onEdit={openReplyEditor} key={String(item.id || index)} />) : <div className="forum-detail-empty"><span className="forum-empty-mark"><i className="far fa-message" /></span><strong>还没有回复</strong><p>把你想到的关键线索写下来，成为第一个回应的人。</p></div>}</> : thread.isPending && activeId ? <div className="forum-detail-empty"><MathCurveLoader size="md" label="正在读取讨论" /></div> : <div className="forum-detail-empty"><span className="forum-empty-mark"><i className="far fa-comments" /></span><strong>讨论从左边开始</strong><p>选择主题后，正文、回复和编辑器都会在这里展开。</p></div>}</div>{active ? <form ref={replyComposerRef} className={`forum-reply-composer${replyFrozen ? ' has-pending-attempt' : ''}`} onSubmit={submitReply}><div className="forum-reply-surface"><label className="visually-hidden" htmlFor="forumReplyContent">写下回复</label><textarea id="forumReplyContent" rows={2} value={replyContent} readOnly={replyFrozen} onChange={(event) => setReplyContent(event.target.value)} placeholder="写下你的回复… 支持 Markdown、代码、LaTeX 与 Mermaid" /><div className="forum-reply-footer">{replyFrozen && reply.isError ? <span className="forum-field-error me-auto">{errorMessage(reply.error)}。结果尚未确认，内容与请求标识已冻结，可原样重试。</span> : reply.isError ? <span className="forum-field-error me-auto">{errorMessage(reply.error)}</span> : storageError ? <span className="forum-field-error me-auto">{storageError}</span> : null}<button className="forum-reply-send" type="submit" aria-label="发送回复" title={replyFrozen ? '使用同一请求标识重试' : '发送回复'} disabled={reply.isPending || !identity.data?.identity.posting_token}><i className={`fas ${reply.isPending ? 'fa-spinner fa-spin' : replyFrozen ? 'fa-rotate-right' : 'fa-arrow-up'}`} /></button></div></div></form> : null}
      </article>
    </section>
    {composerOpen ? <dialog ref={composerRef} className="forum-dialog forum-editor-dialog" onCancel={(event) => {event.preventDefault(); closeEditor()}}><form onSubmit={submit} noValidate><header className="forum-dialog-header forum-editor-dialog-header"><div className="forum-dialog-heading"><span className="forum-dialog-kicker">{editorMode === 'new' ? 'NEW THREAD' : editorMode === 'edit-thread' ? `EDIT · F${String(editorTarget?.id || activeId).padStart(4, '0')}` : `EDIT REPLY · #${String(editorTarget?.id || '')}`}</span><h2>{editorMode === 'new' ? '发起讨论' : editorMode === 'edit-thread' ? '编辑主题' : '编辑回复'}</h2></div><div className="forum-editor-header-actions"><div className="forum-editor-posting-identity"><ForumAvatar avatar={editorMode === 'new' ? identity.data?.identity.posting_avatar : editorTarget?.avatar} name={editorMode === 'new' ? String(identity.data?.identity.posting_name || session?.user?.username || '') : author(editorTarget || {})} className="forum-identicon-sm" /><span className="forum-editor-posting-copy"><strong>{editorMode === 'new' ? String(identity.data?.identity.posting_name || session?.user?.username || '当前身份') : author(editorTarget || {})}</strong><small>{editorMode === 'new' ? '讨论将以当前身份发布' : '身份按首次发布时锁定'}</small></span></div><button className="forum-icon-button" type="button" onClick={closeEditor} aria-label="关闭编辑器"><i className="fas fa-xmark" /></button></div></header><div className="forum-dialog-body">{editorMode !== 'edit-reply' ? <div className="forum-field"><label htmlFor="forumTitle">标题</label><input id="forumTitle" value={title} onChange={(event) => setTitle(event.target.value)} maxLength={255} required autoFocus placeholder="今天讨论点什么呢……？" /></div> : null}<div className="forum-editor-tabs" role="tablist" aria-label="编辑与预览"><button className={previewOpen ? '' : 'is-active'} type="button" role="tab" aria-selected={!previewOpen} onClick={() => setPreviewOpen(false)}>编写</button><button className={previewOpen ? 'is-active' : ''} type="button" role="tab" aria-selected={previewOpen} onClick={() => {setPreviewOpen(true); preview.mutate()}}>预览</button></div>{previewOpen ? <div className="forum-editor-preview forum-markdown numoj-markdown">{preview.data?.rendered_content ? <MarkdownContent className="numoj-markdown" html={preview.data.rendered_content} /> : null}{preview.isPending ? <p className="forum-preview-placeholder">正在生成预览…</p> : null}</div> : <div className="forum-field forum-editor-write"><label className="visually-hidden" htmlFor="forumContent">正文</label><textarea id="forumContent" value={content} onChange={(event) => setContent(event.target.value)} rows={12} required autoFocus={editorMode === 'edit-reply'} placeholder="啊哒哒……啊哒哒……啊哒啊哒……喵喵喵喵喵！" /></div>}<p className="forum-field-error" role="alert">{create.isError || editThread.isError || editReply.isError || preview.isError || updateIdentity.isError || rotateIdentity.isError ? errorMessage(create.error || editThread.error || editReply.error || preview.error || updateIdentity.error || rotateIdentity.error) : ''}</p></div><footer className="forum-dialog-footer"><small>{editorMode === 'new' ? '' : `基于版本 ${String(editorTarget?.edit_version || 1)}`}</small><div className="forum-dialog-actions"><button className="forum-button" type="button" onClick={closeEditor}>取消</button><button className="forum-button forum-button-primary" type="submit" disabled={create.isPending || editThread.isPending || editReply.isPending || (editorMode === 'new' && !identity.data?.identity.posting_token)}>{editorMode === 'new' ? '发布讨论' : '保存修改'}</button></div></footer></form></dialog> : null}
    {identityDialogOpen ? <dialog ref={identityDialogRef} className="forum-dialog forum-identity-dialog" onCancel={(event) => {event.preventDefault(); setIdentityDialogOpen(false)}}><form noValidate onSubmit={(event) => {event.preventDefault(); if (aliasName.trim()) rotateIdentity.mutate(aliasName.trim())}}><header className="forum-dialog-header"><div><span className="forum-dialog-kicker">ANONYMOUS IDENTITY</span><h2>设置匿名身份</h2></div><button className="forum-icon-button" type="button" aria-label="关闭匿名身份设置" onClick={() => setIdentityDialogOpen(false)}><i className="fas fa-xmark" /></button></header><div className="forum-dialog-body"><div className="forum-editor-identity"><ForumAvatar name={aliasName || '等待输入'} className="forum-identicon-lg" /><span><strong>{aliasName || '等待输入'}</strong><small>匿名用户名决定这枚 8×8 头像</small></span></div><div className="forum-field"><label htmlFor="forumAlias"><span>匿名用户名</span><span className={`forum-char-count${aliasName.length > 10 ? ' is-invalid' : ''}`}>{aliasName.length} / 10</span></label><input id="forumAlias" value={aliasName} onChange={(event) => setAliasName(event.target.value.slice(0, 10))} autoComplete="off" placeholder="例如：收敛小浣熊" required autoFocus /></div><p className="forum-field-error" role="alert">{rotateIdentity.isError ? errorMessage(rotateIdentity.error) : ''}</p></div><footer className="forum-dialog-footer"><small>{String(identity.data?.identity.anonymous_cooldown_note || '首次设置不受冷却限制')}</small><div className="forum-dialog-actions"><button className="forum-button" type="button" onClick={() => setIdentityDialogOpen(false)}>取消</button><button className="forum-button forum-button-primary" type="submit" disabled={!aliasName.trim() || rotateIdentity.isPending}>保存并使用</button></div></footer></form></dialog> : null}
    <div className="forum-toast" id="forumToast" role="status" aria-live="polite" aria-atomic="true"><span className="forum-toast-mark" aria-hidden="true" /><span className="forum-toast-copy"><small id="forumToastEyebrow">FORUM · NOTICE</small><strong id="forumToastMessage" /></span></div>
  </div>
}
