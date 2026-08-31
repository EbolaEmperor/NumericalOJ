import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useMemo, useRef, useState, type FormEvent} from 'react'
import {useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {MarkdownContent} from '../components/MarkdownContent'
import {ErrorState, LoadingState} from '../components/PageState'
import {useNavigate} from '../components/PageNavigation'
import {useSession} from '../session'

interface ListResponse extends ApiEnvelope {threads?: JsonRecord[]; items?: JsonRecord[]}
interface ThreadResponse extends ApiEnvelope {thread: JsonRecord; replies?: JsonRecord[]}
interface IdentityResponse extends ApiEnvelope {identity: JsonRecord}
interface PreviewResponse extends ApiEnvelope {rendered_content?: string}

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
  const ref = useRef<HTMLSpanElement>(null)
  useEffect(() => {
    if (!ref.current || !window.NumojIdenticon) return
    window.NumojIdenticon.paint(
      ref.current,
      avatar || window.NumojIdenticon.cellsForSeed(name || 'numericaloj'),
      name || '未知用户',
    )
  }, [avatar, name])
  return <span ref={ref} className={`forum-identicon${className ? ` ${className}` : ''}`} aria-hidden="true" />
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
  const composerRef = useRef<HTMLDialogElement>(null)
  const identityDialogRef = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const element = composerRef.current
    if (composerOpen && element && !element.open) element.showModal()
    return () => {if (element?.open) element.close()}
  }, [composerOpen])
  useEffect(() => {
    const element = identityDialogRef.current
    if (identityDialogOpen && element && !element.open) element.showModal()
    return () => {if (element?.open) element.close()}
  }, [identityDialogOpen])
  const list = useQuery({queryKey: ['forum', scope], queryFn: () => apiFetch<ListResponse>(`/api/forum?scope=${scope}`)})
  const identity = useQuery({queryKey: ['forum', 'identity'], queryFn: () => apiFetch<IdentityResponse>('/api/forum/identity')})
  const rows = list.data?.threads || list.data?.items || []
  const activeId = threadId || (rows[0]?.id ? String(rows[0].id) : '')
  const thread = useQuery({queryKey: ['forum', activeId], queryFn: () => apiFetch<ThreadResponse>(`/api/forum/threads/${activeId}`), enabled: Boolean(activeId)})
  const active = thread.data?.thread
  const replies = thread.data?.replies || []
  const useAnonymous = identity.data?.identity.use_anonymous === true || Number(identity.data?.identity.use_anonymous) === 1
  const create = useMutation({mutationFn: () => apiFetch<ApiEnvelope & {thread?: JsonRecord}>('/api/forum/threads', {method: 'POST', body: JSON.stringify({title, content, client_request_id: crypto.randomUUID(), expected_identity_token: identity.data?.identity.posting_token})}), onSuccess: async (data) => {await queryClient.invalidateQueries({queryKey: ['forum']}); setComposerOpen(false); setPreviewOpen(false); setTitle(''); setContent(''); const id = Number(data.thread?.id); if (id) navigate(`/forum/${id}`)}})
  const editThread = useMutation({mutationFn: () => apiFetch<ApiEnvelope & {thread?: JsonRecord}>(`/api/forum/threads/${String(editorTarget?.id || activeId)}`, {method: 'PATCH', body: JSON.stringify({title, content, edit_version: Number(editorTarget?.edit_version || active?.edit_version || 1), client_request_id: crypto.randomUUID()})}), onSuccess: async () => {setComposerOpen(false); setPreviewOpen(false); await Promise.all([queryClient.invalidateQueries({queryKey: ['forum']}), queryClient.invalidateQueries({queryKey: ['forum', activeId]})])}})
  const editReply = useMutation({mutationFn: () => apiFetch<ApiEnvelope>(`/api/forum/replies/${String(editorTarget?.id || '')}`, {method: 'PATCH', body: JSON.stringify({content, edit_version: Number(editorTarget?.edit_version || 1), client_request_id: crypto.randomUUID()})}), onSuccess: async () => {setComposerOpen(false); setPreviewOpen(false); await queryClient.invalidateQueries({queryKey: ['forum', activeId]})}})
  const updateIdentity = useMutation({mutationFn: (enabled: boolean) => apiFetch<IdentityResponse>('/api/forum/identity/mode', {method: 'PUT', body: JSON.stringify({use_anonymous: enabled})}), onSuccess: (data) => queryClient.setQueryData(['forum', 'identity'], data)})
  const rotateIdentity = useMutation({mutationFn: (displayName?: string) => apiFetch<IdentityResponse>('/api/forum/identity/anonymous', {method: 'POST', body: JSON.stringify({display_name: displayName || undefined, enable: true, client_request_id: crypto.randomUUID()})}), onSuccess: (data) => {queryClient.setQueryData(['forum', 'identity'], data); setIdentityDialogOpen(false); setAliasName('')}})
  const preview = useMutation({mutationFn: () => apiFetch<PreviewResponse>('/api/forum/preview', {method: 'POST', body: JSON.stringify({content})})})
  const reply = useMutation({mutationFn: () => apiFetch<ApiEnvelope>(`/api/forum/threads/${activeId}/replies`, {method: 'POST', body: JSON.stringify({content: replyContent, client_request_id: crypto.randomUUID(), expected_identity_token: identity.data?.identity.posting_token})}), onSuccess: async () => {setReplyContent(''); await Promise.all([queryClient.invalidateQueries({queryKey: ['forum', activeId]}), queryClient.invalidateQueries({queryKey: ['forum', scope]})])}})
  const filtered = useMemo(() => rows.filter((item) => !query.trim() || `${String(item.title || '')} ${String(item.excerpt || item.preview || '')}`.toLowerCase().includes(query.trim().toLowerCase())), [query, rows])
  const openNewThread = () => {setEditorMode('new'); setEditorTarget(null); setTitle(''); setContent(''); setPreviewOpen(false); setComposerOpen(true)}
  const openThreadEditor = () => {if (!active) return; setEditorMode('edit-thread'); setEditorTarget(active); setTitle(String(active.title || '')); setContent(String(active.content || '')); setPreviewOpen(false); setComposerOpen(true)}
  const openReplyEditor = (item: JsonRecord) => {setEditorMode('edit-reply'); setEditorTarget(item); setTitle(''); setContent(String(item.content || '')); setPreviewOpen(false); setComposerOpen(true)}
  const closeEditor = () => {setComposerOpen(false); setPreviewOpen(false)}
  const submit = (event: FormEvent) => {event.preventDefault(); if (editorMode === 'edit-thread') editThread.mutate(); else if (editorMode === 'edit-reply') editReply.mutate(); else create.mutate()}
  if (list.isPending) return <LoadingState label="正在读取讨论区" />
  if (list.isError) return <ErrorState message={list.error.message} />
  return <div className={`forum-page${threadId ? ' is-mobile-detail-open' : ''}`} id="forumApp">
    <section className="forum-workspace" aria-label="讨论区工作台">
      <aside className="forum-list-pane"><div className="forum-pane-tools"><label className="forum-search"><i className="fas fa-search" /><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} autoComplete="off" aria-label="搜索讨论" placeholder="搜索公开讨论内容" /></label></div><div className="forum-filter-strip"><div className="forum-filter-tabs" role="tablist" aria-label="讨论筛选"><button className={`forum-chip${scope === 'all' ? ' is-active' : ''}`} type="button" role="tab" aria-selected={scope === 'all'} onClick={() => setScope('all')}>全部讨论</button><button className={`forum-chip${scope === 'mine' ? ' is-active' : ''}`} type="button" role="tab" aria-selected={scope === 'mine'} onClick={() => setScope('mine')}>我的讨论</button></div><button className="forum-new-thread-button" type="button" onClick={openNewThread}><i className="fas fa-plus" /><span>发起讨论</span></button></div>
        <div className="forum-thread-list" role="listbox" aria-label="讨论列表">{filtered.map((item) => {const id = String(item.id); const name = author(item); const activity = item.last_activity_at || item.updated_at || item.created_at; return <button type="button" className={`forum-thread-row${id === activeId ? ' is-selected' : ''}`} role="option" aria-selected={id === activeId} onClick={() => navigate(`/forum/${id}`)} key={id}><h3 className="forum-thread-title">{String(item.title || '无标题讨论')}</h3><span className="forum-thread-meta"><span className="forum-thread-identity"><ForumAvatar avatar={item.avatar} name={name} className="forum-identicon-xs" /><span className="forum-thread-author">{name}</span>{item.is_anonymous ? <span className="forum-anonymous-mark">匿名</span> : null}</span><span className="forum-thread-active-time" title={absoluteTime(activity)}>{relativeTime(activity)}</span><span className="forum-reply-count"><i className="far fa-comment" />{String(item.reply_count || 0)}</span></span></button>})}{!filtered.length ? <div className="forum-list-empty"><span className="forum-empty-mark"><i className="fas fa-magnifying-glass" /></span><strong>{query ? '没有匹配的讨论' : '讨论区还是空的'}</strong><p>{query ? '换个关键词后再试。' : '从一个具体问题开始，会更容易得到有用的回应。'}</p></div> : null}</div>
        <footer className="forum-list-footer"><div className="forum-identity-control"><ForumAvatar avatar={identity.data?.identity.posting_avatar} name={String(identity.data?.identity.posting_name || session?.user?.username || '')} className="forum-identicon-sm" /><span className="forum-identity-copy"><small>CURRENT IDENTITY</small><strong>{String(identity.data?.identity.posting_name || session?.user?.username || '')}</strong></span><label className="forum-switch-label" title="打开后使用匿名身份"><input type="checkbox" aria-label="匿名身份开关" checked={useAnonymous} disabled={identity.isPending || updateIdentity.isPending} onChange={(event) => updateIdentity.mutate(event.target.checked)} /><span className="forum-switch" aria-hidden="true" /><span>匿名</span></label><button className="forum-identity-refresh" type="button" title="更换匿名身份" aria-label="更换匿名身份" disabled={!useAnonymous || !(identity.data?.identity.can_change_anonymous === true || Number(identity.data?.identity.can_change_anonymous) === 1) || rotateIdentity.isPending} onClick={() => {setAliasName(''); setIdentityDialogOpen(true)}}><i className="fas fa-rotate" /></button></div></footer>
      </aside>
      <article className="forum-detail-pane" aria-live="polite"><header className="forum-detail-header"><button className="forum-icon-button forum-mobile-back" type="button" aria-label="返回讨论列表" onClick={() => navigate('/forum')}><i className="fas fa-arrow-left" /></button><div className="forum-detail-heading"><div className="forum-detail-kicker">{active ? `THREAD · F${String(active.id || activeId).padStart(4, '0')} · ${String(active.reply_count ?? replies.length)} REPLIES` : 'THREAD · SELECT'}</div><h2>{active ? String(active.title || '讨论') : '选择一条讨论开始阅读'}</h2></div><div className="forum-detail-actions">{active?.is_owner ? <button className="forum-button forum-button-quiet" type="button" onClick={openThreadEditor}><i className="fas fa-pen" />编辑主题</button> : null}<button className="forum-icon-button" type="button" aria-label="分享讨论" title="分享讨论" disabled={!active} onClick={() => void navigator.clipboard?.writeText(window.location.href)}><i className="fas fa-link" /></button></div></header>
        <div className="forum-conversation">{active ? <><Post item={active} kind="thread" /><div className="forum-reply-divider">{String(active.reply_count ?? replies.length)} REPLIES</div>{replies.length ? replies.map((item, index) => <Post item={item} kind="reply" onEdit={openReplyEditor} key={String(item.id || index)} />) : <div className="forum-detail-empty"><span className="forum-empty-mark"><i className="far fa-message" /></span><strong>还没有回复</strong><p>把你想到的关键线索写下来，成为第一个回应的人。</p></div>}</> : thread.isPending && activeId ? <div className="forum-detail-empty"><span className="math-curve-loader" data-math-curve-loader data-size="md"><span className="math-curve-loader__label">正在读取讨论</span></span></div> : <div className="forum-detail-empty"><span className="forum-empty-mark"><i className="far fa-comments" /></span><strong>讨论从左边开始</strong><p>选择主题后，正文、回复和编辑器都会在这里展开。</p></div>}</div>{active ? <form className="forum-reply-composer" onSubmit={(event) => {event.preventDefault(); if (replyContent.trim()) reply.mutate()}}><div className="forum-reply-surface"><label className="visually-hidden" htmlFor="forumReplyContent">写下回复</label><textarea id="forumReplyContent" rows={2} value={replyContent} onChange={(event) => setReplyContent(event.target.value)} placeholder="写下你的回复… 支持 Markdown、代码、LaTeX 与 Mermaid" /><div className="forum-reply-footer">{reply.isError ? <span className="forum-field-error me-auto">{errorMessage(reply.error)}</span> : null}<button className="forum-reply-send" type="submit" aria-label="发送回复" title="发送回复" disabled={reply.isPending || !identity.data?.identity.posting_token}><i className={`fas ${reply.isPending ? 'fa-spinner fa-spin' : 'fa-arrow-up'}`} /></button></div></div></form> : null}
      </article>
    </section>
    {composerOpen ? <dialog ref={composerRef} className="forum-dialog forum-editor-dialog" onCancel={(event) => {event.preventDefault(); closeEditor()}}><form onSubmit={submit} noValidate><header className="forum-dialog-header forum-editor-dialog-header"><div className="forum-dialog-heading"><span className="forum-dialog-kicker">{editorMode === 'new' ? 'NEW THREAD' : editorMode === 'edit-thread' ? `EDIT · F${String(editorTarget?.id || activeId).padStart(4, '0')}` : `EDIT REPLY · #${String(editorTarget?.id || '')}`}</span><h2>{editorMode === 'new' ? '发起讨论' : editorMode === 'edit-thread' ? '编辑主题' : '编辑回复'}</h2></div><div className="forum-editor-header-actions"><div className="forum-editor-posting-identity"><ForumAvatar avatar={editorMode === 'new' ? identity.data?.identity.posting_avatar : editorTarget?.avatar} name={editorMode === 'new' ? String(identity.data?.identity.posting_name || session?.user?.username || '') : author(editorTarget || {})} className="forum-identicon-sm" /><span className="forum-editor-posting-copy"><strong>{editorMode === 'new' ? String(identity.data?.identity.posting_name || session?.user?.username || '当前身份') : author(editorTarget || {})}</strong><small>{editorMode === 'new' ? '讨论将以当前身份发布' : '身份按首次发布时锁定'}</small></span></div><button className="forum-icon-button" type="button" onClick={closeEditor} aria-label="关闭编辑器"><i className="fas fa-xmark" /></button></div></header><div className="forum-dialog-body">{editorMode !== 'edit-reply' ? <div className="forum-field"><label htmlFor="forumTitle">标题</label><input id="forumTitle" value={title} onChange={(event) => setTitle(event.target.value)} maxLength={255} required autoFocus placeholder="今天讨论点什么呢……？" /></div> : null}<div className="forum-editor-tabs" role="tablist" aria-label="编辑与预览"><button className={previewOpen ? '' : 'is-active'} type="button" role="tab" aria-selected={!previewOpen} onClick={() => setPreviewOpen(false)}>编写</button><button className={previewOpen ? 'is-active' : ''} type="button" role="tab" aria-selected={previewOpen} onClick={() => {setPreviewOpen(true); preview.mutate()}}>预览</button></div>{previewOpen ? <div className="forum-editor-preview forum-markdown numoj-markdown">{preview.data?.rendered_content ? <MarkdownContent className="numoj-markdown" html={preview.data.rendered_content} /> : null}{preview.isPending ? <p className="forum-preview-placeholder">正在生成预览…</p> : null}</div> : <div className="forum-field forum-editor-write"><label className="visually-hidden" htmlFor="forumContent">正文</label><textarea id="forumContent" value={content} onChange={(event) => setContent(event.target.value)} rows={12} required autoFocus={editorMode === 'edit-reply'} placeholder="啊哒哒……啊哒哒……啊哒啊哒……喵喵喵喵喵！" /></div>}<p className="forum-field-error" role="alert">{create.isError || editThread.isError || editReply.isError || preview.isError || updateIdentity.isError || rotateIdentity.isError ? errorMessage(create.error || editThread.error || editReply.error || preview.error || updateIdentity.error || rotateIdentity.error) : ''}</p></div><footer className="forum-dialog-footer"><small>{editorMode === 'new' ? '' : `基于版本 ${String(editorTarget?.edit_version || 1)}`}</small><div className="forum-dialog-actions"><button className="forum-button" type="button" onClick={closeEditor}>取消</button><button className="forum-button forum-button-primary" type="submit" disabled={create.isPending || editThread.isPending || editReply.isPending || (editorMode === 'new' && !identity.data?.identity.posting_token)}>{editorMode === 'new' ? '发布讨论' : '保存修改'}</button></div></footer></form></dialog> : null}
    {identityDialogOpen ? <dialog ref={identityDialogRef} className="forum-dialog forum-identity-dialog" onCancel={(event) => {event.preventDefault(); setIdentityDialogOpen(false)}}><form noValidate onSubmit={(event) => {event.preventDefault(); if (aliasName.trim()) rotateIdentity.mutate(aliasName.trim())}}><header className="forum-dialog-header"><div><span className="forum-dialog-kicker">ANONYMOUS IDENTITY</span><h2>设置匿名身份</h2></div><button className="forum-icon-button" type="button" aria-label="关闭匿名身份设置" onClick={() => setIdentityDialogOpen(false)}><i className="fas fa-xmark" /></button></header><div className="forum-dialog-body"><div className="forum-editor-identity"><ForumAvatar name={aliasName || '等待输入'} className="forum-identicon-lg" /><span><strong>{aliasName || '等待输入'}</strong><small>匿名用户名决定这枚 8×8 头像</small></span></div><div className="forum-field"><label htmlFor="forumAlias"><span>匿名用户名</span><span className={`forum-char-count${aliasName.length > 10 ? ' is-invalid' : ''}`}>{aliasName.length} / 10</span></label><input id="forumAlias" value={aliasName} onChange={(event) => setAliasName(event.target.value.slice(0, 10))} autoComplete="off" placeholder="例如：收敛小浣熊" required autoFocus /></div><p className="forum-field-error" role="alert">{rotateIdentity.isError ? errorMessage(rotateIdentity.error) : ''}</p></div><footer className="forum-dialog-footer"><small>{String(identity.data?.identity.anonymous_cooldown_note || '首次设置不受冷却限制')}</small><div className="forum-dialog-actions"><button className="forum-button" type="button" onClick={() => setIdentityDialogOpen(false)}>取消</button><button className="forum-button forum-button-primary" type="submit" disabled={!aliasName.trim() || rotateIdentity.isPending}>保存并使用</button></div></footer></form></dialog> : null}
    <div className="forum-toast" id="forumToast" role="status" aria-live="polite" aria-atomic="true"><span className="forum-toast-mark" aria-hidden="true" /><span className="forum-toast-copy"><small id="forumToastEyebrow">FORUM · NOTICE</small><strong id="forumToastMessage" /></span></div>
  </div>
}
