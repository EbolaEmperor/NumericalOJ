import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useMemo, useState, type FormEvent} from 'react'
import {useNavigate, useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface ListResponse extends ApiEnvelope {threads?: JsonRecord[]; items?: JsonRecord[]}
interface ThreadResponse extends ApiEnvelope {thread: JsonRecord; replies?: JsonRecord[]}

function author(item: JsonRecord) {return String(item.display_name || item.author_name || item.username || '未知用户')}
function html(item: JsonRecord) {return String(item.rendered_content || item.content_html || item.content || '')}

function Post({item, kind}: {item: JsonRecord; kind: string}) {
  const name = author(item)
  return <article className="forum-post" data-post-kind={kind}><span className="forum-identicon" aria-hidden="true">{name.slice(0, 2).toUpperCase()}</span><div className="forum-post-content"><header className="forum-post-head"><strong>{name}</strong>{item.is_anonymous ? <span className="forum-anonymous-mark">ANON</span> : null}<time className="forum-post-time" dateTime={String(item.created_at || '')}>{String(item.created_at || '')}</time></header><div className="forum-markdown numoj-markdown" dangerouslySetInnerHTML={{__html: html(item)}} /></div></article>
}

export default function ForumPage() {
  const {threadId} = useParams()
  const {session} = useSession()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [query, setQuery] = useState('')
  const [composerOpen, setComposerOpen] = useState(false)
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const list = useQuery({queryKey: ['forum'], queryFn: () => apiFetch<ListResponse>('/api/forum')})
  const rows = list.data?.threads || list.data?.items || []
  const activeId = threadId || (rows[0]?.id ? String(rows[0].id) : '')
  const thread = useQuery({queryKey: ['forum', activeId], queryFn: () => apiFetch<ThreadResponse>(`/api/forum/threads/${activeId}`), enabled: Boolean(activeId)})
  const create = useMutation({mutationFn: () => apiFetch<ApiEnvelope & {thread?: JsonRecord}>('/api/forum/threads', {method: 'POST', body: JSON.stringify({title, content, client_request_id: crypto.randomUUID()})}), onSuccess: async (data) => {await queryClient.invalidateQueries({queryKey: ['forum']}); setComposerOpen(false); const id = Number(data.thread?.id); if (id) navigate(`/app/forum/${id}`)}})
  const filtered = useMemo(() => rows.filter((item) => !query.trim() || `${String(item.title || '')} ${String(item.excerpt || item.preview || '')}`.toLowerCase().includes(query.trim().toLowerCase())), [query, rows])
  const submit = (event: FormEvent) => {event.preventDefault(); create.mutate()}
  if (list.isPending) return <LoadingState label="正在读取讨论区" />
  if (list.isError) return <ErrorState message={list.error.message} />
  const active = thread.data?.thread
  return <div className={`forum-page${threadId ? ' is-mobile-detail-open' : ''}`} id="forumApp">
    <section className="forum-workspace" aria-label="讨论区工作台">
      <aside className="forum-list-pane"><div className="forum-pane-tools"><label className="forum-search"><i className="fas fa-search" /><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} autoComplete="off" aria-label="搜索讨论" placeholder="搜索公开讨论内容" /></label></div><div className="forum-filter-strip"><div className="forum-filter-tabs" role="tablist"><button className="forum-chip is-active" type="button">全部讨论</button><button className="forum-chip" type="button">我的讨论</button></div><button className="forum-new-thread-button" type="button" onClick={() => setComposerOpen(true)}><i className="fas fa-plus" /><span>发起讨论</span></button></div>
        <div className="forum-thread-list" role="listbox" aria-label="讨论列表">{filtered.map((item) => {const id = String(item.id); const name = author(item); return <button type="button" className={`forum-thread-row${id === activeId ? ' is-selected' : ''}`} role="option" aria-selected={id === activeId} onClick={() => navigate(`/app/forum/${id}`)} key={id}><h3 className="forum-thread-title">{String(item.title || '无标题讨论')}</h3><span className="forum-thread-meta"><span className="forum-thread-identity"><span className="forum-identicon forum-identicon-xs" aria-hidden="true">{name.slice(0, 2).toUpperCase()}</span><span className="forum-thread-author">{name}</span>{item.is_anonymous ? <span className="forum-anonymous-mark">匿名</span> : null}</span><span className="forum-thread-active-time">{String(item.last_activity_at || item.updated_at || item.created_at || '')}</span><span className="forum-reply-count"><i className="far fa-comment" />{String(item.reply_count || 0)}</span></span></button>})}{!filtered.length ? <div className="forum-list-empty"><span className="forum-empty-mark"><i className="fas fa-magnifying-glass" /></span><strong>{query ? '没有匹配的讨论' : '讨论区还是空的'}</strong><p>{query ? '换个关键词后再试。' : '从一个具体问题开始，会更容易得到有用的回应。'}</p></div> : null}</div>
        <footer className="forum-list-footer"><div className="forum-identity-control"><span className="forum-identicon forum-identicon-sm" aria-hidden="true">{session?.user?.username.slice(0, 2).toUpperCase()}</span><span className="forum-identity-copy"><small>CURRENT IDENTITY</small><strong>{session?.user?.username}</strong></span><label className="forum-switch-label"><input type="checkbox" aria-label="匿名身份开关" /><span className="forum-switch" aria-hidden="true" /><span>匿名</span></label><button className="forum-identity-refresh" type="button" title="更换匿名身份"><i className="fas fa-rotate" /></button></div></footer>
      </aside>
      <article className="forum-detail-pane" aria-live="polite"><header className="forum-detail-header"><button className="forum-icon-button forum-mobile-back" type="button" aria-label="返回讨论列表" onClick={() => navigate('/app/forum')}><i className="fas fa-arrow-left" /></button><div className="forum-detail-heading"><div className="forum-detail-kicker">{active ? `THREAD · F${String(active.id || activeId).padStart(4, '0')}` : 'THREAD · SELECT'}</div><h2>{active ? String(active.title || '讨论') : '选择一条讨论开始阅读'}</h2></div><div className="forum-detail-actions"><button className="forum-icon-button" type="button" aria-label="分享讨论" title="分享讨论" disabled={!active} onClick={() => void navigator.clipboard?.writeText(window.location.href)}><i className="fas fa-link" /></button></div></header>
        <div className="forum-conversation">{active ? <><Post item={active} kind="thread" />{(thread.data?.replies || []).map((reply, index) => <Post item={reply} kind="reply" key={String(reply.id || index)} />)}</> : thread.isPending && activeId ? <div className="forum-detail-empty"><span className="math-curve-loader" data-math-curve-loader data-size="md"><span className="math-curve-loader__label">正在读取讨论</span></span></div> : <div className="forum-detail-empty"><span className="forum-empty-mark"><i className="far fa-comments" /></span><strong>讨论从左边开始</strong><p>选择主题后，正文、回复和编辑器都会在这里展开。</p></div>}</div>
      </article>
    </section>
    {composerOpen ? <dialog className="forum-dialog forum-editor-dialog" open><form onSubmit={submit}><header className="forum-dialog-header forum-editor-dialog-header"><div className="forum-dialog-heading"><span className="forum-dialog-kicker">NEW THREAD</span><h2>发起讨论</h2></div><button className="forum-icon-button" type="button" onClick={() => setComposerOpen(false)} aria-label="关闭编辑器"><i className="fas fa-xmark" /></button></header><div className="forum-dialog-body"><div className="forum-field"><label htmlFor="forumTitle">标题</label><input id="forumTitle" value={title} onChange={(event) => setTitle(event.target.value)} maxLength={255} placeholder="今天讨论点什么呢……？" /></div><div className="forum-editor-tabs"><button className="is-active" type="button">编写</button><button type="button">预览</button></div><div className="forum-field forum-editor-write"><textarea value={content} onChange={(event) => setContent(event.target.value)} rows={12} placeholder="啊哒哒……啊哒哒……啊哒啊哒……喵喵喵喵喵！" /></div>{create.isError ? <p className="forum-field-error">{errorMessage(create.error)}</p> : null}</div><footer className="forum-dialog-footer"><small /><div className="forum-dialog-actions"><button className="forum-button" type="button" onClick={() => setComposerOpen(false)}>取消</button><button className="forum-button forum-button-primary" type="submit" disabled={create.isPending}>发布讨论</button></div></footer></form></dialog> : null}
  </div>
}
