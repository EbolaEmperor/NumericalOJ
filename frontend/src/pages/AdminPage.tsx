import {useQuery} from '@tanstack/react-query'
import {useState, type FormEvent} from 'react'

import {apiFetch, queryString} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface UsersResponse extends ApiEnvelope {users: JsonRecord[]; total: number; classes: JsonRecord[]; page?: number; total_pages?: number}

export default function AdminPage() {
  const {session} = useSession()
  const [draft, setDraft] = useState('')
  const [query, setQuery] = useState('')
  const users = useQuery({queryKey: ['admin', 'users', query], queryFn: () => apiFetch<UsersResponse>(`/api/admin/users${queryString({username: query})}`), enabled: Boolean(session?.user?.is_admin)})
  const submit = (event: FormEvent) => {event.preventDefault(); setQuery(draft.trim())}
  if (!session?.user?.is_admin) return <ErrorState message="该页面仅管理员可访问" />
  if (users.isPending) return <LoadingState label="正在读取用户目录" />
  if (users.isError) return <ErrorState message={users.error.message} />
  return <section className="user-admin-v2" data-user-admin>
    <div className="user-admin-workspace">
      <form className="user-admin-toolbar" role="search" autoComplete="off" onSubmit={submit}><label className="user-admin-search"><i className="fas fa-search" /><input type="search" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="搜索用户名或邮箱" aria-label="搜索用户名或邮箱" autoComplete="off" />{draft ? <button type="button" className="user-admin-search-clear" aria-label="清除搜索" onClick={() => {setDraft(''); setQuery('')}}>×</button> : null}</label><button type="submit" className="user-admin-button user-admin-button-dark">应用筛选</button><a href="/admin/users" className="user-admin-button user-admin-button-dark"><i className="fas fa-plus" /><span>新建班级</span></a>{query ? <button type="button" className="user-admin-button user-admin-button-quiet" onClick={() => {setDraft(''); setQuery('')}}>重置</button> : null}<span className="user-admin-toolbar-meta">每页 50 位用户</span></form>
      <section className="user-admin-panel" aria-label="用户列表"><div className="user-admin-table-wrap"><table className="user-admin-table"><colgroup><col className="user-admin-col-user" /><col className="user-admin-col-email" /><col className="user-admin-col-class" /><col className="user-admin-col-action" /></colgroup><tbody>{(users.data?.users || []).map((user) => {
        const memberships = Array.isArray(user.classes) ? user.classes as JsonRecord[] : []
        return <tr key={String(user.id)} data-user-row data-user-id={String(user.id)}><td><div className="user-admin-identity"><span className="numoj-avatar user-admin-avatar" aria-hidden="true">{String(user.username || 'U').slice(0, 2).toUpperCase()}</span><span className="user-admin-identity-copy"><span className="user-admin-name-line"><strong className="user-username">{String(user.username)}</strong>{Number(user.is_admin) === 1 ? <span className="user-admin-role user-role-badge is-admin"><i /><span>教师</span></span> : null}</span><small>UID · {String(Number(user.id || 0)).padStart(4, '0')}</small></span></div></td><td><span className={`user-admin-email${user.email ? '' : ' is-empty'}`}>{String(user.email || '未设置邮箱')}</span></td><td><div className="user-admin-class-summary">{memberships.slice(0, 3).map((item) => <span key={String(item.class_en)}>{String(item.class_cn)}</span>)}{memberships.length > 3 ? <span className="is-more">+{memberships.length - 3}</span> : !memberships.length ? <span className="is-empty">未分配</span> : null}</div></td><td><a className="user-admin-manage-button" href={`/admin/users?user_search=${encodeURIComponent(String(user.username || ''))}`}><span>管理</span><i className="fas fa-arrow-right" /></a></td></tr>
      })}{!users.data?.users?.length ? <tr><td colSpan={4}><div className="user-admin-empty"><span>00</span><strong>没有匹配的用户</strong><p>尝试调整搜索词或班级筛选。</p></div></td></tr> : null}</tbody></table></div></section>
    </div>
  </section>
}
