import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useState, type FormEvent} from 'react'

import {apiFetch, errorMessage, queryString} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {Identicon} from '../components/Identicon'
import {ErrorState, LoadingState} from '../components/PageState'
import {useDismissibleDropdown} from '../components/useDismissibleDropdown'
import {useSession} from '../session'

interface UsersResponse extends ApiEnvelope {users: JsonRecord[]; total: number; classes: JsonRecord[]; page?: number; total_pages?: number; mail_service_configured?: boolean}

function formData(values: Record<string, string>) {const body = new FormData(); Object.entries(values).forEach(([key, value]) => body.append(key, value)); return body}

function ClassFilter({value, classes, onChange, placeholder = '全部班级', icon = 'fa-layer-group', ariaLabel = '筛选班级'}: {value: string; classes: JsonRecord[]; onChange: (value: string) => void; placeholder?: string; icon?: string; ariaLabel?: string}) {
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  const selected = classes.find((item) => String(item.class_en) === value)
  const options = [{class_en: '', class_cn: placeholder}, ...classes]
  return <div ref={rootRef} className={`rk-choice${open ? ' open' : ''}`}><input className="rk-choice-value" value={value} readOnly tabIndex={-1} aria-hidden="true" /><button type="button" className="rk-choice-trigger" role="combobox" aria-haspopup="listbox" aria-expanded={open} aria-label={ariaLabel} onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main"><i className={`fas ${icon}`} /><span>{String(selected?.class_cn || placeholder)}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox">{options.map((item) => {const optionValue = String(item.class_en || ''); return <button type="button" className={`rk-choice-option${optionValue === value ? ' active' : ''}`} role="option" aria-selected={optionValue === value} onClick={() => {onChange(optionValue); setOpen(false)}} key={optionValue || 'all'}><span className="rk-choice-option-main"><i className={`fas ${icon}`} /><span><span className="rk-choice-option-name">{String(item.class_cn || placeholder)}</span></span></span><i className="fas fa-check rk-choice-option-check" /></button>})}</div></div>
}

function UserManager({user, classes, mailReady, close, refresh}: {user: JsonRecord; classes: JsonRecord[]; mailReady: boolean; close: () => void; refresh: () => Promise<unknown>}) {
  const [username, setUsername] = useState(String(user.username || ''))
  const [email, setEmail] = useState(String(user.email || ''))
  const [classEn, setClassEn] = useState('')
  const [gradesOpen, setGradesOpen] = useState(false)
  const [roleConfirm, setRoleConfirm] = useState(false)
  const [resetConfirm, setResetConfirm] = useState(false)
  useEffect(() => {
    setUsername(String(user.username || ''))
    setEmail(String(user.email || ''))
  }, [user.email, user.username])
  const memberships = Array.isArray(user.classes) ? user.classes as JsonRecord[] : []
  const usernameMutation = useMutation({mutationFn: () => apiFetch<ApiEnvelope>('/api/admin/users/username', {method: 'POST', body: formData({user_id: String(user.id), new_username: username})}), onSuccess: refresh})
  const emailMutation = useMutation({mutationFn: () => apiFetch<ApiEnvelope>('/api/admin/users/email', {method: 'POST', body: formData({user_id: String(user.id), email})}), onSuccess: refresh})
  const roleMutation = useMutation({mutationFn: () => apiFetch<ApiEnvelope>('/api/admin/users/admin-role', {method: 'POST', body: formData({user_id: String(user.id)})}), onSuccess: async () => {setRoleConfirm(false); await refresh()}})
  const joinMutation = useMutation({mutationFn: () => apiFetch<ApiEnvelope>('/api/admin/class-memberships', {method: 'POST', body: formData({user_id: String(user.id), class_en: classEn})}), onSuccess: refresh})
  const leaveMutation = useMutation({mutationFn: (target: string) => apiFetch<ApiEnvelope>('/api/admin/class-memberships', {method: 'DELETE', body: formData({user_id: String(user.id), class_en: target})}), onSuccess: refresh})
  const resetMutation = useMutation({mutationFn: () => apiFetch<ApiEnvelope>('/api/admin/users/password-reset', {method: 'POST', body: formData({user_id: String(user.id)})}), onSuccess: () => setResetConfirm(false)})
  const mutationError = usernameMutation.error || emailMutation.error || roleMutation.error || joinMutation.error || leaveMutation.error || resetMutation.error
  const availableClasses = classes.filter((item) => !memberships.some((member) => member.class_en === item.class_en))
  return <><div className="modal fade show d-block user-admin-modal" role="dialog" aria-modal="true" aria-labelledby="manageUserModalLabel"><div className="modal-dialog modal-dialog-centered modal-dialog-scrollable modal-lg"><div className="modal-content"><span className="user-admin-modal-accent" aria-hidden="true" /><header className="modal-header"><div className="user-admin-modal-person"><Identicon seed={String(user.username || 'U')} className="user-admin-modal-avatar" /><div><span className="user-admin-kicker">ACCOUNT / <b>UID {String(Number(user.id || 0)).padStart(4, '0')}</b></span><h2 className="modal-title" id="manageUserModalLabel">{String(user.username || '')}</h2><p>{String(user.email || '未设置邮箱')}</p></div></div><button type="button" className="user-admin-modal-close" onClick={close} aria-label="关闭">×</button></header><div className="modal-body"><div className="user-admin-detail-grid">
    <section className="user-admin-detail-card"><header><span><i className="fas fa-address-card" /></span><div><p>PROFILE</p><h3>账户资料</h3></div></header><form className="user-admin-inline-form" onSubmit={(event) => {event.preventDefault(); usernameMutation.mutate()}}><label htmlFor="manageUsername">用户名</label><div className="user-admin-field-action"><input id="manageUsername" maxLength={50} required autoComplete="off" value={username} onChange={(event) => setUsername(event.target.value)} /><button type="submit" disabled={usernameMutation.isPending}>保存</button></div><p className="user-admin-form-message" aria-live="polite" /></form><form className="user-admin-inline-form" onSubmit={(event) => {event.preventDefault(); emailMutation.mutate()}}><label htmlFor="manageEmail">邮箱</label><div className="user-admin-field-action"><input id="manageEmail" type="email" maxLength={254} required autoComplete="off" value={email} onChange={(event) => setEmail(event.target.value)} /><button type="submit" disabled={emailMutation.isPending}>保存</button></div><p className="user-admin-form-message" aria-live="polite" /></form></section>
    <section className="user-admin-detail-card"><header><span><i className="fas fa-layer-group" /></span><div><p>MEMBERSHIP</p><h3>班级关系</h3></div><b>{memberships.length}</b></header><div className="user-admin-memberships">{memberships.length ? memberships.map((item) => <span className="user-admin-membership" key={String(item.class_en)}><span><strong>{String(item.class_cn || item.class_en)}</strong><small>{String(item.class_en)}</small></span><button type="button" aria-label={`从${String(item.class_cn || item.class_en)}移除该用户`} disabled={leaveMutation.isPending} onClick={() => leaveMutation.mutate(String(item.class_en))}>×</button></span>) : <p className="user-admin-membership-empty">尚未加入任何班级</p>}</div><div className="user-admin-membership-form"><ClassFilter value={classEn} classes={availableClasses} onChange={setClassEn} placeholder="选择要加入的班级" icon="fa-users" ariaLabel="选择要加入的班级" /><button type="button" className="user-admin-icon-action" aria-label="添加班级" title="添加班级" disabled={joinMutation.isPending} onClick={() => {if (classEn) joinMutation.mutate()}}><i className="fas fa-plus" /></button></div><p className="user-admin-form-message" aria-live="polite" /></section>
    <section className="user-admin-detail-card user-admin-detail-card-wide"><header><span><i className="fas fa-shield-alt" /></span><div><p>ACCESS &amp; SECURITY</p><h3>权限与安全</h3></div></header><div className="user-admin-security-list"><article><div><strong>账户身份</strong><p>{Number(user.is_admin) === 1 ? '教师账户拥有站点管理权限。' : '学生账户仅拥有常规学习权限。'}</p></div><span className={`user-admin-role${Number(user.is_admin) === 1 ? ' is-admin' : ''}`}><i />{Number(user.is_admin) === 1 ? '教师' : '学生'}</span>{Number(user.is_admin) !== 1 ? <button type="button" className="user-admin-text-action" disabled={roleMutation.isPending} onClick={() => setRoleConfirm(true)}>授予教师权限</button> : null}</article>{roleConfirm ? <div className="user-admin-confirm-row"><p><strong>确认授予教师权限？</strong>该操作不会在此页面提供撤销入口。</p><div><button type="button" className="user-admin-button user-admin-button-quiet" onClick={() => setRoleConfirm(false)}>取消</button><button type="button" className="user-admin-button user-admin-button-dark" disabled={roleMutation.isPending} onClick={() => roleMutation.mutate()}>确认授予</button></div></div> : null}<article><div><strong>重置登录密码</strong><p>{mailReady ? '生成随机密码，并仅发送至当前账户邮箱。' : '站点邮件服务未配置，暂时无法发送重置邮件。'}</p></div><span className={`user-admin-mail-state${mailReady ? '' : ' is-offline'}`}>{mailReady ? 'MAIL READY' : 'MAIL OFFLINE'}</span><button type="button" className="user-admin-text-action is-danger" disabled={!mailReady || resetMutation.isPending} onClick={() => setResetConfirm(true)}>发送重置邮件</button></article>{resetConfirm ? <div className="user-admin-confirm-row is-danger"><p><strong>确认重置密码？</strong>旧密码将立即失效，随机新密码会发送至 <span>{email}</span>。</p><div><button type="button" className="user-admin-button user-admin-button-quiet" onClick={() => setResetConfirm(false)}>取消</button><button type="button" className="user-admin-button user-admin-button-danger" disabled={resetMutation.isPending} onClick={() => resetMutation.mutate()}>生成并发送</button></div></div> : null}</div></section>
  </div>{mutationError ? <p className="user-admin-form-message is-error">{errorMessage(mutationError)}</p> : null}{resetMutation.isSuccess ? <p className="user-admin-form-message is-success">{resetMutation.data.message}</p> : null}</div><footer className="modal-footer"><button type="button" className="user-admin-button user-admin-button-quiet" onClick={() => setGradesOpen(true)}><i className="fas fa-chart-line" /> 成绩记录</button><button type="button" className="user-admin-button user-admin-button-dark" onClick={close}>完成</button></footer></div></div></div><div className="modal-backdrop fade show" />{gradesOpen ? <GradesDialog user={user} close={() => setGradesOpen(false)} /> : null}</>
}

function GradeRow({userId, grade}: {userId: number; grade: JsonRecord}) {
  const queryClient = useQueryClient()
  const [score, setScore] = useState(String(grade.user_score ?? ''))
  const [validationError, setValidationError] = useState('')
  const save = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>('/api/admin/user-grades', {method: 'POST', body: formData({user_id: String(userId), problem_id: String(grade.problem_id), score: score.trim()})}),
    onSuccess: async () => {await queryClient.invalidateQueries({queryKey: ['admin', 'user-grades', userId]})},
  })
  const submit = () => {
    const raw = score.trim()
    const maxScore = Number(grade.max_score || 0)
    if (raw && (!/^\d+$/.test(raw) || Number(raw) > maxScore)) {
      setValidationError(`成绩必须是 0 到 ${maxScore} 之间的整数，或留空清除`)
      return
    }
    setValidationError('')
    save.mutate()
  }
  const visibleError = validationError || (save.isError ? errorMessage(save.error) : '')
  return <tr><td><span className="user-admin-grade-copy"><strong>{String(grade.problem_title || '未命名题目')}</strong><small>P{String(grade.problem_id).padStart(4, '0')}</small></span></td><td><input className="user-admin-score-field" type="text" inputMode="numeric" value={score} aria-label={`${String(grade.problem_title || '未命名题目')}当前成绩`} aria-invalid={Boolean(visibleError)} aria-describedby={visibleError ? `grade-error-${String(grade.problem_id)}` : undefined} onChange={(event) => {setScore(event.target.value); if (validationError) setValidationError('')}} title={visibleError || undefined} />{visibleError ? <small className="user-admin-form-message is-error" id={`grade-error-${String(grade.problem_id)}`} role="alert">{visibleError}</small> : null}</td><td>{String(grade.max_score ?? '')}</td><td><button type="button" className="user-admin-grade-save" disabled={save.isPending} onClick={submit}>{save.isPending ? '保存中' : '保存'}</button></td></tr>
}

function GradesDialog({user, close}: {user: JsonRecord; close: () => void}) {
  const [search, setSearch] = useState('')
  const result = useQuery({queryKey: ['admin', 'user-grades', user.id], queryFn: () => apiFetch<ApiEnvelope & {grades: JsonRecord[]}>(`/api/admin/user-grades${queryString({user_id: user.id})}`)})
  const grades = (result.data?.grades || []).filter((item) => `${String(item.problem_id)} ${String(item.problem_title || '')}`.toLowerCase().includes(search.toLowerCase()))
  return <div className="modal fade show d-block user-admin-modal user-admin-grades-modal" role="dialog" aria-modal="true">
    <div className="modal-dialog modal-dialog-centered modal-dialog-scrollable modal-xl"><div className="modal-content"><span className="user-admin-modal-accent" />
      <header className="modal-header"><div><span className="user-admin-kicker">LEARNING / SCORE RECORDS</span><h2 className="modal-title">成绩记录 · {String(user.username || '')}</h2><p>直接编辑已产生的题目成绩；留空保存会清除该条成绩。</p></div><button type="button" className="user-admin-modal-close" onClick={close} aria-label="关闭">×</button></header>
      <div className="modal-body"><label className="user-admin-grade-search"><i className="fas fa-search" /><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索题号或题目标题" /></label>
        {result.isPending ? <div className="user-admin-loading">正在读取成绩</div> : result.isError ? <div className="user-admin-inline-state is-error" role="alert"><span>{result.error.message}</span><button type="button" className="user-admin-button user-admin-button-quiet" disabled={result.isFetching} onClick={() => void result.refetch()}>{result.isFetching ? '重试中…' : '重新加载'}</button></div> : <div className="user-admin-grades-table-wrap"><table className="user-admin-grades-table"><thead><tr><th>题目</th><th>当前成绩</th><th>满分</th><th>更新</th></tr></thead><tbody>{grades.length ? grades.map((item) => <GradeRow userId={Number(user.id)} grade={item} key={String(item.problem_id)} />) : <tr><td colSpan={4}><div className="user-admin-membership-empty">暂无匹配的成绩记录</div></td></tr>}</tbody></table></div>}
      </div>
      <footer className="modal-footer"><span>修改将立即写入成绩记录</span><button type="button" className="user-admin-button user-admin-button-dark" onClick={close}>完成</button></footer>
    </div></div>
  </div>
}

function CreateClassDialog({classEn, classCn, setClassEn, setClassCn, create, close}: {classEn: string; classCn: string; setClassEn: (value: string) => void; setClassCn: (value: string) => void; create: {mutate: () => void; isError: boolean; isPending: boolean; error: Error | null}; close: () => void}) {
  return <><div className="modal fade show d-block user-admin-modal" role="dialog" aria-modal="true" aria-labelledby="addClassModalLabel"><div className="modal-dialog modal-dialog-centered"><div className="modal-content"><span className="user-admin-modal-accent" aria-hidden="true" /><form onSubmit={(event) => {event.preventDefault(); create.mutate()}}><header className="modal-header"><div><span className="user-admin-kicker">DIRECTORY / CLASS</span><h2 className="modal-title" id="addClassModalLabel">新建班级</h2><p>创建一个新的班级类型，供用户加入与作业分配。</p></div><button type="button" className="user-admin-modal-close" onClick={close} aria-label="关闭">×</button></header><div className="modal-body user-admin-form-stack"><label className="user-admin-field"><span>英文标识 <small>自动添加 C 前缀</small></span><input value={classEn.replace(/^C/, '')} onChange={(event) => setClassEn(event.target.value)} maxLength={48} pattern="[A-Za-z0-9_]+" placeholder="例如 class2026" required /></label><label className="user-admin-field"><span>班级名称</span><input value={classCn} onChange={(event) => setClassCn(event.target.value)} maxLength={100} placeholder="例如 2026 春季班" required /></label>{create.isError ? <p className="user-admin-form-message is-error">{errorMessage(create.error)}</p> : <p className="user-admin-form-message" />}</div><footer className="modal-footer"><button type="button" className="user-admin-button user-admin-button-quiet" onClick={close}>取消</button><button type="submit" className="user-admin-button user-admin-button-dark" disabled={create.isPending}>创建班级</button></footer></form></div></div></div><div className="modal-backdrop fade show" /></>
}

export default function AdminPage() {
  const {session} = useSession()
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState('')
  const [query, setQuery] = useState('')
  const [draftClass, setDraftClass] = useState('')
  const [classFilter, setClassFilter] = useState('')
  const [page, setPage] = useState(1)
  const [selectedUser, setSelectedUser] = useState<JsonRecord | null>(null)
  const [classOpen, setClassOpen] = useState(false)
  const [classEn, setClassEn] = useState('')
  const [classCn, setClassCn] = useState('')
  const users = useQuery({queryKey: ['admin', 'users', query, classFilter, page], queryFn: () => apiFetch<UsersResponse>(`/api/admin/users${queryString({user_search: query, class: classFilter, page})}`), enabled: Boolean(session?.user?.is_admin)})
  const refresh = async () => {await queryClient.invalidateQueries({queryKey: ['admin', 'users']})}
  useEffect(() => {
    if (!selectedUser) return
    const latest = users.data?.users.find((item) => Number(item.id) === Number(selectedUser.id))
    if (latest && latest !== selectedUser) setSelectedUser(latest)
  }, [selectedUser, users.data?.users])
  const createClass = useMutation({mutationFn: () => apiFetch<ApiEnvelope>('/api/admin/classes', {method: 'POST', body: formData({class_en: classEn.replace(/^C/, ''), class_cn: classCn})}), onSuccess: async () => {setClassOpen(false); setClassEn(''); setClassCn(''); await refresh()}})
  const submit = (event: FormEvent) => {event.preventDefault(); setPage(1); setQuery(draft.trim()); setClassFilter(draftClass)}
  if (!session?.user?.is_admin) return <ErrorState message="该页面仅管理员可访问" />
  if (users.isPending) return <LoadingState label="正在读取用户目录" />
  if (users.isError) return <ErrorState message={users.error.message} retry={() => void users.refetch()} />
  return <section className="user-admin-v2" data-user-admin>
    <div className="user-admin-workspace">
      <form className="user-admin-toolbar" role="search" autoComplete="off" onSubmit={submit}><label className="user-admin-search"><i className="fas fa-search" /><input type="search" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="搜索用户名或邮箱" aria-label="搜索用户名或邮箱" autoComplete="off" />{draft ? <button type="button" className="user-admin-search-clear" aria-label="清除搜索" onClick={() => {setDraft(''); setQuery(''); setPage(1)}}>×</button> : null}</label><div className="user-admin-filter"><ClassFilter value={draftClass} classes={users.data?.classes || []} onChange={setDraftClass} /></div><button type="submit" className="user-admin-button user-admin-button-dark">应用筛选</button><button type="button" onClick={() => setClassOpen(true)} className="user-admin-button user-admin-button-dark"><i className="fas fa-plus" /><span>新建班级</span></button>{query || classFilter ? <button type="button" className="user-admin-button user-admin-button-quiet" onClick={() => {setDraft(''); setQuery(''); setDraftClass(''); setClassFilter(''); setPage(1)}}>重置</button> : null}<span className="user-admin-toolbar-meta">每页 50 位用户</span></form>
      <section className="user-admin-panel" aria-label="用户列表"><div className="user-admin-table-wrap"><table className="user-admin-table"><colgroup><col className="user-admin-col-user" /><col className="user-admin-col-email" /><col className="user-admin-col-class" /><col className="user-admin-col-action" /></colgroup><tbody>{(users.data?.users || []).map((user) => {
        const memberships = Array.isArray(user.classes) ? user.classes as JsonRecord[] : []
        return <tr key={String(user.id)} data-user-row data-user-id={String(user.id)}><td><div className="user-admin-identity"><Identicon seed={String(user.username || 'U')} className="user-admin-avatar" /><span className="user-admin-identity-copy"><span className="user-admin-name-line"><strong className="user-username">{String(user.username)}</strong>{Number(user.is_admin) === 1 ? <span className="user-admin-role user-role-badge is-admin"><i /><span>教师</span></span> : null}</span><small>UID · {String(Number(user.id || 0)).padStart(4, '0')}</small></span></div></td><td><span className={`user-admin-email${user.email ? '' : ' is-empty'}`}>{String(user.email || '未设置邮箱')}</span></td><td><div className="user-admin-class-summary">{memberships.slice(0, 3).map((item) => <span key={String(item.class_en)}>{String(item.class_cn)}</span>)}{memberships.length > 3 ? <span className="is-more">+{memberships.length - 3}</span> : !memberships.length ? <span className="is-empty">未分配</span> : null}</div></td><td><button className="user-admin-manage-button" type="button" onClick={() => setSelectedUser(user)}><span>管理</span><i className="fas fa-arrow-right" /></button></td></tr>
      })}{!users.data?.users?.length ? <tr><td colSpan={4}><div className="user-admin-empty"><span>00</span><strong>没有匹配的用户</strong><p>尝试调整搜索词或班级筛选。</p></div></td></tr> : null}</tbody></table></div>{Number(users.data?.total_pages || 1) > 1 ? <nav className="user-admin-pagination" aria-label="用户列表分页"><span>PAGE {Number(users.data?.page || page)} / {Number(users.data?.total_pages)}</span><div>{page > 1 ? <button type="button" aria-label="上一页" onClick={() => setPage((value) => value - 1)}><i className="fas fa-arrow-left" /></button> : null}{Array.from({length: Number(users.data?.total_pages)}, (_, index) => index + 1).map((pageNumber) => <button type="button" className={pageNumber === page ? 'is-current' : ''} aria-current={pageNumber === page ? 'page' : undefined} onClick={() => setPage(pageNumber)} key={pageNumber}>{pageNumber}</button>)}{page < Number(users.data?.total_pages) ? <button type="button" aria-label="下一页" onClick={() => setPage((value) => value + 1)}><i className="fas fa-arrow-right" /></button> : null}</div></nav> : null}</section>
    </div>{selectedUser ? <UserManager key={String(selectedUser.id)} user={selectedUser} classes={users.data?.classes || []} mailReady={Boolean(users.data?.mail_service_configured)} close={() => setSelectedUser(null)} refresh={refresh} /> : null}{classOpen ? <CreateClassDialog classEn={classEn} classCn={classCn} setClassEn={setClassEn} setClassCn={setClassCn} create={createClass} close={() => setClassOpen(false)} /> : null}
  </section>
}
