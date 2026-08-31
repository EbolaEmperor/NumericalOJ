import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useRef, useState, type FormEvent} from 'react'
import {Link, useNavigate, useSearchParams} from 'react-router-dom'

import {apiFetch, queryString} from '../api/client'
import type {ApiEnvelope, JsonRecord, SubmissionSummary} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface ProblemOption extends JsonRecord {problem_id: number; filter_label: string}
interface Response extends ApiEnvelope {submissions: SubmissionSummary[]; page: number; total_pages: number; page_numbers?: number[]; scope: string; problem_options?: ProblemOption[]; current_problem_label?: string}
interface PanelResponse extends ApiEnvelope {submission: JsonRecord; problem: JsonRecord; test_points: JsonRecord[]; detail_url: string; rejudge_url?: string}
interface RejudgeRangeResponse extends ApiEnvelope {preview?: boolean; too_many?: boolean; max_total?: number; total?: number; min_created_at?: string; max_created_at?: string; progress?: number; done?: number}

const statusOptions = [
  ['', '全部'], ['accepted', 'Accepted'], ['wrong_answer', 'Wrong Answer'], ['unaccepted', 'Unaccepted'],
  ['compile_error', 'Compile Error'], ['output_limit', 'Output Limit Exceeded'], ['in_progress', '运行中'], ['other', '其他'],
]

function verdictClass(status: unknown) {
  return String(status || 'Unknown').toLowerCase().replaceAll(' ', '-')
}

function legacyTimestamp(value: unknown) {
  const text = String(value || '')
  const match = text.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/)
  if (!match) return text || '—'
  return new Date(Date.UTC(
    Number(match[1]), Number(match[2]) - 1, Number(match[3]),
    Number(match[4]), Number(match[5]), Number(match[6]),
  )).toUTCString()
}

function Verdict({status}: {status: unknown}) {
  return <span className={`submission-verdict submission-verdict--${verdictClass(status)}`}><span className="submission-verdict__dot" aria-hidden="true" /><span>{String(status || 'Unknown')}</span></span>
}

function TestSpark({points}: {points: unknown}) {
  if (!Array.isArray(points) || !points.length) return <span className="submission-test-spark__empty" aria-label="暂无测试点">—</span>
  return <span className="submission-test-spark" aria-label={`共 ${points.length} 个测试点`} title={`共 ${points.length} 个测试点`}>{points.slice(0, 18).map((raw, index) => {
    const item = raw && typeof raw === 'object' ? raw as JsonRecord : {}
    const status = String(item.status || 'Unknown')
    const kind = status === 'Accepted' ? 'accepted' : ['Pending', 'Waiting', 'Running', 'Generating'].includes(status) ? 'active' : status === 'Wrong Answer' ? 'wrong-answer' : status === 'Runtime Error' ? 'runtime-error' : status === 'Time Limit Exceeded' ? 'time-limit' : status === 'Unknown' ? 'neutral' : 'other-failure'
    return <span className={`submission-test-spark__bar is-${kind}`} aria-hidden="true" key={index} />
  })}{points.length > 18 ? <span className="submission-test-spark__more">+{points.length - 18}</span> : null}</span>
}

function Panel({id, isAdmin}: {id?: number; isAdmin: boolean}) {
  const result = useQuery({queryKey: ['submission-panel', id], queryFn: () => apiFetch<PanelResponse>(`/api/submissions/${id}?view=panel`), enabled: Boolean(id)})
  const rejudge = useMutation({mutationFn: () => apiFetch<ApiEnvelope>(`/api/submissions/${id}/rejudge`, {method: 'POST'}), onSuccess: () => void result.refetch()})
  if (!id) return <aside className="submission-detail-panel" aria-label="提交详情预览"><div className="submission-detail-empty"><span className="submission-detail-empty__mark" aria-hidden="true"><i className="fas fa-arrow-pointer" /></span><strong>选择一条提交</strong><span>点击左侧记录后，在这里查看判题摘要。</span></div></aside>
  if (result.isPending) return <aside className="submission-detail-panel" aria-label="提交详情预览"><div className="submission-detail-loading"><span className="math-curve-loader" data-math-curve-loader data-size="md"><span className="math-curve-loader__label">正在加载提交详情…</span></span></div></aside>
  if (result.isError) return <aside className="submission-detail-panel" aria-label="提交详情预览"><div className="submission-detail-error"><span className="submission-detail-error__mark" aria-hidden="true"><i className="fas fa-triangle-exclamation" /></span><strong>详情加载失败</strong><span>{result.error.message}</span><button type="button" className="submission-button submission-button--ghost" onClick={() => void result.refetch()}><i className="fas fa-rotate-right" /> 重试</button></div></aside>
  const data = result.data!
  const submission = data.submission || {}
  const problem = data.problem || {}
  return <aside className="submission-detail-panel" aria-label="提交详情预览" aria-live="polite"><article className="submission-detail-content">
    <header className="submission-detail-header"><span className="submission-detail-id">#{String(submission.id)}</span><Link className="submission-icon-button" to={`/submissions/${String(submission.id)}`} title="打开完整详情"><i className="fas fa-arrow-up-right-from-square" /><span className="visually-hidden">打开完整详情</span></Link></header>
    <h2 className="submission-detail-title">{String(submission.problem_title || problem.title || '未命名题目')}</h2>
    <div className="submission-detail-verdict"><Verdict status={submission.status} /></div>
    <div className="submission-detail-score"><strong>{String(submission.score ?? '—')}</strong><span>/{String(problem.max_score ?? '—')}</span></div>
    <dl className="submission-detail-meta"><dt>题目号</dt><dd>P{String(Number(submission.problem_id || problem.id || 0)).padStart(4, '0')}</dd><dt>语言</dt><dd>{String(problem.lang || '—').toUpperCase()}</dd><dt>提交者</dt><dd>{String(submission.username || '—')}</dd><dt>提交时间</dt><dd>{legacyTimestamp(submission.created_at)}</dd></dl>
    <section className="submission-detail-section"><div className="submission-detail-section__heading"><h3>用例结果</h3><span>{data.test_points.length} 个</span></div><div className="submission-test-matrix">{data.test_points.map((point, index) => <span className={`submission-test-dot submission-test-dot--${verdictClass(point.status)}`} title={`${String(point.test_index || index + 1)} · ${String(point.status || 'Unknown')}`} key={index} />)}</div><div className="submission-test-summary"><span>{data.test_points.length ? `共 ${data.test_points.length} 个测试点` : '暂无测试点结果。'}</span></div></section>
    <div className="submission-detail-actions"><Link className="submission-button submission-button--dark" to={`/submissions/${String(submission.id)}`}><i className="fas fa-code" /> 查看完整详情</Link>{isAdmin ? <button type="button" className="submission-button submission-button--accent" disabled={rejudge.isPending} onClick={() => {if (window.confirm('确认重测这条提交吗？')) rejudge.mutate()}}><i className="fas fa-rotate-right" /> {rejudge.isPending ? '重测中…' : '重测此提交'}</button> : null}</div>{rejudge.isSuccess ? <div className="submission-action-feedback is-success">已加入重测队列</div> : null}{rejudge.isError ? <div className="submission-action-feedback is-error">重测失败：{rejudge.error.message}</div> : null}
  </article></aside>
}

function bootstrapModal(element: HTMLElement | null) {
  const runtime = (window as unknown as {bootstrap?: {Modal?: {getOrCreateInstance?: (node: HTMLElement) => {show(): void; hide(): void}; getInstance?: (node: HTMLElement) => {show(): void; hide(): void} | null; new(node: HTMLElement): {show(): void; hide(): void}}}}).bootstrap
  if (!element || !runtime?.Modal) return null
  if (runtime.Modal.getOrCreateInstance) return runtime.Modal.getOrCreateInstance(element)
  return runtime.Modal.getInstance?.(element) || new runtime.Modal(element)
}

function TimeRangeRejudge() {
  const formModal = useRef<HTMLDivElement>(null)
  const progressModal = useRef<HTMLDivElement>(null)
  const [start, setStart] = useState('')
  const [end, setEnd] = useState('')
  const [progressActive, setProgressActive] = useState(false)
  const [progressTotal, setProgressTotal] = useState(0)
  const request = useMutation({mutationFn: (body: {start: string; end: string; confirm_total?: number}) => apiFetch<RejudgeRangeResponse>('/api/admin/rejudge-ranges', {method: 'POST', body: JSON.stringify(body)})})
  const progress = useQuery({queryKey: ['admin', 'rejudge-ranges', 'status'], queryFn: () => apiFetch<RejudgeRangeResponse>('/api/admin/rejudge-ranges/status'), enabled: progressActive, refetchInterval: progressActive ? 1500 : false})
  const percent = Number(progress.data?.progress || 0)
  const done = Number(progress.data?.done || 0)
  const total = Number(progress.data?.total || progressTotal || 0)
  useEffect(() => {if (progressActive && percent >= 100) setProgressActive(false)}, [percent, progressActive])

  const submit = async () => {
    if (!start || !end) {window.alert('请选择起始时间和结束时间'); return}
    if (start > end) {window.alert('起始时间不能晚于结束时间'); return}
    try {
      const preview = await request.mutateAsync({start, end})
      if (!preview.preview) return
      if (preview.too_many) throw new Error(`该时间范围命中 ${preview.total} 条提交，超过单次上限 ${preview.max_total} 条。`)
      const confirmed = window.confirm(`该时间范围将重测 ${preview.total} 条提交。\n实际命中时间：${preview.min_created_at} ~ ${preview.max_created_at}\n\n确认开始重测吗？`)
      if (!confirmed) return
      const result = await request.mutateAsync({start, end, confirm_total: Number(preview.total)})
      setProgressTotal(Number(result.total || 0))
      setProgressActive(true)
      bootstrapModal(formModal.current)?.hide()
      bootstrapModal(progressModal.current)?.show()
    } catch (error) {
      window.alert(`重测失败：${error instanceof Error ? error.message : '请稍后重试'}`)
    }
  }

  return <>
    <button type="button" className="submission-button submission-button--dark" onClick={() => bootstrapModal(formModal.current)?.show()}><i className="fas fa-rotate-right" aria-hidden="true" /> 按时间范围重测</button>
    <div className="modal fade" id="timeRangeRejudgeModal" tabIndex={-1} aria-labelledby="timeRangeRejudgeLabel" aria-hidden="true" ref={formModal}><div className="modal-dialog"><div className="modal-content"><div className="modal-header"><h2 className="modal-title fs-5" id="timeRangeRejudgeLabel"><i className="fas fa-rotate-right me-2" aria-hidden="true" />按时间范围重测</h2><button type="button" className="btn-close" aria-label="关闭" onClick={() => bootstrapModal(formModal.current)?.hide()} /></div><div className="modal-body"><div className="mb-3"><label htmlFor="rejudgeStartTime" className="form-label">起始时间</label><input type="datetime-local" className="form-control" id="rejudgeStartTime" value={start} onChange={(event) => setStart(event.target.value)} /></div><div><label htmlFor="rejudgeEndTime" className="form-label">结束时间</label><input type="datetime-local" className="form-control" id="rejudgeEndTime" value={end} onChange={(event) => setEnd(event.target.value)} /></div></div><div className="modal-footer"><button type="button" className="submission-button submission-button--ghost" onClick={() => bootstrapModal(formModal.current)?.hide()}>取消</button><button type="button" className="submission-button submission-button--accent" id="btnStartTimeRangeRejudge" disabled={request.isPending} onClick={() => void submit()}><i className="fas fa-play" aria-hidden="true" /> 开始重测</button></div></div></div></div>
    <div className="modal fade" id="timeRangeRejudgeProgressModal" tabIndex={-1} aria-labelledby="timeRangeRejudgeProgressLabel" aria-hidden="true" ref={progressModal}><div className="modal-dialog"><div className="modal-content"><div className="modal-header"><h2 className="modal-title fs-5" id="timeRangeRejudgeProgressLabel">重测进度</h2><button type="button" className="btn-close" aria-label="关闭" onClick={() => bootstrapModal(progressModal.current)?.hide()} /></div><div className="modal-body"><div className="progress mb-2"><div className="progress-bar" role="progressbar" id="timeRangeRejudgeProgressBar" style={{width: `${percent}%`}} aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>{percent}%</div></div><p className="small text-muted mb-0" id="timeRangeRejudgeProgressDetail">{progressActive || progress.data ? `已完成 ${done} / ${total}` : '尚未开始'}</p></div><div className="modal-footer"><button type="button" className="submission-button submission-button--ghost" onClick={() => bootstrapModal(progressModal.current)?.hide()}>关闭</button></div></div></div></div>
  </>
}

export default function SubmissionsPage() {
  const {session} = useSession()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const page = Number(params.get('page') || 1)
  const q = params.get('q') || ''
  const status = params.get('status') || ''
  const problemId = params.get('problem_id') || ''
  const [draft, setDraft] = useState(q)
  const [problemDraft, setProblemDraft] = useState('')
  const problemInput = useRef<HTMLInputElement>(null)
  const [selected, setSelected] = useState<number | null>(null)
  const result = useQuery({queryKey: ['submissions', page, q, status, problemId], queryFn: () => apiFetch<Response>(`/api/submissions${queryString({page, q, status, problem_id: problemId, per_page: 30})}`)})
  useEffect(() => {setProblemDraft(result.data?.current_problem_label || '')}, [problemId, result.data?.current_problem_label])
  const search = (event: FormEvent) => {
    event.preventDefault()
    const option = (result.data?.problem_options || []).find((item) => item.filter_label === problemDraft.trim())
    if (problemDraft.trim() && !option) {
      problemInput.current?.setCustomValidity('请从题目建议列表中选择，或清空该筛选。'); problemInput.current?.reportValidity(); return
    }
    problemInput.current?.setCustomValidity('')
    navigate(`/submissions${queryString({q: draft, status, problem_id: option?.problem_id || undefined})}`)
  }
  if (result.isPending) return <LoadingState label="正在同步提交记录" />
  if (result.isError) return <ErrorState message={result.error.message} retry={() => void result.refetch()} />
  const rows = result.data?.submissions || []
  const selectedId = selected && rows.some((row) => row.id === selected) ? selected : rows[0]?.id
  const pages = Array.from({length: Math.max(0, Math.min(result.data?.total_pages || 1, page + 3) - Math.max(1, page - 3) + 1)}, (_, index) => Math.max(1, page - 3) + index)
  return <div className="submission-page" data-submission-page>
    <header className="submission-page-header"><h1>SUBMISSIONS · LIST</h1></header>
    <section className="submission-filter-panel" aria-label="提交记录筛选">
      <form className="submission-filter-form" onSubmit={search}>
        <label className="submission-search-field"><i className="fas fa-magnifying-glass" aria-hidden="true" /><span className="visually-hidden">搜索提交记录</span><input type="search" value={draft} onChange={(event) => setDraft(event.target.value)} maxLength={120} autoComplete="off" placeholder={session?.user?.is_admin ? '搜索提交号、题目、提交者…' : '搜索提交号、题目…'} /></label>
        <label className="submission-problem-filter"><i className="fas fa-book-open" aria-hidden="true" /><span className="visually-hidden">按题目筛选</span><input type="search" value={problemDraft} list="submissionProblemOptions" autoComplete="off" placeholder="全部题目" ref={problemInput} onChange={(event) => {setProblemDraft(event.target.value); event.target.setCustomValidity('')}} /></label>
        <datalist id="submissionProblemOptions">{(result.data?.problem_options || []).map((option) => <option value={option.filter_label} data-problem-id={option.problem_id} key={option.problem_id} />)}</datalist>
        <button type="submit" className="submission-button submission-button--ghost">应用筛选</button>
        {session?.user?.is_admin ? <TimeRangeRejudge /> : null}
        {q || status || problemId ? <Link className="submission-filter-clear" to="/submissions"><i className="fas fa-xmark" /> 清除</Link> : null}
      </form>
      <div className="submission-status-filters" aria-label="按状态筛选"><span className="submission-filter-label">Status</span>{statusOptions.map(([value, label]) => <Link className={`submission-status-chip${status === value ? ' is-active' : ''}`} to={`/submissions${queryString({q, status: value, problem_id: problemId})}`} aria-current={status === value ? 'true' : undefined} key={value || 'all'}>{label}</Link>)}</div>
    </section>
    {(result.data?.total_pages || 1) > 1 ? <nav className="submission-pagination" aria-label="提交记录分页"><div className="submission-pagination__links">{page > 1 ? <Link className="submission-page-link submission-page-link--wide" to={`/submissions${queryString({page: page - 1, q, status})}`} rel="prev"><i className="fas fa-arrow-left" /> 上一页</Link> : null}{pages.map((value) => <Link className={`submission-page-link${value === page ? ' is-active' : ''}`} to={`/submissions${queryString({page: value, q, status})}`} aria-current={value === page ? 'page' : undefined} key={value}>{value}</Link>)}{page < (result.data?.total_pages || 1) ? <Link className="submission-page-link submission-page-link--wide" to={`/submissions${queryString({page: page + 1, q, status})}`} rel="next">下一页 <i className="fas fa-arrow-right" /></Link> : null}</div></nav> : null}
    <section className="submission-master-detail">
      <div className="submission-table-panel"><div className="submission-table-scroll"><table className="submission-data-table"><thead><tr><th className="submission-col-id">提交号</th><th className="submission-col-status">状态</th><th className="submission-col-score">得分</th><th className="submission-col-problem">题目</th><th className="submission-col-tests">用例</th><th className="submission-col-language">语言</th>{session?.user?.is_admin ? <th className="submission-col-user">提交者</th> : null}<th className="submission-col-time">提交时间</th><th className="submission-col-action"><span className="visually-hidden">操作</span></th></tr></thead><tbody>
        {rows.map((row) => {const created = String(row.created_at || ''); const parts = created.split(/[ T]/); return <tr className={`submission-data-row${row.id === selectedId ? ' is-selected' : ''}`} tabIndex={0} aria-label={`提交 #${row.id}，${row.status}`} aria-selected={row.id === selectedId} onClick={() => setSelected(row.id)} onKeyDown={(event) => {if (event.key === 'Enter' || event.key === ' ') setSelected(row.id)}} key={row.id}><td className="submission-col-id"><Link className="submission-id-link" to={`/submissions/${row.id}`}>#{row.id}</Link></td><td className="submission-col-status"><Verdict status={row.status} /></td><td className="submission-col-score"><span className={`submission-score${row.status === 'Accepted' ? ' is-accepted' : !row.score ? ' is-zero' : ''}`}>{row.score ?? '—'}</span>{row.display_max_score ? <> <span className="submission-score-max">/{String(row.display_max_score)}</span></> : null}</td><td className="submission-col-problem"><span className="submission-problem-title">{row.display_problem_title || row.problem_title || '未命名题目'}</span><span className="submission-problem-id">P{String(row.problem_id).padStart(4, '0')}</span></td><td className="submission-col-tests"><TestSpark points={row.test_points} /></td><td className="submission-col-language"><span className="submission-language">{String(row.display_language || '—')}</span></td>{session?.user?.is_admin ? <td className="submission-col-user">{row.username}</td> : null}<td className="submission-col-time"><time dateTime={created}><span>{parts[0] || '—'}</span><span>{parts[1]?.slice(0, 8) || ''}</span></time></td><td className="submission-col-action"><Link className="submission-detail-link" to={`/submissions/${row.id}`} title="完整详情"><i className="fas fa-arrow-up-right-from-square" /></Link></td></tr>})}
        {!rows.length ? <tr><td colSpan={session?.user?.is_admin ? 9 : 8}><div className="submission-empty-state"><span className="submission-empty-state__icon"><i className="fas fa-inbox" /></span><strong>没有找到提交记录</strong><span>调整搜索或筛选条件后再试。</span></div></td></tr> : null}
      </tbody></table></div></div>
      <Panel id={selectedId} isAdmin={Boolean(session?.user?.is_admin)} />
    </section>
  </div>
}
