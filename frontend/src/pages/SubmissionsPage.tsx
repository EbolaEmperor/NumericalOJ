import {useQuery} from '@tanstack/react-query'
import {useState, type FormEvent} from 'react'
import {Link, useNavigate, useSearchParams} from 'react-router-dom'

import {apiFetch, queryString} from '../api/client'
import type {ApiEnvelope, JsonRecord, SubmissionSummary} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface Response extends ApiEnvelope {submissions: SubmissionSummary[]; page: number; total_pages: number; page_numbers?: number[]; scope: string}
interface PanelResponse extends ApiEnvelope {submission: JsonRecord; problem: JsonRecord; test_points: JsonRecord[]; detail_url: string; rejudge_url?: string}

const statusOptions = [
  ['', '全部'], ['accepted', 'Accepted'], ['wrong_answer', 'Wrong Answer'], ['unaccepted', 'Unaccepted'],
  ['compile_error', 'Compile Error'], ['output_limit', 'Output Limit Exceeded'], ['in_progress', '运行中'], ['other', '其他'],
]

function verdictClass(status: unknown) {
  return String(status || 'Unknown').toLowerCase().replaceAll(' ', '-')
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
  if (!id) return <aside className="submission-detail-panel" aria-label="提交详情预览"><div className="submission-detail-empty"><span className="submission-detail-empty__mark" aria-hidden="true"><i className="fas fa-arrow-pointer" /></span><strong>选择一条提交</strong><span>点击左侧记录后，在这里查看判题摘要。</span></div></aside>
  if (result.isPending) return <aside className="submission-detail-panel" aria-label="提交详情预览"><div className="submission-detail-loading"><span className="math-curve-loader" data-math-curve-loader data-size="md"><span className="math-curve-loader__label">正在加载提交详情…</span></span></div></aside>
  if (result.isError) return <aside className="submission-detail-panel" aria-label="提交详情预览"><div className="submission-detail-error"><span className="submission-detail-error__mark" aria-hidden="true"><i className="fas fa-triangle-exclamation" /></span><strong>详情加载失败</strong><span>{result.error.message}</span><button type="button" className="submission-button submission-button--ghost" onClick={() => void result.refetch()}><i className="fas fa-rotate-right" /> 重试</button></div></aside>
  const data = result.data!
  const submission = data.submission || {}
  const problem = data.problem || {}
  return <aside className="submission-detail-panel" aria-label="提交详情预览" aria-live="polite"><article className="submission-detail-content">
    <header className="submission-detail-header"><span className="submission-detail-id">#{String(submission.id)}</span><Link className="submission-icon-button" to={`/app/submissions/${String(submission.id)}`} title="打开完整详情"><i className="fas fa-arrow-up-right-from-square" /><span className="visually-hidden">打开完整详情</span></Link></header>
    <h2 className="submission-detail-title">{String(submission.problem_title || problem.title || '未命名题目')}</h2>
    <div className="submission-detail-verdict"><Verdict status={submission.status} /></div>
    <div className="submission-detail-score"><strong>{String(submission.score ?? '—')}</strong><span>/{String(problem.max_score ?? '—')}</span></div>
    <dl className="submission-detail-meta"><dt>题目号</dt><dd>P{String(Number(submission.problem_id || problem.id || 0)).padStart(4, '0')}</dd><dt>语言</dt><dd>{String(problem.lang || '—').toUpperCase()}</dd><dt>提交者</dt><dd>{String(submission.username || '—')}</dd><dt>提交时间</dt><dd>{String(submission.created_at || '—')}</dd></dl>
    <section className="submission-detail-section"><div className="submission-detail-section__heading"><h3>用例结果</h3><span>{data.test_points.length} 个</span></div><div className="submission-test-matrix">{data.test_points.map((point, index) => <span className={`submission-test-dot submission-test-dot--${verdictClass(point.status)}`} title={`${String(point.test_index || index + 1)} · ${String(point.status || 'Unknown')}`} key={index} />)}</div><div className="submission-test-summary"><span>{data.test_points.length ? `共 ${data.test_points.length} 个测试点` : '暂无测试点结果。'}</span></div></section>
    <div className="submission-detail-actions"><Link className="submission-button submission-button--dark" to={`/app/submissions/${String(submission.id)}`}><i className="fas fa-code" /> 查看完整详情</Link>{isAdmin && data.rejudge_url ? <a className="submission-button submission-button--accent" href={data.rejudge_url}><i className="fas fa-rotate-right" /> 重测此提交</a> : null}</div>
  </article></aside>
}

export default function SubmissionsPage() {
  const {session} = useSession()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const page = Number(params.get('page') || 1)
  const q = params.get('q') || ''
  const status = params.get('status') || ''
  const [draft, setDraft] = useState(q)
  const [selected, setSelected] = useState<number | null>(null)
  const result = useQuery({queryKey: ['submissions', page, q, status], queryFn: () => apiFetch<Response>(`/api/submissions${queryString({page, q, status, per_page: 20})}`)})
  const search = (event: FormEvent) => {event.preventDefault(); navigate(`/app/submissions${queryString({q: draft, status})}`)}
  if (result.isPending) return <LoadingState label="正在同步提交记录" />
  if (result.isError) return <ErrorState message={result.error.message} retry={() => void result.refetch()} />
  const rows = result.data?.submissions || []
  const selectedId = selected && rows.some((row) => row.id === selected) ? selected : rows[0]?.id
  const pages = result.data?.page_numbers || Array.from({length: Math.min(result.data?.total_pages || 1, 7)}, (_, index) => index + 1)
  return <div className="submission-page" data-submission-page>
    <header className="submission-page-header"><h1>SUBMISSIONS · LIST</h1></header>
    <section className="submission-filter-panel" aria-label="提交记录筛选">
      <form className="submission-filter-form" onSubmit={search}>
        <label className="submission-search-field"><i className="fas fa-magnifying-glass" aria-hidden="true" /><span className="visually-hidden">搜索提交记录</span><input type="search" value={draft} onChange={(event) => setDraft(event.target.value)} maxLength={120} autoComplete="off" placeholder={session?.user?.is_admin ? '搜索提交号、题目、提交者…' : '搜索提交号、题目…'} /></label>
        <button type="submit" className="submission-button submission-button--ghost">应用筛选</button>
        {q || status ? <Link className="submission-filter-clear" to="/app/submissions"><i className="fas fa-xmark" /> 清除</Link> : null}
      </form>
      <div className="submission-status-filters" aria-label="按状态筛选"><span className="submission-filter-label">Status</span>{statusOptions.map(([value, label]) => <Link className={`submission-status-chip${status === value ? ' is-active' : ''}`} to={`/app/submissions${queryString({q, status: value})}`} aria-current={status === value ? 'true' : undefined} key={value || 'all'}>{label}</Link>)}</div>
    </section>
    {(result.data?.total_pages || 1) > 1 ? <nav className="submission-pagination" aria-label="提交记录分页"><div className="submission-pagination__links">{page > 1 ? <Link className="submission-page-link submission-page-link--wide" to={`/app/submissions${queryString({page: page - 1, q, status})}`} rel="prev"><i className="fas fa-arrow-left" /> 上一页</Link> : null}{pages.map((value) => <Link className={`submission-page-link${value === page ? ' is-active' : ''}`} to={`/app/submissions${queryString({page: value, q, status})}`} aria-current={value === page ? 'page' : undefined} key={value}>{value}</Link>)}{page < (result.data?.total_pages || 1) ? <Link className="submission-page-link submission-page-link--wide" to={`/app/submissions${queryString({page: page + 1, q, status})}`} rel="next">下一页 <i className="fas fa-arrow-right" /></Link> : null}</div></nav> : null}
    <section className="submission-master-detail">
      <div className="submission-table-panel"><div className="submission-table-scroll"><table className="submission-data-table"><thead><tr><th className="submission-col-id">提交号</th><th className="submission-col-status">状态</th><th className="submission-col-score">得分</th><th className="submission-col-problem">题目</th><th className="submission-col-tests">用例</th><th className="submission-col-language">语言</th>{session?.user?.is_admin ? <th className="submission-col-user">提交者</th> : null}<th className="submission-col-time">提交时间</th><th className="submission-col-action"><span className="visually-hidden">操作</span></th></tr></thead><tbody>
        {rows.map((row) => {const created = String(row.created_at || ''); const parts = created.split(/[ T]/); return <tr className={`submission-data-row${row.id === selectedId ? ' is-selected' : ''}`} tabIndex={0} aria-label={`提交 #${row.id}，${row.status}`} aria-selected={row.id === selectedId} onClick={() => setSelected(row.id)} onKeyDown={(event) => {if (event.key === 'Enter' || event.key === ' ') setSelected(row.id)}} key={row.id}><td className="submission-col-id"><Link className="submission-id-link" to={`/app/submissions/${row.id}`}>#{row.id}</Link></td><td className="submission-col-status"><Verdict status={row.status} /></td><td className="submission-col-score"><span className={`submission-score${row.status === 'Accepted' ? ' is-accepted' : !row.score ? ' is-zero' : ''}`}>{row.score ?? '—'}</span>{row.display_max_score ? <span className="submission-score-max">/{String(row.display_max_score)}</span> : null}</td><td className="submission-col-problem"><span className="submission-problem-title">{row.display_problem_title || row.problem_title || '未命名题目'}</span><span className="submission-problem-id">P{String(row.problem_id).padStart(4, '0')}</span></td><td className="submission-col-tests"><TestSpark points={row.test_points} /></td><td className="submission-col-language"><span className="submission-language">{String(row.display_language || '—')}</span></td>{session?.user?.is_admin ? <td className="submission-col-user">{row.username}</td> : null}<td className="submission-col-time"><time dateTime={created}><span>{parts[0] || '—'}</span><span>{parts[1]?.slice(0, 8) || ''}</span></time></td><td className="submission-col-action"><Link className="submission-detail-link" to={`/app/submissions/${row.id}`} title="完整详情"><i className="fas fa-arrow-up-right-from-square" /></Link></td></tr>})}
        {!rows.length ? <tr><td colSpan={session?.user?.is_admin ? 9 : 8}><div className="submission-empty-state"><span className="submission-empty-state__icon"><i className="fas fa-inbox" /></span><strong>没有找到提交记录</strong><span>调整搜索或筛选条件后再试。</span></div></td></tr> : null}
      </tbody></table></div></div>
      <Panel id={selectedId} isAdmin={Boolean(session?.user?.is_admin)} />
    </section>
  </div>
}
