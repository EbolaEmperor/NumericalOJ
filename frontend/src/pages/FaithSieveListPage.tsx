import {useQuery} from '@tanstack/react-query'
import {useEffect, useState, type FormEvent} from 'react'
import {useSearchParams} from 'react-router-dom'

import {apiFetch, queryString} from '../api/client'
import {Link, useNavigate} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {ExecutionModeIdentity} from '../components/ExecutionModeLogo'
import {FaithSieveHarness, FaithSieveModel} from '../components/FaithSieveRuntimeIdentity'
import {FaithSieveCost} from '../components/FaithSieveCost'
import {ListUsername} from '../components/ListUsername'
import {useSession} from '../session'
import {faithSieveDetailQueryKey, faithSieveIsActive, faithSieveListQueryKey, faithSieveStatusLabel, faithSieveVerdictClass, faithSieveScore, faithSieveExecutionMode, faithSieveRunDetailUrl, faithSieveStageState, type FaithSieveDetailResponse, type FaithSieveListResponse, type FaithSieveRun, type FaithSieveStage} from './faithsieveTypes'
import './faithsieve.css'
import './faithsieve-list.css'

const statuses = ['', 'queued', 'running', 'completed', 'failed', 'inconclusive']

function Verdict({status}: {status: string}) {
  return <span className={`submission-verdict submission-verdict--${faithSieveVerdictClass(status)}`}><span className="submission-verdict__dot" aria-hidden="true" /><span>{faithSieveStatusLabel(status)}</span></span>
}

function ResultIcon({failed = false}: {failed?: boolean}) {
  return <span className={`submission-result-status${failed ? ' is-failed' : ''}`} role="img" aria-label={failed ? '失败' : '无结论'}><i className={`fas ${failed ? 'fa-xmark' : 'fa-minus'}`} aria-hidden="true" /></span>
}

function ListResult({run}: {run: FaithSieveRun}) {
  if (faithSieveIsActive(run.status)) return <MathCurveLoader size="sm" iconOnly ariaLabel={faithSieveStatusLabel(run.status)} />
  if (run.status === 'failed' || run.status === 'endpoint_error') return <ResultIcon failed />
  if (run.status === 'inconclusive' || run.result?.verdict === 'inconclusive') return <ResultIcon />
  const score = run.status === 'completed' ? faithSieveScore(run.result) : null
  if (score == null) return <span className="submission-result-status">{faithSieveStatusLabel(run.status)}</span>
  return <span className="submission-row-result" aria-label={`得分 ${score} / 5`}>
    <span className={`submission-score${score === 0 ? ' is-zero' : run.result?.verdict === 'correct' ? ' is-accepted' : ''}`}>{score}</span>
    <span className="submission-score-max">/5</span>
  </span>
}

function stageResult(stage: FaithSieveStage, runStatus: string) {
  const state = faithSieveStageState(stage, runStatus)
  if (state !== 'completed') return faithSieveStatusLabel(state)
  if (stage.parameters?.node_id && stage.status === 'refuted') return '推理被反驳'
  return ({ok: '已完成', passed: '验证通过', refuted: '反驳成立', inconclusive: '无结论', needs_revision: '需要修订', failed: '失败'} as Record<string, string>)[stage.status || ''] || '已完成'
}

function useDesktopLayout() {
  const query = '(min-width: 1200px)'
  const [desktop, setDesktop] = useState(() => typeof window.matchMedia === 'function' && window.matchMedia(query).matches)
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return
    const media = window.matchMedia(query)
    const update = () => setDesktop(media.matches)
    update()
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])
  return desktop
}

function Preview({run}: {run?: FaithSieveRun}) {
  const query = useQuery({queryKey: faithSieveDetailQueryKey(run?.attempt_id), queryFn: ({signal}) => apiFetch<FaithSieveDetailResponse>(`/api/admin/faithsieve/${run?.attempt_id}`, {signal}), enabled: Boolean(run), refetchInterval: (query) => !query.state.error && faithSieveIsActive(query.state.data?.run.status) ? 2_500 : false})
  if (!run) return <aside className="submission-detail-panel" aria-label="Faith Sieve 预览"><div className="submission-detail-empty"><strong>暂无任务记录</strong></div></aside>
  if (query.isPending) return <aside className="submission-detail-panel" aria-label="Faith Sieve 预览"><div className="submission-detail-loading"><MathCurveLoader size="md" label="正在加载任务详情…" /></div></aside>
  if (query.isError) return <aside className="submission-detail-panel" aria-label="Faith Sieve 预览"><ErrorState message={query.error.message} retry={() => void query.refetch()} /></aside>
  const data = query.data
  const stages = data.workflow.stages || []
  const active = stages.find((stage) => stage.state === 'pending') || stages.at(-1)
  const final = data.result || data.run.result
  const score = faithSieveScore(final)
  const executionMode = faithSieveExecutionMode(data.run)
  const judgeSession = active?.session_id || data.run.session_id
  const url = faithSieveRunDetailUrl({...data.run, session_id: data.run.session_id || judgeSession})
  const owner = data.submission?.username || data.run.username || run.username || '—'
  const submittedAt = data.submission?.created_at || data.run.submission_created_at || run.submission_created_at
  const triggeredAt = data.run.created_at || run.created_at
  return <aside className="submission-detail-panel faithsieve-list-preview" aria-label="Faith Sieve 预览"><article className="submission-detail-content">
    <div className="faithsieve-preview-heading"><h2 className="submission-detail-title">{data.problem?.title || run.problem_title || '题目已删除'}</h2><FaithSieveCost cost={data.run.cost} /></div>
    <div className="faithsieve-preview-source">{data.submission ? <Link to={data.submission.detail_url || `/submissions/${run.submission_id}`}>{owner} · 提交 #{run.submission_id}</Link> : <span>原提交已删除</span>}</div>
    <div className="faithsieve-preview-result"><Verdict status={data.run.status} />{score != null ? <span className="faithsieve-preview-score"><strong>{score}</strong><span>/5</span></span> : null}{final?.verdict === 'correct' ? <span>证明成立</span> : final?.verdict === 'incorrect' ? <span>证明存在问题</span> : null}</div>
    <div className="faithsieve-preview-runtime" aria-label="执行配置"><ExecutionModeIdentity mode={executionMode} /><FaithSieveHarness harness={data.run.runtime?.harness} /><FaithSieveModel model={data.run.runtime?.model} /></div>
    <dl className="faithsieve-preview-times" aria-label="提交与评测时间">
      <div><dt>提交时间</dt><dd>{submittedAt ? <time dateTime={submittedAt.replace(' ', 'T')}>{submittedAt.replace('T', ' ')}</time> : '—'}</dd></div>
      <div><dt>评测触发时间</dt><dd>{triggeredAt ? <time dateTime={triggeredAt.replace(' ', 'T')}>{triggeredAt.replace('T', ' ')}</time> : '—'}</dd></div>
    </dl>
    {active || (executionMode === 'skill' && judgeSession) || (data.run.status === 'failed' && data.run.message) ? <section className="faithsieve-preview-progress">{active ? <div className="faithsieve-preview-stage" aria-label="阶段摘要"><span>{active.label}</span><span>{stageResult(active, data.run.status)}</span></div> : null}{executionMode === 'skill' && judgeSession ? <Link className="faithsieve-preview-session" to={`/agents/${encodeURIComponent(judgeSession)}`}>Judge 会话<i className="fas fa-arrow-up-right-from-square" aria-hidden="true" /></Link> : null}{data.run.status === 'failed' && data.run.message ? <p className="faithsieve-preview-message">{data.run.message}</p> : null}</section> : null}
    <div className="faithsieve-preview-actions">{url ? <Link className="faithsieve-preview-detail-link" to={url}>{executionMode === 'skill' ? '查看 Agent 会话' : '查看完整详情'}<i className="fas fa-arrow-up-right-from-square" aria-hidden="true" /></Link> : <span className="submission-result-status">会话尚未创建</span>}</div>
  </article></aside>
}

export default function FaithSieveListPage() {
  const {session, loading} = useSession()
  const isAdmin = Boolean(session?.user?.is_admin)
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const desktop = useDesktopLayout()
  const [selectedId, setSelectedId] = useState<number>()
  const pageValue = Number(params.get('page') || 1)
  const page = Number.isSafeInteger(pageValue) && pageValue > 0 ? pageValue : 1
  const username = params.get('username') || ''
  const problemId = params.get('problem_id') || ''
  const submissionId = params.get('submission_id') || ''
  const status = params.get('status') || ''
  const [draft, setDraft] = useState({username, problemId, submissionId})
  useEffect(() => {setDraft({username, problemId, submissionId})}, [username, problemId, submissionId])
  useEffect(() => {document.title = 'Faith Sieve - Numerical OJ'}, [])
  const search = queryString({page, username, problem_id: problemId, submission_id: submissionId, status})
  const result = useQuery({
    queryKey: faithSieveListQueryKey(search),
    queryFn: ({signal}) => apiFetch<FaithSieveListResponse>(`/api/admin/faithsieve${search}`, {signal}),
    enabled: isAdmin,
    refetchInterval: (query) => !query.state.error && query.state.data?.runs.some((run) => faithSieveIsActive(run.status)) ? 2_500 : false,
  })
  const href = (changes: {page?: number; status?: string} = {}) => `/admin/faithsieve${queryString({username, problem_id: problemId, submission_id: submissionId, status, ...changes})}`
  const rows = result.data?.runs || []
  const rowIds = rows.map((run) => run.id).join(',')
  useEffect(() => {setSelectedId((current) => current && rows.some((run) => run.id === current) ? current : rows[0]?.id)}, [rowIds])
  const apply = (event: FormEvent) => {event.preventDefault(); navigate(`/admin/faithsieve${queryString({username: draft.username.trim(), problem_id: draft.problemId.trim(), submission_id: draft.submissionId.trim(), status})}`)}
  if (loading) return <LoadingState />
  if (!isAdmin) return <ErrorState message="该页面仅管理员可访问" />
  if (result.isPending) return <LoadingState label="正在读取 Faith Sieve" />
  if (result.isError) return <ErrorState message={result.error.message} retry={() => void result.refetch()} />
  const data = result.data
  const currentPage = data.page
  const pages = data.page_numbers || Array.from({length: Math.max(0, Math.min(data.total_pages, currentPage + 3) - Math.max(1, currentPage - 3) + 1)}, (_, index) => Math.max(1, currentPage - 3) + index)
  return <div className="submission-page faithsieve-page">
    <header className="submission-page-header faithsieve-heading"><h1>Faith Sieve</h1></header>
    <section className="submission-filter-panel" aria-label="Faith Sieve 筛选">
      <form className="submission-filter-form" onSubmit={apply}>
        <label className="submission-search-field"><i className="fas fa-magnifying-glass" aria-hidden="true" /><span className="visually-hidden">学生</span><input type="search" aria-label="学生" value={draft.username} maxLength={50} placeholder="学生" autoComplete="off" onChange={(event) => setDraft({...draft, username: event.target.value})} /></label>
        <label className="submission-problem-filter"><i className="fas fa-book-open" aria-hidden="true" /><span className="visually-hidden">题目号</span><input type="text" aria-label="题目号" inputMode="numeric" pattern="[0-9]*" value={draft.problemId} placeholder="题目号" autoComplete="off" onChange={(event) => setDraft({...draft, problemId: event.target.value})} /></label>
        <label className="submission-problem-filter"><i className="fas fa-hashtag" aria-hidden="true" /><span className="visually-hidden">提交号</span><input type="text" aria-label="提交号" inputMode="numeric" pattern="[0-9]*" value={draft.submissionId} placeholder="提交号" autoComplete="off" onChange={(event) => setDraft({...draft, submissionId: event.target.value})} /></label>
        <button type="submit" className="submission-button submission-button--ghost">应用筛选</button>
        {username || problemId || submissionId || status ? <Link className="submission-filter-clear" to="/admin/faithsieve">清除</Link> : null}
      </form>
      <nav className="submission-status-filters" aria-label="任务状态筛选">{statuses.map((value) => <Link className={`submission-status-chip${status === value ? ' is-active' : ''}`} to={href({status: value})} aria-current={status === value ? 'true' : undefined} key={value || 'all'}>{value ? faithSieveStatusLabel(value) : '全部'}</Link>)}</nav>
    </section>
    {data.total_pages > 1 ? <nav className="submission-pagination" aria-label="Faith Sieve 分页"><div className="submission-pagination__links">{currentPage > 1 ? <Link className="submission-page-link submission-page-link--wide" to={href({page: currentPage - 1})} rel="prev">上一页</Link> : null}{pages.map((number) => <Link className={`submission-page-link${currentPage === number ? ' is-active' : ''}`} to={href({page: number})} aria-current={currentPage === number ? 'page' : undefined} key={number}>{number}</Link>)}{currentPage < data.total_pages ? <Link className="submission-page-link submission-page-link--wide" to={href({page: currentPage + 1})} rel="next">下一页</Link> : null}</div></nav> : null}
    <section className="submission-master-detail">
      <div className="submission-table-panel"><div className="submission-table-scroll"><table className="submission-data-table" aria-label="Faith Sieve 任务"><colgroup><col className="submission-col-result" /><col className="submission-col-mode" /><col className="submission-col-problem" /><col className="submission-col-tests" /><col className="submission-col-user" /><col className="submission-col-action" /></colgroup><thead className="visually-hidden"><tr><th scope="col" className="submission-col-result">结果</th><th scope="col" className="submission-col-mode">模式</th><th scope="col" className="submission-col-problem">题目</th><th scope="col" className="submission-col-tests">Harness 与模型</th><th scope="col" className="submission-col-user">学生</th><th scope="col" className="submission-col-action">操作</th></tr></thead><tbody>{data.runs.map((run) => {
        const url = faithSieveRunDetailUrl(run)
        const select = () => {if (desktop) setSelectedId(run.id); else if (url) navigate(url)}
        return <tr className={`submission-data-row${selectedId === run.id ? ' is-selected' : ''}`} tabIndex={0} aria-label={`Faith Sieve #${run.id}，${faithSieveStatusLabel(run.status)}`} aria-selected={selectedId === run.id} onClick={(event) => {if (!(event.target instanceof Element) || !event.target.closest('a, button, input, textarea')) select()}} onKeyDown={(event) => {if ((event.key === 'Enter' || event.key === ' ') && (!(event.target instanceof Element) || !event.target.closest('a, button, input, textarea'))) {event.preventDefault(); select()}}} key={run.id}>
          <td className="submission-col-result"><ListResult run={run} /></td><td className="submission-col-mode"><ExecutionModeIdentity mode={faithSieveExecutionMode(run)} /></td>
          <td className="submission-col-problem"><Link className="submission-problem-title" to={`/problems/${run.problem_id}`}>{run.problem_title || `P${run.problem_id}`}</Link><span className="submission-problem-id">P{String(run.problem_id).padStart(4, '0')}</span></td>
          <td className="submission-col-tests"><span className="faithsieve-runtime faithsieve-list-runtime"><FaithSieveHarness harness={run.runtime?.harness} iconOnly /><FaithSieveModel model={run.runtime?.model} /></span></td><td className="submission-col-user"><ListUsername username={run.username} /></td><td className="submission-col-action">{url ? <Link className="submission-detail-link" to={url} title={faithSieveExecutionMode(run) === 'skill' ? 'Agent 会话' : '完整详情'} aria-label={`打开 Faith Sieve #${run.id} 的完整详情`}><i className="fas fa-arrow-up-right-from-square" aria-hidden="true" /></Link> : <button type="button" className="submission-detail-link" disabled title="会话尚未创建" aria-label={`Faith Sieve #${run.id} 的会话尚未创建`}><i className="fas fa-arrow-up-right-from-square" aria-hidden="true" /></button>}</td>
        </tr>
      })}{!data.runs.length ? <tr><td colSpan={6}><div className="submission-empty-state"><strong>没有任务记录</strong></div></td></tr> : null}</tbody></table></div></div>
      {desktop ? <Preview run={data.runs.find((run) => run.id === selectedId)} /> : <aside className="submission-detail-panel" aria-hidden="true" />}
    </section>
  </div>
}
