import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useState} from 'react'
import {Link, useParams, useSearchParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface DashboardResponse extends ApiEnvelope {summary: JsonRecord; classes: JsonRecord[]; problems: JsonRecord[]; endpoints: JsonRecord[]}
interface PreviewResponse extends ApiEnvelope {total: number; samples: JsonRecord[]}
interface TasksResponse extends ApiEnvelope {tasks: JsonRecord[]}
interface ProblemDetailResponse extends ApiEnvelope {problem: JsonRecord; results: JsonRecord[]; risk_filter?: string; endpoints: JsonRecord[]}
interface StudentDetailResponse extends ApiEnvelope {username: string; results: JsonRecord[]; endpoints: JsonRecord[]}

function numberText(value: unknown) {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric.toFixed(2) : '0.00'
}

function stringList(value: unknown) {
  return Array.isArray(value) ? value.map((item) => String(item)) : []
}

function displayServerDateTime(value: unknown) {
  const text = String(value || '')
  const httpDate = text.match(/^[A-Za-z]{3},\s+(\d{2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}:\d{2}:\d{2})/)
  if (httpDate) {
    const month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'].indexOf(httpDate[2]) + 1
    return `${httpDate[3]}-${String(month).padStart(2, '0')}-${httpDate[1]} ${httpDate[4]}`
  }
  return text.replace('T', ' ').replace(/Z$/, '').slice(0, 19)
}

function ChoiceSelect({value, options, placeholder, icon, ariaLabel, onChange}: {value: string; options: Array<{value: string; label: string}>; placeholder: string; icon: string; ariaLabel: string; onChange: (value: string) => void}) {
  const [open, setOpen] = useState(false)
  const selected = options.find((item) => item.value === value)
  const choices = [{value: '', label: placeholder}, ...options]
  return <div className={`rk-choice${open ? ' open' : ''}`}><input className="rk-choice-value" value={value} readOnly tabIndex={-1} aria-hidden="true" /><button type="button" className="rk-choice-trigger" role="combobox" aria-haspopup="listbox" aria-expanded={open} aria-label={ariaLabel} onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main"><i className={`fas ${icon}`} /><span>{selected?.label || placeholder}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox">{choices.map((item) => <button type="button" className={`rk-choice-option${item.value === value ? ' active' : ''}`} role="option" aria-selected={item.value === value} key={item.value || 'none'} onClick={() => {onChange(item.value); setOpen(false)}}><span className="rk-choice-option-main"><i className={`fas ${icon}`} /><span className="rk-choice-option-name">{item.label}</span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div></div>
}

function EndpointSelect({value, endpoints, onChange}: {value: string; endpoints: JsonRecord[]; onChange: (value: string) => void}) {
  return <div className="detection-endpoint-field"><label className="form-label form-label-sm">本次检测端点</label><ChoiceSelect value={value} options={endpoints.map((item) => ({value: String(item.id), label: String(item.model || item.name || `端点 #${item.id}`)}))} placeholder="选择检测端点" icon="fa-minus-circle" ariaLabel="本次 AI 检测端点" onChange={onChange} /></div>
}

function runWithEndpoint(endpointId: string, action: () => void) {
  if (!endpointId) {
    window.alert('请先选择本次 AI 检测使用的全局端点')
    return
  }
  action()
}

export default function AiDetectionPage() {
  const {session} = useSession()
  const {detectionProblemId, detectionUsername} = useParams()
  const [searchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const detailMode = Boolean(detectionProblemId || detectionUsername)
  const dashboard = useQuery({queryKey: ['admin', 'ai-detection', 'dashboard'], queryFn: () => apiFetch<DashboardResponse>('/api/admin/ai-detection/dashboard'), enabled: Boolean(session?.user?.is_admin) && !detailMode})
  const tasks = useQuery({queryKey: ['admin', 'ai-detection', 'tasks'], queryFn: () => apiFetch<TasksResponse>('/api/admin/ai-detection/tasks'), enabled: Boolean(session?.user?.is_admin) && !detailMode, refetchInterval: 5000})
  const problemDetail = useQuery({queryKey: ['admin', 'ai-detection', 'problem', detectionProblemId, searchParams.get('risk')], queryFn: () => apiFetch<ProblemDetailResponse>(`/api/admin/ai-detection/problems/${detectionProblemId}${searchParams.get('risk') ? `?risk=${encodeURIComponent(searchParams.get('risk') || '')}` : ''}`), enabled: Boolean(session?.user?.is_admin && detectionProblemId)})
  const studentDetail = useQuery({queryKey: ['admin', 'ai-detection', 'student', detectionUsername], queryFn: () => apiFetch<StudentDetailResponse>(`/api/admin/ai-detection/students/${encodeURIComponent(detectionUsername || '')}`), enabled: Boolean(session?.user?.is_admin && detectionUsername)})
  const [filters, setFilters] = useState<Record<string, string>>({deduplicate: '1'})
  const [detailEndpoint, setDetailEndpoint] = useState('')
  const [previewData, setPreviewData] = useState<PreviewResponse | null>(null)
  const set = (key: string, value: string) => setFilters((current) => ({...current, [key]: value}))
  const preview = useMutation({mutationFn: () => apiFetch<PreviewResponse>('/api/admin/ai-detection/preview', {method: 'POST', body: JSON.stringify(filters)}), onSuccess: setPreviewData})
  const run = useMutation({mutationFn: () => apiFetch<ApiEnvelope>('/api/admin/ai-detection/runs', {method: 'POST', body: JSON.stringify(filters)}), onSuccess: () => queryClient.invalidateQueries({queryKey: ['admin', 'ai-detection', 'tasks']})})
  const runTarget = useMutation({
    mutationFn: ({kind, value}: {kind: 'problem' | 'user'; value: string}) => apiFetch<ApiEnvelope>(kind === 'problem' ? `/api/admin/ai-detection/problems/${value}/runs` : `/api/admin/ai-detection/users/${encodeURIComponent(value)}/runs`, {method: 'POST', body: JSON.stringify({endpoint_id: filters.endpoint_id})}),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['admin', 'ai-detection', 'tasks']}),
  })
  const removeTask = useMutation({
    mutationFn: (taskId: string) => apiFetch<ApiEnvelope>(`/api/admin/ai-detection/tasks/${encodeURIComponent(taskId)}`, {method: 'DELETE'}),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['admin', 'ai-detection', 'tasks']}),
  })
  const stopTask = useMutation({
    mutationFn: (taskId: string) => apiFetch<ApiEnvelope>(`/api/admin/ai-detection/tasks/${encodeURIComponent(taskId)}/stop`, {method: 'POST'}),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['admin', 'ai-detection', 'tasks']}),
  })
  const runDetail = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(detectionProblemId ? `/api/admin/ai-detection/problems/${detectionProblemId}/runs` : `/api/admin/ai-detection/users/${encodeURIComponent(detectionUsername || '')}/runs`, {method: 'POST', body: JSON.stringify({endpoint_id: detailEndpoint})}),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['admin', 'ai-detection']}),
  })
  if (!session?.user?.is_admin) return <ErrorState message="该页面仅管理员可访问" />
  if (detailMode) {
    const detail = detectionProblemId ? problemDetail : studentDetail
    if (detail.isPending) return <LoadingState label="正在读取检测结果" />
    if (detail.isError) return <ErrorState message={detail.error.message} />
    const payload = detail.data!
    const results = payload.results || []
    const endpoints = payload.endpoints || []
    if (detectionProblemId) {
      const problemPayload = payload as ProblemDetailResponse
      const problem = problemPayload.problem || {}
      const risk = searchParams.get('risk') || ''
      return <section className="ai-detection-page"><div className="mb-3"><h5><Link to="/admin/ai-detection" className="text-decoration-none">« AI 检测</Link> / {String(problem.title || `题目 #${detectionProblemId}`)}</h5></div><div className="detection-action-bar mb-3"><EndpointSelect value={detailEndpoint} endpoints={endpoints} onChange={setDetailEndpoint} /><button className="btn btn-outline-primary btn-sm" type="button" disabled={runDetail.isPending} onClick={() => runWithEndpoint(detailEndpoint, () => runDetail.mutate())}><i className="fas fa-sync-alt me-1" /> 批量检测（代表性提交）</button></div><div className="mb-3 d-flex gap-2">{[['', '全部', 'secondary'], ['high', 'High', 'danger'], ['medium', 'Medium', 'warning'], ['low', 'Low', 'success']].map(([value, label, tone]) => <Link key={value || 'all'} to={`/admin/ai-detection/problems/${detectionProblemId}${value ? `?risk=${value}` : ''}`} className={`btn btn-sm btn-outline-${tone}${risk === value ? ' active' : ''}`}>{label}</Link>)}</div>{results.length ? <div className="table-responsive"><table className="table table-sm table-hover align-middle"><thead className="table-light"><tr><th>学生</th><th>提交ID</th><th>状态</th><th>LLM</th><th>行为</th><th>综合</th><th>风险</th><th>LLM 依据</th></tr></thead><tbody>{results.map((item) => {const riskLevel = String(item.risk_level || 'low'); const llm = Number(item.llm_score || 0); return <tr key={String(item.submission_id)}><td><Link to={`/admin/ai-detection/students/${encodeURIComponent(String(item.username))}`}>{String(item.username)}</Link></td><td><Link to={`/submissions/${item.submission_id}`}>#{String(item.submission_id)}</Link></td><td>{item.submission_status === 'Accepted' ? <span className="badge bg-success">AC</span> : <span className="badge bg-secondary">{String(item.submission_status || '-')}</span>}</td><td>{item.llm_score == null ? '-' : <div className="d-flex align-items-center gap-1"><div className="score-bar" style={{width: 50}}><div className={`score-bar-fill ${llm >= .7 ? 'bg-danger' : llm >= .4 ? 'bg-warning' : 'bg-success'}`} style={{width: `${Math.round(llm * 100)}%`}} /></div><small>{numberText(llm)}</small></div>}</td><td><small>{numberText(item.behavior_score)}</small></td><td><strong>{numberText(item.final_score)}</strong></td><td><span className={`badge badge-${riskLevel} text-white`}>{riskLevel}</span></td><td>{stringList(item._evidence).length ? <ul className="evidence-list">{stringList(item._evidence).slice(0, 2).map((entry) => <li key={entry}>{entry}</li>)}</ul> : '-'}</td></tr>})}</tbody></table></div> : <div className="text-muted">暂无检测结果。</div>}{runDetail.isError ? <div className="alert alert-danger mt-3">{errorMessage(runDetail.error)}</div> : null}</section>
    }
    const username = String((payload as StudentDetailResponse).username || detectionUsername || '')
    return <section className="ai-detection-page"><div className="mb-3"><h5><Link to="/admin/ai-detection" className="text-decoration-none">« AI 检测</Link> / 学生: {username}</h5></div><div className="detection-action-bar mb-3"><EndpointSelect value={detailEndpoint} endpoints={endpoints} onChange={setDetailEndpoint} /><button className="btn btn-outline-primary btn-sm" type="button" disabled={runDetail.isPending} onClick={() => runWithEndpoint(detailEndpoint, () => runDetail.mutate())}><i className="fas fa-sync-alt me-1" /> 检测未分析提交</button></div>{results.length ? results.map((item) => {const riskLevel = String(item.risk_level || 'low'); const signals = Array.isArray(item._signals) ? item._signals as JsonRecord[] : []; return <div className={`detection-card risk-border-${riskLevel} mb-3`} key={String(item.submission_id)}><div className="d-flex justify-content-between align-items-start"><div><strong><Link to={`/submissions/${item.submission_id}`}>#{String(item.submission_id)}</Link></strong> — {String(item.problem_title || '')} <span className={`badge badge-${riskLevel} text-white ms-2`}>{riskLevel}</span></div><div className="text-end"><strong className={`risk-${riskLevel}`}>{numberText(item.final_score)}</strong><br /><small className="text-muted">{displayServerDateTime(item.created_at)}</small></div></div><div className="row mt-2"><div className="col-md-6"><small className="text-muted">LLM: {numberText(item.llm_score)}</small>{stringList(item._evidence).length ? <ul className="evidence-list">{stringList(item._evidence).map((entry) => <li key={entry}>{entry}</li>)}</ul> : null}</div><div className="col-md-6"><small className="text-muted">行为: {numberText(item.behavior_score)}</small>{signals.length ? <ul className="evidence-list">{signals.map((signal, index) => <li key={`${String(signal.description)}-${index}`}>{String(signal.description || '')}</li>)}</ul> : null}</div></div></div>}) : <div className="text-muted">该学生暂无检测结果。</div>}{runDetail.isError ? <div className="alert alert-danger mt-3">{errorMessage(runDetail.error)}</div> : null}</section>
  }
  if (dashboard.isPending) return <LoadingState label="正在读取 AI 检测概况" />
  if (dashboard.isError) return <ErrorState message={dashboard.error.message} />
  const summary = dashboard.data.summary || {}
  const counts = summary.level_counts as JsonRecord || {}
  const flagged = summary.flagged_users as JsonRecord[] || []
  const problems = summary.problem_stats as JsonRecord[] || []
  return <section className="ai-detection-page"><h5 className="mb-3"><i className="fas fa-shield-alt me-2" />AI 代码检测</h5><div className="filter-card mb-4"><h6 className="mb-3"><i className="fas fa-filter me-1" /> 筛选并检测</h6><div className="row g-3"><div className="col-md-3"><label className="form-label form-label-sm">班级</label><ChoiceSelect value={filters.class_en || ''} options={dashboard.data.classes.map((item) => ({value: String(item.class_en), label: String(item.class_cn || item.class_en)}))} placeholder="所有班级" icon="fa-users" ariaLabel="筛选班级" onChange={(value) => set('class_en', value)} /></div><div className="col-md-3"><label className="form-label form-label-sm">用户名</label><input className="form-control form-control-sm" value={filters.username || ''} onChange={(event) => set('username', event.target.value)} placeholder="精确匹配" /></div><div className="col-md-3"><label className="form-label form-label-sm">题目</label><ChoiceSelect value={filters.problem_id || ''} options={dashboard.data.problems.map((item) => ({value: String(item.id), label: `${String(item.id)}. ${String(item.title)}`}))} placeholder="所有题目" icon="fa-list-ol" ariaLabel="筛选题目" onChange={(value) => set('problem_id', value)} /></div><div className="col-md-3"><label className="form-label form-label-sm">提交编号</label><input type="number" className="form-control form-control-sm" value={filters.submission_id || ''} onChange={(event) => set('submission_id', event.target.value)} placeholder="精确匹配" min={1} /></div><div className="col-md-3"><label className="form-label form-label-sm">得分范围</label><div className="input-group input-group-sm"><input type="number" className="form-control" value={filters.score_min || ''} onChange={(event) => set('score_min', event.target.value)} placeholder="最低" min={0} /><span className="input-group-text">—</span><input type="number" className="form-control" value={filters.score_max || ''} onChange={(event) => set('score_max', event.target.value)} placeholder="最高" min={0} /></div></div><div className="col-md-3"><label className="form-label form-label-sm">检测端点</label><ChoiceSelect value={filters.endpoint_id || ''} options={dashboard.data.endpoints.map((item) => ({value: String(item.id), label: String(item.model || item.name)}))} placeholder="选择检测端点" icon="fa-minus-circle" ariaLabel="本次 AI 检测端点" onChange={(value) => set('endpoint_id', value)} /></div><div className="col-md-3 d-flex align-items-end"><div className="form-check form-switch mb-1"><input id="aiDetectionDeduplicate" className="form-check-input" type="checkbox" checked={filters.deduplicate === '1'} onChange={(event) => set('deduplicate', event.target.checked ? '1' : '0')} /><label className="form-check-label" htmlFor="aiDetectionDeduplicate">去重 <span className="text-muted" style={{fontSize: '.8em'}}>（同一用户同题保留最高分最后提交）</span></label></div></div><div className="col-md-3 d-flex align-items-end gap-2"><button className="btn btn-outline-secondary btn-sm" type="button" onClick={() => preview.mutate()}><i className="fas fa-search me-1" /> 预览</button>{previewData && previewData.total > 0 ? <button className="btn btn-primary btn-sm" type="button" disabled={run.isPending} onClick={() => runWithEndpoint(filters.endpoint_id || '', () => run.mutate())}><i className="fas fa-play me-1" /> 开始检测 <span>（共 {previewData.total} 条）</span></button> : null}</div></div>{previewData ? <div className="mt-3"><div className="mb-2 text-muted small">匹配到 <strong>{previewData.total}</strong> 条提交记录</div>{previewData.total > 0 ? <div className="table-responsive"><table id="previewTable" className="table table-sm table-bordered align-middle"><thead className="table-light"><tr><th>提交ID</th><th>用户名</th><th>题目</th><th>得分</th><th>状态</th></tr></thead><tbody>{previewData.samples.map((item) => <tr key={String(item.id)}><td><Link to={`/submissions/${item.id}`}>#{String(item.id)}</Link></td><td>{String(item.username)}</td><td>{String(item.problem_title)}</td><td>{String(item.score)}</td><td>{String(item.status)}</td></tr>)}</tbody></table></div> : null}{previewData.total > 20 ? <div className="text-muted small">（仅显示前 20 条，共 {previewData.total} 条）</div> : null}</div> : null}</div>
    <div className="row mb-4 g-3"><div className="col-md-4"><div className="card stat-card border-danger text-center p-3"><h2 className="text-danger mb-0">{String(counts.high || 0)}</h2><small className="text-muted">High Risk</small></div></div><div className="col-md-4"><div className="card stat-card border-warning text-center p-3"><h2 className="text-warning mb-0">{String(counts.medium || 0)}</h2><small className="text-muted">Medium Risk</small></div></div><div className="col-md-4"><div className="card stat-card border-success text-center p-3"><h2 className="text-success mb-0">{String(counts.low || 0)}</h2><small className="text-muted">Low Risk</small></div></div></div>
    {flagged.length ? <><h6 className="mb-2">需关注的学生</h6><div className="table-responsive mb-4"><table className="table table-sm table-hover align-middle"><thead className="table-light"><tr><th>学生</th><th>总检测数</th><th>High</th><th>Medium</th><th>最高分</th><th>平均分</th><th>操作</th></tr></thead><tbody>{flagged.map((item) => <tr key={String(item.username)}><td><Link to={`/admin/ai-detection/students/${encodeURIComponent(String(item.username))}`}>{String(item.username)}</Link></td><td>{String(item.total_detections)}</td><td><span className="risk-high">{String(item.high_count)}</span></td><td><span className="risk-medium">{String(item.medium_count)}</span></td><td>{numberText(item.max_score)}</td><td>{numberText(item.avg_score)}</td><td><button className="btn btn-outline-primary btn-sm" type="button" disabled={runTarget.isPending} onClick={() => runWithEndpoint(filters.endpoint_id || '', () => runTarget.mutate({kind: 'user', value: String(item.username)}))}><i className="fas fa-sync-alt" /></button></td></tr>)}</tbody></table></div></> : null}
    {problems.length ? <><h6 className="mb-2">各题目检测概况</h6><div className="table-responsive"><table className="table table-sm table-hover align-middle"><thead className="table-light"><tr><th>题目</th><th>检测数</th><th>High</th><th>Medium</th><th>平均分</th><th>操作</th></tr></thead><tbody>{problems.map((item) => <tr key={String(item.problem_id)}><td><Link to={`/admin/ai-detection/problems/${item.problem_id}`}>{String(item.problem_title || `题目 #${item.problem_id}`)}</Link></td><td>{String(item.total_detections)}</td><td><span className="risk-high">{String(item.high_count)}</span></td><td><span className="risk-medium">{String(item.medium_count)}</span></td><td>{numberText(item.avg_score)}</td><td><button className="btn btn-outline-primary btn-sm" type="button" disabled={runTarget.isPending} onClick={() => runWithEndpoint(filters.endpoint_id || '', () => runTarget.mutate({kind: 'problem', value: String(item.problem_id)}))}><i className="fas fa-sync-alt" /></button></td></tr>)}</tbody></table></div></> : null}
    {!flagged.length && !problems.length ? <div className="text-muted mt-2">暂无检测数据。先通过上方筛选器选择记录，然后点击「开始检测」。</div> : null}
    {tasks.data?.tasks?.length ? <div className="mt-4"><h6 className="mb-2"><i className="fas fa-tasks me-1" /> 近期检测任务</h6><div className="table-responsive"><table className="table table-sm align-middle mb-0" style={{fontSize: '.88em'}}><thead className="table-light"><tr><th style={{width: 90}}>类型</th><th>参数</th><th style={{width: 80}}>状态</th><th style={{width: 160}}>进度</th><th style={{width: 145}}>提交时间</th><th style={{width: 145}}>完成时间</th><th style={{width: 100}} /></tr></thead><tbody>{tasks.data.tasks.map((item) => {const status = String(item.status || ''); const active = status === 'pending' || status === 'running'; const processed = Number(item.processed || 0); const total = item.total == null ? null : Number(item.total); const percentage = total ? Math.min(100, Math.round(processed / total * 100)) : 0; const taskId = String(item.task_id); return <tr key={taskId}><td>{String(item.type_label || item.task_type || '')}</td><td className="text-muted">{String(item.params_summary || '')}</td><td>{status === 'pending' ? <span className="badge bg-secondary">等待中</span> : status === 'running' ? <span className="badge bg-primary">运行中</span> : status === 'done' ? <span className="badge bg-success">完成</span> : status === 'failed' ? <span className="badge bg-danger">失败</span> : status}</td><td><div className="d-flex align-items-center gap-1"><div className="score-bar flex-grow-1"><div className={`score-bar-fill ${status === 'done' ? 'bg-success' : status === 'pending' ? 'bg-secondary opacity-25' : 'bg-primary'}`} style={{width: `${status === 'pending' ? 100 : percentage}%`}} /></div><small className={status === 'pending' ? 'text-muted' : ''}>{status === 'pending' ? '等待中' : total == null ? '启动中' : `${processed}/${total}`}</small></div></td><td className="text-muted">{String(item.submitted_at || '')}</td><td className="text-muted">{String(item.finished_at || '-')}</td><td>{active ? <button className="btn btn-outline-danger btn-sm py-0 px-1" style={{fontSize: '.75em'}} disabled={stopTask.isPending} onClick={() => {if (window.confirm('确认强制停止该任务？')) stopTask.mutate(taskId)}}>停止</button> : <button className="btn btn-outline-secondary btn-sm py-0 px-1 ms-1" style={{fontSize: '.75em'}} disabled={removeTask.isPending} onClick={() => {if (window.confirm('确认删除该任务？\n\n此操作将同时删除该任务产生的所有 AI 检测记录（不影响其他任务的结果）。')) removeTask.mutate(taskId)}}>删除</button>}</td></tr>})}</tbody></table></div></div> : null}
    {preview.isError || run.isError ? <div className="alert alert-danger">{errorMessage(preview.error || run.error)}</div> : null}
  </section>
}
