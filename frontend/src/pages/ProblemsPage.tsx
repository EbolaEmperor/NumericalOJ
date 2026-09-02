import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useMemo, useState} from 'react'
import {useSearchParams} from 'react-router-dom'

import {apiFetch, queryString} from '../api/client'
import type {ApiEnvelope, JsonRecord, ProblemSummary} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {Link, useNavigate} from '../components/PageNavigation'
import {ReactModal} from '../components/ReactModal'
import {useDismissibleDropdown} from '../components/useDismissibleDropdown'
import {frontierProjects, problemInsights} from '../content/problemDashboard'
import {shouldNavigateFromCardClick} from '../lib/clickableCard'
import {useSession} from '../session'

interface Response extends ApiEnvelope {
  problems: ProblemSummary[]
  count: number
  view_mode?: string
  classes?: JsonRecord[]
  selected_class_en?: string
  selected_class_cn?: string
  numoj_cli_resource?: {label?: string; description?: string}
}

interface ActivityResponse extends ApiEnvelope {activity?: Array<{day: string; count: number; intensity: number; future?: boolean}>; class_cn?: string}

function languageLabel(value?: string) {
  return ({matlab: 'MATLAB', cpp: 'C++', c: 'C', python: 'Python', lean: 'Lean 4', lean4: 'Lean 4'} as Record<string, string>)[String(value || '').toLowerCase()] || value || ''
}

function SubmissionMetric({value}: {value: unknown}) {
  const metrics = (value && typeof value === 'object' ? value : {}) as JsonRecord
  const passRate = metrics.pass_rate == null ? null : Number(metrics.pass_rate)
  const percent = passRate == null ? 0 : Math.round(passRate * 100)
  return <div className="numoj-row-metric"><div><span>{passRate == null ? '—' : `${percent}%`}</span><span>n={Number(metrics.submission_count || 0)}</span></div><div className="numoj-progress" aria-label={passRate == null ? '暂无终态提交' : `通过率 ${percent}%`}><span style={{width: `${percent}%`}} /></div></div>
}

function ClassLogo({item}: {item: JsonRecord}) {
  const logo = item.logo && typeof item.logo === 'object' ? item.logo as JsonRecord : {}
  const cells = Array.isArray(logo.cells) ? logo.cells : []
  return <span className="numoj-class-logo" aria-hidden="true"><svg viewBox="0 0 7 7" focusable="false" shapeRendering="crispEdges">{cells.map((cell, index) => Array.isArray(cell) ? <rect key={index} x={Number(cell[0]) + 1} y={Number(cell[1]) + 1} width="1" height="1" /> : null)}</svg></span>
}

function deadlineParts(value: unknown) {
  if (!value) return {absolute: '', relative: '无截止时间', state: 'numoj-row-deadline-empty'}
  const date = new Date(String(value))
  const remaining = date.getTime() - Date.now()
  const absolute = `${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
  if (remaining < 0) return {absolute, relative: '已截止', state: 'expired'}
  if (remaining < 86_400_000) return {absolute, relative: `剩 ${Math.ceil(remaining / 3_600_000)} 小时`, state: 'urgent'}
  return {absolute, relative: `剩 ${Math.ceil(remaining / 86_400_000)} 天`, state: ''}
}

export default function ProblemsPage() {
  const {session} = useSession()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [params] = useSearchParams()
  const library = params.get('view') === 'library'
  const classEn = params.get('class_en') || ''
  const [pickerOpen, setPickerOpen] = useState(false)
  const pickerRef = useDismissibleDropdown<HTMLDivElement>(pickerOpen, () => setPickerOpen(false))
  const [insightIndex, setInsightIndex] = useState(0)
  const [projectOffset, setProjectOffset] = useState(0)
  const [plagiarismNotice, setPlagiarismNotice] = useState('')
  const prefetchClass = (classEn: string) => {
    void queryClient.prefetchQuery({
      queryKey: ['problems', 'homework', classEn],
      queryFn: () => apiFetch<Response>(`/api/problems${queryString({class_en: classEn})}`),
      staleTime: 60_000,
    })
  }
  const deleteProblem = useMutation({
    mutationFn: (problemId: number) => apiFetch<ApiEnvelope>(`/api/admin/problems/${problemId}`, {method: 'DELETE'}),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['problems']}),
    onError: (error: Error) => window.alert(error.message || '删除失败'),
  })
  const result = useQuery({
    queryKey: ['problems', library ? 'library' : 'homework', classEn],
    queryFn: () => apiFetch<Response>(`/api/problems${queryString({view: library ? 'library' : undefined, class_en: classEn || undefined})}`),
  })
  const selectedClass = useMemo(() => (result.data?.classes || []).find((item) => String(item.class_en) === result.data?.selected_class_en) || result.data?.classes?.[0], [result.data])
  const activity = useQuery({
    queryKey: ['class-activity', result.data?.selected_class_en],
    queryFn: async () => {
      const classCode = String(result.data?.selected_class_en || '')
      const cacheKey = `numoj.problemActivity.v1:${String(session?.user?.id || session?.user?.username || 'anonymous')}:${classCode}`
      try {
        const cached = JSON.parse(window.sessionStorage.getItem(cacheKey) || 'null') as {savedAt?: number; payload?: ActivityResponse} | null
        if (cached?.payload?.success && cached.savedAt && Date.now() - cached.savedAt < 30_000) return cached.payload
      } catch { /* 隐私模式下直接请求 */ }
      const payload = await apiFetch<ActivityResponse>(`/api/class-activity${queryString({class_en: classCode})}`)
      try {window.sessionStorage.setItem(cacheKey, JSON.stringify({savedAt: Date.now(), payload}))} catch { /* 缓存不可用不阻断页面 */ }
      return payload
    },
    enabled: !library && Boolean(result.data?.selected_class_en),
    staleTime: 30_000,
  })

  if (result.isPending) return <LoadingState label="正在装载题目空间" />
  if (result.isError) return <ErrorState message={result.error.message} retry={() => void result.refetch()} />
  const rows = result.data?.problems || []
  const title = library ? '总题库' : result.data?.selected_class_cn || (session?.user?.is_admin ? '班级作业' : '我的作业')
  const insight = problemInsights[insightIndex]
  const projects = [0, 1, 2].map((index) => frontierProjects[(projectOffset + index) % frontierProjects.length])

  return <section className="numoj-problem-dashboard" aria-labelledby="problem-dashboard-title">
    <div className={`numoj-dashboard-grid${library ? ' numoj-library-grid' : ''}`}>
      <div className="numoj-dashboard-main">
        <header className="numoj-page-header">
          <div><p className="numoj-eyebrow">{library ? 'PROBLEM LIBRARY' : 'CLASS WORKSPACE'}</p><h1 id="problem-dashboard-title">{title}</h1></div>
          {session?.user?.is_admin ? <Link to="/admin/problems/new" className="btn btn-primary numoj-primary-action" viewTransition><span aria-hidden="true">＋</span> 添加题目</Link> : null}
        </header>
        <section className="numoj-panel numoj-assignment-panel" aria-label={library ? '全部题目' : '班级作业列表'}>
          {!library && selectedClass ? <div className="numoj-class-switcher" aria-label="选择班级">
            <span className="numoj-class-switcher-label">CLASS</span>
            <div ref={pickerRef} className={`numoj-class-picker${pickerOpen ? ' is-open' : ''}`} data-numoj-class-picker>
              <button type="button" className="numoj-class-picker-trigger" aria-haspopup="listbox" aria-expanded={pickerOpen} onClick={() => setPickerOpen((value) => !value)} title={String(selectedClass.class_cn || '')}><ClassLogo item={selectedClass} /><span className="numoj-class-picker-current">{String(selectedClass.class_cn || '')}</span><i className="fas fa-chevron-down numoj-class-picker-chevron" aria-hidden="true" /></button>
              <div className="numoj-class-picker-menu" role="listbox" aria-label="可选择的班级" hidden={!pickerOpen}>{(result.data?.classes || []).map((item) => {const itemClassEn = String(item.class_en); return <Link className={`numoj-class-picker-option${itemClassEn === result.data?.selected_class_en ? ' active' : ''}`} to={`/problems${queryString({class_en: itemClassEn})}`} role="option" aria-selected={itemClassEn === result.data?.selected_class_en} key={itemClassEn} viewTransition onPointerEnter={() => prefetchClass(itemClassEn)} onFocus={() => prefetchClass(itemClassEn)} onClick={() => setPickerOpen(false)}><ClassLogo item={item} /><span className="numoj-class-picker-option-name">{String(item.class_cn)}</span>{itemClassEn === result.data?.selected_class_en ? <i className="fas fa-check numoj-class-picker-check" aria-hidden="true" /> : null}</Link>})}</div>
            </div>
          </div> : null}
          <div className="numoj-assignment-list">
            {rows.map((item, index) => {
              const isRanking = item.kind === 'ranking'
              const id = Number(item.problem_id || item.competition_id || item.id)
              const target = isRanking ? `/rankings/${id}` : `/problems/${id}`
              if (library) return <article className="numoj-assignment-row numoj-assignment-row-library" data-numoj-assignment-kind="library" key={`${id}-${index}`} onClick={(event) => {if (shouldNavigateFromCardClick(event)) navigate(target)}}>
                <div className="numoj-row-state neutral" aria-hidden="true" />
                <div className="numoj-row-identity"><div className="numoj-row-title-line"><span className="numoj-row-id">P{String(id).padStart(4, '0')}</span><Link className="numoj-row-title-link" to={target} viewTransition>{item.title}</Link></div><div className="numoj-row-tags"><span>{Number(item.type) === 1 ? '编程题' : '书面题'}</span>{item.lang ? <span>{languageLabel(item.lang)}</span> : null}</div></div>
                <SubmissionMetric value={item.submission_metrics} />
                <div className="numoj-row-actions">{session?.user?.is_admin ? <button type="button" className="numoj-icon-button numoj-delete-button" aria-label={`删除题目 ${item.title}`} title="删除题目" disabled={deleteProblem.isPending} onClick={() => {if (window.confirm('确定要删除这个题目吗？')) deleteProblem.mutate(id)}}>×</button> : null}<Link className="numoj-row-arrow" to={target} aria-label={`查看 ${item.title}`} viewTransition>›</Link></div>
              </article>
              const deadline = deadlineParts(item.ddl)
              const completed = Boolean(item.is_completed)
              const pending = Boolean(item.has_pending_submission)
              const hasSubmission = Boolean(item.has_submission)
              return <article className={`numoj-assignment-row numoj-assignment-row-homework${session?.user?.is_admin ? '' : ' is-student-homework'}`} data-numoj-assignment-kind="homework" key={`${id}-${index}`} onClick={(event) => {if (shouldNavigateFromCardClick(event)) navigate(target)}}>
                {session?.user?.is_admin ? <div className="numoj-row-state neutral" aria-hidden="true" /> : item.plagiarism_notice ? <button type="button" className="numoj-row-state warning" aria-label="查看抄袭记录" title="查看抄袭记录" onClick={() => setPlagiarismNotice(String(item.plagiarism_notice))}>!</button> : completed ? <div className="numoj-row-state complete" aria-label="已完成">✓</div> : hasSubmission ? <div className="numoj-row-state failed" role="img" aria-label="有提交但未通过" /> : <div className="numoj-row-state neutral" aria-label="未提交" />}
                <div className="numoj-row-identity"><div className="numoj-row-title-line"><span className="numoj-row-id">H{String(Number(item.homework_id || item.id || id)).padStart(4, '0')}</span><Link className="numoj-row-title-link" to={target} viewTransition>{item.title}</Link></div><div className="numoj-row-tags"><span>{isRanking ? '打榜赛' : Number(item.problem_type) === 2 ? '书面题' : '编程题'}</span>{item.problem_lang ? <span>{languageLabel(String(item.problem_lang))}</span> : null}</div></div>
                {!session?.user?.is_admin ? <div className="numoj-row-result"><div className="numoj-row-grade"><strong>{item.max_score == null ? pending ? '评测中' : deadline.state === 'expired' ? '0' : '-' : String(item.max_score)}{item.total_score != null ? `/${String(item.total_score)}` : ''}</strong><span>{pending ? '以提交时间为准' : item.max_score != null ? deadline.state === 'expired' ? '已结算' : '最高成绩' : deadline.state === 'expired' ? '未按时提交' : '未提交'}</span></div><div className="numoj-row-deadline">{deadline.absolute ? <strong className="numoj-row-deadline-absolute">{deadline.absolute}</strong> : null}<span className={`numoj-row-deadline-relative ${deadline.state}`}>{deadline.relative}</span></div></div> : <><SubmissionMetric value={item.submission_metrics} /><div className="numoj-row-deadline">{deadline.absolute ? <strong className="numoj-row-deadline-absolute">{deadline.absolute}</strong> : null}<span className={`numoj-row-deadline-relative ${deadline.state}`}>{deadline.relative}</span></div></>}
                <Link className="numoj-row-arrow" to={target} aria-label={`查看 ${item.title}`} viewTransition>›</Link>
              </article>
            })}
            {!rows.length ? <div className="numoj-empty-state">{library ? '总题库暂无题目' : result.data?.classes?.length && !result.data.selected_class_en ? '请选择一个班级' : '该班级暂无作业'}</div> : null}
          </div>
        </section>
      </div>

      <aside className="numoj-dashboard-aside" aria-label="学习辅助信息">
        {!library ? <section className="numoj-panel numoj-activity-card"><header><h2>班级活跃度</h2><span>近 12 周</span></header><div className="numoj-heatmap-frame">{activity.isPending ? <div className="numoj-heatmap-loading" role="status"><MathCurveLoader size="lg" label="正在加载班级活跃度" /></div> : activity.data?.activity?.length ? <><div className="numoj-weekday-labels" aria-hidden="true"><span>一</span><span>三</span><span>五</span><span>日</span></div><div className="numoj-heatmap" role="img" aria-label={`${activity.data.class_cn || '当前班级'}近十二周提交活跃度`}>{activity.data.activity.map((item) => <span className={`level-${Math.max(0, Math.min(4, Number(item.intensity) || 0))}${item.future ? ' future' : ''}`} title={`${item.day}：${item.count} 次提交`} aria-hidden="true" key={item.day} />)}</div></> : <div className="numoj-heatmap-message">当前没有可展示的班级活跃度</div>}</div>{activity.data?.activity?.length ? <footer><span>{activity.data.activity[0]?.day.slice(5).replace('-', '/')}</span><span className="numoj-heatmap-legend">少 <i className="level-1" /><i className="level-2" /><i className="level-3" /><i className="level-4" /> 多</span><span>更新至今日</span></footer> : null}</section> : null}
        <section className="numoj-panel numoj-tip-card"><header><h2><span className="numoj-card-mark" aria-hidden="true"><i className="fas fa-lightbulb" /></span>Insights Everyday</h2></header><div className="numoj-insight" aria-live="polite"><p className="numoj-insight-quote">“{insight[0]}”</p><p className="numoj-insight-translation" lang="zh-CN">{insight[1]}</p><cite>— {insight[2]}</cite></div><button type="button" className="numoj-text-button" onClick={() => setInsightIndex((value) => (value + 1) % problemInsights.length)}><i className="fas fa-sync-alt" aria-hidden="true" /><span>换一换</span></button></section>
        <section className="numoj-panel numoj-resource-card"><header><h2><span className="numoj-card-mark" aria-hidden="true"><i className="fab fa-github" /></span>Explore the Frontier</h2></header><ul aria-live="polite">{projects.map((project) => <li key={project}><a href={`https://github.com/${project}`} target="_blank" rel="noopener noreferrer"><span>{project}</span><b>↗</b></a></li>)}</ul><button type="button" className="numoj-text-button" onClick={() => setProjectOffset((value) => (value + 3) % frontierProjects.length)}><i className="fas fa-sync-alt" aria-hidden="true" /><span>换一换</span></button></section>
        <section className="numoj-panel numoj-resource-card"><header><h2><span className="numoj-card-mark" aria-hidden="true"><i className="fas fa-compass" /></span>Resources</h2></header><ul><li><a href="https://github.com/EbolaEmperor/NumericalOJ" target="_blank" rel="noopener noreferrer"><span>NumericalOJ · GitHub<small>github.com/EbolaEmperor/NumericalOJ</small></span><b>↗</b></a></li><li><a href="/api/downloads/numoj-cli.zip" download><span>{result.data?.numoj_cli_resource?.label || (session?.user?.is_admin ? 'numoj-admin CLI' : 'numoj-user CLI')}<small>{result.data?.numoj_cli_resource?.description || (session?.user?.is_admin ? 'Download for agents to manage NumOJ' : 'Download for agents to use NumOJ.')}</small></span><b>↓</b></a></li></ul></section>
      </aside>
    </div>
    <ReactModal open={Boolean(plagiarismNotice)} onClose={() => setPlagiarismNotice('')} id="plagiarismNoticeModal" labelledBy="plagiarismNoticeModalTitle" dialogClassName="modal-dialog-centered"><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="plagiarismNoticeModalTitle"><i className="fas fa-exclamation-triangle me-2 text-warning" />抄袭记录</h5><button type="button" className="btn-close" aria-label="Close" onClick={() => setPlagiarismNotice('')} /></div><div className="modal-body"><p className="mb-0">{plagiarismNotice}</p></div><div className="modal-footer"><button type="button" className="btn btn-secondary" onClick={() => setPlagiarismNotice('')}>关闭</button></div></div></ReactModal>
  </section>
}
