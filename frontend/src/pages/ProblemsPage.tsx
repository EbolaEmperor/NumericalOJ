import {useQuery} from '@tanstack/react-query'
import {useMemo, useState} from 'react'
import {Link, useSearchParams} from 'react-router-dom'

import {apiFetch, queryString} from '../api/client'
import type {ApiEnvelope, JsonRecord, ProblemSummary} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface Response extends ApiEnvelope {
  problems: ProblemSummary[]
  count: number
  view_mode?: string
  classes?: JsonRecord[]
  selected_class_en?: string
  selected_class_cn?: string
}

interface ActivityResponse extends ApiEnvelope {activity?: Array<{day: string; count: number; intensity: number; future?: boolean}>; class_cn?: string}

const insights = [
  ['General methods that leverage computation are ultimately the most effective, and by a large margin.', '充分利用计算能力的通用方法，归根结底总是最有效的，而且优势往往非常显著。', 'Rich Sutton'],
  ['The hottest new programming language is English.', '最热门的新编程语言是英语。', 'Andrej Karpathy'],
  ['Grade the outcome, not the claim.', '评判结果，而不是它的自我陈述。', 'Mikaela Grace et al. · Anthropic'],
]

const projects = ['openai/codex', 'leanprover/lean4', 'huggingface/trl']

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
  const [params] = useSearchParams()
  const library = params.get('view') === 'library'
  const classEn = params.get('class_en') || ''
  const [pickerOpen, setPickerOpen] = useState(false)
  const [insightIndex, setInsightIndex] = useState(0)
  const result = useQuery({
    queryKey: ['problems', library ? 'library' : 'homework', classEn],
    queryFn: () => apiFetch<Response>(`/api/problems${queryString({view: library ? 'library' : undefined, class_en: classEn || undefined})}`),
  })
  const selectedClass = useMemo(() => (result.data?.classes || []).find((item) => String(item.class_en) === result.data?.selected_class_en) || result.data?.classes?.[0], [result.data])
  const activity = useQuery({
    queryKey: ['class-activity', result.data?.selected_class_en],
    queryFn: () => apiFetch<ActivityResponse>(`/api/class-activity${queryString({class_en: result.data?.selected_class_en})}`),
    enabled: !library && Boolean(result.data?.selected_class_en),
    staleTime: 30_000,
  })

  if (result.isPending) return <LoadingState label="正在装载题目空间" />
  if (result.isError) return <ErrorState message={result.error.message} retry={() => void result.refetch()} />
  const rows = result.data?.problems || []
  const title = library ? '总题库' : result.data?.selected_class_cn || (session?.user?.is_admin ? '班级作业' : '我的作业')
  const insight = insights[insightIndex]

  return <section className="numoj-problem-dashboard" aria-labelledby="problem-dashboard-title">
    <div className={`numoj-dashboard-grid${library ? ' numoj-library-grid' : ''}`}>
      <div className="numoj-dashboard-main">
        <header className="numoj-page-header">
          <div><p className="numoj-eyebrow">{library ? 'PROBLEM LIBRARY' : 'CLASS WORKSPACE'}</p><h1 id="problem-dashboard-title">{title}</h1></div>
          {session?.user?.is_admin ? <a href="/admin/add_problem" className="btn btn-primary numoj-primary-action"><span aria-hidden="true">＋</span> 添加题目</a> : null}
        </header>
        <section className="numoj-panel numoj-assignment-panel" aria-label={library ? '全部题目' : '班级作业列表'}>
          {!library && selectedClass ? <div className="numoj-class-switcher" aria-label="选择班级">
            <span className="numoj-class-switcher-label">CLASS</span>
            <div className={`numoj-class-picker${pickerOpen ? ' is-open' : ''}`} data-numoj-class-picker>
              <button type="button" className="numoj-class-picker-trigger" aria-haspopup="listbox" aria-expanded={pickerOpen} onClick={() => setPickerOpen((value) => !value)} title={String(selectedClass.class_cn || '')}><ClassLogo item={selectedClass} /><span className="numoj-class-picker-current">{String(selectedClass.class_cn || '')}</span><i className="fas fa-chevron-down numoj-class-picker-chevron" aria-hidden="true" /></button>
              <div className="numoj-class-picker-menu" role="listbox" aria-label="可选择的班级" hidden={!pickerOpen}>{(result.data?.classes || []).map((item) => <Link className={`numoj-class-picker-option${String(item.class_en) === result.data?.selected_class_en ? ' active' : ''}`} to={`/app/problems${queryString({class_en: String(item.class_en)})}`} role="option" aria-selected={String(item.class_en) === result.data?.selected_class_en} key={String(item.class_en)} onClick={() => setPickerOpen(false)}><ClassLogo item={item} /><span className="numoj-class-picker-option-name">{String(item.class_cn)}</span>{String(item.class_en) === result.data?.selected_class_en ? <i className="fas fa-check numoj-class-picker-check" aria-hidden="true" /> : null}</Link>)}</div>
            </div>
          </div> : null}
          <div className="numoj-assignment-list">
            {rows.map((item, index) => {
              const isRanking = item.kind === 'ranking'
              const id = Number(item.problem_id || item.competition_id || item.id)
              const target = isRanking ? `/app/rankings/${id}` : `/app/problems/${id}`
              if (library) return <article className="numoj-assignment-row numoj-assignment-row-library" data-numoj-assignment-kind="library" key={`${id}-${index}`}>
                <div className="numoj-row-state neutral" aria-hidden="true" />
                <div className="numoj-row-identity"><div className="numoj-row-title-line"><span className="numoj-row-id">P{String(id).padStart(4, '0')}</span><Link className="numoj-row-title-link" to={target}>{item.title}</Link></div><div className="numoj-row-tags"><span>{Number(item.type) === 1 ? '编程题' : '书面题'}</span>{item.lang ? <span>{languageLabel(item.lang)}</span> : null}</div></div>
                <SubmissionMetric value={item.submission_metrics} />
                <div className="numoj-row-actions"><Link className="numoj-row-arrow" to={target} aria-label={`查看 ${item.title}`}>›</Link></div>
              </article>
              const deadline = deadlineParts(item.ddl)
              const completed = Boolean(item.is_completed)
              const pending = Boolean(item.has_pending_submission)
              const hasSubmission = Boolean(item.has_submission)
              return <article className={`numoj-assignment-row numoj-assignment-row-homework${session?.user?.is_admin ? '' : ' is-student-homework'}`} data-numoj-assignment-kind="homework" key={`${id}-${index}`}>
                {session?.user?.is_admin ? <div className="numoj-row-state neutral" aria-hidden="true" /> : completed ? <div className="numoj-row-state complete" aria-label="已完成">✓</div> : hasSubmission ? <div className="numoj-row-state failed" role="img" aria-label="有提交但未通过" /> : <div className="numoj-row-state neutral" aria-label="未提交" />}
                <div className="numoj-row-identity"><div className="numoj-row-title-line"><span className="numoj-row-id">H{String(Number(item.id || id)).padStart(4, '0')}</span><Link className="numoj-row-title-link" to={target}>{item.title}</Link></div><div className="numoj-row-tags"><span>{isRanking ? '打榜赛' : Number(item.problem_type) === 2 ? '书面题' : '编程题'}</span>{item.problem_lang ? <span>{languageLabel(String(item.problem_lang))}</span> : null}</div></div>
                {!session?.user?.is_admin ? <div className="numoj-row-result"><div className="numoj-row-grade"><strong>{item.max_score == null ? pending ? '评测中' : deadline.state === 'expired' ? '0' : '-' : String(item.max_score)}{item.total_score != null ? `/${String(item.total_score)}` : ''}</strong><span>{pending ? '以提交时间为准' : item.max_score != null ? deadline.state === 'expired' ? '已结算' : '最高成绩' : deadline.state === 'expired' ? '未按时提交' : '未提交'}</span></div><div className="numoj-row-deadline">{deadline.absolute ? <strong className="numoj-row-deadline-absolute">{deadline.absolute}</strong> : null}<span className={`numoj-row-deadline-relative ${deadline.state}`}>{deadline.relative}</span></div></div> : <><SubmissionMetric value={item.submission_metrics} /><div className="numoj-row-deadline">{deadline.absolute ? <strong className="numoj-row-deadline-absolute">{deadline.absolute}</strong> : null}<span className={`numoj-row-deadline-relative ${deadline.state}`}>{deadline.relative}</span></div></>}
                <Link className="numoj-row-arrow" to={target} aria-label={`查看 ${item.title}`}>›</Link>
              </article>
            })}
            {!rows.length ? <div className="numoj-empty-state">{library ? '总题库暂无题目' : result.data?.classes?.length && !result.data.selected_class_en ? '请选择一个班级' : '该班级暂无作业'}</div> : null}
          </div>
        </section>
      </div>

      <aside className="numoj-dashboard-aside" aria-label="学习辅助信息">
        {!library ? <section className="numoj-panel numoj-activity-card"><header><h2>班级活跃度</h2><span>近 12 周</span></header><div className="numoj-heatmap-frame">{activity.isPending ? <div className="numoj-heatmap-loading" role="status"><span className="math-curve-loader" data-math-curve-loader data-size="lg"><span className="math-curve-loader__label">正在加载班级活跃度</span></span></div> : activity.data?.activity?.length ? <><div className="numoj-weekday-labels" aria-hidden="true"><span>一</span><span>三</span><span>五</span><span>日</span></div><div className="numoj-heatmap" role="img" aria-label={`${activity.data.class_cn || '当前班级'}近十二周提交活跃度`}>{activity.data.activity.map((item) => <span className={`level-${Math.max(0, Math.min(4, Number(item.intensity) || 0))}${item.future ? ' future' : ''}`} title={`${item.day}：${item.count} 次提交`} aria-hidden="true" key={item.day} />)}</div></> : <div className="numoj-heatmap-message">当前没有可展示的班级活跃度</div>}</div>{activity.data?.activity?.length ? <footer><span>{activity.data.activity[0]?.day.slice(5).replace('-', '/')}</span><span className="numoj-heatmap-legend">少 <i className="level-1" /><i className="level-2" /><i className="level-3" /><i className="level-4" /> 多</span><span>更新至今日</span></footer> : null}</section> : null}
        <section className="numoj-panel numoj-tip-card"><header><h2><span className="numoj-card-mark" aria-hidden="true"><i className="fas fa-lightbulb" /></span>Insights Everyday</h2></header><div className="numoj-insight" aria-live="polite"><p className="numoj-insight-quote">“{insight[0]}”</p><p className="numoj-insight-translation" lang="zh-CN">{insight[1]}</p><cite>— {insight[2]}</cite></div><button type="button" className="numoj-text-button" onClick={() => setInsightIndex((value) => (value + 1) % insights.length)}><i className="fas fa-sync-alt" aria-hidden="true" /><span>换一换</span></button></section>
        <section className="numoj-panel numoj-resource-card"><header><h2><span className="numoj-card-mark" aria-hidden="true"><i className="fab fa-github" /></span>Explore the Frontier</h2></header><ul>{projects.map((project) => <li key={project}><a href={`https://github.com/${project}`} target="_blank" rel="noopener noreferrer"><span>{project}</span><b>↗</b></a></li>)}</ul></section>
        <section className="numoj-panel numoj-resource-card"><header><h2><span className="numoj-card-mark" aria-hidden="true"><i className="fas fa-compass" /></span>Resources</h2></header><ul><li><a href="https://github.com/EbolaEmperor/NumericalOJ" target="_blank" rel="noopener noreferrer"><span>NumericalOJ · GitHub<small>github.com/EbolaEmperor/NumericalOJ</small></span><b>↗</b></a></li><li><a href="/problems/downloads/numoj-cli.zip" download><span>NumOJ CLI Skill<small>下载命令行技能包</small></span><b>↓</b></a></li></ul></section>
      </aside>
    </div>
  </section>
}
