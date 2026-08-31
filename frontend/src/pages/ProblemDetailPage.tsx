import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useRef, useState, type FormEvent, type RefObject} from 'react'
import {useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord, ProblemSummary, SubmissionSummary} from '../api/types'
import {MarkdownContent} from '../components/MarkdownContent'
import {MonacoEditor} from '../components/MonacoEditor'
import {Link, useNavigate} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'
import {LeanWorkbench, type LeanWorkbenchController} from '../components/LeanWorkbench'
import {useSession} from '../session'

interface DetailResponse extends ApiEnvelope {
  problem: ProblemSummary & {content?: string; time_limit_ms?: number; max_score?: number; submission_limit?: number; written_grading_mode?: number}
  rendered_content: string
  initial_code?: string
  lean_workspace?: (JsonRecord & {revision_number?: number}) | null
  last_submissions: SubmissionSummary[]
  remaining_submissions?: number
  can_submit: boolean
  submit_block_reason?: string
  submit_warning?: JsonRecord
  submit: {action: string; input_name: string; input_kind: string; accept?: string; help_text?: string; programming_grading_mode?: number}
}

interface LastCodeResponse extends ApiEnvelope {code: string; submission_id: number; files?: Record<string, string>}
interface ScoresResponse extends ApiEnvelope {problem_id: number; problem_title: string; max_score: number; scores: JsonRecord[]}
interface RejudgeStatusResponse extends ApiEnvelope {progress: number; done: number; total: number}

const abbreviations: Record<string, string> = {'Accepted': 'AC', 'Wrong Answer': 'WA', 'Unaccepted': 'UA', 'Compile Error': 'CE', 'Runtime Error': 'RE', 'Time Limit Exceeded': 'TL', 'Memory Limit Exceeded': 'ML', 'Output Limit Exceeded': 'OL', 'Forbidden': 'FB', 'No Output': 'NO', 'Nonzero Exit Status': 'NZ', 'Pending': 'PD', 'Waiting': 'WT', 'Running': 'RN', 'Generating': 'GN', 'Error': 'ER'}

function languageLabel(value?: string) {
  return ({matlab: 'MATLAB', cpp: 'C++', c: 'C', python: 'Python', lean: 'Lean 4', lean4: 'Lean 4'} as Record<string, string>)[String(value || '').toLowerCase()] || value || ''
}

function useProblemDetailLayout(pageRef: RefObject<HTMLDivElement | null>, problemId?: string, isLean4 = false) {
  useEffect(() => {
    const page = pageRef.current
    const row = page?.querySelector<HTMLElement>('.problem-detail-row')
    const splitter = page?.querySelector<HTMLElement>('[data-problem-detail-splitter]')
    if (!row || !splitter) return
    const desktop = window.matchMedia('(min-width: 992px)')
    const storageKey = isLean4 ? 'numoj.problemDetail.leanStatementRatio' : 'numoj.problemDetail.statementRatio'
    const stored = Number(window.localStorage.getItem(storageKey))
    const defaultRatio = isLean4 ? 0.36 : 0.5
    let preferredRatio = stored > 0 && stored < 1 ? stored : defaultRatio
    let currentWidth = 0
    let pointerId: number | null = null
    let pointerOffset = 0

    const bounds = () => {
      const rect = row.getBoundingClientRect()
      const splitterWidth = Math.max(1, splitter.getBoundingClientRect().width || 7)
      const available = Math.max(1, rect.width - splitterWidth)
      const minimum = Math.min(280, available * 0.42)
      const maximum = Math.max(minimum, available - Math.min(isLean4 ? 480 : 340, available * 0.48))
      return {rect, available, minimum, maximum}
    }
    const apply = (requested: number, remember = false) => {
      if (!desktop.matches) return
      const range = bounds()
      currentWidth = Math.min(range.maximum, Math.max(range.minimum, requested))
      if (remember) preferredRatio = currentWidth / range.available
      row.style.setProperty('--problem-detail-statement-width', `${currentWidth.toFixed(2)}px`)
      const percent = Math.round(currentWidth / range.available * 100)
      splitter.setAttribute('aria-valuemin', String(Math.round(range.minimum / range.available * 100)))
      splitter.setAttribute('aria-valuemax', String(Math.round(range.maximum / range.available * 100)))
      splitter.setAttribute('aria-valuenow', String(percent))
      splitter.setAttribute('aria-valuetext', `题面 ${percent}%，作答区 ${100 - percent}%`)
      window.dispatchEvent(new CustomEvent('numoj:problem-detail-resize'))
    }
    const refresh = () => {
      const range = bounds()
      apply(preferredRatio * range.available)
    }
    const finish = (event: PointerEvent) => {
      if (event.pointerId !== pointerId) return
      pointerId = null
      splitter.classList.remove('is-dragging')
      document.documentElement.classList.remove('is-problem-pane-resizing')
      window.localStorage.setItem(storageKey, preferredRatio.toFixed(4))
    }
    const pointerDown = (event: PointerEvent) => {
      if (!desktop.matches || event.button !== 0) return
      pointerId = event.pointerId
      pointerOffset = event.clientX - splitter.getBoundingClientRect().left
      splitter.setPointerCapture(pointerId)
      splitter.classList.add('is-dragging')
      document.documentElement.classList.add('is-problem-pane-resizing')
      event.preventDefault()
    }
    const pointerMove = (event: PointerEvent) => {
      if (event.pointerId !== pointerId) return
      const range = bounds()
      apply(event.clientX - range.rect.left - pointerOffset, true)
      event.preventDefault()
    }
    const keyDown = (event: KeyboardEvent) => {
      const range = bounds()
      let next = currentWidth
      if (event.key === 'ArrowLeft') next -= event.shiftKey ? 48 : 16
      else if (event.key === 'ArrowRight') next += event.shiftKey ? 48 : 16
      else if (event.key === 'Home') next = range.minimum
      else if (event.key === 'End') next = range.maximum
      else return
      event.preventDefault()
      apply(next, true)
      window.localStorage.setItem(storageKey, preferredRatio.toFixed(4))
    }
    const doubleClick = () => {
      preferredRatio = defaultRatio
      refresh()
      window.localStorage.setItem(storageKey, preferredRatio.toFixed(4))
    }
    const mediaChange = () => {
      if (desktop.matches) refresh()
      else row.style.removeProperty('--problem-detail-statement-width')
    }
    const title = page?.querySelector<HTMLElement>('#problemTitleHeading')
    let titleFitFrame = 0
    const fitTitle = () => {
      if (!title) return
      const isMobile = window.innerWidth <= 768
      let size = isMobile ? 24 : 36
      const minimum = isMobile ? 11 : 12
      title.style.fontSize = `${size}px`
      while (title.scrollWidth > title.clientWidth && size > minimum) {
        size -= 1
        title.style.fontSize = `${size}px`
      }
      if (title.scrollWidth > title.clientWidth && title.clientWidth > 0) {
        title.style.fontSize = `${Math.max(10, Math.floor(size * title.clientWidth / title.scrollWidth))}px`
      }
    }
    const scheduleTitleFit = () => {
      if (titleFitFrame) window.cancelAnimationFrame(titleFitFrame)
      titleFitFrame = window.requestAnimationFrame(() => {titleFitFrame = 0; fitTitle()})
    }
    const observer = new ResizeObserver(() => desktop.matches && refresh())
    observer.observe(row)
    const titleObserver = title?.parentElement ? new ResizeObserver(scheduleTitleFit) : null
    if (title?.parentElement) titleObserver?.observe(title.parentElement)
    splitter.addEventListener('pointerdown', pointerDown)
    splitter.addEventListener('keydown', keyDown)
    splitter.addEventListener('dblclick', doubleClick)
    window.addEventListener('pointermove', pointerMove)
    window.addEventListener('pointerup', finish)
    window.addEventListener('pointercancel', finish)
    desktop.addEventListener('change', mediaChange)
    window.addEventListener('resize', scheduleTitleFit)
    refresh()
    scheduleTitleFit()
    return () => {
      observer.disconnect()
      titleObserver?.disconnect()
      if (titleFitFrame) window.cancelAnimationFrame(titleFitFrame)
      splitter.removeEventListener('pointerdown', pointerDown)
      splitter.removeEventListener('keydown', keyDown)
      splitter.removeEventListener('dblclick', doubleClick)
      window.removeEventListener('pointermove', pointerMove)
      window.removeEventListener('pointerup', finish)
      window.removeEventListener('pointercancel', finish)
      desktop.removeEventListener('change', mediaChange)
      window.removeEventListener('resize', scheduleTitleFit)
      document.documentElement.classList.remove('is-problem-pane-resizing')
    }
  }, [isLean4, pageRef, problemId])
}

function RejudgeProgressModal({progress}: {progress: {percent: number; done: number; total: number}}) {
  return <><button type="button" id="rejudgeProgressTrigger" className="d-none" data-bs-toggle="modal" data-bs-target="#rejudgeProgressModal" tabIndex={-1} aria-hidden="true" /><div className="modal fade" id="rejudgeProgressModal" tabIndex={-1} aria-labelledby="rejudgeProgressLabel" aria-hidden="true"><div className="modal-dialog"><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="rejudgeProgressLabel">重测进度</h5><button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="关闭" /></div><div className="modal-body"><div className="progress mb-3"><div className="progress-bar" role="progressbar" style={{width: `${progress.percent}%`}} aria-valuenow={progress.percent} aria-valuemin={0} aria-valuemax={100}>{progress.percent}%</div></div><p className="small text-muted">{progress.percent < 100 ? <span className="math-curve-loader" data-math-curve-loader data-size="sm"><span className="math-curve-loader__label">已完成 {progress.done} / {progress.total}</span></span> : `已完成 ${progress.done} / ${progress.total}`}</p></div><div className="modal-footer"><button type="button" className="btn btn-secondary" data-bs-dismiss="modal">关闭</button></div></div></div></div></>
}

function ScoresModal({data, pending, error}: {data?: ScoresResponse; pending: boolean; error?: unknown}) {
  const average = data?.scores.length ? (data.scores.reduce((sum, row) => sum + Number(row.score || 0), 0) / data.scores.length).toFixed(2) : '0.00'
  return <div className="modal fade" id="scoresModal" tabIndex={-1} aria-labelledby="scoresModalLabel" aria-hidden="true"><div className="modal-dialog modal-lg"><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="scoresModalLabel"><i className="fas fa-chart-bar me-2" /> 用户得分统计</h5><button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="关闭" /></div><div className="modal-body">{pending ? <div className="text-center"><span className="math-curve-loader" data-math-curve-loader data-size="md"><span className="math-curve-loader__label">正在加载用户得分…</span></span></div> : error ? <div className="alert alert-danger"><i className="fas fa-exclamation-triangle me-2" /><span>{errorMessage(error)}</span></div> : data ? <><div className="mb-3"><h6>{data.problem_id}. {data.problem_title}</h6><p className="text-muted mb-1">满分: <span>{data.max_score}</span> 分</p><p className="text-muted mb-0">平均分: <span>{average}</span> 分</p></div><div className="table-responsive"><table className="table table-striped table-hover"><thead className="table-dark"><tr><th>用户名</th><th>班级</th><th>得分</th><th>状态</th></tr></thead><tbody>{data.scores.map((row) => {const score = Number(row.score || 0); const status = score === Number(data.max_score) ? ['满分', 'text-success'] : score > 0 ? ['部分正确', 'text-warning'] : ['未通过', 'text-danger']; return <tr key={String(row.user_id)}><td>{String(row.username || '')}</td><td>{String(row.classes_display || '')}</td><td>{String(row.score ?? '')}</td><td className={status[1]}>{status[0]}</td></tr>})}</tbody></table></div></> : null}</div><div className="modal-footer"><button type="button" className="btn btn-secondary" data-bs-dismiss="modal">关闭</button></div></div></div></div>
}

export default function ProblemDetailPage() {
  const {problemId} = useParams()
  const {session} = useSession()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [text, setText] = useState('')
  const [writtenFileName, setWrittenFileName] = useState('')
  const [writtenDragDepth, setWrittenDragDepth] = useState(0)
  const [rejudgePolling, setRejudgePolling] = useState(false)
  const [rejudgeProgress, setRejudgeProgress] = useState({percent: 0, done: 0, total: 0})
  const fileRef = useRef<HTMLInputElement>(null)
  const leanControllerRef = useRef<LeanWorkbenchController | null>(null)
  const pageRef = useRef<HTMLDivElement>(null)
  const loadedProblemRef = useRef<string | undefined>(undefined)
  const detail = useQuery({queryKey: ['problem', problemId], queryFn: () => apiFetch<DetailResponse>(`/api/problems/${problemId}`)})
  useEffect(() => {
    if (detail.data && loadedProblemRef.current !== problemId) {
      loadedProblemRef.current = problemId
      setText(detail.data.initial_code || '')
      setWrittenFileName('')
      setWrittenDragDepth(0)
    }
  }, [detail.data, problemId])
  const detailIsLean4 = Boolean(detail.data && Number(detail.data.problem.type || 1) === 1 && ['lean', 'lean4'].includes(String(detail.data.problem.lang || '').toLowerCase()))
  useProblemDetailLayout(pageRef, detail.data ? problemId : undefined, detailIsLean4)
  const submit = useMutation({
    mutationFn: async () => {
      if (!detail.data) throw new Error('题目上下文尚未加载')
      const form = new FormData()
      if (detail.data.submit.input_kind === 'lean_workspace') {
        const workspace = leanControllerRef.current?.prepareSubmission()
        if (!workspace) throw new Error('Lean 4 工作区尚未加载')
        form.append(detail.data.submit.input_name, JSON.stringify(workspace))
      } else if (detail.data.submit.input_kind === 'file') {
        const file = fileRef.current?.files?.[0]
        if (!file) throw new Error('请先选择文件')
        form.append(detail.data.submit.input_name, file)
      } else form.append(detail.data.submit.input_name, text)
      return apiFetch<ApiEnvelope & {submission_id?: number}>(detail.data.submit.action, {method: 'POST', body: form})
    },
    onSuccess: async (payload) => {await queryClient.invalidateQueries({queryKey: ['submissions']}); if (payload.submission_id) navigate(`/submissions/${payload.submission_id}`)},
  })
  const lastCode = useMutation({
    mutationFn: () => apiFetch<LastCodeResponse>(`/api/problems/${problemId}/last-submission-code`),
    onSuccess: (payload) => {
      if (leanControllerRef.current && payload.files) {
        leanControllerRef.current.setWritableFiles(payload.files)
        leanControllerRef.current.focus()
        leanControllerRef.current.checkNow()
      } else setText(payload.code || '')
    },
  })
  const uploadData = useMutation({
    mutationFn: (body: FormData) => apiFetch<ApiEnvelope>(`/api/admin/problems/${problemId}/testdata`, {method: 'POST', body}),
  })
  const uploadLeanWorkspace = useMutation({
    mutationFn: (body: FormData) => apiFetch<ApiEnvelope>(`/api/admin/problems/${problemId}/lean-workspace`, {method: 'POST', body}),
    onSuccess: async () => {await queryClient.invalidateQueries({queryKey: ['problem', problemId]})},
  })
  const rejudge = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(`/api/admin/problems/${problemId}/rejudge`, {method: 'POST'}),
    onSuccess: () => {
      setRejudgeProgress({percent: 0, done: 0, total: 0})
      setRejudgePolling(true)
      document.getElementById('rejudgeProgressTrigger')?.click()
    },
    onError: (error) => window.alert(`重测失败：${errorMessage(error)}`),
  })
  const scores = useMutation({
    mutationFn: () => apiFetch<ScoresResponse>(`/api/admin/problems/${problemId}/scores`),
  })
  const invalidateWrittenSubmissions = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(`/api/admin/problems/${problemId}/invalidate-submissions`, {method: 'POST'}),
    onSuccess: async () => {
      window.alert('无效提交已移除')
      await queryClient.invalidateQueries({queryKey: ['problem', problemId]})
    },
    onError: (error) => window.alert(`错误: ${errorMessage(error)}`),
  })
  useEffect(() => {
    if (!rejudgePolling || !problemId) return
    const check = async () => {
      try {
        const payload = await apiFetch<RejudgeStatusResponse>(`/api/admin/problems/${problemId}/rejudge-status`)
        const percent = Number(payload.progress || 0)
        setRejudgeProgress({percent, done: Number(payload.done || 0), total: Number(payload.total || 0)})
        if (percent >= 100) setRejudgePolling(false)
      } catch {
        setRejudgePolling(false)
      }
    }
    const timer = window.setInterval(() => void check(), 1500)
    return () => window.clearInterval(timer)
  }, [problemId, rejudgePolling])
  if (detail.isPending) return <LoadingState label="正在读取题目与提交上下文" />
  if (detail.isError) return <ErrorState message={detail.error.message} />
  const data = detail.data!
  const problem = data.problem
  const programming = Number(problem.type || 1) === 1
  const isLean4 = programming && ['lean', 'lean4'].includes(String(problem.lang || '').toLowerCase())
  const isPrompt = data.submit.input_kind === 'prompt'
  const writtenMode = Number(problem.written_grading_mode || 1)
  const writtenIsZip = writtenMode === 3 || String(data.submit.accept || '').toLowerCase().includes('zip')
  const writtenFileKind = writtenIsZip ? 'ZIP' : 'PDF'
  const lang = languageLabel(problem.lang)
  const submitForm = (event: FormEvent) => {event.preventDefault(); submit.mutate()}
  const acceptWrittenDrop = (files: FileList | null) => {
    const input = fileRef.current
    const file = files?.[0]
    if (!input || !file) return
    try {
      const transfer = new DataTransfer()
      transfer.items.add(file)
      input.files = transfer.files
    } catch {
      try { input.files = files } catch { return }
    }
    setWrittenFileName(file.name)
  }

  return <div ref={pageRef} className={`problem-detail-page${isLean4 ? ' is-lean-workbench' : ''}`}>
    <nav className="numoj-breadcrumb d-flex" aria-label="面包屑导航"><Link to="/problems?view=library">总题库</Link><span aria-hidden="true">›</span><span>P{String(problem.id).padStart(4, '0')}</span><span aria-hidden="true">›</span><strong>{problem.title}</strong></nav>
    <div className="row problem-detail-row">
      <div id="problemMeta" data-problem-id={problem.id} style={{display: 'none'}} />
      <div className="col-md-6 mb-3 problem-col-left" id="problemStatementPane">
          <div className="problem-header mb-3"><div className={`problem-heading-layout${data.last_submissions?.length ? ' has-recent-submissions' : ''}`}><div className="problem-heading-info"><div className="numoj-problem-kickers d-flex"><span>{programming ? '编程题' : '书面题'}</span>{problem.lang ? <span>{lang}</span> : null}</div><div className="problem-title-row"><h2 className="mb-0 problem-title-singleline" id="problemTitleHeading"><strong className="problem-number">{problem.id}.</strong><span className="problem-title-text">{problem.title}</span></h2></div>{session?.user?.is_admin ? <div className="problem-admin-actions mt-2">
            {programming ? <><Link to={`/agents?problem_id=${problem.id}&mode=solve`} className="btn btn-outline-primary"><i className="fas fa-robot me-1" /> 解题</Link>{!isLean4 && Number(data.submit.programming_grading_mode || 1) === 1 ? <Link to={`/agents?problem_id=${problem.id}&mode=testdata`} className="btn btn-outline-primary"><i className="fas fa-robot me-1" /> 造数据</Link> : null}</> : null}
            <Link to={`/admin/problems/${problem.id}/edit`} className="btn btn-outline-warning me"><i className="fas fa-pencil-alt me-1" /> 编辑</Link>
            {isLean4 ? <><button type="button" className="btn btn-outline-warning" data-bs-toggle="modal" data-bs-target="#uploadLeanWorkspaceModal"><i className="fas fa-folder-open me-1" /> {data.lean_workspace ? '更新题目包' : '上传题目包'}</button>{data.lean_workspace ? <a href={`/api/admin/problems/${problem.id}/lean-workspace/download`} download className="btn btn-outline-secondary"><i className="fas fa-download me-1" /> v{data.lean_workspace.revision_number}</a> : null}</> : <button type="button" className="btn btn-outline-warning" data-bs-toggle="modal" data-bs-target="#uploadDataModal"><i className="fas fa-cloud-upload-alt me-1" /> 上传</button>}
            <button type="button" className="btn btn-outline-danger" onClick={() => {if (window.confirm('确认要重测本题的所有提交吗？')) rejudge.mutate()}} disabled={rejudge.isPending}><i className="fas fa-redo-alt me-1" /> 重测</button><button type="button" className="btn btn-outline-info" data-bs-toggle="modal" data-bs-target="#scoresModal" onClick={() => {scores.reset(); scores.mutate()}}><i className="fas fa-chart-bar me-1" /> 统计</button>
          </div> : null}</div>{data.last_submissions?.length ? <aside className="recent-submissions-card" aria-label="最近提交"><ul>{data.last_submissions.map((item) => <li key={item.id}><span className={`badge submission-status ${String(item.status || '').toLowerCase().replaceAll(' ', '-')}`} title={item.status}>{abbreviations[String(item.status)] || 'UN'}</span><span className="recent-submission-score">{item.score ?? '—'}/{problem.max_score ?? 100}</span><Link to={`/submissions/${item.id}`} className="recent-submission-arrow" aria-label={`查看提交 ${item.id} 详情`} title="查看详情"><svg viewBox="0 0 16 16"><path d="M3.5 8h8M8.5 4.5 12 8l-3.5 3.5" /></svg></Link></li>)}</ul></aside> : null}</div></div>
        <MarkdownContent html={data.rendered_content} className="problem-content numoj-markdown numoj-problem-code-rendering my-3" />
      </div>
      <div className="problem-detail-splitter" id="problemDetailSplitter" role="separator" tabIndex={0} aria-label="调整题面与作答区宽度" aria-orientation="vertical" aria-controls="problemStatementPane problemSubmissionPane" aria-valuemin={20} aria-valuemax={80} aria-valuenow={50} data-problem-detail-splitter />
      <div className="col-md-6 problem-col-right" id="problemSubmissionPane">
        <form className={`mb-4 problem-submit-form ${isPrompt ? 'problem-prompt-submit-form' : programming ? 'problem-code-submit-form' : 'problem-written-submit-form'}`} onSubmit={submitForm}>
          {programming ? <>
            <div className="d-flex justify-content-between align-items-end mb-2 problem-editor-toolbar"><label className="form-label mb-0 code-label-wrap"><span className="code-title-line"><i className={`fas ${isPrompt ? 'fa-terminal' : isLean4 ? 'fa-square-root-alt' : 'fa-code'} me-2`} /> {isPrompt ? 'Prompt' : isLean4 ? 'Lean 4 工作区' : '代码'}</span><span className="code-meta-line">{problem.lang ? <span className="badge bg-secondary"><i className="fas fa-language me-2" />{lang}</span> : null}<span className="badge bg-secondary"><i className="fas fa-stopwatch me-2" />{problem.time_limit_ms || '—'} ms</span></span></label><div className="d-flex flex-column align-items-end">{!session?.user?.is_admin && data.remaining_submissions != null ? <small className={`${data.remaining_submissions <= 3 ? 'text-danger' : 'text-muted'} mb-1`}>剩余提交次数: <strong>{data.remaining_submissions}</strong>/{problem.submission_limit || 10}</small> : null}<div className={`problem-editor-actions${!session?.user?.is_admin ? ' student-code-actions' : ''}`}>{!isPrompt ? <button type="button" className="btn btn-outline-secondary" onClick={() => lastCode.mutate()} disabled={lastCode.isPending}><i className="fas fa-copy me-1" /><span className="d-none d-md-inline">复用上次代码</span><span className="d-inline d-md-none">复用</span></button> : null}<button type="submit" className="btn btn-outline-primary" disabled={!data.can_submit || submit.isPending}><i className="fas fa-paper-plane me-2" />{submit.isPending ? '提交中…' : data.can_submit ? isPrompt ? '提交 Prompt' : isLean4 ? '提交证明' : '提交' : '已达上限'}</button></div></div></div>
            {isPrompt ? <textarea id="promptEditor" name="prompt" className="form-control" rows={18} required value={text} onChange={(event) => setText(event.target.value)} placeholder="请描述你的解题思路，包括算法或数据结构、关键步骤、状态更新和边界处理。后台会先审查 prompt，通过后再生成代码并评测。" /> : <div className={`card problem-editor-card${isLean4 ? ' lean-workbench-card' : ''}`}><div className="card-body p-0">{isLean4 ? <LeanWorkbench problemId={problem.id} workspace={data.lean_workspace} value={text} onChange={setText} onController={(controller) => {leanControllerRef.current = controller}} /> : <MonacoEditor language={String(problem.lang || 'matlab')} problemId={problem.id} value={text} onChange={setText} />}</div></div>}
          </> : <>
            <div className="problem-written-toolbar"><div className="problem-written-actions">{session?.user?.is_admin ? <button type="button" className="btn btn-outline-danger problem-written-cleanup-button" onClick={() => invalidateWrittenSubmissions.mutate()} disabled={invalidateWrittenSubmissions.isPending}><i className="fas fa-trash me-2" /> 移除无效提交</button> : data.remaining_submissions != null ? <span className={`problem-written-quota${data.remaining_submissions <= 2 ? ' is-low' : ''}`}>剩余提交次数: <strong>{data.remaining_submissions}</strong>/{problem.submission_limit || 10}</span> : null}<button type="submit" className="btn btn-outline-primary problem-written-submit-button" disabled={submit.isPending || (!session?.user?.is_admin && !data.can_submit)}><i className="fas fa-upload me-2" /> {submit.isPending ? '上传中…' : session?.user?.is_admin || data.can_submit ? '上传作业' : '已达上限'}</button></div></div>
            <div className="card problem-written-upload-card"><div className="card-body"><div className="problem-written-file-picker" data-file-kind={writtenFileKind}><input ref={fileRef} className="visually-hidden problem-written-file-input" type="file" id="file" name="file" accept={writtenIsZip ? '.zip' : '.pdf'} required onChange={(event) => setWrittenFileName(event.currentTarget.files?.[0]?.name || '')} /><label className={`problem-written-dropzone${writtenFileName ? ' has-file' : ''}${writtenDragDepth ? ' is-dragover' : ''}`} htmlFor="file" title={writtenFileName} onDragEnter={(event) => {event.preventDefault(); setWrittenDragDepth((depth) => depth + 1)}} onDragOver={(event) => {event.preventDefault(); event.dataTransfer.dropEffect = 'copy'}} onDragLeave={(event) => {event.preventDefault(); setWrittenDragDepth((depth) => Math.max(0, depth - 1))}} onDrop={(event) => {event.preventDefault(); setWrittenDragDepth(0); acceptWrittenDrop(event.dataTransfer.files)}}><span className="problem-written-dropzone-icon" aria-hidden="true"><i className={`fas ${writtenIsZip ? 'fa-file-archive' : 'fa-file-pdf'}`} /></span><span className="problem-written-dropzone-copy"><strong>上传文件</strong><small aria-live="polite">{writtenFileName || writtenFileKind}</small></span></label></div><div className="form-text problem-written-format-note">{writtenIsZip ? '请上传 zip 文件，压缩包内必须包含 main.tex 及其依赖文件。' : '请上传 pdf 文件。'}</div></div></div>
            {writtenMode === 4 ? <p className="text-muted problem-written-note"><i className="fas fa-info-circle me-1" /> 纯人工批改：重新提交将覆盖上一次提交，等待老师批改。</p> : <p className="text-muted problem-written-note">提示：书面作业可多次提交，以历史最高分计入成绩。</p>}
          </>}
          {submit.isError || lastCode.isError ? <div className="alert alert-danger mt-3" role="alert">{errorMessage(submit.error || lastCode.error)}</div> : !data.can_submit && data.submit_block_reason ? <div className="alert alert-warning mt-3">{data.submit_block_reason}</div> : null}
        </form>
      </div>
    </div>
    {session?.user?.is_admin ? <>{isLean4 ? <div className="modal fade" id="uploadLeanWorkspaceModal" tabIndex={-1} aria-labelledby="uploadLeanWorkspaceModalLabel" aria-hidden="true"><div className="modal-dialog"><form onSubmit={(event) => {event.preventDefault(); uploadLeanWorkspace.mutate(new FormData(event.currentTarget))}}><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="uploadLeanWorkspaceModalLabel"><i className="fas fa-folder-tree me-2" />发布 Lean 4 题目包</h5><button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="关闭" /></div><div className="modal-body"><label htmlFor="leanPackageZip" className="form-label">选择 ZIP 文件</label><input className="form-control" type="file" id="leanPackageZip" name="lean_package_zip" accept=".zip" required /><div className="form-text mt-2">ZIP 根目录需包含 <code>numoj-lean.json</code>。上传后会发布不可变新版本；已有提交仍绑定原版本。</div>{uploadLeanWorkspace.isError || uploadLeanWorkspace.isSuccess ? <div className={`alert mt-3 ${uploadLeanWorkspace.isSuccess ? 'alert-success' : 'alert-danger'}`}>{uploadLeanWorkspace.isError ? errorMessage(uploadLeanWorkspace.error) : uploadLeanWorkspace.data?.message}</div> : null}</div><div className="modal-footer"><button type="button" className="btn btn-outline-secondary" data-bs-dismiss="modal">取消</button><button type="submit" className="btn btn-outline-primary" disabled={uploadLeanWorkspace.isPending}><i className="fas fa-cloud-upload-alt me-2" />{uploadLeanWorkspace.isPending ? '发布中…' : '发布'}</button></div></div></form></div></div> : <div className="modal fade" id="uploadDataModal" tabIndex={-1} aria-labelledby="uploadDataModalLabel" aria-hidden="true"><div className="modal-dialog"><form onSubmit={(event) => {event.preventDefault(); uploadData.mutate(new FormData(event.currentTarget))}}><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="uploadDataModalLabel"><i className="fas fa-cloud-upload-alt me-2" /> 上传测试数据</h5><button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="关闭" /></div><div className="modal-body"><div className="mb-3"><label htmlFor="testDataZip" className="form-label">选择 ZIP 文件</label><input className="form-control" type="file" id="testDataZip" name="testdata_zip" accept=".zip" required /><div className="form-text">上传包含 1.in, 1.out, 2.in, 2.out 等文件的 ZIP 包。</div></div>{uploadData.isError || uploadData.isSuccess ? <div className={`alert ${uploadData.isSuccess ? 'alert-success' : 'alert-danger'}`}>{uploadData.isError ? errorMessage(uploadData.error) : uploadData.data?.message}</div> : null}</div><div className="modal-footer"><button type="button" className="btn btn-outline-secondary" data-bs-dismiss="modal"><i className="fas fa-times me-2" /> 取消</button><button type="submit" className="btn btn-outline-primary" disabled={uploadData.isPending}><i className="fas fa-cloud-upload-alt me-2" /> {uploadData.isPending ? '上传中…' : '上传'}</button></div></div></form></div></div>}<RejudgeProgressModal progress={rejudgeProgress} /><ScoresModal data={scores.data} pending={scores.isIdle || scores.isPending} error={scores.error} /></> : null}
  </div>
}
