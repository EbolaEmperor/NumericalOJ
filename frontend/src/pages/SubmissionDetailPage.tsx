import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useState} from 'react'
import {Link, useNavigate, useParams} from 'react-router-dom'

import {apiFetch} from '../api/client'
import type {ApiEnvelope, JsonRecord, ProblemSummary} from '../api/types'
import {MonacoEditor} from '../components/MonacoEditor'
import {ErrorState, LoadingState} from '../components/PageState'

interface LeanFile extends JsonRecord {path: string; mode: string; content: string}
interface LeanWorkspace extends JsonRecord {revision?: string; revision_number?: number; default_file?: string; files?: LeanFile[]}
interface DetailResponse extends ApiEnvelope {user?: {is_admin?: number}; submission: {id: number; problem_id: number; problem_title?: string; problem_type?: number; username?: string; status?: string; score?: number; code?: string; prompt_text?: string; generated_from_prompt?: boolean; prompt_generation_error?: string; created_at?: string}; problem?: ProblemSummary & {written_grading_mode?: number}; plang?: string; test_points: JsonRecord[]; lean_workspace?: LeanWorkspace | null; cached_ai_code_marks?: JsonRecord; submission_latex_text?: string; submission_latex_error?: string; submission_latex_html?: string; written_submission?: {show_latex_transcription?: boolean}}
type ModalInstance = {show(): void; hide(): void}
type ModalConstructor = {new(element: HTMLElement): ModalInstance; getOrCreateInstance?: (element: HTMLElement) => ModalInstance; getInstance?: (element: HTMLElement) => ModalInstance | null}

function modalConstructor() {
  return (window as unknown as {bootstrap?: {Modal?: ModalConstructor}}).bootstrap?.Modal
}

function statusClass(value: unknown) {return String(value || 'Unknown').toLowerCase().replaceAll(' ', '-')}
function pointClass(value: unknown) {const status = String(value || 'Unknown'); return status === 'Accepted' ? 'is-accepted' : ['Pending', 'Waiting', 'Running', 'Generating'].includes(status) ? 'is-active' : status === 'Wrong Answer' ? 'is-wrong-answer' : status === 'Runtime Error' ? 'is-runtime-error' : status === 'Time Limit Exceeded' ? 'is-time-limit' : ['Unaccepted', 'Compile Error', 'Memory Limit Exceeded', 'Output Limit Exceeded', 'Forbidden', 'No Output', 'Nonzero Exit Status', 'Error'].includes(status) ? 'is-other-failure' : 'is-neutral'}

const shortStatuses: Record<string, string> = {'Accepted': 'AC', 'Wrong Answer': 'WA', 'Compile Error': 'CE', 'Runtime Error': 'RE', 'Time Limit Exceeded': 'TLE', 'Memory Limit Exceeded': 'MLE', 'Output Limit Exceeded': 'OLE', 'Forbidden': 'FB', 'No Output': 'NO', 'Nonzero Exit Status': 'NZ', 'Pending': 'PD', 'Waiting': 'WT', 'Running': 'RUN', 'Generating': 'GEN', 'Error': 'ERR', 'Unaccepted': 'UA'}

function pointStatusShort(value: unknown) {
  const status = String(value || '').trim()
  return shortStatuses[status] || (status ? status.slice(0, 3).toUpperCase() : '...')
}

function TestPointDetail({point, index, submissionId, lean}: {point: JsonRecord; index: number; submissionId: number; lean: boolean}) {
  const [imageFailed, setImageFailed] = useState(false)
  const status = String(point.status || 'Running')
  const stderr = String(point.stderr || '').trim()
  const stdout = String(point.stdout || '').trim()
  const comment = String(point.comment || '').trim()
  const hasImage = Boolean(point.has_output_image)
  const testIndex = Number(point.test_index || index + 1)
  const time = point.time === 0 || point.time ? `${String(point.time)} ms` : '--'
  const showStderr = Boolean(stderr) && status !== 'Time Limit Exceeded' && status !== 'Accepted'
  const showStdout = Boolean(stdout) && status !== 'Accepted'
  // 旧版以原始数据是否存在决定是否显示“暂无详情”；即使 Accepted 隐藏
  // stdout，只要判题器返回过 stdout，也不会再显示空态提示。
  const noDetail = !stderr && !stdout && !comment && !hasImage
  const imageUrl = `/api/submissions/${submissionId}/outputs/${testIndex}/image`
  return <div className="submission-test-detail">
    <header><span>SELECTED</span><strong>{lean ? `Lean kernel 验证 (${pointStatusShort(status)})` : `测试点 #${index + 1} (${pointStatusShort(status)})`}</strong></header>
    {noDetail ? <div className="submission-test-detail-hint">{lean ? '该证明暂无更多验证详情。' : '该测试点暂无更多详情。'}</div> : null}
    <div className="submission-test-detail-meta">状态：{status} | 运行时间：{time}</div>
    {showStderr ? <section className="submission-test-detail-block"><h3>{lean ? 'Lean 4 错误' : '错误信息'}</h3><pre className="tp-detail-pre">{stderr}</pre></section> : null}
    {showStdout ? <section className="submission-test-detail-block"><h3>{lean ? '验证输出' : '程序输出'}</h3><pre className="tp-detail-pre">{stdout}</pre></section> : null}
    {comment ? <section className="submission-test-detail-block"><h3>{lean ? '验证说明' : hasImage ? 'AI 评语' : '评测说明'}</h3><pre className="tp-detail-pre">{comment}</pre></section> : null}
    {hasImage && !imageFailed ? <section className="submission-test-detail-block"><h3>输出图片</h3><button type="button" className="border-0 bg-transparent p-0" onClick={() => {const image = document.getElementById('modalImage') as HTMLImageElement | null; const link = document.getElementById('downloadImageBtn') as HTMLAnchorElement | null; if (image) {image.src = imageUrl; image.alt = `测试点${index + 1}输出图片`} if (link) link.href = imageUrl; const element = document.getElementById('imageModal'); const Modal = modalConstructor(); if (element && Modal) (Modal.getOrCreateInstance?.(element) || new Modal(element)).show()}}><img className="submission-test-output-image" src={imageUrl} alt={`测试点${index + 1}输出图片`} onError={() => setImageFailed(true)} /></button></section> : null}
  </div>
}

type LeanTreeNode = {folders: Map<string, LeanTreeNode>; files: LeanFile[]}

function LeanTree({files, active, select}: {files: LeanFile[]; active: string; select: (path: string) => void}) {
  const root: LeanTreeNode = {folders: new Map(), files: []}
  files.forEach((file) => {
    const parts = file.path.split('/')
    let node = root
    parts.slice(0, -1).forEach((part) => {
      if (!node.folders.has(part)) node.folders.set(part, {folders: new Map(), files: []})
      node = node.folders.get(part)!
    })
    node.files.push(file)
  })
  const Branch = ({node}: {node: LeanTreeNode}) => <ul className="lean-file-tree-list" role="group">
    {[...node.folders.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([name, child]) => <li key={`folder-${name}`}><button type="button" className="lean-file-tree-row" role="treeitem" aria-expanded="true"><span className="lean-file-tree-chevron" aria-hidden="true">▾</span><i className="lean-file-tree-icon fas fa-folder" aria-hidden="true" /><span className="lean-file-tree-label">{name}</span></button><Branch node={child} /></li>)}
    {[...node.files].sort((a, b) => a.path.localeCompare(b.path)).map((file) => {const label = file.path.split('/').at(-1) || file.path; const readonly = file.mode === 'readonly'; return <li key={file.path}><button type="button" className={`lean-file-tree-row ${readonly ? 'is-readonly' : 'is-writable'}${active === file.path ? ' is-active' : ''}`} role="treeitem" aria-current={active === file.path ? 'true' : 'false'} title={`${file.path}${readonly ? '（题目只读文件）' : '（学生提交文件）'}`} onClick={() => select(file.path)}><span className="lean-file-tree-chevron" aria-hidden="true" /><i className={`lean-file-tree-icon fas ${readonly ? 'fa-lock' : 'fa-pen'}`} aria-hidden="true" /><span className="lean-file-tree-label">{label}</span></button></li>})}
  </ul>
  return <Branch node={root} />
}

function LeanSubmissionSurface({workspace, problemId}: {workspace: LeanWorkspace; problemId: number}) {
  const files = (workspace.files || []).filter((file) => file.path)
  const requested = String(workspace.default_file || '')
  const [active, setActive] = useState(files.some((file) => file.path === requested) ? requested : files[0]?.path || '')
  const file = files.find((item) => item.path === active) || files[0]
  const readonly = file?.mode === 'readonly'
  return <div className="submission-code-surface submission-lean-workspace" id="submissionEditorShell">
    <aside className="lean-file-explorer submission-lean-file-explorer" aria-label="本次提交的 Lean 文件"><header className="lean-file-explorer-bar"><span>Files</span><span className="lean-file-count">{files.length}</span></header><div className="lean-file-tree" role="tree"><LeanTree files={files} active={file?.path || ''} select={setActive} /></div></aside>
    <section className="submission-lean-editor-pane" aria-label="Lean 4 文件内容"><header className="submission-lean-editor-bar"><span className="submission-lean-active-file"><span className="lean-file-mark" aria-hidden="true">λ</span><span title={file?.path}>{file?.path || 'Submission.lean'}</span><span className={`submission-lean-file-mode${readonly ? ' is-readonly' : ''}`}>{readonly ? '题目只读' : '学生提交'}</span></span><span className="submission-lean-revision" title={`工作区版本 ${String(workspace.revision || '')}`}>R{String(workspace.revision_number || 0)}</span></header><div className="submission-lean-editor-body">{file ? <MonacoEditor key={file.path} language="lean4" problemId={problemId} value={file.content || ''} onChange={() => undefined} idPrefix={`submission-lean-${file.path.replace(/[^a-z0-9]/gi, '-')}`} ariaLabel="Lean 4 提交文件，只读" readOnly fontSize={14} lineHeight={22} shellClassName="submission-editor-shell" hostClassName="submission-monaco-container" fallbackClassName="submission-code-fallback" /> : null}</div></section>
  </div>
}

function WrittenPdf({submission}: {submission: DetailResponse['submission']}) {
  const active = ['Pending', 'Waiting', 'Running', 'Generating'].includes(String(submission.status || ''))
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  const url = `/api/submissions/${submission.id}/file`
  useEffect(() => {
    let cancelled = false
    setState('loading')
    void fetch(url, {method: 'HEAD', cache: 'no-store', credentials: 'same-origin'}).then((response) => {if (!cancelled) setState(response.ok ? 'ready' : 'error')}).catch(() => {if (!cancelled) setState('error')})
    return () => {cancelled = true}
  }, [url, submission.status])
  return <div className="submission-pdf-surface" id="pdfViewer">{state === 'ready' ? <iframe title="submission-pdf" className="w-100 h-100 border-0" referrerPolicy="no-referrer" src={url} /> : <div className={`submission-pdf-hint ${state === 'error' ? 'text-danger' : 'text-muted'}`}>{state === 'error' ? '暂无可渲染的 PDF（可能是编译失败）。' : <span className="math-curve-loader" data-math-curve-loader data-size="lg"><span className="math-curve-loader__label">{active ? 'PDF 生成中，请稍候...' : '正在加载 PDF…'}</span></span>}</div>}</div>
}

function WrittenResults({data, refresh}: {data: DetailResponse; refresh: () => void}) {
  const navigate = useNavigate()
  const submission = data.submission
  const isAdmin = Number(data.user?.is_admin) === 1
  const [score, setScore] = useState(String(submission.score ?? 0))
  const [comment, setComment] = useState(submission.code || '')
  const save = useMutation({mutationFn: () => {const body = new FormData(); body.append('score', score); body.append('comment', comment); return apiFetch<ApiEnvelope>(`/api/admin/submissions/${submission.id}/grade`, {method: 'POST', body})}, onSuccess: refresh})
  const next = useMutation({mutationFn: () => apiFetch<ApiEnvelope & {next_submission_id?: number}>(`/api/admin/submissions/${submission.id}/next-pending`), onSuccess: (payload) => {if (payload.next_submission_id) navigate(`/submissions/${payload.next_submission_id}`)}})
  const openEditor = () => {
    setScore(String(submission.score ?? 0)); setComment(submission.code || '')
    const element = document.getElementById('gradeEditModal')
    const Modal = modalConstructor()
    if (element && Modal) (Modal.getOrCreateInstance?.(element) || new Modal(element)).show()
  }
  const closeEditor = () => {
    const element = document.getElementById('gradeEditModal')
    const Modal = modalConstructor()
    if (element && Modal) Modal.getInstance?.(element)?.hide()
  }
  useEffect(() => {if (save.isSuccess) closeEditor()}, [save.isSuccess])
  const rawComment = submission.code || ''
  return <>
    <section className="submission-detail-section"><header className="submission-detail-section-heading"><div><span>GRADING</span><h2>批改结果</h2></div>{isAdmin ? <div className="submission-detail-inline-actions"><button type="button" className="submission-button submission-button--ghost" id="openGradeEditorBtn" onClick={openEditor}><i className="fas fa-pen-to-square" aria-hidden="true" /> 编辑</button><button type="button" className="submission-button submission-button--ghost" id="nextBtn" disabled={next.isPending} onClick={() => next.mutate()}>下一个 <i className="fas fa-arrow-right" aria-hidden="true" /></button></div> : null}</header><div id="studentCommentRendered" className="submission-written-comment">{rawComment.trim() ? rawComment.split('\n').map((line, index) => <span key={index}>{line}{index < rawComment.split('\n').length - 1 ? <br /> : null}</span>) : <span className="text-muted">暂无评语</span>}</div></section>
    {data.written_submission?.show_latex_transcription ? <details className="submission-detail-disclosure submission-latex-card"><summary><span>LATEX TRANSCRIPTION</span><i className="fas fa-chevron-down" aria-hidden="true" /></summary><div id="submissionLatexRendered" className="submission-latex-content">{data.submission_latex_html ? <span dangerouslySetInnerHTML={{__html: data.submission_latex_html}} /> : data.submission_latex_error ? <span className="text-danger">{data.submission_latex_error}</span> : <span className="text-muted">暂无 LaTeX 转写结果。</span>}</div></details> : null}
    {isAdmin ? <div className="modal fade" id="gradeEditModal" tabIndex={-1} aria-labelledby="gradeEditModalLabel" aria-hidden="true"><div className="modal-dialog modal-lg"><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="gradeEditModalLabel"><i className="fas fa-pen-to-square me-2" />编辑批改结果</h5><button type="button" className="btn-close" aria-label="Close" onClick={closeEditor} /></div><div className="modal-body"><div className="mb-3"><label htmlFor="editScoreInput" className="form-label"><i className="fas fa-trophy me-2" />给分 (0-5 分)</label><input type="number" className="form-control" id="editScoreInput" name="score" min={0} max={5} step={1} required value={score} onChange={(event) => setScore(event.target.value)} /></div><div className="mb-0"><label htmlFor="editCommentInput" className="form-label"><i className="fas fa-comment me-2" />评语</label><textarea className="form-control" id="editCommentInput" name="comment" rows={14} value={comment} onChange={(event) => setComment(event.target.value)} /></div>{save.isError ? <div className="alert alert-danger mt-3 mb-0">提交失败：{save.error.message}</div> : null}</div><div className="modal-footer"><button type="button" className="btn btn-outline-secondary" onClick={closeEditor}><i className="fas fa-times me-2" />取消</button><button type="button" className="btn btn-outline-success" id="submitGradeBtn" disabled={save.isPending} onClick={() => save.mutate()}><i className="fas fa-check me-2" />{save.isPending ? '提交中…' : '保存并提交'}</button></div></div></div></div> : null}
  </>
}

function AiTutor({submissionId, cached}: {submissionId: number; cached?: JsonRecord}) {
  const ask = useMutation({mutationFn: () => apiFetch<ApiEnvelope & JsonRecord>('/api/ai/code-marks', {method: 'POST', body: JSON.stringify({submission_id: submissionId})})})
  const response = ask.data || cached
  return <section className="submission-detail-section submission-ai-section"><header className="submission-detail-section-heading"><div><span>AI TUTOR</span><h2>代码诊断</h2></div></header><button type="button" className="submission-button submission-button--ghost" id="askAiBtn" disabled={ask.isPending} onClick={() => ask.mutate()}><i className="fas fa-robot" aria-hidden="true" /> {ask.isPending ? 'AI 分析中…' : '询问 AI 助教'}</button>{ask.isError ? <div className="submission-ai-status is-danger" role="status">{ask.error.message}</div> : null}{response ? <div className="submission-ai-hint">鼠标移动到红色波浪线上可查看更详细的错误。</div> : null}</section>
}

export default function SubmissionDetailPage() {
  const {submissionId} = useParams()
  const [selectedPoint, setSelectedPoint] = useState(0)
  const result = useQuery({queryKey: ['submission', submissionId], queryFn: () => apiFetch<DetailResponse>(`/api/submissions/${submissionId}`), refetchInterval: (query) => {const status = (query.state.data as DetailResponse | undefined)?.submission.status; return status && ['Pending', 'Running', 'Generating'].includes(status) ? 2_000 : false}})
  const rejudge = useMutation({mutationFn: () => apiFetch<ApiEnvelope>(`/api/submissions/${submissionId}/rejudge`, {method: 'POST'}), onSuccess: () => void result.refetch()})
  if (result.isPending) return <LoadingState label="正在读取提交快照" />
  if (result.isError) return <ErrorState message={result.error.message} />
  const data = result.data!
  const submission = data.submission
  const programming = Number(submission.problem_type || data.problem?.type || 1) === 1
  const lean = programming && ['lean', 'lean4'].includes(String(data.plang || '').toLowerCase())
  const maxScore = programming ? data.test_points.length || Number(data.problem?.max_score || 0) || '?' : 5
  const accepted = submission.score != null && String(submission.score) === String(maxScore)
  const activePointIndex = Math.min(selectedPoint, Math.max(0, data.test_points.length - 1))
  const activePoint = data.test_points[activePointIndex]
  return <div className="submission-detail-page" data-math-curve-stroke-scale="1.2">
    <section className="submission-detail-primary" aria-label={lean ? 'Lean 4 提交文件' : programming ? '提交代码' : '书面作业 PDF'}>{programming ? lean && data.lean_workspace ? <LeanSubmissionSurface workspace={data.lean_workspace} problemId={submission.problem_id} /> : <div className="submission-code-surface"><MonacoEditor language={data.plang || 'matlab'} problemId={submission.problem_id} value={submission.code || ''} onChange={() => undefined} idPrefix="submission" ariaLabel="提交代码，只读" readOnly fontSize={14} lineHeight={22} shellClassName="submission-editor-shell" hostClassName="submission-monaco-container" fallbackClassName="submission-code-fallback" /></div> : <WrittenPdf submission={submission} />}</section>
    <aside className="submission-detail-summary-card" aria-label="提交摘要"><div className="submission-detail-topline"><Link className="submission-detail-back" to={`/submissions?problem_id=${submission.problem_id}`}><i className="fas fa-arrow-left" /> SUBMISSIONS</Link><span className="submission-detail-id">#{submission.id}</span></div><h1 className="visually-hidden">提交 #{submission.id}</h1><div className="submission-detail-result"><span className={`submission-verdict submission-verdict--${statusClass(submission.status)}`}><span className="submission-verdict__dot" /><span>{submission.status || 'Unknown'}</span></span><div className="submission-detail-score"><strong className={accepted ? 'is-accepted' : submission.score ? 'is-partial' : 'is-failed'}>{submission.score ?? '—'}</strong><span>/ <span>{maxScore}</span></span></div></div><dl className="submission-detail-meta"><dt>题目</dt><dd className="submission-detail-problem-meta"><Link to={`/problems/${submission.problem_id}`}>{data.problem?.title || submission.problem_title || '未命名题目'}</Link><span>P{String(submission.problem_id).padStart(4, '0')}</span></dd><dt>提交者</dt><dd>{submission.username}</dd><dt>提交时间</dt><dd>{submission.created_at || '—'}</dd></dl>{submission.generated_from_prompt ? <details className="submission-detail-disclosure submission-prompt-card" open><summary><span>ORIGINAL PROMPT</span><i className="fas fa-chevron-down" /></summary><pre>{submission.prompt_text || ''}</pre>{submission.prompt_generation_error ? <div className="submission-inline-error">{submission.prompt_generation_error}</div> : null}</details> : null}{Number(data.user?.is_admin) === 1 ? <><button type="button" className="submission-button submission-button--accent submission-detail-rejudge" disabled={rejudge.isPending} onClick={() => {if (window.confirm('确认重测这条提交吗？')) rejudge.mutate()}}><i className="fas fa-rotate-right" />{rejudge.isPending ? '正在提交重测…' : '重测此提交'}</button><div className={`submission-action-feedback${rejudge.isSuccess ? ' is-success' : rejudge.isError ? ' is-error' : ''}`} role="status">{rejudge.isSuccess ? '已加入重测队列' : rejudge.isError ? `重测失败：${rejudge.error.message}` : ''}</div></> : null}</aside>
    <aside className="submission-detail-results" aria-label={lean ? '证明验证详情' : programming ? '测试点详情' : '批改详情'}>{programming ? <><section className="submission-detail-section"><header className="submission-detail-section-heading"><div><span>{lean ? 'PROOF CHECK' : 'TEST POINTS'}</span></div></header><div className="test-point-grid">{data.test_points.map((point, index) => <button className={`test-point-card ${pointClass(point.status)}${index === activePointIndex ? ' selected' : ''}`} type="button" title={lean ? `证明验证 · ${String(point.status || 'Unknown')}` : `测试点 #${index + 1} · ${String(point.status || 'Unknown')}`} aria-label={lean ? `证明验证，${String(point.status || 'Unknown')}` : `测试点 ${index + 1}，${String(point.status || 'Unknown')}`} aria-pressed={index === activePointIndex} onClick={() => setSelectedPoint(index)} key={index}><span className="tp-index">{lean ? '⊢' : String(index + 1).padStart(2, '0')}</span>{pointClass(point.status) === 'is-active' ? <span className="math-curve-loader" data-math-curve-loader data-icon-only="true" data-size="xs" /> : null}</button>)}</div>{activePoint ? <TestPointDetail point={activePoint} index={activePointIndex} submissionId={submission.id} lean={lean} /> : <div className="submission-test-detail-hint">{lean ? '证明验证中，结果稍后显示。' : '判题中，暂时没有可展示的测试点结果。'}</div>}</section>{submission.status === 'Unaccepted' ? <AiTutor submissionId={submission.id} cached={data.cached_ai_code_marks} /> : null}</> : <WrittenResults data={data} refresh={() => void result.refetch()} />}</aside>
    <div className="modal fade" id="imageModal" tabIndex={-1} aria-labelledby="imageModalLabel" aria-hidden="true"><div className="modal-dialog modal-xl"><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="imageModalLabel"><i className="fas fa-image me-2" /> 输出图片</h5><button type="button" className="btn-close" aria-label="Close" onClick={() => {const element = document.getElementById('imageModal'); const Modal = modalConstructor(); if (element && Modal) Modal.getInstance?.(element)?.hide()}} /></div><div className="modal-body text-center"><img id="modalImage" src="" alt="" className="submission-modal-image" /></div><div className="modal-footer"><button type="button" className="btn btn-secondary" onClick={() => {const element = document.getElementById('imageModal'); const Modal = modalConstructor(); if (element && Modal) Modal.getInstance?.(element)?.hide()}}><i className="fas fa-times me-2" />关闭</button><a id="downloadImageBtn" href="" download className="btn btn-primary"><i className="fas fa-download me-2" />下载图片</a></div></div></div></div>
  </div>
}
