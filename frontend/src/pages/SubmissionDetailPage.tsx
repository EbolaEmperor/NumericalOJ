import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useCallback, useEffect, useMemo, useRef, useState} from 'react'
import {useLocation, useParams} from 'react-router-dom'

import {apiFetch} from '../api/client'
import type {ApiEnvelope, JsonRecord, ProblemSummary} from '../api/types'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {Link, useNavigate} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'
import {MarkdownContent} from '../components/MarkdownContent'
import {MonacoEditor, type MonacoEditorInstance, type MonacoEditorReadyContext} from '../components/MonacoEditor'
import {ReactModal} from '../components/ReactModal'
import {usePersistentVerticalSplitter} from '../components/usePersistentVerticalSplitter'
import {clearMath, typesetMath} from '../markdown/mathjaxRuntime'
import type {MonacoModel} from '../editor/types'
import {loadSubmissionOrigin, rememberSubmissionOrigin, submissionOriginFromState} from '../lib/submissionNavigation'
import {submissionStatusIsActive, type SubmissionStatusSnapshot, useSubmissionStatusStream} from './submission/submissionStatusStream'
import {streamAiCodeMarks} from './submission/aiCodeMarksStream'

interface LeanFile extends JsonRecord {path: string; mode: string; content: string}
interface LeanWorkspace extends JsonRecord {revision?: string; revision_number?: number; default_file?: string; files?: LeanFile[]}
interface DetailResponse extends ApiEnvelope {user?: {is_admin?: number}; submission: {id: number; problem_id: number; problem_title?: string; problem_type?: number; username?: string; status?: string; score?: number | null; code?: string; prompt_text?: string; generated_from_prompt?: boolean; prompt_generation_error?: string; created_at?: string}; problem?: ProblemSummary & {written_grading_mode?: number}; plang?: string; test_points: JsonRecord[]; lean_workspace?: LeanWorkspace | null; cached_ai_code_marks?: JsonRecord; submission_latex_text?: string; submission_latex_error?: string; submission_latex_html?: string; written_submission?: {show_latex_transcription?: boolean}}
type SubmissionEditorContext = MonacoEditorReadyContext & {setDisplayCode: (value: string) => void}

const submissionDetailQueryKey = (submissionId: string | undefined) => ['submission', submissionId] as const

export function mergeSubmissionDetailSnapshot(current: DetailResponse | undefined, snapshot: SubmissionStatusSnapshot) {
  if (!current) return current
  const submission = {...current.submission}
  if (snapshot.status !== undefined) submission.status = String(snapshot.status)
  if (Object.prototype.hasOwnProperty.call(snapshot, 'score')) submission.score = snapshot.score ?? null
  if (snapshot.generated_from_prompt !== undefined) submission.generated_from_prompt = Boolean(snapshot.generated_from_prompt)
  if (snapshot.code !== undefined) submission.code = String(snapshot.code || '')
  if (snapshot.prompt_generation_error !== undefined || snapshot.promptly_review_reply !== undefined) {
    submission.prompt_generation_error = String(snapshot.promptly_review_reply || snapshot.prompt_generation_error || '')
  }
  if (snapshot.written_comment !== undefined) submission.code = String(snapshot.written_comment || '')
  return {
    ...current,
    submission,
    test_points: Array.isArray(snapshot.test_points) ? snapshot.test_points : current.test_points,
    submission_latex_text: snapshot.written_latex_text === undefined ? current.submission_latex_text : String(snapshot.written_latex_text || ''),
    submission_latex_html: snapshot.written_latex_html === undefined ? current.submission_latex_html : String(snapshot.written_latex_html || ''),
    submission_latex_error: snapshot.written_latex_error === undefined ? current.submission_latex_error : String(snapshot.written_latex_error || ''),
  }
}
function statusClass(value: unknown) {return String(value || 'Unknown').toLowerCase().replaceAll(' ', '-')}
function pointClass(value: unknown) {const status = String(value || 'Unknown'); return status === 'Accepted' ? 'is-accepted' : ['Pending', 'Waiting', 'Running', 'Generating'].includes(status) ? 'is-active' : status === 'Wrong Answer' ? 'is-wrong-answer' : status === 'Runtime Error' ? 'is-runtime-error' : status === 'Time Limit Exceeded' ? 'is-time-limit' : ['Unaccepted', 'Compile Error', 'Memory Limit Exceeded', 'Output Limit Exceeded', 'Forbidden', 'No Output', 'Nonzero Exit Status', 'Error'].includes(status) ? 'is-other-failure' : 'is-neutral'}

const shortStatuses: Record<string, string> = {'Accepted': 'AC', 'Wrong Answer': 'WA', 'Compile Error': 'CE', 'Runtime Error': 'RE', 'Time Limit Exceeded': 'TLE', 'Memory Limit Exceeded': 'MLE', 'Output Limit Exceeded': 'OLE', 'Forbidden': 'FB', 'No Output': 'NO', 'Nonzero Exit Status': 'NZ', 'Pending': 'PD', 'Waiting': 'WT', 'Running': 'RUN', 'Generating': 'GEN', 'Error': 'ERR', 'Unaccepted': 'UA'}

function pointStatusShort(value: unknown) {
  const status = String(value || '').trim()
  return shortStatuses[status] || (status ? status.slice(0, 3).toUpperCase() : '...')
}

export function defaultTestPointIndex(points: JsonRecord[]) {
  const failed = points.findIndex((point) => {
    const status = String(point.status || '')
    return status && status !== 'Accepted' && !submissionStatusIsActive(status)
  })
  return failed >= 0 ? failed : 0
}

function submissionSplitValueText(informationPercent: number, contentPercent: number) {
  return `提交信息 ${informationPercent}%，提交内容 ${contentPercent}%`
}

function TestPointDetail({point, index, submissionId, lean, omniAnalysis, onOpenImage}: {point: JsonRecord; index: number; submissionId: number; lean: boolean; omniAnalysis?: string; onOpenImage: (image: {url: string; alt: string}) => void}) {
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
  const noDetail = !stderr && !stdout && !comment && !hasImage && !omniAnalysis
  const imageUrl = `/api/submissions/${submissionId}/outputs/${testIndex}/image`
  return <div className="submission-test-detail">
    <header><span>SELECTED</span><strong>{lean ? `Lean kernel 验证 (${pointStatusShort(status)})` : `测试点 #${index + 1} (${pointStatusShort(status)})`}</strong></header>
    {noDetail ? <div className="submission-test-detail-hint">{lean ? '该证明暂无更多验证详情。' : '该测试点暂无更多详情。'}</div> : null}
    <div className="submission-test-detail-meta">状态：{status} | 运行时间：{time}</div>
    {showStderr ? <section className="submission-test-detail-block"><h3>{lean ? 'Lean 4 错误' : '错误信息'}</h3><pre className="tp-detail-pre">{stderr}</pre></section> : null}
    {showStdout ? <section className="submission-test-detail-block"><h3>{lean ? '验证输出' : '程序输出'}</h3><pre className="tp-detail-pre">{stdout}</pre></section> : null}
    {comment ? <section className="submission-test-detail-block"><h3>{lean ? '验证说明' : hasImage ? 'AI 评语' : '评测说明'}</h3><pre className="tp-detail-pre">{comment}</pre></section> : null}
    {hasImage && !imageFailed ? <section className="submission-test-detail-block"><h3>输出图片</h3><button type="button" className="border-0 bg-transparent p-0" onClick={() => onOpenImage({url: imageUrl, alt: `测试点${index + 1}输出图片`})}><img className="submission-test-output-image" src={imageUrl} alt={`测试点${index + 1}输出图片`} onError={() => setImageFailed(true)} /></button></section> : null}
    {omniAnalysis ? <section className="submission-test-detail-block"><h3>Omni 图片分析</h3><pre className="tp-detail-pre">{omniAnalysis}</pre></section> : null}
  </div>
}

type LeanTreeNode = {folders: Map<string, LeanTreeNode>; files: LeanFile[]}

function LeanTreeBranch({node, active, select}: {node: LeanTreeNode; active: string; select: (path: string) => void}) {
  return <ul className="lean-file-tree-list" role="group">
    {[...node.folders.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([name, child]) => <LeanTreeFolder name={name} node={child} active={active} select={select} key={`folder-${name}`} />)}
    {[...node.files].sort((a, b) => a.path.localeCompare(b.path)).map((file) => {const label = file.path.split('/').at(-1) || file.path; const readonly = file.mode === 'readonly'; return <li key={file.path}><button type="button" className={`lean-file-tree-row ${readonly ? 'is-readonly' : 'is-writable'}${active === file.path ? ' is-active' : ''}`} role="treeitem" aria-current={active === file.path ? 'true' : 'false'} title={`${file.path}${readonly ? '（题目只读文件）' : '（学生提交文件）'}`} onClick={() => select(file.path)}><span className="lean-file-tree-chevron" aria-hidden="true" /><i className={`lean-file-tree-icon fas ${readonly ? 'fa-lock' : 'fa-pen'}`} aria-hidden="true" /><span className="lean-file-tree-label">{label}</span></button></li>})}
  </ul>
}

function LeanTreeFolder({name, node, active, select}: {name: string; node: LeanTreeNode; active: string; select: (path: string) => void}) {
  const [expanded, setExpanded] = useState(true)
  return <li><button type="button" className="lean-file-tree-row" role="treeitem" aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}><span className="lean-file-tree-chevron" aria-hidden="true">{expanded ? '▾' : '▸'}</span><i className="lean-file-tree-icon fas fa-folder" aria-hidden="true" /><span className="lean-file-tree-label">{name}</span></button>{expanded ? <LeanTreeBranch node={node} active={active} select={select} /> : null}</li>
}

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
  return <LeanTreeBranch node={root} active={active} select={select} />
}

function LeanSubmissionSurface({workspace, onEditorReady}: {workspace: LeanWorkspace; onEditorReady: (context: SubmissionEditorContext) => void | (() => void)}) {
  const files = (workspace.files || []).filter((file) => file.path)
  const requested = String(workspace.default_file || '')
  const [active, setActive] = useState(files.some((file) => file.path === requested) ? requested : files[0]?.path || '')
  const editorRef = useRef<MonacoEditorInstance | null>(null)
  const modelsRef = useRef(new Map<string, MonacoModel>())
  const viewStatesRef = useRef(new Map<string, unknown>())
  const activeRef = useRef(active)
  const file = files.find((item) => item.path === active) || files[0]
  const readonly = file?.mode === 'readonly'
  const selectFile = (path: string) => {
    const editor = editorRef.current
    const previous = activeRef.current
    if (editor && previous !== path) viewStatesRef.current.set(previous, editor.saveViewState?.())
    activeRef.current = path
    setActive(path)
    const model = modelsRef.current.get(path)
    if (editor && model) {
      editor.setModel?.(model)
      editor.updateOptions?.({readOnly: true, domReadOnly: true, ariaLabel: `Lean 4 提交文件 ${path}，只读`})
      const viewState = viewStatesRef.current.get(path)
      if (viewState) editor.restoreViewState?.(viewState)
      editor.layout()
    }
  }
  const onReady = (context: MonacoEditorReadyContext) => {
    const {monaco, editor} = context
    editorRef.current = editor
    const models = new Map<string, MonacoModel>()
    files.forEach((item) => {
      const encoded = item.path.split('/').map(encodeURIComponent).join('/')
      models.set(item.path, monaco.editor.createModel(item.content || '', 'lean4', monaco.Uri.parse(`file:///workspace/submission-${String(workspace.submission_id || workspace.revision || 'current')}/${encoded}`)))
    })
    modelsRef.current = models
    const initial = models.get(activeRef.current) || models.values().next().value
    if (initial) editor.setModel?.(initial)
    editor.updateOptions?.({readOnly: true, domReadOnly: true, ariaLabel: `Lean 4 提交文件 ${activeRef.current}，只读`})
    editor.layout()
    const parentCleanup = onEditorReady({
      ...context,
      setDisplayCode: (value) => {
        const defaultPath = models.has(requested) ? requested : files[0]?.path || ''
        if (defaultPath) selectFile(defaultPath)
        if (editor.getValue() !== value) editor.setValue(value)
      },
    })
    return () => {
      if (typeof parentCleanup === 'function') parentCleanup()
      if (editorRef.current === editor) editorRef.current = null
      models.forEach((model) => model.dispose())
      modelsRef.current = new Map()
      viewStatesRef.current.clear()
    }
  }
  return <div className="submission-code-surface submission-code-viewer submission-lean-workspace" id="submissionEditorShell">
    <aside className="lean-file-explorer submission-lean-file-explorer" aria-label="本次提交的 Lean 文件"><header className="lean-file-explorer-bar"><span>Files</span><span className="lean-file-count">{files.length}</span></header><div className="lean-file-tree" role="tree"><LeanTree files={files} active={file?.path || ''} select={selectFile} /></div></aside>
    <section className="submission-lean-editor-pane" aria-label="Lean 4 文件内容"><header className="submission-lean-editor-bar"><span className="submission-lean-active-file"><span className="lean-file-mark" aria-hidden="true">λ</span><span title={file?.path}>{file?.path || 'Submission.lean'}</span><span className={`submission-lean-file-mode${readonly ? ' is-readonly' : ''}`}>{readonly ? '题目只读' : '学生提交'}</span></span><span className="submission-lean-revision" title={`工作区版本 ${String(workspace.revision || '')}`}>R{String(workspace.revision_number || 0)}</span></header><div className="submission-lean-editor-body">{file ? <MonacoEditor language="lean4" problemId={Number(workspace.submission_id || 0)} value={files.find((item) => item.path === requested)?.content || files[0]?.content || ''} onChange={() => undefined} idPrefix="submissionLean" ariaLabel="Lean 4 提交文件，只读" readOnly bundle="full" wordWrap="on" shellBaseClassName="submission-monaco-container" hostClassName="submission-monaco-container" fallbackClassName="submission-code-fallback" onReady={onReady} /> : null}</div></section>
  </div>
}

function WrittenPdf({submission}: {submission: DetailResponse['submission']}) {
  const active = ['Pending', 'Waiting', 'Running', 'Generating'].includes(String(submission.status || ''))
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [version, setVersion] = useState(0)
  const activeRef = useRef(active)
  const readyRef = useRef(false)
  const url = `/api/submissions/${submission.id}/file`
  activeRef.current = active
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | null = null
    let attempts = 0
    let checking = false
    readyRef.current = false
    setState('loading')
    const check = async () => {
      if (cancelled || checking) return
      checking = true
      attempts += 1
      try {
        const response = await fetch(`${url}?check=${Date.now()}`, {method: 'HEAD', cache: 'no-store', credentials: 'same-origin'})
        if (cancelled) return
        if (response.ok) {
          readyRef.current = true
          setVersion(Date.now())
          setState('ready')
          return
        }
      } catch {
        if (cancelled) return
      } finally {
        checking = false
      }
      if (activeRef.current && attempts < 180) {
        setState('loading')
        timer = window.setTimeout(() => {void check()}, 1_000)
      } else setState('error')
    }
    const onFocus = () => {if (!readyRef.current || activeRef.current) {attempts = 0; void check()}}
    window.addEventListener('focus', onFocus)
    void check()
    return () => {cancelled = true; if (timer) window.clearTimeout(timer); window.removeEventListener('focus', onFocus)}
  }, [url])
  return <div className="submission-pdf-surface" id="pdfViewer">{state === 'ready' ? <iframe title="submission-pdf" className="w-100 h-100 border-0" referrerPolicy="no-referrer" src={`${url}?v=${version}`} /> : <div className={`submission-pdf-hint ${state === 'error' ? 'text-danger' : 'text-muted'}`}>{state === 'error' ? '暂无可渲染的 PDF（可能是编译失败）。' : <MathCurveLoader size="lg" label={active ? 'PDF 生成中，请稍候...' : '正在加载 PDF…'} />}</div>}</div>
}

function WrittenComment({text}: {text: string}) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const root = ref.current
    if (!root || !text.trim()) return
    void typesetMath(root)
    return () => clearMath(root)
  }, [text])
  return <div ref={ref} id="studentCommentRendered" className="submission-written-comment">{text.trim() ? text.split('\n').map((line, index, lines) => <span key={index}>{line}{index < lines.length - 1 ? <br /> : null}</span>) : <span className="text-muted">暂无评语</span>}</div>
}

function WrittenResults({data, refresh}: {data: DetailResponse; refresh: () => void}) {
  const navigate = useNavigate()
  const submission = data.submission
  const isAdmin = Number(data.user?.is_admin) === 1
  const [score, setScore] = useState(String(submission.score ?? 0))
  const [comment, setComment] = useState(submission.code || '')
  const [editorOpen, setEditorOpen] = useState(false)
  const save = useMutation({mutationFn: () => {const body = new FormData(); body.append('score', score); body.append('comment', comment); return apiFetch<ApiEnvelope>(`/api/admin/submissions/${submission.id}/grade`, {method: 'POST', body})}, onSuccess: refresh})
  const next = useMutation({mutationFn: () => apiFetch<ApiEnvelope & {next_submission_id?: number}>(`/api/admin/submissions/${submission.id}/next-pending`), onSuccess: (payload) => {if (payload.next_submission_id) navigate(`/submissions/${payload.next_submission_id}`)}})
  const openEditor = () => {
    save.reset()
    setScore(String(submission.score ?? 0)); setComment(submission.code || '')
    setEditorOpen(true)
  }
  const closeEditor = () => setEditorOpen(false)
  useEffect(() => {if (save.isSuccess) closeEditor()}, [save.isSuccess])
  const rawComment = submission.code || ''
  return <>
    <section className="submission-detail-section"><header className="submission-detail-section-heading"><div><span>GRADING</span><h2>批改结果</h2></div>{isAdmin ? <div className="submission-detail-inline-actions"><button type="button" className="submission-button submission-button--ghost" id="openGradeEditorBtn" onClick={openEditor}><i className="fas fa-pen-to-square" aria-hidden="true" /> 编辑</button><button type="button" className="submission-button submission-button--ghost" id="nextBtn" disabled={next.isPending} onClick={() => next.mutate()}>下一个 <i className="fas fa-arrow-right" aria-hidden="true" /></button></div> : null}</header>{next.isError ? <div className="submission-action-feedback is-error" role="status">{next.error.message}</div> : null}<WrittenComment text={rawComment} /></section>
    {data.written_submission?.show_latex_transcription ? <details className="submission-detail-disclosure submission-latex-card"><summary><span>LATEX TRANSCRIPTION</span><i className="fas fa-chevron-down" aria-hidden="true" /></summary><div id="submissionLatexRendered" className="submission-latex-content">{data.submission_latex_html ? <MarkdownContent as="span" className="numoj-markdown" html={data.submission_latex_html} /> : data.submission_latex_error ? <span className="text-danger">{data.submission_latex_error}</span> : submissionStatusIsActive(submission.status) ? <MathCurveLoader size="md" label="LaTeX 转写中…" /> : <span className="text-muted">暂无 LaTeX 转写结果。</span>}</div></details> : null}
    {isAdmin ? <ReactModal open={editorOpen} onClose={closeEditor} id="gradeEditModal" labelledBy="gradeEditModalLabel" dialogClassName="modal-lg"><form onSubmit={(event) => {event.preventDefault(); save.mutate()}}><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="gradeEditModalLabel"><i className="fas fa-pen-to-square me-2" />编辑批改结果</h5><button type="button" className="btn-close" aria-label="Close" onClick={closeEditor} /></div><div className="modal-body"><div className="mb-3"><label htmlFor="editScoreInput" className="form-label"><i className="fas fa-trophy me-2" />给分 (0-5 分)</label><input type="number" className="form-control" id="editScoreInput" name="score" min={0} max={5} step={1} required value={score} onChange={(event) => setScore(event.target.value)} /></div><div className="mb-0"><label htmlFor="editCommentInput" className="form-label"><i className="fas fa-comment me-2" />评语</label><textarea className="form-control" id="editCommentInput" name="comment" rows={14} value={comment} onChange={(event) => setComment(event.target.value)} /></div>{save.isError ? <div className="alert alert-danger mt-3 mb-0">提交失败：{save.error.message}</div> : null}</div><div className="modal-footer"><button type="button" className="btn btn-outline-secondary" onClick={closeEditor}><i className="fas fa-times me-2" />取消</button><button type="submit" className="btn btn-outline-success" id="submitGradeBtn" disabled={save.isPending}><i className="fas fa-check me-2" />{save.isPending ? '提交中…' : '保存并提交'}</button></div></div></form></ReactModal> : null}
  </>
}

function AiTutor({submissionId, cached, editorContext, onResult}: {submissionId: number; cached?: JsonRecord; editorContext: SubmissionEditorContext | null; onResult: (result: JsonRecord | null) => void}) {
  const [result, setResult] = useState<JsonRecord | null>(cached?.success ? cached : null)
  const [reasoning, setReasoning] = useState('')
  const [status, setStatus] = useState(() => cached?.summary ? String(cached.summary) : cached?.success ? '已恢复缓存的代码诊断。' : '')
  const [statusTone, setStatusTone] = useState<'info' | 'danger' | 'warning' | 'success'>(cached?.success ? (Array.isArray(cached.issues) && cached.issues.length ? 'warning' : 'success') : 'info')
  const [loading, setLoading] = useState(false)
  const [cotOpen, setCotOpen] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    if (!cached?.success) return
    setResult(cached)
    setStatus(String(cached.summary || (Array.isArray(cached.issues) && cached.issues.length ? `定位到 ${cached.issues.length} 处关键问题。` : '未定位到明确的问题代码位置。')))
    setStatusTone(Array.isArray(cached.issues) && cached.issues.length ? 'warning' : 'success')
  }, [cached])
  useEffect(() => {onResult(result)}, [onResult, result])
  useEffect(() => () => abortRef.current?.abort(), [])

  useEffect(() => {
    if (!editorContext || !result?.success) return
    const {editor, monaco} = editorContext
    const displayCode = typeof result.code_used === 'string' ? result.code_used : editor.getValue()
    if (editor.getValue() !== displayCode) editorContext.setDisplayCode(displayCode)
    const model = editor.getModel?.()
    if (!model) return
    const codeLines = displayCode.split('\n')
    const decorations: unknown[] = []
    const issues = Array.isArray(result.issues) ? result.issues : []
    issues.forEach((raw) => {
      const issue = raw && typeof raw === 'object' ? raw as JsonRecord : {}
      let start = Number.parseInt(String(issue.line_start || 1), 10)
      let end = Number.parseInt(String(issue.line_end || start), 10)
      if (!Number.isFinite(start)) start = 1
      if (!Number.isFinite(end)) end = start
      if (start > end) [start, end] = [end, start]
      start = Math.max(1, Math.min(codeLines.length || 1, start))
      end = Math.max(1, Math.min(codeLines.length || 1, end))
      const reason = String(issue.reason || '这里可能有问题').trim()
      for (let line = start; line <= end; line += 1) {
        const length = (codeLines[line - 1] || '').length
        if (!length) continue
        decorations.push({range: new monaco.Range(line, 1, line, length + 1), options: {inlineClassName: 'monaco-ai-issue-underline', hoverMessage: {value: reason, isTrusted: false, supportHtml: false}}})
      }
    })
    const createCollection = editor.createDecorationsCollection as undefined | ((items: unknown[]) => {clear: () => void})
    if (createCollection) {
      const collection = createCollection.call(editor, decorations)
      return () => collection.clear()
    }
    const ids = model.deltaDecorations?.([], decorations) || []
    return () => {model.deltaDecorations?.(ids, [])}
  }, [editorContext, result])

  const ask = async () => {
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    setLoading(true)
    setReasoning('')
    setCotOpen(true)
    setStatus('AI 正在定位问题代码，请稍候…')
    setStatusTone('info')
    try {
      await streamAiCodeMarks(submissionId, ({name, payload}) => {
        if (name === 'reasoning') setReasoning((current) => current + String(payload.delta || ''))
        else if (name === 'progress') setStatus(String(payload.message || 'AI 正在整理诊断结果…'))
        else if (name === 'heartbeat') setStatus('AI 仍在分析代码，请稍候…')
        else if (name === 'result') {
          if (!payload.success) throw new Error(String(payload.message || 'AI 未返回可用结果'))
          setResult(payload)
          const issues = Array.isArray(payload.issues) ? payload.issues : []
          setStatus(String(payload.summary || (issues.length ? `已定位 ${issues.length} 处关键问题（鼠标悬停红色波浪线可查看原因）` : '未定位到明确的问题代码位置。')))
          setStatusTone(issues.length ? 'warning' : 'success')
        }
      }, controller.signal)
      setCotOpen(false)
    } catch (error) {
      if (controller.signal.aborted) return
      setResult(null)
      setStatus(`问题标注失败：${error instanceof Error ? error.message : String(error)}`)
      setStatusTone('danger')
    } finally {
      if (abortRef.current === controller) abortRef.current = null
      if (!controller.signal.aborted) setLoading(false)
    }
  }
  const issues = Array.isArray(result?.issues) ? result.issues : []
  return <section className="submission-detail-section submission-ai-section"><header className="submission-detail-section-heading"><div><span>AI TUTOR</span><h2>代码诊断</h2></div></header><button type="button" className="submission-button submission-button--ghost" id="askAiBtn" disabled={loading || !editorContext} onClick={() => void ask()}>{loading ? <MathCurveLoader size="sm" label="AI 分析中…" /> : <><i className="fas fa-robot" aria-hidden="true" /> 询问 AI 助教</>}</button>{reasoning || loading ? <details className={`submission-ai-cot${loading ? ' is-streaming' : ''}`} open={cotOpen} onToggle={(event) => setCotOpen(event.currentTarget.open)}><summary><span><i className="fas fa-wave-square" aria-hidden="true" /> AI 分析过程</span><span className="submission-ai-cot-hint">生成后可展开</span></summary><pre className="submission-ai-cot-text" aria-live="polite">{reasoning || '正在等待模型输出分析过程…'}</pre></details> : null}{status ? <div className={`submission-ai-status${statusTone === 'info' ? '' : ` is-${statusTone}`}`} role="status">{status}</div> : null}{issues.length ? <div className="submission-ai-hint">鼠标移动到红色波浪线上可查看更详细的错误。</div> : null}</section>
}

export default function SubmissionDetailPage() {
  const {submissionId} = useParams()
  const location = useLocation()
  const queryClient = useQueryClient()
  const [selectedPoint, setSelectedPoint] = useState(0)
  const [imagePreview, setImagePreview] = useState<{url: string; alt: string} | null>(null)
  const [codeEditorContext, setCodeEditorContext] = useState<SubmissionEditorContext | null>(null)
  const [aiOmniResult, setAiOmniResult] = useState<JsonRecord | null>(null)
  const pageRef = useRef<HTMLDivElement>(null)
  const splitterRef = useRef<HTMLDivElement>(null)
  const routedOrigin = submissionOriginFromState(location.state)
  const routedNotice = location.state && typeof location.state === 'object'
    ? String((location.state as {submissionNotice?: unknown}).submissionNotice || '')
    : ''
  const routedNoticeTone = location.state && typeof location.state === 'object'
    ? String((location.state as {submissionNoticeTone?: unknown}).submissionNoticeTone || 'warning')
    : 'warning'
  const rememberedOrigin = useMemo(() => loadSubmissionOrigin(submissionId), [submissionId])
  useEffect(() => {if (routedOrigin) rememberSubmissionOrigin(submissionId, routedOrigin)}, [routedOrigin, submissionId])
  const queryKey = submissionDetailQueryKey(submissionId)
  const result = useQuery({queryKey, queryFn: () => apiFetch<DetailResponse>(`/api/submissions/${submissionId}`)})
  useEffect(() => {if (result.data) document.title = '提交详情 - Numerical OJ'}, [result.data])
  const previousActiveRef = useRef<boolean | null>(null)
  useEffect(() => {previousActiveRef.current = null; setSelectedPoint(0)}, [submissionId])
  useEffect(() => {setCodeEditorContext(null); setAiOmniResult(null)}, [submissionId])
  useEffect(() => {
    const data = result.data
    if (!data) return
    const active = submissionStatusIsActive(data.submission.status)
    if (previousActiveRef.current === null || (previousActiveRef.current && !active)) {
      setSelectedPoint(defaultTestPointIndex(data.test_points))
    }
    previousActiveRef.current = active
  }, [result.data?.submission.status, result.data?.test_points, submissionId])
  const applyLiveSnapshot = useCallback((snapshot: SubmissionStatusSnapshot) => {
    queryClient.setQueryData<DetailResponse>(queryKey, (current) => mergeSubmissionDetailSnapshot(current, snapshot))
  }, [queryClient, submissionId])
  const liveProgramming = Number(result.data?.submission.problem_type || result.data?.problem?.type || 1) === 1
  const liveLean = liveProgramming && ['lean', 'lean4'].includes(String(result.data?.plang || '').toLowerCase())
  const stream = useSubmissionStatusStream({
    submissionId: Number(submissionId) || undefined,
    enabled: result.isSuccess && submissionStatusIsActive(result.data.submission.status),
    fallbackPolling: liveProgramming,
    startDelayMs: liveProgramming ? 300 : 0,
    initialMessage: liveLean ? '正在启动 Lean 4 验证...' : '正在编译和初始化...',
    onSnapshot: applyLiveSnapshot,
  })
  usePersistentVerticalSplitter({
    containerRef: pageRef,
    splitterRef,
    enabled: result.isSuccess,
    storageKey: 'numoj.submissionDetail.informationRatio',
    cssVariable: '--submission-detail-information-width',
    defaultRatio: 0.5,
    minimumLeadingPixels: 320,
    minimumTrailingPixels: 420,
    resizingClassName: 'is-submission-detail-resizing',
    valueText: submissionSplitValueText,
  })
  const rejudge = useMutation({mutationFn: () => apiFetch<ApiEnvelope>(`/api/submissions/${submissionId}/rejudge`, {method: 'POST'}), onSuccess: () => void result.refetch()})
  if (result.isPending) return <LoadingState label="正在读取提交快照" />
  if (result.isError) return <ErrorState message={result.error.message} />
  const data = result.data!
  const submission = data.submission
  const programming = Number(submission.problem_type || data.problem?.type || 1) === 1
  const lean = programming && ['lean', 'lean4'].includes(String(data.plang || '').toLowerCase())
  const configuredMaxScore = Number(data.problem?.max_score || 0)
  const maxScore = programming ? configuredMaxScore > 0 ? configuredMaxScore : submissionStatusIsActive(submission.status) ? '?' : data.test_points.length || '?' : 5
  const accepted = submission.score != null && String(submission.score) === String(maxScore)
  const activePointIndex = Math.min(selectedPoint, Math.max(0, data.test_points.length - 1))
  const activePoint = data.test_points[activePointIndex]
  const activeTestIndex = Number(activePoint?.test_index || activePointIndex + 1)
  const omniAnalysis = aiOmniResult?.success && Number(aiOmniResult.image_analysis_test_index || 0) === activeTestIndex ? String(aiOmniResult.image_mismatch_analysis || '').trim() : ''
  const returnTo = routedOrigin || rememberedOrigin || `/submissions?problem_id=${submission.problem_id}`
  const returnLabel = returnTo.startsWith('/problems/') ? 'PROBLEM' : 'SUBMISSIONS'
  return <div ref={pageRef} className="submission-detail-page" data-math-curve-stroke-scale="1.2">
    <section className="submission-detail-primary" id="submissionDetailPrimary" aria-label={lean ? 'Lean 4 提交文件' : programming ? '提交代码' : '书面作业 PDF'}>{programming ? lean && data.lean_workspace ? <LeanSubmissionSurface workspace={data.lean_workspace} onEditorReady={(context) => {setCodeEditorContext(context); return () => setCodeEditorContext((current) => current?.editor === context.editor ? null : current)}} /> : <div className="submission-code-surface submission-code-viewer"><MonacoEditor language={data.plang || 'matlab'} problemId={submission.problem_id} value={submission.code || ''} onChange={() => undefined} idPrefix="submission" ariaLabel="提交代码，只读" readOnly bundle="full" wordWrap="on" shellBaseClassName="submission-monaco-container" hostClassName="submission-monaco-container" fallbackClassName="submission-code-fallback" onReady={(context) => {const submissionContext = {...context, setDisplayCode: (value: string) => context.editor.setValue(value)}; setCodeEditorContext(submissionContext); return () => setCodeEditorContext((current) => current?.editor === context.editor ? null : current)}} /></div> : <WrittenPdf submission={submission} />}</section>
    <aside className="submission-detail-summary-card" id="submissionDetailSummary" aria-label="提交摘要"><div className="submission-detail-topline"><Link className="submission-detail-back" to={returnTo}><i className="fas fa-arrow-left" /> {returnLabel}</Link><span className="submission-detail-id">#{submission.id}</span></div><h1 className="visually-hidden">提交 #{submission.id}</h1>{routedNotice ? <div className={`submission-action-feedback ${routedNoticeTone === 'error' ? 'is-error' : 'is-warning'}`} role="status">{routedNotice}</div> : null}<div className="submission-detail-result"><span className={`submission-verdict submission-verdict--${statusClass(submission.status)}`}><span className="submission-verdict__dot" /><span>{submission.status || 'Unknown'}</span></span><div className="submission-detail-score"><strong className={accepted ? 'is-accepted' : submission.score ? 'is-partial' : 'is-failed'}>{submission.score ?? '—'}</strong><span>/ <span>{maxScore}</span></span></div></div><dl className="submission-detail-meta"><dt>题目</dt><dd className="submission-detail-problem-meta"><Link to={`/problems/${submission.problem_id}`}>{data.problem?.title || submission.problem_title || '未命名题目'}</Link><span>P{String(submission.problem_id).padStart(4, '0')}</span></dd><dt>提交者</dt><dd>{submission.username}</dd><dt>提交时间</dt><dd>{submission.created_at || '—'}</dd></dl>{submission.generated_from_prompt ? <details className="submission-detail-disclosure submission-prompt-card" open><summary><span>ORIGINAL PROMPT</span><i className="fas fa-chevron-down" /></summary><pre>{submission.prompt_text || ''}</pre>{submission.prompt_generation_error ? <div className="submission-inline-error">{submission.prompt_generation_error}</div> : null}</details> : null}{Number(data.user?.is_admin) === 1 ? <><button type="button" className="submission-button submission-button--accent submission-detail-rejudge" disabled={rejudge.isPending} onClick={() => {if (window.confirm('确认重测这条提交吗？')) rejudge.mutate()}}><i className="fas fa-rotate-right" />{rejudge.isPending ? '正在提交重测…' : '重测此提交'}</button><div className={`submission-action-feedback${rejudge.isSuccess ? ' is-success' : rejudge.isError ? ' is-error' : ''}`} role="status">{rejudge.isSuccess ? '已加入重测队列' : rejudge.isError ? `重测失败：${rejudge.error.message}` : ''}</div></> : null}</aside>
    <div ref={splitterRef} className="submission-detail-splitter" role="separator" tabIndex={0} aria-label="调整提交信息与提交内容宽度" aria-orientation="vertical" aria-controls="submissionDetailSummary submissionDetailResults submissionDetailPrimary" aria-valuemin={26} aria-valuemax={66} aria-valuenow={50} />
    <aside className="submission-detail-results" id="submissionDetailResults" aria-label={lean ? '证明验证详情' : programming ? '测试点详情' : '批改详情'}>{programming ? <><section className="submission-detail-section"><header className="submission-detail-section-heading"><div><span>{lean ? 'PROOF CHECK' : 'TEST POINTS'}</span></div></header>{submissionStatusIsActive(submission.status) ? <div className="submission-judging-state" role="status"><MathCurveLoader size="md" label={stream.message} /></div> : null}<div className="test-point-grid">{data.test_points.map((point, index) => <button className={`test-point-card ${pointClass(point.status)}${index === activePointIndex ? ' selected' : ''}`} type="button" title={lean ? `证明验证 · ${String(point.status || 'Unknown')}` : `测试点 #${index + 1} · ${String(point.status || 'Unknown')}`} aria-label={lean ? `证明验证，${String(point.status || 'Unknown')}` : `测试点 ${index + 1}，${String(point.status || 'Unknown')}`} aria-pressed={index === activePointIndex} onClick={() => setSelectedPoint(index)} key={index}><span className="tp-index">{lean ? '⊢' : String(index + 1).padStart(2, '0')}</span>{pointClass(point.status) === 'is-active' ? <MathCurveLoader iconOnly size="xs" /> : null}</button>)}</div>{activePoint ? <TestPointDetail key={`${submission.id}:${activePointIndex}:${String(activePoint.test_index || '')}`} point={activePoint} index={activePointIndex} submissionId={submission.id} lean={lean} omniAnalysis={omniAnalysis} onOpenImage={setImagePreview} /> : <div className="submission-test-detail-hint">{lean ? '证明验证中，结果稍后显示。' : '判题中，暂时没有可展示的测试点结果。'}</div>}</section>{submission.status === 'Unaccepted' ? <AiTutor key={submission.id} submissionId={submission.id} cached={data.cached_ai_code_marks} editorContext={codeEditorContext} onResult={setAiOmniResult} /> : null}</> : <WrittenResults data={data} refresh={() => void result.refetch()} />}</aside>
    <ReactModal open={Boolean(imagePreview)} onClose={() => setImagePreview(null)} id="imageModal" labelledBy="imageModalLabel" dialogClassName="modal-xl"><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="imageModalLabel"><i className="fas fa-image me-2" /> 输出图片</h5><button type="button" className="btn-close" aria-label="Close" onClick={() => setImagePreview(null)} /></div><div className="modal-body text-center">{imagePreview ? <img id="modalImage" src={imagePreview.url} alt={imagePreview.alt} className="submission-modal-image" /> : null}</div><div className="modal-footer"><button type="button" className="btn btn-secondary" onClick={() => setImagePreview(null)}><i className="fas fa-times me-2" />关闭</button>{imagePreview ? <a id="downloadImageBtn" href={imagePreview.url} download className="btn btn-primary"><i className="fas fa-download me-2" />下载图片</a> : null}</div></div></ReactModal>
  </div>
}
