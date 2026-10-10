import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent} from 'react'
import {Navigate, useParams} from 'react-router-dom'

import {ApiError, apiFetch, queryString} from '../api/client'
import {MarkdownContent} from '../components/MarkdownContent'
import {Link} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'
import {FaithSieveReport} from '../components/FaithSieveReport'
import {FaithSieveWorkflowGraph} from '../components/FaithSieveWorkflowGraph'
import {FaithSieveProofTree} from '../components/FaithSieveProofTree'
import {ExecutionModeIdentity} from '../components/ExecutionModeLogo'
import {FaithSieveHarness, FaithSieveModel} from '../components/FaithSieveRuntimeIdentity'
import {FaithSieveCost} from '../components/FaithSieveCost'
import {WrittenSubmissionPdf} from '../components/WrittenSubmissionPdf'
import {usePersistentVerticalSplitter} from '../components/usePersistentVerticalSplitter'
import {useSession} from '../session'
import {parseFaithSieveNodeVerification, parseFaithSieveProofTree} from '../lib/faithSieveProofTree'
import {faithSieveDetailQueryKey, faithSieveIsActive, faithSieveStatusLabel, faithSieveStageState, faithSieveVerdictClass, faithSieveScore, faithSieveExecutionMode, faithSieveRunDetailUrl, faithSieveWorkflowWithResult, type FaithSieveArtifact, type FaithSieveArtifactResponse, type FaithSieveDetailResponse, type FaithSieveStage, type FaithSieveResult, type FaithSieveProofTreeReference, type FaithSieveEdge, type FaithSieveRetryResponse} from './faithsieveTypes'
import './faithsieve.css'

const outcomeLabels: Record<string, string> = {ok: '已确认', passed: '验证通过', refuted: '已反驳', needs_revision: '需要修订', failed: '验证失败', inconclusive: '无结论', correct: '证明成立', incorrect: '证明不成立', low_risk: '低风险', default_order: '使用默认顺序'}
const branchLabels: Record<string, string> = {original: '原命题', negation: '否定命题', counterexample: '反例'}
const artifactNames: Record<string, string> = {'submission.md': '原稿转录', 'extraction.txt': '原稿核对记录', 'extraction.json': '原稿渲染记录', 'steps.md': '证明步骤', 'tree.json': '证明状态树', 'node-selection.json': '验证顺序', 'decomposition.md': '拆分审计', 'faithsieve_result.json': '评测结果', 'problem.md': '题面'}

function recoverableDetailError(error: Error) {
  return !(error instanceof ApiError) || error.status >= 500 || error.status === 408 || error.status === 429
}

function stageOutcome(stage: FaithSieveStage, runStatus: string) {
  const state = faithSieveStageState(stage, runStatus)
  if (state === 'completed' && stage.parameters?.node_id && stage.status === 'refuted') return '推理被反驳'
  return state === 'completed' ? outcomeLabels[stage.status || ''] || '已完成' : faithSieveStatusLabel(state)
}
function proofName(reference?: {format?: string; schema_version?: number} | null) {return reference?.format === 'dependency_dag' ? `证明依赖图${reference.schema_version === 2 ? '（历史）' : ''}` : '证明状态树（历史）'}
function currentProofReference(reference: FaithSieveProofTreeReference | null | undefined, current: FaithSieveProofTreeReference | null | undefined): FaithSieveProofTreeReference | null | undefined {
  if (!reference) return reference
  if (current && reference.path === current.path && (!reference.stage_key || reference.stage_key === current.stage_key)) return {...reference, ...current}
  const {node_verification: _previousSummary, ...historical} = reference
  return historical
}
function artifactName(artifact: FaithSieveArtifact) {
  const name = artifact.name || artifact.path.split('/').at(-1) || artifact.path
  if (name === 'tree.json' || name === 'tree.md') return proofName(artifact)
  return artifactNames[name] || name
}
function elapsedLabel(start?: string, finish?: string, now = Date.now()) {
  if (!start) return ''
  const begin = Date.parse(start.replace(' ', 'T'))
  const end = finish ? Date.parse(finish.replace(' ', 'T')) : now
  if (!Number.isFinite(begin) || !Number.isFinite(end) || end < begin) return ''
  const seconds = Math.floor((end - begin) / 1000)
  const minutes = Math.floor(seconds / 60)
  return minutes >= 60 ? `${Math.floor(minutes / 60)}小时${minutes % 60}分` : minutes ? `${minutes}分${seconds % 60}秒` : `${seconds}秒`
}

function ArtifactFiles({files, selected, open, label}: {files: FaithSieveArtifact[]; selected: FaithSieveArtifact | null; open: (item: FaithSieveArtifact) => void; label: string}) {
  return <div className="faithsieve-files" aria-label={label}>{files.map((item) => <button type="button" className="faithsieve-file" title={item.path} aria-pressed={selected?.path === item.path && selected.stage_key === item.stage_key} onClick={() => open(item)} key={item.path}><i className="far fa-file-lines" aria-hidden="true" /><span>{artifactName(item)}</span><span className="faithsieve-file-type">{item.language === 'markdown' ? 'Markdown' : item.language || item.path.split('.').at(-1)}</span></button>)}</div>
}

function StructuredProofTree({file, title = '', nodeVerification}: {file: FaithSieveArtifactResponse['artifact']; title?: string; nodeVerification?: unknown}) {
  const parsed = useMemo(() => {
    try {
      if (!file.proof_tree) throw new Error(`${file.proof_tree_format === 'dependency_dag' ? '证明依赖图' : '证明状态树'}未通过结构校验`)
      const tree = parseFaithSieveProofTree(file.proof_tree)
      return {tree, error: ''}
    }
    catch (error) {return {tree: null, error: error instanceof Error ? error.message : '证明状态树格式无效'}}
  }, [file.proof_tree, file.proof_tree_format])
  const verification = useMemo(() => {
    try {return {nodes: parsed.tree && (parsed.tree.schema_version === 2 || parsed.tree.schema_version === 3) ? parseFaithSieveNodeVerification(nodeVerification ?? file.proof_node_verification, parsed.tree) : undefined, error: ''}}
    catch (error) {return {nodes: undefined, error: error instanceof Error ? error.message : '节点验证状态无效'}}
  }, [parsed.tree, file.proof_node_verification, nodeVerification])
  return parsed.tree && !verification.error ? <FaithSieveProofTree tree={parsed.tree} nodeVerification={verification.nodes} title={title} /> : <ErrorState message={parsed.error || verification.error} />
}

function stageTreeReference(stage: FaithSieveStage, stages: FaithSieveStage[], edges: FaithSieveEdge[] = []): FaithSieveProofTreeReference | undefined {
  const reference = (item: FaithSieveStage) => {
    const file = item.artifacts?.find((artifact) => artifact.path === 'faithsieve-work/tree.json' || artifact.path === 'faithsieve-work/tree.md')
    return file ? {...file, stage_key: file.stage_key || item.key} : undefined
  }
  if (stage.role === 'tree-builder') return reference(stage)
  if (stage.role !== 'tree-auditor') return undefined
  const queue = [stage.key]
  const seen = new Set(queue)
  for (let index = 0; index < queue.length; index++) {
    for (const edge of edges.filter((edge) => edge.target === queue[index])) {
      if (seen.has(edge.source)) continue
      seen.add(edge.source)
      const parent = stages.find((item) => item.key === edge.source)
      if (parent?.role === 'tree-builder') return reference(parent)
      if (parent) queue.push(parent.key)
    }
  }
  return undefined
}

function ProofTreeContent({attemptId, reference, version}: {attemptId: string; reference: FaithSieveProofTreeReference; version: string}) {
  const result = useQuery({
    queryKey: ['faithsieve-artifact', attemptId, reference.path, reference.stage_key || '', !reference.stage_key ? version : ''],
    queryFn: ({signal}) => apiFetch<FaithSieveArtifactResponse>(`/api/admin/faithsieve/${attemptId}/artifacts${queryString({path: reference.path, stage_key: reference.stage_key})}`, {signal}),
  })
  const name = reference.format === 'dependency_dag' ? '证明依赖图' : '证明状态树'
  return <section aria-label={`${name}内容`}>{result.isPending ? <LoadingState label={`正在读取${name}`} /> : result.isError ? <ErrorState message={result.error.message} retry={() => void result.refetch()} /> : <StructuredProofTree file={result.data.artifact} nodeVerification={reference.node_verification} />}</section>
}

function ArtifactContent({attemptId, artifact, version, close, currentProof}: {attemptId: string; artifact: FaithSieveArtifact; version: string; close: () => void; currentProof?: FaithSieveProofTreeReference | null}) {
  const result = useQuery({
    queryKey: ['faithsieve-artifact', attemptId, artifact.path, artifact.stage_key || '', !artifact.stage_key ? version : ''],
    queryFn: ({signal}) => apiFetch<FaithSieveArtifactResponse>(`/api/admin/faithsieve/${attemptId}/artifacts${queryString({path: artifact.path, stage_key: artifact.stage_key})}`, {signal}),
  })
  const file = result.data?.artifact
  const reference = currentProofReference(artifact, currentProof)
  return <section className="faithsieve-artifact-content" aria-label="工件全文"><header><div><h3 title={artifact.path}>{artifactName({...artifact, format: file?.proof_tree_format || reference?.format, schema_version: file?.schema_version || reference?.schema_version})}</h3><span>{artifact.stage_key ? '所选阶段版本' : '当前版本'}</span></div><button type="button" className="submission-icon-button" aria-label="关闭工件" onClick={close}><i className="fas fa-xmark" aria-hidden="true" /></button></header>
    {result.isPending ? <LoadingState label="正在读取文件" /> : result.isError ? <ErrorState message={result.error.message} retry={() => void result.refetch()} /> : file ? file.proof_tree || file.path === 'faithsieve-work/tree.json' ? <StructuredProofTree file={file} nodeVerification={reference?.node_verification} /> : file.language === 'markdown' || /\.md$/i.test(file.path) ? <FaithSieveReport text={file.content} html={file.content_html} /> : <pre className="faithsieve-code"><code>{file.content}</code></pre> : null}
  </section>
}

function StageDetail({stage, runStatus, pages, final, artifact, selectArtifact, openTree, treeName}: {stage: FaithSieveStage; runStatus: string; pages?: number; final?: FaithSieveResult | null; artifact: FaithSieveArtifact | null; selectArtifact: (item: FaithSieveArtifact) => void; openTree?: () => void; treeName?: string}) {
  const state = faithSieveStageState(stage, runStatus)
  const outcome = stageOutcome(stage, runStatus)
  const source = ['source-extraction', 'source-extractor'].includes(stage.role)
  const confirmedSource = source && state === 'completed' && stage.status === 'ok'
  const branch = branchLabels[stage.parameters?.branch || '']
  const failed = ['refuted', 'failed', 'incorrect'].includes(stage.status || '') || ['protocol_error', 'failed'].includes(state)
  const needsRevision = stage.status === 'needs_revision'
  const score = stage.role === 'result' ? faithSieveScore(final) : null
  return <section className="faithsieve-stage-detail" aria-label="所选阶段详情">
    <header className="faithsieve-stage-heading"><h3>{stage.label}</h3><span className={`faithsieve-stage-outcome${failed ? ' is-issue' : needsRevision ? ' is-warning' : ''}`}>{outcome}</span>{score != null ? <span className="faithsieve-final-score">{score}<small>/5</small></span> : null}</header>
    {branch ? <div className="faithsieve-stage-context">{branch}{stage.parameters?.target ? ` · ${stage.parameters.target === 'proof' ? '证明' : '命题'}` : ''}</div> : null}
    {confirmedSource ? <><p className="faithsieve-stage-summary">{pages ? `${pages} 页原稿已核对` : '原稿已核对'}</p>{stage.report ? <details className="faithsieve-disclosure"><summary>核对记录<i className="fas fa-chevron-down" aria-hidden="true" /></summary><div className="faithsieve-disclosure-content"><FaithSieveReport text={stage.report} html={stage.report_html} /></div></details> : null}</> : stage.report ? stage.role === 'lean-compiler' || stage.role === 'compile-lean' ? <pre className="faithsieve-code">{stage.report}</pre> : <FaithSieveReport text={stage.report} html={stage.report_html} /> : state === 'completed' ? <p className="faithsieve-stage-summary">暂无报告</p> : null}
    {openTree ? <button type="button" className="faithsieve-text-link faithsieve-tree-link" onClick={openTree}>查看{treeName}<i className="fas fa-arrow-up-right-from-square" aria-hidden="true" /></button> : null}
    {stage.artifacts?.length ? <details className="faithsieve-disclosure"><summary>阶段文件<i className="fas fa-chevron-down" aria-hidden="true" /></summary><div className="faithsieve-disclosure-content"><ArtifactFiles files={stage.artifacts} selected={artifact} open={selectArtifact} label="阶段工件" /></div></details> : null}
    {stage.checks?.length || stage.session_id || Object.keys(stage.parameters || {}).length ? <details className="faithsieve-disclosure"><summary>运行记录<i className="fas fa-chevron-down" aria-hidden="true" /></summary><div className="faithsieve-disclosure-content">
      {stage.session_id ? <Link className="faithsieve-text-link" to={`/agents/${encodeURIComponent(stage.session_id)}`}>Judge 会话<i className="fas fa-arrow-up-right-from-square" aria-hidden="true" /></Link> : null}
      {Object.keys(stage.parameters || {}).length ? <dl className="faithsieve-record-meta">{Object.entries(stage.parameters || {}).map(([key, value]) => <div key={key}><dt>{({node_id: '证明结论', edge_id: '证明步骤', obligation_id: '验证义务', attempt: '尝试轮次', branch: '分支', target: '验证对象'} as Record<string, string>)[key] || key}</dt><dd>{key === 'branch' ? branchLabels[String(value)] || String(value) : key === 'target' ? ({proof: '证明', statement: '命题'} as Record<string, string>)[String(value)] || String(value) : String(value)}</dd></div>)}</dl> : null}
      {stage.checks?.map((check, index) => <section className="faithsieve-tool-check" key={index}><header><h4>{check.label}</h4><span>{({ok: '通过', passed: '通过', refuted: '反驳成立', inconclusive: '无结论', failed: '失败', error: '失败'} as Record<string, string>)[check.status || ''] || (check.exit_code != null ? check.exit_code === 0 ? '执行成功' : '执行失败' : faithSieveStatusLabel(check.state))}</span></header>{check.report ? <pre>{check.report}</pre> : null}</section>)}
    </div></details> : null}
  </section>
}

export default function FaithSieveDetailPage() {
  const {attemptId} = useParams()
  const {session, loading} = useSession()
  const queryClient = useQueryClient()
  const isAdmin = Boolean(session?.user?.is_admin)
  const validId = Boolean(attemptId && /^[a-f0-9]{32}$/.test(attemptId))
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [artifact, setArtifact] = useState<FaithSieveArtifact | null>(null)
  const [view, setView] = useState<'workflow' | 'proof-tree'>('workflow')
  const [treeReference, setTreeReference] = useState<FaithSieveProofTreeReference | null>(null)
  const [now, setNow] = useState(Date.now)
  const pageRef = useRef<HTMLDivElement>(null)
  const splitterRef = useRef<HTMLDivElement>(null)
  const resumeInFlight = useRef(false)
  const result = useQuery({
    queryKey: faithSieveDetailQueryKey(attemptId),
    queryFn: ({signal}) => apiFetch<FaithSieveDetailResponse>(`/api/admin/faithsieve/${attemptId}`, {signal}),
    enabled: isAdmin && validId,
    refetchInterval: (query) => {
      if (query.state.error) return recoverableDetailError(query.state.error) && (!query.state.data || faithSieveIsActive(query.state.data.run.status)) ? 5_000 : false
      return faithSieveIsActive(query.state.data?.run.status) ? 2_500 : false
    },
  })
  const resume = useMutation({
    mutationFn: (id: string) => apiFetch<FaithSieveRetryResponse>(`/api/admin/faithsieve/${id}/retry`, {method: 'POST'}),
    retry: false,
    onSuccess: async (payload, id) => {
      queryClient.setQueryData<FaithSieveDetailResponse>(faithSieveDetailQueryKey(id), (data) => data ? {
        ...data, result: null,
        run: {...data.run, status: payload.status, retry_eligible: false, message: '', finished_at: undefined, result: null},
      } : data)
      await Promise.all([
        queryClient.invalidateQueries({queryKey: faithSieveDetailQueryKey(id)}),
        queryClient.invalidateQueries({queryKey: ['faithsieve-list']}),
      ])
    },
    onError: (_error, id) => {void queryClient.invalidateQueries({queryKey: faithSieveDetailQueryKey(id)})},
    onSettled: () => {resumeInFlight.current = false},
  })
  useEffect(() => {setSelectedKey(null); setArtifact(null); setView('workflow'); setTreeReference(null)}, [attemptId])
  useEffect(() => {document.title = result.data ? `Faith Sieve #${result.data.run.id} - Numerical OJ` : 'Faith Sieve - Numerical OJ'}, [result.data?.run.id])
  const activeRun = faithSieveIsActive(result.data?.run.status)
  useEffect(() => {if (!activeRun) return; const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer)}, [activeRun])
  const selectedMode = result.data ? faithSieveExecutionMode(result.data.run) : 'workflow'
  const splitterValueText = useCallback((leading: number, trailing: number) => `Workflow ${leading}%，解答 PDF ${trailing}%`, [])
  usePersistentVerticalSplitter({containerRef: pageRef, splitterRef, enabled: result.isSuccess && isAdmin && selectedMode === 'workflow', storageKey: 'numoj.faithsieve.readingWidth.v2', cssVariable: '--submission-detail-information-width', defaultRatio: 0.6, minimumLeadingPixels: 460, minimumTrailingPixels: 360, valueText: splitterValueText, resizingClassName: 'is-submission-detail-resizing'})
  if (loading) return <LoadingState />
  if (!isAdmin) return <ErrorState message="该页面仅管理员可访问" />
  if (!validId) return <ErrorState message="任务号无效" />
  if (result.isError && (!result.data || !recoverableDetailError(result.error))) return <ErrorState message={result.error.message} retry={() => void result.refetch()} />
  if (!result.data) return <LoadingState label="正在读取 Faith Sieve" />
  const {run, submission, problem, workflow} = result.data
  const executionMode = faithSieveExecutionMode(run)
  if (executionMode === 'skill') {
    const url = faithSieveRunDetailUrl({...run, session_id: run.session_id || workflow.stages.find((stage) => stage.session_id)?.session_id})
    return url ? <Navigate to={url} replace /> : activeRun ? <LoadingState label="等待 Agent 会话创建…" /> : <ErrorState message="该任务尚未创建 Agent 会话" />
  }
  const final = result.data.result || run.result
  const displayed = faithSieveWorkflowWithResult(workflow.stages || [], workflow.edges, !activeRun ? final : null)
  const stages = displayed.stages
  const current = activeRun ? stages.find((stage) => stage.state === 'pending') : undefined
  const selected = stages.find((stage) => stage.key === selectedKey) || current
  const proofTree = currentProofReference(treeReference || workflow.proof_tree, workflow.proof_tree)
  const proofView = view === 'proof-tree' && Boolean(proofTree)
  const canResume = run.status === 'failed' && run.retry_eligible === true
  const resumeError = run.status === 'failed' && resume.isError && resume.variables === attemptId ? resume.error.message : ''
  const selectedTree = currentProofReference(selected ? stageTreeReference(selected, workflow.stages, workflow.edges) : undefined, workflow.proof_tree)
  const elapsed = elapsedLabel(run.started_at, run.finished_at, now)
  const student = submission?.student_name || submission?.username || run.student_name || run.username
  const selectStage = (stage: FaithSieveStage) => {setSelectedKey(stage.key); setArtifact(null)}
  const openArtifact = (item: FaithSieveArtifact, stage?: FaithSieveStage) => {
    if (stage) setSelectedKey(stage.key)
    setArtifact(currentProofReference({...item, stage_key: item.stage_key || stage?.key}, workflow.proof_tree)!)
  }
  const openTree = (reference: FaithSieveProofTreeReference) => {
    setTreeReference(reference)
    setArtifact(null)
    setView('proof-tree')
  }
  const switchViewKey = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
    event.preventDefault()
    const proof = event.key === 'End' || (event.key !== 'Home' && !proofView)
    setView(proof ? 'proof-tree' : 'workflow')
    if (proof) setTreeReference(null)
    setArtifact(null)
    event.currentTarget.querySelector<HTMLButtonElement>(proof ? '#faithsieveTreeTab' : '#faithsieveWorkflowTab')?.focus()
  }
  const progress = <><span className={`submission-verdict submission-verdict--${faithSieveVerdictClass(run.status)}`}><span className="submission-verdict__dot" aria-hidden="true" /><span>{faithSieveStatusLabel(run.status)}</span></span>{current ? <span className="faithsieve-current-stage" role="status">{current.label}</span> : null}{elapsed ? <span className="faithsieve-elapsed">{elapsed}</span> : null}</>
  return <div ref={pageRef} className="submission-detail-page faithsieve-detail-page" data-math-curve-stroke-scale="1.2">
    <section className="submission-detail-primary" id="faithsieveSource" aria-label="学生解答 PDF">{submission ? <WrittenSubmissionPdf submission={submission} /> : <div className="submission-pdf-surface"><div className="submission-pdf-hint">原提交已删除</div></div>}</section>
    <header className="submission-detail-summary-card faithsieve-header" id="faithsieveSummary" aria-label="Faith Sieve 摘要">
      <div className="faithsieve-header-top"><div className="submission-detail-topline"><Link to={`/admin/faithsieve${queryString({submission_id: run.submission_id})}`} className="submission-detail-back"><i className="fas fa-arrow-left" aria-hidden="true" /> Faith Sieve</Link><span className="submission-detail-id">#{run.id}</span></div><div className="faithsieve-execution"><ExecutionModeIdentity mode="workflow" /><FaithSieveHarness harness={run.runtime?.harness} /><FaithSieveModel model={run.runtime?.model} /><FaithSieveCost cost={run.cost} /></div></div>
      <h1 className="visually-hidden">Faith Sieve #{run.id}</h1>
      <div className="faithsieve-subject"><h2>{problem ? <Link to={`/problems/${problem.id}`}>{problem.title}</Link> : run.problem_title || '题目已删除'}</h2><div className="faithsieve-source-reference">{student ? <span>{student}</span> : null}{submission ? <Link to={`/submissions/${submission.id}`}>提交 #{submission.id}</Link> : <span>提交 #{run.submission_id}</span>}</div></div>
    </header>
    <div ref={splitterRef} className="submission-detail-splitter" role="separator" tabIndex={0} aria-label="调整 Workflow 与 PDF 宽度" aria-orientation="vertical" aria-controls="faithsieveWorkflow faithsieveSource" aria-valuemin={26} aria-valuemax={66} aria-valuenow={60} />
    <aside className="submission-detail-results faithsieve-workspace" id="faithsieveWorkflow" aria-label="Faith Sieve Workflow">
      {canResume || resumeError ? <div className="faithsieve-retry-actions">{canResume ? <button type="button" className="submission-button submission-button--ghost" disabled={resume.isPending} aria-busy={resume.isPending} onClick={() => {if (!resume.isPending && !resumeInFlight.current) {resumeInFlight.current = true; resume.mutate(attemptId!)}}}><i className="fas fa-rotate-right" aria-hidden="true" />{resume.isPending ? '提交中…' : '继续评测'}</button> : null}{resumeError ? <div className="submission-action-feedback is-error" role="alert">{resumeError}</div> : null}</div> : null}
      {!activeRun && run.status !== 'completed' && run.message && !final?.comment ? <div className="faithsieve-notice" role="status"><FaithSieveReport text={run.message} /></div> : null}
      {workflow.warnings?.map((warning, index) => <div className="faithsieve-notice" role="status" key={index}>{warning}</div>)}
      <section className="faithsieve-workflow-section" aria-label="Workflow 阶段">
        {proofTree ? <div className="faithsieve-view-switch" role="tablist" aria-label="Faith Sieve 视图" onKeyDown={switchViewKey}><button type="button" role="tab" id="faithsieveWorkflowTab" tabIndex={proofView ? -1 : 0} aria-selected={!proofView} aria-controls="faithsieveDiagram" onClick={() => setView('workflow')}>Workflow</button><button type="button" role="tab" id="faithsieveTreeTab" tabIndex={proofView ? 0 : -1} aria-selected={proofView} aria-controls="faithsieveDiagram" onClick={() => {setView('proof-tree'); setTreeReference(null); setArtifact(null)}}>{proofName(proofTree)}</button></div> : null}
        <div id="faithsieveDiagram" role={proofTree ? 'tabpanel' : undefined} aria-labelledby={proofTree ? proofView ? 'faithsieveTreeTab' : 'faithsieveWorkflowTab' : undefined}>
          {proofView && proofTree ? <>{treeReference && treeReference.stage_key !== workflow.proof_tree?.stage_key ? <div className="faithsieve-stage-context">所选阶段版本</div> : null}<ProofTreeContent key={`${proofTree.path}:${proofTree.stage_key || ''}`} attemptId={attemptId!} reference={proofTree} version={run.updated_at || ''} /></> : <>
            <FaithSieveWorkflowGraph stages={stages} edges={displayed.edges} runStatus={run.status} selectedKey={selected?.key} onSelect={selectStage} title={proofTree ? '' : 'Workflow'} headingMeta={<div className="faithsieve-progress">{progress}</div>} />
            {selected ? <StageDetail key={selected.key} stage={selected} runStatus={run.status} pages={workflow.source?.preprocessing?.pages?.length} final={final} artifact={artifact} selectArtifact={(item) => openArtifact(item, selected)} treeName={proofName(selectedTree)} openTree={selectedTree ? () => openTree(selectedTree) : undefined} /> : null}
          </>}
        </div>
      </section>
      {artifact ? <ArtifactContent key={`${attemptId}:${artifact.stage_key || ''}:${artifact.path}`} attemptId={attemptId!} artifact={artifact} version={run.updated_at || ''} currentProof={workflow.proof_tree} close={() => setArtifact(null)} /> : null}
      <div className="faithsieve-reference-sections">
        {problem ? <details className="faithsieve-disclosure"><summary>题面<i className="fas fa-chevron-down" aria-hidden="true" /></summary><div className="faithsieve-disclosure-content">{problem.content_html ? <MarkdownContent className="numoj-markdown faithsieve-report" html={problem.content_html} /> : <FaithSieveReport text={problem.content || ''} />}</div></details> : null}
        <details className="faithsieve-disclosure"><summary>任务记录<i className="fas fa-chevron-down" aria-hidden="true" /></summary><div className="faithsieve-disclosure-content"><dl className="faithsieve-record-meta">{run.created_at ? <div><dt>创建时间</dt><dd>{run.created_at}</dd></div> : null}{run.started_at ? <div><dt>开始时间</dt><dd>{run.started_at}</dd></div> : null}{run.finished_at ? <div><dt>完成时间</dt><dd>{run.finished_at}</dd></div> : null}</dl>{workflow.artifacts?.length ? <><h3 className="faithsieve-record-heading">当前文件</h3><ArtifactFiles files={workflow.artifacts.map((item) => currentProofReference(item, workflow.proof_tree)!)} selected={artifact} open={(item) => openArtifact(item)} label="当前工件" /></> : null}</div></details>
      </div>
    </aside>
  </div>
}
