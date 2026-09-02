import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useMemo, useRef, useState, type CSSProperties, type Dispatch, type DragEvent, type FormEvent, type ReactNode, type SetStateAction} from 'react'
import {createPortal} from 'react-dom'
import {useParams, useSearchParams} from 'react-router-dom'

import {ApiError, apiFetch, errorMessage, queryString} from '../api/client'
import type {ApiEnvelope, CompetitionSummary, JsonRecord} from '../api/types'
import {Identicon} from '../components/Identicon'
import {MarkdownContent} from '../components/MarkdownContent'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {ModelLogo, modelLogoClass} from '../components/ModelLogo'
import {Link, useNavigate} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'
import {ReactModal} from '../components/ReactModal'
import {useDismissibleDropdown} from '../components/useDismissibleDropdown'
import {EloTrajectoryResult, type EloTrajectorySeries} from '../ranking/EloTrajectoryChart'
import {JudgeDetailModal, MatchDetailModal, MediaPreviewModal, ReverseJudgeDetailModal, type RankingMatchDetail, type RankingMediaTarget, type RankingSubmissionOverlayTarget} from '../ranking/RankingDetailOverlays'
import {useRuleTopology} from '../ranking/ruleTopology'
import {useSession} from '../session'

type RankingFile = JsonRecord & {
  id: number
  filename: string
  file_size?: number
  media_kind?: string
  download_url: string
}

type Submission = JsonRecord & {
  id: number
  username?: string
  status?: string
  score?: number
  elo_rating?: number
  elo_match_count?: number
  created_at?: string
  base_model?: string
  answer_filename?: string
  answer_download_url?: string
  code_filename?: string
  code_download_url?: string
  agent_endpoint_label?: string
  agent_endpoint_harness?: string
  agent_endpoint_model?: string
  ai_answer_download_url?: string
}

type NavigationState = {
  revision?: string
  counts?: {
    leaderboard?: number
    matches?: number
    all_submissions?: number
    appeals?: number
    attachments?: number
  }
  quota?: {remaining?: number; limit?: number}
}
interface NavigationResponse extends ApiEnvelope {revision?: string; navigation?: NavigationState}

interface Response extends ApiEnvelope {
  competition: CompetitionSummary & {
    description?: string
    answer_format?: string
    created_at?: string
    submission_method?: string
  }
  rendered_description?: string
  files?: RankingFile[]
  tab: string
  is_admin?: boolean
  leaderboard?: JsonRecord[]
  user_submissions?: Submission[]
  matches?: JsonRecord[]
  matches_mine?: boolean
  matches_total?: number
  all_submissions?: Submission[]
  submission_stats?: {
    total?: number
    unique_users?: number
    accepted?: number
    top_score?: number | null
  }
  submission_search_q?: string
  all_appeals?: JsonRecord[]
  appeal_stats?: JsonRecord
  batch_classes?: JsonRecord[]
  batch_default_template?: string
  aj_endpoints?: JsonRecord[]
  answer_endpoints?: JsonRecord[]
  quality_gate_endpoints?: JsonRecord[]
  agent_global_endpoint_candidates?: Record<string, JsonRecord[]>
  judge_rules?: JsonRecord[]
  current_page?: number
  total_pages?: number
  page_numbers?: number[]
  can_submit?: boolean
  submit_block_reason?: string
  submit_quota?: {remaining: number; limit: number; next_reset?: string}
  submission_method?: string
  git_repo_url?: string
  navigation?: NavigationState
}

const statusClasses: Record<string, string> = {
  Accepted: 's-ok',
  Active: 's-ok',
  Judging: 's-info',
  Pending: 's-info',
  Queued: 's-info',
  Error: 's-err',
}

const statusLabels: Record<string, string> = {
  Accepted: '通过',
  Active: '对战中',
  Retired: '已退役',
  Judging: '评测中',
  Queued: '等待评测',
  Pending: '待评测',
  Error: '异常',
}

function modeLabel(scoring: string) {
  if (scoring === 'elo') return 'ELO'
  if (scoring === 'agent_judge') return 'AGENT JUDGE'
  if (scoring === 'reverse_judge') return 'REVERSE JUDGE'
  return 'ABSOLUTE'
}

function numberValue(value: unknown, fallback = 0) {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric : fallback
}

function useUnsavedChangesWarning(dirty: boolean) {
  useEffect(() => {
    if (!dirty) return undefined
    const beforeUnload = (event: BeforeUnloadEvent) => {event.preventDefault(); event.returnValue = ''}
    const linkClick = (event: MouseEvent) => {
      const guardedEvent = event as MouseEvent & {numojUnsavedPromptShown?: boolean}
      if (guardedEvent.numojUnsavedPromptShown) return
      const link = event.target instanceof Element ? event.target.closest('a[href]') : null
      if (!link || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return
      guardedEvent.numojUnsavedPromptShown = true
      if (!window.confirm('当前页面有未保存的修改，确定离开吗？')) {event.preventDefault(); event.stopPropagation()}
    }
    window.addEventListener('beforeunload', beforeUnload)
    document.addEventListener('click', linkClick, true)
    return () => {window.removeEventListener('beforeunload', beforeUnload); document.removeEventListener('click', linkClick, true)}
  }, [dirty])
}

function fileSize(bytesValue: unknown) {
  const bytes = numberValue(bytesValue)
  if (bytes >= 1048576) return {short: `${(bytes / 1048576).toFixed(1)}M`, long: `${(bytes / 1048576).toFixed(1)} MB`}
  if (bytes >= 1024) return {short: `${Math.floor(bytes / 1024)}K`, long: `${Math.floor(bytes / 1024)} KB`}
  return {short: `${bytes}B`, long: `${bytes} B`}
}

function submissionScore(row: Submission, isElo: boolean) {
  return isElo ? row.elo_rating : row.score
}

function EndpointIdentity({harness, model, className = '', title}: {harness: unknown; model: unknown; className?: string; title?: string}) {
  const harnessName = endpointHarnessLabel(harness)
  const modelName = String(model || '模型节点')
  return <span className={`ranking-endpoint-identity${className ? ` ${className}` : ''}`} title={title}><i className={harnessIconClass(harness)} aria-hidden="true" /><span className="rj-endpoint-harness-name">{harnessName}</span><span className="rj-endpoint-plus" aria-hidden="true">+</span><ModelLogo model={modelName} className="rj-endpoint-model-logo" /><span className="rj-endpoint-model-name">{modelName}</span></span>
}

function SubmissionCard({row, competition, scoring, isElo, onDetail, onDelete}: {row: Submission; competition: Response['competition']; scoring: string; isElo: boolean; onDetail?: (row: Submission) => void; onDelete?: (row: Submission) => void}) {
  const status = String(row.status || '')
  const score = submissionScore(row, isElo)
  const maxScore = numberValue(competition.max_score, 100)
  const percentage = score == null
    ? 0
    : isElo
      ? Math.max(0, Math.min(100, (numberValue(score) - 800) * 100 / 1600))
      : Math.max(0, Math.min(100, numberValue(score) * 100 / Math.max(1, maxScore)))
  const username = String(row.username || '未知用户')
  return <article className={`aj-sub ${statusClasses[status] || 's-muted'}`} data-submission-id={row.id} data-username={username.toLowerCase()}>
    <div className="aj-sub-r1">
      <div className="aj-sub-idu">
        <span className="aj-sub-user"><Identicon seed={username} className="aj-sub-ava" /><span className="aj-sub-uname">{username}</span></span>
        <span className="aj-sub-id">#{row.id}</span>
        <span className={`aj-st ${statusClasses[status] || 's-muted'}`}><span className="d" />{statusLabels[status] || status || '未知状态'}</span>
      </div>
      <div className="aj-sub-scoreline">
        <span className="aj-bar" role="progressbar" aria-label={`提交 #${row.id} 得分`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(percentage)}><i style={{'--submission-score': `${percentage.toFixed(1)}%`} as CSSProperties} /></span>
        <span className="aj-sub-score">{score == null ? <span>—</span> : isElo ? <><b>{numberValue(score).toFixed(0)}</b><span> · {numberValue(row.elo_match_count)} 战</span></> : <><b>{numberValue(score).toFixed(2)}</b><span> / {maxScore}</span></>}</span>
      </div>
    </div>
    <div className="aj-sub-r2">
      <div className="aj-sub-meta">
        <span className="aj-time">{String(row.created_at || '')}</span>
        {row.agent_endpoint_label ? <EndpointIdentity className="aj-card-meta" harness={row.agent_endpoint_harness} model={row.agent_endpoint_model} title={`AI 节点：${row.agent_endpoint_label}`} /> : null}
        {row.base_model ? <span className="aj-card-meta" title={`基座模型：${row.base_model}`}><ModelLogo model={row.base_model} /><span>{row.base_model}</span></span> : null}
        {row.answer_filename && row.answer_download_url ? <a className="aj-file" href={row.answer_download_url} download title={`下载 ${row.answer_filename}`}><i className="fas fa-file-code" />答案</a> : null}
        {row.code_filename && row.code_download_url ? <a className="aj-file" href={row.code_download_url} download title={`下载 ${row.code_filename}`}><i className="fas fa-file-archive" />{isElo ? '作品' : '代码'}</a> : null}
      </div>
      <div className="aj-acts">{onDetail && (scoring === 'agent_judge' || scoring === 'reverse_judge') ? <button type="button" className={`aj-detail ${scoring === 'agent_judge' ? 'judge-detail-btn' : 'reverse-detail-btn'}`} onClick={() => onDetail(row)}><i className="fas fa-list-check" />{scoring === 'agent_judge' ? '评分详情' : '评测详情'}</button> : null}{onDelete ? <button type="button" className="aj-del" title="删除该提交" aria-label={`删除提交 #${row.id}`} onClick={() => onDelete(row)}><i className="fas fa-trash" /></button> : null}</div>
    </div>
  </article>
}

function FileDrop({kind, title, extension, icon, file, onFile}: {kind: string; title: string; extension: string; icon: string; file: File | null; onFile: (file: File | null) => void}) {
  const [dragging, setDragging] = useState(false)
  const drop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault()
    setDragging(false)
    onFile(event.dataTransfer.files?.[0] || null)
  }
  return <label className={`file-drop${file ? ' has-file' : ''}${dragging ? ' dragover' : ''}`} data-kind={kind} onDragEnter={(event) => {event.preventDefault(); setDragging(true)}} onDragOver={(event) => event.preventDefault()} onDragLeave={() => setDragging(false)} onDrop={drop}>
    <input type="file" name={`${kind}_file`} accept={extension} required hidden onChange={(event) => onFile(event.target.files?.[0] || null)} />
    <div className="file-drop-inner">
      <i className={`fas ${icon} file-drop-icon file-drop-icon-${kind}`} />
      <div className="file-drop-title">{title}</div>
      <div className="file-drop-sub" hidden={Boolean(file)}><span className="file-drop-ext">{extension}</span></div>
      <div className="file-drop-selected" hidden={!file}><i className="fas fa-check-circle" /><span className="file-name">{file?.name}</span><span className="file-size">{file ? fileSize(file.size).long : ''}</span></div>
    </div>
  </label>
}

function SubmitPanel({data, competitionId}: {data: Response; competitionId: string}) {
  const queryClient = useQueryClient()
  const scoring = String(data.competition.scoring_mode || 'absolute').toLowerCase()
  const isElo = scoring === 'elo'
  const isAgentJudge = scoring === 'agent_judge'
  const isReverseJudge = scoring === 'reverse_judge'
  const answerFormat = String(data.competition.answer_format || 'json').toLowerCase()
  const submissionMethod = String(data.submission_method || data.competition.submission_method || 'zip').toLowerCase()
  const endpoints = (data.aj_endpoints || data.answer_endpoints || []).filter((item) => String(item.status || 'enabled') === 'enabled')
  const [reverseMode, setReverseMode] = useState<'git' | 'zip'>('git')
  const [reverseModeOpen, setReverseModeOpen] = useState(false)
  const [endpointOpen, setEndpointOpen] = useState(false)
  const [endpointId, setEndpointId] = useState(() => String(endpoints[0]?.id || ''))
  const [answerFile, setAnswerFile] = useState<File | null>(null)
  const [codeFile, setCodeFile] = useState<File | null>(null)
  const [baseModel, setBaseModel] = useState('')
  const [detailTarget, setDetailTarget] = useState<RankingSubmissionOverlayTarget | null>(null)
  const [gitResult, setGitResult] = useState<(ApiEnvelope & {exists?: boolean; info?: JsonRecord; url?: string}) | null>(null)
  const reverseModeRef = useDismissibleDropdown<HTMLDivElement>(reverseModeOpen, () => setReverseModeOpen(false))
  const endpointRef = useDismissibleDropdown<HTMLDivElement>(endpointOpen, () => setEndpointOpen(false))
  const selectedEndpoint = endpoints.find((item) => String(item.id) === endpointId)
  const endpointHarness = endpointHarnessLabel(selectedEndpoint?.harness)
  const endpointModel = String(selectedEndpoint?.model || (selectedEndpoint?.id ? `节点 #${selectedEndpoint.id}` : ''))
  const endpointLabel = selectedEndpoint ? `${endpointHarness} + ${endpointModel}` : '无可用节点'
  const gitMode = (isAgentJudge && submissionMethod === 'git') || (isReverseJudge && reverseMode === 'git')

  const submit = useMutation({
    mutationFn: () => {
      const body = new FormData()
      if (answerFile) body.append('answer_file', answerFile)
      if (codeFile) body.append('code_file', codeFile)
      if (!isReverseJudge) body.append('base_model', baseModel.trim())
      if (isReverseJudge && endpointId) body.append('agent_endpoint_id', endpointId)
      return apiFetch<ApiEnvelope & {submission_id?: number}>(`/api/ranking/competitions/${competitionId}/submissions`, {method: 'POST', body})
    },
    onSuccess: async () => {
      setAnswerFile(null)
      setCodeFile(null)
      setBaseModel('')
      await queryClient.invalidateQueries({queryKey: ['ranking', competitionId]})
    },
  })
  const checkGit = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope & {exists?: boolean; info?: JsonRecord; url?: string}>(`/api/ranking/competitions/${competitionId}/repository/check`, {method: 'POST'}),
    onSuccess: setGitResult,
    onError: () => setGitResult(null),
  })
  const submitGit = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${competitionId}/repository/submissions`, {method: 'POST', body: JSON.stringify(isReverseJudge ? {agent_endpoint_id: Number(endpointId)} : {})}),
    onSuccess: async () => {setGitResult(null); await queryClient.invalidateQueries({queryKey: ['ranking', competitionId]})},
  })
  const needAnswer = !isElo && !isAgentJudge && !isReverseJudge
  const ready = Boolean(codeFile && (!needAnswer || answerFile) && (isReverseJudge ? endpointId : baseModel.trim()))
  const submissions = data.user_submissions || []
  const best = submissions.reduce<number | null>((current, row) => {
    const score = submissionScore(row, isElo)
    if (score == null) return current
    return current == null ? numberValue(score) : Math.max(current, numberValue(score))
  }, null)
  const submitForm = (event: FormEvent) => {
    event.preventDefault()
    if (ready && !submit.isPending) submit.mutate()
  }
  const gitInfo = gitResult?.info
  const gitReady = Boolean(gitResult?.exists && gitInfo && (!isReverseJudge || endpointId))
  return <section className="ranking-v2-tab ranking-v2-submit" id="rankingSubmitTab" data-ranking-tab-panel="submit">
    {data.submit_quota ? <div className="rank-quota"><span>本轮可提交 <strong>{data.submit_quota.remaining}</strong> / {data.submit_quota.limit} 次</span><span className="rank-quota-sep">·</span><span>每 48 小时刷新</span>{data.submit_quota.next_reset ? <><span className="rank-quota-sep">·</span><span>下次刷新 {String(data.submit_quota.next_reset).slice(0, 16).replace('T', ' ')}</span></> : null}</div> : null}
    {isReverseJudge ? <div className="rj-submit-controls">
      <div className="rj-submit-switch"><label htmlFor="reverseSubmitModeTrigger"><i className="fas fa-upload me-2" />提交方式</label><input type="hidden" value={reverseMode} readOnly /><div ref={reverseModeRef} className={`rk-choice rk-choice-sm${reverseModeOpen ? ' open' : ''}`}><button type="button" className="rk-choice-trigger" id="reverseSubmitModeTrigger" aria-haspopup="listbox" aria-expanded={reverseModeOpen} onClick={() => setReverseModeOpen((value) => !value)}><span className="rk-choice-trigger-main"><i className={`fas ${reverseMode === 'git' ? 'fa-code-branch' : 'fa-file-archive'}`} /><span>{reverseMode === 'git' ? 'Git 仓库' : 'ZIP 压缩包'}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox" aria-label="提交方式" hidden={!reverseModeOpen}>{[['git', 'Git 仓库', 'fa-code-branch'], ['zip', 'ZIP 压缩包', 'fa-file-archive']].map(([value, label, icon]) => <button type="button" className={`rk-choice-option${reverseMode === value ? ' active' : ''}`} role="option" aria-selected={reverseMode === value} key={value} onClick={() => {setReverseMode(value as 'git' | 'zip'); setReverseModeOpen(false)}}><span className="rk-choice-option-main"><i className={`fas ${icon}`} /><span className="rk-choice-option-name">{label}</span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div></div></div>
      <div className="rj-submit-switch rj-node-switch"><label htmlFor="reverseAgentEndpointTrigger"><i className="fas fa-robot me-2" />AI 节点</label><input type="hidden" value={endpointId} readOnly /><div ref={endpointRef} className={`rk-choice rk-choice-sm${endpointOpen ? ' open' : ''}`}><button type="button" className="rk-choice-trigger" id="reverseAgentEndpointTrigger" aria-haspopup="listbox" aria-expanded={endpointOpen} aria-label={`AI 节点：${endpointLabel}`} onClick={() => setEndpointOpen((value) => !value)}><span className="rk-choice-trigger-main rj-endpoint-trigger-main">{selectedEndpoint ? <EndpointIdentity harness={selectedEndpoint.harness} model={endpointModel} /> : <><i className="fas fa-robot" aria-hidden="true" /><span className="rj-endpoint-empty-name">无可用节点</span></>}<span className="visually-hidden" aria-hidden="true">{endpointLabel}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox" aria-label="AI 节点" hidden={!endpointOpen}>{endpoints.map((item) => {const model = String(item.model || `节点 #${item.id}`); return <button type="button" className={`rk-choice-option${String(item.id) === endpointId ? ' active' : ''}`} role="option" aria-selected={String(item.id) === endpointId} key={String(item.id)} onClick={() => {setEndpointId(String(item.id)); setEndpointOpen(false)}}><span className="rk-choice-option-main rj-endpoint-option-main"><EndpointIdentity harness={item.harness} model={model} /></span><i className="fas fa-check rk-choice-option-check" /></button>})}</div></div></div>
    </div> : null}
    {data.submit_block_reason ? <p className="ranking-submit-block-reason"><i className="fas fa-exclamation-triangle me-2" />{data.submit_block_reason}</p> : gitMode ? <div className="gitsub" id="reverseGitPanel">
      <div className="gitsub-head"><h3>Git 提交</h3><span>从你的仓库拉取最新内容并评测</span></div>
      <div className="gitsub-repo"><span className="k">仓库</span><code className="u" id="gitsubUrl">{data.git_repo_url || ''}</code>{data.git_repo_url ? <button type="button" className="gitsub-copy" title="复制地址" aria-label="复制仓库地址" onClick={() => void navigator.clipboard?.writeText(data.git_repo_url || '')}><i className="fas fa-copy" /></button> : null}</div>
      {!data.git_repo_url ? <div className="gitsub-note">管理员尚未配置 Git 仓库标准命名，暂时无法提交。</div> : <><div className="gitsub-actions"><button type="button" className="gitsub-btn gitsub-btn-ghost" disabled={checkGit.isPending} onClick={() => checkGit.mutate()}><MathCurveLoader iconOnly size="xs" hidden={!checkGit.isPending} ariaLabel="检查中" /><span>{checkGit.isPending ? '检查中' : '检查仓库'}</span></button></div>{checkGit.isError ? <div className="gitsub-result"><div className="gitsub-status no"><span className="dot" />{errorMessage(checkGit.error)}</div></div> : gitResult ? <div className="gitsub-result">{gitResult.exists && gitInfo ? <><div className="gitsub-status ok"><span className="dot" />仓库已找到 · 最新提交</div><div className="gitsub-commit"><span className="ck">提交</span><span className="cv subj">{String(gitInfo.subject || '(无标题)')}</span><span className="ck">哈希</span><span className="cv mono">{String(gitInfo.short || '')}</span><span className="ck">作者</span><span className="cv">{String(gitInfo.author || '')}</span><span className="ck">时间</span><span className="cv">{String(gitInfo.date_iso || '')}</span>{String(gitInfo.body || '').trim() ? <><span className="ck">说明</span><span className="cv"><span className="body">{String(gitInfo.body)}</span></span></> : null}</div></> : <><div className={`gitsub-status ${gitResult.exists ? 'ok' : 'no'}`}><span className="dot" />{gitResult.exists ? '仓库已找到' : '未找到仓库'}</div><div className="gitsub-note">{gitResult.message || (gitResult.exists ? '仓库存在，但还没有任何提交。' : '无法访问该仓库，请确认已创建并具备读取权限。')}</div></>}</div> : null}{gitReady ? <div className="gitsub-confirm"><button type="button" className="gitsub-btn gitsub-btn-solid" disabled={submitGit.isPending} onClick={() => submitGit.mutate()}><MathCurveLoader iconOnly size="xs" hidden={!submitGit.isPending} ariaLabel="提交中" /><span>{submitGit.isPending ? '提交中' : '确认提交'}</span></button><span className={`gitsub-confirm-hint${submitGit.isError ? ' no' : ''}`}>{submitGit.isError ? errorMessage(submitGit.error) : ''}</span></div> : null}</>}
    </div> : <form id="rankingSubmitForm" className="submit-form mb-4" onSubmit={submitForm}>
      <div className="row g-3">
        {needAnswer ? <div className="col-md-6"><FileDrop kind="answer" title="答案文件" extension={`.${answerFormat}`} icon={answerFormat === 'zip' ? 'fa-file-archive' : 'fa-file-code'} file={answerFile} onFile={setAnswerFile} /></div> : null}
        <div className={needAnswer ? 'col-md-6' : 'col-md-12'}><FileDrop kind="code" title={isReverseJudge ? '反向评测题目包' : isElo ? '作品压缩包' : '代码文件'} extension=".zip" icon="fa-file-archive" file={codeFile} onFile={setCodeFile} /></div>
      </div>
      {!isReverseJudge ? <div className="mt-4"><label htmlFor="rankingBaseModelInput" className="form-label fw-semibold">基座模型 <span className="text-danger">*</span></label><input type="text" className="form-control" id="rankingBaseModelInput" name="base_model" required maxLength={500} placeholder="例如：deepseek-v4-pro, qwen3.6-plus" value={baseModel} onChange={(event) => setBaseModel(event.target.value)} /></div> : null}
      <div className="submit-actions mt-4"><button type="submit" className="btn btn-primary submit-cta" id="rankingSubmitBtn" disabled={!ready || submit.isPending}><i className="fas fa-paper-plane me-2" />{submit.isPending ? '提交中…' : '提交评测'}</button><span className="submit-hint ms-3 text-muted small" id="rankingSubmitHint">{ready ? '就绪' : isReverseJudge ? !endpointId ? '请选择 AI 节点' : '请选择文件' : !codeFile || (needAnswer && !answerFile) ? '请选择文件' : '请填写基座模型'}</span></div>
      {submit.isError ? <p className="ranking-submit-block-reason mt-3"><i className="fas fa-exclamation-triangle me-2" />{errorMessage(submit.error)}</p> : null}
    </form>}
    <div data-ranking-submission-history>
      <div className="my-history-header"><strong>我的历史提交</strong>{submissions.length ? <div className="history-stats"><span className="history-stat"><span className="history-stat-val">{submissions.length}</span><span className="history-stat-label">次</span></span><span className="history-stat"><span className="history-stat-val">{best == null ? '—' : best.toFixed(isElo ? 0 : 2)}</span><span className="history-stat-label">{isElo ? '最高 ELO' : '最高分'}</span></span></div> : null}</div>
      {submissions.length ? <div className="aj-subs">{submissions.map((row) => <SubmissionCard row={row} competition={data.competition} scoring={scoring} isElo={isElo} onDetail={(item) => setDetailTarget({id: item.id, createdAt: item.created_at, status: item.status, username: item.username, answerDownloadUrl: item.ai_answer_download_url})} key={row.id} />)}</div> : <div className="ranking-v2-empty submissions-empty"><i className="fas fa-inbox" /><strong>暂无提交</strong><span>提交作品后，这里会显示每次评测结果。</span></div>}
    </div>
    {isAgentJudge ? <JudgeDetailModal competitionId={competitionId} target={detailTarget} canAppeal onClose={() => setDetailTarget(null)} onTerminal={() => queryClient.invalidateQueries({queryKey: ['ranking', competitionId]})} /> : null}
    {isReverseJudge ? <ReverseJudgeDetailModal competitionId={competitionId} target={detailTarget} onClose={() => setDetailTarget(null)} onTerminal={() => queryClient.invalidateQueries({queryKey: ['ranking', competitionId]})} /> : null}
  </section>
}

function LeaderboardPanel({data, username}: {data: Response; username?: string}) {
  const rows = data.leaderboard || []
  const scoring = String(data.competition.scoring_mode || 'absolute').toLowerCase()
  const max = numberValue(data.competition.max_score, 100)
  return <section className="ranking-v2-tab ranking-v2-leaderboard">{rows.length ? <div className="ranking-v2-leaderboard-scroll"><div className="leaderboard-list">{rows.map((row, index) => {
    const rank = numberValue(row.rank, index + 1)
    const rowUsername = String(row.username || row.name || '—')
    const score = numberValue(row.best_score ?? row.score ?? row.rating)
    return <div className={`leaderboard-row${rowUsername === username ? ' is-current-user' : ''}`} key={`${rowUsername}-${index}`}><span className={`lb-rank${rank <= 3 ? ' is-top' : ''}`}>{String(rank).padStart(2, '0')}</span><span className="lb-user"><Identicon seed={rowUsername} className="lb-avatar" /><span className="lb-user-copy"><strong className="lb-username"><span>{rowUsername}</span>{rowUsername === username ? <em className="lb-me-badge">YOU</em> : null}</strong><span className="lb-subs">{numberValue(row.submission_count)} SUBMISSIONS</span></span></span><span className="lb-score-bar"><i style={{'--ranking-score-pct': `${Math.min(100, score * 100 / Math.max(1, max))}%`} as CSSProperties} /></span><span className="lb-score">{score.toFixed(scoring === 'elo' ? 0 : 2)} <small>{scoring === 'elo' ? 'ELO' : `/ ${max}`}</small></span></div>
  })}</div></div> : <div className="ranking-v2-empty ranking-v2-empty--leaderboard"><i className="fas fa-ranking-star" /><strong>暂无有效成绩</strong><span>等待首位选手完成评测，排名将在这里出现。</span></div>}</section>
}

function AttachmentList({files}: {files: RankingFile[]}) {
  const [media, setMedia] = useState<RankingMediaTarget | null>(null)
  if (!files.length) return <div className="ranking-attachments-empty">暂无附件</div>
  return <><div className="ranking-file-list" data-ranking-attachment-list>{files.map((file) => {
    const size = fileSize(file.file_size)
    return <div className="ranking-file-row" data-ranking-attachment-row title={`${file.filename} · ${size.long}`} key={file.id}><a href={file.download_url} className="ranking-file-download" download title={`下载 ${file.filename}`}><i className="fas fa-paperclip" /><b>{file.filename}</b><span>{size.short}</span></a>{file.media_kind ? <button type="button" className="ranking-file-action rk-media-btn" title={`${file.media_kind === 'video' ? '播放' : '查看'} ${file.filename}`} onClick={() => setMedia({filename: file.filename, mediaKind: file.media_kind || 'image', inlineUrl: `${file.download_url}?inline=1`, downloadUrl: file.download_url})}><i className={`fas ${file.media_kind === 'video' ? 'fa-play' : 'fa-eye'}`} /></button> : null}</div>
  })}</div><MediaPreviewModal target={media} onClose={() => setMedia(null)} /></>
}

function Pagination({data, tab}: {data: Response; tab: string}) {
  const pages = data.page_numbers || []
  const current = numberValue(data.current_page, 1)
  const total = numberValue(data.total_pages, 1)
  if (total <= 1) return null
  const href = (page: number) => `/rankings/${data.competition.id}${queryString({tab, page, mine: data.matches_mine ? 1 : null, q: data.submission_search_q || null})}`
  return <footer className="matches-pagination"><nav aria-label="分页"><ul className="pagination mb-0">
    <li className={`page-item${current <= 1 ? ' disabled' : ''}`}><Link className="page-link" to={href(current - 1)} aria-label="上一页"><i className="fas fa-arrow-left" /></Link></li>
    {pages.map((page) => <li className={`page-item${page === current ? ' active' : ''}`} key={page}><Link className="page-link" to={href(page)}>{page}</Link></li>)}
    <li className={`page-item${current >= total ? ' disabled' : ''}`}><Link className="page-link" to={href(current + 1)} aria-label="下一页"><i className="fas fa-arrow-right" /></Link></li>
  </ul></nav></footer>
}

type BulkFilterResponse = ApiEnvelope & {
  submissions?: Submission[]
  total?: number
  too_many?: boolean
  max_results?: number
  max_selected?: number
}

type BulkJobResponse = ApiEnvelope & {
  job_id?: string
  total?: number
  processed?: number
  requeued?: number
  created?: number
  failed?: number
  progress?: number
  done?: boolean
}

function AllSubmissionsPanel({data}: {data: Response}) {
  const queryClient = useQueryClient()
  const [params, setParams] = useSearchParams()
  const stats = data.submission_stats || {}
  const rows = data.all_submissions || []
  const total = numberValue(stats.total)
  const accepted = numberValue(stats.accepted)
  const maxScore = numberValue(data.competition.max_score, 100)
  const isElo = String(data.competition.scoring_mode || '').toLowerCase() === 'elo'
  const scoring = String(data.competition.scoring_mode || '').toLowerCase()
  const [detailTarget, setDetailTarget] = useState<RankingSubmissionOverlayTarget | null>(null)
  const [search, setSearch] = useState(data.submission_search_q || '')
  const [bulkStart, setBulkStart] = useState('')
  const [bulkEnd, setBulkEnd] = useState('')
  const [bulkUsername, setBulkUsername] = useState('')
  const [statuses, setStatuses] = useState<string[]>([])
  const [filteredRows, setFilteredRows] = useState<Submission[]>([])
  const [selected, setSelected] = useState<number[]>([])
  const [maxSelected, setMaxSelected] = useState(500)
  const [tooMany, setTooMany] = useState(false)
  const [jobId, setJobId] = useState('')
  const [bulkOpen, setBulkOpen] = useState(false)

  useEffect(() => {setSearch(data.submission_search_q || '')}, [data.submission_search_q])
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const query = search.trim()
      if (query === (params.get('q') || '')) return
      const next = new URLSearchParams(params)
      next.set('tab', 'all_submissions')
      next.set('page', '1')
      if (query) next.set('q', query)
      else next.delete('q')
      setParams(next, {replace: true})
    }, 250)
    return () => window.clearTimeout(timer)
  }, [params, search, setParams])

  const filter = useMutation({
    mutationFn: () => apiFetch<BulkFilterResponse>(`/api/ranking/competitions/${data.competition.id}/rejudge/filter`, {
      method: 'POST',
      body: JSON.stringify({start: bulkStart, end: bulkEnd, username: bulkUsername.trim(), statuses}),
    }),
    onSuccess: (payload) => {
      setFilteredRows(payload.submissions || [])
      setSelected([])
      setMaxSelected(numberValue(payload.max_selected, 500))
      setTooMany(Boolean(payload.too_many))
    },
  })
  const start = useMutation({
    mutationFn: () => apiFetch<BulkJobResponse>(`/api/ranking/competitions/${data.competition.id}/rejudge/jobs`, {
      method: 'POST', body: JSON.stringify({submission_ids: selected}),
    }),
    onSuccess: (payload) => setJobId(String(payload.job_id || '')),
  })
  const job = useQuery({
    queryKey: ['ranking-bulk-rejudge', data.competition.id, jobId],
    queryFn: () => apiFetch<BulkJobResponse>(`/api/ranking/competitions/${data.competition.id}/rejudge/jobs/${encodeURIComponent(jobId)}`),
    enabled: Boolean(jobId),
    refetchInterval: (query) => query.state.data?.done ? false : 1000,
  })
  useEffect(() => {
    if (!job.data?.done) return
    setSelected([])
    void queryClient.invalidateQueries({queryKey: ['ranking', String(data.competition.id)]})
  }, [data.competition.id, job.data?.done, queryClient])

  const toggleStatus = (value: string, checked: boolean) => {
    setStatuses((current) => checked ? [...current, value] : current.filter((item) => item !== value))
  }
  const allSelected = filteredRows.length > 0 && filteredRows.every((row) => selected.includes(row.id))
  const summary = filter.isError
    ? errorMessage(filter.error)
    : tooMany
      ? `命中 ${numberValue(filter.data?.total)} 条，超过显示上限 ${numberValue(filter.data?.max_results)} 条，请缩小筛选范围。`
      : filteredRows.length
        ? `筛选出 ${filteredRows.length} 条，已选择 ${selected.length} 条。`
        : filter.isSuccess ? '暂无筛选结果。' : ''
  const progress = numberValue(job.data?.progress)
  const running = Boolean(jobId && !job.data?.done)
  const remove = useMutation({
    mutationFn: (submissionId: number) => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${data.competition.id}/submissions/${submissionId}`, {method: 'DELETE'}),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['ranking', String(data.competition.id)]}),
  })

  return <section className="ranking-v2-tab ranking-v2-submissions" data-ranking-tab-panel="all_submissions">
    <div className="submissions-stats">
      <div className="sub-stat"><div className="sub-stat-value">{total}</div><div className="sub-stat-label">总提交</div></div>
      <div className="sub-stat"><div className="sub-stat-value">{numberValue(stats.unique_users)}</div><div className="sub-stat-label">参赛用户</div></div>
      <div className="sub-stat"><div className="sub-stat-value">{accepted}<span className="sub-stat-sub"> / {total} · {(accepted * 100 / Math.max(1, total)).toFixed(1)}%</span></div><div className="sub-stat-label">通过</div></div>
      <div className="sub-stat"><div className="sub-stat-value">{stats.top_score == null ? '—' : <>{numberValue(stats.top_score).toFixed(2)}<span className="sub-stat-sub"> / {maxScore}</span></>}</div><div className="sub-stat-label">最高分</div></div>
    </div>
    <div className="submissions-toolbar"><strong>提交记录</strong><div className="submissions-toolbar-actions">
      <button type="button" className="rk-bulk-open" onClick={() => setBulkOpen(true)} disabled={total === 0}><i className="fas fa-rotate-right" /><span>批量重测</span></button>
      {total > 0 ? <div className="submissions-search"><i className="fas fa-search" /><input type="search" id="subSearch" className="form-control form-control-sm" placeholder="按用户名筛选…" autoComplete="off" value={search} onChange={(event) => setSearch(event.target.value)} /></div> : null}
    </div></div>

    <ReactModal open={bulkOpen} onClose={() => setBulkOpen(false)} id="rankingBulkRejudgeModal" labelledBy="rankingBulkRejudgeLabel" className="rk-bulk-modal" dialogClassName="modal-xl modal-dialog-scrollable">
      <div className="modal-content">
        <div className="modal-header"><div><h5 className="modal-title" id="rankingBulkRejudgeLabel">批量重测</h5><div className="rk-bulk-subtitle">在原提交记录上清空旧结果并重新入队，按评测队列并发限制执行。</div></div><button type="button" className="btn-close" onClick={() => setBulkOpen(false)} aria-label="关闭" /></div>
        <div className="modal-body">
          <div className="rk-bulk-filters">
            <label className="rk-bulk-field"><span>起始时间</span><input type="datetime-local" value={bulkStart} onChange={(event) => setBulkStart(event.target.value)} /></label>
            <label className="rk-bulk-field"><span>结束时间</span><input type="datetime-local" value={bulkEnd} onChange={(event) => setBulkEnd(event.target.value)} /></label>
            <label className="rk-bulk-field"><span>用户</span><input type="text" placeholder="用户名包含" value={bulkUsername} onChange={(event) => setBulkUsername(event.target.value)} /></label>
            <button type="button" className="rk-bulk-filter-btn" disabled={filter.isPending || running} onClick={() => filter.mutate()}><i className="fas fa-filter" /><span>{filter.isPending ? '筛选中…' : '筛选'}</span></button>
          </div>
          <div className="rk-bulk-statuses" aria-label="状态筛选">{[['judging', '评测中'], ['waiting', '等待评测'], ['accepted', '通过'], ['abnormal', '异常']].map(([value, label]) => <label key={value}><input type="checkbox" className="rk-bulk-status" value={value} checked={statuses.includes(value)} onChange={(event) => toggleStatus(value, event.target.checked)} /><span>{label}</span></label>)}</div>
          <div className="rk-bulk-result-head"><div>{summary}</div><div className="rk-bulk-select"><label><input type="checkbox" checked={allSelected} disabled={!filteredRows.length || tooMany || running} onChange={(event) => setSelected(event.target.checked ? filteredRows.map((row) => row.id) : [])} /><span>全选</span></label></div></div>
          <div className="rk-bulk-results" aria-live="polite">{filteredRows.length ? filteredRows.map((row) => {
            const status = String(row.status || '')
            const score = submissionScore(row, isElo)
            return <div className="rk-bulk-row" key={row.id}><label className="rk-bulk-check"><input type="checkbox" checked={selected.includes(row.id)} disabled={tooMany || running} onChange={(event) => setSelected((current) => event.target.checked ? [...current, row.id] : current.filter((id) => id !== row.id))} /><span>#{row.id}</span></label><div className="rk-bulk-cell rk-user">{row.username}</div><div className={`rk-bulk-pill ${statusClasses[status] === 's-ok' ? 'ok' : statusClasses[status] === 's-info' ? 'info' : statusClasses[status] === 's-err' ? 'err' : 'muted'}`}>{statusLabels[status] || status || '—'}</div><div className="rk-bulk-cell rk-score">{score == null ? '—' : numberValue(score).toFixed(isElo ? 0 : 2)}</div><div className="rk-bulk-cell rk-model">{row.base_model ? <><ModelLogo model={row.base_model} /> <span>{row.base_model}</span></> : '—'}</div><div className="rk-bulk-cell rk-time">{row.created_at}</div></div>
          }) : <div className="rk-bulk-empty">暂无筛选结果</div>}</div>
          {jobId ? <div className="rk-bulk-progress"><div className="rk-bulk-progress-track"><div className={`rk-bulk-progress-bar${job.data?.done ? ' is-done' : ''}`} style={{width: `${progress}%`}}>{progress}%</div></div><div className="rk-bulk-progress-text">重测入队进度 {numberValue(job.data?.processed)} / {numberValue(job.data?.total, selected.length)}，已入队 {numberValue(job.data?.requeued ?? job.data?.created)}，失败 {numberValue(job.data?.failed)}{job.data?.done ? '。重测已入队，原提交将按队列并发限制重新评测。' : ''}</div></div> : null}
          {start.isError || job.isError ? <div className="alert alert-danger mt-3 mb-0" role="alert">{errorMessage(start.error || job.error)}</div> : null}
        </div>
        <div className="modal-footer"><button type="button" className="rk-bulk-secondary" onClick={() => setBulkOpen(false)}>关闭</button><button type="button" className="rk-bulk-primary" disabled={!selected.length || selected.length > maxSelected || tooMany || running || start.isPending} onClick={() => start.mutate()}><i className="fas fa-play" /><span>确认重测</span></button></div>
      </div>
    </ReactModal>

    {rows.length ? <div className="aj-subs" data-ranking-submission-list>{rows.map((row) => <SubmissionCard row={row} competition={data.competition} scoring={scoring} isElo={isElo} onDetail={(item) => setDetailTarget({id: item.id, createdAt: item.created_at, status: item.status, username: item.username, answerDownloadUrl: item.ai_answer_download_url})} key={row.id} onDelete={(item) => {if (window.confirm(`确认删除提交 #${item.id}？`)) remove.mutate(item.id)}} />)}</div> : <div className="ranking-v2-empty submissions-empty"><i className="fas fa-inbox" /><strong>暂无提交</strong><span>尚未有选手提交作品。</span></div>}
    {total > 0 ? <div className="submissions-pagination mt-3"><Pagination data={data} tab="all_submissions" /></div> : null}
    {scoring === 'agent_judge' ? <JudgeDetailModal competitionId={data.competition.id} target={detailTarget} canAppeal={false} onClose={() => setDetailTarget(null)} onTerminal={() => queryClient.invalidateQueries({queryKey: ['ranking', String(data.competition.id)]})} /> : null}
    {scoring === 'reverse_judge' ? <ReverseJudgeDetailModal competitionId={data.competition.id} target={detailTarget} onClose={() => setDetailTarget(null)} onTerminal={() => queryClient.invalidateQueries({queryKey: ['ranking', String(data.competition.id)]})} /> : null}
  </section>
}

function MatchesPanel({data, username, isAdmin}: {data: Response; username?: string; isAdmin: boolean}) {
  const queryClient = useQueryClient()
  const [detailId, setDetailId] = useState<number | null>(null)
  const [trajectoryOpen, setTrajectoryOpen] = useState(false)
  const [trajectorySearch, setTrajectorySearch] = useState('')
  const [trajectorySearchQuery, setTrajectorySearchQuery] = useState('')
  const [trajectorySearchOpen, setTrajectorySearchOpen] = useState(false)
  const [trajectorySelected, setTrajectorySelected] = useState<JsonRecord[]>([])
  const [trajectoryExpanded, setTrajectoryExpanded] = useState(false)
  const trajectoryResultRef = useRef<HTMLElement>(null)
  const trajectorySearchRef = useDismissibleDropdown<HTMLElement>(trajectorySearchOpen, () => setTrajectorySearchOpen(false))
  const detail = useQuery({
    queryKey: ['ranking-match', data.competition.id, detailId],
    queryFn: () => apiFetch<RankingMatchDetail>(`/api/ranking/competitions/${data.competition.id}/matches/${detailId}`),
    enabled: detailId != null,
  })
  const remove = useMutation({
    mutationFn: (matchId: number) => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${data.competition.id}/matches/${matchId}`, {method: 'DELETE'}),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['ranking', String(data.competition.id)]}),
  })
  const rebuild = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${data.competition.id}/elo/rebuild`, {method: 'POST'}),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['ranking', String(data.competition.id)]}),
  })
  const trajectoryCandidates = useQuery({
    queryKey: ['ranking-elo-trajectory-submissions', data.competition.id, trajectorySearchQuery],
    queryFn: () => apiFetch<ApiEnvelope & {submissions?: JsonRecord[]; truncated?: boolean; max_selected?: number}>(`/api/ranking/competitions/${data.competition.id}/elo/trajectory/submissions${queryString({q: trajectorySearchQuery || null})}`),
    enabled: trajectoryOpen && trajectorySearchOpen,
  })
  const trajectory = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope & {series?: EloTrajectorySeries[]}>(`/api/ranking/competitions/${data.competition.id}/elo/trajectory`, {method: 'POST', body: JSON.stringify({submission_ids: trajectorySelected.map((item) => numberValue(item.id))})}),
    onError: (error) => {
      if (!(error instanceof ApiError) || !Array.isArray(error.payload?.missing_submission_ids)) return
      const missing = new Set(error.payload.missing_submission_ids.map(numberValue))
      setTrajectorySelected((current) => current.filter((item) => !missing.has(numberValue(item.id))))
    },
  })
  const closeTrajectory = () => {
    setTrajectoryOpen(false)
    setTrajectorySearchOpen(false)
    setTrajectoryExpanded(false)
    trajectory.reset()
  }
  const invalidateTrajectory = () => trajectory.reset()
  const toggleTrajectorySelection = (item: JsonRecord, checked: boolean) => {
    invalidateTrajectory()
    setTrajectorySelected((current) => checked ? [...current, item] : current.filter((selected) => numberValue(selected.id) !== numberValue(item.id)))
  }
  const removeTrajectorySelection = (submissionId: number) => {
    invalidateTrajectory()
    setTrajectorySelected((current) => current.filter((selected) => numberValue(selected.id) !== submissionId))
  }
  const analyzeTrajectory = () => {
    setTrajectorySearchOpen(false)
    setTrajectoryExpanded(true)
    trajectory.mutate()
  }
  useEffect(() => {
    if (!trajectoryOpen) return undefined
    const timer = window.setTimeout(() => setTrajectorySearchQuery(trajectorySearch.trim()), 220)
    return () => window.clearTimeout(timer)
  }, [trajectoryOpen, trajectorySearch])
  useEffect(() => {
    if (!trajectory.data) return
    const frame = window.requestAnimationFrame(() => trajectoryResultRef.current?.scrollIntoView({behavior: 'smooth', block: 'nearest'}))
    return () => window.cancelAnimationFrame(frame)
  }, [trajectory.data])
  useEffect(() => {
    if (!trajectoryOpen) return undefined
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closeTrajectory()
    }
    document.body.classList.add('modal-open')
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.body.classList.remove('modal-open')
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [trajectoryOpen])
  const rows = data.matches || []
  const trajectorySearchNote = trajectoryCandidates.isFetching
    ? '正在匹配 username…'
    : trajectoryCandidates.isError
      ? errorMessage(trajectoryCandidates.error)
      : ''
  return <section className="ranking-v2-tab ranking-v2-matches" data-ranking-tab-panel="matches"><div className="matches-card">
    <header className="matches-head"><nav className="matches-filter" aria-label="过滤"><Link className={`matches-filter-pill${!data.matches_mine ? ' is-active' : ''}`} to={`/rankings/${data.competition.id}?tab=matches`}>全部</Link><Link className={`matches-filter-pill${data.matches_mine ? ' is-active' : ''}`} to={`/rankings/${data.competition.id}?tab=matches&mine=1`}>与我相关</Link></nav><div className="matches-head-actions"><span className="matches-meta"><span className={`matches-meta-dot ${numberValue(data.competition.elo_running) === 1 ? 'is-live' : 'is-paused'}`} />{numberValue(data.competition.elo_running) === 1 ? `每 ${numberValue(data.competition.elo_match_interval_seconds, 60)} 秒一轮` : '匹配引擎已暂停'}</span><button type="button" className="matches-rebuild-btn matches-observe-btn" aria-haspopup="dialog" aria-expanded={trajectoryOpen} title="选择在役提交并观察每场对战后的 ELO 变化" onClick={() => setTrajectoryOpen(true)}><i className="fas fa-chart-line" /><span>观察变化</span></button>{isAdmin && rows.length ? <button type="button" className="matches-rebuild-btn" title="按时间顺序重放现存对战、刷新历史 rating 快照" disabled={rebuild.isPending} onClick={() => {if (window.confirm('确认按时间顺序重新计算所有对战的历史 rating 快照，并把每份提交的当前 ELO 同步到重放终态？\n\n这不会删除任何对战行，只是修正因删除操作导致的历史显示错位。')) rebuild.mutate()}}><i className="fas fa-wrench" /><span>重构历史轨迹</span></button> : null}</div></header>
    <div className="matches-scroll">{rows.length ? <div className="matches-list">{rows.map((match) => {
      const winner = numberValue(match.winner, -1)
      const a = String(match.username_a || `sub#${match.submission_a_id}`)
      const b = String(match.username_b || `sub#${match.submission_b_id}`)
      const da = numberValue(match.rating_a_after) - numberValue(match.rating_a_before)
      const db = numberValue(match.rating_b_after) - numberValue(match.rating_b_before)
      const mine = a === username || b === username
      const time = String(match.created_at || '')
      return <article className={`match-row${winner === -1 ? ' is-failed' : winner === 0 ? ' is-draw' : ''}${mine ? ' is-mine' : ''}`} key={numberValue(match.id)}>
        <button type="button" className="match-detail-btn" aria-label={`查看 ${a} 对阵 ${b} 的对战详情`} onClick={() => setDetailId(numberValue(match.id))} />
        <time className="match-time"><span className="match-time-date">{time.slice(5, 10)}</span><span className="match-time-clock">{time.slice(11, 16)}</span></time>
        <div className={`match-side match-side-a ${winner === 1 ? 'match-winner' : winner === 2 ? 'match-loser' : ''}`}><span className="match-person"><Identicon seed={a} className="match-avatar" /><span className="match-username">{a}{a === username ? <em className="match-me-tag">YOU</em> : null}</span></span><span className="match-stats"><span className="match-rating">{numberValue(match.rating_a_before).toFixed(0)}</span><span className={`match-delta${da > 0 ? ' is-up' : da < 0 ? ' is-down' : ''}`}>{da >= 0 ? '+' : ''}{da.toFixed(0)}</span></span></div>
        <div className="match-vs" data-victor={winner === 1 ? 'a' : winner === 2 ? 'b' : winner === 0 ? 'draw' : 'none'}>{winner === -1 ? <span className="match-vs-failed">N/C</span> : winner === 0 ? <span className="match-vs-draw">DRAW</span> : <span className="match-vs-badge"><i className={`fas ${winner === 1 ? 'fa-caret-left' : 'fa-caret-right'}`} /></span>}</div>
        <div className={`match-side match-side-b ${winner === 2 ? 'match-winner' : winner === 1 ? 'match-loser' : ''}`}><span className="match-stats"><span className={`match-delta${db > 0 ? ' is-up' : db < 0 ? ' is-down' : ''}`}>{db >= 0 ? '+' : ''}{db.toFixed(0)}</span><span className="match-rating">{numberValue(match.rating_b_before).toFixed(0)}</span></span><span className="match-person"><span className="match-username">{b === username ? <em className="match-me-tag">YOU</em> : null}{b}</span><Identicon seed={b} className="match-avatar" /></span></div>
        <div className="match-action"><span className="match-detail-label"><span>详情</span><i className="fas fa-arrow-right" /></span>{isAdmin ? <button type="button" className="match-delete-btn" aria-label={`删除对战 #${match.id}`} onClick={() => {if (window.confirm(`确认删除对战 #${match.id}？`)) remove.mutate(numberValue(match.id))}}><i className="fas fa-trash" /></button> : null}</div>
      </article>
    })}</div> : <div className="ranking-v2-empty matches-empty"><i className="fas fa-chess-board" /><strong>{data.matches_mine ? '你还没有踏上擂台' : '擂台尚无对决'}</strong><span>{numberValue(data.competition.elo_running) === 1 ? `等待匹配引擎调度首场对战，每 ${numberValue(data.competition.elo_match_interval_seconds, 60)} 秒一轮。` : '动态评分尚未启动，匹配引擎不会调度对战。'}</span></div>}<Pagination data={data} tab="matches" /></div>
  </div>
  {trajectoryOpen ? createPortal(<div className="ranking-v2-detail elo-trajectory-portal">
    <div className={`modal fade show d-block elo-trajectory-modal${trajectoryExpanded ? ' is-expanded' : ''}`} id="eloTrajectoryModal" tabIndex={-1} role="dialog" aria-modal="true" aria-label="观察得分变化" onPointerDown={(event) => {if (event.target === event.currentTarget) closeTrajectory()}}>
      <div className="modal-dialog">
        <div className="modal-content">
          <div className="modal-body">
            <div className="elo-observer-picker">
              <section ref={trajectorySearchRef} className="elo-observer-search-panel" aria-label="查找提交">
                <div className="submissions-search elo-observer-search">
                  <i className="fas fa-search" aria-hidden="true" />
                  <input type="search" className="form-control form-control-sm" placeholder="按用户名筛选…" autoComplete="off" value={trajectorySearch} onFocus={() => setTrajectorySearchOpen(true)} onChange={(event) => {setTrajectorySearch(event.target.value); setTrajectorySearchOpen(true)}} aria-controls="eloTrajectoryOptions" aria-expanded={trajectorySearchOpen} />
                </div>
                <div className="elo-observer-dropdown" id="eloTrajectoryOptions" role="listbox" aria-multiselectable="true" hidden={!trajectorySearchOpen} onPointerDown={(event) => {if ((event.target as Element).closest('.elo-observer-option')) event.preventDefault()}}>
                  {trajectoryCandidates.isFetching
                    ? <div className="elo-observer-dropdown-state">正在查找在役提交…</div>
                    : trajectoryCandidates.isError
                      ? <div className="elo-observer-dropdown-state">{errorMessage(trajectoryCandidates.error) || '搜索失败'}</div>
                      : (trajectoryCandidates.data?.submissions || []).length
                        ? (trajectoryCandidates.data?.submissions || []).map((item) => {
                          const id = numberValue(item.id)
                          const checked = trajectorySelected.some((selected) => numberValue(selected.id) === id)
                          const createdAt = String(item.created_at || '').slice(0, 16)
                          return <label className={`elo-observer-option${checked ? ' is-selected' : ''}`} role="option" aria-selected={checked} key={id}>
                            <input type="checkbox" checked={checked} disabled={!checked && trajectorySelected.length >= numberValue(trajectoryCandidates.data?.max_selected, 6)} aria-label={`选择 ${String(item.username || '')} 的提交 #${id}`} onChange={(event) => toggleTrajectorySelection(item, event.target.checked)} />
                            <span className="elo-observer-option-main"><strong>{String(item.username || '')}</strong><small>#{id} · {numberValue(item.match_count)} 战{createdAt ? ` · ${createdAt}` : ''}</small></span>
                            <span className="elo-observer-option-rating">{numberValue(item.rating).toFixed(0)}</span>
                          </label>
                        })
                        : <div className="elo-observer-dropdown-state">没有匹配的在役提交</div>}
                </div>
                <div className={`elo-observer-search-note${trajectoryCandidates.isError ? ' is-error' : ''}`} aria-live="polite">{trajectorySearchNote}</div>
              </section>
              <div className="elo-observer-selected" aria-label="已选提交" aria-live="polite">
                {trajectorySelected.length ? trajectorySelected.map((item) => {
                  const id = numberValue(item.id)
                  return <div className="elo-observer-chip" key={id}><span>{String(item.username || '')}<small>#{id}</small></span><button type="button" aria-label={`移除 ${String(item.username || '')} 的提交 #${id}`} onClick={() => removeTrajectorySelection(id)}>×</button></div>
                }) : <div className="elo-observer-selected-empty"><i className="fas fa-wave-square" aria-hidden="true" /><span>尚未选择提交</span></div>}
              </div>
            </div>
            {trajectory.isPending ? <div className="elo-trajectory-status" role="status">正在从数据库整理所选提交的完整对战轨迹…</div> : null}
            {trajectory.isError ? <div className="elo-trajectory-status is-error" role="status">{errorMessage(trajectory.error)}</div> : null}
            {trajectory.data ? <EloTrajectoryResult ref={trajectoryResultRef} series={trajectory.data.series || []} /> : null}
          </div>
          <div className="modal-footer elo-trajectory-footer"><div>
            <button type="button" className="elo-trajectory-secondary" onClick={closeTrajectory}>关闭</button>
            <button type="button" className="elo-trajectory-primary" disabled={!trajectorySelected.length || trajectory.isPending} aria-busy={trajectory.isPending || undefined} onClick={analyzeTrajectory}><i className="fas fa-play" aria-hidden="true" /><span>开始分析</span></button>
          </div></div>
        </div>
      </div>
    </div>
    <div className="modal-backdrop fade show" aria-hidden="true" />
  </div>, document.body) : null}
  <MatchDetailModal open={detailId != null} detail={detail.data} pending={detail.isPending} error={detail.isError ? detail.error : null} onClose={() => setDetailId(null)} /></section>
}

function AppealsPanel({data}: {data: Response}) {
  const appeals = data.all_appeals || []
  const stats = data.appeal_stats || {}
  return <section className="ranking-v2-tab ranking-v2-submissions"><div className="submissions-toolbar"><strong>申诉处理</strong><div className="history-stats"><span className="history-stat"><span className="history-stat-val">{numberValue(stats.pending)}</span><span className="history-stat-label">待处理</span></span><span className="history-stat"><span className="history-stat-val">{numberValue(stats.resolved)}</span><span className="history-stat-label">已处理</span></span></div></div>{appeals.length ? <div className="aj-subs">{appeals.map((appeal) => {
    const status = String(appeal.status || '')
    const cls = status === 'pending' ? 's-info' : status === 'rejected' ? 's-err' : 's-ok'
    const label = status === 'pending' ? '待处理' : status === 'rejected' ? '已驳回' : status === 'resolved' ? '已处理' : status
    const reason = String(appeal.reason || '')
    const user = String(appeal.username || '未知用户')
    return <article className={`aj-sub aj-appeal ${cls}`} key={numberValue(appeal.id)}><div className="aj-sub-r1"><div className="aj-sub-idu"><span className="aj-sub-user"><Identicon seed={user} className="aj-sub-ava" /><span className="aj-sub-uname">{user}</span></span><span className="aj-sub-id">提交 #{String(appeal.submission_id)}</span><span className={`aj-st ${cls}`}><span className="d" />{label}</span></div><div className="aj-sub-score">{appeal.sub_score == null ? <span>—</span> : <><b>{numberValue(appeal.sub_score).toFixed(2)}</b><span> / {numberValue(data.competition.max_score, 100)}</span></>}</div></div><div className="aj-sub-r2"><div className="aj-sub-meta"><span className="aj-time">{String(appeal.created_at || '')}</span>{appeal.base_model ? <span className="aj-chip"><ModelLogo model={appeal.base_model} /><span>{String(appeal.base_model)}</span></span> : null}<span className="aj-chip aj-appeal-reason" title={reason}><i className="fas fa-comment-dots me-1 opacity-75" />{reason.length > 48 ? `${reason.slice(0, 48)}…` : reason}</span></div><div className="aj-acts"><Link className="aj-detail" to={`/rankings/${data.competition.id}/appeals/${appeal.id}`}><i className="fas fa-list-check" />评分详情</Link></div></div></article>
  })}</div> : <div className="aj-subs-empty"><i className="fas fa-magnifying-glass" /><span>没有匹配的申诉</span></div>}<Pagination data={data} tab="appeals" /></section>
}

function RankingChoice({name, value, onChange, label, options, disabled = false}: {name: string; value: string; onChange: (next: string) => void; label: string; options: {value: string; label: string; icon: string}[]; disabled?: boolean}) {
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  const selected = options.find((item) => item.value === value) || options[0]
  const iconClass = (icon: string) => icon.includes(' ') ? icon : `fas ${icon}`
  return <div ref={rootRef} className={`rk-choice${open ? ' open' : ''}${disabled ? ' is-disabled' : ''}`}><input type="hidden" name={name} value={value} disabled={disabled} /><button type="button" className="rk-choice-trigger" aria-haspopup="listbox" aria-expanded={open} aria-label={label} disabled={disabled} onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main"><i className={iconClass(selected.icon)} /><span>{selected.label}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox" aria-label={label} hidden={!open}>{options.map((item) => <button type="button" className={`rk-choice-option${item.value === value ? ' active' : ''}`} role="option" aria-selected={item.value === value} key={item.value} onClick={() => {onChange(item.value); setOpen(false)}}><span className="rk-choice-option-main"><i className={iconClass(item.icon)} /><span className="rk-choice-option-name">{item.label}</span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div></div>
}

function LimitControl({competition, onReset}: {competition: Response['competition']; onReset: () => void}) {
  return <><div className="rank-limit-control"><input className="form-control" name="submit_limit_per_window" type="number" min={0} max={100000} step={1} defaultValue={competition.submit_limit_per_window == null ? '' : String(competition.submit_limit_per_window)} />{competition.submit_limit_per_window ? <button type="button" className="btn btn-outline-secondary rank-limit-refresh-btn" title="刷新提交次数" aria-label="刷新提交次数" onClick={onReset}><i className="fas fa-sync-alt" /></button> : null}</div>{competition.submit_limit_per_window && (competition.limit_window_start || competition.created_at) ? <div className="rank-limit-time"><i className="fas fa-clock me-2" />刷新时间：{String(competition.limit_window_start || competition.created_at).slice(0, 16)}</div> : null}</>
}

function endpointHarnessLabel(value: unknown) {
  const harness = String(value || 'claude_code')
  return harness === 'claude_code' ? 'Claude Code' : harness === 'codex' ? 'Codex' : harness === 'opencode' ? 'opencode' : harness === 'pi' ? 'Pi' : harness
}

function harnessIconClass(value: unknown) {
  const harness = String(value || 'claude_code')
  const key = harness === 'codex' || harness === 'opencode' || harness === 'pi' ? harness : 'claude-code'
  return `harness-logo harness-logo--${key}`
}

function modelIconClass(model: unknown) {
  return modelLogoClass(model)
}

function BatchClassLogo({item, className = 'bm-class-logo'}: {item: JsonRecord; className?: string}) {
  const seed = String(item.logo_seed || '').toLowerCase()
  if (seed.length < 15) return <span className={`${className} is-placeholder`} aria-hidden="true" />
  const cells: ReactNode[] = []
  ;[2, 1, 0].forEach((column) => {
    for (let row = 0; row < 5; row += 1) {
      const paintIndex = (2 - column) * 5 + row
      if (Number.parseInt(seed[paintIndex], 16) % 2 !== 0) continue
      cells.push(<rect x={column + 1} y={row + 1} width="1" height="1" key={`${column}-${row}-a`} />)
      if (column !== 2) cells.push(<rect x={5 - column} y={row + 1} width="1" height="1" key={`${column}-${row}-b`} />)
    }
  })
  return <span className={className} aria-hidden="true"><svg viewBox="0 0 7 7" focusable="false" shapeRendering="crispEdges">{cells}</svg></span>
}

type AjeChoiceOption = {value: string; label: string; icon: string}

function AjeChoice({value, onChange, label, options, disabled = false}: {value: string; onChange: (next: string) => void; label: string; options: AjeChoiceOption[]; disabled?: boolean}) {
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  const selected = options.find((option) => option.value === value) || options[0]
  const iconClass = (icon: string) => icon.includes(' ') ? icon : `fas ${icon}`
  return <div ref={rootRef} className={`aje-harness-picker${open ? ' open' : ''}`}><button type="button" className="aje-harness-trigger" role="combobox" aria-haspopup="listbox" aria-expanded={open} aria-label={label} disabled={disabled} onClick={() => setOpen((current) => !current)}><span className="aje-harness-trigger-main"><i className={iconClass(selected.icon)} aria-hidden="true" /><span>{selected.label}</span></span><i className="fas fa-chevron-down aje-harness-caret" aria-hidden="true" /></button><div className="aje-harness-menu" role="listbox" aria-label={label}>{options.map((option) => <button type="button" className={`aje-harness-option${option.value === value ? ' active' : ''}`} role="option" aria-selected={option.value === value} key={option.value} onClick={() => {onChange(option.value); setOpen(false)}}><span className="aje-harness-option-main"><i className={iconClass(option.icon)} aria-hidden="true" /><span><span className="aje-harness-option-name">{option.label}</span></span></span><i className="fas fa-check aje-harness-option-check" aria-hidden="true" /></button>)}</div></div>
}

function EndpointCard({endpoint, onEdit}: {endpoint: JsonRecord; onEdit: () => void}) {
  const status = String(endpoint.status || 'enabled')
  const protocol = String(endpoint.protocol || (String(endpoint.harness || '') === 'claude_code' ? 'anthropic' : 'openai'))
  const model = String(endpoint.model || '')
  const keyLabel = !endpoint.id && endpoint.global_endpoint_id ? '保存时安全复制 Key' : endpoint.api_key ? '新 Key 待保存' : endpoint.has_key ? 'Key 已配置' : 'Key 未配置'
  return <div className={`aje-card${status === 'disabled' ? ' off' : status === 'paused' ? ' paused' : ''}`}><div className="aje-card-top"><div className="aje-harness"><i className={harnessIconClass(endpoint.harness)} aria-hidden="true" /><span>{endpointHarnessLabel(endpoint.harness)}</span></div><span className="aje-state">{status === 'disabled' ? '停用' : status === 'paused' ? '暂停' : '启用'}</span></div><div className="aje-card-main"><div className="aje-model" title={model}><i className={modelIconClass(model)} aria-hidden="true" /> {model}</div><div className="aje-url" title={String(endpoint.base_url || '未填写 Base URL')}>{String(endpoint.base_url || '未填写 Base URL')}</div></div><div className="aje-card-meta"><span className="aje-chip"><i className="fas fa-link" />{protocol === 'anthropic' ? 'Anthropic' : 'OpenAI'}</span><span className="aje-chip"><i className="fas fa-gauge-high" />并发 {numberValue(endpoint.concurrency_limit, 1)}</span><span className="aje-chip"><i className="fas fa-key" />{keyLabel}</span>{endpoint.id ? null : <span className="aje-chip"><i className="fas fa-circle-plus" />未保存</span>}<button type="button" className="aje-edit-btn" title="编辑端点" aria-label="编辑端点" onClick={onEdit}><i className="fas fa-pen" /></button></div></div>
}

function AgentJudgeSettings({data, reverse}: {data: Response; reverse: boolean}) {
  const queryClient = useQueryClient()
  const [endpoints, setEndpoints] = useState<JsonRecord[]>(data.aj_endpoints || [])
  const [gateEndpoints, setGateEndpoints] = useState<JsonRecord[]>(data.quality_gate_endpoints || [])
  const [timeout, setTimeoutValue] = useState(numberValue(data.competition.agent_judge_timeout_seconds, 1800))
  const [finalizeTimeout, setFinalizeTimeout] = useState(numberValue(data.competition.reverse_judge_finalize_timeout_seconds, 180))
  const [orchestration, setOrchestration] = useState(String(data.competition.agent_judge_orchestration_mode || 'single'))
  const [gateEnabled, setGateEnabled] = useState(Boolean(data.competition.reverse_quality_gate_enabled))
  const [gatePrompt, setGatePrompt] = useState(String(data.competition.reverse_quality_gate_prompt || ''))
  const [editor, setEditor] = useState<{kind: 'main' | 'gate'; index: number; value: JsonRecord} | null>(null)
  const [editorError, setEditorError] = useState('')
  const harnessOptions: AjeChoiceOption[] = [
    {value: 'claude_code', label: 'Claude Code', icon: harnessIconClass('claude_code')},
    {value: 'codex', label: 'Codex', icon: harnessIconClass('codex')},
    {value: 'opencode', label: 'opencode', icon: harnessIconClass('opencode')},
    {value: 'pi', label: 'Pi', icon: harnessIconClass('pi')},
  ]
  const sourceOptions: AjeChoiceOption[] = [{value: 'custom', label: '自定义', icon: 'fa-pen'}, {value: 'global', label: '从全局端点复制', icon: 'fa-project-diagram'}]
  const protocolOptions: AjeChoiceOption[] = [{value: 'openai', label: 'OpenAI 兼容', icon: 'fa-code'}, {value: 'anthropic', label: 'Anthropic 兼容', icon: 'fa-code'}]
  const statusOptions: AjeChoiceOption[] = [{value: 'enabled', label: '启用', icon: 'fa-circle-play'}, {value: 'paused', label: '暂停', icon: 'fa-circle-pause'}, {value: 'disabled', label: '停用', icon: 'fa-circle-stop'}]
  const serverMainFingerprint = JSON.stringify({endpoints: data.aj_endpoints || [], timeout: numberValue(data.competition.agent_judge_timeout_seconds, 1800), finalizeTimeout: numberValue(data.competition.reverse_judge_finalize_timeout_seconds, 180), orchestration: String(data.competition.agent_judge_orchestration_mode || 'single')})
  const serverGateFingerprint = JSON.stringify({endpoints: data.quality_gate_endpoints || [], enabled: Boolean(data.competition.reverse_quality_gate_enabled), prompt: String(data.competition.reverse_quality_gate_prompt || '')})
  const mainBaselineRef = useRef(serverMainFingerprint)
  const gateBaselineRef = useRef(serverGateFingerprint)
  const mainFingerprint = JSON.stringify({endpoints, timeout, finalizeTimeout, orchestration})
  const gateFingerprint = JSON.stringify({endpoints: gateEndpoints, enabled: gateEnabled, prompt: gatePrompt})
  const mainDirty = mainFingerprint !== mainBaselineRef.current
  const gateDirty = gateFingerprint !== gateBaselineRef.current
  useUnsavedChangesWarning(mainDirty || gateDirty || Boolean(editor))
  useEffect(() => {
    if (!mainDirty && serverMainFingerprint !== mainBaselineRef.current) {mainBaselineRef.current = serverMainFingerprint; setEndpoints(data.aj_endpoints || []); setTimeoutValue(numberValue(data.competition.agent_judge_timeout_seconds, 1800)); setFinalizeTimeout(numberValue(data.competition.reverse_judge_finalize_timeout_seconds, 180)); setOrchestration(String(data.competition.agent_judge_orchestration_mode || 'single'))}
    if (!gateDirty && serverGateFingerprint !== gateBaselineRef.current) {gateBaselineRef.current = serverGateFingerprint; setGateEndpoints(data.quality_gate_endpoints || []); setGateEnabled(Boolean(data.competition.reverse_quality_gate_enabled)); setGatePrompt(String(data.competition.reverse_quality_gate_prompt || ''))}
  }, [data, gateDirty, mainDirty, serverGateFingerprint, serverMainFingerprint])
  const save = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope & {endpoints?: JsonRecord[]}>(`/api/ranking/competitions/${data.competition.id}/agent-judge/endpoints`, {method: 'POST', body: JSON.stringify({timeout_seconds: timeout, reverse_judge_finalize_timeout_seconds: finalizeTimeout, orchestration_mode: orchestration, endpoints})}),
    onSuccess: (payload) => {const savedEndpoints = payload.endpoints || endpoints; setEndpoints(savedEndpoints); mainBaselineRef.current = JSON.stringify({endpoints: savedEndpoints, timeout, finalizeTimeout, orchestration}); void queryClient.invalidateQueries({queryKey: ['ranking', String(data.competition.id)]})},
  })
  const saveGate = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope & {endpoints?: JsonRecord[]}>(`/api/ranking/competitions/${data.competition.id}/reverse-judge/quality-gate`, {method: 'POST', body: JSON.stringify({enabled: gateEnabled, prompt: gatePrompt, endpoints: gateEndpoints})}),
    onSuccess: (payload) => {const savedEndpoints = payload.endpoints || gateEndpoints; setGateEndpoints(savedEndpoints); gateBaselineRef.current = JSON.stringify({endpoints: savedEndpoints, enabled: gateEnabled, prompt: gatePrompt}); void queryClient.invalidateQueries({queryKey: ['ranking', String(data.competition.id)]})},
  })
  const openNew = (kind: 'main' | 'gate') => {setEditorError(''); setEditor({kind, index: -1, value: {harness: 'claude_code', source_mode: 'custom', protocol: 'anthropic', concurrency_limit: 1, status: 'enabled', context_window_tokens: 1000000, max_output_tokens: 384000, thinking_compatibility: true}})}
  const applyEditor = () => {
    if (!editor) return
    let next = {...editor.value}
    const contextWindow = Number(next.context_window_tokens)
    const maxOutput = Number(next.max_output_tokens)
    const concurrency = Number(next.concurrency_limit)
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 64) {setEditorError('并发上限必须是 1–64 的整数'); return}
    if (!Number.isInteger(contextWindow) || contextWindow < 1 || contextWindow > 1000000) {setEditorError('上下文窗口必须是 1–1000000 的整数'); return}
    if (!Number.isInteger(maxOutput) || maxOutput < 1 || maxOutput > 1000000) {setEditorError('最大输出必须是 1–1000000 的整数'); return}
    if (maxOutput > contextWindow) {setEditorError('最大输出不能超过上下文窗口'); return}
    if (String(next.source_mode || 'custom') === 'custom' && (!String(next.base_url || '').trim() || !String(next.model || '').trim())) {setEditorError('请填写 Base URL 和模型'); return}
    if (editor.index < 0 && String(next.source_mode || 'custom') === 'global' && !next.global_endpoint_id) {setEditorError('请选择要复制的全局端点'); return}
    if (editor.index < 0 && String(next.source_mode || 'custom') === 'global') {
      const candidates = data.agent_global_endpoint_candidates?.[String(next.harness || 'claude_code')] || []
      const candidate = candidates.find((item) => String(item.id) === String(next.global_endpoint_id || ''))
      if (candidate) next = {...next, base_url: candidate.base_url || '', model: candidate.model || '', protocol: candidate.protocol || 'openai', thinking_compatibility: Boolean(candidate.thinking_enabled)}
    }
    const update = editor.kind === 'main' ? setEndpoints : setGateEndpoints
    update((current) => editor.index < 0 ? [...current, next] : current.map((item, index) => index === editor.index ? next : item))
    setEditorError('')
    setEditor(null)
  }
  const deleteEditor = () => {
    if (!editor) return
    const update = editor.kind === 'main' ? setEndpoints : setGateEndpoints
    update((current) => current.filter((_, index) => index !== editor.index))
    setEditor(null)
  }
  const total = (items: JsonRecord[]) => items.reduce((sum, endpoint) => sum + (String(endpoint.status || 'enabled') === 'enabled' ? numberValue(endpoint.concurrency_limit, 1) : 0), 0)
  const timeoutControl = (label: string, icon: string, value: number, setter: (value: number) => void, step: number, min: number) => <label className="aje-setting aje-timeout"><span className="aje-setting-label"><i className={`fas ${icon} me-2`} />{label}</span><span className="aje-timeout-control"><button type="button" className="aje-timeout-step" aria-label={`减少${label}`} onClick={() => setter(Math.max(min, value - step))}><i className="fas fa-minus" /></button><input type="text" inputMode="numeric" value={value} aria-label={label} onChange={(event) => setter(numberValue(event.target.value, value))} /><span className="aje-timeout-unit">秒</span><button type="button" className="aje-timeout-step" aria-label={`增加${label}`} onClick={() => setter(Math.min(7200, value + step))}><i className="fas fa-plus" /></button></span></label>
  const editorHarness = String(editor?.value.harness || 'claude_code')
  const editorSource = String(editor?.value.source_mode || 'custom')
  const editorProtocol = String(editor?.value.protocol || (editorHarness === 'claude_code' ? 'anthropic' : 'openai'))
  const editorCandidates = data.agent_global_endpoint_candidates?.[editorHarness] || []
  const updateEditorValue = (patch: JsonRecord) => {setEditorError(''); setEditor((current) => current ? {...current, value: {...current.value, ...patch}} : current)}
  const changeEditorHarness = (harness: string) => updateEditorValue({harness, protocol: harness === 'claude_code' ? 'anthropic' : harness === 'codex' || harness === 'opencode' ? 'openai' : editorProtocol, global_endpoint_id: ''})
  const changeGlobalCandidate = (candidateId: string) => {
    const candidate = editorCandidates.find((item) => String(item.id) === candidateId)
    updateEditorValue(candidate ? {global_endpoint_id: candidateId, base_url: candidate.base_url || '', model: candidate.model || '', protocol: candidate.protocol || 'openai', thinking_compatibility: Boolean(candidate.thinking_enabled)} : {global_endpoint_id: ''})
  }
  return <>
    <div className="card mb-3"><div className="card-header"><i className="fas fa-robot me-2" /> {reverse ? 'AI 作答端点' : 'AI 评测模型端点'}</div><div className="card-body aje"><div className="aje-shell"><div className="aje-head"><div><div className="aje-title">{reverse ? 'AI 作答端点池' : '端点池'}</div></div><div className="aje-head-tools"><div className="aje-meta"><span className="aje-count">{endpoints.length} 个端点</span><span className="aje-total">并发 <b>{total(endpoints)}</b></span></div><button type="button" className="aje-add" title="添加端点" aria-label="添加端点" onClick={() => openNew('main')}><i className="fas fa-plus" /></button></div></div><div className="aje-grid">{endpoints.length ? endpoints.map((endpoint, index) => <EndpointCard endpoint={endpoint} onEdit={() => {setEditorError(''); setEditor({kind: 'main', index, value: {...endpoint}})}} key={String(endpoint.id || index)} />) : <div className="aje-empty">暂无端点</div>}</div><div className="aje-foot"><div className={`aje-settings${reverse ? ' reverse-timeout-settings' : ''}`}>{timeoutControl(reverse ? 'AI 作答超时' : '单次评测超时', 'fa-clock', timeout, setTimeoutValue, 60, 60)}{reverse ? timeoutControl('收尾超时', 'fa-hourglass-end', finalizeTimeout, setFinalizeTimeout, 30, 30) : <div className="aje-setting aje-mode"><span className="aje-setting-label"><i className="fas fa-diagram-project me-2" />编排</span><AjeChoice value={orchestration} onChange={setOrchestration} label="评测编排" options={[{value: 'single', label: '一次性评测', icon: 'fa-layer-group'}, {value: 'topological', label: '拓扑序编排', icon: 'fa-diagram-project'}]} /></div>}</div><div className="aje-actions"><span className="small">{save.isError ? errorMessage(save.error) : save.isSuccess ? '已保存' : ''}</span><button type="button" className="aje-save" disabled={save.isPending} onClick={() => save.mutate()}><i className="fas fa-save me-2" />保存</button></div></div></div></div></div>
    {reverse ? <div className="card mb-3"><div className="card-header"><i className="fas fa-shield-halved me-2" /> 质量门禁</div><div className="card-body aje"><div className="qge-config"><div className="qge-config-head"><span className="qge-config-title">审核标准</span><div className="form-check form-switch qge-switch"><input className="form-check-input" type="checkbox" id="qgeEnabled" checked={gateEnabled} onChange={(event) => setGateEnabled(event.target.checked)} /><label className="form-check-label" htmlFor="qgeEnabled">启用</label></div></div><textarea className="qge-prompt" maxLength={20000} aria-label="质量门禁审核标准" value={gatePrompt} onChange={(event) => setGatePrompt(event.target.value)} /></div><div className="aje-shell qge-shell"><div className="aje-head"><div className="aje-title">审核端点池</div><div className="aje-head-tools"><div className="aje-meta"><span className="aje-count">{gateEndpoints.length} 个端点</span><span className="aje-total">并发 <b>{total(gateEndpoints)}</b></span></div><button type="button" className="aje-add" title="添加端点" aria-label="添加质量门禁端点" onClick={() => openNew('gate')}><i className="fas fa-plus" /></button></div></div><div className="aje-grid">{gateEndpoints.length ? gateEndpoints.map((endpoint, index) => <EndpointCard endpoint={endpoint} onEdit={() => {setEditorError(''); setEditor({kind: 'gate', index, value: {...endpoint}})}} key={String(endpoint.id || index)} />) : <div className="aje-empty">暂无端点</div>}</div><div className="aje-foot"><div /><div className="aje-actions"><span className="small">{saveGate.isError ? errorMessage(saveGate.error) : saveGate.isSuccess ? '已保存' : ''}</span><button type="button" className="aje-save" disabled={saveGate.isPending} onClick={() => saveGate.mutate()}><i className="fas fa-save me-2" />保存</button></div></div></div></div></div> : null}
    {editor ? <ReactModal open onClose={() => {setEditorError(''); setEditor(null)}} id="ajeEditModal" labelledBy="ajeEditModalLabel" className="aje-modal" dialogClassName="modal-lg modal-dialog-scrollable"><div className="modal-content">
          <div className="modal-header"><h5 className="modal-title" id="ajeEditModalLabel">{editor.index < 0 ? '添加' : '编辑'}{editor.kind === 'gate' ? '质量门禁端点' : '端点'}</h5><button type="button" className="btn-close" aria-label="关闭" onClick={() => {setEditorError(''); setEditor(null)}} /></div>
          <div className="modal-body"><div className={`aje-modal-grid${editor.index < 0 ? ' is-add' : ''}`}>
            <div className="aje-modal-field aje-col-pick"><span>Agent Harness</span><AjeChoice value={editorHarness} onChange={changeEditorHarness} label="Agent Harness" options={harnessOptions} /></div>
            {editor.index < 0 ? <div className="aje-modal-field aje-col-pick"><span>创建方式</span><RankingChoice name="source_mode" value={editorSource} onChange={(source_mode) => updateEditorValue({source_mode, global_endpoint_id: ''})} label="创建方式" options={sourceOptions} /></div> : null}
            <div className="aje-modal-field aje-col-pick"><span>协议</span><RankingChoice name="protocol" value={editorProtocol} onChange={(protocol) => updateEditorValue({protocol})} label="协议" options={protocolOptions} disabled={editorSource === 'global' || editorHarness !== 'pi'} /></div>
            {editor.index < 0 && editorSource === 'global' ? <div className="aje-modal-field full"><span>全局端点</span><RankingChoice name="global_endpoint_id" value={String(editor.value.global_endpoint_id || '')} onChange={changeGlobalCandidate} label="全局端点" options={[{value: '', label: '请选择全局端点', icon: 'fa-project-diagram'}, ...editorCandidates.map((candidate) => ({value: String(candidate.id), label: String(candidate.model || `节点 #${candidate.id}`), icon: modelIconClass(candidate.model)}))]} /><small className="text-muted">保存时由后端复制 URL、API Key、model 与思考设置；之后与全局端点完全独立。</small></div> : null}
            <label className="aje-modal-field aje-col-half"><span>并发上限</span><input type="number" min={1} max={64} step={1} aria-label="并发上限" value={numberValue(editor.value.concurrency_limit, 1)} onChange={(event) => updateEditorValue({concurrency_limit: numberValue(event.target.value, 1)})} /></label>
            <div className="aje-modal-field aje-col-half choice-top"><span>状态</span><AjeChoice value={String(editor.value.status || 'enabled')} onChange={(status) => updateEditorValue({status})} label="状态" options={statusOptions} /></div>
            {editorSource === 'custom' || editor.index >= 0 ? <>
              <label className="aje-modal-field full"><span>Base URL（{editorProtocol === 'anthropic' ? 'Anthropic' : 'OpenAI'} 兼容）</span><input className="mono" type="text" aria-label={`Base URL（${editorProtocol === 'anthropic' ? 'Anthropic' : 'OpenAI'} 兼容）`} placeholder={editorProtocol === 'anthropic' ? 'https://.../anthropic' : 'https://.../v1'} value={String(editor.value.base_url || '')} onChange={(event) => updateEditorValue({base_url: event.target.value})} /></label>
              <label className="aje-modal-field full"><span>API Key</span><input className="mono" type="password" autoComplete="new-password" aria-label="API Key" placeholder={editor.value.has_key ? '已配置' : '请输入 API Key'} value={String(editor.value.api_key || '')} onChange={(event) => updateEditorValue({api_key: event.target.value})} /></label>
              <label className="aje-modal-field full"><span>模型</span><input type="text" required aria-label="模型" value={String(editor.value.model || '')} onChange={(event) => updateEditorValue({model: event.target.value})} /></label>
            </> : null}
            <label className="aje-modal-field aje-col-4"><span>上下文窗口</span><input type="number" min={1} max={1000000} step={1} required inputMode="numeric" aria-label="上下文窗口" value={numberValue(editor.value.context_window_tokens, 1000000)} onChange={(event) => updateEditorValue({context_window_tokens: numberValue(event.target.value, 1000000)})} /></label>
            <label className="aje-modal-field aje-col-4"><span>最大输出</span><input type="number" min={1} max={1000000} step={1} required inputMode="numeric" aria-label="最大输出" value={numberValue(editor.value.max_output_tokens, 384000)} onChange={(event) => updateEditorValue({max_output_tokens: numberValue(event.target.value, 384000)})} /></label>
            <div className="aje-modal-field aje-col-4"><span id="ajeEditThinkingLabel">Thinking 兼容</span><div className="aje-thinking-compatibility"><div className="form-check form-switch"><input className="form-check-input" type="checkbox" aria-labelledby="ajeEditThinkingLabel" checked={editor.value.thinking_compatibility !== false} onChange={(event) => updateEditorValue({thinking_compatibility: event.target.checked})} /></div></div></div>
          </div>{editorError ? <div className="alert alert-danger mt-3 mb-0" role="alert">{editorError}</div> : null}</div>
          <div className="modal-footer d-flex justify-content-between">{editor.index >= 0 ? <button type="button" className="aje-modal-delete" onClick={deleteEditor}><i className="fas fa-trash-can" /> 删除端点</button> : null}<div className="aje-modal-footer-actions"><button type="button" className="aje-modal-cancel" onClick={() => {setEditorError(''); setEditor(null)}}>取消</button><button type="button" className="aje-modal-apply" onClick={applyEditor}><i className="fas fa-check" /> 应用修改</button></div></div>
        </div>
    </ReactModal> : null}
  </>
}

function AgentRulesTopology({rules, setRules}: {rules: JsonRecord[]; setRules: Dispatch<SetStateAction<JsonRecord[]>>}) {
  const [deleteMode, setDeleteMode] = useState(false)
  const [deleteSelection, setDeleteSelection] = useState<number[]>([])
  const [linkMode, setLinkMode] = useState(false)
  const [linkSource, setLinkSource] = useState<number | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<{from: number; to: number} | null>(null)
  const [modalIndex, setModalIndex] = useState<number | null>(null)
  const [modalDraft, setModalDraft] = useState<JsonRecord | null>(null)
  const {engine, layout, edges, routes} = useRuleTopology(rules, {nodeWidth: 168, nodeHeight: 100, marginX: 24, marginY: 20, columnGap: 88, rowGap: 80, slotPadding: 42, maxSlotStep: 17})
  const compact = (value: unknown, length: number) => {
    const text = String(value || '').replace(/\s+/g, ' ').trim()
    if (!text) return '未填写规则内容'
    return text.length > length ? `${text.slice(0, length)}…` : text
  }
  const updateModalRule = (field: string, value: unknown) => {
    setModalDraft((current) => current ? {...current, [field]: value} : current)
  }
  const closeRuleModal = () => {setModalIndex(null); setModalDraft(null)}
  const saveRuleModal = () => {
    if (modalIndex == null || !modalDraft) return
    setRules((current) => modalIndex >= current.length ? [...current, modalDraft] : current.map((rule, index) => index === modalIndex ? modalDraft : rule))
    closeRuleModal()
  }
  const canAddEdge = (from: number, to: number) => {
    if (!from || !to || from === to || edges.some((edge) => edge.from === from && edge.to === to)) return false
    const adjacency = new Map<number, number[]>()
    for (const edge of edges) adjacency.set(edge.from, [...(adjacency.get(edge.from) || []), edge.to])
    const seen = new Set<number>()
    const hasPath = (start: number): boolean => start === from || (!seen.has(start) && (seen.add(start), (adjacency.get(start) || []).some(hasPath)))
    return !hasPath(to)
  }
  const clickNode = (index: number) => {
    const id = numberValue(rules[index]?.rule_id, index + 1)
    setSelectedEdge(null)
    if (deleteMode) {
      setDeleteSelection((current) => current.includes(index) ? current.filter((value) => value !== index) : [...current, index])
      return
    }
    if (!linkMode) {
      setModalIndex(index); setModalDraft({...rules[index]})
      return
    }
    if (linkSource == null) {
      setLinkSource(id)
      return
    }
    if (linkSource === id) {
      setLinkSource(null)
      return
    }
    if (!canAddEdge(linkSource, id)) return
    setRules((current) => current.map((rule, ruleIndex) => ruleIndex === index ? {...rule, dependencies: [...(Array.isArray(rule.dependencies) ? rule.dependencies : []), linkSource].sort((left, right) => numberValue(left) - numberValue(right))} : rule))
    setLinkMode(false)
    setLinkSource(null)
  }
  const deleteSelectedNodes = () => {
    if (!deleteSelection.length) return
    setRules((current) => {
      const removed = new Set(deleteSelection.map((index) => numberValue(current[index]?.rule_id, index + 1)))
      const kept = current.filter((_, index) => !deleteSelection.includes(index))
      const oldToNew = new Map<number, number>()
      kept.forEach((rule, index) => oldToNew.set(numberValue(rule.rule_id, index + 1), index + 1))
      return kept.map((rule, index) => ({...rule, rule_id: index + 1, dependencies: (Array.isArray(rule.dependencies) ? rule.dependencies : []).map(numberValue).filter((dependency) => !removed.has(dependency) && oldToNew.has(dependency)).map((dependency) => oldToNew.get(dependency))}))
    })
    setDeleteSelection([])
    setDeleteMode(false)
  }
  const simplify = () => setRules((current) => {
    const currentEdges = current.flatMap((rule, index) => (Array.isArray(rule.dependencies) ? rule.dependencies : []).map((dependency) => ({from: numberValue(dependency), to: numberValue(rule.rule_id, index + 1)})))
    const redundant = new Set<string>()
    for (const candidate of currentEdges) {
      const adjacency = new Map<number, number[]>()
      for (const edge of currentEdges) if (edge !== candidate) adjacency.set(edge.from, [...(adjacency.get(edge.from) || []), edge.to])
      const seen = new Set<number>()
      const hasPath = (node: number): boolean => node === candidate.to || (!seen.has(node) && (seen.add(node), (adjacency.get(node) || []).some(hasPath)))
      if (hasPath(candidate.from)) redundant.add(`${candidate.from}:${candidate.to}`)
    }
    return current.map((rule, index) => ({...rule, dependencies: (Array.isArray(rule.dependencies) ? rule.dependencies : []).filter((dependency) => !redundant.has(`${numberValue(dependency)}:${numberValue(rule.rule_id, index + 1)}`))}))
  })
  const modalRule = modalDraft
  return <>
    <div className="aj-topo-layout"><div className="aj-topo-main"><div className="aj-topo-canvas">{!rules.length ? <div className="aj-topo-empty"><div><i className="fas fa-diagram-project mb-2 d-block" style={{fontSize: '1.5rem', opacity: .5}} />还没有评分规则。</div></div> : !layout || !engine ? <div className="aj-topo-empty text-danger">当前依赖存在环，无法生成 DAG。请切回文本视图调整。</div> : <div className="aj-topo-stage" style={{width: Math.ceil(layout.width), height: Math.ceil(layout.height)}}><div className={`aj-topo-surface${linkMode ? ` link-mode${linkSource ? ' link-has-source' : ''}` : ''}${deleteMode ? ' delete-mode' : ''}`} style={{width: layout.width, height: layout.height}}><svg className="aj-topo-svg" width={layout.width} height={layout.height} viewBox={`0 0 ${layout.width} ${layout.height}`}>{edges.map((edge) => {
      const key = engine.edgeKey(edge.from, edge.to)
      const route = routes[key]
      if (!route) return null
      const selected = selectedEdge?.from === edge.from && selectedEdge.to === edge.to
      return <g key={key}><path className={`aj-topo-edge${selected ? ' selected' : ''}`} d={engine.edgePath(route)} data-edge-key={key} data-edge-from={edge.from} data-edge-to={edge.to} /><polygon className={`aj-topo-arrow${selected ? ' selected' : ''}`} points={`${route.x2} ${route.arrowTipY} ${route.x2 - 5} ${route.y2} ${route.x2 + 5} ${route.y2}`} /><path className="aj-topo-edge-hit" d={engine.edgePath(route)} onClick={() => setSelectedEdge(edge)} /></g>
    })}</svg>{selectedEdge ? (() => {const route = routes[engine.edgeKey(selectedEdge.from, selectedEdge.to)]; return route ? <button type="button" className="aj-edge-trash" title="删除这条拓扑" style={{left: (route.x1 + route.x2) / 2, top: route.laneY}} onClick={() => {setRules((current) => current.map((rule, index) => numberValue(rule.rule_id, index + 1) === selectedEdge.to ? {...rule, dependencies: (Array.isArray(rule.dependencies) ? rule.dependencies : []).filter((dependency) => numberValue(dependency) !== selectedEdge.from)} : rule)); setSelectedEdge(null)}}><i className="fas fa-trash-can" /></button> : null})() : null}{rules.map((rule, index) => {
      const id = numberValue(rule.rule_id, index + 1)
      const position = layout.positions[id]
      const blocked = linkMode && linkSource != null && linkSource !== id && !canAddEdge(linkSource, id)
      return <button type="button" className={`aj-topo-node${deleteMode && deleteSelection.includes(index) ? ' delete-selected' : ''}${linkMode && linkSource === id ? ' link-source' : linkMode && linkSource != null && !blocked ? ' link-target' : blocked ? ' link-blocked' : linkMode ? ' link-ready' : ''}`} title={String(rule.rule_text || '未填写规则内容')} style={{left: position.x, top: position.y}} onClick={() => clickNode(index)} key={id}><span className="aj-topo-node-id">规则 {id} · {numberValue(rule.value)} 分</span><span className="aj-topo-node-title">{String(rule.rule_name || '').trim() || compact(rule.rule_text, 14)}</span><span className="aj-topo-node-text">{compact(rule.rule_text, 42)}</span></button>
    })}</div></div>}</div></div><aside className="aj-topo-panel" aria-label="拓扑工具"><div className="aj-topo-actions"><button type="button" className="aj-topo-icon-btn" aria-label="增加节点" title="增加节点" disabled={deleteMode} onClick={() => {setModalIndex(rules.length); setModalDraft({rule_id: rules.length + 1, rule_name: '', rule_text: '', value: 0, dependencies: []})}}><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5" /><path d="M12 9v6M9 12h6M12 2v3M12 19v3M2 12h3M19 12h3" /></svg></button><div className="aj-topo-delete-wrap"><button type="button" className={`aj-topo-icon-btn${deleteMode ? ' delete-active' : ''}`} aria-label="删除节点" title="删除节点" disabled={!rules.length} onClick={() => {setDeleteMode((current) => !current); setDeleteSelection([]); setLinkMode(false); setLinkSource(null)}}><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5" /></svg></button><button type="button" className={`aj-topo-confirm-btn${deleteMode ? ' show' : ''}`} aria-label="确认删除" title="确认删除" disabled={!deleteSelection.length} onClick={deleteSelectedNodes}><i className="fas fa-check" /></button></div><button type="button" className={`aj-topo-icon-btn${linkMode ? ' active' : ''}`} aria-label="添加连接" title="添加连接" disabled={rules.length < 2 || deleteMode} onClick={() => {setLinkMode((current) => !current); setLinkSource(null); setSelectedEdge(null)}}><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="5" cy="12" r="2.5" /><path d="M8 12h8.5M14 8.5 17.5 12 14 15.5" /><circle cx="20" cy="12" r="2.5" /></svg></button><button type="button" className="aj-topo-icon-btn" aria-label="简化拓扑关系" title="简化拓扑关系" disabled={!rules.length || deleteMode} onClick={simplify}><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="5" cy="17" r="2" /><circle cx="12" cy="7" r="2" /><circle cx="19" cy="17" r="2" /><path d="M6.5 15.2 10.5 8.8M13.5 8.8 17.5 15.2M7.5 17h9" /></svg></button></div></aside></div>
    {modalRule && modalIndex != null ? <ReactModal open onClose={closeRuleModal} id="ajRuleModal" labelledBy="ajRuleModalLabel" className="aj-rule-modal" dialogClassName="modal-lg modal-dialog-scrollable"><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="ajRuleModalLabel">编辑规则 {numberValue(modalRule.rule_id, modalIndex + 1)}</h5><button type="button" className="btn-close" aria-label="关闭" onClick={closeRuleModal} /></div><div className="modal-body"><div className="mb-3"><label className="form-label" htmlFor="ajRuleModalName">规则名称</label><input type="text" className="form-control" id="ajRuleModalName" maxLength={120} placeholder="规则名称" value={String(modalRule.rule_name || '')} onChange={(event) => updateModalRule('rule_name', event.target.value)} /></div><div className="mb-3"><label className="form-label" htmlFor="ajRuleModalText">规则原文</label><textarea className="form-control" id="ajRuleModalText" placeholder="用自然语言描述这条评分规则……" value={String(modalRule.rule_text || '')} onChange={(event) => updateModalRule('rule_text', event.target.value)} /></div><div><label className="form-label" htmlFor="ajRuleModalValue">分值</label><input type="number" min={0} step={0.5} className="form-control" id="ajRuleModalValue" value={numberValue(modalRule.value)} onChange={(event) => updateModalRule('value', numberValue(event.target.value))} /></div></div><div className="modal-footer"><button type="button" className="btn btn-outline-secondary" onClick={closeRuleModal}>取消</button><button type="button" className="btn btn-success" onClick={saveRuleModal}>保存修改</button></div></div></ReactModal> : null}
  </>
}

function AgentRulesSettings({data}: {data: Response}) {
  const queryClient = useQueryClient()
  const [rules, setRules] = useState<JsonRecord[]>(data.judge_rules || [])
  const [view, setView] = useState<'text' | 'topo'>('text')
  const serverFingerprint = JSON.stringify(data.judge_rules || [])
  const baselineRef = useRef(serverFingerprint)
  const dirty = JSON.stringify(rules) !== baselineRef.current
  useUnsavedChangesWarning(dirty)
  useEffect(() => {if (!dirty && serverFingerprint !== baselineRef.current) {baselineRef.current = serverFingerprint; setRules(data.judge_rules || [])}}, [data.judge_rules, dirty, serverFingerprint])
  const save = useMutation({mutationFn: () => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${data.competition.id}/agent-judge/rules`, {method: 'POST', body: JSON.stringify({rules})}), onSuccess: () => {baselineRef.current = JSON.stringify(rules); void queryClient.invalidateQueries({queryKey: ['ranking', String(data.competition.id)]})}})
  const update = (index: number, field: string, value: unknown) => setRules((current) => current.map((rule, ruleIndex) => ruleIndex === index ? {...rule, [field]: value} : rule))
  const toggleDependency = (index: number, dependencyId: number) => setRules((current) => current.map((rule, ruleIndex) => {
    if (ruleIndex !== index) return rule
    const dependencies = (Array.isArray(rule.dependencies) ? rule.dependencies : []).map((value) => numberValue(value))
    return {...rule, dependencies: dependencies.includes(dependencyId) ? dependencies.filter((value) => value !== dependencyId) : [...dependencies, dependencyId].sort((left, right) => left - right)}
  }))
  const deleteRule = (index: number) => setRules((current) => {
    const removedId = numberValue(current[index]?.rule_id, index + 1)
    const kept = current.filter((_, ruleIndex) => ruleIndex !== index)
    const oldToNew = new Map<number, number>()
    kept.forEach((rule, ruleIndex) => oldToNew.set(numberValue(rule.rule_id, ruleIndex + 1), ruleIndex + 1))
    return kept.map((rule, ruleIndex) => ({...rule, rule_id: ruleIndex + 1, dependencies: (Array.isArray(rule.dependencies) ? rule.dependencies : []).map((value) => numberValue(value)).filter((value) => value !== removedId && oldToNew.has(value)).map((value) => oldToNew.get(value))}))
  })
  const total = rules.reduce((sum, rule) => sum + numberValue(rule.value), 0)
  return <div className="card mb-3"><div className="card-header"><i className="fas fa-list-check me-2" /> 评分规则</div><div className="card-body aj-rules"><div className="aj-rules-head"><div className="aj-rules-head-left"><span className="aj-count">共 {rules.length} 条规则</span><div className="aj-view-tabs" role="tablist" aria-label="评分规则视图"><button type="button" className={`aj-view-tab${view === 'text' ? ' active' : ''}`} role="tab" aria-selected={view === 'text'} onClick={() => setView('text')}>文本</button><button type="button" className={`aj-view-tab${view === 'topo' ? ' active' : ''}`} role="tab" aria-selected={view === 'topo'} onClick={() => setView('topo')}>拓扑</button></div></div><span className="aj-total">满分 <b>{total}</b> 分</span></div>{view === 'text' ? <div className="aj-view">{rules.length ? rules.map((rule, index) => <div className="aj-rule" key={index}><div className="aj-rule-top"><div className="aj-no">{index + 1}</div><div className="aj-main-fields"><input className="aj-name" maxLength={120} placeholder="规则名称" value={String(rule.rule_name || '')} onChange={(event) => update(index, 'rule_name', event.target.value)} /><textarea className="aj-desc" rows={2} placeholder="用自然语言描述这条评分规则……" value={String(rule.rule_text || '')} ref={(element) => {if (element) {element.style.height = 'auto'; element.style.height = `${element.scrollHeight}px`}}} onInput={(event) => {event.currentTarget.style.height = 'auto'; event.currentTarget.style.height = `${event.currentTarget.scrollHeight}px`}} onChange={(event) => update(index, 'rule_text', event.target.value)} /></div><div className="aj-val"><label>分值</label><div className="aj-stepper"><button type="button" className="aj-step" onClick={() => update(index, 'value', Math.max(0, numberValue(rule.value) - 0.5))}>−</button><input type="number" min={0} step={0.5} value={numberValue(rule.value)} onChange={(event) => update(index, 'value', numberValue(event.target.value))} /><button type="button" className="aj-step" onClick={() => update(index, 'value', numberValue(rule.value) + 0.5)}>+</button></div></div><button type="button" className="aj-del" title="删除规则" onClick={() => deleteRule(index)}><i className="fas fa-trash-can" /></button></div>{rules.length > 1 ? <div className="aj-deps"><span className="aj-deps-label">前置依赖</span>{rules.map((candidate, candidateIndex) => candidateIndex === index ? null : <span className={`aj-pill${(Array.isArray(rule.dependencies) ? rule.dependencies : []).map((value) => numberValue(value)).includes(numberValue(candidate.rule_id, candidateIndex + 1)) ? ' on' : ''}`} role="button" tabIndex={0} key={candidateIndex} onClick={() => toggleDependency(index, numberValue(candidate.rule_id, candidateIndex + 1))}>规则 {numberValue(candidate.rule_id, candidateIndex + 1)}</span>)}</div> : null}</div>) : <div className="aj-empty"><i className="fas fa-list-check mb-2 d-block" style={{fontSize: '1.4rem', opacity: .5}} />还没有评分规则</div>}</div> : <div className="aj-view"><AgentRulesTopology rules={rules} setRules={setRules} /></div>}<button type="button" className="aj-add" onClick={() => setRules((current) => [...current, {rule_id: current.length + 1, rule_name: '', rule_text: '', value: 0, dependencies: []}])}><i className="fas fa-plus" /> 添加规则</button><div className="aj-foot"><button type="button" className="aj-save" disabled={save.isPending} onClick={() => save.mutate()}><i className="fas fa-save me-1" /> 保存规则</button><span className="small">{save.isError ? errorMessage(save.error) : save.isSuccess ? '已保存' : ''}</span></div></div></div>
}

function EditPanel({data}: {data: Response}) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const formRef = useRef<HTMLFormElement>(null)
  const competition = data.competition
  const [mode, setMode] = useState(String(competition.scoring_mode || 'absolute'))
  const [answerFormat, setAnswerFormat] = useState(String(competition.answer_format || 'json'))
  const [submissionMethod, setSubmissionMethod] = useState(String(competition.submission_method || 'zip'))
  const [runtimeMode, setRuntimeMode] = useState(String(competition.elo_runtime_mode || 'legacy'))
  const [referenceFile, setReferenceFile] = useState<File | null>(null)
  const [scriptFile, setScriptFile] = useState<File | null>(null)
  const [attachmentFile, setAttachmentFile] = useState<File | null>(null)
  const [attachmentPreview, setAttachmentPreview] = useState<RankingMediaTarget | null>(null)
  const [formDirty, setFormDirty] = useState(false)
  const baseDirty = formDirty || mode !== String(competition.scoring_mode || 'absolute') || answerFormat !== String(competition.answer_format || 'json') || submissionMethod !== String(competition.submission_method || 'zip') || runtimeMode !== String(competition.elo_runtime_mode || 'legacy')
  useUnsavedChangesWarning(baseDirty || Boolean(referenceFile || scriptFile || attachmentFile))
  const save = useMutation({
    mutationFn: (body: FormData) => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${competition.id}`, {method: 'POST', body}),
    onSuccess: () => {setFormDirty(false); void queryClient.invalidateQueries({queryKey: ['ranking', String(competition.id)]})},
  })
  const upload = useMutation({
    mutationFn: ({path, field, file}: {path: string; field: string; file: File}) => {const body = new FormData(); body.append(field, file); return apiFetch<ApiEnvelope>(`/api/ranking/competitions/${competition.id}/${path}`, {method: 'POST', body})},
    onSuccess: (_payload, request) => {if (request.field === 'reference') setReferenceFile(null); else if (request.field === 'scoring_script') setScriptFile(null); else if (request.field === 'attachment') setAttachmentFile(null); void queryClient.invalidateQueries({queryKey: ['ranking', String(competition.id)]})},
  })
  const command = useMutation({
    mutationFn: ({path, method = 'POST'}: {path: string; method?: 'POST' | 'DELETE'}) => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${competition.id}/${path}`, {method}),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['ranking', String(competition.id)]}),
  })
  const removeCompetition = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${competition.id}`, {method: 'DELETE'}),
    onSuccess: () => navigate('/rankings'),
  })
  const files = data.files || []
  const active = numberValue(competition.is_active) === 1
  const eloRunning = numberValue(competition.elo_running) === 1
  const scriptName = String(competition.scoring_script_name || '')
  const referenceName = String(competition.reference_answer_name || '')
  const uploadCard = (title: ReactNode, current: ReactNode, path: string, field: string, file: File | null, setFile: (file: File | null) => void, accept?: string) => <div className={`card mb-3${!current ? ' border-warning' : ''}`}><div className="card-header">{title}</div><div className="card-body"><div className="mb-3"><strong>当前{field === 'reference' ? '文件' : '脚本'}：</strong>{current}</div><div className="mb-3"><input type="file" className="form-control" accept={accept} onChange={(event) => setFile(event.target.files?.[0] || null)} /></div><button type="button" className="btn btn-outline-primary" disabled={upload.isPending} onClick={(event) => {if (file) upload.mutate({path, field, file}); else event.currentTarget.parentElement?.querySelector<HTMLInputElement>('input[type=file]')?.click()}}><i className="fas fa-cloud-upload-alt me-2" />上传并替换</button>{field === 'scoring_script' && scriptName ? <button type="button" className="btn btn-outline-danger btn-sm ms-2" onClick={() => {if (window.confirm('确认清除评测脚本？')) command.mutate({path: 'scoring-script', method: 'DELETE'})}}><i className="fas fa-trash me-2" />清除评测脚本</button> : null}</div></div>
  return <section className="ranking-v2-settings" data-ranking-tab-panel="edit"><div className="card mb-3"><div className="card-header"><i className="fas fa-pencil-alt me-2" /> 基本信息</div><div className="card-body"><form ref={formRef} id="rankingEditForm" onChange={() => setFormDirty(true)} onSubmit={(event) => {event.preventDefault(); if (event.currentTarget.reportValidity()) save.mutate(new FormData(event.currentTarget))}}>
    <div className="mb-3"><label className="form-label"><i className="fas fa-heading me-2 text-muted" />标题</label><input className="form-control" name="title" defaultValue={String(competition.title || '')} required maxLength={255} /></div>
    <div className="mb-3"><label className="form-label"><i className="fas fa-align-left me-2 text-muted" />摘要</label><textarea className="form-control" name="summary" rows={2} maxLength={500} placeholder="一句话介绍本场打榜赛（展示在列表卡片上，最多 500 字）" defaultValue={String(competition.summary || '')} /></div>
    <div className="row mb-3 align-items-start"><div className="col-md-4"><label className="form-label"><i className="fas fa-star-half-alt me-2 text-muted" />评分模式</label><RankingChoice name="scoring_mode" value={mode} onChange={(value) => {setMode(value); setFormDirty(true)}} label="评分模式" options={[{value: 'absolute', label: '标准答案评分', icon: 'fa-award'}, {value: 'elo', label: 'ELO 对战', icon: 'fa-chess'}, {value: 'agent_judge', label: 'Agent 评测', icon: 'fa-robot'}, {value: 'reverse_judge', label: '反向评测', icon: 'fa-undo-alt'}]} /></div>{mode === 'absolute' ? <><div className="col-md-4"><label className="form-label"><i className="fas fa-trophy me-2 text-muted" />满分</label><input type="number" className="form-control" name="max_score" min={1} max={100000} defaultValue={numberValue(competition.max_score, 100)} /></div><div className="col-md-4"><label className="form-label"><i className="fas fa-file-code me-2 text-muted" />答案格式</label><RankingChoice name="answer_format" value={answerFormat} onChange={(value) => {setAnswerFormat(value); setFormDirty(true)}} label="答案格式" options={[{value: 'json', label: 'JSON（.json）', icon: 'fa-file-code'}, {value: 'zip', label: 'ZIP 压缩包（.zip）', icon: 'fa-file-archive'}]} /></div></> : null}{mode === 'agent_judge' ? <div className="col-md-4"><label className="form-label"><i className="fas fa-upload me-2 text-muted" />提交方式</label><RankingChoice name="submission_method" value={submissionMethod} onChange={(value) => {setSubmissionMethod(value); setFormDirty(true)}} label="提交方式" options={[{value: 'zip', label: '上传 ZIP 压缩包', icon: 'fa-file-archive'}, {value: 'git', label: 'Git 仓库拉取', icon: 'fa-code-branch'}]} /></div> : null}{mode === 'agent_judge' || mode === 'reverse_judge' ? <div className="col-md-4"><label className="form-label"><i className="fas fa-hourglass-half me-2 text-muted" />每 48 小时提交次数</label><LimitControl competition={competition} onReset={() => command.mutate({path: 'submission-limit/reset'})} /></div> : null}</div>
    {mode !== 'agent_judge' ? <div className="row mb-3"><div className="col-md-4"><label className="form-label"><i className="fas fa-stopwatch me-2 text-muted" />评测脚本超时（秒）</label><input className="form-control" name="scoring_script_timeout_seconds" type="number" min={5} max={1800} defaultValue={numberValue(competition.scoring_script_timeout_seconds, 120)} /></div>{mode === 'elo' ? <div className="col-md-4"><label className="form-label"><i className="fas fa-layer-group me-2 text-muted" />评测脚本执行模式</label><RankingChoice name="elo_runtime_mode" value={runtimeMode} onChange={(value) => {setRuntimeMode(value); setFormDirty(true)}} label="评测脚本执行模式" options={[{value: 'legacy', label: '单容器运行时', icon: 'fa-cube'}, {value: 'isolated', label: '隔离运行时', icon: 'fa-shield-alt'}]} /></div> : null}</div> : null}
    {(mode === 'agent_judge' || mode === 'reverse_judge') && (mode === 'reverse_judge' || submissionMethod === 'git') ? <div className="row mb-3"><div className="col-md-12"><label className="form-label"><i className="fas fa-code-branch me-2 text-muted" />Git 仓库标准命名</label><input className="form-control" name="git_format" defaultValue={String(competition.git_format || '')} placeholder="gitea@10.72.190.121:<username>/FinalProject.git" /></div></div> : null}
    {mode !== 'agent_judge' && mode !== 'reverse_judge' ? <div className="row mb-3 align-items-end"><div className="col-md-4"><label className="form-label"><i className="fas fa-hourglass-half me-2 text-muted" />每 48 小时提交次数</label><LimitControl competition={competition} onReset={() => command.mutate({path: 'submission-limit/reset'})} /></div></div> : null}
    <div className="mb-3"><div className="form-check form-switch rank-online-row"><input className="form-check-input" type="checkbox" id="rankingActive" name="is_active" value="1" defaultChecked={active} /><label className="form-check-label" htmlFor="rankingActive"><i className="fas fa-bullhorn me-2 text-muted" />上线</label></div></div>
    {mode === 'elo' ? <fieldset className="border rounded p-3 mb-3"><legend className="float-none w-auto px-2 small fw-semibold text-muted mb-2"><i className="fas fa-chess-knight me-2" />ELO 参数</legend><div className="row g-2 flex-nowrap">{[
      ['elo_initial_rating', 'fa-flag', '初始分', competition.elo_initial_rating, 1500, 100, 5000],
      ['elo_k_factor', 'fa-sliders-h', 'K 因子', competition.elo_k_factor, 32, 1, 200],
      ['elo_max_matches', 'fa-list-ol', '单提交最大对战', competition.elo_max_matches, 200, 1, 10000],
      ['elo_match_interval_seconds', 'fa-clock', '匹配间隔（秒）', competition.elo_match_interval_seconds, 60, 5, 3600],
      ['elo_initial_burst', 'fa-bolt', '新提交即时补战', competition.elo_initial_burst, 5, 0, 50],
      ['elo_max_pairs_per_round', 'fa-random', '每轮匹配对数', competition.elo_max_pairs_per_round, 1, 1, 8],
    ].map(([name, icon, label, value, fallback, min, max]) => <div className="col" key={String(name)}><label className="form-label small"><i className={`fas ${String(icon)} me-2 text-muted`} />{String(label)}</label><input type="number" className="form-control" name={String(name)} defaultValue={numberValue(value, Number(fallback))} min={Number(min)} max={Number(max)} step={1} /></div>)}</div></fieldset> : null}
    <div className="mb-3"><label className="form-label"><i className="fas fa-pen-nib me-2 text-muted" />赛事描述（支持 Markdown）</label><textarea className="form-control" name="description" rows={10} defaultValue={String(competition.description || '')} /></div>
    <button type="submit" className="btn btn-outline-primary" disabled={save.isPending}><i className="fas fa-save me-2" />{save.isPending ? '保存中…' : '保存基本信息'}</button>{save.isSuccess ? <span className="text-success ms-3">已保存</span> : null}{save.isError ? <span className="text-danger ms-3">{errorMessage(save.error)}</span> : null}
  </form></div></div>
  {mode === 'absolute' ? uploadCard(<><i className="fas fa-key me-2" /> 标准答案（.{answerFormat}）</>, referenceName ? <span className="text-success"><i className="fas fa-check-circle me-2" />{referenceName}</span> : <span className="text-danger"><i className="fas fa-times-circle me-2" />尚未上传</span>, 'reference', 'reference', referenceFile, setReferenceFile, `.${answerFormat}`) : null}
  {mode === 'absolute' || mode === 'elo' ? uploadCard(<><i className="fas fa-scroll me-2" /> 评测脚本（.py，必填）</>, scriptName ? <span className="text-success"><i className="fas fa-check-circle me-2" />{scriptName}</span> : <span className="text-warning"><i className="fas fa-exclamation-triangle me-2" />评测脚本必填</span>, 'scoring-script', 'scoring_script', scriptFile, setScriptFile, '.py') : null}
  {mode === 'agent_judge' || mode === 'reverse_judge' ? <AgentJudgeSettings data={data} reverse={mode === 'reverse_judge'} /> : null}
  {mode === 'agent_judge' ? <AgentRulesSettings data={data} /> : null}
  <div className="card mb-3"><div className="card-header"><i className="fas fa-paperclip me-2" /> 附件</div><div className="card-body"><div className="row g-2 mb-3"><div className="col"><input type="file" className="form-control" onChange={(event) => setAttachmentFile(event.target.files?.[0] || null)} /></div><div className="col-auto"><button type="button" className="btn btn-outline-primary" disabled={upload.isPending} onClick={(event) => {if (attachmentFile) upload.mutate({path: 'attachments', field: 'attachment', file: attachmentFile}); else event.currentTarget.closest('.row')?.querySelector<HTMLInputElement>('input[type=file]')?.click()}}><i className="fas fa-cloud-upload-alt me-1" /> 上传附件</button></div></div>{files.length ? <div className="list-group">{files.map((file) => <div className="list-group-item d-flex justify-content-between align-items-center" key={file.id}><div><i className="fas fa-file me-2" />{file.filename}<small className="text-muted ms-2">{Math.floor(numberValue(file.file_size) / 1024)} KB · {String(file.uploaded_at || '')}</small></div><div>{file.media_kind ? <button type="button" className="btn btn-sm btn-outline-primary me-1 rk-media-btn" title={`${file.media_kind === 'video' ? '播放' : '查看'} ${file.filename}`} onClick={() => setAttachmentPreview({filename: file.filename, mediaKind: file.media_kind || 'image', inlineUrl: `${file.download_url}?inline=1`, downloadUrl: file.download_url})}><i className={`fas ${file.media_kind === 'video' ? 'fa-play' : 'fa-eye'}`} /></button> : null}<a href={file.download_url} className="btn btn-sm btn-outline-primary me-1" download><i className="fas fa-download" /></a><button type="button" className="btn btn-sm btn-outline-danger" onClick={() => {if (window.confirm(`删除附件：${file.filename} ?`)) command.mutate({path: `attachments/${file.id}`, method: 'DELETE'})}}><i className="fas fa-trash" /></button></div></div>)}</div> : <p className="text-muted mb-0">暂无附件。</p>}{upload.isError ? <div className="small text-danger mt-3">{errorMessage(upload.error)}</div> : null}</div></div>
  {mode === 'elo' ? <div className="card mb-3"><div className="card-header d-flex justify-content-between align-items-center"><span><i className="fas fa-toggle-on me-2" /> 动态评分运行控制</span><span className={`badge ${eloRunning ? 'bg-success' : 'bg-secondary'}`}><i className={`${eloRunning ? 'fas' : 'far'} fa-circle me-1`} /> {eloRunning ? '运行中' : '已停止'}</span></div><div className="card-body"><div className="d-flex flex-wrap gap-2"><button type="button" className="btn btn-success" disabled={eloRunning || command.isPending} onClick={() => command.mutate({path: 'elo/start'})}><i className="fas fa-play me-1" /> 启动动态评分</button><button type="button" className="btn btn-warning" disabled={!eloRunning || command.isPending} onClick={() => command.mutate({path: 'elo/stop'})}><i className="fas fa-pause me-1" /> 停止动态评分</button><button type="button" className="btn btn-outline-danger" disabled={command.isPending} onClick={() => {if (window.confirm(`重置后将清空本场赛事的全部对战历史，并把池中所有提交的 ELO 分恢复到初始分（${numberValue(competition.elo_initial_rating, 1500).toFixed(0)}）。该操作不可撤销，确认重置吗？`)) command.mutate({path: 'elo/reset'})}}><i className="fas fa-undo me-1" /> 重置动态评分</button></div></div></div> : null}
  {upload.isError || command.isError || removeCompetition.isError ? <div className="alert alert-danger" role="alert"><i className="fas fa-triangle-exclamation me-2" />{errorMessage(upload.error || command.error || removeCompetition.error)}</div> : null}
  <div className="card border-danger"><div className="card-header text-danger"><i className="fas fa-exclamation-triangle me-2" /> 危险操作</div><div className="card-body"><button type="button" className="btn btn-outline-danger" disabled={removeCompetition.isPending} onClick={() => {if (window.confirm(`删除后将同时清除比赛的全部提交与附件，且无法恢复。确认删除 ${competition.title} 吗？`)) removeCompetition.mutate()}}><i className="fas fa-trash me-1" /> 删除比赛</button></div></div>
  <MediaPreviewModal target={attachmentPreview} onClose={() => setAttachmentPreview(null)} />
  </section>
}

function BatchPanel({data}: {data: Response}) {
  const [selectedClasses, setSelectedClasses] = useState<string[]>([])
  const [template, setTemplate] = useState(String(data.batch_default_template || ''))
  const [classOpen, setClassOpen] = useState(false)
  const [classSearch, setClassSearch] = useState('')
  const [endpointOpen, setEndpointOpen] = useState(false)
  const enabledEndpoints = (data.aj_endpoints || []).filter((item) => String(item.status || '') === 'enabled')
  const [endpointId, setEndpointId] = useState(() => String(enabledEndpoints[0]?.id || ''))
  const [jobId, setJobId] = useState('')
  const [selectedUsers, setSelectedUsers] = useState<string[]>([])
  const classPickerRef = useDismissibleDropdown<HTMLDivElement>(classOpen, () => setClassOpen(false))
  const endpointPickerRef = useDismissibleDropdown<HTMLDivElement>(endpointOpen, () => setEndpointOpen(false))
  const isReverse = String(data.competition.scoring_mode || '') === 'reverse_judge'
  const classes = (data.batch_classes || []).filter((item) => `${String(item.class_cn || '')} ${String(item.class_en || '')}`.toLowerCase().includes(classSearch.trim().toLowerCase()))
  const selectedEndpoint = enabledEndpoints.find((item) => String(item.id) === endpointId)
  useEffect(() => {setTemplate(String(data.batch_default_template || ''))}, [data.batch_default_template])
  useEffect(() => {
    if (isReverse && !enabledEndpoints.some((item) => String(item.id) === endpointId)) setEndpointId(String(enabledEndpoints[0]?.id || ''))
  }, [data.aj_endpoints, enabledEndpoints, endpointId, isReverse])
  const endpointLabel = (item: JsonRecord) => {
    const harness = String(item.harness || 'claude_code')
    const harnessLabel = harness === 'claude_code' ? 'Claude Code' : harness === 'codex' ? 'Codex' : harness === 'opencode' ? 'OpenCode' : harness === 'pi' ? 'Pi' : harness
    return `${harnessLabel} (${String(item.model || `节点 #${item.id}`)})`
  }
  const probe = useMutation({mutationFn: () => apiFetch<ApiEnvelope & {job_id: string}>(`/api/ranking/competitions/${data.competition.id}/batch/probes`, {method: 'POST', body: JSON.stringify({classes: selectedClasses, template, agent_endpoint_id: endpointId || undefined})}), onSuccess: (payload) => {setJobId(payload.job_id); setSelectedUsers([])}})
  const status = useQuery({queryKey: ['ranking-batch-probe', data.competition.id, jobId], queryFn: () => apiFetch<ApiEnvelope & {state?: string; found?: JsonRecord[]; total?: number; checked?: number}>(`/api/ranking/competitions/${data.competition.id}/batch/probes/status?job=${encodeURIComponent(jobId)}`), enabled: Boolean(jobId), refetchInterval: (query) => query.state.data?.state === 'done' || query.state.data?.state === 'failed' ? false : 900})
  const found = status.data?.found || []
  const create = useMutation({mutationFn: () => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${data.competition.id}/batch/submissions`, {method: 'POST', body: JSON.stringify({template, usernames: selectedUsers, agent_endpoint_id: endpointId || undefined})})})
  return <section className="ranking-v2-tab ranking-v2-batch" data-ranking-tab-panel="batch_eval"><div className="bm-wrap is-hero"><div className="bm-stage"><div className="bm-control-shell"><div className="bm-control-row">{(data.batch_classes || []).length ? <div ref={classPickerRef} className={`bm-dd${classOpen ? ' open' : ''}`}><button type="button" className="bm-picker-trigger bm-dd-trigger" aria-haspopup="listbox" aria-expanded={classOpen} onClick={() => setClassOpen((open) => !open)}><span className="bm-picker-icon bm-class-logo is-placeholder" /><span className="bm-picker-current"><strong>{selectedClasses.length ? `已选 ${selectedClasses.length} 个班级` : '选择班级'}</strong><small>{selectedClasses.length ? selectedClasses.join(' · ') : 'MULTIPLE SELECT'}</small></span><i className="fas fa-chevron-down bm-picker-caret" /></button><div className="bm-dd-panel" role="listbox" aria-label="选择班级" aria-multiselectable="true" hidden={!classOpen}><div className="bm-dd-search"><i className="fas fa-magnifying-glass" /><input type="search" placeholder="搜索班级" autoComplete="off" spellCheck={false} value={classSearch} onChange={(event) => setClassSearch(event.target.value)} /></div><div className="bm-dd-list">{classes.map((item) => {const code = String(item.class_en || ''); return <label className="bm-opt" key={code}><input type="checkbox" className="bm-cls-cb bm-check" checked={selectedClasses.includes(code)} onChange={(event) => setSelectedClasses((current) => event.target.checked ? [...current, code] : current.filter((value) => value !== code))} /><BatchClassLogo item={item} /><span className="bm-opt-copy"><strong>{String(item.class_cn || code)}</strong><small>{code}</small></span><span className="bm-opt-state"><i className="fas fa-check" /></span></label>})}{classes.length ? null : <div className="bm-empty bm-class-empty">无匹配班级</div>}</div><div className="bm-dd-foot"><button type="button" onClick={() => setSelectedClasses((data.batch_classes || []).map((item) => String(item.class_en || '')))}>全选</button><button type="button" onClick={() => setSelectedClasses([])}>清空</button><button type="button" className="bm-dd-done" onClick={() => setClassOpen(false)}>完成</button></div></div></div> : <div className="bm-picker-trigger is-disabled" aria-disabled="true"><span className="bm-picker-icon"><i className="fas fa-users" /></span><span className="bm-picker-current"><strong>暂无班级</strong><small>NO AVAILABLE CLASS</small></span></div>}</div><div className="bm-control-row">{isReverse ? <div className="bm-node"><div ref={endpointPickerRef} className={`rk-choice${endpointOpen ? ' open' : ''}`}><button type="button" className="rk-choice-trigger" aria-haspopup="listbox" aria-expanded={endpointOpen} onClick={() => setEndpointOpen((open) => !open)}><span className="rk-choice-trigger-main">{selectedEndpoint ? <><i className={harnessIconClass(selectedEndpoint.harness)} aria-hidden="true" /><i className={modelIconClass(selectedEndpoint.model)} aria-hidden="true" /></> : <i className="fas fa-robot" aria-hidden="true" />}<span>{selectedEndpoint ? endpointLabel(selectedEndpoint) : '无可用节点'}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox" aria-label="AI 节点" hidden={!endpointOpen}>{enabledEndpoints.map((item) => <button type="button" className={`rk-choice-option${String(item.id) === endpointId ? ' active' : ''}`} role="option" aria-selected={String(item.id) === endpointId} onClick={() => {setEndpointId(String(item.id)); setEndpointOpen(false)}} key={String(item.id)}><span className="rk-choice-option-main"><i className={harnessIconClass(item.harness)} aria-hidden="true" /><i className={modelIconClass(item.model)} aria-hidden="true" /><span className="rk-choice-option-name">{endpointLabel(item)}</span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div></div></div> : <div className="bm-picker-trigger bm-fixed-node" aria-label="赛事 AI 评测节点"><span className="bm-picker-icon"><i className="fas fa-robot" /></span><span className="bm-picker-current"><strong>赛事默认 AI 节点</strong><small>COMPETITION DEFAULT</small></span><i className="fas fa-circle-check bm-node-ready" /></div>}</div><div className="bm-control-row"><label className="bm-template-shell"><span className="bm-picker-icon"><i className="fas fa-code-branch" /></span><span className="bm-template-group"><input value={template} placeholder="gitea@host:<username>/FinalProject.git" onChange={(event) => setTemplate(event.target.value)} maxLength={500} spellCheck={false} autoComplete="off" autoCapitalize="off" /><small><code>&lt;username&gt;</code> 将替换为成员用户名</small></span></label></div><div className="bm-query-row"><button type="button" className="bm-go" disabled={probe.isPending} onClick={() => probe.mutate()}><i className="fas fa-magnifying-glass" /><span>{probe.isPending ? '查询中…' : '查询'}</span></button></div></div>{probe.isError ? <div className="bm-status text-danger">{errorMessage(probe.error)}</div> : null}{status.data ? <div className="bm-status">{status.data.state === 'done' ? '查询完成' : `正在查询 ${numberValue(status.data.checked)} / ${numberValue(status.data.total)}`}</div> : null}</div>{found.length ? <div className="bm-results"><div className="bm-results-bar"><div className="bm-count">找到 <b>{found.length}</b> 个仓库</div><div className="bm-actions"><button type="button" className="bm-selall" onClick={() => setSelectedUsers(selectedUsers.length === found.length ? [] : found.map((item) => String(item.username)))}>{selectedUsers.length === found.length ? '清空' : '全选'}</button><span className="bm-selcount">已选 {selectedUsers.length}</span><button type="button" className="bm-create" disabled={!selectedUsers.length || create.isPending} onClick={() => create.mutate()}>批量创建提交</button></div></div><div className="bm-grid">{found.map((item) => {const user = String(item.username || ''); return <label className="bm-opt" key={user}><input type="checkbox" className="bm-check" checked={selectedUsers.includes(user)} onChange={(event) => setSelectedUsers((current) => event.target.checked ? [...current, user] : current.filter((value) => value !== user))} /><Identicon seed={user} className="bm-class-logo" /><span className="bm-opt-copy"><strong>{user}</strong><small>{String(item.url || '')}</small></span></label>})}</div>{create.isSuccess ? <div className="bm-createmsg text-success">批量任务已创建</div> : null}{create.isError ? <div className="bm-createmsg text-danger">{errorMessage(create.error)}</div> : null}</div> : status.data?.state === 'done' ? <div className="ranking-v2-empty bm-empty"><i className="fas fa-code-branch" /><strong>没有找到仓库</strong><span>请检查班级范围、仓库模板或仓库读取权限。</span></div> : null}</div></section>
}

export default function RankingDetailPage() {
  const {competitionId = ''} = useParams()
  const queryClient = useQueryClient()
  const {session} = useSession()
  const [params] = useSearchParams()
  const tab = params.get('tab') || 'description'
  const [railOpen, setRailOpen] = useState(false)
  const result = useQuery({queryKey: ['ranking', competitionId, tab, params.toString()], queryFn: () => apiFetch<Response>(`/api/ranking/competitions/${competitionId}${queryString({tab, page: params.get('page'), mine: params.get('mine'), q: params.get('q'), status: params.get('status')})}`), refetchOnWindowFocus: 'always'})
  const navigation = useQuery({queryKey: ['ranking', competitionId, 'navigation-state'], queryFn: () => apiFetch<NavigationResponse>(`/ranking/${competitionId}/navigation-state`), enabled: Boolean(competitionId), refetchInterval: 10000, refetchIntervalInBackground: false, refetchOnWindowFocus: 'always'})
  useEffect(() => {setRailOpen(false)}, [tab])
  useEffect(() => {
    if (result.data?.competition.title) document.title = `${result.data.competition.title} - Numerical OJ`
  }, [result.data?.competition.title])
  useEffect(() => {
    const currentRevision = String(result.data?.navigation?.revision || '')
    const nextRevision = String(navigation.data?.revision || '')
    if (currentRevision && nextRevision && currentRevision !== nextRevision) void queryClient.invalidateQueries({queryKey: ['ranking', competitionId], predicate: (query) => query.queryKey[2] !== 'navigation-state'})
  }, [competitionId, navigation.data?.revision, queryClient, result.data?.navigation?.revision])
  const data = result.data
  const liveNavigation = navigation.data?.navigation ? {...navigation.data.navigation, revision: navigation.data.revision} : data?.navigation
  const navCounts = liveNavigation?.counts || {}
  const scoring = String(data?.competition.scoring_mode || 'absolute').toLowerCase()
  const isElo = scoring === 'elo'
  const isAgentJudge = scoring === 'agent_judge'
  const isAiJudge = isAgentJudge || scoring === 'reverse_judge'
  const isAdmin = Boolean(data?.is_admin || session?.user?.is_admin)
  const tabs = useMemo(() => {
    const values = [
      {value: 'description', icon: 'fa-file-alt', label: '比赛描述'},
      {value: 'submit', icon: 'fa-paper-plane', label: '提交作品'},
      {value: 'leaderboard', icon: 'fa-list-ol', label: '排行榜', count: navCounts.leaderboard},
      ...(isElo ? [{value: 'matches', icon: 'fa-chess', label: '对战数据', count: navCounts.matches}] : []),
    ]
    const admin = isAdmin ? [
      {value: 'all_submissions', icon: 'fa-clipboard-list', label: '所有提交', count: navCounts.all_submissions},
      ...(isAgentJudge ? [{value: 'appeals', icon: 'fa-gavel', label: '申诉处理', count: navCounts.appeals}] : []),
      ...(isAiJudge ? [{value: 'batch_eval', icon: 'fa-layer-group', label: '批量评测'}] : []),
      {value: 'edit', icon: 'fa-pencil-alt', label: '编辑比赛'},
    ] : []
    return {public: values, admin}
  }, [isAdmin, isAgentJudge, isAiJudge, isElo, navCounts.all_submissions, navCounts.appeals, navCounts.leaderboard, navCounts.matches])

  if (result.isPending) return <LoadingState label="正在进入赛场" />
  if (result.isError) return <ErrorState message={result.error.message} />
  const competition = data!.competition
  const files = data!.files || []
  const panel = (() => {
    if (tab === 'description') return <section className="ranking-v2-tab ranking-v2-description">{data!.rendered_description || competition.description ? <MarkdownContent html={data!.rendered_description || String(competition.description)} className="numoj-markdown numoj-problem-code-rendering ranking-description" /> : <div className="ranking-v2-empty ranking-v2-empty--document"><i className="fas fa-file-lines" /><strong>暂无比赛描述</strong><span>赛事管理员尚未发布说明文档。</span></div>}</section>
    if (tab === 'submit') return <SubmitPanel data={data!} competitionId={competitionId} />
    if (tab === 'leaderboard') return <LeaderboardPanel data={data!} username={session?.user?.username} />
    if (tab === 'matches') return <MatchesPanel data={data!} username={session?.user?.username} isAdmin={isAdmin} />
    if (tab === 'all_submissions') return <AllSubmissionsPanel data={data!} />
    if (tab === 'appeals') return <AppealsPanel data={data!} />
    if (tab === 'batch_eval') return <BatchPanel data={data!} />
    if (tab === 'edit') return <EditPanel data={data!} />
    return <section className="ranking-v2-tab"><div className="ranking-v2-empty"><i className="fas fa-circle-question" /><strong>未知比赛页面</strong><span>请从左侧比赛功能重新选择。</span></div></section>
  })()

  return <section className="ranking-detail-v2 ranking-v2-detail" data-ranking-detail data-ranking-initial-tab={tab} data-ranking-scoring-mode={scoring}>
    <header className="ranking-competition-header"><div className="ranking-competition-heading"><div className="ranking-competition-eyebrow"><Link to="/rankings" className="ranking-back-link"><i className="fas fa-arrow-left" /><span>打榜赛列表</span></Link><span>/</span><span>COMPETITION · {numberValue(competition.is_active) === 1 ? 'LIVE' : 'OFFLINE'}</span></div><div className="ranking-competition-title-line"><span className="ranking-competition-id">#{String(competition.id).padStart(3, '0')}</span><h1>{competition.title}</h1></div></div><div className="ranking-header-facts" aria-label="比赛信息"><div className="ranking-header-fact"><span>MODE</span><strong>{modeLabel(scoring)}</strong></div><div className="ranking-header-fact"><span>CREATED</span><strong>{String(competition.created_at || '')}</strong></div><span className={`ranking-status-chip${numberValue(competition.is_active) === 1 ? '' : ' is-offline'}`}><i /><span>{numberValue(competition.is_active) === 1 ? 'LIVE' : 'OFFLINE'}</span></span></div><button type="button" className="ranking-mobile-rail-open" aria-controls="rankingFunctionRail" aria-expanded={railOpen} onClick={() => setRailOpen(true)}><i className="fas fa-sliders-h" /><span>比赛功能</span></button></header>
    <div className="ranking-workspace"><aside className={`ranking-function-rail${railOpen ? ' is-open' : ''}`} id="rankingFunctionRail" aria-label="比赛功能"><button type="button" className="ranking-rail-close" aria-label="关闭比赛功能" onClick={() => setRailOpen(false)}><i className="fas fa-times" /></button><nav className="ranking-rail-nav" aria-label="比赛页面"><p className="ranking-rail-group-label">COMPETITION</p>{tabs.public.map((item) => <Link to={`/rankings/${competitionId}${queryString({tab: item.value})}`} className={`ranking-rail-button${tab === item.value ? ' active' : ''}`} aria-current={tab === item.value ? 'page' : undefined} key={item.value}><i className={`fas ${item.icon}`} /><span>{item.label}</span>{item.count != null ? <span className="ranking-rail-count">{item.count}</span> : null}</Link>)}{tabs.admin.length ? <><p className="ranking-rail-group-label is-admin">ADMIN OPERATIONS</p>{tabs.admin.map((item) => <Link to={`/rankings/${competitionId}${queryString({tab: item.value})}`} className={`ranking-rail-button is-admin${tab === item.value ? ' active' : ''}`} aria-current={tab === item.value ? 'page' : undefined} key={item.value}><i className={`fas ${item.icon}`} /><span>{item.label}</span>{item.count != null ? <span className="ranking-rail-count">{item.count}</span> : null}</Link>)}</> : null}</nav><section className="ranking-rail-attachments" aria-labelledby="rankingAttachmentsTitle"><p className="ranking-attachment-label" id="rankingAttachmentsTitle">ATTACHMENTS · <span>{files.length}</span></p><AttachmentList files={files} /></section></aside><div className="ranking-rail-backdrop" hidden={!railOpen} onClick={() => setRailOpen(false)} /><div className="ranking-content-scroll"><div className="ranking-fragment-progress" aria-hidden="true" /><main className="ranking-panel-stage"><div className="ranking-panel-host"><div data-ranking-panel data-ranking-tab={tab}>{panel}</div></div></main></div></div>
  </section>
}
