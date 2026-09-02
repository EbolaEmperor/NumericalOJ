import {useEffect, useMemo, useRef, useState, type CSSProperties} from 'react'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {MarkdownContent} from '../components/MarkdownContent'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {ReactModal} from '../components/ReactModal'
import {useRuleTopology} from './ruleTopology'
import {useMatchHtmlFrame} from './useMatchHtmlFrame'

export type RankingSubmissionOverlayTarget = {
  id: number
  createdAt?: string
  status?: string
  username?: string
  answerDownloadUrl?: string
}

export type RankingMatchDetail = ApiEnvelope & {
  id: number
  created_at?: string
  username_a?: string
  username_b?: string
  winner?: number
  error_message?: string
  details?: unknown
  detail_output?: {format?: string; content?: string; height?: number}
}

export type RankingMediaTarget = {
  filename: string
  mediaKind: string
  inlineUrl: string
  downloadUrl: string
}

function numberValue(value: unknown, fallback = 0) {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric : fallback
}

function textValue(value: unknown) {
  if (typeof value === 'string') return value
  if (value == null) return ''
  try { return JSON.stringify(value, null, 2) } catch { return String(value) }
}

function legacyMatchOutput(data: RankingMatchDetail) {
  if (data.error_message) return {format: 'text', content: `【脚本错误】\n${data.error_message}`, height: 520}
  if (data.details == null || data.details === '') return {format: 'text', content: '（评测脚本未输出 details 字段）', height: 520}
  if (typeof data.details === 'string') {
    try {
      const parsed = JSON.parse(data.details) as JsonRecord
      const preferred = parsed && typeof parsed === 'object' ? parsed.reason || parsed.verdict || parsed.explanation || parsed.justification || parsed.message : null
      return {format: 'text', content: preferred ? String(preferred) : textValue(parsed), height: 520}
    } catch { return {format: 'text', content: data.details, height: 520} }
  }
  if (typeof data.details === 'object') {
    const detail = data.details as JsonRecord
    const preferred = detail.reason || detail.verdict || detail.explanation || detail.justification || detail.message
    return {format: 'text', content: preferred ? String(preferred) : textValue(detail), height: 520}
  }
  return {format: 'text', content: String(data.details), height: 520}
}

function MatchHtmlDetail({matchId, content, requestedHeight}: {matchId: number; content: string; requestedHeight?: number}) {
  const frame = useMatchHtmlFrame({matchId, content, requestedHeight})
  return <div className="match-detail-html"><iframe key={frame.documentKey} ref={frame.frameRef} title="评分脚本生成的互动对战详情" sandbox="allow-scripts" referrerPolicy="no-referrer" aria-busy={!frame.ready} style={frame.frameStyle} /></div>
}

export function MatchDetailModal({open, detail, pending, error, onClose}: {open: boolean; detail?: RankingMatchDetail; pending: boolean; error?: Error | null; onClose: () => void}) {
  const output = detail ? detail.detail_output && typeof detail.detail_output === 'object' ? detail.detail_output : legacyMatchOutput(detail) : null
  const isHtml = output?.format === 'html'
  const winner = numberValue(detail?.winner, -1)
  const winnerLabel = winner === 1 ? `${detail?.username_a || ''} 胜` : winner === 2 ? `${detail?.username_b || ''} 胜` : winner === 0 ? '平局' : '失败'
  return <ReactModal open={open} onClose={onClose} id="matchDetailModal" labelledBy="matchDetailModalLabel" className="ranking-v2-detail" dialogClassName="modal-xl modal-dialog-scrollable">
    <div className="modal-content match-detail-modal"><div className="modal-header"><h5 className="modal-title" id="matchDetailModalLabel"><i className="fas fa-magnifying-glass me-2" />对战详情</h5><button type="button" className="btn-close" aria-label="Close" onClick={onClose} /></div><div className="modal-body">
      {pending ? <div className="text-center text-muted py-4"><MathCurveLoader size="md" label="加载中…" /></div> : error ? <div className="match-detail-error" role="alert">{errorMessage(error)}</div> : detail && output ? <div>
        <div className="match-detail-toolbar" hidden={isHtml}><div className="match-detail-meta">#{detail.id} · {detail.created_at} · {winnerLabel}</div><div className="match-detail-tools"><span className={`match-detail-format${isHtml ? ' is-html' : ''}`}><i className={`fas ${isHtml ? 'fa-code' : 'fa-align-left'}`} /><span>{isHtml ? '互动 HTML' : '文本'}</span></span></div></div>
        {!isHtml ? <><h6 className="match-detail-heading">评测脚本给出的胜负理由</h6><pre className="match-detail-text">{output.content || ''}</pre></> : <MatchHtmlDetail matchId={detail.id} content={output.content || ''} requestedHeight={output.height} />}
      </div> : null}
    </div><div className="modal-footer"><button type="button" className="btn btn-secondary" onClick={onClose}>关闭</button></div></div>
  </ReactModal>
}

export function MediaPreviewModal({target, onClose}: {target: RankingMediaTarget | null; onClose: () => void}) {
  const videoRef = useRef<HTMLVideoElement>(null)
  useEffect(() => () => {
    const video = videoRef.current
    if (!video) return
    video.pause()
    video.removeAttribute('src')
    video.load()
  }, [target])
  return <ReactModal open={Boolean(target)} onClose={onClose} id="rkMediaViewer" labelledBy="rkMediaTitle" dialogClassName="modal-dialog-centered modal-xl">
    <div className="modal-content"><div className="modal-header py-2"><h5 className="modal-title text-truncate" style={{maxWidth: '70%'}}><i className="fas fa-photo-film me-2" /><span id="rkMediaTitle">{target?.filename}</span></h5><div className="ms-auto d-flex align-items-center gap-2"><a className="btn btn-sm btn-outline-primary" href={target?.downloadUrl} download><i className="fas fa-download me-1" />下载</a><button type="button" className="btn-close" aria-label="关闭" onClick={onClose} /></div></div><div className="modal-body text-center">{target?.mediaKind === 'video' ? <video ref={videoRef} className="rk-media-video" controls preload="metadata" playsInline src={target.inlineUrl} /> : target ? <img className="rk-media-img" src={target.inlineUrl} alt={target.filename} /> : null}</div></div>
  </ReactModal>
}

type SseState = {snapshot: JsonRecord | null; streamError: string}

function useRankingEventSnapshot(url: string | null, open: boolean, onTerminal?: () => void, reconnect = false) {
  const [state, setState] = useState<SseState>({snapshot: null, streamError: ''})
  const onTerminalRef = useRef(onTerminal)
  useEffect(() => {onTerminalRef.current = onTerminal}, [onTerminal])
  useEffect(() => {
    setState({snapshot: null, streamError: ''})
    if (!open || !url) return undefined
    if (!window.EventSource) {
      setState({snapshot: null, streamError: '当前浏览器不支持实时进度，请刷新页面后重试。'})
      return undefined
    }
    let settled = false
    const source = new EventSource(url)
    source.onopen = () => setState((current) => ({...current, streamError: ''}))
    const update = (event: MessageEvent) => {
      try { setState({snapshot: JSON.parse(event.data) as JsonRecord, streamError: ''}) } catch { /* 保留上一个完整快照 */ }
    }
    source.addEventListener('progress', update as EventListener)
    source.addEventListener('done', ((event: MessageEvent) => {settled = true; update(event); source.close(); onTerminalRef.current?.()}) as EventListener)
    source.addEventListener('timeout', ((event: MessageEvent) => {
      if (reconnect) {
        update(event)
        setState((current) => ({...current, streamError: '本轮实时连接已结束，正在自动续接评测进度…'}))
        return
      }
      settled = true
      setState((current) => ({...current, streamError: '实时连接超时，请关闭弹窗后重试。'}))
      source.close()
      onTerminalRef.current?.()
    }) as EventListener)
    source.onerror = () => {
      if (settled) return
      if (reconnect && source.readyState !== EventSource.CLOSED) {
        // 反向评测可能超过单次 SSE 租约；沿用旧版行为，让浏览器自动续接。
        setState((current) => ({...current, streamError: '实时连接暂时中断，正在自动重连…'}))
        return
      }
      settled = true
      setState((current) => ({...current, streamError: '实时连接中断，请关闭弹窗后重试。'}))
      source.close()
    }
    return () => {settled = true; source.close()}
  }, [open, reconnect, url])
  return state
}

const resultBadge: Record<string, {label: string; color: string; background: string}> = {
  pass: {label: '通过', color: '#1f7a4d', background: '#e9f3ec'},
  failed: {label: '未通过', color: '#b03a2e', background: '#f8e9e7'},
  skipped: {label: '依赖跳过', color: '#6c757d', background: '#f1f1f3'},
  error: {label: '异常', color: '#b07340', background: '#fbf0e3'},
  pending: {label: '待评测', color: '#2563cb', background: '#e8f0fb'},
}

function htmlOrText(record: JsonRecord, htmlKey: string, textKey: string) {
  const html = String(record[htmlKey] || '')
  return html ? <MarkdownContent html={html} className="aj-md" /> : <div className="aj-md" style={{whiteSpace: 'pre-wrap'}}>{String(record[textKey] || '')}</div>
}

function TraceMessage({message}: {message: JsonRecord}) {
  const kind = String(message.kind || message.type || message.role || 'assistant').replace('_', '-')
  const titleMap: Record<string, string> = {assistant: 'Agent 回复', thinking: '思考过程', tool: '工具调用', 'tool-result': '工具结果', subagent: '子 Agent'}
  const iconMap: Record<string, string> = {assistant: 'fa-robot', thinking: 'fa-lightbulb', tool: 'fa-wrench', 'tool-result': 'fa-terminal', subagent: 'fa-diagram-project'}
  const title = String(message.title || titleMap[kind] || '执行记录')
  const body = String(message.html || '')
  const plain = textValue(message.content ?? message.text ?? message.output ?? message.arguments ?? message.data)
  const rendered = body ? <MarkdownContent html={body} className="rj-msg-body rj-md" /> : <div className={`rj-msg-body${kind === 'tool' ? ' rj-tool-text' : kind === 'tool-result' ? ' rj-tool-result-text' : ''}`}>{plain}</div>
  if (kind === 'assistant') return <div className="rj-msg assistant"><div className="rj-msg-head"><span className="rj-msg-title"><i className={`fas ${iconMap[kind]}`} />{title}</span>{message.timestamp ? <span>{String(message.timestamp)}</span> : null}</div>{rendered}</div>
  const summaryClass = kind === 'thinking' ? 'rj-thinking-summary' : kind === 'tool' ? 'rj-tool-summary' : kind === 'tool-result' ? 'rj-tool-result-summary' : 'rj-subagent-summary'
  const preview = plain.replace(/\s+/g, ' ').trim().slice(0, 90)
  return <details className={`rj-msg ${kind}${message.error ? ' error' : ''}`}><summary className={summaryClass}><span className="rj-summary-main"><i className={`fas ${iconMap[kind] || 'fa-circle-info'}`} /><strong>{title}</strong>{preview ? <span className="rj-summary-preview">{preview}</span> : null}</span>{message.name ? <span className="rj-summary-meta">{String(message.name)}</span> : null}</summary>{rendered}</details>
}

function ExecutionTrace({trace}: {trace?: JsonRecord | null}) {
  const [expanded, setExpanded] = useState(false)
  useEffect(() => setExpanded(false), [trace])
  if (!trace) return <div className="text-muted text-center py-5"><MathCurveLoader size="md" label="正在加载执行轨迹…" /></div>
  const status = String(trace.status || '')
  const messages = Array.isArray(trace.trace_messages) ? trace.trace_messages as JsonRecord[] : []
  const files = Array.isArray(trace.trace_files) ? trace.trace_files as JsonRecord[] : []
  if (!messages.length && (status === 'running' || status === 'pending')) return <div className="agent-trace-pending"><MathCurveLoader iconOnly size="lg" ariaLabel="执行中" /></div>
  const visible = expanded || messages.length <= 9 ? messages : [...messages.slice(0, 7), {kind: '__ellipsis'}, ...messages.slice(-2)]
  return <div className="agent-execution-trace">{trace.error_message ? <div className="rj-alert">{String(trace.error_message)}</div> : null}<div className="rj-agent-feed">{visible.map((message, index) => String(message.kind) === '__ellipsis' ? <button type="button" className="agent-trace-ellipsis" aria-label="展开全部执行记录" onClick={() => setExpanded(true)} key="ellipsis">•••</button> : <TraceMessage message={message} key={String(message.id || `${index}-${message.kind || message.type || ''}`)} />)}</div>{!messages.length ? <div className="rj-empty">暂无执行记录</div> : null}{files.length ? <details className="rj-raw-json"><summary>轨迹文件</summary><pre className="rj-pre mt-2">{textValue(files)}</pre></details> : null}{trace.stdout ? <details className="rj-raw-json"><summary>stdout</summary><pre className="rj-pre mt-2">{String(trace.stdout)}</pre></details> : null}{trace.stderr ? <details className="rj-raw-json"><summary>stderr</summary><pre className="rj-pre mt-2">{String(trace.stderr)}</pre></details> : null}</div>
}

function JudgeTopology({rules, onRule}: {rules: JsonRecord[]; onRule: (rule: JsonRecord) => void}) {
  const topology = useRuleTopology(rules, {nodeWidth: 176, nodeHeight: 96, marginX: 24, marginY: 20, columnGap: 88, rowGap: 72, slotPadding: 46, maxSlotStep: 18})
  const [focus, setFocus] = useState<number | null>(null)
  if (!rules.length) return <div className="aj-result-topo-empty">暂无评分规则。</div>
  if (!topology.layout) return <div className="aj-result-topo-empty text-danger">当前依赖存在环，无法生成拓扑图。</div>
  const {width, height, positions} = topology.layout
  return <div className="aj-result-topo-main"><div className="aj-result-topo-canvas"><div className="aj-result-stage" style={{width, height}}><div className={`aj-result-surface${focus != null ? ' has-focus' : ''}`} style={{width, height}}><svg className="aj-result-svg" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">{topology.edges.map((edge) => {
    const route = topology.routes[topology.engine.edgeKey(edge.from, edge.to)]
    if (!route) return null
    const active = focus === edge.from || focus === edge.to
    return <g key={`${edge.from}:${edge.to}`}><path className={`aj-result-edge${active ? ' edge-active' : ''}`} d={topology.engine.edgePath(route)} /><polygon className={`aj-result-arrow${active ? ' edge-active' : ''}`} points={`${route.x2} ${route.arrowTipY} ${route.x2 - 5} ${route.y2} ${route.x2 + 5} ${route.y2}`} /></g>
  })}</svg>{rules.map((rule) => {
    const id = numberValue(rule.rule_id)
    const point = positions[id]
    const badge = resultBadge[String(rule.effective || 'pending')] || resultBadge.pending
    if (!point) return null
    const ruleText = String(rule.rule_text || '').replace(/\s+/g, ' ').trim()
    return <button type="button" className={`aj-result-node s-${String(rule.effective || 'pending')}${focus === id ? ' node-active' : ''}`} style={{left: point.x, top: point.y} as CSSProperties} onMouseEnter={() => setFocus(id)} onMouseLeave={() => setFocus(null)} onFocus={() => setFocus(id)} onBlur={() => setFocus(null)} onClick={() => onRule(rule)} key={id}><span className="aj-result-node-id">规则 {id} · {numberValue(rule.value)} 分</span><span className="aj-result-node-title">{String(rule.rule_name || ruleText.slice(0, 14) || '未填写规则内容')}</span><span className="aj-result-node-text">{ruleText.length > 42 ? `${ruleText.slice(0, 42)}…` : ruleText || '未填写规则内容'}</span><span className="aj-result-node-foot"><span className="aj-result-status" style={{color: badge.color, background: badge.background}}>{badge.label}</span><span className="aj-result-score">{numberValue(rule.score)} 分</span></span></button>
  })}</div></div></div></div>
}

function JudgeRules({rules}: {rules: JsonRecord[]}) {
  if (!rules.length) return <div className="text-muted text-center py-5">暂无评分规则。</div>
  return <>{rules.map((rule) => {
    const badge = resultBadge[String(rule.effective || 'pending')] || resultBadge.pending
    return <div className="border rounded p-3 mb-2" key={numberValue(rule.rule_id)}><div className="d-flex justify-content-between align-items-start gap-3"><div><span className="badge me-2" style={{color: badge.color, background: badge.background, borderRadius: 4}}>{badge.label}</span><strong>规则 {numberValue(rule.rule_id)}</strong>{rule.rule_name ? <span className="text-muted small"> {String(rule.rule_name)}</span> : null}<span className="text-muted small"> ({numberValue(rule.value)} 分)</span><div className="small mt-1">{htmlOrText(rule, 'rule_html', 'rule_text')}</div></div><div className="text-end fw-semibold" style={{whiteSpace: 'nowrap'}}>{numberValue(rule.score)} 分</div></div>{rule.evidence_html || rule.evidence ? <details className="mt-2"><summary className="small text-muted">评分证据</summary><div className="aj-evi small p-2 mt-1 mb-0">{htmlOrText(rule, 'evidence_html', 'evidence')}</div></details> : null}</div>
  })}</>
}

type AppealState = ApiEnvelope & {has_appeal?: boolean; status?: string; status_label?: string; reason?: string; admin_response?: string; already?: boolean}

export function JudgeDetailModal({competitionId, target, canAppeal, onClose, onTerminal}: {competitionId: number | string; target: RankingSubmissionOverlayTarget | null; canAppeal: boolean; onClose: () => void; onTerminal?: () => void}) {
  const open = Boolean(target)
  const streamUrl = target ? `/api/ranking/competitions/${competitionId}/submissions/${target.id}/judge-events` : null
  const {snapshot, streamError} = useRankingEventSnapshot(streamUrl, open, onTerminal)
  const [view, setView] = useState<'topo' | 'detail' | 'trace'>('trace')
  const [manualView, setManualView] = useState(false)
  const [rulePopup, setRulePopup] = useState<JsonRecord | null>(null)
  const [appealOpen, setAppealOpen] = useState(false)
  const [appeal, setAppeal] = useState<AppealState | null>(null)
  const [appealReason, setAppealReason] = useState('')
  const [appealError, setAppealError] = useState('')
  const [appealPending, setAppealPending] = useState(false)
  const status = String(snapshot?.status || target?.status || '')
  const rules = Array.isArray(snapshot?.rules) ? snapshot.rules as JsonRecord[] : []
  useEffect(() => {
    setManualView(false); setRulePopup(null); setAppealOpen(false); setAppeal(null); setAppealReason(''); setAppealError('')
    setView(['Judging', 'Queued', 'Pending'].includes(String(target?.status || '')) ? 'trace' : 'detail')
    if (!target || !canAppeal) return
    let active = true
    void apiFetch<AppealState>(`/api/ranking/competitions/${competitionId}/submissions/${target.id}/appeal`).then((payload) => {if (active) setAppeal(payload)}).catch(() => undefined)
    return () => {active = false}
  }, [canAppeal, competitionId, target])
  useEffect(() => {
    if (!manualView && snapshot) setView(['Judging', 'Queued', 'Pending'].includes(status) ? 'trace' : 'detail')
  }, [manualView, snapshot, status])
  const submitAppeal = async () => {
    const reason = appealReason.trim()
    if (!reason) {setAppealError('请填写申诉意见'); return}
    if (!target) return
    setAppealPending(true); setAppealError('')
    try {
      const body = new URLSearchParams({reason})
      const payload = await apiFetch<AppealState>(`/api/ranking/competitions/${competitionId}/submissions/${target.id}/appeal`, {method: 'POST', body, headers: {'Content-Type': 'application/x-www-form-urlencoded'}})
      setAppeal(payload.already ? await apiFetch<AppealState>(`/api/ranking/competitions/${competitionId}/submissions/${target.id}/appeal`) : {...payload, has_appeal: true, status: 'pending', status_label: '待处理', reason})
    } catch (error) {setAppealError(errorMessage(error))} finally {setAppealPending(false)}
  }
  const total = numberValue(snapshot?.total_score)
  const max = numberValue(snapshot?.max_score)
  const statusLabels: Record<string, string> = {Accepted: '评测完成', Error: '评测异常', Judging: '评测中', Queued: '等待评测', Pending: '待评测'}
  const statusText = streamError || `${statusLabels[status] || status || '正在连接评测进度…'}${snapshot?.timed_out ? ' · 已超时，保留已有得分' : ''}`
  return <><ReactModal open={open} onClose={onClose} id="judgeDetailModal" labelledBy="judgeDetailModalLabel" className="ranking-v2-detail" dialogClassName="modal-xl modal-dialog-scrollable">
    <div className="modal-content"><div className="modal-header"><div><h5 className="modal-title" id="judgeDetailModalLabel"><i className="fas fa-list-check me-2 text-warning" />评分详情</h5><div className="text-muted small">#{target?.id}{target?.createdAt ? ` · ${target.createdAt}` : ''}</div></div><div className="d-flex align-items-center gap-2">{canAppeal ? <button type="button" className="btn btn-sm btn-outline-warning" onClick={() => setAppealOpen((value) => !value)}><i className="fas fa-gavel me-1" />{appeal?.has_appeal ? '申诉状态' : '我要申诉'}</button> : null}<button type="button" className="btn-close" aria-label="关闭" onClick={onClose} /></div></div><div className="modal-body">
      <div className="d-flex justify-content-between align-items-center mb-2"><span className="small text-muted d-inline-flex align-items-center gap-1">{status === 'Judging' && !streamError ? <MathCurveLoader iconOnly size="xs" ariaLabel="评测进行中" /> : null}<span>{statusText}</span></span><span className="small text-muted">得分 <span className="fw-semibold">{total}</span> / <span>{max}</span></span></div>
      <div className="progress mb-3" style={{height: 6, background: '#f0f0f2', borderRadius: 999}}><div className="progress-bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={max ? Math.round(total / max * 100) : 0} style={{height: 6, borderRadius: 999, background: '#1f7a4d', width: `${max ? Math.max(0, Math.min(100, total / max * 100)) : 0}%`}} /></div>
      <div className="d-flex justify-content-between align-items-center mb-2"><div className="aj-result-tabs" role="tablist" aria-label="评分结果视图">{([['topo', '拓扑'], ['detail', '详情'], ['trace', '执行轨迹']] as const).map(([value, label]) => <button type="button" className={`aj-result-tab${view === value ? ' active' : ''}`} role="tab" aria-selected={view === value} onClick={() => {setView(value); setManualView(true)}} key={value}>{label}</button>)}</div><span className="small text-muted">{view === 'topo' ? '点击拓扑节点查看规则原文与评分证据' : ''}</span></div>
      {canAppeal && appealOpen ? <div className="border rounded p-3 mb-3">{appeal?.has_appeal ? <div><div className="mb-2"><span className="small text-muted me-1"><i className="fas fa-gavel me-1" />申诉状态：</span><span className="fw-semibold">{appeal.status_label || appeal.status}</span></div><div className="small text-muted mb-1">你的申诉意见：</div><div className="aj-evi small p-2 mb-2">{appeal.reason}</div>{appeal.admin_response ? <><div className="small text-muted mb-1">管理员回复：</div><div className="aj-evi small p-2 mb-0">{appeal.admin_response}</div></> : null}</div> : <div><label className="form-label small text-muted mb-1" htmlFor="appealReason"><i className="fas fa-comment-dots me-2" />申诉意见</label><textarea id="appealReason" className="form-control mb-2" rows={3} maxLength={4000} placeholder="例如：规则 X 我已实现并能正常运行，截图见 …" value={appealReason} onChange={(event) => setAppealReason(event.target.value)} autoFocus /><div className="d-flex align-items-center gap-2"><button type="button" className="btn btn-sm btn-warning" disabled={appealPending} onClick={() => void submitAppeal()}><i className="fas fa-paper-plane me-1" />提交申诉</button><span className={`small${appealError ? ' text-danger' : ''}`}>{appealPending ? '提交中…' : appealError}</span></div></div>}</div> : null}
      <div className="aj-result-view" hidden={view !== 'topo'}>{snapshot ? <JudgeTopology rules={rules} onRule={setRulePopup} /> : <div className="text-muted text-center py-5"><MathCurveLoader size="md" label="正在加载评分拓扑…" /></div>}</div>
      <div className="aj-result-view" hidden={view !== 'detail'}>{snapshot ? <JudgeRules rules={rules} /> : <div className="text-muted text-center py-5"><MathCurveLoader size="md" label="正在加载评分细则…" /></div>}</div>
      <div className="aj-result-view" hidden={view !== 'trace'}><ExecutionTrace trace={snapshot?.execution_trace as JsonRecord | undefined} /></div>
    </div></div>
  </ReactModal>{rulePopup ? <div className="aj-result-pop" role="presentation" onMouseDown={(event) => {if (event.target === event.currentTarget) setRulePopup(null)}}><div className="aj-result-pop-box" role="dialog" aria-modal="true" aria-labelledby="judgeRuleReadTitle"><div className="aj-result-pop-head"><div><div className="aj-result-pop-title" id="judgeRuleReadTitle">规则 {numberValue(rulePopup.rule_id)} · {String(rulePopup.rule_name || String(rulePopup.rule_text || '').slice(0, 14))}</div><div className="aj-result-pop-meta"><span className="badge me-2" style={{color: (resultBadge[String(rulePopup.effective)] || resultBadge.pending).color, background: (resultBadge[String(rulePopup.effective)] || resultBadge.pending).background, borderRadius: 999}}>{(resultBadge[String(rulePopup.effective)] || resultBadge.pending).label}</span><span>得分 {numberValue(rulePopup.score)} / {numberValue(rulePopup.value)}</span></div></div><button type="button" className="aj-result-pop-close" aria-label="关闭" onClick={() => setRulePopup(null)}><i className="fas fa-times" /></button></div><div className="aj-result-pop-body"><div className="aj-result-pop-section"><div className="aj-result-pop-label">规则原文</div>{htmlOrText(rulePopup, 'rule_html', 'rule_text')}</div><div className="aj-result-pop-section"><div className="aj-result-pop-label">评分证据</div><div className="aj-evi small p-2">{rulePopup.evidence_html || rulePopup.evidence ? htmlOrText(rulePopup, 'evidence_html', 'evidence') : <span className="text-muted">暂无评分证据。</span>}</div></div></div></div></div> : null}</>
}

const reverseStepLabels: Record<string, string> = {solution_check: '标准答案', quality_gate: '质量门禁', agent_answer: 'AI 作答', ai_judge: '评测 AI 答案'}

function stepVisible(step: JsonRecord) { return String(step.step_key) !== 'quality_gate' || (String(step.status) !== 'skipped' && !(step.result as JsonRecord | undefined)?.skipped) }

function chooseReverseStep(status: string, steps: JsonRecord[], current: string, manual: boolean) {
  const ordered = [...steps].sort((left, right) => numberValue(left.step_order, Number.POSITIVE_INFINITY) - numberValue(right.step_order, Number.POSITIVE_INFINITY))
  const selectable = (step?: JsonRecord) => Boolean(step && stepVisible(step) && String(step.status) !== 'pending')
  const currentStep = ordered.find((step) => String(step.step_key) === current)
  if (manual && selectable(currentStep)) return current
  let selected: JsonRecord | undefined
  if (status === 'Error') selected = [...ordered].reverse().find((step) => selectable(step) && ['failed', 'error'].includes(String(step.status)))
  else if (status === 'Accepted') selected = [...ordered].reverse().find(selectable)
  selected ||= [...ordered].reverse().find((step) => selectable(step) && String(step.status) === 'running')
  selected ||= [...ordered].reverse().find(selectable)
  selected ||= ordered.find(stepVisible)
  return String(selected?.step_key || 'solution_check')
}

function ReverseResult({step, title}: {step: JsonRecord; title: string}) {
  const result = step.result as JsonRecord | undefined
  if (!result) return <div className="rj-empty">暂无 result.json</div>
  const points = result.test_points && typeof result.test_points === 'object' ? result.test_points as Record<string, JsonRecord> : {}
  return <><div className="rj-result-head"><div className="rj-result-title">{title}</div><div className="rj-score-pill"><strong>{numberValue(result.score)}</strong><small>/ {numberValue(result.max_score)}</small></div></div>{Object.entries(points).map(([key, point]) => <div className="rj-point" key={key}><div className="rj-point-head"><strong>{key}</strong><span className="rj-point-score">{numberValue(point.score)} / {numberValue(point.max_score)}</span></div><div className="rj-point-desc">{String(point.description || '')}</div></div>)}<details className="rj-raw-json"><summary>展开原始 JSON</summary><pre className="rj-pre mt-2">{textValue(result)}</pre></details></>
}

function QualityGate({step}: {step: JsonRecord}) {
  const result = (step.result || {}) as JsonRecord
  const violations = Array.isArray(result.violations) ? result.violations as unknown[] : Array.isArray(result.issues) ? result.issues as unknown[] : []
  const rawVerdict = String(result.verdict || '').toLowerCase().replace(/[\s_-]+/g, '')
  const positive = result.passed === true || result.compliant === true || result.approved === true || ['pass', 'passed', 'accepted', 'approved', 'compliant', 'ok', '通过', '合规'].includes(rawVerdict)
  const negative = result.passed === false || result.compliant === false || result.approved === false || ['fail', 'failed', 'rejected', 'denied', 'noncompliant', 'violation', '不通过', '拒绝', '违规'].includes(rawVerdict)
  const verdict = String(step.status) === 'skipped' || result.skipped ? {label: '未执行', cls: 'skip', icon: 'fa-forward-step'} : String(step.status) === 'error' ? {label: '审核异常', cls: 'fail', icon: 'fa-triangle-exclamation'} : positive ? {label: '通过', cls: 'pass', icon: 'fa-check'} : negative ? {label: '不通过', cls: 'fail', icon: 'fa-xmark'} : {label: String(result.verdict || (String(step.status) === 'running' ? '审核中' : '待确认')), cls: 'skip', icon: 'fa-minus'}
  return <>{step.error_message ? <div className="rj-alert">{String(step.error_message)}</div> : null}<div className="rj-result-head"><div className="rj-result-title">质量门禁</div><span className={`rj-gate-verdict ${verdict.cls}`}><i className={`fas ${verdict.icon}`} />{verdict.label}</span></div><div className="rj-gate-label">审核摘要</div><div className="rj-gate-summary">{String(result.summary || result.reason || (String(step.status) === 'skipped' ? '本次评测未执行质量门禁' : '—'))}</div><div className="rj-gate-label">违规项 · {violations.length}</div>{violations.length ? violations.map((entry, index) => {
    const item = entry && typeof entry === 'object' ? entry as JsonRecord : {description: String(entry)}
    const evidence = Array.isArray(item.evidence) ? item.evidence as JsonRecord[] : []
    return <div className="rj-violation" key={index}><div className="rj-violation-title">{String(item.title || item.rule || item.code || `违规项 ${index + 1}`)}</div><div className="rj-violation-body">{String(item.description || item.message || item.reason || item.detail || textValue(item))}</div>{evidence.length ? <div className="rj-evidence-list">{evidence.map((record, evidenceIndex) => <div className="rj-evidence" key={evidenceIndex}>{record.path || record.line ? <div className="rj-evidence-path">{String(record.path || '')}{record.line ? `${record.path ? ':' : '第 '}${record.line}${record.path ? '' : ' 行'}` : ''}</div> : null}{record.excerpt ? <div className="rj-evidence-excerpt">{String(record.excerpt)}</div> : null}</div>)}</div> : null}</div>
  }) : <div className="rj-empty">无违规项</div>}{step.result ? <details className="rj-raw-json"><summary>展开原始 JSON</summary><pre className="rj-pre mt-2">{textValue(result)}</pre></details> : null}</>
}

export function ReverseJudgeDetailModal({competitionId, target, onClose, onTerminal}: {competitionId: number | string; target: RankingSubmissionOverlayTarget | null; onClose: () => void; onTerminal?: () => void}) {
  const open = Boolean(target)
  const url = target ? `/api/ranking/competitions/${competitionId}/submissions/${target.id}/reverse-judge-events` : null
  const {snapshot, streamError} = useRankingEventSnapshot(url, open, onTerminal, true)
  const steps = useMemo(() => Array.isArray(snapshot?.steps) ? snapshot.steps as JsonRecord[] : [], [snapshot?.steps])
  const [activeStep, setActiveStep] = useState('solution_check')
  const [manual, setManual] = useState(false)
  useEffect(() => {setActiveStep('solution_check'); setManual(false)}, [target])
  useEffect(() => setActiveStep((current) => chooseReverseStep(String(snapshot?.status || ''), steps, current, manual)), [manual, snapshot?.status, steps])
  const step = steps.find((item) => String(item.step_key) === activeStep)
  const status = String(snapshot?.status || '')
  const statusLabels: Record<string, string> = {Accepted: '评测完成', Error: '评测异常', Judging: '评测中', Queued: '等待评测', Pending: '待评测'}
  const agentStep = steps.find((item) => String(item.step_key) === 'agent_answer')
  const answerDownloadUrl = target?.answerDownloadUrl || (target ? `/api/ranking/submissions/${target.id}/reverse-agent-answer` : '')
  return <ReactModal open={open} onClose={onClose} id="reverseJudgeDetailModal" labelledBy="reverseJudgeDetailModalLabel" className="ranking-v2-detail" dialogClassName="modal-xl modal-dialog-scrollable">
    <div className="modal-content rj-modal"><div className="modal-header"><div><h5 className="modal-title" id="reverseJudgeDetailModalLabel"><i className="fas fa-list-check me-2 text-warning" />反向评测详情</h5><div className="text-muted small">#{target?.id}{target?.createdAt ? ` · ${target.createdAt}` : ''}</div></div><button type="button" className="btn-close" aria-label="关闭" onClick={onClose} /></div><div className="modal-body"><div className="rj-summary"><span>{streamError || `${statusLabels[status] || status || '正在连接评测进度…'}${snapshot?.error_message ? ` · ${snapshot.error_message}` : ''}`}</span><span className="rj-summary-actions">{agentStep?.answer_available && answerDownloadUrl ? <a className="rj-answer-download" href={answerDownloadUrl} download><i className="fas fa-download" />下载 AI 解答</a> : null}<span className="rj-total">学生得分 <strong>{snapshot?.total_score == null ? '—' : numberValue(snapshot.total_score)}</strong><small>/100</small></span></span></div>
      <div className="rj-tabs mb-3" role="tablist" aria-label="反向评测步骤">{steps.filter(stepVisible).map((item) => {const key = String(item.step_key); const itemStatus = String(item.status || 'pending'); return <button type="button" className={`rj-tab${activeStep === key ? ' active' : ''}`} disabled={itemStatus === 'pending'} onClick={() => {setActiveStep(key); setManual(true)}} key={key}>{reverseStepLabels[key] || key} <span className={`rj-dot${itemStatus === 'running' ? ' running' : itemStatus === 'passed' ? ' ok' : ['failed', 'error'].includes(itemStatus) ? ' err' : itemStatus === 'skipped' ? ' skip' : ''}`} /></button>})}</div>
      {!snapshot ? <div className="text-muted text-center py-5"><MathCurveLoader size="md" label="正在加载…" /></div> : !step ? <div className="rj-empty">暂无步骤数据</div> : String(step.status) === 'running' && activeStep !== 'agent_answer' ? <div className="rj-step-running"><MathCurveLoader iconOnly size="lg" ariaLabel={`${reverseStepLabels[activeStep] || activeStep}正在运行`} /></div> : <div>{step.error_message ? <div className="rj-alert">{String(step.error_message)}</div> : null}{activeStep === 'agent_answer' ? <ExecutionTrace trace={step} /> : activeStep === 'quality_gate' ? <QualityGate step={step} /> : <ReverseResult step={step} title={reverseStepLabels[activeStep] || String(step.title || activeStep)} />}{activeStep !== 'agent_answer' && activeStep !== 'quality_gate' ? <>{step.stdout ? <details className="rj-raw-json"><summary>stdout</summary><pre className="rj-pre mt-2">{String(step.stdout)}</pre></details> : null}{step.stderr ? <details className="rj-raw-json"><summary>stderr</summary><pre className="rj-pre mt-2">{String(step.stderr)}</pre></details> : null}</> : null}</div>}
    </div></div>
  </ReactModal>
}
