import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useMemo, useState} from 'react'
import {useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, CompetitionSummary, JsonRecord} from '../api/types'
import {MarkdownContent} from '../components/MarkdownContent'
import {ErrorState, LoadingState} from '../components/PageState'
import {Link, useNavigate} from '../components/PageNavigation'
import {useRuleTopology} from '../ranking/ruleTopology'

type AppealResponse = ApiEnvelope & {
  competition: CompetitionSummary
  appeal: JsonRecord
  submission?: JsonRecord
  snapshot?: JsonRecord
  rendered_snapshot?: JsonRecord
}

type Rule = JsonRecord & {
  rule_id: number
  rule_name?: string
  rule_text?: string
  rule_html?: string
  evidence?: string
  evidence_html?: string
  value?: number
  score?: number
  effective?: string
  dependencies?: number[]
}

const order = ['pass', 'failed', 'skipped']
const badges: Record<string, {label: string; color: string; background: string}> = {
  pass: {label: '通过', color: '#1f7a4d', background: 'rgba(34,197,94,0.14)'},
  failed: {label: '未通过', color: '#b03a2e', background: 'rgba(220,53,69,0.14)'},
  skipped: {label: '依赖跳过', color: '#6c757d', background: 'rgba(108,117,125,0.14)'},
  error: {label: '异常', color: '#b07340', background: 'rgba(224,151,97,0.18)'},
  pending: {label: '待评测', color: '#0d6efd', background: 'rgba(13,110,253,0.10)'},
}

function numberValue(value: unknown) {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric : 0
}

function formatNumber(value: unknown) {
  return String(Math.round(numberValue(value) * 100) / 100)
}

function legacyRuleValue(value: unknown) {
  const numeric = numberValue(value)
  return Number.isInteger(numeric) ? numeric.toFixed(1) : String(numeric)
}

function compact(value: unknown, length: number) {
  const text = String(value || '').replace(/\s+/g, ' ').trim()
  if (!text) return '未填写规则内容'
  return text.length > length ? `${text.slice(0, length)}…` : text
}

function ruleTitle(rule: Rule) {
  return String(rule.rule_name || '').trim() || compact(rule.rule_text, 14)
}

function AppealTopology({rules, effective, openRule}: {rules: Rule[]; effective: (rule: Rule) => string; openRule: (ruleId: number) => void}) {
  const [focus, setFocus] = useState<{ruleId?: number; edgeKey?: string} | null>(null)
  const {engine, layout, edges, routes} = useRuleTopology(rules, {nodeWidth: 176, nodeHeight: 96, marginX: 24, marginY: 20, columnGap: 88, rowGap: 72, slotPadding: 46, maxSlotStep: 18})
  if (!rules.length) return <div className="ap-topo-empty">暂无评分规则或评测结果。</div>
  if (!layout) return <div className="ap-topo-empty text-danger">当前依赖存在环，无法生成拓扑图。</div>
  const edgeParts = focus?.edgeKey?.split(':') || []
  return <div className="ap-topo-stage" style={{width: Math.ceil(layout.width), height: Math.ceil(layout.height)}}><div className={`ap-topo-surface${focus ? ' has-focus' : ''}`} style={{width: layout.width, height: layout.height}}><svg className="ap-topo-svg" width={layout.width} height={layout.height} viewBox={`0 0 ${layout.width} ${layout.height}`}>{edges.map((edge) => {
    const key = engine.edgeKey(edge.from, edge.to)
    const route = routes[key]
    if (!route) return null
    const active = focus?.edgeKey === key || focus?.ruleId === edge.from || focus?.ruleId === edge.to
    return <g key={key}><path className={`ap-topo-edge${active ? ' edge-active' : ''}`} d={engine.edgePath(route)} data-edge-key={key} data-edge-from={edge.from} data-edge-to={edge.to} /><polygon className={`ap-topo-arrow${active ? ' edge-active' : ''}`} points={`${route.x2} ${route.arrowTipY} ${route.x2 - 5} ${route.y2} ${route.x2 + 5} ${route.y2}`} data-edge-key={key} data-edge-from={edge.from} data-edge-to={edge.to} /><path className="ap-topo-edge-hit" d={engine.edgePath(route)} onMouseEnter={() => setFocus({edgeKey: key})} onMouseLeave={() => setFocus(null)} /></g>
  })}</svg>{rules.map((rule) => {
    const id = numberValue(rule.rule_id)
    const position = layout.positions[id]
    const state = effective(rule)
    const badge = badges[state] || badges.pending
    const score = state === 'pass' ? numberValue(rule.value) : 0
    const active = focus?.ruleId === id || edgeParts.includes(String(id))
    return <button type="button" className={`ap-topo-node s-${state}${active ? ' node-active' : ''}`} title={String(rule.rule_text || '未填写规则内容')} style={{left: position.x, top: position.y}} onMouseEnter={() => setFocus({ruleId: id})} onMouseLeave={() => setFocus(null)} onFocus={() => setFocus({ruleId: id})} onBlur={() => setFocus(null)} onClick={() => openRule(id)} key={id}><span className="ap-topo-node-id">规则 {id} · {formatNumber(rule.value)} 分</span><span className="ap-topo-node-title">{ruleTitle(rule)}</span><span className="ap-topo-node-text">{compact(rule.rule_text, 42)}</span><span className="ap-topo-node-foot"><span className="ap-topo-status" style={{color: badge.color, background: badge.background}}>{badge.label}</span><span className="ap-topo-score">{formatNumber(score)}/{formatNumber(rule.value)}</span></span></button>
  })}</div></div>
}

export default function RankingAppealReviewPage() {
  const {competitionId = '', appealId = ''} = useParams()
  const navigate = useNavigate()
  const result = useQuery({
    queryKey: ['ranking-appeal-review', competitionId, appealId],
    queryFn: () => apiFetch<AppealResponse>(`/api/ranking/competitions/${competitionId}/appeals/${appealId}/review`),
  })
  const [overrides, setOverrides] = useState<Record<string, string>>({})
  const [reply, setReply] = useState('')
  const [view, setView] = useState<'topo' | 'detail'>('topo')
  const [popupRuleId, setPopupRuleId] = useState<number | null>(null)
  useEffect(() => {
    if (result.data?.appeal.admin_response != null) setReply(String(result.data.appeal.admin_response))
    if (result.data?.appeal.submission_id) document.title = `申诉处理 · 提交 #${result.data.appeal.submission_id} - Numerical OJ`
  }, [result.data?.appeal.admin_response, result.data?.appeal.submission_id])
  const rules = useMemo(() => {
    const rendered = result.data?.rendered_snapshot?.rules
    const raw = Array.isArray(rendered) ? rendered : result.data?.snapshot?.rules
    return (Array.isArray(raw) ? raw : []) as Rule[]
  }, [result.data?.rendered_snapshot?.rules, result.data?.snapshot?.rules])
  const effective = (rule: Rule) => overrides[String(rule.rule_id)] || String(rule.effective || 'pending')
  const total = rules.reduce((sum, rule) => sum + (effective(rule) === 'pass' ? numberValue(rule.value) : 0), 0)
  const maxScore = rules.reduce((sum, rule) => sum + numberValue(rule.value), 0)
  const popupRule = popupRuleId == null ? null : rules.find((rule) => numberValue(rule.rule_id) === popupRuleId) || null
  const commit = useMutation({
    mutationFn: (decision: 'rejected' | 'resolved') => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${competitionId}/appeals/${appealId}`, {method: 'POST', body: JSON.stringify({decision, admin_response: reply, overrides})}),
    onSuccess: () => navigate(`/rankings/${competitionId}?tab=appeals`),
  })
  const rejudge = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${competitionId}/submissions/${result.data?.appeal.submission_id}/rejudge`, {method: 'POST'}),
    onSuccess: () => navigate(`/rankings/${competitionId}?tab=all_submissions`),
  })

  if (result.isPending) return <LoadingState label="正在加载申诉" />
  if (result.isError) return <ErrorState message={errorMessage(result.error)} retry={() => void result.refetch()} />
  const data = result.data
  const appeal = data.appeal
  return <section className="appeal-review-page">
    <div className="ap-head d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3"><div><Link to={`/rankings/${competitionId}?tab=appeals`} className="btn btn-sm btn-outline-secondary"><i className="fas fa-arrow-left me-1" />返回申诉列表</Link>{' '}<span className="ms-2 fw-semibold"><i className="fas fa-gavel me-2 text-warning" />申诉处理</span>{' '}<span className="text-muted ms-2 small">提交 #{String(appeal.submission_id)} · {String(appeal.username || '')}</span></div><div className="small text-muted">申诉时间：{String(appeal.created_at || '')}</div></div>
    <div className="ap-grid"><div className="ap-left"><div className="ap-left-head d-flex justify-content-between align-items-center mb-2"><span className="fw-semibold"><i className="fas fa-list-check me-2 text-warning" />评分详情</span><span className="small text-muted">得分 <span className="fw-semibold">{formatNumber(total)}</span> / <span>{formatNumber(maxScore)}</span></span></div><div className="ap-view-head mb-2"><div className="ap-view-tabs" role="tablist" aria-label="申诉评分视图"><button type="button" className={`ap-view-tab${view === 'topo' ? ' active' : ''}`} role="tab" aria-selected={view === 'topo'} onClick={() => setView('topo')}>拓扑</button><button type="button" className={`ap-view-tab${view === 'detail' ? ' active' : ''}`} role="tab" aria-selected={view === 'detail'} onClick={() => setView('detail')}>详情</button></div><span className="small text-muted">点击拓扑节点查看规则原文与评分证据；改判请切到详情视图。</span></div>
      <div className="ap-view" hidden={view !== 'topo'}><div className="ap-topo-canvas"><AppealTopology rules={rules} effective={effective} openRule={setPopupRuleId} /></div></div>
      <div className="ap-view" hidden={view !== 'detail'}><div className="small text-muted mb-2">点击规则左侧状态标签可切换 <b>通过 → 未通过 → 依赖跳过</b>；改动暂存，<b>点击右侧「驳回」或「处理」后才写入</b>。</div><div>{rules.length ? rules.map((rule) => {const state = effective(rule); const badge = badges[state] || badges.pending; return <div className={`ap-rule border rounded p-3 mb-2${overrides[String(rule.rule_id)] ? ' dirty' : ''}`} data-rule-id={rule.rule_id} data-value={numberValue(rule.value)} data-eff={state} key={rule.rule_id}><div className="d-flex justify-content-between align-items-start gap-3"><div><button type="button" className="badge ap-rule-status me-2" title="点击切换：通过 → 未通过 → 依赖跳过" style={{color: badge.color, background: badge.background, borderRadius: 999}} onClick={() => {const current = order.includes(state) ? order.indexOf(state) : -1; setOverrides((values) => ({...values, [String(rule.rule_id)]: order[(current + 1) % order.length]}))}}>{badge.label}</button><strong>规则 {rule.rule_id}</strong>{rule.rule_name ? <span className="text-muted small">{rule.rule_name}</span> : null}<span className="text-muted small">({legacyRuleValue(rule.value)} 分)</span><MarkdownContent html={String(rule.rule_html || rule.rule_text || '')} className="aj-md small mt-1" /></div><div className="text-end fw-semibold ap-rule-score">{formatNumber(state === 'pass' ? rule.value : 0)} 分</div></div>{rule.evidence_html || rule.evidence ? <details className="mt-2"><summary className="small text-muted">评分证据</summary><MarkdownContent html={String(rule.evidence_html || rule.evidence)} className="aj-md aj-evi small p-2 mt-1 mb-0" /></details> : null}</div>}) : <div className="text-muted text-center py-5">暂无评分规则或评测结果。</div>}</div></div>
    </div><aside className="ap-right"><div className="ap-right-inner"><div className="fw-semibold mb-2"><i className="fas fa-comment-dots me-2 text-primary" />用户申诉意见</div><div className="ap-reason mb-3">{String(appeal.reason || '')}</div>{String(appeal.status || 'pending') !== 'pending' ? <div className="ap-current-status small text-muted mb-3">当前状态：<b>{appeal.status === 'rejected' ? '已驳回' : appeal.status === 'resolved' ? '已处理' : String(appeal.status)}</b>{appeal.admin_username ? `（处理人：${appeal.admin_username}）` : ''}</div> : null}<label className="form-label small text-muted mb-1" htmlFor="appealReply">回复意见</label><textarea id="appealReply" className="form-control mb-3" rows={5} placeholder="给该同学的处理说明…" value={reply} onChange={(event) => setReply(event.target.value)} /><div className="d-flex gap-2 mb-2"><button type="button" className="btn btn-outline-danger flex-fill" disabled={commit.isPending} onClick={() => commit.mutate('rejected')}><i className="fas fa-ban me-1" />驳回</button><button type="button" className="btn btn-success flex-fill" disabled={commit.isPending} onClick={() => commit.mutate('resolved')}><i className="fas fa-check me-1" />处理</button></div>{commit.isError ? <div className="ap-commit-error small text-danger mb-2">{errorMessage(commit.error)}</div> : null}<div className="small text-muted mb-3">「驳回」「处理」都会把左侧暂存的规则改动写入数据库。</div><button type="button" className="btn btn-outline-secondary w-100" disabled={rejudge.isPending} onClick={() => {if (window.confirm(`确认重新评测提交 #${appeal.submission_id}？\n将清空当前评分结果并重新跑 Agent 评测。`)) rejudge.mutate()}}><i className="fas fa-rotate me-1" />{rejudge.isPending ? '重测中…' : '重测'}</button>{rejudge.isSuccess ? <div className="small text-success mt-2">已提交重测任务</div> : null}{rejudge.isError ? <div className="small text-danger mt-2">{errorMessage(rejudge.error)}</div> : null}</div></aside></div>
    {popupRule ? (() => {const state = effective(popupRule); const badge = badges[state] || badges.pending; return <div className="ap-rule-pop" role="presentation" onMouseDown={(event) => {if (event.target === event.currentTarget) setPopupRuleId(null)}}><div className="ap-rule-pop-box" role="dialog" aria-modal="true" aria-labelledby="apRulePopupTitle"><div className="ap-rule-pop-head"><div><div className="ap-rule-pop-title" id="apRulePopupTitle">规则 {popupRule.rule_id} · {ruleTitle(popupRule)}</div><div className="ap-rule-pop-meta"><span className="badge me-2" style={{color: badge.color, background: badge.background, borderRadius: 999}}>{badge.label}</span><span>得分 {formatNumber(state === 'pass' ? popupRule.value : 0)} / {formatNumber(popupRule.value)}</span></div></div><button type="button" className="ap-rule-pop-close" aria-label="关闭" onClick={() => setPopupRuleId(null)}><i className="fas fa-times" /></button></div><div className="ap-rule-pop-body"><div className="ap-rule-pop-section"><div className="ap-rule-pop-label">规则原文</div><MarkdownContent html={String(popupRule.rule_html || popupRule.rule_text || '')} className="aj-md small" /></div><div className="ap-rule-pop-section"><div className="ap-rule-pop-label">评分证据</div>{popupRule.evidence_html || popupRule.evidence ? <MarkdownContent html={String(popupRule.evidence_html || popupRule.evidence)} className="aj-md aj-evi small p-2" /> : <span className="text-muted">暂无评分证据。</span>}</div></div></div></div>})() : null}
  </section>
}
