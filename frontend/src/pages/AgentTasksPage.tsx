import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useMemo, useRef, useState, type ChangeEvent, type DragEvent, type FormEvent, type KeyboardEvent as ReactKeyboardEvent} from 'react'
import {createPortal} from 'react-dom'
import {useSearchParams} from 'react-router-dom'

import {apiFetch, errorMessage, queryString} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {Identicon} from '../components/Identicon'
import {ModelLogo} from '../components/ModelLogo'
import {Link, useNavigate} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'
import {useDismissibleDropdown} from '../components/useDismissibleDropdown'
import {PendingAttachmentStrip} from './agent/AgentAttachments'
import {agentComposerEnterAction, createAgentMessageId, decimalText, fileIdentity, mergeFiles, multiplyDecimal} from './agent/legacyBehavior'
import {useAutosizeTextarea} from './agent/useAutosizeTextarea'

interface Response extends ApiEnvelope {
  user?: {is_admin?: number}
  agent_sessions: JsonRecord[]
  harnesses: JsonRecord[] | string[]
  endpoints_by_harness: Record<string, JsonRecord[]>
  reasoning_efforts_by_harness: Record<string, Array<JsonRecord | string>>
  preference?: {harness?: string; endpoint_id?: string | number; access_role?: string}
  agent_quota_summary: JsonRecord
  agent_personal_endpoints?: JsonRecord[]
  agent_quota_pending_count?: number
  agent_quota_pending_requests?: JsonRecord[]
  agent_scope?: string
  current_page?: number
  total_pages?: number
  page_numbers?: Array<number | null>
}

interface AgentAdminAccessResponse extends ApiEnvelope {
  requests?: JsonRecord[]
  classes?: JsonRecord[]
}

interface AgentEndpointListResponse extends ApiEnvelope {endpoints?: JsonRecord[]}
interface AgentEndpointTestResponse extends ApiEnvelope {test_token?: string; test?: JsonRecord}
interface AgentLaunchOptionsResponse extends ApiEnvelope {endpoints_by_harness?: Record<string, JsonRecord[]>}
interface AgentQuotaResponse extends ApiEnvelope {summary?: JsonRecord; request?: JsonRecord}

type ChoiceOption = {value: string; label: string; icon?: string; model?: string; personal?: boolean; pricingPeriod?: 'peak' | 'offpeak' | ''}

function harnessIcon(value: string) {
  const normalized = canonicalHarness(value).replaceAll('_', '-')
  const key = ['codex', 'opencode', 'pi'].includes(normalized) ? normalized : 'claude-code'
  return `harness-logo harness-logo--${key}`
}

function harnessLabel(value: unknown) {
  const text = String(value || 'Harness')
  return ({claude_code: 'Claude Code', codex: 'Codex', opencode: 'OpenCode', pi: 'Pi'} as Record<string, string>)[canonicalHarness(text)] || text
}

function AgentClassLogo({item, className}: {item?: JsonRecord; className: string}) {
  const cells = Array.isArray(item?.logo) ? item.logo : Array.isArray((item?.logo as JsonRecord | undefined)?.cells) ? (item?.logo as JsonRecord).cells as unknown[] : []
  if (!cells.length) return <span className={`${className} is-placeholder`} aria-hidden="true" />
  return <span className={className} aria-hidden="true"><svg viewBox="0 0 7 7" focusable="false" shapeRendering="crispEdges">{cells.map((cell, index) => Array.isArray(cell) && cell.length >= 2 ? <rect key={index} x={Number(cell[0]) + 1} y={Number(cell[1]) + 1} width="1" height="1" /> : null)}</svg></span>
}

function AgentAccessQueryError({message, retry, busy}: {message: string; retry: () => void; busy: boolean}) {
  return <div className="agent-access-empty" role="alert"><span>{message}</span><button className="agent-access-secondary" type="button" disabled={busy} onClick={retry}>{busy ? '重试中…' : '重新加载'}</button></div>
}

function Choice({value, label, icon, model, options, onChange, disabled = false, onOpen}: {value: string; label: string; icon: string; model?: string; options: ChoiceOption[]; onChange: (value: string) => void; disabled?: boolean; onOpen?: () => void | Promise<unknown>}) {
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  const selected = options.find((option) => option.value === value)
  const iconNode = (className = icon, modelName?: string) => modelName ? <ModelLogo model={modelName} /> : <i className={className.startsWith('fa-') ? `fas ${className}` : className} />
  const pricingPeriod = selected?.pricingPeriod
  const requestOpen = () => {
    if (disabled) return
    if (!open) void onOpen?.()
    setOpen((current) => !current)
  }
  return <div ref={rootRef} className={`rk-choice agent-choice${open ? ' open' : ''}${selected?.personal ? ' is-personal-endpoint' : ''}`}>
    <input className="rk-choice-value" value={value} readOnly tabIndex={-1} aria-hidden="true" />
    <button type="button" className="rk-choice-trigger" role="combobox" aria-label={label} aria-haspopup="listbox" aria-expanded={open} disabled={disabled} onClick={requestOpen} onKeyDown={(event) => {if (['ArrowDown', 'ArrowUp'].includes(event.key)) {event.preventDefault(); if (!open) requestOpen()}}}><span className="rk-choice-trigger-main">{iconNode(selected?.icon || icon, selected?.model || ((selected?.icon || icon).includes('fa-microchip') ? selected?.label || label : model))}<span>{label}</span>{pricingPeriod ? <span className="agent-endpoint-pricing-period agent-endpoint-pricing-period--trigger" data-pricing-period={pricingPeriod}><i aria-hidden="true" /><span>{pricingPeriod === 'peak' ? '高峰期' : '低谷期'}</span></span> : null}</span><i className="fas fa-chevron-down rk-choice-caret" /></button>
    <div className="rk-choice-menu" role="listbox">{options.map((option) => <button type="button" className={`rk-choice-option${option.value === value ? ' active' : ''}${option.personal ? ' is-personal-endpoint' : ''}`} role="option" aria-selected={option.value === value} onClick={() => {onChange(option.value); setOpen(false)}} key={option.value}><span className="rk-choice-option-main">{iconNode(option.icon || icon, option.model || ((option.icon || icon).includes('fa-microchip') ? option.label : undefined))}<span><span className={option.pricingPeriod ? 'agent-endpoint-option-name' : undefined}><span className="rk-choice-option-name">{option.label}</span>{option.pricingPeriod ? <span className="agent-endpoint-pricing-period" data-pricing-period={option.pricingPeriod}><i aria-hidden="true" /><span>{option.pricingPeriod === 'peak' ? '高峰期' : '低谷期'}</span></span> : null}</span></span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div>
  </div>
}

function PersonalEndpointLayer({endpoint, close, refresh}: {endpoint: JsonRecord | null; close: () => void; refresh: () => Promise<unknown>}) {
  const [form, setForm] = useState<Record<string, string>>(() => ({
    protocol: String(endpoint?.protocol || 'openai'), category: String(endpoint?.category || 'text'), base_url: String(endpoint?.base_url || ''), api_key: '', model: String(endpoint?.model || ''), context_window_tokens: String(endpoint?.context_window_tokens || 384000), max_output_tokens: String(endpoint?.max_output_tokens || 32000),
  }))
  const [thinking, setThinking] = useState(Boolean(endpoint?.thinking_enabled))
  const [testToken, setTestToken] = useState('')
  const [openChoice, setOpenChoice] = useState('')
  const formRef = useRef<HTMLFormElement>(null)
  const titleRef = useRef<HTMLHeadingElement>(null)
  const choiceRef = useDismissibleDropdown<HTMLDivElement>(Boolean(openChoice), () => setOpenChoice(''))
  const payload = () => ({...form, name: form.model, thinking_enabled: thinking && form.category !== 'embedding', thinking_format: thinking && form.category !== 'embedding' ? (form.protocol === 'anthropic' ? 'thinking_type' : 'enable_thinking') : 'none', endpoint_id: endpoint?.id})
  useEffect(() => {
    const element = formRef.current
    const baseUrl = element?.querySelector<HTMLInputElement>('input[type="url"]')
    const maxOutput = element?.querySelectorAll<HTMLInputElement>('input[type="number"]')[1]
    let urlValid = false
    try { urlValid = /^https?:$/.test(new URL(form.base_url).protocol) } catch { urlValid = false }
    baseUrl?.setCustomValidity(form.base_url && !urlValid ? '基础地址必须使用 HTTP 或 HTTPS。' : '')
    maxOutput?.setCustomValidity(Number(form.max_output_tokens) > Number(form.context_window_tokens) ? '单次最大输出不得超过上下文窗口。' : '')
  }, [form.base_url, form.context_window_tokens, form.max_output_tokens])
  const testEndpoint = useMutation({mutationFn: (testedPayload: ReturnType<typeof payload>) => apiFetch<AgentEndpointTestResponse>('/api/agent/endpoints/test', {method: 'POST', body: JSON.stringify(testedPayload)}), onSuccess: (data, testedPayload) => {if (JSON.stringify(payload()) !== JSON.stringify(testedPayload)) return; const tested = data.test || {}; const nextForm = {...form, context_window_tokens: String(tested.context_window_tokens || form.context_window_tokens), max_output_tokens: String(tested.max_output_tokens || form.max_output_tokens)}; setForm(nextForm); setTestToken(String(data.test_token || ''))}})
  const saveEndpoint = useMutation({mutationFn: () => apiFetch<ApiEnvelope>(endpoint ? `/api/agent/endpoints/${String(endpoint.id)}` : '/api/agent/endpoints', {method: endpoint ? 'PUT' : 'POST', body: JSON.stringify({...payload(), test_token: testToken})}), onSuccess: async () => {await refresh(); close()}})
  const set = (key: string, next: string) => {setTestToken(''); setForm((current) => ({...current, [key]: next}))}
  const choice = (key: 'protocol' | 'category', options: ChoiceOption[]) => {const selected = options.find((item) => item.value === form[key]) || options[0]; return <div ref={openChoice === key ? choiceRef : undefined} className={`rk-choice numoj-endpoint-editor__choice${openChoice === key ? ' open' : ''}`}><button className="rk-choice-trigger" type="button" role="combobox" aria-haspopup="listbox" aria-expanded={openChoice === key} onClick={() => setOpenChoice((current) => current === key ? '' : key)}><span className="rk-choice-trigger-main"><i className={`fas ${selected.icon}`} /><span>{selected.label}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button>{openChoice === key ? <div className="rk-choice-menu" role="listbox">{options.map((item) => <button type="button" className={`rk-choice-option${item.value === form[key] ? ' active' : ''}`} role="option" aria-selected={item.value === form[key]} key={item.value} onClick={() => {set(key, item.value); if (key === 'category' && item.value === 'embedding') setThinking(false); setOpenChoice('')}}><span className="rk-choice-option-main"><i className={`fas ${item.icon}`} /><span><span className="rk-choice-option-name">{item.label}</span></span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div> : null}</div>}
  const statusError = testEndpoint.error || saveEndpoint.error
  useEffect(() => {titleRef.current?.focus()}, [])
  useEffect(() => {const escape = (event: globalThis.KeyboardEvent) => {if (event.key === 'Escape') close()}; document.addEventListener('keydown', escape); return () => document.removeEventListener('keydown', escape)}, [close])
  return <section className="agent-access-layer agent-access-layer--endpoint" role="dialog" aria-modal="true" aria-labelledby="agentPersonalEndpoint-title"><button className="agent-access-layer-scrim" type="button" tabIndex={-1} aria-label="关闭端点编辑器" onClick={close} /><form ref={formRef} className="numoj-endpoint-editor numoj-endpoint-editor--layer" autoComplete="off" noValidate onKeyDown={(event) => {if (event.key === 'Escape' && openChoice) {event.preventDefault(); event.stopPropagation(); setOpenChoice('')}}} onSubmit={(event) => {event.preventDefault(); if (formRef.current?.reportValidity() && testToken) saveEndpoint.mutate()}}><header className="numoj-endpoint-editor__header"><div><p>ENDPOINT EDITOR</p><h2 ref={titleRef} id="agentPersonalEndpoint-title" tabIndex={-1}>{endpoint ? `编辑端点 #${String(endpoint.id)}` : '新建端点'}</h2></div><button type="button" className="btn-close" aria-label="关闭" onClick={close} /></header><div className="numoj-endpoint-editor__body"><label className="wide"><span>模型名称</span><input value={form.model} onChange={(event) => set('model', event.target.value)} maxLength={200} required autoComplete="off" /></label><label><span>上下文窗口</span><input value={form.context_window_tokens} onChange={(event) => set('context_window_tokens', event.target.value)} type="number" min={1} max={2147483647} step={1} inputMode="numeric" required /></label><label><span>单次最大输出</span><input value={form.max_output_tokens} onChange={(event) => set('max_output_tokens', event.target.value)} type="number" min={1} max={2147483647} step={1} inputMode="numeric" required /></label><label><span>兼容协议</span>{choice('protocol', [{value: 'openai', label: 'OpenAI 兼容', icon: 'fa-code'}, {value: 'anthropic', label: 'Anthropic 兼容', icon: 'fa-brain'}])}</label><label><span>能力类别</span>{choice('category', [{value: 'text', label: '纯文本', icon: 'fa-font'}, {value: 'omni', label: '全模态', icon: 'fa-layer-group'}, {value: 'vision', label: '视觉理解', icon: 'fa-eye'}, {value: 'embedding', label: 'Embedding', icon: 'fa-vector-square'}])}</label><label className="wide"><span>基础地址</span><input value={form.base_url} onChange={(event) => set('base_url', event.target.value)} type="url" required autoComplete="url" placeholder="https://api.example.com/v1" /></label><label><span>API 密钥</span><input value={form.api_key} onChange={(event) => set('api_key', event.target.value)} type="password" required={!endpoint?.api_key_configured} autoComplete="new-password" placeholder="sk-..." /><small>{endpoint?.api_key_configured ? '留空表示继续使用已保存的密钥。' : '新建端点必须填写 API 密钥。'}</small></label>{form.category !== 'embedding' ? <label><span>思考模式</span><button className="numoj-endpoint-editor__thinking" type="button" role="switch" aria-checked={thinking} onClick={() => {setTestToken(''); setThinking((current) => !current)}}><i /><b>{thinking ? '开启' : '关闭'}</b></button></label> : null}{testEndpoint.isPending || testToken || statusError ? <p className={`numoj-endpoint-editor__result wide${testEndpoint.isPending ? ' is-pending' : testToken ? ' is-ok' : ' is-error'}`} role="status">{testEndpoint.isPending ? '测试中…' : testToken ? `连接成功${testEndpoint.data?.test?.latency_ms != null ? ` · ${String(testEndpoint.data.test.latency_ms)} ms` : ''}${testEndpoint.data?.test?.message ? ` · ${String(testEndpoint.data.test.message)}` : ''}` : errorMessage(statusError)}</p> : null}</div><footer className="numoj-endpoint-editor__footer"><button className="numoj-endpoint-editor__secondary" type="button" onClick={close}>放弃</button><button className="numoj-endpoint-editor__secondary" type="button" disabled={testEndpoint.isPending || saveEndpoint.isPending} onClick={() => {if (formRef.current?.reportValidity()) testEndpoint.mutate(payload())}}><i className="fas fa-vial" />{testEndpoint.isPending ? '测试中…' : '测试'}</button><button className="numoj-endpoint-editor__primary" type="submit" disabled={!testToken || saveEndpoint.isPending}>{saveEndpoint.isPending ? '保存中…' : '保存'}</button></footer></form></section>
}

function AgentAccessControl({data, isAdmin}: {data: Response; isAdmin: boolean}) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [tab, setTab] = useState(isAdmin ? 'reviews' : 'quota')
  const [reason, setReason] = useState('')
  const [reviewAmount, setReviewAmount] = useState<Record<string, string>>({})
  const [reviewNote, setReviewNote] = useState<Record<string, string>>({})
  const [selectedClasses, setSelectedClasses] = useState<string[]>([])
  const [grantAmount, setGrantAmount] = useState('')
  const [classPickerOpen, setClassPickerOpen] = useState(false)
  const classPickerRef = useDismissibleDropdown<HTMLDivElement>(classPickerOpen, () => setClassPickerOpen(false))
  const [classSearch, setClassSearch] = useState('')
  const [endpointEditor, setEndpointEditor] = useState<JsonRecord | null | undefined>(undefined)
  const [deleteEndpoint, setDeleteEndpoint] = useState<JsonRecord | null>(null)
  const openButtonRef = useRef<HTMLButtonElement>(null)
  const modalRef = useRef<HTMLDivElement>(null)
  const modalTitleRef = useRef<HTMLHeadingElement>(null)
  useEffect(() => {
    if (!open) return undefined
    requestAnimationFrame(() => modalTitleRef.current?.focus())
    document.body.classList.add('modal-open')
    return () => {
      document.body.classList.remove('modal-open')
      if (openButtonRef.current?.isConnected) openButtonRef.current.focus()
    }
  }, [open])
  useEffect(() => {
    if (!open) return undefined
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        if (classPickerOpen) {
          setClassPickerOpen(false)
          requestAnimationFrame(() => classPickerRef.current?.querySelector<HTMLButtonElement>('.agent-class-picker-trigger')?.focus())
        } else if (endpointEditor !== undefined) setEndpointEditor(undefined)
        else if (deleteEndpoint) setDeleteEndpoint(null)
        else setOpen(false)
        event.preventDefault()
        return
      }
      if (event.key !== 'Tab' || !modalRef.current) return
      const layer = modalRef.current.querySelector<HTMLElement>('.agent-access-layer')
      const scope = layer || modalRef.current
      const focusable = Array.from(scope.querySelectorAll<HTMLElement>('button:not([disabled]):not([tabindex="-1"]), input:not([disabled]):not([type="hidden"]):not([tabindex="-1"]), textarea:not([disabled]):not([tabindex="-1"]), [tabindex]:not([tabindex="-1"])')).filter((element) => !element.hidden && element.getClientRects().length > 0)
      if (!focusable.length) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      const index = focusable.indexOf(document.activeElement as HTMLElement)
      if (event.shiftKey && index <= 0) {event.preventDefault(); last.focus()}
      else if (!event.shiftKey && (index < 0 || document.activeElement === last)) {event.preventDefault(); first.focus()}
    }
    document.addEventListener('keydown', closeOnEscape)
    return () => document.removeEventListener('keydown', closeOnEscape)
  }, [classPickerOpen, deleteEndpoint, endpointEditor, open])
  useEffect(() => {
    if (deleteEndpoint) requestAnimationFrame(() => document.getElementById('agentPersonalEndpointDeleteTitle')?.focus())
  }, [deleteEndpoint])
  const adminAccess = useQuery({queryKey: ['agent-access', 'admin'], queryFn: () => apiFetch<AgentAdminAccessResponse>('/api/agent/quota/requests/pending'), enabled: open && isAdmin})
  const quotaSummary = useQuery({queryKey: ['agent-access', 'quota'], queryFn: () => apiFetch<AgentQuotaResponse>('/api/agent/quota'), enabled: open && !isAdmin})
  const personalEndpoints = useQuery({queryKey: ['agent-access', 'personal-endpoints'], queryFn: () => apiFetch<AgentEndpointListResponse>('/api/agent/endpoints'), enabled: open})
  const prices = useQuery({queryKey: ['agent-access', 'prices'], queryFn: () => apiFetch<AgentEndpointListResponse>('/api/agent/endpoints/prices'), enabled: open && !isAdmin})
  const pending = adminAccess.data?.requests || data.agent_quota_pending_requests || []
  const quotaClasses = adminAccess.data?.classes || []
  const summary = quotaSummary.data?.summary || data.agent_quota_summary || {}
  const requestQuota = useMutation({mutationFn: () => apiFetch<AgentQuotaResponse>('/api/agent/quota/requests', {method: 'POST', body: JSON.stringify({reason})}), onSuccess: async (payload) => {setReason(''); if (payload.summary) queryClient.setQueryData<AgentQuotaResponse>(['agent-access', 'quota'], {success: true, summary: payload.summary}); await queryClient.invalidateQueries({queryKey: ['agent-tasks']})}})
  const review = useMutation({mutationFn: ({id, action}: {id: number; action: 'approve' | 'reject'}) => apiFetch<ApiEnvelope>(`/api/agent/quota/requests/${id}/review`, {method: 'POST', body: JSON.stringify({action, approved_amount: action === 'approve' ? reviewAmount[String(id)] : '0', review_note: (reviewNote[String(id)] || '').trim()})}), onSuccess: async () => {await Promise.all([queryClient.invalidateQueries({queryKey: ['agent-tasks']}), queryClient.invalidateQueries({queryKey: ['agent-access', 'admin']})])}})
  const grant = useMutation({mutationFn: () => apiFetch<ApiEnvelope>('/api/agent/quota/grants/class-batch', {method: 'POST', body: JSON.stringify({classes: selectedClasses, amount_rmb: grantAmount})}), onSuccess: async () => {setSelectedClasses([]); setGrantAmount(''); await Promise.all([queryClient.invalidateQueries({queryKey: ['agent-tasks']}), queryClient.invalidateQueries({queryKey: ['agent-access', 'admin']})])}})
  const removeEndpoint = useMutation({mutationFn: (id: number) => apiFetch<ApiEnvelope>(`/api/agent/endpoints/${id}`, {method: 'DELETE'}), onSuccess: async () => {setDeleteEndpoint(null); await Promise.all([queryClient.invalidateQueries({queryKey: ['agent-access', 'personal-endpoints']}), queryClient.invalidateQueries({queryKey: ['agent-tasks']})])}})
  const refreshEndpoints = () => Promise.all([queryClient.invalidateQueries({queryKey: ['agent-access', 'personal-endpoints']}), queryClient.invalidateQueries({queryKey: ['agent-tasks']})])
  const endpointItems = personalEndpoints.data?.endpoints || data.agent_personal_endpoints || []
  const selectedClassItems = quotaClasses.filter((item) => selectedClasses.includes(String(item.class_en || item.key || item.id || '')))
  const filteredClasses = quotaClasses.filter((item) => `${String(item.label || item.class_name || item.name || item.class_en)} ${String(item.class_en || item.key || item.id || '')}`.toLowerCase().includes(classSearch.trim().toLowerCase()))
  const selectedUserCount = new Set(selectedClassItems.flatMap((item) => Array.isArray(item.user_ids) ? item.user_ids.map(String) : [])).size || selectedClassItems.reduce((sum, item) => sum + Number(item.user_count || item.student_count || 0), 0)
  const grantTotal = multiplyDecimal(grantAmount || '0', selectedUserCount)
  const pendingRequest = Boolean(summary.pending_request)
  const remaining = Number(summary.remaining_amount)
  const quotaNote = summary.public_enabled === false
    ? '全站 Agent 已暂停，当前不能创建任务或继续会话。'
    : summary.has_account === false
      ? '你还没有平台额度；申请获批后即可使用全站端点。自有端点不受额度限制。'
      : Number.isFinite(remaining) && remaining <= -5
        ? '额度已达到 -5 元，运行中的任务会被系统强制停止。'
        : Number.isFinite(remaining) && remaining < 0
          ? '余额低于 0 元；全站端点已停用，自有端点仍可使用。'
          : ''
  const tabs: Array<{value: string; label: string; icon?: string}> = isAdmin
    ? [{value: 'reviews', label: '申请审核'}, {value: 'grants', label: '批量赠送'}, {value: 'personal', label: '自定义端点'}]
    : [{value: 'quota', label: '额度与申请', icon: 'fa-wallet'}, {value: 'prices', label: '端点价格', icon: 'fa-tags'}, {value: 'personal', label: '自定义端点', icon: 'fa-key'}]
  return createPortal(<aside className="agent-access-control">
    <button ref={openButtonRef} className={`agent-access-fab${isAdmin ? ' agent-access-fab--review' : ''}`} type="button" aria-label={isAdmin ? '审核额度申请' : '查看 Agent 额度'} title={isAdmin ? '额度申请审核' : 'Agent 额度'} onClick={() => setOpen(true)}><i className={`fas ${isAdmin ? 'fa-clipboard-check' : 'fa-wallet'}`} />{isAdmin && Number(data.agent_quota_pending_count || 0) > 0 ? <span className="agent-access-fab-badge">{Number(data.agent_quota_pending_count) > 99 ? '99+' : Number(data.agent_quota_pending_count)}</span> : null}</button>
    {open ? <><div ref={modalRef} className="modal fade show d-block agent-access-modal" role="dialog" aria-modal="true" aria-labelledby="agentAccessModalTitle"><div className="modal-dialog modal-dialog-centered modal-dialog-scrollable"><div className="modal-content">
      <header className="agent-access-modal-header"><div><span>{isAdmin ? 'REQUEST DESK' : 'AGENT WALLET'}</span><h2 ref={modalTitleRef} id="agentAccessModalTitle" tabIndex={-1}>{isAdmin ? '额度申请审核' : '额度与端点'}</h2></div><button type="button" className="btn-close" aria-label="关闭" onClick={() => setOpen(false)} /></header>
      <div className="agent-access-modal-scroll"><nav className={isAdmin ? 'agent-access-admin-tabs' : 'agent-access-user-tabs'} role="tablist" aria-label={isAdmin ? '额度管理' : 'Agent 额度与端点'} onKeyDown={(event) => {if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return; const currentIndex = tabs.findIndex((item) => item.value === tab); let nextIndex = currentIndex; if (event.key === 'Home') nextIndex = 0; else if (event.key === 'End') nextIndex = tabs.length - 1; else nextIndex = (currentIndex + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length; event.preventDefault(); setTab(tabs[nextIndex].value); requestAnimationFrame(() => modalRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[nextIndex]?.focus())}}>{tabs.map((item) => <button type="button" role="tab" className={tab === item.value ? 'is-current' : ''} aria-selected={tab === item.value} tabIndex={tab === item.value ? 0 : -1} onClick={() => setTab(item.value)} key={item.value}>{item.icon ? <i className={`fas ${item.icon}`} /> : null}<span>{item.label}</span></button>)}</nav>
        {isAdmin && tab === 'reviews' ? <section role="tabpanel" aria-label="申请审核"><div className="agent-access-review-summary"><span>等待处理</span><strong><b>{pending.length}</b> 项</strong></div><div className="agent-access-review-list">{adminAccess.isPending ? <div className="agent-access-loading">读取申请中</div> : adminAccess.isError ? <div className="agent-access-empty">{adminAccess.error.message}</div> : pending.length ? pending.map((item) => {const id = String(item.id || item.request_id || ''); const reviewing = review.isPending && String(review.variables?.id || '') === id; return <article className="agent-access-review-card" key={id}><header><div><span className="agent-personal-endpoint-number">额度申请 #{id}</span><h3>{String(item.username || item.user_name || `用户 #${String(item.user_id || '')}`)}</h3></div><div className="agent-access-review-meta"><time>{String(item.created_at || '')}</time></div></header>{item.class_name || item.class_label || item.class_en ? <span className="agent-access-review-class"><i className="fas fa-users" />{String(item.class_name || item.class_label || item.class_en)}</span> : null}<p className="agent-access-review-reason">{String(item.reason || '未填写申请理由')}</p><form className="agent-access-review-form" onSubmit={(event) => {event.preventDefault(); review.mutate({id: Number(id), action: 'approve'})}}><label className="agent-access-field"><span>赠送额度</span><span className="agent-access-input-shell agent-access-money-input"><b>¥</b><input type="number" min="0.01" step="0.01" inputMode="decimal" placeholder="0.00" aria-label="赠送额度" required disabled={reviewing} value={reviewAmount[id] || ''} onChange={(event) => setReviewAmount((current) => ({...current, [id]: event.target.value}))} /></span></label><label className="agent-access-field"><span>审核意见</span><span className="agent-access-input-shell"><i className="fas fa-pen" /><input maxLength={1000} placeholder="可选" aria-label="审核意见" disabled={reviewing} value={reviewNote[id] || ''} onChange={(event) => setReviewNote((current) => ({...current, [id]: event.target.value}))} /></span></label><div className="agent-access-review-actions"><button type="submit" disabled={!reviewAmount[id] || reviewing}>通过申请</button><button type="button" disabled={reviewing} onClick={() => review.mutate({id: Number(id), action: 'reject'})}>驳回</button></div></form></article>}) : <div className="agent-access-empty">没有待审核申请</div>}</div></section> : null}
        {isAdmin && tab === 'grants' ? <section className="agent-class-grant-panel" role="tabpanel" aria-label="批量赠送">
          <header><span>CLASS GRANT</span><h3>按班级赠送额度</h3></header>
          <form onSubmit={(event) => {event.preventDefault(); if (selectedClasses.length && selectedUserCount && Number(grantAmount) > 0) grant.mutate()}} noValidate>
            <fieldset className="agent-class-grant-fieldset"><legend>选择班级</legend><div ref={classPickerRef} className={`agent-class-picker${classPickerOpen ? ' is-open' : ''}`}>
              <button type="button" className="agent-class-picker-trigger" aria-haspopup="listbox" aria-expanded={classPickerOpen} onClick={() => setClassPickerOpen((current) => !current)} disabled={!quotaClasses.length}><AgentClassLogo className="agent-class-picker-logo" item={selectedClassItems[0]} /><span className="agent-class-picker-current"><strong>{selectedClasses.length ? `已选择 ${selectedClasses.length} 个班级` : '选择班级'}</strong><small>{selectedClasses.length ? selectedClasses.join(' · ') : 'MULTIPLE SELECT'}</small></span><i className="fas fa-chevron-down agent-class-picker-caret" /></button>
              {classPickerOpen ? <div className="agent-class-picker-panel" role="listbox" aria-label="选择班级" aria-multiselectable="true"><label className="agent-class-picker-search agent-access-input-shell"><i className="fas fa-magnifying-glass" /><input type="search" placeholder="搜索班级" autoComplete="off" spellCheck={false} aria-label="搜索班级" value={classSearch} onChange={(event) => setClassSearch(event.target.value)} /></label><div className="agent-class-grant-options">{filteredClasses.map((item) => {const key = String(item.class_en || item.key || item.id || ''); const selected = selectedClasses.includes(key); return <label className={`agent-class-option${selected ? ' is-selected' : ''}`} key={key}><input className="agent-class-checkbox" type="checkbox" name="classes" value={key} checked={selected} onChange={(event) => setSelectedClasses((current) => event.target.checked ? [...current, key] : current.filter((value) => value !== key))} /><AgentClassLogo className="agent-class-option-logo" item={item} /><span className="agent-class-option-copy"><strong>{String(item.label || item.class_name || item.name || item.class_en || '未命名班级')}</strong><small>{key}</small></span><span className="agent-class-option-state" aria-hidden="true"><i className="fas fa-check" /></span></label>})}</div><div className="agent-class-picker-empty" hidden={Boolean(filteredClasses.length)}>无匹配班级</div><footer className="agent-class-picker-footer"><button type="button" onClick={() => setSelectedClasses((current) => [...new Set([...current, ...filteredClasses.map((item) => String(item.class_en || item.key || item.id || ''))])])}>全选</button><button type="button" onClick={() => setSelectedClasses([])}>清空</button><button type="button" className="is-done" onClick={() => {setClassPickerOpen(false); requestAnimationFrame(() => classPickerRef.current?.querySelector<HTMLButtonElement>('.agent-class-picker-trigger')?.focus())}}>完成</button></footer></div> : null}
            </div></fieldset>
            <label className="agent-class-grant-amount agent-access-field"><span>每人赠送</span><span className="agent-access-input-shell agent-access-money-input"><b>¥</b><input name="amount_rmb" type="number" min="0.01" step="0.01" inputMode="decimal" required placeholder="0.00" value={grantAmount} onChange={(event) => setGrantAmount(event.target.value)} /></span></label>
            <dl className="agent-class-grant-preview" aria-live="polite"><div><dt>去重用户</dt><dd><b>{selectedUserCount}</b> 人</dd></div><div><dt>赠送总额</dt><dd>{grantTotal ? `${grantTotal} 元` : '—'}</dd></div></dl>
            <button type="submit" disabled={!selectedClasses.length || !selectedUserCount || !grantAmount || Number(grantAmount) <= 0 || grant.isPending}>确认赠送</button>
          </form>{grant.isError ? <p className="agent-access-feedback is-error">{errorMessage(grant.error)}</p> : null}
        </section> : null}
        {!isAdmin && tab === 'quota' ? <section>{summary.public_enabled === false ? <div className="agent-access-public-notice"><i className="fas fa-pause-circle" /><div><strong>Agent 暂停向普通用户开放</strong><span>已有会话仍可查看，但不能申请额度、创建任务或继续对话。</span></div></div> : null}<section className="agent-access-balance" aria-labelledby="agentBalanceTitle"><header><span>ACCOUNT</span><h3 id="agentBalanceTitle">额度概览</h3></header><dl><div><dt>已用额度</dt><dd>{decimalText(summary.used_amount) || '0'} 元</dd></div><div className={`is-remaining${Number.isFinite(remaining) && remaining < 0 ? ' is-negative' : ''}`}><dt>剩余额度</dt><dd>{decimalText(summary.remaining_amount) || '0'} 元</dd></div></dl>{quotaNote ? <p className="agent-access-balance-note">{quotaNote}</p> : null}</section><section className="agent-access-section"><header><div><span>REQUEST</span><h3>申请额度</h3></div>{pendingRequest ? <span className="agent-access-status">申请审核中</span> : null}</header><form className="agent-quota-request-form" onSubmit={(event) => {event.preventDefault(); if (summary.public_enabled !== false && !pendingRequest) requestQuota.mutate()}}><label className="agent-access-field agent-quota-request-reason"><span>申请理由</span><span className="agent-access-input-shell is-textarea"><textarea name="reason" rows={3} maxLength={1000} required placeholder="简要说明你准备让 Agent 完成什么任务" disabled={summary.public_enabled === false || pendingRequest || requestQuota.isPending} value={reason} onChange={(event) => setReason(event.target.value)} /></span></label><button className="agent-access-primary agent-quota-request-submit" type="submit" disabled={summary.public_enabled === false || pendingRequest || !reason.trim() || requestQuota.isPending}><span>提交申请</span><i className="fas fa-arrow-right" /></button></form>{requestQuota.isError ? <p className="agent-access-feedback">{errorMessage(requestQuota.error)}</p> : null}</section></section> : null}
        {tab === 'prices' ? <section role="tabpanel" aria-label="端点价格" data-agent-user-panel="prices"><div className="agent-access-panel-intro"><div><span>RATE CARD</span><h3>全站端点价格</h3></div><p>使用全站端点时按实际 Token 实时结算，以下价格单位均为元 / 1M Token。</p></div><div className="agent-rate-list">{prices.isPending ? <div className="agent-access-loading">读取价格中</div> : prices.isError ? <div className="agent-access-empty">{prices.error.message}</div> : (prices.data?.endpoints || []).length ? (prices.data?.endpoints || []).map((item) => <article className="agent-rate-card" key={String(item.id)}><header className="agent-rate-card-header"><span className="agent-rate-logo"><ModelLogo model={item.model} /></span><div className="agent-rate-card-name"><strong title={String(item.model || '')}>{String(item.model || '未命名模型')}</strong><small>{String(item.protocol || 'openai') === 'anthropic' ? 'Anthropic 兼容' : 'OpenAI 兼容'}</small>{item.peak_pricing_enabled ? <span className="agent-rate-pricing-period" data-pricing-period={item.pricing_period === 'peak' ? 'peak' : 'offpeak'}><i aria-hidden="true" /><span>{item.pricing_period === 'peak' ? '高峰期' : '低谷期'}</span></span> : null}</div></header><dl className="agent-rate-values" aria-label="节点价格，人民币每百万 Token"><div className="agent-rate-value"><dt>INPUT</dt><dd>{decimalText(item.input_price_per_million) || '—'}</dd></div><div className="agent-rate-value"><dt>CACHED</dt><dd>{decimalText(item.cached_input_price_per_million) || '—'}</dd></div><div className="agent-rate-value"><dt>OUTPUT</dt><dd>{decimalText(item.output_price_per_million) || '—'}</dd></div></dl></article>) : <div className="agent-access-empty">暂无可用的全站端点</div>}</div></section> : null}
        {tab === 'personal' ? <section className="agent-personal-endpoints" role="tabpanel" aria-label="自定义端点" data-agent-admin-panel={isAdmin ? 'personal' : undefined} data-agent-user-panel={isAdmin ? undefined : 'personal'}><header className="agent-personal-endpoints-heading"><div><span>BRING YOUR OWN KEY</span><h3>自定义端点</h3><p>自有端点使用你的 API 密钥，不消耗平台额度。</p></div><button className="agent-access-secondary is-strong" type="button" onClick={() => setEndpointEditor(null)}><i className="fas fa-plus" />新建端点</button></header><div className="agent-personal-endpoint-list">{personalEndpoints.isPending ? <div className="agent-access-loading">读取端点中</div> : personalEndpoints.isError ? <div className="agent-access-empty">{personalEndpoints.error.message}</div> : endpointItems.length ? endpointItems.map((item) => {const id = String(item.id || item.endpoint_id || ''); const name = String(item.name || item.label || item.model || '自定义端点'); return <article className="agent-personal-endpoint-card" key={id}><div className="agent-personal-endpoint-main"><div className="agent-personal-endpoint-top"><div><span className="agent-personal-endpoint-number">自有节点 #{id}</span><h3 className="agent-personal-endpoint-title"><ModelLogo model={item.model || name} /><span title={name}>{name}</span></h3></div><span className="agent-personal-endpoint-chip">{String(item.protocol || 'openai') === 'anthropic' ? 'Anthropic 兼容' : 'OpenAI 兼容'}</span></div><div className="agent-personal-endpoint-url"><small>模型 · {String(item.model || '未命名')}</small><span title={String(item.base_url || '')}>{String(item.base_url || '未配置地址')}</span></div></div><footer className="agent-personal-endpoint-foot"><span className="agent-personal-endpoint-state"><i />{item.api_key_configured === false ? '密钥未配置' : '密钥已配置'}</span><button type="button" title="编辑" aria-label={`编辑 ${name}`} onClick={() => setEndpointEditor(item)}><i className="fas fa-pen" /></button><button className="is-danger" type="button" title="删除" aria-label={`删除 ${name}`} onClick={() => setDeleteEndpoint(item)}><i className="fas fa-trash-alt" /></button></footer></article>}) : null}</div>{removeEndpoint.isError ? <p className="agent-access-feedback is-error">{errorMessage(removeEndpoint.error)}</p> : null}</section> : null}
        {adminAccess.isError && tab === 'reviews' ? <AgentAccessQueryError message="申请列表读取失败" retry={() => void adminAccess.refetch()} busy={adminAccess.isFetching} /> : null}
        {quotaSummary.isError && tab === 'quota' ? <AgentAccessQueryError message="额度刷新失败，当前显示的是进入页面时的数据。" retry={() => void quotaSummary.refetch()} busy={quotaSummary.isFetching} /> : null}
        {prices.isError && tab === 'prices' ? <AgentAccessQueryError message="价格列表读取失败" retry={() => void prices.refetch()} busy={prices.isFetching} /> : null}
        {personalEndpoints.isError && tab === 'personal' ? <AgentAccessQueryError message="自定义端点读取失败" retry={() => void personalEndpoints.refetch()} busy={personalEndpoints.isFetching} /> : null}
        {review.isError ? <p className="agent-access-feedback">{errorMessage(review.error)}</p> : null}
      </div>
      {endpointEditor !== undefined ? <PersonalEndpointLayer endpoint={endpointEditor} close={() => setEndpointEditor(undefined)} refresh={refreshEndpoints} /> : null}
      {deleteEndpoint ? <section className="agent-access-layer is-compact" role="alertdialog" aria-modal="true" aria-labelledby="agentPersonalEndpointDeleteTitle"><button className="agent-access-layer-scrim" type="button" tabIndex={-1} aria-label="取消删除" onClick={() => setDeleteEndpoint(null)} /><div className="agent-access-layer-panel"><div className="agent-endpoint-delete-body"><span className="agent-endpoint-delete-icon"><i className="fas fa-trash-alt" /></span><div><span>DELETE ENDPOINT</span><h2 id="agentPersonalEndpointDeleteTitle" tabIndex={-1}>删除自定义端点？</h2></div><p>将删除 <strong>{String(deleteEndpoint.name || deleteEndpoint.model || '这个端点')}</strong>。已有会话仍可查看，但不能再通过它继续运行。</p>{removeEndpoint.isError ? <p className="agent-access-feedback is-error">{errorMessage(removeEndpoint.error)}</p> : null}</div><footer className="agent-endpoint-delete-footer"><button className="agent-access-secondary" type="button" onClick={() => setDeleteEndpoint(null)}>保留端点</button><button className="agent-access-danger-button" type="button" disabled={removeEndpoint.isPending} onClick={() => removeEndpoint.mutate(Number(deleteEndpoint.id))}>确认删除</button></footer></div></section> : null}
    </div></div></div><div className="modal-backdrop fade show" onClick={() => setOpen(false)} /></> : null}
  </aside>, document.body)
}

function canonicalHarness(value: string) {const normalized = value.trim().toLowerCase().replaceAll('-', '_'); return normalized === 'open_code' ? 'opencode' : normalized}
function endpointValue(item: JsonRecord) {return String(item.ref || item.choice_value || item.value || item.id || item.endpoint_id || '')}
function personalEndpoint(item: JsonRecord) {return item.is_personal === true || item.scope === 'user' || item.owner_type === 'user' || item.source === 'user' || endpointValue(item).startsWith('user:')}
function endpointsFor(catalog: Record<string, JsonRecord[]>, harness: string) {
  const canonical = canonicalHarness(harness)
  const source = catalog[harness] || catalog[canonical] || catalog[canonical.replaceAll('_', '-')] || []
  return [...source].sort((left, right) => Number(personalEndpoint(right)) - Number(personalEndpoint(left)))
}
function effortsFor(mapping: Response['reasoning_efforts_by_harness'] | undefined, harness: string) {
  const canonical = canonicalHarness(harness)
  return (mapping?.[harness] || mapping?.[canonical] || mapping?.[canonical.replaceAll('_', '-')] || []).map((item) => typeof item === 'string'
    ? {value: item, label: item}
    : {value: String(item.value || ''), label: String(item.label || item.value || '')})
}

export default function AgentTasksPage() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const page = Math.max(1, Number(searchParams.get('page') || 1))
  const requestedScope = searchParams.get('scope') || ''
  const result = useQuery({queryKey: ['agent-tasks', page, requestedScope], queryFn: () => apiFetch<Response>(`/api/agent/sessions${queryString({page, scope: requestedScope || undefined})}`)})
  const [message, setMessage] = useState(() => searchParams.get('problem_id') ? `${searchParams.get('mode') === 'testdata' ? '为题目生成测试数据' : '求解题目'} #${searchParams.get('problem_id')}` : '')
  const [harness, setHarness] = useState('')
  const [endpointId, setEndpointId] = useState('')
  const [reasoningSelections, setReasoningSelections] = useState<Record<string, string>>({})
  const [accessRole, setAccessRole] = useState('')
  const [attachments, setAttachments] = useState<File[]>([])
  const [endpointCatalog, setEndpointCatalog] = useState<Record<string, JsonRecord[]>>({})
  const [endpointRefreshError, setEndpointRefreshError] = useState('')
  const [dragging, setDragging] = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const attemptRef = useRef({id: '', fingerprint: ''})
  useAutosizeTextarea(textareaRef, message, 104, 280)
  useEffect(() => {if (result.data?.endpoints_by_harness) setEndpointCatalog(result.data.endpoints_by_harness)}, [result.data?.endpoints_by_harness])

  const harnesses = useMemo(() => (result.data?.harnesses || []).map((item) => {
    const value = typeof item === 'string' ? item : String(item.value || item.id || item.name || '')
    return {value, label: typeof item === 'string' ? item : String(item.label || item.name || item.value || ''), icon: harnessIcon(value)}
  }), [result.data?.harnesses])
  const preferredHarness = String(result.data?.preference?.harness || '')
  const fallbackHarness = harnesses.find((item) => endpointsFor(endpointCatalog, item.value).length)?.value || harnesses[0]?.value || ''
  const selectedHarness = harness || (harnesses.some((item) => item.value === preferredHarness) ? preferredHarness : fallbackHarness)
  const endpoints = endpointsFor(endpointCatalog, selectedHarness)
  const preferredEndpoint = String(result.data?.preference?.endpoint_id || '')
  const selectedEndpoint = endpoints.some((item) => endpointValue(item) === endpointId)
    ? endpointId
    : endpoints.some((item) => endpointValue(item) === preferredEndpoint) ? preferredEndpoint : endpointValue(endpoints[0] || {})
  const selectedEndpointItem = endpoints.find((item) => endpointValue(item) === selectedEndpoint)
  const effortOptions = effortsFor(result.data?.reasoning_efforts_by_harness, selectedHarness)
  const rememberedEffort = reasoningSelections[canonicalHarness(selectedHarness)] || ''
  const selectedEffort = !effortOptions.length ? '' : effortOptions.some((item) => item.value === rememberedEffort)
    ? rememberedEffort
    : String(effortOptions.find((item) => item.value === 'high')?.value || effortOptions[0]?.value || '')
  const isAdmin = Number(result.data?.user?.is_admin || 0) === 1
  const selectedRole = accessRole || String(result.data?.preference?.access_role || 'user')
  const quota = result.data?.agent_quota_summary || {}
  const publicEnabled = quota.public_enabled !== false
  const quotaCanStart = quota.can_start !== false
  const quotaHasAccount = quota.has_account !== false
  const accessAllowed = isAdmin || (publicEnabled && Boolean(selectedEndpointItem) && (personalEndpoint(selectedEndpointItem || {}) || quotaCanStart))
  const accessNote = !isAdmin && !publicEnabled
    ? 'Agent 暂停向普通用户开放；已有会话仍可查看。'
    : !isAdmin && selectedEndpointItem && !personalEndpoint(selectedEndpointItem) && !quotaCanStart
      ? quotaHasAccount
        ? '余额低于 0 元，不能使用全站端点。你仍可从右下角申请额度，或选择自己的端点。'
        : '你还没有平台额度。请从右下角申请额度，或选择自己的端点。'
      : ''

  const create = useMutation({
    mutationFn: () => {
      const fingerprint = JSON.stringify([message.trim(), selectedHarness, selectedEndpoint, selectedEffort, isAdmin ? selectedRole : 'user', attachments.map(fileIdentity)])
      if (!attemptRef.current.id || attemptRef.current.fingerprint !== fingerprint) attemptRef.current = {id: createAgentMessageId('msg'), fingerprint}
      const form = new FormData()
      form.append('message', message)
      form.append('harness', selectedHarness)
      form.append('endpoint_id', selectedEndpoint)
      form.append('reasoning_effort', selectedEffort)
      form.append('access_role', isAdmin ? selectedRole : 'user')
      form.append('message_id', attemptRef.current.id)
      attachments.forEach((file) => form.append('attachments', file, file.name))
      return apiFetch<ApiEnvelope & {session_id?: string; detail_url?: string}>('/api/agent/sessions', {method: 'POST', body: form})
    },
    onSuccess: async (data) => {
      attemptRef.current = {id: '', fingerprint: ''}
      setMessage('')
      setAttachments([])
      await queryClient.invalidateQueries({queryKey: ['agent-tasks']})
      if (data.detail_url) navigate(data.detail_url)
      else if (data.session_id) navigate(`/agents/${encodeURIComponent(data.session_id)}`)
    },
  })

  const refreshEndpoints = async () => {
    try {
      const payload = await apiFetch<AgentLaunchOptionsResponse>('/api/agent/launch-options?task_kind=custom')
      if (payload.endpoints_by_harness) setEndpointCatalog(payload.endpoints_by_harness)
      setEndpointRefreshError('')
    } catch {
      setEndpointRefreshError('刷新模型节点失败，已保留当前列表。')
    }
  }
  const canCreate = Boolean(message.trim() && selectedHarness && selectedEndpoint && (!effortOptions.length || selectedEffort) && accessAllowed)
  const submit = (event: FormEvent<HTMLFormElement>) => {event.preventDefault(); if (canCreate && !create.isPending) create.mutate()}
  const keyDown = (event: ReactKeyboardEvent<HTMLTextAreaElement>) => {
    if (!agentComposerEnterAction({key: event.key, keyCode: event.keyCode, composing: event.nativeEvent.isComposing, shiftKey: event.shiftKey, ctrlKey: event.ctrlKey, metaKey: event.metaKey, running: false})) return
    event.preventDefault()
    if (canCreate && !create.isPending) event.currentTarget.form?.requestSubmit()
  }
  const chooseAttachments = (event: ChangeEvent<HTMLInputElement>) => {
    setAttachments((current) => mergeFiles(current, event.target.files || []))
    event.target.value = ''
  }
  const dragFiles = (event: DragEvent<HTMLFormElement>, active: boolean) => {
    if (!event.dataTransfer.types.includes('Files')) return
    event.preventDefault()
    event.dataTransfer.dropEffect = 'copy'
    setDragging(active)
  }
  const dropFiles = (event: DragEvent<HTMLFormElement>) => {
    dragFiles(event, false)
    setAttachments((current) => mergeFiles(current, event.dataTransfer.files))
  }

  if (result.isPending) return <LoadingState label="正在读取 Agent 会话" />
  if (result.isError) return <ErrorState message={result.error.message} retry={() => void result.refetch()} />
  const sessions = result.data?.agent_sessions || []
  const scope = result.data?.agent_scope || (isAdmin ? 'all' : 'mine')
  const currentPage = Number(result.data?.current_page || page)
  const totalPages = Number(result.data?.total_pages || 1)
  const pages = result.data?.page_numbers || []
  const controlsDisabled = create.isPending || (!isAdmin && !publicEnabled)

  return <><main className="agent-home" data-agent-home>
    <section className="agent-home-hero" aria-labelledby="agentHomeTitle"><div className="agent-home-heading"><span className="agent-home-kicker">NUMERICAL OJ · AGENT</span><h1 id="agentHomeTitle">今天想让 Agent 做什么？</h1></div><form className={`agent-composer${create.isPending ? ' is-submitting' : ''}${dragging ? ' is-dragging' : ''}`} onSubmit={submit} onDragEnter={(event) => dragFiles(event, true)} onDragOver={(event) => dragFiles(event, true)} onDragLeave={(event) => {if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false)}} onDrop={dropFiles} autoComplete="off"><label className="visually-hidden" htmlFor="agentMessage">任务内容</label><textarea ref={textareaRef} id="agentMessage" name="message" rows={4} maxLength={100000} placeholder="让 Agent 分析问题、编写代码或整理文件…" aria-keyshortcuts="Enter Shift+Enter Control+Enter Meta+Enter" value={message} onChange={(event) => setMessage(event.target.value)} onKeyDown={keyDown} disabled={controlsDisabled} required /><PendingAttachmentStrip files={attachments} remove={(index) => setAttachments((items) => items.filter((_, itemIndex) => itemIndex !== index))} /><div className="agent-composer-footer"><div className="agent-composer-controls" aria-label="任务运行设置"><div className="agent-composer-choice agent-composer-choice--harness"><Choice value={selectedHarness} label={harnesses.find((item) => item.value === selectedHarness)?.label || '选择 Harness'} icon={harnessIcon(selectedHarness)} options={harnesses} disabled={controlsDisabled || !harnesses.length} onChange={(value) => {setHarness(value); setEndpointId('')}} /></div><div className="agent-composer-choice agent-composer-choice--endpoint"><Choice value={selectedEndpoint} label={String(selectedEndpointItem?.model || (endpoints.length ? '选择模型节点' : ''))} icon="fa-microchip" options={endpoints.map((item) => ({value: endpointValue(item), label: String(item.model || item.label || item.name || ''), model: String(item.model || item.label || item.name || ''), personal: personalEndpoint(item), pricingPeriod: item.peak_pricing_enabled ? item.pricing_period === 'peak' ? 'peak' : 'offpeak' : ''}))} onChange={setEndpointId} onOpen={refreshEndpoints} disabled={controlsDisabled} /></div>{effortOptions.length ? <div className="agent-composer-choice agent-composer-choice--effort"><Choice value={selectedEffort} label={effortOptions.find((item) => item.value === selectedEffort)?.label || '选择思考深度'} icon="agent-effort-logo agent-effort-logo--choice" options={effortOptions} disabled={controlsDisabled} onChange={(value) => setReasoningSelections((current) => ({...current, [canonicalHarness(selectedHarness)]: value}))} /></div> : null}{isAdmin ? <div className="agent-composer-choice agent-composer-choice--role"><Choice value={selectedRole} label={selectedRole === 'admin' ? '以管理员身份' : '以用户身份'} icon={selectedRole === 'admin' ? 'fa-user-shield' : 'fa-user'} options={[{value: 'user', label: '以用户身份', icon: 'fa-user'}, {value: 'admin', label: '以管理员身份', icon: 'fa-user-shield'}]} onChange={setAccessRole} disabled={create.isPending} /></div> : null}</div><div className="agent-composer-actions"><label className="agent-icon-button" title="添加附件" aria-label="添加附件"><input ref={fileInputRef} className="visually-hidden" type="file" multiple onChange={chooseAttachments} disabled={controlsDisabled} /><i className="fas fa-plus" /></label><button className="agent-send-button" type="submit" disabled={!canCreate || create.isPending} aria-label="创建 Agent 会话" title="创建会话">{create.isPending ? <span className="spinner-border spinner-border-sm" aria-hidden="true" /> : <i className="fas fa-arrow-up" />}</button></div></div>{!endpoints.length ? <p className="agent-composer-feedback is-error" role="status">该 Harness 暂无兼容的模型节点。</p> : null}{endpointRefreshError ? <p className="agent-composer-feedback is-error" role="status">{endpointRefreshError}</p> : null}{create.isError ? <p className="agent-composer-feedback is-error" role="alert">{errorMessage(create.error)}</p> : null}{accessNote ? <p className="agent-composer-access-note is-error" role="status">{accessNote}</p> : null}</form></section>
    <section className="agent-history" aria-labelledby="agentHistoryTitle"><header className="agent-history-heading"><div><span className="agent-history-kicker">RECENT WORK</span><h2 id="agentHistoryTitle">历史会话</h2></div>{isAdmin ? <nav className="agent-history-scope" aria-label="会话范围"><Link to="/agents?scope=all" className={scope !== 'mine' ? 'is-current' : ''} aria-current={scope !== 'mine' ? 'page' : undefined}>全站会话</Link><Link to="/agents?scope=mine" className={scope === 'mine' ? 'is-current' : ''} aria-current={scope === 'mine' ? 'page' : undefined}>我的会话</Link></nav> : <span>按最近更新排序</span>}</header><div className="agent-history-list">{sessions.map((session, index) => {const actor = String(session.requested_by || session.created_by || 'numericaloj'); const id = String(session.session_id || session.task_id || index); const status = String(session.status || '').toLowerCase(); const runtime = String(session.harness || ''); const title = String(session.title || '未命名任务'); const harnessTitle = harnessLabel(session.harness_label || session.harness); const endpointTitle = String(session.endpoint_model || session.model || '模型节点'); return <Link className="agent-history-row" to={`/agents/${encodeURIComponent(id)}`} key={id} aria-label={`打开会话：${title}`}><Identicon seed={actor} className="agent-history-avatar" /><span className="agent-history-main"><strong title={title}>{title}</strong><small><span>{actor}</span><time>{String(session.updated_at || session.created_at || '')}</time>{['running', 'pending'].includes(status) ? <span className="agent-history-live"><i />运行中</span> : null}</small></span><span className="agent-history-runtime agent-history-runtime--harness" title={`Harness：${harnessTitle}`}><i className={harnessIcon(runtime)} /><span>{harnessTitle}</span></span><span className="agent-history-runtime" title={`模型节点：${endpointTitle}`}><ModelLogo model={session.endpoint_model || session.model} /><span>{endpointTitle}</span></span><i className="fas fa-chevron-right agent-history-arrow" /></Link>})}{!sessions.length ? <div className="agent-history-empty"><span className="agent-history-empty-mark"><i className="fas fa-terminal" /></span><strong>还没有会话</strong><p>从上面的输入框开始，Agent 的工作记录会留在这里。</p></div> : null}</div>{totalPages > 1 ? <nav className="agent-history-pagination" aria-label="历史会话分页">{currentPage > 1 ? <Link to={`/agents${queryString({page: currentPage - 1, scope})}`} aria-label="上一页"><i className="fas fa-arrow-left" /></Link> : null}{pages.map((pageNumber, index) => pageNumber ? <Link to={`/agents${queryString({page: pageNumber, scope})}`} className={pageNumber === currentPage ? 'is-current' : ''} aria-current={pageNumber === currentPage ? 'page' : undefined} key={pageNumber}>{pageNumber}</Link> : <span aria-hidden="true" key={`gap-${index}`}>…</span>)}{currentPage < totalPages ? <Link to={`/agents${queryString({page: currentPage + 1, scope})}`} aria-label="下一页"><i className="fas fa-arrow-right" /></Link> : null}</nav> : null}</section>
  </main><AgentAccessControl data={result.data} isAdmin={isAdmin} /></>
}
