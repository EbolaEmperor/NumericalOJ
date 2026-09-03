import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useCallback, useEffect, useRef, useState, type FormEvent} from 'react'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {ModelLogo} from '../components/ModelLogo'
import {ErrorState, LoadingState} from '../components/PageState'
import {useDismissibleDropdown} from '../components/useDismissibleDropdown'
import {useSession} from '../session'

interface ItemsResponse extends ApiEnvelope {endpoints?: JsonRecord[]; bindings?: JsonRecord[]; settings?: JsonRecord}
interface EndpointTestResponse extends ApiEnvelope {test_token?: string; test?: JsonRecord; context_window_tokens?: number; max_output_tokens?: number; limits_adjusted?: boolean}
interface ServiceTestResponse extends ApiEnvelope {test?: JsonRecord}
interface AgentAccessResponse extends ApiEnvelope {enabled?: boolean; public_enabled?: boolean; agent_public_enabled?: boolean; settings?: JsonRecord}
interface AgentConcurrencyResponse extends ApiEnvelope {limit?: number; applied?: boolean; settings?: JsonRecord}
const unlockConfirmation = '我已阅读上述内容，我清楚后果，我坚持要解锁'
type ProtectionTarget = {kind: 'endpoint' | 'binding'; item: JsonRecord}
type ToastNotice = {id: number; message: string; tone: 'success' | 'error'}
type Notify = (message: string, tone?: ToastNotice['tone']) => void

function value(item: JsonRecord | undefined, key: string, fallback = '') {return String(item?.[key] ?? fallback)}
function endpointIdentity(endpoint: JsonRecord) {
  const model = String(endpoint.model || '未命名模型')
  const id = Number(endpoint.id)
  return Number.isSafeInteger(id) && id > 0 ? `${model}（节点 #${id}）` : model
}
function existingEndpointPayload(endpoint: JsonRecord): JsonRecord {
  return {
    endpoint_id: Number(endpoint.id),
    protocol: endpoint.protocol,
    category: endpoint.category,
    base_url: endpoint.base_url,
    api_key: '',
    model: endpoint.model,
    context_window_tokens: endpoint.context_window_tokens,
    max_output_tokens: endpoint.max_output_tokens,
    thinking_enabled: Boolean(endpoint.thinking_enabled),
    thinking_format: endpoint.thinking_format,
    input_price_per_million: String(endpoint.input_price_per_million ?? ''),
    cached_input_price_per_million: String(endpoint.cached_input_price_per_million ?? ''),
    output_price_per_million: String(endpoint.output_price_per_million ?? ''),
    peak_pricing_enabled: Boolean(endpoint.peak_pricing_enabled),
    peak_time_ranges: endpoint.peak_time_ranges || '',
    peak_input_price_per_million: String(endpoint.peak_input_price_per_million ?? ''),
    peak_cached_input_price_per_million: String(endpoint.peak_cached_input_price_per_million ?? ''),
    peak_output_price_per_million: String(endpoint.peak_output_price_per_million ?? ''),
  }
}
const protocolLabels: Record<string, string> = {openai: 'OpenAI 兼容', anthropic: 'Anthropic 兼容'}
const categoryLabels: Record<string, string> = {omni: '全模态', text: '纯文本', vision: '视觉理解', embedding: 'Embedding'}
function moneyText(raw: unknown) {
  let text = String(raw ?? '').trim()
  if (!text) return '—'
  if (/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(text)) {
    text = text.replace(/^([+-]?)0+(?=\d)/, '$1')
    if (text.includes('.')) text = text.replace(/0+$/, '').replace(/\.$/, '')
    if (['-0', '+0', ''].includes(text)) text = '0'
  }
  return `${text} 元`
}

function ConfigChoice({value: selectedValue, label, options, onChange, variant = 'endpoint', disabled = false}: {value: string; label: string; options: {value: string; label: string; icon: string}[]; onChange: (next: string) => void; variant?: 'endpoint' | 'feature'; disabled?: boolean}) {
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  const selected = options.find((item) => item.value === selectedValue) || options[0]
  const choiceIcon = (item: {label: string; icon: string}) => item.icon === 'fa-microchip' ? <ModelLogo model={item.label} /> : <i className={`fas ${item.icon}`} />
  return <div ref={rootRef} className={`rk-choice ${variant === 'feature' ? 'site-config-choice' : 'numoj-endpoint-editor__choice'}${open ? ' open' : ''}${disabled ? ' is-disabled' : ''}`}><button className="rk-choice-trigger" type="button" role="combobox" aria-haspopup="listbox" aria-expanded={open} aria-label={label} disabled={disabled} onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main">{choiceIcon(selected)}<span>{selected.label}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox" hidden={!open}>{options.map((item) => <button type="button" className={`rk-choice-option${item.value === selectedValue ? ' active' : ''}`} role="option" aria-selected={item.value === selectedValue} key={item.value} onClick={() => {onChange(item.value); setOpen(false)}}><span className="rk-choice-option-main">{choiceIcon(item)}<span><span className="rk-choice-option-name">{item.label}</span></span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div></div>
}

function SiteConfigToast({notice}: {notice: ToastNotice | null}) {
  if (!notice) return null
  return <div className="site-config-toast-region" aria-live={notice.tone === 'error' ? 'assertive' : 'polite'} aria-atomic="true"><div className={`site-config-toast${notice.tone === 'error' ? ' is-error' : ''}`} role={notice.tone === 'error' ? 'alert' : 'status'} key={notice.id}><i className={`fas ${notice.tone === 'error' ? 'fa-exclamation-circle' : 'fa-check-circle'}`} aria-hidden="true" /><span>{notice.message}</span></div></div>
}

function ServiceForm({kind, settings, refresh, notify}: {kind: 'mail' | 'web-search'; settings?: JsonRecord; refresh: () => Promise<unknown>; notify: Notify}) {
  const isMail = kind === 'mail'
  const configured = Boolean(settings && Object.keys(settings).length)
  const formRef = useRef<HTMLFormElement>(null)
  const formFromSettings = (next?: JsonRecord): Record<string, string> => isMail
    ? {smtp_server: value(next, 'smtp_server'), smtp_port: value(next, 'smtp_port', '465'), smtp_username: value(next, 'smtp_username'), smtp_password: ''}
    : {base_url: value(next, 'base_url'), authorization: ''}
  const [form, setForm] = useState<Record<string, string>>(() => {
    return formFromSettings(settings)
  })
  const valid = () => Boolean(formRef.current?.reportValidity())
  const save = useMutation({
    mutationFn: () => apiFetch<ItemsResponse>(`/api/admin/dynamic-config/${kind}`, {method: 'PUT', body: JSON.stringify(form)}),
    onSuccess: async (data) => {setForm(formFromSettings(data.settings)); await refresh(); notify(isMail ? '邮件配置已保存' : '联网搜索配置已保存')},
    onError: (error) => notify(errorMessage(error), 'error'),
  })
  const test = useMutation({
    mutationFn: () => apiFetch<ServiceTestResponse>(`/api/admin/dynamic-config/${kind}/test`, {method: 'POST', body: JSON.stringify(form)}),
    onSuccess: (data) => {
      const result = (data.test || data) as JsonRecord
      const latency = result.latency_ms != null ? `（${String(result.latency_ms)} ms）` : ''
      notify(`${isMail ? '测试邮件已发送' : '搜索服务连接正常'}${latency}`)
    },
    onError: (error) => notify(errorMessage(error), 'error'),
  })
  const clear = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(`/api/admin/dynamic-config/${kind}`, {method: 'DELETE'}),
    onSuccess: async () => {setForm(formFromSettings()); await refresh(); notify(`${isMail ? '邮件' : '联网搜索'}配置已清除`)},
    onError: (error) => notify(errorMessage(error), 'error'),
  })
  const set = (key: string, next: string) => setForm((current) => ({...current, [key]: next}))
  const busy = save.isPending || test.isPending || clear.isPending
  return <form
    ref={formRef}
    className="site-config-feature-card site-config-service-card"
    aria-label={`${isMail ? '邮件服务' : '联网搜索'}配置`}
    autoComplete="off"
    onSubmit={(event: FormEvent) => {event.preventDefault(); if (valid()) save.mutate()}}
  >
    <span className="site-config-feature-icon"><i className={`fas ${isMail ? 'fa-envelope' : 'fa-globe'}`} /></span>
    <div className="site-config-feature-copy site-config-service-copy">
      <div className="site-config-feature-head">
        <h3>{isMail ? '邮件服务' : '联网搜索'}</h3>
        <span className={`site-config-service-state${configured ? ' is-configured' : ''}`}>{configured ? '已配置' : '未配置'}</span>
      </div>
      <div className="site-config-form-grid">
        {isMail ? <>
          <label><span>SMTP 服务器</span><input required value={form.smtp_server} onChange={(event) => set('smtp_server', event.target.value)} /></label>
          <label><span>端口</span><input required type="number" min={1} max={65535} value={form.smtp_port} onChange={(event) => set('smtp_port', event.target.value)} /></label>
          <label><span>用户名</span><input required value={form.smtp_username} onChange={(event) => set('smtp_username', event.target.value)} /></label>
          <label><span>密码</span><input type="password" value={form.smtp_password} onChange={(event) => set('smtp_password', event.target.value)} placeholder={settings?.password_configured ? '留空保持原密码' : ''} /></label>
        </> : <>
          <label className="wide"><span>服务地址</span><input required type="url" value={form.base_url} onChange={(event) => set('base_url', event.target.value)} /></label>
          <label className="wide"><span>认证信息</span><input type="password" value={form.authorization} onChange={(event) => set('authorization', event.target.value)} placeholder={settings?.authorization_configured ? '留空保持原认证信息' : ''} /></label>
        </>}
      </div>
      <footer className="site-config-service-actions">
        <button className="site-config-danger-ghost" type="button" disabled={!configured || busy} onClick={() => {if (window.confirm(`确定清除整组${isMail ? '邮件' : '联网搜索'}配置？`)) clear.mutate()}}>清除</button>
        <span className="site-config-action-spacer" />
        <button className="site-config-secondary" type="button" disabled={busy} onClick={() => {if (valid()) test.mutate()}}><i className={`fas ${isMail ? 'fa-paper-plane' : 'fa-satellite-dish'}`} />{test.isPending ? (isMail ? '发送中…' : '测试中…') : '测试'}</button>
        <button className="site-config-primary" type="submit" disabled={busy}>{save.isPending ? '保存中…' : '保存'}</button>
      </footer>
    </div>
  </form>
}

function EndpointDialog({endpoint, close, refresh}: {endpoint: JsonRecord | null; close: () => void; refresh: () => Promise<unknown>}) {
  const [form, setForm] = useState<Record<string, string>>(() => ({
    protocol: value(endpoint || undefined, 'protocol', 'openai'), category: value(endpoint || undefined, 'category', 'omni'), base_url: value(endpoint || undefined, 'base_url'), api_key: '', model: value(endpoint || undefined, 'model'), context_window_tokens: value(endpoint || undefined, 'context_window_tokens', '384000'), max_output_tokens: value(endpoint || undefined, 'max_output_tokens', '32000'), input_price_per_million: value(endpoint || undefined, 'input_price_per_million'), cached_input_price_per_million: value(endpoint || undefined, 'cached_input_price_per_million'), output_price_per_million: value(endpoint || undefined, 'output_price_per_million'), peak_time_ranges: value(endpoint || undefined, 'peak_time_ranges'), peak_input_price_per_million: value(endpoint || undefined, 'peak_input_price_per_million'), peak_cached_input_price_per_million: value(endpoint || undefined, 'peak_cached_input_price_per_million'), peak_output_price_per_million: value(endpoint || undefined, 'peak_output_price_per_million'),
  }))
  const [thinking, setThinking] = useState(Boolean(endpoint?.thinking_enabled))
  const [peakPricing, setPeakPricing] = useState(Boolean(endpoint?.peak_pricing_enabled))
  const [testToken, setTestToken] = useState('')
  useEffect(() => {
    window.requestAnimationFrame(() => {
      const active = document.activeElement
      if (active instanceof HTMLInputElement && active.closest('.numoj-endpoint-editor')) active.blur()
    })
  }, [])
  useEffect(() => {
    const element = document.querySelector<HTMLFormElement>('.numoj-endpoint-editor')
    const baseUrl = element?.querySelector<HTMLInputElement>('input[type="url"]')
    const maxOutput = element?.querySelectorAll<HTMLInputElement>('input[type="number"]')[1]
    let urlValid = false
    try { urlValid = /^https?:$/.test(new URL(form.base_url).protocol) } catch { urlValid = false }
    baseUrl?.setCustomValidity(form.base_url && !urlValid ? '基础地址必须使用 HTTP 或 HTTPS。' : '')
    maxOutput?.setCustomValidity(Number(form.max_output_tokens) > Number(form.context_window_tokens) ? '单次最大输出不得超过上下文窗口。' : '')
  }, [form.base_url, form.context_window_tokens, form.max_output_tokens])
  const payload = () => ({...Object.fromEntries(Object.entries(form).filter(([, item]) => item !== '')), thinking_enabled: thinking && form.category !== 'embedding', thinking_format: thinking && form.category !== 'embedding' ? (form.protocol === 'anthropic' ? 'thinking_type' : 'enable_thinking') : 'none', peak_pricing_enabled: peakPricing})
  const requireValidForm = () => {
    const element = document.querySelector<HTMLFormElement>('.numoj-endpoint-editor')
    if (!element?.reportValidity()) throw new Error('请先修正表单中的无效字段')
  }
  const test = useMutation({
    mutationFn: () => {requireValidForm(); return apiFetch<EndpointTestResponse>('/api/admin/dynamic-config/llm-endpoints/test', {method: 'POST', body: JSON.stringify({...payload(), endpoint_id: endpoint?.id})})},
    onSuccess: (data) => {
      const tested = (data.test || data) as JsonRecord
      setForm((current) => ({...current, ...(tested.context_window_tokens != null ? {context_window_tokens: String(tested.context_window_tokens)} : {}), ...(tested.max_output_tokens != null ? {max_output_tokens: String(tested.max_output_tokens)} : {})}))
      setTestToken(String(data.test_token || tested.test_token || ''))
    },
  })
  const save = useMutation({mutationFn: () => {requireValidForm(); return apiFetch<ApiEnvelope>(endpoint ? `/api/admin/dynamic-config/llm-endpoints/${endpoint.id}` : '/api/admin/dynamic-config/llm-endpoints', {method: endpoint ? 'PUT' : 'POST', body: JSON.stringify({...payload(), test_token: testToken})})}, onSuccess: async () => {await refresh(); close()}})
  const set = (key: string, next: string) => {setTestToken(''); setForm((current) => ({...current, [key]: next}))}
  const toggleThinking = () => {setTestToken(''); setThinking((current) => !current)}
  const togglePeak = () => {setTestToken(''); setPeakPricing((current) => !current)}
  return <><div className="modal fade show d-block numoj-endpoint-editor-modal" role="dialog" aria-modal="true" aria-labelledby="endpointDialogTitle"><div className="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><form className="numoj-endpoint-editor modal-content" autoComplete="off" noValidate onSubmit={(event) => {event.preventDefault(); if (testToken) save.mutate()}}><header className="numoj-endpoint-editor__header"><div><p>ENDPOINT EDITOR</p><h2 id="endpointDialogTitle">{endpoint ? `编辑端点 #${endpoint.id}` : '新建端点'}</h2></div><button type="button" className="btn-close" aria-label="关闭" onClick={close} /></header><div className="numoj-endpoint-editor__body"><label className="wide"><span>模型名称</span><input value={form.model} onChange={(event) => set('model', event.target.value)} maxLength={200} required autoComplete="off" autoFocus /></label><label><span>上下文窗口</span><input value={form.context_window_tokens} onChange={(event) => set('context_window_tokens', event.target.value)} type="number" min={1} max={2147483647} step={1} inputMode="numeric" required /></label><label><span>单次最大输出</span><input value={form.max_output_tokens} onChange={(event) => set('max_output_tokens', event.target.value)} type="number" min={1} max={2147483647} step={1} inputMode="numeric" required /></label><label><span>兼容协议</span><ConfigChoice value={form.protocol} label="兼容协议" onChange={(next) => set('protocol', next)} options={[{value: 'openai', label: 'OpenAI 兼容', icon: 'fa-code'}, {value: 'anthropic', label: 'Anthropic 兼容', icon: 'fa-brain'}]} /></label><label><span>能力类别</span><ConfigChoice value={form.category} label="能力类别" onChange={(next) => {set('category', next); if (next === 'embedding') setThinking(false)}} options={[{value: 'omni', label: '全模态', icon: 'fa-layer-group'}, {value: 'text', label: '纯文本', icon: 'fa-font'}, {value: 'vision', label: '视觉理解', icon: 'fa-eye'}, {value: 'embedding', label: 'Embedding', icon: 'fa-vector-square'}]} /></label><label className="wide"><span>基础地址</span><input value={form.base_url} onChange={(event) => set('base_url', event.target.value)} type="url" required autoComplete="url" placeholder="https://api.example.com/v1" /></label><label><span>API 密钥</span><input value={form.api_key} onChange={(event) => set('api_key', event.target.value)} type="password" required={!endpoint?.api_key_configured} autoComplete="new-password" placeholder="sk-..." /><small>{endpoint?.api_key_configured ? '留空则保留现有 API 密钥。' : '新建端点必须填写 API 密钥。'}</small></label>{form.category !== 'embedding' ? <label><span>思考模式</span><button className="numoj-endpoint-editor__thinking" type="button" role="switch" aria-checked={thinking} onClick={toggleThinking}><i /><b>{thinking ? '开启' : '关闭'}</b></button></label> : null}<div className="numoj-endpoint-editor__prices wide"><label><span>输入单价（RMB / 1M Token）</span><input value={form.input_price_per_million} onChange={(event) => set('input_price_per_million', event.target.value)} type="number" min={0} step="any" inputMode="decimal" required /></label><label><span>缓存命中单价（RMB / 1M Token）</span><input value={form.cached_input_price_per_million} onChange={(event) => set('cached_input_price_per_million', event.target.value)} type="number" min={0} step="any" inputMode="decimal" required /></label><label><span>输出单价（RMB / 1M Token）</span><input value={form.output_price_per_million} onChange={(event) => set('output_price_per_million', event.target.value)} type="number" min={0} step="any" inputMode="decimal" required /></label></div><section className="numoj-endpoint-editor__peak-pricing wide"><div className="numoj-endpoint-editor__peak-head"><div><span>峰谷计费</span><small>关闭时始终使用上方单价；高峰时间按 UTC+8 计算。</small></div><button className="numoj-endpoint-editor__peak-toggle" type="button" role="switch" aria-checked={peakPricing} onClick={togglePeak}><i /><b>{peakPricing ? '开启' : '关闭'}</b></button></div>{peakPricing ? <div className="numoj-endpoint-editor__peak-fields"><label className="wide"><span>高峰时间（UTC+8）</span><input value={form.peak_time_ranges} onChange={(event) => set('peak_time_ranges', event.target.value)} maxLength={1024} autoComplete="off" placeholder="9:00-12:00, 14:00-18:00" required /><small>使用 - 表示区间，多个区间用英文逗号隔开；忽略空格。</small></label><label><span>高峰期 INPUT（RMB / 1M Token）</span><input value={form.peak_input_price_per_million} onChange={(event) => set('peak_input_price_per_million', event.target.value)} type="number" min={0} step="any" inputMode="decimal" required /></label><label><span>高峰期 CACHED（RMB / 1M Token）</span><input value={form.peak_cached_input_price_per_million} onChange={(event) => set('peak_cached_input_price_per_million', event.target.value)} type="number" min={0} step="any" inputMode="decimal" required /></label><label><span>高峰期 OUTPUT（RMB / 1M Token）</span><input value={form.peak_output_price_per_million} onChange={(event) => set('peak_output_price_per_million', event.target.value)} type="number" min={0} step="any" inputMode="decimal" required /></label></div> : null}</section>{test.isPending || test.isSuccess || test.isError || save.isError ? <p className={`numoj-endpoint-editor__result wide${test.isPending ? ' is-pending' : test.isSuccess ? ' is-ok' : ' is-error'}`} role="status">{test.isPending ? '正在测试端点…' : test.isSuccess ? '连接测试成功，可以保存。' : errorMessage(test.error || save.error)}</p> : null}</div><footer className="numoj-endpoint-editor__footer"><button className="numoj-endpoint-editor__secondary" type="button" onClick={close}>放弃</button><button className="numoj-endpoint-editor__secondary" type="button" onClick={() => test.mutate()} disabled={test.isPending || save.isPending}><i className="fas fa-vial" />{test.isPending ? '测试中…' : '测试'}</button><button className="numoj-endpoint-editor__primary" type="submit" disabled={!testToken || save.isPending}>{save.isPending ? '保存中…' : '保存'}</button></footer></form></div></div><div className="modal-backdrop fade show" /></>
}

export default function SiteConfigPage() {
  const {session} = useSession()
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<'endpoints' | 'features'>('endpoints')
  const [railOpen, setRailOpen] = useState(false)
  const [endpointDialog, setEndpointDialog] = useState<JsonRecord | null | undefined>(undefined)
  const [lockTarget, setLockTarget] = useState<ProtectionTarget | null>(null)
  const [lockReason, setLockReason] = useState('')
  const [unlockTarget, setUnlockTarget] = useState<ProtectionTarget | null>(null)
  const [unlockPassword, setUnlockPassword] = useState('')
  const [unlockText, setUnlockText] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<JsonRecord | null>(null)
  const [concurrencyDraft, setConcurrencyDraft] = useState('8')
  const [notice, setNotice] = useState<ToastNotice | null>(null)
  const noticeTimer = useRef<number | null>(null)
  const noticeSequence = useRef(0)
  const notify = useCallback<Notify>((message, tone = 'success') => {
    if (noticeTimer.current != null) window.clearTimeout(noticeTimer.current)
    noticeSequence.current += 1
    setNotice({id: noticeSequence.current, message, tone})
    noticeTimer.current = window.setTimeout(() => {
      noticeTimer.current = null
      setNotice(null)
    }, tone === 'error' ? 6500 : 3500)
  }, [])
  useEffect(() => () => {
    if (noticeTimer.current != null) window.clearTimeout(noticeTimer.current)
  }, [])
  useEffect(() => {
    if (!lockTarget && !unlockTarget && !deleteTarget) return
    const timer = window.setTimeout(() => {
      const active = document.activeElement
      if (active instanceof HTMLElement) active.blur()
    }, 50)
    return () => window.clearTimeout(timer)
  }, [deleteTarget, lockTarget, unlockTarget])
  const endpoints = useQuery({queryKey: ['admin', 'dynamic-config', 'endpoints'], queryFn: () => apiFetch<ItemsResponse>('/api/admin/dynamic-config/llm-endpoints'), enabled: Boolean(session?.user?.is_admin)})
  const bindings = useQuery({queryKey: ['admin', 'dynamic-config', 'bindings'], queryFn: () => apiFetch<ItemsResponse>('/api/admin/dynamic-config/feature-bindings'), enabled: Boolean(session?.user?.is_admin)})
  const mail = useQuery({queryKey: ['admin', 'dynamic-config', 'mail'], queryFn: () => apiFetch<ItemsResponse>('/api/admin/dynamic-config/mail'), enabled: Boolean(session?.user?.is_admin)})
  const search = useQuery({queryKey: ['admin', 'dynamic-config', 'web-search'], queryFn: () => apiFetch<ItemsResponse>('/api/admin/dynamic-config/web-search'), enabled: Boolean(session?.user?.is_admin)})
  const agentAccess = useQuery({queryKey: ['admin', 'dynamic-config', 'agent-public-access'], queryFn: () => apiFetch<AgentAccessResponse>('/api/admin/dynamic-config/agent-public-access'), enabled: Boolean(session?.user?.is_admin)})
  const agentConcurrency = useQuery({queryKey: ['admin', 'dynamic-config', 'agent-concurrency'], queryFn: () => apiFetch<AgentConcurrencyResponse>('/api/admin/dynamic-config/agent-concurrency'), enabled: Boolean(session?.user?.is_admin)})
  const refresh = () => queryClient.invalidateQueries({queryKey: ['admin', 'dynamic-config']})
  const updateBinding = useMutation({mutationFn: ({key, endpointId}: {key: string; endpointId: string}) => apiFetch<ApiEnvelope>(`/api/admin/dynamic-config/feature-bindings/${encodeURIComponent(key)}`, {method: 'PUT', body: JSON.stringify({endpoint_id: endpointId ? Number(endpointId) : null})}), onSuccess: refresh, onError: (error) => notify(errorMessage(error), 'error')})
  const removeEndpoint = useMutation({mutationFn: (id: number) => apiFetch<ApiEnvelope>(`/api/admin/dynamic-config/llm-endpoints/${id}`, {method: 'DELETE'}), onSuccess: async () => {setDeleteTarget(null); await refresh()}, onError: (error) => notify(errorMessage(error), 'error')})
  const endpointAction = useMutation({mutationFn: ({id, action, body}: {id: number; action: 'lock' | 'unlock'; body: JsonRecord}) => apiFetch<ApiEnvelope>(`/api/admin/dynamic-config/llm-endpoints/${id}/${action}`, {method: 'POST', body: JSON.stringify(action === 'unlock' ? {...body, confirmation: unlockConfirmation} : body)}), onSuccess: async () => {setLockTarget(null); setUnlockTarget(null); await refresh()}, onError: (error) => notify(errorMessage(error), 'error')})
  const bindingAction = useMutation({mutationFn: ({action, body}: {action: 'lock' | 'unlock'; body: JsonRecord}) => apiFetch<ApiEnvelope>(`/api/admin/dynamic-config/feature-bindings/repository_embedding/${action}`, {method: 'POST', body: JSON.stringify(action === 'unlock' ? {...body, confirmation: unlockConfirmation} : body)}), onSuccess: async () => {setLockTarget(null); setUnlockTarget(null); await refresh()}, onError: (error) => notify(errorMessage(error), 'error')})
  const retestEndpoint = useMutation({
    mutationFn: async (item: JsonRecord) => {
      const candidate = existingEndpointPayload(item)
      const tested = await apiFetch<EndpointTestResponse>('/api/admin/dynamic-config/llm-endpoints/test', {method: 'POST', body: JSON.stringify(candidate)})
      const result = (tested.test || tested) as JsonRecord
      if (result.limits_adjusted) {
        const updated: JsonRecord = {...candidate, context_window_tokens: result.context_window_tokens, max_output_tokens: result.max_output_tokens, test_token: tested.test_token || result.test_token}
        delete updated.endpoint_id
        await apiFetch<ApiEnvelope>(`/api/admin/dynamic-config/llm-endpoints/${Number(item.id)}`, {method: 'PUT', body: JSON.stringify(updated)})
      }
      return tested
    },
    onSuccess: refresh,
    onError: (error) => notify(errorMessage(error), 'error'),
  })
  const accessValue = agentAccess.data?.settings?.public_enabled ?? agentAccess.data?.settings?.enabled ?? agentAccess.data?.public_enabled ?? agentAccess.data?.enabled ?? agentAccess.data?.agent_public_enabled ?? true
  const saveAgentAccess = useMutation({mutationFn: () => apiFetch<AgentAccessResponse>('/api/admin/dynamic-config/agent-public-access', {method: 'PUT', body: JSON.stringify({enabled: !Boolean(accessValue)})}), onSuccess: () => queryClient.invalidateQueries({queryKey: ['admin', 'dynamic-config', 'agent-public-access']}), onError: (error) => notify(errorMessage(error), 'error')})
  const savedConcurrency = Number(agentConcurrency.data?.settings?.limit ?? agentConcurrency.data?.limit ?? 8)
  const parsedConcurrency = /^\d{1,3}$/.test(concurrencyDraft) ? Number(concurrencyDraft) : 0
  const concurrencyValid = parsedConcurrency >= 1 && parsedConcurrency <= 100
  const saveAgentConcurrency = useMutation({mutationFn: () => apiFetch<AgentConcurrencyResponse>('/api/admin/dynamic-config/agent-concurrency', {method: 'PUT', body: JSON.stringify({limit: parsedConcurrency})}), onSuccess: () => queryClient.invalidateQueries({queryKey: ['admin', 'dynamic-config', 'agent-concurrency']}), onError: (error) => notify(errorMessage(error), 'error')})
  useEffect(() => {setConcurrencyDraft(String(savedConcurrency))}, [savedConcurrency])
  if (!session?.user?.is_admin) return <ErrorState message="该页面仅管理员可访问" />
  const allConfigQueries = [endpoints, bindings, mail, search, agentAccess, agentConcurrency]
  if (allConfigQueries.every((item) => item.isPending)) return <LoadingState label="正在读取全站配置" />
  if (allConfigQueries.every((item) => item.isError)) return <ErrorState message="全站配置读取失败" retry={() => {allConfigQueries.forEach((item) => void item.refetch())}} />
  const endpointItems = endpoints.data?.endpoints || []
  const bindingItems = bindings.data?.bindings || []
  const featureQueries = [endpoints, bindings, agentAccess, agentConcurrency]
  const featurePending = featureQueries.some((item) => item.isPending)
  const featureError = featureQueries.find((item) => item.isError)?.error
  const switchTab = (next: typeof tab) => {setTab(next); setRailOpen(false)}
  return <section className={`site-config-v2${tab === 'features' ? ' is-features' : ''}${tab === 'features' && (featurePending || featureError) ? ' is-feature-unavailable' : ''}`}>
    <header className="site-config-header"><div className="site-config-heading"><div className="site-config-eyebrow"><span>ADMIN</span><span>/</span><span>GLOBAL CONFIGURATION</span></div><div className="site-config-title-line"><span className="site-config-id">CFG</span><h1>全站配置</h1></div></div><div className="site-config-header-facts"><div className="site-config-header-fact"><span>ACCESS</span><strong>ADMIN</strong></div><div className="site-config-header-fact"><span>SCOPE</span><strong>GLOBAL</strong></div><span className="site-config-status-chip"><i /><span>LIVE</span></span></div><button className="site-config-mobile-rail-open" type="button" aria-expanded={railOpen} onClick={() => setRailOpen(true)}><i className="fas fa-sliders-h" /><span>配置分类</span></button></header>
    <div className="site-config-workspace"><main className="site-config-content-scroll"><div className="site-config-panel-stage">
      {tab === 'endpoints' ? <section className="site-config-panel active">
        <header className="site-config-panel-header"><div><p className="site-config-kicker">ENDPOINT POOL</p><h2>LLM 端点</h2></div><button className="site-config-primary" type="button" onClick={() => setEndpointDialog(null)}><i className="fas fa-plus" /><span>新建端点</span></button></header>
        {endpoints.isPending ? <LoadingState label="正在读取 LLM 端点" /> : endpoints.isError ? <ErrorState message={endpoints.error.message} retry={() => void endpoints.refetch()} /> : endpointItems.length ? <div className="site-config-endpoint-grid">{endpointItems.map((item) => {
          const identity = endpointIdentity(item)
          const passed = ['passed', 'success', 'ok'].includes(String(item.test_status || '').toLowerCase())
          return <article className="site-config-endpoint-card" key={String(item.id)}>
            <div className="site-config-endpoint-main"><div className="site-config-endpoint-top"><div><span className="site-config-endpoint-number">节点 #{String(item.id)}</span><h3 className="site-config-endpoint-title" title={String(item.model || '')}><ModelLogo model={item.model} /><span>{String(item.model || '未命名模型')}</span></h3></div><div className="site-config-endpoint-chips"><span className="site-config-chip is-protocol">{protocolLabels[String(item.protocol || '')] || String(item.protocol || '')}</span><span className="site-config-chip">{categoryLabels[String(item.category || '')] || String(item.category || '')}</span></div></div><div className="site-config-endpoint-url"><small>地址 · {item.api_key_configured ? '密钥已配置' : '密钥缺失'}</small><span title={String(item.base_url || '')}>{String(item.base_url || '')}</span></div><dl className="site-config-endpoint-prices" aria-label="节点价格，人民币每百万 Token"><div><dt>INPUT</dt><dd>{moneyText(item.input_price_per_million)}</dd></div><div><dt>CACHED</dt><dd>{moneyText(item.cached_input_price_per_million)}</dd></div><div><dt>OUTPUT</dt><dd>{moneyText(item.output_price_per_million)}</dd></div></dl></div>
            <footer className="site-config-endpoint-foot"><span className={`site-config-test-state${passed ? ' is-ok' : ''}`} title={String(item.test_message || '')}><i />{passed ? `连接正常${item.test_latency_ms != null ? ` · ${String(item.test_latency_ms)} ms` : ''}` : ['failed', 'error'].includes(String(item.test_status || '').toLowerCase()) ? '最近测试失败' : '尚未测试'}</span>{!item.is_locked ? <><button className="site-config-icon-button" type="button" title="复测连接" aria-label={`复测 ${identity}`} disabled={retestEndpoint.isPending} onClick={() => retestEndpoint.mutate(item)}><i className="fas fa-vial" /></button><button className="site-config-icon-button" type="button" title="加锁" aria-label={`加锁 ${identity}`} onClick={() => {setLockReason(''); setLockTarget({kind: 'endpoint', item})}}><i className="fas fa-lock" /></button><button className="site-config-icon-button" type="button" title="编辑" aria-label={`编辑 ${identity}`} onClick={() => setEndpointDialog(item)}><i className="fas fa-pen" /></button><button className="site-config-icon-button is-danger" type="button" title="删除" aria-label={`删除 ${identity}`} onClick={() => setDeleteTarget(item)}><i className="fas fa-trash-alt" /></button></> : null}</footer>
            {item.is_locked ? <div className="site-config-lock-overlay"><button type="button" onClick={() => {setUnlockPassword(''); setUnlockText(''); setUnlockTarget({kind: 'endpoint', item})}}><i className="fas fa-unlock-alt" /> 解锁</button></div> : null}
          </article>
        })}</div> : <div className="site-config-empty"><span>00</span><h3>尚无端点</h3></div>}
      </section> : null}
      {tab === 'features' && (featurePending || featureError) ? <div className="site-config-feature-load-state">{featurePending ? <LoadingState label="正在读取功能配置" /> : <ErrorState message={featureError instanceof Error ? featureError.message : '功能配置读取失败'} retry={() => {featureQueries.forEach((item) => void item.refetch())}} />}</div> : null}
      {tab === 'features' ? <section className="site-config-panel active"><header className="site-config-panel-header"><div><p className="site-config-kicker">RUNTIME BINDINGS</p><h2>功能配置</h2></div><span className="site-config-auto-state"><i />自动保存</span></header><div className="site-config-agent-settings"><article className="site-config-feature-card site-config-agent-access"><span className="site-config-feature-icon"><i className="fas fa-robot" /></span><div className="site-config-feature-copy"><div className="site-config-feature-head"><h3>允许用户使用 Agent</h3></div><div className="site-config-feature-control"><button className="site-config-switch" type="button" role="switch" aria-checked={Boolean(accessValue)} disabled={saveAgentAccess.isPending} onClick={() => saveAgentAccess.mutate()}><i /><b>{accessValue ? '开启' : '关闭'}</b></button></div></div></article><article className="site-config-feature-card site-config-agent-concurrency"><span className="site-config-feature-icon"><i className="fas fa-layer-group" /></span><div className="site-config-feature-copy"><div className="site-config-feature-head"><h3>Agent 任务并发上限</h3></div><div className="site-config-feature-control"><div className="site-config-agent-concurrency-control"><div className="site-config-agent-stepper" role="group" aria-label="Agent 任务并发上限"><button type="button" aria-label="减少 Agent 任务并发上限" disabled={saveAgentConcurrency.isPending || !concurrencyValid || parsedConcurrency <= 1} onClick={() => setConcurrencyDraft(String(Math.max(1, (concurrencyValid ? parsedConcurrency : savedConcurrency) - 1)))}><i className="fas fa-minus" /></button><input type="text" inputMode="numeric" pattern="[0-9]*" value={concurrencyDraft} maxLength={3} role="spinbutton" aria-label="Agent 任务并发上限" aria-valuemin={1} aria-valuemax={100} aria-valuenow={concurrencyValid ? parsedConcurrency : undefined} aria-invalid={!concurrencyValid} disabled={saveAgentConcurrency.isPending} onChange={(event) => setConcurrencyDraft(event.target.value)} onBlur={() => {if (!concurrencyValid) setConcurrencyDraft(String(savedConcurrency))}} /><button type="button" aria-label="增加 Agent 任务并发上限" disabled={saveAgentConcurrency.isPending || !concurrencyValid || parsedConcurrency >= 100} onClick={() => setConcurrencyDraft(String(Math.min(100, (concurrencyValid ? parsedConcurrency : savedConcurrency) + 1)))}><i className="fas fa-plus" /></button></div><button className="site-config-primary site-config-agent-concurrency-save" type="button" disabled={saveAgentConcurrency.isPending || !concurrencyValid || parsedConcurrency === savedConcurrency} onClick={() => saveAgentConcurrency.mutate()}>保存</button></div><span className="site-config-feature-saving site-config-agent-concurrency-description">{!concurrencyValid ? '请输入 1 至 100 的整数' : parsedConcurrency !== savedConcurrency ? `尚未保存 · 将调整为 ${parsedConcurrency}` : ''}</span></div></div></article></div><div className="site-config-feature-grid">{bindingItems.map((item) => {const key = String(item.feature_key); const lockable = key === 'repository_embedding'; const featureIcon = key === 'ai_code_annotation' ? 'fa-highlighter' : key === 'code_image_analysis' ? 'fa-image' : key === 'repository_structuring' ? 'fa-sitemap' : key === 'repository_embedding' ? 'fa-vector-square' : 'fa-cog'; const allowed = Array.isArray(item.allowed_categories) ? item.allowed_categories as unknown[] : []; const choices = [{value: '', label: '未配置', icon: 'fa-minus-circle'}, ...endpointItems.filter((endpoint) => !allowed.length || allowed.includes(endpoint.category)).map((endpoint) => ({value: String(endpoint.id), label: String(endpoint.model), icon: 'fa-microchip'}))]; return <article className="site-config-feature-card" key={key}><span className="site-config-feature-icon"><i className={`fas ${featureIcon}`} /></span><div className="site-config-feature-copy"><div className="site-config-feature-head"><h3>{String(item.label || item.feature_key)}</h3>{lockable && !item.is_locked ? <button className="site-config-icon-button site-config-feature-lock" type="button" title="加锁" aria-label="加锁" onClick={() => {setLockReason(''); setLockTarget({kind: 'binding', item})}}><i className="fas fa-lock" /></button> : null}</div><div className="site-config-feature-control"><ConfigChoice variant="feature" disabled={Boolean(item.is_locked)} value={String(item.endpoint_id || '')} label={`${String(item.label || item.feature_key)}端点`} options={choices} onChange={(endpointId) => {if (!item.is_locked) updateBinding.mutate({key, endpointId})}} /><span className="site-config-feature-saving" /></div></div>{item.is_locked ? <div className="site-config-lock-overlay"><button type="button" onClick={() => {setUnlockPassword(''); setUnlockText(''); setUnlockTarget({kind: 'binding', item})}}><i className="fas fa-unlock-alt" /> 解锁</button></div> : null}</article>})}</div></section> : null}
      {tab === 'features' ? <section className="site-config-panel site-config-services-panel active"><div className="site-config-feature-grid">{mail.isPending ? <LoadingState label="正在读取邮件服务配置" /> : mail.isError ? <ErrorState message={mail.error.message} retry={() => void mail.refetch()} /> : <ServiceForm kind="mail" settings={mail.data?.settings} refresh={refresh} notify={notify} />}{search.isPending ? <LoadingState label="正在读取联网搜索配置" /> : search.isError ? <ErrorState message={search.error.message} retry={() => void search.refetch()} /> : <ServiceForm kind="web-search" settings={search.data?.settings} refresh={refresh} notify={notify} />}</div></section> : null}
    </div></main><aside className={`site-config-function-rail${railOpen ? ' is-open' : ''}`} aria-label="配置分类" aria-hidden={!railOpen && undefined}><button className="site-config-rail-close" type="button" onClick={() => setRailOpen(false)} aria-label="关闭配置分类"><i className="fas fa-times" /></button><nav className="site-config-rail-nav" role="tablist"><p className="site-config-rail-group-label">CONFIGURATION</p><button className={`site-config-rail-button${tab === 'endpoints' ? ' active' : ''}`} type="button" role="tab" aria-selected={tab === 'endpoints'} onClick={() => switchTab('endpoints')}><i className="fas fa-project-diagram" /><span>LLM 端点</span><span className="site-config-rail-count">{endpointItems.length}</span></button><button className={`site-config-rail-button${tab === 'features' ? ' active' : ''}`} type="button" role="tab" aria-selected={tab === 'features'} onClick={() => switchTab('features')}><i className="fas fa-toggle-on" /><span>功能配置</span><span className="site-config-rail-count">{bindingItems.length + 2}</span></button></nav><div className="site-config-rail-runtime"><p>RUNTIME</p><span><i /> LIVE</span></div></aside></div>
    {endpointDialog !== undefined ? <EndpointDialog endpoint={endpointDialog} close={() => setEndpointDialog(undefined)} refresh={refresh} /> : null}
    {lockTarget ? <><div className="modal fade show d-block site-config-modal" role="dialog" aria-modal="true" aria-labelledby="siteConfigLockTitle"><div className="modal-dialog modal-dialog-centered"><form className="modal-content" onSubmit={(event) => {event.preventDefault(); const reason = lockReason.trim(); if (!reason) return; if (lockTarget.kind === 'endpoint') endpointAction.mutate({id: Number(lockTarget.item.id), action: 'lock', body: {reason}}); else bindingAction.mutate({action: 'lock', body: {reason}})}}><div className="modal-header"><div><p>CHANGE PROTECTION</p><h2 className="modal-title" id="siteConfigLockTitle">{lockTarget.kind === 'endpoint' ? `加锁 · ${endpointIdentity(lockTarget.item)}` : '加锁 · Embedding 绑定'}</h2></div><button type="button" className="btn-close" aria-label="关闭" onClick={() => setLockTarget(null)} /></div><div className="modal-body"><label className="site-config-field"><span>加锁原因</span><textarea required maxLength={1000} rows={4} autoFocus value={lockReason} onChange={(event) => setLockReason(event.target.value)} /></label></div><div className="modal-footer"><button type="button" className="site-config-secondary" onClick={() => setLockTarget(null)}>取消</button><button type="submit" className="site-config-primary" disabled={endpointAction.isPending || bindingAction.isPending}><i className="fas fa-lock" />{endpointAction.isPending || bindingAction.isPending ? '加锁中…' : '加锁'}</button></div></form></div></div><div className="modal-backdrop fade show" /></> : null}
    {unlockTarget ? <><div className="modal fade show d-block site-config-modal" role="dialog" aria-modal="true" aria-labelledby="siteConfigUnlockTitle"><div className="modal-dialog modal-dialog-centered"><form className="modal-content" autoComplete="off" onSubmit={(event) => {event.preventDefault(); if (!unlockTarget.item.can_unlock || unlockText !== unlockConfirmation) return; const body = {password: unlockPassword, confirmation: unlockText}; if (unlockTarget.kind === 'endpoint') endpointAction.mutate({id: Number(unlockTarget.item.id), action: 'unlock', body}); else bindingAction.mutate({action: 'unlock', body})}}><div className="modal-header"><div><p>PROTECTED CONFIG</p><h2 className="modal-title" id="siteConfigUnlockTitle">{unlockTarget.kind === 'endpoint' ? `解锁 · ${endpointIdentity(unlockTarget.item)}` : '解锁 · Embedding 绑定'}</h2></div><button type="button" className="btn-close" aria-label="关闭" onClick={() => setUnlockTarget(null)} /></div><div className="modal-body"><div className="site-config-lock-reason"><span>加锁原因</span><p>{String(unlockTarget.item.lock_reason || '未记录原因')}</p></div>{!unlockTarget.item.can_unlock ? <div className="site-config-lock-denied"><i className="fas fa-user-lock" />你无法解锁</div> : <div data-unlock-owner-fields><label className="site-config-field"><span>当前密码</span><input type="password" required autoComplete="current-password" autoFocus value={unlockPassword} onChange={(event) => setUnlockPassword(event.target.value)} /></label><label className="site-config-field"><span>确认文本</span><input required autoComplete="off" placeholder={unlockConfirmation} value={unlockText} onChange={(event) => setUnlockText(event.target.value)} /></label><p className="site-config-confirmation-copy">{unlockConfirmation}</p></div>}</div><div className="modal-footer"><button type="button" className="site-config-secondary" onClick={() => setUnlockTarget(null)}>关闭</button>{unlockTarget.item.can_unlock ? <button type="submit" className="site-config-danger" disabled={endpointAction.isPending || bindingAction.isPending}><i className="fas fa-unlock" />{endpointAction.isPending || bindingAction.isPending ? '解锁中…' : '解锁'}</button> : null}</div></form></div></div><div className="modal-backdrop fade show" /></> : null}
    {deleteTarget ? <><div className="modal fade show d-block site-config-modal" role="dialog" aria-modal="true" aria-labelledby="siteConfigDeleteTitle"><div className="modal-dialog modal-dialog-centered modal-sm"><form className="modal-content" onSubmit={(event) => {event.preventDefault(); removeEndpoint.mutate(Number(deleteTarget.id))}}><div className="modal-header"><div><p>DELETE ENDPOINT</p><h2 className="modal-title" id="siteConfigDeleteTitle">确认删除</h2></div><button type="button" className="btn-close" aria-label="关闭" onClick={() => setDeleteTarget(null)} /></div><div className="modal-body"><p className="site-config-modal-copy">删除端点 <strong>{endpointIdentity(deleteTarget)}</strong>？</p></div><div className="modal-footer"><button type="button" className="site-config-secondary" onClick={() => setDeleteTarget(null)}>取消</button><button type="submit" className="site-config-danger" disabled={removeEndpoint.isPending}>{removeEndpoint.isPending ? '删除中…' : '删除'}</button></div></form></div></div><div className="modal-backdrop fade show" /></> : null}
    <SiteConfigToast notice={notice} />
  </section>
}
