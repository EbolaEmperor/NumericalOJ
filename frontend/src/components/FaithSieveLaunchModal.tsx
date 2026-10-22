import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useRef, useState} from 'react'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {harnessLogoClass} from '../lib/harnessIdentity'
import type {FaithSieveExecutionMode} from '../pages/faithsieveTypes'
import {ExecutionModeLogo} from './ExecutionModeLogo'
import {ModelLogo} from './ModelLogo'
import {ReactModal} from './ReactModal'

interface LaunchOptions extends ApiEnvelope {
  harnesses?: JsonRecord[]
  endpoints_by_harness?: Record<string, JsonRecord[]>
  preference?: JsonRecord
}

interface LaunchResult extends ApiEnvelope {queued?: number; skipped?: number}
interface LaunchVariables {url: string; harness: string; endpoint_id: number; execution_mode: FaithSieveExecutionMode}

function ChoiceIcon({item, kind}: {item?: JsonRecord; kind: 'harness' | 'model' | 'execution'}) {
  if (kind === 'model') return <ModelLogo model={item?.model || item?.label} />
  if (kind === 'execution') return <ExecutionModeLogo mode={item?.value === 'skill' ? 'skill' : 'workflow'} />
  return <i className={harnessLogoClass(item?.value ?? item?.id)} aria-hidden="true" />
}

function Choice({label, value, items, disabled, kind, onChange}: {label: string; value: string; items: JsonRecord[]; disabled: boolean; kind: 'harness' | 'model' | 'execution'; onChange: (value: string) => void}) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const selected = items.find((item) => String(item.value ?? item.id) === value)
  useEffect(() => {
    if (!open) return
    const close = (event: PointerEvent) => {if (!root.current?.contains(event.target as Node)) setOpen(false)}
    document.addEventListener('pointerdown', close)
    return () => document.removeEventListener('pointerdown', close)
  }, [open])
  return <div className={`agent-launch-field${kind === 'execution' ? ' agent-launch-solution-field' : ''}`}><span className="agent-launch-field-label">{label}</span><div ref={root} className={`rk-choice agent-launch-choice${open ? ' open' : ''}`}><button type="button" className="rk-choice-trigger" role="combobox" aria-label={label} aria-haspopup="listbox" aria-expanded={open} disabled={disabled} onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main">{selected ? <ChoiceIcon item={selected} kind={kind} /> : <i className={`fas ${disabled ? 'fa-circle-notch fa-spin' : 'fa-unlink'}`} aria-hidden="true" />}<span>{String(selected?.label || selected?.model || (disabled ? '正在加载…' : '请选择'))}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox" aria-label={label} hidden={!open}>{items.map((item) => {const itemValue = String(item.value ?? item.id); return <button type="button" className={`rk-choice-option${itemValue === value ? ' active' : ''}`} role="option" aria-selected={itemValue === value} key={itemValue} onClick={() => {onChange(itemValue); setOpen(false)}}><span className="rk-choice-option-main"><ChoiceIcon item={item} kind={kind} /><span><span className="rk-choice-option-name">{String(item.label || item.model || itemValue)}</span></span></span><i className="fas fa-check rk-choice-option-check" /></button>})}</div></div></div>
}

export function FaithSieveLaunchModal({open, action, batch = false, onClose, onQueued}: {open: boolean; action: string; batch?: boolean; onClose: () => void; onQueued: (result: LaunchResult) => void}) {
  const options = useQuery({queryKey: ['faithsieve-launch-options'], queryFn: () => apiFetch<LaunchOptions>('/api/agent/launch-options?task_kind=judge'), enabled: open, staleTime: 0})
  const [harness, setHarness] = useState('')
  const [endpointId, setEndpointId] = useState('')
  const [executionMode, setExecutionMode] = useState<FaithSieveExecutionMode>('workflow')
  useEffect(() => {if (open) setExecutionMode('workflow')}, [open])
  const endpointsByHarness = Object.fromEntries(Object.entries(options.data?.endpoints_by_harness || {}).map(([key, items]) => [key, items.filter((item) => item.category === 'omni')]))
  useEffect(() => {
    if (!open || !options.data) return
    const preferredHarness = String(options.data.preference?.harness || '')
    const availableHarnesses = options.data.harnesses || []
    const preferredAvailable = availableHarnesses.some((item) => String(item.value) === preferredHarness) && Boolean(endpointsByHarness[preferredHarness]?.length)
    const nextHarness = preferredAvailable ? preferredHarness : String(availableHarnesses.find((item) => endpointsByHarness[String(item.value)]?.length)?.value || availableHarnesses[0]?.value || '')
    const candidates = endpointsByHarness[nextHarness] || []
    const preferredEndpoint = String(options.data.preference?.endpoint_id || '')
    setHarness(nextHarness)
    setEndpointId(candidates.some((item) => String(item.id) === preferredEndpoint) ? preferredEndpoint : String(candidates[0]?.id || ''))
  }, [open, options.data])
  const launch = useMutation({
    // 点击时传入当前界面选择，避免 mutation observer 尚未同步 options 时读取旧闭包。
    mutationFn: ({url, ...selection}: LaunchVariables) => apiFetch<LaunchResult>(url, {method: 'POST', body: JSON.stringify(selection)}),
    onSuccess: (result) => {onQueued(result); onClose()},
  })
  const harnessItems = (options.data?.harnesses || []).map((item) => ({...item, id: item.value}))
  const endpointItems = endpointsByHarness[harness] || []
  const executionItems: JsonRecord[] = [{value: 'workflow', label: 'Workflow'}, {value: 'skill', label: 'Skill'}]
  const ready = harnessItems.some((item) => String(item.id) === harness) && endpointItems.some((item) => String(item.id) === endpointId)
  const selectHarness = (value: string) => {setHarness(value); setEndpointId(String((endpointsByHarness[value] || [])[0]?.id || ''))}
  return <ReactModal open={open} onClose={onClose} id="faithsieveLaunchModal" labelledBy="faithsieveLaunchModalLabel" className="agent-launch-modal faithsieve-launch-modal" dialogClassName="modal-dialog-centered"><div className="modal-content"><div className="modal-header"><div className="agent-launch-heading"><span className="agent-launch-heading-icon"><i className="fas fa-filter" /></span><div><p className="agent-launch-eyebrow">FAITHSIEVE</p><h5 className="modal-title" id="faithsieveLaunchModalLabel">{batch ? '批量评测最新提交' : '评测这条提交'}</h5></div></div><button type="button" className="btn-close" aria-label="关闭" onClick={onClose} /></div><div className="modal-body"><div className="agent-launch-selector-grid"><Choice label="执行方式" value={executionMode} items={executionItems} disabled={launch.isPending} kind="execution" onChange={(value) => setExecutionMode(value as FaithSieveExecutionMode)} /><Choice label="Harness" value={harness} items={harnessItems} disabled={options.isPending || launch.isPending || !harnessItems.length} kind="harness" onChange={selectHarness} /><Choice label="LLM 节点" value={endpointId} items={endpointItems} disabled={options.isPending || launch.isPending || !endpointItems.length} kind="model" onChange={setEndpointId} /></div>{options.isError ? <div className="agent-launch-feedback is-error" role="alert">{errorMessage(options.error)}</div> : launch.isError ? <div className="agent-launch-feedback is-error" role="alert">{errorMessage(launch.error)}</div> : options.data && !harnessItems.length ? <div className="agent-launch-feedback is-error" role="alert">当前没有可用的 Harness。</div> : options.data && !endpointItems.length ? <div className="agent-launch-feedback is-error" role="alert">FaithSieve 原稿图像核对需要全模态模型。该 Harness 暂无兼容且已配置完整价格的全模态节点，请选择其他 Harness 或补充全站配置。</div> : null}</div><div className="modal-footer"><button type="button" className="btn btn-outline-secondary" onClick={onClose}>取消</button><button type="button" className="btn btn-primary" disabled={!ready || options.isFetching || options.isError || launch.isPending} onClick={() => launch.mutate({url: action, harness, endpoint_id: Number(endpointId), execution_mode: executionMode})}>{launch.isPending ? '正在入队…' : '启动 FaithSieve'}</button></div></div></ReactModal>
}
