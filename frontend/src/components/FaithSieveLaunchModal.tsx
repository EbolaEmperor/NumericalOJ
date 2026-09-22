import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useRef, useState} from 'react'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {ReactModal} from './ReactModal'

interface LaunchOptions extends ApiEnvelope {
  harnesses?: JsonRecord[]
  endpoints_by_harness?: Record<string, JsonRecord[]>
  preference?: JsonRecord
}

interface LaunchResult extends ApiEnvelope {queued?: number; skipped?: number}

function Choice({label, value, items, disabled, onChange}: {label: string; value: string; items: JsonRecord[]; disabled: boolean; onChange: (value: string) => void}) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const selected = items.find((item) => String(item.value ?? item.id) === value)
  useEffect(() => {
    if (!open) return
    const close = (event: PointerEvent) => {if (!root.current?.contains(event.target as Node)) setOpen(false)}
    document.addEventListener('pointerdown', close)
    return () => document.removeEventListener('pointerdown', close)
  }, [open])
  return <div className="agent-launch-field"><span className="agent-launch-field-label">{label}</span><div ref={root} className={`rk-choice agent-launch-choice${open ? ' open' : ''}`}><button type="button" className="rk-choice-trigger" role="combobox" aria-haspopup="listbox" aria-expanded={open} disabled={disabled} onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main"><i className="fas fa-microchip" /><span>{String(selected?.label || selected?.model || (disabled ? '正在加载…' : '请选择'))}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox" aria-label={label} hidden={!open}>{items.map((item) => {const itemValue = String(item.value ?? item.id); return <button type="button" className={`rk-choice-option${itemValue === value ? ' active' : ''}`} role="option" aria-selected={itemValue === value} key={itemValue} onClick={() => {onChange(itemValue); setOpen(false)}}><span className="rk-choice-option-main"><i className="fas fa-microchip" /><span><span className="rk-choice-option-name">{String(item.label || item.model || itemValue)}</span></span></span><i className="fas fa-check rk-choice-option-check" /></button>})}</div></div></div>
}

export function FaithSieveLaunchModal({open, action, batch = false, onClose, onQueued}: {open: boolean; action: string; batch?: boolean; onClose: () => void; onQueued: (result: LaunchResult) => void}) {
  const options = useQuery({queryKey: ['faithsieve-launch-options'], queryFn: () => apiFetch<LaunchOptions>('/api/agent/launch-options?task_kind=judge'), enabled: open, staleTime: 0})
  const [harness, setHarness] = useState('')
  const [endpointId, setEndpointId] = useState('')
  const endpointsByHarness = options.data?.endpoints_by_harness || {}
  useEffect(() => {
    if (!open || !options.data) return
    const preferredHarness = String(options.data.preference?.harness || options.data.harnesses?.[0]?.value || '')
    const candidates = endpointsByHarness[preferredHarness] || []
    setHarness(preferredHarness)
    setEndpointId(String(options.data.preference?.endpoint_id || candidates[0]?.id || ''))
  }, [open, options.data])
  const launch = useMutation({
    mutationFn: () => apiFetch<LaunchResult>(action, {method: 'POST', body: JSON.stringify({harness, endpoint_id: Number(endpointId)})}),
    onSuccess: (result) => {onQueued(result); onClose()},
  })
  const harnessItems = (options.data?.harnesses || []).map((item) => ({...item, id: item.value}))
  const endpointItems = endpointsByHarness[harness] || []
  const selectHarness = (value: string) => {setHarness(value); setEndpointId(String((endpointsByHarness[value] || [])[0]?.id || ''))}
  return <ReactModal open={open} onClose={onClose} id="faithsieveLaunchModal" labelledBy="faithsieveLaunchModalLabel" className="agent-launch-modal" dialogClassName="modal-dialog-centered"><div className="modal-content"><div className="modal-header"><div className="agent-launch-heading"><span className="agent-launch-heading-icon"><i className="fas fa-filter" /></span><div><p className="agent-launch-eyebrow">FAITHSIEVE JUDGE</p><h5 className="modal-title" id="faithsieveLaunchModalLabel">{batch ? '批量评测最新提交' : '评测这条提交'}</h5></div></div><button type="button" className="btn-close" aria-label="关闭" onClick={onClose} /></div><div className="modal-body"><p className="text-muted">将启动只读 Judge Agent，并注入 FaithSieve skill。批量任务最多同时运行 20 条。</p><div className="agent-launch-selector-grid"><Choice label="Harness" value={harness} items={harnessItems} disabled={options.isPending || launch.isPending} onChange={selectHarness} /><Choice label="LLM 节点" value={endpointId} items={endpointItems} disabled={options.isPending || launch.isPending || !endpointItems.length} onChange={setEndpointId} /></div>{options.isError ? <div className="agent-launch-feedback is-error" role="alert">{errorMessage(options.error)}</div> : launch.isError ? <div className="agent-launch-feedback is-error" role="alert">{errorMessage(launch.error)}</div> : null}</div><div className="modal-footer"><button type="button" className="btn btn-outline-secondary" onClick={onClose}>取消</button><button type="button" className="btn btn-primary" disabled={!harness || !endpointId || launch.isPending} onClick={() => launch.mutate()}>{launch.isPending ? '正在入队…' : '启动 FaithSieve'}</button></div></div></ReactModal>
}
