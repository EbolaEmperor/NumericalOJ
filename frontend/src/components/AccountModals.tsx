import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useMemo, useState, type FormEvent} from 'react'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {useSession} from '../session'
import {useDismissibleDropdown} from './useDismissibleDropdown'

interface ClassItem extends JsonRecord {
  class_en: string
  class_cn?: string
  logo?: {cells?: number[][]}
}

interface ClassesResponse extends ApiEnvelope {
  memberships: ClassItem[]
  all_classes: ClassItem[]
}

function formData(values: Record<string, string>) {
  const body = new FormData()
  Object.entries(values).forEach(([key, value]) => body.append(key, value))
  return body
}

function ClassLogo({item, className}: {item?: ClassItem; className: string}) {
  const cells = Array.isArray(item?.logo?.cells) ? item.logo.cells : []
  return <span className={className} aria-hidden="true"><svg viewBox="0 0 7 7" focusable="false" shapeRendering="crispEdges">{cells.map((cell, index) => Array.isArray(cell) && cell.length >= 2 ? <rect x={Number(cell[0]) + 1} y={Number(cell[1]) + 1} width="1" height="1" key={index} /> : null)}</svg></span>
}

function PasswordModal({notify}: {notify: (message: string) => void}) {
  const {session} = useSession()
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [countdown, setCountdown] = useState(0)
  const mailConfigured = Boolean(session?.capabilities.mail_service_configured)
  const longEnough = password.length >= 6
  const mixed = /[A-Za-z]/.test(password) && /\d/.test(password)
  const matches = confirmation.length > 0 && confirmation === password
  const strength = Math.min(3, Number(longEnough) + Number(mixed) + Number(password.length >= 10))
  const strengthLabel = !password ? '尚未输入' : ['较短', '可用', '良好', '更稳妥'][strength]

  useEffect(() => {
    if (countdown <= 0) return
    const timer = window.setTimeout(() => setCountdown((value) => Math.max(0, value - 1)), 1_000)
    return () => window.clearTimeout(timer)
  }, [countdown])

  const sendCode = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>('/api/account/password/code', {method: 'POST'}),
    onSuccess: (data) => {setCountdown(60); notify(data.message || '验证码已发送')},
  })
  const save = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>('/api/account/password', {method: 'POST', body: formData({code, new_password: password, confirm_password: confirmation})}),
    onSuccess: (data) => {notify(data.message || '密码修改成功'); setCode(''); setPassword(''); setConfirmation('')},
  })
  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (code.length === 6 && longEnough && matches) save.mutate()
  }

  return <div className="modal fade numoj-account-modal numoj-password-modal" id="changePasswordModal" tabIndex={-1} aria-labelledby="changePasswordModalLabel" aria-hidden="true">
    <div className="modal-dialog modal-dialog-centered modal-dialog-scrollable"><div className="modal-content">
      <span className="numoj-account-modal-accent" aria-hidden="true" />
      <div className="modal-header"><div className="numoj-account-modal-title"><span className="numoj-account-kicker">SECURITY · PASSWORD</span><h2 className="modal-title" id="changePasswordModalLabel">修改密码</h2></div><button type="button" className="numoj-account-close" data-bs-dismiss="modal" aria-label="关闭修改密码弹窗"><span aria-hidden="true">×</span></button></div>
      <form id="passwordForm" noValidate onSubmit={submit}>
        <div className="modal-body numoj-account-modal-body">
          <section className="numoj-account-section" aria-labelledby="passwordIdentityTitle"><div className="numoj-account-section-heading"><h3 id="passwordIdentityTitle">验证身份</h3><span>STEP 01 / 02</span></div><div className="numoj-account-identity"><span className="numoj-account-identity-icon" aria-hidden="true">@</span><span className="numoj-account-identity-copy"><strong>{session?.user?.email || '尚未设置邮箱'}</strong><small>{mailConfigured ? '验证码仅发送至当前账户邮箱' : '站点尚未配置邮件服务，请联系管理员'}</small></span><span className="numoj-account-state">{mailConfigured ? '可用' : '不可用'}</span></div></section>
          <div className="numoj-account-form-stack"><div className="numoj-account-field"><div className="numoj-account-input numoj-account-input-action"><input id="passwordCodeInput" name="code" type="text" inputMode="numeric" maxLength={6} autoComplete="one-time-code" placeholder="••••••" aria-label="验证码" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))} required /><button type="button" disabled={!mailConfigured || sendCode.isPending || countdown > 0} onClick={() => sendCode.mutate()}>{sendCode.isPending ? '正在发送…' : countdown > 0 ? `${countdown}秒后重发` : '发送验证码'}</button></div><p className={`numoj-account-field-message${sendCode.isError ? ' is-error' : sendCode.isSuccess ? ' is-success' : ''}`} aria-live="polite">{sendCode.isError ? errorMessage(sendCode.error) : sendCode.isSuccess ? '验证码已发送，请在 5 分钟内完成验证。' : '发送后 5 分钟内有效。'}</p></div></div>
          <div className="numoj-account-form-stack">
            <div className="numoj-account-field"><div className="numoj-account-field-heading"><label htmlFor="newPasswordInput">新密码</label><span>{strengthLabel}</span></div><div className="numoj-account-input"><input id="newPasswordInput" name="new_password" type="password" minLength={6} autoComplete="new-password" placeholder="至少输入 6 个字符" value={password} onChange={(event) => setPassword(event.target.value)} required /></div><div className="numoj-password-meter" data-level={strength} role="progressbar" aria-label="密码强度" aria-valuemin={0} aria-valuemax={3} aria-valuenow={strength}>{[0, 1, 2].map((index) => <span className={index < strength ? 'is-on' : ''} key={index} />)}</div><div className="numoj-password-rules"><span className={longEnough ? 'is-passed' : ''}>至少 6 个字符</span><span className={mixed ? 'is-passed' : ''}>建议同时包含字母与数字</span></div></div>
            <div className="numoj-account-field"><div className="numoj-account-field-heading"><label htmlFor="confirmPasswordInput">确认新密码</label><span>再次输入</span></div><div className="numoj-account-input"><input id="confirmPasswordInput" name="confirm_password" type="password" autoComplete="new-password" placeholder="重复新密码" aria-invalid={confirmation.length > 0 && !matches} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} required /></div>{confirmation ? <p className={`numoj-account-field-message ${matches ? 'is-success' : 'is-error'}`} aria-live="polite">{matches ? '两次输入一致，可以提交。' : '两次输入不一致，请重新检查。'}</p> : null}</div>
          </div>
          {save.isError || save.isSuccess ? <p className={`numoj-account-form-status ${save.isSuccess ? 'is-success' : 'is-error'}`} role="status" aria-live="polite">{save.isError ? errorMessage(save.error) : save.data?.message || '密码修改成功'}</p> : null}
        </div>
        <div className="modal-footer"><span className="numoj-account-footer-note">FORM · VALIDATION INLINE</span><div className="numoj-account-footer-actions"><button type="button" className="numoj-account-button" data-bs-dismiss="modal">取消</button><button type="submit" className="numoj-account-button numoj-account-button-dark" disabled={save.isPending || code.length !== 6 || !longEnough || !matches}>{save.isPending ? '正在保存…' : '确认修改'}</button></div></div>
      </form>
    </div></div>
  </div>
}

function ClassManagerModal({notify}: {notify: (message: string) => void}) {
  const {session, refresh} = useSession()
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState('')
  const [pickerOpen, setPickerOpen] = useState(false)
  const pickerRef = useDismissibleDropdown<HTMLDivElement>(pickerOpen, () => setPickerOpen(false))
  const [confirmLeave, setConfirmLeave] = useState('')
  const [adjustEnabled, setAdjustEnabled] = useState(Boolean(session?.capabilities.class_adjust_enabled))
  const isAdmin = Boolean(session?.user?.is_admin)
  const canAdjust = isAdmin || adjustEnabled
  const classes = useQuery({queryKey: ['account', 'classes'], queryFn: () => apiFetch<ClassesResponse>('/api/account/classes')})
  const memberships = classes.data?.memberships || []
  const membershipIds = useMemo(() => new Set(memberships.map((item) => item.class_en)), [memberships])
  const available = (classes.data?.all_classes || []).filter((item) => !membershipIds.has(item.class_en))
  const selectedItem = available.find((item) => item.class_en === selected)
  const reload = async () => {await queryClient.invalidateQueries({queryKey: ['account', 'classes']}); await refresh()}
  const join = useMutation({mutationFn: () => apiFetch<ApiEnvelope>('/api/account/classes', {method: 'POST', body: formData({class_en: selected})}), onSuccess: async (data) => {notify(data.message || '成功加入班级'); setSelected(''); await reload()}})
  const leave = useMutation({mutationFn: (classEn: string) => apiFetch<ApiEnvelope>(`/api/account/classes/${encodeURIComponent(classEn)}`, {method: 'DELETE'}), onSuccess: async (data) => {notify(data.message || '成功退出班级'); setConfirmLeave(''); await reload()}})
  const toggle = useMutation({mutationFn: (enabled: boolean) => apiFetch<ApiEnvelope & {enabled?: boolean}>('/api/admin/settings/class-adjust', {method: 'POST', body: formData({enabled: enabled ? '1' : '0'})}), onSuccess: async (data) => {setAdjustEnabled(Boolean(data.enabled)); notify(data.enabled ? '已允许学生自助调整班级' : '已禁止学生自助调整班级'); await refresh()}})

  if (!isAdmin && !adjustEnabled) return null
  return <div className="modal fade numoj-account-modal numoj-class-modal" id="classManagerModal" tabIndex={-1} aria-labelledby="classManagerLabel" aria-hidden="true">
    <div className="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div className="modal-content">
      <span className="numoj-account-modal-accent" aria-hidden="true" />
      <div className="modal-header"><div className="numoj-account-modal-title"><span className="numoj-account-kicker">MEMBERSHIP · CLASSES</span><h2 className="modal-title" id="classManagerLabel">调整班级</h2></div><div className="numoj-class-header-actions">{isAdmin ? <label className="numoj-class-permission" htmlFor="classAdjustSwitch"><input type="checkbox" id="classAdjustSwitch" checked={adjustEnabled} disabled={toggle.isPending} onChange={(event) => toggle.mutate(event.target.checked)} /><span className="numoj-class-switch-track" aria-hidden="true"><span /></span><span>学生自助：{adjustEnabled ? '允许' : '禁止'}</span></label> : null}<button type="button" className="numoj-account-close" data-bs-dismiss="modal" aria-label="关闭调整班级弹窗"><span aria-hidden="true">×</span></button></div></div>
      <div className="modal-body numoj-account-modal-body">
        <section className="numoj-account-section" aria-labelledby="myClassesTitle"><div className="numoj-account-section-heading"><h3 id="myClassesTitle">我的班级</h3><span>{classes.isPending ? '正在加载' : `${memberships.length} MEMBERSHIP${memberships.length === 1 ? '' : 'S'}`}</span></div><div className="numoj-membership-list" aria-live="polite">{classes.isPending ? <div className="numoj-membership-state"><span className="math-curve-loader" data-math-curve-loader data-size="sm"><span className="math-curve-loader__label">正在加载班级…</span></span></div> : classes.isError ? <div className="numoj-membership-state is-error">{errorMessage(classes.error)}</div> : memberships.length ? memberships.map((item) => <div className="numoj-membership-row" key={item.class_en}><ClassLogo item={item} className="numoj-membership-logo" /><span className="numoj-membership-copy"><span className="numoj-membership-name"><strong>{item.class_cn || item.class_en}</strong></span><span className="numoj-membership-code">{item.class_en}</span></span><div className="numoj-membership-actions"><button type="button" className={`numoj-membership-action is-danger${confirmLeave === item.class_en ? ' is-confirming' : ''}`} disabled={!canAdjust || (!isAdmin && memberships.length <= 1) || leave.isPending} onClick={() => confirmLeave === item.class_en ? leave.mutate(item.class_en) : setConfirmLeave(item.class_en)}>{confirmLeave === item.class_en ? '再次点击确认' : '退出'}</button></div></div>) : <div className="numoj-membership-state">暂无班级</div>}</div></section>
        <section className="numoj-account-section" aria-labelledby="joinClassTitle"><div className="numoj-account-section-heading"><h3 id="joinClassTitle">加入新班级</h3><span>AVAILABLE</span></div><div className="numoj-class-join-row"><div ref={pickerRef} className={`numoj-class-select${pickerOpen ? ' open' : ''}`}><input type="hidden" value={selected} readOnly /><button className="numoj-class-select-trigger" type="button" aria-haspopup="listbox" aria-expanded={pickerOpen} onClick={() => setPickerOpen((value) => !value)}><ClassLogo item={selectedItem} className={`numoj-class-select-logo${selectedItem ? '' : ' is-placeholder'}`} /><span className="numoj-class-select-current"><strong>{selectedItem?.class_cn || '请选择班级'}</strong><small>{selectedItem?.class_en || 'AVAILABLE'}</small></span><i className="fas fa-chevron-down numoj-class-select-chevron" aria-hidden="true" /></button><div className="numoj-class-select-menu" role="listbox" aria-label="可加入的班级" hidden={!pickerOpen}>{available.length ? available.map((item) => <button type="button" className={`numoj-class-select-option${selected === item.class_en ? ' is-selected' : ''}`} role="option" aria-selected={selected === item.class_en} onClick={() => {setSelected(item.class_en); setPickerOpen(false)}} key={item.class_en}><ClassLogo item={item} className="numoj-class-select-logo" /><span className="numoj-class-select-option-copy"><strong>{item.class_cn || item.class_en}</strong><small>{item.class_en}</small></span><span className="numoj-class-select-option-state" aria-hidden="true">✓</span></button>) : <div className="numoj-class-select-empty">暂无可选班级</div>}</div></div><button className="numoj-account-button numoj-account-button-brand" type="button" disabled={!selected || !canAdjust || join.isPending} onClick={() => join.mutate()}>加入班级</button></div>{join.isError || leave.isError || toggle.isError ? <p className="numoj-account-form-status is-error" role="alert">{errorMessage(join.error || leave.error || toggle.error)}</p> : null}</section>
      </div>
      <div className="modal-footer"><span className="numoj-account-footer-note">CHANGES · SAVED IMMEDIATELY</span><div className="numoj-account-footer-actions"><button type="button" className="numoj-account-button numoj-account-button-dark" data-bs-dismiss="modal">完成</button></div></div>
    </div></div>
  </div>
}

export function AccountModals() {
  const [toast, setToast] = useState('')
  useEffect(() => {
    if (!toast) return
    const timer = window.setTimeout(() => setToast(''), 2_300)
    return () => window.clearTimeout(timer)
  }, [toast])
  return <><div className={`numoj-account-toast${toast ? ' is-visible' : ''}`} role="status" aria-live="polite" hidden={!toast}>{toast}</div><PasswordModal notify={setToast} /><ClassManagerModal notify={setToast} /></>
}
