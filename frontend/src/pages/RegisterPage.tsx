import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useState, type FormEvent} from 'react'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {AuthFrame, PasswordToggle} from '../components/AuthFrame'
import {Link, useNavigate} from '../components/PageNavigation'
import {useDismissibleDropdown} from '../components/useDismissibleDropdown'

interface ClassItem extends JsonRecord {
  class_en: string
  class_cn?: string
  logo?: {cells?: number[][]}
}

interface RegistrationContext extends ApiEnvelope {
  classes: ClassItem[]
  mail_configured: boolean
}

function ClassLogo({item, placeholder = false}: {item?: ClassItem; placeholder?: boolean}) {
  const cells = Array.isArray(item?.logo?.cells) ? item.logo.cells : []
  return <span className={`numoj-class-select-logo${placeholder ? ' is-placeholder' : ''}`} aria-hidden="true"><svg viewBox="0 0 7 7" focusable="false" shapeRendering="crispEdges">{cells.map((cell, index) => Array.isArray(cell) && cell.length >= 2 ? <rect x={Number(cell[0]) + 1} y={Number(cell[1]) + 1} width="1" height="1" key={index} /> : null)}</svg></span>
}

export default function RegisterPage() {
  const navigate = useNavigate()
  const context = useQuery({queryKey: ['auth', 'registration'], queryFn: () => apiFetch<RegistrationContext>('/api/auth/registration')})
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [selectedClass, setSelectedClass] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [pickerOpen, setPickerOpen] = useState(false)
  const pickerRef = useDismissibleDropdown<HTMLDivElement>(pickerOpen, () => setPickerOpen(false))
  const [classError, setClassError] = useState(false)
  const [countdown, setCountdown] = useState(0)
  const selected = context.data?.classes.find((item) => item.class_en === selectedClass)
  const enabled = Boolean(context.data?.mail_configured)

  useEffect(() => {document.title = '注册 - Numerical OJ'}, [])
  useEffect(() => {
    if (countdown <= 0) return
    const timer = window.setTimeout(() => setCountdown((value) => Math.max(0, value - 1)), 1000)
    return () => window.clearTimeout(timer)
  }, [countdown])

  const sendCode = useMutation({
    mutationFn: () => {
      const body = new FormData()
      body.append('email', email.trim())
      return apiFetch<ApiEnvelope>('/api/auth/registration/code', {method: 'POST', body})
    },
    onSuccess: () => setCountdown(60),
  })
  const register = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>('/api/users', {method: 'POST', body: JSON.stringify({email: email.trim(), verification_code: code, username: username.trim(), password, class: selectedClass})}),
    onSuccess: (data) => navigate(`/login?success=${encodeURIComponent(data.message || '注册成功，请登录')}`, {replace: true}),
  })
  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!selectedClass) {
      setClassError(true)
      setPickerOpen(true)
      document.getElementById('registerClassSelectTrigger')?.focus()
      return
    }
    if (enabled && email.trim() && code.length === 6 && username.trim() && password) register.mutate()
  }

  return <AuthFrame active="register">
    {!context.isPending && !enabled ? <p className="numoj-auth-notice" role="status">站点尚未配置邮件服务，请联系管理员</p> : null}
    {context.isError || register.isError ? <div className="numoj-auth-alert is-error" role="alert">{errorMessage(context.error || register.error)}</div> : null}
    <form className="numoj-auth-form" onSubmit={submit}>
      <div className="numoj-auth-field"><label htmlFor="email">邮箱</label><span className="numoj-auth-control"><input id="email" name="email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="请输入邮箱" required /></span></div>
      <div className="numoj-auth-field">
        <label htmlFor="verification_code">验证码</label>
        <span className="numoj-auth-code-row"><span className="numoj-auth-control"><input id="verification_code" name="verification_code" type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={6} pattern="[0-9]{6}" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="请输入验证码" required /></span><button className="numoj-auth-code-button" type="button" disabled={!enabled || sendCode.isPending || countdown > 0} onClick={() => {const input = document.getElementById('email') as HTMLInputElement | null; if (input?.checkValidity()) sendCode.mutate(); else {input?.reportValidity(); input?.focus()}}}>{sendCode.isPending ? '正在发送…' : countdown > 0 ? `${countdown}秒后重发` : '获取验证码'}</button></span>
        {sendCode.isSuccess || sendCode.isError ? <p className={`numoj-auth-field-status ${sendCode.isSuccess ? 'is-success' : 'is-error'}`} aria-live="polite">{sendCode.isSuccess ? sendCode.data.message || '验证码已发送' : errorMessage(sendCode.error)}</p> : null}
      </div>
      <div className="numoj-auth-field"><label htmlFor="username">学号</label><span className="numoj-auth-control"><input id="username" name="username" type="text" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="请输入学号" required /></span></div>
      <div className="numoj-auth-field"><label htmlFor="password">密码</label><span className="numoj-auth-control"><input id="password" name="password" type={passwordVisible ? 'text' : 'password'} autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="请输入密码" required /><PasswordToggle visible={passwordVisible} onToggle={() => setPasswordVisible((value) => !value)} /></span></div>
      <div className="numoj-auth-field">
        <label htmlFor="registerClassSelectTrigger">班级</label>
        <div ref={pickerRef} className={`numoj-class-select numoj-register-class-select${pickerOpen ? ' open' : ''}${classError ? ' is-invalid' : ''}`}>
          <input type="hidden" id="registerClassSelect" name="class" value={selectedClass} readOnly />
          <button className="numoj-class-select-trigger" id="registerClassSelectTrigger" type="button" aria-haspopup="listbox" aria-expanded={pickerOpen} aria-controls="registerClassOptions" aria-describedby="registerClassError" aria-invalid={classError} onClick={() => setPickerOpen((value) => !value)}><ClassLogo item={selected} placeholder={!selected} /><span className="numoj-class-select-current"><strong>{selected?.class_cn || '请选择班级'}</strong><small>{selected?.class_en || 'REQUIRED'}</small></span><svg className="numoj-class-select-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m1 1 4 4 4-4" /></svg></button>
          <div className="numoj-class-select-menu" id="registerClassOptions" role="listbox" aria-label="可注册的班级" hidden={!pickerOpen}>{(context.data?.classes || []).map((item) => <button className={`numoj-class-select-option${selectedClass === item.class_en ? ' is-selected' : ''}`} type="button" role="option" aria-selected={selectedClass === item.class_en} onClick={() => {setSelectedClass(item.class_en); setClassError(false); setPickerOpen(false)}} key={item.class_en}><ClassLogo item={item} /><span className="numoj-class-select-option-copy"><strong>{item.class_cn || item.class_en}</strong><small>{item.class_en}</small></span><span className="numoj-class-select-option-state" aria-hidden="true">✓</span></button>)}</div>
          <p className="numoj-class-select-error" id="registerClassError" role="alert" hidden={!classError}>请选择班级</p>
        </div>
      </div>
      <button className="numoj-auth-primary" type="submit" disabled={!enabled || register.isPending}>{register.isPending ? '正在注册…' : '注册'}</button>
    </form>
    <div className="numoj-auth-secondary is-centered"><span>已有账户？</span><Link to="/login">返回登录</Link></div>
  </AuthFrame>
}
