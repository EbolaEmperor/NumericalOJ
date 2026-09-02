import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useState, type FormEvent} from 'react'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope} from '../api/types'
import {AuthFrame, PasswordToggle} from '../components/AuthFrame'
import {Link, useNavigate} from '../components/PageNavigation'

interface MailContext extends ApiEnvelope {mail_configured: boolean}

export default function ForgotPasswordPage() {
  const navigate = useNavigate()
  const context = useQuery({queryKey: ['auth', 'registration'], queryFn: () => apiFetch<MailContext>('/api/auth/registration')})
  const [step, setStep] = useState<'email' | 'verify'>('email')
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [confirmationVisible, setConfirmationVisible] = useState(false)
  useEffect(() => {document.title = '找回密码 - Numerical OJ'}, [])

  const send = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>('/api/auth/password-reset/code', {method: 'POST', body: JSON.stringify({email: email.trim()})}),
    onSuccess: () => setStep('verify'),
  })
  const reset = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>('/api/auth/password-reset', {method: 'POST', body: JSON.stringify({email: email.trim(), code, new_password: password, confirm_password: confirmation})}),
    onSuccess: (data) => navigate(`/login?success=${encodeURIComponent(data.message || '密码重置成功，请重新登录')}`, {replace: true}),
  })
  const submitEmail = (event: FormEvent) => {event.preventDefault(); if (email.trim()) send.mutate()}
  const submitReset = (event: FormEvent) => {event.preventDefault(); if (code.length === 6 && password && password === confirmation) reset.mutate()}

  return <AuthFrame active="forgot">
    {step === 'email' && !context.isPending && !context.data?.mail_configured ? <p className="numoj-auth-notice" role="status">站点尚未配置邮件服务，请联系管理员</p> : null}
    {context.isError ? <div className="numoj-auth-alert is-error" role="alert"><span>{errorMessage(context.error)}</span><button type="button" className="numoj-auth-link-button" onClick={() => void context.refetch()}>重新加载</button></div> : send.isError || reset.isError ? <div className="numoj-auth-alert is-error" role="alert">{errorMessage(send.error || reset.error)}</div> : null}
    {step === 'email' ? <form className="numoj-auth-form" onSubmit={submitEmail}>
      <div className="numoj-auth-field"><label htmlFor="email">邮箱</label><span className="numoj-auth-control"><input id="email" name="email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="请输入注册邮箱" required autoFocus /></span></div>
      <button className="numoj-auth-primary" type="submit" disabled={context.isPending || !context.data?.mail_configured || send.isPending}>{send.isPending ? '正在发送…' : '发送验证码'}</button>
    </form> : <>
      <p className="numoj-auth-notice">验证码已发送</p>
      <form className="numoj-auth-form" onSubmit={submitReset}>
        <div className="numoj-auth-field"><label htmlFor="code">验证码</label><span className="numoj-auth-control"><input id="code" name="code" type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={6} pattern="[0-9]{6}" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="请输入验证码" required autoFocus /></span></div>
        <div className="numoj-auth-field"><label htmlFor="new_password">新密码</label><span className="numoj-auth-control"><input id="new_password" name="new_password" type={passwordVisible ? 'text' : 'password'} autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="请输入新密码" required /><PasswordToggle visible={passwordVisible} onToggle={() => setPasswordVisible((value) => !value)} /></span></div>
        <div className="numoj-auth-field"><label htmlFor="confirm_password">确认密码</label><span className="numoj-auth-control"><input id="confirm_password" name="confirm_password" type={confirmationVisible ? 'text' : 'password'} autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} placeholder="请再次输入新密码" required /><PasswordToggle visible={confirmationVisible} onToggle={() => setConfirmationVisible((value) => !value)} /></span></div>
        <button className="numoj-auth-primary" type="submit" disabled={reset.isPending}>{reset.isPending ? '正在重置…' : '重置密码'}</button>
      </form>
    </>}
    <div className={`numoj-auth-secondary${step === 'email' ? ' is-centered' : ''}`}>{step === 'verify' ? <button type="button" className="numoj-auth-link-button" onClick={() => setStep('email')}>修改邮箱</button> : null}<Link to="/login">返回登录</Link></div>
  </AuthFrame>
}
