import {useMutation} from '@tanstack/react-query'
import {useEffect, useState, type FormEvent} from 'react'
import {Link, useLocation, useNavigate} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope} from '../api/types'
import {useSession} from '../session'

export default function LoginPage() {
  const {session, loading, refresh} = useSession()
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)

  useEffect(() => {
    document.title = '登录 - Numerical OJ'
    if (!loading && session?.user) navigate('/app/problems', {replace: true})
  }, [loading, navigate, session?.user])

  const mutation = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>('/login', {method: 'POST', body: JSON.stringify({username, password, next: '/app/problems'})}),
    onSuccess: async () => {
      await refresh()
      const target = new URLSearchParams(location.search).get('next')
      navigate(target?.startsWith('/app') ? target : '/app/problems', {replace: true})
    },
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (username.trim() && password) mutation.mutate()
  }

  return <div className="numoj-site-shell numoj-site-shell-guest numoj-auth-shell" data-numoj-shell>
    <main className="numoj-site-main">
      <div className="numoj-content numoj-auth-page">
        <section className="numoj-auth-card" aria-label="Numerical OJ 账户">
          <span className="numoj-auth-accent" aria-hidden="true" />
          <header className="numoj-auth-brand">
            <Link to="/app/problems" aria-label="Numerical OJ 首页">
              <span className="numoj-auth-brand-mark" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M4 20Q8 4 12 12T20 4" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" /></svg></span>
              <strong>Numerical OJ</strong>
            </Link>
          </header>
          <nav className="numoj-auth-tabs" aria-label="账户页面">
            <Link to="/app/login" className="numoj-auth-tab is-active" aria-current="page">登录</Link>
            <a href="/register" className="numoj-auth-tab">注册</a>
            <a href="/forgot_password" className="numoj-auth-tab">找回密码</a>
          </nav>
          <div className="numoj-auth-panel">
            {mutation.isError ? <div className="numoj-auth-alert is-error" role="alert">{errorMessage(mutation.error)}</div> : null}
            <form className="numoj-auth-form" onSubmit={submit}>
              <div className="numoj-auth-field">
                <label htmlFor="username">学号</label>
                <span className="numoj-auth-control"><input id="username" name="username" type="text" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="请输入学号" required autoFocus /></span>
              </div>
              <div className="numoj-auth-field">
                <label htmlFor="password">密码</label>
                <span className="numoj-auth-control">
                  <input id="password" name="password" type={passwordVisible ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="请输入密码" required />
                  <button className="numoj-auth-password-toggle" type="button" onClick={() => setPasswordVisible((value) => !value)} aria-label={passwordVisible ? '隐藏密码' : '显示密码'} aria-pressed={passwordVisible}>
                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.6" /><path className="numoj-auth-eye-slash" d="M4 4l16 16" /></svg>
                  </button>
                </span>
              </div>
              <button className="numoj-auth-primary" type="submit" disabled={mutation.isPending}>{mutation.isPending ? '正在登录…' : '登录'}</button>
            </form>
            <div className="numoj-auth-secondary"><a href="/register">注册新账户</a><a href="/forgot_password">忘记密码？</a></div>
          </div>
        </section>
      </div>
    </main>
  </div>
}
