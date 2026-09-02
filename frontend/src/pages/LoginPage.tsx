import {useMutation, useQueryClient} from '@tanstack/react-query'
import {useEffect, useState, type FormEvent} from 'react'
import {useLocation} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope} from '../api/types'
import {AuthFrame, PasswordToggle} from '../components/AuthFrame'
import {Link, useNavigate} from '../components/PageNavigation'
import {useSession} from '../session'

export default function LoginPage() {
  const {session, loading, refresh} = useSession()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const successMessage = new URLSearchParams(location.search).get('success')

  useEffect(() => {
    document.title = '登录 - Numerical OJ'
    if (!loading && session?.user) navigate('/problems', {replace: true})
  }, [loading, navigate, session?.user])

  const mutation = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>('/api/session', {method: 'POST', body: JSON.stringify({username, password, next: '/problems'})}),
    onSuccess: async () => {
      queryClient.removeQueries({predicate: (query) => query.queryKey[0] !== 'session'})
      await refresh()
      const target = new URLSearchParams(location.search).get('next')
      navigate(target?.startsWith('/') && !target.startsWith('//') ? target : '/problems', {replace: true})
    },
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (username.trim() && password) mutation.mutate()
  }

  return <AuthFrame active="login">
            {successMessage ? <div className="numoj-auth-alert is-success" role="status">{successMessage}</div> : null}
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
                  <PasswordToggle visible={passwordVisible} onToggle={() => setPasswordVisible((value) => !value)} />
                </span>
              </div>
              <button className="numoj-auth-primary" type="submit" disabled={mutation.isPending}>{mutation.isPending ? '正在登录…' : '登录'}</button>
            </form>
            <div className="numoj-auth-secondary"><Link to="/register">注册新账户</Link><Link to="/forgot-password">忘记密码？</Link></div>
  </AuthFrame>
}
