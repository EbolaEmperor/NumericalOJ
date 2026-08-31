import type {ReactNode} from 'react'

import {Link} from './PageNavigation'

type AuthPage = 'login' | 'register' | 'forgot'

const tabs: Array<{id: AuthPage; label: string; path: string}> = [
  {id: 'login', label: '登录', path: '/login'},
  {id: 'register', label: '注册', path: '/register'},
  {id: 'forgot', label: '找回密码', path: '/forgot-password'},
]

export function PasswordToggle({visible, onToggle}: {visible: boolean; onToggle: () => void}) {
  return <button className="numoj-auth-password-toggle" type="button" onClick={onToggle} aria-label={visible ? '隐藏密码' : '显示密码'} aria-pressed={visible}>
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.6" /><path className="numoj-auth-eye-slash" d="M4 4l16 16" /></svg>
  </button>
}

export function AuthFrame({active, children}: {active: AuthPage; children: ReactNode}) {
  return <div className="numoj-site-shell numoj-site-shell-guest numoj-auth-shell" data-numoj-shell>
    <main className="numoj-site-main">
      <div className="numoj-content numoj-auth-page">
        <section className="numoj-auth-card" aria-label="Numerical OJ 账户">
          <span className="numoj-auth-accent" aria-hidden="true" />
          <header className="numoj-auth-brand">
            <Link to="/problems" aria-label="Numerical OJ 首页">
              <span className="numoj-auth-brand-mark" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M4 20Q8 4 12 12T20 4" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" /></svg></span>
              <strong>Numerical OJ</strong>
            </Link>
          </header>
          <nav className="numoj-auth-tabs" aria-label="账户页面">
            {tabs.map((tab) => <Link key={tab.id} to={tab.path} className={`numoj-auth-tab${active === tab.id ? ' is-active' : ''}`} aria-current={active === tab.id ? 'page' : undefined}>{tab.label}</Link>)}
          </nav>
          <div className="numoj-auth-panel">{children}</div>
        </section>
      </div>
    </main>
  </div>
}
