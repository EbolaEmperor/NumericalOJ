import {useQueryClient} from '@tanstack/react-query'
import {useEffect, useMemo, useRef} from 'react'
import {Link, Outlet, useLocation, useNavigate} from 'react-router-dom'

import {apiFetch} from '../api/client'
import type {ApiEnvelope, NavigationItem} from '../api/types'
import {preloadNavigationRoute} from '../routeLoaders'
import {useSession} from '../session'

const prefetchTargets: Record<string, {path: string; queryKey: readonly unknown[]}> = {
  library: {path: '/api/problems?view=library', queryKey: ['problems', 'library', '']},
  problems: {path: '/api/problems', queryKey: ['problems', 'homework', '']},
  submissions: {path: '/api/submissions?page=1&per_page=20', queryKey: ['submissions', 1, '', '']},
  rankings: {path: '/api/ranking/competitions', queryKey: ['rankings']},
  agents: {path: '/agent/tasks', queryKey: ['agent-tasks']},
  forum: {path: '/api/forum', queryKey: ['forum']},
  repository: {path: '/api/repository/context', queryKey: ['repository', 'context']},
  vibehub: {path: '/api/vibehub/projects', queryKey: ['vibehub']},
  admin: {path: '/api/admin/users', queryKey: ['admin', 'users', '']},
}

const iconPaths: Record<string, string[]> = {
  homework: ['M4 6h16M4 12h16M4 18h16'],
  submissions: ['m9 11 3 3L22 4M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11'],
  repository: ['M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3M8 12h8M12 8v8'],
  forum: ['M21 15a4 4 0 0 1-4 4H8l-5 3v-7a4 4 0 0 1-1-2.6V7a4 4 0 0 1 4-4h11a4 4 0 0 1 4 4Z', 'M7 8h10M7 12h7'],
  ranking: ['M6 2v20M18 2v20M2 6h20M2 18h20'],
  vibehub: ['M12 2 9.8 8.2 3 10.5l5.4 4.1L6.8 22l5.2-4 5.2 4-1.6-7.4 5.4-4.1-6.8-2.3Z', 'm4 4 1 1M20 4l-1 1M2 16l1-.3M22 16l-1-.3'],
  library: ['M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5Z', 'M4 5.5v14M8 7h8M8 11h6'],
  users: ['M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75'],
  'admin-homework': ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z', 'M14 2v6h6M8 13h8M8 17h8'],
  agent: ['M12 8V4H8M2 14h20M6 20h12a2 2 0 0 0 2-2v-6H4v6a2 2 0 0 0 2 2ZM8 8h8v6H8Z'],
  ai: ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z', 'm9 12 2 2 4-5'],
  'site-config': ['M4 6h10M18 6h2M4 12h2M10 12h10M4 18h7M15 18h5'],
  password: ['M12 17a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM6 10V8a6 6 0 1 1 12 0v2M5 10h14a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2Z'],
  classes: ['M8 7h12M8 12h10M8 17h12M4 7l1.5 1.5L8 6M4 17l1.5 1.5L8 16'],
  logout: ['M10 17l5-5-5-5M15 12H3M21 19V5a2 2 0 0 0-2-2h-6'],
  'collapse-left': ['m15 18-6-6 6-6'],
  'collapse-right': ['m9 18 6-6-6-6'],
}

function LayoutIcon({name}: {name: string}) {
  return <svg className="numoj-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{(iconPaths[name] || []).map((path, index) => <path d={path} key={index} />)}</svg>
}

function BrandMark() {
  return <span className="numoj-brand-mark" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M4 20Q8 4 12 12T20 4" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" /></svg></span>
}

function isItemActive(item: NavigationItem, pathname: string, search: string) {
  if (item.id === 'library') return pathname === '/app/problems' && new URLSearchParams(search).get('view') === 'library'
  if (item.id === 'problems') return pathname === '/app/problems' && new URLSearchParams(search).get('view') !== 'library'
  if (item.id === 'admin') return pathname === '/app/admin'
  return pathname === item.path || pathname.startsWith(`${item.path}/`)
}

function NavigationLink({item, mobile = false}: {item: NavigationItem; mobile?: boolean}) {
  const {session} = useSession()
  const queryClient = useQueryClient()
  const location = useLocation()
  const active = isItemActive(item, location.pathname, location.search)
  const countKey = item.id === 'library' ? 'problems' : item.id === 'problems' ? 'homeworks' : item.id
  const count = session?.navigation.counts[countKey]
  const prefetch = () => {
    if (!item.spa) return
    preloadNavigationRoute(item.id === 'library' ? 'problems' : item.id)
    const target = prefetchTargets[item.id]
    if (target) void queryClient.prefetchQuery({queryKey: target.queryKey, queryFn: () => apiFetch<ApiEnvelope>(target.path), staleTime: 20_000})
  }
  const contents = <><LayoutIcon name={item.icon} /><span className="numoj-nav-label" {...(mobile && item.id === 'problems' ? {'data-problem-list-label': 'mobile'} : {})}>{item.label}</span>{typeof count === 'number' ? <span className="numoj-nav-count">{count}</span> : null}{item.id === 'agents' && session?.navigation.agent_active ? <span className="numoj-nav-dot" aria-label="存在运行中的 Agent 任务" /> : null}</>
  const className = `numoj-nav-item${active ? ' active' : ''}`
  return item.spa
    ? <Link className={className} to={item.path} title={item.label} onPointerEnter={prefetch} onFocus={prefetch}>{contents}</Link>
    : <a className={className} href={item.path} title={item.label}>{contents}</a>
}

function NavigationGroups({mobile = false, logout}: {mobile?: boolean; logout: () => void}) {
  const {session} = useSession()
  const items = session?.navigation.items || []
  const prefix = mobile ? 'numoj-mobile-nav' : 'numoj-nav'
  return <nav className="numoj-sidebar-nav" aria-label={mobile ? '移动主导航' : '主导航入口'}>
    <section className="numoj-nav-group" aria-labelledby={`${prefix}-workspace`}>
      <h2 id={`${prefix}-workspace`}>WORKSPACE</h2>
      {items.filter((item) => item.group === 'workspace').map((item) => <NavigationLink item={item} mobile={mobile} key={item.id} />)}
    </section>
    {items.some((item) => item.group === 'admin') ? <section className="numoj-nav-group" aria-labelledby={`${prefix}-admin`}><h2 id={`${prefix}-admin`}>ADMIN</h2>{items.filter((item) => item.group === 'admin').map((item) => <NavigationLink item={item} mobile={mobile} key={item.id} />)}</section> : null}
    <section className="numoj-nav-group" aria-labelledby={`${prefix}-user`}>
      <h2 id={`${prefix}-user`}>USER</h2>
      <a className="numoj-nav-item" href="#" data-bs-toggle="modal" data-bs-target="#changePasswordModal" title="修改密码"><LayoutIcon name="password" /><span className="numoj-nav-label">修改密码</span></a>
      {session?.user?.is_admin || session?.capabilities.class_adjust_enabled ? <a className="numoj-nav-item" href="#" data-bs-toggle="modal" data-bs-target="#classManagerModal" title="调整班级"><LayoutIcon name="classes" /><span className="numoj-nav-label">调整班级</span></a> : null}
      <form className="numoj-logout-form" onSubmit={(event) => {event.preventDefault(); logout()}}><button type="submit" className="numoj-nav-item" title="登出"><LayoutIcon name="logout" /><span className="numoj-nav-label">登出</span></button></form>
    </section>
  </nav>
}

function UserFooter({mobile = false}: {mobile?: boolean}) {
  const {session} = useSession()
  const avatarRef = useRef<HTMLSpanElement>(null)
  useEffect(() => {
    const painter = (window as Window & {NumojIdenticon?: {paint: (element: Element, cells: unknown, label: string) => void; cellsForSeed: (seed: string) => unknown}}).NumojIdenticon
    if (painter && avatarRef.current && session?.user?.username) painter.paint(avatarRef.current, painter.cellsForSeed(session.user.username), session.user.username)
  }, [session?.user?.username])
  return <footer className={`numoj-sidebar-footer${mobile ? ' numoj-mobile-sidebar-footer' : ''}`}>
    <div className="numoj-user-summary">
      <span ref={avatarRef} className="numoj-avatar" data-numoj-user-avatar data-avatar-seed={session?.user?.username} data-avatar-label={session?.user?.username} aria-hidden="true">{session?.user?.username.slice(0, 2).toUpperCase()}</span>
      <span className="numoj-user-copy"><strong>{session?.user?.username}</strong><small>{session?.user?.is_admin ? '教师' : '学生'}</small></span>
    </div>
    {mobile ? <button className="numoj-sidebar-toggle numoj-mobile-sidebar-close" type="button" data-bs-dismiss="offcanvas" aria-label="关闭侧边栏" title="关闭侧边栏"><LayoutIcon name="collapse-left" /></button> : <button className="numoj-sidebar-toggle" type="button" data-numoj-sidebar-toggle aria-expanded="true" aria-label="收起侧边栏" title="收起侧边栏"><span className="numoj-collapse-expanded"><LayoutIcon name="collapse-left" /></span><span className="numoj-collapse-collapsed"><LayoutIcon name="collapse-right" /></span></button>}
  </footer>
}

function AccountModals() {
  const {session} = useSession()
  if (!session?.user) return null
  const mailConfigured = session.capabilities.mail_service_configured
  const classAdjustEnabled = session.capabilities.class_adjust_enabled
  const canManageClasses = Boolean(session.user.is_admin) || classAdjustEnabled
  return (
    <>
      <div className="numoj-account-toast" id="accountModalToast" role="status" aria-live="polite" hidden />
      <div className="modal fade numoj-account-modal numoj-password-modal" id="changePasswordModal" tabIndex={-1} aria-labelledby="changePasswordModalLabel" aria-hidden="true">
        <div className="modal-dialog modal-dialog-centered modal-dialog-scrollable">
          <div className="modal-content">
            <span className="numoj-account-modal-accent" aria-hidden="true" />
            <div className="modal-header">
              <div className="numoj-account-modal-title"><span className="numoj-account-kicker">SECURITY · PASSWORD</span><h2 className="modal-title" id="changePasswordModalLabel">修改密码</h2></div>
              <button type="button" className="numoj-account-close" data-bs-dismiss="modal" aria-label="关闭修改密码弹窗"><span aria-hidden="true">×</span></button>
            </div>
            <form id="passwordForm" method="POST" action="/change_password" noValidate data-password-code-url="/send_password_code" data-user-email={session.user.email || ''}>
              <div className="modal-body numoj-account-modal-body">
                <section className="numoj-account-section" aria-labelledby="passwordIdentityTitle">
                  <div className="numoj-account-section-heading"><h3 id="passwordIdentityTitle">验证身份</h3><span>STEP 01 / 02</span></div>
                  <div className="numoj-account-identity"><span className="numoj-account-identity-icon" aria-hidden="true">@</span><span className="numoj-account-identity-copy"><strong>{session.user.email || '尚未设置邮箱'}</strong><small>{mailConfigured ? '验证码仅发送至当前账户邮箱' : '站点尚未配置邮件服务，请联系管理员'}</small></span><span className="numoj-account-state">{mailConfigured ? '可用' : '不可用'}</span></div>
                </section>
                <div className="numoj-account-form-stack"><div className="numoj-account-field"><div className="numoj-account-input numoj-account-input-action"><input id="passwordCodeInput" name="code" type="text" inputMode="numeric" maxLength={6} autoComplete="one-time-code" placeholder="••••••" aria-label="验证码" aria-describedby="passwordCodeMessage" required /><button type="button" id="sendPasswordCodeBtn" disabled={!mailConfigured} aria-disabled={!mailConfigured} title={mailConfigured ? undefined : '站点尚未配置邮件服务，请联系管理员'}>发送验证码</button></div><p className="numoj-account-field-message" id="passwordCodeMessage" aria-live="polite">发送后 5 分钟内有效。</p></div></div>
                <div className="numoj-account-form-stack">
                  <div className="numoj-account-field"><div className="numoj-account-field-heading"><label htmlFor="newPasswordInput">新密码</label><span id="passwordStrengthLabel">尚未输入</span></div><div className="numoj-account-input"><input id="newPasswordInput" name="new_password" type="password" minLength={6} autoComplete="new-password" placeholder="至少输入 6 个字符" required /></div><div className="numoj-password-meter" id="passwordStrengthMeter" data-level="0" role="progressbar" aria-label="密码强度" aria-valuemin={0} aria-valuemax={3} aria-valuenow={0}><span /><span /><span /></div><div className="numoj-password-rules" id="passwordRules"><span id="passwordRuleLength">至少 6 个字符</span><span id="passwordRuleMix">建议同时包含字母与数字</span></div></div>
                  <div className="numoj-account-field"><div className="numoj-account-field-heading"><label htmlFor="confirmPasswordInput">确认新密码</label><span>再次输入</span></div><div className="numoj-account-input"><input id="confirmPasswordInput" name="confirm_password" type="password" autoComplete="new-password" placeholder="重复新密码" aria-describedby="passwordMatchMessage" required /></div><p className="numoj-account-field-message" id="passwordMatchMessage" aria-live="polite" hidden /></div>
                </div>
                <p className="numoj-account-form-status" id="passwordFormStatus" role="status" aria-live="polite" hidden />
              </div>
              <div className="modal-footer"><span className="numoj-account-footer-note">FORM · VALIDATION INLINE</span><div className="numoj-account-footer-actions"><button type="button" className="numoj-account-button" data-bs-dismiss="modal">取消</button><button type="submit" className="numoj-account-button numoj-account-button-dark" id="passwordSubmitBtn" disabled>确认修改</button></div></div>
            </form>
          </div>
        </div>
      </div>
      {canManageClasses ? (
        <div className="modal fade numoj-account-modal numoj-class-modal" id="classManagerModal" tabIndex={-1} aria-labelledby="classManagerLabel" aria-hidden="true" data-is-admin={session.user.is_admin ? '1' : '0'} data-class-adjust-enabled={classAdjustEnabled ? '1' : '0'} data-classes-url="/me/classes" data-join-class-url="/me/join_class" data-leave-class-url="/me/leave_class" data-class-adjust-url="/admin/class_adjust">
          <div className="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
            <div className="modal-content">
              <span className="numoj-account-modal-accent" aria-hidden="true" />
              <div className="modal-header">
                <div className="numoj-account-modal-title"><span className="numoj-account-kicker">MEMBERSHIP · CLASSES</span><h2 className="modal-title" id="classManagerLabel">调整班级</h2></div>
                <div className="numoj-class-header-actions">
                  {session.user.is_admin ? <label className="numoj-class-permission" htmlFor="classAdjustSwitch"><input type="checkbox" id="classAdjustSwitch" defaultChecked={classAdjustEnabled} /><span className="numoj-class-switch-track" aria-hidden="true"><span /></span><span id="classAdjustLabel">学生自助：{classAdjustEnabled ? '允许' : '禁止'}</span></label> : null}
                  <button type="button" className="numoj-account-close" data-bs-dismiss="modal" aria-label="关闭调整班级弹窗"><span aria-hidden="true">×</span></button>
                </div>
              </div>
              <div className="modal-body numoj-account-modal-body">
                <section className="numoj-account-section" aria-labelledby="myClassesTitle"><div className="numoj-account-section-heading"><h3 id="myClassesTitle">我的班级</h3><span id="classMembershipCount">正在加载</span></div><div className="numoj-membership-list" id="myClassesBox" aria-live="polite"><div className="numoj-membership-state"><span className="math-curve-loader" data-math-curve-loader data-size="sm"><span className="math-curve-loader__label">正在加载班级…</span></span></div></div></section>
                <section className="numoj-account-section" aria-labelledby="joinClassTitle"><div className="numoj-account-section-heading"><h3 id="joinClassTitle">加入新班级</h3><span>AVAILABLE</span></div><div className="numoj-class-join-row"><div className="numoj-class-select" id="joinClassPicker" data-numoj-class-select data-class-select-placeholder="请选择班级" data-class-select-placeholder-code="AVAILABLE"><input type="hidden" id="joinClassSelect" data-class-select-input value="" /><button className="numoj-class-select-trigger" type="button" aria-haspopup="listbox" aria-expanded="false" aria-controls="joinClassOptions" data-class-select-trigger><span className="numoj-class-select-logo is-placeholder" data-class-select-current-logo aria-hidden="true" /><span className="numoj-class-select-current"><strong data-class-select-current-label>请选择班级</strong><small data-class-select-current-code>AVAILABLE</small></span><i className="fas fa-chevron-down numoj-class-select-chevron" aria-hidden="true" /></button><div className="numoj-class-select-menu" id="joinClassOptions" role="listbox" aria-label="可加入的班级" data-class-select-menu hidden /></div><button className="numoj-account-button numoj-account-button-brand" id="joinClassBtn" type="button" disabled>加入班级</button></div></section>
              </div>
              <div className="modal-footer"><span className="numoj-account-footer-note">CHANGES · SAVED IMMEDIATELY</span><div className="numoj-account-footer-actions"><button type="button" className="numoj-account-button numoj-account-button-dark" data-bs-dismiss="modal">完成</button></div></div>
            </div>
          </div>
        </div>
      ) : null}
    </>
  )
}

function contentClass(pathname: string) {
  if (/^\/app\/problems\/[^/]+/.test(pathname)) return 'container problem-detail-content-shell mt-4'
  if (pathname === '/app/problems') return 'container mt-4 numoj-problems-content'
  if (/^\/app\/submissions\/[^/]+/.test(pathname)) return 'container-fluid submission-detail-shell'
  if (pathname === '/app/submissions') return 'container-fluid submission-page-shell'
  if (/^\/app\/rankings\/[^/]+/.test(pathname)) return 'container-fluid p-0 ranking-detail-shell'
  if (pathname.startsWith('/app/forum')) return 'forum-content-container'
  if (pathname === '/app/repository') return 'container-fluid p-0 repository-page-shell'
  if (pathname === '/app/vibehub') return 'container-fluid p-0 vibehub-page vibehub-page--gallery'
  if (pathname === '/app/agents') return 'container-fluid agent-home-shell'
  if (pathname === '/app/admin') return 'container-fluid p-0 user-admin-shell'
  return 'container mt-4'
}

export function AppShell() {
  const {refresh} = useSession()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const location = useLocation()
  useEffect(() => {
    let cancelled = false
    const classSelect = document.createElement('script')
    const layout = document.createElement('script')
    classSelect.src = '/static/app/class-select.js'
    classSelect.dataset.numojSpaRuntime = 'class-select'
    layout.src = '/static/app/layout.js'
    layout.dataset.numojSpaRuntime = 'layout'
    classSelect.addEventListener('load', () => {
      if (!cancelled) document.body.appendChild(layout)
    }, {once: true})
    document.body.appendChild(classSelect)
    return () => {
      cancelled = true
      classSelect.remove()
      layout.remove()
    }
  }, [])

  useEffect(() => {
    const connection = (navigator as Navigator & {connection?: {saveData?: boolean; effectiveType?: string}}).connection
    if (connection?.saveData || connection?.effectiveType === '2g') return
    const warm = () => {
      for (const id of ['problems', 'submissions', 'rankings', 'forum']) {
        preloadNavigationRoute(id)
        const target = prefetchTargets[id]
        void queryClient.prefetchQuery({queryKey: target.queryKey, queryFn: () => apiFetch<ApiEnvelope>(target.path), staleTime: 60_000})
      }
    }
    const browser = window as Window & {requestIdleCallback?: (callback: () => void, options?: {timeout: number}) => number; cancelIdleCallback?: (handle: number) => void}
    if (browser.requestIdleCallback) {
      const handle = browser.requestIdleCallback(warm, {timeout: 2_500})
      return () => browser.cancelIdleCallback?.(handle)
    }
    const handle = window.setTimeout(warm, 1_200)
    return () => window.clearTimeout(handle)
  }, [queryClient])

  const logout = useMemo(() => () => {
    void apiFetch<ApiEnvelope>('/logout', {method: 'POST'}).then(refresh).then(() => navigate('/app/login', {replace: true}))
  }, [navigate, refresh])

  return <div className="numoj-site-shell numoj-site-shell-authenticated" data-numoj-shell>
    <aside className="numoj-sidebar d-none d-lg-flex" data-numoj-sidebar aria-label="桌面主导航">
      <Link className="numoj-brand" to="/app/problems" aria-label="Numerical OJ 首页"><BrandMark /><span className="numoj-brand-copy"><strong>Numerical OJ</strong><small>AI-NATIVE JUDGE</small></span></Link>
      <NavigationGroups logout={logout} />
      <UserFooter />
    </aside>

    <header className="numoj-mobile-topbar d-lg-none" aria-label="移动顶栏">
      <Link className="numoj-mobile-topbar-logo" to="/app/problems" aria-label="Numerical OJ 首页"><BrandMark /></Link>
      <strong className="numoj-mobile-topbar-title">NumOJ</strong>
      <button className="numoj-mobile-menu-toggle" type="button" data-bs-toggle="offcanvas" data-bs-target="#offcanvasNavbar" aria-controls="offcanvasNavbar" aria-label="打开主导航"><svg className="numoj-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16" /></svg></button>
    </header>
    <aside className="offcanvas offcanvas-start d-lg-none layout-offcanvas-nav numoj-mobile-sidebar" tabIndex={-1} id="offcanvasNavbar" aria-labelledby="offcanvasNavbarLabel" data-numoj-mobile-sidebar>
      <h2 className="visually-hidden" id="offcanvasNavbarLabel">移动主导航</h2>
      <Link className="numoj-brand numoj-mobile-sidebar-brand" to="/app/problems" aria-label="Numerical OJ 首页"><BrandMark /><span className="numoj-brand-copy"><strong>Numerical OJ</strong><small>AI-NATIVE JUDGE</small></span></Link>
      <NavigationGroups mobile logout={logout} />
      <UserFooter mobile />
    </aside>

    <main className="numoj-site-main">
      <AccountModals />
      <div className={`numoj-content ${contentClass(location.pathname)}`}>
        <div className="numoj-spa-route" key={`${location.pathname}${location.search}`}><Outlet /></div>
      </div>
    </main>
  </div>
}
