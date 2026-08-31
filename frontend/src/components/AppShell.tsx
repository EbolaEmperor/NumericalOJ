import {useQueryClient} from '@tanstack/react-query'
import {createContext, useContext, useEffect, useMemo, useState, type Dispatch, type SetStateAction} from 'react'
import {Outlet, useLocation} from 'react-router-dom'

import {apiFetch} from '../api/client'
import type {ApiEnvelope, NavigationItem} from '../api/types'
import {preloadNavigationRoute} from '../routeLoaders'
import {useSession} from '../session'
import {AccountModals} from './AccountModals'
import {Identicon} from './Identicon'
import {Link, useNavigate} from './PageNavigation'
import {ReactOffcanvas} from './ReactOffcanvas'

interface PrefetchTarget {
  path: string
  queryKey: readonly unknown[]
}

type PageDisplayMode = 'default' | 'vibehub-not-found'

const PageDisplayContext = createContext<Dispatch<SetStateAction<PageDisplayMode>>>(() => undefined)

export function usePageDisplayMode() {
  return useContext(PageDisplayContext)
}

const prefetchTargets: Record<string, readonly PrefetchTarget[]> = {
  library: [{path: '/api/problems?view=library', queryKey: ['problems', 'library', '']}],
  problems: [{path: '/api/problems', queryKey: ['problems', 'homework', '']}],
  submissions: [{path: '/api/submissions?page=1&per_page=30', queryKey: ['submissions', 1, '', '', '']}],
  rankings: [{path: '/api/ranking/competitions', queryKey: ['rankings']}],
  agents: [{path: '/api/agent/sessions?page=1', queryKey: ['agent-tasks', 1, '']}],
  forum: [
    {path: '/api/forum?scope=all', queryKey: ['forum', 'all']},
    {path: '/api/forum/identity', queryKey: ['forum', 'identity']},
  ],
  repository: [
    {path: '/api/repository/context', queryKey: ['repository', 'context']},
    {path: '/api/repository/tree', queryKey: ['repository', 'tree']},
  ],
  vibehub: [{path: '/api/vibehub/projects', queryKey: ['vibehub']}],
  admin: [{path: '/api/admin/users?page=1', queryKey: ['admin', 'users', '', '', 1]}],
  admin_homework: [{path: '/api/admin/homework', queryKey: ['admin', 'homework', '']}],
  ai_detection: [
    {path: '/api/admin/ai-detection/dashboard', queryKey: ['admin', 'ai-detection', 'dashboard']},
    {path: '/api/admin/ai-detection/tasks', queryKey: ['admin', 'ai-detection', 'tasks']},
  ],
  site_config: [
    {path: '/api/admin/dynamic-config/llm-endpoints', queryKey: ['admin', 'dynamic-config', 'endpoints']},
    {path: '/api/admin/dynamic-config/feature-bindings', queryKey: ['admin', 'dynamic-config', 'bindings']},
    {path: '/api/admin/dynamic-config/mail', queryKey: ['admin', 'dynamic-config', 'mail']},
    {path: '/api/admin/dynamic-config/web-search', queryKey: ['admin', 'dynamic-config', 'web-search']},
  ],
}

function warmNavigationItem(id: string, queryClient: ReturnType<typeof useQueryClient>, staleTime: number) {
  preloadNavigationRoute(id === 'library' ? 'problems' : id)
  for (const target of prefetchTargets[id] || []) {
    void queryClient.prefetchQuery({
      queryKey: target.queryKey,
      queryFn: () => apiFetch<ApiEnvelope>(target.path),
      staleTime,
    })
  }
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
  if (item.id === 'library') return pathname === '/problems' && new URLSearchParams(search).get('view') === 'library'
  if (item.id === 'problems') return pathname === '/problems' && new URLSearchParams(search).get('view') !== 'library'
  if (item.id === 'admin') return pathname === '/admin'
  return pathname === item.path || pathname.startsWith(`${item.path}/`)
}

function NavigationLink({item, mobile = false, onNavigate}: {item: NavigationItem; mobile?: boolean; onNavigate?: () => void}) {
  const {session} = useSession()
  const queryClient = useQueryClient()
  const location = useLocation()
  const active = isItemActive(item, location.pathname, location.search)
  const countKey = item.id === 'library' ? 'problems' : item.id === 'problems' ? 'homeworks' : item.id === 'admin' ? 'users' : item.id
  const count = session?.navigation.counts[countKey]
  const prefetch = () => {
    if (!item.spa) return
    warmNavigationItem(item.id, queryClient, 30_000)
  }
  const contents = <><LayoutIcon name={item.icon} /><span className="numoj-nav-label" {...(mobile && item.id === 'problems' ? {'data-problem-list-label': 'mobile'} : {})}>{item.label}</span>{typeof count === 'number' ? <span className="numoj-nav-count">{count}</span> : null}{item.id === 'agents' && session?.navigation.agent_active ? <span className="numoj-nav-dot" aria-label="存在运行中的 Agent 任务" /> : null}</>
  const className = `numoj-nav-item${active ? ' active' : ''}`
  return item.spa
    ? <Link className={className} to={item.path} title={item.label} viewTransition onPointerEnter={prefetch} onFocus={prefetch} onClick={onNavigate}>{contents}</Link>
    : <a className={className} href={item.path} title={item.label} onClick={onNavigate}>{contents}</a>
}

function NavigationGroups({mobile = false, logout, onNavigate, onAccount}: {mobile?: boolean; logout: () => void; onNavigate?: () => void; onAccount: (modal: 'password' | 'classes') => void}) {
  const {session} = useSession()
  const items = session?.navigation.items || []
  const prefix = mobile ? 'numoj-mobile-nav' : 'numoj-nav'
  return <nav className="numoj-sidebar-nav" aria-label={mobile ? '移动主导航' : '主导航入口'}>
    <section className="numoj-nav-group" aria-labelledby={`${prefix}-workspace`}>
      <h2 id={`${prefix}-workspace`}>WORKSPACE</h2>
      {items.filter((item) => item.group === 'workspace').map((item) => <NavigationLink item={item} mobile={mobile} onNavigate={onNavigate} key={item.id} />)}
    </section>
    {items.some((item) => item.group === 'admin') ? <section className="numoj-nav-group" aria-labelledby={`${prefix}-admin`}><h2 id={`${prefix}-admin`}>ADMIN</h2>{items.filter((item) => item.group === 'admin').map((item) => <NavigationLink item={item} mobile={mobile} onNavigate={onNavigate} key={item.id} />)}</section> : null}
    <section className="numoj-nav-group" aria-labelledby={`${prefix}-user`}>
      <h2 id={`${prefix}-user`}>USER</h2>
      <button className="numoj-nav-item" type="button" title="修改密码" onClick={() => {onNavigate?.(); onAccount('password')}}><LayoutIcon name="password" /><span className="numoj-nav-label">修改密码</span></button>
      {session?.user?.is_admin || session?.capabilities.class_adjust_enabled ? <button className="numoj-nav-item" type="button" title="调整班级" onClick={() => {onNavigate?.(); onAccount('classes')}}><LayoutIcon name="classes" /><span className="numoj-nav-label">调整班级</span></button> : null}
      <form className="numoj-logout-form" onSubmit={(event) => {event.preventDefault(); onNavigate?.(); logout()}}><button type="submit" className="numoj-nav-item" title="登出"><LayoutIcon name="logout" /><span className="numoj-nav-label">登出</span></button></form>
    </section>
  </nav>
}

function UserFooter({mobile = false, collapsed = false, toggleSidebar, closeMobile}: {mobile?: boolean; collapsed?: boolean; toggleSidebar?: () => void; closeMobile?: () => void}) {
  const {session} = useSession()
  return <footer className={`numoj-sidebar-footer${mobile ? ' numoj-mobile-sidebar-footer' : ''}`}>
    <div className="numoj-user-summary">
      <Identicon seed={session?.user?.username || ''} />
      <span className="numoj-user-copy"><strong>{session?.user?.username}</strong><small>{session?.user?.is_admin ? '教师' : '学生'}</small></span>
    </div>
    {mobile ? <button className="numoj-sidebar-toggle numoj-mobile-sidebar-close" type="button" onClick={closeMobile} aria-label="关闭侧边栏" title="关闭侧边栏"><LayoutIcon name="collapse-left" /></button> : <button className="numoj-sidebar-toggle" type="button" onClick={toggleSidebar} aria-expanded={!collapsed} aria-label={collapsed ? '展开侧边栏' : '收起侧边栏'} title={collapsed ? '展开侧边栏' : '收起侧边栏'}><span className="numoj-collapse-expanded"><LayoutIcon name="collapse-left" /></span><span className="numoj-collapse-collapsed"><LayoutIcon name="collapse-right" /></span></button>}
  </footer>
}

function contentClass(pathname: string, pageDisplayMode: PageDisplayMode) {
  if (pageDisplayMode === 'vibehub-not-found') return 'container-fluid p-0 vibehub-page'
  if (/^\/problems\/[^/]+/.test(pathname)) return 'container problem-detail-content-shell mt-4'
  if (pathname === '/problems') return 'container mt-4 numoj-problems-content'
  if (/^\/submissions\/[^/]+/.test(pathname)) return 'container-fluid submission-detail-shell'
  if (pathname === '/submissions') return 'container-fluid submission-page-shell'
  if (/^\/rankings\/[^/]+/.test(pathname)) return 'container-fluid p-0 ranking-detail-shell'
  if (pathname.startsWith('/forum')) return 'forum-content-container'
  if (pathname === '/repository') return 'container-fluid p-0 repository-page-shell'
  if (pathname === '/vibehub') return 'container-fluid p-0 vibehub-page vibehub-page--gallery'
  if (pathname === '/vibehub/guide') return 'container-fluid p-0 vibehub-page vibehub-page--guide'
  if (/^\/vibehub\/[^/]+(?:\/play)?$/.test(pathname)) return 'container-fluid p-0 vibehub-player-page'
  if (pathname === '/agents') return 'container-fluid agent-home-shell'
  if (/^\/agents\/[^/]+/.test(pathname)) return 'container-fluid agent-session-shell'
  if (pathname === '/admin') return 'container-fluid p-0 user-admin-shell'
  if (pathname === '/admin/site-config') return 'container-fluid p-0 site-config-shell'
  return 'container mt-4'
}

export function AppShell() {
  const {refresh, session} = useSession()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const location = useLocation()
  const [pageDisplayMode, setPageDisplayMode] = useState<PageDisplayMode>('default')
  const [accountModal, setAccountModal] = useState<'password' | 'classes' | null>(null)
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try { return window.localStorage.getItem('numoj.desktopSidebarCollapsed') === '1' } catch { return false }
  })
  useEffect(() => {
    document.documentElement.classList.toggle('numoj-sidebar-prefers-collapsed', sidebarCollapsed)
    try { window.localStorage.setItem('numoj.desktopSidebarCollapsed', sidebarCollapsed ? '1' : '0') } catch { /* 当前页仍然可正常折叠 */ }
  }, [sidebarCollapsed])

  useEffect(() => {setPageDisplayMode('default')}, [location.pathname])

  useEffect(() => {
    const connection = (navigator as Navigator & {connection?: {saveData?: boolean; effectiveType?: string}}).connection
    if (connection?.saveData || connection?.effectiveType === '2g') return
    const available = (session?.navigation.items || []).filter((item) => item.spa).map((item) => item.id)
    if (!available.length) return
    const priority = ['problems', 'submissions', 'rankings', 'forum'].filter((id) => available.includes(id))
    const secondary = available.filter((id) => !priority.includes(id))
    const browser = window as Window & {requestIdleCallback?: (callback: () => void, options?: {timeout: number}) => number; cancelIdleCallback?: (handle: number) => void}
    const idleHandles: number[] = []
    const timeoutHandles: number[] = []
    let cancelled = false
    const schedule = (callback: () => void, timeout: number, fallbackDelay: number) => {
      if (browser.requestIdleCallback) idleHandles.push(browser.requestIdleCallback(callback, {timeout}))
      else timeoutHandles.push(window.setTimeout(callback, fallbackDelay))
    }
    const warmSecondary = () => {
      if (cancelled) return
      for (const id of secondary) warmNavigationItem(id, queryClient, 60_000)
    }
    const warmPrimary = () => {
      if (cancelled) return
      // 先下载所有当前账号可见页面的代码块，再预取高频页面数据；低频数据放到下一次闲时。
      for (const id of available) preloadNavigationRoute(id === 'library' ? 'problems' : id)
      for (const id of priority) warmNavigationItem(id, queryClient, 60_000)
      schedule(warmSecondary, 5_000, 2_000)
    }
    schedule(warmPrimary, 2_500, 1_200)
    return () => {
      cancelled = true
      for (const handle of idleHandles) browser.cancelIdleCallback?.(handle)
      for (const handle of timeoutHandles) window.clearTimeout(handle)
    }
  }, [queryClient, session?.navigation.items])

  const logout = useMemo(() => () => {
    void apiFetch<ApiEnvelope>('/api/session', {method: 'DELETE'}).then(refresh).then(() => navigate('/login', {replace: true}))
  }, [navigate, refresh])

  const player = pageDisplayMode !== 'vibehub-not-found' && location.pathname !== '/vibehub/guide' && /^\/vibehub\/[^/]+(?:\/play)?$/.test(location.pathname)
  return <div className={`numoj-site-shell numoj-site-shell-authenticated${sidebarCollapsed ? ' is-sidebar-collapsed' : ''}${player ? ' vibehub-player-shell' : ''}`} data-numoj-shell>
    <aside className="numoj-sidebar d-none d-lg-flex" data-numoj-sidebar aria-label="桌面主导航">
      <Link className="numoj-brand" to="/problems" aria-label="Numerical OJ 首页"><BrandMark /><span className="numoj-brand-copy"><strong>Numerical OJ</strong><small>AI-NATIVE JUDGE</small></span></Link>
      <NavigationGroups logout={logout} onAccount={setAccountModal} />
      <UserFooter collapsed={sidebarCollapsed} toggleSidebar={() => setSidebarCollapsed((value) => !value)} />
    </aside>

    <header className="numoj-mobile-topbar d-lg-none" aria-label="移动顶栏">
      <Link className="numoj-mobile-topbar-logo" to="/problems" aria-label="Numerical OJ 首页"><BrandMark /></Link>
      <strong className="numoj-mobile-topbar-title">NumOJ</strong>
      <button className="numoj-mobile-menu-toggle" type="button" aria-controls="offcanvasNavbar" aria-expanded={mobileNavigationOpen} aria-label="打开主导航" onClick={() => setMobileNavigationOpen(true)}><svg className="numoj-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16" /></svg></button>
    </header>
    <ReactOffcanvas open={mobileNavigationOpen} onClose={() => setMobileNavigationOpen(false)} id="offcanvasNavbar" labelledBy="offcanvasNavbarLabel" className="layout-offcanvas-nav numoj-mobile-sidebar">
      <h2 className="visually-hidden" id="offcanvasNavbarLabel">移动主导航</h2>
      <Link className="numoj-brand numoj-mobile-sidebar-brand" to="/problems" aria-label="Numerical OJ 首页" onClick={() => setMobileNavigationOpen(false)}><BrandMark /><span className="numoj-brand-copy"><strong>Numerical OJ</strong><small>AI-NATIVE JUDGE</small></span></Link>
      <NavigationGroups mobile logout={logout} onNavigate={() => setMobileNavigationOpen(false)} onAccount={setAccountModal} />
      <UserFooter mobile closeMobile={() => setMobileNavigationOpen(false)} />
    </ReactOffcanvas>

    <main className="numoj-site-main">
      <AccountModals active={accountModal} onClose={() => setAccountModal(null)} />
      <div className={`numoj-content ${contentClass(location.pathname, pageDisplayMode)}`}>
        <PageDisplayContext.Provider value={setPageDisplayMode}><div className="numoj-spa-route" key={`${location.pathname}${location.search}`}><Outlet /></div></PageDisplayContext.Provider>
      </div>
    </main>
  </div>
}
