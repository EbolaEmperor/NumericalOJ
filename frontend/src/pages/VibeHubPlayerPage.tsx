import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useRef} from 'react'
import {useLocation, useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {usePageDisplayMode} from '../components/AppShell'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {Link} from '../components/PageNavigation'

interface ProjectResponse extends ApiEnvelope {project: JsonRecord}
interface LeaseResponse extends ApiEnvelope {lease_token: string; proxy_url: string; heartbeat_url: string; release_url: string}

export default function VibeHubPlayerPage() {
  const {slug = ''} = useParams()
  const location = useLocation()
  const setPageDisplayMode = usePageDisplayMode()
  const channel = new URLSearchParams(location.search).get('channel') || 'public'
  const lease = useRef<LeaseResponse | null>(null)
  const project = useQuery({queryKey: ['vibehub', 'project', slug, channel], queryFn: () => apiFetch<ProjectResponse>(`/api/vibehub/projects/${encodeURIComponent(slug)}?view=${encodeURIComponent(channel)}`)})
  const acquire = useMutation({mutationFn: () => apiFetch<LeaseResponse>(`/api/vibehub/projects/${encodeURIComponent(slug)}/runtime/leases?channel=${encodeURIComponent(channel)}`, {method: 'POST'}), onSuccess: (data) => {lease.current = data}})
  useEffect(() => {if (project.data && !acquire.isPending && !acquire.data && !acquire.isError) acquire.mutate()}, [project.data])
  useEffect(() => {
    if (project.data?.project?.title) document.title = `正在游玩 ${String(project.data.project.title)} · VibeHub - Numerical OJ`
  }, [project.data])
  useEffect(() => {
    setPageDisplayMode(project.isError ? 'vibehub-not-found' : 'default')
    return () => setPageDisplayMode('default')
  }, [project.isError, setPageDisplayMode])
  useEffect(() => {
    if (!acquire.data) return
    const timer = window.setInterval(() => {void apiFetch<ApiEnvelope>(acquire.data.heartbeat_url, {method: 'POST'}).catch(() => undefined)}, 20_000)
    return () => {
      window.clearInterval(timer)
      const current = lease.current
      if (current) void fetch(current.release_url, {method: 'POST', credentials: 'same-origin', keepalive: true, headers: {'X-Requested-With': 'XMLHttpRequest', Accept: 'application/json'}})
    }
  }, [acquire.data])
  if (project.isError) return <section className="vibe-not-found">
    <span aria-hidden="true"><i /><i /><i /></span>
    <p className="vibe-section-number">404 / WORK NOT AVAILABLE</p>
    <h1>这件作品暂时不在展台上。</h1>
    <p>{errorMessage(project.error) || '它可能还没有发布，或者正在更新中。'}</p>
    <Link className="vibe-button vibe-button--ink" to="/vibehub"><i className="fas fa-arrow-left" aria-hidden="true" />返回 VibeHub</Link>
  </section>
  return <div className="vibe-player" data-vibehub-player data-project-slug={slug}>
    <iframe className="vibe-player-frame" title={String(project.data?.project?.title || slug)} src={acquire.data?.proxy_url || 'about:blank'} sandbox="allow-scripts allow-forms allow-modals allow-pointer-lock allow-downloads allow-popups allow-popups-to-escape-sandbox" allow="fullscreen" referrerPolicy="no-referrer" />
    {project.isPending || acquire.isPending || !acquire.data && !acquire.isError ? <div className="vibe-player-loading" role="status"><MathCurveLoader className="vibe-player-loader" iconOnly size="lg" colorA="#c95d32" colorB="#c95d32" strokeScale={1.08} ariaLabel="正在启动游戏运行环境" /><strong>正在启动游戏运行环境</strong><p>作品镜像已在保存时构建完成，容器启动后会自动进入。</p></div> : null}
    {acquire.isError ? <div className="vibe-player-error" role="alert"><span><i className="fas fa-triangle-exclamation" /></span><h1>作品暂时没有启动</h1><p>{errorMessage(acquire.error)}</p><div><button type="button" onClick={() => acquire.mutate()}><i className="fas fa-rotate-right" />重新尝试</button><Link to={channel === 'latest' ? '/vibehub?view=mine' : '/vibehub'}>返回{channel === 'latest' ? '我的作品' : '作品列表'}</Link></div></div> : null}
  </div>
}
