import {useQuery} from '@tanstack/react-query'
import {useEffect, useRef, useState} from 'react'
import {useLocation, useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {usePageDisplayMode} from '../components/AppShell'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {Link} from '../components/PageNavigation'

interface ProjectResponse extends ApiEnvelope {project: JsonRecord}
interface LeaseResponse extends ApiEnvelope {lease_token: string; proxy_url: string; heartbeat_url: string; release_url: string}
type RuntimeError = Error & {status?: number; retryAfterMilliseconds?: number}

const MAX_ACQUIRE_RETRIES = 3

async function parseLeaseResponse(response: globalThis.Response): Promise<LeaseResponse> {
  const payload = await response.json().catch(() => ({success: false, message: '服务器返回了无法读取的响应。'})) as LeaseResponse
  if (!response.ok || !payload.success) {
    const error = new Error(payload.message || '作品启动失败，请稍后重试。') as RuntimeError
    error.status = response.status
    const retryAfter = Number.parseFloat(response.headers.get('Retry-After') || '')
    error.retryAfterMilliseconds = Number.isFinite(retryAfter) ? Math.min(5000, Math.max(250, retryAfter * 1000)) : 1000
    throw error
  }
  return payload
}

function postRelease(releaseUrl: string, beacon: boolean) {
  if (!releaseUrl) return
  if (beacon && navigator.sendBeacon) {
    navigator.sendBeacon(releaseUrl, new Blob(['{}'], {type: 'application/json'}))
    return
  }
  void fetch(releaseUrl, {method: 'POST', credentials: 'same-origin', keepalive: true, headers: {'Content-Type': 'application/json', Accept: 'application/json'}, body: '{}'}).catch(() => undefined)
}

export default function VibeHubPlayerPage() {
  const {slug = ''} = useParams()
  const location = useLocation()
  const setPageDisplayMode = usePageDisplayMode()
  const channel = new URLSearchParams(location.search).get('channel') || 'public'
  const [runtime, setRuntime] = useState<LeaseResponse | null>(null)
  const [runtimeError, setRuntimeError] = useState('')
  const [acquiring, setAcquiring] = useState(false)
  const [frameReady, setFrameReady] = useState(false)
  const [retryGeneration, setRetryGeneration] = useState(0)
  const leaseRef = useRef<LeaseResponse | null>(null)
  const acquireGeneration = useRef(0)
  const project = useQuery({queryKey: ['vibehub', 'project', slug, channel], queryFn: () => apiFetch<ProjectResponse>(`/api/vibehub/projects/${encodeURIComponent(slug)}?view=${encodeURIComponent(channel)}`)})

  useEffect(() => {
    if (project.data?.project?.title) document.title = `正在游玩 ${String(project.data.project.title)} · VibeHub - Numerical OJ`
  }, [project.data])
  useEffect(() => {
    setPageDisplayMode(project.isError ? 'vibehub-not-found' : 'default')
    return () => setPageDisplayMode('default')
  }, [project.isError, setPageDisplayMode])

  useEffect(() => {
    if (!project.data) return
    let leaving = false
    let released = false
    let heartbeatTimer = 0
    let heartbeatPromise: Promise<void> | null = null
    let heartbeatController: AbortController | null = null
    let heartbeatFailures = 0
    let recovering = false

    const release = (beacon: boolean) => {
      const current = leaseRef.current
      if (!current || released) return
      released = true
      if (heartbeatTimer) window.clearInterval(heartbeatTimer)
      heartbeatTimer = 0
      heartbeatController?.abort()
      heartbeatController = null
      heartbeatPromise = null
      postRelease(current.release_url, beacon)
      if (leaseRef.current === current) leaseRef.current = null
    }
    const heartbeat = () => {
      const current = leaseRef.current
      if (!current || released || !current.heartbeat_url || heartbeatPromise) return heartbeatPromise
      const controller = new AbortController()
      heartbeatController = controller
      const timeout = window.setTimeout(() => controller.abort(), 15_000)
      const pending = fetch(current.heartbeat_url, {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', Accept: 'application/json'}, body: '{}', signal: controller.signal})
        .then((response) => {if (!response.ok) throw new Error('heartbeat failed'); if (leaseRef.current === current && !released) heartbeatFailures = 0})
        .catch(() => {
          if (leaseRef.current !== current || released) return
          heartbeatFailures += 1
          if (heartbeatFailures < 3 || recovering || leaving) return
          recovering = true
          release(false)
          setRuntime(null)
          setFrameReady(false)
          window.setTimeout(() => {if (!leaving) {recovering = false; void startAcquire()}}, 500)
        })
        .finally(() => {window.clearTimeout(timeout); if (heartbeatPromise === pending) heartbeatPromise = null; if (heartbeatController === controller) heartbeatController = null})
      heartbeatPromise = pending
      return pending
    }
    const requestLease = async (generation: number, retryCount: number): Promise<LeaseResponse | null> => {
      try {
        const response = await fetch(`/api/vibehub/projects/${encodeURIComponent(slug)}/runtime/leases?channel=${encodeURIComponent(channel)}`, {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', Accept: 'application/json'}, body: '{}'})
        const payload = await parseLeaseResponse(response)
        if (!payload.lease_token || !payload.proxy_url || !payload.heartbeat_url || !payload.release_url) throw new Error('运行服务没有返回完整的租约信息。')
        if (generation !== acquireGeneration.current || leaving) {
          postRelease(payload.release_url, leaving)
          return null
        }
        released = false
        heartbeatFailures = 0
        const normalized = {...payload, proxy_url: `${payload.proxy_url.replace(/\/$/, '')}/`}
        leaseRef.current = normalized
        setRuntime(normalized)
        setRuntimeError('')
        setFrameReady(false)
        heartbeatTimer = window.setInterval(() => {void heartbeat()}, 20_000)
        return normalized
      } catch (caught) {
        const error = caught as RuntimeError
        if (error.status === 429 && retryCount < MAX_ACQUIRE_RETRIES && generation === acquireGeneration.current && !leaving) {
          await new Promise((resolve) => window.setTimeout(resolve, error.retryAfterMilliseconds || 1000))
          if (generation !== acquireGeneration.current || leaving) return null
          return requestLease(generation, retryCount + 1)
        }
        throw error
      }
    }
    async function startAcquire() {
      const generation = ++acquireGeneration.current
      setAcquiring(true)
      setRuntimeError('')
      released = false
      try { await requestLease(generation, 0) }
      catch (error) {if (generation === acquireGeneration.current && !leaving) setRuntimeError(errorMessage(error))}
      finally {if (generation === acquireGeneration.current && !leaving) setAcquiring(false)}
    }
    const pagehide = () => {leaving = true; acquireGeneration.current += 1; release(true)}
    window.addEventListener('pagehide', pagehide)
    void startAcquire()
    return () => {
      leaving = true
      acquireGeneration.current += 1
      window.removeEventListener('pagehide', pagehide)
      release(false)
    }
  }, [channel, project.data, retryGeneration, slug])

  if (project.isError) return <section className="vibe-not-found">
    <span aria-hidden="true"><i /><i /><i /></span>
    <p className="vibe-section-number">404 / WORK NOT AVAILABLE</p>
    <h1>这件作品暂时不在展台上。</h1>
    <p>{errorMessage(project.error) || '它可能还没有发布，或者正在更新中。'}</p>
    <Link className="vibe-button vibe-button--ink" to="/vibehub"><i className="fas fa-arrow-left" aria-hidden="true" />返回 VibeHub</Link>
  </section>
  const loading = project.isPending || acquiring || Boolean(runtime && !frameReady) || !runtime && !runtimeError
  return <div className={`vibe-player${frameReady ? ' is-ready' : ''}`} data-vibehub-player data-project-slug={slug}>
    <iframe className="vibe-player-frame" title={String(project.data?.project?.title || slug)} src={runtime?.proxy_url || 'about:blank'} onLoad={() => {if (runtime) setFrameReady(true)}} sandbox="allow-scripts allow-forms allow-modals allow-pointer-lock allow-downloads allow-popups allow-popups-to-escape-sandbox" allow="fullscreen" referrerPolicy="no-referrer" />
    {loading ? <div className="vibe-player-loading" role="status"><MathCurveLoader className="vibe-player-loader" iconOnly size="lg" colorA="#c95d32" colorB="#c95d32" strokeScale={1.08} ariaLabel="正在启动游戏运行环境" /><strong>正在启动游戏运行环境</strong><p>作品镜像已在保存时构建完成，容器启动后会自动进入。</p></div> : null}
    {runtimeError ? <div className="vibe-player-error" role="alert"><span><i className="fas fa-triangle-exclamation" /></span><h1>作品暂时没有启动</h1><p>{runtimeError}</p><div><button type="button" onClick={() => setRetryGeneration((value) => value + 1)}><i className="fas fa-rotate-right" />重新尝试</button><Link to={channel === 'latest' ? '/vibehub?view=mine' : '/vibehub'}>返回{channel === 'latest' ? '我的作品' : '作品列表'}</Link></div></div> : null}
  </div>
}
