import {useQuery} from '@tanstack/react-query'
import {useEffect, useRef, useState, type PointerEvent as ReactPointerEvent, type WheelEvent} from 'react'

import {apiFetch} from '../../api/client'
import type {ApiEnvelope, JsonRecord} from '../../api/types'
import {MonacoEditor} from '../../components/MonacoEditor'
import {MarkdownContent} from '../../components/MarkdownContent'
import {MathCurveLoader} from '../../components/MathCurveLoader'
import {languageSpec, languageSpecForFilename} from '../../editor/codeEditorRuntime'
import {stableAgentDocumentId, statusKey} from './legacyBehavior'

interface FileResponse extends ApiEnvelope {file?: JsonRecord}

function mobilePreview() {
  return typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && window.matchMedia('(max-width: 991.98px)').matches
}

function workspaceFileUrl(sessionId: string, path: string, mode?: 'raw' | 'download') {
  const params = new URLSearchParams({path})
  if (mode === 'raw') params.set('raw', '1')
  if (mode === 'download') params.set('download', '1')
  return `/api/agent/sessions/${encodeURIComponent(sessionId)}/workspace/file?${params}`
}

function previewKind(file: JsonRecord, path: string) {
  const explicit = statusKey(file.preview_kind || file.kind || file.preview_type)
  if (['code', 'markdown', 'pdf', 'image', 'text', 'unsupported'].includes(explicit)) return explicit
  const mime = statusKey(file.mime_type || file.mime)
  if (mime.startsWith('image/')) return 'image'
  if (mime === 'application/pdf') return 'pdf'
  const extension = path.split('.').pop()?.toLowerCase()
  if (['md', 'markdown'].includes(extension || '')) return 'markdown'
  if (languageSpecForFilename(path).language) return 'code'
  return file.is_text === true ? 'text' : 'unsupported'
}

function ImagePreview({url, path}: {url: string; path: string}) {
  const [zoom, setZoom] = useState(1)
  const [offset, setOffset] = useState({x: 0, y: 0})
  const pointer = useRef<{id: number; x: number; y: number} | null>(null)
  const setSafeZoom = (next: number) => {
    const value = Math.min(8, Math.max(.25, next))
    setZoom(value)
    if (value <= 1) setOffset({x: 0, y: 0})
  }
  const pointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest('.agent-image-toolbar') || zoom <= 1) return
    pointer.current = {id: event.pointerId, x: event.clientX - offset.x, y: event.clientY - offset.y}
    event.currentTarget.setPointerCapture(event.pointerId)
    event.currentTarget.classList.add('is-panning')
  }
  const pointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (pointer.current?.id !== event.pointerId) return
    setOffset({x: event.clientX - pointer.current.x, y: event.clientY - pointer.current.y})
  }
  const pointerEnd = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (pointer.current?.id !== event.pointerId) return
    pointer.current = null
    event.currentTarget.classList.remove('is-panning')
  }
  const wheel = (event: WheelEvent<HTMLDivElement>) => {event.preventDefault(); setSafeZoom(zoom * (event.deltaY < 0 ? 1.12 : 1 / 1.12))}
  return <div className="agent-file-image-stage" onWheel={wheel} onPointerDown={pointerDown} onPointerMove={pointerMove} onPointerUp={pointerEnd} onPointerCancel={pointerEnd}><img src={url} alt={path} draggable={false} style={{width: `${zoom * 100}%`, height: 'auto', transform: `translate(${offset.x}px, ${offset.y}px)`}} /><div className="agent-image-toolbar"><button type="button" title="缩小" aria-label="缩小" onClick={() => setSafeZoom(zoom / 1.2)}><i className="fas fa-minus" /></button><output>{Math.round(zoom * 100)}%</output><button type="button" title="放大" aria-label="放大" onClick={() => setSafeZoom(zoom * 1.2)}><i className="fas fa-plus" /></button><button type="button" title="适应宽度" aria-label="适应宽度" onClick={() => {setZoom(1); setOffset({x: 0, y: 0})}}><i className="fas fa-expand" /></button></div></div>
}

export function AgentFilePreview({sessionId, path, close}: {sessionId: string; path: string; close: () => void}) {
  const paneRef = useRef<HTMLElement>(null)
  const closeRef = useRef<HTMLButtonElement>(null)
  const [mobile, setMobile] = useState(mobilePreview)
  const result = useQuery({
    queryKey: ['agent-session', sessionId, 'workspace-file', path],
    queryFn: ({signal}) => apiFetch<FileResponse>(workspaceFileUrl(sessionId, path), {signal}),
    staleTime: 0,
  })
  const file = result.data?.file || result.data || {}
  const kind = previewKind(file, path)
  const inlineContent = file.content ?? file.text
  const needsRawText = ['code', 'markdown', 'text'].includes(kind) && inlineContent == null
  const rawText = useQuery({
    queryKey: ['agent-session', sessionId, 'workspace-file-raw', path],
    queryFn: async ({signal}) => {
      const response = await fetch(workspaceFileUrl(sessionId, path, 'raw'), {credentials: 'same-origin', signal, cache: 'no-store'})
      if (!response.ok) throw new Error(`读取文件失败（HTTP ${response.status}）`)
      return response.text()
    },
    enabled: result.isSuccess && needsRawText,
  })
  const returnFocus = useRef<HTMLElement | null>(null)
  useEffect(() => {
    returnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    if (mobilePreview()) requestAnimationFrame(() => closeRef.current?.focus())
    return () => {
      if (returnFocus.current?.isConnected) returnFocus.current.focus()
    }
  }, [])
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return
    const query = window.matchMedia('(max-width: 991.98px)')
    const update = () => setMobile(query.matches)
    update()
    query.addEventListener?.('change', update)
    return () => query.removeEventListener?.('change', update)
  }, [])
  useEffect(() => {
    const trap = (event: KeyboardEvent) => {
      if (!mobilePreview() || !paneRef.current) return
      if (event.key === 'Escape') {event.preventDefault(); close(); return}
      if (event.key !== 'Tab') return
      const focusable = Array.from(paneRef.current.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), iframe, [tabindex]:not([tabindex="-1"])')).filter((node) => node.getClientRects().length > 0)
      if (!focusable.length) {event.preventDefault(); paneRef.current.focus(); return}
      const first = focusable[0]; const last = focusable[focusable.length - 1]
      if (event.shiftKey && (document.activeElement === first || !paneRef.current.contains(document.activeElement))) {event.preventDefault(); last.focus()}
      else if (!event.shiftKey && (document.activeElement === last || !paneRef.current.contains(document.activeElement))) {event.preventDefault(); first.focus()}
    }
    document.addEventListener('keydown', trap)
    return () => document.removeEventListener('keydown', trap)
  }, [close])
  const name = path.split('/').pop() || path
  const rawUrl = String(file.raw_url || workspaceFileUrl(sessionId, path, 'raw'))
  const content = String(inlineContent ?? rawText.data ?? '')
  const html = String(file.html || file.content_html || file.rendered_html || '')
  const explicitLanguage = String(file.language || '')
  const filenameSpec = languageSpecForFilename(path)
  const requestedSpec = explicitLanguage ? languageSpec(explicitLanguage) : filenameSpec
  const spec = filenameSpec.language && (!requestedSpec.language || ['jsx', 'tsx'].includes(filenameSpec.language)) ? filenameSpec : requestedSpec
  const encodedPath = path.split('/').filter(Boolean).map(encodeURIComponent).join('/')
  const loading = result.isPending || (needsRawText && rawText.isPending)
  const error = result.error || rawText.error
  const retry = () => {
    if (result.isError) void result.refetch()
    else if (rawText.isError) void rawText.refetch()
  }
  return <section ref={paneRef} className="agent-file-pane" aria-label="文件预览" role={mobile ? 'dialog' : undefined} aria-modal={mobile || undefined} tabIndex={mobile ? -1 : undefined}><header className="agent-file-header"><div><i className="fas fa-file" aria-hidden="true" /><span data-agent-file-name title={path}>{name}</span></div><div className="agent-file-actions"><a href={workspaceFileUrl(sessionId, path, 'download')} download={name} title="下载文件" aria-label="下载文件"><i className="fas fa-download" /></a><button ref={closeRef} type="button" title="关闭预览" aria-label="关闭文件预览" onClick={close}><i className="fas fa-times" /></button></div></header><div className="agent-file-surface">{loading ? <div className="agent-file-placeholder"><MathCurveLoader size="sm" label="正在读取文件" /></div> : error ? <div className="agent-file-error" role="alert"><i className="fas fa-times-circle" /><strong>{error instanceof Error ? error.message : '无法读取文件'}</strong><button type="button" onClick={retry}>重试</button></div> : kind === 'code' ? <MonacoEditor key={path} language={spec.language || 'plaintext'} problemId={0} value={content} onChange={() => undefined} idPrefix="agentFile" ariaLabel={`${path}，只读文件预览`} readOnly fontSize={12.5} lineHeight={20} bundle="full" semanticContext="agent-workspace" semanticDocumentId={stableAgentDocumentId(sessionId, path)} modelUri={`file:///agent-workspace/${encodeURIComponent(sessionId)}/${encodedPath}`} wordWrap="off" shellBaseClassName="agent-file-code" hostClassName="agent-file-code" fallbackClassName="agent-file-code-fallback" /> : kind === 'markdown' ? html ? <MarkdownContent className="agent-file-markdown numoj-markdown" html={html} /> : <pre className="agent-file-text">{content}</pre> : kind === 'pdf' ? <iframe className="agent-file-pdf" title={path} referrerPolicy="no-referrer" src={rawUrl} /> : kind === 'image' ? <ImagePreview key={path} url={rawUrl} path={path} /> : kind === 'text' ? <pre className="agent-file-text">{content}</pre> : <div className="agent-file-unsupported"><i className="fas fa-file-circle-question" /><strong>无法预览的文件格式</strong></div>}</div></section>
}
