import {useEffect, useMemo, useRef, useState, type CSSProperties} from 'react'

const DEFAULT_HEIGHT = 520
const MIN_HEIGHT = 240
const MAX_HEIGHT = 1200

let readySequence = 0

function numberValue(value: unknown, fallback: number) {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric : fallback
}

function clampHeight(value: unknown) {
  return Math.max(MIN_HEIGHT, Math.min(MAX_HEIGHT, numberValue(value, DEFAULT_HEIGHT)))
}

function contentFingerprint(content: string) {
  // React 需要一个稳定且紧凑的 key，才能像旧版 cloneNode/replaceWith 一样保证
  // 每份详情都得到全新的 iframe，而不把整段评分 HTML 留在 key 中。
  let hash = 2166136261
  for (let index = 0; index < content.length; index += 1) {
    hash ^= content.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return `${content.length}-${(hash >>> 0).toString(36)}`
}

function safariScaleHint() {
  const userAgent = navigator.userAgent || ''
  const isSafari = /Safari\//.test(userAgent) && !/(?:Chrome|Chromium|CriOS|Edg|OPR)\//.test(userAgent)
  if (!isSafari || !window.innerWidth || !window.outerWidth) return 1
  const scale = window.outerWidth / window.innerWidth
  if (!Number.isFinite(scale) || scale <= .25 || scale >= 4) return 1
  const nativeDpr = (window.devicePixelRatio || 1) / scale
  const roundedDpr = Math.round(nativeDpr)
  if (roundedDpr < 1 || roundedDpr > 4 || Math.abs(nativeDpr - roundedDpr) > .03) return 1
  return Math.abs(scale - 1) < .005 ? 1 : scale
}

function htmlDetailDocument(content: string, readyToken: string, scaleHint: number) {
  const csp = [
    "default-src 'none'", "img-src data: blob: https: http:", "media-src data: blob: https: http:",
    "font-src data: blob: https: http:", "style-src 'unsafe-inline' https: http:",
    "script-src 'unsafe-inline' blob: https: http:", "connect-src https: http: wss: ws:",
    "worker-src blob:", "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-src 'none'",
  ].join('; ')

  // 这是旧版多轮 Safari 实机修复后的最终协议。不要改成 CSS zoom，也不要
  // transform iframe 外框：两种做法都会让 WebKit 的绘制坐标和点击坐标分离。
  const readyScript = `<script>(function(){var token=${JSON.stringify(readyToken)};var scale=${JSON.stringify(scaleHint)};var root=document.documentElement;root.setAttribute("data-numoj-embedded-scale",String(scale));if(isFinite(scale)&&scale>0&&Math.abs(scale-1)>=.005){var percent=scale*100;var style=document.createElement("style");style.setAttribute("data-numoj-viewport-fix","");style.textContent="body{transform-origin:0 0!important;transform:scale("+(1/scale)+")!important;width:"+percent+"%!important;height:"+percent+"%!important;min-height:"+percent+"%!important}";document.head.appendChild(style);var body=document.body;var observer=new MutationObserver(function(records){if(!records.some(function(record){return record.type==="childList"||record.type==="characterData"}))return;var visibility=body.style.getPropertyValue("visibility");var priority=body.style.getPropertyPriority("visibility");body.style.setProperty("visibility","hidden","important");void body.offsetHeight;if(visibility)body.style.setProperty("visibility",visibility,priority);else body.style.removeProperty("visibility")});observer.observe(body,{subtree:true,childList:true,characterData:true})}window.parent.postMessage({type:"numoj:html-detail-ready",token:token},"*")})()<\/script>`
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${csp}"><style>html{color-scheme:light}html,body{min-height:100%;margin:0}body{overflow:auto;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}</style></head><body>${content}${readyScript}</body></html>`
}

function setFrameReady(frame: HTMLIFrameElement, ready: boolean) {
  frame.style.visibility = ready ? 'visible' : 'hidden'
  frame.style.opacity = ready ? '1' : '0'
  frame.style.pointerEvents = ready ? 'auto' : 'none'
  frame.setAttribute('aria-busy', ready ? 'false' : 'true')
}

export function useMatchHtmlFrame({
  matchId,
  content,
  requestedHeight,
}: {
  matchId: number
  content: string
  requestedHeight?: number
}) {
  const frameRef = useRef<HTMLIFrameElement>(null)
  const height = clampHeight(requestedHeight)
  const documentKey = useMemo(
    () => `match-${matchId}-${height}-${contentFingerprint(content)}`,
    [content, height, matchId],
  )
  const [readyDocumentKey, setReadyDocumentKey] = useState('')
  const ready = readyDocumentKey === documentKey

  useEffect(() => {
    const mountedFrame = frameRef.current
    if (!mountedFrame) return undefined
    const frame: HTMLIFrameElement = mountedFrame

    let active = true
    let fallbackTimer: number | null = null
    const readyToken = `${++readySequence}-${Date.now()}`
    const objectUrl = URL.createObjectURL(new Blob(
      [htmlDetailDocument(content, readyToken, safariScaleHint())],
      {type: 'text/html;charset=utf-8'},
    ))

    // iframe 已由 documentKey 强制换成新节点；先完成隐藏和尺寸复位，再导航到
    // Blob URL，避免 Safari 把上一份文档的合成层或命中区域复用到新详情。
    setFrameReady(frame, false)
    frame.style.display = 'block'
    frame.style.width = '100%'
    frame.style.maxWidth = 'none'
    frame.style.minHeight = `${MIN_HEIGHT}px`
    frame.style.height = `${height}px`
    frame.style.border = '0'
    frame.style.background = '#fff'
    frame.removeAttribute('src')
    frame.removeAttribute('srcdoc')

    function clearReadyWait() {
      frame.removeEventListener('load', handleLoad)
      window.removeEventListener('message', handleReadyMessage)
      if (fallbackTimer !== null) {
        window.clearTimeout(fallbackTimer)
        fallbackTimer = null
      }
    }

    function markReady() {
      if (!active || frameRef.current !== frame || frame.src !== objectUrl) return
      clearReadyWait()
      // 先在同一消息任务中恢复绘制与命中，再同步 React 状态。Safari 因此不会
      // 多等一个绘制周期，也不会在视觉已出现时仍保留 pointer-events:none。
      setFrameReady(frame, true)
      setReadyDocumentKey(documentKey)
    }

    function handleReadyMessage(event: MessageEvent) {
      if (event.source !== frame.contentWindow) return
      if (!event.data || event.data.type !== 'numoj:html-detail-ready') return
      if (event.data.token !== readyToken) return
      markReady()
    }

    function handleLoad() {
      if (!active || frameRef.current !== frame || frame.src !== objectUrl) return
      frame.removeEventListener('load', handleLoad)
      fallbackTimer = window.setTimeout(markReady, 1500)
    }

    frame.addEventListener('load', handleLoad)
    window.addEventListener('message', handleReadyMessage)
    frame.src = objectUrl

    return () => {
      active = false
      clearReadyWait()
      setFrameReady(frame, false)
      frame.removeAttribute('src')
      frame.removeAttribute('srcdoc')
      URL.revokeObjectURL(objectUrl)
    }
  }, [content, documentKey, height])

  const frameStyle: CSSProperties = {
    display: 'block',
    width: '100%',
    maxWidth: 'none',
    minHeight: MIN_HEIGHT,
    height,
    border: 0,
    background: '#fff',
    visibility: ready ? 'visible' : 'hidden',
    opacity: ready ? 1 : 0,
    pointerEvents: ready ? 'auto' : 'none',
  }

  return {documentKey, frameRef, frameStyle, ready}
}
