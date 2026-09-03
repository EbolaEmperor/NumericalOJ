import {useLayoutEffect, useMemo, useRef, useState, type CSSProperties} from 'react'

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

function htmlDetailDocument(content: string, readyToken: string) {
  const csp = [
    "default-src 'none'", "img-src data: blob: https: http:", "media-src data: blob: https: http:",
    "font-src data: blob: https: http:", "style-src 'unsafe-inline' https: http:",
    "script-src 'unsafe-inline' blob: https: http:", "connect-src https: http: wss: ws:",
    "worker-src blob:", "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-src 'none'",
  ].join('; ')

  // React 版已经用 fresh iframe + Blob URL 隔离每份文档。不要再把父页面的
  // Safari 页面缩放反向施加到 body：iframe 的 vw/vh/dvh 本就按自身视口计算，
  // 二次补偿会把正好占满视口的互动内容放大并裁掉底部控制栏。
  const readyScript = `<script>(function(){window.parent.postMessage({type:"numoj:html-detail-ready",token:${JSON.stringify(readyToken)}},"*")})()<\/script>`
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

  // 旧版 Jinja 的关键不只是“fresh iframe + Blob URL”，还要求 replaceWith 后
  // 在同一个浏览器绘制周期内立刻设置 src。普通 useEffect 会等到提交后的绘制
  // 阶段，Safari 此时可能已经为无文档 iframe 缓存了错误的缩放与裁剪合成层。
  // layout effect 保留 React DOM 提交，同时恢复旧版 attach -> src 的同步时序。
  useLayoutEffect(() => {
    const mountedFrame = frameRef.current
    if (!mountedFrame) return undefined
    const frame: HTMLIFrameElement = mountedFrame

    let active = true
    let fallbackTimer: number | null = null
    const readyToken = `${++readySequence}-${Date.now()}`
    const objectUrl = URL.createObjectURL(new Blob(
      [htmlDetailDocument(content, readyToken)],
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
      // React StrictMode 会在开发环境同步执行一次 setup -> cleanup -> setup，且
      // 复用同一个 DOM 节点。若这里立刻导航到空白页，Safari 会把那次空白合成
      // 层留给紧随其后的真实 Blob。推迟到微任务，并只清理仍指向本次 URL 的
      // iframe；新的 setup 若已接管该节点，就只回收旧 Object URL。
      queueMicrotask(() => {
        if (frame.src === objectUrl) {
          frame.removeAttribute('src')
          frame.removeAttribute('srcdoc')
        }
        URL.revokeObjectURL(objectUrl)
      })
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
