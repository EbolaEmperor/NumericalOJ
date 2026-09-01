import {forwardRef, useCallback, type MouseEvent} from 'react'
import {
  Link as RouterLink,
  useNavigate as useRouterNavigate,
  type LinkProps,
  type NavigateFunction,
  type NavigateOptions,
  type To,
} from 'react-router-dom'

const PAGE_EXIT_MS = 260
const PAGE_ENTER_DELAY_MS = PAGE_EXIT_MS / 2
const PAGE_ENTER_MS = 260
const PAGE_TRANSITION_SNAPSHOT_SELECTOR = '[data-numoj-page-transition-snapshot]'
let pageSnapshotCleanupTimer: number | undefined
let pageEnteringCleanupTimer: number | undefined

function objectPositionFactor(value: string | undefined, fallback = 0.5) {
  if (!value) return fallback
  if (value === 'left' || value === 'top') return 0
  if (value === 'right' || value === 'bottom') return 1
  if (value === 'center') return 0.5
  if (value.endsWith('%')) {
    const percentage = Number.parseFloat(value)
    if (Number.isFinite(percentage)) return percentage / 100
  }
  return fallback
}

function drawSnapshotImage(
  context: CanvasRenderingContext2D,
  source: HTMLImageElement,
  width: number,
  height: number,
  style: CSSStyleDeclaration,
  pixelRatio: number,
) {
  const naturalWidth = source.naturalWidth
  const naturalHeight = source.naturalHeight
  if (!source.complete || naturalWidth <= 0 || naturalHeight <= 0) return

  const fit = style.objectFit || 'fill'
  if (fit === 'fill') {
    context.drawImage(source, 0, 0, width, height)
    return
  }

  const containScale = Math.min(width / naturalWidth, height / naturalHeight)
  const scale = fit === 'cover'
    ? Math.max(width / naturalWidth, height / naturalHeight)
    : fit === 'none'
      ? pixelRatio
      : fit === 'scale-down'
        ? Math.min(pixelRatio, containScale)
        : containScale
  const drawnWidth = naturalWidth * scale
  const drawnHeight = naturalHeight * scale
  const [positionX, positionY] = style.objectPosition.trim().split(/\s+/)
  const left = (width - drawnWidth) * objectPositionFactor(positionX)
  const top = (height - drawnHeight) * objectPositionFactor(positionY)
  context.drawImage(source, left, top, drawnWidth, drawnHeight)
}

function freezeSnapshotImage(source: HTMLImageElement, clone: HTMLImageElement) {
  const rect = source.getBoundingClientRect()
  const style = window.getComputedStyle(source)
  const pixelRatio = Math.min(window.devicePixelRatio || 1, 2)
  const layoutWidth = source.offsetWidth || rect.width
  const layoutHeight = source.offsetHeight || rect.height
  const visible = rect.right > 0
    && rect.bottom > 0
    && rect.left < window.innerWidth
    && rect.top < window.innerHeight
  const canvas = document.createElement('canvas')
  canvas.dataset.numojSnapshotImage = 'true'
  canvas.className = clone.className
  canvas.width = visible ? Math.max(1, Math.round(layoutWidth * pixelRatio)) : 1
  canvas.height = visible ? Math.max(1, Math.round(layoutHeight * pixelRatio)) : 1
  canvas.style.cssText = clone.style.cssText
  canvas.style.boxSizing = style.boxSizing
  canvas.style.display = style.display
  canvas.style.position = style.position
  canvas.style.inset = style.inset
  canvas.style.zIndex = style.zIndex
  canvas.style.width = `${layoutWidth}px`
  canvas.style.height = `${layoutHeight}px`
  canvas.style.minWidth = style.minWidth
  canvas.style.minHeight = style.minHeight
  canvas.style.maxWidth = style.maxWidth
  canvas.style.maxHeight = style.maxHeight
  canvas.style.margin = style.margin
  canvas.style.border = style.border
  canvas.style.borderRadius = style.borderRadius
  canvas.style.opacity = style.opacity
  canvas.style.transform = style.transform
  canvas.style.transformOrigin = style.transformOrigin
  canvas.style.filter = style.filter
  canvas.style.clipPath = style.clipPath
  canvas.style.background = style.background
  canvas.style.boxShadow = style.boxShadow
  canvas.style.mixBlendMode = style.mixBlendMode
  canvas.style.flex = style.flex
  canvas.style.alignSelf = style.alignSelf
  canvas.style.order = style.order
  canvas.style.gridArea = style.gridArea
  canvas.style.verticalAlign = style.verticalAlign

  try {
    const context = canvas.getContext('2d')
    if (context && visible) drawSnapshotImage(context, source, canvas.width, canvas.height, style, pixelRatio)
  } catch {
    // 跨域或尚未解码的图片保持为当前空白帧，不能在退场过程中突然补绘。
  }
  clone.replaceWith(canvas)
}

function copyScrollOffsets(source: HTMLElement, clone: HTMLElement) {
  clone.scrollTop = source.scrollTop
  clone.scrollLeft = source.scrollLeft

  const sourceElements = source.querySelectorAll<HTMLElement>('*')
  const cloneElements = clone.querySelectorAll<HTMLElement>('*')
  sourceElements.forEach((element, index) => {
    const clonedElement = cloneElements[index]
    if (!clonedElement) return
    clonedElement.scrollTop = element.scrollTop
    clonedElement.scrollLeft = element.scrollLeft
    if (element instanceof HTMLImageElement && clonedElement instanceof HTMLImageElement) {
      freezeSnapshotImage(element, clonedElement)
    } else if (element instanceof HTMLCanvasElement && clonedElement instanceof HTMLCanvasElement) {
      clonedElement.width = element.width
      clonedElement.height = element.height
      try {
        clonedElement.getContext('2d')?.drawImage(element, 0, 0)
      } catch {
        // WebGL 或受保护画布无法复制时保持透明，不影响页面切换。
      }
    }
  })
}

/**
 * 声明式 BrowserRouter 不会执行 React Router 的 viewTransition 选项。这里
 * 只保留正文可见区域的短暂快照，让侧栏和移动端顶栏保持稳定；新正文淡入并
 * 上移少量距离，避免整页截图式过渡带来的漂浮感。
 */
export function startPageTransition() {
  if (typeof document === 'undefined') return

  const content = document.querySelector<HTMLElement>('.numoj-content')
  if (!content) return

  const contentRect = content.getBoundingClientRect()
  const visibleLeft = Math.max(0, contentRect.left)
  const visibleTop = Math.max(0, contentRect.top)
  const visibleRight = Math.min(window.innerWidth, contentRect.right)
  const visibleBottom = Math.min(window.innerHeight, contentRect.bottom)
  if (visibleRight <= visibleLeft || visibleBottom <= visibleTop) return

  document.querySelector(PAGE_TRANSITION_SNAPSHOT_SELECTOR)?.remove()
  if (pageSnapshotCleanupTimer !== undefined) window.clearTimeout(pageSnapshotCleanupTimer)
  if (pageEnteringCleanupTimer !== undefined) window.clearTimeout(pageEnteringCleanupTimer)

  const snapshotLayer = document.createElement('div')
  snapshotLayer.className = 'numoj-page-transition-snapshot'
  snapshotLayer.dataset.numojPageTransitionSnapshot = 'true'
  snapshotLayer.setAttribute('aria-hidden', 'true')
  snapshotLayer.setAttribute('inert', '')
  snapshotLayer.style.left = `${visibleLeft}px`
  snapshotLayer.style.top = `${visibleTop}px`
  snapshotLayer.style.width = `${visibleRight - visibleLeft}px`
  snapshotLayer.style.height = `${visibleBottom - visibleTop}px`
  snapshotLayer.style.backgroundColor = window.getComputedStyle(document.body).backgroundColor

  const snapshot = content.cloneNode(true) as HTMLElement
  snapshot.classList.add('numoj-page-transition-clone')
  snapshot.style.left = `${contentRect.left - visibleLeft}px`
  snapshot.style.top = `${contentRect.top - visibleTop}px`
  snapshot.style.width = `${contentRect.width}px`
  snapshot.style.height = `${contentRect.height}px`
  copyScrollOffsets(content, snapshot)
  snapshotLayer.appendChild(snapshot)
  document.body.appendChild(snapshotLayer)

  document.documentElement.classList.remove('numoj-page-transition-entering')
  void content.offsetWidth
  document.documentElement.classList.add('numoj-page-transition-entering')

  pageSnapshotCleanupTimer = window.setTimeout(() => {
    snapshotLayer.remove()
    pageSnapshotCleanupTimer = undefined
  }, PAGE_EXIT_MS + 40)

  pageEnteringCleanupTimer = window.setTimeout(() => {
    document.documentElement.classList.remove('numoj-page-transition-entering')
    pageEnteringCleanupTimer = undefined
  }, PAGE_ENTER_DELAY_MS + PAGE_ENTER_MS + 40)
}

function shouldAnimateClick(event: MouseEvent<HTMLAnchorElement>, target?: string) {
  return event.button === 0
    && !event.defaultPrevented
    && !event.metaKey
    && !event.ctrlKey
    && !event.shiftKey
    && !event.altKey
    && (!target || target === '_self')
}

export const Link = forwardRef<HTMLAnchorElement, LinkProps>(function PageLink(
  {viewTransition = true, onClick, target, ...props},
  ref,
) {
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event)
    if (viewTransition && shouldAnimateClick(event, target)) {
      startPageTransition()
    }
  }
  return <RouterLink ref={ref} viewTransition={false} onClick={handleClick} target={target} {...props} />
})

export function useNavigate(): NavigateFunction {
  const navigate = useRouterNavigate()
  return useCallback(((to: To | number, options?: NavigateOptions) => {
    if (options?.viewTransition !== false) startPageTransition()
    if (typeof to === 'number') return navigate(to)
    return navigate(to, {...options, viewTransition: false})
  }) as NavigateFunction, [navigate])
}
