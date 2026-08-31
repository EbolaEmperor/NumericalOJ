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
