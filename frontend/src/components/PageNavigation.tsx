import {forwardRef, useCallback, type MouseEvent} from 'react'
import {flushSync} from 'react-dom'
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
let activeViewTransition: ViewTransition | undefined

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
      clonedElement.loading = 'eager'
      clonedElement.decoding = 'sync'
      if (element.currentSrc) clonedElement.src = element.currentSrc
    }
  })
}

function prefersReducedMotion() {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function startNativePageTransition(update: () => void) {
  if (typeof document.startViewTransition !== 'function') return false

  try {
    activeViewTransition?.skipTransition()
    const transition = document.startViewTransition(() => {
      flushSync(update)
    })
    activeViewTransition = transition
    void transition.finished.then(
      () => {if (activeViewTransition === transition) activeViewTransition = undefined},
      () => {if (activeViewTransition === transition) activeViewTransition = undefined},
    )
    return true
  } catch {
    activeViewTransition = undefined
    return false
  }
}

/**
 * 保留原来的旧页下沉淡出和新页延迟上浮淡入时序。支持 View Transition 的
 * 浏览器直接使用合成层快照，避免 cloneNode 重新绘制图片和复杂背景；旧浏览器
 * 才使用 DOM 快照回退。
 */
export function startPageTransition(update: () => void) {
  if (typeof document === 'undefined' || prefersReducedMotion()) {
    update()
    return
  }
  if (startNativePageTransition(update)) return

  const content = document.querySelector<HTMLElement>('.numoj-content')
  if (!content) {
    update()
    return
  }

  const contentRect = content.getBoundingClientRect()
  const visibleLeft = Math.max(0, contentRect.left)
  const visibleTop = Math.max(0, contentRect.top)
  const visibleRight = Math.min(window.innerWidth, contentRect.right)
  const visibleBottom = Math.min(window.innerHeight, contentRect.bottom)
  if (visibleRight <= visibleLeft || visibleBottom <= visibleTop) {
    update()
    return
  }

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
  update()

  pageSnapshotCleanupTimer = window.setTimeout(() => {
    snapshotLayer.remove()
    pageSnapshotCleanupTimer = undefined
  }, PAGE_EXIT_MS + 40)

  pageEnteringCleanupTimer = window.setTimeout(() => {
    document.documentElement.classList.remove('numoj-page-transition-entering')
    pageEnteringCleanupTimer = undefined
  }, PAGE_ENTER_DELAY_MS + PAGE_ENTER_MS + 40)
}

function shouldAnimateClick(event: MouseEvent<HTMLAnchorElement>, target?: string, reloadDocument?: boolean) {
  if (event.button !== 0
    || event.defaultPrevented
    || event.metaKey
    || event.ctrlKey
    || event.shiftKey
    || event.altKey
    || reloadDocument
    || target && target !== '_self') return false

  const currentUrl = new URL(window.location.href)
  const destinationUrl = new URL(event.currentTarget.href, currentUrl)
  return destinationUrl.origin === currentUrl.origin && destinationUrl.href !== currentUrl.href
}

export const Link = forwardRef<HTMLAnchorElement, LinkProps>(function PageLink(
  {viewTransition = true, onClick, target, reloadDocument, replace, state, preventScrollReset, relative, to, ...props},
  ref,
) {
  const navigate = useRouterNavigate()
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event)
    if (!viewTransition || !shouldAnimateClick(event, target, reloadDocument)) return

    event.preventDefault()
    startPageTransition(() => navigate(to, {
      replace,
      state,
      preventScrollReset,
      relative,
      viewTransition: false,
    }))
  }
  return <RouterLink ref={ref} viewTransition={false} onClick={handleClick} target={target} reloadDocument={reloadDocument} replace={replace} state={state} preventScrollReset={preventScrollReset} relative={relative} to={to} {...props} />
})

export function useNavigate(): NavigateFunction {
  const navigate = useRouterNavigate()
  return useCallback(((to: To | number, options?: NavigateOptions) => {
    const update = () => {
      if (typeof to === 'number') navigate(to)
      else navigate(to, {...options, viewTransition: false})
    }
    if (options?.viewTransition === false) return update()
    startPageTransition(update)
  }) as NavigateFunction, [navigate])
}
