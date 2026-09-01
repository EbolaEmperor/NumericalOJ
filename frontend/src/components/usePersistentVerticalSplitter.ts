import {useEffect, type RefObject} from 'react'

interface PersistentVerticalSplitterOptions {
  containerRef: RefObject<HTMLElement | null>
  splitterRef: RefObject<HTMLElement | null>
  enabled?: boolean
  storageKey: string
  cssVariable: `--${string}`
  defaultRatio: number
  minimumLeadingPixels: number
  minimumTrailingPixels: number
  valueText: (leadingPercent: number, trailingPercent: number) => string
  mediaQuery?: string
  resizingClassName?: string
  resizeEventName?: string
}

export function usePersistentVerticalSplitter({
  containerRef,
  splitterRef,
  enabled = true,
  storageKey,
  cssVariable,
  defaultRatio,
  minimumLeadingPixels,
  minimumTrailingPixels,
  valueText,
  mediaQuery = '(min-width: 992px)',
  resizingClassName = 'is-pane-resizing',
  resizeEventName,
}: PersistentVerticalSplitterOptions) {
  useEffect(() => {
    if (!enabled) return
    const container = containerRef.current
    const splitter = splitterRef.current
    if (!container || !splitter) return

    const desktop = window.matchMedia(mediaQuery)
    let preferredRatio = defaultRatio
    try {
      const stored = Number(window.localStorage.getItem(storageKey))
      if (stored > 0 && stored < 1) preferredRatio = stored
    } catch {
      // 禁用本地存储时仍保留拖拽能力，只是不跨页面记忆。
    }
    let currentWidth = 0
    let pointerId: number | null = null
    let pointerOffset = 0

    const bounds = () => {
      const rect = container.getBoundingClientRect()
      const splitterWidth = Math.max(1, splitter.getBoundingClientRect().width || 7)
      const available = Math.max(1, rect.width - splitterWidth)
      const minimum = Math.min(minimumLeadingPixels, available * 0.48)
      const maximum = Math.max(
        minimum,
        available - Math.min(minimumTrailingPixels, available * 0.48),
      )
      return {rect, available, minimum, maximum}
    }
    const apply = (requested: number, remember = false) => {
      if (!desktop.matches) return
      const range = bounds()
      currentWidth = Math.min(range.maximum, Math.max(range.minimum, requested))
      if (remember) preferredRatio = currentWidth / range.available
      container.style.setProperty(cssVariable, `${currentWidth.toFixed(2)}px`)
      const leadingPercent = Math.round(currentWidth / range.available * 100)
      const trailingPercent = 100 - leadingPercent
      splitter.setAttribute('aria-valuemin', String(Math.round(range.minimum / range.available * 100)))
      splitter.setAttribute('aria-valuemax', String(Math.round(range.maximum / range.available * 100)))
      splitter.setAttribute('aria-valuenow', String(leadingPercent))
      splitter.setAttribute('aria-valuetext', valueText(leadingPercent, trailingPercent))
      if (resizeEventName) window.dispatchEvent(new CustomEvent(resizeEventName))
    }
    const refresh = () => {
      const range = bounds()
      apply(preferredRatio * range.available)
    }
    const save = () => {
      try {
        window.localStorage.setItem(storageKey, preferredRatio.toFixed(4))
      } catch {
        // 页面布局已经更新，无需因存储不可用中断交互。
      }
    }
    const finish = (event: PointerEvent) => {
      if (event.pointerId !== pointerId) return
      pointerId = null
      splitter.classList.remove('is-dragging')
      document.documentElement.classList.remove(resizingClassName)
      save()
    }
    const pointerDown = (event: PointerEvent) => {
      if (!desktop.matches || event.button !== 0) return
      pointerId = event.pointerId
      pointerOffset = event.clientX - splitter.getBoundingClientRect().left
      try {
        splitter.setPointerCapture(pointerId)
      } catch {
        // 部分浏览器或测试环境不提供 pointer capture，window 监听仍可完成拖拽。
      }
      splitter.classList.add('is-dragging')
      document.documentElement.classList.add(resizingClassName)
      event.preventDefault()
    }
    const pointerMove = (event: PointerEvent) => {
      if (event.pointerId !== pointerId) return
      const range = bounds()
      apply(event.clientX - range.rect.left - pointerOffset, true)
      event.preventDefault()
    }
    const keyDown = (event: KeyboardEvent) => {
      if (!desktop.matches) return
      const range = bounds()
      let next = currentWidth
      if (event.key === 'ArrowLeft') next -= event.shiftKey ? 48 : 16
      else if (event.key === 'ArrowRight') next += event.shiftKey ? 48 : 16
      else if (event.key === 'Home') next = range.minimum
      else if (event.key === 'End') next = range.maximum
      else return
      event.preventDefault()
      apply(next, true)
      save()
    }
    const doubleClick = () => {
      if (!desktop.matches) return
      preferredRatio = defaultRatio
      refresh()
      save()
    }
    const mediaChange = () => {
      if (desktop.matches) refresh()
      else container.style.removeProperty(cssVariable)
    }
    const observer = typeof ResizeObserver === 'undefined'
      ? null
      : new ResizeObserver(() => desktop.matches && refresh())
    observer?.observe(container)
    splitter.addEventListener('pointerdown', pointerDown)
    splitter.addEventListener('keydown', keyDown)
    splitter.addEventListener('dblclick', doubleClick)
    window.addEventListener('pointermove', pointerMove)
    window.addEventListener('pointerup', finish)
    window.addEventListener('pointercancel', finish)
    window.addEventListener('resize', refresh)
    desktop.addEventListener('change', mediaChange)
    refresh()

    return () => {
      observer?.disconnect()
      splitter.removeEventListener('pointerdown', pointerDown)
      splitter.removeEventListener('keydown', keyDown)
      splitter.removeEventListener('dblclick', doubleClick)
      window.removeEventListener('pointermove', pointerMove)
      window.removeEventListener('pointerup', finish)
      window.removeEventListener('pointercancel', finish)
      window.removeEventListener('resize', refresh)
      desktop.removeEventListener('change', mediaChange)
      document.documentElement.classList.remove(resizingClassName)
    }
  }, [
    containerRef,
    cssVariable,
    defaultRatio,
    enabled,
    mediaQuery,
    minimumLeadingPixels,
    minimumTrailingPixels,
    resizeEventName,
    resizingClassName,
    splitterRef,
    storageKey,
    valueText,
  ])
}
