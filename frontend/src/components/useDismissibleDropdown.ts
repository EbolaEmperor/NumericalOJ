import {useEffect, useRef, type RefObject} from 'react'

export function useDismissibleDropdown<T extends HTMLElement>(open: boolean, onDismiss: () => void): RefObject<T | null> {
  const rootRef = useRef<T>(null)
  const onDismissRef = useRef(onDismiss)

  useEffect(() => {
    onDismissRef.current = onDismiss
  }, [onDismiss])

  useEffect(() => {
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (!open) return
      const root = rootRef.current
      if (root && typeof event.composedPath === 'function' && event.composedPath().includes(root)) return
      if (root && event.target instanceof Node && root.contains(event.target)) return
      onDismissRef.current()
    }
    const keyboardNavigation = (event: KeyboardEvent) => {
      const root = rootRef.current
      const target = event.target instanceof HTMLElement ? event.target : null
      const trigger = root?.querySelector<HTMLElement>('[aria-haspopup="listbox"]') || null
      const options = () => Array.from(root?.querySelectorAll<HTMLElement>('[role="option"]') || [])
        .filter((option) => option.getAttribute('aria-disabled') !== 'true' && !option.hasAttribute('disabled'))
      const focusAt = (index: number) => {
        const items = options()
        if (!items.length) return
        items[(index + items.length) % items.length]?.focus()
      }

      if (root && target && root.contains(target) && target === trigger && ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
        event.preventDefault()
        if (!open) trigger.click()
        window.requestAnimationFrame(() => {
          const items = options()
          const selected = items.findIndex((option) => option.getAttribute('aria-selected') === 'true')
          if (event.key === 'ArrowUp' || event.key === 'End') focusAt(items.length - 1)
          else focusAt(selected >= 0 ? selected : 0)
        })
        return
      }
      if (open && root && target && root.contains(target)) {
        const items = options()
        const current = items.indexOf(target.closest<HTMLElement>('[role="option"]') || target)
        if (current >= 0 && ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
          event.preventDefault()
          if (event.key === 'Home') focusAt(0)
          else if (event.key === 'End') focusAt(items.length - 1)
          else focusAt(current + (event.key === 'ArrowDown' ? 1 : -1))
          return
        }
        if (current >= 0 && event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
          const needle = event.key.toLocaleLowerCase()
          const ordered = [...items.slice(current + 1), ...items.slice(0, current + 1)]
          const match = ordered.find((item) => (item.textContent || '').trim().toLocaleLowerCase().startsWith(needle))
          if (match) {event.preventDefault(); match.focus()}
          return
        }
        if (event.key === 'Tab') onDismissRef.current()
      }
      if (open && event.key === 'Escape') {
        event.preventDefault()
        onDismissRef.current()
        trigger?.focus()
      }
    }

    document.addEventListener('pointerdown', closeOnOutsidePointer, true)
    document.addEventListener('keydown', keyboardNavigation)
    return () => {
      document.removeEventListener('pointerdown', closeOnOutsidePointer, true)
      document.removeEventListener('keydown', keyboardNavigation)
    }
  }, [open])

  return rootRef
}
