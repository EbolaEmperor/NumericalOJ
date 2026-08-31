import {useEffect, useRef, type RefObject} from 'react'

export function useDismissibleDropdown<T extends HTMLElement>(open: boolean, onDismiss: () => void): RefObject<T | null> {
  const rootRef = useRef<T>(null)
  const onDismissRef = useRef(onDismiss)

  useEffect(() => {
    onDismissRef.current = onDismiss
  }, [onDismiss])

  useEffect(() => {
    if (!open) return undefined

    const closeOnOutsidePointer = (event: PointerEvent) => {
      const root = rootRef.current
      if (root && typeof event.composedPath === 'function' && event.composedPath().includes(root)) return
      if (root && event.target instanceof Node && root.contains(event.target)) return
      onDismissRef.current()
    }
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onDismissRef.current()
    }

    document.addEventListener('pointerdown', closeOnOutsidePointer, true)
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.removeEventListener('pointerdown', closeOnOutsidePointer, true)
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [open])

  return rootRef
}
