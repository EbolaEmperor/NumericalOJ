import {useEffect, useRef, type RefObject} from 'react'

export function useNativeDialog(
  open: boolean,
  initialFocus?: () => void,
): RefObject<HTMLDialogElement | null> {
  const ref = useRef<HTMLDialogElement>(null)
  const initialFocusRef = useRef(initialFocus)
  initialFocusRef.current = initialFocus

  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return
    if (!open) {
      if (dialog.open) dialog.close()
      return
    }

    if (!dialog.open) dialog.showModal()
    const focusFrame = requestAnimationFrame(() => initialFocusRef.current?.())
    return () => {
      cancelAnimationFrame(focusFrame)
      if (dialog.open) dialog.close()
    }
  }, [open])

  return ref
}
