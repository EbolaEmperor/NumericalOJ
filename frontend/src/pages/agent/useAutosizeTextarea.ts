import {useLayoutEffect, type RefObject} from 'react'

export function useAutosizeTextarea(ref: RefObject<HTMLTextAreaElement | null>, value: string, minimum: number, maximum: number) {
  useLayoutEffect(() => {
    const textarea = ref.current
    if (!textarea) return
    textarea.style.height = 'auto'
    textarea.style.height = `${Math.min(maximum, Math.max(minimum, textarea.scrollHeight))}px`
  }, [maximum, minimum, ref, value])
}
