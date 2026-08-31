import {useEffect, useRef, type ReactNode} from 'react'

export function ReactOffcanvas({open, onClose, id, labelledBy, className = '', children}: {open: boolean; onClose: () => void; id: string; labelledBy: string; className?: string; children: ReactNode}) {
  const panelRef = useRef<HTMLElement>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  useEffect(() => {
    if (!open) return
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {event.preventDefault(); onCloseRef.current()}
    }
    document.addEventListener('keydown', keydown)
    const focusFrame = requestAnimationFrame(() => panelRef.current?.querySelector<HTMLElement>('a[href], button:not([disabled])')?.focus())
    return () => {
      cancelAnimationFrame(focusFrame)
      document.removeEventListener('keydown', keydown)
      document.body.style.overflow = previousOverflow
      previousFocus?.focus()
    }
  }, [open])
  return <>
    <aside ref={panelRef} className={`offcanvas offcanvas-start d-lg-none${open ? ' show' : ''}${className ? ` ${className}` : ''}`} tabIndex={-1} id={id} aria-labelledby={labelledBy} aria-modal={open || undefined} role={open ? 'dialog' : undefined} style={open ? {visibility: 'visible'} : undefined} data-numoj-mobile-sidebar>
      {children}
    </aside>
    {open ? <div className="offcanvas-backdrop fade show d-lg-none" aria-hidden="true" onMouseDown={onClose} /> : null}
  </>
}
