import {useEffect, useRef, type MouseEvent, type ReactNode} from 'react'

let openModalCount = 0

export function ReactModal({
  open,
  onClose,
  id,
  labelledBy,
  className = '',
  dialogClassName = '',
  children,
  closeOnBackdrop = true,
}: {
  open: boolean
  onClose: () => void
  id: string
  labelledBy: string
  className?: string
  dialogClassName?: string
  children: ReactNode
  closeOnBackdrop?: boolean
}) {
  const modalRef = useRef<HTMLDivElement>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    if (!open) return
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    openModalCount += 1
    document.body.classList.add('modal-open')
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onCloseRef.current()
      }
      if (event.key !== 'Tab' || !modalRef.current) return
      const focusable = Array.from(modalRef.current.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])'))
      if (!focusable.length) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last.focus()}
      else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first.focus()}
    }
    document.addEventListener('keydown', keydown)
    const focusFrame = requestAnimationFrame(() => modalRef.current?.querySelector<HTMLElement>('[autofocus], input:not([disabled]), button:not([disabled])')?.focus())
    return () => {
      cancelAnimationFrame(focusFrame)
      document.removeEventListener('keydown', keydown)
      openModalCount = Math.max(0, openModalCount - 1)
      if (!openModalCount) document.body.classList.remove('modal-open')
      previousFocus?.focus()
    }
  }, [open])

  if (!open) return null
  const backdropClick = (event: MouseEvent<HTMLDivElement>) => {
    if (closeOnBackdrop && event.target === event.currentTarget) onClose()
  }
  return <>
    <div ref={modalRef} className={`modal fade show${className ? ` ${className}` : ''}`} id={id} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={labelledBy} style={{display: 'block'}} onMouseDown={backdropClick}>
      <div className={`modal-dialog${dialogClassName ? ` ${dialogClassName}` : ''}`}>{children}</div>
    </div>
    <div className="modal-backdrop fade show" aria-hidden="true" />
  </>
}
