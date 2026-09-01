interface CardClickEvent {
  target: EventTarget | null
  button: number
  defaultPrevented: boolean
  metaKey: boolean
  ctrlKey: boolean
  shiftKey: boolean
  altKey: boolean
}

const INTERACTIVE_SELECTOR = 'a, button, input, select, textarea, summary, [contenteditable="true"]'

export function shouldNavigateFromCardClick(event: CardClickEvent) {
  if (event.button !== 0 || event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return false
  return !(event.target instanceof Element) || !event.target.closest(INTERACTIVE_SELECTOR)
}
