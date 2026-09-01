export interface EditorTouchScrollMetrics {
  deltaX: number
  deltaY: number
  scrollTop: number
  scrollHeight: number
  viewportHeight: number
}

export function shouldHandOffTouchScroll({
  deltaX,
  deltaY,
  scrollTop,
  scrollHeight,
  viewportHeight,
}: EditorTouchScrollMetrics) {
  if (Math.abs(deltaY) <= Math.abs(deltaX) || deltaY === 0) return false
  if (scrollHeight <= 0 || viewportHeight <= 0) return false
  const atTop = scrollTop <= 1
  const atBottom = scrollTop + viewportHeight >= scrollHeight - 1
  return deltaY > 0 ? atBottom : atTop
}
