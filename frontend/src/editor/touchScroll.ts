import type {MonacoEditorInstance} from './types'

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

type MonacoGestureEvent = Event & {translationX?: number; translationY?: number}

export function attachReadonlyEditorTouchHandoff(
  editor: MonacoEditorInstance,
  scrollPage: (deltaY: number) => void = (deltaY) => window.scrollBy({top: deltaY, left: 0}),
) {
  const root = editor.getDomNode?.()
  if (!root) return () => undefined

  // Monaco 的只读模式仍会在手机点击代码时 focus 内部 textarea；阻止它的
  // 非冒泡 tap/contextmenu 手势，才能避免 iOS 的插入光标、放大镜和键盘准备态。
  const preventTextInteraction = (event: Event) => {
    event.preventDefault()
    event.stopPropagation()
    editor.blur?.()
  }
  const blurInternalInput = () => editor.blur?.()
  const handOffAtBoundary = (event: Event) => {
    const gesture = event as MonacoGestureEvent
    const translationX = Number(gesture.translationX || 0)
    const translationY = Number(gesture.translationY || 0)
    const deltaX = -translationX
    const deltaY = -translationY
    if (!Number.isFinite(deltaX) || !Number.isFinite(deltaY)) return

    const scrollTop = editor.getScrollTop?.() || 0
    const scrollHeight = editor.getScrollHeight?.() || 0
    const viewportHeight = editor.getLayoutInfo?.().height || 0
    if (!shouldHandOffTouchScroll({deltaX, deltaY, scrollTop, scrollHeight, viewportHeight})) return

    // 该事件既承载手指位移，也承载 Monaco 松手后的惯性帧。到达边界后
    // 截住同一串事件并滚动页面，页面便能连续接走剩余位移和剩余速度。
    event.preventDefault()
    event.stopPropagation()
    scrollPage(deltaY)
  }

  root.querySelectorAll<HTMLTextAreaElement>('textarea.inputarea').forEach((input) => {
    input.readOnly = true
    input.tabIndex = -1
  })
  root.addEventListener('-monaco-gesturetap', preventTextInteraction, true)
  root.addEventListener('-monaco-gesturecontextmenu', preventTextInteraction, true)
  root.addEventListener('-monaco-gesturechange', handOffAtBoundary, true)
  root.addEventListener('focusin', blurInternalInput, true)

  return () => {
    root.removeEventListener('-monaco-gesturetap', preventTextInteraction, true)
    root.removeEventListener('-monaco-gesturecontextmenu', preventTextInteraction, true)
    root.removeEventListener('-monaco-gesturechange', handOffAtBoundary, true)
    root.removeEventListener('focusin', blurInternalInput, true)
  }
}
