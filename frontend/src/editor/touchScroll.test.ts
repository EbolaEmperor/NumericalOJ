// @vitest-environment jsdom

import {describe, expect, it, vi} from 'vitest'

import type {MonacoEditorInstance} from './types'
import {attachReadonlyEditorTouchHandoff, shouldHandOffTouchScroll} from './touchScroll'

function editorStub(root: HTMLElement, scrollTop: number): MonacoEditorInstance {
  return {
    blur: vi.fn(),
    dispose: vi.fn(),
    focus: vi.fn(),
    getDomNode: () => root,
    getLayoutInfo: () => ({height: 300}),
    getScrollHeight: () => 900,
    getScrollTop: () => scrollTop,
    getValue: () => '',
    layout: vi.fn(),
    onDidChangeModelContent: () => ({dispose: vi.fn()}),
    setValue: vi.fn(),
  }
}

function monacoGesture(type: string, translationX = 0, translationY = 0) {
  const event = new Event(type, {bubbles: false, cancelable: true}) as Event & {translationX: number; translationY: number}
  event.translationX = translationX
  event.translationY = translationY
  return event
}

describe('shouldHandOffTouchScroll', () => {
  it('代码框滚到底后把继续向下的手势交给页面', () => {
    expect(shouldHandOffTouchScroll({deltaX: 1, deltaY: 18, scrollTop: 600, scrollHeight: 900, viewportHeight: 300})).toBe(true)
  })

  it('代码框在顶部时把继续向上的手势交给页面', () => {
    expect(shouldHandOffTouchScroll({deltaX: 0, deltaY: -16, scrollTop: 0, scrollHeight: 900, viewportHeight: 300})).toBe(true)
  })

  it('代码框内部仍优先处理纵向滚动', () => {
    expect(shouldHandOffTouchScroll({deltaX: 1, deltaY: 20, scrollTop: 240, scrollHeight: 900, viewportHeight: 300})).toBe(false)
  })

  it('横向手势不会误触发页面滚动接力', () => {
    expect(shouldHandOffTouchScroll({deltaX: 24, deltaY: 8, scrollTop: 600, scrollHeight: 900, viewportHeight: 300})).toBe(false)
  })

  it('阻止 Monaco 只读区的手机点击获取编辑焦点', () => {
    const root = document.createElement('div')
    const lines = document.createElement('div')
    const textarea = document.createElement('textarea')
    textarea.className = 'inputarea'
    textarea.tabIndex = 0
    root.append(lines, textarea)
    const editor = editorStub(root, 0)
    const monacoTap = vi.fn()
    lines.addEventListener('-monaco-gesturetap', monacoTap)

    const detach = attachReadonlyEditorTouchHandoff(editor, vi.fn())
    const tap = monacoGesture('-monaco-gesturetap')
    lines.dispatchEvent(tap)
    textarea.dispatchEvent(new FocusEvent('focusin', {bubbles: true}))

    expect(tap.defaultPrevented).toBe(true)
    expect(monacoTap).not.toHaveBeenCalled()
    expect(editor.blur).toHaveBeenCalled()
    expect(textarea.readOnly).toBe(true)
    expect(textarea.tabIndex).toBe(-1)
    detach()
  })

  it('代码框到底后把手指位移和后续惯性帧连续交给页面', () => {
    const root = document.createElement('div')
    const lines = document.createElement('div')
    root.append(lines)
    const editor = editorStub(root, 600)
    const scrollPage = vi.fn()
    const monacoScroll = vi.fn()
    lines.addEventListener('-monaco-gesturechange', monacoScroll)
    const detach = attachReadonlyEditorTouchHandoff(editor, scrollPage)

    const touchMove = monacoGesture('-monaco-gesturechange', 1, -18)
    const inertiaFrame = monacoGesture('-monaco-gesturechange', 0, -11)
    lines.dispatchEvent(touchMove)
    lines.dispatchEvent(inertiaFrame)

    expect(scrollPage.mock.calls).toEqual([[18], [11]])
    expect(monacoScroll).not.toHaveBeenCalled()
    expect(touchMove.defaultPrevented).toBe(true)
    expect(inertiaFrame.defaultPrevented).toBe(true)
    detach()
  })

  it('代码框内部尚可滚动时保留 Monaco 原有手势与惯性', () => {
    const root = document.createElement('div')
    const lines = document.createElement('div')
    root.append(lines)
    const editor = editorStub(root, 240)
    const scrollPage = vi.fn()
    const monacoScroll = vi.fn()
    lines.addEventListener('-monaco-gesturechange', monacoScroll)
    const detach = attachReadonlyEditorTouchHandoff(editor, scrollPage)

    const gesture = monacoGesture('-monaco-gesturechange', 1, -20)
    lines.dispatchEvent(gesture)

    expect(scrollPage).not.toHaveBeenCalled()
    expect(monacoScroll).toHaveBeenCalledOnce()
    expect(gesture.defaultPrevented).toBe(false)
    detach()
  })
})
