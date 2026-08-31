import {useEffect, useRef, type RefObject} from 'react'

import {MonacoEditor, type MonacoEditorReadyContext} from './MonacoEditor'

export type LeanSubmissionPayload = {revision: string; files: Record<string, string>}

export type LeanWorkbenchController = {
  checkNow: () => void
  dispose: () => void
  focus: () => void
  getActiveValue: () => string
  layout: () => void
  prepareSubmission: () => LeanSubmissionPayload
  setActiveValue: (value: string) => void
  setWritableFiles: (files: Record<string, string>) => void
}

type LeanWorkspace = Record<string, unknown> & {
  revision_number?: number
  revision?: string
  default_file?: string
  files?: Array<Record<string, unknown>>
}

declare global {
  interface Window {
    NumOJLeanWorkbench?: {
      attach: (options: MonacoEditorReadyContext) => LeanWorkbenchController | null
    }
  }
}

let leanWorkbenchRuntime: Promise<void> | null = null

function loadLeanWorkbenchRuntime() {
  if (window.NumOJLeanWorkbench) return Promise.resolve()
  if (leanWorkbenchRuntime) return leanWorkbenchRuntime
  leanWorkbenchRuntime = new Promise<void>((resolve, reject) => {
    const src = '/static/app/lean-workbench.js'
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${src}"]`)
    const script = existing || document.createElement('script')
    const loaded = () => window.NumOJLeanWorkbench ? resolve() : reject(new Error('Lean 4 工作台加载失败'))
    script.addEventListener('load', loaded, {once: true})
    script.addEventListener('error', () => reject(new Error('Lean 4 工作台加载失败')), {once: true})
    if (!existing) {
      script.src = src
      script.async = true
      script.dataset.numojSpaAsset = 'true'
      document.head.appendChild(script)
    } else if (window.NumOJLeanWorkbench) {
      resolve()
    }
  }).catch((error) => {
    leanWorkbenchRuntime = null
    throw error
  })
  return leanWorkbenchRuntime
}

function useLeanSplitter(rootRef: RefObject<HTMLDivElement | null>, problemId: number) {
  useEffect(() => {
    const root = rootRef.current
    const splitter = root?.querySelector<HTMLElement>('[data-lean-workbench-splitter]')
    if (!root || !splitter) return
    const desktop = window.matchMedia('(min-width: 992px)')
    const storageKey = 'numoj.problemDetail.leanSourceRatio'
    const stored = Number(window.localStorage.getItem(storageKey))
    let preferredRatio = stored > 0 && stored < 1 ? stored : 0.63
    let currentWidth = 0
    let pointerId: number | null = null
    let pointerOffset = 0

    const bounds = () => {
      const rect = root.getBoundingClientRect()
      const splitterWidth = Math.max(1, splitter.getBoundingClientRect().width || 7)
      const available = Math.max(1, rect.width - splitterWidth)
      const minimum = Math.min(240, available * 0.42)
      const maximum = Math.max(minimum, available - Math.min(220, available * 0.48))
      return {rect, available, minimum, maximum}
    }
    const apply = (requested: number, remember = false) => {
      if (!desktop.matches) return
      const range = bounds()
      currentWidth = Math.min(range.maximum, Math.max(range.minimum, requested))
      if (remember) preferredRatio = currentWidth / range.available
      root.style.setProperty('--lean-source-width', `${currentWidth.toFixed(2)}px`)
      const percent = Math.round(currentWidth / range.available * 100)
      splitter.setAttribute('aria-valuemin', String(Math.round(range.minimum / range.available * 100)))
      splitter.setAttribute('aria-valuemax', String(Math.round(range.maximum / range.available * 100)))
      splitter.setAttribute('aria-valuenow', String(percent))
      splitter.setAttribute('aria-valuetext', `代码 ${percent}%，证明状态 ${100 - percent}%`)
      window.dispatchEvent(new CustomEvent('numoj:problem-detail-resize'))
    }
    const refresh = () => {
      const range = bounds()
      apply(preferredRatio * range.available)
    }
    const save = () => window.localStorage.setItem(storageKey, preferredRatio.toFixed(4))
    const finish = (event: PointerEvent) => {
      if (event.pointerId !== pointerId) return
      pointerId = null
      splitter.classList.remove('is-dragging')
      document.documentElement.classList.remove('is-problem-pane-resizing')
      save()
    }
    const pointerDown = (event: PointerEvent) => {
      if (!desktop.matches || event.button !== 0) return
      pointerId = event.pointerId
      pointerOffset = event.clientX - splitter.getBoundingClientRect().left
      splitter.setPointerCapture(pointerId)
      splitter.classList.add('is-dragging')
      document.documentElement.classList.add('is-problem-pane-resizing')
      event.preventDefault()
    }
    const pointerMove = (event: PointerEvent) => {
      if (event.pointerId !== pointerId) return
      const range = bounds()
      apply(event.clientX - range.rect.left - pointerOffset, true)
      event.preventDefault()
    }
    const keyDown = (event: KeyboardEvent) => {
      const range = bounds()
      let next = currentWidth
      if (event.key === 'ArrowLeft') next -= event.shiftKey ? 48 : 16
      else if (event.key === 'ArrowRight') next += event.shiftKey ? 48 : 16
      else if (event.key === 'Home') next = range.minimum
      else if (event.key === 'End') next = range.maximum
      else return
      event.preventDefault()
      apply(next, true)
      save()
    }
    const doubleClick = () => {
      preferredRatio = 0.63
      refresh()
      save()
    }
    const mediaChange = () => {
      if (desktop.matches) refresh()
      else root.style.removeProperty('--lean-source-width')
    }
    const observer = new ResizeObserver(() => desktop.matches && refresh())
    observer.observe(root)
    splitter.addEventListener('pointerdown', pointerDown)
    splitter.addEventListener('keydown', keyDown)
    splitter.addEventListener('dblclick', doubleClick)
    window.addEventListener('pointermove', pointerMove)
    window.addEventListener('pointerup', finish)
    window.addEventListener('pointercancel', finish)
    desktop.addEventListener('change', mediaChange)
    refresh()
    return () => {
      observer.disconnect()
      splitter.removeEventListener('pointerdown', pointerDown)
      splitter.removeEventListener('keydown', keyDown)
      splitter.removeEventListener('dblclick', doubleClick)
      window.removeEventListener('pointermove', pointerMove)
      window.removeEventListener('pointerup', finish)
      window.removeEventListener('pointercancel', finish)
      desktop.removeEventListener('change', mediaChange)
    }
  }, [problemId, rootRef])
}

export function LeanWorkbench({
  problemId,
  workspace,
  value,
  onChange,
  onController,
}: {
  problemId: number
  workspace?: LeanWorkspace | null
  value: string
  onChange: (value: string) => void
  onController: (controller: LeanWorkbenchController | null) => void
}) {
  const rootRef = useRef<HTMLDivElement>(null)
  useLeanSplitter(rootRef, problemId)

  return <div ref={rootRef} className="lean-workbench" id="leanWorkbench" data-problem-id={problemId} data-check-url="/api/lean/check">
    {workspace ? <script type="application/json" id="leanWorkspaceData">{JSON.stringify(workspace)}</script> : null}
    <input type="hidden" id="leanWorkspaceInput" name="lean_workspace" value="" readOnly />
    <section className="lean-source-pane" id="leanSourcePane" aria-label="Lean 4 证明文件编辑器">
      <header className="lean-pane-bar lean-source-bar"><span className="lean-file-name"><span className="lean-file-mark" aria-hidden="true">λ</span><span className="lean-active-file-name" id="leanActiveFileName">Submission.lean</span><span className="lean-active-file-mode" id="leanActiveFileMode">可写</span></span><span className="lean-source-meta"><span className="lean-unicode-hint" title={'输入 Lean 缩写后按空格或 Tab，例如 \\alpha → α'}>\alpha → α</span><span className="lean-cursor-position" id="leanCursorPosition">Ln 1, Col 1</span></span></header>
      <div className="lean-editor-body"><MonacoEditor language="lean4" problemId={problemId} value={value} onChange={onChange} idPrefix="lean" ariaLabel="Lean 4 证明编辑器" onReady={async (context) => {
        await loadLeanWorkbenchRuntime()
        const controller = window.NumOJLeanWorkbench?.attach(context) || null
        onController(controller)
        return () => {
          onController(null)
          controller?.dispose()
        }
      }} /></div>
    </section>
    <div className="lean-workbench-splitter" id="leanWorkbenchSplitter" role="separator" tabIndex={0} aria-label="调整代码与证明状态宽度" aria-orientation="vertical" aria-controls="leanSourcePane leanInspectorPane" aria-valuemin={20} aria-valuemax={80} aria-valuenow={63} data-lean-workbench-splitter />
    <aside className="lean-inspector" id="leanInspectorPane" aria-label="Lean 证明状态">
      <section className="lean-file-explorer" aria-label="Lean 工作区文件"><header className="lean-file-explorer-bar"><span>Files</span><span className="lean-file-count" id="leanFileCount">0</span></header><div className="lean-file-tree" id="leanFileTree" role="tree" /></section>
      <header className="lean-pane-bar lean-inspector-bar"><div className="lean-inspector-tabs" role="tablist" aria-label="证明检查结果"><button type="button" className="lean-inspector-tab is-active" id="leanGoalsTab" role="tab" aria-selected="true" aria-controls="leanGoalsPanel" data-lean-tab="goals">Goals <span className="lean-tab-count" id="leanGoalCount">0</span></button><button type="button" className="lean-inspector-tab" id="leanProblemsTab" role="tab" aria-selected="false" aria-controls="leanProblemsPanel" data-lean-tab="problems">Problems <span className="lean-tab-count" id="leanProblemCount">0</span></button></div><span className="lean-check-status" id="leanCheckStatus" data-state="idle" role="status" aria-live="polite"><span className="lean-status-dot" aria-hidden="true" /><span data-lean-status-text>准备中</span></span></header>
      <div className="lean-inspector-body"><section className="lean-inspector-panel is-active" id="leanGoalsPanel" role="tabpanel" aria-labelledby="leanGoalsTab" data-lean-panel="goals"><div className="lean-panel-empty" id="leanGoalsEmpty"><span className="lean-empty-glyph" aria-hidden="true">⊢</span><strong>等待证明状态</strong><span>把光标放在 tactic 中，这里会显示当前目标。</span></div><div className="lean-goal-list" id="leanGoalList" /></section><section className="lean-inspector-panel" id="leanProblemsPanel" role="tabpanel" aria-labelledby="leanProblemsTab" data-lean-panel="problems" hidden><div className="lean-panel-empty" id="leanProblemsEmpty"><span className="lean-empty-glyph is-check" aria-hidden="true">✓</span><strong>暂时没有问题</strong><span>Lean 的错误与警告会列在这里。</span></div><ol className="lean-problem-list" id="leanProblemList" /></section></div>
      <footer className="lean-inspector-footer"><span><kbd>Ctrl</kbd><span aria-hidden="true">+</span><kbd>Space</kbd> 补全符号</span><span id="leanDocumentVersion">v0</span></footer>
    </aside>
  </div>
}
